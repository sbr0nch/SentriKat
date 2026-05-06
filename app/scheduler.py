from apscheduler.schedulers.background import BackgroundScheduler
from apscheduler.triggers.cron import CronTrigger
from apscheduler.triggers.interval import IntervalTrigger
from apscheduler.events import EVENT_JOB_EXECUTED, EVENT_JOB_ERROR
from app.cisa_sync import sync_cisa_kev
from app import db
from config import Config
from datetime import datetime, timedelta
from sqlalchemy import or_
from zoneinfo import ZoneInfo
import json
import logging
import os
import threading
import time

# Import job dependencies at module level so they are patchable by tests.
# Each is guarded by try/except because some modules may be optional.
try:
    from app.cve_known_products import refresh_known_cve_products
except ImportError:
    refresh_known_cve_products = None

try:
    from app.ldap_sync import LDAPSyncEngine
except ImportError:
    LDAPSyncEngine = None

try:
    from app.models import VulnerabilitySnapshot, SystemSettings
except ImportError:
    VulnerabilitySnapshot = None
    SystemSettings = None

try:
    from app.vendor_advisories import sync_vendor_advisories
except ImportError:
    sync_vendor_advisories = None

try:
    from app.licensing import license_heartbeat
except ImportError:
    license_heartbeat = None

try:
    from app.health_checks import run_all_health_checks
except ImportError:
    run_all_health_checks = None

try:
    from app.epss_sync import sync_epss_scores
except ImportError:
    sync_epss_scores = None

try:
    from app.cpe_dictionary import build_cpe_dictionary
except ImportError:
    build_cpe_dictionary = None

try:
    from app.cpe_mapping import batch_apply_cpe_mappings, cleanup_bad_auto_mappings
except ImportError:
    batch_apply_cpe_mappings = None
    cleanup_bad_auto_mappings = None

try:
    from app.cisa_sync import enrich_with_euvd_exploited, sync_nvd_recent_cves, reenrich_fallback_cvss
except ImportError:
    enrich_with_euvd_exploited = None
    sync_nvd_recent_cves = None
    reenrich_fallback_cvss = None

try:
    from app.kb_sync import kb_sync
except ImportError:
    kb_sync = None

logger = logging.getLogger(__name__)

# In-memory fallback locks (used when DB is unavailable)
_job_locks = {}
_job_locks_lock = threading.Lock()

# Sync retry constants
_MAX_SYNC_RETRIES = 4
_SYNC_RETRY_DELAYS = [900, 1800, 3600, 7200]  # seconds


def _run_with_lock(job_name, func, *args, **kwargs):
    """Run a job function with a database-backed lock to prevent overlap.

    Falls back to in-memory lock if the database is unavailable.
    Stale locks (running > 1 hour) are automatically released.
    """
    # Try database lock first (survives restarts, works cross-process)
    db_lock_acquired = False
    try:
        from app.models import JobState
        db_lock_acquired = JobState.acquire_lock(job_name)
        if not db_lock_acquired:
            logger.info(f"Job '{job_name}' already running (DB lock), skipping")
            return
    except Exception as e:
        # DB unavailable — fall back to in-memory lock
        logger.debug(f"DB lock unavailable for '{job_name}', using in-memory: {e}")
        with _job_locks_lock:
            if _job_locks.get(job_name):
                logger.info(f"Job '{job_name}' already running (memory lock), skipping")
                return
            _job_locks[job_name] = True

    def _release_with_retry(error=None):
        """Release the DB lock with one retry on transient failure (M2)."""
        from app.models import JobState as _JobState
        last_exc = None
        for attempt in range(2):
            try:
                if error is not None:
                    _JobState.release_lock(job_name, error=error)
                else:
                    _JobState.release_lock(job_name)
                return True
            except Exception as rel_err:
                last_exc = rel_err
                logger.error(
                    "Failed to release job lock for '%s' (attempt %d/2): %s",
                    job_name, attempt + 1, rel_err, exc_info=True,
                )
                if attempt == 0:
                    time.sleep(0.5)
        # Final failure — emit a loud ERROR so that the alerting pipeline
        # (ops dashboard / metrics) picks it up.  The lock will be cleaned up
        # by the stuck-job recovery job or by stale-lock expiry.
        logger.error(
            "ALERT: permanently failed to release job lock for '%s': %s",
            job_name, last_exc,
        )
        return False

    job_errored = False
    try:
        return func(*args, **kwargs)
    except Exception as exc:
        job_errored = True
        if db_lock_acquired:
            _release_with_retry(error=exc)
        raise
    finally:
        if db_lock_acquired:
            if not job_errored:
                _release_with_retry()
        else:
            with _job_locks_lock:
                _job_locks[job_name] = False

# Store scheduler globally so we can reschedule jobs when settings change
_scheduler = None
_app = None

# Module-level fd holder for the leader-election flock.  Keeping the fd open
# (and referenced) is what preserves the lock for the lifetime of this
# worker process; if we let it get GC'd the kernel releases the lock.
_scheduler_leader_fd = None
_SCHEDULER_LOCK_PATH = os.environ.get('SENTRIKAT_SCHEDULER_LOCK', '/tmp/sentrikat-scheduler.lock')


def _acquire_scheduler_leader_lock(app):
    """Filesystem-based leader election for multi-worker deployments.

    In a Gunicorn multi-worker setup each worker imports the app and would
    otherwise start its own APScheduler, causing every cron job to run N
    times.  We use a simple non-blocking flock(2) against a well-known
    file; the first worker to get the lock is the scheduler leader, the
    others log and skip scheduler startup.

    Returns True if this process is the scheduler leader (safe to proceed),
    False otherwise.  In TESTING mode the lock is always bypassed so that
    unit tests can freely instantiate schedulers.
    """
    global _scheduler_leader_fd

    # Skip lock in test environments to avoid polluting /tmp and to allow
    # multiple in-process schedulers in the same test run.
    try:
        if app.config.get('TESTING'):
            logger.debug("TESTING mode: skipping scheduler leader lock")
            return True
    except Exception:
        pass
    if (os.environ.get('FLASK_ENV', '') or '').lower() == 'testing':
        logger.debug("FLASK_ENV=testing: skipping scheduler leader lock")
        return True
    if (os.environ.get('SENTRIKAT_SKIP_SCHEDULER_LOCK', '') or '').lower() in ('1', 'true', 'yes'):
        logger.debug("SENTRIKAT_SKIP_SCHEDULER_LOCK set: skipping scheduler leader lock")
        return True

    try:
        import fcntl
        fd = os.open(_SCHEDULER_LOCK_PATH, os.O_CREAT | os.O_RDWR, 0o644)
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except (BlockingIOError, OSError) as lock_err:
            os.close(fd)
            logger.info(
                "Another worker already holds the scheduler lock (%s); "
                "skipping scheduler startup in this worker: %s",
                _SCHEDULER_LOCK_PATH, lock_err,
            )
            return False
        # Write our pid for operational visibility
        try:
            os.ftruncate(fd, 0)
            os.write(fd, f"{os.getpid()}\n".encode())
        except Exception:
            pass
        _scheduler_leader_fd = fd  # keep fd alive for process lifetime
        logger.info(
            "Acquired scheduler leader lock at %s (pid=%s)",
            _SCHEDULER_LOCK_PATH, os.getpid(),
        )
        return True
    except ImportError:
        # Non-POSIX platform (e.g., Windows dev box). Fall through — better
        # to run scheduler than to not run it at all.
        logger.warning("fcntl unavailable; cannot enforce scheduler leader lock")
        return True
    except Exception as e:
        logger.error("Scheduler leader lock setup failed: %s", e, exc_info=True)
        # Fail open: run the scheduler rather than leaving the system with no jobs.
        return True


def _upsert_system_setting(key, value, category='job_metrics'):
    """Upsert a SystemSettings row by key (NULL organization_id = global)."""
    if SystemSettings is None:
        return
    try:
        existing = SystemSettings.query.filter_by(key=key, organization_id=None).first()
        if existing:
            existing.value = value
            existing.category = existing.category or category
        else:
            existing = SystemSettings(
                key=key,
                value=value,
                category=category,
                organization_id=None,
            )
            db.session.add(existing)
        db.session.commit()
    except Exception as e:
        logger.debug("_upsert_system_setting failed for %s: %s", key, e)
        try:
            db.session.rollback()
        except Exception:
            pass


def _get_system_setting_int(key, default=0):
    if SystemSettings is None:
        return default
    try:
        row = SystemSettings.query.filter_by(key=key, organization_id=None).first()
        if row and row.value is not None:
            return int(row.value)
    except Exception:
        pass
    return default


def _job_listener(event):
    """Persist success/failure metrics for scheduled jobs in SystemSettings.

    Fires on every EVENT_JOB_EXECUTED and EVENT_JOB_ERROR. Keys:
      - job_last_success:<job_id>   (unix timestamp str)
      - job_failure_count:<job_id>  (monotonic int)
      - job_last_error:<job_id>     (last exception repr)
      - job_last_error_at:<job_id>  (unix timestamp str)
    Failures are also logged at ERROR with traceback.
    """
    global _app
    job_id = getattr(event, 'job_id', 'unknown')
    if _app is None:
        return
    try:
        with _app.app_context():
            if event.exception:
                failure_key = f'job_failure_count:{job_id}'
                cur = _get_system_setting_int(failure_key, 0)
                _upsert_system_setting(failure_key, str(cur + 1))
                _upsert_system_setting(
                    f'job_last_error:{job_id}',
                    repr(event.exception)[:500],
                )
                _upsert_system_setting(
                    f'job_last_error_at:{job_id}',
                    str(int(time.time())),
                )
                logger.error(
                    "Scheduled job '%s' failed: %s\n%s",
                    job_id, event.exception, getattr(event, 'traceback', ''),
                )
            else:
                _upsert_system_setting(
                    f'job_last_success:{job_id}',
                    str(int(time.time())),
                )
    except Exception as outer:
        logger.debug("Job listener outer error: %s", outer)

def get_display_timezone(app):
    """Get the configured display timezone from settings, defaulting to UTC."""
    with app.app_context():
        if SystemSettings is None:
            return None
        tz_setting = SystemSettings.query.filter_by(key='display_timezone').first()
        tz_name = tz_setting.value if tz_setting and tz_setting.value else 'UTC'
        try:
            return ZoneInfo(tz_name)
        except (KeyError, Exception):
            logger.warning(f"Invalid timezone '{tz_name}', falling back to UTC")
            return ZoneInfo('UTC')

def get_critical_email_settings(app):
    """Get critical email settings from database"""
    with app.app_context():
        enabled_setting = SystemSettings.query.filter_by(key='critical_email_enabled').first()
        time_setting = SystemSettings.query.filter_by(key='critical_email_time').first()

        enabled = enabled_setting.value == 'true' if enabled_setting else True
        email_time = time_setting.value if time_setting else '09:00'

        try:
            hour, minute = map(int, email_time.split(':'))
        except (ValueError, AttributeError):
            hour, minute = 9, 0

        return enabled, hour, minute

def start_scheduler(app):
    """Start the background scheduler for scheduled jobs.

    Uses a filesystem leader-election lock so that only one Gunicorn worker
    actually runs the scheduler (prevents N-way duplicate job execution).
    """
    global _scheduler, _app
    _app = app

    # Leader election: only one worker should run the scheduler
    if not _acquire_scheduler_leader_lock(app):
        return None

    # Defaults applied to every scheduled job ([03.5.6a]):
    # - misfire_grace_time=300s: tolerate up to 5 min of master delay (e.g.
    #   gunicorn worker recycle, container restart, brief load spike) before
    #   the run is marked missed. Default 1s is too tight in production.
    # - coalesce=True: if a job missed N runs while the scheduler was down,
    #   execute the trigger once on resume instead of N times back-to-back
    #   (which can DDoS NVD/CISA APIs after a long outage).
    # - max_instances=1: never run two copies of the same job at once
    #   (e.g. a slow CPE backfill overlapping its next scheduled run).
    job_defaults = {
        'misfire_grace_time': 300,
        'coalesce': True,
        'max_instances': 1,
    }
    scheduler = BackgroundScheduler(job_defaults=job_defaults)
    _scheduler = scheduler

    # Get the user-configured display timezone for all cron-based jobs
    tz = get_display_timezone(app)

    # Schedule daily CISA KEV sync at configured time
    scheduler.add_job(
        func=lambda: _run_with_lock('cisa_sync', cisa_sync_job, app),
        trigger=CronTrigger(hour=Config.SYNC_HOUR, minute=Config.SYNC_MINUTE, timezone=tz),
        id='daily_cisa_sync',
        name='Daily CISA KEV Sync',
        replace_existing=True
    )

    # [08.7.1] fix (audit 2026-05-06): EPSS sync as standalone job, no longer
    # coupled to CISA KEV success. FIRST.org EPSS feed updates ~04:00 UTC daily;
    # we run at 04:30 (display tz) to allow the feed to land.
    if sync_epss_scores is not None:
        scheduler.add_job(
            func=lambda: _run_with_lock('epss_sync', epss_sync_job, app),
            trigger=CronTrigger(hour=4, minute=30, timezone=tz),
            id='daily_epss_sync',
            name='Daily EPSS Score Sync',
            replace_existing=True
        )
        logger.info("EPSS sync scheduled at 04:30 (display timezone)")
    else:
        logger.warning("EPSS sync NOT scheduled — sync_epss_scores not importable")

    # F.1 fix (CVE-MATCHING-PIPELINE.md §F.1): periodic CPE NVD remap every 4h
    # to fill long-tail products (Windows generics, niche software) that fail
    # local Tiers 1+2+3 — the post-KEV auto-remap uses use_nvd=False so this
    # is the only path that ever populates CPE for those products.
    if batch_apply_cpe_mappings is not None:
        scheduler.add_job(
            func=lambda: _run_with_lock('cpe_nvd_remap', cpe_nvd_remap_job, app),
            trigger=IntervalTrigger(hours=4),
            id='cpe_nvd_remap',
            name='Periodic CPE NVD Remap (Tier 4)',
            replace_existing=True
        )
        logger.info("CPE NVD remap scheduled every 4 hours")
    else:
        logger.warning("CPE NVD remap NOT scheduled — batch_apply_cpe_mappings not importable")

    # Schedule LDAP sync if enabled
    ldap_sync_enabled = (os.environ.get('LDAP_SYNC_ENABLED', '') or 'false').lower() == 'true'
    if ldap_sync_enabled:
        ldap_sync_interval = int(os.environ.get('LDAP_SYNC_INTERVAL_HOURS', '') or 24)

        scheduler.add_job(
            func=lambda: _run_with_lock('ldap_sync', ldap_sync_job, app),
            trigger=IntervalTrigger(hours=ldap_sync_interval),
            id='scheduled_ldap_sync',
            name=f'Scheduled LDAP Sync (every {ldap_sync_interval}h)',
            replace_existing=True
        )
        logger.info(f"LDAP sync scheduled every {ldap_sync_interval} hours")

    # Schedule daily critical CVE reminder emails (time from settings, in configured timezone)
    enabled, hour, minute = get_critical_email_settings(app)
    if enabled:
        scheduler.add_job(
            func=lambda: _run_with_lock('critical_cve_reminder', critical_cve_reminder_job, app),
            trigger=CronTrigger(hour=hour, minute=minute, timezone=tz),
            id='daily_critical_cve_reminder',
            name='Daily Critical CVE Reminder Emails',
            replace_existing=True
        )
        logger.info(f"Critical CVE reminder emails scheduled at {hour:02d}:{minute:02d} ({tz})")
    else:
        logger.info("Critical CVE reminder emails disabled")

    # Schedule data retention cleanup (daily at 3 AM in configured timezone)
    scheduler.add_job(
        func=lambda: _run_with_lock('data_retention_cleanup', data_retention_cleanup_job, app),
        trigger=CronTrigger(hour=3, minute=0, timezone=tz),
        id='data_retention_cleanup',
        name='Data Retention Cleanup',
        replace_existing=True
    )
    logger.info("Data retention cleanup scheduled at 03:00")

    # Schedule daily stale match cleanup (at 1:30 AM — before 2 AM snapshot)
    # Removes matches that no longer pass version-range checks after CPE data
    # updates throughout the day (NVD every 2h, EUVD every 6h, vendor advisories daily).
    # Without this, stale false-positive matches persist until the next full KEV sync.
    scheduler.add_job(
        func=lambda: _run_with_lock('stale_match_cleanup', stale_match_cleanup_job, app),
        trigger=CronTrigger(hour=1, minute=30, timezone=tz),
        id='daily_stale_match_cleanup',
        name='Daily Stale Match Cleanup',
        replace_existing=True
    )
    logger.info("Daily stale match cleanup scheduled at 01:30")

    # Schedule daily vulnerability snapshot (at 2 AM in configured timezone)
    scheduler.add_job(
        func=lambda: _run_with_lock('vulnerability_snapshot', vulnerability_snapshot_job, app),
        trigger=CronTrigger(hour=2, minute=0, timezone=tz),
        id='daily_vulnerability_snapshot',
        name='Daily Vulnerability Snapshot',
        replace_existing=True
    )
    logger.info("Vulnerability snapshot scheduled at 02:00")

    # Schedule report processing (every 15 minutes to check for due reports)
    scheduler.add_job(
        func=lambda: _run_with_lock('process_scheduled_reports', process_scheduled_reports_job, app),
        trigger=IntervalTrigger(minutes=15),
        id='process_scheduled_reports',
        name='Process Scheduled Reports',
        replace_existing=True
    )
    logger.info("Scheduled reports processor running every 15 minutes")

    # Schedule vendor advisory sync (1 hour after CISA KEV sync)
    vendor_sync_hour = (Config.SYNC_HOUR + 1) % 24
    scheduler.add_job(
        func=lambda: _run_with_lock('vendor_advisory_sync', vendor_advisory_sync_job, app),
        trigger=CronTrigger(hour=vendor_sync_hour, minute=Config.SYNC_MINUTE, timezone=tz),
        id='vendor_advisory_sync',
        name='Vendor Advisory Sync (OSV, Red Hat, MSRC, Debian)',
        replace_existing=True
    )
    logger.info(f"Vendor advisory sync scheduled at {vendor_sync_hour:02d}:{Config.SYNC_MINUTE:02d}")

    # Schedule license heartbeat (every 12 hours)
    scheduler.add_job(
        func=lambda: _run_with_lock('license_heartbeat', license_heartbeat_job, app),
        trigger=IntervalTrigger(hours=12),
        id='license_heartbeat',
        name='License Server Heartbeat',
        replace_existing=True
    )
    logger.info("License heartbeat scheduled every 12 hours")

    # Schedule hourly usage metering upload to the license server (H7 — Sprint 6).
    # Fires at minute=5 to avoid colliding with the top-of-hour tick that many
    # external services use. The license server floors `ts` to the hour anyway,
    # so the exact firing minute does not affect dedup.
    scheduler.add_job(
        func=lambda: _run_with_lock('usage_metering_upload', usage_metering_upload_job, app),
        trigger=CronTrigger(minute=5, timezone=tz),
        id='usage_metering_upload',
        name='Usage Metering Upload (hourly)',
        replace_existing=True
    )
    logger.info("Usage metering upload scheduled hourly at minute 5")

    # Schedule KB sync (every 12 hours, offset by 5 minutes from license heartbeat)
    scheduler.add_job(
        func=lambda: _run_with_lock('kb_sync', kb_sync_job, app),
        trigger=IntervalTrigger(hours=12, minutes=5),
        id='kb_sync',
        name='SentriKat KB Sync (CPE mappings)',
        replace_existing=True
    )
    logger.info("KB sync scheduled every 12 hours")

    # Schedule NVD CPE dictionary sync (weekly, Sundays at 04:00)
    scheduler.add_job(
        func=lambda: _run_with_lock('nvd_cpe_dict_sync', nvd_cpe_dict_sync_job, app),
        trigger=CronTrigger(day_of_week='sun', hour=4, minute=0, timezone=tz),
        id='nvd_cpe_dict_sync',
        name='NVD CPE Dictionary Sync (weekly)',
        replace_existing=True
    )
    logger.info("NVD CPE dictionary sync scheduled weekly (Sundays 04:00)")

    # Schedule CVE known products cache refresh (every 12 hours)
    # This keeps the _should_skip_software() CVE history guard up to date
    # with newly synced vulnerabilities from CISA KEV and vendor advisories.
    scheduler.add_job(
        func=lambda: _run_with_lock('cve_known_products_refresh', cve_known_products_refresh_job, app),
        trigger=IntervalTrigger(hours=12),
        id='cve_known_products_refresh',
        name='CVE Known Products Cache Refresh',
        replace_existing=True
    )

    # Schedule stuck job recovery (every 10 minutes)
    scheduler.add_job(
        func=lambda: _run_with_lock('stuck_job_recovery', stuck_job_recovery_job, app),
        trigger=IntervalTrigger(minutes=10),
        id='stuck_job_recovery',
        name='Recover Stuck Inventory Jobs',
        replace_existing=True
    )
    logger.info("Stuck job recovery scheduled every 10 minutes")

    # Schedule CVE description parser (every 4 hours)
    # Parses unanalyzed CVE descriptions to extract vendor/product/version
    scheduler.add_job(
        func=lambda: _run_with_lock('cve_description_parser', cve_description_parser_job, app),
        trigger=IntervalTrigger(hours=4),
        id='cve_description_parser',
        name='CVE Description Parser (Awaiting Analysis)',
        replace_existing=True
    )
    logger.info("CVE description parser scheduled every 4 hours")

    # Schedule exploit enrichment (every 6 hours)
    # Checks GitHub for public PoC/exploits for CRITICAL/HIGH CVEs
    scheduler.add_job(
        func=lambda: _run_with_lock('exploit_enrichment', exploit_enrichment_job, app),
        trigger=IntervalTrigger(hours=6),
        id='exploit_enrichment',
        name='Exploit PoC Enrichment (GitHub)',
        replace_existing=True
    )
    logger.info("Exploit enrichment scheduled every 6 hours")

    # Schedule asset type auto-detection (daily at 06:00)
    scheduler.add_job(
        func=lambda: _run_with_lock('auto_detect_asset_type', auto_detect_asset_type_job, app),
        trigger=CronTrigger(hour=6, minute=0, timezone=tz),
        id='auto_detect_asset_type',
        name='Auto-Detect Asset Type (server/workstation/container)',
        replace_existing=True
    )
    logger.info("Asset type auto-detection scheduled daily at 06:00")

    # Schedule agent offline detection (every 5 minutes)
    # Marks agents as offline/stale based on last check-in time
    scheduler.add_job(
        func=lambda: _run_with_lock('agent_offline_detection', agent_offline_detection_job, app),
        trigger=IntervalTrigger(minutes=5),
        id='agent_offline_detection',
        name='Agent Offline Detection',
        replace_existing=True
    )
    logger.info("Agent offline detection scheduled every 5 minutes")

    # Schedule unmapped CPE retry (weekly, Mondays at 05:00 - after Sunday CPE dict sync)
    scheduler.add_job(
        func=lambda: _run_with_lock('unmapped_cpe_retry', unmapped_cpe_retry_job, app),
        trigger=CronTrigger(day_of_week='mon', hour=5, minute=0, timezone=tz),
        id='unmapped_cpe_retry',
        name='Retry CPE Mapping for Unmapped Products',
        replace_existing=True
    )
    logger.info("Unmapped CPE retry scheduled weekly (Mondays 05:00)")

    # Schedule background health checks (every 30 minutes)
    scheduler.add_job(
        func=lambda: _run_with_lock('health_checks', health_check_job, app),
        trigger=IntervalTrigger(minutes=30),
        id='background_health_checks',
        name='Background Health Checks',
        replace_existing=True
    )
    logger.info("Background health checks scheduled every 30 minutes")

    # Schedule independent EUVD sync (every 6 hours)
    # Catches actively exploited zero-days faster than CISA KEV alone.
    # CISA KEV is US-centric and can lag days behind; ENISA EUVD provides
    # European/global coverage for exploited CVEs like CVE-2026-2441.
    scheduler.add_job(
        func=lambda: _run_with_lock('euvd_sync', euvd_sync_job, app),
        trigger=IntervalTrigger(hours=6),
        id='euvd_exploited_sync',
        name='ENISA EUVD Exploited CVE Sync',
        replace_existing=True
    )
    logger.info("ENISA EUVD exploited CVE sync scheduled every 6 hours")

    # Schedule CVSS re-enrichment (every 4 hours)
    # Retries NVD for vulnerabilities that used fallback CVSS sources
    # (CVE.org, ENISA EUVD) due to temporary NVD unavailability
    scheduler.add_job(
        func=lambda: _run_with_lock('cvss_reenrich', cvss_reenrich_job, app),
        trigger=IntervalTrigger(hours=4),
        id='cvss_reenrich',
        name='CVSS Re-enrichment (upgrade fallback sources to NVD)',
        replace_existing=True
    )
    logger.info("CVSS re-enrichment scheduled every 4 hours")

    # Schedule NVD CVE sync (every 2 hours)
    # Imports recent HIGH/CRITICAL CVEs directly from NVD for fast zero-day coverage
    scheduler.add_job(
        func=lambda: _run_with_lock('nvd_cve_sync', nvd_cve_sync_job, app),
        trigger=IntervalTrigger(hours=2),
        id='nvd_cve_sync',
        name='NVD Recent CVE Sync (HIGH/CRITICAL + unscored)',
        replace_existing=True
    )
    logger.info("NVD CVE sync scheduled every 2 hours")

    # Schedule subscription/license expiration checks (daily at 09:00)
    scheduler.add_job(
        func=lambda: _run_with_lock('expiration_check', expiration_check_job, app),
        trigger=CronTrigger(hour=9, minute=0, timezone=tz),
        id='expiration_check',
        name='Subscription/License Expiration Check',
        replace_existing=True
    )
    logger.info("Subscription/license expiration check scheduled at 09:00")

    # Schedule daily orphan-product cleanup (03:00)
    scheduler.add_job(
        func=lambda: _run_with_lock('orphan_products_cleanup', orphan_products_cleanup_job, app),
        trigger=CronTrigger(hour=3, minute=0, timezone=tz),
        id='orphan_products_cleanup',
        name='Orphan Products Cleanup (no org, 90d+ stale)',
        replace_existing=True
    )
    logger.info("Orphan products cleanup scheduled daily at 03:00")

    # Schedule Patch Tuesday digest (2nd Wednesday of every month at 09:00).
    # day='8-14' + day_of_week='wed' ensures we fire on the Wednesday after
    # Microsoft's second-Tuesday patch release — giving MS time to publish,
    # then summarizing the morning after.
    scheduler.add_job(
        func=lambda: _run_with_lock('patch_tuesday_digest', patch_tuesday_digest_job, app),
        trigger=CronTrigger(day='8-14', day_of_week='wed', hour=9, minute=0, timezone=tz),
        id='patch_tuesday_digest',
        name='Patch Tuesday Digest (2nd Wednesday of month at 09:00)',
        replace_existing=True
    )
    logger.info("Patch Tuesday digest scheduled for the 2nd Wednesday of each month at 09:00")

    # Warm up the CVE known products cache on startup
    try:
        if refresh_known_cve_products is not None:
            with app.app_context():
                count = refresh_known_cve_products()
                logger.info(f"CVE known products cache warmed up: {count} entries")
    except Exception as e:
        logger.warning(f"CVE known products cache warmup failed (will retry on first use): {e}")

    scheduler.start()
    # Register job-result listener (M14): persist success/failure metrics
    try:
        scheduler.add_listener(_job_listener, EVENT_JOB_EXECUTED | EVENT_JOB_ERROR)
    except Exception as listener_err:
        logger.warning("Failed to register job listener: %s", listener_err)
    logger.info(f"Scheduler started. CISA KEV sync scheduled at {Config.SYNC_HOUR:02d}:{Config.SYNC_MINUTE:02d}")

    return scheduler

def reschedule_critical_email():
    """Reschedule critical email job when settings change"""
    if not _scheduler or not _app:
        return

    enabled, hour, minute = get_critical_email_settings(_app)
    tz = get_display_timezone(_app)

    # Remove existing job if any
    try:
        _scheduler.remove_job('daily_critical_cve_reminder')
    except Exception:
        pass

    if enabled:
        _scheduler.add_job(
            func=lambda: _run_with_lock('critical_cve_reminder', critical_cve_reminder_job, _app),
            trigger=CronTrigger(hour=hour, minute=minute, timezone=tz),
            id='daily_critical_cve_reminder',
            name='Daily Critical CVE Reminder Emails',
            replace_existing=True
        )
        logger.info(f"Critical CVE reminder rescheduled to {hour:02d}:{minute:02d} ({tz})")
    else:
        logger.info("Critical CVE reminder disabled")

def cpe_nvd_remap_job(app):
    """Periodic CPE remap with NVD Tier 4 fallback for products without CPE.

    F.1 fix (CVE-MATCHING-PIPELINE.md §F.1, audit 2026-05-06): the existing
    post-KEV-sync auto-remap calls batch_apply_cpe_mappings(use_nvd=False)
    which only does Tiers 1+2+3. Products that fail those (e.g., niche
    Windows generics like "Windows SDK", "Universal CRT Headers") never
    get CPE assigned → silent CVE coverage gap.

    This job runs every 4 hours with use_nvd=True + max_nvd_lookups=200
    to fill the long tail. NVD lookups are cached as user-learned mappings
    so the same product won't query NVD twice.

    Rate-limit budget: 200 lookups × 6 runs/day = 1200/day. With NVD API
    key (~144k/day budget) this is <1% of available capacity.
    """
    if batch_apply_cpe_mappings is None:
        logger.warning("CPE NVD remap skipped — batch_apply_cpe_mappings not importable")
        return
    with app.app_context():
        try:
            logger.info("Starting periodic CPE NVD remap (Tier 4 fallback)...")
            updated, total_unmapped = batch_apply_cpe_mappings(
                commit=True, use_nvd=True, max_nvd_lookups=200
            )
            if updated > 0:
                logger.info(
                    f"CPE NVD remap: {updated} products newly mapped "
                    f"(of {total_unmapped} unmapped, {total_unmapped - updated} still unmatched)"
                )
            else:
                logger.info(f"CPE NVD remap: no new mappings (unmapped={total_unmapped})")
        except Exception as e:
            logger.error(f"CPE NVD remap failed: {e}", exc_info=True)


def epss_sync_job(app):
    """Standalone scheduler job for daily EPSS score sync.

    [08.7.1] fix (audit 2026-05-06): originally invoked inline within
    cisa_sync_job, which coupled EPSS updates to CISA KEV sync success.
    If CISA KEV failed (network, NVD rate-limit, Akamai 403) EPSS scores
    would not update. Now runs independently at 04:30 (display timezone)
    so EPSS keeps flowing even when KEV path has issues.

    EPSS feed (FIRST.org) updates daily ~04:00 UTC; running at 04:30 in
    user display timezone covers most cases (worst case slight delay
    for tz west of UTC, fine since EPSS feed is published well in advance).
    """
    if sync_epss_scores is None:
        logger.warning("EPSS sync skipped — sync_epss_scores not importable")
        return
    with app.app_context():
        try:
            logger.info("Starting scheduled EPSS sync...")
            updated, errors, message = sync_epss_scores(force=False)
            logger.info(
                f"EPSS sync completed: {message} (updated={updated}, errors={errors})"
            )
        except Exception as e:
            logger.error(f"EPSS sync failed: {e}", exc_info=True)


def cisa_sync_job(app):
    """Job wrapper to run CISA KEV sync with app context.

    On failure, schedules automatic retries with exponential backoff
    (15min → 30min → 1h → 2h, max 4 retries). On success, clears
    retry state and cancels any pending retry jobs.

    Note ([08.7.1] fix 2026-05-06): EPSS sync was previously invoked here
    inline. It is now an independent scheduler job (epss_sync_job) so
    EPSS doesn't break when CISA KEV sync fails.
    """
    with app.app_context():
        try:
            logger.info("Starting scheduled CISA KEV sync...")
            result = sync_cisa_kev()
            logger.info(f"CISA KEV sync completed: {result}")

            # Rebuild local CPE dictionary from updated vulnerability data
            try:
                logger.info("Rebuilding local CPE dictionary...")
                dict_stats = build_cpe_dictionary()
                logger.info(
                    f"CPE dictionary rebuilt: {dict_stats.get('added', 0)} added, "
                    f"{dict_stats.get('total', 0)} total entries"
                )
            except Exception as cpe_dict_error:
                logger.warning(f"CPE dictionary rebuild failed (non-critical): {cpe_dict_error}")

            # Auto-remap unmapped products after dictionary rebuild
            try:
                updated, total_unmapped = batch_apply_cpe_mappings(
                    commit=True, use_nvd=False, max_nvd_lookups=0
                )
                if updated > 0:
                    logger.info(f"Auto-remapped {updated}/{total_unmapped} products after KEV sync")
            except Exception as remap_err:
                logger.warning(f"Auto-remap after KEV sync failed: {remap_err}")

            # Clean up any bad auto-learned CPE mappings
            try:
                removed = cleanup_bad_auto_mappings()
                if removed > 0:
                    logger.info(f"Cleaned {removed} bad auto_nvd CPE mappings")
            except Exception as cleanup_err:
                logger.warning(f"CPE mapping cleanup failed (non-critical): {cleanup_err}")

            # Sync succeeded - clear retry state and cancel pending retries
            try:
                from app.models import JobState
                retry_count = JobState.get_retry_count('cisa_sync')
                if retry_count > 0:
                    logger.info(f"Sync succeeded after {retry_count} retry attempt(s), resetting retry state")
                JobState.reset_retry('cisa_sync')
            except Exception:
                pass
            _cancel_pending_sync_retries()
            _record_sync_retry_status('idle')

        except Exception as e:
            logger.error(f"CISA KEV sync job failed: {str(e)}")
            _schedule_sync_retry(app)

def _schedule_sync_retry(app):
    """Schedule a CISA sync retry with exponential backoff.

    Backoff schedule: 15min, 30min, 1h, 2h (max 4 retries).
    Uses _run_with_lock to prevent overlap with regular sync.
    Records state in HealthCheckResult for dashboard visibility.
    """
    try:
        from app.models import JobState
        retry_count = JobState.get_retry_count('cisa_sync')
    except Exception:
        retry_count = 0

    if retry_count >= _MAX_SYNC_RETRIES:
        logger.error(
            f"CISA sync failed after {_MAX_SYNC_RETRIES} retries. "
            f"Will retry at next scheduled sync."
        )
        _record_sync_retry_status('exhausted')
        try:
            from app.models import JobState
            JobState.reset_retry('cisa_sync')
        except Exception:
            pass
        return

    delay = _SYNC_RETRY_DELAYS[min(retry_count, len(_SYNC_RETRY_DELAYS) - 1)]
    try:
        from app.models import JobState
        attempt = JobState.increment_retry('cisa_sync')
    except Exception:
        attempt = retry_count + 1

    delay_min = delay // 60
    logger.warning(f"Scheduling CISA sync retry #{attempt}/{_MAX_SYNC_RETRIES} in {delay_min} minutes")
    _record_sync_retry_status('retry_scheduled', attempt, delay)

    if _scheduler:
        run_time = datetime.utcnow() + timedelta(seconds=delay)
        _scheduler.add_job(
            func=lambda: _run_with_lock('cisa_sync', cisa_sync_job, app),
            trigger='date',
            run_date=run_time,
            id=f'cisa_sync_retry_{attempt}',
            name=f'CISA Sync Retry #{attempt} (backoff {delay_min}min)',
            replace_existing=True
        )


def _cancel_pending_sync_retries():
    """Cancel any pending sync retry jobs after a successful sync."""
    if not _scheduler:
        return
    for i in range(1, _MAX_SYNC_RETRIES + 1):
        try:
            _scheduler.remove_job(f'cisa_sync_retry_{i}')
        except Exception:
            pass  # Job doesn't exist, that's fine


def _record_sync_retry_status(state, attempt=0, delay=0):
    """Record sync retry state in HealthCheckResult for dashboard visibility."""
    try:
        from app.models import HealthCheckResult

        if state == 'idle':
            HealthCheckResult.record(
                'sync_retry_status', 'sync', 'ok',
                'Sync operating normally',
                value='OK'
            )
        elif state == 'retry_scheduled':
            delay_min = delay // 60
            HealthCheckResult.record(
                'sync_retry_status', 'sync', 'warning',
                f'Sync failed, retry #{attempt}/{_MAX_SYNC_RETRIES} '
                f'scheduled in {delay_min} minutes',
                value=f'retry #{attempt}',
                details={'attempt': attempt, 'max_retries': _MAX_SYNC_RETRIES,
                         'delay_seconds': delay, 'state': 'retry_scheduled'}
            )
        elif state == 'exhausted':
            HealthCheckResult.record(
                'sync_retry_status', 'sync', 'critical',
                f'Sync failed after {_MAX_SYNC_RETRIES} retries. '
                f'Will retry at next scheduled sync.',
                value='retries exhausted',
                details={'attempt': _MAX_SYNC_RETRIES, 'state': 'exhausted'}
            )
    except Exception as e:
        logger.debug(f"Could not record sync retry status: {e}")


def euvd_sync_job(app):
    """
    Independent ENISA EUVD sync for faster zero-day coverage.

    Runs every 6 hours to catch actively exploited CVEs that aren't yet
    in CISA KEV. Creates new vulnerability entries from EUVD and matches
    them against products. NOW SENDS ALERTS for new matches.
    """
    with app.app_context():
        try:
            from app.cisa_sync import send_alerts_for_new_matches
            from app.filters import rematch_all_products

            sync_start = datetime.utcnow()
            euvd_enriched, euvd_new_count = enrich_with_euvd_exploited()

            if euvd_new_count > 0:
                # Only match newly imported vulnerabilities (not the entire DB)
                from app.models import Vulnerability
                recent_vulns = Vulnerability.query.filter(
                    Vulnerability.created_at >= sync_start
                ).all()
                _, matches = rematch_all_products(
                    target_vulnerabilities=recent_vulns if recent_vulns else None
                )
                logger.info(
                    f"EUVD independent sync: {euvd_new_count} new CVEs, "
                    f"{matches} product matches"
                )
                # Send alerts for new matches from this EUVD sync
                try:
                    send_alerts_for_new_matches(sync_start, source_label='euvd_sync')
                except Exception as alert_err:
                    logger.warning(f"EUVD alert dispatch failed: {alert_err}")
            elif euvd_enriched > 0:
                logger.info(f"EUVD independent sync: enriched {euvd_enriched} existing CVEs")
            else:
                logger.debug("EUVD independent sync: no new exploited CVEs")

        except Exception as e:
            logger.warning(f"EUVD independent sync failed: {e}")


def nvd_cve_sync_job(app):
    """
    Import recent HIGH/CRITICAL CVEs from NVD for fast zero-day coverage.

    Runs every 2 hours. Catches CVEs that CISA KEV and EUVD haven't added yet
    (e.g. CVE-2026-2441 was in NVD the same day Google patched it, but took
    days to appear in CISA KEV). NOW SENDS ALERTS for new matches.
    """
    with app.app_context():
        try:
            from app.cisa_sync import send_alerts_for_new_matches
            from app.filters import rematch_all_products

            sync_start = datetime.utcnow()
            new_count, skipped, errors = sync_nvd_recent_cves()

            if new_count > 0:
                # Only match newly imported vulnerabilities (not the entire DB)
                from app.models import Vulnerability
                recent_vulns = Vulnerability.query.filter(
                    Vulnerability.created_at >= sync_start
                ).all()
                _, matches = rematch_all_products(
                    target_vulnerabilities=recent_vulns if recent_vulns else None
                )
                logger.info(
                    f"NVD CVE sync: {new_count} new CVEs imported, "
                    f"{matches} product matches"
                )
                # Send alerts for new matches from this NVD sync
                try:
                    send_alerts_for_new_matches(sync_start, source_label='nvd_sync')
                except Exception as alert_err:
                    logger.warning(f"NVD sync alert dispatch failed: {alert_err}")
            else:
                logger.debug(f"NVD CVE sync: no new CVEs (skipped {skipped} existing)")

        except Exception as e:
            logger.warning(f"NVD CVE sync job failed: {e}")


def cvss_reenrich_job(app):
    """
    Re-try NVD for vulnerabilities whose CVSS came from fallback sources.

    When NVD is temporarily unavailable, CVSS scores are obtained from
    CVE.org or ENISA EUVD. This job periodically retries NVD to upgrade
    those scores, ensuring we use the most authoritative source.

    Runs every 4 hours. Skips if no fallback-sourced vulns exist.
    """
    with app.app_context():
        try:
            upgraded, checked = reenrich_fallback_cvss(limit=50)
            if checked > 0:
                logger.info(
                    f"CVSS re-enrichment: {upgraded}/{checked} upgraded "
                    f"from fallback to NVD"
                )
            else:
                logger.debug("CVSS re-enrichment: no fallback-sourced vulns to retry")
        except Exception as e:
            logger.warning(f"CVSS re-enrichment job failed (non-critical): {e}")


def ldap_sync_job(app):
    """Job wrapper to run LDAP sync with app context"""
    with app.app_context():
        try:
            logger.info("Starting scheduled LDAP synchronization...")

            # Run sync for all users
            result = LDAPSyncEngine.sync_all_ldap_users(
                organization_id=None,  # Sync all organizations
                initiated_by=None  # System-initiated
            )

            if result.get('success'):
                logger.info(f"LDAP sync completed successfully. Sync ID: {result['sync_id']}, "
                          f"Stats: {result['stats']}, Duration: {result['duration']:.2f}s")
            else:
                logger.error(f"LDAP sync completed with errors: {result.get('error')}")

        except Exception as e:
            logger.error(f"LDAP sync job failed: {str(e)}", exc_info=True)

# For backward compatibility
def sync_job(app):
    """Legacy function name - redirects to cisa_sync_job"""
    cisa_sync_job(app)

def critical_cve_reminder_job(app):
    """Job to send daily reminder emails for unacknowledged critical CVEs"""
    with app.app_context():
        try:
            from app.models import Organization, VulnerabilityMatch, Product
            from app.email_alerts import EmailAlertManager
            from datetime import datetime, timedelta

            logger.info("Starting daily critical CVE reminder emails...")

            # Check if enabled
            enabled_setting = SystemSettings.query.filter_by(key='critical_email_enabled').first()
            if enabled_setting and enabled_setting.value == 'false':
                logger.info("Critical CVE emails disabled in settings, skipping")
                return

            # Get max age setting (default 30 days)
            max_age_setting = SystemSettings.query.filter_by(key='critical_email_max_age_days').first()
            max_age_days = int(max_age_setting.value) if max_age_setting else 30
            cutoff_date = datetime.utcnow() - timedelta(days=max_age_days)

            # Get all organizations with ANY alert setting enabled
            organizations = Organization.query.filter(
                db.or_(
                    Organization.alert_on_critical == True,
                    Organization.alert_on_high == True,
                    Organization.alert_on_ransomware == True,
                    Organization.alert_on_new_cve == True
                )
            ).all()

            total_sent = 0
            total_skipped = 0
            total_errors = 0

            for org in organizations:
                try:
                    # Get unacknowledged vulnerabilities for this org
                    # Filter by match creation date to only include recent ones
                    # Include both legacy organization_id and multi-org table
                    from app.models import product_organizations
                    legacy_ids = db.session.query(Product.id).filter(
                        Product.organization_id == org.id
                    )
                    multi_org_ids = db.session.query(product_organizations.c.product_id).filter(
                        product_organizations.c.organization_id == org.id
                    )
                    org_product_ids = legacy_ids.union(multi_org_ids).scalar_subquery()

                    unack_matches = (
                        VulnerabilityMatch.query
                        .filter(
                            VulnerabilityMatch.product_id.in_(org_product_ids),
                            VulnerabilityMatch.acknowledged == False,
                            VulnerabilityMatch.created_at >= cutoff_date
                        )
                        .all()
                    )

                    if not unack_matches:
                        logger.info(f"No recent unacknowledged CVEs for {org.name}, skipping")
                        total_skipped += 1
                        continue

                    # Send alert - filtering by severity/settings is done in send_critical_cve_alert
                    result = EmailAlertManager.send_critical_cve_alert(org, unack_matches)

                    if result['status'] == 'success':
                        logger.info(f"Sent critical CVE reminder to {org.name}: {result['matches_count']} CVEs to {result['sent_to']} recipients")
                        total_sent += 1
                    elif result['status'] == 'skipped':
                        logger.info(f"Skipped {org.name}: {result['reason']}")
                        total_skipped += 1
                    else:
                        logger.error(f"Failed to send reminder to {org.name}: {result.get('reason')}")
                        total_errors += 1

                except Exception as e:
                    logger.error(f"Error processing reminders for {org.name}: {str(e)}", exc_info=True)
                    total_errors += 1

            logger.info(f"Critical CVE reminder job completed: {total_sent} sent, {total_skipped} skipped, {total_errors} errors")

        except Exception as e:
            logger.error(f"Critical CVE reminder job failed: {str(e)}", exc_info=True)


def stale_match_cleanup_job(app):
    """
    Daily job to remove stale vulnerability matches.

    Throughout the day, CPE data is updated by NVD (2h), EUVD (6h), and
    vendor advisory syncs. These updates may narrow affected version ranges,
    making some existing matches invalid. This job runs cleanup_invalid_matches()
    on the full match table to remove those stale false positives.

    Runs at 01:30 AM — before the 2 AM snapshot so trend data is accurate.
    """
    with app.app_context():
        try:
            from app.filters import cleanup_invalid_matches

            removed = cleanup_invalid_matches()
            if removed > 0:
                logger.info(f"Daily stale match cleanup: removed {removed} invalid matches")
            else:
                logger.debug("Daily stale match cleanup: no stale matches found")
        except Exception as e:
            logger.error(f"Daily stale match cleanup failed: {str(e)}", exc_info=True)


def data_retention_cleanup_job(app):
    """Job to clean up old data based on retention settings"""
    with app.app_context():
        try:
            from app.models import SyncLog
            from app.ldap_models import LDAPAuditLog, LDAPSyncLog
            from app.maintenance import run_all_retention_cleanup
            from app import db
            from datetime import datetime, timedelta

            logger.info("Starting data retention cleanup...")

            # Get retention settings
            audit_retention = SystemSettings.query.filter_by(key='audit_log_retention_days').first()
            sync_retention = SystemSettings.query.filter_by(key='sync_history_retention_days').first()

            audit_days = int(audit_retention.value) if audit_retention else 365
            sync_days = int(sync_retention.value) if sync_retention else 90

            audit_cutoff = datetime.utcnow() - timedelta(days=audit_days)
            sync_cutoff = datetime.utcnow() - timedelta(days=sync_days)

            deleted_counts = {}

            # Clean up old sync logs
            try:
                deleted = SyncLog.query.filter(SyncLog.sync_date < sync_cutoff).delete()
                deleted_counts['sync_logs'] = deleted
            except Exception as e:
                logger.error(f"Error cleaning sync logs: {e}")
                db.session.rollback()
                deleted_counts['sync_logs'] = 0

            # Clean up old LDAP sync logs
            try:
                deleted = LDAPSyncLog.query.filter(LDAPSyncLog.timestamp < sync_cutoff).delete()
                deleted_counts['ldap_sync_logs'] = deleted
            except Exception as e:
                logger.error(f"Error cleaning LDAP sync logs: {e}")
                db.session.rollback()
                deleted_counts['ldap_sync_logs'] = 0

            # Clean up old SaaS structured logs (90-day retention)
            try:
                from app.models import SaasLog
                saas_cutoff = datetime.utcnow() - timedelta(days=90)
                deleted = SaasLog.query.filter(SaasLog.timestamp < saas_cutoff).delete()
                deleted_counts['saas_logs'] = deleted
            except Exception as e:
                logger.error(f"Error cleaning SaaS logs: {e}")
                db.session.rollback()
                deleted_counts['saas_logs'] = 0

            # Note: Application audit logs are file-based (audit.log), managed by log rotation.
            # Only LDAP audit logs are stored in the database.

            # Clean up old LDAP audit logs
            try:
                deleted = LDAPAuditLog.query.filter(LDAPAuditLog.timestamp < audit_cutoff).delete()
                deleted_counts['ldap_audit_logs'] = deleted
            except Exception as e:
                logger.error(f"Error cleaning LDAP audit logs: {e}")
                db.session.rollback()
                deleted_counts['ldap_audit_logs'] = 0

            try:
                db.session.commit()
            except Exception as e:
                logger.error(f"Data retention commit failed: {e}")
                db.session.rollback()

            total_deleted = sum(deleted_counts.values())
            logger.info(f"Data retention cleanup completed. Deleted: {deleted_counts}, Total: {total_deleted}")

            # Run additional retention cleanup (agent events, inventory jobs, alert logs, etc.)
            try:
                retention_results = run_all_retention_cleanup()
                logger.info(f"Additional retention cleanup results: {retention_results}")
            except Exception as e:
                logger.error(f"Additional retention cleanup failed: {e}", exc_info=True)

        except Exception as e:
            logger.error(f"Data retention cleanup failed: {str(e)}", exc_info=True)


def vulnerability_snapshot_job(app):
    """Job to take daily vulnerability snapshots for trend analysis"""
    with app.app_context():
        try:
            from app.models import Organization

            logger.info("Starting daily vulnerability snapshots...")

            # Take snapshots for each organization
            organizations = Organization.query.filter_by(active=True).all()
            snapshot_count = 0
            error_count = 0

            for org in organizations:
                try:
                    VulnerabilitySnapshot.take_snapshot(organization_id=org.id)
                    snapshot_count += 1
                except Exception as e:
                    logger.error(f"Error taking snapshot for org {org.name}: {e}")
                    error_count += 1

            # Also take a global snapshot (organization_id=None)
            try:
                VulnerabilitySnapshot.take_snapshot(organization_id=None)
                snapshot_count += 1
            except Exception as e:
                logger.error(f"Error taking global snapshot: {e}")
                error_count += 1

            logger.info(f"Vulnerability snapshots completed: {snapshot_count} successful, {error_count} errors")

        except Exception as e:
            logger.error(f"Vulnerability snapshot job failed: {str(e)}", exc_info=True)


def process_scheduled_reports_job(app):
    """Job to check and send scheduled reports that are due"""
    with app.app_context():
        try:
            from app.models import ScheduledReport, Organization
            from app.reports import VulnerabilityReportGenerator
            from app.email_alerts import EmailAlertManager
            from datetime import datetime, timedelta

            logger.info("Checking for due scheduled reports...")

            now = datetime.utcnow()

            # Find reports that are due (next_run <= now and enabled)
            due_reports = ScheduledReport.query.filter(
                ScheduledReport.enabled == True,
                ScheduledReport.next_run <= now
            ).all()

            if not due_reports:
                logger.debug("No scheduled reports due")
                return

            sent_count = 0
            error_count = 0

            for report in due_reports:
                try:
                    org = Organization.query.get(report.organization_id)
                    if not org:
                        logger.warning(f"Org not found for report {report.id}")
                        continue

                    # Generate the report
                    generator = VulnerabilityReportGenerator(organization_id=report.organization_id)

                    if report.report_type == 'summary':
                        pdf_buffer = generator.generate_monthly_report()
                    elif report.report_type == 'critical_only':
                        # Generate report with only critical/high priority
                        end_date = datetime.now()
                        start_date = end_date - timedelta(days=30)
                        pdf_buffer = generator.generate_custom_report(
                            start_date=start_date,
                            end_date=end_date,
                            include_acknowledged=False,
                            include_pending=True
                        )
                    else:
                        # Full report
                        end_date = datetime.now()
                        start_date = end_date - timedelta(days=30)
                        pdf_buffer = generator.generate_custom_report(
                            start_date=start_date,
                            end_date=end_date,
                            include_acknowledged=report.include_acknowledged,
                            include_pending=report.include_pending
                        )

                    # Get recipients
                    recipients = report.get_recipient_emails()
                    if not recipients:
                        logger.warning(f"No recipients for report '{report.name}'")
                        report.last_status = 'no_recipients'
                        report.calculate_next_run()
                        db.session.commit()
                        continue

                    # Send email
                    result = EmailAlertManager.send_scheduled_report(
                        recipients=recipients,
                        report_name=report.name,
                        org_name=org.display_name,
                        pdf_buffer=pdf_buffer
                    )

                    # Update report status
                    report.last_sent = now
                    if result.get('success'):
                        report.last_status = 'success'
                        sent_count += 1
                        logger.info(f"Sent report '{report.name}' to {len(recipients)} recipients")
                    else:
                        report.last_status = f"failed: {result.get('error', 'unknown')}"
                        error_count += 1
                        logger.error(f"Failed to send report '{report.name}': {result.get('error')}")

                    # Calculate next run time
                    report.calculate_next_run()
                    db.session.commit()

                except Exception as e:
                    error_count += 1
                    logger.error(f"Error processing report '{report.name}': {e}", exc_info=True)
                    db.session.rollback()
                    try:
                        report.last_status = f"error: {str(e)[:200]}"
                        report.calculate_next_run()
                        db.session.commit()
                    except Exception as retry_err:
                        logger.error(f"Failed to record error for report {report.id}: {retry_err}")
                        db.session.rollback()

            logger.info(f"Scheduled reports processed: {sent_count} sent, {error_count} errors")

        except Exception as e:
            logger.error(f"Scheduled reports job failed: {str(e)}", exc_info=True)


def vendor_advisory_sync_job(app):
    """Job to sync vendor advisories and auto-resolve false-positive CVE matches"""
    with app.app_context():
        try:
            logger.info("Starting vendor advisory sync (OSV.dev, Red Hat, MSRC, Debian)...")
            result = sync_vendor_advisories()
            logger.info(f"Vendor advisory sync completed: "
                        f"{result.get('overrides_created', 0)} overrides created, "
                        f"{result.get('matches_resolved', 0)} false positives resolved, "
                        f"{result.get('feeds_checked', 0)} feeds checked")

            if result.get('errors'):
                for err in result['errors']:
                    logger.warning(f"Vendor advisory feed error: {err}")

        except Exception as e:
            logger.error(f"Vendor advisory sync job failed: {str(e)}", exc_info=True)


def license_heartbeat_job(app):
    """Job to send license heartbeat to the license server"""
    with app.app_context():
        try:
            logger.info("Sending license heartbeat...")
            result = license_heartbeat()
            if result.get('success'):
                logger.info(f"License heartbeat OK: {result.get('message', '')}")
            else:
                logger.warning(f"License heartbeat failed: {result.get('error', 'unknown')}")

        except Exception as e:
            logger.error(f"License heartbeat job failed: {str(e)}", exc_info=True)


def usage_metering_upload_job(app):
    """Hourly job: push per-tenant usage snapshots to the license server (H7)."""
    with app.app_context():
        try:
            from app.metering import send_usage_to_license_server
            logger.info("Starting hourly usage metering upload...")
            results = send_usage_to_license_server()
            if not results:
                logger.info("Usage metering: no active tenants to report")
                return
            ok = sum(1 for r in results if r.get('success'))
            fail = len(results) - ok
            logger.info(
                f"Usage metering upload complete: {ok} ok, {fail} failed "
                f"(of {len(results)} tenants)"
            )
        except Exception as e:
            logger.error(f"Usage metering upload job failed: {e}", exc_info=True)


def nvd_cpe_dict_sync_job(app):
    """Job to sync NVD CPE dictionary, then auto-remap unmapped products."""
    with app.app_context():
        try:
            from app.cpe_dictionary import sync_nvd_cpe_dictionary

            logger.info("Starting NVD CPE dictionary sync (bulk + incremental)...")
            result = sync_nvd_cpe_dictionary()
            logger.info(
                f"NVD CPE dictionary sync complete: "
                f"bulk({result.get('bulk_added', 0)} new), "
                f"incremental({result.get('incremental_added', 0)} new), "
                f"{result.get('total', 0)} total entries"
            )

            # Auto-remap unmapped products using the updated dictionary
            # This is the key step - without it, new dictionary entries sit unused
            try:
                from app.cpe_mapping import batch_apply_cpe_mappings
                updated, total_unmapped = batch_apply_cpe_mappings(
                    commit=True, use_nvd=True, max_nvd_lookups=100
                )
                if updated > 0:
                    logger.info(
                        f"Auto-remapped {updated}/{total_unmapped} unmapped products "
                        f"after dictionary sync"
                    )
            except Exception as remap_err:
                logger.warning(f"Auto-remap after dictionary sync failed: {remap_err}")

            # Promote proven auto_nvd mappings to KB-eligible
            try:
                from app.kb_sync import promote_proven_auto_mappings
                promoted = promote_proven_auto_mappings()
                if promoted > 0:
                    logger.info(f"Promoted {promoted} proven auto_nvd mappings to KB-eligible")
            except Exception as promo_err:
                logger.warning(f"Auto-promote failed: {promo_err}")

        except Exception as e:
            logger.error(f"NVD CPE dictionary sync failed: {str(e)}", exc_info=True)


def kb_sync_job(app):
    """Job to sync CPE mappings with the SentriKat Knowledge Base."""
    with app.app_context():
        try:
            logger.info("Starting KB sync...")
            result = kb_sync()
            if result.get('success'):
                push = result.get('results', {}).get('push', {})
                pull = result.get('results', {}).get('pull', {})
                logger.info(
                    f"KB sync OK: pushed {push.get('pushed', 0)}, "
                    f"imported {pull.get('imported', 0)}"
                )
            else:
                logger.warning(f"KB sync had issues: {result.get('error', 'unknown')}")

        except Exception as e:
            logger.error(f"KB sync job failed: {str(e)}", exc_info=True)


def cve_known_products_refresh_job(app):
    """
    Refresh the CVE known products cache.

    This keeps the _should_skip_software() CVE history guard up to date
    with newly synced vulnerability data from CISA KEV and vendor advisories.
    Runs every 12 hours (after CISA sync has completed).
    """
    with app.app_context():
        try:
            from app.cve_known_products import refresh_known_cve_products
            count = refresh_known_cve_products()
            logger.info(f"CVE known products cache refreshed: {count} entries")
        except Exception as e:
            logger.error(f"CVE known products refresh failed: {str(e)}", exc_info=True)


def stuck_job_recovery_job(app):
    """
    Recover stuck inventory jobs.

    If a background worker crashes mid-processing, the job stays in 'processing'
    status forever. This job resets them to 'pending' for retry (up to 3 attempts)
    or marks them as 'failed' if max retries exceeded.
    Runs every 10 minutes.
    """
    with app.app_context():
        try:
            from app.models import InventoryJob
            from app.agent_api import MAX_JOB_RETRIES, _active_job_ids, _active_job_ids_lock

            cutoff = datetime.utcnow() - timedelta(minutes=30)
            stuck_jobs = InventoryJob.query.filter(
                InventoryJob.status == 'processing',
                InventoryJob.started_at < cutoff
            ).all()

            # Get set of actively processing job IDs to avoid false positives
            with _active_job_ids_lock:
                active_ids = set(_active_job_ids)

            recovered = 0
            failed = 0
            skipped = 0
            for job in stuck_jobs:
                # Skip jobs that are actively being processed by the worker pool
                if job.id in active_ids:
                    skipped += 1
                    continue

                retry_count = job.retry_count if hasattr(job, 'retry_count') and job.retry_count else 0
                if retry_count >= MAX_JOB_RETRIES:
                    logger.warning(f"Job {job.id} exceeded max retries ({MAX_JOB_RETRIES}), marking as failed")
                    job.status = 'failed'
                    job.error_message = f'Failed after {MAX_JOB_RETRIES} retry attempts (stuck in processing)'
                    job.completed_at = datetime.utcnow()
                    failed += 1
                else:
                    logger.warning(f"Recovering stuck job {job.id} (stuck since {job.started_at}, retry {retry_count + 1}/{MAX_JOB_RETRIES})")
                    job.status = 'pending'
                    job.started_at = None
                    job.error_message = f'Recovered from stuck state (retry {retry_count + 1})'
                    if hasattr(job, 'retry_count'):
                        job.retry_count = retry_count + 1
                    recovered += 1
            if stuck_jobs:
                db.session.commit()
                logger.info(f"Stuck job recovery: {recovered} recovered, {failed} permanently failed, {skipped} still active")
        except Exception as e:
            logger.error(f"Stuck job recovery failed: {str(e)}", exc_info=True)
            try:
                db.session.rollback()
            except Exception:
                pass


def cve_description_parser_job(app):
    """Parse CVE descriptions for 'Awaiting Analysis' CVEs to extract vendor/product."""
    with app.app_context():
        try:
            from app.cve_description_parser import enrich_unanalyzed_cves
            count = enrich_unanalyzed_cves()
            logger.info(f"CVE description parser completed: {count} CVEs enriched")
        except Exception as e:
            logger.error(f"CVE description parser failed: {e}")


def exploit_enrichment_job(app):
    """Enrich CVEs with public exploit availability data from GitHub."""
    with app.app_context():
        try:
            from app.exploit_enrichment import enrich_exploit_data
            count = enrich_exploit_data()
            logger.info(f"Exploit enrichment completed: {count} CVEs enriched")
        except Exception as e:
            logger.error(f"Exploit enrichment failed: {e}")


def auto_detect_asset_type_job(app):
    """
    Auto-detect asset_type from os_name/os_version for assets still set to default.

    Many agents report OS info but asset_type defaults to 'server'. This job
    infers the correct type from OS strings:
    - Windows 10/11 → workstation
    - Windows Server → server
    - macOS → workstation
    - Ubuntu Desktop → workstation
    - Container images → container

    Runs once daily. Only updates assets where asset_type was never manually set.
    """
    with app.app_context():
        try:
            from app.models import Asset

            # Only fix assets with default 'server' type that have OS info
            assets = Asset.query.filter(
                Asset.active == True,
                Asset.os_version.isnot(None),
                # Only auto-detect for assets still at default 'server' type
                # that have never been manually categorized
                db.or_(
                    Asset.asset_type == 'server',
                    Asset.asset_type.is_(None)
                )
            ).all()

            updated = 0
            for asset in assets:
                os_ver = (asset.os_version or '').lower()
                os_name = (asset.os_name or '').lower()
                detected_type = None

                # Windows detection
                if 'windows' in os_name or 'windows' in os_ver:
                    if any(w in os_ver for w in ['windows 10', 'windows 11', 'windows 8']):
                        detected_type = 'workstation'
                    elif 'server' in os_ver:
                        detected_type = 'server'
                # macOS is always a workstation
                elif 'macos' in os_name or 'darwin' in os_name or 'mac os' in os_ver:
                    detected_type = 'workstation'
                # Linux desktop detection
                elif 'ubuntu' in os_name or 'ubuntu' in os_ver:
                    if 'desktop' in os_ver:
                        detected_type = 'workstation'
                # Container detection (if hostname looks like a container ID)
                elif asset.hostname and len(asset.hostname) == 12 and all(
                    c in '0123456789abcdef' for c in asset.hostname
                ):
                    detected_type = 'container'

                if detected_type and detected_type != asset.asset_type:
                    asset.asset_type = detected_type
                    updated += 1

            if updated:
                db.session.commit()
                logger.info(f"Auto-detected asset type for {updated} assets")
        except Exception as e:
            logger.error(f"Asset type auto-detection failed: {str(e)}", exc_info=True)
            try:
                db.session.rollback()
            except Exception:
                pass


def unmapped_cpe_retry_job(app):
    """
    Retry CPE mapping for products that have no CPE assigned.

    Products without CPE get zero vulnerability matches (blind spots).
    This weekly job retries the 3-tier mapping for unmapped products,
    which may now succeed because:
    - New entries in local CPE dictionary (from weekly NVD sync)
    - New curated mappings (from KB sync)
    - New regex patterns (from app updates)

    Runs weekly on Mondays at 05:00 (after Sunday's NVD CPE dict sync).
    """
    with app.app_context():
        try:
            from app.models import Product

            unmapped_count = Product.query.filter(
                Product.active == True,
                db.or_(
                    Product.cpe_vendor.is_(None),
                    Product.cpe_vendor == ''
                )
            ).count()

            if unmapped_count == 0:
                logger.info("No unmapped products to retry CPE for")
                return

            logger.info(f"Retrying CPE mapping for {unmapped_count} unmapped products")
            result = batch_apply_cpe_mappings(commit=True, use_nvd=True, max_nvd_lookups=100)
            logger.info(f"CPE retry complete: {result}")
        except Exception as e:
            logger.error(f"Unmapped CPE retry failed: {str(e)}", exc_info=True)


def agent_offline_detection_job(app):
    """
    Detect agents that have gone offline and log status change events.

    Runs every 5 minutes. Transitions:
    - online → offline: no check-in for 15 minutes
    - online/offline → stale: no check-in for 14 days (configurable)

    Logs AgentEvent for each status transition so the Agent Activity page
    and activity log capture offline/reconnection events automatically.
    """
    with app.app_context():
        try:
            from app.models import Asset, AgentEvent
            from sqlalchemy import or_

            now = datetime.utcnow()
            offline_threshold = now - timedelta(minutes=15)
            stale_threshold = now - timedelta(days=14)

            # Find assets going offline (online → offline)
            going_offline = Asset.query.filter(
                Asset.status == 'online',
                Asset.last_checkin < offline_threshold
            ).all()

            for asset in going_offline:
                asset.status = 'offline'
                try:
                    AgentEvent.log_event(
                        organization_id=asset.organization_id,
                        event_type='status_changed',
                        asset_id=asset.id,
                        old_value='online',
                        new_value='offline',
                        details=json.dumps({
                            'reason': 'no_heartbeat',
                            'last_checkin': asset.last_checkin.isoformat() if asset.last_checkin else None,
                            'threshold_minutes': 15
                        })
                    )
                except Exception:
                    pass

            # Find assets going stale (online/offline → stale)
            going_stale = Asset.query.filter(
                Asset.status.in_(['online', 'offline']),
                or_(Asset.last_checkin.is_(None), Asset.last_checkin < stale_threshold)
            ).all()

            for asset in going_stale:
                old_status = asset.status
                asset.status = 'stale'
                try:
                    AgentEvent.log_event(
                        organization_id=asset.organization_id,
                        event_type='status_changed',
                        asset_id=asset.id,
                        old_value=old_status,
                        new_value='stale',
                        details=json.dumps({
                            'reason': 'no_heartbeat',
                            'last_checkin': asset.last_checkin.isoformat() if asset.last_checkin else None,
                            'threshold_days': 14
                        })
                    )
                except Exception:
                    pass

            if going_offline or going_stale:
                db.session.commit()
                logger.info(
                    f"Agent offline detection: {len(going_offline)} marked offline, "
                    f"{len(going_stale)} marked stale"
                )

        except Exception as e:
            logger.error(f"Agent offline detection failed: {str(e)}", exc_info=True)
            try:
                db.session.rollback()
            except Exception:
                pass


def health_check_job(app):
    """
    Run all enabled background health checks.
    Results are stored in HealthCheckResult and notifications sent for problems.
    """
    with app.app_context():
        try:
            results = run_all_health_checks()
            if results.get('skipped'):
                logger.debug("Health checks skipped (disabled)")
                return
            problems = sum(1 for v in results.values() if v in ('warning', 'critical', 'error'))
            logger.info(f"Health checks completed: {len(results)} checks, {problems} issues")
        except Exception as e:
            logger.error(f"Health check job failed: {str(e)}", exc_info=True)


# ============================================================================
# Subscription / License Expiration Notifications
# ============================================================================

# Thresholds: send notification at these days before expiry
EXPIRY_THRESHOLDS = [30, 14, 7, 3, 1]


def expiration_check_job(app):
    """Check for expiring subscriptions (SaaS) and licenses (on-premise).

    Sends email notifications to org admins at 30/14/7/3/1 days before expiry.
    Tracks last notification sent to avoid duplicate alerts on the same threshold.
    """
    with app.app_context():
        try:
            from app.saas import is_saas_mode
            if is_saas_mode():
                _check_saas_expirations()
            else:
                _check_onprem_expiration()
        except Exception as e:
            logger.error(f"Expiration check job failed: {e}", exc_info=True)


def _check_saas_expirations():
    """Check all SaaS tenant subscriptions for upcoming expiration."""
    from app.models import Organization, Subscription, User
    from app.email_provider import send_email, render_email_html
    from app.settings_api import get_setting
    from datetime import datetime, timedelta

    now = datetime.utcnow()

    subscriptions = Subscription.query.filter(
        Subscription.status.in_(['active', 'trialing']),
        Subscription.current_period_end.isnot(None)
    ).all()

    for sub in subscriptions:
        days_left = (sub.current_period_end - now).days
        org = Organization.query.get(sub.organization_id)
        if not org or not org.active:
            continue

        # Find which threshold we're at
        threshold = None
        for t in EXPIRY_THRESHOLDS:
            if days_left <= t:
                threshold = t
                break

        if threshold is None:
            continue  # more than 30 days left

        # Check if we already sent for this threshold (use settings as marker)
        marker_key = f'expiry_notified_{threshold}d'
        already_sent = get_setting(marker_key, 'false', organization_id=org.id)
        if already_sent == 'true':
            continue

        # Get org admin emails
        admins = User.query.filter_by(
            organization_id=org.id, is_active=True
        ).filter(
            (User.role == 'org_admin') | (User.role == 'super_admin')
        ).all()
        recipients = [a.email for a in admins if a.email]
        if not recipients:
            continue

        # Build notification
        plan_name = sub.plan.display_name if sub.plan else 'your plan'
        is_trial = sub.status == 'trialing'

        if is_trial:
            subject = f"SentriKat: Your trial expires in {days_left} day{'s' if days_left != 1 else ''}"
            body_content = f"""
            <p style="font-size: 16px; color: #374151;">Your <strong>{plan_name}</strong> trial expires in <strong>{days_left} day{'s' if days_left != 1 else ''}</strong>.</p>
            <p style="color: #6b7280;">After the trial ends, your account will be downgraded to the Free plan with limited features.</p>
            <div style="text-align: center; margin: 24px 0;">
                <a href="https://sentrikat.com/pricing" style="display: inline-block; background: #1e40af; color: white; text-decoration: none; padding: 12px 28px; border-radius: 8px; font-weight: 600;">
                    Upgrade Now
                </a>
            </div>"""
        else:
            subject = f"SentriKat: Your {plan_name} subscription renews in {days_left} day{'s' if days_left != 1 else ''}"
            if sub.cancel_at_period_end:
                subject = f"SentriKat: Your {plan_name} subscription ends in {days_left} day{'s' if days_left != 1 else ''}"
                body_content = f"""
                <p style="font-size: 16px; color: #374151;">Your <strong>{plan_name}</strong> subscription is set to cancel and will end in <strong>{days_left} day{'s' if days_left != 1 else ''}</strong>.</p>
                <p style="color: #6b7280;">After cancellation, your account will be downgraded to the Free plan. Your data will be preserved for 30 days.</p>
                <div style="text-align: center; margin: 24px 0;">
                    <a href="https://sentrikat.com/pricing" style="display: inline-block; background: #1e40af; color: white; text-decoration: none; padding: 12px 28px; border-radius: 8px; font-weight: 600;">
                        Reactivate Subscription
                    </a>
                </div>"""
            else:
                body_content = f"""
                <p style="font-size: 16px; color: #374151;">Your <strong>{plan_name}</strong> subscription will automatically renew in <strong>{days_left} day{'s' if days_left != 1 else ''}</strong>.</p>
                <p style="color: #6b7280;">No action needed — your service will continue uninterrupted. Review your plan anytime in Settings → Subscription.</p>"""

        html = render_email_html(body_content, org=org, subject=subject)

        result = send_email(
            to=recipients,
            subject=subject,
            html_body=html,
            organization_id=org.id,
            email_type='system',
        )

        if result.get('success'):
            # Mark as sent
            from app.settings_api import set_setting
            set_setting(marker_key, 'true', 'expiration', organization_id=org.id)
            logger.info(f"Expiration notice sent to org {org.name}: {days_left}d left ({sub.status})")

        # Reset lower thresholds when a higher one triggers
        # (so we re-notify at each threshold)
        for lower_t in EXPIRY_THRESHOLDS:
            if lower_t < threshold:
                lower_key = f'expiry_notified_{lower_t}d'
                try:
                    from app.models import SystemSettings
                    existing = SystemSettings.query.filter_by(
                        key=lower_key, organization_id=org.id
                    ).first()
                    if existing:
                        existing.value = 'false'
                except Exception:
                    logger.warning(
                        "Failed to clear onprem expiration setting "
                        "for org %s", getattr(org, 'id', '?'),
                        exc_info=True,
                    )

    try:
        from app import db
        db.session.commit()
    except Exception:
        logger.warning(
            "Failed to commit onprem expiration clear", exc_info=True
        )
        try:
            db.session.rollback()
        except Exception:
            pass


def _check_onprem_expiration():
    """Check on-premise license for upcoming expiration."""
    from app.licensing import get_license
    from app.models import User
    from app.email_provider import send_email, render_email_html
    from app.settings_api import get_setting, set_setting

    license_info = get_license()
    if not license_info or not license_info.expires_at:
        return  # perpetual license or no license

    days_left = license_info.days_until_expiry
    if days_left is None:
        return

    # Find threshold
    threshold = None
    for t in EXPIRY_THRESHOLDS:
        if days_left <= t:
            threshold = t
            break

    if threshold is None:
        return

    marker_key = f'license_expiry_notified_{threshold}d'
    if get_setting(marker_key, 'false') == 'true':
        return

    # Get super_admin emails
    admins = User.query.filter_by(is_active=True).filter(
        (User.role == 'super_admin') | (User.is_admin == True)
    ).all()
    recipients = [a.email for a in admins if a.email]
    if not recipients:
        return

    edition = license_info.edition or 'Professional'
    expires_str = license_info.expires_at.strftime('%d %B %Y') if hasattr(license_info.expires_at, 'strftime') else str(license_info.expires_at)

    if license_info.is_expired:
        subject = f"SentriKat: Your {edition} license has EXPIRED"
        body_content = f"""
        <div style="background: #fef2f2; border-left: 4px solid #dc2626; padding: 16px; margin-bottom: 20px; border-radius: 4px;">
            <p style="margin: 0; color: #991b1b; font-weight: 600;">Your {edition} license expired on {expires_str}.</p>
        </div>
        <p style="color: #374151;">SentriKat is now running in Community mode with limited features. Renew your license to restore full functionality.</p>
        <div style="text-align: center; margin: 24px 0;">
            <a href="https://sentrikat.com/pricing" style="display: inline-block; background: #dc2626; color: white; text-decoration: none; padding: 12px 28px; border-radius: 8px; font-weight: 600;">
                Renew License
            </a>
        </div>"""
    else:
        subject = f"SentriKat: Your {edition} license expires in {days_left} day{'s' if days_left != 1 else ''}"
        urgency_color = '#dc2626' if days_left <= 3 else '#f59e0b' if days_left <= 14 else '#3b82f6'
        body_content = f"""
        <p style="font-size: 16px; color: #374151;">Your <strong>{edition}</strong> license expires on <strong>{expires_str}</strong> (<span style="color: {urgency_color}; font-weight: 600;">{days_left} day{'s' if days_left != 1 else ''} remaining</span>).</p>
        <p style="color: #6b7280;">After expiration, SentriKat will revert to Community mode. Renew before the expiry date to avoid service interruption.</p>
        <div style="text-align: center; margin: 24px 0;">
            <a href="https://sentrikat.com/pricing" style="display: inline-block; background: #1e40af; color: white; text-decoration: none; padding: 12px 28px; border-radius: 8px; font-weight: 600;">
                Renew License
            </a>
        </div>"""

    html = render_email_html(body_content, subject=subject)

    result = send_email(
        to=recipients,
        subject=subject,
        html_body=html,
        email_type='system',
    )

    if result.get('success'):
        set_setting(marker_key, 'true', 'expiration')
        logger.info(f"License expiration notice sent: {days_left}d left")

    # Reset lower thresholds
    for lower_t in EXPIRY_THRESHOLDS:
        if lower_t < threshold:
            set_setting(f'license_expiry_notified_{lower_t}d', 'false', 'expiration')


# ---------------------------------------------------------------------------
# Patch Tuesday digest job
# ---------------------------------------------------------------------------

def _check_email_quota_for_org(org_id):
    """Thin wrapper around email_provider._check_rate_limit for digest jobs.

    Returns True if the org has quota remaining (or quotas are not enforced).
    Centralized here so all report jobs share the same gate.
    """
    try:
        from app.email_provider import _check_rate_limit
        allowed, remaining, limit = _check_rate_limit(org_id)
        return allowed
    except Exception as e:
        # If the quota check itself fails, err on the side of attempting
        # the send — the provider layer will enforce again anyway.
        logger.warning(f"Email quota check failed for org {org_id}: {e}")
        return True


def build_patch_tuesday_digest_data(organization, since_dt=None, until_dt=None):
    """
    Build the summary dict for the Patch Tuesday digest for one org.

    Queries vulnerabilities that:
      - were PUBLISHED (CISA KEV date_added) in the last 7 days
      - match the organization's tracked products (via product_organizations)
      - AND (severity is HIGH/CRITICAL OR vendor is Microsoft OR is_actively_exploited)

    Uses a single joined query with eager-loaded Vulnerability to avoid
    N+1 selects. Returns a dict ready to pass to send_patch_tuesday_digest.
    """
    from app.models import (
        Vulnerability, VulnerabilityMatch, Product, product_organizations
    )
    from sqlalchemy.orm import joinedload
    from sqlalchemy import func as sa_func, or_ as sa_or, distinct

    now = datetime.utcnow()
    until_dt = until_dt or now
    since_dt = since_dt or (until_dt - timedelta(days=7))

    # Month/year label for the subject line
    month_year = until_dt.strftime('%B %Y')

    # Subquery: product IDs tracked by this org (legacy + multi-org).
    legacy_ids = db.session.query(Product.id).filter(
        Product.organization_id == organization.id
    )
    multi_org_ids = db.session.query(product_organizations.c.product_id).filter(
        product_organizations.c.organization_id == organization.id
    )
    org_product_ids = legacy_ids.union(multi_org_ids).scalar_subquery()

    # Single query, eager-load the Vulnerability relationship to avoid N+1.
    base_query = (
        db.session.query(VulnerabilityMatch, Vulnerability, Product)
        .join(Vulnerability, VulnerabilityMatch.vulnerability_id == Vulnerability.id)
        .join(Product, VulnerabilityMatch.product_id == Product.id)
        .filter(
            VulnerabilityMatch.product_id.in_(org_product_ids),
            Vulnerability.date_added >= since_dt.date(),
            Vulnerability.date_added <= until_dt.date(),
            sa_or(
                Vulnerability.severity.in_(['HIGH', 'CRITICAL']),
                sa_func.lower(Vulnerability.vendor_project).like('microsoft%'),
                Vulnerability.is_actively_exploited.is_(True),
            ),
        )
    )

    rows = base_query.all()

    # Deduplicate on CVE id (same CVE may match multiple tracked products).
    by_cve = {}
    affected_product_ids = set()
    for match, vuln, product in rows:
        affected_product_ids.add(product.id)
        if vuln.cve_id not in by_cve:
            by_cve[vuln.cve_id] = (vuln, product)

    unique_vulns = [t[0] for t in by_cve.values()]

    # Severity buckets
    critical_count = sum(1 for v in unique_vulns if (v.severity or '').upper() == 'CRITICAL')
    high_count = sum(1 for v in unique_vulns if (v.severity or '').upper() == 'HIGH')
    medium_count = sum(1 for v in unique_vulns if (v.severity or '').upper() == 'MEDIUM')
    low_count = sum(1 for v in unique_vulns if (v.severity or '').upper() == 'LOW')

    # Top 10 by CVSS score (None scores treated as 0 so they sort last).
    top_sorted = sorted(
        unique_vulns,
        key=lambda v: (v.cvss_score if v.cvss_score is not None else -1.0),
        reverse=True,
    )[:10]

    top_list = []
    for v in top_sorted:
        linked_product = by_cve[v.cve_id][1]
        top_list.append({
            'cve_id': v.cve_id,
            'vendor': v.vendor_project or linked_product.vendor,
            'product': v.product or linked_product.product_name,
            'severity': v.severity or 'UNKNOWN',
            'cvss_score': v.cvss_score,
            'is_exploited': bool(v.is_actively_exploited),
            'description': (v.short_description or '')[:300],
        })

    return {
        'month_year': month_year,
        'total_new': len(unique_vulns),
        'critical_count': critical_count,
        'high_count': high_count,
        'medium_count': medium_count,
        'low_count': low_count,
        'affected_products': len(affected_product_ids),
        'top_vulns': top_list,
        'since': since_dt.isoformat(),
        'until': until_dt.isoformat(),
    }


def patch_tuesday_digest_job(app):
    """
    Monthly Patch Tuesday digest job.

    Runs on the Wednesday after Microsoft's second-Tuesday patch release.
    For each active organization:
      - Queries new CVEs (published in last 7 days) matching tracked products
        with severity HIGH/CRITICAL, Microsoft vendor, or actively exploited.
      - Respects org alert preferences (alert_on_critical).
      - Checks per-org email quota before sending.
      - Sends an HTML digest to all org admins via email_service.
    """
    with app.app_context():
        try:
            from app.models import Organization
            from app.email_service import send_patch_tuesday_digest

            logger.info("Starting Patch Tuesday digest job...")

            organizations = Organization.query.filter_by(active=True).all()

            total_sent = 0
            total_skipped = 0
            total_errors = 0

            for org in organizations:
                try:
                    digest_data = build_patch_tuesday_digest_data(org)

                    has_high_or_critical = (
                        digest_data['critical_count'] > 0
                        or digest_data['high_count'] > 0
                    )

                    # Rate limiting / quota rule: if the org has disabled
                    # critical alerts AND there are no high/critical CVEs,
                    # skip the send to avoid spamming disabled orgs.
                    if not getattr(org, 'alert_on_critical', True) and not has_high_or_critical:
                        logger.info(
                            f"Patch Tuesday: skipping {org.name} "
                            f"(alerts disabled, no high/critical CVEs)"
                        )
                        total_skipped += 1
                        continue

                    # Nothing to report at all? Skip silently.
                    if digest_data['total_new'] == 0:
                        logger.info(
                            f"Patch Tuesday: no new matching CVEs for "
                            f"{org.name}, skipping"
                        )
                        total_skipped += 1
                        continue

                    # Quota gate — same pattern as EmailAlertManager.
                    if not _check_email_quota_for_org(org.id):
                        logger.warning(
                            f"Patch Tuesday: email quota exhausted for "
                            f"{org.name}, skipping digest"
                        )
                        total_skipped += 1
                        continue

                    result = send_patch_tuesday_digest(org, digest_data)
                    if result.get('success'):
                        total_sent += 1
                        logger.info(
                            f"Patch Tuesday digest sent to {org.name}: "
                            f"{digest_data['total_new']} CVEs, "
                            f"{result.get('recipients', 0)} recipients"
                        )
                    else:
                        total_errors += 1
                        logger.error(
                            f"Patch Tuesday digest failed for {org.name}: "
                            f"{result.get('error')}"
                        )

                except Exception as e:
                    total_errors += 1
                    logger.error(
                        f"Error building Patch Tuesday digest for "
                        f"{org.name}: {e}",
                        exc_info=True,
                    )

            logger.info(
                f"Patch Tuesday digest job completed: "
                f"{total_sent} sent, {total_skipped} skipped, "
                f"{total_errors} errors"
            )

        except Exception as e:
            logger.error(
                f"Patch Tuesday digest job failed: {e}",
                exc_info=True,
            )


def cleanup_orphan_products(stale_days=90):
    """Delete products with no org associations and no checkin in N+ days.

    Products can become orphans when:
      - their last linked organization is deleted
      - the admin removes the org association manually
      - auto-approve created a product that was never attached to an org

    We only delete if the product is BOTH orphaned AND stale (no agent
    report in the last ``stale_days`` days, or never).  This avoids
    deleting freshly-created products that are about to be attached to
    an org by the import queue workflow.

    Returns the number of products deleted.
    """
    try:
        from app.models import Product
    except ImportError:
        logger.warning("cleanup_orphan_products: Product model unavailable")
        return 0

    cutoff = datetime.utcnow() - timedelta(days=stale_days)
    try:
        orphans = Product.query.filter(
            ~Product.organizations.any(),
            or_(
                Product.last_agent_report.is_(None),
                Product.last_agent_report < cutoff,
            ),
        ).all()
    except Exception as e:
        logger.error("cleanup_orphan_products query failed: %s", e, exc_info=True)
        return 0

    deleted = 0
    for p in orphans:
        try:
            logger.info(
                "Deleting orphan product id=%s vendor=%s name=%s",
                p.id, p.vendor, p.product_name,
            )
            db.session.delete(p)
            deleted += 1
        except Exception as del_err:
            logger.warning("Failed to delete orphan product id=%s: %s", p.id, del_err)

    if deleted:
        try:
            db.session.commit()
        except Exception as commit_err:
            logger.error("cleanup_orphan_products commit failed: %s", commit_err, exc_info=True)
            db.session.rollback()
            return 0

    return deleted


def orphan_products_cleanup_job(app):
    """Scheduler wrapper for cleanup_orphan_products with app context."""
    with app.app_context():
        try:
            count = cleanup_orphan_products()
            logger.info(f"Orphan product cleanup completed: {count} products deleted")
            return count
        except Exception as e:
            logger.error(f"Orphan product cleanup job failed: {e}", exc_info=True)
            return 0
