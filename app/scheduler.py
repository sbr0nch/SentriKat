from apscheduler.schedulers.background import BackgroundScheduler
from apscheduler.triggers.cron import CronTrigger
from apscheduler.triggers.interval import IntervalTrigger
from app.cisa_sync import sync_cisa_kev
from app import db
from config import Config
from datetime import datetime, timedelta
import json
import logging
import os
import threading

logger = logging.getLogger(__name__)

_job_locks = {}
_job_locks_lock = threading.Lock()


def _run_with_lock(job_name, func, *args, **kwargs):
    """Run a job function with a lock to prevent overlap."""
    with _job_locks_lock:
        if _job_locks.get(job_name):
            logger.info(f"Job '{job_name}' already running, skipping this execution")
            return
        _job_locks[job_name] = True
    try:
        return func(*args, **kwargs)
    finally:
        with _job_locks_lock:
            _job_locks[job_name] = False

# Store scheduler globally so we can reschedule jobs when settings change
_scheduler = None
_app = None

def get_critical_email_settings(app):
    """Get critical email settings from database"""
    with app.app_context():
        from app.models import SystemSettings

        enabled_setting = SystemSettings.query.filter_by(key='critical_email_enabled').first()
        time_setting = SystemSettings.query.filter_by(key='critical_email_time').first()

        enabled = enabled_setting.value == 'true' if enabled_setting else True
        email_time = time_setting.value if time_setting else '09:00'

        try:
            hour, minute = map(int, email_time.split(':'))
        except:
            hour, minute = 9, 0

        return enabled, hour, minute

def start_scheduler(app):
    """Start the background scheduler for scheduled jobs"""
    global _scheduler, _app
    _app = app

    scheduler = BackgroundScheduler()
    _scheduler = scheduler

    # Schedule daily CISA KEV sync at configured time
    scheduler.add_job(
        func=lambda: _run_with_lock('cisa_sync', cisa_sync_job, app),
        trigger=CronTrigger(hour=Config.SYNC_HOUR, minute=Config.SYNC_MINUTE),
        id='daily_cisa_sync',
        name='Daily CISA KEV Sync',
        replace_existing=True
    )

    # Schedule LDAP sync if enabled
    ldap_sync_enabled = os.environ.get('LDAP_SYNC_ENABLED', 'false').lower() == 'true'
    if ldap_sync_enabled:
        ldap_sync_interval = int(os.environ.get('LDAP_SYNC_INTERVAL_HOURS', '24'))

        scheduler.add_job(
            func=lambda: _run_with_lock('ldap_sync', ldap_sync_job, app),
            trigger=IntervalTrigger(hours=ldap_sync_interval),
            id='scheduled_ldap_sync',
            name=f'Scheduled LDAP Sync (every {ldap_sync_interval}h)',
            replace_existing=True
        )
        logger.info(f"LDAP sync scheduled every {ldap_sync_interval} hours")

    # Schedule daily critical CVE reminder emails (time from settings)
    enabled, hour, minute = get_critical_email_settings(app)
    if enabled:
        scheduler.add_job(
            func=lambda: _run_with_lock('critical_cve_reminder', critical_cve_reminder_job, app),
            trigger=CronTrigger(hour=hour, minute=minute),
            id='daily_critical_cve_reminder',
            name='Daily Critical CVE Reminder Emails',
            replace_existing=True
        )
        logger.info(f"Critical CVE reminder emails scheduled at {hour:02d}:{minute:02d}")
    else:
        logger.info("Critical CVE reminder emails disabled")

    # Schedule data retention cleanup (daily at 3 AM)
    scheduler.add_job(
        func=lambda: _run_with_lock('data_retention_cleanup', data_retention_cleanup_job, app),
        trigger=CronTrigger(hour=3, minute=0),
        id='data_retention_cleanup',
        name='Data Retention Cleanup',
        replace_existing=True
    )
    logger.info("Data retention cleanup scheduled at 03:00")

    # Schedule daily vulnerability snapshot (at 2 AM)
    scheduler.add_job(
        func=lambda: _run_with_lock('vulnerability_snapshot', vulnerability_snapshot_job, app),
        trigger=CronTrigger(hour=2, minute=0),
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
        trigger=CronTrigger(hour=vendor_sync_hour, minute=Config.SYNC_MINUTE),
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
        trigger=CronTrigger(day_of_week='sun', hour=4, minute=0),
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

    # Schedule asset type auto-detection (daily at 06:00)
    scheduler.add_job(
        func=lambda: _run_with_lock('auto_detect_asset_type', auto_detect_asset_type_job, app),
        trigger=CronTrigger(hour=6, minute=0),
        id='auto_detect_asset_type',
        name='Auto-Detect Asset Type (server/workstation/container)',
        replace_existing=True
    )
    logger.info("Asset type auto-detection scheduled daily at 06:00")

    # Schedule agent offline detection (every 15 minutes)
    # Marks agents as offline/stale based on last check-in time
    scheduler.add_job(
        func=lambda: _run_with_lock('agent_offline_detection', agent_offline_detection_job, app),
        trigger=IntervalTrigger(minutes=15),
        id='agent_offline_detection',
        name='Agent Offline Detection',
        replace_existing=True
    )
    logger.info("Agent offline detection scheduled every 15 minutes")

    # Schedule unmapped CPE retry (weekly, Mondays at 05:00 - after Sunday CPE dict sync)
    scheduler.add_job(
        func=lambda: _run_with_lock('unmapped_cpe_retry', unmapped_cpe_retry_job, app),
        trigger=CronTrigger(day_of_week='mon', hour=5, minute=0),
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

    # Warm up the CVE known products cache on startup
    try:
        from app.cve_known_products import refresh_known_cve_products
        with app.app_context():
            count = refresh_known_cve_products()
            logger.info(f"CVE known products cache warmed up: {count} entries")
    except Exception as e:
        logger.warning(f"CVE known products cache warmup failed (will retry on first use): {e}")

    scheduler.start()
    logger.info(f"Scheduler started. CISA KEV sync scheduled at {Config.SYNC_HOUR:02d}:{Config.SYNC_MINUTE:02d}")

    return scheduler

def reschedule_critical_email():
    """Reschedule critical email job when settings change"""
    if not _scheduler or not _app:
        return

    enabled, hour, minute = get_critical_email_settings(_app)

    # Remove existing job if any
    try:
        _scheduler.remove_job('daily_critical_cve_reminder')
    except:
        pass

    if enabled:
        _scheduler.add_job(
            func=lambda: _run_with_lock('critical_cve_reminder', critical_cve_reminder_job, _app),
            trigger=CronTrigger(hour=hour, minute=minute),
            id='daily_critical_cve_reminder',
            name='Daily Critical CVE Reminder Emails',
            replace_existing=True
        )
        logger.info(f"Critical CVE reminder rescheduled to {hour:02d}:{minute:02d}")
    else:
        logger.info("Critical CVE reminder disabled")

def cisa_sync_job(app):
    """Job wrapper to run CISA KEV sync with app context, then update EPSS scores"""
    with app.app_context():
        try:
            logger.info("Starting scheduled CISA KEV sync...")
            result = sync_cisa_kev()
            logger.info(f"CISA KEV sync completed: {result}")

            # Also sync EPSS scores after CISA KEV sync
            try:
                from app.epss_sync import sync_epss_scores
                logger.info("Syncing EPSS scores...")
                updated, errors, message = sync_epss_scores(force=False)
                logger.info(f"EPSS sync completed: {message}")
            except Exception as epss_error:
                logger.warning(f"EPSS sync failed (non-critical): {epss_error}")

            # Rebuild local CPE dictionary from updated vulnerability data
            try:
                from app.cpe_dictionary import build_cpe_dictionary
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
                from app.cpe_mapping import batch_apply_cpe_mappings
                updated, total_unmapped = batch_apply_cpe_mappings(
                    commit=True, use_nvd=False, max_nvd_lookups=0
                )
                if updated > 0:
                    logger.info(f"Auto-remapped {updated}/{total_unmapped} products after KEV sync")
            except Exception as remap_err:
                logger.warning(f"Auto-remap after KEV sync failed: {remap_err}")

        except Exception as e:
            logger.error(f"CISA KEV sync job failed: {str(e)}")

def ldap_sync_job(app):
    """Job wrapper to run LDAP sync with app context"""
    with app.app_context():
        try:
            from app.ldap_sync import LDAPSyncEngine

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
            from app.models import Organization, VulnerabilityMatch, Product, SystemSettings
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


def data_retention_cleanup_job(app):
    """Job to clean up old data based on retention settings"""
    with app.app_context():
        try:
            from app.models import SystemSettings, SyncLog
            from app.ldap_models import LDAPAuditLog, LDAPSyncLog
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

        except Exception as e:
            logger.error(f"Data retention cleanup failed: {str(e)}", exc_info=True)


def vulnerability_snapshot_job(app):
    """Job to take daily vulnerability snapshots for trend analysis"""
    with app.app_context():
        try:
            from app.models import VulnerabilitySnapshot, Organization

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
            from app.vendor_advisories import sync_vendor_advisories

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
            from app.licensing import license_heartbeat

            logger.info("Sending license heartbeat...")
            result = license_heartbeat()
            if result.get('success'):
                logger.info(f"License heartbeat OK: {result.get('message', '')}")
            else:
                logger.warning(f"License heartbeat failed: {result.get('error', 'unknown')}")

        except Exception as e:
            logger.error(f"License heartbeat job failed: {str(e)}", exc_info=True)


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
            from app.kb_sync import kb_sync

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
    MAX_RETRIES = 3
    with app.app_context():
        try:
            from app.models import InventoryJob
            cutoff = datetime.utcnow() - timedelta(minutes=30)
            stuck_jobs = InventoryJob.query.filter(
                InventoryJob.status == 'processing',
                InventoryJob.started_at < cutoff
            ).all()
            recovered = 0
            failed = 0
            for job in stuck_jobs:
                retry_count = job.retry_count if hasattr(job, 'retry_count') and job.retry_count else 0
                if retry_count >= MAX_RETRIES:
                    logger.warning(f"Job {job.id} exceeded max retries ({MAX_RETRIES}), marking as failed")
                    job.status = 'failed'
                    job.error_message = f'Failed after {MAX_RETRIES} retry attempts (stuck in processing)'
                    job.completed_at = datetime.utcnow()
                    failed += 1
                else:
                    logger.warning(f"Recovering stuck job {job.id} (stuck since {job.started_at}, retry {retry_count + 1}/{MAX_RETRIES})")
                    job.status = 'pending'
                    job.started_at = None
                    job.error_message = f'Recovered from stuck state (retry {retry_count + 1})'
                    if hasattr(job, 'retry_count'):
                        job.retry_count = retry_count + 1
                    recovered += 1
            if stuck_jobs:
                db.session.commit()
                logger.info(f"Stuck job recovery: {recovered} recovered, {failed} permanently failed")
        except Exception as e:
            logger.error(f"Stuck job recovery failed: {str(e)}", exc_info=True)
            try:
                db.session.rollback()
            except Exception:
                pass


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
            from app.cpe_mapping import batch_apply_cpe_mappings

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

    Runs every 15 minutes. Transitions:
    - online → offline: no check-in for 1 hour
    - online/offline → stale: no check-in for 14 days (configurable)

    Logs AgentEvent for each status transition so the Agent Activity page
    and activity log capture offline/reconnection events automatically.
    """
    with app.app_context():
        try:
            from app.models import Asset, AgentEvent
            from sqlalchemy import or_

            now = datetime.utcnow()
            offline_threshold = now - timedelta(hours=1)
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
                            'threshold_hours': 1
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
            from app.health_checks import run_all_health_checks
            results = run_all_health_checks()
            if results.get('skipped'):
                logger.debug("Health checks skipped (disabled)")
                return
            problems = sum(1 for v in results.values() if v in ('warning', 'critical', 'error'))
            logger.info(f"Health checks completed: {len(results)} checks, {problems} issues")
        except Exception as e:
            logger.error(f"Health check job failed: {str(e)}", exc_info=True)
