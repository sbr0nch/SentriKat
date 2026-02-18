"""
Background Health Check System for SentriKat.

Runs intelligent health checks on all system components and reports
problems/warnings via the notification system. Each check can be
individually enabled/disabled via SystemSettings.

Health checks run in the background via APScheduler and store results
in the HealthCheckResult model for display in the admin UI.
"""

import json
import logging
import os
import shutil
from datetime import datetime, timedelta

from app import db
from app.models import (
    HealthCheckResult, SystemSettings, Organization, Asset,
    Product, InventoryJob, AgentApiKey, SyncLog
)

logger = logging.getLogger(__name__)

# Default check configuration: check_name -> {category, description, default_enabled}
HEALTH_CHECKS = {
    'database': {
        'category': 'system',
        'label': 'Database Connectivity',
        'description': 'Verifies the database is reachable and responsive',
        'default_enabled': True,
    },
    'disk_space': {
        'category': 'system',
        'label': 'Disk Space',
        'description': 'Checks available disk space on the server',
        'default_enabled': True,
    },
    'worker_thread': {
        'category': 'system',
        'label': 'Worker Pool',
        'description': 'Verifies the inventory processing worker pool is alive and healthy',
        'default_enabled': True,
    },
    'stuck_jobs': {
        'category': 'system',
        'label': 'Stuck Inventory Jobs',
        'description': 'Checks for inventory jobs stuck in processing state',
        'default_enabled': True,
    },
    'queue_throughput': {
        'category': 'system',
        'label': 'Queue Throughput',
        'description': 'Monitors job queue growth rate vs processing capacity',
        'default_enabled': True,
    },
    'cve_sync_freshness': {
        'category': 'sync',
        'label': 'CVE Sync Freshness',
        'description': 'Checks if CISA KEV data is recently synced',
        'default_enabled': True,
    },
    'agent_health': {
        'category': 'agents',
        'label': 'Agent Health',
        'description': 'Checks for offline or stale agents across all organizations',
        'default_enabled': True,
    },
    'cpe_coverage': {
        'category': 'sync',
        'label': 'CPE Coverage',
        'description': 'Checks what percentage of products have CPE mappings',
        'default_enabled': True,
    },
    'license_status': {
        'category': 'system',
        'label': 'License Status',
        'description': 'Verifies the license is valid and not approaching limits',
        'default_enabled': True,
    },
    'smtp_connectivity': {
        'category': 'system',
        'label': 'SMTP Connectivity',
        'description': 'Tests if the email server is reachable',
        'default_enabled': True,
    },
    'pending_import_queue': {
        'category': 'agents',
        'label': 'Import Queue Backlog',
        'description': 'Checks for excessive items in the import queue',
        'default_enabled': True,
    },
    'api_source_status': {
        'category': 'sync',
        'label': 'API Source Status',
        'description': 'Checks if CVSS enrichment is using the primary source (NVD) or fallback sources',
        'default_enabled': True,
    },
    'sync_retry_status': {
        'category': 'sync',
        'label': 'Sync Retry Status',
        'description': 'Tracks whether the CISA sync is retrying after a failure',
        'default_enabled': True,
    },
    'server_config': {
        'category': 'system',
        'label': 'Server Configuration',
        'description': 'Checks for missing or incomplete server configuration (SMTP, organizations, API keys)',
        'default_enabled': True,
    },
}


def is_check_enabled(check_name):
    """Check if a specific health check is enabled in settings."""
    setting = SystemSettings.query.filter_by(
        key=f'health_check_{check_name}_enabled'
    ).first()
    if setting:
        return setting.value == 'true'
    # Default from config
    check_config = HEALTH_CHECKS.get(check_name, {})
    return check_config.get('default_enabled', True)


def is_health_checks_enabled():
    """Check if the health check system is globally enabled."""
    setting = SystemSettings.query.filter_by(key='health_checks_enabled').first()
    if setting:
        return setting.value == 'true'
    return True  # Enabled by default


def _record(check_name, status, message, value=None, details=None):
    """Helper to record a health check result with transaction safety."""
    try:
        category = HEALTH_CHECKS.get(check_name, {}).get('category', 'system')
        HealthCheckResult.record(check_name, category, status, message, value, details)
    except Exception:
        # If the session is in a failed state, rollback and retry once
        try:
            db.session.rollback()
            category = HEALTH_CHECKS.get(check_name, {}).get('category', 'system')
            HealthCheckResult.record(check_name, category, status, message, value, details)
        except Exception as retry_err:
            logger.error(f"Failed to record health check '{check_name}' even after rollback: {retry_err}")
            try:
                db.session.rollback()
            except Exception:
                pass


# ============================================================================
# Individual Health Check Functions
# ============================================================================

def check_database():
    """Test database connectivity and response time."""
    import time
    start = time.time()
    try:
        db.session.execute(db.text('SELECT 1'))
        elapsed_ms = (time.time() - start) * 1000

        if elapsed_ms > 5000:
            _record('database', 'warning', f'Database slow ({elapsed_ms:.0f}ms response time)',
                    f'{elapsed_ms:.0f}ms', {'response_time_ms': elapsed_ms})
        else:
            _record('database', 'ok', f'Database healthy ({elapsed_ms:.0f}ms)',
                    f'{elapsed_ms:.0f}ms', {'response_time_ms': elapsed_ms})
    except Exception as e:
        try:
            db.session.rollback()
        except Exception:
            pass
        _record('database', 'critical', f'Database unreachable: {str(e)[:200]}',
                'unreachable', {'error': str(e)[:500]})


def check_disk_space():
    """Check available disk space."""
    try:
        usage = shutil.disk_usage('/')
        free_percent = (usage.free / usage.total) * 100
        free_gb = usage.free / (1024 ** 3)

        if free_percent < 5:
            _record('disk_space', 'critical',
                    f'Critically low disk space: {free_gb:.1f} GB free ({free_percent:.1f}%)',
                    f'{free_percent:.1f}%',
                    {'free_gb': round(free_gb, 1), 'total_gb': round(usage.total / (1024**3), 1),
                     'free_percent': round(free_percent, 1)})
        elif free_percent < 15:
            _record('disk_space', 'warning',
                    f'Low disk space: {free_gb:.1f} GB free ({free_percent:.1f}%)',
                    f'{free_percent:.1f}%',
                    {'free_gb': round(free_gb, 1), 'total_gb': round(usage.total / (1024**3), 1),
                     'free_percent': round(free_percent, 1)})
        else:
            _record('disk_space', 'ok',
                    f'{free_gb:.1f} GB free ({free_percent:.1f}%)',
                    f'{free_percent:.1f}%',
                    {'free_gb': round(free_gb, 1), 'total_gb': round(usage.total / (1024**3), 1),
                     'free_percent': round(free_percent, 1)})
    except Exception as e:
        _record('disk_space', 'error', f'Could not check disk space: {str(e)[:200]}')


def check_worker_thread():
    """Check if the background worker pool is running and healthy."""
    try:
        from app.agent_api import (
            _worker_supervisor, _worker_pool, _active_job_ids,
            _active_job_ids_lock, WORKER_POOL_SIZE
        )

        supervisor_alive = _worker_supervisor is not None and _worker_supervisor.is_alive()
        pool_exists = _worker_pool is not None

        with _active_job_ids_lock:
            active_count = len(_active_job_ids)

        pending = InventoryJob.query.filter_by(status='pending').count()
        processing = InventoryJob.query.filter_by(status='processing').count()

        details = {
            'pool_size': WORKER_POOL_SIZE,
            'active_workers': active_count,
            'available_slots': max(0, WORKER_POOL_SIZE - active_count),
            'pending_jobs': pending,
            'processing_jobs': processing,
            'supervisor_alive': supervisor_alive,
            'pool_initialized': pool_exists
        }

        if not supervisor_alive:
            if pending > 0:
                _record('worker_thread', 'critical',
                        f'Worker pool stopped! {pending} jobs pending, {processing} processing',
                        'stopped', details)
            else:
                _record('worker_thread', 'warning',
                        'Worker pool is not running (no pending jobs)',
                        'stopped', details)
        elif active_count >= WORKER_POOL_SIZE and pending > 10:
            _record('worker_thread', 'warning',
                    f'Worker pool at capacity ({active_count}/{WORKER_POOL_SIZE} busy, '
                    f'{pending} queued). Consider increasing WORKER_POOL_SIZE.',
                    f'{active_count}/{WORKER_POOL_SIZE}', details)
        else:
            _record('worker_thread', 'ok',
                    f'Worker pool healthy ({active_count}/{WORKER_POOL_SIZE} active, '
                    f'{pending} queued)',
                    f'{active_count}/{WORKER_POOL_SIZE}', details)

    except ImportError:
        _record('worker_thread', 'warning', 'Cannot check worker pool status', 'unknown')
    except Exception as e:
        try:
            db.session.rollback()
        except Exception:
            pass
        _record('worker_thread', 'error', f'Error checking worker pool: {str(e)[:200]}')


def check_stuck_jobs():
    """Check for inventory jobs stuck in processing state."""
    try:
        cutoff = datetime.utcnow() - timedelta(minutes=30)
        stuck = InventoryJob.query.filter(
            InventoryJob.status == 'processing',
            InventoryJob.started_at < cutoff
        ).count()

        pending = InventoryJob.query.filter_by(status='pending').count()

        if stuck > 0:
            _record('stuck_jobs', 'warning',
                    f'{stuck} job(s) stuck in processing for >30 min',
                    f'{stuck} stuck',
                    {'stuck_count': stuck, 'pending_count': pending})
        elif pending > 50:
            _record('stuck_jobs', 'warning',
                    f'Large queue backlog: {pending} pending jobs',
                    f'{pending} pending',
                    {'stuck_count': 0, 'pending_count': pending})
        else:
            _record('stuck_jobs', 'ok',
                    f'No stuck jobs ({pending} pending)',
                    f'{pending} pending',
                    {'stuck_count': 0, 'pending_count': pending})
    except Exception as e:
        try:
            db.session.rollback()
        except Exception:
            pass
        _record('stuck_jobs', 'error', f'Error checking jobs: {str(e)[:200]}')


def check_cve_sync_freshness():
    """Check when CISA KEV data was last synced."""
    try:
        last_sync = SyncLog.query.filter(
            SyncLog.status == 'success'
        ).order_by(SyncLog.sync_date.desc()).first()

        if not last_sync:
            _record('cve_sync_freshness', 'warning',
                    'No successful CVE sync found. Run initial sync.',
                    'never synced')
            return

        age = datetime.utcnow() - last_sync.sync_date
        age_hours = age.total_seconds() / 3600

        if age_hours > 72:
            _record('cve_sync_freshness', 'critical',
                    f'CVE data is {age.days} days old. Sync may be failing.',
                    f'{age.days}d old',
                    {'last_sync': last_sync.sync_date.isoformat(), 'age_hours': round(age_hours)})
        elif age_hours > 36:
            _record('cve_sync_freshness', 'warning',
                    f'CVE data is {age_hours:.0f} hours old',
                    f'{age_hours:.0f}h old',
                    {'last_sync': last_sync.sync_date.isoformat(), 'age_hours': round(age_hours)})
        else:
            _record('cve_sync_freshness', 'ok',
                    f'CVE data synced {age_hours:.0f} hours ago',
                    f'{age_hours:.0f}h ago',
                    {'last_sync': last_sync.sync_date.isoformat(), 'age_hours': round(age_hours)})
    except Exception as e:
        try:
            db.session.rollback()
        except Exception:
            pass
        _record('cve_sync_freshness', 'error', f'Error checking sync: {str(e)[:200]}')


def check_agent_health():
    """Check for offline or stale agents across all organizations."""
    try:
        total = Asset.query.filter_by(active=True).count()
        online = Asset.query.filter_by(active=True, status='online').count()
        offline = Asset.query.filter_by(active=True, status='offline').count()
        stale = Asset.query.filter_by(active=True, status='stale').count()

        details = {
            'total': total, 'online': online,
            'offline': offline, 'stale': stale
        }

        if total == 0:
            _record('agent_health', 'ok', 'No agents registered', '0 agents', details)
        elif stale > total * 0.3:
            _record('agent_health', 'critical',
                    f'{stale} of {total} agents are stale (>30%)',
                    f'{stale} stale', details)
        elif offline > total * 0.5:
            _record('agent_health', 'warning',
                    f'{offline} of {total} agents are offline',
                    f'{offline} offline', details)
        else:
            _record('agent_health', 'ok',
                    f'{online}/{total} agents online',
                    f'{online}/{total}', details)
    except Exception as e:
        try:
            db.session.rollback()
        except Exception:
            pass
        _record('agent_health', 'error', f'Error checking agents: {str(e)[:200]}')


def check_cpe_coverage():
    """Check CPE mapping coverage for active products."""
    try:
        total_products = Product.query.filter_by(active=True).count()
        mapped = Product.query.filter(
            Product.active == True,
            Product.cpe_vendor.isnot(None),
            Product.cpe_vendor != ''
        ).count()

        if total_products == 0:
            _record('cpe_coverage', 'ok', 'No active products', '0 products')
            return

        coverage = (mapped / total_products) * 100
        unmapped = total_products - mapped
        details = {'total': total_products, 'mapped': mapped, 'unmapped': unmapped,
                   'coverage_percent': round(coverage, 1)}

        if coverage < 50:
            _record('cpe_coverage', 'warning',
                    f'Low CPE coverage: {coverage:.0f}% ({unmapped} unmapped products)',
                    f'{coverage:.0f}%', details)
        else:
            _record('cpe_coverage', 'ok',
                    f'CPE coverage: {coverage:.0f}% ({mapped}/{total_products})',
                    f'{coverage:.0f}%', details)
    except Exception as e:
        try:
            db.session.rollback()
        except Exception:
            pass
        _record('cpe_coverage', 'error', f'Error checking CPE coverage: {str(e)[:200]}')


def check_license_status():
    """Check license validity and usage limits."""
    try:
        from app.licensing import get_license
        license_info = get_license()

        if not license_info or not license_info.is_valid:
            edition = license_info.get_effective_edition() if license_info else 'unknown'
            _record('license_status', 'ok',
                    f'Running in {edition} mode',
                    edition)
            return

        plan = license_info.get_effective_edition()
        expires = str(license_info.expires_at) if license_info.expires_at else None
        details = {'plan': plan, 'expires_at': expires}
        days_left = license_info.days_until_expiry

        if license_info.is_expired:
            _record('license_status', 'critical',
                    f'License expired',
                    'expired', details)
        elif days_left is not None and days_left < 30:
            details['days_until_expiry'] = days_left
            _record('license_status', 'warning',
                    f'License expires in {days_left} days',
                    f'{days_left}d left', details)
        elif days_left is not None:
            details['days_until_expiry'] = days_left
            _record('license_status', 'ok',
                    f'License valid ({plan}, {days_left}d remaining)',
                    f'{plan}', details)
        else:
            _record('license_status', 'ok',
                    f'License valid ({plan}, no expiration)',
                    f'{plan}', details)
    except ImportError:
        _record('license_status', 'ok', 'License check not available', 'N/A')
    except Exception as e:
        try:
            db.session.rollback()
        except Exception:
            pass
        _record('license_status', 'error', f'Error checking license: {str(e)[:200]}')


def check_smtp_connectivity():
    """Test SMTP server connectivity."""
    try:
        smtp_host = None
        smtp_port = None

        # Check global SMTP settings (same keys used by email_alerts.py)
        setting_host = SystemSettings.query.filter_by(key='smtp_host').first()
        setting_port = SystemSettings.query.filter_by(key='smtp_port').first()

        if setting_host and setting_host.value:
            smtp_host = setting_host.value
            smtp_port = int(setting_port.value) if setting_port and setting_port.value else 587
        else:
            # Check environment (same env vars used by settings_api.py)
            smtp_host = os.environ.get('SMTP_HOST') or os.environ.get('SMTP_SERVER') or os.environ.get('MAIL_SERVER')
            smtp_port = int(os.environ.get('SMTP_PORT', os.environ.get('MAIL_PORT', '587')))

        if not smtp_host:
            _record('smtp_connectivity', 'warning',
                    'No SMTP server configured', 'not configured')
            return

        import socket
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(10)
        result = sock.connect_ex((smtp_host, smtp_port))
        sock.close()

        if result == 0:
            _record('smtp_connectivity', 'ok',
                    f'SMTP server {smtp_host}:{smtp_port} is reachable',
                    'reachable',
                    {'host': smtp_host, 'port': smtp_port})
        else:
            _record('smtp_connectivity', 'warning',
                    f'Cannot connect to SMTP server {smtp_host}:{smtp_port}',
                    'unreachable',
                    {'host': smtp_host, 'port': smtp_port, 'error_code': result})
    except Exception as e:
        try:
            db.session.rollback()
        except Exception:
            pass
        _record('smtp_connectivity', 'error',
                f'SMTP check failed: {str(e)[:200]}')


def check_queue_throughput():
    """
    Monitor job queue growth rate vs processing capacity.
    Detects when the system can't keep up with incoming jobs.
    """
    try:
        from app.agent_api import WORKER_POOL_SIZE

        # Count jobs created in last hour
        one_hour_ago = datetime.utcnow() - timedelta(hours=1)
        jobs_created_last_hour = InventoryJob.query.filter(
            InventoryJob.created_at >= one_hour_ago
        ).count()

        # Count jobs completed in last hour
        jobs_completed_last_hour = InventoryJob.query.filter(
            InventoryJob.status == 'completed',
            InventoryJob.completed_at >= one_hour_ago
        ).count()

        # Count jobs failed in last hour
        jobs_failed_last_hour = InventoryJob.query.filter(
            InventoryJob.status == 'failed',
            InventoryJob.completed_at >= one_hour_ago
        ).count()

        # Current queue depth
        pending = InventoryJob.query.filter_by(status='pending').count()

        # Calculate throughput ratio
        throughput_ratio = (
            jobs_completed_last_hour / jobs_created_last_hour
            if jobs_created_last_hour > 0 else 1.0
        )

        details = {
            'jobs_created_last_hour': jobs_created_last_hour,
            'jobs_completed_last_hour': jobs_completed_last_hour,
            'jobs_failed_last_hour': jobs_failed_last_hour,
            'pending_queue_depth': pending,
            'throughput_ratio': round(throughput_ratio, 2),
            'pool_size': WORKER_POOL_SIZE,
            'failure_rate': round(
                jobs_failed_last_hour / max(1, jobs_created_last_hour) * 100, 1
            )
        }

        if jobs_failed_last_hour > 10:
            _record('queue_throughput', 'critical',
                    f'{jobs_failed_last_hour} jobs failed in last hour! '
                    f'Check error logs for root cause.',
                    f'{jobs_failed_last_hour} failures', details)
        elif pending > 100 and throughput_ratio < 0.5:
            _record('queue_throughput', 'critical',
                    f'Queue growing faster than processing! {pending} pending, '
                    f'only {jobs_completed_last_hour} completed vs {jobs_created_last_hour} '
                    f'created in last hour. Increase WORKER_POOL_SIZE.',
                    f'{pending} backlog', details)
        elif pending > 50 and throughput_ratio < 0.8:
            _record('queue_throughput', 'warning',
                    f'Queue building up: {pending} pending. Processed '
                    f'{jobs_completed_last_hour}/{jobs_created_last_hour} jobs in last hour.',
                    f'{pending} pending', details)
        else:
            msg = f'{jobs_completed_last_hour} completed'
            if jobs_created_last_hour > 0:
                msg += f' / {jobs_created_last_hour} created in last hour'
            if pending > 0:
                msg += f' ({pending} pending)'
            _record('queue_throughput', 'ok', msg,
                    f'{jobs_completed_last_hour} processed', details)

    except Exception as e:
        try:
            db.session.rollback()
        except Exception:
            pass
        _record('queue_throughput', 'error',
                f'Error checking throughput: {str(e)[:200]}')


def check_api_source_status():
    """
    Check if CVSS enrichment is using the primary source (NVD) or fallback sources.

    Reads from the api_source_status HealthCheckResult which is recorded
    by enrich_with_cvss_data() after each sync. Also checks for vulns
    still on fallback sources that haven't been re-enriched yet.
    """
    try:
        from app.models import Vulnerability

        # Count vulns currently on fallback sources
        fallback_count = Vulnerability.query.filter(
            Vulnerability.cvss_source.in_(['cve_org', 'euvd']),
            Vulnerability.cvss_score.isnot(None),
            Vulnerability.cvss_score > 0
        ).count()

        if fallback_count == 0:
            _record('api_source_status', 'ok',
                    'All CVSS scores from NVD (primary source)',
                    value='NVD primary',
                    details={'fallback_vulns': 0})
        else:
            total_with_cvss = Vulnerability.query.filter(
                Vulnerability.cvss_score.isnot(None),
                Vulnerability.cvss_score > 0
            ).count()
            pct = round(fallback_count / max(1, total_with_cvss) * 100, 1)
            status = 'warning' if pct > 5 else 'ok'
            _record('api_source_status', status,
                    f'{fallback_count} vulnerabilities using fallback CVSS sources '
                    f'({pct}%). Auto re-enrichment will retry NVD.',
                    value=f'{fallback_count} fallback',
                    details={'fallback_vulns': fallback_count, 'total_with_cvss': total_with_cvss,
                             'fallback_pct': pct})
    except Exception as e:
        try:
            db.session.rollback()
        except Exception:
            pass
        _record('api_source_status', 'error',
                f'Error checking API source status: {str(e)[:200]}')


def check_sync_retry_status():
    """
    Check if the CISA sync is in retry state.

    This is a passthrough check - the actual state is recorded by
    _record_sync_retry_status() in scheduler.py when retries happen.
    Here we just verify the existing record is still relevant.
    """
    try:
        existing = HealthCheckResult.query.filter_by(check_name='sync_retry_status').first()
        if not existing:
            # No record yet - first run, record OK
            _record('sync_retry_status', 'ok', 'Sync operating normally', value='OK')
        # Otherwise, keep the existing status (managed by scheduler retry logic)
    except Exception as e:
        try:
            db.session.rollback()
        except Exception:
            pass
        _record('sync_retry_status', 'error',
                f'Error checking retry status: {str(e)[:200]}')


def check_pending_import_queue():
    """Check for excessive items in the import queue."""
    try:
        from app.integrations_models import ImportQueue
        pending = ImportQueue.query.filter_by(status='pending').count()
        total = ImportQueue.query.count()

        details = {'pending': pending, 'total': total}

        if pending > 500:
            _record('pending_import_queue', 'warning',
                    f'{pending} items pending review in Import Queue',
                    f'{pending} pending', details)
        else:
            _record('pending_import_queue', 'ok',
                    f'{pending} items in Import Queue',
                    f'{pending} pending', details)
    except Exception as e:
        try:
            db.session.rollback()
        except Exception:
            pass
        _record('pending_import_queue', 'error',
                f'Error checking import queue: {str(e)[:200]}')


# ============================================================================
# Main Runner
# ============================================================================

def check_server_config():
    """Check for missing or incomplete server configuration."""
    try:
        missing = []
        warnings = []

        # Check SMTP configuration
        smtp_host = SystemSettings.query.filter_by(key='smtp_host').first()
        has_smtp = smtp_host and smtp_host.value
        if not has_smtp:
            env_smtp = os.environ.get('SMTP_HOST') or os.environ.get('SMTP_SERVER') or os.environ.get('MAIL_SERVER')
            if not env_smtp:
                missing.append('SMTP not configured (email alerts will not work)')

        # Check organizations have notification emails
        orgs = Organization.query.filter_by(active=True).all()
        orgs_without_emails = []
        for org in orgs:
            try:
                emails = json.loads(org.notification_emails or '[]')
                if isinstance(emails, str):
                    emails = json.loads(emails)
                if not any(e and e.strip() for e in emails):
                    orgs_without_emails.append(org.display_name or org.name)
            except (json.JSONDecodeError, TypeError):
                orgs_without_emails.append(org.display_name or org.name)
        if orgs_without_emails:
            warnings.append(f'{len(orgs_without_emails)} org(s) have no notification emails')

        # Check for at least one agent API key
        key_count = AgentApiKey.query.filter_by(active=True).count()
        if key_count == 0:
            missing.append('No active agent API keys (agents cannot push data)')

        # Check if any CISA sync has ever run
        last_sync = SyncLog.query.order_by(SyncLog.id.desc()).first()
        if not last_sync:
            warnings.append('CISA KEV sync has never run')

        # Report results
        total_issues = len(missing) + len(warnings)
        if missing:
            details = {'missing': missing, 'warnings': warnings}
            _record('server_config', 'critical',
                    f'{len(missing)} critical config issue(s): {missing[0]}',
                    f'{total_issues} issue(s)',
                    details)
        elif warnings:
            details = {'missing': [], 'warnings': warnings}
            _record('server_config', 'warning',
                    f'{len(warnings)} config warning(s): {warnings[0]}',
                    f'{total_issues} warning(s)',
                    details)
        else:
            _record('server_config', 'ok',
                    'Server configuration is complete', 'all configured',
                    {'missing': [], 'warnings': []})
    except Exception as e:
        _record('server_config', 'error', f'Config check failed: {str(e)[:200]}')


# Map check_name -> function
CHECK_FUNCTIONS = {
    'database': check_database,
    'disk_space': check_disk_space,
    'worker_thread': check_worker_thread,
    'stuck_jobs': check_stuck_jobs,
    'queue_throughput': check_queue_throughput,
    'cve_sync_freshness': check_cve_sync_freshness,
    'agent_health': check_agent_health,
    'cpe_coverage': check_cpe_coverage,
    'license_status': check_license_status,
    'smtp_connectivity': check_smtp_connectivity,
    'pending_import_queue': check_pending_import_queue,
    'api_source_status': check_api_source_status,
    'sync_retry_status': check_sync_retry_status,
    'server_config': check_server_config,
}


def run_all_health_checks():
    """
    Run all enabled health checks.
    Called by the scheduler periodically.
    """
    if not is_health_checks_enabled():
        logger.debug("Health checks disabled globally")
        return {'skipped': True, 'reason': 'disabled'}

    results = {}
    for check_name, check_func in CHECK_FUNCTIONS.items():
        if not is_check_enabled(check_name):
            logger.debug(f"Health check '{check_name}' disabled, skipping")
            continue

        try:
            check_func()
            # Read back the result
            result = HealthCheckResult.query.filter_by(check_name=check_name).first()
            if result:
                results[check_name] = result.status
        except Exception as e:
            logger.error(f"Health check '{check_name}' failed: {e}")
            # Rollback failed transaction before attempting to record error
            try:
                db.session.rollback()
            except Exception:
                pass
            _record(check_name, 'error', f'Check failed: {str(e)[:200]}')
            results[check_name] = 'error'

    # Send notifications for warnings/criticals
    _send_health_notifications(results)

    return results


def _send_health_notifications(results):
    """Send email notifications for critical/warning health checks."""
    try:
        # Only notify if there are problems
        problems = {k: v for k, v in results.items() if v in ('warning', 'critical', 'error')}
        if not problems:
            return

        # Check if health notification emails are configured
        setting = SystemSettings.query.filter_by(key='health_check_notify_email').first()
        if not setting or not setting.value:
            return  # No notification emails configured

        # Rate limit: don't send more than once per hour
        last_notif = SystemSettings.query.filter_by(key='health_check_last_notification').first()
        if last_notif and last_notif.value:
            try:
                last_time = datetime.fromisoformat(last_notif.value)
                if (datetime.utcnow() - last_time).total_seconds() < 3600:
                    return  # Too soon
            except (ValueError, TypeError):
                pass

        # Build notification message
        critical_checks = [k for k, v in problems.items() if v == 'critical']
        warning_checks = [k for k, v in problems.items() if v in ('warning', 'error')]

        if not critical_checks and not warning_checks:
            return

        # Send via email if SMTP is configured
        try:
            from app.email_alerts import EmailAlertManager
            subject = f"SentriKat Health Alert: {len(critical_checks)} critical, {len(warning_checks)} warnings"

            body_lines = ["SentriKat Health Check Results:\n"]
            for check_name in critical_checks:
                result = HealthCheckResult.query.filter_by(check_name=check_name).first()
                label = HEALTH_CHECKS.get(check_name, {}).get('label', check_name)
                body_lines.append(f"  CRITICAL: {label} - {result.message if result else 'Unknown'}")
            for check_name in warning_checks:
                result = HealthCheckResult.query.filter_by(check_name=check_name).first()
                label = HEALTH_CHECKS.get(check_name, {}).get('label', check_name)
                body_lines.append(f"  WARNING: {label} - {result.message if result else 'Unknown'}")

            body = '\n'.join(body_lines)

            recipients = [e.strip() for e in setting.value.split(',') if e.strip()]
            if recipients:
                EmailAlertManager.send_generic_alert(
                    recipients=recipients,
                    subject=subject,
                    body=body
                )
                logger.info(f"Health check notification sent to {len(recipients)} recipients")

                # Update last notification time
                if last_notif:
                    last_notif.value = datetime.utcnow().isoformat()
                else:
                    db.session.add(SystemSettings(
                        key='health_check_last_notification',
                        value=datetime.utcnow().isoformat(),
                        category='health'
                    ))
                db.session.commit()
        except Exception as e:
            logger.warning(f"Could not send health notification email: {e}")

    except Exception as e:
        logger.error(f"Error in health notification: {e}")


def get_health_check_config():
    """Get the full health check configuration with current enabled/disabled states."""
    config = []
    for check_name, check_info in HEALTH_CHECKS.items():
        enabled = is_check_enabled(check_name)
        # Get latest result
        result = HealthCheckResult.query.filter_by(check_name=check_name).first()
        config.append({
            'name': check_name,
            'label': check_info['label'],
            'description': check_info['description'],
            'category': check_info['category'],
            'enabled': enabled,
            'last_result': result.to_dict() if result else None,
        })
    return config
