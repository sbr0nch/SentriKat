from apscheduler.schedulers.background import BackgroundScheduler
from apscheduler.triggers.cron import CronTrigger
from apscheduler.triggers.interval import IntervalTrigger
from app.cisa_sync import sync_cisa_kev
from config import Config
import logging
import os

logger = logging.getLogger(__name__)

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
        func=lambda: cisa_sync_job(app),
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
            func=lambda: ldap_sync_job(app),
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
            func=lambda: critical_cve_reminder_job(app),
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
        func=lambda: data_retention_cleanup_job(app),
        trigger=CronTrigger(hour=3, minute=0),
        id='data_retention_cleanup',
        name='Data Retention Cleanup',
        replace_existing=True
    )
    logger.info("Data retention cleanup scheduled at 03:00")

    scheduler.start()
    logger.info(f"Scheduler started. CISA KEV sync scheduled at {Config.SYNC_HOUR:02d}:{Config.SYNC_MINUTE:02d}")

    return scheduler

def reschedule_critical_email():
    """Reschedule critical email job when settings change"""
    global _scheduler, _app
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
            func=lambda: critical_cve_reminder_job(_app),
            trigger=CronTrigger(hour=hour, minute=minute),
            id='daily_critical_cve_reminder',
            name='Daily Critical CVE Reminder Emails',
            replace_existing=True
        )
        logger.info(f"Critical CVE reminder rescheduled to {hour:02d}:{minute:02d}")
    else:
        logger.info("Critical CVE reminder disabled")

def cisa_sync_job(app):
    """Job wrapper to run CISA KEV sync with app context"""
    with app.app_context():
        try:
            logger.info("Starting scheduled CISA KEV sync...")
            result = sync_cisa_kev()
            logger.info(f"CISA KEV sync completed: {result}")
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

            # Get all organizations with email alerts enabled
            organizations = Organization.query.filter(
                Organization.alert_on_critical == True
            ).all()

            total_sent = 0
            total_skipped = 0
            total_errors = 0

            for org in organizations:
                try:
                    # Get unacknowledged critical vulnerabilities for this org
                    # Filter by match creation date to only include recent ones
                    unack_matches = (
                        VulnerabilityMatch.query
                        .join(Product)
                        .filter(
                            Product.organization_id == org.id,
                            VulnerabilityMatch.acknowledged == False,
                            VulnerabilityMatch.created_at >= cutoff_date
                        )
                        .all()
                    )

                    # Filter for CRITICAL priority ONLY
                    critical_matches = [
                        m for m in unack_matches
                        if m.calculate_effective_priority() == 'critical'
                    ]

                    if not critical_matches:
                        logger.info(f"No recent unacknowledged critical CVEs for {org.name}, skipping")
                        total_skipped += 1
                        continue

                    # Send reminder email
                    result = EmailAlertManager.send_critical_cve_alert(org, critical_matches)

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
            from app.models import SystemSettings, SyncLog, AuditLog
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
                deleted_counts['sync_logs'] = 0

            # Clean up old LDAP sync logs
            try:
                deleted = LDAPSyncLog.query.filter(LDAPSyncLog.timestamp < sync_cutoff).delete()
                deleted_counts['ldap_sync_logs'] = deleted
            except Exception as e:
                logger.error(f"Error cleaning LDAP sync logs: {e}")
                deleted_counts['ldap_sync_logs'] = 0

            # Clean up old audit logs
            try:
                deleted = AuditLog.query.filter(AuditLog.timestamp < audit_cutoff).delete()
                deleted_counts['audit_logs'] = deleted
            except Exception as e:
                logger.error(f"Error cleaning audit logs: {e}")
                deleted_counts['audit_logs'] = 0

            # Clean up old LDAP audit logs
            try:
                deleted = LDAPAuditLog.query.filter(LDAPAuditLog.timestamp < audit_cutoff).delete()
                deleted_counts['ldap_audit_logs'] = deleted
            except Exception as e:
                logger.error(f"Error cleaning LDAP audit logs: {e}")
                deleted_counts['ldap_audit_logs'] = 0

            db.session.commit()

            total_deleted = sum(deleted_counts.values())
            logger.info(f"Data retention cleanup completed. Deleted: {deleted_counts}, Total: {total_deleted}")

        except Exception as e:
            logger.error(f"Data retention cleanup failed: {str(e)}", exc_info=True)
