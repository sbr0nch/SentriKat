from apscheduler.schedulers.background import BackgroundScheduler
from apscheduler.triggers.cron import CronTrigger
from apscheduler.triggers.interval import IntervalTrigger
from app.cisa_sync import sync_cisa_kev
from config import Config
import logging
import os

logger = logging.getLogger(__name__)

def start_scheduler(app):
    """Start the background scheduler for scheduled jobs"""
    scheduler = BackgroundScheduler()

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

    # Schedule daily critical CVE reminder emails
    scheduler.add_job(
        func=lambda: critical_cve_reminder_job(app),
        trigger=CronTrigger(hour=9, minute=0),  # Daily at 9 AM
        id='daily_critical_cve_reminder',
        name='Daily Critical CVE Reminder Emails',
        replace_existing=True
    )
    logger.info("Daily critical CVE reminder emails scheduled at 09:00")

    scheduler.start()
    logger.info(f"Scheduler started. CISA KEV sync scheduled at {Config.SYNC_HOUR:02d}:{Config.SYNC_MINUTE:02d}")

    return scheduler

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
            from app.models import Organization, VulnerabilityMatch, Product
            from app.email_alerts import EmailAlertManager
            from datetime import datetime, timedelta

            logger.info("Starting daily critical CVE reminder emails...")

            # Get all organizations with email alerts enabled
            organizations = Organization.query.filter(
                Organization.alert_on_critical == True
            ).all()

            total_sent = 0
            total_skipped = 0
            total_errors = 0

            for org in organizations:
                try:
                    # Get unacknowledged critical/high priority vulnerabilities for this org
                    unack_matches = (
                        VulnerabilityMatch.query
                        .join(Product)
                        .filter(
                            Product.organization_id == org.id,
                            VulnerabilityMatch.acknowledged == False
                        )
                        .all()
                    )

                    # Filter for CRITICAL priority ONLY (not high - too many alerts cause spam)
                    critical_matches = [
                        m for m in unack_matches
                        if m.calculate_effective_priority() == 'critical'
                    ]

                    if not critical_matches:
                        logger.info(f"No unacknowledged critical CVEs for {org.name}, skipping")
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
