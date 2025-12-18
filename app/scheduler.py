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
