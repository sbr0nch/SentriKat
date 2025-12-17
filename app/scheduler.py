from apscheduler.schedulers.background import BackgroundScheduler
from apscheduler.triggers.cron import CronTrigger
from app.cisa_sync import sync_cisa_kev
from config import Config
import logging

logger = logging.getLogger(__name__)

def start_scheduler(app):
    """Start the background scheduler for daily CISA KEV sync"""
    scheduler = BackgroundScheduler()

    # Schedule daily sync at configured time
    scheduler.add_job(
        func=lambda: sync_job(app),
        trigger=CronTrigger(hour=Config.SYNC_HOUR, minute=Config.SYNC_MINUTE),
        id='daily_cisa_sync',
        name='Daily CISA KEV Sync',
        replace_existing=True
    )

    scheduler.start()
    logger.info(f"Scheduler started. Daily sync scheduled at {Config.SYNC_HOUR:02d}:{Config.SYNC_MINUTE:02d}")

    return scheduler

def sync_job(app):
    """Job wrapper to run sync with app context"""
    with app.app_context():
        try:
            logger.info("Starting scheduled CISA KEV sync...")
            result = sync_cisa_kev()
            logger.info(f"Sync completed: {result}")
        except Exception as e:
            logger.error(f"Sync job failed: {str(e)}")
