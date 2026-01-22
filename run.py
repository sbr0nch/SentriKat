from app import create_app, db
from app.scheduler import start_scheduler
import logging
import os

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)

logger = logging.getLogger(__name__)

app = create_app()

# Log the database being used for debugging (only do this if not preloaded by gunicorn)
# When running under gunicorn with --preload, avoid making DB connections in master
if os.environ.get('_SENTRIKAT_LOG_DB') != 'done':
    os.environ['_SENTRIKAT_LOG_DB'] = 'done'
    try:
        db_uri = app.config.get('SQLALCHEMY_DATABASE_URI', 'not set')
        # Mask password if present in URI
        if '@' in db_uri and '://' in db_uri:
            # PostgreSQL or similar with credentials
            masked = db_uri.split('://')[0] + '://' + '***@' + db_uri.split('@')[-1]
            logger.info(f"Database: {masked}")
        else:
            logger.info(f"Database: {db_uri}")
    except Exception as e:
        logger.warning(f"Could not log database info: {e}")

# Scheduler is started by gunicorn_config.py post_fork hook when running with gunicorn
# For standalone/development mode, start it here
if __name__ == '__main__':
    # Start the scheduler for automated syncs
    scheduler = start_scheduler(app)

    # Database is created in create_app() if needed - no need to call db.create_all() here
    # Debug mode ONLY enabled if FLASK_ENV is not production
    debug_mode = os.environ.get('FLASK_ENV', 'development') != 'production'
    app.run(debug=debug_mode, host='0.0.0.0', port=5000)
