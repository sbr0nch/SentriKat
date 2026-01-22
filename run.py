from app import create_app, db
from app.scheduler import start_scheduler
import logging
import os
import fcntl

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)

logger = logging.getLogger(__name__)

app = create_app()

# Log the database being used for debugging
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


def start_scheduler_once():
    """Start scheduler only once across all workers using file locking."""
    lock_file = '/tmp/sentrikat_scheduler.lock'
    try:
        # Try to acquire exclusive lock (non-blocking)
        fd = os.open(lock_file, os.O_CREAT | os.O_RDWR)
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            # Got the lock - we're the first worker, start scheduler
            start_scheduler(app)
            logger.info(f"Scheduler started by worker PID {os.getpid()}")
            # Keep lock file open to hold the lock
            return fd
        except BlockingIOError:
            # Another worker has the lock and is running the scheduler
            os.close(fd)
            logger.info(f"Scheduler already running, skipping in worker PID {os.getpid()}")
            return None
    except Exception as e:
        logger.error(f"Failed to start scheduler: {e}")
        return None


# When running under gunicorn (not as __main__), start scheduler with lock coordination
# This ensures only one worker runs the scheduler
if os.environ.get('GUNICORN_ARBITER_PID'):
    # Running under gunicorn
    with app.app_context():
        _scheduler_lock = start_scheduler_once()
elif __name__ == '__main__':
    # Running standalone/development mode
    scheduler = start_scheduler(app)
    # Debug mode ONLY enabled if FLASK_ENV is not production
    debug_mode = os.environ.get('FLASK_ENV', 'development') != 'production'
    app.run(debug=debug_mode, host='0.0.0.0', port=5000)
