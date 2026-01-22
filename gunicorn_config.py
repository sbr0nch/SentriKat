"""
Gunicorn configuration file for SentriKat

This configuration handles the database connection pool correctly when using
preloaded workers to avoid connection sharing across forked processes.
"""
import os

# Server socket
bind = "0.0.0.0:5000"

# Worker processes
workers = int(os.environ.get('GUNICORN_WORKERS', 2))
timeout = 120
graceful_timeout = 30

# Preload app for faster worker startup and shared code
preload_app = True

# Logging
accesslog = '-'
errorlog = '-'
loglevel = 'info'

# Track which worker should run the scheduler (only first one)
_scheduler_started = False


def post_fork(server, worker):
    """
    Called just after a worker has been forked.

    When using --preload, database connections created in the master process
    get inherited by worker processes. This causes connection corruption
    because multiple processes try to use the same connection.

    We dispose of the engine here to force workers to create their own connections.
    """
    global _scheduler_started
    from app import db

    # Dispose of all pooled connections from the parent process
    # This forces SQLAlchemy to create fresh connections for this worker
    try:
        db.engine.dispose()
        server.log.info(f"Worker {worker.pid}: Database engine disposed, fresh connections ready")
    except Exception as e:
        server.log.error(f"Worker {worker.pid}: Failed to dispose engine: {e}")

    # Start scheduler only in the first worker to avoid duplicate jobs
    if not _scheduler_started:
        _scheduler_started = True
        try:
            from run import app
            from app.scheduler import start_scheduler
            start_scheduler(app)
            server.log.info(f"Worker {worker.pid}: Scheduler started")
        except Exception as e:
            server.log.error(f"Worker {worker.pid}: Failed to start scheduler: {e}")


def on_starting(server):
    """Called just before the master process is initialized."""
    server.log.info("Starting SentriKat with database connection pool management")


def worker_exit(server, worker):
    """Called when a worker exits."""
    from app import db
    try:
        db.session.remove()
        db.engine.dispose()
    except Exception:
        pass
