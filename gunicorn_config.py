"""
Gunicorn configuration file for SentriKat

Each worker initializes the app separately (no preload) to avoid
database connection sharing issues across forked processes.
"""
import os

# Server socket
bind = "0.0.0.0:5000"

# Worker processes
workers = int(os.environ.get('GUNICORN_WORKERS', 2))
timeout = 120
graceful_timeout = 30

# DO NOT preload - let each worker create its own app and connections
# This avoids connection corruption from inherited file descriptors
preload_app = False

# Logging
accesslog = '-'
errorlog = '-'
loglevel = 'info'

# Set environment variable so run.py knows it's under gunicorn
raw_env = ['GUNICORN_ARBITER_PID=1']


def on_starting(server):
    """Called just before the master process is initialized."""
    server.log.info("Starting SentriKat (workers will initialize app separately)")


def worker_exit(server, worker):
    """Called when a worker exits - clean up database connections."""
    try:
        from run import app
        from app import db
        with app.app_context():
            db.session.remove()
            db.engine.dispose()
    except Exception:
        pass


def on_exit(server):
    """Called just before exiting Gunicorn. Clean up scheduler lock."""
    try:
        os.unlink('/tmp/sentrikat_scheduler.lock')
    except Exception:
        pass
