"""
Gunicorn configuration for SentriKat.

Optimized for enterprise vulnerability management workloads:
- Multiple workers for concurrent API requests and sync operations
- gthread worker class for mixed I/O (database queries + HTTP calls)
- Preloading for shared memory and faster worker startup
- Graceful timeout handling for long-running sync operations

Override defaults via environment variables:
  GUNICORN_WORKERS=8   (default: min(CPU*2+1, 16))
  GUNICORN_THREADS=4   (default: 4 per worker)
  GUNICORN_TIMEOUT=120

Scaling guide:
  Small  (< 100 agents):   GUNICORN_WORKERS=4,  GUNICORN_THREADS=4  (16 concurrent)
  Medium (100-1000 agents): GUNICORN_WORKERS=8,  GUNICORN_THREADS=4  (32 concurrent)
  Large  (1000-5000 agents):GUNICORN_WORKERS=12, GUNICORN_THREADS=8  (96 concurrent)
  XLarge (5000-10000 agents):GUNICORN_WORKERS=16,GUNICORN_THREADS=8  (128 concurrent)
"""

import os
import multiprocessing


def _env_int(key, default):
    """Get env var as int, treating empty string as missing."""
    val = os.environ.get(key, '')
    return int(val) if val.strip() else default


# Bind address
bind = os.environ.get('GUNICORN_BIND') or '0.0.0.0:5000'

# Worker configuration
# gthread provides threaded workers - better for I/O-bound workloads
# (database queries, NVD API calls, CISA sync, email sending)
worker_class = 'gthread'

# Number of worker processes
# Default: min(CPU_COUNT * 2 + 1, 16) - cap raised for high-agent deployments
# For small deployments (1-2 CPU): 3-5 workers
# For medium deployments (4 CPU): 8-9 workers
# For large deployments (8+ CPU): 16 workers
_cpu_count = multiprocessing.cpu_count()
_default_workers = min(_cpu_count * 2 + 1, 16)
workers = _env_int('GUNICORN_WORKERS', _default_workers)

# Threads per worker - allows concurrent request handling within each worker
# 4 threads * N workers = 4N concurrent requests
threads = _env_int('GUNICORN_THREADS', 4)

# Timeout for worker response (seconds)
# 120s accommodates long-running operations (CISA sync, report generation)
timeout = _env_int('GUNICORN_TIMEOUT', 120)

# Graceful timeout for worker shutdown
graceful_timeout = 30

# Keep-alive connections (seconds)
keepalive = 5

# Preload application before forking workers
# Benefits:
# - Shared memory for app code (lower total memory usage)
# - Schema migrations run once before any workers start
# - Prevents race conditions in db.create_all()
preload_app = True

# Max requests before worker restart (prevents memory leaks)
# After processing this many requests, worker is gracefully restarted
max_requests = _env_int('GUNICORN_MAX_REQUESTS', 2000)
max_requests_jitter = 200  # Add randomness to prevent all workers restarting at once

# Note: process UID/GID is set by docker-entrypoint.sh via `gosu sentrikat`
# BEFORE gunicorn starts ([03.20.1]). Doing it here (with `user`/`group`)
# would only drop AFTER preload_app, leaving the master to create the log
# files as root — which then locks the workers (sentrikat) out of writing
# to them, silently breaking observability.

# Logging
accesslog = '-'  # stdout
errorlog = '-'   # stderr
loglevel = os.environ.get('GUNICORN_LOG_LEVEL', 'info')

# Request limits
limit_request_line = 8190
limit_request_fields = 100

# Temporary file directory for request body buffering
tmp_upload_dir = None

# Server header
forwarded_allow_ips = os.environ.get('FORWARDED_ALLOW_IPS', '*')  # Trust X-Forwarded-For from nginx (gunicorn doesn't support CIDR notation)
proxy_protocol = False


# =============================================================================
# Server Hooks
# =============================================================================

def post_fork(server, worker):
    """Re-initialize fork-unsafe resources in each worker.

    Two resources need per-worker re-init with preload_app=True:

    1. SQLAlchemy engine/pool — workers inherit the master's open
       PostgreSQL connections via FDs, but pg wire connections corrupt
       when shared across processes.

    2. Python logging handlers — even with master+workers sharing the
       sentrikat UID (so file ownership is fine, see [03.20.1] gosu fix),
       workers can still inherit a `threading.Lock` in *held* state from
       the master if a background thread (APScheduler, DB pool keepalive)
       happened to be mid-emit at fork time. The held lock has no owning
       thread in the child → every subsequent emit silently deadlocks
       on lock.acquire(), which is why /var/log/sentrikat/*.log stay at
       boot-only content even though workers are servicing requests.

    Re-running setup_logging in each worker clears inherited handlers
    and reopens fresh file descriptors with brand-new locks.
    """
    try:
        from run import app
        from app import db
        from app.logging_config import setup_logging
        with app.app_context():
            db.engine.dispose()
            setup_logging(app)
        server.log.info("Worker %s: re-initialized DB pool + logging handlers", worker.pid)
    except Exception as e:
        server.log.warning("Worker %s: failed post_fork init: %s", worker.pid, e)
