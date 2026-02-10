"""
Gunicorn configuration for SentriKat.

Optimized for enterprise vulnerability management workloads:
- Multiple workers for concurrent API requests and sync operations
- gthread worker class for mixed I/O (database queries + HTTP calls)
- Preloading for shared memory and faster worker startup
- Graceful timeout handling for long-running sync operations

Override defaults via environment variables:
  GUNICORN_WORKERS=4  (default: min(CPU*2+1, 8))
  GUNICORN_THREADS=4  (default: 4 per worker)
  GUNICORN_TIMEOUT=120
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
# Default: min(CPU_COUNT * 2 + 1, 8) - capped at 8 for memory safety
# For small deployments (1-2 CPU): 3 workers
# For medium deployments (4 CPU): 8 workers (capped)
_cpu_count = multiprocessing.cpu_count()
_default_workers = min(_cpu_count * 2 + 1, 8)
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

# Security: run as non-root user after binding
user = os.environ.get('GUNICORN_USER', 'sentrikat')
group = os.environ.get('GUNICORN_GROUP', 'sentrikat')

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
forwarded_allow_ips = '*'  # Trust X-Forwarded-For from nginx
proxy_protocol = False


# =============================================================================
# Server Hooks
# =============================================================================

def post_fork(server, worker):
    """Dispose inherited DB connections after fork.

    With preload_app=True, the master process creates the app (and its
    SQLAlchemy engine/pool) before forking workers. Forked children inherit
    the master's open DB connections via file descriptors, but PostgreSQL
    connections are not fork-safe — sharing them across processes corrupts
    the wire protocol (symptoms: 'lost synchronization with server',
    'got message type "a"', PGRES_TUPLES_OK errors).

    Calling engine.dispose() closes all inherited connections so each worker
    creates its own fresh pool on first use.
    """
    try:
        from app import db
        db.engine.dispose()
        server.log.info("Worker %s: disposed inherited DB connections", worker.pid)
    except Exception as e:
        server.log.warning("Worker %s: failed to dispose DB pool: %s", worker.pid, e)
