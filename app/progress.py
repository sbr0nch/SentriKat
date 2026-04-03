"""
Lightweight in-memory progress tracking for long-running operations.

Used by the sync engine, CPE mapping, import queue, and other operations
to report step-by-step progress to the frontend via polling.

Thread-safe: multiple workers can update progress concurrently.
"""
import threading
import time
import logging

logger = logging.getLogger(__name__)

_progress = {}
_lock = threading.Lock()


def start(job_id, total_steps, description='Processing...'):
    """Start tracking a new job."""
    with _lock:
        _progress[job_id] = {
            'job_id': job_id,
            'status': 'running',
            'step': 0,
            'total_steps': total_steps,
            'description': description,
            'detail': '',
            'started_at': time.time(),
            'updated_at': time.time(),
            'result': None,
        }


def update(job_id, step=None, description=None, detail=None):
    """Update progress for an existing job."""
    with _lock:
        if job_id not in _progress:
            return
        p = _progress[job_id]
        if step is not None:
            p['step'] = step
        if description is not None:
            p['description'] = description
        if detail is not None:
            p['detail'] = detail
        p['updated_at'] = time.time()


def finish(job_id, result=None):
    """Mark job as completed."""
    with _lock:
        if job_id not in _progress:
            return
        p = _progress[job_id]
        p['status'] = 'completed'
        p['step'] = p['total_steps']
        p['description'] = 'Completed'
        p['result'] = result
        p['updated_at'] = time.time()


def fail(job_id, error=None):
    """Mark job as failed."""
    with _lock:
        if job_id not in _progress:
            return
        p = _progress[job_id]
        p['status'] = 'error'
        p['description'] = 'Failed'
        p['detail'] = str(error) if error else ''
        p['updated_at'] = time.time()


def get(job_id):
    """Get current progress for a job."""
    with _lock:
        p = _progress.get(job_id)
        if not p:
            return None
        result = dict(p)
        elapsed = time.time() - result['started_at']
        result['elapsed_seconds'] = round(elapsed, 1)
        if result['total_steps'] > 0:
            result['percent'] = round(result['step'] / result['total_steps'] * 100)
        else:
            result['percent'] = 0
        return result


def get_active():
    """Get all active (running) jobs."""
    with _lock:
        active = []
        for p in _progress.values():
            if p['status'] == 'running':
                result = dict(p)
                elapsed = time.time() - result['started_at']
                result['elapsed_seconds'] = round(elapsed, 1)
                if result['total_steps'] > 0:
                    result['percent'] = round(result['step'] / result['total_steps'] * 100)
                else:
                    result['percent'] = 0
                active.append(result)
        return active


def cleanup(max_age_seconds=300):
    """Remove completed/failed jobs older than max_age_seconds."""
    with _lock:
        now = time.time()
        expired = [
            k for k, v in _progress.items()
            if v['status'] in ('completed', 'error') and now - v['updated_at'] > max_age_seconds
        ]
        for k in expired:
            del _progress[k]
