"""
DB-backed progress tracking for long-running operations.

Stores progress in the ``system_settings`` table (key=``progress:<job_id>``,
category=``progress``) so that all gunicorn workers see the same state. The
old in-memory implementation (a process-local dict) was visible only to the
worker that started the job and produced 404s on every poll routed to a
different worker — see bug [03.14.11].

Trade-off: ~10 INSERT/UPDATE per long-running sync (negligible volume) in
exchange for cross-worker correctness. No new infrastructure dependency.
"""
import json
import time
import logging
from datetime import datetime, timedelta

logger = logging.getLogger(__name__)

_PREFIX = 'progress:'
_CATEGORY = 'progress'


def _key(job_id):
    return f'{_PREFIX}{job_id}'


def _save(job_id, payload):
    """Upsert the progress row for job_id."""
    from app import db
    from app.models import SystemSettings
    key = _key(job_id)
    row = SystemSettings.query.filter_by(key=key, category=_CATEGORY, organization_id=None).first()
    payload_json = json.dumps(payload)
    if row is None:
        row = SystemSettings(key=key, value=payload_json, category=_CATEGORY, organization_id=None)
        db.session.add(row)
    else:
        row.value = payload_json
    db.session.commit()


def _load(job_id):
    from app.models import SystemSettings
    row = SystemSettings.query.filter_by(key=_key(job_id), category=_CATEGORY, organization_id=None).first()
    if row is None or not row.value:
        return None
    try:
        return json.loads(row.value)
    except (json.JSONDecodeError, ValueError, TypeError):
        return None


def start(job_id, total_steps, description='Processing...'):
    """Start tracking a new job."""
    now = time.time()
    payload = {
        'job_id': job_id,
        'status': 'running',
        'step': 0,
        'total_steps': total_steps,
        'description': description,
        'detail': '',
        'started_at': now,
        'updated_at': now,
        'result': None,
    }
    _save(job_id, payload)


def update(job_id, step=None, description=None, detail=None):
    """Update progress for an existing job."""
    p = _load(job_id)
    if p is None:
        return
    if step is not None:
        p['step'] = step
    if description is not None:
        p['description'] = description
    if detail is not None:
        p['detail'] = detail
    p['updated_at'] = time.time()
    _save(job_id, p)


def finish(job_id, result=None):
    """Mark job as completed."""
    p = _load(job_id)
    if p is None:
        return
    p['status'] = 'completed'
    p['step'] = p['total_steps']
    p['description'] = 'Completed'
    p['result'] = result
    p['updated_at'] = time.time()
    _save(job_id, p)


def fail(job_id, error=None):
    """Mark job as failed."""
    p = _load(job_id)
    if p is None:
        return
    p['status'] = 'error'
    p['description'] = 'Failed'
    p['detail'] = str(error) if error else ''
    p['updated_at'] = time.time()
    _save(job_id, p)


def _enrich(p):
    """Add elapsed_seconds and percent to a raw progress dict."""
    elapsed = time.time() - p['started_at']
    p['elapsed_seconds'] = round(elapsed, 1)
    if p['total_steps'] > 0:
        p['percent'] = round(p['step'] / p['total_steps'] * 100)
    else:
        p['percent'] = 0
    return p


def get(job_id):
    """Get current progress for a job."""
    p = _load(job_id)
    if p is None:
        return None
    return _enrich(p)


def get_active():
    """Get all currently running jobs."""
    from app.models import SystemSettings
    rows = SystemSettings.query.filter(
        SystemSettings.category == _CATEGORY,
        SystemSettings.organization_id.is_(None),
        SystemSettings.key.like(f'{_PREFIX}%'),
    ).all()
    active = []
    for row in rows:
        if not row.value:
            continue
        try:
            p = json.loads(row.value)
        except (json.JSONDecodeError, ValueError, TypeError):
            continue
        if p.get('status') == 'running':
            active.append(_enrich(p))
    return active


def cleanup(max_age_seconds=300):
    """Remove completed/failed jobs older than max_age_seconds."""
    from app import db
    from app.models import SystemSettings
    threshold = datetime.utcnow() - timedelta(seconds=max_age_seconds)
    rows = SystemSettings.query.filter(
        SystemSettings.category == _CATEGORY,
        SystemSettings.organization_id.is_(None),
        SystemSettings.key.like(f'{_PREFIX}%'),
        SystemSettings.updated_at < threshold,
    ).all()
    deleted = 0
    for row in rows:
        if not row.value:
            db.session.delete(row)
            deleted += 1
            continue
        try:
            p = json.loads(row.value)
        except (json.JSONDecodeError, ValueError, TypeError):
            db.session.delete(row)
            deleted += 1
            continue
        if p.get('status') in ('completed', 'error'):
            db.session.delete(row)
            deleted += 1
    if deleted:
        db.session.commit()
