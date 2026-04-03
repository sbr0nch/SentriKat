"""
Internal API endpoints for cross-VM communication.

Exposes /internal/logs so the admin portal (Web VM) can pull
structured SaaS logs remotely. Secured by INTERNAL_API_KEY and
optionally IP-whitelisted via nginx.
"""

import os
import logging
from datetime import datetime, timedelta

from flask import Blueprint, request, jsonify
from app.models import db, SaasLog

logger = logging.getLogger(__name__)

internal_bp = Blueprint('internal', __name__, url_prefix='/internal')

INTERNAL_API_KEY = os.environ.get('INTERNAL_API_KEY', '')

# Valid filter values
VALID_SOURCES = {'app', 'worker', 'scheduler', 'auth', 'nginx'}
VALID_LEVELS = {'debug', 'info', 'warning', 'error', 'critical'}


def _require_internal_key():
    """Verify Bearer token matches INTERNAL_API_KEY."""
    if not INTERNAL_API_KEY:
        return jsonify({'error': 'Internal API not configured'}), 503

    auth_header = request.headers.get('Authorization', '')
    if not auth_header.startswith('Bearer '):
        return jsonify({'error': 'Unauthorized'}), 401

    token = auth_header[7:]
    if token != INTERNAL_API_KEY:
        return jsonify({'error': 'Unauthorized'}), 401

    return None


def _escape_like(value):
    """Escape LIKE wildcards to prevent injection."""
    return value.replace('%', r'\%').replace('_', r'\_')


@internal_bp.route('/logs', methods=['GET'])
def get_logs():
    """Return recent SaaS log entries for the admin portal.

    Query params:
        source:    Filter by source (app, worker, scheduler, auth, nginx)
        level:     Filter by level (info, warning, error, critical)
        search:    Full-text search on message
        date_from: ISO date lower bound
        date_to:   ISO date upper bound
        limit:     Max entries (default 100, max 1000)
        offset:    Pagination offset (default 0)
    """
    auth_err = _require_internal_key()
    if auth_err:
        return auth_err

    # Parse query params
    source = request.args.get('source', '').strip().lower()
    level = request.args.get('level', '').strip().lower()
    search = request.args.get('search', '').strip()
    date_from = request.args.get('date_from', '').strip()
    date_to = request.args.get('date_to', '').strip()

    try:
        limit = min(int(request.args.get('limit', 100)), 1000)
    except (ValueError, TypeError):
        limit = 100

    try:
        offset = max(int(request.args.get('offset', 0)), 0)
    except (ValueError, TypeError):
        offset = 0

    # Build query
    query = SaasLog.query

    if source and source in VALID_SOURCES:
        query = query.filter(SaasLog.source == source)

    if level and level in VALID_LEVELS:
        query = query.filter(SaasLog.level == level)

    if search:
        escaped = _escape_like(search)
        query = query.filter(SaasLog.message.ilike(f'%{escaped}%'))

    if date_from:
        try:
            dt_from = datetime.fromisoformat(date_from.replace('Z', '+00:00'))
            query = query.filter(SaasLog.timestamp >= dt_from)
        except ValueError:
            pass

    if date_to:
        try:
            dt_to = datetime.fromisoformat(date_to.replace('Z', '+00:00'))
            query = query.filter(SaasLog.timestamp <= dt_to)
        except ValueError:
            pass

    # Get total count for pagination
    total = query.count()

    # Fetch entries ordered by timestamp descending
    entries = (
        query
        .order_by(SaasLog.timestamp.desc())
        .offset(offset)
        .limit(limit)
        .all()
    )

    # Compute today's stats
    today_start = datetime.utcnow().replace(hour=0, minute=0, second=0, microsecond=0)
    errors_today = SaasLog.query.filter(
        SaasLog.timestamp >= today_start,
        SaasLog.level == 'error'
    ).count()
    warnings_today = SaasLog.query.filter(
        SaasLog.timestamp >= today_start,
        SaasLog.level == 'warning'
    ).count()

    return jsonify({
        'entries': [e.to_dict() for e in entries],
        'stats': {
            'total': total,
            'errors_today': errors_today,
            'warnings_today': warnings_today,
        }
    })
