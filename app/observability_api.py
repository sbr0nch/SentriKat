"""
Sprint 6 super-admin observability pages.

Two read-only pages that expose the state of the cross-repo integration
with the upstream SentriKat-web license server:

* GET /super-admin/webhook-events — events received from the upstream
  webhook sender, pulled from SystemSettings idempotency cache.
* GET /super-admin/usage-uploads — last N usage uploads pushed from
  our scheduler job, pulled from SystemSettings observability cache.

Both pages require a super_admin session. They exist primarily for
on-call operators who need to answer "did the portal event arrive?"
and "when did I last successfully push usage?" without shelling into
the container and reading Docker logs.
"""

from __future__ import annotations

import json
import logging
from datetime import datetime, timedelta

from flask import Blueprint, render_template, session, abort

logger = logging.getLogger(__name__)

observability_bp = Blueprint('observability', __name__)


def _require_super_admin():
    """Gate for the observability pages.

    These pages surface cross-repo state (webhook events received from
    the upstream SentriKat-web license server, usage metering uploads
    sent to it). On on-prem installations there is no upstream license
    server, so the pages are SaaS-only — a local super_admin on-prem
    gets a 404, not a 403, to avoid hinting at the existence of routes
    that do not apply to their deployment (see bug [03.6.6] / [03.7.2] /
    [03.7.4]).
    """
    from app.saas import is_saas_mode
    from app.models import User
    from app import db as app_db
    if not is_saas_mode():
        abort(404)
    user_id = session.get('user_id')
    if not user_id:
        abort(403)
    user = app_db.session.get(User, user_id)
    if user is None or not hasattr(user, 'is_super_admin') or not user.is_super_admin():
        abort(403)
    return user


@observability_bp.route('/super-admin/webhook-events', methods=['GET'])
def webhook_events():
    _require_super_admin()
    from app.models import SystemSettings

    # Pull all idempotency entries from the cache. These are dated by
    # updated_at in the underlying row, so we can sort them cheaply.
    rows = (
        SystemSettings.query
        .filter(SystemSettings.key.like('webhook:idempotency:%'))
        .order_by(SystemSettings.updated_at.desc().nullslast())
        .limit(200)
        .all()
    )

    events = []
    for row in rows:
        try:
            body = json.loads(row.value) if row.value else {}
        except (json.JSONDecodeError, ValueError, TypeError):
            body = {'raw': row.value, '_parse_error': True}
        events.append({
            'idempotency_key': row.key.replace('webhook:idempotency:', '', 1),
            'received_at': row.updated_at,
            'event_type': body.get('event_type', '—'),
            'tenant_id': body.get('tenant_id', '—'),
            'result': body.get('result', {}),
            'full': body,
        })

    return render_template(
        'super_admin_webhook_events.html',
        events=events,
        event_count=len(events),
    )


@observability_bp.route('/super-admin/usage-uploads', methods=['GET'])
def usage_uploads():
    _require_super_admin()
    from app.models import SystemSettings

    # The metering job writes its last-run summary under this key.
    summary_row = SystemSettings.query.filter_by(
        key='usage_upload:last_run', organization_id=None
    ).first()
    summary = {}
    if summary_row and summary_row.value:
        try:
            summary = json.loads(summary_row.value)
        except (json.JSONDecodeError, ValueError, TypeError):
            summary = {'_parse_error': True}

    # Per-tenant last state is stored under usage_upload:tenant:<email>
    tenant_rows = (
        SystemSettings.query
        .filter(SystemSettings.key.like('usage_upload:tenant:%'))
        .all()
    )
    tenants = []
    for row in tenant_rows:
        try:
            body = json.loads(row.value) if row.value else {}
        except (json.JSONDecodeError, ValueError, TypeError):
            body = {'_parse_error': True, 'raw': row.value}
        tenants.append({
            'tenant_id': row.key.replace('usage_upload:tenant:', '', 1),
            'last_upload_at': row.updated_at,
            **body,
        })

    tenants.sort(key=lambda t: t.get('last_upload_at') or datetime.min, reverse=True)

    return render_template(
        'super_admin_usage_uploads.html',
        summary=summary,
        tenants=tenants,
        tenant_count=len(tenants),
    )
