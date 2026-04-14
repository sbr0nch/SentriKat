"""
License-server webhook receiver (B3).

The upstream SentriKat license server (sbr0nch/SentriKat-web) pushes events
to this SaaS instance whenever a license state transition happens — for
example when an operator revokes or restores a license, updates a plan, or
cancels a subscription.

Endpoint
--------

``POST /api/license/events`` — JSON body::

    {
      "event_type": "license_revoked" | "license_restored"
                  | "plan_updated" | "limits_updated"
                  | "subscription_cancelled",
      "tenant_id":  int | null,
      "timestamp":  int (unix seconds),
      "payload":    { ... event-specific data ... }
    }

Required headers
----------------

* ``X-SentriKat-Signature`` — hex-encoded HMAC-SHA256 of the raw request
  body, keyed with the environment variable ``SENTRIKAT_WEBHOOK_SECRET``.
  Compared with :func:`hmac.compare_digest` to avoid timing attacks.
* ``X-SentriKat-Timestamp`` — unix seconds, must be within ±300s of now.
* ``X-Idempotency-Key`` — UUID, used to dedupe retries. We persist the
  response JSON in :class:`SystemSettings` under
  ``webhook:idempotency:<uuid>`` for 24 hours; replays return the cached
  response body with HTTP 200.

Response codes
--------------

* ``200`` — event processed (or duplicated idempotency key replayed).
* ``400`` — malformed body, bad timestamp skew or missing headers.
* ``401`` — signature verification failed or webhook secret unset.

Logging
-------

Every accepted event is logged at INFO level with ``tenant_id``,
``event_type`` and ``idempotency_key`` so operators can correlate pushes
from the upstream license server.
"""

from __future__ import annotations

import hmac
import hashlib
import json
import logging
import os
import time
import uuid as _uuid
from datetime import datetime, timedelta

from flask import Blueprint, request, jsonify

logger = logging.getLogger(__name__)

license_webhook_bp = Blueprint('license_webhook', __name__)

# The license server authenticates with its own HMAC signature — CSRF tokens
# do not apply to cross-service webhook calls.
try:
    from app import csrf as _csrf
    _csrf.exempt(license_webhook_bp)
except Exception:  # pragma: no cover - csrf unavailable in tests without app ctx
    pass

#: Maximum accepted clock skew between webhook sender and receiver (seconds).
WEBHOOK_MAX_SKEW_SECONDS = 300

#: Idempotency cache TTL in hours. Duplicate deliveries within this window
#: return the cached response body instead of re-running the handler.
IDEMPOTENCY_TTL_HOURS = 24

#: Recognised event types. Anything else returns a 400.
ALLOWED_EVENT_TYPES = frozenset({
    'license_revoked',
    'license_restored',
    'plan_updated',
    'limits_updated',
    'subscription_cancelled',
})


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _get_webhook_secret() -> str | None:
    secret = (os.environ.get('SENTRIKAT_WEBHOOK_SECRET') or '').strip()
    return secret or None


def _verify_signature(raw_body: bytes, provided: str, secret: str) -> bool:
    """Constant-time HMAC-SHA256 comparison of the provided hex signature."""
    if not provided:
        return False
    expected = hmac.new(
        secret.encode('utf-8'),
        raw_body,
        hashlib.sha256,
    ).hexdigest()
    try:
        return hmac.compare_digest(expected, provided.strip().lower())
    except Exception:
        return False


def _parse_timestamp(header_value: str) -> int | None:
    if header_value is None:
        return None
    try:
        return int(header_value)
    except (TypeError, ValueError):
        return None


def _is_uuid(value: str) -> bool:
    try:
        _uuid.UUID(value)
        return True
    except (ValueError, AttributeError, TypeError):
        return False


def _idempotency_key_for(uuid_str: str) -> str:
    return f"webhook:idempotency:{uuid_str}"


def _lookup_idempotency(uuid_str: str):
    """Return a cached response dict if we've already processed this key.

    Entries older than :data:`IDEMPOTENCY_TTL_HOURS` are treated as expired
    and will be overwritten on the next call.
    """
    try:
        from app.models import SystemSettings
        row = SystemSettings.query.filter_by(
            key=_idempotency_key_for(uuid_str)
        ).first()
        if not row or not row.value:
            return None

        # Expire old entries lazily.
        cutoff = datetime.utcnow() - timedelta(hours=IDEMPOTENCY_TTL_HOURS)
        if row.updated_at and row.updated_at < cutoff:
            return None

        try:
            return json.loads(row.value)
        except (json.JSONDecodeError, ValueError):
            return None
    except Exception as e:
        logger.debug(f"idempotency lookup failed: {e}")
        return None


def _store_idempotency(uuid_str: str, response_body: dict) -> None:
    """Persist the response body under the idempotency key.

    Stored inside :class:`SystemSettings` because that table already exists
    in every deployment and it's trivially queryable from the webhook
    receiver without adding a new model.
    """
    try:
        from app.models import SystemSettings
        from app import db as app_db
        key = _idempotency_key_for(uuid_str)
        row = SystemSettings.query.filter_by(key=key).first()
        serialized = json.dumps(response_body)
        if row:
            row.value = serialized
            row.updated_at = datetime.utcnow()
        else:
            row = SystemSettings(
                key=key,
                value=serialized,
                category='webhook',
                description='License-server webhook idempotency cache',
            )
            app_db.session.add(row)
        app_db.session.commit()
    except Exception as e:
        logger.warning(f"Could not persist idempotency key {uuid_str}: {e}")
        try:
            from app import db as app_db
            app_db.session.rollback()
        except Exception:
            pass


def _system_settings_set(key: str, value: str, category: str = 'licensing') -> None:
    from app.models import SystemSettings
    from app import db as app_db
    row = SystemSettings.query.filter_by(key=key).first()
    if row:
        row.value = value
    else:
        row = SystemSettings(
            key=key, value=value, category=category,
            description='Managed by license webhook receiver',
        )
        app_db.session.add(row)
    app_db.session.commit()


# ---------------------------------------------------------------------------
# Event handlers
# ---------------------------------------------------------------------------

def _handle_license_revoked(tenant_id, payload):
    _system_settings_set('license_revoked', 'true')
    # Bust the in-process license cache so the next get_license() picks up
    # the new revocation state immediately.
    try:
        from app.licensing import reload_license
        reload_license()
    except Exception:
        pass
    return {'status': 'ok', 'action': 'license_revoked'}


def _handle_license_restored(tenant_id, payload):
    _system_settings_set('license_revoked', 'false')
    try:
        from app.licensing import reload_license
        reload_license()
    except Exception:
        pass
    return {'status': 'ok', 'action': 'license_restored'}


def _apply_plan_limits(tenant_id, payload):
    """Shared body for plan_updated and limits_updated events.

    Looks up the :class:`Subscription` for ``tenant_id`` and mirrors the
    supplied limits onto the attached :class:`SubscriptionPlan`. models.py
    is NOT modified — we only issue query/setattr/commit.
    """
    from app.models import Subscription
    from app import db as app_db

    if tenant_id is None:
        # No tenant scope → apply globally to the first active subscription.
        sub = Subscription.query.filter(
            Subscription.status.in_(('active', 'trialing'))
        ).first()
    else:
        sub = Subscription.query.filter_by(organization_id=tenant_id).first()

    if not sub or not sub.plan:
        logger.info(
            f"plan/limits update for tenant={tenant_id}: no subscription found, skipping"
        )
        return {'status': 'ok', 'action': 'plan_update_skipped', 'reason': 'no_subscription'}

    plan = sub.plan
    changed = {}

    # Plan rename (validated against the enum in app.licensing).
    plan_name = payload.get('plan_name')
    if plan_name and hasattr(plan, 'name'):
        try:
            from app.licensing import validate_plan_name
            new_name = validate_plan_name(plan_name)
            if plan.name != new_name:
                plan.name = new_name
                changed['name'] = new_name
        except ValueError as ve:
            logger.warning(f"webhook: invalid plan_name {plan_name!r}: {ve}")

    # Integer/optional limit fields.
    simple_mappings = {
        'max_agents': 'max_agents',
        'max_users': 'max_users',
        'max_products': 'max_products',
    }
    for src, attr in simple_mappings.items():
        if src in payload and hasattr(plan, attr):
            val = payload[src]
            if val is None:
                val = -1
            if getattr(plan, attr) != val:
                setattr(plan, attr, val)
                changed[attr] = val

    # Storage: webhook gives GB, plan stores MB.
    if 'max_storage_gb' in payload and hasattr(plan, 'max_storage_mb'):
        gb = payload['max_storage_gb']
        if gb is not None:
            new_mb = int(gb) * 1024
            if plan.max_storage_mb != new_mb:
                plan.max_storage_mb = new_mb
                changed['max_storage_mb'] = new_mb

    # Features: accept list or JSON string.
    if 'features' in payload and hasattr(plan, 'features'):
        feats = payload['features']
        try:
            plan.features = json.dumps(feats) if not isinstance(feats, str) else feats
            changed['features'] = True
        except Exception:
            pass

    try:
        app_db.session.commit()
        logger.info(
            f"Plan updated via webhook (tenant={tenant_id}, plan={plan.name}): {changed}"
        )
        return {'status': 'ok', 'action': 'plan_updated', 'changes': changed}
    except Exception as e:
        app_db.session.rollback()
        logger.error(f"Failed to persist plan update from webhook: {e}")
        return {'status': 'error', 'error': str(e)}


def _handle_plan_updated(tenant_id, payload):
    return _apply_plan_limits(tenant_id, payload)


def _handle_limits_updated(tenant_id, payload):
    return _apply_plan_limits(tenant_id, payload)


def _handle_subscription_cancelled(tenant_id, payload):
    """Mark the tenant's subscription as canceled and deactivate the org."""
    from app.models import Subscription, Organization
    from app import db as app_db

    if tenant_id is None:
        return {'status': 'error', 'error': 'tenant_id required for subscription_cancelled'}

    sub = Subscription.query.filter_by(organization_id=tenant_id).first()
    if sub:
        sub.status = 'canceled'
        sub.canceled_at = datetime.utcnow()

    org = Organization.query.get(tenant_id)
    if org is not None and hasattr(org, 'active'):
        # Organization has no ``status`` column in this schema; ``active``
        # is the closest semantic equivalent ("is this tenant allowed to
        # use the product?") so we flip it off.
        org.active = False

    try:
        app_db.session.commit()
    except Exception as e:
        app_db.session.rollback()
        logger.error(f"subscription_cancelled commit failed: {e}")
        return {'status': 'error', 'error': str(e)}

    return {'status': 'ok', 'action': 'subscription_cancelled'}


EVENT_HANDLERS = {
    'license_revoked': _handle_license_revoked,
    'license_restored': _handle_license_restored,
    'plan_updated': _handle_plan_updated,
    'limits_updated': _handle_limits_updated,
    'subscription_cancelled': _handle_subscription_cancelled,
}


# ---------------------------------------------------------------------------
# Route
# ---------------------------------------------------------------------------

@license_webhook_bp.route('/api/license/events', methods=['POST'])
def receive_license_event():
    """Receive a push event from the upstream license server."""
    # Webhook secret is mandatory: without it we can't authenticate anything
    # and we prefer failing closed over silently accepting unsigned pushes.
    secret = _get_webhook_secret()
    if not secret:
        logger.error("license webhook called but SENTRIKAT_WEBHOOK_SECRET is not set")
        return jsonify({'error': 'webhook not configured'}), 401

    raw_body = request.get_data(cache=False) or b''

    # --- Signature (401 on mismatch) -------------------------------------
    provided_sig = request.headers.get('X-SentriKat-Signature', '')
    if not _verify_signature(raw_body, provided_sig, secret):
        logger.warning(
            "Rejected license webhook: bad signature from %s",
            request.remote_addr,
        )
        return jsonify({'error': 'invalid signature'}), 401

    # --- Timestamp skew (400) --------------------------------------------
    ts_header = request.headers.get('X-SentriKat-Timestamp', '')
    ts = _parse_timestamp(ts_header)
    if ts is None:
        return jsonify({'error': 'missing or invalid X-SentriKat-Timestamp header'}), 400
    now_ts = int(time.time())
    if abs(now_ts - ts) > WEBHOOK_MAX_SKEW_SECONDS:
        logger.warning(
            "Rejected license webhook: timestamp skew %s seconds (max %s)",
            abs(now_ts - ts), WEBHOOK_MAX_SKEW_SECONDS,
        )
        return jsonify({'error': 'timestamp skew too large'}), 400

    # --- Idempotency key --------------------------------------------------
    idem_key = (request.headers.get('X-Idempotency-Key') or '').strip()
    if not idem_key or not _is_uuid(idem_key):
        return jsonify({'error': 'missing or invalid X-Idempotency-Key header'}), 400

    cached = _lookup_idempotency(idem_key)
    if cached is not None:
        logger.info(
            "license webhook idempotency replay idempotency_key=%s", idem_key
        )
        return jsonify(cached), 200

    # --- Parse body -------------------------------------------------------
    try:
        body = json.loads(raw_body.decode('utf-8') or '{}')
    except (json.JSONDecodeError, UnicodeDecodeError) as e:
        return jsonify({'error': f'invalid JSON body: {e}'}), 400

    if not isinstance(body, dict):
        return jsonify({'error': 'body must be a JSON object'}), 400

    event_type = body.get('event_type')
    tenant_id = body.get('tenant_id')
    payload = body.get('payload') or {}

    if event_type not in ALLOWED_EVENT_TYPES:
        return jsonify({
            'error': f'unknown event_type: {event_type!r}',
            'allowed': sorted(ALLOWED_EVENT_TYPES),
        }), 400

    if tenant_id is not None and not isinstance(tenant_id, int):
        return jsonify({'error': 'tenant_id must be integer or null'}), 400

    if not isinstance(payload, dict):
        return jsonify({'error': 'payload must be a JSON object'}), 400

    # Structured audit log for every accepted event.
    logger.info(
        "license webhook accepted event_type=%s tenant_id=%s idempotency_key=%s",
        event_type, tenant_id, idem_key,
    )

    handler = EVENT_HANDLERS[event_type]
    try:
        result = handler(tenant_id, payload)
    except Exception as e:
        logger.exception(
            "license webhook handler failed event_type=%s tenant_id=%s: %s",
            event_type, tenant_id, e,
        )
        return jsonify({'error': f'handler failed: {e}'}), 500

    response_body = {
        'received': True,
        'event_type': event_type,
        'tenant_id': tenant_id,
        'idempotency_key': idem_key,
        'result': result,
    }
    _store_idempotency(idem_key, response_body)
    return jsonify(response_body), 200
