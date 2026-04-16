"""
License-server webhook receiver (B3) — Sprint 6 contract.

The upstream SentriKat license server (sbr0nch/SentriKat-web) pushes events
to this SaaS instance whenever a license state transition happens. The
contract is:

Endpoint
--------

``POST /api/license/events`` — JSON body::

    {
      "event_type": "license.plan_changed" | "license.revoked"
                  | "license.limits_updated"
                  | "license.suspended" | "license.unsuspended",
      "tenant_id":  "<customer-email>",          # email string (primary key upstream)
      "timestamp":  "<ISO-8601 UTC>",            # sent for human logs only
      "payload":    { ... event-specific data ... }
    }

Event-specific payloads (straight from upstream contract):

* ``license.plan_changed``::

      {license_id, license_key, from_edition, from_status, to_edition,
       to_status, max_agents, subscription_years, reason}

* ``license.revoked``::

      {license_id, license_key, edition, reason}

* ``license.limits_updated``::

      {license_id, license_key,
       limits: {max_users, max_products, max_agents, max_organizations},
       changed: {<field>: {from, to}, ...},
       reason}

* ``license.suspended``::

      {license_id, license_key, stripe_subscription_id, reason}

* ``license.unsuspended``::

      {license_id, license_key, reason}

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

#: Recognised event types (Sprint 6 contract). Anything else returns 400.
ALLOWED_EVENT_TYPES = frozenset({
    'license.plan_changed',
    'license.revoked',
    'license.limits_updated',
    'license.suspended',
    'license.unsuspended',
    'license.addon_changed',
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
# Tenant lookup (Sprint 6 contract uses email as tenant primary key)
# ---------------------------------------------------------------------------

def _lookup_org_by_email(email):
    """Resolve an ``Organization`` from the tenant email the upstream uses.

    The license server identifies tenants by the customer's primary email.
    On our side the primary key is ``organization_id`` (int), so we need a
    lookup: first check ``Organization.billing_email`` (if the column
    exists), then fall back to the org whose owner/admin user has that
    email, then to any user with that email (covering legacy data).

    Returns ``(organization, user)`` — either may be ``None`` if the
    respective row is not found. This lets the caller decide whether to
    log a warning or fall back to a system-wide operation.
    """
    try:
        from app.models import Organization, User
    except Exception as e:
        logger.debug(f"tenant lookup: models unavailable: {e}")
        return None, None

    if not email or not isinstance(email, str):
        return None, None

    email = email.strip().lower()

    # 1. Organization.billing_email (if the schema exposes it).
    org = None
    if hasattr(Organization, 'billing_email'):
        try:
            org = Organization.query.filter(
                Organization.billing_email.ilike(email)
            ).first()
        except Exception:
            org = None

    # 2. Fall back to the user with that email.
    user = None
    try:
        user = User.query.filter(User.email.ilike(email)).first()
    except Exception:
        user = None

    if org is None and user is not None:
        # Prefer the organization the user is active in.
        org_id = getattr(user, 'organization_id', None)
        if org_id:
            try:
                org = Organization.query.get(org_id)
            except Exception:
                org = None

    return org, user


def _find_subscription_for_tenant(tenant_email):
    """Return the ``Subscription`` to mutate for the given tenant email.

    Falls back to the first active subscription when the email does not
    resolve to a specific organization (e.g., single-tenant deployments).
    """
    try:
        from app.models import Subscription
    except Exception:
        return None, None

    org, _user = _lookup_org_by_email(tenant_email)
    if org is not None:
        sub = Subscription.query.filter_by(organization_id=org.id).first()
        return sub, org

    sub = Subscription.query.filter(
        Subscription.status.in_(('active', 'trialing'))
    ).first()
    return sub, None


# ---------------------------------------------------------------------------
# Event handlers (Sprint 6 payload shapes)
# ---------------------------------------------------------------------------

def _handle_license_revoked(tenant_email, payload):
    """``license.revoked`` — set the global revoked flag (fail-closed).

    Payload: ``{license_id, license_key, edition, reason}``. We don't need
    any of these fields to revoke — revocation is binary — but we log the
    ``reason`` so operators can correlate with the upstream audit log.
    """
    _system_settings_set('license_revoked', 'true')
    reason = payload.get('reason', 'no reason provided')
    logger.info(
        "license.revoked tenant=%s license_id=%s reason=%s",
        tenant_email, payload.get('license_id'), reason,
    )
    try:
        from app.licensing import reload_license
        reload_license()
    except Exception:
        pass
    return {'status': 'ok', 'action': 'license_revoked', 'reason': reason}


def _handle_license_unsuspended(tenant_email, payload):
    """``license.unsuspended`` — clear the revoked/suspended flag.

    The upstream contract uses ``suspended`` + ``unsuspended`` for Stripe
    payment-state transitions. From this side both lower to the same
    revoked flag (``true`` while suspended, ``false`` once restored).
    """
    _system_settings_set('license_revoked', 'false')
    _system_settings_set('license_suspended', 'false')
    logger.info(
        "license.unsuspended tenant=%s reason=%s",
        tenant_email, payload.get('reason'),
    )
    try:
        from app.licensing import reload_license
        reload_license()
    except Exception:
        pass
    return {'status': 'ok', 'action': 'license_unsuspended'}


def _handle_license_suspended(tenant_email, payload):
    """``license.suspended`` — Stripe subscription cancelled / non-payment.

    Unlike ``license.revoked``, a suspension is reversible: the upstream
    will emit ``license.unsuspended`` once payment succeeds. We mark both
    ``license_suspended`` and ``license_revoked`` so the read path
    (``LicenseInfo.is_valid``) fails closed until the matching
    unsuspended event arrives.
    """
    _system_settings_set('license_suspended', 'true')
    _system_settings_set('license_revoked', 'true')
    logger.info(
        "license.suspended tenant=%s stripe_sub=%s reason=%s",
        tenant_email,
        payload.get('stripe_subscription_id'),
        payload.get('reason'),
    )
    try:
        from app.licensing import reload_license
        reload_license()
    except Exception:
        pass
    return {'status': 'ok', 'action': 'license_suspended'}


def _handle_license_plan_changed(tenant_email, payload):
    """``license.plan_changed`` — upgrade/downgrade of edition.

    Payload::

        {license_id, license_key, from_edition, from_status, to_edition,
         to_status, max_agents, subscription_years, reason}

    Maps ``to_edition`` to one of the canonical :class:`SubscriptionPlan`
    rows and re-points ``sub.plan_id``. We do NOT rename plans in place:
    canonical plan rows are shared across tenants and renaming would
    corrupt other tenants' state (and hit the UNIQUE constraint on
    ``subscription_plans.name``).
    """
    from app.models import SubscriptionPlan
    from app import db as app_db

    sub, _org = _find_subscription_for_tenant(tenant_email)
    if not sub:
        logger.info(
            "license.plan_changed tenant=%s: no subscription, skipping",
            tenant_email,
        )
        return {
            'status': 'ok',
            'action': 'plan_change_skipped',
            'reason': 'no_subscription',
        }

    # Validate and resolve the target plan.
    to_edition = payload.get('to_edition')
    if not to_edition:
        return {'status': 'error', 'error': 'payload.to_edition required'}

    try:
        from app.licensing import validate_plan_name
        new_name = validate_plan_name(to_edition)
    except ValueError as ve:
        logger.warning(
            f"license.plan_changed invalid to_edition {to_edition!r}: {ve}"
        )
        return {'status': 'error', 'error': f'invalid to_edition: {to_edition}'}

    target_plan = SubscriptionPlan.query.filter_by(name=new_name).first()
    if target_plan is None:
        logger.error(
            "license.plan_changed canonical plan %r not found in DB",
            new_name,
        )
        return {
            'status': 'error',
            'error': f'plan {new_name!r} not found on SaaS (seeding issue)',
        }

    changed = {}
    if sub.plan_id != target_plan.id:
        old_name = sub.plan.name if sub.plan else None
        sub.plan_id = target_plan.id
        changed['plan'] = {'from': old_name, 'to': new_name}

    # ``max_agents`` is informational — the canonical plan already carries
    # the authoritative value. We override per-tenant on the Subscription
    # if a per-tenant column exists (schema varies).
    max_agents = payload.get('max_agents')
    if max_agents is not None and hasattr(sub, 'max_agents_override'):
        if getattr(sub, 'max_agents_override', None) != max_agents:
            sub.max_agents_override = max_agents
            changed['max_agents_override'] = max_agents

    try:
        app_db.session.commit()
        logger.info(
            "license.plan_changed tenant=%s from=%s to=%s changes=%s",
            tenant_email,
            payload.get('from_edition'),
            payload.get('to_edition'),
            changed,
        )
        return {'status': 'ok', 'action': 'plan_changed', 'changes': changed}
    except Exception as e:
        app_db.session.rollback()
        logger.error(f"license.plan_changed commit failed: {e}")
        return {'status': 'error', 'error': str(e)}


def _handle_license_limits_updated(tenant_email, payload):
    """``license.limits_updated`` — new per-plan caps.

    Payload::

        {license_id, license_key,
         limits: {max_users, max_products, max_agents, max_organizations},
         changed: {<field>: {from, to}, ...},
         reason}

    Note: the contract nests the limits under a ``limits`` sub-object
    (unlike our previous flat shape), so we read from ``payload['limits']``.
    """
    from app import db as app_db

    limits = payload.get('limits') or {}
    if not isinstance(limits, dict):
        return {'status': 'error', 'error': 'payload.limits must be an object'}

    sub, _org = _find_subscription_for_tenant(tenant_email)
    if not sub or not sub.plan:
        logger.info(
            "license.limits_updated tenant=%s: no subscription, skipping",
            tenant_email,
        )
        return {
            'status': 'ok',
            'action': 'limits_update_skipped',
            'reason': 'no_subscription',
        }

    plan = sub.plan
    changed = {}

    simple_mappings = {
        'max_agents': 'max_agents',
        'max_users': 'max_users',
        'max_products': 'max_products',
        'max_organizations': 'max_organizations',
    }
    for src, attr in simple_mappings.items():
        if src in limits and hasattr(plan, attr):
            val = limits[src]
            if val is None:
                val = -1
            if getattr(plan, attr) != val:
                setattr(plan, attr, val)
                changed[attr] = val

    # Storage (GB → MB) — optional, nullable per contract.
    if 'max_storage_gb' in limits and hasattr(plan, 'max_storage_mb'):
        gb = limits['max_storage_gb']
        if gb is not None:
            new_mb = int(gb) * 1024
            if plan.max_storage_mb != new_mb:
                plan.max_storage_mb = new_mb
                changed['max_storage_mb'] = new_mb

    # Features list — optional per contract.
    if 'features' in limits and hasattr(plan, 'features'):
        feats = limits['features']
        try:
            plan.features = json.dumps(feats) if not isinstance(feats, str) else feats
            changed['features'] = True
        except Exception:
            pass

    try:
        app_db.session.commit()
        logger.info(
            "license.limits_updated tenant=%s changes=%s reason=%s",
            tenant_email, changed, payload.get('reason'),
        )
        return {'status': 'ok', 'action': 'limits_updated', 'changes': changed}
    except Exception as e:
        app_db.session.rollback()
        logger.error(f"license.limits_updated commit failed: {e}")
        return {'status': 'error', 'error': str(e)}


def _handle_license_addon_changed(tenant_email, payload):
    """``license.addon_changed`` — enable or disable an add-on.

    Payload::

        {addon_name, enabled: true|false, reason}

    Toggles the named add-on on the tenant's :class:`Subscription` using
    :meth:`Subscription.set_addons`.  Unknown add-on names are accepted
    and stored (forward-compatible); the feature-gate layer simply ignores
    names it doesn't recognise.
    """
    from app import db as app_db

    addon_name = payload.get('addon_name')
    if not addon_name or not isinstance(addon_name, str):
        return {'status': 'error', 'error': 'payload.addon_name required (string)'}

    enabled = payload.get('enabled', True)
    if not isinstance(enabled, bool):
        # Be lenient: accept truthy/falsy values.
        enabled = bool(enabled)

    sub, _org = _find_subscription_for_tenant(tenant_email)
    if not sub:
        logger.info(
            "license.addon_changed tenant=%s: no subscription, skipping",
            tenant_email,
        )
        return {
            'status': 'ok',
            'action': 'addon_change_skipped',
            'reason': 'no_subscription',
        }

    addons = sub.get_addons()
    old_value = addons.get(addon_name)
    addons[addon_name] = enabled
    sub.set_addons(addons)

    try:
        app_db.session.commit()
        logger.info(
            "license.addon_changed tenant=%s addon=%s enabled=%s (was %s) reason=%s",
            tenant_email, addon_name, enabled, old_value, payload.get('reason'),
        )
        return {
            'status': 'ok',
            'action': 'addon_changed',
            'addon_name': addon_name,
            'enabled': enabled,
            'was': old_value,
        }
    except Exception as e:
        app_db.session.rollback()
        logger.error(f"license.addon_changed commit failed: {e}")
        return {'status': 'error', 'error': str(e)}


EVENT_HANDLERS = {
    'license.plan_changed': _handle_license_plan_changed,
    'license.revoked': _handle_license_revoked,
    'license.limits_updated': _handle_license_limits_updated,
    'license.suspended': _handle_license_suspended,
    'license.unsuspended': _handle_license_unsuspended,
    'license.addon_changed': _handle_license_addon_changed,
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

    # Sprint 6 contract: tenant_id is the customer's email address (string)
    # — the upstream license server uses it as primary key on its side.
    if tenant_id is not None and not isinstance(tenant_id, str):
        return jsonify({'error': 'tenant_id must be an email string or null'}), 400

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
