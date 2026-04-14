"""
SSO / impersonation endpoint for the license-server admin portal
(Sprint 6 contract — section C).

When an operator in the upstream SentriKat-web portal clicks
"Impersonate tenant", that portal mints a short-lived HS256 JWT with
``aud="saas"`` and TTL 60s, then redirects the operator's browser to
``GET /admin/sso?token=<jwt>``. This handler:

1. Verifies the JWT signature + exp + audience using
   ``SENTRIKAT_SSO_SECRET`` (same secret on both sides).
2. Looks up the tenant indicated by the ``tenant_id`` claim
   (customer email — matches the webhook and metering conventions).
3. Establishes a Flask session scoped to an admin user in that
   organization, marked as impersonated.
4. Writes an audit log entry with
   ``reason="sso_from_license_server"`` so support accesses are
   traceable.
5. Redirects to the tenant dashboard.

JWT claim shape (per contract)::

    {
      "sub":       "sentrikat-admin",
      "aud":       "saas",
      "tenant_id": "alice@example.com",
      "ts":        <int, unix seconds>,
      "exp":       <int, ts + 60>,
      "nonce":     "<opaque string>"
    }

Security properties
-------------------

* Tokens are single-use: the ``nonce`` claim is persisted in
  ``SystemSettings`` with a TTL matching the token ``exp``, so a
  replayed token is rejected even within its 60s validity window.
* All failures (expired, bad signature, replay, unknown tenant)
  return **401 with a generic body** to avoid oracle'ing the
  portal about which claim failed. Details are logged server-side.
* The mock-friendly TTL is intentionally short (60s): the upstream
  contract marks it non-negotiable, and we do not relax it here.
"""

from __future__ import annotations

import logging
import os
from datetime import datetime, timedelta

import jwt  # PyJWT
from flask import Blueprint, abort, redirect, request, session, url_for

logger = logging.getLogger(__name__)

sso_api_bp = Blueprint('sso_api', __name__)

#: JWT audience the upstream portal must sign with.
JWT_AUDIENCE = 'saas'

#: JWT signing algorithm. HS256 matches the upstream contract.
JWT_ALGORITHM = 'HS256'

#: Nonce storage key prefix in ``SystemSettings`` for replay detection.
NONCE_KEY_PREFIX = 'sso:nonce:'

#: Maximum nonce retention window. Tokens beyond TTL are worthless, but
#: we keep the nonce a bit longer (5 minutes) so a replayed token with
#: a slightly-ahead clock still gets rejected.
NONCE_RETENTION_SECONDS = 300


def _get_sso_secret() -> str | None:
    secret = (os.environ.get('SENTRIKAT_SSO_SECRET') or '').strip()
    return secret or None


def _nonce_seen(nonce: str) -> bool:
    """Return True if we've already consumed this nonce."""
    try:
        from app.models import SystemSettings
        row = SystemSettings.query.filter_by(key=NONCE_KEY_PREFIX + nonce).first()
        if row is None:
            return False
        if row.updated_at:
            age = (datetime.utcnow() - row.updated_at).total_seconds()
            if age > NONCE_RETENTION_SECONDS:
                return False
        return True
    except Exception as e:
        logger.debug(f"nonce lookup failed: {e}")
        return False


def _mark_nonce_seen(nonce: str) -> None:
    """Persist the nonce so a replayed token is rejected."""
    try:
        from app.models import SystemSettings
        from app import db as app_db
        key = NONCE_KEY_PREFIX + nonce
        row = SystemSettings.query.filter_by(key=key).first()
        if row is None:
            row = SystemSettings(
                key=key, value='1', category='sso',
                description='SSO impersonation nonce (replay protection)',
            )
            app_db.session.add(row)
        else:
            row.updated_at = datetime.utcnow()
        app_db.session.commit()
    except Exception as e:
        logger.warning(f"could not persist SSO nonce {nonce}: {e}")


def _resolve_admin_for_tenant(tenant_email: str):
    """Return an admin ``User`` for the tenant identified by email.

    We impersonate a specific user (not an anonymous admin) so the
    resulting session carries a real identity and all downstream ACL
    checks work normally. We prefer role='admin' but fall back to any
    user belonging to the same org.
    """
    try:
        from app.models import Organization, User
    except Exception:
        return None

    if not tenant_email:
        return None

    norm = tenant_email.strip().lower()

    # 1) user with matching email
    user = User.query.filter(User.email.ilike(norm)).first()
    if user is not None:
        return user

    # 2) org with matching billing_email, then any admin user in it
    if hasattr(Organization, 'billing_email'):
        org = Organization.query.filter(
            Organization.billing_email.ilike(norm)
        ).first()
        if org is not None:
            admin = User.query.filter_by(
                organization_id=org.id, role='admin'
            ).order_by(User.id.asc()).first()
            if admin is not None:
                return admin

    return None


def _audit_impersonation(user, nonce: str, claims: dict) -> None:
    """Append an audit log entry for SSO impersonation.

    We intentionally avoid adding a new audit table — the existing
    ``audit_log`` (or whichever table is already used by the app) is
    the correct place. If the model is missing we fall back to the
    standard logger at INFO level so the event is still observable.
    """
    try:
        from app.models import AuditLog
        from app import db as app_db
        entry = AuditLog(
            user_id=user.id if user else None,
            organization_id=getattr(user, 'organization_id', None),
            action='sso_impersonate',
            resource_type='session',
            resource_id=nonce,
            details={
                'reason': 'sso_from_license_server',
                'impersonator_sub': claims.get('sub'),
                'tenant_id': claims.get('tenant_id'),
                'token_ts': claims.get('ts'),
                'token_exp': claims.get('exp'),
                'nonce': nonce,
            },
            ip_address=request.remote_addr,
        )
        app_db.session.add(entry)
        app_db.session.commit()
    except Exception as e:
        # AuditLog may not exist in every deployment — log loudly
        # at INFO level so operators can still correlate the access.
        logger.info(
            "SSO impersonation (audit log write failed: %s): "
            "user=%s tenant=%s nonce=%s reason=sso_from_license_server",
            e,
            getattr(user, 'email', None),
            claims.get('tenant_id'),
            nonce,
        )


# ---------------------------------------------------------------------------
# Route
# ---------------------------------------------------------------------------

@sso_api_bp.route('/admin/sso', methods=['GET'])
def sso_login():
    """Handle the GET redirect from the license-server portal."""
    secret = _get_sso_secret()
    if not secret:
        logger.error("SSO called but SENTRIKAT_SSO_SECRET is not set")
        abort(401)

    token = (request.args.get('token') or '').strip()
    if not token:
        abort(401)

    try:
        claims = jwt.decode(
            token,
            secret,
            algorithms=[JWT_ALGORITHM],
            audience=JWT_AUDIENCE,
            options={'require': ['exp', 'aud', 'tenant_id', 'nonce']},
        )
    except jwt.ExpiredSignatureError:
        logger.warning("SSO token expired (ip=%s)", request.remote_addr)
        abort(401)
    except jwt.InvalidAudienceError:
        logger.warning("SSO token has wrong audience (ip=%s)", request.remote_addr)
        abort(401)
    except jwt.InvalidTokenError as e:
        logger.warning("SSO token invalid (%s) ip=%s", e, request.remote_addr)
        abort(401)

    # Hard-required claims the upstream contract mandates.
    tenant_email = claims.get('tenant_id')
    nonce = claims.get('nonce')
    sub = claims.get('sub')
    if not tenant_email or not nonce or sub != 'sentrikat-admin':
        logger.warning("SSO token missing required claims ip=%s", request.remote_addr)
        abort(401)

    # Replay protection — consume nonce.
    if _nonce_seen(nonce):
        logger.warning(
            "SSO token replay detected nonce=%s ip=%s",
            nonce, request.remote_addr,
        )
        abort(401)
    _mark_nonce_seen(nonce)

    # Resolve a real user to impersonate.
    user = _resolve_admin_for_tenant(tenant_email)
    if user is None:
        logger.warning(
            "SSO: no admin user resolvable for tenant=%s ip=%s",
            tenant_email, request.remote_addr,
        )
        abort(401)

    # Establish a session that looks like the real user logged in, but
    # clearly marked as impersonated so downstream middleware can flag
    # the banner in the UI.
    session.clear()
    session['user_id'] = user.id
    session['username'] = user.username
    session['organization_id'] = getattr(user, 'organization_id', None)
    session['impersonated'] = True
    session['impersonated_by'] = sub
    session['impersonated_via'] = 'license_server'
    session['impersonated_nonce'] = nonce
    session.permanent = True

    _audit_impersonation(user, nonce, claims)

    # Redirect to the dashboard. The real endpoint is ``main.index``
    # (route ``/``) — we previously redirected to ``/dashboard`` which
    # does not exist in this app and produced a 404 immediately after
    # a successful SSO handshake. Fall back to ``/`` if ``url_for`` is
    # unavailable (e.g. blueprint not yet registered at import time).
    try:
        dest = url_for('main.index')
    except Exception:
        dest = '/'

    logger.info(
        "SSO impersonation successful user=%s org=%s tenant=%s nonce=%s",
        user.email, session['organization_id'], tenant_email, nonce,
    )
    return redirect(dest)
