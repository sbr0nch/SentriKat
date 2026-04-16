"""
SaaS Tenant Provisioning API

Called by the License Server after a successful Stripe payment/signup.
Creates Organization + User (org_admin) + Subscription automatically.

Security:
- Only available in SaaS mode
- Protected by SENTRIKAT_PROVISION_KEY (shared secret between License Server and SaaS app)
- Never exposed to end users

Endpoints:
- POST /api/provision             — Create new tenant (org + user + subscription)
- POST /api/provision/upgrade     — Change subscription plan
- POST /api/provision/cancel      — Cancel subscription
- GET  /api/provision/status      — Check tenant status (single tenant)
- POST /api/provision/reset-password — Reset tenant user password
- GET  /api/provision/tenants     — List all tenants (for license-server admin UI)
- GET  /api/provision/plans       — List all subscription plans
"""

import hmac
import os
import re
import secrets
import logging
from datetime import datetime, timedelta
from functools import wraps

from flask import Blueprint, request, jsonify
from app import db, csrf, limiter
from app.models import Organization, User, Subscription, SubscriptionPlan, UserOrganization, SystemSettings
from app.saas import is_saas_mode

# B8: idempotency keys are stored in system_settings with this prefix so we
# can deduplicate identical provisioning requests without adding a new table.
_IDEMPOTENCY_PREFIX = 'idempotency:provision:'
_IDEMPOTENCY_CATEGORY = 'provisioning'

logger = logging.getLogger(__name__)

provision_bp = Blueprint('provision', __name__, url_prefix='/api/provision')
csrf.exempt(provision_bp)  # API key auth, not CSRF

# Internal API key — shared between License Server and SaaS app
_PROVISION_KEY = os.environ.get('SENTRIKAT_PROVISION_KEY', '')


def _require_provision_key(f):
    """Decorator: requires valid provision API key in X-Provision-Key header."""
    @wraps(f)
    def decorated(*args, **kwargs):
        if not is_saas_mode():
            return jsonify({'error': 'Provisioning API is only available in SaaS mode'}), 403

        if not _PROVISION_KEY:
            logger.error("SENTRIKAT_PROVISION_KEY not configured. Provisioning disabled.")
            return jsonify({'error': 'Provisioning not configured'}), 503

        provided_key = request.headers.get('X-Provision-Key', '')
        if not provided_key or not hmac.compare_digest(provided_key, _PROVISION_KEY):
            logger.warning(f"Invalid provision key from {request.remote_addr}")
            return jsonify({'error': 'Invalid provision key'}), 401

        return f(*args, **kwargs)
    return decorated


def _generate_org_slug(company_name):
    """Generate a URL-safe organization slug from company name."""
    slug = re.sub(r'[^a-z0-9]+', '-', company_name.lower()).strip('-')
    slug = slug[:50]  # Max 50 chars

    # Ensure uniqueness
    base_slug = slug
    counter = 1
    while Organization.query.filter_by(name=slug).first():
        slug = f"{base_slug}-{counter}"
        counter += 1

    return slug


def _generate_temp_password():
    """Generate a secure temporary password."""
    # 16 chars: letters + digits + special
    return secrets.token_urlsafe(12)


@provision_bp.route('', methods=['POST'])
@limiter.limit("10/minute")
@_require_provision_key
def provision_tenant():
    """
    Create a new SaaS tenant.

    Called by License Server after Stripe checkout.session.completed.

    Request body:
    {
        "email": "user@company.com",          // Required
        "full_name": "Mario Rossi",            // Required
        "company_name": "Acme Corp",           // Required
        "plan_name": "starter",                // Optional, default: "free"
        "billing_cycle": "monthly",            // Optional: monthly|annual
        "stripe_customer_id": "cus_xxx",       // Optional (from Stripe)
        "stripe_subscription_id": "sub_xxx",   // Optional (from Stripe)
        "trial_days": 14                       // Optional, default: 14
    }

    Returns:
    {
        "success": true,
        "tenant": {
            "organization_id": 5,
            "organization_name": "acme-corp",
            "user_id": 12,
            "username": "user@company.com",
            "temporary_password": "xK9mN2pQ...",
            "login_url": "https://app.sentrikat.com/login",
            "plan": "starter",
            "trial_ends": "2026-04-08T00:00:00"
        }
    }
    """
    import json as _json

    data = request.get_json()
    if not data:
        return jsonify({'error': 'No data provided'}), 400

    # Validate required fields
    email = (data.get('email') or '').strip().lower()
    full_name = (data.get('full_name') or '').strip()
    company_name = (data.get('company_name') or '').strip()

    if not email or not full_name or not company_name:
        return jsonify({'error': 'email, full_name, and company_name are required'}), 400

    # Validate email format
    if not re.match(r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$', email):
        return jsonify({'error': 'Invalid email format'}), 400

    # ------------------------------------------------------------------
    # B8.1 — Idempotency: a network retry from the License Server must
    # not create duplicate orgs. If the caller provides `idempotency_key`
    # and we have already completed a provisioning with that key, return
    # the cached result verbatim.
    # ------------------------------------------------------------------
    idempotency_key = (data.get('idempotency_key') or '').strip()
    idem_setting_key = None
    if idempotency_key:
        # Defensive length cap; SystemSettings.key is VARCHAR(100).
        if len(idempotency_key) > 80:
            return jsonify({'error': 'idempotency_key too long (max 80 chars)'}), 400
        idem_setting_key = f'{_IDEMPOTENCY_PREFIX}{idempotency_key}'
        cached = SystemSettings.query.filter_by(
            key=idem_setting_key, organization_id=None
        ).first()
        if cached and cached.value:
            try:
                payload = _json.loads(cached.value)
                logger.info(
                    "Idempotent provisioning replay for key=%s", idempotency_key
                )
                return jsonify(payload), 201
            except Exception as parse_err:  # pragma: no cover - defensive
                logger.error(
                    "Failed to parse cached idempotency payload for %s: %s",
                    idempotency_key, parse_err,
                )

    # Check if user already exists. Response intentionally does NOT echo
    # the existing organization id (H4 information leak).
    existing_user = User.query.filter_by(email=email).first()
    if existing_user:
        return jsonify({
            'error': 'User with this email already exists',
            'code': 'USER_EXISTS',
        }), 409

    # B8.2 — Resolve subscription plan BEFORE starting any writes so that a
    # bad `plan_name` does not leave behind a half-created Organization/User.
    plan_name = data.get('plan_name', 'free')
    plan = SubscriptionPlan.query.filter_by(name=plan_name, is_active=True).first()
    if not plan:
        # Fall back to default plan
        plan = SubscriptionPlan.query.filter_by(is_default=True).first()
    if not plan:
        # Fall back to free plan
        plan = SubscriptionPlan.query.filter_by(name='free').first()
    if not plan:
        logger.error("No subscription plans found. Run seed_default_plans() first.")
        return jsonify({'error': 'No subscription plans configured'}), 500

    try:
        # ------------------------------------------------------------------
        # B8.2 — Atomic savepoint around Org/User/Membership/Subscription.
        # If anything inside fails, the nested transaction is rolled back
        # and we never leave orphan rows. The outer commit below persists
        # both the tenant and (optionally) the idempotency cache entry.
        # ------------------------------------------------------------------
        with db.session.begin_nested():
            # 1. Create Organization
            org_slug = _generate_org_slug(company_name)
            org = Organization(
                name=org_slug,
                display_name=company_name,
                description=f'SaaS tenant provisioned on {datetime.utcnow().strftime("%Y-%m-%d")}',
                active=True
            )
            db.session.add(org)
            db.session.flush()  # Get org.id

            # 2. Create User (org_admin)
            temp_password = _generate_temp_password()
            user = User(
                username=email,  # Use email as username for SaaS
                email=email,
                full_name=full_name[:100],
                organization_id=org.id,
                auth_type='local',
                role='org_admin',
                is_admin=True,
                is_active=True,
                can_manage_products=True,
                can_view_all_orgs=False,
                must_change_password=True  # Force password change on first login
            )
            user.set_password(temp_password)
            db.session.add(user)
            db.session.flush()  # Get user.id

            # 3. Create UserOrganization membership
            membership = UserOrganization(
                user_id=user.id,
                organization_id=org.id,
                role='org_admin'
            )
            db.session.add(membership)

            # 4. Create Subscription
            trial_days = data.get('trial_days', 14)
            now = datetime.utcnow()

            subscription = Subscription(
                organization_id=org.id,
                plan_id=plan.id,
                status='trialing' if trial_days > 0 else 'active',
                billing_cycle=data.get('billing_cycle', 'monthly'),
                current_period_start=now,
                current_period_end=now + timedelta(days=30),
                trial_start=now if trial_days > 0 else None,
                trial_end=(now + timedelta(days=trial_days)) if trial_days > 0 else None,
                stripe_customer_id=data.get('stripe_customer_id'),
                stripe_subscription_id=data.get('stripe_subscription_id')
            )
            db.session.add(subscription)
            db.session.flush()

        # Build response payload
        base_url = os.environ.get('SENTRIKAT_BASE_URL', 'https://app.sentrikat.com')
        response_payload = {
            'success': True,
            'tenant': {
                'organization_id': org.id,
                'organization_name': org.name,
                'organization_display_name': org.display_name,
                'user_id': user.id,
                'username': user.username,
                'email': user.email,
                'temporary_password': temp_password,
                'must_change_password': True,
                'login_url': f'{base_url}/login',
                'plan': plan.name,
                'plan_display_name': plan.display_name,
                'subscription_status': subscription.status,
                'trial_ends': subscription.trial_end.isoformat() if subscription.trial_end else None
            }
        }

        # Persist idempotency cache entry (same transaction as the tenant
        # writes so retries never see partial state).
        if idem_setting_key:
            db.session.add(SystemSettings(
                key=idem_setting_key,
                value=_json.dumps(response_payload),
                category=_IDEMPOTENCY_CATEGORY,
                description='Cached provisioning result for idempotency replay',
                organization_id=None,
            ))

        db.session.commit()

        logger.info(
            f"Provisioned new tenant: org={org_slug} (id={org.id}), "
            f"user={email} (id={user.id}), plan={plan.name}"
        )

        return jsonify(response_payload), 201

    except Exception as e:
        db.session.rollback()
        logger.exception(f"Failed to provision tenant for {email}: {e}")
        return jsonify({'error': 'Failed to provision tenant', 'details': str(e)}), 500


@provision_bp.route('/upgrade', methods=['POST'])
@limiter.limit("10/minute")
@_require_provision_key
def upgrade_subscription():
    """
    Upgrade or change a tenant's subscription plan.

    Called by License Server after Stripe subscription.updated webhook.

    Request body (accepts either format):
    {
        "organization_id": 5,                   // org_id or email required
        "email": "user@company.com",            // org_id or email required
        "plan_name": "pro",                     // plan_name or new_plan required
        "new_plan": "pro",                      // alias for plan_name
        "stripe_subscription_id": "sub_xxx",    // Optional
        "billing_cycle": "annual"               // Optional
    }
    """
    data = request.get_json()
    if not data:
        return jsonify({'error': 'No data provided'}), 400

    # Resolve organization: by org_id or by email lookup
    org_id = data.get('organization_id')
    if not org_id and data.get('email'):
        user = User.query.filter_by(email=data['email'].strip().lower()).first()
        if user:
            org_id = user.organization_id
        else:
            return jsonify({'error': f'No user found with email {data["email"]}'}), 404

    # Accept both plan_name and new_plan (sentrikat-web sends new_plan)
    plan_name = data.get('plan_name') or data.get('new_plan')

    if not org_id or not plan_name:
        return jsonify({'error': 'organization_id (or email) and plan_name (or new_plan) are required'}), 400

    # Find subscription
    sub = Subscription.query.filter_by(organization_id=org_id).first()
    if not sub:
        return jsonify({'error': 'No subscription found for this organization'}), 404

    # Find new plan
    new_plan = SubscriptionPlan.query.filter_by(name=plan_name, is_active=True).first()
    if not new_plan:
        return jsonify({'error': f'Plan "{plan_name}" not found'}), 404

    try:
        old_plan_name = sub.plan.name if sub.plan else 'none'
        sub.plan_id = new_plan.id
        sub.status = 'active'
        sub.updated_at = datetime.utcnow()

        if data.get('billing_cycle'):
            sub.billing_cycle = data['billing_cycle']
        if data.get('stripe_subscription_id'):
            sub.stripe_subscription_id = data['stripe_subscription_id']

        db.session.commit()

        logger.info(
            f"Subscription upgraded: org={org_id}, "
            f"{old_plan_name} → {plan_name}"
        )

        return jsonify({
            'success': True,
            'subscription': sub.to_dict()
        })

    except Exception as e:
        db.session.rollback()
        logger.exception(f"Failed to upgrade subscription for org {org_id}: {e}")
        return jsonify({'error': 'Failed to upgrade subscription'}), 500


@provision_bp.route('/cancel', methods=['POST'])
@limiter.limit("10/minute")
@_require_provision_key
def cancel_subscription():
    """
    Cancel a tenant's subscription.

    Called by License Server after Stripe subscription.deleted webhook.

    Request body (accepts either format):
    {
        "organization_id": 5,               // org_id or email required
        "email": "user@company.com",         // org_id or email required
        "cancel_at_period_end": true,        // Optional: grace period or immediate
        "stripe_subscription_id": "sub_xxx", // Optional
        "reason": "subscription_cancelled"   // Optional
    }
    """
    data = request.get_json()
    if not data:
        return jsonify({'error': 'No data provided'}), 400

    # Resolve organization: by org_id or by email lookup
    org_id = data.get('organization_id')
    if not org_id and data.get('email'):
        user = User.query.filter_by(email=data['email'].strip().lower()).first()
        if user:
            org_id = user.organization_id
        else:
            return jsonify({'error': f'No user found with email {data["email"]}'}), 404

    if not org_id:
        return jsonify({'error': 'organization_id or email is required'}), 400

    sub = Subscription.query.filter_by(organization_id=org_id).first()
    if not sub:
        return jsonify({'error': 'No subscription found for this organization'}), 404

    try:
        if data.get('cancel_at_period_end', True):
            # Grace period: keep active until period end, then downgrade to free
            sub.cancel_at_period_end = True
            sub.canceled_at = datetime.utcnow()
            logger.info(f"Subscription marked for cancellation at period end: org={org_id}")
        else:
            # Immediate: downgrade to free plan now
            free_plan = SubscriptionPlan.query.filter_by(name='free').first()
            if free_plan:
                sub.plan_id = free_plan.id
            sub.status = 'canceled'
            sub.canceled_at = datetime.utcnow()
            logger.info(f"Subscription canceled immediately: org={org_id}")

        db.session.commit()

        return jsonify({
            'success': True,
            'subscription': sub.to_dict()
        })

    except Exception as e:
        db.session.rollback()
        logger.exception(f"Failed to cancel subscription for org {org_id}: {e}")
        return jsonify({'error': 'Failed to cancel subscription'}), 500


@provision_bp.route('/status', methods=['GET'])
@limiter.limit("30/minute")
@_require_provision_key
def get_tenant_status():
    """
    Check tenant status by org_id or email.

    Query params:
        organization_id: int
        email: string
    """
    org_id = request.args.get('organization_id', type=int)
    email = request.args.get('email', '').strip().lower()

    if not org_id and not email:
        return jsonify({'error': 'organization_id or email is required'}), 400

    if email:
        user = User.query.filter_by(email=email).first()
        if not user:
            return jsonify({'error': 'User not found', 'exists': False}), 404
        org_id = user.organization_id

    org = Organization.query.get(org_id)
    if not org:
        return jsonify({'error': 'Organization not found', 'exists': False}), 404

    sub = Subscription.query.filter_by(organization_id=org_id).first()
    user_count = User.query.filter_by(organization_id=org_id, is_active=True).count()

    return jsonify({
        'exists': True,
        'organization': {
            'id': org.id,
            'name': org.name,
            'display_name': org.display_name,
            'active': org.active,
            'created_at': org.created_at.isoformat() if org.created_at else None
        },
        'subscription': sub.to_dict() if sub else None,
        'user_count': user_count
    })


@provision_bp.route('/reset-password', methods=['POST'])
@limiter.limit("10/minute")
@_require_provision_key
def reset_tenant_password():
    """
    Reset a tenant user's password.

    Called by License Server admin panel for EA tenant password resets.

    Request body:
    {
        "email": "user@company.com"
    }

    Returns:
    {
        "success": true,
        "temporary_password": "xK9mN2pQ...",
        "message": "Password reset for user@company.com"
    }
    """
    data = request.get_json()
    if not data:
        return jsonify({'error': 'No data provided'}), 400

    email = (data.get('email') or '').strip().lower()
    if not email:
        return jsonify({'error': 'email is required'}), 400

    user = User.query.filter_by(email=email).first()
    if not user:
        return jsonify({'error': 'User not found'}), 404

    try:
        temp_password = _generate_temp_password()
        user.set_password(temp_password)
        user.must_change_password = True
        db.session.commit()

        logger.info(f"Password reset via provision API for user: {email}")

        return jsonify({
            'success': True,
            'temporary_password': temp_password,
            'message': f'Password reset for {email}'
        })

    except Exception as e:
        db.session.rollback()
        logger.exception(f"Failed to reset password for {email}: {e}")
        return jsonify({'error': 'Failed to reset password'}), 500


# =============================================================================
# Admin listing endpoints
#
# These endpoints are consumed by the license-server admin UI (the "Live
# SaaS Tenants" and "Plans" widgets at portal.sentrikat.com/admin). They
# are read-only and return aggregated views across all tenants + the
# plan catalogue. Auth uses the same X-Provision-Key header as the rest
# of the provisioning blueprint.
#
# Design notes:
#
#  * No pagination yet — customer count is expected to stay under a few
#    thousand for the foreseeable future and the query is cheap. When
#    this stops being true, add ?page= + ?per_page= parameters and an
#    index on subscriptions.status.
#  * Filters are intentionally optional and compose with AND. Missing
#    filters return everything.
#  * Returned field names are deliberately descriptive
#    (organization_name, plan_name, admin_email) rather than short
#    aliases — the license-server portal frontend already accepts
#    either spelling (see portal/src/pages/admin/saas-tenants.astro),
#    so long names are the safer default.
#  * Usage counters (agents N/M, users N/M) are computed server-side
#    from the source of truth (assets table + users table) so the
#    admin panel always reflects current reality, not cached numbers.
# =============================================================================


def _fmt_usage(current, limit):
    """Render a usage counter as ``current/limit`` or ``current/unlimited``.

    The license server's tenants widget shows these as strings verbatim,
    so formatting on the server keeps the wire format stable.
    """
    if limit is None or limit < 0:
        return f"{current}/unlimited"
    return f"{current}/{limit}"


def _tenant_summary(org, sub, plan):
    """Build the tenant summary dict returned by GET /tenants.

    Computes live agent + user counts from the assets / users tables so
    the admin UI never renders stale metering data. Plan limits are
    resolved from the linked plan with ``-1`` treated as "unlimited".
    """
    from app.models import Asset

    # Primary admin email — the first org_admin in the org, falling back
    # to any active user if no admin exists (shouldn't happen but keeps
    # the response shape stable during EA edge cases).
    admin_user = (
        User.query.filter_by(organization_id=org.id, is_active=True)
        .filter(User.role.in_(('org_admin', 'super_admin')))
        .order_by(User.created_at.asc())
        .first()
    )
    if not admin_user:
        admin_user = (
            User.query.filter_by(organization_id=org.id, is_active=True)
            .order_by(User.created_at.asc())
            .first()
        )
    admin_email = admin_user.email if admin_user else None

    # Live counters — authoritative source-of-truth, not agent-reported.
    agent_count = Asset.query.filter_by(organization_id=org.id).count()
    user_count = User.query.filter_by(
        organization_id=org.id, is_active=True
    ).count()

    plan_name = plan.name if plan else (sub.plan.name if sub and sub.plan else None)
    plan_display = plan.display_name if plan else (
        sub.plan.display_name if sub and sub.plan else None
    )

    max_agents = plan.max_agents if plan else None
    max_users = plan.max_users if plan else None

    return {
        # Identity
        'organization_id': org.id,
        'organization_name': org.display_name or org.name,
        'organization_slug': org.name,
        'admin_email': admin_email,
        # Plan + status
        'plan_name': plan_name,
        'plan_display_name': plan_display,
        'status': (sub.status if sub else ('active' if org.active else 'suspended')),
        'billing_cycle': sub.billing_cycle if sub else None,
        'trial_end': (sub.trial_end.isoformat() if sub and sub.trial_end else None),
        'current_period_end': (
            sub.current_period_end.isoformat()
            if sub and sub.current_period_end else None
        ),
        # Usage (strings for the widget, plus raw numbers for sorting)
        'agents': _fmt_usage(agent_count, max_agents),
        'users': _fmt_usage(user_count, max_users),
        'agent_count': agent_count,
        'user_count': user_count,
        'agent_limit': max_agents,
        'user_limit': max_users,
        # Timestamps
        'created_at': org.created_at.isoformat() if org.created_at else None,
    }


@provision_bp.route('/tenants', methods=['GET'])
@limiter.limit("60/minute")
@_require_provision_key
def list_tenants():
    """List all SaaS tenants.

    Query params (all optional):
        plan    — filter by plan name (free, starter, pro, business, enterprise)
        status  — filter by subscription status (active, trialing, past_due,
                  canceled, paused, expired)
        search  — free-text search across organization name / display name
                  / admin email
        limit   — cap the number of results (default 500, max 5000)

    Response (200):
        {
            "tenants": [<_tenant_summary>, ...],
            "total": N,
            "filters_applied": {...}
        }
    """
    plan_filter = (request.args.get('plan') or '').strip().lower()
    status_filter = (request.args.get('status') or '').strip().lower()
    search = (request.args.get('search') or '').strip()
    try:
        limit = int(request.args.get('limit', 500))
    except (TypeError, ValueError):
        limit = 500
    limit = max(1, min(5000, limit))

    # Build base query. We LEFT JOIN the subscription because an
    # organization may exist without a subscription during EA edge cases
    # — we want those visible in the admin UI too, not hidden.
    from sqlalchemy.orm import joinedload

    query = Organization.query.options(
        joinedload(Organization.subscription).joinedload(Subscription.plan),
    )

    # Plan / status filters are applied via a join so we don't accidentally
    # drop orgs with no subscription unless the caller asks for a
    # specific plan (in which case "no plan" obviously doesn't match).
    if plan_filter:
        query = query.join(Organization.subscription).join(Subscription.plan).filter(
            db.func.lower(SubscriptionPlan.name) == plan_filter
        )

    if status_filter:
        query = query.join(Organization.subscription).filter(
            db.func.lower(Subscription.status) == status_filter
        )

    if search:
        like_pattern = f"%{search}%"
        # Search across org name, display_name, and admin user email.
        query = query.outerjoin(
            User,
            db.and_(
                User.organization_id == Organization.id,
                User.is_active.is_(True),
            ),
        ).filter(
            db.or_(
                Organization.name.ilike(like_pattern),
                Organization.display_name.ilike(like_pattern),
                User.email.ilike(like_pattern),
            )
        ).distinct()

    orgs = query.order_by(Organization.created_at.desc()).limit(limit).all()

    tenants = []
    for org in orgs:
        sub = org.subscription if hasattr(org, 'subscription') else None
        plan = sub.plan if sub else None
        try:
            tenants.append(_tenant_summary(org, sub, plan))
        except Exception:
            logger.exception(
                "Failed to build tenant summary for org_id=%s", org.id
            )
            # Fall back to a minimal shape so a single broken row
            # doesn't 500 the whole listing endpoint.
            tenants.append({
                'organization_id': org.id,
                'organization_name': org.display_name or org.name,
                'status': 'unknown',
                'error': 'summary_failed',
            })

    return jsonify({
        'tenants': tenants,
        'total': len(tenants),
        'filters_applied': {
            'plan': plan_filter or None,
            'status': status_filter or None,
            'search': search or None,
            'limit': limit,
        },
    })


@provision_bp.route('/plans', methods=['GET'])
@limiter.limit("60/minute")
@_require_provision_key
def list_plans():
    """List all subscription plans defined in the catalogue.

    Response (200):
        {
            "plans": [
                {
                    "id": "pro",
                    "name": "Professional",
                    "price_monthly_eur": 199,
                    "price_annual_eur": 1990,
                    "max_agents": 25,
                    "max_users": 5,
                    "max_organizations": 1,
                    "max_products": -1,
                    "max_api_keys": 5,
                    "max_storage_mb": 2000,
                    "features": [...enabled feature flag names...],
                    "currency": "EUR",
                    "is_active": true,
                    "is_default": false,
                    "stripe_price_id_monthly": "...",
                    "stripe_price_id_annual": "..."
                },
                ...
            ],
            "total": N
        }

    Only ``is_active=True`` plans are returned by default. Pass
    ``?include_inactive=true`` to include historical/archived plans
    (useful for reconciliation reports on the license server side).
    """
    include_inactive = (request.args.get('include_inactive', '').lower() == 'true')

    query = SubscriptionPlan.query
    if not include_inactive:
        query = query.filter_by(is_active=True)

    plans_out = []
    for plan in query.order_by(SubscriptionPlan.sort_order.asc()).all():
        features_dict = plan.get_features()
        enabled_features = sorted(
            k for k, v in features_dict.items() if v
        )
        plans_out.append({
            # Stable identifier used by the license server to cross-ref
            # with its local plan catalogue. The slug name is the key,
            # matching the existing provision/upgrade endpoint contract.
            'id': plan.name,
            'name': plan.display_name,
            'slug': plan.name,
            'description': plan.description,
            # Pricing — the license server renders in EUR so we surface
            # a pre-divided euro value AND the raw cents (for precision
            # when the portal computes pro-rations).
            'currency': plan.currency,
            'price_monthly_cents': plan.price_monthly_cents,
            'price_annual_cents': plan.price_annual_cents,
            'price_monthly_eur': (plan.price_monthly_cents or 0) / 100.0,
            'price_annual_eur': (plan.price_annual_cents or 0) / 100.0,
            # Limits (-1 means unlimited)
            'max_agents': plan.max_agents,
            'max_users': plan.max_users,
            'max_organizations': plan.max_organizations,
            'max_products': plan.max_products,
            'max_api_keys': plan.max_api_keys,
            'max_storage_mb': plan.max_storage_mb,
            # Features — enabled flag names as a list (widget renders
            # them as bullets) AND the raw dict for clients that need
            # the disabled ones too.
            'features': enabled_features,
            'features_map': features_dict,
            # Stripe
            'stripe_price_id_monthly': plan.stripe_price_id_monthly,
            'stripe_price_id_annual': plan.stripe_price_id_annual,
            'stripe_product_id': plan.stripe_product_id,
            # Metadata
            'is_active': plan.is_active,
            'is_default': plan.is_default,
            'sort_order': plan.sort_order,
        })

    return jsonify({
        'plans': plans_out,
        'total': len(plans_out),
    })


# =============================================================================
# Add-on management
#
# The license server calls this endpoint to enable or disable paid add-ons
# (e.g. the Compliance Pack) on a tenant's subscription. Add-ons are stored
# as a JSON dict on ``subscription.addons`` and layered on top of the base
# plan's feature flags by ``Subscription.has_feature()``.
# =============================================================================

#: Recognised add-on names. Any name not in this set is rejected with 400.
_KNOWN_ADDONS = frozenset({'compliance_pack'})


@provision_bp.route('/addons', methods=['POST'])
@limiter.limit("10/minute")
@_require_provision_key
def manage_addon():
    """
    Enable or disable an add-on on a tenant's subscription.

    Called by the License Server after a Stripe add-on purchase/cancellation.

    Request body:
    {
        "organization_id": 5,               // Required
        "addon_name": "compliance_pack",     // Required (must be in _KNOWN_ADDONS)
        "action": "enable"                   // Required: "enable" or "disable"
    }

    Returns:
    {
        "success": true,
        "addon_name": "compliance_pack",
        "action": "enable",
        "subscription": { ... }
    }
    """
    data = request.get_json()
    if not data:
        return jsonify({'error': 'No data provided'}), 400

    org_id = data.get('organization_id')
    addon_name = (data.get('addon_name') or '').strip()
    action = (data.get('action') or '').strip().lower()

    if not org_id or not addon_name or not action:
        return jsonify({'error': 'organization_id, addon_name, and action are required'}), 400

    if addon_name not in _KNOWN_ADDONS:
        return jsonify({
            'error': f'Unknown addon: {addon_name!r}',
            'known_addons': sorted(_KNOWN_ADDONS),
        }), 400

    if action not in ('enable', 'disable'):
        return jsonify({'error': 'action must be "enable" or "disable"'}), 400

    sub = Subscription.query.filter_by(organization_id=org_id).first()
    if not sub:
        return jsonify({'error': 'No subscription found for this organization'}), 404

    try:
        addons = sub.get_addons()
        if action == 'enable':
            addons[addon_name] = True
        else:
            addons[addon_name] = False
        sub.set_addons(addons)
        sub.updated_at = datetime.utcnow()
        db.session.commit()

        logger.info(
            "Addon %s %sd for org=%s",
            addon_name, action, org_id,
        )

        return jsonify({
            'success': True,
            'addon_name': addon_name,
            'action': action,
            'subscription': sub.to_dict(),
        })

    except Exception as e:
        db.session.rollback()
        logger.exception(f"Failed to {action} addon {addon_name} for org {org_id}: {e}")
        return jsonify({'error': f'Failed to {action} addon'}), 500
