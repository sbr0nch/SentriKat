"""
SaaS Tenant Provisioning API

Called by the License Server after a successful Stripe payment/signup.
Creates Organization + User (org_admin) + Subscription automatically.

Security:
- Only available in SaaS mode
- Protected by SENTRIKAT_PROVISION_KEY (shared secret between License Server and SaaS app)
- Never exposed to end users

Endpoints:
- POST /api/provision          — Create new tenant (org + user + subscription)
- POST /api/provision/upgrade  — Change subscription plan
- POST /api/provision/cancel   — Cancel subscription
- GET  /api/provision/status   — Check tenant status
"""

import os
import re
import secrets
import logging
from datetime import datetime, timedelta
from functools import wraps

from flask import Blueprint, request, jsonify
from app import db, csrf, limiter
from app.models import Organization, User, Subscription, SubscriptionPlan, UserOrganization
from app.saas import is_saas_mode

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
        if not provided_key or provided_key != _PROVISION_KEY:
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

    # Check if user already exists
    existing_user = User.query.filter_by(email=email).first()
    if existing_user:
        return jsonify({
            'error': 'User with this email already exists',
            'code': 'USER_EXISTS',
            'existing_org_id': existing_user.organization_id
        }), 409

    # Get subscription plan
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

        db.session.commit()

        logger.info(
            f"Provisioned new tenant: org={org_slug} (id={org.id}), "
            f"user={email} (id={user.id}), plan={plan.name}"
        )

        # Build login URL
        base_url = os.environ.get('SENTRIKAT_BASE_URL', 'https://app.sentrikat.com')

        return jsonify({
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
        }), 201

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
