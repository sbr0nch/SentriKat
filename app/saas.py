"""
SentriKat Dual-Mode System (On-Premise / SaaS)

This module is the central control point for all mode-dependent behavior.
It ensures on-premise installations continue to work exactly as before,
while SaaS deployments get tenant isolation and self-service capabilities.

Mode is controlled by the SENTRIKAT_MODE environment variable:
- 'onpremise' (default): Everything works as today. No changes.
- 'saas': Tenant isolation, org_admin self-service, per-subscription features.

Usage:
    from app.saas import is_saas_mode, requires_org_scope, saas_admin_or_org_admin

    # Check mode
    if is_saas_mode():
        # SaaS-specific logic
        pass

    # Decorator: In SaaS mode, forces org_id scope on queries
    @app.route('/api/data')
    @login_required
    @requires_org_scope
    def get_data():
        org_id = get_scoped_org_id()  # Always returns an org_id in SaaS mode
        ...

    # Decorator: admin_required in on-premise, org_admin_required in SaaS
    @app.route('/api/settings/ldap')
    @login_required
    @saas_admin_or_org_admin
    def get_ldap_settings():
        ...
"""

import os
import logging
from functools import wraps
from flask import jsonify, request, session

logger = logging.getLogger(__name__)

# Cache the mode at module load time (doesn't change at runtime)
_SENTRIKAT_MODE = os.environ.get('SENTRIKAT_MODE', 'onpremise').lower()


def is_saas_mode():
    """Check if running in SaaS mode.

    Returns True only when SENTRIKAT_MODE=saas.
    Default is on-premise (returns False).
    """
    return _SENTRIKAT_MODE == 'saas'


def is_onpremise_mode():
    """Check if running in on-premise mode (default)."""
    return not is_saas_mode()


def get_scoped_org_id(user=None):
    """Get the organization ID for the current request context.

    On-premise:
        - super_admin: returns org_id from request args, or session, or None (all orgs)
        - others: returns user's organization_id

    SaaS:
        - ALL users (including super_admin): returns org_id from session
        - Never returns None (always scoped to an org)

    Args:
        user: Optional User object. If not provided, fetched from session.

    Returns:
        int or None: Organization ID. In SaaS mode, always returns an int.
    """
    if user is None:
        from app.auth import _safe_get_user
        user = _safe_get_user(session.get('user_id'))

    if user is None:
        return None

    if is_saas_mode():
        # SaaS: Always return the user's current org from session
        org_id = session.get('organization_id')
        if not org_id:
            # Fall back to user's primary org
            org_id = user.organization_id
        return org_id
    else:
        # On-premise: super_admin can access any org or all orgs
        if user.role == 'super_admin' or user.is_admin:
            # Allow explicit org_id from request, fall back to session
            req_org_id = request.args.get('organization_id', type=int)
            return req_org_id or session.get('organization_id')
        else:
            return session.get('organization_id') or user.organization_id


def requires_org_scope(f):
    """Decorator that ensures queries are scoped to an organization in SaaS mode.

    On-premise: No effect (passes through).
    SaaS: Ensures an org_id is always available. Returns 403 if not.
    """
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if is_saas_mode():
            org_id = get_scoped_org_id()
            if org_id is None:
                return jsonify({
                    'error': 'Organization context required',
                    'code': 'ORG_SCOPE_REQUIRED'
                }), 403
        return f(*args, **kwargs)
    return decorated_function


def saas_admin_or_org_admin(f):
    """Decorator for routes that need different access levels per mode.

    On-premise: Requires super_admin (same as @admin_required).
    SaaS: Allows org_admin for their own org's settings.

    This is the key decorator for making org_admin self-sufficient in SaaS.
    """
    @wraps(f)
    def decorated_function(*args, **kwargs):
        from app.auth import AUTH_ENABLED, _safe_get_user

        if not AUTH_ENABLED:
            return f(*args, **kwargs)

        if 'user_id' not in session:
            if request.is_json or request.path.startswith('/api/'):
                return jsonify({'error': 'Authentication required'}), 401
            from flask import redirect, url_for
            return redirect(url_for('auth.login', next=request.url))

        user = _safe_get_user(session['user_id'])
        if not user:
            if request.is_json or request.path.startswith('/api/'):
                return jsonify({'error': 'User not found'}), 401
            from flask import redirect, url_for
            return redirect(url_for('auth.login'))

        if is_saas_mode():
            # SaaS: org_admin and super_admin both allowed
            has_permission = (
                user.role in ['org_admin', 'super_admin'] or
                user.is_admin is True
            )
        else:
            # On-premise: only super_admin (same as @admin_required)
            has_permission = (
                user.role == 'super_admin' or
                user.is_admin is True
            )

        if not has_permission:
            if request.is_json or request.path.startswith('/api/'):
                return jsonify({'error': 'Insufficient privileges'}), 403
            from flask import redirect, url_for
            return redirect(url_for('main.index'))

        return f(*args, **kwargs)
    return decorated_function


def restrict_cross_org_access(f):
    """Decorator that prevents cross-organization data access in SaaS mode.

    On-premise: No effect (super_admin can see all orgs).
    SaaS: Forces super_admin to be scoped to one org at a time.
          Prevents bulk data access across all tenants.
    """
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if is_saas_mode():
            from app.auth import _safe_get_user
            user = _safe_get_user(session.get('user_id'))
            if user and (user.role == 'super_admin' or user.is_admin):
                # In SaaS, even super_admin must specify an org
                org_id = get_scoped_org_id(user)
                if org_id is None:
                    return jsonify({
                        'error': 'Organization scope required in SaaS mode',
                        'code': 'SAAS_ORG_REQUIRED'
                    }), 403
        return f(*args, **kwargs)
    return decorated_function


def get_effective_features(org_id):
    """Get the effective feature set for an organization.

    On-premise: Returns features from RSA-signed license (global).
    SaaS: Returns features from the org's SubscriptionPlan.

    Returns:
        dict: Feature flags like {'ldap': True, 'sso': False, ...}
    """
    if is_saas_mode():
        return _get_saas_features(org_id)
    else:
        return _get_license_features()


def _get_saas_features(org_id):
    """Get features from the org's active subscription plan."""
    try:
        from app.models import Subscription, SubscriptionPlan
        sub = Subscription.query.filter_by(
            organization_id=org_id,
            status='active'
        ).first()

        if not sub:
            # Check for trialing
            sub = Subscription.query.filter_by(
                organization_id=org_id,
                status='trialing'
            ).first()

        if sub and sub.plan:
            return sub.plan.get_features()

        # No subscription = free plan features
        free_plan = SubscriptionPlan.query.filter_by(slug='free').first()
        if free_plan:
            return free_plan.get_features()

        # Absolute fallback: no features
        return {
            'email_alerts': False, 'ldap': False, 'sso': False,
            'webhooks': False, 'white_label': False, 'api_access': False,
            'compliance_reports': False, 'jira_integration': False,
            'push_agents': False, 'backup_restore': False,
            'audit_export': False, 'multi_org': False
        }
    except Exception as e:
        logger.error(f"Error getting SaaS features for org {org_id}: {e}")
        return {}


def _get_license_features():
    """Get features from the on-premise license."""
    try:
        from app.licensing import get_license
        license_info = get_license()
        if license_info.is_professional():
            return {
                'email_alerts': True, 'ldap': True, 'sso': True,
                'webhooks': True, 'white_label': True, 'api_access': True,
                'compliance_reports': True, 'jira_integration': True,
                'push_agents': True, 'backup_restore': True,
                'audit_export': True, 'multi_org': True
            }
        else:
            # Demo/Community edition
            return {
                'email_alerts': False, 'ldap': False, 'sso': False,
                'webhooks': False, 'white_label': False, 'api_access': False,
                'compliance_reports': False, 'jira_integration': False,
                'push_agents': False, 'backup_restore': False,
                'audit_export': False, 'multi_org': False
            }
    except Exception as e:
        logger.error(f"Error getting license features: {e}")
        return {}


def requires_feature(feature_name):
    """Decorator to require a specific feature for a route.

    On-premise: Checks RSA-signed license (global).
    SaaS: Checks the org's SubscriptionPlan features.

    This replaces @requires_professional for dual-mode support.

    Usage:
        @requires_feature('ldap')
        def configure_ldap():
            ...
    """
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            if is_saas_mode():
                # SaaS: Check per-org subscription features
                org_id = get_scoped_org_id()
                features = get_effective_features(org_id)
                if not features.get(feature_name, False):
                    return jsonify({
                        'error': f'{feature_name} is not available on your current plan',
                        'feature_required': feature_name,
                        'upgrade_required': True
                    }), 403
            else:
                # On-premise: Use existing license check
                from app.licensing import get_license
                license_info = get_license()
                if not license_info.is_professional():
                    return jsonify({
                        'error': f'{feature_name} requires a Professional license',
                        'license_required': True,
                        'current_edition': license_info.get_effective_edition()
                    }), 403
            return f(*args, **kwargs)
        return decorated_function
    return decorator


def check_quota_dual(org_id, resource):
    """Check resource quota in dual mode.

    On-premise: Checks RSA license limits (global).
    SaaS: Checks subscription plan limits (per-org).

    Returns:
        tuple: (allowed: bool, message: str)
    """
    from app.metering import check_quota
    return check_quota(org_id, resource)


def get_mode_info():
    """Get current mode information for API responses and UI.

    Returns:
        dict: Mode details for frontend rendering.
    """
    return {
        'mode': _SENTRIKAT_MODE,
        'is_saas': is_saas_mode(),
        'is_onpremise': is_onpremise_mode()
    }
