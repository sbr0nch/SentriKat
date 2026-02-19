"""
Usage metering service for SentriKat.

Tracks per-organization resource usage for:
- On-premise: Usage dashboards and capacity planning
- SaaS: Quota enforcement, billing, and usage-based pricing

Metrics tracked:
- agents_active: Number of active agents (checked in within threshold)
- products_total: Total products being monitored
- users_active: Active users in the organization
- api_calls: API requests made (agent inventory submissions)
- alerts_sent: Email/webhook alerts dispatched
- reports_generated: PDF reports generated
- storage_bytes: File storage used (uploads, exports)

Usage:
    from app.metering import record_usage, get_current_usage, check_quota

    # Record a usage event
    record_usage(org_id=1, metric='api_calls', increment=1)

    # Get current usage snapshot
    usage = get_current_usage(org_id=1)
    # {'agents_active': 12, 'products_total': 340, ...}

    # Check if org is within quota
    allowed, message = check_quota(org_id=1, metric='agents_active')
"""

import logging
from datetime import datetime, timedelta

from app import db
from app.models import (
    Organization, Asset, Product, User, AgentApiKey,
    UsageRecord, Subscription, UserOrganization
)

logger = logging.getLogger(__name__)


def get_current_usage(org_id):
    """
    Get a real-time usage snapshot for an organization.

    Queries live data from the database rather than cached records.

    Args:
        org_id: Organization ID

    Returns:
        dict with current usage metrics
    """
    now = datetime.utcnow()
    online_threshold = now - timedelta(days=14)

    # Count active agents (checked in within last 14 days)
    agents_active = Asset.query.filter(
        Asset.organization_id == org_id,
        Asset.status.in_(['online', 'offline']),
        Asset.last_checkin >= online_threshold
    ).count()

    # Count total products being monitored
    products_total = Product.query.filter(
        Product.organization_id == org_id,
        Product.active == True
    ).count()

    # Count active users
    users_active = db.session.query(UserOrganization).filter(
        UserOrganization.organization_id == org_id
    ).count()
    # Also count legacy users directly assigned
    legacy_users = User.query.filter(
        User.organization_id == org_id,
        User.is_active == True
    ).count()
    users_active = max(users_active, legacy_users)

    # Count API keys
    api_keys = AgentApiKey.query.filter(
        AgentApiKey.organization_id == org_id,
        AgentApiKey.active == True
    ).count()

    # Count total assets (all statuses)
    assets_total = Asset.query.filter(
        Asset.organization_id == org_id
    ).count()

    return {
        'organization_id': org_id,
        'agents_active': agents_active,
        'assets_total': assets_total,
        'products_total': products_total,
        'users_active': users_active,
        'api_keys': api_keys,
        'measured_at': now.isoformat(),
    }


def record_usage_snapshot(org_id):
    """
    Record a point-in-time usage snapshot for an organization.

    Called periodically (e.g., daily) to build usage history for
    billing and capacity planning.

    Args:
        org_id: Organization ID

    Returns:
        List of UsageRecord objects created
    """
    usage = get_current_usage(org_id)
    now = datetime.utcnow()
    period_start = now.replace(hour=0, minute=0, second=0, microsecond=0)
    period_end = period_start + timedelta(days=1)

    records = []
    for metric in ['agents_active', 'assets_total', 'products_total', 'users_active', 'api_keys']:
        record = UsageRecord(
            organization_id=org_id,
            metric=metric,
            value=usage[metric],
            period_start=period_start,
            period_end=period_end,
        )
        db.session.add(record)
        records.append(record)

    db.session.commit()
    logger.debug(f"Recorded usage snapshot for org {org_id}: {usage}")
    return records


def record_usage_event(org_id, metric, increment=1):
    """
    Record an incremental usage event (e.g., API call, alert sent).

    For event-based metrics that accumulate over a billing period.

    Args:
        org_id: Organization ID
        metric: Metric name (e.g., 'api_calls', 'alerts_sent')
        increment: Amount to increment (default 1)
    """
    now = datetime.utcnow()
    period_start = now.replace(day=1, hour=0, minute=0, second=0, microsecond=0)
    # End of current month
    if now.month == 12:
        period_end = period_start.replace(year=now.year + 1, month=1)
    else:
        period_end = period_start.replace(month=now.month + 1)

    # Try to update existing record for this period
    existing = UsageRecord.query.filter(
        UsageRecord.organization_id == org_id,
        UsageRecord.metric == metric,
        UsageRecord.period_start == period_start,
    ).first()

    if existing:
        existing.value += increment
        existing.recorded_at = now
    else:
        record = UsageRecord(
            organization_id=org_id,
            metric=metric,
            value=increment,
            period_start=period_start,
            period_end=period_end,
        )
        db.session.add(record)

    db.session.commit()


def check_quota(org_id, resource):
    """
    Check if an organization is within its quota for a resource.

    In on-premise mode, this checks against the RSA-signed license.
    In SaaS mode, this checks against the subscription plan.

    Args:
        org_id: Organization ID
        resource: Resource name (e.g., 'agents', 'users', 'products')

    Returns:
        Tuple of (allowed: bool, message: str)
    """
    import os

    # Check if SaaS mode is enabled
    saas_mode = os.environ.get('SENTRIKAT_MODE', 'onpremise').lower() == 'saas'

    if saas_mode:
        return _check_saas_quota(org_id, resource)
    else:
        return _check_license_quota(org_id, resource)


def _check_saas_quota(org_id, resource):
    """Check quota against subscription plan (SaaS mode)."""
    subscription = Subscription.query.filter_by(
        organization_id=org_id
    ).first()

    if not subscription or not subscription.is_active():
        return False, "No active subscription"

    plan = subscription.plan
    if not plan:
        return False, "No plan associated with subscription"

    # Get limit from plan (-1 means unlimited)
    limit_attr = f'max_{resource}'
    limit = getattr(plan, limit_attr, None)

    if limit is None:
        return True, "No limit defined"

    if limit == -1:
        return True, "Unlimited"

    # Get current usage
    usage = get_current_usage(org_id)

    # Map resource to usage metric
    resource_to_metric = {
        'agents': 'agents_active',
        'users': 'users_active',
        'products': 'products_total',
        'api_keys': 'api_keys',
    }

    metric = resource_to_metric.get(resource, f'{resource}_total')
    current = usage.get(metric, 0)

    if current >= limit:
        return False, f"{resource.title()} limit reached ({current}/{limit}). Upgrade your plan."

    return True, f"{current}/{limit} {resource} used"


def _check_license_quota(org_id, resource):
    """Check quota against RSA-signed license (on-premise mode)."""
    try:
        from app.licensing import check_agent_limit, check_user_limit, check_org_limit

        if resource == 'agents':
            allowed, limit, msg = check_agent_limit(org_id)
            return allowed, msg
        elif resource == 'users':
            allowed, limit, msg = check_user_limit()
            return allowed, msg
        elif resource == 'organizations':
            allowed, limit, msg = check_org_limit()
            return allowed, msg
        else:
            return True, "No license limit for this resource"
    except ImportError:
        return True, "Licensing module not available"


def get_usage_history(org_id, metric, days=30):
    """
    Get usage history for a specific metric over a time period.

    Args:
        org_id: Organization ID
        metric: Metric name
        days: Number of days of history to retrieve

    Returns:
        List of {date, value} dicts
    """
    since = datetime.utcnow() - timedelta(days=days)

    records = UsageRecord.query.filter(
        UsageRecord.organization_id == org_id,
        UsageRecord.metric == metric,
        UsageRecord.period_start >= since,
    ).order_by(UsageRecord.period_start.asc()).all()

    return [r.to_dict() for r in records]


def get_all_orgs_usage_summary():
    """
    Get usage summary across all organizations.

    Useful for SaaS admin dashboard.

    Returns:
        List of dicts with per-org usage summaries
    """
    orgs = Organization.query.filter_by(active=True).all()
    summaries = []

    for org in orgs:
        usage = get_current_usage(org.id)
        usage['organization_name'] = org.display_name
        usage['organization_slug'] = org.name
        summaries.append(usage)

    return summaries
