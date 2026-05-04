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

import json
import logging
import os
import time
from datetime import datetime, timedelta

from app import db
from app.models import (
    Organization, Asset, Product, User, AgentApiKey,
    UsageRecord, Subscription, UserOrganization
)

logger = logging.getLogger(__name__)


#: Backoff delays (seconds) between retries when posting usage to the
#: license server. Mirrors :data:`app.licensing.HEARTBEAT_RETRY_DELAYS`
#: but with one fewer step (three retries: 1, 2, 4s).
USAGE_UPLOAD_RETRY_DELAYS = (1, 2, 4)


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
            allowed, limit, msg = check_agent_limit()
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


def _resolve_tenant_email(org_id):
    """Return the tenant email upstream uses as its primary key.

    The license server identifies tenants by customer email (Sprint 6
    contract). We prefer ``Organization.billing_email`` when present, and
    otherwise fall back to the first admin-role user attached to the org.
    Returns ``None`` only if nothing usable is found — in that case the
    caller should skip the upload and log a warning.
    """
    try:
        from app.models import Organization, User
    except Exception:
        return None

    org = Organization.query.get(org_id)
    if org is None:
        return None

    if hasattr(org, 'billing_email'):
        email = getattr(org, 'billing_email', None)
        if email:
            return email.strip().lower()

    try:
        admin = User.query.filter_by(
            organization_id=org_id, role='admin'
        ).order_by(User.id.asc()).first()
        if admin and admin.email:
            return admin.email.strip().lower()
    except Exception:
        pass

    try:
        any_user = User.query.filter_by(
            organization_id=org_id
        ).order_by(User.id.asc()).first()
        if any_user and any_user.email:
            return any_user.email.strip().lower()
    except Exception:
        pass

    return None


def _iso_hour_floor_utc(dt=None):
    """ISO-8601 UTC string floored to the hour (Sprint 6 contract).

    The license server normalizes on ``(tenant_id, ts_hour)`` for dedup,
    so sending anything within the same hour collapses to one row. We
    floor the minute/second fields to make the idempotency explicit from
    the client side too.
    """
    if dt is None:
        dt = datetime.utcnow()
    floored = dt.replace(minute=0, second=0, microsecond=0)
    return floored.strftime('%Y-%m-%dT%H:%M:%SZ')


def _build_usage_payload(org_id):
    """Assemble the usage payload the license server expects (H7).

    Schema (Sprint 6 — ``POST {LICENSE_SERVER_URL}/v1/metrics/usage``)::

        {
          "tenant_id":      "<customer-email>",
          "ts":             "<ISO-8601 UTC, floored to hour>",
          "agents_active":  int,
          "products_total": int,
          "users_active":   int,
          "api_calls_1h":   int,
          "scan_count_1h":  int,
          "storage_bytes":  int
        }
    """
    usage = get_current_usage(org_id)
    now = datetime.utcnow()
    one_hour_ago = now - timedelta(hours=1)

    # api_calls in the last hour, if the metric is tracked
    api_calls_1h = 0
    try:
        rec = UsageRecord.query.filter(
            UsageRecord.organization_id == org_id,
            UsageRecord.metric == 'api_calls',
            UsageRecord.recorded_at >= one_hour_ago,
        ).order_by(UsageRecord.recorded_at.desc()).first()
        if rec:
            api_calls_1h = int(rec.value or 0)
    except Exception:
        api_calls_1h = 0

    scan_count_1h = 0
    try:
        rec = UsageRecord.query.filter(
            UsageRecord.organization_id == org_id,
            UsageRecord.metric == 'scans',
            UsageRecord.recorded_at >= one_hour_ago,
        ).order_by(UsageRecord.recorded_at.desc()).first()
        if rec:
            scan_count_1h = int(rec.value or 0)
    except Exception:
        scan_count_1h = 0

    storage_bytes = 0
    try:
        rec = UsageRecord.query.filter(
            UsageRecord.organization_id == org_id,
            UsageRecord.metric == 'storage_bytes',
        ).order_by(UsageRecord.recorded_at.desc()).first()
        if rec:
            storage_bytes = int(rec.value or 0)
    except Exception:
        storage_bytes = 0

    tenant_email = _resolve_tenant_email(org_id)
    if not tenant_email:
        # Signal to the caller that this org has no usable tenant email.
        raise ValueError(f"no tenant email resolvable for org_id={org_id}")

    return {
        'tenant_id': tenant_email,
        'ts': _iso_hour_floor_utc(now),
        'agents_active': int(usage.get('agents_active', 0)),
        'products_total': int(usage.get('products_total', 0)),
        'users_active': int(usage.get('users_active', 0)),
        'api_calls_1h': api_calls_1h,
        'scan_count_1h': scan_count_1h,
        'storage_bytes': storage_bytes,
    }


def _post_with_retry(url, payload, headers, proxies=None, verify_ssl=True):
    """POST with exponential backoff (1/2/4s). Returns (response, exc)."""
    import requests as _requests
    last_exc = None
    for attempt, delay in enumerate([0] + list(USAGE_UPLOAD_RETRY_DELAYS[:-1]), start=1):
        if delay:
            time.sleep(delay)
        try:
            resp = _requests.post(
                url,
                json=payload,
                timeout=15,
                headers=headers,
                proxies=proxies,
                verify=verify_ssl,
            )
            return resp, None
        except (_requests.ConnectionError, _requests.Timeout) as e:
            last_exc = e
            logger.info(
                f"Usage upload attempt {attempt}/{len(USAGE_UPLOAD_RETRY_DELAYS)} "
                f"failed: {type(e).__name__}: {e}"
            )
            continue
        except Exception as e:
            last_exc = e
            logger.warning(f"Usage upload attempt {attempt}: unexpected error: {e}")
            continue
    return None, last_exc


def send_usage_to_license_server():
    """Push per-tenant usage snapshots to the upstream license server (H7).

    For each active organization we build a payload via
    :func:`_build_usage_payload` and ``POST`` it to
    ``{LICENSE_SERVER_URL}/v1/metrics/usage`` with
    ``Authorization: Bearer {SENTRIKAT_METRICS_KEY}``. Network errors
    retry with 1/2/4s backoff.

    Note: ``LICENSE_SERVER_URL`` already includes the ``/api`` prefix
    (default ``https://license.sentrikat.com/api``), matching the
    existing heartbeat/activate endpoints which use ``/v1/...`` suffixes.
    Do NOT add ``/api/`` here — that produces a double prefix and a 404.

    The license server expects ``202 Accepted`` from its receiver and
    normalizes the ``ts`` field to the hour, so sending multiple times
    per hour is safe (idempotent upstream).

    Called from a scheduler job registered in ``app.scheduler`` — runs
    at the top of every hour under the scheduler leader lock.

    Returns:
        A list of per-tenant result dicts::

            [{'tenant_id': 'alice@example.com', 'success': True, 'status_code': 202}, ...]
    """
    from app.licensing import LICENSE_SERVER_URL  # lazy import to avoid cycles

    # Prefer the dedicated metrics key; fall back to the provision key with
    # a deprecation warning (matches /metrics — see app/metrics_api.py).
    metrics_key = (os.environ.get('SENTRIKAT_METRICS_KEY') or '').strip()
    if not metrics_key:
        fallback = (os.environ.get('SENTRIKAT_PROVISION_KEY') or '').strip()
        if fallback:
            logger.warning(
                "DEPRECATION: usage upload using SENTRIKAT_PROVISION_KEY — "
                "set SENTRIKAT_METRICS_KEY (fallback removed in Sprint 6)"
            )
            metrics_key = fallback

    if not metrics_key:
        # On-prem Community installs intentionally don't ship telemetry to
        # the license server — missing SENTRIKAT_METRICS_KEY is the expected
        # operating state, not an error condition. Downgrade ERROR → WARNING
        # so it doesn't trigger spurious 'errors detected' alerts in
        # operator dashboards/SIEM ([03.5.5]).
        logger.warning(
            "send_usage_to_license_server: no SENTRIKAT_METRICS_KEY configured, "
            "skipping usage upload (expected for on-prem Community installs)"
        )
        return []

    try:
        from config import Config
        proxies = Config.get_proxies()
        verify_ssl = Config.get_verify_ssl()
    except Exception:
        proxies = None
        verify_ssl = True

    url = f"{LICENSE_SERVER_URL}/v1/metrics/usage"
    headers = {
        'Content-Type': 'application/json',
        'Authorization': f'Bearer {metrics_key}',
        'User-Agent': 'SentriKat-Usage/1.0',
    }

    results = []
    orgs = Organization.query.filter_by(active=True).all()
    for org in orgs:
        try:
            payload = _build_usage_payload(org.id)
        except ValueError as e:
            # No tenant email resolvable — skip quietly (org still seeding).
            logger.info(f"Skipping usage upload for org {org.id}: {e}")
            results.append({'org_id': org.id, 'success': False, 'skipped': True, 'error': str(e)})
            continue
        except Exception as e:
            logger.warning(f"Could not build usage payload for org {org.id}: {e}")
            results.append({'org_id': org.id, 'success': False, 'error': str(e)})
            continue

        tenant_email = payload['tenant_id']

        resp, exc = _post_with_retry(
            url, payload, headers, proxies=proxies, verify_ssl=verify_ssl
        )
        if resp is None:
            logger.error(
                f"Usage upload failed for tenant {tenant_email} after retries: {exc}"
            )
            results.append({
                'tenant_id': tenant_email,
                'org_id': org.id,
                'success': False,
                'error': str(exc) if exc else 'unknown',
            })
            continue

        if 200 <= resp.status_code < 300:
            logger.info(
                f"Usage upload OK for tenant {tenant_email}: "
                f"{payload['agents_active']} agents, "
                f"{payload['products_total']} products, "
                f"ts={payload['ts']}"
            )
            results.append({
                'tenant_id': tenant_email,
                'org_id': org.id,
                'success': True,
                'status_code': resp.status_code,
            })
        else:
            logger.warning(
                f"Usage upload rejected for tenant {tenant_email}: "
                f"status={resp.status_code} body={resp.text[:200] if resp.text else ''}"
            )
            results.append({
                'tenant_id': tenant_email,
                'org_id': org.id,
                'success': False,
                'status_code': resp.status_code,
            })

    # Sprint 6 observability: persist the last-run summary and per-tenant
    # state so the /super-admin/usage-uploads page can render without
    # shelling into the container for docker logs.
    try:
        from app.models import SystemSettings
        from app import db as app_db
        from datetime import datetime as _dt

        ok_count = sum(1 for r in results if r.get('success'))
        fail_count = len(results) - ok_count

        summary = {
            'ran_at': _dt.utcnow().strftime('%Y-%m-%d %H:%M:%S UTC'),
            'total': len(results),
            'ok': ok_count,
            'failed': fail_count,
            'endpoint': url,
        }

        def _upsert(key, value):
            row = SystemSettings.query.filter_by(
                key=key, organization_id=None
            ).first()
            serialized = json.dumps(value, default=str)
            if row:
                row.value = serialized
                row.updated_at = _dt.utcnow()
            else:
                row = SystemSettings(
                    key=key,
                    value=serialized,
                    category='observability',
                    description='Sprint 6 usage upload state',
                )
                app_db.session.add(row)

        _upsert('usage_upload:last_run', summary)

        for r in results:
            tenant = r.get('tenant_id') or f"org-{r.get('org_id', 'unknown')}"
            _upsert(f'usage_upload:tenant:{tenant}', r)

        app_db.session.commit()
    except Exception as e:
        logger.warning(f"Failed to persist usage upload observability: {e}")
        try:
            from app import db as app_db
            app_db.session.rollback()
        except Exception:
            pass

    return results


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
