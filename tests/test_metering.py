"""
Tests for app/metering.py - Usage metering service.

Covers:
- get_current_usage() live metric counting
- record_usage_snapshot() periodic snapshots
- record_usage_event() incremental event recording
- check_quota() SaaS vs on-premise quota enforcement
- get_usage_history() time-filtered queries
- get_all_orgs_usage_summary() multi-org summary
"""
import pytest
from datetime import datetime, timedelta
from unittest.mock import patch

from app.metering import (
    get_current_usage,
    record_usage_snapshot,
    record_usage_event,
    check_quota,
    get_usage_history,
    get_all_orgs_usage_summary,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _create_org(db_session, name='metering-org', display_name='Metering Org'):
    """Create and return an Organization."""
    from app.models import Organization
    org = Organization(name=name, display_name=display_name, active=True)
    db_session.add(org)
    db_session.flush()
    return org


def _create_user(db_session, org, username='meteruser', email='meter@test.local'):
    """Create and return an active User attached to org."""
    from app.models import User
    user = User(
        username=username,
        email=email,
        role='user',
        is_active=True,
        auth_type='local',
        organization_id=org.id,
    )
    user.set_password('password123')
    db_session.add(user)
    db_session.flush()
    return user


def _create_user_org(db_session, user, org, role='user'):
    """Create a UserOrganization membership record."""
    from app.models import UserOrganization
    membership = UserOrganization(
        user_id=user.id,
        organization_id=org.id,
        role=role,
    )
    db_session.add(membership)
    db_session.flush()
    return membership


def _create_asset(db_session, org, hostname='server-01', status='online', last_checkin=None):
    """Create and return an Asset with a recent checkin."""
    from app.models import Asset
    if last_checkin is None:
        last_checkin = datetime.utcnow()
    asset = Asset(
        organization_id=org.id,
        hostname=hostname,
        status=status,
        last_checkin=last_checkin,
        active=True,
    )
    db_session.add(asset)
    db_session.flush()
    return asset


def _create_product(db_session, org, product_name='Tomcat', active=True):
    """Create and return a Product."""
    from app.models import Product
    product = Product(
        vendor='Apache',
        product_name=product_name,
        version='10.0',
        criticality='medium',
        active=active,
        organization_id=org.id,
    )
    db_session.add(product)
    db_session.flush()
    return product


def _create_api_key(db_session, org, name='key-1', active=True):
    """Create and return an AgentApiKey."""
    from app.models import AgentApiKey
    import hashlib
    import secrets

    raw = secrets.token_hex(16)
    key = AgentApiKey(
        organization_id=org.id,
        name=name,
        key_hash=hashlib.sha256(raw.encode()).hexdigest(),
        key_prefix=raw[:8],
        active=active,
    )
    db_session.add(key)
    db_session.flush()
    return key


# ---------------------------------------------------------------------------
# get_current_usage() tests
# ---------------------------------------------------------------------------

class TestGetCurrentUsage:
    """Tests for live usage snapshot."""

    def test_empty_org_has_zero_counts(self, app, db_session):
        """An org with no data returns zeros for all metrics."""
        org = _create_org(db_session)
        db_session.commit()

        usage = get_current_usage(org.id)
        assert usage['organization_id'] == org.id
        assert usage['agents_active'] == 0
        assert usage['assets_total'] == 0
        assert usage['products_total'] == 0
        assert usage['users_active'] == 0
        assert usage['api_keys'] == 0
        assert 'measured_at' in usage

    def test_counts_active_agents(self, app, db_session):
        """Only agents with recent checkin and online/offline status are counted."""
        org = _create_org(db_session)
        # Active agent (recent checkin, online)
        _create_asset(db_session, org, hostname='active-01', status='online')
        # Active agent (recent checkin, offline)
        _create_asset(db_session, org, hostname='active-02', status='offline')
        # Stale agent (old checkin - outside 14-day threshold)
        _create_asset(db_session, org, hostname='stale-01', status='online',
                       last_checkin=datetime.utcnow() - timedelta(days=30))
        # Decommissioned agent (recent checkin but wrong status)
        _create_asset(db_session, org, hostname='decom-01', status='decommissioned')
        db_session.commit()

        usage = get_current_usage(org.id)
        assert usage['agents_active'] == 2  # only the two recent online/offline ones
        assert usage['assets_total'] == 4   # all assets regardless of status

    def test_counts_active_products(self, app, db_session):
        """Only active products are counted."""
        org = _create_org(db_session)
        _create_product(db_session, org, product_name='ActiveProduct', active=True)
        _create_product(db_session, org, product_name='InactiveProduct', active=False)
        db_session.commit()

        usage = get_current_usage(org.id)
        assert usage['products_total'] == 1

    def test_counts_users_via_user_org(self, app, db_session):
        """Users are counted through UserOrganization memberships."""
        org = _create_org(db_session)
        user1 = _create_user(db_session, org, username='u1', email='u1@test.local')
        user2 = _create_user(db_session, org, username='u2', email='u2@test.local')
        _create_user_org(db_session, user1, org)
        _create_user_org(db_session, user2, org)
        db_session.commit()

        usage = get_current_usage(org.id)
        assert usage['users_active'] >= 2

    def test_counts_active_api_keys(self, app, db_session):
        """Only active API keys are counted."""
        org = _create_org(db_session)
        _create_api_key(db_session, org, name='active-key', active=True)
        _create_api_key(db_session, org, name='revoked-key', active=False)
        db_session.commit()

        usage = get_current_usage(org.id)
        assert usage['api_keys'] == 1

    def test_usage_isolated_between_orgs(self, app, db_session):
        """Metrics only count resources belonging to the queried org."""
        org_a = _create_org(db_session, name='org-a', display_name='Org A')
        org_b = _create_org(db_session, name='org-b', display_name='Org B')

        _create_product(db_session, org_a, product_name='ProdA')
        _create_product(db_session, org_a, product_name='ProdA2')
        _create_product(db_session, org_b, product_name='ProdB')
        db_session.commit()

        usage_a = get_current_usage(org_a.id)
        usage_b = get_current_usage(org_b.id)
        assert usage_a['products_total'] == 2
        assert usage_b['products_total'] == 1


# ---------------------------------------------------------------------------
# record_usage_snapshot() tests
# ---------------------------------------------------------------------------

class TestRecordUsageSnapshot:
    """Tests for periodic usage snapshot recording."""

    def test_creates_usage_records(self, app, db_session):
        """Snapshot creates one UsageRecord per metric."""
        from app.models import UsageRecord

        org = _create_org(db_session)
        _create_product(db_session, org, product_name='SnapProd')
        db_session.commit()

        records = record_usage_snapshot(org.id)
        assert len(records) == 5  # agents_active, assets_total, products_total, users_active, api_keys

        # Verify records are persisted
        stored = UsageRecord.query.filter_by(organization_id=org.id).all()
        assert len(stored) == 5

    def test_snapshot_captures_correct_values(self, app, db_session):
        """Snapshot values match the live usage counts."""
        org = _create_org(db_session)
        _create_product(db_session, org, product_name='P1')
        _create_product(db_session, org, product_name='P2')
        _create_api_key(db_session, org, name='K1')
        db_session.commit()

        records = record_usage_snapshot(org.id)
        by_metric = {r.metric: r.value for r in records}

        assert by_metric['products_total'] == 2
        assert by_metric['api_keys'] == 1
        assert by_metric['agents_active'] == 0
        assert by_metric['assets_total'] == 0

    def test_snapshot_has_period_boundaries(self, app, db_session):
        """Each record has a period_start at midnight and period_end the next day."""
        org = _create_org(db_session)
        db_session.commit()

        records = record_usage_snapshot(org.id)
        for record in records:
            assert record.period_start.hour == 0
            assert record.period_start.minute == 0
            assert record.period_end == record.period_start + timedelta(days=1)


# ---------------------------------------------------------------------------
# record_usage_event() tests
# ---------------------------------------------------------------------------

class TestRecordUsageEvent:
    """Tests for incremental event-based usage recording."""

    def test_creates_new_record(self, app, db_session):
        """First event for a metric creates a new UsageRecord."""
        from app.models import UsageRecord

        org = _create_org(db_session)
        db_session.commit()

        record_usage_event(org.id, 'api_calls', increment=1)

        records = UsageRecord.query.filter_by(
            organization_id=org.id, metric='api_calls'
        ).all()
        assert len(records) == 1
        assert records[0].value == 1

    def test_increments_existing_record(self, app, db_session):
        """Subsequent events in the same period increment the existing record."""
        from app.models import UsageRecord

        org = _create_org(db_session)
        db_session.commit()

        record_usage_event(org.id, 'api_calls', increment=5)
        record_usage_event(org.id, 'api_calls', increment=3)

        records = UsageRecord.query.filter_by(
            organization_id=org.id, metric='api_calls'
        ).all()
        assert len(records) == 1
        assert records[0].value == 8

    def test_different_metrics_separate_records(self, app, db_session):
        """Different metric names produce separate records."""
        from app.models import UsageRecord

        org = _create_org(db_session)
        db_session.commit()

        record_usage_event(org.id, 'api_calls', increment=1)
        record_usage_event(org.id, 'alerts_sent', increment=2)

        api_records = UsageRecord.query.filter_by(
            organization_id=org.id, metric='api_calls'
        ).all()
        alert_records = UsageRecord.query.filter_by(
            organization_id=org.id, metric='alerts_sent'
        ).all()
        assert len(api_records) == 1
        assert len(alert_records) == 1
        assert api_records[0].value == 1
        assert alert_records[0].value == 2

    def test_event_period_is_monthly(self, app, db_session):
        """Event records use the first of the current month as period_start."""
        from app.models import UsageRecord

        org = _create_org(db_session)
        db_session.commit()

        record_usage_event(org.id, 'reports_generated', increment=1)

        record = UsageRecord.query.filter_by(
            organization_id=org.id, metric='reports_generated'
        ).first()
        assert record.period_start.day == 1
        assert record.period_start.hour == 0

        # period_end should be the first of the next month
        if record.period_start.month == 12:
            expected_end_month = 1
        else:
            expected_end_month = record.period_start.month + 1
        assert record.period_end.month == expected_end_month
        assert record.period_end.day == 1


# ---------------------------------------------------------------------------
# check_quota() tests
# ---------------------------------------------------------------------------

class TestCheckQuota:
    """Tests for quota enforcement in SaaS and on-premise modes."""

    def test_onpremise_mode_no_licensing_module(self, app, db_session):
        """In on-premise mode without the licensing module, quota returns allowed."""
        org = _create_org(db_session)
        db_session.commit()

        with patch.dict('os.environ', {'SENTRIKAT_MODE': 'onpremise'}):
            # The licensing module may or may not be importable; either way
            # if ImportError is raised, the function returns True.
            with patch('app.metering._check_license_quota', return_value=(True, 'Licensing module not available')):
                allowed, msg = check_quota(org.id, 'agents')
        assert allowed is True

    def test_onpremise_mode_delegates_to_license(self, app, db_session):
        """In on-premise mode, check_quota delegates to _check_license_quota."""
        org = _create_org(db_session)
        db_session.commit()

        with patch.dict('os.environ', {'SENTRIKAT_MODE': 'onpremise'}):
            with patch('app.metering._check_license_quota', return_value=(False, 'Agent limit reached')) as mock_lic:
                allowed, msg = check_quota(org.id, 'agents')
                mock_lic.assert_called_once_with(org.id, 'agents')
        assert allowed is False
        assert 'limit reached' in msg

    def test_saas_mode_no_subscription_returns_false(self, app, db_session):
        """In SaaS mode, an org without a subscription is denied."""
        org = _create_org(db_session)
        db_session.commit()

        with patch.dict('os.environ', {'SENTRIKAT_MODE': 'saas'}):
            allowed, msg = check_quota(org.id, 'agents')
        assert allowed is False
        assert 'No active subscription' in msg

    def test_saas_mode_with_active_subscription(self, app, db_session):
        """In SaaS mode, an org within its plan limits is allowed."""
        from app.models import SubscriptionPlan, Subscription

        org = _create_org(db_session)

        plan = SubscriptionPlan(
            name='pro',
            display_name='Pro Plan',
            max_agents=10,
            max_users=5,
            max_products=100,
            max_api_keys=3,
        )
        db_session.add(plan)
        db_session.flush()

        subscription = Subscription(
            organization_id=org.id,
            plan_id=plan.id,
            status='active',
        )
        db_session.add(subscription)
        db_session.commit()

        with patch.dict('os.environ', {'SENTRIKAT_MODE': 'saas'}):
            allowed, msg = check_quota(org.id, 'agents')
        assert allowed is True
        assert '0/10' in msg

    def test_saas_mode_limit_reached(self, app, db_session):
        """In SaaS mode, exceeding the plan limit returns denied."""
        from app.models import SubscriptionPlan, Subscription

        org = _create_org(db_session)

        plan = SubscriptionPlan(
            name='starter',
            display_name='Starter Plan',
            max_agents=1,
            max_users=1,
            max_products=1,
            max_api_keys=1,
        )
        db_session.add(plan)
        db_session.flush()

        subscription = Subscription(
            organization_id=org.id,
            plan_id=plan.id,
            status='active',
        )
        db_session.add(subscription)

        # Create 1 active product to hit the limit
        _create_product(db_session, org, product_name='OnlyProduct')
        db_session.commit()

        with patch.dict('os.environ', {'SENTRIKAT_MODE': 'saas'}):
            allowed, msg = check_quota(org.id, 'products')
        assert allowed is False
        assert 'limit reached' in msg.lower() or 'Upgrade' in msg

    def test_saas_mode_unlimited_plan(self, app, db_session):
        """A plan with max_agents=-1 means unlimited."""
        from app.models import SubscriptionPlan, Subscription

        org = _create_org(db_session)
        plan = SubscriptionPlan(
            name='enterprise',
            display_name='Enterprise',
            max_agents=-1,
            max_users=-1,
            max_products=-1,
            max_api_keys=-1,
        )
        db_session.add(plan)
        db_session.flush()

        subscription = Subscription(
            organization_id=org.id,
            plan_id=plan.id,
            status='active',
        )
        db_session.add(subscription)
        db_session.commit()

        with patch.dict('os.environ', {'SENTRIKAT_MODE': 'saas'}):
            allowed, msg = check_quota(org.id, 'agents')
        assert allowed is True
        assert 'Unlimited' in msg

    def test_saas_mode_canceled_subscription_denied(self, app, db_session):
        """A canceled subscription denies access."""
        from app.models import SubscriptionPlan, Subscription

        org = _create_org(db_session)
        plan = SubscriptionPlan(name='basic', display_name='Basic', max_agents=5)
        db_session.add(plan)
        db_session.flush()

        subscription = Subscription(
            organization_id=org.id,
            plan_id=plan.id,
            status='canceled',
        )
        db_session.add(subscription)
        db_session.commit()

        with patch.dict('os.environ', {'SENTRIKAT_MODE': 'saas'}):
            allowed, msg = check_quota(org.id, 'agents')
        assert allowed is False


# ---------------------------------------------------------------------------
# get_usage_history() tests
# ---------------------------------------------------------------------------

class TestGetUsageHistory:
    """Tests for time-filtered usage history queries."""

    def test_returns_records_within_window(self, app, db_session):
        """Records within the requested day window are returned."""
        from app.models import UsageRecord

        org = _create_org(db_session)
        now = datetime.utcnow()

        # Record from 5 days ago (within default 30-day window)
        r1 = UsageRecord(
            organization_id=org.id,
            metric='agents_active',
            value=10,
            period_start=now - timedelta(days=5),
            period_end=now - timedelta(days=4),
        )
        # Record from 60 days ago (outside 30-day window)
        r2 = UsageRecord(
            organization_id=org.id,
            metric='agents_active',
            value=5,
            period_start=now - timedelta(days=60),
            period_end=now - timedelta(days=59),
        )
        db_session.add_all([r1, r2])
        db_session.commit()

        history = get_usage_history(org.id, 'agents_active', days=30)
        assert len(history) == 1
        assert history[0]['value'] == 10

    def test_returns_empty_when_no_records(self, app, db_session):
        """An org with no records returns an empty list."""
        org = _create_org(db_session)
        db_session.commit()

        history = get_usage_history(org.id, 'agents_active')
        assert history == []

    def test_ordered_by_period_start_ascending(self, app, db_session):
        """Results are sorted chronologically (oldest first)."""
        from app.models import UsageRecord

        org = _create_org(db_session)
        now = datetime.utcnow()

        for i in [10, 5, 1]:
            r = UsageRecord(
                organization_id=org.id,
                metric='products_total',
                value=i * 10,
                period_start=now - timedelta(days=i),
                period_end=now - timedelta(days=i - 1),
            )
            db_session.add(r)
        db_session.commit()

        history = get_usage_history(org.id, 'products_total', days=30)
        assert len(history) == 3
        values = [h['value'] for h in history]
        assert values == [100, 50, 10]  # 10 days ago, 5 days ago, 1 day ago

    def test_custom_day_window(self, app, db_session):
        """A narrower day window excludes older records."""
        from app.models import UsageRecord

        org = _create_org(db_session)
        now = datetime.utcnow()

        r1 = UsageRecord(
            organization_id=org.id, metric='api_keys', value=2,
            period_start=now - timedelta(days=3),
            period_end=now - timedelta(days=2),
        )
        r2 = UsageRecord(
            organization_id=org.id, metric='api_keys', value=5,
            period_start=now - timedelta(days=10),
            period_end=now - timedelta(days=9),
        )
        db_session.add_all([r1, r2])
        db_session.commit()

        # 7-day window should include only the 3-day-old record
        history = get_usage_history(org.id, 'api_keys', days=7)
        assert len(history) == 1
        assert history[0]['value'] == 2

    def test_filters_by_metric_name(self, app, db_session):
        """Only records matching the requested metric are returned."""
        from app.models import UsageRecord

        org = _create_org(db_session)
        now = datetime.utcnow()

        for metric, val in [('agents_active', 5), ('products_total', 20), ('users_active', 3)]:
            r = UsageRecord(
                organization_id=org.id, metric=metric, value=val,
                period_start=now - timedelta(days=1),
                period_end=now,
            )
            db_session.add(r)
        db_session.commit()

        history = get_usage_history(org.id, 'products_total', days=30)
        assert len(history) == 1
        assert history[0]['metric'] == 'products_total'
        assert history[0]['value'] == 20


# ---------------------------------------------------------------------------
# get_all_orgs_usage_summary() tests
# ---------------------------------------------------------------------------

class TestGetAllOrgsUsageSummary:
    """Tests for the multi-org admin usage summary."""

    def test_returns_summary_for_all_active_orgs(self, app, db_session):
        """All active organizations appear in the summary."""
        org1 = _create_org(db_session, name='summary-a', display_name='Summary A')
        org2 = _create_org(db_session, name='summary-b', display_name='Summary B')
        db_session.commit()

        summaries = get_all_orgs_usage_summary()
        slugs = {s['organization_slug'] for s in summaries}
        assert 'summary-a' in slugs
        assert 'summary-b' in slugs

    def test_excludes_inactive_orgs(self, app, db_session):
        """Inactive organizations are excluded from the summary."""
        from app.models import Organization

        active = _create_org(db_session, name='active-org', display_name='Active')
        inactive = Organization(name='inactive-org', display_name='Inactive', active=False)
        db_session.add(inactive)
        db_session.commit()

        summaries = get_all_orgs_usage_summary()
        slugs = {s['organization_slug'] for s in summaries}
        assert 'active-org' in slugs
        assert 'inactive-org' not in slugs

    def test_summary_includes_org_identity(self, app, db_session):
        """Each summary dict includes organization_name and organization_slug."""
        _create_org(db_session, name='identity-org', display_name='Identity Org')
        db_session.commit()

        summaries = get_all_orgs_usage_summary()
        entry = next(s for s in summaries if s['organization_slug'] == 'identity-org')
        assert entry['organization_name'] == 'Identity Org'

    def test_summary_contains_usage_metrics(self, app, db_session):
        """Each summary entry has the standard usage metric keys."""
        org = _create_org(db_session, name='metrics-org', display_name='Metrics Org')
        _create_product(db_session, org, product_name='SummaryProd')
        db_session.commit()

        summaries = get_all_orgs_usage_summary()
        entry = next(s for s in summaries if s['organization_slug'] == 'metrics-org')
        assert 'agents_active' in entry
        assert 'products_total' in entry
        assert 'users_active' in entry
        assert 'api_keys' in entry
        assert entry['products_total'] == 1
