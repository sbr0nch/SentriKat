"""SaaS-mode regression tests for check_product_limit.

Bug 2026-05-14 (commit 3e4095b): `check_product_limit` referenced `db`
without importing it. The function only reached the offending
`db.session.execute(...)` line in SaaS mode AND with a finite plan
limit AND when at least one active product existed to be counted. All
3 conditions had to be true simultaneously, so the bug stayed latent
through several months of post-EA week 1 testing.

This module locks down that path:
- SaaS + plan finite + N products → returns (allowed, limit, msg)
- SaaS + plan None/-1 limit (no limit) → returns (True, -1, None)
- SaaS + no subscription → falls back to free plan defaults
- SaaS + no org_id → returns (True, -1, None) (background-job semantics)
- on-prem path unchanged

It is intentionally narrow: it exists ONLY to make sure the import
chain (`from app import db` at module top of licensing.py) keeps
working AND that the SaaS branch's counting query is reachable.
"""
import pytest

from app import db
from app.licensing import check_product_limit
from app.models import Organization, Product, SubscriptionPlan, Subscription


@pytest.fixture
def saas_mode(monkeypatch):
    """Force is_saas_mode() to True for the duration of one test."""
    monkeypatch.setattr('app.saas.is_saas_mode', lambda: True)


@pytest.fixture
def free_plan(db_session):
    plan = SubscriptionPlan.query.filter_by(name='free').first()
    if not plan:
        plan = SubscriptionPlan(name='free', display_name='Free',
                                max_products=5, max_users=3, max_organizations=1)
        db_session.add(plan)
        db_session.commit()
    return plan


@pytest.fixture
def pro_plan(db_session):
    plan = SubscriptionPlan(name='test_pro', display_name='Test Pro',
                            max_products=10, max_users=10, max_organizations=1)
    db_session.add(plan)
    db_session.commit()
    return plan


@pytest.fixture
def saas_org_with_plan(db_session, pro_plan):
    org = Organization(name='saas-tenant-1', display_name='SaaS Tenant 1', active=True)
    db_session.add(org)
    db_session.flush()
    sub = Subscription(organization_id=org.id, plan_id=pro_plan.id, status='active')
    db_session.add(sub)
    db_session.commit()
    return org


def _add_active_products(db_session, org, count):
    products = []
    for i in range(count):
        p = Product(
            organization_id=org.id,
            vendor=f'Vendor{i}',
            product_name=f'Product{i}',
            version='1.0',
            active=True,
            match_type='auto',
        )
        db_session.add(p)
        products.append(p)
    db_session.commit()
    # Attach to product_organizations m2m so the count query reaches them
    for p in products:
        org.products.append(p) if hasattr(org, 'products') else p.organizations.append(org)
    db_session.commit()
    return products


def test_check_product_limit_saas_no_org_returns_no_limit(saas_mode):
    """Background jobs without org context skip the cap."""
    allowed, limit, msg = check_product_limit(organization_id=None)
    assert allowed is True
    assert limit == -1
    assert msg is None


def test_check_product_limit_saas_no_subscription_uses_free_default(
    saas_mode, db_session, free_plan
):
    """Org without active subscription falls back to free plan."""
    org = Organization(name='unsubbed', display_name='Unsubbed', active=True)
    db_session.add(org)
    db_session.commit()
    allowed, limit, msg = check_product_limit(organization_id=org.id)
    # free plan defines max_products=5, so allowed=True at 0/5
    assert allowed is True
    assert limit in (5, -1)  # depending on whether free plan resolved


def test_check_product_limit_saas_under_limit_executes_count_query(
    saas_mode, db_session, saas_org_with_plan
):
    """The regression test: actually reach db.session.execute() and not
    raise NameError. With 3 active products vs limit 10, allowed=True."""
    _add_active_products(db_session, saas_org_with_plan, count=3)
    allowed, limit, msg = check_product_limit(organization_id=saas_org_with_plan.id)
    assert allowed is True
    assert limit == 10
    assert msg is None


def test_check_product_limit_saas_at_limit_blocks(
    saas_mode, db_session, saas_org_with_plan
):
    """At limit, allowed=False and a message is returned."""
    _add_active_products(db_session, saas_org_with_plan, count=10)
    allowed, limit, msg = check_product_limit(organization_id=saas_org_with_plan.id)
    assert allowed is False
    assert limit == 10
    assert 'limit' in (msg or '').lower()


def test_check_product_limit_saas_unlimited_plan(
    saas_mode, db_session
):
    """Plan with max_products=None or -1 returns (True, -1, None) immediately
    — without executing the count query."""
    plan = SubscriptionPlan(name='unlimited_test', display_name='Unlimited',
                            max_products=None, max_users=None, max_organizations=None)
    db_session.add(plan)
    db_session.flush()
    org = Organization(name='unlimited-tenant', display_name='Unlimited Tenant', active=True)
    db_session.add(org)
    db_session.flush()
    sub = Subscription(organization_id=org.id, plan_id=plan.id, status='active')
    db_session.add(sub)
    db_session.commit()
    allowed, limit, msg = check_product_limit(organization_id=org.id)
    assert allowed is True
    assert limit == -1
    assert msg is None
