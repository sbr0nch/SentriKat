"""
Regression tests for the single-org vs multi-org split on
``/alerts/settings``.

Background: the page used to show both a "Global Default Rules" card
AND a "Per-Organization Alert Configuration" table for every tenant,
even SaaS customers on Pro / Starter plans whose plan hard-caps them
at exactly one organization. For those tenants the "defaults for new
organizations" wording is nonsensical — there will never be new orgs —
and the per-org table has a single row, making the dual layout
redundant and confusing.

The fix flips the layout conditionally:

  * ``saas_mode`` AND ``plan.multi_org == False`` AND
    ``max_organizations <= 1`` → single-org layout:
      - Global Default Rules card HIDDEN
      - Per-Organization table header renamed to "Alert Rules ..."
      - Organization column hidden in the table
      - "Global Default" option removed from the Alert Mode dropdown
      - "Reset to global defaults" button hidden
      - Subtitle reworded from "Central hub ..." to "Configure alert
        rules and delivery channels for your organization"

  * everything else (Business+, Enterprise, on-prem) → unchanged
    multi-org layout.

These tests exercise both branches by logging in as an org_admin on a
single-org plan (pro) and then on a multi-org plan (business).
"""

import pytest
from unittest.mock import patch


def _make_user_with_plan(db_session, plan_name):
    """Create an org + org_admin + subscription on the given plan.

    Returns (user, subscription). Seeds default plans if needed.
    """
    from app.models import (
        Organization, User, Subscription, SubscriptionPlan,
    )
    from werkzeug.security import generate_password_hash
    from datetime import datetime, timedelta

    if SubscriptionPlan.query.count() == 0:
        SubscriptionPlan.seed_default_plans()

    plan = SubscriptionPlan.query.filter_by(name=plan_name).first()
    assert plan is not None, f"Plan {plan_name!r} not seeded"

    org = Organization(
        name=f'{plan_name}-org',
        display_name=f'{plan_name.title()} Test Org',
        active=True,
    )
    db_session.add(org)
    db_session.flush()

    user = User(
        username=f'{plan_name}admin',
        email=f'admin-{plan_name}@test.local',
        password_hash=generate_password_hash('pass'),
        role='org_admin',
        organization_id=org.id,
        is_active=True,
        auth_type='local',
    )
    db_session.add(user)
    db_session.flush()

    sub = Subscription(
        organization_id=org.id,
        plan_id=plan.id,
        status='active',
        billing_cycle='monthly',
        current_period_start=datetime.utcnow(),
        current_period_end=datetime.utcnow() + timedelta(days=30),
    )
    db_session.add(sub)
    db_session.commit()
    return user, sub


def _login_as(client, user):
    with client.session_transaction() as sess:
        sess['user_id'] = user.id
        sess['organization_id'] = user.organization_id
        sess['_fresh'] = True


class TestAlertsSettingsSingleOrgLayout:
    """SaaS Pro tenant (max_organizations=1, multi_org=False) → simplified layout."""

    # Markers that are unambiguously tied to the card HTML (not reusable
    # inside JS comments or constants, which also end up in the rendered
    # body because they live in {% block extra_js %}).
    GLOBAL_CARD_HEADER = '<span><i class="bi bi-globe me-2"></i>Global Default Rules</span>'
    GLOBAL_CARD_BODY = 'defaults for newly created organizations'
    GLOBAL_CARD_BADGE = '>Defaults for new organizations<'
    # After M-7 the button no longer has inline onclick; it's bound via
    # addEventListener by id in the nonce'd script block.
    GLOBAL_CARD_SAVE_BUTTON = 'id="saveGlobalDefaultsBtn"'
    RULE_CRITICAL_INPUT = 'id="ruleCritical"'

    MULTI_ORG_TABLE_HEADER = '<span><i class="bi bi-building me-2"></i>Per-Organization Alert Configuration</span>'

    def test_pro_plan_hides_global_defaults_card(
        self, client, db_session, setup_complete
    ):
        with patch('app.saas.is_saas_mode', return_value=True):
            user, _sub = _make_user_with_plan(db_session, 'pro')
            _login_as(client, user)

            resp = client.get('/alerts/settings')
            assert resp.status_code == 200, resp.get_data(as_text=True)[:300]
            body = resp.get_data(as_text=True)

            # The confusing wording must be gone
            assert self.GLOBAL_CARD_BADGE not in body, (
                'REGRESSION: single-org pro plan still shows the '
                '"Defaults for new organizations" badge'
            )
            assert self.GLOBAL_CARD_BODY not in body, (
                'REGRESSION: single-org pro plan still shows the '
                '"defaults for newly created organizations" body text'
            )
            assert self.GLOBAL_CARD_HEADER not in body, (
                'REGRESSION: single-org pro plan still shows the '
                'Global Default Rules card header HTML'
            )
            assert self.GLOBAL_CARD_SAVE_BUTTON not in body, (
                'REGRESSION: single-org pro plan still shows the '
                'saveGlobalDefaults() Save button'
            )
            assert self.RULE_CRITICAL_INPUT not in body, (
                'REGRESSION: single-org pro plan still renders the '
                'ruleCritical global-defaults checkbox'
            )

            # And the per-org table header renames itself
            assert '<i class="bi bi-bell me-2"></i>Alert Rules' in body, (
                'single-org layout should show an "Alert Rules" header'
            )
            assert self.MULTI_ORG_TABLE_HEADER not in body, (
                'single-org layout should NOT show the multi-org header'
            )
            # Subtitle is reworded
            assert 'Configure alert rules and delivery channels for your organization' in body
            assert 'Central hub for alert rules' not in body

            # And the body carries the data-single-org=true flag that
            # the JS reads to adjust column count and dropdown options
            assert 'data-single-org="true"' in body

    def test_free_plan_also_gets_single_org_layout(
        self, client, db_session, setup_complete
    ):
        """Free plan has max_organizations=1 and multi_org=False too."""
        with patch('app.saas.is_saas_mode', return_value=True):
            user, _sub = _make_user_with_plan(db_session, 'free')
            _login_as(client, user)

            resp = client.get('/alerts/settings')
            assert resp.status_code == 200
            body = resp.get_data(as_text=True)
            assert self.GLOBAL_CARD_HEADER not in body
            assert self.GLOBAL_CARD_SAVE_BUTTON not in body
            assert 'data-single-org="true"' in body

    def test_starter_plan_also_gets_single_org_layout(
        self, client, db_session, setup_complete
    ):
        """Starter is explicitly single-org: multi_org=False, max_orgs=1."""
        with patch('app.saas.is_saas_mode', return_value=True):
            user, _sub = _make_user_with_plan(db_session, 'starter')
            _login_as(client, user)

            resp = client.get('/alerts/settings')
            assert resp.status_code == 200
            body = resp.get_data(as_text=True)
            assert self.GLOBAL_CARD_HEADER not in body
            assert self.GLOBAL_CARD_SAVE_BUTTON not in body
            assert 'data-single-org="true"' in body


class TestAlertsSettingsMultiOrgLayout:
    """SaaS Business + Enterprise + on-prem → full multi-org layout preserved."""

    # Same markers as the sibling class — in a real project these would
    # live on a shared base, but duplicating 5 constants is not worth a
    # base class.
    GLOBAL_CARD_HEADER = '<span><i class="bi bi-globe me-2"></i>Global Default Rules</span>'
    GLOBAL_CARD_BODY = 'defaults for newly created organizations'
    GLOBAL_CARD_BADGE = '>Defaults for new organizations<'
    # After M-7 the button no longer has inline onclick; it's bound via
    # addEventListener by id in the nonce'd script block.
    GLOBAL_CARD_SAVE_BUTTON = 'id="saveGlobalDefaultsBtn"'
    RULE_CRITICAL_INPUT = 'id="ruleCritical"'
    MULTI_ORG_TABLE_HEADER = '<span><i class="bi bi-building me-2"></i>Per-Organization Alert Configuration</span>'

    def _assert_full_multi_org_layout(self, body):
        assert self.GLOBAL_CARD_HEADER in body, 'Global Default Rules card header missing'
        assert self.GLOBAL_CARD_BADGE in body, '"Defaults for new organizations" badge missing'
        assert self.GLOBAL_CARD_BODY in body, 'Global defaults body text missing'
        assert self.GLOBAL_CARD_SAVE_BUTTON in body, 'Save Global Defaults button missing'
        assert self.RULE_CRITICAL_INPUT in body, 'ruleCritical checkbox missing'
        assert self.MULTI_ORG_TABLE_HEADER in body, 'Multi-org table header missing'
        assert 'Central hub for alert rules' in body, 'Multi-org subtitle missing'
        assert 'data-single-org="false"' in body, 'data-single-org flag should be false'

    def test_business_plan_shows_global_defaults_card(
        self, client, db_session, setup_complete
    ):
        """Business plan has multi_org=True, max_organizations=10 —
        the admin can and will create new orgs, so the defaults card
        is relevant."""
        with patch('app.saas.is_saas_mode', return_value=True):
            user, _sub = _make_user_with_plan(db_session, 'business')
            _login_as(client, user)

            resp = client.get('/alerts/settings')
            assert resp.status_code == 200, resp.get_data(as_text=True)[:300]
            self._assert_full_multi_org_layout(resp.get_data(as_text=True))

    def test_enterprise_plan_shows_global_defaults_card(
        self, client, db_session, setup_complete
    ):
        with patch('app.saas.is_saas_mode', return_value=True):
            user, _sub = _make_user_with_plan(db_session, 'enterprise')
            _login_as(client, user)

            resp = client.get('/alerts/settings')
            assert resp.status_code == 200
            self._assert_full_multi_org_layout(resp.get_data(as_text=True))

    def test_onpremise_mode_shows_global_defaults_card(
        self, client, db_session, setup_complete
    ):
        """On-prem: single customer but can create multiple internal
        orgs via the admin UI. Keep the full layout regardless of
        plan fields."""
        with patch('app.saas.is_saas_mode', return_value=False):
            user, _sub = _make_user_with_plan(db_session, 'pro')
            _login_as(client, user)

            resp = client.get('/alerts/settings')
            assert resp.status_code == 200
            self._assert_full_multi_org_layout(resp.get_data(as_text=True))
