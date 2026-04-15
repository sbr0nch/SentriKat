"""
Tests for the SaaS Provisioning API (app/provision_api.py).

Verifies tenant creation, upgrade, cancellation, and status check.
"""

import os
import pytest
from unittest.mock import patch, MagicMock
from datetime import datetime


class TestProvisionSecurity:
    """Test provisioning API security."""

    def test_blocked_in_onpremise_mode(self, client):
        """Provisioning API is disabled in on-premise mode."""
        with patch('app.provision_api._PROVISION_KEY', 'test-key'):
            with patch('app.provision_api.is_saas_mode', return_value=False):
                resp = client.post('/api/provision', json={
                    'email': 'test@test.com',
                    'full_name': 'Test User',
                    'company_name': 'Test Corp'
                }, headers={'X-Provision-Key': 'test-key'})
                assert resp.status_code == 403
                assert 'SaaS mode' in resp.get_json()['error']

    def test_rejected_without_api_key(self, client):
        """Requests without API key are rejected."""
        with patch('app.provision_api._PROVISION_KEY', 'test-key'):
            with patch('app.provision_api.is_saas_mode', return_value=True):
                resp = client.post('/api/provision', json={
                    'email': 'test@test.com',
                    'full_name': 'Test User',
                    'company_name': 'Test Corp'
                })
                assert resp.status_code == 401

    def test_rejected_with_wrong_api_key(self, client):
        """Requests with wrong API key are rejected."""
        with patch('app.provision_api._PROVISION_KEY', 'correct-key'):
            with patch('app.provision_api.is_saas_mode', return_value=True):
                resp = client.post('/api/provision', json={
                    'email': 'test@test.com',
                    'full_name': 'Test User',
                    'company_name': 'Test Corp'
                }, headers={'X-Provision-Key': 'wrong-key'})
                assert resp.status_code == 401

    def test_503_when_provision_key_not_configured(self, client):
        """Returns 503 when SENTRIKAT_PROVISION_KEY is not set."""
        with patch('app.provision_api._PROVISION_KEY', ''):
            with patch('app.provision_api.is_saas_mode', return_value=True):
                resp = client.post('/api/provision', json={
                    'email': 'test@test.com',
                    'full_name': 'Test User',
                    'company_name': 'Test Corp'
                }, headers={'X-Provision-Key': 'anything'})
                assert resp.status_code == 503


class TestProvisionTenant:
    """Test tenant provisioning."""

    def test_provision_creates_org_user_subscription(self, client, app):
        """Full provisioning creates org, user, and subscription."""
        with patch('app.provision_api._PROVISION_KEY', 'test-key'):
            with patch('app.provision_api.is_saas_mode', return_value=True):
                # Seed default plans first
                with app.app_context():
                    from app.models import SubscriptionPlan
                    if SubscriptionPlan.query.count() == 0:
                        SubscriptionPlan.seed_default_plans()

                resp = client.post('/api/provision', json={
                    'email': 'mario@acme.com',
                    'full_name': 'Mario Rossi',
                    'company_name': 'Acme Corporation',
                    'plan_name': 'free',
                    'trial_days': 14
                }, headers={'X-Provision-Key': 'test-key'})

                assert resp.status_code == 201
                data = resp.get_json()
                assert data['success'] is True

                tenant = data['tenant']
                assert tenant['email'] == 'mario@acme.com'
                assert tenant['organization_display_name'] == 'Acme Corporation'
                assert tenant['plan'] == 'free'
                assert tenant['subscription_status'] == 'trialing'
                assert tenant['must_change_password'] is True
                assert tenant['temporary_password']  # Should be non-empty
                assert tenant['organization_id'] > 0
                assert tenant['user_id'] > 0

    def test_provision_rejects_missing_fields(self, client):
        """Missing required fields return 400."""
        with patch('app.provision_api._PROVISION_KEY', 'test-key'):
            with patch('app.provision_api.is_saas_mode', return_value=True):
                resp = client.post('/api/provision', json={
                    'email': 'test@test.com'
                    # Missing full_name and company_name
                }, headers={'X-Provision-Key': 'test-key'})
                assert resp.status_code == 400

    def test_provision_rejects_invalid_email(self, client):
        """Invalid email format returns 400."""
        with patch('app.provision_api._PROVISION_KEY', 'test-key'):
            with patch('app.provision_api.is_saas_mode', return_value=True):
                resp = client.post('/api/provision', json={
                    'email': 'not-an-email',
                    'full_name': 'Test User',
                    'company_name': 'Test Corp'
                }, headers={'X-Provision-Key': 'test-key'})
                assert resp.status_code == 400

    def test_provision_rejects_duplicate_email(self, client, app):
        """Duplicate email returns 409."""
        with patch('app.provision_api._PROVISION_KEY', 'test-key'):
            with patch('app.provision_api.is_saas_mode', return_value=True):
                with app.app_context():
                    from app.models import SubscriptionPlan
                    if SubscriptionPlan.query.count() == 0:
                        SubscriptionPlan.seed_default_plans()

                # First provision
                client.post('/api/provision', json={
                    'email': 'dup@test.com',
                    'full_name': 'First User',
                    'company_name': 'First Corp'
                }, headers={'X-Provision-Key': 'test-key'})

                # Second provision with same email
                resp = client.post('/api/provision', json={
                    'email': 'dup@test.com',
                    'full_name': 'Second User',
                    'company_name': 'Second Corp'
                }, headers={'X-Provision-Key': 'test-key'})
                assert resp.status_code == 409
                assert resp.get_json()['code'] == 'USER_EXISTS'


class TestProvisionUpgrade:
    """Test subscription upgrade."""

    def test_upgrade_changes_plan(self, client, app):
        """Upgrade changes subscription plan."""
        with patch('app.provision_api._PROVISION_KEY', 'test-key'):
            with patch('app.provision_api.is_saas_mode', return_value=True):
                with app.app_context():
                    from app.models import SubscriptionPlan
                    if SubscriptionPlan.query.count() == 0:
                        SubscriptionPlan.seed_default_plans()

                # Provision first
                resp = client.post('/api/provision', json={
                    'email': 'upgrade@test.com',
                    'full_name': 'Upgrade User',
                    'company_name': 'Upgrade Corp',
                    'plan_name': 'free'
                }, headers={'X-Provision-Key': 'test-key'})
                org_id = resp.get_json()['tenant']['organization_id']

                # Upgrade
                resp = client.post('/api/provision/upgrade', json={
                    'organization_id': org_id,
                    'plan_name': 'starter'
                }, headers={'X-Provision-Key': 'test-key'})
                assert resp.status_code == 200
                assert resp.get_json()['success'] is True


class TestProvisionCancel:
    """Test subscription cancellation."""

    def test_cancel_at_period_end(self, client, app):
        """Cancel with grace period."""
        with patch('app.provision_api._PROVISION_KEY', 'test-key'):
            with patch('app.provision_api.is_saas_mode', return_value=True):
                with app.app_context():
                    from app.models import SubscriptionPlan
                    if SubscriptionPlan.query.count() == 0:
                        SubscriptionPlan.seed_default_plans()

                # Provision first
                resp = client.post('/api/provision', json={
                    'email': 'cancel@test.com',
                    'full_name': 'Cancel User',
                    'company_name': 'Cancel Corp'
                }, headers={'X-Provision-Key': 'test-key'})
                org_id = resp.get_json()['tenant']['organization_id']

                # Cancel
                resp = client.post('/api/provision/cancel', json={
                    'organization_id': org_id,
                    'cancel_at_period_end': True
                }, headers={'X-Provision-Key': 'test-key'})
                assert resp.status_code == 200
                assert resp.get_json()['success'] is True


class TestProvisionStatus:
    """Test tenant status check."""

    def test_status_by_email(self, client, app):
        """Check status by email."""
        with patch('app.provision_api._PROVISION_KEY', 'test-key'):
            with patch('app.provision_api.is_saas_mode', return_value=True):
                with app.app_context():
                    from app.models import SubscriptionPlan
                    if SubscriptionPlan.query.count() == 0:
                        SubscriptionPlan.seed_default_plans()

                # Provision first
                client.post('/api/provision', json={
                    'email': 'status@test.com',
                    'full_name': 'Status User',
                    'company_name': 'Status Corp'
                }, headers={'X-Provision-Key': 'test-key'})

                # Check status
                resp = client.get(
                    '/api/provision/status?email=status@test.com',
                    headers={'X-Provision-Key': 'test-key'}
                )
                assert resp.status_code == 200
                data = resp.get_json()
                assert data['exists'] is True
                assert data['organization']['display_name'] == 'Status Corp'
                assert data['user_count'] == 1

    def test_status_not_found(self, client):
        """Non-existent email returns 404."""
        with patch('app.provision_api._PROVISION_KEY', 'test-key'):
            with patch('app.provision_api.is_saas_mode', return_value=True):
                resp = client.get(
                    '/api/provision/status?email=nonexistent@test.com',
                    headers={'X-Provision-Key': 'test-key'}
                )
                assert resp.status_code == 404
                assert resp.get_json()['exists'] is False


class TestProvisionB8Regressions:
    """Regression tests for finding B8: idempotency, atomic savepoint,
    and the org_id information leak on duplicate email (H4)."""

    def test_duplicate_email_does_not_leak_existing_org_id(self, client, app):
        """409 must not echo the existing organization id (H4)."""
        with patch('app.provision_api._PROVISION_KEY', 'test-key'):
            with patch('app.provision_api.is_saas_mode', return_value=True):
                with app.app_context():
                    from app.models import SubscriptionPlan
                    if SubscriptionPlan.query.count() == 0:
                        SubscriptionPlan.seed_default_plans()

                client.post('/api/provision', json={
                    'email': 'leak@test.com',
                    'full_name': 'Leak User',
                    'company_name': 'Leak Corp'
                }, headers={'X-Provision-Key': 'test-key'})

                resp = client.post('/api/provision', json={
                    'email': 'leak@test.com',
                    'full_name': 'Leak Second',
                    'company_name': 'Leak Second Corp'
                }, headers={'X-Provision-Key': 'test-key'})
                assert resp.status_code == 409
                body = resp.get_json()
                assert 'existing_org_id' not in body
                assert 'organization_id' not in body

    def test_idempotency_key_returns_cached_result(self, client, app):
        """A retry with the same idempotency_key must NOT create a new org
        and must return the same payload."""
        with patch('app.provision_api._PROVISION_KEY', 'test-key'):
            with patch('app.provision_api.is_saas_mode', return_value=True):
                with app.app_context():
                    from app.models import SubscriptionPlan
                    if SubscriptionPlan.query.count() == 0:
                        SubscriptionPlan.seed_default_plans()

                payload = {
                    'email': 'idem@test.com',
                    'full_name': 'Idem User',
                    'company_name': 'Idem Corp',
                    'idempotency_key': 'stripe-session-abc123',
                }
                r1 = client.post('/api/provision', json=payload,
                                 headers={'X-Provision-Key': 'test-key'})
                assert r1.status_code == 201
                org_id_1 = r1.get_json()['tenant']['organization_id']
                temp_pw_1 = r1.get_json()['tenant']['temporary_password']

                # Replay
                r2 = client.post('/api/provision', json=payload,
                                 headers={'X-Provision-Key': 'test-key'})
                assert r2.status_code == 201
                org_id_2 = r2.get_json()['tenant']['organization_id']
                temp_pw_2 = r2.get_json()['tenant']['temporary_password']

                # Same org and same cached payload
                assert org_id_1 == org_id_2
                assert temp_pw_1 == temp_pw_2

                # Verify only one org was created
                with app.app_context():
                    from app.models import Organization
                    orgs = Organization.query.filter(
                        Organization.display_name == 'Idem Corp'
                    ).all()
                    assert len(orgs) == 1


# =============================================================================
# Admin listing endpoints: GET /api/provision/tenants and /api/provision/plans
#
# These are the two endpoints the license-server admin portal uses to
# populate the "Live SaaS Tenants" and "Plans" widgets. They're
# read-only, protected by the same X-Provision-Key header, and cover
# the cross-tenant admin view from the license-server's perspective.
# =============================================================================


def _seed_plans_and_tenants(client, app, count=3):
    """Provision ``count`` test tenants so the listing endpoints have
    something to return. Returns a list of created tenant dicts.
    """
    with app.app_context():
        from app.models import SubscriptionPlan
        if SubscriptionPlan.query.count() == 0:
            SubscriptionPlan.seed_default_plans()

    created = []
    plans_cycle = ['free', 'starter', 'pro']
    for i in range(count):
        plan = plans_cycle[i % len(plans_cycle)]
        r = client.post('/api/provision', json={
            'email': f'admin{i}@tenant{i}.test',
            'full_name': f'Admin {i}',
            'company_name': f'Tenant {i}',
            'plan_name': plan,
        }, headers={'X-Provision-Key': 'test-key'})
        assert r.status_code == 201, (
            f"Seeding tenant {i} failed: {r.status_code} {r.get_data(as_text=True)[:200]}"
        )
        created.append(r.get_json()['tenant'])
    return created


class TestListTenants:
    """GET /api/provision/tenants — license-server admin UI data source."""

    def test_returns_all_tenants_with_shape(self, client, app):
        with patch('app.provision_api._PROVISION_KEY', 'test-key'):
            with patch('app.provision_api.is_saas_mode', return_value=True):
                _seed_plans_and_tenants(client, app, count=3)

                resp = client.get(
                    '/api/provision/tenants',
                    headers={'X-Provision-Key': 'test-key'},
                )
                assert resp.status_code == 200, resp.get_data(as_text=True)
                data = resp.get_json()

                assert 'tenants' in data
                assert 'total' in data
                assert 'filters_applied' in data
                assert data['total'] == len(data['tenants'])
                assert data['total'] >= 3  # baseline + any setup fixtures

                # Shape check on the first tenant
                t = data['tenants'][0]
                for key in (
                    'organization_id', 'organization_name', 'admin_email',
                    'plan_name', 'status', 'agents', 'users',
                    'agent_count', 'user_count', 'created_at',
                ):
                    assert key in t, f"Missing key {key!r} in tenant summary"

                # Usage counters are formatted as "N/M" or "N/unlimited"
                assert '/' in t['agents']
                assert '/' in t['users']

    def test_filter_by_plan(self, client, app):
        with patch('app.provision_api._PROVISION_KEY', 'test-key'):
            with patch('app.provision_api.is_saas_mode', return_value=True):
                _seed_plans_and_tenants(client, app, count=3)

                resp = client.get(
                    '/api/provision/tenants?plan=pro',
                    headers={'X-Provision-Key': 'test-key'},
                )
                assert resp.status_code == 200
                data = resp.get_json()
                # Every row must be on the pro plan (case-insensitive on
                # the filter side but stored lowercased).
                for t in data['tenants']:
                    assert (t.get('plan_name') or '').lower() == 'pro', (
                        f"filter leaked non-pro tenant: {t}"
                    )
                assert data['filters_applied']['plan'] == 'pro'

    def test_filter_by_status(self, client, app):
        with patch('app.provision_api._PROVISION_KEY', 'test-key'):
            with patch('app.provision_api.is_saas_mode', return_value=True):
                _seed_plans_and_tenants(client, app, count=3)

                # New tenants land in trialing by default (14-day default).
                resp = client.get(
                    '/api/provision/tenants?status=trialing',
                    headers={'X-Provision-Key': 'test-key'},
                )
                assert resp.status_code == 200
                data = resp.get_json()
                for t in data['tenants']:
                    assert (t.get('status') or '').lower() == 'trialing'

    def test_search_matches_email_or_org_name(self, client, app):
        with patch('app.provision_api._PROVISION_KEY', 'test-key'):
            with patch('app.provision_api.is_saas_mode', return_value=True):
                _seed_plans_and_tenants(client, app, count=3)

                # Search by org display name prefix
                resp = client.get(
                    '/api/provision/tenants?search=Tenant 1',
                    headers={'X-Provision-Key': 'test-key'},
                )
                assert resp.status_code == 200
                data = resp.get_json()
                names = [(t.get('organization_name') or '') for t in data['tenants']]
                assert any('Tenant 1' in n for n in names)

                # Search by admin email fragment
                resp = client.get(
                    '/api/provision/tenants?search=admin2@',
                    headers={'X-Provision-Key': 'test-key'},
                )
                assert resp.status_code == 200
                data = resp.get_json()
                assert any(
                    (t.get('admin_email') or '').startswith('admin2@')
                    for t in data['tenants']
                )

    def test_auth_required(self, client, app):
        with patch('app.provision_api._PROVISION_KEY', 'test-key'):
            with patch('app.provision_api.is_saas_mode', return_value=True):
                # No header at all
                r1 = client.get('/api/provision/tenants')
                assert r1.status_code == 401
                # Wrong key
                r2 = client.get(
                    '/api/provision/tenants',
                    headers={'X-Provision-Key': 'wrong-key'},
                )
                assert r2.status_code == 401

    def test_saas_mode_only(self, client, app):
        with patch('app.provision_api._PROVISION_KEY', 'test-key'):
            with patch('app.provision_api.is_saas_mode', return_value=False):
                resp = client.get(
                    '/api/provision/tenants',
                    headers={'X-Provision-Key': 'test-key'},
                )
                assert resp.status_code == 403


class TestListPlans:
    """GET /api/provision/plans — plan catalogue for the license-server."""

    def test_returns_active_plans_with_full_shape(self, client, app):
        with patch('app.provision_api._PROVISION_KEY', 'test-key'):
            with patch('app.provision_api.is_saas_mode', return_value=True):
                with app.app_context():
                    from app.models import SubscriptionPlan
                    if SubscriptionPlan.query.count() == 0:
                        SubscriptionPlan.seed_default_plans()

                resp = client.get(
                    '/api/provision/plans',
                    headers={'X-Provision-Key': 'test-key'},
                )
                assert resp.status_code == 200, resp.get_data(as_text=True)
                data = resp.get_json()

                assert 'plans' in data
                assert 'total' in data
                assert data['total'] == len(data['plans'])
                # Five default plans ship with the app — this catches a
                # silent regression where one gets dropped from seeding.
                assert data['total'] >= 5

                # Every entry has the documented shape.
                for p in data['plans']:
                    for k in (
                        'id', 'name', 'slug', 'currency',
                        'price_monthly_cents', 'price_annual_cents',
                        'price_monthly_eur', 'price_annual_eur',
                        'max_agents', 'max_users', 'max_organizations',
                        'max_products', 'max_api_keys', 'max_storage_mb',
                        'features', 'features_map',
                        'is_active', 'is_default', 'sort_order',
                    ):
                        assert k in p, (
                            f"plan {p.get('id')!r} missing key {k!r}: {p}"
                        )
                    # Features list contains only enabled features
                    assert isinstance(p['features'], list)
                    for feat in p['features']:
                        assert p['features_map'].get(feat) is True
                    # Euro values are pre-divided from cents
                    assert p['price_monthly_eur'] == p['price_monthly_cents'] / 100.0

    def test_sort_order_is_preserved(self, client, app):
        """Plans must come back in sort_order order so the admin UI
        doesn't render them randomly."""
        with patch('app.provision_api._PROVISION_KEY', 'test-key'):
            with patch('app.provision_api.is_saas_mode', return_value=True):
                with app.app_context():
                    from app.models import SubscriptionPlan
                    if SubscriptionPlan.query.count() == 0:
                        SubscriptionPlan.seed_default_plans()

                resp = client.get(
                    '/api/provision/plans',
                    headers={'X-Provision-Key': 'test-key'},
                )
                data = resp.get_json()
                sort_orders = [p['sort_order'] for p in data['plans']]
                assert sort_orders == sorted(sort_orders), (
                    f"Plans out of sort_order: {sort_orders}"
                )

    def test_include_inactive_query_param(self, client, app):
        with patch('app.provision_api._PROVISION_KEY', 'test-key'):
            with patch('app.provision_api.is_saas_mode', return_value=True):
                with app.app_context():
                    from app import db as _db
                    from app.models import SubscriptionPlan
                    if SubscriptionPlan.query.count() == 0:
                        SubscriptionPlan.seed_default_plans()
                    # Disable one plan and check include_inactive behaviour
                    archived = SubscriptionPlan.query.filter_by(name='free').first()
                    if archived:
                        archived.is_active = False
                        _db.session.commit()

                r1 = client.get(
                    '/api/provision/plans',
                    headers={'X-Provision-Key': 'test-key'},
                )
                active_plan_ids = {p['id'] for p in r1.get_json()['plans']}
                assert 'free' not in active_plan_ids

                r2 = client.get(
                    '/api/provision/plans?include_inactive=true',
                    headers={'X-Provision-Key': 'test-key'},
                )
                all_plan_ids = {p['id'] for p in r2.get_json()['plans']}
                assert 'free' in all_plan_ids

    def test_auth_required(self, client, app):
        with patch('app.provision_api._PROVISION_KEY', 'test-key'):
            with patch('app.provision_api.is_saas_mode', return_value=True):
                r1 = client.get('/api/provision/plans')
                assert r1.status_code == 401
                r2 = client.get(
                    '/api/provision/plans',
                    headers={'X-Provision-Key': 'wrong-key'},
                )
                assert r2.status_code == 401
