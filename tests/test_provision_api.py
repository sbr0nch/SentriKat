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
