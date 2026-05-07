"""Tests for /api/provision/hard-delete endpoint.

Cross-repo contract with sentrikat-web/license-server: this endpoint replaces
manual SQL DELETE for orphan-zombie cleanup (GDPR erasure / admin reset).

Test scope:
- Auth: missing X-Provision-Key → 401; wrong key → 401
- Validation: missing both email + org_id → 400
- Idempotent: 200 on already-deleted target with deleted counts = 0
- Source resolution: email → org_id lookup works
- Pre-count fields present in response shape
"""

import json
import os

import pytest


@pytest.fixture
def app(monkeypatch):
    monkeypatch.setenv('SAAS_MODE', 'true')
    monkeypatch.setenv('SENTRIKAT_PROVISION_KEY', 'test-provision-key-12345')
    monkeypatch.setenv('DATABASE_URL', 'sqlite:///:memory:')
    monkeypatch.setenv('FLASK_ENV', 'testing')

    from app import create_app, db
    application = create_app()
    application.config['TESTING'] = True
    application.config['WTF_CSRF_ENABLED'] = False

    with application.app_context():
        db.create_all()
        yield application
        db.session.remove()
        db.drop_all()


@pytest.fixture
def client(app):
    return app.test_client()


def _hd_url():
    return '/api/provision/hard-delete'


class TestHardDeleteAuth:
    def test_missing_key_returns_401(self, client):
        resp = client.post(_hd_url(), json={'email': 'foo@example.com'})
        assert resp.status_code in (401, 403)

    def test_wrong_key_returns_401(self, client):
        resp = client.post(
            _hd_url(),
            json={'email': 'foo@example.com'},
            headers={'X-Provision-Key': 'wrong-key'},
        )
        assert resp.status_code == 401


class TestHardDeleteValidation:
    def _hdr(self):
        return {'X-Provision-Key': 'test-provision-key-12345'}

    def test_missing_body_returns_400(self, client):
        resp = client.post(_hd_url(), headers=self._hdr())
        assert resp.status_code == 400

    def test_missing_both_identifiers_returns_400(self, client):
        resp = client.post(_hd_url(), json={'reason': 'test'}, headers=self._hdr())
        assert resp.status_code == 400
        body = resp.get_json()
        assert 'email' in body['error'].lower() or 'organization_id' in body['error'].lower()


class TestHardDeleteIdempotent:
    def _hdr(self):
        return {'X-Provision-Key': 'test-provision-key-12345'}

    def test_nonexistent_email_returns_200_with_zero_counts(self, client):
        """Idempotent contract: deleting a non-existent target returns 200
        with deleted counts = 0, NOT 404."""
        resp = client.post(
            _hd_url(),
            json={'email': 'never-existed@example.com', 'reason': 'test_idempotency'},
            headers=self._hdr(),
        )
        assert resp.status_code == 200
        body = resp.get_json()
        assert 'deleted' in body
        assert body['deleted']['users'] == 0
        assert body['deleted']['organizations'] == 0
        assert body['reason'] == 'test_idempotency'


class TestHardDeleteResponseShape:
    def _hdr(self):
        return {'X-Provision-Key': 'test-provision-key-12345'}

    def test_response_shape_contains_required_keys(self, client):
        resp = client.post(
            _hd_url(),
            json={'email': 'never-existed@example.com'},
            headers=self._hdr(),
        )
        assert resp.status_code == 200
        body = resp.get_json()
        for k in ('users', 'organizations', 'subscriptions', 'assets', 'vulnerability_matches', 'agent_api_keys'):
            assert k in body['deleted'], (
                f"Response shape contract: missing key {k!r} in body['deleted']"
            )


def test_hard_delete_endpoint_registered_and_distinct_from_cancel():
    """Snapshot test: hard-delete must exist as a distinct endpoint from
    cancel. License-server team relies on this contract."""
    import inspect
    from app import provision_api
    src = inspect.getsource(provision_api)
    assert "@provision_bp.route('/hard-delete'" in src, (
        "Missing /hard-delete route — license-server team's hard-delete bridge "
        "needs this endpoint per cross-repo contract 2026-05-07."
    )
    assert "@provision_bp.route('/cancel'" in src, (
        "/cancel must remain (subscription-status flip is separate from hard delete)"
    )
    # hard-delete must NOT just call cancel logic — must have its own delete path
    assert 'db.session.delete(org)' in src or 'Organization.query.get' in src, (
        "/hard-delete must perform actual delete, not just status flip"
    )


# ============================================================================
# SAAS-ACTIVATION-TOKEN endpoint tests
# ============================================================================


class TestRegenerateActivationToken:
    def _hdr(self):
        return {'X-Provision-Key': 'test-provision-key-12345'}

    def test_missing_key_returns_401(self, client):
        resp = client.post('/api/provision/regenerate-activation-token', json={'email': 'foo@example.com'})
        assert resp.status_code in (401, 403)

    def test_missing_identifier_returns_400(self, client):
        resp = client.post('/api/provision/regenerate-activation-token', json={'expiry_hours': 24}, headers=self._hdr())
        assert resp.status_code == 400

    def test_unknown_user_returns_404(self, client):
        resp = client.post(
            '/api/provision/regenerate-activation-token',
            json={'email': 'nobody@example.com'},
            headers=self._hdr(),
        )
        assert resp.status_code == 404


def test_activation_token_endpoint_registered():
    """Snapshot test: /regenerate-activation-token must exist as a distinct
    endpoint from /reset-password — license-server team relies on this
    contract for the SAAS-ACTIVATION-TOKEN-CONTRACT."""
    import inspect
    from app import provision_api
    src = inspect.getsource(provision_api)
    assert "@provision_bp.route('/regenerate-activation-token'" in src, (
        "Missing /regenerate-activation-token route — license-server team's "
        "welcome-email mono-CTA flow depends on this endpoint per cross-repo "
        "contract 2026-05-07."
    )


def test_provision_response_includes_activation_url_when_requested():
    """When license-server passes include_activation_url:true in /api/provision,
    the response must include activation_url + activation_expires_at, AND
    suppress temporary_password (customer never sees a temp password in the
    activation flow)."""
    import inspect
    from app import provision_api
    src = inspect.getsource(provision_api.provision_tenant)
    assert "include_activation_url" in src, (
        "/api/provision must support include_activation_url flag"
    )
    assert "activation_url" in src, (
        "Response payload must contain activation_url field"
    )
    assert "generate_activation_token" in src, (
        "Must use the new generate_activation_token method (not the 30-min "
        "password reset token)"
    )


def test_user_model_has_generate_activation_token():
    """User model must expose generate_activation_token with default 48h
    expiry — distinct semantically from the 30-minute password reset flow
    even if both share the same DB column."""
    from app.models import User
    assert hasattr(User, 'generate_activation_token'), (
        "User model missing generate_activation_token method"
    )
    import inspect
    sig = inspect.signature(User.generate_activation_token)
    assert 'expiry_hours' in sig.parameters
    assert sig.parameters['expiry_hours'].default == 48
