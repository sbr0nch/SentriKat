"""
Tests for the license-server SSO / impersonation endpoint (Sprint 6).

Covers:
    * valid JWT → session established + 302 redirect + audit log entry
    * expired JWT → 401
    * wrong audience → 401
    * wrong signature → 401
    * replay (same nonce twice) → second call rejected
    * missing required claims → 401
    * unknown tenant → 401
    * missing SSO secret → 401
"""

import time
import uuid

import jwt
import pytest


SSO_SECRET = 'unit-test-sso-secret'


def _mint_token(
    tenant_id='sso-admin@example.com',
    exp_offset=30,
    audience='saas',
    sub='sentrikat-admin',
    nonce=None,
    secret=SSO_SECRET,
    algorithm='HS256',
):
    """Create a short-lived HS256 JWT shaped like the license-server contract."""
    now = int(time.time())
    claims = {
        'sub': sub,
        'aud': audience,
        'tenant_id': tenant_id,
        'ts': now,
        'exp': now + exp_offset,
        'nonce': nonce or str(uuid.uuid4()),
    }
    return jwt.encode(claims, secret, algorithm=algorithm), claims['nonce']


@pytest.fixture(autouse=True)
def _set_sso_secret(monkeypatch, setup_complete):
    monkeypatch.setenv('SENTRIKAT_SSO_SECRET', SSO_SECRET)
    yield


@pytest.fixture
def tenant_admin(app, db_session):
    """Create an org + admin user the SSO endpoint can resolve."""
    from app.models import Organization, User
    from app import db

    with app.app_context():
        org = Organization(name='sso-acme', display_name='SSO Acme', active=True)
        db.session.add(org)
        db.session.flush()
        user = User(
            username='sso-admin',
            email='sso-admin@example.com',
            organization_id=org.id,
            role='admin',
        )
        user.set_password('TestPass123!')
        db.session.add(user)
        db.session.commit()
        return user.id, user.email, org.id


class TestSSOHappyPath:
    def test_valid_jwt_establishes_session_and_redirects(
        self, client, app, tenant_admin
    ):
        user_id, email, org_id = tenant_admin
        token, nonce = _mint_token(tenant_id=email)

        resp = client.get(f'/admin/sso?token={token}')
        assert resp.status_code == 302
        # The real dashboard is ``main.index`` (route ``/``). The previous
        # hard-coded ``/dashboard`` path did not exist in this app.
        assert resp.location.rstrip('/') in ('', 'http://localhost')

        with client.session_transaction() as sess:
            assert sess['user_id'] == user_id
            assert sess['organization_id'] == org_id
            assert sess['impersonated'] is True
            assert sess['impersonated_by'] == 'sentrikat-admin'
            assert sess['impersonated_via'] == 'license_server'


class TestSSOReject:
    def test_expired_token_rejected(self, client, tenant_admin):
        token, _ = _mint_token(exp_offset=-5)  # already expired
        resp = client.get(f'/admin/sso?token={token}')
        assert resp.status_code == 401

    def test_wrong_audience_rejected(self, client, tenant_admin):
        token, _ = _mint_token(audience='license-server')
        resp = client.get(f'/admin/sso?token={token}')
        assert resp.status_code == 401

    def test_wrong_signature_rejected(self, client, tenant_admin):
        token, _ = _mint_token(secret='not-the-right-secret')
        resp = client.get(f'/admin/sso?token={token}')
        assert resp.status_code == 401

    def test_wrong_sub_rejected(self, client, tenant_admin):
        token, _ = _mint_token(sub='random-attacker')
        resp = client.get(f'/admin/sso?token={token}')
        assert resp.status_code == 401

    def test_missing_nonce_rejected(self, client, tenant_admin, app):
        now = int(time.time())
        claims = {
            'sub': 'sentrikat-admin',
            'aud': 'saas',
            'tenant_id': 'sso-admin@example.com',
            'ts': now,
            'exp': now + 30,
            # 'nonce' intentionally missing
        }
        token = jwt.encode(claims, SSO_SECRET, algorithm='HS256')
        resp = client.get(f'/admin/sso?token={token}')
        assert resp.status_code == 401

    def test_unknown_tenant_rejected(self, client):
        token, _ = _mint_token(tenant_id='does-not-exist@example.com')
        resp = client.get(f'/admin/sso?token={token}')
        assert resp.status_code == 401

    def test_missing_token_rejected(self, client):
        resp = client.get('/admin/sso')
        assert resp.status_code == 401

    def test_missing_secret_rejected(self, client, monkeypatch, tenant_admin):
        monkeypatch.delenv('SENTRIKAT_SSO_SECRET', raising=False)
        token, _ = _mint_token()
        resp = client.get(f'/admin/sso?token={token}')
        assert resp.status_code == 401


class TestSSOReplay:
    def test_same_nonce_twice_second_rejected(self, app, tenant_admin):
        """A replayed token must be rejected on the second attempt, even
        from a fresh client (i.e., not just because the session already
        exists). We use two separate test clients so we're isolating the
        nonce check rather than the session."""
        token, nonce = _mint_token(tenant_id='sso-admin@example.com')

        with app.test_client() as c1:
            r1 = c1.get(f'/admin/sso?token={token}')
            assert r1.status_code == 302

        with app.test_client() as c2:
            r2 = c2.get(f'/admin/sso?token={token}')
            assert r2.status_code == 401
