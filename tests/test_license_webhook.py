"""
Tests for the license-server webhook receiver (B3).

Covers:
    * valid signature → 200 and state change persisted
    * wrong signature → 401
    * timestamp skew outside ±300s → 400
    * missing headers → 400
    * idempotency: duplicate delivery returns the cached response body
    * plan_updated: SubscriptionPlan row is mutated
"""

import hmac
import hashlib
import json
import time
import uuid

import pytest


WEBHOOK_SECRET = 'unit-test-webhook-secret'


@pytest.fixture(autouse=True)
def _set_webhook_secret(monkeypatch, setup_complete):
    """Seed the webhook secret and ensure setup_complete so the app doesn't
    return 503 before our handler runs."""
    monkeypatch.setenv('SENTRIKAT_WEBHOOK_SECRET', WEBHOOK_SECRET)
    yield


def _sign(body: bytes, secret: str = WEBHOOK_SECRET) -> str:
    return hmac.new(secret.encode(), body, hashlib.sha256).hexdigest()


def _headers(body: bytes, ts_offset: int = 0, idem: str | None = None, secret=WEBHOOK_SECRET):
    return {
        'Content-Type': 'application/json',
        'X-SentriKat-Signature': _sign(body, secret),
        'X-SentriKat-Timestamp': str(int(time.time()) + ts_offset),
        'X-Idempotency-Key': idem or str(uuid.uuid4()),
    }


def _post(client, body: dict, headers_override=None, raw_headers=None):
    raw = json.dumps(body).encode('utf-8')
    headers = raw_headers if raw_headers is not None else _headers(raw)
    if headers_override:
        headers.update(headers_override)
    return client.post(
        '/api/license/events',
        data=raw,
        headers=headers,
    )


class TestSignature:
    def test_valid_signature_accepted(self, client, app):
        body = {
            'event_type': 'license_revoked',
            'tenant_id': None,
            'timestamp': int(time.time()),
            'payload': {},
        }
        resp = _post(client, body)
        assert resp.status_code == 200, resp.data
        data = resp.get_json()
        assert data['received'] is True
        assert data['event_type'] == 'license_revoked'

        # State side-effect: license_revoked flag flipped in SystemSettings.
        with app.app_context():
            from app.models import SystemSettings
            row = SystemSettings.query.filter_by(key='license_revoked').first()
            assert row is not None
            assert row.value == 'true'

    def test_invalid_signature_rejected(self, client):
        raw = json.dumps({
            'event_type': 'license_revoked',
            'tenant_id': None,
            'timestamp': int(time.time()),
            'payload': {},
        }).encode('utf-8')
        headers = {
            'Content-Type': 'application/json',
            'X-SentriKat-Signature': 'deadbeef' * 8,
            'X-SentriKat-Timestamp': str(int(time.time())),
            'X-Idempotency-Key': str(uuid.uuid4()),
        }
        resp = client.post('/api/license/events', data=raw, headers=headers)
        assert resp.status_code == 401

    def test_wrong_secret_rejected(self, client):
        raw = json.dumps({
            'event_type': 'license_revoked',
            'tenant_id': None,
            'timestamp': int(time.time()),
            'payload': {},
        }).encode('utf-8')
        headers = _headers(raw, secret='wrong-secret')
        resp = client.post('/api/license/events', data=raw, headers=headers)
        assert resp.status_code == 401


class TestTimestampSkew:
    def test_skew_too_old(self, client):
        raw = json.dumps({
            'event_type': 'license_revoked',
            'tenant_id': None,
            'timestamp': int(time.time()),
            'payload': {},
        }).encode('utf-8')
        headers = _headers(raw, ts_offset=-600)  # 10 minutes in the past
        resp = client.post('/api/license/events', data=raw, headers=headers)
        assert resp.status_code == 400
        assert b'skew' in resp.data

    def test_skew_too_new(self, client):
        raw = json.dumps({
            'event_type': 'license_revoked',
            'tenant_id': None,
            'timestamp': int(time.time()),
            'payload': {},
        }).encode('utf-8')
        headers = _headers(raw, ts_offset=600)  # 10 minutes in the future
        resp = client.post('/api/license/events', data=raw, headers=headers)
        assert resp.status_code == 400

    def test_missing_timestamp(self, client):
        raw = json.dumps({'event_type': 'license_revoked', 'payload': {}}).encode()
        headers = {
            'Content-Type': 'application/json',
            'X-SentriKat-Signature': _sign(raw),
            'X-Idempotency-Key': str(uuid.uuid4()),
        }
        resp = client.post('/api/license/events', data=raw, headers=headers)
        assert resp.status_code == 400


class TestIdempotency:
    def test_duplicate_delivery_returns_cached(self, client, app):
        idem = str(uuid.uuid4())
        body = {
            'event_type': 'license_revoked',
            'tenant_id': None,
            'timestamp': int(time.time()),
            'payload': {},
        }
        raw = json.dumps(body).encode()
        headers = _headers(raw, idem=idem)

        resp1 = client.post('/api/license/events', data=raw, headers=headers)
        assert resp1.status_code == 200
        first = resp1.get_json()

        # Send again with the SAME idempotency key but a different signed body.
        body2 = dict(body)
        body2['payload'] = {'different': True}
        raw2 = json.dumps(body2).encode()
        headers2 = _headers(raw2, idem=idem)
        resp2 = client.post('/api/license/events', data=raw2, headers=headers2)
        assert resp2.status_code == 200
        second = resp2.get_json()

        # Response should be the cached one from the first call.
        assert second == first
        assert second['idempotency_key'] == idem

    def test_missing_idempotency_key_rejected(self, client):
        raw = json.dumps({
            'event_type': 'license_revoked',
            'timestamp': int(time.time()),
            'payload': {},
        }).encode()
        headers = {
            'Content-Type': 'application/json',
            'X-SentriKat-Signature': _sign(raw),
            'X-SentriKat-Timestamp': str(int(time.time())),
            # no X-Idempotency-Key
        }
        resp = client.post('/api/license/events', data=raw, headers=headers)
        assert resp.status_code == 400

    def test_non_uuid_idempotency_key_rejected(self, client):
        raw = json.dumps({
            'event_type': 'license_revoked',
            'timestamp': int(time.time()),
            'payload': {},
        }).encode()
        headers = {
            'Content-Type': 'application/json',
            'X-SentriKat-Signature': _sign(raw),
            'X-SentriKat-Timestamp': str(int(time.time())),
            'X-Idempotency-Key': 'not-a-uuid',
        }
        resp = client.post('/api/license/events', data=raw, headers=headers)
        assert resp.status_code == 400


class TestEventHandlers:
    def test_license_restored_clears_flag(self, client, app):
        # Seed the revocation flag.
        with app.app_context():
            from app.models import SystemSettings
            from app import db
            row = SystemSettings(
                key='license_revoked', value='true', category='licensing'
            )
            db.session.add(row)
            db.session.commit()

        body = {
            'event_type': 'license_restored',
            'tenant_id': None,
            'timestamp': int(time.time()),
            'payload': {},
        }
        resp = _post(client, body)
        assert resp.status_code == 200

        with app.app_context():
            from app.models import SystemSettings
            row = SystemSettings.query.filter_by(key='license_revoked').first()
            assert row.value == 'false'

    def test_plan_updated_persists_new_limits(self, client, app, db_session):
        # Arrange: create an org, a plan and a subscription.
        from app.models import Organization, SubscriptionPlan, Subscription
        from app import db

        org = Organization(name='acme', display_name='Acme', active=True)
        db.session.add(org)
        db.session.flush()

        # Re-use an existing seeded plan if present, otherwise create one
        # with a unique name to avoid the UNIQUE constraint on
        # subscription_plans.name (startup seeding may have inserted the
        # canonical plans already).
        plan = SubscriptionPlan.query.filter_by(name='starter').first()
        if plan is None:
            plan = SubscriptionPlan(
                name='webhook_test_plan',
                display_name='Webhook Test',
                max_agents=5,
                max_users=3,
                max_products=50,
            )
            db.session.add(plan)
        else:
            plan.max_agents = 5
            plan.max_users = 3
            plan.max_products = 50
        db.session.flush()

        sub = Subscription(
            organization_id=org.id,
            plan_id=plan.id,
            status='active',
        )
        db.session.add(sub)
        db.session.commit()

        plan_id = plan.id

        body = {
            'event_type': 'plan_updated',
            'tenant_id': org.id,
            'timestamp': int(time.time()),
            'payload': {
                # Don't rename the plan in this test — plan names have a
                # UNIQUE constraint and the app may seed the canonical
                # names at boot, which would make a rename flaky.
                'max_agents': 100,
                'max_users': 50,
                'max_products': 500,
                'max_storage_gb': 10,
                'features': {'sso': True, 'api_access': True},
            },
        }
        resp = _post(client, body)
        assert resp.status_code == 200, resp.data

        # Re-query for verification.
        db.session.expire_all()
        updated = SubscriptionPlan.query.get(plan_id)
        assert updated.max_agents == 100
        assert updated.max_users == 50
        assert updated.max_products == 500
        assert updated.max_storage_mb == 10 * 1024
        # features stored as JSON string
        assert 'sso' in (updated.features or '')

    def test_unknown_event_type_rejected(self, client):
        body = {
            'event_type': 'coffee_brewed',
            'tenant_id': None,
            'timestamp': int(time.time()),
            'payload': {},
        }
        resp = _post(client, body)
        assert resp.status_code == 400
