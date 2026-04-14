"""
Tests for the license-server webhook receiver (B3) — Sprint 6 contract.

Covers:
    * valid signature + timestamp + idempotency → 200
    * wrong signature → 401
    * timestamp skew outside ±300s → 400
    * missing headers → 400
    * idempotency: duplicate delivery returns the cached response body
    * all 5 event types: license.revoked, license.unsuspended,
      license.suspended, license.plan_changed, license.limits_updated
    * tenant_id is a string (email) or null
"""

import hmac
import hashlib
import json
import time
import uuid

import pytest


WEBHOOK_SECRET = 'unit-test-webhook-secret'


@pytest.fixture(autouse=True)
def _set_webhook_secret(monkeypatch, setup_complete, app):
    """Seed the webhook secret and ensure setup_complete so the app doesn't
    return 503 before our handler runs.

    Also tears down the license_revoked / license_suspended flags in
    SystemSettings after each test. The webhook handler writes these
    via ``_system_settings_set()`` and without the cleanup every
    subsequent test (in this file OR cross-file) would see the flags
    still set — which flips ``LicenseInfo.is_valid`` to False globally
    and regresses ``test_licensing.py``."""
    monkeypatch.setenv('SENTRIKAT_WEBHOOK_SECRET', WEBHOOK_SECRET)
    yield
    # Cleanup after each test: remove any license_revoked / license_suspended
    # flag our handlers may have written so the next test starts from a clean
    # slate.
    try:
        with app.app_context():
            from app.models import SystemSettings
            from app import db
            SystemSettings.query.filter(
                SystemSettings.key.in_(('license_revoked', 'license_suspended'))
            ).delete(synchronize_session=False)
            # Also drop idempotency cache so subsequent tests don't hit
            # cached replay responses.
            SystemSettings.query.filter(
                SystemSettings.key.like('webhook:idempotency:%')
            ).delete(synchronize_session=False)
            db.session.commit()
    except Exception:
        pass


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


def _revoked_body(tenant_email=None):
    """Minimal ``license.revoked`` envelope used by most header-focused tests."""
    return {
        'event_type': 'license.revoked',
        'tenant_id': tenant_email,
        'timestamp': '2026-04-14T15:29:27Z',
        'payload': {
            'license_id': 'lic_123',
            'license_key': 'XXXX-YYYY-ZZZZ',
            'edition': 'pro',
            'reason': 'manual_admin_revoke',
        },
    }


class TestSignature:
    def test_valid_signature_accepted(self, client, app):
        resp = _post(client, _revoked_body())
        assert resp.status_code == 200, resp.data
        data = resp.get_json()
        assert data['received'] is True
        assert data['event_type'] == 'license.revoked'

        # State side-effect: license_revoked flag flipped in SystemSettings.
        with app.app_context():
            from app.models import SystemSettings
            row = SystemSettings.query.filter_by(key='license_revoked').first()
            assert row is not None
            assert row.value == 'true'

    def test_invalid_signature_rejected(self, client):
        raw = json.dumps(_revoked_body()).encode('utf-8')
        headers = {
            'Content-Type': 'application/json',
            'X-SentriKat-Signature': 'deadbeef' * 8,
            'X-SentriKat-Timestamp': str(int(time.time())),
            'X-Idempotency-Key': str(uuid.uuid4()),
        }
        resp = client.post('/api/license/events', data=raw, headers=headers)
        assert resp.status_code == 401

    def test_wrong_secret_rejected(self, client):
        raw = json.dumps(_revoked_body()).encode('utf-8')
        headers = _headers(raw, secret='wrong-secret')
        resp = client.post('/api/license/events', data=raw, headers=headers)
        assert resp.status_code == 401


class TestTimestampSkew:
    def test_skew_too_old(self, client):
        raw = json.dumps(_revoked_body()).encode('utf-8')
        headers = _headers(raw, ts_offset=-600)  # 10 minutes in the past
        resp = client.post('/api/license/events', data=raw, headers=headers)
        assert resp.status_code == 400
        assert b'skew' in resp.data

    def test_skew_too_new(self, client):
        raw = json.dumps(_revoked_body()).encode('utf-8')
        headers = _headers(raw, ts_offset=600)  # 10 minutes in the future
        resp = client.post('/api/license/events', data=raw, headers=headers)
        assert resp.status_code == 400

    def test_missing_timestamp(self, client):
        raw = json.dumps(_revoked_body()).encode()
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
        body = _revoked_body()
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
        raw = json.dumps(_revoked_body()).encode()
        headers = {
            'Content-Type': 'application/json',
            'X-SentriKat-Signature': _sign(raw),
            'X-SentriKat-Timestamp': str(int(time.time())),
            # no X-Idempotency-Key
        }
        resp = client.post('/api/license/events', data=raw, headers=headers)
        assert resp.status_code == 400

    def test_non_uuid_idempotency_key_rejected(self, client):
        raw = json.dumps(_revoked_body()).encode()
        headers = {
            'Content-Type': 'application/json',
            'X-SentriKat-Signature': _sign(raw),
            'X-SentriKat-Timestamp': str(int(time.time())),
            'X-Idempotency-Key': 'not-a-uuid',
        }
        resp = client.post('/api/license/events', data=raw, headers=headers)
        assert resp.status_code == 400


class TestEventHandlers:
    def test_license_unsuspended_clears_flag(self, client, app):
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
            'event_type': 'license.unsuspended',
            'tenant_id': 'alice@example.com',
            'timestamp': '2026-04-14T15:29:27Z',
            'payload': {
                'license_id': 'lic_123',
                'license_key': 'XXXX-YYYY-ZZZZ',
                'reason': 'payment_received',
            },
        }
        resp = _post(client, body)
        assert resp.status_code == 200

        with app.app_context():
            from app.models import SystemSettings
            row = SystemSettings.query.filter_by(key='license_revoked').first()
            assert row.value == 'false'
            sus = SystemSettings.query.filter_by(key='license_suspended').first()
            assert sus is not None and sus.value == 'false'

    def test_license_suspended_sets_flags(self, client, app):
        body = {
            'event_type': 'license.suspended',
            'tenant_id': 'alice@example.com',
            'timestamp': '2026-04-14T15:29:27Z',
            'payload': {
                'license_id': 'lic_123',
                'license_key': 'XXXX-YYYY-ZZZZ',
                'stripe_subscription_id': 'sub_abc123',
                'reason': 'non_payment',
            },
        }
        resp = _post(client, body)
        assert resp.status_code == 200

        with app.app_context():
            from app.models import SystemSettings
            revoked = SystemSettings.query.filter_by(key='license_revoked').first()
            suspended = SystemSettings.query.filter_by(key='license_suspended').first()
            assert revoked is not None and revoked.value == 'true'
            assert suspended is not None and suspended.value == 'true'

    def test_plan_changed_repoints_subscription_plan_id(self, client, app, db_session):
        """``license.plan_changed`` re-points ``Subscription.plan_id`` to the
        canonical plan row matching ``to_edition``. We must NOT rename the
        existing plan row — canonical plans are shared across tenants."""
        from app.models import Organization, SubscriptionPlan, Subscription, User
        from app import db

        org = Organization(name='acme-plan', display_name='Acme Plan', active=True)
        db.session.add(org)
        db.session.flush()

        admin = User(
            username='plan-admin',
            email='plan-admin@example.com',
            organization_id=org.id,
        )
        admin.set_password('TestPass123!')
        db.session.add(admin)

        starter = SubscriptionPlan.query.filter_by(name='starter').first()
        pro = SubscriptionPlan.query.filter_by(name='pro').first()
        assert starter is not None and pro is not None, \
            "starter + pro plans should be seeded at app boot"
        starter_id = starter.id
        pro_id = pro.id
        assert starter_id != pro_id

        sub = Subscription(
            organization_id=org.id,
            plan_id=starter_id,
            status='active',
        )
        db.session.add(sub)
        db.session.commit()
        sub_id = sub.id

        body = {
            'event_type': 'license.plan_changed',
            'tenant_id': 'plan-admin@example.com',
            'timestamp': '2026-04-14T15:29:27Z',
            'payload': {
                'license_id': 'lic_plan_1',
                'license_key': 'AAAA-BBBB-CCCC',
                'from_edition': 'starter',
                'from_status': 'active',
                'to_edition': 'pro',
                'to_status': 'active',
                'max_agents': 25,
                'subscription_years': 1,
                'reason': 'upgrade',
            },
        }
        resp = _post(client, body)
        assert resp.status_code == 200, resp.data
        data = resp.get_json()
        assert data['result']['status'] == 'ok', data['result']
        assert data['result']['action'] == 'plan_changed'

        # Both canonical plans must still exist unchanged.
        db.session.expire_all()
        assert db.session.get(SubscriptionPlan, starter_id).name == 'starter'
        assert db.session.get(SubscriptionPlan, pro_id).name == 'pro'

        # The subscription now points at the pro plan.
        updated_sub = db.session.get(Subscription, sub_id)
        assert updated_sub.plan_id == pro_id

    def test_plan_changed_unknown_edition_rejected(self, client, app, db_session):
        """Unknown plan name → 200 with error result (upstream retry policy
        handles this as a dead letter)."""
        from app.models import Organization, SubscriptionPlan, Subscription, User
        from app import db

        org = Organization(name='acme-unk', display_name='Acme Unk', active=True)
        db.session.add(org)
        db.session.flush()
        admin = User(
            username='unk-admin',
            email='unk-admin@example.com',
            organization_id=org.id,
        )
        admin.set_password('TestPass123!')
        db.session.add(admin)
        starter = SubscriptionPlan.query.filter_by(name='starter').first()
        sub = Subscription(
            organization_id=org.id, plan_id=starter.id, status='active',
        )
        db.session.add(sub)
        db.session.commit()

        body = {
            'event_type': 'license.plan_changed',
            'tenant_id': 'unk-admin@example.com',
            'timestamp': '2026-04-14T15:29:27Z',
            'payload': {
                'license_id': 'x', 'license_key': 'y',
                'from_edition': 'starter', 'from_status': 'active',
                'to_edition': 'premium_gold',  # not canonical
                'to_status': 'active',
                'subscription_years': 1, 'reason': 'bogus',
            },
        }
        resp = _post(client, body)
        assert resp.status_code == 200
        data = resp.get_json()
        assert data['result']['status'] == 'error'
        assert 'invalid to_edition' in data['result']['error']

    def test_limits_updated_reads_nested_limits(self, client, app, db_session):
        """``license.limits_updated`` must read from ``payload.limits`` and
        NOT from flat fields (Sprint 6 contract change)."""
        from app.models import Organization, SubscriptionPlan, Subscription, User
        from app import db

        org = Organization(name='acme-lim', display_name='Acme Lim', active=True)
        db.session.add(org)
        db.session.flush()

        admin = User(
            username='lim-admin',
            email='lim-admin@example.com',
            organization_id=org.id,
        )
        admin.set_password('TestPass123!')
        db.session.add(admin)

        plan = SubscriptionPlan.query.filter_by(name='business').first()
        assert plan is not None
        plan.max_agents = 10
        plan.max_users = 5
        plan.max_products = 100
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
            'event_type': 'license.limits_updated',
            'tenant_id': 'lim-admin@example.com',
            'timestamp': '2026-04-14T15:29:27Z',
            'payload': {
                'license_id': 'lic_lim_1',
                'license_key': 'AAAA-BBBB-CCCC',
                'limits': {
                    'max_users': 50,
                    'max_products': 500,
                    'max_agents': 100,
                    'max_organizations': 3,
                    'max_storage_gb': 10,
                    'features': ['nis2', 'sbom_export'],
                },
                'changed': {
                    'max_agents': {'from': 10, 'to': 100},
                },
                'reason': 'agent_pack_purchased',
            },
        }
        resp = _post(client, body)
        assert resp.status_code == 200, resp.data
        data = resp.get_json()
        assert data['result']['action'] == 'limits_updated'

        db.session.expire_all()
        updated = db.session.get(SubscriptionPlan, plan_id)
        assert updated.max_agents == 100
        assert updated.max_users == 50
        assert updated.max_products == 500
        if hasattr(updated, 'max_storage_mb'):
            assert updated.max_storage_mb == 10 * 1024
        if hasattr(updated, 'features'):
            assert 'nis2' in (updated.features or '')

    def test_limits_updated_flat_payload_rejected_silently(self, client, app, db_session):
        """Backward-compat safety net: flat max_agents (no ``limits`` wrap)
        must not mutate the plan. The handler logs no changes and returns a
        successful skip so the upstream retry loop is not triggered."""
        from app.models import Organization, SubscriptionPlan, Subscription, User
        from app import db

        org = Organization(name='acme-flat', display_name='Acme Flat', active=True)
        db.session.add(org)
        db.session.flush()
        admin = User(
            username='flat-admin',
            email='flat-admin@example.com',
            organization_id=org.id,
        )
        admin.set_password('TestPass123!')
        db.session.add(admin)

        plan = SubscriptionPlan.query.filter_by(name='enterprise').first()
        assert plan is not None
        original_agents = plan.max_agents
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
            'event_type': 'license.limits_updated',
            'tenant_id': 'flat-admin@example.com',
            'timestamp': '2026-04-14T15:29:27Z',
            'payload': {
                # Wrong shape: flat fields instead of nested 'limits'.
                'max_agents': 999,
            },
        }
        resp = _post(client, body)
        # We accept the request (HTTP 200) but make no changes.
        assert resp.status_code == 200

        db.session.expire_all()
        updated = db.session.get(SubscriptionPlan, plan_id)
        assert updated.max_agents == original_agents

    def test_unknown_event_type_rejected(self, client):
        body = {
            'event_type': 'coffee_brewed',
            'tenant_id': None,
            'timestamp': '2026-04-14T15:29:27Z',
            'payload': {},
        }
        resp = _post(client, body)
        assert resp.status_code == 400
        data = resp.get_json()
        # Error response lists the allowed set, which now uses the
        # ``license.*`` naming convention.
        assert 'license.revoked' in data['allowed']

    def test_legacy_event_type_rejected(self, client):
        """The old ``license_revoked`` name (pre-Sprint 6) is no longer
        accepted — a clean break, no silent backward-compat."""
        body = {
            'event_type': 'license_revoked',
            'tenant_id': None,
            'timestamp': '2026-04-14T15:29:27Z',
            'payload': {},
        }
        resp = _post(client, body)
        assert resp.status_code == 400

    def test_numeric_tenant_id_rejected(self, client):
        """``tenant_id`` must be a string (email) under Sprint 6 contract."""
        body = {
            'event_type': 'license.revoked',
            'tenant_id': 42,
            'timestamp': '2026-04-14T15:29:27Z',
            'payload': {'license_id': 'x', 'license_key': 'y', 'edition': 'pro', 'reason': 'x'},
        }
        resp = _post(client, body)
        assert resp.status_code == 400
