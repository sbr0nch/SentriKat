"""Tests for the Sprint 6 super-admin observability pages."""

import json

import pytest


@pytest.fixture
def super_admin_user(app, db_session):
    """A user who can open the super-admin pages."""
    from app.models import Organization, User
    from app import db

    with app.app_context():
        org = Organization(name='obs-org', display_name='Obs Org', active=True)
        db.session.add(org)
        db.session.flush()
        user = User(
            username='obs-super',
            email='obs-super@example.com',
            organization_id=org.id,
            role='super_admin',
        )
        user.set_password('TestPass123!')
        db.session.add(user)
        db.session.commit()
        return user.id


@pytest.fixture
def normal_user(app, db_session):
    from app.models import Organization, User
    from app import db

    with app.app_context():
        org = Organization(name='obs-org-n', display_name='Obs Org N', active=True)
        db.session.add(org)
        db.session.flush()
        user = User(
            username='obs-user',
            email='obs-user@example.com',
            organization_id=org.id,
            role='user',
        )
        user.set_password('TestPass123!')
        db.session.add(user)
        db.session.commit()
        return user.id


class TestSuperAdminGating:
    def test_webhook_events_anonymous_403(self, client, setup_complete):
        resp = client.get('/super-admin/webhook-events')
        assert resp.status_code == 403

    def test_usage_uploads_anonymous_403(self, client, setup_complete):
        resp = client.get('/super-admin/usage-uploads')
        assert resp.status_code == 403

    def test_webhook_events_normal_user_403(self, client, setup_complete, normal_user):
        with client.session_transaction() as s:
            s['user_id'] = normal_user
        resp = client.get('/super-admin/webhook-events')
        assert resp.status_code == 403


class TestWebhookEventsPage:
    def test_renders_empty_state(self, client, setup_complete, super_admin_user):
        with client.session_transaction() as s:
            s['user_id'] = super_admin_user
        resp = client.get('/super-admin/webhook-events')
        assert resp.status_code == 200
        assert b'No webhook events received yet' in resp.data

    def test_renders_event_from_system_settings(self, client, app, super_admin_user):
        from app.models import SystemSettings
        from app import db

        with app.app_context():
            row = SystemSettings(
                key='webhook:idempotency:11111111-2222-3333-4444-555555555555',
                value=json.dumps({
                    'received': True,
                    'event_type': 'license.plan_changed',
                    'tenant_id': 'display-test@example.com',
                    'idempotency_key': '11111111-2222-3333-4444-555555555555',
                    'result': {'status': 'ok', 'action': 'plan_changed'},
                }),
                category='webhook',
            )
            db.session.add(row)
            db.session.commit()

        with client.session_transaction() as s:
            s['user_id'] = super_admin_user
        resp = client.get('/super-admin/webhook-events')
        assert resp.status_code == 200
        assert b'license.plan_changed' in resp.data
        assert b'display-test@example.com' in resp.data


class TestUsageUploadsPage:
    def test_renders_empty_state(self, client, setup_complete, super_admin_user):
        with client.session_transaction() as s:
            s['user_id'] = super_admin_user
        resp = client.get('/super-admin/usage-uploads')
        assert resp.status_code == 200
        assert b'No usage uploads have been performed yet' in resp.data

    def test_renders_summary_and_tenants(self, client, app, super_admin_user):
        from app.models import SystemSettings
        from app import db

        with app.app_context():
            summary = SystemSettings(
                key='usage_upload:last_run',
                value=json.dumps({
                    'ran_at': '2026-04-14 16:05:00 UTC',
                    'total': 2,
                    'ok': 2,
                    'failed': 0,
                    'endpoint': 'https://license.sentrikat.com/api/v1/metrics/usage',
                }),
                category='observability',
            )
            tenant_row = SystemSettings(
                key='usage_upload:tenant:display-tenant@example.com',
                value=json.dumps({
                    'tenant_id': 'display-tenant@example.com',
                    'success': True,
                    'status_code': 202,
                }),
                category='observability',
            )
            db.session.add_all([summary, tenant_row])
            db.session.commit()

        with client.session_transaction() as s:
            s['user_id'] = super_admin_user
        resp = client.get('/super-admin/usage-uploads')
        assert resp.status_code == 200
        assert b'display-tenant@example.com' in resp.data
        assert b'2026-04-14 16:05:00' in resp.data
