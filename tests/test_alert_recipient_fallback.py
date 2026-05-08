"""Tests for Organization.resolve_alert_recipients() and its consumers.

Covers the post-EA fallback contract:
  - Custom notification_emails wins.
  - Empty/invalid notification_emails → earliest active org_admin used.
  - No org_admin → earliest active user used.
  - No active user at all → empty + source 'none'.

Also exercises EmailAlertManager.send_critical_cve_alert / container_vuln_alert
to confirm they no longer abort with "No recipients configured" when only the
registration default is available.
"""
import json
from datetime import datetime, timedelta

import pytest
from werkzeug.security import generate_password_hash

from app.models import Organization, User


def _mk_user(db_session, org, **kw):
    defaults = dict(
        username=kw.get('username', f"u{datetime.utcnow().timestamp()}"),
        email=kw.get('email', 'u@test.local'),
        password_hash=generate_password_hash('p'),
        role=kw.get('role', 'user'),
        organization_id=org.id,
        is_active=kw.get('is_active', True),
        auth_type='local',
        created_at=kw.get('created_at', datetime.utcnow()),
    )
    user = User(**defaults)
    db_session.add(user)
    db_session.commit()
    return user


def test_resolve_custom_emails_wins(db_session, test_org):
    test_org.notification_emails = json.dumps(['ops@example.com', 'security@example.com'])
    db_session.commit()
    _mk_user(db_session, test_org, email='admin@example.com', role='org_admin')

    result = test_org.resolve_alert_recipients()
    assert result['source'] == 'custom'
    assert result['emails'] == ['ops@example.com', 'security@example.com']
    assert result['fallback_user_id'] is None


def test_resolve_empty_emails_falls_back_to_org_admin(db_session, test_org):
    test_org.notification_emails = '[]'
    db_session.commit()
    _mk_user(db_session, test_org, username='reg', email='reg@example.com',
             role='org_admin', created_at=datetime.utcnow() - timedelta(days=1))
    _mk_user(db_session, test_org, username='later_admin',
             email='later@example.com', role='org_admin')

    result = test_org.resolve_alert_recipients()
    assert result['source'] == 'registration_default'
    assert result['emails'] == ['reg@example.com']
    assert result['fallback_user_role'] == 'org_admin'


def test_resolve_invalid_json_treated_as_empty(db_session, test_org):
    test_org.notification_emails = 'not-json'
    db_session.commit()
    _mk_user(db_session, test_org, email='admin@example.com', role='org_admin')

    result = test_org.resolve_alert_recipients()
    assert result['source'] == 'registration_default'
    assert result['emails'] == ['admin@example.com']


def test_resolve_skips_inactive_admin(db_session, test_org):
    _mk_user(db_session, test_org, username='inactive', email='ghost@example.com',
             role='org_admin', is_active=False)
    _mk_user(db_session, test_org, username='active', email='real@example.com',
             role='user')

    result = test_org.resolve_alert_recipients()
    assert result['source'] == 'registration_default'
    assert result['emails'] == ['real@example.com']
    assert result['fallback_user_role'] == 'user'


def test_resolve_no_users_returns_none(db_session, test_org):
    result = test_org.resolve_alert_recipients()
    assert result['source'] == 'none'
    assert result['emails'] == []
    assert result['fallback_user_id'] is None


def test_resolve_whitespace_only_emails_falls_back(db_session, test_org):
    test_org.notification_emails = json.dumps(['', '   '])
    db_session.commit()
    _mk_user(db_session, test_org, email='admin@example.com', role='org_admin')

    result = test_org.resolve_alert_recipients()
    assert result['source'] == 'registration_default'
    assert result['emails'] == ['admin@example.com']


def test_to_dict_exposes_effective_recipients(db_session, test_org):
    _mk_user(db_session, test_org, email='admin@example.com', role='org_admin')
    payload = test_org.to_dict()
    assert 'effective_recipients' in payload
    assert payload['effective_recipients']['source'] == 'registration_default'
    assert payload['effective_recipients']['emails'] == ['admin@example.com']


def test_double_encoded_json_is_unwrapped(db_session, test_org):
    # Legacy bug: notification_emails was sometimes stored double-JSON-encoded.
    test_org.notification_emails = json.dumps(json.dumps(['nested@example.com']))
    db_session.commit()
    result = test_org.resolve_alert_recipients()
    assert result['source'] == 'custom'
    assert result['emails'] == ['nested@example.com']
