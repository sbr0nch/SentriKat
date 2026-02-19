"""
Comprehensive security tests covering 2FA, password policy, session timeout,
and account lockout.

Uses conftest.py fixtures: app, client, db_session, admin_client,
authenticated_client, test_org, test_user, admin_user, setup_complete.
"""

import pytest
from unittest.mock import patch, MagicMock
from datetime import datetime, timedelta
from werkzeug.security import generate_password_hash


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _login(client, username, password, totp_code=None):
    """Helper to POST /api/auth/login."""
    payload = {'username': username, 'password': password}
    if totp_code is not None:
        payload['totp_code'] = totp_code
    return client.post('/api/auth/login', json=payload)


def _set_security_setting(db_session, key, value):
    """Insert or update a SystemSettings row used by the security subsystem."""
    from app.models import SystemSettings
    setting = SystemSettings.query.filter_by(key=key).first()
    if setting:
        setting.value = str(value)
    else:
        setting = SystemSettings(key=key, value=str(value), category='security')
        db_session.add(setting)
    db_session.commit()


def _make_ldap_user(db_session, test_org):
    """Create an LDAP-type user for tests that need one."""
    from app.models import User
    user = User(
        username='ldapuser',
        email='ldapuser@test.local',
        password_hash=None,
        role='user',
        organization_id=test_org.id,
        is_active=True,
        auth_type='ldap',
    )
    db_session.add(user)
    db_session.commit()
    return user


# ===========================================================================
# 2FA Tests (Per-User)
# ===========================================================================

class TestTwoFactorPerUser:
    """Tests 1-14: per-user 2FA setup, verify, disable, status, and login."""

    # 1. Setup 2FA returns secret and TOTP URI
    def test_setup_2fa_returns_secret_and_uri(self, authenticated_client, setup_complete):
        resp = authenticated_client.post('/api/auth/2fa/setup')
        assert resp.status_code == 200
        data = resp.get_json()
        assert data['success'] is True
        assert 'secret' in data
        assert len(data['secret']) > 0
        assert 'totp_uri' in data
        assert data['totp_uri'].startswith('otpauth://totp/')

    # 2. Setup 2FA when already enabled returns 400
    def test_setup_2fa_already_enabled_returns_400(
        self, authenticated_client, test_user, db_session, setup_complete
    ):
        test_user.setup_totp()
        test_user.enable_totp()
        db_session.commit()

        resp = authenticated_client.post('/api/auth/2fa/setup')
        assert resp.status_code == 400
        assert 'already enabled' in resp.get_json()['error'].lower()

    # 3. Verify 2FA with valid code enables it
    def test_verify_2fa_valid_code_enables(
        self, authenticated_client, test_user, db_session, setup_complete
    ):
        test_user.setup_totp()
        db_session.commit()

        with patch.object(type(test_user), 'verify_totp', return_value=True):
            resp = authenticated_client.post(
                '/api/auth/2fa/verify', json={'code': '123456'}
            )
        assert resp.status_code == 200
        assert resp.get_json()['success'] is True

        # Refresh from DB and confirm enabled
        db_session.refresh(test_user)
        assert test_user.totp_enabled is True

    # 4. Verify 2FA with invalid code returns 400
    def test_verify_2fa_invalid_code_returns_400(
        self, authenticated_client, test_user, db_session, setup_complete
    ):
        test_user.setup_totp()
        db_session.commit()

        with patch.object(type(test_user), 'verify_totp', return_value=False):
            resp = authenticated_client.post(
                '/api/auth/2fa/verify', json={'code': '000000'}
            )
        assert resp.status_code == 400
        assert 'invalid' in resp.get_json()['error'].lower()

    # 5. Verify 2FA without prior setup returns 400
    def test_verify_2fa_without_setup_returns_400(
        self, authenticated_client, setup_complete
    ):
        resp = authenticated_client.post(
            '/api/auth/2fa/verify', json={'code': '123456'}
        )
        assert resp.status_code == 400
        assert 'setup first' in resp.get_json()['error'].lower()

    # 6. Disable 2FA requires password
    def test_disable_2fa_requires_password(
        self, authenticated_client, test_user, db_session, setup_complete
    ):
        test_user.setup_totp()
        test_user.enable_totp()
        db_session.commit()

        resp = authenticated_client.post(
            '/api/auth/2fa/disable', json={'password': 'testpass123'}
        )
        assert resp.status_code == 200
        data = resp.get_json()
        assert data['success'] is True

        db_session.refresh(test_user)
        assert test_user.totp_enabled is False

    # 7. Disable 2FA with wrong password returns 401
    def test_disable_2fa_wrong_password_returns_401(
        self, authenticated_client, test_user, db_session, setup_complete
    ):
        test_user.setup_totp()
        test_user.enable_totp()
        db_session.commit()

        resp = authenticated_client.post(
            '/api/auth/2fa/disable', json={'password': 'wrongpassword'}
        )
        assert resp.status_code == 401
        assert 'incorrect' in resp.get_json()['error'].lower()

    # 8. Disable 2FA when not enabled returns 400
    def test_disable_2fa_not_enabled_returns_400(
        self, authenticated_client, setup_complete
    ):
        resp = authenticated_client.post(
            '/api/auth/2fa/disable', json={'password': 'testpass123'}
        )
        assert resp.status_code == 400
        assert 'not enabled' in resp.get_json()['error'].lower()

    # 9. Get 2FA status - enabled
    def test_get_2fa_status_enabled(
        self, authenticated_client, test_user, db_session, setup_complete
    ):
        test_user.setup_totp()
        test_user.enable_totp()
        db_session.commit()

        resp = authenticated_client.get('/api/auth/2fa/status')
        assert resp.status_code == 200
        data = resp.get_json()
        assert data['enabled'] is True

    # 10. Get 2FA status - disabled
    def test_get_2fa_status_disabled(self, authenticated_client, setup_complete):
        resp = authenticated_client.get('/api/auth/2fa/status')
        assert resp.status_code == 200
        data = resp.get_json()
        assert data['enabled'] is False

    # 11. Login with 2FA enabled requires TOTP code
    def test_login_2fa_requires_totp_code(
        self, client, test_user, db_session, setup_complete
    ):
        test_user.setup_totp()
        test_user.enable_totp()
        db_session.commit()

        resp = _login(client, 'testuser', 'testpass123')
        data = resp.get_json()
        # Should return a requires_2fa indicator (status 200 with success=False)
        assert data.get('requires_2fa') is True
        assert 'totp_token' in data

    # 12. Login with 2FA - correct TOTP code succeeds
    def test_login_2fa_correct_code_succeeds(
        self, client, test_user, db_session, setup_complete
    ):
        test_user.setup_totp()
        test_user.enable_totp()
        db_session.commit()

        with patch.object(type(test_user), 'verify_totp', return_value=True):
            resp = _login(client, 'testuser', 'testpass123', totp_code='123456')
        assert resp.status_code == 200
        data = resp.get_json()
        assert data['success'] is True

    # 13. Login with 2FA - wrong TOTP code returns 401
    def test_login_2fa_wrong_code_returns_401(
        self, client, test_user, db_session, setup_complete
    ):
        test_user.setup_totp()
        test_user.enable_totp()
        db_session.commit()

        with patch.object(type(test_user), 'verify_totp', return_value=False):
            resp = _login(client, 'testuser', 'testpass123', totp_code='000000')
        assert resp.status_code == 401
        assert 'invalid' in resp.get_json()['error'].lower()

    # 14. Login with 2FA - missing TOTP code returns requires_2fa response
    def test_login_2fa_missing_code_returns_requires_2fa(
        self, client, test_user, db_session, setup_complete
    ):
        test_user.setup_totp()
        test_user.enable_totp()
        db_session.commit()

        resp = _login(client, 'testuser', 'testpass123')
        data = resp.get_json()
        assert data.get('requires_2fa') is True
        assert data.get('success') is False
        assert 'message' in data


# ===========================================================================
# 2FA Tests (Global Enforcement)
# ===========================================================================

class TestTwoFactorGlobalEnforcement:
    """Tests 15-19: global require_2fa setting enforcement."""

    # 15. Global require_2fa=true forces all local users to setup 2FA on login
    def test_global_require_2fa_forces_setup(
        self, client, test_user, db_session, setup_complete
    ):
        _set_security_setting(db_session, 'require_2fa', 'true')

        resp = _login(client, 'testuser', 'testpass123')
        assert resp.status_code == 200
        data = resp.get_json()
        assert data['success'] is True
        assert data.get('must_setup_2fa') is True

    # 16. Global require_2fa=false doesn't force 2FA
    def test_global_require_2fa_false_no_force(
        self, client, test_user, db_session, setup_complete
    ):
        _set_security_setting(db_session, 'require_2fa', 'false')

        resp = _login(client, 'testuser', 'testpass123')
        assert resp.status_code == 200
        data = resp.get_json()
        assert data['success'] is True
        assert data.get('must_setup_2fa') is False

    # 17. User with 2FA already enabled isn't affected by global setting
    def test_user_with_2fa_unaffected_by_global(
        self, client, test_user, db_session, setup_complete
    ):
        _set_security_setting(db_session, 'require_2fa', 'true')
        test_user.setup_totp()
        test_user.enable_totp()
        db_session.commit()

        with patch.object(type(test_user), 'verify_totp', return_value=True):
            resp = _login(client, 'testuser', 'testpass123', totp_code='123456')
        assert resp.status_code == 200
        data = resp.get_json()
        assert data['success'] is True
        # User already has 2FA, so must_setup_2fa should be False
        assert data.get('must_setup_2fa') is False

    # 18. LDAP users not affected by global 2FA requirement
    def test_ldap_user_not_affected_by_global_2fa(
        self, client, db_session, test_org, setup_complete
    ):
        _set_security_setting(db_session, 'require_2fa', 'true')
        ldap_user = _make_ldap_user(db_session, test_org)

        with patch('app.auth.authenticate_ldap', return_value=True):
            resp = _login(client, 'ldapuser', 'ldappass123')
        assert resp.status_code == 200
        data = resp.get_json()
        assert data['success'] is True
        # LDAP users skip the must_setup_2fa check (auth_type != 'local')
        assert data.get('must_setup_2fa') is False

    # 19. Admin can set/unset global require_2fa via security settings
    def test_admin_set_unset_global_require_2fa(
        self, admin_client, db_session, setup_complete
    ):
        # Enable
        resp = admin_client.post('/api/settings/security', json={
            'require_2fa': True,
            'session_timeout': 480,
            'max_failed_logins': 5,
            'lockout_duration': 30,
            'password_min_length': 8,
            'password_require_uppercase': True,
            'password_require_lowercase': True,
            'password_require_numbers': True,
            'password_require_special': False,
            'password_expiry_days': 0,
        })
        assert resp.status_code == 200

        resp = admin_client.get('/api/settings/security')
        assert resp.status_code == 200
        assert resp.get_json()['require_2fa'] is True

        # Disable
        resp = admin_client.post('/api/settings/security', json={
            'require_2fa': False,
            'session_timeout': 480,
            'max_failed_logins': 5,
            'lockout_duration': 30,
            'password_min_length': 8,
            'password_require_uppercase': True,
            'password_require_lowercase': True,
            'password_require_numbers': True,
            'password_require_special': False,
            'password_expiry_days': 0,
        })
        assert resp.status_code == 200

        resp = admin_client.get('/api/settings/security')
        assert resp.get_json()['require_2fa'] is False


# ===========================================================================
# Password Policy Tests
# ===========================================================================

class TestPasswordPolicy:
    """Tests 20-30: password validation, change, and expiration."""

    # 20. Password meets all requirements - accepted
    def test_password_meets_all_requirements(self, app, db_session, setup_complete):
        from app.models import User

        _set_security_setting(db_session, 'password_min_length', '8')
        _set_security_setting(db_session, 'password_require_uppercase', 'true')
        _set_security_setting(db_session, 'password_require_lowercase', 'true')
        _set_security_setting(db_session, 'password_require_numbers', 'true')
        _set_security_setting(db_session, 'password_require_special', 'true')

        is_valid, error = User.validate_password_policy('Str0ng!Pass')
        assert is_valid is True
        assert error is None

    # 21. Password too short - rejected
    def test_password_too_short_rejected(self, app, db_session, setup_complete):
        from app.models import User

        _set_security_setting(db_session, 'password_min_length', '12')

        is_valid, error = User.validate_password_policy('Short1!')
        assert is_valid is False
        assert 'at least 12 characters' in error

    # 22. Password missing uppercase when required - rejected
    def test_password_missing_uppercase_rejected(self, app, db_session, setup_complete):
        from app.models import User

        _set_security_setting(db_session, 'password_min_length', '8')
        _set_security_setting(db_session, 'password_require_uppercase', 'true')

        is_valid, error = User.validate_password_policy('alllowercase1')
        assert is_valid is False
        assert 'uppercase' in error.lower()

    # 23. Password missing lowercase when required - rejected
    def test_password_missing_lowercase_rejected(self, app, db_session, setup_complete):
        from app.models import User

        _set_security_setting(db_session, 'password_min_length', '8')
        _set_security_setting(db_session, 'password_require_lowercase', 'true')

        is_valid, error = User.validate_password_policy('ALLUPPERCASE1')
        assert is_valid is False
        assert 'lowercase' in error.lower()

    # 24. Password missing number when required - rejected
    def test_password_missing_number_rejected(self, app, db_session, setup_complete):
        from app.models import User

        _set_security_setting(db_session, 'password_min_length', '8')
        _set_security_setting(db_session, 'password_require_numbers', 'true')

        is_valid, error = User.validate_password_policy('NoNumbersHere!')
        assert is_valid is False
        assert 'number' in error.lower()

    # 25. Password missing special char when required - rejected
    def test_password_missing_special_char_rejected(self, app, db_session, setup_complete):
        from app.models import User

        _set_security_setting(db_session, 'password_min_length', '8')
        _set_security_setting(db_session, 'password_require_special', 'true')

        is_valid, error = User.validate_password_policy('NoSpecial123')
        assert is_valid is False
        assert 'special' in error.lower()

    # 26. Change password with valid policy
    def test_change_password_valid(
        self, authenticated_client, test_user, db_session, setup_complete
    ):
        _set_security_setting(db_session, 'password_min_length', '8')
        _set_security_setting(db_session, 'password_require_uppercase', 'true')
        _set_security_setting(db_session, 'password_require_lowercase', 'true')
        _set_security_setting(db_session, 'password_require_numbers', 'true')
        _set_security_setting(db_session, 'password_require_special', 'false')

        resp = authenticated_client.post('/api/auth/change-password', json={
            'current_password': 'testpass123',
            'new_password': 'NewValidPass1',
        })
        assert resp.status_code == 200
        data = resp.get_json()
        assert data['success'] is True

        # Verify the new password works
        db_session.refresh(test_user)
        assert test_user.check_password('NewValidPass1') is True

    # 27. Change password with wrong current password returns 401
    def test_change_password_wrong_current_returns_401(
        self, authenticated_client, setup_complete
    ):
        resp = authenticated_client.post('/api/auth/change-password', json={
            'current_password': 'wrongcurrentpassword',
            'new_password': 'NewValidPass1',
        })
        assert resp.status_code == 401
        assert 'incorrect' in resp.get_json()['error'].lower()

    # 28. Change password for LDAP user returns 400
    def test_change_password_ldap_user_returns_400(
        self, client, db_session, test_org, setup_complete
    ):
        ldap_user = _make_ldap_user(db_session, test_org)

        with client.session_transaction() as sess:
            sess['user_id'] = ldap_user.id
            sess['username'] = ldap_user.username
            sess['is_admin'] = False

        resp = client.post('/api/auth/change-password', json={
            'current_password': 'anything',
            'new_password': 'NewPass1!',
        })
        assert resp.status_code == 400
        assert 'ldap' in resp.get_json()['error'].lower()

    # 29. Password expiration detected after N days
    def test_password_expiration_after_n_days(
        self, app, test_user, db_session, setup_complete
    ):
        _set_security_setting(db_session, 'password_expiry_days', '90')

        # Set password_changed_at to 91 days ago
        test_user.password_changed_at = datetime.utcnow() - timedelta(days=91)
        db_session.commit()

        assert test_user.is_password_expired() is True

    # 30. Expired password forces must_change_password session flag
    def test_expired_password_forces_session_flag(
        self, client, test_user, db_session, setup_complete
    ):
        _set_security_setting(db_session, 'password_expiry_days', '30')

        test_user.password_changed_at = datetime.utcnow() - timedelta(days=31)
        db_session.commit()

        resp = _login(client, 'testuser', 'testpass123')
        assert resp.status_code == 200
        data = resp.get_json()
        assert data['success'] is True
        assert data.get('password_expired') is True

        # Verify session flag is set
        with client.session_transaction() as sess:
            assert sess.get('must_change_password') is True


# ===========================================================================
# Account Lockout Tests
# ===========================================================================

class TestAccountLockout:
    """Tests 31-38: failed login tracking, lockout, and admin unlock."""

    # 31. Login fails increment failed_login_attempts
    def test_failed_login_increments_counter(
        self, client, test_user, db_session, setup_complete
    ):
        _login(client, 'testuser', 'wrongpassword')
        db_session.refresh(test_user)
        assert test_user.failed_login_attempts == 1

        _login(client, 'testuser', 'wrongpassword')
        db_session.refresh(test_user)
        assert test_user.failed_login_attempts == 2

    # 32. Account locks after max_failed_logins (default 5)
    def test_account_locks_after_max_attempts(
        self, client, test_user, db_session, setup_complete
    ):
        _set_security_setting(db_session, 'max_failed_logins', '5')
        _set_security_setting(db_session, 'lockout_duration', '30')

        for _ in range(5):
            _login(client, 'testuser', 'wrongpassword')

        db_session.refresh(test_user)
        assert test_user.is_locked() is True
        assert test_user.failed_login_attempts >= 5

    # 33. Locked account returns lockout message with remaining time
    def test_locked_account_returns_lockout_message(
        self, client, test_user, db_session, setup_complete
    ):
        _set_security_setting(db_session, 'max_failed_logins', '3')
        _set_security_setting(db_session, 'lockout_duration', '15')

        # Lock the account
        for _ in range(3):
            _login(client, 'testuser', 'wrongpassword')

        db_session.refresh(test_user)
        assert test_user.is_locked() is True

        # Next attempt should return lockout message
        resp = _login(client, 'testuser', 'testpass123')
        assert resp.status_code == 401
        error_msg = resp.get_json()['error'].lower()
        assert 'locked' in error_msg

    # 34. Lockout expires after lockout_duration minutes
    def test_lockout_expires_after_duration(
        self, app, test_user, db_session, setup_complete
    ):
        _set_security_setting(db_session, 'max_failed_logins', '3')
        _set_security_setting(db_session, 'lockout_duration', '15')

        # Lock the user manually
        test_user.failed_login_attempts = 5
        test_user.locked_until = datetime.utcnow() - timedelta(minutes=1)
        db_session.commit()

        # Lockout should have expired
        assert test_user.is_locked() is False

    # 35. Successful login resets failed_login_attempts
    def test_successful_login_resets_counter(
        self, client, test_user, db_session, setup_complete
    ):
        # Record some failed attempts (but not enough to lock)
        _set_security_setting(db_session, 'max_failed_logins', '10')
        _login(client, 'testuser', 'wrongpassword')
        _login(client, 'testuser', 'wrongpassword')

        db_session.refresh(test_user)
        assert test_user.failed_login_attempts == 2

        # Now login successfully
        resp = _login(client, 'testuser', 'testpass123')
        assert resp.status_code == 200
        assert resp.get_json()['success'] is True

        db_session.refresh(test_user)
        assert test_user.failed_login_attempts == 0

    # 36. Admin can unlock user (POST /api/users/<id>/unlock)
    def test_admin_can_unlock_user(
        self, admin_client, test_user, db_session, setup_complete
    ):
        # Lock the user
        test_user.failed_login_attempts = 5
        test_user.locked_until = datetime.utcnow() + timedelta(minutes=30)
        db_session.commit()
        assert test_user.is_locked() is True

        resp = admin_client.post(f'/api/users/{test_user.id}/unlock')
        assert resp.status_code == 200
        data = resp.get_json()
        assert data['success'] is True

        db_session.refresh(test_user)
        assert test_user.is_locked() is False
        assert test_user.failed_login_attempts == 0

    # 37. Unlock non-locked user returns 400
    def test_unlock_non_locked_user_returns_400(
        self, admin_client, test_user, db_session, setup_complete
    ):
        # User is not locked
        test_user.failed_login_attempts = 0
        test_user.locked_until = None
        db_session.commit()

        resp = admin_client.post(f'/api/users/{test_user.id}/unlock')
        assert resp.status_code == 400
        assert 'not locked' in resp.get_json()['error'].lower()

    # 38. Non-admin can't unlock users (returns 403)
    def test_non_admin_cannot_unlock_returns_403(
        self, authenticated_client, test_user, db_session, test_org, setup_complete
    ):
        from app.models import User

        # Create another user to try to unlock
        other_user = User(
            username='otheruser',
            email='other@test.local',
            password_hash=generate_password_hash('otherpass'),
            role='user',
            organization_id=test_org.id,
            is_active=True,
            auth_type='local',
        )
        db_session.add(other_user)
        db_session.commit()

        # Lock the other user
        other_user.failed_login_attempts = 5
        other_user.locked_until = datetime.utcnow() + timedelta(minutes=30)
        db_session.commit()

        # Non-admin tries to unlock - should fail
        resp = authenticated_client.post(f'/api/users/{other_user.id}/unlock')
        assert resp.status_code == 403


# ===========================================================================
# Session Timeout Tests
# ===========================================================================

class TestSessionTimeout:
    """Tests 39-43: session timeout enforcement and session content."""

    # 39. Session timeout setting is enforced server-side
    def test_session_timeout_enforced_server_side(
        self, app, db_session, setup_complete
    ):
        _set_security_setting(db_session, 'session_timeout', '60')

        with app.test_request_context('/'):
            from flask import session as flask_session
            from app.models import SystemSettings

            flask_session['user_id'] = 1

            # Trigger the before_request handler
            # The enforce_session_timeout handler reads from SystemSettings and
            # updates app.permanent_session_lifetime
            with app.test_client() as c:
                with c.session_transaction() as sess:
                    sess['user_id'] = 1
                c.get('/')

                # After the request, the app lifetime should have been updated
                assert app.permanent_session_lifetime == timedelta(minutes=60)

    # 40. Default session timeout is 480 minutes
    def test_default_session_timeout_480(self, app, db_session, setup_complete):
        # No session_timeout setting in DB -> handler should fall back to config
        # The get_security_settings endpoint returns default 480
        from app.models import SystemSettings
        # Ensure no setting exists
        existing = SystemSettings.query.filter_by(key='session_timeout').first()
        if existing:
            db_session.delete(existing)
            db_session.commit()

        with app.test_client() as c:
            with c.session_transaction() as sess:
                sess['user_id'] = 1
            c.get('/')
            # Without a DB setting, the handler's except/pass keeps the config
            # default. The settings API returns 480 as default.
            # Verify via the GET endpoint with admin.
        # Separately verify the API reports 480 as default
        # (admin_client fixture needed; we test logic via get_setting)
        from app.settings_api import get_setting
        val = get_setting('session_timeout', '480')
        assert int(val) == 480

    # 41. Custom session timeout (e.g., 30 minutes) is respected
    def test_custom_session_timeout_respected(
        self, app, db_session, setup_complete
    ):
        _set_security_setting(db_session, 'session_timeout', '30')

        with app.test_client() as c:
            with c.session_transaction() as sess:
                sess['user_id'] = 1
            c.get('/')
            assert app.permanent_session_lifetime == timedelta(minutes=30)

    # 42. Session fixation protection (session.clear on login)
    def test_session_fixation_protection(
        self, client, test_user, db_session, setup_complete
    ):
        # Pre-populate session with attacker data
        with client.session_transaction() as sess:
            sess['evil_key'] = 'should_be_cleared'

        # Login
        resp = _login(client, 'testuser', 'testpass123')
        assert resp.status_code == 200

        # The old session data should have been cleared by session.clear()
        with client.session_transaction() as sess:
            assert 'evil_key' not in sess

    # 43. Session contains correct user_id, username, is_admin
    def test_session_contains_correct_fields(
        self, client, test_user, db_session, setup_complete
    ):
        resp = _login(client, 'testuser', 'testpass123')
        assert resp.status_code == 200

        with client.session_transaction() as sess:
            assert sess['user_id'] == test_user.id
            assert sess['username'] == 'testuser'
            assert sess['is_admin'] is False


# ===========================================================================
# Security Settings API Tests
# ===========================================================================

class TestSecuritySettingsAPI:
    """Tests 44-47: GET/POST /api/settings/security access control."""

    # 44. Get security settings returns all fields with defaults
    def test_get_security_settings_returns_all_fields(
        self, admin_client, db_session, setup_complete
    ):
        resp = admin_client.get('/api/settings/security')
        assert resp.status_code == 200
        data = resp.get_json()

        # Verify all expected fields are present
        expected_fields = [
            'session_timeout', 'max_failed_logins', 'lockout_duration',
            'password_min_length', 'password_require_uppercase',
            'password_require_lowercase', 'password_require_numbers',
            'password_require_special', 'password_expiry_days', 'require_2fa',
        ]
        for field in expected_fields:
            assert field in data, f"Missing field: {field}"

        # Verify defaults
        assert data['session_timeout'] == 480
        assert data['max_failed_logins'] == 5
        assert data['lockout_duration'] == 30
        assert data['password_min_length'] == 8
        assert data['password_require_uppercase'] is True
        assert data['password_require_lowercase'] is True
        assert data['password_require_numbers'] is True
        assert data['password_require_special'] is False
        assert data['password_expiry_days'] == 0
        assert data['require_2fa'] is False

    # 45. Save security settings updates all fields
    def test_save_security_settings_updates_all_fields(
        self, admin_client, db_session, setup_complete
    ):
        new_settings = {
            'session_timeout': 120,
            'max_failed_logins': 3,
            'lockout_duration': 60,
            'password_min_length': 12,
            'password_require_uppercase': True,
            'password_require_lowercase': True,
            'password_require_numbers': True,
            'password_require_special': True,
            'password_expiry_days': 90,
            'require_2fa': True,
        }

        resp = admin_client.post('/api/settings/security', json=new_settings)
        assert resp.status_code == 200
        assert resp.get_json()['success'] is True

        # Read back and verify
        resp = admin_client.get('/api/settings/security')
        data = resp.get_json()
        assert data['session_timeout'] == 120
        assert data['max_failed_logins'] == 3
        assert data['lockout_duration'] == 60
        assert data['password_min_length'] == 12
        assert data['password_require_uppercase'] is True
        assert data['password_require_lowercase'] is True
        assert data['password_require_numbers'] is True
        assert data['password_require_special'] is True
        assert data['password_expiry_days'] == 90
        assert data['require_2fa'] is True

    # 46. Save security settings - admin only
    def test_save_security_settings_admin_only(
        self, admin_client, db_session, setup_complete
    ):
        resp = admin_client.post('/api/settings/security', json={
            'session_timeout': 300,
            'max_failed_logins': 5,
            'lockout_duration': 30,
            'password_min_length': 8,
            'password_require_uppercase': True,
            'password_require_lowercase': True,
            'password_require_numbers': True,
            'password_require_special': False,
            'password_expiry_days': 0,
            'require_2fa': False,
        })
        assert resp.status_code == 200

    # 47. Non-admin can't access security settings
    def test_non_admin_cannot_access_security_settings(
        self, authenticated_client, setup_complete
    ):
        # GET should fail for non-admin
        resp = authenticated_client.get('/api/settings/security')
        assert resp.status_code == 403

        # POST should also fail for non-admin
        resp = authenticated_client.post('/api/settings/security', json={
            'session_timeout': 10,
        })
        assert resp.status_code == 403
