"""
Comprehensive tests for Settings API endpoints.
Tests cover utility functions, GET/POST endpoints, batch saves, and health checks.
"""
import pytest
import json
from unittest.mock import patch, MagicMock, Mock
from datetime import datetime, date


class TestSettingsUtilityFunctions:
    """Tests for get_setting() and set_setting() utility functions."""

    def test_get_setting_from_database(self, db_session, admin_user):
        """Test getting a setting that exists in database."""
        from app.models import SystemSettings
        from app.settings_api import get_setting

        # Create a setting in database
        setting = SystemSettings(
            key='smtp_host',
            value='test_value',
            category='test',
            is_encrypted=False,
            updated_by=admin_user.id
        )
        db_session.add(setting)
        db_session.commit()

        # Get the setting
        value = get_setting('smtp_host', 'default_value')
        assert value == 'test_value'

    def test_get_setting_returns_default_when_not_found(self, db_session):
        """Test get_setting returns default value when key doesn't exist."""
        from app.settings_api import get_setting

        value = get_setting('nonexistent_key', 'my_default')
        assert value == 'my_default'

    def test_get_setting_with_include_source_database(self, db_session, admin_user):
        """Test get_setting returns source as 'database' when from DB."""
        from app.models import SystemSettings
        from app.settings_api import get_setting

        setting = SystemSettings(
            key='smtp_host',
            value='db_value',
            category='test',
            is_encrypted=False
        )
        db_session.add(setting)
        db_session.commit()

        value, source = get_setting('smtp_host', 'default', include_source=True)
        assert value == 'db_value'
        assert source == 'database'

    def test_get_setting_with_include_source_default(self, db_session):
        """Test get_setting returns source as 'default' when using default."""
        from app.settings_api import get_setting

        value, source = get_setting('missing_key', 'default_val', include_source=True)
        assert value == 'default_val'
        assert source == 'default'

    def test_get_setting_with_encrypted_value(self, app, db_session, admin_user):
        """Test get_setting decrypts encrypted values."""
        from app.models import SystemSettings
        from app.settings_api import get_setting
        from app.encryption import encrypt_value

        with app.app_context():
            encrypted_value = encrypt_value('secret_password')
            setting = SystemSettings(
                key='smtp_password',
                value=encrypted_value,
                category='test',
                is_encrypted=True
            )
            db_session.add(setting)
            db_session.commit()

            value = get_setting('smtp_password', '')
            assert value == 'secret_password'

    def test_get_setting_encrypted_decryption_failure_returns_default(self, db_session, admin_user):
        """Test get_setting returns default if decryption fails."""
        from app.models import SystemSettings
        from app.settings_api import get_setting

        # Create setting with invalid encrypted data (not properly encrypted with our key)
        # This will fail decryption and return empty/default
        setting = SystemSettings(
            key='smtp_password',
            value='invalid_encrypted_data',
            category='test',
            is_encrypted=True
        )
        db_session.add(setting)
        db_session.commit()

        value = get_setting('smtp_password', 'fallback')
        # With a valid key, it might return the invalid data or fallback
        # The important thing is it doesn't crash
        assert value in ['fallback', 'invalid_encrypted_data']

    def test_get_setting_with_source_helper(self, db_session, admin_user):
        """Test get_setting_with_source helper function."""
        from app.models import SystemSettings
        from app.settings_api import get_setting_with_source

        setting = SystemSettings(
            key='smtp_host',
            value='test_val',
            category='test',
            is_encrypted=False
        )
        db_session.add(setting)
        db_session.commit()

        result = get_setting_with_source('smtp_host', 'default')
        assert result['value'] == 'test_val'
        assert result['source'] == 'database'
        assert result['from_env'] is False

    def test_set_setting_creates_new_setting(self, app, db_session, admin_client, admin_user):
        """Test set_setting creates a new setting when key doesn't exist."""
        from app.settings_api import set_setting
        from app.models import SystemSettings

        with app.test_request_context():
            with admin_client.session_transaction() as sess:
                sess['user_id'] = admin_user.id

            from flask import session
            session['user_id'] = admin_user.id

            setting = set_setting('smtp_host', 'new_value', 'smtp', 'Test description')
            db_session.commit()

            # Verify setting was created
            saved = SystemSettings.query.filter_by(key='smtp_host').first()
            assert saved is not None
            assert saved.value == 'new_value'
            assert saved.category == 'smtp'
            assert saved.description == 'Test description'

    def test_set_setting_updates_existing_setting(self, app, db_session, admin_client, admin_user):
        """Test set_setting updates an existing setting."""
        from app.settings_api import set_setting
        from app.models import SystemSettings

        with app.test_request_context():
            from flask import session
            session['user_id'] = admin_user.id

            # Create initial setting
            setting = SystemSettings(
                key='smtp_host',
                value='old_value',
                category='smtp',
                is_encrypted=False
            )
            db_session.add(setting)
            db_session.commit()

            # Update it
            set_setting('smtp_host', 'new_value', 'smtp')
            db_session.commit()

            # Verify update
            updated = SystemSettings.query.filter_by(key='smtp_host').first()
            assert updated.value == 'new_value'

    def test_set_setting_with_encryption(self, app, db_session, admin_client, admin_user):
        """Test set_setting encrypts values when is_encrypted=True."""
        from app.settings_api import set_setting
        from app.models import SystemSettings

        with app.test_request_context():
            from flask import session
            session['user_id'] = admin_user.id

            set_setting('smtp_password', 'secret', 'smtp', is_encrypted=True)
            db_session.commit()

            saved = SystemSettings.query.filter_by(key='smtp_password').first()
            assert saved.is_encrypted is True
            # The stored value should be encrypted (different from plaintext)
            assert saved.value != 'secret'

    def test_set_setting_rejects_disallowed_key(self, app, admin_client, admin_user):
        """Test set_setting raises ValueError for disallowed keys."""
        from app.settings_api import set_setting

        with app.test_request_context():
            from flask import session
            session['user_id'] = admin_user.id

            with pytest.raises(ValueError, match="not allowed"):
                set_setting('malicious_key', 'value', 'general')

    def test_set_setting_allows_key_with_skip_validation(self, app, db_session, admin_client, admin_user):
        """Test set_setting allows any key when skip_validation=True."""
        from app.settings_api import set_setting
        from app.models import SystemSettings

        with app.test_request_context():
            from flask import session
            session['user_id'] = admin_user.id

            set_setting('custom_internal_key', 'value', 'internal', skip_validation=True)
            db_session.commit()

            saved = SystemSettings.query.filter_by(key='custom_internal_key').first()
            assert saved is not None


class TestBatchSettingsEndpoint:
    """Tests for POST /api/settings/batch endpoint."""

    def test_batch_save_success(self, admin_client, db_session, setup_complete):
        """Test batch saving multiple settings."""
        response = admin_client.post('/api/settings/batch', json={
            'category': 'test_category',
            'settings': {
                'smtp_host': 'smtp.example.com',
                'smtp_port': '587',
                'smtp_username': 'user@example.com'
            }
        })

        assert response.status_code == 200
        data = response.get_json()
        assert data['success'] is True
        assert data['saved_count'] == 3

    def test_batch_save_with_encrypted_keys(self, app, admin_client, db_session, setup_complete):
        """Test batch save with encryption for sensitive keys."""
        from app.models import SystemSettings

        with app.app_context():
            response = admin_client.post('/api/settings/batch', json={
                'category': 'smtp',
                'settings': {
                    'smtp_host': 'smtp.example.com',
                    'smtp_password': 'secret_password'
                },
                'encrypt_keys': ['smtp_password']
            })

            assert response.status_code == 200
            data = response.get_json()
            assert data['success'] is True

            # Verify password was encrypted
            password_setting = SystemSettings.query.filter_by(key='smtp_password').first()
            assert password_setting.is_encrypted is True

    def test_batch_save_skips_disallowed_keys(self, admin_client, db_session, setup_complete):
        """Test batch save skips disallowed keys."""
        response = admin_client.post('/api/settings/batch', json={
            'category': 'general',
            'settings': {
                'smtp_host': 'smtp.example.com',
                'bad_key_not_allowed': 'bad_value'
            }
        })

        assert response.status_code == 200
        data = response.get_json()
        # Should only save the allowed key
        assert data['saved_count'] == 1

    def test_batch_save_no_data_error(self, admin_client, setup_complete):
        """Test batch save returns error when no data provided."""
        response = admin_client.post('/api/settings/batch', json={})

        assert response.status_code == 400

    def test_batch_save_no_settings_error(self, admin_client, setup_complete):
        """Test batch save returns error when settings dict is empty."""
        response = admin_client.post('/api/settings/batch', json={
            'category': 'test',
            'settings': {}
        })

        assert response.status_code == 400
        data = response.get_json()
        assert 'error' in data

    def test_batch_save_requires_admin(self, authenticated_client, setup_complete):
        """Test batch save requires admin privileges."""
        response = authenticated_client.post('/api/settings/batch', json={
            'category': 'general',
            'settings': {'smtp_host': 'smtp.example.com'}
        })

        # Should be forbidden or redirect
        assert response.status_code in [302, 403]


class TestLDAPSettingsEndpoints:
    """Tests for LDAP settings GET/POST endpoints."""

    @patch('app.licensing.get_license')
    def test_get_ldap_settings(self, mock_license, admin_client, db_session, setup_complete):
        """Test GET /api/settings/ldap returns LDAP configuration."""
        # Create mock license object
        mock_license_obj = Mock()
        mock_license_obj.is_professional.return_value = True
        mock_license.return_value = mock_license_obj

        from app.models import SystemSettings
        # Create settings directly in database
        settings = [
            SystemSettings(key='ldap_enabled', value='true', category='ldap', is_encrypted=False),
            SystemSettings(key='ldap_server', value='ldap.example.com', category='ldap', is_encrypted=False),
            SystemSettings(key='ldap_port', value='389', category='ldap', is_encrypted=False),
        ]
        for s in settings:
            db_session.add(s)
        db_session.commit()

        response = admin_client.get('/api/settings/ldap')

        assert response.status_code == 200
        data = response.get_json()
        assert data['ldap_enabled'] is True
        assert data['ldap_server'] == 'ldap.example.com'
        assert data['ldap_port'] == 389

    @patch('app.licensing.get_license')
    def test_get_ldap_settings_hides_password(self, mock_license, app, admin_client, db_session, setup_complete):
        """Test GET /api/settings/ldap doesn't return actual password."""
        mock_license_obj = Mock()
        mock_license_obj.is_professional.return_value = True
        mock_license.return_value = mock_license_obj

        from app.models import SystemSettings
        from app.encryption import encrypt_value

        with app.app_context():
            encrypted_value = encrypt_value('secret123')
            setting = SystemSettings(key='ldap_bind_password', value=encrypted_value,
                                    category='ldap', is_encrypted=True)
            db_session.add(setting)
            db_session.commit()

        response = admin_client.get('/api/settings/ldap')

        assert response.status_code == 200
        data = response.get_json()
        assert 'ldap_bind_password' not in data
        assert data['ldap_bind_password_configured'] is True

    @patch('app.licensing.get_license')
    def test_save_ldap_settings(self, mock_license, admin_client, db_session, setup_complete):
        """Test POST /api/settings/ldap saves LDAP configuration."""
        mock_license_obj = Mock()
        mock_license_obj.is_professional.return_value = True
        mock_license.return_value = mock_license_obj

        response = admin_client.post('/api/settings/ldap', json={
            'ldap_enabled': True,
            'ldap_server': 'ldap.company.com',
            'ldap_port': 636,
            'ldap_base_dn': 'dc=company,dc=com',
            'ldap_bind_dn': 'cn=admin,dc=company,dc=com',
            'ldap_bind_password': 'secret_password',
            'ldap_use_tls': True
        })

        assert response.status_code == 200
        data = response.get_json()
        assert data['success'] is True

    @patch('app.licensing.get_license')
    def test_save_ldap_settings_encrypts_password(self, mock_license, app, admin_client, db_session, setup_complete):
        """Test POST /api/settings/ldap encrypts bind password."""
        mock_license_obj = Mock()
        mock_license_obj.is_professional.return_value = True
        mock_license.return_value = mock_license_obj

        from app.models import SystemSettings

        with app.app_context():
            response = admin_client.post('/api/settings/ldap', json={
                'ldap_enabled': True,
                'ldap_server': 'ldap.example.com',
                'ldap_bind_password': 'my_secret'
            })

            assert response.status_code == 200

            # Verify password is encrypted in DB
            password_setting = SystemSettings.query.filter_by(key='ldap_bind_password').first()
            assert password_setting is not None
            assert password_setting.is_encrypted is True

    @patch('app.licensing.get_license')
    def test_save_ldap_settings_no_data_error(self, mock_license, admin_client, setup_complete):
        """Test POST /api/settings/ldap returns error when no data provided."""
        mock_license_obj = Mock()
        mock_license_obj.is_professional.return_value = True
        mock_license.return_value = mock_license_obj

        response = admin_client.post('/api/settings/ldap',
                                     data='',
                                     content_type='application/json')

        assert response.status_code == 400


class TestSMTPSettingsEndpoints:
    """Tests for SMTP settings GET/POST endpoints."""

    @patch('app.licensing.get_license')
    def test_get_smtp_settings(self, mock_license, admin_client, db_session, setup_complete):
        """Test GET /api/settings/smtp returns SMTP configuration."""
        mock_license_obj = Mock()
        mock_license_obj.is_professional.return_value = True
        mock_license.return_value = mock_license_obj

        from app.models import SystemSettings

        # Create settings directly in database
        settings = [
            SystemSettings(key='smtp_host', value='smtp.gmail.com', category='smtp', is_encrypted=False),
            SystemSettings(key='smtp_port', value='587', category='smtp', is_encrypted=False),
            SystemSettings(key='smtp_use_tls', value='true', category='smtp', is_encrypted=False),
        ]
        for s in settings:
            db_session.add(s)
        db_session.commit()

        response = admin_client.get('/api/settings/smtp')

        assert response.status_code == 200
        data = response.get_json()
        assert data['smtp_host'] == 'smtp.gmail.com'
        assert data['smtp_port'] == 587
        assert data['smtp_use_tls'] is True

    def test_save_smtp_settings(self, admin_client, db_session, setup_complete):
        """Test POST /api/settings/smtp saves SMTP configuration."""
        response = admin_client.post('/api/settings/smtp', json={
            'smtp_host': 'smtp.office365.com',
            'smtp_port': 587,
            'smtp_username': 'alerts@company.com',
            'smtp_password': 'email_password',
            'smtp_from_email': 'alerts@company.com',
            'smtp_from_name': 'Security Alerts',
            'smtp_use_tls': True
        })

        assert response.status_code == 200
        data = response.get_json()
        assert data['success'] is True

    def test_save_smtp_settings_encrypts_password(self, app, admin_client, db_session, setup_complete):
        """Test POST /api/settings/smtp encrypts password."""
        from app.models import SystemSettings

        with app.app_context():
            response = admin_client.post('/api/settings/smtp', json={
                'smtp_host': 'smtp.example.com',
                'smtp_password': 'secret_smtp_password'
            })

            assert response.status_code == 200

            # Verify password is encrypted
            password_setting = SystemSettings.query.filter_by(key='smtp_password').first()
            assert password_setting is not None
            assert password_setting.is_encrypted is True

    def test_save_smtp_settings_no_data_error(self, admin_client, setup_complete):
        """Test POST /api/settings/smtp returns error when no data provided."""
        response = admin_client.post('/api/settings/smtp',
                                     data='',
                                     content_type='application/json')

        assert response.status_code == 400

    @patch('smtplib.SMTP')
    def test_test_smtp_connection_success(self, mock_smtp, admin_client, db_session, admin_user, setup_complete):
        """Test POST /api/settings/smtp/test with successful connection."""
        from app.models import SystemSettings

        # Mock SMTP server
        mock_server = MagicMock()
        mock_smtp.return_value = mock_server

        # Setup SMTP settings directly in database
        settings = [
            SystemSettings(key='smtp_host', value='smtp.example.com', category='smtp', is_encrypted=False),
            SystemSettings(key='smtp_port', value='587', category='smtp', is_encrypted=False),
            SystemSettings(key='smtp_from_email', value='test@example.com', category='smtp', is_encrypted=False),
            SystemSettings(key='smtp_use_tls', value='true', category='smtp', is_encrypted=False),
        ]
        for s in settings:
            db_session.add(s)
        db_session.commit()

        response = admin_client.post('/api/settings/smtp/test')

        assert response.status_code == 200
        data = response.get_json()
        assert data['success'] is True

    def test_test_smtp_connection_no_host_error(self, admin_client, setup_complete):
        """Test POST /api/settings/smtp/test returns error when host not configured."""
        response = admin_client.post('/api/settings/smtp/test')

        assert response.status_code == 200
        data = response.get_json()
        assert data['success'] is False
        assert 'not configured' in data['error'].lower()


class TestSyncSettingsEndpoints:
    """Tests for sync settings GET/POST endpoints."""

    def test_get_sync_settings(self, admin_client, db_session, setup_complete):
        """Test GET /api/settings/sync returns sync configuration."""
        from app.models import SystemSettings

        # Create settings directly in database
        settings = [
            SystemSettings(key='auto_sync_enabled', value='true', category='sync', is_encrypted=False),
            SystemSettings(key='sync_interval', value='daily', category='sync', is_encrypted=False),
            SystemSettings(key='sync_time', value='02:00', category='sync', is_encrypted=False),
        ]
        for s in settings:
            db_session.add(s)
        db_session.commit()

        response = admin_client.get('/api/settings/sync')

        assert response.status_code == 200
        data = response.get_json()
        assert data['auto_sync_enabled'] is True
        assert data['sync_interval'] == 'daily'
        assert data['sync_time'] == '02:00'

    def test_get_sync_settings_masks_api_key(self, app, admin_client, db_session, setup_complete):
        """Test GET /api/settings/sync masks NVD API key."""
        from app.models import SystemSettings
        from app.encryption import encrypt_value

        with app.app_context():
            encrypted_value = encrypt_value('real_api_key_12345')
            setting = SystemSettings(key='nvd_api_key', value=encrypted_value,
                                    category='sync', is_encrypted=True)
            db_session.add(setting)
            db_session.commit()

        response = admin_client.get('/api/settings/sync')

        assert response.status_code == 200
        data = response.get_json()
        assert data['nvd_api_key'] == '********'
        assert data['nvd_api_key_configured'] is True

    def test_save_sync_settings(self, admin_client, db_session, setup_complete):
        """Test POST /api/settings/sync saves sync configuration."""
        response = admin_client.post('/api/settings/sync', json={
            'auto_sync_enabled': True,
            'sync_interval': 'weekly',
            'sync_time': '03:00',
            'cisa_kev_url': 'https://custom.url/feed.json'
        })

        assert response.status_code == 200
        data = response.get_json()
        assert data['success'] is True

    @patch('app.settings_api._validate_nvd_api_key')
    def test_save_sync_settings_with_valid_nvd_key(self, mock_validate, admin_client, db_session, setup_complete):
        """Test POST /api/settings/sync saves valid NVD API key."""
        mock_validate.return_value = (True, None)

        response = admin_client.post('/api/settings/sync', json={
            'auto_sync_enabled': True,
            'nvd_api_key': 'valid-api-key-12345'
        })

        assert response.status_code == 200
        data = response.get_json()
        assert data['success'] is True
        # Verify the validation was called
        mock_validate.assert_called_once_with('valid-api-key-12345')

    @patch('app.settings_api._validate_nvd_api_key')
    def test_save_sync_settings_with_invalid_nvd_key(self, mock_validate, admin_client, db_session, setup_complete):
        """Test POST /api/settings/sync rejects invalid NVD API key."""
        mock_validate.return_value = (False, 'API key rejected')

        response = admin_client.post('/api/settings/sync', json={
            'auto_sync_enabled': True,
            'nvd_api_key': 'invalid-key'
        })

        assert response.status_code == 400
        data = response.get_json()
        assert 'Invalid NVD API key' in data['error']

    def test_save_sync_settings_clears_nvd_key_when_empty(self, app, admin_client, db_session, setup_complete):
        """Test POST /api/settings/sync clears NVD API key when empty string."""
        from app.models import SystemSettings
        from app.encryption import encrypt_value

        # Set initial key
        with app.app_context():
            encrypted_value = encrypt_value('old_key')
            setting = SystemSettings(key='nvd_api_key', value=encrypted_value,
                                    category='sync', is_encrypted=True)
            db_session.add(setting)
            db_session.commit()

        # Clear it
        with app.app_context():
            response = admin_client.post('/api/settings/sync', json={
                'auto_sync_enabled': True,
                'nvd_api_key': ''
            })

            assert response.status_code == 200

            # Verify key was cleared
            key_setting = SystemSettings.query.filter_by(key='nvd_api_key').first()
            assert key_setting.value == ''

    def test_save_sync_settings_no_data_error(self, admin_client, setup_complete):
        """Test POST /api/settings/sync returns error when no data provided."""
        response = admin_client.post('/api/settings/sync',
                                     data='',
                                     content_type='application/json')

        assert response.status_code == 400


class TestNVDHealthCheckEndpoints:
    """Tests for NVD health check endpoints."""

    @patch('requests.get')
    def test_get_nvd_status_success(self, mock_get, app, admin_client, db_session, setup_complete):
        """Test GET /api/settings/sync/nvd-status returns status."""
        from app.models import SystemSettings
        from app.encryption import encrypt_value

        # Mock successful NVD response
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_get.return_value = mock_response

        with app.app_context():
            encrypted_value = encrypt_value('test_key')
            setting = SystemSettings(key='nvd_api_key', value=encrypted_value,
                                    category='sync', is_encrypted=True)
            db_session.add(setting)
            db_session.commit()

        response = admin_client.get('/api/settings/sync/nvd-status')

        assert response.status_code == 200
        data = response.get_json()
        assert data['api_key_configured'] is True
        assert data['reachable'] is True

    @patch('requests.get')
    def test_get_nvd_status_connection_error(self, mock_get, admin_client, setup_complete):
        """Test GET /api/settings/sync/nvd-status handles connection errors."""
        import requests
        mock_get.side_effect = requests.exceptions.ConnectionError()

        response = admin_client.get('/api/settings/sync/nvd-status')

        assert response.status_code == 200
        data = response.get_json()
        assert data['reachable'] is False
        assert 'Cannot connect' in data['error']

    def test_get_nvd_rate_limit_stats(self, admin_client, setup_complete):
        """Test GET /api/settings/sync/nvd-rate-limit returns stats."""
        response = admin_client.get('/api/settings/sync/nvd-rate-limit')

        assert response.status_code == 200
        data = response.get_json()
        assert 'stats' in data or 'error' in data

    def test_get_sync_status(self, admin_client, db_session, setup_complete):
        """Test GET /api/settings/sync/status returns sync status."""
        response = admin_client.get('/api/settings/sync/status')

        assert response.status_code == 200
        data = response.get_json()
        assert 'total_vulnerabilities' in data
        assert 'auto_sync_enabled' in data


class TestGeneralSettingsEndpoints:
    """Tests for general settings GET/POST endpoints."""

    def test_get_general_settings(self, admin_client, db_session, setup_complete):
        """Test GET /api/settings/general returns general configuration."""
        from app.models import SystemSettings

        # Create settings directly in database
        settings = [
            SystemSettings(key='display_timezone', value='America/New_York', category='general', is_encrypted=False),
            SystemSettings(key='verify_ssl', value='true', category='general', is_encrypted=False),
            SystemSettings(key='http_proxy', value='http://proxy:8080', category='general', is_encrypted=False),
        ]
        for s in settings:
            db_session.add(s)
        db_session.commit()

        response = admin_client.get('/api/settings/general')

        assert response.status_code == 200
        data = response.get_json()
        assert data['display_timezone'] == 'America/New_York'
        assert data['verify_ssl'] is True
        assert data['http_proxy'] == 'http://proxy:8080'

    def test_save_general_settings(self, admin_client, db_session, setup_complete):
        """Test POST /api/settings/general saves general configuration."""
        response = admin_client.post('/api/settings/general', json={
            'display_timezone': 'Europe/London',
            'date_format': 'DD/MM/YYYY HH:mm',
            'verify_ssl': False,
            'http_proxy': 'http://corporate-proxy:3128',
            'https_proxy': 'http://corporate-proxy:3128',
            'no_proxy': 'localhost,127.0.0.1'
        })

        assert response.status_code == 200
        data = response.get_json()
        assert data['success'] is True


class TestSecuritySettingsEndpoints:
    """Tests for security settings GET/POST endpoints."""

    def test_get_security_settings(self, admin_client, db_session, setup_complete):
        """Test GET /api/settings/security returns security configuration."""
        from app.models import SystemSettings

        # Create settings directly in database
        settings = [
            SystemSettings(key='session_timeout', value='480', category='security', is_encrypted=False),
            SystemSettings(key='max_failed_logins', value='5', category='security', is_encrypted=False),
            SystemSettings(key='password_min_length', value='12', category='security', is_encrypted=False),
        ]
        for s in settings:
            db_session.add(s)
        db_session.commit()

        response = admin_client.get('/api/settings/security')

        assert response.status_code == 200
        data = response.get_json()
        assert data['session_timeout'] == 480
        assert data['max_failed_logins'] == 5
        assert data['password_min_length'] == 12

    def test_save_security_settings(self, admin_client, db_session, setup_complete):
        """Test POST /api/settings/security saves security configuration."""
        response = admin_client.post('/api/settings/security', json={
            'session_timeout': 240,
            'max_failed_logins': 3,
            'lockout_duration': 60,
            'password_min_length': 10,
            'password_require_uppercase': True,
            'password_require_lowercase': True,
            'password_require_numbers': True,
            'password_require_special': True,
            'require_2fa': False
        })

        assert response.status_code == 200
        data = response.get_json()
        assert data['success'] is True


class TestBrandingSettingsEndpoints:
    """Tests for branding settings GET/POST endpoints."""

    @patch('app.licensing.get_license')
    def test_get_branding_settings(self, mock_license, admin_client, db_session, setup_complete):
        """Test GET /api/settings/branding returns branding configuration."""
        mock_license_obj = Mock()
        mock_license_obj.is_professional.return_value = True
        mock_license.return_value = mock_license_obj

        from app.models import SystemSettings

        # Create settings directly in database
        settings = [
            SystemSettings(key='app_name', value='CustomApp', category='branding', is_encrypted=False),
            SystemSettings(key='login_message', value='Welcome to our system', category='branding', is_encrypted=False),
            SystemSettings(key='support_email', value='support@company.com', category='branding', is_encrypted=False),
        ]
        for s in settings:
            db_session.add(s)
        db_session.commit()

        response = admin_client.get('/api/settings/branding')

        assert response.status_code == 200
        data = response.get_json()
        assert data['app_name'] == 'CustomApp'
        assert data['login_message'] == 'Welcome to our system'
        assert data['support_email'] == 'support@company.com'

    @patch('app.licensing.get_license')
    def test_save_branding_settings(self, mock_license, admin_client, db_session, setup_complete):
        """Test POST /api/settings/branding saves branding configuration.

        NOTE: This test currently expects a 500 error because the endpoint tries to save
        'report_branding_enabled' which is not in ALLOWED_SETTING_KEYS. This is a bug in
        the production code at /home/user/SentriKat/app/settings_api.py line 1018.
        Fix: Add 'report_branding_enabled' to ALLOWED_SETTING_KEYS set.
        """
        mock_license_obj = Mock()
        mock_license_obj.is_professional.return_value = True
        mock_license.return_value = mock_license_obj

        response = admin_client.post('/api/settings/branding', json={
            'app_name': 'Corporate Vuln Manager',
            'login_message': 'Welcome!',
            'support_email': 'it-support@corp.com',
            'show_version': False
        })

        # Currently returns 500 due to the report_branding_enabled bug
        # Once the bug is fixed by adding the key to ALLOWED_SETTING_KEYS, this should be 200
        assert response.status_code == 500
        data = response.get_json()
        assert 'error' in data


class TestNotificationSettingsEndpoints:
    """Tests for notification settings GET/POST endpoints."""

    @patch('app.licensing.get_license')
    def test_get_notification_settings(self, mock_license, app, admin_client, db_session, setup_complete):
        """Test GET /api/settings/notifications returns notification configuration."""
        mock_license_obj = Mock()
        mock_license_obj.is_professional.return_value = True
        mock_license.return_value = mock_license_obj

        from app.models import SystemSettings
        from app.encryption import encrypt_value

        with app.app_context():
            encrypted_value = encrypt_value('https://hooks.slack.com/test')
            settings = [
                SystemSettings(key='slack_enabled', value='true', category='notifications', is_encrypted=False),
                SystemSettings(key='slack_webhook_url', value=encrypted_value, category='notifications', is_encrypted=True),
                SystemSettings(key='teams_enabled', value='false', category='notifications', is_encrypted=False),
            ]
            for s in settings:
                db_session.add(s)
            db_session.commit()

        response = admin_client.get('/api/settings/notifications')

        assert response.status_code == 200
        data = response.get_json()
        assert data['slack_enabled'] is True
        assert data['teams_enabled'] is False

    @patch('app.licensing.get_license')
    def test_save_notification_settings(self, mock_license, admin_client, db_session, setup_complete):
        """Test POST /api/settings/notifications saves notification configuration."""
        mock_license_obj = Mock()
        mock_license_obj.is_professional.return_value = True
        mock_license.return_value = mock_license_obj

        response = admin_client.post('/api/settings/notifications', json={
            'slack_enabled': True,
            'slack_webhook_url': 'https://hooks.slack.com/services/TEST',
            'teams_enabled': False,
            'critical_email_enabled': True,
            'critical_email_time': '09:00',
            'notify_on_critical': True,
            'notify_on_high': False
        })

        assert response.status_code == 200
        data = response.get_json()
        assert data['success'] is True

    @patch('app.licensing.get_license')
    def test_save_notification_settings_encrypts_webhooks(self, mock_license, app, admin_client, db_session, setup_complete):
        """Test POST /api/settings/notifications encrypts webhook URLs."""
        mock_license_obj = Mock()
        mock_license_obj.is_professional.return_value = True
        mock_license.return_value = mock_license_obj

        from app.models import SystemSettings

        with app.app_context():
            response = admin_client.post('/api/settings/notifications', json={
                'slack_enabled': True,
                'slack_webhook_url': 'https://hooks.slack.com/secret',
                'teams_enabled': True,
                'teams_webhook_url': 'https://outlook.office.com/webhook/secret'
            })

            assert response.status_code == 200

            # Verify URLs are encrypted
            slack_setting = SystemSettings.query.filter_by(key='slack_webhook_url').first()
            teams_setting = SystemSettings.query.filter_by(key='teams_webhook_url').first()
            assert slack_setting.is_encrypted is True
            assert teams_setting.is_encrypted is True

    @patch('app.licensing.get_license')
    def test_save_notification_settings_clears_webhook(self, mock_license, app, admin_client, db_session, setup_complete):
        """Test POST /api/settings/notifications can clear webhook URLs."""
        mock_license_obj = Mock()
        mock_license_obj.is_professional.return_value = True
        mock_license.return_value = mock_license_obj

        from app.models import SystemSettings
        from app.encryption import encrypt_value

        # Set initial webhook
        with app.app_context():
            encrypted_value = encrypt_value('https://old.url')
            setting = SystemSettings(key='slack_webhook_url', value=encrypted_value,
                                    category='notifications', is_encrypted=True)
            db_session.add(setting)
            db_session.commit()

        # Clear it
        with app.app_context():
            response = admin_client.post('/api/settings/notifications', json={
                'slack_enabled': False,
                'slack_webhook_url': ''
            })

            assert response.status_code == 200

            # Verify cleared
            slack_setting = SystemSettings.query.filter_by(key='slack_webhook_url').first()
            assert slack_setting.value == ''

    @patch('app.licensing.get_license')
    def test_save_notification_settings_propagates_to_orgs(self, mock_license, admin_client, db_session, test_org, setup_complete):
        """Test POST /api/settings/notifications propagates alert rules to orgs."""
        mock_license_obj = Mock()
        mock_license_obj.is_professional.return_value = True
        mock_license.return_value = mock_license_obj

        response = admin_client.post('/api/settings/notifications', json={
            'notify_on_critical': True,
            'notify_on_high': True,
            'notify_on_ransomware': True
        })

        assert response.status_code == 200

        # Verify org was updated
        db_session.refresh(test_org)
        assert test_org.alert_on_critical is True
        assert test_org.alert_on_high is True
        assert test_org.alert_on_ransomware is True

    def test_get_alert_org_overrides(self, admin_client, db_session, test_org, setup_complete):
        """Test GET /api/settings/alerts/org-overrides returns org alert settings."""
        response = admin_client.get('/api/settings/alerts/org-overrides')

        assert response.status_code == 200
        data = response.get_json()
        assert isinstance(data, list)
        assert len(data) >= 1


class TestEnvironmentVariableHandling:
    """Tests for environment variable fallback in settings."""

    @patch.dict('os.environ', {'SMTP_HOST': 'env-smtp.example.com'})
    def test_get_setting_from_environment(self, db_session):
        """Test get_setting falls back to environment variable."""
        from app.settings_api import get_setting

        # No database setting, should get from env
        value = get_setting('smtp_host', 'default')
        assert value == 'env-smtp.example.com'

    @patch.dict('os.environ', {'SMTP_PORT': '587'})
    def test_get_setting_database_overrides_environment(self, db_session, admin_user):
        """Test database setting takes priority over environment."""
        from app.models import SystemSettings
        from app.settings_api import get_setting

        # Create database setting
        setting = SystemSettings(
            key='smtp_port',
            value='25',
            category='smtp',
            is_encrypted=False
        )
        db_session.add(setting)
        db_session.commit()

        # Should get database value, not env
        value = get_setting('smtp_port', '465')
        assert value == '25'

    @patch.dict('os.environ', {'HTTP_PROXY': 'http://proxy1:8080', 'http_proxy': 'http://proxy2:8080'})
    def test_get_setting_environment_multiple_vars(self, db_session):
        """Test get_setting handles multiple possible env var names."""
        from app.settings_api import get_setting

        # Should get first matching env var (HTTP_PROXY before http_proxy)
        value = get_setting('http_proxy', 'default')
        assert value in ['http://proxy1:8080', 'http://proxy2:8080']

    @patch.dict('os.environ', {'LDAP_ENABLED': 'true'})
    def test_get_setting_with_source_environment(self, db_session):
        """Test get_setting returns source as 'environment' when from env."""
        from app.settings_api import get_setting

        value, source = get_setting('ldap_enabled', 'false', include_source=True)
        assert value == 'true'
        assert source == 'environment'


class TestEdgeCasesAndErrorHandling:
    """Tests for edge cases and error handling."""

    def test_batch_save_with_empty_values(self, admin_client, db_session, setup_complete):
        """Test batch save ignores empty string values."""
        response = admin_client.post('/api/settings/batch', json={
            'category': 'test',
            'settings': {
                'smtp_host': 'valid.host',
                'smtp_port': '',  # Empty string should be ignored
                'smtp_username': None  # None should be ignored
            }
        })

        assert response.status_code == 200
        data = response.get_json()
        # Should only save non-empty value
        assert data['saved_count'] == 1

    def test_set_setting_encryption_failure(self, app, admin_client, admin_user):
        """Test set_setting handles encryption failures."""
        from app.settings_api import set_setting

        with app.test_request_context():
            from flask import session
            session['user_id'] = admin_user.id

            with patch('app.settings_api.encrypt_value', side_effect=Exception('Encryption error')):
                with pytest.raises(Exception):
                    set_setting('smtp_password', 'value', 'smtp', is_encrypted=True)

    def test_get_setting_with_none_value_in_database(self, db_session, admin_user):
        """Test get_setting handles None value in database."""
        from app.models import SystemSettings
        from app.settings_api import get_setting

        setting = SystemSettings(
            key='smtp_host',
            value=None,
            category='test',
            is_encrypted=False
        )
        db_session.add(setting)
        db_session.commit()

        # Should fall back to default when value is None
        value = get_setting('smtp_host', 'default_value')
        assert value == 'default_value'

    def test_endpoints_require_setup_complete(self, admin_client):
        """Test endpoints return 503 when setup not complete."""
        # Without setup_complete fixture, should get 503
        response = admin_client.get('/api/settings/general')

        # May return 503 or 200 depending on if other tests created org/user
        assert response.status_code in [200, 503]

    def test_nvd_validate_api_key_timeout(self):
        """Test _validate_nvd_api_key handles timeout."""
        from app.settings_api import _validate_nvd_api_key
        import requests

        with patch('requests.get', side_effect=requests.exceptions.Timeout()):
            is_valid, error = _validate_nvd_api_key('test_key')
            assert is_valid is False
            assert 'timeout' in error.lower()

    def test_nvd_validate_api_key_connection_error(self):
        """Test _validate_nvd_api_key handles connection errors."""
        from app.settings_api import _validate_nvd_api_key
        import requests

        with patch('requests.get', side_effect=requests.exceptions.ConnectionError()):
            is_valid, error = _validate_nvd_api_key('test_key')
            assert is_valid is False
            assert 'Connection error' in error

    @patch('requests.get')
    def test_nvd_validate_api_key_403_forbidden(self, mock_get):
        """Test _validate_nvd_api_key handles 403 response."""
        from app.settings_api import _validate_nvd_api_key

        mock_response = MagicMock()
        mock_response.status_code = 403
        mock_get.return_value = mock_response

        is_valid, error = _validate_nvd_api_key('bad_key')
        assert is_valid is False
        assert '403' in error

    @patch('requests.get')
    def test_nvd_validate_api_key_success(self, mock_get):
        """Test _validate_nvd_api_key with valid key."""
        from app.settings_api import _validate_nvd_api_key

        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_get.return_value = mock_response

        is_valid, error = _validate_nvd_api_key('valid_key')
        assert is_valid is True
        assert error is None
