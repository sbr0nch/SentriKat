"""
Tests for SAML 2.0 SSO module (saml_api.py and saml_manager.py).

Covers:
- SAML API routes: settings GET/POST, metadata, login, ACS, SLS, status, test
- SAML manager functions: is_saml_available, get_saml_settings, prepare_flask_request,
  init_saml_auth, generate_login_url, process_saml_response, get_saml_metadata,
  get_or_create_saml_user
- Admin-only access enforcement on settings endpoints
- CSRF exemption on SAML blueprint
- User auto-provisioning from SAML attributes
- The session.clear() fix in saml_sls (no logout_user call)
- Error handling paths
"""
import pytest
import json
from unittest.mock import patch, MagicMock, PropertyMock


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _enable_saml_settings(db_session):
    """Insert the minimum SAML settings into the database so routes treat SAML as configured."""
    from app.models import SystemSettings
    settings = [
        SystemSettings(key='saml_enabled', value='true', category='saml'),
        SystemSettings(key='saml_idp_metadata', value='<xml>fake</xml>', category='saml'),
        SystemSettings(key='saml_sp_entity_id', value='sentrikat:test', category='saml'),
        SystemSettings(key='saml_sp_acs_url', value='http://localhost:5000/saml/acs', category='saml'),
        SystemSettings(key='saml_sp_sls_url', value='http://localhost:5000/saml/sls', category='saml'),
        SystemSettings(key='saml_default_org_id', value='', category='saml'),
        SystemSettings(key='saml_user_mapping', value='{}', category='saml'),
        SystemSettings(key='saml_auto_provision', value='true', category='saml'),
        SystemSettings(key='saml_update_user_info', value='true', category='saml'),
    ]
    for s in settings:
        db_session.add(s)
    db_session.commit()


# ---------------------------------------------------------------------------
# SAML Manager unit tests
# ---------------------------------------------------------------------------

class TestSamlManagerIsAvailable:
    """Tests for is_saml_available()."""

    def test_is_saml_available_returns_bool(self, app):
        """is_saml_available() must return the module-level SAML_AVAILABLE flag."""
        from app.saml_manager import is_saml_available, SAML_AVAILABLE
        assert is_saml_available() is SAML_AVAILABLE

    @patch('app.saml_manager.SAML_AVAILABLE', True)
    def test_is_saml_available_true_when_library_present(self, app):
        from app.saml_manager import is_saml_available
        assert is_saml_available() is True

    @patch('app.saml_manager.SAML_AVAILABLE', False)
    def test_is_saml_available_false_when_library_missing(self, app):
        from app.saml_manager import is_saml_available
        assert is_saml_available() is False


class TestPrepareFlaskRequest:
    """Tests for prepare_flask_request()."""

    def test_prepare_flask_request_https(self, app):
        """Should set 'https' to 'on' when scheme is https."""
        from app.saml_manager import prepare_flask_request

        with app.test_request_context('https://example.com/saml/acs', method='POST'):
            from flask import request
            result = prepare_flask_request(request)
            assert result['https'] == 'on'
            assert result['http_host'] == 'example.com'
            assert result['script_name'] == '/saml/acs'

    def test_prepare_flask_request_http(self, app):
        """Should set 'https' to 'off' when scheme is http."""
        from app.saml_manager import prepare_flask_request

        with app.test_request_context('http://localhost:5000/saml/login', method='GET'):
            from flask import request
            result = prepare_flask_request(request)
            assert result['https'] == 'off'
            assert result['http_host'] == 'localhost:5000'
            assert result['server_port'] == 5000

    def test_prepare_flask_request_includes_get_and_post_data(self, app):
        """Should carry query-string and form data through."""
        from app.saml_manager import prepare_flask_request

        with app.test_request_context(
            '/saml/acs?next=/dashboard',
            method='POST',
            data={'SAMLResponse': 'base64data'}
        ):
            from flask import request
            result = prepare_flask_request(request)
            assert 'next' in result['get_data']
            assert 'SAMLResponse' in result['post_data']


class TestGetSamlSettings:
    """Tests for get_saml_settings()."""

    @patch('app.saml_manager.SAML_AVAILABLE', False)
    def test_returns_empty_when_library_unavailable(self, app):
        from app.saml_manager import get_saml_settings
        assert get_saml_settings() == {}

    @patch('app.saml_manager.SAML_AVAILABLE', True)
    def test_returns_empty_when_saml_disabled(self, app, db_session):
        """When saml_enabled is false the function should return {}."""
        from app.saml_manager import get_saml_settings
        from app.models import SystemSettings

        db_session.add(SystemSettings(key='saml_enabled', value='false', category='saml'))
        db_session.commit()
        assert get_saml_settings() == {}

    @patch('app.saml_manager.SAML_AVAILABLE', True)
    def test_returns_empty_when_no_idp_metadata(self, app, db_session):
        """When saml_enabled is true but idp_metadata is empty, return {}."""
        from app.saml_manager import get_saml_settings
        from app.models import SystemSettings

        db_session.add(SystemSettings(key='saml_enabled', value='true', category='saml'))
        db_session.commit()
        assert get_saml_settings() == {}

    @patch('app.saml_manager.SAML_AVAILABLE', True)
    @patch('app.saml_manager.OneLogin_Saml2_IdPMetadataParser')
    def test_parses_xml_metadata(self, mock_parser, app, db_session):
        """Should call parse() for raw XML metadata."""
        from app.saml_manager import get_saml_settings

        mock_parser.parse.return_value = {
            'idp': {
                'entityId': 'https://idp.example.com',
                'singleSignOnService': {'url': 'https://idp.example.com/sso'}
            }
        }

        _enable_saml_settings(db_session)

        result = get_saml_settings()
        mock_parser.parse.assert_called_once()
        assert result['idp']['entityId'] == 'https://idp.example.com'
        assert result['sp']['entityId'] == 'sentrikat:test'

    @patch('app.saml_manager.SAML_AVAILABLE', True)
    @patch('app.saml_manager.OneLogin_Saml2_IdPMetadataParser')
    def test_parses_url_metadata(self, mock_parser, app, db_session):
        """Should call parse_remote() when metadata starts with http."""
        from app.saml_manager import get_saml_settings
        from app.models import SystemSettings

        mock_parser.parse_remote.return_value = {
            'idp': {'entityId': 'https://idp.example.com'}
        }

        db_session.add(SystemSettings(key='saml_enabled', value='true', category='saml'))
        db_session.add(SystemSettings(key='saml_idp_metadata', value='https://idp.example.com/metadata', category='saml'))
        db_session.add(SystemSettings(key='saml_sp_entity_id', value='sentrikat:test', category='saml'))
        db_session.add(SystemSettings(key='saml_sp_acs_url', value='http://localhost/saml/acs', category='saml'))
        db_session.commit()

        get_saml_settings()
        mock_parser.parse_remote.assert_called_once_with('https://idp.example.com/metadata')

    @patch('app.saml_manager.SAML_AVAILABLE', True)
    @patch('app.saml_manager.OneLogin_Saml2_IdPMetadataParser')
    def test_includes_sls_when_configured(self, mock_parser, app, db_session):
        """SLS URL should appear in sp settings only when configured."""
        from app.saml_manager import get_saml_settings

        mock_parser.parse.return_value = {'idp': {}}
        _enable_saml_settings(db_session)

        result = get_saml_settings()
        assert 'singleLogoutService' in result['sp']

    @patch('app.saml_manager.SAML_AVAILABLE', True)
    @patch('app.saml_manager.OneLogin_Saml2_IdPMetadataParser')
    def test_returns_empty_on_parse_error(self, mock_parser, app, db_session):
        """Should return {} when IdP metadata parsing throws."""
        from app.saml_manager import get_saml_settings

        mock_parser.parse.side_effect = Exception('Bad XML')
        _enable_saml_settings(db_session)

        assert get_saml_settings() == {}


class TestInitSamlAuth:
    """Tests for init_saml_auth()."""

    @patch('app.saml_manager.SAML_AVAILABLE', False)
    def test_returns_none_when_unavailable(self, app):
        from app.saml_manager import init_saml_auth
        with app.test_request_context('/saml/login'):
            from flask import request
            assert init_saml_auth(request) is None

    @patch('app.saml_manager.SAML_AVAILABLE', True)
    @patch('app.saml_manager.get_saml_settings', return_value={})
    def test_returns_none_when_not_configured(self, mock_settings, app):
        from app.saml_manager import init_saml_auth
        with app.test_request_context('/saml/login'):
            from flask import request
            assert init_saml_auth(request) is None

    @patch('app.saml_manager.SAML_AVAILABLE', True)
    @patch('app.saml_manager.get_saml_settings', return_value={'sp': {}, 'idp': {}})
    @patch('app.saml_manager.OneLogin_Saml2_Auth')
    def test_returns_auth_object(self, mock_auth_cls, mock_settings, app):
        """Should return a OneLogin_Saml2_Auth instance when everything is configured."""
        from app.saml_manager import init_saml_auth
        mock_auth_cls.return_value = MagicMock()

        with app.test_request_context('/saml/login'):
            from flask import request
            auth = init_saml_auth(request)
            assert auth is not None
            mock_auth_cls.assert_called_once()

    @patch('app.saml_manager.SAML_AVAILABLE', True)
    @patch('app.saml_manager.get_saml_settings', return_value={'sp': {}, 'idp': {}})
    @patch('app.saml_manager.OneLogin_Saml2_Auth', side_effect=Exception('Init failed'))
    def test_returns_none_on_exception(self, mock_auth_cls, mock_settings, app):
        from app.saml_manager import init_saml_auth
        with app.test_request_context('/saml/login'):
            from flask import request
            assert init_saml_auth(request) is None


class TestGenerateLoginUrl:
    """Tests for generate_login_url()."""

    @patch('app.saml_manager.init_saml_auth', return_value=None)
    def test_returns_none_when_auth_unavailable(self, mock_init, app):
        from app.saml_manager import generate_login_url
        with app.test_request_context('/saml/login'):
            from flask import request
            assert generate_login_url(request) is None

    @patch('app.saml_manager.init_saml_auth')
    def test_returns_idp_url(self, mock_init, app):
        from app.saml_manager import generate_login_url

        mock_auth = MagicMock()
        mock_auth.login.return_value = 'https://idp.example.com/sso?SAMLRequest=xxx'
        mock_init.return_value = mock_auth

        with app.test_request_context('/saml/login'):
            from flask import request
            url = generate_login_url(request, return_to='/dashboard')
            assert url == 'https://idp.example.com/sso?SAMLRequest=xxx'
            mock_auth.login.assert_called_once_with(return_to='/dashboard')

    @patch('app.saml_manager.init_saml_auth')
    def test_returns_none_on_exception(self, mock_init, app):
        from app.saml_manager import generate_login_url
        mock_auth = MagicMock()
        mock_auth.login.side_effect = Exception('boom')
        mock_init.return_value = mock_auth

        with app.test_request_context('/saml/login'):
            from flask import request
            assert generate_login_url(request) is None


class TestProcessSamlResponse:
    """Tests for process_saml_response()."""

    @patch('app.saml_manager.init_saml_auth', return_value=None)
    def test_returns_failure_when_not_configured(self, mock_init, app):
        from app.saml_manager import process_saml_response
        with app.test_request_context('/saml/acs', method='POST'):
            from flask import request
            success, data, error = process_saml_response(request)
            assert success is False
            assert data is None
            assert error == "SAML not configured"

    @patch('app.saml_manager.init_saml_auth')
    def test_returns_failure_on_validation_errors(self, mock_init, app):
        from app.saml_manager import process_saml_response

        mock_auth = MagicMock()
        mock_auth.get_errors.return_value = ['invalid_response']
        mock_auth.get_last_error_reason.return_value = 'Signature mismatch'
        mock_init.return_value = mock_auth

        with app.test_request_context('/saml/acs', method='POST'):
            from flask import request
            success, data, error = process_saml_response(request)
            assert success is False
            assert 'Signature mismatch' in error

    @patch('app.saml_manager.init_saml_auth')
    def test_returns_failure_when_not_authenticated(self, mock_init, app):
        from app.saml_manager import process_saml_response

        mock_auth = MagicMock()
        mock_auth.get_errors.return_value = []
        mock_auth.is_authenticated.return_value = False
        mock_init.return_value = mock_auth

        with app.test_request_context('/saml/acs', method='POST'):
            from flask import request
            success, data, error = process_saml_response(request)
            assert success is False
            assert error == "Authentication failed"

    @patch('app.saml_manager.init_saml_auth')
    def test_extracts_user_data_successfully(self, mock_init, app, db_session):
        """Full happy-path: authenticated response -> user_data dict."""
        from app.saml_manager import process_saml_response

        mock_auth = MagicMock()
        mock_auth.get_errors.return_value = []
        mock_auth.is_authenticated.return_value = True
        mock_auth.get_nameid.return_value = 'jane@example.com'
        mock_auth.get_session_index.return_value = '_session123'
        mock_auth.get_attributes.return_value = {
            'email': ['jane@example.com'],
            'firstName': ['Jane'],
            'lastName': ['Doe'],
            'displayName': ['Jane Doe']
        }
        mock_init.return_value = mock_auth

        with app.test_request_context('/saml/acs', method='POST'):
            from flask import request
            success, data, error = process_saml_response(request)

        assert success is True
        assert error is None
        assert data['email'] == 'jane@example.com'
        assert data['first_name'] == 'Jane'
        assert data['last_name'] == 'Doe'
        assert data['display_name'] == 'Jane Doe'
        assert data['name_id'] == 'jane@example.com'
        assert data['session_index'] == '_session123'

    @patch('app.saml_manager.init_saml_auth')
    def test_username_derived_from_email_when_missing(self, mock_init, app, db_session):
        """When no username attribute is present, derive it from email."""
        from app.saml_manager import process_saml_response

        mock_auth = MagicMock()
        mock_auth.get_errors.return_value = []
        mock_auth.is_authenticated.return_value = True
        mock_auth.get_nameid.return_value = 'bob@corp.com'
        mock_auth.get_session_index.return_value = None
        mock_auth.get_attributes.return_value = {}
        mock_init.return_value = mock_auth

        with app.test_request_context('/saml/acs', method='POST'):
            from flask import request
            success, data, _ = process_saml_response(request)

        assert success is True
        assert data['username'] == 'bob'
        # email should fall back to name_id when no email attribute
        assert data['email'] == 'bob@corp.com'

    @patch('app.saml_manager.init_saml_auth')
    def test_returns_failure_on_exception(self, mock_init, app):
        from app.saml_manager import process_saml_response

        mock_auth = MagicMock()
        mock_auth.process_response.side_effect = Exception('XML parsing failed')
        mock_init.return_value = mock_auth

        with app.test_request_context('/saml/acs', method='POST'):
            from flask import request
            success, data, error = process_saml_response(request)
            assert success is False
            assert 'XML parsing failed' in error


class TestGetOrCreateSamlUser:
    """Tests for get_or_create_saml_user()."""

    def test_returns_none_when_email_missing(self, app, db_session):
        from app.saml_manager import get_or_create_saml_user
        user, created = get_or_create_saml_user({})
        assert user is None
        assert created is False

    def test_creates_new_user(self, app, db_session, test_org):
        """Should create a brand-new SAML user in the default org."""
        from app.saml_manager import get_or_create_saml_user
        from app.models import User

        user_data = {
            'email': 'newuser@saml.example.com',
            'username': 'newuser',
            'first_name': 'New',
            'last_name': 'User',
            'display_name': 'New User',
        }
        user, created = get_or_create_saml_user(user_data)
        assert created is True
        assert user is not None
        assert user.email == 'newuser@saml.example.com'
        assert user.auth_type == 'saml'
        assert user.role == 'viewer'
        assert user.is_active is True
        assert user.organization_id == test_org.id

    def test_returns_existing_user_by_email(self, app, db_session, test_org):
        """If a user with the same email already exists, return that user."""
        from app.saml_manager import get_or_create_saml_user
        from app.models import User

        existing = User(
            username='existinguser', email='existing@saml.example.com',
            auth_type='local', role='user', organization_id=test_org.id, is_active=True
        )
        db_session.add(existing)
        db_session.commit()

        user, created = get_or_create_saml_user({
            'email': 'existing@saml.example.com',
            'first_name': 'Updated',
            'last_name': 'Name',
        })
        assert created is False
        assert user.id == existing.id
        # auth_type should be updated to saml
        assert user.auth_type == 'saml'

    def test_unique_username_collision(self, app, db_session, test_org):
        """If the desired username already exists, a numeric suffix should be appended."""
        from app.saml_manager import get_or_create_saml_user
        from app.models import User

        # Create a user that occupies the 'alice' username
        existing = User(
            username='alice', email='alice-other@example.com',
            auth_type='local', role='user', organization_id=test_org.id, is_active=True
        )
        db_session.add(existing)
        db_session.commit()

        user, created = get_or_create_saml_user({
            'email': 'alice@saml.example.com',
            'username': 'alice',
        })
        assert created is True
        # Must have a different username
        assert user.username != 'alice'
        assert user.username.startswith('alice')

    def test_returns_none_when_no_organization(self, app, db_session):
        """If no organization exists at all, user creation should fail gracefully."""
        from app.saml_manager import get_or_create_saml_user
        from app.models import Organization

        # Ensure there is no org
        Organization.query.delete()
        db_session.commit()

        user, created = get_or_create_saml_user({
            'email': 'orphan@saml.example.com',
            'username': 'orphan',
        })
        assert user is None
        assert created is False

    def test_full_name_fallback_chain(self, app, db_session, test_org):
        """full_name should prefer display_name, then first+last, then username."""
        from app.saml_manager import get_or_create_saml_user

        # Case 1: display_name present
        user1, _ = get_or_create_saml_user({
            'email': 'dn@example.com', 'username': 'dn',
            'display_name': 'Display Name', 'first_name': 'F', 'last_name': 'L'
        })
        assert user1.full_name == 'Display Name'

        # Case 2: no display_name, first+last present
        user2, _ = get_or_create_saml_user({
            'email': 'fl@example.com', 'username': 'fl',
            'first_name': 'First', 'last_name': 'Last'
        })
        assert user2.full_name == 'First Last'

        # Case 3: nothing but username
        user3, _ = get_or_create_saml_user({
            'email': 'bare@example.com', 'username': 'bareuser',
        })
        assert user3.full_name == 'bareuser'


class TestGetSamlMetadata:
    """Tests for get_saml_metadata()."""

    @patch('app.saml_manager.SAML_AVAILABLE', False)
    def test_returns_none_when_unavailable(self, app):
        from app.saml_manager import get_saml_metadata
        assert get_saml_metadata() is None

    @patch('app.saml_manager.SAML_AVAILABLE', True)
    @patch('app.saml_manager.get_saml_settings', return_value={})
    def test_returns_none_when_not_configured(self, mock_settings, app):
        from app.saml_manager import get_saml_metadata
        assert get_saml_metadata() is None

    @patch('app.saml_manager.SAML_AVAILABLE', True)
    @patch('app.saml_manager.get_saml_settings', return_value={'sp': {}, 'idp': {}})
    @patch('app.saml_manager.OneLogin_Saml2_Settings')
    def test_returns_metadata_xml(self, mock_settings_cls, mock_get, app):
        mock_instance = MagicMock()
        mock_instance.get_sp_metadata.return_value = '<md:EntityDescriptor>...</md:EntityDescriptor>'
        mock_instance.validate_metadata.return_value = []
        mock_settings_cls.return_value = mock_instance

        from app.saml_manager import get_saml_metadata
        result = get_saml_metadata()
        assert result == '<md:EntityDescriptor>...</md:EntityDescriptor>'

    @patch('app.saml_manager.SAML_AVAILABLE', True)
    @patch('app.saml_manager.get_saml_settings', return_value={'sp': {}, 'idp': {}})
    @patch('app.saml_manager.OneLogin_Saml2_Settings', side_effect=Exception('bad settings'))
    def test_returns_none_on_exception(self, mock_cls, mock_get, app):
        from app.saml_manager import get_saml_metadata
        assert get_saml_metadata() is None


# ---------------------------------------------------------------------------
# SAML API route tests
# ---------------------------------------------------------------------------

class TestSamlSettingsGetRoute:
    """GET /api/settings/saml - admin only, requires professional license."""

    @patch('app.licensing.get_license')
    @patch('app.saml_api.is_saml_available', return_value=True)
    def test_returns_settings_for_admin(self, mock_avail, mock_lic, app, admin_client, db_session, setup_complete):
        mock_license = MagicMock()
        mock_license.is_professional.return_value = True
        mock_lic.return_value = mock_license

        _enable_saml_settings(db_session)
        resp = admin_client.get('/api/settings/saml')
        assert resp.status_code == 200
        data = resp.get_json()
        assert data['saml_available'] is True
        assert data['saml_enabled'] is True

    def test_rejects_unauthenticated_user(self, app, client, setup_complete):
        resp = client.get('/api/settings/saml')
        assert resp.status_code in (401, 302)

    @patch('app.licensing.get_license')
    def test_rejects_non_admin_user(self, mock_lic, app, authenticated_client, setup_complete):
        mock_license = MagicMock()
        mock_license.is_professional.return_value = True
        mock_lic.return_value = mock_license

        resp = authenticated_client.get('/api/settings/saml')
        assert resp.status_code in (403, 302)

    @patch('app.licensing.get_license')
    @patch('app.saml_api.is_saml_available', return_value=False)
    def test_includes_install_hint_when_unavailable(self, mock_avail, mock_lic, app, admin_client, db_session, setup_complete):
        mock_license = MagicMock()
        mock_license.is_professional.return_value = True
        mock_lic.return_value = mock_license

        resp = admin_client.get('/api/settings/saml')
        assert resp.status_code == 200
        data = resp.get_json()
        assert data['saml_available'] is False
        assert 'install_hint' in data
        assert 'python3-saml' in data['install_hint']


class TestSamlSettingsPostRoute:
    """POST /api/settings/saml - save settings."""

    @patch('app.licensing.get_license')
    @patch('app.saml_api.is_saml_available', return_value=True)
    def test_saves_settings_successfully(self, mock_avail, mock_lic, app, admin_client, db_session, setup_complete):
        mock_license = MagicMock()
        mock_license.is_professional.return_value = True
        mock_lic.return_value = mock_license

        resp = admin_client.post('/api/settings/saml', json={
            'saml_enabled': True,
            'saml_idp_metadata': '<xml>metadata</xml>',
            'saml_sp_entity_id': 'sentrikat:prod',
            'saml_sp_acs_url': 'https://app.example.com/saml/acs',
            'saml_auto_provision': True,
        })
        assert resp.status_code == 200
        data = resp.get_json()
        assert data['success'] is True

    @patch('app.licensing.get_license')
    @patch('app.saml_api.is_saml_available', return_value=False)
    def test_rejects_when_library_missing(self, mock_avail, mock_lic, app, admin_client, setup_complete):
        mock_license = MagicMock()
        mock_license.is_professional.return_value = True
        mock_lic.return_value = mock_license

        resp = admin_client.post('/api/settings/saml', json={'saml_enabled': True})
        assert resp.status_code == 400
        data = resp.get_json()
        assert data['success'] is False
        assert 'not installed' in data['error']

    @patch('app.licensing.get_license')
    @patch('app.saml_api.is_saml_available', return_value=True)
    @patch('app.saml_api.set_setting', side_effect=Exception('DB error'))
    def test_handles_save_error(self, mock_set, mock_avail, mock_lic, app, admin_client, setup_complete):
        mock_license = MagicMock()
        mock_license.is_professional.return_value = True
        mock_lic.return_value = mock_license

        resp = admin_client.post('/api/settings/saml', json={'saml_enabled': True})
        assert resp.status_code == 500
        data = resp.get_json()
        assert data['success'] is False


class TestSamlTestConfigRoute:
    """POST /api/settings/saml/test - validate IdP metadata."""

    @patch('app.licensing.get_license')
    @patch('app.saml_api.is_saml_available', return_value=False)
    def test_rejects_when_library_missing(self, mock_avail, mock_lic, app, admin_client, setup_complete):
        mock_license = MagicMock()
        mock_license.is_professional.return_value = True
        mock_lic.return_value = mock_license

        resp = admin_client.post('/api/settings/saml/test', json={})
        assert resp.status_code == 400

    @patch('app.licensing.get_license')
    @patch('app.saml_api.is_saml_available', return_value=True)
    @patch('app.saml_api.get_saml_settings', return_value={})
    def test_returns_error_when_not_configured(self, mock_settings, mock_avail, mock_lic, app, admin_client, setup_complete):
        mock_license = MagicMock()
        mock_license.is_professional.return_value = True
        mock_lic.return_value = mock_license

        resp = admin_client.post('/api/settings/saml/test', json={})
        assert resp.status_code == 400
        assert 'not configured' in resp.get_json()['error']

    @patch('app.licensing.get_license')
    @patch('app.saml_api.is_saml_available', return_value=True)
    @patch('app.saml_api.get_saml_settings')
    def test_validates_missing_entity_id(self, mock_settings, mock_avail, mock_lic, app, admin_client, setup_complete):
        mock_license = MagicMock()
        mock_license.is_professional.return_value = True
        mock_lic.return_value = mock_license
        mock_settings.return_value = {'idp': {'entityId': '', 'singleSignOnService': {'url': 'https://sso'}}}

        resp = admin_client.post('/api/settings/saml/test', json={})
        assert resp.status_code == 400
        assert 'Entity ID' in resp.get_json()['error']

    @patch('app.licensing.get_license')
    @patch('app.saml_api.is_saml_available', return_value=True)
    @patch('app.saml_api.get_saml_settings')
    def test_validates_missing_sso_url(self, mock_settings, mock_avail, mock_lic, app, admin_client, setup_complete):
        mock_license = MagicMock()
        mock_license.is_professional.return_value = True
        mock_lic.return_value = mock_license
        mock_settings.return_value = {'idp': {'entityId': 'https://idp', 'singleSignOnService': {'url': ''}}}

        resp = admin_client.post('/api/settings/saml/test', json={})
        assert resp.status_code == 400
        assert 'SSO URL' in resp.get_json()['error']

    @patch('app.licensing.get_license')
    @patch('app.saml_api.is_saml_available', return_value=True)
    @patch('app.saml_api.get_saml_settings')
    def test_reports_valid_configuration(self, mock_settings, mock_avail, mock_lic, app, admin_client, setup_complete):
        mock_license = MagicMock()
        mock_license.is_professional.return_value = True
        mock_lic.return_value = mock_license
        mock_settings.return_value = {
            'idp': {
                'entityId': 'https://idp.example.com',
                'singleSignOnService': {'url': 'https://idp.example.com/sso'}
            }
        }

        resp = admin_client.post('/api/settings/saml/test', json={})
        assert resp.status_code == 200
        data = resp.get_json()
        assert data['success'] is True
        assert data['idp_entity_id'] == 'https://idp.example.com'

    @patch('app.licensing.get_license')
    @patch('app.saml_api.is_saml_available', return_value=True)
    @patch('app.saml_api.get_saml_settings', side_effect=Exception('Unexpected'))
    def test_handles_exception(self, mock_settings, mock_avail, mock_lic, app, admin_client, setup_complete):
        mock_license = MagicMock()
        mock_license.is_professional.return_value = True
        mock_lic.return_value = mock_license

        resp = admin_client.post('/api/settings/saml/test', json={})
        assert resp.status_code == 500
        assert resp.get_json()['success'] is False


class TestSamlMetadataRoute:
    """GET /api/saml/metadata - public endpoint returning SP metadata XML."""

    @patch('app.saml_api.is_saml_available', return_value=False)
    def test_returns_503_when_unavailable(self, mock_avail, app, client, setup_complete):
        resp = client.get('/api/saml/metadata')
        assert resp.status_code == 503

    @patch('app.saml_api.is_saml_available', return_value=True)
    @patch('app.saml_api.get_saml_metadata', return_value=None)
    def test_returns_404_when_not_configured(self, mock_meta, mock_avail, app, client, setup_complete):
        resp = client.get('/api/saml/metadata')
        assert resp.status_code == 404

    @patch('app.saml_api.is_saml_available', return_value=True)
    @patch('app.saml_api.get_saml_metadata', return_value='<md:EntityDescriptor/>')
    def test_returns_xml_metadata(self, mock_meta, mock_avail, app, client, setup_complete):
        resp = client.get('/api/saml/metadata')
        assert resp.status_code == 200
        assert resp.content_type == 'application/xml'
        assert b'EntityDescriptor' in resp.data


class TestSamlLoginRoute:
    """GET /saml/login - initiate SAML login flow."""

    @patch('app.saml_api.is_saml_available', return_value=False)
    def test_redirects_when_unavailable(self, mock_avail, app, client, setup_complete):
        resp = client.get('/saml/login')
        assert resp.status_code == 302
        assert 'saml_unavailable' in resp.headers['Location']

    @patch('app.saml_api.is_saml_available', return_value=True)
    @patch('app.saml_api.get_setting', return_value='false')
    def test_redirects_when_disabled(self, mock_setting, mock_avail, app, client, setup_complete):
        resp = client.get('/saml/login')
        assert resp.status_code == 302
        assert 'saml_disabled' in resp.headers['Location']

    @patch('app.saml_api.is_saml_available', return_value=True)
    @patch('app.saml_api.get_setting', return_value='true')
    @patch('app.saml_api.generate_login_url', return_value=None)
    def test_redirects_on_config_error(self, mock_gen, mock_setting, mock_avail, app, client, setup_complete):
        resp = client.get('/saml/login')
        assert resp.status_code == 302
        assert 'saml_config' in resp.headers['Location']

    @patch('app.saml_api.is_saml_available', return_value=True)
    @patch('app.saml_api.get_setting', return_value='true')
    @patch('app.saml_api.generate_login_url', return_value='https://idp.example.com/sso?SAMLRequest=abc')
    def test_redirects_to_idp(self, mock_gen, mock_setting, mock_avail, app, client, setup_complete):
        resp = client.get('/saml/login')
        assert resp.status_code == 302
        assert resp.headers['Location'] == 'https://idp.example.com/sso?SAMLRequest=abc'


class TestSamlAcsRoute:
    """POST /saml/acs - Assertion Consumer Service."""

    @patch('app.saml_api.is_saml_available', return_value=False)
    def test_redirects_when_unavailable(self, mock_avail, app, client, setup_complete):
        resp = client.post('/saml/acs', data={})
        assert resp.status_code == 302
        assert 'saml_unavailable' in resp.headers['Location']

    @patch('app.saml_api.is_saml_available', return_value=True)
    @patch('app.saml_api.get_setting', return_value='false')
    def test_redirects_when_disabled(self, mock_setting, mock_avail, app, client, setup_complete):
        resp = client.post('/saml/acs', data={})
        assert resp.status_code == 302
        assert 'saml_disabled' in resp.headers['Location']

    @patch('app.saml_api.log_user_login')
    @patch('app.saml_api.login_user_session')
    @patch('app.saml_api.get_or_create_saml_user')
    @patch('app.saml_api.process_saml_response')
    @patch('app.saml_api.is_saml_available', return_value=True)
    @patch('app.saml_api.get_setting')
    def test_successful_login_redirects_to_dashboard(
        self, mock_setting, mock_avail, mock_process, mock_get_user,
        mock_login, mock_audit, app, client, db_session, test_org, setup_complete
    ):
        """Happy path: valid SAML response -> session created -> redirect to dashboard."""
        from app.models import User

        mock_setting.side_effect = lambda key, default='': {
            'saml_enabled': 'true',
            'saml_auto_provision': 'true',
        }.get(key, default)

        user = User(
            username='samluser', email='saml@example.com',
            auth_type='saml', role='viewer', organization_id=test_org.id, is_active=True
        )
        db_session.add(user)
        db_session.commit()

        mock_process.return_value = (True, {'email': 'saml@example.com', 'username': 'samluser'}, None)
        mock_get_user.return_value = (user, False)

        resp = client.post('/saml/acs', data={'SAMLResponse': 'base64data'})
        assert resp.status_code == 302
        assert '/dashboard' in resp.headers['Location'] or resp.headers['Location'].endswith('/')
        mock_login.assert_called_once_with(user)

    @patch('app.saml_api.login_user_session')
    @patch('app.saml_api.get_or_create_saml_user')
    @patch('app.saml_api.process_saml_response')
    @patch('app.saml_api.is_saml_available', return_value=True)
    @patch('app.saml_api.get_setting')
    def test_relay_state_redirect(
        self, mock_setting, mock_avail, mock_process, mock_get_user,
        mock_login, app, client, db_session, test_org, setup_complete
    ):
        """If RelayState is present and starts with /, redirect there."""
        from app.models import User

        mock_setting.side_effect = lambda key, default='': {
            'saml_enabled': 'true',
            'saml_auto_provision': 'true',
        }.get(key, default)

        user = User(
            username='relayuser', email='relay@example.com',
            auth_type='saml', role='viewer', organization_id=test_org.id, is_active=True
        )
        db_session.add(user)
        db_session.commit()

        mock_process.return_value = (True, {'email': 'relay@example.com'}, None)
        mock_get_user.return_value = (user, False)

        resp = client.post('/saml/acs', data={
            'SAMLResponse': 'base64data',
            'RelayState': '/products'
        })
        assert resp.status_code == 302
        assert '/products' in resp.headers['Location']

    @patch('app.saml_api.process_saml_response')
    @patch('app.saml_api.is_saml_available', return_value=True)
    @patch('app.saml_api.get_setting', return_value='true')
    def test_auth_failure_redirects_to_login(self, mock_setting, mock_avail, mock_process, app, client, setup_complete):
        mock_process.return_value = (False, None, 'Signature validation failed')

        resp = client.post('/saml/acs', data={'SAMLResponse': 'bad'})
        assert resp.status_code == 302
        assert 'saml_auth_failed' in resp.headers['Location']

    @patch('app.saml_api.process_saml_response')
    @patch('app.saml_api.is_saml_available', return_value=True)
    @patch('app.saml_api.get_setting')
    def test_auto_provision_disabled_rejects_unknown_user(
        self, mock_setting, mock_avail, mock_process, app, client, db_session, setup_complete
    ):
        """When auto_provision is off and user does not exist, redirect with saml_user_not_found."""
        mock_setting.side_effect = lambda key, default='': {
            'saml_enabled': 'true',
            'saml_auto_provision': 'false',
        }.get(key, default)

        mock_process.return_value = (True, {'email': 'unknown@corp.com'}, None)

        resp = client.post('/saml/acs', data={'SAMLResponse': 'base64data'})
        assert resp.status_code == 302
        assert 'saml_user_not_found' in resp.headers['Location']

    @patch('app.saml_api.login_user_session')
    @patch('app.saml_api.get_or_create_saml_user')
    @patch('app.saml_api.process_saml_response')
    @patch('app.saml_api.is_saml_available', return_value=True)
    @patch('app.saml_api.get_setting')
    def test_user_create_failure_redirects(
        self, mock_setting, mock_avail, mock_process, mock_get_user,
        mock_login, app, client, setup_complete
    ):
        mock_setting.side_effect = lambda key, default='': {
            'saml_enabled': 'true',
            'saml_auto_provision': 'true',
        }.get(key, default)

        mock_process.return_value = (True, {'email': 'fail@corp.com'}, None)
        mock_get_user.return_value = (None, False)

        resp = client.post('/saml/acs', data={'SAMLResponse': 'base64data'})
        assert resp.status_code == 302
        assert 'saml_user_create_failed' in resp.headers['Location']


class TestSamlSlsRoute:
    """GET/POST /saml/sls - Single Logout Service.

    This class specifically verifies the bug fix: session.clear() is used
    instead of the non-existent logout_user() function.
    """

    @patch('app.saml_api.is_saml_available', return_value=False)
    def test_redirects_to_login_when_unavailable(self, mock_avail, app, client, setup_complete):
        resp = client.get('/saml/sls')
        assert resp.status_code == 302

    @patch('app.saml_api.init_saml_auth', return_value=None)
    @patch('app.saml_api.is_saml_available', return_value=True)
    def test_clears_session_when_auth_init_fails(self, mock_avail, mock_init, app, client, setup_complete):
        """When init_saml_auth returns None, session.clear() should be called (not logout_user)."""
        with client.session_transaction() as sess:
            sess['user_id'] = 999
            sess['_fresh'] = True

        resp = client.get('/saml/sls')
        assert resp.status_code == 302

        # Verify session was cleared
        with client.session_transaction() as sess:
            assert 'user_id' not in sess

    @patch('app.saml_api.init_saml_auth')
    @patch('app.saml_api.is_saml_available', return_value=True)
    def test_processes_slo_and_clears_session(self, mock_avail, mock_init, app, client, setup_complete):
        """Successful SLO processing should clear the session."""
        mock_auth = MagicMock()
        mock_auth.process_slo.return_value = None
        mock_auth.get_errors.return_value = []
        mock_init.return_value = mock_auth

        with client.session_transaction() as sess:
            sess['user_id'] = 42

        resp = client.get('/saml/sls')
        assert resp.status_code == 302
        mock_auth.process_slo.assert_called_once()

        with client.session_transaction() as sess:
            assert 'user_id' not in sess

    @patch('app.saml_api.init_saml_auth')
    @patch('app.saml_api.is_saml_available', return_value=True)
    def test_follows_slo_redirect_url(self, mock_avail, mock_init, app, client, setup_complete):
        """If process_slo returns a URL, redirect there."""
        mock_auth = MagicMock()
        mock_auth.process_slo.return_value = 'https://idp.example.com/logout-complete'
        mock_auth.get_errors.return_value = []
        mock_init.return_value = mock_auth

        resp = client.get('/saml/sls')
        assert resp.status_code == 302
        assert resp.headers['Location'] == 'https://idp.example.com/logout-complete'

    @patch('app.saml_api.init_saml_auth')
    @patch('app.saml_api.is_saml_available', return_value=True)
    def test_handles_slo_exception_gracefully(self, mock_avail, mock_init, app, client, setup_complete):
        """On exception during SLO, session should still be cleared."""
        mock_auth = MagicMock()
        mock_auth.process_slo.side_effect = Exception('SLO processing error')
        mock_init.return_value = mock_auth

        with client.session_transaction() as sess:
            sess['user_id'] = 42

        resp = client.get('/saml/sls')
        assert resp.status_code == 302

        with client.session_transaction() as sess:
            assert 'user_id' not in sess

    @patch('app.saml_api.init_saml_auth')
    @patch('app.saml_api.is_saml_available', return_value=True)
    def test_sls_does_not_call_logout_user(self, mock_avail, mock_init, app, client, setup_complete):
        """Regression test: ensure the route uses session.clear() NOT logout_user()."""
        import app.saml_api as saml_module

        # Verify logout_user is not referenced in the module at function level
        assert not hasattr(saml_module, 'logout_user'), (
            "saml_api should not import or define logout_user; "
            "the SLS route must use session.clear() instead"
        )

    def test_sls_accepts_post(self, app, client, setup_complete):
        """The /saml/sls route should accept POST as well as GET."""
        with patch('app.saml_api.is_saml_available', return_value=False):
            resp = client.post('/saml/sls')
            assert resp.status_code == 302


class TestSamlStatusRoute:
    """GET /api/saml/status - public endpoint for login page."""

    @patch('app.saml_api.is_saml_available', return_value=False)
    def test_disabled_when_library_missing(self, mock_avail, app, client, db_session, setup_complete):
        resp = client.get('/api/saml/status')
        assert resp.status_code == 200
        data = resp.get_json()
        assert data['enabled'] is False
        assert data['login_url'] is None

    @patch('app.saml_api.is_saml_available', return_value=True)
    def test_enabled_when_configured(self, mock_avail, app, client, db_session, setup_complete):
        _enable_saml_settings(db_session)

        resp = client.get('/api/saml/status')
        assert resp.status_code == 200
        data = resp.get_json()
        assert data['enabled'] is True
        assert data['login_url'] is not None
        assert '/saml/login' in data['login_url']

    @patch('app.saml_api.is_saml_available', return_value=True)
    def test_disabled_when_setting_is_false(self, mock_avail, app, client, db_session, setup_complete):
        from app.models import SystemSettings
        db_session.add(SystemSettings(key='saml_enabled', value='false', category='saml'))
        db_session.commit()

        resp = client.get('/api/saml/status')
        data = resp.get_json()
        assert data['enabled'] is False


class TestCsrfExemption:
    """Verify that SAML blueprint is exempt from CSRF."""

    def test_saml_blueprint_is_csrf_exempt(self, app):
        """The SAML blueprint should be registered and CSRF-exempt so IdP can POST."""
        from app.saml_api import saml_bp
        # The blueprint exists and was passed to csrf.exempt() at module level.
        # We verify it by confirming the ACS POST works without a CSRF token
        # even when WTF_CSRF_ENABLED is True (in production).
        assert saml_bp.name == 'saml'

    @patch('app.saml_api.is_saml_available', return_value=False)
    def test_acs_post_without_csrf_token_succeeds(self, mock_avail, app, setup_complete):
        """POST to /saml/acs should not require a CSRF token."""
        # Enable CSRF for this specific test to prove exemption
        app.config['WTF_CSRF_ENABLED'] = True
        client = app.test_client()
        resp = client.post('/saml/acs', data={'SAMLResponse': 'test'})
        # Should get a redirect (302), not a CSRF 400 error
        assert resp.status_code == 302


class TestSamlUserProvisioning:
    """Integration-level tests for user auto-provisioning via SAML attributes."""

    def test_new_user_gets_viewer_role(self, app, db_session, test_org):
        """Auto-provisioned SAML users should receive the 'viewer' role."""
        from app.saml_manager import get_or_create_saml_user
        user, created = get_or_create_saml_user({
            'email': 'viewer@company.com',
            'username': 'viewer',
        })
        assert created is True
        assert user.role == 'viewer'

    def test_existing_user_info_updated_on_login(self, app, db_session, test_org):
        """When an existing user logs in via SAML, their profile should be updated."""
        from app.saml_manager import get_or_create_saml_user
        from app.models import User

        user = User(
            username='updateme', email='update@company.com',
            auth_type='local', role='user', organization_id=test_org.id, is_active=True
        )
        db_session.add(user)
        db_session.commit()

        returned, created = get_or_create_saml_user({
            'email': 'update@company.com',
            'first_name': 'Updated',
            'last_name': 'Name',
            'display_name': 'Updated Name',
        })
        assert created is False
        assert returned.id == user.id
        assert returned.auth_type == 'saml'
        assert returned.last_login is not None

    def test_username_derived_from_email_when_absent(self, app, db_session, test_org):
        """If no username is provided, the local part of the email should be used."""
        from app.saml_manager import get_or_create_saml_user
        user, created = get_or_create_saml_user({
            'email': 'auto.derived@company.com',
        })
        assert created is True
        assert user.username == 'auto.derived'

    def test_specific_default_org_id(self, app, db_session):
        """When saml_default_org_id is set, new users should be assigned to that org."""
        from app.saml_manager import get_or_create_saml_user
        from app.models import Organization, SystemSettings

        org_a = Organization(name='OrgA', display_name='Org A', active=True)
        org_b = Organization(name='OrgB', display_name='Org B', active=True)
        db_session.add_all([org_a, org_b])
        db_session.flush()

        db_session.add(SystemSettings(
            key='saml_default_org_id', value=str(org_b.id), category='saml'
        ))
        db_session.commit()

        user, created = get_or_create_saml_user({
            'email': 'orgb@company.com',
            'username': 'orgbuser',
        })
        assert created is True
        assert user.organization_id == org_b.id
