"""
Tests for app/provisioning.py - Tenant provisioning service.

Covers:
- validate_org_name() input validation
- provision_tenant() full lifecycle (org + user + API key creation)
- deprovision_tenant() tenant removal
- Welcome email sending with mocked SMTP
- License limit enforcement
"""
import pytest
from unittest.mock import patch, MagicMock

from app.provisioning import validate_org_name, provision_tenant, deprovision_tenant, ProvisioningError


# ---------------------------------------------------------------------------
# validate_org_name() tests
# ---------------------------------------------------------------------------

class TestValidateOrgName:
    """Tests for organization name validation rules."""

    def test_valid_simple_name(self):
        """Lowercase alpha name within length bounds is accepted."""
        valid, error = validate_org_name('acme')
        assert valid is True
        assert error is None

    def test_valid_name_with_hyphens_and_underscores(self):
        """Names containing hyphens and underscores are accepted."""
        valid, error = validate_org_name('acme-corp_01')
        assert valid is True
        assert error is None

    def test_valid_minimum_length(self):
        """A 3-character name is the shortest allowed."""
        valid, error = validate_org_name('abc')
        assert valid is True
        assert error is None

    def test_valid_maximum_length(self):
        """A 100-character name is the longest allowed."""
        name = 'a' * 100
        valid, error = validate_org_name(name)
        assert valid is True
        assert error is None

    def test_too_short(self):
        """Names shorter than 3 characters are rejected."""
        valid, error = validate_org_name('ab')
        assert valid is False
        assert '3-100' in error

    def test_too_long(self):
        """Names longer than 100 characters are rejected."""
        name = 'a' * 101
        valid, error = validate_org_name(name)
        assert valid is False
        assert '3-100' in error

    def test_empty_string(self):
        """Empty string is rejected."""
        valid, error = validate_org_name('')
        assert valid is False

    def test_none_value(self):
        """None is rejected."""
        valid, error = validate_org_name(None)
        assert valid is False

    def test_must_start_with_letter(self):
        """Names starting with a digit are rejected."""
        valid, error = validate_org_name('1acme')
        assert valid is False
        assert 'start with a letter' in error

    def test_must_start_with_letter_hyphen(self):
        """Names starting with a hyphen are rejected."""
        valid, error = validate_org_name('-acme')
        assert valid is False

    def test_uppercase_rejected(self):
        """Uppercase letters are not allowed."""
        valid, error = validate_org_name('Acme')
        assert valid is False
        assert 'lowercase' in error

    def test_spaces_rejected(self):
        """Spaces are not allowed."""
        valid, error = validate_org_name('acme corp')
        assert valid is False

    def test_special_chars_rejected(self):
        """Special characters like @, !, . are not allowed."""
        for char in ['@', '!', '.', '#', '$', '%']:
            valid, error = validate_org_name(f'acme{char}corp')
            assert valid is False, f"Character '{char}' should be rejected"


# ---------------------------------------------------------------------------
# provision_tenant() tests
# ---------------------------------------------------------------------------

class TestProvisionTenant:
    """Tests for full tenant provisioning lifecycle."""

    VALID_PARAMS = {
        'org_name': 'newcorp',
        'org_display_name': 'New Corp',
        'admin_username': 'admin@newcorp.com',
        'admin_email': 'admin@newcorp.com',
        'admin_password': 'securepass123',
    }

    def test_successful_provision(self, app):
        """Successful provisioning creates org, admin user, and API key."""
        from app.models import Organization, User, AgentApiKey

        result = provision_tenant(**self.VALID_PARAMS)

        assert result['success'] is True

        # Verify organization was created
        org = Organization.query.filter_by(name='newcorp').first()
        assert org is not None
        assert org.display_name == 'New Corp'
        assert org.active is True
        assert result['organization']['id'] == org.id
        assert result['organization']['name'] == 'newcorp'

        # Verify admin user was created
        user = User.query.filter_by(username='admin@newcorp.com').first()
        assert user is not None
        assert user.email == 'admin@newcorp.com'
        assert user.organization_id == org.id
        assert user.role == 'org_admin'
        assert user.is_admin is True
        assert user.is_active is True
        assert result['admin_user']['id'] == user.id

        # Verify API key was created
        api_key = AgentApiKey.query.filter_by(organization_id=org.id).first()
        assert api_key is not None
        assert api_key.active is True
        assert result['api_key']['id'] == api_key.id
        assert result['api_key']['key'] is not None  # raw key returned on creation

    def test_provision_returns_raw_api_key(self, app):
        """The raw API key is returned in the result only at creation time."""
        result = provision_tenant(**self.VALID_PARAMS)
        raw_key = result['api_key']['key']
        assert raw_key.startswith('sk_agent_')
        assert len(raw_key) > 20

    def test_provision_creates_user_organization_membership(self, app):
        """Provisioning creates a UserOrganization join record."""
        from app.models import UserOrganization

        result = provision_tenant(**self.VALID_PARAMS)
        org_id = result['organization']['id']
        user_id = result['admin_user']['id']

        membership = UserOrganization.query.filter_by(
            user_id=user_id, organization_id=org_id
        ).first()
        assert membership is not None
        assert membership.role == 'org_admin'

    def test_provision_with_description_and_notifications(self, app):
        """Optional description and notification_emails are stored."""
        from app.models import Organization
        import json

        params = {**self.VALID_PARAMS, 'org_description': 'Test desc', 'notification_emails': ['a@b.com']}
        result = provision_tenant(**params)

        org = Organization.query.get(result['organization']['id'])
        assert org.description == 'Test desc'
        assert json.loads(org.notification_emails) == ['a@b.com']

    def test_duplicate_org_name_raises(self, app):
        """Provisioning with an existing org name raises ProvisioningError."""
        provision_tenant(**self.VALID_PARAMS)

        with pytest.raises(ProvisioningError, match="already exists"):
            provision_tenant(
                org_name='newcorp',
                org_display_name='Another Corp',
                admin_username='other@newcorp.com',
                admin_email='other@newcorp.com',
                admin_password='securepass123',
            )

    def test_duplicate_email_raises(self, app):
        """Provisioning with an existing email raises ProvisioningError."""
        provision_tenant(**self.VALID_PARAMS)

        with pytest.raises(ProvisioningError, match="already exists"):
            provision_tenant(
                org_name='anothercorp',
                org_display_name='Another Corp',
                admin_username='unique_user',
                admin_email='admin@newcorp.com',
                admin_password='securepass123',
            )

    def test_duplicate_username_raises(self, app):
        """Provisioning with an existing username raises ProvisioningError."""
        provision_tenant(**self.VALID_PARAMS)

        with pytest.raises(ProvisioningError, match="already exists"):
            provision_tenant(
                org_name='anothercorp',
                org_display_name='Another Corp',
                admin_username='admin@newcorp.com',  # same username
                admin_email='different@newcorp.com',
                admin_password='securepass123',
            )

    def test_invalid_org_name_raises(self, app):
        """Invalid org name is caught before any DB work."""
        with pytest.raises(ProvisioningError, match="3-100 characters"):
            provision_tenant(
                org_name='ab',  # too short
                org_display_name='AB',
                admin_username='admin@ab.com',
                admin_email='admin@ab.com',
                admin_password='securepass123',
            )

    def test_short_username_raises(self, app):
        """Username shorter than 3 characters is rejected."""
        with pytest.raises(ProvisioningError, match="at least 3 characters"):
            provision_tenant(
                org_name='validcorp',
                org_display_name='Valid Corp',
                admin_username='ab',
                admin_email='admin@valid.com',
                admin_password='securepass123',
            )

    def test_invalid_email_raises(self, app):
        """Email without @ is rejected."""
        with pytest.raises(ProvisioningError, match="email"):
            provision_tenant(
                org_name='validcorp',
                org_display_name='Valid Corp',
                admin_username='adminuser',
                admin_email='not-an-email',
                admin_password='securepass123',
            )

    def test_short_password_raises(self, app):
        """Password shorter than 8 characters is rejected."""
        with pytest.raises(ProvisioningError, match="at least 8 characters"):
            provision_tenant(
                org_name='validcorp',
                org_display_name='Valid Corp',
                admin_username='adminuser',
                admin_email='admin@valid.com',
                admin_password='short',
            )

    def test_rollback_on_failure(self, app):
        """If provisioning fails mid-way, all changes are rolled back."""
        from app.models import Organization, User

        # Patch AgentApiKey.generate_key to raise an error after org + user are flushed
        with patch('app.provisioning.AgentApiKey.generate_key', side_effect=RuntimeError('key gen failed')):
            with pytest.raises(ProvisioningError, match="Provisioning failed"):
                provision_tenant(**self.VALID_PARAMS)

        # Verify nothing was persisted
        assert Organization.query.filter_by(name='newcorp').first() is None
        assert User.query.filter_by(username='admin@newcorp.com').first() is None

    def test_provision_default_alert_settings(self, app):
        """Provisioned org gets sensible default alert settings."""
        from app.models import Organization

        result = provision_tenant(**self.VALID_PARAMS)
        org = Organization.query.get(result['organization']['id'])

        assert org.alert_on_critical is True
        assert org.alert_on_high is False
        assert org.alert_on_new_cve is True
        assert org.alert_on_ransomware is True
        assert org.alert_days == 'mon,tue,wed,thu,fri'


# ---------------------------------------------------------------------------
# deprovision_tenant() tests
# ---------------------------------------------------------------------------

class TestDeprovisionTenant:
    """Tests for tenant removal."""

    def _create_tenant(self, app):
        """Helper: provision a tenant and return the result."""
        return provision_tenant(
            org_name='removeme',
            org_display_name='Remove Me',
            admin_username='admin@removeme.com',
            admin_email='admin@removeme.com',
            admin_password='securepass123',
        )

    def test_successful_deprovision(self, app):
        """Deprovisioning removes the organization and all related data."""
        from app.models import Organization

        result = self._create_tenant(app)
        org_id = result['organization']['id']

        deprov = deprovision_tenant(org_id, confirm_name='removeme')
        assert deprov['success'] is True

        # Org should be gone
        assert Organization.query.get(org_id) is None

    def test_deprovision_removes_users(self, app):
        """Deprovisioning cascades to remove associated users."""
        from app.models import User

        result = self._create_tenant(app)
        org_id = result['organization']['id']
        user_id = result['admin_user']['id']

        deprovision_tenant(org_id, confirm_name='removeme')
        assert User.query.get(user_id) is None

    def test_deprovision_nonexistent_org_raises(self, app):
        """Attempting to deprovision a non-existent org raises an error."""
        with pytest.raises(ProvisioningError, match="not found"):
            deprovision_tenant(99999)

    def test_deprovision_name_mismatch_raises(self, app):
        """Safety check: confirm_name must match the org name."""
        result = self._create_tenant(app)
        org_id = result['organization']['id']

        with pytest.raises(ProvisioningError, match="does not match"):
            deprovision_tenant(org_id, confirm_name='wrong-name')

    def test_deprovision_without_confirm_name(self, app):
        """Deprovisioning without confirm_name skips the name check."""
        from app.models import Organization

        result = self._create_tenant(app)
        org_id = result['organization']['id']

        deprov = deprovision_tenant(org_id)
        assert deprov['success'] is True
        assert Organization.query.get(org_id) is None


# ---------------------------------------------------------------------------
# Welcome email tests (mocked SMTP)
# ---------------------------------------------------------------------------

class TestWelcomeEmail:
    """Tests for _send_welcome_email via provision_tenant with send_welcome_email=True."""

    VALID_PARAMS = {
        'org_name': 'emailcorp',
        'org_display_name': 'Email Corp',
        'admin_username': 'admin@emailcorp.com',
        'admin_email': 'admin@emailcorp.com',
        'admin_password': 'securepass123',
        'send_welcome_email': True,
    }

    def test_welcome_email_sent(self, app):
        """When SMTP is configured, welcome email is sent and flag is set."""
        settings = {
            'smtp_host': 'mail.test.local',
            'smtp_port': '587',
            'smtp_username': 'smtp_user',
            'smtp_password': 'smtp_pass',
            'smtp_use_tls': 'true',
            'smtp_from_email': 'noreply@test.local',
            'smtp_from_name': 'SentriKat',
        }

        mock_server = MagicMock()

        with patch('app.settings_api.get_setting', side_effect=lambda key, default=None: settings.get(key, default)):
            with patch('smtplib.SMTP', return_value=mock_server):
                result = provision_tenant(**self.VALID_PARAMS)

        assert result['welcome_email_sent'] is True
        mock_server.starttls.assert_called_once()
        mock_server.login.assert_called_once_with('smtp_user', 'smtp_pass')
        mock_server.sendmail.assert_called_once()
        mock_server.quit.assert_called_once()

        # Verify the recipient
        call_args = mock_server.sendmail.call_args
        assert call_args[0][1] == ['admin@emailcorp.com']

    def test_welcome_email_skipped_when_no_smtp(self, app):
        """When no SMTP host is configured, email is silently skipped."""
        with patch('app.settings_api.get_setting', return_value=None):
            result = provision_tenant(**self.VALID_PARAMS)

        assert result['success'] is True
        # welcome_email_sent is not set when _send_welcome_email returns early (no SMTP host)
        assert result.get('welcome_email_sent') is not True

    def test_welcome_email_failure_does_not_block_provisioning(self, app):
        """If SMTP raises an exception, provisioning still succeeds."""
        settings = {
            'smtp_host': 'mail.test.local',
            'smtp_port': '587',
            'smtp_username': 'smtp_user',
            'smtp_password': 'smtp_pass',
            'smtp_use_tls': 'true',
            'smtp_from_email': 'noreply@test.local',
            'smtp_from_name': 'SentriKat',
        }

        with patch('app.settings_api.get_setting', side_effect=lambda key, default=None: settings.get(key, default)):
            with patch('smtplib.SMTP', side_effect=ConnectionRefusedError("SMTP down")):
                result = provision_tenant(**self.VALID_PARAMS)

        assert result['success'] is True
        assert result['welcome_email_sent'] is False


# ---------------------------------------------------------------------------
# License limit enforcement tests
# ---------------------------------------------------------------------------

class TestLicenseLimits:
    """Tests for license limit checks during provisioning."""

    VALID_PARAMS = {
        'org_name': 'licensecorp',
        'org_display_name': 'License Corp',
        'admin_username': 'admin@licensecorp.com',
        'admin_email': 'admin@licensecorp.com',
        'admin_password': 'securepass123',
    }

    @patch('app.licensing.check_agent_api_key_limit', return_value=(True, 10, 'OK'))
    @patch('app.licensing.check_user_limit', return_value=(True, 10, 'OK'))
    @patch('app.licensing.check_org_limit', return_value=(False, 1, 'Org limit reached'))
    def test_org_limit_reached(self, mock_org, mock_user, mock_key, app):
        """Provisioning fails when organization license limit is reached."""
        with pytest.raises(ProvisioningError, match="Organization limit reached"):
            provision_tenant(**self.VALID_PARAMS)

    @patch('app.licensing.check_agent_api_key_limit', return_value=(True, 10, 'OK'))
    @patch('app.licensing.check_user_limit', return_value=(False, 1, 'User limit reached'))
    @patch('app.licensing.check_org_limit', return_value=(True, 10, 'OK'))
    def test_user_limit_reached(self, mock_org, mock_user, mock_key, app):
        """Provisioning fails when user license limit is reached."""
        with pytest.raises(ProvisioningError, match="User limit reached"):
            provision_tenant(**self.VALID_PARAMS)

    @patch('app.licensing.check_agent_api_key_limit', return_value=(False, 1, 'Key limit reached'))
    @patch('app.licensing.check_user_limit', return_value=(True, 10, 'OK'))
    @patch('app.licensing.check_org_limit', return_value=(True, 10, 'OK'))
    def test_api_key_limit_reached(self, mock_org, mock_user, mock_key, app):
        """Provisioning fails when API key license limit is reached."""
        with pytest.raises(ProvisioningError, match="API key limit reached"):
            provision_tenant(**self.VALID_PARAMS)

    @patch('app.licensing.check_agent_api_key_limit', return_value=(True, 10, 'OK'))
    @patch('app.licensing.check_user_limit', return_value=(True, 10, 'OK'))
    @patch('app.licensing.check_org_limit', return_value=(True, 10, 'OK'))
    def test_all_limits_ok_allows_provisioning(self, mock_org, mock_user, mock_key, app):
        """When all license checks pass, provisioning succeeds."""
        result = provision_tenant(**self.VALID_PARAMS)
        assert result['success'] is True
