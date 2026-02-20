"""
Comprehensive test coverage for app/models.py
Tests model methods, properties, and business logic to maximize code coverage.
"""
import pytest
import json
import hashlib
from datetime import datetime, date, timedelta


# =============================================================================
# Organization Model Tests
# =============================================================================

def test_organization_to_dict(db_session, test_org):
    """Test Organization.to_dict() method"""
    from app.models import User
    from werkzeug.security import generate_password_hash

    # Add a user to increment user_count
    user = User(
        username='testuser1',
        email='test1@test.local',
        password_hash=generate_password_hash('test'),
        organization_id=test_org.id,
        is_active=True,
        auth_type='local'
    )
    db_session.add(user)
    db_session.commit()

    # Set notification emails
    test_org.notification_emails = json.dumps(['test@example.com', 'admin@example.com'])
    test_org.smtp_host = 'smtp.example.com'
    test_org.smtp_from_email = 'from@example.com'
    test_org.webhook_enabled = True
    db_session.commit()

    result = test_org.to_dict()

    assert result['id'] == test_org.id
    assert result['name'] == test_org.name
    assert result['display_name'] == test_org.display_name
    assert result['notification_emails'] == ['test@example.com', 'admin@example.com']
    assert result['user_count'] == 1
    assert result['smtp_configured'] is True
    # smtp_password is empty string when not set (no mask without a value)
    assert result['alert_settings']['critical'] == test_org.alert_on_critical
    assert result['is_default'] is False


def test_organization_to_dict_invalid_json(db_session, test_org):
    """Test Organization.to_dict() handles invalid JSON in notification_emails"""
    test_org.notification_emails = 'invalid-json'
    db_session.commit()

    result = test_org.to_dict()
    assert result['notification_emails'] == []


def test_organization_get_webhook_config(db_session, test_org):
    """Test Organization.get_webhook_config() method"""
    test_org.webhook_enabled = True
    test_org.webhook_url = 'https://example.com/webhook'
    test_org.webhook_name = 'Test Webhook'
    test_org.webhook_format = 'slack'
    test_org.webhook_token = 'test-token'
    db_session.commit()

    config = test_org.get_webhook_config()

    assert config['enabled'] is True
    assert config['url'] == 'https://example.com/webhook'
    assert config['name'] == 'Test Webhook'
    assert config['format'] == 'slack'
    assert config['token'] == 'test-token'


def test_organization_get_smtp_config(db_session, test_org):
    """Test Organization.get_smtp_config() method"""
    test_org.smtp_host = 'smtp.gmail.com'
    test_org.smtp_port = 587
    test_org.smtp_username = 'user@gmail.com'
    test_org.smtp_password = 'secret'
    test_org.smtp_use_tls = True
    test_org.smtp_from_email = 'alerts@example.com'
    db_session.commit()

    config = test_org.get_smtp_config()

    assert config['host'] == 'smtp.gmail.com'
    assert config['port'] == 587
    assert config['username'] == 'user@gmail.com'
    assert config['password'] == 'secret'
    assert config['use_tls'] is True
    assert config['from_email'] == 'alerts@example.com'


def test_organization_get_effective_alert_mode(db_session, test_org):
    """Test Organization.get_effective_alert_mode() method"""
    from app.models import SystemSettings

    # Create default settings
    setting = SystemSettings(
        key='default_alert_mode',
        value='daily_reminder',
        category='alerts'
    )
    db_session.add(setting)
    db_session.commit()

    # Test with org-specific setting
    test_org.alert_mode = 'escalation'
    test_org.escalation_days = 5
    db_session.commit()

    result = test_org.get_effective_alert_mode()
    assert result['mode'] == 'escalation'
    assert result['escalation_days'] == 5

    # Test fallback to global default
    test_org.alert_mode = None
    test_org.escalation_days = None
    db_session.commit()

    result = test_org.get_effective_alert_mode()
    assert result['mode'] == 'daily_reminder'


# =============================================================================
# User Model Tests
# =============================================================================

def test_user_set_password(db_session, test_user):
    """Test User.set_password() method"""
    test_user.set_password('newpassword123')
    assert test_user.password_hash is not None
    assert test_user.check_password('newpassword123') is True
    assert test_user.check_password('wrongpassword') is False


def test_user_check_password_no_hash(db_session, test_user):
    """Test User.check_password() with no password_hash (LDAP user)"""
    test_user.password_hash = None
    assert test_user.check_password('anypassword') is False


def test_user_is_locked(db_session, test_user):
    """Test User.is_locked() method"""
    assert test_user.is_locked() is False

    # Lock the user
    test_user.locked_until = datetime.utcnow() + timedelta(minutes=30)
    db_session.commit()

    assert test_user.is_locked() is True

    # Test expired lock
    test_user.locked_until = datetime.utcnow() - timedelta(minutes=1)
    db_session.commit()

    assert test_user.is_locked() is False


def test_user_get_lockout_remaining_minutes(db_session, test_user):
    """Test User.get_lockout_remaining_minutes() method"""
    assert test_user.get_lockout_remaining_minutes() == 0

    test_user.locked_until = datetime.utcnow() + timedelta(minutes=15)
    db_session.commit()

    remaining = test_user.get_lockout_remaining_minutes()
    assert remaining > 0
    assert remaining <= 16  # Rounded up


def test_user_record_failed_login(db_session, test_user):
    """Test User.record_failed_login() method"""
    from app.models import SystemSettings

    # Create lockout settings
    max_attempts = SystemSettings(key='max_failed_logins', value='3', category='security')
    lockout_duration = SystemSettings(key='lockout_duration', value='30', category='security')
    db_session.add(max_attempts)
    db_session.add(lockout_duration)
    db_session.commit()

    # Record failed attempts
    test_user.record_failed_login()
    assert test_user.failed_login_attempts == 1
    assert test_user.locked_until is None

    test_user.record_failed_login()
    assert test_user.failed_login_attempts == 2

    test_user.record_failed_login()
    assert test_user.failed_login_attempts == 3
    assert test_user.locked_until is not None  # Should be locked now


def test_user_reset_failed_login_attempts(db_session, test_user):
    """Test User.reset_failed_login_attempts() method"""
    test_user.failed_login_attempts = 5
    test_user.locked_until = datetime.utcnow() + timedelta(minutes=30)
    db_session.commit()

    test_user.reset_failed_login_attempts()
    assert test_user.failed_login_attempts == 0
    assert test_user.locked_until is None


def test_user_is_password_expired(db_session, test_user):
    """Test User.is_password_expired() method"""
    from app.models import SystemSettings

    # Test LDAP user (should never expire)
    test_user.auth_type = 'ldap'
    assert test_user.is_password_expired() is False

    # Test local user with must_change_password flag
    test_user.auth_type = 'local'
    test_user.must_change_password = True
    assert test_user.is_password_expired() is True

    # Test with expiry setting
    test_user.must_change_password = False
    expiry_setting = SystemSettings(key='password_expiry_days', value='90', category='security')
    db_session.add(expiry_setting)
    db_session.commit()

    test_user.password_changed_at = datetime.utcnow() - timedelta(days=91)
    assert test_user.is_password_expired() is True

    test_user.password_changed_at = datetime.utcnow() - timedelta(days=30)
    assert test_user.is_password_expired() is False


def test_user_get_password_days_until_expiry(db_session, test_user):
    """Test User.get_password_days_until_expiry() method"""
    from app.models import SystemSettings

    # Test LDAP user
    test_user.auth_type = 'ldap'
    assert test_user.get_password_days_until_expiry() is None

    # Test with expiry disabled
    test_user.auth_type = 'local'
    expiry_setting = SystemSettings(key='password_expiry_days', value='0', category='security')
    db_session.add(expiry_setting)
    db_session.commit()

    assert test_user.get_password_days_until_expiry() is None

    # Test with expiry enabled
    expiry_setting.value = '90'
    db_session.commit()

    test_user.password_changed_at = datetime.utcnow() - timedelta(days=60)
    days_left = test_user.get_password_days_until_expiry()
    assert days_left >= 29
    assert days_left <= 30


def test_user_update_password(db_session, test_user):
    """Test User.update_password() method"""
    old_changed_at = test_user.password_changed_at
    test_user.must_change_password = True

    test_user.update_password('newpassword123')

    assert test_user.check_password('newpassword123') is True
    assert test_user.must_change_password is False
    assert test_user.password_changed_at > old_changed_at


def test_user_is_super_admin(db_session, test_user, admin_user):
    """Test User.is_super_admin() method"""
    assert test_user.is_super_admin() is False
    assert admin_user.is_super_admin() is True


def test_user_is_org_admin(db_session, test_user):
    """Test User.is_org_admin() method"""
    test_user.role = 'user'
    assert test_user.is_org_admin() is False

    test_user.role = 'org_admin'
    assert test_user.is_org_admin() is True

    test_user.role = 'super_admin'
    assert test_user.is_org_admin() is True


def test_user_can_manage_organization(db_session, test_user, admin_user, test_org):
    """Test User.can_manage_organization() method"""
    # Regular user cannot manage org
    assert test_user.can_manage_organization(test_org.id) is False

    # Super admin can manage any org
    assert admin_user.can_manage_organization(test_org.id) is True

    # Org admin can manage their own org
    test_user.role = 'org_admin'
    assert test_user.can_manage_organization(test_org.id) is True


def test_user_can_manage_user(db_session, test_user, admin_user):
    """Test User.can_manage_user() method"""
    from app.models import User
    from werkzeug.security import generate_password_hash

    # Regular user cannot manage others
    assert test_user.can_manage_user(admin_user) is False

    # Super admin can manage anyone
    assert admin_user.can_manage_user(test_user) is True

    # Org admin can manage users in their org (but not super admins)
    test_user.role = 'org_admin'

    regular_user = User(
        username='regular',
        email='regular@test.local',
        password_hash=generate_password_hash('test'),
        organization_id=test_user.organization_id,
        role='user',
        auth_type='local'
    )
    db_session.add(regular_user)
    db_session.commit()

    assert test_user.can_manage_user(regular_user) is True
    assert test_user.can_manage_user(admin_user) is False


def test_user_has_access_to_org(db_session, test_user, test_org):
    """Test User.has_access_to_org() method"""
    from app.models import Organization

    # User has access to their own org
    assert test_user.has_access_to_org(test_org.id) is True

    # User does not have access to another org
    other_org = Organization(name='other', display_name='Other Org', active=True)
    db_session.add(other_org)
    db_session.commit()

    assert test_user.has_access_to_org(other_org.id) is False


def test_user_validate_password_policy(db_session):
    """Test User.validate_password_policy() static method"""
    from app.models import User, SystemSettings

    # Create policy settings
    min_length = SystemSettings(key='password_min_length', value='8', category='security')
    req_upper = SystemSettings(key='password_require_uppercase', value='true', category='security')
    req_lower = SystemSettings(key='password_require_lowercase', value='true', category='security')
    req_numbers = SystemSettings(key='password_require_numbers', value='true', category='security')
    req_special = SystemSettings(key='password_require_special', value='false', category='security')

    db_session.add_all([min_length, req_upper, req_lower, req_numbers, req_special])
    db_session.commit()

    # Test valid password
    is_valid, error = User.validate_password_policy('Password123')
    assert is_valid is True
    assert error is None

    # Test too short
    is_valid, error = User.validate_password_policy('Pass1')
    assert is_valid is False
    assert 'at least 8 characters' in error

    # Test missing uppercase
    is_valid, error = User.validate_password_policy('password123')
    assert is_valid is False
    assert 'uppercase' in error

    # Test missing number
    is_valid, error = User.validate_password_policy('Password')
    assert is_valid is False
    assert 'number' in error


# =============================================================================
# Product Model Tests
# =============================================================================

def test_product_to_dict(db_session, sample_product):
    """Test Product.to_dict() method"""
    result = sample_product.to_dict()

    assert result['id'] == sample_product.id
    assert result['vendor'] == 'Apache'
    assert result['product_name'] == 'Tomcat'
    assert result['version'] == '10.1.18'
    assert result['criticality'] == 'high'
    assert result['cpe_vendor'] == 'apache'
    assert result['cpe_product'] == 'tomcat'
    assert result['has_cpe'] is True
    assert result['match_type'] == 'auto'


def test_product_get_effective_cpe(db_session, sample_product):
    """Test Product.get_effective_cpe() method"""
    vendor, product, uri = sample_product.get_effective_cpe()

    assert vendor == 'apache'
    assert product == 'tomcat'
    assert uri is None


def test_product_has_cpe(db_session, sample_product):
    """Test Product.has_cpe() method"""
    assert sample_product.has_cpe() is True

    sample_product.cpe_vendor = None
    sample_product.cpe_product = None
    db_session.commit()

    assert sample_product.has_cpe() is False


def test_product_get_platform_summary(db_session, sample_product):
    """Test Product.get_platform_summary() method"""
    from app.models import ProductInstallation, Asset

    # Create an asset and installation
    asset = Asset(
        organization_id=sample_product.organization_id,
        hostname='server1',
        os_name='Linux',
        active=True
    )
    db_session.add(asset)
    db_session.flush()

    installation = ProductInstallation(
        product_id=sample_product.id,
        asset_id=asset.id,
        detected_on_os='Linux'
    )
    db_session.add(installation)
    db_session.commit()

    summary = sample_product.get_platform_summary()

    assert 'platforms' in summary
    assert 'Linux' in summary['platforms']
    assert summary['platforms']['Linux'] == 1
    assert summary['total_installations'] == 1


# =============================================================================
# Vulnerability Model Tests
# =============================================================================

def test_vulnerability_calculate_priority(db_session, sample_vulnerability):
    """Test Vulnerability.calculate_priority() method"""
    # Test with HIGH severity
    sample_vulnerability.severity = 'HIGH'
    sample_vulnerability.known_ransomware = False
    sample_vulnerability.is_actively_exploited = False
    db_session.commit()

    assert sample_vulnerability.calculate_priority() == 'high'

    # Test ransomware (always critical)
    sample_vulnerability.known_ransomware = True
    db_session.commit()

    assert sample_vulnerability.calculate_priority() == 'critical'

    # Test actively exploited (elevates by one level)
    sample_vulnerability.known_ransomware = False
    sample_vulnerability.severity = 'MEDIUM'
    sample_vulnerability.is_actively_exploited = True
    db_session.commit()

    assert sample_vulnerability.calculate_priority() == 'high'


def test_vulnerability_is_zero_day(db_session, sample_vulnerability):
    """Test Vulnerability.is_zero_day property"""
    # Test EUVD source
    sample_vulnerability.source = 'euvd'
    db_session.commit()

    assert sample_vulnerability.is_zero_day is True

    # Test CISA KEV source
    sample_vulnerability.source = 'cisa_kev'
    db_session.commit()

    assert sample_vulnerability.is_zero_day is False

    # Test NVD with awaiting analysis
    sample_vulnerability.source = 'nvd'
    sample_vulnerability.nvd_status = 'Awaiting Analysis'
    db_session.commit()

    assert sample_vulnerability.is_zero_day is True


def test_vulnerability_nvd_data_incomplete(db_session, sample_vulnerability):
    """Test Vulnerability.nvd_data_incomplete property"""
    sample_vulnerability.nvd_status = 'Awaiting Analysis'
    db_session.commit()

    assert sample_vulnerability.nvd_data_incomplete is True

    sample_vulnerability.nvd_status = 'Analyzed'
    db_session.commit()

    assert sample_vulnerability.nvd_data_incomplete is False


def test_vulnerability_get_set_cpe_entries(db_session, sample_vulnerability):
    """Test Vulnerability.get_cpe_entries() and set_cpe_entries() methods"""
    entries = [{
        'vendor': 'apache',
        'product': 'tomcat',
        'version_start': '10.0.0',
        'version_end': '10.1.25'
    }]

    sample_vulnerability.set_cpe_entries(entries)
    db_session.commit()

    retrieved = sample_vulnerability.get_cpe_entries()
    assert len(retrieved) == 1
    assert retrieved[0]['vendor'] == 'apache'
    assert retrieved[0]['product'] == 'tomcat'

    # Test with None
    sample_vulnerability.set_cpe_entries(None)
    db_session.commit()

    assert sample_vulnerability.cpe_data is None
    assert sample_vulnerability.get_cpe_entries() == []


def test_vulnerability_has_cpe_data(db_session, sample_vulnerability):
    """Test Vulnerability.has_cpe_data() method"""
    assert sample_vulnerability.has_cpe_data() is True

    sample_vulnerability.cpe_data = None
    db_session.commit()

    assert sample_vulnerability.has_cpe_data() is False


def test_vulnerability_get_fix_versions(db_session, sample_vulnerability):
    """Test Vulnerability.get_fix_versions() method"""
    entries = [{
        'vendor': 'apache',
        'product': 'tomcat',
        'version_start': '10.0.0',
        'version_end': '10.1.25',
        'version_start_type': 'including',
        'version_end_type': 'excluding'
    }]

    sample_vulnerability.set_cpe_entries(entries)
    db_session.commit()

    fix_versions = sample_vulnerability.get_fix_versions()

    assert len(fix_versions) == 1
    assert fix_versions[0]['vendor'] == 'apache'
    assert fix_versions[0]['product'] == 'tomcat'
    assert fix_versions[0]['fix_version'] == '10.1.25'
    assert fix_versions[0]['fix_type'] == 'excluding'


# =============================================================================
# VulnerabilityMatch Model Tests
# =============================================================================

def test_vulnerability_match_calculate_effective_priority(db_session, sample_product, sample_vulnerability):
    """Test VulnerabilityMatch.calculate_effective_priority() method"""
    from app.models import VulnerabilityMatch

    match = VulnerabilityMatch(
        product_id=sample_product.id,
        vulnerability_id=sample_vulnerability.id,
        match_method='cpe',
        match_confidence='high'
    )
    db_session.add(match)
    db_session.commit()

    # Should return the vulnerability's priority
    priority = match.calculate_effective_priority()
    assert priority == sample_vulnerability.calculate_priority()


# =============================================================================
# AgentApiKey Model Tests
# =============================================================================

def test_agent_api_key_generate_key():
    """Test AgentApiKey.generate_key() static method"""
    from app.models import AgentApiKey

    key1 = AgentApiKey.generate_key()
    key2 = AgentApiKey.generate_key()

    assert key1.startswith('sk_agent_')
    assert key2.startswith('sk_agent_')
    assert key1 != key2  # Should be unique


def test_agent_api_key_hash_key():
    """Test AgentApiKey.hash_key() static method"""
    from app.models import AgentApiKey

    key = 'sk_agent_test123'
    hash1 = AgentApiKey.hash_key(key)
    hash2 = AgentApiKey.hash_key(key)

    assert hash1 == hash2  # Same key should produce same hash
    assert len(hash1) == 64  # SHA256 produces 64 hex characters


def test_agent_api_key_is_valid(db_session, test_api_key):
    """Test AgentApiKey.is_valid() method"""
    api_key = test_api_key['api_key']

    # Active key with no expiry should be valid
    assert api_key.is_valid() is True

    # Inactive key should be invalid
    api_key.active = False
    db_session.commit()

    assert api_key.is_valid() is False

    # Expired key should be invalid
    api_key.active = True
    api_key.expires_at = datetime.utcnow() - timedelta(days=1)
    db_session.commit()

    assert api_key.is_valid() is False

    # Not yet expired should be valid
    api_key.expires_at = datetime.utcnow() + timedelta(days=30)
    db_session.commit()

    assert api_key.is_valid() is True


def test_agent_api_key_get_allowed_ips(db_session, test_api_key):
    """Test AgentApiKey.get_allowed_ips() method"""
    api_key = test_api_key['api_key']

    # No IPs configured
    assert api_key.get_allowed_ips() == []

    # Set allowed IPs
    api_key.allowed_ips = json.dumps(['192.168.1.0/24', '10.0.0.1'])
    db_session.commit()

    allowed = api_key.get_allowed_ips()
    assert len(allowed) == 2
    assert '192.168.1.0/24' in allowed
    assert '10.0.0.1' in allowed


def test_agent_api_key_get_all_organization_ids(db_session, test_api_key, test_org):
    """Test AgentApiKey.get_all_organization_ids() method"""
    from app.models import Organization

    api_key = test_api_key['api_key']

    # Should include primary org
    org_ids = api_key.get_all_organization_ids()
    assert test_org.id in org_ids

    # Add additional org
    other_org = Organization(name='other', display_name='Other', active=True)
    db_session.add(other_org)
    db_session.flush()

    api_key.additional_organizations.append(other_org)
    db_session.commit()

    org_ids = api_key.get_all_organization_ids()
    assert test_org.id in org_ids
    assert other_org.id in org_ids
    assert len(org_ids) == 2


# =============================================================================
# HealthCheckResult Model Tests
# =============================================================================

def test_health_check_result_record(db_session):
    """Test HealthCheckResult.record() static method"""
    from app.models import HealthCheckResult

    # Record a new check
    HealthCheckResult.record(
        check_name='test_check',
        category='system',
        status='ok',
        message='System is healthy',
        value='100%',
        details={'cpu': 50, 'memory': 70}
    )

    result = HealthCheckResult.query.filter_by(check_name='test_check').first()
    assert result is not None
    assert result.status == 'ok'
    assert result.message == 'System is healthy'
    assert result.value == '100%'

    details = json.loads(result.details)
    assert details['cpu'] == 50

    # Update existing check
    HealthCheckResult.record(
        check_name='test_check',
        category='system',
        status='warning',
        message='High memory usage',
        value='85%'
    )

    result = HealthCheckResult.query.filter_by(check_name='test_check').first()
    assert result.status == 'warning'
    assert result.message == 'High memory usage'
    assert result.value == '85%'


# =============================================================================
# ContainerImage Model Tests
# =============================================================================

def test_container_image_full_name(db_session, test_org):
    """Test ContainerImage.full_name property"""
    from app.models import ContainerImage

    image = ContainerImage(
        organization_id=test_org.id,
        image_name='nginx',
        image_tag='1.25-alpine'
    )
    db_session.add(image)
    db_session.commit()

    assert image.full_name == 'nginx:1.25-alpine'

    # Test without tag
    image.image_tag = None
    db_session.commit()

    assert image.full_name == 'nginx'


def test_container_image_severity_summary(db_session, test_org):
    """Test ContainerImage.severity_summary property"""
    from app.models import ContainerImage

    image = ContainerImage(
        organization_id=test_org.id,
        image_name='nginx',
        critical_count=5,
        high_count=10,
        medium_count=15,
        low_count=20
    )
    db_session.add(image)
    db_session.commit()

    summary = image.severity_summary

    assert summary['critical'] == 5
    assert summary['high'] == 10
    assert summary['medium'] == 15
    assert summary['low'] == 20


def test_container_image_to_dict(db_session, test_org):
    """Test ContainerImage.to_dict() method"""
    from app.models import ContainerImage

    image = ContainerImage(
        organization_id=test_org.id,
        image_name='nginx',
        image_tag='latest',
        image_id='sha256:abc123',
        registry='docker.io',
        os_family='alpine',
        critical_count=3,
        high_count=5,
        total_vulnerabilities=10,
        active=True
    )
    db_session.add(image)
    db_session.commit()

    result = image.to_dict()

    assert result['image_name'] == 'nginx'
    assert result['image_tag'] == 'latest'
    assert result['full_name'] == 'nginx:latest'
    assert result['registry'] == 'docker.io'
    assert result['os_family'] == 'alpine'
    assert result['total_vulnerabilities'] == 10
    assert result['severity']['critical'] == 3
    assert result['severity']['high'] == 5
    assert result['active'] is True


# =============================================================================
# SystemSettings Model Tests
# =============================================================================

def test_system_settings_to_dict(db_session):
    """Test SystemSettings.to_dict() method"""
    from app.models import SystemSettings

    # Test unencrypted setting
    setting = SystemSettings(
        key='test_key',
        value='test_value',
        category='general',
        description='Test setting',
        is_encrypted=False
    )
    db_session.add(setting)
    db_session.commit()

    result = setting.to_dict()

    assert result['key'] == 'test_key'
    assert result['value'] == 'test_value'
    assert result['category'] == 'general'

    # Test encrypted setting
    setting.is_encrypted = True
    db_session.commit()

    result = setting.to_dict()
    assert result['value'] == '***ENCRYPTED***'


# =============================================================================
# SubscriptionPlan Model Tests
# =============================================================================

def test_subscription_plan_get_features(db_session):
    """Test SubscriptionPlan.get_features() method"""
    from app.models import SubscriptionPlan

    features = {'email_alerts': True, 'ldap': False, 'webhooks': True}

    plan = SubscriptionPlan(
        name='test',
        display_name='Test Plan',
        features=json.dumps(features)
    )
    db_session.add(plan)
    db_session.commit()

    retrieved = plan.get_features()
    assert retrieved['email_alerts'] is True
    assert retrieved['ldap'] is False
    assert retrieved['webhooks'] is True


def test_subscription_plan_has_feature(db_session):
    """Test SubscriptionPlan.has_feature() method"""
    from app.models import SubscriptionPlan

    features = {'email_alerts': True, 'ldap': False}

    plan = SubscriptionPlan(
        name='test',
        display_name='Test Plan',
        features=json.dumps(features)
    )
    db_session.add(plan)
    db_session.commit()

    assert plan.has_feature('email_alerts') is True
    assert plan.has_feature('ldap') is False
    assert plan.has_feature('non_existent') is False


def test_subscription_plan_to_dict(db_session):
    """Test SubscriptionPlan.to_dict() method"""
    from app.models import SubscriptionPlan

    features = {'email_alerts': True, 'webhooks': True}

    plan = SubscriptionPlan(
        name='pro',
        display_name='Professional',
        description='For teams',
        max_agents=100,
        max_users=10,
        price_monthly_cents=9900,
        currency='USD',
        features=json.dumps(features),
        is_active=True
    )
    db_session.add(plan)
    db_session.commit()

    result = plan.to_dict()

    assert result['name'] == 'pro'
    assert result['display_name'] == 'Professional'
    assert result['max_agents'] == 100
    assert result['price_monthly_cents'] == 9900
    assert result['currency'] == 'USD'
    assert result['features']['email_alerts'] is True
    assert result['is_active'] is True


# =============================================================================
# ProductExclusion Model Tests
# =============================================================================

def test_product_exclusion_is_excluded(db_session, test_org):
    """Test ProductExclusion.is_excluded() static method"""
    from app.models import ProductExclusion

    # Test no exclusion
    assert ProductExclusion.is_excluded(test_org.id, 'Apache', 'Tomcat', '10.0') is False

    # Add exact version exclusion
    exclusion = ProductExclusion(
        organization_id=test_org.id,
        vendor='Apache',
        product_name='Tomcat',
        version='10.0'
    )
    db_session.add(exclusion)
    db_session.commit()

    # Should match exact version
    assert ProductExclusion.is_excluded(test_org.id, 'Apache', 'Tomcat', '10.0') is True
    # Should not match different version
    assert ProductExclusion.is_excluded(test_org.id, 'Apache', 'Tomcat', '11.0') is False

    # Add version-agnostic exclusion
    exclusion2 = ProductExclusion(
        organization_id=test_org.id,
        vendor='Microsoft',
        product_name='Windows',
        version=None  # All versions
    )
    db_session.add(exclusion2)
    db_session.commit()

    # Should match any version
    assert ProductExclusion.is_excluded(test_org.id, 'Microsoft', 'Windows', '10') is True
    assert ProductExclusion.is_excluded(test_org.id, 'Microsoft', 'Windows', '11') is True


# =============================================================================
# Asset Model Tests
# =============================================================================

def test_asset_get_set_tags(db_session, test_org):
    """Test Asset.get_tags() and set_tags() methods"""
    from app.models import Asset

    asset = Asset(
        organization_id=test_org.id,
        hostname='server1',
        active=True
    )
    db_session.add(asset)
    db_session.commit()

    # Test empty tags
    assert asset.get_tags() == []

    # Set tags
    asset.set_tags(['production', 'web-server', 'critical'])
    db_session.commit()

    tags = asset.get_tags()
    assert len(tags) == 3
    assert 'production' in tags
    assert 'web-server' in tags


def test_asset_get_set_metadata(db_session, test_org):
    """Test Asset.get_metadata() and set_metadata() methods"""
    from app.models import Asset

    asset = Asset(
        organization_id=test_org.id,
        hostname='server1',
        active=True
    )
    db_session.add(asset)
    db_session.commit()

    # Test empty metadata
    assert asset.get_metadata() == {}

    # Set metadata
    metadata = {'owner': 'IT Team', 'location': 'US-EAST-1', 'cost_center': '1234'}
    asset.set_metadata(metadata)
    db_session.commit()

    retrieved = asset.get_metadata()
    assert retrieved['owner'] == 'IT Team'
    assert retrieved['location'] == 'US-EAST-1'
    assert retrieved['cost_center'] == '1234'


# =============================================================================
# User TOTP Tests
# =============================================================================

def test_user_setup_totp(db_session, test_user):
    """Test User.setup_totp() method"""
    secret = test_user.setup_totp()

    assert secret is not None
    assert len(secret) == 32  # Base32 encoded 20 bytes
    assert test_user.totp_secret == secret


def test_user_get_totp_uri(db_session, test_user):
    """Test User.get_totp_uri() method"""
    # No secret set
    assert test_user.get_totp_uri() is None

    # Set secret
    test_user.setup_totp()
    db_session.commit()

    uri = test_user.get_totp_uri()
    assert uri.startswith('otpauth://totp/')
    assert 'SentriKat' in uri
    from urllib.parse import quote
    assert quote(test_user.email, safe='') in uri or test_user.email in uri
    assert test_user.totp_secret in uri


def test_user_verify_totp(db_session, test_user):
    """Test User.verify_totp() method"""
    import time
    import hmac
    import struct
    import base64
    import hashlib

    # No secret
    assert test_user.verify_totp('123456') is False

    # Setup TOTP
    secret = test_user.setup_totp()
    db_session.commit()

    # Generate valid code
    key = base64.b32decode(secret, casefold=True)
    counter = int(time.time()) // 30
    counter_bytes = struct.pack('>Q', counter)
    hmac_hash = hmac.new(key, counter_bytes, hashlib.sha1).digest()
    offset_val = hmac_hash[-1] & 0x0f
    truncated = struct.unpack('>I', hmac_hash[offset_val:offset_val + 4])[0]
    totp_code = str((truncated & 0x7fffffff) % 1000000).zfill(6)

    # Verify valid code
    assert test_user.verify_totp(totp_code) is True

    # Verify invalid code
    assert test_user.verify_totp('000000') is False


def test_user_enable_disable_totp(db_session, test_user):
    """Test User.enable_totp() and disable_totp() methods"""
    # Setup and enable
    test_user.setup_totp()
    test_user.enable_totp()
    db_session.commit()

    assert test_user.totp_enabled is True
    assert test_user.totp_secret is not None

    # Disable
    test_user.disable_totp()
    db_session.commit()

    assert test_user.totp_enabled is False
    assert test_user.totp_secret is None
