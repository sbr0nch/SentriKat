"""
Settings API Endpoints
Handles LDAP, SMTP, Sync, and General system settings

Enterprise Configuration Pattern:
- Priority: Database > Environment Variable > Default
- Environment variables provide initial/fallback values
- UI shows effective value with source indicator
- Changes via UI are persisted to database
"""

from flask import Blueprint, request, jsonify, session
from app import db, csrf
from sqlalchemy import func
from app.models import SystemSettings, User, Vulnerability, SyncLog
from app.auth import admin_required
from app.encryption import encrypt_value, decrypt_value
from app.licensing import requires_professional
from app.error_utils import ERROR_MSGS
from app.logging_config import log_audit_event
import os
import json
from datetime import datetime
import logging

logger = logging.getLogger(__name__)

settings_bp = Blueprint('settings', __name__, url_prefix='/api/settings')

# Exempt API routes from CSRF (they use JSON and are protected by SameSite cookies)
csrf.exempt(settings_bp)

# ============================================================================
# Environment Variable Mapping
# Maps database setting keys to environment variable names
# ============================================================================
ENV_MAPPING = {
    # Sync settings
    'nvd_api_key': 'NVD_API_KEY',
    'cisa_kev_url': 'CISA_KEV_URL',
    'sync_time': 'SYNC_TIME',
    'auto_sync_enabled': 'AUTO_SYNC_ENABLED',

    # Network settings
    'http_proxy': ['HTTP_PROXY', 'http_proxy'],
    'https_proxy': ['HTTPS_PROXY', 'https_proxy'],
    'no_proxy': ['NO_PROXY', 'no_proxy'],
    'verify_ssl': 'VERIFY_SSL',

    # License
    'license_key': 'SENTRIKAT_LICENSE',

    # SMTP settings (can be set via env for containerized deployments)
    'smtp_host': 'SMTP_HOST',
    'smtp_port': 'SMTP_PORT',
    'smtp_username': 'SMTP_USERNAME',
    'smtp_password': 'SMTP_PASSWORD',
    'smtp_from_email': 'SMTP_FROM_EMAIL',
    'smtp_from_name': 'SMTP_FROM_NAME',
    'smtp_use_tls': 'SMTP_USE_TLS',
    'smtp_use_ssl': 'SMTP_USE_SSL',

    # LDAP settings (can be set via env)
    'ldap_enabled': 'LDAP_ENABLED',
    'ldap_server': 'LDAP_SERVER',
    'ldap_port': 'LDAP_PORT',
    'ldap_base_dn': 'LDAP_BASE_DN',
    'ldap_bind_dn': 'LDAP_BIND_DN',
    'ldap_bind_password': 'LDAP_BIND_PASSWORD',
}


def _get_env_value(key):
    """
    Get value from environment variable for a setting key.
    Returns None if not found in environment.
    """
    env_var = ENV_MAPPING.get(key)
    if not env_var:
        return None

    # Support multiple possible env var names (e.g., HTTP_PROXY or http_proxy)
    if isinstance(env_var, list):
        for var in env_var:
            value = os.environ.get(var)
            if value:
                return value
        return None

    return os.environ.get(env_var)


# ============================================================================
# Helper Functions
# ============================================================================

def get_setting(key, default=None, include_source=False):
    """
    Get a setting value with priority: Database > Environment > Default.

    Args:
        key: Setting key name
        default: Default value if not found anywhere
        include_source: If True, returns tuple (value, source) where source is 'database', 'environment', or 'default'

    Returns:
        Value (or tuple of value, source if include_source=True)
    """
    source = 'default'
    value = default

    # First, check database
    setting = SystemSettings.query.filter_by(key=key).first()
    if setting and setting.value:
        # Decrypt if the setting is marked as encrypted
        if setting.is_encrypted:
            try:
                value = decrypt_value(setting.value)
            except Exception as e:
                logger.error(f"Failed to decrypt setting '{key}': {type(e).__name__}. "
                             f"The encryption key may have changed. Re-save this setting to fix.")
                value = default  # Return default (empty) - don't leak encrypted blob
        else:
            value = setting.value
        source = 'database'
    else:
        # Fallback to environment variable
        env_value = _get_env_value(key)
        if env_value is not None:
            value = env_value
            source = 'environment'

    if include_source:
        return value, source
    return value


def get_setting_with_source(key, default=None):
    """
    Get a setting value and its source.
    Returns dict with 'value' and 'source' keys.
    """
    value, source = get_setting(key, default, include_source=True)
    return {
        'value': value,
        'source': source,
        'from_env': source == 'environment'
    }

ALLOWED_SETTING_KEYS = {
    # LDAP settings
    'ldap_enabled', 'ldap_server', 'ldap_port', 'ldap_use_ssl', 'ldap_use_tls',
    'ldap_bind_dn', 'ldap_bind_password', 'ldap_base_dn',
    'ldap_search_filter', 'ldap_user_filter', 'ldap_group_filter',
    'ldap_username_attr', 'ldap_username_attribute', 'ldap_email_attr', 'ldap_email_attribute',
    'ldap_group_attribute', 'ldap_sync_enabled', 'ldap_sync_interval_hours',
    # SMTP settings
    'smtp_enabled', 'smtp_host', 'smtp_server', 'smtp_port', 'smtp_username', 'smtp_password',
    'smtp_from_email', 'smtp_from_name', 'smtp_use_tls', 'smtp_use_ssl',
    # Sync settings
    'auto_sync_enabled', 'sync_interval', 'sync_interval_hours', 'sync_time',
    'auto_match_enabled', 'cisa_kev_url', 'nvd_api_key',
    # General/Proxy settings
    'app_name', 'app_url', 'verify_ssl', 'http_proxy', 'https_proxy', 'no_proxy',
    # Date & Time display settings
    'display_timezone', 'date_format',
    # Security settings
    'session_timeout', 'session_timeout_minutes', 'max_login_attempts', 'max_failed_logins',
    'lockout_duration', 'lockout_duration_minutes', 'require_2fa',
    'password_min_length', 'password_require_uppercase', 'password_require_lowercase',
    'password_require_numbers', 'password_require_special', 'password_history_count',
    'password_expiry_days',
    # Branding settings
    'app_name', 'login_message', 'support_email', 'show_version', 'logo_url',
    'branding_logo', 'branding_primary_color', 'branding_secondary_color',
    # Notification settings
    'slack_enabled', 'slack_webhook_url',
    'teams_enabled', 'teams_webhook_url',
    'generic_webhook_enabled', 'generic_webhook_url', 'generic_webhook_name',
    'generic_webhook_format', 'generic_webhook_custom_template', 'generic_webhook_token',
    'critical_email_enabled', 'critical_email_time', 'critical_email_max_age_days',
    'default_alert_mode', 'default_escalation_days',
    'notify_on_critical', 'notify_on_high', 'notify_on_new_cve', 'notify_on_ransomware',
    'notification_digest_enabled', 'notification_digest_time',
    # Retention settings
    'audit_log_retention_days', 'audit_retention_days',
    'sync_history_retention_days', 'sync_log_retention_days',
    'session_log_retention_days', 'auto_acknowledge_removed_software',
    # Issue Tracker integration settings (multi-tracker support)
    'issue_tracker_type',  # 'disabled', 'jira', 'youtrack', 'github', 'gitlab', 'webhook'
    # Jira settings
    'jira_enabled', 'jira_url', 'jira_email', 'jira_api_token',
    'jira_project_key', 'jira_issue_type', 'jira_use_pat', 'jira_custom_fields',
    # YouTrack settings
    'youtrack_url', 'youtrack_token', 'youtrack_project_id',
    # GitHub Issues settings
    'github_token', 'github_owner', 'github_repo',
    # GitLab Issues settings
    'gitlab_url', 'gitlab_token', 'gitlab_project_id',
    # Generic Webhook settings
    'webhook_url', 'webhook_method', 'webhook_auth_type', 'webhook_auth_value',
    # SAML SSO settings
    'saml_enabled', 'saml_idp_metadata', 'saml_sp_entity_id', 'saml_sp_acs_url',
    'saml_sp_sls_url', 'saml_default_org_id', 'saml_user_mapping',
    'saml_auto_provision', 'saml_update_user_info',
}


def set_setting(key, value, category, description=None, is_encrypted=False, skip_validation=False):
    """
    Set a setting value in database.
    Encrypts the value if is_encrypted=True.

    Args:
        key: Setting key name
        value: Setting value
        category: Setting category
        description: Optional description
        is_encrypted: Whether to encrypt the value
        skip_validation: If True, skip key validation (for internal use only)
    """
    # Validate setting key to prevent arbitrary setting injection
    if not skip_validation and key not in ALLOWED_SETTING_KEYS:
        logger.warning(f"Attempted to set disallowed setting key: {key}")
        raise ValueError(f"Setting key '{key}' is not allowed")

    user_id = session.get('user_id')

    # Encrypt the value if required
    stored_value = value
    if is_encrypted and value:
        try:
            stored_value = encrypt_value(value)
        except Exception as e:
            logger.error(f"Failed to encrypt setting '{key}': {type(e).__name__}")
            raise

    setting = SystemSettings.query.filter_by(key=key).first()
    if setting:
        setting.value = stored_value
        setting.is_encrypted = is_encrypted
        setting.updated_by = user_id
        setting.updated_at = datetime.utcnow()
    else:
        setting = SystemSettings(
            key=key,
            value=stored_value,
            category=category,
            description=description,
            is_encrypted=is_encrypted,
            updated_by=user_id
        )
        db.session.add(setting)

    db.session.commit()
    return setting

# ============================================================================
# Batch Settings Endpoint
# ============================================================================

@settings_bp.route('/batch', methods=['POST'])
@admin_required
def save_batch_settings():
    """
    Save multiple settings at once.

    Request body:
    {
        "category": "issue_tracker",
        "settings": {
            "jira_url": "https://...",
            "jira_email": "...",
            ...
        },
        "encrypt_keys": ["jira_api_token"]  // Keys to encrypt
    }
    """
    data = request.get_json()

    if not data:
        return jsonify({'error': 'No data provided'}), 400

    category = data.get('category', 'general')
    settings = data.get('settings', {})
    encrypt_keys = data.get('encrypt_keys', [])

    if not settings:
        return jsonify({'error': 'No settings provided'}), 400

    try:
        saved_count = 0
        for key, value in settings.items():
            # Check if key is allowed
            if key not in ALLOWED_SETTING_KEYS:
                logger.warning(f"Skipping disallowed setting key: {key}")
                continue

            # Determine if this key should be encrypted
            should_encrypt = key in encrypt_keys

            # Only save non-empty values (or explicitly set to clear)
            if value is not None and value != '':
                set_setting(key, str(value), category, is_encrypted=should_encrypt)
                saved_count += 1

        db.session.commit()
        logger.info(f"Saved {saved_count} settings in category '{category}'")

        return jsonify({
            'success': True,
            'message': f'Saved {saved_count} settings',
            'saved_count': saved_count
        })

    except ValueError as e:
        return jsonify({'error': str(e)}), 400
    except Exception as e:
        logger.exception(f"Error saving batch settings: {e}")
        db.session.rollback()
        return jsonify({'error': 'Failed to save settings'}), 500

# ============================================================================
# LDAP Settings
# ============================================================================

@settings_bp.route('/ldap', methods=['GET'])
@admin_required
@requires_professional('LDAP')
def get_ldap_settings():
    """Get LDAP configuration settings"""
    # Check if bind password is configured (don't return the actual value)
    bind_password = get_setting('ldap_bind_password', '')
    password_configured = bool(bind_password)

    settings = {
        'ldap_enabled': get_setting('ldap_enabled', 'false') == 'true',
        'ldap_server': get_setting('ldap_server', ''),
        'ldap_port': int(get_setting('ldap_port', '389')),
        'ldap_base_dn': get_setting('ldap_base_dn', ''),
        'ldap_bind_dn': get_setting('ldap_bind_dn', ''),
        'ldap_bind_password_configured': password_configured,
        'ldap_search_filter': get_setting('ldap_search_filter', '(sAMAccountName={username})'),
        'ldap_username_attr': get_setting('ldap_username_attr', 'sAMAccountName'),
        'ldap_email_attr': get_setting('ldap_email_attr', 'mail'),
        'ldap_use_tls': get_setting('ldap_use_tls', 'false') == 'true',
        'ldap_sync_enabled': get_setting('ldap_sync_enabled', 'false') == 'true',
        'ldap_sync_interval_hours': int(get_setting('ldap_sync_interval_hours', '24'))
    }
    return jsonify(settings)

@settings_bp.route('/ldap', methods=['POST'])
@admin_required
@requires_professional('LDAP')
def save_ldap_settings():
    """Save LDAP configuration settings"""
    data = request.get_json()

    if not data:
        return jsonify({'error': 'No data provided'}), 400

    try:
        set_setting('ldap_enabled', 'true' if data.get('ldap_enabled') else 'false', 'ldap', 'Enable LDAP authentication')
        set_setting('ldap_server', data.get('ldap_server', ''), 'ldap', 'LDAP server URL')
        set_setting('ldap_port', str(data.get('ldap_port', 389)), 'ldap', 'LDAP server port')
        set_setting('ldap_base_dn', data.get('ldap_base_dn', ''), 'ldap', 'LDAP base DN')
        set_setting('ldap_bind_dn', data.get('ldap_bind_dn', ''), 'ldap', 'LDAP bind DN (service account)')

        # Encrypt bind password
        if data.get('ldap_bind_password'):
            try:
                set_setting('ldap_bind_password', data['ldap_bind_password'], 'ldap', 'LDAP bind password', is_encrypted=True)
            except Exception as enc_err:
                logger.error(f"Failed to encrypt LDAP bind password: {type(enc_err).__name__}")
                return jsonify({'error': 'Failed to encrypt bind password. Check ENCRYPTION_KEY is set.'}), 500

        set_setting('ldap_search_filter', data.get('ldap_search_filter', '(sAMAccountName={username})'), 'ldap', 'LDAP search filter')
        set_setting('ldap_username_attr', data.get('ldap_username_attr', 'sAMAccountName'), 'ldap', 'LDAP username attribute')
        set_setting('ldap_email_attr', data.get('ldap_email_attr', 'mail'), 'ldap', 'LDAP email attribute')
        set_setting('ldap_use_tls', 'true' if data.get('ldap_use_tls') else 'false', 'ldap', 'Use TLS/STARTTLS')
        set_setting('ldap_sync_enabled', 'true' if data.get('ldap_sync_enabled') else 'false', 'ldap', 'Enable scheduled LDAP sync')
        set_setting('ldap_sync_interval_hours', str(data.get('ldap_sync_interval_hours', 24)), 'ldap', 'LDAP sync interval (hours)')

        return jsonify({'success': True, 'message': 'LDAP settings saved successfully'})
    except ValueError as e:
        logger.warning(f"LDAP settings validation error: {e}")
        return jsonify({'error': f'Invalid setting: {str(e)}'}), 400
    except Exception as e:
        logger.exception("Failed to save LDAP settings")
        db.session.rollback()
        return jsonify({'error': 'Failed to save LDAP settings. Check server logs for details.'}), 500

@settings_bp.route('/ldap/test', methods=['POST'])
@admin_required
@requires_professional('LDAP')
def test_ldap_connection():
    """Test LDAP connection"""
    try:
        import ldap3

        ldap_server = get_setting('ldap_server')
        ldap_port = int(get_setting('ldap_port', '389'))
        ldap_bind_dn = get_setting('ldap_bind_dn')
        ldap_bind_password = get_setting('ldap_bind_password')
        ldap_use_tls = get_setting('ldap_use_tls', 'false') == 'true'

        if not ldap_server:
            return jsonify({'success': False, 'error': 'LDAP server not configured'})

        if not ldap_bind_dn or not ldap_bind_password:
            return jsonify({'success': False, 'error': 'LDAP bind credentials not configured'})

        # Parse server URL (handles ldap://, ldaps://, and bare hostname)
        from app.ldap_manager import _parse_ldap_server
        server_host, use_ssl = _parse_ldap_server(ldap_server)
        if not server_host:
            return jsonify({'success': False, 'error': 'LDAP server URL is empty after parsing'})

        # Create server object
        server = ldap3.Server(server_host, port=ldap_port, use_ssl=use_ssl or ldap_use_tls, get_info=ldap3.ALL)

        # Try to bind with service account
        conn = ldap3.Connection(server, user=ldap_bind_dn, password=ldap_bind_password, auto_bind=True)

        if conn.bound:
            conn.unbind()
            return jsonify({
                'success': True,
                'message': f'Successfully connected to LDAP server at {server_host}:{ldap_port}'
            })
        else:
            return jsonify({'success': False, 'error': 'Failed to bind to LDAP server'})

    except ImportError:
        return jsonify({'success': False, 'error': 'ldap3 library not installed. Run: pip install ldap3'})
    except Exception as e:
        logger.warning(f"LDAP connection test failed: {e}")
        return jsonify({'success': False, 'error': ERROR_MSGS['ldap']})


# ============================================================================
# Global SMTP Settings
# ============================================================================

@settings_bp.route('/smtp', methods=['GET'])
@admin_required
@requires_professional('Email Alerts')
def get_smtp_settings():
    """Get global SMTP settings"""
    settings = {
        'smtp_host': get_setting('smtp_host', ''),
        'smtp_port': int(get_setting('smtp_port', '587')),
        'smtp_username': get_setting('smtp_username', ''),
        'smtp_from_email': get_setting('smtp_from_email', ''),
        'smtp_from_name': get_setting('smtp_from_name', 'SentriKat Alerts'),
        'smtp_use_tls': get_setting('smtp_use_tls', 'false') == 'true',
        'smtp_use_ssl': get_setting('smtp_use_ssl', 'false') == 'true'
    }
    return jsonify(settings)

@settings_bp.route('/smtp', methods=['POST'])
@admin_required
def save_smtp_settings():
    """Save global SMTP settings"""
    data = request.get_json()

    if not data:
        return jsonify({'error': 'No data provided'}), 400

    try:
        set_setting('smtp_host', data.get('smtp_host', ''), 'smtp', 'SMTP server hostname')
        set_setting('smtp_port', str(data.get('smtp_port', 587)), 'smtp', 'SMTP server port')
        set_setting('smtp_username', data.get('smtp_username', ''), 'smtp', 'SMTP username')

        # Encrypt SMTP password
        if data.get('smtp_password'):
            try:
                set_setting('smtp_password', data['smtp_password'], 'smtp', 'SMTP password', is_encrypted=True)
            except Exception as enc_err:
                logger.error(f"Failed to encrypt SMTP password: {type(enc_err).__name__}")
                return jsonify({'error': 'Failed to encrypt password. Check ENCRYPTION_KEY is set.'}), 500

        set_setting('smtp_from_email', data.get('smtp_from_email', ''), 'smtp', 'From email address')
        set_setting('smtp_from_name', data.get('smtp_from_name', 'SentriKat Alerts'), 'smtp', 'From name')
        set_setting('smtp_use_tls', 'true' if data.get('smtp_use_tls') else 'false', 'smtp', 'Use TLS/STARTTLS')
        set_setting('smtp_use_ssl', 'true' if data.get('smtp_use_ssl') else 'false', 'smtp', 'Use SSL/TLS')

        return jsonify({'success': True, 'message': 'SMTP settings saved successfully'})
    except ValueError as e:
        logger.warning(f"SMTP settings validation error: {e}")
        return jsonify({'error': f'Invalid setting: {str(e)}'}), 400
    except Exception as e:
        logger.exception("Failed to save SMTP settings")
        db.session.rollback()
        return jsonify({'error': 'Failed to save SMTP settings. Check server logs for details.'}), 500

@settings_bp.route('/smtp/test', methods=['POST'])
@admin_required
def test_smtp_connection():
    """Test global SMTP connection by sending test email"""
    try:
        import smtplib
        from email.mime.text import MIMEText
        from email.mime.multipart import MIMEMultipart
        import socket

        # Get current user's email to send test to
        user_id = session.get('user_id')
        test_recipient = None
        if user_id:
            user = User.query.get(user_id)
            test_recipient = user.email if user else None

        if not test_recipient:
            return jsonify({
                'success': False,
                'error': 'No email address found for your user account. Please add an email to your profile first.'
            })

        smtp_config = {
            'host': get_setting('smtp_host'),
            'port': int(get_setting('smtp_port', '587')),
            'username': get_setting('smtp_username'),
            'password': get_setting('smtp_password'),
            'from_email': get_setting('smtp_from_email'),
            'from_name': get_setting('smtp_from_name', 'SentriKat Alerts'),
            'use_tls': get_setting('smtp_use_tls', 'false') == 'true',
            'use_ssl': get_setting('smtp_use_ssl', 'false') == 'true'
        }

        if not smtp_config['host']:
            return jsonify({'success': False, 'error': 'SMTP server hostname is not configured'})

        if not smtp_config['from_email']:
            return jsonify({'success': False, 'error': 'SMTP "From" email address is not configured'})

        # Create test email
        msg = MIMEMultipart()
        msg['From'] = f"{smtp_config['from_name']} <{smtp_config['from_email']}>"
        msg['To'] = test_recipient
        msg['Subject'] = 'SentriKat SMTP Test - Configuration Successful'

        body = f"""
<html>
<body style="font-family: Arial, sans-serif;">
    <h2 style="color: #1e40af;">✓ SMTP Configuration Test Successful</h2>
    <p>This is a test email from <strong>SentriKat</strong> vulnerability management system.</p>

    <div style="background-color: #f3f4f6; padding: 15px; border-radius: 5px; margin: 20px 0;">
        <h3>SMTP Configuration Details:</h3>
        <ul>
            <li><strong>Server:</strong> {smtp_config['host']}:{smtp_config['port']}</li>
            <li><strong>From:</strong> {smtp_config['from_email']}</li>
            <li><strong>TLS Enabled:</strong> {'Yes' if smtp_config['use_tls'] else 'No'}</li>
            <li><strong>SSL Enabled:</strong> {'Yes' if smtp_config['use_ssl'] else 'No'}</li>
            <li><strong>Test Recipient:</strong> {test_recipient}</li>
        </ul>
    </div>

    <p>If you received this email, your SMTP configuration is working correctly and SentriKat will be able to send vulnerability alerts.</p>

    <hr style="margin: 30px 0;">
    <p style="color: #6b7280; font-size: 12px;">
        This is an automated test email from SentriKat.<br>
        Sent at: {datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S')} UTC
    </p>
</body>
</html>
        """
        msg.attach(MIMEText(body, 'html'))

        # Send email with proper error handling
        server = None
        try:
            # Set socket timeout for connection
            socket.setdefaulttimeout(30)

            if smtp_config['use_ssl']:
                server = smtplib.SMTP_SSL(smtp_config['host'], smtp_config['port'], timeout=30)
            else:
                server = smtplib.SMTP(smtp_config['host'], smtp_config['port'], timeout=30)
                if smtp_config['use_tls']:
                    server.starttls()

            if smtp_config['username'] and smtp_config['password']:
                server.login(smtp_config['username'], smtp_config['password'])

            server.send_message(msg)

        except socket.timeout:
            return jsonify({
                'success': False,
                'error': f'Connection timeout: Could not connect to {smtp_config["host"]}:{smtp_config["port"]} within 30 seconds. Check firewall settings.'
            })
        except smtplib.SMTPAuthenticationError as e:
            return jsonify({
                'success': False,
                'error': f'Authentication failed: Invalid username or password. Server said: {str(e)}'
            })
        except smtplib.SMTPConnectError as e:
            return jsonify({
                'success': False,
                'error': f'Connection refused: Could not connect to {smtp_config["host"]}:{smtp_config["port"]}. Check server address and port.'
            })
        except smtplib.SMTPRecipientsRefused as e:
            return jsonify({
                'success': False,
                'error': f'Recipient rejected: The server refused to send to {test_recipient}. Check if the address is valid.'
            })
        except smtplib.SMTPSenderRefused as e:
            return jsonify({
                'success': False,
                'error': f'Sender rejected: The server refused the "From" address {smtp_config["from_email"]}. You may need to verify this address.'
            })
        except smtplib.SMTPException as e:
            return jsonify({
                'success': False,
                'error': f'SMTP error: {str(e)}'
            })
        except socket.gaierror as e:
            return jsonify({
                'success': False,
                'error': f'DNS lookup failed: Could not resolve hostname "{smtp_config["host"]}". Check the server address.'
            })
        except ConnectionRefusedError:
            return jsonify({
                'success': False,
                'error': f'Connection refused by {smtp_config["host"]}:{smtp_config["port"]}. Check if SMTP server is running and port is correct.'
            })
        finally:
            if server:
                try:
                    server.quit()
                except:
                    pass

        return jsonify({
            'success': True,
            'message': f'✓ Test email sent successfully to {test_recipient}. Please check your inbox (and spam folder).'
        })

    except Exception as e:
        logger.warning(f"SMTP test failed: {e}")
        return jsonify({'success': False, 'error': f'Unexpected error: {str(e)}'})


# ============================================================================
# Sync Settings
# ============================================================================

@settings_bp.route('/sync', methods=['GET'])
@admin_required
def get_sync_settings():
    """Get sync schedule settings"""
    # Check if NVD API key is configured (return masked indicator)
    nvd_key = get_setting('nvd_api_key', '')
    nvd_api_key_configured = bool(nvd_key and nvd_key != '***ENCRYPTED***')

    settings = {
        'auto_sync_enabled': get_setting('auto_sync_enabled', 'false') == 'true',
        'sync_interval': get_setting('sync_interval', 'daily'),
        'sync_time': get_setting('sync_time', '02:00'),
        'cisa_kev_url': get_setting('cisa_kev_url', 'https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json'),
        'nvd_api_key': '********' if nvd_api_key_configured else '',  # Masked for security
        'nvd_api_key_configured': nvd_api_key_configured
    }
    return jsonify(settings)

@settings_bp.route('/sync', methods=['POST'])
@admin_required
def save_sync_settings():
    """Save sync schedule settings"""
    data = request.get_json()

    if not data:
        return jsonify({'error': 'No data provided'}), 400

    try:
        set_setting('auto_sync_enabled', 'true' if data.get('auto_sync_enabled') else 'false', 'sync', 'Enable automatic sync')
        set_setting('sync_interval', data.get('sync_interval', 'daily'), 'sync', 'Sync interval')
        set_setting('sync_time', data.get('sync_time', '02:00'), 'sync', 'Preferred sync time (UTC)')
        set_setting('cisa_kev_url', data.get('cisa_kev_url', ''), 'sync', 'CISA KEV feed URL')

        # Handle NVD API key - validate before saving
        # Only process if key is explicitly included in the request
        if 'nvd_api_key' in data:
            nvd_key = (data.get('nvd_api_key') or '').strip()
            if nvd_key and nvd_key != '********':
                # Validate the API key by making a test request
                is_valid, error_msg = _validate_nvd_api_key(nvd_key)
                if not is_valid:
                    return jsonify({
                        'success': False,
                        'error': f'Invalid NVD API key: {error_msg}. Key was not saved.'
                    }), 400

                set_setting('nvd_api_key', nvd_key, 'sync', 'NVD API key', is_encrypted=True)
            elif nvd_key == '':
                # User explicitly cleared the API key (via Clear button)
                set_setting('nvd_api_key', '', 'sync', 'NVD API key')
        # If 'nvd_api_key' not in data, don't change the existing key

        return jsonify({'success': True, 'message': 'Sync settings saved successfully'})
    except ValueError as e:
        logger.warning(f"Sync settings validation error: {e}")
        return jsonify({'error': f'Invalid setting: {str(e)}'}), 400
    except Exception as e:
        logger.exception("Failed to save sync settings")
        db.session.rollback()
        return jsonify({'error': 'Failed to save sync settings. Check server logs for details.'}), 500


def _validate_nvd_api_key(api_key):
    """
    Validate an NVD API key by making a test request.
    Returns (is_valid, error_message)
    """
    import requests
    from config import Config

    try:
        url = 'https://services.nvd.nist.gov/rest/json/cpes/2.0'
        params = {'keywordSearch': 'test', 'resultsPerPage': 1}
        headers = {'apiKey': api_key}

        proxies = Config.get_proxies()
        verify_ssl = Config.get_verify_ssl()

        response = requests.get(
            url,
            params=params,
            headers=headers,
            proxies=proxies,
            verify=verify_ssl,
            timeout=15
        )

        if response.status_code == 200:
            return True, None
        elif response.status_code == 403:
            return False, 'API key rejected (403 Forbidden)'
        elif response.status_code == 404:
            return False, 'API key invalid or expired (404 Not Found)'
        else:
            return False, f'Unexpected response: {response.status_code}'

    except requests.exceptions.Timeout:
        return False, 'Connection timeout - check network/proxy settings'
    except requests.exceptions.ConnectionError as e:
        return False, f'Connection error: {str(e)}'
    except Exception as e:
        return False, f'Validation failed: {str(e)}'


@settings_bp.route('/sync/nvd-status', methods=['GET'])
@admin_required
def get_nvd_status():
    """
    Check NVD API connectivity and key status.
    Returns status for display in UI health indicator.
    """
    import requests
    from config import Config
    from app.nvd_rate_limiter import get_rate_limiter, get_nvd_stats

    result = {
        'api_key_configured': False,
        'api_key_valid': None,
        'reachable': False,
        'rate_limit': '5 req/30s',
        'error': None,
        'rate_limiter_stats': None
    }

    try:
        nvd_key = get_setting('nvd_api_key', '')
        result['api_key_configured'] = bool(nvd_key)

        if nvd_key:
            result['rate_limit'] = '50 req/30s'

        # Include rate limiter stats
        try:
            result['rate_limiter_stats'] = get_nvd_stats()
        except Exception:
            pass

        # Use rate limiter for the test request
        limiter = get_rate_limiter()
        if not limiter.acquire(timeout=10.0, block=True):
            result['error'] = 'Rate limit - too many recent requests'
            return jsonify(result)

        # Test connection
        url = 'https://services.nvd.nist.gov/rest/json/cpes/2.0'
        params = {'keywordSearch': 'test', 'resultsPerPage': 1}
        headers = {'apiKey': nvd_key} if nvd_key else {}

        proxies = Config.get_proxies()
        verify_ssl = Config.get_verify_ssl()

        response = requests.get(
            url,
            params=params,
            headers=headers,
            proxies=proxies,
            verify=verify_ssl,
            timeout=15
        )

        if response.status_code == 200:
            result['reachable'] = True
            result['api_key_valid'] = True if nvd_key else None
        elif response.status_code == 403:
            result['reachable'] = True
            result['api_key_valid'] = False
            result['error'] = 'API key rejected or rate limited'
        elif response.status_code == 404:
            result['reachable'] = True
            result['api_key_valid'] = False
            result['error'] = 'API key invalid or expired'
        else:
            result['error'] = f'Unexpected status: {response.status_code}'

    except requests.exceptions.Timeout:
        result['error'] = 'Connection timeout'
    except requests.exceptions.ConnectionError:
        result['error'] = 'Cannot connect to NVD API'
    except Exception as e:
        result['error'] = str(e)

    return jsonify(result)


@settings_bp.route('/sync/nvd-rate-limit', methods=['GET'])
@admin_required
def get_nvd_rate_limit_stats():
    """
    Get NVD API rate limiter statistics.
    Useful for monitoring API usage and troubleshooting.
    """
    try:
        from app.nvd_rate_limiter import get_nvd_stats
        stats = get_nvd_stats()

        return jsonify({
            'success': True,
            'stats': stats,
            'message': f"Using {stats['requests_in_window']}/{stats['effective_limit']} slots "
                       f"({stats['available_slots']} available)"
        })
    except Exception as e:
        logger.exception("Failed to get rate limiter stats")
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500


@settings_bp.route('/sync/status', methods=['GET'])
@admin_required
def get_sync_status():
    """Get sync status information"""
    try:
        # Get last sync
        last_sync = SyncLog.query.order_by(SyncLog.sync_date.desc()).first()

        # Get total vulnerabilities
        total_vulns = Vulnerability.query.count() or 0

        # Calculate next sync (simplified - would need proper scheduling logic)
        auto_sync = get_setting('auto_sync_enabled', 'false') == 'true'
        next_sync = 'Not scheduled' if not auto_sync else 'Based on interval'

        return jsonify({
            'last_sync': last_sync.sync_date.strftime('%Y-%m-%d %H:%M:%S UTC') if last_sync else None,
            'last_sync_status': last_sync.status if last_sync else None,
            'last_sync_added': last_sync.vulnerabilities_count if last_sync else 0,
            'last_sync_updated': 0,  # Not tracked in current model
            'next_sync': next_sync,
            'total_vulnerabilities': total_vulns,
            'auto_sync_enabled': auto_sync
        })
    except Exception as e:
        logger.exception("Failed to get sync status")
        return jsonify({'error': ERROR_MSGS['database']}), 500

# ============================================================================
# General Settings
# ============================================================================

@settings_bp.route('/general', methods=['GET'])
@admin_required
def get_general_settings():
    """Get general system settings (date/time, proxy/network)"""
    settings = {
        # Date & Time display settings
        'display_timezone': get_setting('display_timezone', 'UTC'),
        'date_format': get_setting('date_format', 'YYYY-MM-DD HH:mm'),
        # Network/Proxy settings
        'verify_ssl': get_setting('verify_ssl', 'true') == 'true',
        'http_proxy': get_setting('http_proxy', ''),
        'https_proxy': get_setting('https_proxy', ''),
        'no_proxy': get_setting('no_proxy', '')
    }
    return jsonify(settings)

@settings_bp.route('/general', methods=['POST'])
@admin_required
def save_general_settings():
    """Save general system settings (date/time, proxy/network)"""
    data = request.get_json()

    try:
        # Date & Time display settings
        set_setting('display_timezone', data.get('display_timezone', 'UTC'), 'general', 'Display timezone')
        set_setting('date_format', data.get('date_format', 'YYYY-MM-DD HH:mm'), 'general', 'Date display format')
        # Network/Proxy settings
        set_setting('verify_ssl', 'true' if data.get('verify_ssl') else 'false', 'general', 'Verify SSL certificates')
        set_setting('http_proxy', data.get('http_proxy', ''), 'general', 'HTTP proxy URL')
        set_setting('https_proxy', data.get('https_proxy', ''), 'general', 'HTTPS proxy URL')
        set_setting('no_proxy', data.get('no_proxy', ''), 'general', 'No proxy bypass list')

        return jsonify({'success': True, 'message': 'General settings saved successfully'})
    except Exception as e:
        logger.exception("Failed to save general settings")
        return jsonify({'error': ERROR_MSGS['config']}), 500


# ============================================================================
# Security Settings
# ============================================================================

@settings_bp.route('/security', methods=['GET'])
@admin_required
def get_security_settings():
    """Get security settings"""
    settings = {
        'session_timeout': int(get_setting('session_timeout', '480')),
        'max_failed_logins': int(get_setting('max_failed_logins', '5')),
        'lockout_duration': int(get_setting('lockout_duration', '30')),
        'password_min_length': int(get_setting('password_min_length', '8')),
        'password_require_uppercase': get_setting('password_require_uppercase', 'true') == 'true',
        'password_require_lowercase': get_setting('password_require_lowercase', 'true') == 'true',
        'password_require_numbers': get_setting('password_require_numbers', 'true') == 'true',
        'password_require_special': get_setting('password_require_special', 'false') == 'true',
        'password_expiry_days': int(get_setting('password_expiry_days', '0')),  # 0 = disabled
        'require_2fa': get_setting('require_2fa', 'false') == 'true'
    }
    return jsonify(settings)

@settings_bp.route('/security', methods=['POST'])
@admin_required
def save_security_settings():
    """Save security settings"""
    data = request.get_json()

    try:
        set_setting('session_timeout', str(data.get('session_timeout', 480)), 'security', 'Session timeout (minutes)')
        set_setting('max_failed_logins', str(data.get('max_failed_logins', 5)), 'security', 'Max failed login attempts before lockout')
        set_setting('lockout_duration', str(data.get('lockout_duration', 30)), 'security', 'Account lockout duration (minutes)')
        set_setting('password_min_length', str(data.get('password_min_length', 8)), 'security', 'Minimum password length')
        set_setting('password_require_uppercase', 'true' if data.get('password_require_uppercase') else 'false', 'security', 'Require uppercase letter')
        set_setting('password_require_lowercase', 'true' if data.get('password_require_lowercase') else 'false', 'security', 'Require lowercase letter')
        set_setting('password_require_numbers', 'true' if data.get('password_require_numbers') else 'false', 'security', 'Require number')
        set_setting('password_require_special', 'true' if data.get('password_require_special') else 'false', 'security', 'Require special character')
        set_setting('password_expiry_days', str(data.get('password_expiry_days', 0)), 'security', 'Password expiration (days, 0 = disabled)')
        set_setting('require_2fa', 'true' if data.get('require_2fa') else 'false', 'security', 'Require 2FA for all local users')

        return jsonify({'success': True, 'message': 'Security settings saved successfully'})
    except Exception as e:
        logger.exception("Failed to save security settings")
        return jsonify({'error': ERROR_MSGS['config']}), 500


# ============================================================================
# Branding Settings
# ============================================================================

@settings_bp.route('/branding', methods=['GET'])
@admin_required
@requires_professional('White Label')
def get_branding_settings():
    """Get branding/UI settings (Professional license required)"""
    settings = {
        'app_name': get_setting('app_name', 'SentriKat'),
        'login_message': get_setting('login_message', ''),
        'support_email': get_setting('support_email', ''),
        'show_version': get_setting('show_version', 'true') == 'true',
        'logo_url': get_setting('logo_url', '/static/images/favicon-128x128.png'),
        'report_branding_enabled': get_setting('report_branding_enabled', 'true') == 'true'
    }
    return jsonify(settings)

@settings_bp.route('/branding', methods=['POST'])
@admin_required
@requires_professional('White Label')
def save_branding_settings():
    """Save branding/UI settings (Professional license required)"""
    data = request.get_json()

    try:
        set_setting('app_name', data.get('app_name', 'SentriKat'), 'branding', 'Application name')
        set_setting('login_message', data.get('login_message', ''), 'branding', 'Login page message')
        set_setting('support_email', data.get('support_email', ''), 'branding', 'Support email address')
        set_setting('show_version', 'true' if data.get('show_version') else 'false', 'branding', 'Show version in footer')
        set_setting('report_branding_enabled', 'true' if data.get('report_branding_enabled', True) else 'false', 'branding', 'Show branding in compliance reports')

        return jsonify({'success': True, 'message': 'Branding settings saved successfully'})
    except Exception as e:
        logger.exception("Failed to save branding settings")
        return jsonify({'error': ERROR_MSGS['config']}), 500


# ============================================================================
# Notification Settings (Webhooks)
# ============================================================================

@settings_bp.route('/notifications', methods=['GET'])
@admin_required
@requires_professional('Email Alerts')
def get_notification_settings():
    """Get notification/webhook settings (Professional license required)"""
    settings = {
        'slack_webhook_url': get_setting('slack_webhook_url', ''),
        'slack_enabled': get_setting('slack_enabled', 'false') == 'true',
        'teams_webhook_url': get_setting('teams_webhook_url', ''),
        'teams_enabled': get_setting('teams_enabled', 'false') == 'true',
        # Generic webhook (RocketChat, Mattermost, Discord, etc.)
        'generic_webhook_url': get_setting('generic_webhook_url', ''),
        'generic_webhook_enabled': get_setting('generic_webhook_enabled', 'false') == 'true',
        'generic_webhook_name': get_setting('generic_webhook_name', 'Custom Webhook'),
        'generic_webhook_format': get_setting('generic_webhook_format', 'slack'),  # slack, discord, or custom
        'generic_webhook_custom_template': get_setting('generic_webhook_custom_template', ''),
        'generic_webhook_token_configured': bool(get_setting('generic_webhook_token', '')),  # Don't expose token value
        'critical_email_enabled': get_setting('critical_email_enabled', 'true') == 'true',
        'critical_email_time': get_setting('critical_email_time', '09:00'),
        'critical_email_max_age_days': int(get_setting('critical_email_max_age_days', '30')),
        # Alert mode defaults (can be overridden per-org)
        # new_only: Only alert on new CVEs from this sync
        # daily_reminder: Alert on ALL unacknowledged critical CVEs due within 7 days
        # escalation: Re-alert when CVE is within X days of due date
        'default_alert_mode': get_setting('default_alert_mode', 'daily_reminder'),
        'default_escalation_days': int(get_setting('default_escalation_days', '3') or '3')
    }
    return jsonify(settings)

@settings_bp.route('/notifications', methods=['POST'])
@admin_required
@requires_professional('Email Alerts')
def save_notification_settings():
    """Save notification/webhook settings (Professional license required)"""
    data = request.get_json()

    try:
        set_setting('slack_enabled', 'true' if data.get('slack_enabled') else 'false', 'notifications', 'Enable Slack notifications')
        if data.get('slack_webhook_url'):
            set_setting('slack_webhook_url', data['slack_webhook_url'], 'notifications', 'Slack webhook URL', is_encrypted=True)
        elif 'slack_webhook_url' in data and not data.get('slack_webhook_url'):
            set_setting('slack_webhook_url', '', 'notifications', 'Slack webhook URL')

        set_setting('teams_enabled', 'true' if data.get('teams_enabled') else 'false', 'notifications', 'Enable Teams notifications')
        if data.get('teams_webhook_url'):
            set_setting('teams_webhook_url', data['teams_webhook_url'], 'notifications', 'Microsoft Teams webhook URL', is_encrypted=True)
        elif 'teams_webhook_url' in data and not data.get('teams_webhook_url'):
            set_setting('teams_webhook_url', '', 'notifications', 'Microsoft Teams webhook URL')

        # Generic webhook settings (RocketChat, Mattermost, Discord, etc.)
        set_setting('generic_webhook_enabled', 'true' if data.get('generic_webhook_enabled') else 'false', 'notifications', 'Enable generic webhook notifications')
        if data.get('generic_webhook_url'):
            set_setting('generic_webhook_url', data['generic_webhook_url'], 'notifications', 'Generic webhook URL', is_encrypted=True)
        elif 'generic_webhook_url' in data and not data.get('generic_webhook_url'):
            set_setting('generic_webhook_url', '', 'notifications', 'Generic webhook URL')
        set_setting('generic_webhook_name', data.get('generic_webhook_name', 'Custom Webhook'), 'notifications', 'Generic webhook display name')
        set_setting('generic_webhook_format', data.get('generic_webhook_format', 'slack'), 'notifications', 'Generic webhook payload format')
        if data.get('generic_webhook_custom_template'):
            set_setting('generic_webhook_custom_template', data['generic_webhook_custom_template'], 'notifications', 'Custom JSON template for webhook')
        elif 'generic_webhook_custom_template' in data and not data.get('generic_webhook_custom_template'):
            set_setting('generic_webhook_custom_template', '', 'notifications', 'Custom JSON template for webhook')
        # Optional auth token for webhooks that require it
        if data.get('generic_webhook_token'):
            set_setting('generic_webhook_token', data['generic_webhook_token'], 'notifications', 'Webhook auth token', is_encrypted=True)
        elif 'generic_webhook_token' in data and not data.get('generic_webhook_token'):
            # Clear token if explicitly set to empty
            set_setting('generic_webhook_token', '', 'notifications', 'Webhook auth token')

        set_setting('critical_email_enabled', 'true' if data.get('critical_email_enabled') else 'false', 'notifications', 'Enable critical CVE reminder emails')
        set_setting('critical_email_time', data.get('critical_email_time', '09:00'), 'notifications', 'Critical CVE email time (UTC)')
        set_setting('critical_email_max_age_days', str(data.get('critical_email_max_age_days', 30)), 'notifications', 'Max age for CVEs in reminder (days)')

        # Alert mode defaults
        if 'default_alert_mode' in data:
            mode = data['default_alert_mode']
            if mode in ['new_only', 'daily_reminder', 'escalation']:
                set_setting('default_alert_mode', mode, 'notifications', 'Default alert mode for organizations')
        if 'default_escalation_days' in data:
            days = int(data.get('default_escalation_days', 3))
            set_setting('default_escalation_days', str(days), 'notifications', 'Default escalation days before due date')

        return jsonify({'success': True, 'message': 'Notification settings saved successfully'})
    except Exception as e:
        logger.exception("Failed to save notification settings")
        return jsonify({'error': ERROR_MSGS['config']}), 500

def _is_ssrf_safe_url(url):
    """Validate that a URL does not target internal/private network addresses."""
    from urllib.parse import urlparse
    import ipaddress
    import socket

    try:
        parsed = urlparse(url)
        hostname = parsed.hostname
        if not hostname or parsed.scheme not in ('http', 'https'):
            return False

        # Resolve hostname to IP and check against private ranges
        try:
            ip = ipaddress.ip_address(hostname)
        except ValueError:
            # It's a hostname, resolve it
            try:
                resolved = socket.getaddrinfo(hostname, None, socket.AF_UNSPEC, socket.SOCK_STREAM)
                ip = ipaddress.ip_address(resolved[0][4][0])
            except (socket.gaierror, IndexError, OSError):
                return True  # Can't resolve - let the request fail naturally

        # Block private, loopback, link-local, and metadata addresses
        if ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_reserved:
            return False
        # Block AWS/GCP/Azure metadata endpoints
        if str(ip) in ('169.254.169.254', '169.254.170.2'):
            return False

        return True
    except Exception:
        return False


@settings_bp.route('/notifications/test', methods=['POST'])
@admin_required
@requires_professional('Email Alerts')
def test_notification():
    """Test webhook notification (Professional license required)"""
    import requests
    data = request.get_json()
    webhook_type = data.get('type', 'slack')

    # Get proxy and SSL settings
    verify_ssl = get_setting('verify_ssl', 'true') == 'true'
    http_proxy = get_setting('http_proxy', '')
    https_proxy = get_setting('https_proxy', '')

    proxies = {}
    if http_proxy:
        proxies['http'] = http_proxy
    if https_proxy:
        proxies['https'] = https_proxy

    try:
        if webhook_type == 'slack':
            webhook_url = get_setting('slack_webhook_url')
            if not webhook_url:
                return jsonify({'success': False, 'error': 'Slack webhook URL not configured'})

            payload = {
                "text": "🔒 SentriKat Test Notification",
                "blocks": [
                    {
                        "type": "section",
                        "text": {
                            "type": "mrkdwn",
                            "text": "*SentriKat Webhook Test*\n✓ Your Slack integration is working correctly!"
                        }
                    }
                ]
            }
            response = requests.post(webhook_url, json=payload, timeout=30, proxies=proxies, verify=verify_ssl)

        elif webhook_type == 'teams':
            webhook_url = get_setting('teams_webhook_url')
            if not webhook_url:
                return jsonify({'success': False, 'error': 'Teams webhook URL not configured'})

            payload = {
                "@type": "MessageCard",
                "@context": "http://schema.org/extensions",
                "themeColor": "1e40af",
                "summary": "SentriKat Test Notification",
                "sections": [{
                    "activityTitle": "🔒 SentriKat Webhook Test",
                    "activitySubtitle": "Your Microsoft Teams integration is working correctly!",
                    "markdown": True
                }]
            }
            response = requests.post(webhook_url, json=payload, timeout=30, proxies=proxies, verify=verify_ssl)

        elif webhook_type == 'generic':
            webhook_url = get_setting('generic_webhook_url')
            if not webhook_url:
                return jsonify({'success': False, 'error': 'Generic webhook URL not configured. Please save settings first.'})

            # Log the request for debugging (mask sensitive parts of URL)
            masked_url = webhook_url[:50] + '...' if len(webhook_url) > 50 else webhook_url
            logger.info(f"Testing generic webhook to: {masked_url}, verify_ssl={verify_ssl}, using_proxy={bool(proxies)}")

            webhook_format = get_setting('generic_webhook_format', 'slack')
            webhook_name = get_setting('generic_webhook_name', 'Custom Webhook')
            custom_template = get_setting('generic_webhook_custom_template', '')
            webhook_token = get_setting('generic_webhook_token', '')

            # Build headers - add auth token if configured
            headers = {'Content-Type': 'application/json'}
            if webhook_token:
                # Support multiple auth header formats
                headers['X-Webhook-Token'] = webhook_token
                headers['Authorization'] = f'Bearer {webhook_token}'
                headers['X-Auth-Token'] = webhook_token

            # Build payload based on format
            if webhook_format == 'slack' or webhook_format == 'rocketchat':
                # Slack-compatible format (works with RocketChat, Mattermost)
                payload = {
                    "text": f"🔒 SentriKat Test Notification\n✓ Your {webhook_name} integration is working correctly!"
                }
            elif webhook_format == 'discord':
                # Discord webhook format
                payload = {
                    "content": f"🔒 **SentriKat Test Notification**\n✓ Your {webhook_name} integration is working correctly!"
                }
            elif webhook_format == 'custom' and custom_template:
                # Custom JSON template - replace placeholders
                import json as json_module
                try:
                    template_str = custom_template.replace('{{message}}', f'SentriKat Test Notification - Your {webhook_name} integration is working correctly!')
                    template_str = template_str.replace('{{title}}', 'SentriKat Webhook Test')
                    payload = json_module.loads(template_str)
                except json_module.JSONDecodeError as e:
                    return jsonify({'success': False, 'error': f'Invalid custom template JSON: {e}'})
            else:
                # Default simple format
                payload = {
                    "text": f"🔒 SentriKat Test Notification\n✓ Your {webhook_name} integration is working correctly!"
                }

            logger.info(f"Sending webhook request with headers: {list(headers.keys())}, payload keys: {list(payload.keys())}")
            response = requests.post(webhook_url, json=payload, headers=headers, timeout=30, proxies=proxies, verify=verify_ssl)
            logger.info(f"Webhook response: status={response.status_code}, body_length={len(response.text)}")
            webhook_type = webhook_name  # Use custom name for message

        elif webhook_type == 'org':
            # Test org-specific webhook (URL provided in request)
            webhook_url = data.get('webhook_url')
            if not webhook_url:
                return jsonify({'success': False, 'error': 'Webhook URL not provided'})

            # SSRF protection: block requests to internal/private networks
            if not _is_ssrf_safe_url(webhook_url):
                return jsonify({'success': False, 'error': 'Webhook URL must not target internal or private network addresses'}), 400

            webhook_format = data.get('webhook_format', 'slack')
            webhook_name = data.get('webhook_name', 'Organization Webhook')
            webhook_token = data.get('webhook_token', '')

            # Build headers
            headers = {'Content-Type': 'application/json'}
            if webhook_token:
                headers['Authorization'] = f'Bearer {webhook_token}'
                headers['X-Auth-Token'] = webhook_token

            # Build payload based on format
            if webhook_format in ('slack', 'rocketchat'):
                payload = {"text": f"🔒 SentriKat Test\n✓ {webhook_name} is working correctly!"}
            elif webhook_format == 'discord':
                payload = {"content": f"🔒 **SentriKat Test**\n✓ {webhook_name} is working correctly!"}
            elif webhook_format == 'teams':
                payload = {
                    "@type": "MessageCard",
                    "themeColor": "1e40af",
                    "summary": "SentriKat Test",
                    "sections": [{"activityTitle": f"🔒 SentriKat Test - {webhook_name} is working!"}]
                }
            else:
                payload = {"text": f"SentriKat Test - {webhook_name} is working correctly!"}

            response = requests.post(webhook_url, json=payload, headers=headers, timeout=30, proxies=proxies, verify=verify_ssl)
            webhook_type = webhook_name

        else:
            return jsonify({'success': False, 'error': f'Unknown webhook type: {webhook_type}'})

        if response.status_code in [200, 204]:
            return jsonify({'success': True, 'message': f'Test notification sent to {webhook_type.title() if isinstance(webhook_type, str) and webhook_type.islower() else webhook_type}'})
        else:
            # Log full details for debugging
            logger.warning(f"Webhook test failed: status={response.status_code}, body={response.text[:500]}")

            # Return brief user-friendly message
            if response.status_code == 403:
                error_msg = 'Forbidden (403). Check webhook URL has token.'
            elif response.status_code == 401:
                error_msg = 'Unauthorized (401). Check auth token.'
            elif response.status_code == 404:
                error_msg = 'Not Found (404). Check webhook URL.'
            else:
                error_msg = f'Error {response.status_code}. Check server logs.'
            return jsonify({'success': False, 'error': error_msg})

    except requests.exceptions.Timeout:
        return jsonify({'success': False, 'error': 'Connection timed out after 30 seconds. Check your proxy settings and network connectivity.'})
    except requests.exceptions.ProxyError as e:
        logger.warning(f"Webhook proxy error: {e}")
        return jsonify({'success': False, 'error': 'Proxy error. Check your proxy settings.'})
    except requests.exceptions.SSLError as e:
        logger.warning(f"Webhook SSL error: {e}")
        return jsonify({'success': False, 'error': 'SSL error. Try disabling SSL verification in General Settings if using self-signed certificates.'})
    except Exception as e:
        logger.exception("Webhook test failed")
        return jsonify({'success': False, 'error': ERROR_MSGS['external']})


# ============================================================================
# Data Retention Settings
# ============================================================================

@settings_bp.route('/retention', methods=['GET'])
@admin_required
def get_retention_settings():
    """Get data retention settings"""
    settings = {
        'audit_log_retention_days': int(get_setting('audit_log_retention_days', '365')),
        'sync_history_retention_days': int(get_setting('sync_history_retention_days', '90')),
        'session_log_retention_days': int(get_setting('session_log_retention_days', '30')),
        'auto_acknowledge_removed_software': get_setting('auto_acknowledge_removed_software', 'true') == 'true'
    }
    return jsonify(settings)

@settings_bp.route('/retention', methods=['POST'])
@admin_required
def save_retention_settings():
    """Save data retention settings"""
    data = request.get_json()

    try:
        set_setting('audit_log_retention_days', str(data.get('audit_log_retention_days', 365)), 'retention', 'Audit log retention (days)')
        set_setting('sync_history_retention_days', str(data.get('sync_history_retention_days', 90)), 'retention', 'Sync history retention (days)')
        set_setting('session_log_retention_days', str(data.get('session_log_retention_days', 30)), 'retention', 'Session log retention (days)')
        set_setting('auto_acknowledge_removed_software', 'true' if data.get('auto_acknowledge_removed_software', True) else 'false', 'retention', 'Auto-acknowledge CVEs when software is removed')

        return jsonify({'success': True, 'message': 'Retention settings saved successfully'})
    except Exception as e:
        logger.exception("Failed to save retention settings")
        return jsonify({'error': ERROR_MSGS['config']}), 500


@settings_bp.route('/maintenance/auto-acknowledge', methods=['POST'])
@admin_required
def run_auto_acknowledge():
    """
    Manually trigger auto-acknowledge for removed software vulnerabilities.
    Useful for testing or immediate cleanup without waiting for scheduled maintenance.
    """
    try:
        from app.maintenance import auto_acknowledge_resolved_vulnerabilities

        dry_run = request.get_json().get('dry_run', False) if request.is_json else False

        count = auto_acknowledge_resolved_vulnerabilities(dry_run=dry_run)

        return jsonify({
            'success': True,
            'acknowledged_count': count,
            'dry_run': dry_run,
            'message': f"{'Would acknowledge' if dry_run else 'Acknowledged'} {count} vulnerability matches"
        })
    except Exception as e:
        logger.exception("Failed to run auto-acknowledge")
        return jsonify({'error': str(e)}), 500


# ============================================================================
# Logo Upload
# ============================================================================

ALLOWED_IMAGE_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif', 'svg', 'webp'}
MAX_LOGO_SIZE = 2 * 1024 * 1024  # 2MB

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_IMAGE_EXTENSIONS

@settings_bp.route('/branding/logo', methods=['POST'])
@admin_required
def upload_logo():
    """Upload a custom logo"""
    import os
    from werkzeug.utils import secure_filename

    if 'logo' not in request.files:
        return jsonify({'error': 'No file provided'}), 400

    file = request.files['logo']

    if file.filename == '':
        return jsonify({'error': 'No file selected'}), 400

    if not allowed_file(file.filename):
        return jsonify({'error': f'Invalid file type. Allowed: {", ".join(ALLOWED_IMAGE_EXTENSIONS)}'}), 400

    # Check file size
    file.seek(0, 2)  # Seek to end
    size = file.tell()
    file.seek(0)  # Seek back to start

    if size > MAX_LOGO_SIZE:
        return jsonify({'error': f'File too large. Maximum size: {MAX_LOGO_SIZE // (1024*1024)}MB'}), 400

    try:
        # Create uploads directory in /app/data (persistent volume)
        data_dir = os.environ.get('DATA_DIR', '/app/data')
        upload_dir = os.path.join(data_dir, 'uploads')
        os.makedirs(upload_dir, exist_ok=True)

        # Generate safe filename
        ext = file.filename.rsplit('.', 1)[1].lower()
        filename = f'custom_logo.{ext}'
        filepath = os.path.join(upload_dir, filename)

        # Save file
        file.save(filepath)

        # Update branding setting with logo path (served via /data/uploads route)
        logo_url = f'/data/uploads/{filename}'
        set_setting('logo_url', logo_url, 'branding', 'Custom logo URL')

        # Log audit event for logo upload
        log_audit_event(
            'UPDATE',
            'branding',
            resource_id='logo',
            new_value={'logo_url': logo_url, 'filename': filename},
            details=f'Custom logo uploaded: {filename}'
        )

        return jsonify({
            'success': True,
            'message': 'Logo uploaded successfully',
            'logo_url': logo_url
        })
    except Exception as e:
        logger.exception("Logo upload failed")
        return jsonify({'error': ERROR_MSGS['upload']}), 500

@settings_bp.route('/branding/logo', methods=['DELETE'])
@admin_required
def delete_logo():
    """Remove custom logo and revert to default"""
    import os

    try:
        # Get current logo path
        logo_url = get_setting('logo_url', '')

        if logo_url and logo_url.startswith('/data/uploads/'):
            # Delete file from persistent data directory
            # Use basename to prevent path traversal attacks
            data_dir = os.environ.get('DATA_DIR', '/app/data')
            safe_filename = os.path.basename(logo_url)
            # Extra validation: reject any suspicious patterns
            if '..' in safe_filename or safe_filename.startswith('/'):
                return jsonify({'error': 'Invalid logo path'}), 400
            filepath = os.path.join(data_dir, 'uploads', safe_filename)
            # Verify filepath is within uploads directory (belt and suspenders)
            real_filepath = os.path.realpath(filepath)
            real_uploads_dir = os.path.realpath(os.path.join(data_dir, 'uploads'))
            if not real_filepath.startswith(real_uploads_dir):
                return jsonify({'error': 'Invalid logo path'}), 400
            if os.path.exists(filepath):
                os.remove(filepath)
        elif logo_url and logo_url.startswith('/static/uploads/'):
            # Legacy: delete file from static directory
            # Use basename to prevent path traversal attacks
            safe_filename = os.path.basename(logo_url)
            if '..' in safe_filename or safe_filename.startswith('/'):
                return jsonify({'error': 'Invalid logo path'}), 400
            static_dir = os.path.join(os.path.dirname(os.path.dirname(__file__)), 'static', 'uploads')
            filepath = os.path.join(static_dir, safe_filename)
            # Verify filepath is within static/uploads directory
            real_filepath = os.path.realpath(filepath)
            real_static_dir = os.path.realpath(static_dir)
            if not real_filepath.startswith(real_static_dir):
                return jsonify({'error': 'Invalid logo path'}), 400
            if os.path.exists(filepath):
                os.remove(filepath)

        # Remove setting
        setting = SystemSettings.query.filter_by(key='logo_url').first()
        if setting:
            db.session.delete(setting)
            db.session.commit()

        # Log audit event for logo deletion
        log_audit_event(
            'DELETE',
            'branding',
            resource_id='logo',
            old_value={'logo_url': logo_url} if logo_url else None,
            details='Custom logo removed, reverted to default'
        )

        return jsonify({'success': True, 'message': 'Logo removed, reverted to default'})
    except Exception as e:
        logger.exception("Logo deletion failed")
        return jsonify({'error': ERROR_MSGS['internal']}), 500


# ============================================================================
# Backup & Restore
# ============================================================================

@settings_bp.route('/backup', methods=['GET'])
@admin_required
@requires_professional('Backup & Restore')
def create_backup():
    """
    Create a backup of all settings and configuration.
    Only accessible by super admins.

    Returns a JSON file containing:
    - System settings
    - Organizations
    - Users (without password hashes)
    - Products
    - Service catalog
    """
    import json
    from datetime import datetime
    from flask import Response

    from app.auth import get_current_user
    current_user = get_current_user()

    if not current_user or not current_user.is_super_admin():
        return jsonify({'error': 'Only super admins can create backups'}), 403

    try:
        from app.models import Organization, Product, User, ServiceCatalog

        backup_data = {
            'backup_info': {
                'version': '1.1',  # Updated version for CPE mappings support
                'created_at': datetime.utcnow().isoformat(),
                'created_by': current_user.username,
                'app_name': get_setting('app_name', 'SentriKat')
            },
            'settings': {},
            'organizations': [],
            'users': [],
            'products': [],
            'service_catalog': [],
            'user_cpe_mappings': []  # User-learned CPE mappings
        }

        # Export settings
        settings = SystemSettings.query.all()
        for s in settings:
            # Skip encrypted settings for security
            if s.is_encrypted:
                backup_data['settings'][s.key] = '***ENCRYPTED***'
            else:
                backup_data['settings'][s.key] = {
                    'value': s.value,
                    'category': s.category,
                    'description': s.description
                }

        # Export organizations
        for org in Organization.query.all():
            org_data = {
                'id': org.id,
                'name': org.name,
                'display_name': org.display_name,
                'description': org.description,
                'notification_emails': org.notification_emails,
                'alert_on_critical': org.alert_on_critical,
                'alert_on_high': org.alert_on_high,
                'alert_on_new_cve': org.alert_on_new_cve,
                'alert_on_ransomware': org.alert_on_ransomware,
                'active': org.active
                # SMTP credentials excluded for security
            }
            backup_data['organizations'].append(org_data)

        # Export users (without sensitive data)
        for user in User.query.all():
            user_data = {
                'id': user.id,
                'username': user.username,
                'email': user.email,
                'full_name': user.full_name,
                'organization_id': user.organization_id,
                'auth_type': user.auth_type,
                'role': user.role,
                'is_admin': user.is_admin,
                'is_active': user.is_active,
                'can_manage_products': user.can_manage_products,
                'can_view_all_orgs': user.can_view_all_orgs
                # Password hash, TOTP secret excluded for security
            }
            backup_data['users'].append(user_data)

        # Export products
        for product in Product.query.all():
            product_data = {
                'id': product.id,
                'organization_id': product.organization_id,
                'vendor': product.vendor,
                'product_name': product.product_name,
                'version': product.version,
                'keywords': product.keywords,
                'description': product.description,
                'active': product.active,
                'criticality': product.criticality
            }
            backup_data['products'].append(product_data)

        # Export service catalog
        for catalog in ServiceCatalog.query.all():
            catalog_data = {
                'id': catalog.id,
                'vendor': catalog.vendor,
                'product_name': catalog.product_name,
                'category': catalog.category,
                'subcategory': catalog.subcategory,
                'common_names': catalog.common_names,
                'description': catalog.description,
                'is_popular': catalog.is_popular
            }
            backup_data['service_catalog'].append(catalog_data)

        # Export user CPE mappings
        try:
            from app.models import UserCpeMapping
            for mapping in UserCpeMapping.query.all():
                mapping_data = mapping.to_export_dict()
                backup_data['user_cpe_mappings'].append(mapping_data)
        except Exception as e:
            logger.warning(f"Could not export CPE mappings: {e}")

        # Generate filename
        timestamp = datetime.utcnow().strftime('%Y%m%d_%H%M%S')
        filename = f'sentrikat_backup_{timestamp}.json'

        output = json.dumps(backup_data, indent=2)

        logger.info(f"Backup created by {current_user.username}")

        return Response(
            output,
            mimetype='application/json',
            headers={'Content-Disposition': f'attachment; filename={filename}'}
        )

    except Exception as e:
        logger.exception("Backup creation failed")
        return jsonify({'error': ERROR_MSGS['backup']}), 500


@settings_bp.route('/restore', methods=['POST'])
@admin_required
@requires_professional('Backup & Restore')
def restore_backup():
    """
    Restore settings from a backup file.
    Only accessible by super admins.

    Only restores settings - does not restore users/products to prevent data loss.
    """
    import json

    from app.auth import get_current_user
    current_user = get_current_user()

    if not current_user or not current_user.is_super_admin():
        return jsonify({'error': 'Only super admins can restore backups'}), 403

    if 'backup' not in request.files:
        return jsonify({'error': 'No backup file provided'}), 400

    file = request.files['backup']

    if file.filename == '':
        return jsonify({'error': 'No file selected'}), 400

    try:
        backup_data = json.load(file)

        # Validate backup format
        if 'backup_info' not in backup_data or 'settings' not in backup_data:
            return jsonify({'error': 'Invalid backup file format'}), 400

        restored_count = 0
        skipped_count = 0

        # Restore settings (excluding encrypted ones)
        for key, value in backup_data['settings'].items():
            if value == '***ENCRYPTED***':
                skipped_count += 1
                continue

            if isinstance(value, dict):
                set_setting(
                    key,
                    value.get('value', ''),
                    value.get('category', 'general'),
                    value.get('description', '')
                )
                restored_count += 1

        db.session.commit()

        logger.info(f"Backup restored by {current_user.username}: {restored_count} settings restored, {skipped_count} skipped")

        return jsonify({
            'success': True,
            'message': f'Restore complete: {restored_count} settings restored, {skipped_count} encrypted settings skipped',
            'restored_count': restored_count,
            'skipped_count': skipped_count,
            'backup_info': backup_data.get('backup_info', {})
        })

    except json.JSONDecodeError:
        return jsonify({'error': 'Invalid JSON file'}), 400
    except Exception as e:
        db.session.rollback()
        logger.exception("Restore failed")
        return jsonify({'error': ERROR_MSGS['restore']}), 500


@settings_bp.route('/restore-full', methods=['POST'])
@admin_required
@requires_professional('Backup & Restore')
def restore_full_backup():
    """
    Full restore from a backup file - restores everything including orgs, users, products.
    Only works on fresh installations (when only the setup admin exists).

    WARNING: This will replace all data except the current admin user!
    """
    import json
    from app.auth import get_current_user
    from app.models import Organization, Product, User, ServiceCatalog

    current_user = get_current_user()

    if not current_user or not current_user.is_super_admin():
        return jsonify({'error': 'Only super admins can perform full restore'}), 403

    if 'backup' not in request.files:
        return jsonify({'error': 'No backup file provided'}), 400

    file = request.files['backup']
    if file.filename == '':
        return jsonify({'error': 'No file selected'}), 400

    try:
        backup_data = json.load(file)

        # Validate backup format
        if 'backup_info' not in backup_data:
            return jsonify({'error': 'Invalid backup file format'}), 400

        stats = {
            'settings': 0,
            'organizations': 0,
            'users': 0,
            'products': 0,
            'service_catalog': 0,
            'skipped': 0
        }

        # Store current user info to preserve
        current_user_id = current_user.id
        current_user_username = current_user.username

        # Map old IDs to new IDs for relationships
        org_id_map = {}
        user_id_map = {}

        # 1. Restore organizations first (needed for user relationships)
        if 'organizations' in backup_data:
            for org_data in backup_data['organizations']:
                # Check if org with same name exists
                existing = Organization.query.filter_by(name=org_data['name']).first()
                if existing:
                    org_id_map[org_data['id']] = existing.id
                    stats['skipped'] += 1
                    continue

                org = Organization(
                    name=org_data['name'],
                    display_name=org_data.get('display_name', org_data['name']),
                    description=org_data.get('description', ''),
                    notification_emails=org_data.get('notification_emails', '[]'),
                    alert_on_critical=org_data.get('alert_on_critical', True),
                    alert_on_high=org_data.get('alert_on_high', False),
                    alert_on_new_cve=org_data.get('alert_on_new_cve', True),
                    alert_on_ransomware=org_data.get('alert_on_ransomware', True),
                    active=org_data.get('active', True)
                )
                db.session.add(org)
                db.session.flush()  # Get the new ID
                org_id_map[org_data['id']] = org.id
                stats['organizations'] += 1

        # 2. Restore users (without passwords - they'll need to reset or use LDAP)
        if 'users' in backup_data:
            for user_data in backup_data['users']:
                # Skip the current admin user and users that already exist
                if user_data['username'] == current_user_username:
                    user_id_map[user_data['id']] = current_user_id
                    continue

                # Check for existing user by username OR email (both are unique)
                existing = User.query.filter_by(username=user_data['username']).first()
                if not existing and user_data.get('email'):
                    existing = User.query.filter_by(email=user_data['email']).first()

                if existing:
                    user_id_map[user_data['id']] = existing.id
                    stats['skipped'] += 1
                    continue

                # Map old org ID to new org ID
                org_id = org_id_map.get(user_data.get('organization_id'))

                user = User(
                    username=user_data['username'],
                    email=user_data.get('email', ''),
                    full_name=user_data.get('full_name', user_data['username']),
                    organization_id=org_id,
                    auth_type=user_data.get('auth_type', 'local'),
                    role=user_data.get('role', 'user'),
                    is_admin=user_data.get('is_admin', False),
                    is_active=user_data.get('is_active', True),
                    can_manage_products=user_data.get('can_manage_products', True),
                    can_view_all_orgs=user_data.get('can_view_all_orgs', False)
                )
                # Set a temporary password for local users (they'll need to reset)
                if user.auth_type == 'local':
                    import secrets
                    user.set_password(secrets.token_urlsafe(32))
                    user.must_change_password = True

                db.session.add(user)
                db.session.flush()
                user_id_map[user_data['id']] = user.id
                stats['users'] += 1

        # 3. Restore products
        if 'products' in backup_data:
            for product_data in backup_data['products']:
                # Map old org ID to new org ID
                org_id = org_id_map.get(product_data.get('organization_id'))
                if not org_id:
                    stats['skipped'] += 1
                    continue

                # Check if product already exists
                existing = Product.query.filter_by(
                    organization_id=org_id,
                    vendor=product_data.get('vendor', ''),
                    product_name=product_data.get('product_name', '')
                ).first()
                if existing:
                    stats['skipped'] += 1
                    continue

                product = Product(
                    organization_id=org_id,
                    vendor=product_data.get('vendor', ''),
                    product_name=product_data.get('product_name', ''),
                    version=product_data.get('version', ''),
                    keywords=product_data.get('keywords', ''),
                    description=product_data.get('description', ''),
                    active=product_data.get('active', True),
                    criticality=product_data.get('criticality', 'medium')
                )
                db.session.add(product)
                stats['products'] += 1

        # 4. Restore service catalog
        if 'service_catalog' in backup_data:
            for catalog_data in backup_data['service_catalog']:
                # Check if entry already exists
                existing = ServiceCatalog.query.filter_by(
                    vendor=catalog_data.get('vendor', ''),
                    product_name=catalog_data.get('product_name', '')
                ).first()
                if existing:
                    stats['skipped'] += 1
                    continue

                catalog = ServiceCatalog(
                    vendor=catalog_data.get('vendor', ''),
                    product_name=catalog_data.get('product_name', ''),
                    category=catalog_data.get('category', ''),
                    subcategory=catalog_data.get('subcategory', ''),
                    common_names=catalog_data.get('common_names') or None,
                    description=catalog_data.get('description', ''),
                    is_popular=catalog_data.get('is_popular', False)
                )
                db.session.add(catalog)
                stats['service_catalog'] += 1

        # 5. Restore settings (excluding encrypted ones)
        if 'settings' in backup_data:
            for key, value in backup_data['settings'].items():
                if value == '***ENCRYPTED***':
                    stats['skipped'] += 1
                    continue

                if isinstance(value, dict):
                    set_setting(
                        key,
                        value.get('value', ''),
                        value.get('category', 'general'),
                        value.get('description', '')
                    )
                    stats['settings'] += 1

        # 6. Restore user CPE mappings
        stats['cpe_mappings'] = 0
        if 'user_cpe_mappings' in backup_data:
            try:
                from app.cpe_mappings import import_user_mappings
                result = import_user_mappings(
                    backup_data['user_cpe_mappings'],
                    user_id=current_user.id,
                    overwrite=False  # Don't overwrite existing
                )
                stats['cpe_mappings'] = result.get('imported', 0)
                stats['skipped'] += result.get('skipped', 0)
            except Exception as e:
                logger.warning(f"Could not restore CPE mappings: {e}")

        db.session.commit()

        logger.info(f"Full backup restored by {current_user.username}: {stats}")

        return jsonify({
            'success': True,
            'message': 'Full restore complete',
            'stats': stats,
            'backup_info': backup_data.get('backup_info', {}),
            'note': 'Local users will need to reset their passwords'
        })

    except json.JSONDecodeError:
        return jsonify({'error': 'Invalid JSON file'}), 400
    except Exception as e:
        db.session.rollback()
        logger.exception("Full restore failed")
        return jsonify({'error': ERROR_MSGS['restore']}), 500
