"""
Settings API Endpoints
Handles LDAP, SMTP, Sync, and General system settings
"""

from flask import Blueprint, request, jsonify, session
from app import db, csrf
from app.models import SystemSettings, User, Vulnerability, SyncLog
from app.auth import admin_required
from app.encryption import encrypt_value, decrypt_value
from app.licensing import requires_professional
import json
from datetime import datetime
import logging

logger = logging.getLogger(__name__)

settings_bp = Blueprint('settings', __name__, url_prefix='/api/settings')

# Exempt API routes from CSRF (they use JSON and are protected by SameSite cookies)
csrf.exempt(settings_bp)

# ============================================================================
# Helper Functions
# ============================================================================

def get_setting(key, default=None):
    """
    Get a setting value from database.
    Automatically decrypts values marked as encrypted.
    """
    setting = SystemSettings.query.filter_by(key=key).first()
    if not setting:
        return default

    # Decrypt if the setting is marked as encrypted
    if setting.is_encrypted and setting.value:
        try:
            return decrypt_value(setting.value)
        except Exception as e:
            logger.error(f"Failed to decrypt setting '{key}': {type(e).__name__}")
            # Return the raw value - might be legacy plaintext
            return setting.value

    return setting.value

def set_setting(key, value, category, description=None, is_encrypted=False):
    """
    Set a setting value in database.
    Encrypts the value if is_encrypted=True.
    """
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
# LDAP Settings
# ============================================================================

@settings_bp.route('/ldap', methods=['GET'])
@admin_required
@requires_professional('LDAP')
def get_ldap_settings():
    """Get LDAP configuration settings"""
    settings = {
        'ldap_enabled': get_setting('ldap_enabled', 'false') == 'true',
        'ldap_server': get_setting('ldap_server', ''),
        'ldap_port': int(get_setting('ldap_port', '389')),
        'ldap_base_dn': get_setting('ldap_base_dn', ''),
        'ldap_bind_dn': get_setting('ldap_bind_dn', ''),
        'ldap_search_filter': get_setting('ldap_search_filter', '(sAMAccountName={username})'),
        'ldap_username_attr': get_setting('ldap_username_attr', 'sAMAccountName'),
        'ldap_email_attr': get_setting('ldap_email_attr', 'mail'),
        'ldap_use_tls': get_setting('ldap_use_tls', 'false') == 'true'
    }
    return jsonify(settings)

@settings_bp.route('/ldap', methods=['POST'])
@admin_required
@requires_professional('LDAP')
def save_ldap_settings():
    """Save LDAP configuration settings"""
    data = request.get_json()

    try:
        set_setting('ldap_enabled', 'true' if data.get('ldap_enabled') else 'false', 'ldap', 'Enable LDAP authentication')
        set_setting('ldap_server', data.get('ldap_server', ''), 'ldap', 'LDAP server URL')
        set_setting('ldap_port', str(data.get('ldap_port', 389)), 'ldap', 'LDAP server port')
        set_setting('ldap_base_dn', data.get('ldap_base_dn', ''), 'ldap', 'LDAP base DN')
        set_setting('ldap_bind_dn', data.get('ldap_bind_dn', ''), 'ldap', 'LDAP bind DN (service account)')

        # Encrypt bind password
        if data.get('ldap_bind_password'):
            set_setting('ldap_bind_password', data['ldap_bind_password'], 'ldap', 'LDAP bind password', is_encrypted=True)

        set_setting('ldap_search_filter', data.get('ldap_search_filter', '(sAMAccountName={username})'), 'ldap', 'LDAP search filter')
        set_setting('ldap_username_attr', data.get('ldap_username_attr', 'sAMAccountName'), 'ldap', 'LDAP username attribute')
        set_setting('ldap_email_attr', data.get('ldap_email_attr', 'mail'), 'ldap', 'LDAP email attribute')
        set_setting('ldap_use_tls', 'true' if data.get('ldap_use_tls') else 'false', 'ldap', 'Use TLS/STARTTLS')

        return jsonify({'success': True, 'message': 'LDAP settings saved successfully'})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

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

        # Parse server URL
        server_url = ldap_server.replace('ldap://', '').replace('ldaps://', '').split(':')[0]

        # Create server object
        use_ssl = 'ldaps://' in ldap_server
        server = ldap3.Server(server_url, port=ldap_port, use_ssl=use_ssl, get_info=ldap3.ALL)

        # Try to bind with service account
        conn = ldap3.Connection(server, user=ldap_bind_dn, password=ldap_bind_password, auto_bind=True)

        if conn.bound:
            conn.unbind()
            return jsonify({
                'success': True,
                'message': f'✓ Successfully connected to LDAP server at {server_url}:{ldap_port}'
            })
        else:
            return jsonify({'success': False, 'error': 'Failed to bind to LDAP server'})

    except ImportError:
        return jsonify({'success': False, 'error': 'ldap3 library not installed. Run: pip install ldap3'})
    except Exception as e:
        return jsonify({'success': False, 'error': f'LDAP connection failed: {str(e)}'})


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
@requires_professional('Email Alerts')
def save_smtp_settings():
    """Save global SMTP settings"""
    data = request.get_json()

    try:
        set_setting('smtp_host', data.get('smtp_host', ''), 'smtp', 'SMTP server hostname')
        set_setting('smtp_port', str(data.get('smtp_port', 587)), 'smtp', 'SMTP server port')
        set_setting('smtp_username', data.get('smtp_username', ''), 'smtp', 'SMTP username')

        # Encrypt SMTP password
        if data.get('smtp_password'):
            set_setting('smtp_password', data['smtp_password'], 'smtp', 'SMTP password', is_encrypted=True)

        set_setting('smtp_from_email', data.get('smtp_from_email', ''), 'smtp', 'From email address')
        set_setting('smtp_from_name', data.get('smtp_from_name', 'SentriKat Alerts'), 'smtp', 'From name')
        set_setting('smtp_use_tls', 'true' if data.get('smtp_use_tls') else 'false', 'smtp', 'Use TLS/STARTTLS')
        set_setting('smtp_use_ssl', 'true' if data.get('smtp_use_ssl') else 'false', 'smtp', 'Use SSL/TLS')

        return jsonify({'success': True, 'message': 'SMTP settings saved successfully'})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@settings_bp.route('/smtp/test', methods=['POST'])
@admin_required
@requires_professional('Email Alerts')
def test_smtp_connection():
    """Test global SMTP connection by sending test email"""
    try:
        import smtplib
        from email.mime.text import MIMEText
        from email.mime.multipart import MIMEMultipart

        # Get current user's email to send test to
        user_id = session.get('user_id')
        test_recipient = None
        if user_id:
            user = User.query.get(user_id)
            test_recipient = user.email if user else None

        if not test_recipient:
            return jsonify({'success': False, 'error': 'No email address found for current user'})

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

        if not smtp_config['host'] or not smtp_config['from_email']:
            return jsonify({'success': False, 'error': 'SMTP not configured'})

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

        # Send email - check SSL first, then plain SMTP with optional TLS
        if smtp_config['use_ssl']:
            server = smtplib.SMTP_SSL(smtp_config['host'], smtp_config['port'])
        else:
            server = smtplib.SMTP(smtp_config['host'], smtp_config['port'])
            if smtp_config['use_tls']:
                server.starttls()

        if smtp_config['username'] and smtp_config['password']:
            server.login(smtp_config['username'], smtp_config['password'])

        server.send_message(msg)
        server.quit()

        return jsonify({
            'success': True,
            'message': f'✓ Test email sent successfully to {test_recipient}'
        })

    except Exception as e:
        return jsonify({'success': False, 'error': f'SMTP test failed: {str(e)}'})


# ============================================================================
# Sync Settings
# ============================================================================

@settings_bp.route('/sync', methods=['GET'])
@admin_required
def get_sync_settings():
    """Get sync schedule settings"""
    settings = {
        'auto_sync_enabled': get_setting('auto_sync_enabled', 'false') == 'true',
        'sync_interval': get_setting('sync_interval', 'daily'),
        'sync_time': get_setting('sync_time', '02:00'),
        'cisa_kev_url': get_setting('cisa_kev_url', 'https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json')
    }
    return jsonify(settings)

@settings_bp.route('/sync', methods=['POST'])
@admin_required
def save_sync_settings():
    """Save sync schedule settings"""
    data = request.get_json()

    try:
        set_setting('auto_sync_enabled', 'true' if data.get('auto_sync_enabled') else 'false', 'sync', 'Enable automatic sync')
        set_setting('sync_interval', data.get('sync_interval', 'daily'), 'sync', 'Sync interval')
        set_setting('sync_time', data.get('sync_time', '02:00'), 'sync', 'Preferred sync time (UTC)')
        set_setting('cisa_kev_url', data.get('cisa_kev_url', ''), 'sync', 'CISA KEV feed URL')

        # Encrypt NVD API key
        if data.get('nvd_api_key'):
            set_setting('nvd_api_key', data['nvd_api_key'], 'sync', 'NVD API key', is_encrypted=True)

        return jsonify({'success': True, 'message': 'Sync settings saved successfully'})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@settings_bp.route('/sync/status', methods=['GET'])
@admin_required
def get_sync_status():
    """Get sync status information"""
    try:
        # Get last sync
        last_sync = SyncLog.query.order_by(SyncLog.sync_date.desc()).first()

        # Get total vulnerabilities
        total_vulns = Vulnerability.query.count()

        # Calculate next sync (simplified - would need proper scheduling logic)
        auto_sync = get_setting('auto_sync_enabled', 'false') == 'true'
        next_sync = 'Not scheduled' if not auto_sync else 'Based on interval'

        return jsonify({
            'last_sync': last_sync.sync_date.strftime('%Y-%m-%d %H:%M:%S UTC') if last_sync else None,
            'next_sync': next_sync,
            'total_vulnerabilities': total_vulns,
            'auto_sync_enabled': auto_sync
        })
    except Exception as e:
        return jsonify({'error': str(e)}), 500

# ============================================================================
# General Settings
# ============================================================================

@settings_bp.route('/general', methods=['GET'])
@admin_required
def get_general_settings():
    """Get general system settings (proxy/network)"""
    settings = {
        'verify_ssl': get_setting('verify_ssl', 'true') == 'true',
        'http_proxy': get_setting('http_proxy', ''),
        'https_proxy': get_setting('https_proxy', ''),
        'no_proxy': get_setting('no_proxy', ''),
        'session_timeout': int(get_setting('session_timeout', '480'))
    }
    return jsonify(settings)

@settings_bp.route('/general', methods=['POST'])
@admin_required
def save_general_settings():
    """Save general system settings (proxy/network)"""
    data = request.get_json()

    try:
        set_setting('verify_ssl', 'true' if data.get('verify_ssl') else 'false', 'general', 'Verify SSL certificates')
        set_setting('http_proxy', data.get('http_proxy', ''), 'general', 'HTTP proxy URL')
        set_setting('https_proxy', data.get('https_proxy', ''), 'general', 'HTTPS proxy URL')
        set_setting('no_proxy', data.get('no_proxy', ''), 'general', 'No proxy bypass list')
        set_setting('session_timeout', str(data.get('session_timeout', 480)), 'general', 'Session timeout (minutes)')

        return jsonify({'success': True, 'message': 'General settings saved successfully'})
    except Exception as e:
        return jsonify({'error': str(e)}), 500


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
        return jsonify({'error': str(e)}), 500


# ============================================================================
# Branding Settings
# ============================================================================

@settings_bp.route('/branding', methods=['GET'])
@admin_required
def get_branding_settings():
    """Get branding/UI settings"""
    settings = {
        'app_name': get_setting('app_name', 'SentriKat'),
        'login_message': get_setting('login_message', ''),
        'support_email': get_setting('support_email', ''),
        'show_version': get_setting('show_version', 'true') == 'true',
        'logo_url': get_setting('logo_url', '/static/images/favicon-128x128.png')
    }
    return jsonify(settings)

@settings_bp.route('/branding', methods=['POST'])
@admin_required
def save_branding_settings():
    """Save branding/UI settings"""
    data = request.get_json()

    try:
        set_setting('app_name', data.get('app_name', 'SentriKat'), 'branding', 'Application name')
        set_setting('login_message', data.get('login_message', ''), 'branding', 'Login page message')
        set_setting('support_email', data.get('support_email', ''), 'branding', 'Support email address')
        set_setting('show_version', 'true' if data.get('show_version') else 'false', 'branding', 'Show version in footer')

        return jsonify({'success': True, 'message': 'Branding settings saved successfully'})
    except Exception as e:
        return jsonify({'error': str(e)}), 500


# ============================================================================
# Notification Settings (Webhooks)
# ============================================================================

@settings_bp.route('/notifications', methods=['GET'])
@admin_required
def get_notification_settings():
    """Get notification/webhook settings"""
    settings = {
        'slack_webhook_url': get_setting('slack_webhook_url', ''),
        'slack_enabled': get_setting('slack_enabled', 'false') == 'true',
        'teams_webhook_url': get_setting('teams_webhook_url', ''),
        'teams_enabled': get_setting('teams_enabled', 'false') == 'true',
        'critical_email_enabled': get_setting('critical_email_enabled', 'true') == 'true',
        'critical_email_time': get_setting('critical_email_time', '09:00'),
        'critical_email_max_age_days': int(get_setting('critical_email_max_age_days', '30'))
    }
    return jsonify(settings)

@settings_bp.route('/notifications', methods=['POST'])
@admin_required
def save_notification_settings():
    """Save notification/webhook settings"""
    data = request.get_json()

    try:
        set_setting('slack_enabled', 'true' if data.get('slack_enabled') else 'false', 'notifications', 'Enable Slack notifications')
        if data.get('slack_webhook_url'):
            set_setting('slack_webhook_url', data['slack_webhook_url'], 'notifications', 'Slack webhook URL', is_encrypted=True)

        set_setting('teams_enabled', 'true' if data.get('teams_enabled') else 'false', 'notifications', 'Enable Teams notifications')
        if data.get('teams_webhook_url'):
            set_setting('teams_webhook_url', data['teams_webhook_url'], 'notifications', 'Microsoft Teams webhook URL', is_encrypted=True)

        set_setting('critical_email_enabled', 'true' if data.get('critical_email_enabled') else 'false', 'notifications', 'Enable critical CVE reminder emails')
        set_setting('critical_email_time', data.get('critical_email_time', '09:00'), 'notifications', 'Critical CVE email time (UTC)')
        set_setting('critical_email_max_age_days', str(data.get('critical_email_max_age_days', 30)), 'notifications', 'Max age for CVEs in reminder (days)')

        return jsonify({'success': True, 'message': 'Notification settings saved successfully'})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@settings_bp.route('/notifications/test', methods=['POST'])
@admin_required
def test_notification():
    """Test webhook notification"""
    import requests
    data = request.get_json()
    webhook_type = data.get('type', 'slack')

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
            response = requests.post(webhook_url, json=payload, timeout=10)

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
            response = requests.post(webhook_url, json=payload, timeout=10)

        else:
            return jsonify({'success': False, 'error': f'Unknown webhook type: {webhook_type}'})

        if response.status_code in [200, 204]:
            return jsonify({'success': True, 'message': f'Test notification sent to {webhook_type.title()}'})
        else:
            return jsonify({'success': False, 'error': f'Webhook returned status {response.status_code}'})

    except Exception as e:
        return jsonify({'success': False, 'error': str(e)})


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
        'session_log_retention_days': int(get_setting('session_log_retention_days', '30'))
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

        return jsonify({'success': True, 'message': 'Retention settings saved successfully'})
    except Exception as e:
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
        # Create uploads directory if it doesn't exist
        upload_dir = os.path.join(os.path.dirname(os.path.dirname(__file__)), 'static', 'uploads')
        os.makedirs(upload_dir, exist_ok=True)

        # Generate safe filename
        ext = file.filename.rsplit('.', 1)[1].lower()
        filename = f'custom_logo.{ext}'
        filepath = os.path.join(upload_dir, filename)

        # Save file
        file.save(filepath)

        # Update branding setting with logo path
        logo_url = f'/static/uploads/{filename}'
        set_setting('logo_url', logo_url, 'branding', 'Custom logo URL')

        return jsonify({
            'success': True,
            'message': 'Logo uploaded successfully',
            'logo_url': logo_url
        })
    except Exception as e:
        logger.error(f"Logo upload failed: {e}")
        return jsonify({'error': f'Upload failed: {str(e)}'}), 500

@settings_bp.route('/branding/logo', methods=['DELETE'])
@admin_required
def delete_logo():
    """Remove custom logo and revert to default"""
    import os

    try:
        # Get current logo path
        logo_url = get_setting('logo_url', '')

        if logo_url and logo_url.startswith('/static/uploads/'):
            # Delete file
            filepath = os.path.join(os.path.dirname(os.path.dirname(__file__)), logo_url.lstrip('/'))
            if os.path.exists(filepath):
                os.remove(filepath)

        # Remove setting
        setting = SystemSettings.query.filter_by(key='logo_url').first()
        if setting:
            db.session.delete(setting)
            db.session.commit()

        return jsonify({'success': True, 'message': 'Logo removed, reverted to default'})
    except Exception as e:
        logger.error(f"Logo deletion failed: {e}")
        return jsonify({'error': str(e)}), 500


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
                'version': '1.0',
                'created_at': datetime.utcnow().isoformat(),
                'created_by': current_user.username,
                'app_name': get_setting('app_name', 'SentriKat')
            },
            'settings': {},
            'organizations': [],
            'users': [],
            'products': [],
            'service_catalog': []
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
        logger.error(f"Backup creation failed: {e}")
        return jsonify({'error': f'Backup failed: {str(e)}'}), 500


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
        logger.error(f"Restore failed: {e}")
        return jsonify({'error': f'Restore failed: {str(e)}'}), 500
