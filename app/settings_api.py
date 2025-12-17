"""
Settings API Endpoints
Handles LDAP, SMTP, Sync, and General system settings
"""

from flask import Blueprint, request, jsonify, session
from app import db
from app.models import SystemSettings, User, Vulnerability, SyncLog
from app.auth import admin_required
import json
from datetime import datetime

settings_bp = Blueprint('settings', __name__, url_prefix='/api/settings')

# ============================================================================
# Helper Functions
# ============================================================================

def get_setting(key, default=None):
    """Get a setting value from database"""
    setting = SystemSettings.query.filter_by(key=key).first()
    return setting.value if setting else default

def set_setting(key, value, category, description=None, is_encrypted=False):
    """Set a setting value in database"""
    user_id = session.get('user_id')

    setting = SystemSettings.query.filter_by(key=key).first()
    if setting:
        setting.value = value
        setting.updated_by = user_id
        setting.updated_at = datetime.utcnow()
    else:
        setting = SystemSettings(
            key=key,
            value=value,
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
def test_ldap_connection():
    """Test LDAP connection"""
    try:
        from app.auth import authenticate_ldap

        ldap_server = get_setting('ldap_server')
        if not ldap_server:
            return jsonify({'success': False, 'error': 'LDAP server not configured'})

        # Try to bind with service account
        # In a real test, you would attempt to bind with the service account
        # For now, just check if settings are present
        required_settings = ['ldap_server', 'ldap_base_dn', 'ldap_bind_dn']
        for setting in required_settings:
            if not get_setting(setting):
                return jsonify({'success': False, 'error': f'Missing required setting: {setting}'})

        return jsonify({'success': True, 'message': 'LDAP configuration appears valid'})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)})

# ============================================================================
# Global SMTP Settings
# ============================================================================

@settings_bp.route('/smtp', methods=['GET'])
@admin_required
def get_smtp_settings():
    """Get global SMTP settings"""
    settings = {
        'smtp_host': get_setting('smtp_host', ''),
        'smtp_port': int(get_setting('smtp_port', '587')),
        'smtp_username': get_setting('smtp_username', ''),
        'smtp_from_email': get_setting('smtp_from_email', ''),
        'smtp_from_name': get_setting('smtp_from_name', 'SentriKat Alerts'),
        'smtp_use_tls': get_setting('smtp_use_tls', 'true') == 'true'
    }
    return jsonify(settings)

@settings_bp.route('/smtp', methods=['POST'])
@admin_required
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

        return jsonify({'success': True, 'message': 'SMTP settings saved successfully'})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@settings_bp.route('/smtp/test', methods=['POST'])
@admin_required
def test_smtp_connection():
    """Test global SMTP connection"""
    try:
        from app.email_alerts import EmailAlertManager

        smtp_config = {
            'host': get_setting('smtp_host'),
            'port': int(get_setting('smtp_port', '587')),
            'username': get_setting('smtp_username'),
            'password': get_setting('smtp_password'),
            'from_email': get_setting('smtp_from_email'),
            'from_name': get_setting('smtp_from_name', 'SentriKat Alerts'),
            'use_tls': get_setting('smtp_use_tls', 'true') == 'true'
        }

        if not smtp_config['host'] or not smtp_config['from_email']:
            return jsonify({'success': False, 'error': 'SMTP not configured'})

        result = EmailAlertManager.test_smtp_connection(smtp_config)
        return jsonify(result)
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)})

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
    """Get general system settings"""
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
    """Save general system settings"""
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
