"""
SAML 2.0 API endpoints for SentriKat

Provides:
- /api/settings/saml (GET/POST) - SAML configuration (admin only)
- /api/saml/metadata - SP metadata for IdP configuration
- /api/saml/login - Initiate SAML login (redirect to IdP)
- /api/saml/acs - Assertion Consumer Service (IdP posts response here)
- /api/saml/sls - Single Logout Service (optional)
"""
import logging
from flask import Blueprint, request, jsonify, redirect, url_for, session
from app.auth import admin_required, get_current_user, login_user_session
from app.settings_api import get_setting, set_setting
from app.licensing import requires_professional
from app import csrf

logger = logging.getLogger(__name__)

saml_bp = Blueprint('saml', __name__)

# Exempt SAML API routes from CSRF (they use JSON and are protected by SameSite cookies)
csrf.exempt(saml_bp)


# ============================================================================
# SAML Configuration API (Admin only)
# ============================================================================

@saml_bp.route('/api/settings/saml', methods=['GET'])
@admin_required
@requires_professional('SAML SSO')
def get_saml_settings():
    """Get SAML SSO configuration"""
    from app.saml_manager import is_saml_available

    settings = {
        'saml_available': is_saml_available(),
        'saml_enabled': get_setting('saml_enabled', 'false') == 'true',
        'saml_idp_metadata': get_setting('saml_idp_metadata', ''),
        'saml_sp_entity_id': get_setting('saml_sp_entity_id', ''),
        'saml_sp_acs_url': get_setting('saml_sp_acs_url', ''),
        'saml_sp_sls_url': get_setting('saml_sp_sls_url', ''),
        'saml_default_org_id': get_setting('saml_default_org_id', ''),
        'saml_user_mapping': get_setting('saml_user_mapping', '{}'),
        'saml_auto_provision': get_setting('saml_auto_provision', 'true') == 'true',
        'saml_update_user_info': get_setting('saml_update_user_info', 'true') == 'true'
    }

    if not is_saml_available():
        settings['install_hint'] = 'SAML requires the python3-saml library. Install with: pip install python3-saml'

    return jsonify(settings)


@saml_bp.route('/api/settings/saml', methods=['POST'])
@admin_required
@requires_professional('SAML SSO')
def save_saml_settings():
    """Save SAML SSO configuration"""
    from app.saml_manager import is_saml_available

    if not is_saml_available():
        return jsonify({
            'success': False,
            'error': 'SAML library not installed. Run: pip install python3-saml'
        }), 400

    data = request.get_json()

    try:
        set_setting('saml_enabled', 'true' if data.get('saml_enabled') else 'false', 'saml', 'Enable SAML SSO')
        set_setting('saml_idp_metadata', data.get('saml_idp_metadata', ''), 'saml', 'IdP Metadata (XML or URL)')
        set_setting('saml_sp_entity_id', data.get('saml_sp_entity_id', ''), 'saml', 'SP Entity ID')
        set_setting('saml_sp_acs_url', data.get('saml_sp_acs_url', ''), 'saml', 'Assertion Consumer Service URL')
        set_setting('saml_sp_sls_url', data.get('saml_sp_sls_url', ''), 'saml', 'Single Logout Service URL')
        set_setting('saml_default_org_id', str(data.get('saml_default_org_id', '')), 'saml', 'Default organization for new users')
        set_setting('saml_user_mapping', data.get('saml_user_mapping', '{}'), 'saml', 'SAML attribute mapping')
        set_setting('saml_auto_provision', 'true' if data.get('saml_auto_provision', True) else 'false', 'saml', 'Auto-provision new users')
        set_setting('saml_update_user_info', 'true' if data.get('saml_update_user_info', True) else 'false', 'saml', 'Update user info on login')

        return jsonify({'success': True, 'message': 'SAML settings saved successfully'})
    except Exception as e:
        logger.exception("Failed to save SAML settings")
        return jsonify({'success': False, 'error': str(e)}), 500


@saml_bp.route('/api/settings/saml/test', methods=['POST'])
@admin_required
@requires_professional('SAML SSO')
def test_saml_config():
    """Test SAML configuration by validating IdP metadata"""
    from app.saml_manager import is_saml_available, get_saml_settings

    if not is_saml_available():
        return jsonify({
            'success': False,
            'error': 'SAML library not installed'
        }), 400

    try:
        settings = get_saml_settings()
        if not settings:
            return jsonify({
                'success': False,
                'error': 'SAML not configured or IdP metadata invalid'
            }), 400

        # Check required fields
        idp = settings.get('idp', {})
        if not idp.get('entityId'):
            return jsonify({
                'success': False,
                'error': 'IdP Entity ID not found in metadata'
            }), 400

        if not idp.get('singleSignOnService', {}).get('url'):
            return jsonify({
                'success': False,
                'error': 'IdP SSO URL not found in metadata'
            }), 400

        return jsonify({
            'success': True,
            'message': 'SAML configuration is valid',
            'idp_entity_id': idp.get('entityId'),
            'idp_sso_url': idp.get('singleSignOnService', {}).get('url')
        })
    except Exception as e:
        logger.exception("SAML config test failed")
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500


# ============================================================================
# SAML SSO Endpoints
# ============================================================================

@saml_bp.route('/api/saml/metadata', methods=['GET'])
def get_sp_metadata():
    """
    Get SP metadata XML for configuring the IdP.
    This endpoint is public so IdP admins can access it.
    """
    from app.saml_manager import get_saml_metadata, is_saml_available

    if not is_saml_available():
        return jsonify({'error': 'SAML not available'}), 503

    metadata = get_saml_metadata()
    if not metadata:
        return jsonify({'error': 'SAML not configured'}), 404

    return metadata, 200, {'Content-Type': 'application/xml'}


@saml_bp.route('/saml/login', methods=['GET'])
def saml_login():
    """
    Initiate SAML login flow.
    Redirects user to IdP for authentication.
    """
    from app.saml_manager import generate_login_url, is_saml_available

    if not is_saml_available():
        return redirect(url_for('main.login', error='saml_unavailable'))

    if get_setting('saml_enabled', 'false') != 'true':
        return redirect(url_for('main.login', error='saml_disabled'))

    # Get return URL
    return_to = request.args.get('next') or url_for('main.dashboard')

    # Generate login URL
    login_url = generate_login_url(request, return_to)
    if not login_url:
        return redirect(url_for('main.login', error='saml_config'))

    return redirect(login_url)


@saml_bp.route('/saml/acs', methods=['POST'])
def saml_acs():
    """
    Assertion Consumer Service - IdP posts SAML response here.
    Validates response and creates user session.
    """
    from app.saml_manager import process_saml_response, get_or_create_saml_user, is_saml_available
    from app.audit import log_user_login

    if not is_saml_available():
        return redirect(url_for('main.login', error='saml_unavailable'))

    if get_setting('saml_enabled', 'false') != 'true':
        return redirect(url_for('main.login', error='saml_disabled'))

    # Process SAML response
    success, user_data, error = process_saml_response(request)

    if not success:
        logger.error(f"SAML authentication failed: {error}")
        return redirect(url_for('main.login', error='saml_auth_failed'))

    # Get or create user
    auto_provision = get_setting('saml_auto_provision', 'true') == 'true'

    if not auto_provision:
        # Check if user exists
        from app.models import User
        user = User.query.filter_by(email=user_data.get('email')).first()
        if not user:
            logger.warning(f"SAML user not found and auto-provision disabled: {user_data.get('email')}")
            return redirect(url_for('main.login', error='saml_user_not_found'))
    else:
        user, created = get_or_create_saml_user(user_data)
        if not user:
            return redirect(url_for('main.login', error='saml_user_create_failed'))

        if created:
            logger.info(f"Created new SAML user: {user.username}")

    # Create session
    login_user_session(user)

    # Log the login
    try:
        log_user_login(user, 'saml')
    except:
        pass

    # Redirect to RelayState (return URL) or dashboard
    relay_state = request.form.get('RelayState')
    if relay_state and relay_state.startswith('/'):
        return redirect(relay_state)

    return redirect(url_for('main.dashboard'))


@saml_bp.route('/saml/sls', methods=['GET', 'POST'])
def saml_sls():
    """
    Single Logout Service - Handle IdP-initiated logout.
    """
    from app.saml_manager import init_saml_auth, is_saml_available
    from app.auth import logout_user

    if not is_saml_available():
        return redirect(url_for('main.login'))

    auth = init_saml_auth(request)
    if not auth:
        logout_user()
        return redirect(url_for('main.login'))

    # Process logout request/response
    def redirect_callback():
        return redirect(url_for('main.login'))

    try:
        url = auth.process_slo(delete_session_cb=redirect_callback)
        errors = auth.get_errors()
        if errors:
            logger.error(f"SAML SLS errors: {errors}")

        logout_user()

        if url:
            return redirect(url)
    except Exception as e:
        logger.exception("SAML SLS failed")
        logout_user()

    return redirect(url_for('main.login'))


# ============================================================================
# SAML Status Check
# ============================================================================

@saml_bp.route('/api/saml/status', methods=['GET'])
def saml_status():
    """
    Check SAML availability for login page.
    Public endpoint - returns minimal info.
    """
    from app.saml_manager import is_saml_available

    enabled = get_setting('saml_enabled', 'false') == 'true'
    available = is_saml_available()

    return jsonify({
        'enabled': enabled and available,
        'login_url': url_for('saml.saml_login') if enabled and available else None
    })
