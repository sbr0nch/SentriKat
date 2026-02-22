"""
Authentication system with local and LDAP support
Authentication is ENABLED by default for security
"""

from functools import wraps
from flask import Blueprint, render_template, request, jsonify, redirect, url_for, session, flash
from app import db, csrf, limiter
from app.models import User, Organization
from sqlalchemy import func
from sqlalchemy.exc import SQLAlchemyError
from datetime import datetime
import os
import logging

logger = logging.getLogger(__name__)

auth_bp = Blueprint('auth', __name__)

# Exempt API routes from CSRF (they use JSON and are protected by SameSite cookies)
csrf.exempt(auth_bp)

# Authentication is ALWAYS enabled by default (security requirement)
# Only disable for testing with DISABLE_AUTH=true (NOT recommended)
# Production guard: DISABLE_AUTH is ignored when FLASK_ENV=production or SENTRIKAT_ENV=production
_flask_env = os.environ.get('FLASK_ENV', '').lower()
_sentrikat_env = os.environ.get('SENTRIKAT_ENV', '').lower()
_is_production = _flask_env == 'production' or _sentrikat_env == 'production'
if _is_production and os.environ.get('DISABLE_AUTH', 'false').lower() == 'true':
    import logging as _logging
    _logging.getLogger(__name__).critical(
        "SECURITY: DISABLE_AUTH=true is IGNORED in production environment. Authentication remains enabled."
    )
AUTH_ENABLED = True if _is_production else os.environ.get('DISABLE_AUTH', 'false').lower() != 'true'


def _safe_get_user(user_id):
    """
    Safely get a user from the database, handling session state issues.

    Returns the User object or None if not found or error occurs.
    """
    if user_id is None:
        return None

    try:
        # Use a fresh query instead of db.session.get() to avoid session state issues
        user = User.query.filter_by(id=user_id).first()
        return user
    except SQLAlchemyError as e:
        # If there's a database error, try to rollback and retry
        logger.warning(f"Database error getting user {user_id}: {e}")
        try:
            db.session.rollback()
            # Retry with fresh query
            user = User.query.filter_by(id=user_id).first()
            return user
        except Exception as retry_error:
            logger.error(f"Failed to recover user query: {retry_error}")
            db.session.rollback()
            return None
    except Exception as e:
        logger.error(f"Unexpected error getting user {user_id}: {e}")
        return None

def login_required(f):
    """Decorator to require login for routes"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        # If auth is disabled, allow all requests
        if not AUTH_ENABLED:
            return f(*args, **kwargs)

        # Check if user is logged in
        if 'user_id' not in session:
            if request.is_json or request.path.startswith('/api/'):
                return jsonify({'error': 'Authentication required'}), 401
            return redirect(url_for('auth.login', next=request.url))

        # Verify user still exists and is active (use safe query to handle session issues)
        user = _safe_get_user(session['user_id'])
        if not user or not user.is_active:
            session.clear()
            if request.is_json or request.path.startswith('/api/'):
                return jsonify({'error': 'Account disabled'}), 401
            return redirect(url_for('auth.login'))

        # Check if user's organization is still active (skip for super_admins)
        if user.role != 'super_admin' and not user.is_admin:
            if user.organization and not user.organization.active:
                session.clear()
                if request.is_json or request.path.startswith('/api/'):
                    return jsonify({'error': 'Organization disabled. Contact administrator.'}), 401
                flash('Your organization has been disabled. Contact administrator.', 'danger')
                return redirect(url_for('auth.login'))

        return f(*args, **kwargs)
    return decorated_function

def admin_required(f):
    """Decorator to require super admin privileges.

    Allows access for users with:
    - role: super_admin
    - is_admin=True (legacy flag)
    """
    @wraps(f)
    def decorated_function(*args, **kwargs):
        # If auth is disabled, allow all requests
        if not AUTH_ENABLED:
            return f(*args, **kwargs)

        # Check if user is logged in
        if 'user_id' not in session:
            if request.is_json or request.path.startswith('/api/'):
                return jsonify({'error': 'Authentication required'}), 401
            return redirect(url_for('auth.login', next=request.url))

        # Check if user is super_admin or has legacy is_admin flag
        user = _safe_get_user(session['user_id'])
        if not user:
            if request.is_json or request.path.startswith('/api/'):
                return jsonify({'error': 'User not found'}), 401
            return redirect(url_for('auth.login'))

        # Allow super_admin role or legacy is_admin flag
        has_permission = user.role == 'super_admin' or user.is_admin == True

        if not has_permission:
            if request.is_json or request.path.startswith('/api/'):
                return jsonify({'error': 'Super admin privileges required'}), 403
            return redirect(url_for('main.index'))

        return f(*args, **kwargs)
    return decorated_function

def manager_required(f):
    """Decorator to require manager, org admin, or super admin privileges.

    Allows access for users with:
    - role: super_admin, org_admin, or manager
    - is_admin=True (legacy)
    - can_manage_products=True (explicit permission)
    """
    @wraps(f)
    def decorated_function(*args, **kwargs):
        import logging
        logger = logging.getLogger('security')

        # If auth is disabled, allow all requests
        if not AUTH_ENABLED:
            return f(*args, **kwargs)

        # Check if user is logged in
        if 'user_id' not in session:
            logger.warning(f"Unauthorized access attempt to {request.path} - No session")
            if request.is_json or request.path.startswith('/api/'):
                return jsonify({'error': 'Authentication required'}), 401
            return redirect(url_for('auth.login', next=request.url))

        user = _safe_get_user(session['user_id'])
        if not user:
            logger.error(f"User {session['user_id']} not found in database")
            if request.is_json or request.path.startswith('/api/'):
                return jsonify({'error': 'User not found'}), 401
            return redirect(url_for('auth.login'))

        # Allow manager, org_admin, super_admin roles, is_admin flag, or can_manage_products
        has_permission = (
            user.role in ['manager', 'org_admin', 'super_admin'] or
            user.is_admin == True or
            user.can_manage_products == True
        )

        if not has_permission:
            logger.warning(
                f"Access denied to {request.path} for user {user.username} "
                f"(role={user.role}, is_admin={user.is_admin}) from {request.remote_addr}"
            )
            if request.is_json or request.path.startswith('/api/'):
                return jsonify({'error': 'Insufficient privileges'}), 403
            return redirect(url_for('main.index'))

        return f(*args, **kwargs)
    return decorated_function

def org_admin_required(f):
    """Decorator to require org admin or super admin privileges"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        import logging
        logger = logging.getLogger('security')

        # If auth is disabled, allow all requests
        if not AUTH_ENABLED:
            return f(*args, **kwargs)

        # Check if user is logged in
        if 'user_id' not in session:
            logger.warning(f"Unauthorized access attempt to {request.path} - No session")
            if request.is_json or request.path.startswith('/api/'):
                return jsonify({'error': 'Authentication required'}), 401
            return redirect(url_for('auth.login', next=request.url))

        # Check if user is org_admin, super_admin, or legacy is_admin
        user = _safe_get_user(session['user_id'])
        if not user:
            logger.error(f"User {session['user_id']} not found in database")
            if request.is_json or request.path.startswith('/api/'):
                return jsonify({'error': 'User not found'}), 401
            return redirect(url_for('auth.login'))

        # Allow org_admin, super_admin roles, or legacy is_admin flag
        has_permission = (user.role in ['org_admin', 'super_admin'] or
                         user.is_admin == True)

        if not has_permission:
            logger.warning(
                f"Access denied to {request.path} for user {user.username} "
                f"(role={user.role}, is_admin={user.is_admin}) from {request.remote_addr}"
            )
            if request.is_json or request.path.startswith('/api/'):
                return jsonify({'error': 'Organization admin privileges required'}), 403
            return redirect(url_for('main.index'))

        return f(*args, **kwargs)
    return decorated_function

def get_current_user():
    """Get current logged-in user"""
    if not AUTH_ENABLED:
        # If auth is disabled, return a fake admin user
        return None

    if 'user_id' in session:
        return _safe_get_user(session['user_id'])
    return None


def login_user_session(user):
    """
    Set up the session for a successfully authenticated user.
    Used by both local login and SAML SSO.

    Args:
        user: The User object to log in
    """
    from app.models import Organization

    # Session fixation protection: clear old session data
    session.clear()

    # Set session as permanent
    session.permanent = True
    session['user_id'] = user.id
    session['username'] = user.username
    session['is_admin'] = user.is_admin

    # Set organization
    if user.organization_id:
        session['organization_id'] = user.organization_id
    else:
        # Default to first organization
        default_org = Organization.query.filter_by(name='default').first()
        if default_org:
            session['organization_id'] = default_org.id

    # Update last login
    user.last_login = datetime.utcnow()
    db.session.commit()

    return True

@auth_bp.route('/login', methods=['GET'])
def login():
    """Display login page"""
    if not AUTH_ENABLED:
        return redirect(url_for('main.index'))

    # Check if setup is needed (no users exist)
    if User.query.count() == 0:
        return redirect(url_for('auth.setup'))

    if 'user_id' in session:
        return redirect(url_for('main.index'))

    return render_template('login.html')


@auth_bp.route('/api/auth/diag', methods=['GET'])
def auth_diag():
    """
    Temporary diagnostic endpoint to debug login issues.
    Returns non-sensitive auth state information.
    Remove this endpoint after debugging is complete.
    """
    from app.settings_api import get_setting

    diag = {
        'auth_enabled': AUTH_ENABLED,
        'total_users': User.query.count(),
        'active_users': User.query.filter_by(is_active=True).count(),
        'session_has_user_id': 'user_id' in session,
    }

    # Check all users and their auth state (no passwords/secrets)
    users = User.query.all()
    diag['users'] = []
    for u in users:
        diag['users'].append({
            'id': u.id,
            'username': u.username,
            'auth_type': u.auth_type,
            'is_active': u.is_active,
            'role': u.role,
            'is_admin': u.is_admin,
            'is_locked': u.is_locked() if hasattr(u, 'is_locked') else 'N/A',
            'failed_login_attempts': getattr(u, 'failed_login_attempts', 0),
            'locked_until': str(u.locked_until) if getattr(u, 'locked_until', None) else None,
            'has_password_hash': bool(getattr(u, 'password_hash', None)),
        })

    # SAML config state
    diag['saml'] = {
        'enabled': get_setting('saml_enabled', 'false'),
        'sp_entity_id': get_setting('saml_sp_entity_id', ''),
        'sp_acs_url': get_setting('saml_sp_acs_url', ''),
        'has_idp_metadata': bool(get_setting('saml_idp_metadata', '')),
        'auto_provision': get_setting('saml_auto_provision', 'true'),
    }

    # Check SAML library
    try:
        from onelogin.saml2.auth import OneLogin_Saml2_Auth
        diag['saml']['library_installed'] = True
    except ImportError:
        diag['saml']['library_installed'] = False

    # Request info (what Flask sees after ProxyFix)
    diag['request_info'] = {
        'host': request.host,
        'scheme': request.scheme,
        'url': request.url,
        'remote_addr': request.remote_addr,
    }

    # SENTRIKAT_URL env
    diag['sentrikat_url_env'] = os.environ.get('SENTRIKAT_URL', '(not set)')

    return jsonify(diag)


@auth_bp.route('/setup', methods=['GET'])
def setup():
    """First-time setup wizard"""
    # Only allow if no users exist
    if User.query.count() > 0:
        return redirect(url_for('auth.login'))

    return render_template('setup.html')

@auth_bp.route('/api/auth/setup', methods=['POST'])
def api_setup():
    """Handle first-time setup"""
    # Only allow if no users exist
    if User.query.count() > 0:
        return jsonify({'error': 'Setup already completed'}), 400

    data = request.get_json()

    # Validate required fields
    required = ['username', 'password', 'email', 'organization_name']
    for field in required:
        if not data.get(field):
            return jsonify({'error': f'{field} is required'}), 400

    try:
        # Create default organization
        org = Organization(
            name=data['organization_name'].lower().replace(' ', '_'),
            display_name=data['organization_name'],
            description='Default organization',
            active=True
        )
        db.session.add(org)
        db.session.flush()  # Get org.id

        # Create super admin user
        user = User(
            username=data['username'],
            email=data['email'],
            full_name=data.get('full_name', data['username']),
            role='super_admin',
            is_admin=True,
            is_active=True,
            auth_type='local',
            organization_id=org.id,
            can_view_all_orgs=True
        )
        user.set_password(data['password'])
        db.session.add(user)

        # Save proxy settings if provided
        if data.get('proxy_enabled') and data.get('proxy_server'):
            from app.models import SystemSettings

            proxy_settings = [
                ('proxy_enabled', 'true'),
                ('proxy_server', data['proxy_server']),
                ('proxy_port', str(data.get('proxy_port', '8080'))),
                ('proxy_username', data.get('proxy_username', '')),
                ('proxy_password', data.get('proxy_password', ''))
            ]

            for key, value in proxy_settings:
                setting = SystemSettings(key=key, value=value)
                db.session.add(setting)

        db.session.commit()

        return jsonify({
            'success': True,
            'message': 'Setup completed successfully',
            'redirect': url_for('auth.login')
        })

    except Exception as e:
        db.session.rollback()
        return jsonify({'error': f'Setup failed: {str(e)}'}), 500


@auth_bp.route('/api/auth/login', methods=['POST'])
@limiter.limit("5 per minute")  # Prevent brute force attacks
def api_login():
    """Handle login via API"""
    import logging
    logger = logging.getLogger('security')

    if not AUTH_ENABLED:
        return jsonify({'error': 'Authentication is disabled'}), 400

    data = request.get_json()
    username = data.get('username')
    password = data.get('password')

    logger.info(f"Login attempt for username: {username} from {request.remote_addr}")

    if not username or not password:
        logger.warning(f"Login failed: missing username or password from {request.remote_addr}")
        return jsonify({'error': 'Username and password required'}), 400

    # Find user - check for duplicates
    matching_users = User.query.filter_by(username=username).all()
    if len(matching_users) > 1:
        logger.warning(f"DUPLICATE USERS FOUND for username '{username}': {[(u.id, u.is_active, u.auth_type) for u in matching_users]}")

    user = User.query.filter_by(username=username, is_active=True).first()

    if not user:
        # Also check for inactive user to provide better error
        inactive_user = User.query.filter_by(username=username, is_active=False).first()
        if inactive_user:
            logger.warning(f"Login failed: user {username} is inactive/disabled")
            return jsonify({'error': 'Account is disabled. Contact administrator.'}), 401
        logger.warning(f"Login failed: user {username} not found")
        return jsonify({'error': 'Invalid username or password'}), 401

    logger.info(f"User found: {user.username} (id={user.id}, auth_type={user.auth_type}, role={user.role})")

    # Check if account is locked (only for local users)
    if user.auth_type == 'local' and user.is_locked():
        remaining = user.get_lockout_remaining_minutes()
        logger.warning(f"Login blocked: user {username} is locked for {remaining} more minutes")
        return jsonify({
            'error': f'Account is temporarily locked. Try again in {remaining} minutes.'
        }), 401

    # Check if user's organization is active (skip for super_admins)
    if user.role != 'super_admin' and not user.is_admin:
        if user.organization and not user.organization.active:
            logger.warning(f"Login blocked: user {username}'s organization '{user.organization.name}' is disabled")
            return jsonify({'error': 'Your organization has been disabled. Contact administrator.'}), 401

    # Check authentication type
    if user.auth_type == 'local':
        # Local authentication
        if not user.check_password(password):
            # Record failed attempt and potentially lock
            user.record_failed_login()
            db.session.commit()

            # Check if now locked
            if user.is_locked():
                remaining = user.get_lockout_remaining_minutes()
                logger.warning(f"User {username} locked after {user.failed_login_attempts} failed attempts")
                return jsonify({
                    'error': f'Account locked due to too many failed attempts. Try again in {remaining} minutes.'
                }), 401

            logger.warning(f"Login failed for {username}: invalid password (attempt {user.failed_login_attempts})")
            return jsonify({'error': 'Invalid username or password'}), 401

    elif user.auth_type == 'ldap':
        # LDAP authentication - lockout handled by AD, not locally
        try:
            auth_result = authenticate_ldap(user, password)
            if auth_result is not True:
                # auth_result contains error details if it's a dict
                if isinstance(auth_result, dict):
                    return jsonify({
                        'error': auth_result.get('detail', 'Invalid credentials')
                    }), 401
                return jsonify({'error': 'Invalid credentials'}), 401
        except Exception as e:
            logger.exception(f"LDAP authentication error for {username}")
            return jsonify({'error': 'Authentication service unavailable'}), 500

    elif user.auth_type == 'saml':
        logger.info(f"Login attempt for SAML user {username} via password form - directing to SSO")
        return jsonify({'error': 'This account uses SSO authentication. Please use the "Sign in with SSO" button.'}), 401

    else:
        logger.error(f"Login failed: unknown auth_type '{user.auth_type}' for user {username}")
        return jsonify({'error': 'Invalid authentication type. Contact administrator.'}), 401

    # Check if 2FA is required BEFORE resetting failed attempts.
    # Failed attempt counters should only be reset after FULL authentication.
    if user.totp_enabled:
        totp_code = data.get('totp_code')
        if not totp_code:
            # 2FA required but not provided - return partial auth.
            # Do NOT reset failed attempts yet (2FA not completed).
            # Do NOT leak user_id - use a temporary token instead.
            import secrets
            totp_session_token = secrets.token_urlsafe(32)
            session['_2fa_pending_user'] = user.id
            session['_2fa_pending_token'] = totp_session_token
            logger.info(f"2FA required for {username}")
            return jsonify({
                'success': False,
                'requires_2fa': True,
                'totp_token': totp_session_token,
                'message': 'Two-factor authentication required'
            })

        # Verify TOTP code
        if not user.verify_totp(totp_code):
            logger.warning(f"Invalid 2FA code for {username}")
            return jsonify({'error': 'Invalid two-factor authentication code'}), 401

        logger.info(f"2FA verified for {username}")

    # Reset failed login attempts on successful FULL authentication (password + 2FA)
    if user.auth_type == 'local' and (user.failed_login_attempts or 0) > 0:
        user.reset_failed_login_attempts()
        logger.info(f"Reset failed login attempts for {username}")

    # Check if user must set up 2FA (admin required it OR global setting)
    must_setup_2fa = False
    if user.auth_type == 'local' and not user.totp_enabled:
        if getattr(user, 'totp_required', False):
            must_setup_2fa = True
            logger.info(f"2FA setup required for {username} (admin mandated)")
        else:
            # Check global 2FA enforcement setting
            try:
                from app.settings_api import get_setting
                global_2fa = get_setting('require_2fa', 'false') == 'true'
                if global_2fa:
                    must_setup_2fa = True
                    logger.info(f"2FA setup required for {username} (global policy)")
            except Exception:
                pass

    # Check for password expiration (local users only)
    password_expired = False
    if user.auth_type == 'local' and user.is_password_expired():
        password_expired = True
        logger.info(f"Password expired for {username}")

    # Update last login
    logger.info(f"Authentication successful for {username}, updating last login")
    user.last_login = datetime.utcnow()
    user.last_login_ip = request.remote_addr
    db.session.commit()
    logger.info(f"Last login updated for {username}")

    # Session fixation protection: clear old session data before setting new
    # This prevents session fixation attacks where attacker pre-creates a session
    session.clear()

    # Set session as permanent (uses PERMANENT_SESSION_LIFETIME from config)
    session.permanent = True
    session['user_id'] = user.id
    session['username'] = user.username
    session['is_admin'] = user.is_admin

    # Set flag for password change requirement
    if password_expired:
        session['must_change_password'] = True

    # Set flag for 2FA setup requirement
    if must_setup_2fa:
        session['must_setup_2fa'] = True

    # Set organization
    if user.organization_id:
        session['organization_id'] = user.organization_id
    else:
        # Default to first organization
        default_org = Organization.query.filter_by(name='default').first()
        if default_org:
            session['organization_id'] = default_org.id

    return jsonify({
        'success': True,
        'password_expired': password_expired,
        'must_setup_2fa': must_setup_2fa,
        'user': user.to_dict(),
        'redirect': url_for('main.index')
    })

@auth_bp.route('/api/auth/logout', methods=['POST'])
def api_logout():
    """Handle logout via API"""
    session.clear()
    return jsonify({'success': True, 'redirect': url_for('auth.login')})

@auth_bp.route('/logout')
def logout():
    """Logout route"""
    session.clear()
    return redirect(url_for('auth.login'))

@auth_bp.route('/api/auth/status', methods=['GET'])
def auth_status():
    """Check authentication status"""
    return jsonify({
        'enabled': AUTH_ENABLED,
        'authenticated': 'user_id' in session,
        'user': get_current_user().to_dict() if get_current_user() else None
    })


# ============================================================================
# PASSWORD CHANGE
# ============================================================================

@auth_bp.route('/api/auth/change-password', methods=['POST'])
@login_required
def change_password():
    """Change user password (for expired passwords or voluntary change)"""
    import logging
    logger = logging.getLogger('security')

    current_user = get_current_user()
    if not current_user:
        return jsonify({'error': 'Not authenticated'}), 401

    if current_user.auth_type != 'local':
        return jsonify({'error': 'Password change not available for LDAP users'}), 400

    data = request.get_json()
    current_password = data.get('current_password')
    new_password = data.get('new_password')

    if not current_password or not new_password:
        return jsonify({'error': 'Current and new passwords are required'}), 400

    # Verify current password
    if not current_user.check_password(current_password):
        logger.warning(f"Password change failed for {current_user.username}: incorrect current password")
        return jsonify({'error': 'Current password is incorrect'}), 401

    # Validate new password against policy
    is_valid, error_msg = User.validate_password_policy(new_password)
    if not is_valid:
        return jsonify({'error': error_msg}), 400

    # Update password
    current_user.update_password(new_password)
    session.pop('must_change_password', None)
    db.session.commit()

    logger.info(f"Password changed successfully for {current_user.username}")
    return jsonify({'success': True, 'message': 'Password changed successfully'})

# ============================================================================
# TWO-FACTOR AUTHENTICATION
# ============================================================================

@auth_bp.route('/api/auth/2fa/setup', methods=['POST'])
@login_required
def setup_2fa():
    """Generate 2FA secret and return QR code data"""
    current_user = get_current_user()
    if not current_user:
        return jsonify({'error': 'Not authenticated'}), 401

    if current_user.totp_enabled:
        return jsonify({'error': '2FA is already enabled. Disable it first to set up again.'}), 400

    # Generate new TOTP secret
    secret = current_user.setup_totp()
    db.session.commit()

    # Get TOTP URI for QR code
    from app.models import SystemSettings
    app_name_setting = SystemSettings.query.filter_by(key='app_name').first()
    app_name = app_name_setting.value if app_name_setting else 'SentriKat'

    totp_uri = current_user.get_totp_uri(app_name)

    return jsonify({
        'success': True,
        'secret': secret,
        'totp_uri': totp_uri,
        'message': 'Scan the QR code with your authenticator app, then verify with a code'
    })

@auth_bp.route('/api/auth/2fa/qrcode', methods=['GET'])
@login_required
def get_2fa_qrcode():
    """Generate QR code image for 2FA setup"""
    import qrcode
    import io
    from flask import Response

    current_user = get_current_user()
    if not current_user:
        return jsonify({'error': 'Not authenticated'}), 401

    if not current_user.totp_secret:
        return jsonify({'error': 'Run 2FA setup first'}), 400

    # Get TOTP URI
    from app.models import SystemSettings
    app_name_setting = SystemSettings.query.filter_by(key='app_name').first()
    app_name = app_name_setting.value if app_name_setting else 'SentriKat'
    totp_uri = current_user.get_totp_uri(app_name)

    # Generate QR code
    qr = qrcode.QRCode(version=1, box_size=6, border=2)
    qr.add_data(totp_uri)
    qr.make(fit=True)
    img = qr.make_image(fill_color="black", back_color="white")

    # Convert to bytes
    img_io = io.BytesIO()
    img.save(img_io, 'PNG')
    img_io.seek(0)

    return Response(img_io.getvalue(), mimetype='image/png')

@auth_bp.route('/api/auth/2fa/verify', methods=['POST'])
@login_required
def verify_2fa():
    """Verify 2FA code and enable 2FA"""
    import logging
    logger = logging.getLogger('security')

    current_user = get_current_user()
    if not current_user:
        return jsonify({'error': 'Not authenticated'}), 401

    if not current_user.totp_secret:
        return jsonify({'error': 'Run 2FA setup first'}), 400

    data = request.get_json()
    code = data.get('code')

    if not code:
        return jsonify({'error': 'Verification code is required'}), 400

    if current_user.verify_totp(code):
        current_user.enable_totp()
        db.session.commit()
        logger.info(f"2FA enabled for {current_user.username}")
        return jsonify({'success': True, 'message': 'Two-factor authentication enabled successfully'})
    else:
        return jsonify({'error': 'Invalid verification code. Please try again.'}), 400

@auth_bp.route('/api/auth/2fa/disable', methods=['POST'])
@login_required
def disable_2fa():
    """Disable 2FA (requires password verification)"""
    import logging
    logger = logging.getLogger('security')

    current_user = get_current_user()
    if not current_user:
        return jsonify({'error': 'Not authenticated'}), 401

    if not current_user.totp_enabled:
        return jsonify({'error': '2FA is not enabled'}), 400

    data = request.get_json()
    password = data.get('password')

    if not password:
        return jsonify({'error': 'Password is required to disable 2FA'}), 400

    # Verify password based on auth type
    if current_user.auth_type == 'ldap':
        # For LDAP users, verify against LDAP server
        if not authenticate_ldap(current_user, password):
            logger.warning(f"2FA disable failed for {current_user.username}: LDAP authentication failed")
            return jsonify({'error': 'Incorrect password'}), 401
    else:
        # For local users, verify against stored hash
        if not current_user.check_password(password):
            logger.warning(f"2FA disable failed for {current_user.username}: incorrect password")
            return jsonify({'error': 'Incorrect password'}), 401

    current_user.disable_totp()
    db.session.commit()

    logger.info(f"2FA disabled for {current_user.username}")
    return jsonify({'success': True, 'message': 'Two-factor authentication disabled'})

@auth_bp.route('/api/auth/2fa/status', methods=['GET'])
@login_required
def get_2fa_status():
    """Get current 2FA status"""
    current_user = get_current_user()
    if not current_user:
        return jsonify({'error': 'Not authenticated'}), 401

    return jsonify({
        'enabled': current_user.totp_enabled or False,
        'available': True  # 2FA available for all users (local and LDAP)
    })

def authenticate_ldap(user, password):
    """
    Authenticate user against Active Directory LDAP server

    This function:
    1. Binds to AD with service account (BIND_DN)
    2. Searches for user by sAMAccountName (username)
    3. Retrieves user's DN
    4. Attempts bind with user's credentials to verify password

    Args:
        user: User object with username
        password: Password to check

    Returns:
        bool: True if authentication successful
    """
    import logging
    logger = logging.getLogger('security')

    # Refresh user from database to ensure we have current data
    db.session.refresh(user)

    logger.info(f"LDAP: Starting authentication for user {user.username} (id={user.id})")

    # LDAP configuration from database (GUI settings) - use centralized function with decryption
    from app.settings_api import get_setting

    ldap_enabled = get_setting('ldap_enabled', 'false') == 'true'
    if not ldap_enabled:
        raise Exception('LDAP authentication is not enabled')

    ldap_server = get_setting('ldap_server')
    base_dn = get_setting('ldap_base_dn')
    bind_dn = get_setting('ldap_bind_dn')
    bind_pw = get_setting('ldap_bind_password')
    search_filter_template = get_setting('ldap_search_filter', '(uid={username})')
    username_attr = get_setting('ldap_username_attr', 'uid')
    email_attr = get_setting('ldap_email_attr', 'mail')
    use_tls = get_setting('ldap_use_tls', 'false') == 'true'
    ldap_port = int(get_setting('ldap_port', '389'))

    if not ldap_server:
        raise Exception('LDAP server not configured in database settings')

    if not base_dn:
        raise Exception('LDAP base DN not configured in database settings')

    try:
        import ldap3
        from ldap3 import Server, Connection, ALL, SIMPLE, SUBTREE

        # Parse server URL - handle ldap://, ldaps://, and bare hostname formats
        from app.ldap_manager import _parse_ldap_server
        server_host, use_ssl = _parse_ldap_server(ldap_server)
        if not server_host:
            raise Exception('LDAP server URL is empty after parsing')
        # Use SSL from URL prefix or fall back to TLS setting
        if not use_ssl:
            use_ssl = use_tls

        # Create server - use port and TLS from settings
        server = Server(server_host, port=ldap_port, use_ssl=use_ssl, get_info=ALL)

        # Step 1: Bind with service account to search for user
        if bind_dn and bind_pw:
            # Use service account for search
            search_conn = Connection(server, user=bind_dn, password=bind_pw, authentication=SIMPLE)
            if not search_conn.bind():
                raise Exception(f'Failed to bind with service account: {search_conn.result}')
        else:
            # Anonymous bind (not recommended for production)
            search_conn = Connection(server, authentication=SIMPLE)
            if not search_conn.bind():
                raise Exception('Failed to bind anonymously. Configure LDAP_BIND_DN and LDAP_BIND_PW')

        # Step 2: Search for user by username
        import logging
        from ldap3.utils.conv import escape_filter_chars
        logger = logging.getLogger('security')

        # Escape username to prevent LDAP injection attacks
        safe_username = escape_filter_chars(user.username)
        search_filter = search_filter_template.replace('{username}', safe_username)
        logger.info(f"LDAP: Searching for user {user.username}")

        search_conn.search(
            search_base=base_dn,
            search_filter=search_filter,
            search_scope=SUBTREE,
            attributes=[username_attr, email_attr, 'cn', 'displayName']
        )

        if not search_conn.entries:
            search_conn.unbind()
            logger.warning(f"LDAP: User {user.username} not found in LDAP directory")
            return {
                'success': False,
                'detail': f'User "{user.username}" not found in LDAP. Check if username matches AD sAMAccountName.'
            }

        # Log number of entries found (should be 1)
        num_entries = len(search_conn.entries)
        if num_entries > 1:
            logger.warning(f"LDAP: Multiple entries ({num_entries}) found for {user.username}")
            for i, entry in enumerate(search_conn.entries):
                logger.warning(f"LDAP:   Entry {i}: {entry.entry_dn}")

        # Get user's DN (works with both AD and OpenLDAP)
        user_entry = search_conn.entries[0]
        user_dn = str(user_entry.entry_dn)

        logger.info(f"LDAP: Found user {user.username}")

        # Update user's LDAP DN in database if not set or changed
        if user.ldap_dn != user_dn:
            user.ldap_dn = user_dn
            db.session.commit()

        search_conn.unbind()

        # Step 3: Attempt bind with user's credentials
        import logging
        logger = logging.getLogger('security')

        logger.info(f"LDAP: Attempting user bind for DN: {user_dn}")
        user_conn = Connection(server, user=user_dn, password=password, authentication=SIMPLE)

        if not user_conn.bind():
            # Log detailed LDAP error information server-side only
            ldap_result = user_conn.result
            result_code = ldap_result.get('result', 'unknown')
            result_desc = ldap_result.get('description', 'unknown')
            result_msg = ldap_result.get('message', '')

            logger.error(
                f"LDAP bind failed for {user.username}: "
                f"code={result_code}, desc={result_desc}, msg={result_msg}"
            )

            # Return generic error to client (details are in server logs)
            # Determine user-friendly message based on error code
            if result_code == 49:
                if '533' in str(result_msg):
                    user_message = 'Account is disabled'
                elif '775' in str(result_msg):
                    user_message = 'Account is locked'
                elif '532' in str(result_msg) or '773' in str(result_msg):
                    user_message = 'Password expired or must be changed'
                else:
                    user_message = 'Invalid credentials'
            else:
                user_message = 'Authentication failed'

            return {
                'success': False,
                'detail': user_message
            }

        logger.info(f"LDAP: Successful bind for {user.username}")
        user_conn.unbind()
        return True

    except ImportError:
        raise Exception('ldap3 library not installed. Install with: pip install ldap3')
    except Exception as e:
        raise Exception(f'LDAP authentication error: {str(e)}')
