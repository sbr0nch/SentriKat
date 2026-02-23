"""
Authentication system with local and LDAP support
Authentication is ENABLED by default for security
"""

from functools import wraps
from flask import Blueprint, render_template, request, jsonify, redirect, url_for, session, flash
from app import db, csrf, limiter
from app.models import User, Organization, SystemSettings, UserSession
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

        # Check if the session record is still active (concurrent session management)
        try:
            session_record_id = session.get('session_record_id')
            if session_record_id:
                user_session = UserSession.query.get(session_record_id)
                if not user_session or not user_session.is_active:
                    session.clear()
                    if request.is_json or request.path.startswith('/api/'):
                        return jsonify({'error': 'Session revoked'}), 401
                    return redirect(url_for('auth.login'))
        except Exception:
            pass  # Gracefully handle missing table on first run

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


def permission_required(permission):
    """Decorator to check fine-grained permissions.

    Uses the User.has_permission() method which checks custom overrides
    first, then falls back to DEFAULT_PERMISSIONS for the role.

    Usage:
        @app.route('/api/reports')
        @permission_required('view_reports')
        def get_reports():
            ...
    """
    def decorator(f):
        @wraps(f)
        @login_required
        def decorated_function(*args, **kwargs):
            user = get_current_user()
            if not user:
                if request.is_json or request.path.startswith('/api/'):
                    return jsonify({'error': 'Authentication required'}), 401
                return redirect(url_for('auth.login'))
            if not user.has_permission(permission):
                if request.is_json or request.path.startswith('/api/'):
                    return jsonify({'error': 'Insufficient permissions'}), 403
                return redirect(url_for('main.index'))
            return f(*args, **kwargs)
        return decorated_function
    return decorator


def _create_session_record(user):
    """Create a UserSession record for the current login and enforce session limits."""
    try:
        from flask import request as _req
        from datetime import timedelta

        # Determine session expiry from system settings
        timeout_minutes = 480  # default 8 hours
        try:
            timeout_setting = SystemSettings.query.filter_by(key='session_timeout').first()
            if timeout_setting and timeout_setting.value:
                timeout_minutes = int(timeout_setting.value)
        except Exception:
            pass

        now = datetime.utcnow()
        user_session = UserSession(
            session_id=session.sid if hasattr(session, 'sid') else str(id(session)),
            user_id=user.id,
            ip_address=_req.remote_addr,
            user_agent=(_req.user_agent.string or '')[:500],
            created_at=now,
            last_activity=now,
            expires_at=now + timedelta(minutes=timeout_minutes),
            is_active=True,
        )
        db.session.add(user_session)
        db.session.flush()  # Get the ID before commit
        session['session_record_id'] = user_session.id

        # Enforce concurrent session limit
        max_sessions = 5
        try:
            max_sess_setting = SystemSettings.query.filter_by(key='max_concurrent_sessions').first()
            if max_sess_setting and max_sess_setting.value:
                max_sessions = int(max_sess_setting.value)
        except Exception:
            pass
        UserSession.enforce_limit(user.id, max_sessions)

    except Exception as e:
        logger.warning(f"Could not create session record for {user.username}: {e}")
        # Don't block login if session tracking fails
        try:
            db.session.rollback()
        except Exception:
            pass


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

    # Create session record for concurrent session management
    _create_session_record(user)
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

    elif user.auth_type == 'oidc':
        logger.info(f"Login attempt for OIDC user {username} via password form - directing to OIDC SSO")
        return jsonify({'error': 'This account uses OIDC authentication. Please use the "Sign in with SSO" button.'}), 401

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

    # Check if WebAuthn hardware key authentication is required
    # This runs after TOTP (if applicable) - WebAuthn acts as additional 2FA
    try:
        from app.models import WebAuthnCredential
        from app.webauthn_manager import WEBAUTHN_AVAILABLE
        if WEBAUTHN_AVAILABLE and user.webauthn_credentials.count() > 0:
            webauthn_response = data.get('webauthn_response')
            if not webauthn_response:
                # WebAuthn required but not provided - return partial auth
                import secrets
                webauthn_session_token = secrets.token_urlsafe(32)
                session['_webauthn_pending_user'] = user.id
                session['_webauthn_pending_token'] = webauthn_session_token
                logger.info(f"WebAuthn hardware key required for {username}")
                return jsonify({
                    'success': False,
                    'requires_webauthn': True,
                    'webauthn_token': webauthn_session_token,
                    'message': 'Hardware security key authentication required'
                })
    except ImportError:
        pass  # WebAuthn not installed, skip gracefully

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

    # Create session record for concurrent session management
    _create_session_record(user)
    db.session.commit()

    # Audit trail
    try:
        from app.audit import log_audit
        log_audit('LOGIN', 'user', resource_id=user.id, resource_name=user.username,
                  details=f"Login via {user.auth_type}", user=user)
        db.session.commit()
    except Exception:
        pass

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
    # Audit trail (capture before session.clear)
    try:
        from app.audit import log_audit
        log_audit('LOGOUT', 'user', resource_id=session.get('user_id'),
                  resource_name=session.get('username'))
        db.session.commit()
    except Exception:
        pass
    # Deactivate session record
    try:
        session_record_id = session.get('session_record_id')
        if session_record_id:
            user_session = UserSession.query.get(session_record_id)
            if user_session:
                user_session.is_active = False
                db.session.commit()
    except Exception:
        pass
    session.clear()
    return jsonify({'success': True, 'redirect': url_for('auth.login')})

@auth_bp.route('/logout')
def logout():
    """Logout route"""
    # Audit trail (capture before session.clear)
    try:
        from app.audit import log_audit
        log_audit('LOGOUT', 'user', resource_id=session.get('user_id'),
                  resource_name=session.get('username'))
        db.session.commit()
    except Exception:
        pass
    # Deactivate session record
    try:
        session_record_id = session.get('session_record_id')
        if session_record_id:
            user_session = UserSession.query.get(session_record_id)
            if user_session:
                user_session.is_active = False
                db.session.commit()
    except Exception:
        pass
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

    # Invalidate all other sessions for this user (force logout on other devices)
    try:
        current_session_id = session.get('session_record_id')
        other_sessions = UserSession.query.filter(
            UserSession.user_id == current_user.id,
            UserSession.is_active == True,
            UserSession.id != current_session_id
        ).all()
        for s in other_sessions:
            s.is_active = False
        if other_sessions:
            logger.info(f"Invalidated {len(other_sessions)} other sessions for {current_user.username} after password change")
    except Exception as e:
        logger.warning(f"Could not invalidate other sessions: {e}")

    db.session.commit()

    # Audit trail
    try:
        from app.audit import log_audit
        log_audit('PASSWORD_CHANGE', 'user', resource_id=current_user.id,
                  resource_name=current_user.username)
        db.session.commit()
    except Exception:
        pass

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
        # Audit trail
        try:
            from app.audit import log_audit
            log_audit('2FA_ENABLE', 'user', resource_id=current_user.id,
                      resource_name=current_user.username)
            db.session.commit()
        except Exception:
            pass
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

    # Audit trail
    try:
        from app.audit import log_audit
        log_audit('2FA_DISABLE', 'user', resource_id=current_user.id,
                  resource_name=current_user.username)
        db.session.commit()
    except Exception:
        pass

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

# ============================================================================
# WEBAUTHN / FIDO2 HARDWARE SECURITY KEY AUTHENTICATION
# ============================================================================

@auth_bp.route('/api/auth/webauthn/register/begin', methods=['POST'])
@login_required
def webauthn_register_begin():
    """Start WebAuthn registration - generate options for the browser"""
    import base64
    try:
        from app.webauthn_manager import WEBAUTHN_AVAILABLE, generate_registration, options_to_json
    except ImportError:
        return jsonify({'error': 'WebAuthn support not available'}), 501

    if not WEBAUTHN_AVAILABLE:
        return jsonify({'error': 'WebAuthn not available - py_webauthn not installed'}), 501

    current_user = get_current_user()
    if not current_user:
        return jsonify({'error': 'Not authenticated'}), 401

    try:
        options = generate_registration(current_user)

        # Store challenge in session (base64 encoded for serialization)
        session['webauthn_register_challenge'] = base64.b64encode(options.challenge).decode('ascii')

        # Convert options to JSON-serializable format
        from app.webauthn_manager import options_to_json
        options_json = options_to_json(options)

        return jsonify({
            'success': True,
            'options': options_json
        })
    except Exception as e:
        logger.error(f"WebAuthn registration begin failed: {e}")
        return jsonify({'error': f'Failed to start registration: {str(e)}'}), 500


@auth_bp.route('/api/auth/webauthn/register/complete', methods=['POST'])
@login_required
def webauthn_register_complete():
    """Complete WebAuthn registration - verify and save credential"""
    import base64
    try:
        from app.webauthn_manager import WEBAUTHN_AVAILABLE, verify_registration
        from app.models import WebAuthnCredential
    except ImportError:
        return jsonify({'error': 'WebAuthn support not available'}), 501

    if not WEBAUTHN_AVAILABLE:
        return jsonify({'error': 'WebAuthn not available - py_webauthn not installed'}), 501

    current_user = get_current_user()
    if not current_user:
        return jsonify({'error': 'Not authenticated'}), 401

    # Get stored challenge
    challenge_b64 = session.pop('webauthn_register_challenge', None)
    if not challenge_b64:
        return jsonify({'error': 'No registration challenge found. Start registration again.'}), 400

    expected_challenge = base64.b64decode(challenge_b64)

    data = request.get_json()
    if not data or 'credential' not in data:
        return jsonify({'error': 'Missing credential data'}), 400

    try:
        verification = verify_registration(current_user, data['credential'], expected_challenge)

        # Save credential to database
        credential = WebAuthnCredential(
            user_id=current_user.id,
            credential_id=verification.credential_id,
            public_key=verification.credential_public_key,
            sign_count=verification.sign_count,
            name=data.get('name', 'Security Key'),
            created_at=datetime.utcnow()
        )
        db.session.add(credential)
        db.session.commit()

        # Audit trail
        try:
            from app.audit import log_audit
            log_audit('WEBAUTHN_REGISTER', 'user', resource_id=current_user.id,
                      resource_name=current_user.username,
                      details=f"Registered hardware security key: {credential.name}")
            db.session.commit()
        except Exception:
            pass

        logger.info(f"WebAuthn credential registered for {current_user.username}: {credential.name}")
        return jsonify({
            'success': True,
            'message': 'Security key registered successfully',
            'credential': credential.to_dict()
        })
    except Exception as e:
        logger.error(f"WebAuthn registration verify failed for {current_user.username}: {e}")
        return jsonify({'error': f'Registration failed: {str(e)}'}), 400


@auth_bp.route('/api/auth/webauthn/authenticate/begin', methods=['POST'])
def webauthn_authenticate_begin():
    """Start WebAuthn authentication - generate options for the browser"""
    import base64
    try:
        from app.webauthn_manager import WEBAUTHN_AVAILABLE, generate_authentication, options_to_json
    except ImportError:
        return jsonify({'error': 'WebAuthn support not available'}), 501

    if not WEBAUTHN_AVAILABLE:
        return jsonify({'error': 'WebAuthn not available - py_webauthn not installed'}), 501

    # Check for pending WebAuthn 2FA (set during login if user has webauthn credentials)
    pending_user_id = session.get('_webauthn_pending_user')
    if not pending_user_id:
        return jsonify({'error': 'No WebAuthn authentication pending'}), 400

    user = _safe_get_user(pending_user_id)
    if not user:
        return jsonify({'error': 'User not found'}), 400

    try:
        options = generate_authentication(user)

        # Store challenge in session
        session['webauthn_auth_challenge'] = base64.b64encode(options.challenge).decode('ascii')

        from app.webauthn_manager import options_to_json
        options_json = options_to_json(options)

        return jsonify({
            'success': True,
            'options': options_json
        })
    except Exception as e:
        logger.error(f"WebAuthn authentication begin failed: {e}")
        return jsonify({'error': f'Failed to start authentication: {str(e)}'}), 500


@auth_bp.route('/api/auth/webauthn/authenticate/complete', methods=['POST'])
def webauthn_authenticate_complete():
    """Complete WebAuthn authentication - verify assertion"""
    import base64
    try:
        from app.webauthn_manager import WEBAUTHN_AVAILABLE, verify_authentication
        from app.models import WebAuthnCredential
    except ImportError:
        return jsonify({'error': 'WebAuthn support not available'}), 501

    if not WEBAUTHN_AVAILABLE:
        return jsonify({'error': 'WebAuthn not available - py_webauthn not installed'}), 501

    # Check for pending WebAuthn 2FA
    pending_user_id = session.get('_webauthn_pending_user')
    if not pending_user_id:
        return jsonify({'error': 'No WebAuthn authentication pending'}), 400

    user = _safe_get_user(pending_user_id)
    if not user:
        return jsonify({'error': 'User not found'}), 400

    # Get stored challenge
    challenge_b64 = session.pop('webauthn_auth_challenge', None)
    if not challenge_b64:
        return jsonify({'error': 'No authentication challenge found. Start authentication again.'}), 400

    expected_challenge = base64.b64decode(challenge_b64)

    data = request.get_json()
    if not data or 'credential' not in data:
        return jsonify({'error': 'Missing credential data'}), 400

    try:
        # Find the credential record by credential ID from the response
        credential_id_b64 = data['credential'].get('id', '')
        # The credential ID from the browser is base64url encoded
        from webauthn.helpers import base64url_to_bytes
        credential_id_bytes = base64url_to_bytes(credential_id_b64)

        credential_record = WebAuthnCredential.query.filter_by(
            credential_id=credential_id_bytes,
            user_id=user.id
        ).first()

        if not credential_record:
            return jsonify({'error': 'Credential not found'}), 400

        verification = verify_authentication(
            data['credential'], expected_challenge, credential_record
        )

        # Update sign count and last used
        credential_record.sign_count = verification.new_sign_count
        credential_record.last_used_at = datetime.utcnow()

        # Clear WebAuthn pending state
        session.pop('_webauthn_pending_user', None)
        session.pop('_webauthn_pending_token', None)

        # Reset failed login attempts on successful FULL authentication
        if user.auth_type == 'local' and (user.failed_login_attempts or 0) > 0:
            user.reset_failed_login_attempts()

        # Complete login - set up full session
        # Session fixation protection: preserve webauthn state then clear
        session.clear()
        session.permanent = True
        session['user_id'] = user.id
        session['username'] = user.username
        session['is_admin'] = user.is_admin

        # Set organization
        if user.organization_id:
            session['organization_id'] = user.organization_id
        else:
            default_org = Organization.query.filter_by(name='default').first()
            if default_org:
                session['organization_id'] = default_org.id

        # Update last login
        user.last_login = datetime.utcnow()
        user.last_login_ip = request.remote_addr

        # Create session record
        _create_session_record(user)
        db.session.commit()

        # Audit trail
        try:
            from app.audit import log_audit
            log_audit('LOGIN', 'user', resource_id=user.id, resource_name=user.username,
                      details=f"Login via {user.auth_type} + WebAuthn hardware key", user=user)
            db.session.commit()
        except Exception:
            pass

        logger.info(f"WebAuthn authentication successful for {user.username}")
        return jsonify({
            'success': True,
            'user': user.to_dict(),
            'redirect': url_for('main.index')
        })
    except Exception as e:
        logger.error(f"WebAuthn authentication verify failed: {e}")
        return jsonify({'error': f'Authentication failed: {str(e)}'}), 400


@auth_bp.route('/api/auth/webauthn/credentials', methods=['GET'])
@login_required
def webauthn_list_credentials():
    """List user's registered WebAuthn credentials"""
    try:
        from app.models import WebAuthnCredential
    except ImportError:
        return jsonify({'error': 'WebAuthn support not available'}), 501

    current_user = get_current_user()
    if not current_user:
        return jsonify({'error': 'Not authenticated'}), 401

    credentials = WebAuthnCredential.query.filter_by(user_id=current_user.id).all()
    return jsonify({
        'credentials': [c.to_dict() for c in credentials]
    })


@auth_bp.route('/api/auth/webauthn/credentials/<int:credential_id>', methods=['DELETE'])
@login_required
def webauthn_delete_credential(credential_id):
    """Delete a registered WebAuthn credential"""
    try:
        from app.models import WebAuthnCredential
    except ImportError:
        return jsonify({'error': 'WebAuthn support not available'}), 501

    current_user = get_current_user()
    if not current_user:
        return jsonify({'error': 'Not authenticated'}), 401

    credential = WebAuthnCredential.query.get(credential_id)
    if not credential:
        return jsonify({'error': 'Credential not found'}), 404

    if credential.user_id != current_user.id:
        return jsonify({'error': 'Access denied'}), 403

    credential_name = credential.name
    db.session.delete(credential)
    db.session.commit()

    # Audit trail
    try:
        from app.audit import log_audit
        log_audit('WEBAUTHN_DELETE', 'user', resource_id=current_user.id,
                  resource_name=current_user.username,
                  details=f"Removed hardware security key: {credential_name}")
        db.session.commit()
    except Exception:
        pass

    logger.info(f"WebAuthn credential '{credential_name}' deleted for {current_user.username}")
    return jsonify({'success': True, 'message': f'Security key "{credential_name}" removed'})

# ============================================================================
# SESSION MANAGEMENT
# ============================================================================

@auth_bp.route('/api/auth/sessions', methods=['GET'])
@login_required
def list_sessions():
    """List current user's active sessions"""
    current_user = get_current_user()
    if not current_user:
        return jsonify({'error': 'Not authenticated'}), 401

    try:
        sessions = UserSession.query.filter_by(
            user_id=current_user.id, is_active=True
        ).order_by(UserSession.last_activity.desc()).all()

        current_session_id = session.get('session_record_id')
        result = []
        for s in sessions:
            d = s.to_dict()
            d['is_current'] = (s.id == current_session_id)
            result.append(d)

        return jsonify({'sessions': result})
    except Exception as e:
        return jsonify({'error': f'Could not retrieve sessions: {str(e)}'}), 500


@auth_bp.route('/api/auth/sessions/<int:session_id>', methods=['DELETE'])
@login_required
def revoke_session(session_id):
    """Revoke a specific session (cannot revoke own current session)"""
    current_user = get_current_user()
    if not current_user:
        return jsonify({'error': 'Not authenticated'}), 401

    try:
        user_session = UserSession.query.get(session_id)
        if not user_session:
            return jsonify({'error': 'Session not found'}), 404

        if user_session.user_id != current_user.id:
            return jsonify({'error': 'Access denied'}), 403

        current_session_id = session.get('session_record_id')
        if user_session.id == current_session_id:
            return jsonify({'error': 'Cannot revoke your current session'}), 400

        user_session.is_active = False
        db.session.commit()

        return jsonify({'success': True, 'message': 'Session revoked'})
    except Exception as e:
        return jsonify({'error': f'Could not revoke session: {str(e)}'}), 500


@auth_bp.route('/api/admin/users/<int:user_id>/sessions', methods=['DELETE'])
@admin_required
def admin_revoke_sessions(user_id):
    """Admin: revoke all active sessions for a user"""
    try:
        user = User.query.get(user_id)
        if not user:
            return jsonify({'error': 'User not found'}), 404

        active_sessions = UserSession.query.filter_by(
            user_id=user_id, is_active=True
        ).all()

        count = 0
        for s in active_sessions:
            s.is_active = False
            count += 1

        db.session.commit()

        return jsonify({
            'success': True,
            'message': f'Revoked {count} session(s) for user {user.username}'
        })
    except Exception as e:
        return jsonify({'error': f'Could not revoke sessions: {str(e)}'}), 500


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


# ============================================================================
# OIDC / OAuth Authentication
# ============================================================================

@auth_bp.route('/api/auth/oidc/login', methods=['GET'])
def oidc_login():
    """Redirect user to the OIDC provider's authorization endpoint."""
    try:
        from app.oauth_manager import AUTHLIB_AVAILABLE, get_oidc_config, create_oidc_client
    except ImportError:
        return jsonify({'error': 'OAuth module not available'}), 501

    if not AUTHLIB_AVAILABLE:
        return jsonify({'error': 'Authlib is not installed. Install with: pip install Authlib==1.4.1'}), 501

    config = get_oidc_config()
    if not config:
        return jsonify({'error': 'OIDC authentication is not enabled or not configured'}), 400

    try:
        from flask import current_app
        oauth = create_oidc_client(current_app)
        if not oauth:
            return jsonify({'error': 'Failed to create OIDC client'}), 500

        # Build the callback URL
        redirect_uri = url_for('auth.oidc_callback', _external=True)
        return oauth.oidc.authorize_redirect(redirect_uri)

    except Exception as e:
        logger.error(f"OIDC login redirect failed: {e}")
        return jsonify({'error': 'Failed to initiate OIDC login. Check OIDC configuration.'}), 500


@auth_bp.route('/api/auth/oidc/callback', methods=['GET'])
def oidc_callback():
    """Handle the OIDC provider callback after user authentication."""
    try:
        from app.oauth_manager import (
            AUTHLIB_AVAILABLE, get_oidc_config, create_oidc_client, handle_oidc_callback
        )
    except ImportError:
        return jsonify({'error': 'OAuth module not available'}), 501

    if not AUTHLIB_AVAILABLE:
        return jsonify({'error': 'Authlib is not installed'}), 501

    config = get_oidc_config()
    if not config:
        return jsonify({'error': 'OIDC is not enabled'}), 400

    try:
        from flask import current_app
        oauth = create_oidc_client(current_app)
        if not oauth:
            return jsonify({'error': 'Failed to create OIDC client'}), 500

        # Exchange authorization code for token
        token = oauth.oidc.authorize_access_token()
        if not token:
            logger.error("OIDC callback: No token received")
            flash('Authentication failed - no token received from provider.', 'danger')
            return redirect(url_for('auth.login'))

        # Extract userinfo from the token (id_token claims or userinfo endpoint)
        userinfo = token.get('userinfo')
        if not userinfo:
            # Try to parse the id_token
            try:
                userinfo = oauth.oidc.parse_id_token(token)
            except Exception:
                pass

        if not userinfo:
            # Last resort: call the userinfo endpoint
            try:
                resp = oauth.oidc.get('userinfo')
                userinfo = resp.json()
            except Exception as e:
                logger.error(f"OIDC callback: Failed to get userinfo: {e}")
                flash('Authentication failed - could not retrieve user information.', 'danger')
                return redirect(url_for('auth.login'))

        # Process the callback - find or create user
        user, error = handle_oidc_callback(token, userinfo)

        if error:
            logger.warning(f"OIDC callback failed: {error}")
            flash(error, 'danger')
            return redirect(url_for('auth.login'))

        if not user:
            flash('Authentication failed - user account could not be resolved.', 'danger')
            return redirect(url_for('auth.login'))

        # Log the user in using the shared session setup
        login_user_session(user)

        # Audit trail
        try:
            from app.audit import log_audit
            log_audit('LOGIN', 'user', resource_id=user.id, resource_name=user.username,
                      details=f"Login via OIDC ({config.get('provider_name', 'OIDC')})", user=user)
            db.session.commit()
        except Exception:
            pass

        logger.info(f"OIDC login successful for {user.username} via {config.get('provider_name', 'OIDC')}")
        return redirect(url_for('main.index'))

    except Exception as e:
        logger.exception(f"OIDC callback error: {e}")
        flash('OIDC authentication failed. Please try again or contact your administrator.', 'danger')
        return redirect(url_for('auth.login'))


@auth_bp.route('/api/auth/oidc/config', methods=['GET'])
@admin_required
def oidc_config():
    """Get OIDC configuration (admin only, no secrets exposed)."""
    try:
        from app.oauth_manager import get_oidc_public_config
        return jsonify(get_oidc_public_config())
    except ImportError:
        return jsonify({
            'enabled': False,
            'authlib_available': False,
            'error': 'OAuth module not available'
        })


# ============================================================================
# FINE-GRAINED PERMISSIONS API
# ============================================================================

@auth_bp.route('/api/admin/permissions', methods=['GET'])
@admin_required
def list_permissions():
    """List all permissions for all roles (including defaults and custom overrides)."""
    from app.models import Permission, DEFAULT_PERMISSIONS, ALL_PERMISSIONS

    org_id = request.args.get('organization_id', type=int)

    result = {}
    for role, default_perms in DEFAULT_PERMISSIONS.items():
        role_data = {
            'defaults': default_perms,
            'effective': {},
        }

        for perm in ALL_PERMISSIONS:
            # Start with default
            if '*' in default_perms:
                granted = True
            else:
                granted = perm in default_perms

            # Check for custom override
            try:
                override = None
                if org_id is not None:
                    override = Permission.query.filter_by(
                        role=role, permission=perm, organization_id=org_id
                    ).first()
                if not override:
                    override = Permission.query.filter_by(
                        role=role, permission=perm, organization_id=None
                    ).first()

                if override is not None:
                    granted = override.granted
                    role_data['effective'][perm] = {
                        'granted': granted,
                        'source': 'custom',
                        'override_id': override.id,
                    }
                else:
                    role_data['effective'][perm] = {
                        'granted': granted,
                        'source': 'default',
                    }
            except Exception:
                role_data['effective'][perm] = {
                    'granted': granted,
                    'source': 'default',
                }

        result[role] = role_data

    # Include list of all available permissions
    return jsonify({
        'permissions': result,
        'all_permissions': ALL_PERMISSIONS,
        'roles': list(DEFAULT_PERMISSIONS.keys()),
    })


@auth_bp.route('/api/admin/permissions', methods=['PUT'])
@admin_required
def update_permissions():
    """Update permissions for a role.

    Request body:
    {
        "role": "manager",
        "organization_id": null,  // null for global, int for org-specific
        "permissions": {
            "view_vulnerabilities": true,
            "manage_products": false,
            "export_data": true
        }
    }
    """
    from app.models import Permission, DEFAULT_PERMISSIONS, ALL_PERMISSIONS

    data = request.get_json()
    if not data:
        return jsonify({'error': 'No data provided'}), 400

    role = data.get('role')
    if not role or role not in DEFAULT_PERMISSIONS:
        return jsonify({'error': f'Invalid role. Must be one of: {", ".join(DEFAULT_PERMISSIONS.keys())}'}), 400

    if role == 'super_admin':
        return jsonify({'error': 'Cannot modify super_admin permissions (always has all permissions)'}), 400

    org_id = data.get('organization_id')  # None for global overrides
    permissions = data.get('permissions', {})

    if not permissions:
        return jsonify({'error': 'No permissions provided'}), 400

    try:
        updated = 0
        for perm_name, granted in permissions.items():
            if perm_name not in ALL_PERMISSIONS:
                logger.warning(f"Skipping unknown permission: {perm_name}")
                continue

            # Check if this is actually different from the default
            default_perms = DEFAULT_PERMISSIONS.get(role, [])
            default_granted = perm_name in default_perms

            if granted == default_granted and org_id is None:
                # Same as default - remove any existing override
                existing = Permission.query.filter_by(
                    role=role, permission=perm_name, organization_id=None
                ).first()
                if existing:
                    db.session.delete(existing)
                    updated += 1
            else:
                # Different from default (or org-specific) - create/update override
                existing = Permission.query.filter_by(
                    role=role, permission=perm_name, organization_id=org_id
                ).first()
                if existing:
                    existing.granted = granted
                else:
                    new_perm = Permission(
                        role=role,
                        permission=perm_name,
                        granted=granted,
                        organization_id=org_id,
                    )
                    db.session.add(new_perm)
                updated += 1

        db.session.commit()

        # Audit trail
        try:
            from app.audit import log_audit
            log_audit('UPDATE', 'permissions', resource_name=f'role:{role}',
                      details=f"Updated {updated} permission(s) for role '{role}'"
                              + (f" in org {org_id}" if org_id else " (global)"))
            db.session.commit()
        except Exception:
            pass

        return jsonify({
            'success': True,
            'message': f'Updated {updated} permission(s) for role "{role}"',
            'updated_count': updated,
        })

    except Exception as e:
        db.session.rollback()
        logger.exception(f"Failed to update permissions: {e}")
        return jsonify({'error': 'Failed to update permissions'}), 500


@auth_bp.route('/api/auth/me/permissions', methods=['GET'])
@login_required
def get_my_permissions():
    """Get the current user's effective permissions."""
    user = get_current_user()
    if not user:
        return jsonify({'error': 'Not authenticated'}), 401

    org_id = request.args.get('organization_id', type=int)
    if org_id is None:
        org_id = user.organization_id

    effective = user.get_effective_permissions(org_id=org_id)

    return jsonify({
        'role': user.role,
        'organization_id': org_id,
        'permissions': effective,
        'is_super_admin': user.role == 'super_admin' or user.is_admin,
    })
