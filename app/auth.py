"""
Authentication system with local and LDAP support
Authentication is ENABLED by default for security
"""

from functools import wraps
from flask import Blueprint, render_template, request, jsonify, redirect, url_for, session, flash
from app import db, csrf, limiter
from app.models import User, Organization
from datetime import datetime
import os

auth_bp = Blueprint('auth', __name__)

# Exempt API routes from CSRF (they use JSON and are protected by SameSite cookies)
csrf.exempt(auth_bp)

# Authentication is ALWAYS enabled by default (security requirement)
# Only disable for testing with DISABLE_AUTH=true (NOT recommended)
AUTH_ENABLED = os.environ.get('DISABLE_AUTH', 'false').lower() != 'true'

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
        user = User.query.get(session['user_id'])
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

        user = User.query.get(session['user_id'])
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
        user = User.query.get(session['user_id'])
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
                return jsonify({
                    'error': 'Organization admin privileges required',
                    'debug': {
                        'user': user.username,
                        'role': user.role,
                        'is_admin': user.is_admin,
                        'required': 'org_admin or super_admin'
                    }
                }), 403
            return redirect(url_for('main.index'))

        return f(*args, **kwargs)
    return decorated_function

def get_current_user():
    """Get current logged-in user"""
    if not AUTH_ENABLED:
        # If auth is disabled, return a fake admin user
        return None

    if 'user_id' in session:
        return User.query.get(session['user_id'])
    return None

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

    # Check authentication type
    if user.auth_type == 'local':
        # Local authentication
        if not user.check_password(password):
            return jsonify({'error': 'Invalid username or password'}), 401

    elif user.auth_type == 'ldap':
        # LDAP authentication
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

    else:
        logger.error(f"Login failed: unknown auth_type '{user.auth_type}' for user {username}")
        return jsonify({'error': 'Invalid authentication type'}), 500

    # Update last login
    logger.info(f"Authentication successful for {username}, updating last login")
    user.last_login = datetime.utcnow()
    user.last_login_ip = request.remote_addr
    db.session.commit()
    logger.info(f"Last login updated for {username}")

    # Set session as permanent (uses PERMANENT_SESSION_LIFETIME from config)
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

    return jsonify({
        'success': True,
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

        # Parse server URL - handle both "ldap://server" and "server" formats
        if '://' in ldap_server:
            use_ssl = ldap_server.startswith('ldaps://')
            server_host = ldap_server.split('://', 1)[1].split(':')[0]  # Remove protocol and port
        else:
            server_host = ldap_server
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
