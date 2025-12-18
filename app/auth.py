"""
Authentication system with local and LDAP support
Controlled by ENABLE_AUTH environment variable
"""

from functools import wraps
from flask import Blueprint, render_template, request, jsonify, redirect, url_for, session, flash
from app import db
from app.models import User, Organization
from datetime import datetime
import os

auth_bp = Blueprint('auth', __name__)

# Check if authentication is enabled
AUTH_ENABLED = os.environ.get('ENABLE_AUTH', 'false').lower() == 'true'

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
    """Decorator to require admin privileges"""
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

        # Check if user is admin
        user = User.query.get(session['user_id'])
        if not user or not user.is_admin:
            if request.is_json or request.path.startswith('/api/'):
                return jsonify({'error': 'Admin privileges required'}), 403
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

    if 'user_id' in session:
        return redirect(url_for('main.index'))

    return render_template('login.html')

@auth_bp.route('/api/auth/login', methods=['POST'])
def api_login():
    """Handle login via API"""
    if not AUTH_ENABLED:
        return jsonify({'error': 'Authentication is disabled'}), 400

    data = request.get_json()
    username = data.get('username')
    password = data.get('password')

    if not username or not password:
        return jsonify({'error': 'Username and password required'}), 400

    # Find user
    user = User.query.filter_by(username=username, is_active=True).first()

    if not user:
        return jsonify({'error': 'Invalid username or password'}), 401

    # Check authentication type
    if user.auth_type == 'local':
        # Local authentication
        if not user.check_password(password):
            return jsonify({'error': 'Invalid username or password'}), 401

    elif user.auth_type == 'ldap':
        # LDAP authentication
        try:
            if not authenticate_ldap(user, password):
                return jsonify({'error': 'Invalid LDAP credentials'}), 401
        except Exception as e:
            return jsonify({'error': f'LDAP authentication failed: {str(e)}'}), 500

    else:
        return jsonify({'error': 'Invalid authentication type'}), 500

    # Update last login
    user.last_login = datetime.utcnow()
    user.last_login_ip = request.remote_addr
    db.session.commit()

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
    # LDAP configuration from database (GUI settings)
    from app.models import SystemSettings

    def get_setting(key, default=None):
        setting = SystemSettings.query.filter_by(key=key).first()
        return setting.value if setting else default

    ldap_enabled = get_setting('ldap_enabled', 'false') == 'true'
    if not ldap_enabled:
        raise Exception('LDAP authentication is not enabled')

    ldap_server = get_setting('ldap_server')
    base_dn = get_setting('ldap_base_dn')
    bind_dn = get_setting('ldap_bind_dn')
    bind_pw = get_setting('ldap_bind_password')
    search_filter_template = get_setting('ldap_search_filter', '(sAMAccountName={username})')
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

        # Step 2: Search for user by username (sAMAccountName)
        search_filter = search_filter_template.replace('{username}', user.username)
        search_conn.search(
            search_base=base_dn,
            search_filter=search_filter,
            search_scope=SUBTREE,
            attributes=['distinguishedName', 'sAMAccountName', 'mail', 'displayName']
        )

        if not search_conn.entries:
            search_conn.unbind()
            return False

        # Get user's DN
        user_entry = search_conn.entries[0]
        user_dn = user_entry.distinguishedName.value

        # Update user's LDAP DN in database if not set or changed
        if user.ldap_dn != user_dn:
            user.ldap_dn = user_dn
            db.session.commit()

        search_conn.unbind()

        # Step 3: Attempt bind with user's credentials
        user_conn = Connection(server, user=user_dn, password=password, authentication=SIMPLE)

        if not user_conn.bind():
            return False

        user_conn.unbind()
        return True

    except ImportError:
        raise Exception('ldap3 library not installed. Install with: pip install ldap3')
    except Exception as e:
        raise Exception(f'LDAP authentication error: {str(e)}')
