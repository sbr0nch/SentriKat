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

    # Set session
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
    Authenticate user against LDAP server

    Args:
        user: User object with ldap_dn
        password: Password to check

    Returns:
        bool: True if authentication successful
    """
    # LDAP configuration from environment
    ldap_server = os.environ.get('LDAP_SERVER')
    ldap_port = int(os.environ.get('LDAP_PORT', '389'))
    ldap_use_ssl = os.environ.get('LDAP_USE_SSL', 'false').lower() == 'true'

    if not ldap_server:
        raise Exception('LDAP_SERVER not configured')

    if not user.ldap_dn:
        raise Exception('User does not have LDAP DN configured')

    try:
        import ldap3
        from ldap3 import Server, Connection, ALL, SIMPLE

        # Create server
        if ldap_use_ssl:
            server = Server(ldap_server, port=ldap_port, use_ssl=True, get_info=ALL)
        else:
            server = Server(ldap_server, port=ldap_port, get_info=ALL)

        # Attempt bind with user credentials
        conn = Connection(server, user=user.ldap_dn, password=password, authentication=SIMPLE)

        if not conn.bind():
            return False

        conn.unbind()
        return True

    except ImportError:
        raise Exception('ldap3 library not installed. Install with: pip install ldap3')
    except Exception as e:
        raise Exception(f'LDAP connection error: {str(e)}')
