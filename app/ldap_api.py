"""
LDAP Management API Endpoints
Handles LDAP user discovery, invitation, and group management
"""

from flask import Blueprint, request, jsonify, session
from app import db, csrf
from app.models import User
from app.auth import admin_required, org_admin_required
from app.ldap_manager import LDAPManager
from app.licensing import requires_professional, check_user_limit
import logging

logger = logging.getLogger(__name__)

ldap_bp = Blueprint('ldap', __name__, url_prefix='/api/ldap')

# Exempt API routes from CSRF (they use JSON and are protected by SameSite cookies)
csrf.exempt(ldap_bp)


# ============================================================================
# Permission Helpers
# ============================================================================

def get_current_user():
    """Get current logged-in user"""
    user_id = session.get('user_id')
    if user_id:
        return User.query.get(user_id)
    return None


def can_manage_ldap_users(current_user):
    """Check if user can manage LDAP users"""
    if not current_user:
        return False
    # Super admins and org admins can manage LDAP users
    return current_user.role in ['super_admin', 'org_admin']


# ============================================================================
# LDAP User Discovery
# ============================================================================

@ldap_bp.route('/search', methods=['POST'])
@requires_professional('LDAP')
@org_admin_required
def search_ldap_users():
    """
    Search LDAP directory for users

    Permissions:
    - Super Admin: Can search and see all users
    - Org Admin: Can search users for their organization
    """
    current_user = get_current_user()
    if not can_manage_ldap_users(current_user):
        return jsonify({'error': 'Insufficient permissions'}), 403

    data = request.get_json()
    search_query = data.get('query', '*')
    max_results = data.get('max_results', 50)

    result = LDAPManager.search_users(search_query, max_results)

    if not result['success']:
        return jsonify(result), 400

    return jsonify(result)


@ldap_bp.route('/user/<username>/groups', methods=['GET'])
@requires_professional('LDAP')
@org_admin_required
def get_user_ldap_groups(username):
    """
    Get LDAP groups for a specific user

    Permissions:
    - Super Admin: Can view any user's groups
    - Org Admin: Can view users in their organization
    """
    current_user = get_current_user()
    if not can_manage_ldap_users(current_user):
        return jsonify({'error': 'Insufficient permissions'}), 403

    # Check if user exists and permissions
    user = User.query.filter_by(username=username).first()
    if user and current_user.role == 'org_admin':
        # Org admins can only view users in their organization
        if user.organization_id != current_user.organization_id:
            return jsonify({'error': 'Cannot view users from other organizations'}), 403

    result = LDAPManager.get_user_groups(username)

    if not result['success']:
        return jsonify(result), 400

    return jsonify(result)


@ldap_bp.route('/user-groups', methods=['POST'])
@requires_professional('LDAP')
@org_admin_required
def get_user_ldap_groups_post():
    """
    Get LDAP groups for a specific user (POST version)

    Body:
    {
        "username": "jdoe"
    }

    Permissions:
    - Super Admin: Can view any user's groups
    - Org Admin: Can view users in their organization
    """
    current_user = get_current_user()
    if not can_manage_ldap_users(current_user):
        return jsonify({'error': 'Insufficient permissions'}), 403

    data = request.get_json()
    username = data.get('username')

    if not username:
        return jsonify({'error': 'Username is required'}), 400

    # Check if user exists and permissions
    user = User.query.filter_by(username=username).first()
    if user and current_user.role == 'org_admin':
        # Org admins can only view users in their organization
        if user.organization_id != current_user.organization_id:
            return jsonify({'error': 'Cannot view users from other organizations'}), 403

    result = LDAPManager.get_user_groups(username)

    if not result['success']:
        return jsonify(result), 400

    return jsonify(result)


# ============================================================================
# LDAP User Invitation
# ============================================================================

@ldap_bp.route('/invite', methods=['POST'])
@requires_professional('LDAP')
@org_admin_required
def invite_ldap_user():
    """
    Invite/create an LDAP user in the system

    Permissions:
    - Super Admin: Can invite users to any organization
    - Org Admin: Can only invite users to their own organization

    Body:
    {
        "username": "jdoe",
        "email": "jdoe@company.com",
        "full_name": "John Doe",
        "dn": "CN=John Doe,OU=Users,DC=company,DC=com",
        "organization_id": 1,
        "role": "user"
    }
    """
    # Check license limit for users
    allowed, limit, message = check_user_limit()
    if not allowed:
        return jsonify({'error': message, 'license_limit': True}), 403

    current_user = get_current_user()
    if not can_manage_ldap_users(current_user):
        return jsonify({'error': 'Insufficient permissions'}), 403

    data = request.get_json()

    # Required fields
    username = data.get('username')
    email = data.get('email')
    full_name = data.get('full_name')
    dn = data.get('dn')
    organization_id = data.get('organization_id')
    role = data.get('role', 'user')

    if not all([username, email, organization_id]):
        return jsonify({'error': 'Username, email, and organization_id are required'}), 400

    # Permission check for organization assignment
    if not current_user.is_super_admin():
        # Non-super-admins can only invite to their own organization
        if organization_id != current_user.organization_id:
            return jsonify({'error': 'You can only invite users to your own organization'}), 403

        # Only super admins can create super_admins and org_admins
        if role in ['super_admin', 'org_admin']:
            return jsonify({'error': 'Only super admins can create admin users'}), 403

    result = LDAPManager.invite_ldap_user(
        username=username,
        email=email,
        full_name=full_name,
        dn=dn,
        organization_id=organization_id,
        role=role
    )

    if not result['success']:
        return jsonify(result), 400

    return jsonify(result), 201


# ============================================================================
# LDAP User Sync
# ============================================================================

@ldap_bp.route('/user/<int:user_id>/sync', methods=['POST'])
@requires_professional('LDAP')
@org_admin_required
def sync_ldap_user(user_id):
    """
    Synchronize LDAP user's groups and information

    Permissions:
    - Super Admin: Can sync any user
    - Org Admin: Can only sync users in their organization
    """
    current_user = get_current_user()
    if not can_manage_ldap_users(current_user):
        return jsonify({'error': 'Insufficient permissions'}), 403

    user = User.query.get(user_id)
    if not user:
        return jsonify({'error': 'User not found'}), 404

    # Permission check
    if current_user.role == 'org_admin':
        if user.organization_id != current_user.organization_id:
            return jsonify({'error': 'Cannot sync users from other organizations'}), 403

    result = LDAPManager.sync_user_groups(user_id)

    if not result['success']:
        return jsonify(result), 400

    return jsonify(result)


# ============================================================================
# Bulk Operations
# ============================================================================

@ldap_bp.route('/bulk-invite', methods=['POST'])
@requires_professional('LDAP')
@org_admin_required
def bulk_invite_ldap_users():
    """
    Invite multiple LDAP users at once

    Permissions:
    - Super Admin: Can invite to any organization
    - Org Admin: Can only invite to their own organization

    Body:
    {
        "users": [
            {"username": "user1", "email": "user1@company.com", ...},
            {"username": "user2", "email": "user2@company.com", ...}
        ],
        "organization_id": 1,
        "role": "user"
    }
    """
    current_user = get_current_user()
    if not can_manage_ldap_users(current_user):
        return jsonify({'error': 'Insufficient permissions'}), 403

    data = request.get_json()
    users_data = data.get('users', [])
    organization_id = data.get('organization_id')
    role = data.get('role', 'user')

    if not users_data or not organization_id:
        return jsonify({'error': 'Users list and organization_id are required'}), 400

    # Permission check - non-super-admins have restrictions
    if not current_user.is_super_admin():
        if organization_id != current_user.organization_id:
            return jsonify({'error': 'Org admins can only invite to their own organization'}), 403
        if role in ['super_admin', 'org_admin']:
            return jsonify({'error': 'Org admins cannot create admin users'}), 403

    results = {
        'success': [],
        'failed': [],
        'already_exists': []
    }

    for user_data in users_data:
        username = user_data.get('username')
        email = user_data.get('email')
        full_name = user_data.get('full_name')
        dn = user_data.get('dn')

        if not username or not email:
            results['failed'].append({'username': username or 'unknown', 'error': 'Missing username or email'})
            continue

        result = LDAPManager.invite_ldap_user(
            username=username,
            email=email,
            full_name=full_name,
            dn=dn,
            organization_id=organization_id,
            role=role
        )

        if result['success']:
            if 'reactivated' in result.get('message', ''):
                results['already_exists'].append(username)
            else:
                results['success'].append(username)
        else:
            if 'already exists' in result.get('error', ''):
                results['already_exists'].append(username)
            else:
                results['failed'].append({'username': username, 'error': result.get('error')})

    return jsonify({
        'success': True,
        'results': results,
        'summary': {
            'invited': len(results['success']),
            'failed': len(results['failed']),
            'already_exists': len(results['already_exists'])
        }
    })
