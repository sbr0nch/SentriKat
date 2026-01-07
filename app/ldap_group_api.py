"""
Enterprise LDAP Group Management API
REST endpoints for managing LDAP group mappings and synchronization
"""

from flask import Blueprint, request, jsonify, session
from app import db, csrf
from app.models import User, Organization
from app.ldap_models import LDAPGroupMapping, LDAPSyncLog, LDAPAuditLog
from app.ldap_manager import LDAPManager
from app.ldap_sync import LDAPSyncEngine
from app.auth import admin_required, org_admin_required
from app.licensing import requires_professional
from datetime import datetime
import json

ldap_group_bp = Blueprint('ldap_groups', __name__, url_prefix='/api/ldap/groups')

# Exempt API routes from CSRF (they use JSON and are protected by SameSite cookies)
csrf.exempt(ldap_group_bp)


# ============================================================================
# GROUP MAPPING MANAGEMENT
# ============================================================================

@ldap_group_bp.route('/mappings', methods=['GET'])
@org_admin_required
@requires_professional('LDAP')
def get_group_mappings():
    """Get all LDAP group mappings (filtered by org for org_admins)"""
    current_user = User.query.get(session.get('user_id'))

    # Super admins see all mappings
    if current_user.role == 'super_admin':
        mappings = LDAPGroupMapping.query.filter_by(is_active=True).all()
    # Org admins see only their org's mappings
    elif current_user.role == 'org_admin':
        mappings = LDAPGroupMapping.query.filter_by(
            organization_id=current_user.organization_id,
            is_active=True
        ).all()
    else:
        return jsonify({'error': 'Insufficient permissions'}), 403

    return jsonify([m.to_dict() for m in mappings])


@ldap_group_bp.route('/mappings', methods=['POST'])
@org_admin_required
@requires_professional('LDAP')
def create_group_mapping():
    """Create a new LDAP group mapping"""
    data = request.get_json()
    current_user = User.query.get(session.get('user_id'))

    # Validate required fields
    if not data.get('ldap_group_dn') or not data.get('role'):
        return jsonify({'error': 'ldap_group_dn and role are required'}), 400

    # Org admins can only create mappings for their own org
    organization_id = data.get('organization_id')
    if current_user.role == 'org_admin':
        if organization_id and organization_id != current_user.organization_id:
            return jsonify({'error': 'Org admins can only create mappings for their own organization'}), 403
        organization_id = current_user.organization_id

    # Check if mapping already exists (including soft-deleted)
    existing = LDAPGroupMapping.query.filter_by(
        ldap_group_dn=data['ldap_group_dn'],
        organization_id=organization_id,
        role=data['role']
    ).first()

    if existing:
        if existing.is_active:
            return jsonify({'error': 'Mapping already exists'}), 409
        else:
            # Reactivate soft-deleted mapping instead of creating new one
            existing.is_active = True
            existing.ldap_group_cn = data.get('ldap_group_cn', existing.ldap_group_cn)
            existing.ldap_group_description = data.get('ldap_group_description', existing.ldap_group_description)
            existing.auto_provision = data.get('auto_provision', True)
            existing.auto_deprovision = data.get('auto_deprovision', False)
            existing.priority = data.get('priority', 0)
            existing.sync_enabled = data.get('sync_enabled', True)
            existing.member_count = data.get('member_count', existing.member_count)
            existing.updated_by = current_user.id
            existing.updated_at = datetime.utcnow()

            # Log audit event for reactivation
            audit_log = LDAPAuditLog(
                event_type='group_mapping_reactivated',
                user_id=current_user.id,
                organization_id=organization_id,
                ldap_dn=data['ldap_group_dn'],
                description=f"Reactivated LDAP group mapping: {existing.ldap_group_cn} → {data['role']}",
                success=True,
                ip_address=request.remote_addr
            )
            db.session.add(audit_log)
            db.session.commit()

            return jsonify(existing.to_dict()), 200

    # Create mapping
    mapping = LDAPGroupMapping(
        ldap_group_dn=data['ldap_group_dn'],
        ldap_group_cn=data.get('ldap_group_cn', data['ldap_group_dn'].split(',')[0].replace('CN=', '')),
        ldap_group_description=data.get('ldap_group_description'),
        organization_id=organization_id,
        role=data['role'],
        auto_provision=data.get('auto_provision', True),
        auto_deprovision=data.get('auto_deprovision', False),
        priority=data.get('priority', 0),
        sync_enabled=data.get('sync_enabled', True),
        member_count=data.get('member_count', 0),
        created_by=current_user.id
    )

    db.session.add(mapping)

    # Log audit event
    audit_log = LDAPAuditLog(
        event_type='group_mapped',
        user_id=current_user.id,
        organization_id=organization_id,
        ldap_dn=data['ldap_group_dn'],
        description=f"Created LDAP group mapping: {mapping.ldap_group_cn} → {data['role']}",
        success=True,
        ip_address=request.remote_addr
    )
    db.session.add(audit_log)

    db.session.commit()

    return jsonify(mapping.to_dict()), 201


@ldap_group_bp.route('/mappings/<int:mapping_id>', methods=['PUT'])
@org_admin_required
def update_group_mapping(mapping_id):
    """Update an existing LDAP group mapping"""
    mapping = LDAPGroupMapping.query.get_or_404(mapping_id)
    current_user = User.query.get(session.get('user_id'))

    # Check permissions
    if current_user.role == 'org_admin' and mapping.organization_id != current_user.organization_id:
        return jsonify({'error': 'Cannot modify mappings for other organizations'}), 403

    data = request.get_json()

    # Update fields
    if 'ldap_group_dn' in data:
        mapping.ldap_group_dn = data['ldap_group_dn']
    if 'ldap_group_cn' in data:
        mapping.ldap_group_cn = data['ldap_group_cn']
    if 'ldap_group_description' in data:
        mapping.ldap_group_description = data['ldap_group_description']
    if 'organization_id' in data:
        # Only super_admin can change organization, or org_admin can set to their own org
        if current_user.role == 'super_admin' or data['organization_id'] == current_user.organization_id or data['organization_id'] is None:
            mapping.organization_id = data['organization_id'] if data['organization_id'] else None
    if 'role' in data:
        mapping.role = data['role']
    if 'auto_provision' in data:
        mapping.auto_provision = data['auto_provision']
    if 'auto_deprovision' in data:
        mapping.auto_deprovision = data['auto_deprovision']
    if 'priority' in data:
        mapping.priority = data['priority']
    if 'sync_enabled' in data:
        mapping.sync_enabled = data['sync_enabled']

    mapping.updated_at = datetime.utcnow()
    mapping.updated_by = current_user.id

    # Log audit event
    audit_log = LDAPAuditLog(
        event_type='group_mapping_updated',
        user_id=current_user.id,
        organization_id=mapping.organization_id,
        ldap_dn=mapping.ldap_group_dn,
        description=f"Updated LDAP group mapping: {mapping.ldap_group_cn}",
        success=True,
        ip_address=request.remote_addr
    )
    db.session.add(audit_log)

    db.session.commit()

    return jsonify(mapping.to_dict())


@ldap_group_bp.route('/mappings/<int:mapping_id>', methods=['DELETE'])
@org_admin_required
def delete_group_mapping(mapping_id):
    """Delete (deactivate) an LDAP group mapping"""
    mapping = LDAPGroupMapping.query.get_or_404(mapping_id)
    current_user = User.query.get(session.get('user_id'))

    # Check permissions
    if current_user.role == 'org_admin' and mapping.organization_id != current_user.organization_id:
        return jsonify({'error': 'Cannot delete mappings for other organizations'}), 403

    # Soft delete
    mapping.is_active = False
    mapping.updated_at = datetime.utcnow()
    mapping.updated_by = current_user.id

    # Log audit event
    audit_log = LDAPAuditLog(
        event_type='group_unmapped',
        user_id=current_user.id,
        organization_id=mapping.organization_id,
        ldap_dn=mapping.ldap_group_dn,
        description=f"Deleted LDAP group mapping: {mapping.ldap_group_cn}",
        success=True,
        ip_address=request.remote_addr
    )
    db.session.add(audit_log)

    db.session.commit()

    return jsonify({'success': True, 'message': 'Mapping deleted'})


@ldap_group_bp.route('/mappings/<int:mapping_id>/activate', methods=['PUT'])
@org_admin_required
def activate_group_mapping(mapping_id):
    """Activate an LDAP group mapping"""
    mapping = LDAPGroupMapping.query.get_or_404(mapping_id)
    current_user = User.query.get(session.get('user_id'))

    # Check permissions
    if current_user.role == 'org_admin' and mapping.organization_id != current_user.organization_id:
        return jsonify({'error': 'Cannot modify mappings for other organizations'}), 403

    mapping.is_active = True
    mapping.updated_at = datetime.utcnow()
    mapping.updated_by = current_user.id

    # Log audit event
    audit_log = LDAPAuditLog(
        event_type='group_mapping_activated',
        user_id=current_user.id,
        organization_id=mapping.organization_id,
        ldap_dn=mapping.ldap_group_dn,
        description=f"Activated LDAP group mapping: {mapping.ldap_group_cn}",
        success=True,
        ip_address=request.remote_addr
    )
    db.session.add(audit_log)

    db.session.commit()

    return jsonify({'success': True, 'message': 'Mapping activated'})


@ldap_group_bp.route('/mappings/<int:mapping_id>/deactivate', methods=['PUT'])
@org_admin_required
def deactivate_group_mapping(mapping_id):
    """Deactivate an LDAP group mapping"""
    mapping = LDAPGroupMapping.query.get_or_404(mapping_id)
    current_user = User.query.get(session.get('user_id'))

    # Check permissions
    if current_user.role == 'org_admin' and mapping.organization_id != current_user.organization_id:
        return jsonify({'error': 'Cannot modify mappings for other organizations'}), 403

    mapping.is_active = False
    mapping.updated_at = datetime.utcnow()
    mapping.updated_by = current_user.id

    # Log audit event
    audit_log = LDAPAuditLog(
        event_type='group_mapping_deactivated',
        user_id=current_user.id,
        organization_id=mapping.organization_id,
        ldap_dn=mapping.ldap_group_dn,
        description=f"Deactivated LDAP group mapping: {mapping.ldap_group_cn}",
        success=True,
        ip_address=request.remote_addr
    )
    db.session.add(audit_log)

    db.session.commit()

    return jsonify({'success': True, 'message': 'Mapping deactivated'})


# ============================================================================
# GROUP DISCOVERY
# ============================================================================

@ldap_group_bp.route('/discover', methods=['POST'])
@org_admin_required
def discover_ldap_groups():
    """Discover available LDAP groups from directory"""
    data = request.get_json()
    search_base = data.get('search_base', '')
    search_filter = data.get('search_filter', '(objectClass=group)')

    try:
        result = LDAPManager.search_groups(search_base=search_base, search_filter=search_filter)
        if not result['success']:
            return jsonify({'error': result.get('error', 'Search failed')}), 500

        return jsonify({
            'success': True,
            'groups': result['groups']
        })

    except Exception as e:
        return jsonify({'error': str(e)}), 500


@ldap_group_bp.route('/<path:group_dn>/members', methods=['GET'])
@org_admin_required
def get_group_members(group_dn):
    """Get members of a specific LDAP group"""
    try:
        result = LDAPManager.get_group_members(group_dn)
        if not result['success']:
            return jsonify({'error': result.get('error', 'Failed to get members')}), 500

        return jsonify({
            'success': True,
            'members': result['members'],
            'count': len(result['members'])
        })

    except Exception as e:
        return jsonify({'error': str(e)}), 500


# ============================================================================
# SYNCHRONIZATION
# ============================================================================

@ldap_group_bp.route('/sync/manual', methods=['POST'])
@org_admin_required
def trigger_manual_sync():
    """Trigger manual LDAP group synchronization"""
    current_user = User.query.get(session.get('user_id'))
    data = request.get_json() or {}

    # Org admins can only sync their own org
    organization_id = data.get('organization_id')
    if current_user.role == 'org_admin':
        organization_id = current_user.organization_id

    try:
        result = LDAPSyncEngine.sync_all_ldap_users(
            organization_id=organization_id,
            initiated_by=current_user.id
        )

        if not result['success']:
            return jsonify({'error': result.get('error', 'Sync failed')}), 500

        return jsonify({
            'success': True,
            'sync_id': result['sync_id'],
            'stats': result['stats'],
            'duration': result['duration'],
            'total_users': result['total_users']
        })

    except Exception as e:
        return jsonify({'error': str(e)}), 500


@ldap_group_bp.route('/sync/status', methods=['GET'])
@org_admin_required
def get_sync_status():
    """Get current sync status and latest sync info"""
    current_user = User.query.get(session.get('user_id'))

    # Get latest sync log
    query = LDAPSyncLog.query.order_by(LDAPSyncLog.timestamp.desc())

    # Org admins see only their org's syncs
    if current_user.role == 'org_admin':
        query = query.filter_by(organization_id=current_user.organization_id)

    latest_sync = query.first()

    # Get stats
    total_mappings = LDAPGroupMapping.query.filter_by(is_active=True).count()
    total_ldap_users = User.query.filter_by(auth_type='ldap', is_active=True).count()

    return jsonify({
        'latest_sync': latest_sync.to_dict() if latest_sync else None,
        'total_mappings': total_mappings,
        'total_ldap_users': total_ldap_users
    })


@ldap_group_bp.route('/sync/history', methods=['GET'])
@org_admin_required
def get_sync_history():
    """Get synchronization history"""
    current_user = User.query.get(session.get('user_id'))
    limit = request.args.get('limit', 50, type=int)
    offset = request.args.get('offset', 0, type=int)

    query = LDAPSyncLog.query.order_by(LDAPSyncLog.timestamp.desc())

    # Org admins see only their org's syncs
    if current_user.role == 'org_admin':
        query = query.filter_by(organization_id=current_user.organization_id)

    logs = query.limit(limit).offset(offset).all()
    total = query.count()

    return jsonify({
        'logs': [log.to_dict() for log in logs],
        'total': total,
        'limit': limit,
        'offset': offset
    })


@ldap_group_bp.route('/sync/user/<int:user_id>', methods=['POST'])
@org_admin_required
def sync_single_user(user_id):
    """Synchronize a single user's LDAP groups"""
    user = User.query.get_or_404(user_id)
    current_user = User.query.get(session.get('user_id'))

    # Check permissions
    if current_user.role == 'org_admin' and user.organization_id != current_user.organization_id:
        return jsonify({'error': 'Cannot sync users from other organizations'}), 403

    if user.auth_type != 'ldap':
        return jsonify({'error': 'User is not an LDAP user'}), 400

    try:
        result = LDAPSyncEngine.sync_user_from_ldap(
            user,
            initiated_by=current_user.id
        )

        if not result['success']:
            return jsonify({'error': result.get('error', 'Sync failed')}), 500

        return jsonify({
            'success': True,
            'changes': result['changes'],
            'role': result['role']
        })

    except Exception as e:
        return jsonify({'error': str(e)}), 500


# ============================================================================
# AUDIT LOGS
# ============================================================================

@ldap_group_bp.route('/audit', methods=['GET'])
@org_admin_required
def get_audit_logs():
    """Get LDAP audit logs with pagination"""
    current_user = User.query.get(session.get('user_id'))
    page = request.args.get('page', 1, type=int)
    limit = request.args.get('limit', 50, type=int)
    search = request.args.get('search', '')

    query = LDAPAuditLog.query.order_by(LDAPAuditLog.timestamp.desc())

    # Org admins see only their org's audit logs
    if current_user.role == 'org_admin':
        query = query.filter_by(organization_id=current_user.organization_id)

    # Filter by search term if provided
    if search:
        search_filter = f"%{search}%"
        query = query.filter(
            db.or_(
                LDAPAuditLog.user_username.ilike(search_filter),
                LDAPAuditLog.target_user_username.ilike(search_filter),
                LDAPAuditLog.event_type.ilike(search_filter)
            )
        )

    # Calculate pagination
    total = query.count()
    total_pages = (total + limit - 1) // limit  # Ceiling division
    offset = (page - 1) * limit

    logs = query.limit(limit).offset(offset).all()

    return jsonify({
        'logs': [log.to_dict() for log in logs],
        'total': total,
        'page': page,
        'total_pages': total_pages,
        'limit': limit
    })
