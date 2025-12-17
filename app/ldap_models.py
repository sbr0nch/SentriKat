"""
LDAP Group Mapping and Audit Models
Enterprise-grade LDAP integration with group-to-role mapping
"""

from app import db
from datetime import datetime
import json

class LDAPGroupMapping(db.Model):
    """Maps LDAP groups to SentriKat roles and organizations"""
    __tablename__ = 'ldap_group_mappings'

    id = db.Column(db.Integer, primary_key=True)

    # LDAP Group Identification
    ldap_group_dn = db.Column(db.String(500), nullable=False, index=True)
    # Full Distinguished Name: CN=Security-Team,OU=IT,DC=company,DC=com

    ldap_group_cn = db.Column(db.String(200), nullable=False)
    # Common Name for display: "Security-Team"

    ldap_group_description = db.Column(db.Text, nullable=True)
    # Optional description from LDAP

    # Target Mapping
    organization_id = db.Column(db.Integer, db.ForeignKey('organizations.id'), nullable=True, index=True)
    # NULL = applies to all orgs (for super_admin groups)

    role = db.Column(db.String(20), nullable=False, index=True)
    # super_admin, org_admin, manager, user

    # Configuration
    auto_provision = db.Column(db.Boolean, default=True)
    # Automatically create users when they login if they're in this group

    auto_deprovision = db.Column(db.Boolean, default=False)
    # Deactivate users when removed from this group

    priority = db.Column(db.Integer, default=0)
    # For conflict resolution when user is in multiple groups (higher wins)

    sync_enabled = db.Column(db.Boolean, default=True)
    # Enable/disable syncing for this mapping

    # Metadata
    is_active = db.Column(db.Boolean, default=True, index=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    created_by = db.Column(db.Integer, db.ForeignKey('users.id'))
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    updated_by = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=True)
    last_sync = db.Column(db.DateTime, nullable=True)
    last_sync_status = db.Column(db.String(20), nullable=True)  # success, failed, partial
    member_count = db.Column(db.Integer, default=0)  # Cached member count from last sync

    # Relationships
    organization = db.relationship('Organization', backref='ldap_mappings')
    creator = db.relationship('User', foreign_keys=[created_by], backref='created_ldap_mappings')
    updater = db.relationship('User', foreign_keys=[updated_by], backref='updated_ldap_mappings')

    __table_args__ = (
        db.UniqueConstraint('ldap_group_dn', 'organization_id', 'role',
                          name='uix_ldap_group_org_role'),
    )

    def to_dict(self):
        return {
            'id': self.id,
            'ldap_group_dn': self.ldap_group_dn,
            'ldap_group_cn': self.ldap_group_cn,
            'ldap_group_description': self.ldap_group_description,
            'organization_id': self.organization_id,
            'organization_name': self.organization.display_name if self.organization else 'All Organizations',
            'role': self.role,
            'auto_provision': self.auto_provision,
            'auto_deprovision': self.auto_deprovision,
            'priority': self.priority,
            'sync_enabled': self.sync_enabled,
            'is_active': self.is_active,
            'created_at': self.created_at.isoformat() if self.created_at else None,
            'created_by': self.creator.username if self.creator else None,
            'updated_at': self.updated_at.isoformat() if self.updated_at else None,
            'last_sync': self.last_sync.isoformat() if self.last_sync else None,
            'last_sync_status': self.last_sync_status,
            'member_count': self.member_count
        }


class LDAPSyncLog(db.Model):
    """Audit log for LDAP synchronization operations"""
    __tablename__ = 'ldap_sync_logs'

    id = db.Column(db.Integer, primary_key=True)
    sync_id = db.Column(db.String(50), nullable=False, index=True)
    # Batch identifier (UUID) to group related events

    timestamp = db.Column(db.DateTime, default=datetime.utcnow, index=True)

    # Sync Details
    sync_type = db.Column(db.String(50), nullable=False, index=True)
    # full_sync, group_sync, user_sync, login_sync, manual_sync

    organization_id = db.Column(db.Integer, db.ForeignKey('organizations.id'), nullable=True, index=True)
    # NULL = system-wide sync

    initiated_by = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=True)
    # NULL = scheduled/automatic

    # Results
    status = db.Column(db.String(20), nullable=False, index=True)
    # success, partial, failed

    users_added = db.Column(db.Integer, default=0)
    users_updated = db.Column(db.Integer, default=0)
    users_deactivated = db.Column(db.Integer, default=0)
    roles_changed = db.Column(db.Integer, default=0)
    groups_synced = db.Column(db.Integer, default=0)

    # Performance
    duration_seconds = db.Column(db.Float, nullable=True)
    ldap_queries = db.Column(db.Integer, default=0)
    users_processed = db.Column(db.Integer, default=0)

    # Error Tracking
    errors = db.Column(db.Text, nullable=True)
    # JSON array of error objects

    error_message = db.Column(db.Text, nullable=True)
    # Main error message if sync failed

    # Summary
    summary = db.Column(db.Text, nullable=True)
    # Human-readable summary of sync results

    # Relationships
    organization = db.relationship('Organization', backref='ldap_sync_logs')
    initiator = db.relationship('User', backref='initiated_ldap_syncs')

    def to_dict(self):
        errors_list = []
        if self.errors:
            try:
                errors_list = json.loads(self.errors)
            except:
                pass

        return {
            'id': self.id,
            'sync_id': self.sync_id,
            'timestamp': self.timestamp.isoformat() if self.timestamp else None,
            'sync_type': self.sync_type,
            'organization_id': self.organization_id,
            'organization_name': self.organization.display_name if self.organization else 'System-wide',
            'initiated_by': self.initiator.username if self.initiator else 'System',
            'status': self.status,
            'users_added': self.users_added,
            'users_updated': self.users_updated,
            'users_deactivated': self.users_deactivated,
            'roles_changed': self.roles_changed,
            'groups_synced': self.groups_synced,
            'duration_seconds': self.duration_seconds,
            'ldap_queries': self.ldap_queries,
            'users_processed': self.users_processed,
            'errors': errors_list,
            'error_message': self.error_message,
            'summary': self.summary
        }


class LDAPAuditLog(db.Model):
    """Detailed audit log for all LDAP operations"""
    __tablename__ = 'ldap_audit_logs'

    id = db.Column(db.Integer, primary_key=True)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow, index=True)
    sync_id = db.Column(db.String(50), nullable=True, index=True)
    # Link to batch sync if applicable

    # Event Classification
    event_type = db.Column(db.String(50), nullable=False, index=True)
    # user_created, user_updated, user_deactivated, user_reactivated,
    # role_changed, group_mapped, group_unmapped, login_success,
    # login_failed, sync_started, sync_completed, config_changed

    # Actors
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=True, index=True)
    # Admin who performed action

    target_user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=True, index=True)
    # User being affected

    organization_id = db.Column(db.Integer, db.ForeignKey('organizations.id'), nullable=True, index=True)

    ip_address = db.Column(db.String(50), nullable=True)
    user_agent = db.Column(db.String(500), nullable=True)

    # LDAP Context
    ldap_dn = db.Column(db.String(500), nullable=True)
    # Distinguished Name of LDAP object involved

    ldap_groups = db.Column(db.Text, nullable=True)
    # JSON array of group DNs

    # Change Tracking
    field_changed = db.Column(db.String(100), nullable=True)
    old_value = db.Column(db.Text, nullable=True)
    new_value = db.Column(db.Text, nullable=True)

    # Status
    success = db.Column(db.Boolean, default=True, index=True)
    error_message = db.Column(db.Text, nullable=True)
    description = db.Column(db.Text, nullable=True)

    # Additional Context
    metadata = db.Column(db.Text, nullable=True)
    # JSON object for additional context

    # Relationships
    user = db.relationship('User', foreign_keys=[user_id], backref='ldap_actions')
    target_user = db.relationship('User', foreign_keys=[target_user_id], backref='ldap_events')
    organization = db.relationship('Organization', backref='ldap_audit_logs')

    def to_dict(self):
        groups_list = []
        if self.ldap_groups:
            try:
                groups_list = json.loads(self.ldap_groups)
            except:
                pass

        metadata_dict = {}
        if self.metadata:
            try:
                metadata_dict = json.loads(self.metadata)
            except:
                pass

        return {
            'id': self.id,
            'timestamp': self.timestamp.isoformat() if self.timestamp else None,
            'sync_id': self.sync_id,
            'event_type': self.event_type,
            'user': self.user.username if self.user else None,
            'target_user': self.target_user.username if self.target_user else None,
            'organization': self.organization.display_name if self.organization else None,
            'ip_address': self.ip_address,
            'ldap_dn': self.ldap_dn,
            'ldap_groups': groups_list,
            'field_changed': self.field_changed,
            'old_value': self.old_value,
            'new_value': self.new_value,
            'success': self.success,
            'error_message': self.error_message,
            'description': self.description,
            'metadata': metadata_dict
        }
