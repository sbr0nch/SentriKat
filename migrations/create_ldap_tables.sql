-- Enterprise LDAP Group Mapping Tables
-- Run this migration to add LDAP group mapping functionality

-- LDAP Group Mappings Table
CREATE TABLE IF NOT EXISTS ldap_group_mappings (
    id SERIAL PRIMARY KEY,
    ldap_group_dn VARCHAR(500) NOT NULL,
    ldap_group_cn VARCHAR(200) NOT NULL,
    ldap_group_description TEXT,
    organization_id INTEGER REFERENCES organizations(id) ON DELETE CASCADE,
    role VARCHAR(20) NOT NULL CHECK (role IN ('super_admin', 'org_admin', 'manager', 'user')),
    auto_provision BOOLEAN DEFAULT TRUE,
    auto_deprovision BOOLEAN DEFAULT FALSE,
    priority INTEGER DEFAULT 0,
    sync_enabled BOOLEAN DEFAULT TRUE,
    is_active BOOLEAN DEFAULT TRUE,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    created_by INTEGER REFERENCES users(id),
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_by INTEGER REFERENCES users(id),
    last_sync TIMESTAMP,
    last_sync_status VARCHAR(20),
    member_count INTEGER DEFAULT 0,
    UNIQUE (ldap_group_dn, organization_id, role)
);

CREATE INDEX idx_ldap_group_mappings_dn ON ldap_group_mappings(ldap_group_dn);
CREATE INDEX idx_ldap_group_mappings_org ON ldap_group_mappings(organization_id);
CREATE INDEX idx_ldap_group_mappings_role ON ldap_group_mappings(role);
CREATE INDEX idx_ldap_group_mappings_active ON ldap_group_mappings(is_active);

-- LDAP Sync Logs Table
CREATE TABLE IF NOT EXISTS ldap_sync_logs (
    id SERIAL PRIMARY KEY,
    sync_id VARCHAR(50) NOT NULL,
    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    sync_type VARCHAR(50) NOT NULL,
    organization_id INTEGER REFERENCES organizations(id) ON DELETE SET NULL,
    initiated_by INTEGER REFERENCES users(id) ON DELETE SET NULL,
    status VARCHAR(20) NOT NULL CHECK (status IN ('success', 'partial', 'failed')),
    users_added INTEGER DEFAULT 0,
    users_updated INTEGER DEFAULT 0,
    users_deactivated INTEGER DEFAULT 0,
    roles_changed INTEGER DEFAULT 0,
    groups_synced INTEGER DEFAULT 0,
    duration_seconds FLOAT,
    ldap_queries INTEGER DEFAULT 0,
    users_processed INTEGER DEFAULT 0,
    errors TEXT,
    error_message TEXT,
    summary TEXT
);

CREATE INDEX idx_ldap_sync_logs_sync_id ON ldap_sync_logs(sync_id);
CREATE INDEX idx_ldap_sync_logs_timestamp ON ldap_sync_logs(timestamp);
CREATE INDEX idx_ldap_sync_logs_type ON ldap_sync_logs(sync_type);
CREATE INDEX idx_ldap_sync_logs_org ON ldap_sync_logs(organization_id);
CREATE INDEX idx_ldap_sync_logs_status ON ldap_sync_logs(status);

-- LDAP Audit Logs Table
CREATE TABLE IF NOT EXISTS ldap_audit_logs (
    id SERIAL PRIMARY KEY,
    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    sync_id VARCHAR(50),
    event_type VARCHAR(50) NOT NULL,
    user_id INTEGER REFERENCES users(id) ON DELETE SET NULL,
    target_user_id INTEGER REFERENCES users(id) ON DELETE SET NULL,
    organization_id INTEGER REFERENCES organizations(id) ON DELETE SET NULL,
    ip_address VARCHAR(50),
    user_agent VARCHAR(500),
    ldap_dn VARCHAR(500),
    ldap_groups TEXT,
    field_changed VARCHAR(100),
    old_value TEXT,
    new_value TEXT,
    success BOOLEAN DEFAULT TRUE,
    error_message TEXT,
    description TEXT,
    metadata TEXT
);

CREATE INDEX idx_ldap_audit_logs_timestamp ON ldap_audit_logs(timestamp);
CREATE INDEX idx_ldap_audit_logs_sync_id ON ldap_audit_logs(sync_id);
CREATE INDEX idx_ldap_audit_logs_event_type ON ldap_audit_logs(event_type);
CREATE INDEX idx_ldap_audit_logs_user ON ldap_audit_logs(user_id);
CREATE INDEX idx_ldap_audit_logs_target_user ON ldap_audit_logs(target_user_id);
CREATE INDEX idx_ldap_audit_logs_org ON ldap_audit_logs(organization_id);
CREATE INDEX idx_ldap_audit_logs_success ON ldap_audit_logs(success);

-- Comments for documentation
COMMENT ON TABLE ldap_group_mappings IS 'Maps LDAP groups to SentriKat roles and organizations for automatic user provisioning';
COMMENT ON TABLE ldap_sync_logs IS 'Tracks LDAP synchronization batches and their results';
COMMENT ON TABLE ldap_audit_logs IS 'Detailed audit trail of all LDAP operations for compliance and debugging';

COMMENT ON COLUMN ldap_group_mappings.ldap_group_dn IS 'Full LDAP Distinguished Name of the group';
COMMENT ON COLUMN ldap_group_mappings.auto_provision IS 'Automatically create users on first login if they are in this group';
COMMENT ON COLUMN ldap_group_mappings.auto_deprovision IS 'Deactivate users when removed from this group';
COMMENT ON COLUMN ldap_group_mappings.priority IS 'Higher priority wins when user is in multiple groups (conflict resolution)';
