"""
Integration Models for External Software Inventory Systems

Supports both PUSH (external systems send data) and PULL (SentriKat fetches data) models.
"""

from datetime import datetime
from app import db
import json


class Integration(db.Model):
    """
    Configuration for external software inventory integrations.
    Supports various systems like PDQ, SCCM, Lansweeper, or generic REST APIs.
    """
    __tablename__ = 'integrations'

    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)  # User-friendly name

    # Integration type
    integration_type = db.Column(db.String(50), nullable=False, index=True)
    # Types: 'pdq', 'sccm', 'intune', 'lansweeper', 'csv', 'generic_rest', 'agent'

    # Connection settings (encrypted JSON)
    config_encrypted = db.Column(db.Text, nullable=True)
    # Contains: api_url, api_key, username, password, etc.

    # Target organization for imported products
    organization_id = db.Column(db.Integer, db.ForeignKey('organizations.id'), nullable=True)

    # Import behavior
    auto_approve = db.Column(db.Boolean, default=False)  # Auto-add products without review
    default_criticality = db.Column(db.String(20), default='medium')  # Default criticality for new products

    # Sync schedule (cron-like or interval)
    sync_enabled = db.Column(db.Boolean, default=True)
    sync_interval_hours = db.Column(db.Integer, default=6)  # How often to sync (for pull integrations)
    last_sync_at = db.Column(db.DateTime, nullable=True)
    last_sync_status = db.Column(db.String(20), nullable=True)  # 'success', 'failed', 'partial'
    last_sync_message = db.Column(db.Text, nullable=True)
    last_sync_count = db.Column(db.Integer, default=0)  # Products found in last sync

    # API key for push integrations (agents/scripts pushing to SentriKat)
    api_key = db.Column(db.String(64), unique=True, nullable=True, index=True)

    # Metadata
    is_active = db.Column(db.Boolean, default=True, index=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    created_by = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=True)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    # Relationships
    organization = db.relationship('Organization', backref='integrations')
    creator = db.relationship('User', foreign_keys=[created_by])

    def get_config(self):
        """Decrypt and return configuration dict."""
        if not self.config_encrypted:
            return {}
        try:
            from app.encryption import decrypt_value
            decrypted = decrypt_value(self.config_encrypted)
            return json.loads(decrypted)
        except Exception:
            # Fallback to unencrypted (for migration)
            try:
                return json.loads(self.config_encrypted)
            except (json.JSONDecodeError, TypeError, ValueError):
                return {}

    def set_config(self, config_dict):
        """Encrypt and store configuration dict."""
        from app.encryption import encrypt_value
        self.config_encrypted = encrypt_value(json.dumps(config_dict))

    def to_dict(self, include_sensitive=False):
        """Convert to dictionary for JSON serialization."""
        result = {
            'id': self.id,
            'name': self.name,
            'integration_type': self.integration_type,
            'organization_id': self.organization_id,
            'organization_name': self.organization.display_name if self.organization else None,
            'auto_approve': self.auto_approve,
            'default_criticality': self.default_criticality,
            'sync_enabled': self.sync_enabled,
            'sync_interval_hours': self.sync_interval_hours,
            'last_sync_at': self.last_sync_at.isoformat() if self.last_sync_at else None,
            'last_sync_status': self.last_sync_status,
            'last_sync_message': self.last_sync_message,
            'last_sync_count': self.last_sync_count,
            'is_active': self.is_active,
            'created_at': self.created_at.isoformat() if self.created_at else None,
            'has_api_key': bool(self.api_key)
        }

        if include_sensitive:
            result['api_key'] = self.api_key
            result['config'] = self.get_config()

        return result


class ImportQueue(db.Model):
    """
    Queue of software items pending review before being added as products.
    Populated by integrations (both push and pull).
    """
    __tablename__ = 'import_queue'

    id = db.Column(db.Integer, primary_key=True)

    # Source integration
    integration_id = db.Column(db.Integer, db.ForeignKey('integrations.id'), nullable=True, index=True)

    # Software identification
    vendor = db.Column(db.String(200), nullable=False, index=True)
    product_name = db.Column(db.String(200), nullable=False, index=True)
    detected_version = db.Column(db.String(100), nullable=True)  # Version detected by source

    # Available versions (JSON array from NVD lookup)
    available_versions = db.Column(db.Text, nullable=True)

    # Selected version (user choice, NULL = all versions)
    selected_version = db.Column(db.String(100), nullable=True)

    # CPE matching (attempted auto-match)
    cpe_vendor = db.Column(db.String(200), nullable=True)
    cpe_product = db.Column(db.String(200), nullable=True)
    cpe_match_confidence = db.Column(db.Float, nullable=True)  # 0.0 - 1.0

    # Target organization
    organization_id = db.Column(db.Integer, db.ForeignKey('organizations.id'), nullable=True)

    # Software classification (mirrors Product.source_type / Product.ecosystem)
    source_type = db.Column(db.String(30), default='os_package')  # os_package, extension, code_library
    ecosystem = db.Column(db.String(30), nullable=True)  # npm, pypi, maven, apt, rpm, vscode, chrome, etc.

    # Criticality assignment
    criticality = db.Column(db.String(20), default='medium')

    # Status
    status = db.Column(db.String(20), default='pending', index=True)
    # Status: 'pending', 'approved', 'rejected', 'duplicate', 'error'

    # Additional data from source (JSON)
    source_data = db.Column(db.Text, nullable=True)
    # Can contain: install_count, install_locations, source_hostname, etc.

    # Metadata
    created_at = db.Column(db.DateTime, default=datetime.utcnow, index=True)
    processed_at = db.Column(db.DateTime, nullable=True)
    processed_by = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=True)

    # Link to created product (if approved)
    product_id = db.Column(db.Integer, db.ForeignKey('products.id'), nullable=True)

    # Relationships
    integration = db.relationship('Integration', backref='import_items')
    organization = db.relationship('Organization', backref='import_items')
    processor = db.relationship('User', foreign_keys=[processed_by])
    product = db.relationship('Product', backref='import_source')

    def get_available_versions(self):
        """Parse available versions JSON."""
        if not self.available_versions:
            return []
        try:
            return json.loads(self.available_versions)
        except (json.JSONDecodeError, TypeError, ValueError):
            return []

    def set_available_versions(self, versions):
        """Store available versions as JSON."""
        self.available_versions = json.dumps(versions) if versions else None

    def get_source_data(self):
        """Parse source data JSON."""
        if not self.source_data:
            return {}
        try:
            return json.loads(self.source_data)
        except (json.JSONDecodeError, TypeError, ValueError):
            return {}

    def set_source_data(self, data):
        """Store source data as JSON."""
        self.source_data = json.dumps(data) if data else None

    def to_dict(self):
        """Convert to dictionary for JSON serialization."""
        sd = self.get_source_data() or {}
        return {
            'id': self.id,
            'integration_id': self.integration_id,
            'integration_name': self.integration.name if self.integration else (
                'Agent' if self.source_data and 'push_agent' in (self.source_data or '') else 'Manual Import'
            ),
            'vendor': self.vendor,
            'product_name': self.product_name,
            'detected_version': self.detected_version,
            'available_versions': self.get_available_versions(),
            'selected_version': self.selected_version,
            'cpe_vendor': self.cpe_vendor,
            'cpe_product': self.cpe_product,
            'cpe_match_confidence': self.cpe_match_confidence,
            'organization_id': self.organization_id,
            'organization_name': self.organization.display_name if self.organization else None,
            'source_type': self.source_type or (sd.get('source_type', 'os_package') if sd else 'os_package'),
            'ecosystem': self.ecosystem or (sd.get('ecosystem') if sd else None),
            'criticality': self.criticality,
            'status': self.status,
            'source_data': sd,
            'hostname': sd.get('hostname'),
            'agent_name': sd.get('agent_name'),
            'key_type': sd.get('key_type'),
            'is_new': sd.get('is_new', True),
            'created_at': self.created_at.isoformat() if self.created_at else None,
            'processed_at': self.processed_at.isoformat() if self.processed_at else None,
            'product_id': self.product_id
        }


class AgentRegistration(db.Model):
    """
    Registered discovery agents (Windows/Linux endpoints).
    Agents report installed software to SentriKat.
    """
    __tablename__ = 'agent_registrations'

    id = db.Column(db.Integer, primary_key=True)

    # Agent identification
    agent_id = db.Column(db.String(64), unique=True, nullable=False, index=True)  # UUID
    hostname = db.Column(db.String(255), nullable=False, index=True)

    # System information
    os_type = db.Column(db.String(20), nullable=False)  # 'windows', 'linux', 'macos'
    os_version = db.Column(db.String(100), nullable=True)
    os_arch = db.Column(db.String(20), nullable=True)  # 'x64', 'x86', 'arm64'

    # Agent version
    agent_version = db.Column(db.String(20), nullable=True)

    # Parent integration (agents belong to an integration for organization assignment)
    integration_id = db.Column(db.Integer, db.ForeignKey('integrations.id'), nullable=True, index=True)

    # Organization assignment (can override integration default)
    organization_id = db.Column(db.Integer, db.ForeignKey('organizations.id'), nullable=True)

    # Status
    is_active = db.Column(db.Boolean, default=True, index=True)
    last_seen_at = db.Column(db.DateTime, nullable=True)
    last_report_at = db.Column(db.DateTime, nullable=True)
    software_count = db.Column(db.Integer, default=0)  # Number of software items reported

    # Metadata
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    ip_address = db.Column(db.String(45), nullable=True)  # Last known IP

    # Additional system info (JSON)
    system_info = db.Column(db.Text, nullable=True)

    # Relationships
    integration = db.relationship('Integration', backref='agents')
    organization = db.relationship('Organization', backref='agents')

    def get_system_info(self):
        """Parse system info JSON."""
        if not self.system_info:
            return {}
        try:
            return json.loads(self.system_info)
        except (json.JSONDecodeError, TypeError, ValueError):
            return {}

    def set_system_info(self, info):
        """Store system info as JSON."""
        self.system_info = json.dumps(info) if info else None

    def to_dict(self):
        """Convert to dictionary for JSON serialization."""
        return {
            'id': self.id,
            'agent_id': self.agent_id,
            'hostname': self.hostname,
            'os_type': self.os_type,
            'os_version': self.os_version,
            'os_arch': self.os_arch,
            'agent_version': self.agent_version,
            'integration_id': self.integration_id,
            'integration_name': self.integration.name if self.integration else None,
            'organization_id': self.organization_id,
            'organization_name': self.organization.display_name if self.organization else None,
            'is_active': self.is_active,
            'last_seen_at': self.last_seen_at.isoformat() if self.last_seen_at else None,
            'last_report_at': self.last_report_at.isoformat() if self.last_report_at else None,
            'software_count': self.software_count,
            'created_at': self.created_at.isoformat() if self.created_at else None,
            'ip_address': self.ip_address,
            'system_info': self.get_system_info()
        }
