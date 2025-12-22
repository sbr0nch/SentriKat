from datetime import datetime, date
from app import db
from werkzeug.security import generate_password_hash, check_password_hash
import json

# Association table for many-to-many relationship between products and organizations
product_organizations = db.Table('product_organizations',
    db.Column('product_id', db.Integer, db.ForeignKey('products.id'), primary_key=True),
    db.Column('organization_id', db.Integer, db.ForeignKey('organizations.id'), primary_key=True),
    db.Column('assigned_at', db.DateTime, default=datetime.utcnow)
)


class UserOrganization(db.Model):
    """
    Many-to-many relationship between users and organizations with role per org.
    Allows a user to belong to multiple organizations with different roles.
    """
    __tablename__ = 'user_organizations'

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False, index=True)
    organization_id = db.Column(db.Integer, db.ForeignKey('organizations.id'), nullable=False, index=True)
    role = db.Column(db.String(20), default='user', nullable=False)  # super_admin, org_admin, manager, user

    # Metadata
    assigned_at = db.Column(db.DateTime, default=datetime.utcnow)
    assigned_by = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=True)

    # Unique constraint: user can only have one role per organization
    __table_args__ = (
        db.UniqueConstraint('user_id', 'organization_id', name='unique_user_org'),
    )

    # Relationships
    user = db.relationship('User', foreign_keys=[user_id], backref=db.backref('org_memberships', lazy='dynamic', cascade='all, delete-orphan'))
    organization = db.relationship('Organization', backref=db.backref('user_memberships', lazy='dynamic'))
    assigner = db.relationship('User', foreign_keys=[assigned_by])

    def to_dict(self):
        return {
            'id': self.id,
            'user_id': self.user_id,
            'organization_id': self.organization_id,
            'organization_name': self.organization.display_name if self.organization else None,
            'role': self.role,
            'assigned_at': self.assigned_at.isoformat() if self.assigned_at else None,
            'assigned_by': self.assigner.username if self.assigner else None
        }

class Organization(db.Model):
    """Represents a team, vault, or organizational unit with separate settings"""
    __tablename__ = 'organizations'

    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), unique=True, nullable=False, index=True)
    display_name = db.Column(db.String(200), nullable=False)
    description = db.Column(db.Text, nullable=True)

    # SMTP Email Settings (per organization)
    smtp_host = db.Column(db.String(255), nullable=True)
    smtp_port = db.Column(db.Integer, default=587)
    smtp_username = db.Column(db.String(255), nullable=True)
    smtp_password = db.Column(db.String(500), nullable=True)  # Encrypted in production
    smtp_use_tls = db.Column(db.Boolean, default=True)
    smtp_use_ssl = db.Column(db.Boolean, default=False)
    smtp_from_email = db.Column(db.String(255), nullable=True)
    smtp_from_name = db.Column(db.String(100), default='SentriKat Alerts')

    # Alert Settings
    notification_emails = db.Column(db.Text, nullable=True)  # JSON array: ["email1@domain.com", "email2@domain.com"]
    alert_on_critical = db.Column(db.Boolean, default=True)
    alert_on_high = db.Column(db.Boolean, default=False)
    alert_on_new_cve = db.Column(db.Boolean, default=True)
    alert_on_ransomware = db.Column(db.Boolean, default=True)
    alert_time_start = db.Column(db.String(5), default='08:00')  # HH:MM format
    alert_time_end = db.Column(db.String(5), default='18:00')    # HH:MM format
    alert_days = db.Column(db.String(50), default='mon,tue,wed,thu,fri')  # Comma-separated days

    # Metadata
    active = db.Column(db.Boolean, default=True, index=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    def to_dict(self):
        # Count active users in this organization
        user_count = User.query.filter_by(organization_id=self.id, is_active=True).count()

        return {
            'id': self.id,
            'name': self.name,
            'display_name': self.display_name,
            'description': self.description,
            'notification_emails': json.loads(self.notification_emails) if self.notification_emails else [],
            'alert_settings': {
                'critical': self.alert_on_critical,
                'high': self.alert_on_high,
                'new_cve': self.alert_on_new_cve,
                'ransomware': self.alert_on_ransomware,
                'time_start': self.alert_time_start,
                'time_end': self.alert_time_end,
                'days': self.alert_days
            },
            # SMTP Settings (return all except password for security)
            'smtp_host': self.smtp_host,
            'smtp_port': self.smtp_port,
            'smtp_username': self.smtp_username,
            'smtp_password': '********' if self.smtp_password else '',  # Mask password
            'smtp_use_tls': self.smtp_use_tls,
            'smtp_use_ssl': self.smtp_use_ssl,
            'smtp_from_email': self.smtp_from_email,
            'smtp_from_name': self.smtp_from_name,
            'smtp_configured': bool(self.smtp_host and self.smtp_from_email),
            # Alert settings (flat)
            'alert_on_critical': self.alert_on_critical,
            'alert_on_high': self.alert_on_high,
            'alert_on_new_cve': self.alert_on_new_cve,
            'alert_on_ransomware': self.alert_on_ransomware,
            'user_count': user_count,
            'active': self.active,
            'created_at': self.created_at.isoformat() if self.created_at else None
        }

    def get_smtp_config(self):
        """Return SMTP configuration dictionary"""
        return {
            'host': self.smtp_host,
            'port': self.smtp_port,
            'username': self.smtp_username,
            'password': self.smtp_password,
            'use_tls': self.smtp_use_tls,
            'use_ssl': self.smtp_use_ssl,
            'from_email': self.smtp_from_email,
            'from_name': self.smtp_from_name
        }

class Product(db.Model):
    """Software/service inventory managed by admins"""
    __tablename__ = 'products'

    id = db.Column(db.Integer, primary_key=True)
    organization_id = db.Column(db.Integer, db.ForeignKey('organizations.id'), nullable=True, index=True)  # NULL for migration compatibility
    service_catalog_id = db.Column(db.Integer, db.ForeignKey('service_catalog.id'), nullable=True)  # Optional link to catalog
    vendor = db.Column(db.String(200), nullable=False, index=True)
    product_name = db.Column(db.String(200), nullable=False, index=True)
    version = db.Column(db.String(100), nullable=True)
    keywords = db.Column(db.Text, nullable=True)  # Comma-separated additional keywords
    description = db.Column(db.Text, nullable=True)
    active = db.Column(db.Boolean, default=True, index=True)
    criticality = db.Column(db.String(20), default='medium')  # critical, high, medium, low
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    # Relationships
    organization = db.relationship('Organization', backref='products')  # Legacy single org (deprecated)
    organizations = db.relationship('Organization', secondary=product_organizations, backref='assigned_products', lazy='dynamic')  # Multi-org support
    catalog_entry = db.relationship('ServiceCatalog', backref='deployed_instances')

    def to_dict(self):
        # Get assigned organizations
        assigned_orgs = [{'id': org.id, 'name': org.name, 'display_name': org.display_name}
                         for org in self.organizations.all()]

        # Include legacy organization_id for backwards compatibility
        if self.organization_id and not assigned_orgs:
            # If using legacy single org, add it to the list
            if self.organization:
                assigned_orgs = [{'id': self.organization.id, 'name': self.organization.name, 'display_name': self.organization.display_name}]

        return {
            'id': self.id,
            'organization_id': self.organization_id,  # Legacy field
            'organizations': assigned_orgs,  # New multi-org field
            'service_catalog_id': self.service_catalog_id,
            'vendor': self.vendor,
            'product_name': self.product_name,
            'version': self.version,
            'keywords': self.keywords,
            'description': self.description,
            'active': self.active,
            'criticality': self.criticality,
            'created_at': self.created_at.isoformat() if self.created_at else None,
            'updated_at': self.updated_at.isoformat() if self.updated_at else None
        }

class Vulnerability(db.Model):
    """CISA KEV vulnerabilities cache"""
    __tablename__ = 'vulnerabilities'

    id = db.Column(db.Integer, primary_key=True)
    cve_id = db.Column(db.String(50), unique=True, nullable=False, index=True)
    vendor_project = db.Column(db.String(200), nullable=False, index=True)
    product = db.Column(db.String(200), nullable=False, index=True)
    vulnerability_name = db.Column(db.String(500), nullable=False)
    date_added = db.Column(db.Date, nullable=False, index=True)
    short_description = db.Column(db.Text, nullable=False)
    required_action = db.Column(db.Text, nullable=False)
    due_date = db.Column(db.Date, nullable=True, index=True)
    known_ransomware = db.Column(db.Boolean, default=False, index=True)
    notes = db.Column(db.Text, nullable=True)
    cvss_score = db.Column(db.Float, nullable=True, index=True)  # CVSS score from NVD
    severity = db.Column(db.String(20), nullable=True, index=True)  # CRITICAL, HIGH, MEDIUM, LOW
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    def calculate_priority(self):
        """
        Calculate priority based on multiple factors:
        1. CVE Severity (from CVSS score) - PRIMARY FACTOR
        2. Ransomware involvement: Automatic CRITICAL
        3. Due date proximity: Urgent if due soon
        4. Age: Recent CVEs are higher priority
        Returns: critical, high, medium, low
        """
        priority_order = {'critical': 4, 'high': 3, 'medium': 2, 'low': 1}

        # Start with CVE severity if available (PRIMARY)
        if self.severity:
            base_priority = self.severity.lower()
        else:
            # Fallback to age-based if no severity data
            days_since_added = (date.today() - self.date_added).days
            if days_since_added <= 30:
                base_priority = 'high'
            elif days_since_added <= 90:
                base_priority = 'medium'
            else:
                base_priority = 'low'

        current_level = priority_order.get(base_priority, 2)

        # Ransomware = Always Critical (OVERRIDE)
        if self.known_ransomware:
            return 'critical'

        # Check due date urgency (can ELEVATE priority)
        if self.due_date:
            days_until_due = (self.due_date - date.today()).days
            if days_until_due <= 7:
                current_level = max(current_level, priority_order['critical'])
            elif days_until_due <= 30:
                current_level = max(current_level, priority_order['high'])

        # Return the priority level
        for priority, level in priority_order.items():
            if level == current_level:
                return priority

        return 'medium'

    def to_dict(self):
        return {
            'id': self.id,
            'cve_id': self.cve_id,
            'vendor_project': self.vendor_project,
            'product': self.product,
            'vulnerability_name': self.vulnerability_name,
            'date_added': self.date_added.isoformat() if self.date_added else None,
            'short_description': self.short_description,
            'required_action': self.required_action,
            'due_date': self.due_date.isoformat() if self.due_date else None,
            'known_ransomware': self.known_ransomware,
            'notes': self.notes,
            'cvss_score': self.cvss_score,
            'severity': self.severity,
            'priority': self.calculate_priority(),
            'days_old': (date.today() - self.date_added).days if self.date_added else None
        }

class VulnerabilityMatch(db.Model):
    """Matched vulnerabilities for tracked products"""
    __tablename__ = 'vulnerability_matches'

    id = db.Column(db.Integer, primary_key=True)
    product_id = db.Column(db.Integer, db.ForeignKey('products.id'), nullable=False, index=True)
    vulnerability_id = db.Column(db.Integer, db.ForeignKey('vulnerabilities.id'), nullable=False, index=True)
    match_reason = db.Column(db.String(200), nullable=True)  # Why it matched (vendor, product, keyword)
    acknowledged = db.Column(db.Boolean, default=False, index=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    product = db.relationship('Product', backref='matches')
    vulnerability = db.relationship('Vulnerability', backref='matches')

    def calculate_effective_priority(self):
        """
        Calculate effective priority combining:
        - Product criticality
        - Vulnerability priority
        Returns the higher of the two
        """
        vuln_priority = self.vulnerability.calculate_priority()
        product_criticality = self.product.criticality

        priority_order = {'critical': 4, 'high': 3, 'medium': 2, 'low': 1}

        vuln_level = priority_order.get(vuln_priority, 2)
        prod_level = priority_order.get(product_criticality, 2)

        # Return the higher priority
        max_level = max(vuln_level, prod_level)

        for priority, level in priority_order.items():
            if level == max_level:
                return priority

        return 'medium'

    def to_dict(self):
        vuln_dict = self.vulnerability.to_dict()
        product_dict = self.product.to_dict()

        return {
            'id': self.id,
            'product': product_dict,
            'vulnerability': vuln_dict,
            'match_reason': self.match_reason,
            'acknowledged': self.acknowledged,
            'created_at': self.created_at.isoformat() if self.created_at else None,
            'effective_priority': self.calculate_effective_priority(),
            'product_criticality': product_dict['criticality']
        }

class SyncLog(db.Model):
    """Log of CISA KEV sync operations"""
    __tablename__ = 'sync_logs'

    id = db.Column(db.Integer, primary_key=True)
    sync_date = db.Column(db.DateTime, default=datetime.utcnow, index=True)
    status = db.Column(db.String(50), nullable=False)  # success, error
    vulnerabilities_count = db.Column(db.Integer, default=0)
    matches_found = db.Column(db.Integer, default=0)
    error_message = db.Column(db.Text, nullable=True)
    duration_seconds = db.Column(db.Float, nullable=True)

    def to_dict(self):
        return {
            'id': self.id,
            'sync_date': self.sync_date.isoformat() if self.sync_date else None,
            'status': self.status,
            'vulnerabilities_count': self.vulnerabilities_count,
            'matches_found': self.matches_found,
            'error_message': self.error_message,
            'duration_seconds': self.duration_seconds
        }

class ServiceCatalog(db.Model):
    """Catalog of real-world software/services for guided product addition"""
    __tablename__ = 'service_catalog'

    id = db.Column(db.Integer, primary_key=True)
    vendor = db.Column(db.String(200), nullable=False, index=True)
    product_name = db.Column(db.String(200), nullable=False, index=True)
    category = db.Column(db.String(100), nullable=True, index=True)
    subcategory = db.Column(db.String(100), nullable=True)

    # Common identifiers for better matching
    common_names = db.Column(db.Text, nullable=True)  # JSON array
    cpe_vendor = db.Column(db.String(200), nullable=True)  # CPE vendor name
    cpe_product = db.Column(db.String(200), nullable=True)  # CPE product name

    # Metadata
    description = db.Column(db.Text, nullable=True)
    website_url = db.Column(db.String(500), nullable=True)
    typical_versions = db.Column(db.Text, nullable=True)  # JSON array

    # Popularity/Usage
    usage_frequency = db.Column(db.Integer, default=0)
    is_popular = db.Column(db.Boolean, default=False, index=True)

    # Status
    is_active = db.Column(db.Boolean, default=True, index=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    __table_args__ = (
        db.UniqueConstraint('vendor', 'product_name', name='uix_vendor_product'),
    )

    def to_dict(self):
        common_names_list = json.loads(self.common_names) if self.common_names else []
        # Create keywords string from common names for display
        keywords_str = ', '.join(common_names_list) if common_names_list else ''

        return {
            'id': self.id,
            'vendor': self.vendor,
            'product_name': self.product_name,
            'category': self.category,
            'subcategory': self.subcategory,
            'common_names': common_names_list,
            'keywords': keywords_str,  # String format for display/form
            'cpe_vendor': self.cpe_vendor,
            'cpe_product': self.cpe_product,
            'description': self.description,
            'website_url': self.website_url,
            'typical_versions': json.loads(self.typical_versions) if self.typical_versions else [],
            'is_popular': self.is_popular,
            'usage_frequency': self.usage_frequency
        }

class User(db.Model):
    """User accounts for authentication"""
    __tablename__ = 'users'

    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(100), unique=True, nullable=False, index=True)
    email = db.Column(db.String(255), unique=True, nullable=False, index=True)
    full_name = db.Column(db.String(255), nullable=True)  # User's full name
    password_hash = db.Column(db.String(255), nullable=True)  # NULL for LDAP users

    # Organization assignment
    organization_id = db.Column(db.Integer, db.ForeignKey('organizations.id'), nullable=True, index=True)

    # Authentication type
    auth_type = db.Column(db.String(20), default='local')  # 'local', 'ldap'
    ldap_dn = db.Column(db.String(500), nullable=True)  # LDAP Distinguished Name

    # Permissions & Roles
    # Role-based access: super_admin > org_admin > manager > user
    role = db.Column(db.String(20), default='user', index=True)  # super_admin, org_admin, manager, user
    is_admin = db.Column(db.Boolean, default=False)  # Backward compatibility - maps to super_admin or org_admin
    is_active = db.Column(db.Boolean, default=True, index=True)
    can_manage_products = db.Column(db.Boolean, default=True)
    can_view_all_orgs = db.Column(db.Boolean, default=False)  # Super admin only

    # Session tracking
    last_login = db.Column(db.DateTime, nullable=True)
    last_login_ip = db.Column(db.String(50), nullable=True)

    # Metadata
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    # Relationships
    organization = db.relationship('Organization', backref='users')

    def set_password(self, password):
        """Hash and set password for local auth"""
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        """Check password for local auth"""
        if not self.password_hash:
            return False
        return check_password_hash(self.password_hash, password)

    def is_super_admin(self):
        """Check if user is a super admin"""
        return self.role == 'super_admin' or (self.is_admin and self.can_view_all_orgs)

    def is_org_admin(self):
        """Check if user is an organization admin"""
        return self.role in ['super_admin', 'org_admin'] or self.is_admin

    def can_manage_organization(self, org_id):
        """Check if user can manage a specific organization"""
        if self.is_super_admin():
            return True
        # Check legacy single org
        if self.role == 'org_admin' and self.organization_id == org_id:
            return True
        # Check multi-org memberships
        membership = self.org_memberships.filter_by(organization_id=org_id).first()
        if membership and membership.role == 'org_admin':
            return True
        return False

    def can_manage_user(self, target_user):
        """Check if user can manage another user"""
        if self.is_super_admin():
            return True
        if self.role == 'org_admin':
            # Org admins can manage users in their organization (except super admins)
            return (target_user.organization_id == self.organization_id and
                    not target_user.is_super_admin())
        return False

    # =========================================================================
    # Multi-Organization Methods
    # =========================================================================

    def get_all_organizations(self):
        """Get all organizations the user has access to (both legacy and multi-org)"""
        orgs = []

        # Add legacy organization if exists
        if self.organization_id and self.organization:
            orgs.append({
                'id': self.organization.id,
                'name': self.organization.name,
                'display_name': self.organization.display_name,
                'role': self.role,
                'is_primary': True
            })

        # Add multi-org memberships
        for membership in self.org_memberships.all():
            # Skip if already added as primary
            if membership.organization_id == self.organization_id:
                continue
            orgs.append({
                'id': membership.organization.id,
                'name': membership.organization.name,
                'display_name': membership.organization.display_name,
                'role': membership.role,
                'is_primary': False
            })

        return orgs

    def get_role_for_org(self, org_id):
        """Get user's role for a specific organization"""
        # Super admins have super_admin role everywhere
        if self.is_super_admin():
            return 'super_admin'

        # Check legacy organization
        if self.organization_id == org_id:
            return self.role

        # Check multi-org membership
        membership = self.org_memberships.filter_by(organization_id=org_id).first()
        if membership:
            return membership.role

        return None

    def has_access_to_org(self, org_id):
        """Check if user has any access to a specific organization"""
        if self.is_super_admin() or self.can_view_all_orgs:
            return True

        # Check legacy organization
        if self.organization_id == org_id:
            return True

        # Check multi-org membership
        membership = self.org_memberships.filter_by(organization_id=org_id).first()
        return membership is not None

    def is_org_admin_for(self, org_id):
        """Check if user is org_admin for a specific organization"""
        if self.is_super_admin():
            return True

        role = self.get_role_for_org(org_id)
        return role == 'org_admin'

    def add_to_organization(self, org_id, role='user', assigned_by_id=None):
        """Add user to an organization with specified role"""
        # Check if already exists
        existing = self.org_memberships.filter_by(organization_id=org_id).first()
        if existing:
            # Update role
            existing.role = role
            existing.assigned_by = assigned_by_id
            existing.assigned_at = datetime.utcnow()
        else:
            # Create new membership
            membership = UserOrganization(
                user_id=self.id,
                organization_id=org_id,
                role=role,
                assigned_by=assigned_by_id
            )
            db.session.add(membership)
        return True

    def remove_from_organization(self, org_id):
        """Remove user from an organization"""
        membership = self.org_memberships.filter_by(organization_id=org_id).first()
        if membership:
            db.session.delete(membership)
            return True
        return False

    def to_dict(self):
        # Get org memberships
        org_memberships = [m.to_dict() for m in self.org_memberships.all()]

        return {
            'id': self.id,
            'username': self.username,
            'email': self.email,
            'full_name': self.full_name,
            'organization_id': self.organization_id,
            'organization_name': self.organization.display_name if self.organization else None,
            'auth_type': self.auth_type,
            'role': self.role,
            'is_admin': self.is_admin,
            'is_active': self.is_active,
            'can_manage_products': self.can_manage_products,
            'can_view_all_orgs': self.can_view_all_orgs,
            'last_login': self.last_login.isoformat() if self.last_login else None,
            'created_at': self.created_at.isoformat() if self.created_at else None,
            # Multi-org data
            'org_memberships': org_memberships,
            'all_organizations': self.get_all_organizations()
        }

class SystemSettings(db.Model):
    """Global system settings"""
    __tablename__ = 'system_settings'

    id = db.Column(db.Integer, primary_key=True)
    key = db.Column(db.String(100), unique=True, nullable=False, index=True)
    value = db.Column(db.Text, nullable=True)
    category = db.Column(db.String(50), nullable=False, index=True)  # 'ldap', 'smtp', 'sync', 'general'
    description = db.Column(db.Text, nullable=True)
    is_encrypted = db.Column(db.Boolean, default=False)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    updated_by = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=True)

    def to_dict(self):
        return {
            'key': self.key,
            'value': self.value if not self.is_encrypted else '***ENCRYPTED***',
            'category': self.category,
            'description': self.description,
            'updated_at': self.updated_at.isoformat() if self.updated_at else None
        }

class AlertLog(db.Model):
    """Log of email alerts sent"""
    __tablename__ = 'alert_logs'

    id = db.Column(db.Integer, primary_key=True)
    organization_id = db.Column(db.Integer, db.ForeignKey('organizations.id'), nullable=False, index=True)
    alert_type = db.Column(db.String(50), nullable=False, index=True)  # 'critical_cve', 'ransomware', 'new_cve'
    matches_count = db.Column(db.Integer, default=0)
    recipients_count = db.Column(db.Integer, default=0)
    status = db.Column(db.String(20), nullable=False, index=True)  # 'success', 'failed', 'skipped'
    error_message = db.Column(db.Text, nullable=True)
    sent_at = db.Column(db.DateTime, default=datetime.utcnow, index=True)

    # Relationships
    organization = db.relationship('Organization', backref='alert_logs')

    def to_dict(self):
        return {
            'id': self.id,
            'organization_id': self.organization_id,
            'alert_type': self.alert_type,
            'matches_count': self.matches_count,
            'recipients_count': self.recipients_count,
            'status': self.status,
            'error_message': self.error_message,
            'sent_at': self.sent_at.isoformat() if self.sent_at else None
        }
