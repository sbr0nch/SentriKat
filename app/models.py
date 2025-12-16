from datetime import datetime, date
from app import db
from werkzeug.security import generate_password_hash, check_password_hash
import json

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
            'smtp_configured': bool(self.smtp_host and self.smtp_from_email),
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
    organization = db.relationship('Organization', backref='products')
    catalog_entry = db.relationship('ServiceCatalog', backref='deployed_instances')

    def to_dict(self):
        return {
            'id': self.id,
            'organization_id': self.organization_id,
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
        return {
            'id': self.id,
            'vendor': self.vendor,
            'product_name': self.product_name,
            'category': self.category,
            'subcategory': self.subcategory,
            'common_names': json.loads(self.common_names) if self.common_names else [],
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
    password_hash = db.Column(db.String(255), nullable=True)  # NULL for LDAP users

    # Organization assignment
    organization_id = db.Column(db.Integer, db.ForeignKey('organizations.id'), nullable=True, index=True)

    # Authentication type
    auth_type = db.Column(db.String(20), default='local')  # 'local', 'ldap'
    ldap_dn = db.Column(db.String(500), nullable=True)  # LDAP Distinguished Name

    # Permissions
    is_admin = db.Column(db.Boolean, default=False)
    is_active = db.Column(db.Boolean, default=True, index=True)
    can_manage_products = db.Column(db.Boolean, default=True)
    can_view_all_orgs = db.Column(db.Boolean, default=False)  # Super admin

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

    def to_dict(self):
        return {
            'id': self.id,
            'username': self.username,
            'email': self.email,
            'organization_id': self.organization_id,
            'auth_type': self.auth_type,
            'is_admin': self.is_admin,
            'is_active': self.is_active,
            'can_manage_products': self.can_manage_products,
            'can_view_all_orgs': self.can_view_all_orgs,
            'last_login': self.last_login.isoformat() if self.last_login else None,
            'created_at': self.created_at.isoformat() if self.created_at else None
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
