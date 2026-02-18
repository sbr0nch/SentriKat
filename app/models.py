from datetime import datetime, date
from app import db
from werkzeug.security import generate_password_hash, check_password_hash
import json

# Association table for many-to-many relationship between products and organizations
product_organizations = db.Table('product_organizations',
    db.Column('product_id', db.Integer, db.ForeignKey('products.id', ondelete='CASCADE'), primary_key=True),
    db.Column('organization_id', db.Integer, db.ForeignKey('organizations.id', ondelete='CASCADE'), primary_key=True),
    db.Column('assigned_at', db.DateTime, default=datetime.utcnow)
)

# Association table for many-to-many relationship between agent API keys and organizations
agent_api_key_organizations = db.Table('agent_api_key_organizations',
    db.Column('api_key_id', db.Integer, db.ForeignKey('agent_api_keys.id', ondelete='CASCADE'), primary_key=True),
    db.Column('organization_id', db.Integer, db.ForeignKey('organizations.id', ondelete='CASCADE'), primary_key=True),
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
    organization_id = db.Column(db.Integer, db.ForeignKey('organizations.id', ondelete='CASCADE'), nullable=False, index=True)
    role = db.Column(db.String(20), default='user', nullable=False)  # super_admin, org_admin, manager, user

    # Metadata
    assigned_at = db.Column(db.DateTime, default=datetime.utcnow)
    assigned_by = db.Column(db.Integer, db.ForeignKey('users.id', ondelete='SET NULL'), nullable=True)

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
    alert_on_low_confidence = db.Column(db.Boolean, default=False)  # Include LOW confidence matches in alerts (default: skip)
    alert_time_start = db.Column(db.String(5), default='08:00')  # HH:MM format
    alert_time_end = db.Column(db.String(5), default='18:00')    # HH:MM format
    alert_days = db.Column(db.String(50), default='mon,tue,wed,thu,fri')  # Comma-separated days

    # Alert Mode Settings (null = use global default)
    # Modes: 'new_only' (only new CVEs), 'daily_reminder' (all unack'd due <=7d), 'escalation' (re-alert at X days)
    alert_mode = db.Column(db.String(20), nullable=True)  # null = use global default
    escalation_days = db.Column(db.Integer, nullable=True)  # Days before due to escalate (null = use global, default 3)

    # Webhook Settings (per organization - takes priority over global)
    webhook_enabled = db.Column(db.Boolean, default=False)
    webhook_url = db.Column(db.String(500), nullable=True)
    webhook_name = db.Column(db.String(100), default='Organization Webhook')
    webhook_format = db.Column(db.String(50), default='slack')  # slack, discord, teams, rocketchat, custom
    webhook_token = db.Column(db.String(500), nullable=True)  # Optional auth token

    # Agent Product Settings
    agent_require_approval = db.Column(db.Boolean, default=False)  # Require admin approval for agent-added products
    agent_stale_threshold_days = db.Column(db.Integer, default=30)  # Days before agent is considered stale
    product_stale_threshold_days = db.Column(db.Integer, default=90)  # Days before product auto-disables

    # Metadata
    active = db.Column(db.Boolean, default=True, index=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    def to_dict(self):
        # Count active users in this organization
        user_count = User.query.filter_by(organization_id=self.id, is_active=True).count()

        # Safely parse notification_emails JSON
        try:
            notification_emails = json.loads(self.notification_emails) if self.notification_emails else []
        except (json.JSONDecodeError, TypeError):
            notification_emails = []

        return {
            'id': self.id,
            'name': self.name,
            'display_name': self.display_name,
            'description': self.description,
            'notification_emails': notification_emails,
            'alert_settings': {
                'critical': self.alert_on_critical,
                'high': self.alert_on_high,
                'new_cve': self.alert_on_new_cve,
                'ransomware': self.alert_on_ransomware,
                'low_confidence': self.alert_on_low_confidence,  # Include low-confidence matches
                'time_start': self.alert_time_start,
                'time_end': self.alert_time_end,
                'days': self.alert_days,
                'mode': self.alert_mode,  # null = use global default
                'escalation_days': self.escalation_days
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
            'alert_on_low_confidence': self.alert_on_low_confidence,
            # Webhook settings (decrypt URL for editing)
            'webhook_enabled': self.webhook_enabled,
            'webhook_url': self._decrypt_webhook_url(),
            'webhook_name': self.webhook_name,
            'webhook_format': self.webhook_format,
            'webhook_token': '********' if self.webhook_token else '',  # Mask token
            'webhook_configured': bool(self.webhook_enabled and self.webhook_url),
            'user_count': user_count,
            'active': self.active,
            'created_at': self.created_at.isoformat() if self.created_at else None,
            'is_default': self.name == 'default'  # Flag for UI to prevent deletion
        }

    def _decrypt_webhook_url(self):
        """Decrypt webhook URL for display/editing"""
        if not self.webhook_url:
            return None
        try:
            from app.encryption import decrypt_value, is_encrypted
            if is_encrypted(self.webhook_url):
                return decrypt_value(self.webhook_url)
            return self.webhook_url
        except Exception:
            return self.webhook_url

    def get_webhook_config(self):
        """Return webhook configuration dictionary with decrypted values"""
        webhook_url = self.webhook_url
        webhook_token = self.webhook_token

        # Decrypt values if encrypted
        try:
            from app.encryption import decrypt_value, is_encrypted
            if webhook_url and is_encrypted(webhook_url):
                webhook_url = decrypt_value(webhook_url)
            if webhook_token and is_encrypted(webhook_token):
                webhook_token = decrypt_value(webhook_token)
        except Exception:
            pass

        return {
            'enabled': self.webhook_enabled,
            'url': webhook_url,
            'name': self.webhook_name,
            'format': self.webhook_format,
            'token': webhook_token
        }

    def get_smtp_config(self):
        """Return SMTP configuration dictionary with decrypted password"""
        password = self.smtp_password

        # Decrypt password if it's encrypted
        if password:
            try:
                from app.encryption import decrypt_value, is_encrypted
                if is_encrypted(password):
                    password = decrypt_value(password)
            except Exception:
                # If decryption fails, return raw value (might be legacy plaintext)
                pass

        return {
            'host': self.smtp_host,
            'port': self.smtp_port,
            'username': self.smtp_username,
            'password': password,
            'use_tls': self.smtp_use_tls,
            'use_ssl': self.smtp_use_ssl,
            'from_email': self.smtp_from_email,
            'from_name': self.smtp_from_name
        }

    def get_effective_alert_mode(self):
        """
        Get the effective alert mode for this organization.
        Uses org-specific setting if set, otherwise falls back to global default.

        Returns dict with:
            - mode: 'new_only', 'daily_reminder', or 'escalation'
            - escalation_days: int (only relevant for escalation mode)
        """
        from app.settings_api import get_setting

        # Get org-specific or global default
        mode = self.alert_mode
        if not mode:
            mode = get_setting('default_alert_mode', 'daily_reminder')

        escalation_days = self.escalation_days
        if escalation_days is None:
            escalation_days = int(get_setting('default_escalation_days', '3') or '3')

        return {
            'mode': mode,
            'escalation_days': escalation_days
        }


class Product(db.Model):
    """Software/service inventory managed by admins"""
    __tablename__ = 'products'

    id = db.Column(db.Integer, primary_key=True)
    organization_id = db.Column(db.Integer, db.ForeignKey('organizations.id', ondelete='CASCADE'), nullable=True, index=True)  # NULL for migration compatibility
    service_catalog_id = db.Column(db.Integer, db.ForeignKey('service_catalog.id'), nullable=True, index=True)  # Optional link to catalog
    vendor = db.Column(db.String(200), nullable=False, index=True)
    product_name = db.Column(db.String(200), nullable=False, index=True)
    version = db.Column(db.String(100), nullable=True)
    keywords = db.Column(db.Text, nullable=True)  # Comma-separated additional keywords
    description = db.Column(db.Text, nullable=True)
    active = db.Column(db.Boolean, default=True, index=True)
    criticality = db.Column(db.String(20), default='medium')  # critical, high, medium, low
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    # CPE (Common Platform Enumeration) fields for precise vulnerability matching
    cpe_vendor = db.Column(db.String(200), nullable=True, index=True)  # NVD CPE vendor identifier
    cpe_product = db.Column(db.String(200), nullable=True, index=True)  # NVD CPE product identifier
    cpe_uri = db.Column(db.String(500), nullable=True)  # Full CPE 2.3 URI (optional)
    match_type = db.Column(db.String(20), default='auto')  # auto, cpe, keyword, both

    # Agent product queue fields - for approval workflow
    source = db.Column(db.String(20), default='manual', index=True)  # manual, agent
    approval_status = db.Column(db.String(20), default='approved', index=True)  # approved, pending, rejected
    pending_since = db.Column(db.DateTime, nullable=True)  # When added to queue
    reviewed_by = db.Column(db.Integer, db.ForeignKey('users.id', ondelete='SET NULL'), nullable=True)  # Who approved/rejected
    reviewed_at = db.Column(db.DateTime, nullable=True)  # When approved/rejected
    rejection_reason = db.Column(db.String(500), nullable=True)  # Why rejected

    # Auto-disable tracking
    last_agent_report = db.Column(db.DateTime, nullable=True, index=True)  # Last time an agent reported this product
    auto_disabled = db.Column(db.Boolean, default=False)  # Was disabled due to no agent reports

    # Composite indexes for common query patterns
    __table_args__ = (
        db.Index('idx_product_org_active', 'organization_id', 'active'),
        db.Index('idx_product_vendor_name', 'vendor', 'product_name'),
        db.Index('idx_product_approval', 'approval_status', 'source'),
    )

    # Relationships
    organization = db.relationship('Organization', backref='products')  # Legacy single org (deprecated)
    organizations = db.relationship('Organization', secondary=product_organizations, backref='assigned_products', lazy='dynamic')  # Multi-org support
    catalog_entry = db.relationship('ServiceCatalog', backref='deployed_instances')

    def get_effective_cpe(self):
        """
        Get effective CPE identifiers, checking product fields first, then catalog entry.
        Returns: (cpe_vendor, cpe_product, cpe_uri) tuple
        """
        # Product-level CPE takes precedence
        if self.cpe_vendor and self.cpe_product:
            return self.cpe_vendor, self.cpe_product, self.cpe_uri

        # Fall back to catalog entry CPE
        if self.catalog_entry:
            return (
                self.catalog_entry.cpe_vendor,
                self.catalog_entry.cpe_product,
                None  # Catalog entries don't have full URI
            )

        return None, None, None

    def has_cpe(self):
        """Check if this product has CPE identifiers configured."""
        cpe_vendor, cpe_product, _ = self.get_effective_cpe()
        return bool(cpe_vendor and cpe_product)

    def get_platform_summary(self):
        """
        Get a summary of which platforms this product is installed on.
        Returns dict with platform counts and list.
        """
        from sqlalchemy import func

        # Query installation counts by platform
        platform_counts = db.session.query(
            ProductInstallation.detected_on_os,
            func.count(ProductInstallation.id)
        ).filter(
            ProductInstallation.product_id == self.id
        ).group_by(
            ProductInstallation.detected_on_os
        ).all()

        platforms = {}
        for platform, count in platform_counts:
            platform_name = platform or 'unknown'
            platforms[platform_name] = count

        return {
            'platforms': platforms,
            'platform_list': list(platforms.keys()),
            'total_installations': sum(platforms.values())
        }

    def to_dict(self, include_platforms=False):
        # Get assigned organizations
        assigned_orgs = [{'id': org.id, 'name': org.name, 'display_name': org.display_name}
                         for org in self.organizations.all()]

        # Include legacy organization_id for backwards compatibility
        if self.organization_id and not assigned_orgs:
            # If using legacy single org, add it to the list
            if self.organization:
                assigned_orgs = [{'id': self.organization.id, 'name': self.organization.name, 'display_name': self.organization.display_name}]

        # Get effective CPE (product-level or from catalog)
        eff_cpe_vendor, eff_cpe_product, eff_cpe_uri = self.get_effective_cpe()

        # Get platforms from installations (lightweight query)
        platforms = db.session.query(ProductInstallation.detected_on_os).filter(
            ProductInstallation.product_id == self.id,
            ProductInstallation.detected_on_os.isnot(None)
        ).distinct().all()
        platform_list = sorted(set(p[0] for p in platforms if p[0]))

        result = {
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
            'criticality': self.criticality or 'medium',
            'platforms': platform_list,  # OS platforms detected on (Windows, Linux, macOS)
            'created_at': self.created_at.isoformat() if self.created_at else None,
            'updated_at': self.updated_at.isoformat() if self.updated_at else None,
            # CPE fields
            'cpe_vendor': self.cpe_vendor,
            'cpe_product': self.cpe_product,
            'cpe_uri': self.cpe_uri,
            'match_type': self.match_type or 'auto',
            # Effective CPE (resolved from product or catalog)
            'effective_cpe_vendor': eff_cpe_vendor,
            'effective_cpe_product': eff_cpe_product,
            'effective_cpe_uri': eff_cpe_uri,
            'has_cpe': self.has_cpe()
        }

        # Optionally include platform summary (extra query)
        if include_platforms:
            result['platform_summary'] = self.get_platform_summary()

        return result


class ProductExclusion(db.Model):
    """
    Products excluded from agent scanning.
    When a product is deleted with "exclude from future scans", it's added here.
    Agents check this list before adding products to prevent re-adding deleted items.
    """
    __tablename__ = 'product_exclusions'

    id = db.Column(db.Integer, primary_key=True)
    organization_id = db.Column(db.Integer, db.ForeignKey('organizations.id', ondelete='CASCADE'), nullable=False, index=True)
    vendor = db.Column(db.String(200), nullable=False, index=True)
    product_name = db.Column(db.String(200), nullable=False, index=True)
    version = db.Column(db.String(100), nullable=True)  # NULL = exclude all versions
    reason = db.Column(db.Text, nullable=True)  # Why this was excluded
    excluded_by = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    # Unique constraint: one exclusion per vendor/product/version per org
    __table_args__ = (
        db.UniqueConstraint('organization_id', 'vendor', 'product_name', 'version', name='unique_product_exclusion'),
    )

    # Relationships
    organization = db.relationship('Organization', backref=db.backref('product_exclusions', lazy='dynamic'))
    excluded_by_user = db.relationship('User', backref='product_exclusions_created')

    def to_dict(self):
        return {
            'id': self.id,
            'organization_id': self.organization_id,
            'organization_name': self.organization.display_name if self.organization else None,
            'vendor': self.vendor,
            'product_name': self.product_name,
            'version': self.version,
            'reason': self.reason,
            'excluded_by': self.excluded_by_user.username if self.excluded_by_user else None,
            'created_at': self.created_at.isoformat() if self.created_at else None
        }

    @staticmethod
    def is_excluded(organization_id, vendor, product_name, version=None):
        """
        Check if a product is excluded for an organization.
        Checks for exact match first, then version-agnostic exclusion.
        """
        # Check exact match with version
        if version:
            exact = ProductExclusion.query.filter_by(
                organization_id=organization_id,
                vendor=vendor,
                product_name=product_name,
                version=version
            ).first()
            if exact:
                return True

        # Check version-agnostic exclusion (version=NULL means all versions)
        any_version = ProductExclusion.query.filter_by(
            organization_id=organization_id,
            vendor=vendor,
            product_name=product_name,
            version=None
        ).first()
        return any_version is not None


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
    cvss_source = db.Column(db.String(30), nullable=True)  # Source of CVSS data: nvd, cve_org, euvd
    source = db.Column(db.String(20), nullable=True, default='cisa_kev')  # Origin: cisa_kev, euvd
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    # CPE data from NVD (cached for better matching)
    cpe_data = db.Column(db.Text, nullable=True)  # JSON array of affected CPE entries
    cpe_fetched_at = db.Column(db.DateTime, nullable=True)  # When CPE data was last fetched
    nvd_status = db.Column(db.String(50), nullable=True)  # NVD vulnStatus: Awaiting Analysis, Analyzed, etc.

    # Actively exploited flag — set when CVE originates from CISA KEV,
    # ENISA EUVD exploited feed, or has EPSS >= 0.95.  Drives priority
    # routing: actively-exploited CVEs trigger immediate alerts regardless
    # of the organization's normal alert cadence.
    is_actively_exploited = db.Column(db.Boolean, default=False, index=True)

    # EPSS (Exploit Prediction Scoring System) data from FIRST
    # Score: Probability of exploitation in the next 30 days (0-1)
    # Percentile: How this CVE ranks compared to all other CVEs (0-1)
    epss_score = db.Column(db.Float, nullable=True, index=True)
    epss_percentile = db.Column(db.Float, nullable=True)
    epss_fetched_at = db.Column(db.DateTime, nullable=True)

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

        # Known ransomware campaign = Always Critical (small set, always urgent)
        if self.known_ransomware:
            return 'critical'

        # Actively exploited (CISA KEV, EUVD exploited) = ELEVATE by one level.
        # Previously this forced everything to 'critical', which inflated the
        # critical count because most monitored CVEs come from CISA KEV.
        # Now: CRITICAL stays CRITICAL, HIGH→CRITICAL, MEDIUM→HIGH, LOW→MEDIUM.
        # The 'ACTIVELY EXPLOITED' badge still provides visual urgency.
        if self.is_actively_exploited:
            current_level = min(current_level + 1, priority_order['critical'])

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

    @property
    def is_zero_day(self):
        """Determine if this CVE qualifies as a zero-day detected by our system.

        A zero-day in our context means: we detected it via NVD or EUVD
        BEFORE CISA KEV published it. Indicators:
        - source is 'nvd' or 'euvd' (not yet confirmed by CISA KEV)
        - OR source is 'cisa_kev+euvd' (we had it from EUVD before KEV caught up)
        - AND it is actively exploited or has HIGH/CRITICAL severity with
              NVD status still in pre-analysis state
        """
        src = self.source or ''
        # If we got it from EUVD (alone or before KEV caught up), it's a zero-day
        if src in ('euvd', 'cisa_kev+euvd'):
            return True
        # If we got it from NVD while it's still unanalyzed — we caught it early
        if src == 'nvd' and self.nvd_status in ('Awaiting Analysis', 'Received', 'Undergoing Analysis'):
            return True
        return False

    @property
    def nvd_data_incomplete(self):
        """True when NVD hasn't finished analyzing this CVE yet."""
        return self.nvd_status in ('Awaiting Analysis', 'Received', 'Undergoing Analysis')

    def get_cpe_entries(self):
        """Get parsed CPE data if available."""
        if not self.cpe_data:
            return []
        try:
            return json.loads(self.cpe_data)
        except (json.JSONDecodeError, TypeError):
            return []

    def set_cpe_entries(self, entries):
        """Set CPE data from a list of CPE entries."""
        if entries:
            self.cpe_data = json.dumps(entries)
            self.cpe_fetched_at = datetime.utcnow()
        else:
            self.cpe_data = None
            self.cpe_fetched_at = None

    def has_cpe_data(self):
        """Check if CPE data is available."""
        return bool(self.cpe_data)

    def get_fix_versions(self):
        """Extract fix version info from CPE data.

        Returns a list of dicts with vendor, product, and the version that
        resolves the vulnerability (versionEndExcluding or versionEndIncluding).
        """
        entries = self.get_cpe_entries()
        fix_versions = []
        seen = set()
        for entry in entries:
            version_end = entry.get('version_end')
            version_end_type = entry.get('version_end_type')
            if not version_end:
                continue
            vendor = entry.get('vendor', self.vendor_project or '')
            product = entry.get('product', self.product or '')
            key = f"{vendor}|{product}|{version_end}"
            if key in seen:
                continue
            seen.add(key)
            fix_versions.append({
                'vendor': vendor,
                'product': product,
                'fix_version': version_end,
                'fix_type': version_end_type,  # 'excluding' means upgrade to this version; 'including' means upgrade past this version
                'version_start': entry.get('version_start'),
                'version_start_type': entry.get('version_start_type'),
            })
        return fix_versions

    def to_dict(self):
        fix_versions = self.get_fix_versions()
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
            'cvss_source': self.cvss_source,
            'source': self.source or 'cisa_kev',
            'is_actively_exploited': bool(self.is_actively_exploited),
            'priority': self.calculate_priority(),
            'days_old': (date.today() - self.date_added).days if self.date_added else None,
            'has_cpe_data': self.has_cpe_data(),
            'cpe_fetched_at': self.cpe_fetched_at.isoformat() if self.cpe_fetched_at else None,
            # EPSS (Exploit Prediction Scoring System)
            'epss_score': self.epss_score,
            'epss_percentile': self.epss_percentile,
            'epss_fetched_at': self.epss_fetched_at.isoformat() if self.epss_fetched_at else None,
            # Fix version info from NVD CPE data
            'fix_versions': fix_versions,
            'has_fix_version': len(fix_versions) > 0,
            # Zero-day & NVD status indicators
            'is_zero_day': self.is_zero_day,
            'nvd_status': self.nvd_status,
            'nvd_data_incomplete': self.nvd_data_incomplete,
        }

class VulnerabilityMatch(db.Model):
    """Matched vulnerabilities for tracked products"""
    __tablename__ = 'vulnerability_matches'

    id = db.Column(db.Integer, primary_key=True)
    product_id = db.Column(db.Integer, db.ForeignKey('products.id', ondelete='CASCADE'), nullable=False, index=True)
    vulnerability_id = db.Column(db.Integer, db.ForeignKey('vulnerabilities.id', ondelete='CASCADE'), nullable=False, index=True)
    match_reason = db.Column(db.String(200), nullable=True)  # Why it matched (vendor, product, keyword)
    acknowledged = db.Column(db.Boolean, default=False, index=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    # Notification tracking - for "new CVE" alerts
    # NULL = never alerted, set when first alert is sent
    # Reset to NULL when CVE is reopened (unacknowledged) to re-alert
    first_alerted_at = db.Column(db.DateTime, nullable=True, index=True)

    # Snooze feature - temporarily suppress alerts until this datetime
    # NULL = not snoozed, set when user clicks "Remind me later"
    snoozed_until = db.Column(db.DateTime, nullable=True, index=True)

    # Match method and confidence
    match_method = db.Column(db.String(20), default='keyword')  # cpe, keyword, vendor_product
    match_confidence = db.Column(db.String(20), default='medium')  # high (CPE), medium (vendor+product), low (keyword)

    # Auto-acknowledge tracking
    auto_acknowledged = db.Column(db.Boolean, default=False)  # True if auto-ack'd (not manual)
    resolution_reason = db.Column(db.String(50), nullable=True)  # manual, software_removed, version_upgraded, vendor_fix
    acknowledged_at = db.Column(db.DateTime, nullable=True)  # When it was acknowledged
    # Vendor fix confidence: 'high' = verified with distro comparison, 'medium' = needs manual verification
    vendor_fix_confidence = db.Column(db.String(20), nullable=True)  # high, medium (only set when resolution_reason='vendor_fix')

    # Composite indexes for common query patterns
    __table_args__ = (
        db.Index('idx_match_product_ack', 'product_id', 'acknowledged'),
        db.Index('idx_match_vuln_ack', 'vulnerability_id', 'acknowledged'),
    )

    product = db.relationship('Product', backref=db.backref('matches', cascade='all, delete-orphan'))
    vulnerability = db.relationship('Vulnerability', backref=db.backref('matches', cascade='all, delete-orphan'))

    def calculate_effective_priority(self):
        """
        Returns the CVE severity directly.

        Previously this combined CVE severity with product criticality,
        but that was confusing. Now we just use the CVE's severity.

        Returns: critical, high, medium, low (based on CVE's CVSS score)
        """
        return self.vulnerability.calculate_priority()

    def to_dict(self):
        vuln_dict = self.vulnerability.to_dict()
        product_dict = self.product.to_dict()

        return {
            'id': self.id,
            'product': product_dict,
            'vulnerability': vuln_dict,
            'match_reason': self.match_reason,
            'match_method': self.match_method or 'keyword',
            'match_confidence': self.match_confidence or 'medium',
            'acknowledged': self.acknowledged,
            'auto_acknowledged': self.auto_acknowledged,
            'resolution_reason': self.resolution_reason,
            'vendor_fix_confidence': self.vendor_fix_confidence,
            'acknowledged_at': self.acknowledged_at.isoformat() if self.acknowledged_at else None,
            'snoozed_until': self.snoozed_until.isoformat() if self.snoozed_until else None,
            'created_at': self.created_at.isoformat() if self.created_at else None,
            'effective_priority': self.calculate_effective_priority()
        }


class VendorFixOverride(db.Model):
    """
    Tracks vendor patches that fix CVEs without changing the product version.

    This solves the "Path B" problem: when a vendor patches v3.3 in-place
    (backport fix), the NVD CPE data still says 3.2-3.3 are affected.
    This override tells SentriKat that a specific version is actually safe
    for a specific CVE, despite what the CPE range says.
    """
    __tablename__ = 'vendor_fix_overrides'

    id = db.Column(db.Integer, primary_key=True)
    cve_id = db.Column(db.String(20), nullable=False, index=True)
    vendor = db.Column(db.String(255), nullable=False)
    product = db.Column(db.String(255), nullable=False)

    # The version that was patched in-place
    fixed_version = db.Column(db.String(100), nullable=False)

    # Evidence / justification
    fix_type = db.Column(db.String(50), nullable=False, default='backport_patch')  # backport_patch, hotfix, config_mitigation
    vendor_advisory_url = db.Column(db.Text, nullable=True)
    vendor_advisory_id = db.Column(db.String(100), nullable=True)
    patch_identifier = db.Column(db.String(255), nullable=True)
    notes = db.Column(db.Text, nullable=True)

    # Audit trail
    created_by = db.Column(db.Integer, db.ForeignKey('users.id', ondelete='SET NULL'), nullable=True)
    approved_by = db.Column(db.Integer, db.ForeignKey('users.id', ondelete='SET NULL'), nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    approved_at = db.Column(db.DateTime, nullable=True)
    status = db.Column(db.String(20), default='approved', nullable=False)  # pending, approved, rejected

    # Confidence tier: how reliable is this override?
    # 'high' = distro-native comparison (dpkg/rpm/apk) with agent-reported distro_package_version
    # 'medium' = generic comparison, or no distro_package_version from agent, or vendor "not affected" statement
    confidence = db.Column(db.String(20), default='medium', nullable=False)
    confidence_reason = db.Column(db.String(255), nullable=True)  # Human-readable explanation

    # Scope
    organization_id = db.Column(db.Integer, db.ForeignKey('organizations.id', ondelete='CASCADE'), nullable=True)

    __table_args__ = (
        db.Index('idx_vendor_fix_lookup', 'cve_id', 'vendor', 'product', 'fixed_version'),
    )

    creator = db.relationship('User', foreign_keys=[created_by])
    approver = db.relationship('User', foreign_keys=[approved_by])
    organization = db.relationship('Organization', backref=db.backref('vendor_fix_overrides', lazy='dynamic'))

    def to_dict(self):
        return {
            'id': self.id,
            'cve_id': self.cve_id,
            'vendor': self.vendor,
            'product': self.product,
            'fixed_version': self.fixed_version,
            'fix_type': self.fix_type,
            'vendor_advisory_url': self.vendor_advisory_url,
            'vendor_advisory_id': self.vendor_advisory_id,
            'patch_identifier': self.patch_identifier,
            'notes': self.notes,
            'created_by': self.creator.username if self.creator else None,
            'approved_by': self.approver.username if self.approver else None,
            'created_at': self.created_at.isoformat() if self.created_at else None,
            'approved_at': self.approved_at.isoformat() if self.approved_at else None,
            'status': self.status,
            'confidence': self.confidence or 'medium',
            'confidence_reason': self.confidence_reason,
            'organization_id': self.organization_id,
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
    organization_id = db.Column(db.Integer, db.ForeignKey('organizations.id', ondelete='CASCADE'), nullable=True, index=True)

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

    # Failed login tracking
    failed_login_attempts = db.Column(db.Integer, default=0)
    locked_until = db.Column(db.DateTime, nullable=True)

    # Password expiration
    password_changed_at = db.Column(db.DateTime, default=datetime.utcnow)
    must_change_password = db.Column(db.Boolean, default=False)

    # Two-Factor Authentication
    totp_secret = db.Column(db.String(32), nullable=True)
    totp_enabled = db.Column(db.Boolean, default=False)
    totp_required = db.Column(db.Boolean, default=False)  # Admin can require 2FA setup

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

    def is_locked(self):
        """Check if account is locked due to failed login attempts"""
        if self.locked_until is None:
            return False
        return datetime.utcnow() < self.locked_until

    def get_lockout_remaining_minutes(self):
        """Get remaining lockout time in minutes"""
        if not self.is_locked():
            return 0
        remaining = (self.locked_until - datetime.utcnow()).total_seconds() / 60
        return max(0, int(remaining) + 1)  # Round up

    def record_failed_login(self):
        """Record a failed login attempt and lock if threshold reached"""
        from app.models import SystemSettings

        # Get lockout settings
        # Note: setting key is 'max_failed_logins' (as saved by security settings API)
        max_attempts_setting = SystemSettings.query.filter_by(key='max_failed_logins').first()
        lockout_duration_setting = SystemSettings.query.filter_by(key='lockout_duration').first()

        max_attempts = int(max_attempts_setting.value) if max_attempts_setting else 5
        lockout_minutes = int(lockout_duration_setting.value) if lockout_duration_setting else 30

        # Increment failed attempts
        self.failed_login_attempts = (self.failed_login_attempts or 0) + 1

        # Lock if threshold reached
        if self.failed_login_attempts >= max_attempts:
            from datetime import timedelta
            self.locked_until = datetime.utcnow() + timedelta(minutes=lockout_minutes)

    def reset_failed_login_attempts(self):
        """Reset failed login counter on successful login"""
        self.failed_login_attempts = 0
        self.locked_until = None

    def is_password_expired(self):
        """Check if password has expired based on settings"""
        if self.auth_type != 'local':
            return False  # LDAP handles its own expiration

        if self.must_change_password:
            return True

        # Get expiration setting
        expiry_setting = SystemSettings.query.filter_by(key='password_expiry_days').first()
        expiry_days = int(expiry_setting.value) if expiry_setting else 0

        if expiry_days <= 0:
            return False  # Password expiration disabled

        if not self.password_changed_at:
            return True  # Never set, force change

        from datetime import timedelta
        expiry_date = self.password_changed_at + timedelta(days=expiry_days)
        return datetime.utcnow() > expiry_date

    def get_password_days_until_expiry(self):
        """Get number of days until password expires"""
        if self.auth_type != 'local':
            return None

        expiry_setting = SystemSettings.query.filter_by(key='password_expiry_days').first()
        expiry_days = int(expiry_setting.value) if expiry_setting else 0

        if expiry_days <= 0:
            return None  # Never expires

        if not self.password_changed_at:
            return 0

        from datetime import timedelta
        expiry_date = self.password_changed_at + timedelta(days=expiry_days)
        remaining = (expiry_date - datetime.utcnow()).days
        return max(0, remaining)

    def update_password(self, new_password):
        """Update password and reset expiration timer"""
        self.set_password(new_password)
        self.password_changed_at = datetime.utcnow()
        self.must_change_password = False

    def setup_totp(self):
        """Generate a new TOTP secret for 2FA setup"""
        import secrets
        import base64
        # Generate 20 random bytes and encode as base32
        secret_bytes = secrets.token_bytes(20)
        self.totp_secret = base64.b32encode(secret_bytes).decode('utf-8')
        return self.totp_secret

    def get_totp_uri(self, app_name='SentriKat'):
        """Get the TOTP URI for QR code generation"""
        if not self.totp_secret:
            return None
        from urllib.parse import quote
        return f'otpauth://totp/{quote(app_name)}:{quote(self.email)}?secret={self.totp_secret}&issuer={quote(app_name)}'

    def verify_totp(self, code):
        """Verify a TOTP code"""
        if not self.totp_secret:
            return False
        try:
            import hmac
            import struct
            import time
            import base64
            import hashlib

            # Decode the secret
            key = base64.b32decode(self.totp_secret, casefold=True)

            # Get the current time step (30-second window)
            counter = int(time.time()) // 30

            # Check current and adjacent time windows for clock skew
            for offset in range(-1, 2):
                check_counter = counter + offset
                # Generate TOTP
                counter_bytes = struct.pack('>Q', check_counter)
                hmac_hash = hmac.new(key, counter_bytes, hashlib.sha1).digest()
                offset_val = hmac_hash[-1] & 0x0f
                truncated = struct.unpack('>I', hmac_hash[offset_val:offset_val + 4])[0]
                totp_code = (truncated & 0x7fffffff) % 1000000

                if str(totp_code).zfill(6) == str(code).zfill(6):
                    return True

            return False
        except Exception:
            return False

    def enable_totp(self):
        """Enable 2FA after verification"""
        if self.totp_secret:
            self.totp_enabled = True

    def disable_totp(self):
        """Disable 2FA"""
        self.totp_secret = None
        self.totp_enabled = False

    @staticmethod
    def validate_password_policy(password):
        """
        Validate password against policy settings.
        Returns (is_valid, error_message)
        Only applies to local users.
        """
        # Get policy settings
        min_length = SystemSettings.query.filter_by(key='password_min_length').first()
        req_upper = SystemSettings.query.filter_by(key='password_require_uppercase').first()
        req_lower = SystemSettings.query.filter_by(key='password_require_lowercase').first()
        req_numbers = SystemSettings.query.filter_by(key='password_require_numbers').first()
        req_special = SystemSettings.query.filter_by(key='password_require_special').first()

        min_len = int(min_length.value) if min_length else 8
        require_upper = req_upper.value == 'true' if req_upper else True
        require_lower = req_lower.value == 'true' if req_lower else True
        require_numbers = req_numbers.value == 'true' if req_numbers else True
        require_special = req_special.value == 'true' if req_special else False

        errors = []

        if len(password) < min_len:
            errors.append(f'Password must be at least {min_len} characters')

        if require_upper and not any(c.isupper() for c in password):
            errors.append('Password must contain at least one uppercase letter')

        if require_lower and not any(c.islower() for c in password):
            errors.append('Password must contain at least one lowercase letter')

        if require_numbers and not any(c.isdigit() for c in password):
            errors.append('Password must contain at least one number')

        if require_special:
            special_chars = '!@#$%^&*()_+-=[]{}|;:,.<>?'
            if not any(c in special_chars for c in password):
                errors.append('Password must contain at least one special character (!@#$%^&*)')

        if errors:
            return False, '; '.join(errors)
        return True, None

    def is_super_admin(self):
        """Check if user is a super admin - only role-based, not legacy flags"""
        return self.role == 'super_admin'

    def is_org_admin(self):
        """Check if user is an organization admin"""
        return self.role in ['super_admin', 'org_admin']

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
            # Lockout info
            'is_locked': self.is_locked(),
            'failed_login_attempts': self.failed_login_attempts or 0,
            'locked_until': self.locked_until.isoformat() if self.locked_until else None,
            # Password expiration
            'password_expired': self.is_password_expired() if self.auth_type == 'local' else False,
            'password_days_until_expiry': self.get_password_days_until_expiry(),
            'must_change_password': self.must_change_password or False,
            # 2FA status
            'totp_enabled': self.totp_enabled or False,
            'totp_required': self.totp_required or False,
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
    updated_by = db.Column(db.Integer, db.ForeignKey('users.id', ondelete='SET NULL'), nullable=True)

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
    organization_id = db.Column(db.Integer, db.ForeignKey('organizations.id', ondelete='CASCADE'), nullable=False, index=True)
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


# ============================================================================
# ASSET MANAGEMENT - For agent-based inventory tracking
# ============================================================================

class Asset(db.Model):
    """
    Represents a server, host, or machine in the infrastructure.
    Assets can have multiple products installed, each with its own version.
    Used for agent-based inventory tracking across multiple deployments.
    """
    __tablename__ = 'assets'

    id = db.Column(db.Integer, primary_key=True)
    organization_id = db.Column(db.Integer, db.ForeignKey('organizations.id', ondelete='CASCADE'), nullable=False, index=True)

    # Identification
    hostname = db.Column(db.String(255), nullable=False, index=True)
    ip_address = db.Column(db.String(45), nullable=True)  # IPv4 or IPv6
    fqdn = db.Column(db.String(500), nullable=True)  # Fully Qualified Domain Name
    asset_type = db.Column(db.String(50), default='server')  # server, workstation, container, appliance, etc.

    # OS Information
    os_name = db.Column(db.String(100), nullable=True)  # Linux, Windows, macOS, etc.
    os_version = db.Column(db.String(100), nullable=True)  # Ubuntu 22.04, Windows Server 2022, etc.
    os_kernel = db.Column(db.String(100), nullable=True)  # Kernel version

    # Agent Information
    agent_id = db.Column(db.String(255), unique=True, nullable=True, index=True)  # Unique agent identifier
    agent_version = db.Column(db.String(50), nullable=True)
    last_checkin = db.Column(db.DateTime, nullable=True)  # Last heartbeat from agent
    last_inventory_at = db.Column(db.DateTime, nullable=True)  # Last successful inventory report

    # Status
    active = db.Column(db.Boolean, default=True, index=True)
    status = db.Column(db.String(20), default='online')  # online, offline, stale, decommissioned

    # Classification & Management
    criticality = db.Column(db.String(20), default='medium')  # critical, high, medium, low
    environment = db.Column(db.String(50), nullable=True)  # production, staging, development, test
    owner = db.Column(db.String(200), nullable=True)  # Contact/owner for this endpoint
    group_name = db.Column(db.String(100), nullable=True, index=True)  # Group/role (web-servers, databases, etc.)

    # Cached vulnerability stats (updated by CVE scan)
    vulnerable_products_count = db.Column(db.Integer, default=0)  # Products with matching CVEs
    total_vulnerabilities = db.Column(db.Integer, default=0)  # Total CVEs affecting this endpoint
    last_vuln_scan_at = db.Column(db.DateTime, nullable=True)  # When vulnerabilities were last calculated

    # Additional info
    description = db.Column(db.Text, nullable=True)
    notes = db.Column(db.Text, nullable=True)  # Admin notes
    tags = db.Column(db.Text, nullable=True)  # JSON array of tags
    metadata_json = db.Column(db.Text, nullable=True)  # JSON for custom fields
    installed_kbs = db.Column(db.Text, nullable=True)  # JSON array of installed KBs (Windows)

    # Agent Command & Control (server-side management)
    pending_scan = db.Column(db.Boolean, default=False)  # True = agent should scan immediately
    scan_interval_override = db.Column(db.Integer, nullable=True)  # Override interval in minutes (null = use agent default)
    pending_scan_requested_at = db.Column(db.DateTime, nullable=True)  # When scan was requested
    pending_scan_requested_by = db.Column(db.String(100), nullable=True)  # Who requested the scan
    pending_update = db.Column(db.Boolean, default=False)  # True = force agent to check for update on next poll
    pending_update_requested_at = db.Column(db.DateTime, nullable=True)
    pending_update_requested_by = db.Column(db.String(100), nullable=True)

    # Timestamps
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    # Relationships
    organization = db.relationship('Organization', backref=db.backref('assets', lazy='dynamic'))
    product_installations = db.relationship('ProductInstallation', backref='asset', cascade='all, delete-orphan', lazy='dynamic')

    # Unique constraint and composite indexes
    __table_args__ = (
        db.UniqueConstraint('organization_id', 'hostname', name='uix_org_hostname'),
        db.Index('idx_asset_org_agent', 'organization_id', 'agent_id'),
        db.Index('idx_asset_org_status', 'organization_id', 'status'),
    )

    def get_tags(self):
        """Get tags as list."""
        if not self.tags:
            return []
        try:
            return json.loads(self.tags)
        except:
            return []

    def set_tags(self, tag_list):
        """Set tags from list."""
        self.tags = json.dumps(tag_list) if tag_list else None

    def get_metadata(self):
        """Get metadata as dict."""
        if not self.metadata_json:
            return {}
        try:
            return json.loads(self.metadata_json)
        except:
            return {}

    def set_metadata(self, data):
        """Set metadata from dict."""
        self.metadata_json = json.dumps(data) if data else None

    def to_dict(self, include_products=False):
        # Calculate last_seen as the most recent of last_checkin or last_inventory_at
        last_seen = None
        if self.last_checkin and self.last_inventory_at:
            last_seen = max(self.last_checkin, self.last_inventory_at)
        elif self.last_checkin:
            last_seen = self.last_checkin
        elif self.last_inventory_at:
            last_seen = self.last_inventory_at

        result = {
            'id': self.id,
            'organization_id': self.organization_id,
            'organization_name': self.organization.display_name if self.organization else None,
            'hostname': self.hostname,
            'ip_address': self.ip_address,
            'fqdn': self.fqdn,
            'asset_type': self.asset_type,
            'os_name': self.os_name,
            'os_version': self.os_version,
            'os_kernel': self.os_kernel,
            'agent_id': self.agent_id,
            'agent_version': self.agent_version,
            'last_seen': last_seen.isoformat() if last_seen else None,
            'last_checkin': self.last_checkin.isoformat() if self.last_checkin else None,
            'last_inventory_at': self.last_inventory_at.isoformat() if self.last_inventory_at else None,
            'active': self.active,
            'status': self.status,
            # Classification & Management
            'criticality': self.criticality,
            'environment': self.environment,
            'owner': self.owner,
            'group_name': self.group_name,
            # Vulnerability stats
            'vulnerable_products_count': self.vulnerable_products_count,
            'total_vulnerabilities': self.total_vulnerabilities,
            'last_vuln_scan_at': self.last_vuln_scan_at.isoformat() if self.last_vuln_scan_at else None,
            # Additional info
            'description': self.description,
            'notes': self.notes,
            'tags': self.get_tags(),
            'metadata': self.get_metadata(),
            'created_at': self.created_at.isoformat() if self.created_at else None,
            'updated_at': self.updated_at.isoformat() if self.updated_at else None,
            'product_count': self.product_installations.count(),
            # Agent Command & Control
            'pending_scan': self.pending_scan or False,
            'scan_interval_override': self.scan_interval_override,
            'pending_scan_requested_at': self.pending_scan_requested_at.isoformat() if self.pending_scan_requested_at else None,
            'pending_update': self.pending_update or False,
            'latest_agent_version': None,  # Set by API layer
        }

        if include_products:
            result['products'] = [pi.to_dict() for pi in self.product_installations.all()]

        return result


class ProductInstallation(db.Model):
    """
    Links an Asset to a Product with version information.
    Represents "nginx version 1.24 is installed on server-1".

    This allows tracking:
    - Which assets have which products
    - Different versions of the same product across different assets
    - Installation discovery history
    """
    __tablename__ = 'product_installations'

    id = db.Column(db.Integer, primary_key=True)
    asset_id = db.Column(db.Integer, db.ForeignKey('assets.id', ondelete='CASCADE'), nullable=False, index=True)
    product_id = db.Column(db.Integer, db.ForeignKey('products.id', ondelete='CASCADE'), nullable=False, index=True)

    # Version on this specific asset (may differ from Product.version)
    version = db.Column(db.String(100), nullable=True)

    # Installation details
    install_path = db.Column(db.String(500), nullable=True)  # Where it's installed
    distro_package_version = db.Column(db.String(200), nullable=True)  # Full distro version e.g. 2.4.52-1ubuntu4.6
    detected_by = db.Column(db.String(50), default='agent')  # agent, manual, scan
    detected_on_os = db.Column(db.String(50), nullable=True, index=True)  # linux, windows, macos, etc.

    # Status
    is_vulnerable = db.Column(db.Boolean, default=False, index=True)  # Cached: has matching CVEs?
    vulnerability_count = db.Column(db.Integer, default=0)  # Cached: how many CVEs?

    # Timestamps
    discovered_at = db.Column(db.DateTime, default=datetime.utcnow)  # When first seen
    last_seen_at = db.Column(db.DateTime, default=datetime.utcnow)  # Last confirmed present
    verified_at = db.Column(db.DateTime, nullable=True)  # Manual verification date

    # Relationships
    product = db.relationship('Product', backref=db.backref('installations', lazy='dynamic'))

    # Unique constraint: one product per asset
    __table_args__ = (
        db.UniqueConstraint('asset_id', 'product_id', name='uix_asset_product'),
    )

    @staticmethod
    def normalize_os_name(os_name):
        """
        Normalize OS name to a standard platform category.
        Used for filtering and display consistency.
        """
        if not os_name:
            return None

        os_lower = os_name.lower()

        # Windows variants
        if 'windows' in os_lower or 'win32' in os_lower or 'win64' in os_lower:
            return 'windows'

        # Linux variants
        if any(x in os_lower for x in ['linux', 'ubuntu', 'debian', 'centos', 'rhel',
                                        'red hat', 'fedora', 'alpine', 'arch', 'suse']):
            return 'linux'

        # macOS variants
        if any(x in os_lower for x in ['macos', 'mac os', 'darwin', 'osx']):
            return 'macos'

        # BSD variants
        if 'bsd' in os_lower:
            return 'bsd'

        # Unix generic
        if 'unix' in os_lower or 'sunos' in os_lower or 'solaris' in os_lower:
            return 'unix'

        # Container/virtualization
        if 'docker' in os_lower or 'container' in os_lower:
            return 'container'

        return 'other'

    def to_dict(self):
        # Get platform from detected_on_os or derive from asset
        platform = self.detected_on_os
        if not platform and self.asset:
            platform = self.normalize_os_name(self.asset.os_name)

        discovered_iso = self.discovered_at.isoformat() if self.discovered_at else None

        return {
            'id': self.id,
            'asset_id': self.asset_id,
            'asset_hostname': self.asset.hostname if self.asset else None,
            'product_id': self.product_id,
            'vendor': self.product.vendor if self.product else None,
            'product_name': self.product.product_name if self.product else None,
            'version': self.version,
            'install_path': self.install_path,
            'detected_by': self.detected_by,
            'detected_on_os': self.detected_on_os,
            'detected_at': discovered_iso,
            'platform': platform,  # Normalized platform (linux, windows, macos, etc.)
            'is_vulnerable': self.is_vulnerable,
            'vulnerability_count': self.vulnerability_count,
            'discovered_at': discovered_iso,
            'last_seen_at': self.last_seen_at.isoformat() if self.last_seen_at else None,
            'verified_at': self.verified_at.isoformat() if self.verified_at else None
        }


class AgentApiKey(db.Model):
    """
    API keys for agent authentication.
    Each organization can have multiple agent API keys.
    Agents use these keys to authenticate when reporting inventory.
    """
    __tablename__ = 'agent_api_keys'

    id = db.Column(db.Integer, primary_key=True)
    organization_id = db.Column(db.Integer, db.ForeignKey('organizations.id', ondelete='CASCADE'), nullable=False, index=True)

    # Key identification
    name = db.Column(db.String(100), nullable=False)  # Friendly name like "Production Agents"
    key_hash = db.Column(db.String(256), nullable=False, unique=True)  # SHA256 hash of the key
    key_prefix = db.Column(db.String(10), nullable=False)  # First 8 chars for identification

    # Permissions & limits
    active = db.Column(db.Boolean, default=True, index=True)
    max_assets = db.Column(db.Integer, nullable=True)  # NULL = unlimited
    allowed_ips = db.Column(db.Text, nullable=True)  # JSON array of allowed IPs/CIDRs
    auto_approve = db.Column(db.Boolean, default=False)  # Auto-add products without Import Queue review

    # Usage tracking
    last_used_at = db.Column(db.DateTime, nullable=True)
    usage_count = db.Column(db.Integer, default=0)

    # Timestamps
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    expires_at = db.Column(db.DateTime, nullable=True)  # NULL = never expires
    created_by = db.Column(db.Integer, db.ForeignKey('users.id', ondelete='SET NULL'), nullable=True)

    # Relationships
    organization = db.relationship('Organization', backref=db.backref('agent_api_keys', lazy='dynamic'))
    creator = db.relationship('User', backref='created_api_keys')
    additional_organizations = db.relationship(
        'Organization',
        secondary='agent_api_key_organizations',
        backref=db.backref('shared_agent_api_keys', lazy='dynamic'),
        lazy='dynamic'
    )

    def get_all_organization_ids(self):
        """Get all organization IDs this key reports to (primary + additional)."""
        org_ids = {self.organization_id}
        for org in self.additional_organizations.all():
            org_ids.add(org.id)
        return list(org_ids)

    def get_all_organizations(self):
        """Get all Organization objects this key reports to."""
        orgs = [self.organization] if self.organization else []
        for org in self.additional_organizations.all():
            if org.id != self.organization_id:
                orgs.append(org)
        return orgs

    @staticmethod
    def generate_key():
        """Generate a new API key."""
        import secrets
        return f"sk_agent_{secrets.token_urlsafe(32)}"

    @staticmethod
    def hash_key(key):
        """Hash an API key for storage."""
        import hashlib
        return hashlib.sha256(key.encode()).hexdigest()

    def is_valid(self):
        """Check if key is still valid (active and not expired)."""
        if not self.active:
            return False
        if self.expires_at and datetime.utcnow() > self.expires_at:
            return False
        return True

    def get_allowed_ips(self):
        """Get allowed IPs as list."""
        if not self.allowed_ips:
            return []
        try:
            return json.loads(self.allowed_ips)
        except:
            return []

    def to_dict(self, include_key=False):
        additional_orgs = []
        try:
            additional_orgs = [
                {'id': org.id, 'name': org.display_name or org.name}
                for org in self.additional_organizations.all()
            ]
        except Exception:
            pass
        all_org_ids = self.get_all_organization_ids()
        result = {
            'id': self.id,
            'organization_id': self.organization_id,
            'organization_name': self.organization.display_name if self.organization else None,
            'name': self.name,
            'key_prefix': self.key_prefix,
            'active': self.active,
            'max_assets': self.max_assets,
            'allowed_ips': self.get_allowed_ips(),
            'auto_approve': self.auto_approve,
            'last_used_at': self.last_used_at.isoformat() if self.last_used_at else None,
            'usage_count': self.usage_count,
            'created_at': self.created_at.isoformat() if self.created_at else None,
            'expires_at': self.expires_at.isoformat() if self.expires_at else None,
            'is_valid': self.is_valid(),
            'additional_organizations': additional_orgs,
            'all_organization_ids': all_org_ids
        }
        return result


class InventoryJob(db.Model):
    """
    Background job queue for processing large inventory reports.
    Allows agents to quickly submit inventory and let the system process it async.
    """
    __tablename__ = 'inventory_jobs'

    id = db.Column(db.Integer, primary_key=True)
    organization_id = db.Column(db.Integer, db.ForeignKey('organizations.id', ondelete='CASCADE'), nullable=False, index=True)
    asset_id = db.Column(db.Integer, db.ForeignKey('assets.id', ondelete='CASCADE'), nullable=True, index=True)
    api_key_id = db.Column(db.Integer, db.ForeignKey('agent_api_keys.id'), nullable=True, index=True)

    # Job details
    job_type = db.Column(db.String(50), default='inventory')  # inventory, sync, import
    status = db.Column(db.String(20), default='pending', index=True)  # pending, processing, completed, failed
    priority = db.Column(db.Integer, default=5)  # 1=highest, 10=lowest

    # Payload (JSON)
    payload = db.Column(db.Text, nullable=True)  # JSON with inventory data
    total_items = db.Column(db.Integer, default=0)  # Total items to process

    # Results
    items_processed = db.Column(db.Integer, default=0)
    items_created = db.Column(db.Integer, default=0)
    items_updated = db.Column(db.Integer, default=0)
    items_failed = db.Column(db.Integer, default=0)
    error_message = db.Column(db.Text, nullable=True)
    retry_count = db.Column(db.Integer, default=0)  # Number of retry attempts after stuck/failed

    # Timestamps
    created_at = db.Column(db.DateTime, default=datetime.utcnow, index=True)
    started_at = db.Column(db.DateTime, nullable=True)
    completed_at = db.Column(db.DateTime, nullable=True)

    # Relationships
    organization = db.relationship('Organization', backref=db.backref('inventory_jobs', lazy='dynamic'))
    asset = db.relationship('Asset', backref=db.backref('inventory_jobs', lazy='dynamic'))
    api_key = db.relationship('AgentApiKey', backref=db.backref('inventory_jobs', lazy='dynamic'))

    def to_dict(self):
        return {
            'id': self.id,
            'organization_id': self.organization_id,
            'asset_id': self.asset_id,
            'asset_hostname': self.asset.hostname if self.asset else None,
            'job_type': self.job_type,
            'status': self.status,
            'priority': self.priority,
            'total_items': self.total_items,
            'items_processed': self.items_processed,
            'items_created': self.items_created,
            'items_updated': self.items_updated,
            'items_failed': self.items_failed,
            'error_message': self.error_message,
            'created_at': self.created_at.isoformat() if self.created_at else None,
            'started_at': self.started_at.isoformat() if self.started_at else None,
            'completed_at': self.completed_at.isoformat() if self.completed_at else None,
            'progress_percent': round((self.items_processed / self.total_items * 100), 1) if self.total_items > 0 else 0
        }

    @staticmethod
    def get_next_pending():
        """Get the next pending job to process, ordered by priority and creation time."""
        return InventoryJob.query.filter_by(status='pending').order_by(
            InventoryJob.priority.asc(),
            InventoryJob.created_at.asc()
        ).first()


# ============================================================================
# AGENT USAGE TRACKING - Metering and billing for pay-per-agent model
# ============================================================================

class AgentLicense(db.Model):
    """
    Organization's agent usage tracking for metering and billing.

    IMPORTANT ARCHITECTURE NOTE:
    This table is for USAGE TRACKING and BILLING only, NOT for enforcement.
    Actual agent limits are enforced via the RSA-signed license system
    in app/licensing.py (check_agent_limit function).

    The limits stored here (max_agents, max_api_keys) are informational
    and for historical billing purposes. They should NOT be used for
    enforcement because database values can be modified by on-premise
    customers. Use the signed license limits instead.

    The signed license contains tamper-proof limits:
    - max_agents: Global limit across all organizations
    - max_agent_api_keys: Global limit across all organizations

    This table tracks:
    - current_agents: Current count for this org (for billing)
    - peak_agents: Peak usage in billing period
    - billing_cycle, billing dates: For invoicing

    License tiers (informational reference):
    - trial: Limited agents, limited time
    - starter: Small teams (up to 25 agents)
    - professional: Medium deployments (up to 100 agents)
    - enterprise: Large deployments (up to 500 agents)
    - unlimited: No restrictions
    """
    __tablename__ = 'agent_licenses'

    id = db.Column(db.Integer, primary_key=True)
    organization_id = db.Column(db.Integer, db.ForeignKey('organizations.id', ondelete='CASCADE'), nullable=False, unique=True, index=True)

    # License tier and limits
    tier = db.Column(db.String(50), default='trial', nullable=False)  # trial, starter, professional, enterprise, unlimited
    max_agents = db.Column(db.Integer, default=5, nullable=False)  # Max concurrent agents
    max_api_keys = db.Column(db.Integer, default=2, nullable=False)  # Max API keys per org

    # Current usage (cached, updated on agent changes)
    current_agents = db.Column(db.Integer, default=0)  # Active agents count (total)
    peak_agents = db.Column(db.Integer, default=0)  # Peak usage in current period

    # Server vs Client breakdown (for tiered pricing like S1)
    server_count = db.Column(db.Integer, default=0)  # Servers, appliances, containers
    client_count = db.Column(db.Integer, default=0)  # Workstations, desktops, laptops
    peak_servers = db.Column(db.Integer, default=0)  # Peak server count
    peak_clients = db.Column(db.Integer, default=0)  # Peak client count

    # License status
    status = db.Column(db.String(20), default='active', index=True)  # active, trial, suspended, expired, grace_period
    grace_period_until = db.Column(db.DateTime, nullable=True)  # When grace period ends

    # Billing information
    billing_cycle = db.Column(db.String(20), default='monthly')  # monthly, annual
    billing_start_date = db.Column(db.Date, nullable=True)
    next_billing_date = db.Column(db.Date, nullable=True)

    # Trial information
    trial_started_at = db.Column(db.DateTime, nullable=True)
    trial_ends_at = db.Column(db.DateTime, nullable=True)

    # Feature flags (for tier-based features)
    features = db.Column(db.Text, nullable=True)  # JSON: {"version_history": true, "priority_support": true}

    # Timestamps
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    # Relationships
    organization = db.relationship('Organization', backref=db.backref('agent_license', uselist=False))

    # Tier definitions with limits
    TIER_LIMITS = {
        'trial': {'max_agents': 5, 'max_api_keys': 1, 'trial_days': 14},
        'starter': {'max_agents': 25, 'max_api_keys': 3},
        'professional': {'max_agents': 100, 'max_api_keys': 10},
        'enterprise': {'max_agents': 500, 'max_api_keys': 50},
        'unlimited': {'max_agents': 999999, 'max_api_keys': 999}
    }

    def get_features(self):
        """Get enabled features as dict."""
        if not self.features:
            return {}
        try:
            return json.loads(self.features)
        except:
            return {}

    def has_feature(self, feature_name):
        """Check if a feature is enabled."""
        features = self.get_features()
        return features.get(feature_name, False)

    def is_active(self):
        """Check if license is active and valid."""
        if self.status == 'expired':
            return False
        if self.status == 'suspended':
            return False
        if self.status == 'trial' and self.trial_ends_at:
            if datetime.utcnow() > self.trial_ends_at:
                return False
        return True

    def is_in_grace_period(self):
        """Check if license is in grace period (over limit but allowed temporarily)."""
        if not self.grace_period_until:
            return False
        return datetime.utcnow() < self.grace_period_until

    def can_add_agent(self):
        """Check if organization can add another agent."""
        if not self.is_active():
            return False, "License is not active"

        if self.current_agents >= self.max_agents:
            if self.is_in_grace_period():
                return True, "In grace period - please upgrade soon"
            return False, f"Agent limit reached ({self.current_agents}/{self.max_agents})"

        return True, None

    def get_usage_percent(self):
        """Get current usage as percentage of limit."""
        if self.max_agents == 0:
            return 100
        return round((self.current_agents / self.max_agents) * 100, 1)

    # Asset types considered as "servers" (higher cost/value)
    SERVER_TYPES = ['server', 'container', 'appliance', 'virtual_machine', 'vm']
    # Asset types considered as "clients" (lower cost/value)
    CLIENT_TYPES = ['workstation', 'desktop', 'laptop', 'endpoint', 'client']

    def update_agent_count(self):
        """
        Update current_agents count from database with server/client breakdown.

        Server vs Client pricing model (similar to SentinelOne):
        - Servers: Higher value, typically 1 full unit
        - Clients: Lower value, typically 0.5 units
        """
        from app.models import Asset

        # Get all active assets for this org
        active_assets = Asset.query.filter_by(
            organization_id=self.organization_id,
            active=True
        ).filter(Asset.status.in_(['online', 'offline'])).all()

        # Count by type
        server_count = 0
        client_count = 0

        for asset in active_assets:
            asset_type = (asset.asset_type or 'server').lower()
            if asset_type in self.CLIENT_TYPES:
                client_count += 1
            else:
                # Default to server for unknown types (conservative approach)
                server_count += 1

        # Update counts
        self.server_count = server_count
        self.client_count = client_count
        self.current_agents = server_count + client_count

        # Update peaks if needed
        if self.server_count > self.peak_servers:
            self.peak_servers = self.server_count
        if self.client_count > self.peak_clients:
            self.peak_clients = self.client_count
        if self.current_agents > self.peak_agents:
            self.peak_agents = self.current_agents

        return self.current_agents

    def get_weighted_units(self, server_weight=1.0, client_weight=0.5):
        """
        Calculate weighted license units based on server/client breakdown.

        Args:
            server_weight: Weight per server (default 1.0)
            client_weight: Weight per client/workstation (default 0.5)

        Returns:
            float: Total weighted units
        """
        return (self.server_count * server_weight) + (self.client_count * client_weight)

    def to_dict(self):
        return {
            'id': self.id,
            'organization_id': self.organization_id,
            'tier': self.tier,
            'max_agents': self.max_agents,
            'max_api_keys': self.max_api_keys,
            'current_agents': self.current_agents,
            'peak_agents': self.peak_agents,
            # Server vs Client breakdown
            'server_count': self.server_count,
            'client_count': self.client_count,
            'peak_servers': self.peak_servers,
            'peak_clients': self.peak_clients,
            'weighted_units': self.get_weighted_units(),
            'usage_percent': self.get_usage_percent(),
            'status': self.status,
            'is_active': self.is_active(),
            'grace_period_until': self.grace_period_until.isoformat() if self.grace_period_until else None,
            'billing_cycle': self.billing_cycle,
            'next_billing_date': self.next_billing_date.isoformat() if self.next_billing_date else None,
            'trial_ends_at': self.trial_ends_at.isoformat() if self.trial_ends_at else None,
            'features': self.get_features(),
            'created_at': self.created_at.isoformat() if self.created_at else None
        }


class AgentUsageRecord(db.Model):
    """
    Daily usage records for billing and analytics.
    Tracks agent count snapshots for accurate billing.
    """
    __tablename__ = 'agent_usage_records'

    id = db.Column(db.Integer, primary_key=True)
    organization_id = db.Column(db.Integer, db.ForeignKey('organizations.id', ondelete='CASCADE'), nullable=False, index=True)

    # Usage date (one record per day per org)
    record_date = db.Column(db.Date, nullable=False, index=True)

    # Counts at different points
    active_agents = db.Column(db.Integer, default=0)  # Active agents at snapshot time
    online_agents = db.Column(db.Integer, default=0)  # Agents that checked in today
    new_agents = db.Column(db.Integer, default=0)  # New agents registered today
    decommissioned_agents = db.Column(db.Integer, default=0)  # Agents decommissioned today

    # Peak usage
    peak_agents = db.Column(db.Integer, default=0)  # Peak count for the day

    # Inventory stats
    inventory_reports = db.Column(db.Integer, default=0)  # Number of inventory reports
    products_discovered = db.Column(db.Integer, default=0)  # New products discovered

    # Timestamps
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    # Unique constraint: one record per org per day
    __table_args__ = (
        db.UniqueConstraint('organization_id', 'record_date', name='uix_org_date'),
    )

    @staticmethod
    def get_or_create_today(organization_id):
        """Get or create today's usage record."""
        today = date.today()
        record = AgentUsageRecord.query.filter_by(
            organization_id=organization_id,
            record_date=today
        ).first()

        if not record:
            record = AgentUsageRecord(
                organization_id=organization_id,
                record_date=today
            )
            db.session.add(record)
            db.session.flush()

        return record

    def to_dict(self):
        return {
            'id': self.id,
            'organization_id': self.organization_id,
            'record_date': self.record_date.isoformat() if self.record_date else None,
            'active_agents': self.active_agents,
            'online_agents': self.online_agents,
            'new_agents': self.new_agents,
            'decommissioned_agents': self.decommissioned_agents,
            'peak_agents': self.peak_agents,
            'inventory_reports': self.inventory_reports,
            'products_discovered': self.products_discovered
        }


class AgentEvent(db.Model):
    """
    Audit log for agent lifecycle events.
    Tracks all agent registrations, status changes, and decommissions.
    Essential for billing disputes and security auditing.
    """
    __tablename__ = 'agent_events'

    id = db.Column(db.Integer, primary_key=True)
    organization_id = db.Column(db.Integer, db.ForeignKey('organizations.id', ondelete='CASCADE'), nullable=False, index=True)
    asset_id = db.Column(db.Integer, db.ForeignKey('assets.id', ondelete='CASCADE'), nullable=True, index=True)
    api_key_id = db.Column(db.Integer, db.ForeignKey('agent_api_keys.id'), nullable=True, index=True)

    # Event details
    event_type = db.Column(db.String(50), nullable=False, index=True)
    # Types: registered, inventory_reported, heartbeat, status_changed, decommissioned,
    #        license_warning, license_exceeded, ip_blocked, auth_failed

    # Event data
    details = db.Column(db.Text, nullable=True)  # JSON with event-specific details
    old_value = db.Column(db.String(200), nullable=True)  # For status changes
    new_value = db.Column(db.String(200), nullable=True)

    # Request context (for security audit)
    source_ip = db.Column(db.String(45), nullable=True)
    user_agent = db.Column(db.String(500), nullable=True)

    # Timestamp
    created_at = db.Column(db.DateTime, default=datetime.utcnow, index=True)

    # Relationships
    organization = db.relationship('Organization', backref=db.backref('agent_events', lazy='dynamic'))
    asset = db.relationship('Asset', backref=db.backref('events', lazy='dynamic'))
    api_key = db.relationship('AgentApiKey', backref=db.backref('events', lazy='dynamic'))

    def get_details(self):
        """Get details as dict."""
        if not self.details:
            return {}
        try:
            return json.loads(self.details)
        except:
            return {}

    @staticmethod
    def log_event(organization_id, event_type, asset_id=None, api_key_id=None,
                  details=None, old_value=None, new_value=None,
                  source_ip=None, user_agent=None):
        """Create a new event log entry."""
        event = AgentEvent(
            organization_id=organization_id,
            asset_id=asset_id,
            api_key_id=api_key_id,
            event_type=event_type,
            details=json.dumps(details) if details else None,
            old_value=old_value,
            new_value=new_value,
            source_ip=source_ip,
            user_agent=user_agent
        )
        db.session.add(event)
        return event

    def to_dict(self):
        return {
            'id': self.id,
            'organization_id': self.organization_id,
            'asset_id': self.asset_id,
            'asset_hostname': self.asset.hostname if self.asset else None,
            'api_key_id': self.api_key_id,
            'event_type': self.event_type,
            'details': self.get_details(),
            'old_value': self.old_value,
            'new_value': self.new_value,
            'source_ip': self.source_ip,
            'created_at': self.created_at.isoformat() if self.created_at else None
        }


class ProductVersionHistory(db.Model):
    """
    Tracks version changes for products installed on assets.
    Allows tracking when software was updated/downgraded.
    """
    __tablename__ = 'product_version_history'

    id = db.Column(db.Integer, primary_key=True)
    installation_id = db.Column(db.Integer, db.ForeignKey('product_installations.id', ondelete='CASCADE'), nullable=False, index=True)
    asset_id = db.Column(db.Integer, db.ForeignKey('assets.id', ondelete='CASCADE'), nullable=False, index=True)
    product_id = db.Column(db.Integer, db.ForeignKey('products.id', ondelete='CASCADE'), nullable=False, index=True)

    # Version info
    previous_version = db.Column(db.String(100), nullable=True)
    new_version = db.Column(db.String(100), nullable=False)
    change_type = db.Column(db.String(20), default='update')  # install, update, downgrade, reinstall, uninstall

    # Detection info
    detected_by = db.Column(db.String(50), default='agent')  # agent, scan, manual
    detected_at = db.Column(db.DateTime, default=datetime.utcnow, index=True)

    # Relationships
    installation = db.relationship('ProductInstallation', backref=db.backref('version_history', lazy='dynamic'))
    asset = db.relationship('Asset', backref=db.backref('product_changes', lazy='dynamic'))
    product = db.relationship('Product', backref=db.backref('version_changes', lazy='dynamic'))

    @staticmethod
    def _compare_versions(old_ver, new_ver):
        """
        Compare two version strings. Returns:
          1  if new_ver > old_ver  (upgrade)
         -1  if new_ver < old_ver  (downgrade)
          0  if equal or unparseable
        Handles: 1.2.3, 1.2.3-ubuntu1, 1.2.3.4, epoch:ver-release
        """
        import re

        def normalize(v):
            if not v:
                return []
            # Strip epoch (e.g. "2:1.2.3" -> "1.2.3")
            v = re.sub(r'^\d+:', '', v)
            # Strip release suffix after hyphen (e.g. "1.2.3-1ubuntu1" -> "1.2.3")
            v = v.split('-')[0]
            # Split on dots and extract numeric parts
            parts = []
            for segment in v.split('.'):
                # Extract leading number from each segment
                m = re.match(r'(\d+)', segment)
                if m:
                    parts.append(int(m.group(1)))
            return parts

        try:
            old_parts = normalize(old_ver)
            new_parts = normalize(new_ver)
            if not old_parts or not new_parts:
                return 0
            # Pad shorter list with zeros
            max_len = max(len(old_parts), len(new_parts))
            old_parts += [0] * (max_len - len(old_parts))
            new_parts += [0] * (max_len - len(new_parts))
            for o, n in zip(old_parts, new_parts):
                if n > o:
                    return 1
                if n < o:
                    return -1
            return 0
        except Exception:
            return 0

    @staticmethod
    def record_change(installation_id, asset_id, product_id, old_version, new_version, detected_by='agent'):
        """Record a version change with upgrade/downgrade detection."""
        # Cannot record history without a new_version (DB constraint: NOT NULL)
        if not new_version:
            return None

        # Determine change type
        if new_version == '(uninstalled)':
            change_type = 'uninstall'
        elif not old_version:
            change_type = 'install'
        elif old_version == new_version:
            change_type = 'reinstall'
        else:
            cmp = ProductVersionHistory._compare_versions(old_version, new_version)
            if cmp < 0:
                change_type = 'downgrade'
            else:
                change_type = 'update'  # upgrade or unparseable

        record = ProductVersionHistory(
            installation_id=installation_id,
            asset_id=asset_id,
            product_id=product_id,
            previous_version=old_version,
            new_version=new_version,
            change_type=change_type,
            detected_by=detected_by
        )
        db.session.add(record)
        return record

    def to_dict(self):
        return {
            'id': self.id,
            'installation_id': self.installation_id,
            'asset_id': self.asset_id,
            'asset_hostname': self.asset.hostname if self.asset else None,
            'product_id': self.product_id,
            'product_name': f"{self.product.vendor} {self.product.product_name}" if self.product else None,
            'previous_version': self.previous_version,
            'new_version': self.new_version,
            'change_type': self.change_type,
            'detected_by': self.detected_by,
            'detected_at': self.detected_at.isoformat() if self.detected_at else None
        }


class StaleAssetNotification(db.Model):
    """
    Tracks notifications sent for stale/offline agents.
    Prevents notification spam while ensuring admins are alerted.
    """
    __tablename__ = 'stale_asset_notifications'

    id = db.Column(db.Integer, primary_key=True)
    asset_id = db.Column(db.Integer, db.ForeignKey('assets.id', ondelete='CASCADE'), nullable=False, index=True)
    organization_id = db.Column(db.Integer, db.ForeignKey('organizations.id', ondelete='CASCADE'), nullable=False, index=True)

    # Notification state
    notification_type = db.Column(db.String(50), nullable=False)  # offline, stale, critical_offline
    first_detected_at = db.Column(db.DateTime, default=datetime.utcnow)
    last_notified_at = db.Column(db.DateTime, nullable=True)
    notification_count = db.Column(db.Integer, default=0)

    # Resolution
    resolved = db.Column(db.Boolean, default=False, index=True)
    resolved_at = db.Column(db.DateTime, nullable=True)
    resolved_by = db.Column(db.String(50), nullable=True)  # auto, manual, agent_checkin

    # Relationships
    asset = db.relationship('Asset', backref=db.backref('stale_notifications', lazy='dynamic'))
    organization = db.relationship('Organization')

    def to_dict(self):
        return {
            'id': self.id,
            'asset_id': self.asset_id,
            'asset_hostname': self.asset.hostname if self.asset else None,
            'organization_id': self.organization_id,
            'notification_type': self.notification_type,
            'first_detected_at': self.first_detected_at.isoformat() if self.first_detected_at else None,
            'last_notified_at': self.last_notified_at.isoformat() if self.last_notified_at else None,
            'notification_count': self.notification_count,
            'resolved': self.resolved,
            'resolved_at': self.resolved_at.isoformat() if self.resolved_at else None
        }


class UserCpeMapping(db.Model):
    """
    User-learned CPE mappings for software that isn't in the curated database.

    These mappings are:
    - Created when users manually assign CPE to unmapped products
    - Exportable/importable for sharing between instances
    - Used with higher priority than curated database (user knows best)
    """
    __tablename__ = 'user_cpe_mappings'

    id = db.Column(db.Integer, primary_key=True)

    # Source software identification (normalized)
    vendor_pattern = db.Column(db.String(200), nullable=False, index=True)
    product_pattern = db.Column(db.String(200), nullable=False, index=True)

    # Target CPE identifiers
    cpe_vendor = db.Column(db.String(200), nullable=False)
    cpe_product = db.Column(db.String(200), nullable=False)

    # Metadata
    confidence = db.Column(db.Float, default=0.95)  # User mappings are high confidence
    source = db.Column(db.String(50), default='user')  # user, import, community
    notes = db.Column(db.Text, nullable=True)  # Optional notes about this mapping

    # Audit
    created_by = db.Column(db.Integer, db.ForeignKey('users.id', ondelete='SET NULL'), nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    usage_count = db.Column(db.Integer, default=0)  # Track how often this mapping is used

    # Relationships
    creator = db.relationship('User', backref=db.backref('cpe_mappings', lazy='dynamic'))

    # Unique constraint to prevent duplicates
    __table_args__ = (
        db.UniqueConstraint('vendor_pattern', 'product_pattern', name='uq_user_cpe_mapping'),
    )

    def to_dict(self):
        return {
            'id': self.id,
            'vendor_pattern': self.vendor_pattern,
            'product_pattern': self.product_pattern,
            'cpe_vendor': self.cpe_vendor,
            'cpe_product': self.cpe_product,
            'confidence': self.confidence,
            'source': self.source,
            'notes': self.notes,
            'usage_count': self.usage_count,
            'created_by': self.creator.display_name if self.creator else None,
            'created_at': self.created_at.isoformat() if self.created_at else None,
            'updated_at': self.updated_at.isoformat() if self.updated_at else None
        }

    def to_export_dict(self):
        """Minimal format for export/import (no internal IDs)"""
        return {
            'vendor_pattern': self.vendor_pattern,
            'product_pattern': self.product_pattern,
            'cpe_vendor': self.cpe_vendor,
            'cpe_product': self.cpe_product,
            'confidence': self.confidence,
            'notes': self.notes
        }

    @staticmethod
    def normalize_pattern(text):
        """Normalize vendor/product name for matching"""
        if not text:
            return ''
        return text.lower().strip()


# ============================================================================
# LOCAL CPE DICTIONARY - Extracted from vulnerability CPE data
# ============================================================================

class CpeDictionaryEntry(db.Model):
    """
    Local CPE dictionary built from vulnerability CPE data.

    Every vulnerability in the database contains CPE entries (vendor:product).
    We extract these into a searchable table for fast offline CPE matching.
    This eliminates the dependency on rate-limited NVD API for common products.
    """
    __tablename__ = 'cpe_dictionary_entries'

    id = db.Column(db.Integer, primary_key=True)
    cpe_vendor = db.Column(db.String(200), nullable=False, index=True)
    cpe_product = db.Column(db.String(200), nullable=False, index=True)

    # Search aliases from vulnerability human-readable names (pipe-separated)
    search_aliases = db.Column(db.Text, nullable=True)

    # How many CVEs reference this vendor:product (popularity signal)
    cve_count = db.Column(db.Integer, default=0)

    # How many times this entry was used for matching (quality signal)
    usage_count = db.Column(db.Integer, default=0)

    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    __table_args__ = (
        db.UniqueConstraint('cpe_vendor', 'cpe_product', name='uq_cpe_dict_vendor_product'),
    )

    def to_dict(self):
        return {
            'cpe_vendor': self.cpe_vendor,
            'cpe_product': self.cpe_product,
            'cve_count': self.cve_count,
            'usage_count': self.usage_count,
            'aliases': (self.search_aliases or '').split('|') if self.search_aliases else [],
        }


# ============================================================================
# VULNERABILITY TREND TRACKING - Historical data for analytics
# ============================================================================

class VulnerabilitySnapshot(db.Model):
    """
    Daily snapshots of vulnerability statistics for trend analysis.
    Captures key metrics at a point in time for historical comparison.
    """
    __tablename__ = 'vulnerability_snapshots'

    id = db.Column(db.Integer, primary_key=True)
    organization_id = db.Column(db.Integer, db.ForeignKey('organizations.id', ondelete='CASCADE'), nullable=True, index=True)
    snapshot_date = db.Column(db.Date, nullable=False, index=True)

    # Core metrics
    total_vulnerabilities = db.Column(db.Integer, default=0)  # Total CVEs in CISA KEV
    total_matches = db.Column(db.Integer, default=0)  # CVEs matching our products
    unacknowledged = db.Column(db.Integer, default=0)  # Unacked matches
    acknowledged = db.Column(db.Integer, default=0)  # Acked matches
    snoozed = db.Column(db.Integer, default=0)  # Snoozed matches

    # Severity breakdown
    critical_count = db.Column(db.Integer, default=0)
    high_count = db.Column(db.Integer, default=0)
    medium_count = db.Column(db.Integer, default=0)
    low_count = db.Column(db.Integer, default=0)

    # Product metrics
    products_tracked = db.Column(db.Integer, default=0)
    products_with_vulns = db.Column(db.Integer, default=0)

    # Agent metrics (optional)
    active_agents = db.Column(db.Integer, default=0)

    # Metadata
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    __table_args__ = (
        db.UniqueConstraint('organization_id', 'snapshot_date', name='uq_org_snapshot_date'),
    )

    # Relationship
    organization = db.relationship('Organization', backref=db.backref('vulnerability_snapshots', lazy='dynamic'))

    def to_dict(self):
        return {
            'id': self.id,
            'organization_id': self.organization_id,
            'snapshot_date': self.snapshot_date.isoformat() if self.snapshot_date else None,
            'total_vulnerabilities': self.total_vulnerabilities,
            'total_matches': self.total_matches,
            'unacknowledged': self.unacknowledged,
            'acknowledged': self.acknowledged,
            'snoozed': self.snoozed,
            'critical_count': self.critical_count,
            'high_count': self.high_count,
            'medium_count': self.medium_count,
            'low_count': self.low_count,
            'products_tracked': self.products_tracked,
            'products_with_vulns': self.products_with_vulns,
            'active_agents': self.active_agents
        }

    @classmethod
    def _get_org_product_ids(cls, organization_id):
        """Get all product IDs for an organization, including both legacy and multi-org relationships."""
        from sqlalchemy import select
        legacy_ids = [p.id for p in Product.query.filter_by(organization_id=organization_id).all()]
        multi_org_ids = [row.product_id for row in db.session.execute(
            select(product_organizations.c.product_id).where(
                product_organizations.c.organization_id == organization_id
            )
        ).all()]
        return list(set(legacy_ids + multi_org_ids))

    @classmethod
    def take_snapshot(cls, organization_id=None):
        """
        Take a snapshot of current vulnerability statistics.
        If organization_id is None, takes a global snapshot.
        Handles both legacy Product.organization_id and many-to-many product_organizations.
        """
        from sqlalchemy import func, select

        today = date.today()

        # Check if snapshot already exists for today
        existing = cls.query.filter_by(
            organization_id=organization_id,
            snapshot_date=today
        ).first()

        if existing:
            return existing  # Already have today's snapshot

        # Get org product IDs (handles both legacy and multi-org relationships)
        org_product_ids = cls._get_org_product_ids(organization_id) if organization_id else None

        # Get total KEV vulnerabilities
        total_vulns = Vulnerability.query.count()

        # Get match statistics
        match_query = db.session.query(
            func.count(VulnerabilityMatch.id).label('total'),
            func.sum(db.case((VulnerabilityMatch.acknowledged == False, 1), else_=0)).label('unacked'),
            func.sum(db.case((VulnerabilityMatch.acknowledged == True, 1), else_=0)).label('acked'),
            func.sum(db.case((VulnerabilityMatch.snoozed_until != None, 1), else_=0)).label('snoozed')
        )

        if org_product_ids is not None:
            match_query = match_query.filter(
                VulnerabilityMatch.product_id.in_(org_product_ids)
            ) if org_product_ids else match_query.filter(VulnerabilityMatch.id < 0)

        match_stats = match_query.first()

        # Get severity breakdown
        severity_query = db.session.query(
            Vulnerability.severity,
            func.count(VulnerabilityMatch.id)
        ).join(
            VulnerabilityMatch, VulnerabilityMatch.vulnerability_id == Vulnerability.id
        ).filter(
            VulnerabilityMatch.acknowledged == False
        )

        if org_product_ids is not None:
            severity_query = severity_query.filter(
                VulnerabilityMatch.product_id.in_(org_product_ids)
            ) if org_product_ids else severity_query.filter(VulnerabilityMatch.id < 0)

        severity_query = severity_query.group_by(Vulnerability.severity)
        severity_counts = dict(severity_query.all())

        # Get product counts
        if org_product_ids is not None:
            products_tracked = Product.query.filter(
                Product.active == True,
                Product.id.in_(org_product_ids)
            ).count() if org_product_ids else 0
        else:
            products_tracked = Product.query.filter(Product.active == True).count()

        # Products with vulnerabilities
        products_with_vulns_query = db.session.query(
            func.count(func.distinct(VulnerabilityMatch.product_id))
        ).join(Product, VulnerabilityMatch.product_id == Product.id).filter(
            Product.active == True,
            VulnerabilityMatch.acknowledged == False
        )
        if org_product_ids is not None:
            products_with_vulns_query = products_with_vulns_query.filter(
                VulnerabilityMatch.product_id.in_(org_product_ids)
            ) if org_product_ids else products_with_vulns_query.filter(VulnerabilityMatch.id < 0)
        products_with_vulns = products_with_vulns_query.scalar() or 0

        # Get agent count
        agents_query = Asset.query.filter(Asset.active == True)
        if organization_id:
            agents_query = agents_query.filter(Asset.organization_id == organization_id)
        active_agents = agents_query.count()

        # Create snapshot
        snapshot = cls(
            organization_id=organization_id,
            snapshot_date=today,
            total_vulnerabilities=total_vulns,
            total_matches=match_stats.total or 0,
            unacknowledged=match_stats.unacked or 0,
            acknowledged=match_stats.acked or 0,
            snoozed=match_stats.snoozed or 0,
            critical_count=severity_counts.get('CRITICAL', 0),
            high_count=severity_counts.get('HIGH', 0),
            medium_count=severity_counts.get('MEDIUM', 0),
            low_count=severity_counts.get('LOW', 0),
            products_tracked=products_tracked,
            products_with_vulns=products_with_vulns,
            active_agents=active_agents
        )

        db.session.add(snapshot)
        db.session.commit()

        return snapshot

    @classmethod
    def get_trend_data(cls, organization_id=None, days=30):
        """
        Get trend data for the last N days.
        Returns list of snapshots ordered by date.
        """
        from datetime import timedelta
        start_date = date.today() - timedelta(days=days)

        query = cls.query.filter(
            cls.organization_id == organization_id,
            cls.snapshot_date >= start_date
        ).order_by(cls.snapshot_date.asc())

        return query.all()


class ScheduledReport(db.Model):
    """
    Configuration for scheduled vulnerability reports.
    Defines when and to whom reports should be sent.
    """
    __tablename__ = 'scheduled_reports'

    id = db.Column(db.Integer, primary_key=True)
    organization_id = db.Column(db.Integer, db.ForeignKey('organizations.id', ondelete='CASCADE'), nullable=False, index=True)
    name = db.Column(db.String(100), nullable=False)
    description = db.Column(db.Text, nullable=True)

    # Schedule configuration
    frequency = db.Column(db.String(20), nullable=False, default='weekly')  # daily, weekly, monthly
    day_of_week = db.Column(db.Integer, nullable=True)  # 0=Monday, 6=Sunday (for weekly)
    day_of_month = db.Column(db.Integer, nullable=True)  # 1-28 (for monthly)
    time_of_day = db.Column(db.String(5), nullable=False, default='09:00')  # HH:MM format

    # Report configuration
    report_type = db.Column(db.String(20), nullable=False, default='summary')  # summary, full, critical_only
    include_acknowledged = db.Column(db.Boolean, default=True)
    include_pending = db.Column(db.Boolean, default=True)
    include_trends = db.Column(db.Boolean, default=True)
    priority_filter = db.Column(db.String(20), nullable=True)  # critical, high, medium, low or None for all

    # Recipients (comma-separated email addresses or role-based)
    recipients = db.Column(db.Text, nullable=False)  # email1@example.com,email2@example.com
    send_to_managers = db.Column(db.Boolean, default=False)  # Also send to org managers
    send_to_admins = db.Column(db.Boolean, default=True)  # Also send to org admins

    # Status
    enabled = db.Column(db.Boolean, default=True)
    last_sent = db.Column(db.DateTime, nullable=True)
    last_status = db.Column(db.String(50), nullable=True)  # success, failed, no_recipients
    next_run = db.Column(db.DateTime, nullable=True)

    # Audit
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    created_by = db.Column(db.Integer, db.ForeignKey('users.id', ondelete='SET NULL'), nullable=True)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    # Relationships
    organization = db.relationship('Organization', backref=db.backref('scheduled_reports', lazy='dynamic'))
    creator = db.relationship('User', backref=db.backref('created_reports', lazy='dynamic'))

    FREQUENCY_CHOICES = ['daily', 'weekly', 'monthly']
    REPORT_TYPE_CHOICES = ['summary', 'full', 'critical_only']

    def to_dict(self):
        return {
            'id': self.id,
            'organization_id': self.organization_id,
            'name': self.name,
            'description': self.description,
            'frequency': self.frequency,
            'day_of_week': self.day_of_week,
            'day_of_month': self.day_of_month,
            'time_of_day': self.time_of_day,
            'report_type': self.report_type,
            'include_acknowledged': self.include_acknowledged,
            'include_pending': self.include_pending,
            'include_trends': self.include_trends,
            'priority_filter': self.priority_filter,
            'recipients': self.recipients,
            'send_to_managers': self.send_to_managers,
            'send_to_admins': self.send_to_admins,
            'enabled': self.enabled,
            'last_sent': self.last_sent.isoformat() if self.last_sent else None,
            'last_status': self.last_status,
            'next_run': self.next_run.isoformat() if self.next_run else None,
            'created_at': self.created_at.isoformat() if self.created_at else None,
            'created_by': self.created_by
        }

    def calculate_next_run(self):
        """Calculate the next run time based on frequency and schedule"""
        from datetime import datetime, timedelta

        now = datetime.utcnow()
        hour, minute = map(int, self.time_of_day.split(':'))

        if self.frequency == 'daily':
            # Next occurrence of the specified time
            next_run = now.replace(hour=hour, minute=minute, second=0, microsecond=0)
            if next_run <= now:
                next_run += timedelta(days=1)

        elif self.frequency == 'weekly':
            # Next occurrence of the specified day and time
            days_ahead = self.day_of_week - now.weekday()
            if days_ahead < 0:
                days_ahead += 7
            next_run = now.replace(hour=hour, minute=minute, second=0, microsecond=0) + timedelta(days=days_ahead)
            if next_run <= now:
                next_run += timedelta(days=7)

        elif self.frequency == 'monthly':
            # Next occurrence of the specified day of month
            day = min(self.day_of_month or 1, 28)  # Cap at 28 to avoid month-end issues
            next_run = now.replace(day=day, hour=hour, minute=minute, second=0, microsecond=0)
            if next_run <= now:
                # Move to next month
                if now.month == 12:
                    next_run = next_run.replace(year=now.year + 1, month=1)
                else:
                    next_run = next_run.replace(month=now.month + 1)

        else:
            next_run = now + timedelta(days=1)

        self.next_run = next_run
        return next_run

    def get_recipient_emails(self):
        """Get list of email addresses to send to"""
        emails = set()

        # Add explicit recipients
        if self.recipients:
            for email in self.recipients.split(','):
                email = email.strip()
                if email and '@' in email:
                    emails.add(email)

        # Add role-based recipients
        if self.send_to_managers or self.send_to_admins:
            org_users = User.query.filter_by(
                organization_id=self.organization_id,
                is_active=True
            ).all()

            for user in org_users:
                if user.email:
                    if self.send_to_admins and user.role in ['org_admin', 'super_admin']:
                        emails.add(user.email)
                    elif self.send_to_managers and user.role == 'manager':
                        emails.add(user.email)

        return list(emails)


# =============================================================================
# Container Image Scanning Models (Trivy Integration)
# =============================================================================

class ContainerImage(db.Model):
    """
    Represents a Docker/OCI container image discovered on an asset.
    Tracks image metadata, scan results, and vulnerability counts.
    """
    __tablename__ = 'container_images'

    id = db.Column(db.Integer, primary_key=True)
    organization_id = db.Column(db.Integer, db.ForeignKey('organizations.id', ondelete='CASCADE'), nullable=False, index=True)
    asset_id = db.Column(db.Integer, db.ForeignKey('assets.id', ondelete='CASCADE'), nullable=True, index=True)

    # Image identification
    image_name = db.Column(db.String(500), nullable=False, index=True)  # e.g. "nginx", "myapp"
    image_tag = db.Column(db.String(200), nullable=True)  # e.g. "latest", "1.25-alpine"
    image_id = db.Column(db.String(100), nullable=True, index=True)  # SHA256 digest
    image_digest = db.Column(db.String(200), nullable=True)  # Registry digest (sha256:abc...)
    registry = db.Column(db.String(300), nullable=True)  # e.g. "docker.io", "ghcr.io"
    repository = db.Column(db.String(500), nullable=True)  # Full repository path

    # Image metadata
    os_family = db.Column(db.String(50), nullable=True)  # alpine, debian, ubuntu, centos, etc.
    os_version = db.Column(db.String(100), nullable=True)
    architecture = db.Column(db.String(20), nullable=True)  # amd64, arm64
    size_bytes = db.Column(db.BigInteger, nullable=True)
    created_at_image = db.Column(db.DateTime, nullable=True)  # When the image was built

    # Scan results (cached aggregates)
    last_scan_at = db.Column(db.DateTime, nullable=True)
    scanner_version = db.Column(db.String(50), nullable=True)  # e.g. "trivy 0.58.0"
    total_vulnerabilities = db.Column(db.Integer, default=0)
    critical_count = db.Column(db.Integer, default=0)
    high_count = db.Column(db.Integer, default=0)
    medium_count = db.Column(db.Integer, default=0)
    low_count = db.Column(db.Integer, default=0)
    fixed_count = db.Column(db.Integer, default=0)  # Vulns with known fix
    unfixed_count = db.Column(db.Integer, default=0)  # No fix available yet

    # Status
    active = db.Column(db.Boolean, default=True, index=True)
    running = db.Column(db.Boolean, default=False)  # Currently running on the asset

    # Timestamps
    first_seen_at = db.Column(db.DateTime, default=datetime.utcnow)
    last_seen_at = db.Column(db.DateTime, default=datetime.utcnow)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    # Relationships
    organization = db.relationship('Organization', backref=db.backref('container_images', lazy='dynamic'))
    asset = db.relationship('Asset', backref=db.backref('container_images', lazy='dynamic'))
    vulnerabilities = db.relationship('ContainerVulnerability', backref='container_image', cascade='all, delete-orphan', lazy='dynamic')

    __table_args__ = (
        db.Index('idx_container_org_active', 'organization_id', 'active'),
        db.Index('idx_container_image_name', 'image_name', 'image_tag'),
        db.UniqueConstraint('organization_id', 'asset_id', 'image_name', 'image_tag', name='uix_org_asset_image'),
    )

    @property
    def full_name(self):
        """Return full image reference like 'nginx:1.25-alpine'"""
        if self.image_tag:
            return f"{self.image_name}:{self.image_tag}"
        return self.image_name

    @property
    def severity_summary(self):
        """Return severity breakdown dict"""
        return {
            'critical': self.critical_count or 0,
            'high': self.high_count or 0,
            'medium': self.medium_count or 0,
            'low': self.low_count or 0,
        }

    def to_dict(self):
        return {
            'id': self.id,
            'organization_id': self.organization_id,
            'asset_id': self.asset_id,
            'asset_hostname': self.asset.hostname if self.asset else None,
            'image_name': self.image_name,
            'image_tag': self.image_tag,
            'image_id': self.image_id,
            'image_digest': self.image_digest,
            'registry': self.registry,
            'full_name': self.full_name,
            'os_family': self.os_family,
            'os_version': self.os_version,
            'architecture': self.architecture,
            'size_bytes': self.size_bytes,
            'last_scan_at': self.last_scan_at.isoformat() if self.last_scan_at else None,
            'scanner_version': self.scanner_version,
            'total_vulnerabilities': self.total_vulnerabilities,
            'severity': self.severity_summary,
            'fixed_count': self.fixed_count,
            'unfixed_count': self.unfixed_count,
            'active': self.active,
            'running': self.running,
            'first_seen_at': self.first_seen_at.isoformat() if self.first_seen_at else None,
            'last_seen_at': self.last_seen_at.isoformat() if self.last_seen_at else None,
        }


class ContainerVulnerability(db.Model):
    """
    Individual vulnerability found in a container image scan.
    Each record maps a CVE to a specific package within a container image.
    """
    __tablename__ = 'container_vulnerabilities'

    id = db.Column(db.Integer, primary_key=True)
    container_image_id = db.Column(db.Integer, db.ForeignKey('container_images.id'), nullable=False, index=True)

    # Vulnerability identification
    vuln_id = db.Column(db.String(50), nullable=False, index=True)  # CVE-2024-1234 or GHSA-xxx
    severity = db.Column(db.String(20), nullable=True, index=True)  # CRITICAL, HIGH, MEDIUM, LOW, UNKNOWN
    title = db.Column(db.String(500), nullable=True)
    description = db.Column(db.Text, nullable=True)

    # Affected package
    pkg_name = db.Column(db.String(200), nullable=False)  # e.g. "libssl3"
    pkg_version = db.Column(db.String(100), nullable=True)  # Installed version
    pkg_type = db.Column(db.String(50), nullable=True)  # os, library, etc.
    pkg_path = db.Column(db.String(500), nullable=True)  # File path in image

    # Fix information
    fixed_version = db.Column(db.String(100), nullable=True)  # Version that fixes this CVE
    fix_status = db.Column(db.String(30), default='unknown')  # fixed, not_fixed, end_of_life, unknown

    # Scoring
    cvss_score = db.Column(db.Float, nullable=True)
    cvss_vector = db.Column(db.String(200), nullable=True)

    # Source
    data_source = db.Column(db.String(200), nullable=True)  # e.g. "ubuntu", "nvd", "ghsa"
    primary_url = db.Column(db.String(500), nullable=True)  # Link to advisory

    # Status tracking
    acknowledged = db.Column(db.Boolean, default=False)
    acknowledged_at = db.Column(db.DateTime, nullable=True)
    acknowledged_by = db.Column(db.String(100), nullable=True)

    # Timestamps
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    __table_args__ = (
        db.Index('idx_container_vuln_severity', 'container_image_id', 'severity'),
        db.Index('idx_container_vuln_id', 'vuln_id'),
    )

    def to_dict(self):
        return {
            'id': self.id,
            'container_image_id': self.container_image_id,
            'vuln_id': self.vuln_id,
            'severity': self.severity,
            'title': self.title,
            'pkg_name': self.pkg_name,
            'pkg_version': self.pkg_version,
            'pkg_type': self.pkg_type,
            'fixed_version': self.fixed_version,
            'fix_status': self.fix_status,
            'cvss_score': self.cvss_score,
            'data_source': self.data_source,
            'primary_url': self.primary_url,
            'acknowledged': self.acknowledged,
            'created_at': self.created_at.isoformat() if self.created_at else None,
        }


class HealthCheckResult(db.Model):
    """
    Stores results from background health checks.
    Each check is identified by a unique check_name.
    """
    __tablename__ = 'health_check_results'

    id = db.Column(db.Integer, primary_key=True)
    check_name = db.Column(db.String(100), nullable=False, index=True)
    category = db.Column(db.String(50), nullable=False, default='system')  # system, database, agents, sync, security
    status = db.Column(db.String(20), nullable=False, default='unknown')  # ok, warning, critical, error, unknown
    message = db.Column(db.Text, nullable=True)
    details = db.Column(db.Text, nullable=True)  # JSON with check-specific data
    value = db.Column(db.String(200), nullable=True)  # Metric value (e.g. "85%", "3 stale")
    checked_at = db.Column(db.DateTime, default=datetime.utcnow, index=True)

    __table_args__ = (
        db.Index('idx_health_check_name_time', 'check_name', 'checked_at'),
    )

    @staticmethod
    def record(check_name, category, status, message, value=None, details=None):
        """Record a health check result, replacing any previous result for this check."""
        existing = HealthCheckResult.query.filter_by(check_name=check_name).first()
        if existing:
            existing.category = category
            existing.status = status
            existing.message = message
            existing.value = value
            existing.details = json.dumps(details) if details else None
            existing.checked_at = datetime.utcnow()
        else:
            result = HealthCheckResult(
                check_name=check_name,
                category=category,
                status=status,
                message=message,
                value=value,
                details=json.dumps(details) if details else None
            )
            db.session.add(result)
        db.session.commit()

    def to_dict(self):
        return {
            'id': self.id,
            'check_name': self.check_name,
            'category': self.category,
            'status': self.status,
            'message': self.message,
            'value': self.value,
            'details': json.loads(self.details) if self.details else None,
            'checked_at': self.checked_at.isoformat() if self.checked_at else None,
        }
