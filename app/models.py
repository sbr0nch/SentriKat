from datetime import datetime, date
from app import db

class Product(db.Model):
    """Software/service inventory managed by admins"""
    __tablename__ = 'products'

    id = db.Column(db.Integer, primary_key=True)
    vendor = db.Column(db.String(200), nullable=False, index=True)
    product_name = db.Column(db.String(200), nullable=False, index=True)
    version = db.Column(db.String(100), nullable=True)
    keywords = db.Column(db.Text, nullable=True)  # Comma-separated additional keywords
    description = db.Column(db.Text, nullable=True)
    active = db.Column(db.Boolean, default=True, index=True)
    criticality = db.Column(db.String(20), default='medium')  # critical, high, medium, low
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    def to_dict(self):
        return {
            'id': self.id,
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
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    def calculate_priority(self):
        """
        Calculate priority based on multiple factors:
        - Ransomware involvement: Automatic CRITICAL
        - Due date proximity: Urgent if due soon
        - Age: Recent CVEs are higher priority
        Returns: critical, high, medium, low
        """
        # Ransomware = Always Critical
        if self.known_ransomware:
            return 'critical'

        # Check due date
        if self.due_date:
            days_until_due = (self.due_date - date.today()).days
            if days_until_due <= 7:
                return 'critical'
            elif days_until_due <= 30:
                return 'high'

        # Check age of vulnerability
        days_since_added = (date.today() - self.date_added).days

        if days_since_added <= 30:  # Last 30 days
            return 'high'
        elif days_since_added <= 90:  # Last 3 months
            return 'medium'
        else:  # Older than 3 months
            return 'low'

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
