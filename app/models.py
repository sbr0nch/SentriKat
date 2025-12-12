from datetime import datetime
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
    due_date = db.Column(db.Date, nullable=True)
    known_ransomware = db.Column(db.Boolean, default=False, index=True)
    notes = db.Column(db.Text, nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

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
            'notes': self.notes
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

    def to_dict(self):
        return {
            'id': self.id,
            'product': self.product.to_dict(),
            'vulnerability': self.vulnerability.to_dict(),
            'match_reason': self.match_reason,
            'acknowledged': self.acknowledged,
            'created_at': self.created_at.isoformat() if self.created_at else None
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
