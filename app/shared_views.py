"""
Shared Views Model and API
Allows users to share filtered vulnerability views with other authenticated users
"""

from app import db
from datetime import datetime
import uuid

class SharedView(db.Model):
    """Represents a shareable filtered view of vulnerabilities"""
    __tablename__ = 'shared_views'

    id = db.Column(db.Integer, primary_key=True)
    share_token = db.Column(db.String(50), unique=True, nullable=False, index=True)
    name = db.Column(db.String(200), nullable=True)
    description = db.Column(db.Text, nullable=True)

    # Owner information
    created_by = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    organization_id = db.Column(db.Integer, db.ForeignKey('organizations.id'), nullable=True)

    # Filter configuration (stored as JSON)
    filter_priority = db.Column(db.String(20), nullable=True)
    filter_severity = db.Column(db.String(20), nullable=True)
    filter_urgency = db.Column(db.String(20), nullable=True)
    filter_age = db.Column(db.String(20), nullable=True)
    filter_cve = db.Column(db.String(100), nullable=True)
    filter_vendor = db.Column(db.String(200), nullable=True)
    filter_product = db.Column(db.String(200), nullable=True)
    filter_ransomware = db.Column(db.Boolean, default=False)
    filter_unack = db.Column(db.Boolean, default=False)

    # Access control
    is_public = db.Column(db.Boolean, default=False)  # If True, any authenticated user can access
    allowed_organizations = db.Column(db.Text, nullable=True)  # JSON array of org IDs

    # Metadata
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    expires_at = db.Column(db.DateTime, nullable=True)
    access_count = db.Column(db.Integer, default=0)
    last_accessed = db.Column(db.DateTime, nullable=True)
    is_active = db.Column(db.Boolean, default=True, index=True)

    # Relationships
    creator = db.relationship('User', foreign_keys=[created_by], backref='shared_views')

    @staticmethod
    def generate_token():
        """Generate a unique share token"""
        return str(uuid.uuid4())[:8]  # 8 character token

    def to_dict(self):
        """Convert to dictionary for JSON serialization"""
        return {
            'id': self.id,
            'share_token': self.share_token,
            'name': self.name,
            'description': self.description,
            'created_by': self.created_by,
            'creator_username': self.creator.username if self.creator else None,
            'organization_id': self.organization_id,
            'filters': {
                'priority': self.filter_priority,
                'severity': self.filter_severity,
                'urgency': self.filter_urgency,
                'age': self.filter_age,
                'cve': self.filter_cve,
                'vendor': self.filter_vendor,
                'product': self.filter_product,
                'ransomware': self.filter_ransomware,
                'unack': self.filter_unack
            },
            'is_public': self.is_public,
            'created_at': self.created_at.isoformat() if self.created_at else None,
            'expires_at': self.expires_at.isoformat() if self.expires_at else None,
            'access_count': self.access_count,
            'last_accessed': self.last_accessed.isoformat() if self.last_accessed else None,
            'is_active': self.is_active
        }

    def get_share_url(self, base_url=''):
        """Get the full shareable URL"""
        return f"{base_url}/shared/{self.share_token}"
