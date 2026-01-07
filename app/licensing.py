"""
SentriKat Licensing System

Two tiers:
- Community (free): 3 users, 1 org, 20 products, no LDAP/alerts/API
- Professional (paid): Unlimited, all features

License keys are RSA-signed JSON payloads that can be validated offline.
"""

import json
import base64
import logging
from datetime import datetime, date
from functools import wraps
from flask import g, jsonify, session

logger = logging.getLogger(__name__)

# RSA Public Key for license validation (embedded in app)
# The private key is kept secure by the vendor for generating licenses
LICENSE_PUBLIC_KEY = """-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA0Z3VS5JJcds3xfn/ygWy
Qa7hLPj5HQmcKw3HqjpHBxWKxGjnSfvldrUmpFKez1GiWCUxpapqAUCmhHzT7BpE
xMGBn9L4v8Y9pxJjKhUgM3JnSVv4E0EFBWV0zqMZKq4hE5N/gvLMZGm8JVXoYQpo
qSNv9b3qJEZN/psh0HfRkKjUKo1jTBVfLMgqDJHE2N9E6VWlzKY9Tz3FbZr+Fn0V
5kf8MqNx0kHLQ8gEp0pjHfZ7Q8vtLwB2nPkDO5kLyBBq0tKbPMVYz5dEQfG3MZ0x
VavvfGBkI0h1PzVfE5JNpNvl7RE8bScx1Z3fLL7z7uLSoUQX5fR7vnKu5kPkac7j
pwIDAQAB
-----END PUBLIC KEY-----"""

# License tiers and their limits
LICENSE_TIERS = {
    'community': {
        'name': 'Community',
        'max_users': 3,
        'max_organizations': 1,
        'max_products': 20,
        'features': [],  # No premium features
        'powered_by_required': True
    },
    'professional': {
        'name': 'Professional',
        'max_users': -1,  # Unlimited
        'max_organizations': -1,
        'max_products': -1,
        'features': [
            'ldap',
            'email_alerts',
            'white_label',
            'api_access',
            'backup_restore',
            'audit_export',
            'multi_org'
        ],
        'powered_by_required': False
    }
}

# Features that require Professional license
PROFESSIONAL_FEATURES = [
    'ldap',
    'email_alerts',
    'white_label',
    'api_access',
    'backup_restore',
    'audit_export',
    'multi_org'
]


class LicenseInfo:
    """Holds current license information"""

    def __init__(self):
        self.edition = 'community'
        self.customer = None
        self.email = None
        self.license_id = None
        self.issued_at = None
        self.expires_at = None
        self.max_users = 3
        self.max_organizations = 1
        self.max_products = 20
        self.features = []
        self.is_valid = False
        self.is_expired = False
        self.days_until_expiry = None
        self.error = None

    def has_feature(self, feature):
        """Check if license includes a specific feature"""
        if self.edition == 'professional':
            return True
        return feature in self.features

    def is_professional(self):
        """Check if this is a Professional license"""
        return self.edition == 'professional' and self.is_valid and not self.is_expired

    def check_limit(self, limit_type, current_count):
        """
        Check if a limit is exceeded
        Returns: (allowed: bool, limit: int, message: str)
        """
        limits = {
            'users': self.max_users,
            'organizations': self.max_organizations,
            'products': self.max_products
        }

        limit = limits.get(limit_type, 0)
        if limit == -1:  # Unlimited
            return True, -1, None

        if current_count >= limit:
            return False, limit, f'Community license limit: {limit} {limit_type} maximum. Upgrade to Professional for unlimited.'

        return True, limit, None

    def to_dict(self):
        """Convert to dictionary for API responses"""
        return {
            'edition': self.edition,
            'edition_name': LICENSE_TIERS.get(self.edition, {}).get('name', 'Unknown'),
            'customer': self.customer,
            'license_id': self.license_id,
            'is_valid': self.is_valid,
            'is_expired': self.is_expired,
            'is_professional': self.is_professional(),
            'expires_at': self.expires_at.isoformat() if self.expires_at else None,
            'days_until_expiry': self.days_until_expiry,
            'limits': {
                'max_users': self.max_users,
                'max_organizations': self.max_organizations,
                'max_products': self.max_products
            },
            'features': self.features if self.edition == 'professional' else [],
            'powered_by_required': LICENSE_TIERS.get(self.edition, {}).get('powered_by_required', True),
            'error': self.error
        }


# Global license instance
_current_license = None


def get_license():
    """Get current license info"""
    global _current_license
    if _current_license is None:
        _current_license = load_license()
    return _current_license


def reload_license():
    """Force reload license from database"""
    global _current_license
    _current_license = load_license()
    return _current_license


def load_license():
    """Load and validate license from database"""
    from app.models import SystemSettings

    license_info = LicenseInfo()

    try:
        # Get license key from database
        setting = SystemSettings.query.filter_by(key='license_key').first()

        if not setting or not setting.value:
            logger.info("No license key found, using Community edition")
            return license_info

        # Validate the license
        license_info = validate_license(setting.value)

    except Exception as e:
        logger.error(f"Error loading license: {e}")
        license_info.error = str(e)

    return license_info


def validate_license(license_key):
    """
    Validate a license key and return LicenseInfo

    License format: base64(json_payload).base64(signature)
    """
    license_info = LicenseInfo()

    try:
        # For development/testing: check for special dev key
        if license_key == 'SENTRIKAT-DEV-PROFESSIONAL':
            license_info.edition = 'professional'
            license_info.customer = 'Development'
            license_info.license_id = 'DEV-001'
            license_info.is_valid = True
            license_info.max_users = -1
            license_info.max_organizations = -1
            license_info.max_products = -1
            license_info.features = PROFESSIONAL_FEATURES
            logger.info("Development license activated")
            return license_info

        # Split license key into payload and signature
        parts = license_key.strip().split('.')
        if len(parts) != 2:
            license_info.error = 'Invalid license format'
            return license_info

        payload_b64, signature_b64 = parts

        # Decode payload
        try:
            payload_json = base64.urlsafe_b64decode(payload_b64 + '==').decode('utf-8')
            payload = json.loads(payload_json)
        except Exception as e:
            license_info.error = f'Failed to decode license: {e}'
            return license_info

        # Verify signature
        try:
            from cryptography.hazmat.primitives import hashes, serialization
            from cryptography.hazmat.primitives.asymmetric import padding
            from cryptography.hazmat.backends import default_backend

            # Load public key
            public_key = serialization.load_pem_public_key(
                LICENSE_PUBLIC_KEY.encode(),
                backend=default_backend()
            )

            # Decode signature
            signature = base64.urlsafe_b64decode(signature_b64 + '==')

            # Verify
            public_key.verify(
                signature,
                payload_json.encode(),
                padding.PKCS1v15(),
                hashes.SHA256()
            )

        except Exception as e:
            license_info.error = f'License signature invalid: {e}'
            logger.warning(f"License validation failed: {e}")
            return license_info

        # Parse license data
        license_info.license_id = payload.get('license_id')
        license_info.customer = payload.get('customer')
        license_info.email = payload.get('email')
        license_info.edition = payload.get('edition', 'community')

        # Parse dates
        if payload.get('issued_at'):
            license_info.issued_at = datetime.fromisoformat(payload['issued_at']).date()

        if payload.get('expires_at'):
            license_info.expires_at = datetime.fromisoformat(payload['expires_at']).date()
            days_left = (license_info.expires_at - date.today()).days
            license_info.days_until_expiry = days_left
            license_info.is_expired = days_left < 0

        # Set limits based on edition
        tier = LICENSE_TIERS.get(license_info.edition, LICENSE_TIERS['community'])
        limits = payload.get('limits', {})

        license_info.max_users = limits.get('max_users', tier['max_users'])
        license_info.max_organizations = limits.get('max_organizations', tier['max_organizations'])
        license_info.max_products = limits.get('max_products', tier['max_products'])
        license_info.features = payload.get('features', tier['features'])

        # Mark as valid
        license_info.is_valid = True

        if license_info.is_expired:
            logger.warning(f"License {license_info.license_id} has expired")
        else:
            logger.info(f"License validated: {license_info.edition} edition for {license_info.customer}")

    except Exception as e:
        license_info.error = f'License validation error: {e}'
        logger.error(f"License validation error: {e}")

    return license_info


def save_license(license_key):
    """Save license key to database and reload"""
    from app.models import SystemSettings
    from app import db

    # Validate first
    license_info = validate_license(license_key)

    if not license_info.is_valid:
        return False, license_info.error or 'Invalid license key'

    if license_info.is_expired:
        return False, f'License has expired on {license_info.expires_at}'

    # Save to database
    setting = SystemSettings.query.filter_by(key='license_key').first()
    if setting:
        setting.value = license_key
    else:
        setting = SystemSettings(
            key='license_key',
            value=license_key,
            category='licensing',
            description='SentriKat license key'
        )
        db.session.add(setting)

    db.session.commit()

    # Reload global license
    reload_license()

    return True, f'License activated: {license_info.edition.title()} edition for {license_info.customer}'


def remove_license():
    """Remove license and revert to Community"""
    from app.models import SystemSettings
    from app import db

    setting = SystemSettings.query.filter_by(key='license_key').first()
    if setting:
        db.session.delete(setting)
        db.session.commit()

    reload_license()
    return True, 'License removed. Reverted to Community edition.'


# ============================================================================
# Feature Gating Decorators
# ============================================================================

def requires_professional(feature=None):
    """
    Decorator to require Professional license for a route

    Usage:
        @requires_professional()
        def my_route():
            ...

        @requires_professional('ldap')
        def ldap_config():
            ...
    """
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            license_info = get_license()

            if not license_info.is_professional():
                feature_name = feature or 'This feature'
                return jsonify({
                    'error': f'{feature_name} requires a Professional license',
                    'license_required': True,
                    'current_edition': license_info.edition,
                    'upgrade_message': 'Upgrade to Professional to unlock all features'
                }), 403

            return f(*args, **kwargs)
        return decorated_function
    return decorator


def check_user_limit():
    """Check if user limit is reached"""
    from app.models import User

    license_info = get_license()
    current_users = User.query.filter_by(is_active=True).count()

    return license_info.check_limit('users', current_users)


def check_org_limit():
    """Check if organization limit is reached"""
    from app.models import Organization

    license_info = get_license()
    current_orgs = Organization.query.count()

    return license_info.check_limit('organizations', current_orgs)


def check_product_limit():
    """Check if product limit is reached"""
    from app.models import Product

    license_info = get_license()
    current_products = Product.query.count()

    return license_info.check_limit('products', current_products)


# ============================================================================
# License API Routes
# ============================================================================

from flask import Blueprint
from app import csrf

license_bp = Blueprint('license', __name__)

# Exempt license API from CSRF (uses JSON and session auth)
csrf.exempt(license_bp)


@license_bp.route('/api/license', methods=['GET'])
def get_license_info():
    """Get current license information"""
    from app.auth import get_current_user

    user = get_current_user()
    if not user:
        return jsonify({'error': 'Authentication required'}), 401

    license_info = get_license()

    # Get current usage
    from app.models import User, Organization, Product

    response = license_info.to_dict()
    response['usage'] = {
        'users': User.query.filter_by(is_active=True).count(),
        'organizations': Organization.query.count(),
        'products': Product.query.count()
    }

    return jsonify(response)


@license_bp.route('/api/license', methods=['POST'])
def activate_license():
    """Activate a license key"""
    from flask import request
    from app.auth import get_current_user
    from app.logging_config import log_audit_event

    user = get_current_user()
    if not user or not user.is_super_admin():
        return jsonify({'error': 'Super admin access required'}), 403

    data = request.get_json()
    license_key = data.get('license_key', '').strip()

    if not license_key:
        return jsonify({'error': 'License key is required'}), 400

    success, message = save_license(license_key)

    if success:
        log_audit_event('UPDATE', 'license', details=f'License activated: {message}')
        license_info = get_license()
        return jsonify({
            'success': True,
            'message': message,
            'license': license_info.to_dict()
        })
    else:
        return jsonify({'error': message}), 400


@license_bp.route('/api/license', methods=['DELETE'])
def deactivate_license():
    """Remove license and revert to Community"""
    from app.auth import get_current_user
    from app.logging_config import log_audit_event

    user = get_current_user()
    if not user or not user.is_super_admin():
        return jsonify({'error': 'Super admin access required'}), 403

    success, message = remove_license()

    log_audit_event('UPDATE', 'license', details='License removed, reverted to Community')

    return jsonify({
        'success': True,
        'message': message,
        'license': get_license().to_dict()
    })
