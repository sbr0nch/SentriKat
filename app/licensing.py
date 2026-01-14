"""
SentriKat Licensing System

Two tiers:
- Community (free): 3 users, 1 org, 20 products, no LDAP/alerts/API
- Professional (paid): Unlimited, all features

License keys are RSA-signed JSON payloads that can be validated offline.
Single-use validation: Each license tracks activations and can limit installations.
"""

import json
import base64
import hashlib
import logging
import os
import uuid
import socket
from datetime import datetime, date
from functools import wraps
from flask import g, jsonify, session, request

logger = logging.getLogger(__name__)

# Installation ID file path (persists across restarts)
INSTALLATION_ID_FILE = os.path.join(os.path.dirname(os.path.dirname(__file__)), 'data', '.installation_id')

# RSA Public Key for license validation (embedded in app)
# The private key is kept secure by the vendor for generating licenses
LICENSE_PUBLIC_KEY = """-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA3vVRIgzYRX3ikhfymPhO
E2Sl13baVqnqUgWt+vwXRxNek114ToNZaOfka75HxD7bHFq6+nGscUyp+I6Uq0l5
YXYCqeA9euHhWS/uH367xOo3J2tugH+9jMxHUlnOVD+XpUv9TShePwwWIN7h5jWs
TWGHjF0yg+nOb1NjHf9UBYLhATNHsoajWEFptYlr8YtbmeegC6m3+6fF9mB0PdN9
Lp+Ty4P6GfcuCkGA1GIAFNquN+W4x1Q47n0zj7TJ/wwy4cDe2TTIRi+2xosmdXs4
jMD7apb2qLXSRm6ZHkUTw/8O1r4FrSrIIg7Yz1dpHCrs7kCafpBEQOEUobdm65TX
rwIDAQAB
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


# ============================================================================
# Installation Fingerprint Generation
# ============================================================================

def get_installation_id():
    """
    Get or generate a unique installation ID for this instance.
    This ID is persisted to disk and survives restarts.
    Used to track license activations and prevent unauthorized sharing.
    """
    # Try to load existing ID
    if os.path.exists(INSTALLATION_ID_FILE):
        try:
            with open(INSTALLATION_ID_FILE, 'r') as f:
                installation_id = f.read().strip()
                if installation_id and len(installation_id) == 64:
                    return installation_id
        except Exception as e:
            logger.warning(f"Could not read installation ID: {e}")

    # Generate new installation ID based on machine characteristics
    installation_id = _generate_installation_fingerprint()

    # Save to file
    try:
        # Ensure data directory exists
        data_dir = os.path.dirname(INSTALLATION_ID_FILE)
        if data_dir and not os.path.exists(data_dir):
            os.makedirs(data_dir, exist_ok=True)

        with open(INSTALLATION_ID_FILE, 'w') as f:
            f.write(installation_id)
        logger.info(f"Generated new installation ID: {installation_id[:12]}...")
    except Exception as e:
        logger.error(f"Could not save installation ID: {e}")

    return installation_id


def _generate_installation_fingerprint():
    """
    Generate a unique fingerprint for this installation.
    Combines multiple factors to create a stable identifier.
    """
    fingerprint_parts = []

    # Machine-specific identifiers
    try:
        # Hostname
        fingerprint_parts.append(socket.gethostname())
    except:
        pass

    try:
        # MAC address (if available)
        mac = uuid.getnode()
        if mac != uuid.getnode():  # Verify it's stable
            fingerprint_parts.append(str(mac))
        else:
            fingerprint_parts.append(str(mac))
    except:
        pass

    try:
        # Database file path (unique per installation)
        from config import Config
        fingerprint_parts.append(Config.SQLALCHEMY_DATABASE_URI or '')
    except:
        pass

    try:
        # Secret key (unique per installation if properly configured)
        from flask import current_app
        if current_app and current_app.config.get('SECRET_KEY'):
            fingerprint_parts.append(current_app.config['SECRET_KEY'][:16])
    except:
        pass

    # Add a random component for truly unique ID
    fingerprint_parts.append(str(uuid.uuid4()))

    # Combine and hash
    fingerprint_string = '|'.join(str(p) for p in fingerprint_parts)
    return hashlib.sha256(fingerprint_string.encode()).hexdigest()


def hash_license_key(license_key):
    """Generate SHA256 hash of license key for storage (don't store the key itself)"""
    return hashlib.sha256(license_key.encode()).hexdigest()


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
        self.expiration_reason = None  # 'expired', 'grace_period', etc.

        # Activation tracking fields
        self.max_activations = 1  # Default: single-use license
        self.current_activations = 0
        self.activation_exceeded = False
        self.installation_id = None
        self.activation_info = None  # Current activation record

    def get_effective_edition(self):
        """
        Get the effective edition considering expiration.
        Expired licenses revert to Community behavior.
        """
        if self.is_expired:
            return 'community'
        if not self.is_valid:
            return 'community'
        return self.edition

    def get_effective_limits(self):
        """
        Get effective limits considering expiration.
        Expired Professional licenses get Community limits.
        """
        effective_edition = self.get_effective_edition()
        if effective_edition == 'community':
            return {
                'max_users': LICENSE_TIERS['community']['max_users'],
                'max_organizations': LICENSE_TIERS['community']['max_organizations'],
                'max_products': LICENSE_TIERS['community']['max_products']
            }
        return {
            'max_users': self.max_users,
            'max_organizations': self.max_organizations,
            'max_products': self.max_products
        }

    def has_feature(self, feature):
        """
        Check if license includes a specific feature.
        Expired licenses lose all premium features.
        """
        effective_edition = self.get_effective_edition()
        if effective_edition == 'professional':
            return True
        return False  # Community has no premium features

    def is_professional(self):
        """
        Check if this is an active Professional license.
        Returns False if expired, invalid, or Community.
        """
        return (
            self.edition == 'professional' and
            self.is_valid and
            not self.is_expired
        )

    def check_limit(self, limit_type, current_count):
        """
        Check if a limit is exceeded.
        Uses effective limits (Community limits if expired).
        Returns: (allowed: bool, limit: int, message: str)
        """
        effective_limits = self.get_effective_limits()

        limit_map = {
            'users': effective_limits['max_users'],
            'organizations': effective_limits['max_organizations'],
            'products': effective_limits['max_products']
        }

        limit = limit_map.get(limit_type, 0)
        if limit == -1:  # Unlimited
            return True, -1, None

        if current_count >= limit:
            if self.is_expired:
                return False, limit, f'License expired. Community limit: {limit} {limit_type} maximum. Please renew your license.'
            return False, limit, f'Community license limit: {limit} {limit_type} maximum. Upgrade to Professional for unlimited.'

        return True, limit, None

    def get_status_message(self):
        """Get a human-readable status message"""
        if not self.is_valid and self.error:
            return f'Invalid license: {self.error}'
        if self.is_expired:
            return f'License expired on {self.expires_at}. Reverted to Community edition.'
        if self.days_until_expiry is not None and self.days_until_expiry <= 30:
            return f'License expires in {self.days_until_expiry} days'
        if self.is_professional():
            return f'Professional license active for {self.customer}'
        return 'Community edition'

    def to_dict(self):
        """Convert to dictionary for API responses"""
        effective_limits = self.get_effective_limits()
        effective_edition = self.get_effective_edition()

        return {
            'edition': self.edition,
            'effective_edition': effective_edition,
            'edition_name': LICENSE_TIERS.get(effective_edition, {}).get('name', 'Unknown'),
            'customer': self.customer,
            'license_id': self.license_id,
            'is_valid': self.is_valid,
            'is_expired': self.is_expired,
            'is_professional': self.is_professional(),
            'expires_at': self.expires_at.isoformat() if self.expires_at else None,
            'days_until_expiry': self.days_until_expiry,
            'status_message': self.get_status_message(),
            'limits': effective_limits,
            'original_limits': {
                'max_users': self.max_users,
                'max_organizations': self.max_organizations,
                'max_products': self.max_products
            },
            'features': PROFESSIONAL_FEATURES if self.is_professional() else [],
            'powered_by_required': not self.is_professional(),
            'error': self.error,
            # Activation tracking
            'activation': {
                'max_activations': self.max_activations,
                'current_activations': self.current_activations,
                'activation_exceeded': self.activation_exceeded,
                'installation_id': self.installation_id[:12] + '...' if self.installation_id else None,
                'is_single_use': self.max_activations == 1
            }
        }


# Global license instance - ALWAYS reload from DB to ensure consistency
_current_license = None
_license_load_time = None
LICENSE_CACHE_SECONDS = 5  # Only cache for 5 seconds to reduce DB queries


def get_license():
    """
    Get current license info.
    Always reads from database to ensure consistency across workers/requests.
    Short cache to reduce DB queries within the same request.
    """
    global _current_license, _license_load_time

    # Check if we need to reload (cache expired or never loaded)
    now = datetime.utcnow()
    if (_current_license is None or
        _license_load_time is None or
        (now - _license_load_time).total_seconds() > LICENSE_CACHE_SECONDS):
        _current_license = load_license()
        _license_load_time = now

    return _current_license


def reload_license():
    """Force reload license from database"""
    global _current_license, _license_load_time
    _current_license = load_license()
    _license_load_time = datetime.utcnow()
    return _current_license


def load_license():
    """
    Load and validate license from database or environment.

    Priority: Database > Environment Variable (SENTRIKAT_LICENSE)
    This allows containerized deployments to set license via env.

    Also checks activation status for single-use validation.
    """
    from app.models import SystemSettings, LicenseActivation

    license_info = LicenseInfo()
    license_key = None
    source = None

    try:
        # First, check database
        setting = SystemSettings.query.filter_by(key='license_key').first()
        if setting and setting.value:
            license_key = setting.value
            source = 'database'
            logger.debug(f"License found in database: {len(license_key)} chars")
        else:
            # Fallback to environment variable
            env_key = os.environ.get('SENTRIKAT_LICENSE')
            if env_key:
                license_key = env_key
                source = 'environment'
                logger.info("License loaded from SENTRIKAT_LICENSE environment variable")

        if not license_key:
            logger.debug("No license key found, using Community edition")
            return license_info

        # Validate the license
        license_info = validate_license(license_key)
        license_info.source = source  # Track where license came from

        # Add installation ID
        license_info.installation_id = get_installation_id()

        # Check activation status if license is valid
        if license_info.is_valid and license_info.license_id:
            license_key_hash = hash_license_key(license_key)
            activation_status = check_activation_status(
                license_info.license_id,
                license_key_hash,
                license_info.max_activations
            )
            license_info.current_activations = activation_status['current_activations']
            license_info.activation_exceeded = activation_status['exceeded']
            license_info.activation_info = activation_status['current_activation']

            # If activation limit exceeded and not this installation, mark as invalid
            if activation_status['exceeded'] and not activation_status['is_current_installation']:
                license_info.is_valid = False
                license_info.error = f"License activation limit exceeded ({activation_status['current_activations']}/{license_info.max_activations}). This license is active on another installation."

    except Exception as e:
        logger.error(f"Error loading license: {e}", exc_info=True)
        license_info.error = str(e)

    return license_info


def ensure_activation_table_exists():
    """Ensure the license_activations table exists."""
    try:
        from app import db
        from sqlalchemy import inspect
        inspector = inspect(db.engine)
        if 'license_activations' not in inspector.get_table_names():
            from app.models import LicenseActivation
            LicenseActivation.__table__.create(db.engine)
            logger.info("Created license_activations table")
    except Exception as e:
        logger.warning(f"Could not ensure activation table exists: {e}")


def check_activation_status(license_id, license_key_hash, max_activations):
    """
    Check activation status for a license.
    Returns dict with activation details.
    """
    from app.models import LicenseActivation

    # Ensure table exists
    try:
        ensure_activation_table_exists()
    except:
        pass

    installation_id = get_installation_id()

    # Get all active activations for this license
    activations = LicenseActivation.query.filter_by(
        license_id=license_id,
        is_active=True
    ).all()

    current_activations = len(activations)

    # Check if this installation is already activated
    current_activation = None
    is_current_installation = False
    for activation in activations:
        if activation.installation_id == installation_id:
            current_activation = activation.to_dict()
            is_current_installation = True
            break

    # Check if exceeded
    exceeded = False
    if max_activations > 0:  # -1 means unlimited
        if current_activations >= max_activations and not is_current_installation:
            exceeded = True

    return {
        'current_activations': current_activations,
        'max_activations': max_activations,
        'exceeded': exceeded,
        'is_current_installation': is_current_installation,
        'current_activation': current_activation,
        'all_activations': [a.to_dict() for a in activations]
    }


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

        # Parse activation limits (default: 1 = single-use, -1 = unlimited)
        license_info.max_activations = payload.get('max_activations', 1)

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
    """
    Save license key to database, validate activation limits, and create activation record.

    Returns: (success: bool, message: str)
    """
    from app.models import SystemSettings, LicenseActivation
    from app import db

    # Validate first
    license_info = validate_license(license_key)

    if not license_info.is_valid:
        return False, license_info.error or 'Invalid license key'

    if license_info.is_expired:
        return False, f'License has expired on {license_info.expires_at}'

    # Check activation limits before saving
    installation_id = get_installation_id()
    license_key_hash = hash_license_key(license_key)

    # Ensure activation table exists
    ensure_activation_table_exists()

    # Check existing activations for this license
    existing_activations = LicenseActivation.query.filter_by(
        license_id=license_info.license_id,
        is_active=True
    ).all()

    # Check if this installation is already activated
    current_activation = None
    for activation in existing_activations:
        if activation.installation_id == installation_id:
            current_activation = activation
            break

    # If not already activated, check limits
    if not current_activation:
        max_activations = license_info.max_activations
        if max_activations > 0:  # -1 means unlimited
            if len(existing_activations) >= max_activations:
                # Provide details about existing activations
                activation_details = []
                for act in existing_activations:
                    activation_details.append(f"- {act.hostname or 'Unknown'} (activated {act.first_activated_at.strftime('%Y-%m-%d') if act.first_activated_at else 'unknown'})")

                details_str = '\n'.join(activation_details) if activation_details else 'No details available'
                return False, (
                    f"License activation limit reached ({len(existing_activations)}/{max_activations}).\n"
                    f"This license is already activated on:\n{details_str}\n\n"
                    f"Please deactivate one of the existing installations or contact support for additional licenses."
                )

    # Save license key to database
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

    # Create or update activation record
    try:
        hostname = socket.gethostname()
    except:
        hostname = 'Unknown'

    # Try to get IP address
    ip_address = None
    try:
        from flask import request
        if request:
            ip_address = request.remote_addr
    except:
        pass

    if current_activation:
        # Update existing activation
        current_activation.license_key_hash = license_key_hash
        current_activation.last_seen_at = datetime.utcnow()
        current_activation.activation_count += 1
        current_activation.hostname = hostname
        if ip_address:
            current_activation.ip_address = ip_address
        logger.info(f"Updated activation record for license {license_info.license_id}")
    else:
        # Create new activation
        new_activation = LicenseActivation(
            license_id=license_info.license_id,
            license_key_hash=license_key_hash,
            installation_id=installation_id,
            customer=license_info.customer,
            edition=license_info.edition,
            hostname=hostname,
            ip_address=ip_address,
            is_active=True,
            first_activated_at=datetime.utcnow(),
            last_seen_at=datetime.utcnow(),
            activation_count=1
        )
        db.session.add(new_activation)
        logger.info(f"Created new activation record for license {license_info.license_id}")

    db.session.commit()

    # Reload global license
    reload_license()

    activation_msg = ""
    if license_info.max_activations > 0:
        current_count = len(existing_activations) + (0 if current_activation else 1)
        activation_msg = f" (Activation {current_count}/{license_info.max_activations})"

    return True, f'License activated: {license_info.edition.title()} edition for {license_info.customer}{activation_msg}'


def remove_license():
    """
    Remove license and revert to Community.
    Marks the activation as deactivated to free up the license slot.
    """
    from app.models import SystemSettings, LicenseActivation
    from app import db

    installation_id = get_installation_id()

    # First, get the current license to find the activation record
    setting = SystemSettings.query.filter_by(key='license_key').first()
    if setting and setting.value:
        # Mark activation as deactivated
        license_info = validate_license(setting.value)
        if license_info.license_id:
            activation = LicenseActivation.query.filter_by(
                license_id=license_info.license_id,
                installation_id=installation_id,
                is_active=True
            ).first()

            if activation:
                activation.is_active = False
                activation.deactivated_at = datetime.utcnow()
                activation.deactivation_reason = 'Manual removal by admin'
                logger.info(f"Deactivated license {license_info.license_id} on this installation")

    # Remove license key
    if setting:
        db.session.delete(setting)

    db.session.commit()

    reload_license()
    return True, 'License removed and deactivated. Reverted to Community edition.'


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


@license_bp.route('/api/license/activations', methods=['GET'])
def get_license_activations():
    """Get all activations for the current license"""
    from app.auth import get_current_user
    from app.models import LicenseActivation

    user = get_current_user()
    if not user or not user.is_super_admin():
        return jsonify({'error': 'Super admin access required'}), 403

    license_info = get_license()
    if not license_info.license_id:
        return jsonify({
            'activations': [],
            'message': 'No license active'
        })

    # Get all activations (including deactivated for history)
    activations = LicenseActivation.query.filter_by(
        license_id=license_info.license_id
    ).order_by(LicenseActivation.first_activated_at.desc()).all()

    installation_id = get_installation_id()

    return jsonify({
        'license_id': license_info.license_id,
        'max_activations': license_info.max_activations,
        'current_installation_id': installation_id[:12] + '...',
        'activations': [a.to_dict() for a in activations],
        'active_count': sum(1 for a in activations if a.is_active),
        'total_count': len(activations)
    })


@license_bp.route('/api/license/installation', methods=['GET'])
def get_installation_info():
    """Get this installation's ID and details"""
    from app.auth import get_current_user

    user = get_current_user()
    if not user:
        return jsonify({'error': 'Authentication required'}), 401

    installation_id = get_installation_id()

    try:
        hostname = socket.gethostname()
    except:
        hostname = 'Unknown'

    return jsonify({
        'installation_id': installation_id[:12] + '...',  # Partial for privacy
        'full_id': installation_id if user.is_super_admin() else None,
        'hostname': hostname
    })
