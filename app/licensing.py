"""
SentriKat Licensing System

Two tiers:
- Demo (free): 1 user, 1 org, 50 products, 5 agents, no LDAP/SSO/alerts
- Professional (paid): Unlimited users/orgs/products, 10+ agents, all features

License keys are RSA-signed JSON payloads that are hardware-locked.
Each license is tied to a specific installation ID and cannot be used elsewhere.

Agent packs can be purchased to increase agent limits beyond the base 10.
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
from flask import jsonify
from sqlalchemy import func

logger = logging.getLogger(__name__)

# App version (read from VERSION file)
_VERSION_FILE = os.path.join(os.path.dirname(os.path.dirname(__file__)), 'VERSION')

def _get_app_version():
    try:
        with open(_VERSION_FILE, 'r') as f:
            return f.read().strip()
    except Exception:
        return '0.0.0'

# Installation ID file path (persists across restarts)
INSTALLATION_ID_FILE = os.path.join(os.path.dirname(os.path.dirname(__file__)), 'data', '.installation_id')

# Environment variable for fixed installation ID (recommended for Docker)
INSTALLATION_ID_ENV_VAR = 'SENTRIKAT_INSTALLATION_ID'

# Default RSA Public Key - matches the SentriKat-web license server (RSA-4096)
# This is the PUBLIC key used to verify license signatures from portal.sentrikat.com
# Can be overridden via SENTRIKAT_LICENSE_PUBLIC_KEY or SENTRIKAT_LICENSE_PUBLIC_KEY_FILE env vars
_DEFAULT_PUBLIC_KEY = """-----BEGIN PUBLIC KEY-----
MIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEAoby7pyKHNUhXAx4FRoqt
s390fyo/krmgYU2XwxgRm7U9W/kXA+1vEaHPYtehmi0sggefUu4zMaNtr/8dPOS6
XpGZxjPns/+CzpR+mehrjw1ABdEOgFkhnzyAW21ZgT2rHnKSpeCXCrxXz4o65xTr
d5twLQU/dVvK11FvvGbTRxaoPrSLGojAvQ+b3577ym3QGmx716KGjRVxGxXPtl6K
DWu4jLegdNu90NvrJ7lj8yiqPTCbDhwB7JVPBSoIpjegYEZIf5vXhldqNnid7rT3
EL/J/iR+z7rhlss9I2LYioYnCG3qCzMDAjp8wsfPgHmECaexqGY/lzOXtxZyVFnW
fnw/WrMIzuOMDNoG8pGHEq1rz2L2butGd6JOB2u8R4wmUII7lAiCGHMvzWu58770
pQQKasa53nmHo/yAppVtWabJOPHeSdKclyNEThFqXNgjKOUIHLz6fxiMmP22vmAK
mVuNdHbTrgL/59wXdyEMcvN+WQwN1O2sty+VVsCtAjQzyfnFpWJLgQJYFaPZI1e0
nrHoJc31qnCCbbFlBgtzZ8t0WDg9zH/jybZPNJryUXWohLstIoOdbOXn3mxvfCa4
PL86ajCxxRNUMfIkUUuGWBMCT7AvuQ2P5CBccex+u1unbTIca95pbt6Rvv0u81TS
UAClDkq78Bh8tLHSPl9s/nkCAwEAAQ==
-----END PUBLIC KEY-----"""

def get_license_public_key():
    """Get the public key for license validation.

    Priority:
    1. SENTRIKAT_LICENSE_PUBLIC_KEY env var (PEM content directly)
    2. SENTRIKAT_LICENSE_PUBLIC_KEY_FILE env var (path to PEM file)
    3. Default embedded key (matches portal.sentrikat.com)
    """
    # Priority 1: Direct PEM from environment variable
    env_key = os.environ.get('SENTRIKAT_LICENSE_PUBLIC_KEY', '').strip()
    if env_key and '-----BEGIN PUBLIC KEY-----' in env_key:
        logger.debug("Using public key from SENTRIKAT_LICENSE_PUBLIC_KEY env var")
        return env_key

    # Priority 2: File path from environment variable
    env_key_file = os.environ.get('SENTRIKAT_LICENSE_PUBLIC_KEY_FILE', '').strip()
    if env_key_file and os.path.exists(env_key_file):
        try:
            with open(env_key_file, 'r') as f:
                key = f.read().strip()
                if key and '-----BEGIN PUBLIC KEY-----' in key:
                    logger.debug(f"Using public key from SENTRIKAT_LICENSE_PUBLIC_KEY_FILE: {env_key_file}")
                    return key
        except Exception as e:
            logger.warning(f"Could not read public key from SENTRIKAT_LICENSE_PUBLIC_KEY_FILE: {e}")

    # Priority 3: Default embedded key (matches the portal's signing key)
    logger.debug("Using default embedded public key")
    return _DEFAULT_PUBLIC_KEY

# Edition mapping: SentriKat-web uses 'pro'/'demo', SentriKat uses 'professional'/'community'
EDITION_MAP = {
    'pro': 'professional',
    'demo': 'community',
    'professional': 'professional',
    'community': 'community',
}

# License tiers and their limits
# Note: Internal key is 'community' for backwards compatibility, but displayed as 'Demo'
LICENSE_TIERS = {
    'community': {
        'name': 'Demo',  # Changed from 'Demo' - this is a trial/demo version
        'display_name': 'Demo Version',
        'max_users': 1,
        'max_organizations': 1,
        'max_products': 50,
        'max_agents': 5,  # Demo includes 5 agents
        'features': [],
        'powered_by_required': True,
        'is_demo': True
    },
    'professional': {
        'name': 'Professional',
        'display_name': 'Professional License',
        'max_users': -1,  # Unlimited
        'max_organizations': -1,
        'max_products': -1,
        'max_agents': 10,  # Base PRO includes 10 agents (more via agent packs)
        'features': [
            'ldap',
            'email_alerts',
            'white_label',
            'api_access',
            'backup_restore',
            'audit_export',
            'multi_org'
        ],
        'powered_by_required': False,
        'is_demo': False
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
    'multi_org',
    'push_agents',  # Agent deployment feature
    'jira_integration',  # Jira ticket creation
    'compliance_reports'  # CISA BOD 22-01 compliance reports
]


# ============================================================================
# Installation ID - Stable Hardware Fingerprint
# ============================================================================

def _is_docker_environment():
    """
    Detect if running inside a Docker container.
    Uses multiple methods for reliability.
    """
    # Method 1: Check for .dockerenv file
    if os.path.exists('/.dockerenv'):
        return True

    # Method 2: Check cgroup for docker/containerd
    try:
        with open('/proc/1/cgroup', 'r') as f:
            content = f.read()
            if 'docker' in content or 'containerd' in content or 'kubepods' in content:
                return True
    except Exception:
        pass

    # Method 3: Check for container-specific environment variables
    if os.environ.get('KUBERNETES_SERVICE_HOST'):
        return True

    return False


def get_installation_id():
    """
    Get or generate a unique, STABLE installation ID for this instance.
    This ID is persisted to disk and survives restarts.

    Priority order:
    1. SENTRIKAT_INSTALLATION_ID environment variable (recommended for Docker)
    2. Existing ID from file (persists across restarts)
    3. Generate new ID and save to file

    Used for hardware-locked licensing: licenses are tied to this ID.
    """
    # Priority 1: Environment variable (best for Docker - survives rebuilds)
    env_id = os.environ.get(INSTALLATION_ID_ENV_VAR)
    if env_id and len(env_id) >= 16:
        # Normalize format if needed
        if not env_id.startswith('SK-INST-'):
            # Hash the user-provided ID for consistent format
            normalized = f"SK-INST-{hashlib.sha256(env_id.encode()).hexdigest()[:32].upper()}"
            logger.info(f"Using installation ID from environment (normalized): {normalized[:20]}...")
            return normalized
        logger.info(f"Using installation ID from environment: {env_id[:20]}...")
        return env_id

    # Priority 2: Try to load existing ID from file
    if os.path.exists(INSTALLATION_ID_FILE):
        try:
            with open(INSTALLATION_ID_FILE, 'r') as f:
                installation_id = f.read().strip()
                if installation_id and len(installation_id) >= 32:
                    logger.debug(f"Loaded installation ID from file: {installation_id[:20]}...")
                    return installation_id
        except Exception as e:
            logger.warning(f"Could not read installation ID: {e}")

    # Priority 3: Generate new stable installation ID
    is_docker = _is_docker_environment()
    installation_id = _generate_stable_fingerprint(is_docker=is_docker)

    if is_docker:
        logger.warning(
            "Docker environment detected. Installation ID was generated from volatile "
            "container properties. To ensure license persistence across rebuilds, set "
            f"the {INSTALLATION_ID_ENV_VAR} environment variable in your docker-compose.yml"
        )

    # Save to file for persistence
    try:
        data_dir = os.path.dirname(INSTALLATION_ID_FILE)
        if data_dir and not os.path.exists(data_dir):
            os.makedirs(data_dir, exist_ok=True)

        with open(INSTALLATION_ID_FILE, 'w') as f:
            f.write(installation_id)

        logger.info(f"Generated and saved installation ID: {installation_id[:20]}...")
    except Exception as e:
        logger.error(f"Could not save installation ID: {e}")

    return installation_id


def _generate_stable_fingerprint(is_docker=False):
    """
    Generate a stable fingerprint for this installation.

    In Docker environments:
    - Uses database URI hash (stable across rebuilds)
    - Uses volume mount paths
    - Adds random component saved to file for uniqueness

    In bare-metal/VM environments:
    - Uses MAC address (hardware)
    - Uses hostname
    - Uses database URI hash
    """
    fingerprint_parts = []

    if is_docker:
        # Docker-specific: Use only stable identifiers
        # Database URI is stable in Docker (defined in docker-compose.yml)
        try:
            from config import Config
            db_uri = Config.SQLALCHEMY_DATABASE_URI or ''
            # Use more of the hash for uniqueness
            db_hash = hashlib.sha256(db_uri.encode()).hexdigest()[:24]
            fingerprint_parts.append(f"db:{db_hash}")
        except Exception:
            fingerprint_parts.append("db:unknown")

        # Add data directory path (stable mount point)
        data_dir = os.path.dirname(INSTALLATION_ID_FILE)
        if data_dir:
            fingerprint_parts.append(f"data:{data_dir}")

        # Add a random component for uniqueness (but save it for consistency)
        random_file = os.path.join(os.path.dirname(INSTALLATION_ID_FILE), '.instance_random')
        random_component = None
        if os.path.exists(random_file):
            try:
                with open(random_file, 'r') as f:
                    random_component = f.read().strip()
            except Exception:
                pass

        if not random_component:
            random_component = uuid.uuid4().hex[:16]
            try:
                data_dir = os.path.dirname(random_file)
                if data_dir and not os.path.exists(data_dir):
                    os.makedirs(data_dir, exist_ok=True)
                with open(random_file, 'w') as f:
                    f.write(random_component)
            except Exception as e:
                logger.warning(
                    f"Could not persist installation ID random component to {random_file}: {e}. "
                    f"Installation ID may change on container restart. "
                    f"Set SENTRIKAT_INSTALLATION_ID in .env to avoid this."
                )

        fingerprint_parts.append(f"rand:{random_component}")

    else:
        # Bare-metal/VM: Use hardware identifiers
        # MAC address - stable hardware identifier
        try:
            mac = uuid.getnode()
            fingerprint_parts.append(f"mac:{mac}")
        except Exception:
            fingerprint_parts.append("mac:unknown")

        # Hostname
        try:
            hostname = socket.gethostname()
            fingerprint_parts.append(f"host:{hostname}")
        except Exception:
            fingerprint_parts.append("host:unknown")

        # Database URI - unique per installation
        try:
            from config import Config
            db_uri = Config.SQLALCHEMY_DATABASE_URI or ''
            db_hash = hashlib.sha256(db_uri.encode()).hexdigest()[:16]
            fingerprint_parts.append(f"db:{db_hash}")
        except Exception:
            fingerprint_parts.append("db:unknown")

    # Combine and create final hash
    fingerprint_string = '|'.join(fingerprint_parts)
    full_hash = hashlib.sha256(fingerprint_string.encode()).hexdigest()

    # Format as readable installation ID: SK-INST-XXXXXXXX...
    return f"SK-INST-{full_hash[:32].upper()}"


def get_installation_id_display():
    """Get installation ID formatted for display to users."""
    inst_id = get_installation_id()
    # Return full ID for license requests
    return inst_id


# ============================================================================
# License Info Class
# ============================================================================

class LicenseInfo:
    """Holds current license information"""

    def __init__(self):
        self.edition = 'community'
        self.customer = None
        self.email = None
        self.license_id = None
        self.issued_at = None
        self.expires_at = None
        self.max_users = 1
        self.max_organizations = 1
        self.max_products = 50
        # Agent limits (from signed license - tamper-proof)
        self.max_agents = 5  # Demo = 5 agents (PRO has 10+ with agent packs)
        self.max_agent_api_keys = 0
        self.features = []
        self.is_valid = False
        self.is_expired = False
        self.days_until_expiry = None
        self.error = None
        self.licensed_installation_id = None  # The installation ID this license is for
        self.is_hardware_match = False  # Does license match this installation?

    def get_effective_edition(self):
        """Get the effective edition considering expiration and hardware match."""
        if self.is_expired:
            return 'community'
        if not self.is_valid:
            return 'community'
        if not self.is_hardware_match:
            return 'community'
        return self.edition

    def get_effective_limits(self):
        """Get effective limits based on license status."""
        effective_edition = self.get_effective_edition()
        if effective_edition == 'community':
            return {
                'max_users': LICENSE_TIERS['community']['max_users'],
                'max_organizations': LICENSE_TIERS['community']['max_organizations'],
                'max_products': LICENSE_TIERS['community']['max_products'],
                'max_agents': LICENSE_TIERS['community']['max_agents'],  # Demo: 5 agents
                'max_agent_api_keys': 5  # Demo: 5 API keys
            }
        return {
            'max_users': self.max_users,
            'max_organizations': self.max_organizations,
            'max_products': self.max_products,
            'max_agents': self.max_agents,
            'max_agent_api_keys': self.max_agent_api_keys
        }

    def has_feature(self, feature):
        """Check if license includes a specific feature."""
        if not self.is_professional():
            return False
        return feature in self.features if self.features else False

    def is_professional(self):
        """Check if this is an active, valid Professional license."""
        return (
            self.edition == 'professional' and
            self.is_valid and
            not self.is_expired and
            self.is_hardware_match
        )

    def check_limit(self, limit_type, current_count):
        """Check if a limit is exceeded."""
        effective_limits = self.get_effective_limits()

        limit_map = {
            'users': effective_limits['max_users'],
            'organizations': effective_limits['max_organizations'],
            'products': effective_limits['max_products'],
            'agents': effective_limits['max_agents'],
            'agent_api_keys': effective_limits['max_agent_api_keys']
        }

        limit = limit_map.get(limit_type, 0)
        if limit == -1:  # Unlimited
            return True, -1, None

        if current_count >= limit:
            edition = self.get_effective_edition()
            if edition == 'community':
                if limit_type in ['agents', 'agent_api_keys']:
                    return False, limit, f'Demo version limit: {limit} agents. Upgrade to Professional for more agents.'
                return False, limit, f'Demo version limit: {limit} {limit_type}. Upgrade to Professional for unlimited.'
            return False, limit, f'License limit reached: {limit} {limit_type}. Purchase an agent pack to increase.'

        return True, limit, None

    def get_status_message(self):
        """Get a human-readable status message"""
        if self.error:
            return f'License error: {self.error}'
        if not self.is_valid:
            return 'Demo Version - Upgrade to Professional for full features'
        if not self.is_hardware_match:
            return 'License not valid for this installation'
        if self.is_expired:
            return f'License expired on {self.expires_at}'
        if self.days_until_expiry is not None and self.days_until_expiry <= 30:
            return f'License expires in {self.days_until_expiry} days'
        if self.is_professional():
            return f'Professional license for {self.customer}'
        return 'Demo Version'

    def to_dict(self):
        """Convert to dictionary for API responses"""
        effective_limits = self.get_effective_limits()
        effective_edition = self.get_effective_edition()
        current_installation_id = get_installation_id()
        tier = LICENSE_TIERS.get(effective_edition, LICENSE_TIERS['community'])

        return {
            'edition': self.edition,
            'effective_edition': effective_edition,
            'edition_name': tier.get('name', 'Demo'),
            'edition_display_name': tier.get('display_name', 'Demo Version'),
            'is_demo': tier.get('is_demo', True),
            'customer': self.customer,
            'license_id': self.license_id,
            'is_valid': self.is_valid and self.is_hardware_match,
            'is_expired': self.is_expired,
            'is_professional': self.is_professional(),
            'is_hardware_match': self.is_hardware_match,
            'expires_at': self.expires_at.isoformat() if self.expires_at else None,
            'days_until_expiry': self.days_until_expiry,
            'status_message': self.get_status_message(),
            'limits': effective_limits,
            'features': self.features if self.is_professional() and self.features else [],
            'powered_by_required': not self.is_professional(),
            'error': self.error,
            # Installation info
            'installation_id': current_installation_id,
            'licensed_installation_id': self.licensed_installation_id,
            # App version
            'app_version': _get_app_version()
        }


# ============================================================================
# License Loading and Caching
# ============================================================================

_current_license = None
_license_load_time = None
LICENSE_CACHE_SECONDS = 5


def get_license():
    """Get current license info with short caching."""
    global _current_license, _license_load_time

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
    Checks hardware lock - license must match this installation's ID.

    If SENTRIKAT_LICENSE env var is set and DB has no license (or a different one),
    the env var license is synced to DB so the GUI always shows the current state.
    """
    from app.models import SystemSettings
    from app import db as app_db

    license_info = LicenseInfo()
    license_key = None

    try:
        # Check database first
        setting = SystemSettings.query.filter_by(key='license_key').first()
        db_key = setting.value if setting and setting.value else None

        # Check environment variable
        env_key = os.environ.get('SENTRIKAT_LICENSE', '').strip() or None
        if env_key:
            env_key = _clean_license_input(env_key)

        # Sync: if env has a license and DB doesn't (or has a different one), save to DB
        if env_key:
            if not db_key or db_key != env_key:
                try:
                    if setting:
                        setting.value = env_key
                    else:
                        setting = SystemSettings(
                            key='license_key',
                            value=env_key,
                            category='licensing',
                            description='SentriKat license key (synced from SENTRIKAT_LICENSE env var)'
                        )
                        app_db.session.add(setting)
                    app_db.session.commit()
                    logger.info("License synced from SENTRIKAT_LICENSE env var to database")
                    db_key = env_key
                except Exception as e:
                    logger.warning(f"Could not sync license from env to DB: {e}")
                    try:
                        app_db.session.rollback()
                    except Exception:
                        pass

        # Use DB key (which may have been synced from env), or fall back to env
        license_key = db_key or env_key

        if not license_key:
            return license_info

        # Validate the license (includes hardware check)
        license_info = validate_license(license_key)

    except Exception as e:
        logger.error(f"Error loading license: {e}", exc_info=True)
        license_info.error = str(e)

    return license_info


# ============================================================================
# License Validation
# ============================================================================

def _clean_license_input(raw_input):
    """
    Clean and extract the license string from various input formats.

    Handles common user mistakes when pasting license keys:
    - SENTRIKAT_LICENSE=<license> (env var format from portal's env_example)
    - {"sentrikat_license": "<license>", ...} (raw JSON download)
    - Whitespace, newlines, surrounding quotes
    """
    if not raw_input:
        return raw_input

    cleaned = raw_input.strip()

    # Remove BOM if present
    if cleaned.startswith('\ufeff'):
        cleaned = cleaned[1:]

    # Remove surrounding quotes
    if (cleaned.startswith('"') and cleaned.endswith('"')) or \
       (cleaned.startswith("'") and cleaned.endswith("'")):
        cleaned = cleaned[1:-1].strip()

    # Handle SENTRIKAT_LICENSE=<value> prefix (common paste error from portal env_example)
    for prefix in ['SENTRIKAT_LICENSE=', 'sentrikat_license=', 'export SENTRIKAT_LICENSE=']:
        if cleaned.startswith(prefix):
            cleaned = cleaned[len(prefix):].strip()
            # Remove quotes again in case of SENTRIKAT_LICENSE="value"
            if (cleaned.startswith('"') and cleaned.endswith('"')) or \
               (cleaned.startswith("'") and cleaned.endswith("'")):
                cleaned = cleaned[1:-1].strip()
            break

    # Handle JSON object (user pasted the whole download JSON)
    if cleaned.startswith('{'):
        try:
            data = json.loads(cleaned)
            if isinstance(data, dict):
                # Try to extract the signed license string
                for key in ['sentrikat_license', 'signed_license', 'license_key', 'license']:
                    if key in data and isinstance(data[key], str) and '.' in data[key]:
                        cleaned = data[key].strip()
                        logger.info(f"Extracted license from JSON field '{key}'")
                        break
        except (json.JSONDecodeError, ValueError):
            pass  # Not JSON, continue with original

    # Remove any remaining whitespace/newlines within the string
    cleaned = ''.join(cleaned.split())

    return cleaned


def validate_license(license_key):
    """
    Validate a license key and check hardware lock.

    License format: base64(json_payload).base64(signature)

    The payload contains an installation_id field that must match
    this installation's ID for the license to be valid.
    """
    license_info = LicenseInfo()

    try:
        # Clean the input (handle common paste errors)
        license_key = _clean_license_input(license_key)

        # Development key for testing - ONLY works in non-production environments
        # Set SENTRIKAT_ENV=production or FLASK_ENV=production to disable dev license key
        _flask_env = os.environ.get('FLASK_ENV', '').lower()
        _sentrikat_env = os.environ.get('SENTRIKAT_ENV', '').lower()
        is_production = _flask_env == 'production' or _sentrikat_env == 'production'
        if license_key == 'SENTRIKAT-DEV-PROFESSIONAL':
            if is_production:
                logger.warning("Attempted to use development license key in production mode")
                license_info.error = 'Development license key is disabled in production'
                return license_info
            license_info.edition = 'professional'
            license_info.customer = 'Development Mode'
            license_info.license_id = 'DEV-001'
            license_info.is_valid = True
            license_info.is_hardware_match = True  # Dev key works everywhere
            license_info.max_users = -1
            license_info.max_organizations = -1
            license_info.max_products = -1
            license_info.max_agents = -1  # Unlimited agents in dev mode
            license_info.max_agent_api_keys = -1
            license_info.features = PROFESSIONAL_FEATURES + ['push_agents']
            logger.info("Development license activated (non-production environment)")
            return license_info

        # Split license key into payload and signature
        parts = license_key.strip().split('.')
        if len(parts) != 2:
            license_info.error = (
                'Invalid license format. Expected format: <payload>.<signature>\n'
                'Make sure you paste only the license string, not the full JSON file or env var line.'
            )
            return license_info

        payload_b64, signature_b64 = parts

        # Decode payload (JSON - valid UTF-8)
        try:
            # Add padding if needed (SentriKat-web keeps padding, generate_license strips it)
            padded = payload_b64 + '=' * (-len(payload_b64) % 4)
            payload_bytes = base64.urlsafe_b64decode(padded)
            payload_json = payload_bytes.decode('utf-8')
            payload = json.loads(payload_json)
        except UnicodeDecodeError as e:
            license_info.error = (
                f'Failed to decode license payload: {e}\n'
                'This usually means the pasted string includes extra text.\n'
                'Paste only the license string (the base64.base64 value), '
                'not "SENTRIKAT_LICENSE=..." or the JSON download file.'
            )
            logger.warning(f"License payload decode failed (first 30 chars): {payload_b64[:30]}...")
            return license_info
        except Exception as e:
            license_info.error = f'Failed to decode license: {e}'
            return license_info

        # Verify RSA signature (signature stays as binary bytes - NOT utf-8)
        try:
            from cryptography.hazmat.primitives import hashes, serialization
            from cryptography.hazmat.primitives.asymmetric import padding
            from cryptography.hazmat.backends import default_backend

            public_key = serialization.load_pem_public_key(
                get_license_public_key().encode(),
                backend=default_backend()
            )
            sig_padded = signature_b64 + '=' * (-len(signature_b64) % 4)
            signature = base64.urlsafe_b64decode(sig_padded)
            public_key.verify(
                signature,
                payload_bytes,  # Verify against raw bytes, not re-encoded string
                padding.PKCS1v15(),
                hashes.SHA256()
            )
        except Exception as e:
            license_info.error = (
                'Invalid license signature. The license key may have been '
                'signed with a different RSA key than this installation expects.\n'
                'If using the SentriKat portal, set SENTRIKAT_LICENSE_PUBLIC_KEY or '
                'SENTRIKAT_LICENSE_PUBLIC_KEY_FILE to the portal\'s public key.'
            )
            logger.warning(f"License signature verification failed: {e}")
            return license_info

        # Parse license data
        license_info.license_id = payload.get('license_id') or payload.get('license_key')
        license_info.customer = payload.get('customer')
        license_info.email = payload.get('email')

        # Map edition values: SentriKat-web uses 'pro'/'demo',
        # SentriKat uses 'professional'/'community'
        raw_edition = payload.get('edition', 'community')
        license_info.edition = EDITION_MAP.get(raw_edition, raw_edition)

        license_info.licensed_installation_id = payload.get('installation_id')

        # Parse dates (handles both date-only and datetime ISO formats)
        if payload.get('issued_at'):
            try:
                license_info.issued_at = datetime.fromisoformat(payload['issued_at']).date()
            except (ValueError, TypeError):
                pass

        if payload.get('expires_at'):
            try:
                license_info.expires_at = datetime.fromisoformat(payload['expires_at']).date()
                days_left = (license_info.expires_at - date.today()).days
                license_info.days_until_expiry = days_left
                license_info.is_expired = days_left < 0
            except (ValueError, TypeError):
                pass

        # Set limits from signed payload (tamper-proof)
        # Handle None values from SentriKat-web (None = unlimited, same as -1)
        tier = LICENSE_TIERS.get(license_info.edition, LICENSE_TIERS['community'])
        limits = payload.get('limits', {})

        def _resolve_limit(value, default):
            """Resolve limit value: None means unlimited (-1)."""
            if value is None:
                return -1
            return value

        license_info.max_users = _resolve_limit(
            limits.get('max_users', tier['max_users']), tier['max_users'])
        license_info.max_organizations = _resolve_limit(
            limits.get('max_organizations', tier['max_organizations']), tier['max_organizations'])
        license_info.max_products = _resolve_limit(
            limits.get('max_products', tier['max_products']), tier['max_products'])
        # Agent limits
        default_agents = -1 if license_info.edition == 'professional' else 0
        license_info.max_agents = _resolve_limit(
            limits.get('max_agents', default_agents), default_agents)
        license_info.max_agent_api_keys = _resolve_limit(
            limits.get('max_agent_api_keys', default_agents), default_agents)
        license_info.features = payload.get('features', tier['features'])

        # CHECK HARDWARE LOCK
        current_installation_id = get_installation_id()
        licensed_installation_id = license_info.licensed_installation_id

        if not licensed_installation_id:
            # Legacy license without installation ID - allow for backwards compatibility
            # but log a warning
            logger.warning(f"License {license_info.license_id} has no installation_id - allowing for backwards compatibility")
            license_info.is_hardware_match = True
        elif licensed_installation_id == current_installation_id:
            # Perfect match
            license_info.is_hardware_match = True
        else:
            # Hardware mismatch - license is for different installation
            license_info.is_hardware_match = False
            license_info.error = (
                f"License is for a different installation.\n"
                f"Licensed for: {licensed_installation_id[:20]}...\n"
                f"This system:  {current_installation_id[:20]}...\n\n"
                f"Contact support to transfer this license."
            )
            logger.warning(f"Hardware mismatch: license for {licensed_installation_id[:16]}, this is {current_installation_id[:16]}")

        # Mark signature as valid (hardware check is separate)
        license_info.is_valid = True

        if license_info.is_expired:
            logger.warning(f"License {license_info.license_id} has expired")
        elif license_info.is_hardware_match:
            logger.info(f"License validated: {license_info.edition} for {license_info.customer}")

    except Exception as e:
        license_info.error = f'License validation error: {e}'
        logger.error(f"License validation error: {e}")

    return license_info


def save_license(license_key):
    """
    Save license key to database after validation.
    Cleans input before validation (handles common paste errors).
    """
    from app.models import SystemSettings
    from app import db

    # Clean input before validation
    license_key = _clean_license_input(license_key)

    # Validate first
    license_info = validate_license(license_key)

    if not license_info.is_valid:
        return False, license_info.error or 'Invalid license key'

    if license_info.is_expired:
        return False, f'License has expired on {license_info.expires_at}'

    if not license_info.is_hardware_match:
        return False, license_info.error or 'License is not valid for this installation'

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
    reload_license()

    return True, f'License activated: {license_info.edition.title()} edition for {license_info.customer}'


def remove_license():
    """Remove license and revert to Demo version."""
    from app.models import SystemSettings
    from app import db

    setting = SystemSettings.query.filter_by(key='license_key').first()
    if setting:
        db.session.delete(setting)
        db.session.commit()

    reload_license()
    return True, 'License removed. Reverted to Demo version.'


# ============================================================================
# Feature Gating
# ============================================================================

def requires_professional(feature=None):
    """Decorator to require Professional license for a route."""
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            license_info = get_license()
            if not license_info.is_professional():
                feature_name = feature or 'This feature'
                return jsonify({
                    'error': f'{feature_name} requires a Professional license',
                    'license_required': True,
                    'current_edition': license_info.get_effective_edition()
                }), 403
            return f(*args, **kwargs)
        return decorated_function
    return decorator


def check_user_limit():
    """Check if user limit is reached"""
    from app.models import User
    license_info = get_license()
    current_users = User.query.filter(User.is_active == True).count() or 0
    return license_info.check_limit('users', current_users)


def check_org_limit():
    """Check if organization limit is reached"""
    from app.models import Organization
    license_info = get_license()
    current_orgs = Organization.query.count() or 0
    return license_info.check_limit('organizations', current_orgs)


def check_product_limit():
    """Check if product limit is reached"""
    from app.models import Product
    license_info = get_license()
    current_products = Product.query.count() or 0
    return license_info.check_limit('products', current_products)


def check_agent_limit():
    """
    Check if agent (endpoint) limit is reached.

    IMPORTANT: Counts agents GLOBALLY across all organizations.
    This prevents the multi-org bypass vulnerability where users
    create multiple organizations to get around per-org limits.

    Returns: (allowed, limit, message) tuple
    """
    from app.models import Asset
    license_info = get_license()

    # Count ALL active agents across ALL organizations (global limit)
    current_agents = Asset.query.filter(Asset.active == True).count() or 0

    return license_info.check_limit('agents', current_agents)


def check_agent_api_key_limit():
    """
    Check if agent API key limit is reached.

    IMPORTANT: Counts API keys GLOBALLY across all organizations.
    This prevents the multi-org bypass vulnerability.

    Returns: (allowed, limit, message) tuple
    """
    from app.models import AgentApiKey
    license_info = get_license()

    # Count ALL active API keys across ALL organizations (global limit)
    current_keys = AgentApiKey.query.filter(AgentApiKey.active == True).count() or 0

    return license_info.check_limit('agent_api_keys', current_keys)


def get_agent_usage():
    """
    Get current agent usage statistics for display.
    Returns dict with counts and limits, including server/client breakdown.
    """
    from app.models import Asset, AgentApiKey, AgentLicense
    license_info = get_license()
    limits = license_info.get_effective_limits()

    # Get total count
    total_agents = Asset.query.filter(Asset.active == True).count() or 0

    # Get server/client breakdown
    # Server types: server, container, appliance, virtual_machine, vm
    # Client types: workstation, desktop, laptop, endpoint, client
    server_types = AgentLicense.SERVER_TYPES
    client_types = AgentLicense.CLIENT_TYPES

    server_count = Asset.query.filter(
        Asset.active == True,
        func.lower(Asset.asset_type).in_(server_types)
    ).count() or 0

    client_count = Asset.query.filter(
        Asset.active == True,
        func.lower(Asset.asset_type).in_(client_types)
    ).count() or 0

    # Anything not matched is counted as server (unknown defaults to server)
    other_count = total_agents - server_count - client_count
    server_count += other_count

    # Calculate weighted units (servers=1, clients=0.5)
    weighted_units = server_count + (client_count * 0.5)

    return {
        'agents': {
            'current': total_agents,
            'limit': limits['max_agents'],
            'unlimited': limits['max_agents'] == -1
        },
        'breakdown': {
            'servers': server_count,
            'clients': client_count,
            'weighted_units': weighted_units
        },
        'api_keys': {
            'current': AgentApiKey.query.filter(AgentApiKey.active == True).count() or 0,
            'limit': limits['max_agent_api_keys'],
            'unlimited': limits['max_agent_api_keys'] == -1
        },
        'feature_enabled': 'push_agents' in license_info.features or license_info.is_professional()
    }


# ============================================================================
# License Server Heartbeat
# ============================================================================

LICENSE_SERVER_URL = os.environ.get('SENTRIKAT_LICENSE_SERVER', 'https://license.sentrikat.com/api')

def license_heartbeat():
    """
    Send a heartbeat to the SentriKat license server.

    Purpose:
    - Validates the license is still active on the server side
    - Reports usage telemetry (agent count, product count) for billing
    - Checks if the license has been revoked or suspended
    - Retrieves any updated license terms (e.g., expanded agent packs)

    This runs every 12 hours via the scheduler. If the server is unreachable,
    the local license continues to work (graceful degradation). The license
    is ONLY invalidated if the server explicitly returns a revocation response.

    Returns dict with 'success' bool and 'message' or 'error'.
    """
    import requests as _requests
    from config import Config

    license_info = get_license()

    # No heartbeat needed for community edition (no license key)
    if not license_info.is_valid or license_info.edition == 'community':
        return {'success': True, 'message': 'Community edition, no heartbeat needed'}

    try:
        from app.models import Asset, Product, AgentApiKey, Organization

        proxies = Config.get_proxies()
        verify_ssl = Config.get_verify_ssl()
        installation_id = get_installation_id()

        payload = {
            'installation_id': installation_id,
            'license_id': license_info.license_id,
            'edition': license_info.edition,
            'app_version': _get_app_version(),
            'usage': {
                'agents': Asset.query.filter(Asset.active == True).count() or 0,
                'products': Product.query.count() or 0,
                'organizations': Organization.query.filter(Organization.active == True).count() or 0,
                'api_keys': AgentApiKey.query.filter(AgentApiKey.active == True).count() or 0,
            },
        }

        response = _requests.post(
            f'{LICENSE_SERVER_URL}/v1/heartbeat',
            json=payload,
            timeout=15,
            proxies=proxies,
            verify=verify_ssl,
            headers={'Content-Type': 'application/json'}
        )

        if response.status_code == 200:
            data = response.json()

            # Check for license revocation
            if data.get('status') == 'revoked':
                logger.warning("License has been revoked by the server!")
                # Store revocation in system settings
                from app.models import SystemSettings
                from app import db
                revoked = SystemSettings.query.filter_by(key='license_revoked').first()
                if not revoked:
                    revoked = SystemSettings(key='license_revoked', value='true')
                    db.session.add(revoked)
                else:
                    revoked.value = 'true'
                db.session.commit()
                return {'success': False, 'error': 'License has been revoked'}

            # Check for updated limits (e.g., agent pack purchased)
            if data.get('updated_limits'):
                logger.info(f"License server provided updated limits: {data['updated_limits']}")

            return {
                'success': True,
                'message': data.get('message', 'Heartbeat acknowledged'),
                'server_status': data.get('status', 'active'),
            }

        elif response.status_code == 404:
            # License not found on server - could be first-time or server migration
            logger.info("License heartbeat: license not found on server (may be offline-only)")
            return {'success': True, 'message': 'License not registered on server'}

        else:
            logger.warning(f"License heartbeat returned {response.status_code}")
            return {'success': False, 'error': f'Server returned {response.status_code}'}

    except _requests.ConnectionError:
        # Server unreachable - graceful degradation, don't invalidate license
        logger.info("License heartbeat: server unreachable (offline mode)")
        return {'success': True, 'message': 'Server unreachable, continuing offline'}

    except _requests.Timeout:
        logger.info("License heartbeat: server timeout")
        return {'success': True, 'message': 'Server timeout, continuing offline'}

    except Exception as e:
        logger.error(f"License heartbeat failed: {e}")
        return {'success': False, 'error': str(e)}


# ============================================================================
# License API Routes
# ============================================================================

from flask import Blueprint, request
from app import csrf

license_bp = Blueprint('license', __name__)
csrf.exempt(license_bp)


@license_bp.route('/api/license', methods=['GET'])
def get_license_info():
    """Get current license information"""
    from app.auth import get_current_user
    from app.models import User, Organization, Product, Asset, AgentApiKey

    user = get_current_user()
    if not user:
        return jsonify({'error': 'Authentication required'}), 401

    license_info = get_license()
    response = license_info.to_dict()
    response['usage'] = {
        'users': User.query.filter(User.is_active == True).count() or 0,
        'organizations': Organization.query.count() or 0,
        'products': Product.query.count() or 0,
        'agents': Asset.query.filter(Asset.active == True).count() or 0,
        'agent_api_keys': AgentApiKey.query.filter(AgentApiKey.active == True).count() or 0
    }
    # Include agent-specific usage info
    response['agent_usage'] = get_agent_usage()

    return jsonify(response)


@license_bp.route('/api/license', methods=['POST'])
def activate_license():
    """Activate a license key"""
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
        return jsonify({
            'success': True,
            'message': message,
            'license': get_license().to_dict()
        })
    else:
        return jsonify({'error': message}), 400


@license_bp.route('/api/license/activate-online', methods=['POST'])
def activate_license_online():
    """Activate a license online using an activation code.

    The customer provides their activation code (from purchase confirmation).
    This endpoint contacts the SentriKat license portal to exchange the code
    for a hardware-locked license key, then saves it locally.

    Requires SSL/HTTPS connectivity to portal.sentrikat.com.
    Rate limited to 5 attempts per hour to prevent brute force.
    """
    import re
    from app import limiter
    from app.auth import get_current_user
    from app.logging_config import log_audit_event
    import requests as _requests
    from config import Config

    # Rate limit: 5 attempts per hour per IP
    try:
        limiter.check()
    except Exception:
        pass
    # Manual rate limit check via decorator won't work on blueprint-exempt routes,
    # so we use a simple in-memory counter
    _check_activation_rate_limit()

    user = get_current_user()
    if not user or not user.is_super_admin():
        return jsonify({'error': 'Super admin access required'}), 403

    data = request.get_json()
    if not data:
        return jsonify({'error': 'Request body is required'}), 400

    activation_code = (data.get('activation_code') or '').strip()

    if not activation_code:
        return jsonify({'error': 'Activation code is required'}), 400

    # Validate format: 8-128 chars, alphanumeric + hyphens only
    if len(activation_code) < 8 or len(activation_code) > 128:
        return jsonify({'error': 'Invalid activation code format'}), 400

    if not re.match(r'^[A-Za-z0-9\-]+$', activation_code):
        return jsonify({'error': 'Invalid activation code format. Use only letters, numbers, and hyphens.'}), 400

    installation_id = get_installation_id()
    proxies = Config.get_proxies()

    # Always verify SSL for license server connections (security-critical)
    # User's verify_ssl setting only applies to other outbound requests
    verify_ssl = True

    try:
        response = _requests.post(
            f'{LICENSE_SERVER_URL}/v1/license/activate',
            json={
                'activation_code': activation_code,
                'installation_id': installation_id,
                'app_version': _get_app_version(),
            },
            timeout=30,
            proxies=proxies,
            verify=verify_ssl,
            headers={'Content-Type': 'application/json'}
        )

        if response.status_code == 200:
            try:
                resp_data = response.json()
            except (json.JSONDecodeError, ValueError):
                return jsonify({'error': 'Invalid response from license server'}), 502

            license_key = resp_data.get('license_key', '')
            if not isinstance(license_key, str):
                return jsonify({'error': 'Invalid response from license server'}), 502

            license_key = license_key.strip()
            if not license_key:
                return jsonify({'error': 'Server returned empty license key'}), 502

            # Validate and save - RSA signature verification prevents accepting forged keys
            success, message = save_license(license_key)

            if success:
                log_audit_event('UPDATE', 'license', details=f'License activated online: {message}')
                return jsonify({
                    'success': True,
                    'message': message,
                    'license': get_license().to_dict()
                })
            else:
                return jsonify({'error': f'License validation failed: {message}'}), 400

        elif response.status_code == 404:
            return jsonify({'error': 'Activation code not found. Please check the code and try again.'}), 400

        elif response.status_code == 409:
            return jsonify({'error': 'This activation code has already been used. Contact support to transfer the license.'}), 400

        elif response.status_code == 410:
            return jsonify({'error': 'This activation code has expired. Contact support for a new one.'}), 400

        elif response.status_code == 429:
            return jsonify({'error': 'Too many activation attempts. Please try again later.'}), 429

        else:
            logger.warning(f"License server returned {response.status_code} for online activation")
            return jsonify({'error': 'License server returned an unexpected response. Please try again later.'}), 502

    except _requests.ConnectionError:
        return jsonify({
            'error': 'Cannot reach the license server (license.sentrikat.com). '
                     'Check your internet connection and firewall settings. '
                     'If online activation is not possible, use offline activation instead.'
        }), 503

    except _requests.Timeout:
        return jsonify({'error': 'License server timed out. Please try again.'}), 504

    except Exception as e:
        logger.error(f"Online license activation failed: {e}")
        return jsonify({'error': 'Activation failed due to an internal error. Please try again later.'}), 500


# Simple in-memory rate limiter for activation attempts
_activation_attempts = {}  # ip -> [(timestamp, ...)]

def _check_activation_rate_limit():
    """Limit activation attempts to 5 per hour per IP."""
    from flask import request as _req
    import time

    ip = _req.remote_addr or 'unknown'
    now = time.time()
    hour_ago = now - 3600

    # Clean old entries
    if ip in _activation_attempts:
        _activation_attempts[ip] = [t for t in _activation_attempts[ip] if t > hour_ago]
    else:
        _activation_attempts[ip] = []

    if len(_activation_attempts[ip]) >= 5:
        from flask import abort
        abort(429, description='Too many activation attempts. Please try again in an hour.')

    _activation_attempts[ip].append(now)


@license_bp.route('/api/license', methods=['DELETE'])
def deactivate_license():
    """Remove license and revert to Demo"""
    from app.auth import get_current_user
    from app.logging_config import log_audit_event

    user = get_current_user()
    if not user or not user.is_super_admin():
        return jsonify({'error': 'Super admin access required'}), 403

    success, message = remove_license()
    log_audit_event('UPDATE', 'license', details='License removed')

    return jsonify({
        'success': True,
        'message': message,
        'license': get_license().to_dict()
    })


@license_bp.route('/api/license/installation-id', methods=['GET'])
def get_installation_id_api():
    """Get this installation's ID for license requests"""
    from app.auth import get_current_user

    user = get_current_user()
    if not user:
        return jsonify({'error': 'Authentication required'}), 401

    installation_id = get_installation_id()
    is_docker = _is_docker_environment()
    is_from_env = bool(os.environ.get(INSTALLATION_ID_ENV_VAR))

    try:
        hostname = socket.gethostname()
    except Exception:
        hostname = 'Unknown'

    response = {
        'installation_id': installation_id,
        'hostname': hostname,
        'is_docker': is_docker,
        'is_from_environment': is_from_env,
        'instructions': (
            'To request a license:\n'
            '1. Copy your Installation ID above\n'
            '2. Send it to SentriKat sales with your company details\n'
            '3. You will receive a license key locked to this installation'
        )
    }

    # Add Docker-specific warning and instructions if needed
    if is_docker and not is_from_env:
        response['docker_warning'] = (
            'WARNING: Docker detected without fixed Installation ID.\n'
            'Your license may be lost when you rebuild the container.\n\n'
            'To fix this, add to your .env file:\n'
            f'SENTRIKAT_INSTALLATION_ID={installation_id}\n\n'
            'Then rebuild: docker compose up -d --build\n'
            'Your Installation ID will remain stable across future rebuilds.'
        )

    return jsonify(response)
