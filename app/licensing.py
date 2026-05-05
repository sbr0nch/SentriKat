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
import time
import uuid
import socket
import threading
from datetime import datetime, date
from functools import wraps
from flask import jsonify, has_request_context
from sqlalchemy import func

logger = logging.getLogger(__name__)


# ============================================================================
# Exceptions
# ============================================================================

class LicenseRevokedException(Exception):
    """Raised when a license has been revoked by the upstream license server.

    Callers (middleware, decorators, scheduled jobs) should catch this and
    deny access or degrade the service accordingly. Revocation is signalled
    via the ``SystemSettings`` key ``license_revoked`` (set by the license
    server webhook receiver or the heartbeat response handler).
    """


# ============================================================================
# Plan Enum (M13)
# ============================================================================

#: Canonical set of subscription plan names recognised across licensing,
#: metering and the admin UI. Use :func:`validate_plan_name` to check inputs.
VALID_PLAN_NAMES = frozenset({'free', 'starter', 'pro', 'business', 'enterprise'})


def validate_plan_name(name):
    """Validate that ``name`` is a known plan identifier.

    Args:
        name: Plan name to validate (case-insensitive).

    Returns:
        The normalised lower-case plan name.

    Raises:
        ValueError: If ``name`` is not in :data:`VALID_PLAN_NAMES`.
    """
    if not isinstance(name, str):
        raise ValueError(f"Plan name must be a string, got {type(name).__name__}")
    normalized = name.strip().lower()
    if normalized not in VALID_PLAN_NAMES:
        raise ValueError(
            f"Unknown plan name: {name!r}. "
            f"Valid plans: {sorted(VALID_PLAN_NAMES)}"
        )
    return normalized

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
# [03.14.10.expand] Public-facing name is "Community Edition" — matches the
# industry FOSS convention (GitLab CE, MySQL Community, etc.), the License
# page UI, the Health Check banner, and the internal EDITION_MAP key. The
# is_demo flag is kept under that name for backwards compat with code that
# already imports it; it now means "is the free Community tier" rather than
# "trial/demo".
LICENSE_TIERS = {
    'community': {
        'name': 'Community',
        'display_name': 'Community Edition',
        # Limits aligned to the public-facing pricing page on
        # sentrikat.com (10 Agents / 3 Users / 1 Org / 100 Products) so
        # customers reading the landing get exactly what they are promised
        # when they install on-prem ([03.14.10.expand] follow-up).
        # Previous values (1 user / 50 products / 5 agents) were stricter
        # than what marketing was advertising → false-advertising risk.
        'max_users': 3,
        'max_organizations': 1,
        'max_products': 100,
        'max_agents': 10,
        # Community gets the basic agent push capability so the
        # advertised "10 Agents (Windows/Linux/macOS)" actually works.
        # Limits are still enforced numerically (max_agents=10,
        # max_products=100). Agents over the cap get rejected with a
        # specific 'agent limit reached' message; products over the
        # cap go to the import queue instead of being silently dropped.
        # Pro adds the enterprise-grade features (SSO, multi-org,
        # white-label, alerts).
        'features': ['push_agents'],
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
    # 'push_agents' moved to BASE_FEATURES — Community is advertised as
    # supporting 10 endpoints (Windows, Linux, macOS) on the public
    # pricing card, so the agent push capability has to work within
    # those numerical limits. Pro distinguishes itself via the
    # enterprise-grade items above (SSO, multi-org, alerts, etc.),
    # not by gating the basic 'agent reports inventory' flow.
    'jira_integration',  # Jira ticket creation
    'compliance_reports',  # CISA BOD 22-01 compliance reports
    'sbom_export',  # Sprint 4 #32 - CycloneDX/SPDX export
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
    """Holds current license information.

    The :attr:`is_valid` property reflects three independent conditions:

    1. The signed payload was successfully verified (``_signature_valid``).
    2. The license has not expired (``not is_expired``).
    3. The license has NOT been revoked by the upstream license server
       (``not revoked``). Revocation state is populated by :func:`get_license`
       from the ``SystemSettings`` key ``license_revoked`` (written by the
       license-server webhook receiver in :mod:`app.license_webhook` and
       the heartbeat response handler in :func:`license_heartbeat`).

    Hardware-lock enforcement is tracked separately via
    :attr:`is_hardware_match` so that callers can still distinguish between
    a license that is mathematically valid but simply not issued for this
    installation and one that has been revoked or expired.
    """

    def __init__(self):
        self.edition = 'community'
        self.customer = None
        self.email = None
        self.license_id = None
        self.issued_at = None
        self.expires_at = None
        # Defaults pulled from LICENSE_TIERS['community'] so a single
        # source of truth governs the values. Hardcoding them here was
        # the silent bug behind [01.18.5]: bumping LICENSE_TIERS to 3
        # users / 100 products / 10 agents / push_agents-enabled didn't
        # actually take effect, because get_license() returns a fresh
        # LicenseInfo with these constructor defaults whenever no signed
        # license payload is present (= the entire Community customer
        # base).
        _community = LICENSE_TIERS['community']
        self.max_users = _community['max_users']
        self.max_organizations = _community['max_organizations']
        self.max_products = _community['max_products']
        self.max_agents = _community['max_agents']
        self.max_agent_api_keys = 0
        self.features = list(_community['features'])
        # Underlying signature/parse validity. ``is_valid`` is exposed as a
        # property that folds in expiry + revocation so every caller gets the
        # full enforcement story without having to remember each flag.
        self._signature_valid = False
        self.is_expired = False
        self.days_until_expiry = None
        self.error = None
        self.licensed_installation_id = None  # The installation ID this license is for
        self.is_hardware_match = False  # Does license match this installation?
        # B2: revocation flag — set by get_license() from SystemSettings.
        self.revoked = False

    @property
    def is_valid(self):
        """Return True iff the license is signature-valid, unexpired and not revoked."""
        if self.revoked:
            return False
        if self.is_expired:
            return False
        return self._signature_valid

    @is_valid.setter
    def is_valid(self, value):
        # Keep backwards compatibility: existing code writes to ``is_valid``
        # directly during parsing. We store it in ``_signature_valid`` so the
        # property can then layer expiry/revocation on top.
        self._signature_valid = bool(value)

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
        """Check if license includes a specific feature.

        Pre-2026-05 this method short-circuited to False for any non-Pro
        license. That made sense when EVERY feature was Pro-gated, but
        no longer holds: the Community tier explicitly enables a few
        baseline features (push_agents) that the public pricing card
        promises. The check now respects the actual `features` list
        regardless of edition; Pro shortcuts are no longer baked in
        ([01.18.5]).
        """
        if not self.features:
            return False
        return feature in self.features

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
                    return False, limit, f'Community Edition limit: {limit} agents. Upgrade to Professional for more agents.'
                return False, limit, f'Community Edition limit: {limit} {limit_type}. Upgrade to Professional for unlimited.'
            return False, limit, f'License limit reached: {limit} {limit_type}. Purchase an agent pack to increase.'

        return True, limit, None

    def get_status_message(self):
        """Get a human-readable status message"""
        if self.error:
            return f'License error: {self.error}'
        if not self.is_valid:
            return 'Community Edition - Upgrade to Professional for full features'
        if not self.is_hardware_match:
            return 'License not valid for this installation'
        if self.is_expired:
            return f'License expired on {self.expires_at}'
        if self.days_until_expiry is not None and self.days_until_expiry <= 30:
            return f'License expires in {self.days_until_expiry} days'
        if self.is_professional():
            return f'Professional license for {self.customer}'
        return 'Community Edition'

    def to_dict(self):
        """Convert to dictionary for API responses"""
        effective_limits = self.get_effective_limits()
        effective_edition = self.get_effective_edition()
        current_installation_id = get_installation_id()
        tier = LICENSE_TIERS.get(effective_edition, LICENSE_TIERS['community'])

        return {
            'edition': self.edition,
            'effective_edition': effective_edition,
            'edition_name': tier.get('name', 'Community'),
            'edition_display_name': tier.get('display_name', 'Community Edition'),
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
            'features': self.features if self.features else [],
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
_license_lock = threading.Lock()
LICENSE_CACHE_SECONDS = 60


def _apply_revocation_flag(license_info):
    """B2: Overlay the persisted ``license_revoked`` flag onto a LicenseInfo.

    The flag lives in ``SystemSettings(key='license_revoked', value='true')``
    and is written either by the webhook receiver (push from license server)
    or by the heartbeat response handler. We read it here so every consumer
    of :func:`get_license` automatically honours revocation without needing
    to make a second query.
    """
    try:
        from app.models import SystemSettings
        row = SystemSettings.query.filter_by(key='license_revoked').first()
        if row and (row.value or '').strip().lower() == 'true':
            license_info.revoked = True
            if not license_info.error:
                license_info.error = 'License has been revoked by the license server'
        else:
            license_info.revoked = False
    except Exception as e:
        # Never let a DB hiccup turn into a hard license failure — log and
        # treat as not-revoked (fail-open on transient errors).
        logger.debug(f"Could not read license_revoked flag: {e}")
        license_info.revoked = False
    return license_info


def check_license_active_or_raise():
    """Raise :class:`LicenseRevokedException` if the current license is revoked.

    Callers (middleware, feature gates, critical jobs) can use this to abort
    early on a revoked license. It does **not** raise for merely-expired or
    hardware-mismatched licenses — use :meth:`LicenseInfo.is_valid` /
    :meth:`LicenseInfo.is_professional` for those conditions.
    """
    license_info = get_license()
    if license_info.revoked:
        raise LicenseRevokedException(
            license_info.error or 'License has been revoked by the license server'
        )
    return license_info


def get_license():
    """Get current license info with thread-safe caching (60s TTL).

    The returned :class:`LicenseInfo` has the revocation flag from
    ``SystemSettings['license_revoked']`` already applied, so
    ``license.is_valid`` honours revocation out of the box.
    """
    global _current_license, _license_load_time

    # Request-level dedup: avoid re-validating within the same HTTP request
    if has_request_context():
        from flask import g
        cached = getattr(g, '_license_info', None)
        if cached is not None:
            return cached

    now = datetime.utcnow()
    # Fast path: check cache without lock
    if (_current_license is not None and
        _license_load_time is not None and
        (now - _license_load_time).total_seconds() <= LICENSE_CACHE_SECONDS):
        # Always refresh revocation flag even on cache hit — webhook pushes
        # must take effect within the same request, not after 60s.
        _apply_revocation_flag(_current_license)
        if has_request_context():
            from flask import g
            g._license_info = _current_license
        return _current_license

    # Slow path: acquire lock and reload
    with _license_lock:
        # Double-check after acquiring lock (another thread may have refreshed)
        now = datetime.utcnow()
        if (_current_license is not None and
            _license_load_time is not None and
            (now - _license_load_time).total_seconds() <= LICENSE_CACHE_SECONDS):
            result = _current_license
        else:
            _current_license = load_license()
            _license_load_time = datetime.utcnow()
            result = _current_license

    _apply_revocation_flag(result)

    if has_request_context():
        from flask import g
        g._license_info = result
    return result


def reload_license():
    """Force reload license from database (bypasses cache)."""
    global _current_license, _license_load_time
    with _license_lock:
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
    """Remove license and revert to Community Edition."""
    from app.models import SystemSettings
    from app import db

    setting = SystemSettings.query.filter_by(key='license_key').first()
    if setting:
        db.session.delete(setting)
        db.session.commit()

    reload_license()
    return True, 'License removed. Reverted to Community Edition.'


# ============================================================================
# Feature Gating
# ============================================================================

def requires_professional(feature=None):
    """Decorator to require Professional license (on-premise) or active paid plan (SaaS).

    Dual-mode aware: in SaaS mode, checks the org's subscription plan features
    instead of the RSA-signed license. This allows the same decorator to work
    across both deployment modes without requiring callers to change.
    """
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            from app.saas import is_saas_mode, get_scoped_org_id, get_effective_features

            # Super admin bypasses all plan restrictions (platform operator)
            try:
                from flask import session
                from app.models import User
                uid = session.get('user_id')
                if uid:
                    user = User.query.get(uid)
                    if user and user.is_super_admin():
                        return f(*args, **kwargs)
            except Exception:
                pass

            if is_saas_mode():
                # SaaS: check subscription plan features for the current org
                org_id = get_scoped_org_id()
                features = get_effective_features(org_id)
                # Map feature display names to feature keys
                feature_key_map = {
                    'LDAP': 'ldap', 'SAML SSO': 'sso', 'Email Alerts': 'email_alerts',
                    'White Label': 'white_label', 'Integrations': 'push_agents',
                    'Jira Integration': 'jira_integration', 'Issue Tracker Integration': 'jira_integration',
                    'SBOM Export': 'sbom_export',
                    'SIEM Integration': 'siem_integration', 'SIEM': 'siem_integration',
                    'Audit Export': 'audit_export', 'Backup & Restore': 'backup_restore',
                    'Agent Keys': 'push_agents',
                    'Scheduled Reports': 'compliance_reports',
                    'Compliance Reports': 'compliance_reports',
                }
                feature_key = feature_key_map.get(feature, feature.lower().replace(' ', '_') if feature else None)
                if feature_key and not features.get(feature_key, False):
                    feature_name = feature or 'This feature'
                    return jsonify({
                        'error': f'{feature_name} is not available on your current plan',
                        'feature_required': feature_key,
                        'upgrade_required': True
                    }), 403
                # If no specific feature key mapped, check if subscription is active (any paid plan)
                if not feature_key:
                    from app.models import Subscription
                    sub = Subscription.query.filter_by(organization_id=org_id).filter(
                        Subscription.status.in_(['active', 'trialing'])
                    ).first()
                    if not sub or (sub.plan and sub.plan.name == 'free'):
                        feature_name = feature or 'This feature'
                        return jsonify({
                            'error': f'{feature_name} requires a paid plan',
                            'upgrade_required': True
                        }), 403
            else:
                # On-premise: check RSA-signed license
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


def check_user_limit(organization_id=None):
    """Check if user limit is reached.

    On-prem: global cap from license_info.max_users (counts ALL active
        users across all orgs).
    SaaS: per-tenant cap from the org's SubscriptionPlan.max_users.
        Counts active users WHOSE primary organization_id matches the
        target org.

    Args:
        organization_id: required for SaaS to enforce the plan cap.
            If omitted in SaaS the call returns 'no limit' (used by
            background jobs / superadmin paths that have no org
            context). For UI 'create user' and SSO/LDAP provisioning,
            ALWAYS pass the org_id of the user being added.

    Returns: (allowed: bool, limit: int, message: Optional[str])
    """
    from app.saas import is_saas_mode
    from app.models import User

    if is_saas_mode():
        if organization_id is None:
            return True, -1, None
        from app.models import Subscription, SubscriptionPlan
        sub = Subscription.query.filter_by(
            organization_id=organization_id
        ).first()
        if not sub or not sub.plan:
            plan = SubscriptionPlan.query.filter_by(name='free').first()
            if not plan:
                return True, -1, None
        else:
            plan = sub.plan
        limit = getattr(plan, 'max_users', None)
        if limit is None or limit < 0:
            return True, -1, None
        current = User.query.filter(
            User.organization_id == organization_id,
            User.is_active == True
        ).count() or 0
        if current >= limit:
            return False, limit, (
                f'Plan limit reached: {limit} users. '
                f'Upgrade your subscription to add more.'
            )
        return True, limit, None

    license_info = get_license()
    current_users = User.query.filter(User.is_active == True).count() or 0
    return license_info.check_limit('users', current_users)


def check_org_limit():
    """Check if organization limit is reached.
    SaaS: orgs are provisioned by the platform, no global limit.
    """
    from app.saas import is_saas_mode
    if is_saas_mode():
        return True, -1, None  # SaaS: no global limit
    from app.models import Organization
    license_info = get_license()
    current_orgs = Organization.query.count() or 0
    return license_info.check_limit('organizations', current_orgs)


def check_product_limit(organization_id=None):
    """Check if product limit is reached.

    On-prem: global cap from license_info.max_products.
    SaaS: per-tenant cap from the org's SubscriptionPlan.max_products
          ([01.18.5] — same enforcement story as on-prem, just sourced
          from the plan instead of the signed license).

    Args:
        organization_id: optional, only used in SaaS mode. If omitted in
            SaaS mode the call returns 'no limit' (used by call sites
            that genuinely have no org context, e.g. some background
            jobs). For agent inventory + import queue approval,
            ALWAYS pass the org_id.

    Returns: (allowed: bool, limit: int, message: Optional[str])
    """
    from app.saas import is_saas_mode
    from app.models import Product

    if is_saas_mode():
        if organization_id is None:
            return True, -1, None
        from app.models import Subscription, SubscriptionPlan
        sub = Subscription.query.filter_by(
            organization_id=organization_id
        ).first()
        if not sub or not sub.plan:
            # No subscription = use free plan defaults
            plan = SubscriptionPlan.query.filter_by(name='free').first()
            if not plan:
                return True, -1, None
        else:
            plan = sub.plan
        limit = plan.max_products
        if limit is None or limit < 0:
            return True, -1, None
        # Count products linked to this org via the m2m join
        from app.models import product_organizations
        from sqlalchemy import select, func
        current = db.session.execute(
            select(func.count()).select_from(product_organizations).where(
                product_organizations.c.organization_id == organization_id
            )
        ).scalar() or 0
        if current >= limit:
            return False, limit, (
                f'Plan limit reached: {limit} products. '
                f'Upgrade your subscription to add more.'
            )
        return True, limit, None

    license_info = get_license()
    current_products = Product.query.count() or 0
    return license_info.check_limit('products', current_products)


def check_agent_limit():
    """
    Check if agent (endpoint) limit is reached.

    On-premise: Counts agents GLOBALLY across all organizations.
    SaaS: No global limit — managed per-org by subscription plan.

    Returns: (allowed, limit, message) tuple
    """
    from app.saas import is_saas_mode
    if is_saas_mode():
        return True, -1, None  # SaaS: no global limit
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

LICENSE_SERVER_URL = os.environ.get('SENTRIKAT_LICENSE_SERVER', '') or 'https://license.sentrikat.com/api'

#: Backoff delays (in seconds) between heartbeat retries — exponential:
#: 1, 2, 4, 8. Four attempts total before declaring failure.
HEARTBEAT_RETRY_DELAYS = (1, 2, 4, 8)

#: Consecutive heartbeat failures allowed before the operator alert is raised.
HEARTBEAT_FAILURE_ALERT_THRESHOLD = 3


def _persist_heartbeat_failure():
    """Bump ``license_heartbeat_failures`` and set alert if threshold reached.

    H5: previously heartbeat failures were silently swallowed. We now record
    every terminal failure and raise a ``license_heartbeat_alert`` flag after
    three consecutive failures so the admin UI / alerting cron can surface it.
    """
    try:
        from app.models import SystemSettings
        from app import db as app_db
        row = SystemSettings.query.filter_by(key='license_heartbeat_failures').first()
        try:
            current = int((row.value or '0')) if row else 0
        except (TypeError, ValueError):
            current = 0
        new_val = current + 1
        if row:
            row.value = str(new_val)
        else:
            row = SystemSettings(
                key='license_heartbeat_failures',
                value=str(new_val),
                category='licensing',
                description='Consecutive license-server heartbeat failures',
            )
            app_db.session.add(row)

        if new_val >= HEARTBEAT_FAILURE_ALERT_THRESHOLD:
            logger.error(
                f"License heartbeat has failed {new_val} times consecutively — "
                "raising license_heartbeat_alert"
            )
            alert = SystemSettings.query.filter_by(key='license_heartbeat_alert').first()
            if alert:
                alert.value = 'true'
            else:
                alert = SystemSettings(
                    key='license_heartbeat_alert',
                    value='true',
                    category='licensing',
                    description='True when license heartbeat has failed repeatedly',
                )
                app_db.session.add(alert)

        app_db.session.commit()
        return new_val
    except Exception as e:
        logger.warning(f"Could not persist heartbeat failure counter: {e}")
        try:
            from app import db as app_db
            app_db.session.rollback()
        except Exception:
            pass
        return None


def _reset_heartbeat_failure_counter():
    """Clear the heartbeat failure counter and alert flag on success (H5)."""
    try:
        from app.models import SystemSettings
        from app import db as app_db
        changed = False
        row = SystemSettings.query.filter_by(key='license_heartbeat_failures').first()
        if row and row.value != '0':
            row.value = '0'
            changed = True
        alert = SystemSettings.query.filter_by(key='license_heartbeat_alert').first()
        if alert and (alert.value or '').lower() == 'true':
            alert.value = 'false'
            changed = True
        if changed:
            app_db.session.commit()
    except Exception as e:
        logger.debug(f"Could not reset heartbeat counter: {e}")
        try:
            from app import db as app_db
            app_db.session.rollback()
        except Exception:
            pass


def _apply_updated_limits_from_heartbeat(updated_limits):
    """H9: Persist plan limits returned by the license server.

    The heartbeat response may include ``updated_limits`` with new per-plan
    caps (e.g., after a plan change or agent-pack purchase). We look up the
    Subscription for the relevant organization and mirror the values onto
    the associated SubscriptionPlan record. ``models.py`` is NOT modified —
    we only issue query/setattr/commit against the existing schema.
    """
    if not isinstance(updated_limits, dict):
        return
    try:
        from app.models import Subscription
        from app import db as app_db
    except Exception as e:
        logger.debug(f"updated_limits: models unavailable: {e}")
        return

    # Determine which subscription to update. In on-premise mode there is
    # usually one org so we update the first active subscription we find.
    sub = Subscription.query.filter(
        Subscription.status.in_(('active', 'trialing'))
    ).first()
    if not sub or not sub.plan:
        logger.info("updated_limits received but no active subscription/plan to update")
        return

    plan = sub.plan
    mapping = {
        'max_agents': 'max_agents',
        'max_users': 'max_users',
        'max_products': 'max_products',
        'max_organizations': 'max_organizations',
        'max_api_keys': 'max_api_keys',
    }
    # Storage: license server uses GB, SubscriptionPlan stores MB.
    changed = {}
    try:
        for src_key, attr in mapping.items():
            if src_key in updated_limits and hasattr(plan, attr):
                new_val = updated_limits[src_key]
                if new_val is None:
                    new_val = -1
                old_val = getattr(plan, attr)
                if old_val != new_val:
                    setattr(plan, attr, new_val)
                    changed[attr] = new_val

        if 'max_storage_gb' in updated_limits and hasattr(plan, 'max_storage_mb'):
            gb = updated_limits['max_storage_gb']
            if gb is not None:
                new_mb = int(gb) * 1024
                if plan.max_storage_mb != new_mb:
                    plan.max_storage_mb = new_mb
                    changed['max_storage_mb'] = new_mb

        # Optional plan rename (server authoritative name) — validate against enum.
        if 'plan_name' in updated_limits and hasattr(plan, 'name'):
            try:
                new_name = validate_plan_name(updated_limits['plan_name'])
                if plan.name != new_name:
                    plan.name = new_name
                    changed['name'] = new_name
            except ValueError as ve:
                logger.warning(f"updated_limits: ignoring invalid plan_name: {ve}")

        # Features may be a list or JSON string.
        if 'features' in updated_limits and hasattr(plan, 'features'):
            feats = updated_limits['features']
            try:
                plan.features = json.dumps(feats) if not isinstance(feats, str) else feats
                changed['features'] = True
            except Exception:
                pass

        if changed:
            app_db.session.commit()
            logger.info(
                f"Updated subscription plan from heartbeat "
                f"(sub={sub.id}, plan={plan.name}): {changed}"
            )
    except Exception as e:
        logger.warning(f"Failed to apply updated_limits from heartbeat: {e}")
        try:
            app_db.session.rollback()
        except Exception:
            pass


def license_heartbeat():
    """
    Send a heartbeat to the SentriKat license server.

    Purpose:
    - Validates the license is still active on the server side
    - Reports usage telemetry (agent count, product count) for billing
    - Checks if the license has been revoked or suspended
    - Retrieves any updated license terms (e.g., expanded agent packs)

    Runs every 12 hours via the scheduler. On network/transport errors we now
    (H5) retry with exponential backoff (1, 2, 4, 8 seconds — four total
    attempts) and, on complete failure, persist a ``license_heartbeat_failures``
    counter. After :data:`HEARTBEAT_FAILURE_ALERT_THRESHOLD` consecutive
    failures we also set ``license_heartbeat_alert='true'`` so the admin
    dashboard can surface the problem. On success we reset the counter.

    Any ``updated_limits`` returned in the response are persisted to the
    matching :class:`Subscription`/:class:`SubscriptionPlan` record (H9).

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
    except Exception as e:
        logger.error(f"License heartbeat: failed to build payload: {e}")
        return {'success': False, 'error': f'Could not build heartbeat payload: {e}'}

    # H5: exponential backoff retry loop.
    last_exc = None
    response = None
    for attempt, delay in enumerate([0] + list(HEARTBEAT_RETRY_DELAYS[:-1]), start=1):
        if delay:
            time.sleep(delay)
        try:
            response = _requests.post(
                f'{LICENSE_SERVER_URL}/v1/heartbeat',
                json=payload,
                timeout=15,
                proxies=proxies,
                verify=verify_ssl,
                headers={'Content-Type': 'application/json'}
            )
            break  # got an HTTP response, stop retrying (even for 5xx)
        except (_requests.ConnectionError, _requests.Timeout) as e:
            last_exc = e
            logger.info(
                f"License heartbeat attempt {attempt}/{len(HEARTBEAT_RETRY_DELAYS)} "
                f"failed: {type(e).__name__}: {e}"
            )
            continue
        except Exception as e:
            last_exc = e
            logger.warning(
                f"License heartbeat attempt {attempt}: unexpected error: {e}"
            )
            continue

    if response is None:
        # All retries exhausted — record failure + maybe raise alert.
        count = _persist_heartbeat_failure()
        logger.error(
            f"License heartbeat failed after {len(HEARTBEAT_RETRY_DELAYS)} retries "
            f"(consecutive failures: {count}): {last_exc}"
        )
        return {
            'success': False,
            'error': str(last_exc) if last_exc else 'unknown',
            'message': 'Heartbeat failed after retries',
            'consecutive_failures': count,
        }

    try:
        if response.status_code == 200:
            try:
                data = response.json()
            except Exception:
                data = {}

            # Check for license revocation
            if data.get('status') == 'revoked':
                logger.warning("License has been revoked by the server!")
                # Store revocation in system settings
                from app.models import SystemSettings
                from app import db
                revoked = SystemSettings.query.filter_by(key='license_revoked').first()
                if not revoked:
                    revoked = SystemSettings(key='license_revoked', value='true', category='licensing')
                    db.session.add(revoked)
                else:
                    revoked.value = 'true'
                db.session.commit()
                # Successful comms → reset failure counter.
                _reset_heartbeat_failure_counter()
                return {'success': False, 'error': 'License has been revoked'}

            # H9: persist any updated limits from the server.
            if data.get('updated_limits'):
                logger.info(f"License server provided updated limits: {data['updated_limits']}")
                _apply_updated_limits_from_heartbeat(data['updated_limits'])

            _reset_heartbeat_failure_counter()
            return {
                'success': True,
                'message': data.get('message', 'Heartbeat acknowledged'),
                'server_status': data.get('status', 'active'),
            }

        elif response.status_code == 404:
            # License not found on server - could be first-time or server migration
            logger.info("License heartbeat: license not found on server (may be offline-only)")
            _reset_heartbeat_failure_counter()
            return {'success': True, 'message': 'License not registered on server'}

        else:
            logger.warning(f"License heartbeat returned {response.status_code}")
            count = _persist_heartbeat_failure()
            return {
                'success': False,
                'error': f'Server returned {response.status_code}',
                'message': 'Heartbeat failed after retries',
                'consecutive_failures': count,
            }
    except Exception as e:
        logger.error(f"License heartbeat: error processing response: {e}")
        count = _persist_heartbeat_failure()
        return {
            'success': False,
            'error': str(e),
            'message': 'Heartbeat failed after retries',
            'consecutive_failures': count,
        }


# ============================================================================
# License API Routes
# ============================================================================

from flask import Blueprint, request
from app import csrf

license_bp = Blueprint('license', __name__)
csrf.exempt(license_bp)


@license_bp.route('/api/license', methods=['GET'])
def get_license_info():
    """Get current license information.

    On-premise: returns global license info with usage stats.
    SaaS: returns org-scoped subscription info (prevents cross-tenant data leakage).
    """
    from app.auth import get_current_user
    from app.saas import is_saas_mode

    user = get_current_user()
    if not user:
        return jsonify({'error': 'Authentication required'}), 401

    if is_saas_mode():
        # SaaS: return org-scoped subscription info instead of global license data
        from app.saas import get_scoped_org_id, get_effective_features
        from app.models import User, Product, Asset, AgentApiKey, Subscription
        org_id = get_scoped_org_id(user)
        features = get_effective_features(org_id)
        sub = Subscription.query.filter_by(organization_id=org_id).filter(
            Subscription.status.in_(['active', 'trialing'])
        ).first()
        is_pro = sub is not None and sub.plan and sub.plan.name != 'free'
        return jsonify({
            'is_professional': is_pro,
            'edition': sub.plan.name if sub and sub.plan else 'free',
            'features': list(k for k, v in features.items() if v),
            'saas_mode': True,
            'usage': {
                'users': User.query.filter(User.is_active == True, User.organization_id == org_id).count() or 0,
                'organizations': 1,
                'products': Product.query.filter_by(organization_id=org_id).count() or 0,
                'agents': Asset.query.filter(Asset.active == True, Asset.organization_id == org_id).count() or 0,
                'agent_api_keys': AgentApiKey.query.filter(AgentApiKey.active == True, AgentApiKey.organization_id == org_id).count() or 0,
            }
        })

    from app.models import User, Organization, Product, Asset, AgentApiKey

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
    """Activate a license key (on-premise only)"""
    from app.saas import is_saas_mode
    if is_saas_mode():
        return jsonify({'error': 'License activation is not available in SaaS mode. Use the Subscription panel instead.'}), 403

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
    """Activate a license online using an activation code (on-premise only).

    The customer provides their activation code (from purchase confirmation).
    This endpoint contacts the SentriKat license portal to exchange the code
    for a hardware-locked license key, then saves it locally.

    Requires SSL/HTTPS connectivity to portal.sentrikat.com.
    Rate limited to 5 attempts per hour to prevent brute force.
    """
    from app.saas import is_saas_mode
    if is_saas_mode():
        return jsonify({'error': 'Online license activation is not available in SaaS mode.'}), 403
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
    """Remove license and revert to Community Edition (on-premise only)"""
    from app.saas import is_saas_mode
    if is_saas_mode():
        return jsonify({'error': 'License management is not available in SaaS mode.'}), 403

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
    """Get this installation's ID for license requests (on-premise only)"""
    from app.saas import is_saas_mode
    if is_saas_mode():
        return jsonify({'error': 'Installation ID is not applicable in SaaS mode.'}), 403

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
