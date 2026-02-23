"""
OAuth/OIDC Authentication Manager

Supports generic OIDC providers (Okta, Azure AD, Google, Keycloak, etc.)
Configuration is stored in SystemSettings (database), not environment variables.

Authlib is optional - the app works without it; OIDC features are simply unavailable.
"""

import logging

logger = logging.getLogger(__name__)

# Graceful import - app works without authlib installed
try:
    from authlib.integrations.flask_client import OAuth
    AUTHLIB_AVAILABLE = True
except ImportError:
    OAuth = None
    AUTHLIB_AVAILABLE = False
    logger.info("Authlib not installed - OIDC/OAuth authentication unavailable. "
                "Install with: pip install Authlib==1.4.1")


# OIDC setting keys stored in SystemSettings
OIDC_SETTING_KEYS = [
    'oidc_enabled',
    'oidc_provider_name',
    'oidc_client_id',
    'oidc_client_secret',      # encrypted
    'oidc_discovery_url',
    'oidc_scopes',
    'oidc_auto_provision',
    'oidc_default_role',
]


def get_oidc_config():
    """
    Load OIDC configuration from SystemSettings.

    Returns:
        dict: OIDC configuration values, or None if OIDC is not enabled/configured.
    """
    from app.settings_api import get_setting

    enabled = get_setting('oidc_enabled', 'false')
    if enabled != 'true':
        return None

    client_id = get_setting('oidc_client_id', '')
    client_secret = get_setting('oidc_client_secret', '')
    discovery_url = get_setting('oidc_discovery_url', '')

    if not client_id or not discovery_url:
        logger.warning("OIDC is enabled but client_id or discovery_url is not configured")
        return None

    scopes = get_setting('oidc_scopes', 'openid email profile')
    provider_name = get_setting('oidc_provider_name', 'OIDC Provider')
    auto_provision = get_setting('oidc_auto_provision', 'true') == 'true'
    default_role = get_setting('oidc_default_role', 'user')

    return {
        'enabled': True,
        'provider_name': provider_name,
        'client_id': client_id,
        'client_secret': client_secret,
        'discovery_url': discovery_url,
        'scopes': scopes,
        'auto_provision': auto_provision,
        'default_role': default_role,
    }


def create_oidc_client(app):
    """
    Create and register an OAuth client with Authlib using OIDC discovery.

    Args:
        app: Flask application instance

    Returns:
        OAuth client object ready for authorization, or None if not available.
    """
    if not AUTHLIB_AVAILABLE:
        logger.error("Cannot create OIDC client: authlib is not installed")
        return None

    config = get_oidc_config()
    if not config:
        return None

    oauth = OAuth(app)

    # Register the OIDC provider using OpenID Connect discovery
    oauth.register(
        name='oidc',
        client_id=config['client_id'],
        client_secret=config['client_secret'],
        server_metadata_url=config['discovery_url'],
        client_kwargs={
            'scope': config['scopes'],
        },
    )

    return oauth


def handle_oidc_callback(token, userinfo):
    """
    Process OIDC callback - find or create user, prepare for session setup.

    This function looks up the user by email from the OIDC userinfo.
    If auto-provisioning is enabled and the user doesn't exist, it creates one.

    Args:
        token: OAuth token response (contains access_token, id_token, etc.)
        userinfo: Decoded userinfo from the OIDC provider

    Returns:
        tuple: (User object, error_message)
            - On success: (user, None)
            - On failure: (None, "error description")
    """
    from app import db
    from app.models import User, Organization

    if not userinfo:
        return None, 'No user information received from OIDC provider'

    # Extract user attributes from userinfo claims
    email = userinfo.get('email')
    if not email:
        return None, 'OIDC provider did not return an email address'

    # Prefer 'preferred_username' (Keycloak, etc.), fall back to email prefix
    username = userinfo.get('preferred_username') or email.split('@')[0]
    full_name = userinfo.get('name') or ''

    # If preferred_username is an email, use just the local part for username
    if '@' in username:
        username = username.split('@')[0]

    # Sanitize username: lowercase, replace spaces/special chars
    username = username.lower().strip().replace(' ', '_')
    # Remove characters that are not alphanumeric, underscore, hyphen, or dot
    import re
    username = re.sub(r'[^a-z0-9._-]', '', username)

    if not username:
        username = email.split('@')[0].lower()

    logger.info(f"OIDC callback: email={email}, username={username}, name={full_name}")

    config = get_oidc_config()
    if not config:
        return None, 'OIDC configuration is no longer available'

    # Try to find existing user by email first (most reliable)
    user = User.query.filter_by(email=email, is_active=True).first()

    if user:
        # Existing user found - update auth_type if this is their first OIDC login
        if user.auth_type not in ('oidc',):
            logger.info(f"OIDC: User {user.username} exists with auth_type={user.auth_type}, "
                       f"keeping existing auth_type")
        # Update full name if provided and user doesn't have one
        if full_name and not user.full_name:
            user.full_name = full_name
        try:
            db.session.commit()
        except Exception:
            db.session.rollback()
        return user, None

    # Also check by username (in case email changed)
    user = User.query.filter_by(username=username, is_active=True).first()
    if user:
        # User exists with this username but different email
        # Only link if their auth_type is already oidc
        if user.auth_type == 'oidc':
            logger.info(f"OIDC: Linking existing OIDC user {username} with new email {email}")
            user.email = email
            if full_name and not user.full_name:
                user.full_name = full_name
            try:
                db.session.commit()
            except Exception:
                db.session.rollback()
            return user, None
        else:
            # Username collision with a local/ldap user - don't auto-link
            logger.warning(f"OIDC: Username '{username}' already exists with auth_type={user.auth_type}. "
                         f"Cannot auto-link OIDC user with email {email}")
            return None, (f'A user with username "{username}" already exists with a different '
                         f'authentication type. Contact your administrator to link your accounts.')

    # User doesn't exist - check if auto-provisioning is enabled
    if not config.get('auto_provision', True):
        logger.info(f"OIDC: User {email} not found and auto-provisioning is disabled")
        return None, ('Your account has not been provisioned in SentriKat. '
                     'Contact your administrator to create your account.')

    # Auto-provision new user
    default_role = config.get('default_role', 'user')

    # Ensure username is unique (append number if collision with inactive user)
    base_username = username
    counter = 1
    while User.query.filter_by(username=username).first():
        username = f"{base_username}{counter}"
        counter += 1

    # Assign to default organization
    default_org = Organization.query.filter_by(name='default').first()
    if not default_org:
        default_org = Organization.query.first()

    org_id = default_org.id if default_org else None

    user = User(
        username=username,
        email=email,
        full_name=full_name or username,
        auth_type='oidc',
        role=default_role,
        is_active=True,
        is_admin=(default_role == 'super_admin'),
        organization_id=org_id,
        can_manage_products=(default_role in ('super_admin', 'org_admin', 'manager')),
    )

    try:
        db.session.add(user)
        db.session.commit()
        logger.info(f"OIDC: Auto-provisioned new user {username} ({email}) with role {default_role}")
    except Exception as e:
        db.session.rollback()
        logger.error(f"OIDC: Failed to create user {username}: {e}")
        return None, 'Failed to create user account. Please try again or contact your administrator.'

    return user, None


def get_oidc_public_config():
    """
    Get OIDC configuration safe for public/admin display (no secrets).

    Returns:
        dict: OIDC configuration without client_secret.
    """
    from app.settings_api import get_setting

    enabled = get_setting('oidc_enabled', 'false') == 'true'

    return {
        'enabled': enabled,
        'provider_name': get_setting('oidc_provider_name', 'OIDC Provider'),
        'client_id': get_setting('oidc_client_id', ''),
        'discovery_url': get_setting('oidc_discovery_url', ''),
        'scopes': get_setting('oidc_scopes', 'openid email profile'),
        'auto_provision': get_setting('oidc_auto_provision', 'true') == 'true',
        'default_role': get_setting('oidc_default_role', 'user'),
        'client_secret_configured': bool(get_setting('oidc_client_secret', '')),
        'authlib_available': AUTHLIB_AVAILABLE,
    }
