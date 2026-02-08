"""
SAML 2.0 SSO Manager for SentriKat

Provides Single Sign-On (SSO) authentication via SAML 2.0 protocol.
Supports SP-initiated SSO with any SAML 2.0 compliant Identity Provider (IdP).

Architecture:
- SentriKat acts as the Service Provider (SP)
- Customers configure their IdP (Okta, Azure AD, ADFS, etc.)
- Users authenticate at IdP, then are redirected back to SentriKat

Flow:
1. User clicks "Login with SSO" on SentriKat login page
2. SentriKat generates SAML AuthnRequest and redirects to IdP
3. User authenticates at IdP
4. IdP POSTs SAML Response to SentriKat ACS URL
5. SentriKat validates response and creates user session

Requirements:
- pip install python3-saml
- IdP metadata (XML or URL)
- SP certificate and private key (optional but recommended)

Configuration stored in SystemSettings:
- saml_enabled: Enable/disable SAML
- saml_idp_metadata: IdP metadata (XML or URL)
- saml_sp_entity_id: SP entity ID (default: SentriKat installation ID)
- saml_sp_acs_url: Assertion Consumer Service URL
- saml_sp_sls_url: Single Logout Service URL (optional)
- saml_default_org_id: Default org for new SAML users
- saml_user_mapping: JSON mapping of SAML attributes to user fields
"""
import logging
from typing import Optional, Dict, Any, Tuple
from datetime import datetime
from urllib.parse import urlparse

logger = logging.getLogger(__name__)

# Check if python3-saml is available
SAML_AVAILABLE = False
try:
    from onelogin.saml2.auth import OneLogin_Saml2_Auth
    from onelogin.saml2.settings import OneLogin_Saml2_Settings
    from onelogin.saml2.utils import OneLogin_Saml2_Utils
    from onelogin.saml2.idp_metadata_parser import OneLogin_Saml2_IdPMetadataParser
    SAML_AVAILABLE = True
except ImportError:
    logger.warning("python3-saml not installed. SAML SSO will not be available. Install with: pip install python3-saml")


def is_saml_available() -> bool:
    """Check if SAML library is installed."""
    return SAML_AVAILABLE


def get_saml_settings() -> Dict[str, Any]:
    """
    Get SAML configuration from database settings.
    Returns dict suitable for python3-saml.
    """
    from app.settings_api import get_setting
    from app.licensing import get_installation_id

    if not SAML_AVAILABLE:
        return {}

    enabled = get_setting('saml_enabled', 'false') == 'true'
    if not enabled:
        return {}

    # Get IdP metadata
    idp_metadata = get_setting('saml_idp_metadata', '')
    if not idp_metadata:
        return {}

    # Parse IdP metadata
    try:
        if idp_metadata.startswith('http'):
            # URL - fetch and parse
            idp_data = OneLogin_Saml2_IdPMetadataParser.parse_remote(idp_metadata)
        else:
            # Raw XML
            idp_data = OneLogin_Saml2_IdPMetadataParser.parse(idp_metadata)
    except Exception as e:
        logger.error(f"Failed to parse IdP metadata: {e}")
        return {}

    # SP configuration
    sp_entity_id = get_setting('saml_sp_entity_id', '') or f"sentrikat:{get_installation_id()}"
    sp_acs_url = get_setting('saml_sp_acs_url', '')
    sp_sls_url = get_setting('saml_sp_sls_url', '')

    # Build settings dict
    settings = {
        'strict': True,
        'debug': False,
        'sp': {
            'entityId': sp_entity_id,
            'assertionConsumerService': {
                'url': sp_acs_url,
                'binding': 'urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST'
            },
            'NameIDFormat': 'urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress'
        },
        'idp': idp_data.get('idp', {})
    }

    # Add SLS if configured
    if sp_sls_url:
        settings['sp']['singleLogoutService'] = {
            'url': sp_sls_url,
            'binding': 'urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect'
        }

    return settings


def prepare_flask_request(request) -> Dict[str, Any]:
    """
    Convert Flask request to format expected by python3-saml.
    """
    url_data = urlparse(request.url)
    return {
        'https': 'on' if request.scheme == 'https' else 'off',
        'http_host': request.host,
        'server_port': url_data.port or (443 if request.scheme == 'https' else 80),
        'script_name': request.path,
        'get_data': request.args.copy(),
        'post_data': request.form.copy()
    }


def init_saml_auth(request) -> Optional['OneLogin_Saml2_Auth']:
    """
    Initialize SAML Auth object from Flask request.
    Returns None if SAML is not available or configured.
    """
    if not SAML_AVAILABLE:
        return None

    settings = get_saml_settings()
    if not settings:
        return None

    try:
        req = prepare_flask_request(request)
        auth = OneLogin_Saml2_Auth(req, settings)
        return auth
    except Exception as e:
        logger.error(f"Failed to initialize SAML auth: {e}")
        return None


def generate_login_url(request, return_to: Optional[str] = None) -> Optional[str]:
    """
    Generate SAML login URL (redirect to IdP).

    Args:
        request: Flask request object
        return_to: URL to return to after login (optional)

    Returns:
        IdP login URL or None if SAML not configured
    """
    auth = init_saml_auth(request)
    if not auth:
        return None

    try:
        return auth.login(return_to=return_to)
    except Exception as e:
        logger.error(f"Failed to generate SAML login URL: {e}")
        return None


def process_saml_response(request) -> Tuple[bool, Optional[Dict], Optional[str]]:
    """
    Process SAML response from IdP.

    Args:
        request: Flask request with SAML response

    Returns:
        Tuple of (success, user_data, error_message)
        user_data contains: email, username, first_name, last_name, attributes
    """
    auth = init_saml_auth(request)
    if not auth:
        return False, None, "SAML not configured"

    try:
        auth.process_response()
        errors = auth.get_errors()

        if errors:
            error_reason = auth.get_last_error_reason()
            logger.error(f"SAML errors: {errors}, reason: {error_reason}")
            return False, None, f"SAML validation failed: {error_reason}"

        if not auth.is_authenticated():
            return False, None, "Authentication failed"

        # Extract user data from SAML response
        name_id = auth.get_nameid()
        attributes = auth.get_attributes()

        # Get user mapping configuration
        from app.settings_api import get_setting
        import json
        mapping_str = get_setting('saml_user_mapping', '{}')
        try:
            mapping = json.loads(mapping_str)
        except:
            mapping = {}

        # Default mapping
        default_mapping = {
            'email': ['email', 'mail', 'emailAddress', 'http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress'],
            'username': ['username', 'uid', 'http://schemas.xmlsoap.org/ws/2005/05/identity/claims/name'],
            'first_name': ['firstName', 'givenName', 'http://schemas.xmlsoap.org/ws/2005/05/identity/claims/givenname'],
            'last_name': ['lastName', 'sn', 'surname', 'http://schemas.xmlsoap.org/ws/2005/05/identity/claims/surname'],
            'display_name': ['displayName', 'cn', 'http://schemas.xmlsoap.org/ws/2005/05/identity/claims/displayname']
        }

        def get_attribute(attr_keys):
            """Get first matching attribute from SAML response."""
            if isinstance(attr_keys, str):
                attr_keys = [attr_keys]
            for key in attr_keys:
                if key in attributes and attributes[key]:
                    val = attributes[key]
                    return val[0] if isinstance(val, list) else val
            return None

        # Build user data
        user_data = {
            'email': get_attribute(mapping.get('email', default_mapping['email'])) or name_id,
            'username': get_attribute(mapping.get('username', default_mapping['username'])),
            'first_name': get_attribute(mapping.get('first_name', default_mapping['first_name'])),
            'last_name': get_attribute(mapping.get('last_name', default_mapping['last_name'])),
            'display_name': get_attribute(mapping.get('display_name', default_mapping['display_name'])),
            'name_id': name_id,
            'session_index': auth.get_session_index(),
            'attributes': attributes
        }

        # Generate username from email if not provided
        if not user_data['username'] and user_data['email']:
            user_data['username'] = user_data['email'].split('@')[0]

        return True, user_data, None

    except Exception as e:
        logger.exception("Failed to process SAML response")
        return False, None, str(e)


def get_or_create_saml_user(user_data: Dict) -> Tuple[Optional[Any], bool]:
    """
    Get or create a user from SAML data.

    Args:
        user_data: Dict with email, username, first_name, last_name, etc.

    Returns:
        Tuple of (user, created) where created is True if user was just created
    """
    from app import db
    from app.models import User, Organization
    from app.settings_api import get_setting

    email = user_data.get('email')
    if not email:
        logger.error("SAML response missing email")
        return None, False

    # Try to find existing user
    user = User.query.filter_by(email=email).first()

    if user:
        # Update user info if changed
        if user_data.get('first_name'):
            user.first_name = user_data['first_name']
        if user_data.get('last_name'):
            user.last_name = user_data['last_name']
        if user_data.get('display_name'):
            user.display_name = user_data['display_name']

        user.auth_type = 'saml'
        user.last_login = datetime.utcnow()
        db.session.commit()

        return user, False

    # Create new user
    default_org_id = get_setting('saml_default_org_id', '')

    # Get default organization
    if default_org_id:
        try:
            org = Organization.query.get(int(default_org_id))
        except (ValueError, TypeError):
            logger.error(f"Invalid saml_default_org_id: {default_org_id}")
            org = None
    else:
        org = Organization.query.first()

    if not org:
        logger.error("No organization available for SAML user")
        return None, False

    username = user_data.get('username') or email.split('@')[0]

    # Ensure unique username
    base_username = username
    counter = 1
    while User.query.filter_by(username=username).first():
        username = f"{base_username}{counter}"
        counter += 1

    # Build full_name from SAML attributes
    first_name = user_data.get('first_name', '')
    last_name = user_data.get('last_name', '')
    display_name = user_data.get('display_name', '')
    full_name = display_name or f"{first_name} {last_name}".strip() or username

    user = User(
        username=username,
        email=email,
        full_name=full_name,
        auth_type='saml',
        role='viewer',  # Default role for SAML users
        is_active=True,
        organization_id=org.id
    )

    db.session.add(user)
    db.session.commit()

    logger.info(f"Created SAML user: {username} ({email})")
    return user, True


def get_saml_metadata() -> Optional[str]:
    """
    Generate SP metadata XML for configuring IdP.
    """
    if not SAML_AVAILABLE:
        return None

    settings = get_saml_settings()
    if not settings:
        return None

    try:
        saml_settings = OneLogin_Saml2_Settings(settings)
        metadata = saml_settings.get_sp_metadata()
        errors = saml_settings.validate_metadata(metadata)
        if errors:
            logger.error(f"SP metadata validation errors: {errors}")
        return metadata
    except Exception as e:
        logger.error(f"Failed to generate SP metadata: {e}")
        return None
