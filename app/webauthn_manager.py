import logging
import os
import json

logger = logging.getLogger(__name__)

try:
    from webauthn import (
        generate_registration_options,
        verify_registration_response,
        generate_authentication_options,
        verify_authentication_response,
        options_to_json,
    )
    from webauthn.helpers.structs import (
        AuthenticatorSelectionCriteria,
        UserVerificationRequirement,
        ResidentKeyRequirement,
        PublicKeyCredentialDescriptor,
    )
    from webauthn.helpers import bytes_to_base64url
    WEBAUTHN_AVAILABLE = True
except ImportError:
    WEBAUTHN_AVAILABLE = False
    logger.info("py_webauthn not installed - WebAuthn/FIDO2 support disabled")


def get_rp_id():
    """Get Relying Party ID from SENTRIKAT_URL or env"""
    from urllib.parse import urlparse
    url = os.environ.get('SENTRIKAT_URL', 'http://localhost')
    parsed = urlparse(url)
    return parsed.hostname or 'localhost'


def get_rp_name():
    """Get Relying Party name"""
    try:
        from app.models import SystemSettings
        setting = SystemSettings.query.filter_by(key='app_name').first()
        return setting.value if setting else 'SentriKat'
    except Exception:
        return 'SentriKat'


def generate_registration(user):
    """Generate WebAuthn registration options for a user"""
    if not WEBAUTHN_AVAILABLE:
        raise RuntimeError("WebAuthn not available - install py_webauthn")

    existing_credentials = []
    for cred in user.webauthn_credentials:
        existing_credentials.append(
            PublicKeyCredentialDescriptor(id=cred.credential_id)
        )

    options = generate_registration_options(
        rp_id=get_rp_id(),
        rp_name=get_rp_name(),
        user_id=str(user.id).encode(),
        user_name=user.username,
        user_display_name=user.full_name or user.username,
        exclude_credentials=existing_credentials,
        authenticator_selection=AuthenticatorSelectionCriteria(
            user_verification=UserVerificationRequirement.PREFERRED,
        ),
    )
    return options


def verify_registration(user, credential_json, expected_challenge):
    """Verify WebAuthn registration response"""
    if not WEBAUTHN_AVAILABLE:
        raise RuntimeError("WebAuthn not available")

    verification = verify_registration_response(
        credential=credential_json,
        expected_challenge=expected_challenge,
        expected_rp_id=get_rp_id(),
        expected_origin=os.environ.get('SENTRIKAT_URL', 'http://localhost'),
    )
    return verification


def generate_authentication(user):
    """Generate WebAuthn authentication options"""
    if not WEBAUTHN_AVAILABLE:
        raise RuntimeError("WebAuthn not available")

    credentials = []
    for cred in user.webauthn_credentials:
        credentials.append(
            PublicKeyCredentialDescriptor(id=cred.credential_id)
        )

    options = generate_authentication_options(
        rp_id=get_rp_id(),
        allow_credentials=credentials,
        user_verification=UserVerificationRequirement.PREFERRED,
    )
    return options


def verify_authentication(credential_json, expected_challenge, credential_record):
    """Verify WebAuthn authentication response"""
    if not WEBAUTHN_AVAILABLE:
        raise RuntimeError("WebAuthn not available")

    verification = verify_authentication_response(
        credential=credential_json,
        expected_challenge=expected_challenge,
        expected_rp_id=get_rp_id(),
        expected_origin=os.environ.get('SENTRIKAT_URL', 'http://localhost'),
        credential_public_key=credential_record.public_key,
        credential_current_sign_count=credential_record.sign_count,
    )
    return verification
