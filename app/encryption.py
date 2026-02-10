"""
Encryption utilities for sensitive data in SentriKat.

Uses Fernet symmetric encryption from the cryptography library.
The encryption key must be set via the ENCRYPTION_KEY environment variable.

Usage:
    from app.encryption import encrypt_value, decrypt_value

    # Encrypt a password before storing
    encrypted = encrypt_value("my_secret_password")

    # Decrypt when retrieving
    decrypted = decrypt_value(encrypted)
"""

import os
import base64
import hashlib
from cryptography.fernet import Fernet, InvalidToken

# Cache the Fernet instance for performance
_fernet_instance = None


def _get_fernet():
    """Get or create Fernet instance using ENCRYPTION_KEY from environment."""
    global _fernet_instance

    if _fernet_instance is not None:
        return _fernet_instance

    encryption_key = os.environ.get('ENCRYPTION_KEY')

    if not encryption_key:
        # Derive a stable key from SECRET_KEY so encrypted settings (Jira PAT,
        # SMTP password, etc.) survive container restarts as long as SECRET_KEY
        # remains the same.
        import logging
        _logger = logging.getLogger(__name__)
        if os.environ.get('FLASK_ENV') == 'production':
            _logger.warning(
                "ENCRYPTION_KEY not set - deriving from SECRET_KEY. "
                "For best security, set ENCRYPTION_KEY in .env. Generate with: "
                "python -c \"from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())\""
            )
        secret_key = os.environ.get('SECRET_KEY', 'dev-secret-key-change-in-production')
        # Derive a valid Fernet key (32 bytes, base64-encoded) from SECRET_KEY
        key_bytes = hashlib.sha256(secret_key.encode()).digest()
        encryption_key = base64.urlsafe_b64encode(key_bytes).decode()

    _fernet_instance = Fernet(encryption_key.encode() if isinstance(encryption_key, str) else encryption_key)
    return _fernet_instance


def encrypt_value(plaintext):
    """
    Encrypt a plaintext string.

    Args:
        plaintext: The string to encrypt

    Returns:
        Base64-encoded encrypted string, or None if plaintext is None/empty
    """
    if not plaintext:
        return plaintext

    try:
        fernet = _get_fernet()
        encrypted = fernet.encrypt(plaintext.encode())
        return encrypted.decode()
    except Exception as e:
        import logging
        logging.getLogger(__name__).error(f"Encryption failed: {type(e).__name__}")
        raise


def decrypt_value(encrypted_text):
    """
    Decrypt an encrypted string.

    Args:
        encrypted_text: The base64-encoded encrypted string

    Returns:
        Decrypted plaintext string, or None if encrypted_text is None/empty
    """
    if not encrypted_text:
        return encrypted_text

    try:
        fernet = _get_fernet()
        decrypted = fernet.decrypt(encrypted_text.encode())
        return decrypted.decode()
    except InvalidToken:
        # Value might be stored in plaintext (legacy) - return as-is with warning
        import logging
        logging.getLogger(__name__).warning(
            "Failed to decrypt value - may be plaintext legacy data. "
            "Run encryption migration to fix."
        )
        return encrypted_text
    except Exception as e:
        import logging
        logging.getLogger(__name__).error(f"Decryption failed: {type(e).__name__}")
        raise


def is_encrypted(value):
    """
    Check if a value appears to be encrypted (Fernet format).

    Fernet tokens start with 'gAAAAA' (base64-encoded version byte).

    Args:
        value: The string to check

    Returns:
        True if the value appears to be Fernet-encrypted
    """
    if not value or not isinstance(value, str):
        return False

    # Fernet tokens are base64 and start with specific bytes
    # They're typically 100+ characters
    return value.startswith('gAAAAA') and len(value) > 100


def generate_key():
    """Generate a new Fernet encryption key."""
    return Fernet.generate_key().decode()


def clear_cache():
    """Clear the cached Fernet instance (useful for testing)."""
    global _fernet_instance
    _fernet_instance = None
