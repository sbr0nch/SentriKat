#!/usr/bin/env python3
"""
Generate a secure SECRET_KEY for Flask application.

Usage:
    python generate_secret_key.py

This will generate a cryptographically secure random string that can be used
as the SECRET_KEY in your .env file.

The SECRET_KEY is used by Flask to:
- Sign session cookies to prevent tampering
- Encrypt sensitive data in cookies
- Provide cryptographic operations for CSRF protection

IMPORTANT:
- Never commit your SECRET_KEY to version control
- Use a different SECRET_KEY for each environment (dev, staging, production)
- Keep your SECRET_KEY private and secure
- If compromised, generate a new one immediately (this will invalidate all sessions)
"""

import secrets
import string

def generate_secret_key(length=64):
    """
    Generate a cryptographically secure secret key.

    Args:
        length (int): Length of the secret key (default: 64)

    Returns:
        str: A secure random string
    """
    # Using secrets module which is cryptographically strong
    return secrets.token_hex(length // 2)

def generate_alphanumeric_key(length=64):
    """
    Generate a cryptographically secure alphanumeric secret key.

    Args:
        length (int): Length of the secret key (default: 64)

    Returns:
        str: A secure random alphanumeric string
    """
    alphabet = string.ascii_letters + string.digits
    return ''.join(secrets.choice(alphabet) for _ in range(length))

if __name__ == '__main__':
    print("=" * 80)
    print("SECRET_KEY Generator for SentriKat")
    print("=" * 80)
    print()

    print("What is a SECRET_KEY?")
    print("-" * 80)
    print("The SECRET_KEY is a random string used by Flask to securely sign cookies")
    print("and session data. It ensures that users cannot tamper with session data.")
    print()
    print("Why do I need it?")
    print("-" * 80)
    print("Without a strong SECRET_KEY, attackers could forge session cookies and")
    print("impersonate users or manipulate application data.")
    print()
    print("=" * 80)
    print()

    # Generate keys
    hex_key = generate_secret_key(64)
    alphanumeric_key = generate_alphanumeric_key(64)

    print("Generated SECRET_KEYs (choose one):")
    print()
    print("Option 1 - Hexadecimal (recommended):")
    print(f"SECRET_KEY={hex_key}")
    print()
    print("Option 2 - Alphanumeric:")
    print(f"SECRET_KEY={alphanumeric_key}")
    print()
    print("=" * 80)
    print()
    print("How to use:")
    print("1. Copy one of the SECRET_KEY lines above")
    print("2. Open your .env file")
    print("3. Replace the existing SECRET_KEY= line with the new one")
    print("4. Save the file and restart your application")
    print()
    print("SECURITY NOTES:")
    print("- Keep this key private and secure")
    print("- Never commit it to version control")
    print("- Use different keys for dev/staging/production")
    print("- If compromised, generate a new key immediately")
    print("=" * 80)
