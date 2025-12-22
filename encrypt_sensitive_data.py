#!/usr/bin/env python3
"""
Migration script to encrypt sensitive data in the database.

This script encrypts:
1. LDAP bind password in system_settings table
2. SMTP password in system_settings table
3. SMTP passwords in organizations table (per-org settings)

IMPORTANT: Set ENCRYPTION_KEY environment variable before running!
Generate a key with: python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"

Usage:
    # First generate and set encryption key
    export ENCRYPTION_KEY=$(python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())")

    # Then run migration
    python encrypt_sensitive_data.py
"""

import os
import sys

# Add parent directory to path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from app import create_app, db
from app.models import SystemSettings, Organization
from app.encryption import encrypt_value, is_encrypted, generate_key


def check_encryption_key():
    """Check that ENCRYPTION_KEY is set."""
    key = os.environ.get('ENCRYPTION_KEY')
    if not key:
        print("=" * 60)
        print("ERROR: ENCRYPTION_KEY environment variable not set!")
        print("=" * 60)
        print()
        print("Generate and set a key with:")
        print()
        print('  export ENCRYPTION_KEY=$(python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())")')
        print()
        print("Or generate one now:")
        new_key = generate_key()
        print(f"  export ENCRYPTION_KEY={new_key}")
        print()
        print("IMPORTANT: Save this key securely! You will need it to decrypt the data.")
        print("Add it to your .env file or deployment configuration.")
        print("=" * 60)
        return False
    return True


def encrypt_system_settings():
    """Encrypt sensitive system settings (LDAP and SMTP passwords)."""
    sensitive_keys = [
        'ldap_bind_password',
        'smtp_password',
        'nvd_api_key'  # Future: NVD API key
    ]

    encrypted_count = 0
    skipped_count = 0

    for key in sensitive_keys:
        setting = SystemSettings.query.filter_by(key=key).first()
        if not setting:
            continue

        if not setting.value:
            print(f"  {key}: No value set, skipping")
            skipped_count += 1
            continue

        # Check if already encrypted
        if is_encrypted(setting.value):
            print(f"  {key}: Already encrypted, skipping")
            skipped_count += 1
            continue

        # Encrypt the value
        try:
            setting.value = encrypt_value(setting.value)
            setting.is_encrypted = True
            encrypted_count += 1
            print(f"  {key}: ENCRYPTED")
        except Exception as e:
            print(f"  {key}: FAILED to encrypt - {e}")

    return encrypted_count, skipped_count


def encrypt_organization_smtp():
    """Encrypt SMTP passwords in organization settings."""
    organizations = Organization.query.all()

    encrypted_count = 0
    skipped_count = 0

    for org in organizations:
        if not org.smtp_password:
            continue

        # Check if already encrypted
        if is_encrypted(org.smtp_password):
            print(f"  Organization '{org.name}': SMTP password already encrypted, skipping")
            skipped_count += 1
            continue

        # Encrypt the value
        try:
            org.smtp_password = encrypt_value(org.smtp_password)
            encrypted_count += 1
            print(f"  Organization '{org.name}': SMTP password ENCRYPTED")
        except Exception as e:
            print(f"  Organization '{org.name}': FAILED to encrypt SMTP password - {e}")

    return encrypted_count, skipped_count


def main():
    """Run the encryption migration."""
    print("=" * 60)
    print("SentriKat Sensitive Data Encryption Migration")
    print("=" * 60)
    print()

    # Check encryption key
    if not check_encryption_key():
        sys.exit(1)

    app = create_app()

    with app.app_context():
        print("Encrypting system settings...")
        sys_encrypted, sys_skipped = encrypt_system_settings()
        print()

        print("Encrypting organization SMTP passwords...")
        org_encrypted, org_skipped = encrypt_organization_smtp()
        print()

        # Commit all changes
        try:
            db.session.commit()
            print("=" * 60)
            print("Migration completed successfully!")
            print("=" * 60)
            print()
            print("Summary:")
            print(f"  System settings encrypted: {sys_encrypted}")
            print(f"  System settings skipped: {sys_skipped}")
            print(f"  Organization passwords encrypted: {org_encrypted}")
            print(f"  Organization passwords skipped: {org_skipped}")
            print()
            print("IMPORTANT: Save your ENCRYPTION_KEY securely!")
            print("Add it to your .env file or deployment configuration:")
            print(f"  ENCRYPTION_KEY={os.environ.get('ENCRYPTION_KEY')}")
        except Exception as e:
            db.session.rollback()
            print(f"ERROR: Failed to commit changes - {e}")
            sys.exit(1)


if __name__ == '__main__':
    main()
