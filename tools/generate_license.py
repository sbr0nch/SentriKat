#!/usr/bin/env python3
"""
SentriKat License Generator

Generates hardware-locked license keys for SentriKat customers.
Each license is tied to a specific installation ID and cannot be used elsewhere.

WORKFLOW:
1. Customer installs SentriKat and gets their Installation ID from Admin Panel
2. Customer sends Installation ID + company details to SentriKat sales
3. Use this tool to generate a license locked to that Installation ID
4. Send the license key to the customer

Usage:
    # First time: Generate RSA keys
    python generate_license.py --generate-keys

    # Generate a hardware-locked license
    python generate_license.py \\
        --customer "Acme Corp" \\
        --email "admin@acme.com" \\
        --edition professional \\
        --installation-id "SK-INST-ABCD1234..." \\
        --expires 2027-01-15

KEEP THE PRIVATE KEY SECURE - Never share it!
"""

import argparse
import json
import base64
import hashlib
import os
import sys
from datetime import datetime, date
from pathlib import Path

# Directory for keys
KEYS_DIR = Path(__file__).parent / '.license_keys'
PRIVATE_KEY_FILE = KEYS_DIR / 'private_key.pem'
PUBLIC_KEY_FILE = KEYS_DIR / 'public_key.pem'


def generate_keys():
    """Generate RSA key pair for license signing"""
    try:
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.asymmetric import rsa
        from cryptography.hazmat.backends import default_backend
    except ImportError:
        print("Error: cryptography package required. Install with: pip install cryptography")
        sys.exit(1)

    KEYS_DIR.mkdir(exist_ok=True)

    if PRIVATE_KEY_FILE.exists():
        response = input("Keys already exist. Overwrite? (yes/no): ")
        if response.lower() != 'yes':
            print("Cancelled.")
            return

    print("Generating RSA key pair...")

    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )

    # Save private key
    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )
    PRIVATE_KEY_FILE.write_bytes(private_pem)
    os.chmod(PRIVATE_KEY_FILE, 0o600)

    # Save public key
    public_key = private_key.public_key()
    public_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    PUBLIC_KEY_FILE.write_bytes(public_pem)

    print(f"\nKeys generated successfully!")
    print(f"  Private key: {PRIVATE_KEY_FILE}")
    print(f"  Public key:  {PUBLIC_KEY_FILE}")
    print(f"\nIMPORTANT:")
    print(f"  1. Keep the private key SECURE - never share it!")
    print(f"  2. Copy the public key to app/licensing.py (LICENSE_PUBLIC_KEY)")
    print(f"\nPublic key to embed in app:")
    print("-" * 60)
    print(public_pem.decode())
    print("-" * 60)


def generate_license_id():
    """Generate a unique license ID"""
    import time
    import random

    data = f"{time.time()}-{random.randint(0, 999999)}"
    hash_val = hashlib.md5(data.encode()).hexdigest()[:8].upper()
    return f"SK-{datetime.now().year}-{hash_val}"


def create_license(customer, email, edition, installation_id, expires_at=None,
                   max_users=None, max_organizations=None, max_products=None):
    """Create a hardware-locked signed license key"""
    try:
        from cryptography.hazmat.primitives import hashes, serialization
        from cryptography.hazmat.primitives.asymmetric import padding
        from cryptography.hazmat.backends import default_backend
    except ImportError:
        print("Error: cryptography package required. Install with: pip install cryptography")
        sys.exit(1)

    if not PRIVATE_KEY_FILE.exists():
        print("Error: Private key not found. Run with --generate-keys first.")
        sys.exit(1)

    # Load private key
    private_key = serialization.load_pem_private_key(
        PRIVATE_KEY_FILE.read_bytes(),
        password=None,
        backend=default_backend()
    )

    # Build license payload
    license_id = generate_license_id()

    payload = {
        'license_id': license_id,
        'customer': customer,
        'email': email,
        'edition': edition,
        'installation_id': installation_id,  # HARDWARE LOCK
        'issued_at': date.today().isoformat(),
    }

    # Add expiration
    if expires_at:
        payload['expires_at'] = expires_at

    # Add limits
    limits = {}
    if edition == 'professional':
        limits['max_users'] = max_users if max_users else -1
        limits['max_organizations'] = max_organizations if max_organizations else -1
        limits['max_products'] = max_products if max_products else -1
        payload['features'] = [
            'ldap', 'email_alerts', 'white_label',
            'api_access', 'backup_restore', 'audit_export', 'multi_org'
        ]
    else:
        limits['max_users'] = max_users if max_users else 3
        limits['max_organizations'] = max_organizations if max_organizations else 1
        limits['max_products'] = max_products if max_products else 20
        payload['features'] = []

    payload['limits'] = limits

    # Serialize payload
    payload_json = json.dumps(payload, separators=(',', ':'), sort_keys=True)
    payload_b64 = base64.urlsafe_b64encode(payload_json.encode()).decode().rstrip('=')

    # Sign payload
    signature = private_key.sign(
        payload_json.encode(),
        padding.PKCS1v15(),
        hashes.SHA256()
    )
    signature_b64 = base64.urlsafe_b64encode(signature).decode().rstrip('=')

    # Combine into license key
    license_key = f"{payload_b64}.{signature_b64}"

    return license_id, payload, license_key


def main():
    parser = argparse.ArgumentParser(
        description='SentriKat License Generator - Hardware-Locked Licenses',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  Generate keys (first time):
    python generate_license.py --generate-keys

  Generate hardware-locked Professional license:
    python generate_license.py \\
      --customer "Acme Corp" \\
      --email "admin@acme.com" \\
      --edition professional \\
      --installation-id "SK-INST-ABCD1234EFGH5678..." \\
      --expires 2027-01-15

  Generate perpetual license (no expiration):
    python generate_license.py \\
      --customer "Acme Corp" \\
      --email "admin@acme.com" \\
      --edition professional \\
      --installation-id "SK-INST-ABCD1234EFGH5678..."
        """
    )

    parser.add_argument('--generate-keys', action='store_true',
                        help='Generate RSA key pair for signing')
    parser.add_argument('--customer', type=str,
                        help='Customer/Company name')
    parser.add_argument('--email', type=str,
                        help='Customer email')
    parser.add_argument('--edition', type=str, choices=['community', 'professional'],
                        help='License edition')
    parser.add_argument('--installation-id', type=str,
                        help='Installation ID from customer (required for hardware lock)')
    parser.add_argument('--expires', type=str,
                        help='Expiration date (YYYY-MM-DD), omit for perpetual')
    parser.add_argument('--max-users', type=int,
                        help='Custom max users limit')
    parser.add_argument('--max-organizations', type=int,
                        help='Custom max organizations limit')
    parser.add_argument('--max-products', type=int,
                        help='Custom max products limit')
    parser.add_argument('--output', type=str,
                        help='Output file for license key')

    args = parser.parse_args()

    # Generate keys mode
    if args.generate_keys:
        generate_keys()
        return

    # Validate required args for license generation
    if not all([args.customer, args.email, args.edition, args.installation_id]):
        parser.print_help()
        print("\n" + "=" * 70)
        print("ERROR: Missing required arguments")
        print("=" * 70)
        print("\nRequired: --customer, --email, --edition, --installation-id")
        print("\nThe --installation-id is the customer's unique Installation ID")
        print("which they can find in Admin Panel > License tab.")
        print("\nExample Installation ID: SK-INST-A1B2C3D4E5F6G7H8...")
        sys.exit(1)

    # Validate installation ID format
    if not args.installation_id.startswith('SK-INST-'):
        print("Warning: Installation ID should start with 'SK-INST-'")
        print(f"         Got: {args.installation_id[:20]}...")
        response = input("Continue anyway? (yes/no): ")
        if response.lower() != 'yes':
            print("Cancelled.")
            sys.exit(1)

    # Validate expiration date format
    expires_at = None
    if args.expires:
        try:
            datetime.strptime(args.expires, '%Y-%m-%d')
            expires_at = args.expires
        except ValueError:
            print("Error: Invalid date format. Use YYYY-MM-DD")
            sys.exit(1)

    # Generate license
    print(f"\nGenerating {args.edition.upper()} license for {args.customer}...")
    print(f"Locked to installation: {args.installation_id[:24]}...")

    license_id, payload, license_key = create_license(
        customer=args.customer,
        email=args.email,
        edition=args.edition,
        installation_id=args.installation_id,
        expires_at=expires_at,
        max_users=args.max_users,
        max_organizations=args.max_organizations,
        max_products=args.max_products
    )

    # Output
    print("\n" + "=" * 70)
    print("LICENSE GENERATED SUCCESSFULLY")
    print("=" * 70)
    print(f"\nLicense ID:     {license_id}")
    print(f"Customer:       {args.customer}")
    print(f"Email:          {args.email}")
    print(f"Edition:        {args.edition.upper()}")
    print(f"Issued:         {date.today().isoformat()}")
    print(f"Expires:        {expires_at or 'Never (Perpetual)'}")
    print(f"Installation:   {args.installation_id[:32]}...")

    if args.edition == 'professional':
        print(f"Max Users:      {'Unlimited' if payload['limits']['max_users'] == -1 else payload['limits']['max_users']}")
        print(f"Max Orgs:       {'Unlimited' if payload['limits']['max_organizations'] == -1 else payload['limits']['max_organizations']}")
        print(f"Max Products:   {'Unlimited' if payload['limits']['max_products'] == -1 else payload['limits']['max_products']}")

    print("\n" + "-" * 70)
    print("LICENSE KEY (send this to customer):")
    print("-" * 70)
    print(f"\n{license_key}\n")
    print("-" * 70)

    # Save to file if requested
    if args.output:
        output_path = Path(args.output)
        output_data = {
            'license_id': license_id,
            'customer': args.customer,
            'email': args.email,
            'edition': args.edition,
            'installation_id': args.installation_id,
            'issued_at': date.today().isoformat(),
            'expires_at': expires_at,
            'license_key': license_key
        }
        output_path.write_text(json.dumps(output_data, indent=2))
        print(f"\nLicense saved to: {output_path}")

    print("\nINSTRUCTIONS FOR CUSTOMER:")
    print("1. Log into SentriKat as Super Admin")
    print("2. Go to Admin Panel > License")
    print("3. Paste the license key and click Activate")
    print("\nNOTE: This license will ONLY work on the installation with ID:")
    print(f"      {args.installation_id}")


if __name__ == '__main__':
    main()
