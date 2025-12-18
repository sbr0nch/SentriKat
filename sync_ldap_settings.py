#!/usr/bin/env python
"""Sync LDAP settings between database and display current configuration"""
from app import create_app, db
from app.models import SystemSettings
import os

app = create_app()

def get_db_setting(key, default=None):
    """Get setting from database"""
    setting = SystemSettings.query.filter_by(key=key).first()
    return setting.value if setting else default

def get_env_setting(key, default=None):
    """Get setting from environment"""
    return os.environ.get(key, default)

with app.app_context():
    print("\n" + "="*60)
    print("LDAP CONFIGURATION COMPARISON")
    print("="*60)

    ldap_keys = [
        'ldap_enabled',
        'ldap_server',
        'ldap_port',
        'ldap_base_dn',
        'ldap_bind_dn',
        'ldap_bind_password',
        'ldap_search_filter',
        'ldap_username_attr',
        'ldap_email_attr',
        'ldap_use_tls'
    ]

    print(f"\n{'Setting':<25} {'Database':<30} {'Environment':<30}")
    print("-"*85)

    for key in ldap_keys:
        db_val = get_db_setting(key, '')
        env_key = key.upper()
        env_val = get_env_setting(env_key, '')

        # Mask passwords
        if 'password' in key.lower():
            db_val = '***' if db_val else ''
            env_val = '***' if env_val else ''

        # Show mismatch
        match = '✓' if (db_val and env_val and db_val == env_val) or (not db_val and not env_val) else '✗'

        print(f"{match} {key:<23} {str(db_val):<30} {str(env_val):<30}")

    print("\n" + "="*60)
    print("RECOMMENDATIONS:")
    print("="*60)

    db_count = sum(1 for k in ldap_keys if get_db_setting(k))
    env_count = sum(1 for k in ldap_keys if get_env_setting(k.upper()))

    if db_count > 0 and env_count == 0:
        print("\n✓ Settings are in DATABASE only (GUI configuration)")
        print("  This is the correct configuration.")
        print("  Authentication should use database settings.")
    elif env_count > 0 and db_count == 0:
        print("\n! Settings are in ENVIRONMENT only (.env file)")
        print("  GUI won't show these settings.")
        print("  Run this to import into database:")
        print("  python sync_ldap_settings.py --import")
    elif db_count > 0 and env_count > 0:
        print("\n⚠ Settings exist in BOTH database and environment!")
        print("  This causes conflicts.")
        print("  Recommend removing from .env file.")
    else:
        print("\n✗ No LDAP settings configured!")
        print("  Configure via GUI: Admin Panel → Settings → LDAP")

    print()
