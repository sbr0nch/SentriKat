#!/usr/bin/env python
"""
Comprehensive System Audit for SentriKat
Checks GUI ↔ Backend conformity, database state, LDAP configuration
"""

from app import create_app, db
from app.models import User, Organization, SystemSettings
from app.auth import AUTH_ENABLED
import os
import sqlite3
from pathlib import Path

app = create_app()

print("="*80)
print("SENTRIKAT SYSTEM AUDIT")
print("="*80)

# 1. AUTHENTICATION STATUS
print("\n" + "="*80)
print("1. AUTHENTICATION STATUS")
print("="*80)
print(f"AUTH_ENABLED: {AUTH_ENABLED}")
print(f"DISABLE_AUTH env var: {os.environ.get('DISABLE_AUTH', 'not set')}")
print(f"ENABLE_AUTH env var: {os.environ.get('ENABLE_AUTH', 'not set')}")

if not AUTH_ENABLED:
    print("⚠️  WARNING: Authentication is DISABLED - GUI accessible without login!")
else:
    print("✓ Authentication is ENABLED - Login required")

# 2. DATABASE CONFIGURATION
print("\n" + "="*80)
print("2. DATABASE CONFIGURATION")
print("="*80)
print(f"Configured URI: {app.config['SQLALCHEMY_DATABASE_URI']}")

# Find all database files
db_files = list(Path('/opt/sentrikat').rglob('*.db'))
print(f"\nFound {len(db_files)} database files:")
for db_file in db_files:
    size_mb = db_file.stat().st_size / 1024 / 1024
    print(f"  - {db_file} ({size_mb:.2f} MB)")

# Check which database is actually being used
with app.app_context():
    try:
        user_count = User.query.count()
        print(f"\n✓ Active database has {user_count} users")
    except Exception as e:
        print(f"\n✗ ERROR accessing database: {e}")

# 3. USER ACCOUNTS
print("\n" + "="*80)
print("3. USER ACCOUNTS")
print("="*80)

with app.app_context():
    users = User.query.all()
    print(f"Total users: {len(users)}\n")

    for user in users:
        status = "ACTIVE" if user.is_active else "INACTIVE"
        admin_flag = "ADMIN" if user.is_admin else ""
        print(f"  [{status}] {user.username}")
        print(f"      ID: {user.id}")
        print(f"      Email: {user.email or 'not set'}")
        print(f"      Auth Type: {user.auth_type}")
        print(f"      Role: {user.role or 'not set'} {admin_flag}")
        print(f"      Has Password: {bool(user.password_hash)}")

        # Test admin password
        if user.username == 'admin' and user.auth_type == 'local':
            try:
                pwd_check = user.check_password('admin123')
                if pwd_check:
                    print(f"      ✓ Password 'admin123' works")
                else:
                    print(f"      ✗ Password 'admin123' DOES NOT WORK")
            except Exception as e:
                print(f"      ✗ Error checking password: {e}")
        print()

# 4. LDAP CONFIGURATION
print("\n" + "="*80)
print("4. LDAP CONFIGURATION (SystemSettings)")
print("="*80)

with app.app_context():
    ldap_keys = [
        'ldap_enabled', 'ldap_server', 'ldap_port', 'ldap_base_dn',
        'ldap_bind_dn', 'ldap_bind_password', 'ldap_search_filter',
        'ldap_username_attr', 'ldap_email_attr', 'ldap_use_tls'
    ]

    ldap_config = {}
    for key in ldap_keys:
        setting = SystemSettings.query.filter_by(key=key).first()
        if setting:
            value = '***' if 'password' in key else setting.value
            ldap_config[key] = setting.value
            print(f"✓ {key}: {value}")
        else:
            print(f"✗ {key}: NOT SET")
            ldap_config[key] = None

    # Check if LDAP is configured
    if ldap_config.get('ldap_enabled') == 'true':
        if ldap_config.get('ldap_server') and ldap_config.get('ldap_base_dn'):
            print("\n✓ LDAP is CONFIGURED and ENABLED")
        else:
            print("\n⚠️  LDAP enabled but server/base_dn missing")
    else:
        print("\n✗ LDAP is NOT enabled")

# 5. LDAP AUTHENTICATION FLOW
print("\n" + "="*80)
print("5. LDAP AUTHENTICATION CODE CHECK")
print("="*80)

try:
    from app.ldap_manager import LDAPManager

    # Check if get_ldap_config works
    config = LDAPManager.get_ldap_config()
    print(f"LDAPManager.get_ldap_config():")
    print(f"  enabled: {config.get('enabled')}")
    print(f"  server: {config.get('server')}")
    print(f"  base_dn: {config.get('base_dn')}")
    print(f"  port: {config.get('port')}")

    # Check if search_groups exists
    if hasattr(LDAPManager, 'search_groups'):
        print(f"\n✓ LDAPManager.search_groups() method EXISTS")
    else:
        print(f"\n✗ LDAPManager.search_groups() method MISSING")

except Exception as e:
    print(f"✗ ERROR importing LDAP modules: {e}")

# 6. GUI ↔ BACKEND DATA FLOW
print("\n" + "="*80)
print("6. GUI ↔ BACKEND DATA FLOW TEST")
print("="*80)

with app.app_context():
    # Test writing a setting
    test_key = 'audit_test_setting'
    test_setting = SystemSettings.query.filter_by(key=test_key).first()

    if not test_setting:
        test_setting = SystemSettings(
            key=test_key,
            value='test_value_12345',
            category='test',
            description='Audit test'
        )
        db.session.add(test_setting)
        db.session.commit()
        print("✓ Write test: Created test setting")
    else:
        print("✓ Write test: Test setting already exists")

    # Test reading it back
    verify = SystemSettings.query.filter_by(key=test_key).first()
    if verify and verify.value == 'test_value_12345':
        print("✓ Read test: Successfully read back test setting")
    else:
        print("✗ Read test: FAILED to read back setting")

    # Clean up
    if verify:
        db.session.delete(verify)
        db.session.commit()
        print("✓ Cleanup: Removed test setting")

# 7. CRITICAL ISSUES SUMMARY
print("\n" + "="*80)
print("7. CRITICAL ISSUES SUMMARY")
print("="*80)

issues = []

if not AUTH_ENABLED:
    issues.append("⚠️  CRITICAL: Authentication is disabled - anyone can access GUI")

with app.app_context():
    admin = User.query.filter_by(username='admin').first()
    if not admin:
        issues.append("✗ CRITICAL: No admin user found")
    elif not admin.is_active:
        issues.append("⚠️  WARNING: Admin user is inactive")

    ldap_enabled = SystemSettings.query.filter_by(key='ldap_enabled').first()
    if ldap_enabled and ldap_enabled.value == 'true':
        ldap_server = SystemSettings.query.filter_by(key='ldap_server').first()
        if not ldap_server or not ldap_server.value:
            issues.append("✗ LDAP: Enabled but server not configured")

if len(db_files) > 1:
    issues.append(f"⚠️  WARNING: Multiple database files found ({len(db_files)})")

if issues:
    for issue in issues:
        print(issue)
else:
    print("✓ No critical issues found!")

# 8. RECOMMENDATIONS
print("\n" + "="*80)
print("8. RECOMMENDATIONS")
print("="*80)

print("1. Restart server to apply AUTH_ENABLED fix")
print("2. Login with: admin / admin123")
print("3. Test LDAP group discovery with:")
print("   - Base DN: DC=bonelabs,DC=com")
print("   - Filter: (objectClass=group)")
print("4. Remove extra database files if found")

print("\n" + "="*80)
print("AUDIT COMPLETE")
print("="*80)
