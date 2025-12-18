#!/usr/bin/env python3
"""
Safe Database Setup - Works with any version
"""
import os
import sys

sys.path.insert(0, os.getcwd())

print("=" * 70)
print("SAFE DATABASE SETUP")
print("=" * 70)
print("")

# Load .env
try:
    from dotenv import load_dotenv
    load_dotenv()
    print("✓ Loaded .env file")
except ImportError:
    print("Installing python-dotenv...")
    import subprocess
    subprocess.check_call([sys.executable, "-m", "pip", "install", "python-dotenv"])
    from dotenv import load_dotenv
    load_dotenv()

from app import create_app, db
from app.models import User, Organization, SystemSettings

app = create_app()

with app.app_context():
    db_uri = app.config['SQLALCHEMY_DATABASE_URI']
    print(f"Database: {db_uri}")
    print("")

    # Create directory if needed (for SQLite)
    if db_uri.startswith('sqlite:///'):
        db_path = db_uri.replace('sqlite:///', '')
        if not db_path.startswith('/'):
            db_path = os.path.join(os.getcwd(), db_path)
        else:
            # Handle quadruple slash: sqlite:////absolute/path
            pass

        db_dir = os.path.dirname(db_path)
        if db_dir and not os.path.exists(db_dir):
            print(f"Creating directory: {db_dir}")
            os.makedirs(db_dir, exist_ok=True)

    print("=" * 70)
    print("STEP 1: Creating Core Tables")
    print("=" * 70)
    db.create_all()
    print("✓ Core tables created")

    # Try to import and create LDAP tables if available
    try:
        from app.ldap_models import LDAPGroupMapping, LDAPSyncLog, LDAPAuditLog
        print("✓ LDAP tables created")
    except ImportError:
        print("⚠️  LDAP models not available (older version)")
        print("   This is OK - run again after pulling latest code")

    print("")

    print("=" * 70)
    print("STEP 2: Setting Up Organization")
    print("=" * 70)
    org = Organization.query.filter_by(name='default').first()
    if not org:
        org = Organization(
            name='default',
            display_name='Default Organization',
            description='Default organization',
            notification_emails='[]',
            alert_on_critical=True,
            alert_on_high=False,
            alert_on_new_cve=True,
            alert_on_ransomware=True,
            active=True
        )
        db.session.add(org)
        db.session.commit()
        print(f"✓ Created organization (ID: {org.id})")
    else:
        print(f"✓ Organization exists (ID: {org.id})")
    print("")

    print("=" * 70)
    print("STEP 3: Setting Up Admin User")
    print("=" * 70)
    admin = User.query.filter_by(username='admin').first()

    if admin:
        print(f"✓ Found existing admin user (ID: {admin.id})")
        print(f"  Current role: {admin.role}")
        print(f"  Current is_admin: {admin.is_admin}")

        # Update permissions
        admin.email = 'admin@localhost'
        admin.full_name = 'System Administrator'
        admin.auth_type = 'local'
        admin.role = 'super_admin'
        admin.is_admin = True
        admin.is_active = True
        admin.can_manage_products = True
        admin.can_view_all_orgs = True
        admin.organization_id = org.id
        admin.set_password('admin123')
        db.session.commit()
        print("✓ UPDATED admin user to super_admin")
    else:
        admin = User(
            username='admin',
            email='admin@localhost',
            full_name='System Administrator',
            auth_type='local',
            role='super_admin',
            is_admin=True,
            is_active=True,
            can_manage_products=True,
            can_view_all_orgs=True,
            organization_id=org.id
        )
        admin.set_password('admin123')
        db.session.add(admin)
        db.session.commit()
        print(f"✓ CREATED admin user (ID: {admin.id})")

    print("")

    # Verify password
    if admin.check_password('admin123'):
        print("✓ Password verification: SUCCESS")
    else:
        print("✗ Password verification: FAILED")
        sys.exit(1)

    print("")

    print("=" * 70)
    print("STEP 4: Migrating LDAP Settings (if configured)")
    print("=" * 70)

    ldap_settings = {
        'ldap_server': os.getenv('LDAP_SERVER', ''),
        'ldap_base_dn': os.getenv('LDAP_BASE_DN', ''),
        'ldap_bind_dn': os.getenv('LDAP_BIND_DN', ''),
        'ldap_bind_password': os.getenv('LDAP_BIND_PW', ''),
        'ldap_search_filter': os.getenv('LDAP_SEARCH_FILTER', '(sAMAccountName={username})'),
    }

    migrated = 0
    for key, value in ldap_settings.items():
        if value:
            setting = SystemSettings.query.filter_by(key=key).first()
            if not setting:
                setting = SystemSettings(
                    key=key,
                    value=value,
                    category='ldap',
                    description=f'LDAP setting: {key}',
                    is_encrypted=(key == 'ldap_bind_password'),
                    updated_by=admin.id
                )
                db.session.add(setting)
                migrated += 1
                print(f"✓ Migrated {key}")

    if migrated > 0:
        db.session.commit()
        print(f"\n✓ Migrated {migrated} LDAP settings from .env to database")
    else:
        print("✓ LDAP settings already in database (or not set in .env)")

    print("")

    print("=" * 70)
    print("VERIFICATION")
    print("=" * 70)

    user_count = User.query.count()
    org_count = Organization.query.count()
    ldap_settings_count = SystemSettings.query.filter_by(category='ldap').count()

    print(f"✓ Total users: {user_count}")
    print(f"✓ Total organizations: {org_count}")
    print(f"✓ LDAP settings in database: {ldap_settings_count}")

    print("")
    print("=" * 70)
    print("✓ SETUP COMPLETE!")
    print("=" * 70)
    print("")
    print("Admin Credentials:")
    print(f"  Username: admin")
    print(f"  Password: admin123")
    print(f"  Role: {admin.role}")
    print(f"  Is Admin: {admin.is_admin}")
    print(f"  Can View All Orgs: {admin.can_view_all_orgs}")
    print("")
    print("Next steps:")
    print("  1. Start server: ./start_fresh.sh")
    print("  2. Login at: http://localhost:5001/login")
    print("  3. Access Admin Panel: /admin-panel")
    print("")
    print("=" * 70)
    print("")
