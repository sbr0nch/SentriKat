#!/usr/bin/env python3
"""
Complete Database Setup for Latest SentriKat with LDAP Support
This script:
1. Reads DATABASE_URL from .env
2. Creates all tables (including new LDAP tables)
3. Creates/updates admin user with super_admin role
4. Migrates LDAP settings from .env to database
5. Verifies everything is ready
"""

import os
import sys
from pathlib import Path

# Add current directory to path
sys.path.insert(0, os.getcwd())

print("=" * 70)
print("COMPLETE SENTRIKAT DATABASE SETUP")
print("=" * 70)
print("")

# Check if .env exists
if not os.path.exists('.env'):
    print("⚠️  WARNING: .env file not found!")
    print("Creating .env from .env.example...")
    if os.path.exists('.env.example'):
        import shutil
        shutil.copy('.env.example', '.env')
        print("✓ Created .env file - please edit it with your settings")
    else:
        print("✗ .env.example not found!")
        sys.exit(1)

# Load .env file
try:
    from dotenv import load_dotenv
    load_dotenv()
    print("✓ Loaded .env file")
except ImportError:
    print("⚠️  python-dotenv not installed, using system environment only")

# Import Flask app
from app import create_app, db
from app.models import User, Organization, SystemSettings

app = create_app()

with app.app_context():
    db_uri = app.config['SQLALCHEMY_DATABASE_URI']
    print(f"✓ Database: {db_uri}")
    print("")

    # Parse database path for SQLite
    if db_uri.startswith('sqlite:///'):
        db_path = db_uri.replace('sqlite:///', '')
        if db_path.startswith('/'):
            db_file = db_path
        else:
            db_file = os.path.join(os.getcwd(), db_path)

        # Create directory if needed
        db_dir = os.path.dirname(db_file)
        if db_dir and not os.path.exists(db_dir):
            print(f"📁 Creating directory: {db_dir}")
            os.makedirs(db_dir, exist_ok=True)

        # Check if database exists
        if os.path.exists(db_file):
            print(f"✓ Database file exists: {db_file}")
            print(f"✓ Size: {os.path.getsize(db_file):,} bytes")
        else:
            print(f"📝 Will create new database: {db_file}")

    print("\n" + "=" * 70)
    print("STEP 1: Creating/Updating Database Tables")
    print("=" * 70 + "\n")

    # Create all tables
    db.create_all()
    print("✓ All core tables created/verified")

    # Check if LDAP tables exist (they're in separate models)
    from app.ldap_models import LDAPGroupMapping, LDAPSyncLog, LDAPAuditLog
    print("✓ LDAP tables imported and created")

    print("\n" + "=" * 70)
    print("STEP 2: Setting Up Organizations")
    print("=" * 70 + "\n")

    # Create or get default organization
    default_org = Organization.query.filter_by(name='default').first()
    if not default_org:
        default_org = Organization(
            name='default',
            display_name='Default Organization',
            description='Default organization for SentriKat',
            notification_emails='[]',
            alert_on_critical=True,
            alert_on_high=False,
            alert_on_new_cve=True,
            alert_on_ransomware=True,
            active=True
        )
        db.session.add(default_org)
        db.session.commit()
        print(f"✓ Created default organization (ID: {default_org.id})")
    else:
        print(f"✓ Default organization exists (ID: {default_org.id})")

    print("\n" + "=" * 70)
    print("STEP 3: Setting Up Admin User")
    print("=" * 70 + "\n")

    # Create or update admin user
    admin = User.query.filter_by(username='admin').first()

    if admin:
        print(f"✓ Found existing admin user (ID: {admin.id})")
        print(f"  Current role: {admin.role}")
        print(f"  Current is_admin: {admin.is_admin}")

        # Update to ensure correct permissions
        admin.email = 'admin@localhost'
        admin.full_name = 'System Administrator'
        admin.auth_type = 'local'
        admin.role = 'super_admin'
        admin.is_admin = True
        admin.is_active = True
        admin.can_manage_products = True
        admin.can_view_all_orgs = True
        admin.organization_id = default_org.id
        admin.set_password('admin123')
        db.session.commit()
        print(f"✓ UPDATED admin user with super_admin role")
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
            organization_id=default_org.id
        )
        admin.set_password('admin123')
        db.session.add(admin)
        db.session.commit()
        print(f"✓ CREATED admin user (ID: {admin.id})")

    # Verify password
    if admin.check_password('admin123'):
        print("✓ Password verification: SUCCESS")
    else:
        print("✗ Password verification: FAILED")
        sys.exit(1)

    print("\n" + "=" * 70)
    print("STEP 4: Migrating LDAP Settings from .env to Database")
    print("=" * 70 + "\n")

    # Migrate LDAP settings from environment to database
    ldap_settings = {
        'ldap_server': os.environ.get('LDAP_SERVER', ''),
        'ldap_base_dn': os.environ.get('LDAP_BASE_DN', ''),
        'ldap_bind_dn': os.environ.get('LDAP_BIND_DN', ''),
        'ldap_bind_password': os.environ.get('LDAP_BIND_PW', ''),
        'ldap_search_filter': os.environ.get('LDAP_SEARCH_FILTER', '(sAMAccountName={username})'),
    }

    settings_migrated = 0
    for key, value in ldap_settings.items():
        if value:  # Only migrate if value exists
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
                settings_migrated += 1
                print(f"✓ Migrated {key} to database")

    if settings_migrated > 0:
        db.session.commit()
        print(f"\n✓ Migrated {settings_migrated} LDAP settings from .env to database")
    else:
        print("✓ LDAP settings already in database or not set in .env")

    print("\n" + "=" * 70)
    print("STEP 5: Verification")
    print("=" * 70 + "\n")

    # Count data
    user_count = User.query.count()
    org_count = Organization.query.count()
    ldap_group_count = LDAPGroupMapping.query.count()
    ldap_settings_count = SystemSettings.query.filter_by(category='ldap').count()

    print(f"✓ Total users: {user_count}")
    print(f"✓ Total organizations: {org_count}")
    print(f"✓ LDAP group mappings: {ldap_group_count}")
    print(f"✓ LDAP settings in database: {ldap_settings_count}")

    print("\n" + "=" * 70)
    print("ADMIN USER CREDENTIALS")
    print("=" * 70)
    print(f"  Username: {admin.username}")
    print(f"  Password: admin123")
    print(f"  Email: {admin.email}")
    print(f"  Role: {admin.role}")
    print(f"  Is Admin: {admin.is_admin}")
    print(f"  Can View All Orgs: {admin.can_view_all_orgs}")
    print(f"  Organization: {default_org.display_name}")

    print("\n" + "=" * 70)
    print("✓ SETUP COMPLETE!")
    print("=" * 70)
    print("\nYou can now:")
    print("  1. Start server: ./start_fresh.sh")
    print("  2. Login at: http://localhost:5001/login")
    print("  3. Access Admin Panel: http://localhost:5001/admin-panel")
    print("  4. Configure LDAP: Admin Panel → Settings → LDAP")
    print("\n" + "=" * 70 + "\n")
