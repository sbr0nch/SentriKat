#!/usr/bin/env python3
"""
Setup Single Database - Ensures ONE database with all data
This script:
1. Reads DATABASE_URL from .env
2. Creates the database at that location
3. Initializes all tables
4. Creates admin user
5. Creates default organization
"""

import os
import sys
from pathlib import Path

# Load .env file
from dotenv import load_dotenv
load_dotenv()

# Get DATABASE_URL from environment
DATABASE_URL = os.environ.get('DATABASE_URL', 'sqlite:///sentrikat.db')

print("=" * 70)
print("SINGLE DATABASE SETUP")
print("=" * 70)
print(f"\n📍 Database URL from .env: {DATABASE_URL}\n")

# Parse the database path
if DATABASE_URL.startswith('sqlite:///'):
    db_path = DATABASE_URL.replace('sqlite:///', '')

    # Handle absolute vs relative paths
    if db_path.startswith('/'):
        # Absolute path (e.g., sqlite:////opt/sentrikat/data/sentrikat.db)
        db_file = db_path
    else:
        # Relative path (e.g., sqlite:///sentrikat.db)
        db_file = os.path.join(os.getcwd(), db_path)

    print(f"📂 Database file will be: {db_file}")

    # Create directory if needed
    db_dir = os.path.dirname(db_file)
    if db_dir and not os.path.exists(db_dir):
        print(f"📁 Creating directory: {db_dir}")
        os.makedirs(db_dir, exist_ok=True)

    # Check if database already exists
    if os.path.exists(db_file):
        print(f"✓ Database file already exists")
        import sqlite3
        conn = sqlite3.connect(db_file)
        cursor = conn.cursor()
        cursor.execute("SELECT COUNT(*) FROM sqlite_master WHERE type='table'")
        table_count = cursor.fetchone()[0]
        print(f"✓ Existing tables: {table_count}")

        # Check for existing data
        try:
            cursor.execute("SELECT COUNT(*) FROM users")
            user_count = cursor.fetchone()[0]
            print(f"✓ Existing users: {user_count}")
        except:
            user_count = 0
            print(f"✓ Existing users: 0 (users table doesn't exist yet)")

        try:
            cursor.execute("SELECT COUNT(*) FROM organizations")
            org_count = cursor.fetchone()[0]
            print(f"✓ Existing organizations: {org_count}")
        except:
            org_count = 0
            print(f"✓ Existing organizations: 0 (organizations table doesn't exist yet)")

        try:
            cursor.execute("SELECT COUNT(*) FROM products")
            prod_count = cursor.fetchone()[0]
            print(f"✓ Existing products: {prod_count}")
        except:
            prod_count = 0
            print(f"✓ Existing products: 0 (products table doesn't exist yet)")

        try:
            cursor.execute("SELECT COUNT(*) FROM vulnerabilities")
            vuln_count = cursor.fetchone()[0]
            print(f"✓ Existing vulnerabilities: {vuln_count}")
        except:
            vuln_count = 0
            print(f"✓ Existing vulnerabilities: 0 (vulnerabilities table doesn't exist yet)")

        conn.close()
    else:
        print(f"📝 Database will be created at: {db_file}")

else:
    print(f"⚠️  Not a SQLite database: {DATABASE_URL}")
    db_file = None

print("\n" + "=" * 70)
print("INITIALIZING DATABASE")
print("=" * 70 + "\n")

# Import Flask app
from app import create_app, db
from app.models import User, Organization

app = create_app()

with app.app_context():
    # Verify we're using the correct database
    actual_db_uri = app.config['SQLALCHEMY_DATABASE_URI']
    print(f"✓ Flask is using: {actual_db_uri}")

    if DATABASE_URL != actual_db_uri:
        print(f"⚠️  WARNING: .env says {DATABASE_URL} but Flask is using {actual_db_uri}")

    # Create all tables
    print("\n📊 Creating/updating database tables...")
    db.create_all()
    print("✓ All tables created/verified")

    # Create or update default organization
    print("\n🏢 Setting up default organization...")
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

    # Create or update admin user
    print("\n👤 Setting up admin user...")
    admin = User.query.filter_by(username='admin').first()

    if admin:
        print(f"✓ Found existing admin user (ID: {admin.id})")
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
        print(f"✓ UPDATED admin user")
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

    # Display admin details
    print("\n" + "=" * 70)
    print("ADMIN USER DETAILS")
    print("=" * 70)
    print(f"  Username: {admin.username}")
    print(f"  Password: admin123")
    print(f"  Email: {admin.email}")
    print(f"  Role: {admin.role}")
    print(f"  Is Admin: {admin.is_admin}")
    print(f"  Can View All Orgs: {admin.can_view_all_orgs}")
    print(f"  Can Manage Products: {admin.can_manage_products}")
    print(f"  Auth Type: {admin.auth_type}")
    print(f"  Organization ID: {admin.organization_id}")
    print(f"  Organization: {default_org.display_name}")

    # Summary
    user_count = User.query.count()
    org_count = Organization.query.count()

    print("\n" + "=" * 70)
    print("DATABASE SUMMARY")
    print("=" * 70)
    print(f"  Database location: {db_file}")
    print(f"  Total users: {user_count}")
    print(f"  Total organizations: {org_count}")

    print("\n" + "=" * 70)
    print("✓ SETUP COMPLETE!")
    print("=" * 70)
    print("\nYou can now:")
    print("  1. Start the server: ./start_fresh.sh")
    print("  2. Login at: http://localhost:5001/login")
    print("  3. Use credentials: admin / admin123")
    print("\n" + "=" * 70 + "\n")
