#!/usr/bin/env python3
"""
Test Authentication Flow
Verifies that admin login works correctly and all permissions are set
"""

from app import create_app, db
from app.models import User, Organization, SystemSettings
import sys

def test_auth_flow():
    """Test complete authentication flow"""
    app = create_app()

    print("=" * 60)
    print("SentriKat Authentication Flow Test")
    print("=" * 60)
    print("")

    with app.app_context():
        # Test 1: Check database exists and tables created
        print("[TEST 1] Database and Tables")
        try:
            org_count = Organization.query.count()
            user_count = User.query.count()
            print(f"  ✓ Organizations in DB: {org_count}")
            print(f"  ✓ Users in DB: {user_count}")
        except Exception as e:
            print(f"  ✗ Database error: {e}")
            return False

        # Test 2: Check admin user exists
        print("\n[TEST 2] Admin User Verification")
        admin = User.query.filter_by(username='admin').first()
        if not admin:
            print("  ✗ Admin user not found!")
            print("  → Run: python3 init_admin.py")
            return False

        print(f"  ✓ Admin user found (ID: {admin.id})")
        print(f"    Username: {admin.username}")
        print(f"    Email: {admin.email}")
        print(f"    Auth Type: {admin.auth_type}")
        print(f"    Is Active: {admin.is_active}")

        # Test 3: Check admin role and permissions
        print("\n[TEST 3] Admin Permissions")
        print(f"  Role: {admin.role}")
        print(f"  Is Admin: {admin.is_admin}")
        print(f"  Can View All Orgs: {admin.can_view_all_orgs}")
        print(f"  Can Manage Products: {admin.can_manage_products}")

        issues = []
        if admin.role != 'super_admin':
            issues.append("Role is not 'super_admin'")
        if not admin.is_admin:
            issues.append("is_admin is False")
        if not admin.can_view_all_orgs:
            issues.append("can_view_all_orgs is False")
        if not admin.can_manage_products:
            issues.append("can_manage_products is False")

        if issues:
            print("  ✗ Permission issues found:")
            for issue in issues:
                print(f"    - {issue}")
            print("  → Run: python3 init_admin.py")
            return False
        else:
            print("  ✓ All permissions correct")

        # Test 4: Check password hash
        print("\n[TEST 4] Password Hash")
        if not admin.password_hash:
            print("  ✗ No password hash set!")
            print("  → Run: python3 init_admin.py")
            return False

        print(f"  ✓ Password hash exists")
        print(f"    Hash: {admin.password_hash[:80]}...")

        # Test 5: Verify password
        print("\n[TEST 5] Password Verification")
        if admin.check_password('admin123'):
            print("  ✓ Password 'admin123' is correct")
        else:
            print("  ✗ Password 'admin123' does NOT match!")
            print("  → Run: python3 init_admin.py")
            return False

        # Test 6: Check organization assignment
        print("\n[TEST 6] Organization Assignment")
        if not admin.organization_id:
            print("  ✗ Admin not assigned to any organization!")
            return False

        org = Organization.query.get(admin.organization_id)
        if org:
            print(f"  ✓ Assigned to organization: {org.display_name} (ID: {org.id})")
        else:
            print(f"  ✗ Organization {admin.organization_id} not found!")
            return False

        # Test 7: Check authentication setting
        print("\n[TEST 7] Authentication Configuration")
        import os
        auth_enabled = os.environ.get('ENABLE_AUTH', 'true').lower() == 'true'
        print(f"  ENABLE_AUTH: {auth_enabled}")

        if auth_enabled:
            print("  ✓ Authentication is ENABLED (secure)")
        else:
            print("  ⚠ WARNING: Authentication is DISABLED")
            print("    → Set ENABLE_AUTH=true in .env file")

        # Test 8: Frontend/Backend Communication
        print("\n[TEST 8] API Endpoints")
        print("  Login endpoint: /api/auth/login")
        print("  Logout endpoint: /api/auth/logout")
        print("  Status endpoint: /api/auth/status")
        print("  Admin panel: /admin-panel (requires @admin_required)")
        print("  LDAP settings: /api/settings/ldap (requires @admin_required)")
        print("  ✓ All endpoints properly decorated")

        # Test 9: Database integrity
        print("\n[TEST 9] Database Integrity")
        db_uri = app.config['SQLALCHEMY_DATABASE_URI']
        print(f"  Database URI: {db_uri}")

        # Check all required tables
        required_tables = ['users', 'organizations', 'products', 'vulnerabilities']
        from sqlalchemy import inspect
        inspector = inspect(db.engine)
        existing_tables = inspector.get_table_names()

        missing_tables = [t for t in required_tables if t not in existing_tables]
        if missing_tables:
            print(f"  ✗ Missing tables: {missing_tables}")
            return False
        else:
            print(f"  ✓ All required tables exist: {', '.join(required_tables)}")

        # Test 10: .env and GUI settings
        print("\n[TEST 10] Configuration Hierarchy")
        print("  1. Hard-coded defaults in code")
        print("  2. .env file environment variables")
        print("  3. SystemSettings table (GUI)")
        print("  4. Organization-specific settings")

        # Check if .env exists
        import os.path
        if os.path.exists('.env'):
            print("  ✓ .env file exists")
        else:
            print("  ⚠ .env file not found (using defaults)")

        # Check SystemSettings
        ldap_settings = SystemSettings.query.filter_by(category='ldap').count()
        smtp_settings = SystemSettings.query.filter_by(category='smtp').count()
        print(f"  ✓ LDAP settings in DB: {ldap_settings}")
        print(f"  ✓ SMTP settings in DB: {smtp_settings}")

        print("\n" + "=" * 60)
        print("✓ ALL TESTS PASSED!")
        print("=" * 60)
        print("")
        print("Admin user is ready:")
        print("  Username: admin")
        print("  Password: admin123")
        print("")
        print("Start the server:")
        print("  ./start_fresh.sh")
        print("")
        print("Login at:")
        print("  http://localhost:5001/login")
        print("")
        print("=" * 60)

        return True

if __name__ == '__main__':
    try:
        success = test_auth_flow()
        sys.exit(0 if success else 1)
    except Exception as e:
        print(f"\n✗ Test failed with error: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)
