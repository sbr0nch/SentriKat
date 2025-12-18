#!/usr/bin/env python3
"""
Initialize SentriKat with admin user
Creates or updates the admin user with proper credentials and permissions
"""

from app import create_app, db
from app.models import User, Organization
import sys

def init_admin():
    """Create or update admin user with admin123 password"""
    app = create_app()

    with app.app_context():
        # Ensure tables exist
        db.create_all()

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

        # Check if admin user exists
        admin = User.query.filter_by(username='admin').first()

        if admin:
            # Update existing admin user
            print(f"✓ Found existing admin user (ID: {admin.id})")
            print(f"  Current role: {admin.role}")
            print(f"  Current is_admin: {admin.is_admin}")
            print(f"  Current auth_type: {admin.auth_type}")

            # Update to ensure proper permissions
            admin.email = 'admin@localhost'
            admin.full_name = 'System Administrator'
            admin.auth_type = 'local'
            admin.role = 'super_admin'
            admin.is_admin = True
            admin.is_active = True
            admin.can_manage_products = True
            admin.can_view_all_orgs = True
            admin.organization_id = default_org.id

            # Reset password to admin123
            admin.set_password('admin123')

            db.session.commit()

            print(f"\n✓ UPDATED admin user:")
            print(f"  Username: {admin.username}")
            print(f"  Password: admin123")
            print(f"  Email: {admin.email}")
            print(f"  Role: {admin.role}")
            print(f"  Is Admin: {admin.is_admin}")
            print(f"  Can View All Orgs: {admin.can_view_all_orgs}")
            print(f"  Auth Type: {admin.auth_type}")
            print(f"  Organization ID: {admin.organization_id}")

        else:
            # Create new admin user
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

            # Set password
            admin.set_password('admin123')

            db.session.add(admin)
            db.session.commit()

            print(f"\n✓ CREATED admin user:")
            print(f"  Username: {admin.username}")
            print(f"  Password: admin123")
            print(f"  Email: {admin.email}")
            print(f"  Role: {admin.role}")
            print(f"  Is Admin: {admin.is_admin}")
            print(f"  Can View All Orgs: {admin.can_view_all_orgs}")
            print(f"  Auth Type: {admin.auth_type}")
            print(f"  Organization ID: {admin.organization_id}")

        # Verify password hash
        if admin.check_password('admin123'):
            print(f"\n✓ Password verification: SUCCESS")
        else:
            print(f"\n✗ Password verification: FAILED")
            return False

        # Count total users
        user_count = User.query.count()
        print(f"\n✓ Total users in database: {user_count}")

        # Show database location
        db_uri = app.config['SQLALCHEMY_DATABASE_URI']
        print(f"✓ Database location: {db_uri}")

        return True

if __name__ == '__main__':
    print("SentriKat Admin Initialization")
    print("=" * 50)
    print("")

    try:
        success = init_admin()
        if success:
            print("\n" + "=" * 50)
            print("✓ Admin user ready!")
            print("  Login at: http://localhost:5001/login")
            print("  Username: admin")
            print("  Password: admin123")
            print("=" * 50)
            sys.exit(0)
        else:
            print("\n✗ Admin initialization failed")
            sys.exit(1)
    except Exception as e:
        print(f"\n✗ Error: {str(e)}")
        import traceback
        traceback.print_exc()
        sys.exit(1)
