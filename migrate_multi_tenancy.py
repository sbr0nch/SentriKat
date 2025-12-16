#!/usr/bin/env python3
"""
Migration script for multi-tenancy, service catalog, and authentication features
Adds: Organizations, ServiceCatalog, Users, AlertLogs tables
Updates: Products table with organization_id and service_catalog_id
"""

import sys
import os

# Add the app directory to the path
sys.path.insert(0, os.path.abspath(os.path.dirname(__file__)))

from app import create_app, db
from app.models import Organization, Product, ServiceCatalog, User, AlertLog
import json

def run_migration():
    """Run the migration"""
    app = create_app()

    with app.app_context():
        print("Starting multi-tenancy migration...")

        try:
            # Create all new tables
            print("\n1. Creating new tables...")
            db.create_all()
            print("   ✓ Tables created (organizations, service_catalog, users, alert_logs)")

            # Check if default organization exists
            default_org = Organization.query.filter_by(name='default').first()

            if not default_org:
                print("\n2. Creating default organization...")
                default_org = Organization(
                    name='default',
                    display_name='Default Organization',
                    description='Default organization for existing products',
                    notification_emails=json.dumps(['admin@example.com']),
                    alert_on_critical=True,
                    alert_on_high=False,
                    alert_on_new_cve=True,
                    alert_on_ransomware=True,
                    active=True
                )
                db.session.add(default_org)
                db.session.commit()
                print(f"   ✓ Default organization created (ID: {default_org.id})")
            else:
                print(f"\n2. Default organization already exists (ID: {default_org.id})")

            # Assign all existing products to default organization
            print("\n3. Assigning existing products to default organization...")
            products_without_org = Product.query.filter(
                (Product.organization_id == None) | (Product.organization_id == 0)
            ).all()

            if products_without_org:
                for product in products_without_org:
                    product.organization_id = default_org.id
                db.session.commit()
                print(f"   ✓ Assigned {len(products_without_org)} products to default organization")
            else:
                print("   ✓ All products already have organization assignment")

            # Create default admin user
            print("\n4. Checking for admin user...")
            admin_user = User.query.filter_by(username='admin').first()

            if not admin_user:
                print("   Creating default admin user...")
                admin_user = User(
                    username='admin',
                    email='admin@sentrikat.local',
                    auth_type='local',
                    is_admin=True,
                    is_active=True,
                    can_manage_products=True,
                    can_view_all_orgs=True,
                    organization_id=default_org.id
                )
                admin_user.set_password('admin')  # Default password - CHANGE THIS!
                db.session.add(admin_user)
                db.session.commit()
                print(f"   ✓ Admin user created (username: admin, password: admin)")
                print("   ⚠️  IMPORTANT: Change the default admin password immediately!")
            else:
                print(f"   ✓ Admin user already exists (ID: {admin_user.id})")

            print("\n5. Migration completed successfully!")
            print("\nSummary:")
            print(f"  - Organizations: {Organization.query.count()}")
            print(f"  - Products: {Product.query.count()}")
            print(f"  - Service Catalog Entries: {ServiceCatalog.query.count()}")
            print(f"  - Users: {User.query.count()}")
            print(f"  - Alert Logs: {AlertLog.query.count()}")

            print("\n📝 Next Steps:")
            print("  1. Run seed_service_catalog.py to populate the service catalog")
            print("  2. Configure SMTP settings for email alerts")
            print("  3. Change the default admin password")
            print("  4. Create additional organizations and users as needed")

        except Exception as e:
            print(f"\n❌ Migration failed: {str(e)}")
            import traceback
            traceback.print_exc()
            db.session.rollback()
            return 1

    return 0

if __name__ == '__main__':
    sys.exit(run_migration())
