#!/usr/bin/env python3
"""
Create all test users for comprehensive testing

Creates 5 test accounts:
1. admin (super_admin) - Already exists
2. org_admin (org_admin)
3. manager (manager)
4. user (user)
5. ldap_user (ldap)
"""

import os
import sys

sys.path.insert(0, os.getcwd())

from app import create_app, db
from app.models import User, Organization

app = create_app()

with app.app_context():
    print("=" * 70)
    print("CREATING TEST USERS")
    print("=" * 70)
    print("")

    # Get default organization
    default_org = Organization.query.filter_by(name='default').first()
    if not default_org:
        print("✗ Error: Default organization not found")
        print("  Run setup_now.py first")
        sys.exit(1)

    # Create second organization for multi-org testing
    eng_org = Organization.query.filter_by(name='engineering').first()
    if not eng_org:
        eng_org = Organization(
            name='engineering',
            display_name='Engineering Team',
            description='Engineering department',
            notification_emails='[]',
            alert_on_critical=True,
            active=True
        )
        db.session.add(eng_org)
        db.session.commit()
        print(f"✓ Created engineering organization (ID: {eng_org.id})")
    else:
        print(f"✓ Engineering organization exists (ID: {eng_org.id})")

    print("")

    # Test users to create
    test_users = [
        {
            'username': 'admin',
            'email': 'admin@localhost',
            'full_name': 'Super Administrator',
            'role': 'super_admin',
            'is_admin': True,
            'can_view_all_orgs': True,
            'can_manage_products': True,
            'organization_id': default_org.id,
            'auth_type': 'local',
            'password': 'admin123'
        },
        {
            'username': 'org_admin',
            'email': 'org_admin@localhost',
            'full_name': 'Organization Administrator',
            'role': 'org_admin',
            'is_admin': True,
            'can_view_all_orgs': False,
            'can_manage_products': True,
            'organization_id': default_org.id,
            'auth_type': 'local',
            'password': 'orgadmin123'
        },
        {
            'username': 'manager',
            'email': 'manager@localhost',
            'full_name': 'Team Manager',
            'role': 'manager',
            'is_admin': False,
            'can_view_all_orgs': False,
            'can_manage_products': True,
            'organization_id': default_org.id,
            'auth_type': 'local',
            'password': 'manager123'
        },
        {
            'username': 'user',
            'email': 'user@localhost',
            'full_name': 'Regular User',
            'role': 'user',
            'is_admin': False,
            'can_view_all_orgs': False,
            'can_manage_products': False,
            'organization_id': default_org.id,
            'auth_type': 'local',
            'password': 'user123'
        },
        {
            'username': 'eng_admin',
            'email': 'eng_admin@localhost',
            'full_name': 'Engineering Admin',
            'role': 'org_admin',
            'is_admin': True,
            'can_view_all_orgs': False,
            'can_manage_products': True,
            'organization_id': eng_org.id,
            'auth_type': 'local',
            'password': 'engadmin123'
        },
        {
            'username': 'ldap_user',
            'email': 'ldap_user@bonelabs.com',
            'full_name': 'LDAP Test User',
            'role': 'user',
            'is_admin': False,
            'can_view_all_orgs': False,
            'can_manage_products': False,
            'organization_id': default_org.id,
            'auth_type': 'ldap',
            'password': None  # LDAP users don't have password hash
        },
    ]

    created = 0
    updated = 0

    for user_data in test_users:
        username = user_data['username']
        password = user_data.pop('password', None)

        user = User.query.filter_by(username=username).first()

        if user:
            # Update existing user
            for key, value in user_data.items():
                setattr(user, key, value)
            user.is_active = True
            if password:
                user.set_password(password)
            updated += 1
            print(f"✓ Updated user: {username}")
        else:
            # Create new user
            user = User(**user_data)
            user.is_active = True
            if password:
                user.set_password(password)
            db.session.add(user)
            created += 1
            print(f"✓ Created user: {username}")

    db.session.commit()

    print("")
    print("=" * 70)
    print("SUMMARY")
    print("=" * 70)
    print(f"  Created: {created}")
    print(f"  Updated: {updated}")
    print(f"  Total users: {User.query.count()}")
    print("")
    print("=" * 70)
    print("TEST CREDENTIALS")
    print("=" * 70)
    print("")
    print("1. Super Admin:")
    print("   Username: admin")
    print("   Password: admin123")
    print("   Org: Default Organization")
    print("   Access: Full system access")
    print("")
    print("2. Org Admin:")
    print("   Username: org_admin")
    print("   Password: orgadmin123")
    print("   Org: Default Organization")
    print("   Access: Manage users/products in own org")
    print("")
    print("3. Manager:")
    print("   Username: manager")
    print("   Password: manager123")
    print("   Org: Default Organization")
    print("   Access: Manage products, view data")
    print("")
    print("4. Regular User:")
    print("   Username: user")
    print("   Password: user123")
    print("   Org: Default Organization")
    print("   Access: View only")
    print("")
    print("5. Engineering Admin:")
    print("   Username: eng_admin")
    print("   Password: engadmin123")
    print("   Org: Engineering Team")
    print("   Access: Manage Engineering org")
    print("")
    print("6. LDAP User (for LDAP testing):")
    print("   Username: ldap_user")
    print("   Auth: LDAP (use your AD password)")
    print("   Org: Default Organization")
    print("")
    print("=" * 70)
    print("")
    print("Next steps:")
    print("  1. Review COMPREHENSIVE_TESTING_GUIDE.md")
    print("  2. Start testing with different user accounts")
    print("  3. Use incognito windows for multi-user testing")
    print("")
    print("=" * 70)
