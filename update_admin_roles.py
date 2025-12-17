#!/usr/bin/env python3
"""
Update legacy admin users to have proper role values
This script updates users with is_admin=True but no role set to have role='super_admin'
"""

from app import create_app, db
from app.models import User

def update_admin_roles():
    """Update admin users to have proper role values"""
    app = create_app()

    with app.app_context():
        # Find users with is_admin=True but no proper role
        legacy_admins = User.query.filter(
            User.is_admin == True,
            db.or_(User.role == None, User.role == 'user', User.role == '')
        ).all()

        if not legacy_admins:
            print("✓ No legacy admin users found - all users have proper roles")
            return

        print(f"Found {len(legacy_admins)} legacy admin user(s) to update:\n")

        for user in legacy_admins:
            print(f"  • {user.username} (ID: {user.id})")
            print(f"    Current: is_admin={user.is_admin}, role={user.role}")

            # Set role to super_admin for legacy admins
            user.role = 'super_admin'

            print(f"    Updated: role=super_admin")
            print()

        # Commit changes
        try:
            db.session.commit()
            print(f"✓ Successfully updated {len(legacy_admins)} user(s) to super_admin role")
        except Exception as e:
            db.session.rollback()
            print(f"✗ Error updating users: {e}")
            return

        print("\n" + "="*60)
        print("All admin users now have proper roles!")
        print("="*60)

if __name__ == '__main__':
    update_admin_roles()
