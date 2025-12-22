#!/usr/bin/env python3
"""
Promote a user to super_admin role.
Usage: python promote_admin.py <username>
"""

import sys
import os

# Add the app directory to the path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from app import create_app, db
from app.models import User

def promote_to_super_admin(username):
    """Promote a user to super_admin role"""
    app = create_app()

    with app.app_context():
        user = User.query.filter_by(username=username).first()

        if not user:
            print(f"Error: User '{username}' not found")
            return False

        old_role = user.role
        user.role = 'super_admin'
        user.is_admin = True

        db.session.commit()

        print(f"Success! User '{username}' promoted:")
        print(f"  - Old role: {old_role}")
        print(f"  - New role: super_admin")
        print(f"  - is_admin: True")
        return True

def list_super_admins():
    """List all super admins"""
    app = create_app()

    with app.app_context():
        super_admins = User.query.filter_by(role='super_admin').all()

        if not super_admins:
            print("No super admins found in the system!")
        else:
            print(f"Current super admins ({len(super_admins)}):")
            for sa in super_admins:
                status = "active" if sa.is_active else "inactive"
                print(f"  - {sa.username} ({sa.email}) [{status}]")

if __name__ == '__main__':
    if len(sys.argv) < 2:
        print("Usage: python promote_admin.py <username>")
        print("       python promote_admin.py --list")
        sys.exit(1)

    if sys.argv[1] == '--list':
        list_super_admins()
    else:
        username = sys.argv[1]
        promote_to_super_admin(username)
