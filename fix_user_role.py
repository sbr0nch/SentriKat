#!/usr/bin/env python3
"""
Fix user role to super_admin.

Usage:
    python fix_user_role.py <username>

Example:
    python fix_user_role.py systemadmin
"""

import sys
import os

# Add parent directory to path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from app import create_app, db
from app.models import User


def fix_user_role(username):
    """Set user role to super_admin."""
    app = create_app()

    with app.app_context():
        user = User.query.filter_by(username=username).first()

        if not user:
            print(f"ERROR: User '{username}' not found!")
            print("\nAvailable users:")
            for u in User.query.all():
                print(f"  - {u.username} (role: {u.role}, is_admin: {u.is_admin})")
            return False

        print(f"Found user: {user.username}")
        print(f"  Current role: {user.role}")
        print(f"  is_admin flag: {user.is_admin}")

        # Update to super_admin
        user.role = 'super_admin'
        user.is_admin = True

        db.session.commit()

        print(f"\n✓ Updated {user.username} to super_admin!")
        print(f"  New role: {user.role}")
        print(f"  is_admin: {user.is_admin}")

        return True


if __name__ == '__main__':
    if len(sys.argv) < 2:
        print("Usage: python fix_user_role.py <username>")
        print("\nExample:")
        print("  python fix_user_role.py systemadmin")
        sys.exit(1)

    username = sys.argv[1]
    success = fix_user_role(username)
    sys.exit(0 if success else 1)
