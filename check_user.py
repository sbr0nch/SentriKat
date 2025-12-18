#!/usr/bin/env python
"""Check and fix user permissions"""
import sys
from app import create_app, db
from app.models import User

app = create_app()

with app.app_context():
    # List all users
    print("\n=== All Users ===")
    users = User.query.all()
    for user in users:
        print(f"ID: {user.id} | Username: {user.username} | Role: {user.role} | is_admin: {user.is_admin}")

    # Fix admin user if needed
    if len(sys.argv) > 1:
        username = sys.argv[1]
        user = User.query.filter_by(username=username).first()
        if user:
            print(f"\n=== Fixing user: {username} ===")
            user.role = 'super_admin'
            user.is_admin = True
            db.session.commit()
            print(f"✓ Updated {username} to super_admin with is_admin=True")
        else:
            print(f"✗ User {username} not found")
    else:
        print("\nTo fix a user's role, run: python check_user.py USERNAME")
