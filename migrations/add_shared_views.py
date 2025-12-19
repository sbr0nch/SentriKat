#!/usr/bin/env python3
"""
Database migration: Add SharedView table
Run this script to add the shared_views table to your database
"""

from app import create_app, db
from app.models import SharedView

def migrate():
    app = create_app()
    with app.app_context():
        print("Creating shared_views table...")
        db.create_all()
        print("✓ Migration complete!")
        print("  - shared_views table created")

if __name__ == '__main__':
    migrate()
