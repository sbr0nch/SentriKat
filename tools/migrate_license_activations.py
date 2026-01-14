#!/usr/bin/env python3
"""
Migration script to add the license_activations table.
Run this after updating to a version with single-use license validation.

Usage:
    python tools/migrate_license_activations.py
"""

import sys
import os

# Add the parent directory to path for imports
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app import create_app, db
from sqlalchemy import inspect

def check_table_exists(engine, table_name):
    """Check if a table exists in the database."""
    inspector = inspect(engine)
    return table_name in inspector.get_table_names()

def migrate():
    """Run the migration to add license_activations table."""
    app = create_app()

    with app.app_context():
        engine = db.engine

        # Check if table already exists
        if check_table_exists(engine, 'license_activations'):
            print("✓ Table 'license_activations' already exists. No migration needed.")
            return True

        print("Creating 'license_activations' table...")

        # Import the model to ensure it's registered
        from app.models import LicenseActivation

        # Create the table
        LicenseActivation.__table__.create(engine)

        print("✓ Table 'license_activations' created successfully!")

        # Verify
        if check_table_exists(engine, 'license_activations'):
            print("✓ Migration completed successfully.")
            return True
        else:
            print("✗ Migration failed - table was not created.")
            return False

if __name__ == '__main__':
    success = migrate()
    sys.exit(0 if success else 1)
