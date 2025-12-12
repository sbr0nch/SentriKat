#!/usr/bin/env python3
"""
Database migration script to add CVSS score and severity columns to vulnerabilities table
"""
import sys
import os
from app import create_app, db

def migrate():
    app = create_app()
    with app.app_context():
        # Check if the columns already exist
        inspector = db.inspect(db.engine)
        columns = [col['name'] for col in inspector.get_columns('vulnerabilities')]

        needs_migration = False

        if 'cvss_score' not in columns:
            print("Adding 'cvss_score' column to vulnerabilities table...")
            needs_migration = True
        else:
            print("✓ Column 'cvss_score' already exists")

        if 'severity' not in columns:
            print("Adding 'severity' column to vulnerabilities table...")
            needs_migration = True
        else:
            print("✓ Column 'severity' already exists")

        if not needs_migration:
            print("✓ All columns already exist, no migration needed")
            return True

        try:
            # Add the columns with SQLite-compatible syntax
            with db.engine.connect() as conn:
                if 'cvss_score' not in columns:
                    conn.execute(db.text("ALTER TABLE vulnerabilities ADD COLUMN cvss_score FLOAT"))
                    conn.commit()
                    print("✓ Column 'cvss_score' added successfully")

                if 'severity' not in columns:
                    conn.execute(db.text("ALTER TABLE vulnerabilities ADD COLUMN severity VARCHAR(20)"))
                    conn.commit()
                    print("✓ Column 'severity' added successfully")

            print("\n✓ Migration completed successfully")
            print("\nNext steps:")
            print("1. Restart your application: sudo systemctl restart sentrikat")
            print("2. Run enrichment script to fetch CVSS data: python3 enrich_cvss.py")
            return True

        except Exception as e:
            print(f"✗ Migration failed: {str(e)}")
            return False

if __name__ == '__main__':
    success = migrate()
    sys.exit(0 if success else 1)
