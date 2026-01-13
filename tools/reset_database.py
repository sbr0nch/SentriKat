#!/usr/bin/env python3
"""
Database Reset Tool for SentriKat

Resets the SentriKat database by dropping and recreating all tables.
Works with PostgreSQL (production) or any SQLAlchemy-supported database.

WARNING: This will DELETE ALL DATA including users, organizations, and settings!

Usage:
    python tools/reset_database.py           # Interactive mode (prompts for confirmation)
    python tools/reset_database.py --force   # Non-interactive mode (no prompts)
"""

import os
import sys
import argparse

# Add parent directory to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


def get_db_stats(app):
    """Get statistics about the current database."""
    from app.models import User, Organization, Vulnerability, Product, SystemSettings

    stats = {}
    try:
        stats['users'] = User.query.count()
        stats['organizations'] = Organization.query.count()
        stats['vulnerabilities'] = Vulnerability.query.count()
        stats['products'] = Product.query.count()
        stats['settings'] = SystemSettings.query.count()
    except Exception as e:
        stats['error'] = str(e)

    return stats


def reset_database(force=False):
    """Reset the database by dropping and recreating all tables."""
    from app import create_app, db

    print("\n" + "=" * 60)
    print("SENTRIKAT DATABASE RESET")
    print("=" * 60)

    app = create_app()

    with app.app_context():
        # Show current database info
        db_url = app.config.get('SQLALCHEMY_DATABASE_URI', 'unknown')
        # Mask password in URL for display
        if '@' in db_url:
            parts = db_url.split('@')
            masked_url = parts[0].rsplit(':', 1)[0] + ':****@' + parts[1]
        else:
            masked_url = db_url
        print(f"\nDatabase: {masked_url}")

        # Get current stats
        stats = get_db_stats(app)
        if 'error' not in stats:
            print(f"\nCurrent data:")
            print(f"  Users: {stats.get('users', 0)}")
            print(f"  Organizations: {stats.get('organizations', 0)}")
            print(f"  Vulnerabilities: {stats.get('vulnerabilities', 0)}")
            print(f"  Products: {stats.get('products', 0)}")
            print(f"  Settings: {stats.get('settings', 0)}")
        else:
            print(f"\nDatabase appears empty or not initialized.")

        print("\n" + "-" * 60)
        print("This will DELETE ALL DATA and recreate the database schema.")
        print("-" * 60)

        if not force:
            print("\n⚠️  WARNING: This action cannot be undone!")
            response = input("\nType 'RESET' to confirm: ")
            if response != 'RESET':
                print("\nAborted. Database was not modified.")
                sys.exit(0)

        print("\nResetting database...")

        try:
            # Drop all tables
            db.drop_all()
            print("  ✓ All tables dropped")

            # Recreate all tables
            db.create_all()
            print("  ✓ All tables created")

            print("\n" + "=" * 60)
            print("RESET COMPLETE")
            print("=" * 60)
            print("\nNext steps:")
            print("  1. Start/restart SentriKat")
            print("  2. Open browser and complete setup wizard")
            print("  3. To restore data, use Admin > Settings > Backup/Restore")
            print("-" * 60 + "\n")

        except Exception as e:
            print(f"\n✗ Error resetting database: {e}")
            sys.exit(1)


def main():
    parser = argparse.ArgumentParser(description='Reset SentriKat database')
    parser.add_argument('--force', '-f', action='store_true', help='Skip confirmation prompt')
    args = parser.parse_args()

    reset_database(force=args.force)


if __name__ == '__main__':
    main()
