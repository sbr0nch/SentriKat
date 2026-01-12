#!/usr/bin/env python3
"""
Database Reset Tool for SentriKat

This script completely resets the SentriKat database for fresh deployment testing.
WARNING: This will DELETE ALL DATA including users, organizations, and settings!

Usage:
    python tools/reset_database.py           # Interactive mode (prompts for confirmation)
    python tools/reset_database.py --force   # Non-interactive mode (no prompts)

After reset:
    1. Restart SentriKat
    2. Navigate to the web interface
    3. Complete the initial setup wizard
    4. Optionally restore from a backup JSON file
"""

import os
import sys
import shutil
import argparse
from datetime import datetime

# Add parent directory to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

# Database location (matches config.py)
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DATA_DIR = os.path.join(BASE_DIR, 'data')
DB_FILE = os.path.join(DATA_DIR, 'sentrikat.db')

# Other files that may need cleanup
UPLOAD_DIR = os.path.join(BASE_DIR, 'static', 'uploads')
LOG_DIR = os.path.join(BASE_DIR, 'logs')


def get_db_stats():
    """Get statistics about the current database."""
    if not os.path.exists(DB_FILE):
        return None

    stats = {
        'size': os.path.getsize(DB_FILE),
        'modified': datetime.fromtimestamp(os.path.getmtime(DB_FILE)).strftime('%Y-%m-%d %H:%M:%S')
    }

    # Try to get record counts
    try:
        import sqlite3
        conn = sqlite3.connect(DB_FILE)
        cursor = conn.cursor()

        tables = ['user', 'organization', 'vulnerability', 'product', 'system_settings']
        for table in tables:
            try:
                cursor.execute(f'SELECT COUNT(*) FROM {table}')
                stats[f'{table}_count'] = cursor.fetchone()[0]
            except:
                pass

        conn.close()
    except Exception as e:
        stats['error'] = str(e)

    return stats


def reset_database(keep_logs=False):
    """Reset the database and optionally clean up other files."""
    print("\n" + "=" * 60)
    print("SENTRIKAT DATABASE RESET")
    print("=" * 60)

    # Check current state
    if os.path.exists(DB_FILE):
        stats = get_db_stats()
        print(f"\nCurrent database: {DB_FILE}")
        print(f"  Size: {stats['size'] / 1024:.1f} KB")
        print(f"  Modified: {stats['modified']}")
        if 'user_count' in stats:
            print(f"  Users: {stats.get('user_count', 'N/A')}")
            print(f"  Organizations: {stats.get('organization_count', 'N/A')}")
            print(f"  Vulnerabilities: {stats.get('vulnerability_count', 'N/A')}")
            print(f"  Products: {stats.get('product_count', 'N/A')}")
    else:
        print(f"\nNo database found at: {DB_FILE}")

    print("\n" + "-" * 60)
    print("This will DELETE:")
    print(f"  - Database: {DB_FILE}")
    print(f"  - Uploaded files: {UPLOAD_DIR}")
    if not keep_logs:
        print(f"  - Log files: {LOG_DIR}")
    print("-" * 60)

    return True


def perform_reset(keep_logs=False):
    """Actually perform the reset."""
    deleted = []
    errors = []

    # Delete database
    if os.path.exists(DB_FILE):
        try:
            os.remove(DB_FILE)
            deleted.append(f"Database: {DB_FILE}")
        except Exception as e:
            errors.append(f"Database: {e}")

    # Delete SQLite journal/wal files if they exist
    for ext in ['-journal', '-wal', '-shm']:
        wal_file = DB_FILE + ext
        if os.path.exists(wal_file):
            try:
                os.remove(wal_file)
                deleted.append(f"DB file: {wal_file}")
            except Exception as e:
                errors.append(f"DB file {ext}: {e}")

    # Clean uploaded files
    if os.path.exists(UPLOAD_DIR):
        try:
            for f in os.listdir(UPLOAD_DIR):
                filepath = os.path.join(UPLOAD_DIR, f)
                if os.path.isfile(filepath):
                    os.remove(filepath)
                    deleted.append(f"Upload: {f}")
        except Exception as e:
            errors.append(f"Uploads: {e}")

    # Clean logs (optional)
    if not keep_logs and os.path.exists(LOG_DIR):
        try:
            for f in os.listdir(LOG_DIR):
                if f.endswith('.log'):
                    os.remove(os.path.join(LOG_DIR, f))
                    deleted.append(f"Log: {f}")
        except Exception as e:
            errors.append(f"Logs: {e}")

    # Ensure data directory exists for fresh start
    os.makedirs(DATA_DIR, exist_ok=True)

    return deleted, errors


def main():
    parser = argparse.ArgumentParser(description='Reset SentriKat database for fresh deployment')
    parser.add_argument('--force', '-f', action='store_true', help='Skip confirmation prompt')
    parser.add_argument('--keep-logs', action='store_true', help='Keep log files')
    args = parser.parse_args()

    reset_database(keep_logs=args.keep_logs)

    if not args.force:
        print("\n⚠️  WARNING: This action cannot be undone!")
        response = input("\nType 'RESET' to confirm: ")
        if response != 'RESET':
            print("\nAborted. Database was not modified.")
            sys.exit(0)

    print("\nResetting...")
    deleted, errors = perform_reset(keep_logs=args.keep_logs)

    print("\n" + "=" * 60)
    print("RESET COMPLETE")
    print("=" * 60)

    if deleted:
        print("\n✓ Deleted:")
        for item in deleted:
            print(f"    {item}")

    if errors:
        print("\n✗ Errors:")
        for error in errors:
            print(f"    {error}")

    print("\n" + "-" * 60)
    print("Next steps:")
    print("  1. Restart SentriKat: python run.py")
    print("  2. Open browser and complete setup wizard")
    print("  3. To restore data, use Admin > Settings > Backup/Restore")
    print("-" * 60 + "\n")


if __name__ == '__main__':
    main()
