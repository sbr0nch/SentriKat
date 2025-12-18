#!/usr/bin/env python3
"""
Audit both database files to see what data exists in each
"""
import sqlite3
import os

def audit_database(db_path):
    """Audit a database and return its contents"""
    if not os.path.exists(db_path):
        return None

    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()

    # Get all tables
    cursor.execute("SELECT name FROM sqlite_master WHERE type='table' ORDER BY name")
    tables = [row[0] for row in cursor.fetchall()]

    data = {
        'path': db_path,
        'exists': True,
        'size': os.path.getsize(db_path),
        'tables': {}
    }

    # Count rows in each table
    for table in tables:
        try:
            cursor.execute(f"SELECT COUNT(*) FROM {table}")
            count = cursor.fetchone()[0]
            data['tables'][table] = count

            # Get sample data for important tables
            if table == 'users':
                cursor.execute("SELECT username, email, role, is_admin, auth_type FROM users")
                data['users_data'] = cursor.fetchall()
            elif table == 'organizations':
                cursor.execute("SELECT id, name, display_name FROM organizations")
                data['orgs_data'] = cursor.fetchall()
            elif table == 'products':
                cursor.execute("SELECT COUNT(*) FROM products")
                data['products_count'] = cursor.fetchone()[0]
            elif table == 'vulnerabilities':
                cursor.execute("SELECT COUNT(*) FROM vulnerabilities")
                data['vulns_count'] = cursor.fetchone()[0]
        except Exception as e:
            data['tables'][table] = f"Error: {e}"

    conn.close()
    return data

def print_audit(data, label):
    """Print audit results"""
    print(f"\n{'='*70}")
    print(f"{label}")
    print(f"{'='*70}")

    if not data:
        print("❌ Database does not exist")
        return

    print(f"✓ Path: {data['path']}")
    print(f"✓ Size: {data['size']:,} bytes")
    print(f"✓ Tables: {len(data['tables'])}")

    print(f"\nTable Row Counts:")
    for table, count in sorted(data['tables'].items()):
        print(f"  - {table}: {count}")

    if 'users_data' in data and data['users_data']:
        print(f"\n👤 Users:")
        for user in data['users_data']:
            print(f"  - {user[0]} | {user[1]} | role={user[2]} | is_admin={user[3]} | auth_type={user[4]}")

    if 'orgs_data' in data and data['orgs_data']:
        print(f"\n🏢 Organizations:")
        for org in data['orgs_data']:
            print(f"  - [{org[0]}] {org[1]} ({org[2]})")

    if 'products_count' in data:
        print(f"\n📦 Products: {data['products_count']}")

    if 'vulns_count' in data:
        print(f"\n🔒 Vulnerabilities: {data['vulns_count']}")

if __name__ == '__main__':
    print("\n" + "="*70)
    print("DATABASE AUDIT")
    print("="*70)

    # Audit both databases
    db1 = audit_database('/opt/sentrikat/sentrikat.db')
    db2 = audit_database('/opt/sentrikat/data/sentrikat.db')

    print_audit(db1, "DATABASE 1: /opt/sentrikat/sentrikat.db")
    print_audit(db2, "DATABASE 2: /opt/sentrikat/data/sentrikat.db")

    print(f"\n{'='*70}")
    print("RECOMMENDATION")
    print(f"{'='*70}")

    if db1 and db2:
        # Both exist - need to merge
        db1_has_data = sum([v for v in db1['tables'].values() if isinstance(v, int)]) > 2
        db2_has_data = sum([v for v in db2['tables'].values() if isinstance(v, int)]) > 2

        if db2_has_data and not db1_has_data:
            print("✓ DATABASE 2 has more data - use it as primary")
            print("✓ Copy admin user from DB1 to DB2")
        elif db1_has_data and not db2_has_data:
            print("✓ DATABASE 1 has more data - use it as primary")
            print("✓ Update .env to point to DB1")
        else:
            print("⚠ Both databases have data - need to merge")
            print("  Strategy: Keep DB2 (Flask config), copy admin user from DB1")
    elif db1 and not db2:
        print("✓ Only DATABASE 1 exists")
        print("✓ Update .env to: DATABASE_URL=sqlite:///sentrikat.db")
    elif db2 and not db1:
        print("✓ Only DATABASE 2 exists")
        print("✓ .env is already correct, just need to create admin user")
    else:
        print("✗ No databases exist!")

    print("="*70 + "\n")
