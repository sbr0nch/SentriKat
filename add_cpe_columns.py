#!/usr/bin/env python3
"""
Migration script to add CPE-related columns to the database.

Run this script to add the necessary columns for NVD CPE integration:
    python add_cpe_columns.py

This script adds:
- Product: cpe_vendor, cpe_product, cpe_uri, match_type columns
- Vulnerability: cpe_data, cpe_fetched_at columns
- VulnerabilityMatch: match_method, match_confidence columns
- ServiceCatalog: cpe_vendor, cpe_product columns (if not exists)
"""
import os
import sys

# Add project root to path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from sqlalchemy import text
from app import create_app, db


def column_exists(connection, table_name, column_name):
    """Check if a column exists in a table."""
    result = connection.execute(text(f"""
        SELECT column_name
        FROM information_schema.columns
        WHERE table_name = :table AND column_name = :column
    """), {"table": table_name, "column": column_name})
    return result.fetchone() is not None


def add_column_if_not_exists(connection, table_name, column_name, column_type, default=None):
    """Add a column to a table if it doesn't exist."""
    if not column_exists(connection, table_name, column_name):
        default_clause = f" DEFAULT '{default}'" if default else ""
        sql = f"ALTER TABLE {table_name} ADD COLUMN {column_name} {column_type}{default_clause}"
        print(f"  Adding column: {table_name}.{column_name}")
        connection.execute(text(sql))
        return True
    else:
        print(f"  Column already exists: {table_name}.{column_name}")
        return False


def add_index_if_not_exists(connection, index_name, table_name, column_name):
    """Add an index if it doesn't exist."""
    result = connection.execute(text(f"""
        SELECT indexname
        FROM pg_indexes
        WHERE indexname = :index_name
    """), {"index_name": index_name})

    if result.fetchone() is None:
        sql = f"CREATE INDEX {index_name} ON {table_name} ({column_name})"
        print(f"  Creating index: {index_name}")
        connection.execute(text(sql))
        return True
    else:
        print(f"  Index already exists: {index_name}")
        return False


def run_migration():
    """Run the migration to add CPE columns."""
    app = create_app()

    with app.app_context():
        print("\n=== Adding CPE columns to database ===\n")

        with db.engine.connect() as connection:
            with connection.begin():
                # Product table columns
                print("Product table:")
                add_column_if_not_exists(connection, "products", "cpe_vendor", "VARCHAR(200)")
                add_column_if_not_exists(connection, "products", "cpe_product", "VARCHAR(200)")
                add_column_if_not_exists(connection, "products", "cpe_uri", "VARCHAR(500)")
                add_column_if_not_exists(connection, "products", "match_type", "VARCHAR(20)", default="auto")

                # Add indexes for CPE columns
                add_index_if_not_exists(connection, "ix_products_cpe_vendor", "products", "cpe_vendor")
                add_index_if_not_exists(connection, "ix_products_cpe_product", "products", "cpe_product")

                # Vulnerability table columns
                print("\nVulnerabilities table:")
                add_column_if_not_exists(connection, "vulnerabilities", "cpe_data", "TEXT")
                add_column_if_not_exists(connection, "vulnerabilities", "cpe_fetched_at", "TIMESTAMP")

                # VulnerabilityMatch table columns
                print("\nVulnerability_matches table:")
                add_column_if_not_exists(connection, "vulnerability_matches", "match_method", "VARCHAR(20)", default="keyword")
                add_column_if_not_exists(connection, "vulnerability_matches", "match_confidence", "VARCHAR(20)", default="medium")

                # ServiceCatalog table columns (if table exists)
                print("\nService_catalog table:")
                try:
                    add_column_if_not_exists(connection, "service_catalog", "cpe_vendor", "VARCHAR(200)")
                    add_column_if_not_exists(connection, "service_catalog", "cpe_product", "VARCHAR(200)")
                except Exception as e:
                    print(f"  Note: service_catalog table might not exist or use different name: {e}")

        print("\n=== Migration completed successfully! ===\n")
        print("You can now restart the application.")


if __name__ == "__main__":
    run_migration()
