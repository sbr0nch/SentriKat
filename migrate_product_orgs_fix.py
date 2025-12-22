#!/usr/bin/env python3
"""
Migration script to populate product_organizations table from legacy organization_id field.

This ensures products are properly assigned to organizations via the many-to-many table.
"""

import os
import sys

# Add parent directory to path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from app import create_app, db
from app.models import Product, Organization, product_organizations

def migrate_product_organizations():
    """Populate product_organizations from legacy organization_id field."""
    app = create_app()

    with app.app_context():
        # Get all products with a legacy organization_id
        products = Product.query.filter(Product.organization_id.isnot(None)).all()

        print(f"Found {len(products)} products with legacy organization_id")

        migrated = 0
        skipped = 0

        for product in products:
            # Check if already in product_organizations
            existing = db.session.query(product_organizations).filter(
                product_organizations.c.product_id == product.id,
                product_organizations.c.organization_id == product.organization_id
            ).first()

            if existing:
                skipped += 1
                continue

            # Get the organization
            org = Organization.query.get(product.organization_id)
            if org:
                product.organizations.append(org)
                migrated += 1
                print(f"  Migrated: {product.vendor} - {product.product_name} -> Org {org.name}")
            else:
                print(f"  WARNING: Org {product.organization_id} not found for product {product.id}")

        db.session.commit()

        print(f"\nMigration complete:")
        print(f"  Migrated: {migrated}")
        print(f"  Skipped (already exists): {skipped}")
        print(f"  Total products: {len(products)}")

if __name__ == '__main__':
    migrate_product_organizations()
