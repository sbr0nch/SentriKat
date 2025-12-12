#!/usr/bin/env python3
"""
Database migration script to add criticality column to products table
"""
import sys
import os
from app import create_app, db
from app.models import Product

def migrate():
    app = create_app()
    with app.app_context():
        # Check if the column already exists
        inspector = db.inspect(db.engine)
        columns = [col['name'] for col in inspector.get_columns('products')]

        if 'criticality' in columns:
            print("✓ Column 'criticality' already exists in products table")
            return True

        print("Adding 'criticality' column to products table...")

        try:
            # Add the column with SQLite-compatible syntax
            with db.engine.connect() as conn:
                conn.execute(db.text("ALTER TABLE products ADD COLUMN criticality VARCHAR(20) DEFAULT 'medium'"))
                conn.commit()

            print("✓ Column added successfully")

            # Update all existing products to have default criticality
            products = Product.query.all()
            for product in products:
                if not hasattr(product, 'criticality') or product.criticality is None:
                    product.criticality = 'medium'
            db.session.commit()

            print(f"✓ Updated {len(products)} existing products with default criticality='medium'")
            return True

        except Exception as e:
            print(f"✗ Migration failed: {str(e)}")
            return False

if __name__ == '__main__':
    success = migrate()
    sys.exit(0 if success else 1)
