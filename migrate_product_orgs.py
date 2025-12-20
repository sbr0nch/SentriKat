#!/usr/bin/env python3
"""
Migration script to add many-to-many product-organization relationship
"""
from app import create_app, db
from app.models import Product
from sqlalchemy import text

def migrate():
    app = create_app()
    with app.app_context():
        print("Starting product-organization migration...")

        # Create the association table
        print("Creating product_organizations table...")
        try:
            db.session.execute(text("""
                CREATE TABLE IF NOT EXISTS product_organizations (
                    product_id INTEGER NOT NULL,
                    organization_id INTEGER NOT NULL,
                    assigned_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                    PRIMARY KEY (product_id, organization_id),
                    FOREIGN KEY (product_id) REFERENCES products(id) ON DELETE CASCADE,
                    FOREIGN KEY (organization_id) REFERENCES organizations(id) ON DELETE CASCADE
                )
            """))
            db.session.commit()
            print("✓ Table created successfully")
        except Exception as e:
            print(f"Note: Table may already exist - {str(e)}")
            db.session.rollback()

        # Migrate existing organization_id data to many-to-many table
        print("\nMigrating existing organization assignments...")
        products_with_org = Product.query.filter(Product.organization_id.isnot(None)).all()

        migrated_count = 0
        for product in products_with_org:
            try:
                # Check if already migrated
                existing = db.session.execute(text("""
                    SELECT 1 FROM product_organizations
                    WHERE product_id = :pid AND organization_id = :oid
                """), {'pid': product.id, 'oid': product.organization_id}).fetchone()

                if not existing:
                    db.session.execute(text("""
                        INSERT INTO product_organizations (product_id, organization_id, assigned_at)
                        VALUES (:pid, :oid, datetime('now'))
                    """), {'pid': product.id, 'oid': product.organization_id})
                    migrated_count += 1
            except Exception as e:
                print(f"Error migrating product {product.id}: {str(e)}")
                db.session.rollback()
                continue

        db.session.commit()
        print(f"✓ Migrated {migrated_count} product-organization relationships")

        # Verify migration
        print("\nVerifying migration...")
        total_assignments = db.session.execute(text(
            "SELECT COUNT(*) FROM product_organizations"
        )).scalar()
        print(f"✓ Total assignments in new table: {total_assignments}")

        print("\n✅ Migration completed successfully!")
        print("\nNote: The legacy organization_id field is kept for backwards compatibility")
        print("New products will use the many-to-many relationship automatically")

if __name__ == '__main__':
    migrate()
