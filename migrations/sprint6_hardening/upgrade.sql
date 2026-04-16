-- ============================================================================
-- SentriKat Sprint 6 hardening migration
-- ============================================================================
--
-- Changes:
--   1. Add removed_at column to product_installations (soft-delete support)
--   2. Flip can_manage_products default from TRUE to FALSE on users table
--   3. Set can_manage_products = FALSE for existing non-admin/non-manager users
--
-- Safe to re-run: all statements are guarded with IF NOT EXISTS / WHERE clauses.
--
-- How to apply:
--   docker compose exec -T db psql -U $POSTGRES_USER $POSTGRES_DB \
--       < migrations/sprint6_hardening/upgrade.sql
--
-- Rollback:
--   docker compose exec -T db psql -U $POSTGRES_USER $POSTGRES_DB \
--       < migrations/sprint6_hardening/rollback.sql
--
-- ============================================================================

BEGIN;

-- ----------------------------------------------------------------------------
-- 1. Soft-delete for ProductInstallation
-- ----------------------------------------------------------------------------
-- Add removed_at column if it doesn't already exist
DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM information_schema.columns
        WHERE table_name = 'product_installations' AND column_name = 'removed_at'
    ) THEN
        ALTER TABLE product_installations ADD COLUMN removed_at TIMESTAMP NULL;
        CREATE INDEX idx_product_installations_removed_at ON product_installations (removed_at);
    END IF;
END $$;

-- ----------------------------------------------------------------------------
-- 2. Flip can_manage_products default from TRUE to FALSE
-- ----------------------------------------------------------------------------
ALTER TABLE users ALTER COLUMN can_manage_products SET DEFAULT FALSE;

-- ----------------------------------------------------------------------------
-- 3. Set can_manage_products = FALSE for non-privileged users
--    Only affects users with role 'user' (viewers/readers).
--    Managers, org_admins, and super_admins keep their existing value.
-- ----------------------------------------------------------------------------
UPDATE users
SET can_manage_products = FALSE
WHERE role = 'user'
  AND can_manage_products = TRUE;

COMMIT;
