-- ============================================================================
-- SentriKat Sprint 6 hardening — ROLLBACK
-- ============================================================================
--
-- Reverses the sprint6_hardening/upgrade.sql migration.
--
-- WARNING: Step 3 (re-granting can_manage_products to role='user') restores
-- the old insecure default. Only do this if you need to roll back the app
-- code as well.
--
-- ============================================================================

BEGIN;

-- 1. Remove removed_at column from product_installations
DO $$
BEGIN
    IF EXISTS (
        SELECT 1 FROM information_schema.columns
        WHERE table_name = 'product_installations' AND column_name = 'removed_at'
    ) THEN
        DROP INDEX IF EXISTS idx_product_installations_removed_at;
        ALTER TABLE product_installations DROP COLUMN removed_at;
    END IF;
END $$;

-- 2. Restore can_manage_products default to TRUE
ALTER TABLE users ALTER COLUMN can_manage_products SET DEFAULT TRUE;

-- 3. Re-grant can_manage_products to role='user' users (old behaviour)
UPDATE users
SET can_manage_products = TRUE
WHERE role = 'user'
  AND can_manage_products = FALSE;

COMMIT;
