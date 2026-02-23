-- ============================================================================
-- SentriKat: PostgreSQL Row-Level Security (RLS) Policies
-- ============================================================================
-- Adds database-level tenant isolation on top of application-level filtering.
-- This ensures data isolation even if the ORM is bypassed.
--
-- Usage:
--   psql -U sentrikat -d sentrikat -f scripts/enable_rls.sql
--
-- How it works:
--   1. The application sets current_setting('app.current_org_id') on each
--      database connection (via SQLAlchemy event listener).
--   2. RLS policies filter rows by organization_id = current_setting.
--   3. Super-admin connections set app.current_org_id = '0' to bypass RLS.
--
-- IMPORTANT: RLS does NOT apply to the database superuser (postgres).
--            The application user (sentrikat) must NOT be a superuser.
-- ============================================================================

-- Enable RLS on multi-tenant tables
-- Each policy allows access only when organization_id matches the session variable

-- Products
ALTER TABLE products ENABLE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS tenant_isolation_products ON products;
CREATE POLICY tenant_isolation_products ON products
    USING (
        current_setting('app.current_org_id', TRUE) = '0'
        OR organization_id::text = current_setting('app.current_org_id', TRUE)
        OR organization_id IN (
            SELECT po.organization_id FROM product_organizations po
            WHERE po.product_id = products.id
            AND po.organization_id::text = current_setting('app.current_org_id', TRUE)
        )
    );

-- Assets
ALTER TABLE assets ENABLE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS tenant_isolation_assets ON assets;
CREATE POLICY tenant_isolation_assets ON assets
    USING (
        current_setting('app.current_org_id', TRUE) = '0'
        OR organization_id::text = current_setting('app.current_org_id', TRUE)
    );

-- Vulnerability Matches (through product's organization)
ALTER TABLE vulnerability_matches ENABLE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS tenant_isolation_matches ON vulnerability_matches;
CREATE POLICY tenant_isolation_matches ON vulnerability_matches
    USING (
        current_setting('app.current_org_id', TRUE) = '0'
        OR product_id IN (
            SELECT p.id FROM products p
            WHERE p.organization_id::text = current_setting('app.current_org_id', TRUE)
        )
    );

-- Product Installations
ALTER TABLE product_installations ENABLE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS tenant_isolation_installations ON product_installations;
CREATE POLICY tenant_isolation_installations ON product_installations
    USING (
        current_setting('app.current_org_id', TRUE) = '0'
        OR asset_id IN (
            SELECT a.id FROM assets a
            WHERE a.organization_id::text = current_setting('app.current_org_id', TRUE)
        )
    );

-- Import Queue
ALTER TABLE import_queue ENABLE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS tenant_isolation_import_queue ON import_queue;
CREATE POLICY tenant_isolation_import_queue ON import_queue
    USING (
        current_setting('app.current_org_id', TRUE) = '0'
        OR organization_id::text = current_setting('app.current_org_id', TRUE)
    );

-- Inventory Jobs
ALTER TABLE inventory_jobs ENABLE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS tenant_isolation_inventory_jobs ON inventory_jobs;
CREATE POLICY tenant_isolation_inventory_jobs ON inventory_jobs
    USING (
        current_setting('app.current_org_id', TRUE) = '0'
        OR organization_id::text = current_setting('app.current_org_id', TRUE)
    );

-- Agent Events
ALTER TABLE agent_events ENABLE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS tenant_isolation_agent_events ON agent_events;
CREATE POLICY tenant_isolation_agent_events ON agent_events
    USING (
        current_setting('app.current_org_id', TRUE) = '0'
        OR organization_id::text = current_setting('app.current_org_id', TRUE)
    );

-- Alert Logs
ALTER TABLE alert_logs ENABLE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS tenant_isolation_alert_logs ON alert_logs;
CREATE POLICY tenant_isolation_alert_logs ON alert_logs
    USING (
        current_setting('app.current_org_id', TRUE) = '0'
        OR organization_id::text = current_setting('app.current_org_id', TRUE)
    );

-- Verify RLS is enabled
SELECT tablename, rowsecurity
FROM pg_tables
WHERE schemaname = 'public'
AND rowsecurity = true
ORDER BY tablename;
