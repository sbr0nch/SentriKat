-- ============================================================================
-- SentriKat Sprint 4 + Sprint 5 schema upgrade
-- ============================================================================
--
-- This script brings a pre-Sprint-4 production database up to the schema
-- expected by the code at commit b8b78f3+ on the branch
-- claude/fix-windows-agent-ping-d4xak.
--
-- Target: PostgreSQL 15+. Also compatible with SQLite for dev
-- (NOTE: SQLite does not enforce FK constraints by default, and
-- ALTER TABLE RENAME COLUMN is only available in SQLite 3.25+).
--
-- Safe to re-run: all CREATE statements use IF NOT EXISTS and the
-- tracker_issue_key rename is guarded by a DO block on PostgreSQL.
--
-- How to apply (inside the sentrikat container):
--   docker compose exec -T db psql -U $POSTGRES_USER $POSTGRES_DB \
--       < migrations/sprint4_sprint5/upgrade.sql
--
-- Rollback:
--   docker compose exec -T db psql -U $POSTGRES_USER $POSTGRES_DB \
--       < migrations/sprint4_sprint5/rollback.sql
--
-- Audited by two independent agents (security + completeness) on
-- 2026-04-14. See docs/PRE_LAUNCH_AUDIT_AND_TESTING_PLAN.md PARTE 9
-- for the full change list.
--
-- ============================================================================

BEGIN;

-- ----------------------------------------------------------------------------
-- 1. New table: vulnerability_snapshots  (Sprint 5)
-- ----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS vulnerability_snapshots (
    id                      SERIAL PRIMARY KEY,
    organization_id         INTEGER NULL REFERENCES organizations(id) ON DELETE CASCADE,
    snapshot_date           DATE NOT NULL,
    total_vulnerabilities   INTEGER DEFAULT 0,
    total_matches           INTEGER DEFAULT 0,
    unacknowledged          INTEGER DEFAULT 0,
    acknowledged            INTEGER DEFAULT 0,
    snoozed                 INTEGER DEFAULT 0,
    critical_count          INTEGER DEFAULT 0,
    high_count              INTEGER DEFAULT 0,
    medium_count            INTEGER DEFAULT 0,
    low_count               INTEGER DEFAULT 0,
    products_tracked        INTEGER DEFAULT 0,
    products_with_vulns     INTEGER DEFAULT 0,
    active_agents           INTEGER DEFAULT 0,
    created_at              TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT uq_org_snapshot_date UNIQUE (organization_id, snapshot_date)
);

CREATE INDEX IF NOT EXISTS ix_vulnerability_snapshots_organization_id
    ON vulnerability_snapshots (organization_id);
CREATE INDEX IF NOT EXISTS ix_vulnerability_snapshots_snapshot_date
    ON vulnerability_snapshots (snapshot_date);


-- ----------------------------------------------------------------------------
-- 2. New table: sla_policies  (Sprint 3 / Sprint 4)
-- ----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS sla_policies (
    id                  SERIAL PRIMARY KEY,
    organization_id     INTEGER NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    name                VARCHAR(200) NOT NULL,
    severity            VARCHAR(20) NOT NULL,
    max_days            INTEGER NOT NULL,
    enabled             BOOLEAN DEFAULT TRUE,
    notify_on_breach    BOOLEAN DEFAULT TRUE,
    escalate_to         VARCHAR(200) NULL,
    created_at          TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS ix_sla_policies_organization_id
    ON sla_policies (organization_id);


-- ----------------------------------------------------------------------------
-- 3. New table: remediation_assignments  (Sprint 3 / Sprint 4)
-- ----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS remediation_assignments (
    id                      SERIAL PRIMARY KEY,
    organization_id         INTEGER NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    match_id                INTEGER NULL REFERENCES vulnerability_matches(id) ON DELETE CASCADE,
    product_id              INTEGER NULL REFERENCES products(id) ON DELETE CASCADE,
    cve_id                  VARCHAR(20) NULL,
    assigned_to             VARCHAR(200) NOT NULL,
    assigned_by             VARCHAR(200) NOT NULL,
    due_date                DATE NULL,
    status                  VARCHAR(20) DEFAULT 'open',
    priority                VARCHAR(20) DEFAULT 'medium',
    notes                   TEXT NULL,
    resolution_notes        TEXT NULL,
    tracker_issue_key       VARCHAR(100) NULL,
    tracker_issue_url       VARCHAR(500) NULL,
    tracker_type            VARCHAR(20) NULL,
    created_at              TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at              TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    resolved_at             TIMESTAMP NULL
);

CREATE INDEX IF NOT EXISTS ix_remediation_assignments_organization_id
    ON remediation_assignments (organization_id);
CREATE INDEX IF NOT EXISTS ix_remediation_assignments_match_id
    ON remediation_assignments (match_id);
CREATE INDEX IF NOT EXISTS ix_remediation_assignments_product_id
    ON remediation_assignments (product_id);
CREATE INDEX IF NOT EXISTS ix_remediation_assignments_cve_id
    ON remediation_assignments (cve_id);

-- Sprint 4 composite indexes for dashboard queries
CREATE INDEX IF NOT EXISTS idx_assign_org_status
    ON remediation_assignments (organization_id, status);
CREATE INDEX IF NOT EXISTS idx_assign_org_assignee
    ON remediation_assignments (organization_id, assigned_to);
CREATE INDEX IF NOT EXISTS idx_assign_org_due
    ON remediation_assignments (organization_id, due_date);


-- ----------------------------------------------------------------------------
-- 3b. Column rename: jira_issue_key -> tracker_issue_key
-- ----------------------------------------------------------------------------
-- If a previous deploy already created this table under the old name
-- jira_issue_key (Sprint 3 originally used that name), rename it in-place.
-- If the table was just created by the CREATE TABLE above, there is nothing
-- to do.
--
-- The same applies to jira_issue_url (new: tracker_issue_url).
-- ----------------------------------------------------------------------------

DO $$
BEGIN
    IF EXISTS (
        SELECT 1 FROM information_schema.columns
        WHERE table_name = 'remediation_assignments'
          AND column_name = 'jira_issue_key'
    ) AND NOT EXISTS (
        SELECT 1 FROM information_schema.columns
        WHERE table_name = 'remediation_assignments'
          AND column_name = 'tracker_issue_key'
    ) THEN
        ALTER TABLE remediation_assignments
            RENAME COLUMN jira_issue_key TO tracker_issue_key;
    END IF;

    IF EXISTS (
        SELECT 1 FROM information_schema.columns
        WHERE table_name = 'remediation_assignments'
          AND column_name = 'jira_issue_url'
    ) AND NOT EXISTS (
        SELECT 1 FROM information_schema.columns
        WHERE table_name = 'remediation_assignments'
          AND column_name = 'tracker_issue_url'
    ) THEN
        ALTER TABLE remediation_assignments
            RENAME COLUMN jira_issue_url TO tracker_issue_url;
    END IF;

    -- Ensure tracker_type column exists (it's new in Sprint 4)
    IF NOT EXISTS (
        SELECT 1 FROM information_schema.columns
        WHERE table_name = 'remediation_assignments'
          AND column_name = 'tracker_type'
    ) THEN
        ALTER TABLE remediation_assignments
            ADD COLUMN tracker_type VARCHAR(20) NULL;
    END IF;
END $$;


-- ----------------------------------------------------------------------------
-- 4. New table: risk_exceptions  (Sprint 4)
-- ----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS risk_exceptions (
    id                  SERIAL PRIMARY KEY,
    organization_id     INTEGER NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    match_id            INTEGER NULL REFERENCES vulnerability_matches(id) ON DELETE CASCADE,
    cve_id              VARCHAR(20) NULL,
    product_id          INTEGER NULL REFERENCES products(id) ON DELETE CASCADE,
    justification       TEXT NOT NULL,
    approved_by         VARCHAR(200) NOT NULL,
    expires_at          DATE NULL,
    status              VARCHAR(20) DEFAULT 'active',
    created_at          TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at          TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS ix_risk_exceptions_organization_id
    ON risk_exceptions (organization_id);
CREATE INDEX IF NOT EXISTS ix_risk_exceptions_match_id
    ON risk_exceptions (match_id);
CREATE INDEX IF NOT EXISTS ix_risk_exceptions_cve_id
    ON risk_exceptions (cve_id);
CREATE INDEX IF NOT EXISTS ix_risk_exceptions_product_id
    ON risk_exceptions (product_id);

CREATE INDEX IF NOT EXISTS idx_riskexc_org_status
    ON risk_exceptions (organization_id, status);
CREATE INDEX IF NOT EXISTS idx_riskexc_org_expiry
    ON risk_exceptions (organization_id, expires_at);


-- ----------------------------------------------------------------------------
-- 5. New table: product_aliases  (Sprint 4)
-- ----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS product_aliases (
    id                  SERIAL PRIMARY KEY,
    organization_id     INTEGER NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    product_id          INTEGER NOT NULL REFERENCES products(id) ON DELETE CASCADE,
    alias_vendor        VARCHAR(200) NOT NULL,
    alias_product       VARCHAR(200) NOT NULL,
    created_at          TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT uq_product_alias UNIQUE (organization_id, alias_vendor, alias_product)
);

CREATE INDEX IF NOT EXISTS ix_product_aliases_organization_id
    ON product_aliases (organization_id);
CREATE INDEX IF NOT EXISTS ix_product_aliases_product_id
    ON product_aliases (product_id);


-- ----------------------------------------------------------------------------
-- Done
-- ----------------------------------------------------------------------------
COMMIT;

-- Verification queries (run after the migration to double-check):
--
--   SELECT table_name FROM information_schema.tables
--    WHERE table_name IN ('vulnerability_snapshots','sla_policies',
--                         'remediation_assignments','risk_exceptions',
--                         'product_aliases')
--    ORDER BY table_name;
--
--   SELECT indexname FROM pg_indexes
--    WHERE indexname IN ('idx_assign_org_status','idx_assign_org_assignee',
--                        'idx_assign_org_due','idx_riskexc_org_status',
--                        'idx_riskexc_org_expiry','uq_product_alias')
--    ORDER BY indexname;
--
--   SELECT column_name FROM information_schema.columns
--    WHERE table_name = 'remediation_assignments'
--      AND column_name IN ('tracker_issue_key','tracker_issue_url','tracker_type')
--    ORDER BY column_name;
