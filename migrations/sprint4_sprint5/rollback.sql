-- ============================================================================
-- SentriKat Sprint 4 + Sprint 5 schema ROLLBACK
-- ============================================================================
--
-- Reverses migrations/sprint4_sprint5/upgrade.sql.
--
-- WARNING: this script will DROP the following tables and DELETE the data
-- they contain:
--   - vulnerability_snapshots   (trend snapshots since Sprint 5)
--   - sla_policies              (SLA policies, Sprint 4)
--   - remediation_assignments   (assignments, Sprint 3/4)
--   - risk_exceptions           (risk exception log, Sprint 4)
--   - product_aliases           (product aliases, Sprint 4)
--
-- Take a full DB backup before running this. This is NOT idempotent with
-- respect to data: once the tables are dropped, the data is gone. Use
-- ONLY for a rollback from a failed deploy, never in production without
-- a verified backup.
--
-- How to apply:
--   docker compose exec -T db psql -U $POSTGRES_USER $POSTGRES_DB \
--       < migrations/sprint4_sprint5/rollback.sql
-- ============================================================================

BEGIN;

DROP TABLE IF EXISTS product_aliases CASCADE;
DROP TABLE IF EXISTS risk_exceptions CASCADE;

-- Rollback of the rename: only rename back if the new column exists and the
-- old one doesn't. If the table was freshly created by the upgrade script
-- we're about to drop it, so the rename is irrelevant.
DO $$
BEGIN
    IF EXISTS (
        SELECT 1 FROM information_schema.columns
        WHERE table_name = 'remediation_assignments'
          AND column_name = 'tracker_issue_key'
    ) AND NOT EXISTS (
        SELECT 1 FROM information_schema.columns
        WHERE table_name = 'remediation_assignments'
          AND column_name = 'jira_issue_key'
    ) THEN
        ALTER TABLE remediation_assignments
            RENAME COLUMN tracker_issue_key TO jira_issue_key;
    END IF;

    IF EXISTS (
        SELECT 1 FROM information_schema.columns
        WHERE table_name = 'remediation_assignments'
          AND column_name = 'tracker_issue_url'
    ) AND NOT EXISTS (
        SELECT 1 FROM information_schema.columns
        WHERE table_name = 'remediation_assignments'
          AND column_name = 'jira_issue_url'
    ) THEN
        ALTER TABLE remediation_assignments
            RENAME COLUMN tracker_issue_url TO jira_issue_url;
    END IF;

    -- tracker_type is new in Sprint 4, drop it.
    IF EXISTS (
        SELECT 1 FROM information_schema.columns
        WHERE table_name = 'remediation_assignments'
          AND column_name = 'tracker_type'
    ) THEN
        ALTER TABLE remediation_assignments
            DROP COLUMN tracker_type;
    END IF;
END $$;

DROP TABLE IF EXISTS remediation_assignments CASCADE;
DROP TABLE IF EXISTS sla_policies CASCADE;
DROP TABLE IF EXISTS vulnerability_snapshots CASCADE;

COMMIT;
