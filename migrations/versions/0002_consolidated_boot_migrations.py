"""Consolidated boot-time migrations as Alembic revision (M-2).

The legacy ``_apply_schema_migrations`` in ``app/__init__.py`` runs an
idempotent ADD COLUMN sweep at every process start. That works for
single-container on-prem but races under multi-instance SaaS where
several replicas boot simultaneously.

This revision applies the same set of ADD COLUMN operations through
Alembic so that a one-shot deploy job (k8s Job, docker-compose service
with ``restart: "no"``) can run them once before any application
replica comes up. Application replicas should set
``SENTRIKAT_SKIP_BOOT_MIGRATIONS=1`` so they don't try to ALTER the
tables themselves.

Each operation is guarded by an existence check so this revision is
also safe to run against a database that was previously upgraded by
the boot-time path.

Revision ID: 0002_consolidated_boot_migrations
Revises: 0001_baseline
Create Date: 2026-04-17
"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = '0002_consolidated_boot_migrations'
down_revision = '0001_baseline'
branch_labels = None
depends_on = None


# (table_name, column_name, sqlite_def, postgres_def)
# Mirrors the MIGRATIONS list in app/__init__.py:_apply_schema_migrations.
COLUMN_ADDITIONS = [
    ('vulnerability_matches', 'first_alerted_at', 'DATETIME', 'TIMESTAMP'),
    ('agent_api_keys', 'auto_approve', 'BOOLEAN DEFAULT 0', 'BOOLEAN DEFAULT FALSE'),
    ('inventory_jobs', 'api_key_id', 'INTEGER', 'INTEGER'),
    ('users', 'totp_required', 'BOOLEAN DEFAULT 0', 'BOOLEAN DEFAULT FALSE'),
    ('vulnerability_matches', 'auto_acknowledged', 'BOOLEAN DEFAULT 0', 'BOOLEAN DEFAULT FALSE'),
    ('vulnerability_matches', 'resolution_reason', 'VARCHAR(50)', 'VARCHAR(50)'),
    ('vulnerability_matches', 'acknowledged_at', 'DATETIME', 'TIMESTAMP'),
    ('vulnerabilities', 'epss_score', 'REAL', 'DOUBLE PRECISION'),
    ('vulnerabilities', 'epss_percentile', 'REAL', 'DOUBLE PRECISION'),
    ('vulnerabilities', 'epss_fetched_at', 'DATETIME', 'TIMESTAMP'),
    ('assets', 'pending_scan', 'BOOLEAN DEFAULT 0', 'BOOLEAN DEFAULT FALSE'),
    ('assets', 'scan_interval_override', 'INTEGER', 'INTEGER'),
    ('assets', 'pending_scan_requested_at', 'DATETIME', 'TIMESTAMP'),
    ('assets', 'pending_scan_requested_by', 'VARCHAR(100)', 'VARCHAR(100)'),
    ('product_installations', 'distro_package_version', 'VARCHAR(200)', 'VARCHAR(200)'),
    ('assets', 'installed_kbs', 'TEXT', 'TEXT'),
    ('vendor_fix_overrides', 'fix_type', "VARCHAR(50) DEFAULT 'backport_patch'", "VARCHAR(50) DEFAULT 'backport_patch'"),
    ('vendor_fix_overrides', 'vendor_advisory_url', 'TEXT', 'TEXT'),
    ('vendor_fix_overrides', 'vendor_advisory_id', 'VARCHAR(100)', 'VARCHAR(100)'),
    ('vendor_fix_overrides', 'patch_identifier', 'VARCHAR(255)', 'VARCHAR(255)'),
    ('vendor_fix_overrides', 'notes', 'TEXT', 'TEXT'),
    ('vendor_fix_overrides', 'approved_by', 'INTEGER', 'INTEGER'),
    ('vendor_fix_overrides', 'approved_at', 'DATETIME', 'TIMESTAMP'),
    ('vendor_fix_overrides', 'status', "VARCHAR(20) DEFAULT 'approved'", "VARCHAR(20) DEFAULT 'approved'"),
    ('vendor_fix_overrides', 'confidence', "VARCHAR(20) DEFAULT 'medium'", "VARCHAR(20) DEFAULT 'medium'"),
    ('vendor_fix_overrides', 'confidence_reason', 'VARCHAR(255)', 'VARCHAR(255)'),
    ('vulnerability_matches', 'vendor_fix_confidence', 'VARCHAR(20)', 'VARCHAR(20)'),
    ('products', 'source', "VARCHAR(20) DEFAULT 'manual'", "VARCHAR(20) DEFAULT 'manual'"),
    ('products', 'approval_status', "VARCHAR(20) DEFAULT 'approved'", "VARCHAR(20) DEFAULT 'approved'"),
    ('products', 'pending_since', 'DATETIME', 'TIMESTAMP'),
    ('products', 'reviewed_by', 'INTEGER', 'INTEGER'),
    ('products', 'reviewed_at', 'DATETIME', 'TIMESTAMP'),
    ('products', 'rejection_reason', 'VARCHAR(500)', 'VARCHAR(500)'),
    ('products', 'last_agent_report', 'DATETIME', 'TIMESTAMP'),
    ('products', 'auto_disabled', 'BOOLEAN DEFAULT 0', 'BOOLEAN DEFAULT FALSE'),
    ('agent_licenses', 'server_count', 'INTEGER DEFAULT 0', 'INTEGER DEFAULT 0'),
    ('agent_licenses', 'client_count', 'INTEGER DEFAULT 0', 'INTEGER DEFAULT 0'),
    ('agent_licenses', 'peak_servers', 'INTEGER DEFAULT 0', 'INTEGER DEFAULT 0'),
    ('agent_licenses', 'peak_clients', 'INTEGER DEFAULT 0', 'INTEGER DEFAULT 0'),
    ('assets', 'pending_update', 'BOOLEAN DEFAULT 0', 'BOOLEAN DEFAULT FALSE'),
    ('assets', 'pending_update_requested_at', 'DATETIME', 'TIMESTAMP'),
    ('assets', 'pending_update_requested_by', 'VARCHAR(100)', 'VARCHAR(100)'),
    ('inventory_jobs', 'retry_count', 'INTEGER DEFAULT 0', 'INTEGER DEFAULT 0'),
    ('vulnerabilities', 'cvss_source', 'VARCHAR(30)', 'VARCHAR(30)'),
    ('vulnerabilities', 'source', "VARCHAR(20) DEFAULT 'cisa_kev'", "VARCHAR(20) DEFAULT 'cisa_kev'"),
    ('vulnerabilities', 'nvd_status', 'VARCHAR(50)', 'VARCHAR(50)'),
    ('vulnerabilities', 'is_actively_exploited', 'BOOLEAN DEFAULT 0', 'BOOLEAN DEFAULT FALSE'),
    ('agent_api_keys', 'encrypted_key', 'TEXT', 'TEXT'),
    ('agent_api_keys', 'key_type', "VARCHAR(20) DEFAULT 'server'", "VARCHAR(20) DEFAULT 'server'"),
    ('assets', 'reported_by_key_type', 'VARCHAR(20)', 'VARCHAR(20)'),
    ('products', 'source_key_type', 'VARCHAR(20)', 'VARCHAR(20)'),
    ('products', 'source_type', "VARCHAR(30) DEFAULT 'os_package'", "VARCHAR(30) DEFAULT 'os_package'"),
    ('products', 'ecosystem', 'VARCHAR(30)', 'VARCHAR(30)'),
    ('agent_api_keys', 'scan_os_packages', 'BOOLEAN DEFAULT 1', 'BOOLEAN DEFAULT TRUE'),
    ('agent_api_keys', 'scan_extensions', 'BOOLEAN DEFAULT 0', 'BOOLEAN DEFAULT FALSE'),
    ('agent_api_keys', 'scan_dependencies', 'BOOLEAN DEFAULT 0', 'BOOLEAN DEFAULT FALSE'),
    ('product_installations', 'project_path', 'VARCHAR(500)', 'VARCHAR(500)'),
    ('product_installations', 'is_direct_dependency', 'BOOLEAN', 'BOOLEAN'),
    ('import_queue', 'source_type', "VARCHAR(30) DEFAULT 'os_package'", "VARCHAR(30) DEFAULT 'os_package'"),
    ('import_queue', 'ecosystem', 'VARCHAR(30)', 'VARCHAR(30)'),
    ('container_vulnerabilities', 'snoozed_until', 'DATETIME', 'TIMESTAMP'),
    ('container_vulnerabilities', 'first_alerted_at', 'DATETIME', 'TIMESTAMP'),
    ('dependency_scan_results', 'snoozed_until', 'DATETIME', 'TIMESTAMP'),
    ('dependency_scan_results', 'first_alerted_at', 'DATETIME', 'TIMESTAMP'),
    ('users', 'password_reset_token', 'VARCHAR(100)', 'VARCHAR(100)'),
    ('users', 'password_reset_expires', 'DATETIME', 'TIMESTAMP'),
    ('system_settings', 'organization_id', 'INTEGER', 'INTEGER REFERENCES organizations(id) ON DELETE CASCADE'),
    ('organizations', 'use_managed_email', 'BOOLEAN DEFAULT 1', 'BOOLEAN DEFAULT TRUE'),
    ('organizations', 'email_reply_to', 'VARCHAR(255)', 'VARCHAR(255)'),
    ('vulnerabilities', 'exploit_public', 'BOOLEAN DEFAULT 0', 'BOOLEAN DEFAULT FALSE'),
    ('vulnerabilities', 'exploit_source', 'VARCHAR(100)', 'VARCHAR(100)'),
    ('vulnerabilities', 'exploit_url', 'VARCHAR(500)', 'VARCHAR(500)'),
    ('subscriptions', 'addons', 'TEXT', 'TEXT'),
]


def _existing_columns(bind, table_name):
    """Return the set of columns currently present on ``table_name``."""
    if bind.dialect.name == 'sqlite':
        rows = bind.execute(sa.text(f"PRAGMA table_info({table_name})")).fetchall()
        return {r[1] for r in rows}
    rows = bind.execute(
        sa.text(
            "SELECT column_name FROM information_schema.columns "
            "WHERE table_name = :tname"
        ),
        {'tname': table_name},
    ).fetchall()
    return {r[0] for r in rows}


def _table_exists(bind, table_name):
    insp = sa.inspect(bind)
    return table_name in insp.get_table_names()


def upgrade():
    bind = op.get_bind()
    is_sqlite = bind.dialect.name == 'sqlite'
    for table, column, sqlite_def, pg_def in COLUMN_ADDITIONS:
        if not _table_exists(bind, table):
            # Some tables (vendor_fix_overrides, container_vulnerabilities, etc.)
            # are created lazily by db.create_all() — skip if not present yet.
            continue
        if column in _existing_columns(bind, table):
            continue
        col_def = sqlite_def if is_sqlite else pg_def
        op.execute(f"ALTER TABLE {table} ADD COLUMN {column} {col_def}")


def downgrade():
    # Schema rollback is not supported for this consolidation revision —
    # bringing the database back to a pre-MIGRATIONS state would lose
    # data. If a rollback is genuinely required, restore from backup.
    pass
