# Sprint 4 + Sprint 5 schema migration

Manual SQL migration for the schema changes introduced by Sprint 4 and
Sprint 5 (2026-04). This directory exists because the project does not
yet have a Flask-Migrate / Alembic tree initialized; future sprints
should migrate to proper Alembic revisions and these SQL scripts will
be kept for historical reference.

## What it does

- Creates 5 new tables:
  - `vulnerability_snapshots` (Sprint 5 — trending)
  - `sla_policies` (Sprint 4)
  - `remediation_assignments` (Sprint 3/4)
  - `risk_exceptions` (Sprint 4)
  - `product_aliases` (Sprint 4)
- Creates 6 composite indexes + 1 unique constraint used by the new
  list endpoints for acceptable performance on large orgs.
- Renames `jira_issue_key` / `jira_issue_url` to
  `tracker_issue_key` / `tracker_issue_url` on `remediation_assignments`
  (backward-compatible with the Sprint 3 column names; uses an
  idempotent `DO $$ ... $$` guard).
- Adds `tracker_type` column to `remediation_assignments` if missing.

Everything is wrapped in a single transaction (`BEGIN` / `COMMIT`)
and uses `CREATE TABLE IF NOT EXISTS` / `CREATE INDEX IF NOT EXISTS`
so the script is safe to re-run.

## How to apply (PostgreSQL production)

Take a backup first:

```bash
docker compose exec -T db pg_dump -U $(grep POSTGRES_USER .env | cut -d= -f2) \
  $(grep POSTGRES_DB .env | cut -d= -f2) > ~/sentrikat-backup-$(date +%Y%m%d-%H%M).sql
```

Apply the upgrade:

```bash
docker compose exec -T db psql \
  -U $(grep POSTGRES_USER .env | cut -d= -f2) \
  $(grep POSTGRES_DB .env | cut -d= -f2) \
  < migrations/sprint4_sprint5/upgrade.sql
```

Verify the new tables + indexes exist:

```bash
docker compose exec db psql \
  -U $(grep POSTGRES_USER .env | cut -d= -f2) \
  $(grep POSTGRES_DB .env | cut -d= -f2) \
  -c "\dt vulnerability_snapshots sla_policies remediation_assignments risk_exceptions product_aliases"
```

## How to roll back

Only after a failed deploy, and only with a verified backup in hand:

```bash
docker compose exec -T db psql \
  -U $(grep POSTGRES_USER .env | cut -d= -f2) \
  $(grep POSTGRES_DB .env | cut -d= -f2) \
  < migrations/sprint4_sprint5/rollback.sql
```

This drops the five new tables and their data, and (if still needed)
renames `tracker_issue_*` back to `jira_issue_*`. **Irreversible** with
respect to data.

## Why not Alembic?

Flask-Migrate 4.0.5 is already in `requirements.txt` but no `migrations/`
tree has ever been initialized for this project. Setting it up correctly
requires:

1. `flask db init` — creates env.py + alembic.ini + versions/
2. `flask db stamp <baseline>` on each running instance to mark it at
   the pre-Sprint-4 schema
3. `flask db migrate` to auto-generate the revision
4. `flask db upgrade` to apply

Doing that safely on a live production instance is risky without a
staging environment. The manual SQL script here bypasses that risk for
the Sprint 4+5 deploy. The next sprint should initialize Alembic
properly — see `docs/business/99_TODO_BEFORE_LAUNCH.md`.
