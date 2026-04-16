# SentriKat Database Migrations

## Alembic / Flask-Migrate

This project uses Flask-Migrate (Alembic) for schema migrations.

### Quick reference

```bash
# Generate a new migration after changing models
flask db migrate -m "add foo column to bars"

# Apply pending migrations
flask db upgrade

# Rollback one revision
flask db downgrade -1

# Show current revision
flask db current

# Show migration history
flask db history
```

### How it works

- On first startup, `db.create_all()` creates all tables and the Alembic
  version table is stamped at `head` automatically.
- On existing databases, the legacy `_apply_schema_migrations()` function
  still runs for backward compatibility. The Alembic version is stamped
  once (idempotent).
- New schema changes should be added as Alembic revisions, **not** as
  entries in the `_apply_schema_migrations()` tuple.

### Legacy SQL migrations

The `sprint4_sprint5/` and `sprint6_hardening/` directories contain manual
SQL scripts from before Alembic was initialized. They are kept for
reference but are no longer the primary migration mechanism.
