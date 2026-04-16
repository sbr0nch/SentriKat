"""Baseline: stamp existing schema as Alembic-managed.

This is a no-op migration that marks the starting point for Alembic.
All tables, columns, indexes, and constraints that exist in the DB before
this revision are considered part of the baseline.

For a FRESH install: db.create_all() creates all tables, then
    flask db stamp head
marks the DB as up-to-date.

For an EXISTING install (already has all tables):
    flask db stamp head
marks the DB as up-to-date without running any DDL.

Revision ID: 0001_baseline
Revises: None
Create Date: 2026-04-16
"""
from alembic import op
import sqlalchemy as sa

# revision identifiers, used by Alembic.
revision = '0001_baseline'
down_revision = None
branch_labels = None
depends_on = None


def upgrade():
    # Baseline: all tables already exist via db.create_all() or manual SQL.
    # This revision is stamped, not executed.
    pass


def downgrade():
    # Cannot downgrade from baseline — this would mean dropping everything.
    raise RuntimeError("Cannot downgrade past the baseline revision.")
