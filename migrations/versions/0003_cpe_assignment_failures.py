"""F.5 — persistent CPE assignment failures table

[CVE-MATCHING-PIPELINE F.5] Adds `cpe_assignment_failures` so rejections
from `validate_cpe_assignment` are queryable via /admin/cpe-failures.
Previously the rejection surfaced only as a WARNING log line — invisible
operationally and impossible to filter/aggregate.

Revision ID: 0003_cpe_assignment_failures
Revises: 0002_consolidated_boot_migrations
Create Date: 2026-05-XX
"""
from alembic import op
import sqlalchemy as sa


revision = '0003_cpe_assignment_failures'
down_revision = '0002_consolidated_boot_migrations'
branch_labels = None
depends_on = None


def upgrade():
    op.create_table(
        'cpe_assignment_failures',
        sa.Column('id', sa.Integer(), primary_key=True),
        sa.Column('product_id', sa.Integer(),
                  sa.ForeignKey('products.id', ondelete='CASCADE'),
                  nullable=True, index=True),
        sa.Column('product_vendor', sa.String(200), nullable=True),
        sa.Column('product_name', sa.String(500), nullable=True),
        sa.Column('rejected_cpe_vendor', sa.String(200), nullable=False),
        sa.Column('rejected_cpe_product', sa.String(200), nullable=False),
        sa.Column('reason', sa.String(100), nullable=False,
                  server_default='word_overlap_validation_failed'),
        sa.Column('resolved_at', sa.DateTime(), nullable=True, index=True),
        sa.Column('resolved_by', sa.Integer(),
                  sa.ForeignKey('users.id', ondelete='SET NULL'),
                  nullable=True),
        sa.Column('resolution', sa.String(20), nullable=True),
        sa.Column('created_at', sa.DateTime(), nullable=False,
                  server_default=sa.text('CURRENT_TIMESTAMP'), index=True),
    )
    op.create_index(
        'idx_cpe_failures_unresolved_created',
        'cpe_assignment_failures',
        ['resolved_at', 'created_at'],
    )


def downgrade():
    op.drop_index('idx_cpe_failures_unresolved_created',
                  table_name='cpe_assignment_failures')
    op.drop_table('cpe_assignment_failures')
