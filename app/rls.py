"""
PostgreSQL Row-Level Security (RLS) integration for SQLAlchemy.

Sets the `app.current_org_id` session variable on each database connection
so that PostgreSQL RLS policies can filter by organization.

Enable with: RLS_ENABLED=true
Apply policies first: psql -f scripts/enable_rls.sql

Usage:
    from app.rls import setup_rls
    setup_rls(app, db)
"""

import os
import logging
from sqlalchemy import event, text

logger = logging.getLogger(__name__)


def setup_rls(app, db):
    """Install SQLAlchemy connection event listener for RLS."""
    if os.environ.get('RLS_ENABLED', 'false').lower() != 'true':
        return

    logger.info("PostgreSQL Row-Level Security (RLS) integration enabled")

    @event.listens_for(db.engine, 'checkout')
    def set_rls_org_id(dbapi_connection, connection_record, connection_proxy):
        """Set app.current_org_id on connection checkout from pool."""
        try:
            from flask import session, has_request_context
            if has_request_context():
                org_id = session.get('organization_id', '0')
                # Super admins get org_id=0 (bypasses RLS)
                role = session.get('role', '')
                if role == 'super_admin':
                    org_id = '0'
            else:
                # Background jobs bypass RLS
                org_id = '0'

            cursor = dbapi_connection.cursor()
            cursor.execute("SET app.current_org_id = %s", (str(org_id),))
            cursor.close()
        except Exception:
            # Don't break connection checkout on RLS errors
            pass
