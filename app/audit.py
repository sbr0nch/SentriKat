"""
Database-backed audit trail for SentriKat.

Logs security-relevant actions to both the audit_log table and the file-based
audit logger (from logging_config).  Import and call ``log_audit`` wherever an
auditable action takes place.
"""

from datetime import datetime
from flask import request, session, has_request_context
from app import db
from app.logging_config import log_audit_event
import json
import logging

logger = logging.getLogger(__name__)


def log_audit(action, resource_type, resource_id=None, resource_name=None,
              old_values=None, new_values=None, details=None, user=None):
    """Log an audit event to both database and audit.log file.

    Parameters are intentionally flexible - callers pass what they have.
    """
    from app.models import AuditLog

    # Resolve user info
    user_id = None
    username = None
    organization_id = None

    if user:
        user_id = user.id
        username = user.username
        organization_id = getattr(user, 'organization_id', None)
    elif has_request_context() and session.get('user_id'):
        user_id = session.get('user_id')
        username = session.get('username')
        organization_id = session.get('organization_id')

    # Request context info
    ip_address = None
    user_agent_str = None
    if has_request_context():
        ip_address = request.remote_addr
        user_agent_str = str(request.user_agent)[:500] if request.user_agent else None

    # Serialize dicts to JSON strings
    old_json = json.dumps(old_values) if old_values is not None else None
    new_json = json.dumps(new_values) if new_values is not None else None

    try:
        entry = AuditLog(
            timestamp=datetime.utcnow(),
            user_id=user_id,
            username=username,
            organization_id=organization_id,
            ip_address=ip_address,
            user_agent=user_agent_str,
            action=action,
            resource_type=resource_type,
            resource_id=str(resource_id) if resource_id is not None else None,
            resource_name=resource_name,
            old_values=old_json,
            new_values=new_json,
            details=details,
        )
        db.session.add(entry)
        # Use a nested savepoint so audit logging never breaks the caller's transaction
        db.session.flush()
    except Exception:
        logger.warning("Failed to write audit log to database", exc_info=True)
        try:
            db.session.rollback()
        except Exception:
            pass

    # Also write to the file-based audit log
    try:
        log_audit_event(
            action,
            resource_type,
            resource_id=resource_id,
            old_value=old_values,
            new_value=new_values,
            details=details,
        )
    except Exception:
        logger.debug("Failed to write file audit log", exc_info=True)
