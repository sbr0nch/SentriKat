"""
Audit Log API endpoints.

Provides paginated read access and CSV export of the audit trail.
All endpoints require admin privileges.
"""

from flask import Blueprint, request, jsonify, session, Response
from app import db, csrf
from app.auth import admin_required
from app.models import AuditLog
from datetime import datetime
import csv
import io
import logging

logger = logging.getLogger(__name__)

audit_bp = Blueprint('audit', __name__, url_prefix='/api/admin')
csrf.exempt(audit_bp)


@audit_bp.route('/audit-log', methods=['GET'])
@admin_required
def list_audit_log():
    """List audit events with filtering and pagination."""
    page = request.args.get('page', 1, type=int)
    per_page = min(request.args.get('per_page', 50, type=int), 200)

    query = AuditLog.query

    # Filters
    action = request.args.get('action')
    if action:
        query = query.filter(AuditLog.action == action.upper())

    resource_type = request.args.get('resource_type')
    if resource_type:
        query = query.filter(AuditLog.resource_type == resource_type)

    user_id = request.args.get('user_id', type=int)
    if user_id is not None:
        query = query.filter(AuditLog.user_id == user_id)

    date_from = request.args.get('date_from')
    if date_from:
        try:
            dt = datetime.fromisoformat(date_from)
            query = query.filter(AuditLog.timestamp >= dt)
        except ValueError:
            pass

    date_to = request.args.get('date_to')
    if date_to:
        try:
            dt = datetime.fromisoformat(date_to)
            query = query.filter(AuditLog.timestamp <= dt)
        except ValueError:
            pass

    search = request.args.get('search')
    if search:
        like = f'%{search}%'
        query = query.filter(
            db.or_(
                AuditLog.username.ilike(like),
                AuditLog.resource_name.ilike(like),
                AuditLog.resource_id.ilike(like),
                AuditLog.details.ilike(like),
                AuditLog.ip_address.ilike(like),
            )
        )

    query = query.order_by(AuditLog.timestamp.desc())
    pagination = query.paginate(page=page, per_page=per_page, error_out=False)

    return jsonify({
        'items': [item.to_dict() for item in pagination.items],
        'total': pagination.total,
        'page': pagination.page,
        'per_page': pagination.per_page,
        'pages': pagination.pages,
    })


@audit_bp.route('/audit-log/export', methods=['GET'])
@admin_required
def export_audit_log():
    """Export audit log as CSV with the same filters as the list endpoint."""
    query = AuditLog.query

    action = request.args.get('action')
    if action:
        query = query.filter(AuditLog.action == action.upper())

    resource_type = request.args.get('resource_type')
    if resource_type:
        query = query.filter(AuditLog.resource_type == resource_type)

    user_id = request.args.get('user_id', type=int)
    if user_id is not None:
        query = query.filter(AuditLog.user_id == user_id)

    date_from = request.args.get('date_from')
    if date_from:
        try:
            dt = datetime.fromisoformat(date_from)
            query = query.filter(AuditLog.timestamp >= dt)
        except ValueError:
            pass

    date_to = request.args.get('date_to')
    if date_to:
        try:
            dt = datetime.fromisoformat(date_to)
            query = query.filter(AuditLog.timestamp <= dt)
        except ValueError:
            pass

    search = request.args.get('search')
    if search:
        like = f'%{search}%'
        query = query.filter(
            db.or_(
                AuditLog.username.ilike(like),
                AuditLog.resource_name.ilike(like),
                AuditLog.resource_id.ilike(like),
                AuditLog.details.ilike(like),
                AuditLog.ip_address.ilike(like),
            )
        )

    query = query.order_by(AuditLog.timestamp.desc())

    # Cap export to 10 000 rows to avoid memory issues
    rows = query.limit(10000).all()

    buf = io.StringIO()
    writer = csv.writer(buf)
    writer.writerow([
        'timestamp', 'username', 'user_id', 'organization_id',
        'ip_address', 'action', 'resource_type', 'resource_id',
        'resource_name', 'old_values', 'new_values', 'details',
    ])
    for row in rows:
        writer.writerow([
            row.timestamp.isoformat() if row.timestamp else '',
            row.username or '',
            row.user_id or '',
            row.organization_id or '',
            row.ip_address or '',
            row.action or '',
            row.resource_type or '',
            row.resource_id or '',
            row.resource_name or '',
            row.old_values or '',
            row.new_values or '',
            row.details or '',
        ])

    output = buf.getvalue()
    buf.close()

    return Response(
        output,
        mimetype='text/csv',
        headers={'Content-Disposition': 'attachment; filename=audit_log.csv'},
    )
