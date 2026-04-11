"""
Remediation Assignment & SLA Policy API endpoints.

Sprint 3: Provides CRUD for assigning vulnerabilities to owners
and defining SLA policies per severity level.
"""

from flask import Blueprint, request, jsonify, session
from app import db, csrf
from app.auth import login_required, org_admin_required
from app.models import RemediationAssignment, SlaPolicy, Organization, VulnerabilityMatch, Product
from app.saas import is_saas_mode
from datetime import datetime, date
import logging

logger = logging.getLogger(__name__)

bp = Blueprint('remediation', __name__)
csrf.exempt(bp)


# ============================================================================
# Remediation Assignments
# ============================================================================

@bp.route('/api/remediation/assignments', methods=['GET'])
@login_required
def list_assignments():
    """List remediation assignments for the current organization."""
    org_id = session.get('organization_id')
    if not org_id:
        return jsonify({'error': 'Organization required'}), 400

    status_filter = request.args.get('status', '').strip().lower()
    assigned_to = request.args.get('assigned_to', '').strip()

    query = RemediationAssignment.query.filter_by(organization_id=org_id)

    if status_filter:
        query = query.filter_by(status=status_filter)
    if assigned_to:
        query = query.filter_by(assigned_to=assigned_to)

    query = query.order_by(RemediationAssignment.due_date.asc().nullslast())
    assignments = query.limit(100).all()

    # Count overdue
    overdue = sum(1 for a in assignments if a.due_date and a.due_date < date.today() and a.status in ('open', 'in_progress'))

    return jsonify({
        'assignments': [a.to_dict() for a in assignments],
        'total': len(assignments),
        'overdue': overdue,
    })


@bp.route('/api/remediation/assignments', methods=['POST'])
@login_required
@org_admin_required
def create_assignment():
    """Create a new remediation assignment."""
    org_id = session.get('organization_id')
    if not org_id:
        return jsonify({'error': 'Organization required'}), 400

    data = request.get_json()
    if not data or not data.get('assigned_to'):
        return jsonify({'error': 'assigned_to is required'}), 400

    user_id = session.get('user_id')
    from app.models import User
    user = User.query.get(user_id)
    assigned_by = user.username if user else 'unknown'

    due_date = None
    if data.get('due_date'):
        try:
            due_date = datetime.strptime(data['due_date'], '%Y-%m-%d').date()
        except ValueError:
            return jsonify({'error': 'Invalid due_date format (use YYYY-MM-DD)'}), 400

    # Auto-set due date from SLA policy if not specified
    if not due_date and data.get('severity'):
        policy = SlaPolicy.query.filter_by(
            organization_id=org_id,
            severity=data['severity'].lower(),
            enabled=True
        ).first()
        if policy:
            from datetime import timedelta
            due_date = date.today() + timedelta(days=policy.max_days)

    # Validate product_id belongs to this organization (prevent cross-tenant leak)
    if data.get('product_id'):
        from app.models import product_organizations
        from sqlalchemy import select
        owns_product = db.session.execute(
            select(product_organizations.c.product_id).where(
                product_organizations.c.organization_id == org_id,
                product_organizations.c.product_id == data['product_id']
            )
        ).first()
        if not owns_product:
            return jsonify({'error': 'Product not found in your organization'}), 403

    # Validate match_id belongs to a product in this organization
    if data.get('match_id'):
        from app.models import product_organizations
        from sqlalchemy import select
        match = VulnerabilityMatch.query.get(data['match_id'])
        if not match:
            return jsonify({'error': 'Match not found'}), 404
        owns_match = db.session.execute(
            select(product_organizations.c.product_id).where(
                product_organizations.c.organization_id == org_id,
                product_organizations.c.product_id == match.product_id
            )
        ).first()
        if not owns_match:
            return jsonify({'error': 'Match does not belong to your organization'}), 403

    assignment = RemediationAssignment(
        organization_id=org_id,
        match_id=data.get('match_id'),
        product_id=data.get('product_id'),
        cve_id=data.get('cve_id'),
        assigned_to=data['assigned_to'],
        assigned_by=assigned_by,
        due_date=due_date,
        priority=data.get('priority', 'medium'),
        notes=data.get('notes'),
    )
    db.session.add(assignment)
    db.session.commit()

    return jsonify(assignment.to_dict()), 201


@bp.route('/api/remediation/assignments/<int:assignment_id>', methods=['PUT'])
@login_required
@org_admin_required
def update_assignment(assignment_id):
    """Update a remediation assignment (change status, add notes, etc)."""
    org_id = session.get('organization_id')
    assignment = RemediationAssignment.query.filter_by(
        id=assignment_id, organization_id=org_id
    ).first_or_404()

    data = request.get_json()
    if not data:
        return jsonify({'error': 'No data provided'}), 400

    if 'status' in data:
        old_status = assignment.status
        assignment.status = data['status']
        if data['status'] in ('resolved', 'accepted_risk') and old_status not in ('resolved', 'accepted_risk'):
            assignment.resolved_at = datetime.utcnow()

    if 'assigned_to' in data:
        assignment.assigned_to = data['assigned_to']
    if 'due_date' in data:
        if data['due_date']:
            try:
                assignment.due_date = datetime.strptime(data['due_date'], '%Y-%m-%d').date()
            except ValueError:
                return jsonify({'error': 'Invalid due_date format'}), 400
        else:
            assignment.due_date = None
    if 'priority' in data:
        assignment.priority = data['priority']
    if 'notes' in data:
        assignment.notes = data['notes']
    if 'resolution_notes' in data:
        assignment.resolution_notes = data['resolution_notes']

    db.session.commit()
    return jsonify(assignment.to_dict())


@bp.route('/api/remediation/assignments/<int:assignment_id>', methods=['DELETE'])
@login_required
@org_admin_required
def delete_assignment(assignment_id):
    """Delete a remediation assignment."""
    org_id = session.get('organization_id')
    assignment = RemediationAssignment.query.filter_by(
        id=assignment_id, organization_id=org_id
    ).first_or_404()

    db.session.delete(assignment)
    db.session.commit()
    return jsonify({'status': 'deleted'})


# ============================================================================
# SLA Policies
# ============================================================================

@bp.route('/api/sla/policies', methods=['GET'])
@login_required
def list_sla_policies():
    """List SLA policies for the current organization."""
    org_id = session.get('organization_id')
    if not org_id:
        return jsonify({'error': 'Organization required'}), 400

    policies = SlaPolicy.query.filter_by(organization_id=org_id).order_by(
        db.case(
            (SlaPolicy.severity == 'critical', 1),
            (SlaPolicy.severity == 'high', 2),
            (SlaPolicy.severity == 'medium', 3),
            (SlaPolicy.severity == 'low', 4),
        )
    ).all()

    return jsonify({'policies': [p.to_dict() for p in policies]})


@bp.route('/api/sla/policies', methods=['POST'])
@login_required
@org_admin_required
def create_sla_policy():
    """Create a new SLA policy (org_admin only)."""
    org_id = session.get('organization_id')
    if not org_id:
        return jsonify({'error': 'Organization required'}), 400

    data = request.get_json()
    if not data or not data.get('severity') or not data.get('max_days'):
        return jsonify({'error': 'severity and max_days are required'}), 400

    severity = data['severity'].lower()
    if severity not in ('critical', 'high', 'medium', 'low'):
        return jsonify({'error': 'severity must be critical, high, medium, or low'}), 400

    # Check if policy already exists for this severity
    existing = SlaPolicy.query.filter_by(organization_id=org_id, severity=severity).first()
    if existing:
        return jsonify({'error': f'SLA policy for {severity} already exists. Use PUT to update.'}), 409

    policy = SlaPolicy(
        organization_id=org_id,
        name=data.get('name', f'{severity.title()} CVE SLA'),
        severity=severity,
        max_days=int(data['max_days']),
        notify_on_breach=data.get('notify_on_breach', True),
        escalate_to=data.get('escalate_to'),
    )
    db.session.add(policy)
    db.session.commit()

    return jsonify(policy.to_dict()), 201


@bp.route('/api/sla/policies/<int:policy_id>', methods=['PUT'])
@login_required
@org_admin_required
def update_sla_policy(policy_id):
    """Update an SLA policy."""
    org_id = session.get('organization_id')
    policy = SlaPolicy.query.filter_by(id=policy_id, organization_id=org_id).first_or_404()

    data = request.get_json()
    if not data:
        return jsonify({'error': 'No data provided'}), 400

    if 'max_days' in data:
        policy.max_days = int(data['max_days'])
    if 'name' in data:
        policy.name = data['name']
    if 'enabled' in data:
        policy.enabled = bool(data['enabled'])
    if 'notify_on_breach' in data:
        policy.notify_on_breach = bool(data['notify_on_breach'])
    if 'escalate_to' in data:
        policy.escalate_to = data['escalate_to']

    db.session.commit()
    return jsonify(policy.to_dict())


@bp.route('/api/sla/policies/<int:policy_id>', methods=['DELETE'])
@login_required
@org_admin_required
def delete_sla_policy(policy_id):
    """Delete an SLA policy."""
    org_id = session.get('organization_id')
    policy = SlaPolicy.query.filter_by(id=policy_id, organization_id=org_id).first_or_404()

    db.session.delete(policy)
    db.session.commit()
    return jsonify({'status': 'deleted'})


# ============================================================================
# SLA Compliance Dashboard
# ============================================================================

@bp.route('/api/sla/compliance', methods=['GET'])
@login_required
def sla_compliance():
    """Get SLA compliance stats for the dashboard."""
    org_id = session.get('organization_id')
    if not org_id:
        return jsonify({'error': 'Organization required'}), 400

    policies = SlaPolicy.query.filter_by(organization_id=org_id, enabled=True).all()

    if not policies:
        return jsonify({
            'has_policies': False,
            'message': 'No SLA policies configured. Go to Settings > SLA Policies to set up.',
            'compliance': [],
        })

    compliance = []
    for policy in policies:
        # Count matches by severity that are within/outside SLA
        from sqlalchemy import func, select
        from app.models import Vulnerability, product_organizations

        # Get org product IDs
        org_product_ids = db.session.execute(
            select(product_organizations.c.product_id).where(
                product_organizations.c.organization_id == org_id
            )
        ).scalars().all()

        if not org_product_ids:
            continue

        # Count unacknowledged matches of this severity
        match_query = VulnerabilityMatch.query.join(
            Vulnerability
        ).filter(
            VulnerabilityMatch.product_id.in_(org_product_ids),
            VulnerabilityMatch.acknowledged == False,
            func.upper(Vulnerability.severity) == policy.severity.upper()
        )

        total = match_query.count()

        # Count overdue (created_at + max_days < today)
        from datetime import timedelta
        sla_deadline = datetime.utcnow() - timedelta(days=policy.max_days)
        overdue = match_query.filter(VulnerabilityMatch.created_at < sla_deadline).count()

        within_sla = total - overdue
        compliance_pct = (within_sla / total * 100) if total > 0 else 100

        compliance.append({
            'policy': policy.to_dict(),
            'total_matches': total,
            'within_sla': within_sla,
            'overdue': overdue,
            'compliance_percent': round(compliance_pct, 1),
        })

    return jsonify({
        'has_policies': True,
        'compliance': compliance,
    })
