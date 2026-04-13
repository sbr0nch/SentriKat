"""
Remediation Assignment, SLA Policy, Risk Exception & Product Alias API endpoints.

Sprint 3: Provides CRUD for assigning vulnerabilities to owners
and defining SLA policies per severity level.

Sprint 4: Enhanced pagination/sorting/search on assignments, Jira integration
on create, Risk Exception CRUD, Product Alias CRUD.
"""

from flask import Blueprint, request, jsonify, session
from app import db, csrf
from app.auth import login_required, org_admin_required
from app.models import (
    RemediationAssignment, SlaPolicy, Organization, VulnerabilityMatch,
    Product, RiskException, ProductAlias,
)
from app.saas import is_saas_mode
from datetime import datetime, date
from math import ceil
import logging

logger = logging.getLogger(__name__)

bp = Blueprint('remediation', __name__)
csrf.exempt(bp)


# ============================================================================
# Helpers
# ============================================================================

def _org_id_or_400():
    """Return the current org_id from session, or None (caller should 400)."""
    return session.get('organization_id')


def _validate_product_ownership(org_id, product_id):
    """Return True if product_id belongs to the org, False otherwise."""
    from app.models import product_organizations
    from sqlalchemy import select
    row = db.session.execute(
        select(product_organizations.c.product_id).where(
            product_organizations.c.organization_id == org_id,
            product_organizations.c.product_id == product_id,
        )
    ).first()
    return row is not None


def _validate_match_ownership(org_id, match_id):
    """
    Return the VulnerabilityMatch if match_id belongs to a product in the org.
    Returns (match, error_response) -- if error_response is not None, return it.
    """
    from app.models import product_organizations
    from sqlalchemy import select
    match = VulnerabilityMatch.query.get(match_id)
    if not match:
        return None, (jsonify({'error': 'Match not found'}), 404)
    owns = db.session.execute(
        select(product_organizations.c.product_id).where(
            product_organizations.c.organization_id == org_id,
            product_organizations.c.product_id == match.product_id,
        )
    ).first()
    if not owns:
        return None, (jsonify({'error': 'Match does not belong to your organization'}), 403)
    return match, None


# ============================================================================
# Remediation Assignments
# ============================================================================

@bp.route('/api/remediation/assignments', methods=['GET'])
@login_required
def list_assignments():
    """List remediation assignments for the current organization with pagination,
    filtering, sorting, and search."""
    org_id = _org_id_or_400()
    if not org_id:
        return jsonify({'error': 'Organization required'}), 400

    # -- Pagination --
    try:
        page = max(1, int(request.args.get('page', 1)))
    except (ValueError, TypeError):
        page = 1
    try:
        per_page = min(100, max(1, int(request.args.get('per_page', 25))))
    except (ValueError, TypeError):
        per_page = 25

    # -- Base query with eager-loaded relationships --
    from sqlalchemy.orm import joinedload
    query = RemediationAssignment.query.options(
        joinedload(RemediationAssignment.product),
        joinedload(RemediationAssignment.match),
    ).filter_by(organization_id=org_id)

    # -- Filters --
    status_filter = request.args.get('status', '').strip().lower()
    assigned_to = request.args.get('assigned_to', '').strip()
    priority_filter = request.args.get('priority', '').strip().lower()

    if status_filter:
        query = query.filter_by(status=status_filter)
    if assigned_to:
        query = query.filter_by(assigned_to=assigned_to)
    if priority_filter:
        query = query.filter_by(priority=priority_filter)

    # -- Search (assigned_to, notes, cve_id) --
    search = request.args.get('search', '').strip()
    if search:
        like_pattern = f'%{search}%'
        query = query.filter(
            db.or_(
                RemediationAssignment.assigned_to.ilike(like_pattern),
                RemediationAssignment.notes.ilike(like_pattern),
                RemediationAssignment.cve_id.ilike(like_pattern),
            )
        )

    # -- Sorting --
    sort_field = request.args.get('sort', 'due_date').strip().lower()
    order = request.args.get('order', 'asc').strip().lower()

    sort_map = {
        'due_date': RemediationAssignment.due_date,
        'created_at': RemediationAssignment.created_at,
        'priority': db.case(
            (RemediationAssignment.priority == 'critical', 1),
            (RemediationAssignment.priority == 'high', 2),
            (RemediationAssignment.priority == 'medium', 3),
            (RemediationAssignment.priority == 'low', 4),
            else_=5,
        ),
        'status': db.case(
            (RemediationAssignment.status == 'open', 1),
            (RemediationAssignment.status == 'in_progress', 2),
            (RemediationAssignment.status == 'resolved', 3),
            (RemediationAssignment.status == 'accepted_risk', 4),
            else_=5,
        ),
    }

    sort_col = sort_map.get(sort_field, RemediationAssignment.due_date)

    if order == 'desc':
        query = query.order_by(db.desc(sort_col).nullslast())
    else:
        query = query.order_by(db.asc(sort_col).nullslast())

    # -- Paginate --
    total = query.count()
    pages = ceil(total / per_page) if per_page else 1
    assignments = query.offset((page - 1) * per_page).limit(per_page).all()

    # Count overdue across all (not just this page)
    overdue_query = RemediationAssignment.query.filter_by(organization_id=org_id).filter(
        RemediationAssignment.due_date < date.today(),
        RemediationAssignment.status.in_(['open', 'in_progress']),
    )
    overdue = overdue_query.count()

    # Build enriched response
    results = []
    for a in assignments:
        d = a.to_dict()
        # Include product info if available
        if a.product:
            d['product_name'] = f"{a.product.vendor} {a.product.product_name}"
            d['product_version'] = a.product.version
        else:
            d['product_name'] = None
            d['product_version'] = None
        # Include CVE info from match if available
        if a.match and hasattr(a.match, 'vulnerability') and a.match.vulnerability:
            vuln = a.match.vulnerability
            d['cve_info'] = {
                'cve_id': vuln.cve_id,
                'severity': vuln.severity,
                'cvss_score': vuln.cvss_score,
            }
        else:
            d['cve_info'] = None
        results.append(d)

    return jsonify({
        'assignments': results,
        'total': total,
        'page': page,
        'per_page': per_page,
        'pages': pages,
        'overdue': overdue,
    })


@bp.route('/api/remediation/assignments/<int:assignment_id>', methods=['GET'])
@login_required
def get_assignment(assignment_id):
    """Get a single remediation assignment with full detail."""
    org_id = _org_id_or_400()
    if not org_id:
        return jsonify({'error': 'Organization required'}), 400

    from sqlalchemy.orm import joinedload
    assignment = RemediationAssignment.query.options(
        joinedload(RemediationAssignment.product),
        joinedload(RemediationAssignment.match),
    ).filter_by(id=assignment_id, organization_id=org_id).first_or_404()

    d = assignment.to_dict()

    # Include product info
    if assignment.product:
        d['product_name'] = f"{assignment.product.vendor} {assignment.product.product_name}"
        d['product_version'] = assignment.product.version
        d['product_info'] = {
            'id': assignment.product.id,
            'vendor': assignment.product.vendor,
            'product_name': assignment.product.product_name,
            'version': assignment.product.version,
            'criticality': assignment.product.criticality,
        }
    else:
        d['product_name'] = None
        d['product_version'] = None
        d['product_info'] = None

    # Include CVE info from match
    if assignment.match and hasattr(assignment.match, 'vulnerability') and assignment.match.vulnerability:
        vuln = assignment.match.vulnerability
        d['cve_info'] = {
            'cve_id': vuln.cve_id,
            'severity': vuln.severity,
            'cvss_score': vuln.cvss_score,
            'vulnerability_name': getattr(vuln, 'vulnerability_name', None),
        }
    else:
        d['cve_info'] = None

    return jsonify(d)


@bp.route('/api/remediation/assignments', methods=['POST'])
@login_required
@org_admin_required
def create_assignment():
    """Create a new remediation assignment. Optionally create a Jira/issue-tracker ticket."""
    org_id = _org_id_or_400()
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
    product = None
    if data.get('product_id'):
        if not _validate_product_ownership(org_id, data['product_id']):
            return jsonify({'error': 'Product not found in your organization'}), 403
        product = Product.query.get(data['product_id'])

    # Validate match_id belongs to a product in this organization
    match_obj = None
    if data.get('match_id'):
        match_obj, err = _validate_match_ownership(org_id, data['match_id'])
        if err:
            return err

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

    # -- Jira / issue tracker integration --
    warning = None
    if data.get('create_jira_ticket'):
        try:
            from app.issue_trackers import create_vulnerability_issue, get_issue_tracker

            # Build product name for summary
            product_name = 'Unknown Product'
            if product:
                product_name = f"{product.vendor} {product.product_name}"
            elif assignment.product_id:
                p = Product.query.get(assignment.product_id)
                if p:
                    product_name = f"{p.vendor} {p.product_name}"

            # Count CVEs associated with this assignment
            cve_count = 1
            if assignment.cve_id:
                cve_count = 1
            elif match_obj:
                cve_count = 1
            elif product:
                # Product-level assignment -- count active matches
                from app.models import product_organizations
                cve_count = VulnerabilityMatch.query.filter_by(
                    product_id=product.id,
                    acknowledged=False,
                ).count() or 1

            custom_summary = f"[Assignment] Remediate {product_name} - {cve_count} CVEs"

            # Build description
            desc_lines = [
                "## Remediation Assignment",
                f"**Assigned To:** {assignment.assigned_to}",
                f"**Priority:** {assignment.priority}",
                f"**Due Date:** {assignment.due_date.isoformat() if assignment.due_date else 'Not set'}",
            ]
            if assignment.notes:
                desc_lines.append(f"**Notes:** {assignment.notes}")
            if assignment.cve_id:
                desc_lines.append(f"**CVE:** {assignment.cve_id}")
            desc_lines.append(f"\n*Created by {assigned_by} via SentriKat*")
            custom_description = '\n'.join(desc_lines)

            # Determine vulnerability_id for the tracker call
            vulnerability_id = None
            if match_obj and hasattr(match_obj, 'vulnerability_id'):
                vulnerability_id = match_obj.vulnerability_id
            elif assignment.cve_id:
                # Try to look up the vulnerability by CVE ID
                from app.models import Vulnerability
                vuln = Vulnerability.query.filter_by(cve_id=assignment.cve_id).first()
                if vuln:
                    vulnerability_id = vuln.id

            tracker_type = data.get('tracker_type')

            if vulnerability_id:
                success, message, issue_key, issue_url = create_vulnerability_issue(
                    vulnerability_id=vulnerability_id,
                    product_id=assignment.product_id,
                    custom_summary=custom_summary,
                    custom_description=custom_description,
                    tracker_type=tracker_type,
                )
            else:
                # No specific vulnerability -- try to create via tracker directly
                tracker = get_issue_tracker(tracker_type)
                if tracker:
                    success, message, issue_key, issue_url = tracker.create_issue(
                        summary=custom_summary,
                        description=custom_description,
                    )
                else:
                    success = False
                    message = "Issue tracker not configured or disabled"
                    issue_key = None
                    issue_url = None

            if success and issue_key:
                assignment.jira_issue_key = issue_key
                assignment.jira_issue_url = issue_url
                db.session.commit()
                logger.info(f"Created issue {issue_key} for assignment {assignment.id}")
            else:
                warning = f"Assignment created but ticket creation failed: {message}"
                logger.warning(f"Ticket creation failed for assignment {assignment.id}: {message}")

        except Exception as e:
            warning = f"Assignment created but ticket creation failed: {str(e)}"
            logger.exception(f"Error creating ticket for assignment {assignment.id}")

    # -- Email notification --
    try:
        from app.email_service import send_remediation_assignment_notification
        from app.models import Organization
        org = Organization.query.get(org_id)
        if org:
            send_remediation_assignment_notification(assignment, org, action='created')
    except Exception as e:
        logger.warning(f"Failed to send assignment notification: {e}")

    result = assignment.to_dict()
    if warning:
        result['warning'] = warning

    return jsonify(result), 201


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

    old_status = assignment.status
    if 'status' in data:
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

    # Email notification on status change
    new_status = assignment.status
    if new_status != old_status:
        try:
            from app.email_service import send_remediation_assignment_notification
            from app.models import Organization
            org = Organization.query.get(org_id)
            if org:
                action = 'resolved' if new_status in ('resolved', 'accepted_risk') else 'updated'
                send_remediation_assignment_notification(assignment, org, action=action)
        except Exception as e:
            logger.warning(f"Failed to send assignment update notification: {e}")

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


# ============================================================================
# Risk Exceptions (Sprint 4 #33)
# ============================================================================

@bp.route('/api/risk-exceptions', methods=['GET'])
@login_required
def list_risk_exceptions():
    """List risk exceptions for the current organization with optional filters."""
    org_id = _org_id_or_400()
    if not org_id:
        return jsonify({'error': 'Organization required'}), 400

    query = RiskException.query.filter_by(organization_id=org_id)

    # Filters
    status_filter = request.args.get('status', '').strip().lower()
    cve_id_filter = request.args.get('cve_id', '').strip()

    if status_filter:
        query = query.filter_by(status=status_filter)
    if cve_id_filter:
        query = query.filter_by(cve_id=cve_id_filter)

    query = query.order_by(RiskException.created_at.desc())
    exceptions = query.all()

    return jsonify({
        'risk_exceptions': [e.to_dict() for e in exceptions],
        'total': len(exceptions),
    })


@bp.route('/api/risk-exceptions', methods=['POST'])
@login_required
@org_admin_required
def create_risk_exception():
    """Create a new risk exception (org_admin only). Requires justification."""
    org_id = _org_id_or_400()
    if not org_id:
        return jsonify({'error': 'Organization required'}), 400

    data = request.get_json()
    if not data or not data.get('justification'):
        return jsonify({'error': 'justification is required'}), 400

    # Must specify at least one of: match_id, cve_id, product_id
    if not any(data.get(k) for k in ('match_id', 'cve_id', 'product_id')):
        return jsonify({'error': 'At least one of match_id, cve_id, or product_id is required'}), 400

    # Validate product_id ownership
    if data.get('product_id'):
        if not _validate_product_ownership(org_id, data['product_id']):
            return jsonify({'error': 'Product not found in your organization'}), 403

    # Validate match_id ownership
    if data.get('match_id'):
        _, err = _validate_match_ownership(org_id, data['match_id'])
        if err:
            return err

    # Resolve approved_by from current user
    user_id = session.get('user_id')
    from app.models import User
    user = User.query.get(user_id)
    approved_by = user.username if user else 'unknown'

    # Parse optional expires_at
    expires_at = None
    if data.get('expires_at'):
        try:
            expires_at = datetime.strptime(data['expires_at'], '%Y-%m-%d').date()
        except ValueError:
            return jsonify({'error': 'Invalid expires_at format (use YYYY-MM-DD)'}), 400

    exception = RiskException(
        organization_id=org_id,
        match_id=data.get('match_id'),
        cve_id=data.get('cve_id'),
        product_id=data.get('product_id'),
        justification=data['justification'],
        approved_by=approved_by,
        expires_at=expires_at,
        status='active',
    )
    db.session.add(exception)
    db.session.commit()

    return jsonify(exception.to_dict()), 201


@bp.route('/api/risk-exceptions/<int:exception_id>', methods=['PUT'])
@login_required
@org_admin_required
def update_risk_exception(exception_id):
    """Update a risk exception (e.g. revoke it, update justification)."""
    org_id = _org_id_or_400()
    if not org_id:
        return jsonify({'error': 'Organization required'}), 400

    exception = RiskException.query.filter_by(
        id=exception_id, organization_id=org_id
    ).first_or_404()

    data = request.get_json()
    if not data:
        return jsonify({'error': 'No data provided'}), 400

    if 'status' in data:
        allowed_statuses = ('active', 'revoked', 'expired')
        if data['status'] not in allowed_statuses:
            return jsonify({'error': f'status must be one of: {", ".join(allowed_statuses)}'}), 400
        exception.status = data['status']

    if 'justification' in data:
        if not data['justification'] or not data['justification'].strip():
            return jsonify({'error': 'justification cannot be empty'}), 400
        exception.justification = data['justification']

    if 'expires_at' in data:
        if data['expires_at']:
            try:
                exception.expires_at = datetime.strptime(data['expires_at'], '%Y-%m-%d').date()
            except ValueError:
                return jsonify({'error': 'Invalid expires_at format (use YYYY-MM-DD)'}), 400
        else:
            exception.expires_at = None

    db.session.commit()
    return jsonify(exception.to_dict())


@bp.route('/api/risk-exceptions/<int:exception_id>', methods=['DELETE'])
@login_required
@org_admin_required
def delete_risk_exception(exception_id):
    """Delete a risk exception."""
    org_id = _org_id_or_400()
    if not org_id:
        return jsonify({'error': 'Organization required'}), 400

    exception = RiskException.query.filter_by(
        id=exception_id, organization_id=org_id
    ).first_or_404()

    db.session.delete(exception)
    db.session.commit()
    return jsonify({'status': 'deleted'})


# ============================================================================
# Product Aliases (Sprint 4 #36)
# ============================================================================

@bp.route('/api/product-aliases', methods=['GET'])
@login_required
def list_product_aliases():
    """List product aliases for the current organization."""
    org_id = _org_id_or_400()
    if not org_id:
        return jsonify({'error': 'Organization required'}), 400

    aliases = ProductAlias.query.filter_by(organization_id=org_id).order_by(
        ProductAlias.alias_vendor.asc(),
        ProductAlias.alias_product.asc(),
    ).all()

    return jsonify({
        'product_aliases': [a.to_dict() for a in aliases],
        'total': len(aliases),
    })


@bp.route('/api/product-aliases', methods=['POST'])
@login_required
@org_admin_required
def create_product_alias():
    """Create a new product alias (org_admin only). Requires product_id, alias_vendor, alias_product."""
    org_id = _org_id_or_400()
    if not org_id:
        return jsonify({'error': 'Organization required'}), 400

    data = request.get_json()
    if not data:
        return jsonify({'error': 'No data provided'}), 400

    # Validate required fields
    missing = [f for f in ('product_id', 'alias_vendor', 'alias_product') if not data.get(f)]
    if missing:
        return jsonify({'error': f'Missing required fields: {", ".join(missing)}'}), 400

    # Validate product_id ownership
    if not _validate_product_ownership(org_id, data['product_id']):
        return jsonify({'error': 'Product not found in your organization'}), 403

    # Check for duplicate alias
    existing = ProductAlias.query.filter_by(
        organization_id=org_id,
        alias_vendor=data['alias_vendor'].strip(),
        alias_product=data['alias_product'].strip(),
    ).first()
    if existing:
        return jsonify({'error': 'An alias with this vendor/product combination already exists'}), 409

    alias = ProductAlias(
        organization_id=org_id,
        product_id=data['product_id'],
        alias_vendor=data['alias_vendor'].strip(),
        alias_product=data['alias_product'].strip(),
    )
    db.session.add(alias)
    db.session.commit()

    return jsonify(alias.to_dict()), 201


@bp.route('/api/product-aliases/<int:alias_id>', methods=['DELETE'])
@login_required
@org_admin_required
def delete_product_alias(alias_id):
    """Delete a product alias."""
    org_id = _org_id_or_400()
    if not org_id:
        return jsonify({'error': 'Organization required'}), 400

    alias = ProductAlias.query.filter_by(
        id=alias_id, organization_id=org_id
    ).first_or_404()

    db.session.delete(alias)
    db.session.commit()
    return jsonify({'status': 'deleted'})
