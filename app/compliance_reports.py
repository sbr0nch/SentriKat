"""
Compliance Reports API — Sprint 5

Gap analysis reports mapping the organization's vulnerability management
posture to specific requirements of:
  - PCI-DSS v4.0 (Payment Card Industry Data Security Standard)
  - ISO/IEC 27001:2022 (Information Security Management System)
  - SOC 2 Trust Services Criteria (Security category)

IMPORTANT: These are NOT certified audit reports. They are self-assessment
gap analysis reports intended as evidence/input for a qualified auditor.
The output should be reviewed by a QSA (for PCI-DSS) or certified auditor
(for ISO 27001 / SOC 2) before being used in any formal process.

Endpoints:
  GET /api/reports/compliance/pci-dss?format=json|pdf
  GET /api/reports/compliance/iso-27001?format=json|pdf
  GET /api/reports/compliance/soc2?format=json|pdf
"""

from flask import Blueprint, request, jsonify, session, send_file
from datetime import datetime, timedelta, timezone
from io import BytesIO
import logging

from app import db, csrf
from app.models import (
    User, Organization, Product, VulnerabilityMatch, Vulnerability, Asset,
    product_organizations, RemediationAssignment, SlaPolicy, RiskException,
)
from app.saas import is_saas_mode, get_scoped_org_id, get_effective_features


def _get_report_timezone():
    """Return the tenant's configured report timezone (H8).

    Compliance reports compute "overdue for >30/60/90 days" cutoffs. The rest
    of the platform (SLA policy scheduler, dashboard displays) runs in the
    tenant-configured ``display_timezone``. Using ``datetime.utcnow()`` here
    while every other clock uses a tz-aware local time caused reports to
    disagree with the SLA compliance dashboard by up to 24h for tenants
    far from UTC — especially visible around calendar day boundaries.

    We now load ``display_timezone`` from SystemSettings and compute cutoffs
    as tz-aware datetimes in that zone, then convert to naive UTC only at
    the very end when comparing against DB columns (which store naive UTC
    for historical reasons; see ``default=datetime.utcnow`` on models).

    Falls back silently to UTC if the setting is missing or points at an
    unknown tz name.
    """
    tz_name = 'UTC'
    try:
        from app.settings_api import get_setting
        tz_name = get_setting('display_timezone', 'UTC') or 'UTC'
    except Exception:
        tz_name = 'UTC'

    try:
        from zoneinfo import ZoneInfo
        return ZoneInfo(tz_name), tz_name
    except Exception:
        try:
            import pytz
            return pytz.timezone(tz_name), tz_name
        except Exception:
            logger.warning("Unknown display_timezone %r — falling back to UTC", tz_name)
            return timezone.utc, 'UTC'


def _tz_cutoff_utc_naive(tz, days):
    """Return a naive-UTC datetime ``days`` days before "now" in ``tz``.

    The DB stores naive UTC datetimes on VulnerabilityMatch.created_at etc.,
    so after computing the cutoff in the tenant's local time we convert
    back to UTC and strip tzinfo for the comparison to work with SQLAlchemy.
    """
    local_now = datetime.now(tz)
    cutoff_local = local_now - timedelta(days=days)
    cutoff_utc = cutoff_local.astimezone(timezone.utc).replace(tzinfo=None)
    return cutoff_utc

logger = logging.getLogger(__name__)

bp = Blueprint('compliance_reports', __name__)
# NOTE: CSRF is NOT exempted blueprint-wide. Compliance report endpoints are
# session-authenticated and called from the dashboard UI. All GET endpoints
# are naturally safe from CSRF; if we ever add POST endpoints here they will
# go through flask-wtf's CSRFProtect.

# Sprint 4+5 hardening: accepted format values for the ?format= query param.
# Anything else returns HTTP 400.
_VALID_REPORT_FORMATS = frozenset(('json', 'pdf'))

# Sprint 4+5 hardening: cap on the number of evidence items / requirements
# rendered in a PDF to prevent ReportLab OOM on very large organizations.
# Reports beyond the cap include a truncation notice pointing at the JSON
# variant for the full data set.
MAX_REPORT_REQUIREMENTS = 200
MAX_EVIDENCE_ITEMS_PER_REQUIREMENT = 50


def _login_required(f):
    """Local decorator (avoids circular import with reports_api)."""
    from functools import wraps

    @wraps(f)
    def wrapper(*args, **kwargs):
        if 'user_id' not in session:
            return jsonify({'error': 'Authentication required'}), 401
        return f(*args, **kwargs)
    return wrapper


# ============================================================================
# Posture computation (shared by all frameworks)
# ============================================================================

def _compute_vuln_posture(org_ids):
    """Compute shared vulnerability management posture metrics for a set of orgs.

    Returns a dict of evidence fields that each framework evaluator interprets
    against its own requirements.
    """
    from sqlalchemy import func, select

    posture = {
        'total_products': 0,
        'products_scanned': 0,
        'total_matches': 0,
        'matches_critical': 0,
        'matches_high': 0,
        'matches_medium': 0,
        'matches_low': 0,
        # M10: separate counters for CVEs whose NVD analysis is still
        # pending or whose match confidence is below 'high'. These are
        # tracked so the "Data quality notice" section can surface the
        # percentage of findings the auditor should treat as provisional.
        # The scoring rules are unchanged — we only expose the metric.
        'matches_critical_awaiting': 0,
        'matches_high_awaiting': 0,
        'matches_medium_awaiting': 0,
        'matches_low_awaiting': 0,
        'total_awaiting': 0,
        'pct_awaiting': 0.0,
        'open_critical': 0,
        'open_high': 0,
        'overdue_critical_30d': 0,
        'overdue_critical_90d': 0,
        'agents_online': 0,
        'agents_total': 0,
        'last_scan_age_hours': None,
        'scan_frequency_daily': False,
        'avg_remediation_days': None,
        'has_sla_policies': False,
        'has_risk_exceptions': False,
        'resolved_assignments_count': 0,
        # H8: record which timezone was used to compute cutoffs so the
        # auditor can reproduce the numbers.
        'report_timezone': 'UTC',
    }

    if not org_ids:
        return posture

    # Products owned by the scoped orgs (M2M + legacy single-org)
    org_product_ids = db.session.execute(
        select(product_organizations.c.product_id).where(
            product_organizations.c.organization_id.in_(org_ids)
        )
    ).scalars().all()
    legacy_products = db.session.execute(
        select(Product.id).where(Product.organization_id.in_(org_ids))
    ).scalars().all()
    org_product_ids = list(set(list(org_product_ids) + list(legacy_products)))

    posture['total_products'] = len(org_product_ids)
    if not org_product_ids:
        return posture

    # Match counts by severity
    severity_counts = db.session.query(
        func.upper(Vulnerability.severity).label('sev'),
        func.count(VulnerabilityMatch.id),
    ).join(
        Vulnerability, Vulnerability.id == VulnerabilityMatch.vulnerability_id,
    ).filter(
        VulnerabilityMatch.product_id.in_(org_product_ids),
    ).group_by(func.upper(Vulnerability.severity)).all()

    for sev, count in severity_counts:
        posture['total_matches'] += count
        if sev == 'CRITICAL':
            posture['matches_critical'] = count
        elif sev == 'HIGH':
            posture['matches_high'] = count
        elif sev == 'MEDIUM':
            posture['matches_medium'] = count
        elif sev == 'LOW':
            posture['matches_low'] = count

    # M10: count matches whose NVD data is still provisional. A match is
    # "awaiting" when:
    #   - the Vulnerability.nvd_status is one of the NVD pending states, OR
    #   - the VulnerabilityMatch.match_confidence is not 'high' (i.e. the
    #     match was produced by keyword/vendor_product heuristics rather
    #     than a verified CPE range).
    # We compute per-severity breakdowns so the Data Quality Notice can
    # explain which severity buckets are most impacted.
    awaiting_nvd_states = ('Awaiting Analysis', 'Received', 'Undergoing Analysis')
    awaiting_counts = db.session.query(
        func.upper(Vulnerability.severity).label('sev'),
        func.count(VulnerabilityMatch.id),
    ).join(
        Vulnerability, Vulnerability.id == VulnerabilityMatch.vulnerability_id,
    ).filter(
        VulnerabilityMatch.product_id.in_(org_product_ids),
        db.or_(
            Vulnerability.nvd_status.in_(awaiting_nvd_states),
            VulnerabilityMatch.match_confidence != 'high',
        ),
    ).group_by(func.upper(Vulnerability.severity)).all()

    for sev, count in awaiting_counts:
        posture['total_awaiting'] += count
        if sev == 'CRITICAL':
            posture['matches_critical_awaiting'] = count
        elif sev == 'HIGH':
            posture['matches_high_awaiting'] = count
        elif sev == 'MEDIUM':
            posture['matches_medium_awaiting'] = count
        elif sev == 'LOW':
            posture['matches_low_awaiting'] = count

    if posture['total_matches']:
        posture['pct_awaiting'] = round(
            (posture['total_awaiting'] / posture['total_matches']) * 100, 1
        )

    # Open (unacknowledged) by severity
    posture['open_critical'] = db.session.query(VulnerabilityMatch).join(
        Vulnerability, Vulnerability.id == VulnerabilityMatch.vulnerability_id,
    ).filter(
        VulnerabilityMatch.product_id.in_(org_product_ids),
        VulnerabilityMatch.acknowledged == False,  # noqa: E712
        func.upper(Vulnerability.severity) == 'CRITICAL',
    ).count()

    posture['open_high'] = db.session.query(VulnerabilityMatch).join(
        Vulnerability, Vulnerability.id == VulnerabilityMatch.vulnerability_id,
    ).filter(
        VulnerabilityMatch.product_id.in_(org_product_ids),
        VulnerabilityMatch.acknowledged == False,  # noqa: E712
        func.upper(Vulnerability.severity) == 'HIGH',
    ).count()

    # Overdue critical (open and older than 30/90 days).
    # H8: cutoffs are computed in the tenant's display_timezone so compliance
    # reports agree with the SLA dashboard around calendar-day boundaries.
    tz, tz_name = _get_report_timezone()
    posture['report_timezone'] = tz_name
    now = datetime.now(tz).astimezone(timezone.utc).replace(tzinfo=None)
    cutoff_30 = _tz_cutoff_utc_naive(tz, 30)
    cutoff_90 = _tz_cutoff_utc_naive(tz, 90)

    posture['overdue_critical_30d'] = db.session.query(VulnerabilityMatch).join(
        Vulnerability, Vulnerability.id == VulnerabilityMatch.vulnerability_id,
    ).filter(
        VulnerabilityMatch.product_id.in_(org_product_ids),
        VulnerabilityMatch.acknowledged == False,  # noqa: E712
        func.upper(Vulnerability.severity) == 'CRITICAL',
        VulnerabilityMatch.created_at < cutoff_30,
    ).count()

    posture['overdue_critical_90d'] = db.session.query(VulnerabilityMatch).join(
        Vulnerability, Vulnerability.id == VulnerabilityMatch.vulnerability_id,
    ).filter(
        VulnerabilityMatch.product_id.in_(org_product_ids),
        VulnerabilityMatch.acknowledged == False,  # noqa: E712
        func.upper(Vulnerability.severity) == 'CRITICAL',
        VulnerabilityMatch.created_at < cutoff_90,
    ).count()

    # Agents
    posture['agents_total'] = Asset.query.filter(
        Asset.organization_id.in_(org_ids)
    ).count()
    online_threshold = now - timedelta(days=14)
    posture['agents_online'] = Asset.query.filter(
        Asset.organization_id.in_(org_ids),
        Asset.last_checkin >= online_threshold,
    ).count()

    # Products scanned at least once
    posture['products_scanned'] = db.session.query(Product).filter(
        Product.id.in_(org_product_ids),
        Product.last_agent_report.isnot(None),
    ).count()

    # Last scan age
    last_checkin = db.session.query(func.max(Asset.last_checkin)).filter(
        Asset.organization_id.in_(org_ids)
    ).scalar()
    if last_checkin:
        delta = now - last_checkin
        posture['last_scan_age_hours'] = round(delta.total_seconds() / 3600, 1)
        posture['scan_frequency_daily'] = delta.total_seconds() < 86400 * 2

    # Average remediation time
    resolved = db.session.query(
        RemediationAssignment.created_at,
        RemediationAssignment.resolved_at,
    ).filter(
        RemediationAssignment.organization_id.in_(org_ids),
        RemediationAssignment.resolved_at.isnot(None),
    ).all()
    if resolved:
        total_days = sum(
            (r.resolved_at - r.created_at).days for r in resolved
            if r.resolved_at and r.created_at
        )
        posture['resolved_assignments_count'] = len(resolved)
        posture['avg_remediation_days'] = round(total_days / len(resolved), 1)

    # SLA policies + risk exceptions
    posture['has_sla_policies'] = db.session.query(SlaPolicy).filter(
        SlaPolicy.organization_id.in_(org_ids),
        SlaPolicy.enabled == True,  # noqa: E712
    ).count() > 0

    posture['has_risk_exceptions'] = db.session.query(RiskException).filter(
        RiskException.organization_id.in_(org_ids),
        RiskException.status == 'active',
    ).count() > 0

    return posture


# ============================================================================
# Framework evaluators
# ============================================================================

def _evaluate_pci_dss(posture):
    """PCI-DSS v4.0 — Requirements 6.3 + 11.3."""
    reqs = []

    # 6.3.1 - Identify and risk-rank vulnerabilities
    ok = posture['agents_online'] > 0
    reqs.append({
        'id': '6.3.1',
        'title': 'Security vulnerabilities identified and assigned a risk ranking',
        'description': (
            'System components and software must be monitored for security '
            'vulnerabilities. Each identified vulnerability must receive a '
            'risk ranking based on industry best practices and the impact '
            'on the organization.'
        ),
        'status': 'PASS' if ok else 'FAIL',
        'evidence': {
            'assets_monitored': posture['agents_online'],
            'total_vulnerabilities_tracked': posture['total_matches'],
            'risk_ranking_applied': True,
            'intelligence_sources': ['NVD', 'CISA KEV', 'EPSS', 'ExploitDB'],
        },
        'findings': [] if ok else [
            'No agents reporting. Install SentriKat agents on all CDE systems.'
        ],
        'recommendations': [
            'Ensure agents are installed on every Cardholder Data Environment system.',
            'Review product inventory quarterly for completeness.',
        ],
    })

    # 6.3.3 - Critical patches within 1 month
    overdue = posture['overdue_critical_30d']
    status = 'FAIL' if overdue > 0 else 'PASS'
    reqs.append({
        'id': '6.3.3',
        'title': 'Critical security patches installed within one month of release',
        'description': (
            'System components and software must be protected from known '
            'vulnerabilities by installing applicable critical security '
            'patches within one month of release.'
        ),
        'status': status,
        'evidence': {
            'open_critical_vulns': posture['open_critical'],
            'critical_overdue_30_days': posture['overdue_critical_30d'],
            'critical_overdue_90_days': posture['overdue_critical_90d'],
            'avg_remediation_days': posture['avg_remediation_days'],
            'resolved_assignments_tracked': posture['resolved_assignments_count'],
        },
        'findings': [
            f"{overdue} critical vulnerabilities unpatched for more than 30 days."
        ] if overdue > 0 else [],
        'recommendations': [
            'Use Remediation Assignments to track each patch with owner + due date.',
            'Configure SLA policies to auto-flag overdue critical patches.',
        ],
    })

    # 11.3.1 - Internal scans quarterly + after change
    daily = posture['scan_frequency_daily']
    reqs.append({
        'id': '11.3.1',
        'title': 'Internal vulnerability scans quarterly and after significant changes',
        'description': (
            'Perform internal vulnerability scans at least once every three '
            'months and after any significant changes in the network.'
        ),
        'status': 'PASS' if daily else 'PARTIAL',
        'evidence': {
            'last_scan_age_hours': posture['last_scan_age_hours'],
            'scan_frequency': 'Continuous (daily)' if daily else 'Irregular',
            'agents_online': posture['agents_online'],
            'agents_total': posture['agents_total'],
        },
        'findings': [] if daily else [
            'No agent has reported within 48 hours. Investigate offline agents.',
        ],
        'recommendations': [
            'SentriKat provides continuous scanning, exceeding the quarterly minimum.',
        ],
    })

    # 11.3.2 - External scans
    reqs.append({
        'id': '11.3.2',
        'title': 'External vulnerability scans performed quarterly by an ASV',
        'description': (
            'Perform external vulnerability scans at least once every three '
            'months by a PCI SSC Approved Scanning Vendor (ASV).'
        ),
        'status': 'NOT_APPLICABLE',
        'evidence': {
            'scope_note': 'External network perimeter scanning is not provided by SentriKat.',
        },
        'findings': [
            'SentriKat does not perform external network-perimeter scans. '
            'This requirement must be satisfied by a separate PCI SSC Approved '
            'Scanning Vendor (ASV).',
        ],
        'recommendations': [
            'Engage an ASV such as Qualys, Tenable, or Rapid7 for external scans.',
        ],
    })

    return reqs


def _evaluate_iso_27001(posture):
    """ISO/IEC 27001:2022 — Annex A vulnerability and monitoring controls."""
    reqs = []

    # A.8.8 - Management of technical vulnerabilities
    sla_ok = posture['has_sla_policies']
    online = posture['agents_online'] > 0
    full = online and sla_ok
    reqs.append({
        'id': 'A.8.8',
        'title': 'Management of technical vulnerabilities',
        'description': (
            'Information about technical vulnerabilities of information '
            'systems in use shall be obtained, the organization\'s exposure '
            'to such vulnerabilities evaluated and appropriate measures taken.'
        ),
        'status': 'PASS' if full else 'PARTIAL',
        'evidence': {
            'intelligence_sources': [
                'NVD', 'CISA KEV', 'EPSS', 'ExploitDB', 'GitHub PoC', 'Vendor advisories',
            ],
            'assets_under_management': posture['products_scanned'],
            'vulnerabilities_evaluated': posture['total_matches'],
            'sla_policies_configured': sla_ok,
            'risk_exceptions_tracked': posture['has_risk_exceptions'],
            'avg_time_to_remediate_days': posture['avg_remediation_days'],
        },
        'findings': [] if sla_ok else [
            'No SLA policies configured. Define remediation SLAs per severity.'
        ],
        'recommendations': [
            'Configure SLA policies (e.g. 14d critical, 30d high, 60d medium, 90d low).',
            'Use Risk Exceptions to formally document accepted risks with justification.',
        ],
    })

    # A.8.16 - Monitoring activities
    fresh = posture['last_scan_age_hours'] is not None and posture['last_scan_age_hours'] < 48
    reqs.append({
        'id': 'A.8.16',
        'title': 'Monitoring activities',
        'description': (
            'Networks, systems and applications shall be monitored for '
            'anomalous behaviour and appropriate actions taken to evaluate '
            'potential information security incidents.'
        ),
        'status': 'PASS' if (online and fresh) else 'PARTIAL',
        'evidence': {
            'agents_online_percent': (
                round(posture['agents_online'] / posture['agents_total'] * 100, 1)
                if posture['agents_total'] else 0
            ),
            'last_scan_age_hours': posture['last_scan_age_hours'],
            'continuous_monitoring': posture['scan_frequency_daily'],
        },
        'findings': [] if (online and fresh) else [
            'Monitoring coverage is incomplete or scans are stale.',
        ],
        'recommendations': [
            'Investigate offline agents in Dashboard > Agents.',
            'Enable email alerts for critical CVEs in Settings > Notifications.',
        ],
    })

    # A.5.24 - Incident management planning
    tracked = sla_ok and posture['avg_remediation_days'] is not None
    reqs.append({
        'id': 'A.5.24',
        'title': 'Information security incident management planning and preparation',
        'description': (
            'The organization shall plan and prepare for managing information '
            'security incidents by defining and establishing incident '
            'management processes, roles, and responsibilities.'
        ),
        'status': 'PASS' if tracked else 'PARTIAL',
        'evidence': {
            'remediation_assignments_enabled': True,
            'sla_defined': sla_ok,
            'historical_remediation_tracked': posture['avg_remediation_days'] is not None,
            'resolved_cases_last_period': posture['resolved_assignments_count'],
        },
        'findings': [],
        'recommendations': [
            'Use Remediation Assignments to assign owners and due dates.',
            'Export assignment reports monthly for management review.',
        ],
    })

    return reqs


def _evaluate_soc2(posture):
    """SOC 2 Trust Services Criteria (Security category)."""
    reqs = []

    # CC7.1 - Detection and monitoring of vulnerabilities
    detection_ok = posture['agents_online'] > 0 and posture['scan_frequency_daily']
    reqs.append({
        'id': 'CC7.1',
        'title': 'Detection and monitoring procedures identify vulnerabilities',
        'description': (
            'The entity uses detection and monitoring procedures to identify '
            '(1) changes to configurations that result in the introduction '
            'of new vulnerabilities, and (2) susceptibilities to newly '
            'discovered vulnerabilities.'
        ),
        'status': 'PASS' if detection_ok else 'PARTIAL',
        'evidence': {
            'continuous_detection': posture['scan_frequency_daily'],
            'agents_reporting': posture['agents_online'],
            'cve_intel_sources': ['NVD', 'CISA KEV', 'EPSS', 'GitHub PoC'],
            'total_cves_detected': posture['total_matches'],
        },
        'findings': [] if detection_ok else [
            'Continuous detection is not fully active (agents offline or scans stale).',
        ],
        'recommendations': [
            'Ensure all production assets have SentriKat agents installed and online.',
        ],
    })

    # CC7.2 - Monitoring coverage
    cov = 0
    if posture['total_products']:
        cov = posture['products_scanned'] / posture['total_products'] * 100
    cov_ok = cov >= 90
    reqs.append({
        'id': 'CC7.2',
        'title': 'System components monitored for anomalies and vulnerabilities',
        'description': (
            'The entity monitors system components for anomalies indicative '
            'of malicious acts, natural disasters, and errors affecting the '
            'entity\'s ability to meet its objectives.'
        ),
        'status': 'PASS' if cov_ok else 'PARTIAL',
        'evidence': {
            'products_scanned': posture['products_scanned'],
            'products_total': posture['total_products'],
            'coverage_percent': round(cov, 1),
        },
        'findings': [] if cov_ok else [
            f"Coverage is {round(cov, 1)}% (target ≥90%). Some products never scanned.",
        ],
        'recommendations': [
            'Review unscanned products in Inventory and install agents.',
        ],
    })

    # CC7.4 - Response to events
    response_ok = posture['overdue_critical_30d'] == 0 and posture['has_sla_policies']
    reqs.append({
        'id': 'CC7.4',
        'title': 'Response to identified security events',
        'description': (
            'The entity responds to identified security incidents by '
            'executing a defined incident response program to understand, '
            'contain, remediate, and communicate security incidents.'
        ),
        'status': 'PASS' if response_ok else 'PARTIAL',
        'evidence': {
            'critical_vulns_overdue_30d': posture['overdue_critical_30d'],
            'sla_policies_in_place': posture['has_sla_policies'],
            'avg_remediation_days': posture['avg_remediation_days'],
            'incident_tracking': 'Remediation Assignments + Issue Tracker integration',
        },
        'findings': [
            f"{posture['overdue_critical_30d']} critical vulnerabilities overdue (>30 days)."
        ] if posture['overdue_critical_30d'] > 0 else [],
        'recommendations': [
            'Address overdue critical vulnerabilities immediately.',
            'Link remediation assignments to Jira/GitHub for audit trail.',
        ],
    })

    # CC6.6 - Logical access (out of scope)
    reqs.append({
        'id': 'CC6.6',
        'title': 'Logical access boundaries',
        'description': (
            'The entity implements logical access security measures to '
            'protect against threats from sources outside its system boundaries.'
        ),
        'status': 'NOT_APPLICABLE',
        'evidence': {
            'scope_note': 'SentriKat does not manage user access to third-party systems.',
        },
        'findings': [
            'Out of scope for SentriKat. Satisfied by your IAM/SSO/access management tools.',
        ],
        'recommendations': [
            'Use SentriKat SAML SSO + LDAP for SentriKat access itself.',
            'Combine with IAM (Okta, Auth0, Entra ID) for full logical access coverage.',
        ],
    })

    return reqs


# ============================================================================
# Report builder + PDF renderer
# ============================================================================

def _build_report(framework, framework_name, requirements, user, org_name, posture=None):
    """Assemble final report dict with scoring + integrity block."""
    total = len(requirements)
    pass_ = sum(1 for r in requirements if r['status'] == 'PASS')
    fail_ = sum(1 for r in requirements if r['status'] == 'FAIL')
    partial = sum(1 for r in requirements if r['status'] == 'PARTIAL')
    na = sum(1 for r in requirements if r['status'] == 'NOT_APPLICABLE')
    scorable = total - na
    score = round(pass_ / scorable * 100, 1) if scorable > 0 else 0.0

    report = {
        'framework': framework,
        'framework_full_name': framework_name,
        'report_type': 'Gap Analysis (Self-Assessment)',
        'disclaimer': (
            f'This is a SELF-ASSESSMENT gap analysis based on SentriKat '
            f'vulnerability management data. It is NOT a certified '
            f'{framework} audit. Engage a qualified assessor for certification.'
        ),
        'organization': org_name,
        'generated_at': datetime.utcnow().isoformat() + 'Z',
        'generated_by': user.username if user else 'unknown',
        'report_timezone': (posture or {}).get('report_timezone', 'UTC'),
        'summary': {
            'total_requirements': total,
            'pass': pass_,
            'fail': fail_,
            'partial': partial,
            'not_applicable': na,
            'compliance_score_percent': score,
        },
        'requirements': requirements,
    }

    # M10: Data Quality Notice — surface the share of CVE matches whose NVD
    # data is still pending ("Awaiting Analysis" / "Received" /
    # "Undergoing Analysis") or whose match was produced by a lower-
    # confidence heuristic. The PCI scoring is intentionally unchanged; this
    # section exists so the auditor can contextualise the numbers.
    if posture is not None:
        report['data_quality_notice'] = {
            'description': (
                'The following metrics indicate CVE matches whose underlying '
                'data is still provisional. These matches are included in '
                'the scoring as-is, but an auditor should treat them as '
                'lower-confidence evidence until NVD completes its analysis '
                'or the match is manually verified.'
            ),
            'total_matches': posture.get('total_matches', 0),
            'total_awaiting': posture.get('total_awaiting', 0),
            'pct_awaiting': posture.get('pct_awaiting', 0.0),
            'by_severity': {
                'critical': posture.get('matches_critical_awaiting', 0),
                'high': posture.get('matches_high_awaiting', 0),
                'medium': posture.get('matches_medium_awaiting', 0),
                'low': posture.get('matches_low_awaiting', 0),
            },
        }

    # Reuse existing integrity helper from reports_api to stay consistent
    try:
        from app.reports_api import _add_report_integrity
        _add_report_integrity(report, generated_by_user=user)
    except Exception as e:
        logger.warning(f"Could not add integrity block: {e}")

    return report


def _render_pdf(report):
    """Render compliance report to PDF using ReportLab."""
    from reportlab.lib.pagesizes import A4
    from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
    from reportlab.lib.units import cm
    from reportlab.lib import colors
    from reportlab.platypus import (
        SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, PageBreak,
    )

    buf = BytesIO()
    doc = SimpleDocTemplate(
        buf, pagesize=A4,
        leftMargin=2 * cm, rightMargin=2 * cm,
        topMargin=2 * cm, bottomMargin=2 * cm,
    )
    styles = getSampleStyleSheet()
    title_style = ParagraphStyle(
        'Title', parent=styles['Heading1'], fontSize=18,
        textColor=colors.HexColor('#1e40af'), spaceAfter=12,
    )
    body = styles['BodyText']
    small = ParagraphStyle(
        'Small', parent=body, fontSize=9, textColor=colors.gray,
    )

    story = []
    story.append(Paragraph(f"{report['framework']} Gap Analysis", title_style))
    story.append(Paragraph(report['framework_full_name'], body))
    story.append(Spacer(1, 6))
    story.append(Paragraph(f"<b>Organization:</b> {report['organization']}", body))
    story.append(Paragraph(f"<b>Generated:</b> {report['generated_at']}", body))
    story.append(Paragraph(f"<b>Generated by:</b> {report['generated_by']}", body))
    story.append(Spacer(1, 6))
    story.append(Paragraph(f"<i>{report['disclaimer']}</i>", small))
    story.append(Spacer(1, 12))

    s = report['summary']
    summary_data = [
        ['Metric', 'Value'],
        ['Total requirements', str(s['total_requirements'])],
        ['PASS', str(s['pass'])],
        ['PARTIAL', str(s['partial'])],
        ['FAIL', str(s['fail'])],
        ['NOT APPLICABLE', str(s['not_applicable'])],
        ['Compliance score', f"{s['compliance_score_percent']}%"],
    ]
    summary_table = Table(summary_data, colWidths=[9 * cm, 6 * cm])
    summary_table.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#1e40af')),
        ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),
        ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
        ('GRID', (0, 0), (-1, -1), 0.5, colors.gray),
        ('LEFTPADDING', (0, 0), (-1, -1), 6),
        ('RIGHTPADDING', (0, 0), (-1, -1), 6),
        ('TOPPADDING', (0, 0), (-1, -1), 6),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 6),
    ]))
    story.append(summary_table)
    story.append(Spacer(1, 16))

    status_colors = {
        'PASS': colors.HexColor('#16a34a'),
        'FAIL': colors.HexColor('#dc2626'),
        'PARTIAL': colors.HexColor('#f59e0b'),
        'NOT_APPLICABLE': colors.gray,
    }

    for r in report['requirements']:
        sc = status_colors.get(r['status'], colors.black)
        story.append(Paragraph(
            f"<b>{r['id']} — {r['title']}</b>",
            ParagraphStyle(
                'ReqTitle', parent=body, fontSize=12,
                textColor=colors.HexColor('#1e40af'), spaceAfter=4,
            ),
        ))
        story.append(Paragraph(
            f"<font color='{sc.hexval()}'><b>Status: {r['status']}</b></font>", body,
        ))
        story.append(Spacer(1, 4))
        story.append(Paragraph(r['description'], small))
        story.append(Spacer(1, 4))

        if r.get('evidence'):
            story.append(Paragraph('<b>Evidence:</b>', body))
            for k, v in r['evidence'].items():
                story.append(Paragraph(f"• {k}: {v}", small))

        if r.get('findings'):
            story.append(Spacer(1, 4))
            story.append(Paragraph('<b>Findings:</b>', body))
            for f in r['findings']:
                story.append(Paragraph(f"• {f}", small))

        if r.get('recommendations'):
            story.append(Spacer(1, 4))
            story.append(Paragraph('<b>Recommendations:</b>', body))
            for rec in r['recommendations']:
                story.append(Paragraph(f"• {rec}", small))

        story.append(Spacer(1, 12))

    if report.get('integrity'):
        story.append(PageBreak())
        story.append(Paragraph("Document Integrity & Attestation", title_style))
        story.append(Spacer(1, 6))
        for k, v in report['integrity'].items():
            story.append(Paragraph(f"<b>{k}:</b> {v}", small))

    doc.build(story)
    buf.seek(0)
    return buf


# ============================================================================
# Endpoint shared logic
# ============================================================================

def _generate_report(framework, framework_name, evaluator):
    """Shared endpoint logic for all three frameworks."""
    user = User.query.get(session.get('user_id'))
    if not user:
        return jsonify({'error': 'Authentication required'}), 401

    # Feature gate — the auditor-grade frameworks (PCI-DSS v4.0,
    # ISO/IEC 27001:2022, SOC 2 Trust Services Criteria) are sold as a
    # paid add-on ("Compliance Pack", €199/mo) on top of any plan.
    # This is distinct from the ``compliance_reports`` flag, which gates
    # the in-house frameworks (CISA BOD 22-01, EU NIS2) and the scheduled
    # reports feature — those remain bundled in Pro/Business/Enterprise.
    #
    # On-premise: a Professional license unlocks everything, including
    # ``compliance_pack`` — there is no add-on billing concept on-prem.
    if is_saas_mode():
        org_features = get_effective_features(get_scoped_org_id(user))
        if not org_features.get('compliance_pack', False):
            return jsonify({
                'error': (
                    f'{framework} gap analysis reports require the '
                    f'Compliance Pack add-on (€199/mo). They are not '
                    f'included in the base plan.'
                ),
                'feature': 'compliance_pack',
                'addon_required': 'compliance_pack',
                'upgrade_required': True,
            }), 403
    else:
        from app.licensing import get_license
        license_info = get_license()
        if not license_info or not license_info.is_professional():
            return jsonify({
                'error': f'{framework} gap analysis reports require a Professional license',
                'feature': 'compliance_pack',
            }), 403

    # Resolve org scope
    if is_saas_mode():
        saas_org = get_scoped_org_id(user)
        org_ids = [saas_org] if saas_org else [
            m.organization_id for m in user.org_memberships.all()
        ]
    elif user.role == 'super_admin':
        org_id_param = request.args.get('organization_id', type=int)
        if org_id_param:
            org_ids = [org_id_param]
        else:
            org_ids = [o.id for o in Organization.query.all()]
    else:
        org_ids = [m.organization_id for m in user.org_memberships.all()]

    if not org_ids:
        return jsonify({'error': 'No organization in scope'}), 400

    # Display org name
    first_org = Organization.query.get(org_ids[0])
    if first_org:
        org_name = first_org.display_name or first_org.name
    else:
        org_name = 'Unknown'
    if len(org_ids) > 1:
        org_name += f' (+{len(org_ids) - 1} more)'

    # Sprint 4+5 hardening: validate the format param up front so an invalid
    # value returns a clear 400 instead of silently falling through to JSON.
    fmt = request.args.get('format', 'json').lower()
    if fmt not in _VALID_REPORT_FORMATS:
        return jsonify({
            'error': 'Invalid format',
            'message': f"format must be one of {sorted(_VALID_REPORT_FORMATS)}",
        }), 400

    # Compute + evaluate
    posture = _compute_vuln_posture(org_ids)
    requirements = evaluator(posture)
    report = _build_report(framework, framework_name, requirements, user, org_name, posture=posture)

    # Sprint 4+5 hardening: truncate the report if it exceeds the cap. Large
    # orgs can always fetch the full data via the JSON variant.
    if len(report.get('requirements', [])) > MAX_REPORT_REQUIREMENTS:
        report['requirements'] = report['requirements'][:MAX_REPORT_REQUIREMENTS]
        report['truncated'] = True
        report['truncation_note'] = (
            f'Report truncated to the first {MAX_REPORT_REQUIREMENTS} '
            f'requirements. Fetch ?format=json for the complete data.'
        )
    for req in report.get('requirements', []):
        if isinstance(req.get('evidence'), list) and \
                len(req['evidence']) > MAX_EVIDENCE_ITEMS_PER_REQUIREMENT:
            req['evidence'] = req['evidence'][:MAX_EVIDENCE_ITEMS_PER_REQUIREMENT]
            req['evidence_truncated'] = True

    if fmt == 'pdf':
        try:
            pdf_buf = _render_pdf(report)
            return send_file(
                pdf_buf,
                mimetype='application/pdf',
                as_attachment=True,
                download_name=f"{framework.lower().replace(' ', '-')}-gap-analysis.pdf",
            )
        except Exception as e:
            logger.exception(f"Failed to render {framework} PDF report")
            # Sprint 4+5 hardening: include exception class so operators can
            # diagnose OOM vs template errors from the response.
            return jsonify({
                'error': 'PDF generation failed',
                'exception_type': type(e).__name__,
                'detail': str(e)[:500],
            }), 500

    return jsonify(report)


# ============================================================================
# Endpoints
# ============================================================================

@bp.route('/api/reports/compliance/pci-dss', methods=['GET'])
@_login_required
def compliance_pci_dss():
    """PCI-DSS v4.0 gap analysis (Requirement 6.3 + 11.3)."""
    return _generate_report(
        framework='PCI-DSS',
        framework_name='Payment Card Industry Data Security Standard v4.0',
        evaluator=_evaluate_pci_dss,
    )


@bp.route('/api/reports/compliance/iso-27001', methods=['GET'])
@_login_required
def compliance_iso_27001():
    """ISO/IEC 27001:2022 gap analysis (Annex A vulnerability controls)."""
    return _generate_report(
        framework='ISO 27001',
        framework_name='ISO/IEC 27001:2022 Information Security Management System',
        evaluator=_evaluate_iso_27001,
    )


@bp.route('/api/reports/compliance/soc2', methods=['GET'])
@_login_required
def compliance_soc2():
    """SOC 2 Trust Services Criteria gap analysis (Security)."""
    return _generate_report(
        framework='SOC 2',
        framework_name='SOC 2 Trust Services Criteria (Security)',
        evaluator=_evaluate_soc2,
    )
