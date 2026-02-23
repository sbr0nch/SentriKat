"""
Digest email system for SentriKat.
Sends daily or weekly vulnerability digest summaries to organizations.

Reuses the existing SMTP infrastructure from app/email_alerts.py.
"""

import json
import logging
from datetime import datetime, timedelta, date

from app import db
from app.models import (
    Organization, VulnerabilityMatch, Vulnerability, Product,
    AlertLog, product_organizations
)
from app.email_alerts import EmailAlertManager, get_app_url

logger = logging.getLogger(__name__)


def generate_digest(org, period='daily'):
    """Generate vulnerability digest data for an organization.

    Args:
        org: Organization instance
        period: 'daily' or 'weekly'

    Returns:
        dict with:
            - new_vulnerabilities: CVEs added since last digest
            - new_matches: New product matches
            - resolved_matches: Matches acknowledged/resolved in period
            - stats: Summary counts
            - period: The period string
            - period_start: Start of the digest period
            - period_end: End of the digest period
    """
    now = datetime.utcnow()

    if period == 'weekly':
        period_start = now - timedelta(days=7)
    else:
        period_start = now - timedelta(days=1)

    # Get product IDs for this organization (legacy + multi-org)
    legacy_ids = db.session.query(Product.id).filter(
        Product.organization_id == org.id
    )
    multi_org_ids = db.session.query(product_organizations.c.product_id).filter(
        product_organizations.c.organization_id == org.id
    )
    org_product_ids = legacy_ids.union(multi_org_ids).scalar_subquery()

    # New matches created during the period
    new_matches = VulnerabilityMatch.query.filter(
        VulnerabilityMatch.product_id.in_(org_product_ids),
        VulnerabilityMatch.created_at >= period_start
    ).all()

    # Resolved/acknowledged matches during the period
    resolved_matches = VulnerabilityMatch.query.filter(
        VulnerabilityMatch.product_id.in_(org_product_ids),
        VulnerabilityMatch.acknowledged == True,
        VulnerabilityMatch.acknowledged_at >= period_start
    ).all()

    # All currently unacknowledged matches (for total count)
    total_unacknowledged = VulnerabilityMatch.query.filter(
        VulnerabilityMatch.product_id.in_(org_product_ids),
        VulnerabilityMatch.acknowledged == False
    ).count()

    # New vulnerabilities (unique CVEs) from new matches
    new_vuln_ids = set()
    new_vulnerabilities = []
    for match in new_matches:
        if match.vulnerability and match.vulnerability_id not in new_vuln_ids:
            new_vuln_ids.add(match.vulnerability_id)
            new_vulnerabilities.append(match.vulnerability)

    # Categorize by severity
    severity_counts = {'critical': 0, 'high': 0, 'medium': 0, 'low': 0}
    for vuln in new_vulnerabilities:
        priority = vuln.calculate_priority()
        if priority in severity_counts:
            severity_counts[priority] += 1

    # Count actively exploited
    actively_exploited = sum(
        1 for v in new_vulnerabilities if v.is_actively_exploited
    )

    # Count ransomware-related
    ransomware_count = sum(
        1 for v in new_vulnerabilities if v.known_ransomware
    )

    stats = {
        'new_vulnerabilities': len(new_vulnerabilities),
        'new_matches': len(new_matches),
        'resolved_matches': len(resolved_matches),
        'total_unacknowledged': total_unacknowledged,
        'severity': severity_counts,
        'actively_exploited': actively_exploited,
        'ransomware': ransomware_count,
    }

    return {
        'new_vulnerabilities': new_vulnerabilities,
        'new_matches': new_matches,
        'resolved_matches': resolved_matches,
        'stats': stats,
        'period': period,
        'period_start': period_start,
        'period_end': now,
    }


def send_digest_email(org, digest_data, period='daily'):
    """Send digest email using the organization's SMTP settings.

    Reuses the existing EmailAlertManager._send_email infrastructure.

    Args:
        org: Organization instance
        digest_data: dict from generate_digest()
        period: 'daily' or 'weekly'

    Returns:
        dict with 'status' and details
    """
    stats = digest_data['stats']

    # Skip if nothing to report
    if (stats['new_vulnerabilities'] == 0 and
            stats['resolved_matches'] == 0 and
            stats['total_unacknowledged'] == 0):
        return {'status': 'skipped', 'reason': 'Nothing to report'}

    # Get SMTP config - try organization first, then fall back to global
    smtp_config = org.get_smtp_config()
    if not smtp_config['host'] or not smtp_config['from_email']:
        from app.settings_api import get_setting
        smtp_config = {
            'host': get_setting('smtp_host'),
            'port': int(get_setting('smtp_port', '587') or '587'),
            'username': get_setting('smtp_username'),
            'password': get_setting('smtp_password'),
            'use_tls': get_setting('smtp_use_tls', 'true') == 'true',
            'use_ssl': get_setting('smtp_use_ssl', 'false') == 'true',
            'from_email': get_setting('smtp_from_email'),
            'from_name': get_setting('smtp_from_name', 'SentriKat Alerts')
        }

    if not smtp_config['host'] or not smtp_config['from_email']:
        return {'status': 'error', 'reason': 'SMTP not configured'}

    # Get recipients
    recipients = []
    if org.notification_emails:
        try:
            parsed = json.loads(org.notification_emails)
            if isinstance(parsed, str):
                parsed = json.loads(parsed)
            recipients = parsed if isinstance(parsed, list) else []
        except (json.JSONDecodeError, TypeError):
            recipients = []

    if not recipients:
        return {'status': 'error', 'reason': 'No recipients configured'}

    # Build email
    period_label = 'Weekly' if period == 'weekly' else 'Daily'
    subject = (
        f"SentriKat {period_label} Digest: "
        f"{stats['new_vulnerabilities']} new, "
        f"{stats['total_unacknowledged']} unresolved - "
        f"{org.display_name}"
    )

    html_body = _build_digest_email_html(org, digest_data, period)

    try:
        EmailAlertManager._send_email(
            smtp_config=smtp_config,
            recipients=recipients,
            subject=subject,
            html_body=html_body
        )

        # Log success
        _log_digest_alert(org.id, period, stats, len(recipients), 'success', None)

        return {
            'status': 'success',
            'sent_to': len(recipients),
            'stats': stats
        }
    except Exception as e:
        _log_digest_alert(org.id, period, stats, len(recipients), 'failed', str(e))
        return {'status': 'error', 'reason': str(e)}


def _log_digest_alert(org_id, period, stats, recipients_count, status, error_msg):
    """Log digest alert to the AlertLog table."""
    try:
        log = AlertLog(
            organization_id=org_id,
            alert_type=f'digest_{period}',
            matches_count=stats.get('new_matches', 0),
            recipients_count=recipients_count,
            status=status,
            error_message=error_msg
        )
        db.session.add(log)
        db.session.commit()
    except Exception as e:
        logger.warning(f"Failed to log digest alert: {e}")
        try:
            db.session.rollback()
        except Exception:
            pass


def process_digests(period='daily'):
    """Process digests for all organizations that have digest enabled.

    Args:
        period: 'daily' or 'weekly'

    Returns:
        dict with summary of results
    """
    results = {
        'total_orgs': 0,
        'sent': 0,
        'skipped': 0,
        'errors': 0,
        'details': []
    }

    try:
        # Find organizations with digest enabled and matching frequency
        orgs = Organization.query.filter(
            Organization.active == True,
            Organization.digest_enabled == True,
        ).all()

        results['total_orgs'] = len(orgs)

        for org in orgs:
            try:
                # Check if this org's digest frequency matches the requested period
                org_frequency = getattr(org, 'digest_frequency', 'daily') or 'daily'
                if org_frequency != period:
                    results['skipped'] += 1
                    continue

                # For weekly digests, check if today matches the configured day
                if period == 'weekly':
                    org_day = getattr(org, 'digest_day', 'monday') or 'monday'
                    current_day = datetime.utcnow().strftime('%A').lower()
                    if current_day != org_day:
                        results['skipped'] += 1
                        continue

                # Generate and send digest
                digest_data = generate_digest(org, period)
                result = send_digest_email(org, digest_data, period)

                results['details'].append({
                    'organization': org.name,
                    'result': result
                })

                if result['status'] == 'success':
                    results['sent'] += 1
                elif result['status'] == 'skipped':
                    results['skipped'] += 1
                else:
                    results['errors'] += 1
                    logger.error(
                        f"Digest email failed for {org.name}: {result.get('reason')}"
                    )

            except Exception as e:
                results['errors'] += 1
                logger.error(
                    f"Error processing digest for {org.name}: {e}",
                    exc_info=True
                )

    except Exception as e:
        logger.error(f"Digest processing failed: {e}", exc_info=True)

    logger.info(
        f"{period.title()} digest processing complete: "
        f"{results['sent']} sent, {results['skipped']} skipped, "
        f"{results['errors']} errors"
    )

    return results


def _build_digest_email_html(org, digest_data, period):
    """Build HTML email body for the digest.

    Args:
        org: Organization instance
        digest_data: dict from generate_digest()
        period: 'daily' or 'weekly'

    Returns:
        HTML string
    """
    stats = digest_data['stats']
    period_label = 'Weekly' if period == 'weekly' else 'Daily'
    period_start = digest_data['period_start']
    period_end = digest_data['period_end']
    app_url = get_app_url()

    severity = stats['severity']

    # Build new vulnerabilities table rows (top 10)
    vuln_rows_html = ''
    for vuln in digest_data['new_vulnerabilities'][:10]:
        priority = vuln.calculate_priority()
        priority_colors = {
            'critical': '#dc2626',
            'high': '#ea580c',
            'medium': '#ca8a04',
            'low': '#059669'
        }
        color = priority_colors.get(priority, '#6b7280')
        cvss = vuln.cvss_score or 'N/A'
        exploited_badge = (
            '<span style="background: #b91c1c; color: white; padding: 1px 5px; '
            'border-radius: 3px; font-size: 10px; font-weight: 600; margin-left: 4px;">'
            'EXPLOITED</span>'
            if vuln.is_actively_exploited else ''
        )
        ransomware_badge = (
            '<span style="background: #7c2d12; color: white; padding: 1px 5px; '
            'border-radius: 3px; font-size: 10px; font-weight: 600; margin-left: 4px;">'
            'RANSOMWARE</span>'
            if vuln.known_ransomware else ''
        )
        description = (vuln.short_description or '')[:120]
        if len(vuln.short_description or '') > 120:
            description += '...'

        vuln_rows_html += f"""
        <tr>
            <td style="padding: 10px 12px; border-bottom: 1px solid #f3f4f6;">
                <a href="https://nvd.nist.gov/vuln/detail/{vuln.cve_id}"
                   style="color: #1e40af; text-decoration: none; font-weight: 600;">
                    {vuln.cve_id}
                </a>
                {exploited_badge}
                {ransomware_badge}
                <div style="font-size: 12px; color: #6b7280; margin-top: 2px;">
                    {description}
                </div>
            </td>
            <td style="padding: 10px 8px; border-bottom: 1px solid #f3f4f6; text-align: center;">
                <span style="color: {color}; font-weight: 700;">{cvss}</span>
            </td>
            <td style="padding: 10px 8px; border-bottom: 1px solid #f3f4f6; text-align: center;">
                <span style="background: {color}; color: white; padding: 2px 8px;
                       border-radius: 4px; font-size: 11px; font-weight: 600;
                       text-transform: uppercase;">{priority}</span>
            </td>
        </tr>"""

    remaining_vulns = len(digest_data['new_vulnerabilities']) - 10
    if remaining_vulns > 0:
        vuln_rows_html += f"""
        <tr>
            <td colspan="3" style="padding: 10px 12px; text-align: center; color: #6b7280; font-size: 13px;">
                + {remaining_vulns} more vulnerabilit{'y' if remaining_vulns == 1 else 'ies'}
                - <a href="{app_url}" style="color: #1e40af; text-decoration: none;">View all in dashboard</a>
            </td>
        </tr>"""

    # Resolved matches summary
    resolved_html = ''
    if stats['resolved_matches'] > 0:
        resolved_html = f"""
        <div style="margin-top: 24px;">
            <div style="font-size: 13px; font-weight: 600; color: #374151; text-transform: uppercase;
                        letter-spacing: 0.5px; margin-bottom: 12px;">
                Resolved This {period_label.rstrip('ly')} Period
            </div>
            <div style="background: #f0fdf4; border: 1px solid #bbf7d0; border-radius: 6px; padding: 16px;">
                <span style="font-size: 24px; font-weight: 700; color: #16a34a;">
                    {stats['resolved_matches']}
                </span>
                <span style="color: #166534; margin-left: 8px;">
                    vulnerabilit{'y' if stats['resolved_matches'] == 1 else 'ies'} acknowledged/resolved
                </span>
            </div>
        </div>"""

    # No new vulnerabilities message
    no_vulns_html = ''
    if stats['new_vulnerabilities'] == 0:
        no_vulns_html = """
        <div style="background: #f0fdf4; border: 1px solid #bbf7d0; border-radius: 6px;
                    padding: 20px; text-align: center; margin-top: 16px;">
            <span style="font-size: 16px; color: #16a34a; font-weight: 600;">
                No new vulnerabilities detected this period
            </span>
        </div>"""

    html = f"""
<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
</head>
<body style="margin: 0; padding: 0; background-color: #f8fafc;
             font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto,
             'Helvetica Neue', Arial, sans-serif; line-height: 1.5;">
    <table role="presentation" width="100%" cellspacing="0" cellpadding="0"
           style="background-color: #f8fafc;">
        <tr>
            <td align="center" style="padding: 32px 16px;">
                <table role="presentation" width="100%" cellspacing="0" cellpadding="0"
                       style="max-width: 600px; background-color: #ffffff; border-radius: 8px;
                              box-shadow: 0 1px 3px rgba(0,0,0,0.1);">

                    <!-- Header -->
                    <tr>
                        <td style="padding: 24px 32px; border-bottom: 1px solid #e5e7eb;">
                            <table role="presentation" width="100%" cellspacing="0" cellpadding="0">
                                <tr>
                                    <td>
                                        <span style="font-size: 20px; font-weight: 700; color: #1e40af;">
                                            SentriKat
                                        </span>
                                        <span style="color: #9ca3af; margin-left: 8px;">|</span>
                                        <span style="color: #6b7280; margin-left: 8px; font-size: 14px;">
                                            {period_label} Digest
                                        </span>
                                    </td>
                                    <td align="right">
                                        <span style="font-size: 12px; color: #9ca3af;">
                                            {period_end.strftime('%Y-%m-%d %H:%M')} UTC
                                        </span>
                                    </td>
                                </tr>
                            </table>
                        </td>
                    </tr>

                    <!-- Digest Body -->
                    <tr>
                        <td style="padding: 32px;">
                            <!-- Organization Badge -->
                            <div style="margin-bottom: 16px;">
                                <span style="display: inline-block; background: #1e40af; color: #ffffff;
                                             padding: 3px 10px; border-radius: 4px; font-size: 12px;
                                             font-weight: 600; text-transform: uppercase;
                                             letter-spacing: 0.5px;">
                                    {org.display_name}
                                </span>
                                <span style="color: #9ca3af; font-size: 12px; margin-left: 8px;">
                                    {period_start.strftime('%b %d')} - {period_end.strftime('%b %d, %Y')}
                                </span>
                            </div>

                            <!-- Stats Row -->
                            <table role="presentation" width="100%" cellspacing="0" cellpadding="0"
                                   style="margin-bottom: 24px; background: #f9fafb; border-radius: 6px;
                                          border: 1px solid #e5e7eb;">
                                <tr>
                                    <td width="25%" style="text-align: center; padding: 16px 8px;">
                                        <div style="font-size: 28px; font-weight: 700; color: #1e40af;">
                                            {stats['new_vulnerabilities']}
                                        </div>
                                        <div style="font-size: 11px; color: #6b7280;
                                                    text-transform: uppercase;">New CVEs</div>
                                    </td>
                                    <td width="25%" style="text-align: center; padding: 16px 8px;
                                                          border-left: 1px solid #e5e7eb;">
                                        <div style="font-size: 28px; font-weight: 700; color: #dc2626;">
                                            {severity['critical']}
                                        </div>
                                        <div style="font-size: 11px; color: #6b7280;
                                                    text-transform: uppercase;">Critical</div>
                                    </td>
                                    <td width="25%" style="text-align: center; padding: 16px 8px;
                                                          border-left: 1px solid #e5e7eb;">
                                        <div style="font-size: 28px; font-weight: 700; color: #16a34a;">
                                            {stats['resolved_matches']}
                                        </div>
                                        <div style="font-size: 11px; color: #6b7280;
                                                    text-transform: uppercase;">Resolved</div>
                                    </td>
                                    <td width="25%" style="text-align: center; padding: 16px 8px;
                                                          border-left: 1px solid #e5e7eb;">
                                        <div style="font-size: 28px; font-weight: 700; color: #ea580c;">
                                            {stats['total_unacknowledged']}
                                        </div>
                                        <div style="font-size: 11px; color: #6b7280;
                                                    text-transform: uppercase;">Unresolved</div>
                                    </td>
                                </tr>
                            </table>

                            <!-- Severity Breakdown -->
                            <div style="margin-bottom: 24px;">
                                <div style="font-size: 13px; font-weight: 600; color: #374151;
                                            text-transform: uppercase; letter-spacing: 0.5px;
                                            margin-bottom: 8px;">
                                    New Vulnerabilities by Severity
                                </div>
                                <table role="presentation" width="100%" cellspacing="0" cellpadding="0">
                                    <tr>
                                        <td style="padding: 4px 0;">
                                            <table role="presentation" width="100%" cellspacing="0"
                                                   cellpadding="0">
                                                <tr>
                                                    <td width="70" style="font-size: 12px; color: #6b7280;">
                                                        Critical
                                                    </td>
                                                    <td>
                                                        <div style="background: #fee2e2; border-radius: 4px;
                                                                    height: 20px; position: relative;">
                                                            <div style="background: #dc2626; border-radius: 4px;
                                                                        height: 20px;
                                                                        width: {min(severity['critical'] * 10, 100)}%;
                                                                        min-width: {20 if severity['critical'] > 0 else 0}px;">
                                                            </div>
                                                        </div>
                                                    </td>
                                                    <td width="30" style="text-align: right; font-size: 12px;
                                                                         font-weight: 600; color: #dc2626;">
                                                        {severity['critical']}
                                                    </td>
                                                </tr>
                                            </table>
                                        </td>
                                    </tr>
                                    <tr>
                                        <td style="padding: 4px 0;">
                                            <table role="presentation" width="100%" cellspacing="0"
                                                   cellpadding="0">
                                                <tr>
                                                    <td width="70" style="font-size: 12px; color: #6b7280;">
                                                        High
                                                    </td>
                                                    <td>
                                                        <div style="background: #fed7aa; border-radius: 4px;
                                                                    height: 20px; position: relative;">
                                                            <div style="background: #ea580c; border-radius: 4px;
                                                                        height: 20px;
                                                                        width: {min(severity['high'] * 10, 100)}%;
                                                                        min-width: {20 if severity['high'] > 0 else 0}px;">
                                                            </div>
                                                        </div>
                                                    </td>
                                                    <td width="30" style="text-align: right; font-size: 12px;
                                                                         font-weight: 600; color: #ea580c;">
                                                        {severity['high']}
                                                    </td>
                                                </tr>
                                            </table>
                                        </td>
                                    </tr>
                                    <tr>
                                        <td style="padding: 4px 0;">
                                            <table role="presentation" width="100%" cellspacing="0"
                                                   cellpadding="0">
                                                <tr>
                                                    <td width="70" style="font-size: 12px; color: #6b7280;">
                                                        Medium
                                                    </td>
                                                    <td>
                                                        <div style="background: #fef9c3; border-radius: 4px;
                                                                    height: 20px; position: relative;">
                                                            <div style="background: #ca8a04; border-radius: 4px;
                                                                        height: 20px;
                                                                        width: {min(severity['medium'] * 10, 100)}%;
                                                                        min-width: {20 if severity['medium'] > 0 else 0}px;">
                                                            </div>
                                                        </div>
                                                    </td>
                                                    <td width="30" style="text-align: right; font-size: 12px;
                                                                         font-weight: 600; color: #ca8a04;">
                                                        {severity['medium']}
                                                    </td>
                                                </tr>
                                            </table>
                                        </td>
                                    </tr>
                                    <tr>
                                        <td style="padding: 4px 0;">
                                            <table role="presentation" width="100%" cellspacing="0"
                                                   cellpadding="0">
                                                <tr>
                                                    <td width="70" style="font-size: 12px; color: #6b7280;">
                                                        Low
                                                    </td>
                                                    <td>
                                                        <div style="background: #dcfce7; border-radius: 4px;
                                                                    height: 20px; position: relative;">
                                                            <div style="background: #059669; border-radius: 4px;
                                                                        height: 20px;
                                                                        width: {min(severity['low'] * 10, 100)}%;
                                                                        min-width: {20 if severity['low'] > 0 else 0}px;">
                                                            </div>
                                                        </div>
                                                    </td>
                                                    <td width="30" style="text-align: right; font-size: 12px;
                                                                         font-weight: 600; color: #059669;">
                                                        {severity['low']}
                                                    </td>
                                                </tr>
                                            </table>
                                        </td>
                                    </tr>
                                </table>
                            </div>

                            {no_vulns_html}

                            <!-- New Vulnerabilities Table -->
                            {'<div style="margin-bottom: 24px;">' if stats['new_vulnerabilities'] > 0 else '<!--'}
                                <div style="font-size: 13px; font-weight: 600; color: #374151;
                                            text-transform: uppercase; letter-spacing: 0.5px;
                                            margin-bottom: 12px;">
                                    New Vulnerabilities
                                </div>
                                <table role="presentation" width="100%" cellspacing="0" cellpadding="0"
                                       style="border: 1px solid #e5e7eb; border-radius: 6px;">
                                    <tr style="background: #f9fafb;">
                                        <td style="padding: 8px 12px; font-size: 11px; font-weight: 600;
                                                   color: #6b7280; text-transform: uppercase;">CVE</td>
                                        <td style="padding: 8px; font-size: 11px; font-weight: 600;
                                                   color: #6b7280; text-transform: uppercase;
                                                   text-align: center;" width="60">CVSS</td>
                                        <td style="padding: 8px; font-size: 11px; font-weight: 600;
                                                   color: #6b7280; text-transform: uppercase;
                                                   text-align: center;" width="80">Severity</td>
                                    </tr>
                                    {vuln_rows_html}
                                </table>
                            {'</div>' if stats['new_vulnerabilities'] > 0 else '-->'}

                            {resolved_html}

                            <!-- CTA Button -->
                            <div style="text-align: center; margin-top: 24px; margin-bottom: 8px;">
                                <a href="{app_url}"
                                   style="display: inline-block; background: #1e40af; color: #ffffff;
                                          text-decoration: none; padding: 12px 28px; border-radius: 6px;
                                          font-weight: 600; font-size: 14px;">
                                    View Dashboard
                                </a>
                            </div>
                        </td>
                    </tr>

                    <!-- Footer -->
                    <tr>
                        <td style="padding: 24px 32px; border-top: 1px solid #e5e7eb; text-align: center;">
                            <p style="margin: 0; font-size: 12px; color: #9ca3af;">
                                {period_label} digest from SentriKat - {org.display_name}
                            </p>
                            <p style="margin: 8px 0 0 0; font-size: 11px; color: #d1d5db;">
                                Covering {period_start.strftime('%b %d')} to {period_end.strftime('%b %d, %Y')} UTC
                            </p>
                        </td>
                    </tr>

                </table>
            </td>
        </tr>
    </table>
</body>
</html>
"""

    return html
