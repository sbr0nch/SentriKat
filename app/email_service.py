"""
Email notification service for product and remediation assignments.
"""
import smtplib
import logging
from html import escape as html_escape
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from app.models import User
from config import Config

logger = logging.getLogger(__name__)


def _get_app_url():
    """Get the configured SentriKat URL for email links"""
    return Config.SENTRIKAT_URL or ''


def send_product_assignment_notification(product, organization, action='assigned'):
    """
    Send email notification to organization admins when a product is assigned/removed

    Args:
        product: Product model instance
        organization: Organization model instance
        action: 'assigned' or 'removed'
    """
    # Get org admins
    org_admins = User.query.filter_by(
        organization_id=organization.id,
        is_active=True
    ).filter(
        (User.role == 'org_admin') | (User.role == 'super_admin') | (User.is_admin == True)
    ).all()

    if not org_admins:
        logger.debug(f"No admins found for organization {organization.name}")
        return

    # Prepare email content
    if action == 'assigned':
        subject = f"New Product Added: {product.vendor} {product.product_name}"
        body = f"""
        <html>
        <body style="font-family: Arial, sans-serif; line-height: 1.6; color: #333;">
            <div style="max-width: 600px; margin: 0 auto; padding: 20px;">
                <div style="background: #1e40af; color: white; padding: 20px; border-radius: 8px 8px 0 0;">
                    <h2 style="margin: 0;">New Product Assignment</h2>
                </div>
                <div style="background: #f9fafb; padding: 20px; border: 1px solid #e5e7eb; border-top: none; border-radius: 0 0 8px 8px;">
                    <p>A new product has been assigned to your organization <strong>{organization.display_name}</strong>:</p>

                    <div style="background: white; padding: 15px; border-left: 4px solid #1e40af; margin: 20px 0;">
                        <p style="margin: 5px 0;"><strong>Vendor:</strong> {product.vendor}</p>
                        <p style="margin: 5px 0;"><strong>Product:</strong> {product.product_name}</p>
                        {f'<p style="margin: 5px 0;"><strong>Version:</strong> {html_escape(str(product.version))}</p>' if product.version else ''}
                        <p style="margin: 5px 0;"><strong>Criticality:</strong> <span style="text-transform: uppercase; color: {'#dc2626' if product.criticality == 'critical' else '#f59e0b' if product.criticality == 'high' else '#3b82f6'};">{product.criticality}</span></p>
                    </div>

                    <p>SentriKat will now monitor this product for vulnerabilities and send alerts according to your organization's notification settings.</p>

                    <p style="margin-top: 20px;">
                        <a href="{_get_app_url()}/admin" style="background: #1e40af; color: white; padding: 10px 20px; text-decoration: none; border-radius: 5px; display: inline-block;">View in SentriKat</a>
                    </p>
                </div>
                <div style="margin-top: 20px; padding: 15px; font-size: 12px; color: #6b7280; border-top: 1px solid #e5e7eb;">
                    <p>This is an automated notification from SentriKat.</p>
                </div>
            </div>
        </body>
        </html>
        """
    else:  # removed
        subject = f"Product Removed: {product.vendor} {product.product_name}"
        body = f"""
        <html>
        <body style="font-family: Arial, sans-serif; line-height: 1.6; color: #333;">
            <div style="max-width: 600px; margin: 0 auto; padding: 20px;">
                <div style="background: #dc2626; color: white; padding: 20px; border-radius: 8px 8px 0 0;">
                    <h2 style="margin: 0;">Product Removed</h2>
                </div>
                <div style="background: #f9fafb; padding: 20px; border: 1px solid #e5e7eb; border-top: none; border-radius: 0 0 8px 8px;">
                    <p>A product has been removed from your organization <strong>{organization.display_name}</strong>:</p>

                    <div style="background: white; padding: 15px; border-left: 4px solid #dc2626; margin: 20px 0;">
                        <p style="margin: 5px 0;"><strong>Vendor:</strong> {product.vendor}</p>
                        <p style="margin: 5px 0;"><strong>Product:</strong> {product.product_name}</p>
                        {f'<p style="margin: 5px 0;"><strong>Version:</strong> {html_escape(str(product.version))}</p>' if product.version else ''}
                    </div>

                    <p>SentriKat will no longer monitor this product for your organization.</p>
                </div>
                <div style="margin-top: 20px; padding: 15px; font-size: 12px; color: #6b7280; border-top: 1px solid #e5e7eb;">
                    <p>This is an automated notification from SentriKat.</p>
                </div>
            </div>
        </body>
        </html>
        """

    # Send email to all admins via abstraction layer
    admin_emails = [a.email for a in org_admins if a.email]
    if not admin_emails:
        return

    try:
        from app.email_provider import send_email
        send_email(
            to=admin_emails,
            subject=subject,
            html_body=body,
            organization_id=organization.id,
            email_type='system',
        )
    except Exception as e:
        logger.error(f"Failed to send product {action} notification: {str(e)}")


# In-memory throttle: assignment_id -> last_sent_timestamp
# Prevents rapid-fire emails on bulk updates and protects email quota (e.g. Resend free).
# Cleared on app restart, which is fine: this is a soft throttle, not a hard guarantee.
_ASSIGNMENT_EMAIL_THROTTLE = {}
_ASSIGNMENT_EMAIL_THROTTLE_SECONDS = 3600  # 1 hour minimum between emails per assignment


def send_remediation_assignment_notification(assignment, organization, action='created'):
    """
    Send email notification when a remediation assignment is created or resolved.

    Optimized for low-volume email plans (e.g. Resend free tier = 100/day):
    - Only sends on 'created' and 'resolved' (NOT every status change)
    - Sends only to the assignee (NOT CC org admins - admins use the dashboard)
    - Throttles to max 1 email per assignment per hour
    - Respects organization's alert configuration (alert_on_critical etc.)

    Args:
        assignment: RemediationAssignment model instance
        organization: Organization model instance
        action: 'created' or 'resolved' (any other value is silently ignored)
    """
    # Sprint 4 fix: skip noisy 'updated' actions to preserve email quota
    if action not in ('created', 'resolved'):
        logger.debug(f"Skipping {action} notification (only created/resolved trigger emails)")
        return

    # Sprint 4 fix: rate limit per assignment
    import time
    now = time.time()
    last_sent = _ASSIGNMENT_EMAIL_THROTTLE.get(assignment.id, 0)
    if action != 'resolved' and (now - last_sent) < _ASSIGNMENT_EMAIL_THROTTLE_SECONDS:
        logger.info(
            f"Throttled assignment notification for assignment {assignment.id} "
            f"(last sent {int(now - last_sent)}s ago)"
        )
        return

    # Sprint 4 fix: respect org alert configuration
    # If org has configured alert priority filtering, check if this assignment matches
    priority_lower = (assignment.priority or 'medium').lower()
    if priority_lower == 'critical' and not getattr(organization, 'alert_on_critical', True):
        logger.debug(f"Org {organization.id} has critical alerts disabled, skipping")
        return
    if priority_lower == 'high' and not getattr(organization, 'alert_on_high', False):
        # 'high' alerts are off by default; only send if explicitly enabled
        # For assignments specifically, we still send because the user is notified directly
        pass  # don't skip, assignments are direct notifications

    try:
        from app.email_provider import send_email

        # --- Subject line ---
        subject_map = {
            'created': '[SentriKat] New Remediation Assignment',
            'updated': '[SentriKat] Assignment Updated',
            'resolved': '[SentriKat] Assignment Resolved',
        }
        subject = subject_map.get(action, '[SentriKat] Assignment Notification')

        # --- Priority color mapping ---
        priority_colors = {
            'critical': '#dc2626',
            'high': '#f59e0b',
            'medium': '#3b82f6',
            'low': '#6b7280',
        }
        priority = (assignment.priority or 'medium').lower()
        priority_color = priority_colors.get(priority, '#3b82f6')

        # --- Header color by action ---
        header_color_map = {
            'created': '#1e40af',
            'updated': '#f59e0b',
            'resolved': '#16a34a',
        }
        header_color = header_color_map.get(action, '#1e40af')

        # --- Heading text ---
        heading_map = {
            'created': 'New Remediation Assignment',
            'updated': 'Assignment Updated',
            'resolved': 'Assignment Resolved',
        }
        heading = heading_map.get(action, 'Assignment Notification')

        # --- Build detail rows ---
        app_url = _get_app_url()

        safe_assigned_to = html_escape(str(assignment.assigned_to))
        safe_assigned_by = html_escape(str(assignment.assigned_by))
        safe_status = html_escape(str(assignment.status or 'open'))
        safe_priority = html_escape(priority)
        safe_org_name = html_escape(str(organization.display_name))

        # Optional fields
        due_date_html = ''
        if assignment.due_date:
            safe_due = html_escape(str(assignment.due_date))
            due_date_html = f'<p style="margin: 5px 0;"><strong>Due Date:</strong> {safe_due}</p>'

        cve_html = ''
        if assignment.cve_id:
            safe_cve = html_escape(str(assignment.cve_id))
            cve_html = f'<p style="margin: 5px 0;"><strong>CVE:</strong> {safe_cve}</p>'

        product_html = ''
        if assignment.product:
            safe_vendor = html_escape(str(assignment.product.vendor))
            safe_product = html_escape(str(assignment.product.product_name))
            product_html = (
                f'<p style="margin: 5px 0;"><strong>Vendor:</strong> {safe_vendor}</p>'
                f'<p style="margin: 5px 0;"><strong>Product:</strong> {safe_product}</p>'
            )

        notes_html = ''
        if assignment.notes:
            safe_notes = html_escape(str(assignment.notes))
            notes_html = f'<p style="margin: 5px 0;"><strong>Notes:</strong> {safe_notes}</p>'

        resolution_notes_html = ''
        if action == 'resolved' and assignment.resolution_notes:
            safe_res_notes = html_escape(str(assignment.resolution_notes))
            resolution_notes_html = f'<p style="margin: 5px 0;"><strong>Resolution Notes:</strong> {safe_res_notes}</p>'

        # --- Assemble HTML body ---
        body = f"""
        <html>
        <body style="font-family: Arial, sans-serif; line-height: 1.6; color: #333;">
            <div style="max-width: 600px; margin: 0 auto; padding: 20px;">
                <div style="background: {header_color}; color: white; padding: 20px; border-radius: 8px 8px 0 0;">
                    <h2 style="margin: 0;">{heading}</h2>
                </div>
                <div style="background: #f9fafb; padding: 20px; border: 1px solid #e5e7eb; border-top: none; border-radius: 0 0 8px 8px;">
                    <p>A remediation assignment has been {html_escape(action)} in organization <strong>{safe_org_name}</strong>.</p>

                    <div style="background: white; padding: 15px; border-left: 4px solid {header_color}; margin: 20px 0;">
                        <p style="margin: 5px 0;"><strong>Assigned To:</strong> {safe_assigned_to}</p>
                        <p style="margin: 5px 0;"><strong>Assigned By:</strong> {safe_assigned_by}</p>
                        <p style="margin: 5px 0;"><strong>Priority:</strong> <span style="background: {priority_color}; color: white; padding: 2px 8px; border-radius: 4px; font-size: 12px; text-transform: uppercase;">{safe_priority}</span></p>
                        <p style="margin: 5px 0;"><strong>Status:</strong> {safe_status}</p>
                        {due_date_html}
                        {cve_html}
                        {product_html}
                        {notes_html}
                        {resolution_notes_html}
                    </div>

                    <p style="margin-top: 20px;">
                        <a href="{app_url}/dashboard" style="background: #1e40af; color: white; padding: 10px 20px; text-decoration: none; border-radius: 5px; display: inline-block;">View in SentriKat</a>
                    </p>
                </div>
                <div style="margin-top: 20px; padding: 15px; font-size: 12px; color: #6b7280; border-top: 1px solid #e5e7eb;">
                    <p>This is an automated notification from SentriKat.</p>
                </div>
            </div>
        </body>
        </html>
        """

        # --- Build recipient list ---
        # Sprint 4 fix: only send to assignee, not CC admins (admins have the dashboard).
        # This cuts email volume by ~3-5x and prevents Resend free tier exhaustion.
        recipients = []

        if assignment.assigned_to and '@' in assignment.assigned_to:
            recipients.append(assignment.assigned_to)

        if not recipients:
            logger.debug(
                f"No recipients for remediation assignment {assignment.id} "
                f"in organization {organization.name}"
            )
            return

        send_email(
            to=recipients,
            subject=subject,
            html_body=body,
            organization_id=organization.id,
            email_type='alert',
        )
        # Update throttle timestamp
        _ASSIGNMENT_EMAIL_THROTTLE[assignment.id] = now
        # Cleanup old throttle entries to prevent unbounded memory growth
        if len(_ASSIGNMENT_EMAIL_THROTTLE) > 10000:
            cutoff = now - (_ASSIGNMENT_EMAIL_THROTTLE_SECONDS * 24)
            for k in list(_ASSIGNMENT_EMAIL_THROTTLE.keys()):
                if _ASSIGNMENT_EMAIL_THROTTLE[k] < cutoff:
                    del _ASSIGNMENT_EMAIL_THROTTLE[k]

        logger.info(
            f"Sent remediation assignment {action} notification for "
            f"assignment {assignment.id} to {len(recipients)} recipient(s)"
        )

    except Exception as e:
        logger.error(
            f"Failed to send remediation assignment {action} notification "
            f"for assignment {getattr(assignment, 'id', '?')}: {str(e)}"
        )


# ---------------------------------------------------------------------------
# Patch Tuesday digest
# ---------------------------------------------------------------------------

def send_patch_tuesday_digest(organization, new_vulns_data):
    """
    Send the monthly Patch Tuesday digest email to an organization's admins.

    Runs on the Wednesday after Microsoft's Patch Tuesday release. Summarizes
    new CVEs published in the last 7 days that match the org's tracked
    products, with emphasis on HIGH/CRITICAL, Microsoft, and actively
    exploited vulnerabilities.

    Args:
        organization: Organization model instance.
        new_vulns_data: dict built by the scheduler with the following keys:
            {
                'month_year':        'April 2026',
                'total_new':         int,
                'critical_count':    int,
                'high_count':        int,
                'medium_count':      int,
                'low_count':         int,
                'affected_products': int,     # distinct products in org
                'top_vulns':         [        # top 10 by CVSS
                    {
                        'cve_id':      'CVE-2026-1234',
                        'vendor':      'Microsoft',
                        'product':     'Windows 11',
                        'severity':    'CRITICAL',
                        'cvss_score':  9.8,
                        'is_exploited': True,
                        'description': '...',
                    },
                    ...
                ],
            }

    Returns:
        dict: {'success': bool, 'error': str|None, 'recipients': int}
    """
    try:
        # --- Resolve recipients (org admins) ---
        org_admins = User.query.filter_by(
            organization_id=organization.id,
            is_active=True
        ).filter(
            (User.role == 'org_admin') | (User.role == 'super_admin') | (User.is_admin == True)
        ).all()

        admin_emails = [a.email for a in org_admins if a.email]
        if not admin_emails:
            logger.info(
                f"Patch Tuesday digest: no admin recipients for org "
                f"{organization.name}, skipping"
            )
            return {'success': False, 'error': 'No recipients', 'recipients': 0}

        # --- Extract & escape summary fields ---
        month_year = html_escape(str(new_vulns_data.get('month_year', '')))
        total_new = int(new_vulns_data.get('total_new', 0) or 0)
        critical_count = int(new_vulns_data.get('critical_count', 0) or 0)
        high_count = int(new_vulns_data.get('high_count', 0) or 0)
        medium_count = int(new_vulns_data.get('medium_count', 0) or 0)
        low_count = int(new_vulns_data.get('low_count', 0) or 0)
        affected_products = int(new_vulns_data.get('affected_products', 0) or 0)
        top_vulns = new_vulns_data.get('top_vulns', []) or []

        safe_org_name = html_escape(str(organization.display_name or organization.name))
        app_url = _get_app_url()

        # --- Subject ---
        subject = (
            f"[SentriKat] Patch Tuesday Digest - {month_year} "
            f"({total_new} new CVEs)"
        )

        # --- Severity summary cards ---
        def _severity_card(label, count, color):
            return (
                f'<td align="center" style="padding: 12px; background: white; '
                f'border: 1px solid #e5e7eb; border-radius: 6px; width: 25%;">'
                f'<div style="font-size: 11px; color: #6b7280; '
                f'text-transform: uppercase; letter-spacing: 0.5px;">'
                f'{html_escape(label)}</div>'
                f'<div style="font-size: 24px; font-weight: 700; color: {color}; '
                f'margin-top: 4px;">{count}</div>'
                f'</td>'
            )

        severity_table = (
            '<table role="presentation" width="100%" cellspacing="8" '
            'cellpadding="0" style="margin: 16px 0;"><tr>'
            + _severity_card('Critical', critical_count, '#dc2626')
            + _severity_card('High', high_count, '#f59e0b')
            + _severity_card('Medium', medium_count, '#3b82f6')
            + _severity_card('Low', low_count, '#6b7280')
            + '</tr></table>'
        )

        # --- Top 10 rows ---
        severity_colors = {
            'CRITICAL': '#dc2626',
            'HIGH': '#f59e0b',
            'MEDIUM': '#3b82f6',
            'LOW': '#6b7280',
        }

        if top_vulns:
            rows_html = ''
            for v in top_vulns[:10]:
                safe_cve = html_escape(str(v.get('cve_id', '')))
                safe_vendor = html_escape(str(v.get('vendor', '') or ''))
                safe_product = html_escape(str(v.get('product', '') or ''))
                severity = (v.get('severity') or 'UNKNOWN').upper()
                safe_severity = html_escape(severity)
                sev_color = severity_colors.get(severity, '#6b7280')
                cvss_score = v.get('cvss_score')
                safe_cvss = (
                    html_escape(f"{cvss_score:.1f}")
                    if isinstance(cvss_score, (int, float)) else 'N/A'
                )
                exploited_badge = ''
                if v.get('is_exploited'):
                    exploited_badge = (
                        '<span style="background: #dc2626; color: white; '
                        'padding: 2px 6px; border-radius: 3px; font-size: 10px; '
                        'margin-left: 6px; text-transform: uppercase;">'
                        'Exploited</span>'
                    )
                cve_link = f"{app_url}/vulnerabilities?search={safe_cve}" if app_url else '#'
                safe_cve_link = html_escape(cve_link)

                rows_html += (
                    '<tr>'
                    f'<td style="padding: 10px; border-bottom: 1px solid #e5e7eb; '
                    f'font-family: monospace; font-size: 13px;">'
                    f'<a href="{safe_cve_link}" style="color: #1e40af; '
                    f'text-decoration: none;">{safe_cve}</a>{exploited_badge}'
                    '</td>'
                    f'<td style="padding: 10px; border-bottom: 1px solid #e5e7eb; '
                    f'font-size: 13px;">{safe_vendor} {safe_product}</td>'
                    f'<td style="padding: 10px; border-bottom: 1px solid #e5e7eb; '
                    f'text-align: center;">'
                    f'<span style="background: {sev_color}; color: white; '
                    f'padding: 2px 8px; border-radius: 4px; font-size: 11px; '
                    f'font-weight: 600;">{safe_severity}</span>'
                    '</td>'
                    f'<td style="padding: 10px; border-bottom: 1px solid #e5e7eb; '
                    f'text-align: right; font-weight: 600; font-size: 13px;">'
                    f'{safe_cvss}</td>'
                    '</tr>'
                )

            top_vulns_html = (
                '<h3 style="margin: 24px 0 8px 0; color: #1e40af; '
                'font-size: 16px;">Top New CVEs (by CVSS)</h3>'
                '<table role="presentation" width="100%" cellspacing="0" '
                'cellpadding="0" style="background: white; '
                'border: 1px solid #e5e7eb; border-radius: 6px; '
                'border-collapse: separate; border-spacing: 0;">'
                '<thead><tr style="background: #f3f4f6;">'
                '<th align="left" style="padding: 10px; font-size: 11px; '
                'color: #6b7280; text-transform: uppercase;">CVE</th>'
                '<th align="left" style="padding: 10px; font-size: 11px; '
                'color: #6b7280; text-transform: uppercase;">Product</th>'
                '<th align="center" style="padding: 10px; font-size: 11px; '
                'color: #6b7280; text-transform: uppercase;">Severity</th>'
                '<th align="right" style="padding: 10px; font-size: 11px; '
                'color: #6b7280; text-transform: uppercase;">CVSS</th>'
                f'</tr></thead><tbody>{rows_html}</tbody></table>'
            )
        else:
            top_vulns_html = (
                '<p style="color: #6b7280; font-style: italic; '
                'margin: 16px 0;">No matching CVEs were published this cycle.</p>'
            )

        dashboard_url = f"{app_url}/dashboard" if app_url else '#'
        safe_dashboard_url = html_escape(dashboard_url)

        body = f"""
        <html>
        <body style="font-family: Arial, sans-serif; line-height: 1.6; color: #333;">
            <div style="max-width: 640px; margin: 0 auto; padding: 20px;">
                <div style="background: #1e40af; color: white; padding: 20px; border-radius: 8px 8px 0 0;">
                    <h2 style="margin: 0;">Patch Tuesday Digest - {month_year}</h2>
                    <p style="margin: 6px 0 0 0; font-size: 13px; opacity: 0.9;">
                        New vulnerabilities affecting {safe_org_name}
                    </p>
                </div>
                <div style="background: #f9fafb; padding: 20px; border: 1px solid #e5e7eb; border-top: none; border-radius: 0 0 8px 8px;">
                    <p style="margin-top: 0;">
                        <strong>{total_new}</strong> new CVE{'s' if total_new != 1 else ''}
                        published in the last 7 days match your tracked products,
                        affecting <strong>{affected_products}</strong>
                        product{'s' if affected_products != 1 else ''} in your organization.
                    </p>

                    {severity_table}

                    {top_vulns_html}

                    <p style="margin-top: 24px; text-align: center;">
                        <a href="{safe_dashboard_url}" style="background: #1e40af; color: white; padding: 12px 28px; text-decoration: none; border-radius: 6px; display: inline-block; font-weight: 600;">View in SentriKat dashboard</a>
                    </p>
                </div>
                <div style="margin-top: 20px; padding: 15px; font-size: 12px; color: #6b7280; border-top: 1px solid #e5e7eb;">
                    <p>This is an automated Patch Tuesday digest from SentriKat.</p>
                    <p>You are receiving this because you are an administrator of {safe_org_name}.</p>
                </div>
            </div>
        </body>
        </html>
        """

        from app.email_provider import send_email
        result = send_email(
            to=admin_emails,
            subject=subject,
            html_body=body,
            organization_id=organization.id,
            email_type='report',
        )

        if result.get('success'):
            logger.info(
                f"Patch Tuesday digest sent to {len(admin_emails)} admin(s) "
                f"for org {organization.name}: {total_new} new CVEs"
            )
            return {'success': True, 'error': None, 'recipients': len(admin_emails)}
        else:
            logger.error(
                f"Patch Tuesday digest failed for org {organization.name}: "
                f"{result.get('error')}"
            )
            return {
                'success': False,
                'error': result.get('error'),
                'recipients': len(admin_emails),
            }

    except Exception as e:
        logger.error(
            f"Failed to send Patch Tuesday digest for org "
            f"{getattr(organization, 'name', '?')}: {e}",
            exc_info=True,
        )
        return {'success': False, 'error': str(e), 'recipients': 0}
