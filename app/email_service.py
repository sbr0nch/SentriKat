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


def send_remediation_assignment_notification(assignment, organization, action='created'):
    """
    Send email notification when a remediation assignment is created, updated, or resolved.

    Args:
        assignment: RemediationAssignment model instance
        organization: Organization model instance
        action: 'created', 'updated', or 'resolved'
    """
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
        recipients = []

        # Primary recipient: the assigned_to address
        if assignment.assigned_to:
            recipients.append(assignment.assigned_to)

        # CC org admins (same pattern as send_product_assignment_notification)
        org_admins = User.query.filter_by(
            organization_id=organization.id,
            is_active=True
        ).filter(
            (User.role == 'org_admin') | (User.role == 'super_admin') | (User.is_admin == True)
        ).all()

        admin_emails = [a.email for a in org_admins if a.email]
        for email in admin_emails:
            if email not in recipients:
                recipients.append(email)

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
        logger.info(
            f"Sent remediation assignment {action} notification for "
            f"assignment {assignment.id} to {len(recipients)} recipient(s)"
        )

    except Exception as e:
        logger.error(
            f"Failed to send remediation assignment {action} notification "
            f"for assignment {getattr(assignment, 'id', '?')}: {str(e)}"
        )
