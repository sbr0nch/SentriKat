"""
Email notification service for product assignments.
"""
import smtplib
import logging
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
    # Get SMTP configuration from organization
    smtp_config = organization.get_smtp_config()

    # Skip if SMTP not configured
    if not smtp_config.get('host') or not smtp_config.get('from_email'):
        logger.debug(f"SMTP not configured for organization {organization.name}, skipping notification")
        return

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
                        {f'<p style="margin: 5px 0;"><strong>Version:</strong> {product.version}</p>' if product.version else ''}
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
                        {f'<p style="margin: 5px 0;"><strong>Version:</strong> {product.version}</p>' if product.version else ''}
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

    # Send email to each admin
    for admin in org_admins:
        if not admin.email:
            continue

        try:
            msg = MIMEMultipart('alternative')
            msg['From'] = f"{smtp_config['from_name']} <{smtp_config['from_email']}>"
            msg['To'] = admin.email
            msg['Subject'] = subject

            msg.attach(MIMEText(body, 'html'))

            # Connect to SMTP server
            if smtp_config.get('use_ssl'):
                server = smtplib.SMTP_SSL(smtp_config['host'], smtp_config['port'])
            else:
                server = smtplib.SMTP(smtp_config['host'], smtp_config['port'])
                if smtp_config.get('use_tls'):
                    server.starttls()

            # Login if credentials provided
            if smtp_config.get('username') and smtp_config.get('password'):
                server.login(smtp_config['username'], smtp_config['password'])

            # Send email
            server.send_message(msg)
            server.quit()

            logger.info(f"Notification sent to {admin.email} for {action} action on product {product.vendor} {product.product_name}")

        except Exception as e:
            logger.error(f"Failed to send email to {admin.email}: {str(e)}")
            raise
