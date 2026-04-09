"""
Managed email provider abstraction layer.

SaaS mode: Uses Resend API for email delivery (no tenant SMTP config needed).
On-premise: Falls back to traditional SMTP (configured per-org or global).

IMPORTANT: All email sending in the application MUST go through send_email().
           Do NOT import resend or smtplib directly elsewhere.
"""

import os
import logging
import smtplib
import re
from datetime import datetime, date
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from email.mime.base import MIMEBase
from email import encoders

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

RESEND_API_KEY = os.environ.get('RESEND_API_KEY', '')
EMAIL_FROM_ADDRESS = os.environ.get('EMAIL_FROM_ADDRESS', 'noreply@alerts.sentrikat.com')
EMAIL_FROM_NAME = os.environ.get('EMAIL_FROM_NAME', 'SentriKat Alerts')

# Monthly email limits per plan (SaaS)
PLAN_EMAIL_LIMITS = {
    'free': 50,
    'starter': 200,
    'pro': 500,
    'business': 1500,
    'enterprise': 10000,
}

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _obfuscate_email(email_addr):
    """Obfuscate email for logging: user@domain.com → u***@domain.com"""
    if not email_addr or '@' not in email_addr:
        return '***'
    local, domain = email_addr.rsplit('@', 1)
    return f"{local[0]}***@{domain}" if local else f"***@{domain}"


def _get_current_month_key():
    """Return a string like '2026-04' for rate-limit bucketing."""
    return datetime.utcnow().strftime('%Y-%m')


# ---------------------------------------------------------------------------
# Rate limiting (database-backed, no Redis needed)
# ---------------------------------------------------------------------------

def _check_rate_limit(org_id):
    """Check if the org has remaining email quota this month.

    Returns (allowed: bool, remaining: int, limit: int).
    """
    from app.saas import is_saas_mode
    if not is_saas_mode():
        return True, -1, -1  # unlimited on-premise

    from app.models import Organization, Subscription, EmailMonthlyUsage
    from app import db

    org = Organization.query.get(org_id)
    if not org:
        return False, 0, 0

    # Determine plan name
    sub = Subscription.query.filter_by(organization_id=org_id).filter(
        Subscription.status.in_(['active', 'trialing'])
    ).first()
    plan_name = sub.plan.name if (sub and sub.plan) else 'free'
    limit = PLAN_EMAIL_LIMITS.get(plan_name, PLAN_EMAIL_LIMITS['free'])

    month_key = _get_current_month_key()
    usage = EmailMonthlyUsage.query.filter_by(
        organization_id=org_id, month=month_key
    ).first()

    current_count = usage.count if usage else 0
    remaining = max(0, limit - current_count)
    return remaining > 0, remaining, limit


def _increment_usage(org_id):
    """Increment the monthly email counter for an org."""
    from app.saas import is_saas_mode
    if not is_saas_mode():
        return

    from app.models import EmailMonthlyUsage
    from app import db

    month_key = _get_current_month_key()
    usage = EmailMonthlyUsage.query.filter_by(
        organization_id=org_id, month=month_key
    ).first()

    if usage:
        usage.count += 1
    else:
        usage = EmailMonthlyUsage(
            organization_id=org_id, month=month_key, count=1
        )
        db.session.add(usage)

    try:
        db.session.commit()
    except Exception:
        db.session.rollback()


# ---------------------------------------------------------------------------
# Suppression list
# ---------------------------------------------------------------------------

def _is_suppressed(org_id, email_addr):
    """Check if an email address is on the bounce suppression list."""
    from app.models import EmailSuppressionList
    return EmailSuppressionList.query.filter_by(
        organization_id=org_id,
        email=email_addr.lower().strip()
    ).first() is not None


def _filter_suppressed(org_id, recipients):
    """Remove suppressed addresses from a recipient list."""
    from app.models import EmailSuppressionList
    suppressed = {s.email for s in EmailSuppressionList.query.filter_by(
        organization_id=org_id
    ).all()}
    clean = [r for r in recipients if r.lower().strip() not in suppressed]
    dropped = len(recipients) - len(clean)
    if dropped:
        logger.info(f"Filtered {dropped} suppressed recipient(s) for org {org_id}")
    return clean


# ---------------------------------------------------------------------------
# Resend sender
# ---------------------------------------------------------------------------

def _send_via_resend(to_list, subject, html_body, from_addr, from_name,
                     reply_to=None, attachments=None):
    """Send email via Resend API."""
    import resend

    resend.api_key = RESEND_API_KEY

    params = {
        'from': f"{from_name} <{from_addr}>",
        'to': to_list,
        'subject': subject,
        'html': html_body,
    }
    if reply_to:
        params['reply_to'] = reply_to
    if attachments:
        params['attachments'] = attachments

    resp = resend.Emails.send(params)
    return resp


# ---------------------------------------------------------------------------
# SMTP sender (on-premise / custom SMTP fallback)
# ---------------------------------------------------------------------------

def _send_via_smtp(smtp_config, to_list, subject, html_body,
                   reply_to=None, attachments=None):
    """Send email via traditional SMTP (existing logic)."""
    msg = MIMEMultipart('mixed')
    msg['From'] = f"{smtp_config['from_name']} <{smtp_config['from_email']}>"
    msg['To'] = ', '.join(to_list)
    msg['Subject'] = subject
    if reply_to:
        msg['Reply-To'] = reply_to

    html_part = MIMEText(html_body, 'html', 'utf-8')
    msg.attach(html_part)

    # Attach files if any
    if attachments:
        for att in attachments:
            part = MIMEBase('application', 'octet-stream')
            part.set_payload(att['content'])
            encoders.encode_base64(part)
            part.add_header(
                'Content-Disposition', 'attachment',
                filename=att['filename']
            )
            msg.attach(part)

    last_error = None
    for attempt in range(3):
        try:
            if smtp_config.get('use_ssl'):
                server = smtplib.SMTP_SSL(
                    smtp_config['host'], smtp_config['port'], timeout=30)
            else:
                server = smtplib.SMTP(
                    smtp_config['host'], smtp_config['port'], timeout=30)
                if smtp_config.get('use_tls'):
                    server.starttls()

            if smtp_config.get('username') and smtp_config.get('password'):
                server.login(smtp_config['username'], smtp_config['password'])

            server.sendmail(smtp_config['from_email'], to_list, msg.as_string())
            server.quit()
            return  # success
        except Exception as e:
            last_error = e
            if attempt < 2:
                import time
                time.sleep(2 ** (attempt + 1))
    raise last_error


# ---------------------------------------------------------------------------
# White-label template
# ---------------------------------------------------------------------------

def render_email_html(body_content, org=None, subject=''):
    """Wrap body_content in the base email template with optional white-label.

    Business/Enterprise plans with a custom logo get their branding.
    Others get the default SentriKat header.
    """
    from html import escape as html_escape
    from app.saas import is_saas_mode

    logo_url = None
    app_name = 'SentriKat'
    year = datetime.utcnow().year

    if org and is_saas_mode():
        from app.models import Subscription
        sub = Subscription.query.filter_by(organization_id=org.id).filter(
            Subscription.status.in_(['active', 'trialing'])
        ).first()
        plan_name = sub.plan.name if (sub and sub.plan) else 'free'

        # White-label for business/enterprise with custom logo
        if plan_name in ('business', 'enterprise'):
            from app.settings_api import get_setting
            custom_logo = get_setting('logo_url', organization_id=org.id)
            if custom_logo and custom_logo != '/static/images/favicon-128x128.png':
                logo_url = custom_logo
            custom_name = get_setting('app_name', organization_id=org.id)
            if custom_name and custom_name != 'SentriKat':
                app_name = custom_name

    # Escape dynamic values to prevent HTML injection
    safe_app_name = html_escape(app_name)

    # Build header
    if logo_url:
        # White-label: customer logo — validate URL scheme
        if not logo_url.startswith(('http://', 'https://', '/')):
            logo_url = None
    if logo_url:
        safe_logo_url = html_escape(logo_url)
        header_html = f'''
        <div style="background: linear-gradient(135deg, #1e293b 0%, #334155 100%); padding: 24px; text-align: center; border-radius: 12px 12px 0 0;">
            <img src="{safe_logo_url}" alt="{safe_app_name}" style="max-height: 48px; max-width: 200px;">
        </div>'''
    else:
        # Default SentriKat branding
        header_html = '''
        <div style="background: linear-gradient(135deg, #1e40af 0%, #3b82f6 100%); padding: 24px; text-align: center; border-radius: 12px 12px 0 0;">
            <h1 style="color: white; margin: 0; font-size: 22px; font-weight: 600;">SentriKat</h1>
        </div>'''

    return f'''<!DOCTYPE html>
<html><head><meta charset="UTF-8"></head>
<body style="font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Arial, sans-serif; background-color: #f3f4f6; margin: 0; padding: 0;">
<div style="max-width: 600px; margin: 0 auto; padding: 40px 20px;">
    {header_html}
    <div style="background: white; padding: 32px; border-radius: 0 0 12px 12px; box-shadow: 0 4px 6px rgba(0,0,0,0.07);">
        {body_content}
    </div>
    <div style="text-align: center; padding: 20px; color: #9ca3af; font-size: 12px;">
        <p style="margin: 4px 0;">This is an automated message from {safe_app_name}.</p>
        <p style="margin: 4px 0;">&copy; {year} {safe_app_name}</p>
    </div>
</div>
</body></html>'''


# ---------------------------------------------------------------------------
# PUBLIC API — the only function the rest of the app should call
# ---------------------------------------------------------------------------

def send_email(to, subject, html_body, reply_to=None, organization_id=None,
               email_type='system', attachments=None):
    """Send an email through the appropriate provider.

    Args:
        to: Single email string or list of email strings.
        subject: Email subject line.
        html_body: Full HTML body of the email.
        reply_to: Optional Reply-To address.
        organization_id: Tenant ID (for rate limiting, suppression, routing).
        email_type: 'alert', 'report', 'system' (for logging).
        attachments: List of dicts [{'filename': str, 'content': bytes}] or None.

    Returns:
        dict: {'success': bool, 'error': str|None}
    """
    from app.saas import is_saas_mode

    if isinstance(to, str):
        to = [to]
    to = [addr.strip() for addr in to if addr and addr.strip()]

    if not to:
        return {'success': False, 'error': 'No recipients'}

    # --- Validate email addresses ---
    validated = []
    for addr in to:
        if '@' in addr and '.' in addr.split('@')[-1]:
            validated.append(addr)
        else:
            logger.warning(f"Skipping invalid email address: {_obfuscate_email(addr)}")
    to = validated
    if not to:
        return {'success': False, 'error': 'No valid recipients'}

    # --- Suppression list ---
    if organization_id:
        to = _filter_suppressed(organization_id, to)
        if not to:
            logger.info(f"All recipients suppressed for org {organization_id}")
            return {'success': True, 'error': None}  # silent skip

    # --- Rate limiting (SaaS only) ---
    if organization_id and is_saas_mode():
        allowed, remaining, limit = _check_rate_limit(organization_id)
        if not allowed:
            logger.warning(
                f"Email rate limit reached for org {organization_id} "
                f"({limit}/{limit} used this month). Skipping email to "
                f"{[_obfuscate_email(r) for r in to]}, type={email_type}"
            )
            return {'success': False, 'error': 'Monthly email limit reached'}

    # --- Determine routing ---
    use_resend = False

    if is_saas_mode() and organization_id:
        from app.models import Organization
        org = Organization.query.get(organization_id)
        if org and getattr(org, 'use_managed_email', True):
            # Managed email — use Resend
            use_resend = True
            # Apply org's reply_to if set and none provided
            if not reply_to and getattr(org, 'email_reply_to', None):
                reply_to = org.email_reply_to
        elif org:
            # Custom SMTP still configured — use it
            smtp_config = org.get_smtp_config()
            if smtp_config.get('host') and smtp_config.get('from_email'):
                pass  # will use SMTP below
            else:
                use_resend = True  # no custom SMTP, fall back to Resend
    elif is_saas_mode() and not organization_id:
        # System email in SaaS (no org context) — use Resend
        use_resend = True

    # --- Send ---
    log_recipients = [_obfuscate_email(r) for r in to]

    try:
        if use_resend:
            if not RESEND_API_KEY:
                logger.error("RESEND_API_KEY not configured — cannot send managed email")
                return {'success': False, 'error': 'Email provider not configured'}

            resend_attachments = None
            if attachments:
                resend_attachments = [
                    {'filename': a['filename'], 'content': list(a['content'])}
                    for a in attachments
                ]

            _send_via_resend(
                to_list=to,
                subject=subject,
                html_body=html_body,
                from_addr=EMAIL_FROM_ADDRESS,
                from_name=EMAIL_FROM_NAME,
                reply_to=reply_to,
                attachments=resend_attachments,
            )
        else:
            # SMTP path (on-premise or custom SMTP)
            smtp_config = None
            if organization_id:
                from app.models import Organization
                org = Organization.query.get(organization_id)
                if org:
                    smtp_config = org.get_smtp_config()

            # Fallback to global SMTP
            if not smtp_config or not smtp_config.get('host'):
                from app.settings_api import get_setting
                smtp_config = {
                    'host': get_setting('smtp_host', organization_id=None),
                    'port': int(get_setting('smtp_port', '587', organization_id=None) or '587'),
                    'username': get_setting('smtp_username', organization_id=None),
                    'password': get_setting('smtp_password', organization_id=None),
                    'use_tls': get_setting('smtp_use_tls', 'true', organization_id=None) == 'true',
                    'use_ssl': get_setting('smtp_use_ssl', 'false', organization_id=None) == 'true',
                    'from_email': get_setting('smtp_from_email', organization_id=None),
                    'from_name': get_setting('smtp_from_name', 'SentriKat Alerts', organization_id=None),
                }

            if not smtp_config.get('host') or not smtp_config.get('from_email'):
                logger.warning(f"SMTP not configured for org {organization_id}")
                return {'success': False, 'error': 'SMTP not configured'}

            _send_via_smtp(
                smtp_config=smtp_config,
                to_list=to,
                subject=subject,
                html_body=html_body,
                reply_to=reply_to,
                attachments=attachments,
            )

        # --- Success logging & metering ---
        if organization_id and is_saas_mode():
            _increment_usage(organization_id)

        logger.info(
            f"Email sent | org={organization_id} to={log_recipients} "
            f"type={email_type} provider={'resend' if use_resend else 'smtp'}"
        )
        return {'success': True, 'error': None}

    except Exception as e:
        logger.error(
            f"Email failed | org={organization_id} to={log_recipients} "
            f"type={email_type} provider={'resend' if use_resend else 'smtp'} "
            f"error={e}"
        )
        # Return generic error to caller — full details stay in logs
        return {'success': False, 'error': 'Email delivery failed'}
