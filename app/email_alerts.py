"""
Email alert system for critical CVE notifications
Supports: Internal SMTP, Gmail, Office365, and other SMTP providers
"""

import smtplib
import json
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from datetime import datetime, date, time as dt_time
from app.models import Organization, VulnerabilityMatch, AlertLog, Vulnerability
from app import db
from config import Config


def get_app_url():
    """Get the configured SentriKat URL or fallback to localhost"""
    return Config.SENTRIKAT_URL or 'http://localhost:5001'

class EmailAlertManager:
    """Manages email alerts for critical vulnerabilities"""

    @staticmethod
    def should_send_alert_now(organization):
        """Check if current time is within organization's alert window"""
        if not organization.alert_time_start or not organization.alert_time_end:
            return True  # No time restriction

        current_time = datetime.now().time()
        current_day = datetime.now().strftime('%a').lower()

        # Check if today is in alert days
        alert_days = [day.strip() for day in organization.alert_days.split(',')]
        if current_day not in alert_days:
            return False

        # Parse time strings
        start_time = datetime.strptime(organization.alert_time_start, '%H:%M').time()
        end_time = datetime.strptime(organization.alert_time_end, '%H:%M').time()

        # Check if current time is within window
        if start_time <= end_time:
            return start_time <= current_time <= end_time
        else:  # Handle midnight crossing (e.g., 22:00 - 02:00)
            return current_time >= start_time or current_time <= end_time

    @staticmethod
    def send_critical_cve_alert(organization, new_matches):
        """
        Send email alert for new critical CVEs

        Args:
            organization: Organization object with SMTP settings
            new_matches: List of VulnerabilityMatch objects that are new/critical

        Returns:
            dict: Status result with 'status', 'sent_to', 'matches_count', or 'reason'
        """
        if not new_matches:
            return {'status': 'skipped', 'reason': 'No new matches'}

        # Check if we should send alerts now
        if not EmailAlertManager.should_send_alert_now(organization):
            return {'status': 'skipped', 'reason': 'Outside alert time window'}

        # Get SMTP config
        smtp_config = organization.get_smtp_config()
        if not smtp_config['host'] or not smtp_config['from_email']:
            return {'status': 'error', 'reason': 'SMTP not configured'}

        # Get recipient emails
        recipients = json.loads(organization.notification_emails) if organization.notification_emails else []
        if not recipients:
            return {'status': 'error', 'reason': 'No recipients configured'}

        # Filter matches by alert settings
        filtered_matches = []
        for match in new_matches:
            priority = match.calculate_effective_priority()
            vuln = match.vulnerability

            should_alert = False

            # Check alert settings
            if organization.alert_on_critical and priority == 'critical':
                should_alert = True
            elif organization.alert_on_high and priority in ['high', 'critical']:
                should_alert = True
            elif organization.alert_on_ransomware and vuln.known_ransomware:
                should_alert = True
            elif organization.alert_on_new_cve:
                # New CVE within 7 days
                days_old = (date.today() - vuln.date_added).days if vuln.date_added else 999
                if days_old <= 7:
                    should_alert = True

            if should_alert:
                filtered_matches.append(match)

        if not filtered_matches:
            return {'status': 'skipped', 'reason': 'No matches meet alert criteria'}

        # Build email
        subject = f"🚨 SentriKat Alert: {len(filtered_matches)} Critical Vulnerabilities Detected"
        body = EmailAlertManager._build_alert_email_html(organization, filtered_matches)

        # Send email
        try:
            EmailAlertManager._send_email(
                smtp_config=smtp_config,
                recipients=recipients,
                subject=subject,
                html_body=body
            )

            # Log success
            EmailAlertManager._log_alert(
                organization.id,
                'critical_cve',
                len(filtered_matches),
                len(recipients),
                'success',
                None
            )

            return {
                'status': 'success',
                'sent_to': len(recipients),
                'matches_count': len(filtered_matches)
            }

        except Exception as e:
            # Log failure
            EmailAlertManager._log_alert(
                organization.id,
                'critical_cve',
                len(filtered_matches),
                len(recipients),
                'failed',
                str(e)
            )
            return {'status': 'error', 'reason': str(e)}

    @staticmethod
    def _build_alert_email_html(organization, matches):
        """Build HTML email body"""

        # Group by priority
        by_priority = {'critical': [], 'high': [], 'medium': [], 'low': []}
        for match in matches:
            priority = match.calculate_effective_priority()
            by_priority[priority].append(match)

        priority_colors = {
            'critical': '#dc2626',
            'high': '#ea580c',
            'medium': '#ca8a04',
            'low': '#059669'
        }

        html = f"""
<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <style>
        body {{
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            line-height: 1.6;
            color: #333;
            background-color: #f9fafb;
            margin: 0;
            padding: 0;
        }}
        .container {{
            max-width: 800px;
            margin: 0 auto;
            background: white;
        }}
        .header {{
            background-color: #1e40af;
            background: linear-gradient(135deg, #1e40af 0%, #3b82f6 100%);
            color: #ffffff;
            padding: 30px 20px;
            text-align: center;
        }}
        .header h1 {{
            margin: 0 0 10px 0;
            font-size: 28px;
            color: #ffffff;
        }}
        .header p {{
            margin: 5px 0;
            color: #e0e7ff;
        }}
        .content {{
            padding: 30px 20px;
        }}
        .summary-box {{
            background: #f3f4f6;
            border-left: 4px solid #1e40af;
            padding: 20px;
            margin: 20px 0;
            border-radius: 4px;
        }}
        .summary-box h2 {{
            margin-top: 0;
            color: #1e40af;
        }}
        .priority-stats {{
            display: flex;
            flex-wrap: wrap;
            gap: 10px;
            margin: 15px 0;
        }}
        .priority-badge {{
            flex: 1;
            min-width: 150px;
            padding: 10px;
            border-radius: 6px;
            text-align: center;
            color: white;
            font-weight: bold;
        }}
        .vuln-card {{
            border-left: 4px solid #ccc;
            padding: 20px;
            margin: 20px 0;
            background: #f9fafb;
            border-radius: 4px;
            transition: box-shadow 0.2s;
        }}
        .vuln-card:hover {{
            box-shadow: 0 4px 6px rgba(0,0,0,0.1);
        }}
        .vuln-card.critical {{
            border-left-color: {priority_colors['critical']};
            background: #fef2f2;
        }}
        .vuln-card.high {{
            border-left-color: {priority_colors['high']};
            background: #fff7ed;
        }}
        .vuln-card.medium {{
            border-left-color: {priority_colors['medium']};
            background: #fffbeb;
        }}
        .vuln-card h3 {{
            margin-top: 0;
            color: #111827;
        }}
        .badge {{
            display: inline-block;
            padding: 4px 10px;
            border-radius: 4px;
            font-size: 12px;
            font-weight: bold;
            color: white;
            margin-right: 8px;
            margin-bottom: 5px;
        }}
        .badge-critical {{ background: {priority_colors['critical']}; }}
        .badge-high {{ background: {priority_colors['high']}; }}
        .badge-medium {{ background: {priority_colors['medium']}; }}
        .badge-low {{ background: {priority_colors['low']}; }}
        .badge-gray {{ background: #6b7280; }}
        .badge-dark {{ background: #111827; }}
        .info-row {{
            margin: 10px 0;
            padding: 8px 0;
            border-bottom: 1px solid #e5e7eb;
        }}
        .info-row:last-child {{
            border-bottom: none;
        }}
        .info-label {{
            font-size: 11px;
            text-transform: uppercase;
            color: #6b7280;
            font-weight: 600;
            letter-spacing: 0.5px;
        }}
        .info-value {{
            color: #111827;
            margin-top: 3px;
        }}
        .action-required {{
            color: {priority_colors['critical']};
            font-weight: 600;
        }}
        .footer {{
            background: #f3f4f6;
            padding: 20px;
            text-align: center;
            font-size: 13px;
            color: #6b7280;
        }}
        .footer p {{
            margin: 5px 0;
        }}
        .cta-button {{
            display: inline-block;
            padding: 12px 24px;
            background: #1e40af;
            color: white;
            text-decoration: none;
            border-radius: 6px;
            font-weight: bold;
            margin: 10px 0;
        }}
        .more-vulns {{
            padding: 20px;
            background: #e5e7eb;
            border-radius: 6px;
            text-align: center;
            margin: 20px 0;
        }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>SentriKat Security Alert</h1>
            <p><strong>Organization:</strong> {organization.display_name}</p>
            <p><strong>Alert Generated:</strong> {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
        </div>

        <div class="content">
            <div class="summary-box">
                <h2>Action Required</h2>
                <p><strong>{len(matches)}</strong> critical vulnerabilities require your immediate attention:</p>
                <div class="priority-stats">
                    <div class="priority-badge" style="background: {priority_colors['critical']};">
                        <div style="font-size: 24px;">{len(by_priority['critical'])}</div>
                        <div>Critical Priority</div>
                    </div>
                    <div class="priority-badge" style="background: {priority_colors['high']};">
                        <div style="font-size: 24px;">{len(by_priority['high'])}</div>
                        <div>High Priority</div>
                    </div>
                    <div class="priority-badge" style="background: {priority_colors['medium']};">
                        <div style="font-size: 24px;">{len(by_priority['medium'])}</div>
                        <div>Medium Priority</div>
                    </div>
                </div>
            </div>

            <h2 style="color: #111827; border-bottom: 2px solid #e5e7eb; padding-bottom: 10px;">Vulnerability Details</h2>
"""

        # Add vulnerability cards (show top 15 to avoid huge emails)
        for match in matches[:15]:
            vuln = match.vulnerability
            product = match.product
            priority = match.calculate_effective_priority()

            ransomware_badge = '🦠 <span class="badge badge-critical">RANSOMWARE</span> ' if vuln.known_ransomware else ''
            severity_badge = f'<span class="badge badge-gray">CVSS: {vuln.severity} ({vuln.cvss_score})</span>' if vuln.severity else ''

            days_old = (date.today() - vuln.date_added).days if vuln.date_added else 0
            new_badge = '<span class="badge" style="background:#10b981;">NEW</span>' if days_old <= 7 else ''

            html += f"""
            <div class="vuln-card {priority}">
                <h3>{vuln.cve_id} - {vuln.vulnerability_name[:80]}</h3>
                <div style="margin: 10px 0;">
                    <span class="badge badge-{priority}">{priority.upper()} PRIORITY</span>
                    {ransomware_badge}
                    {severity_badge}
                    {new_badge}
                </div>

                <div class="info-row">
                    <div class="info-label">Affected Product</div>
                    <div class="info-value"><strong>{vuln.vendor_project}</strong> - {vuln.product}</div>
                </div>

                <div class="info-row">
                    <div class="info-label">Your Product</div>
                    <div class="info-value">
                        <strong>{product.vendor}</strong> - {product.product_name}
                        {f' (v{product.version})' if product.version else ''}
                        <span class="badge badge-{product.criticality}">{product.criticality.upper()} Criticality</span>
                    </div>
                </div>

                <div class="info-row">
                    <div class="info-label">Description</div>
                    <div class="info-value">{vuln.short_description}</div>
                </div>

                <div class="info-row">
                    <div class="info-label">Required Action</div>
                    <div class="info-value action-required">{vuln.required_action}</div>
                </div>

                <div class="info-row">
                    <div class="info-label">Timeline</div>
                    <div class="info-value">
                        Added: {vuln.date_added} ({days_old} days ago)
                        {f' | <strong style="color:{priority_colors["critical"]};">Due: {vuln.due_date}</strong>' if vuln.due_date else ''}
                    </div>
                </div>

                <div style="margin-top: 15px;">
                    <a href="https://nvd.nist.gov/vuln/detail/{vuln.cve_id}" target="_blank"
                       style="color: #1e40af; text-decoration: none; font-weight: 600;">
                        → View in NVD Database
                    </a>
                </div>
            </div>
"""

        if len(matches) > 15:
            html += f"""
            <div class="more-vulns">
                <p style="font-size: 16px; font-weight: bold; margin: 0;">+ {len(matches) - 15} more vulnerabilities</p>
                <p style="margin: 10px 0 0 0;">Login to SentriKat to view all vulnerabilities</p>
            </div>
"""

        html += """
        </div>

        <div class="footer">
            <p><strong>SentriKat</strong> - Enterprise Vulnerability Management Platform</p>
            <p>Copyright © 2025 Denis Sota. Licensed to Zertificon Solutions GmbH.</p>
            <p style="margin-top: 15px; font-size: 11px;">
                This is an automated security alert. Please do not reply to this email.<br>
                For support, contact your system administrator.
            </p>
        </div>
    </div>
</body>
</html>
"""

        return html

    @staticmethod
    def _send_email(smtp_config, recipients, subject, html_body):
        """Send HTML email via SMTP (supports Gmail, Office365, Internal SMTP)"""
        msg = MIMEMultipart('alternative')
        msg['From'] = f"{smtp_config['from_name']} <{smtp_config['from_email']}>"
        msg['To'] = ', '.join(recipients)
        msg['Subject'] = subject

        # Attach HTML body
        html_part = MIMEText(html_body, 'html', 'utf-8')
        msg.attach(html_part)

        # Determine connection type
        if smtp_config['use_ssl']:
            # Use SSL (typically port 465)
            server = smtplib.SMTP_SSL(smtp_config['host'], smtp_config['port'], timeout=30)
        else:
            # Use plain connection, possibly with STARTTLS
            server = smtplib.SMTP(smtp_config['host'], smtp_config['port'], timeout=30)
            if smtp_config['use_tls']:
                server.starttls()

        # Authenticate if credentials provided
        if smtp_config['username'] and smtp_config['password']:
            server.login(smtp_config['username'], smtp_config['password'])

        # Send email
        server.sendmail(smtp_config['from_email'], recipients, msg.as_string())
        server.quit()

    @staticmethod
    def _log_alert(org_id, alert_type, matches_count, recipients_count, status, error_msg):
        """Log alert to database"""
        log = AlertLog(
            organization_id=org_id,
            alert_type=alert_type,
            matches_count=matches_count,
            recipients_count=recipients_count,
            status=status,
            error_message=error_msg
        )
        db.session.add(log)
        db.session.commit()

    @staticmethod
    def test_smtp_connection(smtp_config):
        """Test SMTP connection and return status"""
        try:
            if smtp_config['use_ssl']:
                server = smtplib.SMTP_SSL(smtp_config['host'], smtp_config['port'], timeout=10)
            else:
                server = smtplib.SMTP(smtp_config['host'], smtp_config['port'], timeout=10)
                if smtp_config['use_tls']:
                    server.starttls()

            if smtp_config['username'] and smtp_config['password']:
                server.login(smtp_config['username'], smtp_config['password'])

            server.quit()
            return {'success': True, 'message': '✓ SMTP connection successful'}
        except Exception as e:
            return {'success': False, 'error': str(e)}


# ============================================================================
# User Invite Email
# ============================================================================

def send_user_invite_email(user):
    """
    Send welcome email to newly invited LDAP user

    Args:
        user: User object that was just invited

    Returns:
        tuple: (success: bool, details: str) - success status and details message
    """
    from app.models import Organization, SystemSettings
    import logging
    logger = logging.getLogger(__name__)

    try:
        # Get user's organization
        organization = Organization.query.get(user.organization_id)
        if not organization:
            msg = f"No organization found for user {user.username}"
            logger.warning(msg)
            return False, msg

        # Try organization SMTP first, then fall back to global SMTP
        smtp_config = organization.get_smtp_config()
        smtp_source = "organization"

        # Check if organization SMTP is configured
        if not smtp_config['host'] or not smtp_config['from_email']:
            logger.info(f"Organization SMTP not configured, trying global SMTP")
            smtp_source = "global"
            # Try global SMTP settings
            def get_setting(key, default=None):
                setting = SystemSettings.query.filter_by(key=key).first()
                return setting.value if setting else default

            smtp_config = {
                'host': get_setting('smtp_host'),
                'port': int(get_setting('smtp_port', '587') or '587'),
                'username': get_setting('smtp_username'),
                'password': get_setting('smtp_password'),
                'use_tls': get_setting('smtp_use_tls', 'true') == 'true',
                'use_ssl': get_setting('smtp_use_ssl', 'false') == 'true',
                'from_email': get_setting('smtp_from_email'),
                'from_name': get_setting('smtp_from_name', 'SentriKat')
            }

        # Final check - SMTP must be configured
        if not smtp_config['host'] or not smtp_config['from_email']:
            msg = f"No SMTP configured (neither org nor global)"
            logger.warning(f"{msg} - cannot send invite email to {user.email}")
            return False, msg

        logger.info(f"Sending invite email to {user.email} via {smtp_source} SMTP: {smtp_config['host']}:{smtp_config['port']}")
        logger.info(f"SMTP config: host={smtp_config['host']}, port={smtp_config['port']}, from={smtp_config['from_email']}, tls={smtp_config['use_tls']}, ssl={smtp_config['use_ssl']}, user={smtp_config['username'] or 'none'}")

        # Build welcome email
        subject = f"Welcome to SentriKat - {organization.display_name}"
        html_body = _build_user_invite_email_html(user, organization)

        # Send email
        EmailAlertManager._send_email(
            smtp_config=smtp_config,
            recipients=[user.email],
            subject=subject,
            html_body=html_body
        )

        msg = f"Email sent via {smtp_source} SMTP ({smtp_config['host']}:{smtp_config['port']}) to {user.email}"
        logger.info(msg)
        return True, msg

    except Exception as e:
        import traceback
        logger = logging.getLogger(__name__)
        error_detail = f"{type(e).__name__}: {str(e)}"
        logger.error(f"Failed to send invite email to {user.email}: {error_detail}")
        logger.error(traceback.format_exc())
        return False, error_detail


def _build_user_invite_email_html(user, organization):
    """Build HTML email body for user invitation"""

    role_descriptions = {
        'super_admin': 'Super Administrator - Full system access',
        'org_admin': 'Organization Administrator - Full organization access',
        'manager': 'Manager - Can manage products and vulnerabilities',
        'user': 'User - View-only access to vulnerabilities'
    }

    role_desc = role_descriptions.get(user.role, 'User')

    html = f"""
<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <style>
        body {{
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            line-height: 1.6;
            color: #333;
            background-color: #f9fafb;
            margin: 0;
            padding: 0;
        }}
        .container {{
            max-width: 600px;
            margin: 0 auto;
            background: white;
        }}
        .header {{
            background-color: #1e40af;
            background: linear-gradient(135deg, #1e40af 0%, #3b82f6 100%);
            color: #ffffff;
            padding: 40px 20px;
            text-align: center;
        }}
        .header h1 {{
            margin: 0 0 10px 0;
            font-size: 28px;
            color: #ffffff;
        }}
        .header p {{
            margin: 5px 0;
            color: #e0e7ff;
            font-size: 16px;
        }}
        .content {{
            padding: 40px 30px;
        }}
        .welcome-box {{
            background: #f0f9ff;
            border-left: 4px solid #3b82f6;
            padding: 20px;
            margin: 20px 0;
            border-radius: 4px;
        }}
        .info-box {{
            background: #f3f4f6;
            padding: 15px;
            margin: 20px 0;
            border-radius: 4px;
        }}
        .info-box h3 {{
            margin: 0 0 10px 0;
            color: #1e40af;
            font-size: 16px;
        }}
        .info-row {{
            display: flex;
            padding: 8px 0;
            border-bottom: 1px solid #e5e7eb;
        }}
        .info-row:last-child {{
            border-bottom: none;
        }}
        .info-label {{
            font-weight: 600;
            width: 120px;
            color: #6b7280;
        }}
        .info-value {{
            flex: 1;
            color: #111827;
        }}
        .button {{
            display: inline-block;
            background: #3b82f6;
            color: white;
            padding: 12px 30px;
            text-decoration: none;
            border-radius: 6px;
            margin: 20px 0;
            font-weight: 600;
        }}
        .footer {{
            background: #f9fafb;
            padding: 20px;
            text-align: center;
            font-size: 12px;
            color: #6b7280;
        }}
        .features {{
            margin: 30px 0;
        }}
        .feature {{
            padding: 10px 0;
            display: flex;
            align-items: flex-start;
        }}
        .feature-icon {{
            color: #3b82f6;
            margin-right: 10px;
            font-size: 20px;
        }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>Welcome to SentriKat</h1>
            <p>Vulnerability Management Platform</p>
        </div>

        <div class="content">
            <div class="welcome-box">
                <h2 style="margin: 0 0 10px 0; color: #1e40af;">Hello {user.full_name or user.username}!</h2>
                <p style="margin: 0;">You've been granted access to SentriKat for <strong>{organization.display_name}</strong>.</p>
            </div>

            <p>You can now log in using your Active Directory credentials to access the vulnerability management platform.</p>

            <div class="info-box">
                <h3>Your Account Details</h3>
                <div class="info-row">
                    <div class="info-label">Username:</div>
                    <div class="info-value"><strong>{user.username}</strong></div>
                </div>
                <div class="info-row">
                    <div class="info-label">Email:</div>
                    <div class="info-value">{user.email}</div>
                </div>
                <div class="info-row">
                    <div class="info-label">Role:</div>
                    <div class="info-value">{role_desc}</div>
                </div>
                <div class="info-row">
                    <div class="info-label">Organization:</div>
                    <div class="info-value">{organization.display_name}</div>
                </div>
            </div>

            <div style="text-align: center;">
                <a href="{get_app_url()}/login" class="button">Login to SentriKat</a>
            </div>

            <div class="features">
                <h3 style="color: #1e40af; margin-bottom: 15px;">What you can do with SentriKat:</h3>
                <div class="feature">
                    <div class="feature-icon">✓</div>
                    <div>Monitor CISA KEV (Known Exploited Vulnerabilities) affecting your products</div>
                </div>
                <div class="feature">
                    <div class="feature-icon">✓</div>
                    <div>Track and acknowledge critical vulnerabilities in real-time</div>
                </div>
                <div class="feature">
                    <div class="feature-icon">✓</div>
                    <div>Receive automated email alerts for critical threats</div>
                </div>
                <div class="feature">
                    <div class="feature-icon">✓</div>
                    <div>Filter and prioritize vulnerabilities by severity and impact</div>
                </div>
                <div class="feature">
                    <div class="feature-icon">✓</div>
                    <div>Share vulnerability views with stakeholders</div>
                </div>
            </div>

            <p style="margin-top: 30px; color: #6b7280; font-size: 14px;">
                <strong>Note:</strong> Use your Active Directory credentials to log in. No separate password is required.
            </p>
        </div>

        <div class="footer">
            <p>This is an automated message from SentriKat</p>
            <p>© {datetime.now().year} {organization.display_name} - Vulnerability Management</p>
        </div>
    </div>
</body>
</html>
"""

    return html


# ============================================================================
# User Status Change Emails (Block/Unblock)
# ============================================================================

def send_user_status_email(user, is_blocked, blocked_by_username=None):
    """
    Send email notification when a user is blocked or unblocked

    Args:
        user: User object whose status changed
        is_blocked: True if user was blocked, False if unblocked
        blocked_by_username: Username of admin who performed the action

    Returns:
        tuple: (success: bool, details: str) - success status and details message
    """
    from app.models import Organization, SystemSettings
    import logging
    logger = logging.getLogger(__name__)

    try:
        # Get user's organization
        organization = Organization.query.get(user.organization_id)
        if not organization:
            msg = f"No organization found for user {user.username}"
            logger.warning(msg)
            return False, msg

        # Try organization SMTP first, then fall back to global SMTP
        smtp_config = organization.get_smtp_config()
        smtp_source = "organization"

        if not smtp_config['host'] or not smtp_config['from_email']:
            smtp_source = "global"
            # Try global SMTP settings
            def get_setting(key, default=None):
                setting = SystemSettings.query.filter_by(key=key).first()
                return setting.value if setting else default

            smtp_config = {
                'host': get_setting('smtp_host'),
                'port': int(get_setting('smtp_port', '587') or '587'),
                'username': get_setting('smtp_username'),
                'password': get_setting('smtp_password'),
                'use_tls': get_setting('smtp_use_tls', 'true') == 'true',
                'use_ssl': get_setting('smtp_use_ssl', 'false') == 'true',
                'from_email': get_setting('smtp_from_email'),
                'from_name': get_setting('smtp_from_name', 'SentriKat')
            }

        if not smtp_config['host'] or not smtp_config['from_email']:
            msg = "No SMTP configured (neither org nor global)"
            logger.warning(f"{msg} - cannot send status email to {user.email}")
            return False, msg

        action = "blocked" if is_blocked else "unblocked"
        subject = f"SentriKat Account {action.title()} - {organization.display_name}"
        html_body = _build_user_status_email_html(user, organization, is_blocked, blocked_by_username)

        logger.info(f"Sending status email to {user.email} via {smtp_source} SMTP: {smtp_config['host']}:{smtp_config['port']}")

        EmailAlertManager._send_email(
            smtp_config=smtp_config,
            recipients=[user.email],
            subject=subject,
            html_body=html_body
        )

        msg = f"Email sent via {smtp_source} SMTP ({smtp_config['host']}:{smtp_config['port']}) to {user.email}"
        logger.info(msg)
        return True, msg

    except Exception as e:
        import traceback
        logger = logging.getLogger(__name__)
        error_detail = f"{type(e).__name__}: {str(e)}"
        logger.error(f"Failed to send status email to {user.email}: {error_detail}")
        logger.error(traceback.format_exc())
        return False, error_detail


def _build_user_status_email_html(user, organization, is_blocked, blocked_by_username=None):
    """Build HTML email for user status change notification"""
    from datetime import datetime

    if is_blocked:
        status_color = "#dc2626"
        status_icon = "🚫"
        status_text = "Account Blocked"
        message = """
            <p>Your SentriKat account has been <strong style="color: #dc2626;">blocked</strong> by an administrator.</p>
            <p>You will not be able to log in to SentriKat until your account is unblocked.</p>
            <p>If you believe this was done in error, please contact your organization administrator.</p>
        """
    else:
        status_color = "#16a34a"
        status_icon = "✅"
        status_text = "Account Unblocked"
        message = """
            <p>Your SentriKat account has been <strong style="color: #16a34a;">unblocked</strong> and restored.</p>
            <p>You can now log in to SentriKat and access the vulnerability management dashboard.</p>
        """

    html = f"""
<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
</head>
<body style="margin: 0; padding: 0; font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, 'Helvetica Neue', Arial, sans-serif; background-color: #f3f4f6;">
    <div style="max-width: 600px; margin: 0 auto; padding: 40px 20px;">
        <div style="background: {status_color}; padding: 30px; text-align: center; border-radius: 12px 12px 0 0;">
            <div style="font-size: 48px; margin-bottom: 10px;">{status_icon}</div>
            <h1 style="color: white; margin: 0; font-size: 24px;">{status_text}</h1>
        </div>

        <div style="background: white; padding: 40px; border-radius: 0 0 12px 12px; box-shadow: 0 4px 6px rgba(0, 0, 0, 0.1);">
            <p style="font-size: 16px; color: #374151;">Hello <strong>{user.full_name or user.username}</strong>,</p>

            {message}

            <div style="background: #f9fafb; padding: 20px; border-radius: 8px; margin: 20px 0;">
                <div style="margin-bottom: 10px;">
                    <strong>Username:</strong> {user.username}
                </div>
                <div style="margin-bottom: 10px;">
                    <strong>Organization:</strong> {organization.display_name}
                </div>
                <div>
                    <strong>Time:</strong> {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
                </div>
            </div>

            {'<p style="color: #6b7280; font-size: 14px;">If your account was unblocked, you can log in using your Active Directory credentials.</p>' if not is_blocked else ''}
        </div>

        <div style="text-align: center; padding: 20px; color: #9ca3af; font-size: 12px;">
            <p>This is an automated message from SentriKat</p>
            <p>© {datetime.now().year} {organization.display_name}</p>
        </div>
    </div>
</body>
</html>
"""

    return html


# ============================================================================
# User Role Change Email
# ============================================================================

def send_role_change_email(user, old_role, new_role, changed_by_username=None):
    """
    Send email notification when a user's role changes

    Args:
        user: User object whose role changed
        old_role: Previous role
        new_role: New role
        changed_by_username: Username of admin who made the change

    Returns:
        tuple: (success: bool, details: str) - success status and details message
    """
    from app.models import Organization, SystemSettings
    import logging
    logger = logging.getLogger(__name__)

    try:
        # Get user's organization
        organization = Organization.query.get(user.organization_id)
        if not organization:
            msg = f"No organization found for user {user.username}"
            logger.warning(msg)
            return False, msg

        # Try organization SMTP first, then fall back to global SMTP
        smtp_config = organization.get_smtp_config()
        smtp_source = "organization"

        if not smtp_config['host'] or not smtp_config['from_email']:
            smtp_source = "global"
            def get_setting(key, default=None):
                setting = SystemSettings.query.filter_by(key=key).first()
                return setting.value if setting else default

            smtp_config = {
                'host': get_setting('smtp_host'),
                'port': int(get_setting('smtp_port', '587') or '587'),
                'username': get_setting('smtp_username'),
                'password': get_setting('smtp_password'),
                'use_tls': get_setting('smtp_use_tls', 'true') == 'true',
                'use_ssl': get_setting('smtp_use_ssl', 'false') == 'true',
                'from_email': get_setting('smtp_from_email'),
                'from_name': get_setting('smtp_from_name', 'SentriKat')
            }

        if not smtp_config['host'] or not smtp_config['from_email']:
            msg = "No SMTP configured (neither org nor global)"
            logger.warning(f"{msg} - cannot send role change email to {user.email}")
            return False, msg

        subject = f"SentriKat Role Changed - {organization.display_name}"
        html_body = _build_role_change_email_html(user, organization, old_role, new_role, changed_by_username)

        logger.info(f"Sending role change email to {user.email} via {smtp_source} SMTP")

        EmailAlertManager._send_email(
            smtp_config=smtp_config,
            recipients=[user.email],
            subject=subject,
            html_body=html_body
        )

        msg = f"Email sent via {smtp_source} SMTP to {user.email}"
        logger.info(msg)
        return True, msg

    except Exception as e:
        import traceback
        logger = logging.getLogger(__name__)
        error_detail = f"{type(e).__name__}: {str(e)}"
        logger.error(f"Failed to send role change email to {user.email}: {error_detail}")
        logger.error(traceback.format_exc())
        return False, error_detail


def _build_role_change_email_html(user, organization, old_role, new_role, changed_by_username=None):
    """Build HTML email for role change notification"""
    from datetime import datetime

    role_descriptions = {
        'super_admin': 'Super Administrator - Full system access across all organizations',
        'org_admin': 'Organization Administrator - Full access within your organization',
        'manager': 'Manager - Can manage products and view vulnerabilities',
        'user': 'User - View-only access to vulnerabilities'
    }

    is_promotion = _role_level(new_role) > _role_level(old_role)
    status_color = "#10b981" if is_promotion else "#f59e0b"  # Green for promotion, amber for demotion
    status_icon = "⬆️" if is_promotion else "⬇️"
    status_text = "Promoted" if is_promotion else "Changed"

    html = f"""
<!DOCTYPE html>
<html>
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
</head>
<body style="margin: 0; padding: 0; background-color: #f3f4f6; font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, 'Helvetica Neue', Arial, sans-serif;">
    <div style="max-width: 600px; margin: 0 auto; padding: 20px;">
        <div style="background: linear-gradient(135deg, {status_color} 0%, {status_color}dd 100%); padding: 30px; border-radius: 12px 12px 0 0; text-align: center;">
            <h1 style="color: white; margin: 0; font-size: 24px;">{status_icon} Role {status_text}</h1>
            <p style="color: rgba(255,255,255,0.9); margin: 10px 0 0 0;">Your permissions have been updated</p>
        </div>

        <div style="background: white; padding: 30px; border-radius: 0 0 12px 12px; box-shadow: 0 4px 6px rgba(0,0,0,0.1);">
            <p style="color: #374151; font-size: 16px; line-height: 1.6;">
                Hello <strong>{user.full_name or user.username}</strong>,
            </p>

            <p style="color: #374151; font-size: 16px; line-height: 1.6;">
                Your role in <strong>{organization.display_name}</strong> has been changed:
            </p>

            <div style="background: #f9fafb; padding: 20px; border-radius: 8px; margin: 20px 0;">
                <div style="margin-bottom: 15px;">
                    <div style="display: inline-block; width: 45%;">
                        <div style="color: #6b7280; font-size: 12px; text-transform: uppercase; margin-bottom: 5px;">Previous Role</div>
                        <div style="color: #374151; font-size: 16px; font-weight: 600;">{old_role.replace('_', ' ').title()}</div>
                    </div>
                    <div style="display: inline-block; width: 8%; text-align: center; color: #9ca3af;">→</div>
                    <div style="display: inline-block; width: 45%;">
                        <div style="color: #6b7280; font-size: 12px; text-transform: uppercase; margin-bottom: 5px;">New Role</div>
                        <div style="color: {status_color}; font-size: 16px; font-weight: 600;">{new_role.replace('_', ' ').title()}</div>
                    </div>
                </div>

                <div style="border-top: 1px solid #e5e7eb; padding-top: 15px; margin-top: 15px;">
                    <div style="color: #6b7280; font-size: 14px;">
                        <strong>New permissions:</strong> {role_descriptions.get(new_role, new_role)}
                    </div>
                </div>
            </div>

            <div style="background: #f9fafb; padding: 15px; border-radius: 8px; margin: 20px 0;">
                <div style="margin-bottom: 8px;">
                    <strong>Changed by:</strong> {changed_by_username or 'System'}
                </div>
                <div>
                    <strong>Time:</strong> {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
                </div>
            </div>

            <p style="color: #6b7280; font-size: 14px;">
                If you did not expect this change or have questions, please contact your administrator.
            </p>
        </div>

        <div style="text-align: center; padding: 20px; color: #9ca3af; font-size: 12px;">
            <p>This is an automated message from SentriKat</p>
            <p>© {datetime.now().year} {organization.display_name}</p>
        </div>
    </div>
</body>
</html>
"""

    return html


def _role_level(role):
    """Get numeric level for a role (higher = more permissions)"""
    levels = {
        'user': 1,
        'manager': 2,
        'org_admin': 3,
        'super_admin': 4
    }
    return levels.get(role, 0)
