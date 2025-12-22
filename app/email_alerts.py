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

        # Get SMTP config - try organization first, then fall back to global
        smtp_config = organization.get_smtp_config()

        # Fall back to global SMTP if organization SMTP not configured
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

        # Check if any SMTP is configured
        if not smtp_config['host'] or not smtp_config['from_email']:
            return {'status': 'error', 'reason': 'SMTP not configured (neither org nor global)'}

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

            # Check alert settings - CRITICAL ONLY (high priority disabled to prevent spam)
            if organization.alert_on_critical and priority == 'critical':
                should_alert = True
            # Note: alert_on_high is intentionally disabled - too many alerts cause spam
            # elif organization.alert_on_high and priority == 'high':
            #     should_alert = True
            elif organization.alert_on_ransomware and vuln.known_ransomware and priority == 'critical':
                # Ransomware alerts only for critical severity
                should_alert = True
            elif organization.alert_on_new_cve and priority == 'critical':
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
        """Build HTML email body - Professional enterprise design"""

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

        app_url = get_app_url()

        html = f"""
<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
</head>
<body style="margin: 0; padding: 0; background-color: #f1f5f9; font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, 'Helvetica Neue', Arial, sans-serif;">
    <!-- Wrapper -->
    <table role="presentation" width="100%" cellspacing="0" cellpadding="0" style="background-color: #f1f5f9;">
        <tr>
            <td align="center" style="padding: 40px 20px;">
                <!-- Main Container -->
                <table role="presentation" width="100%" cellspacing="0" cellpadding="0" style="max-width: 680px; background: white; border-radius: 16px; box-shadow: 0 4px 6px -1px rgba(0, 0, 0, 0.1), 0 2px 4px -1px rgba(0, 0, 0, 0.06); overflow: hidden;">

                    <!-- Header with Logo -->
                    <tr>
                        <td style="background: linear-gradient(135deg, #1e3a8a 0%, #1e40af 50%, #3b82f6 100%); padding: 40px 30px; text-align: center;">
                            <table role="presentation" width="100%" cellspacing="0" cellpadding="0">
                                <tr>
                                    <td align="center">
                                        <!-- Logo Text -->
                                        <h1 style="margin: 0; font-size: 32px; font-weight: 800; color: white; letter-spacing: -0.5px;">
                                            SentriKat
                                        </h1>
                                        <p style="margin: 8px 0 0 0; font-size: 14px; color: #bfdbfe; text-transform: uppercase; letter-spacing: 2px;">
                                            Security Alert
                                        </p>
                                    </td>
                                </tr>
                            </table>
                        </td>
                    </tr>

                    <!-- Alert Banner -->
                    <tr>
                        <td style="background: linear-gradient(135deg, #dc2626 0%, #b91c1c 100%); padding: 20px 30px;">
                            <table role="presentation" width="100%" cellspacing="0" cellpadding="0">
                                <tr>
                                    <td align="center">
                                        <p style="margin: 0; font-size: 18px; font-weight: 700; color: white;">
                                            ⚠️ {len(matches)} Critical Vulnerabilities Detected
                                        </p>
                                        <p style="margin: 8px 0 0 0; font-size: 14px; color: #fecaca;">
                                            Immediate action required for {organization.display_name}
                                        </p>
                                    </td>
                                </tr>
                            </table>
                        </td>
                    </tr>

                    <!-- Priority Summary Cards -->
                    <tr>
                        <td style="padding: 30px;">
                            <table role="presentation" width="100%" cellspacing="0" cellpadding="0">
                                <tr>
                                    <td style="padding-bottom: 20px;">
                                        <p style="margin: 0 0 5px 0; font-size: 12px; font-weight: 600; color: #6b7280; text-transform: uppercase; letter-spacing: 1px;">
                                            Priority Breakdown
                                        </p>
                                    </td>
                                </tr>
                                <tr>
                                    <td>
                                        <table role="presentation" width="100%" cellspacing="0" cellpadding="0">
                                            <tr>
                                                <!-- Critical -->
                                                <td width="33%" style="padding: 0 5px 0 0;">
                                                    <div style="background: linear-gradient(135deg, #fef2f2 0%, #fee2e2 100%); border-left: 4px solid #dc2626; border-radius: 8px; padding: 15px; text-align: center;">
                                                        <div style="font-size: 28px; font-weight: 800; color: #dc2626;">{len(by_priority['critical'])}</div>
                                                        <div style="font-size: 11px; font-weight: 600; color: #991b1b; text-transform: uppercase; letter-spacing: 0.5px;">Critical</div>
                                                    </div>
                                                </td>
                                                <!-- High -->
                                                <td width="33%" style="padding: 0 5px;">
                                                    <div style="background: linear-gradient(135deg, #fff7ed 0%, #ffedd5 100%); border-left: 4px solid #ea580c; border-radius: 8px; padding: 15px; text-align: center;">
                                                        <div style="font-size: 28px; font-weight: 800; color: #ea580c;">{len(by_priority['high'])}</div>
                                                        <div style="font-size: 11px; font-weight: 600; color: #9a3412; text-transform: uppercase; letter-spacing: 0.5px;">High</div>
                                                    </div>
                                                </td>
                                                <!-- Medium -->
                                                <td width="33%" style="padding: 0 0 0 5px;">
                                                    <div style="background: linear-gradient(135deg, #fffbeb 0%, #fef3c7 100%); border-left: 4px solid #ca8a04; border-radius: 8px; padding: 15px; text-align: center;">
                                                        <div style="font-size: 28px; font-weight: 800; color: #ca8a04;">{len(by_priority['medium'])}</div>
                                                        <div style="font-size: 11px; font-weight: 600; color: #854d0e; text-transform: uppercase; letter-spacing: 0.5px;">Medium</div>
                                                    </div>
                                                </td>
                                            </tr>
                                        </table>
                                    </td>
                                </tr>
                            </table>
                        </td>
                    </tr>

                    <!-- CTA Button -->
                    <tr>
                        <td style="padding: 0 30px 30px 30px;" align="center">
                            <a href="{app_url}" style="display: inline-block; background: linear-gradient(135deg, #1e40af 0%, #3b82f6 100%); color: white; text-decoration: none; padding: 14px 32px; border-radius: 8px; font-weight: 600; font-size: 14px; box-shadow: 0 4px 6px -1px rgba(30, 64, 175, 0.3);">
                                View in SentriKat Dashboard →
                            </a>
                        </td>
                    </tr>

                    <!-- Divider -->
                    <tr>
                        <td style="padding: 0 30px;">
                            <div style="height: 1px; background: linear-gradient(to right, transparent, #e5e7eb, transparent);"></div>
                        </td>
                    </tr>

                    <!-- Vulnerability Details Header -->
                    <tr>
                        <td style="padding: 30px 30px 20px 30px;">
                            <h2 style="margin: 0; font-size: 18px; font-weight: 700; color: #111827;">
                                Vulnerability Details
                            </h2>
                        </td>
                    </tr>
"""

        # Add vulnerability cards (show top 15 to avoid huge emails)
        for match in matches[:15]:
            vuln = match.vulnerability
            product = match.product
            priority = match.calculate_effective_priority()

            border_color = priority_colors.get(priority, '#6b7280')
            bg_colors = {
                'critical': '#fef2f2',
                'high': '#fff7ed',
                'medium': '#fffbeb',
                'low': '#f0fdf4'
            }
            bg_color = bg_colors.get(priority, '#f9fafb')

            ransomware_badge = '<span style="display: inline-block; background: #7c2d12; color: white; padding: 2px 8px; border-radius: 4px; font-size: 10px; font-weight: 600; margin-left: 8px;">🦠 RANSOMWARE</span>' if vuln.known_ransomware else ''
            severity_badge = f'<span style="display: inline-block; background: #6b7280; color: white; padding: 2px 8px; border-radius: 4px; font-size: 10px; font-weight: 600; margin-left: 8px;">CVSS {vuln.cvss_score}</span>' if vuln.cvss_score else ''

            days_old = (date.today() - vuln.date_added).days if vuln.date_added else 0
            new_badge = '<span style="display: inline-block; background: #059669; color: white; padding: 2px 8px; border-radius: 4px; font-size: 10px; font-weight: 600; margin-left: 8px;">NEW</span>' if days_old <= 7 else ''

            html += f"""
                    <!-- Vulnerability Card -->
                    <tr>
                        <td style="padding: 0 30px 20px 30px;">
                            <div style="border-left: 4px solid {border_color}; background: {bg_color}; border-radius: 8px; padding: 20px;">
                                <!-- CVE Header -->
                                <div style="margin-bottom: 15px;">
                                    <span style="display: inline-block; background: {border_color}; color: white; padding: 4px 10px; border-radius: 4px; font-size: 11px; font-weight: 700; text-transform: uppercase;">{priority}</span>
                                    {ransomware_badge}
                                    {severity_badge}
                                    {new_badge}
                                </div>
                                <h3 style="margin: 0 0 5px 0; font-size: 16px; font-weight: 700; color: #111827;">
                                    {vuln.cve_id}
                                </h3>
                                <p style="margin: 0 0 15px 0; font-size: 14px; color: #374151;">
                                    {vuln.vulnerability_name[:100]}
                                </p>

                                <!-- Info Grid -->
                                <table role="presentation" width="100%" cellspacing="0" cellpadding="0" style="font-size: 13px;">
                                    <tr>
                                        <td style="padding: 8px 0; border-bottom: 1px solid rgba(0,0,0,0.05);">
                                            <span style="color: #6b7280; font-size: 10px; text-transform: uppercase; letter-spacing: 0.5px; font-weight: 600;">Affected Product</span><br>
                                            <span style="color: #111827;"><strong>{vuln.vendor_project}</strong> - {vuln.product}</span>
                                        </td>
                                    </tr>
                                    <tr>
                                        <td style="padding: 8px 0; border-bottom: 1px solid rgba(0,0,0,0.05);">
                                            <span style="color: #6b7280; font-size: 10px; text-transform: uppercase; letter-spacing: 0.5px; font-weight: 600;">Your Product</span><br>
                                            <span style="color: #111827;"><strong>{product.vendor}</strong> - {product.product_name}{f' (v{product.version})' if product.version else ''}</span>
                                        </td>
                                    </tr>
                                    <tr>
                                        <td style="padding: 8px 0; border-bottom: 1px solid rgba(0,0,0,0.05);">
                                            <span style="color: #6b7280; font-size: 10px; text-transform: uppercase; letter-spacing: 0.5px; font-weight: 600;">Description</span><br>
                                            <span style="color: #374151;">{vuln.short_description[:200]}{'...' if len(vuln.short_description) > 200 else ''}</span>
                                        </td>
                                    </tr>
                                    <tr>
                                        <td style="padding: 8px 0; border-bottom: 1px solid rgba(0,0,0,0.05);">
                                            <span style="color: #6b7280; font-size: 10px; text-transform: uppercase; letter-spacing: 0.5px; font-weight: 600;">Required Action</span><br>
                                            <span style="color: #dc2626; font-weight: 600;">{vuln.required_action}</span>
                                        </td>
                                    </tr>
                                    <tr>
                                        <td style="padding: 8px 0;">
                                            <span style="color: #6b7280; font-size: 10px; text-transform: uppercase; letter-spacing: 0.5px; font-weight: 600;">Timeline</span><br>
                                            <span style="color: #374151;">Added: {vuln.date_added} ({days_old} days ago){f' | <strong style="color:#dc2626;">Due: {vuln.due_date}</strong>' if vuln.due_date else ''}</span>
                                        </td>
                                    </tr>
                                </table>

                                <!-- NVD Link -->
                                <div style="margin-top: 15px;">
                                    <a href="https://nvd.nist.gov/vuln/detail/{vuln.cve_id}" style="color: #1e40af; text-decoration: none; font-size: 13px; font-weight: 600;">
                                        View in NVD Database →
                                    </a>
                                </div>
                            </div>
                        </td>
                    </tr>
"""

        if len(matches) > 15:
            html += f"""
                    <!-- More Vulnerabilities Notice -->
                    <tr>
                        <td style="padding: 0 30px 30px 30px;">
                            <div style="background: #f3f4f6; border-radius: 8px; padding: 20px; text-align: center;">
                                <p style="margin: 0; font-size: 16px; font-weight: 700; color: #374151;">
                                    + {len(matches) - 15} more vulnerabilities
                                </p>
                                <p style="margin: 8px 0 0 0; font-size: 14px; color: #6b7280;">
                                    Login to SentriKat to view all vulnerabilities
                                </p>
                            </div>
                        </td>
                    </tr>
"""

        html += f"""
                    <!-- Footer -->
                    <tr>
                        <td style="background: #f8fafc; padding: 30px; text-align: center; border-top: 1px solid #e5e7eb;">
                            <p style="margin: 0 0 10px 0; font-size: 14px; font-weight: 700; color: #1e40af;">
                                SentriKat
                            </p>
                            <p style="margin: 0 0 5px 0; font-size: 12px; color: #6b7280;">
                                Enterprise Vulnerability Management Platform
                            </p>
                            <p style="margin: 15px 0 0 0; font-size: 11px; color: #9ca3af;">
                                This is an automated security alert from SentriKat.<br>
                                Please do not reply to this email. Contact your administrator for support.
                            </p>
                            <p style="margin: 15px 0 0 0; font-size: 10px; color: #9ca3af;">
                                © {datetime.now().year} {organization.display_name}
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
            # Try global SMTP settings - use centralized function with decryption
            from app.settings_api import get_setting

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
            # Try global SMTP settings - use centralized function with decryption
            from app.settings_api import get_setting

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
            # Try global SMTP settings - use centralized function with decryption
            from app.settings_api import get_setting

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
