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
            dict: Status result with 'status', 'sent_to', 'matches_count', 'new_count', or 'reason'
        """
        if not new_matches:
            return {'status': 'skipped', 'reason': 'No new matches'}

        # Note: Time window check removed - alerts are sent immediately when CVEs are detected.
        # The previous time window logic caused alerts to be lost when sync ran outside
        # business hours. Users can configure email notification rules on their email
        # client/server if they need quiet hours.

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

        # Get recipient emails - handle potentially double-encoded JSON
        recipients = []
        if organization.notification_emails:
            try:
                parsed = json.loads(organization.notification_emails)
                # Check if it's double-encoded (string instead of list)
                if isinstance(parsed, str):
                    parsed = json.loads(parsed)
                recipients = parsed if isinstance(parsed, list) else []
            except (json.JSONDecodeError, TypeError):
                recipients = []

        if not recipients:
            return {'status': 'error', 'reason': 'No recipients configured'}

        # Filter matches by alert settings and confidence level
        filtered_matches = []
        low_confidence_skipped = 0
        now = datetime.utcnow()

        # Get organization's confidence threshold setting (default: skip LOW confidence)
        # Organizations can choose to include low-confidence matches in alerts
        include_low_confidence = getattr(organization, 'alert_on_low_confidence', False)

        for match in new_matches:
            # Skip snoozed matches
            if match.snoozed_until and match.snoozed_until > now:
                continue

            # ENTERPRISE FEATURE: Skip LOW confidence matches by default
            # LOW confidence = keyword-only matching, often false positives
            # HIGH/MEDIUM confidence = CPE matching or vendor+product matching
            if not include_low_confidence and match.match_confidence == 'low':
                low_confidence_skipped += 1
                continue

            severity = match.calculate_effective_priority()  # Now returns CVE severity directly
            vuln = match.vulnerability

            should_alert = False

            # Alert based on CVE severity and user's alert preferences
            # alert_on_critical: Alert for all critical severity CVEs
            if organization.alert_on_critical and severity == 'critical':
                should_alert = True
            # alert_on_high: Alert for all high severity CVEs
            elif organization.alert_on_high and severity == 'high':
                should_alert = True
            # alert_on_ransomware: Alert for any CVE with known ransomware usage
            elif organization.alert_on_ransomware and vuln.known_ransomware:
                should_alert = True
            # alert_on_new_cve: Alert for any new CVE (first time seen)
            elif organization.alert_on_new_cve and match.first_alerted_at is None:
                should_alert = True

            if should_alert:
                filtered_matches.append(match)

        # Log skipped low-confidence matches for transparency
        if low_confidence_skipped > 0:
            import logging
            logging.getLogger(__name__).info(
                f"Skipped {low_confidence_skipped} low-confidence matches for {organization.name} "
                f"(enable alert_on_low_confidence to include)"
            )

        if not filtered_matches:
            return {'status': 'skipped', 'reason': 'No matches meet alert criteria'}

        # Separate NEW matches (never alerted) from already-alerted ones
        # This allows us to show "X new CVEs (Y total)" in the email
        new_matches_list = [m for m in filtered_matches if m.first_alerted_at is None]
        total_matches = len(filtered_matches)
        new_count = len(new_matches_list)

        # Build email with new vs total counts
        if new_count > 0:
            subject = f"🚨 SentriKat Alert: {new_count} New CVE{'s' if new_count != 1 else ''} ({total_matches} total unacknowledged)"
        else:
            subject = f"🚨 SentriKat Daily Digest: {total_matches} Critical Vulnerabilities"

        body = EmailAlertManager._build_alert_email_html(
            organization, filtered_matches, new_count=new_count
        )

        # Send email
        try:
            EmailAlertManager._send_email(
                smtp_config=smtp_config,
                recipients=recipients,
                subject=subject,
                html_body=body
            )

            # Mark NEW matches as alerted (set first_alerted_at)
            now = datetime.utcnow()
            for match in new_matches_list:
                match.first_alerted_at = now
            db.session.commit()

            # Log success
            EmailAlertManager._log_alert(
                organization.id,
                'critical_cve',
                total_matches,
                len(recipients),
                'success',
                None
            )

            return {
                'status': 'success',
                'sent_to': len(recipients),
                'matches_count': total_matches,
                'new_count': new_count
            }

        except Exception as e:
            # Log failure
            EmailAlertManager._log_alert(
                organization.id,
                'critical_cve',
                total_matches,
                len(recipients),
                'failed',
                str(e)
            )
            return {'status': 'error', 'reason': str(e)}

    @staticmethod
    def _build_alert_email_html(organization, matches, new_count=0):
        """Build HTML email body - Clean, professional enterprise design

        Args:
            organization: Organization object
            matches: List of VulnerabilityMatch objects
            new_count: Number of NEW (never-alerted) matches in the list
        """
        total_count = len(matches)

        # Group by priority (CVE-based, not match-based)
        # One CVE affecting 20 products = 1 critical CVE, not 20 matches
        by_priority = {'critical': [], 'high': [], 'medium': [], 'low': []}
        cve_priority_seen = {}  # Track which CVEs we've counted

        for match in matches:
            if not match.product or not match.vulnerability:
                continue  # Skip orphaned matches
            priority = match.calculate_effective_priority()
            cve_id = match.vulnerability.cve_id

            # Only count each CVE once at its highest priority
            if cve_id not in cve_priority_seen:
                cve_priority_seen[cve_id] = priority
                by_priority[priority].append(match)
            elif priority == 'critical' and cve_priority_seen[cve_id] != 'critical':
                # Upgrade to critical if we see a critical match for same CVE
                by_priority[cve_priority_seen[cve_id]] = [m for m in by_priority[cve_priority_seen[cve_id]] if m.vulnerability.cve_id != cve_id]
                by_priority['critical'].append(match)
                cve_priority_seen[cve_id] = 'critical'

        # Unique CVE counts (what users care about)
        unique_cve_count = len(cve_priority_seen)

        # Count amber-tier (likely resolved, needs verification)
        amber_count = sum(1 for m in matches if getattr(m, 'vendor_fix_confidence', None) == 'medium')

        # Group by product for executive summary
        by_product = {}
        product_cves = {}  # Track unique CVEs per product
        for match in matches:
            if not match.product or not match.vulnerability:
                continue  # Skip orphaned matches (product or vulnerability deleted)
            product_key = f"{match.product.vendor} {match.product.product_name}"
            cve_id = match.vulnerability.cve_id
            if product_key not in by_product:
                by_product[product_key] = {'product': match.product, 'matches': [], 'cve_ids': set()}
            if cve_id not in by_product[product_key]['cve_ids']:
                by_product[product_key]['matches'].append(match)
                by_product[product_key]['cve_ids'].add(cve_id)

        priority_colors = {
            'critical': '#dc2626',
            'high': '#ea580c',
            'medium': '#ca8a04',
            'low': '#059669'
        }

        app_url = get_app_url()

        # Build affected products summary (top 5)
        affected_products_html = ""
        for i, (product_key, data) in enumerate(sorted(by_product.items(), key=lambda x: len(x[1]['matches']), reverse=True)[:5]):
            product = data['product']
            count = len(data['matches'])
            affected_products_html += f"""
                <tr>
                    <td style="padding: 8px 12px; border-bottom: 1px solid #f3f4f6;">
                        <span style="color: #111827; font-weight: 500;">{product.vendor} - {product.product_name}</span>
                        {f'<span style="color: #6b7280; font-size: 12px;"> v{product.version}</span>' if product.version else ''}
                    </td>
                    <td style="padding: 8px 12px; border-bottom: 1px solid #f3f4f6; text-align: right;">
                        <span style="background: #fee2e2; color: #991b1b; padding: 2px 8px; border-radius: 4px; font-size: 12px; font-weight: 600;">{count} CVE{'s' if count > 1 else ''}</span>
                    </td>
                </tr>"""

        html = f"""
<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
</head>
<body style="margin: 0; padding: 0; background-color: #f8fafc; font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, 'Helvetica Neue', Arial, sans-serif; line-height: 1.5;">
    <table role="presentation" width="100%" cellspacing="0" cellpadding="0" style="background-color: #f8fafc;">
        <tr>
            <td align="center" style="padding: 32px 16px;">
                <table role="presentation" width="100%" cellspacing="0" cellpadding="0" style="max-width: 600px; background-color: #ffffff; border-radius: 8px; box-shadow: 0 1px 3px rgba(0,0,0,0.1);">

                    <!-- Simple Header -->
                    <tr>
                        <td style="padding: 24px 32px; border-bottom: 1px solid #e5e7eb;">
                            <table role="presentation" width="100%" cellspacing="0" cellpadding="0">
                                <tr>
                                    <td>
                                        <span style="font-size: 20px; font-weight: 700; color: #1e40af;">SentriKat</span>
                                        <span style="color: #9ca3af; margin-left: 8px;">|</span>
                                        <span style="color: #6b7280; margin-left: 8px; font-size: 14px;">Security Alert</span>
                                    </td>
                                    <td align="right">
                                        <span style="font-size: 12px; color: #9ca3af;">{datetime.now().strftime('%Y-%m-%d %H:%M')}</span>
                                    </td>
                                </tr>
                            </table>
                        </td>
                    </tr>

                    <!-- Alert Summary -->
                    <tr>
                        <td style="padding: 32px;">
                            <!-- Alert Badge -->
                            <div style="background: #fef2f2; border: 1px solid #fecaca; border-radius: 6px; padding: 16px 20px; margin-bottom: 24px;">
                                <table role="presentation" width="100%" cellspacing="0" cellpadding="0">
                                    <tr>
                                        <td>
                                            <span style="font-size: 18px; font-weight: 700; color: #991b1b;">
                                                {f'{new_count} New CVE{"s" if new_count != 1 else ""} ({unique_cve_count} total CVEs)' if new_count > 0 else f'{unique_cve_count} Unique CVEs Detected'}
                                            </span>
                                            <p style="margin: 4px 0 0 0; font-size: 14px; color: #7f1d1d;">
                                                Affecting <strong>{organization.display_name}</strong> - Immediate action required
                                            </p>
                                        </td>
                                    </tr>
                                </table>
                            </div>

                            <!-- Stats Row -->
                            <table role="presentation" width="100%" cellspacing="0" cellpadding="0" style="margin-bottom: 24px;">
                                <tr>
                                    <td width="25%" style="text-align: center; padding: 12px 8px;">
                                        <div style="font-size: 28px; font-weight: 700; color: #059669;">{new_count}</div>
                                        <div style="font-size: 12px; color: #6b7280; text-transform: uppercase;">New</div>
                                    </td>
                                    <td width="25%" style="text-align: center; padding: 12px 8px; border-left: 1px solid #e5e7eb;">
                                        <div style="font-size: 28px; font-weight: 700; color: #dc2626;">{len(by_priority['critical'])}</div>
                                        <div style="font-size: 12px; color: #6b7280; text-transform: uppercase;">Critical</div>
                                    </td>
                                    <td width="25%" style="text-align: center; padding: 12px 8px; border-left: 1px solid #e5e7eb;">
                                        <div style="font-size: 28px; font-weight: 700; color: #ea580c;">{len(by_priority['high'])}</div>
                                        <div style="font-size: 12px; color: #6b7280; text-transform: uppercase;">High</div>
                                    </td>
                                    <td width="25%" style="text-align: center; padding: 12px 8px; border-left: 1px solid #e5e7eb;">
                                        <div style="font-size: 28px; font-weight: 700; color: {('#d97706' if amber_count > 0 else '#374151')};">{amber_count if amber_count > 0 else len(by_product)}</div>
                                        <div style="font-size: 12px; color: #6b7280; text-transform: uppercase;">{'Verify' if amber_count > 0 else 'Products'}</div>
                                    </td>
                                </tr>
                            </table>

                            <!-- Affected Products Summary -->
                            <div style="margin-bottom: 24px;">
                                <div style="font-size: 13px; font-weight: 600; color: #374151; text-transform: uppercase; letter-spacing: 0.5px; margin-bottom: 12px;">
                                    Affected Products
                                </div>
                                <table role="presentation" width="100%" cellspacing="0" cellpadding="0" style="background: #f9fafb; border-radius: 6px; border: 1px solid #e5e7eb;">
                                    {affected_products_html}
                                    {f'<tr><td colspan="2" style="padding: 8px 12px; text-align: center;"><span style="color: #6b7280; font-size: 12px;">+ {len(by_product) - 5} more products</span></td></tr>' if len(by_product) > 5 else ''}
                                </table>
                            </div>

                            <!-- CTA Button -->
                            <div style="text-align: center; margin-bottom: 8px;">
                                <a href="{app_url}" style="display: inline-block; background: #1e40af; color: #ffffff; text-decoration: none; padding: 12px 28px; border-radius: 6px; font-weight: 600; font-size: 14px;">
                                    View Dashboard
                                </a>
                            </div>
                        </td>
                    </tr>

                    <!-- Divider -->
                    <tr>
                        <td style="padding: 0 32px;">
                            <div style="height: 1px; background: #e5e7eb;"></div>
                        </td>
                    </tr>

                    <!-- Vulnerability Details Header -->
                    <tr>
                        <td style="padding: 24px 32px 16px 32px;">
                            <span style="font-size: 14px; font-weight: 600; color: #374151; text-transform: uppercase; letter-spacing: 0.5px;">
                                Vulnerability Details
                            </span>
                        </td>
                    </tr>
"""

        # Add vulnerability cards (show top 10 to avoid huge emails)
        for match in matches[:10]:
            vuln = match.vulnerability
            product = match.product
            priority = match.calculate_effective_priority()

            border_color = priority_colors.get(priority, '#6b7280')
            days_old = (date.today() - vuln.date_added).days if vuln.date_added else 0
            days_until_due = (vuln.due_date - date.today()).days if vuln.due_date else None

            # Urgency indicator
            if days_until_due is not None:
                if days_until_due < 0:
                    # OVERDUE - past due date
                    overdue_days = abs(days_until_due)
                    urgency_html = f'<span style="background: #7f1d1d; color: white; padding: 2px 6px; border-radius: 3px; font-size: 11px; font-weight: 600;">⚠️ OVERDUE by {overdue_days} days</span>'
                elif days_until_due == 0:
                    urgency_html = '<span style="background: #dc2626; color: white; padding: 2px 6px; border-radius: 3px; font-size: 11px; font-weight: 600;">⚠️ DUE TODAY</span>'
                elif days_until_due <= 7:
                    urgency_html = f'<span style="background: #fef2f2; color: #991b1b; padding: 2px 6px; border-radius: 3px; font-size: 11px; font-weight: 600;">Due in {days_until_due} days</span>'
                else:
                    urgency_html = f'<span style="color: #6b7280; font-size: 11px;">Due: {vuln.due_date}</span>'
            else:
                urgency_html = ''

            # CVSS color based on score
            cvss_score = vuln.cvss_score or 0
            if cvss_score >= 9.0:
                cvss_color = '#dc2626'  # Critical - red
                cvss_bg = '#fef2f2'
            elif cvss_score >= 7.0:
                cvss_color = '#ea580c'  # High - orange
                cvss_bg = '#fff7ed'
            elif cvss_score >= 4.0:
                cvss_color = '#ca8a04'  # Medium - yellow
                cvss_bg = '#fefce8'
            else:
                cvss_color = '#16a34a'  # Low - green
                cvss_bg = '#f0fdf4'

            # EPSS display
            epss_html = ''
            if vuln.epss_score is not None:
                epss_pct = vuln.epss_score * 100
                if epss_pct >= 10:
                    epss_color = '#dc2626'  # High exploitation probability
                    epss_bg = '#fef2f2'
                elif epss_pct >= 1:
                    epss_color = '#ea580c'  # Medium
                    epss_bg = '#fff7ed'
                else:
                    epss_color = '#16a34a'  # Low
                    epss_bg = '#f0fdf4'
                epss_html = f'''
                                                <td style="padding: 0 4px;">
                                                    <div style="background: {epss_bg}; border-radius: 4px; padding: 6px 10px; text-align: center;">
                                                        <div style="font-size: 10px; color: #6b7280; text-transform: uppercase;">EPSS</div>
                                                        <div style="font-size: 14px; font-weight: 700; color: {epss_color};">{epss_pct:.1f}%</div>
                                                    </div>
                                                </td>'''
            else:
                epss_html = '''
                                                <td style="padding: 0 4px;">
                                                    <div style="background: #f3f4f6; border-radius: 4px; padding: 6px 10px; text-align: center;">
                                                        <div style="font-size: 10px; color: #6b7280; text-transform: uppercase;">EPSS</div>
                                                        <div style="font-size: 12px; color: #9ca3af;">N/A</div>
                                                    </div>
                                                </td>'''

            # Pre-compute amber-tier vendor fix notice
            is_amber = getattr(match, 'vendor_fix_confidence', None) == 'medium'
            amber_badge_html = '<span style="display: inline-block; background: #d97706; color: white; padding: 1px 6px; border-radius: 3px; font-size: 10px; font-weight: 600; margin-left: 6px;">LIKELY RESOLVED - VERIFY</span>' if is_amber else ''
            amber_notice_html = ''
            if is_amber:
                amber_notice_html = (
                    '<!-- Vendor Fix Notice (Amber Tier) -->'
                    '<div style="margin-top: 10px; padding: 8px 10px; background: #fffbeb; border-left: 3px solid #d97706; border-radius: 4px;">'
                    '<span style="font-size: 11px; color: #92400e; text-transform: uppercase; font-weight: 600;">Vendor Fix Detected:</span>'
                    '<span style="font-size: 12px; color: #92400e;"> A vendor patch may be applied but could not be verified with distro-native comparison. Please confirm manually.</span>'
                    '</div>'
                )

            html += f"""
                    <!-- Vulnerability Card -->
                    <tr>
                        <td style="padding: 0 32px 16px 32px;">
                            <table role="presentation" width="100%" cellspacing="0" cellpadding="0" style="border: 1px solid #e5e7eb; border-radius: 6px; border-left: 3px solid {border_color};">
                                <tr>
                                    <td style="padding: 16px;">
                                        <!-- Header row -->
                                        <table role="presentation" width="100%" cellspacing="0" cellpadding="0">
                                            <tr>
                                                <td>
                                                    <a href="https://nvd.nist.gov/vuln/detail/{vuln.cve_id}" style="font-size: 15px; font-weight: 700; color: #1e40af; text-decoration: none;">{vuln.cve_id}</a>
                                                    {f'<span style="background: #7c2d12; color: white; padding: 1px 6px; border-radius: 3px; font-size: 10px; font-weight: 600; margin-left: 6px;">RANSOMWARE</span>' if vuln.known_ransomware else ''}
                                                </td>
                                                <td align="right">
                                                    {urgency_html}
                                                </td>
                                            </tr>
                                        </table>
                                        <!-- Scores Row -->
                                        <table role="presentation" cellspacing="0" cellpadding="0" style="margin-top: 10px;">
                                            <tr>
                                                <td style="padding: 0 4px 0 0;">
                                                    <div style="background: {cvss_bg}; border-radius: 4px; padding: 6px 10px; text-align: center;">
                                                        <div style="font-size: 10px; color: #6b7280; text-transform: uppercase;">CVSS</div>
                                                        <div style="font-size: 14px; font-weight: 700; color: {cvss_color};">{cvss_score if cvss_score else 'N/A'}</div>
                                                    </div>
                                                </td>
                                                {epss_html}
                                                <td style="padding: 0 4px;">
                                                    <div style="background: #f3f4f6; border-radius: 4px; padding: 6px 10px; text-align: center;">
                                                        <div style="font-size: 10px; color: #6b7280; text-transform: uppercase;">Severity</div>
                                                        <div style="font-size: 12px; font-weight: 600; color: {border_color};">{priority}</div>
                                                    </div>
                                                </td>
                                            </tr>
                                        </table>
                                        <!-- Product -->
                                        <div style="margin-top: 10px; font-size: 13px;">
                                            <span style="color: #6b7280;">Affected:</span>
                                            <span style="color: #111827; font-weight: 500;">{product.vendor} - {product.product_name}</span>
                                            {f'<span style="color: #9ca3af;"> v{product.version}</span>' if product.version else ''}
                                            {amber_badge_html}
                                        </div>
                                        <!-- Description -->
                                        <div style="margin-top: 8px; font-size: 13px; color: #4b5563; line-height: 1.4;">
                                            {vuln.short_description[:180]}{'...' if len(vuln.short_description) > 180 else ''}
                                        </div>
                                        {amber_notice_html}
                                        <!-- Action -->
                                        <div style="margin-top: 10px; padding: 8px 10px; background: #f0fdf4; border-left: 3px solid #16a34a; border-radius: 4px;">
                                            <span style="font-size: 11px; color: #166534; text-transform: uppercase; font-weight: 600;">How to Fix:</span>
                                            <span style="font-size: 12px; color: #166534;"> {vuln.required_action[:150]}{'...' if len(vuln.required_action) > 150 else ''}</span>
                                        </div>
                                    </td>
                                </tr>
                            </table>
                        </td>
                    </tr>
"""

        if len(matches) > 10:
            html += f"""
                    <!-- More Vulnerabilities Notice -->
                    <tr>
                        <td style="padding: 0 32px 24px 32px;">
                            <div style="background: #f3f4f6; border-radius: 6px; padding: 12px; text-align: center;">
                                <span style="font-size: 13px; color: #374151;">
                                    + {len(matches) - 10} more vulnerabilities -
                                </span>
                                <a href="{app_url}" style="color: #1e40af; text-decoration: none; font-weight: 600; font-size: 13px;">View all in dashboard</a>
                            </div>
                        </td>
                    </tr>
"""

        html += f"""
                    <!-- Footer -->
                    <tr>
                        <td style="padding: 24px 32px; border-top: 1px solid #e5e7eb; text-align: center;">
                            <p style="margin: 0; font-size: 12px; color: #9ca3af;">
                                Automated alert from SentriKat - {organization.display_name}
                            </p>
                            <p style="margin: 8px 0 0 0; font-size: 11px; color: #d1d5db;">
                                Do not reply to this email
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
    def _send_email(smtp_config, recipients, subject, html_body, max_retries=3):
        """Send HTML email via SMTP with retry logic (supports Gmail, Office365, Internal SMTP)

        Retries up to max_retries times with exponential backoff for transient failures.
        """
        import time

        msg = MIMEMultipart('alternative')
        msg['From'] = f"{smtp_config['from_name']} <{smtp_config['from_email']}>"
        msg['To'] = ', '.join(recipients)
        msg['Subject'] = subject

        # Attach HTML body
        html_part = MIMEText(html_body, 'html', 'utf-8')
        msg.attach(html_part)

        last_error = None
        for attempt in range(max_retries):
            try:
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
                return  # Success

            except Exception as e:
                last_error = e
                if attempt < max_retries - 1:
                    # Exponential backoff: 2s, 4s, 8s
                    wait_time = 2 ** (attempt + 1)
                    time.sleep(wait_time)
                else:
                    # Final attempt failed, raise the error
                    raise last_error

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


# ============================================================================
# Admin-Triggered 2FA Reset Email
# ============================================================================

def send_2fa_reset_email(user, reset_by_username=None):
    """
    Send email notification when an admin resets a user's 2FA

    Args:
        user: User object whose 2FA was reset
        reset_by_username: Username of admin who performed the reset

    Returns:
        tuple: (success: bool, details: str) - success status and details message
    """
    from app.models import Organization
    import logging
    logger = logging.getLogger(__name__)

    try:
        organization = Organization.query.get(user.organization_id)
        if not organization:
            msg = f"No organization found for user {user.username}"
            logger.warning(msg)
            return False, msg

        smtp_config = organization.get_smtp_config()
        smtp_source = "organization"

        if not smtp_config['host'] or not smtp_config['from_email']:
            smtp_source = "global"
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
            logger.warning(f"{msg} - cannot send 2FA reset email to {user.email}")
            return False, msg

        subject = f"SentriKat - Two-Factor Authentication Reset"
        html_body = _build_2fa_reset_email_html(user, organization, reset_by_username)

        logger.info(f"Sending 2FA reset email to {user.email} via {smtp_source} SMTP")

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
        error_detail = f"{type(e).__name__}: {str(e)}"
        logger.error(f"Failed to send 2FA reset email to {user.email}: {error_detail}")
        logger.error(traceback.format_exc())
        return False, error_detail


def _build_2fa_reset_email_html(user, organization, reset_by_username=None):
    """Build HTML email for 2FA reset notification"""

    html = f"""
<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
</head>
<body style="margin: 0; padding: 0; font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, 'Helvetica Neue', Arial, sans-serif; background-color: #f3f4f6;">
    <div style="max-width: 600px; margin: 0 auto; padding: 40px 20px;">
        <div style="background: linear-gradient(135deg, #7c3aed 0%, #a855f7 100%); padding: 30px; text-align: center; border-radius: 12px 12px 0 0;">
            <div style="font-size: 48px; margin-bottom: 10px;">🔐</div>
            <h1 style="color: white; margin: 0; font-size: 24px;">Two-Factor Authentication Reset</h1>
        </div>

        <div style="background: white; padding: 40px; border-radius: 0 0 12px 12px; box-shadow: 0 4px 6px rgba(0, 0, 0, 0.1);">
            <p style="font-size: 16px; color: #374151;">Hello <strong>{user.full_name or user.username}</strong>,</p>

            <div style="background: #fef3c7; border-left: 4px solid #f59e0b; padding: 15px; margin: 20px 0; border-radius: 4px;">
                <p style="margin: 0; color: #92400e; font-weight: 600;">
                    ⚠️ Your two-factor authentication has been reset by an administrator.
                </p>
            </div>

            <p style="color: #374151; font-size: 16px;">
                This means:
            </p>
            <ul style="color: #374151; font-size: 16px;">
                <li>Your previous 2FA setup has been disabled</li>
                <li>You can now log in without a 2FA code</li>
                <li>You should set up 2FA again from your Security Settings after logging in</li>
            </ul>

            <div style="background: #f9fafb; padding: 20px; border-radius: 8px; margin: 20px 0;">
                <div style="margin-bottom: 10px;">
                    <strong>Username:</strong> {user.username}
                </div>
                <div style="margin-bottom: 10px;">
                    <strong>Organization:</strong> {organization.display_name}
                </div>
                <div style="margin-bottom: 10px;">
                    <strong>Reset by:</strong> {reset_by_username or 'Administrator'}
                </div>
                <div>
                    <strong>Time:</strong> {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
                </div>
            </div>

            <p style="color: #dc2626; font-size: 14px; font-weight: 600;">
                🔒 Security Recommendation: Set up 2FA again as soon as possible to protect your account.
            </p>

            <div style="text-align: center; margin: 30px 0;">
                <a href="{get_app_url()}/login" style="display: inline-block; background: #7c3aed; color: white; text-decoration: none; padding: 14px 32px; border-radius: 8px; font-weight: 600; font-size: 14px;">
                    Login to SentriKat
                </a>
            </div>

            <p style="color: #6b7280; font-size: 14px;">
                If you did not request this reset, please contact your administrator immediately.
            </p>
        </div>

        <div style="text-align: center; padding: 20px; color: #9ca3af; font-size: 12px;">
            <p>This is an automated security notification from SentriKat</p>
            <p>© {datetime.now().year} {organization.display_name}</p>
        </div>
    </div>
</body>
</html>
"""

    return html


# ============================================================================
# Admin-Triggered Password Change Email
# ============================================================================

def send_password_change_forced_email(user, forced_by_username=None):
    """
    Send email notification when an admin forces a user to change password

    Args:
        user: User object who must change password
        forced_by_username: Username of admin who triggered this

    Returns:
        tuple: (success: bool, details: str) - success status and details message
    """
    from app.models import Organization
    import logging
    logger = logging.getLogger(__name__)

    try:
        organization = Organization.query.get(user.organization_id)
        if not organization:
            msg = f"No organization found for user {user.username}"
            logger.warning(msg)
            return False, msg

        smtp_config = organization.get_smtp_config()
        smtp_source = "organization"

        if not smtp_config['host'] or not smtp_config['from_email']:
            smtp_source = "global"
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
            logger.warning(f"{msg} - cannot send password change email to {user.email}")
            return False, msg

        subject = f"SentriKat - Password Change Required"
        html_body = _build_password_change_forced_email_html(user, organization, forced_by_username)

        logger.info(f"Sending password change required email to {user.email} via {smtp_source} SMTP")

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
        error_detail = f"{type(e).__name__}: {str(e)}"
        logger.error(f"Failed to send password change email to {user.email}: {error_detail}")
        logger.error(traceback.format_exc())
        return False, error_detail


def _build_password_change_forced_email_html(user, organization, forced_by_username=None):
    """Build HTML email for forced password change notification"""

    html = f"""
<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
</head>
<body style="margin: 0; padding: 0; font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, 'Helvetica Neue', Arial, sans-serif; background-color: #f3f4f6;">
    <div style="max-width: 600px; margin: 0 auto; padding: 40px 20px;">
        <div style="background: linear-gradient(135deg, #ea580c 0%, #f97316 100%); padding: 30px; text-align: center; border-radius: 12px 12px 0 0;">
            <div style="font-size: 48px; margin-bottom: 10px;">🔑</div>
            <h1 style="color: white; margin: 0; font-size: 24px;">Password Change Required</h1>
        </div>

        <div style="background: white; padding: 40px; border-radius: 0 0 12px 12px; box-shadow: 0 4px 6px rgba(0, 0, 0, 0.1);">
            <p style="font-size: 16px; color: #374151;">Hello <strong>{user.full_name or user.username}</strong>,</p>

            <div style="background: #fef3c7; border-left: 4px solid #f59e0b; padding: 15px; margin: 20px 0; border-radius: 4px;">
                <p style="margin: 0; color: #92400e; font-weight: 600;">
                    ⚠️ An administrator has required you to change your password.
                </p>
            </div>

            <p style="color: #374151; font-size: 16px;">
                On your next login, you will be prompted to create a new password. This is a security measure to ensure your account remains protected.
            </p>

            <div style="background: #f9fafb; padding: 20px; border-radius: 8px; margin: 20px 0;">
                <div style="margin-bottom: 10px;">
                    <strong>Username:</strong> {user.username}
                </div>
                <div style="margin-bottom: 10px;">
                    <strong>Organization:</strong> {organization.display_name}
                </div>
                <div style="margin-bottom: 10px;">
                    <strong>Required by:</strong> {forced_by_username or 'Administrator'}
                </div>
                <div>
                    <strong>Time:</strong> {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
                </div>
            </div>

            <p style="color: #374151; font-size: 14px;">
                <strong>What happens next:</strong>
            </p>
            <ol style="color: #374151; font-size: 14px;">
                <li>Log in with your current password</li>
                <li>You'll be prompted to create a new password</li>
                <li>Choose a strong, unique password</li>
                <li>You'll be logged in with your new credentials</li>
            </ol>

            <div style="text-align: center; margin: 30px 0;">
                <a href="{get_app_url()}/login" style="display: inline-block; background: #ea580c; color: white; text-decoration: none; padding: 14px 32px; border-radius: 8px; font-weight: 600; font-size: 14px;">
                    Login to SentriKat
                </a>
            </div>

            <p style="color: #6b7280; font-size: 14px;">
                If you did not expect this requirement, please contact your administrator.
            </p>
        </div>

        <div style="text-align: center; padding: 20px; color: #9ca3af; font-size: 12px;">
            <p>This is an automated security notification from SentriKat</p>
            <p>© {datetime.now().year} {organization.display_name}</p>
        </div>
    </div>
</body>
</html>
"""

    return html


# ============================================================================
# Scheduled Report Email
# ============================================================================

def send_scheduled_report(recipients, report_name, org_name, pdf_buffer):
    """
    Send a scheduled vulnerability report via email with PDF attachment.

    Args:
        recipients: List of email addresses to send to
        report_name: Name of the scheduled report
        org_name: Organization display name
        pdf_buffer: BytesIO object containing the PDF report

    Returns:
        dict: {'success': bool, 'error': str} result
    """
    from email.mime.base import MIMEBase
    from email import encoders
    from app.settings_api import get_setting
    import logging

    logger = logging.getLogger(__name__)

    try:
        # Get global SMTP settings
        smtp_config = {
            'host': get_setting('smtp_host'),
            'port': int(get_setting('smtp_port', '587') or '587'),
            'username': get_setting('smtp_username'),
            'password': get_setting('smtp_password'),
            'use_tls': get_setting('smtp_use_tls', 'true') == 'true',
            'use_ssl': get_setting('smtp_use_ssl', 'false') == 'true',
            'from_email': get_setting('smtp_from_email'),
            'from_name': get_setting('smtp_from_name', 'SentriKat Reports')
        }

        if not smtp_config['host'] or not smtp_config['from_email']:
            return {'success': False, 'error': 'SMTP not configured'}

        # Create message
        msg = MIMEMultipart('mixed')
        msg['From'] = f"{smtp_config['from_name']} <{smtp_config['from_email']}>"
        msg['To'] = ', '.join(recipients)
        msg['Subject'] = f"[SentriKat] {report_name} - {org_name}"

        # Email body
        html_body = f"""
<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
</head>
<body style="font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Arial, sans-serif; background-color: #f3f4f6; margin: 0; padding: 0;">
    <div style="max-width: 600px; margin: 0 auto; padding: 40px 20px;">
        <div style="background: linear-gradient(135deg, #1e40af 0%, #3b82f6 100%); padding: 30px; text-align: center; border-radius: 12px 12px 0 0;">
            <h1 style="color: white; margin: 0; font-size: 24px;">Scheduled Report</h1>
            <p style="color: rgba(255,255,255,0.9); margin: 10px 0 0 0;">{report_name}</p>
        </div>

        <div style="background: white; padding: 40px; border-radius: 0 0 12px 12px; box-shadow: 0 4px 6px rgba(0, 0, 0, 0.1);">
            <p style="font-size: 16px; color: #374151; line-height: 1.6;">
                Hello,
            </p>

            <p style="font-size: 16px; color: #374151; line-height: 1.6;">
                Please find attached the scheduled vulnerability report for <strong>{org_name}</strong>.
            </p>

            <div style="background: #f0f9ff; border-left: 4px solid #3b82f6; padding: 15px; margin: 20px 0; border-radius: 4px;">
                <p style="margin: 0; color: #1e40af;">
                    <strong>Report:</strong> {report_name}<br>
                    <strong>Generated:</strong> {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
                </p>
            </div>

            <p style="color: #6b7280; font-size: 14px;">
                Open the attached PDF to view the full vulnerability report.
            </p>

            <div style="text-align: center; margin: 30px 0;">
                <a href="{get_app_url()}" style="display: inline-block; background: #1e40af; color: white; text-decoration: none; padding: 14px 32px; border-radius: 8px; font-weight: 600; font-size: 14px;">
                    View Dashboard
                </a>
            </div>
        </div>

        <div style="text-align: center; padding: 20px; color: #9ca3af; font-size: 12px;">
            <p>This is an automated report from SentriKat</p>
            <p>© {datetime.now().year} {org_name}</p>
        </div>
    </div>
</body>
</html>
"""

        # Attach HTML body
        html_part = MIMEText(html_body, 'html', 'utf-8')
        msg.attach(html_part)

        # Attach PDF
        pdf_buffer.seek(0)
        pdf_attachment = MIMEBase('application', 'pdf')
        pdf_attachment.set_payload(pdf_buffer.read())
        encoders.encode_base64(pdf_attachment)

        filename = f"{report_name.replace(' ', '_')}_{datetime.now().strftime('%Y%m%d')}.pdf"
        pdf_attachment.add_header(
            'Content-Disposition',
            'attachment',
            filename=filename
        )
        msg.attach(pdf_attachment)

        # Send email
        if smtp_config['use_ssl']:
            server = smtplib.SMTP_SSL(smtp_config['host'], smtp_config['port'], timeout=30)
        else:
            server = smtplib.SMTP(smtp_config['host'], smtp_config['port'], timeout=30)
            if smtp_config['use_tls']:
                server.starttls()

        if smtp_config['username'] and smtp_config['password']:
            server.login(smtp_config['username'], smtp_config['password'])

        server.sendmail(smtp_config['from_email'], recipients, msg.as_string())
        server.quit()

        logger.info(f"Scheduled report '{report_name}' sent to {len(recipients)} recipients")
        return {'success': True}

    except Exception as e:
        logger.exception(f"Failed to send scheduled report '{report_name}'")
        return {'success': False, 'error': str(e)}


# Make the function accessible from the EmailAlertManager class
EmailAlertManager.send_scheduled_report = staticmethod(send_scheduled_report)
