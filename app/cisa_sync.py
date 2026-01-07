import requests
import json
from datetime import datetime, timedelta
from app import db
from app.models import Vulnerability, SyncLog, Product, SystemSettings
from app.nvd_api import fetch_cvss_data
from config import Config
import urllib3
import logging

logger = logging.getLogger(__name__)


def send_webhook_notification(new_cves_count, critical_count, total_matches):
    """Send notifications to configured webhooks (Slack/Teams)"""
    try:
        # Get webhook settings
        slack_enabled = SystemSettings.query.filter_by(key='slack_enabled').first()
        slack_url = SystemSettings.query.filter_by(key='slack_webhook_url').first()
        teams_enabled = SystemSettings.query.filter_by(key='teams_enabled').first()
        teams_url = SystemSettings.query.filter_by(key='teams_webhook_url').first()

        results = []

        # Send to Slack if enabled
        if slack_enabled and slack_enabled.value == 'true' and slack_url and slack_url.value:
            try:
                # Decrypt webhook URL if encrypted
                from app.encryption import decrypt_value
                webhook_url = decrypt_value(slack_url.value) if slack_url.value.startswith('gAAAA') else slack_url.value

                payload = {
                    "blocks": [
                        {
                            "type": "header",
                            "text": {
                                "type": "plain_text",
                                "text": "🔒 SentriKat CVE Sync Complete",
                                "emoji": True
                            }
                        },
                        {
                            "type": "section",
                            "fields": [
                                {"type": "mrkdwn", "text": f"*New CVEs:*\n{new_cves_count}"},
                                {"type": "mrkdwn", "text": f"*Critical:*\n{critical_count}"},
                                {"type": "mrkdwn", "text": f"*Product Matches:*\n{total_matches}"}
                            ]
                        }
                    ]
                }

                if critical_count > 0:
                    payload["blocks"].append({
                        "type": "section",
                        "text": {
                            "type": "mrkdwn",
                            "text": f"⚠️ *{critical_count} critical vulnerabilities* require immediate attention!"
                        }
                    })

                response = requests.post(webhook_url, json=payload, timeout=10)
                results.append({'slack': response.status_code in [200, 204]})
            except Exception as e:
                logger.error(f"Slack webhook failed: {e}")
                results.append({'slack': False, 'error': str(e)})

        # Send to Teams if enabled
        if teams_enabled and teams_enabled.value == 'true' and teams_url and teams_url.value:
            try:
                from app.encryption import decrypt_value
                webhook_url = decrypt_value(teams_url.value) if teams_url.value.startswith('gAAAA') else teams_url.value

                payload = {
                    "@type": "MessageCard",
                    "@context": "http://schema.org/extensions",
                    "themeColor": "dc2626" if critical_count > 0 else "1e40af",
                    "summary": f"SentriKat: {new_cves_count} new CVEs synced",
                    "sections": [{
                        "activityTitle": "🔒 SentriKat CVE Sync Complete",
                        "facts": [
                            {"name": "New CVEs", "value": str(new_cves_count)},
                            {"name": "Critical", "value": str(critical_count)},
                            {"name": "Product Matches", "value": str(total_matches)}
                        ],
                        "markdown": True
                    }]
                }

                if critical_count > 0:
                    payload["sections"][0]["text"] = f"⚠️ **{critical_count} critical vulnerabilities** require immediate attention!"

                response = requests.post(webhook_url, json=payload, timeout=10)
                results.append({'teams': response.status_code in [200, 204]})
            except Exception as e:
                logger.error(f"Teams webhook failed: {e}")
                results.append({'teams': False, 'error': str(e)})

        return results
    except Exception as e:
        logger.error(f"Webhook notification failed: {e}")
        return []

def download_cisa_kev():
    """Download CISA KEV JSON feed"""
    try:
        proxies = Config.get_proxies()
        verify_ssl = Config.get_verify_ssl()  # GUI settings > .env settings

        # Suppress SSL warnings if verification is disabled
        if not verify_ssl:
            urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

        response = requests.get(
            Config.CISA_KEV_URL,
            timeout=30,
            proxies=proxies,
            verify=verify_ssl  # Use configured SSL verification setting
        )
        response.raise_for_status()
        return response.json()
    except Exception as e:
        raise Exception(f"Failed to download CISA KEV: {str(e)}")

def parse_and_store_vulnerabilities(kev_data):
    """Parse CISA KEV JSON and store in database"""
    vulnerabilities = kev_data.get('vulnerabilities', [])
    stored_count = 0
    updated_count = 0

    for vuln_data in vulnerabilities:
        cve_id = vuln_data.get('cveID')
        if not cve_id:
            continue

        # Parse dates
        date_added = None
        due_date = None
        try:
            date_added = datetime.strptime(vuln_data.get('dateAdded'), '%Y-%m-%d').date()
        except:
            pass

        try:
            if vuln_data.get('dueDate'):
                due_date = datetime.strptime(vuln_data.get('dueDate'), '%Y-%m-%d').date()
        except:
            pass

        # Check if vulnerability already exists
        vuln = Vulnerability.query.filter_by(cve_id=cve_id).first()

        if vuln:
            # Update existing vulnerability
            vuln.vendor_project = vuln_data.get('vendorProject', '')
            vuln.product = vuln_data.get('product', '')
            vuln.vulnerability_name = vuln_data.get('vulnerabilityName', '')
            vuln.short_description = vuln_data.get('shortDescription', '')
            vuln.required_action = vuln_data.get('requiredAction', '')
            vuln.due_date = due_date
            vuln.known_ransomware = vuln_data.get('knownRansomwareCampaignUse', 'Unknown').lower() == 'known'
            vuln.notes = vuln_data.get('notes', '')
            updated_count += 1
        else:
            # Create new vulnerability
            vuln = Vulnerability(
                cve_id=cve_id,
                vendor_project=vuln_data.get('vendorProject', ''),
                product=vuln_data.get('product', ''),
                vulnerability_name=vuln_data.get('vulnerabilityName', ''),
                date_added=date_added,
                short_description=vuln_data.get('shortDescription', ''),
                required_action=vuln_data.get('requiredAction', ''),
                due_date=due_date,
                known_ransomware=vuln_data.get('knownRansomwareCampaignUse', 'Unknown').lower() == 'known',
                notes=vuln_data.get('notes', '')
            )
            db.session.add(vuln)
            stored_count += 1

    db.session.commit()
    return stored_count, updated_count

def enrich_with_cvss_data(limit=50):
    """
    Enrich vulnerabilities with CVSS scores from NVD API
    Only processes vulnerabilities without CVSS data
    limit: Maximum number of CVEs to process per run (to avoid rate limits)
    """
    # Get vulnerabilities without CVSS data, prioritize recent ones
    vulns_to_enrich = Vulnerability.query.filter(
        Vulnerability.cvss_score == None
    ).order_by(Vulnerability.date_added.desc()).limit(limit).all()

    if not vulns_to_enrich:
        print("All vulnerabilities already have CVSS data")
        return 0

    enriched_count = 0
    print(f"Enriching {len(vulns_to_enrich)} vulnerabilities with CVSS data from NVD...")

    for vuln in vulns_to_enrich:
        cvss_score, severity = fetch_cvss_data(vuln.cve_id)

        if cvss_score is not None:
            vuln.cvss_score = cvss_score
            vuln.severity = severity
            enriched_count += 1
            print(f"  ✓ {vuln.cve_id}: CVSS {cvss_score} ({severity})")
        else:
            # Mark as checked even if not found
            vuln.cvss_score = 0.0  # 0.0 means "checked but not found"
            print(f"  - {vuln.cve_id}: No CVSS data available")

    db.session.commit()
    print(f"Enriched {enriched_count} vulnerabilities with CVSS data")
    return enriched_count

def sync_cisa_kev(enrich_cvss=False, cvss_limit=50):
    """Main sync function to download and process CISA KEV"""
    start_time = datetime.utcnow()
    sync_log = SyncLog()

    try:
        # Download CISA KEV data
        kev_data = download_cisa_kev()

        # Parse and store vulnerabilities
        stored, updated = parse_and_store_vulnerabilities(kev_data)

        # Match vulnerabilities with products
        from app.filters import match_vulnerabilities_to_products
        matches_count = match_vulnerabilities_to_products()

        # Optionally enrich with CVSS data from NVD
        if enrich_cvss:
            enrich_with_cvss_data(limit=cvss_limit)

        # Send email alerts for new critical matches
        from app.models import Organization, VulnerabilityMatch
        from app.email_alerts import EmailAlertManager

        alert_results = []
        organizations = Organization.query.filter_by(active=True).all()

        for org in organizations:
            # Get new unacknowledged matches for this organization from this sync
            new_matches = VulnerabilityMatch.query\
                .join(Vulnerability).join(Product)\
                .filter(
                    Product.organization_id == org.id,
                    VulnerabilityMatch.acknowledged == False,
                    VulnerabilityMatch.created_at >= start_time
                ).all()

            if new_matches:
                # Send alert
                result = EmailAlertManager.send_critical_cve_alert(org, new_matches)
                alert_results.append({
                    'organization': org.name,
                    'result': result
                })

        # Send webhook notifications if new CVEs found
        if stored > 0 or matches_count > 0:
            # Count critical matches
            from app.models import VulnerabilityMatch
            critical_count = VulnerabilityMatch.query\
                .join(Vulnerability)\
                .filter(
                    VulnerabilityMatch.created_at >= start_time,
                    Vulnerability.known_ransomware == True
                ).count()

            # Also count high CVSS as critical
            critical_count += VulnerabilityMatch.query\
                .join(Vulnerability)\
                .filter(
                    VulnerabilityMatch.created_at >= start_time,
                    Vulnerability.cvss_score >= 9.0
                ).count()

            webhook_results = send_webhook_notification(stored, critical_count, matches_count)
            logger.info(f"Webhook notifications sent: {webhook_results}")

        # Log success
        duration = (datetime.utcnow() - start_time).total_seconds()
        sync_log.status = 'success'
        sync_log.vulnerabilities_count = stored + updated
        sync_log.matches_found = matches_count
        sync_log.duration_seconds = duration

        db.session.add(sync_log)
        db.session.commit()

        return {
            'status': 'success',
            'stored': stored,
            'updated': updated,
            'matches': matches_count,
            'duration': duration,
            'alerts_sent': alert_results
        }

    except Exception as e:
        # Log error
        duration = (datetime.utcnow() - start_time).total_seconds()
        sync_log.status = 'error'
        sync_log.error_message = str(e)
        sync_log.duration_seconds = duration

        db.session.add(sync_log)
        db.session.commit()

        return {
            'status': 'error',
            'error': str(e),
            'duration': duration
        }
