import requests
import json
from datetime import datetime, timedelta
from app import db
from app.models import Vulnerability, SyncLog, Product, SystemSettings, Organization
from app.nvd_api import fetch_cvss_data
from config import Config
import urllib3
import logging

logger = logging.getLogger(__name__)


def send_org_webhook(org, new_cves_count, critical_count, matches_count, matches=None, force=False):
    """Send webhook notification for a specific organization using org settings or global fallback

    Sends BATCHED notifications for NEW CVEs only (first_alerted_at IS NULL).
    Format: "3 new CVEs: CVE-1234, CVE-5678, CVE-9012"

    Args:
        org: Organization object
        new_cves_count: Total new CVEs synced (global count)
        critical_count: Count of critical vulnerabilities for this org
        matches_count: Count of product matches for this org
        matches: Optional list of VulnerabilityMatch objects to include product details
    """
    from datetime import datetime

    proxies = Config.get_proxies()
    verify_ssl = Config.get_verify_ssl()

    # Check if org has its own webhook configured
    if org.webhook_enabled and org.webhook_url:
        try:
            # Use the centralized get_webhook_config() method for decryption
            webhook_config = org.get_webhook_config()
            webhook_url = webhook_config['url']
            webhook_format = webhook_config['format'] or 'slack'
            webhook_token = webhook_config['token']

            if not webhook_url or not webhook_url.startswith(('http://', 'https://')):
                return {'org': org.name, 'success': False, 'error': 'Invalid webhook URL (may be corrupted or improperly decrypted)'}

            headers = {'Content-Type': 'application/json'}
            if webhook_token:
                headers['Authorization'] = f'Bearer {webhook_token}'
                headers['X-Auth-Token'] = webhook_token

            # Filter for NEW matches only (never alerted via webhook), unless forced
            new_matches = []
            if matches:
                if force:
                    new_matches = list(matches)
                else:
                    new_matches = [m for m in matches if m.first_alerted_at is None]

            # If no new matches to alert, skip webhook
            if not new_matches:
                return {'org': org.name, 'success': True, 'skipped': True, 'reason': 'No new CVEs'}

            # Get unique CVE IDs from new matches (batched format)
            # Filter out orphaned matches where vulnerability was deleted
            new_matches = [m for m in new_matches if m.vulnerability]
            if not new_matches:
                return {'org': org.name, 'success': True, 'skipped': True, 'reason': 'No valid new CVEs'}
            new_cve_ids = list(dict.fromkeys([m.vulnerability.cve_id for m in new_matches]))
            new_cve_count = len(new_cve_ids)

            # Build CVE list string (show up to 5, then "+X more")
            if new_cve_count <= 5:
                cve_list_str = ", ".join(new_cve_ids)
            else:
                cve_list_str = ", ".join(new_cve_ids[:5]) + f" +{new_cve_count - 5} more"

            # Count amber-tier items (likely resolved, needs verification)
            verify_count = sum(1 for m in new_matches if getattr(m, 'vendor_fix_confidence', None) == 'medium')
            verify_note = f"\n🟡 {verify_count} likely resolved (verify fix)" if verify_count > 0 else ""

            # Build payload based on format - BATCHED message
            if webhook_format in ('slack', 'rocketchat'):
                text = f"🔒 *SentriKat Alert for {org.display_name}*\n"
                text += f"*{new_cve_count} new CVE{'s' if new_cve_count != 1 else ''}:* {cve_list_str}"
                if critical_count > 0:
                    text += f"\n⚠️ *{critical_count} critical*"
                if verify_count > 0:
                    text += f"\n🟡 *{verify_count} likely resolved* (vendor fix detected - verify manually)"
                payload = {"text": text}
            elif webhook_format == 'discord':
                content = f"🔒 **SentriKat Alert for {org.display_name}**\n"
                content += f"**{new_cve_count} new CVE{'s' if new_cve_count != 1 else ''}:** {cve_list_str}"
                if critical_count > 0:
                    content += f"\n⚠️ **{critical_count} critical**"
                if verify_count > 0:
                    content += f"\n🟡 **{verify_count} likely resolved** (vendor fix detected - verify manually)"
                payload = {"content": content}
            elif webhook_format == 'teams':
                facts = [
                    {"name": "New CVEs", "value": str(new_cve_count)},
                    {"name": "CVE IDs", "value": cve_list_str},
                    {"name": "Critical", "value": str(critical_count)}
                ]
                if verify_count > 0:
                    facts.append({"name": "Likely Resolved (Verify)", "value": str(verify_count)})
                payload = {
                    "@type": "MessageCard",
                    "themeColor": "dc2626" if critical_count > 0 else "1e40af",
                    "summary": f"SentriKat: {new_cve_count} new CVEs for {org.display_name}",
                    "sections": [{
                        "activityTitle": f"🔒 SentriKat Alert for {org.display_name}",
                        "facts": facts
                    }]
                }
            else:  # custom or fallback JSON
                payload = {
                    "text": f"SentriKat Alert: {new_cve_count} new CVEs for {org.display_name}: {cve_list_str}",
                    "organization": org.display_name,
                    "new_cve_count": new_cve_count,
                    "cve_ids": new_cve_ids,
                    "critical_count": critical_count,
                    "verify_count": verify_count
                }

            response = requests.post(webhook_url, json=payload, headers=headers, timeout=10, proxies=proxies, verify=verify_ssl)

            if response.status_code in [200, 204]:
                # Mark these matches as alerted (set first_alerted_at)
                now = datetime.utcnow()
                for match in new_matches:
                    match.first_alerted_at = now
                db.session.commit()

            return {'org': org.name, 'success': response.status_code in [200, 204], 'new_cves': new_cve_count}
        except Exception as e:
            logger.error(f"Org webhook failed for {org.name}: {e}")
            return {'org': org.name, 'success': False, 'error': str(e)}

    return None  # No org-specific webhook, will use global


def send_webhook_notification(new_cves_count, critical_count, total_matches, new_cve_ids=None):
    """Send notifications to configured webhooks (Slack/Teams)

    Args:
        new_cves_count: Number of new CVEs
        critical_count: Number of critical CVEs
        total_matches: Total product matches
        new_cve_ids: Optional list of CVE IDs for batched message
    """
    try:
        # Get webhook settings
        slack_enabled = SystemSettings.query.filter_by(key='slack_enabled').first()
        slack_url = SystemSettings.query.filter_by(key='slack_webhook_url').first()
        teams_enabled = SystemSettings.query.filter_by(key='teams_enabled').first()
        teams_url = SystemSettings.query.filter_by(key='teams_webhook_url').first()

        results = []

        # Build CVE list string if provided (batched format)
        cve_list_str = ""
        if new_cve_ids and len(new_cve_ids) > 0:
            if len(new_cve_ids) <= 5:
                cve_list_str = ", ".join(new_cve_ids)
            else:
                cve_list_str = ", ".join(new_cve_ids[:5]) + f" +{len(new_cve_ids) - 5} more"

        # Send to Slack if enabled
        if slack_enabled and slack_enabled.value == 'true' and slack_url and slack_url.value:
            try:
                # Decrypt webhook URL if encrypted
                from app.encryption import decrypt_value
                webhook_url = decrypt_value(slack_url.value) if slack_url.value.startswith('gAAAA') else slack_url.value

                # Use batched format if CVE IDs provided
                if cve_list_str:
                    payload = {
                        "text": f"🔒 *SentriKat Alert*\n*{new_cves_count} new CVE{'s' if new_cves_count != 1 else ''}:* {cve_list_str}" + (f"\n⚠️ *{critical_count} critical*" if critical_count > 0 else "")
                    }
                else:
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

                # Use batched format if CVE IDs provided
                if cve_list_str:
                    facts = [
                        {"name": "New CVEs", "value": str(new_cves_count)},
                        {"name": "CVE IDs", "value": cve_list_str},
                        {"name": "Critical", "value": str(critical_count)}
                    ]
                else:
                    facts = [
                        {"name": "New CVEs", "value": str(new_cves_count)},
                        {"name": "Critical", "value": str(critical_count)},
                        {"name": "Product Matches", "value": str(total_matches)}
                    ]

                payload = {
                    "@type": "MessageCard",
                    "@context": "http://schema.org/extensions",
                    "themeColor": "dc2626" if critical_count > 0 else "1e40af",
                    "summary": f"SentriKat: {new_cves_count} new CVEs",
                    "sections": [{
                        "activityTitle": "🔒 SentriKat Alert",
                        "facts": facts,
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

def download_cisa_kev(max_retries=3, retry_delay=5):
    """Download CISA KEV JSON feed with retry logic"""
    import time

    proxies = Config.get_proxies()
    verify_ssl = Config.get_verify_ssl()

    # Suppress SSL warnings if verification is disabled
    if not verify_ssl:
        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

    last_error = None
    for attempt in range(max_retries):
        try:
            response = requests.get(
                Config.CISA_KEV_URL,
                timeout=30,
                proxies=proxies,
                verify=verify_ssl
            )
            response.raise_for_status()
            return response.json()
        except json.JSONDecodeError as e:
            last_error = f"Error parsing CISA KEV response: Invalid JSON - {str(e)}"
            logger.error(last_error)
            continue
        except requests.exceptions.Timeout as e:
            last_error = f"Timeout connecting to CISA KEV feed (attempt {attempt + 1}/{max_retries})"
            logger.warning(last_error)
        except requests.exceptions.ConnectionError as e:
            last_error = f"Connection error to CISA KEV feed (attempt {attempt + 1}/{max_retries}): {str(e)}"
            logger.warning(last_error)
        except requests.exceptions.HTTPError as e:
            last_error = f"HTTP error from CISA KEV feed: {e.response.status_code}"
            logger.error(last_error)
            # Don't retry on client errors (4xx)
            if e.response.status_code < 500:
                break
        except Exception as e:
            last_error = f"Error downloading CISA KEV: {str(e)}"
            logger.error(last_error)

        # Wait before retrying (exponential backoff)
        if attempt < max_retries - 1:
            wait_time = retry_delay * (2 ** attempt)
            logger.info(f"Retrying in {wait_time} seconds...")
            time.sleep(wait_time)

    raise Exception(f"Failed to download CISA KEV after {max_retries} attempts: {last_error}")

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

def fetch_cpe_version_data(limit=30):
    """
    Fetch CPE version range data from NVD for vulnerabilities.
    This enables precise version-based matching instead of keyword matching.

    CRITICAL for enterprise accuracy: Without version ranges, ALL versions
    of a product are flagged as vulnerable, causing false positives.

    Args:
        limit: Maximum CVEs to fetch per run (NVD rate limits apply)

    Returns:
        int: Number of vulnerabilities enriched with CPE data
    """
    from app.nvd_cpe_api import match_cve_to_cpe
    import time

    # Get vulnerabilities without CPE data, prioritize:
    # 1. New CVEs (recently added to CISA KEV)
    # 2. CVEs with product matches (more urgent to get version data)
    vulns_to_fetch = Vulnerability.query.filter(
        Vulnerability.cpe_data == None
    ).order_by(Vulnerability.date_added.desc()).limit(limit).all()

    if not vulns_to_fetch:
        logger.info("All vulnerabilities already have CPE version data")
        return 0

    enriched_count = 0
    logger.info(f"Fetching CPE version data for {len(vulns_to_fetch)} vulnerabilities from NVD")

    for vuln in vulns_to_fetch:
        try:
            # Fetch CPE data with version ranges from NVD
            cpe_entries = match_cve_to_cpe(vuln.cve_id)

            if cpe_entries:
                # Store CPE data using the model's method
                vuln.set_cpe_entries(cpe_entries)
                enriched_count += 1
                logger.debug(f"Fetched {len(cpe_entries)} CPE entries for {vuln.cve_id}")
            else:
                # Mark as checked even if no CPE data found
                vuln.cpe_data = '[]'
                vuln.cpe_fetched_at = datetime.utcnow()
                logger.debug(f"No CPE data found for {vuln.cve_id}")

        except Exception as e:
            logger.warning(f"Failed to fetch CPE data for {vuln.cve_id}: {e}")
            continue

    db.session.commit()
    logger.info(f"Enriched {enriched_count} vulnerabilities with CPE version data")
    return enriched_count


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
        logger.info("All vulnerabilities already have CVSS data")
        return 0

    enriched_count = 0
    logger.info(f"Enriching {len(vulns_to_enrich)} vulnerabilities with CVSS data from NVD")

    for vuln in vulns_to_enrich:
        cvss_score, severity = fetch_cvss_data(vuln.cve_id)

        if cvss_score is not None:
            vuln.cvss_score = cvss_score
            vuln.severity = severity
            enriched_count += 1
        else:
            # Mark as checked even if not found (0.0 = "checked but not found")
            vuln.cvss_score = 0.0

    db.session.commit()
    logger.info(f"Enriched {enriched_count} vulnerabilities with CVSS data")
    return enriched_count

def sync_cisa_kev(enrich_cvss=False, cvss_limit=50, fetch_cpe=True, cpe_limit=30):
    """Main sync function to download and process CISA KEV"""
    start_time = datetime.utcnow()
    sync_log = SyncLog()

    try:
        # Download CISA KEV data
        kev_data = download_cisa_kev()

        # Parse and store vulnerabilities
        stored, updated = parse_and_store_vulnerabilities(kev_data)

        # Fetch CPE version data from NVD BEFORE matching
        # This enables precise version-based matching
        cpe_enriched = 0
        if fetch_cpe:
            try:
                cpe_enriched = fetch_cpe_version_data(limit=cpe_limit)
                logger.info(f"Fetched CPE version data for {cpe_enriched} vulnerabilities")
            except Exception as e:
                logger.warning(f"CPE version fetch failed (non-critical): {e}")

        # Match vulnerabilities with products (now with version data if available)
        # Use rematch_all_products() to BOTH clean up stale matches (where CPE
        # version ranges have changed, e.g. vendor released cumulative update)
        # AND create new matches.  Without cleanup, matches persist even after
        # the NVD narrows the affected version range.
        from app.filters import rematch_all_products
        removed_count, matches_count = rematch_all_products()
        if removed_count:
            logger.info(f"Cleaned up {removed_count} stale matches (no longer in affected version range)")

        # Optionally enrich with CVSS data from NVD
        if enrich_cvss:
            enrich_with_cvss_data(limit=cvss_limit)

        # Send email alerts for new critical matches
        from app.models import Organization, VulnerabilityMatch
        from app.email_alerts import EmailAlertManager

        alert_results = []
        webhook_results = []
        orgs_with_own_webhook = set()
        organizations = Organization.query.filter_by(active=True).all()

        for org in organizations:
            # Get the organization's effective alert mode
            alert_config = org.get_effective_alert_mode()
            alert_mode = alert_config['mode']
            escalation_days = alert_config['escalation_days']

            # Get product IDs for this organization - include both legacy and multi-org table
            from app.models import product_organizations
            legacy_ids = [p.id for p in Product.query.filter_by(organization_id=org.id).all()]
            multi_org_ids = [row.product_id for row in db.session.query(
                product_organizations.c.product_id
            ).filter(product_organizations.c.organization_id == org.id).all()]
            org_product_ids = list(set(legacy_ids + multi_org_ids))

            if not org_product_ids:
                continue  # No products for this org

            if alert_mode == 'new_only':
                # Only alert on NEW matches from this sync
                matches_to_alert = VulnerabilityMatch.query.filter(
                    VulnerabilityMatch.product_id.in_(org_product_ids),
                    VulnerabilityMatch.acknowledged == False,
                    VulnerabilityMatch.created_at >= start_time
                ).all()
            elif alert_mode == 'daily_reminder':
                # Alert on ALL unacknowledged critical CVEs due within 7 days
                from datetime import date, timedelta
                cutoff_date = date.today() + timedelta(days=7)
                # Get vulnerability IDs within due date range - fetch IDs first
                vuln_ids_due = [v.id for v in Vulnerability.query.filter(
                    Vulnerability.due_date <= cutoff_date,
                    Vulnerability.due_date >= date.today()
                ).all()]
                if vuln_ids_due:
                    matches_to_alert = VulnerabilityMatch.query.filter(
                        VulnerabilityMatch.product_id.in_(org_product_ids),
                        VulnerabilityMatch.acknowledged == False,
                        VulnerabilityMatch.vulnerability_id.in_(vuln_ids_due)
                    ).all()
                else:
                    matches_to_alert = []
            elif alert_mode == 'escalation':
                # Alert on CVEs approaching due date (within escalation_days)
                from datetime import date, timedelta
                cutoff_date = date.today() + timedelta(days=escalation_days)
                # Get vulnerability IDs within due date range - fetch IDs first
                vuln_ids_due = [v.id for v in Vulnerability.query.filter(
                    Vulnerability.due_date <= cutoff_date,
                    Vulnerability.due_date >= date.today()
                ).all()]
                if vuln_ids_due:
                    matches_to_alert = VulnerabilityMatch.query.filter(
                        VulnerabilityMatch.product_id.in_(org_product_ids),
                        VulnerabilityMatch.acknowledged == False,
                        VulnerabilityMatch.vulnerability_id.in_(vuln_ids_due)
                    ).all()
                else:
                    matches_to_alert = []
            else:
                # Fallback to new_only behavior
                matches_to_alert = VulnerabilityMatch.query.filter(
                    VulnerabilityMatch.product_id.in_(org_product_ids),
                    VulnerabilityMatch.acknowledged == False,
                    VulnerabilityMatch.created_at >= start_time
                ).all()

            if matches_to_alert:
                # Send email alert
                result = EmailAlertManager.send_critical_cve_alert(org, matches_to_alert)
                alert_results.append({
                    'organization': org.name,
                    'alert_mode': alert_mode,
                    'result': result
                })

                # Count critical for this org
                org_critical = sum(1 for m in matches_to_alert if m.vulnerability.known_ransomware or (m.vulnerability.cvss_score and m.vulnerability.cvss_score >= 9.0))

                # Send org-specific webhook if configured (takes priority)
                org_webhook_result = send_org_webhook(org, stored, org_critical, len(matches_to_alert), matches=matches_to_alert)
                if org_webhook_result:
                    webhook_results.append(org_webhook_result)
                    orgs_with_own_webhook.add(org.id)

        # Send global webhook notifications for orgs without their own webhook
        if stored > 0 or matches_count > 0:
            # Count total critical matches (for orgs without their own webhook)
            # Fetch IDs first to avoid subquery issues
            critical_vuln_ids = [v.id for v in Vulnerability.query.filter(
                db.or_(Vulnerability.known_ransomware == True, Vulnerability.cvss_score >= 9.0)
            ).all()]

            if orgs_with_own_webhook:
                # Include both legacy organization_id and multi-org table products
                from app.models import product_organizations
                legacy_excluded = [p.id for p in Product.query.filter(
                    Product.organization_id.in_(orgs_with_own_webhook)
                ).all()]
                multi_org_excluded = [row.product_id for row in db.session.query(
                    product_organizations.c.product_id
                ).filter(product_organizations.c.organization_id.in_(orgs_with_own_webhook)).all()]
                excluded_product_ids = list(set(legacy_excluded + multi_org_excluded))
                if critical_vuln_ids and excluded_product_ids:
                    total_critical = VulnerabilityMatch.query.filter(
                        VulnerabilityMatch.created_at >= start_time,
                        ~VulnerabilityMatch.product_id.in_(excluded_product_ids),
                        VulnerabilityMatch.vulnerability_id.in_(critical_vuln_ids)
                    ).count()
                elif critical_vuln_ids:
                    total_critical = VulnerabilityMatch.query.filter(
                        VulnerabilityMatch.created_at >= start_time,
                        VulnerabilityMatch.vulnerability_id.in_(critical_vuln_ids)
                    ).count()
                else:
                    total_critical = 0
            else:
                if critical_vuln_ids:
                    total_critical = VulnerabilityMatch.query.filter(
                        VulnerabilityMatch.created_at >= start_time,
                        VulnerabilityMatch.vulnerability_id.in_(critical_vuln_ids)
                    ).count()
                else:
                    total_critical = 0

            # Only send global webhook if there are orgs without their own webhook
            global_webhook_results = send_webhook_notification(stored, total_critical, matches_count)
            webhook_results.extend(global_webhook_results)

        if webhook_results:
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
            'cpe_enriched': cpe_enriched,
            'duration': duration,
            'alerts_sent': alert_results
        }

    except Exception as e:
        # Rollback any failed transaction first
        try:
            db.session.rollback()
        except Exception:
            pass

        # Log error
        duration = (datetime.utcnow() - start_time).total_seconds()

        # Try to log the error in a fresh transaction
        try:
            sync_log.status = 'error'
            sync_log.error_message = str(e)
            sync_log.duration_seconds = duration

            db.session.add(sync_log)
            db.session.commit()
        except Exception as log_error:
            # If logging fails, just continue - don't lose the original error
            logger.error(f"Failed to log sync error: {log_error}")
            try:
                db.session.rollback()
            except Exception:
                pass

        return {
            'status': 'error',
            'error': str(e),
            'duration': duration
        }
