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
            # Update existing vulnerability (may have been created by EUVD first)
            vuln.vendor_project = vuln_data.get('vendorProject', '')
            vuln.product = vuln_data.get('product', '')
            vuln.vulnerability_name = vuln_data.get('vulnerabilityName', '')
            vuln.short_description = vuln_data.get('shortDescription', '')
            vuln.required_action = vuln_data.get('requiredAction', '')
            vuln.due_date = due_date
            vuln.known_ransomware = vuln_data.get('knownRansomwareCampaignUse', 'Unknown').lower() == 'known'
            vuln.notes = vuln_data.get('notes', '')
            # Reconcile source: if EUVD created it, now CISA confirms it
            if vuln.source == 'euvd':
                vuln.source = 'cisa_kev+euvd'
                vuln.date_added = date_added or vuln.date_added
            updated_count += 1
        else:
            # Create new vulnerability from CISA KEV
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
                notes=vuln_data.get('notes', ''),
                source='cisa_kev',
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
    from app.nvd_cpe_api import match_cve_to_cpe_with_status
    import time

    from sqlalchemy import or_

    # Get vulnerabilities needing CPE data:
    # 1. Never fetched (cpe_data IS NULL) — highest priority
    # 2. Previously empty AND older than 24h — re-check in case NVD completed analysis
    #    (NVD "Awaiting Analysis" can take days to resolve; we must not give up)
    stale_cutoff = datetime.utcnow() - timedelta(hours=24)

    vulns_to_fetch = Vulnerability.query.filter(
        or_(
            Vulnerability.cpe_data == None,
            db.and_(
                Vulnerability.cpe_data == '[]',
                Vulnerability.cpe_fetched_at < stale_cutoff
            )
        )
    ).order_by(
        # Prioritize: never-fetched first, then oldest stale re-checks
        (Vulnerability.cpe_data == None).desc(),
        Vulnerability.date_added.desc()
    ).limit(limit).all()

    if not vulns_to_fetch:
        logger.info("All vulnerabilities already have CPE version data")
        return 0

    enriched_count = 0
    logger.info(f"Fetching CPE version data for {len(vulns_to_fetch)} vulnerabilities from NVD")

    for vuln in vulns_to_fetch:
        try:
            # Fetch CPE data with version ranges AND vulnStatus from NVD
            cpe_entries, nvd_vuln_status = match_cve_to_cpe_with_status(vuln.cve_id)

            # Always update nvd_status from NVD (handles records imported by old code
            # that never had nvd_status set — critical for recovery)
            if nvd_vuln_status and hasattr(vuln, 'nvd_status'):
                vuln.nvd_status = nvd_vuln_status

            # Recovery: if vendor/product are 'Unknown' (imported by old code before
            # description fallback existed), apply the fallback now
            if vuln.vendor_project == 'Unknown' and vuln.product == 'Unknown' and vuln.short_description:
                import re as _re
                _KNOWN_PRODUCTS = {
                    r'google\s+chrome': ('Google', 'Chrome'),
                    r'chromium': ('Chromium', 'Chromium'),
                    r'mozilla\s+firefox': ('Mozilla', 'Firefox'),
                    r'microsoft\s+edge': ('Microsoft', 'Edge'),
                    r'apple\s+safari': ('Apple', 'Safari'),
                    r'microsoft\s+windows': ('Microsoft', 'Windows'),
                    r'linux\s+kernel': ('Linux', 'Kernel'),
                    r'apache\s+(\w+)': ('Apache', None),
                }
                desc_lower = vuln.short_description.lower()
                for pattern, (v, p) in _KNOWN_PRODUCTS.items():
                    m = _re.search(pattern, desc_lower)
                    if m:
                        vuln.vendor_project = v
                        vuln.product = p or m.group(1).title()
                        logger.info(f"Recovered vendor/product for {vuln.cve_id}: {v}/{vuln.product}")
                        break

            if cpe_entries:
                # Store CPE data using the model's method
                vuln.set_cpe_entries(cpe_entries)
                enriched_count += 1
                logger.debug(f"Fetched {len(cpe_entries)} CPE entries for {vuln.cve_id}")
            else:
                # Check if NVD simply hasn't analyzed this CVE yet.
                # "Awaiting Analysis" means NVD received the CVE but hasn't added
                # CPE configurations. We must NOT stamp cpe_fetched_at, otherwise
                # the matching logic permanently treats it as "not affected" and
                # the CVE is never re-checked even after NVD completes analysis.
                effective_status = nvd_vuln_status or getattr(vuln, 'nvd_status', None)
                if effective_status in ('Awaiting Analysis', 'Received', 'Undergoing Analysis'):
                    # Clear stale cpe_fetched_at so the matching logic doesn't
                    # treat NVD as authoritative when it hasn't analyzed yet
                    if vuln.cpe_fetched_at:
                        vuln.cpe_fetched_at = None
                        vuln.cpe_data = None
                    logger.info(f"Skipping CPE stamp for {vuln.cve_id} — NVD status: {effective_status} (will retry)")
                else:
                    vuln.cpe_data = '[]'
                    vuln.cpe_fetched_at = datetime.utcnow()
                    logger.debug(f"No CPE data found for {vuln.cve_id} (NVD status: {effective_status or 'unknown'})")

        except Exception as e:
            logger.warning(f"Failed to fetch CPE data for {vuln.cve_id}: {e}")
            continue

    db.session.commit()
    logger.info(f"Enriched {enriched_count} vulnerabilities with CPE version data")
    return enriched_count


def enrich_with_cvss_data(limit=50):
    """
    Enrich vulnerabilities with CVSS scores using multi-source fallback chain:
      1. NVD API 2.0 (NIST)
      2. CVE.org + CISA Vulnrichment (ADP)
      3. ENISA EUVD (European Vulnerability Database)
    Only processes vulnerabilities without CVSS data.
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
    source_stats = {'nvd': 0, 'cve_org': 0, 'euvd': 0}
    logger.info(f"Enriching {len(vulns_to_enrich)} vulnerabilities with CVSS data (multi-source)")

    for vuln in vulns_to_enrich:
        cvss_score, severity, source = fetch_cvss_data(vuln.cve_id)

        if cvss_score is not None:
            vuln.cvss_score = cvss_score
            vuln.severity = severity
            vuln.cvss_source = source
            enriched_count += 1
            if source:
                source_stats[source] = source_stats.get(source, 0) + 1
        else:
            # Mark as checked even if not found (0.0 = "checked but not found")
            vuln.cvss_score = 0.0

    db.session.commit()
    sources_summary = ', '.join(f'{k}={v}' for k, v in source_stats.items() if v > 0)
    logger.info(f"Enriched {enriched_count} vulnerabilities with CVSS data ({sources_summary})")

    # Record source stats for health monitoring / degradation detection
    try:
        from app.models import HealthCheckResult
        fallback_count = source_stats.get('cve_org', 0) + source_stats.get('euvd', 0)
        nvd_count = source_stats.get('nvd', 0)
        total_sourced = nvd_count + fallback_count

        if total_sourced > 0 and fallback_count > 0:
            pct_fallback = round(fallback_count / total_sourced * 100, 1)
            if nvd_count == 0:
                status = 'warning'
                msg = (f'NVD unavailable during last enrichment. '
                       f'All {fallback_count} scores from fallback sources '
                       f'({sources_summary}). Will retry NVD automatically.')
            else:
                status = 'warning' if pct_fallback > 50 else 'ok'
                msg = (f'{pct_fallback}% of CVSS scores from fallback sources '
                       f'({sources_summary}). NVD partially degraded.')
            HealthCheckResult.record(
                'api_source_status', 'sync', status, msg,
                value=f'{pct_fallback}% fallback',
                details={
                    'nvd': nvd_count, 'cve_org': source_stats.get('cve_org', 0),
                    'euvd': source_stats.get('euvd', 0),
                    'total': total_sourced, 'fallback_pct': pct_fallback
                }
            )
        elif total_sourced > 0:
            HealthCheckResult.record(
                'api_source_status', 'sync', 'ok',
                f'All {nvd_count} CVSS scores from NVD (primary source)',
                value='NVD primary',
                details={'nvd': nvd_count, 'cve_org': 0, 'euvd': 0,
                         'total': total_sourced, 'fallback_pct': 0}
            )
    except Exception as rec_err:
        logger.debug(f"Could not record source stats: {rec_err}")

    return enriched_count

def enrich_with_euvd_exploited():
    """
    Cross-reference CISA KEV data with ENISA EUVD exploited vulnerabilities.
    The EUVD tracks actively exploited CVEs from a European perspective,
    complementing the US-centric CISA KEV catalog.

    Two roles:
    1. ENRICH existing CISA KEV entries with EUVD CVSS data
    2. CREATE new entries for actively exploited CVEs not yet in CISA KEV
       (zero-day gap coverage — fetches full details from NVD)

    License: ENISA IPR Policy (attribution required).

    Returns:
        tuple: (enriched_count, new_count)
    """
    try:
        kwargs = {}
        proxies = Config.get_proxies()
        verify_ssl = Config.get_verify_ssl()
        if not verify_ssl:
            urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
        kwargs = {'proxies': proxies, 'verify': verify_ssl}

        response = requests.get(
            'https://euvdservices.enisa.europa.eu/api/exploitedvulnerabilities',
            timeout=15,
            **kwargs
        )

        if response.status_code != 200:
            logger.warning(f"EUVD exploited API returned {response.status_code}")
            return 0, 0

        data = response.json()
        # EUVD API returns a bare list of vulnerability dicts
        if isinstance(data, list):
            items = data
        else:
            items = data.get('items', data.get('vulnerabilities', []))
        if not items:
            return 0, 0

        enriched = 0
        new_count = 0
        new_cve_ids = []

        for item in items:
            # Skip non-dict items (API sometimes returns mixed structures)
            if not isinstance(item, dict):
                continue

            # EUVD uses 'aliases' field (newline-separated) for CVE IDs, not 'cveId'
            cve_id = item.get('cveId')
            if not cve_id:
                aliases = item.get('aliases', '')
                if aliases:
                    for alias in aliases.split('\n'):
                        alias = alias.strip()
                        if alias.startswith('CVE-'):
                            cve_id = alias
                            break
            if not cve_id:
                continue

            vuln = Vulnerability.query.filter_by(cve_id=cve_id).first()

            if vuln:
                # Existing CVE — enrich with EUVD CVSS if missing
                euvd_score = item.get('baseScore') or item.get('cvssScore')
                if euvd_score and (vuln.cvss_score is None or vuln.cvss_score == 0.0):
                    vuln.cvss_score = float(euvd_score)
                    severity = item.get('baseSeverity')
                    if severity:
                        vuln.severity = severity.upper()
                    else:
                        from app.nvd_api import _score_to_severity
                        vuln.severity = _score_to_severity(vuln.cvss_score)
                    vuln.cvss_source = 'euvd'
                    enriched += 1
            else:
                # NEW CVE not in CISA KEV — create entry from EUVD + NVD
                new_cve_ids.append((cve_id, item))

        # Batch-create new EUVD entries (fetch details from NVD)
        if new_cve_ids:
            from app.nvd_api import fetch_cve_details, _score_to_severity
            logger.info(f"EUVD: {len(new_cve_ids)} exploited CVEs not in CISA KEV — fetching from NVD")

            for cve_id, euvd_item in new_cve_ids:
                try:
                    # Fetch full CVE details from NVD
                    details = fetch_cve_details(cve_id)

                    # Use EUVD CVSS as fallback if NVD didn't provide one
                    euvd_score = euvd_item.get('baseScore') or euvd_item.get('cvssScore')
                    euvd_severity = euvd_item.get('baseSeverity')

                    if details:
                        cvss_score = details['cvss_score'] or (float(euvd_score) if euvd_score else None)
                        severity = details['severity'] or (euvd_severity.upper() if euvd_severity else _score_to_severity(cvss_score))
                        cvss_source = 'nvd' if details['cvss_score'] else ('euvd' if euvd_score else None)
                        vendor = details['vendor'] or 'Unknown'
                        product = details['product'] or 'Unknown'
                        description = details['description'] or f'Actively exploited vulnerability {cve_id} (details pending)'
                        vuln_name = details['vulnerability_name'] or cve_id
                    else:
                        # NVD unavailable — use what EUVD provides
                        cvss_score = float(euvd_score) if euvd_score else None
                        severity = euvd_severity.upper() if euvd_severity else _score_to_severity(cvss_score)
                        cvss_source = 'euvd' if euvd_score else None
                        # EUVD stores vendor/product in nested arrays
                        vendor_list = euvd_item.get('enisaIdVendor') or []
                        product_list = euvd_item.get('enisaIdProduct') or []
                        vendor = 'Unknown'
                        product = 'Unknown'
                        if vendor_list and isinstance(vendor_list[0], dict):
                            v = vendor_list[0].get('vendor')
                            if isinstance(v, dict):
                                vendor = v.get('name', 'Unknown')
                            elif isinstance(v, str):
                                vendor = v
                        if product_list and isinstance(product_list[0], dict):
                            p = product_list[0].get('product')
                            if isinstance(p, dict):
                                product = p.get('name', 'Unknown')
                            elif isinstance(p, str):
                                product = p
                        description = euvd_item.get('description', '') or f'Actively exploited vulnerability {cve_id} (details pending from NVD)'
                        vuln_name = description[:500]

                    vuln = Vulnerability(
                        cve_id=cve_id,
                        vendor_project=vendor,
                        product=product,
                        vulnerability_name=vuln_name[:500],
                        date_added=datetime.utcnow().date(),
                        short_description=description,
                        required_action='Apply vendor patches immediately. (Detected via ENISA EUVD — not yet in CISA KEV)',
                        due_date=None,
                        known_ransomware=False,
                        notes='Auto-created from ENISA EUVD exploited vulnerabilities feed.',
                        cvss_score=cvss_score,
                        severity=severity,
                        cvss_source=cvss_source,
                        source='euvd',
                    )

                    # Store CPE data if available from NVD
                    if details and details.get('cpe_entries'):
                        vuln.set_cpe_entries(details['cpe_entries'])

                    db.session.add(vuln)
                    new_count += 1
                    logger.info(f"EUVD: created entry for {cve_id} ({vendor} {product})")

                except Exception as e:
                    logger.warning(f"EUVD: failed to create entry for {cve_id}: {e}")
                    continue

        if enriched > 0 or new_count > 0:
            db.session.commit()
            if enriched:
                logger.info(f"EUVD: enriched {enriched} existing vulnerabilities")
            if new_count:
                logger.info(f"EUVD: created {new_count} new vulnerability entries (zero-day gap coverage)")

        return enriched, new_count

    except Exception as e:
        logger.warning(f"EUVD exploited enrichment failed (non-critical): {e}")
        return 0, 0


def sync_cisa_kev(enrich_cvss=True, cvss_limit=200, fetch_cpe=True, cpe_limit=100):
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

        # Enrich with CVSS data (multi-source: NVD → CVE.org → EUVD)
        if enrich_cvss:
            enrich_with_cvss_data(limit=cvss_limit)

        # Cross-reference with ENISA EUVD exploited vulnerabilities
        # Also creates NEW entries for actively exploited CVEs not yet in CISA KEV
        euvd_new_count = 0
        try:
            euvd_enriched, euvd_new_count = enrich_with_euvd_exploited()
        except Exception as e:
            logger.warning(f"EUVD enrichment failed (non-critical): {e}")

        # If EUVD added new vulnerabilities, match them against products
        if euvd_new_count > 0:
            try:
                _, euvd_matches = rematch_all_products()
                logger.info(f"EUVD: matched {euvd_matches} products against {euvd_new_count} new EUVD entries")
            except Exception as e:
                logger.warning(f"EUVD product matching failed (non-critical): {e}")

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


def reenrich_fallback_cvss(limit=50):
    """
    Re-try NVD (primary source) for vulnerabilities whose CVSS scores
    were obtained from fallback sources (CVE.org, ENISA EUVD).

    This closes the gap when NVD was temporarily unavailable during the
    initial enrichment. On success the vulnerability's cvss_source is
    upgraded to 'nvd'.

    Also handles unscored CVEs imported during Phase 2 of the NVD sync
    (Received/Awaiting Analysis). Once NVD scores them:
      - HIGH/CRITICAL → keep and update the score
      - LOW/MEDIUM    → auto-delete (they were only imported because
                         they were unscored and might have been dangerous)

    Args:
        limit: Maximum CVEs to re-enrich per run (respects NVD rate limits)

    Returns:
        (upgraded_count, checked_count)
    """
    from app.nvd_api import _fetch_cvss_from_nvd

    # Part 1: Upgrade fallback-sourced CVEs to NVD
    vulns = Vulnerability.query.filter(
        Vulnerability.cvss_source.in_(['cve_org', 'euvd']),
        Vulnerability.cvss_score.isnot(None),
        Vulnerability.cvss_score > 0
    ).order_by(Vulnerability.date_added.desc()).limit(limit).all()

    upgraded = 0
    for vuln in vulns:
        try:
            score, severity = _fetch_cvss_from_nvd(vuln.cve_id)
            if score is not None:
                vuln.cvss_score = score
                vuln.severity = severity
                vuln.cvss_source = 'nvd'
                upgraded += 1
        except Exception:
            continue

    if upgraded:
        db.session.commit()
        logger.info(
            f"CVSS re-enrichment: upgraded {upgraded}/{len(vulns)} "
            f"from fallback to NVD"
        )

    # Part 2: Score unscored CVEs (imported from Phase 2 with no CVSS).
    # Once NVD analyzes them, either keep (HIGH/CRITICAL) or remove (LOW/MEDIUM).
    from sqlalchemy import or_
    unscored = Vulnerability.query.filter(
        Vulnerability.source == 'nvd',
        Vulnerability.nvd_status.in_(['Received', 'Awaiting Analysis', 'Undergoing Analysis']),
        or_(
            Vulnerability.cvss_score.is_(None),
            Vulnerability.cvss_source.is_(None),
        )
    ).order_by(Vulnerability.date_added.desc()).limit(limit).all()

    scored = 0
    removed = 0
    for vuln in unscored:
        try:
            score, severity = _fetch_cvss_from_nvd(vuln.cve_id)
            if score is None:
                # Still unscored — NVD hasn't analyzed it yet, keep it
                continue

            if severity in ('HIGH', 'CRITICAL'):
                vuln.cvss_score = score
                vuln.severity = severity
                vuln.cvss_source = 'nvd'
                vuln.nvd_status = 'Analyzed'
                scored += 1
            else:
                # LOW or MEDIUM — wouldn't have been imported by Phase 1,
                # only got in because it was unscored. Remove it.
                db.session.delete(vuln)
                removed += 1
                logger.info(
                    f"CVSS re-enrichment: removed {vuln.cve_id} "
                    f"(scored {severity} {score} — below threshold)"
                )
        except Exception:
            continue

    if scored or removed:
        db.session.commit()
        if scored:
            logger.info(
                f"CVSS re-enrichment: scored {scored}/{len(unscored)} "
                f"previously unscored CVEs"
            )
        if removed:
            logger.info(
                f"CVSS re-enrichment: cleaned up {removed} low-severity "
                f"CVEs that were imported while unscored"
            )

    checked = len(vulns) + len(unscored)
    return upgraded + scored, checked


def sync_nvd_recent_cves(hours_back=6, severity_filter=None, max_results=500):
    """
    Sync recent CVEs from NVD API 2.0.

    Fills the gap between CISA KEV (curated, slow) and real-time CVE publication.
    Imports CVEs published in the last `hours_back` hours that aren't already
    in the database.

    Two-phase approach:
      Phase 1: Fetch CVEs with known HIGH/CRITICAL CVSS severity.
      Phase 2: Fetch recently published CVEs that NVD hasn't scored yet
               (status: Received / Awaiting Analysis / Undergoing Analysis).
               This catches zero-days and fresh CVEs before NVD assigns a
               CVSS score — without this, actively exploited vulnerabilities
               like Chrome 0-days would be invisible until NVD processes them.

    Args:
        hours_back: How far back to look (default 6 hours, first run uses 7 days)
        severity_filter: List of severities to import, default ['HIGH', 'CRITICAL']
        max_results: Cap on results per severity level

    Returns:
        tuple: (new_count, skipped_existing, errors)
    """
    if severity_filter is None:
        severity_filter = ['HIGH', 'CRITICAL']

    try:
        from app.nvd_api import _get_api_key, _get_request_kwargs, _score_to_severity
        from app.nvd_rate_limiter import get_rate_limiter

        # Determine time window — check if we've ever done an NVD sync
        last_nvd_sync = SystemSettings.query.filter_by(key='last_nvd_cve_sync').first()
        if last_nvd_sync and last_nvd_sync.value:
            try:
                last_sync_time = datetime.fromisoformat(last_nvd_sync.value)
                # Add 1-minute overlap to avoid missing CVEs at boundaries
                pub_start = last_sync_time - timedelta(minutes=1)
            except (ValueError, TypeError):
                pub_start = datetime.utcnow() - timedelta(hours=hours_back)
        else:
            # First run — look back 7 days to catch recent CVEs
            pub_start = datetime.utcnow() - timedelta(days=7)

        pub_end = datetime.utcnow()

        # NVD API date format: 2024-01-01T00:00:00.000
        date_fmt = '%Y-%m-%dT%H:%M:%S.000'

        api_key = _get_api_key()
        kwargs = _get_request_kwargs()
        headers = {}
        if api_key:
            headers['apiKey'] = api_key

        limiter = get_rate_limiter()
        new_count = 0
        skipped = 0
        errors = 0

        # Phase 1: Fetch CVEs with known HIGH/CRITICAL severity
        for severity in severity_filter:
            start_index = 0

            while start_index < max_results:
                if not limiter.acquire(timeout=60.0, block=True):
                    logger.warning("NVD rate limit timeout during CVE sync")
                    break

                params = {
                    'pubStartDate': pub_start.strftime(date_fmt),
                    'pubEndDate': pub_end.strftime(date_fmt),
                    'cvssV3Severity': severity,
                    'resultsPerPage': min(200, max_results - start_index),
                    'startIndex': start_index,
                }

                try:
                    response = requests.get(
                        'https://services.nvd.nist.gov/rest/json/cves/2.0',
                        params=params,
                        headers=headers,
                        timeout=20,
                        **kwargs
                    )

                    if response.status_code == 403:
                        logger.warning("NVD API rate limited (403), backing off")
                        import time
                        time.sleep(30)
                        continue

                    if response.status_code != 200:
                        logger.warning(f"NVD CVE sync: API returned {response.status_code}")
                        break

                    data = response.json()
                    results = data.get('vulnerabilities', [])
                    total_results = data.get('totalResults', 0)

                    if not results:
                        break

                    for item in results:
                        try:
                            cve_data = item.get('cve', {})
                            cve_id = cve_data.get('id', '')

                            if not cve_id or not cve_id.startswith('CVE-'):
                                continue

                            # Skip if already in DB — unless record has stale data
                            # that needs recovery (e.g., imported by old code before
                            # description fallback existed)
                            existing = Vulnerability.query.filter_by(cve_id=cve_id).first()
                            needs_refresh = (
                                existing and existing.vendor_project == 'Unknown'
                                and existing.product == 'Unknown'
                            )
                            if existing and not needs_refresh:
                                skipped += 1
                                continue

                            # Extract description
                            description = ''
                            for desc in cve_data.get('descriptions', []):
                                if desc.get('lang') == 'en':
                                    description = desc.get('value', '')
                                    break

                            if not description:
                                continue

                            # Skip rejected/disputed CVEs
                            vuln_status = cve_data.get('vulnStatus', '')
                            if vuln_status in ('Rejected', 'Disputed'):
                                continue

                            # Extract CVSS
                            cvss_score = None
                            cvss_severity = None
                            metrics = cve_data.get('metrics', {})
                            for metric_key in ['cvssMetricV31', 'cvssMetricV30']:
                                if metric_key in metrics and metrics[metric_key]:
                                    cvss_data = metrics[metric_key][0].get('cvssData', {})
                                    cvss_score = cvss_data.get('baseScore')
                                    cvss_severity = cvss_data.get('baseSeverity')
                                    break

                            if not cvss_severity:
                                cvss_severity = _score_to_severity(cvss_score)

                            # Extract vendor/product from CPE match criteria
                            vendor = ''
                            product = ''
                            cpe_entries = []
                            from app.nvd_cpe_api import parse_cpe_uri

                            for config in cve_data.get('configurations', []):
                                for node in config.get('nodes', []):
                                    for match in node.get('cpeMatch', []):
                                        if not match.get('vulnerable', False):
                                            continue
                                        cpe_uri = match.get('criteria', '')
                                        parsed = parse_cpe_uri(cpe_uri)

                                        if not vendor and parsed.get('vendor'):
                                            vendor = parsed['vendor'].replace('_', ' ').title()
                                        if not product and parsed.get('product'):
                                            product = parsed['product'].replace('_', ' ').title()

                                        cpe_version = parsed.get('version', '*')
                                        has_range = (
                                            match.get('versionStartIncluding') or
                                            match.get('versionStartExcluding') or
                                            match.get('versionEndIncluding') or
                                            match.get('versionEndExcluding')
                                        )
                                        cpe_entries.append({
                                            'cpe_uri': cpe_uri,
                                            'vendor': parsed.get('vendor', ''),
                                            'product': parsed.get('product', ''),
                                            'version_start': match.get('versionStartIncluding') or match.get('versionStartExcluding'),
                                            'version_end': match.get('versionEndIncluding') or match.get('versionEndExcluding'),
                                            'version_start_type': 'including' if match.get('versionStartIncluding') else 'excluding' if match.get('versionStartExcluding') else None,
                                            'version_end_type': 'including' if match.get('versionEndIncluding') else 'excluding' if match.get('versionEndExcluding') else None,
                                            'exact_version': cpe_version if (not has_range and cpe_version not in ('*', '-', '')) else None,
                                        })

                            # Fallback: extract vendor/product from description if
                            # NVD has no configurations (common for "Awaiting Analysis")
                            if not vendor and not product and description:
                                import re as _re
                                KNOWN_PRODUCTS = {
                                    r'google\s+chrome': ('Google', 'Chrome'),
                                    r'chromium': ('Chromium', 'Chromium'),
                                    r'mozilla\s+firefox': ('Mozilla', 'Firefox'),
                                    r'microsoft\s+edge': ('Microsoft', 'Edge'),
                                    r'apple\s+safari': ('Apple', 'Safari'),
                                    r'microsoft\s+windows': ('Microsoft', 'Windows'),
                                    r'linux\s+kernel': ('Linux', 'Kernel'),
                                    r'apache\s+(\w+)': ('Apache', None),
                                }
                                desc_lower = description.lower()
                                for pattern, (v, p) in KNOWN_PRODUCTS.items():
                                    m = _re.search(pattern, desc_lower)
                                    if m:
                                        vendor = v
                                        product = p or m.group(1).title()
                                        break

                            if needs_refresh:
                                # Update existing stale record (vendor=Unknown recovery)
                                vuln = existing
                                if vendor:
                                    vuln.vendor_project = vendor
                                if product:
                                    vuln.product = product
                                vuln.vulnerability_name = description[:500]
                                vuln.short_description = description
                                vuln.nvd_status = vuln_status or None
                                if cvss_score is not None:
                                    vuln.cvss_score = cvss_score
                                if cvss_severity:
                                    vuln.severity = cvss_severity
                                # Clear stale CPE stamp for Awaiting Analysis CVEs
                                # so matching logic doesn't treat NVD as authoritative
                                if vuln_status in ('Awaiting Analysis', 'Received', 'Undergoing Analysis'):
                                    vuln.cpe_fetched_at = None
                                    vuln.cpe_data = None
                                if cpe_entries:
                                    vuln.set_cpe_entries(cpe_entries)
                                new_count += 1
                                logger.info(f"Refreshed stale {cve_id}: vendor={vendor or 'Unknown'}, product={product or 'Unknown'}")
                            else:
                                # Create new vulnerability record
                                vuln = Vulnerability(
                                    cve_id=cve_id,
                                    vendor_project=vendor or 'Unknown',
                                    product=product or 'Unknown',
                                    vulnerability_name=description[:500],
                                    date_added=datetime.utcnow().date(),
                                    short_description=description,
                                    required_action='Apply vendor patches. (Source: NVD)',
                                    known_ransomware=False,
                                    notes=f'Auto-imported from NVD (severity: {cvss_severity}).',
                                    cvss_score=cvss_score,
                                    severity=cvss_severity,
                                    cvss_source='nvd',
                                    source='nvd',
                                    nvd_status=vuln_status or None,
                                )

                                if cpe_entries:
                                    vuln.set_cpe_entries(cpe_entries)

                                db.session.add(vuln)
                                new_count += 1

                        except Exception as e:
                            logger.debug(f"NVD sync: error processing CVE: {e}")
                            errors += 1
                            continue

                    start_index += len(results)
                    if start_index >= total_results:
                        break

                except requests.exceptions.RequestException as e:
                    logger.warning(f"NVD CVE sync request failed: {e}")
                    errors += 1
                    break

        # Phase 2: Fetch recently published CVEs that NVD hasn't scored yet.
        # These are zero-days and fresh CVEs in "Received" / "Awaiting Analysis"
        # status — NVD has no CVSS assigned so the severity filter above misses
        # them entirely.  We query WITHOUT cvssV3Severity to catch them.
        unscored_start = 0
        unscored_max = 200  # cap — unscored CVEs are typically a small batch

        while unscored_start < unscored_max:
            if not limiter.acquire(timeout=60.0, block=True):
                logger.warning("NVD rate limit timeout during unscored CVE sync")
                break

            params = {
                'pubStartDate': pub_start.strftime(date_fmt),
                'pubEndDate': pub_end.strftime(date_fmt),
                'noRejected': '',
                'resultsPerPage': min(200, unscored_max - unscored_start),
                'startIndex': unscored_start,
            }

            try:
                response = requests.get(
                    'https://services.nvd.nist.gov/rest/json/cves/2.0',
                    params=params,
                    headers=headers,
                    timeout=20,
                    **kwargs
                )

                if response.status_code == 403:
                    logger.warning("NVD API rate limited (403) during unscored sync, backing off")
                    import time
                    time.sleep(30)
                    continue

                if response.status_code != 200:
                    logger.warning(f"NVD unscored CVE sync: API returned {response.status_code}")
                    break

                data = response.json()
                results = data.get('vulnerabilities', [])
                total_results = data.get('totalResults', 0)

                if not results:
                    break

                for item in results:
                    try:
                        cve_data = item.get('cve', {})
                        cve_id = cve_data.get('id', '')

                        if not cve_id or not cve_id.startswith('CVE-'):
                            continue

                        vuln_status = cve_data.get('vulnStatus', '')

                        # Only import unscored CVEs — ones that NVD hasn't analyzed.
                        # Scored CVEs were already handled by Phase 1.
                        if vuln_status not in ('Received', 'Awaiting Analysis', 'Undergoing Analysis'):
                            skipped += 1
                            continue

                        # Skip if already in DB (and not stale)
                        existing = Vulnerability.query.filter_by(cve_id=cve_id).first()
                        needs_refresh = (
                            existing and existing.vendor_project == 'Unknown'
                            and existing.product == 'Unknown'
                        )
                        if existing and not needs_refresh:
                            skipped += 1
                            continue

                        # Extract description
                        description = ''
                        for desc in cve_data.get('descriptions', []):
                            if desc.get('lang') == 'en':
                                description = desc.get('value', '')
                                break

                        if not description:
                            continue

                        if vuln_status in ('Rejected', 'Disputed'):
                            continue

                        # Extract CVSS (may be absent for unscored CVEs)
                        cvss_score = None
                        cvss_severity = None
                        metrics = cve_data.get('metrics', {})
                        for metric_key in ['cvssMetricV31', 'cvssMetricV30']:
                            if metric_key in metrics and metrics[metric_key]:
                                cvss_data = metrics[metric_key][0].get('cvssData', {})
                                cvss_score = cvss_data.get('baseScore')
                                cvss_severity = cvss_data.get('baseSeverity')
                                break

                        if not cvss_severity:
                            cvss_severity = _score_to_severity(cvss_score)

                        # Extract vendor/product from CPE
                        vendor = ''
                        product = ''
                        cpe_entries = []
                        from app.nvd_cpe_api import parse_cpe_uri

                        for config in cve_data.get('configurations', []):
                            for node in config.get('nodes', []):
                                for match in node.get('cpeMatch', []):
                                    if not match.get('vulnerable', False):
                                        continue
                                    cpe_uri = match.get('criteria', '')
                                    parsed = parse_cpe_uri(cpe_uri)

                                    if not vendor and parsed.get('vendor'):
                                        vendor = parsed['vendor'].replace('_', ' ').title()
                                    if not product and parsed.get('product'):
                                        product = parsed['product'].replace('_', ' ').title()

                                    cpe_version = parsed.get('version', '*')
                                    has_range = (
                                        match.get('versionStartIncluding') or
                                        match.get('versionStartExcluding') or
                                        match.get('versionEndIncluding') or
                                        match.get('versionEndExcluding')
                                    )
                                    cpe_entries.append({
                                        'cpe_uri': cpe_uri,
                                        'vendor': parsed.get('vendor', ''),
                                        'product': parsed.get('product', ''),
                                        'version_start': match.get('versionStartIncluding') or match.get('versionStartExcluding'),
                                        'version_end': match.get('versionEndIncluding') or match.get('versionEndExcluding'),
                                        'version_start_type': 'including' if match.get('versionStartIncluding') else 'excluding' if match.get('versionStartExcluding') else None,
                                        'version_end_type': 'including' if match.get('versionEndIncluding') else 'excluding' if match.get('versionEndExcluding') else None,
                                        'exact_version': cpe_version if (not has_range and cpe_version not in ('*', '-', '')) else None,
                                    })

                        # Description fallback for vendor/product
                        if not vendor and not product and description:
                            import re as _re
                            KNOWN_PRODUCTS = {
                                r'google\s+chrome': ('Google', 'Chrome'),
                                r'chromium': ('Chromium', 'Chromium'),
                                r'mozilla\s+firefox': ('Mozilla', 'Firefox'),
                                r'microsoft\s+edge': ('Microsoft', 'Edge'),
                                r'apple\s+safari': ('Apple', 'Safari'),
                                r'microsoft\s+windows': ('Microsoft', 'Windows'),
                                r'linux\s+kernel': ('Linux', 'Kernel'),
                                r'apache\s+(\w+)': ('Apache', None),
                            }
                            desc_lower = description.lower()
                            for pattern, (v, p) in KNOWN_PRODUCTS.items():
                                m = _re.search(pattern, desc_lower)
                                if m:
                                    vendor = v
                                    product = p or m.group(1).title()
                                    break

                        if needs_refresh:
                            vuln = existing
                            if vendor:
                                vuln.vendor_project = vendor
                            if product:
                                vuln.product = product
                            vuln.vulnerability_name = description[:500]
                            vuln.short_description = description
                            vuln.nvd_status = vuln_status or None
                            if cvss_score is not None:
                                vuln.cvss_score = cvss_score
                            if cvss_severity:
                                vuln.severity = cvss_severity
                            if vuln_status in ('Awaiting Analysis', 'Received', 'Undergoing Analysis'):
                                vuln.cpe_fetched_at = None
                                vuln.cpe_data = None
                            if cpe_entries:
                                vuln.set_cpe_entries(cpe_entries)
                            new_count += 1
                            logger.info(f"Refreshed stale unscored {cve_id}: vendor={vendor or 'Unknown'}, product={product or 'Unknown'}, status={vuln_status}")
                        else:
                            vuln = Vulnerability(
                                cve_id=cve_id,
                                vendor_project=vendor or 'Unknown',
                                product=product or 'Unknown',
                                vulnerability_name=description[:500],
                                date_added=datetime.utcnow().date(),
                                short_description=description,
                                required_action='Apply vendor patches. (Source: NVD — awaiting analysis)',
                                known_ransomware=False,
                                notes=f'Auto-imported from NVD (unscored, NVD status: {vuln_status}).',
                                cvss_score=cvss_score,
                                severity=cvss_severity,
                                cvss_source='nvd' if cvss_score else None,
                                source='nvd',
                                nvd_status=vuln_status or None,
                            )

                            if cpe_entries:
                                vuln.set_cpe_entries(cpe_entries)

                            db.session.add(vuln)
                            new_count += 1
                            logger.info(f"Imported unscored {cve_id}: vendor={vendor or 'Unknown'}, product={product or 'Unknown'}, status={vuln_status}")

                    except Exception as e:
                        logger.debug(f"NVD unscored sync: error processing CVE: {e}")
                        errors += 1
                        continue

                unscored_start += len(results)
                if unscored_start >= total_results:
                    break

            except requests.exceptions.RequestException as e:
                logger.warning(f"NVD unscored CVE sync request failed: {e}")
                errors += 1
                break

        if new_count > 0:
            db.session.commit()

        # Record sync time — but ONLY advance the window if we actually
        # got a successful API response.  When the NVD API is unreachable
        # (network error, 403 rate-limit, etc.) we must NOT move the
        # timestamp forward, otherwise CVEs published during the outage
        # window are permanently skipped.  We detect a total failure by
        # checking: zero new CVEs, zero skipped (nothing fetched at all),
        # AND at least one error.
        total_api_failure = (new_count == 0 and skipped == 0 and errors > 0)

        if total_api_failure:
            logger.warning(
                "NVD CVE sync: not advancing sync timestamp — "
                f"API appears unreachable ({errors} errors, 0 results)"
            )
        else:
            if not last_nvd_sync:
                last_nvd_sync = SystemSettings(key='last_nvd_cve_sync', value=pub_end.isoformat(), category='sync')
                db.session.add(last_nvd_sync)
            else:
                last_nvd_sync.value = pub_end.isoformat()
            db.session.commit()

        logger.info(
            f"NVD CVE sync: {new_count} new, {skipped} existing, "
            f"{errors} errors (window: {pub_start.strftime('%Y-%m-%d %H:%M')} to {pub_end.strftime('%H:%M')})"
        )

        return new_count, skipped, errors

    except Exception as e:
        logger.warning(f"NVD CVE sync failed: {e}")
        return 0, 0, 1
