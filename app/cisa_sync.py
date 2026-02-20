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

# Vendor/product patterns for description-based extraction when NVD
# hasn't populated CPE data yet.  Used in fetch_cpe_version_data(),
# sync_nvd_recent_cves Phase 1 and Phase 2.
#
# DYNAMIC APPROACH: patterns are built at runtime from 3 sources:
#   1. Customer's Products table (vendor + product_name + CPE identifiers)
#   2. Small seed set for tricky vendor aliases (e.g., "fortigate" → Fortinet)
#   3. cve_known_products.py static set (~500 products for package filtering)
# This means ANY product a customer adds to SentriKat is automatically
# recognized in CVE descriptions without code changes.
import re as _re
import time as _time

# Minimal seed set for non-obvious aliases that can't be auto-derived
# from the Products table (brand names, abbreviations, etc.).
# Generic patterns use capture groups (None product → captured from text).
_SEED_PRODUCT_PATTERNS = {
    r'fortigate': ('Fortinet', 'FortiGate'),
    r'palo\s+alto\s+(?:networks?\s+)?pan-?os': ('Palo Alto Networks', 'PAN-OS'),
    r'palo\s+alto': ('Palo Alto Networks', 'PAN-OS'),
    r'moveit\s+transfer': ('Progress', 'MOVEit Transfer'),
    r'progress\s+moveit': ('Progress', 'MOVEit Transfer'),
    r'goanywhere': ('Fortra', 'GoAnywhere MFT'),
    r'apple\s+(?:macos|mac\s+os|ios|ipados|watchos|tvos|visionos)': ('Apple', None),
    r'linux\s+kernel': ('Linux', 'Kernel'),
}

# Cache for the dynamically built patterns (rebuilt every 10 minutes)
_dynamic_patterns_cache = {'patterns': None, 'ts': 0}


def _build_dynamic_product_patterns():
    """Build vendor/product regex patterns dynamically from the Products table.

    Merges:
      1. Customer's Products (vendor/product_name + CPE vendor/product)
      2. _SEED_PRODUCT_PATTERNS (non-obvious aliases)

    Returns dict of {regex_pattern: (Vendor, Product_or_None)}.
    Cached for 10 minutes to avoid hammering the DB on every CVE.
    """
    global _dynamic_patterns_cache

    now = _time.time()
    if _dynamic_patterns_cache['patterns'] is not None and (now - _dynamic_patterns_cache['ts']) < 600:
        return _dynamic_patterns_cache['patterns']

    patterns = dict(_SEED_PRODUCT_PATTERNS)
    seen_keys = set()

    try:
        products = Product.query.filter_by(active=True).all()

        for product in products:
            vendor = (product.vendor or '').strip()
            name = (product.product_name or '').strip()

            if not vendor or not name:
                continue

            key = (vendor.lower(), name.lower())
            if key in seen_keys:
                continue
            seen_keys.add(key)

            # Build "vendor product" pattern
            vendor_esc = _re.escape(vendor.lower())
            name_esc = _re.escape(name.lower())
            patterns[vendor_esc + r'\s+' + name_esc] = (vendor, name)

            # Also add product-only pattern if name is specific enough (>= 5 chars)
            if len(name) >= 5:
                patterns[name_esc] = (vendor, name)

            # Add CPE-based patterns (handles underscores → spaces)
            try:
                cpe_vendor, cpe_product, _ = product.get_effective_cpe()
                if cpe_vendor and cpe_product:
                    cv = cpe_vendor.replace('_', ' ')
                    cp = cpe_product.replace('_', ' ')
                    cpe_key = (cv.lower(), cp.lower())
                    if cpe_key not in seen_keys:
                        seen_keys.add(cpe_key)
                        patterns[_re.escape(cv.lower()) + r'\s+' + _re.escape(cp.lower())] = (
                            cv.title(), cp.title()
                        )
            except Exception:
                pass

    except Exception as e:
        # During app startup or outside request context, Products table
        # may not be available — fall back to seed patterns only.
        logger.debug(f"Could not build dynamic patterns from DB: {e}")

    _dynamic_patterns_cache = {'patterns': patterns, 'ts': now}
    return patterns


def _extract_vendor_product_from_description(description):
    """Extract vendor/product from CVE description using dynamic patterns.

    Patterns are built from:
      1. Customer's Products table (vendor/product_name + CPE data)
      2. _SEED_PRODUCT_PATTERNS (non-obvious vendor aliases)

    Returns (vendor, product) or (None, None).
    """
    if not description:
        return None, None
    desc_lower = description.lower()
    patterns = _build_dynamic_product_patterns()
    for pattern, (vendor, product) in patterns.items():
        m = _re.search(pattern, desc_lower)
        if m:
            # If product is None, try to capture from regex group
            if product is None:
                try:
                    product = m.group(1).title()
                except (IndexError, AttributeError):
                    product = None
            return vendor, product
    return None, None


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

            # Count actively exploited CVEs (0-days, CISA KEV, EUVD)
            exploited_count = sum(
                1 for m in new_matches
                if m.vulnerability and m.vulnerability.is_actively_exploited
            )

            # Count zero-day CVEs (detected by SentriKat before CISA KEV)
            zero_day_cves = set()
            for m in new_matches:
                if m.vulnerability and getattr(m.vulnerability, 'is_zero_day', False):
                    zero_day_cves.add(m.vulnerability.cve_id)
            zero_day_count = len(zero_day_cves)

            # Collect affected product names for context
            product_names = []
            seen_products = set()
            for m in new_matches:
                if m.product:
                    pkey = f"{m.product.vendor} {m.product.product_name}"
                    if pkey not in seen_products:
                        seen_products.add(pkey)
                        product_names.append(pkey)
            products_str = ", ".join(product_names[:4])
            if len(product_names) > 4:
                products_str += f" +{len(product_names) - 4} more"

            # Severity breakdown
            high_count = sum(
                1 for m in new_matches
                if m.vulnerability and m.calculate_effective_priority() == 'high'
            )

            # Build payload based on format - BATCHED message
            if webhook_format in ('slack', 'rocketchat'):
                # Header with org context
                text = f"{'🚨' if critical_count > 0 or exploited_count > 0 else '🔒'} *SentriKat Security Alert*\n"
                text += f"*Organization:* {org.display_name}\n"
                text += f"━━━━━━━━━━━━━━━━━━━━━━━━━━━\n"

                # What happened
                text += f"*{new_cve_count} new CVE{'s' if new_cve_count != 1 else ''} detected*\n"

                # Threat indicators (why this matters)
                if zero_day_count > 0:
                    text += f"⚡ *{zero_day_count} ZERO-DAY{'S' if zero_day_count != 1 else ''}* — detected before CISA KEV listing\n"
                if exploited_count > 0:
                    text += f"🚨 *{exploited_count} ACTIVELY EXPLOITED* — immediate patching required\n"
                if critical_count > 0:
                    text += f"🔴 *{critical_count} Critical severity*\n"
                if high_count > 0:
                    text += f"🟠 *{high_count} High severity*\n"
                if verify_count > 0:
                    text += f"🟡 *{verify_count} Likely resolved* — vendor fix detected, verify manually\n"

                # CVE IDs
                text += f"\n*CVEs:* {cve_list_str}\n"

                # Affected products
                if products_str:
                    text += f"*Affected:* {products_str}\n"

                payload = {"text": text}
            elif webhook_format == 'discord':
                # Header
                content = f"{'🚨' if critical_count > 0 or exploited_count > 0 else '🔒'} **SentriKat Security Alert**\n"
                content += f"**Organization:** {org.display_name}\n"
                content += f"───────────────────────\n"

                content += f"**{new_cve_count} new CVE{'s' if new_cve_count != 1 else ''} detected**\n"

                if zero_day_count > 0:
                    content += f"⚡ **{zero_day_count} ZERO-DAY{'S' if zero_day_count != 1 else ''}** — detected before CISA KEV listing\n"
                if exploited_count > 0:
                    content += f"🚨 **{exploited_count} ACTIVELY EXPLOITED** — immediate patching required\n"
                if critical_count > 0:
                    content += f"🔴 **{critical_count} Critical severity**\n"
                if high_count > 0:
                    content += f"🟠 **{high_count} High severity**\n"
                if verify_count > 0:
                    content += f"🟡 **{verify_count} Likely resolved** — vendor fix detected, verify manually\n"

                content += f"\n**CVEs:** {cve_list_str}\n"
                if products_str:
                    content += f"**Affected:** {products_str}\n"

                payload = {"content": content}
            elif webhook_format == 'teams':
                facts = [
                    {"name": "Organization", "value": org.display_name},
                    {"name": "New CVEs", "value": str(new_cve_count)},
                    {"name": "CVE IDs", "value": cve_list_str},
                ]
                if zero_day_count > 0:
                    facts.append({"name": "Zero-Day (Pre-KEV)", "value": f"{zero_day_count} — detected before CISA KEV"})
                if exploited_count > 0:
                    facts.append({"name": "Actively Exploited", "value": f"{exploited_count} — immediate patching required"})
                if critical_count > 0:
                    facts.append({"name": "Critical Severity", "value": str(critical_count)})
                if high_count > 0:
                    facts.append({"name": "High Severity", "value": str(high_count)})
                if verify_count > 0:
                    facts.append({"name": "Likely Resolved (Verify)", "value": str(verify_count)})
                if products_str:
                    facts.append({"name": "Affected Products", "value": products_str})
                payload = {
                    "@type": "MessageCard",
                    "themeColor": "7c3aed" if zero_day_count > 0 else ("dc2626" if critical_count > 0 or exploited_count > 0 else "1e40af"),
                    "summary": f"SentriKat: {new_cve_count} new CVEs for {org.display_name}" + (f" ({zero_day_count} zero-day)" if zero_day_count > 0 else ""),
                    "sections": [{
                        "activityTitle": f"{'🚨' if critical_count > 0 or exploited_count > 0 else '🔒'} SentriKat Security Alert — {org.display_name}",
                        "facts": facts,
                        "markdown": True
                    }]
                }
            else:  # custom or fallback JSON
                payload = {
                    "text": f"SentriKat Security Alert: {new_cve_count} new CVEs for {org.display_name}: {cve_list_str}",
                    "organization": org.display_name,
                    "new_cve_count": new_cve_count,
                    "cve_ids": new_cve_ids,
                    "critical_count": critical_count,
                    "high_count": high_count,
                    "exploited_count": exploited_count,
                    "zero_day_count": zero_day_count,
                    "zero_day_cve_ids": list(zero_day_cves),
                    "verify_count": verify_count,
                    "affected_products": product_names
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
                    text = f"{'🚨' if critical_count > 0 else '🔒'} *SentriKat Security Alert*\n"
                    text += f"*Source:* Global CVE Sync\n"
                    text += f"━━━━━━━━━━━━━━━━━━━━━━━━━━━\n"
                    text += f"*{new_cves_count} new CVE{'s' if new_cves_count != 1 else ''} detected*\n"
                    if critical_count > 0:
                        text += f"🔴 *{critical_count} Critical severity* — immediate action required\n"
                    text += f"\n*CVEs:* {cve_list_str}\n"
                    text += f"*Product matches:* {total_matches}\n"
                    payload = {"text": text}
                else:
                    text = f"🔒 *SentriKat — CVE Sync Complete*\n"
                    text += f"*Source:* Global CVE Sync\n"
                    text += f"━━━━━━━━━━━━━━━━━━━━━━━━━━━\n"
                    text += f"*New CVEs:* {new_cves_count}\n"
                    if critical_count > 0:
                        text += f"🔴 *Critical:* {critical_count} — immediate action required\n"
                    text += f"*Product matches:* {total_matches}\n"
                    payload = {"text": text}

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

                facts = [
                    {"name": "Source", "value": "Global CVE Sync"},
                    {"name": "New CVEs", "value": str(new_cves_count)},
                ]
                if cve_list_str:
                    facts.append({"name": "CVE IDs", "value": cve_list_str})
                if critical_count > 0:
                    facts.append({"name": "Critical Severity", "value": f"{critical_count} — immediate action required"})
                facts.append({"name": "Product Matches", "value": str(total_matches)})

                payload = {
                    "@type": "MessageCard",
                    "@context": "http://schema.org/extensions",
                    "themeColor": "dc2626" if critical_count > 0 else "1e40af",
                    "summary": f"SentriKat: {new_cves_count} new CVEs" + (f" ({critical_count} critical)" if critical_count > 0 else ""),
                    "sections": [{
                        "activityTitle": f"{'🚨' if critical_count > 0 else '🔒'} SentriKat Security Alert — Global CVE Sync",
                        "facts": facts,
                        "markdown": True
                    }]
                }

                response = requests.post(webhook_url, json=payload, timeout=10)
                results.append({'teams': response.status_code in [200, 204]})
            except Exception as e:
                logger.error(f"Teams webhook failed: {e}")
                results.append({'teams': False, 'error': str(e)})

        # Send to Generic webhook if enabled (RocketChat, Mattermost, Discord, etc.)
        from app.settings_api import get_setting
        generic_enabled = get_setting('generic_webhook_enabled') == 'true'
        generic_url_raw = get_setting('generic_webhook_url')
        if generic_enabled and generic_url_raw:
            try:
                from app.encryption import decrypt_value, is_encrypted
                generic_url = decrypt_value(generic_url_raw) if is_encrypted(generic_url_raw) else generic_url_raw
                generic_format = get_setting('generic_webhook_format', 'slack')
                generic_name = get_setting('generic_webhook_name', 'Custom Webhook')
                generic_token = get_setting('generic_webhook_token', '')
                if generic_token and is_encrypted(generic_token):
                    generic_token = decrypt_value(generic_token)

                proxies = Config.get_proxies()
                verify_ssl = Config.get_verify_ssl()

                headers = {'Content-Type': 'application/json'}
                if generic_token:
                    headers['Authorization'] = f'Bearer {generic_token}'
                    headers['X-Auth-Token'] = generic_token

                if generic_format in ('slack', 'rocketchat'):
                    text = f"{'🚨' if critical_count > 0 else '🔒'} *SentriKat Security Alert*\n"
                    text += f"*Source:* Global CVE Sync\n"
                    text += f"━━━━━━━━━━━━━━━━━━━━━━━━━━━\n"
                    text += f"*{new_cves_count} new CVE{'s' if new_cves_count != 1 else ''} detected*\n"
                    if critical_count > 0:
                        text += f"🔴 *{critical_count} Critical severity* — immediate action required\n"
                    if cve_list_str:
                        text += f"\n*CVEs:* {cve_list_str}\n"
                    text += f"*Product matches:* {total_matches}\n"
                    payload = {"text": text}
                elif generic_format == 'discord':
                    content = f"{'🚨' if critical_count > 0 else '🔒'} **SentriKat Security Alert**\n"
                    content += f"**Source:** Global CVE Sync\n"
                    content += f"───────────────────────\n"
                    content += f"**{new_cves_count} new CVE{'s' if new_cves_count != 1 else ''} detected**\n"
                    if critical_count > 0:
                        content += f"🔴 **{critical_count} Critical severity** — immediate action required\n"
                    if cve_list_str:
                        content += f"\n**CVEs:** {cve_list_str}\n"
                    content += f"**Product matches:** {total_matches}\n"
                    payload = {"content": content}
                else:
                    payload = {
                        "text": f"SentriKat Security Alert: {new_cves_count} new CVEs ({critical_count} critical), {total_matches} product matches"
                    }

                response = requests.post(generic_url, json=payload, headers=headers, timeout=10, proxies=proxies, verify=verify_ssl)
                results.append({'generic': response.status_code in [200, 204]})
            except Exception as e:
                logger.error(f"Generic webhook failed: {e}")
                results.append({'generic': False, 'error': str(e)})

        return results
    except Exception as e:
        logger.error(f"Webhook notification failed: {e}")
        return []

def send_alerts_for_new_matches(since_time, source_label='sync'):
    """
    Send email and webhook alerts for new vulnerability matches created since `since_time`.

    This is the SHARED alerting function used by ALL sync paths (CISA KEV, NVD, EUVD).
    Previously only the CISA KEV sync triggered alerts — NVD and EUVD syncs would
    create matches silently, meaning 0-days caught by NVD/EUVD were invisible to
    the customer until the daily reminder ran (up to 24h delay).

    Args:
        since_time: datetime — only matches created after this time trigger alerts
        source_label: str — label for logging (e.g., 'nvd_sync', 'euvd_sync')

    Returns:
        dict with alert_results and webhook_results
    """
    from app.models import Organization, VulnerabilityMatch, product_organizations
    from app.email_alerts import EmailAlertManager
    from datetime import date as _date

    alert_results = []
    webhook_results = []
    orgs_with_own_webhook = set()
    organizations = Organization.query.filter_by(active=True).all()

    for org in organizations:
        try:
            alert_config = org.get_effective_alert_mode()
            alert_mode = alert_config['mode']
            escalation_days = alert_config['escalation_days']

            # Get product IDs for this organization
            legacy_ids = [p.id for p in Product.query.filter_by(organization_id=org.id).all()]
            multi_org_ids = [row.product_id for row in db.session.query(
                product_organizations.c.product_id
            ).filter(product_organizations.c.organization_id == org.id).all()]
            org_product_ids = list(set(legacy_ids + multi_org_ids))

            if not org_product_ids:
                continue

            if alert_mode == 'new_only':
                matches_to_alert = VulnerabilityMatch.query.filter(
                    VulnerabilityMatch.product_id.in_(org_product_ids),
                    VulnerabilityMatch.acknowledged == False,
                    VulnerabilityMatch.created_at >= since_time
                ).all()
            elif alert_mode in ('daily_reminder', 'escalation'):
                # BUG FIX: Previously filtered ONLY on due_date, which silently
                # dropped all NVD/EUVD CVEs (they have NULL due_date).
                # Now: include CVEs with due_date in window OR newly created
                # OR actively exploited (regardless of due_date).
                days_window = 7 if alert_mode == 'daily_reminder' else escalation_days
                cutoff_date = _date.today() + timedelta(days=days_window)

                from sqlalchemy import or_
                vuln_ids_qualifying = [v.id for v in Vulnerability.query.filter(
                    or_(
                        # Original: CVEs with due_date in window
                        db.and_(
                            Vulnerability.due_date <= cutoff_date,
                            Vulnerability.due_date >= _date.today()
                        ),
                        # FIX: actively exploited CVEs (0-days) always qualify
                        Vulnerability.is_actively_exploited == True,
                        # FIX: CVEs with NULL due_date that are HIGH/CRITICAL
                        db.and_(
                            Vulnerability.due_date == None,
                            Vulnerability.severity.in_(['CRITICAL', 'HIGH'])
                        )
                    )
                ).all()]

                if vuln_ids_qualifying:
                    matches_to_alert = VulnerabilityMatch.query.filter(
                        VulnerabilityMatch.product_id.in_(org_product_ids),
                        VulnerabilityMatch.acknowledged == False,
                        VulnerabilityMatch.vulnerability_id.in_(vuln_ids_qualifying)
                    ).all()
                else:
                    matches_to_alert = []
            else:
                matches_to_alert = VulnerabilityMatch.query.filter(
                    VulnerabilityMatch.product_id.in_(org_product_ids),
                    VulnerabilityMatch.acknowledged == False,
                    VulnerabilityMatch.created_at >= since_time
                ).all()

            if matches_to_alert:
                result = EmailAlertManager.send_critical_cve_alert(org, matches_to_alert)
                alert_results.append({
                    'organization': org.name,
                    'alert_mode': alert_mode,
                    'source': source_label,
                    'result': result
                })

                org_critical = sum(
                    1 for m in matches_to_alert
                    if m.vulnerability and (
                        m.vulnerability.is_actively_exploited
                        or m.vulnerability.known_ransomware
                        or (m.vulnerability.cvss_score and m.vulnerability.cvss_score >= 9.0)
                    )
                )

                org_webhook_result = send_org_webhook(
                    org, 0, org_critical, len(matches_to_alert),
                    matches=matches_to_alert
                )
                if org_webhook_result:
                    webhook_results.append(org_webhook_result)
                    orgs_with_own_webhook.add(org.id)

        except Exception as e:
            logger.error(f"Alert processing failed for {org.name} ({source_label}): {e}")

    # Send global webhook for orgs without their own
    new_match_count = VulnerabilityMatch.query.filter(
        VulnerabilityMatch.created_at >= since_time
    ).count()

    if new_match_count > 0:
        critical_vuln_ids = [v.id for v in Vulnerability.query.filter(
            db.or_(
                Vulnerability.known_ransomware == True,
                Vulnerability.cvss_score >= 9.0,
                Vulnerability.is_actively_exploited == True
            )
        ).all()]

        if orgs_with_own_webhook:
            legacy_excluded = [p.id for p in Product.query.filter(
                Product.organization_id.in_(orgs_with_own_webhook)
            ).all()]
            multi_org_excluded = [row.product_id for row in db.session.query(
                product_organizations.c.product_id
            ).filter(product_organizations.c.organization_id.in_(orgs_with_own_webhook)).all()]
            excluded_product_ids = list(set(legacy_excluded + multi_org_excluded))
            if critical_vuln_ids and excluded_product_ids:
                total_critical = VulnerabilityMatch.query.filter(
                    VulnerabilityMatch.created_at >= since_time,
                    ~VulnerabilityMatch.product_id.in_(excluded_product_ids),
                    VulnerabilityMatch.vulnerability_id.in_(critical_vuln_ids)
                ).count()
            elif critical_vuln_ids:
                total_critical = VulnerabilityMatch.query.filter(
                    VulnerabilityMatch.created_at >= since_time,
                    VulnerabilityMatch.vulnerability_id.in_(critical_vuln_ids)
                ).count()
            else:
                total_critical = 0
        else:
            if critical_vuln_ids:
                total_critical = VulnerabilityMatch.query.filter(
                    VulnerabilityMatch.created_at >= since_time,
                    VulnerabilityMatch.vulnerability_id.in_(critical_vuln_ids)
                ).count()
            else:
                total_critical = 0

        global_webhook_results = send_webhook_notification(
            new_match_count, total_critical, new_match_count
        )
        webhook_results.extend(global_webhook_results)

    if webhook_results:
        logger.info(f"[{source_label}] Webhook notifications: {webhook_results}")

    return {'alert_results': alert_results, 'webhook_results': webhook_results}


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
        except (ValueError, TypeError, AttributeError):
            pass

        try:
            if vuln_data.get('dueDate'):
                due_date = datetime.strptime(vuln_data.get('dueDate'), '%Y-%m-%d').date()
        except (ValueError, TypeError, AttributeError):
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
            # CISA KEV = confirmed actively exploited
            vuln.is_actively_exploited = True
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
                is_actively_exploited=True,  # CISA KEV = confirmed actively exploited
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
                v, p = _extract_vendor_product_from_description(vuln.short_description)
                if v:
                    vuln.vendor_project = v
                    vuln.product = p
                    logger.info(f"Recovered vendor/product for {vuln.cve_id}: {v}/{p}")

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

    # Re-match products for newly enriched CVEs. When CPE data arrives for a
    # CVE that previously had none:
    # - New high-confidence CPE matches may be created
    # - Stale medium-confidence text matches may become invalid (CPE is now
    #   authoritative, so text fallback is suppressed)
    # Without this, matches stay stale until the next full daily sync.
    if enriched_count > 0:
        try:
            from app.filters import rematch_all_products
            enriched_vulns = [v for v in vulns_to_fetch if v.cpe_data and v.cpe_data != '[]']
            if enriched_vulns:
                removed, added = rematch_all_products(target_vulnerabilities=enriched_vulns)
                logger.info(
                    f"Re-matched after CPE enrichment: {added} new matches, "
                    f"{removed} stale matches removed"
                )
        except Exception as e:
            logger.warning(f"Re-match after CPE enrichment failed (non-critical): {e}")

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
            # Mark as checked but use a sentinel source so re-enrichment can
            # retry later.  Previously this set cvss_source=None and 0.0 was
            # never retried (reenrich_fallback_cvss only retried cve_org/euvd).
            vuln.cvss_score = 0.0
            vuln.cvss_source = 'pending'

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
                # EUVD exploited feed = confirmed actively exploited
                vuln.is_actively_exploited = True
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
                        is_actively_exploited=True,  # EUVD exploited = confirmed actively exploited
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

        # Send email and webhook alerts for all new matches from this sync
        alerts = send_alerts_for_new_matches(start_time, source_label='cisa_kev')
        alert_results = alerts.get('alert_results', [])

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

    Also handles CNA-scored CVEs imported during Phase 2 of the NVD sync
    (Received/Awaiting Analysis with CNA CVSS). Once NVD analyzes them,
    upgrades from CNA score to the authoritative NVD score.

    Args:
        limit: Maximum CVEs to re-enrich per run (respects NVD rate limits)

    Returns:
        (upgraded_count, checked_count)
    """
    from app.nvd_api import _fetch_cvss_from_nvd

    # Part 1: Upgrade fallback-sourced CVEs to NVD
    # Also retry 'pending' (= all 3 sources returned nothing on first attempt)
    vulns = Vulnerability.query.filter(
        Vulnerability.cvss_source.in_(['cve_org', 'euvd', 'pending']),
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

    # Part 2: Upgrade CNA-scored CVEs (from Phase 2) to NVD Primary scores
    # once NVD finishes analyzing them.
    cna_scored = Vulnerability.query.filter(
        Vulnerability.source == 'nvd',
        Vulnerability.cvss_source == 'cna',
        Vulnerability.nvd_status.in_(['Received', 'Awaiting Analysis', 'Undergoing Analysis']),
    ).order_by(Vulnerability.date_added.desc()).limit(limit).all()

    cna_upgraded = 0
    for vuln in cna_scored:
        try:
            # Check actual NVD status before upgrading -- don't blindly
            # assume "Analyzed" just because a score was returned (it
            # could still be the same CNA/Secondary score).
            from app.nvd_cpe_api import match_cve_to_cpe_with_status
            _, live_status = match_cve_to_cpe_with_status(vuln.cve_id)

            if live_status and live_status not in ('Received', 'Awaiting Analysis', 'Undergoing Analysis'):
                # NVD has actually analyzed it -- safe to upgrade
                score, severity = _fetch_cvss_from_nvd(vuln.cve_id)
                if score is not None:
                    vuln.cvss_score = score
                    vuln.severity = severity
                    vuln.cvss_source = 'nvd'
                    vuln.nvd_status = live_status
                    cna_upgraded += 1
            elif live_status:
                # Still pending -- just update the status field
                vuln.nvd_status = live_status
        except Exception:
            continue

    if cna_upgraded:
        db.session.commit()
        logger.info(
            f"CVSS re-enrichment: upgraded {cna_upgraded}/{len(cna_scored)} "
            f"from CNA to NVD scores"
        )

    checked = len(vulns) + len(cna_scored)
    return upgraded + cna_upgraded, checked


def _extract_cvss_from_metrics(metrics):
    """
    Extract CVSS score and severity from NVD API metrics, preferring
    NVD-assigned (Primary) scores but falling back to CNA-assigned
    (Secondary) scores.

    This is critical for CVEs in "Awaiting Analysis" status where NVD
    hasn't scored yet, but the CNA (e.g., Google, Microsoft) has already
    provided their own CVSS assessment.

    Returns:
        (score, severity, source_type) where source_type is 'Primary' or 'Secondary'
    """
    for metric_key in ['cvssMetricV40', 'cvssMetricV31', 'cvssMetricV30']:
        entries = metrics.get(metric_key, [])
        if not entries:
            continue

        # First pass: look for NVD Primary score
        for entry in entries:
            if entry.get('type') == 'Primary':
                cvss_data = entry.get('cvssData', {})
                score = cvss_data.get('baseScore')
                severity = cvss_data.get('baseSeverity')
                if score is not None:
                    return score, severity, 'Primary'

        # Second pass: fall back to CNA/ADP Secondary score
        for entry in entries:
            if entry.get('type') == 'Secondary':
                cvss_data = entry.get('cvssData', {})
                score = cvss_data.get('baseScore')
                severity = cvss_data.get('baseSeverity')
                if score is not None:
                    return score, severity, 'Secondary'

        # Last resort: just grab whatever is at index 0
        cvss_data = entries[0].get('cvssData', {})
        score = cvss_data.get('baseScore')
        severity = cvss_data.get('baseSeverity')
        if score is not None:
            return score, severity, 'Unknown'

    # CVSS v2.0 fallback (no Primary/Secondary distinction in v2)
    v2_entries = metrics.get('cvssMetricV2', [])
    if v2_entries:
        cvss_data = v2_entries[0].get('cvssData', {})
        score = cvss_data.get('baseScore')
        if score is not None:
            # V2 doesn't have baseSeverity, derive from score
            if score >= 9.0:
                severity = 'CRITICAL'
            elif score >= 7.0:
                severity = 'HIGH'
            elif score >= 4.0:
                severity = 'MEDIUM'
            else:
                severity = 'LOW'
            return score, severity, 'Primary'

    return None, None, None


def sync_nvd_recent_cves(hours_back=6, severity_filter=None, max_results=500):
    """
    Sync recent CVEs from NVD API 2.0.

    Fills the gap between CISA KEV (curated, slow) and real-time CVE publication.
    Imports CVEs published in the last `hours_back` hours that aren't already
    in the database.

    Two-phase approach:
      Phase 1: Fetch CVEs with known HIGH/CRITICAL NVD CVSS severity.
      Phase 2: Fetch CVEs that NVD hasn't analyzed yet (Received / Awaiting
               Analysis) and check for CNA-assigned CVSS scores (e.g., Google
               scores their own Chrome CVEs immediately).  Only imports
               CNA-scored HIGH/CRITICAL — skips LOW/MEDIUM and truly unscored
               CVEs to avoid noise.  This catches zero-days like Chrome 0-days
               that would be invisible until NVD gets around to scoring them.

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

                            # Extract CVSS (prefer NVD Primary, fall back to CNA Secondary)
                            metrics = cve_data.get('metrics', {})
                            cvss_score, cvss_severity, cvss_type = _extract_cvss_from_metrics(metrics)

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
                                vendor, product = _extract_vendor_product_from_description(description)

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

        # Phase 2: Catch HIGH/CRITICAL CVEs that NVD hasn't analyzed yet.
        #
        # Problem: Phase 1 uses cvssV3Severity=HIGH which only returns CVEs
        # where NVD has assigned a score.  Zero-days and fresh CVEs in
        # "Received" / "Awaiting Analysis" status have no NVD score yet —
        # but the CNA (e.g., Google, Microsoft) often provides their own
        # CVSS assessment as a "Secondary" metric in the API response.
        #
        # Solution: query without severity filter, check CNA-assigned
        # (Secondary) CVSS scores, and only import HIGH/CRITICAL.
        # This means zero noise — no LOW/MEDIUM junk, just the dangerous
        # CVEs that NVD is slow to process.
        unscored_start = 0
        unscored_max = 500
        unscored_imported = 0
        unscored_skipped_low = 0

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

                        # Only process CVEs that NVD hasn't analyzed yet.
                        # Analyzed CVEs were already handled by Phase 1.
                        if vuln_status not in ('Received', 'Awaiting Analysis', 'Undergoing Analysis'):
                            skipped += 1
                            continue

                        # Check for CNA-assigned CVSS score (Secondary metric)
                        metrics = cve_data.get('metrics', {})
                        cvss_score, cvss_severity, cvss_type = _extract_cvss_from_metrics(metrics)

                        if not cvss_severity:
                            cvss_severity = _score_to_severity(cvss_score)

                        # Only import if CNA says HIGH or CRITICAL.
                        # No CNA score at all = skip (truly unknown, avoid noise).
                        if cvss_severity not in ('HIGH', 'CRITICAL'):
                            unscored_skipped_low += 1
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
                            vendor, product = _extract_vendor_product_from_description(description)

                        # Determine CVSS source label
                        cvss_source_label = 'cna' if cvss_type == 'Secondary' else 'nvd'

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
                            vuln.cvss_source = cvss_source_label
                            if vuln_status in ('Awaiting Analysis', 'Received', 'Undergoing Analysis'):
                                vuln.cpe_fetched_at = None
                                vuln.cpe_data = None
                            if cpe_entries:
                                vuln.set_cpe_entries(cpe_entries)
                            new_count += 1
                            unscored_imported += 1
                            logger.info(f"Refreshed unscored {cve_id}: vendor={vendor or 'Unknown'}, product={product or 'Unknown'}, cvss={cvss_score} ({cvss_type}), status={vuln_status}")
                        else:
                            vuln = Vulnerability(
                                cve_id=cve_id,
                                vendor_project=vendor or 'Unknown',
                                product=product or 'Unknown',
                                vulnerability_name=description[:500],
                                date_added=datetime.utcnow().date(),
                                short_description=description,
                                required_action='Apply vendor patches. (Source: NVD — CNA-scored, awaiting NVD analysis)',
                                known_ransomware=False,
                                notes=f'Auto-imported from NVD (CNA-scored {cvss_severity} {cvss_score}, NVD status: {vuln_status}).',
                                cvss_score=cvss_score,
                                severity=cvss_severity,
                                cvss_source=cvss_source_label,
                                source='nvd',
                                nvd_status=vuln_status or None,
                            )

                            if cpe_entries:
                                vuln.set_cpe_entries(cpe_entries)

                            db.session.add(vuln)
                            new_count += 1
                            unscored_imported += 1
                            logger.info(f"Imported CNA-scored {cve_id}: vendor={vendor or 'Unknown'}, product={product or 'Unknown'}, cvss={cvss_score} ({cvss_type}), status={vuln_status}")

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

        if unscored_imported or unscored_skipped_low:
            logger.info(
                f"NVD Phase 2 (unscored): {unscored_imported} CNA-scored HIGH/CRITICAL imported, "
                f"{unscored_skipped_low} skipped (LOW/MEDIUM/no score)"
            )

        # Phase 3: Catch-up for late-analyzed CVEs using lastModStartDate.
        #
        # Phases 1 & 2 use pubStartDate which means a CVE published on Monday
        # that NVD doesn't analyze until Friday will be missed — by Friday the
        # publication window has moved past Monday.  Phase 3 queries by
        # lastModStartDate to catch CVEs that were MODIFIED (e.g., NVD added
        # CVSS score) since the last sync, regardless of when they were
        # originally published.  We only create new entries for CVEs not
        # already in our DB (avoid duplicating Phase 1/2 work).
        phase3_imported = 0
        try:
            mod_start = pub_start  # Same window as Phases 1/2
            mod_params = {
                'lastModStartDate': mod_start.strftime(date_fmt),
                'lastModEndDate': pub_end.strftime(date_fmt),
                'cvssV3Severity': 'CRITICAL',
                'resultsPerPage': 200,
                'startIndex': 0,
            }

            for p3_severity in ['CRITICAL', 'HIGH']:
                mod_params['cvssV3Severity'] = p3_severity
                mod_params['startIndex'] = 0

                if not limiter.acquire(timeout=60.0, block=True):
                    break

                try:
                    response = requests.get(
                        'https://services.nvd.nist.gov/rest/json/cves/2.0',
                        params=mod_params,
                        headers=headers,
                        timeout=20,
                        **kwargs
                    )

                    if response.status_code != 200:
                        continue

                    data = response.json()
                    results = data.get('vulnerabilities', [])

                    for item in results:
                        try:
                            cve_data = item.get('cve', {})
                            cve_id = cve_data.get('id', '')
                            if not cve_id or not cve_id.startswith('CVE-'):
                                continue

                            # Only import if NOT already in DB
                            existing = Vulnerability.query.filter_by(cve_id=cve_id).first()
                            if existing:
                                # Update NVD status if it changed (e.g., Awaiting → Analyzed)
                                live_status = cve_data.get('vulnStatus', '')
                                if live_status and existing.nvd_status != live_status:
                                    existing.nvd_status = live_status
                                continue

                            vuln_status = cve_data.get('vulnStatus', '')
                            if vuln_status in ('Rejected', 'Disputed'):
                                continue

                            description = ''
                            for desc in cve_data.get('descriptions', []):
                                if desc.get('lang') == 'en':
                                    description = desc.get('value', '')
                                    break
                            if not description:
                                continue

                            metrics = cve_data.get('metrics', {})
                            cvss_score_p3, cvss_severity_p3, cvss_type_p3 = _extract_cvss_from_metrics(metrics)
                            if not cvss_severity_p3:
                                cvss_severity_p3 = _score_to_severity(cvss_score_p3)

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
                                            match.get('versionStartIncluding') or match.get('versionStartExcluding') or
                                            match.get('versionEndIncluding') or match.get('versionEndExcluding')
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

                            if not vendor and not product and description:
                                vendor, product = _extract_vendor_product_from_description(description)

                            vuln = Vulnerability(
                                cve_id=cve_id,
                                vendor_project=vendor or 'Unknown',
                                product=product or 'Unknown',
                                vulnerability_name=description[:500],
                                date_added=datetime.utcnow().date(),
                                short_description=description,
                                required_action='Apply vendor patches. (Source: NVD — late-analyzed catch-up)',
                                known_ransomware=False,
                                notes=f'Auto-imported from NVD Phase 3 catch-up (severity: {cvss_severity_p3}).',
                                cvss_score=cvss_score_p3,
                                severity=cvss_severity_p3,
                                cvss_source='nvd',
                                source='nvd',
                                nvd_status=vuln_status or None,
                            )
                            if cpe_entries:
                                vuln.set_cpe_entries(cpe_entries)
                            db.session.add(vuln)
                            new_count += 1
                            phase3_imported += 1

                        except Exception as e:
                            logger.debug(f"NVD Phase 3: error processing CVE: {e}")
                            continue

                except requests.exceptions.RequestException as e:
                    logger.debug(f"NVD Phase 3 request failed for {p3_severity}: {e}")
                    continue

        except Exception as e:
            logger.debug(f"NVD Phase 3 catch-up failed (non-critical): {e}")

        if phase3_imported:
            logger.info(f"NVD Phase 3 (lastMod catch-up): {phase3_imported} late-analyzed CVEs imported")

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
