"""
Vendor Advisory Feed Integration

Fetches security advisories from major vendors to auto-detect
in-place patches (Path B fixes). When a vendor publishes a fix
for a CVE that patches an existing version in-place (backport),
this module can suggest or auto-create VendorFixOverride records.

Currently supported:
- Microsoft MSRC (Security Response Center) API

Future:
- Cisco PSIRT
- Adobe Security Bulletins
- Oracle Critical Patch Updates
"""

import logging
import requests
from datetime import datetime, timedelta
from typing import List, Dict, Optional, Any

logger = logging.getLogger(__name__)

# Microsoft MSRC API
MSRC_API_BASE = 'https://api.msrc.microsoft.com'
MSRC_CVRF_URL = f'{MSRC_API_BASE}/cvrf/v3.0'


def fetch_msrc_advisories(months_back: int = 3) -> List[Dict[str, Any]]:
    """
    Fetch Microsoft Security Response Center advisories.

    Returns a list of advisory summaries with CVE mappings.

    Args:
        months_back: How many months of advisories to fetch (default 3)

    Returns:
        List of dicts with keys: cve_id, product, fixed_versions, kb_articles, advisory_id, url
    """
    from config import Config

    advisories = []
    now = datetime.utcnow()

    try:
        # Fetch the list of available update periods
        headers = {'Accept': 'application/json'}
        proxies = Config.get_proxies()
        verify_ssl = Config.get_verify_ssl()

        response = requests.get(
            f'{MSRC_CVRF_URL}/updates',
            headers=headers,
            timeout=15,
            proxies=proxies,
            verify=verify_ssl
        )

        if response.status_code != 200:
            logger.warning(f'MSRC API returned {response.status_code}')
            return []

        updates = response.json().get('value', [])

        # Filter to recent months
        cutoff = now - timedelta(days=months_back * 31)
        recent_updates = []
        for update in updates:
            try:
                # MSRC dates are like "2024-Jan", "2024-Feb", etc.
                update_id = update.get('ID', '')
                if not update_id:
                    continue
                # Parse the date from the ID (format: YYYY-Mon)
                parts = update_id.split('-')
                if len(parts) >= 2:
                    year = int(parts[0])
                    month_str = parts[1][:3]
                    month_map = {
                        'Jan': 1, 'Feb': 2, 'Mar': 3, 'Apr': 4,
                        'May': 5, 'Jun': 6, 'Jul': 7, 'Aug': 8,
                        'Sep': 9, 'Oct': 10, 'Nov': 11, 'Dec': 12
                    }
                    month = month_map.get(month_str, 0)
                    if month > 0:
                        update_date = datetime(year, month, 1)
                        if update_date >= cutoff:
                            recent_updates.append(update_id)
            except (ValueError, IndexError):
                continue

        # Fetch detailed advisory data for each recent update
        for update_id in recent_updates[:months_back]:
            try:
                detail_response = requests.get(
                    f'{MSRC_CVRF_URL}/cvrf/{update_id}',
                    headers=headers,
                    timeout=30,
                    proxies=proxies,
                    verify=verify_ssl
                )

                if detail_response.status_code != 200:
                    continue

                cvrf_data = detail_response.json()
                parsed = _parse_msrc_cvrf(cvrf_data, update_id)
                advisories.extend(parsed)

            except Exception as e:
                logger.warning(f'Failed to fetch MSRC advisory {update_id}: {e}')
                continue

    except Exception as e:
        logger.error(f'Failed to fetch MSRC advisories: {e}')

    return advisories


def _parse_msrc_cvrf(cvrf_data: dict, update_id: str) -> List[Dict[str, Any]]:
    """
    Parse a MSRC CVRF document into structured advisory data.

    Extracts CVE IDs, affected products, KB articles, and fix information.
    """
    advisories = []

    vulnerabilities = cvrf_data.get('Vulnerability', [])
    product_tree = cvrf_data.get('ProductTree', {})

    # Build product ID -> name mapping
    product_map = {}
    for branch in product_tree.get('Branch', []):
        _extract_products(branch, product_map)

    for vuln in vulnerabilities:
        cve_id = vuln.get('CVE', '')
        if not cve_id or not cve_id.startswith('CVE-'):
            continue

        title = vuln.get('Title', {}).get('Value', '')

        # Extract KB articles and fixed product IDs from remediations
        kb_articles = set()
        fixed_product_ids = set()

        for remediation in vuln.get('Remediations', []):
            # Type 2 = "Vendor Fix"
            if remediation.get('Type') == 2:
                kb = remediation.get('Description', {}).get('Value', '')
                if kb:
                    kb_articles.add(kb)

                for prod_id in remediation.get('ProductID', []):
                    fixed_product_ids.add(prod_id)

        # Map product IDs to names
        fixed_products = set()
        for prod_id in fixed_product_ids:
            if prod_id in product_map:
                fixed_products.add(product_map[prod_id])

        if cve_id and (kb_articles or fixed_products):
            advisories.append({
                'cve_id': cve_id,
                'title': title,
                'advisory_id': update_id,
                'url': f'https://msrc.microsoft.com/update-guide/vulnerability/{cve_id}',
                'vendor': 'microsoft',
                'kb_articles': list(kb_articles),
                'fixed_products': list(fixed_products),
            })

    return advisories


def _extract_products(branch: dict, product_map: dict):
    """Recursively extract product IDs and names from CVRF product tree."""
    if 'Items' in branch:
        for item in branch['Items']:
            if 'ProductID' in item:
                product_map[item['ProductID']] = item.get('Value', '')
            _extract_products(item, product_map)


def check_advisory_for_cve(cve_id: str, vendor: str = None) -> List[Dict[str, Any]]:
    """
    Check if any vendor advisory mentions a fix for a specific CVE.

    Args:
        cve_id: The CVE ID to check (e.g., "CVE-2024-12345")
        vendor: Optional vendor filter (e.g., "microsoft")

    Returns:
        List of matching advisory entries
    """
    results = []

    if not vendor or vendor.lower() == 'microsoft':
        advisories = fetch_msrc_advisories(months_back=6)
        for advisory in advisories:
            if advisory['cve_id'] == cve_id:
                results.append(advisory)

    return results


def suggest_vendor_fix_overrides(cve_id: str) -> List[Dict[str, Any]]:
    """
    Check vendor advisory feeds and suggest VendorFixOverride records.

    This is called from the UI when a user wants to check if a vendor
    has published a fix that patches an affected version in-place.

    Returns:
        List of suggested overrides with vendor advisory evidence
    """
    suggestions = []

    advisories = check_advisory_for_cve(cve_id)

    for advisory in advisories:
        suggestions.append({
            'cve_id': cve_id,
            'vendor': advisory['vendor'],
            'advisory_id': advisory.get('advisory_id', ''),
            'advisory_url': advisory.get('url', ''),
            'kb_articles': advisory.get('kb_articles', []),
            'fixed_products': advisory.get('fixed_products', []),
            'title': advisory.get('title', ''),
            'suggested_fix_type': 'hotfix' if advisory.get('kb_articles') else 'backport_patch',
            'suggested_patch_id': ', '.join(advisory.get('kb_articles', [])[:3]),
        })

    return suggestions
