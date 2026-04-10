"""
CVE Description Parser — extract vendor/product/version from CVE text.

When NVD marks a CVE as "Awaiting Analysis", there's no CPE data.
SentriKat falls back to keyword matching (medium confidence).
This parser extracts structured data from the CVE description text
to improve matching accuracy for unanalyzed CVEs.

Example: "A vulnerability in Apache HTTP Server 2.4.49 allows..."
  → vendor: "apache", product: "http server", version: "2.4.49"
"""

import re
import logging

logger = logging.getLogger(__name__)

# Common patterns in CVE descriptions
VERSION_PATTERN = re.compile(
    r'(?:version|v|before|prior to|through|up to)\s*'
    r'(\d+(?:\.\d+){1,4}(?:[-.]?\w+)?)',
    re.IGNORECASE
)

PRODUCT_VERSION_PATTERN = re.compile(
    r'(?:in|affecting|vulnerability in|flaw in|issue in)\s+'
    r'([A-Z][\w\s-]{2,30}?)\s+'
    r'(?:version\s+)?'
    r'(\d+(?:\.\d+){1,4}(?:[-.]?\w+)?)',
    re.IGNORECASE
)

# Known vendor prefixes to clean up
VENDOR_PREFIXES = {
    'apache': ['apache software foundation', 'apache'],
    'microsoft': ['microsoft corporation', 'microsoft'],
    'google': ['google llc', 'google inc', 'google'],
    'mozilla': ['mozilla foundation', 'mozilla'],
    'oracle': ['oracle corporation', 'oracle'],
    'adobe': ['adobe systems', 'adobe inc', 'adobe'],
    'cisco': ['cisco systems', 'cisco'],
    'ibm': ['international business machines', 'ibm'],
    'redhat': ['red hat', 'redhat'],
    'vmware': ['vmware inc', 'vmware'],
    'sap': ['sap se', 'sap'],
    'jenkins': ['jenkins project', 'jenkins'],
    'wordpress': ['wordpress foundation', 'wordpress'],
    'php': ['the php group', 'php group', 'php'],
    'python': ['python software foundation', 'python'],
    'nodejs': ['node.js foundation', 'nodejs', 'node.js'],
}


def parse_cve_description(description):
    """Extract vendor, product, and version info from CVE description text.

    Returns:
        dict with keys: vendor, product, versions (list), affected_before
        Returns None if nothing useful could be extracted.
    """
    if not description or len(description) < 20:
        return None

    result = {
        'vendor': None,
        'product': None,
        'versions': [],
        'affected_before': None,
    }

    # Try to extract product + version pattern
    match = PRODUCT_VERSION_PATTERN.search(description)
    if match:
        product_text = match.group(1).strip()
        version = match.group(2).strip()

        # Clean up product name
        product_text = re.sub(r'\s+', ' ', product_text).strip()

        # Try to identify vendor from product name
        product_lower = product_text.lower()
        for vendor_key, prefixes in VENDOR_PREFIXES.items():
            for prefix in prefixes:
                if product_lower.startswith(prefix):
                    result['vendor'] = vendor_key
                    # Remove vendor prefix from product name
                    product_text = product_text[len(prefix):].strip()
                    break
            if result['vendor']:
                break

        result['product'] = product_text
        result['versions'].append(version)

    # Extract "before X.Y.Z" pattern for fix version
    before_match = re.search(
        r'(?:before|prior to|fixed in|patched in)\s+'
        r'(?:version\s+)?(\d+(?:\.\d+){1,4}(?:[-.]?\w+)?)',
        description, re.IGNORECASE
    )
    if before_match:
        result['affected_before'] = before_match.group(1)

    # Extract all version numbers mentioned
    all_versions = VERSION_PATTERN.findall(description)
    for v in all_versions:
        if v not in result['versions']:
            result['versions'].append(v)

    # Only return if we found something useful
    if result['product'] or result['versions']:
        return result

    return None


def enrich_unanalyzed_cves():
    """Parse descriptions of CVEs in 'Awaiting Analysis' status.

    Updates the vulnerability's vendor_project and product fields
    with extracted data when confidence is reasonable.
    """
    from app import db
    from app.models import Vulnerability

    cves = Vulnerability.query.filter(
        Vulnerability.nvd_status == 'Awaiting Analysis',
        Vulnerability.cpe_fetched_at.is_(None),
    ).limit(100).all()

    enriched = 0
    for vuln in cves:
        desc = vuln.short_description or vuln.vulnerability_name
        if not desc:
            continue

        parsed = parse_cve_description(desc)
        if not parsed:
            continue

        # Only update if we found vendor AND product (avoid low-quality data)
        if parsed['vendor'] and parsed['product']:
            if not vuln.vendor_project:
                vuln.vendor_project = parsed['vendor'].title()
            if not vuln.product:
                vuln.product = parsed['product']
            enriched += 1

    if enriched > 0:
        try:
            db.session.commit()
            logger.info(f"CVE parser enriched {enriched} 'Awaiting Analysis' CVEs")
        except Exception as e:
            db.session.rollback()
            logger.error(f"CVE parser commit failed: {e}")

    return enriched
