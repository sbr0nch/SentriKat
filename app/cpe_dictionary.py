"""
Local CPE Dictionary - Offline CPE matching from vulnerability data + NVD feed.

Two data sources populate the dictionary:

1. VULNERABILITY EXTRACTION (build_cpe_dictionary):
   Every vulnerability in the database has CPE entries (vendor:product).
   We extract these into cpe_dictionary_entries. Automatic, runs daily.
   Gives us coverage for every product mentioned in any synced CVE.

2. NVD CPE DICTIONARY DOWNLOAD (sync_nvd_cpe_dictionary):
   The NVD publishes ~900,000 CPE entries via API. We download ALL unique
   vendor:product pairs with their human-readable titles.
   ~30,000-50,000 unique pairs → massive matching improvement.
   Runs weekly or on-demand. Uses NVD API 2.0 with pagination.

Together these give us offline CPE matching without rate-limited API calls.
"""

import re
import json
import logging
from datetime import datetime

logger = logging.getLogger(__name__)


def build_cpe_dictionary():
    """
    Scan all vulnerabilities and extract unique CPE vendor:product pairs
    into the cpe_dictionary_entries table.

    This runs after CISA KEV sync to keep the dictionary current.
    Does an incremental upsert (new entries added, existing ones updated).

    Returns: dict with 'added', 'updated', 'total' counts
    """
    from app import db
    from app.models import Vulnerability, CpeDictionaryEntry

    stats = {'added': 0, 'updated': 0, 'total': 0, 'errors': 0}

    try:
        # Get all vulnerabilities with CPE data
        vulns_with_cpe = Vulnerability.query.filter(
            Vulnerability.cpe_data.isnot(None),
            Vulnerability.cpe_data != ''
        ).all()

        if not vulns_with_cpe:
            logger.info("No vulnerabilities with CPE data found")
            return stats

        # Extract unique vendor:product pairs with metadata
        seen_pairs = {}  # key: "vendor|product" -> {vendor, product, aliases, cve_count}

        for vuln in vulns_with_cpe:
            try:
                entries = vuln.get_cpe_entries()
                for entry in entries:
                    vendor = (entry.get('vendor') or '').lower().strip()
                    product = (entry.get('product') or '').lower().strip()

                    if not vendor or not product:
                        continue
                    if vendor == '*' or product == '*':
                        continue

                    key = f"{vendor}|{product}"

                    if key not in seen_pairs:
                        seen_pairs[key] = {
                            'vendor': vendor,
                            'product': product,
                            'cve_count': 0,
                            'aliases': set(),
                        }

                    seen_pairs[key]['cve_count'] += 1

                    # Build search aliases from vulnerability metadata
                    if vuln.vendor_project:
                        seen_pairs[key]['aliases'].add(vuln.vendor_project.lower().strip())
                    if vuln.product:
                        seen_pairs[key]['aliases'].add(vuln.product.lower().strip())

            except Exception as e:
                stats['errors'] += 1
                continue

        logger.info(f"Extracted {len(seen_pairs)} unique CPE vendor:product pairs from {len(vulns_with_cpe)} vulnerabilities")

        # Upsert into database
        for key, data in seen_pairs.items():
            try:
                existing = CpeDictionaryEntry.query.filter_by(
                    cpe_vendor=data['vendor'],
                    cpe_product=data['product']
                ).first()

                # Build alias string (deduplicated, pipe-separated)
                aliases_str = '|'.join(sorted(data['aliases'] - {data['vendor'], data['product']}))

                if existing:
                    existing.cve_count = data['cve_count']
                    if aliases_str:
                        existing.search_aliases = aliases_str
                    existing.updated_at = datetime.utcnow()
                    stats['updated'] += 1
                else:
                    entry = CpeDictionaryEntry(
                        cpe_vendor=data['vendor'],
                        cpe_product=data['product'],
                        search_aliases=aliases_str or None,
                        cve_count=data['cve_count'],
                    )
                    db.session.add(entry)
                    stats['added'] += 1

            except Exception as e:
                stats['errors'] += 1
                continue

        db.session.commit()
        stats['total'] = CpeDictionaryEntry.query.count()

        logger.info(
            f"CPE dictionary built: {stats['added']} added, "
            f"{stats['updated']} updated, {stats['total']} total entries"
        )

    except Exception as e:
        logger.error(f"Failed to build CPE dictionary: {e}")
        try:
            db.session.rollback()
        except Exception:
            pass

    return stats


# Pre-compiled vendor normalization patterns
_VENDOR_SUFFIXES = re.compile(
    r'\s*('
    r'inc\.?|incorporated|llc|ltd\.?|limited|corp\.?|corporation|'
    r'co\.?|company|gmbh|ag|s\.?a\.?|b\.?v\.?|n\.?v\.?|'
    r'plc|pty|group|technologies|technology|software|systems|'
    r'computing|international|solutions|enterprises?'
    r')\s*$',
    re.IGNORECASE
)


def _normalize_vendor_for_lookup(vendor):
    """Normalize an agent-reported vendor name for dictionary lookup."""
    if not vendor:
        return ''
    v = vendor.lower().strip()
    v = _VENDOR_SUFFIXES.sub('', v).strip()
    v = v.rstrip(',').strip()
    # Replace spaces/hyphens with underscores (CPE convention)
    v_cpe = re.sub(r'[\s\-]+', '_', v)
    return v_cpe


def _normalize_product_for_lookup(product_name):
    """Normalize an agent-reported product name for dictionary lookup."""
    if not product_name:
        return ''
    p = product_name.lower().strip()
    # Remove parenthetical suffixes
    p = re.sub(r'\s*\([^)]*\)\s*$', '', p)
    # Remove trailing version numbers
    p = re.sub(r'\s+v?\d+[\d.]*\s*$', '', p)
    # Remove architecture suffixes
    p = re.sub(r'\s+(x64|x86|64-bit|32-bit|amd64|arm64)\s*$', '', p)
    # Replace spaces/hyphens with underscores (CPE convention)
    p_cpe = re.sub(r'[\s\-]+', '_', p.strip())
    return p_cpe


def lookup_cpe_dictionary(vendor, product_name):
    """
    Look up a software product in the local CPE dictionary.

    Tries multiple matching strategies:
    1. Exact vendor + product match
    2. Product-only match (ignoring vendor)
    3. Alias match (from vulnerability metadata)

    Args:
        vendor: Agent-reported vendor name (e.g., "Google LLC")
        product_name: Agent-reported product name (e.g., "Google Chrome")

    Returns:
        tuple: (cpe_vendor, cpe_product, confidence) or (None, None, 0.0)
    """
    from app.models import CpeDictionaryEntry

    try:
        norm_vendor = _normalize_vendor_for_lookup(vendor)
        norm_product = _normalize_product_for_lookup(product_name)

        if not norm_product:
            return None, None, 0.0

        # Strategy 1: Exact vendor + product match (highest confidence)
        if norm_vendor:
            entry = CpeDictionaryEntry.query.filter_by(
                cpe_vendor=norm_vendor,
                cpe_product=norm_product
            ).first()
            if entry:
                _increment_usage(entry)
                return entry.cpe_vendor, entry.cpe_product, 0.92

        # Strategy 2: Product-only match (may be ambiguous)
        entries = CpeDictionaryEntry.query.filter_by(
            cpe_product=norm_product
        ).order_by(CpeDictionaryEntry.cve_count.desc()).all()

        if len(entries) == 1:
            # Unambiguous: only one vendor has this product name
            _increment_usage(entries[0])
            return entries[0].cpe_vendor, entries[0].cpe_product, 0.88
        elif len(entries) > 1 and norm_vendor:
            # Multiple vendors have this product - try partial vendor match
            for entry in entries:
                if norm_vendor in entry.cpe_vendor or entry.cpe_vendor in norm_vendor:
                    _increment_usage(entry)
                    return entry.cpe_vendor, entry.cpe_product, 0.85

        # Strategy 3: Search aliases (from vulnerability human-readable names)
        # Build a search term from the original product name
        search_term = product_name.lower().strip()
        all_entries = CpeDictionaryEntry.query.filter(
            CpeDictionaryEntry.search_aliases.isnot(None)
        ).all()

        best_match = None
        best_score = 0

        for entry in all_entries:
            aliases = (entry.search_aliases or '').split('|')
            for alias in aliases:
                if not alias:
                    continue
                # Exact alias match
                if alias == search_term:
                    score = 0.85
                elif alias in search_term or search_term in alias:
                    # Substring match
                    overlap = min(len(alias), len(search_term)) / max(len(alias), len(search_term))
                    score = 0.70 * overlap
                else:
                    continue

                if score > best_score:
                    best_score = score
                    best_match = entry

        if best_match and best_score >= 0.60:
            _increment_usage(best_match)
            return best_match.cpe_vendor, best_match.cpe_product, best_score

        return None, None, 0.0

    except Exception as e:
        logger.debug(f"CPE dictionary lookup failed: {e}")
        return None, None, 0.0


def _increment_usage(entry):
    """Increment usage count for a dictionary entry (non-blocking)."""
    try:
        from app import db
        entry.usage_count = (entry.usage_count or 0) + 1
        db.session.add(entry)
        # Don't commit here - let the caller's transaction handle it
    except Exception:
        pass


def get_dictionary_stats():
    """Get statistics about the local CPE dictionary."""
    from app.models import CpeDictionaryEntry, SystemSettings

    try:
        total = CpeDictionaryEntry.query.count()
        with_aliases = CpeDictionaryEntry.query.filter(
            CpeDictionaryEntry.search_aliases.isnot(None)
        ).count()
        top_used = CpeDictionaryEntry.query.filter(
            CpeDictionaryEntry.usage_count > 0
        ).count()

        # Check last NVD sync time
        last_nvd_sync = None
        try:
            setting = SystemSettings.query.filter_by(key='cpe_dict_last_nvd_sync').first()
            if setting:
                last_nvd_sync = setting.value
        except Exception:
            pass

        return {
            'total_entries': total,
            'with_aliases': with_aliases,
            'used_for_matching': top_used,
            'last_nvd_sync': last_nvd_sync,
        }
    except Exception:
        return {'total_entries': 0, 'with_aliases': 0, 'used_for_matching': 0, 'last_nvd_sync': None}


# ============================================================================
# NVD CPE DICTIONARY DOWNLOAD
# ============================================================================

def sync_nvd_cpe_dictionary(max_pages=500):
    """
    Download the NVD CPE dictionary and extract unique vendor:product pairs
    with human-readable titles.

    The NVD has ~900,000 CPE entries. Most are version-specific duplicates
    (e.g., cpe:2.3:a:google:chrome:120.0.6099, cpe:2.3:a:google:chrome:119.0.6045).
    We extract only unique vendor:product pairs → ~30,000-50,000 entries.

    Uses NVD CPE API 2.0 with pagination (10,000 results per page).
    Rate: 5 req/30s without key, 50 req/30s with key.
    Time estimate: ~5 min with key, ~50 min without key.

    Returns: dict with stats
    """
    import requests
    import time
    import urllib3
    from config import Config
    from app import db
    from app.models import CpeDictionaryEntry, SystemSettings

    stats = {
        'pages_fetched': 0,
        'cpe_entries_scanned': 0,
        'unique_pairs_found': 0,
        'added': 0,
        'updated': 0,
        'total': 0,
        'errors': 0,
    }

    # Get NVD API key
    try:
        from app.nvd_cpe_api import _get_api_key
        api_key = _get_api_key()
    except Exception:
        api_key = None

    has_key = bool(api_key)
    results_per_page = 10000
    delay_between_requests = 0.6 if has_key else 6.0  # Respect rate limits

    logger.info(
        f"Starting NVD CPE dictionary sync "
        f"(API key: {'yes' if has_key else 'no'}, "
        f"delay: {delay_between_requests}s/page)"
    )

    # Collect unique vendor:product pairs
    seen_pairs = {}  # "vendor|product" -> {vendor, product, title, count}

    url = "https://services.nvd.nist.gov/rest/json/cpes/2.0"
    headers = {}
    if api_key:
        headers['apiKey'] = api_key

    proxies = Config.get_proxies()
    verify_ssl = Config.get_verify_ssl()
    if not verify_ssl:
        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

    start_index = 0
    total_results = None
    consecutive_errors = 0

    for page in range(max_pages):
        params = {
            'resultsPerPage': results_per_page,
            'startIndex': start_index,
        }

        try:
            response = requests.get(
                url, params=params, headers=headers,
                timeout=30, proxies=proxies, verify=verify_ssl
            )

            if response.status_code == 403:
                logger.warning("NVD rate limit hit, waiting 30s...")
                time.sleep(30)
                continue

            if response.status_code != 200:
                consecutive_errors += 1
                if consecutive_errors >= 3:
                    logger.error(f"NVD CPE sync: {consecutive_errors} consecutive errors, stopping")
                    break
                time.sleep(delay_between_requests * 2)
                continue

            consecutive_errors = 0
            data = response.json()

            if total_results is None:
                total_results = data.get('totalResults', 0)
                logger.info(f"NVD CPE dictionary: {total_results} total entries to scan")

            products = data.get('products', [])
            if not products:
                break

            for product_entry in products:
                cpe_data = product_entry.get('cpe', {})
                cpe_name = cpe_data.get('cpeName', '')

                # Skip deprecated
                if cpe_data.get('deprecated', False):
                    continue

                # Parse vendor:product from CPE URI
                parts = cpe_name.split(':')
                if len(parts) < 5:
                    continue

                vendor = parts[3].lower()
                product = parts[4].lower()

                if not vendor or not product or vendor == '*' or product == '*':
                    continue

                key = f"{vendor}|{product}"
                stats['cpe_entries_scanned'] += 1

                if key not in seen_pairs:
                    # Get human-readable title
                    titles = cpe_data.get('titles', [])
                    title = titles[0].get('title', '') if titles else ''

                    seen_pairs[key] = {
                        'vendor': vendor,
                        'product': product,
                        'title': title,
                        'count': 0,
                    }

                seen_pairs[key]['count'] += 1

            stats['pages_fetched'] += 1
            start_index += results_per_page

            if start_index >= (total_results or 0):
                break  # All pages fetched

            # Progress log every 10 pages
            if stats['pages_fetched'] % 10 == 0:
                logger.info(
                    f"NVD CPE sync progress: {stats['pages_fetched']} pages, "
                    f"{stats['cpe_entries_scanned']} entries, "
                    f"{len(seen_pairs)} unique pairs"
                )

            time.sleep(delay_between_requests)

        except requests.exceptions.Timeout:
            logger.warning(f"NVD CPE sync timeout on page {page}, retrying...")
            time.sleep(delay_between_requests * 3)
            consecutive_errors += 1
            if consecutive_errors >= 3:
                break
        except Exception as e:
            logger.error(f"NVD CPE sync error on page {page}: {e}")
            consecutive_errors += 1
            if consecutive_errors >= 3:
                break
            time.sleep(delay_between_requests)

    stats['unique_pairs_found'] = len(seen_pairs)
    logger.info(
        f"NVD CPE scan complete: {stats['pages_fetched']} pages, "
        f"{stats['cpe_entries_scanned']} entries, "
        f"{stats['unique_pairs_found']} unique vendor:product pairs"
    )

    # Upsert into database
    batch_count = 0
    for key, data in seen_pairs.items():
        try:
            existing = CpeDictionaryEntry.query.filter_by(
                cpe_vendor=data['vendor'],
                cpe_product=data['product']
            ).first()

            # Build alias from title if meaningful
            title = data.get('title', '')
            alias = ''
            if title:
                # Extract product name from title (e.g. "Apache Tomcat 10.1.18" -> "apache tomcat")
                import re as _re
                clean_title = _re.sub(r'\s+\d[\d.]*.*$', '', title).lower().strip()
                if clean_title and clean_title not in (data['vendor'], data['product']):
                    alias = clean_title

            if existing:
                # Update count, add alias if new
                if data['count'] > (existing.cve_count or 0):
                    existing.cve_count = data['count']
                if alias and alias not in (existing.search_aliases or ''):
                    current = existing.search_aliases or ''
                    existing.search_aliases = f"{current}|{alias}" if current else alias
                existing.updated_at = datetime.utcnow()
                stats['updated'] += 1
            else:
                entry = CpeDictionaryEntry(
                    cpe_vendor=data['vendor'],
                    cpe_product=data['product'],
                    search_aliases=alias or None,
                    cve_count=data['count'],
                )
                db.session.add(entry)
                stats['added'] += 1

            batch_count += 1
            if batch_count % 500 == 0:
                db.session.commit()

        except Exception as e:
            stats['errors'] += 1
            if stats['errors'] % 100 == 0:
                logger.warning(f"NVD CPE sync: {stats['errors']} errors so far")
            continue

    try:
        db.session.commit()
    except Exception as e:
        logger.error(f"NVD CPE sync final commit failed: {e}")
        db.session.rollback()

    # Save sync timestamp
    try:
        setting = SystemSettings.query.filter_by(key='cpe_dict_last_nvd_sync').first()
        if setting:
            setting.value = datetime.utcnow().isoformat()
        else:
            setting = SystemSettings(
                key='cpe_dict_last_nvd_sync',
                value=datetime.utcnow().isoformat(),
                category='sync',
                description='Last NVD CPE dictionary sync timestamp'
            )
            db.session.add(setting)
        db.session.commit()
    except Exception:
        pass

    stats['total'] = CpeDictionaryEntry.query.count()

    logger.info(
        f"NVD CPE dictionary sync complete: "
        f"{stats['added']} added, {stats['updated']} updated, "
        f"{stats['total']} total entries, {stats['errors']} errors"
    )

    return stats
