"""
Local CPE Dictionary - Offline CPE matching from vulnerability data + NVD feed.

Three data sources populate the dictionary:

1. VULNERABILITY EXTRACTION (build_cpe_dictionary):
   Every vulnerability in the database has CPE entries (vendor:product).
   We extract these into cpe_dictionary_entries. Automatic, runs daily.
   Gives us coverage for every product mentioned in any synced CVE.

2. BULK CSV DOWNLOAD (_bulk_download_cpe_csv):
   Downloads the full NVD CPE vendor:product dictionary as a pre-processed
   CSV from github.com/tiiuae/cpedict (~40-50K pairs). Single HTTP request,
   completes in seconds. Used for initial population and monthly refresh.

3. INCREMENTAL NVD API SYNC (_incremental_nvd_sync):
   Uses NVD CPE API 2.0 with lastModStartDate/lastModEndDate to fetch only
   new/changed CPEs since last sync. Keeps the dictionary current between
   bulk downloads. Runs weekly.

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
    2. Product with vendor prefix stripped (e.g. "Google Chrome" → "chrome")
    3. Product-only match (ignoring vendor)
    4. Alias match (from vulnerability metadata)

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

        # Build candidate product names to try:
        # e.g. "Google Chrome" with vendor "Google" → try ["google_chrome", "chrome"]
        product_candidates = [norm_product]
        if norm_vendor:
            # Strip vendor name prefix from product (very common pattern)
            # "google_chrome" with vendor "google" → "chrome"
            vendor_prefix = norm_vendor + '_'
            if norm_product.startswith(vendor_prefix) and len(norm_product) > len(vendor_prefix):
                stripped = norm_product[len(vendor_prefix):]
                product_candidates.append(stripped)
            # Also try: "microsoft_visual_studio" → "visual_studio"
            # Handle multi-word vendors like "adobe_systems" → strip "adobe_" too
            vendor_first_word = norm_vendor.split('_')[0] + '_'
            if vendor_first_word != vendor_prefix and norm_product.startswith(vendor_first_word):
                stripped2 = norm_product[len(vendor_first_word):]
                if stripped2 not in product_candidates:
                    product_candidates.append(stripped2)

        # Strategy 1: Exact vendor + product match (highest confidence)
        if norm_vendor:
            for candidate in product_candidates:
                entry = CpeDictionaryEntry.query.filter_by(
                    cpe_vendor=norm_vendor,
                    cpe_product=candidate
                ).first()
                if entry:
                    _increment_usage(entry)
                    return entry.cpe_vendor, entry.cpe_product, 0.92

        # Strategy 2: Product-only match (may be ambiguous)
        for candidate in product_candidates:
            entries = CpeDictionaryEntry.query.filter_by(
                cpe_product=candidate
            ).order_by(CpeDictionaryEntry.cve_count.desc()).all()

            if len(entries) == 1:
                _increment_usage(entries[0])
                return entries[0].cpe_vendor, entries[0].cpe_product, 0.88
            elif len(entries) > 1 and norm_vendor:
                for entry in entries:
                    if norm_vendor in entry.cpe_vendor or entry.cpe_vendor in norm_vendor:
                        _increment_usage(entry)
                        return entry.cpe_vendor, entry.cpe_product, 0.85

        # Strategy 3: Search aliases (from vulnerability human-readable names)
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
    """Increment usage count for a dictionary entry (non-blocking).

    Uses raw SQL to avoid dirtying the ORM session, which can cause
    autoflush timeouts that roll back the caller's transaction.
    """
    try:
        from app import db
        db.session.execute(
            db.text("UPDATE cpe_dictionary_entries SET usage_count = COALESCE(usage_count, 0) + 1 WHERE id = :id"),
            {'id': entry.id}
        )
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

        # Check sync timestamps
        last_nvd_sync = None
        last_bulk_download = None
        try:
            setting = SystemSettings.query.filter_by(key='cpe_dict_last_nvd_sync').first()
            if setting:
                last_nvd_sync = setting.value
            bulk_setting = SystemSettings.query.filter_by(key='cpe_dict_last_bulk_download').first()
            if bulk_setting:
                last_bulk_download = bulk_setting.value
        except Exception:
            pass

        return {
            'total_entries': total,
            'with_aliases': with_aliases,
            'used_for_matching': top_used,
            'last_nvd_sync': last_nvd_sync,
            'last_bulk_download': last_bulk_download,
        }
    except Exception:
        return {'total_entries': 0, 'with_aliases': 0, 'used_for_matching': 0, 'last_nvd_sync': None}


# ============================================================================
# NVD CPE DICTIONARY SYNC (Bulk download + Incremental API updates)
# ============================================================================

# CSV source: tiiuae/cpedict - daily-updated vendor:product pairs from NVD
_CPE_CSV_URL = "https://raw.githubusercontent.com/tiiuae/cpedict/main/data/cpes.csv"

# NVD API 2.0 for incremental sync
_NVD_CPE_API_URL = "https://services.nvd.nist.gov/rest/json/cpes/2.0"


def sync_nvd_cpe_dictionary():
    """
    Sync the NVD CPE dictionary into our local database.

    Two-phase approach:
    1. BULK DOWNLOAD: Fetch the full vendor:product CSV (~40-50K pairs)
       from github.com/tiiuae/cpedict. Single HTTP request, fast.
       Done on first run and monthly thereafter.

    2. INCREMENTAL SYNC: Use NVD API 2.0 with lastModStartDate/lastModEndDate
       to fetch only CPEs added/changed since last sync. Fast, stays current.

    Returns: dict with combined stats from both phases.
    """
    from app import db
    from app.models import SystemSettings

    stats = {
        'bulk_added': 0, 'bulk_updated': 0, 'bulk_skipped': 0,
        'incremental_added': 0, 'incremental_updated': 0, 'incremental_pages': 0,
        'total': 0, 'errors': 0,
    }

    # Check if we need a bulk download (first run or monthly refresh)
    needs_bulk = True
    try:
        setting = SystemSettings.query.filter_by(key='cpe_dict_last_bulk_download').first()
        if setting and setting.value:
            from datetime import timedelta
            last_bulk = datetime.fromisoformat(setting.value)
            # Re-download bulk CSV monthly
            if (datetime.utcnow() - last_bulk) < timedelta(days=30):
                needs_bulk = False
                logger.info("Bulk CPE CSV downloaded recently, skipping (monthly refresh)")
    except Exception:
        pass

    # Phase 1: Bulk CSV download
    if needs_bulk:
        try:
            bulk_stats = _bulk_download_cpe_csv()
            stats['bulk_added'] = bulk_stats.get('added', 0)
            stats['bulk_updated'] = bulk_stats.get('updated', 0)
            stats['bulk_skipped'] = bulk_stats.get('skipped', 0)
            stats['errors'] += bulk_stats.get('errors', 0)
        except Exception as e:
            logger.error(f"Bulk CPE CSV download failed: {e}")
            stats['errors'] += 1

    # Phase 2: Incremental NVD API sync (new/changed CPEs since last sync)
    try:
        inc_stats = _incremental_nvd_sync()
        stats['incremental_added'] = inc_stats.get('added', 0)
        stats['incremental_updated'] = inc_stats.get('updated', 0)
        stats['incremental_pages'] = inc_stats.get('pages', 0)
        stats['errors'] += inc_stats.get('errors', 0)
    except Exception as e:
        logger.error(f"Incremental NVD CPE sync failed: {e}")
        stats['errors'] += 1

    # Update last sync timestamp
    _save_setting('cpe_dict_last_nvd_sync', datetime.utcnow().isoformat())

    try:
        from app.models import CpeDictionaryEntry
        stats['total'] = CpeDictionaryEntry.query.count()
    except Exception:
        pass

    logger.info(
        f"NVD CPE dictionary sync complete: "
        f"bulk({stats['bulk_added']}+{stats['bulk_updated']}), "
        f"incremental({stats['incremental_added']}+{stats['incremental_updated']}), "
        f"{stats['total']} total, {stats['errors']} errors"
    )

    return stats


def _bulk_download_cpe_csv():
    """
    Download the full NVD CPE vendor:product dictionary as CSV.

    Source: github.com/tiiuae/cpedict (daily-updated from NVD).
    Format: CSV with columns "vendor","product" (~40-50K rows).
    Single HTTP request, completes in seconds.

    Returns: dict with 'added', 'updated', 'skipped', 'errors' counts.
    """
    import requests
    import csv
    import io
    from config import Config
    from app import db
    from app.models import CpeDictionaryEntry

    stats = {'added': 0, 'updated': 0, 'skipped': 0, 'errors': 0, 'total_rows': 0}

    logger.info(f"Downloading CPE dictionary CSV from {_CPE_CSV_URL}...")

    proxies = Config.get_proxies()
    verify_ssl = Config.get_verify_ssl()

    try:
        response = requests.get(
            _CPE_CSV_URL, timeout=60, proxies=proxies, verify=verify_ssl
        )
        response.raise_for_status()
    except requests.RequestException as e:
        logger.error(f"Failed to download CPE CSV: {e}")
        stats['errors'] = 1
        return stats

    content = response.text
    reader = csv.reader(io.StringIO(content))

    # Build a set of existing entries for fast lookup (avoid N+1 queries)
    existing_map = {}
    try:
        for entry in CpeDictionaryEntry.query.with_entities(
            CpeDictionaryEntry.id,
            CpeDictionaryEntry.cpe_vendor,
            CpeDictionaryEntry.cpe_product,
        ).all():
            existing_map[f"{entry.cpe_vendor}|{entry.cpe_product}"] = entry.id
    except Exception:
        pass

    batch_count = 0

    for row in reader:
        if len(row) < 2:
            continue

        vendor = row[0].strip().strip('"').lower()
        product = row[1].strip().strip('"').lower()

        if not vendor or not product:
            continue

        stats['total_rows'] += 1
        key = f"{vendor}|{product}"

        if key in existing_map:
            stats['skipped'] += 1
            continue

        try:
            entry = CpeDictionaryEntry(
                cpe_vendor=vendor,
                cpe_product=product,
                cve_count=0,
            )
            db.session.add(entry)
            existing_map[key] = True  # Mark as seen
            stats['added'] += 1
            batch_count += 1

            if batch_count % 1000 == 0:
                db.session.commit()
                logger.info(f"CPE CSV progress: {stats['total_rows']} rows, {stats['added']} added")

        except Exception as e:
            stats['errors'] += 1
            if stats['errors'] <= 5:
                logger.warning(f"CPE CSV insert error for {vendor}:{product}: {e}")
            db.session.rollback()
            # Re-load existing map after rollback to stay consistent
            existing_map[key] = True
            continue

    try:
        db.session.commit()
    except Exception as e:
        logger.error(f"CPE CSV final commit failed: {e}")
        db.session.rollback()

    # Record bulk download timestamp
    _save_setting('cpe_dict_last_bulk_download', datetime.utcnow().isoformat())

    logger.info(
        f"CPE CSV download complete: {stats['total_rows']} rows, "
        f"{stats['added']} added, {stats['skipped']} already existed, "
        f"{stats['errors']} errors"
    )

    return stats


def _incremental_nvd_sync():
    """
    Fetch new/changed CPEs from NVD API 2.0 since last sync.

    Uses lastModStartDate/lastModEndDate to get only recent changes.
    Much faster than full pagination (~1-5 pages instead of ~130).
    Extracts unique vendor:product pairs and upserts with titles.

    Returns: dict with 'added', 'updated', 'pages', 'errors' counts.
    """
    import requests
    import time
    import urllib3
    from config import Config
    from app import db
    from app.models import CpeDictionaryEntry, SystemSettings

    stats = {'added': 0, 'updated': 0, 'pages': 0, 'scanned': 0, 'errors': 0}

    # Determine sync window
    last_sync_str = None
    try:
        setting = SystemSettings.query.filter_by(key='cpe_dict_last_nvd_sync').first()
        if setting and setting.value:
            last_sync_str = setting.value
    except Exception:
        pass

    now = datetime.utcnow()

    from datetime import timedelta

    if last_sync_str:
        try:
            last_sync = datetime.fromisoformat(last_sync_str)
        except ValueError:
            last_sync = now - timedelta(days=7)
    else:
        # First incremental sync - get last 30 days of changes
        last_sync = now - timedelta(days=30)

    # NVD API requires max 120-day range
    if (now - last_sync) > timedelta(days=120):
        last_sync = now - timedelta(days=119)

    # Format dates for NVD API (ISO-8601 with zero UTC offset)
    start_date = last_sync.strftime('%Y-%m-%dT%H:%M:%S.000')
    end_date = now.strftime('%Y-%m-%dT%H:%M:%S.000')

    logger.info(f"Incremental NVD CPE sync: {start_date} → {end_date}")

    # Get NVD API key
    api_key = None
    try:
        from app.nvd_cpe_api import _get_api_key
        api_key = _get_api_key()
    except Exception:
        pass

    has_key = bool(api_key)
    delay = 0.6 if has_key else 6.0
    results_per_page = 10000

    headers = {}
    if api_key:
        headers['apiKey'] = api_key

    proxies = Config.get_proxies()
    verify_ssl = Config.get_verify_ssl()
    if not verify_ssl:
        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

    # Collect unique vendor:product pairs from this sync window
    seen_pairs = {}
    start_index = 0
    total_results = None
    consecutive_errors = 0

    for page in range(50):  # Max 50 pages for incremental (should be 1-5)
        params = {
            'resultsPerPage': results_per_page,
            'startIndex': start_index,
            'lastModStartDate': start_date,
            'lastModEndDate': end_date,
        }

        try:
            response = requests.get(
                _NVD_CPE_API_URL, params=params, headers=headers,
                timeout=30, proxies=proxies, verify=verify_ssl
            )

            if response.status_code == 403:
                logger.warning("NVD rate limit hit, waiting 30s...")
                time.sleep(30)
                continue

            if response.status_code != 200:
                consecutive_errors += 1
                if consecutive_errors >= 3:
                    logger.error(f"NVD incremental sync: {consecutive_errors} consecutive errors, stopping")
                    break
                time.sleep(delay * 2)
                continue

            consecutive_errors = 0
            data = response.json()

            if total_results is None:
                total_results = data.get('totalResults', 0)
                logger.info(f"NVD incremental sync: {total_results} CPEs modified since last sync")
                if total_results == 0:
                    break

            products = data.get('products', [])
            if not products:
                break

            for product_entry in products:
                cpe_data = product_entry.get('cpe', {})
                cpe_name = cpe_data.get('cpeName', '')

                if cpe_data.get('deprecated', False):
                    continue

                parts = cpe_name.split(':')
                if len(parts) < 5:
                    continue

                vendor = parts[3].lower()
                product = parts[4].lower()

                if not vendor or not product or vendor == '*' or product == '*':
                    continue

                stats['scanned'] += 1
                key = f"{vendor}|{product}"

                if key not in seen_pairs:
                    titles = cpe_data.get('titles', [])
                    title = titles[0].get('title', '') if titles else ''
                    seen_pairs[key] = {
                        'vendor': vendor,
                        'product': product,
                        'title': title,
                    }

            stats['pages'] += 1
            start_index += results_per_page

            if start_index >= (total_results or 0):
                break

            time.sleep(delay)

        except requests.exceptions.Timeout:
            consecutive_errors += 1
            if consecutive_errors >= 3:
                break
            time.sleep(delay * 3)
        except Exception as e:
            logger.error(f"NVD incremental sync page {page} error: {e}")
            consecutive_errors += 1
            if consecutive_errors >= 3:
                break
            time.sleep(delay)

    logger.info(f"NVD incremental: scanned {stats['scanned']} CPEs, {len(seen_pairs)} unique pairs")

    # Upsert new/updated pairs
    batch_count = 0
    for key, data in seen_pairs.items():
        try:
            existing = CpeDictionaryEntry.query.filter_by(
                cpe_vendor=data['vendor'],
                cpe_product=data['product']
            ).first()

            # Build alias from title
            title = data.get('title', '')
            alias = ''
            if title:
                clean_title = re.sub(r'\s+\d[\d.]*.*$', '', title).lower().strip()
                if clean_title and clean_title not in (data['vendor'], data['product']):
                    alias = clean_title

            if existing:
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
                    cve_count=0,
                )
                db.session.add(entry)
                stats['added'] += 1

            batch_count += 1
            if batch_count % 500 == 0:
                db.session.commit()

        except Exception as e:
            stats['errors'] += 1
            continue

    try:
        db.session.commit()
    except Exception as e:
        logger.error(f"NVD incremental sync commit failed: {e}")
        db.session.rollback()

    logger.info(
        f"NVD incremental sync: {stats['added']} added, "
        f"{stats['updated']} updated, {stats['pages']} pages"
    )

    return stats


def _save_setting(key, value):
    """Save a SystemSettings value."""
    try:
        from app import db
        from app.models import SystemSettings
        setting = SystemSettings.query.filter_by(key=key).first()
        if setting:
            setting.value = value
        else:
            setting = SystemSettings(
                key=key,
                value=value,
                category='sync',
                description=f'CPE dictionary sync setting: {key}'
            )
            db.session.add(setting)
        db.session.commit()
    except Exception:
        pass
