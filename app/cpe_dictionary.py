"""
Local CPE Dictionary - Offline CPE matching from vulnerability data.

Problem: SentriKat has only 379 static CPE mappings. When an agent reports
software like "Apache Tomcat" and it's not in the curated dictionary, we
fall back to the NVD API which is rate-limited (5 req/30s without key).

Solution: Every vulnerability in our database already contains CPE entries
(vendor:product pairs). We extract these into a searchable local dictionary.
This gives us CPE coverage for EVERY product mentioned in EVERY vulnerability
we've ever synced — thousands of entries, instantly, with zero API calls.

Example: CVE-2024-21762 affects cpe:2.3:a:fortinet:fortiproxy:*
  → We extract vendor="fortinet", product="fortiproxy"
  → We also store the vulnerability's human-readable names as search aliases
  → When an agent reports "Fortinet FortiProxy", we match locally

Architecture:
  - CpeDictionaryEntry model stores unique vendor:product pairs
  - build_cpe_dictionary() scans all Vulnerability.cpe_data and extracts entries
  - lookup_cpe_dictionary() provides fast matching for apply_cpe_to_product()
  - Scheduled to rebuild after each CISA KEV sync (daily)
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
    from app.models import CpeDictionaryEntry

    try:
        total = CpeDictionaryEntry.query.count()
        with_aliases = CpeDictionaryEntry.query.filter(
            CpeDictionaryEntry.search_aliases.isnot(None)
        ).count()
        top_used = CpeDictionaryEntry.query.filter(
            CpeDictionaryEntry.usage_count > 0
        ).count()

        return {
            'total_entries': total,
            'with_aliases': with_aliases,
            'used_for_matching': top_used,
        }
    except Exception:
        return {'total_entries': 0, 'with_aliases': 0, 'used_for_matching': 0}
