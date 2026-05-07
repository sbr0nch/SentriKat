import logging
import re
import json

from app import db
from app.models import Product, Vulnerability, VulnerabilityMatch, VendorFixOverride
from app.version_utils import _version_sort_key, _version_in_range, detect_version_format
from datetime import date

logger = logging.getLogger(__name__)

def normalize_string(s):
    """Normalize string for matching (lowercase, strip spaces)"""
    if not s:
        return ''
    return s.lower().strip()


def extract_core_product_name(product_name):
    """
    Extract the core product name by removing common suffixes.
    Examples:
        "Mozilla Firefox (x64 en-US)" -> "mozilla firefox"
        "7-Zip 25.01 (x64)" -> "7-zip"
        "Notepad++ (64-bit x64)" -> "notepad++"
        "Git" -> "git"
    """
    if not product_name:
        return ''

    name = product_name.lower().strip()

    # Handle vendor|product separators (e.g., "Dell | Command Update" -> "command update")
    # Many vendors use pipe as a brand separator; the part after the pipe is the real product name
    if '|' in name:
        parts = name.split('|', 1)
        name = parts[1].strip() if len(parts) > 1 and parts[1].strip() else name

    # Remove parenthetical suffixes (architecture, language, etc.)
    name = re.sub(r'\s*\([^)]*\)\s*$', '', name)

    # Remove version numbers at the end (e.g., "7-Zip 25.01" -> "7-Zip")
    name = re.sub(r'\s+[\d]+\.[\d]+.*$', '', name)

    # Remove common suffixes
    suffixes_to_remove = [
        ' x64', ' x86', ' 64-bit', ' 32-bit', ' edition',
        ' installer', ' setup', ' portable'
    ]
    for suffix in suffixes_to_remove:
        if name.endswith(suffix):
            name = name[:-len(suffix)]

    return name.strip()


def check_cpe_match(vulnerability, product):
    """
    Check if a vulnerability matches a product using CPE identifiers.

    Uses the vulnerability's cached CPE data to check against product's CPE identifiers.

    Returns:
        tuple: (match_reasons: list, match_method: str, match_confidence: str)
               - match_reasons: List of reasons for the match
               - match_method: 'cpe' if matched via CPE
               - match_confidence: 'high' for CPE matches
    """
    # Get product's effective CPE
    cpe_vendor, cpe_product, cpe_uri = product.get_effective_cpe()

    if not cpe_vendor or not cpe_product:
        return [], None, None

    # Determine product's CPE part type from its URI for cross-type filtering.
    # Installed software is almost always 'a' (application), never 'o' (OS).
    # This prevents OS-level CVEs from matching unrelated application products
    # (e.g., CVE-2008-0015 for Windows XP matching "Windows SDK EULA").
    product_cpe_part = None
    if cpe_uri and cpe_uri.startswith('cpe:2.3:'):
        uri_parts = cpe_uri.split(':')
        if len(uri_parts) > 2:
            product_cpe_part = uri_parts[2]  # 'a', 'o', or 'h'

    # Try to get cached CPE data from vulnerability
    cpe_entries = vulnerability.get_cpe_entries()

    if cpe_entries:
        # Separate matching entries into ranged, exact-version, and wildcard buckets.
        # Ranged/exact entries are MORE SPECIFIC than wildcards; if any exist for this
        # vendor:product, wildcard entries must be ignored — otherwise a wildcard
        # entry would match products whose version is OUTSIDE the affected range
        # (e.g., Chrome 145 being flagged for a CVE fixed in Chrome 72).
        version = (product.version or '').strip() or None

        # Detect distro-native version format from product ecosystem/OS so that
        # _version_in_range() uses dpkg/rpm/apk comparison instead of generic.
        version_format = detect_version_format(
            getattr(product, 'ecosystem', None) or '',
            # ProductInstallation.detected_on_os isn't directly on Product,
            # but ecosystem captures the same info (e.g. 'debian', 'rhel')
        )

        ranged_entries = []
        exact_entries = []
        wildcard_entries = []

        for entry in cpe_entries:
            entry_vendor = entry.get('vendor', '').lower()
            entry_product = entry.get('product', '').lower()

            if entry_vendor != cpe_vendor.lower() or entry_product != cpe_product.lower():
                continue

            # Cross-type filter: skip OS-level CVE entries for application products.
            # An application (cpe:2.3:a:) should not match OS vulnerabilities (cpe:2.3:o:).
            if product_cpe_part == 'a':
                entry_cpe_part = entry.get('cpe_part')
                if not entry_cpe_part:
                    entry_uri = entry.get('cpe_uri', '')
                    if entry_uri.startswith('cpe:2.3:'):
                        entry_uri_parts = entry_uri.split(':')
                        if len(entry_uri_parts) > 2:
                            entry_cpe_part = entry_uri_parts[2]
                if entry_cpe_part == 'o':
                    continue

            has_version_range = entry.get('version_start') or entry.get('version_end')
            exact_ver = entry.get('exact_version')

            if has_version_range:
                ranged_entries.append(entry)
            elif exact_ver:
                exact_entries.append(entry)
            else:
                wildcard_entries.append(entry)

        # Priority 1: Check version-ranged entries (most authoritative)
        if ranged_entries:
            for entry in ranged_entries:
                if version:
                    if _version_in_range(version,
                                         entry.get('version_start'),
                                         entry.get('version_end'),
                                         entry.get('version_start_type'),
                                         entry.get('version_end_type'),
                                         version_format=version_format):
                        range_str = f"{entry.get('version_start', '*')} - {entry.get('version_end', '*')}"
                        return [f"CPE match: {cpe_vendor}:{cpe_product}:{version} (version {version} in range {range_str})"], 'cpe', 'high'
                    # Version NOT in this range - continue checking other ranges
                else:
                    # Product has no version but CVE has version range
                    range_str = f"{entry.get('version_start', '*')} - {entry.get('version_end', '*')}"
                    return [f"CPE match: {cpe_vendor}:{cpe_product} (version range {range_str}, product version unknown)"], 'cpe', 'medium'
            # If we get here with version-ranged entries, the installed version is
            # NOT in ANY affected range — this product is NOT vulnerable.
            # Do NOT fall through to wildcard entries.
            if version:
                return [], None, None

        # Priority 2: Check exact-version entries
        if exact_entries:
            for entry in exact_entries:
                exact_ver = entry.get('exact_version')
                if version and version.strip() == exact_ver.strip():
                    return [f"CPE match: {cpe_vendor}:{cpe_product}:{version} (exact version match)"], 'cpe', 'high'
                elif not version:
                    return [f"CPE match: {cpe_vendor}:{cpe_product} (exact version {exact_ver}, product version unknown)"], 'cpe', 'medium'
            # Installed version doesn't match any exact affected version.
            # If ranged entries also existed (handled above), we already returned.
            # If only exact entries exist, not matching any means not vulnerable.
            if version:
                return [], None, None

        # Priority 3: Wildcard entries — ONLY used if no ranged/exact entries exist.
        # If the product has a specific version, wildcard entries are unreliable:
        # they usually mean NVD hasn't detailed the affected versions, NOT that
        # all versions are truly vulnerable. Skip to avoid massive false positives.
        if wildcard_entries:
            if not version:
                return [f"CPE match: {cpe_vendor}:{cpe_product} (all versions affected)"], 'cpe', 'medium'
            # Product has a version but CVE only has wildcard CPE — skip.
            # The match will be created if/when NVD adds precise version ranges.
            return [], None, None
    else:
        # No cached CPE data from NVD for this vulnerability.
        # Three scenarios:
        # 1. cpe_fetched_at is set + NVD completed analysis → no CPE data exists (authoritative)
        # 2. cpe_fetched_at is None → NVD hasn't been queried yet
        # 3. NVD status is "Awaiting Analysis" → NVD hasn't analyzed yet (NOT authoritative)
        #
        # CRITICAL: For scenario 1, NVD is authoritative — don't match.
        # For scenarios 2 & 3, NVD can't tell us anything yet, so we fall back
        # to vendor/product text matching to give early visibility.

        # Detect if NVD analysis is still pending (not authoritative)
        nvd_pending = getattr(vulnerability, 'nvd_status', None) in (
            'Awaiting Analysis', 'Received', 'Undergoing Analysis'
        )

        if vulnerability.cpe_fetched_at and not nvd_pending:
            # NVD was queried AND completed analysis — no CPE data exists.
            # Don't fall back to text matching; NVD is authoritative.
            return [], None, None

        if product.version:
            # Product has a specific version but no CPE data to verify ranges.
            # Skip — text matching without version verification causes massive
            # false positives. The match will be created once NVD adds CPE data.
            return [], None, None

        # Fall back to text matching for:
        # - CVEs where NVD hasn't been queried yet
        # - CVEs where NVD analysis is pending (Awaiting Analysis)
        # Use STRICT word-boundary matching to prevent false positives.
        vuln_vendor = normalize_string(vulnerability.vendor_project)
        vuln_product = normalize_string(vulnerability.product)

        # CPE names are typically lowercase with underscores instead of spaces
        normalized_cpe_vendor = cpe_vendor.lower().replace('_', ' ')
        normalized_cpe_product = cpe_product.lower().replace('_', ' ')

        def is_word_match(word, text):
            """Check if word appears as complete word(s) in text using word boundaries."""
            if not word or not text:
                return False
            if word == text:
                return True
            # Word boundary matching
            pattern = r'(?:^|[\s_\-])' + re.escape(word) + r'(?:[\s_\-]|$)'
            return bool(re.search(pattern, text, re.IGNORECASE))

        # Check if CPE vendor/product matches vulnerability vendor/product using word boundaries
        vendor_match = is_word_match(normalized_cpe_vendor, vuln_vendor) or is_word_match(vuln_vendor, normalized_cpe_vendor)
        product_match = is_word_match(normalized_cpe_product, vuln_product) or is_word_match(vuln_product, normalized_cpe_product)

        if vendor_match and product_match:
            if nvd_pending:
                return [f"CPE inference: {cpe_vendor}:{cpe_product} (NVD analysis pending — version not yet verified)"], 'cpe', 'medium'
            return [f"CPE inference: {cpe_vendor}:{cpe_product} (NVD version data pending)"], 'cpe', 'medium'

    return [], None, None


def check_keyword_match(vulnerability, product):
    """
    Check if a vulnerability matches a product using keyword/vendor/product matching.

    Matching logic:
    - Vendor matching: bidirectional (either contains the other)
    - Product matching: uses core product name extraction for better matching
    - Keywords provide additional matches

    Returns:
        tuple: (match_reasons: list, match_method: str, match_confidence: str)
    """
    vuln_vendor = normalize_string(vulnerability.vendor_project)
    vuln_product = normalize_string(vulnerability.product)

    prod_vendor = normalize_string(product.vendor)
    prod_name = normalize_string(product.product_name)

    # Extract core product name (removes "(x64 en-US)", version numbers, etc.)
    prod_name_core = extract_core_product_name(product.product_name)

    # Get additional keywords
    keywords = []
    if product.keywords:
        keywords = [normalize_string(k.strip()) for k in product.keywords.split(',')]

    match_reasons = []

    # Vendor matching: STRICT word-boundary matching to prevent false positives
    # e.g., "sun" should NOT match "samsung", but "apache" matches "apache software foundation"
    def vendors_match(v1, v2):
        if not v1 or not v2:
            return False

        # Exact match first
        if v1 == v2:
            return True

        # Normalize for comparison (handle underscores, hyphens)
        v1_normalized = v1.replace('_', ' ').replace('-', ' ')
        v2_normalized = v2.replace('_', ' ').replace('-', ' ')

        if v1_normalized == v2_normalized:
            return True

        # Word boundary matching - vendor must appear as complete word(s)
        # This prevents "sun" matching "samsung" but allows "apache" in "apache software foundation"
        def is_word_in_text(word, text):
            """Check if word appears as complete word(s) in text."""
            # Create pattern that matches word as whole word or at word boundaries
            pattern = r'(?:^|[\s_\-])' + re.escape(word) + r'(?:[\s_\-]|$)'
            return bool(re.search(pattern, text, re.IGNORECASE))

        # Check both directions but require word boundaries
        return is_word_in_text(v1_normalized, v2_normalized) or is_word_in_text(v2_normalized, v1_normalized)

    # Product matching: use word-boundary matching with length checks
    # to prevent false positives from generic words in longer product names
    # (e.g., "windows" should NOT match "windows desktop targeting pack")
    def products_match(prod, vuln):
        if not prod or not vuln:
            return False
        if prod == vuln:
            return True

        # Strip vendor prefix from product name for tighter comparison
        # "microsoft windows desktop targeting pack" → "windows desktop targeting pack"
        prod_no_vendor = prod
        for vendor in [vuln_vendor, prod_vendor]:
            if vendor and prod.startswith(vendor + ' '):
                prod_no_vendor = prod[len(vendor) + 1:]
                break

        # Exact match after vendor removal
        if prod_no_vendor == vuln:
            return True

        # Word-boundary matching with word-count guard:
        # The vuln product must appear as a whole word AND the product name
        # (after removing vendor) must not have too many extra words.
        # This prevents "windows" matching "windows desktop targeting pack"
        # but allows "sql server" matching "sql server 2012" (+1 extra word).
        vuln_words = [w for w in vuln.split() if len(w) >= 2]
        prod_core_words = [w for w in prod_no_vendor.split() if len(w) >= 2]

        vuln_pattern = r'\b' + re.escape(vuln) + r'\b'
        if re.search(vuln_pattern, prod_no_vendor):
            if len(prod_core_words) <= len(vuln_words) + 2:
                return True

        # Reverse: product name (without vendor) found as whole word in vuln product
        if len(prod_no_vendor) >= 3:
            prod_pattern = r'\b' + re.escape(prod_no_vendor) + r'\b'
            if re.search(prod_pattern, vuln):
                return True

        return False

    # Strict matching: if both vendor AND product are specified, BOTH must match
    if prod_vendor and prod_name:
        vendor_matches = vendors_match(prod_vendor, vuln_vendor)

        # Try matching with both full name and core name
        product_matches = (
            products_match(prod_name, vuln_product) or
            products_match(prod_name_core, vuln_product)
        )

        if vendor_matches and product_matches:
            match_reasons.append(f"Vendor+Product match: {product.vendor} - {product.product_name}")

    # If only vendor specified (no product name), match vendor alone
    elif prod_vendor and not prod_name:
        if vendors_match(prod_vendor, vuln_vendor):
            match_reasons.append(f"Vendor match: {product.vendor}")

    # If only product name specified (no vendor), match product alone
    elif prod_name and not prod_vendor:
        if products_match(prod_name, vuln_product) or products_match(prod_name_core, vuln_product):
            match_reasons.append(f"Product match: {product.product_name}")

    # Keywords provide additional matching (should be specific like "http server")
    # Keywords must match as whole words, not substrings
    for keyword in keywords:
        if keyword and len(keyword) >= 3:  # Minimum 3 chars to avoid too broad matches
            pattern = r'\b' + re.escape(keyword) + r'\b'
            if re.search(pattern, vuln_product):
                match_reasons.append(f"Keyword match: {keyword}")

    if match_reasons:
        # [CVE-MATCHING-PIPELINE F.6] Confidence reflects how much we VERIFIED:
        # - 'vendor_product' as 'medium' is accurate ONLY when the vulnerability
        #   carries cpe_data (so the version range / wildcard scope was at least
        #   knowable upstream — we just chose to fall back here because the
        #   product had no CPE assigned). When cpe_data is NULL the keyword
        #   match never had a chance to verify the version, and historically
        #   (the 'Chrome 147 ↔ CVE-2010' regression on 2026-05-05) it produced
        #   massive false positives. Demote those to 'low' so default
        #   dashboards / counters can filter them out without losing them.
        # - 'keyword' (no vendor+product structural match, just a keyword
        #   substring) stays 'low' as before.
        verified_via_cpe_data = bool(getattr(vulnerability, 'cpe_data', None)) and vulnerability.cpe_data != '[]'
        if any('Vendor+Product' in r for r in match_reasons):
            confidence = 'medium' if verified_via_cpe_data else 'low'
            return match_reasons, 'vendor_product', confidence
        else:
            return match_reasons, 'keyword', 'low'

    return [], None, None


def has_vendor_fix_override(vulnerability, product):
    """
    Check if an approved vendor fix override exists for this CVE + product version.

    This handles "Path B" — when a vendor patches a version in-place (e.g., backport fix)
    but the NVD CPE data still lists that version as affected.

    Returns:
        VendorFixOverride or None
    """
    if not vulnerability.cve_id or not product.version:
        return None

    try:
        from sqlalchemy import func
        override = VendorFixOverride.query.filter(
            VendorFixOverride.cve_id == vulnerability.cve_id,
            func.lower(VendorFixOverride.vendor) == normalize_string(product.vendor),
            func.lower(VendorFixOverride.product) == normalize_string(product.product_name),
            VendorFixOverride.fixed_version == product.version,
            VendorFixOverride.status == 'approved'
        ).first()

        if not override:
            # Also try matching via CPE vendor/product names
            cpe_vendor, cpe_product, _ = product.get_effective_cpe()
            if cpe_vendor and cpe_product:
                override = VendorFixOverride.query.filter(
                    VendorFixOverride.cve_id == vulnerability.cve_id,
                    func.lower(VendorFixOverride.vendor) == cpe_vendor.lower(),
                    func.lower(VendorFixOverride.product) == cpe_product.lower(),
                    VendorFixOverride.fixed_version == product.version,
                    VendorFixOverride.status == 'approved'
                ).first()

        return override
    except Exception as e:
        # A.1 fix (audit 2026-05-06): suppression layer silent failure was
        # masking VendorFixOverride lookup errors. Now logged so ops sees
        # transient DB issues. Returning None still errs on side of "show
        # match" — better a visible false positive than missed suppression.
        logger.warning(
            f"VendorFixOverride lookup failed for cve={vulnerability.cve_id} "
            f"product_id={product.id}: {type(e).__name__}: {e}"
        )
        return None


def _has_active_risk_exception(vulnerability, product):
    """
    Check if there's an active RiskException that suppresses this CVE/product match.

    Priority order (most specific wins):
      1. Asset-specific: exception where product_id == product.id (scoped to any
         org that owns this product).
      2. Wildcard: exception where product_id IS NULL, scoped to any org that
         owns this product (applies org-wide to all products with that CVE).

    An exception is considered active when:
      - status == 'active'
      - expires_at is NULL (permanent) OR expires_at >= today

    Note: check_match() is org-agnostic (VulnerabilityMatch rows are shared
    across all orgs that own a product). We therefore suppress the match if
    ANY org owning this product has an active exception for the CVE. In
    practice most deployments are single-tenant-per-product, so this matches
    the operator's intent. Multi-tenant product sharing is rare.
    """
    if not vulnerability.cve_id or not product:
        return False

    try:
        from app.models import RiskException, product_organizations
        from sqlalchemy import select, or_, and_

        # Collect all org ids that own this product (M2M + legacy FK)
        org_ids = set()
        m2m_rows = db.session.execute(
            select(product_organizations.c.organization_id).where(
                product_organizations.c.product_id == product.id
            )
        ).scalars().all()
        org_ids.update(m2m_rows)
        if getattr(product, 'organization_id', None):
            org_ids.add(product.organization_id)

        if not org_ids:
            return False

        today = date.today()
        active_filter = and_(
            RiskException.status == 'active',
            or_(
                RiskException.expires_at.is_(None),
                RiskException.expires_at >= today,
            ),
        )

        # 1) Asset-specific (most restrictive) — product_id exactly matches.
        specific = RiskException.query.filter(
            RiskException.organization_id.in_(org_ids),
            RiskException.cve_id == vulnerability.cve_id,
            RiskException.product_id == product.id,
            active_filter,
        ).first()
        if specific:
            logger.debug(
                "RiskException id=%d suppressed %s for product id=%d (%s %s) "
                "[product-specific, org_id=%d, expires=%s]",
                specific.id, vulnerability.cve_id, product.id,
                product.vendor, product.product_name,
                specific.organization_id,
                specific.expires_at or 'permanent',
            )
            return True

        # 2) Wildcard — org-wide exception for this CVE (product_id IS NULL).
        wildcard = RiskException.query.filter(
            RiskException.organization_id.in_(org_ids),
            RiskException.cve_id == vulnerability.cve_id,
            RiskException.product_id.is_(None),
            active_filter,
        ).first()
        if wildcard:
            logger.debug(
                "RiskException id=%d suppressed %s for product id=%d (%s %s) "
                "[wildcard/org-wide, org_id=%d, expires=%s]",
                wildcard.id, vulnerability.cve_id, product.id,
                product.vendor, product.product_name,
                wildcard.organization_id,
                wildcard.expires_at or 'permanent',
            )
            return True
        return False
    except Exception as e:
        # Fail-open: never crash match evaluation because of an exception
        # lookup error. Correctness here is best-effort; the worst case is
        # showing a CVE that should have been suppressed, which is strictly
        # safer than silently suppressing a real vuln.
        # A.1 fix (audit 2026-05-06): added logger so transient DB issues
        # surface in ops logs instead of being completely silent.
        logger.warning(
            f"RiskException lookup failed for cve={vulnerability.cve_id} "
            f"product_id={product.id}: {type(e).__name__}: {e}"
        )
        return False


def check_match(vulnerability, product):
    """
    Check if a vulnerability matches a product.

    Respects the product's match_type setting:
    - auto: Use CPE if available, fallback to keyword ONLY if product has no CPE
    - cpe: Only use CPE matching
    - keyword: Only use keyword matching
    - both: Use both CPE and keyword matching

    Also checks for vendor fix overrides (Path B: in-place patches).
    If an approved override exists, the match is suppressed.

    Risk Exceptions: if an active, non-expired RiskException exists for this
    CVE and either (a) the exact product (asset-specific, highest priority) or
    (b) org-wide (product_id IS NULL, wildcard), the match is suppressed and
    the function returns ([], None, None). Call sites already treat an empty
    reasons list as "no match" (see match_vulnerabilities_to_products and
    cleanup_invalid_matches), so no call-site changes are required.

    Returns:
        tuple: (match_reasons: list, match_method: str, match_confidence: str)
    """
    # Skip products tagged as not security relevant (noise: Windows updates,
    # language packs, ADK tools, etc.). These should never get CVE matches.
    cpe_vendor, cpe_product, _ = product.get_effective_cpe()
    if cpe_vendor == '_skip' or cpe_product == '_not_security_relevant':
        return [], None, None

    # Skip browser/IDE extensions — they don't have CVEs in NVD.
    # Their vendor (e.g., "Chrome Web Store") would false-match against
    # the browser's own CVEs (Google Chrome).
    if getattr(product, 'source_type', None) == 'extension':
        return [], None, None

    # Skip products without a version — impossible to verify if affected.
    # Matching without version produces massive false positives (e.g.,
    # Chrome with no version matches ALL Chrome CVEs ever published).
    if not product.version or not product.version.strip():
        return [], None, None

    match_type = product.match_type or 'auto'

    # Determine which matching methods to use
    use_cpe = match_type in ('auto', 'cpe', 'both')
    use_keyword = match_type in ('auto', 'keyword', 'both')

    cpe_reasons = []
    cpe_method = None
    cpe_confidence = None

    keyword_reasons = []
    keyword_method = None
    keyword_confidence = None

    # Check if product has CPE configured (for auto mode logic)
    product_has_cpe = bool(cpe_vendor and cpe_product)

    # Try CPE matching first
    if use_cpe:
        cpe_reasons, cpe_method, cpe_confidence = check_cpe_match(vulnerability, product)

    # Try keyword matching
    if use_keyword:
        if match_type == 'auto':
            # In 'auto' mode: when the product has a CPE, CPE is authoritative
            # ONLY IF the vulnerability has been NVD-enriched (cpe_data populated).
            # When cpe_data is NULL the CPE is not "authoritative says no", it is
            # "CPE missing because enrichment hasn't run yet". Falling back to
            # keyword matching here recovers the ~65% of CVEs that haven't been
            # enriched (see bug [03.14.32]).
            #
            # Behaviour for CVEs WITH cpe_data is unchanged: CPE result stands
            # (no false positives introduced).
            #
            # Products WITHOUT CPE always use keyword (legacy behaviour).
            if not product_has_cpe:
                keyword_reasons, keyword_method, keyword_confidence = check_keyword_match(vulnerability, product)
            elif not vulnerability.cpe_data:
                # CPE missing on the vulnerability → fall back to keyword
                keyword_reasons, keyword_method, keyword_confidence = check_keyword_match(vulnerability, product)
        elif cpe_reasons:
            pass  # Skip keyword matching, CPE matched
        else:
            keyword_reasons, keyword_method, keyword_confidence = check_keyword_match(vulnerability, product)

    # Determine the result
    result_reasons = []
    result_method = None
    result_confidence = None

    if match_type == 'both':
        if cpe_reasons:
            result_reasons, result_method, result_confidence = cpe_reasons, cpe_method, cpe_confidence
        elif keyword_reasons:
            result_reasons, result_method, result_confidence = keyword_reasons, keyword_method, keyword_confidence
    elif match_type == 'cpe':
        result_reasons, result_method, result_confidence = cpe_reasons, cpe_method, cpe_confidence
    elif match_type == 'keyword':
        result_reasons, result_method, result_confidence = keyword_reasons, keyword_method, keyword_confidence
    else:  # auto
        if cpe_reasons:
            result_reasons, result_method, result_confidence = cpe_reasons, cpe_method, cpe_confidence
        elif keyword_reasons:
            result_reasons, result_method, result_confidence = keyword_reasons, keyword_method, keyword_confidence

    # Check for vendor fix override (Path B: in-place vendor patch)
    # If a match was found but an approved override exists, suppress it
    if result_reasons and has_vendor_fix_override(vulnerability, product):
        return [], None, None

    # Check for active RiskException — if the org has formally accepted this
    # risk, suppress the match so it doesn't reappear in counts/reports.
    if result_reasons and _has_active_risk_exception(vulnerability, product):
        return [], None, None

    return result_reasons, result_method, result_confidence

def match_vulnerabilities_to_products(target_products=None, target_vulnerabilities=None):
    """Match vulnerabilities against products.

    Args:
        target_products: Optional list of Product objects to match against.
                         If None, matches all active products.
        target_vulnerabilities: Optional list of Vulnerability objects to check.
                                If None, matches all vulnerabilities.
                                Pass newly-imported vulnerabilities from sync
                                jobs to avoid rechecking the entire DB.
    """
    # Get products to match
    if target_products:
        products = target_products
    else:
        products = Product.query.filter_by(active=True).all()

    # Get vulnerabilities to match
    if target_vulnerabilities:
        vulnerabilities = target_vulnerabilities
    else:
        vulnerabilities = Vulnerability.query.all()

    matches_count = 0

    # Pre-load all existing matches into a set for O(1) lookup.
    # This eliminates the N+1 query problem (was: one DB query per P×V pair).
    product_ids = [p.id for p in products]
    vuln_ids = [v.id for v in vulnerabilities]

    existing_matches_query = VulnerabilityMatch.query
    if product_ids and vuln_ids:
        existing_matches_query = existing_matches_query.filter(
            VulnerabilityMatch.product_id.in_(product_ids),
            VulnerabilityMatch.vulnerability_id.in_(vuln_ids)
        )
    existing_match_set = set()
    existing_match_map = {}
    for m in existing_matches_query.all():
        key = (m.product_id, m.vulnerability_id)
        existing_match_set.add(key)
        existing_match_map[key] = m

    batch_size = 50
    pending = 0

    for product in products:
        for vulnerability in vulnerabilities:
            match_reasons, match_method, match_confidence = check_match(vulnerability, product)

            if match_reasons:
                key = (product.id, vulnerability.id)

                if key not in existing_match_set:
                    # Create new match
                    match = VulnerabilityMatch(
                        product_id=product.id,
                        vulnerability_id=vulnerability.id,
                        match_reason='; '.join(match_reasons),
                        match_method=match_method or 'keyword',
                        match_confidence=match_confidence or 'medium'
                    )
                    db.session.add(match)
                    existing_match_set.add(key)
                    matches_count += 1
                    pending += 1

                    # Forward new match to SIEM if configured
                    try:
                        from app.reports_api import send_syslog_event
                        send_syslog_event(
                            event_type='new_vulnerability',
                            cve_id=vulnerability.cve_id,
                            severity=vulnerability.severity or 'MEDIUM',
                            product=f"{product.vendor} {product.product_name}",
                            message=vulnerability.short_description or vulnerability.vulnerability_name or '',
                            vendor=product.vendor or '',
                            due_date=str(vulnerability.due_date) if vulnerability.due_date else '',
                            ransomware=bool(vulnerability.known_ransomware),
                        )
                    except Exception:
                        pass  # SIEM forwarding is best-effort, never block matching
                else:
                    # Update existing match with new method/confidence if different
                    existing_match = existing_match_map.get(key)
                    if existing_match and (existing_match.match_method != match_method or existing_match.match_confidence != match_confidence):
                        existing_match.match_reason = '; '.join(match_reasons)
                        existing_match.match_method = match_method or 'keyword'
                        existing_match.match_confidence = match_confidence or 'medium'
                        pending += 1

            # Batch commit to reduce lock contention
            if pending >= batch_size:
                db.session.flush()
                pending = 0

    db.session.commit()
    return matches_count


def cleanup_invalid_matches():
    """
    Remove matches that no longer pass the matching criteria.
    This is critical for correctness when NVD CPE version ranges change
    (e.g., vendor releases cumulative update narrowing the affected range).
    Returns count of removed matches.
    """
    import logging
    logger = logging.getLogger(__name__)
    from sqlalchemy.orm import selectinload

    # Re-tag products that are now in the skip list but were mapped before
    # the skip pattern was added. Without this, cleanup_invalid_matches
    # can't catch false positives from newly-added skip patterns.
    from app.agent_api import _should_skip_software
    retagged = 0
    for product in Product.query.filter(
        Product.cpe_vendor.isnot(None),
        Product.cpe_vendor != '_skip'
    ).all():
        if _should_skip_software(product.vendor, product.product_name):
            product.cpe_vendor = '_skip'
            product.cpe_product = '_not_security_relevant'
            retagged += 1
    if retagged:
        db.session.flush()
        logger.info(f"Re-tagged {retagged} products as not-security-relevant (updated skip list)")

    # Process matches in batches to avoid loading entire table into memory.
    # Uses keyset pagination (id > last_id) which is safe even when rows are deleted.
    batch_size = 500
    last_id = 0
    removed_count = 0

    while True:
        batch = VulnerabilityMatch.query.options(
            selectinload(VulnerabilityMatch.product),
            selectinload(VulnerabilityMatch.vulnerability)
        ).filter(
            VulnerabilityMatch.id > last_id
        ).order_by(VulnerabilityMatch.id).limit(batch_size).all()

        if not batch:
            break

        last_id = batch[-1].id

        for match in batch:
            product = match.product
            vulnerability = match.vulnerability

            # Skip if product or vulnerability was deleted
            if not product or not vulnerability:
                db.session.delete(match)
                removed_count += 1
                continue

            # Skip inactive products - don't evaluate matches for disabled products
            if not product.active:
                continue

            # Re-check if this match is still valid with current logic
            match_reasons, new_method, new_confidence = check_match(vulnerability, product)

            if not match_reasons:
                # Match no longer valid - remove it
                if match.acknowledged:
                    logger.info(
                        "Removing previously-acknowledged match %s <-> %s %s %s "
                        "(no longer in affected version range)",
                        vulnerability.cve_id, product.vendor,
                        product.product_name, product.version or 'Any'
                    )
                db.session.delete(match)
                removed_count += 1
            else:
                # Match still valid — update confidence/method if NVD data
                # has matured (e.g., medium→high when NVD completes analysis)
                if new_method and new_confidence:
                    if match.match_confidence != new_confidence or match.match_method != new_method:
                        match.match_confidence = new_confidence
                        match.match_method = new_method
                        match.match_reason = '; '.join(match_reasons)

        db.session.flush()

    db.session.commit()
    return removed_count


def rematch_all_products(target_vulnerabilities=None):
    """
    Full rematch: cleanup invalid matches then add new valid ones.

    Args:
        target_vulnerabilities: Optional list of Vulnerability objects.
                                If provided, only these vulnerabilities are
                                matched (faster for incremental sync jobs).
                                Cleanup still runs against ALL matches.

    Returns tuple of (removed_count, added_count).
    """
    removed = cleanup_invalid_matches()
    added = match_vulnerabilities_to_products(target_vulnerabilities=target_vulnerabilities)
    return removed, added

def get_filtered_vulnerabilities(filters=None):
    """Get vulnerabilities filtered by various criteria"""
    from app.models import product_organizations
    from sqlalchemy.orm import selectinload
    from sqlalchemy import select

    # Build base query - NO joins to avoid column mapping issues
    # Use selectinload for eager loading in separate queries
    query = db.session.query(VulnerabilityMatch).options(
        selectinload(VulnerabilityMatch.product),
        selectinload(VulnerabilityMatch.vulnerability)
    )

    # Exclude matches for inactive products (disabled by admin or auto-disabled)
    active_product_ids = db.session.execute(
        select(Product.id).where(Product.active == True)
    ).scalars().all()
    if active_product_ids:
        query = query.filter(VulnerabilityMatch.product_id.in_(active_product_ids))
    else:
        return []

    if filters:
        # Filter by organization - combine many-to-many AND legacy FK
        if filters.get('organization_id'):
            org_id = filters['organization_id']
            # Many-to-many assignments
            m2m_ids = db.session.execute(
                select(product_organizations.c.product_id).where(
                    product_organizations.c.organization_id == org_id
                )
            ).scalars().all()
            # Legacy FK assignments
            legacy_ids = [p.id for p in Product.query.filter_by(organization_id=org_id).all()]
            org_product_ids = list(set(m2m_ids + legacy_ids))
            if org_product_ids:
                query = query.filter(VulnerabilityMatch.product_id.in_(org_product_ids))
            else:
                return []

        # Filter by product ID
        if filters.get('product_id'):
            query = query.filter(VulnerabilityMatch.product_id == filters['product_id'])

        # Filter by CVE ID - fetch matching vuln IDs first, NO join
        if filters.get('cve_id'):
            vuln_ids = db.session.execute(
                select(Vulnerability.id).where(
                    Vulnerability.cve_id.ilike(f"%{filters['cve_id']}%")
                )
            ).scalars().all()
            if vuln_ids:
                query = query.filter(VulnerabilityMatch.vulnerability_id.in_(vuln_ids))
            else:
                return []

        # Filter by vendor - fetch matching vuln IDs first
        if filters.get('vendor'):
            vendor_vuln_ids = db.session.execute(
                select(Vulnerability.id).where(
                    Vulnerability.vendor_project.ilike(f"%{filters['vendor']}%")
                )
            ).scalars().all()
            if vendor_vuln_ids:
                query = query.filter(VulnerabilityMatch.vulnerability_id.in_(vendor_vuln_ids))
            else:
                return []

        # Filter by product name in vulnerability
        if filters.get('product'):
            product_vuln_ids = db.session.execute(
                select(Vulnerability.id).where(
                    Vulnerability.product.ilike(f"%{filters['product']}%")
                )
            ).scalars().all()
            if product_vuln_ids:
                query = query.filter(VulnerabilityMatch.vulnerability_id.in_(product_vuln_ids))
            else:
                return []

        # Filter by ransomware
        if filters.get('ransomware_only'):
            ransomware_vuln_ids = db.session.execute(
                select(Vulnerability.id).where(Vulnerability.known_ransomware == True)
            ).scalars().all()
            if ransomware_vuln_ids:
                query = query.filter(VulnerabilityMatch.vulnerability_id.in_(ransomware_vuln_ids))
            else:
                return []

        # Filter by acknowledged status
        if filters.get('acknowledged') is not None:
            query = query.filter(VulnerabilityMatch.acknowledged == filters['acknowledged'])

        # Filter by source key type (server/client) - only show matches for products
        # reported by the specified key type
        if filters.get('source_key_type') in ('server', 'client'):
            key_type_product_ids = db.session.execute(
                select(Product.id).where(
                    Product.source_key_type == filters['source_key_type']
                )
            ).scalars().all()
            if key_type_product_ids:
                query = query.filter(VulnerabilityMatch.product_id.in_(key_type_product_ids))
            else:
                return []

        # Filter by source type (os_package, extension, code_library)
        if filters.get('source_type'):
            st_product_ids = db.session.execute(
                select(Product.id).where(
                    Product.source_type == filters['source_type']
                )
            ).scalars().all()
            if st_product_ids:
                query = query.filter(VulnerabilityMatch.product_id.in_(st_product_ids))
            else:
                return []

        # Filter by multiple source types (e.g., code_library + extension)
        if filters.get('source_types'):
            st_product_ids = db.session.execute(
                select(Product.id).where(
                    Product.source_type.in_(filters['source_types'])
                )
            ).scalars().all()
            if st_product_ids:
                query = query.filter(VulnerabilityMatch.product_id.in_(st_product_ids))
            else:
                return []

    # Order by match creation date (newest first)
    query = query.order_by(VulnerabilityMatch.created_at.desc())

    results = query.all()

    # [09.X.3] Suppress matches covered by an active RiskException so the
    # dashboard reflects the action immediately (without waiting for the
    # next sync to recompute matches via match_vulnerabilities_to_products).
    # _has_active_risk_exception is the same helper used during sync.
    if results:
        results = [m for m in results if not _has_active_risk_exception(m.vulnerability, m.product)]

    return results
