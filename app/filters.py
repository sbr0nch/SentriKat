from app import db
from app.models import Product, Vulnerability, VulnerabilityMatch
import re
import json

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

    # Try to get cached CPE data from vulnerability
    cpe_entries = vulnerability.get_cpe_entries()

    if cpe_entries:
        # Check against cached CPE data
        for entry in cpe_entries:
            entry_vendor = entry.get('vendor', '').lower()
            entry_product = entry.get('product', '').lower()

            if entry_vendor == cpe_vendor.lower() and entry_product == cpe_product.lower():
                # Check version range if available
                version = product.version
                has_version_range = entry.get('version_start') or entry.get('version_end')

                if has_version_range:
                    # CPE data has version constraints - verify product version
                    if version:
                        if _version_in_range(version,
                                             entry.get('version_start'),
                                             entry.get('version_end'),
                                             entry.get('version_start_type'),
                                             entry.get('version_end_type')):
                            # Version confirmed in vulnerable range - HIGH confidence
                            range_str = f"{entry.get('version_start', '*')} - {entry.get('version_end', '*')}"
                            return [f"CPE match: {cpe_vendor}:{cpe_product}:{version} (version {version} in range {range_str})"], 'cpe', 'high'
                        # Version NOT in vulnerable range - skip this entry
                        continue
                    else:
                        # Product has no version but CVE has version range
                        # MEDIUM confidence - can't verify if actually affected
                        range_str = f"{entry.get('version_start', '*')} - {entry.get('version_end', '*')}"
                        return [f"CPE match: {cpe_vendor}:{cpe_product} (version range {range_str}, product version unknown)"], 'cpe', 'medium'
                else:
                    # No version constraint - all versions affected
                    if version:
                        return [f"CPE match: {cpe_vendor}:{cpe_product}:{version} (all versions affected)"], 'cpe', 'high'
                    else:
                        return [f"CPE match: {cpe_vendor}:{cpe_product} (all versions affected)"], 'cpe', 'high'
    else:
        # No cached CPE data - try to match against CISA KEV vendor/product
        # Use STRICT word-boundary matching to prevent false positives
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
            return [f"CPE inference: {cpe_vendor}:{cpe_product}"], 'cpe', 'medium'

    return [], None, None


def _version_in_range(version, start, end, start_type, end_type):
    """
    Check if a version falls within a specified range.

    ENTERPRISE LOGIC:
    - If no version range specified (no start AND no end): Returns True (all versions affected)
    - If version range exists but product has no version: Returns False (can't verify, be conservative)
    - Otherwise: Check if version is within the specified range

    This prevents false positives by requiring version verification when CPE data has ranges.
    """
    # If no version range specified at all, all versions are affected
    if not start and not end:
        return True

    # If version range exists but product has no version, we can't verify - be conservative
    if not version:
        return False  # Changed from True - don't assume match without version proof

    version_key = _version_sort_key(version)

    if start:
        start_key = _version_sort_key(start)
        if start_type == 'including':
            if version_key < start_key:
                return False
        else:  # excluding
            if version_key <= start_key:
                return False

    if end:
        end_key = _version_sort_key(end)
        if end_type == 'including':
            if version_key > end_key:
                return False
        else:  # excluding
            if version_key >= end_key:
                return False

    return True


def _version_sort_key(version):
    """
    Generate a sortable key for version strings.
    Handles semver-like versions properly: 1.2.3, 10.1.18, etc.

    Key format: tuple of (type, value) pairs where:
    - type 0 = numeric (for proper numeric comparison)
    - type 1 = string (for alphabetic comparison)

    Examples:
    - "10.1.18" -> ((0,10), (0,1), (0,18))
    - "1.0.0-alpha" -> ((0,1), (0,0), (0,0), (1,'alpha'))
    """
    if not version:
        return tuple()

    parts = []
    # Split on common version delimiters
    for part in re.split(r'[.\-_+]', str(version)):
        if not part:
            continue
        # Try to convert to int for numeric comparison
        try:
            parts.append((0, int(part)))
        except ValueError:
            # Handle mixed alphanumeric like "18ubuntu1"
            # Split into numeric prefix and alpha suffix
            match = re.match(r'^(\d+)(.*)$', part)
            if match:
                parts.append((0, int(match.group(1))))
                if match.group(2):
                    parts.append((1, match.group(2).lower()))
            else:
                parts.append((1, part.lower()))
    return tuple(parts)


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

    # Product matching: check multiple variations
    def products_match(prod, vuln):
        if not prod or not vuln:
            return False
        # Direct containment (either direction)
        if prod in vuln or vuln in prod:
            return True
        # Word-level matching: check if vuln product appears as a word in product name
        # e.g., "firefox" should match "mozilla firefox"
        pattern = r'\b' + re.escape(vuln) + r'\b'
        if re.search(pattern, prod):
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
        # Determine confidence based on match type
        if any('Vendor+Product' in r for r in match_reasons):
            return match_reasons, 'vendor_product', 'medium'
        else:
            return match_reasons, 'keyword', 'low'

    return [], None, None


def check_match(vulnerability, product):
    """
    Check if a vulnerability matches a product.

    Respects the product's match_type setting:
    - auto: Use CPE if available, fallback to keyword
    - cpe: Only use CPE matching
    - keyword: Only use keyword matching
    - both: Use both CPE and keyword matching

    Returns:
        tuple: (match_reasons: list, match_method: str, match_confidence: str)
    """
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

    # Try CPE matching first
    if use_cpe:
        cpe_reasons, cpe_method, cpe_confidence = check_cpe_match(vulnerability, product)

    # Try keyword matching
    if use_keyword:
        # For 'auto' mode, only use keyword if CPE didn't match
        if match_type == 'auto' and cpe_reasons:
            pass  # Skip keyword matching, CPE matched
        else:
            keyword_reasons, keyword_method, keyword_confidence = check_keyword_match(vulnerability, product)

    # Combine results based on match_type
    if match_type == 'both':
        # Return CPE if matched, or keyword if matched, prefer CPE
        if cpe_reasons:
            return cpe_reasons, cpe_method, cpe_confidence
        elif keyword_reasons:
            return keyword_reasons, keyword_method, keyword_confidence
    elif match_type == 'cpe':
        return cpe_reasons, cpe_method, cpe_confidence
    elif match_type == 'keyword':
        return keyword_reasons, keyword_method, keyword_confidence
    else:  # auto
        # Prefer CPE matches (higher confidence)
        if cpe_reasons:
            return cpe_reasons, cpe_method, cpe_confidence
        elif keyword_reasons:
            return keyword_reasons, keyword_method, keyword_confidence

    return [], None, None

def match_vulnerabilities_to_products():
    """Match all active vulnerabilities against active products"""
    # Get all active products
    products = Product.query.filter_by(active=True).all()

    # Get all vulnerabilities
    vulnerabilities = Vulnerability.query.all()

    matches_count = 0

    for product in products:
        for vulnerability in vulnerabilities:
            match_reasons, match_method, match_confidence = check_match(vulnerability, product)

            if match_reasons:
                # Check if match already exists
                existing_match = VulnerabilityMatch.query.filter_by(
                    product_id=product.id,
                    vulnerability_id=vulnerability.id
                ).first()

                if not existing_match:
                    # Create new match
                    match = VulnerabilityMatch(
                        product_id=product.id,
                        vulnerability_id=vulnerability.id,
                        match_reason='; '.join(match_reasons),
                        match_method=match_method or 'keyword',
                        match_confidence=match_confidence or 'medium'
                    )
                    db.session.add(match)
                    matches_count += 1
                else:
                    # Update existing match with new method/confidence if different
                    if existing_match.match_method != match_method or existing_match.match_confidence != match_confidence:
                        existing_match.match_reason = '; '.join(match_reasons)
                        existing_match.match_method = match_method or 'keyword'
                        existing_match.match_confidence = match_confidence or 'medium'

    db.session.commit()
    return matches_count


def cleanup_invalid_matches():
    """
    Remove matches that no longer pass the matching criteria.
    Call this after updating matching logic to clean up stale data.
    Returns count of removed matches.
    """
    all_matches = VulnerabilityMatch.query.all()
    removed_count = 0

    for match in all_matches:
        product = match.product
        vulnerability = match.vulnerability

        # Skip if product or vulnerability was deleted
        if not product or not vulnerability:
            db.session.delete(match)
            removed_count += 1
            continue

        # Re-check if this match is still valid with current logic
        match_reasons, _, _ = check_match(vulnerability, product)

        if not match_reasons:
            # Match no longer valid - remove it
            db.session.delete(match)
            removed_count += 1

    db.session.commit()
    return removed_count


def rematch_all_products():
    """
    Full rematch: cleanup invalid matches then add new valid ones.
    Returns tuple of (removed_count, added_count).
    """
    removed = cleanup_invalid_matches()
    added = match_vulnerabilities_to_products()
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

    if filters:
        # Filter by organization - fetch IDs first
        if filters.get('organization_id'):
            org_product_ids = db.session.execute(
                select(product_organizations.c.product_id).where(
                    product_organizations.c.organization_id == filters['organization_id']
                )
            ).scalars().all()
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

    # Order by match creation date (newest first)
    query = query.order_by(VulnerabilityMatch.created_at.desc())

    return query.all()
