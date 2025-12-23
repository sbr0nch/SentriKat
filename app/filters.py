from app import db
from app.models import Product, Vulnerability, VulnerabilityMatch

def normalize_string(s):
    """Normalize string for matching (lowercase, strip spaces)"""
    if not s:
        return ''
    return s.lower().strip()

def check_match(vulnerability, product):
    """
    Check if a vulnerability matches a product.

    Matching logic (strict by default):
    - If BOTH vendor AND product_name are specified: BOTH must match
    - If only vendor is specified: vendor must match (use with caution)
    - If only product_name is specified: product_name must match
    - Keywords provide additional matches but should be specific
    """
    vuln_vendor = normalize_string(vulnerability.vendor_project)
    vuln_product = normalize_string(vulnerability.product)

    prod_vendor = normalize_string(product.vendor)
    prod_name = normalize_string(product.product_name)

    # Get additional keywords
    keywords = []
    if product.keywords:
        keywords = [normalize_string(k.strip()) for k in product.keywords.split(',')]

    match_reasons = []

    # Strict matching: if both vendor AND product are specified, BOTH must match
    if prod_vendor and prod_name:
        vendor_matches = prod_vendor in vuln_vendor
        # Product matches if either contains the other (handles "HTTP Server" vs "Apache HTTP Server")
        # Only compare product names, not cross-check with vendor
        product_matches = prod_name in vuln_product or vuln_product in prod_name

        if vendor_matches and product_matches:
            match_reasons.append(f"Vendor+Product match: {product.vendor} - {product.product_name}")

    # If only vendor specified (no product name), match vendor alone
    elif prod_vendor and not prod_name:
        if prod_vendor in vuln_vendor:
            match_reasons.append(f"Vendor match: {product.vendor}")

    # If only product name specified (no vendor), match product alone
    elif prod_name and not prod_vendor:
        if prod_name in vuln_product:
            match_reasons.append(f"Product match: {product.product_name}")

    # Keywords provide additional matching (should be specific like "http server")
    # Keywords must match as whole words, not substrings (e.g., "httpd" should NOT match "nhttpd")
    import re
    for keyword in keywords:
        if keyword and len(keyword) >= 3:  # Minimum 3 chars to avoid too broad matches
            # Use word boundary matching: keyword must be a complete word
            # \b matches word boundaries (start/end of string, spaces, punctuation)
            pattern = r'\b' + re.escape(keyword) + r'\b'
            if re.search(pattern, vuln_product):
                match_reasons.append(f"Keyword match: {keyword}")

    return match_reasons

def match_vulnerabilities_to_products():
    """Match all active vulnerabilities against active products"""
    # Get all active products
    products = Product.query.filter_by(active=True).all()

    # Get all vulnerabilities
    vulnerabilities = Vulnerability.query.all()

    matches_count = 0

    for product in products:
        for vulnerability in vulnerabilities:
            match_reasons = check_match(vulnerability, product)

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
                        match_reason='; '.join(match_reasons)
                    )
                    db.session.add(match)
                    matches_count += 1

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
        match_reasons = check_match(vulnerability, product)

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
    query = db.session.query(VulnerabilityMatch).join(Vulnerability).join(Product)

    if filters:
        # Filter by organization
        if filters.get('organization_id'):
            query = query.filter(Product.organization_id == filters['organization_id'])

        # Filter by product ID
        if filters.get('product_id'):
            query = query.filter(VulnerabilityMatch.product_id == filters['product_id'])

        # Filter by CVE ID
        if filters.get('cve_id'):
            query = query.filter(Vulnerability.cve_id.ilike(f"%{filters['cve_id']}%"))

        # Filter by vendor
        if filters.get('vendor'):
            query = query.filter(Vulnerability.vendor_project.ilike(f"%{filters['vendor']}%"))

        # Filter by product
        if filters.get('product'):
            query = query.filter(Vulnerability.product.ilike(f"%{filters['product']}%"))

        # Filter by ransomware
        if filters.get('ransomware_only'):
            query = query.filter(Vulnerability.known_ransomware == True)

        # Filter by acknowledged status
        if filters.get('acknowledged') is not None:
            query = query.filter(VulnerabilityMatch.acknowledged == filters['acknowledged'])

    # Order by date added (newest first)
    query = query.order_by(Vulnerability.date_added.desc())

    return query.all()
