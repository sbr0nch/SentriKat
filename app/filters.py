from app import db
from app.models import Product, Vulnerability, VulnerabilityMatch

def normalize_string(s):
    """Normalize string for matching (lowercase, strip spaces)"""
    if not s:
        return ''
    return s.lower().strip()

def check_match(vulnerability, product):
    """Check if a vulnerability matches a product"""
    vuln_vendor = normalize_string(vulnerability.vendor_project)
    vuln_product = normalize_string(vulnerability.product)

    prod_vendor = normalize_string(product.vendor)
    prod_name = normalize_string(product.product_name)

    # Get additional keywords
    keywords = []
    if product.keywords:
        keywords = [normalize_string(k.strip()) for k in product.keywords.split(',')]

    match_reasons = []

    # Match by vendor
    if prod_vendor and prod_vendor in vuln_vendor:
        match_reasons.append(f"Vendor match: {product.vendor}")

    # Match by product name
    if prod_name and prod_name in vuln_product:
        match_reasons.append(f"Product match: {product.product_name}")

    # Match by keywords in either vendor or product
    for keyword in keywords:
        if keyword:
            if keyword in vuln_vendor or keyword in vuln_product:
                match_reasons.append(f"Keyword match: {keyword}")

    # Also check if vulnerability product contains our vendor
    if prod_vendor and prod_vendor in vuln_product:
        match_reasons.append(f"Vendor in product: {product.vendor}")

    # Check if product name is in vendor_project
    if prod_name and prod_name in vuln_vendor:
        match_reasons.append(f"Product in vendor: {product.product_name}")

    return match_reasons

def match_vulnerabilities_to_products():
    """Match all active vulnerabilities against active products"""
    # Clear old matches (optional - you may want to keep historical data)
    # VulnerabilityMatch.query.delete()

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
