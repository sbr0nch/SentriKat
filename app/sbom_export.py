"""
SBOM (Software Bill of Materials) Export API endpoints.

Sprint 4 #32: Provides CycloneDX 1.5 and SPDX 2.3 JSON export
of an organization's software inventory with matched vulnerabilities.
"""

from flask import Blueprint, request, jsonify, session, make_response
from sqlalchemy import select
from app import db, csrf, limiter
from app.auth import login_required
from app.licensing import requires_professional
from app.models import Product, VulnerabilityMatch, Vulnerability, product_organizations, Organization
from datetime import datetime, timezone
import uuid
import logging

logger = logging.getLogger(__name__)

bp = Blueprint('sbom_export', __name__)
csrf.exempt(bp)


def _get_org_products(org_id, product_ids=None):
    """Fetch products belonging to an organization, optionally filtered by IDs."""
    org_product_id_query = select(product_organizations.c.product_id).where(
        product_organizations.c.organization_id == org_id
    )
    org_product_ids = db.session.execute(org_product_id_query).scalars().all()

    if not org_product_ids:
        return []

    query = Product.query.filter(
        Product.id.in_(org_product_ids),
        Product.active == True,
    )

    if product_ids:
        # Further filter to only requested products (intersect with org ownership)
        query = query.filter(Product.id.in_(product_ids))

    return query.all()


def _parse_product_ids(raw):
    """Parse comma-separated product_ids query param into a list of ints."""
    if not raw:
        return None
    try:
        return [int(pid.strip()) for pid in raw.split(',') if pid.strip()]
    except ValueError:
        return None


def _build_purl(product):
    """Build a Package URL from product fields."""
    ecosystem = (product.ecosystem or '').strip().lower() or 'generic'
    vendor = (product.vendor or 'unknown').strip()
    name = (product.product_name or 'unknown').strip()
    version = (product.version or '').strip()

    purl = f"pkg:{ecosystem}/{vendor}/{name}"
    if version:
        purl += f"@{version}"
    return purl


def _build_bom_ref(product):
    """Build a deterministic bom-ref for a product."""
    return f"sentrikat-product-{product.id}"


def _get_vuln_matches_for_products(product_ids):
    """Fetch vulnerability matches grouped by product_id."""
    if not product_ids:
        return {}

    matches = (
        VulnerabilityMatch.query
        .join(Vulnerability)
        .filter(VulnerabilityMatch.product_id.in_(product_ids))
        .all()
    )

    grouped = {}
    for m in matches:
        grouped.setdefault(m.product_id, []).append(m)
    return grouped


# ============================================================================
# CycloneDX 1.5 Export
# ============================================================================

@bp.route('/api/sbom/export/cyclonedx', methods=['GET'])
@login_required
@requires_professional('SBOM Export')
@limiter.limit("10/hour")
def export_cyclonedx():
    """Export organization software inventory as CycloneDX 1.5 JSON BOM.

    Sprint 4 #32: Rate limited to 10/hour per user (heavy DB query).
    Requires Professional+ license.
    """
    org_id = session.get('organization_id')
    if not org_id:
        return jsonify({'error': 'Organization required'}), 400

    org = Organization.query.get(org_id)
    if not org:
        return jsonify({'error': 'Organization not found'}), 404

    product_ids = _parse_product_ids(request.args.get('product_ids'))
    products = _get_org_products(org_id, product_ids)

    now = datetime.now(timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')
    serial_uuid = str(uuid.uuid4())

    # Build components
    components = []
    for p in products:
        component = {
            'type': 'library',
            'bom-ref': _build_bom_ref(p),
            'name': p.product_name,
            'version': p.version or '',
            'purl': _build_purl(p),
        }
        if p.cpe_uri:
            component['cpe'] = p.cpe_uri
        if p.vendor:
            component['supplier'] = {'name': p.vendor}
        components.append(component)

    # Build vulnerabilities
    product_id_list = [p.id for p in products]
    match_map = _get_vuln_matches_for_products(product_id_list)

    vulnerabilities = []
    seen_vulns = {}  # cve_id -> vuln entry (to merge affects across products)

    for product in products:
        matches = match_map.get(product.id, [])
        for m in matches:
            vuln = m.vulnerability
            cve_id = vuln.cve_id

            affect_entry = {'ref': _build_bom_ref(product)}

            if cve_id in seen_vulns:
                # Add this product as another affected ref
                seen_vulns[cve_id]['affects'].append(affect_entry)
            else:
                vuln_entry = {
                    'id': cve_id,
                    'source': {'name': 'NVD'},
                    'affects': [affect_entry],
                }

                # Build ratings
                ratings = []
                if vuln.cvss_score is not None or vuln.severity:
                    rating = {}
                    if vuln.cvss_score is not None:
                        rating['score'] = vuln.cvss_score
                    if vuln.severity:
                        rating['severity'] = vuln.severity.lower()
                    rating['method'] = 'CVSSv31'
                    ratings.append(rating)

                if ratings:
                    vuln_entry['ratings'] = ratings

                if vuln.short_description:
                    vuln_entry['description'] = vuln.short_description

                vulnerabilities.append(vuln_entry)
                seen_vulns[cve_id] = vuln_entry

    bom = {
        'bomFormat': 'CycloneDX',
        'specVersion': '1.5',
        'version': 1,
        'serialNumber': f'urn:uuid:{serial_uuid}',
        'metadata': {
            'timestamp': now,
            'tools': [{'name': 'SentriKat'}],
            'component': {
                'type': 'application',
                'name': org.display_name or org.name,
            },
        },
        'components': components,
        'vulnerabilities': vulnerabilities,
    }

    response = make_response(jsonify(bom))
    response.headers['Content-Disposition'] = (
        f'attachment; filename="{org.name}-cyclonedx-sbom.json"'
    )
    return response


# ============================================================================
# SPDX 2.3 Export
# ============================================================================

@bp.route('/api/sbom/export/spdx', methods=['GET'])
@login_required
@requires_professional('SBOM Export')
@limiter.limit("10/hour")
def export_spdx():
    """Export organization software inventory as SPDX 2.3 JSON."""
    org_id = session.get('organization_id')
    if not org_id:
        return jsonify({'error': 'Organization required'}), 400

    org = Organization.query.get(org_id)
    if not org:
        return jsonify({'error': 'Organization not found'}), 404

    product_ids = _parse_product_ids(request.args.get('product_ids'))
    products = _get_org_products(org_id, product_ids)

    now = datetime.now(timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')
    doc_uuid = str(uuid.uuid4())
    doc_namespace = f"https://sentrikat.io/spdx/{org.name}/{doc_uuid}"

    # Build packages
    packages = []
    for p in products:
        spdx_id = f"SPDXRef-Package-{p.id}"
        package = {
            'SPDXID': spdx_id,
            'name': p.product_name,
            'versionInfo': p.version or '',
            'downloadLocation': 'NOASSERTION',
            'filesAnalyzed': False,
        }

        if p.vendor:
            package['supplier'] = f'Organization: {p.vendor}'

        # External references
        external_refs = []

        if p.cpe_uri:
            external_refs.append({
                'referenceCategory': 'SECURITY',
                'referenceType': 'cpe23Type',
                'referenceLocator': p.cpe_uri,
            })

        purl = _build_purl(p)
        external_refs.append({
            'referenceCategory': 'PACKAGE-MANAGER',
            'referenceType': 'purl',
            'referenceLocator': purl,
        })

        if external_refs:
            package['externalRefs'] = external_refs

        packages.append(package)

    # Build relationships (DESCRIBES from document to each package)
    relationships = []
    for p in products:
        relationships.append({
            'spdxElementId': 'SPDXRef-DOCUMENT',
            'relatedSpdxElement': f'SPDXRef-Package-{p.id}',
            'relationshipType': 'DESCRIBES',
        })

    spdx_doc = {
        'spdxVersion': 'SPDX-2.3',
        'dataLicense': 'CC0-1.0',
        'SPDXID': 'SPDXRef-DOCUMENT',
        'name': f'{org.name}-sbom',
        'documentNamespace': doc_namespace,
        'creationInfo': {
            'created': now,
            'creators': ['Tool: SentriKat'],
        },
        'packages': packages,
        'relationships': relationships,
    }

    response = make_response(jsonify(spdx_doc))
    response.headers['Content-Disposition'] = (
        f'attachment; filename="{org.name}-spdx-sbom.json"'
    )
    return response


# ============================================================================
# STIX 2.1 Export (Sprint 5)
# ============================================================================

def _stix_timestamp():
    """Return an RFC3339/STIX-compliant UTC timestamp with millisecond precision."""
    return datetime.now(timezone.utc).strftime('%Y-%m-%dT%H:%M:%S.000Z')


@bp.route('/api/sbom/export/stix21', methods=['GET'])
@login_required
@requires_professional('SBOM Export')
@limiter.limit("10/hour")
def export_stix21():
    """Export organization vulnerabilities as a STIX 2.1 JSON bundle.

    Sprint 5: STIX 2.1 is the OASIS standard for threat intelligence sharing,
    used by ISACs, MISP, CISA, and other threat intel platforms.

    Query Parameters:
        product_ids: Optional comma-separated list of product IDs to filter

    Returns:
        A STIX 2.1 Bundle containing:
        - vulnerability SDOs (one per matched CVE)
        - software SCOs (one per product)
        - relationship SROs linking vulnerabilities to affected software
    """
    org_id = session.get('organization_id')
    if not org_id:
        return jsonify({'error': 'Organization required'}), 400

    org = Organization.query.get(org_id)
    if not org:
        return jsonify({'error': 'Organization not found'}), 404

    product_ids = _parse_product_ids(request.args.get('product_ids'))
    products = _get_org_products(org_id, product_ids)

    now = _stix_timestamp()
    bundle_id = f"bundle--{uuid.uuid4()}"

    objects = []

    # 1) software SCOs (one per product)
    software_id_by_product = {}
    for p in products:
        sw_id = f"software--{uuid.uuid4()}"
        software_id_by_product[p.id] = sw_id

        sw_obj = {
            'type': 'software',
            'spec_version': '2.1',
            'id': sw_id,
            'name': p.product_name or 'unknown',
        }
        if p.vendor:
            sw_obj['vendor'] = p.vendor
        if p.version:
            sw_obj['version'] = p.version
        if p.cpe_uri:
            sw_obj['cpe'] = p.cpe_uri
        objects.append(sw_obj)

    # 2) vulnerability SDOs + 3) relationship SROs
    product_id_list = [p.id for p in products]
    match_map = _get_vuln_matches_for_products(product_id_list)

    vuln_id_by_cve = {}  # cve_id -> stix id (dedupe across products)

    for p in products:
        matches = match_map.get(p.id, [])
        for m in matches:
            vuln = m.vulnerability
            cve_id = vuln.cve_id
            if not cve_id:
                continue

            if cve_id not in vuln_id_by_cve:
                vuln_stix_id = f"vulnerability--{uuid.uuid4()}"
                vuln_id_by_cve[cve_id] = vuln_stix_id

                vuln_obj = {
                    'type': 'vulnerability',
                    'spec_version': '2.1',
                    'id': vuln_stix_id,
                    'created': now,
                    'modified': now,
                    'name': cve_id,
                    'description': (vuln.short_description or f'Vulnerability {cve_id}'),
                    'external_references': [
                        {
                            'source_name': 'cve',
                            'external_id': cve_id,
                            'url': f'https://nvd.nist.gov/vuln/detail/{cve_id}',
                        }
                    ],
                }

                # Optional labels for severity / known ransomware
                labels = []
                if getattr(vuln, 'severity', None):
                    labels.append(f'severity-{vuln.severity.lower()}')
                if getattr(vuln, 'known_ransomware', False):
                    labels.append('known-ransomware')
                if labels:
                    vuln_obj['labels'] = labels

                objects.append(vuln_obj)
            else:
                vuln_stix_id = vuln_id_by_cve[cve_id]

            # relationship: vulnerability --[affects]--> software
            sw_stix_id = software_id_by_product.get(p.id)
            if sw_stix_id:
                rel_obj = {
                    'type': 'relationship',
                    'spec_version': '2.1',
                    'id': f'relationship--{uuid.uuid4()}',
                    'created': now,
                    'modified': now,
                    'relationship_type': 'affects',
                    'source_ref': vuln_stix_id,
                    'target_ref': sw_stix_id,
                }
                objects.append(rel_obj)

    bundle = {
        'type': 'bundle',
        'id': bundle_id,
        'objects': objects,
    }

    response = make_response(jsonify(bundle))
    response.headers['Content-Disposition'] = (
        f'attachment; filename="{org.name}-stix21-bundle.json"'
    )
    response.headers['Content-Type'] = 'application/stix+json;version=2.1'
    return response
