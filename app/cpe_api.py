"""
CPE (Common Platform Enumeration) API endpoints for NVD product search and matching.

Provides real-time search against the NVD CPE database for software product identification
and vulnerability matching.
"""
from flask import Blueprint, request, jsonify, session
from datetime import datetime
from app import db, csrf
from app.auth import login_required, manager_required, admin_required
from app.models import Product, Vulnerability, ServiceCatalog
from app.nvd_cpe_api import (
    search_cpe,
    search_cpe_grouped,
    get_cpe_versions,
    match_cve_to_cpe,
    check_product_affected,
    get_cache_stats,
    clear_cache,
    parse_cpe_uri,
    build_cpe_uri
)

bp = Blueprint('cpe', __name__, url_prefix='/api/cpe')

# Exempt API routes from CSRF (they use JSON and are protected by SameSite cookies)
csrf.exempt(bp)


@bp.route('/search', methods=['GET'])
@login_required
def search_products():
    """
    Search NVD CPE database for products.

    Query params:
        q: Search keyword (required, min 2 chars)
        limit: Max results (default 50, max 200)
        grouped: If true, return results grouped by vendor/product (default true)

    Returns:
        If grouped=true (default):
        {
            "vendors": {
                "apache": {
                    "display_name": "Apache",
                    "products": {
                        "tomcat": {
                            "display_name": "Apache Tomcat",
                            "versions": ["10.1.18", "10.0.27", ...],
                            "cpe_vendor": "apache",
                            "cpe_product": "tomcat"
                        }
                    }
                }
            },
            "total_results": int,
            "cached": bool
        }

        If grouped=false:
        {
            "results": [
                {
                    "cpe_uri": "cpe:2.3:a:apache:tomcat:10.1.18:*:*:*:*:*:*:*",
                    "vendor": "apache",
                    "product": "tomcat",
                    "version": "10.1.18",
                    "title": "Apache Tomcat 10.1.18"
                }
            ],
            "total_results": int,
            "cached": bool
        }
    """
    query = request.args.get('q', '').strip()

    if not query or len(query) < 2:
        return jsonify({'error': 'Search query must be at least 2 characters'}), 400

    limit = min(int(request.args.get('limit', 50)), 200)
    grouped = request.args.get('grouped', 'true').lower() == 'true'

    try:
        if grouped:
            results = search_cpe_grouped(query, limit=limit)
            return jsonify({
                'vendors': results,
                'total_results': sum(
                    len(v['products']) for v in results.values()
                ),
                'query': query
            })
        else:
            results = search_cpe(query, limit=limit)
            return jsonify({
                'results': results,
                'total_results': len(results),
                'query': query
            })

    except Exception as e:
        return jsonify({'error': f'CPE search failed: {str(e)}'}), 500


@bp.route('/versions', methods=['GET'])
@login_required
def get_product_versions():
    """
    Get available versions for a specific vendor/product.

    Query params:
        vendor: CPE vendor name (required)
        product: CPE product name (required)
        limit: Max versions to return (default 50)

    Returns:
        {
            "vendor": "apache",
            "product": "tomcat",
            "versions": ["10.1.18", "10.0.27", "9.0.85", ...],
            "total": int
        }
    """
    vendor = request.args.get('vendor', '').strip()
    product = request.args.get('product', '').strip()

    if not vendor or not product:
        return jsonify({'error': 'Vendor and product are required'}), 400

    limit = min(int(request.args.get('limit', 50)), 100)

    try:
        versions = get_cpe_versions(vendor, product, limit=limit)
        return jsonify({
            'vendor': vendor,
            'product': product,
            'versions': versions,
            'total': len(versions)
        })

    except Exception as e:
        return jsonify({'error': f'Failed to fetch versions: {str(e)}'}), 500


@bp.route('/cve/<cve_id>/affected', methods=['GET'])
@login_required
def get_cve_affected_products(cve_id):
    """
    Get CPE entries affected by a specific CVE.

    Returns list of affected vendor/product combinations with version ranges.
    """
    try:
        affected = match_cve_to_cpe(cve_id)
        return jsonify({
            'cve_id': cve_id,
            'affected_products': affected,
            'total': len(affected)
        })

    except Exception as e:
        return jsonify({'error': f'Failed to fetch CVE data: {str(e)}'}), 500


@bp.route('/check-affected', methods=['POST'])
@login_required
def check_product_vulnerability():
    """
    Check if a specific product version is affected by a CVE.

    Request body:
        {
            "cpe_vendor": "apache",
            "cpe_product": "tomcat",
            "version": "10.1.18",
            "cve_id": "CVE-2024-1234"
        }

    Returns:
        {
            "affected": bool,
            "match_reason": "..." or null
        }
    """
    data = request.get_json()

    required = ['cpe_vendor', 'cpe_product', 'version', 'cve_id']
    for field in required:
        if not data.get(field):
            return jsonify({'error': f'{field} is required'}), 400

    try:
        affected, reason = check_product_affected(
            data['cpe_vendor'],
            data['cpe_product'],
            data['version'],
            data['cve_id']
        )
        return jsonify({
            'affected': affected,
            'match_reason': reason,
            'product': {
                'cpe_vendor': data['cpe_vendor'],
                'cpe_product': data['cpe_product'],
                'version': data['version']
            },
            'cve_id': data['cve_id']
        })

    except Exception as e:
        return jsonify({'error': f'Failed to check vulnerability: {str(e)}'}), 500


@bp.route('/parse', methods=['POST'])
@login_required
def parse_cpe():
    """
    Parse a CPE URI into its components.

    Request body:
        {
            "cpe_uri": "cpe:2.3:a:apache:tomcat:10.1.18:*:*:*:*:*:*:*"
        }

    Returns:
        {
            "vendor": "apache",
            "product": "tomcat",
            "version": "10.1.18",
            "part": "a",
            ...
        }
    """
    data = request.get_json()
    cpe_uri = data.get('cpe_uri', '').strip()

    if not cpe_uri:
        return jsonify({'error': 'cpe_uri is required'}), 400

    parsed = parse_cpe_uri(cpe_uri)
    return jsonify(parsed)


@bp.route('/build', methods=['POST'])
@login_required
def build_cpe():
    """
    Build a CPE URI from components.

    Request body:
        {
            "vendor": "apache",
            "product": "tomcat",
            "version": "10.1.18"  // optional, default *
        }

    Returns:
        {
            "cpe_uri": "cpe:2.3:a:apache:tomcat:10.1.18:*:*:*:*:*:*:*"
        }
    """
    data = request.get_json()

    if not data.get('vendor') or not data.get('product'):
        return jsonify({'error': 'vendor and product are required'}), 400

    cpe_uri = build_cpe_uri(
        data['vendor'],
        data['product'],
        data.get('version', '*')
    )

    return jsonify({
        'cpe_uri': cpe_uri,
        'vendor': data['vendor'],
        'product': data['product'],
        'version': data.get('version', '*')
    })


@bp.route('/link-product/<int:product_id>', methods=['POST'])
@manager_required
def link_cpe_to_product(product_id):
    """
    Link CPE identifiers to an existing product.

    Request body:
        {
            "cpe_vendor": "apache",
            "cpe_product": "tomcat",
            "cpe_uri": "cpe:2.3:a:apache:tomcat:*:*:*:*:*:*:*:*",  // optional
            "match_type": "auto"  // auto, cpe, keyword, both
        }

    Returns updated product.
    """
    product = Product.query.get_or_404(product_id)
    data = request.get_json()

    if not data.get('cpe_vendor') or not data.get('cpe_product'):
        return jsonify({'error': 'cpe_vendor and cpe_product are required'}), 400

    product.cpe_vendor = data['cpe_vendor']
    product.cpe_product = data['cpe_product']
    product.cpe_uri = data.get('cpe_uri')
    product.match_type = data.get('match_type', 'auto')

    db.session.commit()

    # Trigger re-matching for this product
    from app.filters import match_vulnerabilities_to_products
    match_vulnerabilities_to_products()

    return jsonify({
        'success': True,
        'product': product.to_dict(),
        'message': 'CPE linked successfully. Vulnerability matching has been refreshed.'
    })


@bp.route('/unlink-product/<int:product_id>', methods=['POST'])
@manager_required
def unlink_cpe_from_product(product_id):
    """
    Remove CPE identifiers from a product.

    Returns updated product.
    """
    product = Product.query.get_or_404(product_id)

    product.cpe_vendor = None
    product.cpe_product = None
    product.cpe_uri = None
    product.match_type = 'keyword'

    db.session.commit()

    # Trigger re-matching for this product
    from app.filters import match_vulnerabilities_to_products
    match_vulnerabilities_to_products()

    return jsonify({
        'success': True,
        'product': product.to_dict(),
        'message': 'CPE unlinked. Product will now use keyword matching.'
    })


@bp.route('/suggest', methods=['GET'])
@login_required
def suggest_cpe_for_product():
    """
    Suggest CPE identifiers for a product based on its vendor/product name.

    Query params:
        vendor: Product vendor name
        product: Product name

    Returns list of potential CPE matches.
    """
    vendor = request.args.get('vendor', '').strip()
    product_name = request.args.get('product', '').strip()

    if not vendor and not product_name:
        return jsonify({'error': 'Vendor or product name required'}), 400

    # Build search query
    search_query = f"{vendor} {product_name}".strip()

    try:
        results = search_cpe_grouped(search_query, limit=20)

        suggestions = []
        for vendor_key, vendor_data in results.items():
            for product_key, product_data in vendor_data['products'].items():
                suggestions.append({
                    'cpe_vendor': vendor_key,
                    'cpe_product': product_key,
                    'display_name': product_data.get('display_name') or product_data.get('title'),
                    'versions': product_data.get('versions', [])[:10],
                    'cpe_uri': build_cpe_uri(vendor_key, product_key)
                })

        return jsonify({
            'query': search_query,
            'suggestions': suggestions,
            'total': len(suggestions)
        })

    except Exception as e:
        return jsonify({'error': f'CPE suggestion failed: {str(e)}'}), 500


@bp.route('/catalog/update/<int:catalog_id>', methods=['POST'])
@admin_required
def update_catalog_cpe(catalog_id):
    """
    Update CPE identifiers for a service catalog entry.

    Request body:
        {
            "cpe_vendor": "apache",
            "cpe_product": "tomcat"
        }
    """
    entry = ServiceCatalog.query.get_or_404(catalog_id)
    data = request.get_json()

    if 'cpe_vendor' in data:
        entry.cpe_vendor = data['cpe_vendor']
    if 'cpe_product' in data:
        entry.cpe_product = data['cpe_product']

    db.session.commit()

    return jsonify({
        'success': True,
        'catalog_entry': entry.to_dict()
    })


@bp.route('/stats', methods=['GET'])
@login_required
def get_cpe_stats():
    """
    Get CPE cache and usage statistics.

    Returns:
        {
            "cache": {
                "total_entries": int,
                "valid_entries": int,
                "cache_ttl_minutes": int
            },
            "products": {
                "total": int,
                "with_cpe": int,
                "without_cpe": int,
                "by_match_type": {...}
            }
        }
    """
    cache_stats = get_cache_stats()

    # Get product CPE statistics
    total_products = Product.query.filter_by(active=True).count()
    products_with_cpe = Product.query.filter(
        Product.active == True,
        Product.cpe_vendor.isnot(None),
        Product.cpe_product.isnot(None)
    ).count()

    # Count by match_type
    match_type_counts = {}
    for match_type in ['auto', 'cpe', 'keyword', 'both']:
        count = Product.query.filter(
            Product.active == True,
            Product.match_type == match_type
        ).count()
        match_type_counts[match_type] = count

    # Check if NVD API key is configured (for rate limit info)
    from app.nvd_cpe_api import _get_api_key
    api_key_configured = bool(_get_api_key())

    return jsonify({
        'cache': cache_stats,
        'products': {
            'total': total_products,
            'with_cpe': products_with_cpe,
            'without_cpe': total_products - products_with_cpe,
            'by_match_type': match_type_counts
        },
        'api': {
            'nvd_api_key_configured': api_key_configured,
            'rate_limit': '50 req/30s' if api_key_configured else '5 req/30s'
        }
    })


@bp.route('/cache/clear', methods=['POST'])
@admin_required
def clear_cpe_cache():
    """
    Clear the CPE search cache.

    Requires admin privileges.
    """
    clear_cache()
    return jsonify({
        'success': True,
        'message': 'CPE cache cleared successfully'
    })


@bp.route('/bulk-suggest', methods=['POST'])
@manager_required
def bulk_suggest_cpe():
    """
    Suggest CPE for multiple products at once.

    Request body:
        {
            "product_ids": [1, 2, 3]
        }

    Returns suggestions for each product.
    """
    data = request.get_json()
    product_ids = data.get('product_ids', [])

    if not product_ids:
        return jsonify({'error': 'product_ids required'}), 400

    results = []
    for product_id in product_ids[:20]:  # Limit to 20 products
        product = Product.query.get(product_id)
        if not product:
            continue

        # Search for this product
        search_query = f"{product.vendor} {product.product_name}".strip()
        try:
            cpe_results = search_cpe_grouped(search_query, limit=5)

            suggestions = []
            for vendor_key, vendor_data in cpe_results.items():
                for product_key, product_data in vendor_data['products'].items():
                    suggestions.append({
                        'cpe_vendor': vendor_key,
                        'cpe_product': product_key,
                        'display_name': product_data.get('display_name'),
                        'versions': product_data.get('versions', [])[:5]
                    })

            results.append({
                'product_id': product_id,
                'product_name': f"{product.vendor} {product.product_name}",
                'suggestions': suggestions[:5],
                'current_cpe': {
                    'vendor': product.cpe_vendor,
                    'product': product.cpe_product
                } if product.cpe_vendor else None
            })

        except Exception:
            results.append({
                'product_id': product_id,
                'product_name': f"{product.vendor} {product.product_name}",
                'suggestions': [],
                'error': 'Failed to fetch suggestions'
            })

    return jsonify({
        'results': results,
        'total_processed': len(results)
    })


@bp.route('/bulk-link', methods=['POST'])
@manager_required
def bulk_link_cpe():
    """
    Link CPE to multiple products at once.

    Request body:
        {
            "links": [
                {
                    "product_id": 1,
                    "cpe_vendor": "apache",
                    "cpe_product": "tomcat"
                },
                ...
            ]
        }
    """
    data = request.get_json()
    links = data.get('links', [])

    if not links:
        return jsonify({'error': 'links array required'}), 400

    results = []
    for link in links[:50]:  # Limit to 50 products
        product_id = link.get('product_id')
        product = Product.query.get(product_id)

        if not product:
            results.append({
                'product_id': product_id,
                'success': False,
                'error': 'Product not found'
            })
            continue

        if not link.get('cpe_vendor') or not link.get('cpe_product'):
            results.append({
                'product_id': product_id,
                'success': False,
                'error': 'cpe_vendor and cpe_product required'
            })
            continue

        product.cpe_vendor = link['cpe_vendor']
        product.cpe_product = link['cpe_product']
        product.cpe_uri = link.get('cpe_uri')
        product.match_type = link.get('match_type', 'auto')

        results.append({
            'product_id': product_id,
            'success': True,
            'product': product.to_dict()
        })

    db.session.commit()

    # Trigger re-matching
    from app.filters import match_vulnerabilities_to_products
    match_vulnerabilities_to_products()

    success_count = sum(1 for r in results if r.get('success'))
    return jsonify({
        'results': results,
        'total_processed': len(results),
        'success_count': success_count,
        'message': f'{success_count} products linked successfully'
    })


# =============================================================================
# USER CPE MAPPINGS - Export/Import
# =============================================================================

@bp.route('/user-mappings', methods=['GET'])
@manager_required
def get_user_mappings():
    """
    Get all user-defined CPE mappings.

    Query params:
        format: 'json' (default) or 'export' (minimal for sharing)

    Returns list of user CPE mappings.
    """
    from app.models import UserCpeMapping

    export_format = request.args.get('format', 'json') == 'export'

    mappings = UserCpeMapping.query.order_by(UserCpeMapping.usage_count.desc()).all()

    if export_format:
        return jsonify({
            'mappings': [m.to_export_dict() for m in mappings],
            'total': len(mappings),
            'export_date': datetime.utcnow().isoformat()
        })
    else:
        return jsonify({
            'mappings': [m.to_dict() for m in mappings],
            'total': len(mappings)
        })


@bp.route('/user-mappings/export', methods=['GET'])
@admin_required
def export_user_mappings():
    """
    Export user CPE mappings as a downloadable JSON file.

    Returns a JSON file attachment.
    """
    from flask import Response
    from app.cpe_mappings import get_all_user_mappings
    import json
    from datetime import datetime

    mappings = get_all_user_mappings()

    export_data = {
        'version': '1.0',
        'export_date': datetime.utcnow().isoformat(),
        'source': 'sentrikat',
        'mappings': mappings
    }

    json_data = json.dumps(export_data, indent=2)

    return Response(
        json_data,
        mimetype='application/json',
        headers={
            'Content-Disposition': f'attachment; filename=cpe_mappings_{datetime.utcnow().strftime("%Y%m%d")}.json'
        }
    )


@bp.route('/user-mappings/import', methods=['POST'])
@admin_required
def import_user_mappings_api():
    """
    Import user CPE mappings from JSON.

    Request body:
        {
            "mappings": [
                {
                    "vendor_pattern": "some vendor",
                    "product_pattern": "some product",
                    "cpe_vendor": "vendor",
                    "cpe_product": "product",
                    "notes": "optional notes"
                }
            ],
            "overwrite": false
        }

    Or upload a JSON file with multipart/form-data.

    Returns import results.
    """
    from flask_login import current_user
    from app.cpe_mappings import import_user_mappings

    # Handle both JSON body and file upload
    if request.content_type and 'multipart/form-data' in request.content_type:
        # File upload
        if 'file' not in request.files:
            return jsonify({'error': 'No file provided'}), 400

        file = request.files['file']
        if not file.filename.endswith('.json'):
            return jsonify({'error': 'File must be JSON'}), 400

        try:
            import json
            data = json.load(file)
        except json.JSONDecodeError:
            return jsonify({'error': 'Invalid JSON file'}), 400
    else:
        # JSON body
        data = request.get_json()

    if not data:
        return jsonify({'error': 'No data provided'}), 400

    mappings = data.get('mappings', [])
    overwrite = data.get('overwrite', False)

    if not mappings:
        return jsonify({'error': 'No mappings in data'}), 400

    result = import_user_mappings(
        mappings,
        user_id=current_user.id if current_user else None,
        overwrite=overwrite
    )

    return jsonify({
        'success': True,
        'imported': result['imported'],
        'skipped': result['skipped'],
        'errors': result['errors'],
        'message': f"Imported {result['imported']} mappings, skipped {result['skipped']}, {result['errors']} errors"
    })


@bp.route('/user-mappings/<int:mapping_id>', methods=['DELETE'])
@admin_required
def delete_user_mapping(mapping_id):
    """Delete a specific user CPE mapping."""
    from app.cpe_mappings import delete_user_mapping as delete_mapping

    if delete_mapping(mapping_id):
        return jsonify({'success': True, 'message': 'Mapping deleted'})
    else:
        return jsonify({'error': 'Mapping not found or delete failed'}), 404


@bp.route('/user-mappings/stats', methods=['GET'])
@manager_required
def user_mapping_stats():
    """Get statistics about user CPE mappings."""
    from app.cpe_mappings import get_user_mapping_stats

    stats = get_user_mapping_stats()
    return jsonify(stats)


@bp.route('/coverage', methods=['GET'])
@manager_required
def cpe_coverage_dashboard():
    """
    Get CPE coverage statistics for the organization.

    Returns comprehensive stats about:
    - Overall CPE coverage percentage
    - Products without CPE
    - Top unmapped vendors
    - Mapping source breakdown

    Query params:
        org_id: Organization ID filter (optional)
    """
    from sqlalchemy import func
    from app.models import Organization
    from app.cpe_mapping import get_cpe_coverage_stats, suggest_cpe_for_products
    from app.cpe_mappings import get_user_mapping_stats

    org_id = request.args.get('org_id', type=int)

    # Base query
    query = Product.query
    if org_id:
        query = query.filter(Product.organization_id == org_id)

    # Overall stats
    total_products = query.count() or 0
    with_cpe = query.filter(
        Product.cpe_vendor.isnot(None),
        Product.cpe_vendor != '',
        Product.cpe_product.isnot(None),
        Product.cpe_product != ''
    ).count() or 0
    without_cpe = total_products - with_cpe

    coverage_percent = round((with_cpe / total_products * 100) if total_products > 0 else 0, 1)

    # Match type breakdown
    match_type_stats = {}
    for match_type in ['auto', 'cpe', 'keyword', 'both', None]:
        if match_type is None:
            count = query.filter(Product.match_type.is_(None)).count()
            match_type_stats['unset'] = count
        else:
            count = query.filter(Product.match_type == match_type).count()
            match_type_stats[match_type] = count

    # Top unmapped vendors (products without CPE grouped by vendor)
    unmapped_by_vendor = db.session.query(
        Product.vendor,
        func.count(Product.id).label('count')
    ).filter(
        db.or_(
            Product.cpe_vendor.is_(None),
            Product.cpe_vendor == ''
        )
    )
    if org_id:
        unmapped_by_vendor = unmapped_by_vendor.filter(Product.organization_id == org_id)

    unmapped_by_vendor = unmapped_by_vendor.group_by(
        Product.vendor
    ).order_by(
        func.count(Product.id).desc()
    ).limit(20).all()

    top_unmapped_vendors = [
        {'vendor': v or 'Unknown', 'count': c}
        for v, c in unmapped_by_vendor
    ]

    # Products with possible CPE suggestions
    suggestions = suggest_cpe_for_products(limit=10)

    # User mapping stats
    user_stats = get_user_mapping_stats()

    # Curated mapping count
    from app.cpe_mappings import SOFTWARE_TO_CPE_MAPPINGS
    from app.cpe_mapping import CPE_MAPPINGS
    curated_count = len(SOFTWARE_TO_CPE_MAPPINGS)
    regex_count = len(CPE_MAPPINGS)

    # Coverage by organization (if super admin viewing all)
    org_coverage = []
    if not org_id:
        orgs = Organization.query.all()
        for org in orgs:
            org_total = Product.query.filter(Product.organization_id == org.id).count() or 0
            org_with_cpe = Product.query.filter(
                Product.organization_id == org.id,
                Product.cpe_vendor.isnot(None),
                Product.cpe_vendor != ''
            ).count() or 0
            if org_total > 0:
                org_coverage.append({
                    'org_id': org.id,
                    'org_name': org.name,
                    'total': org_total,
                    'with_cpe': org_with_cpe,
                    'coverage_percent': round(org_with_cpe / org_total * 100, 1)
                })

    return jsonify({
        'overall': {
            'total_products': total_products,
            'with_cpe': with_cpe,
            'without_cpe': without_cpe,
            'coverage_percent': coverage_percent
        },
        'match_type_breakdown': match_type_stats,
        'top_unmapped_vendors': top_unmapped_vendors,
        'suggestions': suggestions,
        'mapping_sources': {
            'curated_mappings': curated_count,
            'regex_patterns': regex_count,
            'user_mappings': user_stats.get('total_mappings', 0)
        },
        'organization_coverage': org_coverage if org_coverage else None
    })


@bp.route('/apply-suggestions', methods=['POST'])
@admin_required
def apply_cpe_suggestions():
    """
    Apply CPE mapping suggestions to products.

    Request body:
        product_ids: List of product IDs to apply suggestions to
        apply_all: If true, apply to all products without CPE (ignores product_ids)
    """
    from app.cpe_mapping import batch_apply_cpe_mappings, apply_cpe_to_product

    data = request.get_json() or {}
    apply_all = data.get('apply_all', False)
    product_ids = data.get('product_ids', [])

    if apply_all:
        updated, total = batch_apply_cpe_mappings(commit=True)
        return jsonify({
            'success': True,
            'updated': updated,
            'total_without_cpe': total,
            'message': f'Applied CPE mappings to {updated} of {total} products'
        })
    elif product_ids:
        updated = 0
        for pid in product_ids[:100]:  # Limit to 100 at a time
            product = Product.query.get(pid)
            if product and apply_cpe_to_product(product):
                updated += 1
        if updated > 0:
            db.session.commit()
        return jsonify({
            'success': True,
            'updated': updated,
            'message': f'Applied CPE mappings to {updated} products'
        })
    else:
        return jsonify({'error': 'Provide product_ids or set apply_all=true'}), 400
