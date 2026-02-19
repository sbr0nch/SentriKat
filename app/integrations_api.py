"""
Integrations API - Endpoints for external software inventory integrations.

Provides:
1. Push API - External systems/agents send software lists to SentriKat
2. Queue Management - Review, approve, reject pending imports
3. Integration CRUD - Configure external system connections
4. Agent Management - Register and manage discovery agents
"""

from flask import Blueprint, request, jsonify, session, Response
from datetime import datetime
import secrets
import uuid
import logging
from functools import wraps

from sqlalchemy.exc import IntegrityError

from app import db, csrf
from app.integrations_models import Integration, ImportQueue, AgentRegistration
from app.models import Product, Organization, User
from app.auth import admin_required, login_required, get_current_user
from app.licensing import requires_professional
from config import Config

logger = logging.getLogger(__name__)

bp = Blueprint('integrations', __name__)
csrf.exempt(bp)  # API endpoints use session auth, not CSRF tokens


# ============================================================================
# Authentication Helpers
# ============================================================================

def get_integration_by_api_key(api_key):
    """Look up integration by API key."""
    if not api_key:
        return None
    return Integration.query.filter_by(api_key=api_key, is_active=True).first()


def validate_org_access(user, org_id):
    """Validate that a user has access to the given organization.
    Returns (org, error_response) tuple. If error_response is not None, return it."""
    org = Organization.query.get(org_id)
    if not org:
        return None, (jsonify({'error': 'Organization not found'}), 404)
    if not user.is_super_admin() and not user.has_access_to_org(org_id):
        return None, (jsonify({'error': 'Permission denied for this organization'}), 403)
    return org, None


def api_key_or_login_required(f):
    """Allow authentication via API key OR session login."""
    @wraps(f)
    def decorated(*args, **kwargs):
        # Check for API key in header
        api_key = request.headers.get('X-API-Key') or request.headers.get('Authorization', '').replace('Bearer ', '')

        if api_key:
            integration = get_integration_by_api_key(api_key)
            if integration:
                request.integration = integration
                return f(*args, **kwargs)
            return jsonify({'error': 'Invalid API key'}), 401

        # Fall back to session authentication
        if 'user_id' not in session:
            return jsonify({'error': 'Authentication required'}), 401

        request.integration = None
        return f(*args, **kwargs)

    return decorated


# ============================================================================
# Push API - Receive software lists from external systems
# ============================================================================

@bp.route('/api/import', methods=['POST'])
@api_key_or_login_required
def import_software():
    """
    Import software list from external system.

    Can be called with:
    - API key (from integration) in X-API-Key header
    - Session authentication (manual import)

    Request body:
    {
        "source": "pdq_inventory",  // Optional source identifier
        "organization_id": 1,       // Optional, overrides integration default
        "auto_approve": false,      // Optional, auto-add without review
        "software": [
            {
                "vendor": "Microsoft",
                "product": "Office",
                "version": "365",
                "install_count": 50,     // Optional metadata
                "hostnames": ["PC1"]     // Optional metadata
            }
        ]
    }
    """
    data = request.get_json()

    if not data:
        return jsonify({'error': 'No data provided'}), 400

    software_list = data.get('software', [])
    if not software_list:
        return jsonify({'error': 'No software items provided'}), 400

    # Determine integration and organization
    integration = getattr(request, 'integration', None)
    org_id = data.get('organization_id')

    if not org_id and integration:
        org_id = integration.organization_id

    # Validate organization if specified
    if org_id:
        org = Organization.query.get(org_id)
        if not org:
            return jsonify({'error': f'Organization {org_id} not found'}), 404

    auto_approve = data.get('auto_approve', False)
    if integration and integration.auto_approve:
        auto_approve = True

    # Process each software item
    results = {
        'queued': 0,
        'auto_approved': 0,
        'duplicates': 0,
        'errors': 0,
        'items': []
    }

    for item in software_list:
        vendor = item.get('vendor', '').strip()
        product_name = item.get('product', item.get('product_name', '')).strip()
        version = item.get('version', '').strip() or None

        if not vendor or not product_name:
            results['errors'] += 1
            continue

        # Check for existing product
        existing = Product.query.filter(
            db.func.lower(Product.vendor) == vendor.lower(),
            db.func.lower(Product.product_name) == product_name.lower()
        ).first()

        if existing:
            results['duplicates'] += 1
            results['items'].append({
                'vendor': vendor,
                'product': product_name,
                'status': 'duplicate',
                'existing_product_id': existing.id
            })
            continue

        # Check for existing queue item
        existing_queue = ImportQueue.query.filter(
            db.func.lower(ImportQueue.vendor) == vendor.lower(),
            db.func.lower(ImportQueue.product_name) == product_name.lower(),
            ImportQueue.status == 'pending'
        ).first()

        if existing_queue:
            results['duplicates'] += 1
            results['items'].append({
                'vendor': vendor,
                'product': product_name,
                'status': 'already_queued',
                'queue_id': existing_queue.id
            })
            continue

        # Try to find CPE match
        cpe_vendor, cpe_product, confidence = attempt_cpe_match(vendor, product_name)

        # Get available versions from NVD if we have a CPE match
        available_versions = []
        if cpe_vendor and cpe_product:
            available_versions = get_cpe_versions(cpe_vendor, cpe_product)

        # Build source data
        source_data = {}
        for key in ['install_count', 'hostnames', 'install_locations', 'source_hostname']:
            if key in item:
                source_data[key] = item[key]

        # Create queue item
        queue_item = ImportQueue(
            integration_id=integration.id if integration else None,
            vendor=vendor,
            product_name=product_name,
            detected_version=version,
            cpe_vendor=cpe_vendor,
            cpe_product=cpe_product,
            cpe_match_confidence=confidence,
            organization_id=org_id,
            status='pending'
        )
        queue_item.set_available_versions(available_versions)
        queue_item.set_source_data(source_data)

        db.session.add(queue_item)

        if auto_approve:
            # Auto-approve: create product immediately
            product = create_product_from_queue(queue_item)
            if product:
                queue_item.status = 'approved'
                queue_item.product_id = product.id
                queue_item.processed_at = datetime.utcnow()
                results['auto_approved'] += 1
                results['items'].append({
                    'vendor': vendor,
                    'product': product_name,
                    'status': 'auto_approved',
                    'product_id': product.id
                })
            else:
                results['queued'] += 1
                results['items'].append({
                    'vendor': vendor,
                    'product': product_name,
                    'status': 'queued',
                    'queue_id': queue_item.id
                })
        else:
            results['queued'] += 1
            results['items'].append({
                'vendor': vendor,
                'product': product_name,
                'status': 'queued'
            })

    try:
        db.session.commit()
    except Exception as e:
        db.session.rollback()
        logger.error(f"Import software commit failed: {e}")
        return jsonify({'error': 'Database error during import'}), 500

    # Update integration sync status
    if integration:
        integration.last_sync_at = datetime.utcnow()
        integration.last_sync_status = 'success'
        integration.last_sync_count = len(software_list)
        integration.last_sync_message = f"Imported {results['queued']} queued, {results['auto_approved']} auto-approved, {results['duplicates']} duplicates"
        try:
            db.session.commit()
        except Exception as e:
            db.session.rollback()
            logger.error(f"Failed to update integration sync status: {e}")

    return jsonify(results)


@bp.route('/api/import/sbom', methods=['POST'])
@api_key_or_login_required
def import_sbom():
    """
    Import software inventory from an SBOM (Software Bill of Materials).

    Supports:
    - CycloneDX JSON (1.4, 1.5, 1.6)
    - SPDX JSON (2.2, 2.3)

    The SBOM components are parsed into SentriKat's standard software format
    and routed through the normal import pipeline (review queue or auto-approve).

    Request: POST with JSON body containing the SBOM document,
             or multipart/form-data with file upload.

    Query params:
        auto_approve: true/false (default: false)
        organization_id: int (optional)
    """
    import re as _re

    integration = getattr(request, 'integration', None)
    org_id = request.args.get('organization_id', type=int)
    if not org_id and integration:
        org_id = integration.organization_id
    auto_approve = request.args.get('auto_approve', 'false').lower() == 'true'
    if integration and integration.auto_approve:
        auto_approve = True

    # Accept JSON body or file upload
    sbom_data = None
    if request.content_type and 'multipart/form-data' in request.content_type:
        f = request.files.get('file') or request.files.get('sbom')
        if not f:
            return jsonify({'error': 'No file uploaded. Use field name "file" or "sbom".'}), 400
        try:
            import json as _json
            sbom_data = _json.loads(f.read().decode('utf-8'))
        except Exception as e:
            return jsonify({'error': f'Invalid JSON in uploaded file: {e}'}), 400
    else:
        sbom_data = request.get_json()

    if not sbom_data or not isinstance(sbom_data, dict):
        return jsonify({'error': 'Request body must be a JSON SBOM document'}), 400

    # Detect SBOM format
    software_list = []

    if sbom_data.get('bomFormat') == 'CycloneDX' or 'components' in sbom_data:
        # ── CycloneDX ──
        spec_version = sbom_data.get('specVersion', 'unknown')
        components = sbom_data.get('components', [])

        if not components:
            return jsonify({'error': 'CycloneDX SBOM has no components'}), 400

        for comp in components:
            comp_type = comp.get('type', 'library')
            name = comp.get('name', '').strip()
            version = comp.get('version', '').strip() or None
            group = comp.get('group', '').strip()
            publisher = comp.get('publisher', '').strip()
            purl = comp.get('purl', '')

            if not name:
                continue

            # Extract vendor from group, publisher, or purl
            vendor = publisher or group or ''
            if not vendor and purl:
                # Parse purl: pkg:npm/@scope/name@version or pkg:pypi/name@version
                purl_match = _re.match(r'pkg:([^/]+)/(?:@([^/]+)/)?([^@]+)(?:@(.+))?', purl)
                if purl_match:
                    ecosystem = purl_match.group(1)
                    scope = purl_match.group(2)
                    vendor = scope or ecosystem
                    if not version and purl_match.group(4):
                        version = purl_match.group(4)

            if not vendor:
                vendor = name.split('/')[0] if '/' in name else name

            software_list.append({
                'vendor': vendor,
                'product': name,
                'version': version,
                'source_type': 'sbom_cyclonedx',
                'source_detail': f'CycloneDX {spec_version}, type={comp_type}',
            })

    elif sbom_data.get('spdxVersion') or 'packages' in sbom_data:
        # ── SPDX ──
        spdx_version = sbom_data.get('spdxVersion', 'unknown')
        packages = sbom_data.get('packages', [])

        if not packages:
            return jsonify({'error': 'SPDX SBOM has no packages'}), 400

        for pkg in packages:
            name = pkg.get('name', '').strip()
            version = pkg.get('versionInfo', '').strip() or None
            supplier = pkg.get('supplier', '').strip()
            originator = pkg.get('originator', '').strip()

            if not name:
                continue

            # Extract vendor from supplier/originator
            vendor = ''
            for field in [supplier, originator]:
                if field:
                    # SPDX format: "Organization: Name" or "Person: Name"
                    v = _re.sub(r'^(Organization|Person|Tool):\s*', '', field).strip()
                    if v:
                        vendor = v
                        break

            if not vendor:
                # Try to extract from external references
                for ref in pkg.get('externalRefs', []):
                    if ref.get('referenceType') == 'purl':
                        purl = ref.get('referenceLocator', '')
                        purl_match = _re.match(r'pkg:([^/]+)/(?:@([^/]+)/)?([^@]+)', purl)
                        if purl_match:
                            vendor = purl_match.group(2) or purl_match.group(1)
                            break

            if not vendor:
                vendor = name

            software_list.append({
                'vendor': vendor,
                'product': name,
                'version': version,
                'source_type': 'sbom_spdx',
                'source_detail': f'SPDX {spdx_version}',
            })
    else:
        return jsonify({
            'error': 'Unrecognized SBOM format. Supported: CycloneDX JSON, SPDX JSON.',
            'hint': 'CycloneDX must have "bomFormat": "CycloneDX". SPDX must have "spdxVersion".'
        }), 400

    if not software_list:
        return jsonify({'error': 'No valid software components found in SBOM'}), 400

    # Route through existing import pipeline
    results = {
        'format': 'cyclonedx' if 'bomFormat' in sbom_data else 'spdx',
        'total_components': len(software_list),
        'queued': 0,
        'auto_approved': 0,
        'duplicates': 0,
        'errors': 0,
    }

    for item in software_list:
        vendor = item['vendor']
        product_name = item['product']
        version = item.get('version')

        if not vendor or not product_name:
            results['errors'] += 1
            continue

        # Check for existing product
        existing = Product.query.filter(
            db.func.lower(Product.vendor) == vendor.lower(),
            db.func.lower(Product.product_name) == product_name.lower()
        ).first()

        if existing:
            results['duplicates'] += 1
            continue

        # Create import queue entry
        source_data = {
            'source_type': item.get('source_type'),
            'source_detail': item.get('source_detail'),
        }

        queue_item = ImportQueue(
            vendor=vendor,
            product_name=product_name,
            detected_version=version,
            organization_id=org_id,
            status='pending' if not auto_approve else 'approved'
        )
        queue_item.set_source_data(source_data)
        db.session.add(queue_item)

        if auto_approve:
            product = create_product_from_queue(queue_item)
            if product:
                queue_item.status = 'approved'
                queue_item.product_id = product.id
                queue_item.processed_at = datetime.utcnow()
                results['auto_approved'] += 1
            else:
                results['queued'] += 1
        else:
            results['queued'] += 1

    try:
        db.session.commit()
    except Exception as e:
        db.session.rollback()
        logger.error(f"SBOM import commit failed: {e}")
        return jsonify({'error': 'Database error during SBOM import'}), 500

    return jsonify(results)


def attempt_cpe_match(vendor, product_name):
    """
    Attempt to find matching CPE via NVD API search (the actual API call).

    This is the NVD fallback tier - called by get_cpe_for_software() when
    local mappings (user-learned + curated) don't match.

    IMPORTANT: This function must NOT call get_cpe_for_software() to avoid
    circular recursion. It only does the NVD API lookup.

    Returns (cpe_vendor, cpe_product, confidence) tuple.
    """
    try:
        from app.nvd_cpe_api import search_cpe

        # Build search query from vendor + product name
        search_terms = []
        if vendor:
            search_terms.append(vendor.strip())
        if product_name:
            search_terms.append(product_name.strip())

        search_query = ' '.join(search_terms)
        if not search_query or len(search_query) < 2:
            return None, None, 0.0

        results = search_cpe(search_query, limit=10)

        if not results:
            return None, None, 0.0

        # Find best match from NVD results
        best_match = None
        best_score = 0.0

        vendor_lower = (vendor or '').lower().strip()
        product_lower = (product_name or '').lower().strip()

        for result in results:
            nvd_vendor = (result.get('vendor') or '').lower()
            nvd_product = (result.get('product') or '').lower()

            score = 0.0

            # Vendor match scoring
            if vendor_lower and nvd_vendor:
                if vendor_lower == nvd_vendor:
                    score += 0.4
                elif vendor_lower in nvd_vendor or nvd_vendor in vendor_lower:
                    score += 0.25

            # Product match scoring
            if product_lower and nvd_product:
                if product_lower == nvd_product:
                    score += 0.5
                elif product_lower in nvd_product or nvd_product in product_lower:
                    score += 0.3
                else:
                    sim = calculate_similarity(product_lower, nvd_product)
                    score += sim * 0.3

            if score > best_score:
                best_score = score
                best_match = result

        if best_match and best_score >= 0.3:
            return best_match['vendor'], best_match['product'], min(best_score, 0.85)

        return None, None, 0.0

    except Exception as e:
        import logging
        logging.getLogger(__name__).warning(f"NVD CPE match failed for {vendor} {product_name}: {e}")
        return None, None, 0.0


def calculate_similarity(s1, s2):
    """Calculate string similarity (0.0 - 1.0)."""
    s1 = s1.lower()
    s2 = s2.lower()

    if s1 == s2:
        return 1.0

    if s1 in s2 or s2 in s1:
        return 0.8

    # Simple character overlap
    set1 = set(s1)
    set2 = set(s2)
    intersection = len(set1 & set2)
    union = len(set1 | set2)

    if union == 0:
        return 0.0

    return intersection / union


def get_cpe_versions(cpe_vendor, cpe_product):
    """Get available versions for a CPE vendor/product pair."""
    try:
        from app.nvd_cpe_api import search_cpe_grouped

        results = search_cpe_grouped(f"{cpe_vendor} {cpe_product}", limit=5)

        if cpe_vendor in results:
            products = results[cpe_vendor].get('products', {})
            if cpe_product in products:
                return products[cpe_product].get('versions', [])[:20]

        return []
    except Exception:
        return []


def create_product_from_queue(queue_item):
    """Create a Product from an ImportQueue item."""
    try:
        product = Product(
            vendor=queue_item.vendor,
            product_name=queue_item.product_name,
            version=queue_item.selected_version or queue_item.detected_version,
            organization_id=queue_item.organization_id,
            cpe_vendor=queue_item.cpe_vendor,
            cpe_product=queue_item.cpe_product,
            active=True
        )
        db.session.add(product)
        db.session.flush()  # Get the ID

        # Add to product_organizations many-to-many table for proper org tracking
        if queue_item.organization_id:
            org = Organization.query.get(queue_item.organization_id)
            if org and org not in product.organizations:
                product.organizations.append(org)

        return product
    except IntegrityError as e:
        db.session.rollback()
        logger.warning(f"Duplicate product from queue: {queue_item.vendor} {queue_item.product_name}: {e}")
        return None
    except Exception as e:
        db.session.rollback()
        logger.error(f"Failed to create product from queue item {queue_item.id}: {e}")
        return None


# ============================================================================
# Import Queue Management
# ============================================================================

@bp.route('/api/import/queue', methods=['GET'])
@login_required
@requires_professional('Integrations')
def get_import_queue():
    """Get pending import queue items."""
    status = request.args.get('status', 'pending')
    integration_id = request.args.get('integration_id', type=int)
    org_id = request.args.get('organization_id', type=int)
    vendor = request.args.get('vendor', '').strip()
    search = request.args.get('search', '').strip()
    limit = request.args.get('limit', 100, type=int)
    offset = request.args.get('offset', 0, type=int)

    query = ImportQueue.query

    if status:
        query = query.filter_by(status=status)
    if integration_id:
        query = query.filter_by(integration_id=integration_id)
    if org_id:
        query = query.filter_by(organization_id=org_id)
    if vendor:
        query = query.filter(ImportQueue.vendor == vendor)
    if search:
        search_filter = f"%{search}%"
        query = query.filter(
            db.or_(
                ImportQueue.vendor.ilike(search_filter),
                ImportQueue.product_name.ilike(search_filter)
            )
        )

    total = query.count()
    items = query.order_by(ImportQueue.created_at.desc()).offset(offset).limit(limit).all()

    return jsonify({
        'total': total,
        'items': [item.to_dict() for item in items]
    })


@bp.route('/api/import/queue/count', methods=['GET'])
@login_required
@requires_professional('Integrations')
def get_import_queue_count():
    """Get count of pending import queue items."""
    user = get_current_user()
    query = ImportQueue.query.filter_by(status='pending')

    if user and not user.is_super_admin():
        accessible_org_ids = [o['id'] for o in user.get_all_organizations()]
        query = query.filter(ImportQueue.organization_id.in_(accessible_org_ids))

    pending_count = query.count()
    return jsonify({'pending': pending_count})


@bp.route('/api/import/queue/<int:item_id>', methods=['GET'])
@login_required
@requires_professional('Integrations')
def get_queue_item(item_id):
    """Get a specific queue item."""
    item = ImportQueue.query.get_or_404(item_id)
    return jsonify(item.to_dict())


@bp.route('/api/import/queue/<int:item_id>', methods=['PUT'])
@login_required
@requires_professional('Integrations')
def update_queue_item(item_id):
    """Update a queue item (change version, org)."""
    item = ImportQueue.query.get_or_404(item_id)
    data = request.get_json()

    if item.status != 'pending':
        return jsonify({'error': 'Can only update pending items'}), 400

    if 'selected_version' in data:
        item.selected_version = data['selected_version'] or None
    if 'organization_id' in data:
        user = get_current_user()
        if user:
            _, err = validate_org_access(user, data['organization_id'])
            if err:
                return err
        item.organization_id = data['organization_id']
    if 'cpe_vendor' in data:
        item.cpe_vendor = data['cpe_vendor']
    if 'cpe_product' in data:
        item.cpe_product = data['cpe_product']

    try:
        db.session.commit()
    except Exception as e:
        db.session.rollback()
        logger.error(f"Failed to update queue item {item_id}: {e}")
        return jsonify({'error': 'Database error'}), 500
    return jsonify(item.to_dict())


@bp.route('/api/import/queue/<int:item_id>/approve', methods=['POST'])
@login_required
@requires_professional('Integrations')
def approve_queue_item(item_id):
    """Approve a queue item and create the product."""
    item = ImportQueue.query.get_or_404(item_id)

    if item.status != 'pending':
        return jsonify({'error': 'Item already processed'}), 400

    # Allow overriding values in the request
    data = request.get_json() or {}

    if 'selected_version' in data:
        item.selected_version = data['selected_version']
    if 'organization_id' in data:
        user = get_current_user()
        if user:
            _, err = validate_org_access(user, data['organization_id'])
            if err:
                return err
        item.organization_id = data['organization_id']

    # Create the product
    product = create_product_from_queue(item)

    if not product:
        return jsonify({'error': 'Failed to create product'}), 500

    item.status = 'approved'
    item.product_id = product.id
    item.processed_at = datetime.utcnow()
    item.processed_by = session.get('user_id')

    try:
        db.session.commit()
    except IntegrityError:
        db.session.rollback()
        # Check if another request already approved this item
        item = ImportQueue.query.get(item_id)
        if item and item.status == 'approved':
            return jsonify({
                'success': True,
                'product_id': item.product_id,
                'item': item.to_dict(),
                'message': 'Item was already approved'
            })
        return jsonify({'error': 'Conflict during approval'}), 409
    except Exception as e:
        db.session.rollback()
        logger.error(f"Failed to approve queue item {item_id}: {e}")
        return jsonify({'error': 'Database error'}), 500

    # Trigger vulnerability matching
    try:
        from app.filters import match_vulnerabilities_to_products
        match_vulnerabilities_to_products([product])
    except Exception as match_err:
        logger.warning(f"Vulnerability matching failed for product {product.id}: {match_err}")

    return jsonify({
        'success': True,
        'product_id': product.id,
        'item': item.to_dict()
    })


@bp.route('/api/import/queue/<int:item_id>/reject', methods=['POST'])
@login_required
@requires_professional('Integrations')
def reject_queue_item(item_id):
    """Reject/ignore a queue item."""
    item = ImportQueue.query.get_or_404(item_id)

    if item.status != 'pending':
        return jsonify({'error': 'Item already processed'}), 400

    item.status = 'rejected'
    item.processed_at = datetime.utcnow()
    item.processed_by = session.get('user_id')

    try:
        db.session.commit()
    except Exception as e:
        db.session.rollback()
        logger.error(f"Failed to reject queue item {item_id}: {e}")
        return jsonify({'error': 'Database error'}), 500

    return jsonify({'success': True, 'item': item.to_dict()})


@bp.route('/api/import/queue/bulk', methods=['POST'])
@login_required
@requires_professional('Integrations')
def bulk_process_queue():
    """Bulk approve or reject queue items."""
    data = request.get_json()

    if not data:
        return jsonify({'error': 'No data provided'}), 400

    action = data.get('action')  # 'approve' or 'reject'
    item_ids = data.get('item_ids', [])
    organization_id = data.get('organization_id')

    if action not in ['approve', 'reject']:
        return jsonify({'error': 'Invalid action. Use "approve" or "reject"'}), 400

    if not item_ids:
        return jsonify({'error': 'No items specified'}), 400

    # Validate org access if organization_id override is provided
    if organization_id:
        user = get_current_user()
        if user:
            _, err = validate_org_access(user, organization_id)
            if err:
                return err

    results = {'processed': 0, 'errors': 0, 'products': []}

    for item_id in item_ids:
        item = ImportQueue.query.get(item_id)
        if not item or item.status != 'pending':
            results['errors'] += 1
            continue

        if action == 'approve':
            if organization_id:
                item.organization_id = organization_id

            product = create_product_from_queue(item)
            if product:
                item.status = 'approved'
                item.product_id = product.id
                item.processed_at = datetime.utcnow()
                item.processed_by = session.get('user_id')
                results['processed'] += 1
                results['products'].append(product.id)
            else:
                results['errors'] += 1
        else:
            item.status = 'rejected'
            item.processed_at = datetime.utcnow()
            item.processed_by = session.get('user_id')
            results['processed'] += 1

    try:
        db.session.commit()
    except Exception as e:
        db.session.rollback()
        logger.error(f"Bulk process commit failed: {e}")
        return jsonify({'error': 'Database error during bulk processing'}), 500

    # Trigger vulnerability matching for approved products
    if results['products']:
        try:
            from app.filters import match_vulnerabilities_to_products
            products = Product.query.filter(Product.id.in_(results['products'])).all()
            match_vulnerabilities_to_products(products)
        except Exception as e:
            logger.warning(f"Vulnerability matching failed during bulk process: {e}")

    return jsonify(results)


@bp.route('/api/import/queue/approve-all', methods=['POST'])
@admin_required
@requires_professional('Integrations')
def approve_all_queue():
    """Approve all pending import queue items, optionally filtered by vendor or organization."""
    data = request.get_json() or {}
    vendor_filter = data.get('vendor')
    org_filter = data.get('organization_id')

    query = ImportQueue.query.filter_by(status='pending')
    if vendor_filter:
        query = query.filter(ImportQueue.vendor == vendor_filter)
    if org_filter:
        query = query.filter(ImportQueue.organization_id == org_filter)

    items = query.all()
    if not items:
        return jsonify({'processed': 0, 'message': 'No pending items to approve'})

    results = {'processed': 0, 'errors': 0, 'products': []}

    for item in items:
        product = create_product_from_queue(item)
        if product:
            item.status = 'approved'
            item.product_id = product.id
            item.processed_at = datetime.utcnow()
            item.processed_by = session.get('user_id')
            results['processed'] += 1
            results['products'].append(product.id)
        else:
            results['errors'] += 1

    try:
        db.session.commit()
    except Exception as e:
        db.session.rollback()
        logger.error(f"Approve-all commit failed: {e}")
        return jsonify({'error': 'Database error during batch approval'}), 500

    # Trigger vulnerability matching in batches
    if results['products']:
        try:
            from app.filters import match_vulnerabilities_to_products
            products = Product.query.filter(Product.id.in_(results['products'])).all()
            match_vulnerabilities_to_products(products)
        except Exception as e:
            logger.warning(f"Vulnerability matching failed during approve-all: {e}")

    return jsonify(results)


@bp.route('/api/import/queue/reject-all', methods=['POST'])
@admin_required
@requires_professional('Integrations')
def reject_all_queue():
    """Reject all pending import queue items, optionally filtered by vendor or organization."""
    data = request.get_json() or {}
    vendor_filter = data.get('vendor')
    org_filter = data.get('organization_id')

    query = ImportQueue.query.filter_by(status='pending')
    if vendor_filter:
        query = query.filter(ImportQueue.vendor == vendor_filter)
    if org_filter:
        query = query.filter(ImportQueue.organization_id == org_filter)

    count = query.count()
    if count == 0:
        return jsonify({'processed': 0, 'message': 'No pending items to reject'})

    try:
        query.update({
            ImportQueue.status: 'rejected',
            ImportQueue.processed_at: datetime.utcnow(),
            ImportQueue.processed_by: session.get('user_id')
        }, synchronize_session='fetch')
        db.session.commit()
    except Exception as e:
        db.session.rollback()
        logger.error(f"Reject-all commit failed: {e}")
        return jsonify({'error': 'Database error during batch rejection'}), 500

    return jsonify({'processed': count})


@bp.route('/api/import/queue/vendors', methods=['GET'])
@login_required
@requires_professional('Integrations')
def get_queue_vendors():
    """Get list of vendors with pending items and their counts."""
    from sqlalchemy import func

    user = get_current_user()
    query = db.session.query(
        ImportQueue.vendor,
        func.count(ImportQueue.id)
    ).filter_by(
        status='pending'
    )

    if user and not user.is_super_admin():
        accessible_org_ids = [o['id'] for o in user.get_all_organizations()]
        query = query.filter(ImportQueue.organization_id.in_(accessible_org_ids))

    vendor_counts = query.group_by(
        ImportQueue.vendor
    ).order_by(
        func.count(ImportQueue.id).desc()
    ).all()

    return jsonify({
        'vendors': [
            {'vendor': v, 'count': c}
            for v, c in vendor_counts
        ]
    })


# ============================================================================
# Integration Management
# ============================================================================

@bp.route('/api/integrations', methods=['GET'])
@admin_required
@requires_professional('Integrations')
def get_integrations():
    """Get all integrations."""
    user = get_current_user()
    if not user:
        return jsonify({'error': 'Authentication required'}), 401

    # Filter by organization for non-super-admin users
    if user.is_super_admin():
        org_id = request.args.get('organization_id', type=int)
        if org_id:
            integrations = Integration.query.filter_by(is_active=True, organization_id=org_id).order_by(Integration.name).all()
        else:
            integrations = Integration.query.filter_by(is_active=True).order_by(Integration.name).all()
    else:
        org_id = request.args.get('organization_id', type=int)
        if not org_id:
            return jsonify({'error': 'organization_id required'}), 400

        # Check permission - user must be org_admin/manager either globally or in this org
        has_permission = False

        # Check global role first
        if user.role in ['org_admin', 'manager']:
            # Check if user belongs to this org (primary org or membership)
            if user.organization_id == org_id:
                has_permission = True
            else:
                user_org = user.org_memberships.filter_by(organization_id=org_id).first()
                if user_org:
                    has_permission = True
        else:
            # Check org-specific role
            user_org = user.org_memberships.filter_by(organization_id=org_id).first()
            if user_org and user_org.role in ['org_admin', 'manager']:
                has_permission = True

        if not has_permission:
            return jsonify({'error': 'Organization admin or manager access required'}), 403

        integrations = Integration.query.filter_by(is_active=True, organization_id=org_id).order_by(Integration.name).all()

    return jsonify([i.to_dict() for i in integrations])


@bp.route('/api/integrations/<int:integration_id>', methods=['GET'])
@admin_required
@requires_professional('Integrations')
def get_integration(integration_id):
    """Get a specific integration."""
    integration = Integration.query.get_or_404(integration_id)
    # Include sensitive data for editing
    return jsonify(integration.to_dict(include_sensitive=True))


@bp.route('/api/integrations', methods=['POST'])
@admin_required
@requires_professional('Integrations')
def create_integration():
    """Create a new integration."""
    data = request.get_json()

    if not data:
        return jsonify({'error': 'No data provided'}), 400

    name = data.get('name', '').strip()
    integration_type = data.get('integration_type', '').strip()

    if not name:
        return jsonify({'error': 'Name is required'}), 400
    if not integration_type:
        return jsonify({'error': 'Integration type is required'}), 400

    valid_types = ['pdq', 'sccm', 'intune', 'lansweeper', 'csv', 'generic_rest', 'agent']
    if integration_type not in valid_types:
        return jsonify({'error': f'Invalid type. Valid types: {", ".join(valid_types)}'}), 400

    # Validate organization_id if provided
    org_id = data.get('organization_id')
    if org_id:
        user = get_current_user()
        if user:
            _, err = validate_org_access(user, org_id)
            if err:
                return err

    # Generate API key for push integrations
    api_key = secrets.token_urlsafe(32)

    integration = Integration(
        name=name,
        integration_type=integration_type,
        organization_id=org_id,
        auto_approve=data.get('auto_approve', False),
        sync_enabled=data.get('sync_enabled', True),
        sync_interval_hours=data.get('sync_interval_hours', 6),
        api_key=api_key,
        created_by=session.get('user_id')
    )

    # Store configuration (encrypted)
    config = data.get('config', {})
    if config:
        integration.set_config(config)

    db.session.add(integration)
    try:
        db.session.commit()
    except Exception as e:
        db.session.rollback()
        logger.error(f"Failed to create integration: {e}")
        return jsonify({'error': 'Failed to create integration'}), 500

    return jsonify(integration.to_dict(include_sensitive=True)), 201


@bp.route('/api/integrations/<int:integration_id>', methods=['PUT'])
@admin_required
@requires_professional('Integrations')
def update_integration(integration_id):
    """Update an integration."""
    integration = Integration.query.get_or_404(integration_id)
    data = request.get_json()

    if not data:
        return jsonify({'error': 'No data provided'}), 400

    if 'name' in data:
        integration.name = data['name'].strip()
    if 'organization_id' in data:
        user = get_current_user()
        if user:
            _, err = validate_org_access(user, data['organization_id'])
            if err:
                return err
        integration.organization_id = data['organization_id']
    if 'auto_approve' in data:
        integration.auto_approve = data['auto_approve']
    if 'sync_enabled' in data:
        integration.sync_enabled = data['sync_enabled']
    if 'sync_interval_hours' in data:
        integration.sync_interval_hours = data['sync_interval_hours']
    if 'config' in data:
        integration.set_config(data['config'])

    try:
        db.session.commit()
    except Exception as e:
        db.session.rollback()
        logger.error(f"Failed to update integration {integration_id}: {e}")
        return jsonify({'error': 'Failed to update integration'}), 500

    return jsonify(integration.to_dict(include_sensitive=True))


@bp.route('/api/integrations/<int:integration_id>', methods=['DELETE'])
@admin_required
@requires_professional('Integrations')
def delete_integration(integration_id):
    """Delete (deactivate) an integration."""
    integration = Integration.query.get_or_404(integration_id)

    integration.is_active = False
    try:
        db.session.commit()
    except Exception as e:
        db.session.rollback()
        logger.error(f"Failed to delete integration {integration_id}: {e}")
        return jsonify({'error': 'Failed to delete integration'}), 500

    return jsonify({'success': True})


@bp.route('/api/integrations/<int:integration_id>/regenerate-key', methods=['POST'])
@admin_required
@requires_professional('Integrations')
def regenerate_api_key(integration_id):
    """Regenerate API key for an integration."""
    integration = Integration.query.get_or_404(integration_id)

    integration.api_key = secrets.token_urlsafe(32)
    try:
        db.session.commit()
    except Exception as e:
        db.session.rollback()
        logger.error(f"Failed to regenerate API key for integration {integration_id}: {e}")
        return jsonify({'error': 'Failed to regenerate API key'}), 500

    return jsonify({
        'success': True,
        'api_key': integration.api_key
    })


@bp.route('/api/integrations/<int:integration_id>/test', methods=['POST'])
@admin_required
@requires_professional('Integrations')
def test_integration(integration_id):
    """Test connection to an integration."""
    integration = Integration.query.get_or_404(integration_id)

    if integration.integration_type == 'agent':
        # Agent integrations don't have outbound connections to test
        return jsonify({
            'success': True,
            'message': 'Agent integration - waiting for agents to connect'
        })

    # For pull integrations, test the connection
    try:
        from app.integration_connectors import test_connector
        result = test_connector(integration)
        return jsonify(result)
    except Exception as e:
        return jsonify({
            'success': False,
            'error': str(e)
        })


@bp.route('/api/integrations/<int:integration_id>/sync', methods=['POST'])
@admin_required
@requires_professional('Integrations')
def trigger_sync(integration_id):
    """Manually trigger a sync for a pull integration."""
    integration = Integration.query.get_or_404(integration_id)

    if integration.integration_type == 'agent':
        return jsonify({'error': 'Agent integrations cannot be manually synced'}), 400

    try:
        from app.integration_connectors import sync_integration
        result = sync_integration(integration)
        return jsonify(result)
    except Exception as e:
        integration.last_sync_status = 'failed'
        integration.last_sync_message = str(e)
        integration.last_sync_at = datetime.utcnow()
        try:
            db.session.commit()
        except Exception:
            db.session.rollback()
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500


# ============================================================================
# Agent Registration and Reporting
# ============================================================================

@bp.route('/api/agent/register', methods=['POST'])
@api_key_or_login_required
def register_agent():
    """
    Register a new discovery agent.

    Called by agents on first startup.
    Requires integration API key.
    """
    integration = getattr(request, 'integration', None)

    if not integration:
        return jsonify({'error': 'Valid integration API key required'}), 401

    if integration.integration_type != 'agent':
        return jsonify({'error': 'API key is not for an agent integration'}), 400

    data = request.get_json()

    if not data:
        return jsonify({'error': 'No data provided'}), 400

    hostname = data.get('hostname', '').strip()
    os_type = data.get('os_type', '').strip().lower()

    if not hostname:
        return jsonify({'error': 'Hostname is required'}), 400
    if os_type not in ['windows', 'linux', 'macos']:
        return jsonify({'error': 'Invalid os_type. Use: windows, linux, macos'}), 400

    # Check for existing agent with same hostname
    existing = AgentRegistration.query.filter_by(
        hostname=hostname,
        integration_id=integration.id
    ).first()

    if existing:
        # Update existing agent
        existing.os_version = data.get('os_version')
        existing.os_arch = data.get('os_arch')
        existing.agent_version = data.get('agent_version')
        existing.last_seen_at = datetime.utcnow()
        existing.ip_address = request.remote_addr
        existing.is_active = True
        if data.get('system_info'):
            existing.set_system_info(data['system_info'])

        try:
            db.session.commit()
        except Exception as e:
            db.session.rollback()
            logger.error(f"Failed to update agent {existing.agent_id}: {e}")
            return jsonify({'error': 'Failed to update agent'}), 500

        return jsonify({
            'success': True,
            'agent_id': existing.agent_id,
            'message': 'Agent updated'
        })

    # Create new agent
    agent = AgentRegistration(
        agent_id=str(uuid.uuid4()),
        hostname=hostname,
        os_type=os_type,
        os_version=data.get('os_version'),
        os_arch=data.get('os_arch'),
        agent_version=data.get('agent_version'),
        integration_id=integration.id,
        organization_id=integration.organization_id,
        last_seen_at=datetime.utcnow(),
        ip_address=request.remote_addr
    )

    if data.get('system_info'):
        agent.set_system_info(data['system_info'])

    db.session.add(agent)
    try:
        db.session.commit()
    except IntegrityError:
        db.session.rollback()
        # Race condition: another request registered same agent
        existing = AgentRegistration.query.filter_by(
            hostname=hostname,
            integration_id=integration.id
        ).first()
        if existing:
            return jsonify({
                'success': True,
                'agent_id': existing.agent_id,
                'message': 'Agent already registered'
            })
        return jsonify({'error': 'Agent registration conflict'}), 409
    except Exception as e:
        db.session.rollback()
        logger.error(f"Failed to register agent: {e}")
        return jsonify({'error': 'Failed to register agent'}), 500

    return jsonify({
        'success': True,
        'agent_id': agent.agent_id,
        'message': 'Agent registered'
    }), 201


@bp.route('/api/agent/report', methods=['POST'])
@api_key_or_login_required
def agent_report():
    """
    Receive software inventory report from an agent.

    Request body:
    {
        "agent_id": "uuid",
        "software": [
            {"vendor": "...", "product": "...", "version": "..."}
        ]
    }
    """
    integration = getattr(request, 'integration', None)

    if not integration:
        return jsonify({'error': 'Valid integration API key required'}), 401

    data = request.get_json()
    agent_id = data.get('agent_id')

    if not agent_id:
        return jsonify({'error': 'agent_id is required'}), 400

    # Find the agent
    agent = AgentRegistration.query.filter_by(
        agent_id=agent_id,
        integration_id=integration.id
    ).first()

    if not agent:
        return jsonify({'error': 'Agent not found. Please register first.'}), 404

    # Update agent status
    agent.last_seen_at = datetime.utcnow()
    agent.last_report_at = datetime.utcnow()
    agent.ip_address = request.remote_addr

    # Process software list (same as import API)
    software_list = data.get('software', [])
    agent.software_count = len(software_list)

    # Use the same import logic
    import_data = {
        'organization_id': agent.organization_id or integration.organization_id,
        'software': software_list
    }

    # Store original request.integration and call import logic
    results = process_software_import(integration, import_data)

    try:
        db.session.commit()
    except Exception as e:
        db.session.rollback()
        logger.error(f"Failed to process agent report for {agent_id}: {e}")
        return jsonify({'error': 'Failed to process inventory'}), 500

    return jsonify({
        'success': True,
        'agent_id': agent_id,
        'results': results
    })


def process_software_import(integration, data):
    """Process software import (shared logic for API and agent)."""
    software_list = data.get('software', [])
    org_id = data.get('organization_id')

    auto_approve = integration.auto_approve if integration else False

    results = {'queued': 0, 'auto_approved': 0, 'duplicates': 0, 'errors': 0}

    for item in software_list:
        vendor = item.get('vendor', '').strip()
        product_name = item.get('product', item.get('product_name', '')).strip()
        version = item.get('version', '').strip() or None

        if not vendor or not product_name:
            results['errors'] += 1
            continue

        # Check for existing
        existing = Product.query.filter(
            db.func.lower(Product.vendor) == vendor.lower(),
            db.func.lower(Product.product_name) == product_name.lower()
        ).first()

        if existing:
            results['duplicates'] += 1
            continue

        existing_queue = ImportQueue.query.filter(
            db.func.lower(ImportQueue.vendor) == vendor.lower(),
            db.func.lower(ImportQueue.product_name) == product_name.lower(),
            ImportQueue.status == 'pending'
        ).first()

        if existing_queue:
            results['duplicates'] += 1
            continue

        # Create queue item
        cpe_vendor, cpe_product, confidence = attempt_cpe_match(vendor, product_name)

        queue_item = ImportQueue(
            integration_id=integration.id if integration else None,
            vendor=vendor,
            product_name=product_name,
            detected_version=version,
            cpe_vendor=cpe_vendor,
            cpe_product=cpe_product,
            cpe_match_confidence=confidence,
            organization_id=org_id,
            status='pending'
        )

        db.session.add(queue_item)

        if auto_approve:
            product = create_product_from_queue(queue_item)
            if product:
                queue_item.status = 'approved'
                queue_item.product_id = product.id
                queue_item.processed_at = datetime.utcnow()
                results['auto_approved'] += 1
            else:
                results['queued'] += 1
        else:
            results['queued'] += 1

    return results


# ============================================================================
# Agent Management
# ============================================================================

@bp.route('/api/agents', methods=['GET'])
@admin_required
@requires_professional('Integrations')
def get_agents():
    """Get all registered agents."""
    user = get_current_user()
    integration_id = request.args.get('integration_id', type=int)

    query = AgentRegistration.query.filter_by(is_active=True)

    # Non-super-admins only see agents in their accessible orgs
    if user and not user.is_super_admin():
        accessible_org_ids = [o['id'] for o in user.get_all_organizations()]
        query = query.filter(AgentRegistration.organization_id.in_(accessible_org_ids))

    if integration_id:
        query = query.filter_by(integration_id=integration_id)

    agents = query.order_by(AgentRegistration.last_seen_at.desc()).all()

    return jsonify([agent.to_dict() for agent in agents])


@bp.route('/api/agents/<int:agent_id>', methods=['DELETE'])
@admin_required
@requires_professional('Integrations')
def delete_agent(agent_id):
    """Delete (deactivate) an agent."""
    agent = AgentRegistration.query.get_or_404(agent_id)
    agent.is_active = False
    try:
        db.session.commit()
    except Exception as e:
        db.session.rollback()
        logger.error(f"Failed to delete agent {agent_id}: {e}")
        return jsonify({'error': 'Failed to delete agent'}), 500
    return jsonify({'success': True})


# ============================================================================
# Agent Script Downloads (Serves Real Agents from agents/ Directory)
# ============================================================================

def _get_base_url():
    """Get the SentriKat server URL for embedding in agent scripts."""
    base_url = Config.SENTRIKAT_URL
    if not base_url:
        proto = request.headers.get('X-Forwarded-Proto', request.scheme)
        base_url = f"{proto}://{request.host}"
    return base_url.rstrip('/')


def _read_agent_script(filename):
    """Read the real agent script from the agents/ directory."""
    import os
    agents_dir = os.path.join(os.path.dirname(os.path.dirname(__file__)), 'agents')
    script_path = os.path.join(agents_dir, filename)
    if not os.path.exists(script_path):
        return None
    with open(script_path, 'r') as f:
        return f.read()


def _resolve_agent_api_key():
    """Resolve the raw agent API key from query params or database lookup.

    Accepts either:
      - api_key=<raw_key> (from recently created keys in-memory)
      - key_id=<int> (looks up encrypted_key from the database)
    """
    api_key = request.args.get('api_key', '')
    if api_key and api_key != 'YOUR_API_KEY_HERE':
        return api_key

    key_id = request.args.get('key_id', type=int)
    if key_id:
        from app.models import AgentApiKey
        from app.encryption import decrypt_value
        agent_key = AgentApiKey.query.get(key_id)
        if agent_key and agent_key.encrypted_key:
            try:
                return decrypt_value(agent_key.encrypted_key)
            except Exception as e:
                logger.warning(f"Could not decrypt API key {key_id}: {e}")
    return ''


@bp.route('/api/agents/script/windows', methods=['GET'])
@login_required
@requires_professional('Integrations')
def download_windows_agent():
    """Download Windows PowerShell agent script with embedded server URL and API key."""
    api_key = _resolve_agent_api_key()
    base_url = _get_base_url()

    script = _read_agent_script('sentrikat-agent-windows.ps1')
    if not script:
        return jsonify({'error': 'Windows agent script not found on server'}), 404

    # Inject current APP_VERSION so the agent reports the correct version
    from app.agent_api import _inject_agent_version, _get_latest_agent_versions
    script = _inject_agent_version(script, _get_latest_agent_versions().get('windows', '0.0.0'), 'windows')

    # Inject default ServerUrl into the param block
    script = script.replace(
        '[string]$ServerUrl,',
        f'[string]$ServerUrl = "{base_url}",',
        1
    )

    # Inject default ApiKey if we have one
    if api_key and api_key != 'YOUR_API_KEY_HERE':
        safe_key = api_key.replace('`', '``').replace('$', '`$').replace('"', '`"')
        script = script.replace(
            '[string]$ApiKey,',
            f'[string]$ApiKey = "{safe_key}",',
            1
        )

    return Response(
        script,
        mimetype='application/octet-stream',
        headers={'Content-Disposition': 'attachment; filename=sentrikat-agent-windows.ps1'}
    )


@bp.route('/api/agents/script/linux', methods=['GET'])
@login_required
@requires_professional('Integrations')
def download_linux_agent():
    """Download Linux Bash agent script with embedded server URL and API key."""
    api_key = _resolve_agent_api_key()
    base_url = _get_base_url()

    script = _read_agent_script('sentrikat-agent-linux.sh')
    if not script:
        return jsonify({'error': 'Linux agent script not found on server'}), 404

    # Inject current APP_VERSION so the agent reports the correct version
    from app.agent_api import _inject_agent_version, _get_latest_agent_versions
    script = _inject_agent_version(script, _get_latest_agent_versions().get('linux', '0.0.0'), 'linux')

    # Inject default SERVER_URL
    script = script.replace('SERVER_URL=""', f'SERVER_URL="{base_url}"', 1)

    # Inject default API_KEY if we have one
    if api_key and api_key != 'YOUR_API_KEY_HERE':
        safe_key = api_key.replace('\\', '\\\\').replace('$', '\\$').replace('`', '\\`').replace('"', '\\"')
        script = script.replace('API_KEY=""', f'API_KEY="{safe_key}"', 1)

    return Response(
        script,
        mimetype='application/octet-stream',
        headers={'Content-Disposition': 'attachment; filename=sentrikat-agent-linux.sh'}
    )


@bp.route('/api/agents/script/macos', methods=['GET'])
@login_required
@requires_professional('Integrations')
def download_macos_agent():
    """Download macOS Bash agent script with embedded server URL and API key."""
    api_key = _resolve_agent_api_key()
    base_url = _get_base_url()

    script = _read_agent_script('sentrikat-agent-macos.sh')
    if not script:
        return jsonify({'error': 'macOS agent script not found on server'}), 404

    # Inject current APP_VERSION so the agent reports the correct version
    from app.agent_api import _inject_agent_version, _get_latest_agent_versions
    script = _inject_agent_version(script, _get_latest_agent_versions().get('macos', '0.0.0'), 'macos')

    # Inject default SERVER_URL
    script = script.replace('SERVER_URL=""', f'SERVER_URL="{base_url}"', 1)

    # Inject default API_KEY if we have one
    if api_key and api_key != 'YOUR_API_KEY_HERE':
        safe_key = api_key.replace('\\', '\\\\').replace('$', '\\$').replace('`', '\\`').replace('"', '\\"')
        script = script.replace('API_KEY=""', f'API_KEY="{safe_key}"', 1)

    return Response(
        script,
        mimetype='application/octet-stream',
        headers={'Content-Disposition': 'attachment; filename=sentrikat-agent-macos.sh'}
    )


# ============================================================================
# Jira Integration Endpoints
# ============================================================================

@bp.route('/api/integrations/jira/test', methods=['POST'])
@admin_required
@requires_professional('Jira Integration')
def test_jira_connection():
    """Test Jira connection with provided credentials."""
    from app.jira_integration import JiraClient

    data = request.get_json()

    url = data.get('url', '').strip()
    email = data.get('email', '').strip()
    api_token = data.get('api_token', '').strip()

    if not all([url, email, api_token]):
        return jsonify({'success': False, 'error': 'URL, email, and API token are required'}), 400

    # Detect Cloud vs Server
    is_cloud = 'atlassian.net' in url.lower()

    client = JiraClient(url, email, api_token, is_cloud)
    success, message = client.test_connection()

    return jsonify({
        'success': success,
        'message': message,
        'is_cloud': is_cloud
    })


@bp.route('/api/integrations/jira/projects', methods=['GET'])
@admin_required
@requires_professional('Jira Integration')
def get_jira_projects():
    """Get available Jira projects."""
    from app.jira_integration import get_jira_client

    client = get_jira_client()
    if not client:
        return jsonify({'error': 'Jira not configured or disabled'}), 400

    projects = client.get_projects()
    return jsonify({'projects': projects})


@bp.route('/api/integrations/jira/issue-types/<project_key>', methods=['GET'])
@admin_required
@requires_professional('Jira Integration')
def get_jira_issue_types(project_key):
    """Get available issue types for a Jira project."""
    from app.jira_integration import get_jira_client

    client = get_jira_client()
    if not client:
        return jsonify({'error': 'Jira not configured or disabled'}), 400

    issue_types = client.get_issue_types(project_key)
    return jsonify({'issue_types': issue_types})


@bp.route('/api/integrations/jira/create-issue', methods=['POST'])
@login_required
@requires_professional('Jira Integration')
def create_jira_issue():
    """Create a Jira issue for a vulnerability."""
    from app.jira_integration import create_vulnerability_issue

    data = request.get_json()

    vulnerability_id = data.get('vulnerability_id')
    product_id = data.get('product_id')
    custom_summary = data.get('summary')
    custom_description = data.get('description')

    if not vulnerability_id:
        return jsonify({'error': 'vulnerability_id is required'}), 400

    success, message, issue_key = create_vulnerability_issue(
        vulnerability_id=vulnerability_id,
        product_id=product_id,
        custom_summary=custom_summary,
        custom_description=custom_description
    )

    if success:
        from app.settings_api import get_setting
        jira_url = get_setting('jira_url', '')
        issue_url = f"{jira_url.rstrip('/')}/browse/{issue_key}" if jira_url else None

        return jsonify({
            'success': True,
            'message': message,
            'issue_key': issue_key,
            'issue_url': issue_url
        })
    else:
        return jsonify({
            'success': False,
            'error': message
        }), 400


# ============================================================================
# Generic Issue Tracker Endpoints (Multi-tracker support)
# ============================================================================

@bp.route('/api/integrations/issue-tracker/config', methods=['GET'])
@login_required
def get_issue_tracker_config():
    """Get current issue tracker configuration."""
    from app.issue_trackers import get_issue_tracker_config
    config = get_issue_tracker_config()
    return jsonify(config)


@bp.route('/api/integrations/issue-tracker/test', methods=['POST'])
@admin_required
@requires_professional('Issue Tracker Integration')
def test_issue_tracker():
    """Test connection to configured issue tracker."""
    from app.issue_trackers import (
        JiraTracker, YouTrackTracker, GitHubTracker, GitLabTracker, WebhookTracker
    )
    from app.settings_api import get_setting

    data = request.get_json()
    tracker_type = data.get('type', 'disabled')

    if tracker_type == 'disabled':
        return jsonify({'success': False, 'error': 'No tracker type specified'}), 400

    # Get SSL verification setting
    verify_ssl = get_setting('verify_ssl', 'true') == 'true'

    use_saved = data.get('use_saved_token', False)

    try:
        if tracker_type == 'jira':
            url = data.get('url', '').strip()
            email = data.get('email', '').strip()
            api_token = data.get('api_token', '').strip()
            if not api_token and use_saved:
                api_token = get_setting('jira_api_token', '')
            use_pat = data.get('use_pat', False)
            if not all([url, email, api_token]):
                return jsonify({'success': False, 'error': 'URL, email, and API token required'}), 400
            tracker = JiraTracker(url, email, api_token, verify_ssl=verify_ssl, use_pat=use_pat)

        elif tracker_type == 'youtrack':
            url = data.get('url', '').strip()
            token = data.get('token', '').strip()
            if not token and use_saved:
                token = get_setting('youtrack_token', '')
            if not all([url, token]):
                return jsonify({'success': False, 'error': 'URL and token required'}), 400
            tracker = YouTrackTracker(url, token)

        elif tracker_type == 'github':
            token = data.get('token', '').strip()
            if not token and use_saved:
                token = get_setting('github_token', '')
            owner = data.get('owner', '').strip()
            repo = data.get('repo', '').strip()
            if not all([token, owner, repo]):
                return jsonify({'success': False, 'error': 'Token, owner, and repo required'}), 400
            tracker = GitHubTracker(token, owner, repo)

        elif tracker_type == 'gitlab':
            url = data.get('url', 'https://gitlab.com').strip()
            token = data.get('token', '').strip()
            if not token and use_saved:
                token = get_setting('gitlab_token', '')
            project_id = data.get('project_id', '').strip()
            if not all([token, project_id]):
                return jsonify({'success': False, 'error': 'Token and project ID required'}), 400
            tracker = GitLabTracker(url, token, project_id)

        elif tracker_type == 'webhook':
            url = data.get('url', '').strip()
            if not url:
                return jsonify({'success': False, 'error': 'Webhook URL required'}), 400
            method = data.get('method', 'POST')
            auth_type = data.get('auth_type', 'none')
            auth_value = data.get('auth_value', '')
            tracker = WebhookTracker(url, method, auth_type=auth_type, auth_value=auth_value)

        else:
            return jsonify({'success': False, 'error': f'Unknown tracker type: {tracker_type}'}), 400

        success, message = tracker.test_connection()
        return jsonify({
            'success': success,
            'message': message,
            'tracker_name': tracker.get_tracker_name()
        })

    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500


@bp.route('/api/integrations/jira/issue-types', methods=['POST'])
@admin_required
@requires_professional('Issue Tracker Integration')
def fetch_jira_issue_types_post():
    """Fetch available issue types from Jira for a specific project."""
    from app.issue_trackers import JiraTracker
    from app.settings_api import get_setting

    data = request.get_json()
    url = data.get('url', '').strip()
    email = data.get('email', '').strip()
    api_token = data.get('api_token', '').strip()
    project_key = data.get('project_key', '').strip()
    use_pat = data.get('use_pat', False)

    if not all([url, email, api_token, project_key]):
        return jsonify({'error': 'URL, email, token, and project key required'}), 400

    # Get SSL verification setting
    verify_ssl = get_setting('verify_ssl', 'true') == 'true'

    try:
        tracker = JiraTracker(url, email, api_token, verify_ssl=verify_ssl, use_pat=use_pat)
        issue_types = tracker.get_issue_types(project_key)

        if not issue_types:
            return jsonify({
                'issue_types': [],
                'warning': f'No issue types found for project {project_key}. Check the project key exists.'
            })

        return jsonify({'issue_types': issue_types})

    except Exception as e:
        return jsonify({'error': str(e)}), 500


@bp.route('/api/integrations/jira/fields', methods=['POST'])
@admin_required
@requires_professional('Issue Tracker Integration')
def fetch_jira_create_fields():
    """Fetch required and optional fields for creating an issue in Jira."""
    from app.issue_trackers import JiraTracker
    from app.settings_api import get_setting
    import logging
    logger = logging.getLogger(__name__)

    data = request.get_json()
    url = data.get('url', '').strip()
    email = data.get('email', '').strip()
    api_token = data.get('api_token', '').strip()
    project_key = data.get('project_key', '').strip()
    issue_type = data.get('issue_type', '').strip()
    use_pat = data.get('use_pat', False)

    # Fall back to saved credentials if not provided in request
    if not url:
        url = get_setting('jira_url', '')
    if not email:
        email = get_setting('jira_email', '')
    if not api_token:
        api_token = get_setting('jira_api_token', '')
    if not project_key:
        project_key = get_setting('jira_project_key', '')
    if not issue_type:
        issue_type = get_setting('jira_issue_type', 'Task')
    if not use_pat:
        use_pat = get_setting('jira_use_pat', 'false') == 'true'

    if not all([url, email, api_token, project_key, issue_type]):
        missing = []
        if not url: missing.append('URL')
        if not email: missing.append('email/username')
        if not api_token: missing.append('token/password')
        if not project_key: missing.append('project key')
        if not issue_type: missing.append('issue type')
        return jsonify({'error': f'Missing: {", ".join(missing)}. Save settings first or enter credentials.'}), 400

    # Get SSL verification setting
    verify_ssl = get_setting('verify_ssl', 'true') == 'true'

    try:
        logger.info(f"Fetching Jira fields for project={project_key}, issue_type={issue_type}")
        tracker = JiraTracker(url, email, api_token, verify_ssl=verify_ssl, use_pat=use_pat)
        fields = tracker.get_create_fields(project_key, issue_type)

        logger.info(f"Got {len(fields)} fields from Jira createmeta")

        # Separate required and optional fields
        # Note: Some fields might not be marked as required in createmeta but are enforced by Jira
        required_fields = [f for f in fields if f.get('required')]
        optional_fields = [f for f in fields if not f.get('required')]

        # Log field names for debugging
        if fields:
            field_names = [f"{f['name']} ({f['key']}, req={f['required']})" for f in fields[:10]]
            logger.info(f"Sample fields: {field_names}")

        return jsonify({
            'fields': fields,
            'required_fields': required_fields,
            'optional_fields': optional_fields,
            'total': len(fields),
            'required_count': len(required_fields),
            'note': 'Some fields may be required by Jira workflows even if not marked as required here.'
        })

    except Exception as e:
        logger.error(f"Error fetching Jira fields: {e}", exc_info=True)
        return jsonify({'error': str(e)}), 500


@bp.route('/api/integrations/jira/projects', methods=['POST'])
@admin_required
@requires_professional('Issue Tracker Integration')
def fetch_jira_projects_post():
    """Fetch available projects from Jira."""
    from app.issue_trackers import JiraTracker
    from app.settings_api import get_setting

    data = request.get_json()
    url = data.get('url', '').strip()
    email = data.get('email', '').strip()
    api_token = data.get('api_token', '').strip()
    use_pat = data.get('use_pat', False)

    if not all([url, email, api_token]):
        return jsonify({'error': 'URL, email, and token required'}), 400

    # Get SSL verification setting
    verify_ssl = get_setting('verify_ssl', 'true') == 'true'

    try:
        tracker = JiraTracker(url, email, api_token, verify_ssl=verify_ssl, use_pat=use_pat)
        projects = tracker.get_projects()

        if not projects:
            return jsonify({
                'projects': [],
                'warning': 'No projects found. Check your credentials and permissions.'
            })

        return jsonify({'projects': projects})

    except Exception as e:
        return jsonify({'error': str(e)}), 500


@bp.route('/api/integrations/issue-tracker/create-issue', methods=['POST'])
@login_required
@requires_professional('Issue Tracker Integration')
def create_issue_generic():
    """Create an issue using the configured tracker."""
    from app.issue_trackers import create_vulnerability_issue

    data = request.get_json()

    vulnerability_id = data.get('vulnerability_id')
    product_id = data.get('product_id')
    custom_summary = data.get('summary')
    custom_description = data.get('description')

    if not vulnerability_id:
        return jsonify({'error': 'vulnerability_id is required'}), 400

    tracker_type = data.get('tracker_type')  # Optional: specify which tracker to use

    success, message, issue_key, issue_url = create_vulnerability_issue(
        vulnerability_id=vulnerability_id,
        product_id=product_id,
        custom_summary=custom_summary,
        custom_description=custom_description,
        tracker_type=tracker_type
    )

    if success:
        return jsonify({
            'success': True,
            'message': message,
            'issue_key': issue_key,
            'issue_url': issue_url
        })
    else:
        return jsonify({
            'success': False,
            'error': message
        }), 400


@bp.route('/api/integrations/youtrack/projects', methods=['GET'])
@admin_required
@requires_professional('Issue Tracker Integration')
def get_youtrack_projects():
    """Get available YouTrack projects."""
    from app.issue_trackers import YouTrackTracker
    from app.settings_api import get_setting
    # Note: get_setting() already handles decryption for encrypted settings

    url = get_setting('youtrack_url', '')
    # get_setting() returns decrypted value for encrypted settings
    token = get_setting('youtrack_token', '')

    if not all([url, token]):
        return jsonify({'error': 'YouTrack not configured'}), 400

    tracker = YouTrackTracker(url, token)
    projects = tracker.get_projects()
    return jsonify({'projects': projects})
