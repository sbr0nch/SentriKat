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
from functools import wraps

from app import db, csrf
from app.integrations_models import Integration, ImportQueue, AgentRegistration
from app.models import Product, Organization, User
from app.auth import admin_required, login_required
from app.licensing import requires_professional

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

    db.session.commit()

    # Update integration sync status
    if integration:
        integration.last_sync_at = datetime.utcnow()
        integration.last_sync_status = 'success'
        integration.last_sync_count = len(software_list)
        integration.last_sync_message = f"Imported {results['queued']} queued, {results['auto_approved']} auto-approved, {results['duplicates']} duplicates"
        db.session.commit()

    return jsonify(results)


def attempt_cpe_match(vendor, product_name):
    """
    Attempt to find matching CPE vendor/product for given software.
    Uses a multi-tier approach:
    1. User-learned mappings (from confirmed assignments)
    2. Curated mapping database (fast, reliable)
    3. NVD API search (slow, less reliable fallback)

    Returns (cpe_vendor, cpe_product, confidence) tuple.
    """
    try:
        from app.cpe_mappings import get_cpe_for_software, get_user_mapping

        # First check user-learned mappings
        user_cpe_vendor, user_cpe_product = get_user_mapping(vendor, product_name)
        if user_cpe_vendor and user_cpe_product:
            return user_cpe_vendor, user_cpe_product, 0.98  # High confidence for user mappings

        # Use curated mappings with NVD fallback
        cpe_vendor, cpe_product, confidence = get_cpe_for_software(
            vendor, product_name, use_nvd_fallback=True
        )

        if cpe_vendor and cpe_product:
            return cpe_vendor, cpe_product, confidence

        return None, None, 0.0

    except Exception as e:
        import logging
        logging.getLogger(__name__).warning(f"CPE match failed for {vendor} {product_name}: {e}")
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
    except:
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
            from app.models import Organization
            org = Organization.query.get(queue_item.organization_id)
            if org and org not in product.organizations:
                product.organizations.append(org)

        return product
    except Exception as e:
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
    limit = request.args.get('limit', 100, type=int)
    offset = request.args.get('offset', 0, type=int)

    query = ImportQueue.query

    if status:
        query = query.filter_by(status=status)
    if integration_id:
        query = query.filter_by(integration_id=integration_id)
    if org_id:
        query = query.filter_by(organization_id=org_id)

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
    pending_count = ImportQueue.query.filter_by(status='pending').count()
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
        item.organization_id = data['organization_id']
    if 'cpe_vendor' in data:
        item.cpe_vendor = data['cpe_vendor']
    if 'cpe_product' in data:
        item.cpe_product = data['cpe_product']

    db.session.commit()
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
        item.organization_id = data['organization_id']

    # Create the product
    product = create_product_from_queue(item)

    if not product:
        return jsonify({'error': 'Failed to create product'}), 500

    item.status = 'approved'
    item.product_id = product.id
    item.processed_at = datetime.utcnow()
    item.processed_by = session.get('user_id')

    db.session.commit()

    # Trigger vulnerability matching
    try:
        from app.filters import match_vulnerabilities_to_products
        match_vulnerabilities_to_products([product])
    except:
        pass

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

    db.session.commit()

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

    db.session.commit()

    # Trigger vulnerability matching for approved products
    if results['products']:
        try:
            from app.filters import match_vulnerabilities_to_products
            products = Product.query.filter(Product.id.in_(results['products'])).all()
            match_vulnerabilities_to_products(products)
        except:
            pass

    return jsonify(results)


# ============================================================================
# Integration Management
# ============================================================================

@bp.route('/api/integrations', methods=['GET'])
@admin_required
@requires_professional('Integrations')
def get_integrations():
    """Get all integrations."""
    from app.auth import get_current_user

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

    # Generate API key for push integrations
    api_key = secrets.token_urlsafe(32)

    integration = Integration(
        name=name,
        integration_type=integration_type,
        organization_id=data.get('organization_id'),
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
    db.session.commit()

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
        integration.organization_id = data['organization_id']
    if 'auto_approve' in data:
        integration.auto_approve = data['auto_approve']
    if 'sync_enabled' in data:
        integration.sync_enabled = data['sync_enabled']
    if 'sync_interval_hours' in data:
        integration.sync_interval_hours = data['sync_interval_hours']
    if 'config' in data:
        integration.set_config(data['config'])

    db.session.commit()

    return jsonify(integration.to_dict(include_sensitive=True))


@bp.route('/api/integrations/<int:integration_id>', methods=['DELETE'])
@admin_required
@requires_professional('Integrations')
def delete_integration(integration_id):
    """Delete (deactivate) an integration."""
    integration = Integration.query.get_or_404(integration_id)

    integration.is_active = False
    db.session.commit()

    return jsonify({'success': True})


@bp.route('/api/integrations/<int:integration_id>/regenerate-key', methods=['POST'])
@admin_required
@requires_professional('Integrations')
def regenerate_api_key(integration_id):
    """Regenerate API key for an integration."""
    integration = Integration.query.get_or_404(integration_id)

    integration.api_key = secrets.token_urlsafe(32)
    db.session.commit()

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
        db.session.commit()
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

        db.session.commit()

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
    db.session.commit()

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

    db.session.commit()

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
    integration_id = request.args.get('integration_id', type=int)

    query = AgentRegistration.query.filter_by(is_active=True)

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
    db.session.commit()
    return jsonify({'success': True})


# ============================================================================
# Agent Script Downloads (Server-Generated)
# ============================================================================

@bp.route('/api/agents/script/windows', methods=['GET'])
@login_required
@requires_professional('Integrations')
def download_windows_agent():
    """Download Windows PowerShell agent script with embedded API key."""
    api_key = request.args.get('api_key', '')
    base_url = request.url_root.rstrip('/')

    # Build validation section based on whether key is embedded
    if api_key and api_key != 'YOUR_API_KEY_HERE':
        key_section = f'''[string]$ApiKey = "{api_key}",'''
        validation = ''
    else:
        key_section = '''[Parameter(Mandatory=$true)]
    [string]$ApiKey,'''
        validation = '''
# Validate API key
if ([string]::IsNullOrEmpty($ApiKey)) {
    Write-Error "Please provide a valid API key. Get one from Admin Panel > Integrations > Agent Keys"
    Write-Host ""
    Write-Host "Press any key to exit..." -ForegroundColor Cyan
    $null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
    exit 1
}
'''

    script = f'''# SentriKat Discovery Agent for Windows
# ================================================
# Deploy via GPO, SCCM, Intune, or run manually with Task Scheduler
#
# INSTALLATION (for scheduled inventory):
#   1. Save this script to: C:\\SentriKat\\sentrikat-agent.ps1
#   2. Create scheduled task:
#      schtasks /create /tn "SentriKat Agent" /tr "powershell -ExecutionPolicy Bypass -File C:\\SentriKat\\sentrikat-agent.ps1" /sc hourly /ru SYSTEM
#
# UNINSTALL:
#   1. Remove the scheduled task:
#      schtasks /delete /tn "SentriKat Agent" /f
#   2. Delete the script:
#      Remove-Item -Path "C:\\SentriKat" -Recurse -Force
#   3. (Optional) Remove endpoint from SentriKat Admin Panel > Endpoints
#
# Requirements: PowerShell 5.1+, Windows 7/Server 2008 R2 or later
# ================================================

param(
    {key_section}
    [string]$SentriKatUrl = "{base_url}"
)
{validation}
$ErrorActionPreference = "Stop"

# Get system information
$Hostname = $env:COMPUTERNAME
$OSInfo = Get-CimInstance Win32_OperatingSystem
$OSVersion = $OSInfo.Caption
$OSArch = if ([Environment]::Is64BitOperatingSystem) {{ "x64" }} else {{ "x86" }}
$AgentId = (Get-CimInstance Win32_ComputerSystemProduct).UUID
$IPAddress = (Get-NetIPAddress -AddressFamily IPv4 | Where-Object {{ $_.IPAddress -ne '127.0.0.1' -and $_.PrefixOrigin -ne 'WellKnown' }} | Select-Object -First 1).IPAddress

Write-Host ""
Write-Host "========================================" -ForegroundColor Cyan
Write-Host "  SentriKat Windows Discovery Agent" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host "Hostname:   $Hostname"
Write-Host "IP Address: $IPAddress"
Write-Host "OS:         $OSVersion ($OSArch)"
Write-Host "Agent ID:   $AgentId"
Write-Host ""

# Collect installed software
Write-Host "Scanning installed software..." -ForegroundColor Yellow
$Products = @()
$Seen = @{{}}

# Helper function to sanitize strings for JSON
function Sanitize-String {{
    param([string]$Value)
    if ([string]::IsNullOrWhiteSpace($Value)) {{ return "" }}
    # Remove control characters and normalize
    $Value = $Value -replace '[\\x00-\\x1F\\x7F]', ''
    $Value = $Value.Trim()
    return $Value
}}

function Add-Software {{
    param($Publisher, $Name, $Version, $Path)

    if ([string]::IsNullOrWhiteSpace($Name)) {{ return }}

    # Sanitize all inputs
    $Name = Sanitize-String $Name
    $Publisher = Sanitize-String $Publisher
    $Version = Sanitize-String $Version
    $Path = Sanitize-String $Path

    if ([string]::IsNullOrWhiteSpace($Name)) {{ return }}

    $Key = "$($Name.ToLower())"
    if ($Seen.ContainsKey($Key)) {{ return }}
    $Seen[$Key] = $true

    $script:Products += @{{
        vendor = if ($Publisher) {{ $Publisher }} else {{ "Unknown" }}
        product = $Name
        version = if ($Version) {{ $Version }} else {{ "" }}
        path = if ($Path) {{ $Path }} else {{ "" }}
    }}
}}

# From registry (64-bit)
Get-ItemProperty "HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\*" -ErrorAction SilentlyContinue | ForEach-Object {{
    Add-Software -Publisher $_.Publisher -Name $_.DisplayName -Version $_.DisplayVersion -Path $_.InstallLocation
}}

# From registry (32-bit on 64-bit OS)
Get-ItemProperty "HKLM:\\SOFTWARE\\WOW6432Node\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\*" -ErrorAction SilentlyContinue | ForEach-Object {{
    Add-Software -Publisher $_.Publisher -Name $_.DisplayName -Version $_.DisplayVersion -Path $_.InstallLocation
}}

# Current user software
Get-ItemProperty "HKCU:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\*" -ErrorAction SilentlyContinue | ForEach-Object {{
    Add-Software -Publisher $_.Publisher -Name $_.DisplayName -Version $_.DisplayVersion -Path $_.InstallLocation
}}

Write-Host "Found $($Products.Count) unique software items" -ForegroundColor Green
Write-Host ""

# Build payload
$Payload = @{{
    hostname = $Hostname
    ip_address = $IPAddress
    os = @{{
        name = "Windows"
        version = $OSVersion
    }}
    agent = @{{
        id = $AgentId
        version = "1.0.0"
    }}
    products = $Products
}}

# Convert to JSON with proper depth and encoding
try {{
    $Body = $Payload | ConvertTo-Json -Depth 10 -Compress -ErrorAction Stop
    # Convert to UTF-8 bytes for proper encoding
    $BodyBytes = [System.Text.Encoding]::UTF8.GetBytes($Body)
}} catch {{
    Write-Host ""
    Write-Host "ERROR: Failed to serialize JSON!" -ForegroundColor Red
    Write-Host $_.Exception.Message -ForegroundColor Red
    Write-Host ""
    Write-Host "Press any key to exit..." -ForegroundColor Cyan
    $null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
    exit 1
}}

# Report to SentriKat
Write-Host "Sending inventory to SentriKat..." -ForegroundColor Yellow
Write-Host "Payload size: $($BodyBytes.Length) bytes" -ForegroundColor Gray

try {{
    $Response = Invoke-RestMethod -Uri "$SentriKatUrl/api/agent/inventory" `
        -Method POST `
        -Body $BodyBytes `
        -ContentType "application/json; charset=utf-8" `
        -Headers @{{"X-Agent-Key" = $ApiKey}} `
        -ErrorAction Stop

    Write-Host ""
    Write-Host "SUCCESS!" -ForegroundColor Green
    Write-Host "----------------------------------------"
    if ($Response.status -eq "queued") {{
        # Async processing for large batches
        Write-Host "Status:               Queued for processing" -ForegroundColor Yellow
        Write-Host "Job ID:               $($Response.job_id)"
        Write-Host "Asset ID:             $($Response.asset_id)"
        Write-Host "Total Products:       $($Response.message)"
        Write-Host ""
        Write-Host "Large inventory queued for background processing."
        Write-Host "Check job status at: $SentriKatUrl$($Response.check_status_url)"
    }} else {{
        # Sync processing result
        Write-Host "Asset ID:             $($Response.asset_id)"
        if ($Response.summary) {{
            Write-Host "Products Created:     $($Response.summary.products_created)"
            Write-Host "Products Updated:     $($Response.summary.products_updated)"
            Write-Host "Installations Created: $($Response.summary.installations_created)"
            Write-Host "Installations Updated: $($Response.summary.installations_updated)"
        }}
    }}
    Write-Host "----------------------------------------"
}} catch {{
    Write-Host ""
    Write-Host "ERROR!" -ForegroundColor Red
    Write-Host $_.Exception.Message -ForegroundColor Red
    if ($_.Exception.Response) {{
        try {{
            $reader = New-Object System.IO.StreamReader($_.Exception.Response.GetResponseStream())
            Write-Host "Server Response: $($reader.ReadToEnd())" -ForegroundColor Red
        }} catch {{}}
    }}
    Write-Host ""
    Write-Host "Press any key to exit..." -ForegroundColor Cyan
    $null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
    exit 1
}}

Write-Host ""
Write-Host "Agent completed successfully!" -ForegroundColor Green
Write-Host ""
Write-Host "Press any key to exit..." -ForegroundColor Cyan
$null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
'''

    return Response(
        script,
        mimetype='text/plain',
        headers={'Content-Disposition': 'attachment; filename=sentrikat-agent-windows.ps1'}
    )


@bp.route('/api/agents/script/linux', methods=['GET'])
@login_required
@requires_professional('Integrations')
def download_linux_agent():
    """Download Linux Bash agent script with embedded API key."""
    api_key = request.args.get('api_key', '')
    base_url = request.url_root.rstrip('/')

    # Build key section based on whether embedded
    if api_key and api_key != 'YOUR_API_KEY_HERE':
        key_section = f'''API_KEY="{api_key}"
API_URL="${{1:-{base_url}}}"'''
        validation = ''
    else:
        key_section = f'''API_KEY="${{1:?Usage: $0 <api-key>}}"
API_URL="${{2:-{base_url}}}"'''
        validation = '''
# Validate API key
if [ -z "$API_KEY" ]; then
    echo "ERROR: Please provide a valid API key"
    echo "Get one from Admin Panel > Integrations > Agent Keys"
    exit 1
fi
'''

    script = f'''#!/bin/bash
# ================================================
# SentriKat Discovery Agent for Linux
# ================================================
# Deploy via Ansible, Puppet, Chef, or add to cron for persistent monitoring.
#
# INSTALLATION:
#   sudo mkdir -p /opt/sentrikat
#   sudo mv sentrikat-agent.sh /opt/sentrikat/
#   sudo chmod +x /opt/sentrikat/sentrikat-agent.sh
#   # Add to cron (runs every 4 hours):
#   (crontab -l 2>/dev/null; echo "0 */4 * * * /opt/sentrikat/sentrikat-agent.sh >> /var/log/sentrikat-agent.log 2>&1") | crontab -
#
# UNINSTALL:
#   # Remove cron entry:
#   crontab -l | grep -v sentrikat-agent | crontab -
#   # Delete the agent:
#   sudo rm -rf /opt/sentrikat /var/log/sentrikat-agent.log
#   # (Optional) Remove endpoint from SentriKat Admin Panel > Endpoints
#
# Requirements: bash, curl
# ================================================

set -e

{key_section}
{validation}
# Get system information
HOSTNAME=$(hostname)
IP_ADDRESS=$(hostname -I 2>/dev/null | awk '{{print $1}}' || echo "")
OS_NAME="Linux"
OS_VERSION=$(cat /etc/os-release 2>/dev/null | grep PRETTY_NAME | cut -d'"' -f2 || uname -sr)
KERNEL=$(uname -r)
AGENT_ID=$(cat /etc/machine-id 2>/dev/null || hostname)

echo ""
echo "========================================"
echo "  SentriKat Linux Discovery Agent"
echo "========================================"
echo "Hostname:   $HOSTNAME"
echo "IP Address: $IP_ADDRESS"
echo "OS:         $OS_VERSION"
echo "Kernel:     $KERNEL"
echo "Agent ID:   $AGENT_ID"
echo ""

# Collect installed software
echo "Scanning installed software..."
PRODUCTS_FILE=$(mktemp)
trap "rm -f $PRODUCTS_FILE" EXIT

# dpkg (Debian/Ubuntu)
if command -v dpkg-query &> /dev/null; then
    dpkg-query -W -f='${{Package}}|${{Version}}|dpkg\\n' 2>/dev/null | while IFS='|' read pkg ver src; do
        [ -n "$pkg" ] && echo "{{\\"vendor\\":\\"$src\\",\\"product\\":\\"$pkg\\",\\"version\\":\\"$ver\\"}},"
    done >> "$PRODUCTS_FILE"
fi

# rpm (RHEL/CentOS/Fedora)
if command -v rpm &> /dev/null && ! command -v dpkg &> /dev/null; then
    rpm -qa --queryformat '%{{NAME}}|%{{VERSION}}|%{{VENDOR}}\\n' 2>/dev/null | while IFS='|' read pkg ver vendor; do
        [ -n "$pkg" ] && echo "{{\\"vendor\\":\\"${{vendor:-rpm}}\\",\\"product\\":\\"$pkg\\",\\"version\\":\\"$ver\\"}},"
    done >> "$PRODUCTS_FILE"
fi

# snap
if command -v snap &> /dev/null; then
    snap list 2>/dev/null | tail -n +2 | while read name ver rest; do
        [ -n "$name" ] && echo "{{\\"vendor\\":\\"snap\\",\\"product\\":\\"$name\\",\\"version\\":\\"$ver\\"}},"
    done >> "$PRODUCTS_FILE"
fi

# flatpak
if command -v flatpak &> /dev/null; then
    flatpak list --columns=name,version 2>/dev/null | while read name ver; do
        [ -n "$name" ] && echo "{{\\"vendor\\":\\"flatpak\\",\\"product\\":\\"$name\\",\\"version\\":\\"$ver\\"}},"
    done >> "$PRODUCTS_FILE"
fi

# Build products array
if [ -s "$PRODUCTS_FILE" ]; then
    PRODUCTS="[$(sed '$s/,$//' "$PRODUCTS_FILE" | tr '\\n' ' ')]"
    COUNT=$(wc -l < "$PRODUCTS_FILE")
else
    PRODUCTS="[]"
    COUNT=0
fi

echo "Found $COUNT installed packages"
echo ""

# Build JSON payload
PAYLOAD=$(cat <<EOFPAYLOAD
{{
    "hostname": "$HOSTNAME",
    "ip_address": "$IP_ADDRESS",
    "os": {{
        "name": "$OS_NAME",
        "version": "$OS_VERSION",
        "kernel": "$KERNEL"
    }},
    "agent": {{
        "id": "$AGENT_ID",
        "version": "1.0.0"
    }},
    "products": $PRODUCTS
}}
EOFPAYLOAD
)

echo "Sending inventory to SentriKat..."

# Send to SentriKat
RESPONSE=$(curl -s -w "\\n%{{http_code}}" -X POST "$API_URL/api/agent/inventory" \\
    -H "X-Agent-Key: $API_KEY" \\
    -H "Content-Type: application/json" \\
    -d "$PAYLOAD")

HTTP_CODE=$(echo "$RESPONSE" | tail -n1)
BODY=$(echo "$RESPONSE" | sed '$d')

echo ""
if [ "$HTTP_CODE" = "200" ] || [ "$HTTP_CODE" = "201" ] || [ "$HTTP_CODE" = "202" ]; then
    echo "SUCCESS!"
    echo "----------------------------------------"
    echo "$BODY" | python3 -c "
import sys,json
try:
    d=json.load(sys.stdin)
    print(f\\"Asset ID: {{d.get('asset_id')}}\\")
    print(f\\"Products Created: {{d.get('products_created', 0)}}\\")
    print(f\\"Products Updated: {{d.get('products_updated', 0)}}\\")
    print(f\\"Installations Created: {{d.get('installations_created', 0)}}\\")
    print(f\\"Installations Updated: {{d.get('installations_updated', 0)}}\\")
except:
    print(sys.stdin.read())
" 2>/dev/null || echo "$BODY"
    echo "----------------------------------------"
else
    echo "ERROR! (HTTP $HTTP_CODE)"
    echo "----------------------------------------"
    echo "$BODY"
    exit 1
fi

echo ""
echo "Agent completed successfully!"
'''

    return Response(
        script,
        mimetype='text/plain',
        headers={'Content-Disposition': 'attachment; filename=sentrikat-agent-linux.sh'}
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

    try:
        if tracker_type == 'jira':
            url = data.get('url', '').strip()
            email = data.get('email', '').strip()
            api_token = data.get('api_token', '').strip()
            use_pat = data.get('use_pat', False)  # Use Personal Access Token (Bearer auth)
            if not all([url, email, api_token]):
                return jsonify({'success': False, 'error': 'URL, email, and API token required'}), 400
            tracker = JiraTracker(url, email, api_token, verify_ssl=verify_ssl, use_pat=use_pat)

        elif tracker_type == 'youtrack':
            url = data.get('url', '').strip()
            token = data.get('token', '').strip()
            if not all([url, token]):
                return jsonify({'success': False, 'error': 'URL and token required'}), 400
            tracker = YouTrackTracker(url, token)

        elif tracker_type == 'github':
            token = data.get('token', '').strip()
            owner = data.get('owner', '').strip()
            repo = data.get('repo', '').strip()
            if not all([token, owner, repo]):
                return jsonify({'success': False, 'error': 'Token, owner, and repo required'}), 400
            tracker = GitHubTracker(token, owner, repo)

        elif tracker_type == 'gitlab':
            url = data.get('url', 'https://gitlab.com').strip()
            token = data.get('token', '').strip()
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

    success, message, issue_key, issue_url = create_vulnerability_issue(
        vulnerability_id=vulnerability_id,
        product_id=product_id,
        custom_summary=custom_summary,
        custom_description=custom_description
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
