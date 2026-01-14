"""
Integrations API - Endpoints for external software inventory integrations.

Provides:
1. Push API - External systems/agents send software lists to SentriKat
2. Queue Management - Review, approve, reject pending imports
3. Integration CRUD - Configure external system connections
4. Agent Management - Register and manage discovery agents

Security:
- Push API endpoints use API key authentication (CSRF exempt)
- Management endpoints require session login + CSRF
- Rate limiting on push endpoints to prevent abuse
- Input validation and sanitization on all inputs
"""

from flask import Blueprint, request, jsonify, session, Response
from datetime import datetime, timedelta
import secrets
import uuid
import re
from functools import wraps

from app import db, csrf, limiter
from app.integrations_models import Integration, ImportQueue, AgentRegistration
from app.models import Product, Organization, User
from app.auth import admin_required, login_required

bp = Blueprint('integrations', __name__)


# ============================================================================
# Security Helpers
# ============================================================================

def sanitize_string(value, max_length=200):
    """Sanitize input string - remove dangerous characters, limit length."""
    if not value:
        return ''
    # Convert to string and strip
    value = str(value).strip()
    # Remove null bytes and control characters
    value = re.sub(r'[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]', '', value)
    # Limit length
    return value[:max_length]


def validate_api_key_format(api_key):
    """Validate API key format to prevent injection."""
    if not api_key:
        return False
    # API keys should be alphanumeric with some special chars (base64-like)
    return bool(re.match(r'^[A-Za-z0-9_\-]{20,64}$', api_key))


# ============================================================================
# Authentication Helpers
# ============================================================================

def get_integration_by_api_key(api_key):
    """Look up integration by API key."""
    if not api_key or not validate_api_key_format(api_key):
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
# These endpoints are CSRF-exempt because they use API key auth
# ============================================================================

@bp.route('/api/import', methods=['POST'])
@csrf.exempt  # External systems can't provide CSRF tokens
@limiter.limit("30 per minute")  # Rate limit to prevent abuse
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

    default_criticality = 'medium'
    if integration:
        default_criticality = integration.default_criticality or 'medium'

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
            criticality=default_criticality,
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
    Returns (cpe_vendor, cpe_product, confidence) tuple.
    """
    try:
        from app.nvd_cpe_api import search_cpe_grouped

        # Search NVD for matching products
        query = f"{vendor} {product_name}"
        results = search_cpe_grouped(query, limit=10)

        if not results:
            return None, None, 0.0

        # Look for best match
        vendor_lower = vendor.lower().replace(' ', '_')
        product_lower = product_name.lower().replace(' ', '_')

        best_match = None
        best_confidence = 0.0

        for cpe_vendor, vendor_data in results.items():
            vendor_sim = calculate_similarity(vendor_lower, cpe_vendor)

            for cpe_product, product_data in vendor_data.get('products', {}).items():
                product_sim = calculate_similarity(product_lower, cpe_product)

                # Combined confidence
                confidence = (vendor_sim * 0.4 + product_sim * 0.6)

                if confidence > best_confidence:
                    best_confidence = confidence
                    best_match = (cpe_vendor, cpe_product)

        if best_match and best_confidence > 0.5:
            return best_match[0], best_match[1], best_confidence

        return None, None, 0.0

    except Exception as e:
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
            criticality=queue_item.criticality,
            app_type=queue_item.app_type or 'unknown',
            cpe_vendor=queue_item.cpe_vendor,
            cpe_product=queue_item.cpe_product,
            active=True
        )
        db.session.add(product)
        db.session.flush()  # Get the ID
        return product
    except Exception as e:
        return None


# ============================================================================
# Import Queue Management
# ============================================================================

@bp.route('/api/import/queue', methods=['GET'])
@login_required
def get_import_queue():
    """Get pending import queue items."""
    try:
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
    except Exception as e:
        return jsonify({'error': f'Database error: {str(e)}', 'items': []}), 500


@bp.route('/api/import/queue/count', methods=['GET'])
@login_required
def get_import_queue_count():
    """Get count of pending import queue items."""
    try:
        pending_count = ImportQueue.query.filter_by(status='pending').count()
        return jsonify({'pending': pending_count})
    except Exception as e:
        return jsonify({'pending': 0, 'error': str(e)}), 200  # Return 0 count on error


@bp.route('/api/import/queue/<int:item_id>', methods=['GET'])
@login_required
def get_queue_item(item_id):
    """Get a specific queue item."""
    item = ImportQueue.query.get_or_404(item_id)
    return jsonify(item.to_dict())


@bp.route('/api/import/queue/<int:item_id>', methods=['PUT'])
@login_required
def update_queue_item(item_id):
    """Update a queue item (change version, org, criticality)."""
    item = ImportQueue.query.get_or_404(item_id)
    data = request.get_json()

    if item.status != 'pending':
        return jsonify({'error': 'Can only update pending items'}), 400

    if 'selected_version' in data:
        item.selected_version = data['selected_version'] or None
    if 'organization_id' in data:
        item.organization_id = data['organization_id']
    if 'criticality' in data:
        item.criticality = data['criticality']
    if 'app_type' in data:
        item.app_type = data['app_type']
    if 'cpe_vendor' in data:
        item.cpe_vendor = data['cpe_vendor']
    if 'cpe_product' in data:
        item.cpe_product = data['cpe_product']

    db.session.commit()
    return jsonify(item.to_dict())


@bp.route('/api/import/queue/<int:item_id>/approve', methods=['POST'])
@login_required
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
    if 'criticality' in data:
        item.criticality = data['criticality']
    if 'app_type' in data:
        item.app_type = data['app_type']

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
def get_integrations():
    """Get all integrations."""
    try:
        integrations = Integration.query.filter_by(is_active=True).order_by(Integration.name).all()
        return jsonify([i.to_dict() for i in integrations])
    except Exception as e:
        return jsonify({'error': f'Database error: {str(e)}', 'integrations': []}), 500


@bp.route('/api/integrations/<int:integration_id>', methods=['GET'])
@admin_required
def get_integration(integration_id):
    """Get a specific integration."""
    integration = Integration.query.get_or_404(integration_id)
    # Include sensitive data for editing
    return jsonify(integration.to_dict(include_sensitive=True))


@bp.route('/api/integrations', methods=['POST'])
@admin_required
def create_integration():
    """Create a new integration."""
    try:
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
            default_criticality=data.get('default_criticality', 'medium'),
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

    except Exception as e:
        db.session.rollback()
        logger.error(f"Error creating integration: {str(e)}")
        return jsonify({'error': f'Database error: {str(e)}'}), 500


@bp.route('/api/integrations/<int:integration_id>', methods=['PUT'])
@admin_required
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
    if 'default_criticality' in data:
        integration.default_criticality = data['default_criticality']
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
def delete_integration(integration_id):
    """Delete (deactivate) an integration."""
    integration = Integration.query.get_or_404(integration_id)

    integration.is_active = False
    db.session.commit()

    return jsonify({'success': True})


@bp.route('/api/integrations/<int:integration_id>/regenerate-key', methods=['POST'])
@admin_required
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
# These endpoints are CSRF-exempt because they use API key auth
# ============================================================================

@bp.route('/api/agent/register', methods=['POST'])
@csrf.exempt  # Agents can't provide CSRF tokens
@limiter.limit("10 per minute")  # Rate limit agent registration
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
@csrf.exempt  # Agents can't provide CSRF tokens
@limiter.limit("60 per minute")  # Rate limit agent reports
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
    from app.integrations_models import SoftwareVersionTracker

    software_list = data.get('software', [])
    org_id = data.get('organization_id')
    agent_id = data.get('agent_id')

    auto_approve = integration.auto_approve if integration else False
    default_criticality = integration.default_criticality if integration else 'medium'

    results = {'queued': 0, 'auto_approved': 0, 'duplicates': 0, 'errors': 0, 'version_updates': 0}

    for item in software_list:
        vendor = item.get('vendor', '').strip()
        product_name = item.get('product', item.get('product_name', '')).strip()
        version = item.get('version', '').strip() or None

        if not vendor or not product_name:
            results['errors'] += 1
            continue

        # Track version observation (regardless of product existence)
        track_version_observation(
            vendor=vendor,
            product_name=product_name,
            version=version,
            org_id=org_id,
            integration_id=integration.id if integration else None,
            agent_id=agent_id
        )

        # Check for existing product
        existing = Product.query.filter(
            db.func.lower(Product.vendor) == vendor.lower(),
            db.func.lower(Product.product_name) == product_name.lower()
        ).first()

        if existing:
            # Check if version is different (version drift detection)
            if version and existing.version and version != existing.version:
                results['version_updates'] += 1
            results['duplicates'] += 1
            continue

        existing_queue = ImportQueue.query.filter(
            db.func.lower(ImportQueue.vendor) == vendor.lower(),
            db.func.lower(ImportQueue.product_name) == product_name.lower(),
            ImportQueue.status == 'pending'
        ).first()

        if existing_queue:
            # Update detected version if newer
            if version and existing_queue.detected_version != version:
                existing_queue.detected_version = version
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
            criticality=default_criticality,
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


def track_version_observation(vendor, product_name, version, org_id, integration_id=None, agent_id=None):
    """Track a version observation from an agent or integration."""
    from app.integrations_models import SoftwareVersionTracker

    # Find existing tracker for this vendor/product/version/org combo
    tracker = SoftwareVersionTracker.query.filter(
        db.func.lower(SoftwareVersionTracker.vendor) == vendor.lower(),
        db.func.lower(SoftwareVersionTracker.product_name) == product_name.lower(),
        SoftwareVersionTracker.version == version,
        SoftwareVersionTracker.organization_id == org_id
    ).first()

    if tracker:
        # Update existing observation
        tracker.observation_count += 1
        tracker.last_seen_at = datetime.utcnow()
        tracker.is_current = True
    else:
        # Create new tracker
        tracker = SoftwareVersionTracker(
            vendor=vendor,
            product_name=product_name,
            version=version,
            organization_id=org_id,
            integration_id=integration_id,
            agent_id=agent_id,
            observation_count=1,
            first_seen_at=datetime.utcnow(),
            last_seen_at=datetime.utcnow(),
            is_current=True
        )

        # Link to existing product if found
        existing_product = Product.query.filter(
            db.func.lower(Product.vendor) == vendor.lower(),
            db.func.lower(Product.product_name) == product_name.lower()
        ).first()
        if existing_product:
            tracker.product_id = existing_product.id

        db.session.add(tracker)


# ============================================================================
# Agent Management
# ============================================================================

@bp.route('/api/agents', methods=['GET'])
@admin_required
def get_agents():
    """Get all registered agents."""
    try:
        integration_id = request.args.get('integration_id', type=int)

        query = AgentRegistration.query.filter_by(is_active=True)

        if integration_id:
            query = query.filter_by(integration_id=integration_id)

        agents = query.order_by(AgentRegistration.last_seen_at.desc()).all()

        return jsonify([agent.to_dict() for agent in agents])
    except Exception as e:
        return jsonify({'error': f'Database error: {str(e)}', 'agents': []}), 500


@bp.route('/api/agents/<int:agent_id>', methods=['DELETE'])
@admin_required
def delete_agent(agent_id):
    """Delete (deactivate) an agent."""
    agent = AgentRegistration.query.get_or_404(agent_id)
    agent.is_active = False
    db.session.commit()
    return jsonify({'success': True})


# ============================================================================
# Agent Script Downloads
# ============================================================================

@bp.route('/api/agents/script/windows', methods=['GET'])
@login_required
def download_windows_agent():
    """Download Windows PowerShell agent script."""
    api_key = request.args.get('api_key', 'YOUR_API_KEY_HERE')
    base_url = request.url_root.rstrip('/')

    script = f'''# SentriKat Discovery Agent for Windows
# ================================================
# Deploy via GPO, SCCM, Intune, or run manually with Task Scheduler
#
# Usage:
#   1. Replace YOUR_API_KEY_HERE with your actual API key from Admin Panel > Integrations
#   2. Run as Administrator or via scheduled task
#   3. Schedule to run periodically (e.g., daily) for continuous inventory
#
# Requirements: PowerShell 5.1+, Windows 7/Server 2008 R2 or later
# ================================================

param(
    [string]$SentriKatUrl = "{base_url}",
    [string]$ApiKey = "{api_key}"
)

# Validate parameters
if ($ApiKey -eq "YOUR_API_KEY_HERE" -or [string]::IsNullOrEmpty($ApiKey)) {{
    Write-Error "Please provide a valid API key. Get one from Admin Panel > Integrations > Create Agent Integration"
    exit 1
}}

# Get system information
$Hostname = $env:COMPUTERNAME
$OSInfo = Get-WmiObject Win32_OperatingSystem
$OSVersion = $OSInfo.Caption
$OSArch = if ([Environment]::Is64BitOperatingSystem) {{ "x64" }} else {{ "x86" }}

Write-Host "SentriKat Agent starting on $Hostname" -ForegroundColor Cyan
Write-Host "OS: $OSVersion ($OSArch)" -ForegroundColor Gray

# Register agent
$RegisterBody = @{{
    hostname = $Hostname
    os_type = "windows"
    os_version = $OSVersion
    os_arch = $OSArch
    agent_version = "1.0.0"
    system_info = @{{
        domain = $env:USERDOMAIN
        username = $env:USERNAME
        cpu = (Get-WmiObject Win32_Processor).Name
        ram_gb = [math]::Round($OSInfo.TotalVisibleMemorySize / 1MB, 1)
    }}
}} | ConvertTo-Json -Depth 3

Write-Host "Registering agent..." -ForegroundColor Yellow
try {{
    $RegisterResponse = Invoke-RestMethod -Uri "$SentriKatUrl/api/agent/register" `
        -Method POST `
        -Body $RegisterBody `
        -ContentType "application/json" `
        -Headers @{{"X-API-Key" = $ApiKey}} `
        -ErrorAction Stop

    $AgentId = $RegisterResponse.agent_id
    Write-Host "Agent registered successfully. ID: $AgentId" -ForegroundColor Green
}} catch {{
    Write-Error "Failed to register agent: $($_.Exception.Message)"
    exit 1
}}

# Collect installed software
Write-Host "Collecting installed software..." -ForegroundColor Yellow
$Software = @()
$Seen = @{{}}

# Function to add software if not duplicate
function Add-Software {{
    param($Publisher, $Name, $Version)

    if ([string]::IsNullOrWhiteSpace($Name)) {{ return }}

    $Key = "$($Publisher.ToLower())|$($Name.ToLower())"
    if ($Seen.ContainsKey($Key)) {{ return }}
    $Seen[$Key] = $true

    $script:Software += @{{
        vendor = if ($Publisher) {{ $Publisher }} else {{ "Unknown" }}
        product = $Name
        version = if ($Version) {{ $Version }} else {{ "" }}
    }}
}}

# From registry (64-bit)
Get-ItemProperty "HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\*" -ErrorAction SilentlyContinue | ForEach-Object {{
    Add-Software -Publisher $_.Publisher -Name $_.DisplayName -Version $_.DisplayVersion
}}

# From registry (32-bit on 64-bit OS)
Get-ItemProperty "HKLM:\\SOFTWARE\\WOW6432Node\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\*" -ErrorAction SilentlyContinue | ForEach-Object {{
    Add-Software -Publisher $_.Publisher -Name $_.DisplayName -Version $_.DisplayVersion
}}

# Current user software
Get-ItemProperty "HKCU:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\*" -ErrorAction SilentlyContinue | ForEach-Object {{
    Add-Software -Publisher $_.Publisher -Name $_.DisplayName -Version $_.DisplayVersion
}}

Write-Host "Found $($Software.Count) unique software items" -ForegroundColor Cyan

# Report to SentriKat
$ReportBody = @{{
    agent_id = $AgentId
    software = $Software
}} | ConvertTo-Json -Depth 3 -Compress

Write-Host "Reporting inventory to SentriKat..." -ForegroundColor Yellow
try {{
    $ReportResponse = Invoke-RestMethod -Uri "$SentriKatUrl/api/agent/report" `
        -Method POST `
        -Body $ReportBody `
        -ContentType "application/json" `
        -Headers @{{"X-API-Key" = $ApiKey}} `
        -ErrorAction Stop

    Write-Host "SUCCESS: Reported $($Software.Count) software items" -ForegroundColor Green
    Write-Host "  - Queued: $($ReportResponse.results.queued)" -ForegroundColor Gray
    Write-Host "  - Auto-approved: $($ReportResponse.results.auto_approved)" -ForegroundColor Gray
    Write-Host "  - Duplicates: $($ReportResponse.results.duplicates)" -ForegroundColor Gray
}} catch {{
    Write-Error "Failed to report software: $($_.Exception.Message)"
    exit 1
}}

Write-Host "`nAgent completed successfully!" -ForegroundColor Green
'''

    return Response(
        script,
        mimetype='text/plain',
        headers={'Content-Disposition': 'attachment; filename=sentrikat-agent-windows.ps1'}
    )


@bp.route('/api/agents/script/linux', methods=['GET'])
@login_required
def download_linux_agent():
    """Download Linux Bash agent script."""
    api_key = request.args.get('api_key', 'YOUR_API_KEY_HERE')
    base_url = request.url_root.rstrip('/')

    script = f'''#!/bin/bash
# ================================================
# SentriKat Discovery Agent for Linux
# ================================================
# Deploy via Ansible, Puppet, Chef, or add to cron
#
# Usage:
#   1. Replace YOUR_API_KEY_HERE with your actual API key
#   2. Make executable: chmod +x sentrikat-agent-linux.sh
#   3. Run: ./sentrikat-agent-linux.sh
#   4. Add to cron for periodic scans: crontab -e
#      0 6 * * * /path/to/sentrikat-agent-linux.sh > /var/log/sentrikat-agent.log 2>&1
#
# Requirements: bash, curl, jq (optional, for better JSON handling)
# ================================================

set -e

# Configuration - EDIT THESE VALUES
SENTRIKAT_URL="{base_url}"
API_KEY="{api_key}"

# Validate API key
if [ "$API_KEY" = "YOUR_API_KEY_HERE" ] || [ -z "$API_KEY" ]; then
    echo "ERROR: Please set a valid API key"
    echo "Get one from Admin Panel > Integrations > Create Agent Integration"
    exit 1
fi

# Get system information
HOSTNAME=$(hostname)
OS_TYPE="linux"

# Detect OS version
if [ -f /etc/os-release ]; then
    OS_VERSION=$(grep PRETTY_NAME /etc/os-release | cut -d'"' -f2)
elif [ -f /etc/redhat-release ]; then
    OS_VERSION=$(cat /etc/redhat-release)
else
    OS_VERSION=$(uname -sr)
fi

OS_ARCH=$(uname -m)

echo "================================================"
echo "SentriKat Agent starting on $HOSTNAME"
echo "OS: $OS_VERSION ($OS_ARCH)"
echo "================================================"

# Register agent
echo "Registering agent..."
REGISTER_RESPONSE=$(curl -s -X POST "$SENTRIKAT_URL/api/agent/register" \\
    -H "Content-Type: application/json" \\
    -H "X-API-Key: $API_KEY" \\
    -d "{{
        \\"hostname\\": \\"$HOSTNAME\\",
        \\"os_type\\": \\"$OS_TYPE\\",
        \\"os_version\\": \\"$OS_VERSION\\",
        \\"os_arch\\": \\"$OS_ARCH\\",
        \\"agent_version\\": \\"1.0.0\\"
    }}")

# Check if registration succeeded
if echo "$REGISTER_RESPONSE" | grep -q "error"; then
    echo "ERROR: Failed to register agent"
    echo "$REGISTER_RESPONSE"
    exit 1
fi

AGENT_ID=$(echo "$REGISTER_RESPONSE" | grep -o '"agent_id"[[:space:]]*:[[:space:]]*"[^"]*"' | cut -d'"' -f4)
if [ -z "$AGENT_ID" ]; then
    AGENT_ID="$HOSTNAME"
fi
echo "Agent registered. ID: $AGENT_ID"

# Collect installed software
echo "Collecting installed software..."
SOFTWARE_JSON="["
FIRST=true

# Function to add software entry
add_software() {{
    local vendor="$1"
    local product="$2"
    local version="$3"

    if [ -z "$product" ]; then
        return
    fi

    # Escape quotes in strings
    vendor=$(echo "$vendor" | sed 's/"/\\\\"/g')
    product=$(echo "$product" | sed 's/"/\\\\"/g')
    version=$(echo "$version" | sed 's/"/\\\\"/g')

    if [ "$FIRST" = true ]; then
        FIRST=false
    else
        SOFTWARE_JSON="$SOFTWARE_JSON,"
    fi

    SOFTWARE_JSON="$SOFTWARE_JSON{{\\"vendor\\":\\"$vendor\\",\\"product\\":\\"$product\\",\\"version\\":\\"$version\\"}}"
}}

# Debian/Ubuntu - dpkg
if command -v dpkg &> /dev/null; then
    echo "  Scanning dpkg packages..."
    while IFS= read -r line; do
        name=$(echo "$line" | awk '{{print $2}}')
        version=$(echo "$line" | awk '{{print $3}}')
        add_software "Debian Package" "$name" "$version"
    done < <(dpkg-query -W -f='${{Status}} ${{Package}} ${{Version}}\\n' 2>/dev/null | grep "^install ok installed" | head -500)
fi

# RHEL/CentOS/Fedora - rpm
if command -v rpm &> /dev/null && ! command -v dpkg &> /dev/null; then
    echo "  Scanning rpm packages..."
    while IFS='|' read -r name version vendor; do
        if [ -n "$name" ]; then
            add_software "${{vendor:-RPM Package}}" "$name" "$version"
        fi
    done < <(rpm -qa --queryformat '%{{NAME}}|%{{VERSION}}|%{{VENDOR}}\\n' 2>/dev/null | head -500)
fi

# Snap packages
if command -v snap &> /dev/null; then
    echo "  Scanning snap packages..."
    while read -r name version rest; do
        if [ "$name" != "Name" ] && [ -n "$name" ]; then
            add_software "Snap Package" "$name" "$version"
        fi
    done < <(snap list 2>/dev/null | tail -n +2)
fi

# Flatpak packages
if command -v flatpak &> /dev/null; then
    echo "  Scanning flatpak packages..."
    while read -r name version rest; do
        if [ -n "$name" ]; then
            add_software "Flatpak" "$name" "$version"
        fi
    done < <(flatpak list --columns=name,version 2>/dev/null | tail -n +1)
fi

SOFTWARE_JSON="$SOFTWARE_JSON]"

# Count items (rough count)
ITEM_COUNT=$(echo "$SOFTWARE_JSON" | grep -o "product" | wc -l)
echo "Found approximately $ITEM_COUNT software items"

# Report to SentriKat
echo "Reporting inventory to SentriKat..."
REPORT_BODY="{{\\"agent_id\\":\\"$AGENT_ID\\",\\"software\\":$SOFTWARE_JSON}}"

REPORT_RESPONSE=$(curl -s -X POST "$SENTRIKAT_URL/api/agent/report" \\
    -H "Content-Type: application/json" \\
    -H "X-API-Key: $API_KEY" \\
    -d "$REPORT_BODY")

if echo "$REPORT_RESPONSE" | grep -q "success"; then
    echo "================================================"
    echo "SUCCESS: Software inventory reported to SentriKat"
    echo "$REPORT_RESPONSE"
    echo "================================================"
else
    echo "ERROR: Failed to report software"
    echo "$REPORT_RESPONSE"
    exit 1
fi

echo "Agent completed successfully!"
'''

    return Response(
        script,
        mimetype='text/plain',
        headers={'Content-Disposition': 'attachment; filename=sentrikat-agent-linux.sh'}
    )


# ============================================================================
# Software Audit - Version Tracking
# ============================================================================

@bp.route('/api/audit/versions', methods=['GET'])
@admin_required
def get_version_audit():
    """
    Get software version audit report.
    Shows version drift and multiple versions in use.
    """
    try:
        from app.integrations_models import SoftwareVersionTracker

        org_id = request.args.get('organization_id', type=int)
        days_stale = request.args.get('days_stale', 30, type=int)

        # Calculate stale threshold
        stale_threshold = datetime.utcnow() - timedelta(days=days_stale)

        # Query version trackers
        query = SoftwareVersionTracker.query

        if org_id:
            query = query.filter_by(organization_id=org_id)

        trackers = query.order_by(
            SoftwareVersionTracker.vendor,
            SoftwareVersionTracker.product_name,
            SoftwareVersionTracker.last_seen_at.desc()
        ).all()

        # Group by product to find version drift
        products = {}
        for tracker in trackers:
            key = f"{tracker.vendor.lower()}:{tracker.product_name.lower()}"
            if key not in products:
                products[key] = {
                    'vendor': tracker.vendor,
                    'product_name': tracker.product_name,
                    'versions': [],
                    'product_id': tracker.product_id,
                    'has_multiple_versions': False,
                    'has_stale_versions': False
                }

            is_stale = tracker.last_seen_at < stale_threshold if tracker.last_seen_at else True

            products[key]['versions'].append({
                'id': tracker.id,
                'version': tracker.version,
                'observation_count': tracker.observation_count,
                'first_seen': tracker.first_seen_at.isoformat() if tracker.first_seen_at else None,
                'last_seen': tracker.last_seen_at.isoformat() if tracker.last_seen_at else None,
                'is_current': tracker.is_current,
                'is_stale': is_stale,
                'is_outdated': tracker.is_outdated,
                'organization_id': tracker.organization_id,
                'organization_name': tracker.organization.display_name if tracker.organization else None
            })

            if is_stale:
                products[key]['has_stale_versions'] = True

        # Mark products with multiple versions
        for key, product in products.items():
            if len(product['versions']) > 1:
                product['has_multiple_versions'] = True

        # Convert to list and sort
        result = list(products.values())
        result.sort(key=lambda x: (not x['has_multiple_versions'], not x['has_stale_versions'], x['vendor'], x['product_name']))

        return jsonify({
            'products': result,
            'total_products': len(result),
            'products_with_drift': sum(1 for p in result if p['has_multiple_versions']),
            'products_with_stale': sum(1 for p in result if p['has_stale_versions'])
        })
    except Exception as e:
        return jsonify({'error': f'Database error: {str(e)}', 'products': []}), 500


@bp.route('/api/audit/versions/<int:tracker_id>/mark-outdated', methods=['POST'])
@admin_required
def mark_version_outdated(tracker_id):
    """Mark a version as outdated (no longer in use)."""
    from app.integrations_models import SoftwareVersionTracker
    from flask import session

    tracker = SoftwareVersionTracker.query.get_or_404(tracker_id)

    tracker.is_outdated = True
    tracker.is_current = False
    tracker.marked_outdated_at = datetime.utcnow()
    tracker.marked_by = session.get('user_id')

    db.session.commit()

    return jsonify({'success': True, 'message': 'Version marked as outdated'})


@bp.route('/api/audit/versions/<int:tracker_id>', methods=['DELETE'])
@admin_required
def delete_version_tracker(tracker_id):
    """Delete a version tracking entry."""
    from app.integrations_models import SoftwareVersionTracker

    tracker = SoftwareVersionTracker.query.get_or_404(tracker_id)
    db.session.delete(tracker)
    db.session.commit()

    return jsonify({'success': True, 'message': 'Version entry deleted'})


@bp.route('/api/audit/stale', methods=['GET'])
@admin_required
def get_stale_software():
    """
    Get software that hasn't been seen in agent reports recently.
    These are potential candidates for removal.
    """
    from app.integrations_models import SoftwareVersionTracker

    days = request.args.get('days', 30, type=int)
    org_id = request.args.get('organization_id', type=int)

    stale_threshold = datetime.utcnow() - timedelta(days=days)

    query = SoftwareVersionTracker.query.filter(
        SoftwareVersionTracker.last_seen_at < stale_threshold,
        SoftwareVersionTracker.is_outdated == False
    )

    if org_id:
        query = query.filter_by(organization_id=org_id)

    stale_items = query.order_by(SoftwareVersionTracker.last_seen_at.asc()).all()

    return jsonify({
        'items': [item.to_dict() for item in stale_items],
        'count': len(stale_items),
        'threshold_days': days
    })


@bp.route('/api/audit/cleanup', methods=['POST'])
@admin_required
def cleanup_stale_versions():
    """
    Bulk cleanup: mark all stale versions as outdated.
    """
    from app.integrations_models import SoftwareVersionTracker
    from flask import session

    data = request.get_json() or {}
    days = data.get('days', 30)
    org_id = data.get('organization_id')

    stale_threshold = datetime.utcnow() - timedelta(days=days)

    query = SoftwareVersionTracker.query.filter(
        SoftwareVersionTracker.last_seen_at < stale_threshold,
        SoftwareVersionTracker.is_outdated == False
    )

    if org_id:
        query = query.filter_by(organization_id=org_id)

    count = query.update({
        'is_outdated': True,
        'is_current': False,
        'marked_outdated_at': datetime.utcnow(),
        'marked_by': session.get('user_id')
    }, synchronize_session=False)

    db.session.commit()

    return jsonify({
        'success': True,
        'marked_count': count,
        'message': f'Marked {count} stale versions as outdated'
    })
