"""
SentriKat Agent API

API endpoints for agent-based inventory reporting.
Agents deployed on servers use these endpoints to report their software inventory.

Authentication: Agent API Key (header: X-Agent-Key)
"""

from flask import Blueprint, request, jsonify
from datetime import datetime
from functools import wraps
import logging

from app import db, csrf
from app.models import (
    Asset, ProductInstallation, Product, AgentApiKey, Organization
)

logger = logging.getLogger(__name__)

agent_bp = Blueprint('agent', __name__)
csrf.exempt(agent_bp)  # Agents use API keys, not CSRF


# ============================================================================
# Agent Authentication
# ============================================================================

def get_agent_api_key():
    """
    Validate agent API key from request header.
    Returns (AgentApiKey, Organization) tuple or (None, None) if invalid.
    """
    api_key = request.headers.get('X-Agent-Key')
    if not api_key:
        return None, None

    # Hash the key and look it up
    key_hash = AgentApiKey.hash_key(api_key)
    agent_key = AgentApiKey.query.filter_by(key_hash=key_hash).first()

    if not agent_key:
        return None, None

    if not agent_key.is_valid():
        return None, None

    # Update usage stats
    agent_key.last_used_at = datetime.utcnow()
    agent_key.usage_count += 1
    db.session.commit()

    return agent_key, agent_key.organization


def agent_auth_required(f):
    """Decorator requiring valid agent API key."""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        agent_key, organization = get_agent_api_key()
        if not agent_key:
            return jsonify({
                'error': 'Invalid or missing API key',
                'hint': 'Include X-Agent-Key header with your agent API key'
            }), 401

        # Add to request context
        request.agent_key = agent_key
        request.organization = organization
        return f(*args, **kwargs)
    return decorated_function


# ============================================================================
# Inventory Reporting Endpoints
# ============================================================================

@agent_bp.route('/api/agent/inventory', methods=['POST'])
@agent_auth_required
def report_inventory():
    """
    Report software inventory from an agent.

    Expected JSON body:
    {
        "hostname": "server-1.example.com",
        "ip_address": "192.168.1.10",
        "os": {
            "name": "Linux",
            "version": "Ubuntu 22.04",
            "kernel": "5.15.0-91-generic"
        },
        "agent": {
            "id": "unique-agent-id-123",
            "version": "1.0.0"
        },
        "products": [
            {
                "vendor": "Apache",
                "product": "HTTP Server",
                "version": "2.4.52",
                "path": "/usr/sbin/apache2"
            },
            {
                "vendor": "OpenSSL",
                "product": "OpenSSL",
                "version": "3.0.2",
                "path": "/usr/bin/openssl"
            }
        ]
    }
    """
    organization = request.organization
    data = request.get_json()

    if not data:
        return jsonify({'error': 'JSON body required'}), 400

    hostname = data.get('hostname')
    if not hostname:
        return jsonify({'error': 'hostname is required'}), 400

    products = data.get('products', [])

    try:
        # Find or create asset
        agent_id = data.get('agent', {}).get('id')

        # Try to find by agent_id first, then hostname
        asset = None
        if agent_id:
            asset = Asset.query.filter_by(agent_id=agent_id).first()

        if not asset:
            asset = Asset.query.filter_by(
                organization_id=organization.id,
                hostname=hostname
            ).first()

        if not asset:
            # Create new asset
            asset = Asset(
                organization_id=organization.id,
                hostname=hostname
            )
            db.session.add(asset)
            logger.info(f"Created new asset: {hostname} for org {organization.id}")

        # Update asset info
        asset.ip_address = data.get('ip_address')
        asset.fqdn = data.get('fqdn')

        os_info = data.get('os', {})
        asset.os_name = os_info.get('name')
        asset.os_version = os_info.get('version')
        asset.os_kernel = os_info.get('kernel')

        agent_info = data.get('agent', {})
        if agent_info.get('id'):
            asset.agent_id = agent_info['id']
        asset.agent_version = agent_info.get('version')

        asset.last_checkin = datetime.utcnow()
        asset.last_inventory_at = datetime.utcnow()
        asset.status = 'online'

        db.session.flush()  # Get asset ID

        # Process products
        products_created = 0
        products_updated = 0
        installations_created = 0
        installations_updated = 0

        for product_data in products:
            vendor = product_data.get('vendor')
            product_name = product_data.get('product')
            version = product_data.get('version')

            if not vendor or not product_name:
                continue

            # Find or create product
            product = Product.query.filter_by(
                vendor=vendor,
                product_name=product_name
            ).first()

            if not product:
                # Create product
                product = Product(
                    vendor=vendor,
                    product_name=product_name,
                    version=version,  # Use first reported version as default
                    active=True,
                    criticality='medium'
                )
                db.session.add(product)
                db.session.flush()
                products_created += 1

                # Assign to organization
                if organization not in product.organizations.all():
                    product.organizations.append(organization)
            else:
                products_updated += 1
                # Ensure product is assigned to this organization
                if organization not in product.organizations.all():
                    product.organizations.append(organization)

            # Find or create product installation
            installation = ProductInstallation.query.filter_by(
                asset_id=asset.id,
                product_id=product.id
            ).first()

            if not installation:
                installation = ProductInstallation(
                    asset_id=asset.id,
                    product_id=product.id,
                    version=version,
                    install_path=product_data.get('path'),
                    detected_by='agent'
                )
                db.session.add(installation)
                installations_created += 1
            else:
                # Update existing installation
                installation.version = version
                installation.install_path = product_data.get('path')
                installation.last_seen_at = datetime.utcnow()
                installations_updated += 1

        db.session.commit()

        logger.info(
            f"Inventory reported for {hostname}: "
            f"{products_created} products created, {products_updated} updated, "
            f"{installations_created} installations created, {installations_updated} updated"
        )

        return jsonify({
            'status': 'success',
            'asset_id': asset.id,
            'hostname': asset.hostname,
            'summary': {
                'products_created': products_created,
                'products_updated': products_updated,
                'installations_created': installations_created,
                'installations_updated': installations_updated,
                'total_products': len(products)
            }
        })

    except Exception as e:
        db.session.rollback()
        logger.error(f"Error processing inventory report: {e}", exc_info=True)
        return jsonify({'error': f'Failed to process inventory: {str(e)}'}), 500


@agent_bp.route('/api/agent/heartbeat', methods=['POST'])
@agent_auth_required
def agent_heartbeat():
    """
    Simple heartbeat endpoint for agents to report they're alive.
    Lighter than full inventory report.
    """
    organization = request.organization
    data = request.get_json() or {}

    hostname = data.get('hostname')
    agent_id = data.get('agent_id')

    if not hostname and not agent_id:
        return jsonify({'error': 'hostname or agent_id required'}), 400

    # Find asset
    asset = None
    if agent_id:
        asset = Asset.query.filter_by(agent_id=agent_id).first()
    if not asset and hostname:
        asset = Asset.query.filter_by(
            organization_id=organization.id,
            hostname=hostname
        ).first()

    if not asset:
        return jsonify({'error': 'Asset not found. Send full inventory first.'}), 404

    # Update checkin
    asset.last_checkin = datetime.utcnow()
    asset.status = 'online'
    db.session.commit()

    return jsonify({
        'status': 'ok',
        'asset_id': asset.id,
        'hostname': asset.hostname,
        'server_time': datetime.utcnow().isoformat()
    })


# ============================================================================
# Asset Management Endpoints (authenticated)
# ============================================================================

@agent_bp.route('/api/assets', methods=['GET'])
def list_assets():
    """List all assets for the organization."""
    from app.auth import get_current_user, login_required_api

    user = get_current_user()
    if not user:
        return jsonify({'error': 'Authentication required'}), 401

    # Get organization filter
    org_id = request.args.get('organization_id', type=int)

    # Build query
    query = Asset.query

    # Filter by organization based on user role
    if user.is_super_admin():
        if org_id:
            query = query.filter_by(organization_id=org_id)
    else:
        # Non-super-admins can only see their organization's assets
        user_org_ids = [m.organization_id for m in user.org_memberships.all()]
        if org_id and org_id in user_org_ids:
            query = query.filter_by(organization_id=org_id)
        else:
            query = query.filter(Asset.organization_id.in_(user_org_ids))

    # Additional filters
    status = request.args.get('status')
    if status:
        query = query.filter_by(status=status)

    active = request.args.get('active')
    if active is not None:
        query = query.filter_by(active=active.lower() == 'true')

    search = request.args.get('search')
    if search:
        search_term = f"%{search}%"
        query = query.filter(
            db.or_(
                Asset.hostname.ilike(search_term),
                Asset.ip_address.ilike(search_term),
                Asset.fqdn.ilike(search_term)
            )
        )

    # Pagination
    page = request.args.get('page', 1, type=int)
    per_page = min(request.args.get('per_page', 50, type=int), 100)

    # Order by
    order = request.args.get('order', 'hostname')
    direction = request.args.get('direction', 'asc')

    if hasattr(Asset, order):
        order_col = getattr(Asset, order)
        if direction == 'desc':
            order_col = order_col.desc()
        query = query.order_by(order_col)

    # Execute
    pagination = query.paginate(page=page, per_page=per_page, error_out=False)

    return jsonify({
        'assets': [a.to_dict() for a in pagination.items],
        'total': pagination.total,
        'page': page,
        'per_page': per_page,
        'pages': pagination.pages
    })


@agent_bp.route('/api/assets/<int:asset_id>', methods=['GET'])
def get_asset(asset_id):
    """Get asset details with installed products."""
    from app.auth import get_current_user

    user = get_current_user()
    if not user:
        return jsonify({'error': 'Authentication required'}), 401

    asset = Asset.query.get_or_404(asset_id)

    # Check permission
    if not user.is_super_admin():
        user_org_ids = [m.organization_id for m in user.org_memberships.all()]
        if asset.organization_id not in user_org_ids:
            return jsonify({'error': 'Access denied'}), 403

    return jsonify(asset.to_dict(include_products=True))


@agent_bp.route('/api/assets/<int:asset_id>', methods=['DELETE'])
def delete_asset(asset_id):
    """Delete an asset and its product installations."""
    from app.auth import get_current_user

    user = get_current_user()
    if not user:
        return jsonify({'error': 'Authentication required'}), 401

    asset = Asset.query.get_or_404(asset_id)

    # Check permission (requires manager or above)
    if not user.is_super_admin():
        user_org = user.org_memberships.filter_by(organization_id=asset.organization_id).first()
        if not user_org or user_org.role not in ['org_admin', 'manager']:
            return jsonify({'error': 'Manager access required'}), 403

    hostname = asset.hostname
    db.session.delete(asset)
    db.session.commit()

    logger.info(f"Asset deleted: {hostname} by user {user.username}")

    return jsonify({
        'status': 'success',
        'message': f'Asset {hostname} deleted'
    })


# ============================================================================
# Agent API Key Management
# ============================================================================

@agent_bp.route('/api/agent-keys', methods=['GET'])
def list_agent_keys():
    """List agent API keys for organization."""
    from app.auth import get_current_user

    user = get_current_user()
    if not user:
        return jsonify({'error': 'Authentication required'}), 401

    # Check permission
    if not user.is_super_admin():
        # Only org admins can manage keys
        org_id = request.args.get('organization_id', type=int)
        if not org_id:
            return jsonify({'error': 'organization_id required'}), 400

        user_org = user.org_memberships.filter_by(organization_id=org_id).first()
        if not user_org or user_org.role != 'org_admin':
            return jsonify({'error': 'Organization admin access required'}), 403

        keys = AgentApiKey.query.filter_by(organization_id=org_id).all()
    else:
        org_id = request.args.get('organization_id', type=int)
        if org_id:
            keys = AgentApiKey.query.filter_by(organization_id=org_id).all()
        else:
            keys = AgentApiKey.query.all()

    return jsonify({
        'api_keys': [k.to_dict() for k in keys]
    })


@agent_bp.route('/api/agent-keys', methods=['POST'])
def create_agent_key():
    """Create a new agent API key."""
    from app.auth import get_current_user

    user = get_current_user()
    if not user:
        return jsonify({'error': 'Authentication required'}), 401

    data = request.get_json()
    org_id = data.get('organization_id')
    name = data.get('name')

    if not org_id or not name:
        return jsonify({'error': 'organization_id and name required'}), 400

    # Check permission
    if not user.is_super_admin():
        user_org = user.org_memberships.filter_by(organization_id=org_id).first()
        if not user_org or user_org.role != 'org_admin':
            return jsonify({'error': 'Organization admin access required'}), 403

    # Generate key
    raw_key = AgentApiKey.generate_key()
    key_hash = AgentApiKey.hash_key(raw_key)
    key_prefix = raw_key[:10]

    agent_key = AgentApiKey(
        organization_id=org_id,
        name=name,
        key_hash=key_hash,
        key_prefix=key_prefix,
        max_assets=data.get('max_assets'),
        created_by=user.id
    )

    if data.get('expires_days'):
        from datetime import timedelta
        agent_key.expires_at = datetime.utcnow() + timedelta(days=data['expires_days'])

    db.session.add(agent_key)
    db.session.commit()

    logger.info(f"Agent API key created: {name} by {user.username}")

    # Return the raw key ONLY THIS ONE TIME
    result = agent_key.to_dict()
    result['api_key'] = raw_key
    result['warning'] = 'Save this key now. It will not be shown again.'

    return jsonify(result), 201


@agent_bp.route('/api/agent-keys/<int:key_id>', methods=['DELETE'])
def delete_agent_key(key_id):
    """Delete an agent API key."""
    from app.auth import get_current_user

    user = get_current_user()
    if not user:
        return jsonify({'error': 'Authentication required'}), 401

    agent_key = AgentApiKey.query.get_or_404(key_id)

    # Check permission
    if not user.is_super_admin():
        user_org = user.org_memberships.filter_by(organization_id=agent_key.organization_id).first()
        if not user_org or user_org.role != 'org_admin':
            return jsonify({'error': 'Organization admin access required'}), 403

    name = agent_key.name
    db.session.delete(agent_key)
    db.session.commit()

    logger.info(f"Agent API key deleted: {name} by {user.username}")

    return jsonify({
        'status': 'success',
        'message': f'API key {name} deleted'
    })
