"""
SentriKat Agent API

API endpoints for agent-based inventory reporting.
Agents deployed on servers use these endpoints to report their software inventory.

Authentication: Agent API Key (header: X-Agent-Key)

Rate Limiting:
- Inventory reports: 60/minute per API key (1/second average)
- Heartbeats: 120/minute per API key
- General queries: 100/minute per IP
"""

from flask import Blueprint, request, jsonify
from datetime import datetime
from functools import wraps
import logging

from app import db, csrf, limiter
from app.models import (
    Asset, ProductInstallation, Product, AgentApiKey, Organization, InventoryJob
)
import json

# Threshold for async processing (queued instead of immediate)
ASYNC_BATCH_THRESHOLD = 100

logger = logging.getLogger(__name__)

agent_bp = Blueprint('agent', __name__)
csrf.exempt(agent_bp)  # Agents use API keys, not CSRF


# ============================================================================
# Rate Limiting Functions
# ============================================================================

def get_agent_key_for_limit():
    """Get API key from request for rate limiting."""
    return request.headers.get('X-Agent-Key', 'anonymous')


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
# Async Job Processing
# ============================================================================

def queue_inventory_job(organization, data):
    """
    Queue a large inventory report for async processing.
    Returns immediately with job ID.
    """
    hostname = data.get('hostname')
    agent_id = data.get('agent', {}).get('id')

    try:
        # Find or create asset first (so we have asset_id for the job)
        asset = None
        if agent_id:
            asset = Asset.query.filter_by(agent_id=agent_id).first()

        if not asset:
            asset = Asset.query.filter_by(
                organization_id=organization.id,
                hostname=hostname
            ).first()

        if not asset:
            asset = Asset(
                organization_id=organization.id,
                hostname=hostname
            )
            db.session.add(asset)
            db.session.flush()

        # Update basic asset info immediately
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
        asset.status = 'online'

        # Create job with products payload
        job = InventoryJob(
            organization_id=organization.id,
            asset_id=asset.id,
            job_type='inventory',
            status='pending',
            priority=5,
            payload=json.dumps({
                'products': data.get('products', []),
                'hostname': hostname
            }),
            total_items=len(data.get('products', []))
        )
        db.session.add(job)
        db.session.commit()

        logger.info(
            f"Queued inventory job {job.id} for {hostname}: "
            f"{len(data.get('products', []))} products to process"
        )

        return jsonify({
            'status': 'queued',
            'job_id': job.id,
            'asset_id': asset.id,
            'hostname': hostname,
            'message': f'Large batch ({len(data.get("products", []))} products) queued for processing',
            'check_status_url': f'/api/agent/jobs/{job.id}'
        }), 202

    except Exception as e:
        db.session.rollback()
        logger.error(f"Error queueing inventory job: {e}", exc_info=True)
        return jsonify({'error': f'Failed to queue inventory: {str(e)}'}), 500


def process_inventory_job(job):
    """
    Process a queued inventory job.
    Called by background worker.
    """
    try:
        job.status = 'processing'
        job.started_at = datetime.utcnow()
        db.session.commit()

        payload = json.loads(job.payload)
        products = payload.get('products', [])
        asset = Asset.query.get(job.asset_id)
        organization = Organization.query.get(job.organization_id)

        if not asset:
            job.status = 'failed'
            job.error_message = 'Asset not found'
            job.completed_at = datetime.utcnow()
            db.session.commit()
            return False

        products_created = 0
        products_updated = 0
        installations_created = 0
        installations_updated = 0
        items_failed = 0

        for product_data in products:
            try:
                vendor = product_data.get('vendor')
                product_name = product_data.get('product')
                version = product_data.get('version')

                if not vendor or not product_name:
                    items_failed += 1
                    continue

                # Find or create product
                product = Product.query.filter_by(
                    vendor=vendor,
                    product_name=product_name
                ).first()

                if not product:
                    product = Product(
                        vendor=vendor,
                        product_name=product_name,
                        version=version,
                        active=True,
                        criticality='medium'
                    )
                    db.session.add(product)
                    db.session.flush()
                    products_created += 1

                    if organization not in product.organizations.all():
                        product.organizations.append(organization)
                else:
                    products_updated += 1
                    if organization not in product.organizations.all():
                        product.organizations.append(organization)

                # Find or create installation
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
                    installation.version = version
                    installation.install_path = product_data.get('path')
                    installation.last_seen_at = datetime.utcnow()
                    installations_updated += 1

                job.items_processed += 1

                # Commit in batches of 50
                if job.items_processed % 50 == 0:
                    db.session.commit()

            except Exception as e:
                items_failed += 1
                logger.warning(f"Error processing product in job {job.id}: {e}")

        # Update asset inventory timestamp
        asset.last_inventory_at = datetime.utcnow()

        # Finalize job
        job.status = 'completed'
        job.completed_at = datetime.utcnow()
        job.items_created = products_created + installations_created
        job.items_updated = products_updated + installations_updated
        job.items_failed = items_failed
        db.session.commit()

        logger.info(
            f"Completed inventory job {job.id}: "
            f"{products_created} products created, {products_updated} updated, "
            f"{installations_created} installations created, {installations_updated} updated"
        )
        return True

    except Exception as e:
        db.session.rollback()
        job.status = 'failed'
        job.error_message = str(e)
        job.completed_at = datetime.utcnow()
        db.session.commit()
        logger.error(f"Error processing inventory job {job.id}: {e}", exc_info=True)
        return False


# ============================================================================
# Inventory Reporting Endpoints
# ============================================================================

@agent_bp.route('/api/agent/inventory', methods=['POST'])
@limiter.limit("60/minute", key_func=get_agent_key_for_limit)
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

    # Check if batch should be processed asynchronously
    if len(products) >= ASYNC_BATCH_THRESHOLD:
        return queue_inventory_job(organization, data)

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
@limiter.limit("120/minute", key_func=get_agent_key_for_limit)
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
# Job Status & Processing Endpoints
# ============================================================================

@agent_bp.route('/api/agent/jobs/<int:job_id>', methods=['GET'])
@agent_auth_required
def get_job_status(job_id):
    """
    Get status of an inventory job.
    Agents can poll this to check if their queued job is complete.
    """
    organization = request.organization

    job = InventoryJob.query.filter_by(
        id=job_id,
        organization_id=organization.id
    ).first()

    if not job:
        return jsonify({'error': 'Job not found'}), 404

    return jsonify(job.to_dict())


@agent_bp.route('/api/agent/jobs', methods=['GET'])
@agent_auth_required
def list_jobs():
    """List inventory jobs for the organization."""
    organization = request.organization

    status = request.args.get('status')
    limit = request.args.get('limit', 50, type=int)

    query = InventoryJob.query.filter_by(organization_id=organization.id)

    if status:
        query = query.filter_by(status=status)

    jobs = query.order_by(InventoryJob.created_at.desc()).limit(min(limit, 100)).all()

    return jsonify({
        'jobs': [j.to_dict() for j in jobs],
        'total': len(jobs)
    })


@agent_bp.route('/api/admin/process-jobs', methods=['POST'])
def trigger_job_processing():
    """
    Trigger processing of pending inventory jobs.
    Called by cron or manually by admin.
    """
    from app.auth import get_current_user

    user = get_current_user()
    if not user or not user.is_super_admin():
        return jsonify({'error': 'Super admin access required'}), 403

    max_jobs = request.args.get('max', 10, type=int)
    jobs_processed = 0
    jobs_failed = 0

    for _ in range(max_jobs):
        job = InventoryJob.get_next_pending()
        if not job:
            break

        success = process_inventory_job(job)
        if success:
            jobs_processed += 1
        else:
            jobs_failed += 1

    return jsonify({
        'status': 'ok',
        'jobs_processed': jobs_processed,
        'jobs_failed': jobs_failed,
        'message': f'Processed {jobs_processed} jobs ({jobs_failed} failed)'
    })


@agent_bp.route('/api/admin/jobs', methods=['GET'])
def admin_list_jobs():
    """List all inventory jobs (admin view)."""
    from app.auth import get_current_user

    user = get_current_user()
    if not user:
        return jsonify({'error': 'Authentication required'}), 401

    if not user.is_super_admin():
        return jsonify({'error': 'Super admin access required'}), 403

    status = request.args.get('status')
    org_id = request.args.get('organization_id', type=int)
    page = request.args.get('page', 1, type=int)
    per_page = min(request.args.get('per_page', 50, type=int), 100)

    query = InventoryJob.query

    if status:
        query = query.filter_by(status=status)
    if org_id:
        query = query.filter_by(organization_id=org_id)

    pagination = query.order_by(InventoryJob.created_at.desc()).paginate(
        page=page, per_page=per_page, error_out=False
    )

    return jsonify({
        'jobs': [j.to_dict() for j in pagination.items],
        'total': pagination.total,
        'page': page,
        'per_page': per_page,
        'pages': pagination.pages,
        'pending_count': InventoryJob.query.filter_by(status='pending').count(),
        'processing_count': InventoryJob.query.filter_by(status='processing').count()
    })


# ============================================================================
# Asset Management Endpoints (authenticated)
# ============================================================================

@agent_bp.route('/api/assets', methods=['GET'])
@limiter.limit("100/minute")
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
        if not user_org_ids:
            # User has no organization memberships - return empty result
            return jsonify({
                'assets': [],
                'total': 0,
                'page': 1,
                'per_page': 50,
                'pages': 0
            })
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
