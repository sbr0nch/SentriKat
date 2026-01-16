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

from flask import Blueprint, request, jsonify, current_app
from datetime import datetime, timedelta
from functools import wraps
import logging
import threading
import time
import re
import ipaddress

from app import db, csrf, limiter
from app.models import (
    Asset, ProductInstallation, Product, AgentApiKey, Organization, InventoryJob,
    AgentLicense, AgentUsageRecord, AgentEvent, ProductVersionHistory, StaleAssetNotification
)
from app.licensing import requires_professional, get_license, check_agent_limit, check_agent_api_key_limit, get_agent_usage
import json

# Threshold for async processing (queued instead of immediate)
ASYNC_BATCH_THRESHOLD = 100

# Input validation limits
MAX_HOSTNAME_LENGTH = 255
MAX_VENDOR_LENGTH = 200
MAX_PRODUCT_NAME_LENGTH = 200
MAX_VERSION_LENGTH = 100
MAX_PATH_LENGTH = 500
MAX_PRODUCTS_PER_REQUEST = 5000  # Absolute maximum products in single request

# Background worker settings
WORKER_CHECK_INTERVAL = 5  # seconds between job checks
_worker_thread = None
_worker_stop_event = threading.Event()

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

def _ip_in_allowlist(ip_str, allowed_list):
    """
    Check if an IP address is in the allowlist.
    Supports individual IPs and CIDR notation.
    """
    if not allowed_list:
        return True  # No allowlist = allow all

    try:
        client_ip = ipaddress.ip_address(ip_str)

        for allowed in allowed_list:
            allowed = allowed.strip()
            if not allowed:
                continue

            try:
                # Check if it's a CIDR network
                if '/' in allowed:
                    network = ipaddress.ip_network(allowed, strict=False)
                    if client_ip in network:
                        return True
                else:
                    # Single IP comparison
                    if client_ip == ipaddress.ip_address(allowed):
                        return True
            except ValueError:
                # Invalid CIDR/IP in allowlist, skip
                continue

        return False
    except ValueError:
        # Invalid client IP
        logger.warning(f"Invalid client IP address: {ip_str}")
        return False


def get_agent_api_key():
    """
    Validate agent API key from request header.
    Returns (AgentApiKey, Organization) tuple or (None, None) if invalid.

    Security checks:
    1. Key exists and is valid (active, not expired)
    2. IP allowlist enforcement (if configured)
    3. Updates usage statistics for metering
    """
    source_ip = request.remote_addr
    user_agent = request.headers.get('User-Agent', '')[:500]  # Truncate for safety

    api_key = request.headers.get('X-Agent-Key')
    if not api_key:
        logger.warning(f"Agent auth failed: No X-Agent-Key header from {source_ip}")
        return None, None

    # Hash the key and look it up
    key_hash = AgentApiKey.hash_key(api_key)
    agent_key = AgentApiKey.query.filter_by(key_hash=key_hash).first()

    if not agent_key:
        logger.warning(f"Agent auth failed: Invalid API key from {source_ip}")
        # Log failed auth event
        try:
            # We don't know which org, so log without org context
            pass  # Can't log without org_id
        except Exception:
            pass
        return None, None

    if not agent_key.is_valid():
        logger.warning(f"Agent auth failed: Expired/inactive key '{agent_key.name}' from {source_ip}")
        # Log failed auth event
        AgentEvent.log_event(
            organization_id=agent_key.organization_id,
            event_type='auth_failed',
            api_key_id=agent_key.id,
            details={'reason': 'expired_or_inactive'},
            source_ip=source_ip,
            user_agent=user_agent
        )
        db.session.commit()
        return None, None

    # ENFORCE IP ALLOWLIST (if configured)
    allowed_ips = agent_key.get_allowed_ips()
    if allowed_ips and not _ip_in_allowlist(source_ip, allowed_ips):
        logger.warning(
            f"Agent auth failed: IP {source_ip} not in allowlist for key '{agent_key.name}'"
        )
        # Log blocked IP event
        AgentEvent.log_event(
            organization_id=agent_key.organization_id,
            event_type='ip_blocked',
            api_key_id=agent_key.id,
            details={'blocked_ip': source_ip, 'allowed_ips': allowed_ips},
            source_ip=source_ip,
            user_agent=user_agent
        )
        db.session.commit()
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
# Input Validation & Sanitization
# ============================================================================

def sanitize_string(value, max_length, field_name):
    """
    Sanitize and validate a string input.
    Returns (sanitized_value, error) tuple.
    """
    if value is None:
        return None, None

    if not isinstance(value, str):
        return None, f"{field_name} must be a string"

    # Remove control characters (except newlines/tabs which might be in paths)
    sanitized = re.sub(r'[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]', '', value)

    # Trim whitespace
    sanitized = sanitized.strip()

    # Check length
    if len(sanitized) > max_length:
        return sanitized[:max_length], None  # Truncate silently

    return sanitized, None


def validate_inventory_payload(data):
    """
    Validate the inventory payload structure and content.
    Returns (is_valid, errors_list) tuple.
    """
    errors = []

    # Required fields
    hostname = data.get('hostname')
    if not hostname:
        errors.append("hostname is required")
    else:
        hostname, err = sanitize_string(hostname, MAX_HOSTNAME_LENGTH, 'hostname')
        if err:
            errors.append(err)
        elif not hostname:
            errors.append("hostname cannot be empty")
        # Validate hostname format (alphanumeric, hyphens, dots)
        elif not re.match(r'^[a-zA-Z0-9][a-zA-Z0-9._-]*$', hostname):
            errors.append("hostname contains invalid characters")
        data['hostname'] = hostname

    # Products validation
    products = data.get('products', [])
    if not isinstance(products, list):
        errors.append("products must be an array")
    elif len(products) > MAX_PRODUCTS_PER_REQUEST:
        errors.append(f"Too many products ({len(products)}). Maximum is {MAX_PRODUCTS_PER_REQUEST}")
    else:
        # Validate each product
        for i, product in enumerate(products):
            if not isinstance(product, dict):
                errors.append(f"products[{i}] must be an object")
                continue

            vendor = product.get('vendor')
            product_name = product.get('product')

            if vendor:
                vendor, _ = sanitize_string(vendor, MAX_VENDOR_LENGTH, 'vendor')
                product['vendor'] = vendor

            if product_name:
                product_name, _ = sanitize_string(product_name, MAX_PRODUCT_NAME_LENGTH, 'product')
                product['product'] = product_name

            version = product.get('version')
            if version:
                version, _ = sanitize_string(version, MAX_VERSION_LENGTH, 'version')
                product['version'] = version

            path = product.get('path')
            if path:
                path, _ = sanitize_string(path, MAX_PATH_LENGTH, 'path')
                product['path'] = path

    # Optional fields validation
    ip_address = data.get('ip_address')
    if ip_address:
        ip_address, _ = sanitize_string(ip_address, 45, 'ip_address')
        data['ip_address'] = ip_address

    return len(errors) == 0, errors


def check_license_can_add_agent(organization_id, is_new_agent=True):
    """
    Check if the license allows adding a new agent.
    Returns (allowed, message, license_info) tuple.

    IMPORTANT: This now uses the CORE RSA-signed license system for enforcement,
    not the database-only AgentLicense table. The limits in the signed license
    cannot be tampered with by modifying the database.

    Agent limits are GLOBAL (across all organizations) to prevent the multi-org
    bypass vulnerability where users create multiple orgs to circumvent limits.

    The AgentLicense table is now used only for usage tracking/metering.
    """
    # Get license info from core system (RSA-signed, tamper-proof)
    license_info = get_license()
    agent_usage = get_agent_usage()

    # Check if push_agents feature is enabled
    if not agent_usage['feature_enabled']:
        return False, "Push Agents require a Professional license.", {
            'edition': license_info.get_effective_edition(),
            'feature_enabled': False,
            'upgrade_required': True
        }

    # Check GLOBAL agent limit (from signed license)
    if is_new_agent:
        can_add, limit, message = check_agent_limit()
        if not can_add:
            return False, message, {
                'edition': license_info.get_effective_edition(),
                'current_agents': agent_usage['agents']['current'],
                'max_agents': agent_usage['agents']['limit'],
                'limit_reached': True,
                'global_limit': True  # Indicate this is a global limit
            }

    # Update usage tracking (for metering/billing only - not enforcement)
    try:
        license_obj = AgentLicense.query.filter_by(organization_id=organization_id).first()
        if license_obj:
            license_obj.update_agent_count()
    except Exception as e:
        logger.warning(f"Could not update usage tracking: {e}")

    # Calculate usage percentage for warnings
    current = agent_usage['agents']['current']
    limit = agent_usage['agents']['limit']
    warning = None

    if limit != -1:  # Not unlimited
        usage_percent = (current / limit * 100) if limit > 0 else 100
        if usage_percent >= 90:
            warning = f"Agent limit almost reached ({current}/{limit}). Please upgrade soon."
        elif usage_percent >= 80:
            warning = f"Approaching agent limit ({current}/{limit})."

    return True, warning, {
        'edition': license_info.get_effective_edition(),
        'current_agents': current,
        'max_agents': limit,
        'unlimited': limit == -1,
        'global_limit': True
    }


def update_usage_metrics(organization_id, is_new_agent=False, products_count=0):
    """
    Update usage metrics for billing and analytics.
    Called after successful inventory report.
    """
    try:
        # Get or create today's usage record
        usage = AgentUsageRecord.get_or_create_today(organization_id)

        # Increment counters
        usage.inventory_reports += 1
        usage.products_discovered += products_count

        if is_new_agent:
            usage.new_agents += 1

        # Update active agent count
        license_obj = AgentLicense.query.filter_by(organization_id=organization_id).first()
        if license_obj:
            license_obj.update_agent_count()
            usage.active_agents = license_obj.current_agents
            if usage.active_agents > usage.peak_agents:
                usage.peak_agents = usage.active_agents

        db.session.commit()
    except Exception as e:
        logger.error(f"Error updating usage metrics: {e}")
        db.session.rollback()


# ============================================================================
# Background Job Worker
# ============================================================================

def _background_job_worker(app):
    """
    Background worker thread that processes pending inventory jobs.
    Runs continuously until stop event is set.

    IMPORTANT: Each iteration creates a fresh database session to avoid
    stale connection issues (psycopg2 connection pool problems).
    """
    logger.info("Background job worker started")

    while not _worker_stop_event.is_set():
        try:
            # Create fresh app context for each iteration to avoid stale connections
            with app.app_context():
                try:
                    # Get next pending job
                    job = InventoryJob.get_next_pending()

                    if job:
                        job_id = job.id  # Store ID before processing
                        logger.info(f"Background worker processing job {job_id}")
                        try:
                            success = process_inventory_job(job)
                            if success:
                                logger.info(f"Background worker completed job {job_id}")
                            else:
                                logger.warning(f"Background worker: job {job_id} failed")
                        except Exception as e:
                            logger.error(f"Background worker error processing job {job_id}: {e}", exc_info=True)
                            # Mark job as failed - refetch to avoid stale object
                            try:
                                job = InventoryJob.query.get(job_id)
                                if job:
                                    job.status = 'failed'
                                    job.error_message = str(e)[:500]  # Truncate long errors
                                    job.completed_at = datetime.utcnow()
                                    db.session.commit()
                            except Exception as commit_err:
                                logger.error(f"Failed to mark job {job_id} as failed: {commit_err}")
                                db.session.rollback()
                    else:
                        # No pending jobs, sleep before checking again
                        pass  # Will sleep after context exits

                finally:
                    # Always clean up session to prevent connection leaks
                    try:
                        db.session.remove()
                    except Exception:
                        pass

            # Sleep outside the app context to allow connection cleanup
            if not _worker_stop_event.is_set():
                _worker_stop_event.wait(WORKER_CHECK_INTERVAL)

        except Exception as e:
            logger.error(f"Background worker unexpected error: {e}", exc_info=True)
            # Sleep before retrying on error
            if not _worker_stop_event.is_set():
                _worker_stop_event.wait(WORKER_CHECK_INTERVAL)

    logger.info("Background job worker stopped")


def start_background_worker(app):
    """Start the background job worker if not already running."""
    global _worker_thread

    if _worker_thread is not None and _worker_thread.is_alive():
        return  # Already running

    _worker_stop_event.clear()
    _worker_thread = threading.Thread(
        target=_background_job_worker,
        args=(app,),
        daemon=True,
        name="InventoryJobWorker"
    )
    _worker_thread.start()
    logger.info("Started background inventory job worker")


def stop_background_worker():
    """Stop the background job worker."""
    global _worker_thread

    if _worker_thread is None:
        return

    _worker_stop_event.set()
    _worker_thread.join(timeout=10)
    _worker_thread = None
    logger.info("Stopped background inventory job worker")


def ensure_worker_running():
    """Ensure the background worker is running (call from request context)."""
    global _worker_thread

    if _worker_thread is None or not _worker_thread.is_alive():
        try:
            start_background_worker(current_app._get_current_object())
        except Exception as e:
            logger.warning(f"Could not start background worker: {e}")


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

    logger.info(f"queue_inventory_job called for hostname={hostname}, agent_id={agent_id}")

    # Validate organization
    if not organization:
        logger.error(f"queue_inventory_job: organization is None for hostname={hostname}")
        return jsonify({'error': 'Invalid organization. Check API key configuration.'}), 400

    try:
        # Find or create asset first (so we have asset_id for the job)
        asset = None
        if agent_id:
            asset = Asset.query.filter_by(agent_id=agent_id).first()
            logger.debug(f"Found asset by agent_id: {asset}")

        if not asset:
            asset = Asset.query.filter_by(
                organization_id=organization.id,
                hostname=hostname
            ).first()
            logger.debug(f"Found asset by org+hostname: {asset}")

        if not asset:
            asset = Asset(
                organization_id=organization.id,
                hostname=hostname
            )
            db.session.add(asset)
            db.session.flush()
            logger.info(f"Created new asset for {hostname}, id={asset.id}")

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

        products = data.get('products', [])
        logger.info(f"Creating inventory job for {hostname} with {len(products)} products")

        # Create job with products payload
        job = InventoryJob(
            organization_id=organization.id,
            asset_id=asset.id,
            job_type='inventory',
            status='pending',
            priority=5,
            payload=json.dumps({
                'products': products,
                'hostname': hostname
            }),
            total_items=len(products)
        )
        db.session.add(job)
        db.session.commit()

        logger.info(
            f"Queued inventory job {job.id} for {hostname}: "
            f"{len(products)} products to process"
        )

        # Ensure background worker is running to process the job
        ensure_worker_running()

        return jsonify({
            'status': 'queued',
            'job_id': job.id,
            'asset_id': asset.id,
            'hostname': hostname,
            'message': f'Large batch ({len(products)} products) queued for processing',
            'check_status_url': f'/api/agent/jobs/{job.id}'
        }), 202

    except Exception as e:
        db.session.rollback()
        logger.error(f"Error queueing inventory job for {hostname}: {e}", exc_info=True)
        return jsonify({'error': f'Failed to queue inventory: {str(e)}'}), 500


def process_inventory_job(job):
    """
    Process a queued inventory job.
    Called by background worker.

    Session management:
    - Commits in batches of 50 to avoid holding locks too long
    - Uses explicit rollback on errors to ensure clean state
    """
    job_id = job.id  # Store ID to avoid stale reference issues
    logger.info(f"=== Processing inventory job {job_id} ===")

    try:
        job.status = 'processing'
        job.started_at = datetime.utcnow()
        db.session.commit()

        payload = json.loads(job.payload)
        products = payload.get('products', [])
        logger.info(f"Job {job_id}: Loaded {len(products)} products from payload")

        # Store IDs for reference
        asset_id = job.asset_id
        org_id = job.organization_id

        asset = Asset.query.get(asset_id)
        organization = Organization.query.get(org_id)

        logger.info(f"Job {job_id}: Asset={asset.hostname if asset else 'None'}, "
                    f"Org={organization.name if organization else 'None'}")

        if not asset:
            logger.error(f"Job {job_id}: Asset {asset_id} not found")
            job.status = 'failed'
            job.error_message = 'Asset not found'
            job.completed_at = datetime.utcnow()
            db.session.commit()
            return False

        if not organization:
            logger.error(f"Job {job_id}: Organization {org_id} not found")
            job.status = 'failed'
            job.error_message = 'Organization not found'
            job.completed_at = datetime.utcnow()
            db.session.commit()
            return False

        products_created = 0
        products_updated = 0
        installations_created = 0
        installations_updated = 0
        items_failed = 0
        items_processed = 0

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
                    # Normalize OS name to platform category
                    platform = ProductInstallation.normalize_os_name(asset.os_name)

                    installation = ProductInstallation(
                        asset_id=asset.id,
                        product_id=product.id,
                        version=version,
                        install_path=product_data.get('path'),
                        detected_by='agent',
                        detected_on_os=platform  # Track which OS this came from
                    )
                    db.session.add(installation)
                    installations_created += 1
                else:
                    installation.version = version
                    installation.install_path = product_data.get('path')
                    installation.last_seen_at = datetime.utcnow()
                    installations_updated += 1

                items_processed += 1

                # Commit in batches of 50 to avoid holding locks too long
                if items_processed % 50 == 0:
                    # Update job progress before commit
                    job.items_processed = items_processed
                    db.session.commit()
                    logger.debug(f"Job {job_id}: Committed batch at {items_processed} items")

            except Exception as e:
                items_failed += 1
                logger.warning(f"Error processing product in job {job_id}: {e}")
                # Rollback the failed item but continue processing
                try:
                    db.session.rollback()
                    # Re-fetch objects after rollback
                    job = InventoryJob.query.get(job_id)
                    asset = Asset.query.get(asset_id)
                    organization = Organization.query.get(org_id)
                except Exception:
                    pass

        # Update asset inventory timestamp
        asset = Asset.query.get(asset_id)  # Re-fetch to ensure fresh object
        if asset:
            asset.last_inventory_at = datetime.utcnow()

        # Finalize job - re-fetch to ensure fresh object
        job = InventoryJob.query.get(job_id)
        if job:
            job.status = 'completed'
            job.completed_at = datetime.utcnow()
            job.items_processed = items_processed
            job.items_created = products_created + installations_created
            job.items_updated = products_updated + installations_updated
            job.items_failed = items_failed
            db.session.commit()

        logger.info(
            f"Completed inventory job {job_id}: "
            f"{products_created} products created, {products_updated} updated, "
            f"{installations_created} installations created, {installations_updated} updated"
        )
        return True

    except Exception as e:
        logger.error(f"Error processing inventory job {job_id}: {e}", exc_info=True)
        try:
            db.session.rollback()
            # Re-fetch job and mark as failed
            job = InventoryJob.query.get(job_id)
            if job:
                job.status = 'failed'
                job.error_message = str(e)[:500]
                job.completed_at = datetime.utcnow()
                db.session.commit()
        except Exception as commit_err:
            logger.error(f"Failed to mark job {job_id} as failed: {commit_err}")
            db.session.rollback()
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

    Response includes:
    - status: success/queued/error
    - license_warning: (if approaching limit)
    - summary: counts of products processed
    """
    source_ip = request.remote_addr
    user_agent = request.headers.get('User-Agent', '')[:500]
    logger.info(f"=== Agent inventory request received from {source_ip} ===")

    # Get organization from authenticated request
    organization = getattr(request, 'organization', None)
    agent_key = getattr(request, 'agent_key', None)

    logger.info(f"Auth context: org={organization.name if organization else 'None'}, "
                f"key={agent_key.name if agent_key else 'None'}")

    # Parse JSON body
    try:
        data = request.get_json(force=True)  # force=True ignores content-type
    except Exception as e:
        logger.error(f"Failed to parse JSON body: {e}")
        return jsonify({'error': f'Invalid JSON: {str(e)}'}), 400

    if not data:
        logger.warning(f"Agent inventory failed: No JSON body from {source_ip}")
        return jsonify({'error': 'JSON body required'}), 400

    # VALIDATE INPUT
    is_valid, validation_errors = validate_inventory_payload(data)
    if not is_valid:
        logger.warning(f"Agent inventory validation failed from {source_ip}: {validation_errors}")
        return jsonify({
            'error': 'Validation failed',
            'details': validation_errors
        }), 400

    hostname = data.get('hostname')
    products = data.get('products', [])
    logger.info(f"Agent inventory: {hostname} sending {len(products)} products "
                f"(threshold={ASYNC_BATCH_THRESHOLD})")

    # Validate organization
    if not organization:
        logger.error(f"Agent inventory: No organization for {hostname}. "
                     f"API key may not be assigned to an organization.")
        return jsonify({
            'error': 'API key not associated with an organization',
            'hint': 'Ensure the API key is created for a specific organization'
        }), 400

    # Check if this is a new agent (for license check)
    agent_id = data.get('agent', {}).get('id')
    existing_asset = None
    if agent_id:
        existing_asset = Asset.query.filter_by(agent_id=agent_id).first()
    if not existing_asset:
        existing_asset = Asset.query.filter_by(
            organization_id=organization.id,
            hostname=hostname
        ).first()

    is_new_agent = existing_asset is None

    # CHECK LICENSE LIMITS (pay-per-agent enforcement)
    if is_new_agent:
        can_add, license_message, license_info = check_license_can_add_agent(
            organization.id, is_new_agent=True
        )
        if not can_add:
            logger.warning(
                f"License limit exceeded for org {organization.id}: {license_message}"
            )
            # Log license exceeded event
            AgentEvent.log_event(
                organization_id=organization.id,
                event_type='license_exceeded',
                api_key_id=agent_key.id,
                details={
                    'hostname': hostname,
                    'message': license_message,
                    'license': license_info
                },
                source_ip=source_ip,
                user_agent=user_agent
            )
            db.session.commit()
            return jsonify({
                'error': 'License limit exceeded',
                'message': license_message,
                'license': license_info,
                'hint': 'Please upgrade your license to add more agents'
            }), 403
    else:
        # Existing agent - still check license for warning
        _, license_message, license_info = check_license_can_add_agent(
            organization.id, is_new_agent=False
        )

    # Check if batch should be processed asynchronously
    if len(products) >= ASYNC_BATCH_THRESHOLD:
        logger.info(f"Agent inventory: Routing to async processing for {hostname}")
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
                # Normalize OS name to platform category
                platform = ProductInstallation.normalize_os_name(asset.os_name)

                installation = ProductInstallation(
                    asset_id=asset.id,
                    product_id=product.id,
                    version=version,
                    install_path=product_data.get('path'),
                    detected_by='agent',
                    detected_on_os=platform  # Track which OS this came from
                )
                db.session.add(installation)
                db.session.flush()  # Get installation ID for version history
                installations_created += 1

                # Record version history for new installation
                ProductVersionHistory.record_change(
                    installation_id=installation.id,
                    asset_id=asset.id,
                    product_id=product.id,
                    old_version=None,
                    new_version=version,
                    detected_by='agent'
                )
            else:
                # Track version changes
                old_version = installation.version
                if old_version != version and version:
                    ProductVersionHistory.record_change(
                        installation_id=installation.id,
                        asset_id=asset.id,
                        product_id=product.id,
                        old_version=old_version,
                        new_version=version,
                        detected_by='agent'
                    )

                # Update existing installation
                installation.version = version
                installation.install_path = product_data.get('path')
                installation.last_seen_at = datetime.utcnow()
                installations_updated += 1

        # Log inventory event
        AgentEvent.log_event(
            organization_id=organization.id,
            event_type='registered' if is_new_agent else 'inventory_reported',
            asset_id=asset.id,
            api_key_id=agent_key.id,
            details={
                'hostname': hostname,
                'products_count': len(products),
                'products_created': products_created,
                'installations_created': installations_created
            },
            source_ip=source_ip,
            user_agent=user_agent
        )

        db.session.commit()

        # Update usage metrics for billing
        update_usage_metrics(
            organization_id=organization.id,
            is_new_agent=is_new_agent,
            products_count=products_created
        )

        # Resolve any stale notifications for this asset
        if not is_new_agent:
            StaleAssetNotification.query.filter_by(
                asset_id=asset.id,
                resolved=False
            ).update({
                'resolved': True,
                'resolved_at': datetime.utcnow(),
                'resolved_by': 'agent_checkin'
            })
            db.session.commit()

        logger.info(
            f"Inventory reported for {hostname}: "
            f"{products_created} products created, {products_updated} updated, "
            f"{installations_created} installations created, {installations_updated} updated"
        )

        # Build response with license warning if applicable
        response = {
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
        }

        # Include license warning if approaching limit
        if license_message:
            response['license_warning'] = license_message
            response['license'] = license_info

        return jsonify(response)

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
    from app.auth import get_current_user

    try:
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
            try:
                user_org_ids = [m.organization_id for m in user.org_memberships.all()]
            except Exception as e:
                logger.warning(f"Error getting org memberships for user {user.id}: {e}")
                user_org_ids = []

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

        # Safely convert assets to dict
        assets_list = []
        for asset in pagination.items:
            try:
                assets_list.append(asset.to_dict())
            except Exception as e:
                logger.error(f"Error converting asset {asset.id} to dict: {e}")
                assets_list.append({
                    'id': asset.id,
                    'hostname': asset.hostname or 'Unknown',
                    'error': 'Failed to load full details'
                })

        return jsonify({
            'assets': assets_list,
            'total': pagination.total,
            'page': page,
            'per_page': per_page,
            'pages': pagination.pages
        })

    except Exception as e:
        logger.error(f"Error in list_assets: {e}", exc_info=True)
        return jsonify({'error': f'Internal server error: {str(e)}'}), 500


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


@agent_bp.route('/api/assets/<int:asset_id>', methods=['PUT', 'PATCH'])
def update_asset(asset_id):
    """
    Update asset details.

    Editable fields:
    - description, notes, tags
    - criticality (critical, high, medium, low)
    - environment (production, staging, development, test)
    - owner, group_name
    - status (online, offline, stale, decommissioned)
    - active (boolean)
    """
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

    data = request.get_json()
    if not data:
        return jsonify({'error': 'No data provided'}), 400

    # Update allowed fields
    allowed_fields = [
        'description', 'notes', 'criticality', 'environment',
        'owner', 'group_name', 'status', 'active', 'asset_type'
    ]

    updated_fields = []
    for field in allowed_fields:
        if field in data:
            # Validate criticality
            if field == 'criticality' and data[field] not in ['critical', 'high', 'medium', 'low']:
                return jsonify({'error': f'Invalid criticality: {data[field]}'}), 400
            # Validate environment
            if field == 'environment' and data[field] and data[field] not in ['production', 'staging', 'development', 'test']:
                return jsonify({'error': f'Invalid environment: {data[field]}'}), 400
            # Validate status
            if field == 'status' and data[field] not in ['online', 'offline', 'stale', 'decommissioned']:
                return jsonify({'error': f'Invalid status: {data[field]}'}), 400

            setattr(asset, field, data[field])
            updated_fields.append(field)

    # Handle tags specially (accepts array)
    if 'tags' in data:
        asset.set_tags(data['tags'])
        updated_fields.append('tags')

    if not updated_fields:
        return jsonify({'error': 'No valid fields to update'}), 400

    db.session.commit()
    logger.info(f"Asset {asset.hostname} updated by {user.username}: {updated_fields}")

    return jsonify({
        'status': 'success',
        'message': f'Asset {asset.hostname} updated',
        'updated_fields': updated_fields,
        'asset': asset.to_dict()
    })


@agent_bp.route('/api/assets/groups', methods=['GET'])
def list_asset_groups():
    """List all unique asset groups/environments for filtering."""
    from app.auth import get_current_user

    user = get_current_user()
    if not user:
        return jsonify({'error': 'Authentication required'}), 401

    # Build query based on permissions
    if user.is_super_admin():
        query = Asset.query
    else:
        user_org_ids = [m.organization_id for m in user.org_memberships.all()]
        query = Asset.query.filter(Asset.organization_id.in_(user_org_ids))

    # Get distinct groups and environments
    groups = db.session.query(Asset.group_name).filter(
        Asset.group_name.isnot(None),
        Asset.id.in_([a.id for a in query.all()])
    ).distinct().all()

    environments = db.session.query(Asset.environment).filter(
        Asset.environment.isnot(None),
        Asset.id.in_([a.id for a in query.all()])
    ).distinct().all()

    return jsonify({
        'groups': [g[0] for g in groups if g[0]],
        'environments': [e[0] for e in environments if e[0]]
    })


# ============================================================================
# Agent API Key Management
# ============================================================================

@agent_bp.route('/api/agent-keys', methods=['GET'])
@requires_professional('Agent Keys')
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
@requires_professional('Agent Keys')
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

    # CHECK GLOBAL API KEY LIMIT (from signed license - tamper-proof)
    can_add, limit, message = check_agent_api_key_limit()
    if not can_add:
        agent_usage = get_agent_usage()
        return jsonify({
            'error': 'API key limit reached',
            'message': message,
            'current_keys': agent_usage['api_keys']['current'],
            'max_keys': agent_usage['api_keys']['limit'],
            'global_limit': True,  # Indicate this is a global limit
            'hint': 'Please upgrade your license to create more API keys'
        }), 403

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
@requires_professional('Agent Keys')
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


# ============================================================================
# Maintenance & Cleanup Endpoints
# ============================================================================

@agent_bp.route('/api/admin/maintenance/stats', methods=['GET'])
def get_maintenance_stats():
    """Get statistics about stale/orphaned data."""
    from app.auth import get_current_user
    from app.maintenance import get_maintenance_stats as get_stats

    user = get_current_user()
    if not user or not user.is_super_admin():
        return jsonify({'error': 'Super admin access required'}), 403

    try:
        stats = get_stats()
        return jsonify(stats)
    except Exception as e:
        logger.error(f"Error getting maintenance stats: {e}", exc_info=True)
        return jsonify({'error': str(e)}), 500


@agent_bp.route('/api/admin/maintenance/cleanup', methods=['POST'])
def run_maintenance_cleanup():
    """
    Run maintenance cleanup tasks.

    Request body (all optional):
    {
        "dry_run": false,
        "installation_stale_days": 30,
        "asset_stale_days": 14,
        "asset_remove_days": 90,
        "import_queue_keep_days": 30
    }
    """
    from app.auth import get_current_user
    from app.maintenance import run_full_maintenance

    user = get_current_user()
    if not user or not user.is_super_admin():
        return jsonify({'error': 'Super admin access required'}), 403

    data = request.get_json() or {}
    dry_run = data.get('dry_run', False)

    settings = {
        'installation_stale_days': data.get('installation_stale_days'),
        'asset_stale_days': data.get('asset_stale_days'),
        'asset_remove_days': data.get('asset_remove_days'),
        'import_queue_keep_days': data.get('import_queue_keep_days')
    }
    # Remove None values
    settings = {k: v for k, v in settings.items() if v is not None}

    try:
        result = run_full_maintenance(dry_run=dry_run, settings=settings)
        logger.info(f"Maintenance run by {user.username}: {result.to_dict()}")
        return jsonify(result.to_dict())
    except Exception as e:
        logger.error(f"Error running maintenance: {e}", exc_info=True)
        return jsonify({'error': str(e)}), 500


@agent_bp.route('/api/admin/products/<int:product_id>/versions', methods=['GET'])
def get_product_versions(product_id):
    """
    Get version summary for a product across all assets.

    Shows which versions are deployed where - useful for understanding
    version spread before CVE assessment.
    """
    from app.auth import get_current_user
    from app.maintenance import get_product_version_summary

    user = get_current_user()
    if not user:
        return jsonify({'error': 'Authentication required'}), 401

    product = Product.query.get_or_404(product_id)

    # Check permission
    if not user.is_super_admin():
        user_org_ids = [m.organization_id for m in user.org_memberships.all()]
        product_org_ids = [o.id for o in product.organizations.all()]
        if not any(oid in user_org_ids for oid in product_org_ids):
            return jsonify({'error': 'Access denied'}), 403

    try:
        versions = get_product_version_summary(product_id)
        return jsonify({
            'product_id': product_id,
            'product_name': f"{product.vendor} {product.product_name}",
            'tracked_version': product.version,
            'versions': versions,
            'total_installations': sum(v['count'] for v in versions)
        })
    except Exception as e:
        logger.error(f"Error getting product versions: {e}", exc_info=True)
        return jsonify({'error': str(e)}), 500


# ============================================================================
# Integration Summary Endpoint (for Overview tab)
# ============================================================================

@agent_bp.route('/api/integrations/summary', methods=['GET'])
@requires_professional('Integrations')
def get_integrations_summary():
    """
    Get summary of all integrations for the Overview tab.

    Returns counts and status of:
    - Pull sources (connectors)
    - Push agents (agent keys + endpoints)
    - Import queue
    """
    from app.auth import get_current_user
    from app.integrations_models import Integration, ImportQueue

    user = get_current_user()
    if not user:
        return jsonify({'error': 'Authentication required'}), 401

    try:
        # Get organization filter
        if user.is_super_admin():
            org_filter = None
        else:
            org_ids = [m.organization_id for m in user.org_memberships.all()]
            org_filter = org_ids

        # Pull sources (non-agent integrations)
        pull_query = Integration.query.filter(
            Integration.is_active == True,
            Integration.integration_type != 'agent'
        )
        if org_filter:
            pull_query = pull_query.filter(Integration.organization_id.in_(org_filter))
        pull_sources = pull_query.count()

        # Agent integrations
        agent_query = Integration.query.filter(
            Integration.is_active == True,
            Integration.integration_type == 'agent'
        )
        if org_filter:
            agent_query = agent_query.filter(Integration.organization_id.in_(org_filter))
        agent_integrations = agent_query.count()

        # Agent API keys
        key_query = AgentApiKey.query.filter(AgentApiKey.active == True)
        if org_filter:
            key_query = key_query.filter(AgentApiKey.organization_id.in_(org_filter))
        agent_keys = key_query.count()

        # Assets (endpoints)
        asset_query = Asset.query.filter(Asset.active == True)
        if org_filter:
            asset_query = asset_query.filter(Asset.organization_id.in_(org_filter))
        total_assets = asset_query.count()
        online_assets = asset_query.filter(Asset.status == 'online').count()

        # Import queue
        queue_query = ImportQueue.query.filter(ImportQueue.status == 'pending')
        if org_filter:
            queue_query = queue_query.filter(ImportQueue.organization_id.in_(org_filter))
        pending_imports = queue_query.count()

        # Recent activity
        from datetime import timedelta
        one_day_ago = datetime.utcnow() - timedelta(days=1)

        recent_checkins = Asset.query.filter(
            Asset.last_checkin > one_day_ago
        )
        if org_filter:
            recent_checkins = recent_checkins.filter(Asset.organization_id.in_(org_filter))
        recent_checkins_count = recent_checkins.count()

        return jsonify({
            'pull_sources': {
                'total': pull_sources,
                'label': 'Pull Sources',
                'description': 'External systems SentriKat fetches data from'
            },
            'push_agents': {
                'api_keys': agent_keys,
                'endpoints': total_assets,
                'online': online_assets,
                'label': 'Push Agents',
                'description': 'Agents deployed on endpoints pushing data to SentriKat'
            },
            'import_queue': {
                'pending': pending_imports,
                'label': 'Import Queue',
                'description': 'Software pending review before adding to Products'
            },
            'activity': {
                'recent_checkins': recent_checkins_count,
                'label': 'Last 24 Hours',
                'description': 'Endpoints that checked in recently'
            }
        })

    except Exception as e:
        logger.error(f"Error getting integrations summary: {e}", exc_info=True)
        return jsonify({'error': str(e)}), 500


# ============================================================================
# Worker Health & Status Endpoints
# ============================================================================

@agent_bp.route('/api/admin/worker-status', methods=['GET'])
def get_worker_status():
    """
    Get the status of the background job worker.
    Returns worker health, queue depth, and processing statistics.
    """
    from app.auth import get_current_user

    user = get_current_user()
    if not user or not user.is_super_admin():
        return jsonify({'error': 'Super admin access required'}), 403

    global _worker_thread

    # Worker status
    worker_alive = _worker_thread is not None and _worker_thread.is_alive()

    # Queue statistics
    pending_jobs = InventoryJob.query.filter_by(status='pending').count()
    processing_jobs = InventoryJob.query.filter_by(status='processing').count()
    completed_today = InventoryJob.query.filter(
        InventoryJob.status == 'completed',
        InventoryJob.completed_at >= datetime.utcnow().replace(hour=0, minute=0, second=0)
    ).count()
    failed_today = InventoryJob.query.filter(
        InventoryJob.status == 'failed',
        InventoryJob.completed_at >= datetime.utcnow().replace(hour=0, minute=0, second=0)
    ).count()

    # Get most recent job
    latest_job = InventoryJob.query.order_by(InventoryJob.created_at.desc()).first()

    return jsonify({
        'worker': {
            'status': 'running' if worker_alive else 'stopped',
            'is_alive': worker_alive,
            'check_interval_seconds': WORKER_CHECK_INTERVAL
        },
        'queue': {
            'pending': pending_jobs,
            'processing': processing_jobs,
            'completed_today': completed_today,
            'failed_today': failed_today
        },
        'latest_job': latest_job.to_dict() if latest_job else None,
        'config': {
            'async_threshold': ASYNC_BATCH_THRESHOLD,
            'max_products_per_request': MAX_PRODUCTS_PER_REQUEST
        },
        'checked_at': datetime.utcnow().isoformat()
    })


@agent_bp.route('/api/admin/worker/start', methods=['POST'])
def start_worker():
    """Manually start the background worker."""
    from app.auth import get_current_user

    user = get_current_user()
    if not user or not user.is_super_admin():
        return jsonify({'error': 'Super admin access required'}), 403

    try:
        start_background_worker(current_app._get_current_object())
        return jsonify({
            'status': 'success',
            'message': 'Background worker started'
        })
    except Exception as e:
        return jsonify({'error': str(e)}), 500


# ============================================================================
# License Management & Dashboard Endpoints
# ============================================================================

@agent_bp.route('/api/admin/licenses', methods=['GET'])
def list_licenses():
    """List all agent licenses (admin view)."""
    from app.auth import get_current_user

    user = get_current_user()
    if not user:
        return jsonify({'error': 'Authentication required'}), 401

    if user.is_super_admin():
        licenses = AgentLicense.query.all()
    else:
        org_ids = [m.organization_id for m in user.org_memberships.all()]
        licenses = AgentLicense.query.filter(AgentLicense.organization_id.in_(org_ids)).all()

    # Update counts for each license
    for lic in licenses:
        lic.update_agent_count()
    db.session.commit()

    return jsonify({
        'licenses': [lic.to_dict() for lic in licenses]
    })


@agent_bp.route('/api/admin/licenses/<int:org_id>', methods=['GET'])
def get_organization_license(org_id):
    """Get license details for a specific organization."""
    from app.auth import get_current_user

    user = get_current_user()
    if not user:
        return jsonify({'error': 'Authentication required'}), 401

    # Check permission
    if not user.is_super_admin():
        user_org_ids = [m.organization_id for m in user.org_memberships.all()]
        if org_id not in user_org_ids:
            return jsonify({'error': 'Access denied'}), 403

    license_obj = AgentLicense.query.filter_by(organization_id=org_id).first()

    if not license_obj:
        # Create trial license if doesn't exist
        license_obj = AgentLicense(
            organization_id=org_id,
            tier='trial',
            max_agents=AgentLicense.TIER_LIMITS['trial']['max_agents'],
            max_api_keys=AgentLicense.TIER_LIMITS['trial']['max_api_keys'],
            status='trial',
            trial_started_at=datetime.utcnow(),
            trial_ends_at=datetime.utcnow() + timedelta(days=14)
        )
        db.session.add(license_obj)
        db.session.commit()

    # Update count
    license_obj.update_agent_count()
    db.session.commit()

    return jsonify(license_obj.to_dict())


@agent_bp.route('/api/admin/licenses/<int:org_id>', methods=['PUT', 'PATCH'])
def update_license(org_id):
    """
    Update an organization's license (super admin only).
    Used for upgrading tiers, adjusting limits, extending trials.
    """
    from app.auth import get_current_user

    user = get_current_user()
    if not user or not user.is_super_admin():
        return jsonify({'error': 'Super admin access required'}), 403

    license_obj = AgentLicense.query.filter_by(organization_id=org_id).first()
    if not license_obj:
        return jsonify({'error': 'License not found'}), 404

    data = request.get_json()
    if not data:
        return jsonify({'error': 'No data provided'}), 400

    updated_fields = []

    # Update tier
    if 'tier' in data:
        new_tier = data['tier']
        if new_tier in AgentLicense.TIER_LIMITS:
            old_tier = license_obj.tier
            license_obj.tier = new_tier
            # Apply tier defaults if not explicitly set
            tier_limits = AgentLicense.TIER_LIMITS[new_tier]
            if 'max_agents' not in data:
                license_obj.max_agents = tier_limits['max_agents']
            if 'max_api_keys' not in data:
                license_obj.max_api_keys = tier_limits['max_api_keys']
            updated_fields.append(f'tier: {old_tier} -> {new_tier}')
        else:
            return jsonify({'error': f'Invalid tier: {new_tier}'}), 400

    # Update limits
    if 'max_agents' in data:
        license_obj.max_agents = int(data['max_agents'])
        updated_fields.append('max_agents')
    if 'max_api_keys' in data:
        license_obj.max_api_keys = int(data['max_api_keys'])
        updated_fields.append('max_api_keys')

    # Update status
    if 'status' in data:
        if data['status'] in ['active', 'trial', 'suspended', 'expired', 'grace_period']:
            license_obj.status = data['status']
            updated_fields.append('status')
        else:
            return jsonify({'error': f'Invalid status: {data["status"]}'}), 400

    # Update billing
    if 'billing_cycle' in data:
        license_obj.billing_cycle = data['billing_cycle']
        updated_fields.append('billing_cycle')

    # Extend trial
    if 'extend_trial_days' in data:
        days = int(data['extend_trial_days'])
        if license_obj.trial_ends_at:
            license_obj.trial_ends_at = license_obj.trial_ends_at + timedelta(days=days)
        else:
            license_obj.trial_ends_at = datetime.utcnow() + timedelta(days=days)
        updated_fields.append(f'trial extended by {days} days')

    # Set grace period
    if 'grace_period_days' in data:
        days = int(data['grace_period_days'])
        license_obj.grace_period_until = datetime.utcnow() + timedelta(days=days)
        license_obj.status = 'grace_period'
        updated_fields.append(f'grace period set for {days} days')

    db.session.commit()
    logger.info(f"License updated for org {org_id} by {user.username}: {updated_fields}")

    return jsonify({
        'status': 'success',
        'message': f'License updated: {", ".join(updated_fields)}',
        'license': license_obj.to_dict()
    })


@agent_bp.route('/api/admin/usage/<int:org_id>', methods=['GET'])
def get_usage_history(org_id):
    """
    Get usage history for an organization.
    Used for billing and analytics dashboards.
    """
    from app.auth import get_current_user
    from datetime import date

    user = get_current_user()
    if not user:
        return jsonify({'error': 'Authentication required'}), 401

    # Check permission
    if not user.is_super_admin():
        user_org_ids = [m.organization_id for m in user.org_memberships.all()]
        if org_id not in user_org_ids:
            return jsonify({'error': 'Access denied'}), 403

    # Get date range
    days = request.args.get('days', 30, type=int)
    start_date = date.today() - timedelta(days=days)

    records = AgentUsageRecord.query.filter(
        AgentUsageRecord.organization_id == org_id,
        AgentUsageRecord.record_date >= start_date
    ).order_by(AgentUsageRecord.record_date.asc()).all()

    # Calculate totals
    total_reports = sum(r.inventory_reports for r in records)
    peak_agents = max((r.peak_agents for r in records), default=0)
    total_new_agents = sum(r.new_agents for r in records)

    return jsonify({
        'organization_id': org_id,
        'period_days': days,
        'records': [r.to_dict() for r in records],
        'summary': {
            'total_inventory_reports': total_reports,
            'peak_agents': peak_agents,
            'total_new_agents': total_new_agents,
            'average_daily_agents': round(sum(r.active_agents for r in records) / max(len(records), 1), 1)
        }
    })


@agent_bp.route('/api/admin/events', methods=['GET'])
def list_agent_events():
    """
    List agent events for audit trail.
    Supports filtering by organization, event type, and date range.
    """
    from app.auth import get_current_user

    user = get_current_user()
    if not user:
        return jsonify({'error': 'Authentication required'}), 401

    # Build query
    query = AgentEvent.query

    # Filter by organization
    if user.is_super_admin():
        org_id = request.args.get('organization_id', type=int)
        if org_id:
            query = query.filter_by(organization_id=org_id)
    else:
        user_org_ids = [m.organization_id for m in user.org_memberships.all()]
        query = query.filter(AgentEvent.organization_id.in_(user_org_ids))

    # Filter by event type
    event_type = request.args.get('event_type')
    if event_type:
        query = query.filter_by(event_type=event_type)

    # Filter by asset
    asset_id = request.args.get('asset_id', type=int)
    if asset_id:
        query = query.filter_by(asset_id=asset_id)

    # Filter by date range
    days = request.args.get('days', 7, type=int)
    start_date = datetime.utcnow() - timedelta(days=days)
    query = query.filter(AgentEvent.created_at >= start_date)

    # Pagination
    page = request.args.get('page', 1, type=int)
    per_page = min(request.args.get('per_page', 50, type=int), 100)

    pagination = query.order_by(AgentEvent.created_at.desc()).paginate(
        page=page, per_page=per_page, error_out=False
    )

    return jsonify({
        'events': [e.to_dict() for e in pagination.items],
        'total': pagination.total,
        'page': page,
        'per_page': per_page,
        'pages': pagination.pages
    })


@agent_bp.route('/api/admin/version-history', methods=['GET'])
def list_version_history():
    """
    List version change history for products.
    Useful for tracking software updates across the fleet.
    """
    from app.auth import get_current_user

    user = get_current_user()
    if not user:
        return jsonify({'error': 'Authentication required'}), 401

    query = ProductVersionHistory.query

    # Filter by organization (through asset)
    if not user.is_super_admin():
        user_org_ids = [m.organization_id for m in user.org_memberships.all()]
        query = query.join(Asset).filter(Asset.organization_id.in_(user_org_ids))

    # Filter by product
    product_id = request.args.get('product_id', type=int)
    if product_id:
        query = query.filter(ProductVersionHistory.product_id == product_id)

    # Filter by asset
    asset_id = request.args.get('asset_id', type=int)
    if asset_id:
        query = query.filter(ProductVersionHistory.asset_id == asset_id)

    # Filter by change type
    change_type = request.args.get('change_type')
    if change_type:
        query = query.filter(ProductVersionHistory.change_type == change_type)

    # Filter by date range
    days = request.args.get('days', 30, type=int)
    start_date = datetime.utcnow() - timedelta(days=days)
    query = query.filter(ProductVersionHistory.detected_at >= start_date)

    # Pagination
    page = request.args.get('page', 1, type=int)
    per_page = min(request.args.get('per_page', 50, type=int), 100)

    pagination = query.order_by(ProductVersionHistory.detected_at.desc()).paginate(
        page=page, per_page=per_page, error_out=False
    )

    return jsonify({
        'version_history': [vh.to_dict() for vh in pagination.items],
        'total': pagination.total,
        'page': page,
        'per_page': per_page,
        'pages': pagination.pages
    })


# ============================================================================
# License Tier Definitions (for reference)
# ============================================================================

@agent_bp.route('/api/admin/license-tiers', methods=['GET'])
def get_license_tiers():
    """Get available license tiers and their limits."""
    return jsonify({
        'tiers': AgentLicense.TIER_LIMITS,
        'description': {
            'trial': 'Free 14-day trial with limited agents',
            'starter': 'Small teams and single-site deployments',
            'professional': 'Medium organizations with multiple sites',
            'enterprise': 'Large organizations with extensive deployments',
            'unlimited': 'Unlimited agents for enterprise customers'
        }
    })
