from flask import Blueprint, render_template, request, jsonify, redirect, url_for, session, send_from_directory, current_app, make_response
from app import db, csrf, limiter
from sqlalchemy import func
from sqlalchemy.orm import selectinload
import os
from app.models import Product, Vulnerability, VulnerabilityMatch, VendorFixOverride, SyncLog, Organization, ServiceCatalog, User, AlertLog, ProductInstallation, Asset, ProductVersionHistory, ContainerImage, ContainerVulnerability
from app.cisa_sync import sync_cisa_kev
from app.filters import match_vulnerabilities_to_products, get_filtered_vulnerabilities
from app.email_alerts import EmailAlertManager
from app.auth import admin_required, login_required, org_admin_required, manager_required
from app.licensing import requires_professional, check_user_limit, check_org_limit, check_product_limit
from app.error_utils import safe_error_response, ERROR_MSGS
from app import APP_VERSION
import json
import re
import logging
import requests as http_requests
from datetime import datetime, timedelta

logger = logging.getLogger(__name__)

# Application version
API_VERSION = "v1"  # API version for future versioned endpoints (/api/v1/...)
APP_NAME = "SentriKat"
GITHUB_REPO = "sbr0nch/SentriKat"

bp = Blueprint('main', __name__)

# Exempt API routes from CSRF (they use JSON and are protected by SameSite cookies)
csrf.exempt(bp)


# =============================================================================
# Static File Serving (Persistent uploads from data volume)
# =============================================================================

@bp.route('/data/uploads/<path:filename>')
@login_required
def serve_upload(filename):
    """Serve uploaded files from persistent data directory.

    Protected by login_required since uploaded files may contain sensitive branding.
    Flask's send_from_directory has built-in path traversal protection.
    """
    # Additional path traversal protection - reject any path with .. or absolute paths
    if '..' in filename or filename.startswith('/'):
        return jsonify({'error': 'Invalid filename'}), 400

    data_dir = os.environ.get('DATA_DIR', '/app/data')
    uploads_dir = os.path.join(data_dir, 'uploads')
    return send_from_directory(uploads_dir, filename)


# =============================================================================
# Health & Status Endpoints (No authentication required)
# =============================================================================

@bp.route('/api/health', methods=['GET'])
def health_check():
    """
    Health check endpoint for load balancers and monitoring.
    Returns 200 if application is healthy, 503 if database is down.
    """
    health = {
        'status': 'healthy',
        'timestamp': datetime.utcnow().isoformat() + 'Z',
        'version': APP_VERSION,
        'checks': {}
    }

    # Check database connectivity
    try:
        db.session.execute(db.text('SELECT 1'))
        health['checks']['database'] = 'ok'
    except Exception as e:
        health['status'] = 'unhealthy'
        health['checks']['database'] = 'error'
        logger.error(f"Health check - database error: {str(e)}")
        return jsonify(health), 503

    return jsonify(health), 200


@bp.route('/api/system/notifications', methods=['GET'])
@login_required
def system_notifications():
    """
    Returns active system notifications for the notification banner.
    Only admins see all notifications; regular users see a subset.
    """
    from app.auth import get_current_user
    from app.models import AgentApiKey
    notifications = []
    current_user = get_current_user()
    is_admin = current_user.is_super_admin() if current_user and hasattr(current_user, 'is_super_admin') else False

    try:
        now = datetime.utcnow()

        # 1. Stale vulnerability data (no sync in 24+ hours) - admin only
        if is_admin:
            last_sync = SyncLog.query.order_by(SyncLog.sync_date.desc()).first()
            if last_sync:
                hours_since = (now - last_sync.sync_date).total_seconds() / 3600
                if hours_since > 48:
                    notifications.append({
                        'id': 'stale_vuln_data',
                        'level': 'warning',
                        'icon': 'bi-exclamation-triangle-fill',
                        'message': f'Vulnerability data is {int(hours_since)}h old. Last sync: {last_sync.sync_date.strftime("%Y-%m-%d %H:%M")} UTC.',
                        'action': {'label': 'Sync Now', 'url': '#', 'onclick': 'syncCISA()'},
                        'dismissible': True
                    })
            else:
                vuln_count = Vulnerability.query.count()
                if vuln_count == 0:
                    notifications.append({
                        'id': 'no_vuln_data',
                        'level': 'danger',
                        'icon': 'bi-shield-exclamation',
                        'message': 'No vulnerability data loaded. Run an initial CISA KEV sync to start matching.',
                        'dismissible': False
                    })

        # 2. No products configured - all users
        product_count = Product.query.filter_by(auto_disabled=False, approval_status='approved').count()
        if product_count == 0:
            notifications.append({
                'id': 'no_products',
                'level': 'info',
                'icon': 'bi-box-seam',
                'message': 'No products configured yet. Add products to start vulnerability tracking.',
                'action': {'label': 'Add Products', 'url': '/admin'},
                'dismissible': True
            })

        # 3. Agent keys with no recent reports - admin only
        if is_admin:
            active_keys = AgentApiKey.query.filter_by(active=True).count()
            if active_keys > 0:
                recent_report = Product.query.filter(
                    Product.source == 'agent',
                    Product.last_agent_report > now - timedelta(hours=48)
                ).first()
                if not recent_report:
                    agent_products = Product.query.filter(Product.source == 'agent').count()
                    if agent_products > 0:
                        notifications.append({
                            'id': 'agent_stale',
                            'level': 'warning',
                            'icon': 'bi-hdd-network',
                            'message': 'No agent reports received in the last 48 hours. Check agent connectivity.',
                            'action': {'label': 'View Agents', 'url': '/admin-panel#integrations:pushAgents'},
                            'dismissible': True
                        })

        # 4. ENCRYPTION_KEY not set - admin only
        if is_admin:
            if not os.environ.get('ENCRYPTION_KEY'):
                notifications.append({
                    'id': 'no_encryption_key',
                    'level': 'warning',
                    'icon': 'bi-key-fill',
                    'message': 'ENCRYPTION_KEY not set. Encryption is derived from SECRET_KEY. Set a dedicated key for production.',
                    'action': {'label': 'Settings', 'url': '/admin-panel#settings:system'},
                    'dismissible': True
                })

        # 5. License expiring soon - admin only
        if is_admin:
            try:
                from app.licensing import get_license
                from datetime import date
                lic = get_license()
                if lic and lic.expires_at:
                    days_left = (lic.expires_at - date.today()).days
                    if 0 < days_left <= 30:
                        notifications.append({
                            'id': 'license_expiring',
                            'level': 'warning',
                            'icon': 'bi-clock-history',
                            'message': f'Your license expires in {days_left} day{"s" if days_left != 1 else ""}.',
                            'action': {'label': 'License', 'url': '/admin-panel#settings:license'},
                            'dismissible': True
                        })
                    elif days_left <= 0:
                        notifications.append({
                            'id': 'license_expired',
                            'level': 'danger',
                            'icon': 'bi-exclamation-octagon-fill',
                            'message': 'Your license has expired. Some features may be restricted.',
                            'action': {'label': 'Renew', 'url': '/admin-panel#settings:license'},
                            'dismissible': False
                        })
            except Exception:
                pass

        # 6. Pending import queue items - admin only
        if is_admin:
            pending_imports = Product.query.filter_by(approval_status='pending').count()
            if pending_imports > 0:
                notifications.append({
                    'id': 'pending_imports',
                    'level': 'info',
                    'icon': 'bi-inbox-fill',
                    'message': f'{pending_imports} product{"s" if pending_imports != 1 else ""} waiting for review in the import queue.',
                    'action': {'label': 'Review', 'url': '/admin#import-queue'},
                    'dismissible': True
                })

    except Exception as e:
        logger.error(f"Error fetching system notifications: {e}")

    return jsonify({'notifications': notifications})


@bp.route('/api/version', methods=['GET'])
def get_version():
    """
    Get application version information.
    Useful for update checking and support.
    """
    from app.licensing import get_license

    license_info = get_license()

    return jsonify({
        'name': APP_NAME,
        'version': APP_VERSION,
        'api_version': API_VERSION,
        'edition': license_info.edition if license_info else 'community',
        'python': '3.11+',
        'database': 'PostgreSQL',
        'api_base': '/api',
        'api_docs': '/docs/API.md'
    })


@bp.route('/api/updates/check', methods=['GET'])
@login_required
@admin_required
def check_for_updates():
    """Check GitHub for the latest SentriKat release."""
    try:
        # First try /releases/latest (excludes pre-releases)
        resp = http_requests.get(
            f'https://api.github.com/repos/{GITHUB_REPO}/releases/latest',
            timeout=5,
            headers={'Accept': 'application/vnd.github.v3+json'}
        )
        # If no stable release exists, fall back to the most recent release (including pre-releases)
        if resp.status_code != 200:
            resp = http_requests.get(
                f'https://api.github.com/repos/{GITHUB_REPO}/releases',
                timeout=5,
                headers={'Accept': 'application/vnd.github.v3+json'}
            )
            if resp.status_code != 200 or not resp.json():
                return jsonify({'error': 'Could not reach update server', 'update_available': False}), 200
            data = resp.json()[0]  # Most recent release
        else:
            data = resp.json()

        latest_tag = data.get('tag_name', '').lstrip('v')
        current = APP_VERSION

        # Version comparison that handles pre-release tags (e.g., 1.0.0-beta.1)
        def parse_ver(v):
            try:
                # Split off pre-release suffix: "1.0.0-beta.1" -> ("1.0.0", "beta.1")
                base = v.split('-', 1)[0]
                parts = tuple(int(x) for x in base.split('.'))
                # Pre-release versions sort lower than the same version without suffix
                is_prerelease = '-' in v
                return (parts, 0 if is_prerelease else 1)
            except (ValueError, AttributeError):
                return ((0, 0, 0), 0)

        update_available = parse_ver(latest_tag) > parse_ver(current)

        return jsonify({
            'update_available': update_available,
            'current_version': current,
            'latest_version': latest_tag,
            'release_name': data.get('name', ''),
            'release_url': data.get('html_url', ''),
            'published_at': data.get('published_at', ''),
        })
    except http_requests.exceptions.RequestException:
        # Offline or network error - not critical
        return jsonify({'error': 'Could not reach update server', 'update_available': False}), 200
    except Exception as e:
        logger.warning(f'Update check failed: {e}')
        return jsonify({'error': 'Update check failed', 'update_available': False}), 200


@bp.route('/api/status', methods=['GET'])
def get_status():
    """
    Get system status including last sync time.
    No authentication required - basic status only.
    """
    try:
        last_sync = SyncLog.query.order_by(SyncLog.sync_date.desc()).first()
        vuln_count = Vulnerability.query.count() or 0

        return jsonify({
            'status': 'online',
            'version': APP_VERSION,
            'vulnerabilities_tracked': vuln_count,
            'last_sync': last_sync.sync_date.isoformat() + 'Z' if last_sync else None,
            'last_sync_status': last_sync.status if last_sync else None
        })
    except Exception as e:
        logger.error(f"Status check error: {str(e)}")
        db.session.rollback()  # Rollback on error to clean session state
        return jsonify({
            'status': 'error',
            'version': APP_VERSION
        }), 500

def validate_email(email):
    """Validate email format"""
    if not email:
        return False
    pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
    return re.match(pattern, email) is not None


def validate_username(username):
    """Validate username format - alphanumeric, underscore, dash, 3-50 chars"""
    if not username:
        return False
    pattern = r'^[a-zA-Z0-9_-]{3,50}$'
    return re.match(pattern, username) is not None


def validate_password_strength(password):
    """
    Validate password meets security requirements from database settings.
    Only applies to local users.
    """
    from app.models import SystemSettings

    # Get policy settings from database
    min_length = SystemSettings.query.filter_by(key='password_min_length').first()
    req_upper = SystemSettings.query.filter_by(key='password_require_uppercase').first()
    req_lower = SystemSettings.query.filter_by(key='password_require_lowercase').first()
    req_numbers = SystemSettings.query.filter_by(key='password_require_numbers').first()
    req_special = SystemSettings.query.filter_by(key='password_require_special').first()

    # Use settings or defaults
    min_len = int(min_length.value) if min_length else 8
    require_upper = req_upper.value == 'true' if req_upper else True
    require_lower = req_lower.value == 'true' if req_lower else True
    require_numbers = req_numbers.value == 'true' if req_numbers else True
    require_special = req_special.value == 'true' if req_special else False

    errors = []

    if not password or len(password) < min_len:
        errors.append(f'Password must be at least {min_len} characters')

    if require_upper and not re.search(r'[A-Z]', password):
        errors.append('Password must contain at least one uppercase letter')

    if require_lower and not re.search(r'[a-z]', password):
        errors.append('Password must contain at least one lowercase letter')

    if require_numbers and not re.search(r'[0-9]', password):
        errors.append('Password must contain at least one digit')

    if require_special and not re.search(r'[!@#$%^&*(),.?":{}|<>]', password):
        errors.append('Password must contain at least one special character')

    if errors:
        return False, '; '.join(errors)
    return True, None

@bp.route('/')
@login_required
def index():
    """Dashboard homepage"""
    return render_template('dashboard.html')

@bp.route('/shared/<share_token>')
@login_required
def shared_view(share_token):
    """View a shared filtered dashboard"""
    return render_template('dashboard.html', share_token=share_token)

@bp.route('/admin')
@login_required
def admin():
    """Admin panel for managing products"""
    return render_template('admin.html')

@bp.route('/agent-activity')
@org_admin_required
def agent_activity():
    """Agent Activity monitoring page - job queue, worker status, events."""
    return render_template('agent_activity.html')


@bp.route('/containers')
@login_required
def containers():
    """Container security page - view container image vulnerabilities."""
    return render_template('containers.html')


@bp.route('/reports/scheduled')
@org_admin_required
def scheduled_reports():
    """Scheduled reports management page."""
    return render_template('scheduled_reports.html')

@bp.route('/admin-panel')
@org_admin_required
def admin_panel():
    """Full administration panel for users, organizations, and settings.

    Access:
    - super_admin: Full access to all tabs
    - org_admin: Limited access (users in their org, LDAP, SMTP/Sync settings only)
    """
    from app.licensing import get_license
    license_info = get_license()
    return render_template('admin_panel.html', license=license_info)

# API Endpoints

@bp.route('/api/products', methods=['GET'])
@login_required
def get_products():
    """Get products based on user permissions with optional search, filtering, and pagination.

    Query parameters:
    - search: Text search on vendor, product_name, version, keywords
    - filter_org: Filter by organization ID (super admin only)
    - criticality: Filter by criticality (critical, high, medium, low)
    - status: Filter by status (active, inactive)
    - page: Page number (1-indexed)
    - per_page: Items per page (default 25, max 100)
    - grouped: If 'true', group products by vendor+product_name with versions as array

    - Super Admin: See all products (can filter by any org)
    - Others: Only see products assigned to their organization
    """
    from app.models import product_organizations
    from sqlalchemy import select
    import logging
    logger = logging.getLogger(__name__)

    current_user_id = session.get('user_id')
    current_user = User.query.get(current_user_id)

    if not current_user:
        return jsonify({'error': 'User not found'}), 401

    # Get query parameters
    search = request.args.get('search', '').strip()
    filter_org = request.args.get('filter_org', type=int)
    criticality = request.args.get('criticality', '').strip().lower()
    status = request.args.get('status', '').strip().lower()
    cpe_filter = request.args.get('cpe_filter', '').strip().lower()  # with_cpe or without_cpe
    page = request.args.get('page', type=int)
    per_page = request.args.get('per_page', 25, type=int)
    per_page = min(per_page, 100)  # Limit max items per page
    grouped = request.args.get('grouped', '').lower() == 'true'
    sort_by = request.args.get('sort_by', '').strip().lower()
    sort_dir = request.args.get('sort_dir', 'asc').strip().lower()
    if sort_dir not in ('asc', 'desc'):
        sort_dir = 'asc'

    logger.info(f"get_products: user={current_user.username}, role={current_user.role}, is_super_admin={current_user.is_super_admin()}")

    # Build base query based on permissions
    # Fetch IDs first to avoid scalar_subquery issues with connection pool
    query = Product.query

    if current_user.is_super_admin():
        logger.info("get_products: super_admin sees all products")

        # Super admin can filter by specific organization
        if filter_org:
            # Get product IDs for this org - fetch IDs first
            org_product_ids = db.session.execute(
                select(product_organizations.c.product_id).where(
                    product_organizations.c.organization_id == filter_org
                )
            ).scalars().all()
            if org_product_ids:
                query = query.filter(
                    db.or_(
                        Product.id.in_(org_product_ids),
                        Product.organization_id == filter_org
                    )
                )
            else:
                query = query.filter(Product.organization_id == filter_org)
    else:
        # Get user's current organization from session
        org_id = session.get('organization_id') or current_user.organization_id
        logger.info(f"get_products: org_id={org_id}")

        if not org_id:
            logger.info("get_products: no org_id, returning empty list")
            if page:
                return jsonify({'products': [], 'total': 0, 'page': 1, 'per_page': per_page, 'pages': 0})
            return jsonify([])

        # Get products assigned via many-to-many table - fetch IDs first
        org_product_ids = db.session.execute(
            select(product_organizations.c.product_id).where(
                product_organizations.c.organization_id == org_id
            )
        ).scalars().all()
        if org_product_ids:
            query = query.filter(
                db.or_(
                    Product.id.in_(org_product_ids),
                    Product.organization_id == org_id
                )
            )
        else:
            query = query.filter(Product.organization_id == org_id)

        logger.info(f"get_products: filtered to org {org_id}")

    # Apply search filter - split into words and require ALL to match
    if search:
        # Split search into individual terms
        search_terms = search.split()
        for term in search_terms:
            term_pattern = f"%{term}%"
            # Each term must match at least one field
            query = query.filter(
                db.or_(
                    Product.vendor.ilike(term_pattern),
                    Product.product_name.ilike(term_pattern),
                    Product.version.ilike(term_pattern),
                    Product.keywords.ilike(term_pattern)
                )
            )
        logger.info(f"get_products: search terms={search_terms}")

    # Apply criticality filter
    if criticality and criticality in ['critical', 'high', 'medium', 'low']:
        query = query.filter(Product.criticality == criticality)

    # Apply status filter
    if status == 'active':
        query = query.filter(Product.active == True)
    elif status == 'inactive':
        query = query.filter(Product.active == False)

    # Apply CPE filter
    if cpe_filter == 'with_cpe':
        query = query.filter(
            Product.cpe_vendor.isnot(None),
            Product.cpe_vendor != '',
            Product.cpe_product.isnot(None),
            Product.cpe_product != ''
        )
    elif cpe_filter == 'without_cpe':
        query = query.filter(
            db.or_(
                Product.cpe_vendor.is_(None),
                Product.cpe_vendor == '',
                Product.cpe_product.is_(None),
                Product.cpe_product == ''
            )
        )

    # Order by requested column or default vendor+product_name
    _col_map = {
        'product': Product.product_name,
        'vendor': Product.vendor,
        'version': Product.version,
        'status': Product.active,
    }
    order_col = _col_map.get(sort_by)
    if order_col is not None:
        query = query.order_by(order_col.desc() if sort_dir == 'desc' else order_col.asc())
    else:
        query = query.order_by(Product.vendor, Product.product_name)

    # If grouped mode requested, group by vendor+product_name
    if grouped:
        from sqlalchemy import func as sa_func
        products = query.all()
        grouped_products = {}

        # Batch-query vulnerability match counts to avoid N+1 lazy loading
        all_pids = [p.id for p in products]
        vuln_counts = {}
        vuln_unacked = {}
        if all_pids:
            # Total match count per product
            count_rows = db.session.query(
                VulnerabilityMatch.product_id,
                sa_func.count(VulnerabilityMatch.id)
            ).filter(
                VulnerabilityMatch.product_id.in_(all_pids)
            ).group_by(VulnerabilityMatch.product_id).all()
            for pid, cnt in count_rows:
                vuln_counts[pid] = cnt

            # Count of unacknowledged matches per product
            unacked_rows = db.session.query(
                VulnerabilityMatch.product_id,
                sa_func.count(VulnerabilityMatch.id)
            ).filter(
                VulnerabilityMatch.product_id.in_(all_pids),
                VulnerabilityMatch.acknowledged == False
            ).group_by(VulnerabilityMatch.product_id).all()
            for pid, cnt in unacked_rows:
                vuln_unacked[pid] = cnt

        # Batch-query organization info to avoid N+1 on p.organization
        org_map = {}  # org_id -> display name
        product_org_m2m = {}  # product_id -> set of org_ids
        if all_pids:
            # Get orgs from organization_id column
            org_ids_from_col = set(p.organization_id for p in products if p.organization_id)
            # Get orgs from many-to-many table
            m2m_rows = db.session.query(
                product_organizations.c.product_id, product_organizations.c.organization_id
            ).filter(product_organizations.c.product_id.in_(all_pids)).all()
            product_org_m2m = {}  # product_id -> set of org_ids
            for pid, oid in m2m_rows:
                product_org_m2m.setdefault(pid, set()).add(oid)
                org_ids_from_col.add(oid)
            # Fetch all org display names in one query
            if org_ids_from_col:
                for org in Organization.query.filter(Organization.id.in_(org_ids_from_col)).all():
                    org_map[org.id] = org.display_name or org.name

        for p in products:
            # Create unique key from vendor + product_name (case-insensitive)
            key = f"{(p.vendor or '').lower()}|{(p.product_name or '').lower()}"

            if key not in grouped_products:
                grouped_products[key] = {
                    'vendor': p.vendor,
                    'product_name': p.product_name,
                    'cpe_vendor': p.cpe_vendor,
                    'cpe_product': p.cpe_product,
                    'has_cpe': bool(p.cpe_vendor and p.cpe_product),
                    'keywords': p.keywords,
                    'active': p.active,
                    'source': getattr(p, 'source', 'manual'),
                    'criticality': getattr(p, 'criticality', 'medium'),
                    'versions': [],
                    'organization_ids': set(),
                    'organization_names': set(),
                    'platforms': set(),  # Track platforms from installations
                    'platform_counts': {},  # Platform -> installation count
                    'total_installations': 0,
                    'total_vulnerabilities': 0,
                    'has_vulnerable_version': False
                }

            # Add this version entry (using batch-queried counts instead of lazy p.matches)
            vc = vuln_counts.get(p.id, 0)
            ua = vuln_unacked.get(p.id, 0)
            version_entry = {
                'id': p.id,
                'version': p.version or 'Any',
                'active': p.active,
                'cpe_uri': p.cpe_uri,
                'source': getattr(p, 'source', 'manual'),
                'created_at': p.created_at.isoformat() if p.created_at else None,
                'vulnerability_count': vc,
                'is_vulnerable': ua > 0
            }
            grouped_products[key]['versions'].append(version_entry)

            # Aggregate organization info (from column and many-to-many, using batch data)
            p_org_ids = set()
            if p.organization_id:
                p_org_ids.add(p.organization_id)
            p_org_ids.update(product_org_m2m.get(p.id, set()))
            for oid in p_org_ids:
                grouped_products[key]['organization_ids'].add(oid)
                if oid in org_map:
                    grouped_products[key]['organization_names'].add(org_map[oid])

            # Track vulnerability status
            if version_entry['is_vulnerable']:
                grouped_products[key]['has_vulnerable_version'] = True
            grouped_products[key]['total_vulnerabilities'] += version_entry['vulnerability_count']

        # Batch query platforms and installation counts for all products
        all_product_ids = [v['id'] for group in grouped_products.values() for v in group['versions']]
        if all_product_ids:
            # Get platform + count per product
            platform_counts = db.session.query(
                ProductInstallation.product_id,
                ProductInstallation.detected_on_os,
                sa_func.count(ProductInstallation.id)
            ).filter(
                ProductInstallation.product_id.in_(all_product_ids)
            ).group_by(
                ProductInstallation.product_id,
                ProductInstallation.detected_on_os
            ).all()

            # Build product_id -> {platform: count} mapping
            product_platform_counts = {}
            product_install_counts = {}
            for product_id, platform, count in platform_counts:
                if product_id not in product_platform_counts:
                    product_platform_counts[product_id] = {}
                    product_install_counts[product_id] = 0
                pname = platform or 'other'
                product_platform_counts[product_id][pname] = product_platform_counts[product_id].get(pname, 0) + count
                product_install_counts[product_id] += count

            # Get endpoint hostnames per product (for Software Overview)
            endpoint_rows = db.session.query(
                ProductInstallation.product_id,
                Asset.hostname,
                Asset.ip_address
            ).join(Asset, ProductInstallation.asset_id == Asset.id).filter(
                ProductInstallation.product_id.in_(all_product_ids),
                Asset.active == True
            ).all()

            # Build product_id -> set of hostnames
            product_endpoints = {}
            for product_id, hostname, ip_address in endpoint_rows:
                if product_id not in product_endpoints:
                    product_endpoints[product_id] = set()
                product_endpoints[product_id].add(hostname or ip_address or 'Unknown')

            # Assign platforms, installation counts, and endpoints to groups
            for key, group in grouped_products.items():
                group['platform_counts'] = {}
                group['total_installations'] = 0
                group_endpoints = set()
                for v in group['versions']:
                    pid = v['id']
                    if pid in product_platform_counts:
                        for pname, cnt in product_platform_counts[pid].items():
                            group['platform_counts'][pname] = group['platform_counts'].get(pname, 0) + cnt
                        group['platforms'].update(product_platform_counts[pid].keys())
                    if pid in product_install_counts:
                        group['total_installations'] += product_install_counts[pid]
                    if pid in product_endpoints:
                        group_endpoints.update(product_endpoints[pid])
                group['endpoint_hostnames'] = sorted(list(group_endpoints))[:20]  # Limit to first 20

        # Convert to list and clean up sets
        result = []
        for key, group in grouped_products.items():
            group['organization_ids'] = list(group['organization_ids'])
            group['organization_names'] = list(group['organization_names'])
            group['platforms'] = sorted(list(group['platforms']))  # Convert platforms set to sorted list
            # Sort versions - put specific versions first, 'Any' last
            group['versions'].sort(key=lambda v: (v['version'] == 'Any', v['version'] or ''))
            result.append(group)

        # Sort results (supports sort_by param for server-side sorting)
        _sort_keys = {
            'product': lambda g: (g['product_name'] or '').lower(),
            'vendor': lambda g: (g['vendor'] or '').lower(),
            'version': lambda g: len(g.get('versions', [])),
            'organization': lambda g: (', '.join(g.get('organization_names', [])) or '').lower(),
            'status': lambda g: g.get('active', False),
            'platform': lambda g: (', '.join(g.get('platforms', [])) or '').lower(),
            'cpe': lambda g: g.get('has_cpe', False),
        }
        sort_fn = _sort_keys.get(sort_by)
        if sort_fn:
            result.sort(key=sort_fn, reverse=(sort_dir == 'desc'))
        else:
            result.sort(key=lambda g: (g['vendor'] or '', g['product_name'] or ''))

        # Apply pagination if requested
        if page:
            total = len(result)
            start = (page - 1) * per_page
            end = start + per_page
            return jsonify({
                'products': result[start:end],
                'total': total,
                'page': page,
                'per_page': per_page,
                'pages': (total + per_page - 1) // per_page
            })

        logger.info(f"get_products (grouped): returning {len(result)} product groups")
        return jsonify(result)

    # If pagination requested, return paginated result
    if page:
        pagination = query.paginate(page=page, per_page=per_page, error_out=False)
        return jsonify({
            'products': [p.to_dict() for p in pagination.items],
            'total': pagination.total,
            'page': pagination.page,
            'per_page': per_page,
            'pages': pagination.pages
        })

    # Default: return all as array (backward compatibility)
    products = query.all()
    logger.info(f"get_products: returning {len(products)} products")
    return jsonify([p.to_dict() for p in products])

@bp.route('/api/products', methods=['POST'])
@manager_required
def create_product():
    """
    Create a new product

    Permissions:
    - Super Admin: Can create products for any org
    - Org Admin: Can create products for their org only
    - Manager: Can create products for their org only
    """
    # Check license limit for products
    allowed, limit, message = check_product_limit()
    if not allowed:
        return jsonify({'error': message, 'license_limit': True}), 403

    current_user_id = session.get('user_id')
    current_user = User.query.get(current_user_id)

    data = request.get_json()

    if not data.get('vendor', '').strip() or not data.get('product_name', '').strip():
        return jsonify({'error': 'Vendor and product name are required'}), 400

    # Get current organization from session
    org_id = session.get('organization_id')
    if not org_id:
        # Use default organization if not set
        default_org = Organization.query.filter_by(name='default').first()
        org_id = default_org.id if default_org else None

    # Check for duplicate product (case-insensitive)
    # For multi-org support, check if product exists globally (regardless of org)
    # since products can now be assigned to multiple organizations
    version = data.get('version', '').strip() or None  # Treat empty string as None
    vendor_lower = data['vendor'].lower().strip()
    product_name_lower = data['product_name'].lower().strip()

    duplicate_query = Product.query.filter(
        db.func.lower(Product.vendor) == vendor_lower,
        db.func.lower(Product.product_name) == product_name_lower
    )

    # Check version - treat empty string and None as equivalent
    if version:
        duplicate_query = duplicate_query.filter(
            db.func.lower(Product.version) == version.lower()
        )
    else:
        duplicate_query = duplicate_query.filter(
            db.or_(Product.version.is_(None), Product.version == '')
        )

    existing_product = duplicate_query.first()

    if existing_product:
        return jsonify({
            'error': 'A product with the same vendor, name, and version already exists. You can assign it to additional organizations from the product list.'
        }), 409

    # Auto-match CPE if not provided
    cpe_vendor = data.get('cpe_vendor')
    cpe_product = data.get('cpe_product')
    cpe_confidence = 0.0

    if not cpe_vendor or not cpe_product:
        try:
            from app.integrations_api import attempt_cpe_match
            matched_vendor, matched_product, cpe_confidence = attempt_cpe_match(
                data['vendor'].strip(),
                data['product_name'].strip()
            )
            if matched_vendor and matched_product:
                cpe_vendor = matched_vendor
                cpe_product = matched_product
                current_app.logger.info(f"Auto-matched CPE: {data['product_name']} -> {cpe_vendor}:{cpe_product} ({cpe_confidence:.2f})")
        except Exception as e:
            current_app.logger.warning(f"CPE auto-match failed: {e}")

    product = Product(
        organization_id=data.get('organization_id', org_id),
        service_catalog_id=data.get('service_catalog_id'),
        vendor=data['vendor'].strip(),
        product_name=data['product_name'].strip(),
        version=version,  # Already normalized above (empty string -> None)
        keywords=data.get('keywords'),
        description=data.get('description'),
        active=data.get('active', True),
        # CPE fields for NVD matching
        cpe_vendor=cpe_vendor,
        cpe_product=cpe_product,
        cpe_uri=data.get('cpe_uri'),
        match_type=data.get('match_type', 'auto')
    )

    # If service catalog entry was used, increment its usage
    if product.service_catalog_id:
        catalog_entry = ServiceCatalog.query.get(product.service_catalog_id)
        if catalog_entry:
            catalog_entry.usage_frequency += 1

    db.session.add(product)
    db.session.flush()  # Get the product ID

    # Also add to product_organizations many-to-many table
    org_to_assign = data.get('organization_id', org_id)
    if org_to_assign:
        org = Organization.query.get(org_to_assign)
        if org and org not in product.organizations.all():
            product.organizations.append(org)

    db.session.commit()

    # Re-run matching for new product
    match_vulnerabilities_to_products()

    # Return product with CPE match info
    response = product.to_dict()
    response['cpe_matched'] = bool(cpe_vendor and cpe_product)
    response['cpe_confidence'] = cpe_confidence if (cpe_vendor and cpe_product) else 0.0

    return jsonify(response), 201

@bp.route('/api/products/<int:product_id>', methods=['GET'])
@login_required
def get_product(product_id):
    """Get a specific product"""
    product = Product.query.get_or_404(product_id)
    return jsonify(product.to_dict())

@bp.route('/api/products/<int:product_id>', methods=['PUT'])
@manager_required
def update_product(product_id):
    """
    Update a product

    Permissions:
    - Super Admin: Can update any product
    - Org Admin: Can update products in their organization
    - Manager: Can update products in their organization
    """
    current_user_id = session.get('user_id')
    current_user = User.query.get(current_user_id)
    product = Product.query.get_or_404(product_id)

    # Permission check: org admins can only edit products in their org
    if not current_user.is_super_admin():
        # Check if product belongs to user's org (via primary or multi-org assignment)
        product_org_ids = [org.id for org in product.organizations.all()]
        if product.organization_id:
            product_org_ids.append(product.organization_id)
        if current_user.organization_id not in product_org_ids:
            return jsonify({'error': 'You can only edit products in your organization'}), 403

    data = request.get_json()

    # Check for duplicate product if vendor, product_name, or version is being updated
    # For multi-org support, check globally (not just within one org)
    if 'vendor' in data or 'product_name' in data or 'version' in data:
        new_vendor = data.get('vendor', product.vendor)
        new_product_name = data.get('product_name', product.product_name)
        new_version = data.get('version', product.version)

        # Query for existing products with same details (excluding current product)
        duplicate_query = Product.query.filter(
            Product.id != product_id,
            Product.vendor == new_vendor,
            Product.product_name == new_product_name
        )

        # Check version match
        if new_version:
            duplicate_query = duplicate_query.filter_by(version=new_version)
        else:
            duplicate_query = duplicate_query.filter(Product.version.is_(None))

        existing_product = duplicate_query.first()

        if existing_product:
            return jsonify({
                'error': 'A product with the same vendor, name, and version already exists. Products are unique globally.'
            }), 409

    if 'vendor' in data:
        product.vendor = data['vendor']
    if 'product_name' in data:
        product.product_name = data['product_name']
    if 'version' in data:
        product.version = data['version']
    if 'keywords' in data:
        product.keywords = data['keywords']
    if 'description' in data:
        product.description = data['description']
    if 'active' in data:
        product.active = data['active']
    # CPE fields for NVD matching
    old_cpe_vendor = product.cpe_vendor
    old_cpe_product = product.cpe_product
    if 'cpe_vendor' in data:
        product.cpe_vendor = data['cpe_vendor']
    if 'cpe_product' in data:
        product.cpe_product = data['cpe_product']

    # Learn from user CPE assignments - save for future auto-matching
    if (product.cpe_vendor and product.cpe_product and
        (product.cpe_vendor != old_cpe_vendor or product.cpe_product != old_cpe_product)):
        try:
            from app.cpe_mappings import save_user_mapping
            save_user_mapping(
                product.vendor, product.product_name,
                product.cpe_vendor, product.cpe_product,
                user_id=current_user_id,
                notes=f"Learned from product edit: {product.product_name}"
            )
        except Exception as e:
            current_app.logger.warning(f"Failed to save user CPE mapping: {e}")
    if 'cpe_uri' in data:
        product.cpe_uri = data['cpe_uri']
    if 'match_type' in data:
        product.match_type = data['match_type']
    if 'organization_id' in data:
        # Allow setting to None or a valid organization ID
        org_id = data['organization_id']
        if org_id == '' or org_id is None:
            product.organization_id = None
            # Clear multi-org assignments too
            for org in list(product.organizations):
                product.organizations.remove(org)
        else:
            new_org_id = int(org_id)
            product.organization_id = new_org_id
            # Sync with multi-org: ensure the new org is in the organizations list
            new_org = Organization.query.get(new_org_id)
            if new_org:
                # Clear existing and set to just this org for consistency
                for org in list(product.organizations):
                    product.organizations.remove(org)
                product.organizations.append(new_org)

    db.session.commit()

    # Re-run matching after update
    match_vulnerabilities_to_products()

    return jsonify(product.to_dict())

@bp.route('/api/products/<int:product_id>', methods=['DELETE'])
@manager_required
@limiter.limit("500 per minute")  # Allow bulk delete operations
def delete_product(product_id):
    """
    Delete a product or remove it from current organization.

    Query params:
    - exclude: If 'true', add product to exclusion list to prevent re-adding by agents

    Permissions:
    - Super Admin: Deletes product globally from all organizations
    - Org Admin/Manager: Removes product from their org only.
      If product is in multiple orgs, it stays in others.
      If product is only in their org, it gets deleted globally.
    """
    from app.logging_config import log_audit_event
    from app.models import ProductExclusion

    current_user_id = session.get('user_id')
    current_user = User.query.get(current_user_id)
    product = Product.query.get_or_404(product_id)

    # Check if we should exclude this product from future agent scans
    exclude_from_scans = request.args.get('exclude', 'false').lower() == 'true'

    # Get user's current organization
    user_org_id = session.get('organization_id') or current_user.organization_id

    # Get all organizations this product is assigned to
    product_org_ids = [org.id for org in product.organizations.all()]

    # Permission check: non-super-admins can only manage products in their org
    if not current_user.is_super_admin():
        if user_org_id not in product_org_ids:
            return jsonify({'error': 'You can only delete products in your organization'}), 403

    # Store product info for audit log
    product_info = {
        'name': product.product_name,
        'vendor': product.vendor,
        'version': product.version,
        'organizations': product_org_ids,
        'action_by': current_user.username
    }

    try:
        # If exclude requested, add to exclusion list for relevant orgs
        if exclude_from_scans:
            if current_user.is_super_admin():
                # Exclude for all organizations this product was in
                for org_id in product_org_ids:
                    existing = ProductExclusion.query.filter_by(
                        organization_id=org_id,
                        vendor=product.vendor,
                        product_name=product.product_name,
                        version=None
                    ).first()
                    if not existing:
                        exclusion = ProductExclusion(
                            organization_id=org_id,
                            vendor=product.vendor,
                            product_name=product.product_name,
                            version=None,  # Exclude all versions
                            reason='Deleted by admin',
                            excluded_by=current_user_id
                        )
                        db.session.add(exclusion)
            else:
                # Exclude only for user's organization
                existing = ProductExclusion.query.filter_by(
                    organization_id=user_org_id,
                    vendor=product.vendor,
                    product_name=product.product_name,
                    version=None
                ).first()
                if not existing:
                    exclusion = ProductExclusion(
                        organization_id=user_org_id,
                        vendor=product.vendor,
                        product_name=product.product_name,
                        version=None,
                        reason='Deleted by admin',
                        excluded_by=current_user_id
                    )
                    db.session.add(exclusion)

        if current_user.is_super_admin():
            # Super admin: delete product globally
            # Delete all related records first (foreign key constraints)
            ProductInstallation.query.filter_by(product_id=product_id).delete()
            VulnerabilityMatch.query.filter_by(product_id=product_id).delete()
            ProductVersionHistory.query.filter_by(product_id=product_id).delete()
            db.session.delete(product)
            db.session.commit()

            log_audit_event(
                'DELETE',
                'products',
                product_id,
                old_value=product_info,
                details=f"Super admin deleted product {product_info['vendor']} {product_info['name']} globally" + (" (excluded from future scans)" if exclude_from_scans else "")
            )
            return jsonify({'success': True, 'message': 'Product deleted globally' + (' and excluded from future agent scans' if exclude_from_scans else '')})

        else:
            # Org admin/manager: remove from their org only
            user_org = Organization.query.get(user_org_id)

            if len(product_org_ids) > 1:
                # Product is in multiple orgs - just remove from this org
                if user_org in product.organizations:
                    product.organizations.remove(user_org)
                    db.session.commit()

                    exclude_msg = ' and excluded from future agent scans' if exclude_from_scans else ''
                    log_audit_event(
                        'REMOVE_ORG',
                        'products',
                        product_id,
                        old_value={'organization_id': user_org_id},
                        details=f"Removed product {product.vendor} {product.product_name} from {user_org.display_name}" + (" (excluded)" if exclude_from_scans else "")
                    )
                    return jsonify({
                        'success': True,
                        'message': f'Product removed from {user_org.display_name} (still exists in other organizations)' + exclude_msg
                    })
            else:
                # Product only in this org - delete it globally
                # Delete all related records first (foreign key constraints)
                ProductInstallation.query.filter_by(product_id=product_id).delete()
                VulnerabilityMatch.query.filter_by(product_id=product_id).delete()
                ProductVersionHistory.query.filter_by(product_id=product_id).delete()
                db.session.delete(product)
                db.session.commit()

                exclude_msg = ' and excluded from future agent scans' if exclude_from_scans else ''
                log_audit_event(
                    'DELETE',
                    'products',
                    product_id,
                    old_value=product_info,
                    details=f"Deleted product {product_info['vendor']} {product_info['name']}" + (" (excluded)" if exclude_from_scans else "")
                )
                return jsonify({'success': True, 'message': 'Product deleted' + exclude_msg})

        return jsonify({'success': True})

    except Exception as e:
        db.session.rollback()
        logger.exception("Failed to delete product")
        return jsonify({'success': False, 'error': ERROR_MSGS['database']}), 500


@bp.route('/api/products/purge', methods=['POST'])
@admin_required
@limiter.limit("5 per minute")
def purge_products():
    """
    Bulk delete all products from specified organizations or globally.
    Super admin only. Cascading deletes: installations, matches, version history, org links.
    """
    from app.auth import get_current_user
    from app.logging_config import log_audit_event
    current_user = get_current_user()
    if not current_user or not current_user.is_super_admin():
        return jsonify({'error': 'Super admin access required'}), 403

    data = request.get_json()
    if not data:
        return jsonify({'error': 'No data provided'}), 400

    purge_all = data.get('all_organizations', False)
    org_ids = data.get('organization_ids', [])

    if not purge_all and not org_ids:
        return jsonify({'error': 'Specify all_organizations=true or organization_ids'}), 400

    try:
        from app.models import product_organizations

        if purge_all:
            # Delete ALL products globally
            product_ids = [p.id for p in Product.query.with_entities(Product.id).all()]
        else:
            # Get products belonging to the selected organizations
            # Include both legacy org_id and many-to-many
            from sqlalchemy import select, or_

            legacy_ids = set(
                p.id for p in Product.query.filter(Product.organization_id.in_(org_ids))
                .with_entities(Product.id).all()
            )

            m2m_ids = set(
                row.product_id for row in db.session.execute(
                    select(product_organizations.c.product_id).where(
                        product_organizations.c.organization_id.in_(org_ids)
                    )
                ).all()
            )

            product_ids = list(legacy_ids | m2m_ids)

        if not product_ids:
            return jsonify({
                'success': True,
                'deleted_products': 0,
                'deleted_installations': 0,
                'deleted_matches': 0,
                'message': 'No products found for the selected organizations'
            })

        # Cascade delete in correct order (foreign key dependencies)
        # Process in batches to avoid locking issues on large datasets
        batch_size = 500
        total_installations = 0
        total_matches = 0
        total_versions = 0

        for i in range(0, len(product_ids), batch_size):
            batch = product_ids[i:i + batch_size]
            total_versions += ProductVersionHistory.query.filter(
                ProductVersionHistory.product_id.in_(batch)
            ).delete(synchronize_session=False)
            total_installations += ProductInstallation.query.filter(
                ProductInstallation.product_id.in_(batch)
            ).delete(synchronize_session=False)
            total_matches += VulnerabilityMatch.query.filter(
                VulnerabilityMatch.product_id.in_(batch)
            ).delete(synchronize_session=False)

        # Remove many-to-many org links
        db.session.execute(
            product_organizations.delete().where(
                product_organizations.c.product_id.in_(product_ids)
            )
        )

        # Delete products
        deleted_products = Product.query.filter(Product.id.in_(product_ids)).delete(
            synchronize_session=False
        )

        db.session.commit()

        # Audit log
        log_audit_event(
            'delete',
            'products',
            None,
            details=f"Purged {deleted_products} products" +
                    (f" from organizations {org_ids}" if not purge_all else " globally") +
                    f" ({total_installations} installations, {total_matches} matches, {total_versions} version records)"
        )

        logger.warning(
            f"PURGE: User {current_user.username} deleted {deleted_products} products"
            f" ({total_installations} installations, {total_matches} matches)"
            + (" globally" if purge_all else f" from orgs {org_ids}")
        )

        return jsonify({
            'success': True,
            'deleted_products': deleted_products,
            'deleted_installations': total_installations,
            'deleted_matches': total_matches,
            'deleted_versions': total_versions
        })

    except Exception as e:
        db.session.rollback()
        logger.exception("Failed to purge products")
        return jsonify({'success': False, 'error': str(e)}), 500


@bp.route('/api/products/<int:product_id>/organizations', methods=['GET'])
@login_required
def get_product_organizations(product_id):
    """Get organizations assigned to a product"""
    product = Product.query.get_or_404(product_id)

    # Get assigned organizations from many-to-many relationship
    assigned_orgs = [{'id': org.id, 'name': org.name, 'display_name': org.display_name}
                     for org in product.organizations.all()]

    # Also include legacy organization_id (may be in addition to many-to-many)
    if product.organization_id and product.organization:
        legacy_org = {'id': product.organization.id, 'name': product.organization.name,
                      'display_name': product.organization.display_name}
        # Add if not already in list
        if not any(org['id'] == legacy_org['id'] for org in assigned_orgs):
            assigned_orgs.append(legacy_org)

    return jsonify({'organizations': assigned_orgs})

@bp.route('/api/products/<int:product_id>/organizations', methods=['POST'])
@org_admin_required
def assign_product_organizations(product_id):
    """Assign product to multiple organizations"""
    from app.email_service import send_product_assignment_notification

    product = Product.query.get_or_404(product_id)
    data = request.get_json()
    org_ids = data.get('organization_ids', [])

    if not org_ids:
        return jsonify({'error': 'No organizations specified'}), 400

    try:
        added_orgs = []
        for org_id in org_ids:
            org = Organization.query.get(org_id)
            if not org:
                continue

            # Check if already assigned
            if org not in product.organizations.all():
                product.organizations.append(org)
                added_orgs.append(org)

        db.session.commit()

        # Send email notifications to org admins
        for org in added_orgs:
            try:
                send_product_assignment_notification(product, org, 'assigned')
            except Exception as e:
                # Log but don't fail the request
                logger.warning(f"Failed to send notification to {org.name}: {str(e)}")

        return jsonify({
            'success': True,
            'message': f'Product assigned to {len(added_orgs)} organization(s)',
            'organizations': [{'id': org.id, 'name': org.name, 'display_name': org.display_name}
                             for org in product.organizations.all()]
        })

    except Exception as e:
        db.session.rollback()
        logger.exception("Failed to add organization to product")
        return jsonify({'error': ERROR_MSGS['database']}), 500

@bp.route('/api/products/<int:product_id>/organizations/<int:org_id>', methods=['DELETE'])
@org_admin_required
def remove_product_organization(product_id, org_id):
    """Remove an organization from a product"""
    from app.email_service import send_product_assignment_notification

    product = Product.query.get_or_404(product_id)
    org = Organization.query.get_or_404(org_id)

    # Check if confirm_delete parameter is passed (for deleting product with last org)
    confirm_delete = request.args.get('confirm_delete', 'false').lower() == 'true'

    try:
        # Check if org is actually assigned to this product
        is_in_many_to_many = org in product.organizations.all()
        is_legacy_org = product.organization_id == org_id

        if not is_in_many_to_many and not is_legacy_org:
            return jsonify({'error': 'Organization not assigned to this product'}), 404

        # Count current organizations BEFORE removal
        current_org_count = product.organizations.count()
        has_legacy_org = product.organization_id is not None and product.organization_id != org_id

        # Calculate what would be left after removal
        orgs_after_removal = current_org_count - (1 if is_in_many_to_many else 0)
        would_have_orgs = orgs_after_removal > 0 or has_legacy_org

        # If this is the last organization and no confirmation, return error
        if not would_have_orgs and not confirm_delete:
            return jsonify({
                'error': 'This is the last organization assigned to this product.',
                'requires_confirmation': True,
                'message': 'Removing the last organization will delete the product. Do you want to delete the entire product?'
            }), 400

        # Proceed with removal
        removed = False

        if is_in_many_to_many:
            product.organizations.remove(org)
            removed = True

        if is_legacy_org:
            product.organization_id = None
            removed = True

        db.session.commit()

        # Send email notification
        try:
            send_product_assignment_notification(product, org, 'removed')
        except Exception as e:
            logger.warning(f"Failed to send notification to {org.name}: {str(e)}")

        # Check if product has any organizations left after removal
        remaining_orgs = product.organizations.count()
        has_remaining_legacy = product.organization_id is not None

        # If no organizations left and confirm_delete was passed, delete the product
        if remaining_orgs == 0 and not has_remaining_legacy:
            # Capture name before delete (avoids DetachedInstanceError)
            deleted_product_name = product.product_name

            # Delete all related records first (foreign key constraints)
            ProductInstallation.query.filter_by(product_id=product_id).delete()
            VulnerabilityMatch.query.filter_by(product_id=product_id).delete()
            ProductVersionHistory.query.filter_by(product_id=product_id).delete()

            db.session.delete(product)
            db.session.commit()

            return jsonify({
                'success': True,
                'message': f'Product "{deleted_product_name}" has been deleted.',
                'product_deleted': True
            })

        return jsonify({
            'success': True,
            'message': f'Organization {org.display_name} removed from product',
            'product_deleted': False
        })

    except Exception as e:
        db.session.rollback()
        logger.exception("Failed to remove organization from product")
        return jsonify({'error': ERROR_MSGS['database']}), 500

@bp.route('/api/vulnerabilities', methods=['GET'])
@login_required
def get_vulnerabilities():
    """Get vulnerabilities with optional filters for current organization.

    Supports pagination:
    - page: Page number (default: 1, use 0 or 'all' for all results)
    - per_page: Items per page (default: 50, max: 500)

    Returns:
    - If paginated: { items: [...], total: N, page: N, per_page: N, pages: N }
    - If page=0 or page=all: Array of all items (legacy behavior)
    """
    try:
        # Get current organization
        org_id = session.get('organization_id')
        if not org_id:
            default_org = Organization.query.filter_by(name='default').first()
            org_id = default_org.id if default_org else None

        filters = {
            'organization_id': org_id,
            'product_id': request.args.get('product_id', type=int),
            'cve_id': request.args.get('cve_id'),
            'vendor': request.args.get('vendor'),
            'product': request.args.get('product'),
            'ransomware_only': request.args.get('ransomware_only', 'false').lower() == 'true',
            'acknowledged': request.args.get('acknowledged'),
            'priority': request.args.get('priority'),  # critical, high, medium, low
        }

        # Remove None values
        filters = {k: v for k, v in filters.items() if v is not None and v != ''}

        matches = get_filtered_vulnerabilities(filters)

        # Check pagination params
        page_param = request.args.get('page', '0')  # Default to all (legacy)
        per_page = min(request.args.get('per_page', 50, type=int), 500)

        # If page=0 or page=all, return all results (legacy behavior)
        if page_param in ('0', 'all', ''):
            results = []
            for m in matches:
                try:
                    results.append(m.to_dict())
                except Exception as e:
                    logger.error(f"Error converting match {m.id} to dict: {e}")
                    results.append({'id': m.id, 'error': 'Failed to load full details'})
            return jsonify(results)

        # Paginated response
        page = max(int(page_param), 1)
        total = len(matches)
        pages = (total + per_page - 1) // per_page if per_page > 0 else 1

        # Slice for current page
        start = (page - 1) * per_page
        end = start + per_page
        page_matches = matches[start:end]

        results = []
        for m in page_matches:
            try:
                results.append(m.to_dict())
            except Exception as e:
                logger.error(f"Error converting match {m.id} to dict: {e}")
                results.append({'id': m.id, 'error': 'Failed to load full details'})

        return jsonify({
            'items': results,
            'total': total,
            'page': page,
            'per_page': per_page,
            'pages': pages
        })

    except Exception as e:
        logger.exception("Error getting vulnerabilities")
        return jsonify({'error': ERROR_MSGS['database']}), 500

@bp.route('/api/vulnerabilities/stats', methods=['GET'])
@login_required
def get_vulnerability_stats():
    """Get vulnerability statistics with priority breakdown for current organization"""
    from app.models import product_organizations
    from sqlalchemy import select

    # Get current organization
    org_id = session.get('organization_id')
    if not org_id:
        default_org = Organization.query.filter_by(name='default').first()
        org_id = default_org.id if default_org else None

    # Use simple ORM count - avoid complex select patterns
    total_vulns = Vulnerability.query.count() or 0

    # Filter matches by organization - fetch IDs first to avoid subquery issues
    if org_id:
        # Get product IDs for this organization
        org_product_ids = db.session.execute(
            select(product_organizations.c.product_id).where(
                product_organizations.c.organization_id == org_id
            )
        ).scalars().all()

        if org_product_ids:
            total_matches_query = VulnerabilityMatch.query.filter(
                VulnerabilityMatch.product_id.in_(org_product_ids)
            )

            unacknowledged_query = VulnerabilityMatch.query.filter(
                VulnerabilityMatch.product_id.in_(org_product_ids),
                VulnerabilityMatch.acknowledged == False
            )

            # Get ransomware vulnerability IDs
            ransomware_vuln_ids = db.session.execute(
                select(Vulnerability.id).where(Vulnerability.known_ransomware == True)
            ).scalars().all()

            if ransomware_vuln_ids:
                ransomware_query = VulnerabilityMatch.query.filter(
                    VulnerabilityMatch.product_id.in_(org_product_ids),
                    VulnerabilityMatch.vulnerability_id.in_(ransomware_vuln_ids)
                )
            else:
                ransomware_query = VulnerabilityMatch.query.filter(VulnerabilityMatch.id < 0)  # Empty

            products_tracked_query = Product.query.filter(
                Product.id.in_(org_product_ids),
                Product.active == True
            )
        else:
            # No products in org - return zeros
            return jsonify({
                'total_vulnerabilities': total_vulns,
                'total_matches': 0,
                'unacknowledged': 0,
                'unacknowledged_cves': 0,
                'ransomware_related': 0,
                'products_tracked': 0,
                'priority_breakdown': {'critical': 0, 'high': 0, 'medium': 0, 'low': 0},
                'cve_priority_breakdown': {'critical': 0, 'high': 0, 'medium': 0, 'low': 0},
                'critical_count': 0,
                'high_count': 0,
                'medium_count': 0,
                'low_count': 0
            })
    else:
        # No org filter - show all
        total_matches_query = VulnerabilityMatch.query
        unacknowledged_query = VulnerabilityMatch.query.filter(VulnerabilityMatch.acknowledged == False)

        ransomware_vuln_ids = db.session.execute(
            select(Vulnerability.id).where(Vulnerability.known_ransomware == True)
        ).scalars().all()

        if ransomware_vuln_ids:
            ransomware_query = VulnerabilityMatch.query.filter(
                VulnerabilityMatch.vulnerability_id.in_(ransomware_vuln_ids)
            )
        else:
            ransomware_query = VulnerabilityMatch.query.filter(VulnerabilityMatch.id < 0)  # Empty

        products_tracked_query = Product.query.filter_by(active=True)

    total_matches = total_matches_query.count()
    unacknowledged = unacknowledged_query.count()
    ransomware = ransomware_query.count()
    products_tracked = products_tracked_query.count()

    # Count products without CPE mapping (blind spots)
    products_unmapped = Product.query.filter(
        Product.active == True,
        db.or_(
            Product.cpe_vendor.is_(None),
            Product.cpe_vendor == '',
            Product.cpe_product.is_(None),
            Product.cpe_product == ''
        )
    ).count()

    # Calculate priority-based stats (both CVE counts and match counts)
    # Use selectinload to eagerly load relationships and avoid column mapping issues
    all_matches = unacknowledged_query.options(
        selectinload(VulnerabilityMatch.product),
        selectinload(VulnerabilityMatch.vulnerability)
    ).all()

    # Match counts (existing)
    priority_counts = {'critical': 0, 'high': 0, 'medium': 0, 'low': 0}

    # CVE counts (grouped by CVE ID, highest priority per CVE)
    from collections import defaultdict
    cve_priorities = defaultdict(list)  # cve_id -> list of priorities

    for match in all_matches:
        priority = match.calculate_effective_priority()
        priority_counts[priority] = priority_counts.get(priority, 0) + 1
        cve_priorities[match.vulnerability.cve_id].append(priority)

    # Calculate CVE-level priority counts (use highest priority per CVE)
    priority_order = {'critical': 4, 'high': 3, 'medium': 2, 'low': 1}
    level_names = {4: 'critical', 3: 'high', 2: 'medium', 1: 'low'}

    cve_priority_counts = {'critical': 0, 'high': 0, 'medium': 0, 'low': 0}
    for cve_id, priorities in cve_priorities.items():
        # Get highest priority for this CVE
        max_level = max(priority_order.get(p, 2) for p in priorities)
        highest_priority = level_names.get(max_level, 'medium')
        cve_priority_counts[highest_priority] += 1

    total_cves = len(cve_priorities)  # Unique CVE count

    # Container image stats
    container_stats = {'total_images': 0, 'total_container_vulns': 0, 'container_critical': 0, 'container_high': 0}
    try:
        if org_id:
            container_images = ContainerImage.query.filter_by(organization_id=org_id, active=True)
        else:
            container_images = ContainerImage.query.filter_by(active=True)
        container_list = container_images.all()
        container_stats['total_images'] = len(container_list)
        container_stats['total_container_vulns'] = sum(i.total_vulnerabilities or 0 for i in container_list)
        container_stats['container_critical'] = sum(i.critical_count or 0 for i in container_list)
        container_stats['container_high'] = sum(i.high_count or 0 for i in container_list)
    except Exception:
        pass  # Container tables may not exist yet

    # EPSS exploitability stats for matched vulnerabilities
    epss_stats = {'high_epss': 0, 'with_epss': 0, 'avg_epss': 0}
    try:
        matched_vuln_ids = list(set(m.vulnerability_id for m in all_matches))
        if matched_vuln_ids:
            matched_vulns = Vulnerability.query.filter(
                Vulnerability.id.in_(matched_vuln_ids),
                Vulnerability.epss_score.isnot(None)
            ).all()
            epss_stats['with_epss'] = len(matched_vulns)
            if matched_vulns:
                scores = [v.epss_score for v in matched_vulns]
                epss_stats['avg_epss'] = round(sum(scores) / len(scores), 4)
                epss_stats['high_epss'] = sum(1 for s in scores if s >= 0.1)
    except Exception:
        pass

    return jsonify({
        'total_vulnerabilities': total_vulns,
        'total_matches': total_matches,
        'unacknowledged': unacknowledged,
        'unacknowledged_cves': total_cves,  # Unique CVE count
        'ransomware_related': ransomware,
        'products_tracked': products_tracked,
        'products_unmapped': products_unmapped,  # Products without CPE (blind spots)
        'priority_breakdown': priority_counts,
        'cve_priority_breakdown': cve_priority_counts,  # CVE-level counts
        'critical_count': priority_counts['critical'],
        'high_count': priority_counts['high'],
        'medium_count': priority_counts['medium'],
        'low_count': priority_counts['low'],
        # CVE counts for dashboard display
        'critical_cves': cve_priority_counts['critical'],
        'high_cves': cve_priority_counts['high'],
        'medium_cves': cve_priority_counts['medium'],
        'low_cves': cve_priority_counts['low'],
        # Container image scanning stats
        'container': container_stats,
        # EPSS exploitability risk
        'epss': epss_stats,
    })


@bp.route('/api/vulnerabilities/charts', methods=['GET'])
@login_required
def get_vulnerability_chart_data():
    """
    Get chart data for configurable dashboard widgets.

    Query params:
    - chart: Chart type (top_vendors, epss_distribution, remediation_rate, age_distribution, vuln_timeline)

    Returns chart-specific data formatted for Chart.js rendering.
    """
    from app.models import product_organizations, VulnerabilitySnapshot
    from sqlalchemy import select
    from collections import defaultdict

    chart_type = request.args.get('chart', 'top_vendors')

    # Get current organization
    org_id = session.get('organization_id')
    if not org_id:
        default_org = Organization.query.filter_by(name='default').first()
        org_id = default_org.id if default_org else None

    # Get org product IDs (handles both legacy and multi-org)
    org_product_ids = None
    if org_id:
        legacy_ids = [p.id for p in Product.query.filter_by(organization_id=org_id).all()]
        multi_ids = [row.product_id for row in db.session.execute(
            select(product_organizations.c.product_id).where(
                product_organizations.c.organization_id == org_id
            )
        ).all()]
        org_product_ids = list(set(legacy_ids + multi_ids))

    try:
        if chart_type == 'top_vendors':
            return _chart_top_vendors(org_product_ids)
        elif chart_type == 'epss_distribution':
            return _chart_epss_distribution(org_product_ids)
        elif chart_type == 'remediation_rate':
            return _chart_remediation_rate(org_product_ids)
        elif chart_type == 'age_distribution':
            return _chart_age_distribution(org_product_ids)
        elif chart_type == 'vuln_timeline':
            return _chart_vuln_timeline(org_product_ids)
        else:
            return jsonify({'error': f'Unknown chart type: {chart_type}'}), 400
    except Exception as e:
        logger.exception(f"Error generating chart data for {chart_type}")
        return jsonify({'error': 'Failed to generate chart data'}), 500


def _chart_top_vendors(org_product_ids):
    """Top 10 vendors by unacknowledged vulnerability count."""
    query = db.session.query(
        Vulnerability.vendor_project,
        func.count(VulnerabilityMatch.id).label('count')
    ).join(
        VulnerabilityMatch, VulnerabilityMatch.vulnerability_id == Vulnerability.id
    ).filter(
        VulnerabilityMatch.acknowledged == False
    )

    if org_product_ids is not None:
        if org_product_ids:
            query = query.filter(VulnerabilityMatch.product_id.in_(org_product_ids))
        else:
            return jsonify({'labels': [], 'values': [], 'chart_type': 'top_vendors'})

    results = query.group_by(Vulnerability.vendor_project).order_by(
        func.count(VulnerabilityMatch.id).desc()
    ).limit(10).all()

    return jsonify({
        'labels': [r[0] or 'Unknown' for r in results],
        'values': [r[1] for r in results],
        'chart_type': 'top_vendors',
        'title': 'Top Affected Vendors'
    })


def _chart_epss_distribution(org_product_ids):
    """EPSS score distribution across matched vulnerabilities."""
    query = db.session.query(
        Vulnerability.epss_score
    ).join(
        VulnerabilityMatch, VulnerabilityMatch.vulnerability_id == Vulnerability.id
    ).filter(
        VulnerabilityMatch.acknowledged == False,
        Vulnerability.epss_score.isnot(None)
    )

    if org_product_ids is not None:
        if org_product_ids:
            query = query.filter(VulnerabilityMatch.product_id.in_(org_product_ids))
        else:
            return jsonify({'labels': [], 'values': [], 'chart_type': 'epss_distribution'})

    scores = [r[0] for r in query.distinct().all()]

    # Bucket into ranges
    buckets = {'0-10%': 0, '10-30%': 0, '30-50%': 0, '50-70%': 0, '70-90%': 0, '90-100%': 0}
    for s in scores:
        pct = s * 100
        if pct < 10:
            buckets['0-10%'] += 1
        elif pct < 30:
            buckets['10-30%'] += 1
        elif pct < 50:
            buckets['30-50%'] += 1
        elif pct < 70:
            buckets['50-70%'] += 1
        elif pct < 90:
            buckets['70-90%'] += 1
        else:
            buckets['90-100%'] += 1

    return jsonify({
        'labels': list(buckets.keys()),
        'values': list(buckets.values()),
        'chart_type': 'epss_distribution',
        'title': 'EPSS Exploit Probability Distribution',
        'total_scored': len(scores)
    })


def _chart_remediation_rate(org_product_ids):
    """Acknowledged vs unacknowledged over time from snapshots."""
    from app.models import VulnerabilitySnapshot

    org_id = session.get('organization_id')
    if not org_id:
        default_org = Organization.query.filter_by(name='default').first()
        org_id = default_org.id if default_org else None

    snapshots = VulnerabilitySnapshot.get_trend_data(organization_id=org_id, days=30)

    dates = []
    acknowledged = []
    unacknowledged = []
    rates = []

    for s in snapshots:
        dates.append(s.snapshot_date.strftime('%Y-%m-%d'))
        total = (s.acknowledged or 0) + (s.unacknowledged or 0)
        acknowledged.append(s.acknowledged or 0)
        unacknowledged.append(s.unacknowledged or 0)
        rates.append(round((s.acknowledged / total * 100), 1) if total > 0 else 0)

    return jsonify({
        'dates': dates,
        'acknowledged': acknowledged,
        'unacknowledged': unacknowledged,
        'rates': rates,
        'chart_type': 'remediation_rate',
        'title': 'Remediation Progress'
    })


def _chart_age_distribution(org_product_ids):
    """Distribution of vulnerability age (days since added to KEV)."""
    query = db.session.query(
        Vulnerability.date_added
    ).join(
        VulnerabilityMatch, VulnerabilityMatch.vulnerability_id == Vulnerability.id
    ).filter(
        VulnerabilityMatch.acknowledged == False
    )

    if org_product_ids is not None:
        if org_product_ids:
            query = query.filter(VulnerabilityMatch.product_id.in_(org_product_ids))
        else:
            return jsonify({'labels': [], 'values': [], 'chart_type': 'age_distribution'})

    dates = [r[0] for r in query.distinct().all()]
    today = datetime.utcnow().date()

    buckets = {
        '< 7 days': 0,
        '7-30 days': 0,
        '30-90 days': 0,
        '90-180 days': 0,
        '180-365 days': 0,
        '> 1 year': 0
    }

    for d in dates:
        if d is None:
            continue
        age = (today - d).days
        if age < 7:
            buckets['< 7 days'] += 1
        elif age < 30:
            buckets['7-30 days'] += 1
        elif age < 90:
            buckets['30-90 days'] += 1
        elif age < 180:
            buckets['90-180 days'] += 1
        elif age < 365:
            buckets['180-365 days'] += 1
        else:
            buckets['> 1 year'] += 1

    return jsonify({
        'labels': list(buckets.keys()),
        'values': list(buckets.values()),
        'chart_type': 'age_distribution',
        'title': 'Vulnerability Age Distribution'
    })


def _chart_vuln_timeline(org_product_ids):
    """New vulnerabilities added to KEV per month (last 12 months)."""
    from collections import OrderedDict

    twelve_months_ago = datetime.utcnow() - timedelta(days=365)

    query = db.session.query(
        func.date_trunc('month', Vulnerability.date_added).label('month'),
        func.count(func.distinct(Vulnerability.id)).label('total_cves'),
    ).join(
        VulnerabilityMatch, VulnerabilityMatch.vulnerability_id == Vulnerability.id
    ).filter(
        Vulnerability.date_added >= twelve_months_ago
    )

    if org_product_ids is not None:
        if org_product_ids:
            query = query.filter(VulnerabilityMatch.product_id.in_(org_product_ids))
        else:
            return jsonify({'labels': [], 'values': [], 'chart_type': 'vuln_timeline'})

    results = query.group_by('month').order_by('month').all()

    labels = []
    values = []
    for r in results:
        if r[0]:
            labels.append(r[0].strftime('%b %Y'))
            values.append(r[1])

    return jsonify({
        'labels': labels,
        'values': values,
        'chart_type': 'vuln_timeline',
        'title': 'New Affecting CVEs per Month'
    })


@bp.route('/api/vulnerabilities/trends', methods=['GET'])
@login_required
def get_vulnerability_trends():
    """
    Get historical vulnerability trend data for charts.

    Query params:
    - days: Number of days to look back (default: 30, max: 90)

    Returns daily snapshots of vulnerability metrics.
    """
    from app.models import VulnerabilitySnapshot

    days = request.args.get('days', 30, type=int)
    days = min(max(days, 7), 90)  # Clamp between 7 and 90

    # Get current organization
    org_id = session.get('organization_id')
    if not org_id:
        default_org = Organization.query.filter_by(name='default').first()
        org_id = default_org.id if default_org else None

    # Get trend data
    snapshots = VulnerabilitySnapshot.get_trend_data(organization_id=org_id, days=days)

    # Format for charts
    trend_data = {
        'dates': [],
        'total_matches': [],
        'unacknowledged': [],
        'acknowledged': [],
        'critical': [],
        'high': [],
        'medium': [],
        'low': [],
        'products_tracked': []
    }

    for snapshot in snapshots:
        trend_data['dates'].append(snapshot.snapshot_date.strftime('%Y-%m-%d'))
        trend_data['total_matches'].append(snapshot.total_matches)
        trend_data['unacknowledged'].append(snapshot.unacknowledged)
        trend_data['acknowledged'].append(snapshot.acknowledged)
        trend_data['critical'].append(snapshot.critical_count)
        trend_data['high'].append(snapshot.high_count)
        trend_data['medium'].append(snapshot.medium_count)
        trend_data['low'].append(snapshot.low_count)
        trend_data['products_tracked'].append(snapshot.products_tracked)

    return jsonify({
        'days': days,
        'snapshot_count': len(snapshots),
        'trends': trend_data
    })


@bp.route('/api/vulnerabilities/trends/snapshot', methods=['POST'])
@login_required
def take_vulnerability_snapshot():
    """
    Manually trigger a vulnerability snapshot.
    Useful for testing or initial setup.
    Requires admin privileges.
    """
    from app.models import VulnerabilitySnapshot

    # Check admin
    if not session.get('is_admin'):
        return jsonify({'error': 'Admin access required'}), 403

    # Get current organization
    org_id = session.get('organization_id')
    if not org_id:
        default_org = Organization.query.filter_by(name='default').first()
        org_id = default_org.id if default_org else None

    try:
        snapshot = VulnerabilitySnapshot.take_snapshot(organization_id=org_id)
        return jsonify({
            'success': True,
            'message': 'Snapshot taken successfully',
            'snapshot': snapshot.to_dict()
        })
    except Exception as e:
        logger.exception("Error taking snapshot")
        return jsonify({'error': str(e)}), 500


@bp.route('/api/vulnerabilities/grouped', methods=['GET'])
@login_required
def get_vulnerabilities_grouped():
    """
    Get vulnerabilities grouped by CVE ID.

    Instead of showing the same CVE multiple times (once per product),
    this groups by CVE ID and lists affected products under each CVE.

    Supports pagination and filtering:
    - page: Page number (default: 1)
    - per_page: Items per page (default: 25, max: 100)
    - priority: Filter by effective priority (critical, high, medium, low)
    - acknowledged: Filter by acknowledged status (true/false)
    - ransomware_only: Only show ransomware-related CVEs
    - search: Search CVE ID or description

    Returns:
    {
        "items": [
            {
                "cve_id": "CVE-2024-1234",
                "vulnerability": {...},  // Full vulnerability details
                "highest_priority": "critical",  // Highest priority across all affected products
                "affected_products": [
                    {
                        "product_id": 1,
                        "product_name": "nginx",
                        "vendor": "nginx",
                        "criticality": "high",
                        "effective_priority": "high",
                        "acknowledged": false,
                        "match_id": 123
                    }
                ],
                "product_count": 3,
                "unacknowledged_count": 2
            }
        ],
        "total": 150,
        "page": 1,
        "per_page": 25,
        "pages": 6
    }
    """
    from collections import defaultdict

    try:
        # Get current organization
        org_id = session.get('organization_id')
        if not org_id:
            default_org = Organization.query.filter_by(name='default').first()
            org_id = default_org.id if default_org else None

        # Build filters
        filters = {
            'organization_id': org_id,
            'ransomware_only': request.args.get('ransomware_only', 'false').lower() == 'true',
            'acknowledged': request.args.get('acknowledged'),
            'priority': request.args.get('priority'),
        }
        filters = {k: v for k, v in filters.items() if v is not None and v != ''}

        # Platform filter (windows/linux/macos/container) - applied post-query
        platform_filter = request.args.get('platform', '').lower().strip()

        # Get all matches
        matches = get_filtered_vulnerabilities(filters)

        # Pre-fetch affected assets data in batch to avoid N+1 queries
        from app.models import ProductInstallation, Asset
        from sqlalchemy import func

        # Collect all unique product_ids
        product_ids = set()
        for match in matches:
            product_ids.add(match.product.id)

        # Batch fetch asset counts for all products
        asset_counts = {}
        if product_ids:
            count_query = db.session.query(
                ProductInstallation.product_id,
                func.count(ProductInstallation.id).label('count')
            ).filter(
                ProductInstallation.product_id.in_(product_ids)
            )

            # Apply platform filter to counts too
            if platform_filter:
                count_query = count_query.join(Asset, Asset.id == ProductInstallation.asset_id).filter(Asset.active == True)
                if platform_filter == 'container':
                    count_query = count_query.filter(Asset.asset_type == 'container')
                elif platform_filter == 'windows':
                    count_query = count_query.filter(Asset.os_name.ilike('%windows%'))
                elif platform_filter == 'linux':
                    count_query = count_query.filter(db.or_(
                        Asset.os_name.ilike('%linux%'), Asset.os_name.ilike('%ubuntu%'),
                        Asset.os_name.ilike('%debian%'), Asset.os_name.ilike('%centos%'),
                        Asset.os_name.ilike('%rhel%'), Asset.os_name.ilike('%red hat%'),
                        Asset.os_name.ilike('%fedora%'), Asset.os_name.ilike('%suse%'),
                        Asset.os_name.ilike('%arch%'),
                    ))
                elif platform_filter == 'macos':
                    count_query = count_query.filter(db.or_(
                        Asset.os_name.ilike('%macos%'), Asset.os_name.ilike('%mac os%'),
                        Asset.os_name.ilike('%darwin%'),
                    ))

            count_results = count_query.group_by(ProductInstallation.product_id).all()
            asset_counts = {r.product_id: r.count for r in count_results}

        # Batch fetch sample assets (up to 10 per product) using window function
        # We'll get all assets and limit per product in Python for simplicity
        product_assets = defaultdict(list)
        # Track which products have assets matching the platform filter
        products_with_platform_match = set()
        if product_ids:
            asset_query = db.session.query(
                ProductInstallation.product_id,
                Asset.hostname,
                Asset.ip_address,
                Asset.asset_type,
                Asset.os_name
            ).join(
                Asset, Asset.id == ProductInstallation.asset_id
            ).filter(
                ProductInstallation.product_id.in_(product_ids),
                Asset.active == True
            )

            # Apply platform filter at the DB level if specified
            if platform_filter:
                if platform_filter == 'container':
                    asset_query = asset_query.filter(Asset.asset_type == 'container')
                elif platform_filter == 'windows':
                    asset_query = asset_query.filter(Asset.os_name.ilike('%windows%'))
                elif platform_filter == 'linux':
                    asset_query = asset_query.filter(db.or_(
                        Asset.os_name.ilike('%linux%'),
                        Asset.os_name.ilike('%ubuntu%'),
                        Asset.os_name.ilike('%debian%'),
                        Asset.os_name.ilike('%centos%'),
                        Asset.os_name.ilike('%rhel%'),
                        Asset.os_name.ilike('%red hat%'),
                        Asset.os_name.ilike('%fedora%'),
                        Asset.os_name.ilike('%suse%'),
                        Asset.os_name.ilike('%arch%'),
                    ))
                elif platform_filter == 'macos':
                    asset_query = asset_query.filter(db.or_(
                        Asset.os_name.ilike('%macos%'),
                        Asset.os_name.ilike('%mac os%'),
                        Asset.os_name.ilike('%darwin%'),
                    ))

            asset_results = asset_query.all()
            # Group by product_id, limit to 10 per product
            for r in asset_results:
                products_with_platform_match.add(r.product_id)
                if len(product_assets[r.product_id]) < 10:
                    product_assets[r.product_id].append({
                        'hostname': r.hostname,
                        'ip': r.ip_address,
                        'type': r.asset_type,
                        'os_name': r.os_name or ''
                    })

        # Group by CVE ID
        cve_groups = defaultdict(lambda: {
            'vulnerability': None,
            'affected_products': [],
            'priorities': [],
            'unacknowledged_count': 0
        })

        for match in matches:
            cve_id = match.vulnerability.cve_id
            group = cve_groups[cve_id]

            if not group['vulnerability']:
                group['vulnerability'] = match.vulnerability.to_dict()

            effective_priority = match.calculate_effective_priority()
            group['priorities'].append(effective_priority)

            if not match.acknowledged:
                group['unacknowledged_count'] += 1

            # Skip duplicate product entries for the same CVE (can happen if match was created twice)
            existing_product_ids = {p['product_id'] for p in group['affected_products']}
            if match.product.id in existing_product_ids:
                continue

            # Get pre-fetched asset data for this product
            asset_list = product_assets.get(match.product.id, [])
            asset_count = asset_counts.get(match.product.id, 0)

            group['affected_products'].append({
                'match_id': match.id,
                'product_id': match.product.id,
                'product_name': match.product.product_name,
                'vendor': match.product.vendor,
                'version': match.product.version,
                'criticality': match.product.criticality,
                'effective_priority': effective_priority,
                'acknowledged': match.acknowledged,
                'match_method': match.match_method,
                'match_confidence': match.match_confidence,
                'resolution_reason': match.resolution_reason,
                'vendor_fix_confidence': getattr(match, 'vendor_fix_confidence', None),
                'affected_assets': asset_list,
                'affected_assets_count': asset_count
            })

        # Build results list
        priority_order = {'critical': 4, 'high': 3, 'medium': 2, 'low': 1}
        level_names = {4: 'critical', 3: 'high', 2: 'medium', 1: 'low'}

        results = []
        for cve_id, group in cve_groups.items():
            # When platform filter is active, skip CVEs with no matching assets
            if platform_filter:
                has_platform_match = any(
                    p['product_id'] in products_with_platform_match
                    for p in group['affected_products']
                )
                if not has_platform_match:
                    continue

            # Calculate highest priority across all affected products
            max_priority_level = max(priority_order.get(p, 2) for p in group['priorities'])
            highest_priority = level_names.get(max_priority_level, 'medium')

            # Calculate total affected assets across all products
            total_affected_assets = sum(p.get('affected_assets_count', 0) for p in group['affected_products'])

            results.append({
                'cve_id': cve_id,
                'vulnerability': group['vulnerability'],
                'highest_priority': highest_priority,
                'affected_products': group['affected_products'],
                'product_count': len(group['affected_products']),
                'unacknowledged_count': group['unacknowledged_count'],
                'total_affected_assets': total_affected_assets
            })

        # Sort by: 1) highest priority (critical first), 2) newest date_added, 3) unacknowledged count
        def sort_key(x):
            priority = -priority_order.get(x['highest_priority'], 2)
            # Parse date_added for sorting (newest first = descending)
            date_added = x['vulnerability'].get('date_added', '1970-01-01')
            if isinstance(date_added, str):
                try:
                    from datetime import datetime
                    date_obj = datetime.fromisoformat(date_added.replace('Z', '+00:00'))
                    date_sort = -date_obj.timestamp()
                except:
                    date_sort = 0
            else:
                date_sort = 0
            unack = -x['unacknowledged_count']
            return (priority, date_sort, unack)

        results.sort(key=sort_key)

        # Apply search filter if provided
        search = request.args.get('search', '').lower()
        if search:
            results = [r for r in results if
                       search in r['cve_id'].lower() or
                       search in (r['vulnerability'].get('vulnerability_name', '') or '').lower() or
                       search in (r['vulnerability'].get('short_description', '') or '').lower()]

        # Filter by priority if specified
        priority_filter = request.args.get('priority')
        if priority_filter:
            results = [r for r in results if r['highest_priority'] == priority_filter.lower()]

        # Filter by CVE severity (CVSS-based)
        severity_filter = request.args.get('severity')
        if severity_filter:
            results = [r for r in results if r['vulnerability'].get('severity') == severity_filter]

        # Filter by CISA urgency (due date)
        urgency_filter = request.args.get('urgency')
        if urgency_filter:
            from datetime import datetime, timedelta
            today = datetime.utcnow().date()

            def matches_urgency(r):
                due_date_str = r['vulnerability'].get('due_date')
                is_ransomware = r['vulnerability'].get('known_ransomware', False)

                if not due_date_str:
                    return False  # No due date means no urgency

                try:
                    due_date = datetime.fromisoformat(due_date_str.replace('Z', '+00:00')).date()
                    days_until_due = (due_date - today).days
                except:
                    return False

                if urgency_filter == 'critical':
                    # Due within 7 days OR ransomware
                    return days_until_due <= 7 or is_ransomware
                elif urgency_filter == 'high':
                    # Due within 30 days
                    return days_until_due <= 30
                elif urgency_filter == 'has_due_date':
                    return True  # Has any due date
                return True

            results = [r for r in results if matches_urgency(r)]

        # Filter by age (days since added)
        age_filter = request.args.get('age')
        if age_filter:
            try:
                max_days = int(age_filter)
                results = [r for r in results if (r['vulnerability'].get('days_old') or 0) <= max_days]
            except ValueError:
                pass

        # Filter by vendor
        vendor_filter = request.args.get('vendor', '').lower()
        if vendor_filter:
            results = [r for r in results if any(
                vendor_filter in (p.get('vendor', '') or '').lower()
                for p in r['affected_products']
            )]

        # Filter by product name
        product_filter = request.args.get('product', '').lower()
        if product_filter:
            results = [r for r in results if any(
                product_filter in (p.get('product_name', '') or '').lower()
                for p in r['affected_products']
            )]

        # Pagination
        page = max(int(request.args.get('page', 1)), 1)
        per_page = min(int(request.args.get('per_page', 25)), 100)

        total = len(results)
        pages = (total + per_page - 1) // per_page if per_page > 0 else 1

        start = (page - 1) * per_page
        end = start + per_page
        page_results = results[start:end]

        return jsonify({
            'items': page_results,
            'total': total,
            'page': page,
            'per_page': per_page,
            'pages': pages
        })

    except Exception as e:
        logger.exception("Error getting grouped vulnerabilities")
        return jsonify({'error': ERROR_MSGS['database']}), 500


@bp.route('/api/products/aggregated', methods=['GET'])
@login_required
def get_aggregated_product_view():
    """
    Get aggregated view of products across assets, grouped by product and version.
    Shows how many servers have each version of each product.

    Example output:
    {
        "products": [
            {
                "product_id": 1,
                "vendor": "nginx",
                "product_name": "nginx",
                "versions": [
                    {"version": "1.24.0", "asset_count": 30, "vulnerable": true, "cve_count": 5},
                    {"version": "1.25.0", "asset_count": 20, "vulnerable": false, "cve_count": 0}
                ],
                "total_assets": 50
            }
        ]
    }
    """
    from sqlalchemy import func

    # Get current user's organizations
    current_user_id = session.get('user_id')
    current_user = User.query.get(current_user_id)

    # Build base query for installations accessible to user
    if current_user.is_super_admin():
        org_filter = True  # No filter
    else:
        user_org_ids = [org['id'] for org in current_user.get_all_organizations()]
        org_filter = Asset.organization_id.in_(user_org_ids)

    # Get filter parameters
    vulnerable_only = request.args.get('vulnerable_only', 'false').lower() == 'true'
    search = request.args.get('search', '')
    product_id = request.args.get('product_id', type=int)

    # Aggregate: group by product_id and version, count assets
    query = db.session.query(
        ProductInstallation.product_id,
        ProductInstallation.version,
        func.count(ProductInstallation.asset_id.distinct()).label('asset_count'),
        func.sum(db.case((ProductInstallation.is_vulnerable == True, 1), else_=0)).label('vulnerable_count'),
        func.max(ProductInstallation.vulnerability_count).label('max_cve_count')
    ).join(
        Asset, ProductInstallation.asset_id == Asset.id
    ).join(
        Product, ProductInstallation.product_id == Product.id
    )

    # Apply organization filter
    if org_filter is not True:
        query = query.filter(org_filter)

    # Apply search filter
    if search:
        search_term = f"%{search}%"
        query = query.filter(
            db.or_(
                Product.vendor.ilike(search_term),
                Product.product_name.ilike(search_term)
            )
        )

    # Filter by specific product
    if product_id:
        query = query.filter(ProductInstallation.product_id == product_id)

    # Group by product and version
    query = query.group_by(
        ProductInstallation.product_id,
        ProductInstallation.version
    )

    results = query.all()

    # Organize by product
    products_map = {}
    for row in results:
        pid = row.product_id
        if pid not in products_map:
            product = Product.query.get(pid)
            products_map[pid] = {
                'product_id': pid,
                'vendor': product.vendor,
                'product_name': product.product_name,
                'versions': [],
                'total_assets': 0,
                'has_vulnerabilities': False
            }

        version_info = {
            'version': row.version or 'Unknown',
            'asset_count': row.asset_count,
            'vulnerable': row.vulnerable_count > 0,
            'cve_count': row.max_cve_count or 0
        }

        products_map[pid]['versions'].append(version_info)
        products_map[pid]['total_assets'] += row.asset_count

        if version_info['vulnerable']:
            products_map[pid]['has_vulnerabilities'] = True

    # Convert to list and sort versions
    products_list = list(products_map.values())
    for product in products_list:
        # Sort versions by asset count descending
        product['versions'].sort(key=lambda v: v['asset_count'], reverse=True)

    # Filter vulnerable only
    if vulnerable_only:
        products_list = [p for p in products_list if p['has_vulnerabilities']]

    # Sort products by total assets descending
    products_list.sort(key=lambda p: p['total_assets'], reverse=True)

    # Pagination
    page = request.args.get('page', 1, type=int)
    per_page = min(request.args.get('per_page', 50, type=int), 200)
    start = (page - 1) * per_page
    end = start + per_page

    return jsonify({
        'products': products_list[start:end],
        'total': len(products_list),
        'page': page,
        'per_page': per_page,
        'pages': (len(products_list) + per_page - 1) // per_page
    })


@bp.route('/api/products/<int:product_id>/installations', methods=['GET'])
@login_required
def get_product_installations(product_id):
    """
    Get all installations of a product, showing which assets have which versions.
    """
    product = Product.query.get_or_404(product_id)

    # Check access
    current_user_id = session.get('user_id')
    current_user = User.query.get(current_user_id)

    if not current_user.is_super_admin():
        user_org_ids = [org['id'] for org in current_user.get_all_organizations()]
        product_org_ids = [org.id for org in product.organizations.all()]
        if product.organization_id:
            product_org_ids.append(product.organization_id)

        if not any(oid in user_org_ids for oid in product_org_ids):
            return jsonify({'error': 'Access denied'}), 403

    # Get installations with asset info
    installations = ProductInstallation.query.filter_by(product_id=product_id).all()

    result = []
    for inst in installations:
        asset = Asset.query.get(inst.asset_id)
        if asset:
            result.append({
                'installation_id': inst.id,
                'asset_id': asset.id,
                'hostname': asset.hostname,
                'ip_address': asset.ip_address,
                'os_name': asset.os_name,
                'os_version': asset.os_version,
                'version': inst.version,
                'install_path': inst.install_path,
                'is_vulnerable': inst.is_vulnerable,
                'vulnerability_count': inst.vulnerability_count,
                'detected_by': inst.detected_by,
                'discovered_at': inst.discovered_at.isoformat() if inst.discovered_at else None,
                'last_seen_at': inst.last_seen_at.isoformat() if inst.last_seen_at else None
            })

    # Sort by hostname
    result.sort(key=lambda x: x['hostname'])

    return jsonify({
        'product': {
            'id': product.id,
            'vendor': product.vendor,
            'product_name': product.product_name
        },
        'installations': result,
        'total': len(result)
    })


@bp.route('/api/matches/<int:match_id>/acknowledge', methods=['POST'])
@login_required
def acknowledge_match(match_id):
    """Acknowledge a vulnerability match"""
    current_user_id = session.get('user_id')
    current_user = User.query.get(current_user_id)
    match = VulnerabilityMatch.query.get_or_404(match_id)

    # Authorization: verify user can manage this product's matches
    if not current_user.is_super_admin():
        # Get all org IDs the product belongs to
        product_org_ids = [org.id for org in match.product.organizations.all()]
        if match.product.organization_id:
            product_org_ids.append(match.product.organization_id)
        user_org_ids = [org['id'] for org in current_user.get_all_organizations()]
        if not any(org_id in user_org_ids for org_id in product_org_ids):
            return jsonify({'error': 'Insufficient permissions to manage this vulnerability match'}), 403

    match.acknowledged = True
    match.auto_acknowledged = False
    match.resolution_reason = 'manual'
    match.acknowledged_at = datetime.utcnow()
    db.session.commit()
    return jsonify(match.to_dict())

@bp.route('/api/matches/<int:match_id>/unacknowledge', methods=['POST'])
@login_required
def unacknowledge_match(match_id):
    """Unacknowledge a vulnerability match (reopen it for alerts)"""
    current_user_id = session.get('user_id')
    current_user = User.query.get(current_user_id)
    match = VulnerabilityMatch.query.get_or_404(match_id)

    # Authorization: verify user can manage this product's matches
    if not current_user.is_super_admin():
        # Get all org IDs the product belongs to
        product_org_ids = [org.id for org in match.product.organizations.all()]
        if match.product.organization_id:
            product_org_ids.append(match.product.organization_id)
        user_org_ids = [org['id'] for org in current_user.get_all_organizations()]
        if not any(org_id in user_org_ids for org_id in product_org_ids):
            return jsonify({'error': 'Insufficient permissions to manage this vulnerability match'}), 403

    match.acknowledged = False
    match.auto_acknowledged = False
    match.resolution_reason = None
    match.acknowledged_at = None
    # Reset first_alerted_at so it will be alerted again as "new"
    match.first_alerted_at = None
    db.session.commit()
    return jsonify(match.to_dict())


@bp.route('/api/matches/<int:match_id>/snooze', methods=['POST'])
@login_required
def snooze_match(match_id):
    """
    Snooze a vulnerability match for a specified duration.

    Request body:
    {
        "hours": 24  // or "days": 7
    }

    Snoozing temporarily suppresses alerts for this match until the snooze expires.
    Useful when a patch isn't available yet or remediation is planned.
    """
    current_user_id = session.get('user_id')
    current_user = User.query.get(current_user_id)
    match = VulnerabilityMatch.query.get_or_404(match_id)

    # Authorization: verify user can manage this product's matches
    if not current_user.is_super_admin():
        product_org_ids = [org.id for org in match.product.organizations.all()]
        if match.product.organization_id:
            product_org_ids.append(match.product.organization_id)
        user_org_ids = [org['id'] for org in current_user.get_all_organizations()]
        if not any(org_id in user_org_ids for org_id in product_org_ids):
            return jsonify({'error': 'Insufficient permissions'}), 403

    data = request.get_json() or {}
    hours = data.get('hours', 0)
    days = data.get('days', 0)

    if not hours and not days:
        # Default to 24 hours if not specified
        hours = 24

    total_hours = hours + (days * 24)
    match.snoozed_until = datetime.utcnow() + timedelta(hours=total_hours)
    db.session.commit()

    return jsonify({
        'success': True,
        'snoozed_until': match.snoozed_until.isoformat(),
        'match': match.to_dict()
    })


@bp.route('/api/matches/<int:match_id>/unsnooze', methods=['POST'])
@login_required
def unsnooze_match(match_id):
    """Remove snooze from a vulnerability match."""
    current_user_id = session.get('user_id')
    current_user = User.query.get(current_user_id)
    match = VulnerabilityMatch.query.get_or_404(match_id)

    # Authorization
    if not current_user.is_super_admin():
        product_org_ids = [org.id for org in match.product.organizations.all()]
        if match.product.organization_id:
            product_org_ids.append(match.product.organization_id)
        user_org_ids = [org['id'] for org in current_user.get_all_organizations()]
        if not any(org_id in user_org_ids for org_id in product_org_ids):
            return jsonify({'error': 'Insufficient permissions'}), 403

    match.snoozed_until = None
    db.session.commit()
    return jsonify(match.to_dict())


@bp.route('/api/matches/acknowledge-by-cve/<cve_id>', methods=['POST'])
@login_required
def acknowledge_by_cve(cve_id):
    """
    Acknowledge ALL vulnerability matches for a given CVE ID.

    This is the recommended way to acknowledge CVEs since one CVE typically
    requires one fix (e.g., a Windows Update) regardless of how many
    products/versions it affects.

    Returns: { acknowledged_count: X, match_ids: [...] }
    """
    from app.logging_config import log_audit_event

    current_user_id = session.get('user_id')
    current_user = User.query.get(current_user_id)
    org_id = session.get('organization_id')

    # Find the vulnerability
    vuln = Vulnerability.query.filter_by(cve_id=cve_id).first()
    if not vuln:
        return jsonify({'error': f'CVE {cve_id} not found'}), 404

    # Find all matches for this CVE that the user has permission to manage
    from app.models import product_organizations

    if current_user.is_super_admin():
        # Super admin can acknowledge any match
        matches = VulnerabilityMatch.query.filter_by(
            vulnerability_id=vuln.id,
            acknowledged=False
        ).all()
    else:
        # Non-admin: filter by organization membership using scalar_subquery
        user_org_ids = [org['id'] for org in current_user.get_all_organizations()]

        # Get product IDs accessible to user's organizations
        user_product_ids = db.session.query(product_organizations.c.product_id).filter(
            product_organizations.c.organization_id.in_(user_org_ids)
        ).scalar_subquery()

        matches = db.session.query(VulnerabilityMatch).filter(
            VulnerabilityMatch.vulnerability_id == vuln.id,
            VulnerabilityMatch.acknowledged == False,
            VulnerabilityMatch.product_id.in_(user_product_ids)
        ).all()

    if not matches:
        return jsonify({
            'acknowledged_count': 0,
            'match_ids': [],
            'message': 'No unacknowledged matches found for this CVE'
        })

    # Acknowledge all matches
    acknowledged_ids = []
    now = datetime.utcnow()
    for match in matches:
        match.acknowledged = True
        match.auto_acknowledged = False
        match.resolution_reason = 'manual'
        match.acknowledged_at = now
        acknowledged_ids.append(match.id)

    db.session.commit()

    log_audit_event(
        'ACKNOWLEDGE_CVE',
        'vulnerability_matches',
        vuln.id,
        new_value={'acknowledged_count': len(acknowledged_ids), 'cve_id': cve_id},
        details=f"Bulk acknowledged {len(acknowledged_ids)} matches for {cve_id}"
    )

    return jsonify({
        'acknowledged_count': len(acknowledged_ids),
        'match_ids': acknowledged_ids,
        'cve_id': cve_id,
        'message': f'Acknowledged {len(acknowledged_ids)} product(s) for {cve_id}'
    })


@bp.route('/api/matches/unacknowledge-by-cve/<cve_id>', methods=['POST'])
@login_required
def unacknowledge_by_cve(cve_id):
    """
    Unacknowledge ALL vulnerability matches for a given CVE ID.
    """
    from app.logging_config import log_audit_event

    current_user_id = session.get('user_id')
    current_user = User.query.get(current_user_id)

    # Find the vulnerability
    vuln = Vulnerability.query.filter_by(cve_id=cve_id).first()
    if not vuln:
        return jsonify({'error': f'CVE {cve_id} not found'}), 404

    # Find all matches for this CVE that the user has permission to manage
    from app.models import product_organizations

    if current_user.is_super_admin():
        matches = VulnerabilityMatch.query.filter_by(
            vulnerability_id=vuln.id,
            acknowledged=True
        ).all()
    else:
        # Non-admin: filter by organization membership using scalar_subquery
        user_org_ids = [org['id'] for org in current_user.get_all_organizations()]

        # Get product IDs accessible to user's organizations
        user_product_ids = db.session.query(product_organizations.c.product_id).filter(
            product_organizations.c.organization_id.in_(user_org_ids)
        ).scalar_subquery()

        matches = db.session.query(VulnerabilityMatch).filter(
            VulnerabilityMatch.vulnerability_id == vuln.id,
            VulnerabilityMatch.acknowledged == True,
            VulnerabilityMatch.product_id.in_(user_product_ids)
        ).all()

    if not matches:
        return jsonify({
            'unacknowledged_count': 0,
            'match_ids': [],
            'message': 'No acknowledged matches found for this CVE'
        })

    # Unacknowledge all matches and reset first_alerted_at for re-alerting
    unacknowledged_ids = []
    for match in matches:
        match.acknowledged = False
        match.first_alerted_at = None  # Reset so it will be alerted again as "new"
        unacknowledged_ids.append(match.id)

    db.session.commit()

    log_audit_event(
        'UNACKNOWLEDGE_CVE',
        'vulnerability_matches',
        vuln.id,
        new_value={'unacknowledged_count': len(unacknowledged_ids), 'cve_id': cve_id},
        details=f"Bulk unacknowledged {len(unacknowledged_ids)} matches for {cve_id} (will re-alert)"
    )

    return jsonify({
        'unacknowledged_count': len(unacknowledged_ids),
        'match_ids': unacknowledged_ids,
        'cve_id': cve_id,
        'message': f'Unacknowledged {len(unacknowledged_ids)} product(s) for {cve_id}'
    })


# ============================================================================
# Vendor Fix Override API (Path B - in-place vendor patches)
# ============================================================================

@bp.route('/api/vendor-fix-overrides', methods=['GET'])
@login_required
def list_vendor_fix_overrides():
    """List all vendor fix overrides for the current organization."""
    from app.models import VendorFixOverride
    org_id = session.get('organization_id')

    query = VendorFixOverride.query
    if org_id:
        query = query.filter(
            db.or_(
                VendorFixOverride.organization_id == org_id,
                VendorFixOverride.organization_id.is_(None)
            )
        )

    # Filter by CVE if specified
    cve_id = request.args.get('cve_id')
    if cve_id:
        query = query.filter(VendorFixOverride.cve_id == cve_id)

    # Filter by status
    status = request.args.get('status')
    if status:
        query = query.filter(VendorFixOverride.status == status)

    overrides = query.order_by(VendorFixOverride.created_at.desc()).all()
    return jsonify([o.to_dict() for o in overrides])


@bp.route('/api/vendor-fix-overrides/sync', methods=['POST'])
@org_admin_required
def trigger_vendor_advisory_sync():
    """Manually trigger vendor advisory sync (OSV.dev, Red Hat, MSRC, Debian)."""
    from app.vendor_advisories import sync_vendor_advisories
    from app.logging_config import log_audit_event

    try:
        result = sync_vendor_advisories()
        log_audit_event(
            'VENDOR_ADVISORY_SYNC',
            'vendor_fix_overrides',
            None,
            details=f"Manual vendor advisory sync: {result.get('overrides_created', 0)} overrides, "
                     f"{result.get('matches_resolved', 0)} resolved"
        )
        return jsonify(result)
    except Exception as e:
        return jsonify({'error': str(e)}), 500


def _apply_vendor_fix_override(override):
    """
    When a vendor fix override is approved, resolve matching vulnerability matches.
    Returns the number of matches resolved.
    """
    # Find the vulnerability
    vuln = Vulnerability.query.filter_by(cve_id=override.cve_id).first()
    if not vuln:
        return 0

    # Find products matching the override's vendor/product/version
    products = Product.query.filter(
        func.lower(Product.vendor) == override.vendor.lower(),
        func.lower(Product.product_name) == override.product.lower(),
        Product.version == override.fixed_version,
        Product.active == True
    ).all()

    if not products:
        # Also try matching via CPE vendor/product
        products = Product.query.filter(
            func.lower(Product.cpe_vendor) == override.vendor.lower(),
            func.lower(Product.cpe_product) == override.product.lower(),
            Product.version == override.fixed_version,
            Product.active == True
        ).all()

    if not products:
        return 0

    product_ids = [p.id for p in products]
    now = datetime.utcnow()

    # Find unacknowledged matches for these products + this CVE
    matches = VulnerabilityMatch.query.filter(
        VulnerabilityMatch.product_id.in_(product_ids),
        VulnerabilityMatch.vulnerability_id == vuln.id,
        VulnerabilityMatch.acknowledged == False
    ).all()

    confidence = getattr(override, 'confidence', 'medium') or 'medium'
    for match in matches:
        if confidence == 'high':
            # High confidence: fully resolve
            match.acknowledged = True
            match.auto_acknowledged = True
            match.acknowledged_at = now
        # Medium confidence: tag but leave unacknowledged (stays in alerts)
        match.resolution_reason = 'vendor_fix'
        match.vendor_fix_confidence = confidence

    db.session.commit()
    return len(matches)


@bp.route('/api/vendor-advisories/check/<cve_id>', methods=['GET'])
@login_required
def check_vendor_advisories(cve_id):
    """
    Check vendor advisory feeds for patches related to a specific CVE.
    Returns suggestions for vendor fix overrides based on published advisories.
    """
    try:
        from app.vendor_advisories import check_advisory_for_cve
        advisories = check_advisory_for_cve(cve_id)
        return jsonify({
            'cve_id': cve_id,
            'advisories': advisories,
            'count': len(advisories)
        })
    except Exception as e:
        logger.warning(f'Advisory check failed for {cve_id}: {e}')
        return jsonify({
            'cve_id': cve_id,
            'suggestions': [],
            'count': 0,
            'error': str(e)
        })


@bp.route('/api/sync', methods=['POST'])
@admin_required
@limiter.limit("5/minute")
def trigger_sync():
    """
    Manually trigger CISA KEV sync

    Permissions:
    - Super Admin only: Can trigger manual sync of CISA KEV data
    """
    result = sync_cisa_kev()
    return jsonify(result)

@bp.route('/api/sync/status', methods=['GET'])
@login_required
def sync_status():
    """Get last sync status"""
    last_sync = SyncLog.query.order_by(SyncLog.sync_date.desc()).first()
    if last_sync:
        return jsonify(last_sync.to_dict())
    return jsonify({'message': 'No sync performed yet'})

@bp.route('/api/sync/history', methods=['GET'])
@login_required
def sync_history():
    """Get sync history"""
    limit = request.args.get('limit', 10, type=int)
    syncs = SyncLog.query.order_by(SyncLog.sync_date.desc()).limit(limit).all()
    return jsonify([s.to_dict() for s in syncs])


@bp.route('/api/sync/epss', methods=['POST'])
@admin_required
@limiter.limit("5/minute")
def sync_epss():
    """
    Manually trigger EPSS (Exploit Prediction Scoring System) sync.

    Fetches exploit probability scores from FIRST.org for all vulnerabilities.

    Query Parameters:
        force: If 'true', refresh all scores regardless of age

    Permissions:
        - Admin only
    """
    from app.epss_sync import sync_epss_scores

    force = request.args.get('force', '').lower() == 'true'

    try:
        updated, errors, message = sync_epss_scores(force=force)
        return jsonify({
            'success': True,
            'updated': updated,
            'errors': errors,
            'message': message
        })
    except Exception as e:
        logger.exception("EPSS sync failed")
        return jsonify({
            'success': False,
            'error': f'EPSS sync failed: {str(e)}'
        }), 500


@bp.route('/api/sync/epss/status', methods=['GET'])
@login_required
def epss_status():
    """Get EPSS sync status with score distribution for dashboard widgets."""
    from app.models import Vulnerability
    from sqlalchemy import func

    total_vulns = Vulnerability.query.count()
    with_epss = Vulnerability.query.filter(Vulnerability.epss_score.isnot(None)).count()
    last_fetch = db.session.query(func.max(Vulnerability.epss_fetched_at)).scalar()

    # Score distribution (buckets for dashboard chart)
    very_high = Vulnerability.query.filter(Vulnerability.epss_score >= 0.5).count()
    high_risk = Vulnerability.query.filter(
        Vulnerability.epss_score >= 0.1, Vulnerability.epss_score < 0.5
    ).count()
    medium_risk = Vulnerability.query.filter(
        Vulnerability.epss_score >= 0.01, Vulnerability.epss_score < 0.1
    ).count()
    low_risk = Vulnerability.query.filter(
        Vulnerability.epss_score > 0, Vulnerability.epss_score < 0.01
    ).count()

    # Top 10 highest EPSS scores (most likely to be exploited)
    top_epss = Vulnerability.query.filter(
        Vulnerability.epss_score.isnot(None)
    ).order_by(Vulnerability.epss_score.desc()).limit(10).all()

    return jsonify({
        'total_vulnerabilities': total_vulns,
        'with_epss_scores': with_epss,
        'without_epss_scores': total_vulns - with_epss,
        'coverage_percent': round((with_epss / total_vulns * 100), 1) if total_vulns > 0 else 0,
        'last_sync': last_fetch.isoformat() if last_fetch else None,
        'distribution': {
            'very_high': very_high,   # >= 50% probability
            'high': high_risk,         # 10-50%
            'medium': medium_risk,     # 1-10%
            'low': low_risk,           # < 1%
        },
        'top_epss': [{
            'cve_id': v.cve_id,
            'epss_score': round(v.epss_score, 4) if v.epss_score else None,
            'epss_percentile': round(v.epss_percentile, 4) if v.epss_percentile else None,
            'cvss_score': v.cvss_score,
            'known_ransomware': v.known_ransomware,
        } for v in top_epss],
    })


@bp.route('/api/system/health', methods=['GET'])
@login_required
def system_health():
    """System health overview for dashboard - CPE dictionary, sync status."""
    from app.models import Vulnerability, Product, UserCpeMapping
    from sqlalchemy import func

    result = {}

    # CPE coverage
    total_products = Product.query.filter(Product.active == True).count()
    with_cpe = Product.query.filter(
        Product.active == True,
        Product.cpe_vendor.isnot(None),
        Product.cpe_vendor != ''
    ).count()
    result['cpe_coverage'] = {
        'total_products': total_products,
        'with_cpe': with_cpe,
        'without_cpe': total_products - with_cpe,
        'coverage_percent': round((with_cpe / total_products * 100), 1) if total_products > 0 else 0,
    }

    # CPE dictionary stats
    try:
        from app.cpe_dictionary import get_dictionary_stats
        result['cpe_dictionary'] = get_dictionary_stats()
    except Exception:
        result['cpe_dictionary'] = {'total_entries': 0}

    # User-learned mappings
    result['user_mappings'] = {
        'total': UserCpeMapping.query.count(),
        'user': UserCpeMapping.query.filter_by(source='user').count(),
        'auto_nvd': UserCpeMapping.query.filter_by(source='auto_nvd').count(),
        'community': UserCpeMapping.query.filter_by(source='community').count(),
    }

    # Vulnerability sync status
    total_vulns = Vulnerability.query.count()
    with_cpe_data = Vulnerability.query.filter(Vulnerability.cpe_data.isnot(None)).count()
    last_sync = db.session.query(func.max(Vulnerability.created_at)).scalar()
    result['vulnerabilities'] = {
        'total': total_vulns,
        'with_cpe_data': with_cpe_data,
        'last_sync': last_sync.isoformat() if last_sync else None,
    }

    return jsonify(result)


@bp.route('/api/sync/test-connection', methods=['POST'])
@admin_required
def test_connection():
    """Test external API connection (for proxy settings verification)"""
    import requests
    from app.settings_api import get_setting

    # Get proxy settings
    verify_ssl = get_setting('verify_ssl', 'true') == 'true'
    http_proxy = get_setting('http_proxy', '')
    https_proxy = get_setting('https_proxy', '')

    proxies = {}
    if http_proxy:
        proxies['http'] = http_proxy
    if https_proxy:
        proxies['https'] = https_proxy

    try:
        # Test connection to CISA KEV catalog
        test_url = 'https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json'
        response = requests.head(
            test_url,
            timeout=10,
            verify=verify_ssl,
            proxies=proxies if proxies else None,
            allow_redirects=True
        )

        if response.status_code == 200:
            return jsonify({
                'success': True,
                'message': 'Connection successful',
                'status_code': response.status_code
            })
        else:
            return jsonify({
                'success': False,
                'error': f'Received status code {response.status_code}'
            }), 400

    except requests.exceptions.SSLError as e:
        logger.warning(f"SSL error during proxy test: {e}")
        return jsonify({
            'success': False,
            'error': 'SSL Error: Try disabling SSL verification if behind a proxy.'
        }), 400
    except requests.exceptions.ProxyError as e:
        logger.warning(f"Proxy error during proxy test: {e}")
        return jsonify({
            'success': False,
            'error': 'Proxy Error: Check your proxy settings.'
        }), 400
    except requests.exceptions.ConnectionError as e:
        logger.warning(f"Connection error during proxy test: {e}")
        return jsonify({
            'success': False,
            'error': 'Connection Error: Unable to reach the target URL.'
        }), 400
    except requests.exceptions.Timeout as e:
        logger.warning(f"Timeout during proxy test: {e}")
        return jsonify({
            'success': False,
            'error': 'Timeout: The request took too long to complete.'
        }), 400
    except Exception as e:
        logger.exception("Unexpected error during proxy test")
        return jsonify({
            'success': False,
            'error': ERROR_MSGS['network']
        }), 500


@bp.route('/api/products/rematch', methods=['POST'])
@admin_required
def rematch_products():
    """
    Re-run product matching with current (stricter) logic.
    Removes invalid matches and adds new valid ones.

    Permissions:
    - Super Admin only: Can trigger product rematch
    """
    from app.filters import rematch_all_products

    try:
        removed, added = rematch_all_products()
        return jsonify({
            'status': 'success',
            'removed': removed,
            'added': added,
            'message': f'Removed {removed} invalid matches, added {added} new matches'
        })
    except Exception as e:
        logger.exception("Error during product rematch")
        return jsonify({'status': 'error', 'message': ERROR_MSGS['internal']}), 500


@bp.route('/api/products/apply-cpe', methods=['POST'])
@admin_required
def apply_cpe_mappings():
    """
    Apply CPE auto-mappings to products that don't have CPE identifiers.
    Uses multi-tier matching: local patterns, curated mappings, and NVD API.
    Auto-saves NVD discoveries as learned mappings for future use.

    Runs in background thread to avoid Gunicorn worker timeout.
    If the CPE dictionary is empty, triggers a bulk download first.

    Permissions:
    - Super Admin only: Can apply CPE mappings
    """
    import threading
    from app.cpe_mapping import get_cpe_coverage_stats

    try:
        data = request.get_json(silent=True) or {}
        use_nvd = data.get('use_nvd', True)
        max_nvd = data.get('max_nvd_lookups', 200)

        app = current_app._get_current_object()

        def _save_job_status(status, message='', updated=0, total=0):
            """Save CPE apply job status to SystemSettings."""
            import json
            from app.models import SystemSettings
            try:
                db.session.rollback()  # Clear any pending rollback state
            except Exception:
                pass
            val = json.dumps({'status': status, 'message': message, 'updated': updated, 'total': total, 'ts': datetime.utcnow().isoformat()})
            try:
                setting = SystemSettings.query.filter_by(key='cpe_apply_job_status').first()
                if setting:
                    setting.value = val
                else:
                    setting = SystemSettings(key='cpe_apply_job_status', value=val, category='sync')
                    db.session.add(setting)
                db.session.commit()
            except Exception:
                db.session.rollback()

        def _run_cpe_apply():
            with app.app_context():
                try:
                    # If dictionary is empty, do bulk download first
                    from app.models import CpeDictionaryEntry
                    dict_count = CpeDictionaryEntry.query.count()
                    if dict_count < 1000:
                        _save_job_status('downloading', f'Downloading CPE dictionary ({dict_count} entries currently)...')
                        logger.info(f"CPE dictionary has only {dict_count} entries, running bulk download first...")
                        from app.cpe_dictionary import sync_nvd_cpe_dictionary
                        sync_nvd_cpe_dictionary()

                    _save_job_status('mapping', 'Applying CPE mappings to products...')
                    from app.cpe_mapping import batch_apply_cpe_mappings
                    updated, total_without = batch_apply_cpe_mappings(
                        commit=True, use_nvd=use_nvd, max_nvd_lookups=max_nvd
                    )
                    logger.info(f"CPE auto-apply complete: {updated}/{total_without} products mapped")
                    _save_job_status('complete', f'Mapped {updated} of {total_without} unmapped products', updated, total_without)
                except Exception as e:
                    logger.error(f"CPE auto-apply failed: {e}")
                    _save_job_status('error', str(e))

        t = threading.Thread(target=_run_cpe_apply, daemon=True, name='CpeAutoApply')
        t.start()

        stats = get_cpe_coverage_stats()
        return jsonify({
            'status': 'started',
            'coverage': stats,
            'message': 'CPE auto-mapping started in background. Refresh in a minute to see results.'
        }), 202
    except Exception as e:
        logger.exception("Error starting CPE auto-apply")
        return jsonify({'status': 'error', 'message': ERROR_MSGS['internal']}), 500


@bp.route('/api/products/cpe-apply-status', methods=['GET'])
@admin_required
def cpe_apply_status():
    """Get the status of the background CPE auto-apply job."""
    import json
    from app.models import SystemSettings
    setting = SystemSettings.query.filter_by(key='cpe_apply_job_status').first()
    if not setting or not setting.value:
        return jsonify({'status': 'idle', 'message': 'No CPE auto-apply job has run yet.'})
    try:
        data = json.loads(setting.value)
        return jsonify(data)
    except (json.JSONDecodeError, TypeError):
        return jsonify({'status': 'idle', 'message': ''})


@bp.route('/api/products/cpe-suggestions', methods=['GET'])
@admin_required
def get_cpe_suggestions():
    """
    Get CPE mapping suggestions for products without CPE.

    Permissions:
    - Super Admin only: Can view CPE suggestions
    """
    from app.cpe_mapping import suggest_cpe_for_products, get_cpe_coverage_stats

    try:
        suggestions = suggest_cpe_for_products(limit=100)
        stats = get_cpe_coverage_stats()
        return jsonify({
            'status': 'success',
            'suggestions': suggestions,
            'coverage': stats
        })
    except Exception as e:
        logger.exception("Error getting CPE suggestions")
        return jsonify({'status': 'error', 'message': ERROR_MSGS['internal']}), 500


@bp.route('/api/alerts/trigger-critical', methods=['POST'])
@admin_required
def trigger_critical_cve_alerts():
    """
    Manually trigger critical CVE email alerts for all organizations

    Permissions:
    - Super Admin only: Can manually trigger critical CVE alert emails
    """
    from app.email_alerts import EmailAlertManager

    try:
        results = []
        organizations = Organization.query.filter_by(active=True).all()

        for org in organizations:
            # Get unacknowledged critical/high priority vulnerabilities
            # Include products assigned via both legacy organization_id and multi-org table
            from app.models import product_organizations
            legacy_product_ids = db.session.query(Product.id).filter(
                Product.organization_id == org.id
            )
            multi_org_product_ids = db.session.query(product_organizations.c.product_id).filter(
                product_organizations.c.organization_id == org.id
            )
            org_product_ids = legacy_product_ids.union(multi_org_product_ids).scalar_subquery()

            unack_matches = (
                VulnerabilityMatch.query
                .filter(
                    VulnerabilityMatch.product_id.in_(org_product_ids),
                    VulnerabilityMatch.acknowledged == False
                )
                .all()
            )

            # Filter for CRITICAL priority ONLY (not high - too many alerts cause spam)
            critical_matches = [
                m for m in unack_matches
                if m.calculate_effective_priority() == 'critical'
            ]

            if not critical_matches:
                results.append({
                    'organization': org.name,
                    'status': 'skipped',
                    'reason': 'No unacknowledged critical CVEs'
                })
                continue

            # Send alert
            result = EmailAlertManager.send_critical_cve_alert(org, critical_matches)
            results.append({
                'organization': org.name,
                'status': result.get('status'),
                'matches_count': result.get('matches_count', 0),
                'sent_to': result.get('sent_to', 0),
                'reason': result.get('reason', '')
            })

        # Count successes
        sent_count = sum(1 for r in results if r['status'] == 'success')
        skipped_count = sum(1 for r in results if r['status'] == 'skipped')
        error_count = sum(1 for r in results if r['status'] == 'error')

        return jsonify({
            'status': 'success',
            'summary': {
                'total_orgs': len(organizations),
                'emails_sent': sent_count,
                'skipped': skipped_count,
                'errors': error_count
            },
            'details': results
        })

    except Exception as e:
        logger.exception("Error triggering critical CVE alerts")
        return jsonify({
            'status': 'error',
            'error': ERROR_MSGS['smtp']
        }), 500


@bp.route('/api/alerts/trigger-webhooks', methods=['POST'])
@admin_required
def trigger_webhook_alerts():
    """
    Manually trigger webhook alerts for all organizations

    Permissions:
    - Super Admin only: Can manually trigger webhook notifications
    """
    from app.cisa_sync import send_org_webhook

    try:
        results = []
        organizations = Organization.query.filter_by(active=True).all()

        for org in organizations:
            # Check if org has webhooks enabled
            if not org.webhook_enabled or not org.webhook_url:
                results.append({
                    'organization': org.name,
                    'status': 'skipped',
                    'reason': 'Webhook not configured'
                })
                continue

            # Get unacknowledged matches for this org
            # Include products assigned via both legacy organization_id and multi-org table
            from app.models import product_organizations
            legacy_pids = db.session.query(Product.id).filter(
                Product.organization_id == org.id
            )
            multi_org_pids = db.session.query(product_organizations.c.product_id).filter(
                product_organizations.c.organization_id == org.id
            )
            org_product_ids = legacy_pids.union(multi_org_pids).scalar_subquery()

            unack_matches = (
                VulnerabilityMatch.query
                .filter(
                    VulnerabilityMatch.product_id.in_(org_product_ids),
                    VulnerabilityMatch.acknowledged == False
                )
                .all()
            )

            # Filter for critical/high priority matches
            priority_matches = [
                m for m in unack_matches
                if m.calculate_effective_priority() in ('critical', 'high')
            ]

            if not priority_matches:
                results.append({
                    'organization': org.name,
                    'status': 'skipped',
                    'reason': 'No unacknowledged critical/high CVEs'
                })
                continue

            # Count critical
            critical_count = sum(1 for m in priority_matches if m.calculate_effective_priority() == 'critical')

            # Send webhook (force=True bypasses first_alerted_at filter for manual triggers)
            result = send_org_webhook(
                org=org,
                new_cves_count=len(priority_matches),
                critical_count=critical_count,
                matches_count=len(priority_matches),
                matches=priority_matches,
                force=True
            )

            if result:
                if result.get('skipped'):
                    results.append({
                        'organization': org.name,
                        'status': 'skipped',
                        'reason': result.get('reason', 'No new CVEs to alert')
                    })
                elif result.get('success'):
                    results.append({
                        'organization': org.name,
                        'status': 'success',
                        'new_cves': result.get('new_cves', 0)
                    })
                else:
                    results.append({
                        'organization': org.name,
                        'status': 'error',
                        'reason': result.get('error', 'Unknown error')
                    })
            else:
                results.append({
                    'organization': org.name,
                    'status': 'skipped',
                    'reason': 'No webhook configured'
                })

        # Count successes
        sent_count = sum(1 for r in results if r['status'] == 'success')
        skipped_count = sum(1 for r in results if r['status'] == 'skipped')
        error_count = sum(1 for r in results if r['status'] == 'error')

        return jsonify({
            'status': 'success',
            'summary': {
                'total_orgs': len(organizations),
                'webhooks_sent': sent_count,
                'skipped': skipped_count,
                'errors': error_count
            },
            'details': results
        })

    except Exception as e:
        logger.exception("Error triggering webhook alerts")
        return jsonify({
            'status': 'error',
            'error': 'Failed to send webhook notifications'
        }), 500


# ============================================================================
# SERVICE CATALOG API ENDPOINTS
# ============================================================================

@bp.route('/api/catalog', methods=['GET'])
@login_required
def get_all_catalog():
    """Get all services from catalog"""
    services = ServiceCatalog.query.filter_by(is_active=True)\
        .order_by(ServiceCatalog.vendor, ServiceCatalog.product_name).all()
    return jsonify([s.to_dict() for s in services])

@bp.route('/api/catalog/<int:catalog_id>', methods=['GET'])
@login_required
def get_catalog_service(catalog_id):
    """Get a specific service from catalog"""
    service = ServiceCatalog.query.get_or_404(catalog_id)
    return jsonify(service.to_dict())

@bp.route('/api/catalog/search', methods=['GET'])
@login_required
def search_catalog():
    """Search service catalog - supports autocomplete for vendor/product or full search"""
    query = request.args.get('q', '').strip()
    search_type = request.args.get('type')  # 'vendor' or 'product' for autocomplete
    category = request.args.get('category')
    limit = request.args.get('limit', 20, type=int)

    # Autocomplete mode: return unique vendor or product names
    if search_type == 'vendor':
        vendors = ServiceCatalog.query\
            .filter(ServiceCatalog.is_active == True)\
            .filter(ServiceCatalog.vendor.ilike(f'%{query}%'))\
            .with_entities(ServiceCatalog.vendor)\
            .distinct()\
            .order_by(ServiceCatalog.vendor)\
            .limit(limit)\
            .all()
        return jsonify([v.vendor for v in vendors])

    elif search_type == 'product':
        products = ServiceCatalog.query\
            .filter(ServiceCatalog.is_active == True)\
            .filter(ServiceCatalog.product_name.ilike(f'%{query}%'))\
            .with_entities(ServiceCatalog.product_name)\
            .distinct()\
            .order_by(ServiceCatalog.product_name)\
            .limit(limit)\
            .all()
        return jsonify([p.product_name for p in products])

    # Full search mode: return complete service records
    results = ServiceCatalog.query.filter_by(is_active=True)

    if query:
        results = results.filter(
            db.or_(
                ServiceCatalog.vendor.ilike(f'%{query}%'),
                ServiceCatalog.product_name.ilike(f'%{query}%'),
                ServiceCatalog.common_names.ilike(f'%{query}%'),
                ServiceCatalog.description.ilike(f'%{query}%')
            )
        )

    if category:
        results = results.filter_by(category=category)

    # Order by popularity
    results = results.order_by(
        ServiceCatalog.is_popular.desc(),
        ServiceCatalog.usage_frequency.desc()
    ).limit(limit)

    return jsonify([s.to_dict() for s in results.all()])

@bp.route('/api/catalog/categories', methods=['GET'])
@login_required
def get_categories():
    """Get all categories with counts"""
    categories = ServiceCatalog.query\
        .filter_by(is_active=True)\
        .with_entities(
            ServiceCatalog.category,
            func.count(ServiceCatalog.id).label('count')
        )\
        .group_by(ServiceCatalog.category)\
        .all()

    return jsonify([{'name': c.category, 'count': c.count} for c in categories])

@bp.route('/api/catalog/popular', methods=['GET'])
@login_required
def get_popular_services():
    """Get most popular services"""
    limit = request.args.get('limit', 20, type=int)
    services = ServiceCatalog.query.filter_by(is_active=True, is_popular=True)\
        .order_by(ServiceCatalog.usage_frequency.desc()).limit(limit).all()
    return jsonify([s.to_dict() for s in services])

@bp.route('/api/catalog/<int:catalog_id>/use', methods=['POST'])
@login_required
def increment_catalog_usage(catalog_id):
    """Increment usage frequency when a service is selected"""
    service = ServiceCatalog.query.get_or_404(catalog_id)
    service.usage_frequency += 1
    db.session.commit()
    return jsonify({'success': True})

# ============================================================================
# ORGANIZATION MANAGEMENT API ENDPOINTS
# ============================================================================

@bp.route('/api/organizations', methods=['GET'])
@login_required
def get_organizations():
    """Get organizations based on user permissions"""
    try:
        current_user_id = session.get('user_id')
        current_user = User.query.get(current_user_id)

        if not current_user:
            return jsonify({'error': 'User not found'}), 404

        # Super admins and users with can_view_all_orgs see all organizations
        if current_user.is_super_admin() or current_user.can_view_all_orgs:
            orgs = Organization.query.filter_by(active=True).order_by(Organization.display_name).all()
        else:
            # Regular users see all organizations they have access to (primary + multi-org memberships)
            org_ids = set()

            # Add primary organization
            if current_user.organization_id:
                org_ids.add(current_user.organization_id)

            # Add multi-org memberships
            for membership in current_user.org_memberships.all():
                org_ids.add(membership.organization_id)

            if org_ids:
                orgs = Organization.query.filter(
                    Organization.id.in_(org_ids),
                    Organization.active == True
                ).order_by(Organization.display_name).all()
            else:
                orgs = []

        return jsonify([o.to_dict() for o in orgs])
    except Exception as e:
        import logging
        logging.getLogger(__name__).error(f"Error in get_organizations: {str(e)}")
        return jsonify({'error': 'Failed to load organizations'}), 500

@bp.route('/api/organizations', methods=['POST'])
@admin_required
def create_organization():
    """Create a new organization"""
    # Check license limit for organizations
    allowed, limit, message = check_org_limit()
    if not allowed:
        return jsonify({'error': message, 'license_limit': True}), 403

    data = request.get_json()

    if not data.get('name') or not data.get('display_name'):
        return jsonify({'error': 'Name and display name are required'}), 400

    # Check if organization name already exists
    existing = Organization.query.filter_by(name=data['name']).first()
    if existing:
        return jsonify({'error': 'Organization name already exists'}), 400

    org = Organization(
        name=data['name'],
        display_name=data['display_name'],
        description=data.get('description'),
        notification_emails=json.dumps(data['notification_emails']) if isinstance(data.get('notification_emails'), list) else (data.get('notification_emails') or '[]'),
        alert_on_critical=data.get('alert_on_critical', True),
        alert_on_high=data.get('alert_on_high', False),
        alert_on_new_cve=data.get('alert_on_new_cve', True),
        alert_on_ransomware=data.get('alert_on_ransomware', True),
        alert_time_start=data.get('alert_time_start', '08:00'),
        alert_time_end=data.get('alert_time_end', '18:00'),
        alert_days=data.get('alert_days', 'mon,tue,wed,thu,fri'),
        active=data.get('active', True)
    )

    db.session.add(org)
    db.session.commit()

    return jsonify(org.to_dict()), 201

@bp.route('/api/organizations/<int:org_id>', methods=['GET'])
@login_required
def get_organization(org_id):
    """
    Get a specific organization

    Permissions:
    - Super Admin: Can view any organization
    - Org Admin/Manager/User: Can only view organizations they belong to
    """
    current_user_id = session.get('user_id')
    current_user = User.query.get(current_user_id)

    # Permission check: non-super admins can only view their own orgs
    if not current_user.is_super_admin():
        if not current_user.has_access_to_org(org_id):
            return jsonify({'error': 'You do not have access to this organization'}), 403

    org = Organization.query.get_or_404(org_id)
    return jsonify(org.to_dict())

@bp.route('/api/organizations/<int:org_id>', methods=['PUT'])
@org_admin_required
def update_organization(org_id):
    """
    Update an organization

    Permissions:
    - Super Admin: Can update any organization
    - Org Admin: Can update their own organization only
    """
    current_user_id = session.get('user_id')
    current_user = User.query.get(current_user_id)
    org = Organization.query.get_or_404(org_id)

    # Permission check: org admins can only edit their own org
    if not current_user.is_super_admin():
        if not current_user.is_org_admin_for(org_id):
            return jsonify({'error': 'You can only edit your own organization'}), 403

    data = request.get_json()

    if 'display_name' in data:
        org.display_name = data['display_name']
    if 'description' in data:
        org.description = data['description']
    if 'notification_emails' in data:
        emails = data['notification_emails']
        org.notification_emails = json.dumps(emails) if isinstance(emails, list) else (emails or '[]')
    if 'alert_on_critical' in data:
        org.alert_on_critical = data['alert_on_critical']
    if 'alert_on_high' in data:
        org.alert_on_high = data['alert_on_high']
    if 'alert_on_new_cve' in data:
        org.alert_on_new_cve = data['alert_on_new_cve']
    if 'alert_on_ransomware' in data:
        org.alert_on_ransomware = data['alert_on_ransomware']
    if 'alert_on_low_confidence' in data:
        org.alert_on_low_confidence = data['alert_on_low_confidence']
    if 'alert_time_start' in data:
        org.alert_time_start = data['alert_time_start']
    if 'alert_time_end' in data:
        org.alert_time_end = data['alert_time_end']
    if 'alert_days' in data:
        org.alert_days = data['alert_days']
    # Alert mode settings (null = use global default)
    if 'alert_mode' in data:
        mode = data['alert_mode']
        if mode in ['new_only', 'daily_reminder', 'escalation', None, '']:
            org.alert_mode = mode if mode else None  # Empty string becomes null (use default)
    if 'escalation_days' in data:
        days = data['escalation_days']
        org.escalation_days = int(days) if days else None  # Empty becomes null (use default)
    if 'active' in data:
        org.active = data['active']

    # SMTP settings
    if 'smtp_host' in data:
        org.smtp_host = data['smtp_host']
    if 'smtp_port' in data:
        org.smtp_port = data['smtp_port']
    if 'smtp_username' in data:
        org.smtp_username = data['smtp_username']
    # Only update password if provided (not null/empty) - encrypt it
    if 'smtp_password' in data and data['smtp_password']:
        from app.encryption import encrypt_value
        org.smtp_password = encrypt_value(data['smtp_password'])
    if 'smtp_use_tls' in data:
        org.smtp_use_tls = data['smtp_use_tls']
    if 'smtp_use_ssl' in data:
        org.smtp_use_ssl = data['smtp_use_ssl']
    if 'smtp_from_email' in data:
        org.smtp_from_email = data['smtp_from_email']
    if 'smtp_from_name' in data:
        org.smtp_from_name = data['smtp_from_name']

    # Webhook settings (requires Professional license for Email Alerts feature)
    webhook_fields = ['webhook_enabled', 'webhook_url', 'webhook_name', 'webhook_format', 'webhook_token']
    if any(field in data for field in webhook_fields):
        from app.licensing import get_license
        license_info = get_license()
        if not license_info.is_professional():
            return jsonify({
                'error': 'Organization webhooks require a Professional license',
                'license_required': True
            }), 403

    if 'webhook_enabled' in data:
        org.webhook_enabled = data['webhook_enabled']
    if 'webhook_url' in data:
        from app.encryption import encrypt_value
        # Encrypt webhook URL (may contain credentials)
        org.webhook_url = encrypt_value(data['webhook_url']) if data['webhook_url'] else None
    if 'webhook_name' in data:
        org.webhook_name = data['webhook_name'] if data['webhook_name'] else 'Organization Webhook'
    if 'webhook_format' in data:
        org.webhook_format = data['webhook_format'] if data['webhook_format'] else 'slack'
    # Allow clearing webhook_token by sending empty/null value
    if 'webhook_token' in data:
        from app.encryption import encrypt_value
        if data['webhook_token']:
            org.webhook_token = encrypt_value(data['webhook_token'])
        else:
            org.webhook_token = None  # Clear the token

    db.session.commit()

    return jsonify(org.to_dict())

@bp.route('/api/organizations/<int:org_id>', methods=['DELETE'])
@admin_required
def delete_organization(org_id):
    """Delete an organization"""
    org = Organization.query.get_or_404(org_id)

    # Check if organization has products
    product_count = Product.query.filter_by(organization_id=org_id).count()
    if product_count > 0:
        return jsonify({
            'error': f'Cannot delete organization with {product_count} products. Please reassign or delete products first.'
        }), 400

    db.session.delete(org)
    db.session.commit()
    return jsonify({'success': True})

@bp.route('/api/organizations/<int:org_id>/smtp/test', methods=['POST'])
@admin_required
def test_smtp(org_id):
    """Test SMTP connection for an organization by sending a test email"""
    import smtplib
    from email.mime.text import MIMEText
    from email.mime.multipart import MIMEMultipart
    from datetime import datetime

    org = Organization.query.get_or_404(org_id)
    smtp_config = org.get_smtp_config()

    if not smtp_config['host'] or not smtp_config['from_email']:
        return jsonify({'success': False, 'error': 'SMTP not configured'})

    # Get current user's email to send test to
    user_id = session.get('user_id')
    test_recipient = None
    if user_id:
        user = User.query.get(user_id)
        test_recipient = user.email if user else None

    if not test_recipient:
        return jsonify({'success': False, 'error': 'No email address found for current user'})

    try:
        # Create test email
        msg = MIMEMultipart()
        msg['From'] = f"{smtp_config['from_name']} <{smtp_config['from_email']}>"
        msg['To'] = test_recipient
        msg['Subject'] = f'SentriKat SMTP Test - {org.display_name}'

        body = f"""
<html>
<body style="font-family: Arial, sans-serif;">
    <h2 style="color: #1e40af;">✓ SMTP Configuration Test Successful</h2>
    <p>This is a test email from <strong>SentriKat</strong> for organization <strong>{org.display_name}</strong>.</p>

    <div style="background-color: #f3f4f6; padding: 15px; border-radius: 5px; margin: 20px 0;">
        <h3>SMTP Configuration Details:</h3>
        <ul>
            <li><strong>Organization:</strong> {org.display_name}</li>
            <li><strong>Server:</strong> {smtp_config['host']}:{smtp_config['port']}</li>
            <li><strong>From:</strong> {smtp_config['from_email']}</li>
            <li><strong>TLS Enabled:</strong> {'Yes' if smtp_config['use_tls'] else 'No'}</li>
            <li><strong>SSL Enabled:</strong> {'Yes' if smtp_config['use_ssl'] else 'No'}</li>
            <li><strong>Test Recipient:</strong> {test_recipient}</li>
        </ul>
    </div>

    <p>If you received this email, your organization's SMTP configuration is working correctly and SentriKat will be able to send vulnerability alerts.</p>

    <hr style="margin: 30px 0;">
    <p style="color: #6b7280; font-size: 12px;">
        This is an automated test email from SentriKat.<br>
        Sent at: {datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S')} UTC
    </p>
</body>
</html>
        """
        msg.attach(MIMEText(body, 'html'))

        # Send email
        if smtp_config['use_ssl']:
            server = smtplib.SMTP_SSL(smtp_config['host'], smtp_config['port'])
        else:
            server = smtplib.SMTP(smtp_config['host'], smtp_config['port'])
            if smtp_config['use_tls']:
                server.starttls()

        if smtp_config['username'] and smtp_config['password']:
            server.login(smtp_config['username'], smtp_config['password'])

        server.send_message(msg)
        server.quit()

        return jsonify({
            'success': True,
            'message': f'✓ Test email sent successfully to {test_recipient}'
        })

    except Exception as e:
        logger.exception("Failed to send test email")
        return jsonify({'success': False, 'error': ERROR_MSGS['smtp']})

@bp.route('/api/organizations/<int:org_id>/alert-logs', methods=['GET'])
@login_required
def get_alert_logs(org_id):
    """Get alert logs for an organization"""
    # Authorization: verify user can access this organization
    current_user_id = session.get('user_id')
    current_user = User.query.get(current_user_id)

    if not current_user.is_super_admin():
        # Check if user belongs to this organization
        user_org_ids = [org['id'] for org in current_user.get_all_organizations()]
        if org_id not in user_org_ids:
            return jsonify({'error': 'Insufficient permissions to view this organization\'s alert logs'}), 403

    limit = request.args.get('limit', 50, type=int)
    logs = AlertLog.query.filter_by(organization_id=org_id)\
        .order_by(AlertLog.sent_at.desc()).limit(limit).all()
    return jsonify([log.to_dict() for log in logs])

# ============================================================================
# USER MANAGEMENT & AUTHENTICATION API ENDPOINTS
# ============================================================================

@bp.route('/api/current-user', methods=['GET'])
@login_required
def get_current_user():
    """Get current logged-in user info for permission checks"""
    current_user_id = session.get('user_id')
    current_user = User.query.get(current_user_id)

    if not current_user:
        return jsonify({'error': 'User not found'}), 404

    user_dict = current_user.to_dict()

    # Add session-specific info (active organization may differ from primary)
    active_org_id = session.get('organization_id')
    active_org = Organization.query.get(active_org_id) if active_org_id else None
    user_dict['active_organization'] = {
        'id': active_org.id if active_org else None,
        'name': active_org.name if active_org else None,
        'display_name': active_org.display_name if active_org else None
    }
    user_dict['active_organization_id'] = active_org_id
    user_dict['role_in_active_org'] = current_user.get_role_for_org(active_org_id) if active_org_id else None

    # Add debug info to help troubleshoot permissions
    user_dict['debug'] = {
        'is_admin': current_user.is_admin,
        'role': current_user.role,
        'can_access_ldap': (current_user.role in ['org_admin', 'super_admin'] or current_user.is_admin == True)
    }
    return jsonify(user_dict)

@bp.route('/api/fix-admin-role', methods=['POST'])
@login_required
def fix_admin_role():
    """Temporary endpoint to fix legacy admin users - sets role to super_admin if is_admin=True"""
    current_user_id = session.get('user_id')
    current_user = User.query.get(current_user_id)

    if not current_user or not current_user.is_admin:
        return jsonify({'error': 'Only admin users can use this endpoint'}), 403

    # Update role to super_admin
    old_role = current_user.role
    current_user.role = 'super_admin'
    db.session.commit()

    return jsonify({
        'success': True,
        'message': 'Role updated successfully',
        'old_role': old_role,
        'new_role': 'super_admin'
    })

@bp.route('/api/users', methods=['GET'])
@org_admin_required
def get_users():
    """
    Get users based on permissions

    Permissions:
    - Super Admin: See all users
    - Org Admin: See only users in their organization
    """
    current_user_id = session.get('user_id')
    current_user = User.query.get(current_user_id)

    if not current_user:
        return jsonify({'error': 'Unauthorized'}), 401

    # Super admins see all users
    if current_user.is_super_admin():
        users = User.query.order_by(User.username).all()
    # Org admins see only their organization's users
    elif current_user.is_org_admin():
        users = User.query.filter_by(
            organization_id=current_user.organization_id
        ).order_by(User.username).all()
    else:
        return jsonify({'error': 'Insufficient permissions'}), 403

    return jsonify([u.to_dict() for u in users])

@bp.route('/api/users', methods=['POST'])
@org_admin_required
def create_user():
    """Create a new user (local auth only - LDAP users must be discovered/invited)"""
    # Check license limit for users
    allowed, limit, message = check_user_limit()
    if not allowed:
        return jsonify({'error': message, 'license_limit': True}), 403

    data = request.get_json()

    # Validate required fields
    if not data.get('username') or not data.get('email'):
        return jsonify({'error': 'Username and email are required'}), 400

    # Validate username format
    if not validate_username(data['username']):
        return jsonify({'error': 'Invalid username format. Use 3-50 alphanumeric characters, underscores, or dashes'}), 400

    # Validate email format
    if not validate_email(data['email']):
        return jsonify({'error': 'Invalid email format'}), 400

    # Prevent direct LDAP user creation - LDAP users should be discovered/invited
    auth_type = data.get('auth_type', 'local')
    if auth_type == 'ldap':
        return jsonify({'error': 'Cannot create LDAP users directly. Use LDAP discovery instead.'}), 400

    # Check if username or email already exists
    existing = User.query.filter(
        db.or_(User.username == data['username'], User.email == data['email'])
    ).first()
    if existing:
        return jsonify({'error': 'Username or email already exists'}), 400

    # Require password for local users
    if not data.get('password'):
        return jsonify({'error': 'Password is required for local users'}), 400

    # Validate password strength
    is_valid, error_msg = validate_password_strength(data['password'])
    if not is_valid:
        return jsonify({'error': error_msg}), 400

    # Validate role
    valid_roles = ['user', 'manager', 'org_admin', 'super_admin']
    role = data.get('role', 'user')
    if role not in valid_roles:
        return jsonify({'error': f'Invalid role. Must be one of: {", ".join(valid_roles)}'}), 400

    # Authorization: org_admins can only create users in their own organization
    current_user_id = session.get('user_id')
    current_user = User.query.get(current_user_id)
    target_org_id = data.get('organization_id')

    if not current_user.is_super_admin():
        # Org admins cannot create super_admin or org_admin users
        if role in ['super_admin', 'org_admin']:
            return jsonify({'error': 'Only super admins can create admin users'}), 403

        # Org admins can only create users in their own organization
        if target_org_id:
            user_org_ids = [org['id'] for org in current_user.get_all_organizations()]
            if target_org_id not in user_org_ids:
                return jsonify({'error': 'Cannot create users in other organizations'}), 403

    # Derive is_admin from role (don't allow client to set directly - privilege escalation)
    derived_is_admin = role in ('super_admin', 'org_admin')

    # Non-super-admins cannot grant can_view_all_orgs
    can_view_all = data.get('can_view_all_orgs', False) if current_user.is_super_admin() else False

    user = User(
        username=data['username'],
        email=data['email'],
        full_name=(data.get('full_name') or '')[:100],  # Limit length, handle null
        organization_id=target_org_id,
        auth_type='local',  # Force local auth for created users
        role=role,
        is_admin=derived_is_admin,
        is_active=data.get('is_active', True),
        can_manage_products=data.get('can_manage_products', True),
        can_view_all_orgs=can_view_all
    )

    # Set password for local auth
    user.set_password(data['password'])

    db.session.add(user)
    db.session.commit()

    return jsonify(user.to_dict()), 201

@bp.route('/api/users/<int:user_id>', methods=['GET'])
@org_admin_required
def get_user(user_id):
    """Get a specific user"""
    current_user_id = session.get('user_id')
    current_user = User.query.get(current_user_id)
    user = User.query.get_or_404(user_id)

    # Permission check: can this user view this user's details?
    if not current_user.can_manage_user(user) and user_id != current_user_id:
        return jsonify({'error': 'Insufficient permissions to view this user'}), 403

    return jsonify(user.to_dict())

@bp.route('/api/users/<int:user_id>', methods=['PUT'])
@org_admin_required
def update_user(user_id):
    """
    Update a user

    Permissions:
    - Super Admin: Can update any user
    - Org Admin: Can only update users in their organization (except super admins)
    """
    from app.logging_config import log_audit_event

    current_user_id = session.get('user_id')
    current_user = User.query.get(current_user_id)
    user = User.query.get_or_404(user_id)

    # Check permissions (self-modification is always allowed for admins)
    is_self_edit = user_id == current_user_id
    if not is_self_edit and not current_user.can_manage_user(user):
        return jsonify({'error': 'Insufficient permissions to manage this user'}), 403

    data = request.get_json()
    old_role = user.role
    old_org_id = user.organization_id
    warnings = []

    # Username update (only for super admins and must be unique)
    if 'username' in data and data['username'] != user.username:
        if not current_user.is_super_admin():
            return jsonify({'error': 'Only super admins can change usernames'}), 403
        # Check if new username is already taken
        existing = User.query.filter_by(username=data['username']).first()
        if existing and existing.id != user_id:
            return jsonify({'error': 'Username already exists'}), 400
        user.username = data['username']

    if 'email' in data and data['email'] != user.email:
        # Validate email format
        if not validate_email(data['email']):
            return jsonify({'error': 'Invalid email format'}), 400
        # Check for duplicate email
        existing = User.query.filter_by(email=data['email']).first()
        if existing and existing.id != user_id:
            return jsonify({'error': 'Email already exists'}), 400
        user.email = data['email']
    if 'full_name' in data:
        user.full_name = data['full_name']

    # Organization assignment
    if 'organization_id' in data:
        # Org admins can only assign to their own organization
        if current_user.role == 'org_admin' and data['organization_id'] != current_user.organization_id:
            return jsonify({'error': 'Org admins can only assign users to their own organization'}), 403
        user.organization_id = data['organization_id']

    # Role changes
    if 'role' in data:
        new_role = data['role']

        # Prevent demoting the last super_admin
        if old_role == 'super_admin' and new_role != 'super_admin':
            super_admin_count = User.query.filter_by(role='super_admin', is_active=True).count()
            if super_admin_count <= 1 and user.role == 'super_admin':
                return jsonify({'error': 'Cannot demote the last super admin. Create another super admin first.'}), 400

        # Only super admins can create/modify super_admins
        if new_role == 'super_admin' and not current_user.is_super_admin():
            return jsonify({'error': 'Only super admins can create super admin users'}), 403

        # Non-super-admins cannot set org_admin or super_admin roles (except for themselves - they can demote)
        if not current_user.is_super_admin() and new_role in ['super_admin', 'org_admin']:
            if not is_self_edit:  # Org admins can demote themselves but not promote others
                return jsonify({'error': 'Org admins cannot create admin users'}), 403

        # Self-demotion warning
        if is_self_edit and old_role == 'super_admin' and new_role != 'super_admin':
            warnings.append(f'You have demoted yourself from super_admin to {new_role}. You may lose access to some admin features.')

        user.role = new_role

    if 'is_admin' in data:
        # Derive is_admin from role to prevent privilege escalation
        # (org_admin cannot grant is_admin=True to arbitrary users)
        user.is_admin = user.role in ('super_admin', 'org_admin')
    if 'is_active' in data:
        user.is_active = data['is_active']
    if 'can_manage_products' in data:
        user.can_manage_products = data['can_manage_products']

    # Only super admins can modify can_view_all_orgs
    if 'can_view_all_orgs' in data and current_user.is_super_admin():
        user.can_view_all_orgs = data['can_view_all_orgs']

    # Update password if provided (with validation for local users)
    if 'password' in data and user.auth_type == 'local':
        is_valid, error_msg = validate_password_strength(data['password'])
        if not is_valid:
            return jsonify({'error': error_msg}), 400
        user.set_password(data['password'])

    db.session.commit()

    # Log audit event if role changed
    if old_role != user.role:
        log_audit_event(
            'ROLE_CHANGE',
            'users',
            user.id,
            old_value={'role': old_role},
            new_value={'role': user.role},
            details=f"Role changed from {old_role} to {user.role} by {current_user.username}"
        )

        # Send email notification for role change
        try:
            from app.email_alerts import send_role_change_email
            send_role_change_email(user, old_role, user.role, current_user.username)
        except Exception as e:
            import logging
            logging.getLogger(__name__).warning(f"Failed to send role change email: {e}")

    result = user.to_dict()
    if warnings:
        result['warnings'] = warnings

    return jsonify(result)

@bp.route('/api/users/<int:user_id>', methods=['DELETE'])
@org_admin_required
def delete_user(user_id):
    """
    Permanently delete a user from the system.

    Permissions:
    - Super Admin: Can delete any user
    - Org Admin: Can only delete users in their organization (except super admins)

    Note: This is a PERMANENT deletion. Use toggle-active endpoint for blocking/unblocking.
    """
    from app.models import UserOrganization
    from app.logging_config import log_audit_event

    current_user_id = session.get('user_id')
    current_user = User.query.get(current_user_id)
    user = User.query.get_or_404(user_id)

    # Cannot delete yourself
    if user_id == current_user_id:
        return jsonify({'error': 'Cannot delete your own account'}), 400

    # Cannot delete super admins (only other super admins can, with confirmation)
    if user.is_super_admin() and not current_user.is_super_admin():
        return jsonify({'error': 'Only super admins can delete other super admins'}), 403

    # Check permissions
    if not current_user.can_manage_user(user):
        return jsonify({'error': 'Insufficient permissions to delete this user'}), 403

    # Store user info for audit log before deletion
    deleted_username = user.username
    deleted_email = user.email
    deleted_role = user.role

    try:
        # Delete organization memberships first
        UserOrganization.query.filter_by(user_id=user_id).delete()

        # Delete the user
        db.session.delete(user)
        db.session.commit()

        # Log audit event
        log_audit_event(
            'USER_DELETE',
            'users',
            user_id,
            old_value={'username': deleted_username, 'email': deleted_email, 'role': deleted_role},
            details=f"Permanently deleted user {deleted_username}"
        )

        return jsonify({'success': True, 'message': f'User {deleted_username} permanently deleted'})

    except Exception as e:
        db.session.rollback()
        logger.exception(f"Failed to delete user {user_id}")
        return jsonify({'error': ERROR_MSGS['database']}), 500

@bp.route('/api/users/<int:user_id>/toggle-active', methods=['POST'])
@org_admin_required
def toggle_user_active(user_id):
    """
    Toggle user active status (block/unblock)

    Permissions:
    - Super Admin: Can toggle any user
    - Org Admin: Can only toggle users in their organization (except super admins)
    """
    from app.logging_config import log_audit_event
    from app.email_alerts import send_user_status_email

    current_user_id = session.get('user_id')
    current_user = User.query.get(current_user_id)
    user = User.query.get_or_404(user_id)

    # Cannot toggle yourself
    if user_id == current_user_id:
        return jsonify({'error': 'Cannot block/unblock your own account'}), 400

    # Check permissions
    if not current_user.can_manage_user(user):
        return jsonify({'error': 'Insufficient permissions to modify this user'}), 403

    old_status = user.is_active
    user.is_active = not user.is_active
    is_blocked = not user.is_active
    action = 'unblocked' if user.is_active else 'blocked'

    # Log the action
    log_audit_event(
        'BLOCK' if is_blocked else 'UNBLOCK',
        'users',
        user.id,
        old_value={'is_active': old_status},
        new_value={'is_active': user.is_active},
        details=f"User {user.username} {action} by {current_user.username}"
    )

    db.session.commit()

    # Send email notification to the user
    email_sent = False
    email_details = None
    try:
        email_sent, email_details = send_user_status_email(user, is_blocked, current_user.username)
    except Exception as e:
        email_details = str(e)
        import logging
        logging.getLogger(__name__).warning(f"Failed to send status email: {e}")

    message = f'User {user.username} has been {action}'
    if email_sent:
        message += f' ({email_details})'
    elif email_details:
        message += f' (email failed: {email_details})'

    return jsonify({
        'success': True,
        'is_active': user.is_active,
        'message': message,
        'email_sent': email_sent
    })

@bp.route('/api/users/<int:user_id>/unlock', methods=['POST'])
@org_admin_required
def unlock_user(user_id):
    """
    Unlock a user account that was locked due to failed login attempts.

    Permissions:
    - Super Admin: Can unlock any user
    - Org Admin: Can only unlock users in their organization
    """
    from app.logging_config import log_audit_event

    current_user_id = session.get('user_id')
    current_user = User.query.get(current_user_id)
    user = User.query.get_or_404(user_id)

    # Check permissions
    if not current_user.can_manage_user(user):
        return jsonify({'error': 'Insufficient permissions to unlock this user'}), 403

    # Check if actually locked
    if not user.is_locked():
        return jsonify({'error': 'User account is not locked'}), 400

    # Store old values for audit
    old_attempts = user.failed_login_attempts
    old_locked_until = user.locked_until.isoformat() if user.locked_until else None

    # Reset lockout
    user.reset_failed_login_attempts()

    # Log the action
    log_audit_event(
        'UNLOCK',
        'users',
        user.id,
        old_value={'failed_login_attempts': old_attempts, 'locked_until': old_locked_until},
        new_value={'failed_login_attempts': 0, 'locked_until': None},
        details=f"User {user.username} unlocked by {current_user.username}"
    )

    db.session.commit()

    return jsonify({
        'success': True,
        'message': f'User {user.username} has been unlocked'
    })

@bp.route('/api/users/<int:user_id>/reset-2fa', methods=['POST'])
@org_admin_required
def reset_user_2fa(user_id):
    """
    Reset a user's 2FA (disable it) when they lose access to their authenticator.

    Permissions:
    - Super Admin: Can reset any user's 2FA
    - Org Admin: Can only reset 2FA for users in their organization
    """
    from app.logging_config import log_audit_event
    import logging
    logger = logging.getLogger('security')

    current_user_id = session.get('user_id')
    current_user = User.query.get(current_user_id)
    user = User.query.get_or_404(user_id)

    # Cannot reset your own 2FA through admin panel
    if user_id == current_user_id:
        return jsonify({'error': 'Cannot reset your own 2FA through admin panel. Use Security Settings instead.'}), 400

    # Check permissions
    if not current_user.can_manage_user(user):
        return jsonify({'error': 'Insufficient permissions to reset 2FA for this user'}), 403

    # Check if 2FA is enabled
    if not user.totp_enabled:
        return jsonify({'error': 'User does not have 2FA enabled'}), 400

    # Disable 2FA
    user.disable_totp()

    # Log the action
    log_audit_event(
        'RESET_2FA',
        'users',
        user.id,
        old_value={'totp_enabled': True},
        new_value={'totp_enabled': False},
        details=f"2FA reset for {user.username} by {current_user.username}"
    )

    logger.warning(f"2FA reset for user {user.username} (id={user.id}) by admin {current_user.username}")

    db.session.commit()

    # Send email notification
    email_sent = False
    email_details = None
    try:
        from app.email_alerts import send_2fa_reset_email
        email_sent, email_details = send_2fa_reset_email(user, current_user.username)
    except Exception as e:
        email_details = str(e)
        logger.warning(f"Failed to send 2FA reset email: {e}")

    message = f'Two-factor authentication has been reset for {user.username}. They will need to set it up again.'
    if email_sent:
        message += ' (notification email sent)'
    elif email_details:
        message += f' (email failed: {email_details})'

    return jsonify({
        'success': True,
        'message': message,
        'email_sent': email_sent
    })

@bp.route('/api/users/<int:user_id>/force-password-change', methods=['POST'])
@org_admin_required
def force_password_change(user_id):
    """
    Force a user to change their password on next login.

    Permissions:
    - Super Admin: Can force any user
    - Org Admin: Can only force users in their organization
    """
    from app.logging_config import log_audit_event

    current_user_id = session.get('user_id')
    current_user = User.query.get(current_user_id)
    user = User.query.get_or_404(user_id)

    # Cannot force your own password change
    if user_id == current_user_id:
        return jsonify({'error': 'Cannot force password change on your own account. Use Security Settings instead.'}), 400

    # Check permissions
    if not current_user.can_manage_user(user):
        return jsonify({'error': 'Insufficient permissions'}), 403

    # Only for local users
    if user.auth_type != 'local':
        return jsonify({'error': 'Password changes only apply to local users'}), 400

    # Set flag
    user.must_change_password = True

    log_audit_event(
        'FORCE_PASSWORD_CHANGE',
        'users',
        user.id,
        details=f"Password change forced for {user.username} by {current_user.username}"
    )

    db.session.commit()

    # Send email notification
    email_sent = False
    email_details = None
    try:
        from app.email_alerts import send_password_change_forced_email
        email_sent, email_details = send_password_change_forced_email(user, current_user.username)
    except Exception as e:
        email_details = str(e)
        import logging
        logging.getLogger(__name__).warning(f"Failed to send password change email: {e}")

    message = f'{user.username} will be required to change their password on next login'
    if email_sent:
        message += ' (notification email sent)'
    elif email_details:
        message += f' (email failed: {email_details})'

    return jsonify({
        'success': True,
        'message': message,
        'email_sent': email_sent
    })


@bp.route('/api/users/<int:user_id>/require-2fa', methods=['POST'])
@org_admin_required
def require_2fa_for_user(user_id):
    """
    Require a user to set up 2FA on next login.

    Permissions:
    - Super Admin: Can require for any user
    - Org Admin: Can only require for users in their organization
    """
    from app.logging_config import log_audit_event

    current_user_id = session.get('user_id')
    current_user = User.query.get(current_user_id)
    user = User.query.get_or_404(user_id)

    # Cannot require 2FA for yourself via this endpoint
    if user_id == current_user_id:
        return jsonify({'error': 'Use Security Settings to manage your own 2FA'}), 400

    # Check permissions
    if not current_user.can_manage_user(user):
        return jsonify({'error': 'Insufficient permissions'}), 403

    # Only for local users
    if user.auth_type != 'local':
        return jsonify({'error': '2FA management only applies to local users'}), 400

    # If already enabled, nothing to do
    if user.totp_enabled:
        return jsonify({'error': 'User already has 2FA enabled'}), 400

    # Set the totp_required flag (user must set up 2FA on next login)
    user.totp_required = True

    log_audit_event(
        'REQUIRE_2FA',
        'users',
        user.id,
        details=f"2FA required for {user.username} by {current_user.username}"
    )

    db.session.commit()

    return jsonify({
        'success': True,
        'message': f'{user.username} will be required to set up 2FA on next login'
    })


# ============================================================================
# USER ORGANIZATION ASSIGNMENTS (Multi-Org Support)
# ============================================================================

@bp.route('/api/users/<int:user_id>/organizations', methods=['GET'])
@login_required
def get_user_organizations(user_id):
    """Get all organization assignments for a user"""
    from app.models import UserOrganization

    current_user_id = session.get('user_id')
    current_user = User.query.get(current_user_id)
    target_user = User.query.get_or_404(user_id)

    # Permission check: super admin or org admin for one of the user's orgs
    if not current_user.is_super_admin():
        # Org admins can view users in their org
        if not current_user.can_manage_user(target_user):
            return jsonify({'error': 'Insufficient permissions'}), 403

    # Get all org memberships
    memberships = target_user.org_memberships.all()

    # Include primary org if not in memberships
    result = []
    primary_org_id = target_user.organization_id

    if primary_org_id and target_user.organization:
        result.append({
            'id': None,  # No membership ID for legacy org
            'organization_id': primary_org_id,
            'organization_name': target_user.organization.display_name,
            'role': target_user.role,
            'is_primary': True,
            'assigned_at': target_user.created_at.isoformat() if target_user.created_at else None
        })

    for m in memberships:
        if m.organization_id != primary_org_id:
            result.append({
                'id': m.id,
                'organization_id': m.organization_id,
                'organization_name': m.organization.display_name if m.organization else None,
                'role': m.role,
                'is_primary': False,
                'assigned_at': m.assigned_at.isoformat() if m.assigned_at else None,
                'assigned_by': m.assigner.username if m.assigner else None
            })

    return jsonify(result)


@bp.route('/api/users/<int:user_id>/organizations', methods=['POST'])
@login_required
def add_user_organization(user_id):
    """Add a user to an organization with a specific role"""
    from app.models import UserOrganization
    from app.logging_config import log_audit_event

    current_user_id = session.get('user_id')
    current_user = User.query.get(current_user_id)
    target_user = User.query.get_or_404(user_id)

    data = request.get_json()
    org_id = data.get('organization_id')
    role = data.get('role', 'user')

    if not org_id:
        return jsonify({'error': 'organization_id is required'}), 400

    # Validate role
    valid_roles = ['user', 'manager', 'org_admin']
    if current_user.is_super_admin():
        valid_roles.append('super_admin')

    if role not in valid_roles:
        return jsonify({'error': f'Invalid role. Must be one of: {", ".join(valid_roles)}'}), 400

    # Permission checks
    if current_user.is_super_admin():
        # Super admins can assign anyone to any org
        pass
    elif current_user.is_org_admin_for(org_id):
        # Org admins can only assign to their own org
        if role in ['super_admin']:
            return jsonify({'error': 'Only super admins can assign super_admin role'}), 403
    else:
        return jsonify({'error': 'Insufficient permissions'}), 403

    # Check if org exists
    org = Organization.query.get(org_id)
    if not org:
        return jsonify({'error': 'Organization not found'}), 404

    # Add user to organization
    target_user.add_to_organization(org_id, role, current_user_id)
    db.session.commit()

    # Log audit event
    log_audit_event(
        'ADD_ORG_MEMBERSHIP',
        'users',
        user_id,
        new_value={'organization_id': org_id, 'role': role},
        details=f"Added {target_user.username} to {org.display_name} as {role}"
    )

    return jsonify({
        'success': True,
        'message': f'User {target_user.username} added to {org.display_name} as {role}'
    })


@bp.route('/api/users/<int:user_id>/organizations/<int:org_id>', methods=['PUT'])
@login_required
def update_user_organization_role(user_id, org_id):
    """Update a user's role in an organization"""
    from app.models import UserOrganization
    from app.logging_config import log_audit_event

    current_user_id = session.get('user_id')
    current_user = User.query.get(current_user_id)
    target_user = User.query.get_or_404(user_id)

    data = request.get_json()
    new_role = data.get('role')

    if not new_role:
        return jsonify({'error': 'role is required'}), 400

    # Validate role
    valid_roles = ['user', 'manager', 'org_admin']
    if current_user.is_super_admin():
        valid_roles.append('super_admin')

    if new_role not in valid_roles:
        return jsonify({'error': f'Invalid role. Must be one of: {", ".join(valid_roles)}'}), 400

    # Permission checks
    if not current_user.is_super_admin() and not current_user.is_org_admin_for(org_id):
        return jsonify({'error': 'Insufficient permissions'}), 403

    if new_role == 'super_admin' and not current_user.is_super_admin():
        return jsonify({'error': 'Only super admins can assign super_admin role'}), 403

    # Check if this is the primary org
    if target_user.organization_id == org_id:
        # Update the user's main role
        old_role = target_user.role
        target_user.role = new_role
        db.session.commit()

        log_audit_event(
            'UPDATE_ROLE',
            'users',
            user_id,
            old_value={'role': old_role},
            new_value={'role': new_role},
            details=f"Updated {target_user.username}'s role to {new_role} in primary org"
        )
    else:
        # Update membership role
        membership = target_user.org_memberships.filter_by(organization_id=org_id).first()
        if not membership:
            return jsonify({'error': 'User is not a member of this organization'}), 404

        old_role = membership.role
        membership.role = new_role
        membership.assigned_by = current_user_id
        db.session.commit()

        log_audit_event(
            'UPDATE_ORG_ROLE',
            'users',
            user_id,
            old_value={'organization_id': org_id, 'role': old_role},
            new_value={'organization_id': org_id, 'role': new_role},
            details=f"Updated {target_user.username}'s role to {new_role}"
        )

    org = Organization.query.get(org_id)
    return jsonify({
        'success': True,
        'message': f'Role updated to {new_role} for {org.display_name if org else "organization"}'
    })


@bp.route('/api/users/<int:user_id>/organizations/<int:org_id>', methods=['DELETE'])
@login_required
def remove_user_organization(user_id, org_id):
    """Remove a user from an organization"""
    from app.models import UserOrganization
    from app.logging_config import log_audit_event

    current_user_id = session.get('user_id')
    current_user = User.query.get(current_user_id)
    target_user = User.query.get_or_404(user_id)

    # Permission checks
    if not current_user.is_super_admin() and not current_user.is_org_admin_for(org_id):
        return jsonify({'error': 'Insufficient permissions'}), 403

    # Cannot remove from primary org this way
    if target_user.organization_id == org_id:
        return jsonify({'error': 'Cannot remove user from their primary organization. Change primary org first or delete user.'}), 400

    # Remove membership
    membership = target_user.org_memberships.filter_by(organization_id=org_id).first()
    if not membership:
        return jsonify({'error': 'User is not a member of this organization'}), 404

    org = Organization.query.get(org_id)
    old_role = membership.role

    db.session.delete(membership)
    db.session.commit()

    log_audit_event(
        'REMOVE_ORG_MEMBERSHIP',
        'users',
        user_id,
        old_value={'organization_id': org_id, 'role': old_role},
        details=f"Removed {target_user.username} from {org.display_name if org else 'organization'}"
    )

    return jsonify({
        'success': True,
        'message': f'User removed from {org.display_name if org else "organization"}'
    })


# ============================================================================
# DEBUG & DIAGNOSTICS
# ============================================================================

@bp.route('/api/debug/auth-status', methods=['GET'])
@login_required
def debug_auth_status():
    """Debug endpoint to check authentication status"""
    import os
    # Match auth.py: auth is ON by default, only disabled with DISABLE_AUTH=true
    auth_enabled = os.environ.get('DISABLE_AUTH', 'false').lower() != 'true'

    user_info = None
    if 'user_id' in session:
        user = User.query.get(session['user_id'])
        if user:
            user_info = {
                'id': user.id,
                'username': user.username,
                'email': user.email,
                'is_admin': user.is_admin,
                'auth_type': user.auth_type,
                'organization_id': user.organization_id
            }

    return jsonify({
        'auth_enabled': auth_enabled,
        'logged_in': 'user_id' in session,
        'user': user_info,
        'admin_menu_visible': not auth_enabled or (user_info and user_info['is_admin'])
    })

# ============================================================================
# AUDIT LOGS API
# ============================================================================

@bp.route('/api/audit-logs', methods=['GET'])
@admin_required
def get_audit_logs():
    """
    Get audit logs from the audit.log file
    Only accessible by super admins

    Query params:
    - page: Page number (default: 1)
    - per_page: Items per page (default: 50, max: 500)
    - action: Filter by action type (CREATE, UPDATE, DELETE, etc.)
    - resource: Filter by resource type (users, products, etc.)
    - user_id: Filter by user ID
    - search: Text search in message/details
    - start_date: Filter from date (ISO format)
    - end_date: Filter to date (ISO format)
    - sort: Sort field (timestamp, action, resource, user_id)
    - order: Sort order (asc, desc - default: desc)
    """
    import os
    import json
    from datetime import datetime

    current_user_id = session.get('user_id')
    current_user = User.query.get(current_user_id)

    # Only super admins can view audit logs
    if not current_user or not current_user.is_super_admin():
        return jsonify({'error': 'Only super admins can view audit logs'}), 403

    # Get query parameters
    page = request.args.get('page', 1, type=int)
    per_page = min(request.args.get('per_page', 50, type=int), 500)
    action_filter = request.args.get('action')
    resource_filter = request.args.get('resource')
    user_filter = request.args.get('user_id')
    search_query = request.args.get('search', '').lower()
    start_date = request.args.get('start_date')
    end_date = request.args.get('end_date')
    sort_field = request.args.get('sort', 'timestamp')
    sort_order = request.args.get('order', 'desc')

    # Find the audit log file
    log_dir = os.environ.get('LOG_DIR', '/var/log/sentrikat')
    if not os.path.exists(log_dir):
        log_dir = os.path.join(os.path.dirname(os.path.dirname(__file__)), 'logs')

    audit_log_path = os.path.join(log_dir, 'audit.log')

    if not os.path.exists(audit_log_path):
        return jsonify({
            'logs': [],
            'total': 0,
            'page': page,
            'per_page': per_page,
            'total_pages': 0,
            'message': 'No audit logs found'
        })

    all_logs = []
    try:
        # Read all logs and filter
        with open(audit_log_path, 'r', encoding='utf-8') as f:
            for line in f:
                if not line.strip():
                    continue
                try:
                    log_entry = json.loads(line.strip())

                    # Apply filters
                    if action_filter and log_entry.get('action') != action_filter:
                        continue
                    if resource_filter:
                        resource = log_entry.get('resource', '')
                        # Handle resource:id format
                        base_resource = resource.split(':')[0] if ':' in resource else resource
                        if base_resource != resource_filter:
                            continue
                    if user_filter and str(log_entry.get('user_id')) != str(user_filter):
                        continue

                    # Text search
                    if search_query:
                        searchable = json.dumps(log_entry).lower()
                        if search_query not in searchable:
                            continue

                    # Date range filtering
                    log_timestamp = log_entry.get('timestamp', '')
                    if start_date:
                        if log_timestamp < start_date:
                            continue
                    if end_date:
                        if log_timestamp > end_date + 'T23:59:59Z':
                            continue

                    all_logs.append(log_entry)

                except json.JSONDecodeError:
                    continue

        # Sort logs
        reverse_sort = (sort_order == 'desc')
        if sort_field in ['timestamp', 'action', 'resource', 'user_id']:
            all_logs.sort(key=lambda x: x.get(sort_field, ''), reverse=reverse_sort)
        else:
            # Default: sort by timestamp descending (most recent first)
            all_logs.sort(key=lambda x: x.get('timestamp', ''), reverse=True)

        # Calculate pagination
        total = len(all_logs)
        total_pages = (total + per_page - 1) // per_page
        start_idx = (page - 1) * per_page
        end_idx = start_idx + per_page
        paginated_logs = all_logs[start_idx:end_idx]

    except Exception as e:
        logger.exception("Failed to read audit logs")
        return jsonify({'error': ERROR_MSGS['internal']}), 500

    return jsonify({
        'logs': paginated_logs,
        'total': total,
        'page': page,
        'per_page': per_page,
        'total_pages': total_pages
    })

@bp.route('/api/audit-logs/export', methods=['GET'])
@admin_required
@requires_professional('Audit Export')
def export_audit_logs():
    """
    Export audit logs as CSV or JSON file
    Only accessible by super admins

    Query params:
    - format: 'csv' or 'json' (default: csv)
    - days: Number of days to include (default: 30)
    - action: Filter by action type
    - resource: Filter by resource type
    """
    import os
    import json
    import io
    import csv
    from datetime import datetime, timedelta
    from flask import Response

    current_user_id = session.get('user_id')
    current_user = User.query.get(current_user_id)

    # Only super admins can export audit logs
    if not current_user or not current_user.is_super_admin():
        return jsonify({'error': 'Only super admins can export audit logs'}), 403

    # Get query parameters
    export_format = request.args.get('format', 'csv').lower()
    days = request.args.get('days', 30, type=int)
    action_filter = request.args.get('action')
    resource_filter = request.args.get('resource')

    if export_format not in ['csv', 'json']:
        return jsonify({'error': 'Invalid format. Use csv or json'}), 400

    # Calculate date cutoff
    cutoff_date = datetime.utcnow() - timedelta(days=days)
    cutoff_str = cutoff_date.isoformat()

    # Find the audit log file
    log_dir = os.environ.get('LOG_DIR', '/var/log/sentrikat')
    if not os.path.exists(log_dir):
        log_dir = os.path.join(os.path.dirname(os.path.dirname(__file__)), 'logs')

    audit_log_path = os.path.join(log_dir, 'audit.log')

    if not os.path.exists(audit_log_path):
        return jsonify({'error': 'No audit logs found'}), 404

    logs = []
    try:
        with open(audit_log_path, 'r', encoding='utf-8') as f:
            for line in f:
                if not line.strip():
                    continue
                try:
                    log_entry = json.loads(line.strip())

                    # Apply date filter
                    log_time = log_entry.get('timestamp', '')
                    if log_time < cutoff_str:
                        continue

                    # Apply filters
                    if action_filter and log_entry.get('action') != action_filter:
                        continue
                    if resource_filter and not log_entry.get('resource', '').startswith(resource_filter):
                        continue

                    logs.append(log_entry)

                except json.JSONDecodeError:
                    continue

    except Exception as e:
        logger.exception("Failed to read audit logs for export")
        return jsonify({'error': ERROR_MSGS['internal']}), 500

    # Sort by timestamp descending (most recent first)
    logs.sort(key=lambda x: x.get('timestamp', ''), reverse=True)

    # Generate filename
    timestamp = datetime.utcnow().strftime('%Y%m%d_%H%M%S')
    filename = f'audit_logs_{timestamp}.{export_format}'

    if export_format == 'json':
        # Export as JSON
        output = json.dumps(logs, indent=2)
        mimetype = 'application/json'
    else:
        # Export as CSV
        output = io.StringIO()
        if logs:
            # Determine all possible fields from logs
            fieldnames = ['timestamp', 'action', 'resource', 'resource_id', 'user_id', 'username', 'ip_address', 'details']
            writer = csv.DictWriter(output, fieldnames=fieldnames, extrasaction='ignore')
            writer.writeheader()
            for log in logs:
                # Flatten any nested objects in details
                if 'details' in log and isinstance(log['details'], dict):
                    log['details'] = json.dumps(log['details'])
                writer.writerow(log)
        output = output.getvalue()
        mimetype = 'text/csv'

    return Response(
        output,
        mimetype=mimetype,
        headers={'Content-Disposition': f'attachment; filename={filename}'}
    )

# ============================================================================
# CVE SERVICE STATUS CHECK
# ============================================================================

@bp.route('/api/cve-service/status', methods=['GET'])
@login_required
def check_cve_service_status():
    """
    Check if the CVE/NVD service is accessible
    Returns status of connection to NIST NVD API
    """
    import requests
    from config import Config
    import urllib3

    try:
        proxies = Config.get_proxies()
        verify_ssl = Config.get_verify_ssl()

        if not verify_ssl:
            urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

        # Try to reach the NVD API
        response = requests.get(
            'https://services.nvd.nist.gov/rest/json/cves/2.0',
            params={'resultsPerPage': 1},
            timeout=10,
            proxies=proxies,
            verify=verify_ssl
        )

        if response.status_code == 200:
            return jsonify({
                'status': 'online',
                'message': 'NVD service is accessible',
                'response_code': response.status_code
            })
        elif response.status_code == 403:
            return jsonify({
                'status': 'rate_limited',
                'message': 'NVD API rate limited',
                'response_code': response.status_code
            })
        else:
            return jsonify({
                'status': 'error',
                'message': f'NVD returned status {response.status_code}',
                'response_code': response.status_code
            })

    except requests.exceptions.Timeout:
        return jsonify({
            'status': 'timeout',
            'message': 'Connection to NVD timed out'
        })
    except requests.exceptions.ConnectionError as e:
        return jsonify({
            'status': 'offline',
            'message': 'Cannot connect to NVD service'
        })
    except Exception as e:
        return jsonify({
            'status': 'error',
            'message': str(e)
        })

# ============================================================================
# REPORTS API
# ============================================================================

@bp.route('/api/reports/monthly', methods=['GET'])
@login_required
def generate_monthly_report():
    """
    Generate a monthly vulnerability report PDF

    Query parameters:
        year: Report year (default: current year)
        month: Report month (default: current month)
    """
    from flask import make_response
    from app.reports import VulnerabilityReportGenerator
    from datetime import datetime

    try:
        year = request.args.get('year', type=int, default=datetime.now().year)
        month = request.args.get('month', type=int, default=datetime.now().month)

        # Validate month
        if month < 1 or month > 12:
            return jsonify({'error': 'Invalid month'}), 400

        # Get organization from session
        org_id = session.get('organization_id')
        current_user_id = session.get('user_id')
        current_user = User.query.get(current_user_id)

        # Non-super admins can only see their organization
        if current_user and not current_user.is_super_admin() and not current_user.can_view_all_orgs:
            org_id = current_user.organization_id

        # Generate report
        generator = VulnerabilityReportGenerator(organization_id=org_id)
        pdf_buffer = generator.generate_monthly_report(year=year, month=month)

        # Create response
        month_name = datetime(year, month, 1).strftime('%B_%Y')
        filename = f"SentriKat_Vulnerability_Report_{month_name}.pdf"

        response = make_response(pdf_buffer.getvalue())
        response.headers['Content-Type'] = 'application/pdf'
        response.headers['Content-Disposition'] = f'attachment; filename="{filename}"'

        return response

    except Exception as e:
        logger.exception("Failed to generate monthly report")
        return jsonify({'error': ERROR_MSGS['internal']}), 500


@bp.route('/api/reports/custom', methods=['GET'])
@login_required
def generate_custom_report():
    """
    Generate a custom date range vulnerability report PDF

    Query parameters:
        start_date: Start date (YYYY-MM-DD)
        end_date: End date (YYYY-MM-DD)
        include_acknowledged: Include acknowledged vulnerabilities (default: true)
        include_pending: Include pending vulnerabilities (default: true)
    """
    from flask import make_response
    from app.reports import VulnerabilityReportGenerator
    from datetime import datetime

    try:
        start_date_str = request.args.get('start_date')
        end_date_str = request.args.get('end_date')

        if not start_date_str or not end_date_str:
            return jsonify({'error': 'start_date and end_date are required'}), 400

        start_date = datetime.strptime(start_date_str, '%Y-%m-%d')
        end_date = datetime.strptime(end_date_str, '%Y-%m-%d')

        include_acknowledged = request.args.get('include_acknowledged', 'true').lower() == 'true'
        include_pending = request.args.get('include_pending', 'true').lower() == 'true'

        # Get organization from session
        org_id = session.get('organization_id')
        current_user_id = session.get('user_id')
        current_user = User.query.get(current_user_id)

        # Non-super admins can only see their organization
        if current_user and not current_user.is_super_admin() and not current_user.can_view_all_orgs:
            org_id = current_user.organization_id

        # Generate report
        generator = VulnerabilityReportGenerator(organization_id=org_id)
        pdf_buffer = generator.generate_custom_report(
            start_date=start_date,
            end_date=end_date,
            include_acknowledged=include_acknowledged,
            include_pending=include_pending
        )

        # Create response
        filename = f"SentriKat_Report_{start_date_str}_to_{end_date_str}.pdf"

        response = make_response(pdf_buffer.getvalue())
        response.headers['Content-Type'] = 'application/pdf'
        response.headers['Content-Disposition'] = f'attachment; filename="{filename}"'

        return response

    except ValueError as e:
        return jsonify({'error': 'Invalid date format. Use YYYY-MM-DD'}), 400
    except Exception as e:
        logger.exception("Failed to generate custom report")
        return jsonify({'error': ERROR_MSGS['internal']}), 500


@bp.route('/api/reports/export', methods=['GET'])
@login_required
def export_selected_matches():
    """
    Export selected vulnerability matches as PDF

    Query params:
        match_ids: Comma-separated list of match IDs to export
    """
    from app.reports import VulnerabilityReportGenerator

    match_ids_str = request.args.get('match_ids', '')
    if not match_ids_str:
        return jsonify({'error': 'No match IDs provided'}), 400

    try:
        match_ids = [int(id.strip()) for id in match_ids_str.split(',') if id.strip()]
    except ValueError:
        return jsonify({'error': 'Invalid match ID format'}), 400

    if not match_ids:
        return jsonify({'error': 'No valid match IDs provided'}), 400

    try:
        # Get current user's organization
        current_user_id = session.get('user_id')
        current_user = User.query.get(current_user_id)
        org_id = session.get('organization_id') or (current_user.organization_id if current_user else None)

        # Generate report for selected matches
        generator = VulnerabilityReportGenerator(organization_id=org_id)
        pdf_buffer = generator.generate_selected_report(match_ids=match_ids)

        # Create response
        filename = f"SentriKat_Selected_Vulnerabilities_{datetime.now().strftime('%Y%m%d')}.pdf"

        response = make_response(pdf_buffer.getvalue())
        response.headers['Content-Type'] = 'application/pdf'
        response.headers['Content-Disposition'] = f'attachment; filename="{filename}"'

        return response

    except Exception as e:
        logger.exception("Failed to export selected matches")
        return jsonify({'error': ERROR_MSGS['internal']}), 500


# ============================================================================
# SESSION MANAGEMENT (Organization Switching)
# ============================================================================

@bp.route('/api/session/organization', methods=['GET'])
@login_required
def get_current_organization():
    """Get current organization from session"""
    try:
        org_id = session.get('organization_id')
        if org_id:
            org = Organization.query.get(org_id)
            if org:
                return jsonify(org.to_dict())

        # Return default organization
        default_org = Organization.query.filter_by(name='default').first()
        if default_org:
            return jsonify(default_org.to_dict())

        return jsonify({'error': 'No organization found'}), 404
    except Exception as e:
        import logging
        logging.getLogger(__name__).error(f"Error in get_current_organization: {str(e)}")
        return jsonify({'error': 'Failed to load organization'}), 500

@bp.route('/api/session/organization/<int:org_id>', methods=['POST'])
@login_required
def switch_organization(org_id):
    """Switch to a different organization (with permission check)"""
    try:
        current_user_id = session.get('user_id')
        current_user = User.query.get(current_user_id)

        if not current_user:
            return jsonify({'error': 'User not found'}), 404

        org = Organization.query.get(org_id)
        if not org:
            return jsonify({'error': 'Organization not found'}), 404

        # Check if user has permission to switch to this organization
        # This checks: super_admin, can_view_all_orgs, primary org, and multi-org memberships
        if not current_user.has_access_to_org(org_id):
            return jsonify({'error': 'You do not have permission to access this organization'}), 403

        session['organization_id'] = org_id

        # Also get the user's role for this organization for proper permissions
        user_role = current_user.get_role_for_org(org_id)

        return jsonify({
            'success': True,
            'organization': org.to_dict(),
            'role_in_org': user_role
        })
    except Exception as e:
        import logging
        logging.getLogger(__name__).error(f"Error in switch_organization: {str(e)}")
        return jsonify({'error': 'Failed to switch organization'}), 500
