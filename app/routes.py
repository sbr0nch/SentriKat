from flask import Blueprint, render_template, request, jsonify, redirect, url_for, session
from app import db
from app.models import Product, Vulnerability, VulnerabilityMatch, SyncLog, Organization, ServiceCatalog, User, AlertLog
from app.cisa_sync import sync_cisa_kev
from app.filters import match_vulnerabilities_to_products, get_filtered_vulnerabilities
from app.email_alerts import EmailAlertManager
from app.auth import admin_required
import json

bp = Blueprint('main', __name__)

@bp.route('/')
def index():
    """Dashboard homepage"""
    return render_template('dashboard.html')

@bp.route('/admin')
def admin():
    """Admin panel for managing products"""
    return render_template('admin.html')

@bp.route('/admin-panel')
@admin_required
def admin_panel():
    """Full administration panel for users, organizations, and settings"""
    return render_template('admin_panel.html')

# API Endpoints

@bp.route('/api/products', methods=['GET'])
def get_products():
    """Get all products for current organization"""
    # Get current organization
    org_id = session.get('organization_id')
    if not org_id:
        default_org = Organization.query.filter_by(name='default').first()
        org_id = default_org.id if default_org else None

    # Filter by organization
    query = Product.query
    if org_id:
        query = query.filter_by(organization_id=org_id)

    products = query.order_by(Product.vendor, Product.product_name).all()
    return jsonify([p.to_dict() for p in products])

@bp.route('/api/products', methods=['POST'])
def create_product():
    """Create a new product"""
    data = request.get_json()

    if not data.get('vendor') or not data.get('product_name'):
        return jsonify({'error': 'Vendor and product name are required'}), 400

    # Get current organization from session
    org_id = session.get('organization_id')
    if not org_id:
        # Use default organization if not set
        default_org = Organization.query.filter_by(name='default').first()
        org_id = default_org.id if default_org else None

    product = Product(
        organization_id=data.get('organization_id', org_id),
        service_catalog_id=data.get('service_catalog_id'),
        vendor=data['vendor'],
        product_name=data['product_name'],
        version=data.get('version'),
        keywords=data.get('keywords'),
        description=data.get('description'),
        active=data.get('active', True),
        criticality=data.get('criticality', 'medium')
    )

    # If service catalog entry was used, increment its usage
    if product.service_catalog_id:
        catalog_entry = ServiceCatalog.query.get(product.service_catalog_id)
        if catalog_entry:
            catalog_entry.usage_frequency += 1

    db.session.add(product)
    db.session.commit()

    # Re-run matching for new product
    match_vulnerabilities_to_products()

    return jsonify(product.to_dict()), 201

@bp.route('/api/products/<int:product_id>', methods=['GET'])
def get_product(product_id):
    """Get a specific product"""
    product = Product.query.get_or_404(product_id)
    return jsonify(product.to_dict())

@bp.route('/api/products/<int:product_id>', methods=['PUT'])
def update_product(product_id):
    """Update a product"""
    product = Product.query.get_or_404(product_id)
    data = request.get_json()

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
    if 'criticality' in data:
        product.criticality = data['criticality']

    db.session.commit()

    # Re-run matching after update
    match_vulnerabilities_to_products()

    return jsonify(product.to_dict())

@bp.route('/api/products/<int:product_id>', methods=['DELETE'])
def delete_product(product_id):
    """Delete a product"""
    product = Product.query.get_or_404(product_id)
    db.session.delete(product)
    db.session.commit()
    return jsonify({'success': True})

@bp.route('/api/vulnerabilities', methods=['GET'])
def get_vulnerabilities():
    """Get vulnerabilities with optional filters for current organization"""
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
        'acknowledged': request.args.get('acknowledged')
    }

    # Remove None values
    filters = {k: v for k, v in filters.items() if v is not None and v != ''}

    matches = get_filtered_vulnerabilities(filters)

    return jsonify([m.to_dict() for m in matches])

@bp.route('/api/vulnerabilities/stats', methods=['GET'])
def get_vulnerability_stats():
    """Get vulnerability statistics with priority breakdown for current organization"""
    # Get current organization
    org_id = session.get('organization_id')
    if not org_id:
        default_org = Organization.query.filter_by(name='default').first()
        org_id = default_org.id if default_org else None

    total_vulns = Vulnerability.query.count()

    # Filter matches by organization
    total_matches_query = db.session.query(VulnerabilityMatch).join(Product)
    unacknowledged_query = db.session.query(VulnerabilityMatch).join(Product).filter(VulnerabilityMatch.acknowledged == False)
    ransomware_query = db.session.query(VulnerabilityMatch).join(Vulnerability).join(Product).filter(Vulnerability.known_ransomware == True)

    if org_id:
        total_matches_query = total_matches_query.filter(Product.organization_id == org_id)
        unacknowledged_query = unacknowledged_query.filter(Product.organization_id == org_id)
        ransomware_query = ransomware_query.filter(Product.organization_id == org_id)

    total_matches = total_matches_query.count()
    unacknowledged = unacknowledged_query.count()
    ransomware = ransomware_query.count()

    # Calculate priority-based stats
    all_matches = unacknowledged_query.all()

    priority_counts = {'critical': 0, 'high': 0, 'medium': 0, 'low': 0}
    for match in all_matches:
        priority = match.calculate_effective_priority()
        priority_counts[priority] = priority_counts.get(priority, 0) + 1

    # Products tracked for this org
    products_tracked_query = Product.query.filter_by(active=True)
    if org_id:
        products_tracked_query = products_tracked_query.filter_by(organization_id=org_id)
    products_tracked = products_tracked_query.count()

    return jsonify({
        'total_vulnerabilities': total_vulns,
        'total_matches': total_matches,
        'unacknowledged': unacknowledged,
        'ransomware_related': ransomware,
        'products_tracked': products_tracked,
        'priority_breakdown': priority_counts,
        'critical_count': priority_counts['critical'],
        'high_count': priority_counts['high'],
        'medium_count': priority_counts['medium'],
        'low_count': priority_counts['low']
    })

@bp.route('/api/matches/<int:match_id>/acknowledge', methods=['POST'])
def acknowledge_match(match_id):
    """Acknowledge a vulnerability match"""
    match = VulnerabilityMatch.query.get_or_404(match_id)
    match.acknowledged = True
    db.session.commit()
    return jsonify(match.to_dict())

@bp.route('/api/matches/<int:match_id>/unacknowledge', methods=['POST'])
def unacknowledge_match(match_id):
    """Unacknowledge a vulnerability match"""
    match = VulnerabilityMatch.query.get_or_404(match_id)
    match.acknowledged = False
    db.session.commit()
    return jsonify(match.to_dict())

@bp.route('/api/sync', methods=['POST'])
def trigger_sync():
    """Manually trigger CISA KEV sync"""
    result = sync_cisa_kev()
    return jsonify(result)

@bp.route('/api/sync/status', methods=['GET'])
def sync_status():
    """Get last sync status"""
    last_sync = SyncLog.query.order_by(SyncLog.sync_date.desc()).first()
    if last_sync:
        return jsonify(last_sync.to_dict())
    return jsonify({'message': 'No sync performed yet'})

@bp.route('/api/sync/history', methods=['GET'])
def sync_history():
    """Get sync history"""
    limit = request.args.get('limit', 10, type=int)
    syncs = SyncLog.query.order_by(SyncLog.sync_date.desc()).limit(limit).all()
    return jsonify([s.to_dict() for s in syncs])

# ============================================================================
# SERVICE CATALOG API ENDPOINTS
# ============================================================================

@bp.route('/api/catalog/search', methods=['GET'])
def search_catalog():
    """Search service catalog"""
    query = request.args.get('q', '').strip()
    category = request.args.get('category')
    limit = request.args.get('limit', 20, type=int)

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
def get_categories():
    """Get all categories with counts"""
    categories = db.session.query(
        ServiceCatalog.category,
        db.func.count(ServiceCatalog.id).label('count')
    ).filter_by(is_active=True).group_by(ServiceCatalog.category).all()

    return jsonify([{'name': c[0], 'count': c[1]} for c in categories])

@bp.route('/api/catalog/popular', methods=['GET'])
def get_popular_services():
    """Get most popular services"""
    limit = request.args.get('limit', 20, type=int)
    services = ServiceCatalog.query.filter_by(is_active=True, is_popular=True)\
        .order_by(ServiceCatalog.usage_frequency.desc()).limit(limit).all()
    return jsonify([s.to_dict() for s in services])

@bp.route('/api/catalog/<int:catalog_id>/use', methods=['POST'])
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
def get_organizations():
    """Get all organizations"""
    orgs = Organization.query.filter_by(active=True).order_by(Organization.display_name).all()
    return jsonify([o.to_dict() for o in orgs])

@bp.route('/api/organizations', methods=['POST'])
@admin_required
def create_organization():
    """Create a new organization"""
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
        notification_emails=json.dumps(data.get('notification_emails', [])),
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
def get_organization(org_id):
    """Get a specific organization"""
    org = Organization.query.get_or_404(org_id)
    return jsonify(org.to_dict())

@bp.route('/api/organizations/<int:org_id>', methods=['PUT'])
@admin_required
def update_organization(org_id):
    """Update an organization"""
    org = Organization.query.get_or_404(org_id)
    data = request.get_json()

    if 'display_name' in data:
        org.display_name = data['display_name']
    if 'description' in data:
        org.description = data['description']
    if 'notification_emails' in data:
        org.notification_emails = json.dumps(data['notification_emails'])
    if 'alert_on_critical' in data:
        org.alert_on_critical = data['alert_on_critical']
    if 'alert_on_high' in data:
        org.alert_on_high = data['alert_on_high']
    if 'alert_on_new_cve' in data:
        org.alert_on_new_cve = data['alert_on_new_cve']
    if 'alert_on_ransomware' in data:
        org.alert_on_ransomware = data['alert_on_ransomware']
    if 'alert_time_start' in data:
        org.alert_time_start = data['alert_time_start']
    if 'alert_time_end' in data:
        org.alert_time_end = data['alert_time_end']
    if 'alert_days' in data:
        org.alert_days = data['alert_days']
    if 'active' in data:
        org.active = data['active']

    # SMTP settings
    if 'smtp_host' in data:
        org.smtp_host = data['smtp_host']
    if 'smtp_port' in data:
        org.smtp_port = data['smtp_port']
    if 'smtp_username' in data:
        org.smtp_username = data['smtp_username']
    if 'smtp_password' in data:
        org.smtp_password = data['smtp_password']
    if 'smtp_use_tls' in data:
        org.smtp_use_tls = data['smtp_use_tls']
    if 'smtp_use_ssl' in data:
        org.smtp_use_ssl = data['smtp_use_ssl']
    if 'smtp_from_email' in data:
        org.smtp_from_email = data['smtp_from_email']
    if 'smtp_from_name' in data:
        org.smtp_from_name = data['smtp_from_name']

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
    """Test SMTP connection for an organization"""
    org = Organization.query.get_or_404(org_id)
    smtp_config = org.get_smtp_config()

    if not smtp_config['host'] or not smtp_config['from_email']:
        return jsonify({'status': 'error', 'message': 'SMTP not configured'}), 400

    result = EmailAlertManager.test_smtp_connection(smtp_config)
    return jsonify(result)

@bp.route('/api/organizations/<int:org_id>/alert-logs', methods=['GET'])
def get_alert_logs(org_id):
    """Get alert logs for an organization"""
    limit = request.args.get('limit', 50, type=int)
    logs = AlertLog.query.filter_by(organization_id=org_id)\
        .order_by(AlertLog.sent_at.desc()).limit(limit).all()
    return jsonify([log.to_dict() for log in logs])

# ============================================================================
# USER MANAGEMENT & AUTHENTICATION API ENDPOINTS
# ============================================================================

@bp.route('/api/users', methods=['GET'])
@admin_required
def get_users():
    """Get all users (admin only)"""
    users = User.query.filter_by(is_active=True).order_by(User.username).all()
    return jsonify([u.to_dict() for u in users])

@bp.route('/api/users', methods=['POST'])
@admin_required
def create_user():
    """Create a new user"""
    data = request.get_json()

    if not data.get('username') or not data.get('email'):
        return jsonify({'error': 'Username and email are required'}), 400

    # Check if username or email already exists
    existing = User.query.filter(
        db.or_(User.username == data['username'], User.email == data['email'])
    ).first()
    if existing:
        return jsonify({'error': 'Username or email already exists'}), 400

    user = User(
        username=data['username'],
        email=data['email'],
        organization_id=data.get('organization_id'),
        auth_type=data.get('auth_type', 'local'),
        ldap_dn=data.get('ldap_dn'),
        is_admin=data.get('is_admin', False),
        is_active=data.get('is_active', True),
        can_manage_products=data.get('can_manage_products', True),
        can_view_all_orgs=data.get('can_view_all_orgs', False)
    )

    # Set password for local auth
    if user.auth_type == 'local' and data.get('password'):
        user.set_password(data['password'])

    db.session.add(user)
    db.session.commit()

    return jsonify(user.to_dict()), 201

@bp.route('/api/users/<int:user_id>', methods=['GET'])
@admin_required
def get_user(user_id):
    """Get a specific user"""
    user = User.query.get_or_404(user_id)
    return jsonify(user.to_dict())

@bp.route('/api/users/<int:user_id>', methods=['PUT'])
@admin_required
def update_user(user_id):
    """Update a user"""
    user = User.query.get_or_404(user_id)
    data = request.get_json()

    if 'email' in data:
        user.email = data['email']
    if 'organization_id' in data:
        user.organization_id = data['organization_id']
    if 'is_admin' in data:
        user.is_admin = data['is_admin']
    if 'is_active' in data:
        user.is_active = data['is_active']
    if 'can_manage_products' in data:
        user.can_manage_products = data['can_manage_products']
    if 'can_view_all_orgs' in data:
        user.can_view_all_orgs = data['can_view_all_orgs']

    # Update password if provided
    if 'password' in data and user.auth_type == 'local':
        user.set_password(data['password'])

    db.session.commit()

    return jsonify(user.to_dict())

@bp.route('/api/users/<int:user_id>', methods=['DELETE'])
@admin_required
def delete_user(user_id):
    """Delete a user"""
    user = User.query.get_or_404(user_id)
    db.session.delete(user)
    db.session.commit()
    return jsonify({'success': True})

# ============================================================================
# SESSION MANAGEMENT (Organization Switching)
# ============================================================================

@bp.route('/api/session/organization', methods=['GET'])
def get_current_organization():
    """Get current organization from session"""
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

@bp.route('/api/session/organization/<int:org_id>', methods=['POST'])
def switch_organization(org_id):
    """Switch to a different organization"""
    org = Organization.query.get_or_404(org_id)
    session['organization_id'] = org_id
    return jsonify({'success': True, 'organization': org.to_dict()})
