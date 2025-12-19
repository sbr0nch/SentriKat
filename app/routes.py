from flask import Blueprint, render_template, request, jsonify, redirect, url_for, session
from app import db
from app.models import Product, Vulnerability, VulnerabilityMatch, SyncLog, Organization, ServiceCatalog, User, AlertLog
from app.cisa_sync import sync_cisa_kev
from app.filters import match_vulnerabilities_to_products, get_filtered_vulnerabilities
from app.email_alerts import EmailAlertManager
from app.auth import admin_required, login_required
import json

bp = Blueprint('main', __name__)

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

@bp.route('/admin-panel')
@admin_required
def admin_panel():
    """Full administration panel for users, organizations, and settings"""
    return render_template('admin_panel.html')

# API Endpoints

@bp.route('/api/products', methods=['GET'])
@login_required
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
@login_required
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
@login_required
def get_product(product_id):
    """Get a specific product"""
    product = Product.query.get_or_404(product_id)
    return jsonify(product.to_dict())

@bp.route('/api/products/<int:product_id>', methods=['PUT'])
@login_required
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
@login_required
def delete_product(product_id):
    """Delete a product and all related vulnerability matches"""
    product = Product.query.get_or_404(product_id)

    # Delete all related vulnerability matches first
    VulnerabilityMatch.query.filter_by(product_id=product_id).delete()

    # Now delete the product
    db.session.delete(product)
    db.session.commit()
    return jsonify({'success': True})

@bp.route('/api/vulnerabilities', methods=['GET'])
@login_required
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
@login_required
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
@login_required
def acknowledge_match(match_id):
    """Acknowledge a vulnerability match"""
    match = VulnerabilityMatch.query.get_or_404(match_id)
    match.acknowledged = True
    db.session.commit()
    return jsonify(match.to_dict())

@bp.route('/api/matches/<int:match_id>/unacknowledge', methods=['POST'])
@login_required
def unacknowledge_match(match_id):
    """Unacknowledge a vulnerability match"""
    match = VulnerabilityMatch.query.get_or_404(match_id)
    match.acknowledged = False
    db.session.commit()
    return jsonify(match.to_dict())

@bp.route('/api/sync', methods=['POST'])
@login_required
def trigger_sync():
    """Manually trigger CISA KEV sync"""
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
        vendors = db.session.query(ServiceCatalog.vendor)\
            .filter(ServiceCatalog.is_active == True)\
            .filter(ServiceCatalog.vendor.ilike(f'%{query}%'))\
            .distinct()\
            .order_by(ServiceCatalog.vendor)\
            .limit(limit)\
            .all()
        return jsonify([v[0] for v in vendors])

    elif search_type == 'product':
        products = db.session.query(ServiceCatalog.product_name)\
            .filter(ServiceCatalog.is_active == True)\
            .filter(ServiceCatalog.product_name.ilike(f'%{query}%'))\
            .distinct()\
            .order_by(ServiceCatalog.product_name)\
            .limit(limit)\
            .all()
        return jsonify([p[0] for p in products])

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
    categories = db.session.query(
        ServiceCatalog.category,
        db.func.count(ServiceCatalog.id).label('count')
    ).filter_by(is_active=True).group_by(ServiceCatalog.category).all()

    return jsonify([{'name': c[0], 'count': c[1]} for c in categories])

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
@login_required
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
    # Only update password if provided (not null/empty)
    if 'smtp_password' in data and data['smtp_password']:
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
        return jsonify({'success': False, 'error': str(e)})

@bp.route('/api/organizations/<int:org_id>/alert-logs', methods=['GET'])
@login_required
def get_alert_logs(org_id):
    """Get alert logs for an organization"""
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
@admin_required
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
        users = User.query.filter_by(is_active=True).order_by(User.username).all()
    # Org admins see only their organization's users
    elif current_user.is_org_admin():
        users = User.query.filter_by(
            organization_id=current_user.organization_id,
            is_active=True
        ).order_by(User.username).all()
    else:
        return jsonify({'error': 'Insufficient permissions'}), 403

    return jsonify([u.to_dict() for u in users])

@bp.route('/api/users', methods=['POST'])
@admin_required
def create_user():
    """Create a new user (local auth only - LDAP users must be discovered/invited)"""
    data = request.get_json()

    if not data.get('username') or not data.get('email'):
        return jsonify({'error': 'Username and email are required'}), 400

    # Prevent direct LDAP user creation - LDAP users should be discovered/invited
    auth_type = data.get('auth_type', 'local')
    if auth_type == 'ldap':
        return jsonify({'error': 'Cannot create LDAP users directly. LDAP users must be discovered and invited through LDAP authentication.'}), 400

    # Check if username or email already exists
    existing = User.query.filter(
        db.or_(User.username == data['username'], User.email == data['email'])
    ).first()
    if existing:
        return jsonify({'error': 'Username or email already exists'}), 400

    # Require password for local users
    if not data.get('password'):
        return jsonify({'error': 'Password is required for local users'}), 400

    user = User(
        username=data['username'],
        email=data['email'],
        full_name=data.get('full_name'),
        organization_id=data.get('organization_id'),
        auth_type='local',  # Force local auth for created users
        role=data.get('role', 'user'),
        is_admin=data.get('is_admin', False),
        is_active=data.get('is_active', True),
        can_manage_products=data.get('can_manage_products', True),
        can_view_all_orgs=data.get('can_view_all_orgs', False)
    )

    # Set password for local auth
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
    """
    Update a user

    Permissions:
    - Super Admin: Can update any user
    - Org Admin: Can only update users in their organization (except super admins)
    """
    current_user_id = session.get('user_id')
    current_user = User.query.get(current_user_id)
    user = User.query.get_or_404(user_id)

    # Check permissions
    if not current_user.can_manage_user(user):
        return jsonify({'error': 'Insufficient permissions to manage this user'}), 403

    data = request.get_json()

    if 'email' in data:
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
        # Only super admins can create/modify super_admins
        if new_role == 'super_admin' and not current_user.is_super_admin():
            return jsonify({'error': 'Only super admins can create super admin users'}), 403
        # Org admins cannot set org_admin or super_admin roles
        if current_user.role == 'org_admin' and new_role in ['super_admin', 'org_admin']:
            return jsonify({'error': 'Org admins cannot create admin users'}), 403
        user.role = new_role

    if 'is_admin' in data:
        user.is_admin = data['is_admin']
    if 'is_active' in data:
        user.is_active = data['is_active']
    if 'can_manage_products' in data:
        user.can_manage_products = data['can_manage_products']

    # Only super admins can modify can_view_all_orgs
    if 'can_view_all_orgs' in data and current_user.is_super_admin():
        user.can_view_all_orgs = data['can_view_all_orgs']

    # Update password if provided
    if 'password' in data and user.auth_type == 'local':
        user.set_password(data['password'])

    db.session.commit()

    return jsonify(user.to_dict())

@bp.route('/api/users/<int:user_id>', methods=['DELETE'])
@admin_required
def delete_user(user_id):
    """
    Delete a user (soft delete - deactivate)

    Permissions:
    - Super Admin: Can delete any user
    - Org Admin: Can only delete users in their organization (except super admins)
    """
    current_user_id = session.get('user_id')
    current_user = User.query.get(current_user_id)
    user = User.query.get_or_404(user_id)

    # Cannot delete yourself
    if user_id == current_user_id:
        return jsonify({'error': 'Cannot delete your own account'}), 400

    # Check permissions
    if not current_user.can_manage_user(user):
        return jsonify({'error': 'Insufficient permissions to delete this user'}), 403

    user.is_active = False
    db.session.commit()
    return jsonify({'success': True})

# ============================================================================
# DEBUG & DIAGNOSTICS
# ============================================================================

@bp.route('/api/debug/auth-status', methods=['GET'])
@login_required
def debug_auth_status():
    """Debug endpoint to check authentication status"""
    import os
    auth_enabled = os.environ.get('ENABLE_AUTH', 'false').lower() == 'true'

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
# SESSION MANAGEMENT (Organization Switching)
# ============================================================================

@bp.route('/api/session/organization', methods=['GET'])
@login_required
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
@login_required
def switch_organization(org_id):
    """Switch to a different organization"""
    org = Organization.query.get_or_404(org_id)
    session['organization_id'] = org_id
    return jsonify({'success': True, 'organization': org.to_dict()})


# TEMPORARY: Direct login bypass for testing
@bp.route('/debug-login-admin')
def debug_login_admin():
    """TEMPORARY endpoint to bypass login issues - REMOVE IN PRODUCTION"""
    import os
    if os.environ.get('DISABLE_DEBUG_LOGIN', 'false').lower() == 'true':
        return jsonify({'error': 'Debug login is disabled'}), 403
    
    admin = User.query.filter_by(username='admin').first()
    if admin:
        session.clear()
        session['user_id'] = admin.id
        session['username'] = admin.username
        session['organization_id'] = admin.organization_id
        session.permanent = True
        return redirect(url_for('main.index'))
    return jsonify({'error': 'Admin user not found'}), 404
