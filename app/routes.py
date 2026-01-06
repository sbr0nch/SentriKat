from flask import Blueprint, render_template, request, jsonify, redirect, url_for, session
from app import db, csrf
from app.models import Product, Vulnerability, VulnerabilityMatch, SyncLog, Organization, ServiceCatalog, User, AlertLog
from app.cisa_sync import sync_cisa_kev
from app.filters import match_vulnerabilities_to_products, get_filtered_vulnerabilities
from app.email_alerts import EmailAlertManager
from app.auth import admin_required, login_required, org_admin_required, manager_required
import json
import re

bp = Blueprint('main', __name__)

# Exempt API routes from CSRF (they use JSON and are protected by SameSite cookies)
csrf.exempt(bp)


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
    Validate password meets security requirements:
    - At least 12 characters
    - Contains uppercase and lowercase
    - Contains digit
    - Contains special character
    """
    if not password or len(password) < 12:
        return False, "Password must be at least 12 characters"
    if not re.search(r'[A-Z]', password):
        return False, "Password must contain at least one uppercase letter"
    if not re.search(r'[a-z]', password):
        return False, "Password must contain at least one lowercase letter"
    if not re.search(r'[0-9]', password):
        return False, "Password must contain at least one digit"
    if not re.search(r'[!@#$%^&*(),.?":{}|<>]', password):
        return False, "Password must contain at least one special character"
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

@bp.route('/admin-panel')
@org_admin_required
def admin_panel():
    """Full administration panel for users, organizations, and settings.

    Access:
    - super_admin: Full access to all tabs
    - org_admin: Limited access (users in their org, LDAP, SMTP/Sync settings only)
    """
    return render_template('admin_panel.html')

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

    - Super Admin: See all products (can filter by any org)
    - Others: Only see products assigned to their organization
    """
    from app.models import product_organizations
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
    page = request.args.get('page', type=int)
    per_page = request.args.get('per_page', 25, type=int)
    per_page = min(per_page, 100)  # Limit max items per page

    logger.info(f"get_products: user={current_user.username}, role={current_user.role}, is_super_admin={current_user.is_super_admin()}")

    # Build base query based on permissions
    if current_user.is_super_admin():
        query = Product.query
        logger.info("get_products: super_admin sees all products")

        # Super admin can filter by specific organization
        if filter_org:
            query = query.join(
                product_organizations,
                Product.id == product_organizations.c.product_id
            ).filter(
                db.or_(
                    product_organizations.c.organization_id == filter_org,
                    Product.organization_id == filter_org
                )
            )
    else:
        # Get user's current organization from session
        org_id = session.get('organization_id') or current_user.organization_id
        logger.info(f"get_products: org_id={org_id}")

        if not org_id:
            logger.info("get_products: no org_id, returning empty list")
            if page:
                return jsonify({'products': [], 'total': 0, 'page': 1, 'per_page': per_page, 'pages': 0})
            return jsonify([])

        # Get products assigned via many-to-many table or legacy field
        query = Product.query.outerjoin(
            product_organizations,
            Product.id == product_organizations.c.product_id
        ).filter(
            db.or_(
                product_organizations.c.organization_id == org_id,
                Product.organization_id == org_id
            )
        ).distinct()

        logger.info(f"get_products: filtered to org {org_id}")

    # Apply search filter
    if search:
        search_term = f"%{search}%"
        query = query.filter(
            db.or_(
                Product.vendor.ilike(search_term),
                Product.product_name.ilike(search_term),
                Product.version.ilike(search_term),
                Product.keywords.ilike(search_term)
            )
        )

    # Apply criticality filter
    if criticality and criticality in ['critical', 'high', 'medium', 'low']:
        query = query.filter(Product.criticality == criticality)

    # Apply status filter
    if status == 'active':
        query = query.filter(Product.active == True)
    elif status == 'inactive':
        query = query.filter(Product.active == False)

    # Order by vendor, product name
    query = query.order_by(Product.vendor, Product.product_name)

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
    current_user_id = session.get('user_id')
    current_user = User.query.get(current_user_id)

    data = request.get_json()

    if not data.get('vendor') or not data.get('product_name'):
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

    product = Product(
        organization_id=data.get('organization_id', org_id),
        service_catalog_id=data.get('service_catalog_id'),
        vendor=data['vendor'].strip(),
        product_name=data['product_name'].strip(),
        version=version,  # Already normalized above (empty string -> None)
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

    return jsonify(product.to_dict()), 201

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
    if 'criticality' in data:
        product.criticality = data['criticality']
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
def delete_product(product_id):
    """
    Delete a product or remove it from current organization.

    Permissions:
    - Super Admin: Deletes product globally from all organizations
    - Org Admin/Manager: Removes product from their org only.
      If product is in multiple orgs, it stays in others.
      If product is only in their org, it gets deleted globally.
    """
    from app.logging_config import log_audit_event

    current_user_id = session.get('user_id')
    current_user = User.query.get(current_user_id)
    product = Product.query.get_or_404(product_id)

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
        if current_user.is_super_admin():
            # Super admin: delete product globally
            VulnerabilityMatch.query.filter_by(product_id=product_id).delete()
            db.session.delete(product)
            db.session.commit()

            log_audit_event(
                'DELETE',
                'products',
                product_id,
                old_value=product_info,
                details=f"Super admin deleted product {product.vendor} {product.product_name} globally"
            )
            return jsonify({'success': True, 'message': 'Product deleted globally'})

        else:
            # Org admin/manager: remove from their org only
            user_org = Organization.query.get(user_org_id)

            if len(product_org_ids) > 1:
                # Product is in multiple orgs - just remove from this org
                if user_org in product.organizations:
                    product.organizations.remove(user_org)
                    db.session.commit()

                    log_audit_event(
                        'REMOVE_ORG',
                        'products',
                        product_id,
                        old_value={'organization_id': user_org_id},
                        details=f"Removed product {product.vendor} {product.product_name} from {user_org.display_name}"
                    )
                    return jsonify({
                        'success': True,
                        'message': f'Product removed from {user_org.display_name} (still exists in other organizations)'
                    })
            else:
                # Product only in this org - delete it globally
                VulnerabilityMatch.query.filter_by(product_id=product_id).delete()
                db.session.delete(product)
                db.session.commit()

                log_audit_event(
                    'DELETE',
                    'products',
                    product_id,
                    old_value=product_info,
                    details=f"Deleted product {product.vendor} {product.product_name}"
                )
                return jsonify({'success': True, 'message': 'Product deleted'})

        return jsonify({'success': True})

    except Exception as e:
        db.session.rollback()
        return jsonify({'success': False, 'error': str(e)}), 500

@bp.route('/api/products/<int:product_id>/organizations', methods=['GET'])
@login_required
def get_product_organizations(product_id):
    """Get organizations assigned to a product"""
    product = Product.query.get_or_404(product_id)

    # Get assigned organizations from many-to-many relationship
    assigned_orgs = [{'id': org.id, 'name': org.name, 'display_name': org.display_name}
                     for org in product.organizations.all()]

    # Include legacy organization_id for backwards compatibility
    if product.organization_id and not assigned_orgs:
        if product.organization:
            assigned_orgs = [{'id': product.organization.id, 'name': product.organization.name,
                             'display_name': product.organization.display_name}]

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
                print(f"Failed to send notification to {org.name}: {str(e)}")

        return jsonify({
            'success': True,
            'message': f'Product assigned to {len(added_orgs)} organization(s)',
            'organizations': [{'id': org.id, 'name': org.name, 'display_name': org.display_name}
                             for org in product.organizations.all()]
        })

    except Exception as e:
        db.session.rollback()
        return jsonify({'error': str(e)}), 500

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
            print(f"Failed to send notification to {org.name}: {str(e)}")

        # Check if product has any organizations left after removal
        remaining_orgs = product.organizations.count()
        has_remaining_legacy = product.organization_id is not None

        # If no organizations left and confirm_delete was passed, delete the product
        if remaining_orgs == 0 and not has_remaining_legacy:
            # Delete associated vulnerability matches first
            VulnerabilityMatch.query.filter_by(product_id=product_id).delete()

            db.session.delete(product)
            db.session.commit()

            return jsonify({
                'success': True,
                'message': f'Product "{product.product_name}" has been deleted.',
                'product_deleted': True
            })

        return jsonify({
            'success': True,
            'message': f'Organization {org.display_name} removed from product',
            'product_deleted': False
        })

    except Exception as e:
        db.session.rollback()
        return jsonify({'error': str(e)}), 500

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
@admin_required
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
        return jsonify({'status': 'error', 'message': str(e)}), 500


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
            unack_matches = (
                VulnerabilityMatch.query
                .join(Product)
                .filter(
                    Product.organization_id == org.id,
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
        return jsonify({
            'status': 'error',
            'error': str(e)
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
    """Get organizations based on user permissions"""
    current_user_id = session.get('user_id')
    current_user = User.query.get(current_user_id)

    if not current_user:
        return jsonify({'error': 'User not found'}), 404

    # Super admins and users with can_view_all_orgs see all organizations
    if current_user.is_super_admin() or current_user.can_view_all_orgs:
        orgs = Organization.query.filter_by(active=True).order_by(Organization.display_name).all()
    else:
        # Regular users only see their own organization
        if current_user.organization_id:
            orgs = Organization.query.filter_by(id=current_user.organization_id, active=True).all()
        else:
            orgs = []

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

    user = User(
        username=data['username'],
        email=data['email'],
        full_name=data.get('full_name', '')[:100],  # Limit length
        organization_id=data.get('organization_id'),
        auth_type='local',  # Force local auth for created users
        role=role,
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
@org_admin_required
def get_user(user_id):
    """Get a specific user"""
    user = User.query.get_or_404(user_id)
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
        return jsonify({'error': f'Failed to delete user: {str(e)}'}), 500

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
# AUDIT LOGS API
# ============================================================================

@bp.route('/api/audit-logs', methods=['GET'])
@admin_required
def get_audit_logs():
    """
    Get audit logs from the audit.log file
    Only accessible by super admins
    """
    import os
    import json

    current_user_id = session.get('user_id')
    current_user = User.query.get(current_user_id)

    # Only super admins can view audit logs
    if not current_user or not current_user.is_super_admin():
        return jsonify({'error': 'Only super admins can view audit logs'}), 403

    # Get query parameters
    limit = request.args.get('limit', 100, type=int)
    action_filter = request.args.get('action')
    resource_filter = request.args.get('resource')
    user_filter = request.args.get('user_id')

    # Find the audit log file
    log_dir = os.environ.get('LOG_DIR', '/var/log/sentrikat')
    if not os.path.exists(log_dir):
        log_dir = os.path.join(os.path.dirname(os.path.dirname(__file__)), 'logs')

    audit_log_path = os.path.join(log_dir, 'audit.log')

    if not os.path.exists(audit_log_path):
        return jsonify({'logs': [], 'total': 0, 'message': 'No audit logs found'})

    logs = []
    try:
        # Read the file in reverse to get most recent first
        with open(audit_log_path, 'r', encoding='utf-8') as f:
            lines = f.readlines()

        # Parse JSON lines (most recent first)
        for line in reversed(lines):
            if not line.strip():
                continue
            try:
                log_entry = json.loads(line.strip())

                # Apply filters
                if action_filter and log_entry.get('action') != action_filter:
                    continue
                if resource_filter and not log_entry.get('resource', '').startswith(resource_filter):
                    continue
                if user_filter and str(log_entry.get('user_id')) != str(user_filter):
                    continue

                logs.append(log_entry)

                if len(logs) >= limit:
                    break

            except json.JSONDecodeError:
                continue

    except Exception as e:
        return jsonify({'error': f'Failed to read audit logs: {str(e)}'}), 500

    return jsonify({
        'logs': logs,
        'total': len(logs),
        'limit': limit
    })

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
        import traceback
        traceback.print_exc()
        return jsonify({'error': str(e)}), 500


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
        import traceback
        traceback.print_exc()
        return jsonify({'error': str(e)}), 500


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
        import traceback
        traceback.print_exc()
        return jsonify({'error': str(e)}), 500


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
    """Switch to a different organization (with permission check)"""
    current_user_id = session.get('user_id')
    current_user = User.query.get(current_user_id)

    if not current_user:
        return jsonify({'error': 'User not found'}), 404

    org = Organization.query.get_or_404(org_id)

    # Check if user has permission to switch to this organization
    if not current_user.is_super_admin() and not current_user.can_view_all_orgs:
        # Regular users can only access their own organization
        if current_user.organization_id != org_id:
            return jsonify({'error': 'You do not have permission to access this organization'}), 403

    session['organization_id'] = org_id
    return jsonify({'success': True, 'organization': org.to_dict()})
