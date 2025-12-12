from flask import Blueprint, render_template, request, jsonify, redirect, url_for
from app import db
from app.models import Product, Vulnerability, VulnerabilityMatch, SyncLog
from app.cisa_sync import sync_cisa_kev
from app.filters import match_vulnerabilities_to_products, get_filtered_vulnerabilities

bp = Blueprint('main', __name__)

@bp.route('/')
def index():
    """Dashboard homepage"""
    return render_template('dashboard.html')

@bp.route('/admin')
def admin():
    """Admin panel for managing products"""
    return render_template('admin.html')

# API Endpoints

@bp.route('/api/products', methods=['GET'])
def get_products():
    """Get all products"""
    products = Product.query.order_by(Product.vendor, Product.product_name).all()
    return jsonify([p.to_dict() for p in products])

@bp.route('/api/products', methods=['POST'])
def create_product():
    """Create a new product"""
    data = request.get_json()

    if not data.get('vendor') or not data.get('product_name'):
        return jsonify({'error': 'Vendor and product name are required'}), 400

    product = Product(
        vendor=data['vendor'],
        product_name=data['product_name'],
        version=data.get('version'),
        keywords=data.get('keywords'),
        description=data.get('description'),
        active=data.get('active', True)
    )

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
    """Get vulnerabilities with optional filters"""
    filters = {
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
    """Get vulnerability statistics"""
    total_vulns = Vulnerability.query.count()
    total_matches = VulnerabilityMatch.query.count()
    unacknowledged = VulnerabilityMatch.query.filter_by(acknowledged=False).count()
    ransomware = db.session.query(VulnerabilityMatch).join(Vulnerability).filter(
        Vulnerability.known_ransomware == True
    ).count()

    return jsonify({
        'total_vulnerabilities': total_vulns,
        'total_matches': total_matches,
        'unacknowledged': unacknowledged,
        'ransomware_related': ransomware,
        'products_tracked': Product.query.filter_by(active=True).count()
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
