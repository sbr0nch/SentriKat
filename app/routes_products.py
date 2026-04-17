"""Product read-only endpoints (M-1 partial extraction).

This is the first slice of the routes.py split called out in audit
finding M-1. Endpoints that live here are PRODUCT-SCOPED, READ-ONLY
views — specifically installations, version history, and aggregated
vulnerability listings. They were chosen because they have minimal
shared state with the rest of routes.py and thus can be relocated
without ripple effects across the codebase.

Write/mutation endpoints for products (POST/PUT/DELETE, batch-delete,
purge, rematch, apply-cpe) intentionally stay in ``app/routes.py``
for now — they depend on private helpers like ``_wipe_product_children``
and the ``match_vulnerabilities_to_products`` import chain. They'll
migrate here in a follow-up step once those helpers are also relocated.

Registration happens in ``app/__init__.py``. The blueprint does NOT
add a URL prefix, so every route path is identical to what it was
under the main blueprint — no client-visible change.
"""
from __future__ import annotations

import logging

from flask import Blueprint, jsonify

from app import csrf
from app.auth import login_required
from app.authz import current_user, user_can_access_product
from app.models import Asset, Product, ProductInstallation, ProductVersionHistory


logger = logging.getLogger(__name__)

products_bp = Blueprint('products', __name__)
csrf.exempt(products_bp)


@products_bp.route('/api/products/<int:product_id>/installations', methods=['GET'])
@login_required
def get_product_installations(product_id):
    """List every asset that has the product installed."""
    product = Product.query.get_or_404(product_id)
    if not user_can_access_product(current_user(), product):
        return jsonify({'error': 'Access denied'}), 403

    installations = ProductInstallation.query.filter_by(product_id=product_id).filter(
        ProductInstallation.removed_at.is_(None)
    ).all()

    result = []
    for inst in installations:
        asset = Asset.query.get(inst.asset_id)
        if not asset:
            continue
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
            'last_seen_at': inst.last_seen_at.isoformat() if inst.last_seen_at else None,
        })

    result.sort(key=lambda x: x['hostname'] or '')

    return jsonify({
        'product': {
            'id': product.id,
            'vendor': product.vendor,
            'product_name': product.product_name,
        },
        'installations': result,
        'total': len(result),
    })


@products_bp.route('/api/products/<int:product_id>/version-history', methods=['GET'])
@login_required
def get_product_version_history(product_id):
    """Return recent version change history for the product."""
    product = Product.query.get_or_404(product_id)
    if not user_can_access_product(current_user(), product):
        return jsonify({'error': 'Access denied'}), 403

    changes = ProductVersionHistory.query.filter_by(product_id=product_id).order_by(
        ProductVersionHistory.detected_at.desc()
    ).limit(200).all()

    result = []
    for ch in changes:
        asset = Asset.query.get(ch.asset_id)
        result.append({
            'id': ch.id,
            'asset_id': ch.asset_id,
            'hostname': asset.hostname if asset else 'Unknown',
            'previous_version': ch.previous_version,
            'new_version': ch.new_version,
            'change_type': ch.change_type,
            'detected_by': ch.detected_by,
            'detected_at': ch.detected_at.isoformat() if ch.detected_at else None,
        })

    return jsonify({
        'history': result,
        'total': len(result),
    })
