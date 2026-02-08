"""
SentriKat Maintenance Utilities

Provides cleanup and maintenance operations for:
- Stale product installations (not seen for X days)
- Stale assets (not checking in for X days)
- Import queue cleanup (old processed items)
- Data consistency checks

Can be run via:
- CLI command: flask maintenance cleanup
- Scheduled cron job
- Admin API endpoint
"""

from datetime import datetime, timedelta
import logging
from sqlalchemy import or_
from app import db
from app.models import Asset, ProductInstallation, Product, Organization

logger = logging.getLogger(__name__)

# Default thresholds (can be overridden in settings)
DEFAULT_INSTALLATION_STALE_DAYS = 30  # Remove installations not seen for 30 days
DEFAULT_ASSET_STALE_DAYS = 14  # Mark assets as stale after 14 days
DEFAULT_ASSET_REMOVE_DAYS = 90  # Remove assets not seen for 90 days
DEFAULT_IMPORT_QUEUE_KEEP_DAYS = 30  # Keep processed import queue items for 30 days


class MaintenanceResult:
    """Results from a maintenance operation."""

    def __init__(self):
        self.installations_removed = 0
        self.assets_marked_stale = 0
        self.assets_removed = 0
        self.products_cleaned = 0
        self.products_auto_disabled = 0
        self.import_queue_cleaned = 0
        self.vulnerabilities_auto_acknowledged = 0
        self.vulnerabilities_upgraded_acknowledged = 0
        self.errors = []

    def to_dict(self):
        return {
            'installations_removed': self.installations_removed,
            'assets_marked_stale': self.assets_marked_stale,
            'assets_removed': self.assets_removed,
            'products_cleaned': self.products_cleaned,
            'products_auto_disabled': self.products_auto_disabled,
            'import_queue_cleaned': self.import_queue_cleaned,
            'vulnerabilities_auto_acknowledged': self.vulnerabilities_auto_acknowledged,
            'vulnerabilities_upgraded_acknowledged': self.vulnerabilities_upgraded_acknowledged,
            'errors': self.errors,
            'success': len(self.errors) == 0
        }


def cleanup_stale_installations(days=None, dry_run=False):
    """
    Remove ProductInstallation records not seen for X days.

    This handles the case where software is uninstalled from an endpoint -
    if we don't see it reported for X days, we assume it's gone.

    Args:
        days: Number of days threshold (default: DEFAULT_INSTALLATION_STALE_DAYS)
        dry_run: If True, don't actually delete, just count

    Returns:
        Number of installations removed
    """
    if days is None:
        days = DEFAULT_INSTALLATION_STALE_DAYS

    threshold = datetime.utcnow() - timedelta(days=days)

    # Find stale installations
    stale_query = ProductInstallation.query.filter(
        ProductInstallation.last_seen_at < threshold
    )

    count = stale_query.count()

    if count > 0 and not dry_run:
        # Get IDs first to avoid issues with lazy loading during delete
        stale_ids = [i.id for i in stale_query.all()]

        # Delete in batches
        batch_size = 100
        for i in range(0, len(stale_ids), batch_size):
            batch = stale_ids[i:i + batch_size]
            ProductInstallation.query.filter(
                ProductInstallation.id.in_(batch)
            ).delete(synchronize_session=False)
            db.session.commit()

        logger.info(f"Removed {count} stale product installations (>{days} days old)")

    return count


def update_asset_status(stale_days=None, remove_days=None, dry_run=False):
    """
    Update asset status based on last check-in time.

    - Mark as 'offline' if no check-in for X hours
    - Mark as 'stale' if no check-in for Y days
    - Remove if no check-in for Z days (optional)

    Args:
        stale_days: Days before marking as stale (default: DEFAULT_ASSET_STALE_DAYS)
        remove_days: Days before removing (default: DEFAULT_ASSET_REMOVE_DAYS, None to disable)
        dry_run: If True, don't actually modify/delete

    Returns:
        Tuple of (marked_stale, removed)
    """
    if stale_days is None:
        stale_days = DEFAULT_ASSET_STALE_DAYS
    if remove_days is None:
        remove_days = DEFAULT_ASSET_REMOVE_DAYS

    now = datetime.utcnow()
    offline_threshold = now - timedelta(hours=1)  # Offline after 1 hour
    stale_threshold = now - timedelta(days=stale_days)
    remove_threshold = now - timedelta(days=remove_days) if remove_days else None

    marked_stale = 0
    removed = 0

    # Mark offline (no checkin for 1 hour)
    offline_query = Asset.query.filter(
        Asset.status == 'online',
        Asset.last_checkin < offline_threshold
    )
    if not dry_run:
        offline_query.update({'status': 'offline'}, synchronize_session=False)
        db.session.commit()

    # Mark stale (no checkin for X days, including assets with NULL last_checkin)
    stale_query = Asset.query.filter(
        Asset.status.in_(['online', 'offline']),
        or_(Asset.last_checkin.is_(None), Asset.last_checkin < stale_threshold)
    )
    marked_stale = stale_query.count()
    if marked_stale > 0 and not dry_run:
        stale_query.update({'status': 'stale'}, synchronize_session=False)
        db.session.commit()
        logger.info(f"Marked {marked_stale} assets as stale (>{stale_days} days)")

    # Remove very old assets (optional)
    if remove_threshold:
        remove_query = Asset.query.filter(
            Asset.last_checkin < remove_threshold
        )
        removed = remove_query.count()
        if removed > 0 and not dry_run:
            # First remove their installations
            for asset in remove_query.all():
                ProductInstallation.query.filter_by(asset_id=asset.id).delete()
            # Then remove assets
            remove_query.delete(synchronize_session=False)
            db.session.commit()
            logger.info(f"Removed {removed} assets not seen for >{remove_days} days")

    return marked_stale, removed


def cleanup_orphaned_products(dry_run=False):
    """
    Remove products that have no installations and no organization assignments.

    Products auto-created by agents that are no longer on any endpoint
    and not manually assigned to any organization can be cleaned up.

    Args:
        dry_run: If True, don't actually delete

    Returns:
        Number of products removed
    """
    # Find products with no installations
    products_with_installations = db.session.query(
        ProductInstallation.product_id
    ).distinct().scalar_subquery()

    orphaned = Product.query.filter(
        ~Product.id.in_(products_with_installations),
        ~Product.organizations.any()  # No organization assignments
    )

    count = orphaned.count()

    if count > 0 and not dry_run:
        # Don't delete products that were manually created or have catalog entries
        # Only delete auto-discovered products with no references
        orphaned.filter(
            Product.service_catalog_id.is_(None)  # Not linked to catalog
        ).delete(synchronize_session=False)
        db.session.commit()
        logger.info(f"Removed {count} orphaned products")

    return count


DEFAULT_PRODUCT_STALE_DAYS = 90  # Auto-disable products not reported for 90 days


def auto_disable_stale_products(days=None, dry_run=False):
    """
    Auto-disable products that haven't been reported by any agent for X days.

    This handles products that were once installed but are no longer in use.
    Products are NOT deleted, just marked as inactive (active=False) and
    auto_disabled=True so they can be re-enabled if needed.

    Only affects agent-sourced products (source='agent'), not manually created ones.

    Args:
        days: Number of days threshold (default: DEFAULT_PRODUCT_STALE_DAYS)
        dry_run: If True, don't actually modify, just count

    Returns:
        Number of products auto-disabled
    """
    if days is None:
        days = DEFAULT_PRODUCT_STALE_DAYS

    threshold = datetime.utcnow() - timedelta(days=days)

    # Find products that:
    # 1. Are currently active
    # 2. Were added by agents (source='agent')
    # 3. Haven't been reported by any agent for X days
    # 4. Haven't already been auto-disabled
    stale_products = Product.query.filter(
        Product.active == True,
        Product.source == 'agent',  # Only agent-sourced products
        Product.auto_disabled == False,  # Not already auto-disabled
        db.or_(
            Product.last_agent_report < threshold,
            Product.last_agent_report.is_(None)  # Never reported (shouldn't happen but handle it)
        )
    )

    count = stale_products.count()

    if count > 0 and not dry_run:
        stale_products.update({
            'active': False,
            'auto_disabled': True,
            'updated_at': datetime.utcnow()
        }, synchronize_session=False)
        db.session.commit()
        logger.info(f"Auto-disabled {count} stale products (not reported for >{days} days)")

    return count


def re_enable_product_if_reported(product):
    """
    Re-enable a product if it was auto-disabled but an agent reported it again.

    Called when an agent reports a product that was previously auto-disabled.
    This allows products to come back to life if agents start reporting them again.

    Args:
        product: Product object to check and potentially re-enable

    Returns:
        True if product was re-enabled, False otherwise
    """
    if product.auto_disabled:
        product.active = True
        product.auto_disabled = False
        product.last_agent_report = datetime.utcnow()
        db.session.commit()
        logger.info(f"Re-enabled auto-disabled product: {product.vendor} {product.product_name}")
        return True
    return False


def cleanup_import_queue(days=None, dry_run=False):
    """
    Clean up old processed import queue items.

    Keeps pending items forever, but removes approved/rejected items
    older than X days.

    Args:
        days: Days to keep processed items (default: DEFAULT_IMPORT_QUEUE_KEEP_DAYS)
        dry_run: If True, don't actually delete

    Returns:
        Number of items removed
    """
    from app.integrations_models import ImportQueue

    if days is None:
        days = DEFAULT_IMPORT_QUEUE_KEEP_DAYS

    threshold = datetime.utcnow() - timedelta(days=days)

    old_processed = ImportQueue.query.filter(
        ImportQueue.status.in_(['approved', 'rejected']),
        ImportQueue.processed_at < threshold
    )

    count = old_processed.count()

    if count > 0 and not dry_run:
        old_processed.delete(synchronize_session=False)
        db.session.commit()
        logger.info(f"Removed {count} old import queue items (>{days} days)")

    return count


def auto_acknowledge_resolved_vulnerabilities(dry_run=False):
    """
    Auto-acknowledge vulnerability matches for products that are no longer installed anywhere.

    When an agent stops reporting a product (software uninstalled), and the product
    has no remaining installations on any asset, we can auto-acknowledge the related
    vulnerability matches since the software is no longer present.

    This reduces alert fatigue by automatically resolving CVEs for software that
    has been removed from all systems.

    Args:
        dry_run: If True, don't actually modify, just count

    Returns:
        Number of vulnerability matches auto-acknowledged
    """
    from app.models import VulnerabilityMatch

    # Find products with no active installations
    # These are products where software has been removed from all assets
    products_without_installations = Product.query.outerjoin(
        ProductInstallation,
        Product.id == ProductInstallation.product_id
    ).group_by(Product.id).having(
        db.func.count(ProductInstallation.id) == 0
    ).filter(
        Product.active == True  # Only active products (not manually disabled)
    ).all()

    if not products_without_installations:
        return 0

    product_ids = [p.id for p in products_without_installations]

    # Find unacknowledged matches for these products
    matches_to_ack = VulnerabilityMatch.query.filter(
        VulnerabilityMatch.product_id.in_(product_ids),
        VulnerabilityMatch.acknowledged == False
    )

    count = matches_to_ack.count()

    if count > 0 and not dry_run:
        # Update in batches
        now = datetime.utcnow()
        matches_to_ack.update({
            'acknowledged': True,
            'auto_acknowledged': True,
            'resolution_reason': 'software_removed',
            'acknowledged_at': now
        }, synchronize_session=False)
        db.session.commit()

        # Log which products were affected
        product_names = [f"{p.vendor} {p.product_name}" for p in products_without_installations[:5]]
        if len(products_without_installations) > 5:
            product_names.append(f"... and {len(products_without_installations) - 5} more")

        logger.info(
            f"Auto-acknowledged {count} vulnerability matches for removed software: "
            f"{', '.join(product_names)}"
        )

    return count


def auto_acknowledge_upgraded_vulnerabilities(dry_run=False):
    """
    Auto-acknowledge vulnerability matches for products that have been upgraded
    to a version no longer in the vulnerable range.

    When all installations of a product report a version newer than the
    vulnerable range, the CVE match is no longer relevant and can be
    auto-acknowledged.

    Returns:
        Number of vulnerability matches auto-acknowledged
    """
    from app.models import VulnerabilityMatch, ProductInstallation

    count = 0

    # Get unacknowledged matches for products that have CPE data (precise matching)
    unacked_matches = VulnerabilityMatch.query.filter(
        VulnerabilityMatch.acknowledged == False
    ).join(
        Product, VulnerabilityMatch.product_id == Product.id
    ).filter(
        Product.cpe_vendor.isnot(None),
        Product.cpe_product.isnot(None),
        Product.active == True
    ).all()

    if not unacked_matches:
        return 0

    # Group matches by product for efficiency
    product_matches = {}
    for match in unacked_matches:
        if match.product_id not in product_matches:
            product_matches[match.product_id] = []
        product_matches[match.product_id].append(match)

    now = datetime.utcnow()

    for product_id, matches in product_matches.items():
        product = matches[0].product

        # Get all current installation versions for this product
        installations = ProductInstallation.query.filter_by(
            product_id=product_id
        ).all()

        if not installations:
            continue  # No installations - handled by software_removed logic

        # Get all unique current versions
        installed_versions = set()
        for inst in installations:
            if inst.version:
                installed_versions.add(inst.version)

        if not installed_versions:
            continue

        # For each vulnerability match, check if ALL installed versions are outside the vulnerable range
        for match in matches:
            vuln = match.vulnerability
            if not vuln or not vuln.cve_id:
                continue

            try:
                from app.nvd_cpe_api import check_product_affected
                all_versions_safe = True

                for version in installed_versions:
                    is_affected, _ = check_product_affected(
                        product.cpe_vendor,
                        product.cpe_product,
                        version,
                        vuln.cve_id
                    )
                    if is_affected:
                        all_versions_safe = False
                        break

                if all_versions_safe and not dry_run:
                    match.acknowledged = True
                    match.auto_acknowledged = True
                    match.resolution_reason = 'version_upgraded'
                    match.acknowledged_at = now
                    count += 1

            except Exception as e:
                logger.debug(f"Version check failed for {vuln.cve_id}/{product.product_name}: {e}")
                continue

    if count > 0 and not dry_run:
        db.session.commit()
        logger.info(f"Auto-acknowledged {count} vulnerability matches due to version upgrades")

    return count


def run_full_maintenance(dry_run=False, settings=None):
    """
    Run all maintenance tasks.

    Args:
        dry_run: If True, don't actually modify anything
        settings: Dict with custom thresholds

    Returns:
        MaintenanceResult with summary
    """
    settings = settings or {}
    result = MaintenanceResult()

    try:
        # 1. Clean stale installations
        result.installations_removed = cleanup_stale_installations(
            days=settings.get('installation_stale_days'),
            dry_run=dry_run
        )
    except Exception as e:
        result.errors.append(f"Installation cleanup failed: {str(e)}")
        logger.error(f"Installation cleanup failed: {e}", exc_info=True)

    try:
        # 2. Update asset status
        stale, removed = update_asset_status(
            stale_days=settings.get('asset_stale_days'),
            remove_days=settings.get('asset_remove_days'),
            dry_run=dry_run
        )
        result.assets_marked_stale = stale
        result.assets_removed = removed
    except Exception as e:
        result.errors.append(f"Asset status update failed: {str(e)}")
        logger.error(f"Asset status update failed: {e}", exc_info=True)

    try:
        # 3. Clean orphaned products
        result.products_cleaned = cleanup_orphaned_products(dry_run=dry_run)
    except Exception as e:
        result.errors.append(f"Product cleanup failed: {str(e)}")
        logger.error(f"Product cleanup failed: {e}", exc_info=True)

    try:
        # 4. Clean import queue
        result.import_queue_cleaned = cleanup_import_queue(
            days=settings.get('import_queue_keep_days'),
            dry_run=dry_run
        )
    except Exception as e:
        result.errors.append(f"Import queue cleanup failed: {str(e)}")
        logger.error(f"Import queue cleanup failed: {e}", exc_info=True)

    try:
        # 5. Auto-disable stale products (not reported by agents for X days)
        result.products_auto_disabled = auto_disable_stale_products(
            days=settings.get('product_stale_days'),
            dry_run=dry_run
        )
    except Exception as e:
        result.errors.append(f"Product auto-disable failed: {str(e)}")
        logger.error(f"Product auto-disable failed: {e}", exc_info=True)

    try:
        # 6. Auto-acknowledge vulnerabilities for removed software (if enabled)
        auto_ack_enabled = settings.get('auto_acknowledge_removed_software', True)
        if auto_ack_enabled:
            result.vulnerabilities_auto_acknowledged = auto_acknowledge_resolved_vulnerabilities(
                dry_run=dry_run
            )
        else:
            logger.debug("Auto-acknowledge for removed software is disabled")
    except Exception as e:
        result.errors.append(f"Vulnerability auto-acknowledge failed: {str(e)}")
        logger.error(f"Vulnerability auto-acknowledge failed: {e}", exc_info=True)

    try:
        # 7. Auto-acknowledge vulnerabilities where product was upgraded past vulnerable range
        auto_upgrade_ack = settings.get('auto_acknowledge_upgraded_software', True)
        if auto_upgrade_ack:
            result.vulnerabilities_upgraded_acknowledged = auto_acknowledge_upgraded_vulnerabilities(
                dry_run=dry_run
            )
        else:
            logger.debug("Auto-acknowledge for upgraded software is disabled")
    except Exception as e:
        result.errors.append(f"Upgraded vulnerability auto-acknowledge failed: {str(e)}")
        logger.error(f"Upgraded vulnerability auto-acknowledge failed: {e}", exc_info=True)

    return result


def get_maintenance_stats():
    """
    Get statistics about data that would be affected by maintenance.

    Returns:
        Dict with counts of stale/orphaned data
    """
    from app.integrations_models import ImportQueue

    now = datetime.utcnow()

    # Stale installations (not seen for 30+ days)
    install_threshold = now - timedelta(days=DEFAULT_INSTALLATION_STALE_DAYS)
    stale_installations = ProductInstallation.query.filter(
        ProductInstallation.last_seen_at < install_threshold
    ).count()

    # Stale assets (not checking in for 14+ days)
    asset_threshold = now - timedelta(days=DEFAULT_ASSET_STALE_DAYS)
    stale_assets = Asset.query.filter(
        Asset.last_checkin < asset_threshold,
        Asset.status != 'stale'
    ).count()

    # Very old assets (90+ days)
    old_asset_threshold = now - timedelta(days=DEFAULT_ASSET_REMOVE_DAYS)
    very_old_assets = Asset.query.filter(
        Asset.last_checkin < old_asset_threshold
    ).count()

    # Orphaned products
    products_with_installations = db.session.query(
        ProductInstallation.product_id
    ).distinct().scalar_subquery()

    orphaned_products = Product.query.filter(
        ~Product.id.in_(products_with_installations),
        ~Product.organizations.any()
    ).count()

    # Old import queue items
    queue_threshold = now - timedelta(days=DEFAULT_IMPORT_QUEUE_KEEP_DAYS)
    old_queue_items = ImportQueue.query.filter(
        ImportQueue.status.in_(['approved', 'rejected']),
        ImportQueue.processed_at < queue_threshold
    ).count()

    # Stale products (not reported by agents for 90+ days)
    product_threshold = now - timedelta(days=DEFAULT_PRODUCT_STALE_DAYS)
    stale_products = Product.query.filter(
        Product.active == True,
        Product.source == 'agent',
        Product.auto_disabled == False,
        db.or_(
            Product.last_agent_report < product_threshold,
            Product.last_agent_report.is_(None)
        )
    ).count()

    # Already auto-disabled products
    auto_disabled_products = Product.query.filter(
        Product.auto_disabled == True
    ).count()

    return {
        'stale_installations': stale_installations,
        'stale_assets': stale_assets,
        'very_old_assets': very_old_assets,
        'orphaned_products': orphaned_products,
        'stale_products': stale_products,
        'auto_disabled_products': auto_disabled_products,
        'old_import_queue_items': old_queue_items,
        'thresholds': {
            'installation_stale_days': DEFAULT_INSTALLATION_STALE_DAYS,
            'asset_stale_days': DEFAULT_ASSET_STALE_DAYS,
            'asset_remove_days': DEFAULT_ASSET_REMOVE_DAYS,
            'product_stale_days': DEFAULT_PRODUCT_STALE_DAYS,
            'import_queue_keep_days': DEFAULT_IMPORT_QUEUE_KEEP_DAYS
        }
    }


# ============================================================================
# Version Tracking Utilities
# ============================================================================

def get_product_version_summary(product_id):
    """
    Get a summary of all versions of a product across all assets.

    Useful for understanding which versions are deployed and where.

    Args:
        product_id: Product ID to analyze

    Returns:
        List of dicts with version info
    """
    installations = ProductInstallation.query.filter_by(product_id=product_id).all()

    version_map = {}
    for inst in installations:
        version = inst.version or 'Unknown'
        if version not in version_map:
            version_map[version] = {
                'version': version,
                'count': 0,
                'assets': [],
                'first_seen': None,
                'last_seen': None
            }

        v = version_map[version]
        v['count'] += 1
        v['assets'].append({
            'hostname': inst.asset.hostname if inst.asset else 'Unknown',
            'last_seen': inst.last_seen_at.isoformat() if inst.last_seen_at else None
        })

        if inst.discovered_at:
            if not v['first_seen'] or inst.discovered_at < v['first_seen']:
                v['first_seen'] = inst.discovered_at

        if inst.last_seen_at:
            if not v['last_seen'] or inst.last_seen_at > v['last_seen']:
                v['last_seen'] = inst.last_seen_at

    # Convert to list and format dates
    result = []
    for version, data in sorted(version_map.items(), key=lambda x: x[1]['count'], reverse=True):
        result.append({
            'version': version,
            'count': data['count'],
            'asset_count': len(set(a['hostname'] for a in data['assets'])),
            'first_seen': data['first_seen'].isoformat() if data['first_seen'] else None,
            'last_seen': data['last_seen'].isoformat() if data['last_seen'] else None
        })

    return result


def get_version_vulnerability_check(product_id, version):
    """
    Check if a specific version of a product has vulnerabilities.

    This is more precise than just checking Product.version since
    different versions may have different CVEs.

    Args:
        product_id: Product ID
        version: Specific version to check

    Returns:
        Dict with vulnerability info
    """
    from app.filters import match_cve_for_product_version

    product = Product.query.get(product_id)
    if not product:
        return {'error': 'Product not found'}

    cpe_vendor, cpe_product, _ = product.get_effective_cpe()
    if not cpe_vendor or not cpe_product:
        return {
            'product_id': product_id,
            'version': version,
            'has_cpe': False,
            'message': 'No CPE configured for this product'
        }

    # This would call NVD API to check vulnerabilities for specific version
    # For now, return placeholder
    return {
        'product_id': product_id,
        'version': version,
        'cpe_vendor': cpe_vendor,
        'cpe_product': cpe_product,
        'has_cpe': True,
        'message': 'Use NVD API to check vulnerabilities for this specific version'
    }
