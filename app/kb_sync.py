"""
SentriKat Knowledge Base Sync

Syncs CPE mappings and vulnerability intelligence between on-premise
SentriKat instances and the central SentriKat Knowledge Base API.

How it works:
1. PUSH: Send locally-learned CPE mappings to the KB server
   - User-created mappings (source='user')
   - Auto-discovered NVD mappings (source='auto_nvd')
   - Only mappings with usage_count > 0 are pushed (proven useful)

2. PULL: Receive community-curated CPE mappings from the KB server
   - Mappings validated by SentriKat team + community
   - Higher confidence than auto-discovered mappings
   - Won't overwrite user-created local mappings

The KB grows with every SentriKat deployment. After months of use,
the local database becomes self-sufficient even without NVD access.

Configuration:
    SENTRIKAT_KB_SERVER: KB server URL (default: portal.sentrikat.com/api)
    SENTRIKAT_KB_SYNC_ENABLED: Enable/disable sync (default: true)
    SENTRIKAT_KB_SHARE_MAPPINGS: Share local mappings with community (default: true)
"""

import os
import json
import logging
from datetime import datetime

logger = logging.getLogger(__name__)

# KB server URL (same portal as licensing, different endpoints)
KB_SERVER_URL = os.environ.get(
    'SENTRIKAT_KB_SERVER',
    os.environ.get('SENTRIKAT_LICENSE_SERVER', 'https://portal.sentrikat.com/api')
)

# Feature toggles
KB_SYNC_ENABLED = os.environ.get('SENTRIKAT_KB_SYNC_ENABLED', 'true').lower() == 'true'
KB_SHARE_MAPPINGS = os.environ.get('SENTRIKAT_KB_SHARE_MAPPINGS', 'true').lower() == 'true'


def _get_auth_headers():
    """Get authentication headers for KB API calls."""
    from app.licensing import get_installation_id, get_license

    installation_id = get_installation_id()
    license_info = get_license()

    headers = {
        'Content-Type': 'application/json',
        'User-Agent': 'SentriKat-KB-Sync/1.0',
        'X-Installation-ID': installation_id or 'unknown',
        'X-Edition': license_info.get_effective_edition() if license_info else 'community',
    }

    # Use license key for authentication if available
    license_key = os.environ.get('SENTRIKAT_LICENSE', '')
    if license_key:
        headers['Authorization'] = f'Bearer {license_key[:64]}'  # Use first 64 chars as auth token

    return headers


def get_local_mappings_for_sync():
    """
    Get locally-learned CPE mappings that should be synced to the KB.

    Only includes mappings that:
    - Have been used at least once (usage_count > 0)
    - Were created by users or auto-discovered via NVD
    - Are not imported from community (to avoid echo)
    """
    from app.models import UserCpeMapping

    try:
        mappings = UserCpeMapping.query.filter(
            UserCpeMapping.usage_count > 0,
            UserCpeMapping.source.in_(['user', 'auto_nvd'])
        ).order_by(
            UserCpeMapping.usage_count.desc()
        ).limit(500).all()

        return [{
            'vendor_pattern': m.vendor_pattern,
            'product_pattern': m.product_pattern,
            'cpe_vendor': m.cpe_vendor,
            'cpe_product': m.cpe_product,
            'confidence': m.confidence,
            'source': m.source,
            'usage_count': m.usage_count,
        } for m in mappings]

    except Exception as e:
        logger.error(f"Failed to get local mappings for sync: {e}")
        return []


def push_mappings():
    """
    Push locally-learned CPE mappings to the SentriKat KB server.

    Returns dict with 'success', 'pushed', 'message' keys.
    """
    if not KB_SYNC_ENABLED:
        return {'success': True, 'pushed': 0, 'message': 'KB sync disabled'}

    if not KB_SHARE_MAPPINGS:
        return {'success': True, 'pushed': 0, 'message': 'Mapping sharing disabled'}

    mappings = get_local_mappings_for_sync()

    if not mappings:
        logger.debug("No local mappings to push to KB")
        return {'success': True, 'pushed': 0, 'message': 'No mappings to sync'}

    try:
        import requests as _requests

        headers = _get_auth_headers()

        response = _requests.post(
            f'{KB_SERVER_URL}/v1/kb/mappings/push',
            headers=headers,
            json={
                'mappings': mappings,
                'timestamp': datetime.utcnow().isoformat(),
            },
            timeout=30,
            verify=True
        )

        if response.status_code == 200:
            result = response.json()
            accepted = result.get('accepted', 0)
            logger.info(f"KB sync: pushed {len(mappings)} mappings, {accepted} accepted")
            return {
                'success': True,
                'pushed': len(mappings),
                'accepted': accepted,
                'message': f'{accepted} mappings accepted by KB server'
            }
        elif response.status_code == 403:
            logger.warning("KB sync: license not authorized for KB sharing")
            return {'success': False, 'pushed': 0, 'message': 'License not authorized'}
        else:
            logger.warning(f"KB sync push failed: HTTP {response.status_code}")
            return {'success': False, 'pushed': 0, 'message': f'HTTP {response.status_code}'}

    except ImportError:
        logger.warning("KB sync: 'requests' library not available")
        return {'success': False, 'pushed': 0, 'message': 'requests library not installed'}
    except Exception as e:
        logger.warning(f"KB sync push failed: {e}")
        return {'success': False, 'pushed': 0, 'message': str(e)}


def pull_mappings():
    """
    Pull community-curated CPE mappings from the SentriKat KB server.

    Only imports mappings that don't conflict with user-created local mappings.
    Community mappings are imported with source='community' and slightly
    lower confidence than user mappings.

    Returns dict with 'success', 'imported', 'skipped', 'message' keys.
    """
    if not KB_SYNC_ENABLED:
        return {'success': True, 'imported': 0, 'message': 'KB sync disabled'}

    try:
        import requests as _requests

        headers = _get_auth_headers()

        # Include timestamp of last sync to get only new mappings
        from app.models import SystemSettings
        last_sync = None
        try:
            setting = SystemSettings.query.filter_by(key='kb_last_pull').first()
            if setting:
                last_sync = setting.value
        except Exception:
            pass

        params = {}
        if last_sync:
            params['since'] = last_sync

        response = _requests.get(
            f'{KB_SERVER_URL}/v1/kb/mappings/pull',
            headers=headers,
            params=params,
            timeout=30,
            verify=True
        )

        if response.status_code == 200:
            data = response.json()
            community_mappings = data.get('mappings', [])

            if not community_mappings:
                logger.debug("KB sync: no new community mappings available")
                return {'success': True, 'imported': 0, 'message': 'No new mappings'}

            # Import with community source (won't overwrite user mappings)
            from app.cpe_mappings import import_user_mappings

            # Tag all as community source
            for m in community_mappings:
                m['source'] = 'community'
                m['notes'] = f"SentriKat KB community mapping (synced {datetime.utcnow().strftime('%Y-%m-%d')})"

            result = import_user_mappings(
                community_mappings,
                user_id=None,
                overwrite=False  # Never overwrite user mappings
            )

            # Save last sync timestamp
            try:
                from app import db
                setting = SystemSettings.query.filter_by(key='kb_last_pull').first()
                if setting:
                    setting.value = datetime.utcnow().isoformat()
                else:
                    from app.models import SystemSettings as SS
                    setting = SS(key='kb_last_pull', value=datetime.utcnow().isoformat())
                    db.session.add(setting)
                db.session.commit()
            except Exception as e:
                logger.warning(f"Failed to save KB sync timestamp: {e}")

            logger.info(
                f"KB sync: pulled {len(community_mappings)} community mappings, "
                f"imported {result['imported']}, skipped {result['skipped']}"
            )

            return {
                'success': True,
                'imported': result['imported'],
                'skipped': result['skipped'],
                'message': f"{result['imported']} new community mappings imported"
            }

        elif response.status_code == 403:
            logger.warning("KB sync: license not authorized for KB pull")
            return {'success': False, 'imported': 0, 'message': 'License not authorized'}
        else:
            logger.warning(f"KB sync pull failed: HTTP {response.status_code}")
            return {'success': False, 'imported': 0, 'message': f'HTTP {response.status_code}'}

    except ImportError:
        logger.warning("KB sync: 'requests' library not available")
        return {'success': False, 'imported': 0, 'message': 'requests library not installed'}
    except Exception as e:
        logger.warning(f"KB sync pull failed: {e}")
        return {'success': False, 'imported': 0, 'message': str(e)}


def kb_sync():
    """
    Full KB sync cycle: push local mappings, then pull community mappings.

    Called by scheduler every 12 hours (alongside license heartbeat).
    Designed to be non-blocking and fail silently - KB sync is a "nice to have",
    not a critical path.
    """
    logger.info("Starting SentriKat KB sync...")

    results = {
        'push': {'success': False, 'message': 'not attempted'},
        'pull': {'success': False, 'message': 'not attempted'},
    }

    try:
        # Step 1: Push our learned mappings
        results['push'] = push_mappings()

        # Step 2: Pull community mappings
        results['pull'] = pull_mappings()

        success = results['push'].get('success', False) or results['pull'].get('success', False)

        logger.info(
            f"KB sync complete: "
            f"pushed={results['push'].get('pushed', 0)}, "
            f"pulled={results['pull'].get('imported', 0)}"
        )

        return {
            'success': success,
            'results': results,
            'timestamp': datetime.utcnow().isoformat()
        }

    except Exception as e:
        logger.error(f"KB sync failed: {e}")
        return {
            'success': False,
            'error': str(e),
            'results': results,
            'timestamp': datetime.utcnow().isoformat()
        }


def get_kb_sync_status():
    """Get the current KB sync configuration and last sync info."""
    from app.models import SystemSettings, UserCpeMapping

    status = {
        'enabled': KB_SYNC_ENABLED,
        'sharing_enabled': KB_SHARE_MAPPINGS,
        'kb_server': KB_SERVER_URL,
        'last_pull': None,
        'local_mappings': {
            'total': 0,
            'user': 0,
            'auto_nvd': 0,
            'community': 0,
        }
    }

    try:
        setting = SystemSettings.query.filter_by(key='kb_last_pull').first()
        if setting:
            status['last_pull'] = setting.value

        status['local_mappings']['total'] = UserCpeMapping.query.count()
        status['local_mappings']['user'] = UserCpeMapping.query.filter_by(source='user').count()
        status['local_mappings']['auto_nvd'] = UserCpeMapping.query.filter_by(source='auto_nvd').count()
        status['local_mappings']['community'] = UserCpeMapping.query.filter_by(source='community').count()
    except Exception as e:
        logger.warning(f"Failed to get KB sync status: {e}")

    return status
