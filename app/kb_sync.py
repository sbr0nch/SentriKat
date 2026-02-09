"""
SentriKat Knowledge Base Sync

Syncs CPE mappings between on-premise SentriKat instances and the
central SentriKat Knowledge Base API.

Security model (3 layers of protection against bad data):

  PUSH SIDE (what we send):
  - Only human-created mappings (source='user') are pushed
  - auto_nvd mappings are EXCLUDED (fuzzy matching can be wrong)
  - Minimum usage_count >= 5 (must be proven useful, not accidental)
  - Max 500 mappings per push

  SERVER SIDE (portal.sentrikat.com must implement):
  - Store with is_published=FALSE by default
  - Only publish when contribution_count >= 3 (3+ independent instances agree)
  - OR: SentriKat team manually verifies and sets is_verified=TRUE
  - Cap stored confidence at 0.90

  PULL SIDE (what we accept):
  - Community mappings imported with confidence capped at 0.85
  - Local user mappings (confidence=0.95) ALWAYS take priority
  - overwrite=False: never replaces existing local mappings
  - source='community' tag for easy identification and cleanup

Result: A mapping must be (1) created by a human, (2) used 5+ times locally,
(3) confirmed by 3+ independent installations OR SentriKat team, and (4) still
won't override any local mapping the customer already has.

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
    - Were created manually by a human user (source='user')
    - Have been used at least 5 times (proven useful, not accidental)
    - Are not imported from community (to avoid echo)

    SECURITY: We intentionally exclude 'auto_nvd' mappings because they are
    created by fuzzy matching heuristics and may be incorrect. Pushing
    unverified auto-mappings to the community KB could cause false negatives
    (missed vulnerabilities) across all installations that pull them.
    Only human-verified mappings are trusted enough to share.
    """
    from app.models import UserCpeMapping

    try:
        mappings = UserCpeMapping.query.filter(
            UserCpeMapping.usage_count >= 5,  # Must be proven useful, not accidental
            UserCpeMapping.source == 'user'   # Only human-verified mappings
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

            # Tag all as community source with capped confidence
            for m in community_mappings:
                m['source'] = 'community'
                # Cap confidence at 0.85 so local user mappings (0.95) always win
                if m.get('confidence', 0) > 0.85:
                    m['confidence'] = 0.85
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
