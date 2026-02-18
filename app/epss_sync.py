"""
EPSS (Exploit Prediction Scoring System) Sync Module

Fetches EPSS scores from FIRST (Forum of Incident Response and Security Teams)
to provide exploit probability predictions for CVEs.

EPSS API: https://api.first.org/data/v1/epss
- Free, no authentication required
- Rate limit: 100 requests per minute (we batch CVEs to stay well under)
- Returns probability (0-1) that a CVE will be exploited in the next 30 days
"""

import requests
import logging
from datetime import datetime, timedelta
from typing import List, Dict, Optional, Tuple

logger = logging.getLogger(__name__)

# EPSS API configuration
EPSS_API_BASE = "https://api.first.org/data/v1/epss"
EPSS_BATCH_SIZE = 100  # Max CVEs per request (API limit is ~500)
EPSS_CACHE_HOURS = 24  # Re-fetch scores older than this


def fetch_epss_scores(cve_ids: List[str]) -> Dict[str, Dict]:
    """
    Fetch EPSS scores for a list of CVE IDs from FIRST API.

    Args:
        cve_ids: List of CVE IDs (e.g., ['CVE-2024-1234', 'CVE-2024-5678'])

    Returns:
        Dict mapping CVE IDs to their EPSS data:
        {
            'CVE-2024-1234': {
                'epss': 0.0532,      # Probability of exploitation (0-1)
                'percentile': 0.912  # Percentile rank (0-1)
            }
        }
    """
    if not cve_ids:
        return {}

    results = {}

    # Process in batches
    for i in range(0, len(cve_ids), EPSS_BATCH_SIZE):
        batch = cve_ids[i:i + EPSS_BATCH_SIZE]

        try:
            # EPSS API accepts comma-separated CVE IDs
            params = {'cve': ','.join(batch)}
            response = requests.get(EPSS_API_BASE, params=params, timeout=30)
            response.raise_for_status()

            data = response.json()

            batch_count = 0
            if data.get('status') == 'OK' and 'data' in data:
                for item in data['data']:
                    cve_id = item.get('cve')
                    if cve_id:
                        epss_val = float(item.get('epss', 0))
                        pctl_val = float(item.get('percentile', 0))
                        # Clamp to valid 0-1 range
                        epss_val = max(0.0, min(1.0, epss_val))
                        pctl_val = max(0.0, min(1.0, pctl_val))
                        results[cve_id] = {
                            'epss': epss_val,
                            'percentile': pctl_val
                        }
                        batch_count += 1

            logger.debug(f"Fetched EPSS scores for {len(batch)} CVEs, got {batch_count} results")

        except requests.RequestException as e:
            logger.warning(f"EPSS API request failed for batch: {e}")
        except (KeyError, ValueError) as e:
            logger.warning(f"EPSS API response parsing error: {e}")

    return results


def sync_epss_scores(force: bool = False) -> Tuple[int, int, str]:
    """
    Sync EPSS scores for all vulnerabilities in the database.

    Args:
        force: If True, refresh all scores regardless of age

    Returns:
        Tuple of (updated_count, error_count, status_message)
    """
    from app import db
    from app.models import Vulnerability

    updated = 0
    not_found = 0

    try:
        # Get vulnerabilities that need EPSS update
        if force:
            vulns = Vulnerability.query.all()
        else:
            # Only update if never fetched or older than cache period
            cutoff = datetime.utcnow() - timedelta(hours=EPSS_CACHE_HOURS)
            vulns = Vulnerability.query.filter(
                db.or_(
                    Vulnerability.epss_fetched_at.is_(None),
                    Vulnerability.epss_fetched_at < cutoff
                )
            ).all()

        if not vulns:
            return 0, 0, "All EPSS scores are up to date"

        logger.info(f"Syncing EPSS scores for {len(vulns)} vulnerabilities")

        # Extract CVE IDs
        cve_ids = [v.cve_id for v in vulns]

        # Fetch scores from FIRST API
        scores = fetch_epss_scores(cve_ids)

        # Update database
        now = datetime.utcnow()
        for vuln in vulns:
            if vuln.cve_id in scores:
                score_data = scores[vuln.cve_id]
                vuln.epss_score = score_data['epss']
                vuln.epss_percentile = score_data['percentile']
                vuln.epss_fetched_at = now
                updated += 1
            else:
                # CVE not found in EPSS (too old or not yet indexed) — normal
                # Still mark as fetched to avoid repeated lookups
                vuln.epss_fetched_at = now
                not_found += 1

        db.session.commit()

        message = f"Updated {updated} EPSS scores"
        if not_found > 0:
            message += f" ({not_found} CVEs not indexed by EPSS)"

        logger.info(message)
        return updated, not_found, message

    except Exception as e:
        logger.exception("EPSS sync failed")
        db.session.rollback()
        return 0, 1, f"EPSS sync failed: {str(e)}"


def get_epss_score(cve_id: str) -> Optional[Dict]:
    """
    Get EPSS score for a single CVE, fetching if needed.

    Args:
        cve_id: CVE ID (e.g., 'CVE-2024-1234')

    Returns:
        Dict with 'epss' and 'percentile' keys, or None if not available
    """
    from app import db
    from app.models import Vulnerability

    vuln = Vulnerability.query.filter_by(cve_id=cve_id).first()

    if not vuln:
        # CVE not in our database, fetch directly from API
        scores = fetch_epss_scores([cve_id])
        return scores.get(cve_id)

    # Check if score is stale
    if vuln.epss_fetched_at:
        age = datetime.utcnow() - vuln.epss_fetched_at
        if age < timedelta(hours=EPSS_CACHE_HOURS) and vuln.epss_score is not None:
            # Return cached score
            return {
                'epss': vuln.epss_score,
                'percentile': vuln.epss_percentile
            }

    # Fetch fresh score
    scores = fetch_epss_scores([cve_id])

    if cve_id in scores:
        score_data = scores[cve_id]
        vuln.epss_score = score_data['epss']
        vuln.epss_percentile = score_data['percentile']
        vuln.epss_fetched_at = datetime.utcnow()
        db.session.commit()
        return score_data

    return None


def format_epss_display(epss_score: float, epss_percentile: float) -> Dict:
    """
    Format EPSS scores for display in UI.

    Returns:
        Dict with formatted values and risk level
    """
    if epss_score is None or epss_percentile is None:
        return {
            'score_display': 'N/A',
            'percentile_display': 'N/A',
            'risk_level': 'unknown',
            'risk_color': 'secondary'
        }

    # Determine risk level based on percentile
    if epss_percentile >= 0.95:
        risk_level = 'critical'
        risk_color = 'danger'
    elif epss_percentile >= 0.85:
        risk_level = 'high'
        risk_color = 'warning'
    elif epss_percentile >= 0.70:
        risk_level = 'medium'
        risk_color = 'info'
    else:
        risk_level = 'low'
        risk_color = 'success'

    return {
        'score_display': f"{epss_score * 100:.1f}%",  # Convert to percentage
        'percentile_display': f"Top {(1 - epss_percentile) * 100:.0f}%",
        'risk_level': risk_level,
        'risk_color': risk_color
    }
