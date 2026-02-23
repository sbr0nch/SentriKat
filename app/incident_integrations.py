"""
Incident management integrations for SentriKat.
Supports PagerDuty Events API v2 and Opsgenie Alert API.

These integrations allow organizations to automatically create incidents
in their incident management platform when critical vulnerabilities are detected.
"""

import requests
import logging
import uuid

logger = logging.getLogger(__name__)

# API endpoints
PAGERDUTY_EVENTS_URL = 'https://events.pagerduty.com/v2/enqueue'
OPSGENIE_ALERTS_URL = 'https://api.opsgenie.com/v2/alerts'

# Request timeout (seconds)
REQUEST_TIMEOUT = 30


def send_pagerduty_alert(routing_key, title, details, severity='critical', dedup_key=None):
    """Send alert to PagerDuty Events API v2.

    Args:
        routing_key: PagerDuty integration/routing key
        title: Alert summary (max 1024 chars)
        details: Custom details dict
        severity: 'critical', 'error', 'warning', 'info'
        dedup_key: Deduplication key (prevents duplicate incidents).
                   If not provided, a unique key is generated.

    Returns:
        dict with 'success' (bool), 'status' (str), and optionally 'dedup_key' or 'error'
    """
    if not routing_key:
        return {'success': False, 'error': 'No PagerDuty routing key configured'}

    # Validate severity
    valid_severities = ('critical', 'error', 'warning', 'info')
    if severity not in valid_severities:
        severity = 'critical'

    # Generate dedup key if not provided
    if not dedup_key:
        dedup_key = str(uuid.uuid4())

    payload = {
        'routing_key': routing_key,
        'event_action': 'trigger',
        'dedup_key': dedup_key,
        'payload': {
            'summary': title[:1024],  # PagerDuty max summary length
            'severity': severity,
            'source': 'SentriKat',
            'custom_details': details if isinstance(details, dict) else {'details': str(details)}
        }
    }

    try:
        response = requests.post(
            PAGERDUTY_EVENTS_URL,
            json=payload,
            timeout=REQUEST_TIMEOUT,
            headers={'Content-Type': 'application/json'}
        )

        if response.status_code in (200, 201, 202):
            result = response.json() if response.content else {}
            logger.info(f"PagerDuty alert sent successfully: {title[:80]}")
            return {
                'success': True,
                'status': result.get('status', 'success'),
                'dedup_key': result.get('dedup_key', dedup_key)
            }
        else:
            error_msg = f"PagerDuty API returned {response.status_code}"
            try:
                error_body = response.json()
                error_msg += f": {error_body.get('message', response.text[:200])}"
            except Exception:
                error_msg += f": {response.text[:200]}"
            logger.error(error_msg)
            return {'success': False, 'error': error_msg}

    except requests.exceptions.Timeout:
        error_msg = f"PagerDuty API request timed out after {REQUEST_TIMEOUT}s"
        logger.error(error_msg)
        return {'success': False, 'error': error_msg}
    except requests.exceptions.ConnectionError as e:
        error_msg = f"PagerDuty API connection failed: {e}"
        logger.error(error_msg)
        return {'success': False, 'error': error_msg}
    except Exception as e:
        error_msg = f"PagerDuty alert failed: {type(e).__name__}: {e}"
        logger.error(error_msg)
        return {'success': False, 'error': error_msg}


def send_opsgenie_alert(api_key, title, details, priority='P1', tags=None):
    """Send alert to Opsgenie Alert API.

    Args:
        api_key: Opsgenie API key
        title: Alert message (max 130 chars for Opsgenie)
        details: Description text or dict
        priority: P1-P5 (P1 = highest)
        tags: List of tags (e.g., ['critical', 'cve', 'sentrikat'])

    Returns:
        dict with 'success' (bool), 'request_id' (str), and optionally 'error'
    """
    if not api_key:
        return {'success': False, 'error': 'No Opsgenie API key configured'}

    # Validate priority
    valid_priorities = ('P1', 'P2', 'P3', 'P4', 'P5')
    if priority not in valid_priorities:
        priority = 'P1'

    # Build description from details
    if isinstance(details, dict):
        description_parts = []
        for key, value in details.items():
            description_parts.append(f"{key}: {value}")
        description = '\n'.join(description_parts)
    else:
        description = str(details)

    payload = {
        'message': title[:130],  # Opsgenie max message length
        'description': description[:15000],  # Opsgenie max description length
        'priority': priority,
        'source': 'SentriKat',
        'tags': tags or ['sentrikat', 'vulnerability']
    }

    headers = {
        'Content-Type': 'application/json',
        'Authorization': f'GenieKey {api_key}'
    }

    try:
        response = requests.post(
            OPSGENIE_ALERTS_URL,
            json=payload,
            timeout=REQUEST_TIMEOUT,
            headers=headers
        )

        if response.status_code in (200, 201, 202):
            result = response.json() if response.content else {}
            logger.info(f"Opsgenie alert sent successfully: {title[:80]}")
            return {
                'success': True,
                'request_id': result.get('requestId', ''),
                'status': 'success'
            }
        else:
            error_msg = f"Opsgenie API returned {response.status_code}"
            try:
                error_body = response.json()
                error_msg += f": {error_body.get('message', response.text[:200])}"
            except Exception:
                error_msg += f": {response.text[:200]}"
            logger.error(error_msg)
            return {'success': False, 'error': error_msg}

    except requests.exceptions.Timeout:
        error_msg = f"Opsgenie API request timed out after {REQUEST_TIMEOUT}s"
        logger.error(error_msg)
        return {'success': False, 'error': error_msg}
    except requests.exceptions.ConnectionError as e:
        error_msg = f"Opsgenie API connection failed: {e}"
        logger.error(error_msg)
        return {'success': False, 'error': error_msg}
    except Exception as e:
        error_msg = f"Opsgenie alert failed: {type(e).__name__}: {e}"
        logger.error(error_msg)
        return {'success': False, 'error': error_msg}


def _severity_to_pagerduty(severity):
    """Map CVE severity to PagerDuty severity level.

    Args:
        severity: CVE severity string ('critical', 'high', 'medium', 'low')

    Returns:
        PagerDuty severity string ('critical', 'error', 'warning', 'info')
    """
    mapping = {
        'critical': 'critical',
        'high': 'error',
        'medium': 'warning',
        'low': 'info'
    }
    return mapping.get(severity, 'critical')


def _severity_to_opsgenie(severity):
    """Map CVE severity to Opsgenie priority level.

    Args:
        severity: CVE severity string ('critical', 'high', 'medium', 'low')

    Returns:
        Opsgenie priority string ('P1' through 'P5')
    """
    mapping = {
        'critical': 'P1',
        'high': 'P2',
        'medium': 'P3',
        'low': 'P4'
    }
    return mapping.get(severity, 'P1')


def send_incident_alert(org, title, cve_list, severity='critical'):
    """Send alert to configured incident management platform(s).

    Checks organization settings for pagerduty_enabled/opsgenie_enabled
    and sends alerts accordingly. Gracefully skips if not configured.

    Args:
        org: Organization model instance
        title: Alert title/summary
        cve_list: List of CVE IDs or dicts with CVE details
        severity: Alert severity ('critical', 'high', 'medium', 'low')

    Returns:
        dict with 'pagerduty' and 'opsgenie' result dicts (or None if not enabled)
    """
    results = {
        'pagerduty': None,
        'opsgenie': None
    }

    # Build details dict for the alert
    if isinstance(cve_list, list):
        if len(cve_list) > 0 and isinstance(cve_list[0], dict):
            cve_ids = [c.get('cve_id', str(c)) for c in cve_list]
        else:
            cve_ids = [str(c) for c in cve_list]
    else:
        cve_ids = [str(cve_list)]

    details = {
        'organization': org.display_name if hasattr(org, 'display_name') else str(org),
        'cve_count': len(cve_ids),
        'cve_ids': ', '.join(cve_ids[:20]),  # Limit to first 20 CVEs
        'severity': severity,
        'source': 'SentriKat Vulnerability Monitor'
    }

    if len(cve_ids) > 20:
        details['additional_cves'] = f'... and {len(cve_ids) - 20} more'

    # Generate dedup key based on org + CVE list to prevent duplicate incidents
    dedup_key = f"sentrikat-{org.name}-{'-'.join(sorted(cve_ids[:5]))}"

    # Send to PagerDuty if enabled
    if getattr(org, 'pagerduty_enabled', False) and getattr(org, 'pagerduty_routing_key', None):
        try:
            pd_severity = _severity_to_pagerduty(severity)
            results['pagerduty'] = send_pagerduty_alert(
                routing_key=org.pagerduty_routing_key,
                title=title,
                details=details,
                severity=pd_severity,
                dedup_key=dedup_key
            )
        except Exception as e:
            logger.error(f"PagerDuty integration error for {org.name}: {e}")
            results['pagerduty'] = {'success': False, 'error': str(e)}

    # Send to Opsgenie if enabled
    if getattr(org, 'opsgenie_enabled', False) and getattr(org, 'opsgenie_api_key', None):
        try:
            og_priority = _severity_to_opsgenie(severity)
            tags = ['sentrikat', severity, f'cve-count-{len(cve_ids)}']
            results['opsgenie'] = send_opsgenie_alert(
                api_key=org.opsgenie_api_key,
                title=title,
                details=details,
                priority=og_priority,
                tags=tags
            )
        except Exception as e:
            logger.error(f"Opsgenie integration error for {org.name}: {e}")
            results['opsgenie'] = {'success': False, 'error': str(e)}

    # Log results
    pd_status = results['pagerduty']['success'] if results['pagerduty'] else 'not configured'
    og_status = results['opsgenie']['success'] if results['opsgenie'] else 'not configured'
    logger.info(
        f"Incident alert for {org.name}: PagerDuty={pd_status}, Opsgenie={og_status}"
    )

    return results
