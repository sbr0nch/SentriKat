"""
Multi-source CVE intelligence for CVSS scores and severity.

Fallback chain (all free, all legally cleared for commercial use):
  1. NVD API 2.0 (NIST) - primary, most complete CVSS enrichment
  2. CVE.org API (MITRE + CISA Vulnrichment ADP) - CVE record with ADP-provided CVSS
  3. ENISA EUVD API - European Vulnerability Database (NIS2-mandated)

Data licensing:
  - NVD/CVE.org: CVE Terms of Use (permissive, attribution required)
  - CISA Vulnrichment: CC0 1.0 (public domain)
  - ENISA EUVD: ENISA IPR Policy (attribution required)
"""
import requests
import time
import logging
from config import Config
import urllib3
from app.nvd_rate_limiter import get_rate_limiter, NVDRateLimitError

logger = logging.getLogger(__name__)


def _get_api_key():
    """Get NVD API key from database or environment."""
    import os
    try:
        from app.models import SystemSettings
        from app.encryption import decrypt_value

        setting = SystemSettings.query.filter_by(key='nvd_api_key').first()
        if setting and setting.value:
            if setting.is_encrypted:
                try:
                    return decrypt_value(setting.value)
                except Exception as e:
                    logger.warning("NVD API key decrypt failed, using raw value: %s", e)
                    return setting.value
            return setting.value
    except Exception as e:
        logger.warning("NVD API key DB lookup failed, falling back to env: %s", e)

    return os.environ.get('NVD_API_KEY')


def _score_to_severity(cvss_score):
    """Convert a CVSS score to a severity string."""
    if cvss_score is None:
        return None
    if cvss_score >= 9.0:
        return 'CRITICAL'
    elif cvss_score >= 7.0:
        return 'HIGH'
    elif cvss_score >= 4.0:
        return 'MEDIUM'
    else:
        return 'LOW'


def _get_request_kwargs():
    """Get common request kwargs (proxies, SSL, etc.)."""
    proxies = Config.get_proxies()
    verify_ssl = Config.get_verify_ssl()
    if not verify_ssl:
        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
    return {'proxies': proxies, 'verify': verify_ssl}


# ---------------------------------------------------------------------------
# Source 1: NVD API 2.0 (NIST)
# ---------------------------------------------------------------------------

# R-PARSER-RESILIENCE alias map for NVD CVSS extraction.
# Maps each canonical field to a list of dotted lookup paths within an
# NVD ``metrics.cvssMetricVxx[i]`` entry. Adding a new path is enough
# to absorb upstream schema renames.
_NVD_CVSS_ALIASES = {
    'base_score':    ['cvssData.baseScore', 'baseScore', 'cvss.baseScore'],
    'base_severity': ['cvssData.baseSeverity', 'baseSeverity', 'cvss.baseSeverity'],
}


def _extract_cvss_entry(entry):
    """Extract (score, severity) from a single CVSS metric entry.

    Uses field aliases + type coercion so that an upstream renaming
    ``cvssData.baseScore`` → ``baseScore`` (or vice versa) does not
    silently break enrichment.
    """
    from app.parser_resilience import coerce_float, coerce_severity, get_aliased
    score = coerce_float(get_aliased(entry, _NVD_CVSS_ALIASES['base_score']))
    severity = coerce_severity(get_aliased(entry, _NVD_CVSS_ALIASES['base_severity']))
    if score is not None and severity is None:
        severity = coerce_severity(score)  # derive from numeric band
    return score, severity


def _fetch_cvss_from_nvd(cve_id):
    """
    Fetch CVSS score and severity from NVD API 2.0.
    Returns: (cvss_score, severity) or (None, None) if not found/error.

    R-PARSER-RESILIENCE (post-EA week1): metric extraction goes through
    ``_extract_cvss_entry`` which uses field aliases + type coercion,
    so upstream NVD renames do not silently zero-out enrichment.
    """
    from app.parser_resilience import detect_schema_drift
    try:
        limiter = get_rate_limiter()
        if not limiter.acquire(timeout=30.0, block=True):
            logger.warning(f"NVD rate limit timeout for {cve_id}")
            return None, None

        url = Config.NVD_CVE_API_URL
        params = {'cveId': cve_id}
        kwargs = _get_request_kwargs()

        headers = {}
        api_key = _get_api_key()
        if api_key:
            headers['apiKey'] = api_key

        response = requests.get(url, params=params, headers=headers,
                                timeout=10, **kwargs)

        if response.status_code == 200:
            data = response.json()
            detect_schema_drift('nvd_cve', data)
            vulnerabilities = data.get('vulnerabilities', [])
            if not vulnerabilities:
                return None, None

            metrics = vulnerabilities[0].get('cve', {}).get('metrics', {})

            # Try CVSS v4.0 first, then v3.1, v3.0, then v2.0
            # Prefer NVD Primary scores over CNA Secondary scores
            for metric_key in ('cvssMetricV40', 'cvssMetricV31', 'cvssMetricV30'):
                entries = metrics.get(metric_key, [])
                # First pass: look for NVD Primary score
                for entry in entries:
                    if entry.get('type') == 'Primary':
                        return _extract_cvss_entry(entry)
                # Second pass: accept Secondary (CNA) as fallback
                for entry in entries:
                    if entry.get('type') == 'Secondary':
                        return _extract_cvss_entry(entry)
                # Last resort: any entry
                if entries:
                    return _extract_cvss_entry(entries[0])
            if 'cvssMetricV2' in metrics and metrics['cvssMetricV2']:
                score, severity = _extract_cvss_entry(metrics['cvssMetricV2'][0])
                # CVSS v2 has no baseSeverity field — derive from band
                if score is not None and severity is None:
                    severity = _score_to_severity(score)
                return score, severity

            return None, None

        elif response.status_code == 404:
            return None, None
        else:
            logger.warning(f"NVD API error for {cve_id}: {response.status_code}")
            return None, None

    except Exception as e:
        logger.warning(f"NVD API failed for {cve_id}: {e}")
        return None, None


# ---------------------------------------------------------------------------
# Source 2: CVE.org API (MITRE + CISA Vulnrichment ADP)
# ---------------------------------------------------------------------------

def _extract_cve_org_metric(metric):
    """Extract (score, severity) from a CVE.org metric block.

    CVE 5.x schema nests CVSS as ``cvssV3_1`` or ``cvssV4_0``; alias chain
    absorbs minor variants (cvssV3.1, cvssV4.0, ``cvss``).
    """
    from app.parser_resilience import coerce_float, coerce_severity, get_aliased
    aliases = ['cvssV4_0', 'cvssV3_1', 'cvssV3_0', 'cvssV3.1', 'cvssV4.0', 'cvss']
    for key in aliases:
        cvss = metric.get(key)
        if cvss:
            score = coerce_float(get_aliased(cvss, ['baseScore', 'score']))
            severity = coerce_severity(get_aliased(cvss, ['baseSeverity', 'severity']))
            if score is None and severity is None:
                continue
            if severity is None and score is not None:
                severity = coerce_severity(score)
            return score, severity
    return None, None


def _fetch_cvss_from_cve_org(cve_id):
    """
    Fetch CVSS from CVE.org API which includes CISA Vulnrichment ADP data.
    The ADP container often has CVSS scores even when NVD hasn't processed the CVE.
    License: CVE-TOU (permissive) + CC0 (Vulnrichment).
    Returns: (cvss_score, severity) or (None, None).

    R-PARSER-RESILIENCE: per-metric extraction goes through alias chain
    so MITRE 5.x → 6.x renames do not silently break Vulnrichment lookup.
    """
    from app.parser_resilience import detect_schema_drift
    try:
        url = f"{Config.MITRE_CVE_API_URL}/{cve_id}"
        kwargs = _get_request_kwargs()

        response = requests.get(url, timeout=5, **kwargs)

        if response.status_code != 200:
            return None, None

        data = response.json()
        detect_schema_drift('cve_org', data)

        # ADP containers (Vulnrichment from CISA) — preferred
        adp_containers = data.get('containers', {}).get('adp', [])
        for adp in adp_containers:
            for metric in adp.get('metrics', []):
                score, severity = _extract_cve_org_metric(metric)
                if score is not None:
                    return score, severity

        # CNA container (vendor-provided scores) — fallback
        cna = data.get('containers', {}).get('cna', {})
        for metric in cna.get('metrics', []):
            score, severity = _extract_cve_org_metric(metric)
            if score is not None:
                return score, severity

        return None, None

    except Exception as e:
        logger.warning(f"CVE.org API failed for {cve_id}: {e}")
        return None, None


# ---------------------------------------------------------------------------
# Source 3: ENISA EUVD API (European Vulnerability Database)
# ---------------------------------------------------------------------------

# R-PARSER-RESILIENCE alias map for EUVD CVSS extraction.
_EUVD_CVSS_ALIASES = {
    'base_score':    ['baseScore', 'cvssScore', 'cvss.baseScore', 'score', 'cvssData.baseScore'],
    'base_severity': ['baseSeverity', 'severity', 'cvss.baseSeverity'],
}


def _fetch_cvss_from_euvd(cve_id):
    """
    Fetch CVSS from ENISA European Vulnerability Database.
    NIS2-mandated EU source. No authentication required.
    License: ENISA IPR Policy (attribution required).
    Returns: (cvss_score, severity) or (None, None).

    R-PARSER-RESILIENCE: extraction goes through alias chain + coercion
    so an ENISA-side rename (recurring per audit, see SCHEMA_CHANGED
    finding 2026-05-06) does not zero-out enrichment silently.
    """
    from app.parser_resilience import (
        coerce_float, coerce_severity, detect_schema_drift, get_aliased,
    )
    try:
        url = "https://euvdservices.enisa.europa.eu/api/search"
        params = {'cveId': cve_id}
        kwargs = _get_request_kwargs()

        response = requests.get(url, params=params, timeout=5, **kwargs)

        if response.status_code != 200:
            return None, None

        data = response.json()
        detect_schema_drift('euvd', data)

        # EUVD returns a list — accept multiple envelope shapes
        items = data.get('items') or data.get('results') or data.get('data') or []
        if not items:
            return None, None

        item = items[0]
        score = coerce_float(get_aliased(item, _EUVD_CVSS_ALIASES['base_score']))
        if score is None:
            return None, None
        severity = coerce_severity(get_aliased(item, _EUVD_CVSS_ALIASES['base_severity']))
        if severity is None:
            severity = _score_to_severity(score)
        return score, severity

    except Exception as e:
        logger.warning(f"EUVD API failed for {cve_id}: {e}")
        return None, None


# ---------------------------------------------------------------------------
# Public API: Multi-source fetch with fallback chain
# ---------------------------------------------------------------------------

def fetch_cvss_data(cve_id):
    """
    Fetch CVSS score and severity using a multi-source fallback chain:
      1. NVD API 2.0 (NIST) - primary
      2. CVE.org + CISA Vulnrichment (ADP) - secondary
      3. ENISA EUVD - tertiary (European source)

    Returns: (cvss_score, severity, source) or (None, None, None) if not found.
    The 'source' string indicates which source provided the data.
    """
    # Source 1: NVD (primary)
    score, severity = _fetch_cvss_from_nvd(cve_id)
    if score is not None:
        return score, severity, 'nvd'

    # Source 2: CVE.org + Vulnrichment (secondary)
    score, severity = _fetch_cvss_from_cve_org(cve_id)
    if score is not None:
        logger.info(f"CVSS for {cve_id} from CVE.org/Vulnrichment (NVD miss)")
        return score, severity, 'cve_org'

    # Source 3: ENISA EUVD (tertiary)
    score, severity = _fetch_cvss_from_euvd(cve_id)
    if score is not None:
        logger.info(f"CVSS for {cve_id} from ENISA EUVD (NVD+CVE.org miss)")
        return score, severity, 'euvd'

    return None, None, None


def fetch_cve_details(cve_id):
    """
    Fetch full CVE details from NVD API 2.0 for creating new vulnerability entries.

    Used when EUVD reports a CVE that isn't in CISA KEV yet — we need
    description, vendor/product, CVSS, and CPE data to create a usable record.

    Returns:
        dict with keys: description, vendor, product, cvss_score, severity,
                        vulnerability_name, cpe_entries
        or None if not found.
    """
    try:
        limiter = get_rate_limiter()
        if not limiter.acquire(timeout=30.0, block=True):
            logger.warning(f"NVD rate limit timeout for {cve_id}")
            return None

        url = Config.NVD_CVE_API_URL
        params = {'cveId': cve_id}
        kwargs = _get_request_kwargs()

        headers = {}
        api_key = _get_api_key()
        if api_key:
            headers['apiKey'] = api_key

        response = requests.get(url, params=params, headers=headers,
                                timeout=15, **kwargs)

        if response.status_code != 200:
            logger.warning(f"NVD API error for {cve_id}: {response.status_code}")
            return None

        data = response.json()
        vulnerabilities = data.get('vulnerabilities', [])
        if not vulnerabilities:
            return None

        cve_data = vulnerabilities[0].get('cve', {})
        result = {
            'description': '',
            'vendor': '',
            'product': '',
            'vulnerability_name': '',
            'cvss_score': None,
            'severity': None,
            'cpe_entries': [],
        }

        # Extract English description
        descriptions = cve_data.get('descriptions', [])
        for desc in descriptions:
            if desc.get('lang') == 'en':
                result['description'] = desc.get('value', '')
                result['vulnerability_name'] = desc.get('value', '')[:500]
                break

        # Extract CVSS score
        metrics = cve_data.get('metrics', {})
        if 'cvssMetricV31' in metrics and metrics['cvssMetricV31']:
            cvss_data = metrics['cvssMetricV31'][0]['cvssData']
            result['cvss_score'] = cvss_data.get('baseScore')
            result['severity'] = cvss_data.get('baseSeverity')
        elif 'cvssMetricV30' in metrics and metrics['cvssMetricV30']:
            cvss_data = metrics['cvssMetricV30'][0]['cvssData']
            result['cvss_score'] = cvss_data.get('baseScore')
            result['severity'] = cvss_data.get('baseSeverity')

        # Extract CPE entries with version ranges + vendor/product
        from app.nvd_cpe_api import parse_cpe_uri
        configurations = cve_data.get('configurations', [])
        for config in configurations:
            for node in config.get('nodes', []):
                for match in node.get('cpeMatch', []):
                    if not match.get('vulnerable', False):
                        continue
                    cpe_uri = match.get('criteria', '')
                    parsed = parse_cpe_uri(cpe_uri)

                    # Use first vendor/product as the CVE's vendor/product
                    if not result['vendor'] and parsed.get('vendor'):
                        result['vendor'] = parsed['vendor'].replace('_', ' ').title()
                    if not result['product'] and parsed.get('product'):
                        result['product'] = parsed['product'].replace('_', ' ').title()

                    cpe_version = parsed.get('version', '*')
                    has_range = (match.get('versionStartIncluding') or match.get('versionStartExcluding')
                                or match.get('versionEndIncluding') or match.get('versionEndExcluding'))

                    result['cpe_entries'].append({
                        'cpe_uri': cpe_uri,
                        'vendor': parsed.get('vendor', ''),
                        'product': parsed.get('product', ''),
                        'version_start': match.get('versionStartIncluding') or match.get('versionStartExcluding'),
                        'version_end': match.get('versionEndIncluding') or match.get('versionEndExcluding'),
                        'version_start_type': 'including' if match.get('versionStartIncluding') else 'excluding' if match.get('versionStartExcluding') else None,
                        'version_end_type': 'including' if match.get('versionEndIncluding') else 'excluding' if match.get('versionEndExcluding') else None,
                        'exact_version': cpe_version if (not has_range and cpe_version not in ('*', '-', '')) else None,
                    })

        return result

    except Exception as e:
        logger.warning(f"NVD CVE detail fetch failed for {cve_id}: {e}")
        return None


def fetch_cvss_batch(cve_ids, max_retries=3):
    """
    Fetch CVSS data for multiple CVEs using the multi-source fallback chain.

    Args:
        cve_ids: List of CVE IDs to fetch
        max_retries: Number of retry attempts per CVE

    Returns:
        dict of {cve_id: (cvss_score, severity, source)}
    """
    results = {}
    total = len(cve_ids)

    for idx, cve_id in enumerate(cve_ids, 1):
        if idx % 10 == 0 or idx == total:
            logger.info(f"Fetching CVSS data: {idx}/{total}")

        retries = 0
        while retries < max_retries:
            cvss_score, severity, source = fetch_cvss_data(cve_id)

            if cvss_score is not None or retries == max_retries - 1:
                results[cve_id] = (cvss_score, severity, source)
                break

            retries += 1
            time.sleep(1)

    return results
