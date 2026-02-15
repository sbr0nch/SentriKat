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
                except Exception:
                    return setting.value
            return setting.value
    except Exception:
        pass

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

def _fetch_cvss_from_nvd(cve_id):
    """
    Fetch CVSS score and severity from NVD API 2.0.
    Returns: (cvss_score, severity) or (None, None) if not found/error.
    """
    try:
        limiter = get_rate_limiter()
        if not limiter.acquire(timeout=30.0, block=True):
            logger.warning(f"NVD rate limit timeout for {cve_id}")
            return None, None

        url = "https://services.nvd.nist.gov/rest/json/cves/2.0"
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
            vulnerabilities = data.get('vulnerabilities', [])
            if not vulnerabilities:
                return None, None

            metrics = vulnerabilities[0].get('cve', {}).get('metrics', {})

            # Try CVSS v3.1 first, then v3.0, then v2.0
            if 'cvssMetricV31' in metrics and metrics['cvssMetricV31']:
                cvss_data = metrics['cvssMetricV31'][0]['cvssData']
                return cvss_data.get('baseScore'), cvss_data.get('baseSeverity')
            elif 'cvssMetricV30' in metrics and metrics['cvssMetricV30']:
                cvss_data = metrics['cvssMetricV30'][0]['cvssData']
                return cvss_data.get('baseScore'), cvss_data.get('baseSeverity')
            elif 'cvssMetricV2' in metrics and metrics['cvssMetricV2']:
                cvss_data = metrics['cvssMetricV2'][0]['cvssData']
                score = cvss_data.get('baseScore')
                return score, _score_to_severity(score)

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

def _fetch_cvss_from_cve_org(cve_id):
    """
    Fetch CVSS from CVE.org API which includes CISA Vulnrichment ADP data.
    The ADP container often has CVSS scores even when NVD hasn't processed the CVE.
    License: CVE-TOU (permissive) + CC0 (Vulnrichment).
    Returns: (cvss_score, severity) or (None, None).
    """
    try:
        url = f"https://cveawg.mitre.org/api/cve/{cve_id}"
        kwargs = _get_request_kwargs()

        response = requests.get(url, timeout=5, **kwargs)

        if response.status_code != 200:
            return None, None

        data = response.json()

        # Check ADP containers first (Vulnrichment data from CISA)
        adp_containers = data.get('containers', {}).get('adp', [])
        for adp in adp_containers:
            metrics = adp.get('metrics', [])
            for metric in metrics:
                # CVSS v3.1
                if 'cvssV3_1' in metric:
                    cvss = metric['cvssV3_1']
                    return cvss.get('baseScore'), cvss.get('baseSeverity')
                # CVSS v3.0
                if 'cvssV3_0' in metric:
                    cvss = metric['cvssV3_0']
                    return cvss.get('baseScore'), cvss.get('baseSeverity')

        # Check CNA container (vendor-provided scores)
        cna = data.get('containers', {}).get('cna', {})
        cna_metrics = cna.get('metrics', [])
        for metric in cna_metrics:
            if 'cvssV3_1' in metric:
                cvss = metric['cvssV3_1']
                return cvss.get('baseScore'), cvss.get('baseSeverity')
            if 'cvssV3_0' in metric:
                cvss = metric['cvssV3_0']
                return cvss.get('baseScore'), cvss.get('baseSeverity')

        return None, None

    except Exception as e:
        logger.warning(f"CVE.org API failed for {cve_id}: {e}")
        return None, None


# ---------------------------------------------------------------------------
# Source 3: ENISA EUVD API (European Vulnerability Database)
# ---------------------------------------------------------------------------

def _fetch_cvss_from_euvd(cve_id):
    """
    Fetch CVSS from ENISA European Vulnerability Database.
    NIS2-mandated EU source. No authentication required.
    License: ENISA IPR Policy (attribution required).
    Returns: (cvss_score, severity) or (None, None).
    """
    try:
        url = "https://euvdservices.enisa.europa.eu/api/search"
        params = {'cveId': cve_id}
        kwargs = _get_request_kwargs()

        response = requests.get(url, params=params, timeout=5, **kwargs)

        if response.status_code != 200:
            return None, None

        data = response.json()

        # EUVD returns a list of items
        items = data.get('items', [])
        if not items:
            return None, None

        item = items[0]
        score = item.get('baseScore') or item.get('cvssScore')
        if score is not None:
            score = float(score)
            severity = item.get('baseSeverity') or _score_to_severity(score)
            if severity:
                severity = severity.upper()
            return score, severity

        return None, None

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
