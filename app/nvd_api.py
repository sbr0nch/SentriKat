"""
NVD API integration for fetching CVE severity and CVSS scores
"""
import requests
import time
from config import Config

def fetch_cvss_data(cve_id):
    """
    Fetch CVSS score and severity from NVD API 2.0
    Returns: (cvss_score, severity) or (None, None) if not found
    """
    try:
        # NVD API 2.0 endpoint
        url = f"https://services.nvd.nist.gov/rest/json/cves/2.0"
        params = {'cveId': cve_id}

        proxies = Config.get_proxies()

        # Add delay to respect NVD rate limits (5 requests per 30 seconds for public API)
        time.sleep(0.6)  # 600ms delay

        response = requests.get(
            url,
            params=params,
            timeout=10,
            proxies=proxies,
            verify=True
        )

        if response.status_code == 200:
            data = response.json()

            # Navigate the NVD API 2.0 structure
            vulnerabilities = data.get('vulnerabilities', [])
            if not vulnerabilities:
                return None, None

            cve = vulnerabilities[0].get('cve', {})
            metrics = cve.get('metrics', {})

            # Try CVSS v3.1 first, then v3.0, then v2.0
            cvss_score = None
            severity = None

            # CVSS v3.1
            if 'cvssMetricV31' in metrics and metrics['cvssMetricV31']:
                cvss_data = metrics['cvssMetricV31'][0]['cvssData']
                cvss_score = cvss_data.get('baseScore')
                severity = cvss_data.get('baseSeverity')
            # CVSS v3.0
            elif 'cvssMetricV30' in metrics and metrics['cvssMetricV30']:
                cvss_data = metrics['cvssMetricV30'][0]['cvssData']
                cvss_score = cvss_data.get('baseScore')
                severity = cvss_data.get('baseSeverity')
            # CVSS v2.0 (fallback)
            elif 'cvssMetricV2' in metrics and metrics['cvssMetricV2']:
                cvss_data = metrics['cvssMetricV2'][0]['cvssData']
                cvss_score = cvss_data.get('baseScore')
                # Convert CVSS v2 score to severity
                if cvss_score:
                    if cvss_score >= 9.0:
                        severity = 'CRITICAL'
                    elif cvss_score >= 7.0:
                        severity = 'HIGH'
                    elif cvss_score >= 4.0:
                        severity = 'MEDIUM'
                    else:
                        severity = 'LOW'

            return cvss_score, severity

        elif response.status_code == 404:
            # CVE not found in NVD yet
            return None, None
        else:
            print(f"NVD API error for {cve_id}: {response.status_code}")
            return None, None

    except Exception as e:
        print(f"Error fetching CVSS for {cve_id}: {str(e)}")
        return None, None

def fetch_cvss_batch(cve_ids, max_retries=3):
    """
    Fetch CVSS data for multiple CVEs with progress tracking
    Returns: dict of {cve_id: (cvss_score, severity)}
    """
    results = {}
    total = len(cve_ids)

    for idx, cve_id in enumerate(cve_ids, 1):
        print(f"Fetching CVSS data: {idx}/{total} ({cve_id})")

        retries = 0
        while retries < max_retries:
            cvss_score, severity = fetch_cvss_data(cve_id)

            if cvss_score is not None or retries == max_retries - 1:
                results[cve_id] = (cvss_score, severity)
                break

            retries += 1
            time.sleep(1)  # Wait before retry

    return results
