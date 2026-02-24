"""
OSV.dev API client for querying open-source vulnerability data.

OSV (Open Source Vulnerabilities) provides definitive, precise vulnerability
data for open-source packages. Unlike NVD/CPE-based matching, OSV uses
package ecosystem + version directly — no CPE mapping guesswork needed.

API docs: https://osv.dev/docs/
Rate limits: No API key required. Recommended max 100 queries per batch.
"""

import logging
import time
import requests
from datetime import datetime

logger = logging.getLogger(__name__)

OSV_API_BASE = 'https://api.osv.dev/v1'
OSV_QUERY_URL = f'{OSV_API_BASE}/query'
OSV_QUERYBATCH_URL = f'{OSV_API_BASE}/querybatch'
OSV_VULN_URL = f'{OSV_API_BASE}/vulns'

# Maximum queries per batch (OSV limit is 1000, we use 100 for reliability)
MAX_BATCH_SIZE = 100

# Request timeout (seconds)
REQUEST_TIMEOUT = 30

# Retry settings
MAX_RETRIES = 3
RETRY_BACKOFF_BASE = 2  # seconds


class OSVVulnerability:
    """Parsed vulnerability from OSV response."""

    __slots__ = (
        'id', 'aliases', 'summary', 'details', 'severity',
        'cvss_score', 'cvss_vector', 'affected_ranges',
        'fixed_versions', 'references', 'published', 'modified',
        'database_specific', 'ecosystem',
    )

    def __init__(self, data, queried_ecosystem=None):
        if not isinstance(data, dict):
            data = {}
        self.id = str(data.get('id', ''))[:100]
        self.aliases = data.get('aliases', []) if isinstance(data.get('aliases'), list) else []
        self.summary = str(data.get('summary', ''))[:2000]
        self.details = str(data.get('details', ''))[:10000]
        self.ecosystem = queried_ecosystem
        self.published = data.get('published')
        self.modified = data.get('modified')
        self.database_specific = data.get('database_specific', {}) if isinstance(data.get('database_specific'), dict) else {}

        # Extract severity/CVSS
        self.severity = None
        self.cvss_score = None
        self.cvss_vector = None
        self._parse_severity(data)

        # Extract affected ranges and fix versions
        self.affected_ranges = []
        self.fixed_versions = []
        self._parse_affected(data, queried_ecosystem)

        # Extract references
        self.references = []
        refs = data.get('references', [])
        if isinstance(refs, list):
            for ref in refs[:50]:  # Cap references to prevent memory issues
                if isinstance(ref, dict):
                    self.references.append({
                        'type': str(ref.get('type', ''))[:50],
                        'url': str(ref.get('url', ''))[:500],
                    })

    def _parse_severity(self, data):
        """Extract severity info from OSV vulnerability data."""
        severity_list = data.get('severity', [])
        for sev in severity_list:
            score_type = sev.get('type', '')
            score_value = sev.get('score', '')

            if score_type == 'CVSS_V3':
                self.cvss_vector = score_value
                # Extract numeric score from CVSS vector
                self.cvss_score = _extract_cvss_score(score_value)
                if self.cvss_score is not None:
                    self.severity = _cvss_to_severity(self.cvss_score)
                break

        # Fallback: try database_specific severity
        if not self.severity:
            db_spec = data.get('database_specific', {})
            if 'severity' in db_spec:
                self.severity = db_spec['severity'].upper()

    def _parse_affected(self, data, queried_ecosystem):
        """Extract affected version ranges and fix versions."""
        for affected in data.get('affected', []):
            pkg = affected.get('package', {})
            pkg_ecosystem = pkg.get('ecosystem', '')

            # Match ecosystem if specified
            if queried_ecosystem and pkg_ecosystem != queried_ecosystem:
                continue

            for rng in affected.get('ranges', []):
                range_type = rng.get('type', '')
                events = rng.get('events', [])

                range_info = {
                    'type': range_type,
                    'events': events,
                }
                self.affected_ranges.append(range_info)

                # Extract fix versions from 'fixed' events
                for event in events:
                    if 'fixed' in event:
                        self.fixed_versions.append(event['fixed'])

            # Also check 'versions' list (explicit affected versions)
            versions = affected.get('versions', [])
            if versions:
                self.affected_ranges.append({
                    'type': 'EXPLICIT',
                    'versions': versions,
                })

    @property
    def cve_id(self):
        """Get the CVE ID from aliases, if any."""
        for alias in self.aliases:
            if alias.startswith('CVE-'):
                return alias
        return None

    @property
    def primary_url(self):
        """Get the primary advisory URL."""
        for ref in self.references:
            if ref['type'] == 'ADVISORY':
                return ref['url']
        # Fallback to OSV page
        return f'https://osv.dev/vulnerability/{self.id}'

    def to_dict(self):
        return {
            'id': self.id,
            'cve_id': self.cve_id,
            'aliases': self.aliases,
            'summary': self.summary,
            'severity': self.severity,
            'cvss_score': self.cvss_score,
            'cvss_vector': self.cvss_vector,
            'fixed_versions': self.fixed_versions,
            'primary_url': self.primary_url,
            'published': self.published,
            'modified': self.modified,
        }


def _extract_cvss_score(cvss_vector):
    """Extract numeric CVSS score from a CVSS v3 vector string."""
    if not cvss_vector:
        return None
    # Some vectors include the score directly
    # Format: CVSS:3.1/AV:N/AC:L/...
    # We need to calculate it, but for simplicity, check if score is embedded
    # The OSV API doesn't always provide a numeric score, so we estimate from severity
    try:
        # Try to find embedded score (some sources include it)
        if '/' in cvss_vector:
            # Parse CVSS vector to estimate severity
            parts = cvss_vector.split('/')
            # Basic CVSS v3 base score estimation from vector
            av_score = {'N': 0.85, 'A': 0.62, 'L': 0.55, 'P': 0.20}
            ac_score = {'L': 0.77, 'H': 0.44}

            av = ac = None
            for p in parts:
                if p.startswith('AV:'):
                    av = av_score.get(p[3:], 0.55)
                elif p.startswith('AC:'):
                    ac = ac_score.get(p[3:], 0.44)

            if av and ac:
                # Very rough estimate — good enough for severity classification
                base = (av + ac) * 5
                return round(min(10.0, max(0.0, base)), 1)
    except Exception:
        pass
    return None


def _cvss_to_severity(score):
    """Convert CVSS score to severity label."""
    if score is None:
        return None
    if score >= 9.0:
        return 'CRITICAL'
    if score >= 7.0:
        return 'HIGH'
    if score >= 4.0:
        return 'MEDIUM'
    if score >= 0.1:
        return 'LOW'
    return 'NONE'


def query_osv(package_name, version, ecosystem):
    """
    Query OSV for vulnerabilities affecting a specific package version.

    Args:
        package_name: Package name (e.g., 'express', 'requests')
        version: Exact version (e.g., '4.17.1', '2.28.0')
        ecosystem: OSV ecosystem name (e.g., 'npm', 'PyPI', 'crates.io')

    Returns:
        list[OSVVulnerability] or None on error
    """
    payload = {
        'version': version,
        'package': {
            'name': package_name,
            'ecosystem': ecosystem,
        }
    }

    for attempt in range(MAX_RETRIES):
        try:
            response = requests.post(
                OSV_QUERY_URL,
                json=payload,
                timeout=REQUEST_TIMEOUT,
                headers={'Content-Type': 'application/json'},
            )

            if response.status_code == 200:
                data = response.json()
                vulns = data.get('vulns', [])
                return [OSVVulnerability(v, ecosystem) for v in vulns]

            if response.status_code == 429:
                wait = RETRY_BACKOFF_BASE ** (attempt + 1)
                logger.warning(f"OSV rate limit hit, retrying in {wait}s")
                time.sleep(wait)
                continue

            logger.warning(f"OSV query failed for {ecosystem}/{package_name}@{version}: HTTP {response.status_code}")
            return None

        except requests.exceptions.Timeout:
            logger.warning(f"OSV query timeout for {ecosystem}/{package_name}@{version} (attempt {attempt + 1})")
            if attempt < MAX_RETRIES - 1:
                time.sleep(RETRY_BACKOFF_BASE ** (attempt + 1))
            continue
        except requests.exceptions.RequestException as e:
            logger.error(f"OSV query error for {ecosystem}/{package_name}@{version}: {e}")
            return None

    return None


def query_osv_batch(queries):
    """
    Query OSV for multiple packages in a single batch request.

    Args:
        queries: list of dicts with 'name', 'version', 'ecosystem' keys

    Returns:
        dict mapping (ecosystem, name, version) -> list[OSVVulnerability]
        Returns empty dict on error.
    """
    if not queries:
        return {}

    results = {}

    # Process in chunks of MAX_BATCH_SIZE
    for chunk_start in range(0, len(queries), MAX_BATCH_SIZE):
        chunk = queries[chunk_start:chunk_start + MAX_BATCH_SIZE]

        osv_queries = []
        query_keys = []

        for q in chunk:
            name = q.get('name', '')
            version = q.get('version', '')
            ecosystem = q.get('ecosystem', '')

            if not name or not version or not ecosystem:
                continue

            osv_queries.append({
                'version': version,
                'package': {
                    'name': name,
                    'ecosystem': ecosystem,
                }
            })
            query_keys.append((ecosystem, name, version))

        if not osv_queries:
            continue

        payload = {'queries': osv_queries}

        for attempt in range(MAX_RETRIES):
            try:
                response = requests.post(
                    OSV_QUERYBATCH_URL,
                    json=payload,
                    timeout=REQUEST_TIMEOUT * 2,  # Longer timeout for batch
                    headers={'Content-Type': 'application/json'},
                )

                if response.status_code == 200:
                    data = response.json()
                    batch_results = data.get('results', [])

                    for i, result in enumerate(batch_results):
                        if i >= len(query_keys):
                            break
                        key = query_keys[i]
                        vulns_data = result.get('vulns', [])
                        if vulns_data:
                            results[key] = [OSVVulnerability(v, key[0]) for v in vulns_data]
                    break  # Success, move to next chunk

                if response.status_code == 429:
                    wait = RETRY_BACKOFF_BASE ** (attempt + 1)
                    logger.warning(f"OSV batch rate limit, retrying in {wait}s")
                    time.sleep(wait)
                    continue

                logger.warning(f"OSV batch query failed: HTTP {response.status_code}")
                break  # Non-retryable error

            except requests.exceptions.Timeout:
                logger.warning(f"OSV batch timeout (attempt {attempt + 1})")
                if attempt < MAX_RETRIES - 1:
                    time.sleep(RETRY_BACKOFF_BASE ** (attempt + 1))
                continue
            except requests.exceptions.RequestException as e:
                logger.error(f"OSV batch error: {e}")
                break

        # Small delay between chunks to be respectful
        if chunk_start + MAX_BATCH_SIZE < len(queries):
            time.sleep(0.5)

    return results


def scan_dependencies_osv(dependencies):
    """
    Scan a list of dependencies against OSV and return vulnerability results.

    This is the main entry point used by the agent API to scan lock file
    dependencies.

    Args:
        dependencies: list of dicts with 'name', 'version', 'ecosystem' keys
                      (as returned by lockfile_parser.parse_lockfiles_batch)

    Returns:
        dict with:
            'vulnerable': list of {dependency, vulnerabilities} dicts
            'clean': count of dependencies with no vulnerabilities
            'errors': count of query failures
            'stats': scan statistics
    """
    if not dependencies:
        return {
            'vulnerable': [],
            'clean': 0,
            'errors': 0,
            'stats': {'total_scanned': 0, 'total_vulnerabilities': 0},
        }

    start_time = time.time()

    # Build query list (deduplicate by ecosystem+name+version)
    seen = set()
    unique_queries = []
    dep_to_query_key = {}  # Map dep index -> query key for result lookup

    for i, dep in enumerate(dependencies):
        key = (dep.get('ecosystem', ''), dep.get('name', ''), dep.get('version', ''))
        if key[0] and key[1] and key[2]:
            dep_to_query_key[i] = key
            if key not in seen:
                seen.add(key)
                unique_queries.append({
                    'name': key[1],
                    'version': key[2],
                    'ecosystem': key[0],
                })

    logger.info(f"OSV scan: {len(unique_queries)} unique packages from {len(dependencies)} total deps")

    # Batch query OSV
    osv_results = query_osv_batch(unique_queries)

    # Map results back to dependencies
    vulnerable = []
    clean_count = 0
    error_count = 0
    total_vulns = 0

    # Group vulnerabilities by (ecosystem, name, version)
    vuln_by_key = {}
    for key, vulns in osv_results.items():
        if vulns:
            vuln_by_key[key] = vulns

    # Process each dependency
    processed_keys = set()
    for i, dep in enumerate(dependencies):
        key = dep_to_query_key.get(i)
        if not key:
            error_count += 1
            continue

        # Only report each unique package once
        if key in processed_keys:
            continue
        processed_keys.add(key)

        vulns = vuln_by_key.get(key)
        if vulns:
            vuln_dicts = [v.to_dict() for v in vulns]
            vulnerable.append({
                'name': dep['name'],
                'version': dep['version'],
                'ecosystem': dep['ecosystem'],
                'is_direct': dep.get('is_direct', False),
                'purl': dep.get('purl'),
                'source_file': dep.get('source_file'),
                'vulnerabilities': vuln_dicts,
            })
            total_vulns += len(vulns)
        else:
            clean_count += 1

    elapsed = time.time() - start_time
    logger.info(
        f"OSV scan complete: {len(vulnerable)} vulnerable, {clean_count} clean, "
        f"{total_vulns} total vulns in {elapsed:.1f}s"
    )

    return {
        'vulnerable': vulnerable,
        'clean': clean_count,
        'errors': error_count,
        'stats': {
            'total_scanned': len(processed_keys),
            'unique_packages': len(unique_queries),
            'total_vulnerabilities': total_vulns,
            'vulnerable_packages': len(vulnerable),
            'clean_packages': clean_count,
            'scan_duration_seconds': round(elapsed, 2),
        },
    }
