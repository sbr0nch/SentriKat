"""
NVD CPE API integration for searching and matching software products.

Uses the NVD CPE API 2.0 for on-demand product searches:
https://services.nvd.nist.gov/rest/json/cpes/2.0

Rate Limits:
- Without API key: 5 requests per 30 seconds (0.6s delay)
- With API key: 50 requests per 30 seconds (free key from NVD)
"""
import requests
import time
import re
import json
import logging
from datetime import datetime, timedelta
from functools import lru_cache
from threading import Lock
from typing import Optional, Dict, List, Tuple, Any
from config import Config
import urllib3

logger = logging.getLogger(__name__)


# In-memory cache for CPE searches (15-minute TTL)
_cpe_cache: Dict[str, Tuple[List[Dict], datetime]] = {}
_cache_lock = Lock()
_last_request_time: float = 0
_request_lock = Lock()

# Cache TTL (15 minutes)
CACHE_TTL_MINUTES = 15

# Rate limiting: 5 requests per 30 seconds = 0.6s delay
# With API key: 50 requests per 30 seconds = 0.06s delay
MIN_REQUEST_DELAY = 0.6  # Default (no API key)


def _get_api_key() -> Optional[str]:
    """
    Get NVD API key with priority: Database > Environment Variable.

    This allows containerized deployments to set the API key via
    the NVD_API_KEY environment variable.
    """
    import os

    try:
        # First, check database (UI-configured)
        from app.models import SystemSettings
        from app.encryption import decrypt_value

        setting = SystemSettings.query.filter_by(key='nvd_api_key').first()
        if setting and setting.value:
            # Decrypt if encrypted
            if setting.is_encrypted:
                try:
                    return decrypt_value(setting.value)
                except Exception:
                    return setting.value  # Return raw if decrypt fails
            return setting.value
    except Exception:
        pass

    # Fallback to environment variable
    return os.environ.get('NVD_API_KEY')


def _get_request_delay() -> float:
    """Get appropriate delay based on API key availability."""
    api_key = _get_api_key()
    if api_key:
        return 0.06  # 50 requests per 30 seconds with API key
    return MIN_REQUEST_DELAY  # 5 requests per 30 seconds without key


def _rate_limit():
    """Enforce rate limiting between NVD API requests."""
    global _last_request_time

    with _request_lock:
        delay = _get_request_delay()
        elapsed = time.time() - _last_request_time
        if elapsed < delay:
            time.sleep(delay - elapsed)
        _last_request_time = time.time()


def _get_cache_key(query: str, **params) -> str:
    """Generate cache key from query parameters."""
    param_str = json.dumps(params, sort_keys=True)
    return f"{query}:{param_str}"


def _get_cached_result(cache_key: str) -> Optional[List[Dict]]:
    """Get cached result if not expired."""
    with _cache_lock:
        if cache_key in _cpe_cache:
            results, timestamp = _cpe_cache[cache_key]
            if datetime.now() - timestamp < timedelta(minutes=CACHE_TTL_MINUTES):
                return results
            else:
                del _cpe_cache[cache_key]
    return None


def _set_cached_result(cache_key: str, results: List[Dict]):
    """Store results in cache."""
    with _cache_lock:
        _cpe_cache[cache_key] = (results, datetime.now())


def _clean_expired_cache():
    """Remove expired entries from cache."""
    with _cache_lock:
        now = datetime.now()
        expired_keys = [
            key for key, (_, timestamp) in _cpe_cache.items()
            if now - timestamp >= timedelta(minutes=CACHE_TTL_MINUTES)
        ]
        for key in expired_keys:
            del _cpe_cache[key]


def parse_cpe_uri(cpe_uri: str) -> Dict[str, str]:
    """
    Parse a CPE 2.3 URI into components.

    CPE 2.3 format: cpe:2.3:part:vendor:product:version:update:edition:language:sw_edition:target_sw:target_hw:other

    Example: cpe:2.3:a:apache:tomcat:10.1.18:*:*:*:*:*:*:*

    Returns dict with: part, vendor, product, version, update, edition, etc.
    """
    result = {
        'part': None,         # a=application, o=operating system, h=hardware
        'vendor': None,
        'product': None,
        'version': None,
        'update': None,
        'edition': None,
        'language': None,
        'sw_edition': None,
        'target_sw': None,
        'target_hw': None,
        'other': None,
        'raw_uri': cpe_uri
    }

    if not cpe_uri or not cpe_uri.startswith('cpe:'):
        return result

    # Handle both CPE 2.2 and 2.3 formats
    if cpe_uri.startswith('cpe:2.3:'):
        # CPE 2.3 format
        parts = cpe_uri.split(':')
        field_names = ['', '', 'part', 'vendor', 'product', 'version', 'update',
                       'edition', 'language', 'sw_edition', 'target_sw', 'target_hw', 'other']
        for i, name in enumerate(field_names):
            if name and i < len(parts):
                value = parts[i]
                if value != '*' and value != '-':
                    result[name] = value
    else:
        # CPE 2.2 format (URI binding): cpe:/part:vendor:product:version:...
        match = re.match(r'cpe:/([aoh]):([^:]+):([^:]+)(?::([^:]+))?', cpe_uri)
        if match:
            result['part'] = match.group(1)
            result['vendor'] = match.group(2)
            result['product'] = match.group(3)
            if match.group(4):
                result['version'] = match.group(4)

    return result


def build_cpe_uri(vendor: str, product: str, version: str = '*', part: str = 'a') -> str:
    """
    Build a CPE 2.3 URI from components.

    Args:
        vendor: Vendor name (will be normalized)
        product: Product name (will be normalized)
        version: Version string (default: * for any)
        part: CPE part (a=application, o=os, h=hardware)

    Returns:
        CPE 2.3 URI string
    """
    def normalize(s: str) -> str:
        """Normalize string for CPE format."""
        if not s or s == '*':
            return '*'
        # Lowercase, replace spaces with underscores
        return s.lower().replace(' ', '_').replace('-', '_')

    return f"cpe:2.3:{part}:{normalize(vendor)}:{normalize(product)}:{normalize(version)}:*:*:*:*:*:*:*"


def search_cpe(
    keyword: str,
    limit: int = 50,
    exact_match: bool = False,
    include_deprecated: bool = False
) -> List[Dict]:
    """
    Search NVD CPE database for matching products.

    Args:
        keyword: Search term (vendor, product name, etc.)
        limit: Maximum results to return (max 2000)
        exact_match: If True, use exact match instead of keyword search
        include_deprecated: If True, include deprecated CPE entries

    Returns:
        List of matched CPE entries with parsed data
    """
    if not keyword or len(keyword) < 2:
        return []

    # Check cache first
    cache_key = _get_cache_key(keyword, limit=limit, exact_match=exact_match)
    cached = _get_cached_result(cache_key)
    if cached is not None:
        return cached

    # Build API request
    url = "https://services.nvd.nist.gov/rest/json/cpes/2.0"
    params = {
        'resultsPerPage': min(limit, 2000),
        'startIndex': 0
    }

    if exact_match:
        # Use CPE match string for exact matching
        params['cpeMatchString'] = f"cpe:2.3:*:*{keyword}*"
    else:
        # Keyword search (NVD API doesn't accept keywordExactMatch parameter)
        params['keywordSearch'] = keyword

    # Get API key if available
    api_key = _get_api_key()
    headers = {}
    if api_key:
        headers['apiKey'] = api_key

    # Rate limit and make request
    _rate_limit()

    try:
        proxies = Config.get_proxies()
        verify_ssl = Config.get_verify_ssl()

        if not verify_ssl:
            urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

        response = requests.get(
            url,
            params=params,
            headers=headers,
            timeout=15,
            proxies=proxies,
            verify=verify_ssl
        )

        if response.status_code == 200:
            data = response.json()
            products = data.get('products', [])

            # Parse and format results
            results = []
            for product in products:
                cpe_data = product.get('cpe', {})
                cpe_uri = cpe_data.get('cpeName', '')

                # Skip deprecated unless requested
                if not include_deprecated and cpe_data.get('deprecated', False):
                    continue

                parsed = parse_cpe_uri(cpe_uri)

                # Extract title (human-readable name)
                titles = cpe_data.get('titles', [])
                title = titles[0].get('title') if titles else None

                # Build result entry
                result = {
                    'cpe_uri': cpe_uri,
                    'cpe_name_id': cpe_data.get('cpeNameId'),
                    'vendor': parsed['vendor'],
                    'product': parsed['product'],
                    'version': parsed['version'],
                    'title': title,
                    'part': parsed['part'],
                    'deprecated': cpe_data.get('deprecated', False),
                    'last_modified': cpe_data.get('lastModified'),
                    'references': cpe_data.get('refs', [])
                }
                results.append(result)

            # Group by vendor/product for cleaner display
            _set_cached_result(cache_key, results)
            return results

        elif response.status_code == 404:
            return []
        elif response.status_code == 403:
            logger.warning("NVD CPE API rate limit exceeded")
            return []
        else:
            logger.error(f"NVD CPE API error: {response.status_code}")
            return []

    except requests.exceptions.Timeout:
        logger.warning("NVD CPE API timeout")
        return []
    except Exception as e:
        logger.error(f"NVD CPE API error: {str(e)}")
        return []


def search_cpe_grouped(
    keyword: str,
    limit: int = 100
) -> Dict[str, Dict[str, Any]]:
    """
    Search CPE and return results grouped by vendor/product.

    Returns structure:
    {
        "vendor_name": {
            "display_name": "Apache Software Foundation",
            "products": {
                "product_name": {
                    "display_name": "Apache Tomcat",
                    "versions": ["10.1.18", "10.0.27", "9.0.85", ...],
                    "cpe_vendor": "apache",
                    "cpe_product": "tomcat"
                }
            }
        }
    }
    """
    raw_results = search_cpe(keyword, limit=limit)

    grouped: Dict[str, Dict[str, Any]] = {}

    # Split search terms for relevance filtering
    # Separate text terms from version-like terms (numbers)
    all_terms = [term.lower().replace('_', ' ') for term in keyword.split()]
    text_terms = [t for t in all_terms if not t.isdigit() and not re.match(r'^\d+\.\d+', t)]
    version_hints = [t for t in all_terms if t.isdigit() or re.match(r'^\d+\.?\d*', t)]

    def calculate_relevance_score(vendor: str, product: str, title: str) -> int:
        """
        Calculate relevance score for a CPE entry.
        Higher scores mean better matches.
        Returns -1 if entry should be filtered out.
        """
        # Normalize strings for comparison
        vendor_lower = (vendor or '').lower().replace('_', ' ')
        product_lower = (product or '').lower().replace('_', ' ')
        combined = f"{vendor_lower} {product_lower}"

        score = 0

        # ALL text terms must match vendor or product (stricter filter)
        for term in text_terms:
            if term not in combined:
                return -1  # Filter out - doesn't match
            score += 10  # Base score for matching

        # Bonus: version hints matching in product name (e.g., "windows 11" -> windows_11)
        # This helps "Windows 11" score higher than "Windows Media Player" when searching "windows 11"
        for hint in version_hints:
            if hint in product_lower:
                score += 20  # Big bonus for number in product name
            elif hint in vendor_lower:
                score += 5

        # Bonus: exact product name match
        for term in text_terms:
            if term == product_lower:
                score += 15
            elif product_lower.startswith(term):
                score += 8

        return score

    def is_relevant_match(vendor: str, product: str, title: str) -> bool:
        """Check if entry passes relevance threshold."""
        return calculate_relevance_score(vendor, product, title) >= 0

    for entry in raw_results:
        vendor = entry.get('vendor') or 'unknown'
        product = entry.get('product') or 'unknown'
        version = entry.get('version')
        title = entry.get('title', '')

        # Calculate relevance score
        score = calculate_relevance_score(vendor, product, title)
        if score < 0:
            continue  # Filter out irrelevant results

        # Initialize vendor if not exists
        if vendor not in grouped:
            # Try to extract nice vendor name from title
            vendor_display = vendor.replace('_', ' ').title()
            if title:
                # Extract vendor from title like "Apache Tomcat 10.1.18"
                vendor_display = title.split()[0] if ' ' in title else vendor_display

            grouped[vendor] = {
                'display_name': vendor_display,
                'products': {}
            }

        # Initialize product if not exists
        if product not in grouped[vendor]['products']:
            # Try to extract nice product name from title
            product_display = product.replace('_', ' ').title()
            if title:
                # Try to get product name (e.g., "Apache Tomcat" -> "Tomcat")
                parts = title.split()
                if len(parts) >= 2:
                    product_display = ' '.join(parts[:2])  # First two words usually vendor + product

            grouped[vendor]['products'][product] = {
                'display_name': product_display,
                'versions': [],
                'cpe_vendor': vendor,
                'cpe_product': product,
                'title': title,
                'relevance_score': score  # Store relevance score
            }
        else:
            # Update score if this entry has higher relevance
            if score > grouped[vendor]['products'][product].get('relevance_score', 0):
                grouped[vendor]['products'][product]['relevance_score'] = score

        # Add version if not already present
        if version and version != '*' and version not in grouped[vendor]['products'][product]['versions']:
            grouped[vendor]['products'][product]['versions'].append(version)

    # Sort versions for each product (newest first)
    for vendor_data in grouped.values():
        for product_data in vendor_data['products'].values():
            product_data['versions'] = sorted(
                product_data['versions'],
                key=lambda v: _version_sort_key(v),
                reverse=True
            )[:20]  # Limit to 20 most recent versions

    # Sort vendors and products by relevance score (highest first)
    sorted_grouped = {}
    for vendor_key in grouped:
        vendor_data = grouped[vendor_key]
        # Sort products by relevance score
        sorted_products = dict(sorted(
            vendor_data['products'].items(),
            key=lambda x: x[1].get('relevance_score', 0),
            reverse=True
        ))
        sorted_grouped[vendor_key] = {
            'display_name': vendor_data['display_name'],
            'products': sorted_products,
            'max_score': max((p.get('relevance_score', 0) for p in sorted_products.values()), default=0)
        }

    # Sort vendors by their highest product score
    grouped = dict(sorted(
        sorted_grouped.items(),
        key=lambda x: x[1].get('max_score', 0),
        reverse=True
    ))

    return grouped


def _version_sort_key(version: str) -> Tuple:
    """
    Generate a sortable key for version strings.
    Handles semver-like versions: 1.2.3, 10.1.18, etc.
    """
    parts = []
    for part in re.split(r'[.\-_]', version):
        # Try to convert to int for numeric comparison
        try:
            parts.append((0, int(part)))
        except ValueError:
            parts.append((1, part.lower()))
    return tuple(parts)


def get_cpe_versions(vendor: str, product: str, limit: int = 50) -> List[str]:
    """
    Get available versions for a specific vendor/product combination.

    Args:
        vendor: CPE vendor name
        product: CPE product name
        limit: Maximum versions to return

    Returns:
        List of version strings, sorted newest first
    """
    # Build CPE match string for specific vendor/product
    cache_key = f"versions:{vendor}:{product}"
    cached = _get_cached_result(cache_key)
    if cached is not None:
        return cached

    url = "https://services.nvd.nist.gov/rest/json/cpes/2.0"
    params = {
        'cpeMatchString': f"cpe:2.3:*:{vendor}:{product}:*",
        'resultsPerPage': min(limit * 2, 500),  # Fetch extra to account for deduplication
        'startIndex': 0
    }

    api_key = _get_api_key()
    headers = {}
    if api_key:
        headers['apiKey'] = api_key

    _rate_limit()

    try:
        proxies = Config.get_proxies()
        verify_ssl = Config.get_verify_ssl()

        if not verify_ssl:
            urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

        response = requests.get(
            url,
            params=params,
            headers=headers,
            timeout=15,
            proxies=proxies,
            verify=verify_ssl
        )

        if response.status_code == 200:
            data = response.json()
            products = data.get('products', [])

            versions = set()
            for prod in products:
                cpe_data = prod.get('cpe', {})
                if cpe_data.get('deprecated', False):
                    continue

                cpe_uri = cpe_data.get('cpeName', '')
                parsed = parse_cpe_uri(cpe_uri)

                if parsed['version'] and parsed['version'] != '*':
                    versions.add(parsed['version'])

            # Sort and limit
            sorted_versions = sorted(versions, key=_version_sort_key, reverse=True)[:limit]
            _set_cached_result(cache_key, sorted_versions)
            return sorted_versions

        return []

    except Exception as e:
        logger.error(f"Error fetching CPE versions: {str(e)}")
        return []


def match_cve_to_cpe(cve_id: str) -> List[Dict]:
    """
    Get CPE entries affected by a specific CVE.

    This uses the NVD CVE API to get the CPE matches for a vulnerability.

    Args:
        cve_id: CVE identifier (e.g., "CVE-2024-1234")

    Returns:
        List of affected CPE entries
    """
    cache_key = f"cve_cpe:{cve_id}"
    cached = _get_cached_result(cache_key)
    if cached is not None:
        return cached

    url = "https://services.nvd.nist.gov/rest/json/cves/2.0"
    params = {'cveId': cve_id}

    api_key = _get_api_key()
    headers = {}
    if api_key:
        headers['apiKey'] = api_key

    _rate_limit()

    try:
        proxies = Config.get_proxies()
        verify_ssl = Config.get_verify_ssl()

        if not verify_ssl:
            urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

        response = requests.get(
            url,
            params=params,
            headers=headers,
            timeout=15,
            proxies=proxies,
            verify=verify_ssl
        )

        if response.status_code == 200:
            data = response.json()
            vulnerabilities = data.get('vulnerabilities', [])

            if not vulnerabilities:
                return []

            cve_data = vulnerabilities[0].get('cve', {})
            configurations = cve_data.get('configurations', [])

            affected_cpes = []
            for config in configurations:
                nodes = config.get('nodes', [])
                for node in nodes:
                    cpe_matches = node.get('cpeMatch', [])
                    for match in cpe_matches:
                        if match.get('vulnerable', False):
                            cpe_uri = match.get('criteria', '')
                            parsed = parse_cpe_uri(cpe_uri)

                            affected_cpes.append({
                                'cpe_uri': cpe_uri,
                                'vendor': parsed['vendor'],
                                'product': parsed['product'],
                                'version_start': match.get('versionStartIncluding') or match.get('versionStartExcluding'),
                                'version_end': match.get('versionEndIncluding') or match.get('versionEndExcluding'),
                                'version_start_type': 'including' if match.get('versionStartIncluding') else 'excluding' if match.get('versionStartExcluding') else None,
                                'version_end_type': 'including' if match.get('versionEndIncluding') else 'excluding' if match.get('versionEndExcluding') else None
                            })

            _set_cached_result(cache_key, affected_cpes)
            return affected_cpes

        return []

    except Exception as e:
        logger.error(f"Error fetching CVE CPE data: {str(e)}")
        return []


def check_product_affected(
    cpe_vendor: str,
    cpe_product: str,
    version: str,
    cve_id: str
) -> Tuple[bool, Optional[str]]:
    """
    Check if a specific product version is affected by a CVE.

    Args:
        cpe_vendor: CPE vendor name
        cpe_product: CPE product name
        version: Product version to check
        cve_id: CVE identifier

    Returns:
        Tuple of (is_affected: bool, match_reason: Optional[str])
    """
    affected_cpes = match_cve_to_cpe(cve_id)

    for cpe in affected_cpes:
        if cpe['vendor'] != cpe_vendor or cpe['product'] != cpe_product:
            continue

        # If no version range specified, any version matches
        if not cpe.get('version_start') and not cpe.get('version_end'):
            parsed = parse_cpe_uri(cpe['cpe_uri'])
            if parsed.get('version') and parsed['version'] != '*':
                # Exact version match
                if version == parsed['version']:
                    return True, f"CPE exact version match: {cpe['cpe_uri']}"
            else:
                # Any version matches
                return True, f"CPE match (all versions): {cpe['cpe_uri']}"

        # Check version range
        if _version_in_range(
            version,
            cpe.get('version_start'),
            cpe.get('version_end'),
            cpe.get('version_start_type'),
            cpe.get('version_end_type')
        ):
            return True, f"CPE version range match: {cpe['cpe_uri']}"

    return False, None


def _version_in_range(
    version: str,
    start: Optional[str],
    end: Optional[str],
    start_type: Optional[str],
    end_type: Optional[str]
) -> bool:
    """
    Check if a version falls within a specified range.
    """
    if not version:
        return False

    version_key = _version_sort_key(version)

    # Check start bound
    if start:
        start_key = _version_sort_key(start)
        if start_type == 'including':
            if version_key < start_key:
                return False
        else:  # excluding
            if version_key <= start_key:
                return False

    # Check end bound
    if end:
        end_key = _version_sort_key(end)
        if end_type == 'including':
            if version_key > end_key:
                return False
        else:  # excluding
            if version_key >= end_key:
                return False

    return True


def clear_cache():
    """Clear all cached CPE data."""
    global _cpe_cache
    with _cache_lock:
        _cpe_cache.clear()


def get_cache_stats() -> Dict[str, Any]:
    """Get statistics about the CPE cache."""
    with _cache_lock:
        now = datetime.now()
        valid_entries = sum(
            1 for _, (_, timestamp) in _cpe_cache.items()
            if now - timestamp < timedelta(minutes=CACHE_TTL_MINUTES)
        )
        return {
            'total_entries': len(_cpe_cache),
            'valid_entries': valid_entries,
            'cache_ttl_minutes': CACHE_TTL_MINUTES
        }
