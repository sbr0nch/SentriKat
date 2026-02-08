"""
Automatic Vendor Advisory Sync

Fetches security advisories from vendor feeds to auto-detect in-place
patches (Path B / backport fixes). When a vendor publishes a fix for a
CVE that patches an existing version in-place, this module automatically
creates VendorFixOverride records and resolves false-positive matches.

Supported feeds:
- OSV.dev (aggregates Ubuntu, Debian, Alpine, PyPI, npm, Go, Rust, Maven)
- Red Hat Security Data API (RHEL, CentOS, Rocky Linux)
- Microsoft MSRC (Security Response Center) API
- Debian Security Tracker (direct JSON feed)

Architecture:
    scheduler.py  →  sync_vendor_advisories()
                        ├── _sync_osv_advisories()       # Ubuntu, Debian, Alpine, ecosystems
                        ├── _sync_redhat_advisories()     # RHEL family
                        ├── _sync_msrc_advisories()       # Windows / Microsoft
                        └── _auto_resolve_matches()       # Suppress false positives
"""

import logging
import re
import requests
from datetime import datetime, timedelta
from typing import List, Dict, Optional, Tuple, Any
from app.version_utils import is_version_patched, detect_version_format

logger = logging.getLogger(__name__)

# === Feed URLs ===
OSV_API_URL = 'https://api.osv.dev/v1'
REDHAT_API_URL = 'https://access.redhat.com/hydra/rest/securitydata'
MSRC_API_BASE = 'https://api.msrc.microsoft.com'
MSRC_CVRF_URL = f'{MSRC_API_BASE}/cvrf/v3.0'
DEBIAN_TRACKER_URL = 'https://security-tracker.debian.org/tracker/data/json'


def _get_http_config():
    """Get proxy and SSL config from app settings."""
    from config import Config
    return Config.get_proxies(), Config.get_verify_ssl()


def sync_vendor_advisories():
    """
    Main entry point: fetch advisories from all vendor feeds,
    create VendorFixOverride records, and auto-resolve false-positive matches.

    Returns dict with sync stats.
    """
    from app import db

    stats = {
        'overrides_created': 0,
        'matches_resolved': 0,
        'feeds_checked': 0,
        'errors': [],
        'started_at': datetime.utcnow().isoformat(),
    }

    # Get all currently unresolved CVE matches to know what to check
    active_cves = _get_active_matched_cves()
    if not active_cves:
        logger.info("Vendor advisory sync: no active CVE matches to check")
        stats['feeds_checked'] = 0
        return stats

    logger.info(f"Vendor advisory sync: checking {len(active_cves)} active CVEs against vendor feeds")

    # Collect all advisories from all feeds
    all_advisories = []

    # 1. OSV.dev (Ubuntu, Debian, Alpine, open source ecosystems)
    try:
        osv_results = _sync_osv_advisories(active_cves)
        all_advisories.extend(osv_results)
        stats['feeds_checked'] += 1
        logger.info(f"OSV.dev: found {len(osv_results)} advisory matches")
    except Exception as e:
        logger.error(f"OSV.dev sync failed: {e}")
        stats['errors'].append(f"OSV.dev: {str(e)}")

    # 2. Red Hat Security Data API
    try:
        rh_results = _sync_redhat_advisories(active_cves)
        all_advisories.extend(rh_results)
        stats['feeds_checked'] += 1
        logger.info(f"Red Hat: found {len(rh_results)} advisory matches")
    except Exception as e:
        logger.error(f"Red Hat sync failed: {e}")
        stats['errors'].append(f"Red Hat: {str(e)}")

    # 3. Microsoft MSRC
    try:
        msrc_results = _sync_msrc_advisories(active_cves)
        all_advisories.extend(msrc_results)
        stats['feeds_checked'] += 1
        logger.info(f"MSRC: found {len(msrc_results)} advisory matches")
    except Exception as e:
        logger.error(f"MSRC sync failed: {e}")
        stats['errors'].append(f"MSRC: {str(e)}")

    # 4. Debian Security Tracker
    try:
        debian_results = _sync_debian_advisories(active_cves)
        all_advisories.extend(debian_results)
        stats['feeds_checked'] += 1
        logger.info(f"Debian: found {len(debian_results)} advisory matches")
    except Exception as e:
        logger.error(f"Debian sync failed: {e}")
        stats['errors'].append(f"Debian: {str(e)}")

    # Create VendorFixOverride records for new advisories
    if all_advisories:
        created = _create_override_records(all_advisories)
        stats['overrides_created'] = created

    # Auto-resolve matches that now have approved overrides
    resolved = _auto_resolve_matches()
    stats['matches_resolved'] = resolved

    db.session.commit()

    stats['completed_at'] = datetime.utcnow().isoformat()
    logger.info(f"Vendor advisory sync complete: {stats}")
    return stats


# ============================================================================
# Active CVE collection
# ============================================================================

def _get_active_matched_cves() -> Dict[str, List[dict]]:
    """
    Get all currently unresolved CVE matches with their product info.

    Returns dict: { 'CVE-2024-1234': [{'vendor': 'apache', 'product': 'tomcat',
                     'version': '10.1.18', 'os_version': 'Ubuntu 22.04', ...}] }
    """
    from app.models import VulnerabilityMatch, Product, Vulnerability, Asset, ProductInstallation

    matches = (
        VulnerabilityMatch.query
        .filter(VulnerabilityMatch.acknowledged == False)
        .join(Vulnerability, VulnerabilityMatch.vulnerability_id == Vulnerability.id)
        .join(Product, VulnerabilityMatch.product_id == Product.id)
        .with_entities(
            Vulnerability.cve_id,
            Product.vendor,
            Product.product_name,
            Product.version,
            Product.cpe_vendor,
            Product.cpe_product,
            Product.id.label('product_id'),
        )
        .all()
    )

    cve_map = {}
    for m in matches:
        if not m.cve_id:
            continue
        if m.cve_id not in cve_map:
            cve_map[m.cve_id] = []

        # Get OS info from any asset that has this product installed
        os_info = _get_product_os_info(m.product_id)

        cve_map[m.cve_id].append({
            'vendor': (m.cpe_vendor or m.vendor or '').lower(),
            'product': (m.cpe_product or m.product_name or '').lower(),
            'display_vendor': m.vendor,
            'display_product': m.product_name,
            'version': m.version,
            'product_id': m.product_id,
            'os_distro': os_info.get('distro'),
            'os_version': os_info.get('os_version'),
            'distro_package_version': os_info.get('distro_package_version'),
            'installed_kbs': os_info.get('installed_kbs', []),
        })

    return cve_map


def _get_product_os_info(product_id: int) -> dict:
    """Get OS/distro info for a product from its installations on assets."""
    from app.models import ProductInstallation, Asset

    installation = (
        ProductInstallation.query
        .filter_by(product_id=product_id)
        .join(Asset, ProductInstallation.asset_id == Asset.id)
        .with_entities(
            Asset.os_name,
            Asset.os_version,
            ProductInstallation.version,
            ProductInstallation.detected_on_os,
            ProductInstallation.distro_package_version,
            Asset.installed_kbs,
        )
        .first()
    )

    if not installation:
        return {}

    import json

    # Parse installed KBs from Asset
    kbs = []
    if installation.installed_kbs:
        try:
            kbs = json.loads(installation.installed_kbs)
        except (json.JSONDecodeError, TypeError):
            pass

    distro = _detect_distro(installation.os_name, installation.os_version)

    return {
        'distro': distro,
        'os_version': installation.os_version,
        'distro_package_version': installation.distro_package_version,
        'installed_kbs': kbs,
    }


def _detect_distro(os_name: str, os_version: str) -> Optional[str]:
    """Detect the Linux distro from OS name/version strings."""
    if not os_name:
        return None

    combined = f"{os_name} {os_version or ''}".lower()

    if 'ubuntu' in combined:
        return 'ubuntu'
    if 'debian' in combined:
        return 'debian'
    if 'red hat' in combined or 'rhel' in combined or 'centos' in combined or 'rocky' in combined or 'alma' in combined:
        return 'redhat'
    if 'alpine' in combined:
        return 'alpine'
    if 'suse' in combined or 'sles' in combined:
        return 'suse'
    if 'fedora' in combined:
        return 'fedora'
    if 'windows' in combined:
        return 'windows'
    if 'macos' in combined or 'darwin' in combined:
        return 'macos'

    return None


# ============================================================================
# OSV.dev Feed (Ubuntu, Debian, Alpine, PyPI, npm, Go, Rust, Maven)
# ============================================================================

def _sync_osv_advisories(active_cves: Dict[str, List[dict]]) -> List[dict]:
    """
    Query OSV.dev for each active CVE to check if vendor fixes exist.

    OSV.dev is the single most valuable source because it aggregates:
    - Ubuntu Security Notices (USN)
    - Debian Security Advisories (DSA)
    - Alpine SecDB
    - PyPI, npm, Go, Rust, Maven advisories
    """
    proxies, verify_ssl = _get_http_config()
    results = []

    # Batch query OSV for each CVE (OSV supports direct CVE lookup)
    for cve_id, products in active_cves.items():
        try:
            # OSV vulns endpoint: get vulnerability details by ID
            response = requests.get(
                f'{OSV_API_URL}/vulns/{cve_id}',
                timeout=10,
                proxies=proxies,
                verify=verify_ssl
            )

            if response.status_code == 404:
                continue  # CVE not in OSV database
            if response.status_code != 200:
                continue

            osv_data = response.json()
            advisories = _parse_osv_response(cve_id, osv_data, products)
            results.extend(advisories)

        except requests.RequestException as e:
            logger.debug(f"OSV lookup failed for {cve_id}: {e}")
            continue

    return results


def _parse_osv_response(cve_id: str, osv_data: dict, products: List[dict]) -> List[dict]:
    """
    Parse OSV.dev response and match against our affected products.

    OSV data structure:
    {
      "affected": [
        {
          "package": {"name": "apache2", "ecosystem": "Ubuntu:22.04"},
          "ranges": [{"events": [{"introduced": "0"}, {"fixed": "2.4.52-1ubuntu4.6"}]}],
          "versions": ["2.4.52-1ubuntu4.5", ...]
        }
      ]
    }
    """
    results = []

    for affected in osv_data.get('affected', []):
        package = affected.get('package', {})
        pkg_name = package.get('name', '').lower()
        ecosystem = package.get('ecosystem', '').lower()

        # Extract fixed versions from ranges
        fixed_versions = []
        for range_info in affected.get('ranges', []):
            for event in range_info.get('events', []):
                if 'fixed' in event:
                    fixed_versions.append(event['fixed'])

        if not fixed_versions:
            continue

        # Match against our products
        for product_info in products:
            product_name = product_info['product']
            vendor = product_info['vendor']
            version = product_info['version']

            # Check if this OSV entry is relevant to our product
            if not _osv_package_matches_product(pkg_name, ecosystem, product_name, vendor):
                continue

            # Compare installed version against the vendor's fixed version.
            # Use distro_package_version (full distro version from agent) if available,
            # otherwise fall back to the base upstream version.
            has_distro_version = bool(product_info.get('distro_package_version'))
            compare_version = product_info.get('distro_package_version') or version
            os_info = product_info.get('os', '')
            version_format = detect_version_format(ecosystem, os_info)
            is_distro_native = version_format in ('dpkg', 'rpm', 'apk')

            for fixed_ver in fixed_versions:
                # Only create override if installed version >= fixed version
                if not is_version_patched(compare_version, fixed_ver, version_format):
                    continue  # Still vulnerable, don't suppress

                # Determine confidence tier
                if is_distro_native and has_distro_version:
                    confidence = 'high'
                    confidence_reason = f'{version_format} comparison: {compare_version} >= {fixed_ver}'
                else:
                    confidence = 'medium'
                    if not has_distro_version:
                        confidence_reason = f'Generic comparison (no distro package version from agent): {compare_version} >= {fixed_ver}'
                    else:
                        confidence_reason = f'Generic comparison: {compare_version} >= {fixed_ver}'

                results.append({
                    'cve_id': cve_id,
                    'vendor': product_info['display_vendor'],
                    'product': product_info['display_product'],
                    'fixed_version': version,  # The version we're marking as fixed
                    'fix_type': 'backport_patch',
                    'source': 'osv.dev',
                    'advisory_id': osv_data.get('id', ''),
                    'advisory_url': f'https://osv.dev/vulnerability/{osv_data.get("id", cve_id)}',
                    'ecosystem': ecosystem,
                    'fixed_in_version': fixed_ver,
                    'confidence': confidence,
                    'confidence_reason': confidence_reason,
                    'notes': f'OSV.dev: {pkg_name} {compare_version} >= {fixed_ver} ({version_format})',
                })

    return results


def _osv_package_matches_product(pkg_name: str, ecosystem: str, product_name: str, vendor: str) -> bool:
    """Check if an OSV package entry matches one of our tracked products."""
    product_lower = product_name.lower()
    vendor_lower = vendor.lower()

    # Direct name match
    if pkg_name == product_lower:
        return True

    # Common package name variations
    # e.g., product "Apache HTTP Server" → package "apache2" or "httpd"
    name_mappings = {
        'apache2': ['apache', 'httpd', 'http server', 'http_server'],
        'httpd': ['apache', 'http server', 'http_server'],
        'nginx': ['nginx'],
        'openssh-server': ['openssh', 'ssh'],
        'openssh-client': ['openssh', 'ssh'],
        'openssl': ['openssl'],
        'curl': ['curl', 'libcurl'],
        'libcurl': ['curl'],
        'linux-image': ['linux', 'kernel'],
        'postgresql': ['postgresql', 'postgres'],
        'mariadb-server': ['mariadb'],
        'mysql-server': ['mysql'],
        'php': ['php'],
        'python3': ['python', 'cpython'],
        'git': ['git'],
        'sudo': ['sudo'],
        'vim': ['vim'],
        'bind9': ['bind', 'named'],
        'samba': ['samba'],
        'tomcat': ['tomcat'],
    }

    # Check if package name maps to product name
    for pkg, aliases in name_mappings.items():
        if pkg_name == pkg or pkg_name.startswith(pkg + '-'):
            if any(alias in product_lower or alias in vendor_lower for alias in aliases):
                return True

    # Check if product name is contained in package name or vice versa
    if len(product_lower) >= 3 and (product_lower in pkg_name or pkg_name in product_lower):
        return True

    # Check vendor+product combination
    if vendor_lower in pkg_name:
        return True

    return False


# ============================================================================
# Red Hat Security Data API (RHEL, CentOS, Rocky, Alma)
# ============================================================================

def _sync_redhat_advisories(active_cves: Dict[str, List[dict]]) -> List[dict]:
    """
    Query Red Hat Security Data API for CVE fix information.

    Red Hat API provides per-CVE data with affected_release[] showing
    the exact fixed RPM package for each RHEL version.
    """
    proxies, verify_ssl = _get_http_config()
    results = []

    # Only check CVEs that have Red Hat-relevant products
    for cve_id, products in active_cves.items():
        has_redhat = any(
            p.get('os_distro') in ('redhat', None) or
            p.get('vendor', '').lower() in ('red hat', 'redhat', 'centos', 'rocky', 'almalinux')
            for p in products
        )
        if not has_redhat:
            continue

        try:
            response = requests.get(
                f'{REDHAT_API_URL}/cve/{cve_id}.json',
                timeout=10,
                proxies=proxies,
                verify=verify_ssl
            )

            if response.status_code == 404:
                continue
            if response.status_code != 200:
                continue

            rh_data = response.json()
            advisories = _parse_redhat_response(cve_id, rh_data, products)
            results.extend(advisories)

        except requests.RequestException as e:
            logger.debug(f"Red Hat API failed for {cve_id}: {e}")
            continue

    return results


def _parse_redhat_response(cve_id: str, rh_data: dict, products: List[dict]) -> List[dict]:
    """
    Parse Red Hat CVE API response.

    Response includes:
    - affected_release[]: list of fixed RPMs per RHEL version
    - package_state[]: list of affected/not-affected states
    """
    results = []

    # Check affected_release for fixed packages
    for release in rh_data.get('affected_release', []):
        package_name = release.get('package', '')
        advisory = release.get('advisory', '')
        cpe = release.get('cpe', '')

        if not package_name:
            continue

        # Extract base package name and fixed version from RPM NVR
        # e.g., "httpd-2.4.37-47.module+el8.6.0+15654+427eba2e.2.x86_64"
        rpm_name, fixed_evr = _parse_rpm_nvr(package_name)

        for product_info in products:
            if _redhat_package_matches_product(rpm_name, product_info):
                # Compare installed version against fixed version using RPM comparison
                has_distro_version = bool(product_info.get('distro_package_version'))
                installed_ver = product_info.get('distro_package_version') or product_info['version']
                if fixed_evr and installed_ver:
                    if not is_version_patched(installed_ver, fixed_evr, 'rpm'):
                        continue  # Still vulnerable, don't suppress

                # Determine confidence tier
                if has_distro_version and fixed_evr:
                    confidence = 'high'
                    confidence_reason = f'RPM comparison: {installed_ver} >= {fixed_evr}'
                else:
                    confidence = 'medium'
                    confidence_reason = f'Generic comparison (no distro package version from agent): {installed_ver} >= {fixed_evr}'

                results.append({
                    'cve_id': cve_id,
                    'vendor': product_info['display_vendor'],
                    'product': product_info['display_product'],
                    'fixed_version': product_info['version'],
                    'fix_type': 'backport_patch',
                    'source': 'redhat',
                    'advisory_id': advisory,
                    'advisory_url': f'https://access.redhat.com/errata/{advisory}' if advisory else '',
                    'confidence': confidence,
                    'confidence_reason': confidence_reason,
                    'notes': f'Red Hat: {installed_ver} >= {fixed_evr} ({advisory})',
                })

    # Also check package_state for "not affected" status
    for state in rh_data.get('package_state', []):
        if state.get('fix_state') == 'Not affected':
            pkg = state.get('package_name', '')
            for product_info in products:
                if _redhat_package_matches_product(pkg, product_info):
                    results.append({
                        'cve_id': cve_id,
                        'vendor': product_info['display_vendor'],
                        'product': product_info['display_product'],
                        'fixed_version': product_info['version'],
                        'fix_type': 'not_affected',
                        'source': 'redhat',
                        'advisory_id': '',
                        'advisory_url': f'https://access.redhat.com/security/cve/{cve_id}',
                        'confidence': 'medium',
                        'confidence_reason': f'Vendor statement: {pkg} marked "Not affected" (verify manually)',
                        'notes': f'Red Hat: {pkg} marked as "Not affected"',
                    })

    return results


def _parse_rpm_nvr(nvr: str) -> Tuple[str, str]:
    """
    Parse an RPM NVR (Name-Version-Release) or NEVRA into (name, version-release).

    Examples:
        "httpd-2.4.37-47.el8.x86_64" -> ("httpd", "2.4.37-47.el8")
        "python3-urllib3-1.26.5-3.el9.noarch" -> ("python3-urllib3", "1.26.5-3.el9")
        "vim-8.0.1763-19.el8_6.4" -> ("vim", "8.0.1763-19.el8_6.4")
    """
    s = nvr.strip()
    # Strip architecture suffix (.x86_64, .noarch, .i686, .aarch64, .src)
    s = re.sub(r'\.(x86_64|noarch|i[3-6]86|aarch64|ppc64le|s390x|src)$', '', s)

    # RPM NVR: name is everything before the second-to-last dash
    # Version is between second-to-last and last dash
    # Release is after last dash
    # We split on '-' and the last two segments are version and release
    parts = s.rsplit('-', 2)
    if len(parts) == 3:
        name = parts[0]
        evr = f'{parts[1]}-{parts[2]}'
        return (name, evr)
    elif len(parts) == 2:
        return (parts[0], parts[1])
    return (s, '')


def _redhat_package_matches_product(rpm_name: str, product_info: dict) -> bool:
    """Check if a Red Hat RPM name matches our tracked product."""
    rpm_lower = rpm_name.lower()
    product_lower = product_info['product'].lower()
    vendor_lower = product_info['vendor'].lower()

    if rpm_lower == product_lower:
        return True
    if len(product_lower) >= 3 and (product_lower in rpm_lower or rpm_lower in product_lower):
        return True
    if vendor_lower in rpm_lower:
        return True

    return False


# ============================================================================
# Microsoft MSRC API
# ============================================================================

def _sync_msrc_advisories(active_cves: Dict[str, List[dict]]) -> List[dict]:
    """
    Query Microsoft MSRC CVRF API for Windows/Microsoft product patches.

    MSRC publishes monthly Patch Tuesday data with CVE → KB mappings.
    """
    proxies, verify_ssl = _get_http_config()
    results = []

    # Only check if we have Windows/Microsoft products
    microsoft_cves = {}
    for cve_id, products in active_cves.items():
        ms_products = [
            p for p in products
            if p.get('os_distro') == 'windows' or
               p.get('vendor', '').lower() in ('microsoft', 'microsoft corporation') or
               any(kw in p.get('product', '').lower() for kw in
                   ('windows', 'office', 'exchange', 'sharepoint', '.net', 'sql server',
                    'visual studio', 'edge', 'iis', 'active directory'))
        ]
        if ms_products:
            microsoft_cves[cve_id] = ms_products

    if not microsoft_cves:
        return results

    # Fetch recent MSRC update periods
    try:
        headers = {'Accept': 'application/json'}
        response = requests.get(
            f'{MSRC_CVRF_URL}/updates',
            headers=headers,
            timeout=15,
            proxies=proxies,
            verify=verify_ssl
        )

        if response.status_code != 200:
            logger.warning(f'MSRC updates API returned {response.status_code}')
            return results

        updates = response.json().get('value', [])

        # Get the 3 most recent update periods
        recent_ids = _get_recent_msrc_update_ids(updates, months_back=3)

        # Fetch and parse each CVRF document
        cve_kb_map = {}  # cve_id → list of KB articles
        for update_id in recent_ids:
            try:
                detail_resp = requests.get(
                    f'{MSRC_CVRF_URL}/cvrf/{update_id}',
                    headers=headers,
                    timeout=30,
                    proxies=proxies,
                    verify=verify_ssl
                )
                if detail_resp.status_code != 200:
                    continue

                parsed = _parse_msrc_cvrf(detail_resp.json(), update_id)
                for entry in parsed:
                    cve = entry['cve_id']
                    if cve not in cve_kb_map:
                        cve_kb_map[cve] = []
                    cve_kb_map[cve].append(entry)

            except Exception as e:
                logger.debug(f"MSRC CVRF parse failed for {update_id}: {e}")

        # Match against our active CVEs
        for cve_id, ms_products in microsoft_cves.items():
            if cve_id not in cve_kb_map:
                continue

            for entry in cve_kb_map[cve_id]:
                kb_articles = entry.get('kb_articles', [])

                for product_info in ms_products:
                    # Check if agent reported any of these KBs as installed
                    installed_kbs = product_info.get('installed_kbs', [])
                    kb_installed = any(
                        kb in installed_kbs
                        for kb in kb_articles
                    ) if installed_kbs else False

                    # Only create override if KB is confirmed installed by the agent
                    if kb_installed:
                        fix_type = 'hotfix'
                        notes_parts = []
                        if kb_articles:
                            notes_parts.append(f"KB: {', '.join(kb_articles[:3])}")
                        notes_parts.append("(KB confirmed installed)")
                        notes_parts.append(f"MSRC: {entry.get('advisory_id', '')}")

                        results.append({
                            'cve_id': cve_id,
                            'vendor': product_info['display_vendor'],
                            'product': product_info['display_product'],
                            'fixed_version': product_info['version'],
                            'fix_type': fix_type,
                            'source': 'msrc',
                            'advisory_id': entry.get('advisory_id', ''),
                            'advisory_url': entry.get('url', ''),
                            'patch_identifier': ', '.join(kb_articles[:3]),
                            'confidence': 'high',
                            'confidence_reason': f'KB {", ".join(kb_articles[:3])} confirmed installed by agent',
                            'notes': ' | '.join(notes_parts),
                        })

    except Exception as e:
        logger.error(f"MSRC sync failed: {e}")

    return results


def _get_recent_msrc_update_ids(updates: list, months_back: int = 3) -> List[str]:
    """Extract the most recent MSRC update period IDs."""
    now = datetime.utcnow()
    cutoff = now - timedelta(days=months_back * 31)
    recent = []

    month_map = {
        'Jan': 1, 'Feb': 2, 'Mar': 3, 'Apr': 4,
        'May': 5, 'Jun': 6, 'Jul': 7, 'Aug': 8,
        'Sep': 9, 'Oct': 10, 'Nov': 11, 'Dec': 12
    }

    for update in updates:
        update_id = update.get('ID', '')
        if not update_id:
            continue
        try:
            parts = update_id.split('-')
            if len(parts) >= 2:
                year = int(parts[0])
                month = month_map.get(parts[1][:3], 0)
                if month > 0 and datetime(year, month, 1) >= cutoff:
                    recent.append(update_id)
        except (ValueError, IndexError):
            continue

    return recent[:months_back]


def _parse_msrc_cvrf(cvrf_data: dict, update_id: str) -> List[dict]:
    """Parse MSRC CVRF document into structured advisory data."""
    advisories = []
    product_tree = cvrf_data.get('ProductTree', {})

    product_map = {}
    for branch in product_tree.get('Branch', []):
        _extract_products(branch, product_map)

    for vuln in cvrf_data.get('Vulnerability', []):
        cve_id = vuln.get('CVE', '')
        if not cve_id or not cve_id.startswith('CVE-'):
            continue

        title = vuln.get('Title', {}).get('Value', '')
        kb_articles = set()
        fixed_product_ids = set()

        for remediation in vuln.get('Remediations', []):
            if remediation.get('Type') == 2:  # Vendor Fix
                kb = remediation.get('Description', {}).get('Value', '')
                if kb:
                    kb_articles.add(kb)
                for prod_id in remediation.get('ProductID', []):
                    fixed_product_ids.add(prod_id)

        fixed_products = [product_map[pid] for pid in fixed_product_ids if pid in product_map]

        if cve_id and (kb_articles or fixed_products):
            advisories.append({
                'cve_id': cve_id,
                'title': title,
                'advisory_id': update_id,
                'url': f'https://msrc.microsoft.com/update-guide/vulnerability/{cve_id}',
                'vendor': 'microsoft',
                'kb_articles': list(kb_articles),
                'fixed_products': fixed_products,
            })

    return advisories


def _extract_products(branch: dict, product_map: dict):
    """Recursively extract product IDs and names from CVRF product tree."""
    if 'Items' in branch:
        for item in branch['Items']:
            if 'ProductID' in item:
                product_map[item['ProductID']] = item.get('Value', '')
            _extract_products(item, product_map)


def _msrc_product_matches(fixed_products: list, product_info: dict) -> bool:
    """Check if any MSRC fixed product matches our tracked product."""
    product_lower = product_info['product'].lower()
    for fp in fixed_products:
        if product_lower in fp.lower():
            return True
    return False


# ============================================================================
# Debian Security Tracker
# ============================================================================

def _sync_debian_advisories(active_cves: Dict[str, List[dict]]) -> List[dict]:
    """
    Check Debian Security Tracker for fix information.

    The tracker publishes a bulk JSON (~30MB) mapping package → CVE → release status.
    We cache this and check our active CVEs against it.
    """
    proxies, verify_ssl = _get_http_config()
    results = []

    # Only fetch if we have Debian-relevant products
    has_debian = any(
        any(p.get('os_distro') == 'debian' for p in products)
        for products in active_cves.values()
    )
    if not has_debian:
        return results

    try:
        response = requests.get(
            DEBIAN_TRACKER_URL,
            timeout=60,  # Large file, needs more time
            proxies=proxies,
            verify=verify_ssl
        )

        if response.status_code != 200:
            logger.warning(f"Debian tracker returned {response.status_code}")
            return results

        tracker_data = response.json()

        # tracker_data structure: { "package_name": { "CVE-xxx": { "releases": {...} } } }
        for cve_id, products in active_cves.items():
            debian_products = [p for p in products if p.get('os_distro') == 'debian']
            if not debian_products:
                continue

            for pkg_name, cve_data in tracker_data.items():
                if cve_id not in cve_data:
                    continue

                cve_info = cve_data[cve_id]
                releases = cve_info.get('releases', {})

                for release_name, release_info in releases.items():
                    status = release_info.get('status', '')
                    fixed_version = release_info.get('fixed_version', '')

                    if status == 'resolved' and fixed_version:
                        for product_info in debian_products:
                            if _debian_package_matches_product(pkg_name, product_info):
                                # Compare installed version against fixed using dpkg
                                has_distro_version = bool(product_info.get('distro_package_version'))
                                installed_ver = product_info.get('distro_package_version') or product_info['version']
                                if not is_version_patched(installed_ver, fixed_version, 'dpkg'):
                                    continue  # Still vulnerable

                                # Determine confidence tier
                                if has_distro_version:
                                    confidence = 'high'
                                    confidence_reason = f'dpkg comparison: {installed_ver} >= {fixed_version}'
                                else:
                                    confidence = 'medium'
                                    confidence_reason = f'Generic comparison (no distro package version from agent): {installed_ver} >= {fixed_version}'

                                results.append({
                                    'cve_id': cve_id,
                                    'vendor': product_info['display_vendor'],
                                    'product': product_info['display_product'],
                                    'fixed_version': product_info['version'],
                                    'fix_type': 'backport_patch',
                                    'source': 'debian',
                                    'advisory_id': cve_info.get('debianbug', ''),
                                    'advisory_url': f'https://security-tracker.debian.org/tracker/{cve_id}',
                                    'confidence': confidence,
                                    'confidence_reason': confidence_reason,
                                    'notes': f'Debian {release_name}: {installed_ver} >= {fixed_version}',
                                })

    except Exception as e:
        logger.error(f"Debian tracker sync failed: {e}")

    return results


def _debian_package_matches_product(pkg_name: str, product_info: dict) -> bool:
    """Check if a Debian package name matches our tracked product."""
    product_lower = product_info['product'].lower()
    pkg_lower = pkg_name.lower()

    if pkg_lower == product_lower:
        return True
    if len(product_lower) >= 3 and (product_lower in pkg_lower or pkg_lower in product_lower):
        return True

    return False


# ============================================================================
# Override creation and match resolution
# ============================================================================

def _create_override_records(advisories: List[dict]) -> int:
    """
    Create VendorFixOverride records from advisory data.

    De-duplicates against existing records. Auto-approves since these
    come from trusted vendor sources.
    """
    from app.models import VendorFixOverride
    from app import db
    from sqlalchemy import func

    created = 0

    for advisory in advisories:
        cve_id = advisory['cve_id']
        vendor = advisory['vendor']
        product = advisory['product']
        version = advisory['fixed_version']

        if not cve_id or not vendor or not product or not version:
            continue

        # Check for existing override
        existing = VendorFixOverride.query.filter(
            VendorFixOverride.cve_id == cve_id,
            func.lower(VendorFixOverride.vendor) == vendor.lower(),
            func.lower(VendorFixOverride.product) == product.lower(),
            VendorFixOverride.fixed_version == version,
        ).first()

        if existing:
            continue

        override = VendorFixOverride(
            cve_id=cve_id,
            vendor=vendor,
            product=product,
            fixed_version=version,
            fix_type=advisory.get('fix_type', 'backport_patch'),
            vendor_advisory_url=advisory.get('advisory_url', ''),
            vendor_advisory_id=advisory.get('advisory_id', ''),
            patch_identifier=advisory.get('patch_identifier', ''),
            notes=advisory.get('notes', ''),
            confidence=advisory.get('confidence', 'medium'),
            confidence_reason=advisory.get('confidence_reason', ''),
            status='approved',  # Auto-approved from trusted vendor feeds
            created_at=datetime.utcnow(),
            approved_at=datetime.utcnow(),
        )
        db.session.add(override)
        created += 1

    if created:
        db.session.flush()
        logger.info(f"Created {created} new VendorFixOverride records from vendor feeds")

    return created


def _auto_resolve_matches() -> int:
    """
    Auto-resolve VulnerabilityMatch records that have approved VendorFixOverride.

    Three-tier confidence system:
    - HIGH confidence: Full auto-resolve (acknowledged=True, green badge, hidden from alerts).
      These used distro-native comparison (dpkg/rpm/apk) with agent-reported package versions.
    - MEDIUM confidence: Tag with vendor_fix info but leave UNACKNOWLEDGED (amber badge,
      STAYS in alerts/webhooks so customer is notified to verify). These used generic
      comparison or lacked distro_package_version from the agent.

    This design protects legally: medium-confidence items remain visible as "Likely Resolved -
    Verify" and continue triggering alerts until the customer manually confirms.
    """
    from app.models import VulnerabilityMatch, VendorFixOverride, Product, Vulnerability
    from app import db
    from sqlalchemy import func

    resolved_high = 0
    tagged_medium = 0

    # Get all approved overrides
    overrides = VendorFixOverride.query.filter_by(status='approved').all()

    for override in overrides:
        confidence = getattr(override, 'confidence', 'medium') or 'medium'

        if confidence == 'high':
            # HIGH confidence: fully resolve unacknowledged matches
            matches = (
                VulnerabilityMatch.query
                .filter(VulnerabilityMatch.acknowledged == False)
                .join(Vulnerability, VulnerabilityMatch.vulnerability_id == Vulnerability.id)
                .join(Product, VulnerabilityMatch.product_id == Product.id)
                .filter(
                    Vulnerability.cve_id == override.cve_id,
                    db.or_(
                        func.lower(Product.vendor) == override.vendor.lower(),
                        func.lower(Product.cpe_vendor) == override.vendor.lower(),
                    ),
                    db.or_(
                        func.lower(Product.product_name) == override.product.lower(),
                        func.lower(Product.cpe_product) == override.product.lower(),
                    ),
                    Product.version == override.fixed_version,
                )
                .all()
            )

            for match in matches:
                match.acknowledged = True
                match.auto_acknowledged = True
                match.resolution_reason = 'vendor_fix'
                match.vendor_fix_confidence = 'high'
                match.acknowledged_at = datetime.utcnow()
                resolved_high += 1
        else:
            # MEDIUM confidence: tag with vendor_fix info but do NOT acknowledge
            # This keeps the match visible in alerts and on the dashboard as amber
            matches = (
                VulnerabilityMatch.query
                .filter(
                    VulnerabilityMatch.acknowledged == False,
                    # Don't re-tag if already tagged
                    db.or_(
                        VulnerabilityMatch.vendor_fix_confidence.is_(None),
                        VulnerabilityMatch.vendor_fix_confidence != 'medium',
                    ),
                )
                .join(Vulnerability, VulnerabilityMatch.vulnerability_id == Vulnerability.id)
                .join(Product, VulnerabilityMatch.product_id == Product.id)
                .filter(
                    Vulnerability.cve_id == override.cve_id,
                    db.or_(
                        func.lower(Product.vendor) == override.vendor.lower(),
                        func.lower(Product.cpe_vendor) == override.vendor.lower(),
                    ),
                    db.or_(
                        func.lower(Product.product_name) == override.product.lower(),
                        func.lower(Product.cpe_product) == override.product.lower(),
                    ),
                    Product.version == override.fixed_version,
                )
                .all()
            )

            for match in matches:
                # Do NOT set acknowledged=True - keep in active alerts
                match.vendor_fix_confidence = 'medium'
                match.resolution_reason = 'vendor_fix'
                tagged_medium += 1

    if resolved_high or tagged_medium:
        logger.info(
            f"Vendor advisory resolution: {resolved_high} fully resolved (high confidence), "
            f"{tagged_medium} tagged for verification (medium confidence)"
        )

    return resolved_high + tagged_medium


# ============================================================================
# Public API for manual checks
# ============================================================================

def check_advisory_for_cve(cve_id: str) -> List[dict]:
    """
    Check all vendor feeds for advisories related to a specific CVE.
    Used by the API endpoint for on-demand lookups.
    """
    proxies, verify_ssl = _get_http_config()
    results = []

    # Check OSV.dev
    try:
        response = requests.get(
            f'{OSV_API_URL}/vulns/{cve_id}',
            timeout=10,
            proxies=proxies,
            verify=verify_ssl
        )
        if response.status_code == 200:
            osv_data = response.json()
            for affected in osv_data.get('affected', []):
                pkg = affected.get('package', {})
                fixed_versions = []
                for r in affected.get('ranges', []):
                    for e in r.get('events', []):
                        if 'fixed' in e:
                            fixed_versions.append(e['fixed'])

                if fixed_versions:
                    results.append({
                        'source': 'osv.dev',
                        'cve_id': cve_id,
                        'package': pkg.get('name', ''),
                        'ecosystem': pkg.get('ecosystem', ''),
                        'fixed_versions': fixed_versions,
                        'url': f'https://osv.dev/vulnerability/{osv_data.get("id", cve_id)}',
                    })
    except Exception:
        pass

    # Check Red Hat
    try:
        response = requests.get(
            f'{REDHAT_API_URL}/cve/{cve_id}.json',
            timeout=10,
            proxies=proxies,
            verify=verify_ssl
        )
        if response.status_code == 200:
            rh_data = response.json()
            for release in rh_data.get('affected_release', []):
                results.append({
                    'source': 'redhat',
                    'cve_id': cve_id,
                    'package': release.get('package', ''),
                    'advisory': release.get('advisory', ''),
                    'url': f'https://access.redhat.com/security/cve/{cve_id}',
                })
    except Exception:
        pass

    return results
