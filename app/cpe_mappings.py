"""
Curated Software-to-CPE Mapping Database

This module provides reliable software-to-CPE mappings that don't rely on
unreliable NVD API fuzzy searches. Based on industry best practices from
Qualys, Tenable, and Rapid7 which maintain their own mapping databases.

The mapping uses normalized software names (lowercase, common variations)
to match against known CPE vendor:product pairs.
"""

import re
from typing import Optional, Tuple, Dict
import logging

logger = logging.getLogger(__name__)

# =============================================================================
# CURATED SOFTWARE TO CPE MAPPINGS
# =============================================================================
# Format: 'normalized_pattern': ('cpe_vendor', 'cpe_product', confidence)
# Patterns are checked in order - more specific patterns should come first
# =============================================================================

SOFTWARE_TO_CPE_MAPPINGS: Dict[str, Tuple[str, str, float]] = {
    # ---------------------------------------------------------------------
    # BROWSERS
    # ---------------------------------------------------------------------
    'google chrome': ('google', 'chrome', 0.95),
    'chrome': ('google', 'chrome', 0.85),
    'chromium': ('chromium', 'chromium', 0.90),
    'microsoft edge': ('microsoft', 'edge', 0.95),
    'edge': ('microsoft', 'edge', 0.75),
    'mozilla firefox': ('mozilla', 'firefox', 0.95),
    'firefox': ('mozilla', 'firefox', 0.90),
    'opera': ('opera', 'opera_browser', 0.85),
    'brave': ('brave', 'brave', 0.90),
    'vivaldi': ('vivaldi', 'vivaldi', 0.90),

    # ---------------------------------------------------------------------
    # MICROSOFT PRODUCTS
    # ---------------------------------------------------------------------
    'microsoft office': ('microsoft', 'office', 0.90),
    'microsoft 365': ('microsoft', '365_apps', 0.90),
    'office 365': ('microsoft', '365_apps', 0.85),
    'microsoft word': ('microsoft', 'word', 0.95),
    'microsoft excel': ('microsoft', 'excel', 0.95),
    'microsoft outlook': ('microsoft', 'outlook', 0.95),
    'microsoft powerpoint': ('microsoft', 'powerpoint', 0.95),
    'microsoft teams': ('microsoft', 'teams', 0.95),
    'microsoft onedrive': ('microsoft', 'onedrive', 0.95),
    'onedrive': ('microsoft', 'onedrive', 0.85),
    'visual studio code': ('microsoft', 'visual_studio_code', 0.95),
    'vscode': ('microsoft', 'visual_studio_code', 0.85),
    'visual studio': ('microsoft', 'visual_studio', 0.90),
    'microsoft .net': ('microsoft', '.net', 0.90),
    '.net framework': ('microsoft', '.net_framework', 0.90),
    '.net core': ('microsoft', '.net_core', 0.90),
    'dotnet': ('microsoft', '.net', 0.80),
    'powershell': ('microsoft', 'powershell', 0.90),
    'windows terminal': ('microsoft', 'windows_terminal', 0.90),
    'sql server': ('microsoft', 'sql_server', 0.90),
    'microsoft sql': ('microsoft', 'sql_server', 0.85),
    'azure cli': ('microsoft', 'azure_cli', 0.90),

    # ---------------------------------------------------------------------
    # DEVELOPMENT TOOLS
    # ---------------------------------------------------------------------
    'git': ('git-scm', 'git', 0.85),
    'git for windows': ('git-scm', 'git', 0.90),
    'github desktop': ('github', 'desktop', 0.90),
    'nodejs': ('nodejs', 'node.js', 0.90),
    'node.js': ('nodejs', 'node.js', 0.95),
    'node': ('nodejs', 'node.js', 0.75),
    'python': ('python', 'python', 0.90),
    'java': ('oracle', 'jdk', 0.75),
    'openjdk': ('oracle', 'openjdk', 0.90),
    'oracle java': ('oracle', 'jdk', 0.90),
    'amazon corretto': ('amazon', 'corretto', 0.95),
    'corretto': ('amazon', 'corretto', 0.85),
    'adoptopenjdk': ('adoptopenjdk', 'openjdk', 0.90),
    'eclipse temurin': ('eclipse', 'temurin', 0.90),
    'rust': ('rust-lang', 'rust', 0.90),
    'go': ('golang', 'go', 0.80),
    'golang': ('golang', 'go', 0.90),
    'ruby': ('ruby-lang', 'ruby', 0.90),
    'php': ('php', 'php', 0.90),
    'perl': ('perl', 'perl', 0.90),

    # ---------------------------------------------------------------------
    # IDEs & EDITORS
    # ---------------------------------------------------------------------
    'jetbrains intellij': ('jetbrains', 'intellij_idea', 0.95),
    'intellij idea': ('jetbrains', 'intellij_idea', 0.95),
    'intellij': ('jetbrains', 'intellij_idea', 0.85),
    'pycharm': ('jetbrains', 'pycharm', 0.95),
    'webstorm': ('jetbrains', 'webstorm', 0.95),
    'phpstorm': ('jetbrains', 'phpstorm', 0.95),
    'rider': ('jetbrains', 'rider', 0.90),
    'goland': ('jetbrains', 'goland', 0.95),
    'datagrip': ('jetbrains', 'datagrip', 0.95),
    'rubymine': ('jetbrains', 'rubymine', 0.95),
    'clion': ('jetbrains', 'clion', 0.95),
    'notepad++': ('notepad-plus-plus', 'notepad\\+\\+', 0.95),
    'sublime text': ('sublimetext', 'sublime_text', 0.95),
    'atom': ('atom', 'atom', 0.85),
    'vim': ('vim', 'vim', 0.90),
    'neovim': ('neovim', 'neovim', 0.90),
    'emacs': ('gnu', 'emacs', 0.90),

    # ---------------------------------------------------------------------
    # SECURITY & PASSWORD MANAGERS
    # ---------------------------------------------------------------------
    'keepass': ('keepass', 'keepass', 0.95),
    'keepass password safe': ('keepass', 'keepass', 0.95),
    'keepassxc': ('keepassxc', 'keepassxc', 0.95),
    '1password': ('1password', '1password', 0.95),
    'bitwarden': ('bitwarden', 'bitwarden', 0.95),
    'lastpass': ('lastpass', 'lastpass', 0.95),
    'dashlane': ('dashlane', 'dashlane', 0.90),

    # ---------------------------------------------------------------------
    # REMOTE ACCESS & VPN
    # ---------------------------------------------------------------------
    'teamviewer': ('teamviewer', 'teamviewer', 0.95),
    'anydesk': ('anydesk', 'anydesk', 0.95),
    'putty': ('putty', 'putty', 0.95),
    'winscp': ('winscp', 'winscp', 0.95),
    'filezilla': ('filezilla', 'filezilla_client', 0.95),
    'openvpn': ('openvpn', 'openvpn', 0.95),
    'wireguard': ('wireguard', 'wireguard', 0.95),
    'cisco anyconnect': ('cisco', 'anyconnect_secure_mobility_client', 0.95),
    'anyconnect': ('cisco', 'anyconnect_secure_mobility_client', 0.85),
    'globalprotect': ('paloaltonetworks', 'globalprotect', 0.95),
    'palo alto globalprotect': ('paloaltonetworks', 'globalprotect', 0.95),
    'fortinet forticlient': ('fortinet', 'forticlient', 0.95),
    'forticlient': ('fortinet', 'forticlient', 0.90),
    'pulse secure': ('pulsesecure', 'pulse_connect_secure', 0.90),
    'remote desktop': ('microsoft', 'remote_desktop_connection', 0.80),
    'rdp': ('microsoft', 'remote_desktop_connection', 0.70),

    # ---------------------------------------------------------------------
    # COMPRESSION & ARCHIVING
    # ---------------------------------------------------------------------
    '7-zip': ('7-zip', '7-zip', 0.95),
    '7zip': ('7-zip', '7-zip', 0.90),
    'winrar': ('rarlab', 'winrar', 0.95),
    'winzip': ('corel', 'winzip', 0.95),
    'peazip': ('peazip', 'peazip', 0.95),

    # ---------------------------------------------------------------------
    # PDF & DOCUMENT READERS
    # ---------------------------------------------------------------------
    'adobe acrobat': ('adobe', 'acrobat', 0.95),
    'acrobat reader': ('adobe', 'acrobat_reader_dc', 0.95),
    'adobe reader': ('adobe', 'acrobat_reader_dc', 0.90),
    'foxit reader': ('foxitsoftware', 'foxit_reader', 0.95),
    'foxit pdf': ('foxitsoftware', 'foxit_reader', 0.85),
    'pdf24': ('pdf24', 'creator', 0.90),
    'pdf24 creator': ('pdf24', 'creator', 0.95),
    'sumatrapdf': ('sumatrapdfreader', 'sumatrapdf', 0.95),

    # ---------------------------------------------------------------------
    # MEDIA PLAYERS
    # ---------------------------------------------------------------------
    'vlc': ('videolan', 'vlc_media_player', 0.95),
    'vlc media player': ('videolan', 'vlc_media_player', 0.95),
    'windows media player': ('microsoft', 'windows_media_player', 0.90),
    'spotify': ('spotify', 'spotify', 0.95),
    'itunes': ('apple', 'itunes', 0.95),
    'audacity': ('audacityteam', 'audacity', 0.95),

    # ---------------------------------------------------------------------
    # COMMUNICATION
    # ---------------------------------------------------------------------
    'zoom': ('zoom', 'zoom', 0.90),
    'zoom client': ('zoom', 'zoom', 0.95),
    'slack': ('slack', 'slack', 0.95),
    'discord': ('discord', 'discord', 0.95),
    'skype': ('microsoft', 'skype', 0.95),
    'webex': ('cisco', 'webex_meetings', 0.90),
    'cisco webex': ('cisco', 'webex_meetings', 0.95),

    # ---------------------------------------------------------------------
    # DATABASE TOOLS
    # ---------------------------------------------------------------------
    'mysql': ('oracle', 'mysql', 0.90),
    'mysql workbench': ('oracle', 'mysql_workbench', 0.95),
    'postgresql': ('postgresql', 'postgresql', 0.95),
    'postgres': ('postgresql', 'postgresql', 0.85),
    'pgadmin': ('pgadmin', 'pgadmin', 0.90),
    'mongodb': ('mongodb', 'mongodb', 0.95),
    'mongodb compass': ('mongodb', 'compass', 0.95),
    'redis': ('redis', 'redis', 0.95),
    'dbeaver': ('dbeaver', 'dbeaver', 0.95),
    'heidisql': ('heidisql', 'heidisql', 0.95),

    # ---------------------------------------------------------------------
    # CONTAINERS & VIRTUALIZATION
    # ---------------------------------------------------------------------
    'docker': ('docker', 'docker', 0.90),
    'docker desktop': ('docker', 'docker_desktop', 0.95),
    'virtualbox': ('oracle', 'vm_virtualbox', 0.95),
    'oracle virtualbox': ('oracle', 'vm_virtualbox', 0.95),
    'vmware workstation': ('vmware', 'workstation', 0.95),
    'vmware player': ('vmware', 'workstation_player', 0.95),
    'vmware': ('vmware', 'workstation', 0.75),
    'hyper-v': ('microsoft', 'hyper-v', 0.90),
    'vagrant': ('hashicorp', 'vagrant', 0.95),
    'kubernetes': ('kubernetes', 'kubernetes', 0.90),
    'kubectl': ('kubernetes', 'kubectl', 0.90),

    # ---------------------------------------------------------------------
    # SYSTEM UTILITIES
    # ---------------------------------------------------------------------
    'ccleaner': ('piriform', 'ccleaner', 0.95),
    'malwarebytes': ('malwarebytes', 'malwarebytes', 0.95),
    'wireshark': ('wireshark', 'wireshark', 0.95),
    'sysinternals': ('microsoft', 'sysinternals', 0.85),
    'process explorer': ('microsoft', 'process_explorer', 0.90),
    'everything': ('voidtools', 'everything', 0.90),
    'greenshot': ('greenshot', 'greenshot', 0.95),
    'sharex': ('sharex', 'sharex', 0.95),
    'cpu-z': ('cpuid', 'cpu-z', 0.95),
    'gpu-z': ('techpowerup', 'gpu-z', 0.95),
    'hwinfo': ('hwinfo', 'hwinfo', 0.95),

    # ---------------------------------------------------------------------
    # DELL TOOLS
    # ---------------------------------------------------------------------
    'dell command update': ('dell', 'command_update', 0.95),
    'dell command configure': ('dell', 'command_configure', 0.95),
    'dell supportassist': ('dell', 'supportassist', 0.95),

    # ---------------------------------------------------------------------
    # LOGITECH
    # ---------------------------------------------------------------------
    'logitech options': ('logitech', 'options', 0.90),
    'logi options': ('logitech', 'options', 0.85),
    'logitech g hub': ('logitech', 'g_hub', 0.95),

    # ---------------------------------------------------------------------
    # NVIDIA
    # ---------------------------------------------------------------------
    'nvidia geforce': ('nvidia', 'geforce_experience', 0.90),
    'geforce experience': ('nvidia', 'geforce_experience', 0.95),
    'nvidia driver': ('nvidia', 'gpu_display_driver', 0.85),

    # ---------------------------------------------------------------------
    # ADOBE CREATIVE
    # ---------------------------------------------------------------------
    'adobe photoshop': ('adobe', 'photoshop', 0.95),
    'photoshop': ('adobe', 'photoshop', 0.85),
    'adobe illustrator': ('adobe', 'illustrator', 0.95),
    'adobe premiere': ('adobe', 'premiere_pro', 0.95),
    'adobe after effects': ('adobe', 'after_effects', 0.95),
    'adobe creative cloud': ('adobe', 'creative_cloud_desktop_application', 0.95),

    # ---------------------------------------------------------------------
    # ANTIVIRUS
    # ---------------------------------------------------------------------
    'windows defender': ('microsoft', 'windows_defender', 0.95),
    'norton': ('nortonlifelock', 'norton_antivirus', 0.80),
    'norton antivirus': ('nortonlifelock', 'norton_antivirus', 0.95),
    'mcafee': ('mcafee', 'total_protection', 0.80),
    'kaspersky': ('kaspersky', 'anti-virus', 0.80),
    'avast': ('avast', 'antivirus', 0.85),
    'avg': ('avg', 'anti-virus', 0.80),
    'bitdefender': ('bitdefender', 'total_security', 0.85),
    'eset': ('eset', 'nod32_antivirus', 0.80),
    'sophos': ('sophos', 'endpoint_protection', 0.80),
    'trend micro': ('trendmicro', 'officescan', 0.80),
    'crowdstrike': ('crowdstrike', 'falcon', 0.85),
    'carbon black': ('vmware', 'carbon_black_cloud', 0.85),
    'sentinelone': ('sentinelone', 'sentinelone', 0.90),

    # ---------------------------------------------------------------------
    # LINUX COMMON
    # ---------------------------------------------------------------------
    'openssh': ('openbsd', 'openssh', 0.95),
    'openssl': ('openssl', 'openssl', 0.95),
    'apache': ('apache', 'http_server', 0.85),
    'apache httpd': ('apache', 'http_server', 0.95),
    'nginx': ('nginx', 'nginx', 0.95),
    'curl': ('haxx', 'curl', 0.95),
    'wget': ('gnu', 'wget', 0.95),
    'bash': ('gnu', 'bash', 0.90),
    'sudo': ('sudo_project', 'sudo', 0.95),
    'systemd': ('systemd_project', 'systemd', 0.95),
}

# =============================================================================
# VENDOR NAME NORMALIZATION
# =============================================================================
# Maps common vendor name variations to normalized form

VENDOR_NORMALIZATIONS = {
    'microsoft corporation': 'microsoft',
    'microsoft corp': 'microsoft',
    'google llc': 'google',
    'google inc': 'google',
    'apple inc': 'apple',
    'apple computer': 'apple',
    'adobe systems': 'adobe',
    'adobe inc': 'adobe',
    'oracle corporation': 'oracle',
    'oracle america': 'oracle',
    'mozilla foundation': 'mozilla',
    'mozilla corporation': 'mozilla',
    'the document foundation': 'libreoffice',
    'videolan': 'videolan',
    'dell inc': 'dell',
    'dell technologies': 'dell',
    'hewlett packard': 'hp',
    'hp inc': 'hp',
    'logitech': 'logitech',
    'nvidia corporation': 'nvidia',
    'intel corporation': 'intel',
    'amd': 'amd',
    'advanced micro devices': 'amd',
    'cisco systems': 'cisco',
    'vmware': 'vmware',
    'broadcom': 'vmware',  # VMware acquired by Broadcom
    'hashicorp': 'hashicorp',
    'jetbrains': 'jetbrains',
    'jetbrains s.r.o': 'jetbrains',
    'dominik reichl': 'keepass',  # KeePass author
    'martin prikryl': 'winscp',  # WinSCP author
    'geek software gmbh': 'pdf24',
    'imagewriter developers': 'imagewriter',
}


def normalize_text(text: str) -> str:
    """Normalize text for matching - lowercase, remove special chars."""
    if not text:
        return ''
    # Lowercase
    text = text.lower()
    # Remove version numbers at the end (e.g., "Chrome 120.0.1234")
    text = re.sub(r'\s+\d+[\d.]*\s*$', '', text)
    # Remove common suffixes
    text = re.sub(r'\s*(x64|x86|64-bit|32-bit|\(64-bit\)|\(x64\))\s*', '', text, flags=re.IGNORECASE)
    # Normalize whitespace
    text = ' '.join(text.split())
    return text.strip()


def normalize_vendor(vendor: str) -> str:
    """Normalize vendor name using known mappings."""
    if not vendor:
        return ''
    vendor_lower = vendor.lower().strip()
    return VENDOR_NORMALIZATIONS.get(vendor_lower, vendor_lower)


def get_cpe_from_mapping(vendor: str, product_name: str) -> Tuple[Optional[str], Optional[str], float]:
    """
    Look up CPE mapping from curated database.

    Returns: (cpe_vendor, cpe_product, confidence) or (None, None, 0.0)
    """
    if not product_name:
        return None, None, 0.0

    # Normalize inputs
    norm_product = normalize_text(product_name)
    norm_vendor = normalize_vendor(vendor)

    # Build search strings to check
    search_strings = [
        f"{norm_vendor} {norm_product}",  # Full: "google google chrome"
        norm_product,                       # Product only: "google chrome"
        f"{norm_vendor} {norm_product.split()[0]}" if norm_product else '',  # Vendor + first word
    ]

    # Check each search string against mappings
    for search_str in search_strings:
        if not search_str:
            continue
        search_str = search_str.strip()

        # Direct match
        if search_str in SOFTWARE_TO_CPE_MAPPINGS:
            cpe_vendor, cpe_product, confidence = SOFTWARE_TO_CPE_MAPPINGS[search_str]
            logger.debug(f"Direct CPE match: '{search_str}' -> {cpe_vendor}:{cpe_product} ({confidence})")
            return cpe_vendor, cpe_product, confidence

        # Partial match - check if any mapping key is contained in search string
        for pattern, (cpe_vendor, cpe_product, confidence) in SOFTWARE_TO_CPE_MAPPINGS.items():
            if pattern in search_str or search_str in pattern:
                logger.debug(f"Partial CPE match: '{search_str}' ~ '{pattern}' -> {cpe_vendor}:{cpe_product} ({confidence * 0.9})")
                return cpe_vendor, cpe_product, confidence * 0.9  # Slightly lower confidence for partial

    return None, None, 0.0


def get_cpe_for_software(vendor: str, product_name: str, use_nvd_fallback: bool = True) -> Tuple[Optional[str], Optional[str], float]:
    """
    Get CPE for software using:
    1. Curated mapping table (fast, reliable)
    2. NVD API search (slow, less reliable) - optional fallback

    Returns: (cpe_vendor, cpe_product, confidence)
    """
    # First try curated mappings
    cpe_vendor, cpe_product, confidence = get_cpe_from_mapping(vendor, product_name)

    if cpe_vendor and cpe_product:
        return cpe_vendor, cpe_product, confidence

    # Fallback to NVD API search if enabled
    if use_nvd_fallback:
        try:
            from app.integrations_api import attempt_cpe_match
            cpe_vendor, cpe_product, confidence = attempt_cpe_match(vendor, product_name)
            if cpe_vendor and cpe_product:
                logger.debug(f"NVD fallback match: {vendor} {product_name} -> {cpe_vendor}:{cpe_product}")
                return cpe_vendor, cpe_product, confidence
        except Exception as e:
            logger.warning(f"NVD CPE search failed: {e}")

    return None, None, 0.0


# =============================================================================
# USER-LEARNED MAPPINGS
# =============================================================================

def save_user_mapping(vendor: str, product_name: str, cpe_vendor: str, cpe_product: str):
    """
    Save a user-confirmed mapping to the database for future use.
    This allows the system to learn from user corrections.
    """
    from app import db
    from app.models import SystemSettings
    import json

    try:
        # Get or create the user mappings setting
        setting = SystemSettings.query.filter_by(key='user_cpe_mappings').first()

        if setting:
            mappings = json.loads(setting.value or '{}')
        else:
            mappings = {}
            setting = SystemSettings(
                key='user_cpe_mappings',
                category='cpe',
                description='User-confirmed CPE mappings'
            )
            db.session.add(setting)

        # Create normalized key
        norm_key = normalize_text(f"{normalize_vendor(vendor)} {product_name}")

        # Save mapping
        mappings[norm_key] = {
            'vendor': vendor,
            'product_name': product_name,
            'cpe_vendor': cpe_vendor,
            'cpe_product': cpe_product
        }

        setting.value = json.dumps(mappings)
        db.session.commit()

        logger.info(f"Saved user CPE mapping: {norm_key} -> {cpe_vendor}:{cpe_product}")
        return True

    except Exception as e:
        logger.error(f"Failed to save user CPE mapping: {e}")
        return False


def get_user_mapping(vendor: str, product_name: str) -> Tuple[Optional[str], Optional[str]]:
    """
    Check if there's a user-confirmed mapping for this software.
    """
    from app.models import SystemSettings
    import json

    try:
        setting = SystemSettings.query.filter_by(key='user_cpe_mappings').first()
        if not setting or not setting.value:
            return None, None

        mappings = json.loads(setting.value)
        norm_key = normalize_text(f"{normalize_vendor(vendor)} {product_name}")

        if norm_key in mappings:
            m = mappings[norm_key]
            return m.get('cpe_vendor'), m.get('cpe_product')

        return None, None

    except Exception as e:
        logger.error(f"Failed to get user CPE mapping: {e}")
        return None, None
