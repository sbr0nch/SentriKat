"""
CPE Auto-Mapping Module

Maps common software names to their official CPE (Common Platform Enumeration) identifiers.
This enables more precise vulnerability matching against CISA KEV and NVD data.

CPE format: cpe:2.3:a:vendor:product:version:...
We store just vendor and product for matching.
"""

import re
from app import db
from sqlalchemy import func

# ============================================================================
# CPE Mappings Database
# Format: (pattern_type, pattern, cpe_vendor, cpe_product)
# pattern_type: 'exact' (case-insensitive exact match) or 'regex' (regex pattern)
# ============================================================================

CPE_MAPPINGS = [
    # -------------------------------------------------------------------------
    # Web Browsers
    # -------------------------------------------------------------------------
    ('regex', r'^mozilla\s*firefox', 'mozilla', 'firefox'),
    ('regex', r'^firefox', 'mozilla', 'firefox'),
    ('regex', r'^google\s*chrome', 'google', 'chrome'),
    ('regex', r'^chrome', 'google', 'chrome'),
    ('regex', r'^microsoft\s*edge', 'microsoft', 'edge'),
    ('regex', r'^edge', 'microsoft', 'edge_chromium'),
    ('regex', r'^opera', 'opera', 'opera_browser'),
    ('regex', r'^brave', 'brave', 'brave'),
    ('regex', r'^vivaldi', 'vivaldi', 'vivaldi'),

    # -------------------------------------------------------------------------
    # Microsoft Products
    # -------------------------------------------------------------------------
    ('regex', r'^microsoft\s*office', 'microsoft', 'office'),
    ('regex', r'^microsoft\s*365', 'microsoft', '365_apps'),
    ('regex', r'^microsoft\s*word', 'microsoft', 'word'),
    ('regex', r'^microsoft\s*excel', 'microsoft', 'excel'),
    ('regex', r'^microsoft\s*outlook', 'microsoft', 'outlook'),
    ('regex', r'^microsoft\s*powerpoint', 'microsoft', 'powerpoint'),
    ('regex', r'^microsoft\s*teams', 'microsoft', 'teams'),
    ('regex', r'^microsoft\s*visual\s*studio\s*code', 'microsoft', 'visual_studio_code'),
    ('regex', r'^visual\s*studio\s*code', 'microsoft', 'visual_studio_code'),
    ('regex', r'^vs\s*code', 'microsoft', 'visual_studio_code'),
    ('regex', r'^microsoft\s*visual\s*studio', 'microsoft', 'visual_studio'),
    ('regex', r'^visual\s*studio\s+20\d{2}', 'microsoft', 'visual_studio'),
    ('regex', r'^microsoft\s*\.net', 'microsoft', '.net_framework'),
    ('regex', r'^\.net\s*(framework|runtime|sdk)', 'microsoft', '.net'),
    ('regex', r'^microsoft\s*sql\s*server', 'microsoft', 'sql_server'),
    ('regex', r'^sql\s*server', 'microsoft', 'sql_server'),
    ('regex', r'^microsoft\s*sharepoint', 'microsoft', 'sharepoint_server'),
    ('regex', r'^microsoft\s*exchange', 'microsoft', 'exchange_server'),
    ('regex', r'^windows\s*terminal', 'microsoft', 'windows_terminal'),
    ('regex', r'^powershell', 'microsoft', 'powershell'),
    ('regex', r'^onedrive', 'microsoft', 'onedrive'),
    ('regex', r'^skype', 'microsoft', 'skype'),

    # -------------------------------------------------------------------------
    # Adobe Products
    # -------------------------------------------------------------------------
    ('regex', r'^adobe\s*acrobat\s*reader', 'adobe', 'acrobat_reader_dc'),
    ('regex', r'^adobe\s*reader', 'adobe', 'acrobat_reader_dc'),
    ('regex', r'^acrobat\s*reader', 'adobe', 'acrobat_reader_dc'),
    ('regex', r'^adobe\s*acrobat', 'adobe', 'acrobat_dc'),
    ('regex', r'^adobe\s*flash', 'adobe', 'flash_player'),
    ('regex', r'^flash\s*player', 'adobe', 'flash_player'),
    ('regex', r'^adobe\s*photoshop', 'adobe', 'photoshop'),
    ('regex', r'^adobe\s*illustrator', 'adobe', 'illustrator'),
    ('regex', r'^adobe\s*premiere', 'adobe', 'premiere_pro'),
    ('regex', r'^adobe\s*creative\s*cloud', 'adobe', 'creative_cloud_desktop_application'),

    # -------------------------------------------------------------------------
    # Development Tools
    # -------------------------------------------------------------------------
    ('regex', r'^git\b(?!\s*hub)', 'git', 'git'),  # git but not github
    ('regex', r'^git\s+for\s+windows', 'git', 'git'),
    ('regex', r'^github\s*desktop', 'github', 'desktop'),
    ('regex', r'^node\.?js', 'nodejs', 'node.js'),
    ('regex', r'^node\s+js', 'nodejs', 'node.js'),
    ('regex', r'^python', 'python', 'python'),
    ('regex', r'^java\s*(development\s*kit|jdk|runtime|jre)?', 'oracle', 'jdk'),
    ('regex', r'^openjdk', 'oracle', 'openjdk'),
    ('regex', r'^oracle\s*java', 'oracle', 'jdk'),
    ('regex', r'^php', 'php', 'php'),
    ('regex', r'^ruby', 'ruby-lang', 'ruby'),
    ('regex', r'^golang|^go\s+\d', 'golang', 'go'),
    ('regex', r'^rust', 'rust-lang', 'rust'),
    ('regex', r'^perl', 'perl', 'perl'),
    ('regex', r'^jetbrains\s*intellij', 'jetbrains', 'intellij_idea'),
    ('regex', r'^intellij', 'jetbrains', 'intellij_idea'),
    ('regex', r'^jetbrains\s*pycharm', 'jetbrains', 'pycharm'),
    ('regex', r'^pycharm', 'jetbrains', 'pycharm'),
    ('regex', r'^jetbrains\s*webstorm', 'jetbrains', 'webstorm'),
    ('regex', r'^webstorm', 'jetbrains', 'webstorm'),
    ('regex', r'^jetbrains\s*phpstorm', 'jetbrains', 'phpstorm'),
    ('regex', r'^eclipse', 'eclipse', 'eclipse_ide'),
    ('regex', r'^sublime\s*text', 'sublimehq', 'sublime_text'),
    ('regex', r'^notepad\+\+', 'notepad-plus-plus', 'notepad++'),
    ('regex', r'^atom\s*(editor)?', 'atom', 'atom'),
    ('regex', r'^postman', 'postman', 'postman'),
    ('regex', r'^docker\s*desktop', 'docker', 'desktop'),
    ('regex', r'^docker', 'docker', 'docker'),
    ('regex', r'^kubernetes|^kubectl', 'kubernetes', 'kubernetes'),
    ('regex', r'^vagrant', 'hashicorp', 'vagrant'),
    ('regex', r'^terraform', 'hashicorp', 'terraform'),
    ('regex', r'^ansible', 'redhat', 'ansible'),

    # -------------------------------------------------------------------------
    # Utilities & Tools
    # -------------------------------------------------------------------------
    ('regex', r'^7-?zip', '7-zip', '7-zip'),
    ('regex', r'^winrar', 'rarlab', 'winrar'),
    ('regex', r'^winzip', 'corel', 'winzip'),
    ('regex', r'^peazip', 'peazip', 'peazip'),
    ('regex', r'^vlc', 'videolan', 'vlc_media_player'),
    ('regex', r'^videolan\s*vlc', 'videolan', 'vlc_media_player'),
    ('regex', r'^audacity', 'audacityteam', 'audacity'),
    ('regex', r'^gimp', 'gimp', 'gimp'),
    ('regex', r'^inkscape', 'inkscape', 'inkscape'),
    ('regex', r'^libreoffice', 'libreoffice', 'libreoffice'),
    ('regex', r'^openoffice', 'apache', 'openoffice'),
    ('regex', r'^filezilla', 'filezilla', 'filezilla_client'),
    ('regex', r'^putty', 'putty', 'putty'),
    ('regex', r'^winscp', 'winscp', 'winscp'),
    ('regex', r'^wireshark', 'wireshark', 'wireshark'),
    ('regex', r'^nmap', 'nmap', 'nmap'),
    ('regex', r'^virtualbox', 'oracle', 'virtualbox'),
    ('regex', r'^vmware\s*workstation', 'vmware', 'workstation'),
    ('regex', r'^vmware\s*player', 'vmware', 'player'),
    ('regex', r'^vmware\s*fusion', 'vmware', 'fusion'),
    ('regex', r'^keepass', 'keepass', 'keepass'),
    ('regex', r'^bitwarden', 'bitwarden', 'bitwarden'),
    ('regex', r'^1password', 'agilebits', '1password'),
    ('regex', r'^lastpass', 'lastpass', 'lastpass'),
    ('regex', r'^ccleaner', 'piriform', 'ccleaner'),
    ('regex', r'^malwarebytes', 'malwarebytes', 'malwarebytes'),
    ('regex', r'^everything\s*(search)?', 'voidtools', 'everything'),
    ('regex', r'^greenshot', 'greenshot', 'greenshot'),
    ('regex', r'^sharex', 'sharex', 'sharex'),
    ('regex', r'^zoom', 'zoom', 'zoom'),
    ('regex', r'^slack', 'slack', 'slack'),
    ('regex', r'^discord', 'discord', 'discord'),
    ('regex', r'^telegram', 'telegram', 'telegram_desktop'),
    ('regex', r'^signal', 'signal', 'signal-desktop'),
    ('regex', r'^spotify', 'spotify', 'spotify'),

    # -------------------------------------------------------------------------
    # Security & Antivirus
    # -------------------------------------------------------------------------
    ('regex', r'^norton', 'norton', 'norton_antivirus'),
    ('regex', r'^mcafee', 'mcafee', 'total_protection'),
    ('regex', r'^avast', 'avast', 'antivirus'),
    ('regex', r'^avg\s*(antivirus)?', 'avg', 'anti-virus'),
    ('regex', r'^kaspersky', 'kaspersky', 'anti-virus'),
    ('regex', r'^bitdefender', 'bitdefender', 'total_security'),
    ('regex', r'^eset', 'eset', 'nod32_antivirus'),
    ('regex', r'^sophos', 'sophos', 'endpoint_protection'),
    ('regex', r'^trend\s*micro', 'trendmicro', 'officescan'),
    ('regex', r'^crowdstrike', 'crowdstrike', 'falcon'),
    ('regex', r'^carbon\s*black', 'vmware', 'carbon_black'),
    ('regex', r'^sentinel\s*one', 'sentinelone', 'sentinelone'),

    # -------------------------------------------------------------------------
    # Databases
    # -------------------------------------------------------------------------
    ('regex', r'^mysql', 'oracle', 'mysql'),
    ('regex', r'^mariadb', 'mariadb', 'mariadb'),
    ('regex', r'^postgresql|^postgres', 'postgresql', 'postgresql'),
    ('regex', r'^mongodb', 'mongodb', 'mongodb'),
    ('regex', r'^redis', 'redis', 'redis'),
    ('regex', r'^sqlite', 'sqlite', 'sqlite'),
    ('regex', r'^oracle\s*database', 'oracle', 'database'),
    ('regex', r'^elasticsearch', 'elastic', 'elasticsearch'),

    # -------------------------------------------------------------------------
    # Web Servers & Runtime
    # -------------------------------------------------------------------------
    ('regex', r'^apache\s*(http|web)?\s*server', 'apache', 'http_server'),
    ('regex', r'^httpd', 'apache', 'http_server'),
    ('regex', r'^nginx', 'nginx', 'nginx'),
    ('regex', r'^iis|internet\s*information\s*services', 'microsoft', 'internet_information_services'),
    ('regex', r'^tomcat', 'apache', 'tomcat'),
    ('regex', r'^jetty', 'eclipse', 'jetty'),

    # -------------------------------------------------------------------------
    # Networking
    # -------------------------------------------------------------------------
    ('regex', r'^openssl', 'openssl', 'openssl'),
    ('regex', r'^openssh', 'openbsd', 'openssh'),
    ('regex', r'^curl', 'haxx', 'curl'),
    ('regex', r'^wget', 'gnu', 'wget'),

    # -------------------------------------------------------------------------
    # Linux Common Packages
    # -------------------------------------------------------------------------
    ('regex', r'^sudo', 'todd_miller', 'sudo'),
    ('regex', r'^bash', 'gnu', 'bash'),
    ('regex', r'^glibc|^libc6', 'gnu', 'glibc'),
    ('regex', r'^systemd', 'systemd', 'systemd'),
    ('regex', r'^kernel|^linux-image', 'linux', 'linux_kernel'),
    ('regex', r'^vim', 'vim', 'vim'),
    ('regex', r'^nano', 'gnu', 'nano'),
    ('regex', r'^emacs', 'gnu', 'emacs'),
    ('regex', r'^bind|^named', 'isc', 'bind'),
    ('regex', r'^dhcp', 'isc', 'dhcp'),
    ('regex', r'^postfix', 'postfix', 'postfix'),
    ('regex', r'^sendmail', 'sendmail', 'sendmail'),
    ('regex', r'^samba', 'samba', 'samba'),
    ('regex', r'^cups', 'apple', 'cups'),
    ('regex', r'^grub', 'gnu', 'grub2'),

    # -------------------------------------------------------------------------
    # Virtualization & Containers
    # -------------------------------------------------------------------------
    ('regex', r'^qemu', 'qemu', 'qemu'),
    ('regex', r'^libvirt', 'redhat', 'libvirt'),
    ('regex', r'^podman', 'redhat', 'podman'),
    ('regex', r'^containerd', 'linuxfoundation', 'containerd'),
]


def get_cpe_for_product(product_name, vendor_name=None):
    """
    Get CPE vendor and product for a given product name.

    Args:
        product_name: The product name to look up
        vendor_name: Optional vendor name for better matching

    Returns:
        tuple: (cpe_vendor, cpe_product) or (None, None) if no match
    """
    if not product_name:
        return None, None

    # Normalize the product name
    name_lower = product_name.lower().strip()

    # Remove common suffixes for better matching
    name_lower = re.sub(r'\s*\([^)]*\)\s*$', '', name_lower)  # Remove (x64), (64-bit), etc.
    name_lower = re.sub(r'\s+v?\d+\..*$', '', name_lower)     # Remove version numbers

    # Try each mapping
    for pattern_type, pattern, cpe_vendor, cpe_product in CPE_MAPPINGS:
        if pattern_type == 'exact':
            if name_lower == pattern.lower():
                return cpe_vendor, cpe_product
        elif pattern_type == 'regex':
            if re.match(pattern, name_lower, re.IGNORECASE):
                return cpe_vendor, cpe_product

    return None, None


def apply_cpe_to_product(product):
    """
    Apply CPE mapping to a single product if it doesn't have CPE set.

    Args:
        product: Product model instance

    Returns:
        bool: True if CPE was applied, False otherwise
    """
    # Skip if already has CPE
    if product.cpe_vendor and product.cpe_product:
        return False

    cpe_vendor, cpe_product = get_cpe_for_product(product.product_name, product.vendor)

    if cpe_vendor and cpe_product:
        product.cpe_vendor = cpe_vendor
        product.cpe_product = cpe_product
        return True

    return False


def batch_apply_cpe_mappings(commit=True):
    """
    Apply CPE mappings to all products that don't have CPE set.

    Args:
        commit: Whether to commit the changes to database

    Returns:
        tuple: (updated_count, total_without_cpe)
    """
    from app.models import Product

    # Get products without CPE
    products_without_cpe = Product.query.filter(
        db.or_(
            Product.cpe_vendor.is_(None),
            Product.cpe_vendor == '',
            Product.cpe_product.is_(None),
            Product.cpe_product == ''
        )
    ).all()

    total_without_cpe = len(products_without_cpe)
    updated_count = 0

    for product in products_without_cpe:
        if apply_cpe_to_product(product):
            updated_count += 1

    if commit and updated_count > 0:
        db.session.commit()

    return updated_count, total_without_cpe


def get_cpe_coverage_stats():
    """
    Get statistics about CPE coverage for products.

    Returns:
        dict with coverage statistics
    """
    from app.models import Product

    total = Product.query.count() or 0
    with_cpe = Product.query.filter(
        Product.cpe_vendor.isnot(None),
        Product.cpe_vendor != '',
        Product.cpe_product.isnot(None),
        Product.cpe_product != ''
    ).count() or 0

    return {
        'total_products': total,
        'with_cpe': with_cpe,
        'without_cpe': total - with_cpe,
        'coverage_percent': round((with_cpe / total * 100) if total > 0 else 0, 1)
    }


def suggest_cpe_for_products(limit=50):
    """
    Suggest CPE mappings for products without CPE.
    Returns list of suggestions without applying them.

    Args:
        limit: Maximum number of suggestions to return

    Returns:
        list of dicts with product info and suggested CPE
    """
    from app.models import Product

    products_without_cpe = Product.query.filter(
        db.or_(
            Product.cpe_vendor.is_(None),
            Product.cpe_vendor == '',
            Product.cpe_product.is_(None),
            Product.cpe_product == ''
        )
    ).limit(limit * 2).all()  # Get more to filter

    suggestions = []
    for product in products_without_cpe:
        cpe_vendor, cpe_product = get_cpe_for_product(product.product_name, product.vendor)
        if cpe_vendor and cpe_product:
            suggestions.append({
                'product_id': product.id,
                'product_name': product.product_name,
                'vendor': product.vendor,
                'suggested_cpe_vendor': cpe_vendor,
                'suggested_cpe_product': cpe_product
            })
            if len(suggestions) >= limit:
                break

    return suggestions
