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
    ('regex', r'^git\b(?!\s*hub)', 'git-scm', 'git'),  # git but not github
    ('regex', r'^git\s+for\s+windows', 'git-scm', 'git'),
    ('regex', r'^github\s*desktop', 'github', 'desktop'),
    ('regex', r'^node\.?js', 'nodejs', 'node.js'),
    ('regex', r'^node\s+js', 'nodejs', 'node.js'),
    ('regex', r'^python', 'python', 'python'),
    ('regex', r'^java(?!script)\s*(development\s*kit|jdk|runtime|jre|se|ee)?$', 'oracle', 'jdk'),
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
    ('regex', r'^sublime\s*text', 'sublimetext', 'sublime_text'),
    ('regex', r'^notepad\+\+', 'notepad-plus-plus', 'notepad++'),
    ('regex', r'^atom\s*(editor)?', 'atom', 'atom'),
    ('regex', r'^postman', 'postman', 'postman'),
    ('regex', r'^docker\s*desktop', 'docker', 'docker_desktop'),
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
    ('regex', r'^virtualbox', 'oracle', 'vm_virtualbox'),
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
    ('regex', r'^sudo', 'sudo_project', 'sudo'),
    ('regex', r'^bash', 'gnu', 'bash'),
    ('regex', r'^glibc|^libc6', 'gnu', 'glibc'),
    ('regex', r'^systemd', 'systemd_project', 'systemd'),
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

    # -------------------------------------------------------------------------
    # Dell Products (commonly reported as "Dell | Product Name")
    # Pipe separators are normalized before matching, so these patterns
    # match the part after the pipe (e.g., "Dell | Command Update" → "command update")
    # -------------------------------------------------------------------------
    ('regex', r'^command\s*update', 'dell', 'command_update'),
    ('regex', r'^supportassist', 'dell', 'supportassist'),
    ('regex', r'^bios', 'dell', 'bios'),
    ('regex', r'^power\s*manager', 'dell', 'power_manager'),
    ('regex', r'^digital\s*delivery', 'dell', 'digital_delivery'),
    ('regex', r'^openmanage\s*(server\s*administrator)?', 'dell', 'openmanage_server_administrator'),
    ('regex', r'^idrac', 'dell', 'idrac_firmware'),
    ('regex', r'^wyse\s*management\s*suite', 'dell', 'wyse_management_suite'),
    ('regex', r'^emc\s*unity', 'dell', 'emc_unity_operating_environment'),
    ('regex', r'^avamar', 'dell', 'avamar'),

    # -------------------------------------------------------------------------
    # HP / HPE Products (similar naming patterns)
    # -------------------------------------------------------------------------
    ('regex', r'^hp\s*support\s*assistant', 'hp', 'support_assistant'),
    ('regex', r'^hpe?\s*system\s*management\s*homepage', 'hp', 'system_management_homepage'),
    ('regex', r'^ilo\s*\d?', 'hp', 'integrated_lights-out'),
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

    # Handle vendor|product separators (e.g., "Dell | Command Update" -> "command update")
    if '|' in name_lower:
        parts = name_lower.split('|', 1)
        name_lower = parts[1].strip() if len(parts) > 1 and parts[1].strip() else name_lower

    # Remove common suffixes for better matching
    name_lower = re.sub(r'\s*\([^)]*\)', '', name_lower)      # Remove all parenthetical content
    name_lower = re.sub(r'\s+v?\d+[\d.]*\s*$', '', name_lower)  # Remove trailing version numbers
    name_lower = re.sub(r'\s+mui\s*$', '', name_lower)        # Remove trailing MUI
    name_lower = name_lower.strip()

    # Try each mapping
    for pattern_type, pattern, cpe_vendor, cpe_product in CPE_MAPPINGS:
        if pattern_type == 'exact':
            if name_lower == pattern.lower():
                return cpe_vendor, cpe_product
        elif pattern_type == 'regex':
            if re.match(pattern, name_lower, re.IGNORECASE):
                return cpe_vendor, cpe_product

    return None, None


def validate_cpe_assignment(product_vendor, product_name, cpe_vendor, cpe_product):
    """
    Sanity-check a CPE assignment to prevent clearly wrong mappings.

    Catches cases like Logitech products getting assigned git-scm:git.
    The key heuristic: at least one word in the product vendor OR product name
    must overlap with the CPE vendor OR CPE product. If there's zero overlap,
    the mapping is almost certainly wrong.

    Args:
        product_vendor: The product's vendor name (e.g., "Logitech")
        product_name: The product name (e.g., "Logi Options+")
        cpe_vendor: The proposed CPE vendor (e.g., "git-scm")
        cpe_product: The proposed CPE product (e.g., "git")

    Returns:
        bool: True if the assignment looks reasonable, False if suspicious
    """
    if not cpe_vendor or not cpe_product:
        return False

    # Skip validation for known special markers
    if cpe_vendor == '_skip':
        return True

    # Normalize all strings for comparison
    def to_words(s):
        if not s:
            return set()
        # Split on non-alphanumeric, lowercase, filter short noise words
        words = set(re.split(r'[^a-z0-9]+', s.lower()))
        return {w for w in words if len(w) >= 3}

    vendor_words = to_words(product_vendor)
    product_words = to_words(product_name)
    all_product_words = vendor_words | product_words

    cpe_vendor_words = to_words(cpe_vendor)
    cpe_product_words = to_words(cpe_product)
    all_cpe_words = cpe_vendor_words | cpe_product_words

    # Check for ANY overlap between product info and CPE info
    overlap = all_product_words & all_cpe_words
    if overlap:
        return True

    # Check for substring matches (e.g., "chrome" in "chromium", "fire" in "firefox")
    for pw in all_product_words:
        for cw in all_cpe_words:
            if len(pw) >= 4 and len(cw) >= 4:
                if pw in cw or cw in pw:
                    return True

    # No overlap at all — this mapping is almost certainly wrong
    # e.g., Logitech/Logi Options+ → git-scm/git
    return False


def apply_cpe_to_product(product):
    """
    Apply CPE mapping to a single product if it doesn't have CPE set.

    Uses multi-tier matching:
    1. Regex patterns (fast, from CPE_MAPPINGS)
    2. Curated dictionary mappings (comprehensive, from cpe_mappings.py)
    3. User-learned mappings (from database)

    Args:
        product: Product model instance

    Returns:
        bool: True if CPE was applied, False otherwise
    """
    # Skip if already has CPE
    if product.cpe_vendor and product.cpe_product:
        return False

    # Tier 1: Try regex patterns (fast)
    cpe_vendor, cpe_product = get_cpe_for_product(product.product_name, product.vendor)

    # Tier 2: Try curated dictionary + user mappings (comprehensive)
    if not cpe_vendor or not cpe_product:
        try:
            from app.cpe_mappings import get_cpe_for_software
            cpe_vendor, cpe_product, _ = get_cpe_for_software(
                product.vendor, product.product_name, use_nvd_fallback=False
            )
        except Exception:
            pass

    # Tier 3: Try local CPE dictionary (extracted from vulnerability data)
    if not cpe_vendor or not cpe_product:
        try:
            from app.cpe_dictionary import lookup_cpe_dictionary
            cpe_vendor, cpe_product, _ = lookup_cpe_dictionary(
                product.vendor, product.product_name
            )
        except Exception:
            pass

    if cpe_vendor and cpe_product:
        # Sanity check: prevent clearly wrong mappings
        if not validate_cpe_assignment(product.vendor, product.product_name,
                                       cpe_vendor, cpe_product):
            import logging
            logging.getLogger(__name__).warning(
                f"CPE sanity check BLOCKED: {product.vendor}/{product.product_name} "
                f"→ {cpe_vendor}:{cpe_product} (no word overlap)"
            )
            return False
        product.cpe_vendor = cpe_vendor
        product.cpe_product = cpe_product
        return True

    return False


def batch_apply_cpe_mappings(commit=True, use_nvd=True, max_nvd_lookups=200):
    """
    Apply CPE mappings to all products that don't have CPE set.

    Uses multi-tier matching:
    1. Regex patterns + curated dictionary (instant, local)
    2. NVD API search for unmatched products (slower, dynamic)
    3. Auto-saves NVD discoveries as user-learned mappings for future use

    Args:
        commit: Whether to commit the changes to database
        use_nvd: Whether to use NVD API for products not matched locally
        max_nvd_lookups: Max NVD API queries to make per batch (rate limit protection)

    Returns:
        tuple: (updated_count, total_without_cpe)
    """
    import logging
    import time
    from app.models import Product

    logger = logging.getLogger(__name__)

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

    # Phase 0: Tag noise products (Windows ADK, dev tools, etc.) so they
    # don't show as "unmapped" and don't waste NVD API calls
    from app.agent_api import _should_skip_software
    real_products = []
    skipped_count = 0
    for product in products_without_cpe:
        if _should_skip_software(product.vendor, product.product_name):
            product.cpe_vendor = '_skip'
            product.cpe_product = '_not_security_relevant'
            skipped_count += 1
            updated_count += 1
        else:
            real_products.append(product)

    if skipped_count:
        logger.info(f"CPE Phase 0: tagged {skipped_count} noise products as not-security-relevant")

    # Phase 1: Apply local matches (regex + curated dict + local dictionary)
    # Use no_autoflush to prevent mid-query flushes that can cause statement timeouts
    still_unmatched = []
    with db.session.no_autoflush:
        for product in real_products:
            if apply_cpe_to_product(product):
                updated_count += 1
            else:
                still_unmatched.append(product)

    logger.info(f"CPE Phase 1 (local): mapped {updated_count - skipped_count}/{len(real_products)}, {len(still_unmatched)} still unmatched")

    # Commit Phase 0+1 changes now to keep session clean for Phase 2.
    # Phase 2 does queries (user mappings, NVD API) that trigger autoflush.
    # If dirty product objects are pending, autoflush causes statement_timeout.
    if commit and updated_count > 0:
        db.session.commit()
        logger.info(f"CPE Phase 0+1 committed: {updated_count} products updated")

    # Log unmatched products for debugging
    if still_unmatched:
        samples = still_unmatched[:20]
        for p in samples:
            logger.info(f"  UNMATCHED: vendor='{p.vendor}' product='{p.product_name}'")

    # Phase 2: Try NVD API for remaining unmatched products (online, rate-limited)
    if use_nvd and still_unmatched:
        nvd_lookups = 0
        # Deduplicate by vendor+product_name to avoid redundant API calls
        seen_keys = set()
        unique_unmatched = []
        for product in still_unmatched:
            key = f"{product.vendor}|{product.product_name}".lower()
            if key not in seen_keys:
                seen_keys.add(key)
                unique_unmatched.append(product)

        try:
            from app.cpe_mappings import get_cpe_for_software, save_user_mapping
        except ImportError:
            logger.warning("cpe_mappings module not available for NVD fallback")
            unique_unmatched = []

        for product in unique_unmatched:
            if nvd_lookups >= max_nvd_lookups:
                logger.info(f"Reached max NVD lookups ({max_nvd_lookups}), stopping")
                break

            try:
                cpe_vendor, cpe_product, confidence = get_cpe_for_software(
                    product.vendor, product.product_name, use_nvd_fallback=True
                )
                nvd_lookups += 1

                if cpe_vendor and cpe_product and confidence >= 0.6:
                    # Sanity check: prevent clearly wrong mappings
                    if not validate_cpe_assignment(product.vendor, product.product_name,
                                                   cpe_vendor, cpe_product):
                        logger.warning(
                            f"CPE sanity check BLOCKED (NVD): {product.vendor}/{product.product_name} "
                            f"→ {cpe_vendor}:{cpe_product} (confidence={confidence:.0%}, no word overlap)"
                        )
                        continue

                    # Apply to this product
                    product.cpe_vendor = cpe_vendor
                    product.cpe_product = cpe_product
                    updated_count += 1

                    # Auto-save as user-learned mapping for future use
                    try:
                        save_user_mapping(
                            vendor=product.vendor,
                            product_name=product.product_name,
                            cpe_vendor=cpe_vendor,
                            cpe_product=cpe_product,
                            source='auto_nvd',
                            notes=f'Auto-discovered via NVD API (confidence: {confidence:.0%})'
                        )
                    except Exception as e:
                        logger.debug(f"Could not save auto-learned mapping: {e}")

                    # Apply same CPE to all products with same vendor+product_name
                    for other in still_unmatched:
                        if (other.id != product.id and
                            other.vendor == product.vendor and
                            other.product_name == product.product_name and
                            not other.cpe_vendor):
                            other.cpe_vendor = cpe_vendor
                            other.cpe_product = cpe_product
                            updated_count += 1

                # Rate limit: brief pause between NVD API calls
                if nvd_lookups % 5 == 0:
                    time.sleep(1)

            except Exception as e:
                logger.debug(f"NVD lookup failed for {product.vendor} {product.product_name}: {e}")

    logger.info(f"CPE Phase 2 (NVD API): total mapped {updated_count}/{total_without_cpe}")

    if commit and updated_count > 0:
        db.session.commit()
        logger.info(f"CPE batch apply committed: {updated_count} products updated")

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


def cleanup_bad_auto_mappings():
    """
    Remove auto-learned user_cpe_mappings that fail the validation check.

    Scans all mappings with source='auto_nvd' and removes those where the
    CPE vendor/product has no word overlap with the vendor/product pattern.
    This catches historically bad mappings like Logitech → git-scm:git.

    Returns:
        int: Number of mappings removed
    """
    import logging
    logger = logging.getLogger(__name__)
    from app.models import UserCpeMapping

    bad_mappings = []
    auto_mappings = UserCpeMapping.query.filter(
        UserCpeMapping.source == 'auto_nvd'
    ).all()

    for mapping in auto_mappings:
        if not validate_cpe_assignment(
            mapping.vendor_pattern,
            mapping.product_pattern,
            mapping.cpe_vendor,
            mapping.cpe_product
        ):
            bad_mappings.append(mapping)
            logger.info(
                f"Removing bad auto_nvd mapping: "
                f"{mapping.vendor_pattern}/{mapping.product_pattern} → "
                f"{mapping.cpe_vendor}:{mapping.cpe_product}"
            )

    removed = len(bad_mappings)
    for mapping in bad_mappings:
        db.session.delete(mapping)

    if removed > 0:
        db.session.commit()
        logger.info(f"Cleaned up {removed} bad auto_nvd CPE mappings")

    return removed
