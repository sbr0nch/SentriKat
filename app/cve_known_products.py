"""
CVE Known Products - Smart Package Filtering via CVE History

Instead of relying solely on hardcoded skip lists (which can accidentally
skip packages that DO have CVEs like openssl, xz-utils, bzip2, tcpdump),
this module maintains a set of package names that have historically been
associated with vulnerabilities.

Strategy:
    1. Structural filters (suffixes like -doc, -dbg, -locale) are always safe
       because they indicate non-runtime derivative packages.
    2. Before any pattern/exact-match skip, check if the package has CVE history.
       If yes → NEVER skip it, regardless of other rules.
    3. Pattern/exact-match rules only apply to packages with NO CVE history.

Data sources (layered):
    - Static set: ~500 packages known to have had CVEs (immediate, offline)
    - Database set: vendor/product names from synced CISA KEV + CPE data
    - Both are merged into an in-memory cache for O(1) lookups.

This approach is fundamentally safer than hardcoded skip lists because:
    - A package with CVE history can NEVER be accidentally skipped
    - The known-vulnerable set grows automatically as new CVEs are synced
    - Only packages that have NEVER had a CVE in their entire history
      can be filtered by noise-reduction patterns
"""

import re
import threading
import logging
from datetime import datetime, timedelta

logger = logging.getLogger(__name__)

# Thread-safe in-memory cache
_known_cve_products = set()
_cache_lock = threading.Lock()
_last_refresh = None
CACHE_TTL_HOURS = 12  # Refresh every 12 hours

# =============================================================================
# STATIC KNOWN VULNERABLE PRODUCTS
# =============================================================================
# Packages that have had CVEs in NVD history. This set provides day-1
# coverage even before any CISA/NVD data is synced. Entries are lowercase.
#
# Sources: NVD CVE database, CISA KEV catalog, Debian Security Tracker,
#          Red Hat CVE database, Ubuntu USN database.
#
# IMPORTANT: This is a SAFETY NET, not a complete list. The database
# augmentation (from synced CISA KEV + CPE data) adds more dynamically.
# =============================================================================

STATIC_KNOWN_CVE_PRODUCTS = {
    # -------------------------------------------------------------------------
    # Cryptography & TLS Libraries
    # -------------------------------------------------------------------------
    'openssl', 'libssl', 'libssl1.1', 'libssl3', 'libssl-dev',
    'gnutls', 'libgnutls', 'libgnutls28', 'libgnutls30',
    'nss', 'libnss', 'libnss3', 'nss-util',
    'mbedtls', 'libmbedtls', 'boringssl', 'wolfssl',
    'libgcrypt', 'libgcrypt20', 'libsodium', 'libsodium23',
    'nettle', 'libnettle', 'libhogweed',
    'gnupg', 'gnupg2', 'gpg', 'gpgme', 'libgpgme',

    # -------------------------------------------------------------------------
    # Compression Libraries (xz-utils, bzip2, zlib, etc.)
    # -------------------------------------------------------------------------
    'xz', 'xz-utils', 'liblzma', 'liblzma5',
    'bzip2', 'libbz2', 'libbz2-1.0',
    'zlib', 'zlib1g', 'libz',
    'gzip', 'pigz',
    'lz4', 'liblz4', 'liblz4-1',
    'zstd', 'libzstd', 'libzstd1',
    'snappy', 'libsnappy',
    'brotli', 'libbrotli',
    'libarchive', 'libarchive13',
    'p7zip', '7zip', '7-zip',
    'unzip', 'zip', 'tar',
    'cpio', 'rpm2cpio',

    # -------------------------------------------------------------------------
    # Networking & Transfer
    # -------------------------------------------------------------------------
    'curl', 'libcurl', 'libcurl4', 'libcurl3',
    'wget', 'wget2',
    'openssh', 'openssh-client', 'openssh-server', 'libssh', 'libssh2',
    'tcpdump', 'libpcap', 'libpcap0.8',
    'nmap', 'wireshark', 'tshark',
    'rsync', 'socat', 'netcat', 'ncat', 'nc',
    'iproute2', 'net-tools', 'traceroute',
    'ftp', 'lftp', 'telnet',
    'iptables', 'nftables', 'ebtables',
    'iw', 'wireless-tools', 'wpa_supplicant', 'hostapd',
    'openvpn', 'wireguard', 'strongswan', 'libreswan',
    'haproxy', 'squid', 'varnish', 'traefik',
    'dnsmasq', 'unbound', 'pdns', 'knot',

    # -------------------------------------------------------------------------
    # Core System Libraries & Utilities
    # -------------------------------------------------------------------------
    'glibc', 'libc6', 'libc-bin', 'libc6-dev', 'musl', 'musl-utils',
    'bash', 'dash', 'zsh', 'ksh', 'tcsh', 'fish',
    'sudo', 'doas',
    'systemd', 'libsystemd', 'systemd-libs',
    'coreutils', 'util-linux', 'libblkid', 'libmount', 'libuuid',
    'shadow', 'shadow-utils', 'login', 'passwd',
    'pam', 'libpam', 'libpam-modules', 'libpam-runtime',
    'dbus', 'libdbus', 'dbus-daemon',
    'polkit', 'policykit', 'libpolkit',
    'udev', 'libudev', 'eudev',
    'procps', 'procps-ng', 'psmisc',
    'acl', 'libacl', 'attr', 'libattr',
    'e2fsprogs', 'libext2fs', 'xfsprogs', 'btrfs-progs',
    'lvm2', 'device-mapper', 'mdadm', 'cryptsetup',
    'grub', 'grub2', 'grub-common', 'shim', 'shim-signed',

    # -------------------------------------------------------------------------
    # Package Managers (they process untrusted input)
    # -------------------------------------------------------------------------
    'apt', 'apt-get', 'libapt', 'libapt-pkg',
    'dpkg', 'libdpkg-perl',
    'rpm', 'librpm', 'yum', 'dnf',
    'apk', 'apk-tools',
    'pip', 'setuptools', 'wheel',
    'npm', 'yarn', 'pnpm',
    'gem', 'bundler',
    'composer',
    'cargo',
    'nuget',

    # -------------------------------------------------------------------------
    # Kernel
    # -------------------------------------------------------------------------
    'linux', 'linux-image', 'linux-kernel', 'kernel',
    'linux-headers', 'linux-libc-dev',
    'kmod', 'module-init-tools',

    # -------------------------------------------------------------------------
    # Web Servers
    # -------------------------------------------------------------------------
    'nginx', 'libnginx',
    'apache', 'apache2', 'httpd', 'libapache2',
    'lighttpd', 'caddy',
    'tomcat', 'jetty',
    'gunicorn', 'uwsgi',
    'iis', 'internet information services',

    # -------------------------------------------------------------------------
    # Programming Languages & Runtimes
    # -------------------------------------------------------------------------
    'python', 'python2', 'python2.7', 'python3', 'python3.8',
    'python3.9', 'python3.10', 'python3.11', 'python3.12',
    'libpython', 'cpython',
    'perl', 'perl5', 'libperl',
    'ruby', 'ruby2', 'ruby3', 'libruby',
    'php', 'php7', 'php8', 'libphp', 'php-fpm', 'php-cgi',
    'nodejs', 'node', 'node.js',
    'openjdk', 'java', 'jdk', 'jre', 'openjdk-11', 'openjdk-17',
    'golang', 'go',
    'rust', 'rustc',
    'dotnet', '.net', '.net framework', '.net core',
    'mono', 'mono-runtime',
    'lua', 'luajit',
    'erlang', 'elixir',
    'r-base', 'r-cran',
    'swift',

    # -------------------------------------------------------------------------
    # Databases
    # -------------------------------------------------------------------------
    'mysql', 'mysql-server', 'mysql-client', 'libmysql', 'libmysqlclient',
    'mariadb', 'mariadb-server', 'mariadb-client', 'libmariadb',
    'postgresql', 'postgres', 'libpq', 'libpq5',
    'redis', 'redis-server', 'redis-tools',
    'sqlite', 'sqlite3', 'libsqlite3',
    'mongodb', 'mongod', 'mongos',
    'elasticsearch', 'opensearch',
    'cassandra', 'couchdb', 'memcached',

    # -------------------------------------------------------------------------
    # DNS / DHCP / Mail
    # -------------------------------------------------------------------------
    'bind', 'bind9', 'named', 'libbind', 'libdns',
    'dnsmasq',
    'dhcp', 'dhcpcd', 'dhclient', 'isc-dhcp',
    'postfix', 'sendmail', 'exim', 'exim4', 'dovecot',
    'cyrus-imapd', 'spamassassin', 'clamav',

    # -------------------------------------------------------------------------
    # File Sharing / Printing
    # -------------------------------------------------------------------------
    'cups', 'libcups', 'cups-filters',
    'samba', 'libsmbclient', 'smbd', 'nmbd', 'winbind',
    'nfs-utils', 'nfs-kernel-server', 'rpcbind', 'libnfs',

    # -------------------------------------------------------------------------
    # Image / Media / Document Processing
    # -------------------------------------------------------------------------
    'imagemagick', 'libmagickcore', 'libmagickwand',
    'graphicsmagick',
    'ghostscript', 'libgs',
    'poppler', 'libpoppler', 'poppler-utils',
    'ffmpeg', 'libavcodec', 'libavformat', 'libavutil', 'libswscale',
    'gstreamer', 'libgstreamer',
    'libpng', 'libpng16', 'libpng12',
    'libjpeg', 'libjpeg-turbo', 'libjpeg62', 'libjpeg8',
    'libtiff', 'libtiff5', 'libtiff6',
    'libwebp', 'libwebp7',
    'giflib', 'libgif',
    'openjpeg', 'libopenjp2',
    'librsvg', 'libcairo', 'cairo',
    'exiv2', 'libexif',
    'dcraw', 'rawtherapee',
    'mupdf', 'xpdf',

    # -------------------------------------------------------------------------
    # XML / JSON / Data Parsing
    # -------------------------------------------------------------------------
    'libxml2', 'libxslt', 'libxslt1',
    'expat', 'libexpat', 'libexpat1',
    'xerces', 'xerces-c',
    'libyaml', 'pyyaml',
    'jansson', 'json-c', 'libjson',
    'protobuf', 'libprotobuf',
    'grpc', 'libgrpc',

    # -------------------------------------------------------------------------
    # Version Control
    # -------------------------------------------------------------------------
    'git', 'git-core', 'libgit2',
    'subversion', 'svn', 'libsvn',
    'mercurial', 'hg',
    'cvs',

    # -------------------------------------------------------------------------
    # Editors (process untrusted files)
    # -------------------------------------------------------------------------
    'vim', 'vim-common', 'vim-runtime', 'neovim',
    'emacs', 'xemacs',
    'nano',
    'less', 'most',

    # -------------------------------------------------------------------------
    # Containers / Virtualization
    # -------------------------------------------------------------------------
    'docker', 'docker-ce', 'docker-engine', 'docker.io',
    'containerd', 'containerd.io',
    'runc',
    'podman', 'buildah', 'skopeo', 'cri-o',
    'qemu', 'qemu-kvm', 'qemu-system', 'libvirt', 'libvirtd',
    'virtualbox', 'vboxguest',
    'lxc', 'lxd',
    'kubernetes', 'kubectl', 'kubelet',

    # -------------------------------------------------------------------------
    # Monitoring / Logging
    # -------------------------------------------------------------------------
    'nagios', 'zabbix', 'prometheus', 'grafana',
    'snmp', 'net-snmp', 'snmpd',
    'rsyslog', 'syslog-ng',
    'logrotate',
    'collectd', 'telegraf',
    'kibana', 'logstash',

    # -------------------------------------------------------------------------
    # Common Libraries with CVE History
    # -------------------------------------------------------------------------
    'libevent', 'libuv',
    'boost', 'libboost',
    'pcre', 'pcre2', 'libpcre', 'libpcre2',
    'icu', 'libicu', 'libicu-dev',
    'freetype', 'libfreetype', 'libfreetype6',
    'fontconfig', 'libfontconfig',
    'harfbuzz', 'libharfbuzz',
    'pango', 'libpango',
    'gdk-pixbuf', 'libgdk-pixbuf',
    'gtk', 'gtk2', 'gtk3', 'gtk4', 'libgtk',
    'qt', 'qt5', 'qt6', 'qtbase', 'libqt5', 'libqt6',
    'mesa', 'libgl', 'libglx', 'libegl',
    'xorg', 'xorg-server', 'xwayland', 'x11', 'libx11', 'libxpm',
    'wayland', 'libwayland',
    'sdl', 'sdl2', 'libsdl',
    'avahi', 'libavahi',
    'cups-browsed',
    'ntpd', 'ntp', 'chrony', 'ntpsec',
    'krb5', 'libkrb5', 'kerberos', 'heimdal',
    'ldap', 'openldap', 'libldap', 'slapd',
    'cyrus-sasl', 'libsasl2',
    'libtasn1', 'p11-kit',

    # -------------------------------------------------------------------------
    # Web Browsers & Components
    # -------------------------------------------------------------------------
    'firefox', 'firefox-esr',
    'chromium', 'chromium-browser',
    'thunderbird',
    'webkit', 'webkit2gtk', 'libwebkit2gtk',
    'electron',
    'google chrome', 'chrome',
    'microsoft edge', 'edge',
    'opera', 'brave', 'vivaldi',
    'safari',

    # -------------------------------------------------------------------------
    # Desktop Applications with CVE History
    # -------------------------------------------------------------------------
    'libreoffice', 'openoffice',
    'vlc',
    'gimp',
    'inkscape',
    'blender',
    'audacity',
    'filezilla',
    'putty', 'winscp',
    'wireshark',
    '7-zip', '7zip', 'p7zip',
    'winrar', 'winzip',
    'keepass', 'bitwarden', '1password',
    'zoom', 'slack', 'teams', 'discord', 'signal', 'telegram',
    'adobe reader', 'acrobat', 'acrobat reader',
    'adobe flash', 'flash player',
    'notepad++',

    # -------------------------------------------------------------------------
    # Windows-Specific Products with CVE History
    # -------------------------------------------------------------------------
    'windows', 'windows 10', 'windows 11', 'windows server',
    'microsoft office', 'microsoft word', 'microsoft excel',
    'microsoft outlook', 'microsoft powerpoint',
    'microsoft exchange', 'exchange server',
    'microsoft sharepoint', 'sharepoint',
    'internet explorer',
    'internet information services',
    'powershell',
    '.net framework', '.net core', 'asp.net',
    'sql server', 'microsoft sql',
    'visual studio', 'visual studio code',
    'onedrive', 'skype',
    'windows defender',
    'microsoft print spooler',
    'win32k',

    # -------------------------------------------------------------------------
    # macOS-Specific Products with CVE History
    # -------------------------------------------------------------------------
    'macos', 'mac os x', 'osx',
    'safari',
    'webkit',
    'xcode',
    'cups',

    # -------------------------------------------------------------------------
    # Security / AV Products (they themselves have CVEs)
    # -------------------------------------------------------------------------
    'norton', 'mcafee', 'avast', 'avg',
    'kaspersky', 'bitdefender', 'eset',
    'sophos', 'trendmicro', 'trend micro',
    'crowdstrike', 'falcon',
    'sentinelone',
    'malwarebytes',
    'clamav', 'clamd',

    # -------------------------------------------------------------------------
    # CI/CD / DevOps Tools
    # -------------------------------------------------------------------------
    'jenkins', 'gitlab', 'gitlab-runner',
    'ansible', 'puppet', 'chef', 'salt', 'saltstack',
    'terraform', 'vagrant', 'packer',
    'helm', 'istio', 'envoy',

    # -------------------------------------------------------------------------
    # Java Ecosystem (many high-profile CVEs)
    # -------------------------------------------------------------------------
    'spring', 'spring-boot', 'spring-framework',
    'log4j', 'log4j2', 'apache-log4j',
    'struts', 'struts2', 'apache-struts',
    'jackson', 'jackson-databind',
    'tomcat', 'wildfly', 'jboss',
    'maven', 'gradle',

    # -------------------------------------------------------------------------
    # Python Ecosystem
    # -------------------------------------------------------------------------
    'django', 'flask', 'fastapi',
    'twisted', 'tornado',
    'pillow', 'pil',
    'requests', 'urllib3', 'httpx',
    'paramiko', 'fabric',
    'cryptography', 'pyopenssl',
    'lxml', 'beautifulsoup',
    'jinja2', 'mako',
    'sqlalchemy', 'psycopg2',
    'celery', 'kombu',
    'numpy', 'scipy', 'pandas',

    # -------------------------------------------------------------------------
    # Node.js Ecosystem
    # -------------------------------------------------------------------------
    'express', 'koa', 'fastify',
    'lodash', 'underscore',
    'minimist', 'yargs',
    'axios', 'node-fetch',
    'jsonwebtoken', 'passport',

    # -------------------------------------------------------------------------
    # Container Base Image Packages (Alpine, Debian, RHEL)
    # -------------------------------------------------------------------------
    'busybox', 'toybox',
    'alpine-baselayout', 'alpine-keys',
    'apk-tools',
    'ca-certificates', 'openssl-config',
    'tzdata',
}


def _build_from_database():
    """
    Build known-CVE-products set from the local vulnerability database.

    Extracts vendor and product names from:
    - CISA KEV entries (Vulnerability.vendor_project / .product)
    - Cached CPE data (Vulnerability.cpe_data JSON entries)

    Returns a set of lowercase package names.
    """
    products = set()
    try:
        from app.models import Vulnerability
        from app import db

        # Get all unique vendor/product pairs from CISA KEV
        rows = db.session.query(
            Vulnerability.vendor_project,
            Vulnerability.product
        ).distinct().all()

        for vendor, product in rows:
            if product:
                p = product.lower().strip()
                products.add(p)
                # Add normalized variants (NVD uses underscores, Linux uses hyphens)
                products.add(p.replace(' ', '-'))
                products.add(p.replace(' ', '_'))
                products.add(p.replace('_', '-'))
            if vendor:
                v = vendor.lower().strip()
                products.add(v)
                products.add(v.replace(' ', '-'))
                products.add(v.replace(' ', '_'))

        # Also extract product names from CPE data
        vulns_with_cpe = db.session.query(
            Vulnerability.cpe_data
        ).filter(
            Vulnerability.cpe_data.isnot(None),
            Vulnerability.cpe_data != '[]'
        ).all()

        import json
        for (cpe_data_str,) in vulns_with_cpe:
            try:
                entries = json.loads(cpe_data_str) if isinstance(cpe_data_str, str) else cpe_data_str
                if not isinstance(entries, list):
                    continue
                for entry in entries:
                    if entry.get('product'):
                        p = entry['product'].lower().strip()
                        products.add(p)
                        products.add(p.replace('_', '-'))
                    if entry.get('vendor'):
                        v = entry['vendor'].lower().strip()
                        products.add(v)
                        products.add(v.replace('_', '-'))
            except (json.JSONDecodeError, TypeError, AttributeError):
                continue

    except Exception as e:
        logger.debug(f"Could not build CVE products from database: {e}")

    return products


def refresh_known_cve_products():
    """
    Refresh the in-memory cache of known CVE products.

    Merges the static set with database-derived products.
    Thread-safe via lock.

    Returns the total number of known CVE products.
    """
    global _known_cve_products, _last_refresh

    db_products = _build_from_database()

    with _cache_lock:
        _known_cve_products = STATIC_KNOWN_CVE_PRODUCTS | db_products
        _last_refresh = datetime.utcnow()

    count = len(_known_cve_products)
    logger.info(f"CVE known products cache refreshed: {count} entries "
                f"({len(STATIC_KNOWN_CVE_PRODUCTS)} static + {len(db_products)} from DB)")
    return count


def _ensure_cache():
    """Ensure cache is populated and not stale. Auto-refreshes if needed."""
    global _last_refresh

    needs_refresh = (
        not _last_refresh
        or not _known_cve_products
        or (datetime.utcnow() - _last_refresh) > timedelta(hours=CACHE_TTL_HOURS)
    )

    if needs_refresh:
        try:
            refresh_known_cve_products()
        except Exception:
            # If DB refresh fails, at least use the static set
            if not _known_cve_products:
                with _cache_lock:
                    _known_cve_products.update(STATIC_KNOWN_CVE_PRODUCTS)
                    _last_refresh = datetime.utcnow()


def has_cve_history(package_name):
    """
    Check if a package name has ever been associated with a CVE.

    Uses the in-memory cache for O(1) lookups. Auto-refreshes the cache
    if it's stale (older than CACHE_TTL_HOURS).

    Checks the name as-is, plus common normalizations:
    - Lowercase/stripped
    - With hyphens replaced by underscores and vice versa
    - With trailing version numbers stripped (e.g., "python3.11" → "python3" → "python")
    - With 'lib' prefix stripped for library packages

    Args:
        package_name: The package name to check (e.g., "openssl", "xz-utils")

    Returns:
        True if the package has CVE history, False otherwise.
    """
    if not package_name:
        return False

    _ensure_cache()

    name = package_name.lower().strip()

    with _cache_lock:
        products = set(_known_cve_products)

    # Direct match
    if name in products:
        return True

    # Try hyphen/underscore normalization
    if name.replace('-', '_') in products:
        return True
    if name.replace('_', '-') in products:
        return True

    # Strip trailing version numbers: "python3.11" → "python3" → "python"
    base = re.sub(r'[\d.]+$', '', name).rstrip('-').rstrip('_')
    if base and base != name and base in products:
        return True

    # Try further stripping: "python3" → strip trailing digit
    base2 = re.sub(r'\d+$', '', base).rstrip('-').rstrip('_')
    if base2 and base2 != base and base2 in products:
        return True

    # For "lib"-prefixed packages, check the base: "libssl3" → "ssl" → also "libssl"
    if name.startswith('lib'):
        lib_base = name[3:]  # Remove "lib" prefix
        lib_base = re.sub(r'[\d.]+$', '', lib_base).rstrip('-').rstrip('_')
        if lib_base and lib_base in products:
            return True
        # Also check "lib" + base (e.g., "libssl")
        if f"lib{lib_base}" in products:
            return True

    return False


def get_known_cve_product_count():
    """Get the current count of known CVE products in the cache."""
    _ensure_cache()
    with _cache_lock:
        return len(_known_cve_products)
