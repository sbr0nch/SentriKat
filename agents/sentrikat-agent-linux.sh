#!/bin/bash
#
# SentriKat Linux Agent - Software Inventory Collector
#
# Silent daemon agent that collects software inventory from Linux endpoints
# and reports to a SentriKat server. Designed to run as a systemd service.
#
# Version: 1.0.0
# Requires: bash, curl, jq (optional for JSON parsing)
#
# Usage:
#   ./sentrikat-agent-linux.sh --server-url "https://sentrikat.example.com" --api-key "sk_agent_xxx"
#   ./sentrikat-agent-linux.sh --install --server-url "https://..." --api-key "..."
#   ./sentrikat-agent-linux.sh --uninstall
#

set -euo pipefail

AGENT_VERSION="1.3.0"
CONFIG_DIR="/etc/sentrikat"
CONFIG_FILE="${CONFIG_DIR}/agent.conf"
LOG_FILE="/var/log/sentrikat-agent.log"
PID_FILE="/var/run/sentrikat-agent.pid"
SYSTEMD_SERVICE="/etc/systemd/system/sentrikat-agent.service"
SYSTEMD_TIMER="/etc/systemd/system/sentrikat-agent.timer"
HEARTBEAT_SERVICE="/etc/systemd/system/sentrikat-heartbeat.service"
HEARTBEAT_TIMER="/etc/systemd/system/sentrikat-heartbeat.timer"

# Default settings
SERVER_URL=""
API_KEY=""
INTERVAL_HOURS=4
HEARTBEAT_MINUTES=5
AGENT_ID=""

# ============================================================================
# Logging Functions
# ============================================================================

# JSON string escaping function
json_escape() {
    local str="$1"
    # Escape backslashes first, then quotes, then control characters
    str="${str//\\/\\\\}"      # Backslash
    str="${str//\"/\\\"}"      # Double quote
    str="${str//$'\n'/\\n}"    # Newline
    str="${str//$'\r'/\\r}"    # Carriage return
    str="${str//$'\t'/\\t}"    # Tab
    # Remove other control characters
    str=$(echo "$str" | tr -d '\000-\011\013-\037')
    echo "$str"
}

log() {
    local level="${1:-INFO}"
    local message="${2:-}"
    local timestamp
    timestamp=$(date '+%Y-%m-%d %H:%M:%S')

    # Ensure log directory exists
    mkdir -p "$(dirname "$LOG_FILE")" 2>/dev/null || true

    # Rotate log if > 10MB
    if [[ -f "$LOG_FILE" ]] && [[ $(stat -f%z "$LOG_FILE" 2>/dev/null || stat -c%s "$LOG_FILE" 2>/dev/null) -gt 10485760 ]]; then
        mv "$LOG_FILE" "${LOG_FILE}.old" 2>/dev/null || true
    fi

    echo "[$timestamp] [$level] $message" >> "$LOG_FILE"

    if [[ "${VERBOSE:-false}" == "true" ]]; then
        case "$level" in
            ERROR) echo -e "\033[31m[$timestamp] [$level] $message\033[0m" ;;
            WARN)  echo -e "\033[33m[$timestamp] [$level] $message\033[0m" ;;
            *)     echo "[$timestamp] [$level] $message" ;;
        esac
    fi
}

log_info() { log "INFO" "$1"; }
log_warn() { log "WARN" "$1"; }
log_error() { log "ERROR" "$1"; }

# ============================================================================
# Configuration Management
# ============================================================================

load_config() {
    if [[ -f "$CONFIG_FILE" ]]; then
        # shellcheck source=/dev/null
        source "$CONFIG_FILE"
    fi

    # Command line args override config file
    [[ -n "${ARG_SERVER_URL:-}" ]] && SERVER_URL="$ARG_SERVER_URL"
    [[ -n "${ARG_API_KEY:-}" ]] && API_KEY="$ARG_API_KEY"

    # Generate agent ID if not set
    if [[ -z "$AGENT_ID" ]]; then
        # Try to get machine ID
        if [[ -f /etc/machine-id ]]; then
            AGENT_ID=$(cat /etc/machine-id)
        elif [[ -f /var/lib/dbus/machine-id ]]; then
            AGENT_ID=$(cat /var/lib/dbus/machine-id)
        else
            AGENT_ID=$(uuidgen 2>/dev/null || cat /proc/sys/kernel/random/uuid)
        fi
        save_config
    fi
}

save_config() {
    mkdir -p "$CONFIG_DIR" 2>/dev/null || true
    chmod 700 "$CONFIG_DIR"

    cat > "$CONFIG_FILE" << EOF
# SentriKat Agent Configuration
SERVER_URL="${SERVER_URL}"
API_KEY="${API_KEY}"
INTERVAL_HOURS=${INTERVAL_HOURS}
HEARTBEAT_MINUTES=${HEARTBEAT_MINUTES}
AGENT_ID="${AGENT_ID}"
EOF

    chmod 600 "$CONFIG_FILE"
}

# ============================================================================
# System Information Collection
# ============================================================================

get_system_info() {
    local hostname
    local fqdn
    local ip_address
    local os_name
    local os_version
    local kernel

    hostname=$(hostname -s 2>/dev/null || hostname)
    fqdn=$(hostname -f 2>/dev/null || hostname)

    # Get primary IP address
    ip_address=$(ip route get 1.1.1.1 2>/dev/null | awk '{print $7; exit}' || hostname -I 2>/dev/null | awk '{print $1}')

    # Detect OS
    if [[ -f /etc/os-release ]]; then
        # shellcheck source=/dev/null
        source /etc/os-release
        os_name="${NAME:-Linux}"
        os_version="${VERSION:-${VERSION_ID:-unknown}}"
    elif [[ -f /etc/redhat-release ]]; then
        os_name="Red Hat"
        os_version=$(cat /etc/redhat-release)
    else
        os_name="Linux"
        os_version=$(uname -r)
    fi

    kernel=$(uname -r)

    # Escape all values for JSON safety
    hostname=$(json_escape "$hostname")
    fqdn=$(json_escape "$fqdn")
    ip_address=$(json_escape "$ip_address")
    os_name=$(json_escape "$os_name")
    os_version=$(json_escape "$os_version")
    kernel=$(json_escape "$kernel")

    cat << EOF
{
    "hostname": "${hostname}",
    "fqdn": "${fqdn}",
    "ip_address": "${ip_address}",
    "os": {
        "name": "${os_name}",
        "version": "${os_version}",
        "kernel": "${kernel}"
    },
    "agent": {
        "id": "${AGENT_ID}",
        "version": "${AGENT_VERSION}"
    }
}
EOF
}

# ============================================================================
# Software Inventory Collection
# ============================================================================

get_installed_software() {
    log_info "Collecting software inventory..."

    local products=()
    local count=0
    local total_scanned=0

    # ---------------------------------------------------------------------------
    # Smart inventory filter: include only packages that matter for CVE matching
    # Strategy: explicit EXCLUDE of known noise first, then INCLUDE by category.
    # This keeps the inventory focused (typically 100-300 packages) instead of
    # sending every dpkg/rpm entry (often 1500-3000 on a full server).
    # ---------------------------------------------------------------------------
    is_security_relevant() {
        local pkg="$1"
        local pkg_lower="${pkg,,}"  # Convert to lowercase

        # ---- STAGE 1: Exclude known noise (fast reject) ----
        case "$pkg_lower" in
            # Documentation, manpages, locales, translations
            *-doc|*-docs|*-man|*-locale*|*-l10n*|*-i18n*|*-lang|*-lang-*) return 1 ;;
            manpages*|man-db*|info|texinfo*) return 1 ;;
            # Development headers & debug symbols (not runtime-vulnerable)
            *-dev|*-devel|*-dbg|*-dbgsym|*-debug|*-debuginfo) return 1 ;;
            *-headers) return 1 ;;
            # Static libraries (not used at runtime)
            *-static) return 1 ;;
            # Fonts, themes, icons, wallpapers
            fonts-*|*-fonts|*-icon*|*-theme*|*-wallpaper*|adwaita-*|hicolor-*) return 1 ;;
            # Python2/3 pure-data modules (not services, no CVE surface)
            python3-*|python-*)
                # EXCEPT: python3 runtime itself, crypto, http, and security libs
                case "$pkg_lower" in
                    python3|python3.*|python3-openssl*|python3-cryptography*|python3-jwt*|python3-django*|python3-flask*|python3-requests*|python3-urllib3*|python3-paramiko*|python3-twisted*|python3-tornado*|python3-aiohttp*) return 0 ;;
                    *) return 1 ;;
                esac
                ;;
            # Perl modules (rarely CVE-tracked individually)
            perl-*|libperl*) return 1 ;;
            # Ruby gems (rarely CVE-tracked via distro)
            ruby-*) return 1 ;;
            # Texlive and LaTeX (not security relevant)
            texlive*|latex*) return 1 ;;
            # X11/Wayland display libraries (huge count, low CVE)
            libx11-*|libxcb*|libxext*|libxfixes*|libxi-*|libxkb*|libxrandr*|libxrender*|libxshmfence*|libxtst*|libxcomposite*|libxcursor*|libxdamage*|libxinerama*) return 1 ;;
            xserver-*|xfonts-*|x11-*) return 1 ;;
            # GLib/GTK/GNOME/KDE desktop noise
            libglib2.0-*|libgtk*|libgdk*|libpango*|libcairo*|libatk*|libgdk-pixbuf*|libharfbuzz*|libfontconfig*|libfreetype*) return 1 ;;
            gnome-*|kde-*|plasma-*|gir1.2-*) return 1 ;;
            # Systemd sub-packages (noise - we only care about systemd itself)
            systemd-*|libsystemd*|libudev*) return 1 ;;
            # Low-level libc/compiler runtime (matched by kernel/glibc instead)
            libc6*|libc-*|libstdc++*|libgcc*|gcc-*-base|cpp-*) return 1 ;;
            # Misc low-CVE noise
            *-data|*-common|*-base)
                case "$pkg_lower" in
                    ca-certificates-*|openssh-*|openssl-*) return 0 ;;  # Keep security-related -base/-common
                    *) return 1 ;;
                esac
                ;;
        esac

        # ---- STAGE 2: Include by category (explicit allow) ----
        case "$pkg_lower" in
            # Web servers & reverse proxies
            apache2|httpd|nginx|nginx-*|haproxy|traefik|caddy|lighttpd|varnish*) return 0 ;;
            # Databases
            mysql-server*|mysql-client*|mariadb-server*|mariadb-client*|postgresql*|postgres*|mongodb*|redis-server|redis-tools|memcached|sqlite3|elasticsearch*|couchdb*|neo4j*) return 0 ;;
            # Programming language runtimes (not -dev, not lib wrappers)
            php|php[0-9]*|php[0-9]*-*) return 0 ;;
            python3|python3.[0-9]*|python2|python2.[0-9]*) return 0 ;;
            ruby|ruby[0-9]*) return 0 ;;
            nodejs|node|npm|yarn) return 0 ;;
            java*-runtime*|openjdk*-jre*|openjdk*-jdk*|default-jre*|default-jdk*) return 0 ;;
            golang*|go|dotnet*|mono-runtime*|erlang*|elixir*) return 0 ;;
            # Core crypto & TLS libraries
            openssl|libssl[0-9]*|libcrypto[0-9]*|gnutls*|libnss3|nss|nss-*) return 0 ;;
            ca-certificates) return 0 ;;
            # SSH & remote access
            openssh-server|openssh-client|openssh|libssh*|dropbear*) return 0 ;;
            # Container & orchestration
            docker-ce*|docker.io|containerd*|podman|buildah|skopeo|cri-o*) return 0 ;;
            kubernetes*|kubectl|kubelet|kubeadm|helm|k3s|minikube) return 0 ;;
            # Virtualization
            qemu*|libvirt*|virtualbox*|vagrant*) return 0 ;;
            # Core system services
            systemd|sudo|polkit|policykit*|cron|at) return 0 ;;
            dbus|avahi*|cups*|sane*) return 0 ;;
            # Networking services
            bind9|named|dnsmasq|unbound|nsd) return 0 ;;
            postfix|dovecot*|exim*|sendmail*|cyrus*) return 0 ;;
            samba*|nfs-kernel-server|nfs-common|vsftpd|proftpd*|openvpn*|wireguard*|strongswan*|ipsec*) return 0 ;;
            # Monitoring, logging, observability
            prometheus|grafana*|zabbix*|nagios*|icinga*|telegraf|collectd|datadog*) return 0 ;;
            rsyslog|syslog-ng|journald|fluentd|logstash|filebeat*) return 0 ;;
            # Security tools & firewalling
            fail2ban|iptables|nftables|ufw|firewalld) return 0 ;;
            apparmor|selinux*|aide|tripwire|clamav*|rkhunter|chkrootkit) return 0 ;;
            # Version control (servers can expose git/svn)
            git|git-core|subversion|mercurial) return 0 ;;
            # Message queues & middleware
            rabbitmq*|kafka*|activemq*|mosquitto*|nats-server) return 0 ;;
            # App servers & frameworks
            tomcat*|jetty*|wildfly*|jboss*|gunicorn|uwsgi|unicorn|puma) return 0 ;;
            # CI/CD tools
            jenkins*|gitlab-*|drone*) return 0 ;;
            # Known CVE-prone software
            log4j*|struts*|spring*|jackson*|fastjson*) return 0 ;;
            imagemagick*|ghostscript*|ffmpeg*|libav*|poppler*) return 0 ;;
            # Kernel & bootloader
            linux-image-[0-9]*|kernel|kernel-core|grub2*|grub-*) return 0 ;;
            # Core libraries with frequent CVEs
            glibc|libc-bin|zlib*|libxml2|libxslt*|expat|libexpat*|pcre*|icu*|libicu*) return 0 ;;
            libcurl[0-9]*|curl|wget) return 0 ;;
            libjpeg*|libpng*|libtiff*|libwebp*) return 0 ;;
            # Package managers (track their version for supply-chain)
            apt|dpkg|rpm|yum|dnf|pip|pip3|gem|composer|cargo|snap*|flatpak) return 0 ;;
            # Shells & common CLI tools with CVE history
            bash|zsh|dash|ksh|vim|vim-*|screen|tmux) return 0 ;;
            tar|gzip|bzip2|xz-utils|unzip|p7zip*|cpio|rsync) return 0 ;;
            # Proxies & load balancers
            squid*|dante*|tinyproxy|privoxy) return 0 ;;
            # DNS resolvers
            resolvconf|systemd-resolved) return 0 ;;
            *) return 1 ;;
        esac
    }

    # Debian/Ubuntu: dpkg
    if command -v dpkg &>/dev/null; then
        while IFS=$'\t' read -r name version; do
            [[ -z "$name" ]] && continue
            ((total_scanned++))

            # Filter to security-relevant packages only
            if ! is_security_relevant "$name"; then
                continue
            fi

            # Extract vendor from package name or use "Debian" as fallback
            local vendor="Debian"
            case "$name" in
                apache*|httpd*) vendor="Apache" ;;
                nginx*) vendor="Nginx" ;;
                mysql*|mariadb*) vendor="Oracle/MariaDB" ;;
                postgresql*|postgres*) vendor="PostgreSQL" ;;
                redis*) vendor="Redis" ;;
                docker*) vendor="Docker" ;;
                openssl*|openssh*) vendor="OpenSSL/OpenSSH" ;;
                curl*) vendor="Curl" ;;
                git|git-core) vendor="Git" ;;
                linux-*|kernel-*) vendor="Linux" ;;
                php*) vendor="PHP" ;;
                python*) vendor="Python" ;;
                nodejs*|node|npm) vendor="Node.js" ;;
                java*|openjdk*) vendor="Oracle/OpenJDK" ;;
                mongodb*) vendor="MongoDB" ;;
                elasticsearch*) vendor="Elastic" ;;
                prometheus*) vendor="Prometheus" ;;
                grafana*) vendor="Grafana" ;;
            esac

            # Escape JSON special characters
            name=$(json_escape "$name")
            version=$(json_escape "$version")
            # Send full distro version as distro_package_version for confidence scoring
            products+=("{\"vendor\": \"$vendor\", \"product\": \"$name\", \"version\": \"$version\", \"distro_package_version\": \"$version\"}")
            ((count++))
        done < <(dpkg-query -W -f='${Package}\t${Version}\n' 2>/dev/null)
    fi

    # RHEL/CentOS/Fedora: rpm
    if command -v rpm &>/dev/null && [[ ! -f /etc/debian_version ]]; then
        while IFS=$'\t' read -r name version vendor; do
            [[ -z "$name" ]] && continue
            ((total_scanned++))

            # Filter to security-relevant packages only
            if ! is_security_relevant "$name"; then
                continue
            fi

            [[ "$vendor" == "(none)" ]] && vendor="Community"

            # Escape JSON special characters
            name=$(json_escape "$name")
            version=$(json_escape "$version")
            vendor=$(json_escape "$vendor")
            # Send full distro version as distro_package_version for confidence scoring
            products+=("{\"vendor\": \"$vendor\", \"product\": \"$name\", \"version\": \"$version\", \"distro_package_version\": \"$version\"}")
            ((count++))
        done < <(rpm -qa --queryformat '%{NAME}\t%{VERSION}-%{RELEASE}\t%{VENDOR}\n' 2>/dev/null)
    fi

    # Alpine: apk
    if command -v apk &>/dev/null; then
        while IFS='-' read -r name version; do
            [[ -z "$name" ]] && continue
            ((total_scanned++))

            # Filter to security-relevant packages only
            if ! is_security_relevant "$name"; then
                continue
            fi

            name=$(json_escape "$name")
            version=$(json_escape "$version")
            products+=("{\"vendor\": \"Alpine\", \"product\": \"$name\", \"version\": \"$version\"}")
            ((count++))
        done < <(apk info -v 2>/dev/null | sed 's/-[0-9].*/-&/' | sed 's/--/-/')
    fi

    # Arch: pacman
    if command -v pacman &>/dev/null; then
        while IFS=' ' read -r name version; do
            [[ -z "$name" ]] && continue
            ((total_scanned++))

            # Filter to security-relevant packages only
            if ! is_security_relevant "$name"; then
                continue
            fi

            name=$(json_escape "$name")
            version=$(json_escape "$version")
            products+=("{\"vendor\": \"Arch\", \"product\": \"$name\", \"version\": \"$version\"}")
            ((count++))
        done < <(pacman -Q 2>/dev/null)
    fi

    # Snap packages (include all - typically user-installed apps)
    if command -v snap &>/dev/null; then
        while read -r name version; do
            [[ -z "$name" || "$name" == "Name" ]] && continue
            name=$(json_escape "$name")
            version=$(json_escape "$version")
            products+=("{\"vendor\": \"Snap\", \"product\": \"$name\", \"version\": \"$version\"}")
            ((count++))
        done < <(snap list 2>/dev/null | awk 'NR>1 {print $1, $2}')
    fi

    # Flatpak packages (include all - typically user-installed apps)
    if command -v flatpak &>/dev/null; then
        while IFS=$'\t' read -r name version origin; do
            [[ -z "$name" || "$name" == "Name" ]] && continue
            name=$(json_escape "$name")
            version=$(json_escape "$version")
            origin=$(json_escape "${origin:-Flatpak}")
            products+=("{\"vendor\": \"$origin\", \"product\": \"$name\", \"version\": \"$version\"}")
            ((count++))
        done < <(flatpak list --columns=name,version,origin 2>/dev/null)
    fi

    log_info "Scanned $total_scanned installed packages, selected $count security-relevant packages"

    # Build JSON array
    local json_array="["
    local first=true
    for product in "${products[@]}"; do
        if [[ "$first" == "true" ]]; then
            first=false
        else
            json_array+=","
        fi
        json_array+="$product"
    done
    json_array+="]"

    echo "$json_array"
}

# ============================================================================
# Container Image Scanning (Trivy Integration)
# ============================================================================

TRIVY_BIN="/usr/local/bin/trivy"
TRIVY_CACHE_DIR="/var/cache/sentrikat/trivy"
TRIVY_DB_DIR="${TRIVY_CACHE_DIR}/db"
CONTAINER_SCAN_ENABLED="${CONTAINER_SCAN_ENABLED:-auto}"  # auto, true, false
# Offline mode: set TRIVY_OFFLINE=true in agent.conf to skip download attempts.
# Pre-deploy trivy binary to /usr/local/bin/trivy and optionally
# pre-download the DB with: trivy image --download-db-only --cache-dir /var/cache/sentrikat/trivy
TRIVY_OFFLINE="${TRIVY_OFFLINE:-false}"

check_docker_available() {
    if command -v docker &>/dev/null && docker info &>/dev/null 2>&1; then
        return 0
    elif command -v podman &>/dev/null; then
        return 0
    fi
    return 1
}

install_trivy() {
    # Check common paths: pre-deployed binary, system package, or our install location
    if [[ -x "$TRIVY_BIN" ]]; then
        log_info "Trivy found at $TRIVY_BIN"
        return 0
    fi

    # Check if trivy is already in PATH (e.g. installed via package manager)
    if command -v trivy &>/dev/null; then
        TRIVY_BIN=$(command -v trivy)
        log_info "Trivy found in PATH at $TRIVY_BIN"
        return 0
    fi

    # Offline mode: don't attempt download
    if [[ "$TRIVY_OFFLINE" == "true" ]]; then
        log_warn "Trivy not found and TRIVY_OFFLINE=true. Pre-deploy trivy to $TRIVY_BIN"
        log_warn "Download from: https://github.com/aquasecurity/trivy/releases"
        return 1
    fi

    log_info "Installing Trivy for container image scanning..."
    mkdir -p "$TRIVY_CACHE_DIR" 2>/dev/null || true

    # Detect architecture
    local arch
    case "$(uname -m)" in
        x86_64)  arch="Linux-64bit" ;;
        aarch64) arch="Linux-ARM64" ;;
        armv7l)  arch="Linux-ARM" ;;
        *)
            log_warn "Unsupported architecture $(uname -m) for Trivy"
            return 1
            ;;
    esac

    # Download Trivy release binary directly (no piping curl to sh)
    local tmpdir
    tmpdir=$(mktemp -d)
    local trivy_version="0.58.2"
    local download_url="https://github.com/aquasecurity/trivy/releases/download/v${trivy_version}/trivy_${trivy_version}_${arch}.tar.gz"

    log_info "Downloading Trivy v${trivy_version} from GitHub..."
    if curl -sfL --max-time 120 "$download_url" -o "$tmpdir/trivy.tar.gz" 2>/dev/null; then
        tar xzf "$tmpdir/trivy.tar.gz" -C "$tmpdir" trivy 2>/dev/null
        if [[ -f "$tmpdir/trivy" ]]; then
            mv "$tmpdir/trivy" "$TRIVY_BIN"
            chmod 755 "$TRIVY_BIN"
            log_info "Trivy v${trivy_version} installed successfully"
            rm -rf "$tmpdir"
            return 0
        fi
    fi

    log_warn "Failed to download Trivy. Container scanning will be skipped."
    log_warn "For offline deployment, pre-install trivy to $TRIVY_BIN"
    rm -rf "$tmpdir"
    return 1
}

get_container_images() {
    local images=()

    # Docker images
    if command -v docker &>/dev/null && docker info &>/dev/null 2>&1; then
        while IFS= read -r line; do
            [[ -z "$line" || "$line" == "<none>:<none>" ]] && continue
            images+=("$line")
        done < <(docker images --format "{{.Repository}}:{{.Tag}}|{{.ID}}|{{.Size}}" 2>/dev/null | grep -v '<none>')
    fi

    # Podman images (if docker not available)
    if [[ ${#images[@]} -eq 0 ]] && command -v podman &>/dev/null; then
        while IFS= read -r line; do
            [[ -z "$line" || "$line" == "<none>:<none>" ]] && continue
            images+=("$line")
        done < <(podman images --format "{{.Repository}}:{{.Tag}}|{{.ID}}|{{.Size}}" 2>/dev/null | grep -v '<none>')
    fi

    printf '%s\n' "${images[@]}"
}

scan_container_images() {
    # Check if container scanning should run
    if [[ "$CONTAINER_SCAN_ENABLED" == "false" ]]; then
        log_info "Container scanning disabled by configuration"
        return 0
    fi

    # Auto-detect Docker/Podman
    if ! check_docker_available; then
        if [[ "$CONTAINER_SCAN_ENABLED" == "auto" ]]; then
            log_info "No container runtime detected, skipping container scan"
            return 0
        else
            log_warn "Container scanning enabled but no container runtime found"
            return 1
        fi
    fi

    log_info "Starting container image scan..."

    # Install Trivy if needed
    if ! install_trivy; then
        log_warn "Trivy not available, skipping container scan"
        return 1
    fi

    # Get list of images
    local image_list
    image_list=$(get_container_images)

    if [[ -z "$image_list" ]]; then
        log_info "No container images found"
        return 0
    fi

    local image_count=0
    local scan_results="["
    local first=true

    while IFS='|' read -r image_ref image_id image_size; do
        [[ -z "$image_ref" ]] && continue

        log_info "Scanning container image: $image_ref"

        # Run Trivy scan with JSON output
        local trivy_output
        trivy_output=$("$TRIVY_BIN" image \
            --format json \
            --severity HIGH,CRITICAL \
            --cache-dir "$TRIVY_CACHE_DIR" \
            --quiet \
            --timeout 5m \
            "$image_ref" 2>/dev/null)

        if [[ $? -ne 0 || -z "$trivy_output" ]]; then
            log_warn "Trivy scan failed for $image_ref"
            continue
        fi

        # Build our scan result payload
        local image_name="${image_ref%%:*}"
        local image_tag="${image_ref#*:}"
        [[ "$image_tag" == "$image_ref" ]] && image_tag="latest"

        # Escape values
        image_name=$(json_escape "$image_name")
        image_tag=$(json_escape "$image_tag")
        image_id=$(json_escape "${image_id:0:12}")

        # Write trivy output to temp file for processing
        local tmpfile
        tmpfile=$(mktemp)
        echo "$trivy_output" > "$tmpfile"

        if [[ "$first" == "true" ]]; then
            first=false
        else
            scan_results+=","
        fi

        # Wrap the raw Trivy JSON with our metadata
        scan_results+="{\"image_name\": \"$image_name\", \"image_tag\": \"$image_tag\", \"image_id\": \"$image_id\", \"trivy_output\": $(cat "$tmpfile")}"

        rm -f "$tmpfile"
        ((image_count++))

        # Limit to 50 images per scan to avoid overwhelming the server
        if [[ $image_count -ge 50 ]]; then
            log_warn "Reached 50 image limit, skipping remaining images"
            break
        fi
    done <<< "$image_list"

    scan_results+="]"

    if [[ $image_count -eq 0 ]]; then
        log_info "No images scanned successfully"
        return 0
    fi

    log_info "Scanned $image_count container images"

    # Send results to SentriKat server
    send_container_scan_results "$scan_results"
}

send_container_scan_results() {
    local scan_results="$1"
    local endpoint="${SERVER_URL}/api/agent/container-scan"

    log_info "Sending container scan results to $endpoint..."

    local payload
    payload="{\"agent_id\": \"${AGENT_ID}\", \"hostname\": \"$(hostname)\", \"scanner\": \"trivy\", \"scanner_version\": \"$("$TRIVY_BIN" --version 2>/dev/null | head -1 | awk '{print $2}' || echo 'unknown')\", \"images\": ${scan_results}}"

    # Write payload to temp file
    local tmpfile
    tmpfile=$(mktemp)
    echo "$payload" > "$tmpfile"

    local max_retries=3
    local retry_delay=5

    for ((i=1; i<=max_retries; i++)); do
        local response
        local http_code

        response=$(curl -s -w "\n%{http_code}" -X POST "$endpoint" \
            -H "X-Agent-Key: $API_KEY" \
            -H "Content-Type: application/json" \
            -H "User-Agent: SentriKat-Agent/$AGENT_VERSION (Linux)" \
            --data-binary "@${tmpfile}" \
            --max-time 120 \
            2>&1) || true

        http_code=$(echo "$response" | tail -n1)
        local body
        body=$(echo "$response" | sed '$d')

        if [[ "$http_code" == "200" || "$http_code" == "202" ]]; then
            log_info "Container scan results sent successfully (HTTP $http_code)"
            rm -f "$tmpfile"
            return 0
        else
            log_warn "Container scan upload attempt $i failed: HTTP $http_code - $body"
            if [[ $i -lt $max_retries ]]; then
                sleep $retry_delay
                retry_delay=$((retry_delay * 2))
            fi
        fi
    done

    rm -f "$tmpfile"
    log_error "Failed to send container scan results after $max_retries attempts"
    return 1
}

# ============================================================================
# API Communication
# ============================================================================

send_inventory() {
    local system_info="$1"
    local products="$2"

    local endpoint="${SERVER_URL}/api/agent/inventory"

    log_info "Sending inventory to $endpoint..."

    # Build payload by writing to temp file incrementally.
    # This avoids "Argument list too long" errors when $products is very large
    # (e.g. 1000+ packages) since we never pass the full string as an argument.
    local tmpfile
    tmpfile=$(mktemp)

    # Write system_info without closing brace, then append products, then close
    printf '%s' "$system_info" | sed 's/}$//' > "$tmpfile"
    printf ', "products": ' >> "$tmpfile"
    printf '%s' "$products" >> "$tmpfile"
    printf '}' >> "$tmpfile"

    # Retry logic
    local max_retries=3
    local retry_delay=5

    for ((i=1; i<=max_retries; i++)); do
        local response
        local http_code

        # Use --data-binary @file to avoid argument list limits
        response=$(curl -s -w "\n%{http_code}" -X POST "$endpoint" \
            -H "X-Agent-Key: $API_KEY" \
            -H "Content-Type: application/json" \
            -H "User-Agent: SentriKat-Agent/$AGENT_VERSION (Linux)" \
            --data-binary "@${tmpfile}" \
            --max-time 120 \
            2>&1) || true

        http_code=$(echo "$response" | tail -n1)
        local body
        body=$(echo "$response" | sed '$d')

        if [[ "$http_code" == "200" || "$http_code" == "202" ]]; then
            log_info "Inventory sent successfully (HTTP $http_code)"
            log_info "Response: $body"
            rm -f "$tmpfile"
            return 0
        else
            log_warn "Attempt $i failed: HTTP $http_code - $body"

            if [[ $i -lt $max_retries ]]; then
                log_info "Retrying in $retry_delay seconds..."
                sleep $retry_delay
                retry_delay=$((retry_delay * 2))
            fi
        fi
    done

    rm -f "$tmpfile"
    log_error "Failed to send inventory after $max_retries attempts"
    return 1
}

send_heartbeat() {
    local endpoint="${SERVER_URL}/api/agent/heartbeat"

    curl -s -X POST "$endpoint" \
        -H "X-Agent-Key: $API_KEY" \
        -H "Content-Type: application/json" \
        -d "{\"hostname\": \"$(hostname)\", \"agent_id\": \"$AGENT_ID\"}" \
        --max-time 30 >/dev/null 2>&1
}

check_commands() {
    # Poll the server for pending commands (heartbeat with command check)
    local endpoint="${SERVER_URL}/api/agent/commands?agent_id=${AGENT_ID}&hostname=$(hostname)&version=${AGENT_VERSION}&platform=linux"

    log_info "Checking for commands from server..."

    local response
    response=$(curl -s -X GET "$endpoint" \
        -H "X-Agent-Key: $API_KEY" \
        -H "Content-Type: application/json" \
        --max-time 30 2>&1) || {
        log_warn "Failed to check commands: connection error"
        return 1
    }

    # Parse commands (basic parsing without jq dependency)
    if echo "$response" | grep -q '"command": "scan_now"'; then
        log_info "Received scan_now command - triggering immediate inventory scan"
        return 0  # Return 0 to trigger scan
    fi

    if echo "$response" | grep -q '"command": "update_config"'; then
        log_info "Received config update command"
        # Extract new interval if present
        local new_interval
        new_interval=$(echo "$response" | grep -o '"scan_interval_minutes": [0-9]*' | grep -o '[0-9]*' | head -1)
        if [[ -n "$new_interval" && "$new_interval" -ge 15 ]]; then
            local new_hours=$((new_interval / 60))
            if [[ $new_hours -gt 0 && $new_hours != "$INTERVAL_HOURS" ]]; then
                log_info "Updating scan interval from ${INTERVAL_HOURS}h to ${new_hours}h"
                INTERVAL_HOURS=$new_hours
                save_config
                # Update systemd timer if installed
                if [[ -f "$SYSTEMD_TIMER" ]]; then
                    update_systemd_timer
                fi
            fi
        fi
    fi

    if echo "$response" | grep -q '"command": "update_available"'; then
        local latest_version
        latest_version=$(echo "$response" | grep -o '"latest_version": "[^"]*"' | cut -d'"' -f4)
        log_warn "Agent update available: ${AGENT_VERSION} -> ${latest_version}"
        log_info "Download from: ${SERVER_URL}/api/agent/download/linux"
    fi

    return 1  # No scan needed
}

update_systemd_timer() {
    # Update the systemd timer with new interval
    cat > "$SYSTEMD_TIMER" << EOF
[Unit]
Description=Run SentriKat Agent periodically

[Timer]
OnBootSec=5min
OnUnitActiveSec=${INTERVAL_HOURS}h
RandomizedDelaySec=10min

[Install]
WantedBy=timers.target
EOF
    systemctl daemon-reload 2>/dev/null || true
    log_info "Updated systemd timer to ${INTERVAL_HOURS}h interval"
}

# ============================================================================
# Installation Functions
# ============================================================================

install_agent() {
    log_info "Installing SentriKat agent..."

    # Check for root
    if [[ $EUID -ne 0 ]]; then
        echo "ERROR: Installation requires root privileges"
        exit 1
    fi

    # Save configuration
    save_config

    # Copy script to system location
    local script_dest="/usr/local/bin/sentrikat-agent"
    cp "$0" "$script_dest"
    chmod 755 "$script_dest"

    # Create systemd service for full inventory scan
    cat > "$SYSTEMD_SERVICE" << EOF
[Unit]
Description=SentriKat Software Inventory Agent
After=network-online.target
Wants=network-online.target

[Service]
Type=oneshot
ExecStart=/usr/local/bin/sentrikat-agent --run-once
User=root
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
EOF

    # Create systemd timer for full inventory scan
    cat > "$SYSTEMD_TIMER" << EOF
[Unit]
Description=Run SentriKat Agent periodically

[Timer]
OnBootSec=5min
OnUnitActiveSec=${INTERVAL_HOURS}h
RandomizedDelaySec=10min

[Install]
WantedBy=timers.target
EOF

    # Create systemd service for heartbeat/command polling
    cat > "$HEARTBEAT_SERVICE" << EOF
[Unit]
Description=SentriKat Agent Heartbeat
After=network-online.target
Wants=network-online.target

[Service]
Type=oneshot
ExecStart=/usr/local/bin/sentrikat-agent --heartbeat
User=root
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
EOF

    # Create systemd timer for heartbeat (every 5 minutes)
    cat > "$HEARTBEAT_TIMER" << EOF
[Unit]
Description=SentriKat Agent Heartbeat Timer

[Timer]
OnBootSec=2min
OnUnitActiveSec=${HEARTBEAT_MINUTES}min
RandomizedDelaySec=30s

[Install]
WantedBy=timers.target
EOF

    # Enable and start timers
    systemctl daemon-reload
    systemctl enable --now sentrikat-agent.timer
    systemctl enable --now sentrikat-heartbeat.timer

    log_info "Agent installed successfully"
    echo "SentriKat Agent installed:"
    echo "  - Full scan: every ${INTERVAL_HOURS} hours"
    echo "  - Heartbeat: every ${HEARTBEAT_MINUTES} minutes (checks for commands)"
    echo "Run 'systemctl status sentrikat-agent.timer' to check scan status"
    echo "Run 'systemctl status sentrikat-heartbeat.timer' to check heartbeat status"
}

uninstall_agent() {
    log_info "Uninstalling SentriKat agent..."

    if [[ $EUID -ne 0 ]]; then
        echo "ERROR: Uninstallation requires root privileges"
        exit 1
    fi

    # Stop and disable scan timer
    systemctl stop sentrikat-agent.timer 2>/dev/null || true
    systemctl disable sentrikat-agent.timer 2>/dev/null || true

    # Stop and disable heartbeat timer
    systemctl stop sentrikat-heartbeat.timer 2>/dev/null || true
    systemctl disable sentrikat-heartbeat.timer 2>/dev/null || true

    # Remove systemd files
    rm -f "$SYSTEMD_SERVICE" "$SYSTEMD_TIMER"
    rm -f "$HEARTBEAT_SERVICE" "$HEARTBEAT_TIMER"
    systemctl daemon-reload

    # Remove script
    rm -f /usr/local/bin/sentrikat-agent

    # Optionally remove config (commented out by default)
    # rm -rf "$CONFIG_DIR"

    log_info "Agent uninstalled"
    echo "SentriKat Agent uninstalled"
}

heartbeat_mode() {
    # Heartbeat mode: check for commands and trigger scan if requested
    log_info "Running heartbeat check..."

    load_config

    if [[ -z "$SERVER_URL" || -z "$API_KEY" ]]; then
        log_error "SERVER_URL and API_KEY are required"
        exit 1
    fi

    # Check for commands from server
    if check_commands; then
        # scan_now command received - run full inventory
        log_info "Executing requested scan..."
        main
    else
        log_info "Heartbeat complete - no scan requested"
    fi
}

# ============================================================================
# Main Execution
# ============================================================================

show_help() {
    cat << EOF
SentriKat Linux Agent v${AGENT_VERSION}

Usage: $0 [OPTIONS]

Options:
  --server-url URL     SentriKat server URL (required)
  --api-key KEY        Agent API key (required)
  --interval HOURS     Scan interval in hours (default: 4)
  --install            Install as systemd service (includes heartbeat timer)
  --uninstall          Uninstall agent
  --run-once           Run inventory collection once and exit
  --heartbeat          Run heartbeat check (polls for commands)
  --verbose            Enable verbose output
  --help               Show this help message

Examples:
  # Run once for testing
  $0 --server-url "https://sentrikat.example.com" --api-key "sk_agent_xxx" --verbose

  # Install as service (includes heartbeat every 5 min)
  sudo $0 --install --server-url "https://sentrikat.example.com" --api-key "sk_agent_xxx"

  # Check for commands (used by heartbeat timer)
  $0 --heartbeat

  # Uninstall
  sudo $0 --uninstall
EOF
}

main() {
    log_info "SentriKat Agent v${AGENT_VERSION} starting..."

    # Load configuration
    load_config

    # Validate configuration
    if [[ -z "$SERVER_URL" || -z "$API_KEY" ]]; then
        log_error "SERVER_URL and API_KEY are required"
        echo "ERROR: --server-url and --api-key are required"
        echo "Run '$0 --help' for usage information"
        exit 1
    fi

    # Collect and send inventory
    local system_info
    system_info=$(get_system_info)
    log_info "System: $(echo "$system_info" | grep -o '"hostname"[^,]*' | head -1)"

    local products
    products=$(get_installed_software)

    local product_count
    product_count=$(echo "$products" | grep -o '"product"' | wc -l)

    if [[ $product_count -eq 0 ]]; then
        log_warn "No software found to report"
        exit 0
    fi

    if send_inventory "$system_info" "$products"; then
        log_info "Inventory report completed successfully"
    else
        log_error "Inventory report failed"
        exit 1
    fi

    # Run container image scan (if Docker/Podman detected)
    scan_container_images || log_warn "Container scanning encountered issues (non-fatal)"
}

# Parse arguments
INSTALL=false
UNINSTALL=false
RUN_ONCE=false
HEARTBEAT=false
VERBOSE=false

while [[ $# -gt 0 ]]; do
    case $1 in
        --server-url)
            ARG_SERVER_URL="$2"
            shift 2
            ;;
        --api-key)
            ARG_API_KEY="$2"
            shift 2
            ;;
        --interval)
            INTERVAL_HOURS="$2"
            shift 2
            ;;
        --install)
            INSTALL=true
            shift
            ;;
        --uninstall)
            UNINSTALL=true
            shift
            ;;
        --run-once)
            RUN_ONCE=true
            shift
            ;;
        --heartbeat)
            HEARTBEAT=true
            shift
            ;;
        --verbose|-v)
            VERBOSE=true
            shift
            ;;
        --help|-h)
            show_help
            exit 0
            ;;
        *)
            echo "Unknown option: $1"
            show_help
            exit 1
            ;;
    esac
done

# Handle actions
if [[ "$INSTALL" == "true" ]]; then
    load_config
    install_agent
    exit 0
fi

if [[ "$UNINSTALL" == "true" ]]; then
    uninstall_agent
    exit 0
fi

if [[ "$HEARTBEAT" == "true" ]]; then
    heartbeat_mode
    exit 0
fi

# Default: run main
main
