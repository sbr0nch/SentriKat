#!/bin/bash
#
# SentriKat Linux Agent - Software Inventory Collector
#
# Silent daemon agent that collects software inventory from Linux endpoints
# and reports to a SentriKat server. Designed to run as a systemd service.
#
# Version: 1.4.0
# Requires: bash, curl, jq (optional for JSON parsing)
#
# Usage:
#   ./sentrikat-agent-linux.sh --server-url "https://sentrikat.example.com" --api-key "sk_agent_xxx"
#   ./sentrikat-agent-linux.sh --install --server-url "https://..." --api-key "..."
#   ./sentrikat-agent-linux.sh --uninstall
#

set -euo pipefail

AGENT_VERSION="1.4.0"
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
SCAN_EXTENSIONS="${SCAN_EXTENSIONS:-false}"        # VSCode/IDE extension scanning
SCAN_DEPENDENCIES="${SCAN_DEPENDENCIES:-false}"    # Code library dependency scanning

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
SCAN_EXTENSIONS=${SCAN_EXTENSIONS}
SCAN_DEPENDENCIES=${SCAN_DEPENDENCIES}
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

    # Get primary IP address (the interface used to route to the internet)
    ip_address=$(ip route get 1.1.1.1 2>/dev/null | awk '/src/ {for(i=1;i<=NF;i++) if($i=="src") print $(i+1); exit}')
    # Fallback: first non-loopback IP from hostname
    if [[ -z "$ip_address" ]]; then
        ip_address=$(hostname -I 2>/dev/null | awk '{print $1}')
    fi

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

    # Debian/Ubuntu: dpkg
    if command -v dpkg &>/dev/null; then
        while IFS=$'\t' read -r name version; do
            [[ -z "$name" ]] && continue

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

    log_info "Collected $count installed OS packages (server-side filtering)"

    # ========================================================================
    # VSCode / IDE Extension Scanning (if enabled via SCAN_EXTENSIONS=true)
    # ========================================================================
    if [[ "${SCAN_EXTENSIONS:-false}" == "true" ]]; then
        local ext_count=0
        log_info "Scanning VSCode/IDE extensions..."

        # Scan all user home directories for VSCode extensions
        for user_home in /home/* /root; do
            [[ ! -d "$user_home" ]] && continue

            # VSCode extensions
            local vscode_ext_dir="$user_home/.vscode/extensions"
            if [[ -d "$vscode_ext_dir" ]]; then
                for ext_dir in "$vscode_ext_dir"/*/; do
                    [[ ! -d "$ext_dir" ]] && continue
                    local pkg_json="$ext_dir/package.json"
                    [[ ! -f "$pkg_json" ]] && continue

                    # Parse package.json without jq (grep-based)
                    local ext_name ext_version ext_publisher ext_display
                    ext_name=$(grep -o '"name"[[:space:]]*:[[:space:]]*"[^"]*"' "$pkg_json" | head -1 | cut -d'"' -f4)
                    ext_version=$(grep -o '"version"[[:space:]]*:[[:space:]]*"[^"]*"' "$pkg_json" | head -1 | cut -d'"' -f4)
                    ext_publisher=$(grep -o '"publisher"[[:space:]]*:[[:space:]]*"[^"]*"' "$pkg_json" | head -1 | cut -d'"' -f4)
                    ext_display=$(grep -o '"displayName"[[:space:]]*:[[:space:]]*"[^"]*"' "$pkg_json" | head -1 | cut -d'"' -f4)

                    [[ -z "$ext_name" ]] && continue
                    local display="${ext_display:-$ext_name}"
                    local pub="${ext_publisher:-Unknown}"

                    display=$(json_escape "$display")
                    ext_version=$(json_escape "${ext_version:-unknown}")
                    pub=$(json_escape "$pub")
                    local epath
                    epath=$(json_escape "$ext_dir")

                    products+=("{\"vendor\": \"$pub\", \"product\": \"$display\", \"version\": \"$ext_version\", \"path\": \"$epath\", \"source_type\": \"vscode_extension\", \"ecosystem\": \"vscode\"}")
                    ((ext_count++)) || true
                done
            fi

            # VSCode Insiders
            local vscode_insiders_dir="$user_home/.vscode-insiders/extensions"
            if [[ -d "$vscode_insiders_dir" ]]; then
                for ext_dir in "$vscode_insiders_dir"/*/; do
                    [[ ! -d "$ext_dir" ]] && continue
                    local pkg_json="$ext_dir/package.json"
                    [[ ! -f "$pkg_json" ]] && continue

                    local ext_name ext_version ext_publisher ext_display
                    ext_name=$(grep -o '"name"[[:space:]]*:[[:space:]]*"[^"]*"' "$pkg_json" | head -1 | cut -d'"' -f4)
                    ext_version=$(grep -o '"version"[[:space:]]*:[[:space:]]*"[^"]*"' "$pkg_json" | head -1 | cut -d'"' -f4)
                    ext_publisher=$(grep -o '"publisher"[[:space:]]*:[[:space:]]*"[^"]*"' "$pkg_json" | head -1 | cut -d'"' -f4)
                    ext_display=$(grep -o '"displayName"[[:space:]]*:[[:space:]]*"[^"]*"' "$pkg_json" | head -1 | cut -d'"' -f4)

                    [[ -z "$ext_name" ]] && continue
                    local display="${ext_display:-$ext_name}"
                    local pub="${ext_publisher:-Unknown}"

                    display=$(json_escape "$display")
                    ext_version=$(json_escape "${ext_version:-unknown}")
                    pub=$(json_escape "$pub")

                    products+=("{\"vendor\": \"$pub\", \"product\": \"$display\", \"version\": \"$ext_version\", \"source_type\": \"vscode_extension\", \"ecosystem\": \"vscode\"}")
                    ((ext_count++)) || true
                done
            fi
        done
        log_info "Collected $ext_count VSCode/IDE extensions"
        count=$((count + ext_count))
    fi

    # ========================================================================
    # Code Dependency Scanning (if enabled via SCAN_DEPENDENCIES=true)
    # ========================================================================
    if [[ "${SCAN_DEPENDENCIES:-false}" == "true" ]]; then
        local dep_count=0
        log_info "Scanning code dependencies..."

        # --- Python: pip freeze (global + virtualenvs) ---
        if command -v pip3 &>/dev/null || command -v pip &>/dev/null; then
            local pip_cmd="pip3"
            command -v pip3 &>/dev/null || pip_cmd="pip"
            while IFS='==' read -r pkg_name pkg_version; do
                [[ -z "$pkg_name" || "$pkg_name" == "pip" || "$pkg_name" == "setuptools" || "$pkg_name" == "wheel" ]] && continue
                pkg_name=$(json_escape "$pkg_name")
                pkg_version=$(json_escape "$pkg_version")
                products+=("{\"vendor\": \"PyPI\", \"product\": \"$pkg_name\", \"version\": \"$pkg_version\", \"source_type\": \"code_library\", \"ecosystem\": \"pypi\"}")
                ((dep_count++)) || true
            done < <($pip_cmd freeze 2>/dev/null | tr '==' '\t' | awk -F'\t' '{print $1"=="$2}' | sed 's/==$/==/;s/==$//') || true
        fi

        # --- Python: scan requirements.txt / Pipfile.lock in common dirs ---
        for search_dir in /home /opt /srv /var/www; do
            [[ ! -d "$search_dir" ]] && continue
            while IFS= read -r reqfile; do
                local proj_dir
                proj_dir=$(dirname "$reqfile")
                while IFS= read -r line; do
                    # Skip comments, empty lines, options
                    [[ -z "$line" || "$line" == \#* || "$line" == -* ]] && continue
                    # Parse name==version or name>=version
                    local pkg_name pkg_version
                    if [[ "$line" == *"=="* ]]; then
                        pkg_name="${line%%==*}"
                        pkg_version="${line#*==}"
                    elif [[ "$line" == *">="* ]]; then
                        pkg_name="${line%%>=*}"
                        pkg_version="${line#*>=}"
                    else
                        pkg_name="$line"
                        pkg_version="unknown"
                    fi
                    # Strip extras like package[extra]
                    pkg_name="${pkg_name%%\[*}"
                    pkg_name=$(echo "$pkg_name" | tr -d '[:space:]')
                    [[ -z "$pkg_name" ]] && continue

                    pkg_name=$(json_escape "$pkg_name")
                    pkg_version=$(json_escape "$pkg_version")
                    local pp
                    pp=$(json_escape "$reqfile")
                    products+=("{\"vendor\": \"PyPI\", \"product\": \"$pkg_name\", \"version\": \"$pkg_version\", \"source_type\": \"code_library\", \"ecosystem\": \"pypi\", \"project_path\": \"$pp\", \"is_direct\": true}")
                    ((dep_count++)) || true
                done < "$reqfile"
            done < <(find "$search_dir" -maxdepth 4 -name "requirements.txt" -readable 2>/dev/null | head -50)
        done

        # --- Node.js: global npm packages ---
        if command -v npm &>/dev/null; then
            while IFS=':' read -r pkg_name pkg_version; do
                [[ -z "$pkg_name" || "$pkg_name" == "npm" ]] && continue
                pkg_name=$(json_escape "$pkg_name")
                pkg_version=$(json_escape "$pkg_version")
                products+=("{\"vendor\": \"npm\", \"product\": \"$pkg_name\", \"version\": \"$pkg_version\", \"source_type\": \"code_library\", \"ecosystem\": \"npm\"}")
                ((dep_count++)) || true
            done < <(npm ls -g --depth=0 --parseable --long 2>/dev/null | tail -n +2 | awk -F'node_modules/' '{print $2}' | awk -F'@' '{if(NF>2){n=""; for(i=1;i<NF;i++){if(i>1)n=n"@"; n=n$i}; print n":"$NF}else{print $1":"$2}}') || true
        fi

        # --- Node.js: scan package-lock.json for direct deps ---
        for search_dir in /home /opt /srv /var/www; do
            [[ ! -d "$search_dir" ]] && continue
            while IFS= read -r lockfile; do
                local proj_dir
                proj_dir=$(dirname "$lockfile")
                local pkg_json="$proj_dir/package.json"
                [[ ! -f "$pkg_json" ]] && continue

                # Extract dependencies from package.json (direct deps only)
                # Parse "dependencies": { "name": "^version", ... }
                local in_deps=false
                local brace_count=0
                while IFS= read -r line; do
                    if echo "$line" | grep -q '"dependencies"'; then
                        in_deps=true
                        brace_count=0
                        continue
                    fi
                    if [[ "$in_deps" == "true" ]]; then
                        if echo "$line" | grep -q '{'; then
                            ((brace_count++)) || true
                            continue
                        fi
                        if echo "$line" | grep -q '}'; then
                            in_deps=false
                            continue
                        fi
                        local dep_name dep_ver
                        dep_name=$(echo "$line" | grep -o '"[^"]*"' | head -1 | tr -d '"')
                        dep_ver=$(echo "$line" | grep -o '"[^"]*"' | tail -1 | tr -d '"' | sed 's/[\^~>=<]//g')
                        [[ -z "$dep_name" ]] && continue

                        dep_name=$(json_escape "$dep_name")
                        dep_ver=$(json_escape "$dep_ver")
                        local pp
                        pp=$(json_escape "$lockfile")
                        products+=("{\"vendor\": \"npm\", \"product\": \"$dep_name\", \"version\": \"$dep_ver\", \"source_type\": \"code_library\", \"ecosystem\": \"npm\", \"project_path\": \"$pp\", \"is_direct\": true}")
                        ((dep_count++)) || true
                    fi
                done < "$pkg_json"
            done < <(find "$search_dir" -maxdepth 4 -name "package-lock.json" -readable 2>/dev/null | head -50)
        done

        # --- Ruby: global gems ---
        if command -v gem &>/dev/null; then
            while read -r gem_name gem_version; do
                [[ -z "$gem_name" ]] && continue
                # gem list outputs "name (version1, version2)" format
                gem_version=$(echo "$gem_version" | tr -d '(),' | awk '{print $1}')
                gem_name=$(json_escape "$gem_name")
                gem_version=$(json_escape "$gem_version")
                products+=("{\"vendor\": \"RubyGems\", \"product\": \"$gem_name\", \"version\": \"$gem_version\", \"source_type\": \"code_library\", \"ecosystem\": \"gem\"}")
                ((dep_count++)) || true
            done < <(gem list --local 2>/dev/null | grep -v '^\*\*\*') || true
        fi

        # --- Rust: cargo global packages ---
        if command -v cargo &>/dev/null; then
            while IFS=' ' read -r crate_name crate_version _rest; do
                [[ -z "$crate_name" || "$crate_name" == "warning:" ]] && continue
                crate_name=$(json_escape "$crate_name")
                crate_version=$(json_escape "${crate_version:-unknown}")
                products+=("{\"vendor\": \"crates.io\", \"product\": \"$crate_name\", \"version\": \"$crate_version\", \"source_type\": \"code_library\", \"ecosystem\": \"cargo\"}")
                ((dep_count++)) || true
            done < <(cargo install --list 2>/dev/null | grep -E '^[a-zA-Z]') || true
        fi

        # --- Go: global binaries ---
        if command -v go &>/dev/null; then
            local gopath="${GOPATH:-$HOME/go}"
            if [[ -d "$gopath/bin" ]]; then
                for gobin in "$gopath/bin"/*; do
                    [[ ! -x "$gobin" ]] && continue
                    local bin_name
                    bin_name=$(basename "$gobin")
                    # Try to get version from binary
                    local go_ver
                    go_ver=$("$gobin" --version 2>/dev/null | head -1 | grep -oE '[0-9]+\.[0-9]+\.[0-9]+' | head -1) || go_ver="unknown"
                    bin_name=$(json_escape "$bin_name")
                    go_ver=$(json_escape "$go_ver")
                    products+=("{\"vendor\": \"Go\", \"product\": \"$bin_name\", \"version\": \"$go_ver\", \"source_type\": \"code_library\", \"ecosystem\": \"go\"}")
                    ((dep_count++)) || true
                done
            fi
        fi

        # --- Composer (PHP): global packages ---
        if command -v composer &>/dev/null; then
            while IFS= read -r line; do
                local comp_name comp_ver
                comp_name=$(echo "$line" | awk '{print $1}')
                comp_ver=$(echo "$line" | awk '{print $2}')
                [[ -z "$comp_name" ]] && continue
                comp_name=$(json_escape "$comp_name")
                comp_ver=$(json_escape "${comp_ver:-unknown}")
                products+=("{\"vendor\": \"Packagist\", \"product\": \"$comp_name\", \"version\": \"$comp_ver\", \"source_type\": \"code_library\", \"ecosystem\": \"composer\"}")
                ((dep_count++)) || true
            done < <(composer global show 2>/dev/null | awk '{print $1, $2}') || true
        fi

        log_info "Collected $dep_count code dependencies"
        count=$((count + dep_count))
    fi

    log_info "Total collected: $count items"

    # Write JSON array directly to a temp file to avoid "Argument list too long"
    # errors. With 1000+ packages the JSON string can exceed bash/kernel ARG_MAX.
    local outfile
    outfile=$(mktemp /tmp/sentrikat-products-XXXXXX.json)

    printf '[' > "$outfile"
    local first=true
    for product in "${products[@]}"; do
        if [[ "$first" == "true" ]]; then
            first=false
        else
            printf ',' >> "$outfile"
        fi
        printf '%s' "$product" >> "$outfile"
    done
    printf ']' >> "$outfile"

    echo "$outfile"
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

    # Write scan results directly to temp file (avoids ARG_MAX)
    local results_file
    results_file=$(mktemp /tmp/sentrikat-container-XXXXXX.json)
    printf '[' > "$results_file"

    local image_count=0
    local first=true

    while IFS='|' read -r image_ref image_id image_size; do
        [[ -z "$image_ref" ]] && continue

        log_info "Scanning container image: $image_ref"

        # Run Trivy scan with JSON output directly to temp file
        local trivy_tmpfile
        trivy_tmpfile=$(mktemp)
        "$TRIVY_BIN" image \
            --format json \
            --severity HIGH,CRITICAL \
            --cache-dir "$TRIVY_CACHE_DIR" \
            --quiet \
            --timeout 5m \
            "$image_ref" > "$trivy_tmpfile" 2>/dev/null

        if [[ $? -ne 0 || ! -s "$trivy_tmpfile" ]]; then
            log_warn "Trivy scan failed for $image_ref"
            rm -f "$trivy_tmpfile"
            continue
        fi

        local image_name="${image_ref%%:*}"
        local image_tag="${image_ref#*:}"
        [[ "$image_tag" == "$image_ref" ]] && image_tag="latest"

        image_name=$(json_escape "$image_name")
        image_tag=$(json_escape "$image_tag")
        image_id=$(json_escape "${image_id:0:12}")

        if [[ "$first" == "true" ]]; then
            first=false
        else
            printf ',' >> "$results_file"
        fi

        # Write metadata + trivy output directly to file (no bash variable)
        printf '{"image_name": "%s", "image_tag": "%s", "image_id": "%s", "trivy_output": ' \
            "$image_name" "$image_tag" "$image_id" >> "$results_file"
        cat "$trivy_tmpfile" >> "$results_file"
        printf '}' >> "$results_file"

        rm -f "$trivy_tmpfile"
        ((image_count++))

        if [[ $image_count -ge 50 ]]; then
            log_warn "Reached 50 image limit, skipping remaining images"
            break
        fi
    done <<< "$image_list"

    printf ']' >> "$results_file"

    if [[ $image_count -eq 0 ]]; then
        log_info "No images scanned successfully"
        rm -f "$results_file"
        return 0
    fi

    log_info "Scanned $image_count container images"

    # Send results to SentriKat server
    send_container_scan_results "$results_file"
}

send_container_scan_results() {
    local results_file="$1"  # Path to temp file with JSON array of scan results
    local endpoint="${SERVER_URL}/api/agent/container-scan"

    log_info "Sending container scan results to $endpoint..."

    local trivy_version
    trivy_version=$("$TRIVY_BIN" --version 2>/dev/null | head -1 | awk '{print $2}' || echo 'unknown')
    local my_hostname
    my_hostname=$(hostname)

    # Assemble payload to temp file (no large bash variables)
    local tmpfile
    tmpfile=$(mktemp)
    printf '{"agent_id": "%s", "hostname": "%s", "scanner": "trivy", "scanner_version": "%s", "images": ' \
        "$AGENT_ID" "$my_hostname" "$trivy_version" > "$tmpfile"
    cat "$results_file" >> "$tmpfile"
    printf '}' >> "$tmpfile"
    rm -f "$results_file"

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
    local products_file="$2"   # Path to temp file containing JSON array

    local endpoint="${SERVER_URL}/api/agent/inventory"

    log_info "Sending inventory to $endpoint..."

    # Build payload by assembling temp files - never pass large strings as arguments.
    # $products_file is a path to a JSON array file written by get_installed_software.
    local tmpfile
    tmpfile=$(mktemp)

    # Write: { system_info_fields..., "products": <contents of products_file> }
    printf '%s' "$system_info" | sed 's/}$//' > "$tmpfile"
    printf ', "products": ' >> "$tmpfile"
    cat "$products_file" >> "$tmpfile"
    printf '}' >> "$tmpfile"

    # Clean up the products temp file
    rm -f "$products_file"

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
        -d "{\"hostname\": \"$(hostname)\", \"agent_id\": \"$AGENT_ID\", \"agent_version\": \"$AGENT_VERSION\"}" \
        --max-time 30 >/dev/null 2>&1
}

auto_update_agent() {
    # Auto-update the agent script from the server
    # Flow: download -> verify -> backup -> replace -> restart service
    local target_version="$1"
    local download_url="${SERVER_URL}/api/agent/download/linux"
    local script_path="/usr/local/bin/sentrikat-agent"
    local backup_path="${script_path}.backup.${AGENT_VERSION}"
    local tmp_script

    log_info "Auto-updating agent: ${AGENT_VERSION} -> ${target_version}"

    # Download new script to temp file
    tmp_script=$(mktemp)
    local http_code
    http_code=$(curl -s -w "%{http_code}" -o "$tmp_script" \
        -H "X-Agent-Key: $API_KEY" \
        --max-time 60 "$download_url" 2>/dev/null)

    if [[ "$http_code" != "200" ]]; then
        log_error "Failed to download update (HTTP $http_code)"
        rm -f "$tmp_script"
        return 1
    fi

    # Verify the downloaded script is valid bash
    if ! head -1 "$tmp_script" | grep -q '^#!/bin/bash'; then
        log_error "Downloaded file is not a valid bash script"
        rm -f "$tmp_script"
        return 1
    fi

    # Verify it contains the expected version
    if ! grep -q "AGENT_VERSION=" "$tmp_script"; then
        log_error "Downloaded script missing AGENT_VERSION marker"
        rm -f "$tmp_script"
        return 1
    fi

    # Backup current script
    if [[ -f "$script_path" ]]; then
        cp "$script_path" "$backup_path" 2>/dev/null || true
        log_info "Backed up current agent to $backup_path"
    fi

    # Replace the script
    chmod +x "$tmp_script"
    if mv "$tmp_script" "$script_path" 2>/dev/null; then
        log_info "Agent updated successfully to ${target_version}"

        # Restart the systemd service if installed
        if systemctl is-active --quiet sentrikat-agent.timer 2>/dev/null; then
            log_info "Restarting agent service..."
            systemctl restart sentrikat-heartbeat.service 2>/dev/null || true
        fi
    else
        # mv failed (permissions?), try with sudo
        if command -v sudo &>/dev/null; then
            sudo mv "$tmp_script" "$script_path" 2>/dev/null && \
                log_info "Agent updated successfully (via sudo) to ${target_version}" || {
                log_error "Failed to replace agent script"
                rm -f "$tmp_script"
                # Restore backup
                [[ -f "$backup_path" ]] && mv "$backup_path" "$script_path" 2>/dev/null
                return 1
            }
        else
            log_error "Failed to replace agent script (permission denied)"
            rm -f "$tmp_script"
            return 1
        fi
    fi
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
        auto_update_agent "$latest_version"
    fi

    # Update scan capabilities from server (license-gated features)
    if echo "$response" | grep -q '"scan_capabilities"'; then
        local cap_extensions cap_dependencies
        cap_extensions=$(echo "$response" | grep -o '"extensions": *[a-z]*' | head -1 | grep -o 'true\|false')
        cap_dependencies=$(echo "$response" | grep -o '"dependencies": *[a-z]*' | head -1 | grep -o 'true\|false')
        if [[ -n "$cap_extensions" && "$cap_extensions" != "$SCAN_EXTENSIONS" ]]; then
            log_info "Server updated scan capability: extensions=$cap_extensions"
            SCAN_EXTENSIONS="$cap_extensions"
            save_config
        fi
        if [[ -n "$cap_dependencies" && "$cap_dependencies" != "$SCAN_DEPENDENCIES" ]]; then
            log_info "Server updated scan capability: dependencies=$cap_dependencies"
            SCAN_DEPENDENCIES="$cap_dependencies"
            save_config
        fi
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

    # Run first inventory immediately so the asset appears in the dashboard
    echo "Running initial inventory scan..."
    log_info "Running initial inventory scan after install..."
    if main 2>/dev/null; then
        echo "Initial scan complete - agent is now visible in SentriKat dashboard"
    else
        echo "Initial scan failed - agent will retry on next scheduled scan"
        log_warn "Initial inventory failed, will retry on next scheduled run"
    fi
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
    # Heartbeat mode: send heartbeat + check for commands
    log_info "Running heartbeat check..."

    load_config

    if [[ -z "$SERVER_URL" || -z "$API_KEY" ]]; then
        log_error "SERVER_URL and API_KEY are required"
        exit 1
    fi

    # Send heartbeat to keep agent online in dashboard
    send_heartbeat

    # Check for commands from server (scan_now, update, etc.)
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

    # get_installed_software returns a temp FILE PATH (not a JSON string)
    # to avoid bash "Argument list too long" with large inventories
    local products_file
    products_file=$(get_installed_software)

    if [[ ! -f "$products_file" ]]; then
        log_error "Failed to collect software inventory"
        exit 1
    fi

    local product_count
    product_count=$(grep -o '"product"' "$products_file" | wc -l)

    log_info "Sending $product_count products to server..."

    if [[ $product_count -eq 0 ]]; then
        log_warn "No software found to report"
        rm -f "$products_file"
        exit 0
    fi

    if send_inventory "$system_info" "$products_file"; then
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
