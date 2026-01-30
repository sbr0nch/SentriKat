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

AGENT_VERSION="1.0.0"
CONFIG_DIR="/etc/sentrikat"
CONFIG_FILE="${CONFIG_DIR}/agent.conf"
LOG_FILE="/var/log/sentrikat-agent.log"
PID_FILE="/var/run/sentrikat-agent.pid"
SYSTEMD_SERVICE="/etc/systemd/system/sentrikat-agent.service"
SYSTEMD_TIMER="/etc/systemd/system/sentrikat-agent.timer"

# Default settings
SERVER_URL=""
API_KEY=""
INTERVAL_HOURS=4
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

    # Security-relevant package patterns to include (case-insensitive matching)
    # These are packages commonly tracked for CVEs
    is_security_relevant() {
        local pkg="$1"
        local pkg_lower="${pkg,,}"  # Convert to lowercase

        # Include these important package categories
        case "$pkg_lower" in
            # Web servers & proxies
            apache*|httpd*|nginx*|haproxy*|traefik*|caddy*|lighttpd*) return 0 ;;
            # Databases
            mysql*|mariadb*|postgres*|mongodb*|redis*|memcached*|sqlite*|elasticsearch*) return 0 ;;
            # Programming languages & runtimes
            php*|python3|ruby*|nodejs*|node|npm|java*|openjdk*|golang*|dotnet*|mono*) return 0 ;;
            # Security & crypto
            openssl*|openssh*|gnupg*|gpg*|libssl*|libcrypto*|ca-certificates*) return 0 ;;
            # Container & virtualization
            docker*|containerd*|podman*|kubernetes*|kubectl*|helm*|vagrant*|virtualbox*|qemu*) return 0 ;;
            # System services
            systemd*|dbus*|polkit*|sudo*|cron*) return 0 ;;
            # Network services
            bind9*|named*|dnsmasq*|postfix*|dovecot*|exim*|sendmail*|samba*|nfs*|vsftpd*|proftpd*) return 0 ;;
            # Monitoring & logging
            prometheus*|grafana*|zabbix*|nagios*|rsyslog*|syslog*|logrotate*) return 0 ;;
            # Security tools
            fail2ban*|iptables*|nftables*|ufw*|firewalld*|selinux*|apparmor*|aide*|tripwire*|clamav*) return 0 ;;
            # Version control
            git|git-core|subversion*|mercurial*) return 0 ;;
            # Message queues
            rabbitmq*|kafka*|activemq*|zeromq*) return 0 ;;
            # Common vulnerable software
            log4j*|struts*|tomcat*|jetty*|wildfly*|jboss*|spring*) return 0 ;;
            # Kernel & boot
            linux-image*|linux-headers*|grub*|kernel*) return 0 ;;
            # Package managers (for tracking)
            apt|dpkg|rpm|yum|dnf|pip*|gem*|composer*|cargo*) return 0 ;;
            # Common utilities with CVE history
            curl|wget|tar|gzip|bzip2|xz*|unzip*|bash|zsh|vim*|tmux*) return 0 ;;
            *) return 1 ;;
        esac
    }

    # Debian/Ubuntu: dpkg
    if command -v dpkg &>/dev/null; then
        while IFS=$'\t' read -r name version; do
            [[ -z "$name" ]] && continue

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
            products+=("{\"vendor\": \"$vendor\", \"product\": \"$name\", \"version\": \"$version\"}")
            ((count++))
        done < <(dpkg-query -W -f='${Package}\t${Version}\n' 2>/dev/null)
    fi

    # RHEL/CentOS/Fedora: rpm
    if command -v rpm &>/dev/null && [[ ! -f /etc/debian_version ]]; then
        while IFS=$'\t' read -r name version vendor; do
            [[ -z "$name" ]] && continue

            # Filter to security-relevant packages only
            if ! is_security_relevant "$name"; then
                continue
            fi

            [[ "$vendor" == "(none)" ]] && vendor="Community"

            # Escape JSON special characters
            name=$(json_escape "$name")
            version=$(json_escape "$version")
            vendor=$(json_escape "$vendor")
            products+=("{\"vendor\": \"$vendor\", \"product\": \"$name\", \"version\": \"$version\"}")
            ((count++))
        done < <(rpm -qa --queryformat '%{NAME}\t%{VERSION}-%{RELEASE}\t%{VENDOR}\n' 2>/dev/null)
    fi

    # Alpine: apk
    if command -v apk &>/dev/null; then
        while IFS='-' read -r name version; do
            [[ -z "$name" ]] && continue

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

    log_info "Found $count software packages"

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
# API Communication
# ============================================================================

send_inventory() {
    local system_info="$1"
    local products="$2"

    local endpoint="${SERVER_URL}/api/agent/inventory"

    log_info "Sending inventory to $endpoint..."

    # Build payload by inserting products into system_info JSON
    # The system_info ends with "}" - we replace it with ", "products": [...] }"
    local payload
    payload=$(echo "$system_info" | sed 's/}$//')
    payload="${payload}, \"products\": ${products}}"

    # Write payload to temp file to avoid "Argument list too long" error
    local tmpfile
    tmpfile=$(mktemp)
    echo "$payload" > "$tmpfile"

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

    # Create systemd service
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

    # Create systemd timer
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

    # Enable and start timer
    systemctl daemon-reload
    systemctl enable --now sentrikat-agent.timer

    log_info "Agent installed successfully"
    echo "SentriKat Agent installed and scheduled to run every ${INTERVAL_HOURS} hours"
    echo "Run 'systemctl status sentrikat-agent.timer' to check status"
}

uninstall_agent() {
    log_info "Uninstalling SentriKat agent..."

    if [[ $EUID -ne 0 ]]; then
        echo "ERROR: Uninstallation requires root privileges"
        exit 1
    fi

    # Stop and disable timer
    systemctl stop sentrikat-agent.timer 2>/dev/null || true
    systemctl disable sentrikat-agent.timer 2>/dev/null || true

    # Remove systemd files
    rm -f "$SYSTEMD_SERVICE" "$SYSTEMD_TIMER"
    systemctl daemon-reload

    # Remove script
    rm -f /usr/local/bin/sentrikat-agent

    # Optionally remove config (commented out by default)
    # rm -rf "$CONFIG_DIR"

    log_info "Agent uninstalled"
    echo "SentriKat Agent uninstalled"
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
  --install            Install as systemd service
  --uninstall          Uninstall agent
  --run-once           Run inventory collection once and exit
  --verbose            Enable verbose output
  --help               Show this help message

Examples:
  # Run once for testing
  $0 --server-url "https://sentrikat.example.com" --api-key "sk_agent_xxx" --verbose

  # Install as service
  sudo $0 --install --server-url "https://sentrikat.example.com" --api-key "sk_agent_xxx"

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
}

# Parse arguments
INSTALL=false
UNINSTALL=false
RUN_ONCE=false
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

# Default: run main
main
