#!/bin/bash
#
# SentriKat macOS Agent - Software Inventory Collector
#
# Silent daemon agent that collects software inventory from macOS endpoints
# and reports to a SentriKat server. Designed to run as a LaunchDaemon.
#
# Version: 1.4.0
# Requires: bash, curl
#
# Software sources:
#   - system_profiler SPApplicationsDataType (GUI apps)
#   - pkgutil (system packages)
#   - Homebrew (brew list)
#   - MacPorts (port installed) [if available]
#
# Usage:
#   ./sentrikat-agent-macos.sh --server-url "https://sentrikat.example.com" --api-key "sk_agent_xxx"
#   ./sentrikat-agent-macos.sh --install --server-url "https://..." --api-key "..."
#   ./sentrikat-agent-macos.sh --uninstall
#

set -euo pipefail

AGENT_VERSION="1.4.0"
CONFIG_DIR="/Library/Application Support/SentriKat"
CONFIG_FILE="${CONFIG_DIR}/agent.conf"
LOG_FILE="/Library/Logs/sentrikat-agent.log"
LAUNCHDAEMON_PLIST="/Library/LaunchDaemons/com.sentrikat.agent.plist"
HEARTBEAT_PLIST="/Library/LaunchDaemons/com.sentrikat.heartbeat.plist"

# Default settings
SERVER_URL=""
API_KEY=""
INTERVAL_HOURS=4
HEARTBEAT_MINUTES=5
AGENT_ID=""

# ============================================================================
# Logging Functions
# ============================================================================

json_escape() {
    local str="$1"
    str="${str//\\/\\\\}"
    str="${str//\"/\\\"}"
    str="${str//$'\n'/\\n}"
    str="${str//$'\r'/\\r}"
    str="${str//$'\t'/\\t}"
    str=$(echo "$str" | tr -d '\000-\011\013-\037')
    echo "$str"
}

log() {
    local level="${1:-INFO}"
    local message="${2:-}"
    local timestamp
    timestamp=$(date '+%Y-%m-%d %H:%M:%S')

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

    [[ -n "${ARG_SERVER_URL:-}" ]] && SERVER_URL="$ARG_SERVER_URL"
    [[ -n "${ARG_API_KEY:-}" ]] && API_KEY="$ARG_API_KEY"

    if [[ -z "$AGENT_ID" ]]; then
        # macOS hardware UUID
        AGENT_ID=$(ioreg -d2 -c IOPlatformExpertDevice 2>/dev/null | awk -F'"' '/IOPlatformUUID/{print $4}')
        if [[ -z "$AGENT_ID" ]]; then
            AGENT_ID=$(uuidgen)
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

    hostname=$(scutil --get ComputerName 2>/dev/null || hostname -s 2>/dev/null || hostname)
    fqdn=$(hostname -f 2>/dev/null || scutil --get HostName 2>/dev/null || hostname)

    # Get primary IP address (route to external)
    ip_address=$(route get 1.1.1.1 2>/dev/null | awk '/interface:/{intf=$2} /gateway:/{gw=$2} END{if(intf) system("ipconfig getifaddr " intf)}' 2>/dev/null)
    if [[ -z "$ip_address" ]]; then
        ip_address=$(ipconfig getifaddr en0 2>/dev/null || ipconfig getifaddr en1 2>/dev/null || echo "unknown")
    fi

    os_name="macOS"
    os_version=$(sw_vers -productVersion 2>/dev/null || echo "unknown")
    kernel=$(uname -r)

    # Get macOS marketing name (e.g. "Ventura", "Sonoma")
    local build
    build=$(sw_vers -buildVersion 2>/dev/null || echo "")
    local full_version="macOS ${os_version}"
    if [[ -n "$build" ]]; then
        full_version="${full_version} (${build})"
    fi

    hostname=$(json_escape "$hostname")
    fqdn=$(json_escape "$fqdn")
    ip_address=$(json_escape "$ip_address")
    os_version=$(json_escape "$full_version")
    kernel=$(json_escape "$kernel")

    cat << EOF
{
    "hostname": "${hostname}",
    "fqdn": "${fqdn}",
    "ip_address": "${ip_address}",
    "os": {
        "name": "macOS",
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

    # -----------------------------------------------------------------------
    # 1. GUI Applications via system_profiler
    # -----------------------------------------------------------------------
    log_info "Scanning installed applications (system_profiler)..."

    # system_profiler outputs XML-like text; parse with awk for speed
    local app_data
    app_data=$(system_profiler SPApplicationsDataType -detailLevel mini 2>/dev/null || true)

    if [[ -n "$app_data" ]]; then
        local current_name="" current_version="" current_vendor="" current_path=""

        while IFS= read -r line; do
            # Application name (indented header ending with :)
            if [[ "$line" =~ ^[[:space:]]{4}[^[:space:]] && "$line" =~ :$ ]]; then
                # Save previous entry
                if [[ -n "$current_name" ]]; then
                    local esc_name esc_version esc_vendor esc_path
                    esc_name=$(json_escape "$current_name")
                    esc_version=$(json_escape "${current_version:-unknown}")
                    esc_vendor=$(json_escape "${current_vendor:-Unknown}")
                    esc_path=$(json_escape "${current_path:-}")
                    products+=("{\"vendor\": \"$esc_vendor\", \"product\": \"$esc_name\", \"version\": \"$esc_version\", \"path\": \"$esc_path\"}")
                    ((count++))
                fi
                current_name="${line%%:*}"
                current_name="${current_name#"${current_name%%[![:space:]]*}"}"  # Trim leading whitespace
                current_version=""
                current_vendor=""
                current_path=""
            elif [[ "$line" =~ Version: ]]; then
                current_version="${line#*: }"
            elif [[ "$line" =~ "Obtained from:" ]]; then
                current_vendor="${line#*: }"
                # Map "Apple" / "Identified Developer" etc.
                case "$current_vendor" in
                    Apple) current_vendor="Apple" ;;
                    "Identified Developer"|"Mac App Store") current_vendor="${current_vendor}" ;;
                    *) current_vendor="${current_vendor:-Unknown}" ;;
                esac
            elif [[ "$line" =~ Location: ]]; then
                current_path="${line#*: }"
            fi
        done <<< "$app_data"

        # Don't forget the last entry
        if [[ -n "$current_name" ]]; then
            local esc_name esc_version esc_vendor esc_path
            esc_name=$(json_escape "$current_name")
            esc_version=$(json_escape "${current_version:-unknown}")
            esc_vendor=$(json_escape "${current_vendor:-Unknown}")
            esc_path=$(json_escape "${current_path:-}")
            products+=("{\"vendor\": \"$esc_vendor\", \"product\": \"$esc_name\", \"version\": \"$esc_version\", \"path\": \"$esc_path\"}")
            ((count++))
        fi
    fi

    log_info "Found $count applications via system_profiler"

    # -----------------------------------------------------------------------
    # 2. System packages via pkgutil (receipts)
    # -----------------------------------------------------------------------
    log_info "Scanning system packages (pkgutil)..."

    local pkg_count=0
    while IFS= read -r pkg_id; do
        [[ -z "$pkg_id" ]] && continue

        local pkg_version
        pkg_version=$(pkgutil --pkg-info "$pkg_id" 2>/dev/null | awk -F': ' '/version:/{print $2}')

        # Extract a human-friendly name from the package ID
        local pkg_name="${pkg_id##*.}"
        local pkg_vendor="${pkg_id%%.*}"

        # Map common vendors
        case "$pkg_id" in
            com.apple.*) pkg_vendor="Apple" ;;
            com.microsoft.*) pkg_vendor="Microsoft" ;;
            com.google.*) pkg_vendor="Google" ;;
            org.mozilla.*) pkg_vendor="Mozilla" ;;
            com.docker.*) pkg_vendor="Docker" ;;
            com.oracle.*) pkg_vendor="Oracle" ;;
            org.postgresql.*) pkg_vendor="PostgreSQL" ;;
            io.homebrew.*) continue ;;  # Skip - handled by brew list below
            *) pkg_vendor="${pkg_vendor:-Unknown}" ;;
        esac

        pkg_name=$(json_escape "$pkg_name")
        pkg_version=$(json_escape "${pkg_version:-unknown}")
        pkg_vendor=$(json_escape "$pkg_vendor")

        products+=("{\"vendor\": \"$pkg_vendor\", \"product\": \"$pkg_name\", \"version\": \"$pkg_version\"}")
        ((count++))
        ((pkg_count++))
    done < <(pkgutil --pkgs 2>/dev/null | grep -v '^com\.apple\.' || true)
    # Note: we skip com.apple.* system packages to avoid massive noise (500+ entries)
    # Apple OS vulnerabilities are tracked by macOS version, not individual pkg receipts

    log_info "Found $pkg_count third-party system packages"

    # -----------------------------------------------------------------------
    # 3. Homebrew packages
    # -----------------------------------------------------------------------
    if command -v brew &>/dev/null; then
        log_info "Scanning Homebrew packages..."
        local brew_count=0

        # Formulae (CLI tools)
        while IFS=' ' read -r name version; do
            [[ -z "$name" ]] && continue
            name=$(json_escape "$name")
            version=$(json_escape "$version")
            products+=("{\"vendor\": \"Homebrew\", \"product\": \"$name\", \"version\": \"$version\"}")
            ((count++))
            ((brew_count++))
        done < <(brew list --formula --versions 2>/dev/null || true)

        # Casks (GUI apps installed via Homebrew)
        while IFS=' ' read -r name version; do
            [[ -z "$name" ]] && continue
            name=$(json_escape "$name")
            version=$(json_escape "$version")
            products+=("{\"vendor\": \"Homebrew Cask\", \"product\": \"$name\", \"version\": \"$version\"}")
            ((count++))
            ((brew_count++))
        done < <(brew list --cask --versions 2>/dev/null || true)

        log_info "Found $brew_count Homebrew packages"
    fi

    # -----------------------------------------------------------------------
    # 4. MacPorts packages (if installed)
    # -----------------------------------------------------------------------
    if command -v port &>/dev/null; then
        log_info "Scanning MacPorts packages..."
        local port_count=0

        while read -r line; do
            [[ -z "$line" ]] && continue
            # Format: "  name @version_revision+variants (active)"
            local name version
            name=$(echo "$line" | awk '{print $1}')
            version=$(echo "$line" | awk '{print $2}' | sed 's/^@//' | sed 's/_/ /')

            [[ -z "$name" ]] && continue
            name=$(json_escape "$name")
            version=$(json_escape "${version:-unknown}")

            products+=("{\"vendor\": \"MacPorts\", \"product\": \"$name\", \"version\": \"$version\"}")
            ((count++))
            ((port_count++))
        done < <(port installed 2>/dev/null | tail -n +2 || true)

        log_info "Found $port_count MacPorts packages"
    fi

    log_info "Collected $count installed packages total (server-side filtering)"

    # Write JSON array to temp file (avoids ARG_MAX issues)
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
TRIVY_CACHE_DIR="/Library/Caches/SentriKat/trivy"
CONTAINER_SCAN_ENABLED="${CONTAINER_SCAN_ENABLED:-auto}"
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
    if [[ -x "$TRIVY_BIN" ]]; then
        log_info "Trivy found at $TRIVY_BIN"
        return 0
    fi

    if command -v trivy &>/dev/null; then
        TRIVY_BIN=$(command -v trivy)
        log_info "Trivy found in PATH at $TRIVY_BIN"
        return 0
    fi

    if [[ "$TRIVY_OFFLINE" == "true" ]]; then
        log_warn "Trivy not found and TRIVY_OFFLINE=true. Pre-deploy trivy to $TRIVY_BIN"
        return 1
    fi

    log_info "Installing Trivy for container image scanning..."
    mkdir -p "$TRIVY_CACHE_DIR" 2>/dev/null || true

    local arch
    case "$(uname -m)" in
        x86_64)  arch="macOS-64bit" ;;
        arm64)   arch="macOS-ARM64" ;;
        *)
            log_warn "Unsupported architecture $(uname -m) for Trivy"
            return 1
            ;;
    esac

    local tmpdir
    tmpdir=$(mktemp -d)
    local trivy_version="0.58.2"
    local download_url="https://github.com/aquasecurity/trivy/releases/download/v${trivy_version}/trivy_${trivy_version}_${arch}.tar.gz"

    log_info "Downloading Trivy v${trivy_version}..."
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
    rm -rf "$tmpdir"
    return 1
}

scan_container_images() {
    if [[ "$CONTAINER_SCAN_ENABLED" == "false" ]]; then
        log_info "Container scanning disabled by configuration"
        return 0
    fi

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

    if ! install_trivy; then
        log_warn "Trivy not available, skipping container scan"
        return 1
    fi

    local image_list
    image_list=$(docker images --format "{{.Repository}}:{{.Tag}}|{{.ID}}|{{.Size}}" 2>/dev/null | grep -v '<none>' || true)

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

    # Assemble final payload to temp file (no large bash variables)
    local endpoint="${SERVER_URL}/api/agent/container-scan"
    local trivy_version
    trivy_version=$("$TRIVY_BIN" --version 2>/dev/null | head -1 | awk '{print $2}' || echo 'unknown')
    local my_hostname
    my_hostname=$(scutil --get ComputerName 2>/dev/null || hostname)

    local tmpfile
    tmpfile=$(mktemp)
    printf '{"agent_id": "%s", "hostname": "%s", "scanner": "trivy", "scanner_version": "%s", "images": ' \
        "$AGENT_ID" "$my_hostname" "$trivy_version" > "$tmpfile"
    cat "$results_file" >> "$tmpfile"
    printf '}' >> "$tmpfile"
    rm -f "$results_file"

    curl -s -X POST "$endpoint" \
        -H "X-Agent-Key: $API_KEY" \
        -H "Content-Type: application/json" \
        -H "User-Agent: SentriKat-Agent/$AGENT_VERSION (macOS)" \
        --data-binary "@${tmpfile}" \
        --max-time 120 >/dev/null 2>&1 || log_warn "Failed to send container scan results"

    rm -f "$tmpfile"
}

# ============================================================================
# API Communication
# ============================================================================

send_inventory() {
    local system_info="$1"
    local products_file="$2"

    local endpoint="${SERVER_URL}/api/agent/inventory"

    log_info "Sending inventory to $endpoint..."

    local tmpfile
    tmpfile=$(mktemp)

    printf '%s' "$system_info" | sed 's/}$//' > "$tmpfile"
    printf ', "products": ' >> "$tmpfile"
    cat "$products_file" >> "$tmpfile"
    printf '}' >> "$tmpfile"

    rm -f "$products_file"

    local max_retries=3
    local retry_delay=5

    for ((i=1; i<=max_retries; i++)); do
        local response
        local http_code

        response=$(curl -s -w "\n%{http_code}" -X POST "$endpoint" \
            -H "X-Agent-Key: $API_KEY" \
            -H "Content-Type: application/json" \
            -H "User-Agent: SentriKat-Agent/$AGENT_VERSION (macOS)" \
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
        -d "{\"hostname\": \"$(scutil --get ComputerName 2>/dev/null || hostname)\", \"agent_id\": \"$AGENT_ID\"}" \
        --max-time 30 >/dev/null 2>&1
}

check_commands() {
    local hostname
    hostname=$(scutil --get ComputerName 2>/dev/null || hostname)
    local endpoint="${SERVER_URL}/api/agent/commands?agent_id=${AGENT_ID}&hostname=${hostname}&version=${AGENT_VERSION}&platform=macos"

    log_info "Checking for commands from server..."

    local response
    response=$(curl -s -X GET "$endpoint" \
        -H "X-Agent-Key: $API_KEY" \
        -H "Content-Type: application/json" \
        --max-time 30 2>&1) || {
        log_warn "Failed to check commands: connection error"
        return 1
    }

    if echo "$response" | grep -q '"command": "scan_now"'; then
        log_info "Received scan_now command - triggering immediate inventory scan"
        return 0
    fi

    if echo "$response" | grep -q '"command": "update_available"'; then
        local latest_version
        latest_version=$(echo "$response" | grep -o '"latest_version": "[^"]*"' | cut -d'"' -f4)
        log_warn "Agent update available: ${AGENT_VERSION} -> ${latest_version}"
        log_info "Download from: ${SERVER_URL}/api/agent/download/macos"
    fi

    return 1
}

# ============================================================================
# Installation Functions
# ============================================================================

install_agent() {
    log_info "Installing SentriKat agent..."

    if [[ $EUID -ne 0 ]]; then
        echo "ERROR: Installation requires root privileges (use sudo)"
        exit 1
    fi

    save_config

    # Copy script to system location
    local script_dest="/usr/local/bin/sentrikat-agent"
    cp "$0" "$script_dest"
    chmod 755 "$script_dest"

    # Calculate interval in seconds
    local interval_seconds=$((INTERVAL_HOURS * 3600))
    local heartbeat_seconds=$((HEARTBEAT_MINUTES * 60))

    # Create LaunchDaemon for full inventory scan
    cat > "$LAUNCHDAEMON_PLIST" << EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>com.sentrikat.agent</string>
    <key>ProgramArguments</key>
    <array>
        <string>/usr/local/bin/sentrikat-agent</string>
        <string>--run-once</string>
    </array>
    <key>StartInterval</key>
    <integer>${interval_seconds}</integer>
    <key>RunAtLoad</key>
    <true/>
    <key>StandardOutPath</key>
    <string>/Library/Logs/sentrikat-agent-stdout.log</string>
    <key>StandardErrorPath</key>
    <string>/Library/Logs/sentrikat-agent-stderr.log</string>
</dict>
</plist>
EOF

    # Create LaunchDaemon for heartbeat/command polling
    cat > "$HEARTBEAT_PLIST" << EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>com.sentrikat.heartbeat</string>
    <key>ProgramArguments</key>
    <array>
        <string>/usr/local/bin/sentrikat-agent</string>
        <string>--heartbeat</string>
    </array>
    <key>StartInterval</key>
    <integer>${heartbeat_seconds}</integer>
    <key>RunAtLoad</key>
    <true/>
    <key>StandardOutPath</key>
    <string>/Library/Logs/sentrikat-heartbeat-stdout.log</string>
    <key>StandardErrorPath</key>
    <string>/Library/Logs/sentrikat-heartbeat-stderr.log</string>
</dict>
</plist>
EOF

    # Load the daemons
    launchctl load "$LAUNCHDAEMON_PLIST" 2>/dev/null || true
    launchctl load "$HEARTBEAT_PLIST" 2>/dev/null || true

    log_info "Agent installed successfully"
    echo "SentriKat Agent installed:"
    echo "  - Full scan: every ${INTERVAL_HOURS} hours"
    echo "  - Heartbeat: every ${HEARTBEAT_MINUTES} minutes (checks for commands)"
    echo "Run 'sudo launchctl list | grep sentrikat' to check status"
}

uninstall_agent() {
    log_info "Uninstalling SentriKat agent..."

    if [[ $EUID -ne 0 ]]; then
        echo "ERROR: Uninstallation requires root privileges (use sudo)"
        exit 1
    fi

    launchctl unload "$LAUNCHDAEMON_PLIST" 2>/dev/null || true
    launchctl unload "$HEARTBEAT_PLIST" 2>/dev/null || true

    rm -f "$LAUNCHDAEMON_PLIST" "$HEARTBEAT_PLIST"
    rm -f /usr/local/bin/sentrikat-agent

    log_info "Agent uninstalled"
    echo "SentriKat Agent uninstalled"
}

heartbeat_mode() {
    log_info "Running heartbeat check..."

    load_config

    if [[ -z "$SERVER_URL" || -z "$API_KEY" ]]; then
        log_error "SERVER_URL and API_KEY are required"
        exit 1
    fi

    if check_commands; then
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
SentriKat macOS Agent v${AGENT_VERSION}

Usage: $0 [OPTIONS]

Options:
  --server-url URL     SentriKat server URL (required)
  --api-key KEY        Agent API key (required)
  --interval HOURS     Scan interval in hours (default: 4)
  --install            Install as LaunchDaemon (includes heartbeat)
  --uninstall          Uninstall agent
  --run-once           Run inventory collection once and exit
  --heartbeat          Run heartbeat check (polls for commands)
  --verbose            Enable verbose output
  --help               Show this help message

Examples:
  # Run once for testing
  $0 --server-url "https://sentrikat.example.com" --api-key "sk_agent_xxx" --verbose

  # Install as LaunchDaemon (includes heartbeat every 5 min)
  sudo $0 --install --server-url "https://sentrikat.example.com" --api-key "sk_agent_xxx"

  # Uninstall
  sudo $0 --uninstall
EOF
}

main() {
    log_info "SentriKat Agent v${AGENT_VERSION} (macOS) starting..."

    load_config

    if [[ -z "$SERVER_URL" || -z "$API_KEY" ]]; then
        log_error "SERVER_URL and API_KEY are required"
        echo "ERROR: --server-url and --api-key are required"
        echo "Run '$0 --help' for usage information"
        exit 1
    fi

    local system_info
    system_info=$(get_system_info)
    log_info "System: $(echo "$system_info" | grep -o '"hostname"[^,]*' | head -1)"

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

    # Run container image scan (if Docker detected)
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
