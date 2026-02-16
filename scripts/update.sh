#!/bin/bash
# ============================================================
# SentriKat Update Script
# ============================================================
# Updates a SentriKat installation to the latest (or specified) version.
#
# Usage:
#   ./scripts/update.sh              # Update to latest version
#   ./scripts/update.sh 1.0.3        # Update to specific version
#   ./scripts/update.sh --check      # Check for updates only
#
# Works for both Docker and manual installations.
# ============================================================

set -e

REPO="sbr0nch/SentriKat"
PORTAL_API="${SENTRIKAT_LICENSE_SERVER:-https://license.sentrikat.com/api}"
CURRENT_VERSION_FILE=""
CURRENT_VERSION=""
TARGET_VERSION=""
CHECK_ONLY=false
INSTALLATION_ID=""

# Load proxy settings from .env if present (so curl and docker use them)
load_proxy_from_env() {
    local env_file=""
    for candidate in "./.env" "../.env" "${INSTALL_DIR:-.}/.env"; do
        if [ -f "$candidate" ]; then
            env_file="$candidate"
            break
        fi
    done
    [ -z "$env_file" ] && return

    # Only set if not already in environment
    if [ -z "${HTTP_PROXY:-}" ]; then
        local val
        val=$(grep -E '^HTTP_PROXY=' "$env_file" 2>/dev/null | head -1 | cut -d'=' -f2-)
        [ -n "$val" ] && export HTTP_PROXY="$val"
    fi
    if [ -z "${HTTPS_PROXY:-}" ]; then
        local val
        val=$(grep -E '^HTTPS_PROXY=' "$env_file" 2>/dev/null | head -1 | cut -d'=' -f2-)
        [ -n "$val" ] && export HTTPS_PROXY="$val"
    fi
    if [ -z "${NO_PROXY:-}" ]; then
        local val
        val=$(grep -E '^NO_PROXY=' "$env_file" 2>/dev/null | head -1 | cut -d'=' -f2-)
        [ -n "$val" ] && export NO_PROXY="$val"
    fi
}

# Load installation ID for portal API calls
load_installation_id() {
    local install_dir="${INSTALL_DIR:-.}"

    # 1. From data/.installation_id file
    if [ -f "${install_dir}/data/.installation_id" ]; then
        INSTALLATION_ID=$(cat "${install_dir}/data/.installation_id" 2>/dev/null | tr -d '[:space:]')
    fi

    # 2. Fallback to environment variable
    if [ -z "$INSTALLATION_ID" ]; then
        INSTALLATION_ID="${SENTRIKAT_INSTALLATION_ID:-}"
    fi

    if [ -z "$INSTALLATION_ID" ]; then
        log_warn "No installation ID found. Update check will still work but won't be tracked."
    fi
}

# Build curl args for portal API
portal_curl() {
    local headers=(-H "Content-Type: application/json")
    [ -n "$INSTALLATION_ID" ] && headers+=(-H "X-Installation-ID: ${INSTALLATION_ID}")
    [ -n "$CURRENT_VERSION" ] && headers+=(-H "X-App-Version: ${CURRENT_VERSION}")
    curl -sf "${headers[@]}" "$@"
}

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

log_info()  { echo -e "${BLUE}[INFO]${NC} $1"; }
log_ok()    { echo -e "${GREEN}[OK]${NC} $1"; }
log_warn()  { echo -e "${YELLOW}[WARN]${NC} $1"; }
log_error() { echo -e "${RED}[ERROR]${NC} $1"; }

# Detect if a directory is a SentriKat installation
is_sentrikat_dir() {
    local dir="$1"
    # Full installation (source/tarball): has VERSION + app/licensing.py
    if [ -f "${dir}/VERSION" ] && [ -f "${dir}/app/licensing.py" ]; then
        return 0
    fi
    # Docker-only deployment: has docker-compose.yml referencing sentrikat image
    if [ -f "${dir}/docker-compose.yml" ] && \
       grep -q "ghcr.io/sbr0nch/sentrikat" "${dir}/docker-compose.yml" 2>/dev/null; then
        return 0
    fi
    return 1
}

# Find the SentriKat installation directory
find_install_dir() {
    # 1. Explicit override via environment variable
    if [ -n "${SENTRIKAT_DIR:-}" ] && is_sentrikat_dir "$SENTRIKAT_DIR"; then
        echo "$SENTRIKAT_DIR"
        return
    fi

    # 2. Walk up from the current directory (handles running from any subdirectory)
    local dir
    dir=$(pwd)
    while [ "$dir" != "/" ]; do
        if is_sentrikat_dir "$dir"; then
            echo "$dir"
            return
        fi
        dir=$(dirname "$dir")
    done

    # 3. Check well-known installation paths
    for candidate in /opt/sentrikat /app /data/sentrikat; do
        if is_sentrikat_dir "$candidate"; then
            echo "$candidate"
            return
        fi
    done

    echo ""
}

# Get current installed version
get_current_version() {
    local install_dir="$1"

    if [ -f "${install_dir}/VERSION" ]; then
        CURRENT_VERSION=$(cat "${install_dir}/VERSION" | tr -d '[:space:]')
        CURRENT_VERSION_FILE="${install_dir}/VERSION"
    elif [ -f "${install_dir}/docker-compose.yml" ]; then
        # Docker-only deployment: extract version from image tag
        CURRENT_VERSION=$(grep -o 'ghcr.io/sbr0nch/sentrikat:[^ "]*' "${install_dir}/docker-compose.yml" 2>/dev/null \
            | head -1 | cut -d: -f2)
        [ -z "$CURRENT_VERSION" ] && CURRENT_VERSION="unknown"
    else
        CURRENT_VERSION="unknown"
    fi
}

# Get latest release version from the portal
get_latest_version() {
    local response http_code

    # Query the portal for the latest release
    http_code=$(portal_curl -o /tmp/sentrikat_latest.json -w '%{http_code}' \
        "${PORTAL_API}/v1/releases/latest" 2>/dev/null) || true

    if [ "$http_code" = "204" ]; then
        log_error "No releases published on the portal yet."
        exit 1
    fi

    if [ "$http_code" != "200" ] || [ ! -s /tmp/sentrikat_latest.json ]; then
        log_error "Could not reach SentriKat portal (${PORTAL_API}). Check your internet connection."
        rm -f /tmp/sentrikat_latest.json
        exit 1
    fi

    response=$(cat /tmp/sentrikat_latest.json)
    rm -f /tmp/sentrikat_latest.json

    # Extract version and strip 'v' prefix
    echo "$response" | grep -o '"version": *"[^"]*"' | head -1 | sed 's/.*"v\?\([^"]*\)"/\1/'
}

# Get download URL for a specific version (served by the portal)
get_download_url() {
    local version="$1"
    echo "${PORTAL_API}/v1/releases/${version}/download"
}

# Compare versions (returns 0 if $1 > $2)
version_gt() {
    [ "$(printf '%s\n' "$1" "$2" | sort -V | tail -1)" != "$2" ]
}

# Docker-based update - only updates the image tag, never replaces docker-compose.yml
update_docker() {
    local install_dir="$1"
    local version="$2"

    log_info "Updating Docker installation to v${version}..."

    # Check if docker-compose.yml exists
    if [ ! -f "${install_dir}/docker-compose.yml" ]; then
        log_error "docker-compose.yml not found in ${install_dir}"
        exit 1
    fi

    # Update image tag in docker-compose.yml (only the tag, not the whole file)
    if grep -q "ghcr.io/sbr0nch/sentrikat:" "${install_dir}/docker-compose.yml"; then
        sed -i "s|ghcr.io/sbr0nch/sentrikat:[^ \"]*|ghcr.io/sbr0nch/sentrikat:${version}|g" "${install_dir}/docker-compose.yml"
        log_info "Updated image tag to ${version}"
    fi

    # Pull new image
    log_info "Pulling new Docker image..."
    cd "${install_dir}"
    if ! (docker compose pull 2>/dev/null || docker-compose pull); then
        log_error "Failed to pull Docker image ghcr.io/sbr0nch/sentrikat:${version}"
        log_error "The image may not exist yet, or GHCR packages may not be public."
        log_error "Check: https://github.com/${REPO}/actions"
        # Revert image tag
        sed -i "s|ghcr.io/sbr0nch/sentrikat:[^ \"]*|ghcr.io/sbr0nch/sentrikat:${CURRENT_VERSION}|g" "${install_dir}/docker-compose.yml"
        log_warn "Reverted docker-compose.yml to v${CURRENT_VERSION}"
        exit 1
    fi
    log_ok "Docker image pulled"

    # Restart services
    log_info "Restarting SentriKat..."
    docker compose up -d 2>/dev/null || docker-compose up -d
    log_ok "SentriKat restarted"

    # Update VERSION file
    echo "${version}" > "${install_dir}/VERSION"
}

# File-based update (non-Docker)
update_files() {
    local install_dir="$1"
    local version="$2"
    local download_url
    download_url=$(get_download_url "$version")
    local tmp_dir
    tmp_dir=$(mktemp -d)

    log_info "Downloading SentriKat v${version}..."

    # Download release package from portal
    local curl_args=(-sfL -o "${tmp_dir}/sentrikat-${version}.tar.gz")
    [ -n "$INSTALLATION_ID" ] && curl_args+=(-H "X-Installation-ID: ${INSTALLATION_ID}")
    if ! curl "${curl_args[@]}" "$download_url"; then
        log_error "Failed to download v${version}. URL: ${download_url}"
        rm -rf "$tmp_dir"
        exit 1
    fi
    log_ok "Downloaded release package"

    # Extract
    log_info "Extracting..."
    cd "$tmp_dir"
    tar xzf "sentrikat-${version}.tar.gz"

    # Find extracted directory
    local extract_dir
    extract_dir=$(find "$tmp_dir" -maxdepth 1 -type d -name "sentrikat-*" | head -1)
    if [ -z "$extract_dir" ]; then
        log_error "Could not find extracted directory"
        rm -rf "$tmp_dir"
        exit 1
    fi

    # Backup critical files
    local backup_dir="${install_dir}/backups/pre-update-$(date +%Y%m%d%H%M%S)"
    mkdir -p "$backup_dir"
    log_info "Creating backup in ${backup_dir}..."

    # Backup app directory, configs
    for item in app static templates VERSION .env docker-compose.yml; do
        if [ -e "${install_dir}/${item}" ]; then
            cp -r "${install_dir}/${item}" "${backup_dir}/"
        fi
    done
    log_ok "Backup created"

    # Update app files (preserve .env, docker-compose.yml, and data)
    log_info "Updating application files..."
    for item in app static templates scripts tools agents docs nginx \
                Dockerfile docker-entrypoint.sh \
                requirements.txt VERSION README.md; do
        if [ -e "${extract_dir}/${item}" ]; then
            # Remove old and copy new
            rm -rf "${install_dir}/${item}"
            cp -r "${extract_dir}/${item}" "${install_dir}/${item}"
        fi
    done

    # Ensure VERSION is updated
    echo "${version}" > "${install_dir}/VERSION"
    log_ok "Application files updated"

    # Clean up
    rm -rf "$tmp_dir"

    log_warn "If running with Docker, restart with: docker compose up -d"
    log_warn "If running with systemd, restart with: sudo systemctl restart sentrikat"
}

# ── Main ──────────────────────────────────────────────────────

echo ""
echo "=========================================="
echo "  SentriKat Update Tool"
echo "=========================================="
echo ""

# Parse arguments
case "${1:-}" in
    --check|-c)
        CHECK_ONLY=true
        ;;
    --help|-h)
        echo "Usage: $0 [VERSION|--check|--help]"
        echo ""
        echo "  (no args)     Update to the latest version"
        echo "  VERSION        Update to a specific version (e.g., 1.0.3)"
        echo "  --check, -c    Check for updates without installing"
        echo "  --help, -h     Show this help message"
        echo ""
        exit 0
        ;;
    "")
        ;;
    *)
        TARGET_VERSION="$1"
        ;;
esac

# Find installation
INSTALL_DIR=$(find_install_dir)
if [ -z "$INSTALL_DIR" ]; then
    log_error "Could not find SentriKat installation."
    log_error "Run this script from the SentriKat directory, or set SENTRIKAT_DIR=/path/to/sentrikat"
    exit 1
fi
INSTALL_DIR=$(cd "$INSTALL_DIR" && pwd)
log_info "Installation directory: ${INSTALL_DIR}"

# Load proxy settings from .env (for curl and docker commands)
load_proxy_from_env
if [ -n "${HTTP_PROXY:-}" ] || [ -n "${HTTPS_PROXY:-}" ]; then
    log_info "Proxy: ${HTTPS_PROXY:-${HTTP_PROXY}}"
fi

# Load installation ID for portal API
load_installation_id
if [ -n "$INSTALLATION_ID" ]; then
    log_info "Installation ID: ${INSTALLATION_ID:0:20}..."
fi
log_info "Update server: ${PORTAL_API}"

# Get current version
get_current_version "$INSTALL_DIR"
log_info "Current version: ${CURRENT_VERSION}"

# Get target version
if [ -z "$TARGET_VERSION" ]; then
    log_info "Checking for latest release..."
    TARGET_VERSION=$(get_latest_version)
fi

if [ -z "$TARGET_VERSION" ]; then
    log_error "Could not determine target version."
    exit 1
fi
log_info "Target version:  ${TARGET_VERSION}"

# Compare versions
if [ "$CURRENT_VERSION" = "$TARGET_VERSION" ]; then
    log_ok "Already up to date (v${CURRENT_VERSION})."
    exit 0
fi

if [ "$CURRENT_VERSION" != "unknown" ] && ! version_gt "$TARGET_VERSION" "$CURRENT_VERSION"; then
    log_warn "Target version (${TARGET_VERSION}) is not newer than current (${CURRENT_VERSION})."
    if [ "$CHECK_ONLY" = true ]; then
        exit 0
    fi
    read -p "Continue anyway? [y/N] " -n 1 -r
    echo
    if [[ ! $REPLY =~ ^[Yy]$ ]]; then
        exit 0
    fi
fi

if [ "$CHECK_ONLY" = true ]; then
    echo ""
    log_ok "Update available: v${CURRENT_VERSION} -> v${TARGET_VERSION}"
    echo ""
    echo "  Run '$0' to update, or '$0 ${TARGET_VERSION}' for this specific version."
    echo ""
    exit 0
fi

echo ""
log_info "Updating: v${CURRENT_VERSION} -> v${TARGET_VERSION}"
echo ""

# Detect installation type and update
if command -v docker &> /dev/null && [ -f "${INSTALL_DIR}/docker-compose.yml" ] && \
   grep -q "ghcr.io/sbr0nch/sentrikat" "${INSTALL_DIR}/docker-compose.yml" 2>/dev/null; then
    update_docker "$INSTALL_DIR" "$TARGET_VERSION"
else
    update_files "$INSTALL_DIR" "$TARGET_VERSION"
fi

echo ""
echo "=========================================="
log_ok "SentriKat updated to v${TARGET_VERSION}!"
echo "=========================================="
echo ""
echo "  Next steps:"
echo "  1. Verify the application is running correctly"
echo "  2. Check Administration > License for version info"
echo "  3. Clear your browser cache (Ctrl+Shift+R)"
echo ""
