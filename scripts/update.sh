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
# Supports three deployment types (auto-detected):
#   1. Docker image (customer package with ghcr.io pre-built image)
#   2. Docker build (developer/self-hosted, builds from source)
#   3. Standalone (no Docker, source-based)
#
# Environment variables:
#   SENTRIKAT_DIR        Override installation directory detection
#   GITHUB_TOKEN         Auth token for private repos
#   SENTRIKAT_LICENSE_SERVER  Portal API URL override
# ============================================================

set -e

REPO="sbr0nch/SentriKat"
GITHUB_API="https://api.github.com/repos/${REPO}"
PORTAL_API="${SENTRIKAT_LICENSE_SERVER:-https://license.sentrikat.com/api}"
CURRENT_VERSION_FILE=""
CURRENT_VERSION=""
TARGET_VERSION=""
CHECK_ONLY=false
INSTALLATION_ID=""
DEPLOY_TYPE="" # docker_image, docker_build, standalone

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

    if [ -f "${install_dir}/data/.installation_id" ]; then
        INSTALLATION_ID=$(cat "${install_dir}/data/.installation_id" 2>/dev/null | tr -d '[:space:]')
    fi

    if [ -z "$INSTALLATION_ID" ]; then
        INSTALLATION_ID="${SENTRIKAT_INSTALLATION_ID:-}"
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
NC='\033[0m'

log_info()  { echo -e "${BLUE}[INFO]${NC} $1"; }
log_ok()    { echo -e "${GREEN}[OK]${NC} $1"; }
log_warn()  { echo -e "${YELLOW}[WARN]${NC} $1"; }
log_error() { echo -e "${RED}[ERROR]${NC} $1"; }

# ============================================================
# Installation Detection
# ============================================================

# Detect if a directory is a SentriKat installation
is_sentrikat_dir() {
    local dir="$1"

    # 1. Full source install: VERSION + app/licensing.py
    if [ -f "${dir}/VERSION" ] && [ -f "${dir}/app/licensing.py" ]; then
        return 0
    fi

    # 2. Customer Docker deploy: docker-compose.yml with pre-built GHCR image
    if [ -f "${dir}/docker-compose.yml" ] && \
       grep -q "ghcr.io/sbr0nch/sentrikat" "${dir}/docker-compose.yml" 2>/dev/null; then
        return 0
    fi

    # 3. Developer Docker (build from source): Dockerfile + docker-compose.yml + app/
    if [ -f "${dir}/docker-compose.yml" ] && [ -f "${dir}/Dockerfile" ] && \
       [ -f "${dir}/app/licensing.py" ]; then
        return 0
    fi

    # 4. Source checkout without VERSION file: run.py + app/licensing.py
    if [ -f "${dir}/run.py" ] && [ -f "${dir}/app/licensing.py" ]; then
        return 0
    fi

    return 1
}

# Resolve a path to absolute, following symlinks when possible
resolve_path() {
    local p="$1"
    # Try readlink -f (Linux), then realpath, then manual resolution
    readlink -f "$p" 2>/dev/null && return
    realpath "$p" 2>/dev/null && return
    # Manual: cd into it (works for directories and relative paths)
    if [ -d "$p" ]; then
        (cd "$p" 2>/dev/null && pwd) && return
    elif [ -f "$p" ]; then
        local dir base
        dir="$(cd "$(dirname "$p")" 2>/dev/null && pwd)" || return 1
        base="$(basename "$p")"
        echo "${dir}/${base}" && return
    fi
    # Last resort: return as-is
    echo "$p"
}

# Find the SentriKat installation directory
find_install_dir() {
    # Helper: check a directory and its app/ subdirectory
    _check_dir_and_app() {
        local d="$1"
        [ -d "$d" ] || return 1
        if is_sentrikat_dir "$d"; then
            echo "$d"
            return 0
        fi
        if [ -d "${d}/app" ] && is_sentrikat_dir "${d}/app"; then
            echo "${d}/app"
            return 0
        fi
        return 1
    }

    local result

    # 1. Explicit override via SENTRIKAT_DIR
    if [ -n "${SENTRIKAT_DIR:-}" ]; then
        local resolved
        resolved="$(resolve_path "$SENTRIKAT_DIR" 2>/dev/null)" || resolved="$SENTRIKAT_DIR"
        result=$(_check_dir_and_app "$resolved") && { echo "$result"; return; }
    fi

    # 2. Derive from script's own location (scripts/update.sh → parent is install root)
    #    Handles symlinks and indirect invocations (e.g. bash /other/path/update.sh)
    local script_path="${BASH_SOURCE[0]:-$0}"
    if [ -n "$script_path" ] && [ "$script_path" != "bash" ] && [ "$script_path" != "-bash" ]; then
        local real_path
        real_path="$(resolve_path "$script_path" 2>/dev/null)" || real_path=""
        if [ -n "$real_path" ]; then
            local script_parent
            script_parent="$(dirname "$(dirname "$real_path")")"
            result=$(_check_dir_and_app "$script_parent") && { echo "$result"; return; }
        fi
    fi

    # 3. Walk up from current directory
    local dir
    dir=$(pwd)
    while [ "$dir" != "/" ]; do
        result=$(_check_dir_and_app "$dir") && { echo "$result"; return; }
        dir=$(dirname "$dir")
    done

    # 4. Well-known installation paths
    for candidate in /opt/sentrikat /app /data/sentrikat; do
        result=$(_check_dir_and_app "$candidate") && { echo "$result"; return; }
    done

    echo ""
}

# Detect deployment type
detect_deploy_type() {
    local dir="$1"

    if ! command -v docker &> /dev/null; then
        DEPLOY_TYPE="standalone"
        return
    fi

    if [ ! -f "${dir}/docker-compose.yml" ]; then
        DEPLOY_TYPE="standalone"
        return
    fi

    # Pre-built image from GHCR
    if grep -q "ghcr.io/sbr0nch/sentrikat" "${dir}/docker-compose.yml" 2>/dev/null; then
        DEPLOY_TYPE="docker_image"
        return
    fi

    # Build from source (has build: directive)
    if grep -qE '^\s+build:' "${dir}/docker-compose.yml" 2>/dev/null; then
        DEPLOY_TYPE="docker_build"
        return
    fi

    DEPLOY_TYPE="standalone"
}

# ============================================================
# Version Detection
# ============================================================

get_current_version() {
    local install_dir="$1"

    # 1. VERSION file
    if [ -f "${install_dir}/VERSION" ]; then
        CURRENT_VERSION=$(cat "${install_dir}/VERSION" | tr -d '[:space:]')
        CURRENT_VERSION_FILE="${install_dir}/VERSION"
        return
    fi

    # 2. Docker image tag in docker-compose.yml
    if [ -f "${install_dir}/docker-compose.yml" ]; then
        local ver
        ver=$(grep -o 'ghcr.io/sbr0nch/sentrikat:[^ "]*' "${install_dir}/docker-compose.yml" 2>/dev/null \
            | head -1 | cut -d: -f2)
        if [ -n "$ver" ]; then
            CURRENT_VERSION="$ver"
            return
        fi
    fi

    # 3. Running Docker container label
    if command -v docker &> /dev/null; then
        local ver
        ver=$(docker inspect sentrikat --format '{{ index .Config.Labels "org.opencontainers.image.version" }}' 2>/dev/null) || true
        if [ -n "$ver" ] && [ "$ver" != "<no value>" ]; then
            CURRENT_VERSION="$ver"
            return
        fi
    fi

    CURRENT_VERSION="unknown"
}

# Get latest release version (tries portal, falls back to GitHub)
get_latest_version() {
    local version=""

    # 1. Try portal
    local http_code
    http_code=$(portal_curl -o /tmp/sentrikat_latest.json -w '%{http_code}' \
        "${PORTAL_API}/v1/releases/latest" 2>/dev/null) || true

    if [ "$http_code" = "200" ] && [ -s /tmp/sentrikat_latest.json ]; then
        version=$(cat /tmp/sentrikat_latest.json | grep -o '"version": *"[^"]*"' | head -1 | sed 's/.*"v\?\([^"]*\)"/\1/')
    fi
    rm -f /tmp/sentrikat_latest.json

    if [ -n "$version" ]; then
        echo "$version"
        return
    fi

    # 2. Fallback to GitHub Releases API
    log_info "Portal unavailable, checking GitHub..."
    local gh_args=(-sf)
    [ -n "${GITHUB_TOKEN:-}" ] && gh_args+=(-H "Authorization: token ${GITHUB_TOKEN}")

    local response
    response=$(curl "${gh_args[@]}" "${GITHUB_API}/releases/latest" 2>/dev/null) || true

    if [ -n "$response" ]; then
        version=$(echo "$response" | grep -o '"tag_name": *"[^"]*"' | head -1 | sed 's/.*"v\?\([^"]*\)"/\1/')
    fi

    if [ -n "$version" ]; then
        echo "$version"
        return
    fi

    log_error "Could not determine latest version from portal or GitHub."
    exit 1
}

# Compare versions (returns 0 if $1 > $2)
version_gt() {
    [ "$(printf '%s\n' "$1" "$2" | sort -V | tail -1)" != "$2" ]
}

# ============================================================
# Download
# ============================================================

# Download release source (tries GitHub archive, then release asset, then portal)
download_release() {
    local version="$1"
    local output="$2"

    local gh_args=(-fL --progress-bar -o "$output")
    [ -n "${GITHUB_TOKEN:-}" ] && gh_args+=(-H "Authorization: token ${GITHUB_TOKEN}")

    # 1. GitHub source archive (best for build-from-source deployments)
    log_info "Downloading from GitHub..."
    if curl "${gh_args[@]}" "https://github.com/${REPO}/archive/refs/tags/v${version}.tar.gz" 2>/dev/null; then
        log_ok "Downloaded source archive from GitHub"
        return 0
    fi

    # 2. GitHub release asset (deployment package)
    if curl "${gh_args[@]}" "https://github.com/${REPO}/releases/download/v${version}/sentrikat-${version}.tar.gz" 2>/dev/null; then
        log_ok "Downloaded release package from GitHub"
        return 0
    fi

    # 3. Portal
    log_info "Trying portal download..."
    local portal_args=(-fL --progress-bar -o "$output")
    [ -n "$INSTALLATION_ID" ] && portal_args+=(-H "X-Installation-ID: ${INSTALLATION_ID}")
    if curl "${portal_args[@]}" "${PORTAL_API}/v1/releases/${version}/download" 2>/dev/null; then
        log_ok "Downloaded from portal"
        return 0
    fi

    log_error "Failed to download v${version} from any source."
    log_error "Tried: GitHub source archive, GitHub release, portal"
    [ -z "${GITHUB_TOKEN:-}" ] && log_warn "If the repo is private, set GITHUB_TOKEN=<your-token>"
    return 1
}

# ============================================================
# Update Functions
# ============================================================

# Update source files on disk (shared by docker_build and standalone)
update_source_files() {
    local install_dir="$1"
    local version="$2"
    local tmp_dir
    tmp_dir=$(mktemp -d)
    local archive="${tmp_dir}/sentrikat-${version}.tar.gz"

    log_info "Downloading SentriKat v${version}..."
    if ! download_release "$version" "$archive"; then
        rm -rf "$tmp_dir"
        exit 1
    fi

    # Extract
    log_info "Extracting..."
    tar xzf "$archive" -C "$tmp_dir"

    # Find extracted directory (handles GitHub SentriKat-x.y.z or release sentrikat-x.y.z)
    local extract_dir
    extract_dir=$(find "$tmp_dir" -maxdepth 1 -type d ! -path "$tmp_dir" | head -1)

    if [ -z "$extract_dir" ]; then
        log_error "Could not find extracted directory in archive"
        rm -rf "$tmp_dir"
        exit 1
    fi
    log_info "Extracted: $(basename "$extract_dir")"

    # Backup critical files
    local backup_dir="${install_dir}/backups/pre-update-$(date +%Y%m%d%H%M%S)"
    mkdir -p "$backup_dir"
    log_info "Creating backup in ${backup_dir}..."

    for item in app static templates VERSION .env docker-compose.yml Dockerfile; do
        if [ -e "${install_dir}/${item}" ]; then
            cp -r "${install_dir}/${item}" "${backup_dir}/"
        fi
    done
    log_ok "Backup created"

    # Replace source files (NEVER touch .env, docker-compose.yml, or data/)
    log_info "Updating application files..."
    for item in app static templates scripts tools agents docs nginx \
                Dockerfile docker-entrypoint.sh gunicorn.conf.py \
                requirements.txt VERSION README.md run.py; do
        if [ -e "${extract_dir}/${item}" ]; then
            rm -rf "${install_dir}/${item}"
            cp -r "${extract_dir}/${item}" "${install_dir}/${item}"
        fi
    done

    # Ensure VERSION is written
    echo "${version}" > "${install_dir}/VERSION"
    log_ok "Application files updated"

    # Make scripts executable
    chmod +x "${install_dir}/scripts/"*.sh 2>/dev/null || true

    rm -rf "$tmp_dir"
}

# --- Docker image update (customer deployment with pre-built GHCR image) ---
update_docker_image() {
    local install_dir="$1"
    local version="$2"

    log_info "Updating Docker image to v${version}..."

    # Update image tag in docker-compose.yml
    sed -i "s|ghcr.io/sbr0nch/sentrikat:[^ \"]*|ghcr.io/sbr0nch/sentrikat:${version}|g" "${install_dir}/docker-compose.yml"
    log_info "Updated image tag to ${version}"

    # Pull new image
    log_info "Pulling new Docker image..."
    cd "${install_dir}"
    if ! (docker compose pull 2>/dev/null || docker-compose pull); then
        log_error "Failed to pull Docker image ghcr.io/sbr0nch/sentrikat:${version}"
        log_error "The image may not exist yet, or GHCR packages may not be public."
        log_error "Check: https://github.com/${REPO}/pkgs/container/sentrikat"
        # Revert
        if [ -n "$CURRENT_VERSION" ] && [ "$CURRENT_VERSION" != "unknown" ]; then
            sed -i "s|ghcr.io/sbr0nch/sentrikat:[^ \"]*|ghcr.io/sbr0nch/sentrikat:${CURRENT_VERSION}|g" "${install_dir}/docker-compose.yml"
            log_warn "Reverted docker-compose.yml to v${CURRENT_VERSION}"
        fi
        exit 1
    fi
    log_ok "Docker image pulled"

    # Restart
    log_info "Restarting SentriKat..."
    docker compose up -d 2>/dev/null || docker-compose up -d
    log_ok "SentriKat restarted"

    echo "${version}" > "${install_dir}/VERSION"
}

# --- Docker build update (developer/self-hosted, builds from source) ---
update_docker_build() {
    local install_dir="$1"
    local version="$2"

    log_info "Updating Docker (build from source) to v${version}..."

    # Update source files first
    update_source_files "$install_dir" "$version"

    # Rebuild Docker image from updated source
    log_info "Rebuilding Docker image (this may take a few minutes)..."
    cd "${install_dir}"
    if ! (docker compose build 2>&1 || docker-compose build 2>&1); then
        log_error "Docker build failed. Check the output above for errors."
        log_warn "Source files were updated. Retry manually:"
        log_warn "  cd ${install_dir} && docker compose build && docker compose up -d"
        exit 1
    fi
    log_ok "Docker image rebuilt"

    # Restart
    log_info "Restarting SentriKat..."
    docker compose up -d 2>/dev/null || docker-compose up -d
    log_ok "SentriKat restarted"
}

# --- Standalone update (no Docker) ---
update_standalone() {
    local install_dir="$1"
    local version="$2"

    update_source_files "$install_dir" "$version"

    echo ""
    log_warn "Restart SentriKat for changes to take effect:"
    log_warn "  systemd:  sudo systemctl restart sentrikat"
    log_warn "  manual:   Restart your Python/Gunicorn process"
}

# ============================================================
# Main
# ============================================================

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
        echo "  (no args)      Update to the latest stable version"
        echo "  VERSION         Update to a specific version (e.g., 1.0.3 or 1.0.0-beta.1)"
        echo "  --check, -c    Check for updates without installing"
        echo "  --help, -h     Show this help message"
        echo ""
        echo "Environment:"
        echo "  SENTRIKAT_DIR   Override install directory detection"
        echo "  GITHUB_TOKEN    Auth token for private GitHub repos"
        echo ""
        exit 0
        ;;
    "")
        ;;
    *)
        TARGET_VERSION="${1#v}" # Strip leading 'v' if present
        ;;
esac

# Find installation
INSTALL_DIR=$(find_install_dir)
if [ -z "$INSTALL_DIR" ]; then
    log_error "Could not find SentriKat installation."
    log_error "Looked for SentriKat files (VERSION, app/licensing.py, docker-compose.yml, run.py)"
    log_error "in these locations (and their app/ subdirectories):"
    [ -n "${SENTRIKAT_DIR:-}" ] && log_error "  SENTRIKAT_DIR: ${SENTRIKAT_DIR}"
    log_error "  Script location: $(dirname "${BASH_SOURCE[0]:-$0}" 2>/dev/null || echo "unknown")"
    log_error "  Working directory: $(pwd) (walked up to /)"
    log_error "  Well-known paths: /opt/sentrikat, /app, /data/sentrikat"
    log_error ""
    log_error "Set SENTRIKAT_DIR=/path/to/sentrikat to override."
    exit 1
fi
INSTALL_DIR=$(cd "$INSTALL_DIR" && pwd)
log_info "Installation directory: ${INSTALL_DIR}"

# Detect deployment type
detect_deploy_type "$INSTALL_DIR"
log_info "Deployment type: ${DEPLOY_TYPE}"

# Load proxy settings
load_proxy_from_env
if [ -n "${HTTP_PROXY:-}" ] || [ -n "${HTTPS_PROXY:-}" ]; then
    log_info "Proxy: ${HTTPS_PROXY:-${HTTP_PROXY}}"
fi

# Load installation ID
load_installation_id
if [ -n "$INSTALLATION_ID" ]; then
    log_info "Installation ID: ${INSTALLATION_ID:0:20}..."
fi

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

# Execute update based on deployment type
case "$DEPLOY_TYPE" in
    docker_image)
        update_docker_image "$INSTALL_DIR" "$TARGET_VERSION"
        ;;
    docker_build)
        update_docker_build "$INSTALL_DIR" "$TARGET_VERSION"
        ;;
    standalone)
        update_standalone "$INSTALL_DIR" "$TARGET_VERSION"
        ;;
esac

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
