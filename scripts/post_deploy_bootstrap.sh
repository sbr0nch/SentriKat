#!/usr/bin/env bash
#
# SentriKat Post-Deploy Bootstrap
# ================================
#
# Idempotent operational setup for a fresh SentriKat on-prem deployment.
# Run ONCE after `docker compose up -d` and the first-run setup wizard.
#
# What it does (in order):
#   1. Verify NVD_API_KEY is configured in system_settings (fail fast if not)
#   2. Run apply_cpe_to_product on all existing products via batch_apply_cpe_mappings
#      with NVD Tier 4 fallback enabled
#   3. Loop fetch_cpe_version_data until no more CVEs lack cpe_data, with
#      progress checkpoints — typically 30-60 minutes with NVD API key,
#      6-8 hours without one
#   4. Print final status: % products with CPE, % CVEs with cpe_data, total matches
#
# Idempotent: safe to re-run. Skips work already done. Resumes from where the
# previous run left off if interrupted.
#
# Usage:
#   ./scripts/post_deploy_bootstrap.sh [--nvd-key <key>] [--no-cpe-backfill]
#
# Environment variables (alternative to flags):
#   NVD_API_KEY       — overrides DB value if set
#   SENTRIKAT_CONTAINER — container name (default: sentrikat)
#   DB_CONTAINER      — postgres container name (default: sentrikat-db)
#   DB_PASSWORD       — postgres password (read from .env if not set)
#
# Exit codes:
#   0 — success, system ready
#   1 — fatal error (containers down, DB unreachable, missing config)
#   2 — NVD API key invalid or rate-limit exhausted; bootstrap incomplete
#       but recoverable (re-run later)

set -euo pipefail

# ---------------------------------------------------------------------------
# Defaults & arg parsing
# ---------------------------------------------------------------------------
SENTRIKAT_CONTAINER="${SENTRIKAT_CONTAINER:-sentrikat}"
DB_CONTAINER="${DB_CONTAINER:-sentrikat-db}"
DB_USER="${DB_USER:-sentrikat}"
DB_NAME="${DB_NAME:-sentrikat}"
NVD_KEY_OVERRIDE=""
SKIP_CPE_BACKFILL=0
LOOP_SLEEP_SECONDS=2

while [[ $# -gt 0 ]]; do
    case "$1" in
        --nvd-key)
            NVD_KEY_OVERRIDE="$2"; shift 2 ;;
        --no-cpe-backfill)
            SKIP_CPE_BACKFILL=1; shift ;;
        -h|--help)
            sed -n '2,30p' "$0"; exit 0 ;;
        *)
            echo "Unknown arg: $1. Use --help." >&2; exit 1 ;;
    esac
done

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
log()  { printf '\033[36m[bootstrap]\033[0m %s\n' "$*"; }
ok()   { printf '\033[32m[ok]\033[0m %s\n' "$*"; }
warn() { printf '\033[33m[warn]\033[0m %s\n' "$*" >&2; }
fail() { printf '\033[31m[fail]\033[0m %s\n' "$*" >&2; exit 1; }

run_in_app() {
    docker exec -i "$SENTRIKAT_CONTAINER" python -c "$1"
}

run_in_db() {
    if [[ -z "${DB_PASSWORD:-}" ]] && [[ -f .env ]]; then
        DB_PASSWORD="$(grep -E '^POSTGRES_PASSWORD=' .env | cut -d= -f2- | tr -d '"')"
    fi
    docker exec -e PGPASSWORD="${DB_PASSWORD:-}" "$DB_CONTAINER" \
        psql -U "$DB_USER" -d "$DB_NAME" -tAq -c "$1"
}

# ---------------------------------------------------------------------------
# Step 0: pre-flight
# ---------------------------------------------------------------------------
log "Pre-flight: verifying containers + DB reachable"

docker inspect "$SENTRIKAT_CONTAINER" >/dev/null 2>&1 \
    || fail "Container '$SENTRIKAT_CONTAINER' not found. Is 'docker compose up' running?"
docker inspect "$DB_CONTAINER" >/dev/null 2>&1 \
    || fail "Container '$DB_CONTAINER' not found."

run_in_db "SELECT 1;" >/dev/null \
    || fail "Cannot connect to Postgres in '$DB_CONTAINER'. Check DB_PASSWORD env var or .env file."

ok "Containers up and DB reachable"

# ---------------------------------------------------------------------------
# Step 1: NVD API key in system_settings
# ---------------------------------------------------------------------------
log "Step 1/4: ensuring NVD_API_KEY in system_settings"

current_key="$(run_in_db "SELECT value FROM system_settings WHERE key='nvd_api_key' AND organization_id IS NULL LIMIT 1;" || true)"
current_key="$(echo "$current_key" | tr -d '[:space:]')"

if [[ -n "$NVD_KEY_OVERRIDE" ]]; then
    log "  Overriding NVD key from --nvd-key flag"
    run_in_db "DELETE FROM system_settings WHERE key='nvd_api_key' AND organization_id IS NULL;" >/dev/null
    run_in_db "INSERT INTO system_settings(key,value,category) VALUES ('nvd_api_key','$NVD_KEY_OVERRIDE','sync');" >/dev/null
    ok "  NVD key written to system_settings"
elif [[ -n "${NVD_API_KEY:-}" ]] && [[ -z "$current_key" ]]; then
    log "  Importing NVD key from \$NVD_API_KEY env var"
    run_in_db "INSERT INTO system_settings(key,value,category) VALUES ('nvd_api_key','$NVD_API_KEY','sync');" >/dev/null
    ok "  NVD key written from env"
elif [[ -n "$current_key" ]]; then
    masked="${current_key:0:4}...${current_key: -4}"
    ok "  NVD key already set ($masked)"
else
    warn "  No NVD API key configured. Bootstrap will proceed but CPE backfill will run at 10 req/min instead of 50."
    warn "  To fix: rerun with --nvd-key <YOUR_KEY> or set NVD_API_KEY env var."
fi

# ---------------------------------------------------------------------------
# Step 2: batch_apply_cpe_mappings (Tiers 1+2+3 + NVD Tier 4)
# ---------------------------------------------------------------------------
log "Step 2/4: batch_apply_cpe_mappings (Tiers 1+2+3+NVD Tier 4 for unmatched)"

before="$(run_in_db "SELECT COUNT(*) FROM products WHERE cpe_vendor IS NULL OR cpe_vendor = '';")"
log "  Products without CPE before: ${before:-?}"

run_in_app "
from app import create_app
app = create_app()
with app.app_context():
    from app.cpe_mapping import batch_apply_cpe_mappings
    updated, total = batch_apply_cpe_mappings(commit=True, use_nvd=True)
    print(f'  -> updated={updated} of {total} products without CPE')
" || warn "  batch_apply_cpe_mappings exited non-zero (NVD rate-limit?)"

after="$(run_in_db "SELECT COUNT(*) FROM products WHERE cpe_vendor IS NULL OR cpe_vendor = '';")"
ok "  Products without CPE after: ${after:-?} (was ${before:-?})"

# ---------------------------------------------------------------------------
# Step 3: CPE backfill loop — fetch_cpe_version_data until total reaches 0
# ---------------------------------------------------------------------------
if [[ "$SKIP_CPE_BACKFILL" -eq 1 ]]; then
    warn "Step 3/4: SKIPPED (--no-cpe-backfill)"
else
    log "Step 3/4: CPE backfill loop"
    log "  Will fetch cpe_data for vulnerabilities lacking it. Loops in batches"
    log "  of 30 CVEs until none remain. Expected duration: 30-60 min with NVD"
    log "  key, 6-8 hours without one. Press Ctrl-C to stop and resume later."

    iteration=0
    consecutive_zero=0
    while true; do
        iteration=$((iteration + 1))
        enriched="$(run_in_app "
from app import create_app
app = create_app()
with app.app_context():
    from app.cisa_sync import fetch_cpe_version_data
    n = fetch_cpe_version_data(limit=30, oldest_first=True, skip_awaiting=True)
    print(n)
" 2>/dev/null | tail -1)"

        # Strip whitespace and validate it's an integer
        enriched="${enriched//[!0-9]/}"
        enriched="${enriched:-0}"

        remaining="$(run_in_db "SELECT COUNT(*) FROM vulnerabilities WHERE cpe_data IS NULL AND (cpe_fetched_at IS NULL OR nvd_status NOT IN ('Awaiting Analysis', 'Received', 'Undergoing Analysis'));" || echo "?")"

        log "  iter=$iteration  enriched=$enriched  remaining=$remaining"

        if [[ "$enriched" -eq 0 ]]; then
            consecutive_zero=$((consecutive_zero + 1))
            if [[ "$consecutive_zero" -ge 3 ]]; then
                ok "  CPE backfill converged (3 consecutive zero-enrich iterations)"
                break
            fi
        else
            consecutive_zero=0
        fi

        sleep "$LOOP_SLEEP_SECONDS"
    done
fi

# ---------------------------------------------------------------------------
# Step 4: final status
# ---------------------------------------------------------------------------
log "Step 4/4: final status snapshot"

total_products="$(run_in_db "SELECT COUNT(*) FROM products WHERE active=true;")"
products_with_cpe="$(run_in_db "SELECT COUNT(*) FROM products WHERE active=true AND cpe_vendor IS NOT NULL AND cpe_vendor != '';")"
total_cves="$(run_in_db "SELECT COUNT(*) FROM vulnerabilities;")"
cves_with_cpe="$(run_in_db "SELECT COUNT(*) FROM vulnerabilities WHERE cpe_data IS NOT NULL;")"
total_matches="$(run_in_db "SELECT COUNT(*) FROM vulnerability_matches;")"
high_conf_matches="$(run_in_db "SELECT COUNT(*) FROM vulnerability_matches WHERE match_confidence='high';")"

cat <<EOF

╔══════════════════════════════════════════════════════════════╗
║              SentriKat Post-Deploy Status                    ║
╠══════════════════════════════════════════════════════════════╣
║  Active products:         $(printf '%-30s' "$total_products") ║
║    └─ with CPE assigned:  $(printf '%-30s' "$products_with_cpe") ║
║  Total CVEs:              $(printf '%-30s' "$total_cves") ║
║    └─ with cpe_data:      $(printf '%-30s' "$cves_with_cpe") ║
║  Total matches:           $(printf '%-30s' "$total_matches") ║
║    └─ confidence=high:    $(printf '%-30s' "$high_conf_matches") ║
╚══════════════════════════════════════════════════════════════╝

EOF

# Sanity warning if coverage is poor
if [[ "${total_products:-0}" -gt 0 ]]; then
    coverage_pct=$(( products_with_cpe * 100 / total_products ))
    if [[ "$coverage_pct" -lt 60 ]]; then
        warn "Product CPE coverage is ${coverage_pct}%. Below 60% suggests Tier 1-3 didn't"
        warn "match many products. Likely causes: niche/internal software not in NVD CPE"
        warn "dictionary, or names too generic to disambiguate. Manual CPE assignment via"
        warn "/admin/products may be needed for the uncovered set."
    else
        ok "Product CPE coverage: ${coverage_pct}% — healthy"
    fi
fi

ok "Bootstrap complete. SentriKat is ready for first-use."
