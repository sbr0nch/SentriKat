#!/bin/bash
# ============================================================================
# SentriKat Full System Audit Script
# ============================================================================
# Tests ALL core business functionality before go-live.
# Run on the SentriKat server VM where docker compose is running.
#
# Usage:
#   chmod +x tools/full_audit.sh
#   sudo bash tools/full_audit.sh
#
# Output saved to: /tmp/sentrikat-audit-report.txt
# ============================================================================

set -o pipefail

REPORT="/tmp/sentrikat-audit-report.txt"
BASE_URL="https://localhost"
CURL_OPTS="-sk --connect-timeout 10 --max-time 30"
PASS=0
FAIL=0
WARN=0

# Colors for terminal
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m'

# Start report
{
echo "============================================================================"
echo "  SentriKat Full System Audit Report"
echo "  Generated: $(date -u '+%Y-%m-%d %H:%M:%S UTC')"
echo "  Server: $(hostname)"
echo "============================================================================"
echo ""
} > "$REPORT"

log() {
    echo "$1" | tee -a "$REPORT"
}

section() {
    echo "" | tee -a "$REPORT"
    echo "============================================================================" | tee -a "$REPORT"
    echo "  $1" | tee -a "$REPORT"
    echo "============================================================================" | tee -a "$REPORT"
}

pass() {
    PASS=$((PASS + 1))
    echo -e "  ${GREEN}[PASS]${NC} $1" | tee -a "$REPORT"
}

fail() {
    FAIL=$((FAIL + 1))
    echo -e "  ${RED}[FAIL]${NC} $1" | tee -a "$REPORT"
}

warn() {
    WARN=$((WARN + 1))
    echo -e "  ${YELLOW}[WARN]${NC} $1" | tee -a "$REPORT"
}

info() {
    echo -e "  ${CYAN}[INFO]${NC} $1" | tee -a "$REPORT"
}

# ============================================================================
# 1. DOCKER SERVICES
# ============================================================================
section "1. Docker Services Health"

# Check docker is running
if command -v docker &>/dev/null; then
    pass "Docker is installed"
else
    fail "Docker not found"
fi

# Check all containers
for SVC in sentrikat sentrikat-db sentrikat-nginx; do
    STATUS=$(docker inspect --format='{{.State.Status}}' "$SVC" 2>/dev/null)
    HEALTH=$(docker inspect --format='{{.State.Health.Status}}' "$SVC" 2>/dev/null)
    if [ "$STATUS" = "running" ]; then
        if [ "$HEALTH" = "healthy" ]; then
            pass "$SVC: running + healthy"
        elif [ "$HEALTH" = "starting" ]; then
            warn "$SVC: running but health check still starting"
        elif [ -z "$HEALTH" ] || [ "$HEALTH" = "<no value>" ]; then
            pass "$SVC: running (no healthcheck configured)"
        else
            warn "$SVC: running but health=$HEALTH"
        fi
    else
        fail "$SVC: status=$STATUS (expected: running)"
    fi
done

# Container resource usage
log ""
log "  Container resource usage:"
docker stats --no-stream --format "    {{.Name}}: CPU={{.CPUPerc}} MEM={{.MemUsage}}" 2>/dev/null | tee -a "$REPORT"

# Check container restart counts
for SVC in sentrikat sentrikat-db sentrikat-nginx; do
    RESTARTS=$(docker inspect --format='{{.RestartCount}}' "$SVC" 2>/dev/null)
    if [ "$RESTARTS" -gt 0 ] 2>/dev/null; then
        warn "$SVC has restarted $RESTARTS times"
    fi
done

# ============================================================================
# 2. DATABASE CONNECTIVITY
# ============================================================================
section "2. Database Connectivity & Schema"

# Test DB connection from inside container
DB_CHECK=$(docker exec sentrikat-db pg_isready -U sentrikat 2>&1)
if echo "$DB_CHECK" | grep -q "accepting connections"; then
    pass "PostgreSQL accepting connections"
else
    fail "PostgreSQL not ready: $DB_CHECK"
fi

# Check DB version
DB_VERSION=$(docker exec sentrikat-db psql -U sentrikat -d sentrikat -t -c "SELECT version();" 2>&1 | head -1 | xargs)
info "PostgreSQL version: $DB_VERSION"

# Check critical tables exist
log ""
log "  Table row counts:"
for TABLE in products vulnerabilities vulnerability_matches assets product_installations \
             agent_api_keys organizations users sync_logs vendor_fix_overrides \
             service_catalog scheduled_reports agent_events inventory_jobs \
             cpe_dictionary_entries vulnerability_snapshots stale_asset_notifications; do
    COUNT=$(docker exec sentrikat-db psql -U sentrikat -d sentrikat -t -c \
        "SELECT COUNT(*) FROM $TABLE;" 2>&1 | xargs)
    if [[ "$COUNT" =~ ^[0-9]+$ ]]; then
        info "$TABLE: $COUNT rows"
    else
        fail "Table $TABLE missing or error: $COUNT"
    fi
done

# Check critical columns that agent inventory needs
log ""
log "  Schema checks (agent-required columns):"
for COL_CHECK in \
    "products:source" \
    "products:last_agent_report" \
    "products:auto_disabled" \
    "products:approval_status" \
    "assets:installed_kbs" \
    "assets:pending_scan" \
    "assets:scan_interval_override" \
    "product_installations:distro_package_version" \
    "product_installations:detected_on_os" \
    "vulnerabilities:epss_score" \
    "vulnerabilities:epss_percentile" \
    "agent_api_keys:auto_approve" \
    "vendor_fix_overrides:fix_type" \
    "vendor_fix_overrides:confidence"; do
    TABLE=$(echo "$COL_CHECK" | cut -d: -f1)
    COL=$(echo "$COL_CHECK" | cut -d: -f2)
    EXISTS=$(docker exec sentrikat-db psql -U sentrikat -d sentrikat -t -c \
        "SELECT column_name FROM information_schema.columns WHERE table_name='$TABLE' AND column_name='$COL';" 2>&1 | xargs)
    if [ "$EXISTS" = "$COL" ]; then
        pass "Column $TABLE.$COL exists"
    else
        fail "MISSING column $TABLE.$COL - agent inventory will fail!"
    fi
done

# Check DB size
DB_SIZE=$(docker exec sentrikat-db psql -U sentrikat -d sentrikat -t -c \
    "SELECT pg_size_pretty(pg_database_size('sentrikat'));" 2>&1 | xargs)
info "Database size: $DB_SIZE"

# ============================================================================
# 3. API HEALTH ENDPOINTS
# ============================================================================
section "3. API Health & Core Endpoints"

# Health check
HEALTH_RESP=$(curl $CURL_OPTS "$BASE_URL/api/health" 2>&1)
HEALTH_CODE=$(curl $CURL_OPTS -o /dev/null -w "%{http_code}" "$BASE_URL/api/health" 2>&1)
if [ "$HEALTH_CODE" = "200" ]; then
    pass "/api/health -> 200 OK"
    DB_STATUS=$(echo "$HEALTH_RESP" | python3 -c "import sys,json; print(json.load(sys.stdin).get('checks',{}).get('database','unknown'))" 2>/dev/null)
    info "Database check: $DB_STATUS"
else
    fail "/api/health -> HTTP $HEALTH_CODE"
fi

# Version check
VERSION_RESP=$(curl $CURL_OPTS "$BASE_URL/api/version" 2>&1)
VERSION_CODE=$(curl $CURL_OPTS -o /dev/null -w "%{http_code}" "$BASE_URL/api/version" 2>&1)
if [ "$VERSION_CODE" = "200" ]; then
    APP_VERSION=$(echo "$VERSION_RESP" | python3 -c "import sys,json; print(json.load(sys.stdin).get('version','unknown'))" 2>/dev/null)
    pass "/api/version -> $APP_VERSION"
else
    fail "/api/version -> HTTP $VERSION_CODE"
fi

# Sync status
SYNC_CODE=$(curl $CURL_OPTS -o /dev/null -w "%{http_code}" "$BASE_URL/api/sync/status" 2>&1)
if [ "$SYNC_CODE" = "200" ]; then
    pass "/api/sync/status -> 200 OK"
else
    warn "/api/sync/status -> HTTP $SYNC_CODE (may need auth)"
fi

# System health (detailed)
SYSHEALTH_RESP=$(curl $CURL_OPTS "$BASE_URL/api/system/health" 2>&1)
SYSHEALTH_CODE=$(curl $CURL_OPTS -o /dev/null -w "%{http_code}" "$BASE_URL/api/system/health" 2>&1)
if [ "$SYSHEALTH_CODE" = "200" ]; then
    pass "/api/system/health -> 200 OK"
else
    warn "/api/system/health -> HTTP $SYSHEALTH_CODE (may need auth)"
fi

# ============================================================================
# 4. EXTERNAL API CONNECTIVITY
# ============================================================================
section "4. External API Connectivity"

# Test CISA KEV
CISA_CODE=$(curl -sk --connect-timeout 15 --max-time 30 -o /dev/null -w "%{http_code}" \
    "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json" 2>&1)
if [ "$CISA_CODE" = "200" ]; then
    pass "CISA KEV feed: reachable (HTTP $CISA_CODE)"
else
    fail "CISA KEV feed: HTTP $CISA_CODE (sync will fail!)"
fi

# Test NVD API
NVD_CODE=$(curl -sk --connect-timeout 15 --max-time 30 -o /dev/null -w "%{http_code}" \
    "https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=CVE-2024-0001" 2>&1)
if [ "$NVD_CODE" = "200" ]; then
    pass "NVD CVE API: reachable (HTTP $NVD_CODE)"
elif [ "$NVD_CODE" = "403" ]; then
    warn "NVD CVE API: rate limited (HTTP 403) - needs API key for production"
else
    fail "NVD CVE API: HTTP $NVD_CODE"
fi

# Test NVD CPE API
NVD_CPE_CODE=$(curl -sk --connect-timeout 15 --max-time 30 -o /dev/null -w "%{http_code}" \
    "https://services.nvd.nist.gov/rest/json/cpes/2.0?cpeMatchString=cpe:2.3:a:apache:http_server" 2>&1)
if [ "$NVD_CPE_CODE" = "200" ]; then
    pass "NVD CPE API: reachable (HTTP $NVD_CPE_CODE)"
elif [ "$NVD_CPE_CODE" = "403" ]; then
    warn "NVD CPE API: rate limited (HTTP 403)"
else
    fail "NVD CPE API: HTTP $NVD_CPE_CODE"
fi

# Test EPSS API
EPSS_CODE=$(curl -sk --connect-timeout 15 --max-time 30 -o /dev/null -w "%{http_code}" \
    "https://api.first.org/data/v1/epss?cve=CVE-2024-0001" 2>&1)
if [ "$EPSS_CODE" = "200" ]; then
    pass "EPSS API (FIRST.org): reachable (HTTP $EPSS_CODE)"
else
    fail "EPSS API: HTTP $EPSS_CODE (EPSS scoring will fail)"
fi

# Test License Server
LICENSE_CODE=$(curl -sk --connect-timeout 15 --max-time 30 -o /dev/null -w "%{http_code}" \
    "https://portal.sentrikat.com/api" 2>&1)
if [ "$LICENSE_CODE" = "200" ] || [ "$LICENSE_CODE" = "404" ] || [ "$LICENSE_CODE" = "301" ] || [ "$LICENSE_CODE" = "302" ]; then
    pass "License server (portal.sentrikat.com): reachable (HTTP $LICENSE_CODE)"
else
    warn "License server: HTTP $LICENSE_CODE (license activation/heartbeat may fail)"
fi

# Test OSV API (vendor advisories)
OSV_CODE=$(curl -sk --connect-timeout 15 --max-time 30 -o /dev/null -w "%{http_code}" \
    "https://api.osv.dev/v1/vulns/CVE-2024-0001" 2>&1)
if [ "$OSV_CODE" = "200" ] || [ "$OSV_CODE" = "404" ]; then
    pass "OSV API (vendor advisories): reachable (HTTP $OSV_CODE)"
else
    fail "OSV API: HTTP $OSV_CODE"
fi

# Test from INSIDE the container (proxy/DNS issues)
log ""
log "  Testing connectivity from inside sentrikat container:"
CONTAINER_CISA=$(docker exec sentrikat curl -sk --connect-timeout 10 --max-time 20 -o /dev/null -w "%{http_code}" \
    "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json" 2>&1)
if [ "$CONTAINER_CISA" = "200" ]; then
    pass "Container -> CISA KEV: reachable"
else
    fail "Container -> CISA KEV: HTTP $CONTAINER_CISA (check HTTP_PROXY/NO_PROXY settings!)"
fi

CONTAINER_NVD=$(docker exec sentrikat curl -sk --connect-timeout 10 --max-time 20 -o /dev/null -w "%{http_code}" \
    "https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=CVE-2024-0001" 2>&1)
if [ "$CONTAINER_NVD" = "200" ]; then
    pass "Container -> NVD API: reachable"
elif [ "$CONTAINER_NVD" = "403" ]; then
    warn "Container -> NVD API: rate limited (HTTP 403)"
else
    fail "Container -> NVD API: HTTP $CONTAINER_NVD (check proxy settings!)"
fi

CONTAINER_EPSS=$(docker exec sentrikat curl -sk --connect-timeout 10 --max-time 20 -o /dev/null -w "%{http_code}" \
    "https://api.first.org/data/v1/epss?cve=CVE-2024-0001" 2>&1)
if [ "$CONTAINER_EPSS" = "200" ]; then
    pass "Container -> EPSS API: reachable"
else
    fail "Container -> EPSS API: HTTP $CONTAINER_EPSS"
fi

# ============================================================================
# 5. SSL/TLS CONFIGURATION
# ============================================================================
section "5. SSL/TLS & Nginx Configuration"

# Check SSL cert
SSL_INFO=$(echo | openssl s_client -connect localhost:443 -servername localhost 2>/dev/null | openssl x509 -noout -subject -dates -issuer 2>/dev/null)
if [ -n "$SSL_INFO" ]; then
    pass "SSL certificate present"
    echo "$SSL_INFO" | while IFS= read -r line; do
        info "$line"
    done
else
    warn "Could not read SSL certificate info"
fi

# Check HTTPS redirect
HTTP_REDIRECT=$(curl -sk -o /dev/null -w "%{http_code}" "http://localhost/api/health" 2>&1)
if [ "$HTTP_REDIRECT" = "301" ] || [ "$HTTP_REDIRECT" = "302" ]; then
    pass "HTTP->HTTPS redirect active (HTTP $HTTP_REDIRECT)"
elif [ "$HTTP_REDIRECT" = "200" ]; then
    info "HTTP serves directly (no HTTPS redirect) - OK if intentional"
else
    warn "HTTP response: $HTTP_REDIRECT"
fi

# Check security headers
log ""
log "  Security headers:"
HEADERS=$(curl $CURL_OPTS -I "$BASE_URL/api/health" 2>&1)
for HEADER in "x-frame-options" "x-content-type-options" "strict-transport-security" \
              "content-security-policy" "referrer-policy" "x-xss-protection"; do
    if echo "$HEADERS" | grep -qi "$HEADER"; then
        VALUE=$(echo "$HEADERS" | grep -i "$HEADER" | head -1 | cut -d: -f2- | xargs)
        pass "Header $HEADER: $VALUE"
    else
        warn "Missing header: $HEADER"
    fi
done

# Nginx version
NGINX_VER=$(echo "$HEADERS" | grep -i "^server:" | head -1 | xargs)
info "Server: $NGINX_VER"

# ============================================================================
# 6. LICENSE STATUS
# ============================================================================
section "6. License Status"

LICENSE_RESP=$(curl $CURL_OPTS "$BASE_URL/api/license" 2>&1)
LICENSE_CODE=$(curl $CURL_OPTS -o /dev/null -w "%{http_code}" "$BASE_URL/api/license" 2>&1)
if [ "$LICENSE_CODE" = "200" ]; then
    EDITION=$(echo "$LICENSE_RESP" | python3 -c "import sys,json; d=json.load(sys.stdin); print(d.get('edition','unknown'))" 2>/dev/null)
    CUSTOMER=$(echo "$LICENSE_RESP" | python3 -c "import sys,json; d=json.load(sys.stdin); print(d.get('customer','unknown'))" 2>/dev/null)
    EXPIRY=$(echo "$LICENSE_RESP" | python3 -c "import sys,json; d=json.load(sys.stdin); print(d.get('expiration_date','unknown'))" 2>/dev/null)
    MAX_AGENTS=$(echo "$LICENSE_RESP" | python3 -c "import sys,json; d=json.load(sys.stdin); print(d.get('max_agents','unknown'))" 2>/dev/null)
    VALID=$(echo "$LICENSE_RESP" | python3 -c "import sys,json; d=json.load(sys.stdin); print(d.get('valid', False))" 2>/dev/null)

    if [ "$VALID" = "True" ]; then
        pass "License valid: $EDITION edition"
    else
        fail "License INVALID"
    fi
    info "Customer: $CUSTOMER"
    info "Expiration: $EXPIRY"
    info "Max agents: $MAX_AGENTS"
else
    warn "License endpoint: HTTP $LICENSE_CODE (may need auth or no license installed)"
fi

# Installation ID
INST_ID_RESP=$(curl $CURL_OPTS "$BASE_URL/api/license/installation-id" 2>&1)
INST_ID=$(echo "$INST_ID_RESP" | python3 -c "import sys,json; print(json.load(sys.stdin).get('installation_id','unknown'))" 2>/dev/null)
if [ -n "$INST_ID" ] && [ "$INST_ID" != "unknown" ]; then
    info "Installation ID: $INST_ID"
else
    warn "Could not retrieve installation ID"
fi

# ============================================================================
# 7. DATA QUALITY - VULNERABILITIES
# ============================================================================
section "7. Vulnerability Data Quality"

# Total CVEs
TOTAL_CVES=$(docker exec sentrikat-db psql -U sentrikat -d sentrikat -t -c \
    "SELECT COUNT(*) FROM vulnerabilities;" 2>&1 | xargs)
info "Total CVEs in database: $TOTAL_CVES"

if [ "$TOTAL_CVES" -gt 0 ] 2>/dev/null; then
    pass "Vulnerability database has data"

    # Severity distribution
    log ""
    log "  Severity distribution:"
    docker exec sentrikat-db psql -U sentrikat -d sentrikat -t -c \
        "SELECT severity, COUNT(*) as cnt FROM vulnerabilities GROUP BY severity ORDER BY cnt DESC;" 2>&1 | \
        while IFS= read -r line; do
            [ -n "$line" ] && info "  $line"
        done

    # CVSS coverage
    CVSS_MISSING=$(docker exec sentrikat-db psql -U sentrikat -d sentrikat -t -c \
        "SELECT COUNT(*) FROM vulnerabilities WHERE cvss_score IS NULL OR cvss_score = 0;" 2>&1 | xargs)
    CVSS_PCT=$(echo "scale=1; ($TOTAL_CVES - $CVSS_MISSING) * 100 / $TOTAL_CVES" | bc 2>/dev/null || echo "?")
    if [ "$CVSS_MISSING" -gt 0 ] 2>/dev/null; then
        warn "CVEs missing CVSS scores: $CVSS_MISSING / $TOTAL_CVES ($CVSS_PCT% coverage)"
    else
        pass "All CVEs have CVSS scores"
    fi

    # EPSS coverage
    EPSS_MISSING=$(docker exec sentrikat-db psql -U sentrikat -d sentrikat -t -c \
        "SELECT COUNT(*) FROM vulnerabilities WHERE epss_score IS NULL;" 2>&1 | xargs)
    if [[ "$EPSS_MISSING" =~ ^[0-9]+$ ]] && [ "$EPSS_MISSING" -gt 0 ]; then
        EPSS_PCT=$(echo "scale=1; ($TOTAL_CVES - $EPSS_MISSING) * 100 / $TOTAL_CVES" | bc 2>/dev/null || echo "?")
        warn "CVEs missing EPSS scores: $EPSS_MISSING / $TOTAL_CVES ($EPSS_PCT% coverage)"
    else
        pass "EPSS scores present"
    fi

    # CISA KEV flagged
    KEV_COUNT=$(docker exec sentrikat-db psql -U sentrikat -d sentrikat -t -c \
        "SELECT COUNT(*) FROM vulnerabilities WHERE is_known_exploited = true;" 2>&1 | xargs)
    info "CISA KEV (actively exploited): $KEV_COUNT CVEs"

    # Last sync
    LAST_SYNC=$(docker exec sentrikat-db psql -U sentrikat -d sentrikat -t -c \
        "SELECT sync_date, sync_type, new_count, total_count FROM sync_logs ORDER BY sync_date DESC LIMIT 1;" 2>&1 | xargs)
    info "Last sync: $LAST_SYNC"
else
    fail "Vulnerability database is EMPTY - run a sync first!"
fi

# ============================================================================
# 8. DATA QUALITY - PRODUCTS & MATCHING
# ============================================================================
section "8. Products & CVE Matching Quality"

TOTAL_PRODUCTS=$(docker exec sentrikat-db psql -U sentrikat -d sentrikat -t -c \
    "SELECT COUNT(*) FROM products WHERE active = true;" 2>&1 | xargs)
info "Active products: $TOTAL_PRODUCTS"

TOTAL_MATCHES=$(docker exec sentrikat-db psql -U sentrikat -d sentrikat -t -c \
    "SELECT COUNT(*) FROM vulnerability_matches;" 2>&1 | xargs)
info "Total CVE matches: $TOTAL_MATCHES"

if [ "$TOTAL_MATCHES" -gt 0 ] 2>/dev/null; then
    # Match method distribution
    log ""
    log "  Match method distribution:"
    docker exec sentrikat-db psql -U sentrikat -d sentrikat -t -c \
        "SELECT match_method, match_confidence, COUNT(*) as cnt FROM vulnerability_matches GROUP BY match_method, match_confidence ORDER BY cnt DESC;" 2>&1 | \
        while IFS= read -r line; do
            [ -n "$line" ] && info "  $line"
        done

    # Acknowledged vs unacknowledged
    ACK_COUNT=$(docker exec sentrikat-db psql -U sentrikat -d sentrikat -t -c \
        "SELECT COUNT(*) FROM vulnerability_matches WHERE acknowledged = true;" 2>&1 | xargs)
    UNACK_COUNT=$(docker exec sentrikat-db psql -U sentrikat -d sentrikat -t -c \
        "SELECT COUNT(*) FROM vulnerability_matches WHERE acknowledged = false;" 2>&1 | xargs)
    info "Acknowledged matches: $ACK_COUNT"
    info "Unacknowledged matches: $UNACK_COUNT"
fi

# CPE coverage
CPE_PRODUCTS=$(docker exec sentrikat-db psql -U sentrikat -d sentrikat -t -c \
    "SELECT COUNT(*) FROM products WHERE active = true AND cpe_vendor IS NOT NULL AND cpe_vendor != '' AND cpe_vendor != '_skip';" 2>&1 | xargs)
SKIP_PRODUCTS=$(docker exec sentrikat-db psql -U sentrikat -d sentrikat -t -c \
    "SELECT COUNT(*) FROM products WHERE active = true AND (cpe_vendor = '_skip' OR cpe_product = '_not_security_relevant');" 2>&1 | xargs)
NO_CPE=$(docker exec sentrikat-db psql -U sentrikat -d sentrikat -t -c \
    "SELECT COUNT(*) FROM products WHERE active = true AND (cpe_vendor IS NULL OR cpe_vendor = '') AND (cpe_product IS NULL OR cpe_product = '');" 2>&1 | xargs)
info "Products with CPE mapping: $CPE_PRODUCTS"
info "Products marked as skip/noise: $SKIP_PRODUCTS"
info "Products without any CPE: $NO_CPE"

# Vendor fix overrides
VFO_COUNT=$(docker exec sentrikat-db psql -U sentrikat -d sentrikat -t -c \
    "SELECT COUNT(*) FROM vendor_fix_overrides;" 2>&1 | xargs)
info "Vendor fix overrides: $VFO_COUNT"

# ============================================================================
# 9. AGENT SYSTEM
# ============================================================================
section "9. Agent System"

# Agent API keys
AGENT_KEYS=$(docker exec sentrikat-db psql -U sentrikat -d sentrikat -t -c \
    "SELECT COUNT(*) FROM agent_api_keys WHERE revoked = false;" 2>&1 | xargs)
info "Active agent API keys: $AGENT_KEYS"

# Assets/Endpoints
TOTAL_ASSETS=$(docker exec sentrikat-db psql -U sentrikat -d sentrikat -t -c \
    "SELECT COUNT(*) FROM assets;" 2>&1 | xargs)
ONLINE_ASSETS=$(docker exec sentrikat-db psql -U sentrikat -d sentrikat -t -c \
    "SELECT COUNT(*) FROM assets WHERE status = 'online';" 2>&1 | xargs)
STALE_ASSETS=$(docker exec sentrikat-db psql -U sentrikat -d sentrikat -t -c \
    "SELECT COUNT(*) FROM assets WHERE last_checkin < NOW() - INTERVAL '24 hours';" 2>&1 | xargs)
info "Total endpoints: $TOTAL_ASSETS"
info "Online endpoints: $ONLINE_ASSETS"
if [ "$STALE_ASSETS" -gt 0 ] 2>/dev/null; then
    warn "Stale endpoints (no checkin >24h): $STALE_ASSETS"
fi

# Product installations
TOTAL_INSTALLS=$(docker exec sentrikat-db psql -U sentrikat -d sentrikat -t -c \
    "SELECT COUNT(*) FROM product_installations;" 2>&1 | xargs)
info "Total product installations: $TOTAL_INSTALLS"

# Agent events (recent)
RECENT_EVENTS=$(docker exec sentrikat-db psql -U sentrikat -d sentrikat -t -c \
    "SELECT event_type, COUNT(*) FROM agent_events WHERE created_at > NOW() - INTERVAL '24 hours' GROUP BY event_type;" 2>&1 | xargs)
info "Agent events (last 24h): $RECENT_EVENTS"

# Test agent inventory endpoint (without key - should get 401)
AGENT_INV_CODE=$(curl $CURL_OPTS -o /dev/null -w "%{http_code}" \
    -X POST "$BASE_URL/api/agent/inventory" \
    -H "Content-Type: application/json" \
    -d '{"hostname":"audit-test"}' 2>&1)
if [ "$AGENT_INV_CODE" = "401" ] || [ "$AGENT_INV_CODE" = "403" ]; then
    pass "Agent inventory endpoint rejects unauthenticated requests (HTTP $AGENT_INV_CODE)"
else
    fail "Agent inventory endpoint: unexpected HTTP $AGENT_INV_CODE (expected 401/403)"
fi

# Test agent heartbeat endpoint (without key - should get 401)
AGENT_HB_CODE=$(curl $CURL_OPTS -o /dev/null -w "%{http_code}" \
    -X POST "$BASE_URL/api/agent/heartbeat" \
    -H "Content-Type: application/json" \
    -d '{"hostname":"audit-test"}' 2>&1)
if [ "$AGENT_HB_CODE" = "401" ] || [ "$AGENT_HB_CODE" = "403" ]; then
    pass "Agent heartbeat endpoint rejects unauthenticated requests (HTTP $AGENT_HB_CODE)"
else
    fail "Agent heartbeat endpoint: unexpected HTTP $AGENT_HB_CODE"
fi

# ============================================================================
# 10. ORGANIZATIONS & USERS
# ============================================================================
section "10. Organizations & Users"

ORG_COUNT=$(docker exec sentrikat-db psql -U sentrikat -d sentrikat -t -c \
    "SELECT COUNT(*) FROM organizations;" 2>&1 | xargs)
USER_COUNT=$(docker exec sentrikat-db psql -U sentrikat -d sentrikat -t -c \
    "SELECT COUNT(*) FROM users WHERE is_active = true;" 2>&1 | xargs)
ADMIN_COUNT=$(docker exec sentrikat-db psql -U sentrikat -d sentrikat -t -c \
    "SELECT COUNT(*) FROM users WHERE role = 'admin' AND is_active = true;" 2>&1 | xargs)
info "Organizations: $ORG_COUNT"
info "Active users: $USER_COUNT"
info "Admin users: $ADMIN_COUNT"

if [ "$ADMIN_COUNT" -eq 0 ] 2>/dev/null; then
    fail "No admin users found!"
fi

# List orgs with SMTP configured
SMTP_ORGS=$(docker exec sentrikat-db psql -U sentrikat -d sentrikat -t -c \
    "SELECT name FROM organizations WHERE smtp_host IS NOT NULL AND smtp_host != '';" 2>&1 | xargs)
if [ -n "$SMTP_ORGS" ]; then
    info "Orgs with SMTP: $SMTP_ORGS"
else
    warn "No organizations have SMTP configured (email alerts won't work)"
fi

# ============================================================================
# 11. SCHEDULED JOBS (Background Scheduler)
# ============================================================================
section "11. Scheduled Jobs & Background Tasks"

# Check if gunicorn workers are running
GUNICORN_PIDS=$(docker exec sentrikat pgrep -f gunicorn 2>/dev/null | wc -l)
if [ "$GUNICORN_PIDS" -gt 0 ]; then
    pass "Gunicorn running ($GUNICORN_PIDS processes)"
else
    fail "Gunicorn not running!"
fi

# Check scheduler by looking at recent sync logs
SYNC_24H=$(docker exec sentrikat-db psql -U sentrikat -d sentrikat -t -c \
    "SELECT sync_type, sync_date, status FROM sync_logs WHERE sync_date > NOW() - INTERVAL '48 hours' ORDER BY sync_date DESC LIMIT 5;" 2>&1)
if [ -n "$SYNC_24H" ]; then
    log ""
    log "  Recent sync logs (last 48h):"
    echo "$SYNC_24H" | while IFS= read -r line; do
        [ -n "$line" ] && info "  $line"
    done
else
    warn "No sync logs in last 48 hours - scheduler may not be running"
fi

# Check worker status endpoint
WORKER_CODE=$(curl $CURL_OPTS -o /dev/null -w "%{http_code}" "$BASE_URL/api/admin/worker-status" 2>&1)
info "Worker status endpoint: HTTP $WORKER_CODE"

# ============================================================================
# 12. NGINX RATE LIMITING
# ============================================================================
section "12. Rate Limiting & Security"

# Rapid-fire test (should not get rate limited within 5 requests)
RATE_OK=0
RATE_LIMITED=0
for i in $(seq 1 5); do
    CODE=$(curl $CURL_OPTS -o /dev/null -w "%{http_code}" "$BASE_URL/api/health" 2>&1)
    if [ "$CODE" = "200" ]; then
        RATE_OK=$((RATE_OK + 1))
    elif [ "$CODE" = "429" ]; then
        RATE_LIMITED=$((RATE_LIMITED + 1))
    fi
done

if [ "$RATE_OK" -eq 5 ]; then
    pass "Health endpoint not rate limited (5 rapid requests OK)"
elif [ "$RATE_LIMITED" -gt 0 ]; then
    warn "Rate limiting triggered on health endpoint ($RATE_LIMITED/5 got 429)"
fi

# Check CSRF protection on auth endpoints
CSRF_CODE=$(curl $CURL_OPTS -o /dev/null -w "%{http_code}" \
    -X POST "$BASE_URL/api/login" \
    -H "Content-Type: application/json" \
    -d '{"username":"test","password":"test"}' 2>&1)
info "Login endpoint without CSRF: HTTP $CSRF_CODE"

# ============================================================================
# 13. DISK & RESOURCES
# ============================================================================
section "13. Disk & System Resources"

# Docker volumes
log "  Docker volume sizes:"
for VOL in sentrikat_postgres_data sentrikat_sentrikat_data; do
    VOL_SIZE=$(docker system df -v 2>/dev/null | grep "$VOL" | awk '{print $3}' | head -1)
    if [ -n "$VOL_SIZE" ]; then
        info "$VOL: $VOL_SIZE"
    fi
done

# Host disk space
DISK_PCT=$(df / 2>/dev/null | tail -1 | awk '{print $5}' | tr -d '%')
DISK_AVAIL=$(df -h / 2>/dev/null | tail -1 | awk '{print $4}')
if [ "$DISK_PCT" -gt 90 ] 2>/dev/null; then
    fail "Disk usage: ${DISK_PCT}% (only $DISK_AVAIL free!)"
elif [ "$DISK_PCT" -gt 80 ] 2>/dev/null; then
    warn "Disk usage: ${DISK_PCT}% ($DISK_AVAIL free)"
else
    pass "Disk usage: ${DISK_PCT}% ($DISK_AVAIL free)"
fi

# Memory
MEM_TOTAL=$(free -h 2>/dev/null | awk '/^Mem:/{print $2}')
MEM_USED=$(free -h 2>/dev/null | awk '/^Mem:/{print $3}')
MEM_AVAIL=$(free -h 2>/dev/null | awk '/^Mem:/{print $7}')
info "Memory: $MEM_USED used / $MEM_TOTAL total ($MEM_AVAIL available)"

# ============================================================================
# 14. APPLICATION LOGS CHECK
# ============================================================================
section "14. Recent Application Errors"

# Check for recent errors in sentrikat container logs
RECENT_ERRORS=$(docker logs sentrikat --since 1h 2>&1 | grep -iE "error|exception|traceback|500" | tail -20)
if [ -n "$RECENT_ERRORS" ]; then
    warn "Recent errors found in sentrikat logs (last 1h):"
    echo "$RECENT_ERRORS" | head -20 | while IFS= read -r line; do
        echo "    $line" | tee -a "$REPORT"
    done
else
    pass "No errors in sentrikat logs (last 1h)"
fi

# Check nginx error log
NGINX_ERRORS=$(docker logs sentrikat-nginx --since 1h 2>&1 | grep -iE "error|emerg|crit" | grep -v "SSL_do_handshake" | tail -10)
if [ -n "$NGINX_ERRORS" ]; then
    warn "Recent nginx errors (last 1h):"
    echo "$NGINX_ERRORS" | head -10 | while IFS= read -r line; do
        echo "    $line" | tee -a "$REPORT"
    done
else
    pass "No nginx errors (last 1h)"
fi

# Check for the specific 500 database error
DB_500_ERRORS=$(docker logs sentrikat --since 24h 2>&1 | grep -i "Error processing inventory" | tail -5)
if [ -n "$DB_500_ERRORS" ]; then
    fail "Agent inventory 500 errors found (last 24h):"
    echo "$DB_500_ERRORS" | while IFS= read -r line; do
        echo "    $line" | tee -a "$REPORT"
    done
    # Get the actual traceback
    log ""
    log "  Full traceback for last inventory error:"
    docker logs sentrikat --since 24h 2>&1 | grep -A 30 "Error processing inventory" | tail -35 | while IFS= read -r line; do
        echo "    $line" | tee -a "$REPORT"
    done
else
    pass "No agent inventory errors (last 24h)"
fi

# ============================================================================
# 15. ENVIRONMENT CONFIGURATION
# ============================================================================
section "15. Environment Configuration"

# Check critical env vars inside container
for VAR in SENTRIKAT_URL SECRET_KEY DATABASE_URL FLASK_ENV SENTRIKAT_INSTALLATION_ID; do
    VAL=$(docker exec sentrikat printenv "$VAR" 2>/dev/null)
    if [ -n "$VAL" ]; then
        # Mask secrets
        case "$VAR" in
            SECRET_KEY|ENCRYPTION_KEY|DATABASE_URL)
                DISPLAY="${VAL:0:10}***"
                ;;
            *)
                DISPLAY="$VAL"
                ;;
        esac
        pass "$VAR is set: $DISPLAY"
    else
        if [ "$VAR" = "SENTRIKAT_INSTALLATION_ID" ]; then
            warn "$VAR not set (license will regenerate on rebuild!)"
        elif [ "$VAR" = "SECRET_KEY" ]; then
            fail "$VAR not set (sessions will break on restart!)"
        else
            warn "$VAR not set"
        fi
    fi
done

# Check proxy settings
HTTP_PROXY=$(docker exec sentrikat printenv HTTP_PROXY 2>/dev/null)
HTTPS_PROXY=$(docker exec sentrikat printenv HTTPS_PROXY 2>/dev/null)
if [ -n "$HTTP_PROXY" ] || [ -n "$HTTPS_PROXY" ]; then
    info "HTTP_PROXY: ${HTTP_PROXY:-not set}"
    info "HTTPS_PROXY: ${HTTPS_PROXY:-not set}"
    info "NO_PROXY: $(docker exec sentrikat printenv NO_PROXY 2>/dev/null)"
fi

# ============================================================================
# SUMMARY
# ============================================================================
section "AUDIT SUMMARY"

TOTAL=$((PASS + FAIL + WARN))
log ""
log "  Results: $TOTAL checks performed"
echo -e "  ${GREEN}PASSED: $PASS${NC}" | tee -a "$REPORT"
echo -e "  ${RED}FAILED: $FAIL${NC}" | tee -a "$REPORT"
echo -e "  ${YELLOW}WARNINGS: $WARN${NC}" | tee -a "$REPORT"
log ""

if [ "$FAIL" -eq 0 ]; then
    echo -e "  ${GREEN}>>> SYSTEM READY FOR PRODUCTION <<<${NC}" | tee -a "$REPORT"
else
    echo -e "  ${RED}>>> $FAIL CRITICAL ISSUES MUST BE FIXED BEFORE GO-LIVE <<<${NC}" | tee -a "$REPORT"
fi

log ""
log "  Full report saved to: $REPORT"
log "============================================================================"
