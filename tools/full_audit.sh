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
# 0. WAIT FOR DATABASE READINESS
# ============================================================================
section "0. Pre-flight: Waiting for Database"

DB_READY=false
for i in $(seq 1 30); do
    if docker exec sentrikat-db pg_isready -U sentrikat &>/dev/null; then
        DB_READY=true
        pass "Database ready after ${i}s"
        break
    fi
    echo -n "." | tee -a "$REPORT"
    sleep 2
done
echo "" | tee -a "$REPORT"

if [ "$DB_READY" = "false" ]; then
    fail "Database not ready after 60 seconds - results below may be unreliable!"
    warn "PostgreSQL may be recovering. Wait and re-run this script."
fi

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
        "SELECT COUNT(*) FROM vulnerabilities WHERE known_ransomware = true;" 2>&1 | xargs)
    info "Known ransomware campaign CVEs: $KEV_COUNT"

    # Last sync
    LAST_SYNC=$(docker exec sentrikat-db psql -U sentrikat -d sentrikat -t -c \
        "SELECT sync_date, status, vulnerabilities_count, matches_found FROM sync_logs ORDER BY sync_date DESC LIMIT 1;" 2>&1 | xargs)
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
    "SELECT COUNT(*) FROM agent_api_keys WHERE active = true;" 2>&1 | xargs)
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
    "SELECT COUNT(*) FROM users WHERE role IN ('super_admin', 'org_admin') AND is_active = true;" 2>&1 | xargs)
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
    "SELECT status, sync_date, vulnerabilities_count, matches_found FROM sync_logs WHERE sync_date > NOW() - INTERVAL '48 hours' ORDER BY sync_date DESC LIMIT 5;" 2>&1)
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
    -X POST "$BASE_URL/api/auth/login" \
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
# 16. CORE API ENDPOINT TESTING (curl)
# ============================================================================
section "16. Core API Endpoint Tests"

# --- Unauthenticated endpoints ---
log "  --- Public Endpoints ---"

# Health endpoint
HEALTH_RESP=$(curl $CURL_OPTS "$BASE_URL/api/health" 2>&1)
HEALTH_CODE=$(curl $CURL_OPTS -o /dev/null -w "%{http_code}" "$BASE_URL/api/health" 2>&1)
if [ "$HEALTH_CODE" = "200" ]; then
    pass "GET /api/health → HTTP 200"
    HEALTH_DB=$(echo "$HEALTH_RESP" | python3 -c "import sys,json; print(json.load(sys.stdin).get('checks',{}).get('database','?'))" 2>/dev/null)
    info "Health DB check: $HEALTH_DB"
else
    fail "GET /api/health → HTTP $HEALTH_CODE"
fi

# Version endpoint
VERSION_RESP=$(curl $CURL_OPTS "$BASE_URL/api/version" 2>&1)
VERSION_CODE=$(curl $CURL_OPTS -o /dev/null -w "%{http_code}" "$BASE_URL/api/version" 2>&1)
if [ "$VERSION_CODE" = "200" ]; then
    APP_VER=$(echo "$VERSION_RESP" | python3 -c "import sys,json; print(json.load(sys.stdin).get('version','?'))" 2>/dev/null)
    pass "GET /api/version → HTTP 200 (v$APP_VER)"
else
    fail "GET /api/version → HTTP $VERSION_CODE"
fi

# Status endpoint (may or may not require auth)
STATUS_CODE=$(curl $CURL_OPTS -o /dev/null -w "%{http_code}" "$BASE_URL/api/status" 2>&1)
info "GET /api/status → HTTP $STATUS_CODE"

# --- Authenticate for protected endpoints ---
log ""
log "  --- Authenticated Endpoint Tests ---"

# Try to login and get session cookie
COOKIE_JAR="/tmp/sentrikat-audit-cookies.txt"
rm -f "$COOKIE_JAR"

# Get admin credentials from environment or use defaults
AUDIT_USER="${SENTRIKAT_AUDIT_USER:-admin}"
AUDIT_PASS="${SENTRIKAT_AUDIT_PASS:-}"

AUTH_OK=false
if [ -n "$AUDIT_PASS" ]; then
    LOGIN_CODE=$(curl $CURL_OPTS -o /dev/null -w "%{http_code}" \
        -c "$COOKIE_JAR" \
        -X POST "$BASE_URL/api/auth/login" \
        -H "Content-Type: application/json" \
        -d "{\"username\":\"$AUDIT_USER\",\"password\":\"$AUDIT_PASS\"}" 2>&1)

    if [ "$LOGIN_CODE" = "200" ]; then
        pass "API login successful (user: $AUDIT_USER)"
        AUTH_OK=true
    else
        warn "API login failed: HTTP $LOGIN_CODE (set SENTRIKAT_AUDIT_USER/SENTRIKAT_AUDIT_PASS env vars)"
    fi
else
    # Check if auth is disabled (common in dev)
    AUTH_CHECK_CODE=$(curl $CURL_OPTS -o /dev/null -w "%{http_code}" "$BASE_URL/api/license" 2>&1)
    if [ "$AUTH_CHECK_CODE" = "200" ]; then
        info "Auth appears disabled - API accessible without login"
        AUTH_OK=true
    else
        warn "No SENTRIKAT_AUDIT_PASS set. Skipping authenticated tests."
        info "Set SENTRIKAT_AUDIT_PASS=<admin-password> to enable full API testing"
    fi
fi

if [ "$AUTH_OK" = "true" ]; then
    AUTH_CURL="curl $CURL_OPTS -b $COOKIE_JAR"

    # License info
    LIC_RESP=$($AUTH_CURL "$BASE_URL/api/license" 2>&1)
    LIC_CODE=$($AUTH_CURL -o /dev/null -w "%{http_code}" "$BASE_URL/api/license" 2>&1)
    if [ "$LIC_CODE" = "200" ]; then
        LIC_EDITION=$(echo "$LIC_RESP" | python3 -c "import sys,json; print(json.load(sys.stdin).get('edition','?'))" 2>/dev/null)
        LIC_STATUS=$(echo "$LIC_RESP" | python3 -c "import sys,json; d=json.load(sys.stdin); print(d.get('status','?'))" 2>/dev/null)
        LIC_PRO=$(echo "$LIC_RESP" | python3 -c "import sys,json; print(json.load(sys.stdin).get('is_professional',False))" 2>/dev/null)
        pass "GET /api/license → HTTP 200 (edition=$LIC_EDITION, professional=$LIC_PRO, status=$LIC_STATUS)"
    else
        fail "GET /api/license → HTTP $LIC_CODE"
    fi

    # Installation ID
    INSTALL_RESP=$($AUTH_CURL "$BASE_URL/api/license/installation-id" 2>&1)
    INSTALL_CODE=$($AUTH_CURL -o /dev/null -w "%{http_code}" "$BASE_URL/api/license/installation-id" 2>&1)
    if [ "$INSTALL_CODE" = "200" ]; then
        INSTALL_ID=$(echo "$INSTALL_RESP" | python3 -c "import sys,json; print(json.load(sys.stdin).get('installation_id','?'))" 2>/dev/null)
        pass "Installation ID: ${INSTALL_ID:0:12}..."
    else
        warn "GET /api/license/installation-id → HTTP $INSTALL_CODE"
    fi

    # Sync status
    SYNC_RESP=$($AUTH_CURL "$BASE_URL/api/sync/status" 2>&1)
    SYNC_CODE=$($AUTH_CURL -o /dev/null -w "%{http_code}" "$BASE_URL/api/sync/status" 2>&1)
    if [ "$SYNC_CODE" = "200" ]; then
        pass "GET /api/sync/status → HTTP 200"
    else
        warn "GET /api/sync/status → HTTP $SYNC_CODE"
    fi

    # Products list
    PROD_RESP=$($AUTH_CURL "$BASE_URL/api/products?limit=1" 2>&1)
    PROD_CODE=$($AUTH_CURL -o /dev/null -w "%{http_code}" "$BASE_URL/api/products?limit=1" 2>&1)
    if [ "$PROD_CODE" = "200" ]; then
        pass "GET /api/products → HTTP 200"
    else
        fail "GET /api/products → HTTP $PROD_CODE"
    fi

    # Vulnerabilities stats
    VULN_RESP=$($AUTH_CURL "$BASE_URL/api/vulnerabilities/stats" 2>&1)
    VULN_CODE=$($AUTH_CURL -o /dev/null -w "%{http_code}" "$BASE_URL/api/vulnerabilities/stats" 2>&1)
    if [ "$VULN_CODE" = "200" ]; then
        pass "GET /api/vulnerabilities/stats → HTTP 200"
    else
        fail "GET /api/vulnerabilities/stats → HTTP $VULN_CODE"
    fi

    # System notifications
    NOTIF_CODE=$($AUTH_CURL -o /dev/null -w "%{http_code}" "$BASE_URL/api/system/notifications" 2>&1)
    if [ "$NOTIF_CODE" = "200" ]; then
        NOTIF_COUNT=$($AUTH_CURL "$BASE_URL/api/system/notifications" 2>&1 | python3 -c "import sys,json; print(len(json.load(sys.stdin).get('notifications',[])))" 2>/dev/null)
        pass "GET /api/system/notifications → HTTP 200 ($NOTIF_COUNT active notifications)"
    else
        warn "GET /api/system/notifications → HTTP $NOTIF_CODE"
    fi

    # Organizations
    ORG_CODE=$($AUTH_CURL -o /dev/null -w "%{http_code}" "$BASE_URL/api/organizations" 2>&1)
    if [ "$ORG_CODE" = "200" ]; then
        pass "GET /api/organizations → HTTP 200"
    else
        warn "GET /api/organizations → HTTP $ORG_CODE"
    fi

    # Users
    USR_CODE=$($AUTH_CURL -o /dev/null -w "%{http_code}" "$BASE_URL/api/users" 2>&1)
    if [ "$USR_CODE" = "200" ]; then
        pass "GET /api/users → HTTP 200"
    else
        warn "GET /api/users → HTTP $USR_CODE"
    fi

    # CPE Dictionary status
    CPE_CODE=$($AUTH_CURL -o /dev/null -w "%{http_code}" "$BASE_URL/api/cpe/dictionary/status" 2>&1)
    if [ "$CPE_CODE" = "200" ]; then
        CPE_RESP=$($AUTH_CURL "$BASE_URL/api/cpe/dictionary/status" 2>&1)
        CPE_COUNT=$(echo "$CPE_RESP" | python3 -c "import sys,json; print(json.load(sys.stdin).get('total_mappings',0))" 2>/dev/null)
        pass "GET /api/cpe/dictionary/status → HTTP 200 ($CPE_COUNT CPE mappings)"
    else
        info "GET /api/cpe/dictionary/status → HTTP $CPE_CODE"
    fi
fi

# Cleanup
rm -f "$COOKIE_JAR"

# ============================================================================
# 17. LICENSE SERVER & PORTAL CONNECTIVITY
# ============================================================================
section "17. License Server & Portal Connectivity"

# Get license server URL from container
LICENSE_SERVER=$(docker exec sentrikat printenv SENTRIKAT_LICENSE_SERVER 2>/dev/null)
if [ -z "$LICENSE_SERVER" ]; then
    LICENSE_SERVER="https://portal.sentrikat.com/api"
fi
info "License server URL: $LICENSE_SERVER"

# DNS resolution
LICENSE_HOST=$(echo "$LICENSE_SERVER" | sed 's|https\?://||' | sed 's|/.*||')
if docker exec sentrikat getent hosts "$LICENSE_HOST" &>/dev/null || \
   docker exec sentrikat python3 -c "import socket; socket.getaddrinfo('$LICENSE_HOST', 443)" &>/dev/null; then
    pass "DNS resolves: $LICENSE_HOST"
else
    # Behind proxy DNS may resolve at proxy level
    warn "Cannot resolve DNS directly: $LICENSE_HOST (may resolve via proxy)"
fi

# Helper: test license endpoint with proxy and direct
test_license_ep() {
    local LABEL="$1"
    local URL="$2"
    local METHOD="$3"  # GET or POST
    local DATA="$4"

    local CURL_EXTRA=""
    [ "$METHOD" = "POST" ] && CURL_EXTRA="-X POST -H 'Content-Type: application/json' -d '$DATA'"

    # With proxy (default)
    local CODE_PROXY
    if [ "$METHOD" = "POST" ]; then
        CODE_PROXY=$(docker exec sentrikat curl -sk --connect-timeout 8 --max-time 15 \
            -o /dev/null -w "%{http_code}" \
            -X POST -H "Content-Type: application/json" \
            -H "User-Agent: SentriKat-Audit/1.0" \
            -d "$DATA" "$URL" 2>&1)
    else
        CODE_PROXY=$(docker exec sentrikat curl -sk --connect-timeout 8 --max-time 15 \
            -o /dev/null -w "%{http_code}" \
            -H "User-Agent: SentriKat-Audit/1.0" \
            "$URL" 2>&1)
    fi
    [ "$CODE_PROXY" = "000" ] && CODE_PROXY="FAIL"

    # Without proxy (direct)
    local CODE_DIRECT
    if [ "$METHOD" = "POST" ]; then
        CODE_DIRECT=$(docker exec sentrikat curl -sk --noproxy '*' --connect-timeout 8 --max-time 15 \
            -o /dev/null -w "%{http_code}" \
            -X POST -H "Content-Type: application/json" \
            -H "User-Agent: SentriKat-Audit/1.0" \
            -d "$DATA" "$URL" 2>&1)
    else
        CODE_DIRECT=$(docker exec sentrikat curl -sk --noproxy '*' --connect-timeout 8 --max-time 15 \
            -o /dev/null -w "%{http_code}" \
            -H "User-Agent: SentriKat-Audit/1.0" \
            "$URL" 2>&1)
    fi
    [ "$CODE_DIRECT" = "000" ] && CODE_DIRECT="FAIL"

    # Report
    local OK=false
    if echo "$CODE_PROXY" | grep -qE '^[2-4][0-9][0-9]$'; then
        OK=true
        pass "$LABEL → HTTP $CODE_PROXY via proxy"
    elif echo "$CODE_DIRECT" | grep -qE '^[2-4][0-9][0-9]$'; then
        OK=true
        pass "$LABEL → HTTP $CODE_DIRECT direct (no proxy needed)"
    fi

    if [ "$OK" = "false" ]; then
        fail "$LABEL → unreachable (proxy=$CODE_PROXY, direct=$CODE_DIRECT)"
    else
        info "  proxy=$CODE_PROXY  direct=$CODE_DIRECT"
    fi
}

# Health endpoint
test_license_ep "License server health" "$LICENSE_SERVER/v1/health" "GET"

# Heartbeat endpoint
test_license_ep "Heartbeat endpoint" "$LICENSE_SERVER/v1/heartbeat" "POST" '{"test":true}'

# Activation endpoint
test_license_ep "Activation endpoint" "$LICENSE_SERVER/v1/license/activate" "POST" '{"test":true}'

# Check last heartbeat from app logs
LAST_HB=$(docker logs sentrikat --since 24h 2>&1 | grep -i "heartbeat" | tail -3)
if [ -n "$LAST_HB" ]; then
    log "  Recent heartbeat activity:"
    echo "$LAST_HB" | while IFS= read -r line; do
        info "  $line"
    done
else
    warn "No heartbeat activity in last 24h"
fi

# ============================================================================
# 18. KB (KNOWLEDGE BASE) SYNC CONNECTIVITY
# ============================================================================
section "18. Knowledge Base (KB) Sync"

# Get KB server URL from container
KB_SERVER=$(docker exec sentrikat printenv SENTRIKAT_KB_SERVER 2>/dev/null)
if [ -z "$KB_SERVER" ]; then
    KB_SERVER="$LICENSE_SERVER"
fi
info "KB server URL: $KB_SERVER"

# Check KB sync enabled
KB_ENABLED=$(docker exec sentrikat printenv SENTRIKAT_KB_SYNC_ENABLED 2>/dev/null)
KB_SHARE=$(docker exec sentrikat printenv SENTRIKAT_KB_SHARE_MAPPINGS 2>/dev/null)
info "KB sync enabled: ${KB_ENABLED:-true (default)}"
info "KB share mappings: ${KB_SHARE:-true (default)}"

# Test KB pull endpoint (proxy vs direct)
KB_PULL_PROXY=$(docker exec sentrikat curl -sk --connect-timeout 8 --max-time 15 \
    -w "\n%{http_code}" \
    -H "User-Agent: SentriKat-Audit/1.0" \
    "$KB_SERVER/v1/kb/mappings/pull?since=2020-01-01T00:00:00Z" 2>&1)
KB_PULL_PROXY_CODE=$(echo "$KB_PULL_PROXY" | tail -1)
[ "$KB_PULL_PROXY_CODE" = "000" ] && KB_PULL_PROXY_CODE="FAIL"

KB_PULL_DIRECT=$(docker exec sentrikat curl -sk --noproxy '*' --connect-timeout 8 --max-time 15 \
    -w "\n%{http_code}" \
    -H "User-Agent: SentriKat-Audit/1.0" \
    "$KB_SERVER/v1/kb/mappings/pull?since=2020-01-01T00:00:00Z" 2>&1)
KB_PULL_DIRECT_CODE=$(echo "$KB_PULL_DIRECT" | tail -1)
[ "$KB_PULL_DIRECT_CODE" = "000" ] && KB_PULL_DIRECT_CODE="FAIL"

if echo "$KB_PULL_PROXY_CODE" | grep -qE '^[2-4][0-9][0-9]$'; then
    KB_PULL_COUNT=$(echo "$KB_PULL_PROXY" | head -n -1 | python3 -c "import sys,json; print(len(json.load(sys.stdin).get('mappings',[])))" 2>/dev/null || echo "?")
    pass "KB pull endpoint: HTTP $KB_PULL_PROXY_CODE via proxy ($KB_PULL_COUNT mappings)"
elif echo "$KB_PULL_DIRECT_CODE" | grep -qE '^[2-4][0-9][0-9]$'; then
    KB_PULL_COUNT=$(echo "$KB_PULL_DIRECT" | head -n -1 | python3 -c "import sys,json; print(len(json.load(sys.stdin).get('mappings',[])))" 2>/dev/null || echo "?")
    pass "KB pull endpoint: HTTP $KB_PULL_DIRECT_CODE direct ($KB_PULL_COUNT mappings)"
else
    warn "KB pull endpoint unreachable (proxy=$KB_PULL_PROXY_CODE, direct=$KB_PULL_DIRECT_CODE)"
fi

# Test KB push endpoint (proxy vs direct)
KB_PUSH_PROXY=$(docker exec sentrikat curl -sk --connect-timeout 8 --max-time 15 \
    -o /dev/null -w "%{http_code}" \
    -X POST -H "Content-Type: application/json" \
    -H "User-Agent: SentriKat-Audit/1.0" \
    -d '{"mappings":[],"timestamp":"2024-01-01T00:00:00Z"}' \
    "$KB_SERVER/v1/kb/mappings/push" 2>&1)
[ "$KB_PUSH_PROXY" = "000" ] && KB_PUSH_PROXY="FAIL"

KB_PUSH_DIRECT=$(docker exec sentrikat curl -sk --noproxy '*' --connect-timeout 8 --max-time 15 \
    -o /dev/null -w "%{http_code}" \
    -X POST -H "Content-Type: application/json" \
    -H "User-Agent: SentriKat-Audit/1.0" \
    -d '{"mappings":[],"timestamp":"2024-01-01T00:00:00Z"}' \
    "$KB_SERVER/v1/kb/mappings/push" 2>&1)
[ "$KB_PUSH_DIRECT" = "000" ] && KB_PUSH_DIRECT="FAIL"

if echo "$KB_PUSH_PROXY" | grep -qE '^[2-4][0-9][0-9]$'; then
    pass "KB push endpoint: HTTP $KB_PUSH_PROXY via proxy"
elif echo "$KB_PUSH_DIRECT" | grep -qE '^[2-4][0-9][0-9]$'; then
    pass "KB push endpoint: HTTP $KB_PUSH_DIRECT direct"
else
    warn "KB push endpoint unreachable (proxy=$KB_PUSH_PROXY, direct=$KB_PUSH_DIRECT)"
fi

# Check local CPE mapping stats
CPE_STATS=$(docker exec sentrikat-db psql -U sentrikat -d sentrikat -t -c \
    "SELECT
        COUNT(*) AS total,
        COUNT(CASE WHEN source = 'user' THEN 1 END) AS user_created,
        COUNT(CASE WHEN source = 'community' THEN 1 END) AS community,
        COUNT(CASE WHEN source LIKE 'auto%' THEN 1 END) AS auto_mapped
    FROM cpe_mappings;" 2>&1 | xargs)
if [ -n "$CPE_STATS" ] && ! echo "$CPE_STATS" | grep -qi "error\|does not exist"; then
    info "CPE mappings: $CPE_STATS (total | user | community | auto)"
else
    info "CPE mappings table: not available or empty"
fi

# Check recent KB sync logs
KB_LOGS=$(docker logs sentrikat --since 24h 2>&1 | grep -i "kb.sync\|knowledge.base\|kb_sync" | tail -5)
if [ -n "$KB_LOGS" ]; then
    log "  Recent KB sync activity:"
    echo "$KB_LOGS" | while IFS= read -r line; do
        info "  $line"
    done
else
    info "No KB sync activity in last 24h"
fi

# ============================================================================
# 19. UPDATE CHECKER VERIFICATION
# ============================================================================
section "19. Software Update Checker"

# Test GitHub releases API directly (same as the app uses)
GITHUB_REPO="sbr0nch/SentriKat"
info "GitHub repo: $GITHUB_REPO"

# Check GitHub API connectivity (try proxy first, then direct)
GH_RAW=$(docker exec sentrikat curl -sk --connect-timeout 8 --max-time 15 \
    -w "\n%{http_code}" \
    -H "User-Agent: SentriKat-Audit/1.0" \
    "https://api.github.com/repos/$GITHUB_REPO/releases/latest" 2>&1)
GH_HTTP=$(echo "$GH_RAW" | tail -1)
GH_VIA="proxy"

# Fallback to direct if proxy failed
if [ "$GH_HTTP" = "000" ]; then
    GH_RAW=$(docker exec sentrikat curl -sk --noproxy '*' --connect-timeout 8 --max-time 15 \
        -w "\n%{http_code}" \
        -H "User-Agent: SentriKat-Audit/1.0" \
        "https://api.github.com/repos/$GITHUB_REPO/releases/latest" 2>&1)
    GH_HTTP=$(echo "$GH_RAW" | tail -1)
    GH_VIA="direct"
fi

GH_BODY=$(echo "$GH_RAW" | head -n -1)
if [ "$GH_HTTP" = "200" ]; then
    GH_TAG=$(echo "$GH_BODY" | python3 -c "import sys,json; print(json.load(sys.stdin).get('tag_name','?'))" 2>/dev/null)
    GH_NAME=$(echo "$GH_BODY" | python3 -c "import sys,json; print(json.load(sys.stdin).get('name','?'))" 2>/dev/null)
    GH_DATE=$(echo "$GH_BODY" | python3 -c "import sys,json; print(json.load(sys.stdin).get('published_at','?'))" 2>/dev/null)
    GH_RESP="200|${GH_TAG}|${GH_NAME}|${GH_DATE}"
elif [ "$GH_HTTP" = "000" ]; then
    GH_RESP="ERR:Connection|||"
else
    GH_RESP="${GH_HTTP}|||"
fi

GH_STATUS=$(echo "$GH_RESP" | cut -d'|' -f1)
GH_TAG=$(echo "$GH_RESP" | cut -d'|' -f2)
GH_NAME=$(echo "$GH_RESP" | cut -d'|' -f3)
GH_DATE=$(echo "$GH_RESP" | cut -d'|' -f4)

case "$GH_STATUS" in
    200)
        pass "GitHub releases API reachable (via $GH_VIA)"
        info "Latest release: $GH_TAG ($GH_NAME)"
        info "Published: $GH_DATE"

        # Compare with current version
        CURRENT_VER=$(docker exec sentrikat python3 -c "
import os, sys
sys.path.insert(0, '/app')
try:
    from app import APP_VERSION
    print(APP_VERSION)
except:
    print('unknown')
" 2>&1)
        info "Current installed version: $CURRENT_VER"

        # Strip 'v' prefix for comparison
        LATEST_CLEAN=$(echo "$GH_TAG" | sed 's/^v//')
        if [ "$CURRENT_VER" = "$LATEST_CLEAN" ]; then
            pass "Running latest version ($CURRENT_VER)"
        elif [ "$CURRENT_VER" != "unknown" ]; then
            warn "Update available: $CURRENT_VER → $LATEST_CLEAN"
        fi
        ;;
    404)
        info "No releases found on GitHub (HTTP 404)"
        ;;
    403)
        warn "GitHub API rate limited (HTTP 403) - try again later"
        ;;
    ERR:*)
        fail "Cannot reach GitHub API: $GH_STATUS"
        ;;
    *)
        warn "GitHub API returned HTTP $GH_STATUS"
        ;;
esac

# Also check fallback endpoint (all releases including pre-releases)
GH_ALL_RAW=$(docker exec sentrikat curl -sk --connect-timeout 8 --max-time 15 \
    -w "\n%{http_code}" \
    -H "User-Agent: SentriKat-Audit/1.0" \
    "https://api.github.com/repos/$GITHUB_REPO/releases" 2>&1)
GH_ALL_STATUS=$(echo "$GH_ALL_RAW" | tail -1)
# Fallback to direct if proxy failed
if [ "$GH_ALL_STATUS" = "000" ]; then
    GH_ALL_RAW=$(docker exec sentrikat curl -sk --noproxy '*' --connect-timeout 8 --max-time 15 \
        -w "\n%{http_code}" \
        -H "User-Agent: SentriKat-Audit/1.0" \
        "https://api.github.com/repos/$GITHUB_REPO/releases" 2>&1)
    GH_ALL_STATUS=$(echo "$GH_ALL_RAW" | tail -1)
fi
[ "$GH_ALL_STATUS" = "000" ] && GH_ALL_STATUS="ERR:Connection"
GH_ALL_COUNT=$(echo "$GH_ALL_RAW" | head -n -1 | python3 -c "import sys,json; print(len(json.load(sys.stdin)))" 2>/dev/null || echo "?")
info "Total GitHub releases (incl. pre-release): $GH_ALL_COUNT"

# Test the actual /api/updates/check endpoint if authenticated
if [ "$AUTH_OK" = "true" ]; then
    COOKIE_JAR="/tmp/sentrikat-audit-cookies.txt"
    if [ -n "$AUDIT_PASS" ]; then
        # Re-login (cookie may have expired)
        curl $CURL_OPTS -o /dev/null -c "$COOKIE_JAR" \
            -X POST "$BASE_URL/api/auth/login" \
            -H "Content-Type: application/json" \
            -d "{\"username\":\"$AUDIT_USER\",\"password\":\"$AUDIT_PASS\"}" 2>/dev/null
    fi
    UPDATE_RESP=$(curl $CURL_OPTS -b "$COOKIE_JAR" "$BASE_URL/api/updates/check" 2>&1)
    UPDATE_CODE=$(curl $CURL_OPTS -b "$COOKIE_JAR" -o /dev/null -w "%{http_code}" "$BASE_URL/api/updates/check" 2>&1)
    if [ "$UPDATE_CODE" = "200" ]; then
        UPDATE_AVAIL=$(echo "$UPDATE_RESP" | python3 -c "import sys,json; print(json.load(sys.stdin).get('update_available',False))" 2>/dev/null)
        UPDATE_LATEST=$(echo "$UPDATE_RESP" | python3 -c "import sys,json; print(json.load(sys.stdin).get('latest_version','?'))" 2>/dev/null)
        UPDATE_ERR=$(echo "$UPDATE_RESP" | python3 -c "import sys,json; print(json.load(sys.stdin).get('error',''))" 2>/dev/null)
        if [ -n "$UPDATE_ERR" ] && [ "$UPDATE_ERR" != "" ] && [ "$UPDATE_ERR" != "None" ]; then
            warn "Update check endpoint returned error: $UPDATE_ERR"
        else
            pass "GET /api/updates/check → HTTP 200 (update_available=$UPDATE_AVAIL, latest=$UPDATE_LATEST)"
        fi
    else
        warn "GET /api/updates/check → HTTP $UPDATE_CODE"
    fi
    rm -f "$COOKIE_JAR"
fi

# ============================================================================
# 20. CVE MATCHING ALGORITHM VERIFICATION
# ============================================================================
section "20. Core CVE Matching Algorithm"

# Check if matching data exists
MATCH_COUNT=$(docker exec sentrikat-db psql -U sentrikat -d sentrikat -t -c \
    "SELECT COUNT(*) FROM vulnerability_matches;" 2>&1 | xargs)
MATCH_ACTIVE=$(docker exec sentrikat-db psql -U sentrikat -d sentrikat -t -c \
    "SELECT COUNT(*) FROM vulnerability_matches WHERE acknowledged = false;" 2>&1 | xargs)
MATCH_ACK=$(docker exec sentrikat-db psql -U sentrikat -d sentrikat -t -c \
    "SELECT COUNT(*) FROM vulnerability_matches WHERE acknowledged = true;" 2>&1 | xargs)

if echo "$MATCH_COUNT" | grep -qE '^[0-9]+$'; then
    info "Total vulnerability matches: $MATCH_COUNT (active: $MATCH_ACTIVE, acknowledged: $MATCH_ACK)"
else
    warn "Could not query vulnerability_matches table"
fi

# Check match types distribution (CPE vs keyword)
MATCH_TYPES=$(docker exec sentrikat-db psql -U sentrikat -d sentrikat -t -c \
    "SELECT
        COUNT(CASE WHEN match_type = 'cpe' THEN 1 END) AS cpe_matches,
        COUNT(CASE WHEN match_type = 'keyword' THEN 1 END) AS keyword_matches,
        COUNT(CASE WHEN match_type = 'both' THEN 1 END) AS both_matches,
        COUNT(CASE WHEN match_type IS NULL OR match_type NOT IN ('cpe','keyword','both') THEN 1 END) AS other
    FROM vulnerability_matches;" 2>&1 | xargs)
if ! echo "$MATCH_TYPES" | grep -qi "error"; then
    info "Match types: $MATCH_TYPES (cpe | keyword | both | other)"
fi

# Check confidence distribution
CONFIDENCE_DIST=$(docker exec sentrikat-db psql -U sentrikat -d sentrikat -t -c \
    "SELECT
        COUNT(CASE WHEN confidence = 'HIGH' THEN 1 END) AS high,
        COUNT(CASE WHEN confidence = 'MEDIUM' THEN 1 END) AS medium,
        COUNT(CASE WHEN confidence = 'LOW' THEN 1 END) AS low
    FROM vulnerability_matches;" 2>&1 | xargs)
if ! echo "$CONFIDENCE_DIST" | grep -qi "error"; then
    info "Match confidence: $CONFIDENCE_DIST (HIGH | MEDIUM | LOW)"
fi

# Verify matching algorithm via Python inside the container
log ""
log "  --- Algorithm Integrity Test ---"
ALGO_TEST=$(docker exec sentrikat python3 -c "
import os, sys
sys.path.insert(0, '/app')
os.environ.setdefault('FLASK_APP', 'app')

results = []

# Test 1: Import core matching functions
try:
    from app.filters import match_vulnerabilities_to_products, check_cpe_match, check_keyword_match
    results.append('PASS:Core matching functions importable')
except Exception as e:
    results.append(f'FAIL:Cannot import matching functions: {e}')

# Test 2: Keyword matching logic with known patterns
try:
    from app.filters import check_keyword_match

    class MockVuln:
        vendor_project = 'microsoft'
        product = 'windows'
        cve_id = 'CVE-2024-0001'
        short_description = 'Microsoft Windows vulnerability in kernel'
        notes = ''
        cpe_entries = []

    class MockProd:
        vendor = 'Microsoft'
        product_name = 'Windows 10'
        name = 'Windows 10'
        version = '10.0'
        match_type = 'keyword'
        keywords = ''
        effective_cpe_vendor = None
        effective_cpe_product = None

    match = check_keyword_match(MockVuln(), MockProd())
    # Returns tuple: (match_reasons, match_method, match_confidence)
    if match and isinstance(match, tuple) and len(match) >= 3 and match[0]:
        results.append(f'PASS:Keyword match working (confidence={match[2]}, method={match[1]})')
    elif match and isinstance(match, tuple) and len(match) >= 1 and not match[0]:
        results.append('WARN:Keyword match returned no match for obvious Microsoft Windows test')
    else:
        results.append('WARN:Keyword match returned unexpected result')
except Exception as e:
    results.append(f'FAIL:Keyword match test error: {e}')

# Test 3: Version comparison utilities
try:
    from app.version_utils import compare_versions
    # 1.0 < 2.0
    cmp = compare_versions('1.0', '2.0')
    if cmp < 0:
        results.append('PASS:Version comparison working (1.0 < 2.0)')
    else:
        results.append(f'FAIL:Version comparison wrong: compare_versions(1.0, 2.0) = {cmp}')
except ImportError:
    results.append('INFO:version_utils not available')
except Exception as e:
    results.append(f'FAIL:Version comparison error: {e}')

# Test 4: CPE mapping module
try:
    from app.cpe_mapping import get_cpe_suggestions
    results.append('PASS:CPE mapping module importable')
except ImportError:
    results.append('INFO:CPE mapping module not available')
except Exception as e:
    results.append(f'WARN:CPE mapping import issue: {e}')

# Test 5: Encryption roundtrip
try:
    from app.encryption import encrypt_value, decrypt_value, clear_cache
    clear_cache()
    test_val = 'audit-test-secret-12345'
    encrypted = encrypt_value(test_val)
    decrypted = decrypt_value(encrypted)
    if decrypted == test_val:
        results.append('PASS:Encryption roundtrip working')
    else:
        results.append('FAIL:Encryption roundtrip mismatch')
    clear_cache()
except Exception as e:
    results.append(f'FAIL:Encryption test error: {e}')

for r in results:
    print(r)
" 2>&1)

echo "$ALGO_TEST" | while IFS= read -r line; do
    if echo "$line" | grep -q "^PASS:"; then
        MSG=$(echo "$line" | sed 's/^PASS://')
        pass "$MSG"
    elif echo "$line" | grep -q "^FAIL:"; then
        MSG=$(echo "$line" | sed 's/^FAIL://')
        fail "$MSG"
    elif echo "$line" | grep -q "^WARN:"; then
        MSG=$(echo "$line" | sed 's/^WARN://')
        warn "$MSG"
    elif echo "$line" | grep -q "^INFO:"; then
        MSG=$(echo "$line" | sed 's/^INFO://')
        info "$MSG"
    elif [ -n "$line" ]; then
        info "$line"
    fi
done

# Vendor fix overrides
VFO_COUNT=$(docker exec sentrikat-db psql -U sentrikat -d sentrikat -t -c \
    "SELECT COUNT(*) FROM vendor_fix_overrides WHERE status = 'approved';" 2>&1 | xargs)
if echo "$VFO_COUNT" | grep -qE '^[0-9]+$'; then
    info "Vendor fix overrides (approved): $VFO_COUNT"
fi

# ============================================================================
# 21. EXTERNAL SERVICE CONNECTIVITY
# ============================================================================
section "21. External Service Connectivity"

# Detect proxy configuration
CONTAINER_HTTP_PROXY=$(docker exec sentrikat printenv HTTP_PROXY 2>/dev/null || docker exec sentrikat printenv http_proxy 2>/dev/null)
CONTAINER_HTTPS_PROXY=$(docker exec sentrikat printenv HTTPS_PROXY 2>/dev/null || docker exec sentrikat printenv https_proxy 2>/dev/null)

if [ -n "$CONTAINER_HTTP_PROXY" ] || [ -n "$CONTAINER_HTTPS_PROXY" ]; then
    info "Container proxy: ${CONTAINER_HTTPS_PROXY:-$CONTAINER_HTTP_PROXY}"
    PROXY_CONFIGURED=true
else
    info "No proxy configured in container"
    PROXY_CONFIGURED=false
fi

# Helper: test connectivity with and without proxy, and SSL verify vs skip
# Usage: test_endpoint "Label" "URL" [POST_DATA]
test_endpoint() {
    local LABEL="$1"
    local URL="$2"
    local POST_DATA="$3"
    local CURL_METHOD=""
    [ -n "$POST_DATA" ] && CURL_METHOD="-X POST -H 'Content-Type: application/json' -d '$POST_DATA'"

    # Test 1: With proxy + skip SSL verify (most permissive)
    local CODE_PROXY_NOSSL
    if [ -n "$POST_DATA" ]; then
        CODE_PROXY_NOSSL=$(docker exec sentrikat curl -sk --connect-timeout 8 --max-time 15 \
            -o /dev/null -w "%{http_code}" \
            -X POST -H "Content-Type: application/json" \
            -H "User-Agent: SentriKat-Audit/1.0" \
            -d "$POST_DATA" "$URL" 2>&1)
    else
        CODE_PROXY_NOSSL=$(docker exec sentrikat curl -sk --connect-timeout 8 --max-time 15 \
            -o /dev/null -w "%{http_code}" \
            -H "User-Agent: SentriKat-Audit/1.0" \
            "$URL" 2>&1)
    fi
    [ "$CODE_PROXY_NOSSL" = "000" ] && CODE_PROXY_NOSSL="FAIL"

    # Test 2: With proxy + SSL verify (secure)
    local CODE_PROXY_SSL
    if [ -n "$POST_DATA" ]; then
        CODE_PROXY_SSL=$(docker exec sentrikat curl -s --connect-timeout 8 --max-time 15 \
            -o /dev/null -w "%{http_code}" \
            -X POST -H "Content-Type: application/json" \
            -H "User-Agent: SentriKat-Audit/1.0" \
            -d "$POST_DATA" "$URL" 2>&1)
    else
        CODE_PROXY_SSL=$(docker exec sentrikat curl -s --connect-timeout 8 --max-time 15 \
            -o /dev/null -w "%{http_code}" \
            -H "User-Agent: SentriKat-Audit/1.0" \
            "$URL" 2>&1)
    fi
    [ "$CODE_PROXY_SSL" = "000" ] && CODE_PROXY_SSL="FAIL"

    # Test 3: Without proxy + skip SSL verify (direct)
    local CODE_DIRECT_NOSSL
    if [ -n "$POST_DATA" ]; then
        CODE_DIRECT_NOSSL=$(docker exec sentrikat curl -sk --noproxy '*' --connect-timeout 8 --max-time 15 \
            -o /dev/null -w "%{http_code}" \
            -X POST -H "Content-Type: application/json" \
            -H "User-Agent: SentriKat-Audit/1.0" \
            -d "$POST_DATA" "$URL" 2>&1)
    else
        CODE_DIRECT_NOSSL=$(docker exec sentrikat curl -sk --noproxy '*' --connect-timeout 8 --max-time 15 \
            -o /dev/null -w "%{http_code}" \
            -H "User-Agent: SentriKat-Audit/1.0" \
            "$URL" 2>&1)
    fi
    [ "$CODE_DIRECT_NOSSL" = "000" ] && CODE_DIRECT_NOSSL="FAIL"

    # Test 4: Without proxy + SSL verify (strictest)
    local CODE_DIRECT_SSL
    if [ -n "$POST_DATA" ]; then
        CODE_DIRECT_SSL=$(docker exec sentrikat curl -s --noproxy '*' --connect-timeout 8 --max-time 15 \
            -o /dev/null -w "%{http_code}" \
            -X POST -H "Content-Type: application/json" \
            -H "User-Agent: SentriKat-Audit/1.0" \
            -d "$POST_DATA" "$URL" 2>&1)
    else
        CODE_DIRECT_SSL=$(docker exec sentrikat curl -s --noproxy '*' --connect-timeout 8 --max-time 15 \
            -o /dev/null -w "%{http_code}" \
            -H "User-Agent: SentriKat-Audit/1.0" \
            "$URL" 2>&1)
    fi
    [ "$CODE_DIRECT_SSL" = "000" ] && CODE_DIRECT_SSL="FAIL"

    # Determine status and report
    local BEST_CODE="FAIL"
    local NEEDS_PROXY="no"
    local NEEDS_SSL_SKIP="no"
    local STATUS_ICON="FAIL"

    # Check what works
    if echo "$CODE_DIRECT_SSL" | grep -qE '^[2-4][0-9][0-9]$'; then
        BEST_CODE="$CODE_DIRECT_SSL"
        STATUS_ICON="PASS"
        NEEDS_PROXY="no"
        NEEDS_SSL_SKIP="no"
    elif echo "$CODE_DIRECT_NOSSL" | grep -qE '^[2-4][0-9][0-9]$'; then
        BEST_CODE="$CODE_DIRECT_NOSSL"
        STATUS_ICON="PASS"
        NEEDS_PROXY="no"
        NEEDS_SSL_SKIP="yes"
    elif echo "$CODE_PROXY_SSL" | grep -qE '^[2-4][0-9][0-9]$'; then
        BEST_CODE="$CODE_PROXY_SSL"
        STATUS_ICON="PASS"
        NEEDS_PROXY="yes"
        NEEDS_SSL_SKIP="no"
    elif echo "$CODE_PROXY_NOSSL" | grep -qE '^[2-4][0-9][0-9]$'; then
        BEST_CODE="$CODE_PROXY_NOSSL"
        STATUS_ICON="PASS"
        NEEDS_PROXY="yes"
        NEEDS_SSL_SKIP="yes"
    fi

    # Build result string
    local DETAIL="proxy+noSSL=$CODE_PROXY_NOSSL  proxy+SSL=$CODE_PROXY_SSL  direct+noSSL=$CODE_DIRECT_NOSSL  direct+SSL=$CODE_DIRECT_SSL"

    if [ "$STATUS_ICON" = "PASS" ]; then
        local REQS=""
        [ "$NEEDS_PROXY" = "yes" ] && REQS="NEEDS PROXY"
        [ "$NEEDS_SSL_SKIP" = "yes" ] && REQS="${REQS:+$REQS, }SSL verify fails"
        [ -z "$REQS" ] && REQS="direct+SSL OK"
        pass "$LABEL → HTTP $BEST_CODE ($REQS)"
    else
        fail "$LABEL → unreachable"
    fi
    info "  $DETAIL"
}

log ""
log "  --- Connectivity Matrix (proxy vs direct, SSL verify vs skip) ---"
log ""

test_endpoint "NVD API (CVE data)" \
    "https://services.nvd.nist.gov/rest/json/cves/2.0?resultsPerPage=1"

test_endpoint "CISA KEV feed" \
    "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"

test_endpoint "EPSS API (FIRST.org)" \
    "https://api.first.org/data/v1/epss?cve=CVE-2024-0001"

test_endpoint "OSV API (vendor advisories)" \
    "https://api.osv.dev/v1/query" \
    '{"package":{"name":"test","ecosystem":"PyPI"}}'

test_endpoint "GitHub API (updates)" \
    "https://api.github.com/rate_limit"

test_endpoint "License server (portal)" \
    "${LICENSE_SERVER:-https://portal.sentrikat.com/api}/v1/health"

log ""
log "  --- Summary ---"
if [ "$PROXY_CONFIGURED" = "true" ]; then
    info "Proxy configured: ${CONTAINER_HTTPS_PROXY:-$CONTAINER_HTTP_PROXY}"
    info "If all 'direct' tests FAIL and 'proxy' tests PASS → proxy is REQUIRED"
    info "If 'proxy+SSL' FAILs but 'proxy+noSSL' works → proxy does SSL interception"
fi

# ============================================================================
# 22. SECURITY CONFIGURATION CHECK
# ============================================================================
section "22. Security Configuration"

# Check if running with default SECRET_KEY
SECRET_KEY=$(docker exec sentrikat printenv SECRET_KEY 2>/dev/null)
if [ "$SECRET_KEY" = "dev-secret-key-change-in-production" ] || [ -z "$SECRET_KEY" ]; then
    fail "Using DEFAULT SECRET_KEY - sessions are insecure! Set a unique SECRET_KEY in .env"
else
    pass "SECRET_KEY is set (not default)"
fi

# Check ENCRYPTION_KEY
ENC_KEY=$(docker exec sentrikat printenv ENCRYPTION_KEY 2>/dev/null)
if [ -z "$ENC_KEY" ]; then
    warn "ENCRYPTION_KEY not set (deriving from SECRET_KEY)"
else
    pass "ENCRYPTION_KEY is set explicitly"
fi

# Check FLASK_ENV
FLASK_ENV=$(docker exec sentrikat printenv FLASK_ENV 2>/dev/null)
if [ "$FLASK_ENV" = "development" ]; then
    warn "FLASK_ENV=development (debug mode may be enabled)"
elif [ "$FLASK_ENV" = "production" ]; then
    pass "FLASK_ENV=production"
else
    info "FLASK_ENV=${FLASK_ENV:-not set}"
fi

# Check if debug mode is off
DEBUG_MODE=$(docker exec sentrikat printenv FLASK_DEBUG 2>/dev/null)
if [ "$DEBUG_MODE" = "1" ] || [ "$DEBUG_MODE" = "true" ]; then
    fail "FLASK_DEBUG is ON - must be disabled in production!"
else
    pass "Debug mode is OFF"
fi

# SSL/TLS on nginx
SSL_CERT=$(docker exec sentrikat-nginx ls -la /etc/nginx/ssl/ 2>/dev/null)
if [ -n "$SSL_CERT" ]; then
    pass "SSL certificates present in nginx"
    # Check cert expiry
    CERT_EXPIRY=$(docker exec sentrikat-nginx openssl x509 -enddate -noout -in /etc/nginx/ssl/cert.pem 2>/dev/null | cut -d= -f2)
    if [ -n "$CERT_EXPIRY" ]; then
        info "SSL cert expires: $CERT_EXPIRY"
        # Check if expiring within 30 days
        CERT_EPOCH=$(date -d "$CERT_EXPIRY" +%s 2>/dev/null)
        NOW_EPOCH=$(date +%s)
        if [ -n "$CERT_EPOCH" ]; then
            DAYS_LEFT=$(( (CERT_EPOCH - NOW_EPOCH) / 86400 ))
            if [ "$DAYS_LEFT" -lt 0 ]; then
                fail "SSL certificate EXPIRED ($DAYS_LEFT days ago)"
            elif [ "$DAYS_LEFT" -lt 30 ]; then
                warn "SSL certificate expires in $DAYS_LEFT days"
            else
                pass "SSL certificate valid ($DAYS_LEFT days remaining)"
            fi
        fi
    fi
else
    warn "No SSL certificates found in nginx"
fi

# Check HTTP → HTTPS redirect
HTTP_CODE=$(curl -s -o /dev/null -w "%{http_code}" --connect-timeout 5 "http://localhost/" 2>&1)
if [ "$HTTP_CODE" = "301" ] || [ "$HTTP_CODE" = "308" ]; then
    pass "HTTP → HTTPS redirect active (HTTP $HTTP_CODE)"
elif [ "$HTTP_CODE" = "000" ]; then
    info "HTTP port not exposed (HTTPS-only)"
else
    warn "HTTP not redirecting to HTTPS (HTTP $HTTP_CODE)"
fi

# Check security headers
SEC_HEADERS=$(curl $CURL_OPTS -I "$BASE_URL/" 2>&1)
if echo "$SEC_HEADERS" | grep -qi "Strict-Transport-Security"; then
    pass "HSTS header present"
else
    warn "HSTS header missing"
fi
if echo "$SEC_HEADERS" | grep -qi "X-Content-Type-Options"; then
    pass "X-Content-Type-Options header present"
else
    warn "X-Content-Type-Options header missing"
fi
if echo "$SEC_HEADERS" | grep -qi "X-Frame-Options"; then
    pass "X-Frame-Options header present"
else
    info "X-Frame-Options header not found (may use CSP frame-ancestors)"
fi

# Check session cookie security
SESSION_COOKIE=$(curl $CURL_OPTS -c - "$BASE_URL/" 2>&1 | grep -i "session")
if echo "$SESSION_COOKIE" | grep -qi "Secure"; then
    pass "Session cookie has Secure flag"
else
    info "Session cookie Secure flag not detected in initial response"
fi
if echo "$SESSION_COOKIE" | grep -qi "HttpOnly"; then
    pass "Session cookie has HttpOnly flag"
else
    info "Session cookie HttpOnly flag not detected in initial response"
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
