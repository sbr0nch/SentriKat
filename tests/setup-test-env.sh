#!/usr/bin/env bash
set -euo pipefail

# ============================================================================
# SentriKat Test Environment Setup
# Starts Keycloak (SAML IdP) + OpenLDAP + Syslog receiver
# and configures SentriKat to use them.
# ============================================================================

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"
COMPOSE_FILE="$PROJECT_DIR/docker-compose.test.yml"

# SentriKat base URL (where the Flask app is running)
SENTRIKAT_URL="${SENTRIKAT_URL:-http://localhost:5000}"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

info()  { echo -e "${BLUE}[INFO]${NC}  $*"; }
ok()    { echo -e "${GREEN}[OK]${NC}    $*"; }
warn()  { echo -e "${YELLOW}[WARN]${NC}  $*"; }
err()   { echo -e "${RED}[ERROR]${NC} $*"; }

# ── Step 1: Start containers ───────────────────────────────────────
info "Starting test containers..."
docker compose -f "$COMPOSE_FILE" up -d

# ── Step 2: Wait for services ──────────────────────────────────────
info "Waiting for OpenLDAP..."
for i in $(seq 1 30); do
    if docker exec sentrikat-openldap ldapsearch -x -H ldap://localhost \
        -b "dc=sentrikat,dc=test" -D "cn=admin,dc=sentrikat,dc=test" \
        -w admin "(objectClass=inetOrgPerson)" dn 2>/dev/null | grep -q "uid="; then
        ok "OpenLDAP is ready with test users"
        break
    fi
    [ "$i" -eq 30 ] && { err "OpenLDAP did not start in time"; exit 1; }
    sleep 2
done

info "Waiting for Keycloak (this takes 30-90 seconds on first start)..."
for i in $(seq 1 60); do
    if curl -sf http://localhost:8080/health/ready 2>/dev/null | grep -q "UP"; then
        ok "Keycloak is ready"
        break
    fi
    [ "$i" -eq 60 ] && { err "Keycloak did not start in time"; exit 1; }
    sleep 3
done

info "Waiting for Syslog receiver..."
sleep 2
if docker ps --filter "name=sentrikat-syslog" --filter "status=running" -q | grep -q .; then
    ok "Syslog receiver is running"
else
    warn "Syslog receiver may not be ready"
fi

# ── Step 3: Fetch Keycloak SAML IdP metadata ──────────────────────
info "Fetching Keycloak SAML IdP metadata..."
IDP_METADATA_URL="http://localhost:8080/realms/sentrikat/protocol/saml/descriptor"

for i in $(seq 1 10); do
    IDP_METADATA=$(curl -sf "$IDP_METADATA_URL" 2>/dev/null || true)
    if [ -n "$IDP_METADATA" ] && echo "$IDP_METADATA" | grep -q "EntityDescriptor"; then
        ok "Got IdP metadata ($(echo "$IDP_METADATA" | wc -c) bytes)"
        break
    fi
    [ "$i" -eq 10 ] && { err "Could not fetch IdP metadata"; exit 1; }
    sleep 3
done

# ── Step 4: Print configuration instructions ──────────────────────
echo ""
echo "============================================================================"
echo -e "${GREEN} Test Environment Ready!${NC}"
echo "============================================================================"
echo ""
echo -e "${BLUE}LDAP Configuration (Settings > Authentication > LDAP):${NC}"
echo "  Server:          ldap://localhost (or ldap://openldap if SentriKat is in Docker)"
echo "  Port:            389"
echo "  Base DN:         dc=sentrikat,dc=test"
echo "  Bind DN:         cn=readonly,dc=sentrikat,dc=test"
echo "  Bind Password:   readonly"
echo "  Search Filter:   (uid={username})"
echo "  Username Attr:   uid"
echo "  Email Attr:      mail"
echo ""
echo "  Test Users:"
echo "    john.doe     / password123  (regular user)"
echo "    jane.admin   / password123  (admin group)"
echo "    marco.rossi  / password123  (regular user)"
echo ""
echo -e "${BLUE}SAML Configuration (Settings > Authentication > SAML):${NC}"
echo "  IdP Metadata URL:  $IDP_METADATA_URL"
echo "  SP Entity ID:      sentrikat-saml"
echo "  SP ACS URL:        ${SENTRIKAT_URL}/saml/acs"
echo "  SP SLS URL:        ${SENTRIKAT_URL}/saml/sls  (optional)"
echo ""
echo "  Keycloak Admin:    http://localhost:8080  (admin / admin)"
echo "  Keycloak Realm:    sentrikat"
echo ""
echo "  Test Users (Keycloak-local):"
echo "    testuser    / password123"
echo "    testadmin   / password123"
echo ""
echo "  LDAP Users (federated via Keycloak):"
echo "    john.doe    / password123"
echo "    jane.admin  / password123"
echo "    marco.rossi / password123"
echo ""
echo -e "${BLUE}SAML works with OpenLDAP?${NC}"
echo "  YES - Keycloak federates OpenLDAP users. When a user logs in via SAML,"
echo "  Keycloak can authenticate them against OpenLDAP. So LDAP users can login"
echo "  via SAML SSO (through Keycloak) OR directly via LDAP (through SentriKat)."
echo ""
echo -e "${BLUE}Syslog / SIEM Configuration (Settings > SIEM / Syslog):${NC}"
echo "  Host:        localhost (or syslog if SentriKat is in Docker)"
echo "  Port:        5514 (mapped from container 514)"
echo "  Protocol:    UDP or TCP"
echo "  Format:      CEF, JSON, or RFC5424"
echo ""
echo "  View messages:  docker logs -f sentrikat-syslog"
echo ""
echo "============================================================================"
echo -e "${YELLOW}Quick Teardown:${NC}  docker compose -f docker-compose.test.yml down -v"
echo "============================================================================"
