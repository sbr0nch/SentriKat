#!/bin/bash
# SentriKat LDAP Test Environment Setup
# Starts OpenLDAP with test users for development

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

echo "=========================================="
echo "SentriKat LDAP Test Environment"
echo "=========================================="
echo ""

# Check for docker-compose
if ! command -v docker-compose &> /dev/null; then
    if command -v docker &> /dev/null && docker compose version &> /dev/null; then
        COMPOSE_CMD="docker compose"
    else
        echo "Error: docker-compose is not installed"
        exit 1
    fi
else
    COMPOSE_CMD="docker-compose"
fi

# Parse arguments
case "${1:-start}" in
    start)
        echo "Starting LDAP test environment..."
        $COMPOSE_CMD -f docker-compose.ldap.yml up -d

        echo ""
        echo "Waiting for LDAP to be ready..."
        sleep 5

        # Check if healthy
        if docker exec sentrikat-openldap ldapsearch -x -H ldap://localhost:389 -b "dc=sentrikat,dc=local" -D "cn=admin,dc=sentrikat,dc=local" -w admin123 "(objectClass=organization)" > /dev/null 2>&1; then
            echo ""
            echo "LDAP server is ready!"
            echo ""
            echo "=========================================="
            echo "Access Information:"
            echo "=========================================="
            echo "LDAP Server:    ldap://localhost:389"
            echo "phpLDAPadmin:   http://localhost:8080"
            echo ""
            echo "Admin DN:       cn=admin,dc=sentrikat,dc=local"
            echo "Admin Password: admin123"
            echo ""
            echo "=========================================="
            echo "SentriKat LDAP Settings:"
            echo "=========================================="
            echo "Server:         ldap://localhost"
            echo "Port:           389"
            echo "Base DN:        dc=sentrikat,dc=local"
            echo "Bind DN:        cn=admin,dc=sentrikat,dc=local"
            echo "Username Attr:  uid"
            echo "Email Attr:     mail"
            echo ""
            echo "Test users: 17 users across 4 departments"
            echo "See ldap/README.md for full list"
        else
            echo "Warning: LDAP may not be fully ready yet"
            echo "Check logs with: docker-compose -f docker-compose.ldap.yml logs -f"
        fi
        ;;

    stop)
        echo "Stopping LDAP test environment..."
        $COMPOSE_CMD -f docker-compose.ldap.yml down
        echo "LDAP environment stopped"
        ;;

    reset)
        echo "Resetting LDAP test environment..."
        $COMPOSE_CMD -f docker-compose.ldap.yml down -v
        $COMPOSE_CMD -f docker-compose.ldap.yml up -d
        echo "LDAP environment reset and restarted"
        ;;

    status)
        echo "LDAP environment status:"
        $COMPOSE_CMD -f docker-compose.ldap.yml ps
        ;;

    logs)
        $COMPOSE_CMD -f docker-compose.ldap.yml logs -f
        ;;

    test)
        echo "Testing LDAP connection..."
        if docker exec sentrikat-openldap ldapsearch -x -H ldap://localhost:389 -b "ou=Users,dc=sentrikat,dc=local" -D "cn=admin,dc=sentrikat,dc=local" -w admin123 "(objectClass=person)" 2>/dev/null | grep -c "uid:" ; then
            echo "users found in LDAP"
        else
            echo "Error: Could not connect to LDAP or no users found"
            exit 1
        fi
        ;;

    *)
        echo "Usage: $0 {start|stop|reset|status|logs|test}"
        echo ""
        echo "Commands:"
        echo "  start   - Start LDAP test environment"
        echo "  stop    - Stop LDAP test environment"
        echo "  reset   - Reset all data and restart"
        echo "  status  - Show container status"
        echo "  logs    - Follow container logs"
        echo "  test    - Test LDAP connection"
        exit 1
        ;;
esac
