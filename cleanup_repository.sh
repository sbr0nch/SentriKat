#!/bin/bash
# Cleanup old/obsolete files from repository

echo "=========================================="
echo "SentriKat Repository Cleanup"
echo "=========================================="
echo ""

# Files to remove (obsolete/duplicate)
FILES_TO_REMOVE=(
    "diagnose.sh"
    "fix_permissions.sh"
    "migrate_add_criticality.py"
    "migrate_add_cvss.py"
    "migrate_multi_tenancy.py"
    "setup_complete_database.py"
    "setup_database_safe.py"
    "fix_and_restart.sh"
    "force_login.py"
    "ENTERPRISE_ANALYSIS.md"
    "SETUP_GUIDE.md"
    "UPDATE_GUIDE.md"
    "DEPLOYMENT_GUIDE.md"
    "SETTINGS_AND_ENV_GUIDE.md"
)

echo "Files to be removed:"
for file in "${FILES_TO_REMOVE[@]}"; do
    if [ -f "$file" ]; then
        echo "  - $file"
    fi
done

echo ""
read -p "Proceed with cleanup? (y/N): " confirm

if [[ $confirm =~ ^[Yy]$ ]]; then
    for file in "${FILES_TO_REMOVE[@]}"; do
        if [ -f "$file" ]; then
            git rm "$file"
            echo "✓ Removed $file"
        fi
    done

    echo ""
    echo "✓ Cleanup complete!"
    echo ""
    echo "Files kept:"
    echo "  ✅ LICENSE.md - Legal"
    echo "  ✅ INSTALLATION_GUIDE.md - Main setup docs"
    echo "  ✅ LDAP_CONFIGURATION_GUIDE.md - LDAP setup"
    echo "  ✅ LDAP_RBAC_IMPLEMENTATION_GUIDE.md - LDAP advanced"
    echo "  ✅ ENTERPRISE_READINESS.md - Enterprise features"
    echo "  ✅ TESTING_CHECKLIST.md - Original testing"
    echo "  ✅ COMPREHENSIVE_TESTING_GUIDE.md - NEW comprehensive testing"
    echo "  ✅ generate_secret_key.py - Utility"
    echo "  ✅ seed_service_catalog.py - Needed for setup"
    echo "  ✅ start_fresh.sh - Dev utility"
    echo "  ✅ enrich_cvss.py - Functionality"
    echo "  ✅ update_admin_roles.py - Utility"
    echo "  ✅ check_user.py - Debug utility"
    echo "  ✅ audit_system.py - Diagnostic"
    echo "  ✅ sync_ldap_settings.py - LDAP utility"
    echo ""
    echo "Next step: git commit -m 'Clean up obsolete files and documentation'"
else
    echo "Cleanup cancelled"
fi
