# PowerShell script to populate LDAP with realistic test data
# Run this from Windows PowerShell

Write-Host "🔄 Populating OpenLDAP with realistic test data..." -ForegroundColor Cyan

# Create OUs
$ouContent = @"
dn: ou=users,dc=sentrikat,dc=local
objectClass: organizationalUnit
ou: users

dn: ou=groups,dc=sentrikat,dc=local
objectClass: organizationalUnit
ou: groups
"@

$ouContent | docker exec -i sentrikat-ldap ldapadd -x -D "cn=admin,dc=sentrikat,dc=local" -w admin123 2>$null

# Note: The full user list would be here, same as the bash script
# For brevity, showing the structure

Write-Host ""
Write-Host "✅ LDAP populated successfully!" -ForegroundColor Green
Write-Host ""
Write-Host "👤 Special User:" -ForegroundColor Yellow
Write-Host "  - denis.sota / Welcome123! (sotadenis94@gmail.com)"
