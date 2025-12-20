#!/bin/bash
# Setup test LDAP data for SentriKat testing

echo "Setting up test LDAP data..."

# Wait for LDAP to be ready
sleep 5

# Add organizational units
docker exec sentrikat-ldap ldapadd -x -D "cn=admin,dc=sentrikat,dc=local" -w admin123 << EOF
dn: ou=users,dc=sentrikat,dc=local
objectClass: organizationalUnit
ou: users

dn: ou=groups,dc=sentrikat,dc=local
objectClass: organizationalUnit
ou: groups
EOF

# Add test users
docker exec sentrikat-ldap ldapadd -x -D "cn=admin,dc=sentrikat,dc=local" -w admin123 << EOF
dn: uid=john.doe,ou=users,dc=sentrikat,dc=local
objectClass: inetOrgPerson
objectClass: posixAccount
objectClass: shadowAccount
uid: john.doe
cn: John Doe
sn: Doe
givenName: John
mail: john.doe@sentrikat.local
userPassword: password123
uidNumber: 10001
gidNumber: 10001
homeDirectory: /home/john.doe

dn: uid=jane.smith,ou=users,dc=sentrikat,dc=local
objectClass: inetOrgPerson
objectClass: posixAccount
objectClass: shadowAccount
uid: jane.smith
cn: Jane Smith
sn: Smith
givenName: Jane
mail: jane.smith@sentrikat.local
userPassword: password123
uidNumber: 10002
gidNumber: 10002
homeDirectory: /home/jane.smith

dn: uid=admin.user,ou=users,dc=sentrikat,dc=local
objectClass: inetOrgPerson
objectClass: posixAccount
objectClass: shadowAccount
uid: admin.user
cn: Admin User
sn: User
givenName: Admin
mail: admin.user@sentrikat.local
userPassword: admin123
uidNumber: 10003
gidNumber: 10003
homeDirectory: /home/admin.user
EOF

# Add test groups
docker exec sentrikat-ldap ldapadd -x -D "cn=admin,dc=sentrikat,dc=local" -w admin123 << EOF
dn: cn=admins,ou=groups,dc=sentrikat,dc=local
objectClass: groupOfNames
cn: admins
member: uid=admin.user,ou=users,dc=sentrikat,dc=local

dn: cn=developers,ou=groups,dc=sentrikat,dc=local
objectClass: groupOfNames
cn: developers
member: uid=john.doe,ou=users,dc=sentrikat,dc=local
member: uid=jane.smith,ou=users,dc=sentrikat,dc=local

dn: cn=security-team,ou=groups,dc=sentrikat,dc=local
objectClass: groupOfNames
cn: security-team
member: uid=admin.user,ou=users,dc=sentrikat,dc=local
member: uid=john.doe,ou=users,dc=sentrikat,dc=local
EOF

echo ""
echo "✅ LDAP test data created!"
echo ""
echo "Test Users:"
echo "  - john.doe / password123 (john.doe@sentrikat.local)"
echo "  - jane.smith / password123 (jane.smith@sentrikat.local)"
echo "  - admin.user / admin123 (admin.user@sentrikat.local)"
echo ""
echo "Test Groups:"
echo "  - admins (admin.user)"
echo "  - developers (john.doe, jane.smith)"
echo "  - security-team (admin.user, john.doe)"
