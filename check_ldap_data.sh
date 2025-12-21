#!/bin/bash
echo "🔍 Checking LDAP data..."
echo ""

echo "1️⃣ Checking if container is running:"
docker ps | grep ldap || echo "❌ LDAP container not found"
echo ""

echo "2️⃣ Searching for all users in LDAP:"
docker exec sentrikat-ldap ldapsearch -x -D "cn=admin,dc=sentrikat,dc=local" -w admin123 -b "ou=users,dc=sentrikat,dc=local" "(objectClass=person)" uid cn mail 2>&1 | head -50
echo ""

echo "3️⃣ Counting users:"
docker exec sentrikat-ldap ldapsearch -x -D "cn=admin,dc=sentrikat,dc=local" -w admin123 -b "ou=users,dc=sentrikat,dc=local" "(objectClass=person)" uid 2>&1 | grep "^uid:" | wc -l
echo ""

echo "4️⃣ Testing LDAP connection from localhost:"
nc -zv localhost 389 2>&1 || echo "❌ Cannot connect to LDAP on localhost:389"
echo ""

echo "5️⃣ Checking specific user denis.sota:"
docker exec sentrikat-ldap ldapsearch -x -D "cn=admin,dc=sentrikat,dc=local" -w admin123 -b "ou=users,dc=sentrikat,dc=local" "(uid=denis.sota)" 2>&1
