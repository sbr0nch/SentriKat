#!/bin/bash
# Populate LDAP with realistic test users
# One user will have email: sotadenis94@gmail.com

echo "🔄 Populating OpenLDAP with realistic test data..."

# Wait for LDAP to be ready
sleep 2

# Create OUs if they don't exist
docker exec sentrikat-ldap ldapadd -x -D "cn=admin,dc=sentrikat,dc=local" -w admin123 2>/dev/null << 'OUEOF'
dn: ou=users,dc=sentrikat,dc=local
objectClass: organizationalUnit
ou: users

dn: ou=groups,dc=sentrikat,dc=local
objectClass: organizationalUnit
ou: groups
OUEOF

# Add realistic test users
docker exec sentrikat-ldap ldapadd -x -D "cn=admin,dc=sentrikat,dc=local" -w admin123 << 'USEREOF'
dn: uid=denis.sota,ou=users,dc=sentrikat,dc=local
objectClass: inetOrgPerson
objectClass: posixAccount
objectClass: shadowAccount
uid: denis.sota
cn: Denis Sota
sn: Sota
givenName: Denis
displayName: Denis Sota
mail: sotadenis94@gmail.com
userPassword: Welcome123!
uidNumber: 10001
gidNumber: 10001
homeDirectory: /home/denis.sota

dn: uid=sarah.johnson,ou=users,dc=sentrikat,dc=local
objectClass: inetOrgPerson
objectClass: posixAccount
objectClass: shadowAccount
uid: sarah.johnson
cn: Sarah Johnson
sn: Johnson
givenName: Sarah
displayName: Sarah Johnson
mail: sarah.johnson@company.com
userPassword: Pass123!
uidNumber: 10002
gidNumber: 10002
homeDirectory: /home/sarah.johnson

dn: uid=michael.chen,ou=users,dc=sentrikat,dc=local
objectClass: inetOrgPerson
objectClass: posixAccount
objectClass: shadowAccount
uid: michael.chen
cn: Michael Chen
sn: Chen
givenName: Michael
displayName: Michael Chen
mail: michael.chen@company.com
userPassword: Pass123!
uidNumber: 10003
gidNumber: 10003
homeDirectory: /home/michael.chen

dn: uid=emily.rodriguez,ou=users,dc=sentrikat,dc=local
objectClass: inetOrgPerson
objectClass: posixAccount
objectClass: shadowAccount
uid: emily.rodriguez
cn: Emily Rodriguez
sn: Rodriguez
givenName: Emily
displayName: Emily Rodriguez
mail: emily.rodriguez@company.com
userPassword: Pass123!
uidNumber: 10004
gidNumber: 10004
homeDirectory: /home/emily.rodriguez

dn: uid=david.kim,ou=users,dc=sentrikat,dc=local
objectClass: inetOrgPerson
objectClass: posixAccount
objectClass: shadowAccount
uid: david.kim
cn: David Kim
sn: Kim
givenName: David
displayName: David Kim
mail: david.kim@company.com
userPassword: Pass123!
uidNumber: 10005
gidNumber: 10005
homeDirectory: /home/david.kim

dn: uid=jessica.brown,ou=users,dc=sentrikat,dc=local
objectClass: inetOrgPerson
objectClass: posixAccount
objectClass: shadowAccount
uid: jessica.brown
cn: Jessica Brown
sn: Brown
givenName: Jessica
displayName: Jessica Brown
mail: jessica.brown@company.com
userPassword: Pass123!
uidNumber: 10006
gidNumber: 10006
homeDirectory: /home/jessica.brown

dn: uid=james.wilson,ou=users,dc=sentrikat,dc=local
objectClass: inetOrgPerson
objectClass: posixAccount
objectClass: shadowAccount
uid: james.wilson
cn: James Wilson
sn: Wilson
givenName: James
displayName: James Wilson
mail: james.wilson@company.com
userPassword: Pass123!
uidNumber: 10007
gidNumber: 10007
homeDirectory: /home/james.wilson

dn: uid=amanda.taylor,ou=users,dc=sentrikat,dc=local
objectClass: inetOrgPerson
objectClass: posixAccount
objectClass: shadowAccount
uid: amanda.taylor
cn: Amanda Taylor
sn: Taylor
givenName: Amanda
displayName: Amanda Taylor
mail: amanda.taylor@company.com
userPassword: Pass123!
uidNumber: 10008
gidNumber: 10008
homeDirectory: /home/amanda.taylor

dn: uid=robert.martinez,ou=users,dc=sentrikat,dc=local
objectClass: inetOrgPerson
objectClass: posixAccount
objectClass: shadowAccount
uid: robert.martinez
cn: Robert Martinez
sn: Martinez
givenName: Robert
displayName: Robert Martinez
mail: robert.martinez@company.com
userPassword: Pass123!
uidNumber: 10009
gidNumber: 10009
homeDirectory: /home/robert.martinez

dn: uid=linda.anderson,ou=users,dc=sentrikat,dc=local
objectClass: inetOrgPerson
objectClass: posixAccount
objectClass: shadowAccount
uid: linda.anderson
cn: Linda Anderson
sn: Anderson
givenName: Linda
displayName: Linda Anderson
mail: linda.anderson@company.com
userPassword: Pass123!
uidNumber: 10010
gidNumber: 10010
homeDirectory: /home/linda.anderson

dn: uid=john.thompson,ou=users,dc=sentrikat,dc=local
objectClass: inetOrgPerson
objectClass: posixAccount
objectClass: shadowAccount
uid: john.thompson
cn: John Thompson
sn: Thompson
givenName: John
displayName: John Thompson
mail: john.thompson@company.com
userPassword: Pass123!
uidNumber: 10011
gidNumber: 10011
homeDirectory: /home/john.thompson

dn: uid=maria.garcia,ou=users,dc=sentrikat,dc=local
objectClass: inetOrgPerson
objectClass: posixAccount
objectClass: shadowAccount
uid: maria.garcia
cn: Maria Garcia
sn: Garcia
givenName: Maria
displayName: Maria Garcia
mail: maria.garcia@company.com
userPassword: Pass123!
uidNumber: 10012
gidNumber: 10012
homeDirectory: /home/maria.garcia

dn: uid=william.lee,ou=users,dc=sentrikat,dc=local
objectClass: inetOrgPerson
objectClass: posixAccount
objectClass: shadowAccount
uid: william.lee
cn: William Lee
sn: Lee
givenName: William
displayName: William Lee
mail: william.lee@company.com
userPassword: Pass123!
uidNumber: 10013
gidNumber: 10013
homeDirectory: /home/william.lee

dn: uid=jennifer.white,ou=users,dc=sentrikat,dc=local
objectClass: inetOrgPerson
objectClass: posixAccount
objectClass: shadowAccount
uid: jennifer.white
cn: Jennifer White
sn: White
givenName: Jennifer
displayName: Jennifer White
mail: jennifer.white@company.com
userPassword: Pass123!
uidNumber: 10014
gidNumber: 10014
homeDirectory: /home/jennifer.white

dn: uid=christopher.harris,ou=users,dc=sentrikat,dc=local
objectClass: inetOrgPerson
objectClass: posixAccount
objectClass: shadowAccount
uid: christopher.harris
cn: Christopher Harris
sn: Harris
givenName: Christopher
displayName: Christopher Harris
mail: christopher.harris@company.com
userPassword: Pass123!
uidNumber: 10015
gidNumber: 10015
homeDirectory: /home/christopher.harris

dn: uid=patricia.clark,ou=users,dc=sentrikat,dc=local
objectClass: inetOrgPerson
objectClass: posixAccount
objectClass: shadowAccount
uid: patricia.clark
cn: Patricia Clark
sn: Clark
givenName: Patricia
displayName: Patricia Clark
mail: patricia.clark@company.com
userPassword: Pass123!
uidNumber: 10016
gidNumber: 10016
homeDirectory: /home/patricia.clark

dn: uid=daniel.lewis,ou=users,dc=sentrikat,dc=local
objectClass: inetOrgPerson
objectClass: posixAccount
objectClass: shadowAccount
uid: daniel.lewis
cn: Daniel Lewis
sn: Lewis
givenName: Daniel
displayName: Daniel Lewis
mail: daniel.lewis@company.com
userPassword: Pass123!
uidNumber: 10017
gidNumber: 10017
homeDirectory: /home/daniel.lewis

dn: uid=barbara.robinson,ou=users,dc=sentrikat,dc=local
objectClass: inetOrgPerson
objectClass: posixAccount
objectClass: shadowAccount
uid: barbara.robinson
cn: Barbara Robinson
sn: Robinson
givenName: Barbara
displayName: Barbara Robinson
mail: barbara.robinson@company.com
userPassword: Pass123!
uidNumber: 10018
gidNumber: 10018
homeDirectory: /home/barbara.robinson

dn: uid=matthew.walker,ou=users,dc=sentrikat,dc=local
objectClass: inetOrgPerson
objectClass: posixAccount
objectClass: shadowAccount
uid: matthew.walker
cn: Matthew Walker
sn: Walker
givenName: Matthew
displayName: Matthew Walker
mail: matthew.walker@company.com
userPassword: Pass123!
uidNumber: 10019
gidNumber: 10019
homeDirectory: /home/matthew.walker

dn: uid=nancy.hall,ou=users,dc=sentrikat,dc=local
objectClass: inetOrgPerson
objectClass: posixAccount
objectClass: shadowAccount
uid: nancy.hall
cn: Nancy Hall
sn: Hall
givenName: Nancy
displayName: Nancy Hall
mail: nancy.hall@company.com
userPassword: Pass123!
uidNumber: 10020
gidNumber: 10020
homeDirectory: /home/nancy.hall

dn: uid=anthony.young,ou=users,dc=sentrikat,dc=local
objectClass: inetOrgPerson
objectClass: posixAccount
objectClass: shadowAccount
uid: anthony.young
cn: Anthony Young
sn: Young
givenName: Anthony
displayName: Anthony Young
mail: anthony.young@company.com
userPassword: Pass123!
uidNumber: 10021
gidNumber: 10021
homeDirectory: /home/anthony.young

dn: uid=karen.allen,ou=users,dc=sentrikat,dc=local
objectClass: inetOrgPerson
objectClass: posixAccount
objectClass: shadowAccount
uid: karen.allen
cn: Karen Allen
sn: Allen
givenName: Karen
displayName: Karen Allen
mail: karen.allen@company.com
userPassword: Pass123!
uidNumber: 10022
gidNumber: 10022
homeDirectory: /home/karen.allen

dn: uid=thomas.king,ou=users,dc=sentrikat,dc=local
objectClass: inetOrgPerson
objectClass: posixAccount
objectClass: shadowAccount
uid: thomas.king
cn: Thomas King
sn: King
givenName: Thomas
displayName: Thomas King
mail: thomas.king@company.com
userPassword: Pass123!
uidNumber: 10023
gidNumber: 10023
homeDirectory: /home/thomas.king

dn: uid=betty.wright,ou=users,dc=sentrikat,dc=local
objectClass: inetOrgPerson
objectClass: posixAccount
objectClass: shadowAccount
uid: betty.wright
cn: Betty Wright
sn: Wright
givenName: Betty
displayName: Betty Wright
mail: betty.wright@company.com
userPassword: Pass123!
uidNumber: 10024
gidNumber: 10024
homeDirectory: /home/betty.wright

dn: uid=steven.lopez,ou=users,dc=sentrikat,dc=local
objectClass: inetOrgPerson
objectClass: posixAccount
objectClass: shadowAccount
uid: steven.lopez
cn: Steven Lopez
sn: Lopez
givenName: Steven
displayName: Steven Lopez
mail: steven.lopez@company.com
userPassword: Pass123!
uidNumber: 10025
gidNumber: 10025
homeDirectory: /home/steven.lopez

dn: uid=helen.hill,ou=users,dc=sentrikat,dc=local
objectClass: inetOrgPerson
objectClass: posixAccount
objectClass: shadowAccount
uid: helen.hill
cn: Helen Hill
sn: Hill
givenName: Helen
displayName: Helen Hill
mail: helen.hill@company.com
userPassword: Pass123!
uidNumber: 10026
gidNumber: 10026
homeDirectory: /home/helen.hill

dn: uid=kevin.green,ou=users,dc=sentrikat,dc=local
objectClass: inetOrgPerson
objectClass: posixAccount
objectClass: shadowAccount
uid: kevin.green
cn: Kevin Green
sn: Green
givenName: Kevin
displayName: Kevin Green
mail: kevin.green@company.com
userPassword: Pass123!
uidNumber: 10027
gidNumber: 10027
homeDirectory: /home/kevin.green

dn: uid=dorothy.baker,ou=users,dc=sentrikat,dc=local
objectClass: inetOrgPerson
objectClass: posixAccount
objectClass: shadowAccount
uid: dorothy.baker
cn: Dorothy Baker
sn: Baker
givenName: Dorothy
displayName: Dorothy Baker
mail: dorothy.baker@company.com
userPassword: Pass123!
uidNumber: 10028
gidNumber: 10028
homeDirectory: /home/dorothy.baker

dn: uid=ryan.nelson,ou=users,dc=sentrikat,dc=local
objectClass: inetOrgPerson
objectClass: posixAccount
objectClass: shadowAccount
uid: ryan.nelson
cn: Ryan Nelson
sn: Nelson
givenName: Ryan
displayName: Ryan Nelson
mail: ryan.nelson@company.com
userPassword: Pass123!
uidNumber: 10029
gidNumber: 10029
homeDirectory: /home/ryan.nelson

dn: uid=lisa.carter,ou=users,dc=sentrikat,dc=local
objectClass: inetOrgPerson
objectClass: posixAccount
objectClass: shadowAccount
uid: lisa.carter
cn: Lisa Carter
sn: Carter
givenName: Lisa
displayName: Lisa Carter
mail: lisa.carter@company.com
userPassword: Pass123!
uidNumber: 10030
gidNumber: 10030
homeDirectory: /home/lisa.carter
USEREOF

# Add test groups
docker exec sentrikat-ldap ldapadd -x -D "cn=admin,dc=sentrikat,dc=local" -w admin123 << 'GROUPEOF'
dn: cn=administrators,ou=groups,dc=sentrikat,dc=local
objectClass: groupOfNames
cn: administrators
member: uid=denis.sota,ou=users,dc=sentrikat,dc=local
member: uid=sarah.johnson,ou=users,dc=sentrikat,dc=local

dn: cn=security-team,ou=groups,dc=sentrikat,dc=local
objectClass: groupOfNames
cn: security-team
member: uid=denis.sota,ou=users,dc=sentrikat,dc=local
member: uid=michael.chen,ou=users,dc=sentrikat,dc=local
member: uid=emily.rodriguez,ou=users,dc=sentrikat,dc=local
member: uid=david.kim,ou=users,dc=sentrikat,dc=local

dn: cn=developers,ou=groups,dc=sentrikat,dc=local
objectClass: groupOfNames
cn: developers
member: uid=jessica.brown,ou=users,dc=sentrikat,dc=local
member: uid=james.wilson,ou=users,dc=sentrikat,dc=local
member: uid=amanda.taylor,ou=users,dc=sentrikat,dc=local
member: uid=robert.martinez,ou=users,dc=sentrikat,dc=local
member: uid=linda.anderson,ou=users,dc=sentrikat,dc=local
member: uid=john.thompson,ou=users,dc=sentrikat,dc=local

dn: cn=qa-team,ou=groups,dc=sentrikat,dc=local
objectClass: groupOfNames
cn: qa-team
member: uid=maria.garcia,ou=users,dc=sentrikat,dc=local
member: uid=william.lee,ou=users,dc=sentrikat,dc=local
member: uid=jennifer.white,ou=users,dc=sentrikat,dc=local

dn: cn=support,ou=groups,dc=sentrikat,dc=local
objectClass: groupOfNames
cn: support
member: uid=christopher.harris,ou=users,dc=sentrikat,dc=local
member: uid=patricia.clark,ou=users,dc=sentrikat,dc=local
member: uid=daniel.lewis,ou=users,dc=sentrikat,dc=local
member: uid=barbara.robinson,ou=users,dc=sentrikat,dc=local

dn: cn=managers,ou=groups,dc=sentrikat,dc=local
objectClass: groupOfNames
cn: managers
member: uid=matthew.walker,ou=users,dc=sentrikat,dc=local
member: uid=nancy.hall,ou=users,dc=sentrikat,dc=local
member: uid=anthony.young,ou=users,dc=sentrikat,dc=local
GROUPEOF

echo ""
echo "✅ LDAP populated with 30 realistic test users!"
echo ""
echo "👤 Special User:"
echo "  - denis.sota / Welcome123! (sotadenis94@gmail.com) - in administrators & security-team groups"
echo ""
echo "📊 User Distribution:"
echo "  - 30 total users"
echo "  - Groups: administrators, security-team, developers, qa-team, support, managers"
echo ""
echo "🔐 Default password for other users: Pass123!"
echo ""
