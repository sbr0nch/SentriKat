# LDAP Test Environment

This directory contains configuration for a local OpenLDAP test environment for SentriKat development.

## Quick Start

```bash
# Start LDAP server
docker-compose -f docker-compose.ldap.yml up -d

# Check if running
docker-compose -f docker-compose.ldap.yml ps

# View logs
docker-compose -f docker-compose.ldap.yml logs -f openldap

# Stop
docker-compose -f docker-compose.ldap.yml down
```

## Access

| Service | URL | Credentials |
|---------|-----|-------------|
| LDAP Server | ldap://localhost:389 | cn=admin,dc=sentrikat,dc=local / admin123 |
| phpLDAPadmin | http://localhost:8080 | Login DN: cn=admin,dc=sentrikat,dc=local |

## SentriKat LDAP Settings

Configure these settings in SentriKat Admin Panel > Settings > LDAP:

| Setting | Value |
|---------|-------|
| LDAP Server | ldap://localhost |
| Port | 389 |
| Base DN | dc=sentrikat,dc=local |
| Bind DN | cn=admin,dc=sentrikat,dc=local |
| Bind Password | admin123 |
| Username Attribute | uid |
| Email Attribute | mail |
| Search Filter | (uid={username}) |
| Use TLS | No |

## Test Users

### IT Department (ou=IT)
| Username | Name | Email | Role |
|----------|------|-------|------|
| admin.user | Admin User | admin.user@sentrikat.local | Super Admin |
| mike.johnson | Mike Johnson | mike.johnson@sentrikat.local | Org Admin |
| john.doe | John Doe | john.doe@sentrikat.local | User |
| charlie.davis | Charlie Davis | charlie.davis@sentrikat.local | User |
| grace.martinez | Grace Martinez | grace.martinez@sentrikat.local | User |

### Security Department (ou=Security)
| Username | Name | Email | Role |
|----------|------|-------|------|
| sarah.chen | Sarah Chen | sarah.chen@sentrikat.local | Super Admin |
| emma.wilson | Emma Wilson | emma.wilson@sentrikat.local | Org Admin |
| alice.jones | Alice Jones | alice.jones@sentrikat.local | User |
| frank.garcia | Frank Garcia | frank.garcia@sentrikat.local | User |
| ivy.hernandez | Ivy Hernandez | ivy.hernandez@sentrikat.local | User |

### Engineering Department (ou=Engineering)
| Username | Name | Email | Role |
|----------|------|-------|------|
| jane.smith | Jane Smith | jane.smith@sentrikat.local | User |
| bob.williams | Bob Williams | bob.williams@sentrikat.local | User |
| david.brown | David Brown | david.brown@sentrikat.local | Manager |
| james.anderson | James Anderson | james.anderson@sentrikat.local | Manager |
| diana.miller | Diana Miller | diana.miller@sentrikat.local | User |
| henry.rodriguez | Henry Rodriguez | henry.rodriguez@sentrikat.local | User |

### Management (ou=Management)
| Username | Name | Email | Role |
|----------|------|-------|------|
| lisa.taylor | Lisa Taylor | lisa.taylor@sentrikat.local | Manager |

## Test Groups

| Group DN | Description | Members |
|----------|-------------|---------|
| cn=SentriKat-Admins,ou=Groups,dc=sentrikat,dc=local | Super Administrators | admin.user, sarah.chen |
| cn=SentriKat-OrgAdmins,ou=Groups,dc=sentrikat,dc=local | Org Administrators | mike.johnson, emma.wilson |
| cn=SentriKat-Managers,ou=Groups,dc=sentrikat,dc=local | Managers | david.brown, lisa.taylor, james.anderson |
| cn=SentriKat-Users,ou=Groups,dc=sentrikat,dc=local | Regular Users | All other users |
| cn=IT-Team,ou=Groups,dc=sentrikat,dc=local | IT Department | IT staff |
| cn=Security-Team,ou=Groups,dc=sentrikat,dc=local | Security Department | Security staff |

## Testing LDAP Connection

```bash
# Test connection
ldapsearch -x -H ldap://localhost:389 \
  -D "cn=admin,dc=sentrikat,dc=local" \
  -w admin123 \
  -b "dc=sentrikat,dc=local" \
  "(objectClass=person)"

# Search for specific user
ldapsearch -x -H ldap://localhost:389 \
  -D "cn=admin,dc=sentrikat,dc=local" \
  -w admin123 \
  -b "ou=Users,dc=sentrikat,dc=local" \
  "(uid=john.doe)"

# List all groups
ldapsearch -x -H ldap://localhost:389 \
  -D "cn=admin,dc=sentrikat,dc=local" \
  -w admin123 \
  -b "ou=Groups,dc=sentrikat,dc=local" \
  "(objectClass=groupOfNames)"
```

## Troubleshooting

### Container won't start
```bash
# Check logs
docker-compose -f docker-compose.ldap.yml logs openldap

# Reset data (removes all users)
docker-compose -f docker-compose.ldap.yml down -v
docker-compose -f docker-compose.ldap.yml up -d
```

### Can't connect from SentriKat
1. Ensure Docker container is running
2. Check port 389 is not blocked by firewall
3. Verify LDAP settings in admin panel match values above
4. Use `uid` as username attribute (not `sAMAccountName`)

### Users not loading
- Make sure to use wildcard `*` search or specific username
- Check Base DN is correct: `dc=sentrikat,dc=local`
- Verify bind credentials work via phpLDAPadmin
