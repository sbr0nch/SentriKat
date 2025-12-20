# SentriKat Testing Guide - LDAP & SMTP

This guide helps you test LDAP authentication and SMTP email features using local Docker containers.

## Quick Start

### 1. Start Test Servers

```bash
cd /home/user/SentriKat

# Start MailHog (SMTP) and OpenLDAP servers
docker-compose -f docker-compose.test.yml up -d

# Wait 10 seconds for LDAP to initialize
sleep 10

# Populate LDAP with test users and groups
chmod +x setup_test_ldap.sh
./setup_test_ldap.sh
```

### 2. Access Web Interfaces

- **MailHog (Email Testing)**: http://localhost:8025
  - All emails sent by SentriKat will appear here
  - No emails actually sent to real addresses

- **phpLDAPadmin (LDAP Management)**: http://localhost:8080
  - Login DN: `cn=admin,dc=sentrikat,dc=local`
  - Password: `admin123`

---

## SMTP Configuration (MailHog)

### In SentriKat Settings → SMTP Settings:

```
SMTP Host: localhost
SMTP Port: 1025
SMTP Username: (leave empty)
SMTP Password: (leave empty)
Use TLS: ❌ Unchecked
Use SSL: ❌ Unchecked
From Email: noreply@sentrikat.local
From Name: SentriKat Alerts
```

### Test Email:
1. Go to Settings → SMTP Settings
2. Enter the configuration above
3. Click "Test Connection" or send a test alert
4. Open http://localhost:8025 to see the email!

---

## LDAP Configuration

### In SentriKat Settings → LDAP Settings:

```
LDAP Server: localhost
LDAP Port: 389
Use SSL: ❌ Unchecked
Use TLS: ❌ Unchecked

Bind DN: cn=admin,dc=sentrikat,dc=local
Bind Password: admin123

User Search Base: ou=users,dc=sentrikat,dc=local
User Search Filter: (uid={username})
Username Attribute: uid
Email Attribute: mail
Full Name Attribute: cn

Group Search Base: ou=groups,dc=sentrikat,dc=local
Group Search Filter: (member={dn})
Group Name Attribute: cn
```

---

## Test Users

| Username | Password | Email | Groups |
|----------|----------|-------|--------|
| john.doe | password123 | john.doe@sentrikat.local | developers, security-team |
| jane.smith | password123 | jane.smith@sentrikat.local | developers |
| admin.user | admin123 | admin.user@sentrikat.local | admins, security-team |

### Login Test:
1. Go to SentriKat login page
2. Try logging in with: `john.doe` / `password123`
3. Should authenticate via LDAP!

---

## Test Groups

| Group Name | Members |
|------------|---------|
| admins | admin.user |
| developers | john.doe, jane.smith |
| security-team | admin.user, john.doe |

### Group Mapping Test:
1. Go to Settings → LDAP Groups
2. Click "Discover Groups"
3. Search Base: `ou=groups,dc=sentrikat,dc=local`
4. Should find: admins, developers, security-team
5. Map groups to SentriKat roles

---

## Testing Workflows

### Test LDAP Authentication:
```bash
# 1. Enable LDAP in SentriKat settings
# 2. Try login with john.doe / password123
# 3. Check user was created in SentriKat
# 4. Verify user's email is john.doe@sentrikat.local
```

### Test LDAP Group Sync:
```bash
# 1. Map LDAP group "admins" → SentriKat role "org_admin"
# 2. Login as admin.user
# 3. Verify user has org_admin role
# 4. Add admin.user to "developers" group in phpLDAPadmin
# 5. Trigger group sync in SentriKat
# 6. Verify group membership updated
```

### Test Email Notifications:
```bash
# 1. Configure SMTP settings (see above)
# 2. Assign a product to an organization
# 3. Check MailHog (http://localhost:8025) for notification email
# 4. Verify email contains product details
# 5. Test removing org from product → check email again
```

---

## Troubleshooting

### LDAP Connection Failed:
```bash
# Check LDAP is running
docker ps | grep ldap

# Test LDAP connection manually
ldapsearch -x -H ldap://localhost:389 -D "cn=admin,dc=sentrikat,dc=local" -w admin123 -b "dc=sentrikat,dc=local"

# Check LDAP logs
docker logs sentrikat-ldap
```

### SMTP Not Sending:
```bash
# Check MailHog is running
docker ps | grep mailhog

# MailHog logs
docker logs sentrikat-mailhog

# Test SMTP manually with telnet
telnet localhost 1025
```

### View All LDAP Users:
```bash
docker exec sentrikat-ldap ldapsearch -x -D "cn=admin,dc=sentrikat,dc=local" -w admin123 -b "ou=users,dc=sentrikat,dc=local"
```

### View All LDAP Groups:
```bash
docker exec sentrikat-ldap ldapsearch -x -D "cn=admin,dc=sentrikat,dc=local" -w admin123 -b "ou=groups,dc=sentrikat,dc=local"
```

---

## Stop Test Servers

```bash
# Stop containers
docker-compose -f docker-compose.test.yml down

# Stop and remove all data (clean slate)
docker-compose -f docker-compose.test.yml down -v
```

---

## Real-World Migration

When ready to use real LDAP/SMTP servers:

1. **LDAP**: Replace `localhost:389` with your company's LDAP server
2. **SMTP**: Replace MailHog settings with real SMTP server (Gmail, Office365, etc.)
3. Update Search Bases to match your LDAP structure (e.g., `ou=People,dc=company,dc=com`)
4. Update filters and attributes to match your LDAP schema

---

## Notes

- ⚠️ **This setup is for TESTING ONLY** - not production ready
- No SSL/TLS for simplicity (enable in production!)
- Passwords stored in plaintext in LDAP (use proper hashing in production)
- MailHog doesn't actually send emails (use real SMTP in production)
- All data is ephemeral unless you keep Docker volumes
