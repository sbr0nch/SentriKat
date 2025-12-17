# LDAP / Active Directory Configuration Guide

## Overview

SentriKat supports LDAP/Active Directory authentication, allowing users to log in with their corporate credentials. This guide explains how to configure LDAP authentication properly.

## Important Concepts

### LDAP Users Cannot Be Created Directly

**Key Point:** LDAP users are **discovered automatically** when they log in for the first time. You cannot create LDAP users through the admin panel - only local users can be created there.

**How it works:**
1. Configure LDAP settings (server, bind credentials, search filters)
2. User attempts to log in with their AD/LDAP username and password
3. SentriKat validates credentials against LDAP server
4. On successful authentication, user account is automatically created
5. Admin can then assign organization and roles to the LDAP user

## Configuration Fields

### Required Settings

#### 1. LDAP Server
- **Field:** `ldap_server`
- **Example:** `ldap://dc01.company.com` or `ldaps://dc01.company.com`
- **Description:** Your LDAP/AD server hostname or IP
- **Note:** Use `ldaps://` for SSL/TLS encryption

#### 2. Port
- **Field:** `ldap_port`
- **Default:** `389` (LDAP) or `636` (LDAPS)
- **Description:** LDAP server port

#### 3. Base DN (Distinguished Name)
- **Field:** `ldap_base_dn`
- **Example:** `DC=company,DC=com`
- **Description:** The base DN where user searches will begin
- **How to find:** Run `dsquery` on Windows or check with your AD admin

#### 4. Bind DN (Service Account)
- **Field:** `ldap_bind_dn`
- **Example:** `CN=SentriKat Service,OU=Service Accounts,DC=company,DC=com`
- **Description:** Distinguished Name of a service account with read permissions
- **Requirements:**
  - Must have read access to search for users in the directory
  - Does NOT need admin rights
  - Recommend creating a dedicated service account

#### 5. Bind Password
- **Field:** `ldap_bind_password`
- **Description:** Password for the service account
- **Security:** Encrypted in database, never displayed in UI for security

### Optional Settings

#### Search Filter
- **Field:** `ldap_search_filter`
- **Default:** `(sAMAccountName={username})`
- **Description:** LDAP query filter to find users
- **Common Filters:**
  - Active Directory: `(sAMAccountName={username})`
  - Generic LDAP: `(uid={username})`
  - Email-based: `(mail={username}@company.com)`
- **Note:** `{username}` is replaced with the login username

#### Username Attribute
- **Field:** `ldap_username_attr`
- **Default:** `sAMAccountName`
- **Description:** LDAP attribute containing the username
- **Common Values:**
  - Active Directory: `sAMAccountName`
  - Generic LDAP: `uid` or `cn`

#### Email Attribute
- **Field:** `ldap_email_attr`
- **Default:** `mail`
- **Description:** LDAP attribute containing user's email address

#### Use TLS/STARTTLS
- **Field:** `ldap_use_tls`
- **Default:** `false`
- **Description:** Upgrade connection to TLS using STARTTLS
- **Note:** Different from LDAPS - this upgrades an unencrypted connection

## Example Configurations

### Example 1: Active Directory (Standard)

```
LDAP Server: ldap://dc01.bonelabs.com
Port: 389
Base DN: DC=bonelabs,DC=com
Bind DN: CN=sentrikat-svc,OU=Service Accounts,DC=bonelabs,DC=com
Bind Password: [your-service-account-password]
Search Filter: (sAMAccountName={username})
Username Attr: sAMAccountName
Email Attr: mail
Use TLS: true (recommended)
```

### Example 2: Active Directory with SSL

```
LDAP Server: ldaps://dc01.bonelabs.com
Port: 636
Base DN: DC=bonelabs,DC=com
Bind DN: CN=sentrikat-svc,OU=Service Accounts,DC=bonelabs,DC=com
Bind Password: [your-service-account-password]
Search Filter: (sAMAccountName={username})
Username Attr: sAMAccountName
Email Attr: mail
Use TLS: false (already using SSL)
```

### Example 3: OpenLDAP

```
LDAP Server: ldap://ldap.company.com
Port: 389
Base DN: ou=users,dc=company,dc=com
Bind DN: cn=readonly,dc=company,dc=com
Bind Password: [your-bind-password]
Search Filter: (uid={username})
Username Attr: uid
Email Attr: mail
Use TLS: true
```

## Testing LDAP Configuration

1. Fill in all LDAP settings in Admin Panel → Settings → LDAP
2. Click **"Test Connection"** button
3. Verify you see: ✓ Successfully connected to LDAP server

**If test fails:**
- Check server hostname/IP is correct and reachable
- Verify port is correct (389 for LDAP, 636 for LDAPS)
- Confirm Bind DN and password are correct
- Check firewall rules allow connection
- Verify service account has read permissions

## User Login Flow

1. **User visits login page**
2. **Enters username and password**
3. **SentriKat searches LDAP:**
   - Binds to LDAP using service account
   - Searches for user using search filter
   - Finds user's DN
4. **Authenticates user:**
   - Attempts bind with user's DN and provided password
   - If successful, authentication passes
5. **Creates/updates user account:**
   - First login: Creates new user with `auth_type='ldap'`
   - Subsequent logins: Updates last login timestamp
6. **User logged in successfully**

## Managing LDAP Users

### Creating LDAP Users
- ❌ Cannot create through Admin Panel
- ✅ Users created automatically on first successful login
- ✅ Admin assigns organization and roles after first login

### Editing LDAP Users
- ✅ Can change: organization, role, permissions
- ❌ Cannot change: username, auth type
- ❌ Cannot set password (managed by LDAP)

### Disabling LDAP Users
- Set user status to "Inactive" in Admin Panel
- User can no longer log in even with valid LDAP credentials

## Troubleshooting

### "LDAP bind credentials not configured"
- Ensure Bind DN and Bind Password are filled in
- Password fields are hidden for security - if you previously saved a password, it's still there

### "Failed to bind to LDAP server"
- Verify Bind DN format is correct (full distinguished name)
- Check Bind Password is correct
- Test with ldapsearch or similar tool to verify credentials

### "User not found in LDAP"
- Check Base DN is correct
- Verify Search Filter matches your directory structure
- Confirm user exists in the search scope

### "Connection timeout"
- Check LDAP server hostname/IP is reachable
- Verify firewall allows connection on LDAP port
- Try using IP address instead of hostname

## Security Best Practices

1. **Use LDAPS or STARTTLS** - Encrypt LDAP traffic
2. **Dedicated Service Account** - Create a specific account for SentriKat
3. **Minimal Permissions** - Service account only needs read access
4. **Regular Password Rotation** - Rotate service account password periodically
5. **Monitor Failed Logins** - Watch for suspicious authentication attempts

## Integration with .env File

LDAP settings can be pre-configured via environment variables (useful for Docker):

```bash
# Enable LDAP
LDAP_ENABLED=true

# Server Settings
LDAP_SERVER=ldap://dc01.company.com
LDAP_PORT=389

# Bind Credentials
LDAP_BIND_DN=CN=sentrikat-svc,OU=Service Accounts,DC=company,DC=com
LDAP_BIND_PASSWORD=your-password-here

# Search Settings
LDAP_BASE_DN=DC=company,DC=com
LDAP_SEARCH_FILTER=(sAMAccountName={username})
LDAP_USERNAME_ATTR=sAMAccountName
LDAP_EMAIL_ATTR=mail
LDAP_USE_TLS=true
```

**Note:** Settings in the Admin Panel database take precedence over environment variables. Environment variables are used as defaults if no database settings exist.

## Support

For additional help:
- Check server logs for detailed error messages
- Consult your Active Directory administrator
- Review LDAP search syntax documentation
- Test LDAP connection using tools like `ldapsearch` or JXplorer

## Additional Resources

- [Active Directory LDAP Syntax](https://docs.microsoft.com/en-us/windows/win32/adsi/search-filter-syntax)
- [OpenLDAP Documentation](https://www.openldap.org/doc/)
- [LDAP Search Filter Guide](https://ldap.com/ldap-filters/)
