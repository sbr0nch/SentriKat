# SentriKat Configuration Guide

This guide covers all configuration options for SentriKat, including environment variables, GUI settings, and their priorities.

---

## Table of Contents

- [Configuration Overview](#configuration-overview)
- [Environment Variables](#environment-variables)
- [GUI Settings](#gui-settings)
- [Configuration Priority](#configuration-priority)
- [Generating Security Keys](#generating-security-keys)
- [LDAP Configuration](#ldap-configuration)
- [SMTP Configuration](#smtp-configuration)
- [Proxy Configuration](#proxy-configuration)
- [Security Settings](#security-settings)

---

## Configuration Overview

SentriKat can be configured through two methods:

1. **Environment Variables** - Set in `.env` file or system environment
2. **GUI Settings** - Configured through the web interface (Administration > Settings)

### Configuration Files

| File | Purpose |
|------|---------|
| `.env` | Environment variables (primary configuration) |
| `config.py` | Application defaults and environment parsing |
| Database | GUI settings stored in `system_settings` table |

---

## Environment Variables

### Required Variables (Production)

These **must** be set for production deployments:

| Variable | Description | How to Generate |
|----------|-------------|-----------------|
| `SECRET_KEY` | Flask session signing key (64+ hex chars) | `python -c "import secrets; print(secrets.token_hex(32))"` |
| `ENCRYPTION_KEY` | Fernet key for encrypting sensitive data | `python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"` |

### Optional Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `DATABASE_URL` | `sqlite:///sentrikat.db` | Database connection string |
| `FLASK_ENV` | `development` | Set to `production` for production mode |
| `SENTRIKAT_URL` | (auto-detected) | Base URL for email links |

### Database Configuration

**SQLite (Default):**
```bash
DATABASE_URL=sqlite:///sentrikat.db
# Or absolute path:
DATABASE_URL=sqlite:////opt/sentrikat/data/sentrikat.db
```

**PostgreSQL:**
```bash
DATABASE_URL=postgresql://username:password@hostname:5432/database_name
```

### Session & Cookie Settings

| Variable | Default | Description |
|----------|---------|-------------|
| `SESSION_COOKIE_SECURE` | `true` | Require HTTPS for cookies |
| `PERMANENT_SESSION_LIFETIME` | 4 hours | Session timeout |

> **Note**: Set `SESSION_COOKIE_SECURE=false` for local HTTP development only.

### Sync Settings

| Variable | Default | Description |
|----------|---------|-------------|
| `SYNC_HOUR` | `2` | Hour for automatic sync (0-23) |
| `SYNC_MINUTE` | `0` | Minute for automatic sync (0-59) |

### Proxy Settings

| Variable | Description |
|----------|-------------|
| `HTTP_PROXY` | HTTP proxy URL (e.g., `http://proxy:8080`) |
| `HTTPS_PROXY` | HTTPS proxy URL |
| `NO_PROXY` | Comma-separated bypass list |

### SSL Settings

| Variable | Default | Description |
|----------|---------|-------------|
| `VERIFY_SSL` | `true` | Verify SSL certificates for external requests |

> **Warning**: Only set `VERIFY_SSL=false` in corporate environments with SSL inspection.

---

## GUI Settings

GUI settings are configured in **Administration > Settings** and stored in the database.

### Settings Categories

| Category | Settings Included |
|----------|-------------------|
| **LDAP** | Server, port, bind DN, search filter, attributes |
| **SMTP** | Server, port, credentials, from address |
| **Sync** | Auto-sync enable, interval, time, CISA URL |
| **General** | SSL verification, proxy, session timeout |

### Accessing Settings

1. Log in as **Super Admin**
2. Click **Administration** in the navigation bar
3. Select **Settings**
4. Choose the appropriate tab (LDAP, SMTP, Sync, General)

---

## Configuration Priority

When a setting is available in both environment variables and GUI:

```
┌─────────────────────────────────────────────────────────┐
│                  Configuration Priority                  │
├─────────────────────────────────────────────────────────┤
│                                                         │
│   GUI Settings (Database)   ◄── HIGHEST PRIORITY        │
│           ▼                                             │
│   Environment Variables (.env)                          │
│           ▼                                             │
│   Application Defaults (config.py)  ◄── LOWEST         │
│                                                         │
└─────────────────────────────────────────────────────────┘
```

### Why GUI Takes Priority

1. **Runtime Flexibility**: Change settings without restart
2. **User-Friendly**: Non-technical users can modify settings
3. **Audit Trail**: GUI changes are logged with user who made them
4. **Per-Org Settings**: Organizations can have different SMTP configs

### When to Use Environment Variables

Use environment variables for:

- **Initial deployment** before GUI is accessible
- **Docker/Kubernetes** deployments with config maps
- **Secrets management** integration (Vault, AWS Secrets Manager)
- **CI/CD pipelines** automated deployments

### Settings Behavior Table

| Setting | ENV Priority | GUI Priority | Notes |
|---------|--------------|--------------|-------|
| `SECRET_KEY` | **Required** | N/A | Only via environment |
| `ENCRYPTION_KEY` | **Required** | N/A | Only via environment |
| `DATABASE_URL` | **Required** | N/A | Only via environment |
| LDAP Settings | Fallback | **Primary** | GUI overrides ENV |
| SMTP Settings | Fallback | **Primary** | GUI overrides ENV |
| Proxy Settings | Fallback | **Primary** | GUI overrides ENV |
| SSL Verification | Fallback | **Primary** | GUI overrides ENV |

---

## Generating Security Keys

### SECRET_KEY

The `SECRET_KEY` is used to sign session cookies and other security-related data.

**Requirements:**
- Minimum 32 characters
- Random, unpredictable value
- Keep secret and never commit to version control

**Generate with Python:**
```bash
python -c "import secrets; print(secrets.token_hex(32))"
```

**Example output:**
```
a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6q7r8s9t0u1v2w3x4y5z6
```

**Generate with OpenSSL:**
```bash
openssl rand -hex 32
```

### ENCRYPTION_KEY

The `ENCRYPTION_KEY` is used to encrypt sensitive data like LDAP and SMTP passwords stored in the database.

**Requirements:**
- Valid Fernet key (base64-encoded 32-byte key)
- Must remain constant after encrypting data
- Losing this key means encrypted data is unrecoverable

**Generate with Python:**
```bash
python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"
```

**Example output:**
```
ZmDfcTF7_60GrrY182zHd_1TlYjNkWqq6LTSmTNXV0E=
```

### Key Storage Best Practices

1. **Never commit keys to version control**
2. Store in `.env` file with restricted permissions:
   ```bash
   chmod 600 .env
   ```
3. Use secrets management for production:
   - HashiCorp Vault
   - AWS Secrets Manager
   - Azure Key Vault
   - Kubernetes Secrets

### Rotating Keys

**SECRET_KEY Rotation:**
- Rotating invalidates all existing sessions
- Users will need to log in again
- No data loss

**ENCRYPTION_KEY Rotation:**
1. Export all encrypted settings
2. Set new `ENCRYPTION_KEY`
3. Re-encrypt and update all sensitive data
4. Run migration script:
   ```bash
   python encrypt_sensitive_data.py
   ```

---

## LDAP Configuration

### Environment Variables

```bash
# Not recommended - use GUI instead
LDAP_SERVER=ldap://your-ldap-server.com
LDAP_PORT=389
LDAP_BASE_DN=DC=company,DC=com
LDAP_BIND_DN=CN=service_account,OU=Service Accounts,DC=company,DC=com
LDAP_BIND_PW=your_password
LDAP_SEARCH_FILTER=(sAMAccountName={username})
```

### GUI Configuration

Navigate to **Administration > Settings > LDAP**

| Setting | Description | Example |
|---------|-------------|---------|
| **Enable LDAP** | Turn on LDAP authentication | Checked |
| **Server** | LDAP server hostname or IP | `ldap.company.com` |
| **Port** | LDAP port | `389` (LDAP) or `636` (LDAPS) |
| **Use TLS** | Enable STARTTLS | Checked for port 389 |
| **Base DN** | Search base | `DC=company,DC=com` |
| **Bind DN** | Service account DN | `CN=sentrikat,OU=Services,DC=company,DC=com` |
| **Bind Password** | Service account password | (encrypted in database) |
| **Search Filter** | User search filter | `(sAMAccountName={username})` |
| **Username Attribute** | Attribute for username | `sAMAccountName` |
| **Email Attribute** | Attribute for email | `mail` |

### Testing LDAP

1. Configure all settings
2. Click **Test Connection**
3. Verify "Connection successful" message

### Common LDAP Configurations

**Active Directory:**
```
Server: ldap://dc01.company.com
Port: 389
Base DN: DC=company,DC=com
Bind DN: CN=svc_sentrikat,OU=Service Accounts,DC=company,DC=com
Search Filter: (sAMAccountName={username})
Username Attr: sAMAccountName
Email Attr: mail
```

**OpenLDAP:**
```
Server: ldap://ldap.company.com
Port: 389
Base DN: dc=company,dc=com
Bind DN: cn=admin,dc=company,dc=com
Search Filter: (uid={username})
Username Attr: uid
Email Attr: mail
```

---

## SMTP Configuration

### Global SMTP (Super Admin)

Navigate to **Administration > Settings > SMTP**

| Setting | Description | Example |
|---------|-------------|---------|
| **SMTP Host** | Mail server hostname | `smtp.company.com` |
| **SMTP Port** | Mail server port | `587` |
| **Username** | SMTP authentication user | `alerts@company.com` |
| **Password** | SMTP authentication password | (encrypted) |
| **From Email** | Sender email address | `sentrikat@company.com` |
| **From Name** | Sender display name | `SentriKat Alerts` |
| **Use TLS** | Enable STARTTLS | Checked |
| **Use SSL** | Use SSL/TLS connection | Unchecked (use TLS instead) |

### Organization SMTP

Each organization can have its own SMTP settings:

1. Go to **Administration > Organizations**
2. Click **Edit** on the organization
3. Configure SMTP settings in the organization form

**Priority**: Organization SMTP > Global SMTP

### Testing SMTP

1. Configure SMTP settings
2. Click **Send Test Email**
3. Check your inbox for test message

### Common SMTP Configurations

**Office 365:**
```
Host: smtp.office365.com
Port: 587
Use TLS: Yes
Username: your-email@company.com
Password: your-password or app-password
```

**Gmail:**
```
Host: smtp.gmail.com
Port: 587
Use TLS: Yes
Username: your-email@gmail.com
Password: app-specific-password
```

**Internal Relay (no auth):**
```
Host: mailrelay.company.internal
Port: 25
Use TLS: No
Username: (empty)
Password: (empty)
```

---

## Proxy Configuration

### Environment Variables

```bash
HTTP_PROXY=http://proxy.company.com:8080
HTTPS_PROXY=http://proxy.company.com:8080
NO_PROXY=localhost,127.0.0.1,.company.internal
```

### GUI Configuration

Navigate to **Administration > Settings > General**

| Setting | Description |
|---------|-------------|
| **HTTP Proxy** | Proxy for HTTP connections |
| **HTTPS Proxy** | Proxy for HTTPS connections |
| **No Proxy** | Hosts to bypass proxy |

### When Proxy is Used

- CISA KEV feed synchronization
- NVD API calls (if configured)
- Any external HTTP/HTTPS requests

---

## Security Settings

### SSL Certificate Verification

**Environment:**
```bash
VERIFY_SSL=true  # default, recommended
VERIFY_SSL=false # only for SSL inspection environments
```

**GUI:** Administration > Settings > General > Verify SSL Certificates

### Session Security

| Setting | Value | Purpose |
|---------|-------|---------|
| `SESSION_COOKIE_SECURE` | `true` | Only send cookies over HTTPS |
| `SESSION_COOKIE_HTTPONLY` | `true` | Prevent JavaScript access |
| `SESSION_COOKIE_SAMESITE` | `Strict` | CSRF protection |

### Production Security Checklist

- [ ] Set strong `SECRET_KEY`
- [ ] Set `ENCRYPTION_KEY` and run encryption migration
- [ ] Set `FLASK_ENV=production`
- [ ] Use HTTPS with valid certificates
- [ ] Set `SESSION_COOKIE_SECURE=true`
- [ ] Configure proper firewall rules
- [ ] Enable LDAP over TLS (STARTTLS or LDAPS)
- [ ] Use app-specific passwords for SMTP

---

## Example .env File

```bash
# ===========================================
# SentriKat Configuration
# ===========================================

# ----- REQUIRED FOR PRODUCTION -----
SECRET_KEY=your-64-character-hex-string-here
ENCRYPTION_KEY=your-fernet-encryption-key-here

# ----- Database -----
DATABASE_URL=sqlite:////opt/sentrikat/data/sentrikat.db
# DATABASE_URL=postgresql://user:pass@localhost/sentrikat

# ----- Application -----
FLASK_ENV=production
SENTRIKAT_URL=https://sentrikat.company.com

# ----- Session Security -----
SESSION_COOKIE_SECURE=true

# ----- Sync Schedule -----
SYNC_HOUR=2
SYNC_MINUTE=0

# ----- Proxy (if needed) -----
# HTTP_PROXY=http://proxy:8080
# HTTPS_PROXY=http://proxy:8080
# NO_PROXY=localhost,127.0.0.1

# ----- SSL -----
VERIFY_SSL=true
```

---

## Next Steps

- [Installation Guide](INSTALLATION.md) - Install SentriKat
- [User Guide](USER_GUIDE.md) - Learn daily operations
- [Admin Guide](ADMIN_GUIDE.md) - Administration tasks
