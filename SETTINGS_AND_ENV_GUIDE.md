# Settings and Environment Variables Guide

## Overview

SentriKat uses a two-tier configuration system:
1. **Environment Variables (.env file)** - For initial deployment and Docker setups
2. **Database Settings (Admin Panel)** - For runtime configuration and changes

This guide explains how both work together and when to use each.

## Configuration Hierarchy

**Priority Order:**
1. **Database Settings** (Admin Panel) - Highest priority
2. **Environment Variables** (.env file) - Used as defaults
3. **Application Defaults** - Built-in fallback values

### How It Works

- When SentriKat starts, it reads environment variables from `.env`
- If no database settings exist, environment variables become the defaults
- Changes made in Admin Panel are saved to database and override `.env` values
- Restarting the application does NOT reset database settings

## Settings Categories

### 1. LDAP / Active Directory Authentication

#### Environment Variables (`.env`)

```bash
# Enable LDAP authentication
LDAP_ENABLED=true

# LDAP Server Configuration
LDAP_SERVER=ldap://dc01.company.com
LDAP_PORT=389

# Service Account Credentials
LDAP_BIND_DN=CN=sentrikat-svc,OU=Service Accounts,DC=company,DC=com
LDAP_BIND_PASSWORD=your-service-account-password

# Directory Search Configuration
LDAP_BASE_DN=DC=company,DC=com
LDAP_SEARCH_FILTER=(sAMAccountName={username})
LDAP_USERNAME_ATTR=sAMAccountName
LDAP_EMAIL_ATTR=mail
LDAP_USE_TLS=true
```

#### Admin Panel

Navigate to: **Admin Panel → Settings → LDAP**

- All LDAP settings can be configured through the UI
- Passwords are encrypted and hidden for security
- Click "Test Connection" to verify settings
- Settings persist across application restarts

**When to use each:**
- **Environment Variables**: Initial deployment, Docker containers, automated provisioning
- **Admin Panel**: Post-deployment changes, testing different configurations, production tweaks

---

### 2. Global SMTP Settings

#### Environment Variables (`.env`)

```bash
# SMTP Server Configuration
SMTP_HOST=smtp.gmail.com
SMTP_PORT=587
SMTP_USERNAME=alerts@company.com
SMTP_PASSWORD=your-app-password

# Email Sender Information
SMTP_FROM_EMAIL=sentrikat-alerts@company.com
SMTP_FROM_NAME=SentriKat Security Alerts

# TLS/SSL Configuration
SMTP_USE_TLS=true
```

#### Admin Panel

Navigate to: **Admin Panel → Settings → Global SMTP**

- Configure fallback SMTP for all organizations
- Organizations can override with their own SMTP settings
- Test email sends to current user's email address
- Passwords are encrypted in database

**Email Sending Logic:**
1. Check if organization has custom SMTP configured
2. If yes, use organization's SMTP
3. If no, fall back to global SMTP settings

**When to use each:**
- **Environment Variables**: Single-tenant deployments, simple setups
- **Admin Panel**: Multi-tenant systems, per-organization email configs

---

### 3. Sync Schedule (CISA KEV)

#### Environment Variables (`.env`)

```bash
# Sync Configuration
AUTO_SYNC_ENABLED=true
SYNC_INTERVAL=daily
SYNC_TIME=02:00

# CISA KEV Feed URL
CISA_KEV_URL=https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json

# NVD API Configuration (optional)
NVD_API_KEY=your-nvd-api-key-here
```

#### Admin Panel

Navigate to: **Admin Panel → Settings → Sync Schedule**

- **Scope**: Global (applies to all organizations)
- Configure automatic sync schedule
- Set sync time (UTC timezone)
- Add NVD API key for enhanced CVE data

**Sync Intervals:**
- `daily` - Once per day at specified time
- `weekly` - Once per week
- `manual` - No automatic sync (admin-triggered only)

**When to use each:**
- **Environment Variables**: Production deployments with fixed schedule
- **Admin Panel**: Adjusting sync times, testing different intervals

---

### 4. General System Settings

#### Environment Variables (`.env`)

```bash
# Application Configuration
SECRET_KEY=your-secret-key-here-change-this
DEBUG=false

# Database Configuration
DATABASE_URL=sqlite:///data/sentrikat.db
# or for PostgreSQL:
# DATABASE_URL=postgresql://user:pass@localhost/sentrikat

# Session Configuration
SESSION_TIMEOUT=480  # minutes (8 hours)
SESSION_COOKIE_SECURE=true  # Set true for HTTPS deployments

# SSL/TLS Verification
VERIFY_SSL=true  # Set false to disable SSL verification (not recommended)

# Proxy Configuration (if needed)
HTTP_PROXY=http://proxy.company.com:8080
HTTPS_PROXY=http://proxy.company.com:8080
NO_PROXY=localhost,127.0.0.1,.local

# Flask Configuration
FLASK_PORT=5001
FLASK_HOST=0.0.0.0
```

#### Admin Panel

Navigate to: **Admin Panel → Settings → General**

- SSL verification settings
- Proxy configuration
- Session timeout
- Runtime-configurable options

**When to use each:**
- **Environment Variables**: Server configuration, ports, database URLs, secrets
- **Admin Panel**: Operational settings that may need adjustment

---

## Common Configuration Scenarios

### Scenario 1: Fresh Installation

**Recommended Approach:**

1. Create `.env` file with basic settings:
   ```bash
   SECRET_KEY=generated-secret-key
   DATABASE_URL=sqlite:///data/sentrikat.db
   FLASK_PORT=5001
   ```

2. Start SentriKat

3. Complete setup wizard

4. Configure LDAP/SMTP through Admin Panel

**Why:** Setup wizard creates initial admin user, then configure everything through UI.

---

### Scenario 2: Docker Deployment

**Recommended Approach:**

1. Use environment variables in `docker-compose.yml`:
   ```yaml
   environment:
     - DATABASE_URL=postgresql://user:pass@db:5432/sentrikat
     - LDAP_ENABLED=true
     - LDAP_SERVER=ldap://dc01.company.com
     - SMTP_HOST=smtp.company.com
     - SMTP_PORT=587
   ```

2. Mount `.env` file as volume (for secrets)

3. Admin Panel for runtime changes

**Why:** Environment variables integrate well with container orchestration.

---

### Scenario 3: Multi-Tenant Setup

**Recommended Approach:**

1. Minimal `.env` for infrastructure:
   ```bash
   SECRET_KEY=...
   DATABASE_URL=postgresql://...
   ```

2. Use Admin Panel for:
   - Per-organization SMTP settings
   - Organization-specific alert configurations
   - User management

**Why:** Database settings support multi-tenancy better than environment variables.

---

### Scenario 4: CI/CD Pipeline

**Recommended Approach:**

1. Store secrets in secret manager (Vault, AWS Secrets Manager, etc.)

2. Inject as environment variables:
   ```bash
   export SECRET_KEY=$(vault read -field=value secret/sentrikat/secret-key)
   export DATABASE_URL=$(vault read -field=value secret/sentrikat/db-url)
   ```

3. Use environment variables for:
   - Database connection
   - External API keys
   - Service credentials

**Why:** CI/CD tools integrate with secret managers via environment variables.

---

## Password and Secret Handling

### Encrypted Settings (Database)

These are **encrypted** when stored in database:
- SMTP passwords
- LDAP bind passwords
- NVD API keys

**Security Notes:**
- Passwords never displayed in Admin Panel after saving
- "Leave blank to keep existing" - password persists if field is empty
- Encryption uses application `SECRET_KEY`

### Plain Environment Variables

Environment variables in `.env` are **not encrypted**:
- Protect `.env` file with proper permissions: `chmod 600 .env`
- Never commit `.env` to version control (add to `.gitignore`)
- Use secret managers for production deployments

---

## Best Practices

### 1. Secret Management

**Development:**
```bash
# .env file (git-ignored)
SECRET_KEY=dev-secret-key
LDAP_BIND_PASSWORD=dev-password
```

**Production:**
```bash
# Use secret manager or vault
SECRET_KEY=$(vault read -field=value secret/sentrikat/secret-key)
```

### 2. Configuration Changes

**Infrastructure Changes** (requires restart):
- Database URL
- Flask port/host
- Secret key

**Operational Changes** (no restart):
- SMTP settings
- LDAP configuration
- Sync schedule
- Alert settings

Use Admin Panel for operational changes to avoid restarts.

### 3. Backup and Migration

**Export current settings:**
```bash
# Database settings are in the database
sqlite3 data/sentrikat.db "SELECT * FROM system_settings;"
```

**Migrate settings:**
1. Export database settings
2. Set as environment variables in new deployment
3. Or migrate database directly

### 4. Multi-Environment Setup

```bash
# .env.development
DEBUG=true
DATABASE_URL=sqlite:///data/dev.db

# .env.staging
DEBUG=false
DATABASE_URL=postgresql://staging-db/sentrikat

# .env.production
DEBUG=false
DATABASE_URL=postgresql://prod-db/sentrikat
SESSION_COOKIE_SECURE=true
```

Load appropriate `.env` file per environment.

---

## Troubleshooting

### "Settings not saving"

**Symptom:** Changes in Admin Panel don't persist

**Solutions:**
1. Check database write permissions
2. Verify `DATABASE_URL` is correct
3. Check application logs for errors
4. Ensure database is not read-only

### "Password field empty after save"

**This is normal!** Passwords are hidden for security.

- Password **is saved** in database (encrypted)
- Leave field blank to keep existing password
- Enter new password only to change it

### "Environment variables not working"

**Check:**
1. `.env` file is in application root directory
2. `.env` file is loaded (check with `python -c "from config import Config; print(Config.LDAP_SERVER)"`)
3. Database settings may be overriding environment variables
4. Restart application after changing `.env`

### "Settings reset after restart"

**This should NOT happen.** If it does:
- Database settings should persist across restarts
- Check database file exists and is writable
- Verify no automation is resetting database

---

## Reference: All Environment Variables

### Application Core
```bash
SECRET_KEY=                 # Flask secret key (required)
DATABASE_URL=               # Database connection string
DEBUG=false                 # Enable debug mode (dev only)
FLASK_PORT=5001            # Port to run on
FLASK_HOST=0.0.0.0         # Host to bind to
```

### Authentication
```bash
ENABLE_AUTH=true           # Enable authentication system
LDAP_ENABLED=false         # Enable LDAP authentication
LDAP_SERVER=               # LDAP server URL
LDAP_PORT=389              # LDAP port
LDAP_BASE_DN=              # Base DN for searches
LDAP_BIND_DN=              # Service account DN
LDAP_BIND_PASSWORD=        # Service account password
LDAP_SEARCH_FILTER=        # User search filter
LDAP_USERNAME_ATTR=        # Username attribute
LDAP_EMAIL_ATTR=           # Email attribute
LDAP_USE_TLS=false         # Use STARTTLS
```

### Email / SMTP
```bash
SMTP_HOST=                 # SMTP server
SMTP_PORT=587              # SMTP port
SMTP_USERNAME=             # SMTP username
SMTP_PASSWORD=             # SMTP password
SMTP_FROM_EMAIL=           # From email address
SMTP_FROM_NAME=            # From display name
SMTP_USE_TLS=true          # Use TLS/STARTTLS
```

### Sync / Feeds
```bash
AUTO_SYNC_ENABLED=false    # Enable automatic sync
SYNC_INTERVAL=daily        # Sync interval
SYNC_TIME=02:00           # Sync time (UTC)
CISA_KEV_URL=             # CISA KEV feed URL
NVD_API_KEY=              # NVD API key
```

### Security & Network
```bash
SESSION_TIMEOUT=480        # Session timeout (minutes)
SESSION_COOKIE_SECURE=false # Secure cookies (HTTPS only)
VERIFY_SSL=true            # Verify SSL certificates
HTTP_PROXY=                # HTTP proxy URL
HTTPS_PROXY=               # HTTPS proxy URL
NO_PROXY=                  # Proxy bypass list
```

---

## Summary

**Use Environment Variables (.env) for:**
- Initial configuration
- Infrastructure settings (database, ports, hosts)
- Docker/container deployments
- Secrets in development
- CI/CD automation

**Use Admin Panel (Database) for:**
- Runtime configuration changes
- Per-organization settings
- Operational adjustments
- Testing different configurations
- Multi-tenant setups

**Remember:**
- Database settings override environment variables
- Passwords are encrypted in database
- Changes in Admin Panel persist across restarts
- Protect `.env` files with proper permissions
- Use secret managers for production secrets

For more help, see:
- `LDAP_CONFIGURATION_GUIDE.md` - Detailed LDAP setup
- `INSTALLATION_GUIDE.md` - Installation instructions
- `DEPLOYMENT_GUIDE.md` - Production deployment guide
