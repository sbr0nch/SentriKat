# SENTRIKAT - COMPLETE ARCHITECTURE DOCUMENTATION
## Confidential Business & Technical Document
### For Investors, Buyers & Due Diligence

---

**Document Version:** 1.0.0
**Last Updated:** February 2026
**Classification:** CONFIDENTIAL - NOT FOR PUBLIC DISTRIBUTION
**Author:** SentriKat Development Team

---

## TABLE OF CONTENTS

1. [Executive Summary](#1-executive-summary)
2. [Product Overview](#2-product-overview)
3. [Technology Stack](#3-technology-stack)
4. [System Architecture](#4-system-architecture)
5. [Database Schema](#5-database-schema)
6. [API Reference](#6-api-reference)
7. [Security Implementation](#7-security-implementation)
8. [Integrations](#8-integrations)
9. [Agent System](#9-agent-system)
10. [Licensing System](#10-licensing-system)
11. [Portal & Website (SentriKat-web)](#11-portal--website-sentrikat-web)
12. [Deployment Architecture](#12-deployment-architecture)
13. [Business Model](#13-business-model)
14. [Intellectual Property](#14-intellectual-property)
15. [Appendices](#15-appendices)

---

# 1. EXECUTIVE SUMMARY

## What is SentriKat?

SentriKat is an **Enterprise Vulnerability Management Platform** that helps organizations track and remediate security vulnerabilities in their software inventory. It automatically correlates installed software with known vulnerabilities from authoritative sources (CISA KEV, NVD) and provides actionable alerts.

## Key Value Proposition

| Problem | SentriKat Solution |
|---------|-------------------|
| Organizations don't know what software they have | Push agents auto-discover installed software |
| CVE databases are hard to search | Automatic CPE matching to 800K+ NVD products |
| CISA KEV deadlines are missed | Due date tracking with email/Slack alerts |
| Vulnerability remediation is untracked | Jira/GitHub/GitLab ticket creation |
| No visibility across enterprise | Multi-tenant dashboard with RBAC |

## Platform Components

```
┌─────────────────────────────────────────────────────────────────┐
│                    SENTRIKAT ECOSYSTEM                          │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│  ┌─────────────────┐     ┌─────────────────┐                   │
│  │   SENTRIKAT     │     │  SENTRIKAT-WEB  │                   │
│  │   (Core App)    │     │   (Portal)      │                   │
│  │                 │     │                 │                   │
│  │ • Vuln Mgmt     │     │ • Landing Page  │                   │
│  │ • Dashboard     │     │ • Customer Portal│                  │
│  │ • Agents        │     │ • License Server │                  │
│  │ • Integrations  │     │ • Documentation  │                  │
│  │ • Reporting     │     │ • Downloads      │                  │
│  └─────────────────┘     └─────────────────┘                   │
│           │                       │                             │
│           └───────────┬───────────┘                             │
│                       │                                         │
│              ┌────────▼────────┐                                │
│              │   LICENSE KEY   │                                │
│              │   VALIDATION    │                                │
│              │  (RSA Signed)   │                                │
│              └─────────────────┘                                │
│                                                                 │
└─────────────────────────────────────────────────────────────────┘
```

## Codebase Metrics

| Metric | Value |
|--------|-------|
| Total Python Code | 32,428 lines |
| Database Models | 24 SQLAlchemy models |
| API Endpoints | 80+ REST endpoints |
| Frontend Templates | 6 major pages (800+ KB HTML) |
| External Integrations | 15+ (Jira, LDAP, SAML, etc.) |
| Test Coverage | pytest suite included |

---

# 2. PRODUCT OVERVIEW

## 2.1 Core Features

### Vulnerability Management
- **CISA KEV Sync**: Daily automatic sync with CISA Known Exploited Vulnerabilities catalog
- **NVD Integration**: Search 800,000+ products in National Vulnerability Database
- **CVE Matching**: Automatic correlation between installed software and CVEs
- **EPSS Scoring**: Exploit Prediction Scoring System integration from FIRST.org
- **Due Date Tracking**: CISA BOD 22-01 compliance with deadline alerts

### Asset & Inventory Management
- **Push Agents**: Windows (PowerShell) and Linux (Bash) agents for auto-discovery
- **Software Inventory**: Track installed software across all endpoints
- **Asset Lifecycle**: Online/offline/stale/decommissioned status tracking
- **Multi-Source Import**: PDQ, SCCM, Intune, Lansweeper, CSV, REST API

### Enterprise Authentication
- **Local Authentication**: Username/password with bcrypt hashing
- **LDAP/Active Directory**: Full AD integration with group mapping
- **SAML 2.0 SSO**: Okta, Azure AD, ADFS, Google Workspace support
- **Two-Factor Auth**: TOTP (Google Authenticator compatible)

### Alerting & Notifications
- **Email Alerts**: Critical CVE notifications, daily digests, due date reminders
- **Webhooks**: Slack, Microsoft Teams, Discord, custom HTTP
- **Escalation**: Re-alert if not acknowledged within N days

### Issue Tracking Integration
- **Jira**: Cloud and Server/Data Center support
- **GitHub Issues**: Create issues from CVEs
- **GitLab Issues**: Create issues from CVEs
- **YouTrack**: JetBrains issue tracker
- **Generic Webhook**: Custom integrations

### Reporting & Compliance
- **CISA BOD 22-01**: Compliance dashboard and reports
- **Scheduled Reports**: PDF export via email
- **Vulnerability Trends**: Historical tracking with snapshots
- **Shared Dashboards**: Token-based public links

## 2.2 Editions

| Feature | Demo (Free) | Professional |
|---------|-------------|--------------|
| Users | 1 | Unlimited |
| Organizations | 1 | Unlimited |
| Products | 50 | Unlimited |
| Push Agents | 5 | 10+ (with packs) |
| CISA KEV Sync | ✓ | ✓ |
| NVD Search | ✓ | ✓ |
| LDAP/AD | ✗ | ✓ |
| SAML SSO | ✗ | ✓ |
| Email Alerts | ✗ | ✓ |
| Webhooks | ✗ | ✓ |
| Jira Integration | ✗ | ✓ |
| Scheduled Reports | ✗ | ✓ |
| Backup/Restore | ✗ | ✓ |
| White-Label | ✗ | ✓ |
| API Access | ✗ | ✓ |

---

# 3. TECHNOLOGY STACK

## 3.1 Backend

| Component | Technology | Version | Purpose |
|-----------|------------|---------|---------|
| Language | Python | 3.11+ | Core application |
| Framework | Flask | 3.0+ | Web framework |
| ORM | SQLAlchemy | 2.0+ | Database abstraction |
| Database | PostgreSQL | 15+ | Data persistence |
| Task Queue | APScheduler | 3.10+ | Background jobs |
| Web Server | Gunicorn | 21+ | WSGI server |
| Proxy | nginx | 1.25+ | Reverse proxy, SSL |

## 3.2 Frontend

| Component | Technology | Purpose |
|-----------|------------|---------|
| CSS Framework | Bootstrap 5 | Responsive UI |
| Template Engine | Jinja2 | Server-side rendering |
| Charts | Chart.js | Data visualization |
| Tables | DataTables | Sortable/filterable tables |
| Icons | Font Awesome | UI icons |

## 3.3 Security Libraries

| Library | Purpose |
|---------|---------|
| cryptography | Fernet encryption, RSA signing |
| bcrypt | Password hashing |
| flask-wtf | CSRF protection |
| flask-limiter | Rate limiting |
| python3-saml | SAML/SSO |
| ldap3 | LDAP/AD integration |
| pyotp | TOTP 2FA |

## 3.4 External APIs

| API | Purpose | Rate Limit |
|-----|---------|------------|
| CISA KEV | Vulnerability catalog | None (JSON file) |
| NVD API | CVE/CPE database | 5/30s free, 50/30s with key |
| FIRST EPSS | Exploit scoring | None |
| Jira REST | Ticket creation | Per Jira limits |

## 3.5 Containerization

```dockerfile
# Base image
FROM python:3.11-slim

# Dependencies
- gcc, libpq-dev (PostgreSQL)
- libxml2-dev, libxmlsec1-dev (SAML)

# Runtime
- Gunicorn with 2 workers
- 120 second timeout
- Preload for DB initialization
```

---

# 4. SYSTEM ARCHITECTURE

## 4.1 Directory Structure

```
SentriKat/
├── app/                          # Flask application (32,428 LOC)
│   ├── __init__.py               # App factory, blueprints
│   ├── models.py                 # 24 SQLAlchemy models (2,488 LOC)
│   ├── routes.py                 # Main API routes (4,439 LOC)
│   ├── auth.py                   # Authentication (900+ LOC)
│   ├── licensing.py              # License validation (975 LOC)
│   ├── agent_api.py              # Agent endpoints (2,500+ LOC)
│   ├── cisa_sync.py              # CISA KEV sync (500+ LOC)
│   ├── ldap_*.py                 # LDAP modules (1,500+ LOC)
│   ├── saml_*.py                 # SAML modules (650+ LOC)
│   ├── jira_integration.py       # Jira connector (400+ LOC)
│   ├── email_alerts.py           # Email system (626 LOC)
│   ├── scheduler.py              # Background jobs (468 LOC)
│   ├── encryption.py             # Fernet utils (141 LOC)
│   └── templates/                # Jinja2 templates
│       ├── base.html             # Layout (174 KB)
│       ├── dashboard.html        # Main view (115 KB)
│       ├── admin_panel.html      # Settings (245 KB)
│       └── ...
│
├── agents/                       # Agent scripts
│   ├── sentrikat-agent-windows.ps1
│   └── sentrikat-agent-linux.sh
│
├── static/                       # CSS, JS, images
├── tests/                        # pytest suite
├── nginx/                        # Reverse proxy config
├── docker-compose.yml            # Orchestration
├── Dockerfile                    # Container build
├── requirements.txt              # Python deps (29 packages)
└── .github/workflows/            # CI/CD
    ├── ci.yml                    # Tests on push
    └── release.yml               # Build & publish
```

## 4.2 Request Flow

```
┌──────────┐     ┌──────────┐     ┌──────────┐     ┌──────────┐
│  Client  │────>│  nginx   │────>│ Gunicorn │────>│  Flask   │
│ (Browser)│     │ (Proxy)  │     │ (WSGI)   │     │  (App)   │
└──────────┘     └──────────┘     └──────────┘     └──────────┘
                      │                                  │
                      │ SSL/TLS                          │
                      │ Rate Limiting                    │
                      │ Static Files                     │
                                                        │
                                              ┌──────────▼──────────┐
                                              │     PostgreSQL      │
                                              │     (Database)      │
                                              └─────────────────────┘
```

## 4.3 Background Jobs (APScheduler)

| Job | Schedule | Purpose |
|-----|----------|---------|
| CISA KEV Sync | Daily 02:00 UTC | Fetch latest vulnerabilities |
| Critical CVE Email | Daily 09:00 UTC | Send alert digests |
| Data Retention Cleanup | Daily 03:00 UTC | Delete old logs |
| Vulnerability Snapshot | Daily 02:00 UTC | Historical tracking |
| Scheduled Reports | Every 15 min | Process report queue |
| LDAP Sync | Configurable | Sync users from AD |

---

# 5. DATABASE SCHEMA

## 5.1 Entity Relationship Overview

```
┌─────────────────┐       ┌─────────────────┐
│      User       │──────<│ UserOrganization│>──────│  Organization  │
└─────────────────┘       └─────────────────┘       └─────────────────┘
        │                                                    │
        │                                                    │
        ▼                                                    ▼
┌─────────────────┐                              ┌─────────────────┐
│   AgentApiKey   │                              │     Product     │
└─────────────────┘                              └─────────────────┘
        │                                                │
        ▼                                                ▼
┌─────────────────┐                              ┌─────────────────┐
│      Asset      │<─────────────────────────────│ProductInstallation│
└─────────────────┘                              └─────────────────┘
        │                                                │
        ▼                                                ▼
┌─────────────────┐                              ┌─────────────────┐
│   AgentEvent    │                              │VulnerabilityMatch│
└─────────────────┘                              └─────────────────┘
                                                         │
                                                         ▼
                                                 ┌─────────────────┐
                                                 │  Vulnerability  │
                                                 │   (CISA KEV)    │
                                                 └─────────────────┘
```

## 5.2 Core Tables

### User & Organization

```sql
-- Multi-tenant user management
CREATE TABLE "user" (
    id SERIAL PRIMARY KEY,
    username VARCHAR(100) UNIQUE NOT NULL,
    email VARCHAR(255) UNIQUE NOT NULL,
    password_hash VARCHAR(255),
    auth_type VARCHAR(20) DEFAULT 'local',  -- local, ldap, saml
    role VARCHAR(20) DEFAULT 'user',
    totp_secret VARCHAR(32),  -- 2FA
    failed_login_attempts INTEGER DEFAULT 0,
    locked_until TIMESTAMP,
    last_login TIMESTAMP,
    is_active BOOLEAN DEFAULT TRUE,
    created_at TIMESTAMP DEFAULT NOW()
);

CREATE TABLE organization (
    id SERIAL PRIMARY KEY,
    name VARCHAR(100) UNIQUE NOT NULL,
    display_name VARCHAR(255),
    smtp_host VARCHAR(255),  -- Encrypted
    smtp_password VARCHAR(512),  -- Encrypted
    webhook_url VARCHAR(512),  -- Encrypted
    alert_mode VARCHAR(20) DEFAULT 'daily_reminder',
    is_active BOOLEAN DEFAULT TRUE,
    created_at TIMESTAMP DEFAULT NOW()
);

CREATE TABLE user_organization (
    id SERIAL PRIMARY KEY,
    user_id INTEGER REFERENCES "user"(id),
    organization_id INTEGER REFERENCES organization(id),
    role VARCHAR(20) DEFAULT 'user',  -- super_admin, org_admin, manager, user
    assigned_at TIMESTAMP DEFAULT NOW()
);
```

### Product & Vulnerability

```sql
-- Software inventory
CREATE TABLE product (
    id SERIAL PRIMARY KEY,
    vendor VARCHAR(200) NOT NULL,
    product_name VARCHAR(200) NOT NULL,
    version VARCHAR(100),
    cpe_vendor VARCHAR(200),
    cpe_product VARCHAR(200),
    cpe_uri VARCHAR(500),
    criticality VARCHAR(20) DEFAULT 'medium',
    source VARCHAR(20) DEFAULT 'manual',  -- manual, agent, integration
    approval_status VARCHAR(20) DEFAULT 'approved',
    is_active BOOLEAN DEFAULT TRUE,
    created_at TIMESTAMP DEFAULT NOW()
);

-- CISA KEV vulnerabilities
CREATE TABLE vulnerability (
    id SERIAL PRIMARY KEY,
    cve_id VARCHAR(20) UNIQUE NOT NULL,
    vendor_project VARCHAR(200),
    product VARCHAR(200),
    vulnerability_name TEXT,
    date_added DATE,
    due_date DATE,
    short_description TEXT,
    required_action TEXT,
    known_ransomware BOOLEAN DEFAULT FALSE,
    cvss_score DECIMAL(3,1),
    severity VARCHAR(20),
    epss_score DECIMAL(5,4),
    cpe_data JSONB,  -- Cached CPE entries
    created_at TIMESTAMP DEFAULT NOW()
);

-- Product-to-CVE matching
CREATE TABLE vulnerability_match (
    id SERIAL PRIMARY KEY,
    product_id INTEGER REFERENCES product(id),
    vulnerability_id INTEGER REFERENCES vulnerability(id),
    match_method VARCHAR(20),  -- cpe, keyword, vendor_product
    match_confidence VARCHAR(10),  -- high, medium, low
    acknowledged BOOLEAN DEFAULT FALSE,
    resolution_reason VARCHAR(50),
    snoozed_until DATE,
    first_alerted_at TIMESTAMP,
    created_at TIMESTAMP DEFAULT NOW(),
    UNIQUE(product_id, vulnerability_id)
);
```

### Agent & Asset

```sql
-- Agent API keys
CREATE TABLE agent_api_key (
    id SERIAL PRIMARY KEY,
    organization_id INTEGER REFERENCES organization(id),
    name VARCHAR(100),
    key_hash VARCHAR(64),  -- SHA256
    key_prefix VARCHAR(8),
    max_assets INTEGER DEFAULT 100,
    allowed_ips JSONB,  -- CIDR list
    auto_approve BOOLEAN DEFAULT FALSE,
    last_used_at TIMESTAMP,
    usage_count INTEGER DEFAULT 0,
    expires_at TIMESTAMP,
    is_active BOOLEAN DEFAULT TRUE,
    created_at TIMESTAMP DEFAULT NOW()
);

-- Discovered endpoints
CREATE TABLE asset (
    id SERIAL PRIMARY KEY,
    organization_id INTEGER REFERENCES organization(id),
    hostname VARCHAR(255) NOT NULL,
    ip_address VARCHAR(45),
    fqdn VARCHAR(255),
    os_name VARCHAR(100),
    os_version VARCHAR(100),
    agent_id VARCHAR(36) UNIQUE,
    agent_version VARCHAR(20),
    last_checkin TIMESTAMP,
    last_inventory_at TIMESTAMP,
    status VARCHAR(20) DEFAULT 'online',
    vulnerable_products_count INTEGER DEFAULT 0,
    pending_scan BOOLEAN DEFAULT FALSE,
    tags JSONB,
    is_active BOOLEAN DEFAULT TRUE,
    created_at TIMESTAMP DEFAULT NOW()
);

-- Software on specific asset
CREATE TABLE product_installation (
    id SERIAL PRIMARY KEY,
    asset_id INTEGER REFERENCES asset(id),
    product_id INTEGER REFERENCES product(id),
    version VARCHAR(100),
    install_path VARCHAR(500),
    is_vulnerable BOOLEAN DEFAULT FALSE,
    discovered_at TIMESTAMP DEFAULT NOW(),
    last_seen_at TIMESTAMP,
    UNIQUE(asset_id, product_id)
);
```

## 5.3 Total: 24 Tables

| Category | Tables |
|----------|--------|
| Auth/Users | User, Organization, UserOrganization, SystemSettings |
| Products | Product, ServiceCatalog, ProductExclusion, UserCpeMapping |
| Vulnerabilities | Vulnerability, VulnerabilityMatch, VulnerabilitySnapshot |
| Agents | AgentApiKey, Asset, ProductInstallation, AgentEvent, InventoryJob |
| Integrations | Integration, ImportQueue, AgentRegistration |
| Logging | SyncLog, AlertLog, ScheduledReport, StaleAssetNotification |

---

# 6. API REFERENCE

## 6.1 Authentication Endpoints

```
POST   /api/auth/login               # Username/password login
POST   /api/auth/logout              # End session
POST   /api/auth/2fa/setup           # Enable TOTP
POST   /api/auth/2fa/verify          # Verify TOTP code
GET    /api/auth/status              # Current user info
```

## 6.2 Product Management

```
GET    /api/products                 # List (paginated, filterable)
POST   /api/products                 # Create product
GET    /api/products/<id>            # Get details
PUT    /api/products/<id>            # Update
DELETE /api/products/<id>            # Delete
POST   /api/products/rematch         # Re-run CVE matching
```

## 6.3 Vulnerability Management

```
GET    /api/vulnerabilities          # List CVEs
GET    /api/vulnerabilities/stats    # Counts by severity
GET    /api/vulnerabilities/trends   # Historical data
POST   /api/matches/<id>/acknowledge # Mark as handled
POST   /api/matches/<id>/snooze      # Defer alerts
```

## 6.4 Agent API

```
POST   /api/agent/register           # Self-registration
POST   /api/agent/inventory          # Report software
POST   /api/agent/heartbeat          # Keep-alive
GET    /api/agents/script/windows    # Download PS1
GET    /api/agents/script/linux      # Download SH
```

## 6.5 Integrations

```
GET    /api/integrations             # List integrations
POST   /api/integrations/jira/test   # Test Jira connection
POST   /api/integrations/jira/create-issue  # Create ticket
GET    /api/import/queue             # Pending imports
POST   /api/import/queue/<id>/approve  # Approve import
```

## 6.6 Settings & License

```
GET    /api/settings/ldap            # LDAP config
POST   /api/settings/ldap            # Update LDAP
POST   /api/settings/ldap/test       # Test connection
GET    /api/license                  # License info
POST   /api/license                  # Activate license
GET    /api/license/installation-id  # Hardware ID
```

**Total: 80+ REST endpoints with proper HTTP methods**

---

# 7. SECURITY IMPLEMENTATION

## 7.1 Authentication

| Method | Implementation |
|--------|----------------|
| Local | bcrypt password hashing, configurable policy |
| LDAP | ldap3 library, bind authentication, injection prevention |
| SAML | python3-saml (OneLogin), RSA signature validation |
| 2FA | pyotp TOTP, 30-second codes, QR setup |

## 7.2 Encryption

```python
# Fernet symmetric encryption for sensitive data
from cryptography.fernet import Fernet

# Encrypted values:
- LDAP bind password
- SMTP password
- Webhook URLs/tokens
- Integration API keys
- SAML IdP metadata (optional)

# Format: gAAAAA... (base64-encoded)
# Key: 32-byte random, environment variable
```

## 7.3 Session Security

```python
SESSION_COOKIE_HTTPONLY = True   # No JS access
SESSION_COOKIE_SECURE = True     # HTTPS only
SESSION_COOKIE_SAMESITE = 'Lax'  # CSRF protection
PERMANENT_SESSION_LIFETIME = 4 hours
```

## 7.4 Rate Limiting

```python
# flask-limiter configuration
DEFAULT: 1000/day, 200/hour per IP

# Agent API (per API key):
- Inventory: 60/minute
- Heartbeat: 120/minute

# Password reset: 5/hour
# Login: Lockout after 5 failures
```

## 7.5 OWASP Protections

| Vulnerability | Protection |
|---------------|------------|
| SQL Injection | SQLAlchemy ORM (parameterized) |
| XSS | Jinja2 autoescaping |
| CSRF | flask-wtf tokens |
| Clickjacking | X-Frame-Options: SAMEORIGIN |
| MIME Sniffing | X-Content-Type-Options: nosniff |

## 7.6 Audit Logging

All security events logged:
- Login attempts (success/failure)
- Password changes
- 2FA setup/disable
- License activation
- Settings changes
- User management
- API key operations

---

# 8. INTEGRATIONS

## 8.1 Issue Trackers

| Platform | Features |
|----------|----------|
| Jira Cloud/Server | Projects, issue types, custom fields |
| GitHub Issues | Create from CVE |
| GitLab Issues | Create from CVE |
| YouTrack | Create from CVE |
| Generic Webhook | Custom HTTP POST |

## 8.2 Authentication Providers

| Provider | Protocol |
|----------|----------|
| Active Directory | LDAP v3 |
| OpenLDAP | LDAP v3 |
| Okta | SAML 2.0 |
| Azure AD | SAML 2.0 |
| ADFS | SAML 2.0 |
| Google Workspace | SAML 2.0 |

## 8.3 Inventory Sources

| Source | Method |
|--------|--------|
| Windows Agents | PowerShell registry scan |
| Linux Agents | Package manager queries |
| PDQ Deploy | REST API |
| Microsoft SCCM | Database/WMI |
| Microsoft Intune | Graph API |
| Lansweeper | REST API |
| CSV Import | File upload |

## 8.4 Notification Channels

| Channel | Format |
|---------|--------|
| Email | HTML templates via SMTP |
| Slack | Block Kit JSON |
| Microsoft Teams | Adaptive Cards |
| Discord | Embed JSON |
| Custom Webhook | Configurable JSON |

---

# 9. AGENT SYSTEM

## 9.1 Architecture

```
┌────────────────────────────────────────────────────────┐
│                    ENDPOINT                            │
│  ┌─────────────────────────────────────────────────┐  │
│  │              SentriKat Agent                     │  │
│  │  • Windows: PowerShell (.ps1)                   │  │
│  │  • Linux: Bash (.sh)                            │  │
│  │  • Runs as scheduled task/cron                  │  │
│  │  • Scans registry/package managers              │  │
│  └───────────────────────┬─────────────────────────┘  │
└──────────────────────────┼─────────────────────────────┘
                           │ HTTPS POST
                           │ X-Agent-Key: sk_agent_xxx
                           ▼
┌────────────────────────────────────────────────────────┐
│                  SENTRIKAT SERVER                      │
│  ┌─────────────────────────────────────────────────┐  │
│  │           /api/agent/inventory                   │  │
│  │  • Validate API key                             │  │
│  │  • Rate limit check                             │  │
│  │  • Process inventory                            │  │
│  │  • Match to products                            │  │
│  │  • Queue for CPE matching                       │  │
│  └─────────────────────────────────────────────────┘  │
└────────────────────────────────────────────────────────┘
```

## 9.2 Data Collection

### Windows (PowerShell)
```powershell
# Registry locations scanned:
HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall
HKLM:\Software\Wow6432Node\...\Uninstall  # 32-bit
HKCU:\Software\...\Uninstall              # Per-user

# Additional sources:
Get-Package (PackageManagement)
Get-WindowsFeature
Get-AppxPackage (Store apps)
```

### Linux (Bash)
```bash
# Package managers:
dpkg -l        # Debian/Ubuntu
rpm -qa        # RHEL/CentOS
apk list       # Alpine
pacman -Q      # Arch
snap list      # Snap packages
flatpak list   # Flatpak apps
```

## 9.3 Security

- API keys: SHA256 hashed in database
- IP whitelisting: Optional CIDR filtering
- Rate limiting: Per-key limits
- TLS: HTTPS only
- Input validation: Size limits, sanitization

## 9.4 Deployment

```bash
# Windows (as Administrator):
Invoke-WebRequest -Uri "https://sentrikat/api/agent/script/windows" -OutFile agent.ps1
.\agent.ps1 -Install -Key "sk_agent_xxx"

# Linux (as root):
curl -o agent.sh https://sentrikat/api/agent/script/linux
chmod +x agent.sh
./agent.sh --install --key "sk_agent_xxx"
```

---

# 10. LICENSING SYSTEM

## 10.1 License Format

```
Format: <base64url(JSON_payload)>.<base64url(RSA_signature)>

Signed Payload:
{
  "license_id": "e863e3e3-94d4-42af-901c-cbcf2be11b09",
  "customer": "Acme Corp",
  "email": "admin@acme.com",
  "edition": "pro",                           // Maps to "professional" in SentriKat
  "issued_at": "2026-02-05T16:07:43.990328",
  "expires_at": null,                          // null = perpetual
  "installation_id": "SK-INST-<32-hex-chars>",
  "limits": {
    "max_users": null,                         // null = unlimited (-1 in SentriKat)
    "max_organizations": null,
    "max_products": null,
    "max_agents": 10,
    "max_agent_api_keys": 10
  },
  "features": ["all", "ldap", "sso", "webhooks", "api"]
}

Cryptographic Details:
- Algorithm: RSA-4096 with PKCS1v15 padding + SHA-256
- Signing: json.dumps(payload, sort_keys=True, separators=(',',':'))
- Encoding: base64url (URL-safe base64 with padding)
- Key: License server private key signs, SentriKat app has embedded public key
```

## 10.2 Edition & Limit Mapping

```
SentriKat-web (portal/server)  →  SentriKat (Flask app)
─────────────────────────────────────────────────────────
Edition:  "pro"                →  "professional"
Edition:  "demo"               →  "community"
Limits:   null                 →  -1 (unlimited)
Limits:   10                   →  10 (exact value)
```

## 10.3 Hardware Locking (Installation ID)

```
Generation Priority:
1. SENTRIKAT_INSTALLATION_ID env var (recommended for Docker)
2. Existing ID from data/.installation_id file
3. Auto-generated from system properties (hostname, MAC, etc.)

Format: SK-INST-<32-uppercase-hex-chars>
Example: SK-INST-30E9761FE3895E4377B45AB37658A49C

For Docker: ALWAYS set SENTRIKAT_INSTALLATION_ID in .env
  → Survives container rebuilds
  → Without it, ID changes on every rebuild = license invalidated
```

## 10.4 Complete License Activation Flow

```
┌──────────────┐     ┌──────────────────┐     ┌──────────────────┐
│   Customer   │     │  Portal + Server  │     │    SentriKat     │
│  (Browser)   │     │ (SentriKat-web)   │     │   (Flask App)    │
└──────┬───────┘     └────────┬─────────┘     └────────┬─────────┘
       │                      │                         │
       │  1. Purchase PRO     │                         │
       │─────────────────────>│                         │
       │  (Stripe checkout)   │                         │
       │                      │                         │
       │  2. Get license key  │                         │
       │<─────────────────────│                         │
       │  SK-XXXX-XXXX-XXXX   │                         │
       │                      │                         │
       │  3. Install SentriKat│                         │
       │──────────────────────────────────────────────>│
       │  docker compose up -d│                         │
       │                      │                         │
       │  4. Get Installation ID                        │
       │<─────────────────────────────────────────────│
       │  SK-INST-XXXXXXXX    │ (Admin > License tab)   │
       │                      │                         │
       │  5. Bind Installation│                         │
       │─────────────────────>│                         │
       │  (paste SK-INST-xxx) │                         │
       │                      │                         │
       │                      │  6. Sign license        │
       │                      │  (RSA-4096 + SHA-256)   │
       │                      │                         │
       │  7. Copy signed license                        │
       │<─────────────────────│                         │
       │  SENTRIKAT_LICENSE=  │                         │
       │  eyJ...payload.sig   │                         │
       │                      │                         │
       │  8. Paste in GUI or .env                       │
       │──────────────────────────────────────────────>│
       │                      │                         │
       │                      │  9. SentriKat validates: │
       │                      │  - Strip prefix          │
       │                      │  - Decode base64         │
       │                      │  - Verify RSA signature  │
       │                      │  - Check installation ID │
       │                      │  - Map edition/limits    │
       │                      │  - Save to database      │
       │                      │                         │
       │  10. Professional!   │                         │
       │<─────────────────────────────────────────────│
       │  All features unlocked                         │
```

## 10.5 Input Cleaning (Common Paste Errors)

SentriKat handles these common customer mistakes automatically:

```python
# 1. Portal "Copy to Clipboard" adds prefix:
"SENTRIKAT_LICENSE=eyJ...payload.signature"  →  "eyJ...payload.signature"

# 2. Customer pastes from shell:
"export SENTRIKAT_LICENSE=eyJ..."  →  "eyJ...payload.signature"

# 3. Customer pastes the JSON download file:
{"sentrikat_license": "eyJ...sig", "license_key": "SK-XXXX"}  →  "eyJ...sig"

# 4. Customer wraps in quotes:
'"eyJ...payload.signature"'  →  "eyJ...payload.signature"

# 5. BOM characters, whitespace, newlines: all stripped
```

## 10.6 License Sources & Sync

```
Priority Order (for loading):
1. Database (system_settings.license_key)
2. SENTRIKAT_LICENSE environment variable

Sync Behavior:
- If env var has a license and DB doesn't → auto-saves to DB
- If env var has a DIFFERENT license than DB → updates DB
- GUI always shows the current active license (from DB)
- This means: set SENTRIKAT_LICENSE env var → appears in GUI automatically
```

## 10.7 Public Key Configuration

```
Priority Order (for public key):
1. SENTRIKAT_LICENSE_PUBLIC_KEY env var (PEM content directly)
2. SENTRIKAT_LICENSE_PUBLIC_KEY_FILE env var (path to PEM file)
3. tools/.license_keys/public_key.pem file
4. Default embedded key (RSA-4096, matches license server)

For 99% of installations: the embedded default key works.
Only override if using a self-hosted license server with custom keys.
```

## 10.8 Validation Flow (Detailed)

```
1. Clean input (_clean_license_input)
   - Strip SENTRIKAT_LICENSE= prefix
   - Extract from JSON wrapper
   - Remove BOM, quotes, whitespace

2. Split on "." → payload_b64, signature_b64
   - Must be exactly 2 parts

3. Decode payload (base64url → UTF-8 → JSON)
   - Add base64 padding if needed
   - Parse JSON payload

4. Verify RSA signature
   - Load public key (priority chain)
   - PKCS1v15 + SHA-256
   - Verify against raw payload bytes (NOT re-serialized)

5. Check installation ID
   - payload.installation_id must match this server's ID
   - Mismatch = "License is for a different installation"
   - No installation_id = legacy license, allowed

6. Map editions and limits
   - "pro" → "professional", "demo" → "community"
   - null → -1 (unlimited)

7. Check expiration
   - expires_at null = perpetual (never expires)
   - Expired = revert to Demo mode

8. Apply features and save to database
```

## 10.9 Feature Gating

```python
@requires_professional('Email Alerts')
def send_alert():
    # Returns 403 if Demo edition
    pass

# Limit checks:
check_user_limit()          # Returns False if at limit
check_organization_limit()  # -1 = unlimited
check_agent_limit()         # Based on license + agent packs
```

## 10.10 License Lifecycle

```
Purchase → Bind → Activate → Use → Renew/Expire
   │         │        │        │        │
   │         │        │        │     ┌──┴──┐
   │         │        │        │   Renew  Expire
   │         │        │        │     │      │
   │         │        │        │   New sig  Demo mode
   │         │        │        │            (30-day warning)
   │         │        │        │
   │         │        │     Server Migration:
   │         │        │     → Rebind on portal with new SK-INST-xxx
   │         │        │     → Get new signed license
   │         │        │     → Old license rejected (ID mismatch)
   │         │        │
   │         │     Professional mode (all features)
   │         │     Saved in database, persists across restarts
   │         │
   │      Portal signs with RSA-4096
   │      License locked to installation ID
   │
   Stripe payment → portal account created
```

---

# 11. PORTAL & WEBSITE (SentriKat-web)

## 11.1 Components

```
SentriKat-web/
├── landing/          # Marketing website (Next.js)
├── portal/           # Customer portal (Next.js)
├── license-server/   # License API (FastAPI)
├── docs/            # Documentation (MkDocs)
└── docker-compose.yml
```

## 11.2 License Server (FastAPI)

```python
# License API endpoints:
POST /api/licenses/activate          # Bind installation ID to license
POST /api/licenses/verify-signed     # Verify a signed license string
GET  /api/licenses/{key}             # Get license status
POST /api/licenses/{key}/rebind      # Rebind to new installation ID

# Signing process:
1. Customer binds installation ID via portal
2. Server serializes: json.dumps(payload, sort_keys=True, separators=(',',':'))
3. Signs with RSA-4096 private key (PKCS1v15 + SHA-256)
4. Returns: base64url(payload) + "." + base64url(signature)

# RSA-4096 key pair:
- Private key: /app/keys/license_private.pem (signs licenses, NEVER shipped)
- Public key: /app/keys/license_public.pem (embedded in SentriKat app)
```

## 11.3 Customer Portal (Astro)

Features:
- License management (view, bind, rebind, download)
- "Copy to Clipboard" button (copies SENTRIKAT_LICENSE=<signed_string>)
- "Download as File" button (JSON with sentrikat_license field)
- Download center (latest releases, update scripts)
- Account management (Stripe billing integration)
- Installation guides and documentation links

## 11.4 Release Integration

```yaml
# GitHub Actions workflow notifies portal:
POST /api/releases
{
  "version": "1.0.1",
  "image": "ghcr.io/sbr0nch/sentrikat:1.0.1",
  "download_url": "https://github.com/.../sentrikat-1.0.1.tar.gz"
}
```

---

# 12. DEPLOYMENT ARCHITECTURE

## 12.1 Docker Compose (Standard)

```yaml
services:
  sentrikat:
    image: ghcr.io/sbr0nch/sentrikat:1.0.1
    ports:
      - "5000:5000"
    environment:
      - DATABASE_URL=postgresql://user:pass@db/sentrikat
      - SECRET_KEY=...
      - SENTRIKAT_INSTALLATION_ID=...
    volumes:
      - sentrikat-data:/app/data

  db:
    image: postgres:16-alpine
    volumes:
      - postgres-data:/var/lib/postgresql/data
```

## 12.2 Production (with nginx)

```yaml
services:
  nginx:
    image: nginx:alpine
    ports:
      - "443:443"
    volumes:
      - ./ssl:/etc/nginx/ssl

  sentrikat:
    image: ghcr.io/sbr0nch/sentrikat:1.0.1
    # Internal network only

  db:
    image: postgres:16-alpine
    # Internal network only
```

## 12.3 CI/CD Pipeline

```yaml
# .github/workflows/release.yml
# Triggered by: git tag v1.0.3 -m "Release" && git push origin v1.0.3
on:
  push:
    tags: ["v*.*.*"]

jobs:
  test:        # Run pytest with PostgreSQL
  build:       # Build Docker image, write VERSION file from tag
  push:        # Push to GHCR (ghcr.io/sbr0nch/sentrikat:<version>)
  release:     # Create GitHub Release with sentrikat-<version>.tar.gz
  notify:      # POST to portal API (optional)
```

## 12.4 Update Mechanism

```
Update Scripts (included in release packages):
- scripts/update.sh    (Linux/macOS)
- scripts/update.ps1   (Windows PowerShell)

What gets updated:
✓ Docker image (new code, dependencies)
✓ Application files (app/, static/, templates/)
✓ VERSION file

What is PRESERVED (never touched):
✓ .env file (all configuration)
✓ Database (PostgreSQL volume)
✓ License (stored in database)
✓ Installation ID (env var or data/.installation_id)
✓ Custom certificates
✓ Data directory (uploads, backups)

Usage:
  ./scripts/update.sh              # Auto-update to latest
  ./scripts/update.sh --check      # Check only, no install
  ./scripts/update.sh 1.0.3        # Update to specific version
  .\scripts\update.ps1             # Windows equivalent

Docker users can also:
  docker compose pull && docker compose up -d
```

## 12.5 Versioning

```
Single source of truth: VERSION file in repo root
- Read by app at startup (app/__init__.py → APP_VERSION)
- Displayed in footer, license page, and X-App-Version header
- Set automatically by CI/CD from git tag (v1.0.3 → "1.0.3")
- Update script uses VERSION to detect current vs available version
```

---

# 13. BUSINESS MODEL

## 13.1 Pricing Tiers

| Tier | Price | Agents | Features |
|------|-------|--------|----------|
| Demo | Free | 5 | Basic only |
| Professional | $X/month | 10 | All features |
| Agent Pack +10 | +$Y/month | +10 | Add-on |
| Agent Pack +25 | +$Z/month | +25 | Add-on |
| Unlimited | Custom | ∞ | Enterprise |

## 13.2 Revenue Model

- **Subscription**: Monthly/annual licenses
- **Agent Packs**: Pay for endpoint scale
- **Support**: Premium support tiers
- **Services**: Implementation, training

## 13.3 Target Market

- Mid-size enterprises (100-5000 employees)
- Managed Security Service Providers (MSSPs)
- Government/regulated industries
- Companies requiring CISA BOD 22-01 compliance

---

# 14. INTELLECTUAL PROPERTY

## 14.1 Codebase Ownership

- All code written from scratch
- No GPL/AGPL dependencies that require disclosure
- Commercial license allows resale

## 14.2 Key Dependencies (Permissive Licenses)

| Package | License |
|---------|---------|
| Flask | BSD-3-Clause |
| SQLAlchemy | MIT |
| cryptography | Apache 2.0 / BSD |
| python3-saml | MIT |
| ldap3 | LGPL-3.0 |
| gunicorn | MIT |
| PostgreSQL | PostgreSQL License |

## 14.3 Trademarks

- "SentriKat" name
- Logo and branding assets
- Domain names

---

# 15. APPENDICES

## A. Environment Variables

```bash
# Required
SECRET_KEY=<32-byte-hex>
ENCRYPTION_KEY=<fernet-key>
DATABASE_URL=postgresql://...
SENTRIKAT_INSTALLATION_ID=SK-INST-...

# Optional
NVD_API_KEY=<nvd-key>
SENTRIKAT_LICENSE=<license-key>
FLASK_ENV=production
VERIFY_SSL=true
HTTP_PROXY=http://proxy:3128
```

## B. API Rate Limits

| Endpoint | Limit |
|----------|-------|
| Global | 1000/day, 200/hour |
| Agent inventory | 60/minute |
| Agent heartbeat | 120/minute |
| Password reset | 5/hour |

## C. Supported Browsers

- Chrome 90+
- Firefox 88+
- Safari 14+
- Edge 90+

## D. System Requirements

| Component | Minimum | Recommended |
|-----------|---------|-------------|
| CPU | 2 cores | 4+ cores |
| RAM | 4 GB | 8+ GB |
| Storage | 20 GB | 100+ GB |
| Database | PostgreSQL 14+ | PostgreSQL 16+ |

---

## DOCUMENT REVISION HISTORY

| Version | Date | Author | Changes |
|---------|------|--------|---------|
| 1.0.0 | Feb 2026 | Development Team | Initial release |

---

**END OF DOCUMENT**

*This document is confidential and intended for authorized recipients only. Unauthorized distribution is prohibited.*
