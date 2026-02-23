# SENTRIKAT - COMPLETE ARCHITECTURE DOCUMENTATION
## Confidential Business & Technical Document
### For Investors, Buyers & Due Diligence

---

**Document Version:** 1.6.0
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
15. [UI/UX Architecture](#15-uiux-architecture)
16. [Appendices](#16-appendices)

---

# 1. EXECUTIVE SUMMARY

## What is SentriKat?

SentriKat is an **Enterprise Vulnerability Management Platform** that helps organizations track and remediate security vulnerabilities in their software inventory. It automatically correlates installed software with known vulnerabilities from authoritative sources (CISA KEV, NVD, CVE.org/Vulnrichment, ENISA EUVD, OSV, EPSS) using a **multi-source intelligence architecture** with automatic fallback -- eliminating single-point-of-failure dependency on any one data source.

## Key Value Proposition

| Problem | SentriKat Solution |
|---------|-------------------|
| Organizations don't know what software they have | Push agents auto-discover installed software |
| CVE databases are hard to search | Automatic CPE matching via NVD, CVE.org, EUVD (multi-source) |
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
| Total Python Code | 40,000+ lines |
| Database Models | 37 SQLAlchemy models |
| API Endpoints | 280+ REST endpoints |
| Frontend Templates | 6 major pages (800+ KB HTML) |
| External Integrations | 20+ (Jira, LDAP, SAML, OIDC, PagerDuty, etc.) |
| Test Coverage | 1,296 pytest tests |

---

# 2. PRODUCT OVERVIEW

## 2.1 Core Features

### Vulnerability Management
- **CISA KEV Sync**: Daily automatic sync with CISA Known Exploited Vulnerabilities catalog
- **NVD Recent CVEs**: Automatic import of HIGH/CRITICAL CVEs every 2 hours (zero-day coverage)
- **NVD Integration**: Search 800,000+ products in National Vulnerability Database
- **On-Demand CVE Lookup**: Admin can import any CVE by ID for immediate 0-day response
- **CVE Matching**: Automatic correlation between installed software and CVEs
- **EPSS Scoring**: Exploit Prediction Scoring System integration from FIRST.org
- **Due Date Tracking**: CISA BOD 22-01 compliance with deadline alerts

### Asset & Inventory Management
- **Push Agents**: Windows (PowerShell) and Linux (Bash) agents for auto-discovery
- **Software Inventory**: Track installed software across all endpoints
- **Asset Lifecycle**: Online/offline/stale/decommissioned status tracking
- **Multi-Source Import**: PDQ, SCCM, Intune, Lansweeper, CSV, REST API

### Enterprise Authentication & Identity
- **Local Authentication**: Username/password with bcrypt hashing
- **LDAP/Active Directory**: Full AD integration with group mapping
- **SAML 2.0 SSO**: Okta, Azure AD, ADFS, Google Workspace support
- **OAuth 2.0 / OpenID Connect**: Generic OIDC provider support via Authlib
- **WebAuthn/FIDO2**: Hardware security key and biometric authentication
- **Two-Factor Auth**: TOTP (Google Authenticator compatible)
- **Session Management**: Concurrent session limits, device tracking, forced logout
- **RBAC Permissions**: Fine-grained permission_required decorator system

### Alerting & Notifications
- **Email Alerts**: Critical CVE notifications, due date reminders
- **Digest Emails**: Configurable daily/weekly summary emails with vulnerability trends
- **Webhooks**: Slack, Microsoft Teams, Discord, custom HTTP — with HMAC-SHA256 signing
- **Incident Management**: PagerDuty and Opsgenie integration for critical alerts
- **Escalation**: Re-alert if not acknowledged within N days

### Audit & Compliance
- **Audit Trail**: Full audit logging of all security-relevant events (AuditLog model)
- **Audit API**: Query, filter, and export audit logs via REST API
- **CISA BOD 22-01**: Compliance dashboard and reports
- **EU NIS2**: ENISA EUVD integration for European compliance

### Issue Tracking Integration
- **Multi-Tracker Support**: Enable multiple issue trackers simultaneously (comma-separated configuration)
- **Jira**: Cloud and Server/Data Center support
- **GitHub Issues**: Create issues from CVEs
- **GitLab Issues**: Create issues from CVEs
- **YouTrack**: JetBrains issue tracker
- **Generic Webhook**: Custom integrations
- **Per-Tracker Actions**: Dashboard shows dedicated buttons per enabled tracker for ticket creation

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
| OAuth/OIDC | ✗ | ✓ |
| WebAuthn/FIDO2 | ✗ | ✓ |
| Email Alerts | ✗ | ✓ |
| Digest Emails | ✗ | ✓ |
| Webhooks (HMAC) | ✗ | ✓ |
| PagerDuty/Opsgenie | ✗ | ✓ |
| Jira Integration | ✗ | ✓ |
| Scheduled Reports | ✗ | ✓ |
| Audit Trail | ✗ | ✓ |
| Backup/Restore | ✗ | ✓ |
| White-Label | ✗ | ✓ |
| API Access | ✗ | ✓ |
| Prometheus Metrics | ✗ | ✓ |

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
| Icons | Bootstrap Icons | UI icons |

## 3.3 Security Libraries

| Library | Purpose |
|---------|---------|
| cryptography | Fernet encryption, RSA signing |
| bcrypt | Password hashing |
| flask-wtf | CSRF protection |
| flask-limiter | Rate limiting |
| python3-saml | SAML/SSO |
| Authlib | OAuth 2.0 / OpenID Connect |
| webauthn | WebAuthn/FIDO2 (hardware keys, biometrics) |
| ldap3 | LDAP/AD integration |
| pyotp | TOTP 2FA |
| prometheus_client | Prometheus metrics export |

## 3.4 External APIs (Multi-Source Intelligence Architecture)

SentriKat uses a **multi-source fallback chain** for vulnerability intelligence, eliminating single-point-of-failure dependency on any one data source. All sources are free and legally cleared for commercial use.

### CVSS Enrichment (Fallback Chain: NVD → CVE.org → EUVD)

| API | Purpose | License | Rate Limit |
|-----|---------|---------|------------|
| NVD API 2.0 | CVSS scores, CPE data (primary) | CVE Terms of Use | 5/30s free, 50/30s with key |
| CVE.org + Vulnrichment | CVSS from CISA ADP (secondary) | CVE-TOU + CC0 | No formal limit |
| ENISA EUVD | European CVSS + exploited vulns (tertiary) | ENISA IPR (CC-BY-4.0) | No formal limit |

### Vulnerability Catalog & Threat Intelligence

| API | Purpose | License | Rate Limit |
|-----|---------|---------|------------|
| CISA KEV | Exploited vulnerability catalog | CC0 (Public Domain) | None (JSON file) |
| ENISA EUVD Exploited | EU exploited vulnerabilities | ENISA IPR (CC-BY-4.0) | No formal limit |
| FIRST EPSS | Exploit probability scoring | Free (attribution) | None |

### Vendor Advisory / Patch Detection

| API | Purpose | License | Rate Limit |
|-----|---------|---------|------------|
| OSV.dev | Ubuntu/Debian/Alpine/PyPI/npm/Go/Rust | CC-BY-4.0 / CC0 | None |
| Red Hat Security Data | RHEL/CentOS/Rocky fix info | Free API | None |
| Microsoft MSRC CVRF | Windows/Office patch data | Free API | None |
| Debian Security Tracker | Debian fix tracking | Free | None (bulk JSON) |

### Issue Tracking & Integrations

| API | Purpose | Rate Limit |
|-----|---------|------------|
| Jira REST | Ticket creation | Per Jira limits |
| GitHub Issues | Issue creation | Per GitHub limits |
| GitLab Issues | Issue creation | Per GitLab limits |

## 3.5 Containerization

```dockerfile
# Base image
FROM python:3.11-slim

# Dependencies
- gcc, libpq-dev (PostgreSQL)
- libxml2-dev, libxmlsec1-dev (SAML)

# Runtime
- Gunicorn with gthread workers (configurable via gunicorn.conf.py)
- Auto-scaling workers: min(CPU*2+1, 8) with 4 threads each
- 120 second timeout, max-requests recycling for memory safety
- Preload for DB initialization and shared memory
- Bundled vendor assets (Bootstrap, Chart.js) for offline/on-premise deployment
```

## 3.6 On-Premise / Air-Gapped Deployment

SentriKat supports fully on-premise deployments. Frontend assets (Bootstrap, Chart.js, icons) are bundled
during Docker build via `scripts/download_vendor_assets.sh`. Templates use local-first loading with CDN fallback.

### Network Requirements (On-Premise)

| Category | Service | URL | Required |
|----------|---------|-----|----------|
| **CRITICAL** | CISA KEV | `https://www.cisa.gov/feeds/...` | YES |
| **CRITICAL** | NVD CVE API | `https://services.nvd.nist.gov/rest/json/cves/2.0` | YES (primary CVSS source) |
| **CRITICAL** | NVD CPE API | `https://services.nvd.nist.gov/rest/json/cpes/2.0` | YES |
| **FALLBACK** | CVE.org API | `https://cveawg.mitre.org/api/cve/` | CVSS fallback when NVD unavailable |
| **FALLBACK** | ENISA EUVD | `https://euvdservices.enisa.europa.eu/api/` | CVSS fallback + EU exploited vulns |
| **ESSENTIAL** | OSV API | `https://api.osv.dev/v1` | For false-positive reduction |
| **ESSENTIAL** | Red Hat API | `https://access.redhat.com/hydra/rest/securitydata` | For RHEL patch detection |
| **ESSENTIAL** | Debian Tracker | `https://security-tracker.debian.org/tracker/data/json` | For Debian patch detection |
| **OPTIONAL** | EPSS API | `https://api.first.org/data/v1/epss` | Exploit probability scoring |
| **OPTIONAL** | SMTP | Org-configured | Email alerts |
| **OPTIONAL** | LDAP | Org-configured | Enterprise user sync |
| **OPTIONAL** | Issue Trackers | Jira/GitHub/GitLab | Ticket creation |
| **OPTIONAL** | Webhooks | Slack/Teams/Custom | Real-time notifications |
| **OPTIONAL** | License Server | `https://portal.sentrikat.com/api` | Graceful degradation if offline |
| **OPTIONAL** | GitHub API | `https://api.github.com` | Version update checks |

All HTTP calls respect proxy settings (`HTTP_PROXY`, `HTTPS_PROXY`) and SSL verification (`VERIFY_SSL`).

---

# 4. SYSTEM ARCHITECTURE

## 4.1 Directory Structure

```
SentriKat/
├── app/                          # Flask application (40,000+ LOC)
│   ├── __init__.py               # App factory, blueprints, metrics, RLS
│   ├── models.py                 # 37 SQLAlchemy models (3,900+ LOC)
│   ├── routes.py                 # Main API routes (4,500+ LOC)
│   ├── auth.py                   # Authentication + OAuth/OIDC/WebAuthn (1,800+ LOC)
│   ├── licensing.py              # License validation (975 LOC)
│   ├── agent_api.py              # Agent endpoints (2,500+ LOC)
│   ├── cisa_sync.py              # CISA KEV sync + webhook dispatch (600+ LOC)
│   ├── ldap_*.py                 # LDAP modules (1,500+ LOC)
│   ├── saml_*.py                 # SAML modules (650+ LOC)
│   ├── oauth_manager.py          # OAuth 2.0 / OpenID Connect (267 LOC)
│   ├── webauthn_manager.py       # WebAuthn/FIDO2 hardware keys (117 LOC)
│   ├── jira_integration.py       # Jira connector (400+ LOC)
│   ├── issue_trackers.py          # Multi-tracker engine (Jira/GitHub/GitLab/YouTrack)
│   ├── vendor_advisories.py      # Auto vendor patch detection (1000+ LOC)
│   ├── version_utils.py          # dpkg/RPM/APK version comparison (444 LOC)
│   ├── email_alerts.py           # Email system (626 LOC)
│   ├── digest_emails.py          # Daily/weekly digest emails (687 LOC)
│   ├── webhook.py                # Centralized webhook with retry + HMAC-SHA256 (131 LOC)
│   ├── incident_integrations.py  # PagerDuty + Opsgenie integration (301 LOC)
│   ├── audit.py                  # Audit trail helper (89 LOC)
│   ├── audit_api.py              # Audit log API endpoints (168 LOC)
│   ├── metrics.py                # Prometheus /metrics endpoint (162 LOC)
│   ├── rls.py                    # PostgreSQL Row-Level Security (49 LOC)
│   ├── scheduler.py              # Background jobs (629+ LOC)
│   ├── encryption.py             # Fernet utils + production enforcement (163 LOC)
│   ├── logging_config.py         # JSON structured logging + syslog (52 LOC)
│   └── templates/                # Jinja2 templates
│       ├── base.html             # Layout, dark mode, sidebar badges, global CSS/JS
│       ├── dashboard.html        # Dashboard with charts, priority cards, CVE table
│       ├── admin.html            # Inventory (Products, Endpoints, Software Overview)
│       ├── admin_panel.html      # Admin (Users, Orgs, Integrations, Settings)
│       └── ...
│
├── agents/                       # Agent scripts
│   ├── sentrikat-agent-windows.ps1
│   ├── sentrikat-agent-linux.sh
│   └── sentrikat-agent-macos.sh
│
├── static/                       # CSS, JS, images
│   └── js/
│       ├── admin_panel.js        # Admin panel logic (~9500 LOC)
│       └── sentrikat-core.js     # Core utilities (DOM, Toast, escaping)
│
├── tests/                        # 1,296 pytest tests
│
├── migrations/                   # Alembic database migrations
│   ├── alembic.ini
│   ├── env.py
│   └── script.py.mako
│
├── helm/sentrikat/               # Helm chart for Kubernetes
│   ├── Chart.yaml
│   ├── values.yaml
│   └── templates/                # K8s resource templates
│
├── k8s/                          # Plain Kubernetes manifests
│   ├── app-deployment.yaml
│   ├── postgres-statefulset.yaml
│   ├── ingress.yaml
│   └── ...
│
├── scripts/                      # Operational scripts
│   ├── backup_cron.sh            # Automated backup with retention
│   ├── enable_rls.sql            # PostgreSQL RLS setup
│   ├── backup_database.sh
│   └── download_vendor_assets.sh
│
├── nginx/                        # Reverse proxy config
├── docker-compose.yml            # Orchestration
├── Dockerfile                    # Container build
├── requirements.txt              # Python deps (35+ packages)
├── .github/workflows/            # CI/CD
│   ├── ci.yml                    # Tests + coverage + Trivy scanning
│   └── release.yml               # Build & publish
└── .github/dependabot.yml        # Automated dependency updates
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
| CISA KEV Sync | Daily 02:00 UTC | Fetch latest exploited vulnerabilities from CISA |
| NVD Recent CVEs Sync | Every 2 hours | Import new HIGH/CRITICAL CVEs from NVD (zero-day coverage) |
| Critical CVE Email | Daily 09:00 UTC | Send alert digests |
| **Digest Emails** | Daily/Weekly (configurable) | Send vulnerability summary digest emails |
| Data Retention Cleanup | Daily 03:00 UTC | Delete old logs, audit records, expired sessions |
| Vulnerability Snapshot | Daily 02:00 UTC | Historical tracking |
| Scheduled Reports | Every 15 min | Process report queue |
| LDAP Sync | Configurable | Sync users from AD |
| **Vendor Advisory Sync** | Daily 03:00 UTC | Sync OSV.dev, Red Hat, MSRC, Debian feeds |
| **Maintenance** | Daily 04:00 UTC | 7-step cleanup & auto-resolution |
| **Session Cleanup** | Every 30 min | Expire stale sessions, enforce concurrent limits |
| **Usage Snapshot** | Daily | Record per-org usage metrics for billing/capacity |

### 4.3.1 Maintenance Pipeline (7 Steps)

| Step | Task | Description |
|------|------|-------------|
| 1 | Clean stale installations | Remove ProductInstallation records not seen for 30+ days |
| 2 | Update asset status | Mark offline agents as stale (14d) or removed (90d) |
| 3 | Clean orphaned products | Remove agent-created products with zero installations (includes org-assigned orphans) |
| 4 | Clean import queue | Purge old processed import queue entries |
| 5 | Auto-disable stale products | Disable products not reported by agents |
| 6 | Auto-acknowledge (removed) | Resolve CVEs for products with zero installations |
| 7 | **Auto-acknowledge (upgraded)** | Resolve CVEs where all installations upgraded past vulnerable range |

### 4.3.2 Endpoint Deletion & Orphan Cleanup

When an endpoint (asset) is deleted — either manually by an admin or automatically after 90 days of inactivity — the system performs **immediate orphan cleanup** to prevent "0 endpoints" ghost products from lingering in the product list.

**Deletion cascade flow:**

```
Admin deletes endpoint "LT-CLZ8X34"
    │
    ├─→ 1. Snapshot affected product IDs (all products installed on this asset)
    ├─→ 2. Delete ProductVersionHistory for this asset
    ├─→ 3. Delete ProductInstallation for this asset
    ├─→ 4. Delete AgentEvent, StaleAssetNotification, InventoryJob, ContainerImage
    ├─→ 5. Delete Asset record
    │
    └─→ 6. IMMEDIATE ORPHAN CLEANUP:
         ├─→ Check which affected products now have zero installations anywhere
         ├─→ For agent-created products (source='agent') not linked to service catalog:
         │   ├─→ Delete VulnerabilityMatch records
         │   ├─→ Delete ProductVersionHistory records
         │   ├─→ Remove organization assignments (product_organizations)
         │   └─→ Delete Product record
         └─→ Log cleanup count (e.g., "cleaned up 15 orphaned products")
```

**Why this matters:** Without immediate cleanup, deleting an endpoint and re-registering the same machine would leave old products showing "0 endpoints" in the product list. The agent would then re-report its current inventory (creating new installations), but any products that are no longer installed would remain as ghosts until the daily maintenance ran. Now they are cleaned up immediately.

**Safety guards (products NOT deleted):**
- Manually created products (`source='manual'`)
- Products linked to the service catalog
- Products that still have installations on other endpoints

### 4.3.3 Agent Re-Registration After Endpoint Deletion

When the same physical machine re-registers after its endpoint was deleted:

```
Machine "LT-CLZ8X34" re-registers with agent
    │
    ├─→ Lookup by agent_id (BIOS UUID) → NOT FOUND (asset was deleted)
    ├─→ Lookup by hostname + org → NOT FOUND (asset was deleted)
    ├─→ CREATE new Asset record (new auto-increment ID)
    │
    └─→ Process inventory:
         ├─→ For each reported product: find or create Product + ProductInstallation
         ├─→ Products that already exist in DB: reuse them, create new installation
         ├─→ Products that were cleaned up: re-created as new products
         └─→ Result: clean state, no "0 endpoint" ghosts
```

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
                                                 │ (CISA KEV + NVD)│
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

-- Vulnerability data (CISA KEV + NVD)
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
    cpe_data JSONB,           -- Cached CPE entries from NVD
    cpe_fetched_at TIMESTAMP, -- When CPE data was last fetched
    nvd_status VARCHAR(50),   -- NVD analysis status (Awaiting Analysis, Analyzed, etc.)
    source VARCHAR(20),       -- Origin: cisa_kev, nvd, euvd
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

## 5.3 Total: 37 Tables

| Category | Tables |
|----------|--------|
| Auth/Users | User, Organization, UserOrganization, SystemSettings, Permission, WebAuthnCredential, UserSession |
| Products | Product, ServiceCatalog, ProductExclusion, UserCpeMapping, CpeDictionaryEntry, ProductVersionHistory |
| Vulnerabilities | Vulnerability, VulnerabilityMatch, VulnerabilitySnapshot, VendorFixOverride |
| Agents | AgentApiKey, Asset, ProductInstallation, AgentEvent, InventoryJob, AgentLicense, AgentUsageRecord |
| Containers | ContainerImage, ContainerVulnerability |
| Dependencies | DependencyScan, DependencyScanResult |
| Reporting | ScheduledReport, HealthCheckResult |
| Billing | SubscriptionPlan, Subscription, UsageRecord |
| Logging | SyncLog, AlertLog, StaleAssetNotification, AuditLog |

---

# 6. API REFERENCE

## 6.1 Authentication Endpoints

```
POST   /api/auth/login               # Username/password login
POST   /api/auth/logout              # End session
POST   /api/auth/2fa/setup           # Enable TOTP
POST   /api/auth/2fa/verify          # Verify TOTP code
GET    /api/auth/status              # Current user info

# OAuth/OIDC
GET    /api/auth/oidc/login          # Redirect to OIDC provider
GET    /api/auth/oidc/callback       # OIDC callback handler

# WebAuthn/FIDO2
POST   /api/auth/webauthn/register/begin     # Start key registration
POST   /api/auth/webauthn/register/complete   # Complete key registration
POST   /api/auth/webauthn/login/begin        # Start key authentication
POST   /api/auth/webauthn/login/complete      # Complete key authentication

# Session Management
GET    /api/auth/sessions            # List active sessions for current user
DELETE /api/auth/sessions/<id>       # Terminate a specific session
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
POST   /api/sync                     # Manual full sync (CISA KEV + NVD recent CVEs)
POST   /api/sync/cve/<cve_id>       # On-demand import of a single CVE by ID
POST   /api/matches/<id>/acknowledge # Mark as handled (sets resolution_reason='manual')
POST   /api/matches/<id>/unacknowledge  # Reopen for alerts
POST   /api/matches/<id>/snooze      # Defer alerts
POST   /api/matches/acknowledge-by-cve/<cve_id>  # Bulk acknowledge all matches for a CVE
POST   /api/matches/unacknowledge-by-cve/<cve_id> # Bulk reopen all matches for a CVE
```

### 6.3.1 Vulnerability Resolution Methods

SentriKat tracks HOW a vulnerability was resolved via `resolution_reason`:

| Method | Trigger | Description |
|--------|---------|-------------|
| `manual` | User clicks Acknowledge | Admin manually reviews and marks as handled |
| `software_removed` | Maintenance job | Product has zero installations (uninstalled from all assets) |
| `version_upgraded` | Maintenance job | All installations upgraded past the vulnerable version range |
| `vendor_fix` (high) | Vendor Advisory Sync | Distro-native comparison (dpkg/RPM/APK) confirmed fix applied |
| `vendor_fix` (medium) | Vendor Advisory Sync | Generic comparison or missing agent data - needs manual verification |

### 6.3.2 Cumulative Update / Auto-Resolution Logic

When vendors release software updates that fix CVEs (e.g., Firefox 126 fixes CVE-2024-XXXX
that affected versions 100-125), SentriKat automatically detects this:

```
                  NVD says: CVE-2024-XXXX affects Firefox 100.0 - 125.0

    Your installation: Firefox 126.0
                       ↓
    check_product_affected("mozilla", "firefox", "126.0", "CVE-2024-XXXX")
                       ↓
    Version 126.0 > versionEnd 125.0 → NOT AFFECTED
                       ↓
    All installations safe → auto_acknowledge(resolution_reason='version_upgraded')
```

**How it works step by step:**

1. NVD publishes affected version ranges for each CVE (versionStart, versionEnd)
2. During maintenance (step 7), the system queries all unacknowledged CVE matches
3. For each match, it checks ALL installations of that product across all assets
4. Using NVD CPE version range data, it determines if each installed version is affected
5. If **ALL** installed versions are outside the vulnerable range → CVE auto-acknowledged
6. If even ONE machine still runs a vulnerable version → CVE stays active

**Key detail:** This only works for products with CPE data (precise NVD matching).
Keyword-only matches are not auto-resolved since version ranges aren't available.

### 6.3.3 Vendor Advisory Sync & Three-Tier Confidence System

SentriKat automatically detects in-place vendor patches (backport fixes) by syncing with
multiple vendor advisory feeds. This eliminates false positives where NVD CPE data marks a
version as affected even though the vendor has already backported the fix.

**Supported Feeds:**

| Feed | Coverage | Auth Required | Comparison Method |
|------|----------|---------------|-------------------|
| OSV.dev | Ubuntu, Debian, Alpine, PyPI, npm, Go, Rust, Maven | No | dpkg/RPM/APK/generic |
| Red Hat Security Data API | RHEL, CentOS, Rocky, Alma | No | RPM |
| Microsoft MSRC CVRF | Windows, Office, Exchange, .NET | No | KB verification |
| Debian Security Tracker | Debian | No | dpkg |

**Three-Tier Confidence System:**

```
┌─────────────────────────────────────────────────────────────────┐
│                    CONFIDENCE TIERS                              │
├─────────────────┬───────────────────┬───────────────────────────┤
│   AFFECTED      │  LIKELY RESOLVED  │  RESOLVED                 │
│   (Red)         │  (Amber)          │  (Green)                  │
│                 │                   │                           │
│ No vendor fix   │ Vendor fix found  │ Vendor fix confirmed      │
│ data found      │ but comparison    │ via distro-native         │
│                 │ used generic      │ comparison (dpkg/RPM/APK) │
│                 │ algorithm or no   │ with agent-reported       │
│                 │ agent distro pkg  │ distro_package_version    │
│                 │ version available │                           │
│                 │                   │                           │
│ Stays in alerts │ STAYS IN ALERTS   │ Auto-resolved             │
│ Full visibility │ "Verify" badge    │ Green badge               │
│                 │ User must confirm │ Hidden from alerts        │
└─────────────────┴───────────────────┴───────────────────────────┘
```

**Why three tiers (legal protection):** SentriKat is security software. If we suppress a
real vulnerability and the customer gets breached, we face liability. The medium-confidence
tier protects both us and the customer: it says "we detected a likely fix, but please verify"
rather than silently removing the CVE from their dashboard.

**Version comparison algorithms:**

| Format | Algorithm | Used For |
|--------|-----------|----------|
| dpkg | Debian Policy Manual §5.6.12 (epoch:upstream-revision, tilde handling) | Ubuntu, Debian, Mint, Kali |
| RPM | rpmvercmp (digit-beats-alpha, segment tokenization) | RHEL, CentOS, Rocky, Alma, Fedora, SUSE |
| APK | Semver-like with -rN revision suffix | Alpine Linux |
| generic | Numeric segment comparison | PyPI, npm, other ecosystems |

### 6.3.4 Zero-Day CVE Pipeline

SentriKat is designed to surface zero-day vulnerabilities as quickly as possible, even when
upstream data sources (NVD, CISA KEV) have incomplete data. This is critical because:

- CISA KEV only lists *known exploited* vulnerabilities — many 0-days aren't added for days/weeks
- NVD often marks new CVEs as "Awaiting Analysis" for days before adding CPE configuration data
- Without CPE data, traditional matching cannot link a CVE to affected products

**Multi-Source Ingestion (No Single Point of Failure):**

| Source | Schedule | What It Catches |
|--------|----------|-----------------|
| CISA KEV Sync | Daily 02:00 UTC + manual | Known exploited vulnerabilities with due dates |
| NVD Recent CVEs | Every 2 hours + manual | All HIGH/CRITICAL CVEs published in the last 6 hours |
| ENISA EUVD Exploited | Daily (during CISA sync) | EU-tracked exploited CVEs not yet in CISA KEV |
| Manual CVE Lookup | On-demand (`POST /api/sync/cve/<id>`) | Any specific CVE by ID (admin 0-day response tool) |

#### Three-Phase NVD Sync (`sync_nvd_recent_cves`)

The NVD sync uses three complementary phases to ensure no CVE slips through:

| Phase | Query Strategy | What It Catches |
|-------|---------------|-----------------|
| **Phase 1** | `pubStartDate` + `cvssV3Severity=HIGH/CRITICAL` | Analyzed CVEs with NVD-assigned CVSS scores |
| **Phase 2** | `pubStartDate` without severity filter | "Awaiting Analysis" CVEs with CNA-assigned HIGH/CRITICAL scores |
| **Phase 3** | `lastModStartDate` + `cvssV3Severity=HIGH/CRITICAL` | Late-analyzed CVEs (published days ago, scored today) |

**Why three phases?** Phase 1 only catches CVEs that NVD has already scored. Zero-days published
with "Awaiting Analysis" status have no NVD score and would be invisible. Phase 2 solves this by
importing CVEs where the CNA (vendor/researcher) assigned a HIGH/CRITICAL score, even though NVD
hasn't analyzed them yet. Phase 3 uses `lastModStartDate` (instead of `pubStartDate`) to catch
CVEs published during a previous window but only scored after — filling the gap between publication
and analysis.

**CVSS Source Tracking:**

Each vulnerability tracks where its CVSS score came from via `cvss_source`:

| Value | Meaning |
|-------|---------|
| `nvd` | NVD Primary score (highest authority) |
| `cna` | CNA-assigned score from Phase 2 (pre-NVD analysis) |
| `cve_org` | CVE.org/Vulnrichment fallback |
| `euvd` | ENISA EUVD fallback |
| `pending` | All 3 sources returned nothing on first attempt |

A background re-enrichment job periodically upgrades `cna`/`cve_org`/`euvd`/`pending` scores
to `nvd` once NVD completes analysis, ensuring CVSS accuracy improves over time.

**API Outage Protection:**

If the NVD API is completely unreachable (all phases return 0 new CVEs, 0 existing, but errors > 0),
the sync timestamp is NOT advanced. This ensures that CVEs published during the outage are picked
up on the next successful sync, preventing permanent data gaps.

**Handling "Awaiting Analysis" CVEs:**

When NVD publishes a CVE but hasn't completed analysis (no CPE configurations yet):

1. **`nvd_status` tracking** — Each vulnerability stores NVD's analysis state (`Awaiting Analysis`,
   `Analyzed`, `Received`, `Undergoing Analysis`). This prevents the system from treating
   "NVD hasn't analyzed it yet" the same as "NVD confirmed it affects nothing."

2. **Description-based vendor/product extraction** — When NVD has no CPE data, the system parses
   the CVE description to identify the affected product (e.g., "Use after free in CSS in
   **Google Chrome** prior to 145.0.7632.75" → vendor=Google, product=Chrome). This uses a
   two-tier pattern system:
   - **Seed patterns**: Hardcoded regex for non-obvious vendor aliases (FortiGate, PAN-OS, MOVEit, etc.)
   - **Dynamic patterns**: Auto-built from the Products table (10-minute cache), including CPE underscore-to-space conversions

3. **Deferred CPE stamping** — CVEs with `nvd_status` of `Awaiting Analysis`, `Received`, or
   `Undergoing Analysis` are NOT marked as "checked with no CPE data." They remain in the
   retry queue and are re-fetched on every sync cycle until NVD completes analysis.

4. **Stale CPE re-check** — Even CVEs that were previously stamped with empty CPE data are
   automatically re-checked after 24 hours. This recovers CVEs that were imported before the
   `nvd_status` tracking was in place, and handles edge cases where NVD analysis takes longer
   than expected.

5. **Recovery mechanism** — During CPE fetching, the system recovers vendor/product for CVEs
   imported before description-based extraction was implemented, and backfills `nvd_status`
   for older records missing this field.

**EUVD Exploited Vulnerability Tracking:**

ENISA's EUVD provides an independent feed of actively exploited vulnerabilities, filling the gap
when CVEs are being exploited but haven't been added to CISA KEV yet:

```
EUVD Exploited Feed
    │
    ├─→ CVE already in CISA KEV?
    │   YES → Enrich with EUVD CVSS (if missing) + mark is_actively_exploited=True
    │
    └─→ CVE NOT in CISA KEV?
        └─→ Create new Vulnerability with source='euvd', is_actively_exploited=True
            ├─→ Fetch full details from NVD (CVSS, CPE, description)
            ├─→ Use EUVD CVSS as fallback if NVD unavailable
            └─→ If CISA KEV adds it later → source becomes 'cisa_kev+euvd' (dual-source tracking)
```

**Complete Zero-Day Lifecycle:**

```
0-day dropped (e.g., Chrome CVE published)
    │
    ├─→ NVD has it within hours (vulnStatus: "Awaiting Analysis")
    │       │
    │       ├─→ Scheduled NVD sync (every 2h) picks it up via Phase 2 (CNA score)
    │       │   OR admin clicks Sync button (now includes NVD)
    │       │   OR admin uses POST /api/sync/cve/<id> for immediate import
    │       │
    │       ├─→ No CPE configs yet → description parsed → vendor=Google, product=Chrome
    │       ├─→ nvd_status="Awaiting Analysis" → CPE NOT stamped → stays in retry queue
    │       ├─→ rematch runs → keyword match against Chrome products → appears on dashboard
    │       ├─→ cvss_source='cna' → CVSS from vendor/researcher score
    │       │
    │       ├─→ Hours later: EUVD marks as exploited → is_actively_exploited=True
    │       ├─→ Days later: NVD completes analysis → CPE data fetched → precise version matching
    │       └─→ Re-enrichment upgrades cvss_source from 'cna' to 'nvd'
    │
    └─→ CISA KEV adds it (if exploited) → due date tracking + alerts
        └─→ If already from EUVD → source='cisa_kev+euvd'
```

**Admin On-Demand CVE Lookup (`POST /api/sync/cve/<cve_id>`):**

For immediate 0-day response, admins can import any CVE by ID without waiting for scheduled syncs:

```bash
curl -X POST https://sentrikat.example.com/api/sync/cve/CVE-2026-2441 \
  -H "Cookie: session=<admin-session>"
```

Returns: CVE details, whether CPE data was available, and how many product matches were created.
Targeted matching: only rematches active products against the imported CVE (not a full rematch).
Supports `?force=1` to refresh stale data even if CVE already exists.
Rate limited: 10/minute.

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

## 6.6 Audit & Monitoring

```
GET    /api/audit/logs               # Query audit trail (paginated, filterable)
GET    /api/audit/logs/export        # Export audit logs as CSV
GET    /metrics                      # Prometheus metrics endpoint
```

## 6.7 Settings & License

```
GET    /api/settings/ldap            # LDAP config
POST   /api/settings/ldap            # Update LDAP
POST   /api/settings/ldap/test       # Test connection
GET    /api/license                  # License info + usage stats
POST   /api/license                  # Activate license
GET    /api/license/installation-id  # Hardware ID for license binding
GET    /api/version                  # App version, edition, API info
GET    /api/updates/check            # Check GitHub for latest release (admin-only)
```

### In-App Update Check

The `/api/updates/check` endpoint queries the GitHub Releases API to check if a newer
version is available. It returns:

```json
{
  "update_available": true,
  "current_version": "1.0.3",
  "latest_version": "1.0.4",
  "release_name": "SentriKat v1.0.4",
  "release_url": "https://github.com/sbr0nch/SentriKat/releases/tag/v1.0.4",
  "published_at": "2026-02-10T12:00:00Z"
}
```

- Auto-checks when admin opens the License tab
- Manual "Check for updates" button available
- Gracefully handles offline scenarios (returns `update_available: false` with error message)
- 5-second timeout to avoid blocking the UI

**Total: 100+ REST endpoints with proper HTTP methods**

---

# 7. SECURITY IMPLEMENTATION

## 7.1 Authentication

| Method | Implementation |
|--------|----------------|
| Local | bcrypt password hashing, configurable policy |
| LDAP | ldap3 library, bind authentication, injection prevention |
| SAML | python3-saml (OneLogin), RSA signature validation |
| OAuth/OIDC | Authlib library, generic OIDC provider support (Google, Azure AD, Okta, Keycloak, etc.) |
| WebAuthn/FIDO2 | webauthn library, hardware security keys (YubiKey), biometric auth (Touch ID, Windows Hello) |
| 2FA | pyotp TOTP, 30-second codes, QR setup |

### OAuth/OIDC Configuration

```
OIDC_CLIENT_ID=<client-id>
OIDC_CLIENT_SECRET=<client-secret>
OIDC_DISCOVERY_URL=https://accounts.google.com/.well-known/openid-configuration
```

Supports auto-discovery of provider endpoints (authorization, token, userinfo) via `.well-known/openid-configuration`.

### WebAuthn/FIDO2

- Registration: `POST /api/auth/webauthn/register/begin` + `POST /api/auth/webauthn/register/complete`
- Authentication: `POST /api/auth/webauthn/login/begin` + `POST /api/auth/webauthn/login/complete`
- Credential storage: `WebAuthnCredential` model with `credential_id`, `public_key`, `sign_count`
- Supports platform authenticators (Touch ID, Windows Hello) and roaming authenticators (YubiKey, SoloKeys)

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
- PagerDuty/Opsgenie routing keys

# Format: gAAAAA... (base64-encoded)
# Key: 32-byte random, environment variable
# Production enforcement: ENCRYPTION_KEY must be explicitly set (no auto-generation)
```

## 7.3 Session Security

```python
SESSION_COOKIE_HTTPONLY = True   # No JS access
SESSION_COOKIE_SECURE = True     # HTTPS only
SESSION_COOKIE_SAMESITE = 'Lax'  # CSRF protection
PERMANENT_SESSION_LIFETIME = 4 hours
```

### Session Management (Enterprise)

- **UserSession model**: Tracks all active sessions per user (device, IP, browser, last activity)
- **Concurrent session limits**: Configurable max sessions per user (oldest evicted on overflow)
- **Forced logout**: Admins can terminate any user's session
- **Automatic cleanup**: Expired sessions purged every 30 minutes by scheduler
- **Device tracking**: User-Agent, IP address, and last-active timestamp per session

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
| XSS | Jinja2 autoescaping + `escapeHtml()` for dynamic innerHTML/showToast/onclick |
| CSRF | flask-wtf tokens (agent API routes exempt) |
| Clickjacking | X-Frame-Options: SAMEORIGIN |
| MIME Sniffing | X-Content-Type-Options: nosniff |
| Markdown Injection | Sanitized issue tracker ticket descriptions |

## 7.6 Audit Logging

### Audit Trail System (Enterprise)

All security events are stored in the `AuditLog` model with full context:

```
AuditLog:
  - user_id, username    # Who performed the action
  - action               # What was done (login, settings_change, user_create, etc.)
  - resource_type        # Target type (user, organization, setting, etc.)
  - resource_id          # Target ID
  - details              # JSON with before/after values
  - ip_address           # Client IP
  - user_agent           # Browser/client info
  - created_at           # Timestamp
```

**Audit API** (`/api/audit/logs`):
- Paginated query with filtering by action, user, resource, date range
- Export support for compliance reporting
- Admin-only access with organization isolation

**Events logged:**
- Login attempts (success/failure)
- Password changes
- 2FA setup/disable
- License activation
- Settings changes (with before/after diff)
- User management (create, update, delete, role changes)
- API key operations (create, revoke)
- Organization changes
- Webhook configuration changes
- Integration configuration changes

### Syslog Forwarding

Structured JSON logs can be forwarded to external SIEM/syslog collectors:

```
SYSLOG_HOST=siem.example.com
SYSLOG_PORT=514
SYSLOG_PROTOCOL=udp    # udp or tcp
```

## 7.7 Row-Level Security (PostgreSQL)

PostgreSQL Row-Level Security policies enforce tenant isolation at the database level:

```sql
-- Example RLS policy (generated by scripts/enable_rls.sql)
ALTER TABLE products ENABLE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON products
  USING (organization_id = current_setting('app.current_org_id')::integer);
```

Applied to all tenant-scoped tables (products, assets, vulnerabilities, etc.) as an additional defense layer beyond application-level filtering.

## 7.8 SSRF Protection

All outbound webhook requests pass through `validate_url_for_request()` which blocks:
- Private/internal IP ranges (10.x, 172.16-31.x, 192.168.x, 127.x, ::1)
- Link-local addresses (169.254.x)
- Non-HTTP(S) schemes
- DNS rebinding attacks (resolved IP validated before request)

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

**Multi-Tracker Architecture**: Multiple trackers can be enabled simultaneously via comma-separated `issue_tracker_type` setting (e.g., `jira,github`). The dashboard renders per-tracker action buttons, and admin settings show all tracker configurations at once via checkboxes.

## 8.2 Authentication Providers

| Provider | Protocol |
|----------|----------|
| Active Directory | LDAP v3 |
| OpenLDAP | LDAP v3 |
| Okta | SAML 2.0 / OIDC |
| Azure AD | SAML 2.0 / OIDC |
| ADFS | SAML 2.0 |
| Google Workspace | SAML 2.0 / OIDC |
| Keycloak | OIDC |
| Any OIDC Provider | OAuth 2.0 / OpenID Connect |
| YubiKey / SoloKeys | WebAuthn/FIDO2 |
| Touch ID / Windows Hello | WebAuthn/FIDO2 (platform) |

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
| Digest Email | Daily/weekly HTML summary with vulnerability trends |
| Slack | Block Kit JSON (HMAC-SHA256 signed) |
| Microsoft Teams | Adaptive Cards (HMAC-SHA256 signed) |
| Discord | Embed JSON (HMAC-SHA256 signed) |
| Custom Webhook | Configurable JSON (HMAC-SHA256 signed) |
| PagerDuty | Events API v2 (trigger/resolve incidents) |
| Opsgenie | Alert API v2 (create/close alerts) |

### Webhook Delivery System (`app/webhook.py`)

Centralized webhook delivery with enterprise reliability:
- **Retry logic**: Exponential backoff (2s, 4s, 8s) — up to 3 retries
- **HMAC-SHA256 signing**: `X-Webhook-Signature` and `X-Webhook-Timestamp` headers
- **SSRF protection**: All URLs validated before delivery
- **4xx short-circuit**: Client errors (400-499) do not trigger retries
- **Proxy support**: Respects `HTTP_PROXY`/`HTTPS_PROXY` settings

### Incident Management (`app/incident_integrations.py`)

- **PagerDuty**: Auto-creates incidents for CRITICAL/HIGH CVEs, auto-resolves when acknowledged
- **Opsgenie**: Auto-creates alerts with priority mapping, auto-closes when resolved
- **Deduplication**: Uses CVE ID as dedup key to prevent duplicate incidents
- **Severity mapping**: CVSS score mapped to PD/OG priority levels

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
# Windows — Install as Windows service (recommended, visible in services.msc):
Invoke-WebRequest -Uri "https://sentrikat/api/agent/script/windows" -OutFile agent.ps1
.\agent.ps1 -InstallService -ServerUrl "https://sentrikat.example.com" -ApiKey "sk_agent_xxx"

# Windows — Install as scheduled task (alternative):
.\agent.ps1 -Install -ServerUrl "https://sentrikat.example.com" -ApiKey "sk_agent_xxx"

# Linux (as root — installs as systemd service):
curl -o agent.sh https://sentrikat/api/agent/script/linux
chmod +x agent.sh
sudo ./agent.sh --install --server-url "https://sentrikat.example.com" --api-key "sk_agent_xxx"

# macOS (as root — installs as LaunchDaemon):
curl -o agent.sh https://sentrikat/api/agent/script/macos
chmod +x agent.sh
sudo ./agent.sh --install --server-url "https://sentrikat.example.com" --api-key "sk_agent_xxx"
```

---

# 10. LICENSING SYSTEM

## 10.1 License Format

```
<base64(json_payload)>.<base64(rsa_signature)>

Payload:
{
  "license_id": "LIC-2025-001-ABC123",
  "customer": "Acme Corp",
  "email": "admin@acme.com",
  "edition": "professional",
  "issued_at": "2025-01-01",
  "expires_at": "2026-01-01",
  "installation_id": "SK-INST-<hash>",
  "limits": {
    "max_users": -1,
    "max_organizations": -1,
    "max_products": -1,
    "max_agents": 50
  },
  "features": ["ldap", "email_alerts", "white_label"]
}
```

## 10.2 Hardware Locking

```
Installation ID = SHA256(
  database_uri +
  data_volume_path +
  random_component (persisted)
)

Format: SK-INST-<64-char-hex>

For Docker: Set SENTRIKAT_INSTALLATION_ID in .env
```

## 10.3 Activation Methods

### Online Activation (recommended)
```
Customer purchases license → receives activation code (SK-XXXX-XXXX-XXXX-XXXX)
 ↓
Admin panel → "Activate Online" → enters code
 ↓
POST portal.sentrikat.com/api/v1/license/activate
  { activation_code, installation_id, app_version }
 ↓
Portal returns RSA-signed license key (locked to installation_id)
 ↓
Local validation (RSA-4096 signature + hardware match) → saved to DB
```

**Security hardening:**
- SSL always enforced (ignores VERIFY_SSL setting for license server)
- Rate limited: 5 attempts/hour/IP (in-memory + server-side)
- Activation codes: `^[A-Za-z0-9\-]+$`, 8-128 chars
- Generic error messages (no internal state leakage)
- RSA signature verification prevents accepting forged keys even if MITM

### Offline Activation
```
Admin copies Installation ID from admin panel
 → sends to SentriKat (email/portal)
 → receives signed license key
 → pastes in admin panel → validated locally
```

## 10.4 Validation Flow

```
1. Extract payload and signature from license key
2. Verify RSA-4096 signature against embedded public key
3. Check installation_id matches hardware fingerprint
4. Check expiration date
5. Apply limits and features
```

## 10.5 License Heartbeat

```
Every 12 hours → POST portal.sentrikat.com/api/v1/license/heartbeat
  { installation_id, license_id, edition, app_version, usage }

Responses:
  200 + status=active → continue normally
  200 + status=revoked → store revocation flag, downgrade
  200 + updated_limits → apply new limits (e.g. agent pack purchased)
  404 → license not on server (offline-only license, OK)
  Connection error → graceful degradation, local license continues
```

## 10.6 Feature Gating

```python
@requires_professional('Email Alerts')
def send_alert():
    # Only Professional edition
    pass

# Returns 403 if Demo edition
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

## 11.2 License Server

```python
# FastAPI endpoints:
POST /api/v1/license/activate     # Online activation (code → signed key)
POST /api/v1/license/heartbeat    # Installation heartbeat + telemetry
POST /api/licenses/request        # Customer requests license (manual flow)
POST /api/licenses/generate       # Admin generates license
GET  /api/licenses/{id}           # Get license status
POST /api/licenses/{id}/revoke    # Revoke license

# Online activation flow:
# Input:  { activation_code, installation_id, app_version }
# Output: { license_key: "<base64(payload)>.<base64(signature)>" }
# Errors: 404=code not found, 409=already used, 410=expired, 429=rate limited

# RSA key management:
- Private key: Signs licenses (NEVER shipped, stored on license server only)
- Public key: Embedded in SentriKat app (validates signatures locally)
```

## 11.3 Customer Portal

Features:
- License request form
- Download center (releases)
- Support ticket creation
- Documentation links
- Account management

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

## 12.3 Kubernetes Deployment

### Plain Manifests (`k8s/`)

```
k8s/
├── namespace.yaml          # sentrikat namespace
├── secret.yaml             # Database credentials, encryption key
├── configmap.yaml          # App configuration
├── app-deployment.yaml     # SentriKat app (3 replicas, rolling update)
├── app-service.yaml        # ClusterIP service
├── postgres-statefulset.yaml  # PostgreSQL with persistent volume
├── postgres-service.yaml   # PostgreSQL headless service
├── ingress.yaml            # Ingress with TLS
└── pdb.yaml                # PodDisruptionBudget (minAvailable: 1)
```

### Helm Chart (`helm/sentrikat/`)

```yaml
# helm install sentrikat helm/sentrikat/ -f values.yaml
replicaCount: 3
image:
  repository: ghcr.io/sbr0nch/sentrikat
  tag: latest

resources:
  requests: { cpu: 250m, memory: 512Mi }
  limits: { cpu: "1", memory: 1Gi }

autoscaling:
  enabled: true
  minReplicas: 2
  maxReplicas: 10
  targetCPUUtilization: 70

ingress:
  enabled: true
  tls: true

postgresql:
  persistence:
    size: 50Gi
```

Features: HPA auto-scaling, PodDisruptionBudget, Ingress with TLS, configurable resource limits, PostgreSQL StatefulSet with persistent volumes.

## 12.4 Database Migrations (Alembic)

```
migrations/
├── alembic.ini
├── env.py            # SQLAlchemy model auto-detection
└── script.py.mako    # Migration template
```

Schema changes managed via Alembic: `flask db upgrade` applies pending migrations on startup.

## 12.5 Monitoring & Observability

### Prometheus Metrics (`/metrics`)

```
# Application metrics exposed at /metrics endpoint
sentrikat_http_requests_total{method, endpoint, status}
sentrikat_http_request_duration_seconds{method, endpoint}
sentrikat_active_users_total
sentrikat_vulnerabilities_total{severity}
sentrikat_agents_total{status}
sentrikat_sync_duration_seconds{source}
sentrikat_webhook_deliveries_total{format, status}
```

### Automated Backups (`scripts/backup_cron.sh`)

- PostgreSQL `pg_dump` with configurable retention (7/30/90 days)
- Cron-ready script with rotation and compression
- Supports local and remote (S3-compatible) backup targets

## 12.6 CI/CD Pipeline

```yaml
# .github/workflows/ci.yml
on: [push, pull_request]

jobs:
  test:        # Run pytest with 70% coverage minimum
  security:    # Trivy container image scanning
  lint:        # Code quality checks

# .github/workflows/release.yml
on:
  push:
    tags: ["v*.*.*"]

jobs:
  test:        # Run pytest
  build:       # Build Docker image
  push:        # Push to GHCR
  release:     # Create GitHub Release
  notify:      # Update portal
```

### Dependabot (`.github/dependabot.yml`)

Automated dependency update PRs for Python (pip) and GitHub Actions.

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

# 15. UI/UX ARCHITECTURE

## 15.1 Dashboard

- **Two-Column Widget Layout**: Stats cards (left) and configurable chart widgets (right) side by side
- **Clickable Priority Cards**: CRITICAL/HIGH/MEDIUM/LOW cards filter the CVE table by severity
- **Configurable Chart Widgets**: Two widget slots with gear dropdown to select from 6 chart types:
  - **Priority Breakdown** (doughnut) - Unacknowledged matches by severity
  - **Top Affected Vendors** (horizontal bar) - Top 10 vendors with open vulnerabilities
  - **EPSS Distribution** (bar) - Exploit probability score distribution across matched CVEs
  - **Vulnerability Age** (bar) - Time distribution since CVEs were added to KEV catalog
  - **Monthly Timeline** (bar) - New affecting CVEs per month over the last 12 months
  - **Remediation Progress** (line) - Acknowledged vs unacknowledged trend over 30 days
- **Saved Widget Preferences**: Widget selection persists in localStorage; changing a widget automatically saves it as default
- **EPSS Risk Filter**: New filter in the advanced filters panel to filter CVEs by EPSS percentile (Top 5%/15%/30%)
- **Dark Mode Awareness**: Chart.js colors (grid, ticks, legend, tooltips) adapt to the active theme
- **Dismissible CPE Warning**: Products-without-CPE alert can be dismissed; reappears after 4 hours or when the count changes

## 15.2 Inventory Page (admin.html)

- **Products Tab**: Grouped product table with vendor, versions (vulnerable highlighted in red), CPE status, platforms, organizations
- **Connected Endpoints Tab**: Asset inventory (previously on Integrations page)
- **Software Overview Tab**: Cross-endpoint de-duplicated view with version sprawl detection and platform counts
- **Assign CPE Shortcut**: Products without CPE show a clickable "Assign" badge that opens the edit modal with NVD search pre-populated

## 15.3 Admin Panel (admin_panel.html)

- **Settings Tab Consolidation**: 12 settings sub-tabs consolidated to 6 grouped tabs using `showSettingsGroup()` with visual separators (dashed `<hr>` dividers and accent borders)
- **Multi-Tracker Checkboxes**: Issue tracker selection uses checkboxes instead of single dropdown, allowing simultaneous configuration
- **Integrations Tab**: Simplified view with Agent Keys (renamed from Push Agents) management

## 15.4 Theming

- **Dark Mode**: Full support via `[data-theme="dark"]` CSS selectors on `<html>` element
- **CSS Custom Properties**: `--surface-color`, `--text-color`, `--border-color`, etc. for consistent theming
- **Component Coverage**: All cards, tables, charts, modals, alerts, and separators adapt to dark mode

---

# 16. APPENDICES

## A. Environment Variables


```bash
# ── REQUIRED ──────────────────────────────────────────
SECRET_KEY=<random-string>           # Flask session signing (generate with: python -c "import secrets; print(secrets.token_hex(32))")
DB_PASSWORD=<database-password>      # PostgreSQL password

# ── OPTIONAL (auto-generated if missing) ──────────────
ENCRYPTION_KEY=<fernet-key>          # Auto-generated on first run, stored in DB
SENTRIKAT_INSTALLATION_ID=SK-INST-...  # Auto-generated hardware fingerprint

# ── LICENSE ───────────────────────────────────────────
SENTRIKAT_LICENSE=<signed-license-string>  # From portal.sentrikat.com (auto-syncs to DB)
# SENTRIKAT_LICENSE_PUBLIC_KEY=<base64-pem> # Override embedded public key (advanced)

# ── NVD API ───────────────────────────────────────────
NVD_API_KEY=<nvd-key>               # Optional but recommended (higher rate limits)

# ── NETWORK ───────────────────────────────────────────
FLASK_ENV=production                 # production or development
VERIFY_SSL=true                      # Set to false only for dev/self-signed certs
HTTP_PROXY=http://proxy:3128         # Corporate proxy support

# ── OAUTH/OIDC ───────────────────────────────────────
OIDC_CLIENT_ID=                      # OIDC provider client ID
OIDC_CLIENT_SECRET=                  # OIDC provider client secret
OIDC_DISCOVERY_URL=                  # OIDC .well-known/openid-configuration URL

# ── INCIDENT MANAGEMENT ──────────────────────────────
PAGERDUTY_ROUTING_KEY=               # PagerDuty Events API v2 routing key
OPSGENIE_API_KEY=                    # Opsgenie Alert API key

# ── OBSERVABILITY ────────────────────────────────────
SYSLOG_HOST=                         # Syslog/SIEM server (e.g., siem.example.com)
SYSLOG_PORT=514                      # Syslog port (default: 514)
SYSLOG_PROTOCOL=udp                  # udp or tcp

# ── PERFORMANCE ──────────────────────────────────────
GUNICORN_WORKERS=                    # Auto: min(CPU*2+1, 8). Set explicitly if needed.
GUNICORN_THREADS=4                   # Threads per worker (default: 4)
GUNICORN_TIMEOUT=120                 # Request timeout in seconds
```

**Minimum `.env` for Docker deployment:**
```bash
SECRET_KEY=change-me-to-something-random-and-long
DB_PASSWORD=change-me-to-a-secure-password
```

## B. API Rate Limits

| Endpoint | Limit |
|----------|-------|
| Global | 1000/day, 200/hour |
| Agent inventory | 60/minute |
| Agent heartbeat | 120/minute |
| Password reset | 5/hour |
| License online activation | 5/hour/IP |

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
| 1.1.0 | Feb 2026 | Development Team | Added: CVE auto-resolution, in-app update check, sidebar highlighting, dashboard redesign, clickable priority cards, dark mode, multi-tracker support, XSS fixes, settings consolidation, Software Overview tab, CPE UX improvements |
| 1.2.0 | Feb 2026 | Development Team | Added: Automatic vendor advisory sync (OSV.dev, Red Hat, MSRC, Debian), distro-native version comparison (dpkg/RPM/APK), three-tier confidence system (affected/likely resolved/resolved), license server heartbeat, agent distro_package_version support |
| 1.3.0 | Feb 2026 | Development Team | Added: Online license activation (activation code exchange via portal.sentrikat.com with rate limiting and security hardening), fixed agent product organization assignment, fixed Software Overview N+1 query performance |
| 1.4.0 | Feb 2026 | Development Team | Added: Configurable dashboard chart widgets (6 types with saved defaults), on-premise asset bundling, gthread Gunicorn workers with auto-scaling, connection pooling, EPSS filter, network requirements audit. Fixed: duplicate sortBy ID bug, VulnerabilitySnapshot multi-tenant mismatch |
| 1.5.0 | Feb 2026 | Development Team | Added: Immediate orphan cleanup on endpoint deletion (prevents "0 endpoints" ghost products after re-registration), endpoint deletion cascade documentation (§4.3.2), agent re-registration lifecycle (§4.3.3). Enhanced: Zero-day pipeline documentation with three-phase NVD sync, CNA CVSS source tracking, API outage protection, EUVD exploited vulnerability flow, re-enrichment cycle (§6.3.4). Fixed: maintenance cleanup_orphaned_products now handles org-assigned orphans (products with 0 installations but still assigned to organizations) |
| 1.6.0 | Feb 2026 | Development Team | **Enterprise Sprint (23 features)**: Added OAuth/OIDC via Authlib (§7.1), WebAuthn/FIDO2 hardware key auth (§7.1), session management with concurrent limits (§7.3), audit trail system with AuditLog model and REST API (§7.6), syslog forwarding (§7.6), PostgreSQL Row-Level Security (§7.7), SSRF protection for webhooks (§7.8), centralized webhook delivery with HMAC-SHA256 signing and retry logic (§8.4), PagerDuty and Opsgenie incident integration (§8.4), daily/weekly digest emails (§8.4), Prometheus /metrics endpoint (§12.5), Kubernetes manifests and Helm chart (§12.3), Alembic database migrations (§12.4), automated backup scripts (§12.5), Dependabot configuration, CI pipeline with 70% coverage gate and Trivy scanning (§12.6), RBAC permission_required decorator, production ENCRYPTION_KEY enforcement. New models: Permission, WebAuthnCredential, UserSession, AuditLog, DependencyScan, DependencyScanResult, SubscriptionPlan, Subscription, UsageRecord. Total: 37 models, 1,296 tests passing |

---

**END OF DOCUMENT**

*This document is confidential and intended for authorized recipients only. Unauthorized distribution is prohibited.*
