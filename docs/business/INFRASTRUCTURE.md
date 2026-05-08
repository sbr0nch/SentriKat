# SentriKat — Infrastructure & DevOps

> Internal reference: deployment architecture, multi-staging, CI/CD pipeline.
> **Consolidated 2026-05-07** from 3 source files for navigability.

## Table of Contents

- [Part 1 — Architecture Overview](#part-1--architecture-overview) (00 — business view)
- [Part 2 — Multi-Staging Architecture](#part-2--multi-staging-architecture) (09)
- [Part 3 — DevOps + CI/CD Plan](#part-3--devops--cicd-plan) (10)

For technical deep-dive on the matching pipeline and CVE data flow, see `docs/architecture/ARCHITECTURE.md`.

---

## Part 1 — Architecture Overview

# SENTRIKAT - COMPLETE ARCHITECTURE DOCUMENTATION
## Confidential Business & Technical Document
### For Investors, Buyers & Due Diligence

---

**Document Version:** 1.5.0
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
| Total Python Code | ~50,000+ lines (post Sprint 4+5) |
| Database Models | 35+ SQLAlchemy models |
| API Endpoints | 280+ REST endpoints |
| Frontend Templates | 9+ major pages |
| External Integrations | 15+ (Jira, GitHub, GitLab, YouTrack, LDAP, SAML, OSV, MSRC, etc.) |
| Test Coverage | 1,024+ pytest tests across 30+ test files |
| Compliance Frameworks | CISA BOD 22-01, EU NIS2, PCI-DSS v4.0, ISO/IEC 27001:2022, SOC 2, EU CRA (SBOM) |

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
- **Multi-Tracker Support**: Enable multiple issue trackers simultaneously (comma-separated configuration)
- **Jira**: Cloud and Server/Data Center support
- **GitHub Issues**: Create issues from CVEs
- **GitLab Issues**: Create issues from CVEs
- **YouTrack**: JetBrains issue tracker
- **Generic Webhook**: Custom integrations
- **Per-Tracker Actions**: Dashboard shows dedicated buttons per enabled tracker for ticket creation

### Reporting & Compliance
- **CISA BOD 22-01**: Compliance dashboard and reports
- **EU NIS2**: Article 21(2)(d)(e)(g) gap analysis report
- **PCI-DSS v4.0**: Gap analysis report (Req 6.3 secure systems, 11.3 vulnerability management) — JSON / PDF
- **ISO/IEC 27001:2022**: Gap analysis report (Annex A.8.8, A.8.16, A.5.24) — JSON / PDF
- **SOC 2**: Gap analysis report (CC7.1, CC7.2, CC7.4, CC6.6) — JSON / PDF
- **Cyber Resilience Act (EU 2024/2847)**: SBOM export ready for vendor obligations (effective Sep 2026)
- **Scheduled Reports**: PDF export via email
- **Vulnerability Trends**: Historical tracking with daily snapshots + Chart.js dashboard widget
- **Patch Tuesday Digest**: Monthly automated email on the 2nd Wednesday covering MSRC CVEs affecting the fleet
- **Integrity block**: All compliance reports carry SHA256 + HMAC signatures for audit evidence
- **Shared Dashboards**: Token-based public links

### SBOM Export (Software Bill of Materials)
- **CycloneDX 1.5 JSON**: Industry-standard SBOM with components, dependencies, vulnerabilities (purl format)
- **SPDX 2.3 JSON**: Linux Foundation SBOM standard with package definitions and external refs
- **STIX 2.1 Bundle**: Cyber threat intelligence format with vulnerability SDOs, software SCOs, relationship SROs
- **Use cases**: CRA compliance, EO 14028 (US federal), supply chain security, threat intel sharing (MISP/ISAC)

### Remediation Workflows
- **Assignments**: Create remediation tasks with due dates, severity, assignee, status (open/in_progress/resolved)
- **SLA Policies**: Configurable SLA per severity with automatic due_date computation
- **SLA Compliance**: Real-time dashboard of compliant vs overdue assignments
- **Issue Tracker Integration**: Native Jira / GitHub / GitLab / YouTrack / Webhook ticket creation with `tracker_issue_key` / `tracker_issue_url` / `tracker_type` tracking
- **Email Notifications**: Throttled (max 1/assignment/hour, only on created and resolved) to preserve Resend quotas
- **Risk Exception Management**: Accept-risk workflow with mandatory justification, optional expiry, ISO/SOC2 evidence
- **Product Aliases**: Vendor/product disambiguation for fleet normalization

### Agent Resilience (Sprint 4)
- **Delta Scan**: SHA256 hash-based change detection — full inventory only when software actually changes (~90% bandwidth reduction)
- **Gzip Compression**: All inventory + heartbeat payloads gzip-compressed with server-side zip-bomb protection (10MB decompressed / 2MB compressed limits)
- **Store-and-Forward**: Spool directory persists failed heartbeats and replays them in chronological order (max 50 spooled files)
- **24h forced full**: Heartbeat re-syncs full inventory at least daily even if hash unchanged

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
| Icons | Bootstrap Icons | UI icons |

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

## 3.7 Dual-Mode Architecture (SaaS vs On-Premise)

SentriKat operates in two mutually exclusive modes controlled by the `SENTRIKAT_MODE` environment variable:

- **`onpremise`** (default): Traditional self-hosted deployment with RSA-4096 signed license keys.
- **`saas`**: Multi-tenant cloud deployment with per-organization subscription plans via Stripe.

SaaS mode activation requires cryptographic validation (`SENTRIKAT_SAAS_TOKEN` = SHA-256 of `SENTRIKAT_SAAS_SECRET`) to prevent on-premise customers from enabling it.

### Mode Isolation Summary

The following controls enforce proper feature separation between modes:

**SaaS-only restrictions (not available to tenants):**
- Organization create/delete (provisioned by platform only)
- License activation/deactivation (subscriptions managed via Stripe)
- Backup & Restore (infrastructure operation)
- System Logs and Health Checks (visible only to platform super_admin)
- NVD Sync Settings (centrally managed)
- Data Retention Settings (platform policy with enforced minimums)
- Check for Updates (platform-managed)
- Worker management (infrastructure)

**On-Premise-only elements:**
- Organization Switcher (SaaS tenants are single-org)
- License management UI (RSA key activation/deactivation)
- Installation ID exposure
- DEMO VERSION banner

**Decorator system for dual-mode access control:**
- `@saas_admin_or_org_admin`: Allows org_admin in SaaS, requires super_admin in on-premise
- `@requires_professional(feature)`: SaaS-aware; checks subscription plan features in SaaS, RSA license in on-premise
- `@requires_feature(feature)`: Explicit dual-mode feature gating via `saas.py`
- `@restrict_cross_org_access`: Enforces tenant isolation in SaaS (no effect in on-premise)

See `docs/SAAS_INTEGRATION_SPEC.md` Section 12 for the complete isolation matrix.

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
│   ├── issue_trackers.py          # Multi-tracker engine (Jira/GitHub/GitLab/YouTrack)
│   ├── vendor_advisories.py      # Auto vendor patch detection (1000+ LOC)
│   ├── version_utils.py          # dpkg/RPM/APK version comparison (444 LOC)
│   ├── email_alerts.py           # Email system (626 LOC)
│   ├── scheduler.py              # Background jobs (468 LOC)
│   ├── encryption.py             # Fernet utils (141 LOC)
│   └── templates/                # Jinja2 templates
│       ├── base.html             # Layout, dark mode, global CSS/JS
│       ├── dashboard.html        # Dashboard with charts, priority cards, CVE table
│       ├── admin.html            # Inventory (Products, Endpoints, Software Overview)
│       ├── admin_panel.html      # Admin (Users, Orgs, Integrations, Settings)
│       └── ...
│
├── agents/                       # Agent scripts
│   ├── sentrikat-agent-windows.ps1
│   └── sentrikat-agent-linux.sh
│
├── static/                       # CSS, JS, images
│   └── js/
│       ├── admin_panel.js        # Admin panel logic (~9500 LOC)
│       └── sentrikat-core.js     # Core utilities (DOM, Toast, escaping)
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
| CISA KEV Sync | Daily 02:00 UTC | Fetch latest exploited vulnerabilities from CISA |
| NVD Recent CVEs Sync | Every 2 hours | Import new HIGH/CRITICAL CVEs from NVD (zero-day coverage) |
| Critical CVE Email | Daily 09:00 UTC | Send alert digests |
| Data Retention Cleanup | Daily 03:00 UTC | Delete old logs |
| Vulnerability Snapshot | Daily 02:00 UTC | Historical tracking |
| Scheduled Reports | Every 15 min | Process report queue |
| LDAP Sync | Configurable | Sync users from AD |
| **Vendor Advisory Sync** | Daily 03:00 UTC | Sync OSV.dev, Red Hat, MSRC, Debian feeds |
| **Maintenance** | Daily 04:00 UTC | 7-step cleanup & auto-resolution |

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

## 5.3 Total: 35+ Tables (post Sprint 4+5)

| Category | Tables |
|----------|--------|
| Auth/Users | User, Organization, UserOrganization, SystemSettings |
| Products | Product, ServiceCatalog, ProductExclusion, UserCpeMapping, CpeDictionaryEntry, ProductVersionHistory, **ProductAlias** |
| Vulnerabilities | Vulnerability, VulnerabilityMatch, VulnerabilitySnapshot, VendorFixOverride |
| Agents | AgentApiKey, Asset, ProductInstallation, AgentEvent, InventoryJob, AgentLicense, AgentUsageRecord |
| Containers | ContainerImage, ContainerVulnerability |
| **Remediation & Risk** | **RemediationAssignment, SLAPolicy, RiskException** |
| Reporting | ScheduledReport, HealthCheckResult |
| Logging | SyncLog, AlertLog, StaleAssetNotification |

**New in Sprint 4 (4 models):** RemediationAssignment, SLAPolicy, RiskException, ProductAlias.
**Existing model used in Sprint 5:** VulnerabilitySnapshot (now actively populated by the daily snapshot job and read by the trending dashboard widget + `/api/vulnerabilities/trends` endpoint).

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

# Product Aliases (Sprint 4 — vendor/product disambiguation)
GET    /api/product-aliases          # List aliases for the org
POST   /api/product-aliases          # Create alias (alias_vendor + alias_product → product_id)
DELETE /api/product-aliases/<id>     # Delete alias
```

## 6.2bis Remediation, SLA, Risk Exceptions (Sprint 4)

```
# Remediation Assignments
GET    /api/remediation/assignments              # List (filters: status, assignee, due)
POST   /api/remediation/assignments              # Create assignment
GET    /api/remediation/assignments/<id>         # Get details
PUT    /api/remediation/assignments/<id>         # Update (status, assignee, tracker_issue_key)
DELETE /api/remediation/assignments/<id>         # Delete

# SLA Policies
GET    /api/sla/policies                         # List policies
POST   /api/sla/policies                         # Create policy
PUT    /api/sla/policies/<id>                    # Update
DELETE /api/sla/policies/<id>                    # Delete
GET    /api/sla/compliance                       # Real-time compliance summary

# Risk Exceptions (accept-risk workflow with justification + expiry)
GET    /api/risk-exceptions                      # List exceptions
POST   /api/risk-exceptions                      # Create exception
PUT    /api/risk-exceptions/<id>                 # Update (extend expiry, change status)
DELETE /api/risk-exceptions/<id>                 # Revoke / delete
```

## 6.2ter SBOM Export (Sprint 4 + Sprint 5)

```
GET    /api/sbom/export/cyclonedx                # CycloneDX 1.5 JSON bundle
GET    /api/sbom/export/spdx                     # SPDX 2.3 JSON bundle
GET    /api/sbom/export/stix21                   # STIX 2.1 bundle (vuln SDOs + software SCOs + relationship SROs)
```

All SBOM endpoints are licensing-gated (feature key `sbom_export` in
`PROFESSIONAL_FEATURES`) and rate-limited to 10 requests/hour per organization.

## 6.2quater Compliance Reports (Sprint 5)

```
GET    /api/reports/compliance/bod-22-01         # CISA BOD 22-01 (existing)
GET    /api/reports/compliance/nis2              # EU NIS2 (existing)
GET    /api/reports/compliance/pci-dss           # PCI-DSS v4.0 gap analysis (Sprint 5)
GET    /api/reports/compliance/iso-27001         # ISO/IEC 27001:2022 gap analysis (Sprint 5)
GET    /api/reports/compliance/soc2              # SOC 2 gap analysis (Sprint 5)
POST   /api/reports/patch-tuesday/trigger        # Manual trigger of monthly Patch Tuesday digest (dry_run supported)
```

All compliance reports support `?format=json` (default) or `?format=pdf`. Each
report carries an `integrity` block with HMAC-SHA256 over the canonical JSON
body so auditors can verify the report has not been tampered with after
generation.

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

## 6.6 Settings & License

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
| XSS | Jinja2 autoescaping + `escapeHtml()` for dynamic innerHTML/showToast/onclick |
| CSRF | flask-wtf tokens (agent API routes exempt) |
| Clickjacking | X-Frame-Options: SAMEORIGIN |
| MIME Sniffing | X-Content-Type-Options: nosniff |
| Markdown Injection | Sanitized issue tracker ticket descriptions |

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

**Multi-Tracker Architecture**: Multiple trackers can be enabled simultaneously via comma-separated `issue_tracker_type` setting (e.g., `jira,github`). The dashboard renders per-tracker action buttons, and admin settings show all tracker configurations at once via checkboxes.

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

## 12.3 CI/CD Pipeline

```yaml
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

---

# 13. BUSINESS MODEL

## 13.1 Pricing Tiers

**On-Premise:**

| Tier | Price | Agents | Features |
|------|-------|--------|----------|
| Demo | Free | 5 | Basic only |
| Professional | €4,999/year | 10 base + packs | All features |
| Agent Pack +25 | +€999/year | +25 | Add-on |
| Agent Pack +50 | +€1,499/year | +50 | Add-on |
| Agent Pack +100 | +€2,499/year | +100 | Add-on |
| Unlimited Agents | +€3,999/year | Unlimited | Add-on |
| Support Pack | +€999/year | - | Priority support |

**SaaS (app.sentrikat.com):**

| Tier | Monthly | Annual | Agents | Users |
|------|---------|--------|--------|-------|
| Free | €0 | €0 | 3 | 1 |
| Starter | €59/mo | €590/yr | 10 | 3 |
| Professional | €199/mo | €1,990/yr | 25 | 5 |
| Business | €499/mo | €4,990/yr | 50 | 10 |
| Enterprise | €999/mo | €9,990/yr | Unlimited | Unlimited |

## 13.2 Revenue Model

- **Subscription**: Monthly/annual SaaS plans (€59-999/mo) or on-premise license (€4,999/yr)
- **Agent Packs**: Pay for endpoint scale (on-premise: +25/+50/+100/unlimited)
- **Support**: Premium support pack (€999/yr)
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

---

**END OF DOCUMENT**

*This document is confidential and intended for authorized recipients only. Unauthorized distribution is prohibited.*


---

## Part 2 — Multi-Staging Architecture

# SENTRIKAT - MULTI-STAGING ARCHITECTURE
## Piano Architetturale per Ambienti Development, Staging e Production

---

**Versione:** 1.0
**Ultimo Aggiornamento:** Febbraio 2026
**Autore:** SentriKat Development Team

---

## 1. PANORAMICA

### 1.1 Obiettivi del Multi-Staging

| Obiettivo | Descrizione |
|-----------|-------------|
| **Isolamento** | Separazione completa tra ambienti per evitare impatti su produzione |
| **Qualità** | Test approfonditi prima del rilascio |
| **Velocità** | Deploy frequenti con rischio controllato |
| **Compliance** | Audit trail e controllo cambiamenti |
| **Disaster Recovery** | Ambiente di fallback in caso di problemi |

### 1.2 Ambienti Proposti

```
┌─────────────────────────────────────────────────────────────────────┐
│                     SENTRIKAT ENVIRONMENT PIPELINE                   │
├─────────────────────────────────────────────────────────────────────┤
│                                                                      │
│   ┌──────────┐    ┌──────────┐    ┌──────────┐    ┌──────────┐     │
│   │   DEV    │───>│  TEST    │───>│ STAGING  │───>│   PROD   │     │
│   │          │    │          │    │          │    │          │     │
│   │ Feature  │    │ QA/Auto  │    │ Pre-Prod │    │  Live    │     │
│   │ Branch   │    │ Testing  │    │ Validation│   │ Customers│     │
│   └──────────┘    └──────────┘    └──────────┘    └──────────┘     │
│        │               │               │               │            │
│        ▼               ▼               ▼               ▼            │
│   [Developers]   [CI/CD Auto]   [QA Team +     [Monitoring +       │
│                                  Stakeholders]  On-Call]            │
│                                                                      │
└─────────────────────────────────────────────────────────────────────┘
```

---

## 2. ARCHITETTURA PER AMBIENTE

### 2.1 Development (DEV)

**Scopo:** Sviluppo locale e feature branch testing

```yaml
# docker-compose.dev.yml
version: '3.8'

services:
  sentrikat:
    build:
      context: .
      dockerfile: Dockerfile.dev
    ports:
      - "5000:5000"
    environment:
      - FLASK_ENV=development
      - FLASK_DEBUG=1
      - DATABASE_URL=postgresql://dev:dev@db:5432/sentrikat_dev
      - SECRET_KEY=dev-secret-key-not-for-prod
      - SENTRIKAT_LICENSE=  # Demo mode
    volumes:
      - ./app:/app/app:ro  # Hot reload
      - ./tests:/app/tests:ro
    depends_on:
      - db
      - mailhog

  db:
    image: postgres:16-alpine
    environment:
      - POSTGRES_USER=dev
      - POSTGRES_PASSWORD=dev
      - POSTGRES_DB=sentrikat_dev
    ports:
      - "5432:5432"  # Accessible for debugging
    volumes:
      - dev-postgres:/var/lib/postgresql/data

  mailhog:
    image: mailhog/mailhog
    ports:
      - "1025:1025"  # SMTP
      - "8025:8025"  # Web UI

  adminer:
    image: adminer
    ports:
      - "8080:8080"  # Database admin UI

volumes:
  dev-postgres:
```

**Caratteristiche DEV:**
- Hot reload del codice
- Debug mode attivo
- Database locale con dati di test
- MailHog per cattura email
- Adminer per gestione DB
- Nessuna licenza richiesta (Demo mode)

---

### 2.2 Test (TEST/CI)

**Scopo:** Test automatizzati in CI/CD

```yaml
# docker-compose.test.yml
version: '3.8'

services:
  sentrikat-test:
    build:
      context: .
      dockerfile: Dockerfile
    environment:
      - FLASK_ENV=testing
      - DATABASE_URL=postgresql://test:test@db-test:5432/sentrikat_test
      - SECRET_KEY=test-secret-key
      - TESTING=true
    depends_on:
      - db-test

  db-test:
    image: postgres:16-alpine
    environment:
      - POSTGRES_USER=test
      - POSTGRES_PASSWORD=test
      - POSTGRES_DB=sentrikat_test
    tmpfs:
      - /var/lib/postgresql/data  # RAM disk for speed

  test-runner:
    build:
      context: .
      dockerfile: Dockerfile.test
    command: pytest -v --cov=app --cov-report=xml
    environment:
      - DATABASE_URL=postgresql://test:test@db-test:5432/sentrikat_test
    depends_on:
      - db-test
    volumes:
      - ./test-results:/app/test-results
```

**Caratteristiche TEST:**
- Database in RAM per velocità
- Coverage report generato
- Nessuna persistenza dati
- Esecuzione isolata per ogni build
- Timeout aggressivi

---

### 2.3 Staging (STAGING)

**Scopo:** Validazione pre-produzione con dati realistici

```yaml
# docker-compose.staging.yml
version: '3.8'

services:
  nginx:
    image: nginx:alpine
    ports:
      - "443:443"
    volumes:
      - ./nginx/staging.conf:/etc/nginx/nginx.conf:ro
      - ./ssl/staging:/etc/nginx/ssl:ro
    depends_on:
      - sentrikat

  sentrikat:
    image: ghcr.io/sbr0nch/sentrikat:${VERSION:-latest}
    environment:
      - FLASK_ENV=staging
      - DATABASE_URL=postgresql://${DB_USER}:${DB_PASS}@db:5432/sentrikat_staging
      - SECRET_KEY=${SECRET_KEY}
      - ENCRYPTION_KEY=${ENCRYPTION_KEY}
      - SENTRIKAT_INSTALLATION_ID=${STAGING_INSTALLATION_ID}
      - SENTRIKAT_LICENSE=${STAGING_LICENSE}
      - VERIFY_SSL=true
    depends_on:
      - db
    deploy:
      resources:
        limits:
          memory: 2G
          cpus: '2'

  db:
    image: postgres:16-alpine
    environment:
      - POSTGRES_USER=${DB_USER}
      - POSTGRES_PASSWORD=${DB_PASS}
      - POSTGRES_DB=sentrikat_staging
    volumes:
      - staging-postgres:/var/lib/postgresql/data
    deploy:
      resources:
        limits:
          memory: 1G

  # Backup automatico giornaliero
  backup:
    image: prodrigestivill/postgres-backup-local
    environment:
      - POSTGRES_HOST=db
      - POSTGRES_DB=sentrikat_staging
      - POSTGRES_USER=${DB_USER}
      - POSTGRES_PASSWORD=${DB_PASS}
      - BACKUP_KEEP_DAYS=7
      - SCHEDULE=@daily
    volumes:
      - ./backups/staging:/backups

volumes:
  staging-postgres:
```

**Caratteristiche STAGING:**
- Immagine Docker identica a produzione
- Dati anonimi/sanitizzati da produzione
- SSL/TLS attivo
- Backup automatici
- Resource limits simili a produzione
- Licenza staging dedicata
- Accessibile a QA e stakeholders

**URL Staging:** `https://staging.sentrikat.com` (interno)

---

### 2.4 Production (PROD)

**Scopo:** Ambiente live per i clienti

```yaml
# docker-compose.prod.yml
version: '3.8'

services:
  nginx:
    image: nginx:alpine
    ports:
      - "443:443"
      - "80:80"  # Redirect to HTTPS
    volumes:
      - ./nginx/prod.conf:/etc/nginx/nginx.conf:ro
      - ./ssl/prod:/etc/nginx/ssl:ro
      - ./nginx/logs:/var/log/nginx
    depends_on:
      - sentrikat
    restart: always
    deploy:
      resources:
        limits:
          memory: 256M

  sentrikat:
    image: ghcr.io/sbr0nch/sentrikat:${VERSION}
    environment:
      - FLASK_ENV=production
      - DATABASE_URL=postgresql://${DB_USER}:${DB_PASS}@db:5432/sentrikat_prod
      - SECRET_KEY=${SECRET_KEY}
      - ENCRYPTION_KEY=${ENCRYPTION_KEY}
      - SENTRIKAT_INSTALLATION_ID=${PROD_INSTALLATION_ID}
      - SENTRIKAT_LICENSE=${PROD_LICENSE}
      - NVD_API_KEY=${NVD_API_KEY}
      - VERIFY_SSL=true
      - GUNICORN_WORKERS=4
      - GUNICORN_TIMEOUT=120
    depends_on:
      - db
    restart: always
    deploy:
      resources:
        limits:
          memory: 4G
          cpus: '4'
    healthcheck:
      test: ["CMD", "curl", "-f", "http://localhost:5000/health"]
      interval: 30s
      timeout: 10s
      retries: 3
      start_period: 40s

  db:
    image: postgres:16-alpine
    environment:
      - POSTGRES_USER=${DB_USER}
      - POSTGRES_PASSWORD=${DB_PASS}
      - POSTGRES_DB=sentrikat_prod
    volumes:
      - prod-postgres:/var/lib/postgresql/data
      - ./postgres/conf:/etc/postgresql/conf.d:ro
    restart: always
    deploy:
      resources:
        limits:
          memory: 4G
    command: >
      postgres
        -c shared_buffers=1GB
        -c effective_cache_size=3GB
        -c maintenance_work_mem=256MB
        -c checkpoint_completion_target=0.9
        -c wal_buffers=16MB
        -c max_connections=200

  # Backup automatico
  backup:
    image: prodrigestivill/postgres-backup-local
    environment:
      - POSTGRES_HOST=db
      - POSTGRES_DB=sentrikat_prod
      - POSTGRES_USER=${DB_USER}
      - POSTGRES_PASSWORD=${DB_PASS}
      - BACKUP_KEEP_DAYS=30
      - BACKUP_KEEP_WEEKS=8
      - BACKUP_KEEP_MONTHS=6
      - SCHEDULE=0 2 * * *  # 2 AM daily
    volumes:
      - ./backups/prod:/backups
    restart: always

  # Monitoring
  prometheus:
    image: prom/prometheus:latest
    volumes:
      - ./monitoring/prometheus.yml:/etc/prometheus/prometheus.yml
      - prometheus-data:/prometheus
    restart: always

  grafana:
    image: grafana/grafana:latest
    ports:
      - "3000:3000"
    volumes:
      - grafana-data:/var/lib/grafana
    restart: always

volumes:
  prod-postgres:
  prometheus-data:
  grafana-data:
```

**Caratteristiche PROD:**
- High availability ready
- Backup multi-livello (daily/weekly/monthly)
- Monitoring con Prometheus/Grafana
- Health checks
- Auto-restart on failure
- Tuned PostgreSQL
- SSL/TLS con certificati validi
- Rate limiting attivo

---

## 3. NETWORK ARCHITECTURE

### 3.1 Separazione Network

```
┌─────────────────────────────────────────────────────────────────────┐
│                        NETWORK TOPOLOGY                              │
├─────────────────────────────────────────────────────────────────────┤
│                                                                      │
│  ┌─────────────────────────────────────────────────────────────┐    │
│  │                    INTERNET / CLIENTS                         │    │
│  └─────────────────────────────┬───────────────────────────────┘    │
│                                │                                     │
│                    ┌───────────▼───────────┐                        │
│                    │      CLOUDFLARE       │                        │
│                    │      (CDN/WAF)        │                        │
│                    └───────────┬───────────┘                        │
│                                │                                     │
│  ┌─────────────────────────────┼─────────────────────────────────┐  │
│  │                     DMZ NETWORK                                │  │
│  │         ┌───────────────────▼───────────────────┐             │  │
│  │         │           NGINX PROXY                  │             │  │
│  │         │         (SSL Termination)              │             │  │
│  │         └───────────────────┬───────────────────┘             │  │
│  └─────────────────────────────┼─────────────────────────────────┘  │
│                                │                                     │
│  ┌─────────────────────────────┼─────────────────────────────────┐  │
│  │                  APPLICATION NETWORK                           │  │
│  │         ┌───────────────────▼───────────────────┐             │  │
│  │         │        SENTRIKAT APP                   │             │  │
│  │         │       (Flask/Gunicorn)                 │             │  │
│  │         └───────────────────┬───────────────────┘             │  │
│  └─────────────────────────────┼─────────────────────────────────┘  │
│                                │                                     │
│  ┌─────────────────────────────┼─────────────────────────────────┐  │
│  │                   DATABASE NETWORK                             │  │
│  │         ┌───────────────────▼───────────────────┐             │  │
│  │         │          POSTGRESQL                    │             │  │
│  │         │         (No external)                  │             │  │
│  │         └───────────────────────────────────────┘             │  │
│  └───────────────────────────────────────────────────────────────┘  │
│                                                                      │
└─────────────────────────────────────────────────────────────────────┘
```

### 3.2 Firewall Rules

```bash
# Production firewall rules (UFW example)

# Default policies
ufw default deny incoming
ufw default allow outgoing

# Allow SSH (with IP restriction)
ufw allow from 10.0.0.0/8 to any port 22

# Allow HTTPS
ufw allow 443/tcp

# Allow HTTP (redirect to HTTPS)
ufw allow 80/tcp

# Internal network for services
ufw allow from 172.18.0.0/16 to any

# Block direct database access
ufw deny 5432

# Enable
ufw enable
```

---

## 4. DATA FLOW E PROMOZIONE

### 4.1 Flusso di Promozione Codice

```
┌──────────┐    ┌──────────┐    ┌──────────┐    ┌──────────┐
│ Feature  │───>│  Test    │───>│ Staging  │───>│   Main   │
│ Branch   │    │  Pass    │    │  Approve │    │  Release │
└──────────┘    └──────────┘    └──────────┘    └──────────┘
     │               │               │               │
     │               │               │               │
     ▼               ▼               ▼               ▼
┌──────────┐    ┌──────────┐    ┌──────────┐    ┌──────────┐
│   DEV    │    │   TEST   │    │ STAGING  │    │   PROD   │
│  (auto)  │    │  (auto)  │    │ (manual) │    │ (manual) │
└──────────┘    └──────────┘    └──────────┘    └──────────┘
```

### 4.2 Promozione Dati (Reverse)

```
PROD ──sanitize──> STAGING ──subset──> DEV

⚠️ MAI copiare dati da DEV/STAGING a PROD
```

**Script di sanitizzazione:**

```bash
#!/bin/bash
# sanitize-prod-to-staging.sh

# Dump produzione
pg_dump -h prod-db -U admin sentrikat_prod > /tmp/prod_dump.sql

# Sanitize sensitive data
sed -i 's/password_hash.*$/password_hash = "$2b$12$sanitized"/g' /tmp/prod_dump.sql
sed -i 's/smtp_password.*$/smtp_password = "REDACTED"/g' /tmp/prod_dump.sql
sed -i 's/webhook_url.*$/webhook_url = "https://staging-webhook.example.com"/g' /tmp/prod_dump.sql

# Remove PII
psql -f /tmp/prod_dump.sql sentrikat_staging
psql sentrikat_staging << EOF
  UPDATE "user" SET email = 'user_' || id || '@example.com';
  UPDATE "user" SET username = 'user_' || id;
  DELETE FROM alert_log;
  DELETE FROM sync_log WHERE created_at < NOW() - INTERVAL '7 days';
EOF

echo "Staging database sanitized from production"
```

---

## 5. DEPLOYMENT STRATEGY

### 5.1 Blue-Green Deployment (Production)

```
┌─────────────────────────────────────────────────────────────────────┐
│                    BLUE-GREEN DEPLOYMENT                             │
├─────────────────────────────────────────────────────────────────────┤
│                                                                      │
│                    ┌──────────────────┐                             │
│                    │   LOAD BALANCER  │                             │
│                    │    (nginx)       │                             │
│                    └────────┬─────────┘                             │
│                             │                                        │
│              ┌──────────────┴──────────────┐                        │
│              │ (switch traffic)            │                        │
│              ▼                             ▼                        │
│   ┌──────────────────┐         ┌──────────────────┐                │
│   │   BLUE (v1.0.0)  │         │  GREEN (v1.0.1)  │                │
│   │   ✓ ACTIVE       │         │   ○ STANDBY      │                │
│   │                  │         │   (new version)  │                │
│   └──────────────────┘         └──────────────────┘                │
│                                                                      │
│   ROLLBACK: Switch traffic back to BLUE                            │
│                                                                      │
└─────────────────────────────────────────────────────────────────────┘
```

**nginx config per blue-green:**

```nginx
# /etc/nginx/conf.d/sentrikat.conf

upstream sentrikat_blue {
    server sentrikat-blue:5000;
}

upstream sentrikat_green {
    server sentrikat-green:5000;
}

# Active backend (change this for deployment)
map $request_uri $backend {
    default sentrikat_blue;  # Change to sentrikat_green for deploy
}

server {
    listen 443 ssl http2;
    server_name sentrikat.com;

    location / {
        proxy_pass http://$backend;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
    }
}
```

### 5.2 Rolling Deployment (Kubernetes - Futuro)

```yaml
# k8s/deployment.yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: sentrikat
spec:
  replicas: 3
  strategy:
    type: RollingUpdate
    rollingUpdate:
      maxSurge: 1
      maxUnavailable: 0
  selector:
    matchLabels:
      app: sentrikat
  template:
    metadata:
      labels:
        app: sentrikat
    spec:
      containers:
      - name: sentrikat
        image: ghcr.io/sbr0nch/sentrikat:1.0.1
        ports:
        - containerPort: 5000
        readinessProbe:
          httpGet:
            path: /health
            port: 5000
          initialDelaySeconds: 10
          periodSeconds: 5
        livenessProbe:
          httpGet:
            path: /health
            port: 5000
          initialDelaySeconds: 30
          periodSeconds: 10
```

---

## 6. CONFIGURATION MANAGEMENT

### 6.1 Environment Variables per Ambiente

```bash
# .env.dev
FLASK_ENV=development
DATABASE_URL=postgresql://dev:dev@localhost:5432/sentrikat_dev
SECRET_KEY=dev-not-secure
DEBUG=true

# .env.staging
FLASK_ENV=staging
DATABASE_URL=postgresql://staging_user:${DB_PASS}@db:5432/sentrikat_staging
SECRET_KEY=${SECRET_KEY}
DEBUG=false
SENTRIKAT_LICENSE=${STAGING_LICENSE}

# .env.prod
FLASK_ENV=production
DATABASE_URL=postgresql://prod_user:${DB_PASS}@db:5432/sentrikat_prod
SECRET_KEY=${SECRET_KEY}
DEBUG=false
SENTRIKAT_LICENSE=${PROD_LICENSE}
NVD_API_KEY=${NVD_API_KEY}
```

### 6.2 Secrets Management

**Opzione 1: Docker Secrets (Docker Swarm)**
```yaml
secrets:
  db_password:
    external: true
  secret_key:
    external: true

services:
  sentrikat:
    secrets:
      - db_password
      - secret_key
```

**Opzione 2: HashiCorp Vault (Enterprise)**
```bash
# Lettura secrets da Vault
export DATABASE_URL=$(vault kv get -field=url secret/sentrikat/prod/database)
export SECRET_KEY=$(vault kv get -field=key secret/sentrikat/prod/app)
```

**Opzione 3: Cloud Provider Secrets**
- AWS Secrets Manager
- Azure Key Vault
- Google Secret Manager

---

## 7. MONITORING E ALERTING

### 7.1 Stack di Monitoring

```
┌─────────────────────────────────────────────────────────────────────┐
│                     MONITORING STACK                                 │
├─────────────────────────────────────────────────────────────────────┤
│                                                                      │
│   ┌─────────────┐    ┌─────────────┐    ┌─────────────┐            │
│   │ SENTRIKAT   │───>│ PROMETHEUS  │───>│  GRAFANA    │            │
│   │  /metrics   │    │  (scrape)   │    │ (visualize) │            │
│   └─────────────┘    └─────────────┘    └─────────────┘            │
│          │                  │                   │                    │
│          │                  ▼                   │                    │
│          │           ┌─────────────┐            │                    │
│          │           │ALERTMANAGER │────────────┤                    │
│          │           └─────────────┘            │                    │
│          │                  │                   │                    │
│          ▼                  ▼                   ▼                    │
│   ┌─────────────┐    ┌─────────────┐    ┌─────────────┐            │
│   │    LOKI     │    │   SLACK     │    │  PAGERDUTY  │            │
│   │   (logs)    │    │  (alerts)   │    │ (on-call)   │            │
│   └─────────────┘    └─────────────┘    └─────────────┘            │
│                                                                      │
└─────────────────────────────────────────────────────────────────────┘
```

### 7.2 Metriche Chiave

| Metrica | Warning | Critical | Azione |
|---------|---------|----------|--------|
| CPU Usage | >70% | >90% | Scale up |
| Memory Usage | >75% | >90% | Scale up / investigate |
| Disk Usage | >70% | >85% | Cleanup / expand |
| Response Time (p99) | >2s | >5s | Investigate / scale |
| Error Rate | >1% | >5% | Investigate |
| DB Connections | >80% pool | >95% pool | Increase pool |
| Agent Checkin Failures | >5% | >20% | Alert + investigate |

### 7.3 Alert Rules (Prometheus)

```yaml
# alerting_rules.yml
groups:
  - name: sentrikat
    rules:
      - alert: HighErrorRate
        expr: rate(http_requests_total{status=~"5.."}[5m]) > 0.05
        for: 5m
        labels:
          severity: critical
        annotations:
          summary: "High error rate detected"

      - alert: SlowResponses
        expr: histogram_quantile(0.99, rate(http_request_duration_seconds_bucket[5m])) > 5
        for: 10m
        labels:
          severity: warning
        annotations:
          summary: "Slow response times"

      - alert: DatabaseConnectionsHigh
        expr: pg_stat_activity_count > 180
        for: 5m
        labels:
          severity: warning
        annotations:
          summary: "Database connections approaching limit"
```

---

## 8. DISASTER RECOVERY

### 8.1 RPO e RTO per Ambiente

| Ambiente | RPO (Data Loss) | RTO (Downtime) |
|----------|-----------------|----------------|
| DEV | N/A | N/A |
| TEST | N/A | N/A |
| STAGING | 24 hours | 4 hours |
| PROD | 1 hour | 30 minutes |

### 8.2 Backup Strategy

```bash
#!/bin/bash
# backup-strategy.sh

# Continuous WAL archiving (Point-in-Time Recovery)
# postgresql.conf:
# archive_mode = on
# archive_command = 'aws s3 cp %p s3://sentrikat-backups/wal/%f'

# Daily full backup
pg_dump -Fc sentrikat_prod | aws s3 cp - s3://sentrikat-backups/daily/$(date +%Y%m%d).dump

# Weekly full backup (kept for 3 months)
if [ $(date +%u) -eq 7 ]; then
    pg_dump -Fc sentrikat_prod | aws s3 cp - s3://sentrikat-backups/weekly/$(date +%Y%m%d).dump
fi

# Monthly backup (kept for 1 year)
if [ $(date +%d) -eq 1 ]; then
    pg_dump -Fc sentrikat_prod | aws s3 cp - s3://sentrikat-backups/monthly/$(date +%Y%m).dump
fi
```

### 8.3 Recovery Procedures

```bash
#!/bin/bash
# restore-from-backup.sh

# 1. Stop application
docker-compose -f docker-compose.prod.yml stop sentrikat

# 2. Restore database
BACKUP_FILE=$1
aws s3 cp s3://sentrikat-backups/daily/${BACKUP_FILE} /tmp/restore.dump
pg_restore -c -d sentrikat_prod /tmp/restore.dump

# 3. Verify data integrity
psql sentrikat_prod -c "SELECT COUNT(*) FROM vulnerability;"
psql sentrikat_prod -c "SELECT COUNT(*) FROM product;"

# 4. Start application
docker-compose -f docker-compose.prod.yml up -d sentrikat

# 5. Verify health
curl -f http://localhost:5000/health
```

---

## 9. COSTI STIMATI

### 9.1 Costi Infrastruttura Mensili

| Ambiente | Server | Database | Storage | Totale/mese |
|----------|--------|----------|---------|-------------|
| DEV | Locale | Locale | Locale | €0 |
| TEST | CI/CD minutes | N/A | N/A | ~€20 (GitHub) |
| STAGING | VPS 2CPU/4GB | Incluso | 50GB | ~€25 |
| PROD (small) | VPS 4CPU/8GB | Managed | 100GB | ~€80 |
| PROD (medium) | VPS 8CPU/16GB | Managed | 250GB | ~€200 |

**Provider consigliati (EU-based):**
- Hetzner Cloud: https://www.hetzner.com/cloud
- OVH: https://www.ovhcloud.com
- Scaleway: https://www.scaleway.com

### 9.2 Costi Aggiuntivi

| Servizio | Costo | Note |
|----------|-------|------|
| Cloudflare | Free tier | CDN, DDoS, basic WAF |
| SSL Certificate | Free (Let's Encrypt) | Auto-renewal |
| Monitoring (Grafana Cloud) | Free tier | 10k metrics |
| Backup Storage (S3) | ~€5/mese | Per 100GB |
| Domain | ~€15/anno | .com |

---

## 10. PIANO DI IMPLEMENTAZIONE

### 10.1 Fase 1: Fondazione (Settimana 1-2)

- [ ] Setup VPS per staging
- [ ] Configurare docker-compose.staging.yml
- [ ] Implementare CI/CD per staging auto-deploy
- [ ] Configurare backup automatici

### 10.2 Fase 2: Produzione (Settimana 3-4)

- [ ] Setup VPS produzione
- [ ] Configurare SSL/TLS
- [ ] Implementare monitoring base
- [ ] Test disaster recovery

### 10.3 Fase 3: Ottimizzazione (Settimana 5-8)

- [ ] Fine-tuning PostgreSQL
- [ ] Implementare blue-green deployment
- [ ] Setup alerting completo
- [ ] Documentazione runbook

---

## RISORSE E RIFERIMENTI

- [12 Factor App](https://12factor.net/) - Best practices per app cloud-native
- [Docker Compose Production](https://docs.docker.com/compose/production/)
- [PostgreSQL Tuning](https://pgtune.leopard.in.ua/) - Calcolo parametri ottimali
- [Prometheus Best Practices](https://prometheus.io/docs/practices/)

---

*Documento da aggiornare con le specifiche dell'infrastruttura scelta.*


---

## Part 3 — DevOps + CI/CD Plan

# SENTRIKAT - DEVOPS & CI/CD PLAN
## Stato Attuale e Roadmap delle Automazioni

---

**Versione:** 1.0
**Ultimo Aggiornamento:** Febbraio 2026
**Autore:** SentriKat Development Team

---

## 1. STATO ATTUALE (AS-IS)

### 1.1 Infrastruttura CI/CD Esistente

```
┌─────────────────────────────────────────────────────────────────────┐
│                    CURRENT CI/CD PIPELINE                            │
├─────────────────────────────────────────────────────────────────────┤
│                                                                      │
│   ┌──────────┐    ┌──────────┐    ┌──────────┐    ┌──────────┐     │
│   │  PUSH    │───>│   CI     │───>│  BUILD   │───>│  GHCR    │     │
│   │  (git)   │    │ (tests)  │    │ (docker) │    │ (publish)│     │
│   └──────────┘    └──────────┘    └──────────┘    └──────────┘     │
│        │               │               │               │            │
│        │               │               │               │            │
│   [Developer]     [GitHub]        [GitHub]        [GitHub]         │
│                   Actions         Actions         Actions          │
│                                                                      │
│   ✅ Attivo       ✅ Attivo       ✅ Attivo       ✅ Attivo         │
│                                                                      │
└─────────────────────────────────────────────────────────────────────┘
```

### 1.2 Workflow Esistenti

#### `.github/workflows/ci.yml` - Continuous Integration

```yaml
# Stato: ✅ ATTIVO
name: CI

on:
  push:
    branches: [main]
  pull_request:
    branches: [main]

jobs:
  lint:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-python@v5
        with:
          python-version: '3.11'
      - run: pip install flake8
      - run: flake8 app/ --count --select=E9,F63,F7,F82 --show-source

  test:
    runs-on: ubuntu-latest
    needs: lint
    services:
      postgres:
        image: postgres:16
        env:
          POSTGRES_PASSWORD: test
        ports:
          - 5432:5432
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-python@v5
      - run: pip install -r requirements.txt
      - run: pytest tests/ -v
```

**Metriche attuali:**
- Tempo medio build: ~3-5 minuti
- Success rate: ~95%
- Coverage: Non ancora configurato

#### `.github/workflows/release.yml` - Release Automation

```yaml
# Stato: ✅ ATTIVO
name: Release

on:
  push:
    tags: ['v*.*.*']

jobs:
  build-and-push:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: docker/login-action@v3
        with:
          registry: ghcr.io
          username: ${{ github.actor }}
          password: ${{ secrets.GITHUB_TOKEN }}
      - uses: docker/build-push-action@v5
        with:
          push: true
          tags: |
            ghcr.io/sbr0nch/sentrikat:${{ github.ref_name }}
            ghcr.io/sbr0nch/sentrikat:latest
```

**Output attuali:**
- Docker image su GHCR
- GitHub Release con asset zip
- docker-compose.yml incluso nel release

### 1.3 Cosa Manca (Gaps)

| Area | Stato Attuale | Gap |
|------|---------------|-----|
| Test Coverage | Non tracciato | Nessun report coverage |
| Security Scanning | Non attivo | Nessun SAST/DAST |
| Dependency Updates | Manuale | Nessun Dependabot |
| Staging Deploy | Manuale | Nessun auto-deploy |
| Production Deploy | Manuale | Nessun auto-deploy |
| Monitoring | Non attivo | Nessun alerting |
| Documentation | Manuale | Nessuna doc generation |

---

## 2. ROADMAP DEVOPS

### 2.1 Timeline Overview

```
         Q1 2026          Q2 2026          Q3 2026          Q4 2026
            │                │                │                │
            ▼                ▼                ▼                ▼
    ┌───────────────┐ ┌───────────────┐ ┌───────────────┐ ┌───────────────┐
    │  FOUNDATION   │ │   QUALITY     │ │   SECURITY    │ │   SCALE       │
    │               │ │               │ │               │ │               │
    │ • Basic CI/CD │ │ • Coverage    │ │ • SAST/DAST   │ │ • K8s ready   │
    │ • Lint/Test   │ │ • Staging CD  │ │ • Compliance  │ │ • Multi-region│
    │ • Docker      │ │ • Dependabot  │ │ • Pen testing │ │ • DR tested   │
    │               │ │               │ │               │ │               │
    │ ✅ COMPLETATO │ │ 🔄 IN CORSO   │ │ ⏳ PIANIFICATO│ │ ⏳ PIANIFICATO│
    └───────────────┘ └───────────────┘ └───────────────┘ └───────────────┘
```

---

## 3. FASE 2: QUALITY (Q2 2026)

### 3.1 Test Coverage Reporting

```yaml
# .github/workflows/ci.yml - AGGIORNAMENTO
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-python@v5
        with:
          python-version: '3.11'

      - name: Install dependencies
        run: |
          pip install -r requirements.txt
          pip install pytest-cov

      - name: Run tests with coverage
        run: |
          pytest tests/ -v \
            --cov=app \
            --cov-report=xml \
            --cov-report=html \
            --cov-fail-under=70

      - name: Upload coverage to Codecov
        uses: codecov/codecov-action@v4
        with:
          files: ./coverage.xml
          fail_ci_if_error: true

      - name: Upload coverage report
        uses: actions/upload-artifact@v4
        with:
          name: coverage-report
          path: htmlcov/
```

**Target Coverage:**
- Q2 2026: 70%
- Q3 2026: 80%
- Q4 2026: 85%

### 3.2 Continuous Deployment to Staging

```yaml
# .github/workflows/deploy-staging.yml - NUOVO
name: Deploy to Staging

on:
  push:
    branches: [main]
  workflow_dispatch:

jobs:
  deploy:
    runs-on: ubuntu-latest
    environment: staging

    steps:
      - uses: actions/checkout@v4

      - name: Build and push image
        uses: docker/build-push-action@v5
        with:
          push: true
          tags: ghcr.io/sbr0nch/sentrikat:staging

      - name: Deploy to staging server
        uses: appleboy/ssh-action@v1.0.3
        with:
          host: ${{ secrets.STAGING_HOST }}
          username: ${{ secrets.STAGING_USER }}
          key: ${{ secrets.STAGING_SSH_KEY }}
          script: |
            cd /opt/sentrikat
            docker-compose pull
            docker-compose up -d --force-recreate
            docker system prune -f

      - name: Health check
        run: |
          sleep 30
          curl -f https://staging.sentrikat.com/health || exit 1

      - name: Notify Slack
        uses: slackapi/slack-github-action@v1.25.0
        with:
          payload: |
            {
              "text": "✅ Deployed to staging: ${{ github.sha }}"
            }
        env:
          SLACK_WEBHOOK_URL: ${{ secrets.SLACK_WEBHOOK }}
```

### 3.3 Dependabot Configuration

```yaml
# .github/dependabot.yml - NUOVO
version: 2
updates:
  - package-ecosystem: "pip"
    directory: "/"
    schedule:
      interval: "weekly"
      day: "monday"
    open-pull-requests-limit: 5
    groups:
      security:
        applies-to: security-updates
      minor-and-patch:
        applies-to: version-updates
        update-types:
          - "minor"
          - "patch"
    reviewers:
      - "sbr0nch"
    labels:
      - "dependencies"
      - "automated"

  - package-ecosystem: "docker"
    directory: "/"
    schedule:
      interval: "weekly"
    labels:
      - "docker"
      - "automated"

  - package-ecosystem: "github-actions"
    directory: "/"
    schedule:
      interval: "monthly"
    labels:
      - "ci"
      - "automated"
```

### 3.4 Pre-commit Hooks

```yaml
# .pre-commit-config.yaml - NUOVO
repos:
  - repo: https://github.com/pre-commit/pre-commit-hooks
    rev: v4.5.0
    hooks:
      - id: trailing-whitespace
      - id: end-of-file-fixer
      - id: check-yaml
      - id: check-added-large-files
        args: ['--maxkb=500']
      - id: check-merge-conflict
      - id: detect-private-key

  - repo: https://github.com/psf/black
    rev: 24.1.0
    hooks:
      - id: black
        args: ['--line-length=120']

  - repo: https://github.com/PyCQA/flake8
    rev: 7.0.0
    hooks:
      - id: flake8
        args: ['--max-line-length=120']

  - repo: https://github.com/PyCQA/isort
    rev: 5.13.2
    hooks:
      - id: isort

  - repo: https://github.com/PyCQA/bandit
    rev: 1.7.7
    hooks:
      - id: bandit
        args: ['-r', 'app/', '-ll']
```

---

## 4. FASE 3: SECURITY (Q3 2026)

### 4.1 SAST (Static Application Security Testing)

```yaml
# .github/workflows/security.yml - NUOVO
name: Security Scan

on:
  push:
    branches: [main]
  pull_request:
    branches: [main]
  schedule:
    - cron: '0 0 * * 0'  # Weekly on Sunday

jobs:
  sast:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Run Bandit (Python SAST)
        run: |
          pip install bandit
          bandit -r app/ -f json -o bandit-report.json || true

      - name: Upload Bandit report
        uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: bandit-report.json

  dependency-scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Run Safety (dependency vulnerabilities)
        run: |
          pip install safety
          safety check -r requirements.txt --json > safety-report.json || true

      - name: Run pip-audit
        run: |
          pip install pip-audit
          pip-audit -r requirements.txt --format json > pip-audit-report.json || true

  container-scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Build image
        run: docker build -t sentrikat:scan .

      - name: Run Trivy vulnerability scanner
        uses: aquasecurity/trivy-action@master
        with:
          image-ref: 'sentrikat:scan'
          format: 'sarif'
          output: 'trivy-results.sarif'
          severity: 'CRITICAL,HIGH'

      - name: Upload Trivy scan results
        uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: 'trivy-results.sarif'

  secret-scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          fetch-depth: 0

      - name: TruffleHog OSS
        uses: trufflesecurity/trufflehog@main
        with:
          path: ./
          base: ${{ github.event.repository.default_branch }}
          head: HEAD
```

### 4.2 DAST (Dynamic Application Security Testing)

```yaml
# .github/workflows/dast.yml - NUOVO (per staging)
name: DAST Scan

on:
  workflow_dispatch:
  schedule:
    - cron: '0 3 * * 1'  # Weekly Monday 3 AM

jobs:
  zap-scan:
    runs-on: ubuntu-latest
    steps:
      - name: OWASP ZAP Baseline Scan
        uses: zaproxy/action-baseline@v0.11.0
        with:
          target: 'https://staging.sentrikat.com'
          rules_file_name: '.zap/rules.tsv'

      - name: Upload ZAP report
        uses: actions/upload-artifact@v4
        with:
          name: zap-report
          path: report_html.html
```

### 4.3 Software Bill of Materials (SBOM)

```yaml
# Aggiunta a release.yml
- name: Generate SBOM
  uses: anchore/sbom-action@v0
  with:
    image: ghcr.io/sbr0nch/sentrikat:${{ github.ref_name }}
    format: spdx-json
    output-file: sbom.spdx.json

- name: Upload SBOM to release
  uses: softprops/action-gh-release@v1
  with:
    files: sbom.spdx.json
```

---

## 5. FASE 4: SCALE (Q4 2026)

### 5.1 Production Deployment con Approval

```yaml
# .github/workflows/deploy-production.yml - NUOVO
name: Deploy to Production

on:
  release:
    types: [published]
  workflow_dispatch:
    inputs:
      version:
        description: 'Version to deploy'
        required: true

jobs:
  deploy-production:
    runs-on: ubuntu-latest
    environment: production  # Richiede approval

    steps:
      - uses: actions/checkout@v4

      - name: Verify staging deployment
        run: |
          # Controlla che questa versione sia stata testata in staging
          STAGING_VERSION=$(curl -s https://staging.sentrikat.com/api/version | jq -r '.version')
          if [ "$STAGING_VERSION" != "${{ github.event.release.tag_name }}" ]; then
            echo "Version mismatch: staging=$STAGING_VERSION, releasing=${{ github.event.release.tag_name }}"
            exit 1
          fi

      - name: Create deployment record
        run: |
          echo "Deploying ${{ github.event.release.tag_name }} to production"
          echo "Deployed by: ${{ github.actor }}"
          echo "Time: $(date -u)"

      - name: Deploy to production
        uses: appleboy/ssh-action@v1.0.3
        with:
          host: ${{ secrets.PROD_HOST }}
          username: ${{ secrets.PROD_USER }}
          key: ${{ secrets.PROD_SSH_KEY }}
          script: |
            cd /opt/sentrikat

            # Backup current state
            docker-compose exec -T db pg_dump -U postgres sentrikat > backup_$(date +%Y%m%d_%H%M%S).sql

            # Pull new version
            export VERSION=${{ github.event.release.tag_name }}
            docker-compose pull

            # Blue-green deployment
            docker-compose up -d --no-deps --scale sentrikat=2 sentrikat
            sleep 30
            docker-compose up -d --no-deps --scale sentrikat=1 sentrikat

            # Cleanup
            docker system prune -f

      - name: Health check
        run: |
          for i in {1..10}; do
            if curl -f https://sentrikat.com/health; then
              echo "Health check passed"
              exit 0
            fi
            sleep 10
          done
          echo "Health check failed"
          exit 1

      - name: Notify success
        if: success()
        uses: slackapi/slack-github-action@v1.25.0
        with:
          payload: |
            {
              "text": "🚀 Production deployed: ${{ github.event.release.tag_name }}"
            }
        env:
          SLACK_WEBHOOK_URL: ${{ secrets.SLACK_WEBHOOK }}

      - name: Notify failure
        if: failure()
        uses: slackapi/slack-github-action@v1.25.0
        with:
          payload: |
            {
              "text": "❌ Production deployment FAILED: ${{ github.event.release.tag_name }}"
            }
        env:
          SLACK_WEBHOOK_URL: ${{ secrets.SLACK_WEBHOOK }}
```

### 5.2 Kubernetes Helm Chart (Futuro)

```yaml
# helm/sentrikat/values.yaml - FUTURO
replicaCount: 3

image:
  repository: ghcr.io/sbr0nch/sentrikat
  tag: "1.0.0"
  pullPolicy: IfNotPresent

service:
  type: ClusterIP
  port: 5000

ingress:
  enabled: true
  className: "nginx"
  annotations:
    cert-manager.io/cluster-issuer: "letsencrypt-prod"
  hosts:
    - host: sentrikat.com
      paths:
        - path: /
          pathType: Prefix
  tls:
    - secretName: sentrikat-tls
      hosts:
        - sentrikat.com

resources:
  limits:
    cpu: 2000m
    memory: 4Gi
  requests:
    cpu: 500m
    memory: 1Gi

autoscaling:
  enabled: true
  minReplicas: 2
  maxReplicas: 10
  targetCPUUtilizationPercentage: 70

postgresql:
  enabled: true
  auth:
    database: sentrikat
  primary:
    persistence:
      size: 100Gi
```

---

## 6. PIPELINE COMPLETA (TARGET)

### 6.1 Visione Completa

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                        COMPLETE CI/CD PIPELINE (TARGET)                      │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                              │
│  ┌─────────┐  ┌─────────┐  ┌─────────┐  ┌─────────┐  ┌─────────┐           │
│  │ COMMIT  │─>│  LINT   │─>│  TEST   │─>│  SAST   │─>│  BUILD  │           │
│  │         │  │ flake8  │  │ pytest  │  │ bandit  │  │ docker  │           │
│  │         │  │ black   │  │ coverage│  │ trivy   │  │         │           │
│  └─────────┘  └─────────┘  └─────────┘  └─────────┘  └─────────┘           │
│       │            │            │            │            │                  │
│       │            │            │            │            │                  │
│       ▼            ▼            ▼            ▼            ▼                  │
│  [Feature]    [Quality]    [Quality]    [Security]   [Artifact]             │
│   Branch       Gate         Gate         Gate         Ready                 │
│                                                                              │
│                              │                                               │
│                              │ PR Merge to main                              │
│                              ▼                                               │
│  ┌─────────────────────────────────────────────────────────────────────┐    │
│  │                          STAGING                                     │    │
│  │  Auto-deploy → Smoke tests → DAST scan → Integration tests          │    │
│  └─────────────────────────────────────────────────────────────────────┘    │
│                              │                                               │
│                              │ Manual approval + Tag                         │
│                              ▼                                               │
│  ┌─────────────────────────────────────────────────────────────────────┐    │
│  │                         PRODUCTION                                   │    │
│  │  Blue-green → Health check → Smoke tests → Monitor → Rollback ready │    │
│  └─────────────────────────────────────────────────────────────────────┘    │
│                                                                              │
└─────────────────────────────────────────────────────────────────────────────┘
```

### 6.2 Gate Summary

| Gate | Strumenti | Threshold | Bloccante |
|------|-----------|-----------|-----------|
| Lint | flake8, black, isort | No errors | Sì |
| Unit Tests | pytest | 100% pass | Sì |
| Coverage | pytest-cov | ≥70% | Sì |
| SAST | Bandit, Safety | No HIGH | Sì |
| Container Scan | Trivy | No CRITICAL | Sì |
| Secret Scan | TruffleHog | No secrets | Sì |
| Staging Smoke | curl, pytest | All pass | Sì |
| DAST | OWASP ZAP | No HIGH | Warning |

---

## 7. MONITORING & OBSERVABILITY

### 7.1 Application Metrics (Prometheus)

```python
# app/metrics.py - NUOVO
from prometheus_client import Counter, Histogram, Gauge, generate_latest
from functools import wraps
import time

# Metriche
REQUEST_COUNT = Counter(
    'sentrikat_requests_total',
    'Total HTTP requests',
    ['method', 'endpoint', 'status']
)

REQUEST_LATENCY = Histogram(
    'sentrikat_request_duration_seconds',
    'Request latency',
    ['method', 'endpoint'],
    buckets=[.005, .01, .025, .05, .075, .1, .25, .5, .75, 1.0, 2.5, 5.0, 7.5, 10.0]
)

ACTIVE_AGENTS = Gauge(
    'sentrikat_active_agents',
    'Number of active agents',
    ['organization']
)

VULNERABILITY_COUNT = Gauge(
    'sentrikat_vulnerabilities_total',
    'Total vulnerabilities tracked',
    ['severity']
)

DB_CONNECTIONS = Gauge(
    'sentrikat_db_connections',
    'Database connection pool usage'
)

def track_request(f):
    @wraps(f)
    def wrapper(*args, **kwargs):
        start = time.time()
        try:
            response = f(*args, **kwargs)
            status = response.status_code
        except Exception as e:
            status = 500
            raise
        finally:
            REQUEST_COUNT.labels(
                method=request.method,
                endpoint=request.endpoint,
                status=status
            ).inc()
            REQUEST_LATENCY.labels(
                method=request.method,
                endpoint=request.endpoint
            ).observe(time.time() - start)
        return response
    return wrapper

# Endpoint per Prometheus
@app.route('/metrics')
def metrics():
    return generate_latest()
```

### 7.2 Logging Strutturato

```python
# app/logging_config.py - NUOVO
import logging
import json
from datetime import datetime

class JSONFormatter(logging.Formatter):
    def format(self, record):
        log_record = {
            'timestamp': datetime.utcnow().isoformat(),
            'level': record.levelname,
            'logger': record.name,
            'message': record.getMessage(),
            'module': record.module,
            'function': record.funcName,
            'line': record.lineno
        }

        if hasattr(record, 'user_id'):
            log_record['user_id'] = record.user_id
        if hasattr(record, 'organization_id'):
            log_record['organization_id'] = record.organization_id
        if hasattr(record, 'request_id'):
            log_record['request_id'] = record.request_id
        if record.exc_info:
            log_record['exception'] = self.formatException(record.exc_info)

        return json.dumps(log_record)

# Configurazione
logging.config.dictConfig({
    'version': 1,
    'formatters': {
        'json': {
            '()': JSONFormatter
        }
    },
    'handlers': {
        'console': {
            'class': 'logging.StreamHandler',
            'formatter': 'json',
            'stream': 'ext://sys.stdout'
        },
        'file': {
            'class': 'logging.handlers.RotatingFileHandler',
            'formatter': 'json',
            'filename': '/var/log/sentrikat/app.log',
            'maxBytes': 10485760,  # 10MB
            'backupCount': 5
        }
    },
    'root': {
        'level': 'INFO',
        'handlers': ['console', 'file']
    }
})
```

### 7.3 Grafana Dashboards

```json
// grafana/dashboards/sentrikat-overview.json - NUOVO
{
  "title": "SentriKat Overview",
  "panels": [
    {
      "title": "Request Rate",
      "type": "graph",
      "targets": [
        {
          "expr": "rate(sentrikat_requests_total[5m])",
          "legendFormat": "{{method}} {{endpoint}}"
        }
      ]
    },
    {
      "title": "Response Time (p99)",
      "type": "gauge",
      "targets": [
        {
          "expr": "histogram_quantile(0.99, rate(sentrikat_request_duration_seconds_bucket[5m]))"
        }
      ]
    },
    {
      "title": "Error Rate",
      "type": "stat",
      "targets": [
        {
          "expr": "rate(sentrikat_requests_total{status=~\"5..\"}[5m]) / rate(sentrikat_requests_total[5m]) * 100"
        }
      ]
    },
    {
      "title": "Active Agents",
      "type": "stat",
      "targets": [
        {
          "expr": "sum(sentrikat_active_agents)"
        }
      ]
    },
    {
      "title": "Vulnerabilities by Severity",
      "type": "piechart",
      "targets": [
        {
          "expr": "sentrikat_vulnerabilities_total",
          "legendFormat": "{{severity}}"
        }
      ]
    }
  ]
}
```

---

## 8. COSTI E RISORSE

### 8.1 Costi GitHub Actions

| Piano | Minuti inclusi | Costo extra | Stima mensile |
|-------|----------------|-------------|---------------|
| Free | 2,000 min/mese | $0.008/min | €0 (se < 2000) |
| Team | 3,000 min/mese | $0.008/min | ~€4/user/mese |
| Enterprise | 50,000 min/mese | $0.008/min | Custom |

**Stima utilizzo SentriKat:**
- CI per PR: ~5 min × 20 PR/mese = 100 min
- Staging deploy: ~3 min × 20/mese = 60 min
- Security scans: ~10 min × 4/mese = 40 min
- Release: ~5 min × 4/mese = 20 min
- **Totale: ~220 min/mese** (ben dentro il free tier)

### 8.2 Strumenti Aggiuntivi

| Strumento | Costo | Note |
|-----------|-------|------|
| Codecov | Free (open source) | Coverage reporting |
| Snyk | Free (100 tests/mese) | Dependency scanning |
| Grafana Cloud | Free (10k metrics) | Monitoring |
| Slack | Free tier | Notifications |

---

## 9. CHECKLIST IMPLEMENTAZIONE

### Fase 2 (Q2 2026)
- [ ] Configurare pytest-cov
- [ ] Integrare Codecov
- [ ] Creare deploy-staging.yml
- [ ] Configurare Dependabot
- [ ] Implementare pre-commit hooks
- [ ] Setup Slack notifications

### Fase 3 (Q3 2026)
- [ ] Aggiungere Bandit alla CI
- [ ] Configurare Trivy container scan
- [ ] Implementare TruffleHog
- [ ] Setup OWASP ZAP per staging
- [ ] Generare SBOM nelle release

### Fase 4 (Q4 2026)
- [ ] Creare deploy-production.yml con approval
- [ ] Implementare blue-green deployment
- [ ] Setup Prometheus metrics
- [ ] Configurare Grafana dashboards
- [ ] Preparare Helm chart (se K8s)

---

## 10. RISORSE E RIFERIMENTI

- [GitHub Actions Documentation](https://docs.github.com/en/actions)
- [Docker Build Best Practices](https://docs.docker.com/develop/develop-images/dockerfile_best-practices/)
- [OWASP DevSecOps Guidelines](https://owasp.org/www-project-devsecops-guideline/)
- [12 Factor App](https://12factor.net/)
- [Prometheus Best Practices](https://prometheus.io/docs/practices/)
- [Grafana Dashboards](https://grafana.com/grafana/dashboards/)

---

*Questo documento viene aggiornato ad ogni milestone DevOps completata.*
