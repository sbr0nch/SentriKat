<h1 align="center">
  <br>
  SentriKat
  <br>
</h1>

<h4 align="center">Enterprise Vulnerability Management Platform</h4>

<p align="center">
  <img src="https://img.shields.io/badge/version-1.0.2-blue.svg" alt="Version"/>
  <img src="https://img.shields.io/badge/python-3.11+-green.svg" alt="Python"/>
  <img src="https://img.shields.io/badge/docker-ready-blue.svg" alt="Docker"/>
  <img src="https://img.shields.io/badge/license-Commercial-red.svg" alt="License"/>
</p>

<p align="center">
  <a href="#what-sentrikat-does">What It Does</a> •
  <a href="#architecture">Architecture</a> •
  <a href="#core-pipeline">Core Pipeline</a> •
  <a href="#quick-start">Quick Start</a> •
  <a href="#agents">Agents</a> •
  <a href="#api-reference">API</a> •
  <a href="#editions">Editions</a>
</p>

---

## What SentriKat Does

SentriKat is a **self-hosted vulnerability management platform** that discovers your software inventory, matches it against known exploited vulnerabilities, and helps you prioritize remediation before attackers exploit the gaps.

**The core problem it solves:** Most organizations have hundreds or thousands of software products installed across their infrastructure. When a vulnerability is actively exploited in the wild (listed in CISA's Known Exploited Vulnerabilities catalog), security teams need to know *immediately* which of their systems are affected. SentriKat automates this entire workflow.

**What makes it different from Tenable/Qualys/Rapid7:**
- **CISA KEV-native** — built around actively exploited vulnerabilities, not 200,000+ theoretical CVEs
- **Vendor backport detection** — automatically detects when Linux distros have patched a CVE via backport, eliminating false positives that plague other scanners
- **Self-hosted, air-gap capable** — runs entirely on your infrastructure, no data leaves your network
- **Lightweight agents** — transparent bash/PowerShell scripts (not opaque binaries), auditable by your security team
- **10x cheaper** — EUR 2,499/year vs $25,000-$100,000+ for enterprise alternatives

### How It Works (End-to-End Flow)

```
 INVENTORY COLLECTION          SERVER PROCESSING             USER INTERFACE
 ─────────────────────         ───────────────────           ──────────────

 ┌─────────────────┐           ┌─────────────────┐          ┌──────────────┐
 │  Windows Agent   │──┐       │  3-Phase Filter  │          │  Dashboard   │
 │  (PowerShell)    │  │       │  ┌─────────────┐ │          │  ┌────────┐  │
 ├─────────────────┤  │       │  │ Structural  │ │          │  │Priority│  │
 │  Linux Agent     │──┼──────►│  │ CVE Guard   │ │          │  │ Matrix │  │
 │  (Bash)          │  │       │  │ Noise Filter│ │          │  └────────┘  │
 ├─────────────────┤  │       │  └─────────────┘ │          │  ┌────────┐  │
 │  macOS Agent     │──┤       ├─────────────────┤          │  │ Vuln   │  │
 │  (Bash)          │  │       │  CPE Assignment  │          │  │ List   │  │
 ├─────────────────┤  │       │  ┌─────────────┐ │          │  └────────┘  │
 │  CSV / API       │──┘       │  │ Tier 1-3    │ │          │  ┌────────┐  │
 │  Import          │          │  │ + NVD API   │ │          │  │Endpoint│  │
 └─────────────────┘           │  └─────────────┘ │          │  │ Mgmt   │  │
                               ├─────────────────┤          │  └────────┘  │
 ┌─────────────────┐           │  Vuln Matching   │          │  ┌────────┐  │
 │  CISA KEV Feed   │──┐       │  ┌─────────────┐ │──────────►│ Alerts │  │
 │  (1,484+ CVEs)   │  │       │  │ CPE Match   │ │          │  │& Email │  │
 ├─────────────────┤  │       │  │ Keyword     │ │          │  └────────┘  │
 │  NVD Database    │──┼──────►│  │ Backport    │ │          │  ┌────────┐  │
 │  (800K+ products)│  │       │  └─────────────┘ │          │  │Reports │  │
 ├─────────────────┤  │       ├─────────────────┤          │  │& PDF   │  │
 │  Vendor Advisories──┘       │  CVSS/EPSS       │          │  └────────┘  │
 │  OSV/RedHat/MSRC│           │  Enrichment      │          └──────────────┘
 │  Debian          │           └─────────────────┘
 └─────────────────┘
```

---

## Architecture

### Technology Stack

| Layer | Technology | Purpose |
|-------|-----------|---------|
| **Web Framework** | Python 3.11, Flask 3.x | REST API + server-rendered UI |
| **Database** | PostgreSQL 15 (prod) / SQLite (dev) | 30 SQLAlchemy models, org-isolated data |
| **Background Jobs** | APScheduler | CISA sync, maintenance, alerts, vendor advisories |
| **Web Server** | nginx + Gunicorn (gthread) | Reverse proxy, SSL termination, multi-worker |
| **Frontend** | Jinja2, Bootstrap 5, Chart.js | Server-rendered templates, interactive dashboards |
| **Security** | Fernet encryption, bcrypt, CSRF, CSP | OWASP-compliant security stack |
| **Containerization** | Docker, Docker Compose | 3-service deployment (app + db + nginx) |
| **Authentication** | Local + LDAP/AD + SAML 2.0 + TOTP 2FA | Enterprise SSO support |
| **Licensing** | RSA-4096 signed, hardware-locked | Online/offline activation via portal |

### Codebase Structure

```
SentriKat/
├── app/                          # Core application (47 Python modules)
│   ├── __init__.py               # Flask app factory + schema migrations
│   ├── models.py                 # 30 SQLAlchemy models (~2,900 lines)
│   ├── routes.py                 # Main web UI + API routes (~4,400 lines)
│   ├── agent_api.py              # Agent inventory endpoints + 3-phase filtering
│   ├── filters.py                # Vulnerability matching engine (CPE + keyword)
│   ├── cpe_mapping.py            # 224 regex CPE patterns + auto-mapping
│   ├── cpe_dictionary.py         # Local NVD CPE dictionary (50K+ entries)
│   ├── cpe_mappings.py           # User-defined CPE mappings + NVD fallback
│   ├── cisa_sync.py              # CISA KEV sync + NVD CVSS enrichment
│   ├── vendor_advisories.py      # OSV.dev, Red Hat, MSRC, Debian feeds
│   ├── cve_known_products.py     # CVE history lookup for filtering guard
│   ├── scheduler.py              # 15+ background jobs (APScheduler)
│   ├── maintenance.py            # Stale asset cleanup, auto-acknowledgment
│   ├── auth.py                   # Login/session/2FA management
│   ├── ldap_manager.py           # LDAP authentication provider
│   ├── ldap_sync.py              # Automated LDAP group sync engine
│   ├── saml_manager.py           # SAML 2.0 SSO processing
│   ├── licensing.py              # RSA-4096 license validation + enforcement
│   ├── email_alerts.py           # SMTP alert management
│   ├── issue_trackers.py         # Jira, GitHub, GitLab, YouTrack, Webhook
│   ├── integration_connectors.py # PDQ, SCCM, Lansweeper connectors
│   ├── encryption.py             # Fernet encryption for sensitive config
│   ├── version_utils.py          # dpkg/RPM/APK version comparison
│   ├── nvd_api.py                # NVD CVSS data retrieval
│   ├── nvd_cpe_api.py            # NVD CPE search + caching
│   ├── nvd_rate_limiter.py       # Token bucket rate limiter for NVD
│   ├── epss_sync.py              # EPSS exploit probability scores
│   ├── kb_sync.py                # Knowledge base sync (proven mappings)
│   ├── cache_utils.py            # In-memory caching layer
│   ├── reports.py                # PDF report generation (ReportLab)
│   ├── reports_api.py            # Scheduled report API
│   ├── settings_api.py           # System configuration API
│   ├── cpe_api.py                # CPE lookup & management API
│   ├── integrations_api.py       # Import queue + integration API
│   ├── shared_views_api.py       # Shareable dashboard links
│   ├── ldap_api.py               # LDAP user management API
│   ├── ldap_group_api.py         # LDAP group-to-role mapping
│   ├── saml_api.py               # SAML SSO endpoints
│   ├── api_docs.py               # OpenAPI/Swagger spec generation
│   ├── setup.py                  # First-run setup wizard
│   ├── logging_config.py         # JSON structured logging
│   ├── performance_middleware.py  # Request performance monitoring
│   └── error_utils.py            # Consistent error handling
│
├── agents/                       # Deployment agent scripts
│   ├── sentrikat-agent-linux.sh  # Linux agent (dpkg/rpm/apk/pacman/snap/flatpak)
│   ├── sentrikat-agent-macos.sh  # macOS agent (pkgutil/homebrew)
│   └── sentrikat-agent-windows.ps1  # Windows agent (registry/WMI/AppxPackage)
│
├── templates/                    # 9 Jinja2 HTML templates
│   ├── base.html                 # Base layout (header, nav, footer, dark mode)
│   ├── dashboard.html            # Main dashboard with charts
│   ├── admin.html                # Admin panel
│   ├── login.html                # Login form
│   ├── setup.html                # First-run setup wizard
│   ├── agent_activity.html       # Agent status dashboard
│   ├── containers.html           # Container scanning dashboard
│   └── scheduled_reports.html    # Report scheduling UI
│
├── static/                       # Frontend assets
│   ├── js/                       # Client-side JavaScript
│   └── vendor/                   # Bootstrap 5, Chart.js, jQuery
│
├── tests/                        # Test suite (214 tests)
│   ├── test_api_endpoints.py     # API endpoint tests
│   ├── test_auth.py              # Authentication tests
│   ├── test_licensing.py         # License validation tests
│   ├── test_multi_tenant.py      # Organization isolation tests
│   ├── test_rate_limiting.py     # Rate limit enforcement tests
│   ├── test_version_utils.py     # Version comparison tests
│   └── test_vulnerability_filtering.py  # Vulnerability matching tests
│
├── docs/                         # Documentation
│   ├── API.md                    # API endpoint reference
│   └── business/                 # Business planning docs (16 documents)
│
├── scripts/                      # Deployment utilities
│   ├── backup_database.sh        # PostgreSQL backup
│   ├── update.sh                 # Production update (Linux)
│   ├── update.ps1                # Production update (Windows)
│   └── download_vendor_assets.sh # Offline CDN fallback
│
├── tools/                        # Admin utilities
│   ├── generate_license.py       # RSA license key generation
│   ├── diagnose_license.py       # License troubleshooting
│   └── reset_database.py         # Database reset tool
│
├── nginx/                        # nginx configuration templates
├── docker-compose.yml            # 3-service deployment
├── Dockerfile                    # Multi-stage Python 3.11-slim build
├── gunicorn.conf.py              # Worker config (auto-scaling, thread pool)
├── config.py                     # Flask configuration
├── requirements.txt              # 27 Python dependencies
└── .env.example                  # Environment template (164 lines, commented)
```

### Database Schema (30 Models)

```
AUTHENTICATION                 PRODUCTS & INVENTORY           VULNERABILITIES
──────────────                 ────────────────────           ───────────────
User                           Product                        Vulnerability
Organization                   ProductInstallation            VulnerabilityMatch
UserOrganization               ProductExclusion               VulnerabilitySnapshot
SystemSettings                 ProductVersionHistory          VendorFixOverride
                               ServiceCatalog
AGENTS                         UserCpeMapping                 INTEGRATIONS
──────                         CpeDictionaryEntry             ────────────
Asset                                                         Integration
AgentApiKey                    REPORTING & ALERTS             ImportQueue
AgentLicense                   ──────────────────             AgentRegistration
AgentUsageRecord               AlertLog
AgentEvent                     ScheduledReport                LDAP/SAML
InventoryJob                   StaleAssetNotification         ─────────
                               SharedView                     LDAPGroupMapping
CONTAINERS                                                    LDAPSyncLog
──────────                                                    LDAPAuditLog
ContainerImage
ContainerVulnerability
```

### Background Jobs (APScheduler)

| Job | Schedule | Purpose |
|-----|----------|---------|
| CISA KEV Sync | Daily 02:00 UTC | Fetch exploited vulnerabilities catalog |
| Vendor Advisory Sync | Daily 03:00 UTC | OSV.dev, Red Hat, MSRC, Debian backport data |
| NVD CPE Dictionary Sync | Weekly (Sun 04:00) | Bulk CPE dictionary update (50K+ entries) |
| CVE Known Products Refresh | Every 12 hours | Refresh CVE history guard for filtering |
| EPSS Score Sync | Daily | Exploit Prediction Scoring System update |
| Critical Email Digest | Daily 09:00 UTC | Alert digest for unacknowledged critical CVEs |
| Maintenance | Daily 04:00 UTC | 7-step cleanup (stale assets, orphans, auto-resolve) |
| Stuck Job Recovery | Every 10 minutes | Reset stuck inventory jobs to pending |
| Asset Type Auto-Detection | Daily 06:00 | Infer server/workstation from OS version |
| Unmapped CPE Retry | Weekly (Mon 05:00) | Retry CPE mapping for unmapped products |
| License Heartbeat | Every 12 hours | License validation + telemetry |
| Vulnerability Snapshots | Daily 02:00 UTC | Historical vulnerability state for trending |

---

## Core Pipeline

This section describes the complete data flow from agent installation to dashboard vulnerability display. This is the most critical path in SentriKat.

### Stage 1: Agent Inventory Collection

Agents are lightweight scripts (bash/PowerShell) deployed on endpoints. They collect installed software and report to the SentriKat server.

**What agents collect:**
- Hostname, OS name, OS version
- All installed packages with vendor, product name, version, install path
- Container images (Docker/Podman) if present

**Supported package managers:**
| Platform | Method |
|----------|--------|
| Windows | Registry (32/64-bit Uninstall keys), Get-Package, Get-WindowsFeature, Get-AppxPackage |
| Linux (Debian/Ubuntu) | `dpkg -l` |
| Linux (RHEL/CentOS/Fedora) | `rpm -qa` |
| Linux (Alpine) | `apk info` |
| Linux (Arch) | `pacman -Q` |
| Linux (Snap) | `snap list` |
| Linux (Flatpak) | `flatpak list` |
| macOS | `pkgutil`, `brew list`, system extensions |

**Agent security:**
- API key authentication (SHA256 hashed on server)
- Optional IP whitelisting per key
- TLS required in production
- Input validation with strict size limits
- Rate limiting: 60 inventory reports/minute, 120 heartbeats/minute

**Agent endpoint:** `POST /api/agent/inventory`

### Stage 2: Server-Side Filtering (3-Phase CVE-History-Guarded)

A typical Linux server reports 2,000-5,000 packages. Most are noise (documentation, debug symbols, library sonames, locale data). SentriKat filters these down to security-relevant products only.

**Why this matters:** Without filtering, a customer's dashboard shows 10,000+ products. Users panic ("everything is vulnerable!") and the system becomes unusable.

**Phase 1 — Structural Derivatives (always safe to skip):**
Packages ending in `-doc`, `-dbg`, `-locale`, `-dev`, `-headers`, `-fonts`, etc. These are non-runtime derivatives of base packages and never have their own CVEs.

**Phase 2 — CVE History Guard (safety net):**
Before applying any noise pattern, check if the package has EVER had a CVE in NVD/CISA history (672+ known products cached). If yes, the package is **always kept** regardless of any noise patterns. This prevents false negatives — packages like `openssl`, `xz-utils`, `bzip2`, `tcpdump` are always protected.

**Phase 3 — Noise Patterns (only for packages with zero CVE history):**
Pattern and exact-match rules for Windows/macOS/Linux noise. Only applied to packages that passed the CVE history guard:
- Windows: language packs, KB metadata entries, ADK components, telemetry agents, store apps
- Linux: `lib*N` runtime library sonames, `golang-*`/`node-*`/`ruby-*` source packages, firmware blobs, X11/GNOME plumbing, systemd ancillary units
- macOS: `com.apple.*` system components
- Cross-platform: VC++ redistributables, .NET SDK/targeting packs, font metadata

**Implementation:** `app/agent_api.py` → `_should_skip_software()`

### Stage 3: Asset Creation & Inventory Processing

After filtering, products are linked to an asset (endpoint):

1. **Asset lookup/creation:** Find or create the asset by `(organization_id, hostname)` with `IntegrityError` race condition protection for concurrent agent reports
2. **Product deduplication:** Match by `(organization_id, vendor, product_name)` — avoid duplicating products across endpoints
3. **Installation tracking:** Create `ProductInstallation` records linking products to assets with versions
4. **Version history:** Track version changes over time in `ProductVersionHistory`

**Async processing:** Inventory payloads > 750 items are queued as `InventoryJob` and processed by background workers. Payloads ≤ 750 are processed synchronously (faster for typical agent chunks of 500).

**Stuck job recovery:** Jobs in `processing` state for >30 minutes are automatically reset to `pending` by the stuck job recovery scheduler.

### Stage 4: Asset Type Auto-Detection

Assets default to `server` type. A daily job infers the correct type from OS information:

| OS String | Detected Type |
|-----------|---------------|
| Windows 10, Windows 11, Windows 8 | workstation |
| Windows Server * | server |
| macOS, Darwin, Mac OS | workstation |
| Ubuntu Desktop | workstation |
| 12-char hex hostname | container |

**Implementation:** `app/scheduler.py` → `auto_detect_asset_type_job()`

### Stage 5: CPE Auto-Assignment (4-Tier Mapping)

Products need CPE (Common Platform Enumeration) identifiers for accurate vulnerability matching. SentriKat automatically maps product names to CPE using a 4-tier system:

| Tier | Method | Speed | Coverage |
|------|--------|-------|----------|
| **Tier 1** | 224 curated regex patterns | Instant | Common software (browsers, Office, Java, databases, etc.) |
| **Tier 2** | Curated dictionary + user-defined mappings | Instant | Custom/organization-specific software |
| **Tier 3** | Local CPE dictionary (50K+ entries from NVD bulk CSV) | Instant | Long-tail products with known CVEs |
| **Tier 4** | NVD API live search (rate-limited) | Slow (~1s/query) | Everything else |

**Product name normalization:** Before matching, product names are normalized:
- Pipe separators stripped: `"Dell | Command Update"` → `"command update"`
- Parenthetical suffixes removed: `"Firefox (x64 en-US)"` → `"firefox"`
- Version numbers stripped: `"7-Zip 25.01"` → `"7-zip"`
- Architecture suffixes removed: `"Git x64"` → `"git"`

**Vendor-specific CPE mappings:** Dell, HP/HPE, Adobe, Microsoft, Mozilla, and 200+ other vendors have explicit regex patterns.

**Weekly retry:** Products that failed CPE mapping are retried every Monday at 05:00 (after Sunday's NVD dictionary sync adds new entries).

**Implementation:** `app/cpe_mapping.py` → `apply_cpe_to_product()`, `batch_apply_cpe_mappings()`

### Stage 6: Vulnerability Matching

Products with CPE are matched against vulnerabilities from CISA KEV and NVD:

**Matching modes** (configurable per product):
| Mode | Behavior |
|------|----------|
| `auto` (default) | CPE match first; keyword match only if no CPE |
| `cpe` | CPE match only |
| `keyword` | Vendor+product name keyword match only |
| `both` | CPE and keyword (union of results) |

**CPE Matching (high confidence):**
1. Compare product's CPE vendor+product against vulnerability's cached CPE entries
2. If version ranges exist, verify product version is within the affected range
3. Uses dpkg/RPM/APK-aware version comparison for Linux distro packages

**Keyword Matching (medium confidence):**
1. Word-boundary vendor matching (prevents "sun" matching "samsung")
2. Core product name extraction + bidirectional containment check
3. Additional keyword matching from product's keyword field

**Vendor Backport Detection (false positive elimination):**
After matching, SentriKat checks vendor advisory feeds to detect backported fixes:

| Feed | Coverage |
|------|----------|
| OSV.dev | Ubuntu, Debian, Alpine, Python, Node.js, Go, Rust ecosystems |
| Red Hat | RHEL, CentOS, Rocky, Alma |
| MSRC | Windows, Office, Exchange, SQL Server |
| Debian Security Tracker | Debian stable/testing/unstable |

**3-tier resolution confidence:**
- **AFFECTED (Red):** No vendor fix found
- **LIKELY RESOLVED (Amber):** Vendor fix found, generic version comparison
- **RESOLVED (Green):** Vendor fix confirmed via distro-native version comparison (dpkg/RPM/APK)

**Implementation:** `app/filters.py` → `check_match()`, `app/vendor_advisories.py`

### Stage 7: Dashboard & Alerting

Matched vulnerabilities appear on the dashboard with:
- **Priority matrix:** CRITICAL / HIGH / MEDIUM / LOW cards (clickable filters)
- **EPSS scores:** Exploit Prediction Scoring System probability
- **Ransomware flag:** CVEs known to be used by ransomware groups
- **CISA due dates:** Remediation deadlines from BOD 22-01
- **Remediation tracking:** Acknowledge, snooze, or create Jira/GitHub/GitLab issues

**Alert channels:**
- Email digests (daily critical CVE summary)
- Webhooks (Slack, Teams, Discord, custom)
- Syslog/CEF forwarding (Splunk, ELK, ArcSight, QRadar)
- Escalation (re-alert if not acknowledged within N days)

**Export & Reporting:**
- CSV/Excel export of vulnerability list (with UTF-8 BOM for Excel)
- Executive summary one-pager PDF (risk score, KPIs, top priorities)
- CISA BOD 22-01 compliance report (JSON, CSV, PDF)
- EU NIS2 compliance report — Article 21(2)(d)(e)(g) mapping (JSON, CSV, PDF)
- Scheduled reports (daily/weekly/monthly email delivery)

---

## Quick Start

### Prerequisites

- **Docker** 20.10+ with Docker Compose
- **Memory**: 2GB minimum, 4GB recommended
- **Disk**: 500MB for application + database

### Installation

```bash
# 1. Clone the repository
git clone https://github.com/sbr0nch/SentriKat.git
cd SentriKat

# 2. Create environment file
cp .env.example .env

# 3. Generate security keys (REQUIRED)
python3 -c "import secrets; print(secrets.token_hex(32))"
python3 -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"
python3 -c "import uuid; print(f'SK-INST-{uuid.uuid4().hex[:32].upper()}')"

# 4. Edit .env and set:
#    SECRET_KEY, ENCRYPTION_KEY, SENTRIKAT_INSTALLATION_ID (from step 3)
#    DB_PASSWORD (strong password)
#    DATABASE_URL (must contain same password as DB_PASSWORD)
#    SERVER_NAME (your domain)
#    SENTRIKAT_URL (full URL with https://)

# 5. Start services
docker-compose up -d

# 6. Access the application
# The setup wizard will guide you through initial configuration
```

### First-Time Setup

1. Navigate to your SentriKat URL
2. Complete the setup wizard:
   - Create admin account
   - Set organization name
   - Configure email settings (optional)
   - Seed service catalog (~47 pre-configured services)
   - Run initial CISA KEV sync (~1,400+ CVEs)
3. Deploy agents or add products manually

### SSL/TLS Configuration

```bash
# Place certificates in nginx/ssl/ (fullchain.pem + privkey.pem)
# Update .env:
NGINX_TEMPLATE=nginx-ssl.conf.template
ENABLE_SSL=true
SSL_CERT_FILE=fullchain.pem
SSL_KEY_FILE=privkey.pem
SESSION_COOKIE_SECURE=true
FORCE_HTTPS=true

docker-compose restart nginx
```

### Corporate Proxy / Custom CA Certificates

SentriKat supports corporate proxies and custom CA certificates:

```bash
# Proxy configuration
HTTP_PROXY=http://proxy.example.com:8080
HTTPS_PROXY=http://proxy.example.com:8080
NO_PROXY=localhost,127.0.0.1,db

# Custom CA certificates: place .crt files in certs/ directory
# They are automatically installed during container startup
```

---

## Agents

### Windows Agent

```powershell
# Download from your SentriKat instance
Invoke-WebRequest -Uri "https://your-sentrikat/api/agent/download/windows" -OutFile agent.ps1

# Install as scheduled task
.\agent.ps1 -Install -Url "https://your-sentrikat" -Key "your-api-key"
```

Collects: Registry (Uninstall keys, 32/64-bit), Get-Package, Get-WindowsFeature, Get-AppxPackage

### Linux Agent

```bash
curl -o sentrikat-agent.sh https://your-sentrikat/api/agent/download/linux
chmod +x sentrikat-agent.sh
sudo ./sentrikat-agent.sh --install --url "https://your-sentrikat" --key "your-api-key"
```

Collects: dpkg, rpm, apk, pacman, snap, flatpak packages

### macOS Agent

```bash
curl -o sentrikat-agent.sh https://your-sentrikat/api/agent/download/macos
chmod +x sentrikat-agent.sh
./sentrikat-agent.sh --install --url "https://your-sentrikat" --key "your-api-key"
```

Collects: pkgutil, Homebrew, system extensions

### Container Scanning

Agents automatically detect Docker/Podman and scan container images:
- No additional configuration needed
- Uses Trivy (Apache-2.0, auto-installed) for scanning
- Detects OS vulnerabilities + application dependencies (Python, Node.js, Java, Go, Rust)
- Results appear on the Containers dashboard alongside endpoint vulnerabilities
- Container scanning is included at no extra cost in Professional edition

### Agent API Keys

1. Go to **Administration > Agent API Keys**
2. Click **Create API Key**
3. Set organization scope and permissions
4. Optionally restrict to specific IP ranges
5. Copy the generated key (shown only once)

---

## API Reference

SentriKat provides 100+ REST API endpoints. Full interactive documentation is available at `/api/docs` on your SentriKat instance.

### Authentication

```bash
# Session-based (web applications)
POST /api/auth/login
Content-Type: application/json
{"username": "admin", "password": "secret"}

# API Key (agents and integrations)
X-Agent-Key: your-api-key
```

### Key Endpoints

```bash
# Health & Status
GET  /api/health                         # Health check
GET  /api/version                        # Version info
GET  /api/sync/status                    # Sync status

# Vulnerabilities
GET  /api/vulnerabilities                # List vulnerabilities (paginated)
GET  /api/vulnerabilities/stats          # Dashboard statistics
POST /api/matches/{id}/acknowledge       # Acknowledge a CVE match
POST /api/matches/acknowledge-by-cve/{cve_id}  # Bulk acknowledge by CVE

# Products
GET  /api/products                       # List products
POST /api/products                       # Create product
PUT  /api/products/{id}                  # Update product
POST /api/products/rematch               # Re-run vulnerability matching

# Agent Inventory
POST /api/agent/inventory                # Report software inventory
POST /api/agent/heartbeat                # Agent keepalive
POST /api/agent/container-scan           # Report container scan results

# CPE Management
GET  /api/cpe/search?q=firefox           # Search NVD CPE database
POST /api/cpe/link                       # Manually assign CPE to product
GET  /api/cpe/stats                      # CPE coverage statistics

# Import Queue
GET  /api/import/queue                   # View pending imports
POST /api/import/queue/{id}/approve      # Approve queued product

# Sync
POST /api/sync                           # Trigger CISA KEV sync
POST /api/vendor-advisories/sync         # Trigger vendor advisory sync

# Settings
GET  /api/settings/{key}                 # Read setting
POST /api/settings/{key}                 # Write setting

# Reports & Compliance
GET  /api/reports/export/csv             # Export vulnerabilities as CSV (Excel)
GET  /api/reports/executive-summary      # Executive summary (risk score, KPIs)
GET  /api/reports/compliance/bod-22-01   # CISA BOD 22-01 compliance report
GET  /api/reports/compliance/nis2        # EU NIS2 compliance report
GET  /api/reports/scheduled              # List scheduled reports
POST /api/reports/download               # Generate PDF report

# SIEM Integration
GET  /api/settings/syslog                # Get syslog forwarding config
POST /api/settings/syslog                # Update syslog forwarding config
POST /api/settings/syslog/test           # Send test syslog event
```

### Example: Agent Inventory Report

```bash
curl -X POST https://your-sentrikat/api/agent/inventory \
  -H "X-Agent-Key: your-api-key" \
  -H "Content-Type: application/json" \
  -d '{
    "hostname": "workstation-001",
    "os": "Ubuntu 22.04 LTS",
    "products": [
      {"vendor": "Mozilla", "product": "Firefox", "version": "115.0"},
      {"vendor": "Apache", "product": "HTTP Server", "version": "2.4.57"},
      {"vendor": "OpenSSL", "product": "OpenSSL", "version": "3.0.2"}
    ]
  }'
```

---

## Network Requirements

SentriKat requires outbound HTTPS access to external vulnerability data sources:

| Domain | Purpose | Schedule |
|--------|---------|----------|
| `www.cisa.gov` | CISA KEV vulnerability catalog | Daily (02:00 UTC) |
| `services.nvd.nist.gov` | NVD CPE/CVSS data enrichment | During product search + weekly sync |
| `api.osv.dev` | OSV vendor backport detection | Daily (03:00 UTC) |
| `access.redhat.com` | Red Hat/CentOS/Rocky advisories | Daily (03:00 UTC) |
| `api.msrc.microsoft.com` | Microsoft Patch Tuesday data | Daily (03:00 UTC) |
| `security-tracker.debian.org` | Debian security tracker | Daily (03:00 UTC) |
| `portal.sentrikat.com` | License validation heartbeat | Every 12 hours |
| `api.first.org` | EPSS scores (optional) | Daily |
| `api.github.com` | Update check (optional) | On admin dashboard load |

**Air-gapped deployments:** Only `www.cisa.gov` and `services.nvd.nist.gov` are critical. All other feeds are optional and degrade gracefully.

**Optional:** Get a free NVD API key from [nvd.nist.gov](https://nvd.nist.gov/developers/request-an-api-key) for 10x faster product search.

---

## Editions

### Demo Edition (Free)

| Limit | Value |
|-------|-------|
| Users | 1 |
| Organizations | 1 |
| Products | 50 |
| Push Agents | 5 |

Includes: CISA KEV sync, NVD search, vulnerability matching, basic dashboard, CSV import, push agents (limited), container scanning

### Professional Edition (EUR 2,499/year)

| Limit | Value |
|-------|-------|
| Users | Unlimited |
| Organizations | Unlimited |
| Products | Unlimited |
| Push Agents | 10 (base) + agent packs |

**Agent Packs:**
| Pack | Price/Year |
|------|-----------|
| +25 agents | EUR 499 |
| +50 agents | EUR 899 |
| +100 agents | EUR 1,499 |
| Unlimited agents | EUR 2,199 |

**Additional features:** LDAP/AD, SAML SSO, email alerts, webhooks (Slack/Teams/Discord), syslog/CEF forwarding (SIEM), multi-organization, backup/restore, white-label branding, full API access, issue tracker integrations (Jira, GitHub, GitLab, YouTrack), scheduled reports, CSV/Excel export, executive summary PDF, NIS2 + BOD 22-01 compliance reports, audit log export, container scanning

### License Activation

```bash
# Via environment variable
SENTRIKAT_LICENSE=your-license-key

# Or via Admin UI: Administration > License > Activate License
```

Licenses are hardware-locked to your Installation ID (`SENTRIKAT_INSTALLATION_ID`). Supports both online activation (automatic via portal) and offline activation (manual key exchange).

---

## Security

### Built-in Protections

| Protection | Implementation |
|-----------|----------------|
| SQL Injection | SQLAlchemy ORM (parameterized queries) |
| XSS | Jinja2 autoescaping + Content Security Policy |
| CSRF | Flask-WTF CSRF tokens on all forms |
| Clickjacking | X-Frame-Options, CSP frame-ancestors |
| Session Security | HttpOnly, SameSite=Lax, Secure flag, 4-hour timeout |
| Password Hashing | Werkzeug/bcrypt |
| Sensitive Data | Fernet encryption (LDAP passwords, SMTP creds, webhook tokens, API keys) |
| Rate Limiting | 1000/day, 200/hour per IP; 5/min on login; account lockout after 5 failures |
| Security Headers | HSTS, X-Content-Type-Options, Referrer-Policy via Flask-Talisman |
| Agent Auth | SHA256 hashed API keys, optional IP whitelisting |
| License Validation | RSA-4096 signature verification, hardware locking |

### Production Checklist

- [ ] Set strong `SECRET_KEY` and `ENCRYPTION_KEY` (refuse defaults)
- [ ] Use unique `DB_PASSWORD`
- [ ] Enable HTTPS with valid certificates
- [ ] Set `FLASK_ENV=production`
- [ ] Set `SESSION_COOKIE_SECURE=true`
- [ ] Configure firewall (only expose 80/443)
- [ ] Set up log rotation
- [ ] Configure backup schedule
- [ ] Enable NVD API key for faster product search
- [ ] Configure email for alert notifications

---

## Integrations

### Inventory Sources

| Source | Method |
|--------|--------|
| Push Agents | Windows (PowerShell), Linux (Bash), macOS (Bash) |
| PDQ Deploy | REST API connector |
| SCCM | REST API connector |
| Microsoft Intune | REST API connector |
| Lansweeper | REST API connector |
| CSV Import | Bulk upload with review queue |
| REST API | Custom integrations via agent API |

### Issue Trackers

Multiple trackers can be enabled simultaneously:
- **Jira** — Create issues with custom fields and priority mapping
- **GitHub Issues** — Auto-create issues with CVE labels
- **GitLab Issues** — Auto-create issues with vulnerability labels
- **YouTrack** — JetBrains issue tracker integration
- **Webhook** — Generic webhook for custom workflows

### Alert Channels

- **Email** — HTML digests via SMTP, configurable time windows
- **Slack** — Webhook integration for channel notifications
- **Microsoft Teams** — Webhook integration
- **Discord** — Webhook integration
- **Custom Webhooks** — JSON payload to any endpoint
- **Syslog/CEF** — Forward events to SIEM (Splunk, ELK, ArcSight, QRadar) via UDP/TCP

### Compliance Frameworks

- **CISA BOD 22-01** — Remediation tracking with due dates, compliance percentage, overdue reporting
- **EU NIS2 (Directive 2022/2555)** — Article 21 mapping: vulnerability handling (2e), supply chain visibility (2d), cyber hygiene (2g)
- **Executive Summary** — Board-ready one-pager with risk score, KPIs, severity breakdown, top priorities

### Authentication Providers

- **Local** — Built-in username/password with bcrypt hashing
- **LDAP/Active Directory** — Group-to-organization mapping, automated sync
- **SAML 2.0** — Okta, Azure AD, ADFS, Google Workspace
- **TOTP 2FA** — Time-based One-Time Password (Google Authenticator, Authy)

---

## Troubleshooting

### Common Issues

**Container won't start:**
```bash
docker-compose logs sentrikat    # Check application logs
docker-compose config            # Verify environment
```

**Database connection failed:**
```bash
docker-compose logs db           # Check PostgreSQL logs
# Verify DATABASE_URL password matches DB_PASSWORD
```

**SSL certificate errors (corporate CA):**
```bash
# Place .crt files in certs/ directory
# Container automatically installs them on startup
# Or set VERIFY_SSL=false (not recommended for production)
```

**requests SSL error with corporate proxies:**
SentriKat uses `requests==2.31.0` specifically because 2.32.x has eager SSL context preloading that rejects some corporate CA certificates (Fortinet, Zscaler, etc.).

### Health Check

```bash
curl -k https://localhost/api/health
# Expected: {"status": "healthy", "checks": {"database": "ok"}}
```

---

## Development

### Local Development Setup

```bash
# Install dependencies
pip install -r requirements.txt

# Set environment
export FLASK_ENV=development
export SECRET_KEY=dev-secret-key
export DATABASE_URL=sqlite:///dev.db

# Run
python run.py
```

### Running Tests

```bash
# Full suite (214 tests)
python -m pytest tests/ -v

# Specific test file
python -m pytest tests/test_vulnerability_filtering.py -v

# With coverage
python -m pytest tests/ --cov=app --cov-report=html
```

### Key Environment Variables

| Variable | Required | Description |
|----------|----------|-------------|
| `SECRET_KEY` | Yes | Flask session signing key |
| `ENCRYPTION_KEY` | Yes | Fernet key for sensitive data encryption |
| `DATABASE_URL` | Yes | PostgreSQL connection URL |
| `DB_PASSWORD` | Yes | PostgreSQL password (must match DATABASE_URL) |
| `SENTRIKAT_URL` | Yes | Public URL (for email links) |
| `SERVER_NAME` | Yes | Hostname for nginx |
| `SENTRIKAT_INSTALLATION_ID` | Yes | Hardware lock for licensing |
| `NVD_API_KEY` | No | NVD API key (10x faster search) |
| `FLASK_ENV` | No | `production` or `development` |
| `HTTP_PROXY` / `HTTPS_PROXY` | No | Corporate proxy settings |
| `VERIFY_SSL` | No | SSL verification (`true`/`false`) |
| `SYNC_HOUR` / `SYNC_MINUTE` | No | CISA sync schedule (default: 02:00 UTC) |
| `GUNICORN_WORKERS` | No | Worker count (default: min(CPU*2+1, 8)) |
| `GUNICORN_THREADS` | No | Threads per worker (default: 4) |

---

## Support

- **Documentation**: [docs.sentrikat.com](https://docs.sentrikat.com)
- **Email**: support@sentrikat.com
- **Issues**: GitHub Issues

---

## License

SentriKat is **commercial software**. Copyright 2024-2026 Denis Sota. All Rights Reserved.

- **Demo Edition**: Free for evaluation and small deployments (5 agents, 1 user)
- **Professional Edition**: Commercial license required

Purchase licenses at [sentrikat.com/pricing](https://sentrikat.com/pricing). See [LICENSE.md](LICENSE.md) for full terms.

---

<p align="center">
  <sub>Built for security teams who need clarity, not noise.</sub>
  <br>
  <sub>&copy; 2024-2026 Denis Sota. All Rights Reserved.</sub>
</p>
