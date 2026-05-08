# SentriKat API Documentation

> **Version**: 1.0
> **Base URL**: `/api`
> **Authentication**: Session-based (Cookie) or API Key (for agent endpoints)

## Table of Contents

1. [Authentication](#authentication)
2. [Vulnerabilities](#vulnerabilities)
3. [Products](#products)
4. [Assets](#assets)
5. [Organizations](#organizations)
6. [Users](#users)
7. [Scheduled Reports](#scheduled-reports)
8. [Settings](#settings)
9. [Sync & Status](#sync--status)
10. [Agents & Integrations](#agents--integrations)
11. [CPE Management](#cpe-management)
12. [SAML SSO](#saml-sso)
13. [Vendor Advisory Sync](#vendor-advisory-sync)
14. [Licensing](#licensing)
15. [Health Checks](#health-checks)
16. [Agent API Keys (Multi-Org)](#agent-api-keys-multi-org)
17. [Dependency Scanning (Code Dependencies)](#dependency-scanning-code-dependencies)
18. [GDPR & Privacy](#gdpr--privacy)
19. [Prometheus Metrics](#prometheus-metrics)
20. [SBOM Export](#sbom-export) — *Sprint 4 + Sprint 5*
21. [Compliance Reports](#compliance-reports) — *Sprint 5*
22. [Remediation Assignments & SLA](#remediation-assignments--sla) — *Sprint 4*
23. [Risk Exceptions](#risk-exceptions) — *Sprint 4*
24. [Product Aliases](#product-aliases) — *Sprint 4*
25. [Vulnerability Trending](#vulnerability-trending) — *Sprint 5*
26. [Patch Tuesday Digest](#patch-tuesday-digest) — *Sprint 5*

---

## Authentication

All API endpoints require authentication unless specified otherwise.

### Login

```http
POST /api/auth/login
Content-Type: application/json

{
  "username": "admin",
  "password": "password",
  "totp_code": "123456"  // Optional, required if 2FA enabled
}
```

**Response**:
```json
{
  "success": true,
  "user": {
    "id": 1,
    "username": "admin",
    "role": "super_admin",
    "organization_id": 1
  }
}
```

### Logout

```http
POST /api/auth/logout
```

### Check Auth Status

```http
GET /api/auth/status
```

**Response**:
```json
{
  "authenticated": true,
  "user_id": 1,
  "username": "admin",
  "is_admin": true,
  "organization_id": 1
}
```

### Change Password

```http
POST /api/auth/change-password
Content-Type: application/json

{
  "current_password": "old_password",
  "new_password": "new_secure_password"
}
```

### 2FA Setup

```http
POST /api/auth/2fa/setup
```

**Response**:
```json
{
  "success": true,
  "secret": "BASE32_SECRET",
  "qr_uri": "otpauth://totp/..."
}
```

### 2FA Verify

```http
POST /api/auth/2fa/verify
Content-Type: application/json

{
  "totp_code": "123456"
}
```

---

## Vulnerabilities

### Get Vulnerability Statistics

```http
GET /api/vulnerabilities/stats
```

**Response**:
```json
{
  "total_vulnerabilities": 1234,
  "total_matches": 45,
  "unacknowledged": 12,
  "ransomware_related": 3,
  "products_tracked": 50,
  "priority_breakdown": {
    "critical": 5,
    "high": 10,
    "medium": 15,
    "low": 15
  }
}
```

### Get Vulnerability Trends

```http
GET /api/vulnerabilities/trends?days=30
```

**Response**:
```json
{
  "days": 30,
  "snapshot_count": 30,
  "trends": {
    "dates": ["2024-01-01", "2024-01-02"],
    "total_matches": [42, 45],
    "unacknowledged": [10, 12],
    "critical": [3, 4],
    "high": [8, 9]
  }
}
```

### Get Vulnerabilities (Grouped by CVE)

```http
GET /api/vulnerabilities/grouped?page=1&per_page=25&priority=critical&acknowledged=false
```

**Query Parameters**:
| Parameter | Type | Description |
|-----------|------|-------------|
| page | int | Page number (default: 1) |
| per_page | int | Items per page (max: 100) |
| priority | string | Filter by priority (critical, high, medium, low) |
| acknowledged | bool | Filter by acknowledged status |
| ransomware_only | bool | Only show ransomware CVEs |
| search | string | Search CVE ID or description |

### Acknowledge Vulnerability Match

```http
POST /api/matches/{match_id}/acknowledge
```

### Unacknowledge Vulnerability Match

```http
POST /api/matches/{match_id}/unacknowledge
```

### Snooze Vulnerability Match

```http
POST /api/matches/{match_id}/snooze
Content-Type: application/json

{
  "hours": 168  // Snooze for 1 week
}
```

### Bulk Acknowledge by CVE

```http
POST /api/matches/acknowledge-by-cve/{cve_id}
```

---

## Products

### List Products

```http
GET /api/products?search=apache&active=true
```

**Query Parameters**:
| Parameter | Type | Description |
|-----------|------|-------------|
| search | string | Search vendor/product name |
| active | bool | Filter by active status |
| has_vulns | bool | Only products with vulnerabilities |

### Create Product

```http
POST /api/products
Content-Type: application/json

{
  "vendor": "Apache",
  "product_name": "Tomcat",
  "version": "10.1.18",
  "criticality": "high",
  "active": true,
  "cpe_vendor": "apache",
  "cpe_product": "tomcat"
}
```

### Update Product

```http
PUT /api/products/{product_id}
Content-Type: application/json

{
  "version": "10.1.19",
  "criticality": "critical"
}
```

### Delete Product

```http
DELETE /api/products/{product_id}
```

### Re-match Vulnerabilities

```http
POST /api/products/rematch
```

---

## Assets

### List Assets

```http
GET /api/assets?asset_type=server&active=true
```

### Get Asset Details

```http
GET /api/assets/{asset_id}
```

### Update Asset

```http
PUT /api/assets/{asset_id}
Content-Type: application/json

{
  "hostname": "server01.example.com",
  "ip_address": "10.0.0.1",
  "asset_type": "server",
  "active": true
}
```

### Delete Asset

```http
DELETE /api/assets/{asset_id}
```

### Get Asset Groups

```http
GET /api/assets/groups
```

---

## Organizations

### List Organizations

```http
GET /api/organizations
```

### Create Organization

```http
POST /api/organizations
Content-Type: application/json

{
  "name": "acme",
  "display_name": "ACME Corporation",
  "active": true
}
```

### Update Organization

```http
PUT /api/organizations/{org_id}
Content-Type: application/json

{
  "display_name": "ACME Corp Updated",
  "alert_on_critical": true,
  "alert_on_high": true,
  "notification_emails": ["admin@acme.com"]
}
```

### Delete Organization

```http
DELETE /api/organizations/{org_id}
```

### Test Organization SMTP

```http
POST /api/organizations/{org_id}/smtp/test
```

---

## Users

### List Users

```http
GET /api/users
```

### Create User

```http
POST /api/users
Content-Type: application/json

{
  "username": "newuser",
  "email": "user@example.com",
  "password": "secure_password",
  "role": "user",
  "organization_id": 1,
  "auth_type": "local"
}
```

**Roles**: `super_admin`, `org_admin`, `manager`, `user`

### Update User

```http
PUT /api/users/{user_id}
Content-Type: application/json

{
  "email": "updated@example.com",
  "role": "manager"
}
```

### Delete User

```http
DELETE /api/users/{user_id}
```

### Toggle User Active Status

```http
POST /api/users/{user_id}/toggle-active
```

### Unlock User Account

```http
POST /api/users/{user_id}/unlock
```

### Reset User 2FA

```http
POST /api/users/{user_id}/reset-2fa
```

### Force Password Change

```http
POST /api/users/{user_id}/force-password-change
```

---

## Scheduled Reports

### List Scheduled Reports

```http
GET /api/reports/scheduled
```

### Create Scheduled Report

```http
POST /api/reports/scheduled
Content-Type: application/json

{
  "name": "Weekly Vulnerability Report",
  "frequency": "weekly",
  "day_of_week": 1,
  "time_of_day": "09:00",
  "report_type": "summary",
  "recipients": "admin@example.com,security@example.com",
  "send_to_admins": true,
  "include_acknowledged": true,
  "include_pending": true,
  "enabled": true
}
```

**Frequency Options**: `daily`, `weekly`, `monthly`
**Report Types**: `summary`, `full`, `critical_only`

### Update Scheduled Report

```http
PUT /api/reports/scheduled/{report_id}
Content-Type: application/json

{
  "time_of_day": "08:00",
  "enabled": false
}
```

### Delete Scheduled Report

```http
DELETE /api/reports/scheduled/{report_id}
```

### Toggle Report Enabled

```http
POST /api/reports/scheduled/{report_id}/toggle
```

### Send Report Now

```http
POST /api/reports/scheduled/{report_id}/send-now
```

### Download Report

```http
POST /api/reports/download
Content-Type: application/json

{
  "report_type": "monthly",
  "year": 2024,
  "month": 1
}
```

---

## Settings

### Get/Save LDAP Settings

```http
GET /api/settings/ldap
POST /api/settings/ldap
```

### Test LDAP Connection

```http
POST /api/settings/ldap/test
```

### Get/Save SMTP Settings

```http
GET /api/settings/smtp
POST /api/settings/smtp
```

### Test SMTP Connection

```http
POST /api/settings/smtp/test
```

### Get/Save Sync Settings

```http
GET /api/settings/sync
POST /api/settings/sync
```

### Get NVD API Status

```http
GET /api/settings/sync/nvd-status
```

### Get/Save General Settings

```http
GET /api/settings/general
POST /api/settings/general
```

### Get/Save Security Settings

```http
GET /api/settings/security
POST /api/settings/security
```

### Get/Save Branding Settings

```http
GET /api/settings/branding
POST /api/settings/branding
```

### Upload Logo

```http
POST /api/settings/branding/logo
Content-Type: multipart/form-data
```

---

## Sync & Status

### Trigger Manual Sync

```http
POST /api/sync
```

### Get Sync Status

```http
GET /api/sync/status
```

### Get Sync History

```http
GET /api/sync/history
```

### Health Check

```http
GET /api/health
```

**Response**:
```json
{
  "status": "healthy",
  "database": "connected",
  "timestamp": "2024-01-15T10:30:00Z"
}
```

### Version Info

```http
GET /api/version
```

---

## Agents & Integrations

### Agent Inventory Report

```http
POST /api/agent/inventory
X-API-Key: agent_api_key_here
Content-Type: application/json

{
  "hostname": "server01",
  "ip_address": "10.0.0.1",
  "os": "Windows Server 2022",
  "software": [
    {"vendor": "Apache", "product": "Tomcat", "version": "10.1.18"},
    {"vendor": "Microsoft", "product": "SQL Server", "version": "2019"}
  ]
}
```

### Agent Heartbeat

```http
POST /api/agent/heartbeat
X-API-Key: agent_api_key_here
Content-Type: application/json

{
  "hostname": "server01",
  "uptime_seconds": 86400
}
```

### List Agent API Keys

```http
GET /api/agent-keys
```

### Create Agent API Key

```http
POST /api/agent-keys
Content-Type: application/json

{
  "name": "Production Agent Key",
  "organization_id": 1,
  "auto_approve": false
}
```

### Revoke Agent API Key

```http
DELETE /api/agent-keys/{key_id}
```

### List Integrations

```http
GET /api/integrations
```

### Create Integration

```http
POST /api/integrations
Content-Type: application/json

{
  "name": "SCCM Integration",
  "type": "sccm",
  "organization_id": 1,
  "enabled": true
}
```

### Import from External System

```http
POST /api/import
X-API-Key: integration_api_key_here
Content-Type: application/json

{
  "source": "sccm",
  "software": [
    {"vendor": "Adobe", "product": "Reader", "version": "2024.001"}
  ]
}
```

---

## CPE Management

### Search CPE Database

```http
GET /api/cpe/search?vendor=apache&product=tomcat
```

### Get CPE Versions

```http
GET /api/cpe/versions?vendor=apache&product=tomcat
```

### Link CPE to Product

```http
POST /api/cpe/link-product/{product_id}
Content-Type: application/json

{
  "cpe_vendor": "apache",
  "cpe_product": "tomcat"
}
```

### Get CPE Suggestions

```http
GET /api/cpe/suggest?vendor=Apache&product=Tomcat
```

### Bulk CPE Link

```http
POST /api/cpe/bulk-link
Content-Type: application/json

{
  "mappings": [
    {"product_id": 1, "cpe_vendor": "apache", "cpe_product": "tomcat"},
    {"product_id": 2, "cpe_vendor": "microsoft", "cpe_product": "sql_server"}
  ]
}
```

---

## SAML SSO

### Get SAML Configuration

```http
GET /api/settings/saml
```

### Save SAML Configuration

```http
POST /api/settings/saml
Content-Type: application/json

{
  "enabled": true,
  "idp_entity_id": "https://idp.example.com",
  "idp_sso_url": "https://idp.example.com/sso",
  "idp_x509_cert": "-----BEGIN CERTIFICATE-----...",
  "sp_entity_id": "https://sentrikat.example.com",
  "attribute_mapping": {
    "email": "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress"
  }
}
```

### Test SAML Configuration

```http
POST /api/settings/saml/test
```

### Get SP Metadata

```http
GET /api/saml/metadata
```

Returns XML metadata for IdP configuration.

### Check SAML Status

```http
GET /api/saml/status
```

---

## Licensing

### Get License Information

```http
GET /api/license
```

**Response**:
```json
{
  "edition": "professional",
  "is_valid": true,
  "expires": "2025-12-31",
  "limits": {
    "max_agents": 500,
    "max_organizations": 10
  },
  "features": {
    "ldap": true,
    "saml": true,
    "scheduled_reports": true
  }
}
```

### Get Installation ID

```http
GET /api/license/installation-id
```

### Activate License (Offline)

```http
POST /api/license
Content-Type: application/json

{
  "license_key": "LICENSE_KEY_STRING"
}
```

**Response** (200):
```json
{
  "success": true,
  "message": "License activated: Professional edition for Acme Corp",
  "license": { ... }
}
```

### Activate License (Online)

Exchange an activation code for a hardware-locked license key via the SentriKat license portal.
Requires HTTPS connectivity to `portal.sentrikat.com`. Rate limited to 5 attempts per hour.

```http
POST /api/license/activate-online
Content-Type: application/json

{
  "activation_code": "SK-XXXX-XXXX-XXXX-XXXX"
}
```

**Response** (200):
```json
{
  "success": true,
  "message": "License activated: Professional edition for Acme Corp",
  "license": { ... }
}
```

**Error responses**:
| Code | Description |
|------|-------------|
| 400 | Invalid/expired/already-used activation code |
| 403 | Super admin access required |
| 429 | Too many attempts (max 5/hour) |
| 502 | License server returned an unexpected response |
| 503 | Cannot reach license server |
| 504 | License server timeout |

**Security**: SSL is always enforced for license server connections regardless of the `VERIFY_SSL` setting.
Activation codes must match `^[A-Za-z0-9\-]+$` (8-128 characters).

### Remove License

```http
DELETE /api/license
```

Reverts to Community edition.

---

## Error Responses

All API endpoints return consistent error responses:

```json
{
  "error": "Error message describing the issue"
}
```

**HTTP Status Codes**:
| Code | Description |
|------|-------------|
| 200 | Success |
| 201 | Created |
| 400 | Bad Request |
| 401 | Unauthorized |
| 403 | Forbidden |
| 404 | Not Found |
| 429 | Rate Limited |
| 500 | Server Error |

---

## Rate Limiting

The API implements rate limiting to prevent abuse:

- **Default**: 1000 requests/day, 200 requests/hour
- **Agent Endpoints**: 60-120 requests/minute
- **Auth Endpoints**: 10 requests/minute (to prevent brute force)

Rate limit headers are included in responses:
```
X-RateLimit-Limit: 1000
X-RateLimit-Remaining: 999
X-RateLimit-Reset: 1704067200
```

---

## Pagination

List endpoints support pagination:

```http
GET /api/products?page=1&per_page=25
```

**Response**:
```json
{
  "items": [...],
  "total": 150,
  "page": 1,
  "per_page": 25,
  "pages": 6
}
```

---

## Vendor Advisory Sync

SentriKat automatically detects in-place vendor patches (backport fixes) by syncing with vendor advisory feeds. This eliminates false positives where NVD CPE data still marks a version as affected even though the vendor has backported the fix.

### How It Works

1. SentriKat daily syncs advisory data from OSV.dev, Red Hat, Microsoft MSRC, and Debian
2. When an advisory confirms a fix exists for a CVE+product+version already in your inventory
3. The system compares the installed version against the fixed version using **distro-native algorithms** (dpkg for Debian/Ubuntu, RPM for RHEL/CentOS, APK for Alpine)
4. Based on comparison quality, a **confidence tier** is assigned

### Three-Tier Confidence System

| Tier | Badge | Behavior | When |
|------|-------|----------|------|
| **AFFECTED** | Red | Full alerts, dashboard visibility | No vendor fix data found |
| **LIKELY RESOLVED** | Amber "Verify Fix" | Stays in alerts with verification notice | Vendor fix detected but used generic comparison or no `distro_package_version` from agent |
| **RESOLVED** | Green "Verified Fix" | Auto-resolved, hidden from alerts | Distro-native comparison (dpkg/RPM/APK) confirmed with agent-reported package version |

**High confidence** (green) means:
- The agent reported the distro-native package version (e.g., `2.4.52-1ubuntu4.6`)
- The correct distro algorithm was used (dpkg EVR for Ubuntu, RPM EVR for RHEL, etc.)
- The installed version is confirmed >= the vendor's fixed version

**Medium confidence** (amber) means:
- A vendor fix exists, but verification was done with generic comparison, OR
- The agent did not report a `distro_package_version`, OR
- The fix is a vendor "not affected" statement without version proof

Medium-confidence items **remain visible** in email alerts and webhook notifications with a "Verify Fix" indicator until the user manually confirms.

### GET `/api/vendor-fix-overrides`

List all vendor fix override records (both manual and automatic).

**Query Parameters**:
- `cve_id` (optional): Filter by CVE ID
- `status` (optional): Filter by status (`approved`, `pending`, `rejected`)

**Response**:
```json
[
  {
    "id": 1,
    "cve_id": "CVE-2024-38475",
    "vendor": "Apache",
    "product": "HTTP Server",
    "fixed_version": "2.4.52",
    "fix_type": "backport_patch",
    "confidence": "high",
    "confidence_reason": "dpkg comparison: 2.4.52-1ubuntu4.6 >= 2.4.52-1ubuntu4.3",
    "vendor_advisory_url": "https://osv.dev/vulnerability/USN-6885-1",
    "status": "approved",
    "created_at": "2025-01-15T03:00:00Z"
  }
]
```

### POST `/api/vendor-fix-overrides/sync`

Manually trigger a vendor advisory sync. Requires admin role.

**Response**:
```json
{
  "overrides_created": 12,
  "matches_resolved": 8,
  "feeds_checked": 4,
  "errors": []
}
```

### GET `/api/vendor-advisories/check/<cve_id>`

Check vendor advisory feeds for patches related to a specific CVE.

**Response**:
```json
{
  "cve_id": "CVE-2024-38475",
  "advisories": [
    {
      "source": "osv.dev",
      "package": "apache2",
      "ecosystem": "Ubuntu:22.04",
      "fixed_versions": ["2.4.52-1ubuntu4.10"],
      "url": "https://osv.dev/vulnerability/USN-6885-1"
    }
  ],
  "count": 1
}
```

---

## Health Checks

Background health monitoring system that checks all system components and reports problems.

### Get Health Check Status

```http
GET /api/admin/health-checks
Authorization: Session (Super Admin)
```

**Response**:
```json
{
  "enabled": true,
  "notify_email": "admin@example.com",
  "checks": [
    {
      "name": "database",
      "label": "Database Connectivity",
      "description": "Verifies the database is reachable and responsive",
      "category": "system",
      "enabled": true,
      "last_result": {
        "status": "ok",
        "message": "Database healthy (12ms)",
        "value": "12ms",
        "checked_at": "2025-01-15T10:30:00"
      }
    }
  ]
}
```

Available checks: `database`, `disk_space`, `worker_thread`, `stuck_jobs`, `cve_sync_freshness`, `agent_health`, `cpe_coverage`, `license_status`, `smtp_connectivity`, `pending_import_queue`.

### Update Health Check Settings

```http
PUT /api/admin/health-checks/settings
Content-Type: application/json
Authorization: Session (Super Admin)

{
  "enabled": true,
  "notify_email": "ops@example.com",
  "checks": {
    "database": true,
    "smtp_connectivity": false
  }
}
```

### Run Health Checks Now

```http
POST /api/admin/health-checks/run
Authorization: Session (Super Admin)
```

---

## Agent API Keys (Multi-Org)

### Create Agent API Key

```http
POST /api/agent-keys
Content-Type: application/json
Authorization: Session (Org Admin or Super Admin)

{
  "name": "Production Servers",
  "organization_id": 1,
  "additional_organization_ids": [2, 3],
  "auto_approve": true,
  "max_assets": 0,
  "expires_days": 365
}
```

The `additional_organization_ids` field is optional. When provided, software reported by agents using this key will be assigned to all specified organizations independently.

**Response**:
```json
{
  "id": 5,
  "name": "Production Servers",
  "organization_id": 1,
  "organization_name": "Main Org",
  "additional_organizations": [
    {"id": 2, "name": "Dev Team"},
    {"id": 3, "name": "QA Team"}
  ],
  "all_organization_ids": [1, 2, 3],
  "api_key": "sk_agent_xxxx...",
  "warning": "Save this key now. It will not be shown again."
}
```

### Agent Command & Control

Agents poll for pending commands (scan requests, updates) via the commands endpoint.

```http
GET /api/agent/commands?agent_id=xxx&hostname=yyy&platform=windows&agent_version=1.4.0
Authorization: X-Agent-Key
```

Returns pending commands: `scan_now`, `update_available`, `update_config`.

### Agent Script Download (Auto-Update)

Agents download the latest script when an update is available.

```http
GET /api/agent/download/{platform}
Authorization: X-Agent-Key
```

Platforms: `linux`, `windows`, `macos`. Returns the script file with `X-Agent-Version` header.
The server automatically injects the current `APP_VERSION` (from the `VERSION` file) into the downloaded script's `AGENT_VERSION` variable. This means agent versions track the SentriKat release version automatically — bumping the `VERSION` file for a release is sufficient to trigger agent updates.

### Agent Update Push

Push software updates to agents remotely.

```http
POST /api/admin/assets/{id}/trigger-update
Authorization: Session (Admin)
```

```http
POST /api/admin/assets/trigger-update-all
Authorization: Session (Admin)
```

### Agent Version Summary

```http
GET /api/admin/agents/version-summary
Authorization: Session (Admin)
```

Returns total agents, up-to-date count, outdated count, pending updates, version breakdown by platform.

---

### VulnerabilityMatch Confidence Fields

The `VulnerabilityMatch` object now includes vendor fix confidence information:

```json
{
  "id": 42,
  "acknowledged": false,
  "resolution_reason": "vendor_fix",
  "vendor_fix_confidence": "medium",
  "match_confidence": "high"
}
```

- `vendor_fix_confidence`: `"high"` (verified, auto-resolved) or `"medium"` (needs verification, stays active)
- `resolution_reason`: `"vendor_fix"` when a vendor advisory was matched
- `acknowledged`: `false` for medium confidence (stays in alerts), `true` for high confidence

---

## Dependency Scanning (Code Dependencies)

SentriKat scans lockfiles from your codebase against [OSV.dev](https://osv.dev) (Google's open-source vulnerability database) for precise, ecosystem-native vulnerability matching — no CPE guesswork.

### Supported Lockfiles

| Ecosystem | Lockfile(s) |
|-----------|------------|
| **Node.js** | `package-lock.json`, `yarn.lock`, `pnpm-lock.yaml` |
| **Python** | `Pipfile.lock`, `poetry.lock` |
| **Rust** | `Cargo.lock` |
| **Go** | `go.sum`, `go.mod` |
| **Ruby** | `Gemfile.lock` |
| **PHP** | `composer.lock` |
| **.NET** | `packages.lock.json` |

### Submit Dependency Scan

Submits lockfile contents for vulnerability scanning. The server parses dependencies, queries OSV.dev, and returns results.

```http
POST /api/agent/dependency-scan
X-Agent-Key: your-api-key
Content-Type: application/json

{
  "hostname": "my-server",
  "agent_id": "optional-unique-id",
  "project_name": "my-web-app",
  "lockfiles": [
    {
      "filename": "package-lock.json",
      "project_path": "/home/user/myproject",
      "content": "{ ... raw lockfile content ... }"
    }
  ]
}
```

**Fields:**

| Field | Required | Description |
|-------|----------|-------------|
| `hostname` | Yes* | Server hostname or project identifier |
| `agent_id` | Yes* | Unique agent/scanner ID |
| `project_name` | No | Human-readable project name (used for auto-created assets) |
| `lockfiles` | Yes | Array of lockfile objects |
| `lockfiles[].filename` | Yes | Must be one of the supported lockfile names (see above) |
| `lockfiles[].content` | Yes | Raw lockfile content as string (max 10 MB per file) |
| `lockfiles[].project_path` | No | Path to the lockfile on disk |

*At least one of `hostname` or `agent_id` is required.

**Limits:**

| Limit | Value |
|-------|-------|
| Max lockfiles per request | 50 |
| Max lockfile size | 10 MB per file |
| Max total payload | 50 MB |
| Max dependencies per lockfile | 10,000 |
| Rate limit | 30 requests/minute per API key |

**API Key Requirements:**

The API key must have `scan_dependencies` capability enabled. Enable this in **Administration > Agent API Keys > Edit Key > Dependency Scanning**.

**Response** (200):
```json
{
  "status": "success",
  "scan_id": 42,
  "summary": {
    "lockfiles_parsed": 1,
    "total_dependencies": 245,
    "direct_dependencies": 32,
    "transitive_dependencies": 213,
    "vulnerable_packages": 3,
    "total_vulnerabilities": 5,
    "severity": {
      "critical": 1,
      "high": 2,
      "medium": 2,
      "low": 0
    }
  },
  "vulnerable": [
    {
      "name": "express",
      "version": "4.17.1",
      "ecosystem": "npm",
      "is_direct": true,
      "purl": "pkg:npm/express@4.17.1",
      "vulnerabilities": [
        {
          "id": "GHSA-rv95-896h-c2vc",
          "cve_id": "CVE-2024-29041",
          "severity": "MEDIUM",
          "cvss_score": 6.1,
          "summary": "Express.js Open Redirect vulnerability",
          "fixed_versions": ["4.19.2"],
          "primary_url": "https://osv.dev/vulnerability/GHSA-rv95-896h-c2vc"
        }
      ]
    }
  ]
}
```

**Error Responses:**

| Code | Reason |
|------|--------|
| 400 | Missing required fields, invalid hostname format, or bad payload |
| 403 | API key does not have `scan_dependencies` enabled |
| 413 | Payload exceeds 50 MB |
| 429 | Rate limit exceeded (30/min) or asset creation limit reached |

### List Dependency Scans

```http
GET /api/dependency-scans
Authorization: Session (login required)
```

Returns the 100 most recent completed dependency scans for the user's organizations.

**Response:**
```json
{
  "scans": [
    {
      "id": 42,
      "asset_id": 10,
      "scan_status": "completed",
      "lockfiles_submitted": 2,
      "lockfiles_parsed": 2,
      "total_dependencies": 500,
      "vulnerable_count": 5,
      "total_vulnerabilities": 8,
      "critical_count": 1,
      "high_count": 3,
      "medium_count": 2,
      "low_count": 2,
      "created_at": "2026-02-24T10:00:00Z"
    }
  ],
  "stats": {
    "total_scans": 25,
    "total_vulnerabilities": 45,
    "total_critical": 3
  }
}
```

### Get Dependency Scan Details

```http
GET /api/dependency-scans/{scan_id}
Authorization: Session (login required)
```

Returns detailed results for a specific scan, including all vulnerability findings.

### Using the Lightweight Scanner (CI/CD)

Install and run the standalone scanner — no full agent needed:

```bash
# Install
pip install sentrikat-scan

# Configure
export SENTRIKAT_SERVER=https://your-sentrikat-instance
export SENTRIKAT_API_KEY=sk_your_key_here

# Scan (exits non-zero if vulnerabilities found above threshold)
sentrikat-scan --fail-on high

# CI/CD examples
sentrikat-scan --json            # Machine-readable output
sentrikat-scan --verbose         # Detailed output
sentrikat-scan --test            # Test connectivity only
```

The scanner is a single Python file with zero dependencies (Python 3.7+). Download it directly if pip is not available:

```bash
curl -O https://your-sentrikat-server/downloads/sentrikat-scan.py
chmod +x sentrikat-scan.py
./sentrikat-scan.py --fail-on high
```

---

## GDPR & Privacy

### Export Personal Data (GDPR Article 15 — Right of Access)

```http
GET /api/gdpr/export
Authorization: Session (any authenticated user)
Rate Limit: 5/hour
```

Returns a JSON file containing all personal data for the current user: profile, organization memberships, and API keys created.

**Response** (200 — `Content-Disposition: attachment`):
```json
{
  "export_date": "2026-03-28T12:00:00",
  "gdpr_article": "Art. 15 — Right of Access",
  "user": {
    "id": 12,
    "username": "mario.rossi@acme.com",
    "email": "mario.rossi@acme.com",
    "full_name": "Mario Rossi",
    "role": "org_admin",
    "auth_type": "local",
    "is_active": true,
    "created_at": "2026-01-15T10:30:00",
    "last_login": "2026-03-28T09:00:00",
    "totp_enabled": true
  },
  "organizations": [
    {"id": 1, "name": "Acme Corp", "role": "org_admin"}
  ],
  "api_keys": [
    {"id": 5, "name": "prod-agent-key", "active": true, "created_at": "2026-02-01T..."}
  ]
}
```

### Delete Personal Data (GDPR Article 17 — Right to Erasure)

```http
POST /api/gdpr/delete
Authorization: Session (any authenticated user)
Rate Limit: 3/day
```

Anonymizes the user's account and deactivates it. Vulnerability data is retained in anonymized form per GDPR Art. 17(3)(d) (public security exception).

**Response** (200):
```json
{
  "success": true,
  "message": "Your account has been anonymized and deactivated..."
}
```

**Error** (409 — last super_admin):
```json
{
  "error": "Cannot delete the only super_admin account. Promote another user first."
}
```

---

## Prometheus Metrics

### Get Metrics

```http
GET /metrics
Authorization: Bearer <SENTRIKAT_METRICS_KEY> (optional) or localhost access
```

Returns Prometheus text format metrics.

**Key metrics:**

| Metric | Type | Description |
|--------|------|-------------|
| `sentrikat_organizations_active` | Gauge | Active organizations |
| `sentrikat_users_active` | Gauge | Active users |
| `sentrikat_products_active` | Gauge | Monitored products |
| `sentrikat_agents_online` | Gauge | Agents checked in within 14 days |
| `sentrikat_agents_total` | Gauge | Total registered agents |
| `sentrikat_vulnerabilities_total` | Gauge | Vulnerabilities in database |
| `sentrikat_vulnerability_matches_total` | Gauge | Total vulnerability matches |
| `sentrikat_vulnerability_matches_by_severity` | Gauge | Matches by severity (CRITICAL/HIGH/MEDIUM/LOW) |
| `sentrikat_api_keys_active` | Gauge | Active agent API keys |
| `sentrikat_subscriptions` | Gauge | Subscriptions by status (SaaS only) |
| `sentrikat_assignments{status}` | Gauge | Remediation assignments by status (`open`, `in_progress`, `resolved`) — *Sprint 4* |
| `sentrikat_assignments_overdue` | Gauge | Remediation assignments past their `due_date` — *Sprint 4* |
| `sentrikat_assignments_with_tracker_ticket` | Gauge | Assignments linked to an external issue tracker — *Sprint 4* |
| `sentrikat_risk_exceptions{status}` | Gauge | Risk exceptions by status (`active`, `revoked`, `expired`) — *Sprint 4* |
| `sentrikat_product_aliases_total` | Gauge | Product aliases configured — *Sprint 4* |

**Prometheus scrape config:**
```yaml
scrape_configs:
  - job_name: 'sentrikat'
    static_configs:
      - targets: ['sentrikat.example.com']
    scheme: https
    authorization:
      credentials: '<SENTRIKAT_METRICS_KEY>'
```

**Environment variable:**
```bash
SENTRIKAT_METRICS_KEY=your-secure-random-key-here
```

---

## SBOM Export

*Sprint 4 + Sprint 5* — Export the organization's software inventory + matched
vulnerabilities as a Software Bill of Materials in industry-standard formats.

All endpoints are:
- **Licensing-gated** (feature key `sbom_export` in `PROFESSIONAL_FEATURES`). Free users get HTTP 403 with an upgrade message.
- **Rate-limited** to 10 requests/hour per organization (HTTP 429 on overflow).
- **Org-scoped** — the bundle contains only data belonging to the caller's organization.

### CycloneDX 1.5 Export

```http
GET /api/sbom/export/cyclonedx
Cookie: session=<token>
```

Returns a CycloneDX 1.5 JSON bundle with `bomFormat`, `specVersion`,
`components` (one per product, with `purl` like `pkg:apt/openssl/openssl@1.1.1k`)
and `vulnerabilities` (one per matched CVE with `ratings`, `affects` refs,
`source`).

**Validation:** the resulting JSON validates against
`https://cyclonedx.github.io/cyclonedx.org/tool-center/`.

### SPDX 2.3 Export

```http
GET /api/sbom/export/spdx
```

Returns an SPDX 2.3 JSON bundle (`spdxVersion: "SPDX-2.3"`) with `packages`
array — each package has `SPDXID`, `name`, `versionInfo`, `externalRefs`
(`cpe23Type` if available), and `licenseDeclared`.

### STIX 2.1 Export *(Sprint 5)*

```http
GET /api/sbom/export/stix21
```

Returns a STIX 2.1 bundle (`type: "bundle"`) with:
- `vulnerability` SDOs — one per matched CVE, with `external_references[0].source_name = "cve"`
- `software` SCOs — one per affected product, with `name` and `version`
- `relationship` SROs — `relationship_type: "affects"` linking vuln → software

**Validation:** the bundle validates against
`https://oasis-open.github.io/cti-stix-validator/`.

**Use cases:** Cyber Resilience Act (EU 2024/2847) compliance, EO 14028
(US federal), supply chain security, threat intel sharing (MISP/ISAC).

---

## Compliance Reports

*Sprint 5* — Gap analysis reports for major security frameworks. All endpoints
support `?format=json` (default) and `?format=pdf`. Every report carries an
`integrity` block (`{algorithm: "HMAC-SHA256", hash, signed_at}`) computed
over the canonical JSON body so auditors can verify the report has not been
tampered with after generation.

All endpoints are **licensing-gated** (feature key `compliance_reports` —
included in Professional and above, or sold as the *Compliance Pack* add-on)
and **rate-limited** to 10 requests/hour per organization.

### PCI-DSS v4.0 Gap Analysis

```http
GET /api/reports/compliance/pci-dss[?format=json|pdf]
```

Maps the organization's posture against PCI-DSS v4.0 Requirements **6.3**
(Develop and maintain secure systems and software) and **11.3** (Regularly
test security of systems and networks).

**Response (JSON):**
```json
{
  "framework": "PCI-DSS",
  "version": "4.0",
  "generated_at": "2026-04-14T08:30:00Z",
  "organization": { "id": 1, "name": "Acme" },
  "requirements": [
    {
      "id": "6.3",
      "title": "Develop and maintain secure systems and software",
      "status": "PASS|PARTIAL|FAIL|NOT_APPLICABLE",
      "evidence": [...],
      "gaps": [...],
      "recommendations": [...]
    }
  ],
  "integrity": {
    "algorithm": "HMAC-SHA256",
    "hash": "...",
    "signed_at": "2026-04-14T08:30:00Z"
  }
}
```

### ISO/IEC 27001:2022 Gap Analysis

```http
GET /api/reports/compliance/iso-27001[?format=json|pdf]
```

Maps controls **Annex A.8.8** (Management of technical vulnerabilities),
**Annex A.8.16** (Monitoring activities) and **Annex A.5.24** (Information
security incident management planning and preparation).

### SOC 2 Gap Analysis

```http
GET /api/reports/compliance/soc2[?format=json|pdf]
```

Maps the Trust Services Criteria **CC7.1**, **CC7.2**, **CC7.4** (System
operations / monitoring) and **CC6.6** (Logical and physical access
controls — vulnerability management).

### Existing reports (unchanged)

- `GET /api/reports/compliance/bod-22-01` — CISA BOD 22-01
- `GET /api/reports/compliance/nis2` — EU NIS2 Article 21(2)(d)(e)(g)

---

## Remediation Assignments & SLA

*Sprint 4* — Track who owns the fix for which vulnerability, when it's due,
and whether the SLA has been met.

### List Assignments

```http
GET /api/remediation/assignments?status=open&assignee=42&overdue=true&page=1&per_page=50
```

**Filters:** `status` (`open` / `in_progress` / `resolved`), `assignee`
(user_id), `overdue` (boolean), `severity`, `cve_id`, `product_id`,
`tracker_type`.

### Get Assignment Details

```http
GET /api/remediation/assignments/<assignment_id>
```

### Create Assignment

```http
POST /api/remediation/assignments
Content-Type: application/json

{
  "vulnerability_match_id": 123,
  "assignee_user_id": 42,
  "due_date": "2026-05-01",
  "severity": "HIGH",
  "notes": "Patch openssl on prod-web-01"
}
```

Returns 201 with the created assignment. The system will compute `due_date`
automatically if not provided and an applicable `SLAPolicy` exists.

### Update Assignment

```http
PUT /api/remediation/assignments/<assignment_id>
Content-Type: application/json

{
  "status": "in_progress",
  "tracker_issue_key": "SEC-1234",
  "tracker_issue_url": "https://acme.atlassian.net/browse/SEC-1234",
  "tracker_type": "jira"
}
```

The `tracker_issue_key` field replaces the legacy `jira_issue_key` field but
the old name is still accepted for backward compatibility.

### Delete Assignment

```http
DELETE /api/remediation/assignments/<assignment_id>
```

### SLA Policies

```http
GET    /api/sla/policies                  # List all policies for the org
POST   /api/sla/policies                  # Create policy
PUT    /api/sla/policies/<policy_id>      # Update
DELETE /api/sla/policies/<policy_id>      # Delete
```

A policy maps `(severity, asset_type)` → days-to-remediate. New assignments
inherit a `due_date` from the matching policy if one exists.

### SLA Compliance Summary

```http
GET /api/sla/compliance
```

Returns aggregate compliance counters: `compliant`, `at_risk`, `breached`,
broken down by severity and assignee. Used by the dashboard.

**Rate limits:** assignments 60 req/min, SLA policies 30 req/min.

---

## Risk Exceptions

*Sprint 4* — Accept-the-risk workflow with mandatory justification, optional
expiry, and ISO/SOC2 audit evidence.

### List Risk Exceptions

```http
GET /api/risk-exceptions?status=active&cve_id=CVE-2024-1234
```

### Create Risk Exception

```http
POST /api/risk-exceptions
Content-Type: application/json

{
  "vulnerability_match_id": 123,
  "justification": "WAF mitigation in place; production patching scheduled for Q3.",
  "expires_at": "2026-12-31T23:59:59Z",
  "approved_by_user_id": 1
}
```

`justification` is **required** (HTTP 400 if missing). `expires_at` is
optional — if omitted the exception is permanent (the UI shows "Permanent"
in the Expires column).

### Update Risk Exception

```http
PUT /api/risk-exceptions/<exception_id>
Content-Type: application/json

{
  "status": "revoked",
  "expires_at": "2026-06-30T00:00:00Z"
}
```

Used to extend expiry, revoke an active exception, or change status.

### Delete Risk Exception

```http
DELETE /api/risk-exceptions/<exception_id>
```

**Behavior:**
- An active exception removes the affected `VulnerabilityMatch` from the
  active dashboard (it still appears in the exceptions panel).
- Expired exceptions are automatically flagged with `is_expired: true` and
  no longer suppress the match.
- Cross-tenant access returns 404 (not 403, to avoid id enumeration).

**Rate limit:** 30 POST/min per organization.

---

## Product Aliases

*Sprint 4* — Vendor/product disambiguation. Useful when the same software
appears under different names in your fleet (e.g. `openssl` vs `openssl-libs`
vs `openssl3`) and you want them all to map to the same canonical product.

### List Aliases

```http
GET /api/product-aliases
```

Returns the alias rows with embedded canonical product info.

### Create Alias

```http
POST /api/product-aliases
Content-Type: application/json

{
  "product_id": 42,
  "alias_vendor": "OpenSSL",
  "alias_product": "openssl-libs"
}
```

Returns 201 with the created alias. Returns 409 if `(organization_id,
alias_vendor, alias_product)` is already mapped (unique constraint
`uq_product_alias`).

### Delete Alias

```http
DELETE /api/product-aliases/<alias_id>
```

**Rate limit:** 30 POST/min.

---

## Vulnerability Trending

*Sprint 5* — Historical snapshots of vulnerability state for trend analysis.

### Get Trends

```http
GET /api/vulnerabilities/trends?days=30
```

Returns an array of daily snapshots:

```json
{
  "trends": [
    {
      "date": "2026-04-01",
      "total": 1247,
      "critical": 12,
      "high": 88,
      "medium": 510,
      "low": 637,
      "open": 980,
      "resolved": 267
    }
  ]
}
```

The daily snapshot is captured by the `snapshot_vulnerabilities_daily` job
at 02:00 UTC. The dashboard widget consumes this endpoint with three views:
total, by severity, and open vs resolved.

### Force Snapshot (admin)

```http
POST /api/vulnerabilities/trends/snapshot
```

Manually triggers a snapshot for the current organization. Useful for
demos and tests. Admin only (returns 403 for non-admin users).

---

## Patch Tuesday Digest

*Sprint 5* — Monthly automated email digest of MSRC Patch Tuesday CVEs
affecting your fleet, sent on the 2nd Wednesday of each month at 09:00.

### Manual Trigger

```http
POST /api/reports/patch-tuesday/trigger?dry_run=true
```

Triggers the digest job manually. With `dry_run=true` (default for safety) the
endpoint returns what *would* be sent without actually sending the email:

```json
{
  "organizations_scanned": 12,
  "matches_found": 47,
  "email_would_be_sent": true,
  "skipped_reasons": {
    "no_new_cves": 3,
    "quota_exhausted": 1
  }
}
```

With `dry_run=false` (admin only) the email is actually delivered. Each
organization that has at least one matching CVE since the previous Patch
Tuesday digest receives an email subject like *"SentriKat Patch Tuesday
Digest — April 2026"*.

**Notes:**
- Uses `Vulnerability.date_added` (not `published_date` — that field does
  not exist on the model).
- Respects the Resend free tier quota (skips orgs over quota with a
  `quota_exhausted` log entry).
- The scheduler cron is `day=8-14, dow=wed, hour=9, minute=0`.
