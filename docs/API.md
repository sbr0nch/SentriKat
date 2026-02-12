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
