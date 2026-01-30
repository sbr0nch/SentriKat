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
13. [Licensing](#licensing)

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

### Upload License

```http
POST /api/license
Content-Type: application/json

{
  "license_key": "LICENSE_KEY_STRING"
}
```

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
