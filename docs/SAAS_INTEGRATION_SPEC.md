# SentriKat SaaS Integration Specification

**Version:** 1.0
**Date:** 2026-02-19
**Audience:** Web/Portal development team
**Purpose:** Everything needed to integrate sentrikat.com portal with the SaaS backend

---

## TABLE OF CONTENTS

1. [Architecture Overview](#1-architecture-overview)
2. [Pricing & Plans (Final)](#2-pricing--plans)
3. [Complete Customer Journey](#3-complete-customer-journey)
4. [Stripe Integration Spec](#4-stripe-integration-spec)
5. [Portal → SaaS API Contracts](#5-portal--saas-api-contracts)
6. [License System: Current vs SaaS](#6-license-system-current-vs-saas)
7. [Agent Distribution in SaaS](#7-agent-distribution-in-saas)
8. [Database Schema (New Tables)](#8-database-schema)
9. [Environment Configuration](#9-environment-configuration)
10. [Deployment Architecture](#10-deployment-architecture)
11. [Migration Plan: On-Premise Portal → SaaS Portal](#11-migration-plan)

---

## 1. ARCHITECTURE OVERVIEW

### What exists today (on-premise)

```
┌─────────────────────────────────────────────────────────┐
│  sentrikat.com (your website)                           │
│                                                         │
│  ┌─────────┐     ┌──────────────────────────────────┐  │
│  │ Pricing  │────→│ Stripe Checkout                  │  │
│  │ Page     │     │ (customer pays for Pro license)  │  │
│  └─────────┘     └──────────────┬───────────────────┘  │
│                                 │                       │
│                     ┌───────────▼───────────────┐      │
│                     │ Customer Portal            │      │
│                     │ - Download SentriKat Docker│      │
│                     │ - Manage license keys      │      │
│                     │ - View activation codes    │      │
│                     └───────────┬───────────────┘      │
│                                 │                       │
│              ┌──────────────────▼────────────────────┐  │
│              │ License Server API                     │  │
│              │ license.sentrikat.com/api              │  │
│              │ - POST /v1/license/activate            │  │
│              │ - POST /v1/heartbeat                   │  │
│              │ - GET  /v1/releases/latest             │  │
│              └──────────────────┬────────────────────┘  │
└─────────────────────────────────┼───────────────────────┘
                                  │
                    Customer downloads & installs
                                  │
                    ┌─────────────▼──────────────┐
                    │ Customer's own server       │
                    │ docker-compose up           │
                    │ ├── SentriKat app           │
                    │ ├── PostgreSQL              │
                    │ └── Nginx                   │
                    │                             │
                    │ Activates license with code │
                    │ Agents report to THIS server│
                    └─────────────────────────────┘
```

### What we're adding (SaaS)

```
┌─────────────────────────────────────────────────────────────┐
│  sentrikat.com (your website) - UPDATED                     │
│                                                             │
│  ┌─────────┐     ┌──────────────────────────────────────┐  │
│  │ Pricing  │────→│ Stripe Checkout                      │  │
│  │ Page     │     │ Customer chooses:                    │  │
│  │          │     │  A) On-Premise (existing flow)       │  │
│  │          │     │  B) SaaS Cloud (NEW flow) ◄──────    │  │
│  └─────────┘     └──────────────┬───────────────────┘    │  │
│                                 │                         │  │
│              ┌──────────────────▼─────────────────────┐   │  │
│              │  Customer Portal - UPDATED              │   │  │
│              │                                         │   │  │
│              │  On-Premise tab:                        │   │  │
│              │   - Download Docker (existing)          │   │  │
│              │   - License keys (existing)             │   │  │
│              │   - Activation codes (existing)         │   │  │
│              │                                         │   │  │
│              │  SaaS tab: (NEW)                        │   │  │
│              │   - "Your instance: app.sentrikat.com"  │   │  │
│              │   - Login credentials                   │   │  │
│              │   - API key for agents                  │   │  │
│              │   - Usage dashboard                     │   │  │
│              │   - Plan upgrade/downgrade              │   │  │
│              │   - Billing history (Stripe portal)     │   │  │
│              └──────────────────┬─────────────────────┘   │  │
│                                 │                         │  │
│              ┌──────────────────▼─────────────────────┐   │  │
│              │  License Server API - UPDATED           │   │  │
│              │  license.sentrikat.com/api              │   │  │
│              │                                         │   │  │
│              │  Existing (on-premise):                 │   │  │
│              │  - POST /v1/license/activate            │   │  │
│              │  - POST /v1/heartbeat                   │   │  │
│              │  - GET  /v1/releases/latest             │   │  │
│              │                                         │   │  │
│              │  NEW (SaaS provisioning):               │   │  │
│              │  - POST /v1/saas/provision  ◄──────     │   │  │
│              │  - POST /v1/saas/deprovision            │   │  │
│              │  - GET  /v1/saas/usage/:org_id          │   │  │
│              │  - POST /v1/saas/update-plan            │   │  │
│              └──────────────────┬─────────────────────┘   │  │
└─────────────────────────────────┼─────────────────────────────┘
                                  │
                    Calls the SaaS instance
                                  │
               ┌──────────────────▼───────────────────────┐
               │  app.sentrikat.com (SaaS Instance)       │
               │  ONE shared SentriKat installation       │
               │                                          │
               │  ┌──────────────────────────────────┐   │
               │  │ Cloudflare (CDN + SSL + DDoS)    │   │
               │  └─────────────┬────────────────────┘   │
               │                │                         │
               │  ┌─────────────▼────────────────────┐   │
               │  │ Load Balancer                     │   │
               │  └──────┬──────────────┬────────────┘   │
               │         │              │                 │
               │  ┌──────▼──────┐ ┌────▼─────────┐      │
               │  │ Flask App 1 │ │ Flask App 2  │      │
               │  └──────┬──────┘ └────┬─────────┘      │
               │         │              │                 │
               │  ┌──────▼──────────────▼─────────┐      │
               │  │ Managed PostgreSQL             │      │
               │  │ ALL customers in ONE database  │      │
               │  │ Isolated by organization_id    │      │
               │  └───────────────────────────────┘      │
               └──────────────────────────────────────────┘
                    ↑                     ↑
               All customers          All agents
               log in here            report here
               (with their            (with their
                own credentials)       own API keys)
```

### KEY POINT: Where Customers Log In

**ALL SaaS customers log into the SAME URL: `app.sentrikat.com`**

This is how Slack, GitHub, Jira Cloud, and 95% of SaaS products work.
There is NO per-customer VM or per-customer installation.

Data isolation is handled at the database level:
- Every table has an `organization_id` column
- Every query filters by `organization_id`
- Customer A can NEVER see Customer B's data
- This is already built and tested (`tests/test_multi_tenant.py`)

---

## 2. PRICING & PLANS

### On-Premise (UNCHANGED - keep as-is on the portal)

| | Demo | Professional |
|---|---|---|
| Price | Free | €2,499/year |
| Agents | 5 | 10 base + packs |
| Agent Packs | - | +25=€499, +50=€899, +100=€1,499, Unlimited=€2,199 |
| Delivery | Docker download | Docker download + license key |

### SaaS Plans (NEW - add to pricing page)

| | Free | Starter | Professional | Business | Enterprise |
|---|---|---|---|---|---|
| **Monthly** | €0 | €29/mo | €79/mo | €199/mo | €499/mo+ |
| **Annual** | €0 | €290/yr | €790/yr | €1,990/yr | €4,990/yr+ |
| **Savings** | - | 17% | 17% | 17% | 17% |
| | | | | | |
| **Agents** | 5 | 25 | 100 | 500 | Unlimited |
| **Users** | 1 | 3 | 10 | 50 | Unlimited |
| **Organizations** | 1 | 1 | 3 | 10 | Unlimited |
| **Products** | 50 | Unlimited | Unlimited | Unlimited | Unlimited |
| **API Keys** | 1 | 2 | 5 | 25 | Unlimited |
| **Storage** | 100 MB | 500 MB | 2 GB | 10 GB | Unlimited |
| | | | | | |
| **Email Alerts** | - | Yes | Yes | Yes | Yes |
| **Webhooks** | - | Yes | Yes | Yes | Yes |
| **API Access** | - | Yes | Yes | Yes | Yes |
| **LDAP** | - | - | Yes | Yes | Yes |
| **Jira** | - | - | Yes | Yes | Yes |
| **Compliance Reports** | - | - | Yes | Yes | Yes |
| **Multi-Org** | - | - | Yes | Yes | Yes |
| **SSO (SAML)** | - | - | - | Yes | Yes |
| **White Label** | - | - | - | Yes | Yes |
| **Backup/Restore** | - | - | - | Yes | Yes |
| **Push Agents** | - | - | Yes | Yes | Yes |
| **Audit Export** | - | - | Yes | Yes | Yes |
| **Dedicated Instance** | - | - | - | - | Optional |
| **SLA** | - | - | - | - | Custom |
| **Priority Support** | - | - | - | - | Yes |

### Competitive Position

```
Per-agent cost comparison (annual):

€40/agent  SentriKat On-Premise (with packs)
€23/agent  Rapid7 InsightVM
€22/agent  Tenable VM Cloud
€14/agent  SentriKat SaaS Starter  ◄ Undercuts Rapid7/Tenable
€10/agent  Nucleus Security
 €8/agent  SentriKat SaaS Pro      ◄ Best mid-market value
 €7/agent  ManageEngine VM+
 €4/agent  SentriKat SaaS Business ◄ Cheapest at scale
```

### Why SaaS doesn't cannibalize On-Premise

| On-Premise buyer | SaaS buyer |
|---|---|
| Government, military, finance (compliance) | Startups, SMBs, MSPs |
| Must keep data in-house | Wants zero infrastructure |
| Pays €2,499+ upfront for control | Pays €29-199/mo for convenience |
| Manages own server | We manage everything |
| Different market segment | Different market segment |

---

## 3. COMPLETE CUSTOMER JOURNEY

### Journey A: On-Premise (existing, no changes needed)

```
1. Customer visits sentrikat.com/pricing
2. Clicks "Buy Professional" (on-premise)
3. Stripe Checkout → pays €2,499
4. Stripe webhook → Portal creates:
   - Customer account
   - License record
   - Activation code
5. Customer sees portal dashboard:
   - Download link for Docker images
   - Activation code: "SK-ACT-XXXXX"
   - Installation guide
6. Customer installs Docker on their server
7. Customer enters activation code in SentriKat admin
8. SentriKat calls POST license.sentrikat.com/api/v1/license/activate
   - Sends: {activation_code, installation_id}
   - Receives: hardware-locked signed license
9. License activated → Professional features unlocked
10. Customer deploys agents
```

### Journey B: SaaS (NEW - what portal team needs to build)

```
1. Customer visits sentrikat.com/pricing
2. Clicks "Start Free" or "Subscribe to Pro" (SaaS tab)
3. For Free: just email + password signup form
   For Paid: Stripe Checkout → pays €29-499/mo
4. Stripe webhook → Portal calls SaaS provisioning API:

   POST app.sentrikat.com/api/internal/provision
   Headers:
     X-Internal-Key: <shared secret between portal and SaaS>
   Body: {
     "org_name": "acme-corp",
     "org_display_name": "ACME Corporation",
     "admin_email": "john@acme.com",
     "admin_password": "<auto-generated>",
     "plan": "pro",
     "stripe_customer_id": "cus_xxx",
     "stripe_subscription_id": "sub_xxx"
   }

   Response: {
     "success": true,
     "organization": {"id": 42, "name": "acme-corp"},
     "admin_user": {"id": 15, "username": "john@acme.com"},
     "api_key": {
       "id": 8,
       "key": "sk_agent_xxxxxxxxxxxxxxxx",  ← Only returned once!
       "key_prefix": "sk_agent_xx"
     }
   }

5. Portal stores the mapping:
   stripe_customer_id → organization_id (for billing events)

6. Portal sends welcome email to customer:
   - Login URL: https://app.sentrikat.com
   - Username: john@acme.com
   - Temporary password (must change on first login)
   - API key: sk_agent_xxxxxxxx
   - Quick start guide link

7. Customer clicks login URL → lands on app.sentrikat.com
   - Logs in with email + temporary password
   - Forced password change on first login
   - Sees their empty dashboard
   - Goes to Agents → copies API key → deploys agents

8. Monthly: Stripe auto-charges
   On payment success → no action needed
   On payment failure → Stripe retries 3x over 7 days
   After all retries fail:
     Portal calls: POST app.sentrikat.com/api/internal/suspend
     Body: {"organization_id": 42, "reason": "payment_failed"}
     → Org set to read-only (can view but not add agents)

   After 30 days suspended:
     Portal calls: POST app.sentrikat.com/api/internal/deprovision
     Body: {"organization_id": 42, "confirm_name": "acme-corp"}
     → Data deleted after 90-day grace period
```

### Journey C: Upgrade/Downgrade

```
1. Customer clicks "Upgrade" in portal OR in SaaS app
2. Portal updates Stripe subscription
3. Stripe webhook (subscription.updated) → Portal calls:

   POST app.sentrikat.com/api/internal/update-plan
   Headers:
     X-Internal-Key: <shared secret>
   Body: {
     "organization_id": 42,
     "new_plan": "business",
     "new_limits": {
       "max_agents": 500,
       "max_users": 50,
       "max_organizations": 10,
       "max_api_keys": 25
     },
     "features": {
       "email_alerts": true,
       "ldap": true,
       "sso": true,
       "webhooks": true,
       "white_label": true,
       "compliance_reports": true,
       "jira_integration": true,
       "push_agents": true,
       "backup_restore": true,
       "audit_export": true,
       "multi_org": true
     }
   }

   Response: {"success": true, "effective_immediately": true}

4. Customer immediately gets access to new features/limits
```

---

## 4. STRIPE INTEGRATION SPEC

### Products & Prices to Create in Stripe

```
Stripe Product: "SentriKat SaaS"
  └── Price: "Starter Monthly"   → €29/mo,   recurring, EUR
  └── Price: "Starter Annual"    → €290/yr,   recurring, EUR
  └── Price: "Pro Monthly"       → €79/mo,   recurring, EUR
  └── Price: "Pro Annual"        → €790/yr,   recurring, EUR
  └── Price: "Business Monthly"  → €199/mo,  recurring, EUR
  └── Price: "Business Annual"   → €1,990/yr, recurring, EUR
  └── Price: "Enterprise Monthly"→ €499/mo,  recurring, EUR
  └── Price: "Enterprise Annual" → €4,990/yr, recurring, EUR

Stripe Product: "SentriKat On-Premise" (existing, keep as-is)
  └── (your existing prices)
```

### Stripe Webhook Events to Handle

| Event | Portal Action | SaaS API Call |
|---|---|---|
| `checkout.session.completed` | Create customer record | `POST /api/internal/provision` |
| `customer.subscription.updated` | Update plan record | `POST /api/internal/update-plan` |
| `customer.subscription.deleted` | Mark as canceled | `POST /api/internal/suspend` |
| `invoice.payment_succeeded` | Log payment | (none needed) |
| `invoice.payment_failed` | Send warning email | (none after 3rd failure → suspend) |
| `customer.subscription.trial_will_end` | Send trial ending email | (none) |

### Stripe Customer Portal

For self-service billing management (update card, view invoices, cancel):

```
POST sentrikat.com/api/billing/portal-session
→ Creates Stripe billing portal session
→ Redirects customer to https://billing.stripe.com/session/xxx
→ Customer can update payment method, view invoices, cancel
→ Stripe sends webhooks for any changes
```

---

## 5. PORTAL → SAAS API CONTRACTS

### Authentication: Internal API Key

All calls from the portal to the SaaS instance use a shared secret:

```
Header: X-Internal-Key: <SAAS_INTERNAL_API_KEY>
```

This key is set in both:
- Portal environment: `SAAS_INTERNAL_API_KEY=your-secret-here`
- SaaS instance environment: `SAAS_INTERNAL_API_KEY=your-secret-here`

**IMPORTANT:** This is NOT the same as agent API keys. This is a server-to-server secret.

### Endpoint: Provision Tenant

```
POST app.sentrikat.com/api/internal/provision

Headers:
  Content-Type: application/json
  X-Internal-Key: <secret>

Request Body:
{
  "org_name": "acme-corp",              // Required. Lowercase slug, 3-100 chars
  "org_display_name": "ACME Corp",      // Required. Human-readable name
  "admin_email": "admin@acme.com",      // Required. Becomes username + email
  "admin_password": "TempP@ss123!",     // Required. Min 8 chars. Customer must change
  "plan": "pro",                        // Required. One of: free, starter, pro, business, enterprise
  "stripe_customer_id": "cus_xxx",      // Required for paid plans
  "stripe_subscription_id": "sub_xxx",  // Required for paid plans
  "billing_cycle": "monthly",           // "monthly" or "annual"
  "trial_days": 14,                     // Optional. 0 = no trial
  "notification_emails": ["admin@acme.com"], // Optional
  "org_description": "...",             // Optional
}

Success Response (201):
{
  "success": true,
  "organization": {
    "id": 42,
    "name": "acme-corp",
    "display_name": "ACME Corp"
  },
  "admin_user": {
    "id": 15,
    "username": "admin@acme.com",
    "email": "admin@acme.com"
  },
  "api_key": {
    "id": 8,
    "name": "ACME Corp - Default Key",
    "key_prefix": "sk_agent_xx",
    "key": "sk_agent_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"
    // ^^^ ONLY returned on creation. Store securely for welcome email!
  },
  "subscription": {
    "id": 5,
    "plan": "pro",
    "status": "active",          // or "trialing" if trial_days > 0
    "stripe_subscription_id": "sub_xxx"
  }
}

Error Responses:
  400: {"error": "Organization name must be 3-100 characters"}
  400: {"error": "Username or email already exists"}
  401: {"error": "Invalid internal API key"}
  403: {"error": "Organization limit reached"}
  409: {"error": "Organization 'acme-corp' already exists"}
  500: {"error": "Provisioning failed: <details>"}
```

### Endpoint: Update Plan

```
POST app.sentrikat.com/api/internal/update-plan

Headers:
  Content-Type: application/json
  X-Internal-Key: <secret>

Request Body:
{
  "organization_id": 42,
  // OR
  "stripe_subscription_id": "sub_xxx",

  "new_plan": "business",          // Plan name
  "effective_immediately": true     // Apply limits now (default true)
}

Success Response (200):
{
  "success": true,
  "organization_id": 42,
  "old_plan": "pro",
  "new_plan": "business",
  "new_limits": {
    "max_agents": 500,
    "max_users": 50,
    "max_organizations": 10,
    "max_api_keys": 25,
    "max_storage_mb": 10000
  }
}
```

### Endpoint: Suspend Tenant

```
POST app.sentrikat.com/api/internal/suspend

Headers:
  Content-Type: application/json
  X-Internal-Key: <secret>

Request Body:
{
  "organization_id": 42,
  "reason": "payment_failed",        // or "manual", "abuse", "trial_expired"
  "read_only": true                   // Allow read access but block writes
}

Success Response (200):
{
  "success": true,
  "organization_id": 42,
  "status": "suspended",
  "agents_affected": 45,             // Number of agents that will stop reporting
  "data_retained_until": "2026-05-19T00:00:00Z"  // 90-day retention
}
```

### Endpoint: Deprovision Tenant

```
DELETE app.sentrikat.com/api/internal/deprovision

Headers:
  Content-Type: application/json
  X-Internal-Key: <secret>

Request Body:
{
  "organization_id": 42,
  "confirm_name": "acme-corp",       // Safety: must match org name
  "export_data": true                // Optional: export data before deletion
}

Success Response (200):
{
  "success": true,
  "message": "Organization 'acme-corp' and all data removed",
  "records_deleted": {
    "products": 340,
    "assets": 45,
    "vulnerability_matches": 1250,
    "users": 8,
    "api_keys": 3
  }
}
```

### Endpoint: Get Usage

```
GET app.sentrikat.com/api/internal/usage/:org_id

Headers:
  X-Internal-Key: <secret>

Success Response (200):
{
  "organization_id": 42,
  "organization_name": "ACME Corp",
  "plan": "pro",
  "limits": {
    "max_agents": 100,
    "max_users": 10,
    "max_organizations": 3,
    "max_products": -1,
    "max_api_keys": 5
  },
  "current_usage": {
    "agents_active": 67,
    "assets_total": 72,
    "products_total": 340,
    "users_active": 5,
    "api_keys": 3
  },
  "percentage_used": {
    "agents": 67,          // 67 of 100 = 67%
    "users": 50,           // 5 of 10 = 50%
    "api_keys": 60         // 3 of 5 = 60%
  },
  "measured_at": "2026-02-19T14:30:00Z"
}
```

### Endpoint: List All Tenants (Admin)

```
GET app.sentrikat.com/api/internal/tenants

Headers:
  X-Internal-Key: <secret>

Query params:
  ?status=active          // active, suspended, all
  ?plan=pro               // filter by plan
  ?page=1&per_page=50

Success Response (200):
{
  "tenants": [
    {
      "organization_id": 42,
      "name": "acme-corp",
      "display_name": "ACME Corp",
      "plan": "pro",
      "status": "active",
      "stripe_customer_id": "cus_xxx",
      "agents_active": 67,
      "users_active": 5,
      "created_at": "2026-01-15T10:30:00Z",
      "last_activity": "2026-02-19T14:25:00Z"
    },
    ...
  ],
  "total": 156,
  "page": 1,
  "per_page": 50
}
```

---

## 6. LICENSE SYSTEM: CURRENT VS SAAS

### On-Premise: RSA-Signed License (NO CHANGES)

```
Portal generates license → Customer activates with code →
SentriKat verifies RSA signature → Features unlocked

License format: base64(json_payload).base64(rsa_signature)
Signed with: RSA-4096, SHA256, PKCS1v15
Hardware-locked to: SENTRIKAT_INSTALLATION_ID (SK-INST-XXXXX)
```

**Keep this exactly as-is.** On-premise licensing continues to work independently.

### SaaS: Subscription-Based (NEW)

```
Portal provisions tenant → Subscription record created →
Plan limits enforced by application → No license file needed

Controlled by: subscription_plans + subscriptions tables
Enforced via: SENTRIKAT_MODE=saas environment variable
```

**In SaaS mode:**
- The RSA license system is bypassed entirely
- Limits come from the `Subscription` → `SubscriptionPlan` database records
- Features come from the plan's `features` JSON column
- The portal controls everything via the internal API

**The switching logic (already in the codebase):**

```python
# In app/metering.py
def check_quota(org_id, resource):
    saas_mode = os.environ.get('SENTRIKAT_MODE', 'onpremise') == 'saas'
    if saas_mode:
        return _check_saas_quota(org_id, resource)   # ← Subscription table
    else:
        return _check_license_quota(org_id, resource) # ← RSA license file
```

---

## 7. AGENT DISTRIBUTION IN SAAS

### On-Premise (current)
Customer downloads agent scripts from their own SentriKat instance:
```
GET their-server.com/api/agents/script/linux
→ Script with SERVER_URL=their-server.com embedded
```

### SaaS (how it works)
Customer downloads agent scripts from the shared SaaS instance:
```
GET app.sentrikat.com/api/agents/script/linux
→ Script with SERVER_URL=app.sentrikat.com embedded
→ Script has customer's API key embedded
→ Agent reports to app.sentrikat.com with X-Agent-Key header
→ API key maps to their organization_id → data isolated
```

**No changes needed to agent scripts.** The existing agent download endpoints
already inject the correct SERVER_URL from the request context. In SaaS mode,
that URL will be `app.sentrikat.com` for everyone.

### Portal Download Page for SaaS Customers

The portal can provide:

1. **Direct download links** (proxy through the SaaS instance):
```
https://app.sentrikat.com/api/agents/script/linux?key=sk_agent_xxx
https://app.sentrikat.com/api/agents/script/windows?key=sk_agent_xxx
https://app.sentrikat.com/api/agents/script/macos?key=sk_agent_xxx
```

2. **One-liner install commands** (for customer convenience):
```bash
# Linux
curl -sSL "https://app.sentrikat.com/api/agents/script/linux?key=sk_agent_xxx" | sudo bash

# Windows (PowerShell as Admin)
irm "https://app.sentrikat.com/api/agents/script/windows?key=sk_agent_xxx" | iex

# macOS
curl -sSL "https://app.sentrikat.com/api/agents/script/macos?key=sk_agent_xxx" | sudo bash
```

3. **API key display** (from provisioning response, stored in portal DB):
```
Your API Key: sk_agent_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx
```

---

## 8. DATABASE SCHEMA

### New Tables (already created in the codebase)

```sql
-- Defines available plans (seeded once on startup)
CREATE TABLE subscription_plans (
    id              SERIAL PRIMARY KEY,
    name            VARCHAR(50) UNIQUE NOT NULL,    -- free, starter, pro, business, enterprise
    display_name    VARCHAR(100) NOT NULL,
    description     TEXT,

    -- Limits (-1 = unlimited)
    max_agents          INTEGER DEFAULT 5,
    max_users           INTEGER DEFAULT 1,
    max_organizations   INTEGER DEFAULT 1,
    max_products        INTEGER DEFAULT 50,
    max_api_keys        INTEGER DEFAULT 1,
    max_storage_mb      INTEGER DEFAULT 100,

    -- Features (JSON)
    features        TEXT,    -- {"email_alerts": true, "ldap": false, ...}

    -- Pricing (in cents, EUR)
    price_monthly_cents     INTEGER DEFAULT 0,
    price_annual_cents      INTEGER DEFAULT 0,
    currency                VARCHAR(3) DEFAULT 'EUR',

    -- Stripe IDs (set after creating products in Stripe dashboard)
    stripe_price_id_monthly VARCHAR(100),
    stripe_price_id_annual  VARCHAR(100),
    stripe_product_id       VARCHAR(100),

    -- Metadata
    is_active       BOOLEAN DEFAULT TRUE,
    is_default      BOOLEAN DEFAULT FALSE,
    sort_order      INTEGER DEFAULT 0,
    created_at      TIMESTAMP DEFAULT NOW(),
    updated_at      TIMESTAMP DEFAULT NOW()
);

-- Links an org to a plan (one per org)
CREATE TABLE subscriptions (
    id                  SERIAL PRIMARY KEY,
    organization_id     INTEGER NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    plan_id             INTEGER NOT NULL REFERENCES subscription_plans(id),

    status              VARCHAR(20) DEFAULT 'active',
    -- active, trialing, past_due, canceled, paused, suspended, expired

    billing_cycle       VARCHAR(20) DEFAULT 'monthly',  -- monthly, annual
    current_period_start TIMESTAMP,
    current_period_end   TIMESTAMP,

    trial_start         TIMESTAMP,
    trial_end           TIMESTAMP,

    -- Stripe integration
    stripe_customer_id      VARCHAR(100),
    stripe_subscription_id  VARCHAR(100) UNIQUE,

    canceled_at             TIMESTAMP,
    cancel_at_period_end    BOOLEAN DEFAULT FALSE,

    created_at      TIMESTAMP DEFAULT NOW(),
    updated_at      TIMESTAMP DEFAULT NOW()
);

CREATE INDEX idx_subscriptions_org ON subscriptions(organization_id);
CREATE INDEX idx_subscriptions_stripe ON subscriptions(stripe_customer_id);

-- Usage tracking for billing and quotas
CREATE TABLE usage_records (
    id                  SERIAL PRIMARY KEY,
    organization_id     INTEGER NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    metric              VARCHAR(50) NOT NULL,
    -- agents_active, products_total, users_active, api_calls,
    -- alerts_sent, reports_generated, storage_bytes

    value               BIGINT DEFAULT 0,
    period_start        TIMESTAMP NOT NULL,
    period_end          TIMESTAMP NOT NULL,
    recorded_at         TIMESTAMP DEFAULT NOW()
);

CREATE INDEX idx_usage_org_metric_period ON usage_records(organization_id, metric, period_start);
```

### Existing Tables (no changes needed)

The SaaS instance uses the same tables as on-premise. Key ones:

| Table | Role in SaaS |
|---|---|
| `organizations` | One row per tenant/customer |
| `users` | Customer's users (login accounts) |
| `user_organizations` | Links users to orgs (multi-org support) |
| `agent_api_keys` | Per-org API keys for agents |
| `assets` | Devices reporting via agents (per-org) |
| `products` | Software detected on assets (per-org) |
| `vulnerabilities` | SHARED across all orgs (CISA KEV data) |
| `vulnerability_matches` | Per-org vulnerability findings |
| `system_settings` | Global SaaS config |

---

## 9. ENVIRONMENT CONFIGURATION

### SaaS Instance (app.sentrikat.com)

```bash
# ── Mode ──
SENTRIKAT_MODE=saas                    # Switches from license to subscription enforcement
FLASK_ENV=production
SENTRIKAT_ENV=production

# ── Security ──
SECRET_KEY=<random-64-hex-chars>
ENCRYPTION_KEY=<fernet-key>

# ── Database (Managed PostgreSQL) ──
DATABASE_URL=postgresql://sentrikat:<password>@managed-db-host:25060/sentrikat?sslmode=require

# ── Application ──
SENTRIKAT_URL=https://app.sentrikat.com
SESSION_COOKIE_SECURE=true
FORCE_HTTPS=true

# ── Internal API (portal ↔ SaaS communication) ──
SAAS_INTERNAL_API_KEY=<shared-secret-with-portal>

# ── Storage (S3 for shared file access across instances) ──
STORAGE_BACKEND=s3
S3_ENDPOINT_URL=https://nyc3.digitaloceanspaces.com
S3_BUCKET_NAME=sentrikat-saas-files
S3_ACCESS_KEY=<key>
S3_SECRET_KEY=<secret>
S3_REGION=nyc3

# ── Scaling ──
GUNICORN_WORKERS=8
GUNICORN_THREADS=4
DB_POOL_SIZE=15
DB_POOL_MAX_OVERFLOW=25
WORKER_POOL_SIZE=8
```

### Portal (sentrikat.com)

```bash
# ── SaaS Instance Connection ──
SAAS_INSTANCE_URL=https://app.sentrikat.com
SAAS_INTERNAL_API_KEY=<same-shared-secret>

# ── Stripe ──
STRIPE_SECRET_KEY=sk_live_xxxx           # or sk_test_xxxx for testing
STRIPE_WEBHOOK_SECRET=whsec_xxxx
STRIPE_PUBLISHABLE_KEY=pk_live_xxxx

# ── Stripe Price IDs (create in Stripe dashboard, paste here) ──
STRIPE_PRICE_STARTER_MONTHLY=price_xxx
STRIPE_PRICE_STARTER_ANNUAL=price_xxx
STRIPE_PRICE_PRO_MONTHLY=price_xxx
STRIPE_PRICE_PRO_ANNUAL=price_xxx
STRIPE_PRICE_BUSINESS_MONTHLY=price_xxx
STRIPE_PRICE_BUSINESS_ANNUAL=price_xxx
STRIPE_PRICE_ENTERPRISE_MONTHLY=price_xxx
STRIPE_PRICE_ENTERPRISE_ANNUAL=price_xxx

# ── On-Premise License Server (existing, keep as-is) ──
LICENSE_PRIVATE_KEY_FILE=/path/to/private_key.pem
```

---

## 10. DEPLOYMENT ARCHITECTURE

### Phase 1: Start Simple (1-50 customers)

```
Cloudflare (DNS + SSL + DDoS)
        │
        ▼
┌──────────────────────────────────┐
│  Single DigitalOcean Droplet     │
│  $24/mo (4GB RAM, 2 vCPU)       │
│                                  │
│  docker-compose:                 │
│  ├── sentrikat (Flask+Gunicorn)  │
│  └── nginx (reverse proxy)      │
│                                  │
│  ← All customers log in here    │
│  ← All agents report here       │
└──────────────┬───────────────────┘
               │
┌──────────────▼───────────────────┐
│  DigitalOcean Managed PostgreSQL │
│  $15/mo (1GB RAM, 10GB storage)  │
│  Automatic backups               │
└──────────────────────────────────┘

Total: ~€44/month
```

### Phase 2: Scale (50-500 customers)

```
Cloudflare (DNS + SSL + DDoS + WAF)
        │
        ▼
┌──────────────────────────────────┐
│  DigitalOcean Load Balancer      │
│  $12/mo                          │
│                                  │
│  ┌──────────┐  ┌──────────┐     │
│  │ Flask #1 │  │ Flask #2 │     │
│  │ $48/mo   │  │ $48/mo   │     │
│  └────┬─────┘  └────┬─────┘     │
│       │              │           │
│  ┌────▼──────────────▼────┐     │
│  │ Managed PostgreSQL     │     │
│  │ $60/mo (4GB, HA)       │     │
│  └────────────────────────┘     │
│                                  │
│  ┌────────────────────────┐     │
│  │ Managed Redis           │     │
│  │ $15/mo (sessions+cache) │     │
│  └────────────────────────┘     │
│                                  │
│  ┌────────────────────────┐     │
│  │ DigitalOcean Spaces     │     │
│  │ $5/mo (file storage)    │     │
│  └────────────────────────┘     │
└──────────────────────────────────┘

Total: ~€240/month
```

---

## 11. MIGRATION PLAN: PORTAL CHANGES

### What the portal team needs to build (NEW code):

| Component | Priority | Effort | Description |
|---|---|---|---|
| **SaaS pricing page** | P0 | 1-2 days | Add SaaS tab to existing pricing page with new plans |
| **Stripe products setup** | P0 | 1 day | Create products+prices in Stripe dashboard |
| **SaaS signup flow** | P0 | 2-3 days | Form → Stripe Checkout → webhook → provision API call |
| **Stripe webhook handler** | P0 | 2-3 days | Handle checkout.completed, subscription.updated/deleted, invoice.payment_failed |
| **Portal SaaS dashboard** | P1 | 3-5 days | Show SaaS customer: login URL, API key, usage, plan, billing |
| **Provisioning API caller** | P1 | 1-2 days | Portal service that calls app.sentrikat.com/api/internal/* |
| **Welcome email template** | P1 | 1 day | Email with login URL, credentials, API key, quick start |
| **Plan upgrade/downgrade** | P2 | 2-3 days | Change Stripe subscription + call update-plan API |
| **Usage dashboard** | P2 | 2-3 days | Show customer their usage vs limits (call usage API) |
| **Admin dashboard** | P2 | 3-5 days | Internal view of all SaaS tenants, usage, revenue |
| **Self-serve cancellation** | P3 | 1-2 days | Cancel button → Stripe cancel → suspend API call |

### What the portal team does NOT need to change:

- On-premise purchase flow (unchanged)
- License generation/activation (unchanged)
- Docker download page (unchanged)
- Agent pack purchases (unchanged)
- Existing customer portal for on-premise (unchanged)

### Portal Database: New Tables Needed

```sql
-- Maps portal customers to SaaS organizations
CREATE TABLE saas_customers (
    id                      SERIAL PRIMARY KEY,
    portal_user_id          INTEGER REFERENCES users(id),  -- Portal's user table
    stripe_customer_id      VARCHAR(100) UNIQUE,
    saas_organization_id    INTEGER,          -- org ID on app.sentrikat.com
    saas_org_name           VARCHAR(100),
    plan                    VARCHAR(50),
    status                  VARCHAR(20),      -- active, suspended, canceled
    api_key_prefix          VARCHAR(20),      -- For display (sk_agent_xx...)
    created_at              TIMESTAMP DEFAULT NOW(),
    updated_at              TIMESTAMP DEFAULT NOW()
);
```

---

## APPENDIX A: Sequence Diagrams

### A1. SaaS Signup (Paid Plan)

```
Customer          sentrikat.com        Stripe           app.sentrikat.com
   │                  │                   │                    │
   │  Click "Pro"     │                   │                    │
   │─────────────────>│                   │                    │
   │                  │  Create Checkout  │                    │
   │                  │──────────────────>│                    │
   │                  │  Checkout URL     │                    │
   │                  │<──────────────────│                    │
   │  Redirect to     │                   │                    │
   │  Stripe Checkout │                   │                    │
   │<─────────────────│                   │                    │
   │                  │                   │                    │
   │  Enter card      │                   │                    │
   │  details + pay   │                   │                    │
   │─────────────────────────────────────>│                    │
   │                  │                   │                    │
   │                  │  Webhook:         │                    │
   │                  │  checkout.complete│                    │
   │                  │<──────────────────│                    │
   │                  │                   │                    │
   │                  │  POST /api/internal/provision          │
   │                  │───────────────────────────────────────>│
   │                  │                   │  Create org+user+key
   │                  │                   │                    │
   │                  │  {org_id, user, api_key}               │
   │                  │<───────────────────────────────────────│
   │                  │                   │                    │
   │                  │  Save saas_customer record             │
   │                  │                   │                    │
   │                  │  Send welcome email                    │
   │  Welcome email   │                   │                    │
   │<─────────────────│                   │                    │
   │                  │                   │                    │
   │  Login at        │                   │                    │
   │  app.sentrikat   │                   │                    │
   │─────────────────────────────────────────────────────────>│
   │                  │                   │    Dashboard       │
   │<─────────────────────────────────────────────────────────│
```

### A2. Agent Connects to SaaS

```
Agent              app.sentrikat.com           Database
  │                      │                        │
  │  POST /api/agent/inventory                    │
  │  X-Agent-Key: sk_agent_xxx                    │
  │─────────────────────>│                        │
  │                      │  SHA256(key) → lookup  │
  │                      │───────────────────────>│
  │                      │  agent_api_key found   │
  │                      │  organization_id = 42  │
  │                      │<───────────────────────│
  │                      │                        │
  │                      │  Check quota:          │
  │                      │  agents_active < 100?  │
  │                      │───────────────────────>│
  │                      │  Yes (67 < 100)        │
  │                      │<───────────────────────│
  │                      │                        │
  │                      │  Save products with    │
  │                      │  organization_id = 42  │
  │                      │───────────────────────>│
  │                      │                        │
  │  {"status": "ok",    │                        │
  │   "products": 45}    │                        │
  │<─────────────────────│                        │
```

### A3. Payment Failure → Suspension

```
Stripe             sentrikat.com        app.sentrikat.com
  │                      │                    │
  │  invoice.payment     │                    │
  │  _failed (attempt 1) │                    │
  │─────────────────────>│                    │
  │                      │  Send warning      │
  │                      │  email to customer │
  │                      │                    │
  │  (3 days later)      │                    │
  │  invoice.payment     │                    │
  │  _failed (attempt 2) │                    │
  │─────────────────────>│                    │
  │                      │  Send urgent email │
  │                      │                    │
  │  (3 days later)      │                    │
  │  invoice.payment     │                    │
  │  _failed (final)     │                    │
  │─────────────────────>│                    │
  │                      │                    │
  │  customer.subscription                    │
  │  .deleted            │                    │
  │─────────────────────>│                    │
  │                      │  POST /api/internal/suspend
  │                      │───────────────────>│
  │                      │  {"organization_id": 42,
  │                      │   "reason": "payment_failed",
  │                      │   "read_only": true}
  │                      │                    │
  │                      │  Org suspended     │
  │                      │<───────────────────│
  │                      │                    │
  │                      │  Send "suspended"  │
  │                      │  email to customer │
```

---

## APPENDIX B: Testing Checklist

### Stripe Test Mode

- Use `sk_test_xxxx` keys (not live)
- Test card: `4242 4242 4242 4242` (any expiry, any CVC)
- Test failure card: `4000 0000 0000 0002` (decline)
- Test 3D Secure: `4000 0025 0000 3155`
- Webhook testing: Use Stripe CLI `stripe listen --forward-to localhost:5000/webhook`

### End-to-End Test Scenarios

```
[ ] Free signup → provision → login → deploy agent → see vulnerabilities
[ ] Paid signup → Stripe checkout → provision → login → features unlocked
[ ] Upgrade from Free to Pro → limits increased immediately
[ ] Downgrade from Pro to Starter → limits reduced, excess agents warned
[ ] Payment failure → 3 retries → suspension → read-only access
[ ] Re-payment after suspension → access restored
[ ] Cancellation → grace period → data cleanup
[ ] Two customers → verify data isolation (A cannot see B's data)
[ ] Agent from Customer A → cannot send data to Customer B's org
[ ] Usage approaching limit → warning shown in dashboard
[ ] Usage at limit → new agents rejected with clear error
```

---

**Document end. Questions? Contact the SaaS engineering team.**
