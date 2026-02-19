# SentriKat - Full Pre-Release Audit & SaaS Migration Guide

**Date:** 2026-02-18
**Scope:** Full software audit, SaaS migration analysis, cloud guide, mobile agent feasibility

---

## TABLE OF CONTENTS

1. [Pre-Release Software Audit](#1-pre-release-software-audit)
2. [SaaS Migration - Is It Doable?](#2-saas-migration---is-it-doable)
3. [Cloud Provider Guide (Zero Knowledge)](#3-cloud-provider-guide-for-beginners)
4. [What Changes for SaaS Architecture](#4-what-changes-for-saas-architecture)
5. [Mobile & Device Agent Support](#5-mobile--device-agent-support)
6. [Cost Estimates](#6-cost-estimates)
7. [Step-by-Step Migration Roadmap](#7-step-by-step-migration-roadmap)

---

# 1. PRE-RELEASE SOFTWARE AUDIT

## 1.1 Security Audit

### Overall Rating: B+ (GOOD - Production Ready with minor fixes)

### What's GOOD (no action needed):

| Area | Status | Details |
|------|--------|---------|
| SQL Injection | SAFE | SQLAlchemy ORM used everywhere, no raw SQL |
| Password Storage | SAFE | PBKDF2 via werkzeug, properly salted |
| Session Management | SAFE | Session fixation prevention, 4hr TTL, SameSite=Lax |
| CSRF Protection | SAFE | Flask-WTF enabled, API routes properly exempted |
| XSS Prevention | SAFE | Jinja2 auto-escaping, HTML escaped in emails |
| LDAP Injection | SAFE | `escape_filter_chars()` used properly |
| Command Injection | SAFE | No `os.system()` or `shell=True` anywhere |
| Path Traversal | SAFE | `..` and absolute path rejection on uploads |
| Multi-Tenant Isolation | SAFE | `organization_id` on all tables, tested in test_multi_tenant.py |
| Rate Limiting | EXCELLENT | Per-endpoint limits: login 5/min, agent 60/min, heartbeat 120/min |
| Container Security | SAFE | Non-root user `sentrikat`, no secrets in image |
| Encryption | SAFE | Fernet (AES-128-CBC) for SMTP passwords, API keys, webhook tokens |
| 2FA | IMPLEMENTED | TOTP with QR code setup |
| RBAC | IMPLEMENTED | super_admin, org_admin, manager, user roles enforced |
| Account Lockout | IMPLEMENTED | 5 failed attempts -> 30 minute lockout |

### What NEEDS FIXING before release:

#### CRITICAL (Fix Now)

1. **Bare `except:` clauses** - Found in models.py, saml_api.py, settings_api.py
   - Risk: Catches KeyboardInterrupt, SystemExit - can mask real errors
   - Fix: Change `except:` to `except Exception:` everywhere

2. **No SAML SSO tests** - Zero test coverage for SAML authentication flow
   - Risk: SAML is a complex protocol, bugs can bypass authentication entirely
   - Fix: Add test_saml.py with login flow, assertion parsing, edge cases

3. **No email delivery tests** - email_alerts.py has no test coverage
   - Risk: Alert emails could silently fail in production
   - Fix: Add tests with mock SMTP server

#### HIGH (Fix before v1.0)

4. **File upload type validation** - Only size limit (16MB), no file type checking
   - Risk: Malicious files could be uploaded
   - Fix: Whitelist allowed extensions (.png, .jpg, .svg for logos)

5. **Webhook URL validation** - URLs not validated for safe formats
   - Risk: SSRF (Server-Side Request Forgery) via webhook to internal services
   - Fix: Validate URL scheme (https only), block private IP ranges

6. **LGPL dependency review** - ldap3 and psycopg2 are LGPL v3
   - Risk: License compliance issues if distributing as proprietary
   - Fix: Review bundling strategy, add LICENSE file to repo

#### MEDIUM (Fix in v1.1)

7. **2FA not enforced for admins** - Optional for all users including super_admin
8. **Error logging may leak credentials** - email_service.py logs full exceptions
9. **No LICENSE file** in repository root
10. **Test coverage ~60-70%** - Missing: reports, Jira integration, stale asset logic

### Production Deployment Checklist

```bash
# Generate secrets
SECRET_KEY=$(python -c "import secrets; print(secrets.token_hex(32))")
ENCRYPTION_KEY=$(python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())")

# Required environment variables
FLASK_ENV=production
SENTRIKAT_ENV=production
SESSION_COOKIE_SECURE=true   # if using HTTPS
FORCE_HTTPS=true             # if SSL enabled

# Database: use strong password, TLS, non-default port
DATABASE_URL=postgresql://sentrikat:STRONG_PASSWORD@db:5432/sentrikat

# Verify PostgreSQL max_connections formula:
# max_connections >= GUNICORN_WORKERS * (DB_POOL_SIZE + DB_POOL_MAX_OVERFLOW) + 10
```

## 1.2 Dependency Audit

All 21 packages reviewed - **no known CVEs** in current versions:

| Package | Version | License | Status |
|---------|---------|---------|--------|
| Flask | 3.0.0 | BSD-3 | Current |
| Flask-SQLAlchemy | 3.1.1 | BSD-3 | Current |
| Flask-Migrate | 4.0.5 | MIT | Current |
| Flask-WTF | 1.2.1 | BSD-3 | Current |
| Flask-Limiter | 3.5.0 | MIT | Current |
| Flask-Talisman | 1.1.0 | Apache-2 | Current |
| APScheduler | 3.10.4 | MIT | Current |
| requests | 2.32.4 | Apache-2 | Current |
| gunicorn | 22.0.0 | MIT | Current |
| cryptography | 46.0.5 | Apache-2/BSD | Current |
| ldap3 | 2.9.1 | **LGPL v3** | Review needed |
| psycopg2-binary | 2.9.9 | **LGPL v3** | Review needed |
| reportlab | 4.0.7 | BSD-3 | Current |
| python3-saml | 1.16.0 | MIT | Current |
| Pillow | 12.1.1 | HPND | Current |
| PyYAML | 6.0.1 | MIT | Current |
| email-validator | 2.1.0 | CC0 | Current |
| python-dotenv | 1.0.0 | BSD-3 | Current |
| qrcode | 7.4.2 | BSD | Current |
| pytest | 7.4.3 | MIT | Dev only |
| pytest-cov | 4.1.0 | MIT | Dev only |

## 1.3 Code Quality

- **No hardcoded secrets** found
- **No dead code** of concern
- **Logging**: Generally good, some inconsistency (module-level vs root logger)
- **Database patterns**: Using legacy `query.get()` instead of `db.session.get()` (cosmetic)
- **Error handling**: Mostly good except bare `except:` clauses noted above

---

# 2. SAAS MIGRATION - IS IT DOABLE?

## Short Answer: YES, absolutely. Your codebase is already 70% SaaS-ready.

Here's why - SentriKat already has:

| SaaS Requirement | Already Built? | Where in Code |
|-----------------|---------------|---------------|
| Multi-tenancy (data isolation) | YES | `organization_id` on ALL tables, CASCADE deletes |
| Per-tenant configuration | YES | Organization model stores SMTP, webhooks, alerts per-org |
| Role-based access control | YES | super_admin, org_admin, manager, user roles |
| Users in multiple orgs | YES | UserOrganization junction table |
| API key authentication | YES | AgentApiKey with SHA256 hashing, IP whitelisting |
| License/feature gating | YES | RSA-4096 signed licenses, `@requires_professional` decorator |
| Usage tracking | YES | AgentLicense tracks current_agents, peak_agents per org |
| Encryption of secrets | YES | Fernet encryption for passwords, tokens, keys |
| Rate limiting | YES | Per-endpoint and per-API-key limits |
| Docker containerization | YES | 3-service compose: app + postgres + nginx |
| Background job processing | YES | ThreadPoolExecutor with retry logic |
| Comprehensive API | YES | Full REST API for all operations |

### What's MISSING for SaaS (the 30%):

| Requirement | Current State | What to Build |
|-------------|--------------|---------------|
| Self-serve signup | Manual org creation via admin | Signup page + auto-provisioning API |
| Billing/payments | None | Stripe integration |
| Per-tenant quotas | License-based limits only | Org-level agent/storage/API quotas |
| Tenant provisioning | Manual | Automated org + admin user + API key creation |
| External task queue | In-process ThreadPoolExecutor | Celery + Redis for 1000+ tenants |
| Row-level DB security | Application-level filtering only | PostgreSQL RLS policies |
| Horizontal scaling | Single instance | Load balancer + multiple app instances |
| Usage metering | Basic agent counting | Detailed API calls, storage, agents metering |
| Admin dashboard | Super admin in app | Separate SaaS admin panel |
| Tenant isolation (compute) | Shared everything | Optional dedicated instances for enterprise |

---

# 3. CLOUD PROVIDER GUIDE FOR BEGINNERS

## "I have zero cloud knowledge" - Here's what you need to know

### 3.1 What IS "the cloud"?

Think of it like this:
- **Right now**: You run SentriKat on a Docker on YOUR computer/server
- **Cloud**: You run SentriKat on SOMEONE ELSE'S computer/server, which they manage
- **SaaS**: Your CUSTOMERS access SentriKat on YOUR cloud infrastructure

That's it. Cloud = renting computers, storage, and networking from a provider.

### 3.2 Which Cloud Provider?

There are 3 major providers. Here's my honest recommendation:

| Provider | Best For | Complexity | Cost | Recommendation |
|----------|----------|-----------|------|----------------|
| **AWS** | Everything, most services | HIGH | Medium | Not for beginners |
| **Google Cloud (GCP)** | Data/ML, good UI | MEDIUM | Medium | Good option |
| **DigitalOcean** | Simple apps, startups | LOW | LOW | **START HERE** |
| **Hetzner** | EU-based, cheapest | LOW | VERY LOW | **Best value** |
| **Azure** | Enterprise/Windows | HIGH | High | Overkill for now |

**My recommendation: Start with DigitalOcean or Hetzner, graduate to AWS/GCP later.**

Why? Because:
- DigitalOcean/Hetzner have simple UIs, you won't get lost
- Their managed databases "just work"
- Pricing is predictable (no surprise bills)
- You can migrate to AWS later when you have 100+ customers

### 3.3 What Services Do You Need?

Here's the mapping from "your Docker setup" to "cloud services":

```
YOUR DOCKER SETUP              →  CLOUD EQUIVALENT
─────────────────────────────────────────────────────
PostgreSQL container            →  Managed Database (they handle backups, updates)
SentriKat Flask app container   →  App Platform / Kubernetes / VM
Nginx container                 →  Load Balancer (included with App Platform)
Docker volumes (data)           →  Object Storage (S3/Spaces) for files
.env file                       →  Secret Manager / Environment variables
Your computer                   →  Virtual Machines (Droplets/Instances)
```

### 3.4 Architecture Options (Simplest to Most Complex)

#### Option A: "Just Put My Docker in the Cloud" (Easiest - Start Here)

```
                    ┌─────────────────────────┐
                    │   DigitalOcean / Hetzner │
                    │                          │
  Customers ──────→ │  ┌──────────────────┐    │
                    │  │ VM ($20-40/month) │    │
                    │  │                   │    │
                    │  │ docker-compose up │    │
                    │  │ (same as now!)    │    │
                    │  └──────────────────┘    │
                    │                          │
                    │  ┌──────────────────┐    │
                    │  │ Managed PostgreSQL│    │
                    │  │ ($15/month)       │    │
                    │  └──────────────────┘    │
                    └─────────────────────────┘
```

**How to do this:**
1. Create account on DigitalOcean
2. Create a Droplet (VM) - $20/month for 4GB RAM
3. Create a Managed Database (PostgreSQL) - $15/month
4. SSH into Droplet, install Docker, run `docker-compose up`
5. Point your domain to the Droplet's IP address
6. Done! Same as running locally, but now it's online

**Total cost: ~$35-55/month** to start

**Pros:** Simple, you already know Docker
**Cons:** Doesn't auto-scale, single point of failure

#### Option B: "App Platform" (Easy + Auto-managed)

```
                    ┌─────────────────────────────┐
                    │   DigitalOcean App Platform  │
                    │                              │
  Customers ──────→ │  ┌────────────────────────┐  │
                    │  │ Auto Load Balancer      │  │
                    │  └─────────┬──────────────┘  │
                    │            │                  │
                    │  ┌────────▼────────┐         │
                    │  │ SentriKat App    │         │
                    │  │ (auto-deployed   │         │
                    │  │  from GitHub)    │         │
                    │  └────────┬────────┘         │
                    │           │                   │
                    │  ┌───────▼─────────┐         │
                    │  │ Managed Database │         │
                    │  └─────────────────┘         │
                    └─────────────────────────────┘
```

**How to do this:**
1. Push your code to GitHub
2. Connect DigitalOcean App Platform to your repo
3. It auto-builds your Docker, deploys it, gives you HTTPS
4. Add a managed database
5. Set environment variables in the dashboard
6. Done! Auto-deploys when you push to GitHub

**Total cost: ~$30-70/month** depending on size

**Pros:** Zero DevOps, auto-HTTPS, auto-deploy from git
**Cons:** Less control, slightly more expensive

#### Option C: "Proper SaaS" (Medium complexity - Target for 50+ customers)

```
                    ┌───────────────────────────────────────┐
                    │            AWS / GCP                   │
                    │                                        │
  Customers ──────→ │  ┌──────────────────────────────────┐  │
                    │  │ CloudFlare (CDN + DDoS + SSL)     │  │
                    │  └──────────────┬───────────────────┘  │
                    │                 │                       │
                    │  ┌──────────────▼───────────────────┐  │
                    │  │ Load Balancer (ALB)               │  │
                    │  └────────┬──────────────┬──────────┘  │
                    │           │              │              │
                    │  ┌───────▼──────┐ ┌────▼─────────┐   │
                    │  │ App Instance 1│ │App Instance 2│   │
                    │  │ (SentriKat)  │ │(SentriKat)   │   │
                    │  └───────┬──────┘ └────┬─────────┘   │
                    │          │              │              │
                    │  ┌───────▼──────────────▼──────────┐  │
                    │  │ Managed PostgreSQL (RDS/Cloud SQL)│  │
                    │  │ + Read Replicas                   │  │
                    │  └──────────────┬───────────────────┘  │
                    │                 │                       │
                    │  ┌──────────────▼───────────────────┐  │
                    │  │ Redis (ElastiCache / Memorystore) │  │
                    │  │ (for Celery task queue + caching) │  │
                    │  └──────────────────────────────────┘  │
                    │                                        │
                    │  ┌──────────────────────────────────┐  │
                    │  │ S3 / Cloud Storage (file storage) │  │
                    │  └──────────────────────────────────┘  │
                    └───────────────────────────────────────┘
```

**Total cost: ~$150-500/month** depending on usage

**Pros:** Scales to 10,000+ customers, redundant, professional
**Cons:** Needs DevOps knowledge or hiring someone

### 3.5 Concrete Setup Guide - DigitalOcean (Step by Step)

Here's exactly what to do if you choose DigitalOcean:

```
STEP 1: Create Account
  → go to digitalocean.com
  → sign up (they give $200 free credit for 60 days)

STEP 2: Create Managed Database
  → Dashboard → Databases → Create Database Cluster
  → Engine: PostgreSQL 15
  → Plan: Basic ($15/mo for 1GB RAM, 10GB storage)
  → Datacenter: Choose closest to your customers
  → Name: sentrikat-db
  → Click Create
  → SAVE the connection string (looks like:
    postgresql://user:password@host:25060/defaultdb?sslmode=require)

STEP 3: Create a Droplet (VM)
  → Dashboard → Droplets → Create Droplet
  → Image: Ubuntu 22.04 LTS
  → Plan: Basic $24/mo (4GB RAM, 2 vCPUs, 80GB SSD)
  → Add SSH key (or use password)
  → Name: sentrikat-app
  → Click Create

STEP 4: Set Up the Droplet
  → SSH in: ssh root@YOUR_DROPLET_IP
  → Run these commands:

  # Install Docker
  curl -fsSL https://get.docker.com -o get-docker.sh
  sh get-docker.sh

  # Install docker-compose
  apt install docker-compose-plugin

  # Clone your repo (or upload your files)
  git clone YOUR_REPO_URL /opt/sentrikat
  cd /opt/sentrikat

  # Create .env file
  cp .env.example .env
  nano .env
  # Set DATABASE_URL to the connection string from Step 2
  # Set SECRET_KEY, ENCRYPTION_KEY (generate them)
  # Remove the PostgreSQL service from docker-compose.yml
  # (because you're using the managed database now!)

  # Start SentriKat (without the db service)
  docker compose up -d sentrikat nginx

STEP 5: Point Your Domain
  → Go to your domain registrar (GoDaddy, Namecheap, Cloudflare, etc.)
  → Add A record: sentrikat.yourdomain.com → YOUR_DROPLET_IP
  → Enable Cloudflare proxy for free SSL + DDoS protection

STEP 6: Done!
  → Visit https://sentrikat.yourdomain.com
  → Run the setup wizard
  → Create organizations for your customers
```

### 3.6 Database: Move It OUT of Docker

You asked about this specifically. **YES, absolutely move the database out of Docker.** Here's why and how:

**Why move the database out?**
```
CURRENT (database inside Docker):
  ✗ If Docker crashes, you lose data
  ✗ No automatic backups
  ✗ No automatic failover
  ✗ YOU manage PostgreSQL updates/security patches
  ✗ Performance limited to single container

MANAGED DATABASE (cloud):
  ✓ Automatic daily backups (point-in-time recovery)
  ✓ Automatic failover (if primary dies, standby takes over)
  ✓ Provider handles security patches
  ✓ Can scale storage/CPU independently
  ✓ Accessible from multiple app instances
  ✓ SSL/TLS encryption in transit by default
```

**How to migrate:**

```bash
# 1. Export data from your Docker PostgreSQL
docker exec sentrikat-db-1 pg_dump -U sentrikat sentrikat > backup.sql

# 2. Import into managed database
psql "postgresql://user:password@managed-host:25060/defaultdb?sslmode=require" < backup.sql

# 3. Update .env
DATABASE_URL=postgresql://user:password@managed-host:25060/defaultdb?sslmode=require

# 4. Remove db service from docker-compose.yml
# Just comment out or remove the 'db:' section

# 5. Restart app
docker compose up -d sentrikat nginx

# That's it! Your app now uses the managed database.
```

**Cost comparison:**
| Option | Monthly Cost | Backups | Failover | You Manage |
|--------|-------------|---------|----------|-----------|
| Docker PostgreSQL | $0 (part of VM) | Manual | None | Everything |
| DigitalOcean Managed DB | $15-30 | Automatic | Optional ($30+) | Nothing |
| AWS RDS | $30-100 | Automatic | Yes ($60+) | Little |
| Hetzner + manual PG | $5-10 | Manual | Manual | Most things |

### 3.7 How Customers Get Their Instance (Auto-Provisioning)

This is the key SaaS question. There are two models:

#### Model 1: SHARED INSTANCE (Recommended to start)

All customers share ONE SentriKat installation. They're isolated by `organization_id`.

```
Customer signs up → API creates Organization → Creates admin user →
Creates API key → Sends welcome email with credentials

THIS IS ALREADY MOSTLY BUILT! SentriKat already supports multi-org!
```

**What you need to add:**
1. A signup page/form
2. An API endpoint that automatically:
   - Creates an Organization
   - Creates an admin User for that org
   - Generates an Agent API Key
   - Sends welcome email
3. Billing integration (Stripe)

**Pros:** Simple, cheap (one server for all), easy to maintain
**Cons:** "Noisy neighbor" risk (one heavy customer affects all)

#### Model 2: DEDICATED INSTANCE (For enterprise customers later)

Each customer gets their OWN isolated SentriKat container + database.

```
Customer signs up → System provisions:
  1. New PostgreSQL database (or schema)
  2. New Docker container for SentriKat
  3. Unique subdomain (customer1.sentrikat.com)
  4. Sends credentials
```

**What you'd need:**
1. Orchestration tool (Kubernetes, Docker Swarm, or Terraform)
2. Wildcard SSL certificate (*.sentrikat.com)
3. Automated provisioning scripts
4. Per-tenant monitoring
5. Billing per-instance

**Pros:** Full isolation, can offer different SLAs
**Cons:** Much more complex, much more expensive

**My recommendation:** Start with Model 1 (shared). Add Model 2 as a premium tier later.

---

# 4. WHAT CHANGES FOR SAAS ARCHITECTURE

## 4.1 Database Changes

### Current → SaaS Architecture

```
CURRENT (per-installation):
┌─────────────────────────┐
│ Docker PostgreSQL        │
│ └── sentrikat database  │
│     └── all tables      │
└─────────────────────────┘

SAAS OPTION A - Shared Database (RECOMMENDED):
┌──────────────────────────────────┐
│ Managed PostgreSQL               │
│ └── sentrikat database           │
│     ├── organizations table      │  ← Tenant registry
│     ├── products table           │  ← org_id filtered (ALREADY DONE)
│     ├── assets table             │  ← org_id filtered (ALREADY DONE)
│     ├── vulnerabilities table    │  ← SHARED across all orgs (efficient!)
│     └── ...all other tables      │  ← org_id filtered (ALREADY DONE)
│                                  │
│     + Row Level Security (RLS)   │  ← ADD THIS for defense-in-depth
│     + Connection pooling (PgBouncer) ← ADD THIS for 1000+ connections
└──────────────────────────────────┘

SAAS OPTION B - Schema-per-tenant:
┌──────────────────────────────────┐
│ Managed PostgreSQL               │
│ ├── schema: tenant_abc123       │  ← Isolated
│ │   └── all tables              │
│ ├── schema: tenant_def456       │  ← Isolated
│ │   └── all tables              │
│ └── schema: shared              │  ← Vulnerabilities, CVE data
│     └── vulnerability tables    │
└──────────────────────────────────┘
```

**Recommendation:** Option A (shared database with org_id). You already have this! Just add:
1. PostgreSQL Row-Level Security (RLS) as safety net
2. PgBouncer connection pooler for many concurrent tenants
3. Read replicas for reporting queries

### Row-Level Security Example (add to migrations):

```sql
-- This makes it IMPOSSIBLE for a bug to leak data across orgs
ALTER TABLE products ENABLE ROW LEVEL SECURITY;

CREATE POLICY products_org_isolation ON products
  USING (organization_id = current_setting('app.current_org_id')::integer);

-- Your app sets this per-request:
-- SET LOCAL app.current_org_id = '42';
```

## 4.2 Background Jobs → External Queue

### Current: In-Process Threading

```python
# Current: ThreadPoolExecutor inside Flask (app/inventory_worker.py)
# Works fine for 1 instance, breaks with multiple instances
executor = ThreadPoolExecutor(max_workers=WORKER_POOL_SIZE)
```

### SaaS: Celery + Redis

```
┌─────────────┐    ┌─────────┐    ┌──────────────┐
│ Flask App    │───→│ Redis   │───→│ Celery Worker │
│ (publishes)  │    │ (queue) │    │ (processes)   │
└─────────────┘    └─────────┘    └──────────────┘
```

**Why change?**
- Multiple app instances can share one job queue
- Jobs survive app restarts
- Can scale workers independently
- Better monitoring (Flower dashboard)

**When to change:** When you have 50+ organizations or 1000+ agents

**What changes in code:**
- `inventory_worker.py` → Celery tasks
- `email_alerts.py` → Celery tasks (async email sending)
- `cisa_sync.py` → Celery beat schedule
- APScheduler → Celery Beat (periodic tasks)

## 4.3 File Storage → Object Storage

### Current: Docker Volume

```python
# Current: files stored in /app/data/uploads/
UPLOAD_FOLDER = os.path.join(DATA_DIR, 'uploads')
```

### SaaS: S3-Compatible Object Storage

```python
# SaaS: files stored in cloud object storage
import boto3  # works with AWS S3, DigitalOcean Spaces, MinIO

s3 = boto3.client('s3',
    endpoint_url='https://nyc3.digitaloceanspaces.com',  # or AWS S3
    aws_access_key_id='...',
    aws_secret_access_key='...'
)

# Upload: s3.upload_fileobj(file, 'sentrikat-uploads', f'org_{org_id}/logo.png')
# Download: s3.download_fileobj('sentrikat-uploads', key, file)
```

**Why change?**
- Files shared across multiple app instances
- Unlimited storage
- Built-in CDN
- Per-org storage isolation by key prefix

**Cost:** DigitalOcean Spaces: $5/month for 250GB + CDN

## 4.4 Configuration → Feature Flags / Plans

### Current: License file + environment variables

### SaaS: Subscription plans stored in database

```
FREE PLAN:          5 agents,  1 org,   50 products, community features
PROFESSIONAL:      50 agents,  3 orgs, unlimited products, + LDAP, alerts
ENTERPRISE:       500 agents, unlimited orgs, unlimited products, + SSO, API, white-label
CUSTOM:          negotiated limits
```

**What to build:**
1. `SubscriptionPlan` model (name, limits, features, price)
2. `Subscription` model (org_id, plan_id, status, stripe_id, started_at, expires_at)
3. Modify `check_agent_limit()` to read from Subscription instead of license file
4. Stripe webhook handler for payment events
5. Upgrade/downgrade flow in UI

## 4.5 API Changes for SaaS

### New endpoints needed:

```
POST /api/signup              → Create org + admin user + trial
POST /api/billing/subscribe   → Start paid subscription
POST /api/billing/webhook     → Stripe webhook handler
GET  /api/billing/usage       → Current usage metrics
GET  /api/billing/invoices    → Invoice history
POST /api/billing/portal      → Redirect to Stripe customer portal

GET  /api/saas/health         → SaaS-level health (all tenants)
GET  /api/saas/metrics        → Usage across all tenants (admin only)
POST /api/saas/provision      → Auto-provision new tenant (internal)
```

### Existing endpoints - NO CHANGES NEEDED:

All current API endpoints already filter by `organization_id`. The agent API already uses API keys. These work as-is for SaaS.

## 4.6 Functions That Change for SaaS

Here's a concrete list of what changes and what stays:

### NO CHANGES (Works as-is):

| File | Function/Module | Why it works |
|------|----------------|--------------|
| `agent_api.py` | All agent endpoints | Already uses API key auth + org_id |
| `models.py` | All models | Already have organization_id FK |
| `auth.py` | Login/logout/2FA | Session-based, org-aware |
| `encryption.py` | Encrypt/decrypt | Stateless, key from env |
| `vulnerability matching` | CPE matching logic | Shared vulnerability DB is ideal |
| `cisa_sync.py` | KEV feed sync | Shared across all orgs (efficient) |
| `email_alerts.py` | Alert logic | Already per-org SMTP settings |

### NEEDS MODIFICATION:

| File | What Changes | Why |
|------|-------------|-----|
| `inventory_worker.py` | Move to Celery tasks | Multi-instance scaling |
| `__init__.py` (scheduler) | APScheduler → Celery Beat | Shared schedule across instances |
| `routes.py` (file uploads) | Local disk → S3/Spaces | Shared storage across instances |
| `config.py` | Add plan/billing config | Subscription-based limits |
| `models.py` | Add Subscription, Plan models | Billing support |
| `settings_api.py` | Add billing endpoints | Customer self-service |
| `docker-compose.yml` | Add Redis service | For Celery + caching |

### NEW CODE NEEDED:

| Component | Purpose | Complexity |
|-----------|---------|-----------|
| `billing.py` | Stripe integration | Medium |
| `provisioning.py` | Auto-create org/user/key | Low |
| `signup.py` / signup UI | Self-serve registration | Low |
| `usage_metering.py` | Track API calls, agents, storage | Medium |
| `saas_admin.py` | SaaS operator dashboard | Medium |
| `health_monitoring.py` | Per-tenant health checks | Low |
| Celery worker config | Task queue setup | Low-Medium |

---

# 5. MOBILE & DEVICE AGENT SUPPORT

## 5.1 Current Agent Architecture

The current agent API is **protocol-agnostic** - it's a simple REST API that accepts JSON:

```
Agent → POST /api/agent/inventory
Header: X-Agent-Key: <api-key>
Body: {
    "hostname": "my-device",
    "ip_address": "192.168.1.50",
    "os_name": "Ubuntu",
    "os_version": "22.04",
    "agent_version": "1.0",
    "asset_type": "server",          ← Can be anything!
    "products": [
        {
            "vendor": "Apache",
            "product_name": "httpd",
            "version": "2.4.52",
            "source_type": "os_package"  ← Can be extended!
        }
    ]
}
```

This means **ANY device that can make an HTTP POST request can be an agent!**

## 5.2 Mobile Agents (Android / iOS)

### Feasibility: VERY DOABLE

**Android Agent:**
- Can list installed apps via `PackageManager.getInstalledPackages()`
- Gets: app name, package name, version, install date
- Sends via standard HTTP to SentriKat API
- Can run as background service with periodic inventory

**iOS Agent:**
- **Limited**: iOS doesn't allow listing other apps (sandbox)
- **MDM route**: If enrolled in MDM (Jamf, Intune), MDM can push inventory
- **Partial**: Can report device info (iOS version, model, jailbreak status)

**What to change in SentriKat:**

```python
# Add new asset_type values
ASSET_TYPES = [
    'server', 'workstation',           # existing
    'mobile_android', 'mobile_ios',    # NEW
    'tablet', 'chromebook',            # NEW
    'iot', 'network_device',           # NEW
    'container', 'virtual_machine'     # NEW
]

# Add new source_type values
SOURCE_TYPES = [
    'os_package', 'extension', 'code_library',  # existing
    'mobile_app', 'mobile_system',                # NEW - mobile apps
    'firmware', 'network_os',                     # NEW - IoT/network
    'browser_extension',                          # NEW - browser
    'container_image'                             # NEW - containers
]
```

**Android Agent (Kotlin concept):**

```kotlin
// This is all it takes - the API is already compatible!
class SentriKatAgent(private val apiKey: String, private val serverUrl: String) {

    fun submitInventory() {
        val apps = packageManager.getInstalledPackages(0).map { pkg ->
            mapOf(
                "vendor" to (pkg.applicationInfo?.packageName?.split(".")?.take(2)?.joinToString(".") ?: "unknown"),
                "product_name" to (pkg.applicationInfo?.loadLabel(packageManager)?.toString() ?: pkg.packageName),
                "version" to (pkg.versionName ?: "unknown"),
                "source_type" to "mobile_app"
            )
        }

        val body = mapOf(
            "hostname" to Build.MODEL,
            "os_name" to "Android",
            "os_version" to Build.VERSION.RELEASE,
            "asset_type" to "mobile_android",
            "products" to apps
        )

        // POST to /api/agent/inventory with X-Agent-Key header
        // THE EXISTING API HANDLES THIS AS-IS!
    }
}
```

## 5.3 IoT / Network Devices

### Feasibility: DOABLE with agent-per-type approach

| Device Type | How to Collect Inventory | Agent Approach |
|-------------|------------------------|----------------|
| **Routers/Switches** (Cisco, Juniper) | SSH/SNMP → `show version` | Server-side agent scans network |
| **Firewalls** (Palo Alto, Fortinet) | API calls to firewall | Server-side agent |
| **Printers/IoT** | SNMP discovery | Server-side agent |
| **Smart TVs / Displays** | SNMP / UPnP | Server-side agent |
| **Embedded Linux** | Install lightweight agent | Direct agent (like current) |
| **Docker containers** | `docker inspect` | Server-side agent |
| **Kubernetes** | k8s API → list images | Server-side agent |

**Key insight:** You don't need an agent ON each device. A "network scanner agent" running on a server can inventory network devices via SNMP/SSH and submit to SentriKat.

```
Network Scanner Agent Architecture:

┌──────────────┐     SNMP/SSH      ┌─────────────────┐
│ SentriKat    │←── inventory ────│ Scanner Agent    │
│ Server       │    via API        │ (runs on server) │
└──────────────┘                   └────────┬────────┘
                                            │ scans
                                   ┌────────▼────────┐
                                   │ Network Devices  │
                                   │ Routers, Switches│
                                   │ Firewalls, IoT   │
                                   └─────────────────┘
```

## 5.4 Browser Extension Agent

### Feasibility: VERY DOABLE

A Chrome/Firefox/Edge extension could:
- List installed browser extensions + versions
- Report browser version
- Detect vulnerable browser plugins
- Report to SentriKat via API

```javascript
// Chrome Extension - background.js
chrome.management.getAll(function(extensions) {
    const inventory = extensions.map(ext => ({
        vendor: ext.id,
        product_name: ext.name,
        version: ext.version,
        source_type: 'browser_extension'
    }));

    fetch(SENTRIKAT_URL + '/api/agent/inventory', {
        method: 'POST',
        headers: {
            'X-Agent-Key': API_KEY,
            'Content-Type': 'application/json'
        },
        body: JSON.stringify({
            hostname: navigator.userAgent,
            os_name: navigator.platform,
            asset_type: 'workstation',
            products: inventory
        })
    });
});
```

## 5.5 Summary: Agent Roadmap

| Priority | Agent Type | Effort | Value |
|----------|-----------|--------|-------|
| 1 (NOW) | Windows/Linux/macOS agent | EXISTS | Core product |
| 2 (SOON) | Android mobile agent | 2-3 weeks | High (BYOD tracking) |
| 3 (SOON) | Browser extension agent | 1-2 weeks | High (extension vulns) |
| 4 (MEDIUM) | Network scanner (SNMP/SSH) | 3-4 weeks | High (infrastructure) |
| 5 (LATER) | iOS (via MDM integration) | 4-6 weeks | Medium (Apple restrictions) |
| 6 (LATER) | Container/K8s scanner | 2-3 weeks | High (cloud-native) |
| 7 (FUTURE) | IoT/embedded agent | Variable | Niche |

---

# 6. COST ESTIMATES

## 6.1 SaaS Infrastructure Costs (Monthly)

### Tier 1: Startup (1-50 customers, <500 agents)

| Service | Provider | Cost/month |
|---------|----------|-----------|
| VM (4GB RAM, 2 vCPU) | DigitalOcean | $24 |
| Managed PostgreSQL (1GB) | DigitalOcean | $15 |
| Object Storage (250GB) | DigitalOcean Spaces | $5 |
| Domain + DNS | Cloudflare | Free |
| SSL Certificate | Cloudflare/Let's Encrypt | Free |
| Email (transactional) | Mailgun/Resend | Free tier |
| Monitoring | UptimeRobot | Free |
| **TOTAL** | | **~$44/month** |

### Tier 2: Growth (50-500 customers, 500-5000 agents)

| Service | Provider | Cost/month |
|---------|----------|-----------|
| VM x2 (8GB RAM each) | DigitalOcean | $96 |
| Load Balancer | DigitalOcean | $12 |
| Managed PostgreSQL (4GB) | DigitalOcean | $60 |
| Redis (managed) | DigitalOcean | $15 |
| Object Storage | DigitalOcean Spaces | $5 |
| Email (transactional) | Mailgun | $35 |
| Monitoring | Datadog/Grafana | $30 |
| Backups + DR | DigitalOcean | $20 |
| **TOTAL** | | **~$273/month** |

### Tier 3: Scale (500+ customers, 5000+ agents)

| Service | Provider | Cost/month |
|---------|----------|-----------|
| Kubernetes cluster | AWS EKS / GCP GKE | $200-400 |
| Managed PostgreSQL (HA) | AWS RDS / GCP Cloud SQL | $200-400 |
| Redis cluster | AWS ElastiCache | $50-100 |
| Object Storage | AWS S3 | $10-30 |
| CDN | CloudFront/Cloudflare | $20-50 |
| Email | AWS SES | $10-50 |
| Monitoring | Datadog | $100-300 |
| WAF + DDoS | Cloudflare Pro | $20-200 |
| **TOTAL** | | **~$600-1500/month** |

## 6.2 Revenue Model Suggestion

| Plan | Price/month | Includes | Target |
|------|------------|----------|--------|
| Free | $0 | 5 agents, 1 org, community features | Try-before-buy |
| Pro | $49-99 | 50 agents, LDAP, alerts, webhooks | Small business |
| Business | $199-399 | 250 agents, SSO, API, white-label | Mid-market |
| Enterprise | $999+ | Unlimited, dedicated instance, SLA | Large companies |

**Break-even example:**
- Infrastructure: $273/month (Tier 2)
- 10 Pro customers at $99 = $990/month
- **Profit: $717/month with just 10 customers**

---

# 7. STEP-BY-STEP MIGRATION ROADMAP

## Phase 1: Quick Wins (Week 1-2) - "Cloud-Ready"

```
□ Move PostgreSQL to managed database (DigitalOcean/Hetzner)
□ Deploy Docker on cloud VM
□ Set up domain + SSL (Cloudflare)
□ Set up automated backups
□ Fix audit findings (bare except, file upload validation)
□ Add LICENSE file
```

**Result:** SentriKat runs in the cloud, accessible via HTTPS. Still single-tenant-per-instance.

## Phase 2: Multi-Tenant SaaS (Week 3-6) - "SaaS MVP"

```
□ Add self-serve signup endpoint (POST /api/signup)
□ Build auto-provisioning (create org → user → API key → welcome email)
□ Add Stripe billing integration (subscribe, webhook, portal)
□ Add subscription plans to database (Free, Pro, Business)
□ Modify license checks to use Subscription model
□ Add usage metering (agents count, API calls)
□ Add per-org quotas and enforcement
□ Build simple landing page with pricing
```

**Result:** Customers can sign up, pay, and use SentriKat. You have a SaaS!

## Phase 3: Scale (Week 7-12) - "Production SaaS"

```
□ Add Redis for caching + session store
□ Migrate background jobs to Celery + Redis
□ Move file storage to S3/Spaces
□ Add PgBouncer for connection pooling
□ Set up 2+ app instances behind load balancer
□ Add PostgreSQL Row-Level Security
□ Set up monitoring (Grafana/Datadog)
□ Set up log aggregation
□ Add SaaS admin dashboard
□ Security hardening pass
```

**Result:** Scalable, monitored, production-grade SaaS.

## Phase 4: Growth Features (Month 3-6)

```
□ Android mobile agent
□ Browser extension agent
□ Network scanner agent (SNMP/SSH)
□ Kubernetes/container scanning
□ Enhanced reporting/compliance
□ API documentation (Swagger/OpenAPI)
□ Customer onboarding wizard
□ White-label enhancements
□ SOC 2 Type I preparation
```

**Result:** Competitive SaaS product with multi-platform agent support.

---

# APPENDIX A: Quick Reference - Provider Comparison

| Feature | DigitalOcean | Hetzner | AWS | GCP |
|---------|-------------|---------|-----|-----|
| **Beginner-friendly** | Very | Yes | No | Medium |
| **Cheapest VM** | $4/mo | $3.29/mo | $8/mo | $6/mo |
| **Managed PostgreSQL** | $15/mo | No | $30/mo | $25/mo |
| **Managed Redis** | $15/mo | No | $15/mo | $10/mo |
| **Object Storage** | $5/mo (250GB) | $5/mo (unlimited egress) | Pay per use | Pay per use |
| **Load Balancer** | $12/mo | $6/mo | $18/mo | $18/mo |
| **Free SSL** | Yes | Yes | Yes | Yes |
| **App Platform** | Yes ($12+/mo) | No | Yes (Elastic Beanstalk) | Yes (Cloud Run) |
| **Kubernetes** | $12/mo + nodes | $0 control plane | $72/mo + nodes | $72/mo + nodes |
| **EU Data Centers** | Amsterdam, Frankfurt | Falkenstein, Helsinki, Nuremberg | Frankfurt, Ireland | Belgium, Netherlands |
| **US Data Centers** | NYC, SFO | Ashburn (VA) | 20+ regions | 10+ regions |
| **Surprise bills risk** | LOW | VERY LOW | HIGH | MEDIUM |
| **Support** | Good | Basic (cheap) | Pay extra | Pay extra |

# APPENDIX B: SentriKat Architecture - Current vs SaaS

```
CURRENT (Single-Instance):
┌─────────────────────────────────────────┐
│ Customer's Server / VM                  │
│                                         │
│ ┌─────────┐  ┌──────────┐  ┌────────┐ │
│ │ Nginx   │→ │ Flask    │→ │ PgSQL  │ │
│ │ :80/443 │  │ :5000    │  │ :5432  │ │
│ └─────────┘  └──────────┘  └────────┘ │
│       All inside Docker Compose        │
└─────────────────────────────────────────┘
        ↑               ↑
   Web Users        Agents (servers/workstations)


SAAS (Multi-Tenant):
┌──────────────────────────────────────────────────────────┐
│ Cloud (DigitalOcean / AWS / GCP)                         │
│                                                          │
│ ┌──────────┐   ┌────────────────────┐   ┌────────────┐ │
│ │Cloudflare│──→│ Load Balancer      │   │ Managed    │ │
│ │CDN + WAF │   └────┬──────────┬────┘   │ PostgreSQL │ │
│ └──────────┘        │          │         │ (shared)   │ │
│                ┌────▼───┐ ┌───▼────┐    └─────┬──────┘ │
│                │Flask #1│ │Flask #2│          │        │
│                │        │ │        │──────────┘        │
│                └───┬────┘ └───┬────┘                    │
│                    │          │                          │
│               ┌────▼──────────▼────┐   ┌─────────────┐ │
│               │   Redis            │   │ S3 / Spaces │ │
│               │ (cache + queues)   │   │ (files)     │ │
│               └────────────────────┘   └─────────────┘ │
└──────────────────────────────────────────────────────────┘
        ↑                    ↑                ↑
   Web Users (all orgs)   Agents (all orgs)  Mobile Agents
   via browser            via API key         via API key
```

---

**Document generated:** 2026-02-18
**Codebase analyzed:** SentriKat (all source files, configs, tests, Docker setup)
**Conclusion:** SentriKat is well-built, security-solid, and has excellent SaaS foundations. The migration is very achievable following this roadmap.
