# SentriKat - Technical Customer Review

**Date:** February 2026
**Reviewer Persona:** New technical customer evaluating SentriKat for enterprise deployment
**Scope:** Website presence, documentation, deployment, code quality, security, missing features

---

## EXECUTIVE SUMMARY

SentriKat is a technically solid vulnerability management platform with 35K+ lines of well-structured Python code, 80+ API endpoints, and an intelligent CISA KEV-focused matching engine. However, it is **not commercially ready**: the website returns 403, legal documents contain placeholders, there is no registered business entity, and a development license backdoor exists in the public codebase.

**Rating: 6/10 overall - strong technical foundation, critical commercial gaps.**

---

## PHASE 1: WEBSITE & ONLINE PRESENCE

### All Domains Return 403

| URL | Status | Expected |
|-----|--------|----------|
| sentrikat.com | 403 Forbidden | Landing page with features, pricing, CTA |
| www.sentrikat.com | 403 Forbidden | Redirect to sentrikat.com |
| portal.sentrikat.com | 403 Forbidden | Customer portal, license management |
| docs.sentrikat.com | 403 Forbidden | Product documentation |
| demo.sentrikat.com | 403 Forbidden | Live demo instance |

**Impact:** A security product with no accessible website undermines credibility immediately. Technical customers will assume the project is abandoned or not production-ready.

### GitHub README Quality

The README.md is well-written with ASCII diagrams, feature tables, and a clear Quick Start guide. However:
- Links to docs.sentrikat.com say "Coming Soon"
- Link to sentrikat.com/pricing leads to 403
- Contact email in LICENSE.md is a personal Gmail address

---

## PHASE 2: LEGAL & BUSINESS DOCUMENTS

### Placeholder Issues

| Document | Placeholder | Location |
|----------|------------|----------|
| Privacy Policy | `[Your Jurisdiction]` | Line 215 |
| Privacy Policy | `[Your Address]` | Line 239 |
| Terms of Service | `[Jurisdiction]` | Line 261 |
| Terms of Service | `[email/address]` | Line 295 |
| Executive Summary | `[your-email]`, `[Your Name]` | Lines 9, 151 |
| Executive Summary | `$X/month`, `$Y/month`, `$Z/month` | Lines 71-74 |
| Competitive Analysis | `$X,XXX` per 100 endpoints | Lines 239-244 |

### Pricing Inconsistency

The Pricing Strategy doc (04_PRICING_STRATEGY.md) defines EUR 2,499/year for Professional, but the Executive Summary and Competitive Analysis still use `$X` placeholders.

### Business Entity: Does Not Exist

The TODO_BEFORE_LAUNCH.md (written in Italian) confirms:
- No legal entity (SRL/SRLS not yet formed)
- No P.IVA (tax ID)
- No business bank account
- No Stripe setup
- No domain registration verified
- Legal documents need lawyer review

### Special License Grant

LICENSE.md:83-106 contains a perpetual royalty-free license grant to "Zertificon Solutions GmbH" visible in the public repository. This should be a separate agreement, not embedded in the public license file.

---

## PHASE 3: DEPLOYMENT & DEMO TESTING

### Setup Experience

**What works well:**
- `.env.example` is comprehensive (164 lines with clear comments)
- `docker-compose.yml` is clean (3 services: nginx, app, postgres)
- Quick Start instructions are accurate
- Health check endpoints work (/api/health, /api/sync/status)

**Issues found:**
1. No pre-built Docker image on GHCR - users must `docker-compose build` locally
2. Default `SENTRIKAT_ENV=production` blocks the dev license key; undocumented how to test Professional features
3. `DB_PASSWORD` must be manually kept in sync with `DATABASE_URL` - error-prone
4. No `docker-compose.demo.yml` or single-command demo mode
5. Generating ENCRYPTION_KEY requires the `cryptography` Python package pre-installed
6. No docker pull shortcut (e.g., `docker run -p 80:80 ghcr.io/sbr0nch/sentrikat:demo`)

### Test Suite Results

| Result | Count | Notes |
|--------|-------|-------|
| Passed | 127 | Solid unit test coverage |
| Failed | 4 | All in test_nvd_cpe_api.py - environment issue, not code bugs |
| Errors | 83 | All from cryptography library incompatibility in sandbox |

**Test coverage gaps:**
- No end-to-end tests (agent -> matching -> alert flow)
- No CISA sync integration tests
- No performance/load tests
- No frontend/template tests
- No security-specific tests (auth bypass, privilege escalation)

---

## PHASE 4: SECURITY REVIEW

### Critical Findings

#### 1. Development License Backdoor (CRITICAL)
**File:** `app/licensing.py:668`
```python
if license_key == 'SENTRIKAT-DEV-PROFESSIONAL':
```
Hardcoded in public GitHub repo. Only guarded by `SENTRIKAT_ENV == 'production'`. Anyone reading the code can activate unlimited Professional features.

#### 2. Authentication Bypass (CRITICAL)
**File:** `app/auth.py:34`
```python
AUTH_ENABLED = True if _is_production else os.environ.get('DISABLE_AUTH', 'false').lower() != 'true'
```
Setting `DISABLE_AUTH=true` completely bypasses authentication in non-production environments.

#### 3. Inconsistent Production Detection (HIGH)
- `auth.py:26-28`: Checks `FLASK_ENV == 'production' OR SENTRIKAT_ENV == 'production'`
- `licensing.py:667`: Checks ONLY `SENTRIKAT_ENV == 'production'`

Result: With `FLASK_ENV=production` but without `SENTRIKAT_ENV`, auth works but dev license key is active.

#### 4. Hardcoded Default Secrets (HIGH)
- `config.py:22`: `SECRET_KEY = 'dev-secret-key-change-in-production'`
- `encryption.py:49`: Derives encryption key from SECRET_KEY if ENCRYPTION_KEY not set

If deployed without changing these defaults, all sensitive data (LDAP passwords, SMTP passwords, webhook tokens) is encrypted with a publicly known key.

### Good Security Practices

| Area | Implementation | Status |
|------|---------------|--------|
| SQL Injection | SQLAlchemy ORM (parameterized queries) | Good |
| XSS | Jinja2 autoescaping + escapeHtml() | Good |
| LDAP Injection | escape_filter_chars() | Good |
| Password Hashing | Werkzeug/bcrypt | Good |
| Rate Limiting | 5/min login, lockout after 5 failures | Good |
| Session Security | HttpOnly, SameSite=Lax, 4h timeout | Good |
| Security Headers | Talisman (HSTS, CSP, X-Frame-Options) | Good |
| Input Validation | Agent API size limits, sanitization | Good |

---

## PHASE 5: FEATURES MISSING (CUSTOMER WISHLIST)

### Must-Have Before Purchase

1. **Working website** with landing page, pricing, documentation
2. **Live demo instance** (demo.sentrikat.com with sample data)
3. **Registered business entity** with proper legal contacts
4. **Pre-built Docker image** on a public registry
5. **Public documentation** with searchable guides and API reference
6. **Changelog/release notes** with security advisories
7. **Remove dev backdoor** from public codebase

### Important for Evaluation

8. **Agentless scanning** - Push-only agents are limiting; passive network discovery would be valuable
9. **SBOM import** - SPDX/CycloneDX support for CI/CD pipeline integration
10. **SaaS option** - For organizations that don't want to self-host
11. **ServiceNow integration** - Critical for mid-market (currently "Roadmap")
12. **Multi-framework compliance mapping** - NIS2, DORA, ISO 27001 (not just CISA BOD 22-01)
13. **Security certification** - SOC 2 or pentest report for a security product
14. **Demo video** - 3-minute walkthrough of the complete workflow
15. **Community channel** - SLA says "Community Forum" for Demo tier, but no forum exists

### Nice-to-Have

16. **Mobile-responsive dashboard** - Current Bootstrap 5 likely responsive, but untested
17. **Terraform/Ansible deployment** - Infrastructure-as-code templates
18. **Kubernetes Helm chart** - For K8s-native organizations
19. **Splunk/SIEM integration** - Currently "Roadmap"
20. **Customer success stories** - Case studies, testimonials

---

## PHASE 6: COMPETITIVE POSITIONING ANALYSIS

### Strengths vs Competition

| Strength | Impact |
|----------|--------|
| CISA KEV-native focus | Unique differentiator vs Tenable/Qualys |
| Self-hosted with data sovereignty | Strong for EU/regulated industries |
| Push agents in PowerShell/Bash | No agent installer, no binaries, auditable |
| Vendor backport detection (3-tier) | Intelligent false-positive reduction |
| EUR 2,499/year pricing | 5-10x cheaper than Tenable/Qualys for SMB |
| Air-gapped support | Real competitive advantage for defense/govt |

### Weaknesses vs Competition

| Weakness | Impact |
|----------|--------|
| No agentless scanning | Can't discover unknown software on network |
| No active vulnerability scanning | Only matches known inventory vs KEV/NVD |
| Single developer | Bus factor = 1, no SLA credibility |
| No certifications | SOC 2, ISO 27001 expected for security tools |
| No SaaS option | Limits addressable market significantly |
| No brand awareness | Zero marketing presence, no reviews, no analyst coverage |

---

## FINAL VERDICT

### Scores by Area

| Area | Score | Notes |
|------|-------|-------|
| Vision & Market Fit | 9/10 | Excellent niche: affordable CISA KEV-focused self-hosted VM |
| Code Quality | 7/10 | Well-structured, 35K+ LOC, good patterns, some security issues |
| Testing | 6/10 | Solid unit tests, missing E2E/integration/performance |
| Documentation | 7/10 | Great README and internal docs, no public-facing docs |
| Deployment | 6/10 | Docker works but no pre-built image, no easy demo mode |
| Online Presence | 1/10 | Website doesn't exist - absolute deal-breaker |
| Business Maturity | 2/10 | No legal entity, placeholder contracts, personal email |
| Security Posture | 6/10 | Good practices overall, but dev backdoor in public code |
| **Overall** | **6/10** | **Strong product, not commercially ready** |

### Bottom Line

The technical foundation is genuinely impressive for a single-developer product. The vendor backport detection with three confidence tiers, the multi-tracker issue integration, and the CISA KEV-first approach show deep domain knowledge.

**But I cannot buy this today.** There's no company to contract with, no website to evaluate, no demo to test without cloning a repo, and a development backdoor sitting in the public codebase.

**The gap is not technical - it's commercial.** The TODO_BEFORE_LAUNCH.md already identifies every issue. Executing on that checklist would transform SentriKat from a strong open-source project into a viable commercial product.

---

*Review generated February 2026*
