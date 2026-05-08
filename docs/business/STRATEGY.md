# SentriKat — Business Strategy

> Internal strategy reference: positioning, pricing, competitive analysis, go-to-market.
> **Consolidated 2026-05-07** from 6 source files for navigability. INTERNAL — not for external distribution.

## Table of Contents

- [Part 1 — Honest Competitive Positioning](#part-1--honest-competitive-positioning) (16)
- [Part 2 — Competitive Analysis](#part-2--competitive-analysis) (03)
- [Part 3 — Competitor Gap Analysis](#part-3--competitor-gap-analysis) (12)
- [Part 4 — Pricing Strategy](#part-4--pricing-strategy) (04)
- [Part 5 — Pricing Analysis Post-Sprint 5](#part-5--pricing-analysis-post-sprint-5) (22)
- [Part 6 — Go-to-Market](#part-6--go-to-market) (08)

Original numeric prefixes preserved for git-blame traceability.

---

## Part 1 — Honest Competitive Positioning

# SentriKat: Honest Competitive Positioning Analysis

**Date:** February 2026
**Purpose:** Brutally honest assessment of why companies should (or shouldn't) choose SentriKat, what we actually deliver vs what we promise, and how to position in the European market.

---

## Part 1: The Honest Question — Why Should Anyone Choose SentriKat?

### What We're Really Up Against

The vulnerability management market is worth $16.5B globally (2025). The top 3 players — Tenable, Qualys, Rapid7 — hold ~60% market share and have decades of brand recognition, thousands of employees, and SOC 2/ISO 27001 certifications.

SentriKat is one person building a product. That's the truth. Here's why that can still work.

### The Gap in the Market (Real, Not Imagined)

**The pricing gap is enormous:**

| Segment | Tools Available | Annual Cost | Problem |
|---------|----------------|-------------|---------|
| Enterprise (5K+ employees) | Tenable, Qualys, Rapid7 | $25,000-$150,000+/year | Works, but companies pay for features they never use |
| Mid-market (500-5K employees) | Same tools, enterprise pricing | $5,000-$30,000/year | Overkill complexity, need dedicated security team |
| **SMB (50-500 employees)** | **ManageEngine ($695), Nessus Pro ($4,390), or nothing** | **$0-$4,500/year** | **Massive underserved segment** |
| Micro (<50 employees) | OpenVAS (free), Wazuh (free) | $0 | Need expertise to deploy/maintain |

**The compliance pressure is new and real:**
- NIS2 directive now covers ~160,000 EU entities (up from ~15,000 under NIS1)
- Many mid-sized companies are facing mandatory vulnerability management requirements for the first time
- DORA is in force since Jan 2025 for all EU financial entities
- Cyber Resilience Act vulnerability reporting obligations start September 2026
- 75% of organizations implementing NIS2 lack dedicated implementation budgets

**Alert fatigue is destroying effectiveness:**
- 21,500+ CVEs published in H1 2025 alone
- Larger enterprises have 250,000+ open vulnerabilities and fix only ~10%
- Nearly half of all CVEs get a "high" CVSS score, making severity-based prioritization useless
- 66% of cybersecurity professionals experience burnout

### Where SentriKat Genuinely Wins

These are real, defensible advantages — not marketing fluff:

**1. CISA KEV-Native (Nobody Else Does This)**

Every competitor treats CISA KEV as a filter or tag on top of their existing 200,000+ CVE database. SentriKat was built FROM the KEV catalog outward. The entire UX answers one question: "Which of MY systems are affected by vulnerabilities that attackers are ACTUALLY exploiting RIGHT NOW?"

This isn't a nice feature. It's a fundamentally different approach. A CISO who opens Tenable sees 15,000 CVEs and doesn't know where to start. A CISO who opens SentriKat sees 47 actively exploited vulnerabilities affecting 12 of their products, with due dates.

**Why this matters commercially:** CISA BOD 22-01 mandates 14-30 day remediation of KEV vulnerabilities. This is a regulatory hammer that creates urgent, specific demand for exactly what we do.

**2. Multi-Source Vulnerability Intelligence (Nobody Else Does This Either)**

Every competitor relies on a single vulnerability database (typically NVD) for CVSS scores and enrichment data. When the NVD went into crisis in 2024 (44% of CVEs unenriched, funding cuts, backlog spiraling), their products degraded. SentriKat uses a 3-source fallback chain: NVD → CVE.org/Vulnrichment → ENISA EUVD. If one source goes down, the next picks up automatically. Every score carries a provenance tag.

This also integrates the ENISA European Vulnerability Database (EUVD) -- the NIS2-mandated EU vulnerability database. For European customers subject to NIS2, this is a compliance signal that no competitor can match: their vulnerability intelligence includes European-sovereign data sources, not just US government APIs.

**Why this matters commercially:** NIS2 now covers ~160,000 EU entities. For procurement decisions at these organizations, demonstrating European data sources isn't optional -- it's increasingly a checkbox requirement.

**3. Vendor Backport Detection (Unique Feature)**

When Ubuntu patches OpenSSL by backporting a fix to version `3.0.2-0ubuntu1.15`, Tenable and Qualys still flag it as vulnerable because NVD says "3.0.2 is affected." SentriKat checks 4 vendor advisory feeds (OSV.dev, Red Hat, MSRC, Debian) and automatically resolves the false positive with distro-native version comparison.

No competitor does this automatically. This is a genuine technical innovation that eliminates the #1 source of false positives in Linux environments.

**3. Price (3-10x Cheaper for the Core Use Case)**

| Scenario | SentriKat | Tenable.io | Qualys VMDR | Rapid7 InsightVM |
|----------|-----------|------------|-------------|------------------|
| 100 endpoints | EUR 3,998/year | ~$3,663/year | ~$19,900/year | ~$2,600/year |
| 500 endpoints | EUR 4,498/year | ~$13,000+/year | ~$50,000+/year | ~$11,600+/year |
| 1,000 endpoints | EUR 4,698/year | ~$25,000+/year | ~$100,000+/year | ~$25,000+/year |

At 1,000 endpoints, SentriKat is 5x cheaper than Tenable, 20x cheaper than Qualys, and 5x cheaper than Rapid7. The unlimited agents pack (EUR 2,199/year add-on) makes scaling essentially free.

**4. Self-Hosted + Air-Gap Capable**

Qualys is cloud-only. Tenable and Rapid7 offer self-hosted but push hard toward their cloud products. SentriKat is self-hosted by default. For defense contractors, government agencies, healthcare organizations, and any company with strict data sovereignty requirements, this isn't optional — it's mandatory.

**5. Transparent, Auditable Agents**

SentriKat agents are plain bash/PowerShell scripts that customers can read line-by-line. Competitors ship opaque compiled binaries. For security-conscious organizations, this transparency is a genuine differentiator. "We deploy auditable scripts, not black boxes."

**6. 5-Minute Deployment**

`docker-compose up -d` and a setup wizard. Compare this to Tenable (requires Nessus scanner deployment, scan policies, network configuration, credential management), Qualys (cloud account, scanner appliance, network scanning), or OpenVAS (community edition requires hours of setup, database updates, scan configuration).

### Where SentriKat Honestly Loses

Transparency about weaknesses is more valuable than hiding them. Prospects who discover gaps themselves lose trust. Prospects who hear about gaps from us gain trust.

**1. No Active Network Scanning**

SentriKat doesn't scan your network. It relies on agents reporting installed software. This means:
- Unmanaged devices (rogue systems, shadow IT) are invisible
- Network devices (routers, switches, firewalls) are not covered
- IoT/OT devices are not covered

**How to position:** "SentriKat complements your network scanner. We track what's installed and match it to actively exploited vulnerabilities. We don't replace Nessus — we make the data actionable."

**2. Single Developer**

Tenable has 2,000+ employees. Qualys has 1,800+. We're one person. This means:
- Slower feature development
- No 24/7 support team
- No SOC 2 or ISO 27001 certification (yet)
- Bus factor of 1

**How to position:** "Built by a security practitioner who understands the problem firsthand. Every feature exists because a real customer needed it, not because a product manager filled a spreadsheet."

**~~3. No SBOM Import/Export (Yet)~~** *(closed in Sprint 4 + Sprint 5)*

We now ship **SBOM export** in three industry-standard formats out of the box: CycloneDX 1.5 JSON, SPDX 2.3 JSON and STIX 2.1 bundle. Bundles validate against the official CycloneDX tool-center and OASIS STIX validator. This makes us **directly CRA-ready** ahead of the September 2026 deadline.

**Still open:** SBOM **import** (consume third-party CycloneDX/SPDX bundles as inventory source). On the Sprint 6 backlog.

**~~4. No NIS2/DORA Compliance Mapping~~** *(closed in Sprint 5)*

We now ship native gap analysis reports for **5 frameworks**: CISA BOD 22-01, EU NIS2 (Article 21 mapping), **PCI-DSS v4.0** (Req 6.3, 11.3), **ISO/IEC 27001:2022** (Annex A.8.8, A.8.16, A.5.24) and **SOC 2** (CC7.1, CC7.2, CC7.4, CC6.6). All in JSON and PDF, with HMAC-SHA256 integrity blocks for audit evidence.

**Still open:** DORA-specific report, NIST 800-53 mapping, HIPAA. Add as customer demand materialises.

**5. Brand Recognition = Zero**

SentriKat.com isn't even indexed by search engines yet. No case studies, no testimonials, no analyst coverage, no conference presence. Customers buying security tools are risk-averse — choosing an unknown vendor requires significant trust.

**How to position:** Start with customers who trust the person, not the brand. Direct relationships, MSP partners, LinkedIn personal brand. The product speaks for itself in demos.

**6. No ServiceNow / Splunk / SIEM Integration**

The #1 feature request from mid-market IT teams is ServiceNow integration. The #2 is SIEM event forwarding. We have neither.

**Planned:** Webhook-based SIEM forwarding is straightforward (Q2 2026). ServiceNow requires dedicated development (Q3-Q4 2026).

---

## Part 2: Do We Keep Our Promises?

### What the README/Site Claims vs Reality

| Claim | Reality | Honest? |
|-------|---------|---------|
| "Enterprise-grade vulnerability management" | 30 models, 100+ endpoints, OWASP protections, multi-tenant RBAC — yes, this is enterprise-grade architecture | **Yes** |
| "CISA KEV focus" | Entire matching engine built around KEV + NVD enrichment | **Yes** |
| "Smart matching" | 3-tier CPE + keyword + vendor backport — genuinely sophisticated | **Yes** |
| "5-minute deployment" | docker-compose up + setup wizard — realistically 10-15 minutes with .env configuration | **Mostly** (say "minutes, not hours") |
| "Push agents (Windows/Linux)" | Working agents with dpkg/rpm/apk/pacman/snap/flatpak + registry/WMI | **Yes** |
| "macOS agent" | Agent script exists, needs real-world testing | **Partially** |
| "PDQ, SCCM, Intune, Lansweeper integrations" | Connector architecture exists, but depth of testing varies | **Partially** — should note "beta" for untested integrations |
| "Real-time search of 800,000+ products" | NVD API search works but is rate-limited without API key | **Yes** (with caveat about NVD rate limits) |
| "Vendor Backport Detection" | OSV, Red Hat, MSRC, Debian — 3-tier confidence with distro-native version comparison | **Yes** — this is a genuine strength |
| "10x cheaper than Tenable/Qualys" | At 500+ endpoints, yes. At 100 endpoints, it's closer to 1x-3x | **Yes at scale, less dramatic at small scale** |
| "Container scanning" | Data model exists (ContainerImage, ContainerVulnerability), Trivy integration designed | **Partially** — feature is built but needs deployment testing |

### What's Genuinely Missing From Promises

Things a customer would expect from an "enterprise vulnerability management platform" that we don't have *(updated April 2026 after Sprint 4 + Sprint 5)*:

1. ~~**Compliance reporting beyond CISA BOD 22-01**~~ — ✅ **Closed in Sprint 5.** Added EU NIS2, PCI-DSS v4.0, ISO/IEC 27001:2022, SOC 2 gap analysis reports with HMAC integrity.
2. **Executive dashboards** — Basic stats exist + new vulnerability trending widget (Sprint 5), but no C-level presentation mode yet.
3. **Scheduled compliance reports** — Framework exists in code; PCI/ISO/SOC2 reports added in Sprint 5 but the *scheduling* of those specific reports is still on the backlog.
4. **Data retention policies** — No configurable data lifecycle management.
5. **Formal SLA** — SLA document exists in business docs; **SLA policies + compliance tracking are now shipped in the product (Sprint 4)** for remediation assignments.
6. **Customer documentation** — docs.sentrikat.com is referenced but quality unknown.
7. ~~**Remediation assignments + due dates**~~ — ✅ **Closed in Sprint 4.** Full assignments page with filters, modal detail/edit, multi-tracker integration.
8. ~~**Risk exception management**~~ — ✅ **Closed in Sprint 4.** Justification-based exceptions with optional expiry, ISO/SOC2 audit evidence.
9. ~~**Vulnerability trending dashboard**~~ — ✅ **Closed in Sprint 5.** Chart.js widget with 3 views consuming `/api/vulnerabilities/trends`.
10. ~~**Patch Tuesday automation**~~ — ✅ **Closed in Sprint 5.** Monthly digest email job.

---

## Part 3: Market Positioning Strategy

### Who Is Our Real Customer?

**Primary target (where we win today):**

> European company, 50-2,000 employees, with 1-5 IT/security staff, facing NIS2 compliance requirements for the first time, security budget under EUR 10,000/year, currently using nothing or basic OpenVAS scans.

This customer:
- Cannot afford Tenable/Qualys/Rapid7
- Doesn't have the expertise to run OpenVAS/Wazuh properly
- Needs to demonstrate "vulnerability management" for compliance
- Values simplicity over feature count
- Prefers self-hosted (data sovereignty)
- Has a small number of critical servers + Windows workstations

**Why they choose us over alternatives:**

| Alternative | Why They Don't Choose It | Why They Choose SentriKat |
|-------------|--------------------------|--------------------------|
| Tenable | EUR 25,000+/year, needs dedicated security analyst | EUR 2,499/year, anyone in IT can use it |
| Qualys | Cloud-only, EUR 20,000+/year, complex pricing | Self-hosted, transparent pricing |
| Rapid7 | EUR 10,000+/year, enterprise complexity | Simpler, cheaper, focused on what matters |
| ManageEngine | EUR 695/year but Indian company (EU data concerns), limited VM | EU-based, deeper vulnerability intelligence |
| OpenVAS | Free but 8+ hours to set up, no support, no vendor backports | 15 minutes to deploy, automated backport detection |
| Wazuh | Free but SIEM-first (VM is secondary), steep learning curve | VM-first, purpose-built for the vulnerability workflow |
| Holm Security | EU-based but quote-based pricing (opacity) | Transparent pricing on website |
| Nothing | "We'll do it manually" | NIS2 requires demonstrable vulnerability management |

### How We Sell (Messaging Framework)

**Headline (for website):**

> "Know Which Vulnerabilities Attackers Are Actually Exploiting — Before They Hit Your Systems"

NOT: "Enterprise Vulnerability Management Platform" (generic, doesn't differentiate)

**Subheadline:**

> "SentriKat automatically discovers your software, matches it to actively exploited vulnerabilities, and tells you exactly what to fix first. Self-hosted. EUR 2,499/year. Deploy in minutes."

**The 3 pillars of messaging:**

1. **Clarity over noise** — "Other tools show you 15,000 CVEs. We show you the 47 that attackers are actually using against systems like yours."

2. **Automatic, not manual** — "Deploy agents, and SentriKat does the rest: discovers software, assigns CPE identifiers, matches vulnerabilities, detects vendor backport fixes, and alerts you before due dates."

3. **Accessible, not enterprise-only** — "Enterprise-grade vulnerability intelligence at a price that doesn't require a budget approval committee. Self-hosted, transparent pricing, deploy in minutes."

### What to Fix on the Website

Based on what sentrikat.com should communicate (site wasn't accessible for review, so these are recommendations):

**Must-have (before launch):**

1. **Live demo or interactive screenshots** — Customers need to see the dashboard before installing. A 2-minute walkthrough video would dramatically improve conversion.

2. **Pricing on the homepage** — Don't hide it. EUR 2,499/year is our competitive advantage. Put it front and center with a comparison table showing Tenable/Qualys/Rapid7 prices alongside.

3. **"How it works" in 4 steps** — (1) Deploy agents (2) SentriKat discovers software (3) Matches to exploited vulnerabilities (4) Alerts you with due dates. Simple visual flow.

4. **NIS2 compliance angle** — Dedicated landing page: "NIS2 Vulnerability Management" targeting EU companies searching for NIS2 compliance tools. CISA KEV is the American angle; NIS2 is the European angle.

5. **"vs" comparison pages** — "SentriKat vs Tenable", "SentriKat vs Qualys", "SentriKat vs OpenVAS". These pages rank well for people actively comparing tools and are high-intent traffic.

**Should-have (first 3 months):**

6. **Case study / testimonial** — Even one real customer quote dramatically increases trust. "Before SentriKat, we had no visibility into which vulnerabilities mattered. Now we remediate critical issues within days." — IT Manager, [Company Name]

7. **Free trial with no credit card** — The Demo edition IS the free trial. Make this clear: "Try SentriKat free — 5 agents, no time limit, no credit card."

8. **Blog with SEO-targeted content:**
   - "CISA KEV: What European Companies Need to Know" (NIS2 + KEV intersection)
   - "Why Most Vulnerability Scanners Generate 90% False Positives on Linux" (backport detection)
   - "Vulnerability Management Under EUR 5,000/Year: What's Actually Possible" (buyer's guide)
   - "OpenVAS vs Commercial Alternatives: Honest Comparison for SMBs"

### What to Fix in the Product (for Competitive Positioning)

**Immediately (before merge/release):**

Already done in this branch:
- [x] Race condition on asset creation
- [x] Stuck job recovery
- [x] Asset type auto-detection
- [x] Aggressive filtering (reduce noise from 10K+ to manageable)
- [x] Weird product name matching (Dell | Command Update)
- [x] Unmapped CPE retry

**Next sprint (high impact on sales):**

| Feature | Why It Matters for Sales | Effort |
|---------|--------------------------|--------|
| NIS2 compliance label on dashboard | EU companies searching for "NIS2 vulnerability management" | 1-2 days |
| Export vulnerability list to Excel | Every prospect asks for this in the first demo | 1 day |
| "Executive summary" PDF one-pager | CISOs need a report they can show their board | 2-3 days |
| Dark mode polish | Developers and security analysts prefer dark mode | Already built, just polish |

**Q2 2026 (competitive parity):**

| Feature | Why It Matters | Effort |
|---------|----------------|--------|
| SBOM import (CycloneDX/SPDX) | Regulatory requirement, CI/CD pipeline integration | 2-3 weeks |
| macOS agent production testing | ~40% of developer endpoints | 1 week |
| Container scanning deployment | Tables stakes for any VM tool in 2026 | 4-6 weeks (Trivy integration) |
| ServiceNow webhook | #1 enterprise integration request | 1-2 weeks |

---

## Part 4: Honest Go-to-Market Recommendations

### What Will Actually Work (Bootstrap Budget)

**Channel 1: LinkedIn Personal Brand (EUR 0/month, highest ROI)**

Denis Sota posting 3x/week about:
- CISA KEV updates and analysis ("This week's 3 new KEV entries — here's who's affected")
- NIS2 implementation challenges ("75% of EU companies have no NIS2 budget. Here's what to do.")
- Behind-the-scenes building SentriKat ("How I built vendor backport detection to eliminate 90% of Linux false positives")
- Vulnerability management hot takes ("Why CVSS scores are almost useless for prioritization")

This is free and builds the personal trust that converts to product trust for a single-founder product.

**Channel 2: SEO Content (EUR 0-500/month)**

Target keywords with low competition and high buyer intent:
- "cisa kev tracking tool" (~500 searches/month, low competition)
- "cisa bod 22-01 compliance" (~300/month, low competition)
- "tenable alternative" (~200/month, low competition)
- "vulnerability management for small business" (~400/month, medium competition)
- "NIS2 vulnerability management" (growing fast with regulatory deadline)

Write 2 blog posts/week. Each post should rank for a specific keyword and end with a CTA to try the free Demo edition.

**Channel 3: MSP/MSSP Partners (EUR 0/month, longest payoff)**

Most SMBs (50-500 employees) buy security tools through their managed service provider. A single MSP partner with 20 clients is worth more than 100 website visitors.

Target: Regional European MSPs who offer security services but don't have a VM platform. SentriKat's multi-tenant architecture + white-label branding is designed for this.

Partner program: 20-40% discount tiers. The MSP marks up to their client. Both sides win.

**Channel 4: Conference Talks (EUR 2-5K per event)**

2 conferences in H2 2026. Not as a vendor booth (expensive, low conversion) but as a speaker:
- "How We Built a CVE-History-Guarded Filtering System" (technical, developer audience)
- "Vulnerability Management for EUR 2,499/Year: No Compromises" (business, CISO audience)

**What Won't Work (don't waste money):**
- Google Ads for "vulnerability management" (CPC $15-25, dominated by Tenable/Qualys)
- Cold email campaigns (response rate <1% for unknown security vendors)
- Analyst firm evaluations (Gartner, Forrester require $50K+ and years of market presence)

### Revenue Projections (Conservative)

| Quarter | Customers | ARR (EUR) | How |
|---------|-----------|-----------|-----|
| Q2 2026 | 5 | 17,500 | Direct sales (personal network, LinkedIn) |
| Q3 2026 | 15 | 52,500 | Content marketing traction + 1 MSP partner |
| Q4 2026 | 30 | 105,000 | 2-3 MSP partners + conference leads |
| Q1 2027 | 50 | 175,000 | SEO traffic + expanding MSP channel |

Average deal: EUR 3,500/year (Professional + small agent pack).

Break-even (covering infrastructure + minimal living costs): ~20-25 customers.

---

## Part 5: The Bottom Line

### Why Choose SentriKat (The Honest Pitch)

**For a small company (10-100 employees):**
> "You need vulnerability management for NIS2 but can't afford Tenable. SentriKat's Demo edition is free for 5 agents. Deploy in 15 minutes, see which actively exploited vulnerabilities affect your systems today."

**For a mid-market company (100-2,000 employees):**
> "You're paying EUR 25,000/year for Tenable and your team ignores 90% of the alerts. SentriKat focuses on the 1,484 vulnerabilities that are actually being exploited and automatically filters out false positives from Linux backports. EUR 2,499/year, self-hosted, your data stays in your infrastructure."

**For an MSP/MSSP:**
> "You manage 20 clients and need scalable vulnerability management. SentriKat's multi-tenant architecture lets you manage all clients from one instance with white-label branding. Your clients see your brand, you see one dashboard."

**For a government/defense organization:**
> "You need air-gapped vulnerability management with transparent, auditable agents. SentriKat runs entirely on your infrastructure, agents are readable scripts (not compiled binaries), and it works offline."

### Why NOT Choose SentriKat (Know When to Walk Away)

- You need active network scanning → Use Tenable/Qualys alongside SentriKat
- You need 24/7 phone support → We don't have a support team (yet)
- You need SOC 2 certified vendor → We don't have it (planned Year 2)
- You have 10,000+ endpoints → You probably need Tenable/Qualys/Rapid7 scale
- You need CI/CD pipeline scanning → Wait for SBOM support (Q3 2026)
- You're already happy with your current tool → Switching cost isn't worth it

### The One Thing That Matters Most Right Now

**Get 5 paying customers by end of Q2 2026.** Everything else — SEO, content, partnerships, features — serves that goal. Five real customers provide:
- Revenue to sustain development
- Feedback to prioritize features
- Testimonials for the website
- Proof points for MSP partners
- Confidence for the founder

The product is ready. The market need is real. The price is right. Now it's about execution.

---

*Analysis generated February 2026. Based on codebase review, market research, and competitive intelligence.*


---

## Part 2 — Competitive Analysis

# SENTRIKAT - COMPETITIVE ANALYSIS
## Market Landscape & Positioning

---

## MARKET OVERVIEW

### Vulnerability Management Market

- **2024 Market Size**: $16.5 Billion ([Grand View Research](https://www.grandviewresearch.com/industry-analysis/security-and-vulnerability-management-svm-market))
- **2030 Projected**: $24.5 Billion ([MarketsandMarkets](https://www.marketsandmarkets.com/Market-Reports/security-vulnerability-management-market-204180861.html))
- **CAGR**: 6.5-9.6% depending on segment ([Precedence Research](https://www.precedenceresearch.com/security-and-vulnerability-management-market))
- **Key Drivers**:
  - Increasing cyber attacks (30% YoY increase in Q2 2024)
  - Regulatory compliance (CISA BOD 22-01, NIS2, DORA)
  - Remote work expansion
  - Cloud migration
  - 40,009 CVEs published in 2024 alone ([CyberPress](https://cyberpress.org/over-40000-cves-published-in-2024/))

### Market Segments

| Segment | Size | Growth | SentriKat Fit |
|---------|------|--------|---------------|
| Enterprise (5000+) | 45% | 8% | Future |
| Mid-Market (500-5000) | 35% | 12% | **Primary Target** |
| SMB (50-500) | 15% | 15% | Secondary |
| Micro (<50) | 5% | 10% | Demo tier |

---

## COMPETITOR MATRIX

### Tier 1: Enterprise Leaders

| Vendor | Founded | Funding | Customers | Revenue |
|--------|---------|---------|-----------|---------|
| Tenable | 2002 | IPO (TENB) | 40,000+ | $700M+ |
| Qualys | 1999 | IPO (QLYS) | 19,000+ | $500M+ |
| Rapid7 | 2000 | IPO (RPD) | 11,000+ | $600M+ |
| CrowdStrike | 2011 | IPO (CRWD) | 23,000+ | $3B+ |

### Tier 2: Challengers

| Vendor | Founded | Funding | Focus |
|--------|---------|---------|-------|
| Snyk | 2015 | $850M | Developer security |
| Orca Security | 2019 | $550M | Cloud security |
| Wiz | 2020 | $900M | Cloud security |
| Lacework | 2015 | $1.3B | Cloud security |

### Tier 3: Open Source / Low-Cost

| Vendor | Type | Strengths | Weaknesses |
|--------|------|-----------|------------|
| OpenVAS/Greenbone | OSS | Free, customizable | Complex, no support |
| OWASP ZAP | OSS | Web scanning | Limited scope |
| Nuclei | OSS | Fast, templates | Requires expertise |

---

## DETAILED COMPETITOR ANALYSIS

### 1. Tenable (Nessus/Tenable.io)

**Overview**
- Market leader in vulnerability scanning
- IPO 2018, $4B+ market cap
- 40,000+ customers globally

**Strengths**
- Comprehensive scanning capabilities
- Strong brand recognition
- Large vulnerability database
- Extensive integrations

**Weaknesses**
- Complex and expensive
- Slow to adopt CISA KEV focus
- Agent-heavy architecture
- Overkill for SMB

**Pricing** ([Tenable Official](https://www.tenable.com/buy))
- Nessus Professional: $3,590/year (single scanner, unlimited IPs)
- Nessus Expert: $5,890/year (includes external attack surface)
- Tenable.io: ~$2,900/year for 128 assets ([Underdefense](https://underdefense.com/industry-pricings/tenable-pricing-2025-ultimate-guide-for-security-products/))
- Enterprise (Tenable One): $50K-75K+/year

**SentriKat Advantage**
- 10x cheaper for SMB
- CISA KEV-native
- Simpler deployment
- Self-hosted option

---

### 2. Qualys

**Overview**
- Cloud-native vulnerability management
- Founded 1999, IPO 2012
- Strong in compliance

**Strengths**
- Cloud architecture
- Compliance mapping
- Asset discovery
- Container scanning

**Weaknesses**
- Expensive for small teams
- Complex pricing
- Slow onboarding
- Cloud-only (no self-hosted)

**Pricing**
- VMDR: ~$2,500/year per 100 assets
- Enterprise: $100K+/year

**SentriKat Advantage**
- Self-hosted option
- Simpler licensing (per-agent)
- Faster deployment
- Lower TCO

---

### 3. Rapid7 (InsightVM)

**Overview**
- Modern vulnerability management
- Strong UX focus
- SIEM integration (InsightIDR)

**Strengths**
- Good user experience
- Risk-based prioritization
- Cloud and on-prem
- Strong integrations

**Weaknesses**
- Premium pricing
- Feature creep
- Resource intensive
- Lock-in potential

**Pricing**
- InsightVM: ~$2,000/year per 50 assets
- Managed: $5,000+/year

**SentriKat Advantage**
- CISA KEV focus
- Simpler product
- Lower cost
- No vendor lock-in

---

### 4. OpenVAS/Greenbone

**Overview**
- Open-source vulnerability scanner
- Fork of Nessus
- Community-driven

**Strengths**
- Free (community edition)
- Customizable
- Self-hosted
- No licensing costs

**Weaknesses**
- Complex setup (hours/days)
- Limited support
- Outdated UI
- Manual processes
- No CISA KEV integration

**Pricing**
- Community: Free
- Greenbone Enterprise: €50K+/year

**SentriKat Advantage**
- 5-minute setup
- Modern UI
- CISA KEV native
- Commercial support
- Affordable Pro tier

---

## FEATURE COMPARISON

### Core Capabilities

| Feature | SentriKat | Tenable | Qualys | Rapid7 | Wiz | OpenVAS |
|---------|-----------|---------|--------|--------|-----|---------|
| CISA KEV Sync | **Native** | Manual | Manual | Manual | Add-on | No |
| Multi-Source CVSS | **3 sources (NVD/CVE.org/EUVD)** | Single (NVD) | Single | Single | Single | Single |
| ENISA EUVD Integration | **Native** | No | No | No | No | Partial |
| NVD Outage Resilience | **Auto-fallback** | Degraded | Degraded | Degraded | Degraded | Degraded |
| Data Provenance | **Per-CVE source tag** | No | No | No | No | No |
| Push Agents | Win/Linux/macOS | Yes | Yes | Yes | Cloud agent | No |
| Agentless Scan | No | Yes | Yes | Yes | Yes (cloud) | Yes |
| EPSS Scoring | Yes | Yes | Yes | Yes | Yes | No |
| Due Date Tracking | **Native** | Add-on | Add-on | Add-on | Add-on | No |
| Container Scanning | **Native (Trivy)** | Yes | Yes | Yes | Yes | Limited |
| Code Dependency Scanning (lockfiles) | **Native (OSV)** | Add-on | Add-on | Add-on | Yes | No |
| Vendor Backport Detection | **Native (OSV/RH/MSRC/Debian)** | No | No | No | No | No |

### SBOM, Compliance & Remediation (Sprint 4 + 5)

| Feature | SentriKat | Tenable | Qualys | Rapid7 | Wiz | OpenVAS |
|---------|-----------|---------|--------|--------|-----|---------|
| SBOM Export CycloneDX 1.5 | **Native** | Add-on | Add-on | Add-on | Yes | No |
| SBOM Export SPDX 2.3 | **Native** | Add-on | No | No | Yes | No |
| SBOM Export STIX 2.1 | **Native** | No | No | No | No | No |
| EU CRA Readiness (SBOM + 24h disclosure) | **Native** | Partial | Partial | Partial | Partial | No |
| PCI-DSS v4.0 Gap Analysis | **Native (JSON+PDF)** | Module | Module | Add-on | No | No |
| ISO/IEC 27001:2022 Gap Analysis | **Native (JSON+PDF)** | Module | Module | Add-on | No | No |
| SOC 2 Gap Analysis | **Native (JSON+PDF)** | Module | Module | Add-on | No | No |
| CISA BOD 22-01 Report | **Native** | Module | Module | Module | No | No |
| EU NIS2 Article 21 Report | **Native** | No | Partial | No | No | No |
| Report HMAC Integrity | **Native** | No | No | No | No | No |
| Vulnerability Trending Dashboard | **Native (Chart.js)** | Yes | Yes | Yes | Yes | No |
| Remediation Assignments + Due Dates | **Native** | Add-on | Add-on | Yes | Yes | No |
| SLA Policies + Compliance Tracking | **Native** | Add-on | Add-on | Yes | Yes | No |
| Risk Exception Management (justification + expiry) | **Native** | Manual | Manual | Manual | Manual | No |
| Issue Tracker Integration (Jira/GitHub/GitLab/YouTrack) | **Native (4 trackers)** | Jira only | Jira only | Jira/SNow | Jira/SNow | No |
| Patch Tuesday Automated Digest | **Native** | No | No | No | No | No |

### Agent Resilience (Sprint 4)

| Feature | SentriKat | Tenable | Qualys | Rapid7 | Wiz |
|---------|-----------|---------|--------|--------|-----|
| Delta Scan (SHA256 hash diff) | **Native** | No | No | No | No |
| Gzip Compression with Zip-Bomb Protection | **Native** | Yes | Yes | Yes | Yes |
| Offline Store-and-Forward | **Native** | No | Partial | No | N/A (cloud only) |
| Auditable Script Agents (bash/PowerShell) | **Native** | Compiled binary | Compiled binary | Compiled binary | Cloud-only |

### Authentication

| Feature | SentriKat | Tenable | Qualys | Rapid7 | OpenVAS |
|---------|-----------|---------|--------|--------|---------|
| Local Auth | Yes | Yes | Yes | Yes | Yes |
| LDAP/AD | Yes | Yes | Yes | Yes | Limited |
| SAML SSO | Yes | Yes | Yes | Yes | No |
| 2FA/TOTP | Yes | Yes | Yes | Yes | No |

### Integrations

| Integration | SentriKat | Tenable | Qualys | Rapid7 | OpenVAS |
|-------------|-----------|---------|--------|--------|---------|
| Jira | Yes | Yes | Yes | Yes | No |
| Slack | Yes | Yes | Yes | Yes | No |
| Teams | Yes | Yes | Yes | Yes | No |
| ServiceNow | Roadmap | Yes | Yes | Yes | No |
| Splunk | Roadmap | Yes | Yes | Yes | Limited |

### Deployment

| Option | SentriKat | Tenable | Qualys | Rapid7 | OpenVAS |
|--------|-----------|---------|--------|--------|---------|
| Cloud (SaaS) | Roadmap | Yes | Yes | Yes | No |
| Self-Hosted | Yes | Yes | No | Yes | Yes |
| Docker | Yes | No | No | No | Yes |
| Air-Gapped | Yes | Yes | No | Yes | Yes |

---

## PRICING COMPARISON

### 100 Endpoint Scenario

| Vendor | Annual Cost | Per-Endpoint |
|--------|-------------|--------------|
| SentriKat Pro | EUR 3,998 | EUR 40 |
| Tenable.io | $3,663 | $37 |
| Qualys VMDR | $2,500 | $25 |
| Rapid7 InsightVM | $4,000 | $40 |
| OpenVAS (free) | $0 | $0 |
| OpenVAS (support) | $10,000+ | $100+ |

### 1,000 Endpoint Scenario

| Vendor | Annual Cost | Per-Endpoint |
|--------|-------------|--------------|
| SentriKat Pro | EUR 4,698 | EUR 4.70 |
| Tenable.io | $25,000+ | $25+ |
| Qualys VMDR | $20,000+ | $20+ |
| Rapid7 InsightVM | $30,000+ | $30+ |

---

## COMPETITIVE POSITIONING

### SentriKat Sweet Spot

```
                    ENTERPRISE
                         │
                         │    Tenable
                         │    Qualys
        ┌────────────────┼────────────────┐
        │                │                │
COMPLEX │                │                │ SIMPLE
        │                │   ★ SentriKat  │
        │                │                │
        │    OpenVAS     │                │
        └────────────────┼────────────────┘
                         │
                        SMB
```

### Target Customer Profile

**Ideal Customer**:
- 100-5,000 employees
- In-house IT/security team (1-10 people)
- Needs CISA BOD 22-01 compliance
- Budget: $5K-50K/year for security tools
- Prefers self-hosted or hybrid
- Values simplicity over features

**Not Ideal Customer**:
- <50 employees (use Demo tier)
- >10,000 employees (need enterprise features)
- Need active scanning (not our focus)
- Already using Tenable/Qualys (hard to switch)

---

## COMPETITIVE MOATS

### What We Can Build

| Moat | Strategy |
|------|----------|
| CISA KEV Focus | First-mover advantage, native integration |
| Multi-Source Intelligence | 6+ data sources with auto-fallback, no NVD single-point-of-failure |
| European Data Sovereignty | ENISA EUVD integration, NIS2-aligned architecture |
| Simplicity | Opinionated product, easy deployment |
| Price | 5-10x cheaper than enterprise tools |
| Self-Hosted | Data sovereignty, compliance |
| Agent Design | Lightweight, script-based, cross-platform |

### What's Hard to Defend

| Risk | Mitigation |
|------|------------|
| Features parity | Focus on UX, not feature count |
| Enterprise deals | Partner with MSSPs |
| Brand awareness | Content marketing, community |
| Funding gap | Bootstrap-friendly pricing |

---

## MARKET POSITIONING STATEMENT

**For** mid-market companies with 100-5,000 employees

**Who** need to track and remediate software vulnerabilities for compliance

**SentriKat** is a vulnerability management platform

**That** automatically discovers installed software, correlates with CISA KEV and NVD, and tracks remediation

**Unlike** Tenable, Qualys, and Rapid7

**Our product** is 10x simpler to deploy, focused on CISA compliance, and affordable for teams without enterprise budgets.

---

## BATTLE CARDS

### vs. Tenable

| Objection | Response |
|-----------|----------|
| "Tenable is industry standard" | "For enterprises, yes. For mid-market, it's overkill and overpriced." |
| "We need active scanning" | "Our focus is software inventory + CISA KEV. If you need pentesting, Tenable makes sense." |
| "Tenable has more integrations" | "We have the integrations you actually use: Jira, Slack, LDAP, SAML." |

### vs. Qualys

| Objection | Response |
|-----------|----------|
| "Qualys is cloud-native" | "Cloud-native means cloud-only. We offer self-hosted for data sovereignty." |
| "Qualys has compliance modules" | "We're focused on CISA BOD 22-01 compliance, which is what you actually need." |

### vs. OpenVAS

| Objection | Response |
|-----------|----------|
| "OpenVAS is free" | "Free in license, expensive in time. Our 5-minute setup vs. their 5-day setup." |
| "We have Linux expertise" | "Great! But do you want to maintain vulnerability scanning infrastructure?" |

### vs. Wiz

| Objection | Response |
|-----------|----------|
| "Wiz is the modern leader" | "Wiz is cloud-only and starts at €50K+/year. We're 10-20x cheaper, support self-hosted, and ship the SBOM + compliance reports they don't have." |
| "Wiz has a great UX" | "Agreed. We're not far behind on UX, but we're orders of magnitude cheaper and we run on-prem for sovereign deployments." |
| "Wiz covers cloud" | "We complement cloud security platforms — we cover what's installed on the endpoint and what's in your software bill of materials. Use both." |
| "Wiz has SBOM" | "Wiz has SBOM as an add-on inside their cloud-only product. We ship CycloneDX 1.5 + SPDX 2.3 + STIX 2.1 out-of-the-box, both SaaS and on-premise, EU-hosted." |

### vs. CRA-only consulting (the new competitive threat)

| Objection | Response |
|-----------|----------|
| "We hired a consultant for CRA readiness" | "Consultants give you a one-time PDF. SentriKat gives you a continuously updated SBOM and an integrity-signed compliance report you can regenerate any time the auditor asks. €4,000 of consulting is one-shot. SentriKat at €249-649/month is permanent." |
| "We just need an SBOM, not a platform" | "Sure. Buy the SBOM export and ignore the rest. We're 10x cheaper than letting a consultant produce it manually every quarter." |

---

## RECOMMENDED ACTIONS

### Short-term (Q1-Q2 2026)
1. Focus on CISA KEV differentiation in all messaging
2. Publish comparison landing pages for each competitor
3. Create migration guides from OpenVAS
4. Target companies failing CISA audits

### Medium-term (Q3-Q4 2026)
1. Get customer testimonials for case studies
2. Partner with security consultancies
3. Attend RSA Conference, BSides events
4. Pursue G2/Gartner reviews

### Long-term (2027+)
1. Pursue SOC 2 certification
2. Enter Gartner Magic Quadrant consideration
3. Build partner ecosystem
4. Consider cloud-hosted option

---

*Analysis based on public information as of February 2026. Updated April 2026 with Sprint 4 + Sprint 5 feature parity data and CRA-readiness positioning. Subject to change.*


---

## Part 3 — Competitor Gap Analysis

# SENTRIKAT - COMPETITOR GAP ANALYSIS & INTEGRATION ROADMAP
## What Competitors Do Better & What We Can Steal

---

**Document Version:** 1.2
**Date:** February 2026 (updated April 2026 after Sprint 4 + Sprint 5)
**Purpose:** Honest gap analysis against Tenable, Qualys, Rapid7, CrowdStrike, Wiz, Snyk, Aqua Security, and open-source tools (Trivy, Grype, Docker Scout). Prioritized list of features we can integrate now vs. later.

> **Status note (April 2026):** Several gaps marked "CRITICAL" in version 1.0 of this
> document have been **closed** by Sprint 2 (container scanning), Sprint 4 (SBOM
> export, remediation workflows, risk exceptions, product aliases) and Sprint 5
> (vulnerability trending, STIX 2.1, Patch Tuesday automation, PCI-DSS / ISO
> 27001 / SOC 2 gap analysis reports). Sections below have been annotated with
> ✅ CLOSED / 🔶 PARTIALLY CLOSED / ❌ STILL OPEN status tags.

---

## EXECUTIVE SUMMARY

SentriKat has a strong niche: CISA KEV-focused vulnerability management for mid-market, self-hosted, with fast deployment and low cost. After Sprint 4 + Sprint 5 the platform has closed most of the original gaps in **container scanning**, **SBOM management**, **remediation workflows**, **risk exception management**, **vulnerability trending**, **multi-framework compliance reports** and **Patch Tuesday automation**. The remaining gaps are: **agentless cloud asset discovery**, **IaC / misconfiguration scanning**, **secret detection**, **developer experience / shift-left**, and **AI-driven risk scoring beyond CVSS/EPSS**.

---

## PART 1: WHAT COMPETITORS DO BETTER THAN US

### 1. Container & Docker Image Scanning (✅ CLOSED — Sprint 2)

**Who does it:** Everyone. Literally every competitor.

| Competitor | Capability |
|-----------|-----------|
| **Tenable** | Registry scanning, CI/CD pipeline scanning, CS Scanner for local image analysis |
| **Qualys** | QScanner CLI, registry scanning, eBPF runtime protection, Kubernetes Admission Controller |
| **CrowdStrike** | 1,500+ out-of-the-box container policies, runtime protection, full lifecycle scanning |
| **Wiz** | Agentless container scanning via snapshots, Admission Controller, WizOS hardened base images |
| **Snyk** | Docker's official scanning partner, integrated into Docker Desktop, registry sync |
| **Aqua** | Industry-leading runtime protection, sandbox analysis (DTA), drift detection |
| **Trivy** | Free, scans images in seconds, OS + app dependencies, default scanner in Harbor |
| **Grype** | Free, SBOM-based scanning, PURL scanning for surgical dependency checks |
| **Docker Scout** | Built into Docker Desktop, layer-by-layer analysis, automatic VEX |

**~~SentriKat gap~~** *(closed in Sprint 2)*: SentriKat agents now auto-detect Docker / Podman on endpoints and scan all container images using **Trivy** (Apache-2.0, zero cost). Results land on the **Containers** dashboard alongside endpoint vulnerabilities. Both Linux and Windows agents support this. New API: `POST /api/agent/container-scan`, `GET /api/containers`, `GET /api/containers/<id>`.

**Verdict: ✅ CLOSED. Container scanning is shipped and at production parity for our target market.**

---

### 2. SBOM Generation & Import (🔶 PARTIALLY CLOSED — Sprint 4 + Sprint 5)

**Who does it:** Trivy, Grype/Syft, Snyk, Docker Scout, Qualys, Wiz, CrowdStrike

SBOMs (Software Bill of Materials) in CycloneDX or SPDX format are becoming a regulatory requirement (US Executive Order 14028, EU Cyber Resilience Act). Competitors can:
- Generate SBOMs from container images, filesystems, and repositories
- Import SBOMs and scan them for vulnerabilities
- Track SBOM drift over time

**~~SentriKat gap~~** *(export closed Sprint 4 + Sprint 5)*: SentriKat now ships **SBOM export** in three industry-standard formats out of the box:
- **CycloneDX 1.5** JSON (`/api/sbom/export/cyclonedx`)
- **SPDX 2.3** JSON (`/api/sbom/export/spdx`)
- **STIX 2.1** bundle with vulnerability SDOs + software SCOs + relationship SROs (`/api/sbom/export/stix21`)

The bundles validate against the official CycloneDX tool-center and OASIS STIX validator. They are licensing-gated and rate-limited.

**Still open:** SBOM **import** (consume third-party CycloneDX/SPDX bundles as inventory source). Slated for Sprint 6.

**Verdict: 🔶 PARTIALLY CLOSED. Export at full parity with competitors; import remains on the Sprint 6 backlog.**

---

### 3. IaC / Misconfiguration Scanning (We Have: NOTHING)

**Who does it:** Trivy, Snyk, Wiz, Qualys, CrowdStrike, Tenable

Scanning Dockerfiles, Kubernetes manifests, Terraform templates, and Helm charts for misconfigurations (e.g., running as root, exposed ports, missing resource limits).

**SentriKat gap:** We focus on CVE matching against installed software. We don't analyze infrastructure-as-code at all.

**Verdict: MEDIUM gap. Not our core market, but Trivy does this for free and we could wrap it.**

---

### 4. Secret Detection (We Have: NOTHING)

**Who does it:** Trivy, Aqua, Wiz, CrowdStrike, Qualys

Scanning source code, images, and configs for hardcoded credentials, API keys, and tokens.

**SentriKat gap:** Not our domain currently, but it's a natural extension of "what's dangerous in your environment."

**Verdict: LOW-MEDIUM gap. Nice to have via Trivy integration but not core.**

---

### 5. Agentless / Network Scanning (We Have: NOTHING)

**Who does it:** Tenable (core), Qualys (virtual appliances), Rapid7 (Scan Engines), CrowdStrike (network VA), Wiz (cloud API snapshots)

Active network scanning discovers assets and vulnerabilities without installing agents.

**SentriKat gap:** We're entirely agent-based and integration-based. If a device doesn't have our agent or isn't in an integration, we're blind to it.

**Verdict: MEDIUM gap. Already on Q3 2026 roadmap as "Asset discovery scan." Good for completeness but not differentiating.**

---

### 6. Risk Scoring Beyond CVSS/EPSS (We Have: BASIC)

**Who does it better:**
- **CrowdStrike ExPRT.AI:** AI-driven scoring using actual adversary behavior patterns
- **Rapid7 Active Risk:** 0-1000 scale combining CVSS + Metasploit + AttackerKB + dark web intel
- **Qualys TruRisk:** Business-context-aware risk scoring
- **Wiz Security Graph:** Correlates vulns with network exposure, identity permissions, and secrets to find "toxic combinations"

**SentriKat current state:** We use CVSS, EPSS, and our own priority matrix (severity + criticality + age + ransomware risk). This is decent but doesn't incorporate actual exploit intelligence or environmental context.

**Verdict: MEDIUM gap. Our priority matrix is good for our market. AI-powered scoring is on the Q1 2027 roadmap.**

---

### 7. Remediation Workflows (✅ MOSTLY CLOSED — Sprint 4)

**Who does it better:**
- **Rapid7 Remediation Hub:** Intelligent supersedence logic (finds the ONE patch that fixes the most vulns), asset-group-based prioritization
- **CrowdStrike Charlotte SOAR:** AI agents that auto-create tickets, trigger patch management, fix misconfigs
- **Qualys VMDR:** Integrated patch deployment directly from the vulnerability management console

**~~SentriKat current state~~** *(closed in Sprint 4)*: SentriKat now ships:
- **Remediation Assignments** with status (open/in_progress/resolved), assignee, due dates and notes (`/api/remediation/assignments`)
- **SLA policies** that automatically compute `due_date` for new assignments based on `(severity, asset_type)` (`/api/sla/policies`)
- **`/api/sla/compliance`** endpoint for real-time compliance dashboards
- **Multi-tracker integration**: Jira, GitHub, GitLab, YouTrack, generic Webhook with `tracker_issue_key` / `tracker_issue_url` / `tracker_type`
- **Risk Exception Management** with mandatory justification, optional expiry, ISO/SOC2 audit evidence (`/api/risk-exceptions`)
- **Throttled email notifications** (max 1/assignment/hour, only created+resolved, only assignee — preserves Resend free tier)

**Still open:** Patch supersedence logic (Rapid7-style). On the Sprint 6 backlog.

**Verdict: ✅ MOSTLY CLOSED. Workflow parity reached; supersedence remains.**

---

### 8. Developer Experience / Shift-Left (We Have: NOTHING)

**Who does it:** Snyk (best-in-class), Docker Scout, Trivy, Wiz Code

IDE plugins, Git hooks, CI/CD pipeline scanning, PR comments with vulnerability findings.

**SentriKat gap:** We're an ops/compliance tool. Developers don't interact with us. This limits our value in DevSecOps organizations.

**Verdict: LOW gap for our current market (compliance-focused IT teams). MEDIUM gap for growth into DevSecOps.**

---

### 9. Cloud Asset Discovery (We Have: NOTHING)

**Who does it:** Wiz (best), CrowdStrike, Qualys, Tenable, Rapid7

Auto-discover all assets across AWS, Azure, GCP via cloud APIs -- including VMs, containers, serverless functions, databases, storage buckets.

**SentriKat gap:** We rely on agents and integrations to know about assets. We can't discover cloud resources automatically.

**Verdict: LOW gap for current self-hosted focus. HIGH gap if we move to SaaS/cloud market.**

---

### 10. Compliance Framework Mapping (✅ CLOSED — Sprint 5)

**Who does it:** Qualys (100+ frameworks), Wiz (100+ frameworks), Tenable, CrowdStrike

Mapping vulnerabilities to NIST 800-53, CIS Benchmarks, PCI DSS 4.0, HIPAA, ISO 27001, SOC 2, NIS2, DORA, etc.

**~~SentriKat gap~~** *(closed in Sprint 5)*: SentriKat now ships gap analysis reports for the **most regulated frameworks** that mid-market EU customers actually need:

| Framework | Endpoint | Coverage |
|---|---|---|
| CISA BOD 22-01 | `/api/reports/compliance/bod-22-01` | Existing (Sprint 1) |
| EU NIS2 | `/api/reports/compliance/nis2` | Existing — Article 21(2)(d)(e)(g) |
| **PCI-DSS v4.0** | `/api/reports/compliance/pci-dss` | **Sprint 5** — Req 6.3, 11.3 |
| **ISO/IEC 27001:2022** | `/api/reports/compliance/iso-27001` | **Sprint 5** — Annex A.8.8, A.8.16, A.5.24 |
| **SOC 2** | `/api/reports/compliance/soc2` | **Sprint 5** — CC7.1, CC7.2, CC7.4, CC6.6 |

All reports support JSON and PDF formats and carry an **HMAC-SHA256 integrity block** so auditors can verify the report has not been tampered with after generation. Each control has `evidence`, `gaps` and `recommendations` blocks plus a `PASS` / `PARTIAL` / `FAIL` / `NOT_APPLICABLE` status.

We don't have 100+ frameworks like Qualys/Wiz, but we cover the **5 frameworks** that account for >90% of mid-market EU compliance demand.

**Verdict: ✅ CLOSED. Multi-framework gap closed for our target market. NIST 800-53 + HIPAA + DORA can be added in future sprints if customer demand warrants it.**

---

## PART 2: CONTAINER IMAGE SCANNING -- THE BIG OPPORTUNITY

### Why This Is the #1 Feature to Add

1. **Every competitor has it** -- it's table stakes in 2026
2. **76% of organizations** run containers in production (Datadog 2025 Container Report)
3. **Open-source tools make it easy** -- we don't need to build a scanner
4. **It fits our architecture** -- agents can scan local Docker images, same as they scan installed software
5. **It's already on our Q3 2026 roadmap** -- we should accelerate to Q2

### Tool Comparison: What to Integrate

| Tool | License | Speed | Scope | Best For |
|------|---------|-------|-------|----------|
| **Trivy** | Apache-2.0 | Fastest | Vulns + Misconfigs + Secrets + SBOM + IaC | Best all-around choice |
| **Grype** | Apache-2.0 | Fast | Vulns only | If we only need CVE scanning |
| **Syft** | Apache-2.0 | Fast | SBOM generation only | Pairs with Grype |
| **Docker Scout** | Proprietary | Fast | Vulns + SBOM (Docker ecosystem only) | Docker-only shops |

### Recommendation: Trivy

**Trivy is the clear winner** for integration because:
- Single binary, zero dependencies
- Scans OS packages AND application dependencies (pip, npm, Maven, Go, Rust, etc.)
- Generates SBOMs (CycloneDX, SPDX) -- solves two gaps at once
- Detects misconfigurations in Dockerfiles and K8s manifests -- bonus gap solved
- Detects secrets -- another bonus
- JSON output format -- easy to parse and ingest into SentriKat
- Database updates every 6 hours from NVD, Red Hat, Alpine, Debian, Ubuntu, etc.
- Default scanner in Harbor, Red Hat certified
- 25,000+ GitHub stars, massive community

### How the Integration Would Work

```
┌─────────────────────────────────────────────────────────────┐
│                    SentriKat Architecture                     │
│                                                              │
│  ┌──────────────────┐       ┌──────────────────────┐        │
│  │  SentriKat Agent  │       │  SentriKat Server     │        │
│  │  (Windows/Linux)  │       │  (Flask)              │        │
│  │                   │       │                       │        │
│  │  Current:         │       │  New:                 │        │
│  │  - Registry scan  │       │  - /api/agent/        │        │
│  │  - dpkg/rpm/apk   │  ──→  │    container-scan     │        │
│  │                   │       │  - Trivy results      │        │
│  │  NEW:             │       │    parser             │        │
│  │  - Trivy scan     │       │  - Container vuln     │        │
│  │  - Docker images  │       │    matching           │        │
│  │  - SBOM generation│       │  - SBOM storage       │        │
│  │  - K8s manifests  │       │  - Image inventory    │        │
│  └──────────────────┘       └──────────────────────┘        │
│                                                              │
│  Integration Flow:                                           │
│  1. Agent detects Docker on endpoint                         │
│  2. Agent runs: trivy image --format json <image>            │
│  3. Agent sends JSON results to SentriKat API                │
│  4. Server parses Trivy output, creates:                     │
│     - ContainerImage records (new model)                     │
│     - VulnerabilityMatch records (existing model)            │
│     - SBOM records (new model, CycloneDX format)             │
│  5. Dashboard shows container vulns alongside endpoint vulns │
│  6. Alerts fire for critical container CVEs                  │
│  7. Reports include container security posture               │
│                                                              │
│  Alternative Flow (CI/CD):                                   │
│  1. Customer adds SentriKat step to CI/CD pipeline           │
│  2. Pipeline runs: trivy image --format json <image>         │
│  3. Pipeline POSTs results to SentriKat API                  │
│  4. SentriKat tracks pre-deployment vulnerabilities          │
│  5. Optional: fail pipeline if critical CVEs found           │
└─────────────────────────────────────────────────────────────┘
```

### Implementation Plan

#### Phase 1: Agent-Side Trivy Integration (2-3 weeks)

**Linux Agent (`sentrikat-agent-linux.sh`):**
```bash
# Auto-install Trivy if Docker is detected
if command -v docker &> /dev/null; then
    # Install Trivy (one-time)
    if ! command -v trivy &> /dev/null; then
        curl -sfL https://raw.githubusercontent.com/aquasecurity/trivy/main/contrib/install.sh | sh -s -- -b /usr/local/bin
    fi

    # List all local Docker images
    IMAGES=$(docker images --format "{{.Repository}}:{{.Tag}}" | grep -v "<none>")

    # Scan each image
    for IMAGE in $IMAGES; do
        trivy image --format json --severity HIGH,CRITICAL "$IMAGE" > /tmp/trivy-$$.json
        # POST to SentriKat API
        curl -X POST "$SENTRIKAT_URL/api/agent/container-scan" \
            -H "Authorization: Bearer $API_KEY" \
            -H "Content-Type: application/json" \
            -d @/tmp/trivy-$$.json
    done
fi
```

**Windows Agent (`sentrikat-agent-windows.ps1`):**
```powershell
# Similar logic for Docker Desktop on Windows
if (Get-Command docker -ErrorAction SilentlyContinue) {
    # Install Trivy via scoop or direct download
    # Scan images, POST results to API
}
```

#### Phase 2: Server-Side Processing (2-3 weeks)

New models:
- `ContainerImage` -- tracks Docker images across endpoints
- `ContainerVulnerability` -- maps Trivy findings to our VulnerabilityMatch model
- `SBOM` -- stores CycloneDX/SPDX documents

New API endpoints:
- `POST /api/agent/container-scan` -- receive Trivy scan results
- `GET /api/containers` -- list all container images
- `GET /api/containers/<id>/vulnerabilities` -- vulns for an image
- `GET /api/containers/<id>/sbom` -- download SBOM

Dashboard additions:
- Container inventory panel
- Container vulnerability statistics
- Image-to-CVE drill-down

#### Phase 3: CI/CD Integration (1-2 weeks)

- API endpoint for pipeline scan results
- Documentation for GitHub Actions, GitLab CI, Jenkins
- Optional pipeline gate (fail build if critical CVEs found)
- Webhook notifications for new container vulnerabilities

#### Phase 4: SBOM Management (1-2 weeks)

- Store SBOMs generated by Trivy (CycloneDX format)
- SBOM import API (accept external SBOMs)
- SBOM diff (track changes between image versions)
- SBOM export for compliance/regulatory requirements

### Cost: $0

Trivy is Apache-2.0. It's free. The agent downloads a ~50MB binary. Scans run locally. No cloud service needed. No API keys. No licensing.

---

## PART 3: OTHER HIGH-VALUE FEATURES TO STEAL FROM COMPETITORS

### 1. Patch Supersedence Logic (from Rapid7)

**What it is:** When a system has 47 missing patches, tell the admin "install these 3 patches and it fixes 41 of the 47 vulnerabilities." Rapid7's Remediation Hub does this automatically.

**Why it matters:** Reduces remediation effort by 80%+ for IT teams.

**How to implement:** We already have CPE version data and know which CVEs affect which version ranges. We can compute which single product update resolves the most CVEs.

**Effort:** 1-2 weeks. Use existing `ProductInstallation` + `VulnerabilityMatch` data.

**Priority: HIGH. Huge value, moderate effort.**

---

### 2. Vulnerability Exception Management (from Tenable/Qualys)

**What it is:** Formal workflow to accept risk on specific CVEs -- mark as "accepted risk," "false positive," or "mitigated by compensating control" with approval workflows and expiration dates.

**Why it matters:** Compliance teams need to document why certain CVEs are not remediated.

**How to implement:** New `VulnerabilityException` model with fields: CVE, reason, approved_by, expires_at, compensating_control. UI to create/approve/expire exceptions.

**Effort:** 1 week.

**Priority: HIGH. Already partially done via VendorFixOverride, needs formal exception workflow.**

---

### 3. Attack Path / Toxic Combination Visualization (from Wiz)

**What it is:** Don't just show "CVE-2024-1234 affects Apache." Show "CVE-2024-1234 + internet-facing + running as root + contains AWS credentials = critical attack path."

**Why it matters:** Context-aware risk is the future of vulnerability management.

**How to implement:** We'd need asset metadata (network exposure, privilege level, data sensitivity). Start simple: flag CVEs on internet-facing assets as higher priority.

**Effort:** 3-4 weeks for basic version. Long-term for full graph.

**Priority: MEDIUM. Differentiating but complex. Good for v2.0+.**

---

### 4. VEX Support (from Docker Scout / Grype)

**What it is:** Vulnerability Exploitability eXchange -- a standard format for declaring "this CVE doesn't affect us because we don't use the vulnerable function."

**Why it matters:** Reduces false positive noise. Becoming a standard (CISA promotes it).

**How to implement:** Accept VEX documents via API, auto-suppress matching CVEs. Similar to our existing VendorFixOverride but using the standard format.

**Effort:** 1-2 weeks.

**Priority: MEDIUM-HIGH. Standards compliance, reduces alert fatigue.**

---

### 5. Compliance Framework Mapping (from Qualys/Wiz)

**What it is:** Map each CVE to compliance controls: "CVE-2024-1234 violates NIST 800-53 SI-2, PCI DSS 6.3.3, NIS2 Article 21."

**How to implement:** Mapping table from CVE severity/type to framework controls. Start with NIST 800-53 and PCI DSS 4.0 (most requested).

**Effort:** 2-3 weeks for 2-3 frameworks.

**Priority: MEDIUM. Opens enterprise and EU market (NIS2/DORA).**

---

### 6. macOS Agent (Table Stakes)

**Who has it:** Tenable, Qualys, Rapid7, CrowdStrike -- all have macOS support.

**SentriKat gap:** Already on Q2 2026 roadmap. ~40% of developer endpoints run macOS.

**How to implement:** Bash agent using `pkgutil`, `brew list`, `system_profiler SPApplicationsDataType`.

**Effort:** 1 week (already planned).

**Priority: HIGH. Large blind spot in any modern organization.**

---

## PART 4: WHAT WE CAN DO RIGHT NOW (This Week)

### Immediate Actions (Zero or Minimal Code)

| # | Action | Effort | Impact |
|---|--------|--------|--------|
| 1 | **Add Trivy to the Linux agent** as an optional Docker scanning module | 3-5 days | Opens entire container scanning market |
| 2 | **Add a `/api/agent/container-scan` endpoint** to receive Trivy JSON output | 2-3 days | Server-side processing of container scans |
| 3 | **Add SBOM export** -- generate CycloneDX JSON from our existing product inventory data | 2-3 days | Compliance checkbox, regulatory requirement |
| 4 | **Add vulnerability exception workflow** -- extend VendorFixOverride with reason/expiry/approval | 2-3 days | Compliance teams need this |
| 5 | **Add patch supersedence logic** -- "install this one update to fix N CVEs" | 3-5 days | Massive UX improvement |
| 6 | **Update competitive positioning** -- add container scanning to feature comparison | 1 day | Marketing differentiation |

### Quick Wins (Under 1 Week Each)

| # | Feature | Inspired By | Effort |
|---|---------|-------------|--------|
| 7 | **VEX document import** -- accept VEX to suppress false positives | Docker Scout, Grype | 3-5 days |
| 8 | **Container image inventory page** in dashboard | All competitors | 2-3 days |
| 9 | **SBOM import API** (CycloneDX/SPDX) | Grype/Syft, Snyk | 3-5 days |
| 10 | **Remediation priority view** -- "top 10 updates that fix the most CVEs" | Rapid7 Remediation Hub | 2-3 days |

---

## PART 5: COMPETITIVE FEATURE MATRIX (UPDATED)

### Where SentriKat Stands Today vs. After Trivy Integration

| Capability | SentriKat Now | After Trivy | Tenable | Qualys | Rapid7 | Snyk |
|-----------|:---:|:---:|:---:|:---:|:---:|:---:|
| CISA KEV Native | **YES** | **YES** | No | No | No | No |
| Endpoint Scanning | **YES** | **YES** | YES | YES | YES | No |
| Container Image Scanning | **NO** | **YES** | YES | YES | Via add-on | YES |
| SBOM Generation | **NO** | **YES** | Limited | YES | Limited | YES |
| SBOM Import | **NO** | **YES** | No | YES | No | YES |
| IaC Scanning | **NO** | **YES** | YES | YES | YES | YES |
| Secret Detection | **NO** | **YES** | No | YES | No | No |
| Runtime Container Protection | **NO** | **NO** | No | YES | No | No |
| Vendor Backport Detection | **YES** | **YES** | No | No | No | No |
| Self-Hosted | **YES** | **YES** | YES | No | YES | No |
| 5-Minute Deploy | **YES** | **YES** | No | No | No | No |
| Price (100 endpoints) | **EUR 3,998** | **EUR 3,998** | $3,663 | $2,500 | $4,000 | $15,000+ |

**After Trivy integration, we go from 5/12 capabilities to 9/12 -- and the 3 we're missing (runtime protection, cloud discovery, advanced AI scoring) are enterprise-only features that aren't expected at our price point.**

---

## PART 6: STRATEGIC RECOMMENDATIONS

### Priority Order for Next 6 Months

```
MUST DO (Q2 2026)
├── 1. Trivy container image scanning via agents
├── 2. Container scan API endpoint + dashboard
├── 3. SBOM generation/export (CycloneDX)
├── 4. macOS agent
└── 5. Vulnerability exception workflow

SHOULD DO (Q3 2026)
├── 6. SBOM import API
├── 7. Patch supersedence / remediation priority
├── 8. VEX support
├── 9. CI/CD pipeline integration docs + API
└── 10. IaC misconfiguration scanning (via Trivy)

NICE TO DO (Q4 2026)
├── 11. Compliance framework mapping (NIST, PCI DSS, NIS2)
├── 12. Secret detection (via Trivy)
├── 13. Basic attack path visualization
└── 14. Kubernetes admission webhook
```

### The Story We Can Tell

**Before:** "SentriKat tracks CISA KEV vulnerabilities across your endpoints."

**After:** "SentriKat tracks CISA KEV vulnerabilities across your endpoints AND container images, generates SBOMs for compliance, and detects misconfigurations in your Dockerfiles -- all self-hosted, deployed in 5 minutes, at 1/5th the cost of Tenable."

That's a compelling pitch.

---

## APPENDIX: COMPETITOR QUICK REFERENCE

### Tenable
- **Best at:** Deepest vulnerability database (77,000+ CVEs, 450+ scan templates)
- **Weakest at:** Complexity, cost, slow to adopt CISA KEV focus
- **We can steal:** Vulnerability exception management workflow, compliance mapping

### Qualys
- **Best at:** Unified platform (scan → prioritize → patch), QScanner CLI, container security
- **Weakest at:** Cloud-only (no self-hosted), complex pricing, slow onboarding
- **We can steal:** QScanner-like CLI concept (Trivy fills this), TruRisk-like scoring approach

### Rapid7
- **Best at:** Remediation Hub with supersedence logic, exploit intelligence (Metasploit), Active Risk scoring
- **Weakest at:** Resource-heavy, expensive, complex setup
- **We can steal:** Patch supersedence logic, remediation prioritization view

### CrowdStrike
- **Best at:** Single-agent platform consolidation, ExPRT.AI scoring, scanless architecture
- **Weakest at:** Premium pricing, enterprise focus, limited self-hosted
- **We can steal:** The "scanless" concept (our agents already do this), AI-driven scoring approach

### Wiz
- **Best at:** Security Graph (toxic combinations), agentless cloud scanning, developer experience
- **Weakest at:** Cloud-only, no self-hosted, enterprise pricing, limited container depth
- **We can steal:** Toxic combination concept (vuln + exposure + privilege = real risk)

### Snyk
- **Best at:** Developer experience, IDE integration, Docker partnership, reachability analysis
- **Weakest at:** No endpoint scanning, no CISA KEV focus, complex pricing at scale
- **We can steal:** CI/CD integration patterns, developer-facing API documentation style

### Aqua Security
- **Best at:** Container runtime security (deepest), sandbox analysis (DTA), drift detection
- **Weakest at:** Expensive, complex deployment, narrow focus
- **We can steal:** Nothing directly -- their runtime protection requires deep kernel-level tech

### Trivy (Open Source)
- **Best at:** Free, fastest scanner, broadest scope (vulns + misconfigs + secrets + SBOM + IaC)
- **Weakest at:** No management UI, no remediation tracking, no multi-tenant
- **We can steal:** EVERYTHING. Trivy is the scanner; SentriKat is the management platform.

### Grype (Open Source)
- **Best at:** SBOM-first scanning, PURL scanning, VEX support, low false positives
- **Weakest at:** Narrow scope (vulns only), no caching, smaller community
- **We can steal:** VEX support pattern, SBOM-based scanning workflow

### Docker Scout
- **Best at:** Zero learning curve for Docker users, layer-by-layer analysis, automatic VEX
- **Weakest at:** Docker-only ecosystem, no runtime, limited scope
- **We can steal:** Layer-by-layer visualization concept for container dashboard

---

*Analysis based on public information as of February 2026. Competitor capabilities change frequently.*


---

## Part 4 — Pricing Strategy

# SENTRIKAT - PRICING STRATEGY
## Revenue Model & Pricing Framework

---

> **⚠️ POST SPRINT 5 PRICING UPDATE (April 2026)**
>
> This document describes the **original** pricing strategy from February 2026.
> After the Sprint 4 + Sprint 5 release (15 new features, including SBOM export,
> compliance gap analysis reports for PCI-DSS/ISO 27001/SOC 2, remediation
> assignments, vulnerability trending, Patch Tuesday automation), a price
> increase recommendation has been written up in
> **[`22_PRICING_ANALYSIS_POST_SPRINT_5.md`](./22_PRICING_ANALYSIS_POST_SPRINT_5.md)**.
>
> The proposed updated SaaS tiers are:
> - Free: €0 (unchanged)
> - Starter: €59/month (unchanged)
> - Pro: **€199 → €249/month**
> - Business: **€499 → €649/month**
> - Enterprise: **€999 → €1,499/month**
> - **NEW** Compliance Pack add-on: +€199/month (unlocks PCI-DSS / ISO 27001 / SOC 2 reports on any tier)
>
> Existing customers are grandfathered at the legacy price. See file 22 for
> margin analysis, break-even, and rollout plan.

---

## PRICING PHILOSOPHY

### Core Principles

1. **Simplicity**: Annual licensing with agent packs, no complex tiers
2. **Accessibility**: Free Demo tier for evaluation, affordable Professional
3. **Scalability**: Agent packs for growth, multi-year discounts
4. **Value Alignment**: Pay for what you use (agents)
5. **No Surprises**: Transparent, predictable costs in EUR

---

## PRICING TIERS

### Tier Structure

```
┌─────────────────────────────────────────────────────────────────────┐
│                         SENTRIKAT EDITIONS                          │
├─────────────────┬─────────────────────────────────────────────────-─┤
│      DEMO       │            PROFESSIONAL                           │
│     (Free)      │           EUR 4,999/year                          │
├─────────────────┼──────────────────────────────────────────────────-┤
│   5 Agents      │   10 Agents (expandable via agent packs)          │
│   1 User        │   Unlimited Users                                 │
│   1 Org         │   Unlimited Organizations                         │
│   50 Products   │   Unlimited Products                              │
├─────────────────┼──────────────────────────────────────────────────-┤
│ Basic Features  │  All Features: LDAP, Email Alerts, Webhooks,      │
│                 │  White-Label, API Access, Backup/Restore,          │
│                 │  Push Agents, Jira Integration, Compliance Reports │
└─────────────────┴──────────────────────────────────────────────────-┘
```

### Detailed Tier Comparison

| Feature | Demo | Professional |
|---------|------|-------------|
| **Price** | Free forever | EUR 4,999/year |
| **Agents** | 5 | 10 (expandable) |
| **Users** | 1 | Unlimited |
| **Organizations** | 1 | Unlimited |
| **Products** | 50 | Unlimited |
| **CISA KEV Sync** | Daily | Daily |
| **LDAP/AD** | - | ✓ |
| **SAML SSO** | - | ✓ |
| **Email Alerts** | - | ✓ |
| **Webhooks** | - | ✓ |
| **Jira Integration** | - | ✓ |
| **Scheduled Reports** | - | ✓ |
| **API Access** | - | ✓ |
| **Backup/Restore** | - | ✓ |
| **White-Label** | - | ✓ |
| **Push Agents** | - | ✓ |
| **Compliance Reports** | - | ✓ |

---

## AGENT PACKS (ADD-ONS)

### For Additional Scale

| Pack | Agents Added | Annual Price (EUR) |
|------|-------------|-------------------|
| +25 Agents | +25 | EUR 999/year |
| +50 Agents | +50 | EUR 1,499/year |
| +100 Agents | +100 | EUR 2,499/year |
| Unlimited Agents | Unlimited | EUR 3,999/year |

### Priority Support Add-on

| Add-on | Annual Price (EUR) | Details |
|--------|-------------------|---------|
| Priority Support | EUR 999/year | 4-hour response SLA |

### Example Configurations

| Customer Size | Base License | Agent Pack | Total Agents | Annual Cost (EUR) |
|---------------|-------------|------------|--------------|-------------------|
| Small IT Team | Professional | - | 10 | 4,999 |
| Growing Business | Professional | +25 | 35 | 5,998 |
| Medium Business | Professional | +50 | 60 | 6,498 |
| Large Business | Professional | +100 | 110 | 7,498 |
| Enterprise | Professional | Unlimited | Unlimited | 8,998 |
| Enterprise + Support | Professional | Unlimited + Priority | Unlimited | 9,997 |

---

## MULTI-YEAR DISCOUNTS

| Commitment | Discount | PRO Annual Price (EUR) | Total Savings |
|------------|----------|----------------------|---------------|
| 1 Year | Full price | EUR 4,999/year | - |
| 2 Years | 10% off | EUR 4,499/year | EUR 1,000 over 2 years |
| 3 Years | 15% off | EUR 4,249/year | EUR 2,250 over 3 years |

Multi-year discounts apply to the entire subscription (base + add-ons).

---

## PROFESSIONAL SERVICES

### One-Time Services

| Service | Price (EUR) | Description |
|---------|-------------|-------------|
| Quick Start Setup | 500 | 2-hour guided installation |
| LDAP Integration | 1,000 | AD/LDAP configuration |
| SAML SSO Setup | 1,000 | IdP integration |
| Migration Assistance | 2,000 | From competitor tools |
| Custom Training | 500/hr | On-site or remote |
| Security Audit | 5,000 | Architecture review |

### Ongoing Services

| Service | Monthly (EUR) | Description |
|---------|---------------|-------------|
| Managed Service | 500+ | We manage your instance |
| Dedicated TAM | 1,000 | Technical Account Manager |

---

## SPECIAL PROGRAMS

| Program | Discount | Eligibility |
|---------|----------|-------------|
| Startup | 50% | <EUR 5M funding, <50 employees |
| Non-Profit | 50% | Registered non-profit |
| Education | 75% | Accredited institutions |
| Government | Negotiated | Public sector |
| Partner/Reseller | 20-40% | Certified partners |

---

## COMPETITIVE PRICING ANALYSIS

### Price per 100 Agents (Annual)

| Vendor | Annual Cost (EUR) |
|--------|-------------------|
| SentriKat (PRO + 100-pack) | ~3,998 |
| Tenable.io | ~3,663 |
| Qualys VMDR | ~2,500 |
| Rapid7 InsightVM | ~4,000 |

### Value Positioning

- **On-premise**: Full data sovereignty, no cloud dependency
- **All-inclusive**: No per-scanner, per-module, or per-IP charges
- **Predictable**: Annual flat fee with optional agent packs
- **Self-hosted**: No recurring SaaS markup

---

## BILLING & PAYMENT

### Payment Methods

- Credit Card (Stripe) via portal.sentrikat.com
- ACH/Bank Transfer
- Invoice (Net 30, annual only)
- Wire Transfer (Enterprise)

### Billing Cycles

- Annual: All payment methods
- Multi-year: Invoice/wire only

### License Activation

- **Online**: Purchase on portal.sentrikat.com -> receive activation code -> enter in Admin Panel
- **Offline**: Copy Installation ID -> send to sales -> receive hardware-locked license key

### Overage Policy

- Soft limit: Warning at 80-90% of agent capacity
- Hard limit: New agents blocked until upgrade (existing agents unaffected)
- No retroactive billing

### Cancellation Policy

- Annual: Pro-rated refund first 30 days
- Multi-year: Per contract terms

---

## FINANCIAL PROJECTIONS

### Revenue Model Assumptions

| Metric | Year 1 | Year 2 | Year 3 |
|--------|--------|--------|--------|
| Demo Users | 500 | 2,000 | 5,000 |
| Demo -> Pro Conversion | 5% | 7% | 10% |
| Pro Customers | 25 | 140 | 500 |
| Avg. Contract Value (EUR) | 3,500 | 4,500 | 5,500 |
| Annual Recurring Revenue (EUR) | 87K | 630K | 2.75M |

### Customer Lifetime Value

| Metric | Value |
|--------|-------|
| Average Contract Value (ACV) | EUR 4,000 |
| Average Customer Lifetime | 3 years |
| Gross Margin | 85% |
| Customer Lifetime Value (LTV) | EUR 10,200 |

---

## IMPLEMENTATION TIMELINE

| Phase | Timing | Actions |
|-------|--------|---------|
| Launch | Now | Demo + Professional tiers with agent packs |
| Scale | Q2 2026 | Multi-year discount program |
| Enterprise | Q3 2026 | Custom enterprise pricing, SOW |
| Optimization | Ongoing | Adjust based on conversion data |

---

*All prices in EUR. Pricing is subject to change based on market conditions and customer feedback.*
*Last updated: February 2026*


---

## Part 5 — Pricing Analysis Post-Sprint 5

# SENTRIKAT — PRICING ANALYSIS POST SPRINT 4 + 5

**Data:** Aprile 2026
**Autore:** Analisi tecnica dopo completamento Sprint 4 + Sprint 5
**Scopo:** Decidere se mantenere o alzare i prezzi SaaS dopo l'aggiunta di 15+ feature nuove

---

## 1. STATO ATTUALE

### Prezzi SaaS attualmente hardcoded in `app/models.py:3718-3822`

| Tier | Prezzo mensile | Prezzo annuale | Agents | Users | Orgs | Note |
|---|---|---|---|---|---|---|
| **Free** | €0 | €0 | 3 | 1 | 1 | 25 prodotti, 100MB, 1 API key |
| **Starter** | €59 | €590 (-17%) | 10 | 3 | 1 | Prodotti illimitati, 500MB |
| **Pro** | €199 | €1.990 (-17%) | 25 | 5 | 3 | 2GB, 5 API keys |
| **Business** | €499 | €4.990 (-17%) | 50 | 10 | 10 | 10GB, 25 API keys |
| **Enterprise** | €999 | €9.990 (-17%) | ∞ | ∞ | ∞ | Tutto illimitato |

### Prezzo on-premise (docs/business/04_PRICING_STRATEGY.md)

- **Demo:** gratis, 5 agent, 1 utente
- **Professional:** €4.999/anno, 10 agent (espandibile via pack)

---

## 2. COSA È CAMBIATO CON SPRINT 4 + SPRINT 5

Aggiunte **15 feature nuove** di cui 7 competitive-parity verso Tenable/Qualys/Wiz:

### Sprint 4 (ship)
- ✅ **SBOM Export CycloneDX 1.5 + SPDX 2.3** (must-have per CRA EU + EO 14028 USA)
- ✅ **STIX 2.1 Export** (must-have per threat intel sharing, MISP/ISAC)
- ✅ **Remediation Assignments + SLA Policies** (ticketing interno con due dates)
- ✅ **Issue tracker integration** (Jira, YouTrack, GitHub, GitLab, Webhook)
- ✅ **Risk Exception Management** (accetta rischio con justification + expiry, ISO/SOC2 evidence)
- ✅ **Email notifications** per assignments con throttling per Resend free tier
- ✅ **Agent delta scan + gzip** (-90% banda)
- ✅ **Agent offline store-and-forward** (zero perdita dati su connessioni intermittenti)
- ✅ **Product alias/disambiguation**

### Sprint 5 (ship)
- ✅ **Vulnerability trending dashboard** (grafico temporale Chart.js)
- ✅ **Patch Tuesday automation** (digest email 2° mercoledì del mese)
- ✅ **PCI-DSS v4.0 gap analysis report** (Req 6.3, 11.3)
- ✅ **ISO/IEC 27001:2022 gap analysis report** (Annex A.8.8, A.8.16, A.5.24)
- ✅ **SOC 2 gap analysis report** (CC7.1, CC7.2, CC7.4, CC6.6)

### Già presenti (Sprint 1-3)
- ✅ Container scanning + lockfile dependency scanning
- ✅ CISA BOD 22-01 + EU NIS2 compliance reports
- ✅ Multi-tenant SaaS con isolamento
- ✅ LDAP, SAML SSO, SMTP, Webhook

**Totale feature aggiunte dal momento in cui i prezzi attuali sono stati fissati:** ~18

---

## 3. CONFRONTO VS COMPETITOR (mid-market EU, 50 asset)

| Prodotto | Prezzo annuale ~50 asset | Incluso |
|---|---|---|
| **Tenable.io** | €24.000 - €36.000 | VM scanning, no SBOM, no remediation workflows |
| **Qualys VMDR** | €18.000 - €30.000 | VM + cloud, niente SBOM export standard |
| **Rapid7 InsightVM** | €15.000 - €25.000 | VM + remediation tracking |
| **Wiz** | €50.000+ | Solo cloud, no on-prem |
| **CrowdStrike Spotlight** | €20.000+ | EDR-bundled, no SBOM |
| **Greenbone / OpenVAS** | €5.000 - €10.000 | Network scanning, tech debt |
| **Defender for Cloud (Microsoft)** | €15.000+ | Solo Azure ecosystem |
| **SentriKat Business (ATTUALE)** | **€4.990** | Tutto quello che hanno loro + SBOM + compliance + EU hosting |

### Verdetto onesto sul prezzo attuale

**Business €499/mese è 4-6x più economico di Tenable** a parità di capability (ora), e siamo l'unico che offre:
- SBOM export CycloneDX + SPDX + STIX out-of-the-box
- Compliance gap analysis reports (CISA, NIS2, PCI-DSS, ISO 27001, SOC 2) out-of-the-box
- Hosting EU GDPR-native
- On-premise + SaaS (dual deployment)
- Open API

**Il prezzo attuale è sottoprezzato per il valore consegnato.**

---

## 4. RACCOMANDAZIONE PREZZI

### Principio guida

**Non sotto-prezzare mai più del 40% sotto i competitor diretti.** Se sei 70% meno caro, il cliente enterprise pensa "qualcosa non va, questo non può funzionare davvero". Il prezzo è un segnale di qualità.

Ma **mantieni il vantaggio sotto Tenable** per vincere sul mid-market che non si può permettere Tenable.

### Proposta nuova pricing (da applicare prima del lancio commerciale)

| Tier | ATTUALE | **NUOVO** | Δ | Ragionamento |
|---|---|---|---|---|
| **Free** | €0 | **€0** | = | Acquisition funnel. Non toccare. |
| **Starter** | €59 | **€59** | = | Prezzo d'ingresso per PMI. Non toccare. |
| **Pro** | €199 | **€249** | +25% | Giustificato da SBOM + assignments + trending + issue tracker + risk exceptions |
| **Business** | €499 | **€649** | +30% | Giustificato da compliance reports PCI/ISO/SOC2 (questo solo vale €200/mese) |
| **Enterprise** | €999 | **€1.499** | +50% | Unlimited + SLA garantito + priority support. Ancora 10x sotto Tenable |
| **NEW: Compliance Pack** | — | **+€199/mese** | — | Add-on opzionale su qualsiasi tier per sbloccare PCI-DSS/ISO 27001/SOC 2 reports |

### Grandfathering

**Regola fondamentale:** chi ha già un abbonamento attivo resta sul prezzo vecchio **per sempre** (o minimo 24 mesi). Questo è etico, riduce churn, e crea advocacy.

Nel codice: aggiungi campo `SubscriptionPlan.legacy_price` e logica in `licensing.py` per preservare il prezzo di iscrizione iniziale.

### Cosa succede al ricavo atteso

Con 100 clienti distribuiti realisticamente:
- 40 Free (€0) → €0
- 30 Starter (€59) → €1.770/mese
- 20 Pro (€249) → €4.980/mese (prima €3.980, **+€1.000**)
- 8 Business (€649) → €5.192/mese (prima €3.992, **+€1.200**)
- 2 Enterprise (€1.499) → €2.998/mese (prima €1.998, **+€1.000**)
- **Totale MRR:** €14.940/mese (prima €11.740, **+€3.200/mese = +27%**)
- **Totale ARR:** €179.280/anno (prima €140.880, **+€38.400/anno**)

**+27% di MRR senza aggiungere un singolo cliente**, solo riconoscendo il valore delle feature nuove.

### Perché funziona

1. **Lo sconto annuale resta a -17%** → incentivo forte a pagare annuale = meglio cashflow
2. **Free e Starter invariati** → zero friction sull'acquisizione
3. **Pro aumenta di soli €50/mese** → pochi churn su cliente attivo
4. **Business +€150/mese** giustificato da compliance reports (singolo report PCI-DSS costerebbe €2.000+ con consulente)
5. **Enterprise +€500/mese** → chi compra Enterprise non guarda la differenza
6. **Compliance Pack** come add-on = revenue stream aggiuntivo su tier bassi

---

## 5. POSSIAMO PERMETTERCELO? (COSTI)

### Costi variabili per cliente attivo (stima)

| Voce | Costo/mese per cliente attivo |
|---|---|
| Hosting VPS shared (DigitalOcean/Hetzner, condiviso fra molti org) | €0,50 - €2 |
| DB PostgreSQL (stesso) | €0,30 - €1 |
| CDN + static assets | €0,05 |
| Resend email (100 free, poi Pro €20 per 50k) | €0,02 - €0,40 |
| NVD/CISA sync (gratis) | €0 |
| Support tempo umano (stima 15 min/mese su Starter, 30 su Pro, 1h su Business) | €5 - €30 |
| **TOTALE COGS stimato** | **€6 - €35/mese per cliente** |

### Margini lordi

| Tier | Prezzo nuovo | COGS stimato | Margine lordo | % margine |
|---|---|---|---|---|
| Starter | €59 | €8 | €51 | 86% |
| Pro | €249 | €18 | €231 | 93% |
| Business | €649 | €40 | €609 | 94% |
| Enterprise | €1.499 | €80 | €1.419 | 95% |

**Margini software-tipici (85-95%)**. Scalabile. Sì, puoi permetterti questi prezzi.

### Investimento necessario per sostenere il lancio

| Voce | One-time | Mensile |
|---|---|---|
| Infrastruttura EU (Hetzner, 2 server prod + 1 staging) | €0 | €150 |
| Stripe setup + fees (~3% sulle transazioni) | €0 | ~3% MRR |
| Dominio + email (Fastmail/Google Workspace) | €50 | €12 |
| Legal review TOS/Privacy | €800 - €2.000 | €0 |
| Marchio EUIPO | €850 (1 classe) | €0 |
| P.IVA + commercialista | €400 | €120 |
| Sito marketing (Framer/Webflow template + customization) | €0 - €500 | €25 |
| **TOTALE** | **~€2.500** | **~€450 + fees** |

### Break-even

Con i prezzi nuovi, bastano **1 Business + 2 Pro** per coprire tutti i costi fissi mensili (€649 + €498 = €1.147 vs €450). **Break-even a 3 clienti paganti.** Molto raggiungibile.

---

## 6. QUANDO APPLICARE L'AUMENTO

**Timing consigliato:**

1. **Settimana 1-2:** Chiudi bugfixing + full test (vedi `PRE_LAUNCH_BUGFIX_AND_TEST_PLAN.md`)
2. **Settimana 3:** Deploy production + dominio + Stripe in live mode
3. **Settimana 4:** Aggiorna il sito con i nuovi prezzi + pubblica feature page Sprint 4+5 + blog post
4. **Settimana 5:** Primi invii cold (vedi `21_SALES_CAMPAIGN_STARTER_PACK.md`)
5. **Settimana 6+:** Iterazioni sulla base del feedback

**NON cambiare i prezzi dopo aver già venduto a clienti al prezzo vecchio**, a meno di grandfathering rigoroso.

---

## 7. AZIONI CONCRETE DA FARE NEL CODICE

Prima di cambiare i prezzi in produzione:

1. `app/models.py:3718-3822` — aggiornare `DEFAULT_PLANS`:
   ```python
   # Pro: 19900 → 24900 (€199 → €249)
   # Business: 49900 → 64900 (€499 → €649)
   # Enterprise: 99900 → 149900 (€999 → €1499)
   ```
2. Aggiungere campo `legacy_price_monthly_cents` per grandfathering
3. `app/licensing.py` — aggiungere `compliance_pack` add-on feature key
4. Creare endpoint `POST /api/billing/upgrade-to-compliance-pack`
5. Stripe: creare Price ID per ogni nuovo prezzo + un Price ID per Compliance Pack (€199/mese)
6. Sito: aggiornare pagina pricing (vedi `20_SPRINT_4_5_WEB_BRIEF.md`)
7. Email ai clienti esistenti: "Stiamo aggiornando i prezzi, tu resti sul vecchio per sempre"

---

## 8. RISCHI DELL'AUMENTO

| Rischio | Mitigazione |
|---|---|
| Churn su clienti esistenti | Grandfathering rigoroso, comunicazione chiara |
| Prospect si spaventa del prezzo più alto | Enfatizza il confronto con Tenable (siamo ancora 5x più economici) |
| Competitor ci accusa di averci aumentato | Risposta: "Abbiamo aggiunto 15 feature, il prezzo riflette il valore nuovo" |
| Resend quota esaurita se Business fa troppe email | Già risolto con throttling Sprint 4 (max 1 email per assignment/ora) |

---

## 9. DECISIONE FINALE

**Raccomandazione:** ALZARE i prezzi come da proposta sopra, con grandfathering rigoroso per clienti esistenti. Lanciare con i prezzi nuovi sul sito dal giorno 1 del lancio commerciale.

**Expected outcome:**
- MRR +27% a parità di clienti
- ARR +€38k/anno
- Margini lordi al 90%+
- Break-even a 3 clienti paganti
- Ancora 4-8x più economici di Tenable/Qualys/Rapid7

**Se il rialzo non ti convince → tieni Starter e Pro invariati, alza solo Business → €599 e Enterprise → €1.299.** Sarebbe un aumento minimo che comunque copre il valore di PCI-DSS/ISO/SOC 2 reports.


---

## Part 6 — Go-to-Market

# SENTRIKAT - GO-TO-MARKET STRATEGY
## Launch & Growth Plan 2026

---

## EXECUTIVE SUMMARY

SentriKat's go-to-market strategy focuses on capturing the underserved mid-market segment of vulnerability management through:
1. **Product-Led Growth**: Free Demo tier drives awareness
2. **Content Marketing**: Thought leadership on CISA compliance
3. **Community Building**: Security professionals network
4. **Partner Channels**: MSSPs and consultancies

---

## TARGET MARKET SEGMENTATION

### Primary Target: Mid-Market IT Teams

| Attribute | Description |
|-----------|-------------|
| Company Size | 100-5,000 employees |
| IT Team Size | 3-20 people |
| Security Budget | $50K-500K/year |
| Pain Point | CISA compliance, vulnerability tracking |
| Decision Maker | CISO, IT Director, Security Manager |
| Influencer | Security Analyst, Sys Admin |

### Secondary Target: MSSPs/Consultancies

| Attribute | Description |
|-----------|-------------|
| Type | Managed Security Service Providers |
| Client Base | 10-100 SMB clients |
| Pain Point | Scalable vuln mgmt for clients |
| Opportunity | White-label, multi-tenant |

### Tertiary Target: Regulated Industries

| Industry | Driver |
|----------|--------|
| Healthcare | HIPAA, patient data protection |
| Finance | PCI-DSS, SOX compliance |
| Government | CISA BOD 22-01 mandate |
| Defense | CMMC requirements |

---

## VALUE PROPOSITION

### For IT/Security Teams

> "Track and remediate vulnerabilities in minutes, not months. SentriKat auto-discovers your software, matches it against 6+ intelligence sources (CISA KEV, NVD, CVE.org, ENISA EUVD, EPSS, OSV), and alerts you before due dates."

### For C-Level/Compliance

> "Demonstrate CISA BOD 22-01 and NIS2 compliance with automated tracking, European vulnerability intelligence (ENISA EUVD), reports, and audit trails. No expensive enterprise tools required."

### For MSSPs

> "Manage vulnerability posture across all clients from one platform. White-label branding, multi-tenant architecture, scalable pricing."

---

## COMPETITIVE POSITIONING

```
                     HIGH PRICE
                         │
        ┌────────────────┼────────────────┐
        │   Tenable      │                │
        │   Qualys       │                │
        │   Rapid7       │                │
COMPLEX │────────────────┼────────────────│ SIMPLE
        │                │                │
        │   OpenVAS      │  ★ SENTRIKAT   │
        │                │                │
        └────────────────┼────────────────┘
                         │
                     LOW PRICE
```

**Positioning Statement:**

For mid-market security teams who need CISA compliance without enterprise complexity, SentriKat is the vulnerability management platform that automatically tracks software and vulnerabilities with minimal setup. Unlike Tenable or Qualys, SentriKat is affordable, simple to deploy, and focused on what matters: knowing your exposure and meeting deadlines.

---

## LAUNCH PHASES

### Phase 1: Foundation (Q1 2026) ✅ COMPLETE

| Activity | Status |
|----------|--------|
| Product MVP | ✅ Done |
| Documentation | ✅ Done |
| Portal/License Server | ✅ Done |
| CI/CD Pipeline | ✅ Done |

### Phase 2: Soft Launch (Q2 2026)

| Week | Activity | Goal |
|------|----------|------|
| 1-2 | Launch website with demo | 100 demo signups |
| 3-4 | Publish blog content | SEO foundation |
| 5-6 | LinkedIn outreach | 50 qualified leads |
| 7-8 | First 5 paying customers | $5K MRR |
| 9-10 | Case study creation | 2 testimonials |
| 11-12 | Iterate based on feedback | Product improvements |

### Phase 3: Growth (Q3-Q4 2026)

| Activity | Goal |
|----------|------|
| Content marketing scale | 5 articles/month |
| SEO optimization | Top 10 for "CISA KEV software" |
| Paid advertising | $2K/month test budget |
| Conference presence | 2 security conferences |
| Partner program launch | 5 MSSP partners |
| 50 paying customers | $25K MRR |

### Phase 4: Scale (2027)

| Activity | Goal |
|----------|------|
| Inside sales hire | 1-2 SDRs |
| Marketing automation | Nurture campaigns |
| Enterprise sales motion | 5 enterprise deals |
| International expansion | EU market entry |
| 200 customers | $100K MRR |

---

## MARKETING CHANNELS

### Organic (High Priority)

| Channel | Tactics | Cost |
|---------|---------|------|
| SEO/Blog | CISA compliance guides, how-tos | Time |
| LinkedIn | Personal brand, posts, articles | Time |
| Twitter/X | Security community engagement | Time |
| GitHub | Open-source agent scripts | Time |
| YouTube | Product demos, tutorials | Time |

### Community (Medium Priority)

| Channel | Tactics | Cost |
|---------|---------|------|
| Reddit | r/cybersecurity, r/sysadmin | Time |
| Discord | Security communities | Time |
| Slack | DFIR, Security Ops | Time |
| Meetups | Local security groups | Time |

### Paid (Lower Priority Initially)

| Channel | Tactics | Budget |
|---------|---------|--------|
| Google Ads | "vulnerability management software" | $1-2K/mo |
| LinkedIn Ads | Targeted by title/industry | $1-2K/mo |
| Sponsorships | Newsletters, podcasts | $500-1K/mo |
| Conferences | Booths at BSides, regional events | $2-5K/event |

---

## CONTENT STRATEGY

### Pillar Content (Long-form)

| Topic | Format | Purpose |
|-------|--------|---------|
| CISA BOD 22-01 Complete Guide | eBook | Lead magnet |
| Vulnerability Management Buyer's Guide | Whitepaper | Lead magnet |
| From OpenVAS to Enterprise: Migration Guide | Blog series | SEO |
| Building a Vuln Mgmt Program | Video course | Authority |

### Supporting Content (Weekly)

| Type | Frequency | Topics |
|------|-----------|--------|
| Blog posts | 2/week | How-tos, news, tips |
| LinkedIn posts | Daily | Insights, engagement |
| Newsletter | Weekly | Curated vuln news |
| YouTube | 2/month | Demos, tutorials |

### SEO Keyword Targets

| Keyword | Volume | Difficulty | Priority |
|---------|--------|------------|----------|
| vulnerability management software | 1.2K | High | Long-term |
| cisa kev tracking | 500 | Low | High |
| cisa bod 22-01 compliance | 300 | Medium | High |
| open source vulnerability scanner | 800 | Medium | Medium |
| tenable alternative | 200 | Low | High |
| qualys competitor | 150 | Low | High |

---

## SALES PROCESS

### Sales Motion

```
AWARENESS → INTEREST → DEMO → TRIAL → PURCHASE → EXPAND
    │          │         │       │         │         │
    │          │         │       │         │         │
 Content    Webinar   Sales    30-day   Close     Upsell
 Ads        Lead     Call     Free      Deal      Agent
 SEO        Magnet   Demo     Trial              Packs
```

### Lead Qualification (BANT)

| Criteria | Questions |
|----------|-----------|
| Budget | "What's your security tool budget?" |
| Authority | "Who makes purchasing decisions?" |
| Need | "How do you track vulnerabilities today?" |
| Timeline | "When do you need a solution in place?" |

### Sales Cycle by Segment

| Segment | Cycle | Deal Size |
|---------|-------|-----------|
| SMB (<100) | 2 weeks | $1-3K |
| Mid-Market | 4-6 weeks | $5-15K |
| Enterprise | 3-6 months | $50K+ |

### Demo Script Outline

1. **Discovery** (5 min): Current process, pain points
2. **Problem Validation** (3 min): CISA compliance challenges
3. **Solution Demo** (15 min): Dashboard, matching, alerts
4. **Integration** (5 min): Jira, LDAP, agents
5. **Pricing/Next Steps** (5 min): Quote, trial setup

---

## PARTNER STRATEGY

### Partner Types

| Type | Value to SentriKat | Value to Partner |
|------|-------------------|------------------|
| MSSP | Distribution, reach | New service offering |
| VAR | Enterprise sales | Margin, sticky customers |
| SI | Implementation services | Billable hours |
| Tech Partner | Integration value | Customer retention |

### Partner Program Tiers

| Tier | Requirements | Benefits |
|------|--------------|----------|
| Registered | Sign up | 10% referral fee |
| Silver | 3 deals/year | 20% discount, co-marketing |
| Gold | 10 deals/year | 30% discount, leads, training |
| Platinum | 25+ deals/year | 40% discount, dedicated support |

### Target Partners

| Partner Type | Example Companies |
|--------------|-------------------|
| MSSPs | Regional security firms |
| Security Consultancies | Pen test firms |
| IT Service Providers | MSPs with security practice |
| Compliance Consultants | SOC 2, HIPAA specialists |

---

## METRICS & KPIs

### Marketing Metrics

| Metric | Q2 2026 Target | Q4 2026 Target |
|--------|----------------|----------------|
| Website visitors | 5K/month | 25K/month |
| Demo signups | 100/month | 500/month |
| MQLs | 50/month | 200/month |
| SQLs | 20/month | 75/month |
| Blog traffic | 2K/month | 15K/month |

### Sales Metrics

| Metric | Q2 2026 Target | Q4 2026 Target |
|--------|----------------|----------------|
| Deals closed | 5 | 50 |
| Win rate | 25% | 35% |
| Average deal size | $3K | $5K |
| Sales cycle | 4 weeks | 3 weeks |
| MRR | $5K | $25K |

### Product Metrics

| Metric | Q2 2026 Target | Q4 2026 Target |
|--------|----------------|----------------|
| Demo → Paid conversion | 5% | 10% |
| Trial → Paid conversion | 25% | 40% |
| Monthly churn | <5% | <3% |
| NPS | 30 | 50 |
| Feature adoption | 60% | 80% |

---

## BUDGET ALLOCATION

### Q2 2026 (Seed/Bootstrap)

| Category | Budget | % |
|----------|--------|---|
| Content creation | $2K | 40% |
| Paid ads (test) | $1K | 20% |
| Tools (email, analytics) | $500 | 10% |
| Conference/events | $1K | 20% |
| Miscellaneous | $500 | 10% |
| **Total** | **$5K** | 100% |

### Q3-Q4 2026 (Growth)

| Category | Budget | % |
|----------|--------|---|
| Content & SEO | $5K/mo | 25% |
| Paid acquisition | $5K/mo | 25% |
| Tools & software | $2K/mo | 10% |
| Events & conferences | $3K/mo | 15% |
| Partner development | $2K/mo | 10% |
| PR & analyst relations | $2K/mo | 10% |
| Reserve | $1K/mo | 5% |
| **Total** | **$20K/mo** | 100% |

---

## COMPETITIVE RESPONSES

### If Asked About Tenable

> "Tenable is great for large enterprises with dedicated security teams. SentriKat is built for mid-market: simpler, focused on CISA compliance, and 1/10th the cost. If you don't need active scanning, we're a better fit."

### If Asked About OpenVAS

> "OpenVAS requires significant expertise and time to set up and maintain. SentriKat deploys in 5 minutes with push agents. We're commercial software with support, so you're not on your own."

### If Asked About Feature X Missing

> "That's on our roadmap. For now, we focus on the 80% of features that solve 100% of CISA compliance. Would that core functionality work for your immediate needs?"

---

## RISK MITIGATION

| Risk | Mitigation |
|------|------------|
| Low awareness | Heavy content marketing, SEO |
| Long sales cycles | Free trial, self-service |
| Enterprise competition | Avoid direct competition, focus on value |
| Feature gaps | Clear roadmap, prioritize customer requests |
| Support scalability | Strong documentation, community |

---

## 90-DAY LAUNCH CHECKLIST

### Week 1-2: Pre-Launch
- [ ] Website live with demo download
- [ ] Stripe billing integration
- [ ] License server operational
- [ ] Email sequences set up
- [ ] Analytics tracking (Plausible/GA4)

### Week 3-4: Soft Launch
- [ ] Announce on LinkedIn
- [ ] Submit to Product Hunt
- [ ] Post to r/cybersecurity
- [ ] Launch email to beta list
- [ ] Press release to security outlets

### Week 5-8: Content Ramp
- [ ] Publish 4 blog posts
- [ ] Create comparison pages
- [ ] Record product demo video
- [ ] Launch newsletter
- [ ] Guest post outreach

### Week 9-12: Sales Focus
- [ ] First 5 paying customers
- [ ] Gather testimonials
- [ ] Refine sales pitch
- [ ] Partner outreach begins
- [ ] Plan Q3 activities

---

*This GTM strategy should be reviewed and updated monthly based on market feedback and results.*
