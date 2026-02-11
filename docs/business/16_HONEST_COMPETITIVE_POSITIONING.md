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

**2. Vendor Backport Detection (Unique Feature)**

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

**3. No SBOM Import/Export (Yet)**

SBOM (Software Bill of Materials) is becoming a regulatory requirement under EU Cyber Resilience Act and US Executive Order 14028. We don't support CycloneDX or SPDX import yet.

**Planned:** Q3 2026 (via Trivy integration which generates SBOMs natively).

**4. No NIS2/DORA Compliance Mapping**

We track CISA BOD 22-01 compliance but don't map to NIS2, DORA, PCI-DSS, ISO 27001, or NIST frameworks. For EU customers, NIS2 mapping is increasingly expected.

**How to position:** Frame CISA KEV tracking as a component of NIS2 Article 21 compliance (vulnerability handling). Add NIS2 framework mapping by Q4 2026.

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

Things a customer would expect from an "enterprise vulnerability management platform" that we don't have:

1. **Compliance reporting beyond CISA BOD 22-01** — No NIS2, DORA, PCI-DSS, ISO 27001 reports
2. **Executive dashboards** — Basic stats exist, but no C-level presentation mode
3. **Scheduled compliance reports** — Framework exists in code (ScheduledReport model) but needs refinement
4. **Data retention policies** — No configurable data lifecycle management
5. **Formal SLA** — SLA document exists in business docs but no SLA enforcement in product
6. **Customer documentation** — docs.sentrikat.com is referenced but quality unknown

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
