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
