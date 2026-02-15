# Multi-Source Vulnerability Intelligence Architecture
## Marketing & Website Brief

**Date:** February 2026
**Purpose:** Copy-paste brief for the marketing/website team to update messaging, landing pages, and sales materials.

---

## WHY WE DID THIS

SentriKat previously relied on a single data source (the US NIST NVD) for CVSS scores, CPE version data, and vulnerability enrichment. This created:

1. **Single point of failure** -- when NVD goes down (which happens regularly), CVSS enrichment stops entirely
2. **US government dependency** -- a Swiss product depending 100% on a US federal agency with documented funding instability
3. **Coverage gaps** -- as of 2025-2026, 44% of CVEs added to NVD had no enrichment data (no CVSS, no CPE, no CWE) due to the ongoing NVD backlog crisis
4. **Regulatory risk** -- NIS2 directive explicitly mandates European vulnerability databases; customers in regulated sectors increasingly require European data sovereignty

## WHAT WE IMPLEMENTED

### Multi-Source CVSS Fallback Chain

SentriKat now fetches vulnerability severity scores from three independent sources in a priority-based fallback chain:

```
NVD API 2.0 (NIST)
    |
    +--> miss? --> CVE.org + CISA Vulnrichment (ADP)
                       |
                       +--> miss? --> ENISA EUVD (EU)
```

- **Primary**: NIST NVD API 2.0 -- the most complete CVSS enrichment source
- **Secondary**: CVE.org with CISA Vulnrichment (ADP containers) -- CVSS scores are now embedded directly in the CVE record by CISA, bypassing NVD entirely
- **Tertiary**: ENISA European Vulnerability Database (EUVD) -- the NIS2-mandated EU vulnerability database launched in 2025

Every CVSS score now carries a `cvss_source` provenance tag (nvd, cve_org, or euvd) so customers know exactly where the data came from.

### ENISA EUVD Exploited Vulnerabilities

The EUVD maintains its own "exploited vulnerabilities" list -- the European equivalent of CISA KEV. SentriKat now cross-references this during every sync cycle, adding European exploit intelligence to complement the US-centric CISA KEV catalog.

### NVD Connectivity Monitoring

A real-time notification banner now alerts administrators when the NVD API is unreachable, timed out, or rate-limited. The footer also shows live NVD service status with a color-coded LED indicator.

### Full Data Source Attribution

The application footer now properly attributes all data sources with links:
- CISA KEV | NVD | CVE.org | ENISA EUVD | EPSS | OSV

---

## ALL DATA SOURCES (Complete List)

| Source | What It Provides | License | Cost |
|--------|-----------------|---------|------|
| **CISA KEV** | Exploited vulnerability catalog with remediation deadlines | CC0 (Public Domain) | Free |
| **NIST NVD** | CVSS scores, CPE product/version data | CVE Terms of Use | Free |
| **CVE.org + Vulnrichment** | CVE records with CISA-provided CVSS enrichment | CVE-TOU + CC0 | Free |
| **ENISA EUVD** | European vulnerability database, exploited vulns | ENISA IPR (CC-BY-4.0) | Free |
| **FIRST EPSS** | Exploit probability prediction scores | Free (attribution) | Free |
| **OSV.dev** | Open-source vulnerability advisories | CC-BY-4.0 / CC0 | Free |
| **Red Hat Security** | RHEL/CentOS/Rocky fix status | Free API | Free |
| **Microsoft MSRC** | Windows/Office patch data (KB articles) | Free API | Free |
| **Debian Tracker** | Debian package fix status | Free | Free |

All sources are free, legally cleared for commercial use, and require only attribution (which we provide in the footer).

---

## WEBSITE / MARKETING COPY

### Headline Options (pick one)

1. "Multi-Source Vulnerability Intelligence. No Single Point of Failure."
2. "6 Data Sources. One Dashboard. Zero Blind Spots."
3. "European Vulnerability Intelligence Built Into Every Scan."

### Feature Block (for features page / landing page)

**Multi-Source Vulnerability Intelligence**

SentriKat aggregates vulnerability data from 6+ authoritative sources across the US and Europe -- not just one government database. When one source is unavailable, the system automatically falls back to the next.

- **CISA KEV** -- actively exploited vulnerabilities with remediation deadlines
- **NIST NVD** -- CVSS severity scores and CPE version matching
- **CVE.org + CISA Vulnrichment** -- vendor-provided and CISA-enriched CVE data
- **ENISA EUVD** -- the EU's own vulnerability database (NIS2-mandated)
- **FIRST EPSS** -- machine-learning exploit probability predictions
- **OSV.dev + vendor feeds** -- vendor-specific patch detection for 4 ecosystems

Every data point carries provenance tracking so you always know where the intelligence came from.

### NIS2 / European Sovereignty Block (for NIS2 landing page)

**Built for European Compliance**

SentriKat integrates the ENISA European Vulnerability Database (EUVD) -- the official NIS2-mandated vulnerability database for the EU. This means:

- Vulnerability data sourced from European infrastructure, not just US government APIs
- Cross-referencing of EUVD exploited vulnerabilities alongside CISA KEV
- Data provenance tracking for audit trails
- Self-hosted deployment keeps all data within your infrastructure

For organizations subject to NIS2, DORA, or the Cyber Resilience Act, SentriKat provides European vulnerability intelligence without vendor lock-in to US cloud services.

### Competitive Comparison Block

| Capability | SentriKat | Tenable | Qualys | OpenVAS |
|------------|-----------|---------|--------|---------|
| Multi-source CVSS enrichment | 3 sources with fallback | Single source | Single source | Single source |
| European EUVD integration | Native | No | No | Partial |
| CISA KEV native | Yes | Filter only | Filter only | No |
| NVD outage resilience | Auto-fallback | Degraded | Degraded | Degraded |
| Data provenance tracking | Per-CVE source tag | No | No | No |
| Self-hosted / air-gap | Yes | No | No | Yes |
| EPSS exploit prediction | Built-in | Add-on | Add-on | No |
| Vendor backport detection | 4 feeds, 3-tier confidence | Basic | Basic | No |

### One-Liner for Pitch Decks

"SentriKat is the only vulnerability management platform with a multi-source intelligence architecture that automatically falls back across NVD, CVE.org, and the EU's ENISA EUVD -- so you're never blind when one source goes down."

### For the "How It Works" Section

```
Step 1: Agents discover installed software
Step 2: CISA KEV + EUVD identify exploited vulnerabilities
Step 3: Multi-source enrichment (NVD → CVE.org → EUVD) adds CVSS scores
Step 4: Vendor advisory feeds (OSV, Red Hat, MSRC, Debian) detect patches
Step 5: Alerts fire via email, Slack, Teams, or Jira
```

---

## BLOG POST TOPICS (for SEO / thought leadership)

1. "Why We Stopped Trusting a Single Vulnerability Database" -- story of NVD backlog crisis and our multi-source solution
2. "ENISA EUVD: What European Companies Need to Know" -- educational piece on the new EU vulnerability database
3. "NVD Is Broken: Here's What We Did About It" -- technical deep-dive on the fallback architecture
4. "From CISA KEV to ENISA EUVD: Vulnerability Management for NIS2" -- compliance angle targeting EU buyers
5. "The Hidden Risk in Your Vulnerability Scanner: Single-Source Dependency" -- thought leadership targeting security pros

---

## SOCIAL MEDIA / LINKEDIN POSTS

**Post 1 (announcement):**
> We just shipped multi-source vulnerability intelligence in SentriKat.
>
> Instead of depending on a single government database (NVD) that's been in crisis since 2024, we now pull CVSS scores from 3 independent sources: NVD, CVE.org/Vulnrichment, and the EU's ENISA EUVD.
>
> If one goes down, the next picks up automatically. Every score carries a provenance tag so you know exactly where it came from.
>
> This is what vulnerability management should look like in 2026.

**Post 2 (NIS2 angle):**
> NIS2 mandates European vulnerability databases (Article 12).
>
> We integrated the ENISA EUVD directly into SentriKat -- not as an afterthought, but as a core data source in our multi-source fallback chain.
>
> For EU-regulated companies, this matters: your vulnerability intelligence doesn't depend on a single US federal agency anymore.

---

*This brief is for internal use. Hand to the marketing/website team for implementation.*
