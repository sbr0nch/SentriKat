# SENTRIKAT - COMPETITOR GAP ANALYSIS & INTEGRATION ROADMAP
## What Competitors Do Better & What We Can Steal

---

**Document Version:** 1.0
**Date:** February 2026
**Purpose:** Honest gap analysis against Tenable, Qualys, Rapid7, CrowdStrike, Wiz, Snyk, Aqua Security, and open-source tools (Trivy, Grype, Docker Scout). Prioritized list of features we can integrate now vs. later.

---

## EXECUTIVE SUMMARY

SentriKat has a strong niche: CISA KEV-focused vulnerability management for mid-market, self-hosted, with fast deployment and low cost. But competitors have capabilities we're entirely missing -- particularly **container/image scanning**, **SBOM management**, **agentless cloud discovery**, and **developer-facing workflows**. The good news: much of this can be integrated using open-source tools (Trivy, Grype, Syft) without building from scratch.

---

## PART 1: WHAT COMPETITORS DO BETTER THAN US

### 1. Container & Docker Image Scanning (We Have: NOTHING)

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

**SentriKat gap:** We scan installed software on endpoints. We don't touch containers at all. For any organization running Docker or Kubernetes (which is most of our target market in 2026), we're blind to an entire attack surface.

**Verdict: CRITICAL gap. Must address.**

---

### 2. SBOM Generation & Import (We Have: NOTHING)

**Who does it:** Trivy, Grype/Syft, Snyk, Docker Scout, Qualys, Wiz, CrowdStrike

SBOMs (Software Bill of Materials) in CycloneDX or SPDX format are becoming a regulatory requirement (US Executive Order 14028, EU Cyber Resilience Act). Competitors can:
- Generate SBOMs from container images, filesystems, and repositories
- Import SBOMs and scan them for vulnerabilities
- Track SBOM drift over time

**SentriKat gap:** We have no SBOM support at all. We track installed software via agents but can't produce or consume standard SBOM formats.

**Verdict: HIGH gap. Already on Q3 2026 roadmap. Should accelerate.**

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

### 7. Remediation Workflows (We Have: BASIC)

**Who does it better:**
- **Rapid7 Remediation Hub:** Intelligent supersedence logic (finds the ONE patch that fixes the most vulns), asset-group-based prioritization
- **CrowdStrike Charlotte SOAR:** AI agents that auto-create tickets, trigger patch management, fix misconfigs
- **Qualys VMDR:** Integrated patch deployment directly from the vulnerability management console

**SentriKat current state:** We track due dates, send alerts, create Jira tickets. But we don't suggest which single patch to deploy first, and we don't integrate with patch management tools.

**Verdict: MEDIUM gap. Supersedence logic (Rapid7-style) would be very valuable and relatively easy to build since we already have CPE version data.**

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

### 10. Compliance Framework Mapping (We Have: CISA BOD 22-01 ONLY)

**Who does it:** Qualys (100+ frameworks), Wiz (100+ frameworks), Tenable, CrowdStrike

Mapping vulnerabilities to NIST 800-53, CIS Benchmarks, PCI DSS 4.0, HIPAA, ISO 27001, SOC 2, NIS2, DORA, etc.

**SentriKat gap:** We're laser-focused on CISA BOD 22-01 compliance. This is a strength (simplicity) but a weakness when prospects need multi-framework compliance.

**Verdict: MEDIUM gap. Adding 2-3 key frameworks (NIST, PCI DSS, NIS2) would significantly expand our market.**

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
