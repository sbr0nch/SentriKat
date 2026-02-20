# SentriKat Agent Scanning Audit Report

**Date:** 2026-02-20
**Scope:** Container scanning, code dependency scanning, server processing, GUI display
**Files Audited:** 18 core files, ~15,000 lines of code

---

## Executive Summary

The agent scanning pipeline (container images + code dependencies) is **functionally solid** with real
Trivy integration, proper server-side validation, license gating, and working GUI pages. There is
**no mock or hardcoded data in production paths** -- all scanning data flows from real agents through
authenticated APIs to the database and GUI.

However, the feature is **not yet competitive** with industry leaders (Snyk, Docker Scout, Wiz, JFrog Xray).
The GUI pages are minimal, missing critical information that security buyers expect, and several
important features are absent. Below is the full audit with prioritized recommendations.

---

## 1. Architecture Overview (What Exists Today)

```
AGENT (Linux/macOS/Windows)
  |-- OS Package Scan (dpkg/rpm/apk/pacman/brew/etc.)
  |-- Extension Scan (VS Code, Chrome, Firefox, Edge, JetBrains) [if licensed]
  |-- Dependency Scan (pip, npm, cargo, go, gem, composer) [if licensed]
  |-- Container Scan (Trivy against Docker/Podman images) [if Trivy available]
  |
  +-- POST /api/agent/inventory (OS + extensions + dependencies)
  +-- POST /api/agent/container-scan (Trivy JSON output)
  +-- GET  /api/agent/commands (polls for scan_capabilities, scan_now, etc.)

SERVER
  |-- Validates, gates by license, processes inventory
  |-- Stores in: products, product_installations, container_images, container_vulnerabilities
  |-- Background worker for batches >= 750 items
  |-- Version change triggers vulnerability re-matching

GUI
  |-- /containers  --> Container Security page (image list + vulnerability detail)
  |-- /dependencies --> Dependencies page (library/extension list + installation detail)
  |-- Dashboard has "Containers" and "Dependencies" source filters
```

---

## 2. What's Good (Production-Ready Strengths)

### 2.1 No Mock/Hardcoded Data in Production

- All container scan data comes from real Trivy output parsed server-side
- All dependency data comes from actual package manager output on agents
- The `simulate-load` endpoint (`/api/admin/worker/simulate-load`) exists but is
  properly gated behind `@admin_required` + `super_admin` check and tagged as `job_type='load_test'`
- The mock URL in `integration_connectors.py:91` is in a docstring comment, not active code

### 2.2 Solid Server-Side Security

- **Authentication:** Hashed API keys (`AgentApiKey.hash_key`), IP allowlist enforcement
- **Input validation:** `sanitize_string()`, `validate_inventory_payload()`, length limits on all fields
- **License gating:** Extension/dependency scanning properly gated by API key capabilities
- **Rate limiting:** 60/min for inventory, 30/min for container scans, 60/min for commands
- **Defense in depth:** Organization ownership verified on container scans (line 4640)
- **Payload size limit:** 10MB max for container scans
- **Batch processing:** Commits every 50 items, async queue for large inventories

### 2.3 Robust Agent Implementation

- Proper JSON escaping prevents injection in all three agent scripts
- Config files use restrictive permissions (chmod 600 / Windows ACLs)
- Temp files for large payloads avoid memory issues
- Retry logic with exponential backoff (3 retries, 5s/10s/20s)
- Container image limit of 50 per request
- Trivy auto-installation on all platforms

### 2.4 Container Scanning Data Model Is Complete

The `ContainerVulnerability` model captures all the right fields:
- CVE ID, severity, title, description
- Package name, version, type, path within image
- Fixed version, fix status (fixed/not_fixed/end_of_life)
- CVSS score, CVSS vector, data source, primary URL
- Acknowledgment tracking (acknowledged, acknowledged_at, acknowledged_by)

### 2.5 Three-Phase CVE History Guard

The `_should_skip_software()` function uses a smart 3-phase approach that prevents
accidentally filtering out packages with known CVE history. This is better than most
competitors' static skip lists.

---

## 3. Critical Issues (Must Fix Before Release)

### 3.1 SQL Injection Risk in Search Filters

**Severity: MEDIUM** (SQLAlchemy parameterizes, but LIKE wildcards are user-controlled)

**Files:** `agent_api.py:4897`, `agent_api.py:4997-4999`, `agent_api.py:2515-2520`

```python
# Current - passes raw user input into LIKE pattern
query = query.filter(ContainerImage.image_name.ilike(f'%{search}%'))
```

The `%` and `_` characters in user input are LIKE wildcards. A user searching for `%` would
match everything. While SQLAlchemy prevents actual SQL injection, the LIKE wildcard behavior
could be exploited for information disclosure or DoS via expensive queries.

**Fix:** Escape LIKE special characters:
```python
from sqlalchemy import func
search_escaped = search.replace('%', '\\%').replace('_', '\\_')
query = query.filter(ContainerImage.image_name.ilike(f'%{search_escaped}%', escape='\\'))
```

### 3.2 Maintenance.py Has a Placeholder Function

**File:** `maintenance.py:764`

```python
# This would call NVD API to check vulnerabilities for specific version
# For now, return placeholder
return {
    'has_cpe': True,
    'message': 'Use NVD API to check vulnerabilities for this specific version'
}
```

This function returns a placeholder response instead of actually checking vulnerabilities.
While it appears to be for a manual spot-check feature (not the main scanning pipeline),
it should either be implemented or clearly marked as not-yet-available in the GUI.

### 3.3 No HTTPS Enforcement on Agent Server URL

**Severity: HIGH**

None of the three agents validate that `SERVER_URL` uses HTTPS. An HTTP connection
would expose the API key in transit.

**Fix:** Add validation in all agents:
```bash
# Linux/macOS
if [[ ! "$SERVER_URL" =~ ^https:// ]]; then
    log_error "Server URL must use HTTPS for security"
    exit 1
fi
```

### 3.4 Agent Auto-Update Has No Cryptographic Verification

**Severity: HIGH**

All three agents verify downloaded update scripts only by checking for shebang lines
and `AGENT_VERSION=` markers. A MITM attacker could serve a malicious script that
passes these checks and executes with root/SYSTEM privileges.

**Fix:** Implement signature verification (e.g., Ed25519 or RSA) for agent downloads.

---

## 4. GUI Gaps (What's Missing vs. Competitors)

### 4.1 Container Security Page -- Current State

The `/containers` page shows:
- Stats: Total images, Critical count, High count, Total vulns
- Image cards with severity bars and badges
- Detail panel: OS, Registry, Scanner version, Total vulns, Fixable count
- Vulnerability table: Severity, CVE (linked), Package, Installed version, Fixed version, CVSS

### 4.2 Container Security Page -- What's Missing

| Missing Feature | Competitor Baseline | Priority |
|----------------|-------------------|----------|
| **EPSS score per vulnerability** | Grype, Docker Scout, GitHub, Dependency-Track | HIGH |
| **Exploit availability indicator** | Snyk, Wiz, JFrog Xray, GitHub | HIGH |
| **CISA KEV (Known Exploited) flag** | Wiz, Grype, GitHub | HIGH |
| **Filter by fixability** (has fix / no fix) | ALL competitors | HIGH |
| **Medium/Low severity filter options** | Only Critical/High available now | MEDIUM |
| **Image digest / full registry path** | Docker Scout, Snyk | MEDIUM |
| **Image size** | Model has `size_bytes`, not shown in GUI | LOW |
| **Architecture** | Model has `architecture`, not shown in GUI | LOW |
| **SBOM export** (CycloneDX/SPDX) | ALL competitors, now regulatory requirement | HIGH |
| **Vulnerability description/title** | Model has both, not shown in GUI | MEDIUM |
| **Sort options** (by CVSS, by severity, by package) | ALL competitors | MEDIUM |
| **Pagination** | Hard limit of 500 images, no pagination | MEDIUM |
| **Trend over time** (vuln count history) | Docker Scout, Snyk, Dependency-Track | HIGH |
| **Acknowledge/suppress individual CVEs** | Model supports it (`acknowledged` field), no GUI | HIGH |
| **CSV/PDF export** | Most competitors | MEDIUM |
| **Remediation advice** (upgrade path) | Snyk, Docker Scout | HIGH |

### 4.3 Dependencies Page -- Current State

The `/dependencies` page shows:
- Stats: Dependencies count, Extensions count, Ecosystems, Vulnerable count
- Dependency cards with ecosystem badges and endpoint counts
- Detail panel: Ecosystem, Type, Endpoints, Vulnerabilities count
- Installation table: Endpoint, Version, Project Path, Direct/Transitive flag

### 4.4 Dependencies Page -- What's Missing

| Missing Feature | Competitor Baseline | Priority |
|----------------|-------------------|----------|
| **Vulnerability details per dependency** | Only shows count, not which CVEs | CRITICAL |
| **CVE list for vulnerable dependencies** | Snyk, GitHub, GitLab, Dependency-Track | CRITICAL |
| **EPSS score** | Grype, Docker Scout, GitHub | HIGH |
| **License information** | Snyk, Trivy, Docker Scout, JFrog Xray, GitLab | HIGH |
| **Outdated version indicator** | All competitors show if newer version exists | HIGH |
| **Latest available version** | Snyk, GitHub Dependabot | HIGH |
| **SBOM export** | All competitors | HIGH |
| **Severity breakdown per dependency** | Snyk, Dependency-Track | MEDIUM |
| **Dependency tree visualization** | Snyk, GitHub, npm audit | MEDIUM |
| **Sort by vulnerability count or risk** | All competitors | MEDIUM |
| **Pagination** | Hard limit of 1000, no pagination | MEDIUM |
| **Filter by "has vulnerabilities"** | All competitors | HIGH |
| **Direct vs. transitive filter** | Snyk, GitHub | MEDIUM |
| **CSV/PDF export** | Most competitors | MEDIUM |

### 4.5 Dashboard Integration -- Current State

The dashboard has "Containers" and "Dependencies" source filter buttons that filter
the vulnerability stats and grouped CVE cards. This is good baseline integration.

### 4.6 Dashboard Integration -- What's Missing

| Missing Feature | Priority |
|----------------|----------|
| **Container vulnerability trend chart** | HIGH |
| **Dependency vulnerability trend chart** | HIGH |
| **"Most vulnerable images" widget** | MEDIUM |
| **"Most vulnerable dependencies" widget** | MEDIUM |
| **Remediation velocity metrics** (mean time to fix) | MEDIUM |

---

## 5. Agent Scanning Gaps

### 5.1 Cross-Platform Inconsistencies

| Feature | Linux | Windows | macOS | Issue |
|---------|-------|---------|-------|-------|
| Podman support | Yes | **No** | Yes | Windows missing |
| requirements.txt scanning | Yes | **No** | Yes | Windows missing |
| Ruby gems | Yes | **No** | Yes | Windows missing |
| Go modules (go.sum) | Yes | **No** | Yes | Windows missing |
| NuGet/.csproj scanning | Partial | Yes | Partial | Linux/macOS limited |
| Container scan retry | Yes (3x) | Yes (3x) | **No** | macOS missing retry |

### 5.2 Missing Package Managers

| Ecosystem | Status | Competitor Support |
|-----------|--------|-------------------|
| **Poetry** (Python pyproject.toml) | Missing | Snyk, Trivy, Grype |
| **Bundler** (Ruby Gemfile.lock) | Missing | Snyk, Trivy, Grype |
| **Maven** (pom.xml) | Missing | Snyk, Trivy, Grype, JFrog Xray |
| **Gradle** (build.gradle) | Missing | Snyk, Trivy, Grype, JFrog Xray |
| **pnpm** (pnpm-lock.yaml) | Missing | Snyk, Trivy, Grype |
| **yarn** (yarn.lock) | Missing | Snyk, Trivy, Grype |
| **.NET** (packages.config, .deps.json) | Partial | Snyk, Trivy |

### 5.3 Fragile JSON Parsing in Agents

**Linux/macOS agents** use hand-rolled shell-based JSON parsing for:
- `package-lock.json` (grep state machine, lines 519-546 in Linux agent)
- Chrome/Edge `manifest.json` (grep-based extraction)
- Firefox `extensions.json` (requires Python3, fails silently if unavailable)

**Risk:** Fails on minified JSON, escaped quotes, multiline values, nested objects.

**Fix:** Use `jq` (pre-installed on most systems, 1.2MB binary if not) or use the
package manager's native parseable output format (e.g., `npm ls --json`).

### 5.4 Hardcoded Trivy Version

All agents hardcode `TRIVY_VERSION=0.58.2`. If this version becomes vulnerable or
outdated, every deployed agent needs a full update.

**Fix:** Make Trivy version configurable via the commands endpoint response, or
auto-detect the latest version from the GitHub API.

---

## 6. Competitive Feature Gap Analysis

### 6.1 Features SentriKat Has That Competitors Don't Bundle

- **Unified OS + extension + dependency + container scanning** in a single lightweight agent
- **Multi-organization deployment** with single agent reporting to multiple orgs
- **Import queue** for manual review before auto-creating products
- **CVE history guard** for intelligent noise filtering
- **Push-based agent** architecture (no need for registry access or CI/CD integration)

### 6.2 Must-Have Features to Be Competitive (Priority Order)

1. **Show CVE details for vulnerable dependencies** (CRITICAL -- currently only shows count)
2. **EPSS score display** for both containers and dependencies
3. **CISA KEV / Exploit availability indicator** per vulnerability
4. **SBOM export** (CycloneDX + SPDX) for both containers and dependencies
5. **Acknowledge/suppress CVEs** from the GUI (model already supports it)
6. **Filter by fixability** (has fix available / no fix)
7. **License compliance** detection and display
8. **Vulnerability trend charts** over time
9. **CSV/PDF export** for both container and dependency scan results
10. **Sort by CVSS/EPSS/severity** in vulnerability tables

### 6.3 Differentiating Features (What Would Make SentriKat Stand Out)

1. **Unified risk view**: No competitor combines OS packages + code deps + extensions +
   containers in a single pane with cross-correlation
2. **Agent-based continuous monitoring**: Most competitors are CI/CD or registry-based;
   SentriKat's push agent model is unique for runtime visibility
3. **Multi-org with single agent**: Enterprise MSP feature that competitors charge premium for
4. **Version change tracking**: The `ProductVersionHistory` and automatic re-matching when
   versions change is sophisticated and unique

---

## 7. Recommended Free/Open-Source Tools

### 7.1 Already Integrated (Keep)

| Tool | License | Status | Maintained |
|------|---------|--------|-----------|
| **Trivy** | Apache 2.0 | Integrated in all agents | Actively maintained by Aqua Security, 25k+ GitHub stars |

### 7.2 Recommended for Integration

| Tool | License | What It Adds | Maintenance Status |
|------|---------|-------------|-------------------|
| **EPSS API** | Free public API (FIRST.org) | Exploit probability scores per CVE | Actively maintained, updated daily |
| **CISA KEV Feed** | Public domain (US Gov) | Known exploited vulnerabilities catalog | Updated multiple times per week |
| **CycloneDX CLI** | Apache 2.0 | SBOM generation in standard format | OWASP project, very actively maintained |
| **jq** | MIT | Reliable JSON parsing in agents | Extremely mature, ubiquitous |

### 7.3 Tools to Consider Later

| Tool | License | What It Adds |
|------|---------|-------------|
| **Syft** | Apache 2.0 | Comprehensive SBOM generation (more complete than manual parsing) |
| **Grype** | Apache 2.0 | Alternative vulnerability database (supplements Trivy) |
| **OSV.dev API** | Apache 2.0 | Open Source Vulnerabilities database (better for dependencies) |

---

## 8. Implementation Roadmap (Recommended Priority)

### Phase 1: Critical Fixes (Week 1)

- [ ] Fix LIKE wildcard escaping in search filters (3 locations)
- [ ] Add HTTPS enforcement in agent scripts
- [ ] Add container scan retry logic to macOS agent
- [ ] Show CVE details for vulnerable dependencies (link to existing vulnerability data)

### Phase 2: Competitive Parity (Weeks 2-3)

- [ ] Integrate EPSS API scores (free, daily-updated CSV from FIRST.org)
- [ ] Integrate CISA KEV feed (free, JSON feed from CISA)
- [ ] Add "Fixable" filter to container vulnerability page
- [ ] Add acknowledge/suppress CVE functionality in GUI
- [ ] Add Medium/Low severity filter options
- [ ] Add sort options to vulnerability tables
- [ ] Add pagination to container and dependency list APIs
- [ ] Show vulnerability description/title in container detail

### Phase 3: Differentiating Features (Weeks 3-5)

- [ ] SBOM export (CycloneDX + SPDX format) for containers and dependencies
- [ ] CSV/PDF export for scan results
- [ ] Vulnerability trend charts (track counts over time per image/dependency)
- [ ] License compliance detection (parse license field from package managers)
- [ ] "Most vulnerable images/dependencies" dashboard widgets

### Phase 4: Agent Improvements (Weeks 5-6)

- [ ] Add yarn.lock and pnpm-lock.yaml parsing
- [ ] Add Poetry (pyproject.toml/poetry.lock) support
- [ ] Add Maven (pom.xml) and Gradle (build.gradle) support
- [ ] Fix Windows agent parity (Podman, requirements.txt, Ruby, Go)
- [ ] Replace hand-rolled JSON parsing with jq fallback
- [ ] Make Trivy version configurable from server

### Phase 5: Enterprise Polish (Weeks 6-8)

- [ ] Agent auto-update with cryptographic signature verification
- [ ] Composite risk score (CVSS x EPSS x fixability x CISA KEV)
- [ ] Policy engine (block/alert based on severity thresholds)
- [ ] Remediation advice ("upgrade package X to version Y")
- [ ] API key rotation support

---

## 9. Detailed File Inventory

### Backend
| File | Lines | Purpose |
|------|-------|---------|
| `app/agent_api.py` | 5,122 | All scanning endpoints, validation, processing |
| `app/models.py` | 3,413 | ContainerImage, ContainerVulnerability, Product, ProductInstallation |
| `app/routes.py` | 6,778 | GUI routes for /containers, /dependencies |
| `app/maintenance.py` | 773 | Has placeholder for NVD version check |
| `app/integrations_api.py` | 400+ | SBOM import (CycloneDX + SPDX) already exists |

### Agent Scripts
| File | Lines | Purpose |
|------|-------|---------|
| `agents/sentrikat-agent-linux.sh` | 1,468 | Linux agent (most complete) |
| `agents/sentrikat-agent-windows.ps1` | 1,639 | Windows agent (missing some ecosystems) |
| `agents/sentrikat-agent-macos.sh` | 1,357 | macOS agent (missing container scan retry) |

### Frontend
| File | Size | Purpose |
|------|------|---------|
| `app/templates/containers.html` | 255 lines | Container security GUI |
| `app/templates/dependencies.html` | 236 lines | Dependencies GUI |
| `app/templates/dashboard.html` | 2,500+ lines | Main dashboard with source filters |

### Tests
| File | Lines | Purpose |
|------|-------|---------|
| `tests/test_scan_features.py` | 707 | Extension/dependency gate tests |
| `tests/test_container_dependency_scanning.py` | 1,701 | Container + dependency integration tests |

---

## 10. Conclusion

**The scanning infrastructure is real, secure, and well-engineered.** The agent-to-server pipeline
is production-quality with proper authentication, validation, rate limiting, and async processing.
There is no mock data in production paths.

**The main gap is the GUI.** The container and dependency pages display basic information but are
missing the features that security buyers expect in 2026: EPSS scores, exploit availability,
CISA KEV status, fixability filters, SBOM export, trend charts, and CVE details for dependencies.

**The agent scanning breadth is good but has cross-platform inconsistencies** that should be
resolved, particularly Windows missing several package managers that Linux/macOS support.

**The unique positioning is strong:** SentriKat is the only tool that combines OS packages,
code dependencies, IDE/browser extensions, and container images in a single lightweight
push-agent with multi-organization support. With the GUI enhancements in Phases 2-3, this
feature set is sellable and competitive.
