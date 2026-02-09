# COPY-PASTE PROMPT FOR SENTRIKAT-WEB TEAM
## Update Landing Page, Docs, and Portal for Container Image Scanning

---

**Give this entire document to whoever manages the SentriKat-web repository (landing, docs, portal).**

---

## CONTEXT

We've added **Container Image Scanning powered by Trivy** to SentriKat. This is a major new feature that needs to be reflected across the entire web presence. Here's what changed:

### What's New in the Product (v1.2.0)

1. **SentriKat agents now auto-detect Docker/Podman** on endpoints and scan all container images using Trivy (open-source, Apache-2.0, zero cost)
2. **New API endpoint**: `POST /api/agent/container-scan` receives Trivy JSON results
3. **New API endpoints**: `GET /api/containers` and `GET /api/containers/<id>` for viewing results
4. **Dashboard now shows container vulnerability stats** alongside endpoint vulnerability stats
5. **Both Linux and Windows agents** support this (agents v1.2.0)
6. **Scans find**: OS package vulnerabilities, application dependency vulnerabilities (pip, npm, Maven, Go, Rust), and reports fix availability

### How It Works (for documentation)

1. Agent detects Docker or Podman on the endpoint
2. Agent auto-installs Trivy (~50MB binary, one-time download)
3. Agent runs `trivy image --format json --severity HIGH,CRITICAL <image>` for each local image
4. Agent sends JSON results to SentriKat server via `/api/agent/container-scan`
5. Server stores results in `container_images` and `container_vulnerabilities` tables
6. Dashboard, alerts, and reports include container vulnerability data
7. No extra configuration needed -- it's automatic if Docker is present

### Business Model

- Container scanning is included in the **Professional Edition** at no extra cost
- It uses the **existing agent deployment** -- no new agent needed
- This counts toward the existing agent license (same endpoint = same agent slot)
- It's a value-add that differentiates us from competitors at our price point

---

## CHANGES NEEDED ON SENTRIKAT-WEB

### 1. Landing Page (`landing/src/`)

#### Hero Section (`Hero.astro`)
Update the tagline or add a secondary line:
- **Before**: "Enterprise Vulnerability Management for CISA Known Exploited Vulnerabilities"
- **After**: "Enterprise Vulnerability Management for CISA Known Exploited Vulnerabilities"
- **Add subtitle**: "Now with container image scanning — track vulnerabilities across your endpoints AND Docker images"

#### Features Section (`Features.astro`)
Add a new feature card:
```
Title: Container Image Scanning
Icon: Shield/Container icon (use lucide-react "Container" or "Box" icon)
Description: "Automatically scan Docker and Podman images on your endpoints using Trivy.
Detect OS and application vulnerabilities in every container image — no extra configuration needed."
Bullets:
- Auto-detects Docker & Podman on endpoints
- Scans all local images for HIGH and CRITICAL CVEs
- Reports fix availability for every vulnerability
- Zero extra cost — included in Professional Edition
```

#### How It Works Section (`HowItWorks.astro`)
Add step or update existing flow:
```
Step 4 (new): "Container Scanning"
"Agents automatically detect Docker images and scan them for vulnerabilities
using Trivy, the industry-standard open-source scanner."
```

#### Pricing Section (`Pricing.astro`)
Add to Professional Edition feature list:
- "Container Image Scanning (Docker & Podman)"
- "Trivy-powered vulnerability detection"

#### WhyDifferent Section (`WhyDifferent.astro`)
Add a comparison point:
- "Container scanning included at no extra cost — competitors charge $10,000+/year for this"

---

### 2. Documentation Site (`docs/docs/`)

#### New Page: `docs/docs/agents/container-scanning.md`
Create this new documentation page:

```markdown
# Container Image Scanning

SentriKat agents automatically detect Docker and Podman on endpoints and scan
all local container images for vulnerabilities using [Trivy](https://trivy.dev/),
the industry-standard open-source security scanner.

## How It Works

1. The SentriKat agent detects Docker or Podman during its regular scan cycle
2. Trivy is automatically downloaded and cached (~50MB, one-time)
3. All local images are scanned for HIGH and CRITICAL severity vulnerabilities
4. Results are sent to the SentriKat server alongside the regular software inventory
5. Container vulnerabilities appear in the dashboard, alerts, and reports

## Requirements

- Docker or Podman installed on the endpoint
- Internet access (for initial Trivy binary download and vulnerability database)
- Agent v1.2.0 or later

## Configuration

Container scanning is **enabled by default** when Docker/Podman is detected.

### Linux Agent

Set in `/etc/sentrikat/agent.conf`:
```bash
# Auto-detect (default) — scans if Docker/Podman found
CONTAINER_SCAN_ENABLED=auto

# Force enable
CONTAINER_SCAN_ENABLED=true

# Disable container scanning
CONTAINER_SCAN_ENABLED=false
```

### Windows Agent

Container scanning runs automatically when Docker Desktop is detected.

## What Gets Scanned

- **OS packages**: Alpine APK, Debian/Ubuntu dpkg, RHEL/CentOS rpm, etc.
- **Application dependencies**: pip (Python), npm (Node.js), Maven (Java), Go modules, Rust crates, Ruby gems
- **Severity filter**: Only HIGH and CRITICAL vulnerabilities are reported (configurable)

## API Reference

### Submit Container Scan Results
```
POST /api/agent/container-scan
Header: X-Agent-Key: <your-api-key>
```

### List Container Images
```
GET /api/containers
GET /api/containers?severity=critical
GET /api/containers?search=nginx
```

### Get Image Details
```
GET /api/containers/<image_id>
```

## Limits

- Maximum 50 images scanned per cycle
- Scan timeout: 5 minutes per image
- Results sent via the same agent API key as regular inventory

## Trivy Details

- Scanner: [Trivy by Aqua Security](https://trivy.dev/)
- License: Apache-2.0 (free, open source)
- Vulnerability database: Updated every 6 hours from NVD, Red Hat, Alpine, Debian, Ubuntu, and more
- Binary size: ~50MB (cached locally)
```

#### Update Navigation (`mkdocs.yml`)
Add under the Agents section:
```yaml
- Agents:
  - Windows Agent: agents/windows.md
  - Linux Agent: agents/linux.md
  - Container Scanning: agents/container-scanning.md   # NEW
  - PDQ Deploy: agents/pdq-deploy.md
```

#### Update API Reference (`docs/docs/api/`)
Add container scanning endpoints to the API documentation.

---

### 3. Customer Portal (`portal/src/`)

#### Downloads Page
If there's a downloads/changelog section, add:
- **Agent v1.2.0** changelog: "Added automatic container image scanning via Trivy. Agents now detect Docker/Podman and scan all local images for vulnerabilities."

---

### 4. Nginx Config (if needed)

No changes needed — the container API endpoints are part of the existing SentriKat application, not a new service.

---

## DESIGN NOTES

### Suggested Icons (Lucide React)
- `Container` or `Box` for container scanning feature
- `Shield` or `ShieldCheck` for security scanning
- `Scan` for the scanning process

### Color Scheme
- Use the existing SentriKat color palette
- Container-related elements could use a **teal/cyan accent** to differentiate from endpoint (blue) data

### Screenshots Needed
Once the feature is live, capture:
1. Dashboard showing container vulnerability stats widget
2. Container image list view with severity badges
3. Container image detail view with vulnerability table

---

## TIMELINE

This should be updated ASAP to match the v1.2.0 agent release. Priority order:
1. Landing page feature section (highest visibility)
2. Documentation page (users need this)
3. Pricing section update
4. Portal downloads/changelog
