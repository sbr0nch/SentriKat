# SENTRIKAT CONTAINER SCANNING - TESTING & VERIFICATION GUIDE

---

## PART 1: HOW TRIVY WORKS (AND WHY WE TRUST IT)

### What Is Trivy?

Trivy is an open-source vulnerability scanner by **Aqua Security**, one of the largest container security companies. It's the most widely adopted open-source scanner in the industry (25,000+ GitHub stars, used by AWS, Google, GitLab, and others).

### How Trivy Scanning Actually Works

```
┌──────────────────────────────────────────────────────────────────┐
│                    HOW TRIVY SCANS AN IMAGE                      │
│                                                                  │
│  1. Trivy pulls the image manifest (layer list)                  │
│  2. Extracts each filesystem layer without running the container │
│  3. Reads package manager databases:                             │
│     - /var/lib/dpkg/status (Debian/Ubuntu)                       │
│     - /lib/apk/db/installed (Alpine)                             │
│     - /var/lib/rpm/Packages (RHEL/CentOS)                        │
│     - package-lock.json, requirements.txt, go.sum, etc.          │
│  4. Builds a list of every installed package + version            │
│  5. Compares against its vulnerability database                  │
│  6. Outputs matches as JSON with CVE ID, severity, fix version   │
└──────────────────────────────────────────────────────────────────┘
```

**Key point:** Trivy never runs the container. It reads the filesystem layers statically. This is safe — no code from the container executes.

### Trivy's Vulnerability Database

Trivy pulls vulnerability data from these **authoritative sources**:

| Source | What It Covers |
|--------|---------------|
| NVD (NIST) | All public CVEs |
| Red Hat Security Advisories | RHEL, CentOS, Fedora |
| Debian Security Tracker | Debian packages |
| Ubuntu CVE Tracker | Ubuntu packages |
| Alpine SecDB | Alpine packages |
| GitHub Advisory Database | npm, pip, Maven, Go, Rust, etc. |
| Aqua Vulnerability DB | Aggregated + enriched data |

The database is updated every **6 hours** automatically. Trivy caches it locally at `~/.cache/trivy/db/`.

### Why We Can Trust It

1. **Open source** (Apache-2.0) — anyone can audit the code: https://github.com/aquasecurity/trivy
2. **Backed by Aqua Security** — commercial company with reputation at stake
3. **Used in production by**: AWS ECR, Google Artifact Registry, GitLab CI, Harbor Registry
4. **CNCF ecosystem** — part of the Cloud Native Computing Foundation landscape
5. **No network access needed during scan** — the image is read locally, only the vuln DB is downloaded
6. **Deterministic** — same image + same DB = same results every time

### What Trivy Does NOT Do

- Does NOT run containers or execute any code from images
- Does NOT send your image data anywhere (everything stays local)
- Does NOT modify images or containers
- Does NOT require Docker daemon access for the scan itself (can scan tarballs too)

---

## PART 2: AUTOMATED TESTS

### Running the Automated Test Suite

The test file is at `tests/test_container_scanning.py`. It tests models, API endpoints, auth, validation, and edge cases.

```bash
# From the SentriKat project root
cd /home/user/SentriKat

# Install test dependencies (if not already installed)
pip install pytest

# Run the container scanning tests
python -m pytest tests/test_container_scanning.py -v

# Run with more detail on failures
python -m pytest tests/test_container_scanning.py -v --tb=long

# Run a specific test class
python -m pytest tests/test_container_scanning.py::TestContainerScanEndpoint -v

# Run a single test
python -m pytest tests/test_container_scanning.py::TestContainerScanEndpoint::test_submit_scan_success -v
```

### What the Tests Cover

| Test Class | Tests | What It Validates |
|-----------|-------|-------------------|
| `TestContainerImageModel` | 3 | Model creation, `to_dict()`, `full_name` property |
| `TestContainerVulnerabilityModel` | 1 | Vulnerability creation and serialization |
| `TestContainerScanEndpoint` | 9 | POST /api/agent/container-scan — success, auth, validation, edge cases |
| `TestContainerListEndpoint` | 3 | GET /api/containers — auth, empty state, with data |
| `TestContainerDetailEndpoint` | 1 | GET /api/containers/<id> — detail view with vulns |

### Key Security Tests

- **`test_reject_without_api_key`** — No API key = 401
- **`test_reject_invalid_api_key`** — Bad API key = 401
- **`test_reject_unknown_asset`** — Unknown agent_id = 404 (not 500)
- **`test_cvss_score_validation`** — CVSS > 10.0 is dropped (stored as NULL)
- **`test_scanner_allowlist`** — XSS in scanner name is handled safely
- **`test_malformed_trivy_output_handled`** — Garbage input doesn't crash the server
- **`test_too_many_images_rejected`** — 51+ images = 400 (DoS protection)

---

## PART 3: MANUAL TESTING GUIDE

### Prerequisites

You need:
- SentriKat running locally (via Docker Compose)
- Docker installed on the machine
- `curl` for API calls
- An organization + API key created in the SentriKat web UI

### Step 1: Start SentriKat

```bash
cd /home/user/SentriKat
docker compose up -d
```

Wait for the health check to pass:
```bash
docker compose ps
# All services should show "healthy"
```

### Step 2: Create an Organization and API Key

1. Open `http://localhost` in your browser
2. Log in as admin (or create first user)
3. Go to **Settings** > **Agent API Keys**
4. Click **Generate New Key**
5. Copy the key (starts with `sk_`)
6. Note your **organization ID** (visible in the URL or settings)

### Step 3: Register a Test Asset

Before container scanning works, the agent must be registered. Simulate this:

```bash
# Replace YOUR_API_KEY with your actual key
API_KEY="sk_your_key_here"

# Register a fake agent/asset
curl -X POST http://localhost/api/agent/check-in \
  -H "Content-Type: application/json" \
  -H "X-Agent-Key: $API_KEY" \
  -d '{
    "agent_id": "test-manual-agent-001",
    "hostname": "my-docker-server",
    "os_name": "Ubuntu",
    "os_version": "22.04",
    "agent_version": "1.2.0"
  }'
```

Expected response: `200 OK` with asset details.

### Step 4: Submit a Container Scan (Simulated)

This simulates what the agent would send after scanning Docker images with Trivy:

```bash
curl -X POST http://localhost/api/agent/container-scan \
  -H "Content-Type: application/json" \
  -H "X-Agent-Key: $API_KEY" \
  -d '{
    "agent_id": "test-manual-agent-001",
    "hostname": "my-docker-server",
    "scanner": "trivy",
    "scanner_version": "0.58.2",
    "images": [
      {
        "image_name": "nginx",
        "image_tag": "1.25-alpine",
        "image_id": "sha256:a1b2c3d4e5f6",
        "trivy_output": {
          "SchemaVersion": 2,
          "Metadata": {
            "OS": {"Family": "alpine", "Name": "3.19.0"}
          },
          "Results": [
            {
              "Target": "nginx:1.25-alpine (alpine 3.19.0)",
              "Type": "alpine",
              "Vulnerabilities": [
                {
                  "VulnerabilityID": "CVE-2024-9143",
                  "PkgName": "libssl3",
                  "InstalledVersion": "3.1.4-r0",
                  "FixedVersion": "3.1.4-r1",
                  "Severity": "HIGH",
                  "Title": "OpenSSL: Low-level invalid GF(2^m) parameters",
                  "Description": "Use of the low-level GF(2^m) elliptic curve APIs with untrusted explicit values for the field polynomial can lead to out-of-bounds memory reads or writes.",
                  "PrimaryURL": "https://nvd.nist.gov/vuln/detail/CVE-2024-9143",
                  "CVSS": {
                    "nvd": {
                      "V3Score": 7.5,
                      "V3Vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H"
                    }
                  }
                },
                {
                  "VulnerabilityID": "CVE-2024-12345",
                  "PkgName": "curl",
                  "InstalledVersion": "8.5.0-r0",
                  "FixedVersion": "",
                  "Severity": "CRITICAL",
                  "Title": "Test critical vulnerability in curl",
                  "CVSS": {
                    "nvd": {"V3Score": 9.8}
                  }
                }
              ]
            }
          ]
        }
      },
      {
        "image_name": "redis",
        "image_tag": "7.2",
        "image_id": "sha256:f6e5d4c3b2a1",
        "trivy_output": {
          "SchemaVersion": 2,
          "Metadata": {
            "OS": {"Family": "debian", "Name": "bookworm"}
          },
          "Results": []
        }
      }
    ]
  }'
```

**Expected response:**
```json
{
  "status": "success",
  "summary": {
    "images_processed": 2,
    "images_created": 2,
    "images_updated": 0,
    "total_vulnerabilities": 2
  }
}
```

### Step 5: Verify Data in the API

**List all container images:**
```bash
# This requires a logged-in session (use browser or session cookie)
curl http://localhost/api/containers \
  -H "Cookie: session=YOUR_SESSION_COOKIE"
```

**Expected:** JSON with `stats.total_images: 2`, nginx showing 2 vulns, redis showing 0.

**Get image detail:**
```bash
curl http://localhost/api/containers/1 \
  -H "Cookie: session=YOUR_SESSION_COOKIE"
```

**Expected:** Image details with `vulnerability_count: 2` and the two CVEs listed.

### Step 6: Test Security Controls

**Test 1: No API key**
```bash
curl -X POST http://localhost/api/agent/container-scan \
  -H "Content-Type: application/json" \
  -d '{"agent_id": "test", "hostname": "test", "scanner": "trivy", "images": []}'
```
Expected: `401 Unauthorized`

**Test 2: Bad API key**
```bash
curl -X POST http://localhost/api/agent/container-scan \
  -H "Content-Type: application/json" \
  -H "X-Agent-Key: sk_this_is_fake" \
  -d '{"agent_id": "test", "hostname": "test", "scanner": "trivy", "images": []}'
```
Expected: `401 Unauthorized`

**Test 3: Unknown agent**
```bash
curl -X POST http://localhost/api/agent/container-scan \
  -H "Content-Type: application/json" \
  -H "X-Agent-Key: $API_KEY" \
  -d '{"agent_id": "does-not-exist", "hostname": "unknown", "scanner": "trivy", "images": []}'
```
Expected: `404 Not Found`

**Test 4: Too many images (>50)**
```bash
# Generate a payload with 51 images
python3 -c "
import json
images = [{'image_name': f'img{i}', 'image_tag': 'latest', 'trivy_output': {}} for i in range(51)]
payload = {'agent_id': 'test-manual-agent-001', 'hostname': 'my-docker-server', 'scanner': 'trivy', 'images': images}
print(json.dumps(payload))
" | curl -X POST http://localhost/api/agent/container-scan \
  -H "Content-Type: application/json" \
  -H "X-Agent-Key: $API_KEY" \
  -d @-
```
Expected: `400 Bad Request` with message about exceeding limit.

### Step 7: Test the Real Agent (End-to-End)

If you have a Linux server or VM with Docker:

```bash
# 1. Copy the agent script
scp agents/sentrikat-agent-linux.sh user@your-server:/tmp/

# 2. SSH into the server
ssh user@your-server

# 3. Configure the agent
sudo mkdir -p /etc/sentrikat
sudo tee /etc/sentrikat/agent.conf << 'EOF'
SENTRIKAT_URL="https://your-sentrikat-instance.com"
API_KEY="sk_your_key_here"
HOSTNAME_OVERRIDE=""
CONTAINER_SCAN_ENABLED=auto
# For air-gapped: TRIVY_OFFLINE=true (pre-install trivy first)
EOF

# 4. Run the agent manually (for testing)
sudo bash /tmp/sentrikat-agent-linux.sh

# 5. Check agent logs
cat /var/log/sentrikat/agent.log
```

**What to look for in the logs:**
```
[INFO] Docker detected: /usr/bin/docker
[INFO] Installing Trivy v0.58.2...
[INFO] Trivy installed successfully
[INFO] Found 3 Docker images to scan
[INFO] Scanning image: nginx:1.25-alpine...
[INFO] Scanning image: redis:7.2...
[INFO] Scanning image: postgres:16...
[INFO] Container scan results sent successfully (3 images, 7 vulnerabilities)
```

**If Docker is not installed:**
```
[INFO] Docker not found, skipping container scanning
```

**If offline/air-gapped (no internet, Trivy not pre-installed):**
```
[WARN] TRIVY_OFFLINE is set but Trivy is not installed. Pre-deploy Trivy binary to /usr/local/bin/trivy
[WARN] Skipping container scanning — Trivy not available
```

### Step 8: Verify in the Dashboard

1. Open SentriKat in your browser
2. Go to the **Dashboard**
3. The vulnerability stats should now include container data:
   - Total container images
   - Container critical/high vulnerability counts
4. Go to **Containers** (if UI page exists) or check via API

---

## PART 4: TROUBLESHOOTING

### Agent Can't Download Trivy

**Symptom:** Agent logs show download failure.

**Solutions:**
1. Check internet access: `curl -I https://github.com`
2. Check proxy settings in `/etc/sentrikat/agent.conf`
3. For air-gapped environments:
   - Download Trivy binary on a machine with internet
   - Copy to `/usr/local/bin/trivy` on the target machine
   - Set `TRIVY_OFFLINE=true` in agent.conf
   - The agent will find it in PATH and skip download

### Trivy Scan Times Out

**Symptom:** Agent logs show timeout on large images.

**Cause:** Very large images (multi-GB) with thousands of packages take longer to scan.

**Solution:** The agent sets a 5-minute timeout per image. If this isn't enough, the image is skipped and others continue.

### Container Scan Data Not Showing in Dashboard

**Check list:**
1. Is the agent registered? (`GET /api/admin/assets` — look for the hostname)
2. Did the scan submit successfully? (Check agent logs for HTTP 200)
3. Is the API key valid and associated with the right organization?
4. Check the database directly:
   ```sql
   SELECT * FROM container_images ORDER BY created_at DESC LIMIT 10;
   SELECT * FROM container_vulnerabilities ORDER BY created_at DESC LIMIT 10;
   ```

### "Unknown asset" Error (404)

The agent's `agent_id` must match a registered asset in the same organization as the API key.

1. Check the agent is registered: Look for the asset in SentriKat UI under Assets
2. Verify the `agent_id` matches between agent config and the asset record
3. Ensure the API key belongs to the same organization as the asset

---

*Document Version: 1.0 — February 2026*
