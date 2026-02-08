# SentriKat - Investor Demo Test Checklist

**Purpose:** Step-by-step verification of all features before investor demo
**Estimated time:** 30-45 minutes

---

## PRE-DEMO: Environment Setup

- [ ] Fresh `docker compose up -d` with clean volumes
- [ ] Verify all 3 containers healthy: `docker compose ps`
- [ ] Open browser to `http://localhost` (or configured URL)
- [ ] Verify Setup Wizard appears on first access

---

## STEP 1: Setup Wizard (First Run Experience)

| Test | Action | Expected Result |
|------|--------|-----------------|
| 1.1 | Open app for the first time | Setup wizard page appears |
| 1.2 | Enter organization name (e.g. "Acme Corp") | Form accepts input |
| 1.3 | Create admin account (username/password/email) | Account created successfully |
| 1.4 | Optionally configure SMTP | Settings saved (or skip) |
| 1.5 | Optionally configure proxy | Settings saved (or skip) |
| 1.6 | Seed service catalog | ~47 services loaded |
| 1.7 | Run initial CISA KEV sync | ~1200+ CVEs downloaded |
| 1.8 | Complete setup | Redirect to dashboard |
| 1.9 | Try accessing /setup again | Redirects to dashboard (locked) |
| 1.10 | Try POST /api/setup/create-admin | Returns 403 (locked) |

---

## STEP 2: Dashboard

| Test | Action | Expected Result |
|------|--------|-----------------|
| 2.1 | View dashboard | Stats cards visible (vulnerabilities tracked, products, etc.) |
| 2.2 | Vulnerability trends chart | Chart renders with data |
| 2.3 | Click priority cards (CRITICAL/HIGH) | CVE table filters by severity |
| 2.4 | Toggle dark mode | All elements adapt correctly |
| 2.5 | Toggle back to light mode | All elements revert correctly |
| 2.6 | Check "Powered by SentriKat" footer | Visible in Demo edition |

---

## STEP 3: Product Management

| Test | Action | Expected Result |
|------|--------|-----------------|
| 3.1 | Click "Add Product" | Modal opens |
| 3.2 | Search NVD for "Firefox" | Results appear from NVD API |
| 3.3 | Select a CPE result | Vendor/product/version auto-filled |
| 3.4 | Save product | Product appears in inventory |
| 3.5 | Verify CVE matches appear | Matching CVEs listed on dashboard |
| 3.6 | Add product "Apache HTTP Server 2.4" | Product added, CVEs matched |
| 3.7 | Edit a product (change version) | Product updated successfully |
| 3.8 | Delete a product | Product removed, matches cleared |
| 3.9 | Try adding product with empty name | Validation error (blocked) |
| 3.10 | Import via CSV | Upload processed, products in review queue |

---

## STEP 4: CISA KEV Sync

| Test | Action | Expected Result |
|------|--------|-----------------|
| 4.1 | Go to Admin > Sync | Sync status page |
| 4.2 | Click "Sync Now" | Sync runs, shows progress |
| 4.3 | Verify sync results | New/updated CVE count displayed |
| 4.4 | Check sync log | Timestamped sync history |

---

## STEP 5: Vulnerability Management

| Test | Action | Expected Result |
|------|--------|-----------------|
| 5.1 | View unacknowledged CVEs | List of active vulnerabilities |
| 5.2 | Click a CVE for details | Details panel with description, due date, CVSS |
| 5.3 | Acknowledge a CVE | Status changes, removed from active list |
| 5.4 | Unacknowledge a CVE | Status reverts, back in active list |
| 5.5 | Snooze a CVE (7 days) | CVE hidden until snooze expires |
| 5.6 | Filter by severity | Only selected severity shown |
| 5.7 | Search for specific CVE ID | CVE found and displayed |
| 5.8 | Check EPSS scores | Scores displayed where available |
| 5.9 | Check ransomware flag | Ransomware badge on tagged CVEs |

---

## STEP 6: Agent System (Demo Mode - 5 agents max)

| Test | Action | Expected Result |
|------|--------|-----------------|
| 6.1 | Go to Admin > Agent Keys | Agent key management page |
| 6.2 | Create new API key | Key generated (shown once) |
| 6.3 | Download Windows agent script | PS1 file downloaded |
| 6.4 | Download Linux agent script | SH file downloaded |
| 6.5 | Simulate agent inventory via API | `curl -X POST /api/agent/inventory -H "X-Agent-Key: ..."` |
| 6.6 | Check new endpoint appears | Asset listed in Connected Endpoints |
| 6.7 | Check software inventory | Products from agent listed |

### Agent API Test Command:
```bash
curl -X POST http://localhost/api/agent/inventory \
  -H "X-Agent-Key: YOUR_KEY_HERE" \
  -H "Content-Type: application/json" \
  -d '{
    "hostname": "demo-server-01",
    "os": "Ubuntu 22.04 LTS",
    "products": [
      {"vendor": "Mozilla", "product": "Firefox", "version": "115.0"},
      {"vendor": "Apache", "product": "HTTP Server", "version": "2.4.57"},
      {"vendor": "OpenSSL", "product": "OpenSSL", "version": "3.0.2"}
    ]
  }'
```

---

## STEP 7: Inventory Page

| Test | Action | Expected Result |
|------|--------|-----------------|
| 7.1 | Products tab | All products listed with vendor, versions, CPE status |
| 7.2 | Connected Endpoints tab | All agent-reported assets |
| 7.3 | Software Overview tab | De-duplicated cross-endpoint view |
| 7.4 | Click "Assign CPE" on product without CPE | NVD search modal opens pre-populated |

---

## STEP 8: Admin Panel

| Test | Action | Expected Result |
|------|--------|-----------------|
| 8.1 | Users tab | Admin user listed |
| 8.2 | Organizations tab | Default org listed |
| 8.3 | Settings > General | App name, branding settings |
| 8.4 | Settings > Sync | CISA sync schedule, NVD API key field |
| 8.5 | Settings > Security | Session timeout, password policy |
| 8.6 | Settings > Email/Webhooks | SMTP config, webhook URL fields |
| 8.7 | Settings > LDAP | LDAP configuration (shows Pro required in Demo) |
| 8.8 | Settings > Issue Trackers | Jira/GitHub/GitLab checkboxes |

---

## STEP 9: License Management

| Test | Action | Expected Result |
|------|--------|-----------------|
| 9.1 | Go to Admin > License | License info page |
| 9.2 | Verify Demo edition shown | "Demo Version" with limits displayed |
| 9.3 | Check limits display | 1 user, 1 org, 50 products, 5 agents |
| 9.4 | Check Installation ID | SK-INST-... displayed |
| 9.5 | "Check for updates" button | Shows current version vs latest |
| 9.6 | Activate license (if testing Pro) | Enter key, verify Professional unlocked |

---

## STEP 10: API Documentation

| Test | Action | Expected Result |
|------|--------|-----------------|
| 10.1 | Navigate to /api/docs | Interactive API documentation page |
| 10.2 | Browse endpoint categories | All 80+ endpoints listed |
| 10.3 | Try an endpoint (e.g. GET /api/health) | Response shown inline |
| 10.4 | Check /api/health directly | `{"status": "healthy", "checks": {"database": "ok"}}` |
| 10.5 | Check /api/version | Version, edition, API info returned |

---

## STEP 11: Reports (Professional Only)

| Test | Action | Expected Result |
|------|--------|-----------------|
| 11.1 | Navigate to Reports | Report generation page |
| 11.2 | Generate vulnerability report | PDF downloaded |
| 11.3 | Generate compliance report | PDF with CISA BOD 22-01 status |

---

## STEP 12: Backup & Restore (Professional Only)

| Test | Action | Expected Result |
|------|--------|-----------------|
| 12.1 | Go to Admin > Backup | Backup page |
| 12.2 | Create backup | JSON backup file downloaded |
| 12.3 | Verify backup file has data | Open JSON, check products/vulns present |

---

## STEP 13: Security Verification

| Test | Action | Expected Result |
|------|--------|-----------------|
| 13.1 | Try wrong password 5x | Account locked message |
| 13.2 | Check response headers | HSTS, CSP, X-Frame-Options present |
| 13.3 | Try accessing admin as non-admin | 403 Forbidden |
| 13.4 | Check session cookie flags | HttpOnly, SameSite set |
| 13.5 | Try XSS in product name | Escaped, no script execution |

---

## STEP 14: Edge Cases

| Test | Action | Expected Result |
|------|--------|-----------------|
| 14.1 | Add product at limit (50th product in Demo) | Success |
| 14.2 | Try adding 51st product | Limit error with upgrade message |
| 14.3 | Try creating 2nd user in Demo | Limit error with upgrade message |
| 14.4 | Try creating 6th agent in Demo | Limit error with upgrade message |
| 14.5 | Refresh page during sync | No crash, sync continues |

---

## POST-DEMO: Quick Health Check

```bash
# Verify all containers running
docker compose ps

# Check app health
curl -s http://localhost/api/health | python3 -m json.tool

# Check sync status
curl -s http://localhost/api/sync/status | python3 -m json.tool

# Check version
curl -s http://localhost/api/version | python3 -m json.tool
```

---

## KNOWN LIMITATIONS (Demo Edition)

These are expected behaviors, not bugs:
- Max 1 user, 1 organization, 50 products, 5 agents
- LDAP/SAML/Email/Webhooks require Professional license
- Reports and Backup require Professional license
- "Powered by SentriKat" footer cannot be removed
- White-label branding not available

---

*Checklist version 1.0 - February 2026*
