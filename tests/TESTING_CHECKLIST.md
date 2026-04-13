# SentriKat Secondary Features Testing Checklist

## Prerequisites

```bash
# Start test environment (Keycloak + OpenLDAP + Syslog)
./tests/setup-test-env.sh

# Start SentriKat (development mode)
python run.py
```

---

## 1. Settings > System Sub-Tabs (NEW)

- [ ] Click **Settings > System** — secondary pill nav appears (Sync & Updates, General, Security, Data Retention)
- [ ] Click each sub-tab — only that section's card is visible
- [ ] Switch away to another main tab (Email, Compliance) — system sub-panes all hide
- [ ] Switch back to System — last active sub-tab is remembered
- [ ] Non-admin user: General and Security sub-tabs should NOT appear
- [ ] Save settings in each sub-tab — values persist after page reload

---

## 2. LDAP Authentication

**Config** (Settings > Authentication > LDAP):
| Field | Value |
|-------|-------|
| Server | `ldap://localhost` |
| Port | `389` |
| Base DN | `dc=sentrikat,dc=test` |
| Bind DN | `cn=readonly,dc=sentrikat,dc=test` |
| Bind Password | `readonly` |
| Search Filter | `(uid={username})` |
| Username Attr | `uid` |
| Email Attr | `mail` |

**Tests:**
- [ ] Enable LDAP, save config
- [ ] Test Connection — should succeed
- [ ] Search LDAP users — should find john.doe, jane.admin, marco.rossi
- [ ] Invite `john.doe` to an organization
- [ ] Log out, log in as `john.doe` / `password123` — should succeed
- [ ] Verify user shows `auth_type: ldap` in admin panel
- [ ] Try wrong password — should fail with clear error
- [ ] Try non-existent user — should fail gracefully
- [ ] Disable LDAP — LDAP login button should disappear

---

## 3. SAML SSO

**Config** (Settings > Authentication > SAML):
| Field | Value |
|-------|-------|
| IdP Metadata URL | `http://localhost:8080/realms/sentrikat/protocol/saml/descriptor` |
| SP Entity ID | `sentrikat-saml` |
| SP ACS URL | `http://localhost:5000/saml/acs` |
| Auto-provision | Enabled |

**Tests:**
- [ ] Enable SAML, paste IdP metadata URL, save
- [ ] Test SAML Config — should validate successfully
- [ ] Visit `/api/saml/metadata` — should return valid XML
- [ ] Click "Login with SSO" on login page
- [ ] Redirected to Keycloak login page
- [ ] Log in as `testuser` / `password123`
- [ ] Redirected back to SentriKat, logged in as testuser
- [ ] Check user was auto-provisioned (Settings > Users)
- [ ] Log in as LDAP user via SAML (`john.doe` / `password123` through Keycloak)
- [ ] Verify SAML attributes mapped correctly (email, name)
- [ ] Log out — session cleared

**Does SAML work with OpenLDAP?** YES. Keycloak federates OpenLDAP users.
LDAP users can authenticate two ways:
1. **SAML SSO** → Keycloak → validates against OpenLDAP → returns SAML assertion
2. **Direct LDAP** → SentriKat → validates against OpenLDAP directly

---

## 4. Audit Logs

**Tests:**
- [ ] Perform actions: create user, save settings, run sync
- [ ] Go to Settings > Compliance > Audit Logs
- [ ] Verify entries appear with: timestamp, user, action, resource, details
- [ ] Filter by action type — results update
- [ ] Filter by user — results update
- [ ] Export audit logs (CSV) — file downloads
- [ ] Check file rotation: `ls -la /var/log/sentrikat/audit.log*` (max 20MB, 50 backups)

---

## 5. Data Retention

**Tests:**
- [ ] Go to Settings > System > Data Retention
- [ ] Set audit log retention to 365 days
- [ ] Set sync history retention to 90 days
- [ ] Set session log retention to 30 days
- [ ] Save — success toast
- [ ] Verify values persist after page reload
- [ ] Check scheduler logs for `cleanup_old_data` job running at 3:00 AM
- [ ] Auto-acknowledge toggle: enable, click "Run Auto-Acknowledge Now"
- [ ] Verify acknowledged matches update (if applicable data exists)

---

## 6. Compliance Reports

### 6a. CISA BOD 22-01 Report
- [ ] Go to Settings > Compliance > Reports
- [ ] Click BOD 22-01 JSON — downloads JSON with KEV compliance data
- [ ] Click BOD 22-01 CSV — downloads CSV
- [ ] Click BOD 22-01 PDF — downloads PDF
- [ ] Verify data is real (not placeholder): check CVE IDs, dates, counts

### 6b. NIS2 Directive Report (NEW)
- [ ] Click NIS2 JSON — downloads JSON with Article 21 mapping
- [ ] Click NIS2 CSV — downloads CSV
- [ ] Click NIS2 PDF — downloads PDF
- [ ] Verify sections: supply_chain, vulnerability_handling, cyber_hygiene
- [ ] Verify compliance_status is calculated (COMPLIANT / PARTIALLY / NON-COMPLIANT)
- [ ] Check MTTR calculation (if acknowledged vulnerabilities exist)

### 6c. Executive Summary (NEW)
- [ ] Dashboard > Export > Executive Summary PDF — downloads one-pager
- [ ] Settings > Compliance > Executive Summary JSON — downloads JSON
- [ ] Verify risk score (0-100) is calculated
- [ ] Verify top 5 urgent vulnerabilities listed
- [ ] Verify KPIs: total matches, critical, overdue, remediation rate

---

## 7. CSV Export (NEW)

- [ ] Dashboard > Export > Export CSV (Excel) — downloads CSV
- [ ] Open in Excel — no encoding issues (UTF-8 BOM)
- [ ] Verify 18 columns present: CVE ID, severity, product, vendor, etc.
- [ ] Apply dashboard filters (priority=critical) — re-export — CSV shows only critical
- [ ] Check filter pass-through: acknowledged filter works in export

---

## 8. Scheduled Reports

- [ ] Go to Settings > Compliance > Scheduled Reports
- [ ] Create new report: daily, 09:00, summary type
- [ ] Add recipient email
- [ ] Enable "send to managers" toggle
- [ ] Save — report appears in list
- [ ] Click "Send Now" — report sends (check email or logs)
- [ ] Verify `last_sent` timestamp updates
- [ ] Create weekly report with NIS2 type (Compliance EU NIS2 option)
- [ ] Toggle report off — verify `enabled: false`
- [ ] Delete report — removed from list
- [ ] Check scheduler logs for `process_scheduled_reports` job (every 10 min)

**Note:** Requires SMTP configured in Settings > Email & Alerts

---

## 9. Notifications

### 9a. Email Alerts
- [ ] Configure SMTP (Settings > Email & Alerts)
- [ ] Test email — verify delivery
- [ ] Trigger a sync — if new critical CVEs found, alert should send
- [ ] Check AlertLog table for sent records

### 9b. Slack / Teams / Webhook
- [ ] Settings > Integrations > Slack: add webhook URL, test
- [ ] Settings > Integrations > Teams: add webhook URL, test
- [ ] Settings > Integrations > Generic Webhook: add URL, select format, test

### 9c. Issue Trackers
- [ ] Settings > Integrations > Jira: configure, test connection
- [ ] Create issue from a vulnerability — verify ticket in Jira

---

## 10. License Activation

### 10a. Online Activation
- [ ] Go to Settings > License
- [ ] Note the Installation ID displayed
- [ ] Enter activation code, click "Activate Online"
- [ ] If server reachable: license activates, features unlock
- [ ] If server unreachable: shows error, falls back to offline

### 10b. Installation ID Stability
- [ ] Note current Installation ID
- [ ] Restart SentriKat — ID should be same
- [ ] **Docker:** Set `SENTRIKAT_INSTALLATION_ID` in .env — rebuild — ID stays same
- [ ] **Without env var in Docker:** rebuild will generate new ID = license invalid

### 10c. License Heartbeat
- [ ] Check logs for `license_heartbeat` running every 12 hours
- [ ] Verify telemetry: agent count, product count, org count sent
- [ ] Works offline: no error if portal unreachable

---

## 11. EPSS Scoring

- [ ] Run a CISA KEV sync (to get vulnerabilities)
- [ ] Check any vulnerability detail — EPSS score should show
- [ ] If no score: trigger EPSS sync manually or wait for scheduler
- [ ] Verify EPSS fields in DB: `epss_score`, `epss_percentile`, `epss_fetched_at`
- [ ] **After server rebuild:** EPSS scores should persist (stored in DB, not cache)
- [ ] **Should it reset?** NO — scores are in PostgreSQL. Only in-memory cache resets (re-fetched within 24h)
- [ ] Risk level color coding: Critical (95%+), High (85%+), Medium (70%+), Low (<70%)

---

## 12. CPE Dictionary

- [ ] Settings > System > Sync — check CPE dictionary stats
- [ ] Verify entries count > 0 (should have thousands after sync)
- [ ] Check last sync timestamps (bulk download + incremental)
- [ ] Test: add a known product (e.g., "Apache HTTP Server") — should get CPE auto-mapped
- [ ] Verify lookup strategies: exact match (0.92), product-only (0.88), alias (0.60-0.85)
- [ ] Check KB sync status if enabled

---

## 13. Knowledge Base (KB)

- [ ] Settings > System > Sync — check KB server status
- [ ] If enabled: verify `last_pull` timestamp
- [ ] KB pulls community CPE mappings (capped at 0.85 confidence)
- [ ] KB pushes local mappings with usage_count >= 5
- [ ] Check scheduler logs for KB sync job

---

## 14. Two-Factor Authentication (2FA)

### 14a. Per-User Setup
- [ ] Log in as any user
- [ ] Go to user profile/settings
- [ ] Click "Enable 2FA"
- [ ] QR code appears — scan with Google Authenticator / Authy
- [ ] Enter 6-digit code to verify — 2FA enabled
- [ ] Log out, log in — prompted for 2FA code
- [ ] Enter correct code — access granted
- [ ] Enter wrong code — access denied

### 14b. Per-Organization (Admin Require)
- [ ] As admin, set `totp_required: true` for a user
- [ ] That user is forced to set up 2FA on next login
- [ ] Cannot bypass without setting up TOTP

### 14c. Disable
- [ ] User disables 2FA from profile
- [ ] Next login — no 2FA prompt

---

## 15. SIEM / Syslog Forwarding (NEW)

### How to Test:

```bash
# 1. Start syslog receiver (already in test env)
docker logs -f sentrikat-syslog

# 2. Configure in SentriKat (Settings > SIEM / Syslog):
#    Host: localhost
#    Port: 5514
#    Protocol: UDP
#    Format: CEF
#    Enabled: On

# 3. Click "Test Connection" — watch docker logs for message

# 4. Alternative: test with netcat (no Docker needed)
nc -u -l -p 5514    # UDP listener
nc -l -p 5514       # TCP listener
# Then send test from SentriKat UI
```

**Tests:**
- [ ] Configure syslog (Settings > SIEM / Syslog)
- [ ] Save settings — success toast
- [ ] Click "Test Connection"
- [ ] **CEF format:** Verify in syslog: `CEF:0|SentriKat|VulnerabilityManagement|1.0|test|...`
- [ ] Switch to JSON format, test again — verify JSON structure in logs
- [ ] Switch to RFC5424 format, test again — verify RFC structure
- [ ] Switch UDP → TCP, test — verify works over TCP
- [ ] Disable syslog, save — no more events forwarded
- [ ] Reload page — settings persisted correctly

---

## Quick Validation Commands

```bash
# Check scheduler jobs are registered
curl -s http://localhost:5000/api/sync/status | python3 -m json.tool

# Check EPSS scores exist
curl -s http://localhost:5000/api/vulnerabilities?limit=5 | python3 -m json.tool | grep epss

# Check license status
curl -s http://localhost:5000/api/license/status | python3 -m json.tool

# Check SAML metadata
curl -s http://localhost:5000/api/saml/metadata

# Check SAML status
curl -s http://localhost:5000/api/saml/status | python3 -m json.tool

# Download NIS2 report (requires auth cookie)
curl -b cookies.txt http://localhost:5000/api/reports/compliance/nis2?format=json | python3 -m json.tool

# Test syslog with netcat (manual)
echo '<14>1 2026-02-11T12:00:00Z sentrikat test - - - Test message' | nc -u localhost 5514
```

---

---

## Sprint 4: Assignments Management (#29)

**Setup:** Have at least one product with vulnerabilities tracked. Be logged in as `org_admin`.

- [ ] Open dashboard. The Assignments widget appears in the left column.
- [ ] Click the list icon on the Assignments widget header → Assignments Management panel expands.
- [ ] Use Remediation Actions table → click person-plus icon → Assign modal opens with product pre-filled.
- [ ] Fill in assignee email, priority, due date, notes. Click "Assign". Toast shows "Assigned to ...".
- [ ] New assignment appears in the management table.
- [ ] **Filter by Status:** select "Open" → only open assignments shown. Select "All" → all visible.
- [ ] **Filter by Priority:** select "Critical" → only critical shown.
- [ ] **Search:** type assignee email → filters results.
- [ ] **Pagination:** create >25 assignments → pagination controls appear → click page 2 works.
- [ ] **Quick status change:** Click play (▶) on an open assignment → status flips to In Progress with toast.
- [ ] **Quick resolve:** Click ✓ on in_progress assignment → status flips to Resolved.
- [ ] **Detail/Edit modal:** Click pencil icon → modal opens with all fields populated.
- [ ] In modal, change status to "Accepted Risk", add resolution notes, save → table updates.
- [ ] Delete button on detail modal (org_admin only) → confirms → removes from list.
- [ ] Try as a non-admin user → mutation buttons hidden / 403 on direct API call.
- [ ] **Cross-tenant test:** Org A admin tries to GET /api/remediation/assignments/<id> for Org B's assignment → 404.
- [ ] **Rate limit:** 60+ POST /api/remediation/assignments in 1 minute → 429 after 60.

## Sprint 4: Issue Tracker Integration on Assignments (#30)

**Setup:** Configure Jira (or any tracker) in Admin → Integrations → Issue Trackers. Connect successfully.

- [ ] Open Assign modal → "Also create issue tracker ticket" checkbox is visible.
- [ ] Without tracker configured → checkbox is hidden.
- [ ] Check the box, submit → assignment created AND ticket appears in the table "Ticket" column with link.
- [ ] Click ticket link → opens the tracker issue in a new tab.
- [ ] Open Detail modal → "Ticket" field shows tracker key + type label "(jira)".
- [ ] **Tracker failure path:** Misconfigure tracker (wrong API key) → submit → assignment IS created, but warning toast: "Warning: ticket creation failed".
- [ ] Verify the same flow works with **YouTrack**, **GitHub**, **GitLab** if configured.
- [ ] Verify multi-tracker: enable Jira + GitHub → tracker_type field in POST selects which one.
- [ ] DB check: `SELECT tracker_issue_key, tracker_issue_url, tracker_type FROM remediation_assignments WHERE id=?` → all three populated correctly.

## Sprint 4: Email Notifications for Assignments (#31)

**Setup:** Configure SMTP or use Resend in dev mode. Have a test email inbox.

- [ ] Create a new assignment with `assigned_to=test@example.com` → 1 email arrives within 30s.
- [ ] Email subject: `[SentriKat] New Remediation Assignment`. Body shows priority badge, due date, product, notes.
- [ ] **Update test (no email expected):** Change status open → in_progress → no email.
- [ ] **Resolve test:** Change status to "resolved" → 1 email arrives, subject `[SentriKat] Assignment Resolved`.
- [ ] **Throttle test:** Create 3 assignments in 5 seconds → first one sends email, subsequent same-assignment updates within 1 hour are throttled (logged as "throttled" but no email).
- [ ] Org admins are NOT CC'd (only the assignee receives the email).
- [ ] Email volume after 10 create + 10 status changes + 5 resolutions = max 15 emails (NOT 50+).
- [ ] **HTML escape test:** Assignee notes contain `<script>alert(1)</script>` → email body shows it as literal text, no script execution.

## Sprint 4: SBOM Export (#32)

**Setup:** Have at least 5 products with versions and at least 3 matched CVEs.

- [ ] Open dashboard → Export dropdown → "SBOM Export" section visible.
- [ ] Click "CycloneDX 1.5 (JSON)" → downloads a JSON file.
- [ ] Open file → has `bomFormat: "CycloneDX"`, `specVersion: "1.5"`, `components` array, `vulnerabilities` array.
- [ ] Each component has: type, name, version, purl (e.g. `pkg:apt/openssl/openssl@1.1.1k`), supplier (vendor).
- [ ] Each vulnerability has: id (CVE), source, ratings, affects refs to components.
- [ ] Click "SPDX 2.3 (JSON)" → downloads JSON file with `spdxVersion: "SPDX-2.3"`, `packages` array.
- [ ] Each package has SPDXID, name, versionInfo, externalRefs (cpe23Type if available).
- [ ] **Validate with online tool:** Upload to https://cyclonedx.github.io/cyclonedx.org/tool-center/ → no validation errors.
- [ ] **Cross-tenant:** Org A user calls `/api/sbom/export/cyclonedx` → only Org A products in output.
- [ ] **License gate:** Free user (no Professional license) → 403 with upgrade message.
- [ ] **Rate limit:** 11+ requests in 1 hour → 429 after 10.

## Sprint 4: Risk Exception Management (#33)

- [ ] Click the shield icon to open the Risk Exceptions panel (or use API directly).
- [ ] **Create:** Use API: `POST /api/risk-exceptions` with `{justification: "WAF mitigation in place", expires_at: "2026-12-31", cve_id: "CVE-2024-1234", product_id: 1}` → 201.
- [ ] Exception appears in the panel with status "Active".
- [ ] Justification truncated to 60 chars in table; full text in tooltip.
- [ ] **Filter by status:** "Active" → only active visible. "Revoked" → only revoked.
- [ ] **Revoke:** Click X button on active → confirms → status changes to "Revoked".
- [ ] **Permanent exception:** Create without `expires_at` → "Expires" column shows "Permanent".
- [ ] **Expiry warning:** Create with past `expires_at` → `is_expired: true` flag → warning icon shown.
- [ ] **Required field:** Submit without justification → 400 error "Justification required".
- [ ] **Cross-tenant:** Try to revoke another org's exception → 404.
- [ ] **non-admin:** Regular user tries POST → 403.
- [ ] **Rate limit:** 30+ POSTs/minute → 429 after 30.

## Sprint 4: Agent Delta Scan + HTTP Compression (#34)

**Setup:** Install Linux/macOS/Windows agent on a test machine. Configure to point to test server.

### Linux/macOS agent
- [ ] First run: agent sends FULL inventory. Server log shows `delta=full`.
- [ ] Second run (no software changes): agent sends LIGHTWEIGHT heartbeat. Server log shows `delta=unchanged`.
- [ ] Verify `last_hash.txt` exists at `/var/lib/sentrikat/last_hash.txt` (Linux) or `/usr/local/var/sentrikat/last_hash.txt` (macOS).
- [ ] Install a new package (e.g. `apt install jq`) → next run sends FULL inventory again.
- [ ] **24h forced full:** Set system clock forward 25h → next run sends full even if hash unchanged.
- [ ] **Compression check:** tcpdump on agent → POST body uses `Content-Encoding: gzip` header.
- [ ] Server log: payload size <2KB after gzip (was 100-500KB before).

### Windows agent
- [ ] Same checks apply. Hash file at `$env:ProgramData\SentriKat\last_hash.txt`.
- [ ] PowerShell GZip compression visible in network capture.

### Server-side
- [ ] **Zip bomb protection:** Send a 1KB compressed payload that decompresses to 100MB → server returns 413 "Decompressed payload too large".
- [ ] **Oversized compressed:** Send 5MB compressed → server returns 413 "Compressed payload too large".
- [ ] Normal heartbeat (10KB compressed → 100KB decompressed) → 200 OK.

## Sprint 4: Agent Store-and-Forward (#35)

- [ ] Stop the SentriKat server (or block its hostname in /etc/hosts on the agent machine).
- [ ] Run agent 5 times → all heartbeats fail → 5 files appear in `/var/lib/sentrikat/spool/` (Linux) or equivalent.
- [ ] Restart the server / unblock connectivity.
- [ ] Run agent once → spool files are sent in chronological order BEFORE the new heartbeat.
- [ ] Spool directory is empty after replay.
- [ ] **Spool limit:** Block server, run 60+ heartbeats → spool contains 50 files (oldest deleted).
- [ ] **Replay stops on failure:** Block server again mid-replay → no further replay attempts until next successful heartbeat.
- [ ] Verify in server logs: each spooled payload received and processed in order.

## Sprint 4: Product Alias / Disambiguation (#36)

- [ ] **Create alias via API:** `POST /api/product-aliases {product_id: 1, alias_vendor: "OpenSSL", alias_product: "openssl-libs"}` → 201.
- [ ] **List:** `GET /api/product-aliases` → returns the alias with embedded product info.
- [ ] **Duplicate check:** POST same alias → 409 conflict.
- [ ] **Cross-tenant:** Try product_id from another org → 403.
- [ ] **Delete:** `DELETE /api/product-aliases/<id>` → 200 → list is empty.
- [ ] **Non-admin:** Regular user POST → 403.
- [ ] **Rate limit:** 30+ POST/minute → 429.
- [ ] DB: unique constraint enforced on `(organization_id, alias_vendor, alias_product)`.

## Sprint 4: Telemetry / Metrics

- [ ] `GET /metrics` (Prometheus endpoint) → contains `sentrikat_assignments{status="open"}`, `sentrikat_assignments_overdue`, `sentrikat_assignments_with_tracker_ticket`.
- [ ] Contains `sentrikat_risk_exceptions{status="active"}` and `sentrikat_product_aliases_total`.
- [ ] All values reflect current DB state.

## Sprint 4: Database & Migration

- [ ] Run `db.create_all()` on a fresh DB → all new tables exist: `remediation_assignments`, `sla_policies`, `risk_exceptions`, `product_aliases`.
- [ ] `remediation_assignments` table has `tracker_issue_key`, `tracker_issue_url`, `tracker_type` columns.
- [ ] Composite indexes exist: `idx_assign_org_status`, `idx_assign_org_assignee`, `idx_assign_org_due`, `idx_riskexc_org_status`, `idx_riskexc_org_expiry`.
- [ ] `product_aliases` has unique constraint `uq_product_alias`.
- [ ] **Migration from existing prod DB:** Add migration script for new columns/tables (Alembic or manual SQL).

---

## Test Environment Teardown

```bash
docker compose -f docker-compose.test.yml down -v
```
