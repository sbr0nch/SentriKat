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

## Test Environment Teardown

```bash
docker compose -f docker-compose.test.yml down -v
```
