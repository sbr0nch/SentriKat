# Fase 11 — Integrations

> Outbound integrations verso ticketing, chat, SIEM, asset discovery. Surface principale: `app/integrations_api.py` (~2000 righe), `/admin/integrations` UI, settings tab "Integrations".
>
> **Testlab disponibile** (PC casa): Mailpit (SMTP), webhook-tester (8800), jira-mock (8080→1080), syslog (514 UDP). Vedi `CLAUDE.md` § Testlab.

## Aree coperte — Ticketing

| Area | Surface | Description | Env |
|---|---|---|---|
| 11.1 | **Jira Cloud / Server / Data Center** | OAuth or API token, project search, issue type config, custom fields, link CVE→issue | 🏢☁️ both |
| 11.2 | **GitHub Issues** | PAT auth, repo selector, label mapping | 🏢☁️ both |
| 11.3 | **GitLab Issues** | PAT or OAuth, project selector | 🏢☁️ both |
| 11.4 | **YouTrack** | Permanent token auth | 🏢☁️ both |

## Aree coperte — Chat

| Area | Surface | Description | Env |
|---|---|---|---|
| 11.5 | **Slack** | Incoming webhook URL, channel routing | 🏢☁️ both |
| 11.6 | **MS Teams** | Adaptive card payload, channel webhook | 🏢☁️ both |
| 11.7 | **Discord** | Webhook URL, embed format | 🏢☁️ both |

## Aree coperte — Generic

| Area | Surface | Description | Env |
|---|---|---|---|
| 11.8 | **Generic Webhook outbound** | JSON POST, custom headers, event filter | 🏢☁️ both |
| 11.9 | **SIEM Syslog** | RFC 5424 / CEF / LEEF format, TCP/UDP/TLS | 🏢☁️ both |

## Aree coperte — Asset Discovery (inbound)

| Area | Surface | Description | Env |
|---|---|---|---|
| 11.10 | **PDQ Inventory** | API token, scan results import → products | 🏢☁️ both |
| 11.11 | **Microsoft SCCM/MECM** | SQL or WMI query, on-prem only | 🏢 on-prem |
| 11.12 | **Microsoft Intune** | Graph API OAuth, device fleet | ☁️ SaaS |
| 11.13 | **Lansweeper** | API token, asset import | 🏢☁️ both |

## Aree common

| Area | Surface | Description | Env |
|---|---|---|---|
| 11.14 | Test Connection (every type) | `/api/integrations/<id>/test` button | 🏢☁️ both |
| 11.15 | Regenerate API key | `/api/integrations/<id>/regenerate-key` | 🏢☁️ both |
| 11.16 | Manual sync trigger | `/api/integrations/<id>/sync` POST | 🏢☁️ both |
| 11.17 | Webhook outbox retry | Failed events retry, max attempts, dead-letter | 🏢☁️ both |
| 11.18 | RBAC integration access | super_admin only configures, manager can trigger sync | 🏢☁️ both |
| 11.19 | Audit trail per integration | who configured, when, what changed | 🏢☁️ both |

## 7-dim standard

---

_Sezioni 11.1-11.19 da popolare durante walkthrough. Anti-pattern: Massimiliano testerà 11.1 (Jira mock) prima per validare flow CVE→issue, poi 11.5 (Slack) e 11.8 (Webhook tester) per validare outbound generico. Asset connectors (11.10-11.13) deferred (richiedono setup connectors esterni)._

---

## Walkthrough protocol — pre-EA pass (2026-05-07)

> Prerequisite: testlab containers up (`cd C:\SentriKat\testlab; docker compose -f docker-compose.testlab.yml up -d`).
> Verifica: `docker ps | findstr testlab` → `testlab-jira-mock`, `testlab-mailpit`, `testlab-webhook-tester` running.

### W11.1 — Jira (mock) integration

**Setup**:
1. Login admin → `/admin/integrations` → New Integration → Type: Jira
2. URL: `http://host.docker.internal:8080`
3. Auth: API token. Email: `test@sentrikat.local`. Token: `mock-token-123`
4. Project key: `VULN`
5. Click `Test Connection`
6. Click `Save`

**7-dim**:
- **Dim 1 happy path**: Test Connection green ✅ → save success → integration appears in list
- **Dim 2 persistence**: F5 → integration still listed → click edit → fields populated
- **Dim 3 CRUD**: edit URL → save → verify update; create 2nd Jira integration → distinguishable; delete one → only remaining
- **Dim 4 RBAC**: logout, login as `manager` → `/admin/integrations` denied OR read-only; login as `user` → 403
- **Dim 5 state transitions**: integration status `pending` → `active` after first successful test
- **Dim 6 negative input**: bad URL (`http://nonexistent:9999`) → Test Connection error w/ readable message; empty project key → validation block
- **Dim 7 integration/audit**:
  - From dashboard, open a CVE → "Create Jira Issue" button → fills issue → submits → check `http://localhost:8080/mockserver/expectations` for received POST `/rest/api/2/issue`
  - Audit log: super_admin user shows `integration_create` + `integration_test` events with timestamp + IP

**Bugs to log**: any UX glitch (spinner stuck, error after success, button doesn't enable) → ID `[11.1.X]`

### W11.5 — Slack webhook (use webhook-tester as receiver)

**Setup**:
1. New Integration → Type: Slack
2. Webhook URL: `http://host.docker.internal:8800/<your-uuid-from-webhook-tester-UI>`
3. Get UUID from `http://localhost:8800` (auto-generated on first visit, copy URL)
4. Channel: `#alerts` (will appear in payload, mock doesn't validate)
5. Test Connection → expect green; webhook-tester UI shows the test payload

**7-dim** (compressed): same pattern as W11.1, focused on:
- Dim 1: Test Connection emits payload visible in webhook-tester
- Dim 6: malformed URL (missing scheme) → error
- Dim 7: trigger an alert (simulate via Alerts page if Phase 12 ready, or manual test event) → webhook-tester logs the JSON

### W11.8 — Generic Webhook outbound

**Setup**: same as W11.5 but Type=Generic Webhook. Add custom header `X-Sentrikat-Test: 1`. Verify webhook-tester receives request with that header echoed.

**Dim 7 critical**: Webhook outbox retry — temporarily set webhook-tester URL to invalid path → trigger event → verify exponential backoff in `/admin/integrations/<id>/outbox` (or DB `webhook_outbox` table), then fix URL → verify dead-letter recovery works.

### W11.9 — SIEM Syslog (testlab-syslog UDP 514)

**Setup**:
1. New Integration → Type: Syslog
2. Host: `testlab-syslog`. Port: `514`. Protocol: UDP. Format: RFC 5424
3. Save (no Test Connection for UDP)
4. Trigger any audit event (e.g., login as another user) → check `docker exec testlab-syslog cat /var/log/syslog | tail -20` for the message

### W11.14 — Test Connection (matrix per type)

Per ogni type integrato, premi Test Connection → annota:
- Tempo risposta (target < 5s)
- Errore leggibile su URL non raggiungibile (NON stack trace; NON timeout silente)
- 401 → messaggio "credenziali errate" (NON solo "Connection failed")

### Quando segnalare bug

Format: `[11.X.N]` Severity Env Title. Esempio:
```
[11.1.3] 🔴 HIGH 🏢 — Jira Test Connection ritorna 200 anche se URL irraggiungibile
- Symptom: ...
- Repro: ...
- Expected: ...
- Hypothesis: ...
```

Logger sweep di stamane (PR #14acef5) ora rende visibili nei log `application.log` failure di parser e DB events; controlla `docker exec sentrikat tail -f /var/log/sentrikat/application.log` durante il walkthrough per cogliere errori che prima erano silenti.

## Bug summary

| Bug ID | Severity | Env | Title |
|---|---|---|---|
| _(none yet)_ | | | |

## Cross-ref

- `app/integrations_api.py` (~2000 righe) — main module
- `tests/mock-configs/` — mockserver expectations per Jira / GitLab / GitHub
- `CLAUDE.md` § Jira mock — endpoint preconfigurati con project key VULN
