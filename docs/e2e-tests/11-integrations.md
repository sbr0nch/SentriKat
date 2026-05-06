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

## Bug summary

| Bug ID | Severity | Env | Title |
|---|---|---|---|
| _(none yet)_ | | | |

## Cross-ref

- `app/integrations_api.py` (~2000 righe) — main module
- `tests/mock-configs/` — mockserver expectations per Jira / GitLab / GitHub
- `CLAUDE.md` § Jira mock — endpoint preconfigurati con project key VULN
