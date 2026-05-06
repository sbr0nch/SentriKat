# Fase 09 — Remediation & SLA

> Assignments, SLA policies, risk exceptions, product aliases, escalation tracking. Workflow di gestione vulnerabilità: dal match scoperto al fix completato.
>
> **Surface principale**: `/assignments` (UI), `app/remediation_api.py`, `app/maintenance.py:auto_expire_risk_exceptions`.

## Aree coperte

| Area | Surface | Description | Env |
|---|---|---|---|
| 09.1 | `/api/assignments` POST/GET/PATCH | Crea assignment per match (assignee, due_date, priority, status), state machine new→in_progress→resolved | 🏢☁️ both |
| 09.2 | SLA policy config | Setup policy per severity/priority (es. CRITICAL=72h, HIGH=7d, MEDIUM=30d) | 🏢☁️ both |
| 09.3 | SLA breach detection | Match approaching due / overdue, escalation, daily digest | 🏢☁️ both |
| 09.4 | Risk Exception | Asset-specific + org-wide wildcards, expires_at, audit trail | 🏢☁️ both |
| 09.5 | `auto_expire_risk_exceptions` | Scheduler job che expira exception scadute | 🏢☁️ both |
| 09.6 | Product Aliases | Stesso prodotto ribattezzato in due agent → unify match | 🏢☁️ both |
| 09.7 | Email notification on assignment | `send_remediation_assignment_notification` (`email_service.py:127`) | 🏢☁️ both |
| 09.8 | Webhook outbound on state change | `assignment.created`, `assignment.resolved` events | 🏢☁️ both |
| 09.9 | Bulk assignment from product card | "Assign all CVEs for product X" workflow | 🏢☁️ both |
| 09.10 | Assignment notes RBAC | `_can_view_assignment_notes` + `_redact_assignment_notes` filters | 🏢☁️ both |

## 7-dim standard

(Vedi `00-INDEX.md` § 7-dim)

---

_Sezioni 09.1-09.10 da popolare durante walkthrough live. Status iniziale: ⬜ da iniziare._

## Bug summary

| Bug ID | Severity | Env | Title |
|---|---|---|---|
| _(none yet)_ | | | |
