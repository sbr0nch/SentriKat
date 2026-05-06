# Fase 12 — Alerts & Notifications

> Email + webhook outbox per eventi prodotto: nuovo match HIGH, assignment, digest critici. Surface principale: `app/email_service.py`, `app/alerts.py` (se esiste), settings tab "Alert Management" + "Email (SMTP)".

## Aree coperte

| Area | Surface | Description | Env |
|---|---|---|---|
| 12.1 | **SMTP config** | Host, port, TLS/STARTTLS, username, password (Fernet-encrypted), Reply-To | 🏢☁️ both |
| 12.2 | **SMTP Test Connection** | Send test email a indirizzo arbitrary, verifica accept | 🏢☁️ both |
| 12.3 | **Critical CVE digest giornaliero** | Aggregated email con tutti i nuovi HIGH/CRITICAL match scoperti nelle ultime 24h | 🏢☁️ both |
| 12.4 | **Patch Tuesday email** | Microsoft second-Tuesday CVE roundup (`send_patch_tuesday_digest`) | 🏢☁️ both |
| 12.5 | **Assignment notification** | `send_remediation_assignment_notification` quando assignment created/updated | 🏢☁️ both |
| 12.6 | **Product assignment notification** | `send_product_assignment_notification` quando product viene assegnato a un'org diversa | 🏢☁️ both |
| 12.7 | **Webhook outbox** | Internal queue + worker, retry su fail, max 3 tentativi, dead-letter dopo | 🏢☁️ both |
| 12.8 | **Alert rules per organization** | Override per-org: silence Critical-only, escalation contacts, throttle rate | 🏢☁️ both |
| 12.9 | **Alert throttling** | Max N email/hour per org per tipo, anti-flood | 🏢☁️ both |
| 12.10 | **Email quota tracking** | `/api/settings/email/quota`, monthly limit, alert quando 80%/95% | 🏢☁️ both |
| 12.11 | **Delivery deliverability** | SPF/DKIM/DMARC alignment, Reply-To header, List-Unsubscribe RFC 8058 (post sentrikat-web PR #257 lato customer email) | 🏢☁️ both |
| 12.12 | **Bounce handling** | Catch hard bounces, suspend email to bouncing addresses, audit log | 🏢☁️ both |

## 7-dim standard

---

_Sezioni 12.1-12.12 da popolare durante walkthrough live. Anti-pattern: testlab Mailpit (port 1025 SMTP, 8025 UI) per validate end-to-end senza spedire mail reali. Webhook tester (port 8800) per webhook outbox._

## Bug summary

| Bug ID | Severity | Env | Title |
|---|---|---|---|
| _(none yet)_ | | | |

## Cross-ref

- `app/email_service.py` — sender abstraction
- Scheduler jobs `critical_cve_reminder`, `patch_tuesday_digest`
- `CLAUDE.md` § Testlab Mailpit + Webhook-tester
- `docs/e2e-tests/04-portal-customer.md` `[04.1.5]` — OTP email branding deliverability lato customer (cluster cross-flow)
