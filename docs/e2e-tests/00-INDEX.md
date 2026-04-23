# SentriKat E2E Test & Bug List — Master Index

> **Obiettivo:** mappare TUTTO SentriKat (SaaS + on-prem + portal + landing + prodotto core) con test end-to-end e raccogliere una bug list esaustiva. **Non risolviamo qui.** Solo testare e annotare.
>
> **Metodo collaborativo:** Claude dà un prompt puntuale per una sezione alla volta → utente esegue nel browser/terminale → riporta output/screenshot/errori → Claude aggiunge bug nel file della fase corrispondente → si passa al prossimo prompt.

---

## Repo coinvolte

| Repo | Path | Ruolo |
|---|---|---|
| `sbr0nch/SentriKat` | `/home/user/SentriKat` | Prodotto core (Flask, vuln mgmt, agent API, app.sentrikat.com) |
| `sbr0nch/SentriKat-web` | remota (https://github.com/sbr0nch/SentriKat-web) | Landing + Portal + License server FastAPI + Docs MkDocs + Flarum + nginx |

## Domini produzione

| Dominio | Componente | Repo |
|---|---|---|
| `sentrikat.com` | Landing marketing (Astro) | SentriKat-web `/landing` |
| `portal.sentrikat.com` | Portal customer + admin (Astro) | SentriKat-web `/portal` |
| `api.sentrikat.com` | License server (FastAPI) | SentriKat-web `/license-server` |
| `docs.sentrikat.com` | Documentazione (MkDocs) | SentriKat-web `/docs` |
| `community.sentrikat.com` | Forum (Flarum) | SentriKat-web `/community` |
| `app.sentrikat.com` | Prodotto SaaS core (Flask) | SentriKat (core) |
| *(self-hosted)* | Istanza on-prem | SentriKat (core) via Docker |

---

## Fasi del journey (16 fasi)

Ogni fase ha un proprio file `NN-nome.md` (creato al momento, non tutti in anticipo).

| # | File | Area | Status |
|---|---|---|---|
| 01 | `01-landing-site.md` | Landing `sentrikat.com`: nav, CTA, pagine marketing, blog, vs/*, compliance, pricing, legal, sitemap, RSS, cookie banner | ✅ completata (3 bug, 1 warn, 3 info, 18 OK — follow-up non bloccanti aperti) |
| 02 | `02-signup-saas.md` | Signup SaaS: form Early Access, capacity check, `/api/v1/provision/trial`, Stripe checkout, webhook, bridge provisioning → `app.sentrikat.com` | ⬜ |
| 03 | `03-signup-onprem.md` | Signup on-prem: lead/contact sales, acquisto license, download binario, install Docker, setup wizard, attivazione RSA, hardware lock | ⬜ |
| 04 | `04-portal-customer.md` | `portal.sentrikat.com` customer: OTP login, dashboard, account, licenze, downloads, support/feedback, checkout, upgrade, logout | ⬜ |
| 05 | `05-portal-admin.md` | `portal.sentrikat.com` admin: 25 pagine admin (customers, licenses, plans, leads, demo-requests, feedback, audit, logs, usage-metrics, ecc.) | ⬜ |
| 06 | `06-app-auth-rbac.md` | `app.sentrikat.com` auth: local, LDAP/AD, SAML 2.0, TOTP 2FA, session, password reset, RBAC (super_admin/org_admin/manager/user) | ⬜ |
| 07 | `07-agents-inventory.md` | Agent: download script Win/Linux/macOS, deploy, API key, inventory, heartbeat, job processing, asset mgmt, container scan, dependency scan (sentrikat-scan CLI) | ⬜ |
| 08 | `08-scanning-matching.md` | Vuln matching: CISA KEV sync, NVD/CVE.org/ENISA fallback, CPE 4-tier mapping, 3-phase filter (derivatives/history-guard/noise), backport detection (OSV/RedHat/MSRC/Debian), EPSS | ⬜ |
| 09 | `09-remediation-sla.md` | Assignments, SLA policies, risk exceptions, product aliases, escalation, tracking | ⬜ |
| 10 | `10-compliance-sbom.md` | Reports: CISA BOD 22-01, NIS2, PCI-DSS v4.0, ISO 27001:2022, SOC 2, SBOM (CycloneDX/SPDX/STIX), executive summary, scheduled reports, Patch Tuesday digest, SBOM import | ⬜ |
| 11 | `11-integrations.md` | Jira, GitHub Issues, GitLab Issues, YouTrack, Slack, Teams, Discord, webhook generico, SIEM syslog/CEF, connettori PDQ/SCCM/Intune/Lansweeper | ⬜ |
| 12 | `12-alerts-notifications.md` | SMTP config, critical digest giornaliero, Patch Tuesday email, webhook outbox, alert rules per org, throttling, reply-to, email quota | ⬜ |
| 13 | `13-admin-ops.md` | Admin panel core, super admin, health checks, logs, Prometheus metrics, OpenTelemetry, backup/restore (on-prem), scheduler jobs, maintenance, cleanup | ⬜ |
| 14 | `14-saas-specific.md` | SaaS: quota/limiti per piano, feature gating, isolamento multi-tenant, license webhook, trial expiry, upgrade/cancel, metering, addons | ⬜ |
| 15 | `15-security-edge.md` | SQL injection, XSS, CSRF, LDAP injection, SSRF, command injection, path traversal, rate limiting, lockout, encryption at rest (Fernet), edge cases (DB down, disk full, NVD down, ecc.) | ⬜ |
| 16 | `16-extra-shared.md` | Shared views pubblici, GDPR export/delete, community Flarum, docs MkDocs, n8n workflow, nginx reverse proxy, deploy pipeline (CI/CD + staging) | ⬜ |

**Legenda status:** ⬜ da iniziare · 🟡 in corso · ✅ completato (tutte le sotto-aree viste)

---

## Formato bug (da usare in ogni file fase)

Ogni bug/osservazione va aggiunta con questo schema:

```markdown
### [01.3.2] Titolo breve del bug

- **Fase**: 01 — Landing site
- **Area**: Form Trial Signup
- **URL/Endpoint**: `https://sentrikat.com/#trial` → `POST /api/v1/provision/trial`
- **Tipo**: 🔴 Bug | 🟡 Warning | 🔵 Info/UX | 🟢 OK (test passato)
- **Severity**: Critical | High | Medium | Low | Info
- **Environment**: prod | staging | local dev
- **Steps to reproduce**:
  1. Apri ...
  2. Compila ...
  3. Clicca ...
- **Expected**: ...
- **Actual**: ...
- **Evidence**: screenshot path / console log / response JSON
- **Note**: ipotesi causa, file sorgente sospetto, workaround
- **Discovered**: 2026-04-23
```

**ID schema**: `<fase>.<area>.<contatore>` → esempio `01.3.2` = fase 01, area 3 (form), bug #2.

---

## Come procediamo (workflow)

1. Io (Claude) ti do **UN prompt puntuale** per una sotto-area (es: "apri sentrikat.com, guarda la navbar, riporta: link che funzionano, link rotti, errori console, rendering mobile").
2. Tu esegui (browser, DevTools aperto, mobile view, dati test ecc.) e mi mandi: screenshot, testo errori, response JSON, quello che serve.
3. Io aggiorno il file della fase corrente aggiungendo i bug trovati con lo schema sopra (+ creo il file se è la prima volta che entriamo in quella fase).
4. Ti do il **prossimo prompt** della stessa fase (o passiamo alla successiva quando la fase è chiusa).
5. A fine fase aggiorno lo status qui sopra (🟡 → ✅).

**Sotto-fasi tipiche** dentro una fase = aree dichiarate nella tabella. Dentro ciascuna area testiamo: happy path → edge case → errore → security.

---

## Progress log

| Data | Fase | Azione | Note |
|---|---|---|---|
| 2026-04-23 | — | Setup struttura test | Creato indice, definito formato |
| 2026-04-23 | 01 | Primo giro home (load + nav + footer + mobile) | 2 bug, 1 warning, 4 OK registrati in `01-landing-site.md` |
| 2026-04-23 | 01 | Conferma navbar (no duplicato logo/wordmark) | 01.4.1 confermato OK |
| 2026-04-23 | 01 | Marketing + legal via footer → OK batch | 01.11.1, 01.14.1 OK |
| 2026-04-23 | 01 | vs/ + SEO artifacts + 404 | vs/ OK, sitemap/robots/rss/security.txt OK, 🔴 bug 404→home redirect (01.17.1) |
| 2026-04-23 | 01 | Blog + form rendering + capacity | blog OK (post IT mischiato), contact/demo/contact-sales/feedback rendering OK, capacity `{"active":2,"capacity":30,"status":"open"}` |
| 2026-04-23 | 01 | **FASE 01 chiusa** | 3 bug (2 High, 1 Med), 1 warning, 3 info, 18 OK — pronto per fase 02 |

---

## Bug counter globale

- 🔴 Bug: 3
- 🟡 Warning: 1
- 🔵 Info/UX: 3
- 🟢 OK passati: 18

*(aggiornati a mano ad ogni commit)*
