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
| 02 | `02-signup-saas.md` | Signup SaaS: form Early Access, capacity check, `/api/v1/provision/trial`, Stripe checkout, webhook, bridge provisioning → `app.sentrikat.com` | ✅ 90% (2 bug, 2 warn, 13 info, 13 OK; 4 sotto-aree rimandate a fase 05 admin) |
| 03 | `03-signup-onprem.md` | Signup on-prem: lead/contact sales, acquisto license, download binario, install Docker, setup wizard, attivazione RSA, hardware lock | 🟡 in corso (install OK, wizard step 1 OK, 1 bug HIGH version, 2 warn log level/rate-limiter) |
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

## Testing depth standard — matrice per ogni feature

Dal 2026-04-23 l'utente ha alzato il livello: ogni feature deve essere **coperta in tutte le direzioni**, non solo happy path. Per ogni feature/area d'ora in poi usiamo questa checklist di 7 dimensioni:

| # | Dimensione | Cosa testare |
|---|---|---|
| 1 | **Happy path** | Config corretta, azione riuscita con UI feedback positivo |
| 2 | **Persistence** | La config/entità sopravvive a refresh, restart container, re-login |
| 3 | **CRUD completo** | Create, Read (list + detail), Update, Delete. Ogni operazione deve essere testata + verificato che il resto del sistema reagisca |
| 4 | **Role-based access** | Stessa azione tentata da ogni ruolo (super_admin, org_admin, manager, user, LDAP-mapped, SAML-mapped). Chi può cosa? Verifica 403 dove atteso |
| 5 | **State transitions** | Accept, Ban, Disable, Force password change, Enable, Re-enable, Delete, Restore. Ogni transizione deve essere testata + verificato l'impatto (es. utente bannato non deve più poter loggare) |
| 6 | **Negative / edge** | Input invalidi, null, stringhe troppo lunghe, SQL injection-like, XSS, race condition (2 admin che modificano lo stesso oggetto), payload oltre limite quota, utente inesistente, password sbagliata |
| 7 | **Integration / cross-feature** | Come la feature impatta le altre? Es: LDAP user creato → compare in "All Users"? Email digest lo include? Audit log traccia? Webhook outbound lo segnala? |

Esempio concreto per LDAP (riferimento per 03.11.2):

```
LDAP dimension matrix:
1. Happy path       : admin.user login LDAP → dashboard
2. Persistence      : config sopravvive restart; sync scheduler runs
3. CRUD             : admin invita LDAP user bulk, rimuove, modifica role post-invite
4. Role-based       : super_admin/org_admin/manager/viewer login LDAP → UI/menu corretti per ruolo
5. State transitions: disable.user → login rifiutato; admin ban admin.user → login rifiutato; admin revoca session attiva → utente forzato a re-login
6. Negative         : utente inesistente LDAP, password sbagliata, LDAP server down, bind user con password errata, filter LDAP malformato, utente con uid contenente caratteri speciali
7. Integration      : login LDAP → audit log evento "user.login.ldap"; disable user → webhook outbound; LDAP sync → SystemNotification "N users synced"; email digest include nuovi LDAP users
```

Stessa matrice applicata a **ogni area** in tutte le fasi: SMTP, SAML, Jira, Webhook, Syslog, Agents, Products, Vulnerabilities, Remediation, Compliance Reports, Alerts, Backup/Restore, Billing, ecc.

**ID schema esteso** per distinguere dimensioni:
`<fase>.<area>.<dim>.<num>` → esempio `03.11.2.5.2` = fase 03, area 11.2 (LDAP), dimensione 5 (State transitions), test #2 (es. admin ban del bug trovato)

Quando il volume di test diventa grosso, ogni area avrà il suo sub-file (`03.11.2-ldap.md`) invece di gonfiare il file fase.

---

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
| 2026-04-23 | 02 | Happy path trial SaaS (submit+email) | 🔴 02.4.1 temp password in plaintext via email (Med-High); 🔴 02.2.1 validation in DE; 🟡 02.4.2 valuta $ vs €; 🟡 02.4.3 email layout; 🟢 form rendering + 201 + deployment switcher + terms-block OK |
| 2026-04-23 | 02 | Login + force password change + dashboard | 02.4.3 declassificato ❌ falso positivo; 🟢 login+forced-change+password-policy(min8)+mismatch OK; 🔵 02.6.3 complexity da verificare, 02.6.4 copy admin-renew su SaaS, 02.7.2 badge uppercase, 02.7.3 feature gating Starter, 02.7.4 no onboarding wizard; dashboard empty-state OK, Stripe NOT proposed ✅ |
| 2026-04-23 | 02 | 409 true duplicate + pricing + Subscription | 🟢 409 on same email + UI chiara; 🟢 /pricing OK; 🟡 02.7.6 "Billing Monthly / Renews 23 May" su EA gratuito; 🔵 4 info su Subscription (subtitle LDAP hardcoded, breadcrumb Administration, no EA badge, no usage quota, SBOM Export mismatch sidebar vs feature list) — **FASE 02 chiusa al 90%** |
| 2026-04-23 | 03 | Install beta.6 on Windows + first-boot | 🟢 build OK (~2min), 3 container healthy; 🔴 03.5.3 VERSION file inchiodato a beta.2 nel tag beta.6 (health+header dicono versione sbagliata); 🟡 03.5.4 Flask-Limiter in-memory storage (no Redis); 🟡 03.5.5 ERROR log per metrics key assente (dovrebbe essere WARN/INFO); 🔵 03.5.6 APScheduler missed jobs in catch-up; 🟢 wizard /setup visibile 6-step; 🔵 03.6.2 Multi-Tenancy listata in welcome anche su DEMO |
| 2026-04-23 | 03 | Setup wizard walk + first login | 🔴 **03.6.3 HIGH** wizard auto-locka dopo step 3, `POST /api/setup/seed-services` → 403 "Setup already completed", step 5-6 mai visibili; 🔴 03.6.6 sezione "Platform Operations" (SaaS) visibile in sidebar on-prem; 🔵 03.6.5 label "Create →" su step intermedi (ambiguo), 03.6.7 debug log JS in production, 03.6.8 nessun 302 su /setup post-lock; 🟢 password validation client-side, org+admin+login OK; 🔁 VERSION bug [03.5.3] CONFERMATO su 3 canali (VERSION file, /api/health, footer UI) + JS core hardcoded "v1.0.0" |
| 2026-04-23 | 03 | Sidebar map + Platform Operations probing | 🟢 mappa sidebar on-prem documentata (confronto vs SaaS Starter); 🔴 03.7.2 pagina Webhook Events mostra copy "upstream SentriKat-web license server" con concetti SaaS-only (plan change/revocation); 🔴 03.7.3 typo `/ap1/license/events` (dovrebbe essere `/api/`); 🔴 03.7.4 pagina Usage Uploads dice "this SaaS" + espone comando Python in UI customer-facing (privacy/trust issue per on-prem); 🔵 03.7.5 `system_settings` senza chiavi setup (flag altrove); 🟢 03.7.6 empty-state banner actionable ("Run CISA sync", "Add Products"); 🔵 03.7.7 nessun errore console → rafforza severity 03.6.6 (non cosmetic, funzionale) |
| 2026-04-23 | 03 | SMTP → Mailpit configurata da UI | 🟢 save + test UI feedback verde, config persistente; ⏳ consegna email in Mailpit (http://localhost:8025) pending verifica utente; 🟡 03.11.1.5 password field mostra `••••••••` senza password reale (misleading); 🔵 03.11.1.3 subtitle hardcoded "LDAP configuration..." cross-ref [02.7.7]; 🔵 03.11.1.4 label inconsistency sidebar "Email (SMTP)" vs tab "Email & Alerts"; 🔵 03.11.1.6 nessun campo Reply-To nel form; 🔵 03.11.1.7 copy multi-tenant "Default SMTP for all orgs" esposto anche in DEMO single-org; 🔵 03.11.1.8 helper text port non include dev port 1025 |
| 2026-04-23 | 03 | SMTP delivery verificata in Mailpit | 🟢 2 email arrivate in Mailpit (http://localhost:8025) con From=noreply@sentrikat.local, To=admin, Subject "SentriKat SMTP Test - Configuration Successful" — pipeline SMTP client→testlab funziona, nessuna delivery a Internet; 🔵 03.11.1.9 nessun throttling sui test email; 🔵 03.11.1.10 body test email espone host+port SMTP in plaintext (info disclosure minore) |

---

## Bug counter globale

- 🔴 Bug: 12
- 🟡 Warning: 7
- 🔵 Info/UX: 36
- 🟢 OK passati: 54
- ⏸️ Test bloccati: 1

*(aggiornati a mano ad ogni commit)*

---

## Backlog "Test bloccati da fix propedeutici" ⏸️

Test che non sono eseguibili finché non viene risolto un bug a monte. Da riprendere dopo la fase di fix.

| Test ID | Fase/Area | Sommario | Bloccato da |
|---|---|---|---|
| ⏸️ 03.11.2.9 | 03 / LDAP login | Login di un utente LDAP seedato non può essere testato significativamente finché non c'è la pagina admin per "accettare/invitare" l'utente LDAP prima del login | [03.11.2.3] Sidebar LDAP Users / LDAP Groups sparita |

**Regola operativa**: quando un test fallisce ma è chiaro che dipende da un altro bug non ancora fixato, lo spostiamo qui invece di marcarlo come "bug autonomo" (evita falsi positivi sul conteggio bug). Riapriremo questi test in una seconda passata dopo la fase fix, in ordine di dipendenza (prima i fix bloccanti, poi i test sbloccati).
