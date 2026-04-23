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

## Deployment scope labels (sempre obbligatorio su ogni bug)

Ogni bug deve dichiarare esplicitamente **dove vive** per evitare che un fix su un side comprometta l'altro. Usare uno o più di questi label:

| Label | Significato | Repo / Path |
|---|---|---|
| 🏢 **on-prem only** | Bug si manifesta solo su installazione on-prem Docker self-hosted. `SENTRIKAT_MODE=onpremise` | `sbr0nch/SentriKat` (`app/`) |
| ☁️ **SaaS only** | Bug si manifesta solo su `app.sentrikat.com`. `SENTRIKAT_MODE=saas` | `sbr0nch/SentriKat` (`app/`) |
| 🏢☁️ **both (shared core)** | Bug in codice condiviso, manifesto in entrambi i mode. **Fix richiede test su both** | `sbr0nch/SentriKat` (`app/`) |
| 🌐 **landing** | Bug sul sito marketing `sentrikat.com` (Astro static) | `sbr0nch/SentriKat-web` (`landing/`) |
| 🏛 **portal** | Bug sul portal clienti/admin `portal.sentrikat.com` (Astro + API calls) | `sbr0nch/SentriKat-web` (`portal/`) |
| 🔐 **license-server** | Bug sull'API FastAPI `api.sentrikat.com` / provisioning | `sbr0nch/SentriKat-web` (`license-server/`) |
| 📚 **docs** | Bug sulla documentazione `docs.sentrikat.com` (MkDocs) | `sbr0nch/SentriKat-web` (`docs/`) |
| 🚀 **release** | Bug nel release process (GitHub Actions, VERSION file, Docker image build) | `sbr0nch/SentriKat` (`.github/`) + `packaging/` |
| 📦 **agent** | Bug specifico dello script agent (PowerShell/bash) | `sbr0nch/SentriKat` (`agents/`) |
| 🔄 **cross-repo** | Bug che tocca più repo/scope insieme | — |

**Regola d'oro**: se un bug è `🏢☁️ both`, il fix DEVE essere testato nei 2 mode separatamente PRIMA del merge. Un fix cieco può compromettere l'altro.

---

## Formato bug (da usare in ogni file fase)

Ogni bug/osservazione va aggiunta con questo schema:

```markdown
### [01.3.2] Titolo breve del bug

- **Fase**: 01 — Landing site
- **Area**: Form Trial Signup
- **Deployment scope**: 🌐 landing          ← NUOVO OBBLIGATORIO
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
- **Impact on other scope**: ... (es. "Nessun impatto su SaaS; solo landing" / "Fix su core condiviso — testare entrambi i mode")
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

- 🔴 Bug: 22
- 🟡 Warning: 10
- 🔵 Info/UX: 55
- 🟢 OK passati: 76
- ⏸️ Test bloccati: 6

*(aggiornati a mano ad ogni commit)*

---

## Backlog "Test bloccati da fix propedeutici" ⏸️

Test che non sono eseguibili finché non viene risolto un bug a monte. Da riprendere dopo la fase di fix.

| Test ID | Fase/Area | Sommario | Bloccato da |
|---|---|---|---|
| ⏸️ 03.11.2.9 | 03 / LDAP login | Login di un utente LDAP seedato non può essere testato significativamente finché non c'è la pagina admin per "accettare/invitare" l'utente LDAP prima del login | [03.11.2.3] Sidebar LDAP Users / LDAP Groups sparita |
| ⏸️ 03.11.4 (all) | 03 / Jira integration | Test funzionali Jira non eseguibili con testlab docker in `FLASK_ENV=production` (policy SSRF hardening ignora `ALLOW_PRIVATE_URLS`) | [03.11.4.5] + hardening policy in production mode |
| ⏸️ 03.11.5 (all) | 03 / Webhook | Test funzionali Webhook out bloccati dalla stessa policy SSRF | [03.11.5.2] stesso root cause di 03.11.4.5 |
| ⏸️ 03.11.6.4 | 03 / GitLab | Test funzionali GitLab bloccati dalla stessa policy SSRF | stesso root cause di 03.11.4.5 |
| ⏸️ 03.11.6.8 | 03 / YouTrack | Saltato in questa sessione (pattern atteso uguale), test rinviato a post-fix | stesso root cause presunto |
| ⏸️ 03.12.6–15 | 03 / Agent inventory | Agent install OK ma initial scan 403/401 con messaggio fuorviante "Invalid API key". Key attiva nel DB (`active=t`, usage_count=3). Root cause vero nascosto da messaggio generico | [03.12.14] + possibilmente license-server-upstream validation in DEMO |

**Regola operativa**: quando un test fallisce ma è chiaro che dipende da un altro bug non ancora fixato, lo spostiamo qui invece di marcarlo come "bug autonomo" (evita falsi positivi sul conteggio bug). Riapriremo questi test in una seconda passata dopo la fase fix, in ordine di dipendenza (prima i fix bloccanti, poi i test sbloccati).

---

## Follow-up TODO list (da testare esplicitamente in un secondo giro)

Raccolta delle cose che **vanno provate** ma che non abbiamo testato funzionalmente durante il primo giro (o perché bloccate, o perché è bastato il rendering per il primo pass). Lista ordinata per fase/area.

### Fase 01 — Landing
- 01.3.2 Security headers via DevTools Network → verificare HSTS, X-Frame-Options, CSP, Referrer-Policy
- 01.4.2 Conferma `href` esatti link navbar
- 01.12.x Blog: tutti i 14 post aperti, code blocks, tabelle, OG image share, canonical link
- 01.13 vs/* — verificare contenuto unico (no duplicate content SEO)
- 01.14 Legal — `terms_version` coerente `/terms` vs `/ea-terms`, link mutuali, last-updated, `/impressum` escluso da sitemap
- 01.15 Form Contact/Demo/Contact-Sales/Feedback — submit reale con validazione campi, Turnstile failure, 422 validation, rate limit
- 01.16.1a Contenuto `sitemap-0.xml` (esclusione `/impressum`, presenza di tutti URL)
- 01.16.3 `rss.xml` — tutti 14 post presenti, `pubDate`, `description`, `category`

### Fase 02 — SaaS Signup
- 02.4.5-4.8 SPF/DKIM/DMARC, reply-to, tracking, List-Unsubscribe welcome email
- 02.6.3 Password policy: `password`, `12345678`, `aaaaaaaa` testati per breached-list check
- 02.8.2 True duplicate email (stesso email già registrato senza alias) → 409 + UI message chiaro
- 02.9 Edge 503 `EA_CAPACITY_FULL` (serve admin capacity = `active`)
- 02.10 Edge 422 validation server-side (fetch/curl malformed payload)
- 02.11 Provisioning bridge cross-ref via `/admin/webhook-outbox` + `/admin/saas-tenants` (fase 05)
- 02.13 Terms tracking (`terms_accepted_at`, `terms_version`) verifica in `/admin/customers/<id>` (fase 05)
- 02.14.2 Pricing page: sconti multi-anno 10%/15%, listino agent packs, add-on Compliance Pack/Priority Support, toggle monthly/annual

### Fase 03 — On-Prem

#### Setup wizard
- 03.5.6a `misfire_grace_time` + `coalesce=True` su APScheduler jobs
- 03.7.5 Codice sorgente flag `setup_complete` dopo fix [03.6.3]

#### System Settings → Sync & Updates
- 03.14.x click **Sync CISA Now** manualmente + verifica Total Vulnerabilities cresce
- 03.14.x Enable Automatic Sync + verifica Next Scheduled si popola + dopo prossimo run verifica Last Sync
- 03.14.x click **Sync EPSS Scores Now** + verifica CVEs with EPSS cresce
- 03.14.x click **Sync CPE Dictionary Now** + verifica Total Entries ~50K
- 03.14.x click **Rebuild from Vulnerabilities** CPE + differenze vs Sync Now
- 03.14.x click **Send Email Alerts Now** + verifica arrivo in Mailpit
- 03.14.x click **Send Webhook Alerts Now** (una volta sbloccato SSRF)
- 03.14.x NVD API Key inserita → verifica rate limit cresce a 10K/day
- 03.14.x Sync Interval cambio (Daily → Weekly → Custom) + verifica next run

#### System Settings → General / Security / Data Retention (sub-tabs non ancora aperti)
- 03.14.x aprire tab **General** → mappare tutti i campi (timezone, language, org branding, logo, ecc.)
- 03.14.x aprire tab **Security** → password policy, session timeout, 2FA enforce, account lockout
- 03.14.x aprire tab **Data Retention** → retention policy vuln data/audit log/alerts/snapshots

#### Settings → Compliance
- 03.14.5a click JSON/CSV/PDF di **ogni** report type (7 totali) anche con dati vuoti — verificare download ok, nessun 403 feature-gated
- 03.14.5a Audit Log: test search + filter (date range, action, resource, user, IP) anche se empty
- 03.14.5a Export Audit Log (JSON/CSV) → verificare file generato
- 03.14.5a Report scheduling: create scheduled report (ogni frequenza) + verifica delivery email

#### Settings → Health Checks
- 03.14.6a click **Run Now** → verificare timestamp aggiornati
- 03.14.7a investigare **Worker Pool STOPPED** → cliccare dettaglio, correlare con [03.13.3] Background Worker Running
- 03.14.x Disabilitare singoli check via toggle + verifica che check sparisca
- 03.14.x Configurare Notification Email + Send alerts via webhooks → forzare fail (es. stoppare DB) + verificare email/webhook ricevuti

#### Settings → License
- 03.14.x click **Check** button → osserva request a `license.sentrikat.com` (Network tab) + risposta
- 03.14.11a Invitare un secondo user (Users & Access → Invite) → verifica "License limit exceeded" con messaggio chiaro
- 03.14.x Creare una seconda Organization → verifica "1/1 → limit" blocca
- 03.14.x Activate Online con code invalido → verifica errore UI
- 03.14.x Copy Installation ID button → verifica clipboard
- 03.14.x Upgrade flow end-to-end con license PRO (quando disponibile)

#### Settings → Appearance / Logs / Admin Guide (non ancora aperti)
- 03.14.x aprire tab **Appearance** → logo upload, theme picker, white-label options
- 03.14.x aprire tab **Logs** → verificare accesso file log (application, error, access, security, audit, sync, jobs)
- 03.14.x aprire tab **Admin Guide** → verificare contenuto documentazione

#### Fase 03.11 integrazioni — dims aperti
- 03.11.1 SMTP dim 2/3/4/5/6/7 — persistence post-restart, disable+rewire, role-based access, test con host invalido/port out-of-range, audit log evento, webhook forwarding dei fallimenti
- 03.11.2 LDAP dims 4/5/6/7 + [03.11.2.9] dopo fix 03.11.2.3 (admin accept page)
- 03.11.3 SAML dims 6/7 — assertion replay, expired, invalid signature, audit log, webhook outbound per login
- 03.11.4-6 Jira/Webhook/GitLab/YouTrack dopo fix SSRF policy: CRUD config, test connection, create issue reale, status sync, priority mapping
- 03.11.6.8 YouTrack esplicito test (SSRF uniformity confirm)
- 03.11.7 Syslog dims 2/3/5/6/7 — persistence, CRUD destination, host invalido/port out-of-range, format CEF vs JSON vs RFC5424, eventi reali (login, CVE match, remediation)
- 03.12 Agent dopo fix license gate [03.13.2] — full test inventory, matching, asset CRUD, disable, ban, force scan, scheduler 240min actually fires

#### Sezioni non ancora toccate
- `/admin-panel` admin tabbed UI con 25 pagine (fase 05 sidebar portal admin + cross-ref fase 03 admin locale)
- `Platform Operations → Cross-Repo Integration` + Webhook Events + Usage Uploads (che abbiamo visto essere bug in [03.6.6]/[03.7.x])
- `Organizations` page (crea/modifica/elimina org, con e senza limite 1/1 Community)
- `Assignments` page vuota — CRUD remediation assignments
- `/assignments` test con dati reali quando inventory popolato
- `/reports/scheduled` page
- `/exports/sbom` SBOM export UI
- `/shared/<token>` shareable views
- Dashboard filtri (All/Servers/Clients/Containers/Dependencies) + widget interattività (Take Snapshot, Set up SLA)

### Fase 04 — Portal Customer
- Tutto da testare: login OTP, dashboard, licenze, downloads, support, checkout, upgrade, logout

### Fase 05 — Portal Admin
- Tutto da testare: 25 pagine admin

### Fase 06+
- Fase 06 App core auth/RBAC/2FA
- Fase 07 Agent+inventory (blocked da [03.13.2] license gate)
- Fase 08 Scanning/matching (blocked dal fatto di non avere ancora inventory data)
- Fase 09 Remediation/SLA
- Fase 10 Compliance/SBOM (UI testata, download da verificare)
- Fase 11 Integrations (3 bloccate da SSRF)
- Fase 12 Alerts/Notifications
- Fase 13 Admin ops / backup-restore / scheduler
- Fase 14 SaaS-specific
- Fase 15 Security/edge
- Fase 16 Extras (community, docs, n8n, nginx)

**Razionale**: questa lista sostiene l'istruzione utente `"ogni cosa deve essere testata e funzionante, facciamo tutto piano piano"`. Non è ancora eseguita, serve da memoria per il secondo giro e per il code reading finale post-fix.

---

## Scope map — retroactive (tutti i bug/osservazioni registrati finora)

Tabella che classifica i bug per **deployment scope** così quando si fixa sappiamo dove intervenire e cosa non compromettere. Le etichette usano i label di `Deployment scope labels` sopra.

| ID | Tipo | Scope | Sommario breve |
|---|---|---|---|
| 01.2.1 | 🔴 | 🌐 landing | CSP `style-src` blocca Google Fonts |
| 01.8.1 | 🔴 | 🌐 landing | Cookie banner non renderizzato al first load |
| 01.9.1 | 🟡 | 🌐 landing + 📚 docs | Post IT in sito EN-only senza switcher i18n |
| 01.12.3 | 🔵 | 🌐 landing | Blog index manca badge lingua sul post IT |
| 01.16.1 | 🔵 | 🌐 landing | Sitemap-0 contenuto da verificare |
| 01.16.4 | 🔵 | 🌐 landing | `security.txt` dichiara IT+DE su sito EN |
| 01.17.1 | 🔴 | 🌐 landing + nginx | 404 redireziona a / con 200 invece di servire 404.html |
| 02.2.1 | 🔴 | 🌐 landing | Validation checkbox terms in DE (browser locale native) |
| 02.3.2 | 🔵 | 🔐 license-server | Alias Gmail `+tag` bloccati con 409 (feature voluta, UX review) |
| 02.4.1 | 🔴 | ☁️ SaaS + 🔐 license-server | Temp password in plaintext nel welcome email |
| 02.4.2 | 🟡 | ☁️ SaaS + 🔐 license-server | Email template usa `$` USD invece di `€` EUR |
| 02.4.5–4.8 | 🔵 | 🔐 license-server | Email SPF/DKIM/DMARC, reply-to, tracking, List-Unsubscribe da verificare |
| 02.6.3 | 🔵 | ☁️ SaaS (core app) | Password policy complexity oltre min-length da verificare |
| 02.6.4 | 🔵 | 🏢☁️ both | Copy "admin asked to renew" su SaaS first-login |
| 02.7.2 | 🔵 | ☁️ SaaS | Badge company uppercase CSS |
| 02.7.3 | 🔵 | ☁️ SaaS | Feature gating Starter: sidebar include SBOM ma Features Included no |
| 02.7.4 | 🔵 | ☁️ SaaS | No onboarding wizard/tour al primo login |
| 02.7.6 | 🟡 | ☁️ SaaS | Billing "Monthly / Renews" su Early Access gratuito |
| 02.7.7 | 🔵 | 🏢☁️ both | Subtitle "LDAP config" hardcoded anche dove LDAP non attivo |
| 02.7.8 | 🔵 | 🏢☁️ both | Breadcrumb "Home / Administration" inconsistente |
| 02.7.9 | 🔵 | ☁️ SaaS | Manca label "Early Access" su Current Plan card |
| 02.7.10 | 🔵 | 🏢☁️ both | Manca usage/quota attuale (x/max con %) |
| 02.7.11 | 🔵 | 🏢☁️ both | SBOM Export mismatch sidebar vs Features Included |
| 03.5.3 | 🔴 | 🚀 release + 🏢☁️ both | VERSION file inchiodato a beta.2 su tag beta.6 (health/header/footer tutti dicono beta.2) |
| 03.5.4 | 🟡 | 🏢☁️ both | Flask-Limiter usa in-memory storage (no Redis) |
| 03.5.5 | 🟡 | 🏢☁️ both | `send_usage_to_license_server` logga ERROR invece di WARN/INFO |
| 03.6.3 | 🔴 | 🏢 on-prem only | Setup wizard auto-lock dopo step 3 (step 4-6 irraggiungibili) |
| 03.6.5 | 🔵 | 🏢 on-prem | Label "Create →" su step intermedi wizard |
| 03.6.6 | 🔴 | 🏢 on-prem only | Sidebar "Platform Operations" section esposta anche in on-prem |
| 03.6.7 | 🔵 | 🏢☁️ both | Console debug `[SentriKat]` visibile in production mode |
| 03.6.8 | 🔵 | 🏢 on-prem | `/setup` non redirige a /login dopo completamento |
| 03.7.2 | 🔴 | 🏢 on-prem only | Webhook Events page: copy SaaS-only renderizzata in on-prem |
| 03.7.3 | 🔴 | 🏢 on-prem only | Typo `/ap1/license/events` invece di `/api/` |
| 03.7.4 | 🔴 | 🏢 on-prem only | Usage Uploads page dice "this SaaS" + espone comando Python in UI |
| 03.7.5 | 🔵 | 🏢 on-prem | `system_settings` non ha chiavi `%setup%` (flag altrove) |
| 03.7.7 | 🔵 | 🏢 on-prem | Voci Platform Operations funzionanti (non solo cosmetiche) |
| 03.11.1.3 | 🔵 | 🏢☁️ both | Cross-ref [02.7.7] anche su on-prem |
| 03.11.1.4 | 🔵 | 🏢☁️ both | Inconsistency "Email (SMTP)" sidebar vs tab "Email & Alerts" |
| 03.11.1.5 | 🟡 | 🏢☁️ both | Password SMTP mostra `••••••••` senza password salvata |
| 03.11.1.9 | 🔵 | 🏢☁️ both | Nessun throttle su Send Test Email |
| 03.11.1.10 | 🔵 | 🏢☁️ both | Test email espone host+port SMTP in plaintext |
| 03.11.2.2 | 🔴 | 🏢☁️ both | Form LDAP manca Group Mapping fields |
| 03.11.2.3 | 🔴 | 🏢☁️ both | Sidebar Users&Access manca voci LDAP Users/Groups (regressione refactor mode-gating) |
| 03.11.2.4 | 🟡 | 🏢☁️ both | LDAP Test Connection richiede Save prima |
| 03.11.2.5 | 🔵 | 🏢☁️ both | LDAP Server URL ambiguity URL+Port |
| 03.11.2.6 | 🔵 | 🏢☁️ both | Form LDAP manca Display Name Attr / Default Role / Auto-create toggle |
| 03.11.2.7 | 🔵 | 🏢☁️ both | Banner "LDAP Setup" implica auto-create senza controllo esplicito |
| 03.11.2.8 | 🔵 | 🏢☁️ both | `ldap.log` non su stdout container |
| 03.11.2.10 | 🟡 | 🏢☁️ both | Sezione LDAP nascosta dopo save, workaround refresh+tab |
| 03.11.3.2 | 🔴 | 🏢 on-prem (scenario docker) | SAML docker network trap: single URL field per metadata |
| 03.11.3.3 | 🔵 | test setup | Keycloak testlab client usa `RSA_SHA1` (deprecato) |
| 03.11.3.5 | 🔵 | test setup | Realm signing key `RS256` documentata |
| 03.11.3.12 | 🔵 | 🏢☁️ both | `manager == org_admin` sidebar identica; org_admin non vede MANAGEMENT/SYSTEM |
| 03.11.3.15 | 🔵 | 🏢☁️ both | Popup delete user con stile testo grezzo (probabile `window.confirm()`) |
| 03.11.4.5 | 🔴 | 🏢☁️ both | SSRF `ALLOW_PRIVATE_URLS` ignorato in prod; dev mode richiesto per test locale |
| 03.11.5.3 | 🔴 | 🏢☁️ both | Test Connection webhook → 500 invece di 400 strutturato |
| 03.11.5.4 | 🟡 | 🏢☁️ both | Log CRITI SSRF spam (1 per request invece di 1 al boot) |
| 03.11.6.1 | 🔵 | 🏢☁️ both | GitHub Issues form manca Base URL (no Enterprise Server support) |
| 03.11.6.3 | 🔵 | 🏢☁️ both | Error handling inconsistente tra `/test` endpoint dei tracker (GitHub clear, webhook 500) |
| 03.11.6.5 | 🔵 | 🏢☁️ both | GitLab: UI mostra 2 messaggi di errore contraddittori simultaneamente |
| 03.11.6.7 | 🔵 | 🏢☁️ both | Log SSRF label hardcoded "Jira tracker setup" anche per GitLab |
| 03.11.7.4 | 🔵 | 🏢☁️ both | Syslog: singolo Send Test produce "un sacco di contenuto" (flood o multi-line?) |
| 03.12.3 | 🔵 | 🏢 on-prem (UI) | Date picker "Expires" placeholder in DE (i18n browser native) |
| 03.12.6 | 🔴 | 📦 agent + 🏢☁️ both | "Initial scan failed" silent fail senza dettaglio (root cause poi: 03.13.2) |
| 03.12.7 | 🔴 | 📦 agent | No local `agent.log` per debug post-failure |
| 03.12.10 | 🔵 | 📦 agent | Scheduled task punta a path user Downloads invece di %PROGRAMDATA% |
| 03.12.13 | 🔴 | 🏢☁️ both | 403 agent non loggato in stdout sentrikat (solo nginx access log) |
| 03.12.14 | 🔴 | 🏢☁️ both CRITICAL | Response `"Invalid or missing API key"` FUORVIANTE (real reason: license gate) |
| 03.12.15 | 🔴 | meta | Diagnostic dead-end senza code reading — risolto poi con [03.13.2] |
| 03.13.2 | 🎯 | 🏢 on-prem (Community tier) | Root cause agent: Push Agents require Professional — Community non include |
| 03.13.3 | 🔵 | 🏢☁️ both | Terminology mismatch: "Worker Pool" (health) vs "Background Worker" (agent activity) |
| 03.14.2 | 🟡 | 🏢 on-prem | Auto-sync CISA KEV OFF default (DEMO no telemetria) |
| 03.14.3 | 🔵 | 🏢☁️ both | Metric discrepancy `Total Vulnerabilities 639` vs `KEV Catalog 13,978` |
| 03.14.4 | 🔵 | 🏢☁️ both | Audit Logs filtri date in `tt.mm.jjjj` (DE) |
| 03.14.7 | 🟡 | 🏢☁️ both | Health Check "Worker Pool STOPPED" vs Agent Activity "Running" contraddizione |
| 03.14.9 | 🔴 | 🏢☁️ both + 🚀 release | License page dice "Up to date beta.2" mentre beta.6 disponibile (update-check rotto) |
| 03.14.10 | 🔵 | 📚 docs + 🏢 on-prem | Terminology mismatch "DEMO" (handbook) vs "COMMUNITY" (UI) |
| 03.14.10.expand | 🔴 | 🔄 cross-repo | Edition tier mismatch HIGH: docs, UI, marketing, email tutti dicono cose diverse |
| 03.14.11 | 🟡 | 🏢 on-prem (Community) | Community limits 1/1 user + 1/1 org al max out-of-the-box |
| 03.14.12 | 🔵 | 🏢☁️ both | "Weighted Units: 0.0" metric non documentato |

**Note importanti sul fix planning**:
- Bug marcati `🏢☁️ both` vanno testati in **entrambi i mode** dopo fix. Non basta verificare che funzioni on-prem — potrebbe rompere SaaS (o viceversa)
- Bug `🌐 landing` sono isolati in repo separato (`SentriKat-web/landing`) — fix non impatta prodotto core
- Bug `🚀 release` sono nel workflow CI — fix in `.github/workflows/release.yml` può impattare tutti i tag futuri
- Bug `🔐 license-server` vivono in `SentriKat-web/license-server` (FastAPI), separato dal Flask core — fix isolato
- Bug `📦 agent` vivono nel client-side PowerShell/bash — fix impatta customer host ma non server

---
