# SentriKat E2E Test & Bug List — Master Index

> **Obiettivo:** mappare TUTTO SentriKat (SaaS + on-prem + portal + landing + prodotto core) con test end-to-end e raccogliere una bug list esaustiva. **Non risolviamo qui.** Solo testare e annotare.
>
> **Metodo collaborativo:** Claude dà un prompt puntuale per una sezione alla volta → utente esegue nel browser/terminale → riporta output/screenshot/errori → Claude aggiunge bug nel file della fase corrispondente → si passa al prossimo prompt.

---

## 🔴 HANDOFF — leggi PRIMA di continuare (session continuity)

Se sei un nuovo Claude che apre questa sessione o se ci ritorniamo dopo una pausa, questa è la sintesi operativa.

### 🛑 LAST SESSION STOP — 2026-04-24

L'utente ha detto `"per oggi mi fermo qui, ricordami domani dove eravamo e cosa dobbiamo fare"` subito dopo aver aperto `https://portal.sentrikat.com` e scoperto che l'**OTP non arriva via email**. La fase 04 è stata aperta ma **bloccata al primo test**.

### 🟢 SESSION RESUMED — 2026-04-25 (laptop remoto, no docker + no testlab)

L'utente è tornato su un **laptop diverso** (viaggio). **Non ha l'on-prem Docker né il testlab** di ieri. Possiamo continuare solo su **superfici web prod** (sentrikat.com, portal, app.sentrikat.com, docs, community) + 7-dim su fasi 01/02/03 già fatte ma incomplete.

### 🛑 SESSION END — 2026-04-25 (fine giornata sul laptop remoto)

**Sessione chiusa a commit `6e5689a`**. Tutto il testabile oggi in browser-only è stato coperto.

**Next session bootstrap — qualsiasi nuovo Claude legga questo file deve**:
1. Leggere SUBITO la sezione HANDOFF (questa + quelle sopra) prima di qualsiasi azione
2. Leggere il resto del master 00-INDEX.md per capire strategia complete (7-dim matrix, deployment scope labels, strategies A-G time-based)
3. Scansionare la tabella fasi (sotto) + scope map retroactive per capire state actual
4. Annunciare all'utente: (a) in quale fase siamo (b) counter bug (c) proposta di cosa fare

**Aree rimaste da testare** (priorità decrescente):

| Categoria | Test | Prereq |
|---|---|---|
| 🏢 **On-prem locale** (laptop principale) | Trigger manuali sync (CISA/EPSS/CPE — Strategia A), agent scan se license Pro OR Strategia F seed DB, compliance reports download con dati, backup/restore, all log viewer content, sub-tabs non ancora esplorati profondamente | Docker + testlab running |
| 🔄 **Testlab integrations reali** | LDAP login E2E, SAML login via Keycloak, Jira/Webhook/GitLab con `FLASK_ENV=development` per bypass SSRF, Mailpit as SMTP, Syslog events reali | Docker + testlab |
| 🔓 **Blocked backlog** (8 entries) | Ogni blocked dopo il rispettivo fix upstream | Fix prima |
| 🏛 **Fase 05 Portal Admin** | Accesso `ADMIN_API_KEY` del license-server | Credenziale |
| 🌐 **Tech debt 7-dim** Fase 01/02 | Cookie banner persistence, Turnstile failure, audit log integration, 2FA setup E2E, ecc. | Browser-only (qualsiasi laptop) |
| 📚 **Docs content audit** | Page-by-page terminology/link/screenshot/tutorial consistency | Browser-only |
| 🚀 **CI/CD pipeline** (16.5) | GitHub Actions workflow review, release process | GitHub admin access |

**Counter finale sessione 2026-04-25**: 29 bug (1 CRITICAL, 10 High) / 13 warnings / 65 info / 100 OKs / 8 blocked. 39+ commits ahead di main su branch `claude/add-sentikat-e2e-tests-Cyd6M` (user farà PR quando vuole).

**Regola user**: *"i test devono essere come sempre completi, ogni funzione. se stiamo controllando una pagina allora controlliamo tutto di quella pagina."* → applicare 7-dim a ogni pagina di oggi in poi.

**Agenda sessione 2026-04-25** (decisa da claude, utente ha detto "basta che teniamo traccia di tutto"):
1. **Retry OTP portal + spam check** (30s — chiudere o confermare bug `[04.1.3]`)
2. **Fase 06 App SaaS auth/RBAC matrix completo** (`app.sentrikat.com`, credenziali già pronte da fase 02) — dim 4 role-based, dim 5 state transitions, dim 6 negative, dim 7 integration
3. Se OTP funziona: **Fase 04 Portal Customer intero** (Dashboard, Account, Licenses, Downloads, Support, Checkout)
4. Se OTP rotto: **Fase 05 Portal Admin** se l'utente ha bearer `ADMIN_API_KEY` (skip se non disponibile)
5. **Debito tecnico Fase 01/02 7-dim** in background se c'è tempo
6. `docs.sentrikat.com` e `community.sentrikat.com` (componenti minori ma da mappare)

**Test rinviati** (richiedono docker/testlab del laptop precedente):
- Tutti i trigger on-prem Strategia A
- Tutte le integrazioni testlab (LDAP/SAML/Jira/Webhook/Syslog reali)
- Seed DB fake data (Strategia F)
- Agent install / scan (bloccato comunque dal license gate)
- Compliance reports download con dati reali
- Log viewer in-app / security.log content

Questi test restano nel follow-up TODO + blocked backlog, li ripiglieremo quando torna al laptop principale.

---

### Dov'eravamo (ultimo update: 2026-04-24, commit recenti `469d5f2` + successivi)

- **Fasi completate o in corso**:
  - ✅ Fase 01 Landing — 3 bug, 1 warn, 3 info, 18 OK ma **SOLO happy path + navigation**, NON 7-dim
  - ✅ Fase 02 Signup SaaS — 2 bug, 2 warn, 13 info, 13 OK, 90% chiusa, MA **senza framework 7-dim completo**
  - 🟡 Fase 03 On-prem — enorme scope, 50+ finding registrati, 6 aree ⏸️ bloccate. Pragmaticamente chiusa dove non bloccata
  - 🟡 Fase 04 Portal Customer — **BLOCCATA dal primo test**: bug `[04.1.3]` OTP email non arriva, login impossibile
- **Bug totali counter**: vedi "Bug counter globale" in fondo a questo file. Aggiornato a ogni commit
- **Branch**: `claude/add-sentikat-e2e-tests-Cyd6M` su `sbr0nch/SentriKat`. Docs in `docs/e2e-tests/`

### Framework consolidato (DA USARE da qui in avanti)

Durante il lavoro sono stati introdotti **tre framework** che prima NON erano in vigore:

1. **7-dim matrix** (vedi sezione "Testing depth standard" in questo file): ogni area va testata in 7 dimensioni (Happy / Persistence / CRUD / Role-based / State transitions / Negative / Integration)
2. **Deployment scope labels** (vedi "Deployment scope labels"): ogni bug dichiara `🏢 on-prem` / `☁️ SaaS` / `🏢☁️ both` / `🌐 landing` / `🏛 portal` / `🔐 license-server` / `📚 docs` / `🚀 release` / `📦 agent` / `🔄 cross-repo`
3. **Time-based strategies A-G** (vedi "Strategie per testare feature time-based"): ogni feature async/scheduled ha una strategia esplicita per il test

### ⚠️ Debito tecnico — cosa va ri-testato con framework completo

Le aree seguenti sono state testate **prima** dell'adozione completa del framework. Vanno ri-passate in un secondo giro:

| Area | Cosa manca | Priority |
|---|---|---|
| Fase 01 Landing (tutto) | 7-dim: dim 2 persistence (i.e. config cookie banner sopravvive ad hard refresh?), dim 5 state transition (cookie accept → reject → accept), dim 6 negative (CAPTCHA failure su form, rate limit submit form) | Medium |
| Fase 02 Signup SaaS | 7-dim: dim 5 (disable user dopo signup, cancel trial via admin), dim 6 (special char in email/company, unicode nella company, SQL injection test su fields), dim 7 (audit log evento `user.signup`, webhook outbound, SIEM forwarding su signup event) | Medium |
| Fase 03.11.1 SMTP | 7-dim: dim 2 persistence post-restart, dim 3 CRUD (disable+rewire), dim 5 (destination down → graceful fail), dim 6 (host invalido, port out-of-range, format invalido), dim 7 (eventi REALI come password reset, CVE alert, digest — non solo test event) | High (user-facing) |
| Fase 03.11.7 SIEM | 7-dim: stesso pattern SMTP — persistence, CRUD, state down, negative input, real event flow | Medium |
| Fase 03.11.3 SAML | dim 6 assertion replay, expired, invalid signature; dim 7 audit log + webhook outbound login | Medium |
| Fase 03.14 Settings tabs | mancano click reali su ogni bottone (Sync CISA Now, Sync EPSS Now, Sync CPE Now, Run Auto-Ack Now, Send Email Alerts Now, Send Webhook Alerts Now, ecc.) — vedi catalogo "Scheduler jobs" nella sezione strategy time-based | High (senza questi la feature non è validata) |

### Aree BLOCCATE (backlog — vedi sezione "Test bloccati da fix propedeutici")

Non ritentare senza prima avere un fix upstream:
- `[03.6.3]` setup wizard step 3 auto-lock → step 4-6 mai visibili
- `[03.11.2.3]` sidebar Users&Access manca voci LDAP (regressione refactor mode-gating)
- `[03.11.2.9]` login LDAP blocked by 03.11.2.3
- `[03.11.4.5]` SSRF policy in prod mode ignora `ALLOW_PRIVATE_URLS` (Jira + Webhook + GitLab locali untestable)
- `[03.11.5.2]` Webhook blocked, stesso root cause
- `[03.11.6.4]` GitLab blocked, stesso
- `[03.12.x + 03.13.2]` Agent Push feature-gated a Professional (Community)
- `[04.1.3]` OTP email non arriva su portal prod

### Prossimo step suggerito (continuità)

Strategia concordata: **"Mixed"** — non perdere tempo a sbloccare test, procedere su aree indipendenti.

Oggi siamo bloccati in fase 04 (portal customer) al primo test. Opzioni per ripartire:

1. **Fase 05 Portal Admin** (stessa base Astro ma auth admin bearer `ADMIN_API_KEY`, bypassa OTP customer) — probabilmente funziona
2. **Fase 06 App core auth/RBAC** (`app.sentrikat.com`): abbiamo già account admin locale + SAML user su on-prem — matrix RBAC completo con dim 4
3. **Fase 13 Admin ops on-prem** (backup/restore, scheduler trigger tutti, admin dashboards) con strategia A (Run Now buttons) → popola dati reali
4. **Second pass con seed DB** (Strategia F): insertion di fake product + vuln match → dashboard, remediation, compliance reports diventano testabili senza sbloccare agent

### Riferimenti PR recenti rilevanti (contesto)

- **SentriKat-web PR #225/226/227** (17-apr, branch `claude/fix-login-issue-wCfsw`): tre iterazioni per fix login portal → area fragile. Il bug [04.1.3] OTP NON-arrivo è probabile regressione di una di queste PR, oppure di qualche commit successivo
- **PR #231** (22-apr, `fix(license-server): wrap enqueue_webhook_event in try/except`): toccava license-server outbox; improbabile abbia rotto OTP ma **va considerato** perché license-server è il processo che invia OTP
- **Nessun commit esplicito su OTP/SMTP nel periodo** visibile via GitHub UI commits page — il fix "di ieri/altro ieri" di cui parla l'utente potrebbe essere un commit con titolo generico (es. `fix(portal)`, `fix(login-issue)`) che implicitamente toccava il flow email

### File layout docs/e2e-tests/

- `00-INDEX.md` ← master (questo file)
- `01-landing-site.md` ← fase 01 details
- `02-signup-saas.md` ← fase 02 details
- `03-signup-onprem.md` ← fase 03 details (più grande — 50+ find)
- `04-portal-customer.md` ← fase 04 appena scaffolded, blocked al primo test

Ogni bug ha ID `<fase>.<area>.<n>` (es. `03.11.2.3`). Extended form `<fase>.<area>.<dim>.<n>` quando applichiamo 7-dim matrix.

---

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
| 16 | `16-extra-shared.md` | Shared views pubblici, GDPR export/delete, community Flarum, docs MkDocs, n8n workflow, nginx reverse proxy, deploy pipeline (CI/CD + staging) | 🟡 parziale (16.1 docs + 16.2 community mapped; 16.3/16.4/16.5 richiedono admin access) |

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
| **2026-04-26** | — | **🔧 SESSION FIX — Batch 1 core** (laptop remoto, scope SentriKat only) | Creato `FIX-HANDOFF-sentrikat-web.md` per bug scoped al secondo repo. Applicati fix in SentriKat core:<br>✅ **[03.5.3]** VERSION file beta.2→beta.6 + guard CI release.yml (fail-fast se VERSION≠tag) — `VERSION`, `.github/workflows/release.yml`<br>❌ **[03.7.3]** FALSE POSITIVE — template ha già `/api/license/events` corretto al tag beta.6. Probabile mis-trascrizione `i`→`1` nel test. Bug chiuso senza fix codice<br>✅ **[03.6.6]** + **[03.7.2]** + **[03.7.4]** (1 fix consolidato) — sidebar Platform Operations gated con `saas_mode`, route `/super-admin/webhook-events` e `/super-admin/usage-uploads` restituiscono 404 in on-prem, rimosso comando Python debug dal template usage uploads — `app/templates/base.html`, `app/observability_api.py`, `app/templates/super_admin_usage_uploads.html`<br>✅ **[03.12.14]** agent error messages richer — `get_agent_api_key()` ora ritorna reason-code specifico (`missing_api_key`/`invalid_api_key`/`inactive_api_key`/`expired_api_key`/`ip_not_allowed`) invece del generico "Invalid or missing API key". `api_docs.py` OpenAPI spec aggiornata — `app/agent_api.py`, `app/api_docs.py`<br>✅ **[03.11.2.3]** sidebar LDAP Users/Groups regressione — aggiunto `is_platform_admin` al gating di `has_ldap` in modo che super_admin on-prem DEMO le veda (allineamento con Authentication settings) — `app/templates/base.html`<br>✅ **[03.11.4.5]** SSRF `ALLOW_PRIVATE_URLS` — CRITI spam log ridotto a 1 warning single-shot, UI error arricchito con hint su `FLASK_ENV=development`, docstring aggiornato — `app/network_security.py`<br>**Verifica differita**: laptop principale con docker → rebuild + rigiro test sulle aree fixate |
| **2026-04-26** | — | **✅ VERIFY ROUND 1** (rebuild SaaS + sito web prod, smoke tests browser+curl) | Verificati 9 fix su prod live:<br>✅ **[01.17.1]** `curl -I /path-non-esistente` → HTTP/2 404<br>✅ **[01.16.4]** security.txt `Preferred-Languages: en`<br>✅ **[03.5.3]** `/api/health` → `1.0.0-beta.6` (era beta.2)<br>✅ **[03.12.14]** POST `/api/agent/inventory` con bogus key → `{"error":"invalid_api_key","hint":"...","message":"..."}` (era generico)<br>✅ **[01.2.1]** sentrikat.com no CSP error console<br>✅ **[01.8.1]** cookie banner visibile in incognito<br>✅ **[02.2.1]** trial form terms validation in EN<br>✅ **[01.9.1]/[01.12.3]** badge IT su post blog italiano<br>✅ **[04.1.3]** OTP arriva in Gmail entro 30s, login portal completato (implicit verify via portal access)<br>**Pending**: `[02.4.1]/[02.4.2]` welcome email (rinviato — basta nuova email per re-test). **Verifiche on-prem differite** (LDAP sidebar, Platform Ops gating, SSRF UI hint, Wizard step 5-6) → richiedono rebuild su laptop principale |
| **2026-04-26** | 04 | **🆕 NEW BUG `[04.2.1]` CSP portal regression** scoperto durante verify round 1 | Sintomo: `https://portal.sentrikat.com` stuck su "Verifying authentication..." con 3 CSP errors console (script-src 'self' nonce-... bloccava inline `<script type="module">` da `cdn.jsdelivr.net` e da pages stesse).<br>**Root cause**: Astro/Vite inlinea script `<4KB` direttamente in HTML senza propagare il `__CSP_NONCE__` placeholder. Solo gli script con `is:inline nonce="__CSP_NONCE__"` esplicito beneficiavano del `sub_filter` nginx. Pattern M-7 nonce-based CSP era stato introdotto 10 gg fa (commit `93b9c42`/`5d5b1bb`), il bug latente esisteva da allora ma è esploso ora che il portal è stato rebuildato dopo i fix di [04.1.3].<br>**🔧 FIX**: una riga in `portal/astro.config.mjs` → `vite.build.assetsInlineLimit: 0` (forza Vite a emettere TUTTI gli script come file esterni `/_astro/*.js`, autorizzati da `script-src 'self'`). Sicurezza M-7 invariata. Commit `42d7ea0` su `claude/fix-sentrikat-e2e-handoff-gsI9M`<br>✅ **VERIFIED**: portal sblocca, dashboard renderizza, no CSP errors |
| **2026-04-26** | 04 | **🆕 NEW BUG `[04.2.2]` Chart.js eval() viola CSP su pagine `/admin/*`** | Sub-bug discoverato durante diagnosi `[04.2.1]`: Chart.js usa `new Function()` per le animazioni, blocato da `script-src` senza `'unsafe-eval'`. **Non impatta dashboard cliente** (Chart.js solo in pagine admin portal). **Pending**: bundlare Chart.js localmente con tree-shake delle animazioni, oppure aggiungere `'unsafe-eval'` (degrade security). Da affrontare in sessione dedicata |
| **2026-04-26** | — | **🔧 SESSION FIX — Batch web (parallela)** (sbr0nch/SentriKat-web, branch `claude/fix-sentrikat-e2e-handoff-gsI9M`, PR aperta dall'utente) | **12/12 bug del handoff fixati**, 9 commit atomici, HEAD `b766153`. Dettaglio in `docs/e2e-tests/FIX-HANDOFF-sentrikat-web.md` — Progress log. Highlights:<br>✅ **[04.1.3] CRITICAL OTP** (`524208b`) — root cause **NON** era PR #231 come ipotizzato in handoff: era `send_email` + `BackgroundTasks` che catturavano ogni eccezione con `print(...)` → response sempre 200 anche su fallimento SMTP. Fix: `logger.exception` + `await` sincrono + return 500 esplicito<br>✅ **[02.4.1]** + **[02.4.2]** (`0f93867`) — temp password plaintext rimossa, redirect a forgot-password (OTP); `$0`→`€0`<br>✅ **[01.17.1]** (`06f157d`) — nginx `try_files =404` + `error_page /404.html`<br>✅ **[01.2.1]** (`dec104a`) — CSP allow-list Google Fonts (self-hosting resta follow-up)<br>✅ **[01.8.1]** (`e339bdd`) — CookieBanner rewrite difensivo (3 cause plausibili coperte)<br>✅ **[02.2.1]** (`004d25c`) — `setCustomValidity` EN su terms checkbox<br>✅ **[01.16.4]** (`bd7bf25`) — `security.txt` Preferred-Languages: en<br>✅ **[01.9.1]** + **[01.12.3]** (`beb7d27`) — blog i18n minimale con badge lingua (Option B)<br>✅ **[01.16.1]** — verified only, no fix needed<br>✅ **[02.3.2]** (`b766153`) — specialized 409 message per Gmail `+tag`<br>⏸️ **[02.4.5-4.8]** email deliverability (SPF/DKIM/DMARC/Reply-To/List-Unsubscribe) — **non fixati**, richiedono modifiche DNS + decisione architetturale. Da trattare in sessione dedicata<br>**Verifica differita**: laptop principale → testare login portal OTP in prod |

---

## Bug counter globale

**Post verify round 1 — 2026-04-26 fine giornata** (rebuild + test prod):

- 🔴 Bug aperti: **13** *(-1 nuovo bug sub `[04.2.2]` Chart.js, +1 nuovo bug `[04.2.1]` poi fixato → net 12 + 1 sub-bug aperto)*
- 🟡 Warning: 10
- 🔵 Info/UX: 61
- 🟢 OK passati: 100
- ⏸️ Test bloccati: 5 (residui solo on-prem dependencies)
- ✅ Fix applicati: **20** *(7 core + 13 web — incluso `[04.2.1]` di oggi)*
- ✅✅ Fix VERIFIED: **9** su 20 *(round 1 completato: 8 batch + [04.2.1] CSP)*. Restano da verificare: `[02.4.1]/[02.4.2]` welcome email (browser, ricabbia 5 min) + 7 fix core on-prem (richiedono laptop principale con docker)

*(aggiornati a mano ad ogni commit)*

---

## Backlog "Test bloccati da fix propedeutici" ⏸️

Test che non sono eseguibili finché non viene risolto un bug a monte. Da riprendere dopo la fase di fix.

**Legenda post-fix 2026-04-26**: `🔧` = fix applicato (unverified), pronto per re-test sul laptop principale. `⏸️` = ancora bloccato.

| Test ID | Fase/Area | Sommario | Stato |
|---|---|---|---|
| 🔧 03.11.2.9 | 03 / LDAP login | Login di un utente LDAP seedato non può essere testato significativamente finché non c'è la pagina admin per "accettare/invitare" l'utente LDAP prima del login | **Unblocked** dopo fix [03.11.2.3] (commit `d44fcd0`). Re-test richiede rebuild on-prem docker |
| 🔧 03.11.4 (all) | 03 / Jira integration | Test funzionali Jira non eseguibili con testlab docker in `FLASK_ENV=production` (policy SSRF hardening ignora `ALLOW_PRIVATE_URLS`) | **Unblocked parzialmente**: [03.11.4.5] fixato in log + UI hint (commit `4bf0afd`), la policy hardening resta by-design. Workaround: passare a `FLASK_ENV=development` per test locale |
| 🔧 03.11.5 (all) | 03 / Webhook | Test funzionali Webhook out bloccati dalla stessa policy SSRF | **Unblocked** con stesso workaround di 03.11.4 |
| 🔧 03.11.6.4 | 03 / GitLab | Test funzionali GitLab bloccati dalla stessa policy SSRF | **Unblocked** con stesso workaround |
| 🔧 03.11.6.8 | 03 / YouTrack | Saltato in questa sessione (pattern atteso uguale), test rinviato a post-fix | **Unblocked** con stesso workaround |
| ⏸️ 03.12.6–15 | 03 / Agent inventory | Agent install OK ma initial scan 403/401 con messaggio fuorviante "Invalid API key". Key attiva nel DB (`active=t`, usage_count=3). Root cause vero nascosto da messaggio generico | **Message migliorato** dopo [03.12.14] fix (commit `4327d27`) ma root cause reale (`[03.13.2]` Push Agents gated su Community) resta — upgrade a Professional richiesto per test completo |
| 🔧 04.1.3 (Phase 04 intera) | 04 / Portal Customer OTP | OTP email non arriva nonostante response 200 OK. Regressione confermata: funzionava 7 giorni fa, rotto ≥ 2026-04-24. Intero portal customer (dashboard, licenses, downloads, support, checkout) non raggiungibile | **Unblocked** dopo fix SentriKat-web commit `524208b` (root cause: `send_email` swallow con `BackgroundTasks`, NON era PR #231). Re-test: login portal con OTP in prod dopo deploy |
| 🔧 06.6.1 (dim 4 RBAC matrix) | 06 / App SaaS RBAC | Matrix role-based dei 3 users SaaS Starter non testabile: i 2 user creati (manager, user) non ricevono invite email (stesso cluster SMTP di 04.1.3) | **Unblocked** presunto dopo fix `524208b` (stesso cluster `send_email`). Re-test: inviare invite e verificare delivery |

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

## Strategie per testare feature time-based / scheduled / asincrone

Utente ha giustamente osservato: *"tipo quando metto alert ogni mattina alle 9 come faccio a testarlo? pensa a una soluzione. veramente dobbiamo testare TUTTO."* — questa sezione dichiara **come** testiamo le feature che non producono feedback immediato.

### Classificazione delle feature time-based

| Categoria | Esempio | Come testare |
|---|---|---|
| **Interval jobs** | CISA KEV sync daily 02:00 UTC, EPSS daily, critical email digest daily 09:00 UTC, maintenance 04:00 UTC | Strategia A (trigger manuale) o B (cambio interval) o D (docker date) |
| **Event-driven** | Alert su nuovo CVE match, webhook su assignment overdue, audit log on user.login, lockout dopo 5 failed login | Strategia E (trigger l'evento) o F (DB insert fake) |
| **Retention cleanup** | Audit log >365d eliminato, session log >30d, sync history >90d | Strategia F (DB insert con data futura) o D (docker date forward) |
| **Background workers** | APScheduler (14 jobs noti), inventory job processor, stuck job recovery (ogni 10 min) | Strategia A (Run Now) o C (Python one-shot) |
| **Expirations** | License expiry, agent API key expires_at, password expiry, session timeout, trial end date | Strategia D (docker date forward) o F (DB update expires_at nel passato) |
| **External scheduled** | Patch Tuesday (2nd Wed of month), weekly CPE dictionary (lunedi 05:00) | Strategia A (trigger manuale se bottone c'è) o D (docker date a 2nd Wed mese successivo) |
| **Delivery delays** | Email throttling, webhook retry backoff, SMTP queue | Strategia E (forza trigger multipli rapidi) |
| **Async processing** | Inventory queue processing, CPE matching batch, snapshot creation | Strategia A (Run Now) + D (wait for timer) |

### Strategie di testing (catalogo)

#### **Strategia A — Trigger manuali "Run Now" / "Sync Now" / "Test Now"**
Molte feature hanno un bottone che bypassa lo scheduler. Preferita perché veloce e isolata.

Bottoni `Run Now` / `Sync Now` / `Send Now` **già osservati** nell'UI:
- `Settings → System → Sync & Updates`: Sync CISA Now, Sync EPSS Scores Now, Sync CPE Dictionary Now, Rebuild from Vulnerabilities, Send Email Alerts Now, Send Webhook Alerts Now
- `Settings → Email & Alerts`: Send Test Email
- `Settings → Authentication → LDAP`: Test Connection
- `Settings → Authentication → SAML`: Test Configuration
- `Settings → SIEM / Syslog`: Send Test Event
- `Settings → System → Data Retention`: Run Auto-Acknowledge Now
- `Settings → Health Checks`: Run Now (tutti i check)
- `Settings → License`: Check (update check)

**Quando usarla**: sempre quando possibile. Evita time-travel/system date change, mantiene ambiente pulito.

#### **Strategia B — Cambio intervallo schedule a valore basso**
Cambiare "Sync Interval: Daily" → "Every N minutes" nel form (se il dropdown lo supporta), aspettare il prossimo run.

Limiti: alcune UI hanno dropdown enumerato (Daily/Weekly/Monthly), non custom. In quel caso non si può usare.

**Quando usarla**: quando Strategia A non è disponibile e vogliamo testare l'automatism (non solo il codice del job).

#### **Strategia C — Python one-shot nel container**
Invocare direttamente la funzione del job via Python exec:
```powershell
docker compose -p v100-beta6 exec sentrikat python -c "
from app import create_app
from app.scheduler import <job_name>
<job_name>(create_app())
"
```
La pagina Usage Uploads già suggerisce questo pattern ([03.7.4]).

**Quando usarla**: per job APScheduler che non hanno UI button (es. `stuck_job_recovery`, `asset_type_auto_detect`, `vulnerability_snapshots`).

#### **Strategia D — Time-travel container (docker date change o libfaketime)**
Spostare in avanti l'orologio del container per attivare scheduler + trigger date-based:
```powershell
# Opzione D1 — cambiare system date (richiede container privileged)
docker compose -p v100-beta6 exec sentrikat date -s "2026-05-13 09:05:00"

# Opzione D2 — libfaketime override (non invasivo, richiede pacchetto nel container)
# LD_PRELOAD=/usr/lib/faketime/libfaketime.so.1 FAKETIME="+30d" python ...

# Opzione D3 — restart container con env var custom per data offset
# (serve feature nel prodotto per supportare SENTRIKAT_TIME_OFFSET=+30d)
```

**Quando usarla**: per testare Patch Tuesday (2nd Wednesday), retention cleanup, license expiry, trial end date, password expiry.

**Attenzione**: cambiando data tutti i container la vedono diversamente rispetto al host → aspettare dopo restart per sincronizzazione. Possibile confusione. Usa sandbox dedicata.

#### **Strategia E — Forzare l'evento che triggera il flow**
Per event-driven feature, generare l'evento stesso invece di aspettare:
- **Lockout**: fare 6 login falliti consecutivi → verificare account locked per 30 min
- **Alert su CVE critico**: inserire manualmente un product + CVE critical match via DB
- **Webhook su assignment overdue**: creare assignment con `due_date` nel passato
- **Email digest**: Sync CISA manual + verificare se digest viene trigger (o combo con B/D)
- **Session timeout**: settare `SESSION_TIMEOUT_MINUTES=1`, aspettare 1 min, verificare logout
- **Sessione inattiva**: logout + aspettare N min + verificare token invalido

**Quando usarla**: per policy-based feature (lockout, timeout, rate limit).

#### **Strategia F — Inserimento dati test direttamente in DB**
Per testare flow che richiedono dati preesistenti (inventory, CVE match, products) quando Push Agents è bloccato dalla license:
```powershell
# Inserisci fake product
docker compose exec db psql -U sentrikat sentrikat -c "
  INSERT INTO products (vendor, product_name, version, ...) VALUES ('Microsoft', 'Office', '16.0.0.0', ...);
"

# Inserisci fake vulnerability match
docker compose exec db psql -U sentrikat sentrikat -c "
  INSERT INTO vulnerability_matches (product_id, vulnerability_id, confidence, ...) VALUES (1, 1, 'HIGH', ...);
"

# Setta expires_at nel passato per trigger expiration
docker compose exec db psql -U sentrikat sentrikat -c "
  UPDATE agent_api_keys SET expires_at = NOW() - INTERVAL '1 day' WHERE id = 1;
"
```

**Quando usarla**: per popolare il prodotto e testare dashboard, remediation, compliance reports, SLA, trending — senza dipendere da agent Push bloccato.

**Rischi**: può corrompere lo stato DB. Sempre dump del DB prima di fare test invasivi su DB. Meglio su un'istanza dedicata "testing".

#### **Strategia G — Configurazione condizionale**
Alcune feature hanno env var o setting per abbreviare il tempo:
- `SMTP_QUEUE_RETRY_DELAY=5s` invece del default 60s
- `WEBHOOK_RETRY_BACKOFF=1,2,4` invece di `30,60,120`
- `AGENT_HEARTBEAT_INTERVAL=10s` invece di 5 min

**Quando usarla**: se il prodotto supporta override configurabili. Altrimenti richiede code patch (non nel nostro scope "no fix").

---

### Catalogo completo scheduler jobs + test strategy per ciascuno

14 jobs APScheduler noti dalla mappatura originale. Stato test per ognuno:

| Job | Schedule default | Strategy applicable | Test status |
|---|---|---|---|
| cisa_kev_sync | Daily 02:00 UTC | A (Sync CISA Now btn) / B (change interval) | ⬜ da testare (button visto in UI) |
| vendor_advisory_sync | Daily 03:00 UTC | A (forse esiste) / C (python one-shot) | ⬜ |
| nvd_cpe_dictionary_sync | Weekly Sun 04:00 | A (Sync CPE Dictionary Now) | ⬜ |
| cve_known_products_refresh | Every 12h | C (python) | ⬜ |
| epss_score_sync | Daily | A (Sync EPSS Scores Now) | ⬜ |
| critical_email_digest | Daily 09:00 UTC | A (Send Email Alerts Now) / D (time travel) | ⬜ |
| maintenance_job | Daily 04:00 UTC | A (probabile) / C | ⬜ |
| stuck_job_recovery | Every 10 min | C / D (aspetta 10min+1s) | ⬜ |
| asset_type_auto_detect | Daily 06:00 UTC | C | ⬜ |
| unmapped_cpe_retry | Weekly Mon 05:00 | C | ⬜ |
| kb_sync | Every 12h | C | ⬜ |
| license_heartbeat | Every 12h | C | ⬜ (bloccato se license server upstream) |
| vulnerability_snapshots | Daily 02:00 UTC | C | ⬜ (richiede dati tramite Strategia F) |
| patch_tuesday_digest | 2nd Wed 09:00 UTC | D (time travel a 2nd Wed) / A se ha button | ⬜ |

### Time-based feature da testare (non coperte da 14 jobs)

| Feature | Trigger | Strategy |
|---|---|---|
| Account lockout dopo 5 failed login | 5 POST /login con password sbagliata | E |
| Session timeout dopo 480 min idle | Logout automatico dopo idle | E + G (setta 1 min) |
| Password expiry (disabled default 0) | Cambia a 1 day, aspetta 1 day | G + D |
| Trial end date SaaS | 14 giorni default | D (time travel) |
| Audit log retention > 365d | Insert fake audit log con timestamp 400 giorni fa → run cleanup | F + A |
| Sync history retention > 90d | stesso pattern | F + A |
| Session log retention > 30d | stesso | F + A |
| Email throttling (max 10 identical vulns/day) | Send 11 email identiche rapidamente | E (11 trigger consecutivi) |
| Webhook retry backoff | Webhook verso endpoint intenzionalmente down → osservare retry | E + stop testlab-webhooks |
| Agent offline detection (ogni 5 min) | Stop agent → aspetta 5 min → status change | D/E |
| Alert on new CVE match | Insert CVE + product match via DB | F + E |
| SLA escalation su assignment overdue | Insert assignment con due_date passata | F |
| License expiry warnings | Update license expires_at a 7 gg | F |
| API key expires_at | Update key expires_at | F |
| 2FA setup + verify | Setup flow + QR scan | E |
| Force password change | Admin mark user as must-change → login | E |
| Breached password check (NIST) | Test con password notoriamente compromesse ("password", "12345678") | E |
| CAPTCHA Turnstile failure | Submit form con token fake | E |

### Download / Export feature da testare

Trigger immediato ma validation è sul file generato. Feature:

| Feature | File generato | Test |
|---|---|---|
| CSV vulnerability export | `GET /api/reports/export/csv` | Apri CSV, verifica headers + data |
| BOD 22-01 JSON | `GET /api/reports/compliance/bod-22-01?format=json` | Parse JSON, verifica schema |
| BOD 22-01 PDF | stesso `?format=pdf` | Apri PDF, verifica branding/contenuto |
| NIS2 JSON/CSV/PDF | `GET /api/reports/compliance/nis2` | 3 formati |
| PCI-DSS PDF | `GET /api/reports/compliance/pci-dss` | PDF branded |
| ISO 27001 PDF | stesso | |
| SOC 2 PDF | stesso | |
| Executive Summary PDF | `GET /api/reports/executive-summary` | One-pager |
| Overdue Items PDF | `Download Overdue Report` btn | Lista CVE overdue |
| SBOM CycloneDX | `GET /api/sbom/export/cyclonedx` | Valid JSON CycloneDX 1.5 schema |
| SBOM SPDX | `GET /api/sbom/export/spdx` | Valid JSON SPDX 2.3 |
| SBOM STIX 2.1 | `GET /api/sbom/export/stix21` | Valid bundle |
| Audit Log export | Export btn in Audit Logs page | CSV/JSON |
| GDPR Export | `GET /api/gdpr/export` | Full user data export |
| DB Backup | `POST /api/settings/backup` (on-prem only) | SQL dump |
| Agent script download | `GET /api/agent/download/<platform>` | PowerShell/.sh file |
| License activation (offline) | Paste key → validate | |

### Regola operativa

Quando troviamo una feature time-based / async che non possiamo testare immediatamente, invece di skipparla:
1. Documentiamola nella "Follow-up TODO list" sopra
2. Annotiamo la **Strategia** (A/B/C/D/E/F/G) che useremo nel secondo giro
3. Se richiede setup test data (Strategia F) → flag `requires-db-seed`
4. Se richiede time travel (D) → flag `requires-time-travel`
5. Nel secondo giro eseguiamo la strategy e catturiamo il risultato

Questo dà copertura completa a "testare TUTTO di TUTTO" senza dover aspettare giorni reali per ogni evento.

---

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
