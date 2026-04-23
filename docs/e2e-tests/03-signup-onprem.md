# Fase 03 — Signup On-Prem

> Test end-to-end del flow on-premise: acquisto/lead → download package → setup Docker → first-run wizard → activation DEMO/PRO → primo login → configurazione integrazioni (via testlab locale) → deploy agent.
>
> **Environment**: Windows 11 + Docker Desktop, Sentrikat build `v1.0.0-beta.6` clonato da `https://github.com/sbr0nch/SentriKat.git`, project dir `C:\SentriKat\v1.0.0-beta.6\`, compose project name `v100-beta6`.
> **Testlab**: `C:\SentriKat\testlab\docker-compose.testlab.yml` (Keycloak, OpenLDAP, Mailpit, webhook-tester, jira-mock, syslog, proxy, dozzle, uptime-kuma, elasticsearch, kibana).
>
> **Hostname mapping**:
> - Nel browser/host Windows: servizi testlab raggiungibili su `localhost:<porta>`
> - Dai container sentrikat: stessi servizi su `host.docker.internal:<porta>`
>
> **Testlab ports confermate (dal `docker-compose.testlab.yml` utente)**:
> - Mailpit SMTP `1025`, Web UI `8025`
> - OpenLDAP `389` + `636`, phpLDAPadmin `6443`
> - Keycloak `8180` (HTTP) + `8443` (HTTPS), admin: `admin/admin123`
> - Jira mock `8080` (MockServer → container 1080)
> - Webhook tester `8800`
> - Syslog `5514 UDP+TCP`
> - Squid proxy `3128`
> - Dozzle (log viewer) `9999`
> - Uptime-Kuma `3001`

## Aree coperte

| Area | Descrizione |
|---|---|
| 03.1 | Pre-install: form TrialSignup `deployment=on-prem` su sentrikat.com (SaaS test coperto in fase 02; questo è il branch on-prem del form) |
| 03.2 | Pre-install: `/contact-sales` lead creation |
| 03.3 | Pre-install: release package download (GitHub Releases asset vs git clone) |
| 03.4 | Install: `.env` generation, secret generation PowerShell + Fernet via docker |
| 03.5 | Install: `docker compose up --build` → migrations applied, scheduler started |
| 03.6 | First-run setup wizard `localhost/setup` (6 step) |
| 03.7 | License activation DEMO (nessun file license) |
| 03.8 | License activation PRO (file `.license` RSA-4096) — se disponibile |
| 03.9 | Hardware lock verification (`SENTRIKAT_INSTALLATION_ID`) |
| 03.10 | First login + dashboard empty |
| 03.11 | Integrazioni da admin UI: SMTP (→ Mailpit), LDAP/AD (→ OpenLDAP), SAML (→ Keycloak), Webhook (→ webhook-tester), Jira (→ jira-mock), SIEM syslog |
| 03.12 | Deploy Windows agent (PowerShell script) + inventory first report |
| 03.13 | CISA KEV sync first run + primo matching vulnerabilità |
| 03.14 | Backup DB + restore (feature on-prem only) |
| 03.15 | Upgrade path: rebuild con `SENTRIKAT_INSTALLATION_ID` fissato → license sopravvive |

---

## 03.5 — Install `docker compose up` (primo boot)

### [03.5.1] Build + startup completati con successo ✅

- **Fase**: 03
- **Area**: Install
- **Environment**: Windows 11 + Docker Desktop, tag `v1.0.0-beta.6`
- **Tipo**: 🟢 OK
- **Actual**:
  - Image build ≈ 87s (pip install) + 32s (layer export) = ~2 min
  - Compose up: 3 container creati (`sentrikat`, `sentrikat-db`, `sentrikat-nginx`)
  - Dopo ~50 min di idle: tutti `Up (healthy)`
  - Network `v100-beta6_default` creata
  - Volumes `v100-beta6_sentrikat_data` + `v100-beta6_postgres_data` creati
- **Discovered**: 2026-04-23

### [03.5.2] Schema migrations applicate automaticamente ✅

- **Tipo**: 🟢 OK
- **Log relevant**:
  ```
  INFO in __init__ (create_app:937): Applying schema migrations for PostgreSQL...
  INFO  [alembic.runtime.migration] Running stamp_revision  -> 0002_consolidated_boot_migrations
  ```
- **Discovered**: 2026-04-23

### [03.5.3] 🔴 VERSION file hardcoded a `1.0.0-beta.2` nel tag `v1.0.0-beta.6`

- **Fase**: 03
- **Area**: Release process / version reporting
- **Tipo**: 🔴 Bug
- **Severity**: **High** (version reporting errato → impossibile per un customer/support capire quale build sta girando)
- **Environment**: prod (repo) / local (build locale)
- **Steps to reproduce**:
  1. `git clone --branch v1.0.0-beta.6 --depth 1 https://github.com/sbr0nch/SentriKat.git`
  2. `cat VERSION` → restituisce `1.0.0-beta.2` (**NON** `1.0.0-beta.6`)
  3. Avvia la stack + `curl http://localhost/api/health` → response contiene `"version":"1.0.0-beta.2"` e header `X-App-Version: 1.0.0-beta.2`
- **Expected**: `VERSION` file = `1.0.0-beta.6`, `/api/health` risponde `"version":"1.0.0-beta.6"`
- **Actual**: entrambi dicono `1.0.0-beta.2`
- **Root cause**: il workflow `.github/workflows/release.yml` scrive il VERSION file a build-time (`echo "${GITHUB_REF_NAME#v}" > VERSION` nello step `Set VERSION file`), MA:
  - L'aggiornamento avviene **solo dentro** il build Docker di GitHub Actions (quindi incide sull'image GHCR)
  - **Non viene committato nel repo**, quindi `git clone` restituisce la vecchia versione committata
  - Un build locale con `docker compose up --build` ricompone l'image usando il VERSION file del working tree, che è ancora `1.0.0-beta.2`
- **Impatto**:
  - Self-hosters che clonano il tag e buildano vedono versione fuorviante
  - Header `X-App-Version` inaffidabile per debug/support
  - Log iniziali mostrano versione sbagliata
  - **I 4 tag precedenti (beta.3, beta.4, beta.5) probabilmente hanno lo stesso problema** (VERSION inchiodato a beta.2)
- **Fix candidato**:
  - Opzione A: pre-release checklist / pre-commit hook che bumpa `VERSION` PRIMA del tag (commit `chore(release): bump version to X.Y.Z` + push + tag su HEAD)
  - Opzione B: rimuovere VERSION file fisico e leggerlo dinamicamente da `git describe --tags` al runtime
  - Opzione C: `Dockerfile` step `ARG VERSION` + `RUN echo $VERSION > /app/VERSION` al build, passato da docker compose come build arg
- **File sospetto**: `.github/workflows/release.yml` + `VERSION` file + `app/__init__.py` (dove viene letto)
- **Discovered**: 2026-04-23

### [03.5.4] 🟡 Flask-Limiter usa storage in-memory (warning produzione)

- **Fase**: 03
- **Area**: Install / rate limiting
- **Tipo**: 🟡 Warning
- **Severity**: Medium (rate limit per-worker invece di cluster-wide → se Gunicorn scala a N worker i limiti si moltiplicano per N)
- **Environment**: on-prem Docker default
- **Log relevant**:
  ```
  UserWarning: Using the in-memory storage for tracking rate limits as no storage was explicitly specified.
  This is not recommended for production use.
  See: https://flask-limiter.readthedocs.io#configuring-a-storage-backend
  ```
- **Expected**: storage Redis (o equivalente) per rate limiting persistente cluster-wide
- **Actual**: storage in-memory, reset a ogni restart, incoerente tra worker multipli
- **Impatto**:
  - Rate limit configurato "5 login/min" diventa "5 × N_worker/min" se si scala
  - Se Gunicorn riavvia un worker (es. `GUNICORN_MAX_REQUESTS`) il counter si azzera
  - Un attaccante può aggirare aumentando il concorrency
- **Fix candidato**:
  - Aggiungere servizio `redis:7-alpine` al `docker-compose.yml` (opzionale, abilitabile via env)
  - `.env.example`: `RATE_LIMIT_STORAGE_URL=redis://redis:6379/0` (o vuoto per in-memory)
  - Documentare in `docs/DEPLOYMENT.md` che per HA / multi-worker serve Redis
- **Discovered**: 2026-04-23

### [03.5.5] 🟡 `send_usage_to_license_server` logga `ERROR` invece di `WARN` quando `SENTRIKAT_METRICS_KEY` manca

- **Fase**: 03
- **Area**: Install / licensing / log levels
- **Tipo**: 🟡 Warning
- **Severity**: Low-Medium (log hygiene)
- **Environment**: on-prem senza license telemetry
- **Log relevant**:
  ```
  ERROR [app.metering] send_usage_to_license_server: no SENTRIKAT_METRICS_KEY configured, aborting usage upload
  ```
- **Expected**: `WARN` o `INFO` level (manca la key → feature disabilitata by design, non è un errore)
- **Actual**: `ERROR` (genera noise in monitoring/SIEM; attiva alert Sentry/Prometheus "error rate" su install DEMO che non hanno metrics key)
- **Fix candidato**: in `app/metering.py`, se `SENTRIKAT_METRICS_KEY is None`: fare early return **senza logging**, oppure loggare `INFO` (es. "usage telemetry disabled, metrics key not configured"). Alternativa: girare il check in config validation al boot e fail-fast se `SENTRIKAT_MODE=saas` senza metrics key.
- **File sospetto**: `app/metering.py` → funzione `send_usage_to_license_server`
- **Discovered**: 2026-04-23

### [03.5.6] Scheduler APScheduler attivo, job schedulati correttamente ✅ (con nota)

- **Fase**: 03
- **Area**: Scheduler
- **Tipo**: 🟢 OK / 🔵 Info
- **Actual**: vari `WARNI [apscheduler.executors.default] Run time of job "..." was missed by 0:00:01.xxx` per job `Agent Offline Detection`, `Recover Stuck Inventory Jobs`, `Process Scheduled Reports`, `Background Health Checks`
- **Note**: "Run time missed by ~1.2s" è normale all'avvio (scheduler catch-up dopo boot lento o dopo idle — quando Docker Desktop mette in pausa i container in background su Windows, gli interval jobs accumulano missed run alla ripresa).
- **Non blocca** il funzionamento; è un side-effect architetturale di APScheduler + `misfire_grace_time` default.
- **Follow-up TODO 03.5.6a**: verificare se `misfire_grace_time` è impostato nelle definizioni job. Se no, impostarlo esplicitamente a un valore ragionevole (es. 300s) e aggiungere coalesce=True per evitare run multipli in catch-up.
- **File sospetto**: `app/scheduler.py`
- **Discovered**: 2026-04-23

---

## 03.6 — Setup wizard first-run (`localhost/setup`)

### [03.6.1] Wizard first-run appare al primo accesso ✅

- **Fase**: 03
- **Area**: Setup wizard
- **URL**: `http://localhost/` → redirect a `http://localhost/setup`
- **Tipo**: 🟢 OK
- **Actual**:
  - Accedendo a `/` SentriKat redireziona automaticamente a `/setup` (comportamento corretto per installazione mai inizializzata)
  - Wizard a **6 step** visibile (stepper 1-2-3-4-5-6 in cima)
  - Step 1 — Welcome: titolo "🚀 Welcome", subtitle "Get up and running in a few quick steps", feature highlights (CVE Tracking, Alerts, Prioritization, Multi-Tenancy), bottone "Get Started →"
  - Logo mascot stile mongoose + wordmark SentriKat, layout coerente col branding del portal
- **Discovered**: 2026-04-23

### [03.6.2] 🔵 Wizard mostra feature "Multi-Tenancy" anche su DEMO (non disponibile)

- **Fase**: 03
- **Area**: Setup wizard / feature gating
- **Tipo**: 🔵 Info
- **Severity**: Low
- **Actual**: la welcome card mostra 4 feature headline, tra cui **Multi-Tenancy** ("Separate orgs with independent product catalogs"). Ma in DEMO Edition (mappa architetturale) Multi-Tenancy è gated a licenze Professional.
- **Potential UX issue**: un utente che installa la DEMO si aspetta Multi-Tenancy disponibile basandosi sul wizard, poi scopre in-app che non lo è → frustrazione.
- **Fix candidato**: mostrare accanto a ogni feature un badge "DEMO" / "PRO" / "BUSINESS" per disambiguare cosa è incluso in che edition; oppure nascondere le feature non incluse nella edition corrente.
- **Discovered**: 2026-04-23

### [03.6.3] 🔴 HIGH — Setup wizard si auto-locka dopo step 3: step 4/5/6 irraggiungibili, Seed Catalog → 403

- **Fase**: 03
- **Area**: Setup wizard / bootstrap flow
- **Tipo**: 🔴 Bug
- **Severity**: **High** (blocker: impedisce di completare il wizard, impossibile seedare il service catalog di 80+ servizi, utente perde passaggi 5-6 non testabili)
- **Environment**: local Windows Docker, beta.6 build locale, first install pulita
- **Steps to reproduce**:
  1. First-run `localhost/setup`
  2. Step 1 Welcome → click "Get Started →"
  3. Step 2 Organization: compila Name (e.g. "SentriKat Test Org") + opt desc/alert emails → click "Create →"
  4. Step 3 Admin Account: compila username `admin`, email, Full Name, password (min 8) + confirm → click "Create →"
  5. Step 4 Service Catalog: click "Seed Catalog →"
- **Expected**: `POST /api/setup/seed-services` → 200/201, lista di 80+ servizi caricata, avanzi a step 5
- **Actual**:
  - Console browser: `POST http://localhost/api/setup/seed-services → 403 (FORBIDDEN)` (stack trace: `seedServices @ setup:681`)
  - Banner rosso inline: **"Setup already completed."**
  - Impossibile procedere; qualsiasi refresh redirige a `/login` (il setup flag è definitivamente settato)
  - Step 5 e 6 del wizard **mai visibili**, la mappa del flow rimane incompleta
- **Root cause ipotesi**:
  - Il backend marca `setup_complete=True` dopo lo step 3 (creazione admin + org), invece che al termine di TUTTI i 6 step
  - Il middleware che gate-gli endpoint `/api/setup/*` controlla questo flag → 403 "Setup already completed" su qualsiasi POST successivo
  - Probabilmente in `app/setup.py` o `app/routes.py` c'è un `if setup.is_complete(): return 403` su tutti gli endpoint `/api/setup/*` senza distinguere quali step sono stati effettivamente fatti
- **Impatto**:
  - Customer on-prem non riceve i 80+ servizi preconfigurati (Microsoft Office, Apache, nginx, MySQL, ecc.) → deve seedarli a mano o importarli da CSV
  - Feature del catalog → inutile per DEMO/first-run
  - Step 5 e 6 (che potrebbero essere: License activation? SMTP setup? Integrations?) irraggiungibili → **non possiamo testarli in questa install**
- **Fix candidato**:
  - Il flag "setup complete" deve dipendere da un checkpoint finale (step 6 final submit), non dal completamento di ogni step singolo
  - Oppure: endpoint `/api/setup/*` devono essere accessibili in stato `in_progress` fino al final commit, non solo prima del primo POST riuscito
  - File sospetto: `app/setup.py`, `app/routes.py` (probabilmente funzione `require_setup_incomplete` o decorator simile)
- **Workaround operativo**:
  - **Non attuabile via UI**: una volta auto-lockato il wizard non torna indietro
  - Via CLI: connettersi al DB e flippare la flag `setup_complete=False` manualmente (`docker compose -p v100-beta6 exec sentrikat-db psql -U sentrikat sentrikat -c "UPDATE system_settings SET setup_complete=false WHERE id=1;"` — nome tabella da verificare)
  - Oppure: wipe volumi + re-install + creare prima admin via env var (se supportato) e saltare wizard
- **Discovered**: 2026-04-23

### [03.6.4] Step 3 password validation (min 8 char) client-side OK ✅

- **Tipo**: 🟢 OK
- **Actual**: input password `test123` (6 char) → banner rosso "Password must be at least 8 characters long!" appare in cima al form; rinserire `TestPass123!` → accettato, admin creato. Coerente con [02.6.2] dell'app SaaS.
- **Discovered**: 2026-04-23

### [03.6.5] 🔵 Label bottoni wizard: "Create →" usato anche per step non-terminali

- **Fase**: 03
- **Area**: Setup wizard / copywriting
- **Tipo**: 🔵 Info
- **Severity**: Low (UX)
- **Actual**: sia step 2 (Organization) che step 3 (Admin Account) mostrano il bottone `Create →`. Ma il "create" finale (commit del setup) dovrebbe avvenire solo all'ultimo step. I non-finali dovrebbero dire `Next →` per chiarezza.
- **Correlato**: il bug [03.6.3] potrebbe dipendere proprio dal fatto che il backend interpreta ogni "Create" come commit → marca setup complete prematuramente
- **Fix candidato**: step 2/3/4 usano `Next →`, solo step 6 (Finalize?) usa `Finish →` o `Complete →`
- **Discovered**: 2026-04-23

### [03.6.6] 🔴 Dopo login as admin, sidebar mostra "Platform Operations" (sezione SaaS) su installazione on-prem

- **Fase**: 03
- **Area**: Post-setup / sidebar / mode gating
- **Tipo**: 🔴 Bug
- **Severity**: **Medium-High** (security/UX: espone voci di menu irrilevanti per on-prem e potenzialmente confondenti o esposte a click inutili/error-prone)
- **Environment**: on-prem, `SENTRIKAT_MODE=onpremise`, DEMO edition, primo login come admin (auto-promoted a super_admin su first-run)
- **Steps to reproduce**:
  1. Completa setup wizard fino al login
  2. Login come admin
  3. Osserva sidebar
- **Actual**: dopo "System" section, appare una sezione **"Platform Operations"** con 3 voci:
  - `Cross-Repo Integration`
  - `Webhook Events`
  - `Usage Uploads`
- **Expected**: queste 3 voci sono parti del **portal admin SaaS** (vedi mappatura repo: `portal/src/pages/admin/saas-tenants.astro`, `webhook-outbox.astro`, `usage-metrics.astro`). In installazione on-prem non hanno senso (non c'è cross-repo, non c'è outbound webhook verso un tenant SaaS, non c'è usage upload).
- **Impatto**:
  - Customer on-prem vede feature che non gli appartengono → confusione
  - Click su `Usage Uploads` probabilmente cerca di chiamare `/api/admin/usage/...` con `SENTRIKAT_METRICS_KEY` che non esiste → errori a ripetizione
  - Espone concetti SaaS-only (cross-repo, webhook outbox) a un customer che potrebbe interpretarli come "funzioni mancanti / bug"
- **Root cause ipotesi**:
  - Il menu template (probabilmente in `app/templates/base.html` o layout component) non fa il check `{% if saas_mode %}` prima di renderizzare la sezione Platform Operations
  - Oppure: la sezione è aggiunta via blueprint/role check ma il check è `is_super_admin` invece di `is_saas_super_admin`
- **Fix candidato**:
  - Wrap della section `Platform Operations` con `{% if config['SENTRIKAT_MODE'] == 'saas' %}` nel template
  - Oppure: gating delle rotte dei 3 endpoint (`/admin/cross-repo`, `/admin/webhook-events`, `/admin/usage-uploads`) a `@saas_only` decorator (simmetrico al `@on_prem_only` usato per backup/restore)
- **File sospetto**: `app/templates/base.html` o `app/templates/admin_panel.html` + relativi route handler
- **Discovered**: 2026-04-23

### [03.6.7] 🔵 Console debug log `[SentriKat] Initializing...` visibili in production mode

- **Fase**: 03
- **Area**: Frontend / logging hygiene
- **Tipo**: 🔵 Info
- **Severity**: Low
- **Environment**: `FLASK_ENV=production`, `SENTRIKAT_ENV=production` nel `.env`
- **Actual**: dopo login la console browser mostra:
  ```
  [SentriKat] Initializing SentriKat Core v1.0.0
  sentrikat-core.js:30 [SentriKat] SentriKat Core initialized
  sentrikat-core.js:30 [SentriKat] Loading show, count: 1
  sentrikat-core.js:30 [SentriKat] Loading hide, count: 0
  ```
- **Note**: log interni di debug UX, nessun dato sensibile esposto; utili in dev. In production andrebbero silenziati (es. `if (process.env.NODE_ENV !== "production") console.log(...)` oppure gated da `window.SENTRIKAT_DEBUG` flag)
- **Osservazione collaterale**: la versione loggata dalla core JS è **`v1.0.0`** (hardcoded?), mentre `VERSION` file e `/api/health` dicono `1.0.0-beta.2` → terza versione "disallineata" (cfr. [03.5.3]): repo dice beta.2, footer/health dicono beta.2, JS core dice 1.0.0. Tre canali, tre valori diversi.
- **File sospetto**: `app/static/js/sentrikat-core.js`
- **Discovered**: 2026-04-23

### [03.6.8] 🔵 Nessun 302 redirect su `/setup` dopo completamento: l'UI mostra wizard + banner "Setup already completed"

- **Fase**: 03
- **Area**: Setup wizard / routing
- **Tipo**: 🔵 Info
- **Severity**: Low
- **Actual**: dopo il lock del wizard al step 3 (vedi [03.6.3]), visitare `localhost/setup` mostra ancora la card wizard (step 4) con il banner rosso "Setup already completed." — invece di redirezionare a `/login` o `/` con HTTP 302
- **Fix candidato**: il router deve `abort(302, location='/login')` (o `/` se loggato) quando il setup è già stato completato, invece di servire il wizard con un errore inline
- **Discovered**: 2026-04-23

### [03.6.9] Creazione org + admin user + login con credenziali scelte ✅

- **Fase**: 03
- **Area**: Setup wizard / admin user
- **Tipo**: 🟢 OK
- **Credenziali usate (per tracking dei test successivi)**:
  - Org name: (da confermare utente — testuale creata allo step 2)
  - Username: `admin`
  - Email: `sotadenis94@gmail.com`
  - Full Name: `System Administrator`
  - Password: `TestPass123!`
- **Actual**:
  - Step 2 Organization → Create OK
  - Step 3 Admin Account → Create OK, admin promosso automaticamente a super_admin (primo utente on-prem)
  - Login post-setup funzionante; banner/errori su email o password sbagliate mostrati correttamente
- **Discovered**: 2026-04-23

---

## 03.5 — Bug update: conferma VERSION file

### [03.5.3.confirm] Conferma su 3 canali che la versione riportata è `1.0.0-beta.2` anche se il tag è `v1.0.0-beta.6`

- **Conferma di bug [03.5.3]** dopo install effettiva:
  - `Get-Content C:\SentriKat\v1.0.0-beta.6\VERSION` → `1.0.0-beta.2`
  - `/api/health` JSON → `"version":"1.0.0-beta.2"` + header `X-App-Version: 1.0.0-beta.2`
  - Footer UI dopo login → `Powered by SentriKat v1.0.0-beta.2`
  - Bonus inconsistency (vedi [03.6.7]): core JS log → `SentriKat Core v1.0.0` (stringa hardcoded, non legge dal VERSION)
- **Aggiornamento Severity**: resta **High** perché impatta 3 canali visibili al customer (footer, API, log interno) + 1 canale sviluppatore (JS core)
- **Discovered (confirm)**: 2026-04-23

---

*(aggiornamento incrementale — dashboard post-login + esplorazione menu "Platform Operations" da confermare, poi configurazione integrazioni testlab, poi deploy agent)*

---

## 03.7 — Mapping sidebar post-login + approfondimento "Platform Operations"

### [03.7.1] Sidebar on-prem DEMO (super_admin) — mappa completa ✅

- **Fase**: 03
- **Area**: Post-setup / navigation
- **Tipo**: 🟢 OK (mapping)
- **Mappa completa sidebar osservata** (on-prem, primo admin auto-promosso super_admin, edition DEMO):

```
OVERVIEW
  - Dashboard
  - Assignments

INVENTORY
  - Products ▼
    - Products List
    - Endpoints
    - Containers
    - Dependencies
    - Import Queue
    - SBOM Export
    - Exclusions

MANAGEMENT
  - Users & Access ▼
    - All Users
  - Organizations

INTEGRATIONS
  - Integrations ▼
    - Agent Keys
    - Agent Activity
    - Scheduled Reports
    - Issue Trackers

SYSTEM
  - Settings ▼
    - Authentication
    - Alert Management
    - Email (SMTP)
    - SIEM / Syslog
    - System
    - Compliance
    - Appearance
    - License
    - Health Checks
    - System Logs
    - Admin Guide

PLATFORM OPERATIONS          ← SEZIONE SaaS-ONLY, non dovrebbe essere qui
  - Cross-Repo Integration ▼
    - Webhook Events
    - Usage Uploads
```

- **Confronto con SaaS Starter (fase 02 [02.7.3])**:
  - On-prem aggiunge: `Organizations` (multi-tenant), `Scheduled Reports`, `Issue Trackers`, 11 voci in `Settings` (Auth, SIEM/Syslog, System, Compliance, Appearance, License, Health Checks, System Logs, Admin Guide); **manca** `Subscription` (corretto, è SaaS-only); più sezione **PLATFORM OPERATIONS** non prevista.
  - SaaS Starter ha solo `Alert Management / Email & Notifications / Subscription` sotto Settings (3 voci) — feature gating coerente.
- **Discovered**: 2026-04-23

### [03.7.2] 🔴 HIGH — `Webhook Events` page: contenuto 100% SaaS-specific esposto in on-prem

- **Fase**: 03
- **Area**: Platform Operations / mode gating
- **Tipo**: 🔴 Bug
- **Severity**: **High** (consolida [03.6.6]: non è solo menu cosmetic, la pagina è funzionalmente accessibile e mostra copy SaaS-only)
- **URL visitato**: cliccando `Platform Operations → Cross-Repo Integration → Webhook Events`
- **Network**: nessun errore console, endpoint risponde OK
- **Actual — contenuto pagina**:
  ```
  License Webhook Events Received
  Events pushed by the upstream SentriKat-web license server to POST /ap1/license/events.
  Shows the last 0 entries from the idempotency cache (max 200, retention 24h).
  [Back to Super Admin]

  No webhook events received yet. When the upstream license server sends its
  first event (plan change, revocation, suspension, etc.), it will appear here.
  ```
- **Note**: parla esplicitamente di "upstream SentriKat-web license server" che gestisce "plan change, revocation, suspension" — concetti SaaS puri. Su on-prem DEMO/PRO non c'è un upstream license server che manda questi eventi.
- **Discovered**: 2026-04-23

### [03.7.3] 🔴 HIGH — Typo nell'endpoint documentato: `POST /ap1/license/events`

- **Fase**: 03
- **Area**: Platform Operations / Webhook Events / documentazione inline
- **Tipo**: 🔴 Bug
- **Severity**: **Medium** (chiunque copi-incolli questo path per debug/configurazione lo troverà broken; degrada fiducia nel prodotto)
- **Actual**: il testo descrittivo della pagina Webhook Events dice:
  `"Events pushed by the upstream SentriKat-web license server to POST /ap1/license/events"`
  Il path `/ap1/` è evidentemente un **typo** (`ap1` vs `api`).
- **Expected**: `POST /api/v1/license/events` o `POST /api/license/events` (da confermare nel codice)
- **Impatto**:
  - Se questa stringa è solo descrittiva hardcoded → typo da correggere nel template
  - Se è il path effettivo dell'endpoint → funzione probabilmente rotta (ma l'utente non può testare perché è on-prem, non riceve mai webhook dal license server)
- **Fix candidato**: grep `'/ap1/'` nel repo — se appare solo nel template descrittivo è cosmetic; se appare anche in una `@app.route` è broken functionally
- **File sospetto**: `app/templates/super_admin_webhook_events.html` (nome template visto nel mapping originale)
- **Discovered**: 2026-04-23

### [03.7.4] 🔴 HIGH — `Usage Uploads` page: copy parla di "this SaaS" su installazione on-prem

- **Fase**: 03
- **Area**: Platform Operations / mode gating
- **Tipo**: 🔴 Bug
- **Severity**: **Medium-High** (copy hardcoded senza mode detection; confonde/allarmante per customer on-prem che leggono "upstream license server" e pensano che i loro dati siano inviati fuori)
- **URL**: `Platform Operations → Usage Uploads`
- **Network**: nessun errore, pagina carica regolarmente
- **Actual — contenuto pagina**:
  ```
  Usage Metering Uploads
  Hourly usage rollups pushed from this SaaS to the upstream license server at /v1/metrics/usage.
  Runs at minute :05 of every hour under the scheduler leader lock.

  No usage uploads have been performed yet. The metering job runs hourly at minute :05.
  You can trigger it manually with:

      docker compose exec sentrikat python -c "
      from app import create_app
      from app.scheduler import usage_metering_upload_job
      usage_metering_upload_job(create_app())
      "
  ```
- **Issue multipli** in questa singola pagina:
  1. Dice "**from this SaaS**" — ma siamo in `SENTRIKAT_MODE=onpremise`. Copy hardcoded senza detection
  2. Una installazione on-prem DEMO/PRO **non deve** mandare usage rollups "upstream" (privacy/compliance): cosa succede se il job parte? (teoricamente fail perché manca `SENTRIKAT_METRICS_KEY`, ma la pagina suggerisce comunque di lanciarlo)
  3. La pagina **espone comandi tecnici di debug Python** a un super_admin UI. Non è una console: è una feature page. Suggerisce all'utente di eseguire `docker compose exec ... python -c "..."` che richiede shell host access — info da runbook, non da UI customer-facing
- **Privacy concern**: un customer on-prem sensibile (healthcare/finance/classified) leggendo questa pagina potrebbe legittimamente chiedersi: "i miei dati vengono caricati ovunque?" La presenza della voce + copy "pushed to upstream" → problema di trust
- **Fix candidato**:
  - Intero menu `Platform Operations` nascosto quando `SENTRIKAT_MODE != 'saas'` (risolve anche [03.6.6] in un colpo)
  - Se mantenuto, il copy deve distinguere on-prem vs SaaS
  - Il comando CLI debug va in docs/runbook, non in UI
- **Discovered**: 2026-04-23

### [03.7.5] 🔵 Info — `system_settings` table NON contiene chiavi `%setup%`

- **Fase**: 03
- **Area**: Setup state storage / investigation [03.6.3]
- **Tipo**: 🔵 Info
- **Actual**:
  ```sql
  SELECT key, value FROM system_settings WHERE key LIKE '%setup%';
  → (0 rows)
  ```
- **Interpretazione**: il flag `setup_complete` non è in `system_settings`. Potrebbe essere:
  - in un'altra tabella (candidati: `system_state`, `app_state`, `bootstrap`)
  - derivato dall'esistenza di `User` con `role=super_admin` (se esiste almeno 1 → setup considered done)
  - una colonna in `Organization` o un singleton `SetupState`
- **Rilevante per [03.6.3]**: senza conoscere dove risiede il flag, non c'è workaround user-level per sbloccare il wizard. Se è derivato dalla presenza admin → unica via è wipe volumi + re-install.
- **Follow-up TODO (solo lettura, nessun fix)**: quando investigheremo il codice per il report finale, cercare `setup_complete` o `is_setup_done` in `app/models.py` e `app/setup.py` per mappare la sorgente di truth.
- **Discovered**: 2026-04-23

### [03.7.6] Dashboard empty state: banner actionable ben fatti ✅

- **Fase**: 03
- **Area**: Dashboard / empty state
- **Tipo**: 🟢 OK
- **Actual**: in cima alle pagine (presumibilmente globale, non solo dashboard) appaiono 2 banner:
  - **Rosso** (critical): `"No vulnerability data loaded. Run an initial CISA KEV sync to start matching."`
  - **Azzurro** (info): `"No products configured yet. Add products to start vulnerability tracking."` + link cliccabile "Add Products"
- **Valutazione UX**: chiaro, actionable, guida l'utente verso i primi step. Migliore dell'onboarding SaaS che è muto ([02.7.4]).
- **Follow-up TODO**: verificare se i banner sono globali (visibili su ogni pagina finché vero) o solo in dashboard; verificare se il bottone "Run CISA sync" esiste e se `Add Products` porta alla pagina corretta (`/products`?).
- **Discovered**: 2026-04-23

### [03.7.7] 🔵 Nessun errore console su click delle pagine Platform Operations

- **Fase**: 03
- **Area**: Frontend / JS error hygiene
- **Tipo**: 🔵 Info
- **Actual**: utente conferma che cliccando `Webhook Events` e `Usage Uploads` NON ci sono errori in console del browser; le pagine caricano pulite, endpoint risponde 200
- **Note**: è una buona notizia tecnicamente, ma **aggrava [03.6.6]** perché il bug non è solo cosmetico (voce visibile ma endpoint bloccato) — le pagine sono davvero funzionanti e accessibili
- **Discovered**: 2026-04-23

---

*(next: dashboard screenshot attesa dall'utente — poi configurazione integrazioni testlab)*

---

## 03.11 — Integrazioni testlab

### 03.11.1 — SMTP → Mailpit

#### [03.11.1.1] SMTP save + test → feedback verde UI ✅ (pending delivery verification)

- **Fase**: 03
- **Area**: Settings → Email & Alerts → Global SMTP Configuration
- **URL**: `http://localhost/admin/settings` (tab "Email & Alerts")
- **Tipo**: 🟢 OK (UI level) / ⏳ pending verifica consegna
- **Values configured**:
  - SMTP Server: `host.docker.internal`
  - Port: `1025`
  - Username: (empty)
  - Password: (empty — ma UI mostra 8 bullet, vedi [03.11.1.5])
  - From Email: `noreply@sentrikat.local`
  - From Name: `SentriKat Local`
  - Use TLS/STARTTLS: OFF
  - Use SSL: OFF
- **UI feedback**:
  - `Send Test Email` → toast verde (success) in alto a destra, zero errori console
  - `Save SMTP Settings` → toast verde, config persistente dopo navigation (cambiare tab + tornare → valori rimangono)
- **⚠️ Da verificare (ATTENZIONE)**: l'assenza di errori UI NON garantisce che l'email sia arrivata nel Mailpit locale. Possibili esiti:
  - ✅ Email in Mailpit inbox → testlab pipeline funzionante (happy path)
  - ❌ Nessuna email in Mailpit, ma forse `noreply@sentrikat.local` → routata via DNS pubblico e persa (mail server inesistente per quel dominio)
  - ❌ Email partita verso l'inbox reale (`sotadenis94@gmail.com`) → il client SMTP non ha rispettato la config e ha usato fallback (problema di config)
- **Follow-up**: aprire `http://localhost:8025` (Mailpit Web UI) e confermare (→ 03.11.1.2)
- **Discovered**: 2026-04-23

#### [03.11.1.2] Consegna email verificata in Mailpit ✅

- **Fase**: 03
- **Area**: Settings / SMTP / delivery test
- **Tipo**: 🟢 OK
- **URL evidence**: `http://localhost:8025`
- **Actual**:
  - 2 email ricevute in Mailpit inbox (una per ogni click "Send Test Email")
  - From: `"SentriKat Local" <noreply@sentrikat.local>`
  - To: `sotadenis94@gmail.com` (email dell'admin loggato — destinatario di default dei test email, corretto)
  - Subject: `"SentriKat SMTP Test - Configuration Successful"`
  - Body preview: `"✓ SMTP Configuration Test Successful This is a test email from SentriKat vulnerability management system. SMTP Configuration Details: Server: host.docker.internal:1025 From: noreply@sentrikat.local ..."`
- **Conferma pipeline**:
  - ✅ Client SMTP si connette a `host.docker.internal:1025` dal container
  - ✅ Mailpit riceve correttamente
  - ✅ Nessuna consegna verso Internet (`sotadenis94@gmail.com` non è uscito dal laboratorio locale — Mailpit cattura qualunque dominio)
  - ✅ From = `noreply@sentrikat.local` come configurato
  - ✅ To = email admin loggato
- **Discovered**: 2026-04-23

#### [03.11.1.9] 🔵 Nessun throttling/dedup dei test email in UI

- **Fase**: 03
- **Area**: Settings / SMTP / rate limiting UX
- **Tipo**: 🔵 Info
- **Severity**: Low
- **Actual**: due click consecutivi su `Send Test Email` → due email consegnate. Niente cooldown / "Email già inviata di recente, riprova tra X secondi" / dedup lato UI.
- **Impatto**: accettabile (test tool), ma un admin impaziente può flooding la propria casella / Mailpit con decine di test. Se integrato con rate limiting globale del Flask-Limiter ([03.5.4]) potrebbe essere implicitamente limitato in prod.
- **Discovered**: 2026-04-23

#### [03.11.1.10] 🔵 Test email contiene info di config SMTP in plaintext nel body

- **Fase**: 03
- **Area**: Settings / SMTP / test email content / info disclosure
- **Tipo**: 🔵 Info
- **Severity**: Low (scenario di minaccia molto specifico)
- **Actual**: il body della test email include `"SMTP Configuration Details: Server: host.docker.internal:1025 From: noreply@sentrikat.local..."` — la configurazione interna è trasmessa in plaintext via SMTP
- **Threat model**: se la email finisce in mano a terzi (spear-phishing audit, email gateway compromesso, mailbox rubata) l'attaccante scopre hostname interno + porta SMTP del sistema di vuln management (piccolo OSINT)
- **Trade-off**: il body tecnico è utile per debug, quindi conservarlo è giusto. Forse un'opzione "Verbose/Minimal" o ridurre i dettagli a "host+port masked"
- **Discovered**: 2026-04-23

#### [03.11.1.3] 🔁 Conferma bug [02.7.7] anche su on-prem: subtitle pagina "LDAP configuration, SMTP settings, and system options"

- **Fase**: 03
- **Area**: Copy / System Settings header
- **Tipo**: 🔵 Info (cross-ref)
- **Actual**: la pagina System Settings ha titolo `"System Settings"` con sottotitolo hardcoded `"LDAP configuration, SMTP settings, and system options"`, **identico** al SaaS ([02.7.7]).
- **Valutazione on-prem**: sul on-prem DEMO, LDAP, SMTP e system options **sono effettivamente disponibili** → copy meno inappropriato che in SaaS Starter. Comunque resta copy hardcoded non dinamico.
- **Discovered**: 2026-04-23

#### [03.11.1.4] 🔵 Inconsistency nome voce: sidebar dice "Email (SMTP)", tab dice "Email & Alerts"

- **Fase**: 03
- **Area**: Navigation consistency
- **Tipo**: 🔵 Info
- **Severity**: Low (navigation clarity)
- **Actual**:
  - Sidebar: `Settings → Email (SMTP)`
  - Tab bar interno alla pagina: `Email & Alerts`
- **Issue**: lo stesso link porta a due label diverse, l'utente non è sicuro di essere nella sezione giusta
- **Fix candidato**: uniformare a `Email & Alerts` (più accurato perché la pagina probabilmente include anche template alert/digest, non solo SMTP server config)
- **Discovered**: 2026-04-23

#### [03.11.1.5] 🟡 Campo Password SMTP mostra `••••••••` (8 bullet) senza password reale salvata

- **Fase**: 03
- **Area**: Settings / SMTP / UI state
- **Tipo**: 🟡 Warning
- **Severity**: Medium (ingannevole: l'utente pensa di avere una password salvata quando non c'è)
- **Environment**: on-prem DEMO, primo utilizzo della pagina SMTP
- **Steps to reproduce**:
  1. First-time install (nessuna config SMTP precedente, env `SMTP_PASSWORD` vuoto)
  2. Apri Settings → Email & Alerts
- **Expected**: il campo Password è **vuoto** (placeholder "Leave blank to keep existing password" visibile se c'è uno storico, altrimenti vuoto pulito)
- **Actual**: il campo mostra 8 bullet `••••••••` pre-popolati, suggerendo l'esistenza di una password salvata che non c'è. Accanto: helper text "Leave blank to keep existing password. Passwords are encrypted and not shown for security."
- **Root cause ipotesi**:
  - L'input type=password renderizza placeholder come bullet in alcuni browser
  - Oppure il backend restituisce un valore maschera (8 bullet letterali) come sentinel per dire "c'è qualcosa" anche quando non c'è
- **Impatto**:
  - UX: utente potrebbe pensare che password sia configurata da default e non inserire la propria → connessione SMTP fallisce silenziosamente (l'helper text salva, ma è facile da ignorare)
  - Debug confuso: "ho lasciato vuoto, vedo 8 bullet, quindi è salvato qualcosa?"
- **Fix candidato**:
  - Placeholder text che si vede se campo vuoto, non bullet pre-popolati
  - Oppure: distinguere visivamente "no password saved" (campo vuoto) vs "password saved, hidden" (bullet + helper text)
- **File sospetto**: template della pagina Email & Alerts + endpoint GET settings (forse restituisce `"password": "********"` come masked)
- **Discovered**: 2026-04-23

#### [03.11.1.6] 🔵 Nessun campo "Reply-To" visibile nel form SMTP

- **Fase**: 03
- **Area**: Settings / SMTP / fields
- **Tipo**: 🔵 Info
- **Severity**: Low
- **Actual**: il form SMTP ha: Server, Port, Username, Password, From Email, From Name, Use TLS, Use SSL. Non c'è un campo esplicito "Reply-To".
- **Note**: dalla mappatura originale esiste endpoint `/api/settings/email/reply-to` → la feature esiste ma forse è configurata altrove (Alert Management? Email templates?)
- **Follow-up TODO**: esplorare pagina "Alert Management" (visibile in sidebar) per vedere se il Reply-To sta lì
- **Discovered**: 2026-04-23

#### [03.11.1.7] Subtitle "Default SMTP for all orgs. Organizations can override" esposto anche in DEMO single-org ✅ (info)

- **Fase**: 03
- **Area**: Settings / SMTP / copy multi-tenant
- **Tipo**: 🔵 Info
- **Actual**: banner blu al top del form: `"Default SMTP settings for all organizations. Organizations can override these with their own SMTP config."`
- **Valutazione**: in DEMO on-prem c'è di default 1 sola org → copy ridondante ma architetturalmente corretto (la feature multi-tenant è presente anche in DEMO on-prem). Allinea con il fatto che "Organizations" è una voce della sidebar.
- **Discovered**: 2026-04-23

#### [03.11.1.8] Helper text port "587 (TLS) or 465 (SSL)" non include 25/1025/2525 ✅ (info)

- **Fase**: 03
- **Area**: Settings / SMTP / UX guidance
- **Tipo**: 🔵 Info
- **Actual**: sotto il campo Port c'è l'helper "587 (TLS) or 465 (SSL)". Il nostro 1025 (Mailpit) funziona ma non è suggerito.
- **Valutazione**: accettabile (`1025` è dev/testlab, non port production standard). Helper è accurato per uso produzione.
- **Discovered**: 2026-04-23

