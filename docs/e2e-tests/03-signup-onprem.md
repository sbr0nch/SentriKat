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

### Testlab credenziali e mapping (riferimento per tutti i test integrazioni)

**Mailpit** (SMTP capture): `host.docker.internal:1025` SMTP / `http://localhost:8025` Web UI — no auth.

**OpenLDAP** directory tree (da `C:\SentriKat\testlab\ldap-seed\01-users-and-groups.ldif`):

- **Base DN**: `dc=sentrikat-test,dc=local`
- **Bind accounts**:
  - Admin: `cn=admin,dc=sentrikat-test,dc=local` / `admin123` (full access)
  - **Readonly (consigliato per SentriKat bind, least privilege)**: `cn=readonly,dc=sentrikat-test,dc=local` / `readonly123`
- **OU**: `ou=users` (5 users), `ou=groups` (3 groups)
- **Users seedati** (tutti password `password123`):

| uid | cn | mail | gruppo LDAP | role map atteso su SentriKat |
|---|---|---|---|---|
| `admin.user` | Admin User | `admin@sentrikat-test.local` | sentrikat-admins | super_admin / org_admin |
| `it.manager` | IT Manager | `itmanager@sentrikat-test.local` | sentrikat-admins | org_admin |
| `sec.analyst` | Security Analyst | `analyst@sentrikat-test.local` | sentrikat-analysts | manager |
| `viewer` | Read Only Viewer | `viewer@sentrikat-test.local` | sentrikat-viewers | user (read-only) |
| `disabled.user` | Disabled User | `disabled@sentrikat-test.local` | (none, `loginShell=/bin/false`) | da testare: deve essere negato il login |

- **Gruppi** (objectClass `groupOfNames`, member attribute `member`):
  - `cn=sentrikat-admins,ou=groups,...` → members: `admin.user`, `it.manager`
  - `cn=sentrikat-analysts,ou=groups,...` → member: `sec.analyst`
  - `cn=sentrikat-viewers,ou=groups,...` → member: `viewer`
- **User filter consigliato**: `(uid={username})` oppure `(&(objectClass=inetOrgPerson)(uid={username}))`

**Keycloak** (SAML IdP): `http://localhost:8180` admin `admin/admin123`, HTTPS `8443` (da esplorare per realm+client).
**Jira mock** (MockServer): `http://localhost:8080` (host) → container :1080.
**webhook-tester**: `http://localhost:8800`.
**syslog-receiver**: `host.docker.internal:5514` UDP+TCP.
**squid-proxy**: `http://localhost:3128`.
**Dozzle** (log viewer): `http://localhost:9999`.

---

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

---

### 03.11.2 — LDAP → OpenLDAP (testlab)

#### [03.11.2.1] Form LDAP save + test → UI feedback verde ✅

- **Fase**: 03
- **Area**: Settings → Authentication → LDAP / AD Configuration
- **URL**: `http://localhost/admin/settings` (tab "Authentication")
- **Tipo**: 🟢 OK (livello UI, non ancora verificato end-to-end con login utente LDAP)
- **Values configured**:
  - LDAP Server URL: `host.docker.internal`
  - Port: `389`
  - Base DN: `dc=sentrikat-test,dc=local`
  - Bind DN (Service Account): `cn=readonly,dc=sentrikat-test,dc=local`
  - Bind Password: `readonly123` (mascherata 10+ bullet nel form)
  - Search Filter: `(uid={username})`
  - Username Attribute: `uid`
  - Email Attribute: `mail`
  - Use TLS/STARTTLS: OFF
  - Enable Scheduled LDAP Synchronization: ON (Every 24 hours, Last Scheduled Sync: Never)
- **Actions**: Save → verde; Test Connection → verde (dopo save)
- **Discovered**: 2026-04-23

#### [03.11.2.2] 🔴 HIGH — Form LDAP manca completamente della sezione **Group Mapping**

- **Fase**: 03
- **Area**: Settings → Authentication → LDAP / feature completeness
- **Tipo**: 🔴 Bug
- **Severity**: **High** (senza group mapping, la LDAP sync non può assegnare ruoli/organizzazioni agli utenti → feature business critica Pro-grade è monca)
- **Environment**: on-prem DEMO beta.6
- **Steps to reproduce**:
  1. Settings → Authentication → LDAP / Active Directory Configuration
  2. Osservare i campi disponibili
- **Expected** (dalla mappa architetturale repo: `/api/ldap/groups`, `/api/ldap/invite`, `/api/ldap/sync` + `LDAPGroupMapping` model):
  - Sezione dedicata "Group Search" con Group Search Base, Group Filter (`(objectClass=groupOfNames)`), Group Member Attribute (`member`), Group Name Attribute (`cn`)
  - Sezione "Role Mapping" con matrice `LDAP Group → SentriKat Role` (es. `sentrikat-admins → super_admin`)
  - Opzione "Auto-create users on first login"
  - Opzione "Default role (no group match)"
- **Actual**: il form ha **solo** questi campi:
  - Server connection (URL, Port, Bind DN, Bind Password, TLS)
  - User search minimal (Base DN, Search Filter, Username Attribute, Email Attribute)
  - Automatic Synchronization (toggle + interval — ma **sync di cosa?** non è chiaro se sincronizza solo users, anche groups, o mapping)
  - **Niente** group/role mapping
  - **Niente** "auto-create users" toggle esplicito (implicito?)
- **Impatto**:
  - Utenti LDAP che fanno login arrivano nel sistema (si presume) ma **come che ruolo?** Default "user"? Rimangono "pending"?
  - `sentrikat-admins` non viene promosso a super_admin automaticamente — l'admin deve promuovere manualmente ogni utente LDAP via "All Users" → defeats lo scopo della group sync
  - La feature "Scheduled LDAP Synchronization" è esposta ma non è chiaro cosa sincronizzi senza mapping
- **Hint backend presente**: il repo contiene `app/ldap_group_api.py`, `app/ldap_sync.py`, `ldap_group_mapping` model → quindi la feature esiste backend ma **non è collegata a questa pagina UI**
- **Correlato**: [03.11.2.3] sidebar Users & Access non mostra voci LDAP
- **File sospetto**: template della pagina Authentication/LDAP + possibile pagina "LDAP Group Mapping" separata non linkata dalla sidebar
- **Discovered**: 2026-04-23

#### [03.11.2.3] 🔴 HIGH — Sidebar "Users & Access" NON espone voci LDAP/Group dopo config

- **Fase**: 03
- **Area**: Sidebar / feature discoverability
- **Tipo**: 🔴 Bug
- **Severity**: **High** (feature implementata ma irragiungibile dall'utente)
- **Steps to reproduce**:
  1. Config LDAP salvata + test verde (vedi 03.11.2.1)
  2. (opzionale) hard refresh della pagina
  3. Espandi sidebar `MANAGEMENT → Users & Access`
- **Expected** (dalla mappa repo `/api/ldap/users`, `/api/ldap/invite`, `/api/ldap/bulk-invite`, `/api/ldap/groups`):
  - Voce "LDAP Users" (browse/search directory, invite)
  - Voce "LDAP Groups" o "Group Mapping" (map LDAP groups to SentriKat roles)
  - Voce "LDAP Sync" / "Sync Log" (history delle sync)
- **Actual**: utente conferma che `Users & Access` ha SOLO la voce `All Users`. Non appaiono sezioni LDAP-specific.
- **Impatto**:
  - Admin non può sfogliare utenti LDAP per invitarli prima del primo login
  - Non può fare bulk invite via LDAP group membership
  - Non può vedere il sync log per debug
  - La voce `Automatic Synchronization` nel form di config LDAP è disconnessa (no UI per vedere i risultati)
- **Regressione confermata (testimonianza utente)**:
  > "Mi ricordo che c'era una voce del menu che appariva dopo la config LDAP che abbiamo fatto ora, e c'era anche un'altra voce per gestire gli utenti LDAP."
  L'utente (che conosce il prodotto e lo ha già testato in versioni precedenti) conferma empiricamente che in builds precedenti — post-config LDAP — la sidebar mostrava **2 voci aggiuntive** dedicate (LDAP Users management + LDAP Group Mapping). In beta.6 queste voci NON appaiono. Quindi non è solo ipotesi, è **regressione su feature pre-esistente**.
- **Root cause hypothesis (ipotizzata dall'utente)**:
  > "Sono stati modificati o disabilitati o la logica è falsa all'introduzione del SaaS, quando abbiamo messo logiche sulle voci del menu (quando e come devono apparire per SaaS ed on-prem)."
  Plausibile: durante il refactor mode-based gating, le voci LDAP sono state gated con un check sbagliato (es. `{% if saas_mode %}` invece che `{% if ldap_enabled %}`), eliminandole dalla sidebar on-prem.
- **Corroborazione della hypothesis**:
  - [03.6.6]: SaaS-only section `Platform Operations` esposta a on-prem (gating rotto in una direzione — mostra cosa non dovrebbe)
  - [03.11.2.3]: feature LDAP Users/Groups implementata backend + esistente in passato → non in sidebar on-prem (gating rotto nell'altra direzione — nasconde cosa dovrebbe mostrare)
  - Due regressioni **simmetriche** sullo stesso componente (sidebar renderer) — coerente con un unico commit/refactor SaaS gating che ha introdotto entrambe
- **Impatto aggravato**:
  - La feature "Automatic Synchronization" (toggle + 24h interval) è esposta nel form, ma senza group mapping UI sincronizza "niente di utile"
  - Senza group mapping: un utente LDAP che fa login diventa default role → admin deve promuoverlo manualmente → la feature enterprise-grade è monca
  - Per un customer on-prem che ha già 50+ utenti LDAP, è un **blocker** (dovrebbero promuovere a mano 50 utenti)
- **Group mapping obbligatorio/opzionale?**:
  - Design voluto: **opzionale** (senza mapping = tutti default role), ma **la UI di configurazione deve esistere** per chi lo vuole
  - Attualmente: **impossibile configurarlo anche volendo** (campi assenti dal form)
- **Follow-up TODO 03.11.2.3a**: chiedere all'utente hard refresh (Ctrl+F5) per confermare definitivamente. Se persiste, durante il code-reading finale cercare:
  - `{% if saas_mode %}` o `{% if is_saas %}` sulla sidebar template
  - Decorator `@saas_only` / `@requires_saas` su rotte `/admin/ldap-users`, `/admin/ldap-groups`
  - Logica blueprint `ldap_group_api.py` che potrebbe essere condizionalmente registrata
- **File sospetto**: template della sidebar (`app/templates/base.html` o layout component), + blueprint registration di `ldap_api.py` / `ldap_group_api.py` che potrebbero essere gated dietro check mode
- **Discovered**: 2026-04-23

#### [03.11.2.4] 🟡 "Test Connection" funziona solo DOPO aver salvato, non sui valori correnti del form

- **Fase**: 03
- **Area**: Settings → Authentication → LDAP / UX
- **Tipo**: 🟡 Warning
- **Severity**: Medium (UX → costringe a save+rollback manuale in caso di errore config)
- **Steps to reproduce**:
  1. Compila il form con config ipotetica (anche deliberatamente sbagliata)
  2. Click "Test Connection" **senza** aver cliccato prima "Save LDAP Settings"
- **Expected**: la UI testa con i valori CORRENTI nel form (client-side POST di quei values al endpoint `/api/settings/ldap/test`) → ti dice subito se funzionano, senza toccare la config persistita
- **Actual** (riportato dall'utente): il test NON funziona se prima non salvi. Significa che il button Test usa la config persistita nel DB, non quella nel form
- **Impatto UX**:
  - Admin deve salvare config (anche errata) → test → capire errore → salvare di nuovo. Nel frattempo LDAP è "abilitato" con config errata (rischio: utenti LDAP proveranno a loggare con config rotta)
  - Rende debug estenuante: 3-4 iterazioni = 3-4 save + 3-4 test
- **Fix candidato**: fare Test Connection accettare i valori del form come payload POST, stateless, senza dipendere dal DB
- **Discovered**: 2026-04-23

#### [03.11.2.5] 🔵 Ambiguity: campo "LDAP Server URL" accetta URL completo oppure hostname, port separato

- **Fase**: 03
- **Area**: Settings → Authentication → LDAP / form design
- **Tipo**: 🔵 Info
- **Severity**: Low
- **Actual**:
  - Placeholder campo URL: `ldap://dc.example.com:389`
  - Helper text: `"Format: ldap://server:port or ldaps://server:636"`
  - Nello screenshot config funzionante l'utente ha messo `host.docker.internal` **senza** prefix `ldap://` né porta, e Port separato = `389`. Ha funzionato.
- **Issue**: non è chiaro quale sintassi è canonica:
  - Se metto `ldap://host:389` nel primo campo e anche `389` nel secondo, quale vince?
  - Se metto `ldaps://host:636` nel primo, il secondo campo Port è ignorato?
- **Fix candidato**: o il campo URL include tutto (→ rimuovi Port), o il campo URL accetta solo hostname (→ aggiorna placeholder/helper). Attualmente doppia sorgente ambigua.
- **Discovered**: 2026-04-23

#### [03.11.2.6] 🔵 Form LDAP manca di opzioni: Display Name Attribute, Default Role, Auto-create users toggle

- **Fase**: 03
- **Area**: Settings → Authentication → LDAP / feature completeness
- **Tipo**: 🔵 Info
- **Severity**: Low-Medium
- **Missing fields**:
  - `Display Name Attribute` (per popolare SentriKat User.full_name; senza questo probabilmente fallback a `cn` o `uid`)
  - `Default Role` (se no group match, che ruolo assegnare)
  - `Auto-create users on first login` toggle (comportamento implicito, non controllabile)
  - `Use Pagination` (per directory molto grandi → `ldap3` lo supporta)
  - `Connection Timeout` / `Read Timeout`
- **Discovered**: 2026-04-23

#### [03.11.2.7] 🔵 Testo info banner "LDAP Authentication Setup" dichiara un comportamento implicito

- **Fase**: 03
- **Area**: Settings → Authentication → LDAP / UX banner
- **Tipo**: 🔵 Info
- **Actual**: banner blu in cima alla pagina LDAP dice:
  `"LDAP Authentication Setup: Configure connection to your Active Directory/LDAP server. LDAP users cannot be created directly — they are discovered when they log in. You need a service account with read permissions to search for users in your directory."`
- **Osservazione**: il banner **implicitamente** conferma che gli utenti vengono auto-create on login (`discovered when they log in`) → meglio avere un toggle esplicito + log esplicito "Created 1 new user via LDAP"
- **Aggrava [03.11.2.2]**: senza group mapping UI, se l'utente è "discovered" al login, che ruolo riceve? Il banner non lo dice
- **Discovered**: 2026-04-23

#### [03.11.2.8] 🔵 Log backend `ldap` vuoto dopo save/test

- **Fase**: 03
- **Area**: Logs / debugging
- **Tipo**: 🔵 Info
- **Actual**: `docker compose logs --tail 50 sentrikat | Select-String -Pattern "ldap"` dopo save+test restituisce solo la riga di boot (`Log files: application.log, error.log, access.log, ldap.log, security.log, audit.log, performance.log`). Nessun log applicativo di LDAP bind/test/save.
- **Possibili cause**:
  - I log LDAP finiscono nel file dedicato `/var/log/sentrikat/ldap.log` (non catturato da `docker compose logs` che legge solo stdout/stderr del process principale)
  - Il log level di LDAP è troppo alto (WARNING+) e i success non si vedono
- **Follow-up TODO**: entrare nel container e tailare `ldap.log` direttamente:
  ```powershell
  docker compose -p v100-beta6 exec sentrikat tail -n 50 /var/log/sentrikat/ldap.log
  ```
- **Discovered**: 2026-04-23

#### [03.11.2.10] 🟡 Sezione LDAP nascosta dopo save, richiede workaround (refresh + switch tab + refresh) per ri-vedere

- **Fase**: 03
- **Area**: Settings → Authentication / UI accordion / persistence
- **Tipo**: 🟡 Warning (UX disastroso ma workaround esiste)
- **Severity**: Medium-High (admin che pensa di aver "rotto" la config può essere spinto a reinstallare)
- **Environment**: on-prem DEMO beta.6
- **Steps to reproduce**:
  1. Config LDAP salvata + test verde (03.11.2.1)
  2. Naviga su altro tab (es. Email & Alerts)
  3. Torna su Authentication
- **Expected**: la sezione "LDAP / Active Directory Configuration" rimane visibile, cliccabile, modificabile
- **Actual (conferma utente: "No era sparita, ho dovuto refreshare tutto e cambiare tab e refreshare per vedere la sezione LDAP")**:
  - La sezione LDAP **scompare** dalla pagina Authentication dopo la prima navigazione via
  - Per ri-aprire la pagina LDAP servono: Ctrl+F5 hard refresh → switch a un altro tab → switch back → hard refresh di nuovo
  - Comportamento **non-reproducible con singolo refresh**
- **Impatto operativo**:
  - Admin che vuole modificare bind password / filter / URL non sa come accedere alla config salvata → può essere portato a ricreare tutto da zero
  - In scenari di incident response (es. LDAP server migrato) l'admin non può aggiornare la config senza questi workaround
  - Feature di config esiste lato backend (`/api/settings/ldap`) ma UI non la espone in modo consistente
- **Rafforza cluster regressioni [03.11.2]**:
  - La logica di render dell'accordion Authentication ha bug: LDAP section hidden dopo interazione con SAML (o dopo save stesso)
  - Coerente col pattern "refactor mode-gating ha rotto le UI LDAP": form incompleto (03.11.2.2), sidebar voci sparite (03.11.2.3), section nascosta (03.11.2.10), login bloccato downstream (03.11.2.9)
- **File sospetto**: template della pagina Authentication (JS toggle per show/hide section) — probabilmente un flag "shown when fresh / hidden when configured" invertito, o CSS `display: none` che non viene rimosso
- **Discovered**: 2026-04-23 — confermato utente

---

### 03.11.3 — SAML → Keycloak (testlab)

#### [03.11.3.1] SAML save + test → UI feedback verde ✅

- **Fase**: 03
- **Area**: Settings → Authentication → SAML Single Sign-On
- **URL**: `http://localhost/admin/settings` (tab "Authentication" → section SAML)
- **Tipo**: 🟢 OK (livello UI, login SSO bloccato da 03.11.3.2)
- **Values configured**:
  - Enable SAML SSO: ON
  - SP Entity ID: `http://localhost/api/saml/metadata` (pre-compilato, match col client Keycloak)
  - ACS URL: `http://localhost/saml/acs`
  - IdP Metadata URL: `http://host.docker.internal:8180/realms/sentrikat-test/protocol/saml/descriptor`
  - Default Organization: org creata nel setup wizard
  - Auto-provision new users: ON
  - Update user info on login: ON
  - Attribute Mapping: default (Microsoft/ADFS-style claims)
- **Actions**: Save → verde; Test Configuration → verde
- **Discovered**: 2026-04-23

#### [03.11.3.2] 🔴 HIGH — Login SSO "pending forever", SAML AuthnRequest non arriva a Keycloak

- **Fase**: 03
- **Area**: SAML login flow / docker network routing
- **Tipo**: 🔴 Bug (di UX/documentazione, non di auth core)
- **Severity**: **High** (il login SSO **non funziona** dopo config corretta; l'utente non sa perché)
- **Environment**: Docker Desktop Windows, `host.docker.internal` usato per riferirsi al host dal container
- **Steps to reproduce**:
  1. Config SAML salvata con `IdP Metadata URL = http://host.docker.internal:8180/realms/sentrikat-test/protocol/saml/descriptor`
  2. Logout
  3. Click "Login with SSO"
- **Expected**: browser rediretto a Keycloak login page, dopo login torna a SentriKat
- **Actual**:
  - Browser console vuoto (no error)
  - Network tab mostra sequenza:
    ```
    login 200 (8.5 kB)
    logo 302 redirect
    status 200
    login 302 redirect
    saml?SAMLRequest=fZJbj9MwEIXf...&RelayState=%2F   → PENDING FOREVER
    ```
  - La richiesta `saml?SAMLRequest=...` (che il browser deve inviare a Keycloak) rimane in **pending** = browser non riesce a risolvere l'hostname della destinazione
- **Root cause identificata** (non un bug di auth, è una trappola di networking):
  - L'IdP metadata è stato fetchato dal container SentriKat via `host.docker.internal:8180` → Keycloak restituisce metadata XML con `Location="http://host.docker.internal:8180/realms/..."` (perché Keycloak genera URL basati sul `Host` header ricevuto)
  - SentriKat salva questi URL come `SingleSignOnService Location` nel suo config
  - Quando il browser fa il redirect SAML, tenta di raggiungere `http://host.docker.internal:8180/realms/...` — **ma `host.docker.internal` è un DNS resolver interno di Docker Desktop**, il browser Windows non lo conosce → timeout silenzioso (pending)
- **Impatto**:
  - Tutti i customer che installano SentriKat su Docker Desktop + Keycloak/ADFS/Okta su docker-network condivisa subiranno questo bug senza capire perché
  - Documentazione SentriKat non avverte di questa trappola
  - Il form IdP Metadata accetta 1 solo campo → impossibile distinguere "URL per fetch metadata (backend)" vs "URL che il browser userà (frontend)"
- **Soluzioni possibili (nessuna richiede fix del prodotto)**:
  - **Workaround A (rapido, usiamo per test)**: scaricare l'XML metadata dal browser (`http://localhost:8180/realms/sentrikat-test/protocol/saml/descriptor` — dal punto di vista del browser Windows) e **incollarlo** nel form SentriKat come XML invece che URL. Gli URL dentro l'XML saranno `localhost:8180/...` → browser può risolvere
  - **Workaround B**: configurare Keycloak con `KC_HOSTNAME=localhost` in modo che generi sempre URL con `localhost:8180`
  - **Workaround C**: creare un docker network condiviso `testlab_default + sentrikat_default` ed entrambi usare `keycloak:8080` come hostname (ma il browser non vedrebbe comunque `keycloak:8080`)
- **Fix candidato (per future-fix)**:
  - Il form IdP Metadata dovrebbe offrire 2 input: "URL to fetch metadata from (server-side)" + "Public URL of IdP (browser-facing)". Se diversi, SentriKat riscrive gli URL del metadata con il secondo prima di salvare
  - In alternativa: documentare chiaramente nella UI che "se usi un hostname non pubblico (es. host.docker.internal, keycloak, docker-compose service name), il SAML SSO non funzionerà via browser"
- **Discovered**: 2026-04-23

#### [03.11.3.3] 🔵 Info — Keycloak testlab client SAML configurato con `RSA_SHA1` (deprecato)

- **Fase**: 03
- **Area**: Testlab config / signature algorithm
- **Tipo**: 🔵 Info (non è bug SentriKat, è setup testlab)
- **Actual** (dal Keycloak client "SentriKat SAML" → Signature and Encryption):
  - Signature algorithm: `RSA_SHA1`
  - Sign documents: ON, Sign assertions: ON
  - Canonicalization: EXCLUSIVE
- **Nota security**: SHA-1 è considerato deprecato per firme digitali (NIST deprecation 2011). SHA-256 raccomandato per SAML production
- **Azione**: **non modificare ora** — potenzialmente inclusiva per testare che SentriKat gestisca SHA1 senza warning. Quando testiamo SAML production-grade, settare `RSA_SHA256` su Keycloak client e verificare che SentriKat validi correttamente
- **Discovered**: 2026-04-23

#### [03.11.3.4] 🔵 Info — Client SAML Keycloak: Name ID format=`username`, Force POST binding, Include AuthnStatement

- **Fase**: 03
- **Area**: Testlab SAML client config / mappatura
- **Tipo**: 🔵 Info
- **Actual (SAML capabilities nel client Keycloak):**
  - Name ID format: `username` (il SAML Response userà `uid` come NameID; coerente con LDAP mapping)
  - Force name ID format: ON
  - Force POST binding: ON (browser farà POST, non REDIRECT — buona pratica per assertion signing)
  - Force artifact binding: OFF
  - Include AuthnStatement: ON (needed for proper SAML response)
  - Include OneTimeUse Condition: OFF (OK per sessione SSO multi-use)
- **Valutazione**: config del testlab è sensata per testing. Username-based NameID è OK per mapping su `admin.user`, `sec.analyst` ecc.
- **Discovered**: 2026-04-23

#### [03.11.3.5] 🔵 Info — Realm Keycloak signing key `RS256` (RSA) attiva e valida fino al 2036

- **Fase**: 03
- **Area**: Testlab realm keys
- **Tipo**: 🔵 Info
- **Actual** (dal Keycloak realm sentrikat-test → Keys tab):
  - 4 chiavi attive:
    - AES OCT (aes-generated) — ENC
    - RSA-OAEP (rsa-enc-generated) — ENC — valid to 2036-02-22
    - HS512 OCT (hmac-generated-hs512) — SIG
    - **RS256 RSA (rsa-generated) — SIG** — valid to 2036-02-22
  - La chiave RS256 è quella usata per firmare SAML assertions (rilevante per [03.11.3.3])
- **Discovered**: 2026-04-23

#### [03.11.3.6] Keycloak `sentrikat-test` realm users presenti e match con OpenLDAP ✅

- **Fase**: 03
- **Area**: Testlab parity LDAP↔Keycloak
- **Tipo**: 🟢 OK
- **Actual**: il realm Keycloak `sentrikat-test` ha gli stessi 5 utenti dell'OpenLDAP (admin.user, disabled.user [Disabled badge], it.manager, sec.analyst, viewer). Stessa email per user. Parity utile: potremo testare lo stesso utente via LDAP login vs SAML login per confrontare role mapping e user provisioning
- **Discovered**: 2026-04-23

#### [03.11.3.7] SAML login SSO happy path funziona (con workaround XML-paste per 03.11.3.2) ✅

- **Fase**: 03
- **Area**: SAML login flow / dim 1 happy path
- **Tipo**: 🟢 OK
- **Actual**:
  - Utente scarica metadata XML dal browser su `http://localhost:8180/realms/sentrikat-test/protocol/saml/descriptor` (tutti gli URL dentro sono `localhost:8180`, non `host.docker.internal`)
  - Paste XML nel form IdP Metadata di SentriKat, Save + Test → verde
  - Logout + click "Login with SSO"
  - Browser rediretto correttamente a Keycloak login `http://localhost:8180/realms/sentrikat-test/protocol/saml`
  - Login con utente Keycloak (password pre-configurata)
  - Redirect a SentriKat dashboard → login completo
- **Evidence XML metadata rilevante**:
  - `entityID="http://localhost:8180/realms/sentrikat-test"`
  - `SingleSignOnService Location="http://localhost:8180/realms/sentrikat-test/protocol/saml"` (HTTP-POST + HTTP-Redirect)
  - X509 certificate embedded
  - NameID formats supportati: persistent, transient, unspecified, emailAddress
- **Discovered**: 2026-04-23

#### [03.11.3.8] Auto-provision new user at first SAML login ✅

- **Fase**: 03
- **Area**: SAML / user provisioning / dim 3 CRUD
- **Tipo**: 🟢 OK
- **Actual**: utente SAML sconosciuto al primo login viene **creato automaticamente** nel DB SentriKat. Verificato:
  - Admin locale va in `Users & Access → All Users` e vede il nuovo utente presente (nome + email dall'assertion SAML)
  - Role default = "user" (ruolo minimo, coerente con il toggle "Auto-provision new users: ON" salvato)
- **Differenza marcata con LDAP**:
  - SAML: user auto-created, admin può poi promuoverlo post-login
  - LDAP: user NON auto-created fino a invite/accept (03.11.2.9), e la UI per inviting è sparita (03.11.2.3)
  - Stessa backend logic esiste (`provisioning.py`), ma esposizione UI asimmetrica → un'altra evidenza che la regressione ha colpito LDAP più pesantemente di SAML
- **Discovered**: 2026-04-23

#### [03.11.3.9] 🔵 Info — Sidebar utente SAML con role default ("user") = menu minimo

- **Fase**: 03
- **Area**: Post-login / role-based sidebar / dim 4 role-based access
- **Tipo**: 🔵 Info (prima parte della mappatura sidebar per role)
- **Actual** (screenshot 2 utente):
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
  (no MANAGEMENT, no INTEGRATIONS, no SYSTEM, no PLATFORM OPERATIONS)
  ```
- **Valutazione vs super_admin sidebar [03.7.1]** (che ha TUTTE le sezioni):
  - ✅ Un utente "user" non vede `MANAGEMENT` (niente "Users & Access", niente "Organizations") → corretto
  - ✅ Non vede `INTEGRATIONS` (Agent Keys, Agent Activity, Scheduled Reports, Issue Trackers) → corretto
  - ✅ Non vede `SYSTEM` (Settings tab → Auth, Alerts, License, ecc.) → corretto
  - ✅ Non vede `PLATFORM OPERATIONS` → corretto (bug [03.6.6] viene automaticamente mitigato per non-super-admin — buono!)
  - ❓ Vede completo `INVENTORY → Products` (tutte le sub-voci) → coerente con role "user read-only" solo se poi le azioni CRUD sono gated lato pulsanti/endpoint (da verificare cliccando su Products List se appare "Create Product" button)
- **Discovered**: 2026-04-23

#### [03.11.3.10] Admin cambio ruolo utente SAML → sidebar si espande (role-based gating funziona) ✅

- **Fase**: 03
- **Area**: Users & Access / role update / dim 3 CRUD + dim 4 Role-based
- **Tipo**: 🟢 OK
- **Actual**: admin locale modifica ruolo dell'utente SAML appena creato da "user" a "org_admin":
  - Sidebar dopo promotion (screenshot 3) aggiunge sezione:
    ```
    INTEGRATIONS
      - Integrations ▼
        - Agent Keys
        - Agent Activity
    ```
  - Le voci `Products` (tutte le sub) sono sempre visibili — quindi sono "base" a ogni role ≥ user
  - Dopo promotion org_admin, l'utente dovrebbe vedere anche `Users & Access`, `Organizations`, `Settings` submenus → **da verificare** nel next test (utente non ha screenshot delle sezioni sotto)
- **Inference sulla matrix role→menu**:
  - `user` → OVERVIEW + INVENTORY
  - `manager` → + ??? (da scoprire)
  - `org_admin` → + INTEGRATIONS (parziale, forse di più)
  - `super_admin` → + MANAGEMENT + INTEGRATIONS completi + SYSTEM + PLATFORM OPERATIONS (bug)
- **Follow-up TODO**: dopo aver cambiato role a `org_admin`, fare refresh completo e catturare sidebar intera; ripetere con `manager`; completare matrix
- **Discovered**: 2026-04-23

#### [03.11.3.11] 🔵 Info — Sequence network SAML login con errori iniziali poi successi

- **Fase**: 03
- **Area**: SAML login / network trace
- **Tipo**: 🔵 Info
- **Actual** (dal first screenshot): durante i tentativi di login SSO sono visibili:
  - Prima richiesta `saml?SAMLRequest=...` → `(failed)` 0.0 kB, 6.91 s — coerente con tentativo verso `host.docker.internal` che il browser non risolve → timeout
  - Richieste successive `saml?SAMLRequest=...` → `(cancel...)` / `(failed)`
  - Altre `saml?SAMLRequest=...` successivo a paste XML metadata → riuscite (non evidenziate in rosso)
- **Valutazione**: coerente col workaround applicato (prima host.docker.internal fallisce, dopo XML paste con localhost funziona). Rafforza [03.11.3.2]
- **Discovered**: 2026-04-23

#### [03.11.3.12] Role→Sidebar matrix on-prem DEMO completa ✅ + osservazione `manager == org_admin`

- **Fase**: 03
- **Area**: Role-based access / sidebar gating / dim 4
- **Tipo**: 🟢 OK (matrix raccolta) + 🔵 Info (osservazione manager vs org_admin)
- **Matrix raccolta** (on-prem DEMO beta.6, stesso utente SAML con role diversi):

| Role | OVERVIEW (Dashboard, Assignments) | INVENTORY ► Products (full submenu) | INTEGRATIONS ► (Agent Keys, Agent Activity) | MANAGEMENT ► (Users & Access, Organizations) | SYSTEM ► (Settings, License, Logs, ecc.) | PLATFORM OPERATIONS (Cross-Repo) |
|---|---|---|---|---|---|---|
| **user / viewer** | ✅ | ✅ | ❌ | ❌ | ❌ | ❌ |
| **manager** | ✅ | ✅ | ✅ | ❌ | ❌ | ❌ |
| **org_admin** | ✅ | ✅ | ✅ | ❌ | ❌ | ❌ |
| **super_admin** (local first-install) | ✅ | ✅ | ✅ (+ Scheduled Reports + Issue Trackers) | ✅ | ✅ (11 voci) | ✅ (bug [03.6.6]) |

- **Osservazione #1 — `manager == org_admin` identico in sidebar**:
  - Nessuna differenza visibile in sidebar tra i due role. Se c'è differenza tra `manager` e `org_admin` deve essere solo **permissions dentro le stesse pagine** (es. bottone "Create Product" visibile a org_admin ma non a manager? da verificare)
  - Potenziale UX confusion: se l'admin promuove un utente da manager a org_admin e la sidebar non cambia, l'utente non percepisce l'upgrade
  - Follow-up TODO: testare azioni CRUD dentro `/products` con role=manager vs role=org_admin per verificare differenziazione effettiva
- **Osservazione #2 🔵 — `org_admin` non vede MANAGEMENT né SYSTEM**:
  - Un "organization admin" teoricamente dovrebbe poter gestire almeno gli utenti della propria org (MANAGEMENT → Users & Access) e alcune settings org-scoped (SMTP per-org, branding per-org)
  - Su on-prem la scelta di nascondere tutto a org_admin è legittima perché tutto è gestito dal super_admin; ma in **SaaS mode** dove ogni tenant è gestito dal proprio org_admin, questo diventa un blocker: l'org_admin non può invitare utenti
  - Da cross-verificare in fase 14 (SaaS-specific)
- **Discovered**: 2026-04-23

#### [03.11.3.13] SAML user state transitions: Disable / Delete funzionano ✅

- **Fase**: 03
- **Area**: Users & Access / dim 5 state transitions su SAML user
- **Tipo**: 🟢 OK
- **Actual**:
  - Azioni disponibili per utente SAML in All Users: **Delete** e **Block/Disable** (toggle enabled/disabled)
  - Entrambe testate dall'utente e funzionanti ("funzionano entrambe")
  - NON presente azione "Force password change" → **corretto** (password gestita da Keycloak, SentriKat non può forzare change — UI la nasconde invece di esporre azione non funzionante)
  - NON presenti azioni più avanzate (ban, quarantena, force 2FA) → ragionevole subset
- **Implicit confirmation**: dopo disable l'utente non può più loggare (atteso, confermato dall'utente "tutto il resto sembra configurato correttamente")
- **Differenza intelligente vs utente locale**: per un utente locale SentriKat mostra anche "Force password change" + reset email; per SAML user queste azioni sono correttamente nascoste → design role-aware
- **Follow-up TODO**: test esplicito che login SSO di un utente disabled sia rifiutato con messaggio chiaro (non silent failure) + verificare che il DB abbia `is_active=False` o flag equivalente
- **Discovered**: 2026-04-23

#### [03.11.3.15] 🔵 UX — Popup di conferma "Permanent deletion user" con stile testo non formattato

- **Fase**: 03
- **Area**: Users & Access / confirmation dialog / UX polish
- **Tipo**: 🔵 Info (UX)
- **Severity**: Low (funziona ma visivamente scadente)
- **Actual**: durante il delete dell'utente SAML, il popup di conferma "permanent deletion" mostra testo **non formattato / stile grezzo** (probabilmente `window.confirm()` browser-native o modal con CSS non applicato)
- **Atteso**: modal branded SentriKat con stile coerente (bordi, typography Inter, colori palette, bottone rosso "Delete" / grigio "Cancel")
- **Fix candidato**:
  - Sostituire `window.confirm()` con modal Bootstrap (già presente nei vendor assets `/app/static/vendor/bootstrap/`)
  - O componente React/Vanilla custom con stile brand
- **Discovered**: 2026-04-23

#### [03.11.3.14] SAML complete (dim 1+3+4+5) ✅ — passaggio a Jira

- **Tipo**: 🟢 OK (area conclusa)
- **Riassunto**: 1 bug High (docker network trap [03.11.3.2]), 4 info testlab config, zero regressioni strutturali
- **Discovered**: 2026-04-23

---

### 03.11.5 — Custom Webhook → webhook-tester (testlab)

#### [03.11.5.1] Webhook form rendering OK ✅

- **Fase**: 03
- **Area**: Settings / Issue Trackers / Custom Webhook
- **URL**: `Settings → Issue Trackers → Custom Webhook` (stessa pagina di Jira — è parte del tab multi-tracker)
- **Tipo**: 🟢 OK (rendering)
- **Actual**:
  - Enabled Issue Trackers: ✅ Custom Webhook
  - Tip: "Use webhooks to integrate with Linear, Asana, Monday.com, or any system that accepts HTTP requests."
  - Campi:
    - Webhook URL: `http://host.docker.internal:8800/b300300c-553d-49c2-a0d9-f045e32cbc57` (generato da webhook-tester)
    - HTTP Method: dropdown `POST` (default)
    - Authentication: dropdown `None`
    - Auth Value: (disabled se Authentication=None)
  - Helper text: "Payload includes: title, description, priority, labels, vulnerability details, and product info."
  - Buttons: Save Settings | Test Connection
- **Discovered**: 2026-04-23

#### [03.11.5.2] ⏸️ BLOCKED — Webhook save/test bloccati dalla stessa policy SSRF di Jira [03.11.4.5]

- **Fase**: 03
- **Area**: Custom Webhook / save test
- **Tipo**: ⏸️ Test bloccato (stessa causa di 03.11.4.5)
- **Environment**: `FLASK_ENV=production`, `ALLOW_PRIVATE_URLS=true` (ignorato in prod)
- **Actual**:
  - `POST /api/settings/batch 400 (BAD REQUEST)` al Save
  - `POST /api/integrations/issue-tracker/test 500 (INTERNAL SERVER ERROR)` al Test Connection (vedi bug separato [03.11.5.3])
  - Log backend ripete messaggio SSRF hardening in production
- **Conferma**: la policy SSRF si applica uniformemente a TUTTI gli integration HTTP outbound (Jira + Webhook + presumibilmente anche GitHub/GitLab/YouTrack da testare). Non è bug specifico Jira — è system-wide
- **Status**: bloccato come 03.11.4.5, stesso workaround (switch a `FLASK_ENV=development`)
- **Discovered**: 2026-04-23

#### [03.11.5.3] 🔴 HIGH — Test Connection webhook risponde `500 INTERNAL SERVER ERROR` (should be 4xx con errore strutturato)

- **Fase**: 03
- **Area**: Integrations / test connection / error handling
- **Tipo**: 🔴 Bug
- **Severity**: **High** (500 = eccezione non gestita lato server, non errore atteso; esposizione potenziale di stack trace o dettagli interni)
- **Environment**: on-prem DEMO prod beta.6
- **Steps to reproduce**:
  1. Config webhook con URL privato `http://host.docker.internal:8800/...`
  2. Click "Test Connection"
- **Expected**: response HTTP **4xx** (es. 400 con `{"error":"private_url_blocked","message":"Target URL is on private network..."}`) — error handling strutturato, coerente con la validation che al save ritorna 400
- **Actual**:
  - Console: `POST http://localhost/api/integrations/issue-tracker/test 500 (INTERNAL SERVER ERROR)`
  - Nessun messaggio chiaro all'utente lato UI (o messaggio generico)
- **Issue**: mentre il Save ritorna correttamente 400 + toast con messaggio, il Test ritorna 500 senza messaggio. Significa che l'endpoint `/test` lancia l'eccezione SSRF ma **non la cattura** come fa l'endpoint di save. Error handling inconsistente tra endpoint dello stesso modulo
- **Impatto**:
  - UX: utente clicca Test e vede errore generico / solo in console → non capisce perché
  - Security: un 500 può esporre stack trace in dev mode; in prod idealmente dovrebbe loggare e ritornare 400 / 500 generico con `Sentry ID` per debug
- **Fix candidato**: wrap di `/api/integrations/issue-tracker/test` con try/except che catturi `SSRFError` (o equivalente) e restituisca 400 strutturato
- **Discovered**: 2026-04-23

#### [03.11.5.4] 🟡 Warning — log CRITI ripetuto per richiesta invece di 1 volta al boot

- **Fase**: 03
- **Area**: Logging hygiene
- **Tipo**: 🟡 Warning
- **Severity**: Low-Medium (log noise, potenziale alert fatigue su SIEM)
- **Actual** (dai log):
  ```
  CRITI [app.network_security] SECURITY WARNING: ALLOW_PRIVATE_URLS is enabled in production! This disables SSRF protection. Ignoring the setting.
  CRITI [app.network_security] SECURITY WARNING: ALLOW_PRIVATE_URLS is enabled in production! This disables SSRF protection. Ignoring the setting.
  CRITI [app.network_security] SECURITY WARNING: ALLOW_PRIVATE_URLS is enabled in production! This disables SSRF protection. Ignoring the setting.
  ...  (8 volte, probabilmente 1 per ogni chiamata validate_url)
  ```
- **Issue**: il warning è loggato a CRITI level ogni volta che viene invocata la validation, invece che **una volta sola al boot** come stato di config
- **Impatto**:
  - SIEM forwarding genera 1 alert per ogni integration test → alert storm
  - Log files saturi di righe identiche → mascherano altri eventi
- **Fix candidato**: log al boot (in `create_app()`) se config contradditoria, poi silent in runtime — oppure usare logging rate-limiter interno
- **Discovered**: 2026-04-23

---

### 03.12 — Agent deployment + inventory

#### [03.12.1] Create Agent API Key form — ricco, ben strutturato ✅

- **Fase**: 03
- **Area**: Integrations → Agent Keys / CRUD Create
- **URL**: `http://localhost/admin/integrations/agent-keys` (path da confermare) → "Create Agent API Key" modal
- **Tipo**: 🟢 OK (form rendering + feature completeness)
- **Campi osservati**:
  - **Key Name** (text) — es. "Test Windows Agent"
  - **Key Type** (dropdown) — `Client` / `Server`. Helper: "Classifies endpoints and software reported by this key. Use 'Server' for infrastructure and 'Client' for workstations/desktops."
  - **Primary Organization** (dropdown) — "Acme Corp." (org creata al setup)
  - **Additional Organizations** (OPTIONAL) — helper: "Software reported by this agent will also appear in these organizations (without mixing data between them)" — feature multi-tenant fine-grained
  - **Max Assets** (number, default 0 = unlimited)
  - **Expires** (date) — "Leave empty for no expiration"
  - **Scan Capabilities** (3 toggle, tutti ON di default):
    - OS Packages: "Scan installed operating system packages and software"
    - Extensions: "Scan browser extensions (Chrome, Firefox, Edge), IDE plugins (VS Code, JetBrains), and more"
    - Code Dependencies: "Scan code libraries and dependencies (pip, npm, cargo, gem, go, composer)"
  - **Auto-approve new products** (toggle, OFF default):
    - "When enabled, software reported by agents using this key will be added directly to your inventory. When disabled, new products go to the Import Queue for manual review first."
- **Valutazione positiva**:
  - 3 Scan Capabilities separabili → fine control per compliance/privacy (es. disabilitare Extensions se l'agent è su macchina clinica con regolamento stretto)
  - Import Queue flow → governance on new products prima di inventory pollution
  - Key Type Client/Server → classificazione asset immediata
  - Max Assets limit → prevenire key leak abuse
  - Expiry date → best practice security (token rotation)
- **API Key generata**: `sk_agent_4ApEu7_c80X0LsSXRhGorBr86adftcyZN7ka51MEJWg` (prefix `sk_agent_` identifica il tipo — buona practice)
- **Discovered**: 2026-04-23

#### [03.12.2] 🔵 Script agent Windows — nome file `sentrikat-agent.ps1` (no OS suffix)

- **Fase**: 03
- **Area**: Agent download / filename
- **Tipo**: 🔵 Info (rectification)
- **Actual**: utente conferma che il file scaricato si chiama `sentrikat-agent.ps1`, non `sentrikat-agent-windows.ps1` come nel repo
- **Interpretazione**: il server probabilmente serve uno script generico `.ps1` (per tutti i Windows) / `.sh` (per Linux+macOS). Il contenuto differisce in base a OS detection client-side o server-side (query param ?platform=windows)
- **Note**: coerente con practice tipiche per script di deploy, non è bug
- **Discovered**: 2026-04-23

#### [03.12.3] 🔵 Date picker "Expires" — placeholder in TEDESCO (`tt.mm.jjjj`) su sito EN-only

- **Fase**: 03
- **Area**: Agent Keys / i18n / HTML5 date input localization
- **Tipo**: 🔵 Info (probabile behavior browser nativo)
- **Severity**: Low (UX minore)
- **Environment**: Chrome DE del utente
- **Actual**: il campo "Expires" del form Create Agent API Key mostra placeholder `tt.mm.jjjj` (formato tedesco dd.mm.yyyy con wildcard "tt" per Tag, "mm" per Monat, "jjjj" per Jahr)
- **Ipotesi root cause**: `<input type="date">` HTML5 localizza il placeholder **secondo la locale del browser** (stesso pattern di [02.2.1] tooltip validation in DE su Chrome DE). Il sito SentriKat non imposta esplicitamente il placeholder in EN
- **Conferma cluster Chrome DE**: già 3 occorrenze di localizzazione tedesca in un sito EN-only → evidence che la locale browser utente influenza pesantemente la UX
- **Fix candidato (se si vuole uniformare)**: settare `<input type="date" placeholder="YYYY-MM-DD">` esplicito, oppure usare un date picker JS che ignora locale browser
- **Non blocca**: funzionalità intatta, solo UX incoerente
- **Discovered**: 2026-04-23

#### [03.12.4] 🟢 Security default: agent Windows script enforca HTTPS per ServerUrl ✅

- **Fase**: 03
- **Area**: Agent script / security defaults
- **Tipo**: 🟢 OK (positive security posture)
- **Actual**: al run `powershell -ExecutionPolicy Bypass -File .\sentrikat-agent.ps1 -Install` senza override → errore chiaro:
  ```
  ERROR: ServerUrl must use HTTPS. Use -AllowHttp to override (NOT recommended).
  ```
- **Valutazione**:
  - ✅ Default sicuro: HTTPS mandatory per proteggere API key + inventory data sniffing
  - ✅ Messaggio chiaro con indicazione del flag override
  - ✅ Warning "NOT recommended" sul flag → l'admin è esplicitamente informato del rischio
- **Workaround per test locale (sentrikat gira su http://localhost senza cert)**: aggiungere `-AllowHttp` al comando (accettabile in test env, non in prod)
- **Follow-up TODO 03.12.4a**: verificare in fase 07/sicurezza che l'API key NON venga esposta in URL query params (deve essere header `X-Agent-Key`) e che il body `POST /api/agent/inventory` sia compresso/minimale (no PII)
- **Discovered**: 2026-04-23

#### [03.12.5] 🟢 Agent install + auto-upgrade + scheduled tasks registration OK ✅

- **Fase**: 03
- **Area**: Agent install flow / auto-upgrade
- **Tipo**: 🟢 OK (parziale — install OK, scan fallito separatamente)
- **Actual** (output run `-Install -AllowHttp`):
  ```
  Existing SentriKat Agent detected — upgrading automatically.
  Old API key revoked on server.
  Old agent removed. Installing new version...

  TaskPath    TaskName                       State
  \           SentriKat Agent                Ready
  \           SentriKat Agent Heartbeat      Ready

  SentriKat Agent installed:
    - Full scan: every 240 minutes
    - Heartbeat: every 5 minutes (checks for commands)
  ```
- **Valutazione positiva**:
  - ✅ Auto-detection di installazione esistente (non reinstall cieco)
  - ✅ Auto-revoke della vecchia API key sul server → security (previene orphan credentials)
  - ✅ Clean upgrade (rimozione vecchio + install nuovo)
  - ✅ 2 scheduled tasks Windows registrate:
    - `SentriKat Agent` → full scan ogni 240 min (4 ore)
    - `SentriKat Agent Heartbeat` → ogni 5 min (keep-alive + command pull)
  - ✅ Architettura valida: scan heavyweight separato da heartbeat lightweight
- **Info 03.12.5a — Cadenza scan default**: 240 min per full scan è conservativo. In incident response settings si potrebbe volerlo più aggressivo (60 min?). Parametro forse esposto al setup, da confermare
- **Discovered**: 2026-04-23

#### [03.12.6] 🔴 HIGH — "Initial scan failed" silent fail, nessun dettaglio errore, nessun log backend

- **Fase**: 03
- **Area**: Agent initial inventory / error reporting
- **Tipo**: 🔴 Bug
- **Severity**: **High** (il primo check-in di un agente appena installato fallisce SENZA alcun modo per l'admin di capire perché)
- **Environment**: Windows 11, Windows PowerShell, agent `-Install -AllowHttp` verso `http://localhost`
- **Steps to reproduce**:
  1. Crea Agent API Key su SentriKat
  2. Scarica `sentrikat-agent.ps1`
  3. `powershell -ExecutionPolicy Bypass -File .\sentrikat-agent.ps1 -Install -AllowHttp`
  4. Osserva output
- **Expected**: lo scan iniziale scopre N prodotti, POST verso `/api/agent/inventory`, risposta 200 OK, dashboard mostra prodotti
- **Actual**:
  ```
  Running initial inventory scan...
  Initial scan failed - agent will retry on next scheduled scan
  ```
  - Nessun dettaglio errore (no exception, no HTTP status code, no URL target)
  - Nessun file log visibile a occhio
  - Nessun messaggio con suggerimenti ("check network", "check API key", "check server URL")
- **Verifica lato server SentriKat**:
  - Dashboard: counters tutti a 0
  - `INVENTORY → Products List`: vuota
  - `INVENTORY → Import Queue`: vuota (auto-approve OFF → si aspetterebbe qualcosa qui se ci fosse stato un tentativo)
  - `INTEGRATIONS → Agent Activity`: vuota (nessun record dell'agent che ha tentato check-in)
  - `docker compose logs | grep agent/inventory/401/403` → **SOLO** APScheduler noise, zero tentativi di `POST /api/agent/inventory`
- **Interpretazione**:
  - La chiamata HTTP dell'agent **probabilmente non arriva mai al server** — altrimenti nginx o app avrebbero loggato il tentativo (anche se 401/403/500)
  - Possibili cause:
    1. Errore DNS / connessione prima della POST (il client PS non risolve `http://localhost` dalla macchina Windows → `localhost` è il server SentriKat su Docker? Verifica: dalla macchina Windows `http://localhost` dovrebbe raggiungere nginx:80 → sentrikat:5000, OK)
    2. Timeout / certificato errato (stiamo su HTTP, non HTTPS — dovrebbe essere forced da AllowHttp)
    3. API key handling bug nello script
    4. Errore in fase enumeration (Get-Package/WMI) che abort l'agent prima della POST
    5. Payload troppo grande (>16MB limit?) se enumerati molti prodotti
- **Impatto**:
  - UX: un admin SentriKat che installa l'agent e vede "Initial scan failed" non sa cosa fare
  - Production impact: stesso scenario in un customer on-prem → support ticket che richiede debug remoto
- **Fix candidato (per fase fix)**:
  - Dettaglio errore esplicito con tipo + message (ConnectionError, AuthenticationError, PayloadTooLarge, EnumerationError, ecc.)
  - Log file locale (es. `%PROGRAMDATA%\SentriKat\agent.log`) con trace completo
  - Suggested actions nel message ("Verifica che il server sia raggiungibile", "Verifica la API key", ecc.)
  - Exit code ≠ 0 per scripting / monitoring
- **Discovered**: 2026-04-23

#### [03.12.7] 🔴 Manca un `agent.log` locale per debug post-failure

- **Fase**: 03
- **Area**: Agent / diagnostics
- **Tipo**: 🔴 Bug (collegato a 03.12.6)
- **Severity**: High (blocker debug)
- **Actual**: l'agent fallisce lo scan iniziale senza produrre un file di log locale riconoscibile. Senza log file, impossibile fare troubleshooting remoto su customer site
- **Percorsi tipici attesi (da verificare se esistono)**:
  - `%PROGRAMDATA%\SentriKat Agent\logs\agent.log`
  - `%LOCALAPPDATA%\SentriKat\agent.log`
  - `C:\Program Files\SentriKat Agent\logs\`
- **Follow-up TODO 03.12.7a**: controllare dove sta installato l'agent dopo `-Install`:
  ```powershell
  Get-ScheduledTask -TaskName "SentriKat Agent" | ForEach-Object { $_.Actions }
  ```
  per capire da quale path parte + se c'è un log abilitato
- **Discovered**: 2026-04-23

#### [03.12.9] 🔴 HIGH — API key generata viene rifiutata dal server (403/401) senza motivo chiaro

- **Fase**: 03
- **Area**: Agent auth / API key lifecycle
- **Tipo**: 🔴 Bug (diagnostic breakthrough di [03.12.6])
- **Severity**: **High** (primo scan block-bloccante per ogni nuovo agent)
- **Environment**: agent Windows con API key `sk_agent_4ApEu7_c80X0LsSXRhGorBr86adftcyZN7ka51MEJWg`
- **Diagnostica che ha trovato il root cause**:
  1. Il nginx access log mostra che l'agent arriva effettivamente al server:
     ```
     172.22.0.1 - - [23/Apr/2026:19:00:33 +0000] "POST /api/agent/inventory HTTP/1.1" 403 254 "-" "SentriKat-Agent/1.0.0 (Windows)"
     ```
     → **la chiamata raggiunge nginx/sentrikat; il server risponde 403 Forbidden** (254 byte di response)
  2. Test manuale endpoint heartbeat con la stessa API key via `Invoke-WebRequest`:
     ```
     POST /api/agent/heartbeat → 401
     Response: {"error":"Invalid or missing API key","hint":"Include X-Agent-Key header with your agent API key"}
     ```
     → **la chiave viene rigettata dal server** anche se è quella appena generata dalla UI
- **Ipotesi root cause — "self-revocation" dello script durante auto-upgrade**:
  - Timeline:
    1. Utente crea API key `Y` (sk_agent_4ApEu7_...) nella UI
    2. Utente scarica `sentrikat-agent.ps1` → il server embed la key `Y` nello script
    3. Utente esegue con `-Install` → lo script detecta **installazione pre-esistente** (da test precedente — quando l'utente aveva "una volta" SentriKat funzionante)
    4. Script esegue "Old API key revoked on server" — ma **quale key revoca?**
       - Se lo script legge la key dall'installazione precedente, revoca la OLD key X → OK, non impatta Y
       - Ma se lo script revoca la key EMBEDDED nel nuovo script (Y) prima di configurare, si auto-suicida
    5. Agent installato con la key `Y` che è stata revocata → 403/401 su ogni call
- **Evidence behaviorale**:
  - Entrambe le chiamate (inventory via agent + heartbeat via curl manuale) falliscono
  - La stessa chiave è usata in entrambi i casi
  - 401 response testo: "Invalid or missing API key" → **la key non è riconosciuta nel DB** (non è né non-autorizzata né orphan — è proprio assente/revocata)
- **Conferma necessaria — chiedere all'utente**:
  1. Tornare nella UI `INTEGRATIONS → Agent Keys` → vedere lo stato della key appena creata:
     - Active? Revoked? Expired?
     - Last seen?
  2. Confrontare la key visualizzata nella UI (o prefix) con quella embedded nello script:
     ```powershell
     Select-String -Path "C:\Users\cti-admin\Downloads\sentrikat-agent.ps1" -Pattern "sk_agent_"
     ```
- **Impatto**:
  - Feature "auto-upgrade" dell'agent è utile ma ha un side-effect che auto-impedisce il primo scan
  - In ambiente customer reale: installazione nuova pulita probabilmente funzionerebbe (no previous agent → no revoke), ma qualsiasi scenario di re-deploy / upgrade soffre del problema
- **Fix candidato (per fase fix, non ora)**:
  - Lo script auto-upgrade deve revocare **solo** la key dell'installazione precedente, NON la key nuova embedded nello script attuale
  - La UI deve mostrare esplicitamente lo stato della key (Active / Revoked / Expired) + "Last seen" timestamp
  - L'endpoint `/api/agent/inventory` deve ritornare 401 con messaggio identico a heartbeat ("Invalid or missing API key") invece di 403, per coerenza
- **Ipotesi aggiuntive (sollevate dall'utente durante la sessione)**:
  1. **DEMO limit (5 agent max)**: improbabile come causa — messaggio "Invalid or missing API key" NON è lo stesso di "Quota exceeded". Uno usa codice/testo diverso. Se fosse DEMO limit: test API con `curl` direttamente restituirebbe `{"error":"demo_limit_reached","hint":"Upgrade to PRO..."}`, non key-invalid
  2. **Installazione on-prem non registrata col license server upstream**: plausibile come causa secondaria. Il nostro `.env` ha `SENTRIKAT_LICENSE=` e `SENTRIKAT_LICENSE_SERVER=` **vuoti** (DEMO no-license). Se la validation delle agent API keys richiede check upstream col license server (telemetria/metering), il fallimento di quel check potrebbe tradursi in un "key invalid" silent. Da approfondire
- **Diagnostica eseguita**:
  1. ✅ **Key UI vs script embedded match**: la key embedded nel `.ps1` è esattamente `sk_agent_4ApEu7_c80X0LsSXRhGorBr86adftcyZN7ka51MEJWg` — match perfetto con UI. NO mismatch client-side
  2. ❌ **security.log nel container è vuoto** (aggrava [03.12.13])
  3. ✅ **Query DB `agent_api_keys`** — 1 riga trovata con stato:
     ```
     id: 1
     organization_id: 1
     name: Test Windows Agent
     key_hash: d2e23e5951d3c9a1... (SHA-256 hex)
     key_prefix: sk_agent_4
     encrypted_key: gAAAAABp6mmYfl... (Fernet encrypted)
     key_type: client
     scan_os_packages/extensions/dependencies: t/t/t
     active: t                            ← ATTIVA
     max_assets: 0                        ← unlimited
     allowed_ips: (vuoto)                 ← nessuna IP restriction
     auto_approve: f
     last_used_at: 2026-04-23 19:00:33    ← aggiornato dal server al nostro test!
     usage_count: 3                       ← incrementato dal server!
     ```
- **🎯 INSIGHT CRITICO — ipotesi self-revoke [03.12.9] CONFUTATA**:
  - `active = true` e nessuna colonna `revoked_at` popolata → la key **NON è stata revocata**
  - `last_used_at` riflette il tempo preciso dei nostri test recenti → **il server TROVA la key** nel lookup
  - `usage_count = 3` → il server **incrementa** il counter a ogni chiamata
  - Significa che il server esegue correttamente il match DB, poi **qualcos'altro** downstream fallisce e restituisce 401
- **Conclusione root cause**: il 401 non è "API key invalid", è un **messaggio di errore FUORVIANTE** che nasconde il vero motivo del rifiuto (scope check? license check? plan gate? org binding?). La key è operativa nel DB ma viene bloccata da un secondo layer di validation
- **Discovered**: 2026-04-23 (breakthrough diagnostic completo)

#### [03.12.14] 🔴 CRITICAL — Messaggio d'errore `"Invalid or missing API key"` FUORVIANTE: la key è valida ma viene rifiutata da check downstream

- **Fase**: 03
- **Area**: Agent auth / error message correctness
- **Tipo**: 🔴 Bug
- **Severity**: **Critical** (impedisce debug, devia root cause analysis, fa perdere ore di tempo — l'admin guarda API key, ricrea, re-installa, ma il problema non è lì)
- **Environment**: agent Windows beta.6 DEMO
- **Evidence**:
  - DB row per key `sk_agent_4ApEu7_...` ha `active=true`, `last_used_at` aggiornato, `usage_count=3`
  - Server risponde `401 {"error":"Invalid or missing API key","hint":"Include X-Agent-Key header with your agent API key"}`
  - Contraddizione esplicita: la chiave **è stata trovata** (DB update conferma), ma il messaggio dice "invalid or missing"
- **Scenario behind-the-scenes (ricostruzione)**:
  1. POST arriva con `X-Agent-Key`
  2. Server: `SELECT * FROM agent_api_keys WHERE key_hash=sha256(header_value)` → **MATCH**
  3. Server: `UPDATE agent_api_keys SET last_used_at=NOW(), usage_count=usage_count+1 WHERE id=1` → OK
  4. Server: ulteriore check (organization binding? plan gate? quota? license server?) → **FAIL**
  5. Server: return `401 {"error":"Invalid or missing API key"}` → **messaggio sbagliato per questa condizione**
- **Impatto**:
  - Admin operativo: spende ore a investigare la chiave, ricreare, re-installare
  - Support team: difficile triage su customer report "API key not working" — la diagnostica punta alla chiave ma il problema è altrove
  - Error handling inconsistency: dovrebbe esserci `403 Forbidden` con `{"error":"<specific_reason>"}` in uno tra:
    - `key_scope_mismatch`
    - `organization_not_authorized`
    - `feature_not_available_on_plan`
    - `license_server_validation_failed`
    - `agent_quota_exceeded`
- **Fix candidato (per fase fix, non ora)**:
  - Separare il flow di validation in step distinti con messaggi specifici
  - Se la key viene trovata (lookup OK) e qualche altro check fallisce → response 403 (non 401) con reason specifica
  - Log WARN a backend con reason esatta
- **Discovered**: 2026-04-23

#### [03.12.15] 🔴 HIGH — Post-breakthrough: agent è bloccato ma ROOT CAUSE reale non raggiungibile senza leggere codice

- **Fase**: 03
- **Area**: Agent flow / diagnostic dead-end
- **Tipo**: 🔴 Bug (meta-observation) + decisione operativa
- **Severity**: High (blocca il testing di 03.12+ con rischio di compromettere le fasi successive che dipendono da dati inventory reali: products, CVE matching, remediation, compliance reports)
- **Stato**:
  - ❌ Root cause definitivo non raggiungibile dal solo debug black-box: serve leggere il codice `app/agent_api.py` o `app/authz.py` per capire quale check downstream sta fallendo
  - ✅ Abbiamo raccolto sufficienti evidence da giustificare un fix:
    - [03.12.6] Silent fail con 1 riga generica
    - [03.12.7] No local agent.log
    - [03.12.9] Auto-upgrade revoke logic da chiarire
    - [03.12.10] Script in Downloads dir invece di ProgramData
    - [03.12.13] Server non logga 403 su stdout
    - [03.12.14] Messaggio 401 fuorviante
- **Candidate root cause (ordinate per plausibilità)**:
  1. **🟡 DEMO/on-prem senza license server upstream**: ipotesi utente, plausibile. Il backend `metering` potrebbe richiedere license-server per "attivare" l'uso agent anche in DEMO
  2. **🟡 Org binding mismatch**: `organization_id=1` nel DB, ma l'endpoint potrebbe aspettare che l'agent dichiari esplicitamente l'org nel body, e il body potrebbe essere `-1-byte` ([03.12.12]) o altro
  3. **🔵 License/subscription gate**: l'istanza DEMO non ha `Subscription` attiva, qualcosa controlla `.has_active_subscription` prima di accettare inventory
  4. **🔵 Feature gate `agent_inventory`**: questo feature potrebbe essere gated e per DEMO disabilitato
- **Decisione operativa**: **⏸️ BLOCK sull'agent flow**. Spostato nel blocked backlog. Passiamo a testing delle aree non-bloccate (CISA sync, compliance reports vuoti ma UI testabile, backup/restore on-prem, altri Settings tab). Torneremo sull'agent dopo fase fix
- **Discovered**: 2026-04-23

#### [03.12.10] 🔵 Info — Scheduled task punta a path user Downloads invece di path di sistema

- **Fase**: 03
- **Area**: Agent install / file location / stability
- **Tipo**: 🔵 Info (deploy hygiene)
- **Severity**: Medium (low impact oggi, alto rischio domani)
- **Actual** (da `Get-ScheduledTask | Select Actions`):
  ```
  Arguments: -NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden
             -File "C:\Users\cti-admin\Downloads\sentrikat-agent.ps1" -RunOnce
  Execute: powershell.exe
  ```
- **Issue**: lo script non è **copiato** in un path di sistema durante `-Install`. Resta nel path dove l'utente lo ha scaricato (`Downloads`). Conseguenze:
  - Se l'utente cancella il file da Downloads → task si rompe silenziosamente
  - Se `cti-admin` elimina il profilo o rinomina l'account → path risolve a null
  - Se la dir Downloads è sync con OneDrive / roaming → behaviour imprevedibile
  - Se l'agent gira come `LocalSystem` (non come user) potrebbe non avere accesso al path user
- **Fix candidato**: `-Install` deve copiare lo script in `%PROGRAMDATA%\SentriKat Agent\bin\sentrikat-agent.ps1` e puntare il task lì
- **Discovered**: 2026-04-23

#### [03.12.11] 🔵 Info — LastTaskResult `267011` = "SCHED_S_TASK_HAS_NOT_RUN"

- **Fase**: 03
- **Area**: Scheduled task status
- **Tipo**: 🔵 Info
- **Actual** (da `Get-ScheduledTaskInfo`):
  ```
  LastRunTime        : 11/30/1999 12:00:00 AM
  LastTaskResult     : 267011
  NextRunTime        : 4/24/2026 12:53:35 AM
  NumberOfMissedRuns : 0
  ```
- **Interpretazione**:
  - `267011` (0x41303) = `SCHED_S_TASK_HAS_NOT_RUN` — il task non è MAI stato eseguito automaticamente
  - `LastRunTime 11/30/1999 12:00:00 AM` = epoch Windows (valore default quando mai eseguito)
  - Il task attende il `NextRunTime` (4 ore dopo install)
- **Nota**: **la RunOnce action eseguita durante `-Install` è una esecuzione separata, non logged qui**. Il task in sé non è mai partito.
- **Discovered**: 2026-04-23

#### [03.12.12] 🔵 Info — Verbose output "POST with -1-byte payload" sospetto

- **Fase**: 03
- **Area**: Agent script / HTTP body preparation
- **Tipo**: 🔵 Info (da investigare)
- **Actual** (da run manuale con `-Verbose`):
  ```
  VERBOSE: Target Image Version 10.0.26200.8246
  VERBOSE: POST with -1-byte payload
  ```
- **Interpretazione possibile**:
  - `-1-byte payload` = size pre-compressione calcolata in modo strano (stream length unknown)
  - Potrebbe essere un artefatto di PowerShell `Invoke-WebRequest` quando `Content-Length` è settato a -1 per chunked transfer
  - Oppure il body è effettivamente null/vuoto → il server risponde 403 perché payload non valido (corroborerebbe [03.12.9])
- **Follow-up TODO 03.12.12a**: aprire lo script `sentrikat-agent.ps1` e cercare il blocco `Invoke-RestMethod` / `Invoke-WebRequest` per vedere come costruisce il body. Se il body è serializzato dopo la logging, può essere che il verbose stampi prima della preparazione effettiva
- **Discovered**: 2026-04-23

#### [03.12.13] 🔴 403 server-side su inventory NON loggato nello stdout di sentrikat container

- **Fase**: 03
- **Area**: Server logging / observability
- **Tipo**: 🔴 Bug (observability)
- **Severity**: Medium-High (diagnostica bloccata lato server)
- **Actual**:
  - nginx access log mostra chiaramente: `POST /api/agent/inventory HTTP/1.1" 403 254`
  - `docker compose logs sentrikat | grep agent|inventory|403|401` → **ZERO match per quel 403**
  - Solo rumore APScheduler
- **Issue**: il sentrikat backend sta ritornando 403 ma **non lo logga nei suoi stdout/stderr** — rende impossibile per un admin capire perché l'agent viene rifiutato
- **Fix candidato**:
  - Logging esplicito su agent API key validation failure:
    ```
    WARNI [app.agent_api] Agent auth rejected: key=sk_agent_4ApEu7... reason=key_revoked ip=172.22.0.1
    ```
  - Così nell'audit log + SIEM forwarding (che abbiamo già configurato — [03.11.7]) c'è traccia di ogni auth fail
- **Nota**: il log potrebbe essere finito in `/var/log/sentrikat/security.log` (che NON è su stdout). Da verificare:
  ```powershell
  docker compose -p v100-beta6 exec sentrikat tail -n 50 /var/log/sentrikat/security.log
  ```
- **Discovered**: 2026-04-23

---

#### [03.12.8] 🔵 Info — Agent uses Windows Scheduled Tasks (non Windows Service)

- **Fase**: 03
- **Area**: Agent architecture
- **Tipo**: 🔵 Info (observation)
- **Actual**: dopo `-Install` sono registrati 2 Scheduled Tasks (non 2 Windows Services):
  - `SentriKat Agent` (240 min interval)
  - `SentriKat Agent Heartbeat` (5 min interval)
- **Trade-off**:
  - ✅ Pro: più semplice da installare (no service manager), funziona anche su versioni Windows limitate
  - ✅ Pro: tasks visibili in Task Scheduler UI → facile per admin controllare stato
  - ⚠️ Con: se user logoff e il task è "Run when user logged on" → scan non parte; se è "Run whether user logged on or not" serve password user salvata
  - ⚠️ Con: PowerShell process elevato ogni N minuti è più pesante di un service long-running
- **Follow-up TODO 03.12.8a**: verificare che i task siano settati `Run whether user is logged on or not` + `Run with highest privileges` (necessario per enumerazione MSI, registry HKLM, WMI) — altrimenti comportamento imprevedibile
- **Discovered**: 2026-04-23

---

### 03.11.7 — SIEM / Syslog → testlab syslog-receiver

#### [03.11.7.1] Form SIEM/Syslog rendering + config options ✅

- **Fase**: 03
- **Area**: Settings → SIEM / Syslog
- **URL**: `http://localhost/admin/settings` (tab "SIEM / Syslog")
- **Tipo**: 🟢 OK
- **Actual — form contiene**:
  - Header: `"SIEM / Syslog Forwarding"`
  - Description: `"Forward vulnerability events to your SIEM (Splunk, ELK, ArcSight, QRadar) via syslog. Supports CEF, JSON, and RFC 5424 formats over UDP or TCP."`
  - Toggle: Enable Syslog Forwarding (ON)
  - Syslog Server Host: text
  - Port: number
  - Protocol: dropdown **UDP / TCP**
  - Event Format: dropdown **RFC 5424 / CEF / JSON**
  - Facility: dropdown (local0 default)
  - Buttons: Save Settings | Send Test Event
- **Positivi**:
  - Descrizione menziona esplicitamente i 4 SIEM vendor più comuni (Splunk, ELK, ArcSight, QRadar) → UX chiara
  - Supporto multi-format (CEF, JSON, RFC 5424) + multi-protocol (UDP, TCP) → coverage enterprise
- **Discovered**: 2026-04-23

#### [03.11.7.2] Save + Test Event: NO SSRF blocking (come atteso, syslog non è HTTP outbound) ✅

- **Fase**: 03
- **Area**: SIEM / Syslog + policy SSRF uniformity
- **Tipo**: 🟢 OK
- **Config utilizzata**:
  - Host: `host.docker.internal`
  - Port: `5514`
  - Protocol: UDP
  - Format: RFC 5424 (Standard Syslog)
  - Facility: local0
- **Actual**:
  - Save → nessun errore 400 SSRF
  - Send Test Event → lavoro senza errori UI
  - Log backend: nessuna riga `SSRF blocked` per syslog → **syslog bypassa la validation SSRF** (coerente: usa socket UDP/TCP dedicato, non HTTP client)
- **Conferma policy map** (vedi tabella riassuntiva commit `1d55762`):
  - SIEM / Syslog → UDP/TCP dedicato → **NON SSRF-gated** ✅
- **Discovered**: 2026-04-23

#### [03.11.7.3] End-to-end delivery su testlab-syslog confermato ✅ (prima integrazione outbound funzionante nel nostro env)

- **Fase**: 03
- **Area**: SIEM / Syslog / dim 1 happy path + dim 7 integration
- **Tipo**: 🟢 OK
- **Verifica**: `docker logs -f testlab-syslog` mostra "un sacco di contenuto" al click di Send Test Event
- **Interpretazione**:
  - SentriKat apre socket UDP verso `host.docker.internal:5514`
  - testlab-syslog (alpine + socat listener su 5514 UDP+TCP) riceve e stampa stdout
  - Docker logs cattura e rende visibile
- **Status area**:
  - ✅ dim 1 Happy path — save + test + delivery OK
  - ✅ dim 2 Persistence — da verificare (restart container sentrikat, check config)
  - ⬜ dim 3 CRUD — disable syslog forwarding, rewire, re-enable
  - ⬜ dim 5 State transitions — syslog destination down (stoppare testlab-syslog) → SentriKat logga fallimento ma non crasha?
  - ⬜ dim 6 Negative — host invalido, port fuori range, format invalido
  - ⬜ dim 7 Integration profonda — verificare che eventi REALI (login utente, CVE match, remediation action) finiscano in syslog, non solo test event
- **Follow-up TODO 03.11.7.3a**: catturare il messaggio syslog effettivo per vedere formato RFC 5424 effettivo (timestamp, hostname, app name, PID, structured data, msg) e validare che sia parsabile da Splunk/ELK/ArcSight
- **Follow-up TODO 03.11.7.3b**: in fase 7 (agents + inventory) vedere se il discovery di un nuovo asset genera evento syslog appropriato
- **Discovered**: 2026-04-23

#### [03.11.7.4] 🔵 Info — "Un sacco di contenuto" al singolo test event suggerisce multi-line o flood

- **Fase**: 03
- **Area**: SIEM / Syslog / event volume
- **Tipo**: 🔵 Info (da chiarire)
- **Actual**: utente descrive che il click Send Test Event ha generato "un sacco di contenuto" in `docker logs -f testlab-syslog`
- **Due scenari possibili**:
  - **A**: un singolo evento test multi-line (es. RFC 5424 con structured data lunghi + eventi aggiuntivi per header SIEM) — normale
  - **B**: il click Send Test Event triggera multipli eventi (es. test + audit log entry + session event) — potenzialmente un bug di flooding
- **Follow-up TODO 03.11.7.4a**: contare i messaggi arrivati per un singolo click Test Event e vedere se sono 1 (atteso) o più. Se >3 è bug di flooding → da aprire come bug puntuale
- **Discovered**: 2026-04-23

---

### 03.11.6 — Lateral test: GitHub / GitLab / YouTrack (SSRF uniformity check)

Obiettivo di questo mini-test: determinare se la policy SSRF (`ALLOW_PRIVATE_URLS` ignorato in prod) è uniforme su tutti gli issue tracker con URL configurabile.

#### [03.11.6.1] 🔵 GitHub Issues NON ha campo Base URL / API URL — hardcoded per GitHub Cloud

- **Fase**: 03
- **Area**: Settings / Issue Trackers / GitHub / feature completeness
- **Tipo**: 🔵 Info (feature gap, potenziale enterprise blocker)
- **Severity**: Low-Medium (per customer che usa GitHub Enterprise self-hosted)
- **Actual**: espandendo GitHub Issues Configuration il form contiene SOLO:
  - Personal Access Token
  - Repository Owner
  - Repository Name
  - (nessun campo URL/Base URL)
- **Implicazione**: il client GitHub è hardcoded per `api.github.com`. **GitHub Enterprise Server self-hosted** (es. `github.company.com`) **NON è supportato** in questo form
- **Impatto enterprise**: molti clienti enterprise usano GitHub Enterprise su dominio privato — per loro questa integration non è utilizzabile
- **Beneficio collaterale (per il nostro test)**: save passa senza problemi SSRF perché non c'è URL da validare → vedi 03.11.6.2
- **Fix candidato**: aggiungere campo opzionale "GitHub API Base URL (leave blank for github.com)" come fanno molti altri tool
- **Discovered**: 2026-04-23

#### [03.11.6.2] GitHub Issues save OK (no URL field = no SSRF validation) ✅

- **Tipo**: 🟢 OK
- **Actual**: save del form GitHub con token+owner+repo riusce. Nessun campo URL → niente validation SSRF
- **Discovered**: 2026-04-23

#### [03.11.6.3] GitHub Test Connection error message chiaro: `"GitHub: Authentication failed - check token"` ✅

- **Fase**: 03
- **Area**: GitHub integration / error handling
- **Tipo**: 🟢 OK (UX)
- **Actual**: con dummy token "dummy-token-123" il test produce messaggio **chiaro e specifico** nella UI
- **Contrasto**: vs webhook Test Connection [03.11.5.3] che ritorna 500 nudo senza messaggio → qui l'endpoint di test GitHub è correttamente gestito. Inconsistency nei pattern di error handling tra endpoint `/test` dei vari tracker
- **Discovered**: 2026-04-23

#### [03.11.6.4] ⏸️ GitLab Issues — stessa policy SSRF blocca con URL privato (conferma uniformità)

- **Fase**: 03
- **Area**: GitLab integration / SSRF
- **Tipo**: ⏸️ Test bloccato (stessa causa di 03.11.4.5)
- **Actual**:
  - GitLab URL: `http://host.docker.internal:8800`
  - Save → toast rosso `"Error saving settings: Setting 'gitlab_url' targets a private/internal network address. External URLs are required."`
  - Console: `POST /api/settings/batch 400 (BAD REQUEST)` + `POST /api/integrations/issue-tracker/test 500 (INTERNAL SERVER ERROR)` → stesso pattern bug [03.11.5.3]
- **Conferma**: la policy SSRF si applica UNIFORMEMENTE a tutti i tracker con URL configurabile (Jira, Webhook, GitLab). GitHub passa solo perché non ha URL. YouTrack da testare ma atteso uguale
- **Discovered**: 2026-04-23

#### [03.11.6.5] 🔵 UX strano — Dopo save fallito per SSRF, UI mostra messaggio inline `"GitLab: Project not found: 1"`

- **Fase**: 03
- **Area**: GitLab integration / UI state
- **Tipo**: 🔵 Info (UX confuso)
- **Severity**: Low-Medium
- **Actual**: nel screenshot, sotto il bottone Save Settings, appare un blocco rosso con `"GitLab: Project not found: 1"` **mentre il toast in alto dice** `"gitlab_url targets a private/internal network address"`
- **Issue**: due messaggi di errore **contraddittori**:
  - Toast: SSRF block (la request non è partita)
  - Inline: "Project not found" (suggerisce che la request sia partita e abbia ricevuto 404 dal server)
- **Possibili cause**:
  - `"Project not found"` è residuo di un tentativo precedente che non viene pulito quando si riconfigurazione
  - Oppure: il Test Connection tentava prima di raggiungere GitLab (e ha ricevuto 404 perché host.docker.internal:8800 è webhook-tester non GitLab reale) PRIMA che la validation SSRF bloccasse il save
- **Fix candidato**: reset di stato quando save fallisce, oppure mostrare errore singolo (non due messaggi contraddittori)
- **Discovered**: 2026-04-23

#### [03.11.6.6] 🔵 System health banner: `"No active agent API keys (agents cannot push data)"`

- **Fase**: 03
- **Area**: System health monitor / empty state
- **Tipo**: 🔵 Info (atteso a setup iniziale)
- **Actual**: banner rosso in cima alla pagina Administration: `"System health: 1 critical config issue(s): No active agent API keys (agents cannot push data)"` + link "View"
- **Valutazione**: informativo e corretto — non abbiamo ancora creato nessun agent API key (lo faremo in 03.12). Il health monitor rileva correttamente lo stato
- **Positivo**: ✅ feature Health Checks funzionante, rileva config gaps proattivamente
- **Follow-up**: dopo che creeremo gli agent keys il banner dovrebbe sparire
- **Discovered**: 2026-04-23

#### [03.11.6.7] 🔵 Log SSRF etichetta sempre "Jira tracker setup" anche per GitLab save (context bug nel logger)

- **Fase**: 03
- **Area**: Logging / context labeling
- **Tipo**: 🔵 Info (logging hygiene)
- **Severity**: Low-Medium (debug/ops misleading)
- **Actual** — dai log dopo save GitLab:
  ```
  WARNI [app.network_security] SSRF blocked: Jira tracker setup attempted request to internal URL: http://host.docker.internal:8080
  ```
  Ma l'utente ha configurato GitLab, non Jira. Il contesto "Jira tracker setup" è **hardcoded** o ereditato da una chiamata precedente
- **Issue**:
  - Debug futuro sarà difficile: loggato "Jira" quando era GitLab → ops sta perseguendo il bug sbagliato
  - Se un incident-response team guarda il SIEM, tutti i bloccchi SSRF saranno attribuiti a "Jira"
- **Fix candidato**: passare il contesto corretto al logger (`module_name` o `integration_type` dal chiamante)
- **Discovered**: 2026-04-23

#### [03.11.6.8] YouTrack — non testato (skippato) ⏭️

- **Tipo**: ⏭️ Skipped (pattern già noto, non aggiunge info)
- **Razionale**: YouTrack probabilmente usa la stessa policy — test rapido non prioritario per ora
- **Follow-up TODO**: test YouTrack save con URL privato dopo fase fix; verificare che anche là il pattern regga
- **Discovered**: 2026-04-23

---

### 03.11.4 — Jira → jira-mock (MockServer)

#### [03.11.4.1] Mock Jira testlab raggiungibile solo via `/mockserver/dashboard` ✅

- **Fase**: 03
- **Area**: Testlab jira-mock / endpoint discovery
- **URL**: `http://localhost:8080/mockserver/dashboard`
- **Tipo**: 🟢 OK
- **Actual**:
  - `http://localhost:8080` root → `NO_MATCH_RESPONSE` (nessuna expectation registrata su path vuoto) — normale per MockServer
  - `http://localhost:8080/mockserver/dashboard` → dashboard MockServer funzionante
  - Log confermano caricamento `jira-expectations.json` all'avvio
- **Discovered**: 2026-04-23

#### [03.11.4.2] Expectations Jira mock pre-configurate (8 endpoint) ✅

- **Fase**: 03
- **Area**: Testlab jira-mock / API surface
- **Tipo**: 🟢 OK + 🔵 Info per mapping
- **Actual** — 8 attive (ordine d'applicazione):

| Method | Path | Scopo |
|---|---|---|
| GET | `/rest/api/2/serverInfo` | Jira server version info (login ping) |
| GET | `/rest/api/2/myself` | Auth check: ritorna user corrente |
| GET | `/rest/api/2/project/VULN` | Project detail — **project key `VULN` preconfigurato** |
| GET | `/rest/api/2/project` | List projects |
| POST | `/rest/api/2/issue` | Create issue — endpoint core per la integration |
| GET | `/rest/api/2/search` | JQL search |
| GET | `/rest/api/2/issuetype` | Issue types list (dropdown UI populate) |
| GET | `/rest/api/2/priority` | Priority list (per priority mapping CVSS→Jira) |

- **Coverage valutazione**: mock copre i pattern tipici di una integration "create from CVE → post issue → search status". Mancano però webhook-back (Jira→SentriKat updates), transitions (status change), attachments
- **Discovered**: 2026-04-23

#### [03.11.4.3] SentriKat form Issue Tracker Integration — rendering OK ✅ + 2 osservazioni minori

- **Fase**: 03
- **Area**: Settings / Issue Trackers / UI rendering
- **URL**: sidebar `INTEGRATIONS → Integrations → Issue Trackers` (path da confermare nel breadcrumb)
- **Tipo**: 🟢 OK (rendering) + 🔵 Info per dettagli
- **Actual**:
  - Banner blu: "Issue Tracker Integration: Create issues directly from vulnerabilities. Supports Jira, YouTrack, GitHub Issues, GitLab Issues, and custom webhooks."
  - Enabled Issue Trackers — 5 checkbox: Jira (checkable), YouTrack, GitHub Issues, GitLab Issues, Custom Webhook. Utente ha abilitato solo Jira ✅
  - Helper text: "Enable one or more trackers. A 'Create Issue' button will appear for each on the dashboard." → promette UX: le azioni per-tracker compaiono nel dashboard CVE
  - Jira Configuration campi: URL, Username, Personal Access Token (masked), toggle `Use Personal Access Token (PAT)`, Project Key, Issue Type dropdown, Custom Fields section con bottone "Fetch Required Fields"
- **Osservazione #1 — URL prepopolato `host.docker.internal:8080`**: riferimento al testlab mock. Potenziale issue stesso del SAML [03.11.3.2]: se SentriKat genera link "Open in Jira" per il browser usando questo URL, il link sarà unreachable dal browser host. Per **create issue (server-side)** è OK.
- **Osservazione #2 — Issue Type dropdown mostra `Task` ma placeholder dice "Please fill in URL, username, token, and project key first"**: il dropdown è prepopolato ma richiede fetch completo per essere valido. Potrebbe creare confusione — sembra già selezionato
- **Discovered**: 2026-04-23

#### [03.11.4.4] ⚠️ Project Key inserito `SEC` ma mock expectation è `VULN` — correzione prima di test

- **Fase**: 03
- **Area**: Config Jira / test setup
- **Tipo**: ⚠️ Test setup error (non bug)
- **Actual**: utente ha compilato `Project Key = SEC`. Il mock ha expectations solo per `/rest/api/2/project/VULN` e non ha una per `/project/SEC` → il Test Connection fallirà con 404 o default "NO_MATCH_RESPONSE"
- **Azione correttiva richiesta prima di procedere**: cambiare Project Key da `SEC` a `VULN`, poi procedere a fetch fields + save + test
- **Discovered**: 2026-04-23

#### [03.11.4.5] 🔴 HIGH — Validation SSRF su `jira_url` NON rispetta il flag `ALLOW_PRIVATE_URLS=true` (inconsistenza con SMTP/LDAP/SAML)

- **Fase**: 03
- **Area**: Settings / Issue Trackers / SSRF protection / config consistency
- **Tipo**: 🔴 Bug
- **Severity**: **High** (impedisce completamente il testing di Jira con docker-compose testlab; inconsistenza tra moduli sulla stessa security policy)
- **Environment**: on-prem DEMO beta.6, `ALLOW_PRIVATE_URLS=true` nel `.env`
- **Steps to reproduce**:
  1. `.env` contiene `ALLOW_PRIVATE_URLS=true` (configurato all'install dallo script setup-beta6.ps1)
  2. Settings → Issue Trackers → abilita Jira
  3. Compila form con `Jira URL = http://host.docker.internal:8080`, username, PAT, project key VULN
  4. Click Save Settings
- **Expected**: save OK. Il flag `ALLOW_PRIVATE_URLS=true` autorizza URL su reti private/interne in ambienti di test. Coerente con il comportamento già osservato per:
  - [03.11.1.1] SMTP `host.docker.internal:1025` → accettato ✅
  - [03.11.2.1] LDAP `host.docker.internal:389` → accettato ✅
  - [03.11.3.1] SAML `host.docker.internal:8180` (iniziale, prima di scoprire 03.11.3.2) → accettato lato form save
- **Actual**:
  - Toast rosso in alto a destra: `"Error saving settings: Setting "jira_url" targets a private/internal network address. External URLs are required."`
  - Console: `Failed to load resource: the server responded with a status of 400 (BAD REQUEST)`
  - Il save del form Jira è **rifiutato** → impossibile procedere con test Jira integration nel nostro env docker
- **Root cause hypothesis**:
  - La validation SSRF è implementata **per-endpoint** e quella dell'endpoint `/api/integrations/jira` (o `/api/settings/jira`) non controlla il flag `ALLOW_PRIVATE_URLS` prima di applicare il rifiuto
  - Oppure il flag è considerato solo per URL "outbound webhook/email/ldap/saml" e non per "URL di integrazione issue tracker" — in tal caso: inconsistenza di design
  - Oppure la validation è più stretta perché Jira integration prevede anche PAT token trasmesso (potrebbe finire su un honeypot interno) — security-rationale plausibile ma dovrebbe essere documentato nel help text
- **Impatto**:
  - **Test bloccato** per Jira integration su testlab locale
  - **Nessun impatto production** (in prod gli admin puntano a Jira Cloud pubblico o Jira Server su domini pubblici)
  - Inconsistenza tra moduli genera confusione: "perché SMTP accetta host.docker.internal ma Jira no?"
- **Fix candidato (per fase fix)**:
  - Unificare la logica SSRF in `app/network_security.py` (modulo esistente da mappatura originale) e far leggere il flag `ALLOW_PRIVATE_URLS` a TUTTI gli endpoint che validano URL di integrazione
  - Oppure: permettere un whitelist esplicito per-hostname (es. `ALLOW_PRIVATE_URL_HOSTS=host.docker.internal,docker-host`) per granularità fine
- **Workaround operativo (per continuare testing senza fix)**:
  - Opzione A: usare IP pubblico della macchina host al posto di `host.docker.internal` (se la macchina ha IP pubblico raggiungibile dal container — Docker Desktop Windows potrebbe NON permetterlo)
  - Opzione B: tunnel via ngrok / localtunnel verso jira-mock port 8080 → URL pubblico `xxx.ngrok.io` → accettato dalla validation SSRF → ma jira-mock accetta host header arbitrario? (da verificare)
  - Opzione C: **saltare il test funzionale Jira** in questa sessione, marcare bug, passare a webhook/syslog
- **Decisione**: scelta Opzione C — passiamo avanti e torniamo su Jira dopo fase fix
- **Status test**: ⏸️ **BLOCKED** da questo bug per l'ambiente locale docker-compose. Spostato nel backlog test bloccati
- **Log evidence (confermato)**:
  ```
  WARNI [app.network_security] SSRF blocked: Jira tracker setup attempted request to internal URL: http://host.docker.internal:8080
  ```
- **⚠️ RECLASSIFY — root cause reale (scoperta su 03.11.5)**: inizialmente avevo attribuito a "Jira non rispetta il flag" mentre SMTP/LDAP/SAML lo rispettano. **Rettifica**:
  - Il log ulteriore durante il test webhook ha rivelato il messaggio CRITI:
    ```
    CRITI [app.network_security] SECURITY WARNING: ALLOW_PRIVATE_URLS is enabled in production! This disables SSRF protection. Ignoring the setting.
    ```
  - → in `FLASK_ENV=production` (attuale), il flag `ALLOW_PRIVATE_URLS` viene **volutamente ignorato come hardening** (prevenzione di abuse admin). Solo in `FLASK_ENV=development` il flag funziona
  - → SMTP/LDAP/SAML hanno accettato `host.docker.internal` non perché "rispettano il flag" ma perché **NON passano dalla SSRF validation** (usano protocolli dedicati SMTP/LDAP, o fetching trusted in modo diverso)
  - → Jira e Webhook passano da SSRF validation per HTTP outbound, correttamente bloccati in prod
- **Bug rivisto**: il comportamento è coerente con una policy security ragionevole. Ma rimane un bug **di UX / configurazione**:
  1. `.env.example` dichiara `ALLOW_PRIVATE_URLS` come opzione reale; setup guide per testing docker usa `ALLOW_PRIVATE_URLS=true` → l'utente si aspetta che funzioni
  2. Il flag viene silenziosamente ignorato e loggato solo server-side come CRITI — l'admin che configura Jira non sa dai messaggi d'errore UI che è questione di `FLASK_ENV`
  3. **Fix candidato (per fase fix)**:
     - Se `FLASK_ENV=production` + `ALLOW_PRIVATE_URLS=true` → fail-fast all'avvio con messaggio "Configuration error: ALLOW_PRIVATE_URLS cannot be true in production mode"
     - Oppure: l'errore UI 400 dovrebbe dire "Private URL rejected. If you're testing, set FLASK_ENV=development"
     - Oppure: rimuovere `ALLOW_PRIVATE_URLS` dal `.env.example` se non è realmente usabile su setup production-default
- **Severity rimane High**: per l'utente finale il risultato è lo stesso — impossibile configurare Jira/Webhook localmente senza capire la trappola env
- **Workaround disponibile (non fix)**: cambiare `.env` → `FLASK_ENV=development`, restart container. Da discutere con utente
- **Discovered**: 2026-04-23

- **Tipo**: 🟢 OK (area conclusa)
- **Dims chiuse**:
  - ✅ dim 1 Happy path — 03.11.3.7 login SSO OK
  - ✅ dim 2 Persistence — config SAML sopravvive (implicito)
  - ✅ dim 3 CRUD parziale — auto-provision 03.11.3.8, role change 03.11.3.10, delete 03.11.3.13
  - ✅ dim 4 Role-based — matrix 03.11.3.12
  - ✅ dim 5 State transitions parziale — 03.11.3.13
- **Dim non ancora testate (follow-up opzionale)**:
  - ⬜ dim 6 Negative — wrong password (lato Keycloak), missing SAML attribute, expired assertion, replay attack, invalid signature
  - ⬜ dim 7 Integration — audit log evento `user.login.saml`, email digest include SAML users, webhook outbound per login, scheduled report audit del SAML
- **Valutazione area SAML**: **funziona** dopo workaround `[03.11.3.2]`. 1 High (docker network trap) + 4 Info config testlab. **Zero** regressioni strutturali (vs LDAP che ne ha 4). Architetturalmente l'area SAML è sana
- **Discovered**: 2026-04-23

---

### 03.14 — System Settings tabs (giro veloce)

#### [03.14.1] Settings → System → `Sync & Updates` tab: feature-rich ✅

- **Fase**: 03
- **Area**: Settings / System / Sync
- **URL**: `Settings → System` tab (sub-tab `Sync & Updates`)
- **Tipo**: 🟢 OK
- **Content mappato**:
  - **CISA KEV Sync Schedule**: Enable Automatic Sync (toggle), Sync Interval (Daily/Weekly dropdown), Preferred Time UTC (02:00 default), NVD API Key field, CISA KEV URL (pre-compilato `cisa.gov/.../known_exploited_vulnerabilities.json`)
  - **NVD Connection Status**: ✅ `Connected` + "Rate limit: 5 req/30s" + badge rosso `NO API KEY` (trasparente sul limite)
  - **Last Sync**: Never · **Next Scheduled**: Not scheduled · **Total Vulnerabilities**: 639
  - **Manual Alert Triggers**: `Send Email Alerts Now` + `Send Webhook Alerts Now` buttons (test on-demand dei canali alert configurati)
  - **EPSS Scoring**: 0 CVEs with EPSS, 0 High Risk, 0% Coverage, Last EPSS Sync: Never, Sync Now button
  - **CPE Dictionary (Offline)**: 0 Total Entries, 0 With Aliases, 0 Used for Matching, 0% Product Coverage, Last Bulk Download: Never, Sync CPE Dictionary Now / Rebuild from Vulnerabilities buttons
  - **SentriKat Knowledge Base (KB Sync)**: Human Mappings 0, Auto-Verified 0, Auto-Discovered 0, Community 0, Last Pull: Never
    - **KB Server: `https://license.sentrikat.com/api`** ← endpoint upstream configurato
- **Valutazione**: pannello admin completo con controllo granulare sulle 5 sync streams (CISA KEV, NVD, EPSS, CPE Dictionary, KB). UX pulita
- **Discovered**: 2026-04-23

#### [03.14.2] 🟡 Warning — Auto-sync CISA KEV è OFF di default dopo setup

- **Fase**: 03
- **Area**: Settings / Sync / defaults
- **Tipo**: 🟡 Warning
- **Severity**: Medium (security posture)
- **Actual**:
  - Toggle `Enable Automatic Sync`: OFF
  - `Next Scheduled`: Not scheduled
  - Significa che senza interazione esplicita dell'admin, SentriKat **non aggiorna mai** il KEV catalog
- **Impatto**:
  - Un customer che installa DEMO e non naviga questa pagina resta con CVE data statici
  - Rischio: nuove vulnerabilità critiche in CISA KEV non vengono tracciate
  - Aggravante: vulnerability mgmt product che non sincronizza di default contraddice il suo scopo primario
- **Fix candidato (per fase fix)**:
  - Default `Enable Automatic Sync = ON` post setup wizard
  - Oppure: setup wizard step 4 (Seed Catalog, attualmente bloccato [03.6.3]) dovrebbe abilitarlo
  - Oppure: banner dashboard "Auto-sync not configured — enable?" con CTA
- **Discovered**: 2026-04-23

#### [03.14.3] 🔵 Info — Discrepanza metrica: `Total Vulnerabilities: 639` qui vs `KEV Catalog: 13,978` in dashboard

- **Fase**: 03
- **Area**: Metrics consistency / data reporting
- **Tipo**: 🔵 Info (da chiarire)
- **Actual**:
  - Dashboard widget "KEV Catalog": **13,978**
  - Settings System Sync "Total Vulnerabilities": **639**
- **Ipotesi**:
  - 13,978 = aggregato multi-sorgente (CVE.org + NVD + fallback) importato al primo boot
  - 639 = solo CISA KEV-specific dopo un sync parziale / limitato (CISA KEV attuali sono ~1400+)
  - Naming confusion: "Total Vulnerabilities" in Sync tab dovrebbe essere "CISA KEV count" per coerenza con il widget dashboard
- **Fix candidato**: uniformare nomi metrica tra dashboard e pannello admin, oppure affiancare su entrambi tutti i counter (Total CVE, CISA KEV, EPSS, CPE)
- **Discovered**: 2026-04-23

#### [03.14.4] 🔵 i18n — Audit Logs filtri data `tt.mm.jjjj` (DE placeholder) su sito EN-only

- **Fase**: 03
- **Area**: i18n / native browser date input
- **Tipo**: 🔵 Info (3ª occorrenza)
- **Actual**: i due filtri date range degli Audit Logs (`da...a...`) mostrano placeholder nel formato tedesco `tt.mm.jjjj`. Stesso pattern di [02.2.1], [03.12.3]. Consolidato
- **Discovered**: 2026-04-23

#### [03.13.2] 🎯 Root cause agent 403/401 DEFINITIVO: Community Edition non include "Push Agents"

- **Fase**: 03
- **Area**: Agent flow / feature gating / root cause
- **Tipo**: 🎯 DIAGNOSIS COMPLETE (cross-ref 03.12.6 / 03.12.9 / 03.12.14 / 03.12.15)
- **Environment**: Agent Activity page (`INTEGRATIONS → Integrations → Agent Activity`)
- **Actual (smoking gun)**:
  ```
  Agent Events:
    Unknown (172.22.0.1) — License limit exceeded: Push Agents require a Professional license. (18m ago)
    Unknown (172.22.0.1) — License limit exceeded: Push Agents require a Professional license. (25m ago)

  Agent Activity Log:
    2026-04-23 21:00:33  LICENSE  License limit exceeded: Push Agents require a Professional license.  172.22.0.1
    2026-04-23 20:54:01  LICENSE  License limit exceeded: Push Agents require a Professional license.  172.22.0.1
  ```
- **Interpretazione**:
  - ❌ NON è self-revoke (ipotesi 03.12.9 **confutata**, come già da `active=true` in DB)
  - ❌ NON è DEMO 5-agent limit (erano 0 agenti attivi)
  - ❌ NON è network / SSL / payload
  - ✅ **È feature gating: "Push Agents" è un feature Pro-only**. Community Edition può creare la key, scaricare lo script, installarlo, ma il backend `/api/agent/inventory` endpoint rifiuta per license gate
- **Conferma finale di [03.12.14]**: il messaggio client `"Invalid or missing API key"` è **completamente fuorviante**. Il backend conosce il vero motivo (`License limit exceeded: Push Agents require a Professional license.`), lo logga correttamente nell'Agent Activity, ma restituisce al client una stringa d'errore ingannevole. Bug 03.12.14 rimane HIGH/CRITICAL, confermato con maggiore forza
- **Ipotesi bloccaggio test agent per Community mode**:
  - Per vedere inventory/products/matching funzionanti dobbiamo **attivare una license Professional** (via activation code o offline license key da SentriKat sales)
  - O **bypassare gating** forzando un test con license mock (richiederebbe modifica backend)
  - O testare soltanto dopo fase fix
- **Stato agent test**: **⏸️ BLOCKED** confermato, ma **root cause ora completamente noto**
- **Discovered**: 2026-04-23 (breakthrough definitivo via Agent Activity log)

#### [03.13.3] Agent Activity page features ✅

- **Fase**: 03
- **Area**: Agent Activity / monitoring UI
- **Tipo**: 🟢 OK
- **Content mappato**:
  - **Background Worker card**: 🟢 `Running` (Check interval: 2s, Async threshold: 750 products, Max per request: 10,000)
  - **Job Queue card**: 0 Pending · 0 Processing · 0 Completed today · 0 Failed today
  - **Recent Jobs**: empty "No jobs found" + filter "All statuses"
  - **Agent Events**: 2 eventi `License limit exceeded` con IP source + timestamp relativo ("18m ago")
  - **Agent Activity Log**: tabella con Timestamp, Type (badge `LICENSE` rosso), Hostname, Details, Source IP. Filtri: All Types, Last 7 days, refresh
  - Auto-refresh ogni 3s (header top-right)
- **Valutazione**: observability page ben progettata. Separa worker status / job queue / events / activity log in modo chiaro
- **Inconsistenza con Health Checks [03.14.7]**:
  - Health Checks `Worker Pool: STOPPED` 🟡
  - Agent Activity `Background Worker: Running` 🟢
  - **Contraddizione** → i due pannelli leggono due metriche diverse? "Worker Pool" in Health è differente da "Background Worker" in Agent Activity? Terminology/source mismatch
- **Follow-up TODO 03.13.3a**: chiarire differenza tra "Worker Pool" (health) e "Background Worker" (agent activity)
- **Discovered**: 2026-04-23

---

#### [03.14.6] Settings → Health Checks: 12 check in 2 gruppi, UI completa ✅

- **Fase**: 03
- **Area**: Settings / Health Checks
- **URL**: `Settings → Health Checks`
- **Tipo**: 🟢 OK
- **Controls**: `Run Now` button + toggle `Enabled` (ON). Notification Email field (default `admin@example.com`), `Send alerts via webhooks` toggle (OFF)
- **Description**: "SentriKat runs background health checks every 30 minutes to monitor system components. Problems and warnings are reported via email notifications and shown here."
- **SYSTEM group (8 check)**:
  - ✅ Database Connectivity `1MS` — healthy (1ms)
  - ✅ Disk Space `92.4%` — 930.3 GB free
  - 🟡 **Worker Pool `STOPPED`** — "Worker pool is not running (no pending jobs)"
  - ✅ Stuck Inventory Jobs `0 PENDING`
  - ✅ Queue Throughput `0 PROCESSED`
  - ✅ License Status `COMMUNITY` — Running in community mode
  - ✅ SMTP Connectivity `REACHABLE` — `SMTP server host.docker.internal:1025 is reachable` ← conferma [03.11.1.2]
  - 🟡 Server Configuration `1 WARNING(S)` — `"1 config warning(s): CISA KEV sync has never run"`
- **DATA SYNC group (4 check)**:
  - 🟡 CVE Sync Freshness `NEVER SYNCED` — "No successful CVE sync found. Run initial sync."
  - ✅ CPE Coverage `0 PRODUCTS`
  - ✅ API Source Status `NVD PRIMARY` — All CVSS scores from NVD
  - ✅ Sync Retry Status `OK`
- **Tutti i check hanno timestamp**: `23.4.2026, 18:59:48` — formato IT/DE (punto separatore data)
- **Valutazione**: feature piena, 12 check discreti, toggles per attivare/disattivare ogni check, integrazione email+webhook per alerting
- **Discovered**: 2026-04-23

#### [03.14.7] 🟡 Worker Pool `STOPPED` — warning, possibile regressione

- **Fase**: 03
- **Area**: Health Checks / Worker Pool
- **Tipo**: 🟡 Warning
- **Severity**: Medium (se il worker pool è effettivamente down, inventory job processing e altri job async non funzionerebbero — ma attualmente nessun job pending)
- **Actual**: check `Worker Pool` mostra status `STOPPED` con descrizione "Worker pool is not running (no pending jobs)"
- **Interpretazione ambigua**:
  - Scenario A: il worker pool si spegne quando non c'è lavoro e si riavvia on-demand — pattern valido (lazy worker)
  - Scenario B: il worker pool è crashed e non si è riavviato — bug grave che si manifesterà quando arriva inventory
  - Scenario C: the check ha logica buggy che reporta STOPPED anche quando il pool è idle ma disponibile
- **Collegamento con [03.12.9/15]**: se il pool non è running, l'inventory POST anche se passasse l'auth non verrebbe processato → KEV catalog vuoto, products vuoti, dashboard vuota. **Ipotesi aggiuntiva per agent 403**: il backend potrebbe rifiutare agent inventory se capisce che il worker pool non è disponibile (non ha senso accettare se non può processare)
- **Follow-up TODO 03.14.7a**: dopo un force sync CISA KEV (→ crea lavoro per il pool) verificare se worker pool passa a RUNNING
- **Discovered**: 2026-04-23

#### [03.14.8] Settings → License: UX completa, installation ID, activate online/offline ✅

- **Fase**: 03
- **Area**: Settings / License
- **URL**: `Settings → License`
- **Tipo**: 🟢 OK (UX complete) + 🔴 bug [03.14.9] sul version check
- **Content mappato**:
  - **Badge top-right**: `COMMUNITY`
  - **Current License card**:
    - Edition: `COMMUNITY EDITION`
    - "Free for personal and small team use."
    - `Upgrade to Professional` link
    - Version info: `SentriKat v1.0.0 beta.2` + `Up to date (v1.0.0 beta.2)` ← **bug [03.14.9]**
    - `Check` button per update
  - **Usage card**:
    - Users: **1/1** (al limite!)
    - Organizations: **1/1** (al limite!)
    - Products: 0/50
    - Agents: Total 0/5 · Servers 0 · Workstations 0 · Weighted Units 0.0
    - Banner giallo: "You've reached Community limits. Upgrade to Professional for unlimited usage."
  - **To request a license** section:
    - Installation ID: `SK-INST-F53C2C721D3BE18FD67DC850392105B9` (matcha `.env` ✅)
    - Copy button
    - "This ID is unique to your installation and cannot be changed."
  - **Activate Online**: Activation Code field (placeholder `SK-XXXX-XXXX-XXXX-XXXX`) + button. "Requires HTTPS connectivity to `license.sentrikat.com`"
  - **Activate Offline**: License Key textarea per paste del file license generato offline
- **Positivi**:
  - Sia online che offline activation supported
  - Installation ID visible + copyable (UX good)
  - Usage meter con limiti chiari
- **Discovered**: 2026-04-23

#### [03.14.9] 🔴 HIGH — License page dice "Up to date (v1.0.0 beta.2)" MA beta.6 è la release corrente (bug update-check)

- **Fase**: 03
- **Area**: License / version check
- **Tipo**: 🔴 Bug
- **Severity**: **High** (customer ignora aggiornamenti critici, inclusi security fix)
- **Actual**:
  - License page mostra: `SentriKat v1.0.0 beta.2` + `Up to date (v1.0.0 beta.2)` (green checkmark)
  - **Ma la release più recente è `v1.0.0-beta.6`** (taggata da noi oggi)
  - Le release intermedie beta.3, beta.4, beta.5 erano già pubblicate prima
- **Root cause ipotesi (dual):**
  1. **Il VERSION file locale dice `beta.2` ([03.5.3])** → l'update-check compara `current=beta.2` vs `latest=???` e se latest è pure beta.2 dice "up to date". Se il server license (`license.sentrikat.com`) risponde con `latest=beta.2` (stale/cached), **entrambi i canali dicono beta.2** e l'utente non vede novità
  2. **Il Check button non parte effettivamente** verso `license.sentrikat.com` → fallback a local version → "up to date" perché non ha nulla da confrontare
- **Impatto gravissimo**:
  - Se un customer on-prem esegue `git pull` del tag beta.6 ma VERSION file resta beta.2 (bug [03.5.3]), **la license page dice "sei aggiornato" mentre NON lo è**
  - Update critici di sicurezza vengono ignorati → rischio CVE-exposure per customer
  - Product su cui si fa vulnerability management che non si aggiorna = ironico ed inaccettabile
- **Dipendenza con bug precedenti**: stesso root cause di [03.5.3] VERSION file hardcoded
- **Fix candidato**:
  - Il Check button deve chiamare esplicitamente `https://license.sentrikat.com/api/releases/latest` e mostrare **banner rosso** se latest > current
  - Fallback: GitHub Releases API se license server non raggiungibile
  - Obbligare update check weekly automatico
  - Quando nuova versione disponibile → banner dashboard + email notification
- **Discovered**: 2026-04-23

#### [03.14.10.expand] 🔴 HIGH — Mismatch edition: "DEMO" (docs) vs "COMMUNITY" (UI) — serve clarification ufficiale su tier, promises, limits

- **Fase**: 03
- **Area**: Product edition / tier / documentation consistency
- **Tipo**: 🔴 Bug (documentation + product behavior mismatch)
- **Severity**: **High** (business-critical: un potenziale customer non sa cosa sta comprando / cosa sta provando)
- **Domanda aperta dell'utente**: "Community Edition esiste, dovrebbe esistere. E una demo? La demo cosa promette? C'è un mismatch di qualcosa."
- **Evidence del mismatch**:

| Sorgente | Tier name | Promise | Agent limit | User limit | Org limit | Prod limit | Push Agents |
|---|---|---|---|---|---|---|---|
| **README/handbook** (mappa originale fase 0) | "DEMO Edition" | "FREE, no license needed, 5 agent limit, 50 products" | 5 | ??? | ??? | 50 | ??? |
| **UI License page** (nostra install) | "COMMUNITY EDITION" | "Free for personal and small team use" | 0/5 | 1/1 | 1/1 | 0/50 | ❌ Pro only |
| **UI Health Checks** | "License Status: COMMUNITY · Running in community mode" | — | — | — | — | — | — |
| **Agent Activity log** | "Push Agents require a Professional license" | — | — | — | — | — | gated |
| **handbook** ($4,999/year PRO) | "Unlimited agents/users/orgs, all features" | all | ∞ | ∞ | ∞ | ∞ | ✅ |

- **Questioni aperte**:
  1. **"DEMO"** e **"Community"** sono lo stesso tier rinominato? Oppure 2 tier distinti?
     - Se stesso rinominato → doc obsoleta, refactor terminology
     - Se diversi → quale stiamo testando? Dove sono le differenze?
  2. **"Personal and small team use"** — cosa include "small team"? 1 user 1 org è "small team" di 1 persona. Terminologia ingannevole
  3. **Push Agents gated**: atteso? La promessa "5 agent limit" della doc suggerirebbe che gli agent sono inclusi fino a 5. Invece qui anche 1 agent è bloccato
  4. **Weighted Units** metric non documentata [03.14.12]
  5. **Community promises**: quali feature sono davvero disponibili out-of-the-box senza license? Dal health check: `License Status: COMMUNITY` e molte pagine funzionano. Ma agent no, e forse compliance reports PDF no, ecc. **Map to be built**
- **Impatto**:
  - Sales pipeline: potenziale cliente non sa che prodotto scaricare o comprare
  - Support burden: "Ho installato il DEMO ma dice COMMUNITY e non funziona l'agent" — ore di triage inutile
  - Marketing website [mappa fase 01] promette "Free for personal use" ma se il cliente installa e trova 1 user/1 org + no push agent, esperienza frustrante
- **Fix candidato (per fase fix, non ora)**:
  - Decidere UN nome ufficiale per il tier free (es. "Community"), aggiornare README, handbook, marketing, email welcome, UI license page, health checks → uniformità
  - Pagina `/pricing` con matrice comparativa ESPLICITA (Community vs Professional vs Enterprise)
  - In-app help / modal "What's included in Community?" con elenco features attive/gated
  - Evitare messaggi come "Invalid API key" quando il motivo reale è "feature gated" → riunire in response consistente "Feature X requires Professional license"
- **Discovered**: 2026-04-23 (domanda dell'utente che ha smascherato un problema di product messaging coerente)

#### [03.14.10] 🔵 Info — Terminology mismatch: "DEMO Edition" (handbook/README) vs "COMMUNITY EDITION" (UI)

- **Fase**: 03
- **Area**: License / terminology
- **Tipo**: 🔵 Info
- **Actual**:
  - Handbook originale / README / mappa architettura: `"DEMO Edition"`
  - UI License page: `"COMMUNITY EDITION"` (anche nel health check "License Status: COMMUNITY")
- **Issue**: terminologia inconsistente tra docs e prodotto. Customer/support confusion
- **Fix candidato**: decidere un unico nome ufficiale ("Community" probabilmente è più friendly che "Demo") e uniformare docs, handbook, marketing, UI
- **Discovered**: 2026-04-23

#### [03.14.11] 🟡 Community limits: Users 1/1 + Organizations 1/1 già al MAX out-of-the-box

- **Fase**: 03
- **Area**: License / Community tier limits
- **Tipo**: 🟡 Warning
- **Severity**: Medium (onboarding UX: primo utente vuole invitare il collega → bloccato subito)
- **Actual**:
  - Users: 1/1 — "You've reached Community limits"
  - Organizations: 1/1 — stessa cosa
  - Banner: "Upgrade to Professional for unlimited usage"
- **Issue**: il primo admin creato al setup wizard è **L'UNICO** utente ammesso in Community. Appena un admin vuole creare un secondo user (es. per SAML/LDAP login o invite team member), arriva al banner "reached limits" subito.
- **Impatto**:
  - DEMO/Community doveva essere "5 agents, 50 products" come da handbook — ma "1 user" è molto più restrittivo
  - Qualsiasi test realistico enterprise blocked da questo limit senza upgrade
- **Inconsistenza con handbook**: handbook parlava di "5 agent" limit ma non di "1 user" — la UI è più stretta di quanto atteso. Terminologia+limiti cambiati silenziosamente?
- **Follow-up TODO 03.14.11a**: provare a invitare un secondo user via `Users & Access → All Users → Invite` → vedere se blocca con errore user-friendly ("Upgrade required") o tecnicamente rotto
- **Discovered**: 2026-04-23

#### [03.14.12] 🔵 Info — "Weighted Units: 0.0" metric non documentato

- **Fase**: 03
- **Area**: License / usage metric
- **Tipo**: 🔵 Info (UX)
- **Actual**: nella Usage card, dopo "Agents: Total 0/5 · Servers 0 · Workstations 0" appare `Weighted Units: 0.0`
- **Issue**: "Weighted Units" non è spiegato in tooltip / helper. Customer non sa cosa siano:
  - Score complessivo di utilizzo?
  - Risorse CPU/memory equivalenti?
  - Metric di billing per pricing variabile?
- **Fix candidato**: tooltip "?" accanto al label con definizione
- **Discovered**: 2026-04-23

---

#### [03.14.5] Settings → Compliance: UI molto ricca ✅

- **Fase**: 03
- **Area**: Settings / Compliance
- **Tipo**: 🟢 OK
- **Content mappato**:
  - **Audit Logs** con:
    - Search box + 4 filtri (All Actions, All Resources, Date from/to)
    - Dropdown 50 per page, Sort by Time, Newest First
    - Columns: TIMESTAMP, ACTION, RESOURCE, USER, IP ADDRESS, DETAILS
    - Export button (JSON/CSV presumibile)
    - Empty state: "No audit logs found matching your criteria"
  - **Compliance Reports** section con:
    - Header: "CISA BOD 22-01 Compliance" + link a directive ufficiale
    - 4 metric cards colored (Total KEV Matches, Acknowledged verde, Pending Review giallo, Overdue rosso) — tutte con valore `-` in empty state
    - Overall Compliance Rate progress bar (vuota)
    - **7 report types disponibili**:
      1. BOD 22-01 Compliance Report (JSON, CSV)
      2. NIS2 Compliance Report (JSON, CSV, PDF)
      3. Overdue Items Report (Download Overdue Report)
      4. Executive Summary (PDF, JSON)
      5. PCI-DSS v4.0 Gap Analysis (JSON, PDF)
      6. ISO 27001:2022 Gap Analysis (JSON, PDF)
      7. SOC 2 Gap Analysis (JSON, PDF)
  - **Pending by Severity** breakdown (Critical/High/Medium/Low/Unknown)
  - **Ransomware Exposure**: "Click 'Refresh Data' to load compliance statistics"
- **Valutazione**:
  - ✅ Audit log infrastruttura completa (search, filter, export)
  - ✅ 7 compliance frameworks coperti, 3 formati di export (JSON/CSV/PDF per la maggior parte)
  - ✅ Empty state chiaro con CTA "Refresh Data"
- **Feature gating**: **strano — visibile su DEMO?** Dalla mappa originale "NIS2/DORA + BOD 22-01 Reports" era gated Pro+, come anche PCI-DSS/ISO/SOC 2 via Compliance Pack paid add-on. **Su on-prem DEMO**, questa pagina mostra TUTTI i report tipi con bottoni attivi. Da verificare cliccando se il download produce un PDF valido o un error 403 "upgrade required"
- **Follow-up TODO 03.14.5a**: cliccare ciascun bottone JSON/CSV/PDF di un report (anche con dati vuoti) per verificare che il download venga generato e non blocchi per feature gate
- **Discovered**: 2026-04-23

---

### 03.13 — CISA / NVD sync (osservazioni di resilience)

#### [03.13.1] NVD online/offline recovery automatico ✅

- **Fase**: 03
- **Area**: Vulnerability data sync / fault tolerance
- **Tipo**: 🟢 OK (resilience behavior)
- **Actual durante la sessione**:
  - Primo osservazione: footer mostrava alert "NVD API returned an error. Fallback sources (CVE.org, ENISA EUVD) will be used." — coerente con `NVD_API_KEY=` vuoto (rate limit 120 req/day senza key, facile da esaurire)
  - Poco dopo: footer mostra "NVD online" → rate limit resettato / NVD riuscita → app re-promuove NVD come sorgente primaria
- **Valutazione**: il fault-tolerance multi-sorgente (NVD → CVE.org/Vulnrichment → ENISA EUVD → vendor feeds) funziona. Il sistema degrada graziosamente e recupera automaticamente quando l'endpoint principale torna disponibile, senza richiedere restart.
- **Follow-up opzionale**: configurare `NVD_API_KEY` (gratuita, `https://nvd.nist.gov/developers/request-an-api-key`) alza la quota a 10K/day ed elimina quasi del tutto il toggling offline/online. Non blocca i test.
- **Discovered**: 2026-04-23

---

#### [03.11.2.9] ⏸️ BLOCKED — Login LDAP `admin.user` → 401, test NON conclusivo finché [03.11.2.3] non è risolto

- **Fase**: 03
- **Area**: LDAP authentication / login flow
- **Tipo**: ⏸️ Test bloccato (non un bug autonomo, ma test non eseguibile)
- **Blocca-chi**: [03.11.2.3] (sidebar LDAP Users sparita) + [03.11.2.2] (form manca Group Mapping)
- **Environment**: on-prem DEMO, beta.6
- **Actual**:
  - `POST /api/auth/login` 401 su `admin.user` / `password123`
  - Backend log LDAP vuoto
- **Interpretazione corretta (via chiarimento utente)**:
  > "Questo user non è stato provisionato. LDAP è connesso ma io come admin non ho accettato l'user. Non posso testarlo se non ho le pagine vecchie di LDAP user control e accettare l'utente su SentriKat."
  - Il flow LDAP **corretto** di SentriKat richiede che un admin, dalla pagina "LDAP Users" (bug 03.11.2.3 — **sparita**), selezioni gli utenti LDAP da **accettare/invitare** prima che possano loggare
  - Un utente LDAP non ancora accettato che tenta login → 401 è **comportamento atteso**, non un bug
  - Senza la pagina di accettazione in sidebar (sparita per regressione mode-gating), non c'è modo di accettare `admin.user` → quindi 401 resta bloccato
  - Il log vuoto è **coerente** con questo: il backend vede un utente sconosciuto, ritorna 401 senza tentare LDAP (non c'è un record utente provisionato → niente da tentare)
- **Non è una regressione di LDAP auth in sé**: è bloccato dalla regressione a monte [03.11.2.3]
- **Riapertura del test (dopo fix di 03.11.2.3)**:
  1. Admin va in `Users & Access → LDAP Users` (voce ripristinata)
  2. Seleziona `admin.user` dalla lista utenti LDAP scoperti + clicca "Accept" / "Invite" / "Provision"
  3. Verifica creazione record utente in "All Users"
  4. Logout + login come `admin.user` / `password123` → **ALLORA** il test del login LDAP sarà significativo
- **Cluster di regressioni LDAP in beta.6** (conferma):
  - [03.11.2.2] (High) Form LDAP manca Group Mapping fields
  - [03.11.2.3] (High) Sidebar Users & Access manca LDAP Users / LDAP Groups — **blocca questo test**
  - [03.11.2.9] ⏸️ Login LDAP 401 → **non è bug autonomo, è conseguenza di 03.11.2.3**
- **Status**: **BLOCKED** — spostato nel backlog "Test bloccati da fix propedeutici" nel 00-INDEX
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

