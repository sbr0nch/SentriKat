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
  → log esplicito dal modulo `app/network_security.py`, con contesto "Jira tracker setup" → **la policy è scritta specificatamente per Jira**, non è un behavior ereditato generico
- **Confermata specificità per Jira**: la stringa "Jira tracker setup" nel log conferma che la validation ha un code path dedicato per Jira separato dagli altri moduli. SMTP/LDAP/SAML usano un code path che rispetta `ALLOW_PRIVATE_URLS`, Jira no. Bug di design consolidato
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

