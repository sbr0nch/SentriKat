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

---

*(aggiornamento incrementale — step 2-6 wizard da testare, quindi primo login, license activation, ecc.)*
