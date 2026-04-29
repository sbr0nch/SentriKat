# Fase 05 — Portal Admin (`portal.sentrikat.com/admin/*`)

> **Scope**: console admin del license-server, accessibile via `ADMIN_API_KEY`/super-admin login. Sidebar con ~25 voci raggruppate in: OVERVIEW, EARLY ACCESS, SALES PIPELINE, CUSTOMER SUPPORT, BILLING & LICENSING, PRODUCT INTELLIGENCE, SYSTEM.
>
> **Sessione apertura**: 2026-04-28/29 (PC casa con docker + testlab disponibili).
> **Auth corrente**: super-admin loggato come `sotadenis94@gmail.com` (vedi [05.6.2]).
> **Acquisizione**: 8 screenshot delle pagine principali del gruppo PRODUCT INTELLIGENCE + SYSTEM. Sidebar gruppi BILLING & LICENSING (Customers/Licenses/Activations/Pricing/Plans) marcati `POST-EA` o `READ-ONLY` → ancora da testare.

---

## Pagine coperte in questa apertura

| ID | Path | Stato |
|---|---|---|
| 05.1 | `/admin/releases` | 🔴 1 bug, 🔵 1 info |
| 05.2 | `/admin/kb` | 🟡 1 warn |
| 05.3 | `/admin/datasources` | 🔴 1 bug |
| 05.4 | `/admin/status` | 🔴 1 bug (mismatch con 05.3) |
| 05.5 | `/admin/logs` | 🔴 1 bug, 🟡 1 warn |
| 05.6 | `/admin/users` | 🔴 1 bug, 🔵 1 info |
| 05.7 | `/admin/runbook` | 🟢 OK |
| 05.8 | `/admin/settings` | 🔴 1 bug, 🟡 1 warn, 🟢 OK quick actions |
| 05.10 | `/admin/customers` | 🟢 OK 7-dim (3 customer attivi) |
| 05.11 | `/admin/leads` | 🟢 OK happy/CRUD (1 lead seed) |
| 05.12 | `/admin/demo-requests` | 🟢 OK happy (empty state) |
| 05.13 | `/admin/newsletter` | 🔴 1 bug (subscribers list 403 "Invalid admin key") |
| 05.14 | `/admin/support` | 🔵 1 info (CSS class leak in stat card) |
| 05.15 | `/admin/canned-responses` | 🟢 OK (empty state) |
| 05.16 | `/admin/health` | 🔵 1 info (semantica "healthy" su zero-data) |
| 05.17 | `/admin/feedback` | 🔵 1 info (possibile mancanza dedup), 🟢 2 entry seed |
| 05.18 | `/admin/licenses` (POST-EA) | 🟢 OK (empty as expected) |
| 05.19 | `/admin/activations` (POST-EA) | 🔵 1 info (UX redundancy), 🟢 OK empty |
| 05.20 | `/admin/pricing` (Pricing Calculator) | 🔵 2 info (purpose docs, terminology) |
| 05.21 | `/admin/plans` (Subscription Plans) | 🔴 1 HIGH (price mismatch 3 fonti), 🔵 1 info (`-1` placeholder leak) |
| 05.22 | `/admin/saas-tenants` (EA Tenants) | 🔴 1 HIGH (stats 401 "Admin API key required"), 🟢 6 tenant live OK |
| 05.23 | `/admin/webhook-outbox` (Webhook Outbox) | 🟢 OK empty state |
| 05.24 | `/admin/usage-metrics` (Usage Metrics) | 🔵 1 info (telemetria API calls/Scans sempre 0) |

## Pagine ancora NON aperte (sidebar)

Audit Log dedicato (visibile via Settings → "Go to Audit Log") + Status & Incidents sub-views (drill-down per singolo incident) — **nessuna pagina principale resta da mappare**.

---

## 05.1 — `/admin/releases` (Releases)

**Layout**: 4 KPI tile (Total Releases, Latest Version, Deprecated, CVE Findings) + bottoni "Sync from GitHub" e "+ Manual Release" + lista "All Releases" (empty state).

### Findings

- 🔴 **[05.1.1] Releases vuoto vs `/api/health` 1.0.0-beta.6** (HIGH)
  - Total Releases: **0** · Latest Version: **-** · Deprecated: 0 · CVE Findings: 0
  - Ma `/api/health` (verificato in [03.5.3]) restituisce `1.0.0-beta.6`, e questa è la versione effettivamente deployata in prod.
  - Diagnosi probabile: il job di "Sync from GitHub" non è mai stato eseguito, oppure pipeline release/changelog non popola questo endpoint.
  - Impatto: la "Releases page" pubblica/admin è sempre vuota → impossibile tracciare changelog, deprecation, CVE per release.
  - Repro: aprire `/admin/releases` → tutto a zero. Cliccare "Sync from GitHub" e verificare che si popoli (test da fare oggi col docker su).

- 🔵 **[05.1.2] CVE Findings: 0 ma KB ha 64.697 mappings** (INFO)
  - Possibile by-design (CVE per-release, non per KB globale), ma andrebbe documentato cosa significa esattamente "CVE findings" qui — se è "CVE che colpiscono UNA delle nostre release" allora 0 è coerente con [05.1.1] (non ci sono release).
  - Azione: chiarire label o aggiungere tooltip.

### Test follow-up (oggi con docker)

- [ ] Cliccare "Sync from GitHub" → verificare popolamento + audit log entry.
- [ ] Cliccare "+ Manual Release" → testare CRUD release manuale + validation.
- [ ] 7-dim dim 6: tentare manual release con version invalida (es. `not-semver`).

---

## 05.2 — `/admin/kb` (KB Mappings)

**Layout**: Database Overview (Total/Published/Verified/Last NVD Sync) + 4 KPI tile (Total Mappings, Pending Review, Verified, Contributors) + filtro (Search · `Community` dropdown · All Status · Filter button) + lista "KB Mappings".

### Findings

- 🟢 **NVD sync HEALTHY** — 64.697 mappings totali, tutti verified, tutti published, last sync 2026-04-27 08:26 (status: healthy today). Eccellente.
- 🟡 **[05.2.1] Filter "Community" mostra "No mappings found"** (WARN)
  - Filtro default su dropdown è `Community`, e con quel filtro la lista sotto è **vuota** ("No mappings found").
  - Solo togliendo il filtro (o scegliendo un'altra opzione) si vedrebbero i 64.697.
  - UX issue: l'utente atterra sulla pagina e vede "0 mappings" sotto, mentre i KPI sopra dicono 64.697 → confusione.
  - Probabile fix: default filter a "All" invece che "Community".
- 🔵 **Contributors: 0** — coerente con prod nuova senza installazioni community che pubblicano mapping.

### Test follow-up

- [ ] Provare ogni opzione del dropdown filter, verificare che almeno una popoli la lista.
- [ ] 7-dim dim 6: search con SQL injection / XSS / unicode.
- [ ] Cliccare "Sync NVD" (top-right) → verificare audit log + che il counter "Last NVD Sync" si aggiorni.
- [ ] Verificare un singolo KB mapping (CVE → CPE) per controllare correttezza dato.

---

## 05.3 — `/admin/datasources` (Data Sources)

**Layout**: 4 KPI tile (Total Sources, Healthy, Degraded, Down) + card per ogni source con "Probe" button + tabella "Health Check History".

### Findings

- 🔴 **[05.3.1] Data source "Unknown" in stato Critical/DOWN, senza identificativo** (HIGH)
  - 1 source totale, 0 healthy, **1 DOWN (Critical)**.
  - Card mostra: nome **"Unknown"**, status badge **UNKNOWN**, Response: `-`, Last Check: `-`. Nessun nome, nessun URL, nessuna data ultima probe.
  - "Health Check History" vuota → mai stata fatta una probe automatica.
  - Diagnosi probabile: seed/migration ha inserito una riga senza populating dei campi `name`/`url`, oppure il config loader non riesce a leggere `data_sources.yaml`/env.
  - Impatto: KPI "Down: 1 Critical" sempre rosso anche se in realtà non c'è una vera source down — è una source mai configurata. Falso allarme permanente.
  - Repro: aprire `/admin/datasources` → vedere card "Unknown" rossa.

### Test follow-up

- [ ] Cliccare "Probe" sulla card "Unknown" → verificare che tipo di errore arriva (network? config missing? null URL?).
- [ ] Cliccare "Probe All Sources" (top-right) → verificare audit log + history popolata.
- [ ] Indagare nel DB on-prem: `SELECT * FROM data_sources;` → vedere se la riga è bonafide o un orfano.
- [ ] 7-dim dim 3 CRUD: come si crea/modifica una data source? Manca un UI per aggiungere/editare?

---

## 05.4 — `/admin/status` (Status & Incidents)

**Layout**: bottoni "Reset All Uptime History" + "View Public Status Page" + sezioni "Active Incidents & Maintenance" e "Incident History".

### Findings

- 🔴 **[05.4.1] Public status dichiara "All systems operational" mentre `/admin/datasources` mostra 1 source DOWN/Critical** (HIGH)
  - Sezione "Active Incidents & Maintenance" → testo verde: *"No active incidents. All systems operational."*
  - Ma in [05.3.1] una data source è Critical/Down.
  - Mismatch: la status page **non legge** lo stato delle data source per popolare automaticamente gli incidents. È puramente manuale ("+ New Incident", "Schedule Maintenance").
  - Impatto: customer e public vedono "tutto verde" anche quando un componente backend è giù → degrado della affidabilità della status page. **Per una piattaforma che si chiama "monitoraggio vulnerabilità", una status page disonesta è un problema reputazionale.**
  - Fix proposto: integrare datasources health check → auto-incident creation quando una source è Down per >N minuti.

### Test follow-up

- [ ] Cliccare "+ New Incident" → testare CRUD incidents (dim 3) + che pubblichi davvero su public status page (dim 7).
- [ ] Cliccare "Schedule Maintenance" → testare scheduling + che apparirebbe il banner di manutenzione lato customer.
- [ ] Cliccare "View Public Status Page" → verificare l'URL pubblico (probabilmente `status.sentrikat.com` o `/status`) e cosa vede un visitatore.
- [ ] Cliccare "Reset All Uptime History" → 🟡 **destructive action**, verificare che ci sia conferma modal e audit log.

---

## 05.5 — `/admin/logs` (Centralized Logs)

**Layout**: filtri (All Sources · All Actions · All Actors · Search · Actor email · IP address · date range) + 5 KPI tile (Total/Audit/Activation/SaaS/Today) + banner "Retention Policy" + tabella "All Logs".

### Findings

- 🟢 **[05.5.1] Centralized Logs completamente vuoto durante una sessione admin attiva** (HIGH — ✅✅ FIXED + VERIFIED post-deploy `23ce9da`)
  - **Era**: `/admin/logs` Total/Audit/Activation/SaaS = 0 anche durante sessione admin attiva.
  - **Fix `sentrikat-web` commit `31805d6`**: `/admin/auth/login` emette `LOGIN_SUCCESS` / `LOGIN_FAILED` con `details.reason` su ogni outcome via `log_admin_action`. `/admin/users` POST/PATCH/DELETE emettono `ADMIN_ACTION` con operatore + target.
  - **✅ VERIFIED 2026-04-29 (utente)**: dopo deploy 23ce9da + login fresh, `/admin/logs` e `/admin/audit` ora popolati. **Comportamento confermato by-design**: gli eventi audit sono scritti SOLO per accessi via account (login UI), NON per chiamate via `ADMIN_API_KEY` programmatica. Corretto: l'API key è un agent secret e non ha "user identity" da loggare nello user audit trail.

- 🟡 **[05.5.2] Retention policy mostrata qui (365d audit) ≠ retention policy in `/admin/settings` (730 DAYS audit)** (WARN)
  - Banner qui: *"Retention Policy: Activation logs: 90 days · Audit logs: **365 days** · SaaS logs: 90 days · System logs: 30 days (Docker)"*.
  - In `/admin/settings` → Data Retention Policy: Audit Logs **730 DAYS**.
  - Una delle due UI è mentendo, oppure leggono da config diverse. Va riconciliato.

### Test follow-up

- [ ] Generare un evento ovvio (logout + re-login) e ricaricare `/admin/logs` → vedere se appare. Se NO → bug confermato HIGH.
- [ ] Provare ogni filtro (Source/Action/Actor/IP/date) per verificare che query funzioni.
- [ ] Cliccare "CSV" e "JSON" export → verificare contenuto + audit log entry per l'export.
- [ ] Verificare DB on-prem: `SELECT COUNT(*) FROM audit_log;` per capire se è il logger morto o solo la UI.

---

## 05.6 — `/admin/users` (Admin Users)

**Layout**: 3 KPI tile (Total Users, Active, Super Admins) + tabella "Team Members" + tabella "Role Permissions" (matrice Area × Role: Super Admin / Admin / Support / Sales / Ops / Viewer).

### Findings

- 🟢 **Permissions matrix** ben strutturata e leggibile. Differenziazione coerente: Super Admin = Full ovunque; Admin = Full su tutto tranne nessun accesso a "Settings"; Support/Sales/Ops/Viewer con scopi limitati. ✅
- 🟢 **[05.6.1] Last Login `-` per super-admin attualmente loggato** (HIGH — ✅✅ FIXED + VERIFIED post-deploy `23ce9da`)
  - **Era**: `Last Login: -` per super-admin in `/admin/users`, anche dopo OTP login fresh.
  - **Fix `sentrikat-web` commit `31805d6`**: `admin.py:171` ora scrive `user.last_login_at = datetime.utcnow()` su ogni successful `/admin/auth/login` (e `portal.py:373` per OTP customer).
  - **✅ VERIFIED 2026-04-29 (utente)**: dopo logout/login fresh, `/admin/users` mostra timestamp del login corrente. Bug chiuso definitivamente.

- 🔵 **[05.6.2] Super-admin di produzione usa email gmail personale** (INFO/governance)
  - Email: `sotadenis94@gmail.com`. Per una piattaforma B2B in fase Early Access è un governance smell:
    - Se il dominio gmail viene compromesso, perde accesso il founder + l'azienda.
    - Audit/compliance preferiscono `admin@sentrikat.com` con MFA enforced.
  - Action: creare almeno un secondo super-admin su email aziendale, e migrare il primario su email custodial (questa è una decisione utente, non un bug del codice).

### Test follow-up

- [ ] Cliccare "+ New User" → creare admin secondario, verificare email invito + che appaia in tabella.
- [ ] Cliccare "Edit" / "Disable" / "Delete" sull'utente esistente → testare CRUD (dim 3). ⚠️ NON disabilitarsi da soli → testare con il secondo user.
- [ ] 7-dim dim 4 RBAC: loggarsi come ogni ruolo e verificare che la matrice di Role Permissions sia rispettata effettivamente (es. un Viewer può aprire `/admin/customers` in read?).
- [ ] 7-dim dim 6: invite con email malformata, ruolo invalido, lockout dopo N failed login.

---

## 05.7 — `/admin/runbook` (Architecture Runbook)

**Layout**: documento embedded "SentriKat Architecture & Scaling Runbook" con sezioni: 1. Overview · 2. Architecture at a glance (sub: 2.1 Component topology) · …

### Findings

- 🟢 **OK** — runbook visibile, ben formattato, dichiara "single source of truth" + "Golden rule: if this document and the code disagree, the code wins". Buona pratica.
- 🔵 **[05.7.1] Missing "Last updated" date / changelog** (INFO)
  - Il banner dice *"Keep in sync with production. Update on every infra / contract PR."* ma **non** mostra l'ultima data di aggiornamento né l'autore. Senza quel timestamp, la "golden rule" è retorica.
  - Action: aggiungere footer con `Last updated: <YYYY-MM-DD>` + link al commit GitHub che lo ha modificato.

### Test follow-up

- [ ] Scrollare tutto il runbook → verificare che le sezioni 2.1 (Component topology), 9 (Change log) siano popolate e coerenti con `app.sentrikat.com` + `portal.sentrikat.com`.
- [ ] Verificare se il runbook è solo lettura o se admin può editarlo da UI (dim 3 CRUD).

---

## 05.8 — `/admin/settings` (Settings)

**Layout**: header con riga summary (`v1` / `Apr 27 2026, 12:46 PM` / `Connected` / `3` / `-` / `-`) + 4 sezioni:

1. **Environment Configuration** — tabella var → status (CONFIGURED / NOT SET).
2. **Quick Actions** — 4 card: Sync GitHub Releases · Sync NVD Database · Probe Data Sources · Export Audit Log.
3. **Data Retention Policy** — tabella log type → retention/total/expiring/oldest entry/notes.
4. **SaaS & Cloud Migration Readiness** (parzialmente visibile).

### Env Configuration osservata

| Variable | Status |
|---|---|
| `ADMIN_API_KEY` | CONFIGURED |
| `DATABASE_URL` | CONFIGURED |
| `RESEND_API_KEY` | CONFIGURED |
| `EMAIL_FROM` | CONFIGURED |
| `GITHUB_TOKEN` | CONFIGURED |
| `GITHUB_REPO` | CONFIGURED |
| `PUBLIC_API_URL` | CONFIGURED |
| `RSA_PRIVATE_KEY` | **NOT SET** 🔴 |
| `NVD_API_KEY` | **NOT SET** 🟡 |
| `STRIPE_SECRET_KEY` | CONFIGURED |
| `STRIPE_WEBHOOK_SECRET` | CONFIGURED |

### Findings

- 🔴 **[05.8.1] `RSA_PRIVATE_KEY = NOT SET` in produzione** (HIGH)
  - Se il license server firma le license con questa chiave (vedi `AGENT_SIGNING.md` / `docs/ADMIN_GUIDE.md`), allora le license generate sono **non firmate** o il sign step è failed silently.
  - Possibile spiegazione benigna: la chiave è stata spostata in DB (vault) invece che in env, e il check qui non riflette. → Da verificare nel codice.
  - Impatto se davvero non firmata: agent può rifiutare la license, oppure non c'è proof of authenticity → rischio di license forgery.
  - Correlato: in [03.5.3] / [03.12.14] abbiamo testato license activation → se ha funzionato, allora la chiave è da qualche altra parte. Il bug qui è la UI che dice "NOT SET" senza distinguere "non in env, ma in vault".

- 🟡 **[05.8.2] `NVD_API_KEY = NOT SET`** (WARN)
  - NVD sync risulta HEALTHY (vedi 05.2) → significa che senza API key NIST applica rate limit basso (5 req / 30s anonymous vs 50 req / 30s authenticated).
  - Impatto: sync iniziale lento, possibili throttling intermittenti. Non blocca, ma da configurare prima di scalare.

- 🟢 **[05.8.3] Quick Actions ben progettati** — 4 azioni con label chiara + descrizione + bottone unico ("Sync Now" / "Probe All" / "Go to Audit Log"). Mantenere questo pattern. ✅
- 🟢 **[05.8.4] Data Retention Policy** — tabella chiara con retention per tipo log + nota "Cleanup schedule: Daily at 03:00 UTC · Last checked: Apr 27 2026". ✅ (ma vedi mismatch [05.5.2]).

### Test follow-up

- [ ] Cliccare ogni Quick Action → verificare che parta il job, audit log entry, success/error feedback.
- [ ] "Run Cleanup Now" (in Data Retention) → ⚠️ destructive, verificare modal di conferma + audit log.
- [ ] 7-dim dim 4: verificare che SOLO Super Admin veda `/admin/settings` (la matrice in 05.6 dice Settings = Full solo per Super Admin).
- [ ] Indagare nel codice: `RSA_PRIVATE_KEY` lookup — env-only o anche DB/vault? Aggiornare la UI per riflettere "configured via vault" se applicabile.
- [ ] Scrollare sotto "SaaS & Cloud Migration Readiness" → mappare contenuto in un nuovo sub-finding.

---

---

## 05.9 — Bug trovati durante re-test 2026-04-29

### `[05.9.1]` 🔴🔴 **CRITICAL** — Intera UI admin morta ai click: CSP `script-src-attr` blocca TUTTI gli inline handler

**ESCALATION 2026-04-29**: scoperto che NON è solo "Sign Out" — utente conferma che **tutti** i bottoni dell'admin sono incliccabili: Export CSV/JSON, campanellina notifiche, Sign Out, e per estensione presumibilmente anche `+ New User`, `+ New Incident`, `Probe`, `Sync from GitHub`, `Sync NVD`, `Sync Now`, `Probe All`, `Filter`, `Clear`, `Edit`, `Disable`, `Delete`, `Reset All Uptime History`, `Run Cleanup Now`, `Refresh`, `Go to Audit Log`, `+ Manual Release`, `Schedule Maintenance`. **L'intero portal admin è in pratica read-only forzato**, ma per bug, non per design.

- Console browser mostra ripetuti errori CSP su ogni click:
  ```
  Content-Security-Policy: Le impostazioni della pagina hanno bloccato l'esecuzione
  di un gestore eventi (script-src-attr) in quanto viola la seguente direttiva:
  "script-src 'self' 'nonce-ce4aae40edc7df44b92117a9fafba33b'".
  Considerare l'utilizzo di un hash ("sha256-y0nKik4dM+1fXZh10edAXaR/Ck6G362K0i51lEfsER4=")
  insieme a "unsafe-hashes". admin:702:7
  ```
  + warning identici con hash diversi (`sha256-7X/TEBMYawkpLTmqph9jNMqmP7vLvBcPZkLBLwPk8G8=`, ecc.) — ogni hash corrisponde a un `onclick=""` distinto in pagina.
- Diagnosi: il template HTML del portal admin usa `onclick=""` inline (HTML attribute event handler) su tutti i bottoni, ma il CSP del portal admin ha `script-src 'self' 'nonce-...'` SENZA `'unsafe-inline'` né `'unsafe-hashes'` con gli sha corretti, e senza `script-src-attr 'unsafe-inline'`. Conseguenza: tutti gli handler inline sono bloccati silenziosamente.
- File coinvolto (dal log): `admin:702:7` → uno dei template Jinja `/admin/<page>.html` o un layout/partial condiviso. Linea 702 è probabilmente in un layout comune (sidebar/header).
- Impatto:
  - **Session non chiudibile**.
  - **Nessuna azione amministrativa eseguibile dalla UI** (sync, probe, CRUD, export, manutenzione).
  - L'unico modo per amministrare è API diretta con `ADMIN_API_KEY` o accesso DB.
  - In Early Access con un solo super-admin → operatività zero dalla UI.
- Correlato a [04.2.1] CSP portal regression (lato customer, già fixato in `42d7ea0`) — stesso pattern, qui sull'admin layout.
- Fix proposto (in ordine di preferenza):
  1. Sostituire tutti gli `onclick=""` inline con `data-action="..."` + un singolo `<script nonce="{{ csp_nonce }}">` esterno che legge `data-action` e fa `addEventListener` (pattern unobtrusive JS).
  2. Oppure: aggiungere `'unsafe-hashes'` + lo sha256 di ogni handler nella CSP (fragile, hash da rigenerare ad ogni cambio).
  3. Sconsigliato: aggiungere `'unsafe-inline'` (rompe la security posture, motivo originale del CSP nonce-based).
- Repro: aprire `/admin/<qualsiasi>`, click "Sign Out" o qualunque bottone → nessuna azione, console F12 mostra warning CSP.

**⏸️ BLOCKING**: i seguenti test follow-up sono BLOCCATI da [05.9.1] finché non viene fixato:
- 05.1: click "Sync from GitHub" / "+ Manual Release"
- 05.2: click "Sync NVD" / search filter
- 05.3: click "Probe" / "Probe All Sources"
- 05.4: click "+ New Incident" / "Schedule Maintenance" / "Reset All Uptime History"
- 05.5: click "CSV" / "JSON" export, click "Filter"
- 05.6: click "+ New User" / "Edit" / "Disable" / "Delete"
- 05.8: click ogni Quick Action / "Run Cleanup Now" / "Refresh"
- Sign Out (universale)

### `/admin/audit` — pagina **dedicata audit log**, anch'essa vuota (HIGH — stesso root cause di [05.5.1])

Scoperta nuova: il sidebar ha **due** voci log distinte:
- `/admin/logs` (gruppo "Centralized Logs", riga `Logs / Audit` nella matrice permessi 05.6) → KPI: Total / Audit / Activation / SaaS / Today.
- `/admin/audit` (gruppo "SYSTEM" → `Audit Log`) → KPI: Total Events / Today / This Week / This Month.

Entrambe mostrano 0 entries dopo OTP login fresh. Stesso bug HIGH già tracked come `[05.5.1]`.

- 🔵 **[05.9.2]** Due pagine diverse per "audit log" (Centralized Logs vs Audit Log) — possibile duplicato UI o concettualmente distinte (centralized = aggregator, audit = security trail). Va chiarito + tooltip + label coerenti, oppure unificate.

---

## 05.10 — `/admin/customers` (Customers)

> Sessione 2026-04-29. Super-admin loggato. Tutti i 7-dim ✅ confermati dall'utente sullo screenshot inviato.

### Findings

- 🟢 **Happy path**: pagina carica, 4 stat card (Total `3`, Active `3`, Inactive `0`, Verified `3`) coerenti con la tabella sotto.
- 🟢 **Tabella**: 3 customer (`muscleaddiction49`, `Alex Vecchi` con company `Vecchi Enterprise LTD`, `Denis Sota`). Colonne: Name, Email, Company, Licenses, Verified, Status, Last Login, Created, Actions.
- 🟢 **Action set per riga**: 8 azioni (`ID copy`, `Licenses`, `Suspend`, `OTP`, `Notes`, `Ticket`, `Export`, `Delete trash`). Coverage CRUD completa.
- 🟢 **Search**: campo "Search by name, email, or company" presente in top.
- 🟢 **CTA "+ New Customer"** in top-right → creazione disponibile.
- 🟢 **Last Login** popolato per `muscleaddiction49` (`Apr 27, 2026, 12:31 PM`) e `Denis Sota` (`Apr 26, 2026, 12:41 PM`) → sblocca anche follow-up `[05.6.1]` (last_login persistence) per via traversa.
- 🟢 **dim 4 RBAC**: confermato che `/admin/*` richiede super-admin (badge "Super Admin" in sidebar).
- 🟢 **dim 6 negative**: tested by user.
- 🟢 **dim 7 audit**: tested by user — azioni admin ora finiscono in `[05.5.1]` audit log (cluster già verificato).

### Test follow-up

- Stress: creare 50+ customer e verificare paginazione/lazy-load (oggi solo 3, paginazione non testabile).
- Action `Suspend` flow E2E (cambia status `Active`→`Suspended`, riflette su Customer Health, audit log entry?).
- Action `OTP` flow: cosa fa? rigenera OTP? invia email? Verificare con Mailpit.
- Action `Export` per-row: che formato (CSV/JSON), include licenses+activations?

---

## 05.11 — `/admin/leads` (Leads Pipeline)

> Sessione 2026-04-29. 1 lead seed (`Smoke / Test SRL / WEBSITE / new / priority MEDIUM`). 7-dim happy/CRUD verificato.

### Findings

- 🟢 **Header**: titolo "Leads Pipeline", CTA `+ Add Lead`, `Export CSV`.
- 🟢 **Stat cards** (4): Total Leads `1`, Pipeline Value `EUR 0`, Avg Score `0/100`, Followups Due `0` ("All caught up").
- 🟢 **Filtri**: Search (name/company/email/title), Status, Priority, Sources, Refresh.
- 🟢 **Tabella Pipeline**: `1 lead`, colonne Priority, Name, Company, Title, Source, Status, Score, Value, Next Action, Actions.
- 🟢 **Currency EUR** consistente (vs `$` USD del bug `[02.4.2]` che era su welcome email — qui è OK).
- 🟢 **Score 0/100** placeholder ragionevole per lead `new` senza scoring.
- 🟢 **Action icons** per riga: `Detail/expand` (chevron) + `Delete`.
- 🟢 **Sidebar full visibile** (Super Admin): conferma struttura completa documentata in cluster `[05.10]`–`[05.14]`.

### Test follow-up

- Demo `Add Lead` form (campi obbligatori, validation, audit entry).
- Edit lead dal Detail → cambia status `new`→`contacted`→`qualified`→`won/lost`, verifica cascade su pipeline value + audit log.
- Filtro Source = WEBSITE/EMAIL/REFERRAL/ecc. funzionante (oggi 1 sola source `WEBSITE`).
- `Followups Due` calcolo: cosa scatta (data > now su `next_action_date`?). Test seed con followup arretrato.

---

## 05.12 — `/admin/demo-requests` (Demo Requests)

> Sessione 2026-04-29. Empty state — coverage limitata a happy path UI.

### Findings

- 🟢 **Header**: titolo "Demo Requests", filtri Search + Status + bottone Filter.
- 🟢 **Stat cards** (4): Total `0`, Pending `0` ("All processed"), Approved `0`, Rejected `0`.
- 🟢 **Tabella**: colonne Date, Name, Email, Company, Size, Terms, IP Address, Status, Actions. Empty: "No demo requests found".
- 🟢 **IP Address column** presente → utile per anti-spam audit.
- 🟢 **Terms column** → conferma Demo Requests ha checkbox legale (cross-ref `[02.2.1]` validation DE su sito EN).

### Test follow-up

- Compilare demo request da landing page (`sentrikat.com`) → verifica appare qui in `pending`.
- Test action Approve/Reject (oggi non visibile per via empty).
- Verifica rate-limit: 5 demo request consecutive da stesso IP devono bloccare/segnalare.
- Cross-ref Mailpit: approval/rejection trigger email al richiedente?

---

## 05.13 — `/admin/newsletter` (Newsletter)

> Sessione 2026-04-29. **🔴 BUG aperto**: subscribers list non carica per auth fail.

### Findings

- 🟢 **Compose form** rendering OK: campi Subject, Card Title, Body (HTML) con placeholder template `<p style='color: #d1d5db;'>Your newsletter content here...</p>`.
- 🟢 **CTA `Send to All Subscribers`** presente.
- 🔴 **`[05.13.1]`** **HIGH** — Subscribers list 403 "Invalid admin key" (vedi sotto).

### `[05.13.1]` 🔴 **HIGH** — Subscribers list endpoint risponde 403 "Invalid admin key"

**Sintomi**:
- Sezione "Subscribers" sotto il compose form resta in stato `Loading...` indefinitamente.
- DevTools console: `XHR GET https://portal.sentrikat.com/api/v1/newsletter_… → HTTP/3 403`.
- Toast bottom-right rosso: **"Failed to load: Invalid admin key"**.

**Impatto**:
- Page funzionalmente rotta: super-admin non può vedere chi è iscritto, contare subscribers, esportare lista, rimuovere singoli.
- Compose + Send è in teoria possibile (form non bloccato) ma diventa "shoot in the dark" — non sai a quanti stai mandando.
- Privacy/GDPR: super-admin che vuole rispondere a richiesta art. 15 GDPR ("dimmi cosa hai di me") non ha modo di trovare l'email del richiedente.

**Sospetto root cause** (da confermare con codice `SentriKat-web/portal-admin`):
- Stesso pattern del cluster `[05.9.1]`: endpoint `/api/v1/newsletter_…` richiede header `X-Admin-Key` ma il fetch lato client non lo allega (probabile regressione del refactor session→key auth).
- Differenza rispetto a `[05.9.1]` (che era CSP `script-src-attr`): qui il problema è auth header, NON CSP. Il fix one-shot CSP `23ce9da` non lo copre. Va indagato lato backend `license-server` quale endpoint serve `/api/v1/newsletter_*` e quale auth si aspetta.

**Severity = HIGH**: feature di prodotto inutilizzabile end-to-end. Deployment scope: `🌐 portal admin` (`SentriKat-web` repo) + possibile fix lato `🔐 license-server` (FastAPI) se l'endpoint è esposto da lì.

### Test follow-up (post-fix)

- Verifica subscribers list popola.
- Test Send to All Subscribers con seed di 2-3 subscriber → arrivo email su Mailpit (testlab) o real inbox.
- Audit log entry per ogni newsletter inviata (cluster `[05.5.1]`).
- Unsubscribe link nella newsletter → click → status passa a `unsubscribed` → email non più ricevuta.

---

## 05.14 — `/admin/support` (Support Tickets)

> Sessione 2026-04-29. Empty state. **🔵 BUG cosmetico**: leak nome classe CSS in stat card.

### Findings

- 🟢 **Header**: titolo "Support Tickets", CTA `+ New Ticket`.
- 🟢 **Filtri completi**: All Status, All Priority, All Categories, Search, bottoni Filter + Clear.
- 🟢 **Stat cards** (4): Total `0`, Open `0`, In Progress `0`, Resolved `0`.
- 🟢 **Tabella**: Ticket, Subject, Customer, Category, Priority, Status, Replies, Created. Empty: "No tickets found".
- 🔵 **`[05.14.1]`** Leak CSS class `badge-green` nello stat card "Resolved" (vedi sotto).

### `[05.14.1]` 🔵 **INFO/UX** — Stat card "Resolved" stampa testo `badge-green` come label

**Sintomo**:
- Sotto il numero `0` della stat "RESOLVED" appare il testo letterale **`badge-green`** in colore verde.
- Dovrebbe essere o (a) niente, o (b) un sotto-testo tipo "All resolved" (come `[05.12]` Demo Requests "All processed").
- Sembra che la variabile `subtitle_class` (es. `text-success` / `badge-green`) sia stata stampata come `subtitle_text` per errore nel template.

**Impatto**:
- Solo cosmetico, non blocca funzionalità.
- UX: utente confuso da stringa tecnica esposta in UI; suggerisce template incompleto / merge sbagliato.

**Severity = INFO**: bug di lavorazione template, non di prodotto. Deployment scope: `🌐 portal admin` (`SentriKat-web/portal-admin`).

### Test follow-up

- Aprire un ticket dalla customer-side (`portal.sentrikat.com/support`) → verifica appare qui con status `Open`.
- Workflow ticket: Open → In Progress → Resolved → Closed (state transitions dim 5).
- Reply admin → email customer → audit log entry.
- Filter Category con seed (security, billing, technical, ...) → coverage dim 6.

---

## 05.15 — `/admin/canned-responses` (Response Templates)

> Sessione 2026-04-29. Empty state. Coverage UI happy path.

### Findings

- 🟢 **Header**: titolo "Response Templates", CTA `+ New Template`.
- 🟢 **Filtro**: `All Categories` dropdown.
- 🟢 **Empty state copy** "No templates yet. Create your first response template to speed up support." — buona UX (action-oriented, non solo "no data").

### Test follow-up

- Crea template (subject, body, category, tags) → appare in Support Tickets reply UI?
- Categorie predefinite (security/billing/technical/...) o free-form?
- Variable substitution (es. `{{customer.name}}`) supportato? Test con un template e una reply.
- RBAC: solo super-admin può creare/editare? customer support agent solo usare?

---

## 05.16 — `/admin/health` (Customer Health)

> Sessione 2026-04-29. Pagina dashboard di "alerting" customer-side. Tutti gli indicatori a 0.

### Findings

- 🟢 **6 stat card** in top: Expiring (7D) `0`, Expiring (30D) `0`, Inactive Installs `0`, Failed Activations `0`, Locked Accounts `0`, Open Tickets `0`.
- 🟢 **4 sezioni** dettagliate sotto:
  - **Expiring Licenses (30 days)** — colonne Customer, Company, License, Edition, Expires, Days Left, Actions. Empty: "All licenses healthy".
  - **Inactive Installations (7+ days)** — Customer, Hostname, OS, Version, Last Seen, Days Inactive. Empty: "All installations active".
  - **Failed Activations (7 days)** — Time, Installation ID, License, IP, Details. Empty: "No failed activations".
  - **Locked Accounts** — Customer, Email, Failed Attempts, Locked Until, Actions. Empty: "No locked accounts".
- 🔵 **`[05.16.1]`** Semantica "All ... healthy" su zero-data (vedi sotto).

### `[05.16.1]` 🔵 **INFO/UX** — Empty state non distingue "nessun dato" da "tutto sano"

**Sintomo**:
- "Expiring Licenses (30 days)" → empty state "**All licenses healthy**". Ma i 3 customer in `[05.10]` hanno colonna Licenses = `0` (nessuna licenza emessa). Quindi non c'è "salute" buona, c'è **assenza totale di licenze** da monitorare.
- Stesso pattern per "All installations active" (zero installation, non "tutte attive") e "No failed activations" (zero attivazioni totali, non solo zero failed).

**Impatto**:
- Super-admin che apre questa pagina vede tutto verde e crede di avere customer attivi sani. In realtà non ha mai venduto una licenza (stato pre-EA atteso, ma il dashboard non lo dice).
- Rischio falsa sicurezza in fase di scale-up: quando il primo customer paga, il dashboard non distingue "0 license OK perché nuovo customer" da "0 license OK perché tutto bene".

**Suggerimento**:
- Empty copy con denominator: "0 of 0 licenses expiring" / "Monitoring 0 installations" / "No license activity in the last 7 days".
- Oppure card top con "Total Customers / Total Licenses" così il super-admin sa il denominator a colpo d'occhio.

**Severity = INFO**: cosmetico-strategico, non blocca funzionalità. Deployment scope: `🌐 portal admin`.

### Test follow-up

- Seed 1 license che scade in 5 giorni → verifica appare in "Expiring (7D)" + sezione Expiring Licenses.
- Seed 1 installation con `last_heartbeat = NOW() - 8 days` → verifica "Inactive Installs" sale a 1.
- Trigger 6 failed login per un user → verifica appare in "Locked Accounts" (cluster `[05.6]`).
- Action su Locked Accounts: cosa fa il bottone "Actions"? Unlock? Reset password?

---

## 05.17 — `/admin/feedback` (Feedback)

> Sessione 2026-04-29. 2 entry seed (utente test `muscleaddiction49` ha smoke-tested il bug report). Coverage 7-dim happy + dim 7 audit nuovo.

### Findings

- 🟢 **Header**: titolo "Feedback".
- 🟢 **Stat card (4)**: Total `2`, Bugs `2`, Features `0`, Open `2` "Needs attention".
- 🟢 **Filtri**: Search feedback, All Types, All Statuses.
- 🟢 **Tabella "Bug Reports & Feature Requests"**: Type, Status, Title, Customer, Tags, Date, Replies.
- 🟢 **Entry seed**:
  - Riga 1: BUG / SUBMITTED / "Testing the bug report feature" / muscleaddiction49 / (no tag) / Apr 27, 2026 / (no replies)
  - Riga 2: BUG / SUBMITTED / "Testing the bug report feature" / muscleaddiction49 / DASHBOARD / Apr 27, 2026 / (no replies)
- 🔵 **`[05.17.1]`** Possibile mancanza dedup (vedi sotto).

### `[05.17.1]` 🔵 **INFO/UX** — Submit duplicato non rilevato

**Sintomo**:
- 2 entry con **stesso titolo identico** ("Testing the bug report feature"), **stesso customer**, **stessa data** (Apr 27, 2026), differenti solo per il tag (una `null`, una `DASHBOARD`).
- Suggerisce che l'utente abbia premuto Submit due volte o che il form non normalizzi il payload (tag opzionale → 2 stati distinti). Non c'è warning "Sembri aver già inviato questo feedback".

**Impatto**:
- Customer in panico/frustrazione che spamma 5 volte lo stesso bug intasa il funnel admin.
- Stat "Open: 2 — Needs attention" gonfiata da duplicate → super-admin perde tempo.

**Suggerimento**:
- Submit-side: normalizza payload (trim title) + warn se stesso title+customer in ultime 24h.
- Admin-side: bottone "Merge duplicates" o auto-clustering by title similarity.

**Severity = INFO**: scelta di prodotto, non vero bug. Deployment scope: `🌐 portal admin` + `🔐 license-server` (API submit).

### Test follow-up

- Click su una riga → vedi il body del bug report? screenshot allegato? user-agent / browser info catturato?
- Workflow status: SUBMITTED → ACKNOWLEDGED → IN_PROGRESS → RESOLVED / WON'T_FIX.
- Reply admin: notifica email al customer? entry in audit log `[05.5.1]`?
- Filter Type=FEATURE → con seed feature request, separazione bug vs feature OK?
- RBAC: customer-side può vedere solo i propri feedback, super-admin tutti?

---

## 05.18 — `/admin/licenses` (Licenses POST-EA)

> Sessione 2026-04-29. Empty atteso pre-EA. Coverage shell UI.

### Findings

- 🟢 **Header**: titolo "Licenses", CTA `+ New License`.
- 🟢 **Filtri**: All Editions, All Statuses, Customer ID input, bottone Search.
- 🟢 **Stat card (4)**: Total `0`, Active `0`, Pro `0`, Trials Active `0`.
- 🟢 **Tabella "Licenses" — `0 licenses`**: License Key, Customer, Edition, Status, Agents, Subscription, Expires, Trial. Empty: "No licenses found".
- 🟢 **Sidebar label POST-EA**: coerente con strategia di rilascio (la pagina esiste ma il modello dati si attiva solo dopo Early Access end).

### Test follow-up (post-EA)

- Crea license trial 30gg → verifica conta in `Trials Active`.
- Crea license Professional → verifica conta in `Pro`.
- Filter by Customer ID → match esatto / parziale?
- Action revoke license → status passa a REVOKED, bloccata immediatamente l'attivazione lato agent? `[03.13.2]` cross-ref.
- Cross-ref `[02.7.6]` (Billing "Monthly/Renews" su EA gratuito): verifica anche qui edge case EA tier.

---

## 05.19 — `/admin/activations` (Activations POST-EA)

> Sessione 2026-04-29. Empty atteso pre-EA. UX duplicata da osservare.

### Findings

- 🟢 **Header**: titolo "Activations".
- 🟢 **Banner top**: "No active installations — Waiting for first activation" (icon dot, info-level).
- 🟢 **Stat card (5)**: Active Installations `0` / `0 total`, Online (24H) `0` / "No active installations", Stale (1-3 DAYS) `0` / "All healthy", Offline (3+ DAYS) `0` / "None detected", Heartbeats (24H) `0` / "Last 24 hours".
- 🟢 **Sezione "Activation Events"**: filter `All Events` + Refresh, area log empty con icona heart-pulse e testo "No activation events found".
- 🔵 **`[05.19.1]`** UX redundancy "no install" detto 3 volte (vedi sotto).

### `[05.19.1]` 🔵 **INFO/UX** — Triplo messaggio "no installations"

**Sintomo**:
- Banner top: "No active installations — Waiting for first activation"
- Stat 1 subtitle: "0 total"
- Stat 2 subtitle: "No active installations"
- Stat 3 subtitle: "All healthy" (su 0 stale)

3 conferme dello stesso fatto. Quando arriverà il primo customer, le 4 card diventano informative; ora sono rumore.

**Impatto**: nessuno funzionale. UI overcrowded ma pragmatica.

**Suggerimento**: in stato vuoto mostra solo il banner top, nascondi le stat card o le mostra in stato `dim/disabled`.

**Severity = INFO**. Deployment scope: `🌐 portal admin`.

### Test follow-up (post-EA)

- Installa 1 agent on-prem → verifica appare in `Active Installations` + log evento in `Activation Events`.
- Heartbeat ogni N min: verifica `Heartbeats (24H)` cresce.
- Stop agent per 25h → verifica passaggio a `Stale (1-3 DAYS)` poi a `Offline (3+ DAYS)`.
- Filter `All Events` → discrimina activation/deactivation/heartbeat/error.

---

## 05.20 — `/admin/pricing` (Pricing Calculator)

> Sessione 2026-04-29. Tool sales-side per calcolare quote customer.

### Findings

- 🟢 **Form**: Edition (Free/Starter/Professional/Business/Enterprise), Subscription Years (1/2/3), Extra Agents (above 10 included), Priority Support (Yes/No).
- 🟢 **Output card**: Base Annual, Agent Add-on, Support Add-on, Discount %, Discounted Annual, Duration, Total Price.
- 🟢 **Default Professional 0 extra agent / 1 year / no priority** → `EUR 4999.00`.
- 🟢 **Discount tiers** sotto: 1 Year 0%, 2 Years 10%, 3 Years 15% — coerente con landing page positioning.
- 🟢 **SaaS Plans Reference** tabella in fondo: Starter €59/mo €590/yr 25 agents 3 users; Pro €249/mo €2490/yr 100 agents 10 users; Business €649/mo €6490/yr 500 agents 50 users.
- 🔵 **`[05.20.1]`** Purpose ambiguo (vedi sotto).
- 🔵 **`[05.20.2]`** Terminologia inconsistente "Pro" vs "Professional".

### `[05.20.1]` 🔵 **INFO/UX** — Purpose della pagina poco chiaro: "non capisco a cosa serva" (utente)

**Sintomo**:
- Pagina marcata `READ-ONLY` in sidebar e contiene 2 logiche separate (Calculator dinamico + SaaS Plans Reference statico).
- Nessuna intro/help-text che spiega: "Use this to quote on-prem deals" o "This shows what the customer-facing pricing page should display".
- Sovrapposizione concettuale con `/admin/plans` (lì plan card) e con `sentrikat.com/pricing` (la landing page pubblica).

**Impatto**: super-admin nuovo o sales team confusi su quale strumento usare per quote → rischio quote errate o inconsistenti vs sito pubblico.

**Suggerimento**: header con "Per quotare deal on-prem custom (>10 agents, multi-year). Per pricing SaaS standard, vedi /admin/plans."

**Severity = INFO**. Deployment scope: `🌐 portal admin`.

### `[05.20.2]` 🔵 **INFO/UX** — Terminologia inconsistente: "Professional" (Edition dropdown) vs "Pro" (Reference table)

**Sintomo**: Edition dropdown ha valori `FREE/STARTER/PROFESSIONAL/BUSINESS/ENTERPRISE`. La tabella SaaS Plans Reference sotto ha row `Starter / Pro / Business`. Stesso plan, due nomi.

**Impatto**: micro, ma quando il sales team copia/incolla in un email è una segnalazione "qual è il nome ufficiale?" ripetuta.

**Severity = INFO**. Deployment scope: `🌐 portal admin`.

---

## 05.21 — `/admin/plans` (Subscription Plans — read-only code reference)

> Sessione 2026-04-29. **🔴 BUG HIGH**: prezzi divergenti tra 3 fonti di verità.

### Findings

- 🟢 **Header**: titolo "Subscription Plans", testo top-right "Plans are defined in code — read-only view".
- 🟢 **5 plan card**: Free, Starter, Professional, Business, Enterprise.
- 🟢 **Prezzi/quote dichiarati**:
  - Free: `Free` · Agents 3 · Users 1 · Orgs 1 · Products 25 · features: `push_agents`
  - Starter: `€59/mo` · Agents 10 · Users 3 · Orgs 1 · Products `-1` · features: api_access, email_alerts, push_agents, webhooks
  - Professional: `€199/mo` · Agents 25 · Users 5 · Orgs 1 · Products `-1` · features: api_access, audit_export, compliance_reports, email_alerts, jira_integration, push_agents, sbom_export, siem_integration, webhooks
  - Business: `€499/mo` · Agents 50 · Users 10 · Orgs 10 · Products `-1` · adds: backup_restore, ldap, multi_org, sso, white_label
  - Enterprise: `€999/mo` · Agents `-1` · Users `-1` · Orgs `-1` · Products `-1` · stesso featureset Business
- 🔴 **`[05.21.1]`** **HIGH** — prezzi/quote divergono da `/admin/pricing` Calculator e Reference (vedi sotto).
- 🔵 **`[05.21.2]`** Placeholder `-1` per "Unlimited" leakka in UI come testo letterale.

### `[05.21.1]` 🔴 **HIGH** — Triple source-of-truth divergence: Plans vs Pricing Calculator vs Reference

**Sintomo** (Professional plan come esempio canonico):

| Fonte | Mensile | Annuale | Agenti | Users |
|---|---|---|---|---|
| `/admin/plans` (code-defined) | **€199/mo** | €2388/yr | 25 | 5 |
| `/admin/pricing` Calculator output (default Pro 0 extra agent 1 yr no support) | n/d | **EUR 4999.00** | 10 incl + addon | n/d |
| `/admin/pricing` SaaS Plans Reference table | **€249/mo** | €2490/yr | 100 | 10 |

3 fonti, **3 prezzi diversi** (ratio 4999 : 2490 : 2388 → quasi **2× spread**), **3 quote di agents diverse** (25 vs 10 vs 100).

Stesso pattern presumibile per gli altri plan (Business/Enterprise non confrontabili perché Calculator non li mostra in reference).

**Impatto** (CRITICAL trasversale):
- **Sales team** usa Calculator → quota customer **EUR 4999** per Professional.
- **Customer** apre landing `sentrikat.com/pricing` (servita da Plans probabilmente) → vede **€199/mo** = €2388/yr.
- **Deal salta** appena customer fa il confronto: o sales sembra aver gonfiato, o il sito sembra ingannevole.
- **Consistency promise**: il principio cardine `"Zero coverage parziale è accettabile"` di CLAUDE.md vale anche per pricing — un solo numero sbagliato erode fiducia totale.

**Sospetto root cause**:
- Plans page legge da Pydantic model in `SentriKat-web/license-server` (tag "defined in code").
- Pricing Calculator legge da `server_config` (tag "all values loaded from server config" sotto il titolo) — probabilmente file YAML/JSON deployato separatamente.
- SaaS Plans Reference table — terza fonte hardcoded nel template del Calculator stesso.
- Drift inevitabile in assenza di single source of truth.

**Fix prescriptivo**:
1. Una sola sorgente: il Pydantic model in license-server (Plans page diventa autorevole).
2. Pricing Calculator legge dallo stesso model (no `server_config` separato).
3. Reference table eliminata (o generata dinamica dal model).
4. Test CI: `make pricing-consistency-check` che fallisce se i 3 numeri divergono.

**Severity = HIGH** (CRITICAL borderline) per l'impatto commerciale diretto. Deployment scope: `🌐 portal admin` + `🔐 license-server` + 🌐 landing page (cross-repo, propagation a `SentriKat-web/landing` da verificare).

### `[05.21.2]` 🔵 **INFO/UX** — `-1` placeholder per "Unlimited" leakka come testo letterale

**Sintomo**:
- Card Enterprise: `Agents: -1 · Users: -1 · Orgs: -1 · Products: -1` invece di `Unlimited` / `∞`.
- Card Starter/Professional/Business: `Products: -1` (Free dice `Products: 25` correttamente).

**Impatto**: cosmetico ma fa sembrare il prodotto bacato/in beta. Customer/sales che screenshotta la card per discussion vede un -1 invasivo.

**Suggerimento**: template formatter `value if value > 0 else "Unlimited"`.

**Severity = INFO**. Deployment scope: `🌐 portal admin`.

### Test follow-up

- Cross-ref customer-facing landing `sentrikat.com/pricing`: quale numero mostra per Pro/Professional? Diventa 4ª fonte.
- Cross-ref `/admin/pricing` con Edition=Free → calculator deve mostrare 0 (verifica edge case).
- Cross-ref `[02.4.2]` warm-email USD/EUR: deve usare gli stessi numeri.

---

## 05.22 — `/admin/saas-tenants` (Early Access Tenants)

> Sessione 2026-04-29. **🔴 BUG HIGH**: stats endpoint 401, tabella tenant OK.

### Findings

- 🔴 **`[05.22.1]`** **HIGH** — Top stat card `Early Access Capacity __/30`, `Active --`, `Suspended --`, `Cancelled --` mostrano `--` perché endpoint stats fallisce con `401 Admin API key required` (vedi sotto).
- 🟢 **Section "Live SaaS Tenants"** sotto carica regolarmente 6 tenant (cross-ref `[05.24]` Usage Metrics):
  - `Takirtnes` (admin: `muscleaddiction49@gmail.com`) — STARTER · ACTIVE · Apr 23
  - `Sberlerch SPA` (admin: `contact.sotadenis@gmail.com`) — ENTERPRISE · ACTIVE · Apr 16
  - `Vecchi Enterprise LTD` (admin: `alex.vecchi@outlook.com`) — BUSINESS · ACTIVE · Apr 15
  - `testing Inc` (admin: `sotadenis94@gmail.com`) — STARTER · ACTIVE · Mar 29
  - `Acme Italia SRL` (admin: `cliente1@test.com`) — ENTERPRISE · ACTIVE · Mar 28
  - `SentriKat` (admin: `admin@sentrikat.com`) — `-` (no plan?) · ACTIVE · Mar 28
- 🟢 **Action toolbox per row**: `Change Plan`, `Usage`, `Cancel`. Coverage CRUD admin OK.
- 🟢 **Filtri**: All plans, All statuses, Refresh.
- 🟢 **Export CSV** + link "SaaS Early Access Management" external (probabilmente tenant onboarding).

### `[05.22.1]` 🔴 **HIGH** — EA Tenants stats endpoint risponde 401 "Admin API key required"

**Sintomi**:
- DevTools console: `Stats load failed Error: Admin API key required` + 2 XHR `GET /api/v1/admin/ea-tenants/... → HTTP/2 401`.
- 4 stat card mostrano `--` invece di numeri reali.
- "EARLY ACCESS CAPACITY" mostra `__/30` con bar di progresso vuota → impossibile sapere a colpo d'occhio quanti spot EA restano (info CRITICA per il go-to-market).

**Impatto**:
- Super-admin che apre la pagina vede `--` ovunque e crede di non avere ancora EA tenant. In realtà ne ha 6 (visibili più in basso). Inconsistenza interna.
- Capacity bar rotta = decisioni di marketing/pricing prese a caso ("possiamo offrire altri 5 EA slot? non sappiamo").
- Cluster con `[05.13.1]` (newsletter subscribers list 401): stesso pattern — endpoint stats vs endpoint list trattati con auth diversi. **Sospetto**: middleware auth header `X-Admin-Key` non applicato uniformemente sui route admin. Va consolidato lato `SentriKat-web/portal-admin` o `🔐 license-server`.

**Fix prescriptivo**:
1. Identificare con grep tutti i fetch `/api/v1/admin/*` lato client e verificare che allegano `X-Admin-Key`.
2. Lato server: requirement uniforme — o tutti gli endpoint admin richiedono X-Admin-Key, o nessuno.
3. Test smoke che chiama in successione tutti gli endpoint admin con session cookie + X-Admin-Key e verifica 200.

**Severity = HIGH**: feature core (capacity tracking) inutilizzabile. Cluster cross-ref `[05.13.1]`. Deployment scope: `🌐 portal admin` + `🔐 license-server`.

### Test follow-up (post-fix)

- Stat card mostrano numeri reali (Active=6, EA Capacity=6/30 visibile).
- Action `Change Plan` su tenant → audit log entry + Stripe webhook event in `[05.23]`.
- Action `Cancel` → status passa a `CANCELLED`, tenant non più ACTIVE.
- Cross-ref con Plans page (`[05.21]`): tenant ENTERPRISE devono pagare €999/mo (o quanto è il numero giusto, vedi `[05.21.1]`).

---

## 05.23 — `/admin/webhook-outbox` (Webhook Outbox)

> Sessione 2026-04-29. Empty state. Sprint label visibile in UI.

### Findings

- 🟢 **Header + descrizione**: titolo "Webhook Outbox", label `SPRINT 6 BRIDGE (B3)` accanto + helper "Outbound `license.*` events to the SaaS core. DLQ rows can be replayed after fixing root cause."
- 🟢 **Filter chips**: All / Pending / Failed / Sent / DLQ. Coverage status set complete.
- 🟢 **Counter "0 total"** coerente con empty state.
- 🟢 **Tabella "Recent events"**: Status, Event type, Tenant, Attempts, Created, Sent, Last error, Action. Empty: "No events".
- 🟢 **Sprint tag in UI** (`B3`): cross-ref con runbook `[05.7]` per tracking infra-bridge sprint progress. Buona pratica trasparenza.

### Test follow-up

- Trigger un evento da app SaaS (es. license expiration imminent) → verifica appare qui in stato `Pending` poi `Sent`.
- Forza failure (URL webhook destinatario down) → status `Failed` con `Attempts > 1`, dopo N tentativi `DLQ`.
- DLQ replay button: cosa fa? rinviene il payload originale e re-tenta?
- Cross-ref `[05.22.1]`: i Change Plan / Cancel su tenant emettono `license.plan_changed` / `license.cancelled` qui?

---

## 05.24 — `/admin/usage-metrics` (Usage Metrics)

> Sessione 2026-04-29. 6 tenant-month rows popolate. **🔵 Anomalia**: API calls/Scans always 0.

### Findings

- 🟢 **Header**: "Usage Metrics", label `SPRINT 6 BRIDGE (H7)` + helper "Hourly usage rollups received from the SaaS core, aggregated per tenant per month."
- 🟢 **Tabella "Per-tenant monthly usage"**: 6 tenant(s) · 6 tenant-month row(s).

| Tenant | Hours | Peak agents | Peak products | Peak users | API calls | Scans | Peak storage | Last received |
|---|---|---|---|---|---|---|---|---|
| `admin@sentrikat.com` | 334 | 0 | 1 | 0 | 0 | 0 | — | Apr 29, 2026 |
| `alex.vecchi@outlook.com` | 334 | 0 | 1 | 0 | 0 | 0 | — | Apr 29, 2026 |
| `cliente1@test.com` | 334 | 1 | **182** | 1 | 0 | 0 | — | Apr 29, 2026 |
| `contact.sotadenis@gmail.com` | 310 | 1 | **78** | 1 | 0 | 0 | — | Apr 29, 2026 |
| `muscleaddiction49@gmail.com` | 148 | 0 | 0 | 2 | 0 | 0 | — | Apr 29, 2026 |
| `sotadenis94@gmail.com` | 334 | 0 | 3 | 1 | 0 | 0 | — | Apr 29, 2026 |

- 🟢 Hours reported coerenti (334 ≈ 14 giorni × 24h, plausibile per Apr).
- 🟢 Peak products per `cliente1@test.com` (182) e `contact.sotadenis@gmail.com` (78) → tenant attivamente popolati.
- 🔵 **`[05.24.1]`** API calls = 0 e Scans = 0 per **tutti e 6** i tenant (vedi sotto).

### `[05.24.1]` 🔵 **INFO/UX (potenziale 🟡 WARN se billing-driven)** — telemetria API calls/Scans sempre 0

**Sintomo**:
- Tenant con 78–182 prodotti tracciati hanno **0 API calls** e **0 scans** mensili.
- Peak storage = `—` (em-dash) per tutti — feature non ancora implementata o roll-up rotto.

**Possibili cause**:
1. **Counters non incrementati** lato app SaaS quando arriva una request `/api/v1/products` o uno scan agent. Bug di `usage tracking middleware`.
2. **Rollup orario non scrive** queste metriche (parziale): scrive Hours/Products/Users ma manca instrumentation per API calls/Scans.
3. **Numeri reali davvero 0**: i tenant hanno prodotti popolati via UI/import, non via API/scan agent. Plausibile per ambiente test/EA.

**Per distinguere**: query SQL nel DB SaaS (`app.sentrikat.com`):
```sql
SELECT COUNT(*) FROM api_request_log WHERE tenant_id = ... AND created_at >= '2026-04-01';
SELECT COUNT(*) FROM agent_scan_log WHERE tenant_id = ... AND created_at >= '2026-04-01';
```
- Se >0 → bug rollup (severità 🟡 WARN, business-critical perché blocca billing usage-based).
- Se 0 → comportamento atteso, il dato è onesto. Promuovere a 🔵 INFO permanente.

**Impatto**:
- Se billing usage-based diventa attivo (post-EA), questi numeri **sono la fattura**. Un bug qui = customer fatturato 0 quando ha consumato.
- Cross-ref `[05.21.1]` pricing: piano usage-based richiede telemetria affidabile.

**Severity preliminare = 🔵 INFO** (in attesa di SQL count). Promuovere a 🟡 WARN se rollup confermato rotto. Deployment scope: app SaaS (`app.sentrikat.com`) + `🔐 license-server` rollup.

### Test follow-up

- Run query SQL sopra per definire severity finale.
- Trigger 10 API call su un tenant test → next hourly rollup deve incrementare API calls.
- Trigger 1 agent scan → next rollup deve incrementare Scans + Peak storage.
- Filtro mese: solo Apr 2026 visibile, verifica navigation Marzo/Maggio.

---

## Re-verify rapido — Releases / KB Mappings / Data Sources (sezioni 05.1/05.2/05.3)

> Sessione 2026-04-29 sera. Re-verify post screenshot, niente di nuovo da aggiungere ma osservazioni che confermano stato.

- **`/admin/releases`** (`05.1`): tutto come `[05.1.1]` (Total Releases `0`, Latest Version `-`). 0 release ingestate via GitHub sync nonostante VERSION inchiodato a beta.2/beta.6 (cluster `[03.5.3]`). CTA `Sync from GitHub` + `Manual Release` presenti. **Stato: bug `[05.1.1]` ancora aperto**, da fixare via release ingest.
- **`/admin/kb`** (`05.2`): 64,749 mapping totali, tutti published, 0 pending review, 0 contributors. **Status NVD Sync: `unreachable (today)`** in colore arancione/warning — **conferma `[05.2.1]`** (NVD probe unreachable). Filter chip "Community" + "All Status".
- **`/admin/datasources`** (`05.3`): 1 totale, 0 healthy, 1 down "Critical" (label `Unknown` / status UNKNOWN). **Conferma `[05.3.1]`** (data source non identificato). Cross-ref `[05.4.1]` (status page disonesta).

Niente da aggiornare nei doc precedenti, sono ancora gli stessi bug.

---

## Riepilogo apertura Fase 05

- **Bug aperti**: 11 (di cui 10 HIGH `[05.1.1]` `[05.3.1]` `[05.4.1]` `[05.5.1]` ✅ `[05.6.1]` ✅ `[05.8.1]` `[05.9.1]` `[05.13.1]` `[05.21.1]` `[05.22.1]`, 2 WARN `[05.2.1]` `[05.5.2]` `[05.8.2]`). ✅ = verified 2026-04-29.
- **Info/governance**: 10 (`[05.1.2]` `[05.6.2]` `[05.7.1]` `[05.14.1]` `[05.16.1]` `[05.17.1]` `[05.19.1]` `[05.20.1]`+`[05.20.2]` `[05.21.2]` `[05.24.1]`).
- **OK**: 4 + 13 nuove pagine 7-dim happy (NVD sync, runbook, role matrix, quick actions + customers/leads/demo-requests/newsletter compose-side/support-tickets shell + response-templates/customer-health/feedback/licenses-POST-EA/activations-POST-EA/pricing/plans + EA tenants tabella/webhook-outbox/usage-metrics).
- **Pagine ancora da aprire**: 0 sidebar principale. Solo Audit Log dedicato (cross-ref Settings → "Go to Audit Log") e Status sub-views. **Phase 05 sidebar mapping COMPLETO**.

### Cluster bug correlati

- **Audit logging rotto**: `[05.5.1]` (audit log vuoto) + `[05.6.1]` (last_login non scritto) → root cause comune, probabilmente middleware audit non agganciato.
- **Status page disonesta**: `[05.4.1]` (status verde) + `[05.3.1]` (datasource down) → status page manuale, non legge probe automatici.
- **UI inconsistencies su retention**: `[05.5.2]` (365d vs 730d) → almeno una pagina mostra valori obsoleti.
- **Pricing source-of-truth split** (NUOVO): `[05.21.1]` (HIGH 3 fonti) + `[05.20.1]` (purpose ambiguo) + `[05.20.2]` ("Pro" vs "Professional") → manca single source of truth nel pricing model. Cross-repo: anche landing page (`SentriKat-web/landing/sentrikat.com/pricing`) potenziale 4ª fonte da verificare.
- **Auth-fail su admin endpoints** (NUOVO, escalation): `[05.13.1]` newsletter 403 + `[05.22.1]` EA Tenants stats 401 → cluster auth header non uniforme su `/api/v1/admin/*`. Stessa root cause sospettata, deployment scope `🌐 portal admin` + `🔐 license-server`. Da fixare con audit completo dei fetch admin client-side.
- **Telemetry rollup parziale** (NUOVO): `[05.24.1]` Usage Metrics API calls/Scans = 0 — può essere bug rollup o comportamento atteso, da SQL-verify nel DB SaaS.
- **Empty state cosmetic leaks** (NUOVO): `[05.14.1]` (`badge-green` literal) + `[05.21.2]` (`-1` literal per Unlimited) + `[05.16.1]` (semantica "healthy" su zero-data) + `[05.19.1]` (triple "no installs"). Cluster di template polish da risolvere insieme.

