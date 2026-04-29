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

## Pagine ancora NON aperte (sidebar)

EA Tenants, Webhook Outbox, Usage Metrics, Leads, Demo Requests, Newsletter, Support Tickets, Response Templates, Customer Health, Feedback, Customers (POST-EA), Licenses (POST-EA), Activations (POST-EA), Pricing (READ-ONLY), Plans, Audit Log (visibile via Settings → "Go to Audit Log"), Status & Incidents sub-views.

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

- 🔴 **[05.5.1] Centralized Logs completamente vuoto durante una sessione admin attiva** (HIGH)
  - Total: **0** · Audit: 0 · Activation: 0 · SaaS: 0 · Today: 0.
  - Stiamo aprendo `/admin/logs` da una sessione super-admin autenticata in questo momento → l'evento `admin.login` (oltre a tutte le navigazioni admin) **dovrebbe** apparire come audit log entry.
  - Diagnosi probabile: l'audit logger non scrive su questo storage (forse scrive su file/Docker logs ma non sul DB letto da questa pagina), oppure il middleware audit non è agganciato alle route admin.
  - Impatto: zero traceability di azioni admin. Compliance issue (SOC2/GDPR richiedono audit trail di accessi privilegiati).
  - Correlato a [05.6.1] (last login `-`).

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
- 🔴 **[05.6.1] Last Login `-` per super-admin attualmente loggato** (HIGH)
  - L'utente `admin-sentrikat / sotadenis94@gmail.com / SUPER ADMIN / ACTIVE` ha `Last Login: -` → mai aggiornato.
  - Stiamo navigando come quell'utente in questo momento. La login deve aver settato il campo.
  - Diagnosi: stessa causa di [05.5.1] — auth flow non scrive `last_login_at` né emette evento audit.
  - Impatto: impossibile sapere quando un super-admin si è loggato l'ultima volta → security blind spot.

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

## Riepilogo apertura Fase 05

- **Bug aperti**: 7 (di cui 5 HIGH `[05.1.1]` `[05.3.1]` `[05.4.1]` `[05.5.1]` `[05.6.1]` `[05.8.1]`, 2 WARN `[05.2.1]` `[05.5.2]` `[05.8.2]`).
- **Info/governance**: 3 (`[05.1.2]` `[05.6.2]` `[05.7.1]`).
- **OK**: 4 (NVD sync, runbook, role matrix, quick actions).
- **Pagine ancora da aprire**: ~17 (vedi sidebar). Continuare nelle prossime sessioni.

### Cluster bug correlati

- **Audit logging rotto**: `[05.5.1]` (audit log vuoto) + `[05.6.1]` (last_login non scritto) → root cause comune, probabilmente middleware audit non agganciato.
- **Status page disonesta**: `[05.4.1]` (status verde) + `[05.3.1]` (datasource down) → status page manuale, non legge probe automatici.
- **UI inconsistencies su retention**: `[05.5.2]` (365d vs 730d) → almeno una pagina mostra valori obsoleti.

