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

> Sezioni 05.5–05.8 in commit successivo (vedi [05.5] Logs, [05.6] Users, [05.7] Runbook, [05.8] Settings).
