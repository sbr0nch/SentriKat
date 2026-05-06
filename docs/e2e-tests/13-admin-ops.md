# Fase 13 — Admin Ops (admin core dell'app deployata)

> Test end-to-end delle operazioni admin **dentro** un'installazione SentriKat (sia on-prem locale sia SaaS multi-tenant). Distinto dal Phase 05 (`portal.sentrikat.com` admin → gestione customer/license esterna).
>
> **Environment principale**: PC casa, on-prem locale Docker (`v100-beta6` compose project) → coverage completa inclusa **backup/restore** (on-prem only feature).
> **Environment confronto**: SaaS prod (`app.sentrikat.com`) → conferma su feature condivise; backup/restore N/A.
>
> **Super admin disponibili**: ✅ on-prem + ✅ SaaS.
>
> **Fase di walkthrough**: aperta 2026-05-06 (corrispondente a "W6 Admin ops" della customer journey, post-fix CVE pipeline + F.2 manual UI).

---

## Aree coperte

| Area | Surface | Description | Env |
|---|---|---|---|
| 13.1 | `/admin` (panel core landing) | Dashboard overview, navigation, stat cards | 🏢☁️ both |
| 13.2 | `/admin/health` | Health checks status + Run Now per probe (DB, NVD, scheduler, mailer, integrazioni) | 🏢☁️ both |
| 13.3 | `/admin/logs` | Log viewer: lista log file, view tail, download intero, level filter | 🏢 on-prem (filesystem); ☁️ SaaS via S3/cloud logs |
| 13.4 | `/admin/sync` (CVE/CPE/EPSS) | Trigger manuale sync CISA KEV / NVD recent / CPE backfill / EPSS; sync status; history | 🏢☁️ both |
| 13.5 | `/api/settings/backup` + `/restore` + `/restore-full` | DB dump JSON, upload+merge, full replace | 🏢 on-prem only |
| 13.6 | `/admin/scheduler` o `/api/settings/sync` | APScheduler jobs: list, last run, next run, enable/disable | 🏢☁️ both |
| 13.7 | `/api/settings/retention` | Data retention: vuln/audit/alert/snapshot policies | 🏢☁️ both |
| 13.8 | `/api/settings/maintenance/*` | Auto-acknowledge, cleanup invalid matches, vacuum/analyze | 🏢 on-prem; ☁️ SaaS scheduled only |
| 13.9 | Audit log viewer (UI) | List audit_events, filter by user/action/object, export CSV | 🏢☁️ both |
| 13.10 | User management super-admin | List all users (cross-org in SaaS), promote/demote, disable, reset password | 🏢☁️ both |
| 13.11 | License management (admin app side) | View installed license (DEMO/PRO), expiry, hardware lock, refresh license | 🏢 on-prem primarily |
| 13.12 | Prometheus metrics endpoint | `/metrics`: scrape, value sanity check (active products, matches, sync stats) | 🏢☁️ both |
| 13.13 | OpenTelemetry (se attivo) | Trace export, span coverage | 🏢☁️ both (config gated) |
| 13.14 | System settings / general / security | UI tabs: general, security (session timeout, password policy), branding | 🏢☁️ both |
| 13.15 | Maintenance ops | `cleanup_invalid_matches` re-run, force CPE rebatch, vacuum DB | 🏢 on-prem |

---

## 7 dimensioni applicate ad ogni pagina

(Standard del progetto — vedi `00-INDEX.md` § 7-dim.)

1. **Happy path** — l'utente apre la pagina, vede contenuto coerente
2. **Persistence** — refresh / logout-login: stato preservato
3. **CRUD** — create/edit/delete dove applicabile
4. **RBAC** — super_admin sì, manager no, user no
5. **State transitions** — disable user, restore backup, ecc.
6. **Negative input** — file backup corrotto, JSON malformato, valori out-of-range
7. **Integration / audit** — ogni azione admin scrive `audit_events`; webhook outbound se configurato

---

## Sezioni walkthrough

> Ogni sezione viene riempita man mano durante il walkthrough. Bug ID format: `[13.S.B]` o `[13.S.B.N]`.

### 13.1 — Admin panel landing (Dashboard)

> **URL effettivo**: `http://localhost/` (on-prem) e `https://app.sentrikat.com/` (SaaS) — **non è una rotta `/admin` separata**, l'admin landing è la stessa Vulnerability Dashboard del normale utente, con sidebar estesa per super-admin. Sezioni admin-only sono sotto **Management** (Organizations, Users & Access cross-org), **System** (Settings, License/Subscription, Health Checks, System Logs, Platform Operations [SaaS only]).

#### Sidebar/menu — confronto on-prem vs SaaS

| Sezione | On-prem | SaaS | Note |
|---|---|---|---|
| Overview → Dashboard, Assignments | ✅ | ✅ | identico |
| Inventory → Products, Endpoints, Containers, Dependencies, Import Queue, SBOM Export, Exclusions | ✅ | ✅ | identico |
| Management → Users & Access (All Users, LDAP Users, LDAP Groups) | ✅ | ✅ | identico |
| Management → **Organizations** | ✅ | ❌ | Coerente: SaaS è single-tenant per il customer, super-admin SaaS gestisce orgs solo dal portal admin esterno (`portal.sentrikat.com/admin`) |
| Integrations → Integrations, Agent Keys, Agent Activity, Scheduled Reports, Issue Trackers | ✅ | ✅ | identico |
| System → Settings, Authentication, Alert Mgmt, SMTP, SIEM/Syslog, System, Compliance, Appearance | ✅ | ✅ | identico |
| System → **License** | ✅ | ❌ | On-prem mostra licenza locale (DEMO/PRO RSA-4096) |
| System → **Subscription** | ❌ | ✅ | SaaS mostra subscription Stripe-backed |
| System → Health Checks, System Logs, Admin Guide | ✅ | ✅ | identico |
| **Platform Operations** (4 voci) | ❌ | ✅ | SaaS only: Cross-Repo Integration, Webhook Events, Usage Uploads, + Platform Operations parent — relativo al collegamento con portal admin / license-server |

**Verdict menu**: differenze coerenti con l'architettura. Nessun gap inatteso.

#### Dashboard content — on-prem (Test Org, Community Edition)

- **Top banner Community Edition**: "Limited to 3 user, 100 products. Get a License" → ✅ allineato con landing pricing
- **Banner import queue**: "89 products waiting for review" → richiama F.3 (CPE applicato a queue approval, ma non auto-approve)
- **Banner system health**: "2 warnings" → da investigare in 13.2
- **Banner CPE mapping**: "30 products without CPE mapping" + bottone "Auto-Detect CPE" → 70/100 hanno CPE (coerente con audit precedente; 30 sono prodotti Windows generici tipo "Windows SDK", "Universal CRT Headers Libraries and Sources" che falliscono Tier 1-3)
- **Banner version**: "4 products without a known version" → coerente con F.9 (agent registry parser limitations)
- **Stat cards**: 0-DAY 0, **CRITICAL 1** (1 match), HIGH 0, MEDIUM 0
- **KEV Catalog**: 2,396 CVE (87% del totale 2,748 enriched) | Affecting Products: 1 | Needs Review: 0 | Products Tracked: 100
- **Remediation Actions**: 1 riga — "Update Igor Pavlov 7-Zip 19.00 (x64) from 19.00" con badge **EXPLOITED** ← coerente con CVE-2025-0411
- **SLA Compliance**: "No SLA policies configured" — atteso (no setup eseguito)
- **Last Synchronization**: 06/05/2026 02:00:15 **FAILED** | 0 matches found in 15.11s ⚠️
- **CRITICAL RISK card**: CVE-2025-0411, OVERDUE BY 432 DAYS, CISA KEV, 1 PRODUCT (1 OPEN), 1 ENDPOINT, button NVD + Share

#### Dashboard content — SaaS (`SentriKat test` tenant)

- **Top**: badge "SENTRIKAT" (no org dropdown — single-tenant view per customer)
- **Banner agent**: "No agent reports received in the last 48 hours. Check agent connectivity"
- **Banner import queue**: "1 product waiting for review"
- **Banner system health**: "1 critical config issue(s): SMTP not configured (email alerts will not work)" 🔴
- **Banner CPE mapping**: "1 products without CPE mapping"
- **Stat cards**: tutto 0
- **KEV Catalog**: 15,604 CVE (vs 2,396 on-prem — SaaS ha enrichment più maturo, ~6.5x dataset)
- **Affecting Products**: 0 | Products Tracked: 1
- **Vulnerability Trends**: tutto 0 da 2026-04-06 a oggi

---

#### Bug identificati 13.1

##### [13.1.1] 🔴 Pagination "Showing 1-50 of 0" mentre header dice "Vulnerabilities (1 CVEs)"

- **Env**: 🏢 on-prem (probabilmente anche ☁️ SaaS — non testato perché 0 vuln)
- **Severity**: 🔴 HIGH (UI inconsistency visibile a customer al demo)
- **Symptom**: Header sezione Vulnerabilities mostra "(1 CVEs)" coerente con la card CRITICAL RISK renderizzata sotto, ma pagination dice "Showing 1-50 of 0".
- **Hypothesis**: Counter `total_count` per pagination calcolato su query post-filter diversa dal counter dell'header (probabile filter `Unacknowledged Only` ON nel filtro di default che esclude la riga, mentre header conta tutto).
- **Repro**: aprire dashboard → osservare contatore in fondo
- **Discovered**: 2026-05-06

##### [13.1.2] 🟡 Filtro "Vendor=Microsoft, Product=Windows" sembra applicato di default ma il risultato è CVE 7-Zip

- **Env**: 🏢 on-prem + ☁️ SaaS (entrambi mostrano gli stessi placeholder "Microsoft"/"Windows" nei campi)
- **Severity**: 🟡 MEDIUM — confonde l'utente: vede valore in input ma il backend lo ignora
- **Symptom**: Filter input Vendor mostra "Microsoft" e Product mostra "Windows" come testo, ma i risultati ignorano i valori (7-Zip CVE viene renderizzato).
- **Hypothesis**: testo è **placeholder** HTML5, NON valore — disambiguazione mancante: dovrebbe essere `placeholder="Microsoft"` con campo vuoto, ma se renderizzato come `value=` confonde. Da verificare in DOM.
- **Discovered**: 2026-05-06

##### [13.1.3] 🟡 Last Synchronization on-prem: FAILED (0 matches in 15.11s)

- **Env**: 🏢 on-prem (06/05/2026 02:00:15)
- **Severity**: 🟡 MEDIUM (non blocca demo: dato corrente è già buono dalla sync precedente, ma scheduler non sta riuscendo)
- **Symptom**: Run schedulato del 6 maggio 02:00 è fallito in 15s. Banner non specifica errore.
- **Hypothesis A**: NVD rate-limit (test API key esposta in chat history potrebbe essere stata revocata)
- **Hypothesis B**: timeout di rete dal container al NVD/CISA upstream
- **Hypothesis C**: scheduler healthy ma il job ha sollevato eccezione → rollback senza match update
- **Action**: 13.4 (sync trigger) farà un Run Now manuale per riprodurre + leggere log
- **Discovered**: 2026-05-06

##### [13.1.4] 🟡 SaaS tenant `SentriKat test`: SMTP not configured

- **Env**: ☁️ SaaS
- **Severity**: 🟡 MEDIUM — funzionale ma non urgente, in SaaS lo SMTP dovrebbe essere platform-default (Resend via license-server / sentrikat-web), non richiesto per-tenant
- **Symptom**: Banner critical su SaaS dice "SMTP not configured" — implica che ogni nuovo tenant SaaS deve configurare SMTP a mano, contraddice l'integrazione Resend deliverability committed in sentrikat-web PR #257.
- **Action**: chiedere a sessione gemella sentrikat-web se license-server espone SMTP shared via tenant provisioning, e se sì come il core lo legge
- **Discovered**: 2026-05-06

##### [13.1.5] 🔵 SaaS tenant: 0 agent reports negli ultimi 48h

- **Env**: ☁️ SaaS
- **Severity**: 🔵 INFO (atteso se è un tenant di test senza agent installato; banner è informativo corretto)
- **Action**: nessuna — il banner è UX feedback corretto

##### [13.1.6] 🟢 OK — Community Edition banner + KEV CRITICAL match coerenti

- ✅ Banner pricing allineato con landing (3 user / 100 products)
- ✅ CVE-2025-0411 visibile come unico match con tutti i metadata corretti (KEV, EXPLOITED, OVERDUE 432 days)
- ✅ KEV Catalog 2,396 con 1 affecting product (87% enrichment dataset)
- ✅ Sidebar admin-only correttamente nascosta a manager/user (da verificare in 13.1 dim 4 RBAC quando hai un user normale a portata)

#### Coverage 7-dim per 13.1

| Dim | Stato |
|---|---|
| 1. Happy path | ✅ |
| 2. Persistence | ⏸️ da testare (logout-login + refresh) |
| 3. CRUD | n/a per dashboard |
| 4. RBAC | ⏸️ da testare con user non-admin |
| 5. State transitions | n/a |
| 6. Negative input | ⏸️ filter con SQL injection / unicode (rimandato a 15-security-edge) |
| 7. Integration / audit | ⏸️ verificare audit_events `dashboard.view` (probabilmente NON loggato e va bene) |

---

### 13.2 — Health checks `/admin/health`

_Da iniziare._

---

### 13.3 — Log viewer `/admin/logs`

_Da iniziare._

---

### 13.4 — Sync trigger CISA/NVD/CPE/EPSS

_Da iniziare._

---

### 13.5 — Backup + Restore (on-prem only)

_Da iniziare._

---

### 13.6 — Scheduler jobs

_Da iniziare._

---

### 13.7 — Data retention

_Da iniziare._

---

### 13.8 — Maintenance ops

_Da iniziare._

---

### 13.9 — Audit log viewer

_Da iniziare._

---

### 13.10 — User management super-admin

_Da iniziare._

---

### 13.11 — License management (admin app side)

_Da iniziare._

---

### 13.12 — Prometheus metrics

_Da iniziare._

---

### 13.13 — OpenTelemetry

_Da iniziare._

---

### 13.14 — System settings (general / security / branding)

_Da iniziare._

---

### 13.15 — Maintenance ops on-prem (CLI / scripts)

_Da iniziare._

---

## Bug summary (aggiornato durante walkthrough)

| Bug ID | Severity | Env | Title |
|---|---|---|---|
| _(none yet)_ | | | |

---

## Open follow-up

_Da popolare a fine walkthrough._
