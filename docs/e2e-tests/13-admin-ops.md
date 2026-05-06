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

### 13.1 — Admin panel landing `/admin`

_Da iniziare. URL on-prem: `http://localhost/admin` (via nginx) o `http://localhost:5000/admin` (diretto)._

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
