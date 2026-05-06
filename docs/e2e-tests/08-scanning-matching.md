# Fase 08 — Scanning & Matching

> Test end-to-end del pipeline CVE matching nel core SentriKat: ingestion vulnerabilità (CISA KEV / NVD recent / ENISA EUVD / NVD per-CPE search), enrichment (CVSS / CPE backfill / EPSS / public exploit), CPE assignment al prodotto (4-tier), matching (`check_cpe_match` + `check_keyword_match`), suppression (Vendor Fix Override / Risk Exception), cleanup invalid matches.
>
> **Prerequisito doc**: leggere prima `docs/architecture/CVE-MATCHING-PIPELINE.md` e `docs/architecture/CVE-DATA-FLOW.md`. Questa fase è il **walkthrough operativo** di quei due file.
>
> **Fase di apertura**: 2026-05-06 post-fix F.2 (manual UI CPE assignment). Live test su on-prem locale Test Org con 100 prodotti agent-pushed + manual Tomcat 9.0.50.

---

## Aree coperte

| Area | Surface | Description | Env |
|---|---|---|---|
| 08.1 | CISA KEV sync (`/api/sync` POST CISA) | Fetch + parse + store, `is_actively_exploited=True`, `known_ransomware`, vendor_project, due_date | 🏢☁️ both |
| 08.2 | NVD recent sync (hourly scheduler) | Pull modified hours_back, populate `cpe_data` + cvss + severity | 🏢☁️ both |
| 08.3 | ENISA EUVD enrich loop | Reconcile vendor/product, `source='cisa_kev+euvd'` | 🏢☁️ both |
| 08.4 | NVD per-CPE search (`fetch_cves_by_cpe`) | On-demand discover all CVEs per CPE | 🏢☁️ both |
| 08.5 | CPE backfill (`/api/sync/cpe-backfill`) | `fetch_cpe_version_data`, populate `cpe_data` su vuln esistenti | 🏢☁️ both |
| 08.6 | CVSS enrich + fallback | enrich_with_cvss_data, reenrich_fallback_cvss | 🏢☁️ both |
| 08.7 | EPSS sync (`/api/sync/epss`) | epss_score, epss_percentile, EPSS≥0.95 → is_actively_exploited=True | 🏢☁️ both |
| 08.8 | Public exploit enrichment | ExploitDB + GitHub PoC, exploit_public flag | 🏢☁️ both |
| 08.9 | CPE assignment 4-tier | apply_cpe_to_product (T1+2+3) + batch_apply_cpe_mappings (T4 NVD) + validate_cpe_assignment | 🏢☁️ both |
| 08.10 | check_cpe_match decision tree | All 10 confidence scenarios (cpe/high, cpe/medium, NVD-pending, no-cpe, ecc.) | 🏢☁️ both |
| 08.11 | check_keyword_match fallback | vendor_product / vendor / product / keyword confidence, post-F.6 demote to low when no version verifiable | 🏢☁️ both |
| 08.12 | Vendor Fix Override suppression | `has_vendor_fix_override` filter | 🏢☁️ both |
| 08.13 | Risk Exception suppression | `_has_active_risk_exception` filter (asset-specific + org-wide) | 🏢☁️ both |
| 08.14 | cleanup_invalid_matches | post-rematch, delete falsi positivi precedenti | 🏢☁️ both |
| 08.15 | Match confidence surfacing in UI | match_confidence visibile in dashboard / vulnerability_match.to_dict() | 🏢☁️ both |
| 08.16 | Sync history (`/api/sync/history`) | Last sync timestamps, success/fail status, durations | 🏢☁️ both |
| 08.17 | NVD rate-limit awareness | `/api/sync/nvd-rate-limit` headroom, status, throttling | 🏢☁️ both |
| 08.18 | NVD API key handling | system_settings.nvd_api_key, fallback no-key (10 req/min vs 50 with key) | 🏢☁️ both |

---

## 7 dimensioni applicate

(Standard 7-dim — vedi `00-INDEX.md`.)

1. **Happy path** — sync completa, match popolati
2. **Persistence** — restart container, dati preservati, scheduler riprende
3. **CRUD** — vuln add/update/delete via sync; product CPE add/update; match insert/cleanup
4. **RBAC** — `/api/sync` admin-only; manager/user no
5. **State transitions** — vuln pending → analyzed; match new → acknowledged → resolved → cleanup
6. **Negative input** — NVD 503, EUVD malformed JSON, schema drift, rate-limit hit
7. **Integration / audit** — audit_events `sync.cisa-kev.run`, webhook outbound su new HIGH match

---

## 08.1 — CISA KEV sync

> URL admin trigger: `POST /api/sync` con `{"source": "cisa-kev"}` o equivalente button in `/admin/sync` UI.
> Function: `sync_cisa_kev` in `app/cisa_sync.py:874+`. Frequency: daily via APScheduler.

### Path corretto admin sync

❌ `/admin/sync` → 404 (UI old reference)
✅ `/admin-panel#settings:system` (Settings tab → System sub-tab)
✅ Header button "Sync" (top-right area) → trigger sync globale CISA+NVD

### Live test 2026-05-06

User trigger: clicked "Sync" in header → spinner "Syncing..." attivo.

#### Synchronization History panel observed

| Date & Time | Status | Vulnerabilities | Matches Found | Duration |
|---|---|---|---|---|
| 06/05/2026 02:00:15 | 🔴 **FAILED** | 0 | 0 | **15.11s** |
| 05/05/2026 10:22:42 | 🟢 SUCCESS | 1587 | 0 | 752.56s |

#### NVD Connection Status panel observed

- NVD: **Connected**
- Rate limit: 50 req/30s **API Key Active**
- Last Sync: 2026-05-06 02:00:15 UTC
- Total Vulnerabilities: 2396

#### CPE Dictionary panel observed

- Total Entries: **65,175**
- With Aliases: 799
- **Used for Matching: 0** ← anomalo
- Product Coverage: 70%
- Last Bulk Download: 06/05/2026 12:32:16

---

### Bug findings 08.1

#### [08.1.1] 🟡 MEDIUM — Last Sync schedulata 06/05 02:00:15 FAILED in 15s con 0 vuln/0 match

- **Env**: 🏢 on-prem locale (probabile anche ☁️ SaaS, da confermare)
- **Severity**: 🟡 MEDIUM — sync manuale dal header funziona, ma scheduler rotto = drift data nel tempo
- **Symptom**: il job APScheduler delle 02:00 fallisce in 15s senza esporre root cause in UI. La sync precedente del 05/05 10:22 era SUCCESS con 1587 vuln in 752s.
- **Hypothesis A**: NVD test API key esposta in chat history (`04f90ab1-61aa-405f-be91-c42b66e982f6` per `SESSION-HANDOFF` § "License key in chat history") potrebbe essere stata revocata da NIST. Tutte le sync NVD-dipendenti falliscono.
- **Hypothesis B**: errore di rete schedulato (testlab proxy down? container DNS hiccup alle 02:00?)
- **Hypothesis C**: APScheduler retry logic ingoia eccezione e marca "FAILED" senza log dettagliato
- **Action diagnostica**: `docker logs sentrikat --since 24h | grep -iE "sync|cisa|02:00"` per estrarre stack trace
- **Discovered**: 2026-05-06

#### [08.1.2] 🔴 HIGH — CPE Dictionary "Used for Matching: 0" su 65,175 total entries

- **Env**: 🏢 on-prem (confermato), ☁️ SaaS da verificare
- **Severity**: 🔴 HIGH per la qualità del matching e diagnostica accuracy
- **Symptom**: pannello CPE Dictionary stats mostra `Used for Matching: 0` mentre Total Entries=65,175 e Product Coverage=70%. Le due cose sono incompatibili: se 70% dei product hanno CPE assegnato e parte di quelli vengono via Tier 3 (local CPE dictionary), il counter "Used for Matching" deve essere > 0.
- **Hypothesis A** (più probabile): counter di metrica rotto — il dictionary è caricato e usato, ma `lookup_cpe_dictionary` non incrementa il counter `used_for_matching`. Verifica: F.2 verified live ha mostrato che apply_cpe_to_product ha trovato match Tier 3 per Apache Tomcat → la dictionary VIENE usata. Quindi il counter è bug.
- **Hypothesis B** (catastrofico se vero): dictionary caricata ma `lookup_cpe_dictionary` mai invocato — improbabile perché contraddirebbe la verifica F.2.
- **Action diagnostica**: leggere `app/cpe_dictionary.py` → cercare counter incremento in `lookup_cpe_dictionary`. Se assente, aggiungerlo. Se presente, capire perché non gira.
- **Cross-link**: osservato durante 08.1 ma il bug è in `app/cpe_dictionary.py` (core SentriKat, on-prem + SaaS). Non cross-repo.
- **Discovered**: 2026-05-06

#### [08.1.3] 🟡 MEDIUM — Dashboard footer "Last Sync FAILED" desincronizzato mentre sync attiva

- **Severity**: 🟡 MEDIUM (UX confusing al demo)
- **Symptom**: durante una sync attiva (spinner "Syncing..." nell'header funzionante), il dashboard footer continua a mostrare lo stato della sync precedente "06/05 02:00:15 FAILED | 0 matches found in 15.11s" invece di un live indicator tipo "Sync in progress... (X seconds elapsed)".
- **Hypothesis**: footer fa una query statica al carico pagina invece di websocket / polling per stato live
- **Action**: il footer dovrebbe leggere stato live (`GET /api/sync/status`) e mostrare badge in-progress quando applicabile. Aggiungere reactive state.
- **Discovered**: 2026-05-06

#### [08.1.4] 🔵 INFO — `/admin/sync` URL inesistente — path corretto è `/admin-panel#settings:system`

- **Severity**: 🔵 INFO (documentazione interna)
- **Action**: aggiornato in questo file. Se `CVE-MATCHING-PIPELINE.md` o `13-admin-ops.md` referenziano `/admin/sync`, anche quelli vanno aggiornati.

#### [08.1.5] 🟢 OK — Sync manuale via header button operativa

- ✅ Bottone "Sync" nell'header con spinner animato durante esecuzione
- ✅ NVD Connection Status: Connected, API Key Active, rate limit 50 req/30s
- ✅ Total Vulnerabilities counter live (2396)
- ✅ CPE Dictionary auto-bulk-downloaded oggi 12:32 (65k entries)

---

## 08.2 — NVD recent sync

_Da iniziare._

---

## 08.3 — ENISA EUVD enrich loop

_Da iniziare._

---

## 08.4 — NVD per-CPE search

_Da iniziare._

---

## 08.5 — CPE backfill

_Da iniziare._

---

## 08.6 — CVSS enrich + fallback

_Da iniziare._

---

## 08.7 — EPSS sync

_Da iniziare._

---

## 08.8 — Public exploit enrichment

_Da iniziare._

---

## 08.9 — CPE assignment 4-tier

_Da iniziare._

---

## 08.10 — check_cpe_match decision tree

_Da iniziare._

---

## 08.11 — check_keyword_match fallback

_Da iniziare._

---

## 08.12 — Vendor Fix Override

_Da iniziare._

---

## 08.13 — Risk Exception

_Da iniziare._

---

## 08.14 — cleanup_invalid_matches

_Da iniziare._

---

## 08.15 — Match confidence surfacing UI

_Da iniziare._

---

## 08.16 — Sync history

_Da iniziare._

---

## 08.17 — NVD rate-limit awareness

_Da iniziare._

---

## 08.18 — NVD API key handling

_Da iniziare._

---

## Live state baseline 2026-05-06

Dopo F.2 fix + Apache Tomcat 9.0.50 manual create:

- **Total products**: 101 (100 agent-pushed + 1 manual Tomcat)
- **Products con CPE**: 71 (70 agent matched via Tier 1-3 + 1 Tomcat via Tier 1-3 dopo F.2)
- **Products senza CPE**: 30 (Windows generici tipo "Windows SDK", "Universal CRT Headers" — fail Tier 1-3, da rilevare con batch+NVD Tier 4)
- **Total CVEs**: 2,396 KEV catalog + ~352 NVD recent enrich = ~2,748
- **CVE con cpe_data**: ~2,109 (88% del KEV catalog)
- **vulnerability_matches**: 4 (CVE-2025-0411 7-Zip + CVE-2025-24813 Tomcat + CVE-2023-44487 Tomcat + CVE-2025-0411 7-Zip carryover — wait verifica)
- **Match method distribution**: 100% `cpe / high` (target: nessun keyword fallback in produzione clean)
- **Last sync schedulata 06/05/2026 02:00:15**: FAILED in 15.11s (vedi `[13.1.3]` da diagnosticare)

---

## Bug summary (aggiornato durante walkthrough)

| Bug ID | Severity | Env | Title |
|---|---|---|---|
| _(none yet)_ | | | |

---

## Open follow-up

_Da popolare a fine walkthrough._
