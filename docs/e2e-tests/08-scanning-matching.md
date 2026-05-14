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

#### [08.1.2] 🔵 INFO (era 🔴 HIGH — declassato post code-review) — CPE Dictionary "Used for Matching: 0" è comportamento corretto, non bug

> **Update 2026-05-06 post code-read di `app/cpe_dictionary.py`**: NON è un bug funzionale.

- **Env**: 🏢 on-prem + ☁️ SaaS (entrambi)
- **Severity finale**: 🔵 INFO (UI label confondente, non funzionalità rotta)
- **Symptom osservato**: pannello CPE Dictionary stats mostra `Used for Matching: 0` mentre Total Entries=65,175 e Product Coverage=70%.
- **Code analysis**:
  - `apply_cpe_to_product` (`cpe_mapping.py:349`) prova in ordine: Tier 1 (regex CPE_MAPPINGS) → Tier 2 (curated dict `cpe_mappings.py`) → Tier 3 (`lookup_cpe_dictionary`)
  - `_increment_usage` (raw SQL UPDATE su `usage_count`) viene chiamato **solo dentro Tier 3**, non in T1/T2
  - `get_dictionary_stats` (`cpe_dictionary.py:344`) computa `used_for_matching = COUNT(entries WHERE usage_count > 0)`
- **Perché è 0**:
  - Apache Tomcat 9.0.50 (F.2 verified) → matchato da Tier 1 regex (`apache:tomcat` è builtin) → mai raggiunge T3
  - 70 product agent-pushed con CPE (Microsoft .NET runtime, Visual C++ Redist, ecc.) → matchati prevalentemente T1+T2
  - 30 product agent-pushed senza CPE (Windows SDK, Universal CRT Headers) → falliscono anche T3 (non sono nel dict NVD)
  - Risultato: zero prodotti hanno usato T3 dictionary lookup → counter rimane a 0
- **Conferma**: il dict è caricato, indicizzato e pronto come fallback. Lo zero è la prova che T1+T2 coprono il workload tipico (Microsoft + comuni stack OSS).
- **Fix consigliato (cosmetico)**: rinominare label UI "Used for Matching" in "Tier 3 Lookup Hits" o "Dictionary Activations (lifetime)" per disambiguare. Codice di metrica corretto, label confondente.
- **Discovered**: 2026-05-06
- **Note**: questa è esattamente la categoria di "preoccupazione che a un check di codice si scopre essere expected behavior". Salva-tempo: prima di marcare HIGH bug su counter sospetti, leggere sempre il codice di metrica.


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

**Function**: `sync_nvd_recent_cves` (`cisa_sync.py:1627`)
**Trigger**: scheduler job `nvd_cve_sync` (`scheduler.py`), separate from `cisa_sync` daily
**Args**: `hours_back=6`, `severity_filter`, `max_results=500`
**Endpoint**: `Config.NVD_CVE_API_URL` (post B.1 fix)

🟢 **OK** — function exists, scheduled, uses Config-extracted URL, has rate-limit awareness via NVD API key. No code-only finding.

---

## 08.3 — ENISA EUVD enrich loop

**Function**: enrich loop dentro `sync_cisa_kev` (`cisa_sync.py:1242-1309`)
**Trigger**: scheduler job `euvd_sync` separato + invocazione inline post-CISA KEV
**Endpoint**: `Config.EUVD_API_URL` (post B.1 fix)

🟡 **MEDIUM concern** (08.3.1): pre `[05.3.2]` finding reported `ENISA EUVD: SCHEMA_CHANGED` lato sentrikat-web monitor. Il parser EUVD core deve essere audited contro la R-PARSER-RESILIENCE pattern (defensive `.get()`, alias chain, schema drift telemetry). Da fare quando arrivano i 2 curl di Massimiliano per recuperare sample JSON nuovo. Linka a `VULN-FEED-BROKER-DESIGN.md § R-PARSER-RESILIENCE`.

#### Curl recon outputs 2026-05-06 (preliminary)

Massimiliano da `sentrikat-nurnb-1` (Hetzner SaaS VM):

**CISA KEV** `curl -I https://www.cisa.gov/.../known_exploited_vulnerabilities.json`:
```
HTTP/2 403
content-type: text/html
content-length: 454
x-reference-error: 18.a3d01702.1778075172.d7c3f3c
```
→ **Akamai-fronted block** (header `x-reference-error` è signature Akamai). Tre ipotesi:
1. User-Agent default `curl/X.Y.Z` blacklisted da Akamai bot-protection
2. SentriKat custom UA (`SentriKat/1.0 (Vulnerability Management; +https://sentrikat.com)`, vedi `cisa_sync.py:840`) anch'esso blacklisted → **rotto in produzione**
3. IP range Hetzner cloud blocked → **rotto solo da SaaS deploy**

**Diagnostics follow-up** richieste a Massimiliano:
```bash
curl -I -H 'User-Agent: Mozilla/5.0 (Linux x86_64) Gecko/20100101 Firefox/120.0' \
  'https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json'
curl -I -H 'User-Agent: SentriKat/1.0 (Vulnerability Management; +https://sentrikat.com)' \
  'https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json'
```

**EUVD** `curl https://euvd.enisa.europa.eu/api/v1/vulnerabilities?size=1`:
- 897 byte ricevuti (`jq` parse error → non JSON, probabilmente HTML error/redirect)
- **Hostname sospetto**: SESSION-HANDOFF cita `euvdservices.enisa.europa.eu` (l'endpoint che il core SentriKat usa), la sessione gemella ha testato `euvd.enisa.europa.eu`. **Probabilmente URL sbagliato lato monitor sentrikat-web**.

**Diagnostics follow-up**:
```bash
curl -s 'https://euvd.enisa.europa.eu/api/v1/vulnerabilities?size=1' | head -50  # vedi che è
curl -s 'https://euvdservices.enisa.europa.eu/api/v1/vulnerabilities?size=1' | head -50  # alternative
```

#### Implicazioni per la sessione gemella sentrikat-web ([05.3.2] fix)

- Se CISA 403 è UA-block: fix S = cambiare UA del monitor a quello del cisa_sync core, oppure rotare UA periodicamente
- Se EUVD URL è sbagliato: fix S = cambiare hostname del monitor da `euvd` a `euvdservices`
- In entrambi i casi: **sintomo monitor-side, NON real upstream issue**. Il core SentriKat probabilmente sta ingestendo correttamente entrambe le feed (verifica con sync history del giorno precedente: 05/05/2026 10:22 SUCCESS con 1587 vuln ingerite)

**Cluster bug class**: false positive nel monitoring sentrikat-web (`/admin/datasources` AUTH_CHANGED + SCHEMA_CHANGED) deriva da configurazione monitor sbagliata, NON da rottura reale upstream. Conferma utile dopo i due follow-up curl di Massimiliano.

---

## 08.4 — NVD per-CPE search

**Function**: `fetch_cves_by_cpe(cpe_vendor, cpe_product, max_results=2000)` (`cisa_sync.py:2276`)
**Trigger**: on-demand UI flow ("Discover CVEs for this CPE" button on product detail)
**Endpoint**: `Config.NVD_CVE_API_URL` (post B.1 fix)

🟢 **OK** — on-demand only, no automation. UI verify deferred a quando l'utente clicca il bottone.

---

## 08.5 — CPE backfill

**Function**: `fetch_cpe_version_data(limit=30, oldest_first=False, skip_awaiting=False)` (`cisa_sync.py:941`)
**Trigger**: dentro `sync_cisa_kev` con `cpe_limit=100` + admin via `/api/sync/cpe-backfill`
**Endpoint**: `Config.NVD_CPE_API_URL` (post B.1 fix)

🟡 **08.5.1 MEDIUM** — `cpe_limit=100` per single sync run. Per un customer con 2400 KEV CVEs, ci vogliono 24 sync (= 24 giorni) per backfill completo. Mitigato dal fatto che `bootstrap_post_deploy.sh` chiama il loop in stand-alone, ma per drift incrementale post-deploy il rate è basso. Considerare alzare a 300-500 in un sync fresh (NVD key permits 50 req/30s = 1500/15min).

---

## 08.6 — CVSS enrich + fallback

**Functions**:
- `enrich_with_cvss_data(limit=50)` (`cisa_sync.py:1078`) — inside `sync_cisa_kev`
- `reenrich_fallback_cvss(limit=50)` (`cisa_sync.py:1475`) — scheduled `cvss_reenrich` job

🟢 **OK** — duplo: enrich primario nel sync, refresh per fallback non-NVD. Fallback chain in `_score_to_severity` ben definita (vedi `CVE-MATCHING-PIPELINE.md` § C). No code-only finding.

---

## 08.7 — EPSS sync

**Function**: `sync_epss_scores(force=False)` (`epss_sync.py:85`)
**Trigger**: ⚠️ NON è un job scheduler indipendente. È chiamato **dentro `cisa_sync_job`** (`scheduler.py:721`) dopo che CISA KEV sync ha successo.

🟢 **08.7.1 ✅ FIXED 2026-05-06** (era 🔴 HIGH) — EPSS estratto a scheduler job standalone `daily_epss_sync` con `CronTrigger(hour=4, minute=30, timezone=tz)` indipendente da CISA KEV. La vecchia inline call dentro `cisa_sync_job` rimossa. Ora se CISA KEV fallisce (Akamai 403, NVD rate-limit, network), EPSS continua a girare. EPSS feed FIRST.org si aggiorna ~04:00 UTC; run schedulato a 04:30 (display tz) copre la finestra. Function `epss_sync_job(app)` aggiunta in `scheduler.py:720`.

---

## 08.8 — Public exploit enrichment

**Function**: `enrich_exploit_data` (`exploit_enrichment.py:39`)
**Trigger**: scheduler job `exploit_enrichment`
**Sources**: ExploitDB CSV + GitHub PoC search

🟢 **OK** — scheduled, sets `exploit_public=True/False` + `exploit_url`. Distinto da `is_actively_exploited` (KEV-only).

---

## 08.9 — CPE assignment 4-tier

**Functions**:
- `apply_cpe_to_product(product)` — `cpe_mapping.py:349` (Tiers 1+2+3 only)
- `batch_apply_cpe_mappings(commit, use_nvd, max_nvd_lookups)` — `cpe_mapping.py:408` (T1+2+3+4 with NVD)

🟢 **Reviewed 2026-05-06** — F.2 fix verified live (Apache Tomcat). A.2 fix added logger.warning per Tier 2/3 transient failures. B.2 fix added inline doc per `use_nvd_fallback=False`. Tutti gli audit point chiusi.

---

## 08.10 — check_cpe_match decision tree

**Function**: `check_cpe_match(vulnerability, product)` — `filters.py:57`
**Confidence levels**: 10 scenari documentati in `CVE-MATCHING-PIPELINE.md` § D

🟢 **Reviewed** — coperto dal test `test_check_cpe_match_high_confidence_in_range` (regression guard).

---

## 08.11 — check_keyword_match fallback

**Function**: `check_keyword_match(vulnerability, product)` — `filters.py:245`
**Confidence levels**: 4 (vendor_product/medium → low post-F.6, vendor/medium, product/medium, keyword/low)

🟢 **F.6 fix verified** — coperto dal test `test_check_keyword_match_no_version_returns_low_confidence`. Demote a `low` quando version non verificabile.

---

## 08.12 — Vendor Fix Override

**Function**: `has_vendor_fix_override(vulnerability, product)` — `filters.py:384` (chiamata a `_has_vendor_fix_override` interno)
**A.1 fix applied 2026-05-06**: `except Exception` ora logga warning prima di return None.

🟢 **Reviewed + fixed** — suppression layer ora ha visibility ops in caso di transient DB errors.

---

## 08.13 — Risk Exception

**Function**: `_has_active_risk_exception(vulnerability, product)` — `filters.py:444`
**A.1 fix applied 2026-05-06**: log warning su Exception.

🟢 **Reviewed + fixed**.

---

## 08.14 — cleanup_invalid_matches

**Function**: `cleanup_invalid_matches()` — `filters.py:736` (entry point), runs after every sync via scheduler job `stale_match_cleanup` (`scheduler.py`)
**F.8 fix applied 2026-05-06**: si invoca anche dopo `apply_cpe_to_product` quando un product flippa da no-CPE a CPE.

🟢 **Reviewed + tested** — coperto da smoke test `test_cleanup_invalid_matches_removes_keyword_after_cpe_apply`.

---

## 08.15 — Match confidence surfacing UI

⏸️ **UI verify deferred** — `vulnerability_match.to_dict()` (`models.py:865`) include `match_confidence`. Da verificare nel template dashboard se il badge è renderizzato. Customer-facing data quality badge è uno dei "6 must" (`SESSION-HANDOFF` Week 1 #3).

---

## 08.16 — Sync history

🟢 **Live verified 2026-05-06** in 08.1 (panel Synchronization History): mostra date, status, vuln count, matches found, duration. Endpoint `/api/sync/history` (`routes.py:5575`).

---

## 08.17 — NVD rate-limit awareness

**Module**: `app/nvd_rate_limiter.py` (esiste, da ispezionare)
**Endpoint**: `GET /api/sync/nvd-rate-limit` (`settings_api.py:932`)

🟡 **08.17.1 INFO** — funzionalità presente ma audit del comportamento sotto stress (cosa fa quando hit rate-limit: backoff exponential? retry? fallback?) deferred. Non blocker pre-EA.

---

## 08.18 — NVD API key handling

**Storage**: `system_settings` table, key `nvd_api_key`, organization_id NULL (global)
**Read**: ovunque viene chiamato NVD, include header `apiKey` se presente
**Without key**: 10 req/min, with key 50 req/30s

🟢 **Reviewed + bootstrapable** — `scripts/post_deploy_bootstrap.sh` step 1 gestisce l'inserimento. Documentato in `docs/operations/post-deploy-bootstrap.md`. Chiave attualmente esposta in chat history (vedi `SESSION-HANDOFF` § "License key in chat history") da rotare post-EA.

---

## Riepilogo Phase 08 — code-only audit closure 2026-05-06

| Area | Stato | Note |
|---|---|---|
| 08.1 | ✅ live | CISA KEV sync: 4 finding (1 MED scheduler fail, 1 MED UX, 1 INFO path, 1 INFO false alarm) |
| 08.2 | 🟢 OK | NVD recent — scheduled, Config-URL |
| 08.3 | 🟡 MED | EUVD parser audit pending (post curl recon) |
| 08.4 | 🟢 OK | NVD per-CPE on-demand |
| 08.5 | 🟡 MED | cpe_limit=100/sync potenzialmente slow; OK con bootstrap.sh |
| 08.6 | 🟢 OK | CVSS enrich + fallback |
| 08.7 | 🔴 HIGH | EPSS coupled with CISA KEV — extract to own scheduler job |
| 08.8 | 🟢 OK | Public exploit enrichment scheduled |
| 08.9 | 🟢 OK + fix | F.2 + A.2 + B.2 chiusi |
| 08.10 | 🟢 OK + test | check_cpe_match coperto da test |
| 08.11 | 🟢 OK + test | F.6 demote coperto da test |
| 08.12 | 🟢 OK + fix | A.1 chiuso |
| 08.13 | 🟢 OK + fix | A.1 chiuso |
| 08.14 | 🟢 OK + test | F.8 + smoke test |
| 08.15 | ⏸️ UI | data quality badge — Week 1 6-must |
| 08.16 | 🟢 OK | sync history UI verified |
| 08.17 | 🟡 INFO | rate-limiter audit comportamento sotto stress deferred |
| 08.18 | 🟢 OK | NVD key handling + bootstrap |

**Findings nuovi Phase 08 (oggi)**:
- 🔴 `[08.7.1]` HIGH: EPSS sync coupled con CISA KEV (estrarre a scheduler job separato)
- 🟡 `[08.5.1]` MED: cpe_limit=100/sync slow per drift incrementale large customer
- 🟡 `[08.3.1]` MED: EUVD parser audit pending sample JSON post-curl
- 🟡 `[08.17.1]` INFO: rate-limiter behavior audit deferred

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
| `[08.9.1]` | 🟡 MEDIUM | 🏢☁️ both | Edit Product modal: CPE picker auto-renames vendor+product_name → 409 duplicate |

### [08.9.1] 🟡 Edit Product CPE picker rinomina vendor/product_name → 409 quando esiste già un prodotto con stessi vendor/name

- **Env**: 🏢☁️ both — verificato live su SaaS 2026-05-14
- **Severity**: 🟡 MEDIUM — UX confusa, non blocca workflow
- **Symptom**: utente apre Edit Product su prodotto X (es. Apache/Http Server), nel modal "Find Your Product" cerca "apache tomcat" e seleziona il match → al Save backend risponde 409 "A product with the same vendor, name, and version already exists" perché il modal ha rinominato `vendor=Apache, product_name=Tomcat` (preso dal CPE selezionato) e c'è già un altro prodotto Apache/Tomcat nell'inventario.
- **Root cause**: il frontend del modal usa il CPE search come source of truth per vendor+product_name. In modalità Edit questo è sbagliato — l'utente probabilmente vuole solo cambiare CPE, non rinominare il prodotto.
- **Repro 2026-05-14**:
  1. Crea prodotto Apache Tomcat (CPE apache:tomcat)
  2. Crea prodotto Apache Http Server (CPE apache:http_server)
  3. Edit Apache Http Server → search "apache tomcat" → seleziona match → Save
  4. Toast "A product with the same vendor, name, and version already exists" appare in alto a destra
- **Discovered**: 2026-05-14 durante smoke 1.4 F.8 verify
- **Fix proposte**:
  - (A) Modal in modalità Edit: separare il "CPE picker" dal "vendor/product_name rename". Default: change CPE only.
  - (B) Aggiungere checkbox esplicita "also rename product to match CPE" — off di default in Edit.
  - (C) Backend: se la rename rileva duplicate, restituire 409 con messaggio "use existing product id=Y, or pick a different CPE" e link al record gemello.
- **Effort**: 1-2h frontend modal logic + ~30 min backend error message refine.
- **Priority**: post-EA, non blocker.

---

## Open follow-up

_Da popolare a fine walkthrough._
