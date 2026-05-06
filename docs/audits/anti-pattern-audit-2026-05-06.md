# Anti-Pattern Audit — 2026-05-06

> **Tipo**: static code review — NO fix applicato in questa sessione, solo catalogo.
> **Scope**: `app/*.py` (74 file, 70k righe).
> **Audience**: Massimiliano (operator) + future Claude session per prioritizzare fix post-EA.
> **Trigger**: domanda dell'utente "ho paura che fixiamo fixiamo poi comunque è pieno di bug LOGICI" → risposta proposta = audit statico signal/noise alto invece di altri walkthrough UI.

---

## Sintesi numerica

| Metric | Count |
|---|---|
| Total `except Exception:`/`except:` blocks across `app/*.py` | **131** |
| of which **silent** (no log, only `pass`/`return None`/`continue`) | **131** stimati (campionamento) |
| **🔴 HIGH** concern (mascherano regressioni o suppression) | **3 cluster** |
| **🟡 MEDIUM** concern (hardcoded URL, missing inline doc) | **2 categorie** |
| **🟢 OK** (intent documentato o backwards-compat) | resto (~125 silent) |

---

## 🔴 HIGH severity — fix raccomandati Week 2 post-EA

### A.1 — `filters.py:432` `has_vendor_fix_override` silent return None

**File**: `app/filters.py:425-433`
```python
try:
    from sqlalchemy import func
    override = VendorFixOverride.query.filter(...).first()
    # ...
    return override
except Exception:
    return None
```

**Perché preoccupa**: questa è una **suppression layer** (vedi `CVE-MATCHING-PIPELINE.md` §E). Quando un admin ha registrato un Vendor Fix Override (es. "RHEL ha backportato il fix di CVE-X in version Y"), il match deve essere soppresso. Se la query SQL solleva eccezione (DB transient error, schema migration in corso, FTS index lock, ecc.) → `return None` silenzioso → il match NON viene soppresso → il customer vede un falso positivo. **Esattamente il bug class che vogliamo evitare** ("zero coverage parziale" del CLAUDE.md).

**Fix raccomandato**:
```python
except SQLAlchemyError as e:
    logger.warning(f"VendorFixOverride lookup failed for CVE={vulnerability.cve_id} product={product.id}: {e}")
    # Return None to err on side of "show match" — better false positive than missed suppression
    return None
```

Same pattern probably in `_has_active_risk_exception` (filters.py:445+) — to verify.

**Severity**: 🔴 HIGH per credibilità (admin fa un override, sistema lo ignora silenziosamente, customer vede match risolto come ancora aperto, fiducia rotta).
**Effort**: S (~30 min di code change + log + test).

---

### A.2 — `cpe_mapping.py:378+388` Tier 2 + Tier 3 fallthrough silent

**File**: `app/cpe_mapping.py:371-389` (within `apply_cpe_to_product`, the function we just fixed in F.2)

```python
# Tier 2: Try curated dictionary + user mappings (comprehensive)
if not cpe_vendor or not cpe_product:
    try:
        from app.cpe_mappings import get_cpe_for_software
        cpe_vendor, cpe_product, _ = get_cpe_for_software(...)
    except Exception:
        pass

# Tier 3: Try local CPE dictionary
if not cpe_vendor or not cpe_product:
    try:
        from app.cpe_dictionary import lookup_cpe_dictionary
        cpe_vendor, cpe_product, _ = lookup_cpe_dictionary(...)
    except Exception:
        pass
```

**Perché preoccupa**:
- F.2 fix appena verificato live (Apache Tomcat) usa Tier 1 (regex). Funziona.
- Ma se il DB è temporaneamente irraggiungibile durante un agent push burst (transient connection pool exhaustion), `lookup_cpe_dictionary` raise → `pass` → product saved senza CPE → **silently no CVE match**.
- Stesso problema se `get_cpe_for_software` import fallisce (race condition in module loading).
- L'utente non avrà mai un segnale che T2/T3 stanno fallendo se non sta cliccando "Used for Matching" counter (che è 0 a regime, vedi `[08.1.2]`).

**Fix raccomandato**: aggiungere `logger.warning(f"Tier 2 lookup failed for {product.vendor}/{product.product_name}: {e}")` invece di `pass`. Stesso per T3. Ottiene la stessa robustezza ma genera segnale ops.

**Severity**: 🔴 HIGH se il DB ha mai problemi transient — altrimenti solo MEDIUM.
**Effort**: S (~15 min).

---

### A.3 — `agent_api.py:655` agent inventory path uses `use_nvd_fallback=False`

**File**: `app/agent_api.py:655`
```python
cpe_v, cpe_p, _ = get_cpe_for_software(vendor, product_name, use_nvd_fallback=False)
```

**Status**: NON è un nuovo bug — già documentato come **F.1** in `CVE-MATCHING-PIPELINE.md` (line 265-273). Lo cataloghiamo qui solo per completezza dell'audit.

Il flag `use_nvd_fallback=False` è intenzionale (NVD lookup at agent push blocca ingestion su rate-limit). Ma:
1. Non c'è inline comment che spiega "intenzionale, vedi F.1"
2. Dipende dall'esistenza di un cron `batch_apply_cpe_mappings(use_nvd=True)` che oggi NON è schedulato (vedi 6-must #1 nel SESSION-HANDOFF)

**Fix raccomandato**: 2 cose separate
1. Inline comment + link a F.1 (1 min)
2. Implementazione del cron schedulato `batch_apply_cpe_mappings(use_nvd=True)` Week 1 post-EA (vedi SESSION-HANDOFF "6 must #1") — 2-3 giorni di lavoro

**Severity**: 🔴 HIGH se il cron non viene schedulato — i 30 product Windows generici resteranno senza CPE per sempre.

---

## 🟡 MEDIUM severity — Week 2-3 post-EA

### B.1 — Hardcoded URLs NVD/CISA/EUVD ripetuti in 6+ file

**Files**:
- `app/cpe_dictionary.py:357` `_CPE_CSV_URL`
- `app/cpe_dictionary.py:360` `_NVD_CPE_API_URL`
- `app/nvd_api.py:83, 151, 289` (NVD CVE + MITRE 5.x)
- `app/nvd_cpe_api.py:215, 543, 618, 710` (NVD)
- `app/cisa_sync.py:1707, 1909, 2123` (NVD CVE)

**Perché preoccupa**: NVD ha già fatto migration di endpoint nel passato (v1.0 → v2.0 — 2023). Se rifa, dobbiamo cercare/sostituire in 9+ posti, alto rischio di dimenticare uno e creare deriva. Stesso per quando il **vuln-feed broker** (mese 2-3) andrà online: dovremo redirezionare TUTTI questi a `vuln-feed.sentrikat.com` con un singolo flag.

**Fix raccomandato**: estrarre in `app/config_endpoints.py` o `Config` class con override env-var:
```python
class Config:
    NVD_CVE_API_URL = os.getenv('NVD_CVE_API_URL', 'https://services.nvd.nist.gov/rest/json/cves/2.0')
    NVD_CPE_API_URL = os.getenv('NVD_CPE_API_URL', 'https://services.nvd.nist.gov/rest/json/cpes/2.0')
    # ...
```

Quando il broker andrà live: `NVD_CVE_API_URL=https://vuln-feed.sentrikat.com/api/v1/cves` via env, zero code change.

**Severity**: 🟡 MEDIUM — non rompe niente oggi, ma debt che cresce.
**Effort**: M (~2h refactor + grep+sed dei 9 punti).

---

### B.2 — `cpe_mapping.py:376` `use_nvd_fallback=False` senza inline doc

**File**: `app/cpe_mapping.py:376` (within `apply_cpe_to_product`)
```python
cpe_vendor, cpe_product, _ = get_cpe_for_software(
    product.vendor, product.product_name, use_nvd_fallback=False
)
```

**Perché preoccupa**: nuovo dev legge questa riga, vede `use_nvd_fallback=False`, pensa "ah, qui non vogliamo NVD". Cambia in `True` "per migliorare il matching". → Agent ingestion in produzione si blocca su NVD rate-limit, agent push fallisce in batch.

**Fix raccomandato**: 1 riga di commento.
```python
cpe_vendor, cpe_product, _ = get_cpe_for_software(
    product.vendor, product.product_name,
    # NVD fallback disabled here intentionally — see CVE-MATCHING-PIPELINE.md §F.1.
    # NVD lookups are deferred to scheduled batch_apply_cpe_mappings cron.
    use_nvd_fallback=False
)
```

**Severity**: 🟡 MEDIUM (futuro-Claude o futuro-dev rischia di fare il "fix" sbagliato).
**Effort**: 1 minuto.

---

## 🟢 Audit clean (silent except è appropriato)

Categorie di silent-except documentate o legitimately benign — **non toccare**:

| Pattern | Esempi | Motivo OK |
|---|---|---|
| Backwards-compat tabelle non ancora migrate | `agent_api.py:6408, 6634`, `routes.py:3208, 3246` con `# Container/DependencyScan tables may not exist yet` | Comment esplicito, intent chiaro |
| Best-effort SIEM forwarding | `filters.py:728` con `# SIEM forwarding is best-effort, never block matching` | Comment esplicito, intent chiaro |
| Defensive parsing CPE data | `cisa_sync.py:99, 890, 896` parsing JSON cpe_data field | Fallback a seed patterns, log debug presente |
| Error-recovery rollback in error handler | `cisa_sync.py:1446, 1465` rollback di rollback | Se il rollback fallisce, niente di più da fare |
| Worker cleanup in `finally` | `agent_api.py:1208` `db.session.remove()` | Cleanup best-effort, benign |
| `org_memberships` fallback | `routes.py:1794, 1861` | Single-org behavior se relationship non popolata |
| Validation early-exit | tanti `routes.py` `except ValueError: pass` su int parsing | Falla gracefully a default value |

---

## Pattern NON trovati (good news)

- ❌ Zero `except: pass` (bare except). Tutti gli `except Exception:` o specifici.
- ❌ Zero `commit()` mancanti dopo `add()` osservabili da grep statico (l'app usa session-flush coerentemente).
- ❌ Zero hardcoded prices/limits in `app/*.py` (sono in `plans_config` lato sentrikat-web, separato).

---

## Priorità per dopo-EA

**Week 1 (≤2026-05-15)**:
- A.1 `filters.py:432` `has_vendor_fix_override` log + verify (~30 min)
- A.2 `cpe_mapping.py:378+388` log Tier 2/3 failures (~15 min)
- B.2 `cpe_mapping.py:376` inline comment (~1 min)

**Total Week 1 effort**: ~50 min, **alto valore signal/noise**.

**Week 2-3**:
- A.3 cron schedulato `batch_apply_cpe_mappings(use_nvd=True)` (parte del 6-must, già pianificato)
- B.1 estrazione URLs in Config — refactor 2h, propagare lentamente

**Mese 2+**:
- Audit completo dei 131 silent-except con copertura caso-per-caso (probabilmente 90% sono OK, 10% richiedono log).

---

## Cross-reference

- `docs/architecture/CVE-MATCHING-PIPELINE.md` § F.1, F.6, F.8 — gap già noti coerenti con questo audit
- `docs/SESSION-HANDOFF-2026-05-06.md` § "6 must" #1 — cron `batch_apply_cpe_mappings` schedulato è la fix di A.3
- `docs/architecture/VULN-FEED-BROKER-DESIGN.md` § "R-PARSER-RESILIENCE" — pattern simile per parser broker (mese 2-3)

## Note metodologiche

- L'audit è **statico** (grep + AST scan via Python script). Non sostituisce il test funzionale, ma trova categorie di bug che il test funzionale fatica a rivelare (silent failures sotto carico transient).
- Lo script Python usato è inline nel comando bash della sessione 2026-05-06 — se va replicato, riprodurre in `scripts/audit_silent_excepts.py` come tool ricorrente CI.
- Il pattern A.1 (`has_vendor_fix_override`) è il più critico perché coinvolge la **suppression layer**, che è il pezzo di pipeline più fragile (un bug qui significa false positive visibile al customer).
