# SentriKat — Pre-Launch Manual Testing Checklist

> **Scopo:** questa cartella contiene la checklist completa di test manuali
> da eseguire **prima di annunciare il prodotto pubblicamente**. Ogni file
> e' una parte autonoma, stampabile separatamente. Un file per ogni area.

---

## Come usarla

1. **Stampa i file che ti servono** (o tieneli aperti in un tab del
   browser). Ogni `[ ]` e' un test da fare: segna `X` se passa, `F` se
   fallisce, `S` se lo skippi consapevolmente (scrivi il motivo a lato).
2. **Parti da `01_prerequisites.md`**. Se qualcosa la' non esiste,
   **fermati** e fixalo prima di qualsiasi altro test.
3. **Poi `02_smoke_test_critical_path.md`** (30 minuti). Se qualcosa qui
   fallisce → **STOP**: c'e' un blocker di produzione.
4. **Poi le altre parti** (03-09). Puoi decidere quali fare prima in base
   al tempo che hai. Le priorita' alte sono: 05 (security hardening), 06
   (cross-repo integration), 07 (cross-tenant), 09 (go-live).
5. **Alla fine** hai il permesso di lanciare. Non prima.

---

## Indice delle parti

| # | File | Durata stimata | Priorita' |
|---|---|---|---|
| A | [`01_prerequisites.md`](01_prerequisites.md) | 10 min | 🔴 Obbligatoria |
| B | [`02_smoke_test_critical_path.md`](02_smoke_test_critical_path.md) | 30 min | 🔴 Obbligatoria |
| C | [`03_core_features.md`](03_core_features.md) | 2-3h | 🟠 Alta |
| D | [`04_sprint4_5_features.md`](04_sprint4_5_features.md) | 1-2h | 🔴 Obbligatoria (nuove feature) |
| E | [`05_security_hardening.md`](05_security_hardening.md) | 1h | 🔴 Obbligatoria |
| F | [`06_cross_repo_integration.md`](06_cross_repo_integration.md) | 1-2h | 🔴 Obbligatoria (flussi end-to-end SaaS ↔ admin portal) |
| G | [`07_cross_tenant_isolation.md`](07_cross_tenant_isolation.md) | 30 min | 🔴 Obbligatoria (multi-org) |
| H | [`08_browser_and_agents.md`](08_browser_and_agents.md) | 1h | 🟠 Alta |
| I | [`09_go_live_and_post_launch.md`](09_go_live_and_post_launch.md) | 30 min + ongoing | 🔴 Obbligatoria (ultimo giorno + 48h dopo) |

**Totale tempo minimo** per una passata completa: **~6-9 ore**. Puoi
spalmarle su 2-3 giorni. La minimum viable "launch gate" e' A + B + D +
E + F + G + I = ~5 ore, sacrificando C (feature esistenti testate
molte volte in passato) e H (browser/agent — si fanno prima ma non
bloccanti se sai che i tuoi clienti usano Chrome moderno).

---

## Stato al 2026-04-14

- **Test suite automatica**: 1.328 / 1.329 passing (99.92%). L'unico fail
  e' un edge case di test environment, non una regressione. Vedi
  `docs/business/99_TODO_BEFORE_LAUNCH.md` sezione 0.8.
- **Sprint 4+5 audit**: completato. Tutti i BLOCKER + MEDIUM + LOW fixati
  (vedi commit `da73199`). Debito tecnico rimanente documentato in
  `docs/business/99_TODO_BEFORE_LAUNCH.md`.
- **Deploy**: avvenuto con successo sulla VM di produzione con la
  migration SQL per le 5 tabelle nuove (Sprint 4+5). Container sentrikat
  `healthy`, scheduler jobs Sprint 4+5 registrati.

---

## Convenzioni dei file

- Codice da copia-incollare in shell → `code block` con `bash` highlight
- Variabile da sostituire → `<NOME_VARIABILE>`
- Link a un altro documento → `docs/...` o `tests/...` relative path
- Nota di pericolo → **⚠️** in testa al paragrafo
- Nota di nota → **💡**

---

## Dopo il lancio

Quando tutto questo e' verde e il prodotto e' live, passa a:
- `docs/business/99_TODO_BEFORE_LAUNCH.md` — debito tecnico residuo per
  Sprint 6-7
- `docs/business/22_PRICING_ANALYSIS_POST_SPRINT_5.md` — analisi prezzi
- `docs/PRE_LAUNCH_AUDIT_AND_TESTING_PLAN.md` PARTE 9+10 — report
  completo dell'audit Sprint 4+5

Buon lancio.
