# SESSION HANDOFF — 2026-05-08

> Successore di `archived/SESSION-HANDOFF-2026-05-07.md`. Leggi quello prima per il contesto storico (TODO #2 alerting fallback, Batch C closure, docs reorganize).

## TL;DR sessione 2026-05-08

🟢 **Stato invariato: SHIP-READY**. Nessun bug HIGH aperto.

| PR del giorno | Branch | Cosa |
|---|---|---|
| (open, da mergiare) | `claude/cve-matching-fixes-f6-f8` | F.8 purge + rematch on CPE flip — manual UI + batch refactored. F.6 era già implementato 2026-05-05 (`9b7932e`); il commit aggiunge solo regression test. |

PR del 2026-05-07 già su `main`:
- `cff206e` Merge #427 — TODO #2 alerting fallback + Batch C closure
- `60ef5e4` Merge #428 — Docs reorganize Step 1+2+3

Branch zombie da cancellare a piacere (UI GitHub): `claude/post-ea-week1-batch-C` (commit `d7377c5` redundant).

---

## ✅ Cosa abbiamo fatto fino a oggi (post-EA week 1)

| Item | Stato | Quando |
|---|---|---|
| TODO #1 welcome email retest | chiuso utente | 2026-05-07 mattina |
| TODO #2 alerting email default fallback | mergiato | PR #427 / 2026-05-08 |
| Batch C `[13.1.2]` filter placeholder | mergiato | PR #427 |
| Batch C raw JSON link 404 | mergiato | PR #427 |
| Batch C 4 silent except logger sweep | mergiato | PR #427 |
| Batch C `[08.5.1]` cpe_limit 100→300 | già fatto in PR #414 | — |
| Batch C R-PARSER-RESILIENCE su parse_and_store_vulnerabilities | già fatto in PR #414 (esteso a nvd_api + epss_sync) | — |
| Docs reorganize Step 1+2+3 | mergiato | PR #428 |
| F.6 demote keyword vendor_product confidence | già fatto in `9b7932e` 2026-05-05 (regression test aggiunto oggi) | 2026-05-05 |
| F.8 purge + rematch on CPE flip | PR open `claude/cve-matching-fixes-f6-f8` | 2026-05-08 |

---

## 📋 Backlog aggiornato

### 🔴 1. Smoke test residui (operatore, ~45 min totali)

| # | Voce | Effort | Cosa fare in concreto |
|---|---|---|---|
| 1.1 | Verifica `[13.1.2]` filter placeholder | 5 min | Apri dashboard on-prem o SaaS post-deploy, ispeziona DOM Vendor/Product input. Conferma `placeholder="Filter by vendor…"` (no brand example). |
| 1.2 | Verifica `/admin/health` raw JSON link | 2 min | Click sul link in fondo alla pagina health → deve aprire `/api/admin/health-summary` in nuovo tab senza 404. |
| 1.3 | Verifica TODO #2 alerting fallback | 20 min | Crea tenant SaaS test, NON configurare custom email, attendi alert critical → deve arrivare all'email di registrazione admin con label `(registration default)` visibile nel modal `/admin/alerts → Delivery`. |
| 1.4 | **NUOVO** verifica F.8 purge on CPE flip | 10 min | Su on-prem: scegli un prodotto agent-push senza CPE che ha 5+ match keyword/vendor_product (es. "Microsoft Visual C++ Redistributable"). Vai su `/products/{id}` → Edit → setta `cpe_vendor=microsoft`, `cpe_product=visual_c++` → Save. Verifica che (a) i match keyword vecchi spariscono, (b) appaiono nuovi match `cpe/high` o nessun match (entrambi sono OK — è il segnale che F.8 ha pulito). |
| 1.5 | **NUOVO** verifica F.6 confidence labeling | 5 min | Filtra dashboard per `Match Confidence = Low (keyword only)`. Conferma che match `vendor_product` per CVE con `cpe_data IS NULL` ora appaiono come `low` (non più `medium`). Tipico: vecchi CVE 2009-2015 contro prodotti Windows generici. |

### 🟡 2. Multi-day dev hardening (post-evento, ~9-12 dev-days totali — ridotto)

| # | Voce | Effort | Impatto | Note |
|---|---|---|---|---|
| 2.1 | ~~F.6 demote vendor_product confidence~~ | — | — | ✅ già fatto 2026-05-05 (`9b7932e`) + regression test 2026-05-08 |
| 2.2 | ~~F.8 cleanup post-CPE-flip~~ | — | — | ✅ PR open 2026-05-08 (manual UI + batch refactor) |
| 2.3 | **F.1** scheduler job `apply_cpe_nvd_backfill` ogni 6h su prodotti `cpe_vendor IS NULL` | 2 g.u. | chiude gap "agent push lascia 100/100 prodotti senza CPE per giorni" | richiede APScheduler + NVD rate-limit handling |
| 2.4 | **F.5** `CpeAssignmentFailure` table + admin UI `/admin/cpe-failures` | 1 g.u. | visibility su mapping rifiutati dal validator | F.5 audit log già aggiunto in `cpe_mapping.py:419-432` (CPE_REJECTED audit_event) — manca solo la UI dedicata |
| 2.5 | R-PARSER-RESILIENCE estesa a euvd_sync + cve_org parser | 2 g.u. | resilienza schema drift cross-feed | oggi solo cisa_sync/nvd_api/epss_sync coperti |
| 2.6 | 6-must #5 agent registry parser hardening Win MSI long-tail | 3-4 g.u. | chiude F.9 al 100% | repo `sentrikat-agent` (NON questo) |
| 2.7 | `[13.1.4]` SaaS SMTP platform-default Resend | 2h | nuovi tenant SaaS non vedono più "SMTP not configured" | cross-repo con sentrikat-web |
| 2.8 | `[08.17.1]` NVD rate-limiter audit sotto stress | 4h | benchmark + tuning, evita degrade silenzioso | scrivere `tests/test_nvd_ratelimit_stress.py` |

### 🟠 3. Walkthrough E2E live (multi-day, opzionale post-EA, ~10-15 g.u.)

> **Importante**: i walkthrough devono ora **incorporare verifica delle nuove feature** post-2026-05-07 (TODO #2 alerting fallback, [13.1.2], raw JSON link, F.6, F.8). Smoke test 1.x sopra coprono il quick check; il walkthrough completo li ri-testa in 7-dim (negative input, RBAC, persistence, ecc.).

| # | Phase | Effort | Surface | Aggiunte 2026-05-08 da incorporare |
|---|---|---|---|---|
| 3.1 | Phase 06 auth/RBAC 7-dim (testlab Keycloak+OpenLDAP) | 1-2 g.u. | sicurezza | — |
| 3.2 | Phase 07 agents 7-dim (docker locale + VM Win/Linux) | 1 g.u. | parser long-tail | dim 5 state transitions: agent push → CPE flip → F.8 cleanup verifica |
| 3.3 | Phase 08 scanning/matching 7-dim | 1 g.u. | matching pipeline | **F.6 confidence demotion** dim 6 negative + dim 7 audit; **F.8 purge** dim 5 state transitions; verifica `match_confidence='low'` filtering UI |
| 3.4 | Phase 09 remediation (assignments, SLA, risk exception) | 4-8h | workflow customer | — |
| 3.5 | Phase 10 compliance (report PDF) | 4-8h | enterprise deliverable | report PDF deve nascondere `confidence='low'` di default? decisione di prodotto |
| 3.6 | Phase 11 integrations (Jira, Slack, Teams, webhook, SIEM) | 1 g.u. | moat sticky | — |
| 3.7 | Phase 12 alerts (digest, Patch Tuesday, throttling) | 4h | alerting stress | **TODO #2 fallback dim 7 audit**: log evento "alert sent to registration_default" deve essere visibile in audit_events |
| 3.8 | Phase 13 admin ops sub-areas (13.2-13.15) | 4h | sub-aree | `/admin/health` raw JSON link dim 4 RBAC (manager non deve vederla) |
| 3.9 | Phase 14 saas-specific (multi-tenant isolation, plan gating) | 1 g.u. | rischio #1 | TODO #2 fallback dim 4 RBAC: tenant A admin non riceve alert per tenant B (isolation) |
| 3.10 | Phase 15 security-edge (OWASP A01-A07 manuale + edge cases) | 1 g.u. | + pentest pro | — |

### 🟢 4. Strategic moat (mese 2-3, ~6-8 settimane)
- 4.1 Vuln-feed broker server-side (sentrikat-web) — 3-4 settimane
- 4.2 Vuln-feed broker client-side (core) — 1 settimana
- 4.3 Sentrikat proprietary intelligence layer — 2-4 settimane

### 🔵 5. Esterno / paid
- 5.1 Pentest professionale ~5-10k€ pre-customer-enterprise
- 5.2 ENISA EUVD developer credentials (form gratuito)
- 5.3 POSTGRES_PASSWORD rotation prod (runbook esiste)
- 5.4 NVD API key rotation prod (runbook esiste, key esposta in chat)

---

## 🚀 Prossima azione suggerita

| Tempo | Suggerimento |
|---|---|
| **5-10 min smoke test** | 1.1 + 1.2 (rapidi, browser-only) |
| **30-45 min smoke test completo** | 1.1 + 1.2 + 1.3 + 1.4 + 1.5 |
| **0.5 g.u. autonoma** | 2.4 F.5 admin UI `/admin/cpe-failures` (audit log già scritto, manca solo la pagina che lo legge filtrato) |
| **2 g.u. autonoma** | 2.3 F.1 scheduler job NVD backfill — chiude il gap "agent push 100/100 senza CPE" che è il root cause #1 dei falsi positivi |
| **chiusura post-EA week 1** | 2.5 R-PARSER-RESILIENCE su euvd/cve_org + 2.7 `[13.1.4]` SaaS SMTP — entrambe sotto le 4h, completano il pacchetto resilience |

---

## 🛡️ Anti-timeout reminder

- Mai Read/Edit > 250 righe in colpo
- Mai Bash con output > 15KB (usa head, --max-count, -n)
- Commit + push ogni 1-2 step utili
- Mai Agent (subagent) per task incrementali
- Branch nuovo `claude/<task-name>` da main aggiornato
