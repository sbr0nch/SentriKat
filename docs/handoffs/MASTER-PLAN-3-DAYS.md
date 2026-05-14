# MASTER PLAN — Chiusura E2E completa SentriKat + sentrikat-web

> Piano operativo step-by-step per finalizzare il prodotto in **2-3 giorni reali**: bug fix residui + new features + E2E walkthrough completo + testing. Aggiornato al 2026-05-XX (current main `2c33fe5` = PR #429 mergiato).

## Convenzione

- 🧑 **TU** = operatore (Massimiliano) — browser, PC casa con docker+testlab quando serve
- 🤖 **IO** = Claude session — code, test, docs, autonomo
- ⏱️ effort = giornate-uomo "vere" (per IO ≈ minuti reali; per TU = effort browser/manuale)
- ✅ done · 🟡 in corso · ⬜ pending · 🔧 unverified · ❌ blocked

---

## Day 1 — Smoke test + dev autonomo iniziale ✅ COMPLETATO 2026-05-14

| Step | Owner | Effort | Cosa | Stato |
|---|---|---|---|---|
| 1.1 | 🧑 | 5 min | `[13.1.2]` filter placeholder dashboard — verificato live | ✅ |
| 1.2 | 🧑 | 2 min | `/admin/health` raw JSON link | ✅ |
| 1.3 | 🧑 | 20 min | TODO #2 alerting fallback modal label "Currently sending to: X CUSTOM/registration default" | ✅ |
| 1.4 | 🧑 | 10 min | F.8 purge on CPE flip — log SaaS: `F.8 purge_and_rematch: rebuilt matches for 1 product(s)` | ✅ |
| 1.5 | 🧑 | 5 min | F.6 confidence labeling — filtro Confidence=Low presente in dashboard | ✅ |
| 1.6 | 🧑 | 5 min | F.5 `/admin/cpe-failures` page si carica su both | ✅ |
| 1.7 | 🧑 | 3 min | F.1 scheduler — log: `CPE NVD remap scheduled every 4 hours` | ✅ |
| 2.1 | 🤖 | done | Scaffold Phase 09 — già pronto in repo | ✅ |
| 2.2 | 🤖 | done | Scaffold Phase 10 — già pronto in repo | ✅ |
| 2.3 | 🤖 | done | F.5 admin UI `/admin/cpe-failures` — model + migration 0003 + 3 endpoint + template + 7 test | ✅ `cf8309e` |
| 2.4 | 🤖 | done | F.1 scheduler — era già fatto in main | ✅ |
| 2.5 | 🧑 | 5 min | Review PR Day-1, merge | ✅ mergiato pre-Day-2 |

### Bug nuovi scoperti Day 1
- `[08.9.1]` 🟡 MEDIUM: Edit Product CPE picker auto-renames vendor+product_name → 409 duplicate. Vedi `08-scanning-matching.md`. Post-EA fix.
- Bug latente `db NameError` in `check_product_limit` SaaS branch: fixato in `3e4095b` + hoist top-level import in `d0b97b9` + regression test in `tests/test_check_product_limit_saas.py`. Documentato come incident handoff.

## Day 2 — Walkthrough auth/agents + dev resilience

| Step | Owner | Effort | Cosa | Stato |
|---|---|---|---|---|
| 3.1 | 🧑 | 1-2 g.u. | Phase 06 auth/RBAC 7-dim (PC casa, testlab Keycloak + OpenLDAP) | ⬜ |
| 3.2 | 🤖 | done | R-PARSER-RESILIENCE su `euvd_sync` | ✅ `cd12ffb` |
| 3.3 | 🤖 | done | R-PARSER-RESILIENCE su `cve_org` parser — già in main | ✅ |
| 3.4 | 🤖 | done | NVD rate-limiter stress test — già in `tests/test_nvd_rate_limiter_stress.py` (235 righe, 7 test classes) | ✅ |
| 3.5 | 🧑 | 1 g.u. | Phase 07 agents 7-dim (docker locale + VM Win/Linux) | ⬜ |
| 3.6 | 🧑+🤖 | 4h | Phase 08 scanning/matching 7-dim — incorpora F.6/F.8 verifica (dim 5 state transitions + dim 6 negative). Bug `[08.9.1]` già annotato | 🟡 in corso |
| 3.7 | 🧑 | 5 min | Review PR Day-2, merge se OK | ⬜ |

## Day 3 — Integrations + alerts + admin ops + saas-specific + security-edge + chiusura

| Step | Owner | Effort | Cosa | Stato |
|---|---|---|---|---|
| 4.1 | 🧑+🤖 | 1 g.u. | Phase 11 integrations (testlab Jira mock + webhook-tester + SIEM syslog) | ⬜ |
| 4.2 | 🧑+🤖 | 4h | Phase 12 alerts (Mailpit + webhook outbox + TODO #2 fallback dim 4 RBAC + dim 7 audit) | ⬜ |
| 4.3 | 🧑+🤖 | 4h | Phase 13.2-13.15 admin ops (health 13.2, logs 13.3, sync 13.4, backup/restore 13.5, scheduler 13.6, retention 13.7, maintenance 13.8, audit 13.9, users 13.10, license 13.11, prometheus 13.12, otel 13.13, settings 13.14, maintenance ops 13.15) | ⬜ |
| 4.4 | 🧑+🤖 | 1 g.u. | Phase 14 saas-specific (multi-tenant isolation dim 4 RBAC, plan gating, license webhook, trial expiry, metering, TODO #2 cross-tenant test) | ⬜ |
| 4.5 | 🧑+🤖 | 1 g.u. | Phase 15 security-edge manual OWASP (SQLi, XSS, CSRF, LDAP inj, SSRF, command inj, path traversal, rate limit, lockout) | ⬜ |
| 4.6 | 🧑 | mezza g.u. | Phase 16.3-16.5 (docs MkDocs link audit, community Flarum, CI/CD GitHub Actions) | ⬜ |
| 4.7 | 🤖 | parallel | Cross-repo coordination: `[13.1.4]` SaaS SMTP platform-default — apri handoff in `FIX-HANDOFF-sentrikat-web-root.md` | ⬜ |
| 4.8 | 🤖 | final | Aggiorna `00-INDEX.md` con stato finale 16 fasi + crea `SESSION-HANDOFF-end-of-3-day-sprint.md` | ⬜ |

## Out-of-scope per il 3-day sprint (lavoro futuro)

- 6-must #5 agent registry hardening Win MSI long-tail → repo `sentrikat-agent` (separato)
- Strategic moat (vuln-feed broker server+client, intelligence layer) → mese 2-3
- Paid: pentest pro 5-10k€ + ENISA EUVD creds form → quando vuoi
- POSTGRES_PASSWORD + NVD API key rotation prod → ops, runbook esiste

## Convenzione PR

Una branch dedicata per ogni Day, commit granulari per step, push frequenti:
- `claude/day-1-smoke-and-dev` (Step 2.1-2.4)
- `claude/day-2-walkthrough-and-resilience` (Step 3.2-3.4)
- `claude/day-3-final-walkthrough-cleanup` (Step 4.7-4.8)

Walkthrough E2E (Step 1.x, 3.1, 3.5, 3.6, 4.1-4.6) modificano solo doc, possono andare nella branch del Day.

## Comunicazione live

Durante l'esecuzione di ogni step:
- 🤖 IO annuncia start step, push appena finito, breve riassunto
- 🧑 TU riporti screenshot/output per smoke test e walkthrough, io annoto bug nel file fase
- Bug ID format: `[FF.S.B]` come da convenzione 00-INDEX.md
