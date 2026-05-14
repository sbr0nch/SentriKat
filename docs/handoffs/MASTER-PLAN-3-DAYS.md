# MASTER PLAN — Chiusura E2E completa SentriKat + sentrikat-web

> Piano operativo step-by-step per finalizzare il prodotto in **2-3 giorni reali**: bug fix residui + new features + E2E walkthrough completo + testing. Aggiornato al 2026-05-XX (current main `2c33fe5` = PR #429 mergiato).

## Convenzione

- 🧑 **TU** = operatore (Massimiliano) — browser, PC casa con docker+testlab quando serve
- 🤖 **IO** = Claude session — code, test, docs, autonomo
- ⏱️ effort = giornate-uomo "vere" (per IO ≈ minuti reali; per TU = effort browser/manuale)
- ✅ done · 🟡 in corso · ⬜ pending · 🔧 unverified · ❌ blocked

---

## Day 1 — Smoke test + dev autonomo iniziale

| Step | Owner | Effort | Cosa | Stato |
|---|---|---|---|---|
| 1.1 | 🧑 | 5 min | Verifica `[13.1.2]` filter placeholder dashboard (DOM ispezione) | ⬜ |
| 1.2 | 🧑 | 2 min | Verifica `/admin/health` raw JSON link (click → tab JSON apre) | ⬜ |
| 1.3 | 🧑 | 20 min | Verifica TODO #2 alerting fallback (tenant SaaS nuovo + alert critical → arriva all'admin di registrazione) | ⬜ |
| 1.4 | 🧑 | 10 min | Verifica F.8 purge on CPE flip (admin edit CPE → match vecchi spariscono) | ⬜ |
| 1.5 | 🧑 | 5 min | Verifica F.6 confidence labeling (filtro `Confidence=Low` mostra vendor_product con `cpe_data NULL`) | ⬜ |
| 2.1 | 🤖 | parallel | Scaffold Phase 09 `09-remediation-sla.md` con 7-dim aree | ⬜ |
| 2.2 | 🤖 | parallel | Scaffold Phase 10 `10-compliance-sbom.md` con 7-dim aree | ⬜ |
| 2.3 | 🤖 | parallel | F.5 admin UI `/admin/cpe-failures` (audit log esiste, manca pagina) | ⬜ |
| 2.4 | 🤖 | parallel | F.1 scheduler job `apply_cpe_nvd_backfill` ogni 6h | ⬜ |
| 2.5 | 🧑 | 5 min | Review PR Day-1, merge se OK | ⬜ |

## Day 2 — Walkthrough auth/agents + dev resilience

| Step | Owner | Effort | Cosa | Stato |
|---|---|---|---|---|
| 3.1 | 🧑 | 1-2 g.u. | Phase 06 auth/RBAC 7-dim (PC casa, testlab Keycloak + OpenLDAP) | ⬜ |
| 3.2 | 🤖 | parallel | R-PARSER-RESILIENCE su `euvd_sync` (EUVD path inside cisa_sync.py:1242-1309) | ⬜ |
| 3.3 | 🤖 | parallel | R-PARSER-RESILIENCE su `cve_org` parser | ⬜ |
| 3.4 | 🤖 | parallel | `[08.17.1]` NVD rate-limiter stress audit + `tests/test_nvd_ratelimit_stress.py` | ⬜ |
| 3.5 | 🧑 | 1 g.u. | Phase 07 agents 7-dim (docker locale + VM Win/Linux) | ⬜ |
| 3.6 | 🧑+🤖 | 4h | Phase 08 scanning/matching 7-dim — incorpora F.6/F.8 verifica (dim 5 state transitions + dim 6 negative) | ⬜ |
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
