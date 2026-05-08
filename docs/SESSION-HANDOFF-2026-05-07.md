# SESSION HANDOFF — 2026-05-07

> Continuation of `SESSION-HANDOFF-END-OF-DAY-2026-05-06.md`. Read that one first for the broader context (11 PR mergiate, ship-ready state, customer journey verified live).

## TL;DR sessione 2026-05-07

🟢 **Stato invariato: SHIP-READY**. Nessun bug HIGH aperto.

Branch lavoro: `claude/review-cve-pipeline-Xdz9m` (2 commit nuovi, da PR-are quando l'utente vuole).

| Commit | Cosa |
|---|---|
| `b4c5841` | feat(alerts): registration-default fallback per org notification emails + UI label (TODO #2) |
| `48c2ffc` | chore(batch-c): [13.1.2] filter placeholder + raw JSON link + silent except logger sweep (TODO #3) |

### TODO #1 (welcome email retest) — chiuso dall'utente prima che io intervenissi.

### TODO #2 (alerting email default) — DONE
- `Organization.resolve_alert_recipients()` con priorità `custom → registration_default (earliest org_admin) → final fallback (earliest user)`.
- Wiring: `email_alerts.py` (2 call sites), `health_checks.py` (warning vs hard-fail), `settings_api.py` `/alerts/org-overrides`, `Organization.to_dict()`.
- UI: `alerts_settings.html` delivery modal mostra "Currently sending to: X (registration default | custom)" — aggiornato live mentre l'utente digita.
- Test: `tests/test_alert_recipient_fallback.py` (8 case — custom wins, fallback, invalid JSON, inactive admin, no users, whitespace-only, to_dict, double-encoded).

### TODO #3 (Batch C residuo) — DONE (parecchio era già stato fatto in PR precedenti)

| Item handoff | Stato reale 2026-05-07 |
|---|---|
| C.1 [13.1.2] filter Microsoft/Windows placeholder | ✅ FIX nuovo (`48c2ffc`): placeholder ora "Filter by vendor…" / "Filter by product…" + autocomplete=off (rimossa confusione brand→value). Da verificare con screenshot post-deploy. |
| C.1bis raw JSON link 404 su /admin/health | ✅ FIX nuovo (`48c2ffc`): rimosso JS `openHealthSummaryJson` blob handler, link ora anchor diretto `target="_blank"` su `/api/admin/health-summary`. |
| C.2 anti-pattern logger sweep ~14 silent excepts | 🟢 quasi tutti già fixati nelle PR #414/#415 (audit doc out of date). 4 reali identificati e patchati: `agent_api.py:4642` audit log, `agent_api.py:5621` V3Score CVSS parse, `integrations_api.py:713` CPE version lookup, `integrations_api.py:757` F.3 fallback. `nvd_api/nvd_cpe_api/cisa_sync` già con `logger.warning` — niente da fare. |
| C.3 [08.5.1] cpe_limit raise 100→300 | 🟢 già fatto in PR #414. `cisa_sync.py:1505` `cpe_limit=300` con commento `[08.5.1] (post-EA week1)`. |
| C.4 R-PARSER-RESILIENCE applied a `parse_and_store_vulnerabilities` | 🟢 già fatto. `cisa_sync.py:962-1077` import da `parser_resilience` con `_KEV_ALIASES`, `require_aliased`, `get_aliased`, `coerce_bool`, `detect_schema_drift`. Pattern esteso anche a `nvd_api.py` (3 call sites) e `epss_sync.py`. Tests: `tests/test_parser_resilience.py` + `tests/test_parser_resilience_extended.py`. |
| C.5 pytest regression test per Batch C | 🟢 implicito: TODO #2 ha test nuovo, [13.1.2] è UI-only (nessun test logico), R-PARSER-RESILIENCE coperto da test esistenti. |

---

## 📋 LISTA COMPLETA — cosa manca / cosa fare

Aggiornato 2026-05-07 fine-sessione. Ordinato per priorità decrescente.

### 🔴 1. Smoke test residui (operatore, ~1h)

- **B.5 W3 wizard step 2-6** — `docker compose down -v` + walkthrough setup wizard fresh on-prem. Da documentare in `docs/e2e-tests/03-signup-onprem.md` step 2-6.
- **Verifica live [13.1.2] fix** — screenshot dashboard post-deploy con nuovo placeholder, confermare rimozione brand-confusion.
- **Verifica live raw JSON link** — click dal `/admin/health` → deve aprire JSON in nuovo tab senza 404.
- **Verifica live TODO #2 fallback** — creare tenant SaaS test, NON configurare custom email, attendere alert critical → deve arrivare all'email del registrazione admin con label "(registration default)" visibile in UI.

### 🟠 2. Walkthrough E2E live (multi-day, post-evento)

| Phase | Effort | Surface | Stato |
|---|---|---|---|
| 03 wizard step 2-6 | 1h | destructive on-prem fresh | scaffold + step 1 done |
| 06 auth/RBAC 7-dim | 1-2 giorni | testlab Keycloak+OpenLDAP | scaffold (16 aree mappate) |
| 07 agents 7-dim | 1 giorno | docker compose locale | scaffold (20 aree mappate) |
| 08.15+08.16 UI | 1h | match badge + sync history | scaffold |
| 09 remediation | 4-8h | assignments, SLA, risk exception | ⬜ scaffold da fare |
| 10 compliance | 4-8h | report PDF generation | ⬜ scaffold da fare |
| 11 integrations | 1 giorno | testlab Jira mock + SMTP | ⬜ scaffold da fare |
| 12 alerts | 4h | Mailpit + webhook tester | ⬜ scaffold da fare |
| 13.2-13.15 admin ops | 4h | sub-aree | scaffold |
| 14 saas-specific | 1 giorno | bridge license-server | scaffold (22 aree mappate) |
| 15 security-edge | 1 giorno | OWASP smoke + edge cases | scaffold (40 aree mappate); pentest pro raccomandato |
| 16.3-16.5 | mezza giornata | n8n + nginx + CI/CD | parziale |

**Totale stimato**: ~10-15 giornate uomo distribuite su settimane.

### 🟡 3. Multi-day dev (post-evento, prima dello scaling)

| Item | Effort | Where | Note |
|---|---|---|---|
| **6-must #5 agent registry parser hardening** Win MSI (DisplayVersion vs Version, InstallShield builds) — long-tail vendors con registry non-standard | 3-4 dev-days | repo `sentrikat-agent` | F.9 in CVE-MATCHING-PIPELINE.md ha già hardening base; rimangono i vendor non-standard |
| **6-must #4 R-PARSER-RESILIENCE applied a euvd_sync + cve_org_sync** (oltre cisa_sync/nvd/epss già fatti) | 2 dev-days | core | EUVD-only path inside cisa_sync.py 1242-1309 ancora dict-direct |
| **F.1 apply_cpe_to_product NVD background job** (su agent push i prodotti senza CPE rimangono CPE-less fino al batch admin-triggered) | 2 dev-days | core | aggiungere scheduler job che chiama `batch_apply_cpe_mappings(use_nvd=True)` su prodotti con cpe_vendor IS NULL |
| **F.5 validate_cpe_assignment failures table** (admin-visible elenco rejection del validator, oggi solo WARNING log) | 1 dev-day | core | traceability: spesso un buon mapping viene scartato da heuristic word-overlap |
| **F.6 demote keyword `vendor_product` confidence to 'low'** quando version non verificabile | 0.5 dev-day | core | mitigation B in CVE-MATCHING-PIPELINE.md §F.6; più conservativo del default attuale 'medium' |
| **F.8 cleanup_invalid_matches dopo CPE flip su prodotto** (oggi i match keyword vecchi rimangono) | 1 dev-day | core | trigger su `apply_cpe_to_product` quando flippa da no-CPE a CPE |
| **[13.1.4] SaaS SMTP platform-default Resend** — nuovi tenant SaaS oggi vedono "SMTP not configured" banner | 2h | cross-repo | richiede coordination con sentrikat-web (license-server endpoint per SMTP shared) |
| **[08.17.1] NVD rate-limiter audit** comportamento sotto stress | 4h | core | benchmark con + senza API key + scenario rate-limit raggiunto |

**Totale**: ~12-15 dev-days.

### 🟢 4. Strategic moat (mese 2-3)

- **Vuln-feed broker server-side** in `sentrikat-web/license-server/vuln_feed/` — design completo in `docs/architecture/VULN-FEED-BROKER-DESIGN.md` con R-PARSER-RESILIENCE requirement. ~3-4 settimane 1 dev.
- **Vuln-feed broker client-side** in `app/vuln_feed_client.py` — ~1 settimana.
- **Sentrikat proprietary intelligence layer** — strategic, ~2-4 settimane.

### 🔵 5. Esterno / paid

- **Pentest professionale** ~5-10k€ pre-customer-enterprise (auth + multi-tenant + agent ingestion scope).
- **ENISA developer credentials EUVD** — gratis, form ENISA, sblocca probe re-enable lato sentrikat-web.
- **POSTGRES_PASSWORD rotation** prod — runbook esiste in `scripts/ROTATE-POSTGRES-PASSWORD.md` (sentrikat-web side).
- **NVD API key rotation** prod — runbook esiste in `scripts/ROTATE-NVD-API-KEY.md`.

---

## 🚀 Cosa fare alla prossima sessione

### Se l'utente dice "continuiamo / lavora in autonomia"

1. Pulizia branch: l'utente apre PR su `claude/review-cve-pipeline-Xdz9m` (2 commit nuovi sopra `main`), review, merge.
2. Apri nuovo branch da main aggiornato per il prossimo task.
3. Default suggerito: F.6 demote keyword vendor_product confidence — 0.5 dev-day, isolato, alto-impatto su falsi positivi keyword fallback.

### Se l'utente dice "smoke test post-deploy"

1. Verifica live le 4 cose della sezione 1 di questa lista.
2. Documenta esiti in 13-admin-ops.md / 03-signup-onprem.md.

### Se l'utente dice "Phase X walkthrough"

Segui il file 0X-*.md scaffold. 7-dim per ogni area.

---

## 🛡️ Anti-timeout reminder

- Mai Read/Edit > 250 righe in colpo
- Mai Bash con output > 15KB (usa head, --max-count, -n)
- Commit + push ogni 1-2 step utili
- Mai Agent (subagent) per task incrementali
- Branch nuovo `claude/<task-name>` da main aggiornato
