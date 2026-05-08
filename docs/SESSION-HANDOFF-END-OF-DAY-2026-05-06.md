# SESSION HANDOFF — End of 2026-05-06 (Long Session)

> **Per la prossima Claude session che apre `sbr0nch/SentriKat`. Leggimi PRIMA di fare qualsiasi cosa.**

## ⏱️ TL;DR — dove siamo

🟢 **Prodotto SHIP-READY**. EA event può partire (2026-05-08) o slittare a 2026-05-09+ a discrezione operatore.

**Update finale 2026-05-06 (post BoldBrain event andato bene)**:

✅ **Customer journey verificato live in prod SaaS**:
- Signup PRO tenant → login → dashboard popolata
- KEV Catalog 1,589 entries visibili (= CISA 403 da Hetzner mitigato post sentrikat-web Bundle 2 GitHub mirror)
- Hard-delete cascade funzionante (PR #260+#261+#263)

⏸️ **Da retestare domani 2026-05-07** (email cancellate/utente ricreato):
- Welcome email "Imposta password" link — 2 link su 3 hanno URL diversi tra loro (sospetto regressione PR #269 sentrikat-web?)
- Click "Imposta password" non manda email follow-up
- Massimiliano ricreerà utente fresh + screenshot

🆕 **Feature request scoperto durante test (NUOVO)**:
- **Alerting email default behavior**: oggi se utente non setta email di alerting né health check email, l'admin loggato (che ha registrato il tenant) **non riceve niente di automatico** (da verificare in codice).
- **Comportamento desiderato**:
  1. Default: use registration email del primo admin account
  2. Override: se utente setta email custom → quelle vincono
  3. UI: comunicare chiaramente quale email riceverà alerts ("Currently sending to: admin@example.com (registration default)" oppure "admin@example.com, ops@example.com (custom)")
- **Effort**: ~2-4h (controllo codice + fallback logic + UI label) — backlog Week 1 post-EA

**Sessione 2026-05-06 ha mergiato 6 PR su core + 5 su sentrikat-web** (totale 11+ PR mergiate). Score finale:

| Metric | Stato |
|---|---|
| Bug HIGH/CRITICAL aperti | **0** |
| Audit gaps F.x core | 8/9 chiusi (F.9 = repo agent separato) |
| 6-must Week 1 | 4/6 chiusi (#1+#2+#3+#6); #4+#5 multi-day post-evento |
| Anti-pattern silent excepts core | 194 catalogati, 5 critici fissati con logger |
| OWASP smoke statico (3 file core) | 0 reali findings |
| Critical-path test pytest in CI | 12 |
| Phase E2E scaffold | 16/16 mappate |
| Audit doc | 4 cumulativi |

## 📦 PR mergiate oggi (cronologicamente)

| PR | Cosa |
|---|---|
| #410 + #411 | F.2 manual UI CPE + Phase 05 re-verify + R-PARSER-RESILIENCE design + 5 critical-path test |
| #412 | Phase 08 scaffold + 08.1 CISA KEV findings (parziale, anticipo merge) |
| #413 | Audit fixes A.1+A.2+B.1+B.2 + bootstrap script + Phase 09-12 scaffold + OWASP audit + [08.7.1] EPSS extract |
| #414 | Batch A: F.1 cron + F.4 restore + F.5 audit_event + F.7 stale KEV + 6-must #2 health-summary endpoint + 6-must #3 data quality badge + audit ext |
| #415 | Batch B: 7 regression test + Phase 06+07+14+15 scaffold + 00-INDEX update + 6-must #2 frontend `/admin/health` template |
| #(open) | Batch C in progress: [13.1.1] pagination "of 0" fix mergiato; [13.1.2] + raw JSON link deferred |

Lato sentrikat-web (per traccia, NON tuo repo): PR #252-#270 mergiati (Bundle 1+2 + [05.3.2] auto-resolved + welcome email canonical + admin pages cleanup).

## 🎯 Cosa fa il prodotto adesso (verificato live)

Smoke test 2026-05-06 (Massimiliano nel browser, screenshot in chat):

- ✅ Manual UI product create → CPE auto-assegnata (F.2 verified)
- ✅ Dashboard CVE cards mostrano badge **VERIFIED** (verde) per cpe/high
- ✅ Badge **PROBABLE** (giallo) per nuovo 0-day OpenMRS senza cpe_data ancora
- ✅ `/admin-panel#settings:health` mostra KPI dashboard popolato
- ✅ Welcome email signup mostra "Community Edition · 3 users · 1 org · 100 products · 10 agents" (canonical da plans_config)
- ✅ Sentrikat-web Bundle 2 chiude tutti i bug HIGH cross-repo

## 🚧 Cosa MANCA (per categoria + effort)

### A. Smoke test residui (operatore, ~1h totali)

- B.5 W3 wizard step 2-6 (`docker compose down -v` + walkthrough setup wizard fresh)
- Verifica `/admin/health` raw JSON link (404 osservato — minor UX bug)
- Verifica `[13.1.2]` filter Microsoft/Windows placeholder vs value disambiguation

### B. Walkthrough live E2E (multi-day, post-evento)

| Phase | Effort | Surface |
|---|---|---|
| 03 wizard step 2-6 | 1h | destructive on-prem fresh |
| 06 auth/RBAC 7-dim | 1-2 giorni | testlab Keycloak+OpenLDAP |
| 07 agents 7-dim | 1 giorno | docker compose locale |
| 08.15+08.16 UI | 1h | match badge + sync history |
| 09 remediation | 4-8h | assignments, SLA, risk exception |
| 10 compliance | 4-8h | report PDF generation |
| 11 integrations | 1 giorno | testlab Jira mock + SMTP |
| 12 alerts | 4h | Mailpit + webhook tester |
| 13.2-13.15 admin ops | 4h | sub-aree |
| 14 saas-specific | 1 giorno | bridge license-server |
| 15 security-edge | 1 giorno | OWASP smoke + edge cases |

**Totale**: ~10-15 giornate uomo

### C. Multi-day dev (post-evento, prima di scaling)

| Item | Effort | Where |
|---|---|---|
| 6-must #4: NVD R-PARSER-RESILIENCE applied to `app/cisa_sync.py:874` `parse_and_store_vulnerabilities` + `app/nvd_api.py` | 4-5 dev-days | core |
| 6-must #5: agent registry parser hardening Win MSI (DisplayVersion vs Version, InstallShield builds) | 3-4 dev-days | repo `sentrikat-agent` |
| Anti-pattern fix B.3+B.4+B.5: logger.warning sui silent excepts in `agent_api.py:1208/1758/2530/2779/2795/4536/4599/5677/5992/6608` + `cisa_sync.py:99/930/936/1486/1505/1551/1590` + `nvd_api.py:36/39` + `nvd_cpe_api.py:59` | 2h | core |
| `[08.5.1]` cpe_limit raise 100→300 in cisa_sync.py | 1h | core |
| `[08.17.1]` NVD rate-limiter audit comportamento sotto stress | 4h | core |
| `[13.1.1]` pagination fix → ✅ FATTO PR Batch C | done | — |
| `[13.1.2]` filter placeholder vs value | 30 min | core |
| `[13.1.4]` SaaS SMTP platform-default Resend | 2h | cross-repo |
| Frontend health-summary: fix raw JSON link (404 in admin-panel SPA) | 30 min | core template |

**Totale**: ~10-15 dev-days

### D. Strategic moat (mese 2-3)

- **Vuln-feed broker server-side** in `sentrikat-web/license-server/vuln_feed/` — design completo in `docs/architecture/VULN-FEED-BROKER-DESIGN.md` con R-PARSER-RESILIENCE requirement. ~3-4 settimane 1 dev.
- **Vuln-feed broker client-side** in `app/vuln_feed_client.py` — 1 settimana.
- **Sentrikat proprietary intelligence layer** — strategic, ~2-4 settimane.

### E. Esterno / paid

- **Pentest professionale** ~5-10k€ pre-customer-enterprise (auth + multi-tenant + agent ingestion scope)
- **ENISA developer credentials EUVD** — gratis, form ENISA, sblocca probe re-enable lato sentrikat-web
- **POSTGRES_PASSWORD rotation** prod — runbook esiste in `scripts/ROTATE-POSTGRES-PASSWORD.md` (sentrikat-web side)
- **NVD API key rotation** prod — runbook esiste in `scripts/ROTATE-NVD-API-KEY.md`

## 📚 Files chiave da leggere per nuova sessione

In ordine:

1. **Questo file** (`docs/SESSION-HANDOFF-END-OF-DAY-2026-05-06.md`) — orientation
2. `docs/SESSION-HANDOFF-2026-05-06.md` — handoff originale (ora include addendum end-of-day)
3. `docs/architecture/CVE-MATCHING-PIPELINE.md` — pipeline audit completo, F.1-F.9 status updated
4. `docs/architecture/VULN-FEED-BROKER-DESIGN.md` — design broker mese 2-3 con R-PARSER-RESILIENCE
5. `docs/audits/anti-pattern-audit-2026-05-06.md` + `..-extension..md` — silent except catalogue
6. `docs/audits/owasp-sample-audit-2026-05-06.md` — OWASP smoke 0 findings
7. `docs/e2e-tests/00-INDEX.md` — status table aggiornato 16 fasi
8. `docs/operations/post-deploy-bootstrap.md` — operator guide nuovo deploy on-prem
9. `tests/test_cve_matching_critical_paths.py` + `tests/test_audit_fixes_post_ea_week1.py` — 12 critical-path test
10. `CLAUDE.md` — operational rules anti-timeout

## 🚀 Cosa fare alla prossima sessione

### Se l'utente dice "continuiamo"

1. **Mergi PR Batch C in corso** (se non già mergiato — fix [13.1.1] pagination)
2. **Continua Batch C residuo**: [13.1.2] filter, raw JSON link, B.3+B.4+B.5 silent except logger sweep, [08.5.1] cpe_limit, R-PARSER-RESILIENCE applied a cisa_sync.py
3. **Scrivi pytest test** per ogni fix Batch C

### Se l'utente dice "smoke test post-deploy / W3 wizard"

1. Guida operatore al `docker compose down -v` + setup wizard step-by-step
2. Documenta in `docs/e2e-tests/03-signup-onprem.md` step 2-6

### Se l'utente dice "Phase X walkthrough"

1. Apri il file `docs/e2e-tests/0X-*.md`
2. Segui 7-dim per ogni area listed
3. Bug ID format: `[FF.S.B]` (Fase.Sezione.Bug)

### Se chiede di sentrikat-web

L'altra Claude session sull'altro repo è in standby. Cross-repo:
- `FIX-HANDOFF-sentrikat-web.md` con gli ultimi update
- Bundle 1+2 chiusi (PR #266+#267+#268+#269+#270)
- Backlog non urgente: ENISA EUVD creds + CVE.org HTTP 400 param fix + UI cleanup `/admin/datasources` filter

## ⚠️ Trigger per inviare la sessione gemella sentrikat-web

- ENISA EUVD developer credentials arrivati → riattivare probe con auth header
- CVE.org HTTP 400 sblocco — letta documentazione MITRE 5.x param naming
- Sentrikat core chiude un fix che affetta API contract con license-server (raro)

## 🔑 Credenziali / API Keys note

⚠️ **NVD test API key esposta in chat history**: `04f90ab1-61aa-405f-be91-c42b66e982f6` — **da rotare post-EA**. Runbook esiste sentrikat-web side.

⚠️ **POSTGRES_PASSWORD prod** — leak in chat passate. Runbook rotation esiste.

## 🛡️ Anti-timeout (CLAUDE.md riassunto)

- Mai Read/Edit > 250 righe in colpo
- Mai Bash con output > 15KB (usa head, --max-count, -n)
- Commit + push ogni 1-2 step utili
- Mai Agent (subagent) per task incrementali
- Branch nuovo `claude/<task-name>` da main aggiornato

---

## ✉️ Messaggio copia-incolla per l'utente per la prossima sessione

```
Apri nuova sessione Claude Code su sbr0nch/SentriKat. Primo prompt:

Leggi docs/SESSION-HANDOFF-END-OF-DAY-2026-05-06.md per orientation.
Poi mi dici (a) in che stato siamo, (b) cosa è prioritario adesso,
(c) proponi 3 opzioni di lavoro autonomo.

Quel Claude trova tutto: bug aperti, fix mergiati oggi, scaffold E2E
pronti, audit doc, critical-path test in CI, e cosa manca per Livello
1/2/3 di "tutto finito".

Stato: 🟢 SHIP-READY. EA può partire o slittare al 2026-05-09+.
Sentrikat-web parallel session: in standby fino a ENISA creds o
nuovi findings walkthrough.

PR Batch C in corso (fix [13.1.1] pagination) — ricorda di mergiarla
prima di partire con altro lavoro.
```
