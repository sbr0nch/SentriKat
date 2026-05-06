# SESSION HANDOFF — 2026-05-06

> **Read this FIRST if you are a new Claude session opening on this repo.** Then dive into the linked docs.
>
> **Owner**: Massimiliano (CEO) — building toward EA event ~2026-05-08.
> **Last working session**: 2026-05-06 (this file written at end of it).
> **Active branch**: `claude/sentrikat-setup-overview-Vv78M` — has been merged to `main` already (8 commits). Future work on a new `claude/*` branch.

---

## Where we stand

**Pipeline core (CVE matching) is now SHIP-READY pre-EA.** Live test on Community on-prem at end of session showed:

- 100 products active, 70 with CPE assigned
- 2384 CVEs in DB, 2109 (88%) with `cpe_data` enriched from NVD
- **1 vulnerability_match** total: CVE-2025-0411 (7-Zip Mark-of-the-Web Bypass, CISA KEV, "overdue by 432 days") matched against 7-Zip 19.00 via `cpe / high` confidence with version range `None - 24.09`
- Match method distribution: `cpe / high` 100%, `vendor_product` 0%, `keyword` 0%
- The single match was manually validated against NVD: vendor + product + version range all coherent

**Before today's work**: same dataset showed 379 matches, 87% false positives ("Chrome 147 ↔ CVE-2010-4204 CRITICAL 9.8" type). Today's audit + 8 commits + operational backfill closed the gap.

---

## What was committed this session (branch `claude/sentrikat-setup-overview-Vv78M`)

| Commit (chronological) | What |
|---|---|
| `2c82549` | fix [01.18.5]: plug cap bypass via `/api/import/queue/bulk` (the +1 product Massimiliano found) |
| `8956df1` | fix [01.18.5]: async agent push (`process_inventory_job`) cap bypass + UI double-click flicker |
| `5976e4f` | fix [01.18.5] SaaS audit: enforce `SubscriptionPlan.max_users` and `max_agents` per tenant (was no-op in SaaS) |
| `0fb2b8a` | fix [01.18.5] SaaS audit: pass org_id to `check_product_limit` in `/api/products` POST |
| `f4d513f` | fix [01.18.5]: count only ACTIVE products in cap; re-check on reactivate (admin-friendly behavior) |
| `e7e3d3e` | docs: `docs/architecture/CVE-MATCHING-PIPELINE.md` — full forensic audit, 9 gaps F.1–F.9 identified |
| `9b7932e` | fix(cve-pipeline): close gaps F.3, F.6, F.8 (CPE on import-queue path, demote unverified vendor_product, rematch after CPE apply) |

Total diff: ~600 lines code + 344 lines doc.

---

## Documents that matter — read order for next session

1. **THIS FILE** (`docs/SESSION-HANDOFF-2026-05-06.md`) — orientation
2. **`docs/architecture/CVE-MATCHING-PIPELINE.md`** ★ — full pipeline audit, 9 gaps catalogued. **The most important architecture doc on the core**. Read all sections A–G.
3. **`docs/architecture/VULN-FEED-BROKER-DESIGN.md`** (new this session) — design for centralized vulnerability feed, contract for cross-repo coordination with `sentrikat-web/license-server/`
4. **`docs/architecture/CVE-DATA-FLOW.md`** — high-level data flow (existed before; companion to CVE-MATCHING-PIPELINE)
5. **`docs/MASTER-PLAN.md`** — 4-phase strategy (existed before)
6. **`docs/SCALE-TESTING-ROADMAP.md`** — post-launch scale testing (existed before)
7. **`docs/e2e-tests/00-INDEX.md`** — E2E walkthrough state across W1–W6 (Phase 2 customer journey). Note: see "Round 7" history at top — that work is complete; this session was Round 8 hardening.
8. **`docs/e2e-tests/E2E-FLOWS-INDEX.md`** — 46 flows listed
9. **`CLAUDE.md`** — operational rules, must read once

---

## What remains — prioritized

### Pre-EA (≤48h from 2026-05-06)
**Nothing in code.** Mission for the operator (Massimiliano):

1. Once a fresh on-prem instance is deployed for an EA customer, run **post-deploy bootstrap**:
   ```bash
   docker exec -e PGPASSWORD=$DB_PASSWORD sentrikat-db psql -U sentrikat -d sentrikat \
     -c "DELETE FROM system_settings WHERE key='nvd_api_key' AND organization_id IS NULL; \
         INSERT INTO system_settings(key,value,category) VALUES ('nvd_api_key','<KEY>','sync');"
   docker exec sentrikat python -c "from app import create_app; app=create_app(); ctx=app.app_context(); ctx.push(); from app.cpe_mapping import batch_apply_cpe_mappings; batch_apply_cpe_mappings(commit=True, use_nvd=True)"
   # then loop fetch_cpe_version_data until total returns 0 (≈30-60 min with NVD key)
   ```
   This is operational, not a fix. Document it in customer-facing onboarding.

### Week 1 post-EA — the **6 must**

These culminate the promise "affidabile + automatico + perfetto + credibile + trustabile". Detail in CVE-MATCHING-PIPELINE.md F.x and below.

| # | Feature | File hints | Effort | Deps |
|---|---|---|---|---|
| 1 | **Scheduled background jobs** (cron `batch_apply_cpe_mappings` + `fetch_cpe_version_data` + `sync_cisa_kev` + `reset_stale_kev_flags`) | `app/scheduler.py` already imports `cisa_sync` jobs — extend with new entries. APScheduler. | 2-3 days | none |
| 2 | **Health dashboard internal** (admin page `/admin/health` showing % products with CPE, % CVE with cpe_data, last sync ts, NVD rate-limit headroom, match method distribution) | new `app/health_api.py`, new template `app/templates/admin_health.html`, JS chart on existing admin layout | 2-3 days | #1 in place to populate data |
| 3 | **Data quality badge customer-facing** (every match in dashboard tagged `Verified (CPE)` / `Probable (name match)`; coverage indicators in dashboard top: "CVE database last update X ago, match accuracy X%") | dashboard templates, vulnerability_match.to_dict() already has match_confidence, surface it in UI | 1-2 days | none |
| 4 | **NVD enrichment robustness** (retry with backoff, alternate sources MITRE 5.x and OSV.dev for description+CVSS, local CPE dictionary cache) | `app/nvd_api.py`, `app/nvd_cpe_api.py`, `app/nvd_rate_limiter.py` already exist — extend | 4-5 days | none |
| 5 | **Agent registry parser hardening** (Windows MSI: prefer DisplayVersion > ProductVersion > Version; pattern detection for InstallShield build numbers like "64.x.xxxxx") | agent-side code (NOT in this repo — separate `sentrikat-agent`?). If agent code is in `app/agents/` of this repo, extend there. | 3-4 days | agent rebuild + redeploy |
| 6 | **Reset stale flags lifecycle** (each `sync_cisa_kev` resets `is_actively_exploited=False` for CVEs not in current KEV anymore, unless EUVD or EPSS≥0.95 supports the flag) | `app/cisa_sync.py:874` parse_and_store_vulnerabilities — add delta logic | 1 day | none |

**Total**: ~14-18 dev-days. Sprint of 1.5-2 weeks for 1 dev, or 1 week for 2 devs.

### Week 2-4 post-EA — bug fixing from EA feedback + remaining audit gaps F.1, F.4, F.5, F.7, F.9

### Month 2-3 post-EA — **VULN-FEED-BROKER**

This is the **strategic moat**. Read `docs/architecture/VULN-FEED-BROKER-DESIGN.md`. Coordinated work with `sentrikat-web/license-server/`. See "Cross-repo coordination" below.

---

## Cross-repo coordination — sentrikat ↔ sentrikat-web

**Problem**: this Claude session has access to `sbr0nch/sentrikat` only. A separate Claude session is needed for `sbr0nch/SentriKat-web` (with its own MCP access there). Both must produce code that **interoperates** — endpoint names, request/response schemas, auth flow must match.

**Solution**: a **shared API contract document** in this repo, `docs/architecture/VULN-FEED-BROKER-DESIGN.md`, that BOTH sessions read. Whoever modifies the contract first wins; the other adapts. The doc is the single source of truth.

### Workflow for parallel sessions

1. **This session (sentrikat core)**:
   - Reads `VULN-FEED-BROKER-DESIGN.md` API contract
   - Implements **client-side**: HTTP client in `app/vuln_feed_client.py`, settings flag `VULN_FEED_URL`, auth via license HMAC
   - When `VULN_FEED_URL` is unset → fall back to direct NVD (legacy behavior, retro-compatibility for V1.0 customers)
   - When set → poll the broker endpoints

2. **Other session (sentrikat-web/license-server)**:
   - Reads same `VULN-FEED-BROKER-DESIGN.md`
   - Implements **server-side**: FastAPI router `license-server/vuln_feed/` with endpoints matching the contract
   - Imports the enrichment pipeline (port `cisa_sync.py` and friends as a shared library, or copy initially)
   - Hosts the enrichment scheduler centrally
   - Auth: HMAC verify using existing license_id → installation registry

3. **Both sessions push to their own `claude/*` branches**; user merges to respective `main` independently when contract matches.

### Handoff to the SentriKat-web session

When opening a new session on `sbr0nch/SentriKat-web`, paste this prompt:

> Read the file `docs/architecture/VULN-FEED-BROKER-DESIGN.md` from the repo `sbr0nch/sentrikat` (https://github.com/sbr0nch/sentrikat/blob/main/docs/architecture/VULN-FEED-BROKER-DESIGN.md). It contains the API contract for the Vulnerability Feed Broker that we need to host inside `license-server/`. Your job: implement the **server side** of that contract. The client side will be implemented in parallel by the sentrikat core session. Do NOT modify the contract without coordinating — if you need a change, edit the doc in sentrikat repo first and tell the user.

---

## E2E walkthrough state (W1–W6)

From the previous session-handoff at top of this file, plus today's work:

| Phase | Status | Notes |
|---|---|---|
| W1 Landing | ✅ + 3 bug HIGH fixed | sentrikat-web team merged 12 PRs |
| W2 Signup fresh email | ⏸️ blocked but unblocked by sentrikat-web [01.18.4] welcome email fix |
| W3 Setup wizard | ✅ + 2 bug HIGH fixed | [03.6.3.b], [03.6.7] |
| W4 Daily use | ✅ verified live with seed data | CVE matching now clean post-fix |
| W4 Agent push | ✅ verified | 100 products via agent push, no false positives post-fix |
| W5 Portal customer | ⏸️ blocked → unblocked by sentrikat-web fixes (need re-test) |
| W6 Admin ops | ❌ NOT STARTED | backup/restore, audit log, license management — ~half day of work |
| Bug [01.18.5] product cap | ✅ verified all paths (manual UI, agent sync, agent async, import queue single, import queue bulk, approve-all, reactivate). |
| SaaS smoke test | ⏸️ blocked (operator on different machine) |

**Recommendation for next session**: knock out **W6 Admin ops walkthrough** (one of the items the user explicitly named as remaining for EA). Then SaaS smoke test if operator has access.

---

## Operational reality checks before next session

1. **Branch state**: confirm `git status` is clean and `git log --oneline -5` shows commits up to `9b7932e` or later (PR merged to main).
2. **Doc inventory**: confirm `docs/architecture/CVE-MATCHING-PIPELINE.md` and `docs/architecture/VULN-FEED-BROKER-DESIGN.md` exist.
3. **CLAUDE.md** — re-read; rules around anti-timeout, no large reads, commit/push frequently still apply.
4. **NVD API key** is in `system_settings` (test key for local; rotate post-EA).
5. **License key in chat history**: NVD test key `04f90ab1-61aa-405f-be91-c42b66e982f6` exposed in chat — ROTATE after EA.

---

## Backlog tracker (for the operator)

Cross-repo:
- [ ] **(sentrikat core, week 1 post-EA)** 6 must: scheduled jobs, internal health dashboard, customer data-quality badge
- [ ] **(sentrikat-web/license-server, month 2)** Vuln-feed broker server side — see VULN-FEED-BROKER-DESIGN.md
- [ ] **(sentrikat core, month 2)** Vuln-feed client + flag `VULN_FEED_URL`
- [ ] **(sentrikat core, month 2)** Reset is_actively_exploited stale flags (F.7)
- [ ] **(sentrikat-agent, month 2-3)** Windows registry parser hardening (F.9)
- [ ] **(sentrikat core, month 3)** NVD enrichment alternate sources (F.4)
- [ ] **(sentrikat-web/license-server, month 3+)** Telemetry collector for trending CVE / threat intel
- [ ] **(operator)** Rotate POSTGRES_PASSWORD (leak from sentrikat-web sessions)
- [ ] **(operator)** Rotate NVD test API key

E2E remaining:
- [ ] **W6** Admin ops walkthrough (backup, restore, audit, license mgmt)
- [ ] **W5/W2** retry post sentrikat-web hard-delete + welcome email fixes
- [ ] **SaaS** end-to-end smoke (signup → tenant create → login → product → agent → match → dashboard)

Tech debt audit-found, post-EA:
- [ ] F.1 cron `batch_apply_cpe_mappings(use_nvd=True)`
- [ ] F.4 `settings_api` restore CPE re-application
- [ ] F.5 surface `validate_cpe_assignment` rejections operationally

---

## Quick wins / 1-line summaries to remember

- **Match logic is correct**. Today's false positives were a **data-quality cascade**, not a logic bug. Fixed by enrichment + cpe assignment + 3 surgical code fixes.
- **Architecture for SaaS multi-tenant is already centralized** (one Flask instance, shared `vulnerabilities` table, one NVD key per instance). Don't waste time redesigning.
- **The strategic moat is the vuln-feed broker**, not the matcher. Build it month 2-3.
- **Sweet spot target**: Italian / EU mid-market (100-2000 endpoint), regulated industry (banks, healthcare, public admin), on-prem-friendly. Don't try to compete with Tenable/Wiz on enterprise feature breadth.
- **Trust comes from transparency**: data quality badges + health dashboard internal + customer-facing coverage indicators (the 3 high-priority must-haves of week 1 post-EA).

---

End of handoff. Resume from "What remains — prioritized" → Week 1 post-EA when ready.
