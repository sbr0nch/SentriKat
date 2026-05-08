# Changelog

All notable changes to SentriKat. Format: [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

This file is updated with each significant feature/fix landing on `main`. For full commit history, see `git log`.

## [Unreleased] — 2026-05-08

### Added
- **`/api/provision/hard-delete`** — GDPR-style cascade delete endpoint for SaaS tenant cleanup. Idempotent (200 with zero counts on no-op), atomic (full rollback on failure), explicit pre-delete on 7 non-cascade FK tables + `user_organizations` to avoid `NotNullViolation` from autoflush. Cross-repo contract with sentrikat-web/license-server `delete_customer` flow.
- **`/api/provision/regenerate-activation-token`** + extended `/api/provision` with `include_activation_url` flag — welcome-email mono-CTA "Set your password" flow (industry pattern: Linear/Vercel/Notion). 48h default expiry, configurable. Reuses existing `/reset-password?token=...` page.
- **`User.generate_activation_token(expiry_hours=48)`** — semantic wrapper distinct from 30-min password-reset token.
- **R-PARSER-RESILIENCE applied to all enrichment feeds** — alias chains + type coercion + schema-drift telemetry on NVD CVSS extraction, CISA KEV record-level fields, ENISA EUVD, FIRST EPSS, MITRE CVE.org / Vulnrichment. Tolerates upstream rename of optional fields without silent zero-out.
- **Pattern B — user role can mark own assignments resolved** — backend permission check + frontend "Mark Resolved" button. Closes the assignment workflow loop (admin assigns → user fixes → user resolves).
- **Risk Exception UI triggers** — per-CVE-card "Risk Exception" button + sidebar panel; immediate dashboard suppression after creation (no waiting for next sync).
- **CISA KEV Akamai bypass** — browser UA + GitHub mirror fallback (`raw.githubusercontent.com/cisagov/kev-data`) when datacenter IPs are blocked. SaaS Hetzner deployment now ingests KEV correctly.
- **`[FK-CASCADE]` audit + tech-debt task** — 7 FK to `organizations.id` and 10 FK to `users.id` lacking `ondelete='CASCADE'` identified in `integrations_models`, `ldap_models`, `shared_views`. Migration deferred post-EA.

### Changed
- **`EMAIL_FROM_ADDRESS` default** from `noreply@alerts.sentrikat.com` (subdomain not verified on Resend) to `noreply@sentrikat.com` (root domain, verified). Forgot-password flow restored. Subdomain split deferred until separate marketing flow launches (see `docker-compose.yml` comment).
- **`reset_password` UPDATE statement** — bind `must_change_password = :must_change` as boolean parameter instead of integer literal `= 0`. Works on both PostgreSQL (strict type) and SQLite (test).
- **`sync_cisa_kev` `cpe_limit`** raised 100 → 300. Cuts cold-start KEV CPE enrichment from ~24h to ~8 scheduler cycles.
- **`parse_and_store_vulnerabilities` source reconciliation** — now reconciles `nvd` and `cve_org` source labels to `cisa_kev+<original>` when KEV later confirms the same CVE. Fixes the SaaS dashboard "KEV Catalog" widget under-count (was showing the wrong 15.6k or 0 instead of correct ~1.250 KEV count).
- **Dashboard "KEV Catalog" widget filter** — uses `LIKE '%cisa_kev%'` to count all reconciled source patterns.
- **F.7 stale-KEV reset** — extended to `cisa_kev+nvd` and `cisa_kev+cve_org` resettable sources (still excludes `cisa_kev+euvd` because EUVD has its own actively_exploited signal).
- **NVD rate-limiter** — full audit + 17 stress tests covering safety-factor, burst behavior, window expiry, concurrent access (20-thread + 100-thread races), API-key cache invalidation, decorator semantics.
- **Silent-except logger sweep** — 22 call sites instrumented (NVD, CISA, agent, integrations, LDAP, SBOM) so previously-silent transient failures now appear in `application.log`.
- **Documentation reorganization** — 97 → 64 active MD files; audience-based folders (`docs/customer/`, `docs/architecture/`, `docs/contracts/`, `docs/handoffs/`, `docs/business/`); 12 stale internal docs archived to `docs/archive/`.

### Fixed
- **Forgot-password email silent failure** — Resend rejected with `domain not verified`; root cause was un-verified subdomain. See above.
- **`/hard-delete` 500 NotNullViolation** — SQLAlchemy autoflush hit FK references without `ondelete='CASCADE'`. Now wraps in `no_autoflush` + explicit pre-delete.
- **CSRF token missing on 4 `@csrf_protect_session` endpoints** (2FA setup/verify/disable, change-password) — frontend wasn't sending `X-CSRFToken` header; latent since file creation 2026-04-29. Same for SLA/risk-exception fetches against the non-csrf-exempt `remediation_api` blueprint.
- **Bootstrap modal `_element` null TypeError** in `closeSecuritySettings` — guarded with `securityModal._element` check.
- **SLA save toast** showing 'success' even with 0 saved policies — branched into success/danger/warning based on actual `saved` count.
- **`[13.1.1]` Dashboard pagination "Showing 1-50 of 0"** — counter mismatch.
- **`[13.1.2]` Dashboard filter placeholders** confused as values — changed to `e.g. Microsoft` / `e.g. Windows`.
- **`/admin/health` raw JSON link 404** — replaced anchor `target="_blank"` with fetch+blob URL (auth context preserved).

### Cross-repo contracts (with `sentrikat-web/license-server`)
- `SAAS-HARD-DELETE-CONTRACT` — POST `/api/provision/hard-delete` semantics
- `SAAS-ACTIVATION-TOKEN-CONTRACT` — `include_activation_url` + `/regenerate-activation-token`
- `SAAS_INTEGRATION_SPEC` — pre-existing, formalized in `docs/contracts/`

See `docs/contracts/CROSS-REPO-CONTRACTS.md`.

---

## [v1.0.0-beta.6] — 2026-04-26

Pre-EA hardening sprint. Round 1-7 walkthrough findings closed.

### Added
- 6-must Week 1: items #1, #2, #3, #6 closed (data quality badges, `/admin/health` endpoint+template, CVE card data-quality badges, EPSS extract `[08.7.1]`).
- F.1 cron NVD remap, F.2 manual UI CPE, F.4 restore CPE re-apply, F.5 audit_event reject, F.7 stale KEV reset.
- 12 critical-path regression tests in CI.
- 16/16 E2E test phases scaffolded (`docs/e2e-tests/00-INDEX.md`).
- Anti-pattern audit, OWASP smoke audit, CVE pipeline forensic audit.
- `[01.18.x]` license cap enforcement on Import Queue + SaaS support; SubscriptionPlan caps in SaaS mode.
- Setup wizard fixes: `[03.6.3]` step 3 auto-lock, `[03.6.3.b]` step 4 401, `[03.6.7]` step 5 504.

### Changed
- Community Edition limits aligned with public pricing (`[03.14.10]`).
- LicenseInfo defaults sourced from `LICENSE_TIERS` (closes silent bug).

---

## [v1.0.0-beta.5 and earlier]

See `docs/archive/` for historical audits and migration plans:
- `FULL_AUDIT_AND_SAAS_MIGRATION.md`
- `SAAS_AUDIT_AND_PLAN.md`
- `MASTER-PLAN.md`
- `MULTI_EXPERT_AUDIT.md`
