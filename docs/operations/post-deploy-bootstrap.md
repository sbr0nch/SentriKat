# Post-Deploy Bootstrap

> **Audience**: operator deploying SentriKat on-prem to a new customer.
> **Tool**: `scripts/post_deploy_bootstrap.sh` (this repo).
> **When to run**: ONCE, after `docker compose up -d` and the first-run setup wizard, BEFORE handing the system to the customer.

---

## Why this exists

A fresh SentriKat install has empty `vulnerabilities` and unmatched `products` tables. Without bootstrap:

- Customer logs in → dashboard shows `0 matches` → looks broken
- Products from agent push come in without CPE → can't match against any CVE
- The CISA KEV / NVD enrichment that powers the matching has never run

Manually executing 3 SQL/Python steps in the right order is error-prone (the SESSION-HANDOFF documents this gap in detail). The bootstrap script automates them in idempotent fashion.

## What the script does

| Step | Action | Idempotent? |
|---|---|---|
| 0 | Pre-flight: verify `sentrikat` and `sentrikat-db` containers are running and Postgres is reachable | yes |
| 1 | Configure NVD API key in `system_settings.nvd_api_key` (skips if already set) | yes |
| 2 | Run `batch_apply_cpe_mappings(use_nvd=True)` to assign CPE to all products via Tier 1 (regex) + Tier 2 (curated dict) + Tier 3 (local CPE dictionary) + Tier 4 (NVD search for unmatched) | yes — only processes products without CPE |
| 3 | Loop `fetch_cpe_version_data(limit=30, oldest_first=True, skip_awaiting=True)` until 3 consecutive iterations return 0 enrichments | yes — resumable; safe to Ctrl-C and re-run |
| 4 | Print final coverage status: products with CPE, CVEs with `cpe_data`, total matches, high-confidence matches | informational |

After step 4, the customer has a populated dashboard. Typical first-deployment values:

- ~70-90% products with CPE (depends on how niche the customer's software stack is)
- ~85-95% CVEs with `cpe_data` (CISA KEV is well-known, NVD enriches the rest over time)
- 1-50 matches (depends on customer infrastructure age)
- 100% of matches with `cpe / high` confidence (no keyword fallback)

## Prerequisites

Required:
- Docker stack up (`docker compose up -d`) and healthy
- First-run setup wizard completed (`/setup` page) → at least 1 organization + 1 super_admin user
- Customer products imported (manual UI, agent push, or import queue) — script can be run before or after, but coverage is computed at run time
- NVD API key — strongly recommended (50 req/30s vs 10 req/min unauth). [Request one free at NVD](https://nvd.nist.gov/developers/request-an-api-key)

Optional:
- `.env` file in CWD with `POSTGRES_PASSWORD=...` (auto-detected) — alternatively set `DB_PASSWORD` env var

## Usage

```bash
# Standard run with NVD key passed via flag (idempotent)
./scripts/post_deploy_bootstrap.sh --nvd-key 04f90ab1-61aa-405f-be91-c42b66e982f6

# Use NVD_API_KEY env var instead
NVD_API_KEY="04f90ab1-..." ./scripts/post_deploy_bootstrap.sh

# Skip the long CPE backfill loop (useful for CI/test, or if backfill ran already)
./scripts/post_deploy_bootstrap.sh --no-cpe-backfill

# Override container names (if customized in docker-compose)
SENTRIKAT_CONTAINER=mycorp-sentrikat \
DB_CONTAINER=mycorp-postgres \
DB_USER=mycorp \
DB_NAME=mycorp_sk \
./scripts/post_deploy_bootstrap.sh

# Help
./scripts/post_deploy_bootstrap.sh --help
```

## Expected runtime

| Customer size | Products | NVD API key | Estimated time |
|---|---|---|---|
| Small (lab) | < 50 | yes | 5-10 min |
| Small (lab) | < 50 | no | 30-60 min |
| Medium | 50-500 | yes | 30-60 min |
| Medium | 50-500 | no | 4-8 hours |
| Large enterprise | > 500 | yes | 1-3 hours |
| Large enterprise | > 500 | no | 8-24 hours |

The dominant cost is **step 3 CPE backfill loop**: NVD CPE Match endpoint at 30 CVEs/iteration × 2-second delay. With ~2400 CISA KEV CVEs, that's ~80 iterations ≈ 30-50 min with key.

## Re-running

The script is **fully idempotent**:

- Step 1 skips if `nvd_api_key` already in `system_settings`
- Step 2 only processes products with `cpe_vendor IS NULL`
- Step 3 picks up where it left off — `cpe_fetched_at` timestamp prevents re-fetch of CVEs already enriched
- Step 4 just reads counters

You can safely re-run after:

- Adding more products via agent or manual UI
- A network blip during a previous run
- Rotating the NVD API key (use `--nvd-key` to overwrite)

## Troubleshooting

### "Container 'sentrikat' not found"

The container name doesn't match. Check `docker ps` and pass the right name via `SENTRIKAT_CONTAINER=...`.

### "Cannot connect to Postgres"

Either:
- `DB_PASSWORD` env var not set and no `.env` file in CWD
- Postgres not yet healthy after compose up — wait 30s and retry
- DB user/name customized — pass `DB_USER=...` `DB_NAME=...`

### Step 2 prints "updated=0 of N products without CPE"

Local tiers (regex + curated dict + local CPE dictionary) couldn't match any product, AND NVD lookups failed. Common causes:

1. NVD rate-limit exhausted — wait 30s, re-run
2. NVD API key invalid — verify with `curl -H 'apiKey: $KEY' 'https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=CVE-2024-1'`
3. Products have very generic names ("Application X v1.0") that don't disambiguate — manual CPE assignment via `/admin/products` needed

### Step 3 loop stuck on "remaining=N" but enriched=0

NVD has flagged those CVEs as "Awaiting Analysis" / "Received" / "Undergoing Analysis" — they will not yield CPE data even if re-fetched. The script's `skip_awaiting=True` flag should exclude them, but if they keep appearing in the count, ignore: they're noise. The loop will terminate after 3 zero-enrich iterations.

### "Bootstrap incomplete" + exit code 2

Recoverable: NVD rate-limit hit during step 2 or 3. Re-run after waiting (default reset is per-30-seconds for NVD).

### Coverage warning at end ("Product CPE coverage is X%, below 60%")

Some products use names too generic to map automatically. Options:

1. Manual CPE assignment via `/admin/products` for each uncovered product
2. Wait for the customer to report which products are critical → focus manual mapping there
3. Update `app/cpe_mapping.py` `CPE_MAPPINGS` to add new regex entries for customer-specific software (requires code change + redeploy)

## After bootstrap completes

1. Have the customer log in → verify dashboard shows expected match count
2. Configure SMTP under `/admin/settings` for email alerts
3. Configure scheduled syncs (CISA KEV daily, NVD recent hourly) — should be automatic via APScheduler but verify in `/admin-panel#settings:system`
4. Document the actual CPE coverage % in customer's deployment notes — useful for SLA conversations

## Cross-reference

- `scripts/post_deploy_bootstrap.sh` — the script itself
- `docs/architecture/CVE-MATCHING-PIPELINE.md` — full pipeline audit, explains why the 3 steps are needed
- `docs/SESSION-HANDOFF-2026-05-06.md` § "Pre-EA" — original problem statement that motivated this script
- `app/cpe_mapping.py:408` — `batch_apply_cpe_mappings` function
- `app/cisa_sync.py:941` — `fetch_cpe_version_data` function
