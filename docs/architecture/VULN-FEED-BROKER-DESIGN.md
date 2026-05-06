# Vulnerability Feed Broker — API Contract & Design

> **Cross-repo coordination document.** Read by both `sbr0nch/sentrikat` (this repo, client side) and `sbr0nch/SentriKat-web` (license-server, server side) sessions.
>
> **Single source of truth for**: endpoint paths, request/response schemas, auth flow, error codes, versioning policy.
>
> **Edit policy**: whoever changes this doc first, communicates the change before the other session is mid-implementation. Bumps `Contract-Version` in the header below.

**Contract-Version**: `0.1.0-draft` (2026-05-06)
**Status**: design — implementation starts month 2 post-EA.

---

## Why

Today, every SentriKat installation (SaaS or on-prem) calls NVD / CISA / EUVD directly to enrich its local `vulnerabilities` table. Three problems:

1. **Aggregate NVD load**: 10 on-prem customers = 10× NVD traffic for the same data.
2. **No proprietary intelligence layer**: we can't add "Sentrikat threat intel" (custom CVE classification, internal severity overrides, trending data) without forking NVD.
3. **On-prem firewall friction**: customers see outbound HTTPS to nvd.nist.gov, services.nvd.nist.gov, www.cisa.gov, euvdservices.enisa.europa.eu — multiple endpoints, different security postures, hard to whitelist cleanly.

The Vulnerability Feed Broker (referred to as "the broker" or "vuln-feed" below) lives in `sentrikat-web/license-server/` (FastAPI + Postgres) and exposes a single HTTPS endpoint that:

- Hosts the **enriched, deduplicated, cleaned** vulnerability database
- Serves it over a versioned JSON API to all installations
- Is the only outbound destination clients need to whitelist (`vuln-feed.sentrikat.com:443`)
- Becomes the platform for Sentrikat-proprietary intelligence over time

---

## High-level architecture

```
┌─────────────────────────────────────────────────────────────────┐
│  sentrikat-web/license-server/  (FastAPI)                       │
│  Hostname: vuln-feed.sentrikat.com                              │
│                                                                  │
│  ┌─────────────────────┐   ┌──────────────────────────────────┐ │
│  │ Existing routers    │   │ NEW: vuln_feed router            │ │
│  │ /api/v1/license/*   │   │ /api/v1/vuln-feed/*              │ │
│  │ /api/v1/provision/* │   │                                  │ │
│  │ /api/v1/billing/*   │   │ Endpoints:                       │ │
│  └─────────────────────┘   │  GET /vulnerabilities            │ │
│                             │  GET /cve/{cve_id}               │ │
│                             │  GET /cpe-dictionary             │ │
│                             │  GET /exploit-intel              │ │
│                             │  GET /health                     │ │
│                             │  GET /manifest                   │ │
│                             └──────────────────────────────────┘ │
│                                       │                          │
│  ┌────────────────────────────────────┴───────────────────────┐  │
│  │ Shared Postgres (license-server's own DB)                  │  │
│  │   tables (NEW):                                             │  │
│  │   - vuln_cves (CVE master, enriched)                       │  │
│  │   - vuln_cpe_data (CPE applicability per CVE)              │  │
│  │   - vuln_cpe_dict (cached NVD CPE dictionary)              │  │
│  │   - vuln_exploit_intel (sentrikat proprietary, future)     │  │
│  │   - vuln_kev_history (CISA KEV add/remove timeline)        │  │
│  └────────────────────────────────────────────────────────────┘  │
│                                                                  │
│  ┌────────────────────────────────────────────────────────────┐  │
│  │ Background jobs (APScheduler/Celery in license-server):    │  │
│  │   - sync_cisa_kev          every 6h                        │  │
│  │   - sync_nvd_recent        every 1h                        │  │
│  │   - cpe_backfill           continuous (rate-limit aware)   │  │
│  │   - cvss_enrichment        every 4h                        │  │
│  │   - euvd_sync              every 6h                        │  │
│  │   - epss_sync              every 24h                       │  │
│  │   - reset_stale_kev_flags  every 24h                       │  │
│  └────────────────────────────────────────────────────────────┘  │
└─────────────────────────────────────────────────────────────────┘
                  ▲                    ▲                     ▲
                  │                    │                     │
            HTTPS pull           HTTPS pull            HTTPS pull
    auth: HMAC(license_id)  auth: HMAC(license_id)   auth: ...
                  │                    │                     │
   ┌──────────────┘    ┌───────────────┘     ┌───────────────┘
   │                   │                     │
sentrikat (SaaS    sentrikat (on-prem    sentrikat (on-prem
eu-central-1)       Customer A)           Customer B)
```

---

## Authentication

### Concept

Every Sentrikat installation (SaaS or on-prem) has a **license** issued by `license-server`. The license carries:
- `installation_id` (UUID, globally unique)
- `customer_id`
- `tier` (community / professional / enterprise)
- `feature_flags` (push_agents, ldap, white_label, ...)
- A **shared HMAC secret** (server keeps a copy, client keeps a copy)

The vuln-feed broker uses that **same shared HMAC secret** for client authentication. No new credential to manage.

### Request signing scheme

Each request from client to broker:

```
GET /api/v1/vuln-feed/vulnerabilities?since=2026-05-01T00:00:00Z&page=1
Headers:
  X-Sentrikat-Installation: 01J9X...
  X-Sentrikat-Timestamp: 2026-05-06T11:34:00Z
  X-Sentrikat-Signature: hex(HMAC-SHA256(secret, "{method}\n{path}\n{query}\n{timestamp}\n{installation_id}"))
```

Server verifies:
1. Installation exists and is active (not suspended/expired)
2. Timestamp within ±5 minutes of server time (replay protection)
3. Signature matches

Response: 200 with payload, or 401/403 with error code.

### Tier-based access control

| Tier | Endpoints accessible |
|---|---|
| community | `/health`, `/manifest`, `/cpe-dictionary` (read-only basic feeds) |
| professional | community + `/vulnerabilities`, `/cve/{id}`, `/exploit-intel` |
| enterprise | professional + telemetry-aware "trending CVE" feed (future) |

If a community-tier installation tries to call `/vulnerabilities`, response is 403 with error code `tier_insufficient` and a hint about upgrade.

> **Note**: community tier still gets cpe-dictionary so they have local CPE assignment capability. The vulnerability feed itself is a Pro feature. This is one of the "Pro upgrade pressure" levers.

---

## Endpoints

All endpoints under base `/api/v1/vuln-feed/`. Base URL: `https://vuln-feed.sentrikat.com`.

### `GET /health`

Public, unauthenticated. Used by clients for health-check and freshness signal.

**Response 200**:
```json
{
  "status": "healthy",
  "contract_version": "0.1.0",
  "data_freshness": {
    "cisa_kev_last_sync": "2026-05-06T11:00:00Z",
    "nvd_recent_last_sync": "2026-05-06T11:30:00Z",
    "cpe_backfill_progress_pct": 100,
    "total_cves": 287512,
    "kev_cves": 1587,
    "exploited_cves": 4203
  }
}
```

`status` ∈ `healthy` | `degraded` | `down`. Degraded means at least one upstream sync is >24h late.

---

### `GET /manifest`

Authenticated (any tier). Tells the client what feeds are available and how often to poll.

**Response 200**:
```json
{
  "feeds": [
    {
      "name": "vulnerabilities",
      "endpoint": "/api/v1/vuln-feed/vulnerabilities",
      "supports_incremental": true,
      "poll_interval_seconds": 900,
      "last_modified": "2026-05-06T11:30:00Z",
      "tier_required": "professional"
    },
    {
      "name": "cpe-dictionary",
      "endpoint": "/api/v1/vuln-feed/cpe-dictionary",
      "supports_incremental": true,
      "poll_interval_seconds": 86400,
      "last_modified": "2026-05-06T03:00:00Z",
      "tier_required": "community"
    },
    {
      "name": "exploit-intel",
      "endpoint": "/api/v1/vuln-feed/exploit-intel",
      "supports_incremental": true,
      "poll_interval_seconds": 3600,
      "last_modified": "2026-05-06T11:00:00Z",
      "tier_required": "professional"
    }
  ]
}
```

Client uses `last_modified` to decide whether to skip a poll (HTTP 304 Not Modified is also supported via `If-Modified-Since` header).

---

### `GET /vulnerabilities`

Paginated, incremental list of CVEs.

**Query params**:
- `since` (ISO 8601 timestamp, optional) — return CVEs modified after this time
- `page` (int, default 1)
- `page_size` (int, default 100, max 500)
- `kev_only` (bool, default false) — return only CVEs in CISA KEV

**Response 200**:
```json
{
  "page": 1,
  "page_size": 100,
  "total": 287512,
  "next_page": "/api/v1/vuln-feed/vulnerabilities?since=2026-05-01T00:00:00Z&page=2",
  "data": [
    {
      "cve_id": "CVE-2025-0411",
      "vendor_project": "7-zip",
      "product": "7-zip",
      "vulnerability_name": "7-Zip Mark of the Web Bypass Vulnerability",
      "short_description": "...",
      "date_added": "2025-02-06",
      "due_date": "2025-02-27",
      "cvss_score": 7.0,
      "cvss_source": "nvd_v3.1",
      "severity": "HIGH",
      "is_actively_exploited": true,
      "known_ransomware": false,
      "exploit_public": true,
      "exploit_source": "exploitdb",
      "exploit_url": "https://...",
      "epss_score": 0.412,
      "epss_percentile": 0.957,
      "source": "cisa_kev+nvd",
      "nvd_status": "Analyzed",
      "cpe_data_url": "/api/v1/vuln-feed/cve/CVE-2025-0411",
      "last_modified": "2026-05-06T08:14:00Z"
    }
    // ...
  ]
}
```

Note: `cpe_data` itself is NOT inlined here (would be huge). Client fetches it via `cve/{id}` only when actually needed (i.e., when matching against a Product not yet evaluated). Allows efficient incremental pull.

---

### `GET /cve/{cve_id}`

Full CVE detail including CPE applicability data.

**Response 200**:
```json
{
  "cve_id": "CVE-2025-0411",
  // ... all fields from list endpoint above
  "cpe_data": [
    {
      "vendor": "7-zip",
      "product": "7-zip",
      "cpe_uri": "cpe:2.3:a:7-zip:7-zip:*:*:*:*:*:*:*:*",
      "cpe_part": "a",
      "version_start": null,
      "version_start_type": null,
      "version_end": "24.09",
      "version_end_type": "excluding",
      "exact_version": null
    }
  ],
  "cpe_fetched_at": "2026-05-04T22:15:00Z"
}
```

Client uses this to populate its local `vulnerabilities.cpe_data` (JSON-serialized array of entries — same shape as today).

---

### `GET /cpe-dictionary`

Returns the cached, normalized CPE dictionary. Used by clients during `apply_cpe_to_product` Tier 3 lookup, eliminating the need to call NVD CPE search directly.

**Query params**:
- `since` (ISO 8601, optional)
- `page` (int, default 1)
- `page_size` (int, default 1000)

**Response 200**:
```json
{
  "page": 1,
  "total": 1248301,
  "data": [
    {
      "cpe_vendor": "7-zip",
      "cpe_product": "7-zip",
      "cpe_uri": "cpe:2.3:a:7-zip:7-zip:24.09:*:*:*:*:*:*:*",
      "title": "7-Zip 24.09",
      "deprecated": false,
      "last_modified": "2024-11-29T00:00:00Z"
    }
    // ...
  ]
}
```

---

### `GET /exploit-intel` (PRO TIER ONLY)

Sentrikat-curated intelligence beyond NVD/CISA. Initially: aggregation of ExploitDB, GitHub PoC, vendor advisories. Future: trending data from anonymous client telemetry.

**Response 200**:
```json
{
  "data": [
    {
      "cve_id": "CVE-2025-0411",
      "exploit_public": true,
      "exploit_sources": [
        {"name": "exploitdb", "url": "...", "confidence": "high"},
        {"name": "github_poc", "url": "https://github.com/...", "confidence": "medium"}
      ],
      "trending_signal": null,
      "sentrikat_severity_override": null,
      "first_seen_in_wild": "2025-02-04T00:00:00Z"
    }
  ]
}
```

`trending_signal` and `sentrikat_severity_override` are reserved for future telemetry-driven features.

---

## Error response format

All non-2xx responses follow:

```json
{
  "error": "tier_insufficient",
  "message": "This endpoint requires Professional tier or higher.",
  "documentation_url": "https://docs.sentrikat.com/vuln-feed/access-control"
}
```

Standard `error` codes:
- `auth_invalid_signature`, `auth_replay_detected`, `auth_installation_unknown`, `auth_installation_suspended`
- `tier_insufficient`, `feature_not_enabled`
- `rate_limit_exceeded`, `quota_exceeded`
- `not_found`, `bad_request`, `internal_error`

---

## Versioning

- URL-versioned: `/api/v1/...`. Major versions only. Breaking changes go to `/v2/`.
- `Contract-Version` header on responses signals the spec version implemented (`0.1.0`, `0.2.0`, ...).
- Clients send `Accept: application/vnd.sentrikat.vuln-feed.v1+json` (optional but recommended).
- Backward compatibility: server keeps `/v1` running for at least 12 months after `/v2` GA.

---

## Rate limiting (server side)

Per-installation rate limits to protect the broker:
- 60 requests/minute on `/vulnerabilities` and `/cpe-dictionary`
- 600 requests/minute on `/cve/{id}` (random access common during initial sync)
- Unauthenticated `/health`: 1000 requests/minute per source IP

Exceeding returns 429 with `Retry-After` header.

---

## Client-side implementation contract (sentrikat repo)

A client library `app/vuln_feed_client.py` MUST implement:

```python
class VulnFeedClient:
    def __init__(self, base_url: str, installation_id: str, hmac_secret: str): ...
    def health(self) -> dict: ...
    def manifest(self) -> dict: ...
    def list_vulnerabilities(self, since: datetime | None = None, page: int = 1, page_size: int = 100, kev_only: bool = False) -> dict: ...
    def get_cve(self, cve_id: str) -> dict: ...
    def list_cpe_dictionary(self, since: datetime | None = None, page: int = 1) -> dict: ...
    def get_exploit_intel(self, since: datetime | None = None) -> dict: ...
```

Wired into existing sync jobs:

```python
# app/cisa_sync.py — modified
def sync_cisa_kev(...):
    if SystemSettings.get('vuln_feed_url'):
        # NEW: pull from broker
        client = VulnFeedClient(...)
        data = client.list_vulnerabilities(since=last_sync, kev_only=True)
        _ingest_from_broker(data)
    else:
        # LEGACY: direct NVD/CISA (existing code)
        ...
```

Settings keys (in `system_settings`):
- `vuln_feed_url` — the broker base URL (empty/null = legacy direct mode)
- `vuln_feed_installation_id` — UUID set during license activation
- `vuln_feed_hmac_secret` — encrypted

When `vuln_feed_url` is set, ALL sync code paths take the broker route. NVD direct calls are bypassed.

---

## Server-side implementation contract (sentrikat-web repo)

`license-server/vuln_feed/` (new directory) MUST contain:

```
license-server/
└── vuln_feed/
    ├── __init__.py
    ├── router.py             # FastAPI APIRouter at prefix /api/v1/vuln-feed
    ├── auth.py               # HMAC signature verification dependency
    ├── models.py             # SQLAlchemy: vuln_cves, vuln_cpe_data, ...
    ├── schemas.py            # Pydantic response schemas matching this contract
    ├── enrichment/           # Ports of cisa_sync.py, nvd_*.py from sentrikat core
    │   ├── cisa_sync.py
    │   ├── nvd_api.py
    │   ├── nvd_cpe_api.py
    │   ├── euvd_sync.py
    │   └── epss_sync.py
    └── jobs.py               # APScheduler / Celery beat job definitions
```

Recommended approach: **port the existing enrichment code** from `sbr0nch/sentrikat/app/cisa_sync.py` and friends (already mature, ~2000 lines well-tested). Don't rewrite from scratch.

### R-PARSER-RESILIENCE — Non-functional requirement (added 2026-05-06)

**Trigger**: 2026-05-06 sentrikat-web admin `/admin/datasources` showed `ENISA EUVD: SCHEMA_CHANGED`, `CISA KEV: AUTH_CHANGED`, `CVE.org Vulnrichment: DEGRADED`. Pattern reveals fragility: any minor upstream schema change blocks ingestion until human intervention. Unacceptable for a vulnerability platform that must keep flowing.

**Requirement**: enrichment parsers (cisa_sync.py, nvd_api.py, euvd_sync.py, epss_sync.py) MUST follow the **defensive parser pattern**:

1. **Required vs optional fields explicit**:
   - `REQUIRED_FIELDS = ['cve_id', ...]` → if missing → fail loud with `SchemaIncompatibleError`, alert ops
   - `OPTIONAL_FIELDS = ['cvss_score', 'description', ...]` → if missing → log warning, continue with default

2. **Field aliases / lookup chain**:
   ```python
   FIELD_ALIASES = {
       'cve_id': ['cve_id', 'cveId', 'identifier', 'cve.id'],
       'cvss_score': ['cvss.baseScore', 'cvssV3.score', 'cvssMetricV3.cvssData.baseScore', 'score'],
       'severity': ['severity', 'baseSeverity', 'cvss.baseSeverity'],
   }
   ```
   Try each alias in order, first hit wins. Decouples canonical SentriKat naming from upstream churn.

3. **Schema drift telemetry (non-blocking)**:
   ```python
   shape_hash = hash_keys_recursively(payload)
   if shape_hash != last_known_shape_hash:
       telemetry.emit('feed.schema_drift', {'feed': 'euvd', 'before': old, 'after': new})
       last_known_shape_hash = shape_hash
   # Continue ingestion — don't abort
   ```

4. **Pydantic models with `model_config = ConfigDict(extra='ignore')`**:
   - Tolerate added fields silently
   - Use `Optional[X] = None` for fields that may disappear

5. **Health-check distinction**:
   - **HEALTHY** — fetch + parse OK
   - **DEGRADED** — fetch OK, parse partial (some optional fields missing or unrecognized)
   - **SCHEMA_CHANGED** — fetch OK, parse blocked because **required field gone or renamed without alias coverage** → human triage needed
   - **AUTH_CHANGED** — fetch returned 401/403/unexpected envelope (upstream changed auth) → ops update credential
   - **DOWN** — fetch failed (5xx, timeout, DNS, etc.)

6. **Type coercion at parse boundary**: if upstream changes `severity` from string `"HIGH"` to int `7`, parser auto-coerces with mapping table; doesn't crash.

7. **Reference implementation**: when porting `cisa_sync.py` to `vuln_feed/enrichment/cisa_sync.py`, refactor inline `data['key']` → `_get_aliased(data, FIELD_ALIASES['key'])`. Effort estimate: +0.5 day per parser file (5 parsers ≈ 2.5 days additional, well-spent investment).

**Acceptance**: a parser implementation passes R-PARSER-RESILIENCE if a sentrikat-web pen-test team can rename, re-nest, or remove an OPTIONAL field in a synthetic upstream response and the parser still ingests records (with telemetry emitted). Renaming a REQUIRED field correctly produces SchemaIncompatibleError + alert.

**Cross-repo applicability**: same pattern SHOULD be retrofitted into `sbr0nch/sentrikat/app/cisa_sync.py` etc. for V1.0 customers running direct-to-NVD before broker is live. Not blocking for EA, but on the post-EA hardening backlog (F.4 NVD enrichment robustness — see `CVE-MATCHING-PIPELINE.md`).

---

## Migration path for existing on-prem customers

1. **V1.0 (today, EA)**: every customer uses direct-NVD mode. No broker. `vuln_feed_url` not set anywhere.
2. **V1.1 (month 2-3 post-EA)**: broker deployed. Existing on-prem customers continue direct-NVD by default. New on-prem deployments get `vuln_feed_url` pre-configured.
3. **V1.2 (month 4-5)**: docs encourage existing customers to migrate to broker (one-line `system_settings` update). Both modes still supported.
4. **V2.0 (month 9-12)**: direct-NVD mode deprecated. Customers must use broker.

Reasoning: V1.0 customers chose on-prem partly for "no outbound to vendor cloud". Forcing broker on day-one breaks that promise. V1.1+ is opt-in. V2.0 is the long-tail consolidation.

---

## Risks & mitigations

| Risk | Mitigation |
|---|---|
| Broker becomes single point of failure for all customers | (a) HA deploy from day 1 (2+ instances behind load balancer); (b) Cloudflare CDN caching for `/cpe-dictionary` and incremental `/vulnerabilities` pulls; (c) clients keep their local cache and degrade gracefully if broker unreachable for <72h |
| Customer data residency concerns | Broker is in EU (Hetzner Falkenstein same as license-server). Document explicitly in customer-facing privacy policy. EU customers stay in EU. |
| HMAC secret leakage from compromised installation | License server has revocation already. Add `installation_id` to a denylist; broker checks denylist on each request. |
| Cost of CDN + compute for large customer base | Cloudflare free tier covers up to ~100k requests/day for static-ish responses. Postgres can serve up to ~10k installations on a 4-core/16GB instance with proper indexing. Monthly cost <€100 for first 100 customers. |
| Schema evolution breaks clients | URL versioning + Contract-Version header + 12-month overlap policy (described above). |

---

## Open questions for next architectural review

1. **GraphQL vs REST?** Started with REST for simplicity. GraphQL would let clients request only fields they need, reducing bandwidth on `/vulnerabilities`. Reconsider at v2 if performance demands it.
2. **WebSocket / SSE for push updates?** Polling is simpler and adequate for 15-min freshness. Push only if customers demand sub-minute alerts on KEV additions (premium feature).
3. **gRPC for internal SaaS-to-broker calls?** SaaS instances are first-party — could use a faster protocol than HTTPS REST. Marginal benefit; defer.
4. **Telemetry collection for trending data**: requires explicit customer opt-in and clear privacy notice. Design doc TBD when feature is greenlit.

---

## Decision log

| Date | Decision | Reason |
|---|---|---|
| 2026-05-06 | Broker lives inside `license-server` (not standalone service) | Reuse auth + Postgres + deploy infra. Lazy decoupling — split later if it grows. |
| 2026-05-06 | HMAC over license shared secret (not OAuth/JWT) | License system already issues shared secrets; no new auth infra needed. |
| 2026-05-06 | URL versioning (`/v1/`) over header versioning | More cache-friendly for CDN; clearer for customer documentation. |
| 2026-05-06 | Direct-NVD remains default for V1.0 EA customers | Avoid breaking the on-prem trust model day-one. Migrate gradually. |

---

End of contract.
