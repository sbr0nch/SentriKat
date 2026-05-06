# Fase 07 — Agents & Inventory

> Test end-to-end del flow agent: download → install → enroll → inventory push → heartbeat → asset management. Surface principale: `app/agent_api.py` (~6500 righe), agent client repo separato (`sentrikat-agent`), CLI `sentrikat-scan`.

## Aree coperte — Agent lifecycle

| Area | Surface | Description | Env |
|---|---|---|---|
| 07.1 | Agent script download Windows (PowerShell) | `/agent/download/windows` → `.ps1` script with embedded API key + tenant URL | 🏢☁️ both |
| 07.2 | Agent script download Linux | `/agent/download/linux` → `.sh` script | 🏢☁️ both |
| 07.3 | Agent script download macOS | `/agent/download/macos` → `.sh` script | 🏢☁️ both |
| 07.4 | API key generation per agent group | `/admin/agent-keys` UI, regenerate, revoke | 🏢☁️ both |
| 07.5 | Agent enroll flow | First contact: send hostname, OS, agent_version → server registers Endpoint row | 🏢☁️ both |
| 07.6 | Agent heartbeat | Periodic ping `/api/v1/agent/heartbeat`, updates last_seen | 🏢☁️ both |
| 07.7 | Agent offline detection | Scheduler job `agent_offline_detection`, mark stale endpoints | 🏢☁️ both |

## Aree coperte — Inventory ingestion

| Area | Surface | Description | Env |
|---|---|---|---|
| 07.8 | Inventory push sync (`report_inventory`) | Synchronous endpoint, blocks agent until processed | 🏢☁️ both |
| 07.9 | Inventory push async (`process_inventory_job`) | Worker pool, agent gets 202 Accepted immediately | 🏢☁️ both |
| 07.10 | Product CPE assignment at ingest | `apply_cpe_to_product(product)` Tier 1+2+3 | 🏢☁️ both |
| 07.11 | Cap enforcement during ingest | `[01.18.5]` SaaS subscription plan caps, on-prem license caps | 🏢☁️ both |
| 07.12 | Import queue routing | New products go to queue if config = "review-first", else direct to inventory | 🏢☁️ both |
| 07.13 | Container scan (Docker/Podman) | Agent v1.2.0 Trivy integration, OS+app deps in containers | 🏢☁️ both |
| 07.14 | Dependency scan (sentrikat-scan CLI) | Standalone CLI for Python/npm/Maven/Go/Rust deps in repos | 🏢☁️ both |

## Aree coperte — Asset management

| Area | Surface | Description | Env |
|---|---|---|---|
| 07.15 | Endpoint detail page | `/endpoints/<id>` — installed software list, CVE matches, scan history | 🏢☁️ both |
| 07.16 | Endpoint deletion | Cascade delete products if not on other endpoints | 🏢☁️ both |
| 07.17 | Source-type classification | server / client / container / dependency / endpoint — UI filter | 🏢☁️ both |
| 07.18 | Endpoint to org mapping | M2M `endpoint_organizations` (MSSP multi-org) | 🏢☁️ both |
| 07.19 | Auto-detect asset type | Scheduler job `auto_detect_asset_type` — heuristics on hostname / OS | 🏢☁️ both |
| 07.20 | Stuck job recovery | Scheduler `stuck_job_recovery` — retry inventory jobs interrupted by crash | 🏢☁️ both |

## 7-dim standard

---

_Sezioni 07.1-07.20 da popolare durante walkthrough live. Anti-pattern: PC casa con docker compose locale per agent enrollment, Windows VM in testlab per agent .ps1 download._

## Bug summary

| Bug ID | Severity | Env | Title |
|---|---|---|---|
| _(none yet)_ | | | |

## Cross-ref

- `app/agent_api.py` (~6500 righe) — main module
- `tests/test_agent_inventory.py` — esistono test unit
- `tests/test_container_dependency_scanning.py`
- `scripts/sentrikat-scan.py` — CLI standalone
- `docs/AGENT_SIGNING.md` — agent code signing process
- `CVE-MATCHING-PIPELINE.md` § F.9 — agent registry parser hardening (Win MSI DisplayVersion vs Version)
