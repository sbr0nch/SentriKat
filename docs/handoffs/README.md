# `docs/handoffs/` — Cross-team and cross-session handoff messages

This folder contains:

1. **Cross-repo handoffs** — current coordination notes between `sentrikat` (this repo, SaaS app + on-prem core) and `sentrikat-web` (license-server, portal admin, marketing site). When a finding from one side affects the other, it lands here as `FIX-HANDOFF-sentrikat-web-*.md`.

2. **`archived/`** — past session-end handoffs (`SESSION-HANDOFF-YYYY-MM-DD-*.md`). These are point-in-time snapshots of "where we were when this session ended". Useful for context when restarting a long-running thread, but **not** authoritative — always defer to current code state and `CHANGELOG.md`.

## Conventions

- Cross-repo: `FIX-HANDOFF-<other-repo>-<scope>.md` — living document, updated as findings land.
- Session: `SESSION-HANDOFF-YYYY-MM-DD[-suffix].md` — moved to `archived/` when superseded.

## When to write a handoff

- A finding involves **the other repo** (cross-repo coordination).
- A session ends with **incomplete work** that the next session should know about.
- A **decision was made** (architecture, timing, scope) that should outlive a single Slack message.

## When NOT to write a handoff

- Routine fix landed and tested → put it in `CHANGELOG.md`, not here.
- Internal-only architecture decision → put it in `docs/architecture/` or `docs/audits/`.
- Customer-facing change → update `docs/customer/USER_GUIDE.md`.

## Current cross-repo coordination

See:
- [`FIX-HANDOFF-sentrikat-web-root.md`](./FIX-HANDOFF-sentrikat-web-root.md) — top-level cross-repo issues
- [`FIX-HANDOFF-sentrikat-web-e2e.md`](./FIX-HANDOFF-sentrikat-web-e2e.md) — E2E-test-driven cross-repo findings
- [`/docs/contracts/CROSS-REPO-CONTRACTS.md`](../contracts/CROSS-REPO-CONTRACTS.md) — formal API contract source-of-truth
