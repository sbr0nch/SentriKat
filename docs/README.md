# SentriKat — Documentation Index

Audience-based navigation. Find what you need by who you are.

## I am a customer / SaaS tenant

**Start with**: [`customer/USER_GUIDE.md`](./customer/USER_GUIDE.md) — comprehensive guide (handbook + admin + SaaS + storage + Windows).

Other customer-facing docs:
- [`customer/API.md`](./customer/API.md) — REST API reference
- [`customer/AGENT_SIGNING.md`](./customer/AGENT_SIGNING.md) — code-signing for the Windows/Linux agents
- [`customer/compliance/OWASP-ASVS.md`](./customer/compliance/OWASP-ASVS.md) — OWASP ASVS coverage statement

## I am operating SentriKat in production

- [`operations/post-deploy-bootstrap.md`](./operations/post-deploy-bootstrap.md) — bootstrap a fresh on-prem deploy
- [`customer/USER_GUIDE.md`](./customer/USER_GUIDE.md) Part 2 — administrator guide

## I am a developer

- [`architecture/ARCHITECTURE.md`](./architecture/ARCHITECTURE.md) — CVE data flow, matching pipeline, scale considerations
- [`architecture/VULN-FEED-BROKER-DESIGN.md`](./architecture/VULN-FEED-BROKER-DESIGN.md) — Q3 broker design (R-PARSER-RESILIENCE spec)
- [`contracts/CROSS-REPO-CONTRACTS.md`](./contracts/CROSS-REPO-CONTRACTS.md) — APIs between SaaS app and license-server
- [`audits/`](./audits/) — point-in-time anti-pattern + OWASP audits

## I am running QA / testing

- [`e2e-tests/00-INDEX.md`](./e2e-tests/00-INDEX.md) — master index of 16 E2E phases (each `0X-*.md` is a phase doc)
- [`../tests/launch-checklist/00_README.md`](../tests/launch-checklist/00_README.md) — launch checklist workflow

## I am a stakeholder / business owner

> Confidential — internal only.

- [`business/01_EXECUTIVE_SUMMARY.md`](./business/01_EXECUTIVE_SUMMARY.md)
- [`business/02_PRODUCT_ROADMAP.md`](./business/02_PRODUCT_ROADMAP.md)
- [`business/STRATEGY.md`](./business/STRATEGY.md) — competitive analysis, pricing, GTM (consolidated)
- [`business/INFRASTRUCTURE.md`](./business/INFRASTRUCTURE.md) — multi-staging, CI/CD plan (consolidated)
- [`business/INVESTOR_DEMO_CHECKLIST.md`](./business/INVESTOR_DEMO_CHECKLIST.md)
- [`business/05_TERMS_OF_SERVICE.md`](./business/05_TERMS_OF_SERVICE.md), `06_PRIVACY_POLICY.md`, `07_SLA.md` — legal docs (kept separate by legal requirement)
- [`business/99_TODO_BEFORE_LAUNCH.md`](./business/99_TODO_BEFORE_LAUNCH.md) — living launch checklist

## I am a Claude session / AI assistant

- [`/CLAUDE.md`](../CLAUDE.md) — operator instructions (anti-timeout rules, branch policy, principio cardine)
- [`handoffs/`](./handoffs/) — cross-team and cross-session handoff messages
- [`handoffs/archived/`](./handoffs/archived/) — past session handoffs

## I am cross-repo (sentrikat-web team)

- [`contracts/CROSS-REPO-CONTRACTS.md`](./contracts/CROSS-REPO-CONTRACTS.md) — single source of truth
- [`handoffs/FIX-HANDOFF-sentrikat-web-root.md`](./handoffs/FIX-HANDOFF-sentrikat-web-root.md), [`-e2e.md`](./handoffs/FIX-HANDOFF-sentrikat-web-e2e.md) — current coordination

---

## Folder map

```
docs/
├── README.md                       ← you are here
├── customer/                       ← customer-facing docs
│   ├── USER_GUIDE.md               ← merged from 5 source files
│   ├── API.md
│   ├── AGENT_SIGNING.md
│   └── compliance/OWASP-ASVS.md
├── architecture/                   ← internal technical reference
│   ├── ARCHITECTURE.md             ← CVE flow + matching + scale
│   └── VULN-FEED-BROKER-DESIGN.md
├── operations/                     ← runbooks
│   └── post-deploy-bootstrap.md
├── contracts/                      ← cross-repo API contracts
│   ├── CROSS-REPO-CONTRACTS.md     ← consolidated
│   └── SAAS_INTEGRATION_SPEC.md    ← legacy original
├── e2e-tests/                      ← QA phase docs (16 phases + INDEX)
│   ├── 00-INDEX.md
│   └── 01-*.md … 16-*.md
├── audits/                         ← point-in-time audits (immutable)
├── business/                       ← INTERNAL strategy & legal
│   ├── 01_EXECUTIVE_SUMMARY.md
│   ├── 02_PRODUCT_ROADMAP.md
│   ├── STRATEGY.md                 ← merged competitive+pricing+GTM
│   ├── INFRASTRUCTURE.md           ← merged architecture+devops
│   ├── INVESTOR_DEMO_CHECKLIST.md
│   ├── 05/06/07_*.md               ← legal (TOS / Privacy / SLA)
│   └── 99_TODO_BEFORE_LAUNCH.md
├── handoffs/                       ← cross-team / cross-session
│   ├── FIX-HANDOFF-sentrikat-web-*.md
│   └── archived/                   ← past session handoffs
└── archive/                        ← stale / superseded docs
```

## Doc reorganization 2026-05-08

This structure replaces the previous flat layout (97 MD files in mixed paths). Key consolidations:

- `customer/USER_GUIDE.md` ← merged 5 source files (HANDBOOK + ADMIN + SAAS + STORAGE + WINDOWS)
- `architecture/ARCHITECTURE.md` ← merged 3 (CVE-DATA-FLOW + CVE-MATCHING-PIPELINE + SCALE-TESTING)
- `business/STRATEGY.md` ← merged 6 (competitive + pricing + GTM)
- `business/INFRASTRUCTURE.md` ← merged 3 (architecture + multi-staging + DevOps)
- `contracts/CROSS-REPO-CONTRACTS.md` ← new, formalizes 3 contracts

12 stale/superseded files moved to `archive/`. Nothing deleted — git history preserved.

See `CHANGELOG.md` for the full list of changes.
