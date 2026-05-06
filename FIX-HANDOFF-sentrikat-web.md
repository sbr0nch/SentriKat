# HANDOFF — sentrikat-web parallel session

> Paste the prompt below into a fresh Claude Code session opened on the `sbr0nch/SentriKat-web` repo.
> That session has MCP access to the web repo; this session does not.

---

## Prompt to paste

```
You are working on `sbr0nch/SentriKat-web` — the cloud platform side of SentriKat
(landing, portal customer, portal admin, license-server, docs). A parallel
Claude session is working on `sbr0nch/sentrikat` (the core vulnerability
management Flask app, both on-prem and SaaS-side).

Your immediate priority is to read TWO documents that live in the sentrikat
core repo:

1. https://github.com/sbr0nch/sentrikat/blob/main/docs/SESSION-HANDOFF-2026-05-06.md
   — overall state of the project, what was done in the last session, what
     remains, and how the two sessions coordinate.

2. https://github.com/sbr0nch/sentrikat/blob/main/docs/architecture/VULN-FEED-BROKER-DESIGN.md
   — the API contract for the Vulnerability Feed Broker, which YOU need to
     implement on the server side inside `license-server/`.

After reading both, do NOT start implementing immediately. Instead:

A. Read the local repo structure with whatever MCP tools you have available.
   Confirm `license-server/` exists and is a FastAPI service.

B. Identify where the new `vuln_feed/` router should live (probably
   `license-server/app/vuln_feed/` or similar).

C. Read the existing `license-server/` auth code (license issuance, HMAC
   verification, installation registry) — the new broker MUST reuse this
   same auth, NOT introduce a separate credential.

D. Report back to the user:
   - confirmed location for the new code
   - any inconsistencies between the contract doc and what's already in
     license-server (e.g., if license-server already has a `vulnerabilities`
     table for some other purpose, naming might collide)
   - your proposed implementation plan in 3-5 milestones (week-sized chunks)

E. Wait for user confirmation before writing any code.

Strict rules:
- Do NOT modify the API contract document (VULN-FEED-BROKER-DESIGN.md) without
  first telling the user. That doc lives in the sentrikat core repo, not yours.
  If you need a change, the user will edit it there and the parallel session
  on sentrikat core will pick it up.
- Do NOT push to main. Push to `claude/<branch>` and ask user to PR.
- Read frugally — use `Read` with offset/limit on any file >200 lines (per the
  CLAUDE.md anti-timeout rules in the sentrikat core repo, which apply to you
  too in spirit if not literally).
- Commit + push every 1-2 useful steps so we don't lose work to timeouts.

The work order is:
- Milestone 0: this scoping task (A-E above), no code changes
- Milestone 1: skeleton router with /health and /manifest endpoints, no real
  data yet, just contract conformance
- Milestone 2: SQLAlchemy models for vuln_cves / vuln_cpe_data + migration
- Milestone 3: port `cisa_sync.py` from sentrikat core to a vuln_feed/enrichment/
  module; wire scheduled jobs
- Milestone 4: implement /vulnerabilities + /cve/{id} endpoints with real data
- Milestone 5: implement /cpe-dictionary + /exploit-intel
- Milestone 6: tier-based access control + rate limiting
- Milestone 7: integration test against the sentrikat core client (which the
  parallel session will deliver around the same time)

Each milestone is its own PR. Coordinate with the user between milestones.

Start by reading the two docs above, then complete Milestone 0.
```

---

## Notes for the operator (Massimiliano)

- Open the new Claude Code session on `SentriKat-web` repo first (separate
  terminal / window). The two sessions don't talk to each other directly —
  YOU are the bridge.
- The sentrikat core session (this one) is working in parallel on the **client
  side** of the broker contract: `app/vuln_feed_client.py` + settings flag
  `VULN_FEED_URL` + sync-job dispatch logic. Both sides will be ready around
  month 2-3 post-EA.
- For pre-EA (this week and next), focus is NOT on the broker. It's on:
    * `sentrikat` core: the 6 must operational features (scheduled jobs,
      health dashboard, data quality badges) — see SESSION-HANDOFF-2026-05-06.md
    * `sentrikat-web`: post-EA bug fixing, customer onboarding tooling, any
      polish from EA event feedback
- The broker is **strategic moat** work — important but not urgent. Do not
  pull either team off pre-EA priorities to start it early.

---

## Sync rituals between sessions

When a session changes anything that affects the other side, the operator:

1. Has the changing session push to `claude/*` branch + open PR
2. Pastes the PR URL into the OTHER session and asks for review/awareness
3. Updates SESSION-HANDOFF-2026-05-06.md (in sentrikat core repo) with the
   change reference
4. Bumps `Contract-Version` in VULN-FEED-BROKER-DESIGN.md if the change
   touches the API contract

Both sessions read SESSION-HANDOFF first thing on resume. That's the canonical
state.

---

End of handoff for sentrikat-web session.
