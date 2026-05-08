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

---

# UPDATE 2026-05-06 — bug aperti consolidati dalla sessione core

> Aggiunto dopo sessione walkthrough Phase 04 + Phase 05 re-verify post PR #252-#263 stable.
> **Tutto sotto è già documentato in dettaglio nei file della repo `sbr0nch/SentriKat`** (pubblica). Leggere lì per evidence + screenshot + repro steps.

## Files da leggere (in ordine)

1. `docs/SESSION-HANDOFF-2026-05-06.md` — orientation generale
2. `docs/e2e-tests/04-portal-customer.md` — § "Re-test 7-dim sistematico — 2026-05-06" (in fondo). 5 finding portal customer
3. `docs/e2e-tests/05-admin-portal.md` — sezioni `[05.x]` aggiornate con verify/fix status + 3 nuovi bug
4. `docs/architecture/VULN-FEED-BROKER-DESIGN.md` — § "R-PARSER-RESILIENCE" requirement nuovo

## Bug aperti consolidati lato sentrikat-web

### 🔴 HIGH — pre-EA / urgent

| Bug ID | File detail | Title sintetico | Suggerimento fix |
|---|---|---|---|
| `[05.1.2]` | `05-admin-portal.md` § 05.1 | KPI tile "CVE Findings" su `/admin/releases` stampa literal `0[object Object][object Object]...` | Trova template `<div>{cveCount}{cveList}</div>` o equivalente, sostituisci con solo `{cveCount}` o `{cveList.map(c => c.id).join(', ')}` |
| `[05.3.2]` | `05-admin-portal.md` § 05.3 | CISA KEV `AUTH_CHANGED`, ENISA EUVD `SCHEMA_CHANGED`, CVE.org `DEGRADED` su `/admin/datasources` | (1) Verificare URL/auth CISA KEV — se feed pubblico immutato, fix monitor fingerprint. (2) Aggiornare parser EUVD per nuovo schema. (3) Implementare R-PARSER-RESILIENCE per evitare ricorrenza |
| `[05.4.1]` | `05-admin-portal.md` § 05.4 | Public status "All systems operational" mentre datasources mostra DOWN | Auto-create incident draft quando data source DOWN/DEGRADED. Status page deve riflettere monitoring automatico, non solo incidents manuali |

### 🟡 MEDIUM — post-EA backlog

| Bug ID | File detail | Title |
|---|---|---|
| `[04.5.1]` | `04-portal-customer.md` § 04.5 | `v1.0.0-beta.6` marcato LATEST invece di `v1.0.0` stable (semver sort) — utente mitiga manualmente cancellando tag obsoleti |
| `[04.5.2]` | `04-portal-customer.md` § 04.5 | "Unknown" CVE count su tutte le release; solo l'ultima ha "Secure — No known vulnerabilities" |
| `[05.1.3]` | `05-admin-portal.md` § 05.1 | "NaN MB" su tutte le 7 release in `/admin/releases` (size field undefined senza fallback) |
| `[05.21.1]` | `05-admin-portal.md` § 05.21 | `/admin/plans` ancora hardcoded ("Plans are defined in code"), prezzi/limits divergono da Calculator e plans_config canonical. Customer-facing OK. |

### 🔵 INFO — nice-to-have

| Bug ID | File detail | Title |
|---|---|---|
| `[04.2.1]` | `04-portal-customer.md` § 04.2 | Enterprise plan limits: 10 agents · 3 users — verificare che sia il valore canonical voluto, non residuo seed/test |
| `[04.7.1]` | `04-portal-customer.md` § 04.7 | Field "Company" vuoto in /account anche se l'utente l'ha compilato a signup — verifica che customer.profile.company persista da signup form |
| `[04.5.3]` | `04-portal-customer.md` § 04.5 | "What's New — Agent v1.2.0" Trivy container scanning — feature highlight ok, mantenere il pattern |

## Verde / chiusi (non più da toccare)

PR #252-#263 hanno fixato (verified live 2026-05-06):
- `[05.1.1]` releases empty → ora 7 release popolate
- `[05.3.1]` data source "Unknown" → 6 source nominati
- `[05.5.1]` centralized logs vuoto (deploy `23ce9da`)
- `[05.6.1]` last login `-` (deploy `23ce9da`)
- `[05.8.1]` RSA_PRIVATE_KEY → CONFIGURED
- `[05.9.1]` CSP script-src-attr → handlers funzionano
- `[05.13.1]` newsletter subscribers 403 → carica
- `[05.22.1]` EA Tenants stats 401 → cards funzionano
- `[04.1.3]` OTP email regression → email arriva (PR #257)

## Nuova architettura — R-PARSER-RESILIENCE (non-funzionale)

Aggiunto a `VULN-FEED-BROKER-DESIGN.md` § "R-PARSER-RESILIENCE" come requirement obbligatorio per il broker mese 2-3. **Quando implementi i parser in `license-server/vuln_feed/enrichment/`, segui il pattern**: REQUIRED vs OPTIONAL, field aliases, schema drift telemetry non-blocking, Pydantic `extra='ignore'`. Evita di hardcodare il path `data['key']` ovunque.

Lo stesso pattern è raccomandato anche per `sbr0nch/sentrikat/app/cisa_sync.py` esistente (post-EA backlog F.4).

---

## Prompt copia-incolla aggiornato per la sessione gemella

```
Sessione Claude su sbr0nch/SentriKat-web. Pre-EA è stable, le PR
#252-#263 sono mergeate in prod e l'evento è in corso. Ora ti
arrivano dalla sessione core (sbr0nch/SentriKat) i nuovi bug
emersi dal walkthrough Phase 04 + 05 re-verify del 2026-05-06.

Leggi questi file dalla repo pubblica sbr0nch/sentrikat tramite
WebFetch o equivalente:

1. https://github.com/sbr0nch/sentrikat/blob/main/FIX-HANDOFF-sentrikat-web.md
   — sezione "UPDATE 2026-05-06" in fondo. Dossier sintetico bug
   aperti, già categorizzati HIGH / MEDIUM / INFO.

2. https://github.com/sbr0nch/sentrikat/blob/main/docs/e2e-tests/05-admin-portal.md
   — dettaglio per ogni [05.x] bug: repro, screenshot URL,
   hypothesis root-cause, suggerimento fix.

3. https://github.com/sbr0nch/sentrikat/blob/main/docs/e2e-tests/04-portal-customer.md
   — sezione "Re-test 7-dim sistematico — 2026-05-06" per i 5
   findings portal customer.

4. https://github.com/sbr0nch/sentrikat/blob/main/docs/architecture/VULN-FEED-BROKER-DESIGN.md
   — sezione "R-PARSER-RESILIENCE": requirement nuovo per i parser
   broker mese 2-3.

Dopo aver letto, NON scrivere codice subito. Riporta all'utente:

A. Per i 3 bug HIGH (`[05.1.2]`, `[05.3.2]`, `[05.4.1]`):
   - Identifica il file colpevole nel tuo repo (path probabile)
   - Stima effort di fix (S = <2h, M = mezza giornata, L = giornata+)
   - Identifica eventuali blocker (es. credenziali CISA da
     ottenere, schema EUVD nuovo da analizzare)

B. Per i 4 bug MEDIUM:
   - Conferma se vanno in backlog post-EA (raccomandato) o
     fixati ora prima dell'evento (solo se < 2h totali e zero
     rischio regressione)

C. R-PARSER-RESILIENCE:
   - Quando arrivi al lavoro broker mese 2-3, conferma che il
     pattern è applicabile in license-server/vuln_feed/.
     Se vedi obiezioni o miglior approccio (es. un parser
     library ufficiale vuln-data Python), dimmelo prima di
     implementare.

D. Stato attuale del tuo repo lato deploy:
   - tutti i container sono ancora running e healthy?
   - daily security scan (`d935a1b`) sta girando?
   - prossimo deploy schedulato quando?

E. Domande aperte per Massimiliano (l'operatore): max 5.

Regole:
- Frugale con i Read (offset/limit su file >200 righe)
- Push su tuo branch claude/<name>, non su main
- Aggiorna FIX-HANDOFF-sentrikat-web.md sul repo sentrikat (push
  via PR su sbr0nch/sentrikat) quando un bug viene chiuso, così
  l'altra sessione vede il progresso

Non aspettarti risposta dalla sessione core fino a quando
Massimiliano non riapre quella e ti porta news.
```
