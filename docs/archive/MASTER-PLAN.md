# SentriKat — Master Plan: Bug Fixing → Launch → Scale

> Strategia operativa di alto livello per portare SentriKat da "in
> testing" a "GA enterprise certified". Documento di riferimento
> per pianificazione product/engineering.
>
> **Aggiornato**: 2026-05-04
> **Owner**: Denis Sota + AI assistant pair-coding

---

## Le 4 fasi (in ordine cronologico)

### Fase 1 — Bug Fixing & Smoke Test (NOW, ~80% done)

**Obiettivo**: trovare e fixare il maggior numero possibile di bug
funzionali sull'app, sia core (sentrikat) che web (sentrikat-web).

**Approccio**: testing per componente — singole pagine, singoli flussi
auth, singoli endpoint API. Bug discovery sistematica con framework
7-dim (happy path, persistence, CRUD, RBAC, state transitions,
negative input, integration).

**Output**: counter `00-INDEX.md` con bug elencati per fase, fixati,
verified.

**Stato attuale (2026-05-04)**:
- 6 round di fix completati (Round 1 → Round 6)
- 27/27 fix VERIFIED su core SentriKat
- 0 bug HIGH/CRITICAL aperti su core
- 8 fix Phase 05 cross-repo VERIFIED dal team web
- 2 fix cross-repo aperti (`[05.21.1]` pricing, `[02.4.5-4.8]` email)
- 4 docs items handoff in corso
- Side findings: 4 INFO (raccolta per Round 7)

**Definizione di "fatto"**:
- Bug HIGH/CRITICAL counter aperti = 0 sia core che web
- Smoke test 6 step end-to-end OK su tutto il flusso ammin
- Tutti i fix verified live (browser + log + db check)

**ETA**: 1-2 giorni di lavoro residuo (chiusura side findings + verify
post merge web team).

---

### Fase 2 — Customer Walkthrough Test (NEXT, ~0% done)

**Obiettivo**: l'utente (Denis) esegue un giro completo come se fosse
un customer reale, partendo da signup-as-a-customer fino all'uso
quotidiano della piattaforma. Trova bug che il testing per
componente non vede (UX flow rotti, transitions tra pagine,
integration tra feature, naming inconsistencies sotto pressione
reale).

**Approccio**: 2 walkthrough — uno SaaS, uno on-prem.

#### 2.A SaaS walkthrough (~2-3h)

Scenario: nuovo customer che valuta SentriKat per la sua azienda.

1. **Discovery**: visit `https://sentrikat.com` → leggi landing
   page → click "Get Started" / "Try Free"
2. **Signup**: form `https://sentrikat.com/signup` → conferma email
   → trial trigger
3. **Login**: `https://app.sentrikat.com` → OTP → setup wizard
4. **Setup**: org name → admin user → seed catalog → run initial sync
5. **Daily use**: dashboard → vulnerability list → settings →
   integrations (Jira test) → users invite (vede limite Community)
6. **Account self-service**: `https://portal.sentrikat.com` → license
   page → download agent → support form

#### 2.B On-prem walkthrough (~2-3h)

Scenario: IT admin enterprise installa SentriKat on-premise.

1. **Discovery**: docs.sentrikat.com → "Deploy on-prem" guide
2. **Install**: `git clone` + `docker compose up` + .env setup
3. **First boot**: `localhost/setup` wizard → admin user → service
   catalog → initial sync
4. **Configure**: SMTP → SAML/LDAP → Jira integration → notification
   policy
5. **Daily use**: dashboard → admin panel → user management → audit
   log → backup test
6. **Upgrade simulation**: stop docker → pull new tag → up → verify
   migration

**Output**: Round 7 fix sui bug scoperti durante walkthrough.

**ETA**: 1 sessione 5-6h walkthrough + 1-2 giorni fix.

---

### Fase 3 — E2E Flow Validation (~0% done)

**Obiettivo**: validare i 46 flussi E2E catalogati in
`docs/e2e-tests/E2E-FLOWS-INDEX.md` con dataset realistico (small
flows, non scale).

**Approccio**: 6 sessioni di test focalizzate per area, ogni
sessione 2-3h. Ogni flusso ha pre-req + step + verify checklist nel
doc index.

**Pre-requisiti dev**:
- `scripts/seed_e2e_dev.py` lanciato (5 asset + 10 product + 30 vuln
  + matches) — già scritto
- License Pro temporanea attiva localmente per agent flows AG-2..AG-7
- testlab containers running (Mailpit, Keycloak, OpenLDAP, Jira mock,
  webhook-tester) per integration flows IN-1..IN-5

**Sessioni**:
1. VM flows (post-seed) — 2-3h
2. Health + report — 2h
3. Agent E2E con Pro license — 3-4h
4. Cross-repo (portal admin/customer + sync/heartbeat/metering) — 2-3h
5. Integrations + RBAC — 2-3h
6. Admin ops finali — 1-2h

**Definizione di "fatto"**: tutti i 46 flussi marcati ✅ o 🔴 (con bug
aperto + fix). Counter "Done" del doc al 100% o spiegata l'eccezione.

**ETA**: 12-17h spalmati in 1-2 settimane di lavoro saltuario.

---

### Fase 4 — Scale & Performance (FUTURO, post-launch)

**Obiettivo**: portare SentriKat da "fits 5-50 endpoint customer
pilot" a "GA enterprise certified per 5000+ endpoint".

**Approccio**: 5 livelli progressivi (vedi
`docs/SCALE-TESTING-ROADMAP.md`).

**Trigger di attivazione** per livello:
- L1 Load test base — quando arriva il primo customer Pro 50-500 ep
- L2 DB scale dataset — quando arriva il primo customer Enterprise
  500-5000
- L3 Fleet simulator — pre-go-live customer 1000+
- L4 Chaos engineering — pre customer mission-critical / SLA hard
- L5 Real customer pilot — design partner per 30 giorni 99.9% SLA

**Stima costi**: 35-45K€ + 3-4 mesi cal per arrivare a "GA enterprise
certified" (vedi roadmap doc per breakdown).

**ETA**: dipende da rate di acquisizione customer enterprise. Tipico:
6-12 mesi post-launch.

---

## Strategia merge cross-repo (importante)

Il prodotto è split su 3 repo:
- `sbr0nch/sentrikat` (core on-prem + SaaS Flask app)
- `sbr0nch/sentrikat-web` (landing + portal customer + portal admin)
- License-server (parte di sentrikat-web monorepo)

Quando un fix tocca più di un repo, **merge sequenziale con smoke
test** tra l'uno e l'altro per evitare regressione cascade:

1. Repo A → merge in main → smoke test 5 min
2. Repo B → rebase su main aggiornato → merge → smoke test
3. Repo C → idem

Mai merge parallelo simultaneo per cambiamenti correlati. Vedi
discussione 2026-05-04 con web team per esempio.

---

## Risk register

| Rischio | Probabilità | Impatto | Mitigazione |
|---|---|---|---|
| Bug funzionale residuo non scoperto in fase 2 walkthrough | Alta | Medio | Customer pilot con observability heavy |
| Cross-repo fix breaking change tra release | Media | Alto | Merge sequenziale + smoke test obbligatorio |
| Customer enterprise firma prima di completion fase 4 L1-L3 | Media | Alto | SOW con SLA proportional al livello completato |
| DB schema migration regression in production | Bassa | Alto | Test su staging mirror produzione + flask db downgrade |
| Email deliverability poor (welcome OTP/digest) | Media | Medio | DNS SPF/DKIM/DMARC verificato + monitoring inbox placement |
| Logging silent breakage (vedi `[03.20.1]`) | Già occorso | Medio | Health check sui log files + observability dashboard |

---

## Counter globali

### Bug fixing (Fase 1)

| Categoria | Count |
|---|---|
| Bug HIGH/CRITICAL aperti core | 0 |
| Bug HIGH/CRITICAL aperti web | 2 (web team in flight) |
| Fix VERIFIED core | 27 |
| Fix VERIFIED web | 8+12 = 20 |
| Side findings INFO aperti | 4 |
| Round completati | 6 |

### E2E flow validation (Fase 3)

| Area | Done / Total |
|---|---|
| AG | 0/7 |
| VM | 0/6 |
| RB | 0/5 |
| PA | 0/5 |
| PC | 0/6 |
| SY | 0/6 |
| IN | 0/5 |
| AD | 0/6 |
| **Totale** | **0/46 (0%)** |

### Scale levels (Fase 4)

| Livello | Status |
|---|---|
| L1 Load test base | ❌ not started |
| L2 DB scale dataset | ❌ not started |
| L3 Fleet simulator | ❌ not started |
| L4 Chaos engineering | ❌ not started |
| L5 Customer pilot | ❌ not started |

---

## Documenti correlati

| Doc | Purpose |
|---|---|
| `docs/e2e-tests/00-INDEX.md` | Bug discovery tracker (Fase 1) |
| `docs/e2e-tests/E2E-FLOWS-INDEX.md` | E2E flow validation tracker (Fase 3) |
| `docs/SCALE-TESTING-ROADMAP.md` | Scale levels strategy (Fase 4) |
| `docs/e2e-tests/FIX-HANDOFF-sentrikat-web.md` | Cross-repo fix coordination |
| `docs/e2e-tests/HANDOFF-docs-drafts.md` | Docs.sentrikat.com content drafts |
| `scripts/seed_e2e_dev.py` | Dev DB seeding for E2E flows |
| `CLAUDE.md` | Operational rules per AI pair |

---

## Update log

| Data | Update |
|---|---|
| 2026-05-04 | Doc creato. Fase 1 a 80%, Fase 2 inizia post merge web team 3 PR |
