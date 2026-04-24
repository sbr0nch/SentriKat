# Fase 16 — Extra & Shared (`docs.sentrikat.com`, `community.sentrikat.com`, n8n, nginx, deploy pipeline)

> Sezioni accessorie dell'ecosistema SentriKat-web (doc, community forum, n8n workflow, nginx reverse proxy, CI/CD). Questa fase apre con le 2 surfaces pubbliche raggiungibili dal browser.

## Aree coperte

| Area | Descrizione |
|---|---|
| 16.1 | `docs.sentrikat.com` — documentazione MkDocs Material |
| 16.2 | `community.sentrikat.com` — forum Flarum |
| 16.3 | n8n workflow automation (infrastruttura interna) |
| 16.4 | nginx reverse proxy config + TLS |
| 16.5 | CI/CD pipeline (`release.yml`, `ci.yml`, `deploy.yml`, `staging-deploy.yml`, `docker-security.yml`) |

---

## 16.1 — `docs.sentrikat.com` (MkDocs Material)

### [16.1.1] Homepage rendering + navigation ✅

- **Fase**: 16 · **Area**: Docs
- **Deployment scope**: 📚 docs
- **Tipo**: 🟢 OK
- **Content mappato**:
  - Top nav: `Home · SaaS Quick Guides · Getting Started · User Guide · Admin Guide · API Reference · Agents · FAQ`
  - Dark mode toggle + search box (top right)
  - Homepage hero: "Welcome to SentriKat" + 4 featured cards con **badge deployment**:
    - 🟢 **SaaS — Start in 2 Minutes** `[SAAS]` → "No installation needed. Sign up, deploy agents, see results. Free during Early Access." → link `SaaS Quick Guides`
    - 🟢 **Self-Hosted — Full Control** `[ON-PREM]` → "Deploy on your own infrastructure with Docker. Air-gapped and TOTP 2FA supported." → link `Installation Guide`
    - 🟢 **Focus on Real Threats** `[BOTH]` → `"Stop drowning in 200,000+ CVEs. SentriKat tracks only the ~1,484 vulnerabilities that CISA has confirmed are being actively exploited in the wild."` → link `User Guide`
    - 🟢 **Powerful API** `[BOTH]` → "RESTful API for all operations." → link `API Reference`
  - Right TOC sidebar: `Table of contents · What is SentriKat? · Key Features · Quick Start · Editions & Pricing · SaaS Plans · On-Premises Editions · Support`
- **Discovered**: 2026-04-25

### [16.1.2] 🟢 Badge system `[SAAS]` / `[ON-PREM]` / `[BOTH]` è **best practice** per documentation multi-deployment

- **Fase**: 16 · **Area**: Docs / UX design
- **Deployment scope**: 📚 docs
- **Tipo**: 🟢 OK (positive design) + 🔵 Info
- **Actual**: ogni contenuto "target-aware" ha un badge colorato che chiarisce subito la scope. Best practice per documentation di prodotti con multi-deployment mode
- **Valutazione**: **risolve parzialmente** il mismatch [03.14.10.expand] (DEMO vs Community vs Demo version) — la docs ha disambiguazione visiva, quindi **è il prodotto UI** ad avere terminology inconsistente, non la documentazione
- **Follow-up TODO 16.1.2a**: verificare che ogni pagina della doc applichi questi badge coerentemente. Se alcuni tutorial mancano del badge → inconsistency (es. "Deploy LDAP" senza specificare se SaaS o on-prem)
- **Discovered**: 2026-04-25

### [16.1.3] 🔴 HIGH — Ennesima discrepanza metric KEV catalog — 3 valori diversi su 3 surfaces

- **Fase**: 16 · **Area**: Metric consistency / marketing accuracy
- **Deployment scope**: 🔄 cross-repo (docs + core app + marketing)
- **Tipo**: 🔴 Bug
- **Severity**: **High** (fiducia del customer + marketing accuracy — 3 numeri diversi dice "ce la stiamo inventando")
- **Evidence della discrepanza**:

| Sorgente | Counter reported | Scope |
|---|---|---|
| [02.7.1] Dashboard widget on-prem "KEV Catalog" | **13,978** | core app empty-state dashboard |
| [03.14.3] Settings → System → Sync & Updates "Total Vulnerabilities" | **639** | admin sync page, post sync parziale |
| [16.1.3] docs.sentrikat.com hero card "tracks only the ~1,484 vulnerabilities" | **~1,484** | marketing/docs copy |
| Realtà CISA KEV (aprile 2026 circa) | **~1,400 entries** (stimato) | fonte esterna |

- **Issue**: 3 surfaces del prodotto riportano 3 numeri completamente diversi per lo stesso "KEV Catalog". Il customer che:
  - Legge la docs → aspetta ~1,484
  - Apre la dashboard → vede 13,978
  - Apre admin sync → vede 639
  → **confusion totale**. Quale è "veramente" il KEV catalog?
- **Ipotesi**:
  - `1,484` = numero reale CISA KEV (more or less accurate per la release docs)
  - `639` = sync parziale locale incompleto (bug sync [03.14.2] auto-sync OFF)
  - `13,978` = metric diversa: "Total CVE tracked across all sources (CISA KEV + NVD + ENISA + OSV)" — **mislabeling** come "KEV Catalog" nella dashboard
- **Fix candidato**:
  1. Decidere cosa è "KEV Catalog" vs "Total Vulnerabilities": scegliere 1 canonical name + rename uniformly
  2. Marketing copy (`~1,484`) deve essere live-updated o approximate con tolerance ("1,400+")
  3. Dashboard widget deve mostrare il numero **reale di KEV entries**, non il total CVE tracked
- **Discovered**: 2026-04-25

### [16.1.4] 🔵 Docs menziona "On-Premises Editions" (plurale) — esistono più tier on-prem?

- **Fase**: 16 · **Area**: Docs / edition taxonomy
- **Deployment scope**: 📚 docs + 🏢 on-prem
- **Tipo**: 🔵 Info (aggrava [03.14.10.expand])
- **Actual**: TOC right sidebar include voce `On-Premises Editions` (plurale) — suggerisce che esistono più tier on-prem (Community + Professional + Enterprise?)
- **Potenziale chiarimento cluster**: se docs distingue tier on-prem → la terminology UI "COMMUNITY EDITION" potrebbe essere corretta (tier free + altri tier a pagamento), ma "Demo version" nel message error [03.14.20] resta inconsistente
- **Follow-up TODO 16.1.4a**: aprire la pagina `On-Premises Editions` nella docs e catturare la matrice tier (Community / Professional / Enterprise + prezzi + feature matrix completa)
- **Discovered**: 2026-04-25

### [16.1.5] ⬜ Follow-up TODO audit completo docs content

- **Fase**: 16 · **Area**: Docs content audit
- **Deployment scope**: 📚 docs
- **Tipo**: 🔵 Info (massive TODO)
- **Utente conferma**: "docs sembra tutto apposto ho navigato un po, ovviamente i contenuti non posso analizzarli tutti, servirà in futuro un audit"
- **Task**: audit page-by-page della documentation per:
  - Coerenza terminology (DEMO / Community / Edition naming)
  - Coerenza SaaS vs On-Prem badges
  - Link interni funzionanti
  - Screenshots aggiornati (release beta.6, non beta.2)
  - Step-by-step tutorial testati end-to-end
  - API Reference: ogni endpoint documentato esiste realmente nel backend
  - FAQ coerente con bug conosciuti (se la FAQ dice "OTP arriva in secondi", rispetto ad oggi [04.1.3], bug)
- **Effort stimato**: multi-session, non testabile in un giro veloce
- **Discovered**: 2026-04-25 (riserva per future session)

---

## 16.2 — `community.sentrikat.com` (Flarum)

### [16.2.1] Community forum rendering + base content ✅

- **Fase**: 16 · **Area**: Community forum
- **Deployment scope**: 🔐 community (repo `SentriKat-web/community/`)
- **Tipo**: 🟢 OK
- **Content**:
  - Header: "SentriKat Community" + Search Forum + Sign Up + Log In
  - Hero banner: "Welcome to the SentriKat Community — Share knowledge, report bugs, ask questions, and connect with other SentriKat users. No support contract needed."
  - Sidebar: "Start a Discussion" (CTA blu prominent) + "All Discussions"
  - Filter: Latest (dropdown)
  - Refresh icon top-right
  - **2 thread esistenti** (entrambi da `SK-Denis`, 11 Feb, 0 reply):
    - `Welcome & Forum Rules`
    - `How to Write a Good Bug Report (Template)`
- **Utente valutazione**: "il community magari e brutto da vedere pero le cose sembrano funzionare ogni bottone e cose" → funzionalità OK, aesthetic neutrale
- **Discovered**: 2026-04-25

### [16.2.2] 🔵 Info — Timestamp "11 Feb" senza anno visibile

- **Fase**: 16 · **Area**: Community / date display
- **Deployment scope**: 🔐 community
- **Tipo**: 🔵 Info (minor UX)
- **Actual**: thread mostrano `started 11 Feb` — senza anno. Oggi è 2026-04-25, "11 Feb" è ~2.5 mesi fa ambiguo (2026? 2025?)
- **Flarum default**: hover sulla data dovrebbe mostrare full timestamp tooltip — non verificato dall'utente
- **Follow-up TODO 16.2.2a**: verificare che hover-tooltip mostra anno + timezone. Se manca → UX gap (ma è default Flarum, presumibile OK)
- **Discovered**: 2026-04-25

### [16.2.3] 🟡 Warning — Community forum ha signup separato (potenziale friction cross-account)

- **Fase**: 16 · **Area**: Community / cross-account identity
- **Deployment scope**: 🔐 community + 🔄 cross-repo
- **Tipo**: 🟡 Warning
- **Severity**: Medium (UX friction — customer deve gestire 4° account dopo SaaS signup + Portal OTP + app.sentrikat.com + community)
- **Actual**: bottoni `Sign Up` + `Log In` separati nella top-right del forum. Nessun visibile "Login with SentriKat account" o OAuth
- **Issue ipotizzato**: Flarum usa il proprio user DB, senza SSO con il `license-server` o il core app. Il customer:
  - Ha account A su `app.sentrikat.com` (signup SaaS)
  - Ha account B su `portal.sentrikat.com` (OTP)
  - Ha account C ipotetico su `community.sentrikat.com` (signup separato)
  → 3+ account per una singola identity. Se oltretutto portal OTP è rotto [04.1.3], almeno il community è raggiungibile con account suo
- **Fix candidato**: integrare Flarum con SAML/OIDC verso il license-server o core app — un utente, un login ovunque. Richiede plugin Flarum SSO
- **Follow-up TODO 16.2.3a**: verificare se Sign Up richiede email confirmation. Se sì + email cluster rotto [04.1.3] → community signup anche bloccato
- **Discovered**: 2026-04-25

### [16.2.4] 🔵 Info — "No support contract needed" messaging community-first

- **Fase**: 16 · **Area**: Community / messaging
- **Tipo**: 🔵 Info (positive brand tone)
- **Actual**: copy "Share knowledge, report bugs, ask questions, and connect with other SentriKat users. No support contract needed."
- **Valutazione**: messaggio trasparente, community-friendly. **No gating**: ognuno può aprire thread, non serve essere customer paying. Good brand posture
- **Discovered**: 2026-04-25

---

## Status fase 16

**Parzialmente coperta** (2 aree su 5):
- ✅ 16.1 docs.sentrikat.com: rendering + homepage + badge system OK. **1 High bug (metric KEV)** + 1 massive follow-up audit
- ✅ 16.2 community.sentrikat.com: rendering + base content OK. **1 warning (account friction)**
- ⬜ 16.3 n8n workflow — non accessibile pubblicamente, richiede admin access
- ⬜ 16.4 nginx reverse proxy — non testabile browser-only (test headers/CSP/rate limit)
- ⬜ 16.5 CI/CD pipeline — richiede admin access GitHub Actions
