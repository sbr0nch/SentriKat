# SentriKat Pre-Launch Audit & Testing Plan

**Data**: 2026-04-09
**Ultimo aggiornamento**: 2026-04-14 (extended con Sprint 4 + Sprint 5)
**Target lancio**: 2026-04-10 (Early Access) — esteso con feature Sprint 4+5 prima del lancio GA
**Scope**: SentriKat (backend/core) + SentriKat-web (landing/portal/license-server)

---

## PARTE 1: ARCHITETTURA E CONNESSIONI TRA LE REPO

### Come si collegano le due repo

```
UTENTE (browser)
    |
    v
[sentrikat.com]  ──Landing Page (Astro, port 4321)──> Newsletter, Blog, Pricing, Trial Signup
    |                                                          |
    v                                                          v
[portal.sentrikat.com]  ──Customer Portal (Astro, port 4322)  |
    |                         |                                |
    v                         v                                v
[api.sentrikat.com]  ──License Server (FastAPI, port 8001)─────┘
    |                    |              |             |
    |                    v              v             v
    |              [Stripe API]   [Resend Email]  [PostgreSQL license DB]
    |
    |  ── POST /api/provision (X-Provision-Key) ──>
    v
[app.sentrikat.com]  ──SentriKat Core (Flask, port 5000)
    |                    |              |             |
    v                    v              v             v
[Agent API]        [PostgreSQL DB]  [Scheduler]   [LDAP/SAML]
```

### Flusso di collegamento chiave (Provisioning Bridge)

| License Server (SentriKat-web) | SentriKat Core (SentriKat) |
|---|---|
| `POST /api/v1/provision/trial` | `POST /api/provision` (provision_api.py) |
| `provision.py:provision_saas_tenant()` | Crea Organization + User + Subscription |
| `provision.py:upgrade_saas_tenant()` | `POST /api/provision/upgrade` |
| `provision.py:cancel_saas_tenant()` | `POST /api/provision/cancel` |
| `provision.py:get_saas_tenant_status()` | `GET /api/provision/status` |
| `ea_tenants.py:reset_tenant_password()` | `POST /api/provision/reset-password` |

**Autenticazione bridge**: Header `X-Provision-Key` con shared secret (`SENTRIKAT_PROVISION_KEY`), constant-time comparison (hmac.compare_digest)

### Log Integration (SaaS VM ↔ Web VM)

| Web VM (portal) | SaaS VM (app) |
|---|---|
| `GET /admin/logs` (admin UI) | `GET /internal/logs` (API, bearer token) |
| Fonti: audit_logs + activation_logs + saas_logs | Fonte: SaasLog model |
| Auth: ADMIN_API_KEY | Auth: INTERNAL_API_KEY + IP whitelist nginx |

---

## PARTE 2: VULNERABILITA DI SICUREZZA — STATO FINALE

### CRITICHE

| # | Problema | Repo | Stato |
|---|---------|------|-------|
| C1 | Cross-org data write in POST /api/products | SentriKat | **FIXATO** — validazione org_id contro user memberships |
| ~~C2~~ | ~~Cross-org data read in GET /api/assets~~ | SentriKat | **FALSO POSITIVO** — codice gia protetto |
| ~~C3~~ | ~~Missing auth su /api/settings/sync~~ | SentriKat | **FALSO POSITIVO** — ha @saas_admin_or_org_admin |
| C4 | Token revocation in-memory | SentriKat-web | **Accettabile per EA** — JWT 2h, rischio minimo |

### ALTE

| # | Problema | Repo | Stato |
|---|---------|------|-------|
| H1 | ENCRYPTION_KEY fallback silenzioso | SentriKat | **FIXATO** — raise ValueError in prod |
| H2 | ALLOW_PRIVATE_URLS bypass SSRF | SentriKat | **FIXATO** — return False in prod |
| H3 | ADMIN_API_KEY esposto a n8n | SentriKat-web | **FIXATO** — N8N_API_KEY separato |
| H4 | Turnstile fail-open | SentriKat-web | **FIXATO** — fail-closed su errore rete |
| H5 | Cross-org report data leak | SentriKat | **FIXATO** — many-to-many check + org validation |

### MEDIE

| # | Problema | Repo | Stato |
|---|---------|------|-------|
| ~~M1~~ | ~~Job lock in-memory~~ | SentriKat | **FIXATO** — JobState DB model |
| ~~M2~~ | ~~Retry state non persistito~~ | SentriKat | **FIXATO** — JobState DB model |
| ~~M3~~ | ~~Password reset token scadenza~~ | SentriKat | **FALSO POSITIVO** — SHA-256, 30min, single-use |
| ~~M4~~ | ~~Provision key timing attack~~ | SentriKat | **FIXATO** — hmac.compare_digest() |

### TROVATE IN AUDIT FINALE (sessione serale)

| # | Problema | Repo | Stato |
|---|---------|------|-------|
| F1 | ImportQueue cross-org enumeration | SentriKat | **FIXATO** — org scope obbligatorio per non-super-admin |
| F2 | Open redirect in SAML ACS (//attacker.com) | SentriKat | **FIXATO** — blocco URL protocol-relative |
| F3 | Setup endpoint senza rate limit | SentriKat | **FIXATO** — 3/min rate limit |
| F4 | Webhook URLs stored senza SSRF check | SentriKat | **Accettabile** — solo admin puo settare webhook |
| F5 | AgentApiKey list in on-prem senza org filter | SentriKat | **Accettabile** — non rilevante per SaaS launch |

### BASSE (non fixate, rischio accettabile)

| # | Problema | Note |
|---|---------|------|
| L1 | /api/version espone APP_VERSION pubblicamente | Info disclosure minimo |
| L2 | .env.example espone dettagli architettura | Roadmap per attacker |
| L3 | GITHUB_REPO=sbr0nch/SentriKat hardcoded | Rivela nome repo privato |

### RIEPILOGO FIX: 15 vulnerabilita analizzate, 12 fixate, 3 falsi positivi

---

## PARTE 3: CUSTOMER JOURNEY SAAS - PIANO DI TESTING

### Scenario A: Nuovo cliente - Signup Free/EA fino a uso completo

```
A1. Landing Page
  [ ] Aprire sentrikat.com
  [ ] Verificare Hero section (immagini, stats, CTA)
  [ ] Verificare sezione Features, How It Works, Pricing
  [ ] Verificare pricing tab Cloud vs On-Prem (prezzi barrati, "EUR 0 EA")
  [ ] Verificare EA banner (contatore posti: 30 cloud, 15 on-prem)
  [ ] Verificare tutte le pagine legali: /privacy, /terms, /eula, /dpa, /ea-terms, /impressum, /sla, /subprocessors
  [ ] Verificare /blog (12 articoli, featured post, sidebar, tags)
  [ ] Verificare /blog/rss.xml funziona
  [ ] Verificare pagine /vs/tenable, /vs/qualys, /vs/rapid7
  [ ] Verificare /features, /about, /contact, /security, /nis2
  [ ] Verificare 404 page su URL inesistente
  [ ] Verificare link social (LinkedIn, Twitter) esistono e funzionano
  [ ] Verificare OG image (/images/og-image.png) e meta tags
  [ ] Verificare newsletter subscribe nel footer

A2. Trial Signup (CRITICO)
  [ ] Compilare form Trial Signup (name, email, company, size)
  [ ] Accettare checkbox EA Terms + ToS + Privacy + DPA
  [ ] Verificare Turnstile anti-spam funziona
  [ ] Submit -> POST /api/v1/provision/trial con plan_name: "pro"
  [ ] Verificare chiamata al SaaS bridge: POST /api/provision
  [ ] Verificare creazione: Organization, User (org_admin), Subscription
  [ ] Verificare email di benvenuto con credenziali temporanee
  [ ] Verificare salvataggio EA tenant nel license server DB
  [ ] Verificare notifica admin (email a sales@sentrikat.com)
  [ ] Testare signup con email gia esistente -> errore 409 USER_EXISTS
  [ ] Testare rate limit (5/min) -> 429 dopo 5 tentativi
  [ ] Testare validazione campi (email invalida, nome vuoto)

A3. Primo Login SaaS
  [ ] Andare su app.sentrikat.com/login
  [ ] Login con credenziali temporanee dalla email
  [ ] Verificare force password change (must_change_password=true)
  [ ] Cambiare password
  [ ] Verificare dashboard carica correttamente
  [ ] Verificare sidebar menu mostra voci corrette per piano "pro"
  [ ] Verificare org name = company name dal signup

A4. Uso Base SentriKat
  [ ] Dashboard: widget vulnerabilita, KEV stats, risk score
  [ ] Verificare sync CISA KEV funziona (scheduler o manuale)
  [ ] Aggiungere prodotto manualmente
  [ ] Verificare CVE matching funziona
  [ ] Verificare dettaglio vulnerabilita (EPSS, KEV, severity)
  [ ] Export CSV/PDF funziona

A5. Agent Deployment
  [ ] Creare API key per agente (Admin > Agent Keys)
  [ ] Scaricare script agente Linux/macOS/Windows
  [ ] Verificare script contiene URL e API key corretti
  [ ] Eseguire agente su macchina di test
  [ ] Verificare heartbeat arriva (Agent Activity page)
  [ ] Verificare inventario software appare
  [ ] Verificare CVE matching automatico su software rilevato
  [ ] Verificare limiti agente (piano pro = 25 agenti max)

A6. Alert e Notifiche
  [ ] Configurare email alerts (Admin > Settings > Alerts)
  [ ] Verificare alert su CVE critica
  [ ] Verificare alert su ransomware
  [ ] Verificare alert scheduling (orari, giorni)
  [ ] Verificare rate limit email per piano (pro = 500/mese)

A7. Report e Compliance
  [ ] Generare report executive summary
  [ ] Generare report compliance (BOD 22-01)
  [ ] Creare scheduled report
  [ ] Verificare report arriva via email
  [ ] Verificare NIS2/DORA compliance features
```

### Scenario B: Upgrade/Downgrade Piano

```
B1. Cambio Piano via Portal
  [ ] Login su portal.sentrikat.com (OTP flow)
  [ ] Verificare lista licenze/sottoscrizioni
  [ ] Richiedere upgrade (upgrade-request endpoint)
  [ ] Verificare email notifica admin con link approvazione HMAC
  [ ] Admin clicca link approvazione
  [ ] Verificare piano aggiornato in SaaS via bridge /provision/upgrade
  [ ] Verificare feature gate cambiate (es. LDAP abilitato su Business)

B2. Stripe Checkout (post-EA, ma testare il flusso)
  [ ] POST /api/v1/payments/create-checkout con piano starter
  [ ] Verificare redirect a Stripe Checkout
  [ ] Completare pagamento (test mode)
  [ ] Verificare webhook checkout.session.completed ricevuto
  [ ] Verificare license creata
  [ ] Verificare SaaS tenant provisionato
  [ ] Verificare email benvenuto inviata

B3. Agent Upgrade
  [ ] POST /api/v1/payments/agent-upgrade/preview
  [ ] Verificare calcolo costo differenziale
  [ ] POST /api/v1/payments/agent-upgrade/checkout
  [ ] Verificare Stripe session creata
  [ ] Simulare webhook -> verificare max_agents aggiornato
```

### Scenario C: Cancellazione / Chiusura EA

```
C1. Cancellazione Subscription
  [ ] Admin sospende EA tenant -> POST /admin/ea-tenants/{id}/suspend
  [ ] Verificare SaaS bridge chiama /api/provision/cancel
  [ ] Verificare status tenant cambia a "suspended"
  [ ] Verificare utente non puo piu loggare (o accesso limitato)

C2. Riattivazione
  [ ] Admin riattiva tenant -> POST /admin/ea-tenants/{id}/reactivate
  [ ] Verificare SaaS bridge ri-provisiona
  [ ] Verificare accesso ripristinato

C3. Cancellazione via Stripe (post-EA)
  [ ] Simulare webhook subscription.deleted
  [ ] Verificare cancel_at_period_end=true mantiene accesso fino a fine periodo
  [ ] Verificare cancel_at_period_end=false -> downgrade immediato a free

C4. Account Deletion (GDPR)
  [ ] DELETE /portal/me dal customer portal
  [ ] Verificare licenze revocate (status=REVOKED, signed_data=null)
  [ ] Verificare attivazioni, log, codici cancellati
  [ ] Verificare record Customer cancellato dal DB
  [ ] Verificare email conferma cancellazione inviata
  [ ] Verificare notifica admin per clienti paganti
```

### Scenario D: Newsletter e Blog

```
D1. Newsletter Subscribe
  [ ] Inserire email nel form footer -> POST /api/v1/newsletter/subscribe
  [ ] Verificare subscriber salvato nel DB
  [ ] Verificare email di benvenuto ricevuta
  [ ] Verificare link unsubscribe nella email funziona
  [ ] Testare re-subscribe dopo unsubscribe
  [ ] Testare rate limit (5/min)
  [ ] Testare email duplicata -> "Already subscribed"

D2. Newsletter Admin Send
  [ ] GET /api/v1/newsletter/admin/subscribers (con admin key)
  [ ] POST /api/v1/newsletter/admin/send con subject + body HTML
  [ ] Verificare email ricevuta da tutti i subscriber attivi
  [ ] Verificare footer con unsubscribe link personalizzato per subscriber
  [ ] Verificare conteggio sent/failed

D3. Blog
  [ ] Verificare /blog lista tutti i 12 articoli
  [ ] Verificare singolo articolo si apre correttamente
  [ ] Verificare tags e categorie funzionano
  [ ] Verificare articolo italiano (gestione-vulnerabilita-pmi)
  [ ] Verificare /blog/rss.xml valido
```

### Scenario E: LDAP / SSO (piano Business/Enterprise)

```
E1. LDAP Setup
  [ ] Andare su Admin > Settings > LDAP
  [ ] Configurare: server, port, base DN, bind DN, password, TLS
  [ ] Verificare password LDAP criptata in DB (is_encrypted=True)
  [ ] Testare connessione LDAP
  [ ] Verificare ricerca utenti LDAP (/api/ldap/search)
  [ ] Invitare utente da LDAP (/api/ldap/invite)
  [ ] Bulk invite funziona
  [ ] Verificare LDAP sync automatico (scheduler ogni N ore)
  [ ] Verificare utenti auto-creati hanno permessi minimi

E2. SAML SSO (piano Professional+)
  [ ] Verificare feature gate @requires_professional('SAML SSO')
  [ ] Configurare SAML IdP settings
  [ ] Testare login SAML
  [ ] Verificare auto-provisioning utenti
  [ ] Verificare open redirect bloccato su RelayState (FIXATO F2)
```

### Scenario F: On-Premise Flow

```
F1. Demo Request
  [ ] Compilare form "Request Access" su landing page (sezione #demo)
  [ ] Verificare DemoRequest salvato nel DB license server
  [ ] Verificare email admin con link approvazione HMAC
  [ ] Admin clicca link -> licenza creata
  [ ] Verificare email al cliente con license key

F2. Installazione e Attivazione
  [ ] Cliente installa SentriKat via docker-compose
  [ ] Vai su Admin > License, copia Installation ID (SK-INST-xxx)
  [ ] Login su portal.sentrikat.com
  [ ] POST /portal/licenses/{id}/bind con installation_id
  [ ] Verificare firma RSA generata (signed_data)
  [ ] Download licenza -> GET /portal/licenses/{id}/download
  [ ] Inserire licenza in SentriKat (.env o Admin panel)
  [ ] Verificare licenza validata correttamente
  [ ] Verificare features sbloccate in base a edizione

F3. Rebind (migrazione server)
  [ ] POST /portal/licenses/{id}/bind con nuovo installation_id e rebind=true
  [ ] Verificare vecchio installation_id sostituito
  [ ] Scaricare nuova licenza firmata
```

### Scenario G: Scenari Edge / Errori

```
G1. Rate Limiting
  [ ] Verificare 5/min su login, trial signup, OTP
  [ ] Verificare 3/min su setup endpoint (FIXATO F3)
  [ ] Verificare 10/min su provisioning endpoints
  [ ] Verificare 60/min su API generali
  [ ] Verificare lockout account dopo 5 OTP falliti (30 min)

G2. Multi-Tenant Isolation (CRITICO)
  [ ] Creare 2 org separate in SaaS
  [ ] Org A prova a leggere prodotti Org B -> deve fallire
  [ ] Org A prova a leggere asset Org B -> deve fallire (verificato: gia protetto)
  [ ] Org A prova a creare prodotto in Org B -> deve fallire (FIXATO C1)
  [ ] Org A prova a leggere report Org B -> deve fallire (FIXATO H5)
  [ ] Org A prova a leggere import queue Org B -> deve fallire (FIXATO F1)
  [ ] Verificare ogni API filtra per organization_id

G3. Session & Auth
  [ ] Verificare session timeout (default 4h)
  [ ] Verificare session invalidata su cambio password
  [ ] Verificare cookie HttpOnly + Secure + SameSite=Lax
  [ ] Verificare CSRF exemption sulle API (corretto per JSON)

G4. Email Delivery
  [ ] Verificare Resend API key configurato
  [ ] Verificare dominio email verificato su Resend
  [ ] Testare suppression list (bounced email)
  [ ] Testare rate limit mensile per piano
  [ ] Verificare fallback SMTP per on-prem

G5. Error Handling
  [ ] Testare provision bridge down -> errore graceful, admin notificato
  [ ] Testare Stripe webhook con signature invalida -> 400
  [ ] Testare DB down -> error handling appropriato
  [ ] Testare invio email fallito -> non blocca operazione principale
```

---

## PARTE 4: TUTTI I FIX APPLICATI (12 totali)

### Repo SentriKat (backend/core) — 10 fix

| # | Fix | File | Commit |
|---|-----|------|--------|
| C1 | Cross-org product creation — validazione org_id | routes.py | `34a6ac0` |
| M4 | Timing attack provision key — hmac.compare_digest() | provision_api.py | `34a6ac0` |
| H1 | Encryption key fail-fast in prod — raise ValueError | encryption.py | `8e7dd90` |
| H2 | SSRF bypass in prod — return False forzato | network_security.py | `8e7dd90` |
| H5a | Executive summary cross-org — many-to-many check | reports_api.py | `8e7dd90` |
| H5b | Download report cross-org — match_ids validation | reports_api.py | `8e7dd90` |
| M1 | Job lock in-memory -> DB — JobState model | models.py, scheduler.py | `6940a5f` |
| M2 | Retry state in-memory -> DB — JobState model | scheduler.py | `6940a5f` |
| F1 | ImportQueue cross-org enumeration — org scope | integrations_api.py | `8e6a3bf` |
| F2 | Open redirect SAML ACS — block // URLs | saml_api.py | `8e6a3bf` |
| F3 | Setup endpoint rate limit — 3/min | auth.py | `8e6a3bf` |
| -- | Seed default plans per SQLite | __init__.py | `ffcc020` |
| -- | Endpoint POST /api/provision/reset-password | provision_api.py | `ffcc020` |

### Repo SentriKat-web (landing/portal/license-server) — 2 fix

| # | Fix | File |
|---|-----|------|
| H3 | n8n API key separato (N8N_API_KEY) | docker-compose.yml |
| H4 | Turnstile fail-closed su errore rete | contact.py |

### Falsi positivi (scartati dopo verifica)

| # | Problema | Motivo |
|---|---------|--------|
| C2 | Cross-org asset read | list_assets() filtra gia per org_memberships |
| C3 | Missing auth su /sync | Ha gia @saas_admin_or_org_admin |
| M3 | Password reset token | SHA-256, scadenza 30min, single-use |

---

## PARTE 5: CHECKLIST PRE-LANCIO FINALE

### Infrastruttura — VERIFICATO
- [x] DNS configurato: sentrikat.com, app.sentrikat.com, portal.sentrikat.com
- [x] SSL/TLS certificati validi (Cloudflare)
- [x] Nginx proxy routing corretto
- [x] PostgreSQL backup presente
- [x] Docker compose production funzionante
- [x] Health check endpoints rispondono (/api/health -> "healthy")
- [x] Monitoring infra-monitor.sh con Telegram alerts (cooldown 2h)

### Secrets & Config — VERIFICATO
- [x] SECRET_KEY generato e unico per ogni servizio
- [x] SENTRIKAT_PROVISION_KEY uguale tra license server e SaaS
- [x] ENCRYPTION_KEY configurato (generato e aggiunto al .env SaaS VM)
- [x] RESEND_API_KEY configurato
- [x] ADMIN_API_KEY configurato
- [x] ALLOW_PRIVATE_URLS non presente in .env (default=false)
- [x] INTERNAL_API_KEY configurato per log integration
- [x] TURNSTILE_SECRET_KEY configurato

### Assets Statici — VERIFICATO
- [x] /images/screenshots/dashboard.png esiste
- [x] /images/og-image.png esiste
- [x] Favicon varianti presenti
- [x] Logo SVG presente in /public/

### Database — VERIFICATO
- [x] Subscription plans seed eseguito ("Subscription plans synced with defaults")
- [x] EA capacity config: 30 cloud, 15 on-prem
- [x] Plans allineati tra license-server e SentriKat core
- [x] Migration 007 (trial_config) eseguita

### Sito Web — VERIFICATO
- [x] Nomi database rimossi dalle pagine pubbliche (NVD, CISA KEV, ecc.)
- [x] "24/7 support" rimosso ovunque
- [x] Support levels realistici (Email, Email 1bd, Email+Calls, Custom)
- [x] "Dedicated Infrastructure" -> "On-Premises Deployment"
- [x] SEO titles e descriptions su tutte le pagine
- [x] Pagina 404 creata
- [x] Homepage meta description aggiunta
- [x] Pricing feature table aggiornata (agent discovery, code deps, CVE dashboard)
- [x] Footer pulito (niente nomi database)

### Portal Admin — VERIFICATO
- [x] Customer Health dashboard
- [x] Support Tickets sistema
- [x] Canned Responses templates
- [x] Notification Center (campanella)
- [x] Centralized Logs (audit + activation + SaaS)
- [x] License management completo (trial upgrade, feature toggles, quick actions)
- [x] Audit log con filtri avanzati
- [x] Retention policy documentata (activation 90d, audit 365d)

### Legal
- [ ] Privacy Policy completa (verificare non sia placeholder)
- [ ] Terms of Service completi
- [ ] EA Terms completi
- [ ] DPA completo
- [ ] EULA completo
- [ ] Impressum con dati reali
- [ ] Cookie banner se necessario

---

## PARTE 6: POST-LANCIO (PRIMA SETTIMANA)

- [x] ~~Fixare H1-H5~~ — tutti fixati
- [x] ~~Migrare job locks da in-memory a database~~ — JobState model
- [x] ~~Persistere retry state in DB~~ — JobState model
- [ ] Aggiungere test automatici cross-org (`test_cross_org_access.py`)
- [ ] Aggiungere Alembic migrations per SentriKat core
- [ ] Setup CI/CD pipeline
- [ ] Penetration test esterno
- [ ] Monitorare email deliverability (bounce rate)
- [ ] Monitorare agent connections
- [ ] Raccogliere feedback EA users
- [ ] Token revocation persistente (C4 — migrare a PostgreSQL/Redis)
- [ ] SSRF check su webhook URLs stored in DB (F4)
- [ ] Completare workflow n8n (10-14) per notifiche Telegram
- [ ] Configurare backup automatico giornaliero (attuale e' manuale)

---

## PARTE 7: STATISTICHE SESSIONE (audit originario 2026-04-09)

- **Vulnerabilita analizzate**: 15
- **Fix applicati**: 12 (10 in SentriKat, 2 in SentriKat-web)
- **Falsi positivi scartati**: 3
- **Launch blockers risolti**: 2 (seed plans SQLite, endpoint reset-password)
- **Documenti creati**: 2 (audit plan, briefing web session)
- **Commit in questa repo**: 6

---

## PARTE 8: SPRINT 4 + SPRINT 5 VERIFICATION (aggiunto 2026-04-14)

Le Sprint 4 e 5 hanno introdotto 15 feature nuove. Questa parte del documento
cattura tutte le verifiche che vanno fatte **prima** del prossimo deploy in
produzione perche' queste feature toccano lo schema del DB, lo scheduler, il
middleware HTTP e il licensing.

### 8.1 Database migration (BLOCKER)

Le seguenti tabelle e colonne sono state aggiunte in Sprint 4 / 5 e **devono
essere materializzate sul DB di produzione** prima di fare deploy:

**Tabelle nuove:**
- `remediation_assignments` (Sprint 4)
- `sla_policies` (Sprint 4)
- `risk_exceptions` (Sprint 4)
- `product_aliases` (Sprint 4)
- `vulnerability_snapshots` (Sprint 5 — gia' usata dal job di snapshotting)

**Colonne nuove su tabelle esistenti:**
- `remediation_assignments.tracker_issue_key` (rinominata da `jira_issue_key` con
  backward compat — vedi `app/remediation_api.py`)
- `remediation_assignments.tracker_issue_url`
- `remediation_assignments.tracker_type`

**Indici compositi nuovi:**
- `idx_assign_org_status` su `remediation_assignments (organization_id, status)`
- `idx_assign_org_assignee` su `remediation_assignments (organization_id, assignee_user_id)`
- `idx_assign_org_due` su `remediation_assignments (organization_id, due_date)`
- `idx_riskexc_org_status` su `risk_exceptions (organization_id, status)`
- `idx_riskexc_org_expiry` su `risk_exceptions (organization_id, expires_at)`
- `uq_product_alias` unique constraint su `product_aliases (organization_id, alias_vendor, alias_product)`

**Strategia di migration:**

- [ ] **Opzione A (consigliata)**: scrivere una Alembic migration dedicata che
      crea le 5 tabelle nuove, aggiunge le 3 colonne su `remediation_assignments`
      (se stanno gia' esistendo con il nome vecchio `jira_issue_key`, fare ALTER
      TABLE RENAME) e crea i 5+1 indici.
- [ ] **Opzione B (tampone)**: far girare `db.create_all()` al primo avvio post
      deploy e fare ALTER TABLE manuali per la ridenominazione di
      `jira_issue_key`. Rischio piu' alto, documentare le query esatte.
- [ ] Backup completo del DB di produzione prima della migration.
- [ ] Rollback plan: script che rimuove i nuovi indici/tabelle in caso di errore.
- [ ] Test della migration su copia del DB di produzione prima di applicarla in
      prod.

### 8.2 Scheduler jobs nuovi (verifica post-deploy)

Verificare che i seguenti job siano registrati e attivi dopo il deploy:

- [ ] `patch_tuesday_digest` — cron `day=8-14, dow=wed, hour=9, minute=0`
      (Sprint 5). Test manuale: `POST /api/reports/patch-tuesday/trigger?dry_run=true`.
- [ ] `snapshot_vulnerabilities_daily` — giornaliero 02:00 UTC (Sprint 5).
      Verificare che scriva una riga su `vulnerability_snapshots` per ogni org.
- [ ] `app.scheduler.get_jobs()` su shell Flask mostra tutti e 16+ i job.

### 8.3 Sprint 4 hardening — verifica che sia tutto attivo

- [ ] **Email throttling** per notifiche remediation: max 1 email per
      assignment/ora, solo su `created` e `resolved`, solo all'assignee (no CC
      admin). Preserva il Resend free tier (100/day, 3000/month).
- [ ] **Zip bomb protection** sul middleware gzip: max 10MB decompressed /
      2MB compressed. Testare con payload malevolo → 413.
- [ ] **Rate limits**:
  - SBOM export: 10 req/ora
  - Remediation assignments: 60 req/minuto
  - Risk exceptions: 30 req/minuto
  - Product aliases: 30 req/minuto
- [ ] **Licensing gate** su SBOM: feature key `sbom_export` in
      `PROFESSIONAL_FEATURES`. Utente Free → 403 con messaggio di upgrade.
- [ ] **DB composite indexes** effettivamente creati (vedi 8.1).

### 8.4 Smoke test delle feature nuove (manuale, ~30 min)

Seguire la sequenza completa almeno una volta su un'istanza reale prima del
deploy in produzione:

- [ ] Login come admin di un org con dati di test.
- [ ] **Assignments**: creare, assegnare, cambiare status inline, aprire modal
      dettaglio, creare ticket Jira fittizio, verificare tracker_issue_url
      salvato.
- [ ] **SLA policies**: creare una policy, applicarla a una severity, verificare
      che due_date venga calcolata correttamente.
- [ ] **Risk exception**: creare con justification, verificare che il CVE
      "scompaia" dal dashboard attivo, verificare expiry warning.
- [ ] **Product alias**: creare un alias, verificare che il prodotto alias si
      risolva sul prodotto canonico.
- [ ] **SBOM export CycloneDX**: download, apertura JSON, validare su
      cyclonedx.org/tool-center/.
- [ ] **SBOM export SPDX**: download, validare.
- [ ] **SBOM export STIX 2.1**: download, validare su oasis-open.github.io/cti-stix-validator/.
- [ ] **Compliance report PCI-DSS**: JSON + PDF, verificare integrity block.
- [ ] **Compliance report ISO 27001**: JSON + PDF.
- [ ] **Compliance report SOC 2**: JSON + PDF.
- [ ] **Vulnerability trending widget**: visibile su dashboard, 3 toggle
      funzionanti.
- [ ] **Patch Tuesday trigger manuale**: `POST /api/reports/patch-tuesday/trigger?dry_run=true`.
- [ ] **Agent delta scan**: seconda esecuzione agent senza cambi invia
      `delta=unchanged`, gzip visibile nel tcpdump.
- [ ] **Agent store-and-forward**: stoppare server, correre agent 3 volte,
      riavviare server, verificare replay in ordine.

### 8.5 Test suite automatica

- [ ] `python3 -m pytest tests/ -q` → 1.024+ test pass, 0 fail.
- [ ] Tempo totale della suite < 5 minuti (se piu' alto indagare regressioni di
      performance nei test).
- [ ] Nessun `DeprecationWarning` nuovo rispetto alla baseline precedente.
- [ ] Coverage su `app/sbom_export.py`, `app/compliance_reports.py`,
      `app/remediation_api.py` ≥ 70%.

### 8.6 Telemetry / Prometheus

- [ ] `GET /metrics` contiene i counter nuovi:
  - `sentrikat_assignments{status="open|in_progress|resolved"}`
  - `sentrikat_assignments_overdue`
  - `sentrikat_assignments_with_tracker_ticket`
  - `sentrikat_risk_exceptions{status="active|revoked|expired"}`
  - `sentrikat_product_aliases_total`
- [ ] I valori riflettono lo stato reale del DB.

### 8.7 Web (sentrikat-web) coordinamento

Cose da chiedere al team SentriKat-web prima del deploy:

- [ ] Aggiungere SBOM, assignments, compliance reports e vulnerability trending
      alla feature list della landing page.
- [ ] Aggiornare la tabella comparativa vs Tenable/Qualys/Rapid7/Wiz.
- [ ] Aggiornare la pricing table con i nuovi prezzi (vedi
      `docs/business/22_PRICING_ANALYSIS_POST_SPRINT_5.md`) — solo se
      l'aumento viene approvato.
- [ ] Preparare 3 screenshot: trending dashboard, assignments page, compliance
      report PDF preview.

### 8.8 Go-live checklist (estratto minimo)

- [ ] DB backup completato e verificato.
- [ ] Alembic migration testata su copia del DB di produzione.
- [ ] Test suite al verde.
- [ ] Smoke test manuale delle feature Sprint 4+5 completato.
- [ ] Rollback plan documentato e testato.
- [ ] DNS / SSL verificati.
- [ ] Monitoring alert configurati per i job nuovi (patch_tuesday_digest,
      snapshot_vulnerabilities_daily).
- [ ] Email di comunicazione ai clienti EA pronta (feature nuove in changelog).

---

*Documento generato dalla sessione di audit del 2026-04-09*
*Esteso il 2026-04-14 con Sprint 4 + Sprint 5 verification*
*Branch: claude/fix-windows-agent-ping-d4xak*
