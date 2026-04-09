# SentriKat Pre-Launch Audit & Testing Plan

**Data**: 2026-04-09
**Target lancio**: 2026-04-10 (Early Access)
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
[Agent API]        [SQLite/PG DB]  [Scheduler]   [LDAP/SAML]
```

### Flusso di collegamento chiave (Provisioning Bridge)

| License Server (SentriKat-web) | SentriKat Core (SentriKat) |
|---|---|
| `POST /api/v1/provision/trial` | `POST /api/provision` (provision_api.py) |
| `provision.py:provision_saas_tenant()` | Crea Organization + User + Subscription |
| `provision.py:upgrade_saas_tenant()` | `POST /api/provision/upgrade` |
| `provision.py:cancel_saas_tenant()` | `POST /api/provision/cancel` |
| `provision.py:get_saas_tenant_status()` | `GET /api/provision/status` |

**Autenticazione bridge**: Header `X-Provision-Key` con shared secret (`SENTRIKAT_PROVISION_KEY`)

---

## PARTE 2: VULNERABILITA DI SICUREZZA TROVATE

### CRITICHE (da fixare PRIMA del lancio)

| # | Problema | Repo | File:Linea | Impatto | Stato |
|---|---------|------|-----------|---------|-------|
| C1 | **Cross-org data write in POST /api/products** | SentriKat | routes.py:1574 | Utente SaaS puo creare prodotti in org altrui inviando `organization_id` arbitrario nel JSON | **FIXATO** |
| ~~C2~~ | ~~Cross-org data read in GET /api/assets~~ | SentriKat | agent_api.py:2534 | ~~FALSO POSITIVO: il codice filtra correttamente per org_memberships~~ | N/A |
| ~~C3~~ | ~~Missing auth su /api/settings/sync~~ | SentriKat | settings_api.py:710 | ~~FALSO POSITIVO: ha gia @saas_admin_or_org_admin~~ | N/A |
| C4 | **Token revocation in-memory** | SentriKat-web | license-server/app/core/security.py | `_revoked_tokens: Set[str]` si perde al restart del server, token revocati tornano validi per max 2h | Accettabile per EA (JWT 2h) |

### ALTE (da fixare entro prima settimana)

| # | Problema | Repo | File | Impatto |
|---|---------|------|------|---------|
| H1 | ENCRYPTION_KEY fallback a SECRET_KEY senza errore in prod | SentriKat | encryption.py:39-51 | Crypto debole se ENCRYPTION_KEY non settato |
| H2 | ALLOW_PRIVATE_URLS=true in prod solo loga warning | SentriKat | network_security.py:22 | SSRF protection disabilitabile |
| H3 | ADMIN_API_KEY passato a container n8n | SentriKat-web | docker-compose.yml | Se n8n compromesso, attacker ha accesso admin API |
| H4 | Turnstile fail-open su errore rete | SentriKat-web | contact.py | Spam possibile bloccando richieste a Cloudflare |
| H5 | Cross-org report data su /api/reports endpoints | SentriKat | reports_api.py | Possibile leak dati report cross-tenant |

### MEDIE

| # | Problema | Repo | Note |
|---|---------|------|------|
| M1 | Job lock in-memory (non cross-process) | SentriKat | scheduler.py:87-98 |
| M2 | Retry state non persistito | SentriKat | scheduler.py:82-84 |
| M3 | Password reset token senza check scadenza esplicito | SentriKat | models.py |
| ~~M4~~ | ~~Provision key comparison non constant-time~~ | SentriKat | provision_api.py:52 — **FIXATO** |

### BASSE

| # | Problema | Note |
|---|---------|------|
| L1 | /api/version espone APP_VERSION pubblicamente | Info disclosure minimo |
| L2 | .env.example espone dettagli architettura | Roadmap per attacker |
| L3 | GITHUB_REPO=sbr0nch/SentriKat hardcoded | Rivela nome repo privato |

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
  [ ] Submit → POST /api/v1/provision/trial con plan_name: "pro"
  [ ] Verificare chiamata al SaaS bridge: POST /api/provision
  [ ] Verificare creazione: Organization, User (org_admin), Subscription
  [ ] Verificare email di benvenuto con credenziali temporanee
  [ ] Verificare salvataggio EA tenant nel license server DB
  [ ] Verificare notifica admin (email a sales@sentrikat.com)
  [ ] Testare signup con email gia esistente → errore 409 USER_EXISTS
  [ ] Testare rate limit (5/min) → 429 dopo 5 tentativi
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
  [ ] Simulare webhook → verificare max_agents aggiornato
```

### Scenario C: Cancellazione / Chiusura EA

```
C1. Cancellazione Subscription
  [ ] Admin sospende EA tenant → POST /admin/ea-tenants/{id}/suspend
  [ ] Verificare SaaS bridge chiama /api/provision/cancel
  [ ] Verificare status tenant cambia a "suspended"
  [ ] Verificare utente non puo piu loggare (o accesso limitato)

C2. Riattivazione
  [ ] Admin riattiva tenant → POST /admin/ea-tenants/{id}/reactivate
  [ ] Verificare SaaS bridge ri-provisiona
  [ ] Verificare accesso ripristinato

C3. Cancellazione via Stripe (post-EA)
  [ ] Simulare webhook subscription.deleted
  [ ] Verificare cancel_at_period_end=true mantiene accesso fino a fine periodo
  [ ] Verificare cancel_at_period_end=false → downgrade immediato a free

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
  [ ] Inserire email nel form footer → POST /api/v1/newsletter/subscribe
  [ ] Verificare subscriber salvato nel DB
  [ ] Verificare email di benvenuto ricevuta
  [ ] Verificare link unsubscribe nella email funziona
  [ ] Testare re-subscribe dopo unsubscribe
  [ ] Testare rate limit (5/min)
  [ ] Testare email duplicata → "Already subscribed"

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
```

### Scenario F: On-Premise Flow

```
F1. Demo Request
  [ ] Compilare form "Request Access" su landing page (sezione #demo)
  [ ] Verificare DemoRequest salvato nel DB license server
  [ ] Verificare email admin con link approvazione HMAC
  [ ] Admin clicca link → licenza creata
  [ ] Verificare email al cliente con license key

F2. Installazione e Attivazione
  [ ] Cliente installa SentriKat via docker-compose
  [ ] Vai su Admin > License, copia Installation ID (SK-INST-xxx)
  [ ] Login su portal.sentrikat.com
  [ ] POST /portal/licenses/{id}/bind con installation_id
  [ ] Verificare firma RSA generata (signed_data)
  [ ] Download licenza → GET /portal/licenses/{id}/download
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
  [ ] Verificare 10/min su provisioning endpoints
  [ ] Verificare 60/min su API generali
  [ ] Verificare lockout account dopo 5 OTP falliti (30 min)

G2. Multi-Tenant Isolation (CRITICO)
  [ ] Creare 2 org separate in SaaS
  [ ] Org A prova a leggere prodotti Org B → deve fallire
  [ ] Org A prova a leggere asset Org B → deve fallire (BUG C2!)
  [ ] Org A prova a creare prodotto in Org B → deve fallire (BUG C1!)
  [ ] Org A prova a leggere report Org B → deve fallire (BUG H5!)
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
  [ ] Testare provision bridge down → errore graceful, admin notificato
  [ ] Testare Stripe webhook con signature invalida → 400
  [ ] Testare DB down → error handling appropriato
  [ ] Testare invio email fallito → non blocca operazione principale
```

---

## PARTE 4: FIX APPLICATI

### Fix C1: Cross-org product creation (routes.py) -- APPLICATO
Aggiunta validazione in `POST /api/products` che verifica che `organization_id` dal JSON
appartenga alle org dell'utente corrente. Solo super_admin puo creare prodotti in org arbitrarie.

### ~~Fix C2~~: FALSO POSITIVO
Il codice in `agent_api.py:list_assets()` filtra gia correttamente per `org_memberships`.

### ~~Fix C3~~: FALSO POSITIVO
L'endpoint `/api/settings/sync` ha gia il decoratore `@saas_admin_or_org_admin`.

### Fix C4: Token revocation (license-server) -- ACCETTABILE PER EA
JWT ha scadenza 2h. La revocation in-memory e' sufficiente per EA launch.
Da migrare a PostgreSQL/Redis post-lancio.

### Fix M4: Constant-time comparison per provision key -- APPLICATO
Cambiato `provided_key != _PROVISION_KEY` in `hmac.compare_digest()` in `provision_api.py`
per prevenire timing attacks sulla chiave di provisioning.

---

## PARTE 5: CHECKLIST PRE-LANCIO FINALE

### Infrastruttura
- [ ] DNS configurato: sentrikat.com, app.sentrikat.com, portal.sentrikat.com, api.sentrikat.com, docs.sentrikat.com
- [ ] SSL/TLS certificati validi su tutti i domini
- [ ] Nginx proxy routing corretto (/api/ → license server)
- [ ] PostgreSQL (license DB) backup automatico
- [ ] SQLite/PostgreSQL (SentriKat core DB) backup automatico
- [ ] Docker compose production funzionante
- [ ] Health check endpoints rispondono (/api/health)
- [ ] Monitoring/alerting configurato

### Secrets & Config
- [ ] SECRET_KEY generato e unico per ogni servizio
- [ ] SENTRIKAT_PROVISION_KEY uguale tra license server e SaaS
- [ ] ENCRYPTION_KEY configurato (non usare fallback SECRET_KEY)
- [ ] RESEND_API_KEY configurato e dominio verificato
- [ ] ADMIN_API_KEY configurato
- [ ] ALLOW_PRIVATE_URLS=false in produzione
- [ ] Stripe keys (test mode per ora, switch a live quando pronti)
- [ ] TURNSTILE_SECRET_KEY configurato

### Assets Statici
- [ ] /images/screenshots/dashboard.png esiste
- [ ] /images/og-image.png esiste
- [ ] Favicon varianti presenti
- [ ] Logo SVG presente in /public/

### Profili Social / Link Esterni
- [ ] LinkedIn company page (linkedin.com/company/sentrikat)
- [ ] Twitter/X handle (@sentrikat)
- [ ] GitHub public profile
- [ ] Email funzionanti: sales@, support@, noreply@sentrikat.com

### Database
- [ ] Subscription plans seed (`seed_default_plans()` eseguito)
- [ ] EA capacity config corretto (30 cloud, 15 on-prem)
- [ ] Plans config allineato tra license-server e SentriKat core

### Legal
- [ ] Privacy Policy completa (non placeholder)
- [ ] Terms of Service completi
- [ ] EA Terms completi
- [ ] DPA completo
- [ ] EULA completo
- [ ] Impressum con dati reali
- [ ] Cookie banner se necessario

---

## PARTE 6: POST-LANCIO (PRIMA SETTIMANA)

- [ ] Fixare H1-H5 (vulnerabilita alte)
- [ ] Aggiungere test automatici cross-org (`test_cross_org_access.py`)
- [ ] Migrare job locks da in-memory a database
- [ ] Persistere retry state in DB
- [ ] Aggiungere Alembic migrations per SentriKat core
- [ ] Setup CI/CD pipeline
- [ ] Penetration test esterno
- [ ] Monitorare email deliverability (bounce rate)
- [ ] Monitorare agent connections
- [ ] Raccogliere feedback EA users

---

*Documento generato automaticamente dalla sessione di audit del 2026-04-09*
*Sessione: claude/recover-blocked-session-J4dQt*
