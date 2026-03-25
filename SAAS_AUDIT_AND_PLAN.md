# SentriKat - Audit Completo & Piano SaaS

> Generato il 25 marzo 2026 - Audit di SentriKat (app) + SentriKat-web (landing, portal, license-server)

---

## EXECUTIVE SUMMARY

SentriKat e' un prodotto **tecnicamente maturo** e **vendibile** nella versione on-premise attuale.
Il 90% dell'infrastruttura SaaS e' gia' implementata. Per il lancio on-premise mancano solo fix di sicurezza minori e lo switch Stripe a live.

| Metrica | Valore |
|---------|--------|
| Linee di codice (app) | ~50,000+ |
| API endpoints | 186+ |
| Tabelle DB | 33 |
| Test functions | 1,278 |
| Versione | 1.0.0-beta.1 |
| SaaS readiness | ~90% (on-premise pronto) |

---

## PARTE 1: AUDIT SENTRIKAT (APP PRINCIPALE)

### Backend: 8.5/10
- 186+ endpoint ben strutturati in blueprint
- Sicurezza solida: password hashing, LDAP injection prevention, SSRF protection, rate limiting, encryption Fernet
- RBAC completo: super_admin > org_admin > manager > user (114+ route protections)
- 3 metodi auth: locale, LDAP/AD, SAML 2.0
- Multi-tenancy: isolamento per organization_id su tutte le tabelle
- No raw SQL, error handling safe

### Frontend: 6.8/10
- Dashboard ricca con CVE cards, severity filtering, statistiche
- Admin panel completo (5,107 righe HTML + 10,255 righe JS)
- Dark mode ben implementato
- Problema: file monolitici (admin_panel.js = 10K righe)
- No test frontend, accessibilita' parziale

### Infra/DevOps: 8/10
- Docker production-ready (non-root, health checks, CA custom)
- CI con Flake8 + pytest + Bandit + pip-audit
- Release automatizzata su GHCR + PyPI
- 7 tipi di log con rotazione

### Sicurezza: 8/10
- Session: HttpOnly, SameSite=Lax, Secure
- Flask-Talisman con HSTS e CSP
- Rate limiting (1000/day, 200/hour, login 5/min)
- Encryption at rest per credenziali

---

## PARTE 2: AUDIT SENTRIKAT-WEB

### Landing Page (Astro 4 + Tailwind): 9/10
- Design moderno dark theme, responsive, animazioni Framer Motion
- SEO eccellente (JSON-LD, Open Graph, sitemap, RSS)
- Legal pages complete (Privacy GDPR/nDSG, Terms, EULA, Impressum)
- NIS2 compliance page, competitor comparison
- **Gap**: solo "Request Demo", manca "Buy Now" su pricing

### Portal (Astro + React): 8/10
- Checkout Stripe funzionante (test mode)
- Dashboard licenze, download, attivazione
- Admin panel con 10+ pagine
- OTP authentication
- **Gap**: no invoice history, no usage dashboard

### License Server (FastAPI): 8.5/10
- RSA-4096 license signing
- Stripe webhook handler completo
- Activation codes con rate limiting
- Customer management con OTP
- **Gap**: no auto-renewal, rate limiting in-memory

### Infra: 8/10
- Docker Compose 13 servizi (landing, portal, API, docs, community, n8n, nginx, 2x DB)
- Nginx con rate limiting, CSP per-dominio, bot blocking, HSTS
- CI/CD GitHub Actions
- Content pipeline automatizzato

---

## PARTE 3: PROBLEMI CRITICI PER IL SAAS

### PROBLEMA 1: Super Admin vede TUTTI i dati dei clienti

Nel modello on-premise questo e' OK. Nel modello SaaS e' un **disastro legale**.

| Cosa puo' vedere il super_admin | File | Gravita' |
|-------------------------------|------|---------|
| Tutte le organizzazioni | routes.py:5516 | CRITICO |
| Tutti gli utenti di tutti i clienti | routes.py:5891 | CRITICO |
| Backup completo di TUTTI i dati | settings_api.py:1883 | CRITICO |
| Report compliance di TUTTE le org | reports_api.py:588,1073,1452 | CRITICO |
| Tutte le integrazioni Jira/webhook | integrations_api.py:1081 | ALTO |
| Tutti gli agenti di tutti i clienti | integrations_api.py:1582 | ALTO |
| Tutte le LDAP mappings | ldap_group_api.py:35 | MEDIO |
| Health checks cross-org | routes.py:161 | MEDIO |
| Log di sistema (tutti i clienti) | routes.py:310 | MEDIO |

**Pattern problematico** (reports_api.py:588-621):
```python
if user.role == 'super_admin' and org_id:
    org_filter = [org_id]
elif user.role == 'super_admin':
    org_filter = None  # <-- PERICOLOSO: nessun filtro = tutti i dati
```

### PROBLEMA 2: Org Admin NON e' autosufficiente

Per il SaaS, ogni cliente (org_admin) deve poter fare tutto da solo.

#### Funzionalita' BLOCCATE per org_admin (super_admin only):

**Configurazione:**
- LDAP/AD configuration (GET/POST /api/settings/ldap)
- SAML SSO configuration (GET/POST /api/settings/saml)
- General system settings
- Security settings (password policies, lockout)
- Branding/logo upload
- Notification webhook configuration
- Data retention settings

**Monitoring:**
- Health checks (GET /api/admin/health-checks)
- Application logs (GET /api/admin/logs)
- Audit logs (GET /api/audit-logs)
- Update checks

**Integrazioni:**
- Jira/YouTrack/GitHub/GitLab integration (tutte le CRUD)
- Test integration/webhook
- Import queue (approve/reject all)

**Gestione:**
- Backup & Restore
- License management
- Organization creation/deletion
- CVE sync trigger
- Product rematch/purge
- Scheduled reports (create/update/delete)

#### Funzionalita' GIA' disponibili per org_admin:

- User CRUD nella propria org
- Organization settings update (SMTP, webhook, alert rules)
- LDAP user search, invite, bulk invite
- LDAP group mapping management
- Product-to-org assignment
- View agent activity, scheduled reports page

### PROBLEMA 3: Impostazioni globali vs per-org

| Impostazione | Oggi | Per SaaS |
|-------------|------|----------|
| LDAP config | 1 server globale | Ogni org il suo |
| SAML config | 1 IdP globale | Ogni org il suo |
| SMTP | Globale + override per org | OK (gia' per-org) |
| Webhook | Per-org | OK |
| Branding/logo | Globale | Per-org |
| Password policy | Globale | Per-org o globale |
| Rate limiting | Per IP | Per org + per IP |
| Feature gating | 1 licenza globale | Per piano sottoscrizione |
| Storage | Flat, no separazione | Prefisso per org |
| Scheduler/sync | 1 job globale | OK (vuln data e' pubblica) |
| Log/audit | Nessun org_id | org_id in ogni entry |

---

## PARTE 4: ARCHITETTURA SCALABILE

### Modello On-Premise (ATTUALE)

```
TUA VPS Hetzner (budget)
  sentrikat.com ---- Landing page
  portal.sentrikat.com -- Portal (checkout, licenze)
  api.sentrikat.com ---- License server
  docs/community/n8n

          |
          | Cliente compra licenza PRO, scarica SentriKat
          v

SERVER DEL CLIENTE (loro infrastruttura)
  SentriKat + PostgreSQL + Nginx
  Il cliente gestisce tutto da solo
```

### Modello SaaS (FUTURO)

```
TUA VPS #1 Hetzner (budget, come oggi)
  sentrikat.com ---- Landing page
  portal.sentrikat.com -- Portal + billing
  api.sentrikat.com ---- License server

          |
          | Cliente si registra, paga, accede via browser
          v

TUA VPS #2 Hetzner (piu' potente)
  app.sentrikat.com <-- TUTTI i clienti SaaS qui

  SentriKat (1 istanza, multi-tenant)
    Org: "Acme Corp"    -> i loro prodotti/CVE
    Org: "Swiss Bank"   -> i loro prodotti/CVE
    Org: "Pharma AG"    -> i loro prodotti/CVE
    Ogni cliente vede SOLO i suoi dati

  PostgreSQL (1 database, dati isolati per org)
```

### Scaling Path

| Clienti | Setup | Costo/mese |
|---------|-------|-----------|
| 0-50 | VPS #1 (web) + VPS #2 (app+DB) | ~EUR 25 |
| 50-200 | + Managed PostgreSQL separato | ~EUR 80 |
| 200-1000 | + Load balancer + 2 app server | ~EUR 150 |
| 1000+ | Kubernetes su Hetzner Cloud | ~EUR 300+ |

### Provider EU-compliant consigliati

| Servizio | Provider | Datacenter | GDPR |
|----------|----------|------------|------|
| Hosting VPS | Hetzner | Germania | OK |
| Database managed | Hetzner | Germania | OK |
| DNS/CDN | Cloudflare | EU routing | OK |
| Email | Resend | EU region | OK |
| Pagamenti | Stripe | Svizzera/EU | OK |
| Monitoring | Uptime Kuma (self-hosted) | tuo server | OK |
| Backup | Hetzner Storage Box | Germania | OK |

---

## PARTE 5: COSA FARE PER LANCIARE ON-PREMISE

### Step 1: Security fix sentrikat-web (72 min) [COLLEGA]
Vedi sezione "Istruzioni per il collega" sotto.

### Step 2: Collegare "Buy Now" su landing -> checkout portal [COLLEGA]

### Step 3: Creare azienda + banca + Stripe live [TU]
- Einzelfirma o GmbH in Svizzera (~1 settimana)
- Conto business (Postfinance o neon business)
- Stripe live: cambiare API keys nel .env

### Step 4: Fix SaaS-critical su SentriKat app [OPZIONALE PER ON-PREMISE]
Questi fix sono necessari SOLO quando si passa al modello SaaS:
- Super admin data isolation
- Org admin self-service
- Per-org LDAP/SAML
- Per-org feature gating

---

## PARTE 6: LISTA COMPLETA MODIFICHE PER SAAS (FUTURO)

### Priorita' 1 - Data Isolation (CRITICO per SaaS)

1. **Rimuovere accesso cross-org per super_admin in modalita' SaaS**
   - reports_api.py: cambiare `org_filter = None` -> richiedere org_id esplicito
   - settings_api.py: backup/restore solo per org specifica
   - routes.py: user listing filtrato per org
   - integrations_api.py: integrazioni filtrate per org

2. **Aggiungere flag `SENTRIKAT_MODE=saas`** che:
   - Disabilita accesso cross-org per super_admin
   - Abilita feature gating per-subscription
   - Abilita provisioning automatico post-pagamento

### Priorita' 2 - Org Admin Self-Service (ALTO per SaaS)

3. **Spostare da @admin_required a @org_admin_required:**
   - LDAP configuration (con scope per org)
   - SAML SSO configuration (con scope per org)
   - Branding/logo (per org)
   - Integration management (Jira, ecc.)
   - Scheduled reports CRUD
   - Audit logs (filtrati per org)
   - Health checks (metriche per org)

4. **Creare versioni per-org di:**
   - SystemSettings -> OrgSettings per LDAP, SAML, password policy
   - Feature gating basato su SubscriptionPlan invece di licenza globale

### Priorita' 3 - Infrastruttura SaaS (MEDIO)

5. **Bridge license-server -> SentriKat provisioning**
   - Dopo pagamento Stripe: chiamata API a SentriKat per creare org+user+apikey
   - Usa provisioning.py gia' esistente

6. **Storage per-org**
   - Prefisso org_id su tutti gli upload
   - Quota storage per piano

7. **Logging per-org**
   - Aggiungere org_id a tutti i log audit
   - Filtro log per org nell'admin UI

8. **Rate limiting per-org**
   - Aggiungere org_id/user_id al rate limiter
   - Quota API calls per piano

### Priorita' 4 - Nice-to-have

9. Auto-renewal Stripe (recurring billing)
10. Self-service cancellation
11. Invoice history nel portal
12. Usage dashboard per tenant
13. Per-org data retention policies

---

## PARTE 7: ISTRUZIONI PER IL COLLEGA (SENTRIKAT-WEB)

### PRIORITA' 1 - Security Fix (URGENTE, ~72 min totali)

#### 1. Account lockout su login portal (15 min)
- **File**: `license-server/app/api/portal.py`
- Aggiungere protezione brute-force: dopo 5 tentativi falliti -> lockout 15 minuti
- Aggiungere campi `failed_login_attempts` e `locked_until` al model Customer se non esistono

#### 2. Fix email enumeration (5 min)
- **File**: `license-server/app/api/portal.py`
- L'endpoint OTP non deve rivelare se l'email esiste o no
- Rispondere SEMPRE 201 Created, anche se l'email non e' nel DB

#### 3. XSS nell'admin dashboard del portal (30 min)
- **File**: `portal/src/pages/admin/index.astro`
- Ci sono ~40 punti dove `innerHTML` viene usato con dati dinamici senza escape
- Aggiungere funzione escape e wrappare tutti i valori:
```javascript
const esc = s => s?.replace(/[&<>"']/g, c => ({
  '&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":"&#39;"
}[c])) ?? '';
```

#### 4. Pinnare versione Flarum (2 min)
- **File**: `docker-compose.yml`
- Cambiare `crazymax/flarum:latest` -> `crazymax/flarum:1.8.5`

#### 5. Rimuovere password di default MariaDB (5 min)
- **File**: `docker-compose.yml`
- Rimuovere valori default per `FLARUM_DB_PASSWORD` e `FLARUM_DB_ROOT_PASSWORD`
- Farli fallire se non settati in .env

#### 6. Disabilitare API docs in produzione (2 min)
- **File**: `license-server/app/main.py`
- Aggiungere: `docs_url=None, redoc_url=None` quando `DEBUG=false`

#### 7. Restringere MIME types forum upload (5 min)
- **File**: `community/setup.sh`
- Rimuovere `image/*` (troppo generico, include SVG malevoli) e `application/zip`
- Usare: `image/jpeg,image/png,image/gif,application/pdf`

#### 8. Minimizzare risposta root endpoint (2 min)
- **File**: `license-server/app/main.py`
- L'endpoint `/` deve restituire solo `{"status": "ok"}`

#### 9. Hardening health endpoint (5 min)
- L'endpoint `/health` non deve esporre dettagli interni
- Solo: `{"status": "healthy"}` o `{"status": "unhealthy"}`

### PRIORITA' 2 - Collegamento Landing -> Checkout

1. **Aggiungere bottone "Buy Now" / "Start Now" sulla pricing page della landing**
   - Piano PRO: link a `https://portal.sentrikat.com/checkout`
   - Piano Demo: link a `https://portal.sentrikat.com/login`

2. **Verificare flusso end-to-end:**
   - Landing -> Portal checkout -> Stripe -> Webhook -> License -> Email
   - Test con carta: `4242 4242 4242 4242`

### PRIORITA' 3 - Asset mancanti

1. **og-image.png** (1200x630px) in `landing/public/images/og-image.png`
2. **favicon PNG** (32x32, 16x16) + **apple-touch-icon.png** (180x180)
3. **Verificare link esterni**: docs, community, portal

### PRIORITA' 4 - Switch Stripe Live (quando azienda pronta)

1. Creare account Stripe live
2. Nel `.env`:
   - `STRIPE_SECRET_KEY` -> `sk_live_...`
   - `STRIPE_WEBHOOK_SECRET` -> secret live
3. Webhook URL in Stripe Dashboard: `https://api.sentrikat.com/api/v1/payments/webhook`
   - Evento: `checkout.session.completed`
4. Rimuovere banner "TEST MODE" dal portal
5. Test acquisto reale

---

## STRIPE IN SVIZZERA

Stripe funziona perfettamente in Svizzera (attivo dal 2013).

**Requisiti:**
- Societa' svizzera (Einzelfirma/GmbH/AG) + conto bancario svizzero
- Documenti: estratto RC, documento identita', IBAN
- Tempi attivazione: ~2-3 giorni dopo verifica

**Note fiscali:**
- Stripe NON gestisce IVA
- IVA svizzera: 8.1% (dal 2024)
- Reverse charge per clienti EU con VAT ID
- Consiglio: usa un tool come Stripe Tax o un commercialista

---

## NOTE FINALI

- **Pricing attuale**: 2 tier (Demo gratis + Pro EUR 2,499/anno) - on-premise
- **Il modello a 5 tier SaaS** (Free/Starter/Pro/Business/Enterprise) e' predisposto in models.py per il futuro
- **Per il lancio on-premise** servono solo: security fix + Buy Now button + Stripe live
- **Per il lancio SaaS** servono le modifiche elencate in Parte 6 (data isolation, org admin self-service, bridge provisioning)
