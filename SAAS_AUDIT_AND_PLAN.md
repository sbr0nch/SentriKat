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

## PARTE 4: ARCHITETTURA DUAL-MODE (ON-PREMISE + SAAS)

### Principio fondamentale

```
SENTRIKAT_MODE=onpremise (default)  ->  ZERO cambiamenti, tutto come oggi
SENTRIKAT_MODE=saas                 ->  Tenant isolation + org_admin self-service
```

Un singolo codebase, un singolo deploy. La modalita' e' controllata da
una variabile d'ambiente. Nessun fork, nessun branch separato.

### Modulo centrale: app/saas.py

Tutte le decisioni mode-dependent passano da qui:

```python
from app.saas import (
    is_saas_mode,              # True/False
    get_scoped_org_id,         # Forza org_id in SaaS
    requires_org_scope,        # Decorator: blocca senza org_id
    saas_admin_or_org_admin,   # Decorator: admin in on-prem, org_admin in SaaS
    restrict_cross_org_access, # Decorator: blocca cross-org in SaaS
    requires_feature,          # Decorator: licenza in on-prem, subscription in SaaS
    get_effective_features,    # Features da licenza o subscription
)
```

### Comportamento per ruolo e modalita'

| Azione | On-Premise super_admin | SaaS super_admin | SaaS org_admin |
|--------|----------------------|------------------|----------------|
| Vedere tutte le org | SI | NO (solo la sua) | NO |
| Configurare LDAP | SI (globale) | NO | SI (per la sua org) |
| Configurare SAML | SI (globale) | NO | SI (per la sua org) |
| Backup tutti i dati | SI | NO | NO |
| Backup propria org | SI | SI | SI |
| Gestire integrazioni | SI (tutte) | NO | SI (per la sua org) |
| Feature gating | Licenza RSA globale | N/A | Subscription plan |
| Vedere log | SI (tutti) | NO | SI (solo sua org) |

### Modello On-Premise (ATTUALE, INVARIATO)

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

---

## PARTE 8: SECURITY AUDIT DELLA VERSIONE SAAS

### Vulnerabilita' Corrette (Commit aef9866)

| # | Problema | Gravita' | File | Stato |
|---|----------|----------|------|-------|
| 1 | Secret SaaS hardcoded nel codice | CRITICO | saas.py | CORRETTO - ora legge da env var SENTRIKAT_SAAS_SECRET |
| 2 | API key permette override org_id | CRITICO | integrations_api.py | CORRETTO - locked to integration.organization_id |
| 3 | /api/cpe/coverage espone tutti gli org | CRITICO | cpe_api.py | CORRETTO - aggiunto SaaS org scoping |
| 4 | SBOM import permette override org_id | CRITICO | integrations_api.py | CORRETTO - locked to integration.organization_id |
| 5 | Org switch permesso in SaaS mode | MEDIO | routes.py | CORRETTO - bloccato in SaaS mode |

### Vulnerabilita' Corrette (Commit e0c89cd)

| # | Problema | Gravita' | File | Stato |
|---|----------|----------|------|-------|
| 6 | super_admin vede tutti gli utenti | CRITICO | routes.py | CORRETTO - SaaS scoping su /api/users |
| 7 | super_admin vede tutte le org | CRITICO | routes.py | CORRETTO - SaaS scoping su /api/organizations |
| 8 | reports senza org filter | CRITICO | reports_api.py | CORRETTO - 3 pattern org_filter fixati |
| 9 | LDAP/SAML solo per super_admin | ALTO | settings_api.py, saml_api.py | CORRETTO - @saas_admin_or_org_admin |
| 10 | Branding/Logo solo per super_admin | ALTO | settings_api.py | CORRETTO - @saas_admin_or_org_admin |
| 11 | Integrations senza cross-org check | ALTO | integrations_api.py | CORRETTO - @restrict_cross_org_access |
| 12 | Backup/restore non bloccato in SaaS | ALTO | settings_api.py | CORRETTO - ritorna 403 in SaaS mode |

### Vulnerabilita' Residue (da risolvere prima del lancio SaaS)

| # | Problema | Gravita' | File | Azione |
|---|----------|----------|------|--------|
| A | SystemSettings globali (non per-org) | ALTO | models.py, settings_api.py | Aggiungere organization_id a SystemSettings |
| B | LDAP config si sovrascrive tra org | ALTO | settings_api.py | Dipende da fix A |
| C | SMTP config condivisa tra org | MEDIO | email_alerts.py | Dipende da fix A |

**Nota**: I fix A-C richiedono una migration del database (aggiungere `organization_id` alla tabella `system_settings`).
Questo e' l'unico cambiamento strutturale necessario per il lancio SaaS.

### Come funziona la protezione SaaS Token

```
On-premise (.env):
  SENTRIKAT_MODE=onpremise    (o assente = default)
  → Nessun token necessario
  → Tutto funziona come prima

SaaS deployment (.env):
  SENTRIKAT_MODE=saas
  SENTRIKAT_SAAS_SECRET=<segreto-che-solo-noi-conosciamo>
  SENTRIKAT_SAAS_TOKEN=<sha256-del-segreto>
  → Token validato all'avvio
  → Se il token e' sbagliato, fallback a on-premise

I clienti on-premise NON conoscono SENTRIKAT_SAAS_SECRET,
quindi anche se settano SENTRIKAT_MODE=saas, il sistema
cade in on-premise mode. Impossibile attivare SaaS senza il secret.
```

---

## PARTE 9: COME METTERE IL SAAS ONLINE

### Architettura di Deployment

```
                        ┌─────────────────────────┐
                        │   Cloudflare (DNS + CDN) │
                        │   app.sentrikat.com      │
                        └────────────┬────────────┘
                                     │
                    ┌────────────────┼────────────────┐
                    │                │                 │
              ┌─────▼─────┐   ┌─────▼─────┐   ┌──────▼──────┐
              │  VPS #1   │   │  VPS #2   │   │  VPS #3     │
              │  WEB      │   │  SAAS APP │   │  (futuro)   │
              │  ~€10/mo  │   │  ~€15/mo  │   │  Scale-out  │
              ├───────────┤   ├───────────┤   └─────────────┘
              │ sentrikat │   │ sentrikat │
              │ -web      │   │ (Flask +  │
              │ (Astro +  │   │  Gunicorn │
              │  Portal)  │   │  + Nginx) │
              │ License   │   │           │
              │ Server    │   │ PostgreSQL│
              └───────────┘   │ 15        │
                              │ Redis     │
                              └───────────┘
```

### Step-by-Step Deployment

**1. Prepara VPS #2 (SaaS App) - Hetzner Cloud**
```bash
# Server: CPX21 (3 vCPU, 4GB RAM, 80GB SSD) ~€10/mo
# OS: Ubuntu 22.04 LTS
# Location: Falkenstein (Germania) = EU data residency

# Installa Docker
curl -fsSL https://get.docker.com | sh
apt install docker-compose-plugin

# Clona il repo
git clone git@github.com:sbr0nch/SentriKat.git /opt/sentrikat
cd /opt/sentrikat

# Crea .env per SaaS
cp .env.example .env
```

**2. Configura .env per SaaS**
```bash
# Genera secrets
SECRET_KEY=$(python3 -c "import secrets; print(secrets.token_hex(32))")
ENCRYPTION_KEY=$(python3 -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())")
SAAS_SECRET=$(python3 -c "import secrets; print(secrets.token_hex(32))")
SAAS_TOKEN=$(python3 -c "import hashlib; print(hashlib.sha256(b'${SAAS_SECRET}'.encode() if isinstance(b'${SAAS_SECRET}', bytes) else '${SAAS_SECRET}'.encode()).hexdigest())")

# In .env:
SENTRIKAT_MODE=saas
SENTRIKAT_SAAS_SECRET=${SAAS_SECRET}
SENTRIKAT_SAAS_TOKEN=${SAAS_TOKEN}
SENTRIKAT_ENV=production
SECRET_KEY=${SECRET_KEY}
ENCRYPTION_KEY=${ENCRYPTION_KEY}
DATABASE_URL=postgresql://sentrikat:STRONG_PASSWORD@db:5432/sentrikat
```

**3. Docker Compose per SaaS**
```bash
docker compose up -d
# Verifica che i log dicano "SaaS mode activated and validated."
docker compose logs app | grep "SaaS mode"
```

**4. Configura Nginx + SSL**
```bash
# Installa certbot
apt install certbot python3-certbot-nginx

# Ottieni certificato
certbot --nginx -d app.sentrikat.com

# Nginx proxy a Gunicorn
# La config gia' presente nel repo funziona
```

**5. Configura Cloudflare**
```
A record: app.sentrikat.com → IP VPS #2
Proxy: ON (arancione)
SSL: Full (strict)
```

**6. Collega Stripe Live**
```
- Switcha le API keys da test a live nel license-server
- Aggiorna i webhook endpoint a app.sentrikat.com
- Testa un pagamento con carta reale
```

### Flusso Cliente SaaS

```
1. Cliente visita sentrikat.com → vede landing page
2. Clicca "Start Free Trial" → Stripe Checkout
3. Stripe webhook → License Server crea account
4. License Server → POST /api/provision su VPS #2
   - Crea Organization
   - Crea User (org_admin)
   - Crea Subscription (trial 14 giorni)
5. Cliente riceve email con credenziali
6. Login su app.sentrikat.com → vede SOLO i suoi dati
7. Dopo 14 giorni: upgrade o downgrade a Free tier
```

### Scaling Path

| Fase | Trigger | Azione | Costo |
|------|---------|--------|-------|
| 1. Lancio | 0-50 clienti | VPS #2 single server | ~€15/mo |
| 2. Crescita | 50-200 clienti | Managed DB (Hetzner) + Redis separato | ~€40/mo |
| 3. Scale | 200-500 clienti | 2x app server + Load Balancer | ~€80/mo |
| 4. Enterprise | 500+ clienti | Kubernetes (Hetzner Cloud) | ~€150/mo+ |

---

## PARTE 10: GESTIONE AGENTS DEI CLIENTI SAAS

### Il Problema

Ogni cliente SaaS puo' avere 10-100+ agents (discovery agents) che:
- Inviano dati software periodicamente tramite API
- Consumano risorse (CPU, DB writes, network)
- Devono essere isolati per organizzazione
- Devono rispettare i limiti del piano

### Architettura Agent Management

```
                   Agents del Cliente A          Agents del Cliente B
                   (PDQ, SCCM, custom)           (Intune, custom)
                          │                              │
                          ▼                              ▼
                   ┌──────────────┐              ┌──────────────┐
                   │ API Key A    │              │ API Key B    │
                   │ org_id = 1   │              │ org_id = 2   │
                   └──────┬───────┘              └──────┬───────┘
                          │                              │
                          ▼                              ▼
                ┌─────────────────────────────────────────────┐
                │              Rate Limiter (per org)          │
                │     Free: 100 req/day    Pro: 10,000/day     │
                └─────────────────────┬───────────────────────┘
                                      │
                                      ▼
                ┌─────────────────────────────────────────────┐
                │         /api/import  +  /api/import/sbom     │
                │    (org_id locked to integration.org_id)     │
                └─────────────────────┬───────────────────────┘
                                      │
                                      ▼
                ┌─────────────────────────────────────────────┐
                │              Import Queue (per org)          │
                │     auto_approve o review manuale            │
                └─────────────────────────────────────────────┘
```

### Limiti per Piano

| Risorsa | Free | Starter | Professional | Business | Enterprise |
|---------|------|---------|-------------|----------|-----------|
| Agents | 2 | 10 | 50 | 200 | Illimitati |
| API calls/giorno | 100 | 1,000 | 10,000 | 50,000 | 100,000 |
| Products monitorati | 25 | 100 | 500 | 2,000 | Illimitati |
| Data retention | 30gg | 90gg | 1 anno | 2 anni | 5 anni |

### Come Gestirlo in Pratica

**1. Gia' implementato:**
- `AgentRegistration` model in `integrations_models.py` (tracking agents per org)
- `check_quota()` in `metering.py` (verifica limiti per piano)
- `Integration` model con `api_key` legata a `organization_id`
- Agent heartbeat tracking (`last_seen`, `agent_version`, `os_info`)

**2. Da aggiungere per il lancio:**
- Dashboard admin: overview agents per org (quanti attivi, ultimo heartbeat)
- Alert automatici: agent offline > 24h
- Rate limiting per-org sui import endpoints (gia' rate-limited globalmente, serve per-org)
- Cleanup automatico: agent non visti da > 90 giorni → disabilitati

**3. Per voi operatori (management):**
- Super admin su `app.sentrikat.com` puo' vedere TUTTE le org (on-premise mode su admin panel separato)
- Oppure: pannello admin dedicato (endpoint `/api/admin/...`) che bypassa il SaaS scoping
- Monitoraggio: Prometheus + Grafana su metriche agents (connections, data volume, errors)
- Alerting: PagerDuty/Telegram quando un org supera i limiti o un agent ha errori

### Script di Monitoraggio (da aggiungere)

```python
# Endpoint: GET /api/admin/agents/overview (super_admin only, platform mode)
# Ritorna:
{
  "total_agents": 347,
  "active_24h": 289,
  "by_organization": [
    {"org_id": 1, "org_name": "Acme Corp", "agents": 45, "active": 42, "plan": "business"},
    {"org_id": 2, "org_name": "Foo Inc", "agents": 12, "active": 10, "plan": "starter"}
  ],
  "alerts": [
    {"org_id": 3, "message": "5 agents offline > 24h", "severity": "warning"}
  ]
}
```

---

## RIEPILOGO STATO COMPLETAMENTO

### Fatto (commits su branch claude/code-audit-saas-plan-BUYDj):

- [x] Audit completo SentriKat + SentriKat-web
- [x] `app/saas.py` - Modulo centrale dual-mode con token validation
- [x] `tests/test_saas_mode.py` - 21 test tutti passano
- [x] `.env.example` - Documentazione variabili SaaS
- [x] `reports_api.py` - 3 fix cross-org data leakage
- [x] `settings_api.py` - 7 endpoint @saas_admin_or_org_admin + backup/restore block
- [x] `saml_api.py` - 2 endpoint @saas_admin_or_org_admin
- [x] `integrations_api.py` - Cross-org fix + API key org lock
- [x] `routes.py` - Org listing + user listing SaaS scoping + org switch block
- [x] `cpe_api.py` - Coverage dashboard SaaS scoping
- [x] Rimosso secret hardcoded dal codice sorgente
- [x] Security audit completato

### Da fare prima del lancio SaaS:

- [ ] Aggiungere `organization_id` a `SystemSettings` (migration DB)
- [ ] Rendere `get_setting()`/`set_setting()` org-aware in SaaS mode
- [ ] Rate limiting per-org sugli import endpoints
- [ ] Dashboard admin per overview agents
- [ ] Provisioning bridge: License Server → SaaS app
- [ ] Stripe live switch su sentrikat-web
- [ ] Test end-to-end con flusso completo (signup → trial → import → dashboard)
