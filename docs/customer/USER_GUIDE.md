# SentriKat — User Guide

> Comprehensive guide for SentriKat operators (admin), SaaS tenants, and end users.
> **Consolidated 2026-05-07** from 5 source files (HANDBOOK + ADMIN_GUIDE + SAAS_USER_GUIDE + STORAGE_GUIDE + WINDOWS_TEST_GUIDE) for navigability.

## Table of Contents

- [Part 1 — Product Handbook](#part-1--product-handbook) — what SentriKat does, architecture, tech stack
- [Part 2 — Administrator Guide](#part-2--administrator-guide) — setup, users, settings, integrations
- [Part 3 — SaaS Tenant Guide](#part-3--saas-tenant-guide) — SaaS-specific (login, billing, tenants)
- [Part 4 — Storage Reference](#part-4--storage-reference) — DB layout, retention, backup
- [Part 5 — Windows Testing Guide](#part-5--windows-testing-guide) — Windows agent install + verify

---

## Part 1 — Product Handbook

# SentriKat — Handbook Completo

> Tutto quello che devi sapere su SentriKat, dalla A alla Z.
> Ultimo aggiornamento: 28 Marzo 2026

---

## 1. COS'E' SENTRIKAT

SentriKat e' una piattaforma di **Vulnerability Management** enterprise. Monitora prodotti software, li confronta con il database NVD (National Vulnerability Database) e CISA KEV, e avvisa quando ci sono vulnerabilita' critiche.

### Cosa fa concretamente:
- **Inventario software**: tieni traccia di tutti i software nella tua organizzazione
- **Matching CVE**: confronta automaticamente il tuo inventario con le vulnerabilita' note
- **Alert**: notifiche email/webhook quando esce una CVE critica che ti riguarda
- **Compliance**: report di conformita' per audit (ISO 27001, NIS2, etc.)
- **Discovery agents**: agent che scansionano automaticamente i software installati
- **Multi-tenant**: ogni organizzazione vede solo i propri dati

### Stack tecnologico:
```
Backend:    Python 3.11 + Flask 3.1.3 + SQLAlchemy
Database:   PostgreSQL 15
Server:     Gunicorn (WSGI) + Nginx (reverse proxy)
Container:  Docker + Docker Compose
Frontend:   Jinja2 templates + JavaScript + Chart.js
Auth:       Session-based + LDAP/AD + SAML 2.0 + TOTP 2FA
```

---

## 2. ARCHITETTURA

### 2.1 Struttura del Codice (app/)

```
app/
├── __init__.py          — App factory (create_app), blueprint registration
├── models.py            — Tutti i modelli DB (33 tabelle)
├── routes.py            — Route principali (7000+ righe)
├── auth.py              — Autenticazione, decorators RBAC
├── saas.py              — Dual-mode system (on-premise vs SaaS)
├── provision_api.py     — API provisioning tenant SaaS
├── reports_api.py       — Report vulnerabilita' e compliance
├── settings_api.py      — Configurazione sistema (LDAP, SMTP, branding)
├── integrations_api.py  — Integrazioni esterne + agent import
├── cpe_api.py           — Ricerca CPE e matching NVD
├── saml_api.py          — SAML 2.0 SSO
├── licensing.py         — Sistema licenze RSA-4096 (on-premise)
├── metering.py          — Usage metering e quota check
├── email_alerts.py      — Sistema alert email
├── filters.py           — Matching vulnerabilita' → prodotti
├── nvd_cpe_api.py       — Client API NVD per ricerca CPE
├── cisa_sync.py         — Sync catalogo CISA KEV
├── encryption.py        — Encryption Fernet per settings sensibili
├── agent_api.py         — API per discovery agents
└── logging_config.py    — Configurazione logging multi-file
```

### 2.2 Modelli Database Principali

```
Organization          — Tenant (multi-org support)
User                  — Utenti con RBAC (super_admin/org_admin/manager/user)
UserOrganization      — Membership multi-org (M:N con ruolo per org)
Product               — Software monitorati (con CPE mapping)
Vulnerability         — CVE dal database NVD
VulnerabilityMatch    — Match tra Product e Vulnerability
SubscriptionPlan      — Piani SaaS (Free/Starter/Pro/Business/Enterprise)
Subscription          — Abbonamento attivo per organizzazione
Integration           — Configurazione integrazioni esterne
AgentRegistration     — Agent discovery registrati
ImportQueue           — Coda import software (review/auto-approve)
SystemSettings        — Configurazione sistema (key-value)
SyncLog               — Log sincronizzazioni NVD/CISA
AlertLog              — Storico alert inviati
```

### 2.3 RBAC (Role-Based Access Control)

```
super_admin   — Vede tutto (solo on-premise). In SaaS: scoped alla propria org
org_admin     — Gestisce la propria organizzazione (utenti, settings, prodotti)
manager       — Gestisce prodotti e vede report
user          — Solo lettura dashboard e vulnerabilita'
```

### 2.4 Dual-Mode (on-premise vs SaaS)

```
SENTRIKAT_MODE=onpremise (default)     SENTRIKAT_MODE=saas
├── super_admin vede TUTTO             ├── super_admin scoped a 1 org
├── Licenza RSA-4096                   ├── Subscription plan
├── Settings globali                   ├── Settings per-org (futuro)
├── Backup/restore abilitato           ├── Backup/restore disabilitato
├── Org switch permesso                ├── Org switch bloccato
└── Nessun provisioning                └── /api/provision automatico
```

Il tutto e' controllato da `app/saas.py` con 6 decorators:
- `is_saas_mode()` / `is_onpremise_mode()`
- `@requires_org_scope` — blocca senza org_id in SaaS
- `@saas_admin_or_org_admin` — admin in on-prem, org_admin in SaaS
- `@restrict_cross_org_access` — blocca accesso cross-tenant
- `@requires_feature(name)` — feature gating dual-mode
- `get_scoped_org_id(user)` — forza scope in SaaS

---

## 3. DUE REPOSITORY

### 3.1 SentriKat (github.com/sbr0nch/SentriKat)
L'applicazione principale. Contiene tutto il backend, il frontend, il database, il sistema di auth, il vulnerability matching, ecc. Deployato come Docker container.

**Usato per:**
- On-premise: installazione del cliente
- SaaS: istanza multi-tenant su app.sentrikat.com

### 3.2 SentriKat-web (github.com/sbr0nch/SentriKat-web)
Il sito web pubblico + infrastruttura di vendita. Contiene:

```
landing/          — Sito pubblico sentrikat.com (Astro 4 + Tailwind)
portal/           — Portale clienti portal.sentrikat.com (Astro + React)
license-server/   — Server licenze + pagamenti (FastAPI + Stripe)
docs/             — Documentazione docs.sentrikat.com (MkDocs)
community/        — Forum community.sentrikat.com (Flarum)
nginx/            — Reverse proxy per tutti i sottodomini
n8n/              — Workflow automation
```

### 3.3 Come Funzionano Insieme

```
FLUSSO CLIENTE ON-PREMISE:
sentrikat.com → "Buy Now" → Stripe → License Server → genera licenza RSA
→ Cliente scarica Docker → installa → attiva licenza

FLUSSO CLIENTE SAAS:
sentrikat.com → "Start Trial" → Stripe → License Server
→ Provisioning Bridge → POST /api/provision su app.sentrikat.com
→ Crea org + user + subscription → Email con credenziali
→ Cliente fa login su app.sentrikat.com
```

---

## 4. INFRASTRUTTURA

### 4.1 Stato Attuale

```
VPS #1 (Hetzner, Nuremberg)          VPS #2 (Hetzner, Nuremberg)
sentrikat-nurnb-1                     ubuntu-4gb-nbg1-3
├── sentrikat.com (landing)           ├── app.sentrikat.com (SaaS)
├── api.sentrikat.com (license)       ├── SentriKat Flask app
├── portal.sentrikat.com              ├── PostgreSQL 15
├── docs.sentrikat.com                ├── Nginx + Cloudflare SSL
├── community.sentrikat.com           └── Docker Compose
├── n8n.sentrikat.com
└── Nginx + Cloudflare SSL

           Cloudflare (DNS + CDN + SSL)
           ├── sentrikat.com → VPS #1
           ├── api.sentrikat.com → VPS #1
           ├── portal.sentrikat.com → VPS #1
           ├── docs.sentrikat.com → VPS #1
           └── app.sentrikat.com → VPS #2
```

### 4.2 Piano di Scalabilita'

| Fase | Clienti | Azione | Costo/mese |
|------|---------|--------|------------|
| **Lancio** | 0-50 | Tutto su VPS #2 (CPX22) | ~€10 |
| **Crescita** | 50-200 | Managed DB separato + upgrade VPS | ~€40 |
| **Scale** | 200-500 | 2x app server + Load Balancer Hetzner | ~€80 |
| **Enterprise** | 500+ | Kubernetes Hetzner Cloud + DB cluster | ~€200+ |

#### Quando scalare:

```
SEGNALI CHE DEVI SCALARE:
├── CPU costantemente > 70% → aggiungi workers Gunicorn o seconda VPS
├── RAM > 80% → upgrade VPS (CPX22 → CPX31 → CPX41)
├── DB query lente (> 500ms) → Managed DB separato (Hetzner)
├── Connessioni DB > 200 → Increase PG_MAX_CONNECTIONS + pool
└── Disco > 70% → Aggiungere volume Hetzner o S3 storage
```

#### Come scalare il database:

```
Fase 1 (ora):     PostgreSQL nel Docker (stessa VPS)
Fase 2 (50+ cli): Hetzner Managed Database (€15/mo, backup automatici)
                   Cambia DATABASE_URL nel .env → finito
Fase 3 (200+ cli): Read replica per report pesanti
Fase 4 (500+ cli): Database cluster con failover
```

#### Come scalare l'app:

```
Fase 1 (ora):     1 container, 4 Gunicorn workers
Fase 2:           Increase GUNICORN_WORKERS=8, GUNICORN_THREADS=8
Fase 3:           2 VPS con Hetzner Load Balancer (€5/mo)
                   Entrambe puntano allo stesso Managed DB
                   Session store su Redis (aggiungere al compose)
Fase 4:           Kubernetes con auto-scaling
```

---

## 5. ALERTING E MONITORAGGIO

### 5.1 Cosa Monitorare

| Metrica | Tool | Soglia Alert |
|---------|------|-------------|
| CPU/RAM/Disco | Hetzner Monitoring (gratis) | CPU >80%, RAM >85%, Disco >75% |
| Container status | Docker healthcheck (gia' attivo) | Container unhealthy |
| App response time | Uptime Kuma (self-hosted, gratis) | Response >2s o down |
| DB connections | PostgreSQL pg_stat | Connections >80% max |
| Error rate | Log file analysis | >10 errori/min |
| SSL expiry | Cloudflare (automatico) | Auto-renew |

### 5.2 Setup Raccomandato

**Fase 1 (ora, gratis):**
1. **Hetzner Monitoring** — gia' incluso, attiva gli alert per CPU/RAM/Disco
2. **Uptime Kuma** — container Docker per monitorare endpoint:
   ```bash
   docker run -d --name uptime-kuma -p 3001:3001 -v uptime-kuma:/app/data louislam/uptime-kuma
   ```
   Monitors: `https://app.sentrikat.com/api/health`

3. **Notifiche Telegram** — Uptime Kuma supporta Telegram, Slack, Discord, email

**Fase 2 (quando cresci):**
- Prometheus + Grafana per metriche dettagliate
- PagerDuty o Opsgenie per on-call rotation
- Sentry per error tracking applicativo

### 5.3 Health Check Endpoints

```
GET /api/health          → {"status": "healthy", "database": "ok"}
                            Gia' usato da Docker healthcheck e nginx
```

---

## 6. PRICING COMPLETO

### On-Premise (venduto tramite sito):
| Piano | Prezzo | Cosa include |
|-------|--------|-------------|
| Demo | Gratis | 1 user, 50 prodotti, no integrations |
| Professional | €4,999/anno | Illimitato, LDAP, SAML, integrazioni, white-label |

### SaaS (app.sentrikat.com):
| Piano | Prezzo | Agents | Users | Costo/agent/anno |
|-------|--------|--------|-------|-----------------|
| Free | €0 | 3 | 1 | - |
| Starter | €59/mo | 10 | 3 | €70.80 |
| Professional | €199/mo | 25 | 5 | €95.60 |
| Business | €499/mo | 50 | 10 | €119.76 |
| Enterprise | €999/mo | Illimitati | Illimitati | Custom |

### Confronto Mercato:
```
SentriKat Pro:    €95.60/agent/anno
Nucleus Security: €8-12/asset
Rapid7 InsightVM: €20-25/asset
Tenable.io:       €20-30/asset
Qualys VMDR:      €15-25/asset
```

---

## 7. PROVISIONING SAAS — COME FUNZIONA

### 7.1 Flusso Automatico (produzione)

```
1. Cliente visita sentrikat.com
2. Sceglie piano → click "Start Trial" / "Buy Now"
3. Stripe Checkout → pagamento
4. Stripe Webhook → License Server (VPS #1)
5. License Server chiama POST /api/provision (VPS #2)
   Headers: X-Provision-Key: <shared-secret>
   Body: {email, full_name, company_name, plan_name, stripe_customer_id}
6. SentriKat SaaS crea: Organization + User (org_admin) + Subscription
7. License Server invia email welcome con credenziali temporanee
8. Cliente fa login su app.sentrikat.com → cambia password → usa il prodotto
```

### 7.2 API Provisioning (4 endpoint)

```
POST /api/provision           — Crea tenant (org + user + subscription)
POST /api/provision/upgrade   — Cambia piano (accetta email o org_id)
POST /api/provision/cancel    — Cancella abbonamento
GET  /api/provision/status    — Controlla stato tenant (per email o org_id)
```

Tutti protetti da `X-Provision-Key` header + SaaS mode check.

### 7.3 Come Testare il Provisioning

```bash
# Crea tenant
curl -X POST https://app.sentrikat.com/api/provision \
  -H "X-Provision-Key: <key>" \
  -H "Content-Type: application/json" \
  -d '{"email":"test@test.com","full_name":"Test","company_name":"Test Corp","plan_name":"starter","trial_days":14}'

# Controlla stato
curl https://app.sentrikat.com/api/provision/status?email=test@test.com \
  -H "X-Provision-Key: <key>"

# Upgrade piano
curl -X POST https://app.sentrikat.com/api/provision/upgrade \
  -H "X-Provision-Key: <key>" \
  -H "Content-Type: application/json" \
  -d '{"email":"test@test.com","new_plan":"pro"}'

# Cancella
curl -X POST https://app.sentrikat.com/api/provision/cancel \
  -H "X-Provision-Key: <key>" \
  -H "Content-Type: application/json" \
  -d '{"email":"test@test.com"}'
```

---

## 8. GESTIONE AGENTS

### Cosa sono gli Agents
Software installati sui server/PC dei clienti che scansionano il software installato e lo inviano a SentriKat via API.

### Come funzionano:
```
Agent (sul PC del cliente) → POST /api/import con API key
                           → SentriKat riceve lista software
                           → Matching automatico con CVE
                           → Alert se ci sono vulnerabilita'
```

### Limiti per Piano:
```
Free:       3 agents
Starter:    10 agents
Pro:        25 agents
Business:   50 agents
Enterprise: illimitati
```

### Sicurezza:
- Ogni API key e' legata a 1 organizzazione
- In SaaS mode, l'org_id non puo' essere sovrascritto
- Rate limiting per-org sugli endpoint import

---

## 9. SICUREZZA

### 9.1 Protezioni Implementate
- Password hashing (Werkzeug/PBKDF2)
- CSRF protection (Flask-WTF)
- Rate limiting (Flask-Limiter)
- Encryption at rest (Fernet per settings sensibili)
- LDAP injection prevention
- SSRF protection
- SVG XSS validation
- Session timeout configurabile
- Account lockout dopo N tentativi falliti
- Force password change (must_change_password flag)
- TOTP 2FA support

### 9.2 Protezioni SaaS Specifiche
- SaaS token validation (HMAC-SHA256)
- Cross-tenant isolation su tutti gli endpoint
- API key locked to organization
- Org switch bloccato
- Backup/restore disabilitato
- Provisioning protetto da API key interna

### 9.3 Vulnerabilita' Corrette
12 vulnerabilita' trovate e corrette durante l'audit (vedi SAAS_AUDIT_AND_PLAN.md Parte 8).

---

## 10. OPERAZIONI QUOTIDIANE

### 10.1 Deploy di un aggiornamento

```bash
ssh root@91.99.19.164
cd /opt/sentrikat
git pull
docker compose up -d --build
docker compose logs -f sentrikat    # verifica che parta bene
```

### 10.2 Vedere i log

```bash
docker compose logs sentrikat              # log app
docker compose logs sentrikat-nginx        # log nginx
docker compose logs sentrikat-db           # log database
docker compose exec sentrikat cat /var/log/sentrikat/error.log    # errori
docker compose exec sentrikat cat /var/log/sentrikat/security.log # sicurezza
```

### 10.3 Creare un tenant manualmente

```bash
curl -X POST http://localhost/api/provision \
  -H "X-Provision-Key: <key>" \
  -H "Content-Type: application/json" \
  -d '{"email":"cliente@azienda.com","full_name":"Nome Cognome","company_name":"Azienda SRL","plan_name":"starter","trial_days":14}'
```

### 10.4 Backup database

```bash
docker compose exec sentrikat-db pg_dump -U sentrikat sentrikat > backup_$(date +%Y%m%d).sql
```

### 10.5 Restore database

```bash
docker compose exec -i sentrikat-db psql -U sentrikat sentrikat < backup_20260328.sql
```

### 10.6 Accesso diretto al database

```bash
docker compose exec sentrikat-db psql -U sentrikat sentrikat
# Poi SQL:
SELECT id, name, display_name FROM organizations;
SELECT id, username, email, role, organization_id FROM users;
SELECT s.id, o.name, p.name as plan FROM subscriptions s JOIN organizations o ON s.organization_id=o.id JOIN subscription_plans p ON s.plan_id=p.id;
```

### 10.7 Riavvio completo

```bash
cd /opt/sentrikat
docker compose down
docker compose up -d
```

---

## 11. VARIABILI DI AMBIENTE (.env)

### Obbligatorie:
```
SECRET_KEY              — Firma session cookies (generare random)
ENCRYPTION_KEY          — Encryption Fernet per settings DB
DATABASE_URL            — postgresql://user:pass@host:port/db
DB_PASSWORD             — Password PostgreSQL
```

### SaaS Mode:
```
SENTRIKAT_MODE          — onpremise (default) o saas
SENTRIKAT_SAAS_SECRET   — Secret per validazione token SaaS
SENTRIKAT_SAAS_TOKEN    — SHA-256 del secret (validazione all'avvio)
SENTRIKAT_PROVISION_KEY — API key per provisioning (shared con License Server)
SENTRIKAT_BASE_URL      — URL pubblica (per link nelle risposte API)
```

### Opzionali:
```
SENTRIKAT_ENV           — production o development
NVD_API_KEY             — API key NVD per sync vulnerabilita' (gratis, consigliata)
GUNICORN_WORKERS        — Numero workers (default: auto)
GUNICORN_THREADS        — Thread per worker (default: 4)
SMTP_HOST/PORT/USER/PASS — Per invio email alert
```

---

## 12. GLOSSARIO

| Termine | Significato |
|---------|-------------|
| CVE | Common Vulnerabilities and Exposures - ID univoco di una vulnerabilita' |
| CPE | Common Platform Enumeration - naming standard per software |
| KEV | Known Exploited Vulnerabilities - catalogo CISA delle CVE attivamente sfruttate |
| NVD | National Vulnerability Database - database USA di tutte le CVE |
| RBAC | Role-Based Access Control - sistema di permessi basato su ruoli |
| Tenant | Un'organizzazione cliente nel sistema SaaS multi-tenant |
| Provisioning | Creazione automatica di un nuovo tenant (org + user + subscription) |
| Agent | Software che scansiona un PC/server e invia l'inventario a SentriKat |
| SBOM | Software Bill of Materials - lista componenti software di un'app |


---

## Part 2 — Administrator Guide

# SentriKat Administration Guide

Operations reference for managing a SentriKat vulnerability management platform.

---

## 1. Quick Reference

### Default Credentials

| Item | Default | Notes |
|------|---------|-------|
| Admin login | `admin` / `admin` | Created during setup wizard; change immediately |
| PostgreSQL user | `sentrikat` | Password set via `DB_PASSWORD` in `.env` |
| Application port | `5000` (internal) | Not exposed externally; nginx proxies to it |

### Default URLs and Ports

| Endpoint | URL | Purpose |
|----------|-----|---------|
| Web UI | `http://localhost` (port 80) | Main interface |
| HTTPS | `https://localhost` (port 443) | When SSL is enabled |
| Health check | `GET /api/health` | Load balancer / uptime monitoring (no auth) |
| Metrics | `GET /metrics` | Prometheus-compatible metrics (optional auth via `SENTRIKAT_METRICS_KEY`) |
| GDPR export | `GET /api/gdpr/export` | Personal data export (authenticated user) |
| GDPR delete | `POST /api/gdpr/delete` | Account anonymization (authenticated user) |
| Sync status | `GET /api/sync/status` | CISA KEV / NVD sync status (auth required) |
| System health | `GET /api/system/health` | Detailed system health (auth required) |
| Health checks | `GET /api/admin/health-checks` | Background health check results (admin) |
| Security policy | `/.well-known/security.txt` | Responsible disclosure policy |
| Setup wizard | `/setup` | First-run configuration (disabled after setup) |

### Key Configuration Files

| File | Purpose |
|------|---------|
| `.env` | All environment variables (copy from `.env.example`) |
| `docker-compose.yml` | Container orchestration (PostgreSQL, app, nginx) |
| `docker-compose.storage.yml` | Optional: bind-mount override for custom storage paths |
| `config.py` | Application configuration (reads from environment) |
| `gunicorn.conf.py` | Web server tuning (workers, threads, timeouts) |
| `nginx/nginx.conf.template` | HTTP reverse proxy config |
| `nginx/nginx-ssl.conf.template` | HTTPS reverse proxy config |
| `certs/` | Directory for custom CA certificates (corporate PKI) |

---

## 2. Day-to-Day Operations

### Monitoring Health

**Quick health check** (no authentication required):
```bash
curl -s http://localhost/api/health | python3 -m json.tool
```
Returns `200` if healthy, `503` if database is unreachable.

**Background health checks** run every 30 minutes covering: database, disk space, worker pool, stuck jobs, CVE sync freshness, agent health, CPE coverage, license, SMTP, import queue, and API source status. View at **Settings > Health Checks**.

**Docker container health:**
```bash
docker compose ps                       # Container status
docker compose logs --tail=50 sentrikat # Application logs
docker compose logs --tail=50 db        # Database logs
docker compose logs --tail=50 nginx     # Nginx logs
```

### Checking Sync Status

SentriKat syncs vulnerability data from multiple sources on automatic schedules:

| Source | Schedule | Description |
|--------|----------|-------------|
| CISA KEV | Daily at `SYNC_HOUR:SYNC_MINUTE` (default 02:00 UTC) | Known exploited vulnerabilities |
| EPSS scores | After each CISA KEV sync | Exploit prediction scores |
| ENISA EUVD | Every 6 hours | European exploited CVE feed |
| NVD recent CVEs | Every 2 hours | HIGH/CRITICAL CVEs from NVD |
| Vendor advisories | 1 hour after CISA sync | OSV, Red Hat, MSRC, Debian |
| NVD CPE dictionary | Weekly (Sundays 04:00 UTC) | Product-to-CPE mapping data |
| CVSS re-enrichment | Every 4 hours | Upgrades fallback CVSS to NVD |
| KB sync | Every 12 hours | SentriKat knowledge base CPE mappings |

If the CISA KEV sync fails, automatic retries use exponential backoff: 15 min, 30 min, 1 hour, 2 hours (max 4 retries).

**Check sync status:** Settings > Sync Settings, or the Sync History page. Trigger manual sync from the UI or `POST /api/sync/trigger`.

### Managing Users and Organizations

- **Users:** Settings > User Management. Roles: `super_admin`, `org_admin`, `manager`, `user`.
- **Organizations:** Settings > Organizations. Each org has its own products, agents, alerts, and SMTP.
- Users can belong to multiple organizations with different roles per org.

### Reviewing Agent Status

View at **Agents > Agent Status**. Transitions: **online** -> **offline** (15 min no heartbeat) -> **stale** (14 days). Detection runs every 5 minutes.

---

## 3. Configuration

### Environment Variables (.env)

```bash
cp .env.example .env
python3 -c "import secrets; print(secrets.token_hex(32))"    # Generate SECRET_KEY
python3 -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"  # Generate ENCRYPTION_KEY
```

**Required:** `SECRET_KEY`, `ENCRYPTION_KEY` (auto-generated if unset), `DB_PASSWORD` (must match `DATABASE_URL`).

**Production:** `SERVER_NAME`, `SENTRIKAT_URL`, `SENTRIKAT_ENV=production`, `SESSION_COOKIE_SECURE=true`.

### Proxy Configuration

Set in `.env` for corporate networks:
```ini
HTTP_PROXY=http://proxy.corp.com:3128
HTTPS_PROXY=http://proxy.corp.com:3128
NO_PROXY=localhost,127.0.0.1,db,.yourcompany.com
```

For SSL-inspecting proxies, set `VERIFY_SSL=false` or add your corporate CA to `certs/`:
```bash
cp your-corporate-ca.crt certs/
docker compose restart sentrikat
```
The entrypoint script installs all `.crt` and `.pem` files from `certs/` into the system trust store.

### SSL/TLS Setup

1. Place certificate files in a directory (e.g., `/etc/ssl/sentrikat/`).
2. Update `.env`:
```ini
NGINX_TEMPLATE=nginx-ssl.conf.template
SSL_CERT_PATH=/etc/ssl/sentrikat
SSL_CERT_FILE=fullchain.pem
SSL_KEY_FILE=privkey.pem
SESSION_COOKIE_SECURE=true
FORCE_HTTPS=true
SENTRIKAT_URL=https://sentrikat.yourcompany.com
```
3. Restart: `docker compose up -d`

The SSL template enforces TLS 1.2+, modern cipher suites, HSTS, OCSP stapling, and security headers.

### LDAP/SAML SSO Configuration

**LDAP** is configured via the web UI at **Settings > LDAP / Active Directory**. Key settings:
- LDAP server, port, Base DN, Bind DN, Bind password
- Search filter (default: `(sAMAccountName={username})`)
- Username/email attribute mappings
- TLS toggle

Scheduled LDAP sync can be enabled with env vars:
```ini
LDAP_SYNC_ENABLED=true
LDAP_SYNC_INTERVAL_HOURS=24
```

**SAML 2.0 SSO** is configured at **Settings > SAML SSO**. SentriKat acts as the Service Provider (SP). Supply your IdP metadata (XML or URL) from Okta, Azure AD, ADFS, etc. Configure:
- SP entity ID, ACS URL, SLS URL
- Default organization for new SAML users
- Attribute-to-user-field mappings

### Email/SMTP Setup

Configure at **Settings > Email & Alerts** (global) or per-organization. Env var fallbacks: `SMTP_HOST`, `SMTP_PORT` (587), `SMTP_USERNAME`, `SMTP_PASSWORD`, `SMTP_USE_TLS` (true), `SMTP_FROM_EMAIL`, `SMTP_FROM_NAME`. Web UI settings take precedence.

### Timezone and Sync Schedule

Sync times use UTC. Set `SYNC_HOUR` and `SYNC_MINUTE` in `.env` (default: 02:00). Critical CVE reminder time is set in the web UI.

---

## 4. Agent Management

### Agent Deployment

Generate an API key at **Agents > API Keys**. Agent scripts are in the `agents/` directory.

**Linux:**
```bash
# Install as systemd service (runs every 4 hours, heartbeat every 5 minutes)
sudo ./sentrikat-agent-linux.sh --install \
  --server-url "https://sentrikat.yourcompany.com" \
  --api-key "sk_agent_xxxxxxxxxxxx"
```
Config: `/etc/sentrikat/agent.conf` | Log: `/var/log/sentrikat-agent.log`

**Windows (PowerShell 5.1+):**
```powershell
# Install as scheduled task
.\sentrikat-agent-windows.ps1 -Install `
  -ServerUrl "https://sentrikat.yourcompany.com" `
  -ApiKey "sk_agent_xxxxxxxxxxxx"

# Or install as Windows Service
.\sentrikat-agent-windows.ps1 -InstallService `
  -ServerUrl "https://sentrikat.yourcompany.com" `
  -ApiKey "sk_agent_xxxxxxxxxxxx"
```
Config: `%ProgramData%\SentriKat\config.json`

**macOS:**
```bash
sudo ./sentrikat-agent-macos.sh --install \
  --server-url "https://sentrikat.yourcompany.com" \
  --api-key "sk_agent_xxxxxxxxxxxx"
```

**Agent authentication:** Uses `X-Agent-Key` header. Rate limits: 60 inventory reports/min, 120 heartbeats/min per API key.

### Agent Updates (Push Updates)

SentriKat supports push-updating agents remotely. Mark assets for update in the web UI or via API; the agent picks up the pending update on its next heartbeat and self-updates.

### Agent Troubleshooting

- **Not reporting:** Verify server URL and API key. Check `/var/log/sentrikat-agent.log` (Linux) or Event Viewer (Windows).
- **Showing offline:** Check firewall rules for HTTPS. Heartbeat interval is 5 min; offline after 15 min.
- **Inventory backlog:** Check worker pool at Settings > Health Checks. Increase `WORKER_POOL_SIZE`.
- **Uninstall:** Linux: `--uninstall` flag. Windows: `-Uninstall` parameter.

### API Key Management

Create at **Agents > API Keys** (scoped per org). Keys support auto-approve for agent-discovered products. Rotate by creating a new key, deploying to agents, then revoking the old one.

#### API Key Types

Keys have a **Key Type** that indicates deployment target:

| Type | Description | Use Case |
|------|-------------|----------|
| **Server** | Deployed on infrastructure servers | Data center, cloud servers, CI/CD |
| **Client** | Deployed on end-user workstations | Laptops, desktops, developer machines |

The dashboard includes a **Server/Client toggle** to filter vulnerabilities by key type, so you can view server-side vs client-side exposure separately.

#### Scan Capabilities

Each API key controls what the agent is allowed to scan. These are **license-gated** features configurable per key:

| Capability | Default | Description |
|------------|---------|-------------|
| **OS Packages** | ON | Standard OS package scanning (dpkg, rpm, apk, etc.) |
| **Extensions** | OFF | Scans browser extensions (Chrome, Firefox, Edge) and IDE plugins (VS Code, JetBrains) |
| **Code Dependencies** | OFF | Scans project dependency files (requirements.txt, package-lock.json, go.sum, Gemfile, Cargo.toml, composer.json) |

When a capability is **disabled** on the API key, any data the agent sends for that category is silently rejected by the server. This ensures license compliance and prevents accidental data collection.

### Extension & Dependency Scanning

#### How It Works

1. **Create an API key** with the desired scan capabilities enabled (Settings > Agent Keys)
2. **Deploy the agent** — it automatically polls the server for its capabilities via `/api/agent/commands`
3. **The agent scans** based on what the server tells it:
   - **Extensions**: Scans VS Code, JetBrains, Chrome, Firefox, and Edge extensions/plugins across all user profiles
   - **Code Dependencies**: Searches for lock/requirements files in `/home`, `/opt`, `/srv`, `/var/www` (up to 5 levels deep)
4. **Results appear** in Inventory > Products, filterable by type

#### What Gets Scanned (Dependencies)

| Ecosystem | How it's detected | Files parsed |
|-----------|-------------------|--------------|
| **Python (PyPI)** | `pip3 freeze` + file search | `requirements.txt` |
| **Node.js (npm)** | `npm ls -g` + file search | `package-lock.json`, `package.json` |
| **Ruby (gem)** | `gem list --local` | Global gems |
| **Rust (cargo)** | `cargo install --list` | Global crates |
| **Go** | File search | `go.sum` |
| **PHP (composer)** | `composer global show` | Global packages |

**No extra tools need to be installed.** The agent uses whatever package managers are already present on the machine. Missing tools are silently skipped.

#### Security Notes

- Agent scripts **never execute unknown binaries** (Go scanning reads `go.sum` files, not binaries)
- Extension scanning **skips symlinks** to prevent path traversal
- Dependency data is validated against a **whitelist of known ecosystems** before storage
- The `is_direct` flag distinguishes direct dependencies from transitive ones

---

## 5. Backup & Restore

### Database Backup

**Using the included script:**
```bash
./scripts/backup_database.sh                     # Default: ./backups/
./scripts/backup_database.sh /mnt/backups        # Custom location
```
The script auto-compresses with gzip and cleans up backups older than 7 days.

**Manual Docker backup:**
```bash
docker compose exec -T db pg_dump -U sentrikat sentrikat > sentrikat_backup_$(date +%Y%m%d).sql
gzip sentrikat_backup_*.sql
```

### Volume Backup

```bash
# Application data volume (encryption keys, uploads, branding)
docker run --rm -v sentrikat_sentrikat_data:/data -v $(pwd):/backup \
  alpine tar czf /backup/sentrikat_data_$(date +%Y%m%d).tar.gz -C /data .
```

If using `STORAGE_ROOT`, back up that directory instead: `tar czf sentrikat_storage.tar.gz -C /data/sentrikat .`

### Restore Procedures

**Database restore:**
```bash
# Stop the application first to prevent writes
docker compose stop sentrikat
# Restore
gunzip < sentrikat_backup_20260101.sql.gz | \
  docker compose exec -T db psql -U sentrikat sentrikat
# Restart
docker compose start sentrikat
```

**Critical:** The `ENCRYPTION_KEY` must match the key used when the backup was created. If lost, encrypted settings (SMTP passwords, LDAP bind passwords) must be re-entered. The key is persisted at `${DATA_DIR}/.encryption_key`.

### Scheduled Backup Recommendations

Add to crontab on the Docker host:
```cron
# Daily database backup at 4 AM
0 4 * * * cd /opt/sentrikat && ./scripts/backup_database.sh /mnt/backups/sentrikat
```

---

## 6. Maintenance

### Log Management

**Log files** (default directory: `/var/log/sentrikat`, configurable via `LOG_DIR`):

| File | Content | Rotation |
|------|---------|----------|
| `application.log` | General application logs (INFO+) | 10 MB x 10 |
| `error.log` | Errors and critical issues | 10 MB x 10 |
| `access.log` | HTTP request logs | 20 MB x 10 |
| `security.log` | Auth and permission events | 10 MB x 20 |
| `audit.log` | Data modification audit trail (JSON) | 20 MB x 50 |
| `ldap.log` | LDAP operations | 10 MB x 10 |
| `performance.log` | Slow query/endpoint profiling (JSON) | 20 MB x 10 |

All logs use `RotatingFileHandler` with automatic rotation. Console output goes to Docker logs (`docker compose logs`).

**View logs in Docker:**
```bash
docker compose logs -f sentrikat          # Follow app logs
docker compose exec sentrikat tail -100 /var/log/sentrikat/error.log
docker compose exec sentrikat tail -100 /var/log/sentrikat/security.log
```

### Database Maintenance

PostgreSQL auto-vacuums by default. For large installations:
```bash
# Full vacuum (reclaims disk, requires exclusive lock -- schedule during downtime)
docker compose exec db vacuumdb -U sentrikat -d sentrikat --full --analyze

# Regular vacuum + analyze (online, no lock)
docker compose exec db vacuumdb -U sentrikat -d sentrikat --analyze
```

### Data Retention and Cleanup

Automated data retention runs daily at 03:00 UTC. Configure in **Settings > Administration**:
- `sync_history_retention_days` (default: 90)
- `audit_log_retention_days` (default: 365)

Maintenance tasks (run via Settings > Maintenance or the scheduler):
- Remove stale product installations (not reported for 30+ days)
- Mark assets stale after 14 days, remove after 90 days
- Clean orphaned agent-created products
- Auto-disable products not reported for 90+ days
- Auto-acknowledge CVEs for uninstalled or upgraded software
- Clean processed import queue items after 30 days

### Updating SentriKat

**Using the update script (recommended):**
```bash
./scripts/update.sh              # Update to latest version
./scripts/update.sh 1.0.3        # Update to specific version
./scripts/update.sh --check      # Check for updates only
```

The script auto-detects deployment type (Docker image, Docker build, or standalone), creates a pre-update backup, and handles the upgrade.

**Manual Docker update (build from source):**
```bash
git pull origin main
docker compose build
docker compose up -d
```

**Post-update:** Clear browser cache with Ctrl+Shift+R. Verify at Settings > License (shows version).

---

## 7. Performance Tuning

### Gunicorn Worker Configuration

Set in `.env`. Defaults auto-detect CPU count.

```ini
GUNICORN_WORKERS=8       # Default: min(CPU*2+1, 16)
GUNICORN_THREADS=4       # Threads per worker (default: 4)
GUNICORN_TIMEOUT=120     # Request timeout seconds
```

Workers auto-recycle after 2000 requests (with jitter) to prevent memory leaks.

### Database Connection Pooling

```ini
DB_POOL_SIZE=10          # Base connections per worker (default: 10)
DB_POOL_MAX_OVERFLOW=20  # Burst connections per worker (default: 20)
DB_POOL_TIMEOUT=30       # Seconds to wait for connection (default: 30)
DB_POOL_RECYCLE=1800     # Recycle connections every 30 min (default: 1800)
DB_STATEMENT_TIMEOUT=60000  # Max query time in ms (default: 60000)
```

**PostgreSQL tuning** (set in `.env`, applied to the `db` container):
```ini
PG_MAX_CONNECTIONS=300   # Must be >= WORKERS * (POOL_SIZE + MAX_OVERFLOW) + 10
PG_SHARED_BUFFERS=256MB  # 25% of total RAM, max 8 GB
PG_EFFECTIVE_CACHE=768MB # 75% of total RAM
PG_WORK_MEM=4MB          # Per sort/hash operation
```

### Background Worker Pool

Controls concurrent inventory job processing:
```ini
WORKER_POOL_SIZE=4       # Parallel job threads (default: 4)
```

### Recommended Hardware

| Deployment | Agents | CPU | RAM | Disk | Workers | Pool Size |
|------------|--------|-----|-----|------|---------|-----------|
| Small | < 100 | 2 cores | 4 GB | 20 GB | 4 | 2 |
| Medium | 100-1K | 4 cores | 8 GB | 50 GB | 8 | 4 |
| Large | 1K-5K | 8 cores | 16 GB | 100 GB | 12 | 8 |
| Enterprise | 5K-10K+ | 16 cores | 32 GB | 200 GB | 16 | 16 |

Rule of thumb: 1 CPU core per 2 Gunicorn workers, 256 MB RAM per worker.

---

## 8. Troubleshooting

### Common Issues

**Application won't start:**
- Check `SECRET_KEY` is set in `.env` (production mode requires it).
- Check `DB_PASSWORD` matches the password in `DATABASE_URL`.
- Run `docker compose logs sentrikat` for error details.

**"Setup wizard" keeps appearing:**
- At least one organization and one user must exist. The setup endpoint is at `/setup`.

**502 Bad Gateway from nginx:**
- The `sentrikat` container is still starting (allow 60s) or has crashed.
- Check: `docker compose ps` and `docker compose logs sentrikat`.

**Sync failures (CISA/NVD):**
- Check internet connectivity from the container: `docker compose exec sentrikat curl -I https://www.cisa.gov`
- If behind a proxy, verify `HTTP_PROXY`/`HTTPS_PROXY` in `.env`.
- For SSL inspection proxies, add your CA cert to `certs/` and restart.
- NVD API key recommended for 10x higher rate limit. Set at Settings > Sync Settings or `NVD_API_KEY` in `.env`.

**Slow performance / inventory backlog:**
- Check worker pool status at Settings > Health Checks.
- Increase `WORKER_POOL_SIZE` (default: 4) for more concurrent processing.
- Increase `GUNICORN_WORKERS` if the web UI feels slow.
- Check `performance.log` for slow endpoints.

### Checking Logs

```bash
docker compose exec sentrikat tail -50 /var/log/sentrikat/error.log      # Errors
docker compose exec sentrikat tail -50 /var/log/sentrikat/security.log   # Auth events
docker compose exec sentrikat tail -20 /var/log/sentrikat/audit.log      # Audit trail (JSON)
docker compose logs db --tail=50                                          # Database issues
```

### Agent Connectivity Issues

1. Verify agent can reach the server: `curl -k https://sentrikat.yourcompany.com/api/health`
2. Verify API key is valid and not revoked.
3. Check agent log: `/var/log/sentrikat-agent.log` (Linux), Event Viewer (Windows).
4. Check nginx access log: `docker compose logs nginx | grep agent`
5. If behind a proxy, ensure agents can reach the SentriKat URL directly or through the proxy.

### Database Issues

**Connection pool exhaustion** ("QueuePool limit" errors): increase `DB_POOL_SIZE`, `DB_POOL_MAX_OVERFLOW`, and `PG_MAX_CONNECTIONS`. Check active connections:
```bash
docker compose exec db psql -U sentrikat -c "SELECT count(*) FROM pg_stat_activity;"
```

**Stuck jobs:** Auto-recovered every 10 minutes (up to 5 retries). Check at Settings > Health Checks.

**Database size:** `docker compose exec db psql -U sentrikat -c "SELECT pg_size_pretty(pg_database_size('sentrikat'));"`
Run maintenance cleanup (Settings > Maintenance) to remove stale data.

---

## 9. Security Hardening

### SSL Configuration

Use `nginx-ssl.conf.template` in production. The template enforces:
- TLS 1.2 and 1.3 only
- Modern ECDHE cipher suites
- HSTS with `max-age=31536000` and `includeSubDomains`
- OCSP stapling
- Security headers: `X-Frame-Options`, `X-Content-Type-Options`, `X-XSS-Protection`, `Referrer-Policy`

### Session Security

Set `SESSION_COOKIE_SECURE=true` and `FORCE_HTTPS=true` in `.env` for production. Hardcoded defaults: `HTTPONLY=True`, `SAMESITE=Lax`, session lifetime 4 hours.

### Rate Limiting

**Application level** (Flask-Limiter): 1000 requests/day, 200 requests/hour per IP (default).

**Nginx level**: API endpoints limited to 10 requests/second per IP with burst of 20. Connection limit: 50 concurrent per IP.

**Agent API**: 60 inventory reports/minute, 120 heartbeats/minute per API key.

### Network Isolation

In Docker, only the `nginx` container exposes ports externally. The `sentrikat` app and `db` containers communicate over the internal Docker network. PostgreSQL is never exposed to the host.

For additional isolation, place SentriKat on a management VLAN and restrict agent traffic to HTTPS (port 443) only.

### API Key Rotation

1. Create a new agent API key in the web UI.
2. Deploy the new key to agents (update config files or push via management tools).
3. Verify agents are reporting with the new key (check agent status).
4. Revoke the old key.

Sensitive settings (LDAP bind password, SMTP password, webhook tokens) are encrypted at rest using the `ENCRYPTION_KEY`. If you rotate the encryption key, re-enter all encrypted settings.

---

## 9. SaaS Agent Connectivity Guide

This section is for **SaaS customers** (`app.sentrikat.com`) who need to connect agents from their on-premises network to the SentriKat cloud platform.

### How It Works

SentriKat agents run on your servers/endpoints and periodically send software inventory data to the SaaS platform over HTTPS. The communication is **outbound only** — agents initiate all connections. No inbound ports need to be opened.

```
Your Network                         Internet                    SentriKat Cloud
┌──────────────┐                                           ┌──────────────────┐
│ Your Server  │    HTTPS (port 443) outbound only         │ app.sentrikat.com│
│              │──────────────────────────────────────────►│                  │
│ SentriKat    │  POST /api/agent/inventory                │ Agent API        │
│ Agent        │  POST /api/agent/heartbeat                │ receives data    │
│              │  GET  /api/agent/jobs                     │                  │
│              │  Header: X-Agent-Key: sk_agent_xxx        │ Dashboard shows  │
└──────────────┘                                           │ vulnerabilities  │
                                                           └──────────────────┘
```

### Network Requirements

Your firewall/proxy must allow **outbound HTTPS** to the SentriKat platform:

| Destination | Port | Protocol | Required |
|-------------|------|----------|----------|
| `app.sentrikat.com` | 443 | HTTPS (TLS 1.2+) | **YES** |

**That's it.** No inbound ports, no VPN, no static IP required.

### What the Agent Sends

| Data | Frequency | Size |
|------|-----------|------|
| Software inventory (installed packages, versions) | Every 4-24 hours (configurable) | 50-200 KB |
| Heartbeat (agent status) | Every 5 minutes | < 1 KB |
| Job polling (check for tasks) | Every 60 seconds | < 1 KB |

The agent sends **only software inventory data** (package names, versions, OS info). It does **not** send files, credentials, user data, network topology, or any other sensitive information.

### Setup Steps

1. **Create an Agent Key** in the SentriKat web UI: Settings > Integrations > Agent Keys > Create API Key
2. **Download the agent** script from the Agent Keys page
3. **Install the agent** on your server:
   ```bash
   # Linux
   curl -sSL https://app.sentrikat.com/agent/install.sh | bash -s -- --key YOUR_AGENT_KEY

   # Windows (PowerShell as Administrator)
   iwr -Uri https://app.sentrikat.com/agent/install.ps1 -OutFile install.ps1; .\install.ps1 -Key YOUR_AGENT_KEY
   ```
4. **Verify** the agent appears in the SentriKat dashboard within a few minutes

### Firewall / Proxy Configuration

If your network uses a web proxy:

```bash
# Set proxy for the agent
export HTTPS_PROXY=http://proxy.yourcompany.com:8080
export NO_PROXY=localhost,127.0.0.1
```

If your firewall requires domain allowlisting, add:
- `app.sentrikat.com` (port 443)

If your firewall requires IP allowlisting, resolve `app.sentrikat.com` to get the current IP. Note: the IP may change; domain-based rules are preferred.

### Verifying Connectivity

Test from the server where the agent will run:

```bash
# Quick connectivity test
curl -s https://app.sentrikat.com/api/health
# Should return: {"status": "ok"}

# Full agent simulation
curl -s -H "X-Agent-Key: YOUR_KEY" https://app.sentrikat.com/api/agent/heartbeat -X POST
# Should return: 200 OK
```

### Troubleshooting

| Issue | Check |
|-------|-------|
| Agent can't connect | `curl -v https://app.sentrikat.com/api/health` — check for TLS or proxy errors |
| Firewall blocking | Ensure outbound 443 is allowed to `app.sentrikat.com` |
| Corporate proxy | Set `HTTPS_PROXY` environment variable for the agent process |
| SSL inspection | If your firewall does SSL inspection, add the corporate CA to the agent's trust store |
| Agent not appearing | Check agent logs; verify the API key is correct and active |

---

## 10. Sprint 4 + Sprint 5 Features (Remediation, SBOM, Compliance, Trending)

This section covers the admin-facing aspects of the features shipped in
Sprint 4 and Sprint 5. The full API reference is in `docs/API.md`.

### 10.1 Remediation Assignments & SLA Policies

**Where:** the **Assignments** page in the admin UI.

**What admins do:**
- Create and assign remediation tasks to users with a due date.
- Define **SLA policies** that automatically compute `due_date` for new
  assignments based on `(severity, asset_type)`.
- Monitor SLA compliance from the dashboard widget (uses
  `/api/sla/compliance`).
- Bulk update statuses inline from the table.

**Issue tracker integration:** when an assignment is linked to a Jira /
GitHub / GitLab / YouTrack issue, store the key in `tracker_issue_key`,
the URL in `tracker_issue_url`, and the type in `tracker_type`. Both the
old field name (`jira_issue_key`) and the new one are accepted by the API.

**Email notifications:** transactional emails are sent only on `created`
and `resolved`, only to the assignee, and are throttled to **max 1 email
per assignment per hour**. This is by design to preserve the Resend free
tier (100/day, 3000/month). If you need a higher cadence, configure a
paid Resend plan and adjust the throttle in `app/email_service.py`.

**Rate limits:** assignments 60 req/min, SLA policies 30 req/min.

**Database indexes (Sprint 4):**
- `idx_assign_org_status` on `remediation_assignments(organization_id, status)`
- `idx_assign_org_assignee` on `remediation_assignments(organization_id, assignee_user_id)`
- `idx_assign_org_due` on `remediation_assignments(organization_id, due_date)`

If you upgrade from a pre-Sprint-4 deployment, you must add these indexes
manually or via Alembic migration before deploying — see
`docs/PRE_LAUNCH_AUDIT_AND_TESTING_PLAN.md` Part 8 for details.

### 10.2 Risk Exception Management

**Where:** the **Risk Exceptions** panel (shield icon in the dashboard
header) or the API directly (`/api/risk-exceptions`).

**What admins do:**
- Accept the risk on a vulnerability with a mandatory `justification`.
- Optionally set an `expires_at` date — without it, the exception is
  permanent.
- Revoke or extend exceptions at any time.
- Use exceptions as **audit evidence** for ISO 27001 and SOC 2 controls
  (the compliance reports in section 10.4 reference active exceptions
  in the `evidence` block).

**Behavior:** an active exception removes the affected
`VulnerabilityMatch` from the active dashboard but keeps it visible in
the exceptions panel. Expired exceptions auto-flag with `is_expired:
true` and stop suppressing the match.

**Database indexes (Sprint 4):**
- `idx_riskexc_org_status` on `risk_exceptions(organization_id, status)`
- `idx_riskexc_org_expiry` on `risk_exceptions(organization_id, expires_at)`

### 10.3 SBOM Export (CycloneDX / SPDX / STIX 2.1)

**Where:** Dashboard → Export dropdown → SBOM section. Or directly:
- `GET /api/sbom/export/cyclonedx`
- `GET /api/sbom/export/spdx`
- `GET /api/sbom/export/stix21` (Sprint 5)

**Licensing:** SBOM export is gated by the `sbom_export` feature key in
`PROFESSIONAL_FEATURES`. Free users get HTTP 403 with an upgrade message.

**Rate limit:** 10 requests/hour per organization.

**When to use which format:**
- **CycloneDX 1.5** — most widely supported, recommended for CRA / EO
  14028 compliance and supply-chain tooling integration.
- **SPDX 2.3** — Linux Foundation standard, often required by open-source
  audits.
- **STIX 2.1** — for sharing into MISP / ISAC threat intel platforms.

**Validation:** the bundles validate against
`https://cyclonedx.github.io/cyclonedx.org/tool-center/` and
`https://oasis-open.github.io/cti-stix-validator/`.

### 10.4 Compliance Gap Analysis Reports (PCI / ISO / SOC 2)

**Where:** Dashboard → Reports dropdown → Compliance section. Or directly
via API:
- `GET /api/reports/compliance/pci-dss[?format=json|pdf]`
- `GET /api/reports/compliance/iso-27001[?format=json|pdf]`
- `GET /api/reports/compliance/soc2[?format=json|pdf]`

**What you get:** for each framework, a JSON or PDF report mapping the
relevant controls to your current posture with status `PASS`, `PARTIAL`,
`FAIL`, or `NOT_APPLICABLE`. Each requirement has `evidence`, `gaps`,
and `recommendations` blocks.

**Integrity:** every report carries an `integrity` block with HMAC-SHA256
over the canonical JSON body. Auditors can independently verify the
report has not been tampered with after generation.

**Mapped controls:**
- **PCI-DSS v4.0:** Requirements 6.3 (secure software) and 11.3
  (vulnerability management).
- **ISO/IEC 27001:2022:** Annex A.8.8 (technical vulnerabilities), A.8.16
  (monitoring activities), A.5.24 (incident management planning).
- **SOC 2:** CC7.1, CC7.2, CC7.4 (system monitoring) and CC6.6
  (vulnerability management).

**Licensing:** included in Professional and above. May be packaged as the
**Compliance Pack** add-on for Starter/Pro tiers — see
`docs/business/22_PRICING_ANALYSIS_POST_SPRINT_5.md`.

### 10.5 Vulnerability Trending Dashboard

**Where:** the main dashboard, "Vulnerability Trends" widget (Chart.js).

**Three views:**
- **Total** — total open vulnerabilities over time
- **By severity** — stacked area chart with critical/high/medium/low bands
- **Open vs resolved** — comparison of acknowledged/resolved vs still open

**Data source:** the `vulnerability_snapshots` table, populated daily at
02:00 UTC by the `snapshot_vulnerabilities_daily` scheduler job. Use
`POST /api/vulnerabilities/trends/snapshot` to force a snapshot manually
(admin only) — useful for demos or after a manual cleanup.

**Empty state:** fresh organisations show "No trend data yet — first
snapshot will be captured at 02:00 UTC".

### 10.6 Patch Tuesday Digest Automation

**Schedule:** every 2nd Wednesday of the month at **09:00** local time
(scheduler cron `day=8-14, dow=wed, hour=9, minute=0`).

**What it sends:** an email digest to each organization's admin(s) listing
the MSRC Patch Tuesday CVEs published since the previous run that match
products installed on the org's fleet. Subject line: *"SentriKat Patch
Tuesday Digest — &lt;Month Year&gt;"*.

**Manual trigger:** `POST /api/reports/patch-tuesday/trigger?dry_run=true`

The `dry_run=true` mode is the default and returns what *would* be sent
without actually sending the email. With `dry_run=false` (admin only) the
email is delivered live.

**Skipped reasons:** the digest is skipped for a given org with a clear
log entry when:
- No new matching CVEs since the previous run (`no_new_cves`)
- Email quota exhausted on the email provider (`quota_exhausted`)

**Note on field names:** the job uses `Vulnerability.date_added`. Do not
introduce code paths that reference `published_date` — that field does
**not** exist on the `Vulnerability` model.

### 10.7 Agent Resilience (Sprint 4)

**Delta scan:** the agent computes a SHA256 hash of its inventory and
sends only a lightweight heartbeat when nothing changes. Forced full
inventory every 24h. Hash file location:
- Linux: `/var/lib/sentrikat/last_hash.txt`
- macOS: `/usr/local/var/sentrikat/last_hash.txt`
- Windows: `$env:ProgramData\SentriKat\last_hash.txt`

**Gzip compression:** all inventory and heartbeat payloads are
gzip-compressed (`Content-Encoding: gzip`). Server-side **zip-bomb
protection** rejects payloads above 10MB decompressed or 2MB compressed
(HTTP 413 *"Decompressed payload too large"* / *"Compressed payload too
large"*).

**Store-and-forward:** failed heartbeats are spooled to a local directory
(max 50 files, oldest deleted on overflow) and replayed in chronological
order on the next successful heartbeat. Spool directories:
- Linux: `/var/lib/sentrikat/spool/`
- macOS: `/usr/local/var/sentrikat/spool/`
- Windows: `$env:ProgramData\SentriKat\spool\`

### 10.8 Product Aliases (vendor/product disambiguation)

**Where:** API only (no dedicated UI in Sprint 4 — UI planned for Sprint 6).

**What it does:** maps `(alias_vendor, alias_product)` to a canonical
product so different naming conventions across the fleet (e.g. `openssl`
vs `openssl-libs` vs `openssl3`) all roll up to the same product record.

**API:**
- `GET /api/product-aliases`
- `POST /api/product-aliases {product_id, alias_vendor, alias_product}`
- `DELETE /api/product-aliases/<id>`

**Constraint:** unique on `(organization_id, alias_vendor, alias_product)`
— enforced by the `uq_product_alias` index. Duplicate POST returns 409.

**Rate limit:** 30 POST/min.


---

## Part 3 — SaaS Tenant Guide

# SentriKat — SaaS User Guide

> **Audience:** customer organisation admins and users on the managed
> SentriKat SaaS platform (`https://app.sentrikat.com`). If you are
> running SentriKat on your own infrastructure, see
> [`ADMIN_GUIDE.md`](ADMIN_GUIDE.md) instead.

This guide covers the **feature-level** usage of SentriKat for SaaS
customers — how to onboard your team, manage your inventory, tune
alerts, and consume reports. Infrastructure concerns (Docker,
PostgreSQL, SSL certificates, SMTP, license files) are handled by the
SentriKat platform team and are not relevant to SaaS customers.

---

## 1. Getting started

### 1.1 Your first login

1. Open the signup email from `noreply@alerts.sentrikat.com`.
2. Click the activation link — you will land on `https://app.sentrikat.com/login`.
3. Enter your email and the initial password from the email.
4. You will be asked to **renew your password** on first login. This
   is also the flow used if your password later expires or an
   administrator asks you to reset it.
5. Set up 2FA (Profile menu → Security Settings → Enable 2FA). We
   recommend enabling it for every human account, especially for
   `org_admin` and above.

### 1.2 Understanding your role

SentriKat has four roles. The badge in the top-right header always
shows your current role.

| Role | What it can do | Where it can go |
|------|----------------|-----------------|
| **Super Admin** | Platform-level. Only SentriKat staff have this. | Everywhere including platform operations. |
| **Org Admin** | Full control of your organisation — users, billing, integrations, alerts, settings. | All sidebar sections. |
| **Manager** | Manage products, endpoints, integrations, scheduled reports, issue trackers. Cannot invite users or change billing. | Overview, Inventory, Integrations. |
| **User** | Read-only by default — see dashboard, products, assignments. Sensitive assignment notes are redacted. | Overview, Inventory (read-only). |

> ℹ️ There is no separate "viewer" role — `user` **is** the read-only
> role. An org admin can grant a specific user write access to
> products by toggling the `can_manage_products` flag in Users &
> Access without promoting them to Manager.

### 1.3 Plans and feature gates

Your current plan is visible at **Settings → Subscription**. Features
are gated by plan:

| Feature | Free | Starter | Pro | Business | Enterprise |
|---------|:----:|:-------:|:---:|:--------:|:----------:|
| Email alerts | ✗ | ✓ | ✓ | ✓ | ✓ |
| Webhooks | ✗ | ✓ | ✓ | ✓ | ✓ |
| Push agents | ✓ | ✓ | ✓ | ✓ | ✓ |
| API access | ✗ | ✓ | ✓ | ✓ | ✓ |
| Compliance reports (NIS2, CISA BOD 22-01) | ✗ | ✗ | ✓ | ✓ | ✓ |
| Issue trackers (Jira / GitHub / GitLab / YouTrack) | ✗ | ✗ | ✓ | ✓ | ✓ |
| SIEM / syslog forwarding | ✗ | ✗ | ✓ | ✓ | ✓ |
| Audit log export | ✗ | ✗ | ✓ | ✓ | ✓ |
| LDAP / Active Directory | ✗ | ✗ | ✗ | ✓ | ✓ |
| SAML SSO | ✗ | ✗ | ✗ | ✓ | ✓ |
| White-labelling | ✗ | ✗ | ✗ | ✓ | ✓ |
| Backup & restore | ✗ | ✗ | ✗ | ✓ | ✓ |
| Multi-Tenant (multi-org) | ✗ | ✗ | ✗ | ✓ | ✓ |
| Compliance Pack add-on (PCI-DSS, ISO 27001, SOC 2) | — | — | add-on | add-on | add-on |

Agent / user / storage limits are on the Subscription page. Upgrading
is a self-service action; downgrading requires manual action and may
require reducing your inventory first.

---

## 2. Invite your team

**Settings → Users & Access → All Users → + Invite User**.

- Email: the invitee receives an activation link at this address.
- Role: pick one of `user`, `manager`, `org_admin`.
- Organization: only relevant if you have multiple orgs (Business+).

Org Admins can delete users, reset passwords, and lock accounts from
the same page. User activity is visible in **Settings → Audit Log**
on plans with audit export.

---

## 3. Build your inventory

### 3.1 Push agents

1. **Sidebar → Integrations → Agent Keys** → click **+ New Agent Key**.
2. Copy the generated key (it is shown **once**).
3. Download the installer for your OS:
   - Linux: `curl -sSL $BASE/static/agents/sentrikat-agent-linux.sh | bash -s -- --install --server-url $BASE --api-key <KEY>`
   - macOS: `chmod +x sentrikat-agent-macos.sh && sudo ./sentrikat-agent-macos.sh --install --server-url $BASE --api-key <KEY>`
   - Windows: run the signed `.ps1` installer with elevated privileges
4. The agent will register within ~60 seconds. You will see the new
   asset at **Inventory → Endpoints**.

**Mass-removal protection (QA round 3):** if an agent ever reports a
drop of more than 50 % of its installed software in a single check-in
(and it had 5+ products to start with), SentriKat refuses the
removals, logs an `anomaly_rejected` event in Agent Activity, and
surfaces a warning in the response. New / updated products in the
same report are still accepted. This stops a compromised or malicious
agent from wiping its own vulnerability record. The threshold is
tunable via the `AGENT_MAX_REMOVAL_PCT` environment variable on the
platform side — talk to us if you have a legitimate reason (mass
provisioning, image rebase) that requires a temporary relaxation.

### 3.2 Manual product entry

**Inventory → Products List → + Add Product**. The modal searches the
NVD CPE dictionary as you type — pick a canonical entry so
vulnerability matching works correctly. Custom vendors / products
without a CPE are supported but will not auto-match NVD CVEs.

> ℹ️ **Tenant isolation:** two different customers can independently
> own the same (vendor, name, version) triple. You will only ever see
> duplicate-detection errors for products that already exist inside
> **your** organisation(s).

### 3.3 Import queue

When an agent discovers software that isn't in the CPE dictionary or
whose vendor mapping is ambiguous, it lands in **Inventory → Import
Queue**. Managers and admins can approve, reject, or bulk-process
items from there.

### 3.4 Exclusions

**Inventory → Exclusions → + Add Exclusion** opens a modal with a
dual-source search box: start typing and you will see matches from
**your current inventory** and from the **NVD CPE dictionary**
side-by-side. Picking either auto-fills vendor + product_name with
canonical values. An exclusion blocks future agent scans from
re-importing the excluded software.

---

## 4. Act on vulnerabilities

### 4.1 Dashboard

`/` (Dashboard) is the main workspace. Top-of-page alert cards show
zero-day, critical, high, and medium counts — click any of them to
filter the vulnerability list below. Filters, sort, pagination, CVE /
vendor / product search, and unacknowledged toggle all work together.

### 4.2 Remediation assignments

Click any match to open its detail, then **+ Create Assignment** to
assign it to a user, set a priority, due date, and optional notes.
The full list of your assignments lives at **Assignments** in the
sidebar (direct URL: `/assignments`).

- Notes are **redacted** for non-admin roles (`user`, `manager`) —
  only admins can read assignment rationale.
- Status transitions enforce a state machine: terminal states
  (`resolved`, `accepted_risk`) cannot be re-opened. Create a new
  assignment instead.
- Integrations with Jira, GitHub, GitLab, YouTrack or generic webhook
  create an external ticket and store the link on the assignment.

### 4.3 Risk exceptions

Click **Accept Risk** on a match detail to record a compensating
control / justification / optional expiry date. Active exceptions
hide the match from the critical list until they expire.

---

## 5. Alerts, reports and integrations

### 5.1 Email delivery

All emails (alerts, reports, notifications) are sent by the SentriKat
platform from `noreply@alerts.sentrikat.com`. **You do not configure
SMTP in SaaS mode** — it's managed delivery via Resend.

Your monthly quota is visible at **Settings → Email & Notifications**.
Free: 50 / Starter: 500 / Pro: 500 / Business: 2000 / Enterprise: 10000
emails per month. Exceeding the quota does not block the app — alerts
queue silently until the next month.

### 5.2 Alert Management

**Settings → Alert Management** is a dedicated page (not a tab). It
lets you:

- Set an alert mode per org: `critical_only`, `high_and_above`, `all`
- Configure email recipients per org
- Add webhook delivery channels (Slack, Teams, generic)
- Toggle individual alert triggers (daily digest, patch Tuesday,
  overdue remediations, new KEV entries, …)

### 5.3 Scheduled reports

**Integrations → Scheduled Reports** (yes, under Integrations — not
under Settings / Compliance). Create a recurring vulnerability report
that gets emailed to a list of recipients. Valid report types:

- `summary` — monthly high-level overview (PDF)
- `full` — 30-day detailed report (PDF)
- `critical_only` — only CRITICAL severity matches

Click **Send Now** on any report for an immediate one-off send —
useful for validating delivery before the first scheduled run.

### 5.4 Issue trackers

**Integrations → Issue Trackers** (Pro+). Configure credentials for
Jira, GitHub Issues, GitLab Issues, YouTrack, or a generic webhook.
Once configured, the **Create Assignment** modal gets an extra
"Create tracker ticket" checkbox.

### 5.5 SIEM / Syslog forwarding

**Settings → SIEM / Syslog** (Pro+). Send every vulnerability match
and remediation event as a syslog message (UDP / TCP, CEF or RFC 5424
JSON) to your SIEM. Typical use-cases: Splunk, ELK, Wazuh,
QRadar, Sentinel.

### 5.6 Compliance reports

**Settings → Compliance** (Pro+). Generate point-in-time reports for
CISA BOD 22-01 and the EU NIS2 Directive. PCI-DSS, ISO 27001 and
SOC 2 are gated behind the **Compliance Pack** add-on.

All compliance reports include a `document_integrity` block with a
SHA-256 content hash and an HMAC-SHA256 signature using the
platform's secret key. This is a **tamper-evident** audit trail —
proof that the report has not been modified after generation — but
it is **not a legal digital signature**. Present it to auditors as
supporting evidence; a compliance officer still needs to review and
sign the official submission.

### 5.7 SBOM export

**Inventory → SBOM Export** is a dedicated page with three buttons
(CycloneDX 1.5 / SPDX 2.3 / STIX 2.1) plus copy-paste `curl` snippets
for CI pipelines. All three formats also live under the Dashboard's
**Export** dropdown for quick access.

CLI example:

```bash
curl -sk -H "X-API-Key: $SENTRIKAT_API_KEY" \
  https://app.sentrikat.com/api/sbom/export/cyclonedx -o sbom.json
```

Rate-limited to 10 exports / hour / user. Exports larger than the
bundle cap return HTTP 413 — use `?product_ids=1,2,3` to split.

---

## 6. Billing and subscription

**Settings → Subscription** shows your current plan, billing cycle,
next renewal date, feature matrix, and usage vs. limits (agents,
users, products, API keys, storage). Upgrading is self-service; plan
change takes effect at the next billing cycle unless you choose
"immediate" at checkout.

Invoices arrive by email and are also available from the Subscription
page.

---

## 7. Troubleshooting

### 7.1 "Password has expired" at login

That is the renew-password flow. You will be asked for your current
password and a new one. The new password must satisfy the platform
policy (min 12 chars, mixed case, digit, special char by default).

### 7.2 Agent install on macOS fails with "existing agent detected"

Fixed in QA round 3 — the install script now correctly distinguishes
a clean machine from one with a partial / aborted prior install. If
you see this error on a deployed platform older than the fix, either
run `sudo ./sentrikat-agent-macos.sh --uninstall` first, or manually
remove `/Library/Application Support/SentriKat/agent.conf` and rerun
the installer.

### 7.3 CVE I acknowledged keeps reappearing

Acknowledge is per-match. If the underlying vulnerability record is
re-imported from NVD with a newer `last_modified` timestamp, the
match is re-created and the acknowledge is cleared — this is correct
behaviour, because something material changed about the CVE. Use a
**Risk Exception** instead of Acknowledge for permanent
suppressions.

### 7.4 Dashboard is slow

For organisations with more than ~5000 matches, use the filter and
pagination controls instead of "All" page size. The backend is
indexed for the common filter combinations but rendering a 10k-row
table in the browser is slow regardless of backend speed.

### 7.5 Email quota exceeded

Alerts are silently dropped until the next month. Contact support if
this is a recurring issue — you probably need a plan upgrade or a
tuned alert policy (e.g. `critical_only` instead of `all`).

---

## 8. Security notes

- **Tenant isolation** is enforced at the query level. An org admin
  can only see and modify data in organisations they belong to —
  even the product duplicate check is scoped to your organisation
  boundary (so other customers' inventories never leak).
- **Agent trust boundary**: agents can report any software for the
  asset they are bound to, and can create new assets within the org
  their API key belongs to. They **cannot** write to other
  organisations or inflate platform-wide metering (which is
  server-side counted). The mass-removal anomaly threshold prevents
  a compromised agent from wiping its own vulnerability history.
- **CSRF** is enforced on every state-changing endpoint — including
  the first-login password renewal form.
- **2FA (TOTP)** is available to every user and can be enforced per
  organisation via Settings → Users & Access → Security.
- **Audit log export** (Pro+) captures every create / update / delete
  on your organisation's data with actor, timestamp, and diff.

---

## 9. Getting help

- **In-app**: help icons (?) next to every feature link to the
  corresponding section of this guide.
- **Email**: `support@sentrikat.com`
- **Status page**: `https://status.sentrikat.com`
- **GitHub issues** (public): `https://github.com/sbr0nch/SentriKat/issues`


---

## Part 4 — Storage Reference

# Storage Configuration Guide

SentriKat stores several types of persistent data. By default everything lives
inside Docker named volumes, which is fine for small deployments. For production
servers — especially those with a dedicated data drive — you can redirect all
heavy data to a custom location with a single environment variable.

---

## What data does SentriKat store?

| Data type | Default location | Size profile |
|---|---|---|
| **PostgreSQL database** | Docker volume `postgres_data` | Grows with inventory & vulnerabilities |
| **Application logs** (7 rotating files) | `/var/log/sentrikat` inside container | 10–20 MB each, auto-rotated |
| **Uploads** (logos, branding) | `/app/data/uploads` inside container | Small (< 10 MB) |
| **Encryption key** | `/app/data/.encryption_key` | 1 file |
| **Database backups** | `./backups` on host | Grows with database size |

---

## Quick setup — one variable

If your server has a second disk mounted at `/data`:

```bash
# .env
STORAGE_ROOT=/data/sentrikat
```

Create the directory tree and start with the storage override:

```bash
sudo mkdir -p /data/sentrikat/{postgres,data,logs,backups}
sudo chown -R 999:999 /data/sentrikat/postgres   # PostgreSQL UID
sudo chown -R $(id -u):$(id -g) /data/sentrikat/{data,logs,backups}

docker compose -f docker-compose.yml -f docker-compose.storage.yml up -d
```

This gives you:

```
/data/sentrikat/
├── postgres/    ← PostgreSQL database files
├── data/        ← uploads, encryption key
├── logs/        ← application.log, error.log, audit.log, ...
└── backups/     ← database backup .sql.gz files
```

The backup script also picks up `STORAGE_ROOT` automatically:

```bash
./scripts/backup_database.sh          # writes to /data/sentrikat/backups/
```

---

## Fine-grained overrides

Individual path variables take precedence over `STORAGE_ROOT`. For example, to
put only the database on a fast SSD and everything else on a large spinning disk:

```bash
# .env
STORAGE_ROOT=/mnt/hdd/sentrikat       # logs, uploads, backups → HDD
LOG_DIR=/mnt/hdd/sentrikat/logs       # (derived from STORAGE_ROOT anyway)
```

Then in `docker-compose.storage.yml`, override just the Postgres volume to
point at the SSD:

```yaml
services:
  db:
    volumes:
      - /mnt/ssd/sentrikat/postgres:/var/lib/postgresql/data
```

### All available variables

| Variable | Derived from STORAGE_ROOT as | Default (no STORAGE_ROOT) |
|---|---|---|
| `LOG_DIR` | `${STORAGE_ROOT}/logs` | `/var/log/sentrikat` |
| `DATA_DIR` | `${STORAGE_ROOT}/data` | `/app/data` |
| `BACKUP_DIR` | `${STORAGE_ROOT}/backups` | `./backups` |
| PostgreSQL | `${STORAGE_ROOT}/postgres` (via override file) | Docker named volume |

Setting any individual variable explicitly overrides the `STORAGE_ROOT` derivation.

---

## Without STORAGE_ROOT (default)

If you don't set `STORAGE_ROOT`, everything stays as before:

- PostgreSQL → `postgres_data` Docker named volume
- App data → `sentrikat_data` Docker named volume (mounted at `/app/data`)
- Logs → `/var/log/sentrikat` inside the container
- Backups → `./backups` relative to docker-compose directory

No changes are needed if you're happy with Docker named volumes.

---

## Migrating existing data to a new location

If you already have data in Docker named volumes and want to move to a bind mount:

```bash
# 1. Stop SentriKat
docker compose down

# 2. Find where Docker stores the named volume
docker volume inspect sentrikat_postgres_data | grep Mountpoint

# 3. Copy data to new location
sudo cp -a /var/lib/docker/volumes/sentrikat_postgres_data/_data/* /data/sentrikat/postgres/
sudo cp -a /var/lib/docker/volumes/sentrikat_sentrikat_data/_data/* /data/sentrikat/data/

# 4. Set STORAGE_ROOT in .env
echo 'STORAGE_ROOT=/data/sentrikat' >> .env

# 5. Start with storage override
docker compose -f docker-compose.yml -f docker-compose.storage.yml up -d

# 6. Verify everything works, then optionally remove old volumes
docker volume rm sentrikat_postgres_data sentrikat_sentrikat_data
```

---

## Permissions

- **PostgreSQL** runs as UID 999 inside the container. The `postgres/` directory
  must be owned by `999:999`.
- **SentriKat app** runs as a non-root user. The `data/` and `logs/` directories
  should be writable by the container user (or world-writable `chmod 777` for
  simplicity in trusted environments).


---

## Part 5 — Windows Testing Guide

# SentriKat - Complete Windows Test Guide

**For:** Investor demo / Full feature test
**Environment:** Windows 11 + Docker Desktop
**Time needed:** ~45 minutes

---

## PHASE 0: Prerequisites

```powershell
# Verify Docker Desktop is running
docker --version
docker compose version

# Verify testlab is running
docker compose -f C:\SentriKat\testlab\docker-compose.testlab.yml ps
```

All 8 testlab services should be "Up". If not:
```powershell
docker compose -f C:\SentriKat\testlab\docker-compose.testlab.yml up -d
```

---

## PHASE 1: Download Package from Portal

1. Go to **sentrikat.com** -> request demo or purchase
2. You'll receive an activation code (format: `SK-XXXX-XXXX-XXXX-XXXX`)
3. Download the release package `sentrikat-X.X.X.tar.gz`
4. Extract to `C:\SentriKat`

You should have:
```
C:\SentriKat\
  docker-compose.yml
  .env.example
  nginx\
  scripts\
  certs\
```

---

## PHASE 2: Configure Environment

```powershell
cd C:\SentriKat
copy .env.example .env
```

Edit `.env` with Notepad or VS Code - set these values:

```env
# Generate these (run in PowerShell):
# python -c "import secrets; print(secrets.token_hex(32))"
SECRET_KEY=<paste generated key>

# python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"
ENCRYPTION_KEY=<paste generated key>

# Generate once, keep forever:
# python -c "import uuid; print(f'SK-INST-{uuid.uuid4().hex[:32].upper()}')"
SENTRIKAT_INSTALLATION_ID=<paste generated ID>

# Database
DB_PASSWORD=MySecurePassword123!
DATABASE_URL=postgresql://sentrikat:MySecurePassword123!@db:5432/sentrikat

# Network
SERVER_NAME=localhost
SENTRIKAT_URL=http://localhost
HTTP_PORT=80

# For local testing (no HTTPS)
FORCE_HTTPS=false
SESSION_COOKIE_SECURE=false
FLASK_ENV=production
SENTRIKAT_ENV=production
NGINX_TEMPLATE=nginx.conf.template
```

**IMPORTANT:** Write down the `SENTRIKAT_INSTALLATION_ID` - you'll need it for license activation.

---

## PHASE 3: Start SentriKat

```powershell
cd C:\SentriKat
docker compose up -d
```

Wait for all 3 containers to be healthy:
```powershell
docker compose ps
```

Expected output:
```
NAME              STATUS          PORTS
sentrikat-db      Up (healthy)
sentrikat         Up (healthy)
sentrikat-nginx   Up (healthy)    0.0.0.0:80->80/tcp
```

If `sentrikat` shows "starting", wait 30-60 seconds for the database to initialize.

Open browser: **http://localhost**

---

## PHASE 4: Setup Wizard

The setup wizard appears on first launch. Follow these steps:

### Step 1: Welcome
- Click **"Get Started"**

### Step 2: Organization
- **Name:** `Acme Corp` (or your company name)
- **Description:** `Security operations`
- **Alert Emails:** `admin@test.local`
- Click **"Create"**

### Step 3: Admin Account
- **Username:** `admin`
- **Password:** `Admin123!secure` (min 8 chars)
- **Email:** `admin@test.local`
- **Full Name:** `System Administrator`
- Click **"Create"**

### Step 4: Service Catalog
- Click **"Seed Catalog"**
- Wait for confirmation (~47 services loaded)

### Step 5: CISA KEV Sync
- Click **"Start Sync"**
- Wait 30-60 seconds for ~1200+ CVEs to download
- If it fails (proxy/firewall), click **"Skip"** - you can sync later from Admin panel

### Step 6: Complete
- Click **"Continue"**
- You'll be redirected to the login page

---

## PHASE 5: Login & Activate License

### Login
- Username: `admin`
- Password: `Admin123!secure`

### Activate License
1. Go to **Administration > License** (sidebar menu)
2. You'll see "Demo Version" with limits
3. Note the **Installation ID** displayed (should match your `.env`)
4. Click **"Online Activation"** (or "Activate License")
5. Paste your activation code: `SK-XXXX-XXXX-XXXX-XXXX`
6. Click **"Activate"**
7. Should show: **"Professional"** with 10 agents

If online activation fails (firewall), use manual activation:
1. Copy the Installation ID
2. Go to portal.sentrikat.com, log in
3. Bind the license to your Installation ID
4. Download the license key
5. Paste in SentriKat > Administration > License > "Activate License"

---

## PHASE 6: Configure Integrations (Using Testlab)

### 6A. Email (MailHog)

1. Go to **Administration > Settings** (or Organization settings)
2. Find Email/SMTP section
3. Configure:

| Field | Value |
|-------|-------|
| SMTP Host | `host.docker.internal` |
| SMTP Port | `1025` |
| Use TLS | No |
| Username | *(empty)* |
| Password | *(empty)* |
| From Email | `sentrikat@test.local` |
| From Name | `SentriKat Alerts` |

4. Click **"Send Test Email"**
5. Open **http://localhost:8025** (MailHog) - verify email arrived

### 6B. LDAP (OpenLDAP)

1. Go to **Administration > LDAP/AD**
2. Configure:

| Field | Value |
|-------|-------|
| Enabled | Yes |
| Host | `host.docker.internal` |
| Port | `389` |
| Use SSL | No |
| Bind DN | `cn=admin,dc=sentrikat-test,dc=local` |
| Bind Password | `admin123` |
| User Search Base | `ou=users,dc=sentrikat-test,dc=local` |
| User Filter | `(uid={username})` |
| Username Attribute | `uid` |
| Email Attribute | `mail` |
| Display Name Attribute | `displayName` |
| Group Search Base | `ou=groups,dc=sentrikat-test,dc=local` |
| Group Filter | `(member={userDN})` |
| Group Name Attribute | `cn` |
| Admin Group | `sentrikat-admins` |

3. Click **"Test Connection"** - should show success
4. Click **"Save"**

### 6C. Webhooks

1. Open **http://localhost:8800** (Webhook Tester)
2. Copy the webhook URL
3. Replace `localhost` with `host.docker.internal` in the URL
4. Go to **Administration > Webhooks**
5. Add Custom Webhook with the modified URL
6. Click **"Test"** - verify payload appears in Webhook Tester

### 6D. Jira Integration

1. Go to **Administration > Issue Trackers**
2. Enable Jira:

| Field | Value |
|-------|-------|
| URL | `http://host.docker.internal:8080` |
| Username | `admin` |
| API Token | `mock-token-12345` |
| Project Key | `VULN` |
| Issue Type | `Vulnerability` |

3. Click **"Test Connection"** - should return Jira v9.12.0
4. Click **"Save"**

---

## PHASE 7: Test Core Features

### 7A. Add Products Manually

1. Go to **Inventory > Products**
2. Click **"Add Product"**
3. Search NVD for: `Firefox`
4. Select `Mozilla Firefox` from results
5. Set version: `115.0`
6. Click **"Save"**
7. Repeat for:
   - `Apache HTTP Server` version `2.4.57`
   - `OpenSSL` version `3.0.2`
   - `Microsoft Exchange Server` version `2019`

### 7B. Check Vulnerability Matches

1. Go to **Dashboard**
2. You should see matched CVEs for the products you added
3. Click a CVE to see full details
4. Try **Acknowledge** on a CVE
5. Try **Unacknowledge**
6. Try **Snooze** (7 days)
7. Filter by **Critical** / **High** severity

### 7C. Deploy an Agent

1. Go to **Administration > Agent Keys**
2. Click **"Create API Key"**
3. **Copy the key** (shown only once!)

#### Option A: Install the real agent (recommended)

Download the agent script and install as a Windows service:

```powershell
# Install as Windows service (visible in services.msc, auto-restart on failure)
.\sentrikat-agent-windows.ps1 -InstallService -ServerUrl "https://YOUR_SERVER" -ApiKey "YOUR_KEY_HERE"

# Verify it's running
Get-Service SentriKatAgent

# Alternative: Install as scheduled task instead
.\sentrikat-agent-windows.ps1 -Install -ServerUrl "https://YOUR_SERVER" -ApiKey "YOUR_KEY_HERE"
```

The agent will automatically:
- Run an initial inventory scan immediately
- Send heartbeats every 5 minutes
- Rescan every 4 hours (configurable)
- Auto-update when new agent versions are pushed

#### Option B: Simulate with API call (quick test)

```powershell
# Test agent registration + inventory via direct API call
$headers = @{
    "X-Agent-Key" = "YOUR_KEY_HERE"
    "Content-Type" = "application/json"
}

$body = @{
    hostname = "WIN-SERVER-01"
    os = "Windows Server 2022"
    ip = "192.168.1.100"
    products = @(
        @{vendor="Mozilla"; product="Firefox"; version="115.0"},
        @{vendor="Apache"; product="HTTP Server"; version="2.4.57"},
        @{vendor="OpenSSL"; product="OpenSSL"; version="3.0.2"},
        @{vendor="Microsoft"; product="Exchange Server"; version="2019"},
        @{vendor="Microsoft"; product="Windows Server"; version="2022"}
    )
} | ConvertTo-Json -Depth 3

Invoke-RestMethod -Uri "http://localhost/api/agent/inventory" -Method POST -Headers $headers -Body $body
```

5. Check **Inventory > Connected Endpoints** - your endpoint should appear
6. Check that new products from agent show up

### 7D. Deploy Linux Agent (if available)

```powershell
# Simulate a Linux server
$body2 = @{
    hostname = "LINUX-WEB-01"
    os = "Ubuntu 22.04 LTS"
    ip = "192.168.1.101"
    products = @(
        @{vendor="Nginx"; product="Nginx"; version="1.24.0"},
        @{vendor="PostgreSQL"; product="PostgreSQL"; version="15.4"},
        @{vendor="Python"; product="Python"; version="3.11.5"},
        @{vendor="Docker"; product="Docker Engine"; version="24.0.7"}
    )
} | ConvertTo-Json -Depth 3

Invoke-RestMethod -Uri "http://localhost/api/agent/inventory" -Method POST -Headers $headers -Body $body2
```

---

## PHASE 8: Test LDAP Login

1. **Log out** from admin account
2. Login with LDAP user:
   - Username: `sec.analyst`
   - Password: `password123`
3. Should see dashboard with limited permissions (analyst role)
4. Log out, try: `it.manager` / `password123` (admin role)
5. Try: `disabled.user` / `password123` - should **FAIL** (no group)

---

## PHASE 9: Test Email Alerts

1. Login as admin
2. Go to **Administration > Settings > Email**
3. Ensure SMTP is configured (from Phase 6A)
4. Go to **Administration > Settings > Alerts**
5. Enable alerts for Critical CVEs
6. Trigger a manual sync (Admin > Sync > Sync Now)
7. Check **http://localhost:8025** (MailHog) for alert emails

---

## PHASE 10: Test Reports & Backup (Professional)

### Reports
1. Go to **Reports**
2. Generate **Vulnerability Report** -> PDF downloaded
3. Generate **Compliance Report** -> PDF with CISA BOD 22-01 status

### Backup
1. Go to **Administration > Backup**
2. Click **"Create Backup"** -> JSON file downloaded
3. Open the file - verify it contains products, vulnerabilities, settings

---

## PHASE 11: Test API Documentation

1. Go to **http://localhost/api/docs**
2. Browse the interactive API documentation
3. Try executing `GET /api/health` from the docs UI
4. Try `GET /api/version`

---

## PHASE 12: Test Security

### Account Lockout
```powershell
# Try 5 wrong passwords
1..5 | ForEach-Object {
    try {
        $loginBody = @{username="admin"; password="wrongpassword$_"} | ConvertTo-Json
        Invoke-RestMethod -Uri "http://localhost/api/auth/login" -Method POST -Body $loginBody -ContentType "application/json"
    } catch { Write-Host "Attempt $_ : $($_.Exception.Response.StatusCode)" }
}
# 6th attempt should show "Account locked"
```

### Security Headers
```powershell
$response = Invoke-WebRequest -Uri "http://localhost" -UseBasicParsing
$response.Headers | Format-Table Key, Value
# Should see: X-Content-Type-Options, X-Frame-Options, Content-Security-Policy
```

### XSS Test
1. Add a product with name: `<script>alert('xss')</script>`
2. Verify the script tag is displayed as text, NOT executed

---

## PHASE 13: Dark Mode

1. Toggle dark mode (theme switch in top bar)
2. Navigate through: Dashboard, Inventory, Admin, Reports
3. Verify all elements are readable and properly styled
4. Toggle back to light mode

---

## PHASE 14: Create Jira Issue from CVE

1. Go to Dashboard, find a Critical CVE
2. Click **"Create Jira Issue"** (or similar button)
3. Check **http://localhost:8080/mockserver/dashboard** for the captured request
4. Verify issue creation payload is correct

---

## Quick Reference Commands

```powershell
# Check SentriKat status
docker compose -f C:\SentriKat\docker-compose.yml ps

# View SentriKat logs
docker logs sentrikat --tail 50

# Restart SentriKat
docker compose -f C:\SentriKat\docker-compose.yml restart

# Full reset (destroy all data)
docker compose -f C:\SentriKat\docker-compose.yml down -v
docker compose -f C:\SentriKat\docker-compose.yml up -d

# Check testlab
docker compose -f C:\SentriKat\testlab\docker-compose.testlab.yml ps

# Check all emails received
Start-Process "http://localhost:8025"

# Check webhook payloads
Start-Process "http://localhost:8800"

# Check Jira mock
Start-Process "http://localhost:8080/mockserver/dashboard"
```

---

## Troubleshooting

### "Connection refused" on port 80
```powershell
# Check if nginx is running
docker logs sentrikat-nginx --tail 20
# Check if something else uses port 80
Get-NetTCPConnection -LocalPort 80 -ErrorAction SilentlyContinue
```

### CISA Sync fails
- Check internet connectivity from container:
  ```powershell
  docker exec sentrikat curl -s https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json | Select-Object -First 100
  ```
- If behind corporate proxy, set `HTTP_PROXY`/`HTTPS_PROXY` in `.env`

### Agent inventory returns 401
- Verify the API key is correct (check for trailing spaces)
- Verify the key is active in Admin > Agent Keys

### License activation fails
- Check Installation ID matches: Admin > License vs `.env`
- Check internet connectivity to portal.sentrikat.com
- Try manual activation via portal

### LDAP login fails
- Test connection first from Admin > LDAP
- Verify testlab LDAP container is running: `docker logs testlab-ldap --tail 20`
- Check with phpLDAPadmin: https://localhost:6443

---

*Guide version 1.0 - February 2026*
