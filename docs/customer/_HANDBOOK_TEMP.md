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
