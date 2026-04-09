# BRIEFING PER SESSIONE CLAUDE CODE - SENTRIKAT-WEB

## Copia e incolla questo messaggio nella sessione Claude Code che gestisce la repo SentriKat-web

---

Ho appena completato un audit di sicurezza completo cross-repo tra SentriKat (backend/core Flask) e SentriKat-web (landing/portal/license-server). L'audit ha analizzato come le due repo si collegano tramite il Provisioning Bridge e ha trovato diversi problemi.

## PROBLEMI DA FIXARE IN SENTRIKAT-WEB

### H3 - ADMIN_API_KEY esposto a n8n (ALTA priorita)
In `docker-compose.yml`, il container n8n riceve `SENTRIKAT_ADMIN_KEY: ${ADMIN_API_KEY}`. Se n8n viene compromesso, l'attacker ha accesso completo all'admin API del license server.
**Fix richiesto**: Creare un API key separato con permessi limitati per n8n (es. `N8N_API_KEY` con scope ridotto), oppure rimuoverlo se n8n non ne ha bisogno.

### H4 - Turnstile fail-open (MEDIA priorita)
In `license-server/app/api/contact.py`, la funzione `verify_turnstile_token` ritorna `True` se la connessione a Cloudflare fallisce (fail-open). Questo permette spam se un attacker blocca le richieste outbound a Cloudflare.
**Fix richiesto**: Cambiare in fail-closed (return False su errore di rete), oppure aggiungere rate limiting piu aggressivo come fallback.

### C4 - Token revocation in-memory (BASSA per EA)
In `license-server/app/core/security.py`, `_revoked_tokens` e un `Set[str]` in-memory. Si perde al restart del server, quindi token revocati tornano validi fino alla scadenza naturale (2h).
**Fix suggerito post-EA**: Migrare a tabella PostgreSQL o Redis.

## VERIFICHE DI CONNESSIONE CON SENTRIKAT CORE

Il Provisioning Bridge deve funzionare perfettamente. Ecco i punti di connessione:

### 1. Trial Signup Flow
- `POST /api/v1/provision/trial` (trial.py) chiama `provision_saas_tenant()` (provision.py)
- Che chiama `POST {SAAS_PROVISION_URL}` con header `X-Provision-Key: {SENTRIKAT_PROVISION_KEY}`
- SentriKat Core risponde con `{tenant: {organization_id, user_id, temporary_password, login_url}}`
- **VERIFICARE**: `SAAS_PROVISION_URL` e `SENTRIKAT_PROVISION_KEY` sono configurati identici in entrambi i servizi

### 2. Plan Upgrade Flow
- `upgrade_saas_tenant()` chiama `POST {SAAS_PROVISION_URL}/upgrade`
- Invia `{email, plan_name, new_plan, stripe_subscription_id}`
- **NOTA**: il backend SentriKat accetta sia `plan_name` che `new_plan` (backward compat)

### 3. Cancellation Flow
- `cancel_saas_tenant()` chiama `POST {SAAS_PROVISION_URL}/cancel`
- Supporta `cancel_at_period_end: true` (grace period) o `false` (immediato)

### 4. Status Check
- `get_saas_tenant_status()` chiama `GET {SAAS_PROVISION_URL}/status?email=xxx`
- Usato dal trial signup per verificare se l'utente esiste gia (previene duplicati)

## VERIFICHE ASSETS E PAGINE

Verificare che esistano:
- [ ] `/images/screenshots/dashboard.png` in `landing/public/`
- [ ] `/images/og-image.png` in `landing/public/`
- [ ] Favicon varianti in `landing/public/`
- [ ] Tutti i link nel footer funzionano (LinkedIn, Twitter)
- [ ] `/blog/rss.xml` viene generato correttamente
- [ ] Nginx config in produzione redirige `/api/` al license server (porta 8001)

## VERIFICHE PIANI E PRICING

Il `plans_config.py` nel license server e la fonte unica di verita per i piani SaaS:
- free, starter, pro, business, enterprise
- Prezzi in centesimi EUR (monthly_eur e annual_eur)
- EA config: 30 posti cloud, 15 on-prem

Verificare che:
- [ ] I piani nel `plans_config.py` corrispondano a quelli nella Pricing section del landing
- [ ] Il form TrialSignup invia `plan_name: "pro"` (hardcoded per EA)
- [ ] I piani nel license server corrispondano ai `SubscriptionPlan` nel SentriKat Core (free, starter, pro, business, enterprise)

## CONFIGURAZIONE ENV CRITICA

Queste variabili DEVONO essere settate identicamente tra license server e SentriKat Core:
```
SENTRIKAT_PROVISION_KEY=<stesso valore in entrambi>
SAAS_PROVISION_URL=https://app.sentrikat.com/api/provision  (nel license server)
SENTRIKAT_BASE_URL=https://app.sentrikat.com                 (nel SentriKat core)
```

Inoltre nel license server:
```
SECRET_KEY=<generato, nessun default>
API_KEY_SALT=<generato, nessun default>
ADMIN_API_KEY=<generato, nessun default>
RESEND_API_KEY=<dalla dashboard Resend>
STRIPE_SECRET_KEY=<opzionale per EA, obbligatorio per pagamenti>
STRIPE_WEBHOOK_SECRET=<opzionale per EA>
TURNSTILE_SECRET_KEY=<dalla dashboard Cloudflare>
```
