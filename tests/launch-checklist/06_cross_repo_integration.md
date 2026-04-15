# 06 — Cross-Repo Integration: SaaS ↔ Admin Portal / License Server (Part F)

> **Durata:** 2-3h. **Priorità:** 🔴 Obbligatoria prima del go-live.
>
> Questa parte testa i flussi end-to-end tra **SentriKat SaaS**
> (questo repo) e **SentriKat-web** (repo `sbr0nch/SentriKat-web` —
> admin portal + license server + billing/marketing site).
>
> **Aggiornato al contract Sprint 6** — event types hanno il prefisso
> `license.*`, `tenant_id` è **email string**, metering sender usa
> `{LICENSE_SERVER_URL}/v1/metrics/usage` (dove `LICENSE_SERVER_URL`
> include già il prefisso `/api`).
>
> **Prereq**: entrambi gli ambienti devono essere deployati e collegati.
> I 4 secret condivisi devono essere identici sui due lati:
> `SENTRIKAT_PROVISION_KEY`, `SENTRIKAT_METRICS_KEY`,
> `SENTRIKAT_WEBHOOK_SECRET`, `SENTRIKAT_SSO_SECRET`.
>
> **Convenzione:** ogni test descrive
> 1. **Azione** (dove la fai)
> 2. **Verifica lato portal** (SentriKat-web admin)
> 3. **Verifica lato SaaS** (questo repo — UI + pagine super-admin)
> 4. **Verifica DB / logs** (sanity check)

---

## F.0 Setup iniziale (una volta sola)

- [ ] Portal admin raggiungibile: `https://admin.sentrikat.com` (o URL di staging)
- [ ] SaaS raggiungibile: `https://app.sentrikat.com`
- [ ] DNS risolve entrambi
- [ ] TLS valido su entrambi (no cert warnings)
- [ ] Portal configurato con `SAAS_CALLBACK_URL` puntato al SaaS
- [ ] SaaS ha `SENTRIKAT_LICENSE_SERVER` in env (default
      `https://license.sentrikat.com/api` — **include `/api`**, non aggiungerlo
      nel path sender)
- [ ] `SENTRIKAT_PROVISION_KEY` identico su entrambi i lati
- [ ] `SENTRIKAT_METRICS_KEY` identico su entrambi i lati (usage + metrics auth)
- [ ] `SENTRIKAT_WEBHOOK_SECRET` identico (HMAC firma webhook license events)
- [ ] `SENTRIKAT_SSO_SECRET` identico (JWT HS256 impersonation)
- [ ] Portal ha superadmin account creato (`portal_admin@sentrikat.com`)
- [ ] SaaS ha super-admin locale (`saas_admin@sentrikat.com`) — solo fallback
- [ ] Stripe / billing provider in **test mode** per questa sessione
- [ ] Logs in real-time: `docker compose logs -f sentrikat` sul SaaS, equivalente sul portal

### F.0.1 Smoke test degli endpoint cross-repo

Questi devono **tutti** rispondere come atteso prima di procedere col
resto della Part F.

- [ ] `curl -sk https://app.sentrikat.com/api/health` → `200` `{"status":"healthy"}`
- [ ] `curl -skI https://app.sentrikat.com/metrics` → `401` (auth required)
- [ ] `curl -sk -X POST https://app.sentrikat.com/api/license/events -d '{}'` → `401` `{"error":"invalid signature"}`
- [ ] `curl -skI https://app.sentrikat.com/admin/sso` → `401` (no token)
- [ ] `curl -skI https://app.sentrikat.com/admin/sso/exit` → `302` (redirect, no session → login)
- [ ] `docker compose logs sentrikat 2>&1 | grep "Usage Metering Upload"` → vedi il job registrato e "scheduled hourly at minute 5"
- [ ] `docker compose logs sentrikat 2>&1 | grep "Acquired scheduler leader lock"` → una sola volta

---

## F.1 Customer Signup (Portal → SaaS provisioning)

**Flusso**: un potenziale cliente si registra sul portale, il portale
crea l'organizzazione sul SaaS, invia credenziali email.

### F.1.1 Self-service signup

> 💡 I nomi dei piani canonici lato SaaS sono (vedi `models.py::SubscriptionPlan.DEFAULT_PLANS`):
> `free`, `starter`, `pro`, `business`, `enterprise`. Non esiste un
> plan chiamato "Free Trial" — "trial" e' uno *stato* della
> Subscription (subscription_status='trial'), non un plan. Durante
> il trial il plan di riferimento e' `free` (o il plan scelto, con
> status=trial e trial_ends_at = +14gg).

- [ ] Apri `https://sentrikat.com/signup` (marketing site) in incognito
- [ ] Compila form: company name, email admin, password, plan=`free`
      (subscription_status diventera' automaticamente `trial` se il
      portale implementa il flusso 14gg)
- [ ] Check email verification: arriva email con link
- [ ] Click verify → redirect a portal customer dashboard
- [ ] **Portal admin panel** (`/admin/customers`): nuova row "AcmeCorp"
      status=`active`, subscription_status=`trial`, trial_ends_at = +14 giorni
- [ ] **SaaS admin** (`/super-admin/organizations`): appare "AcmeCorp"
      org con status `active`, slot = piano trial
- [ ] Org nel SaaS ha `license_key` valorizzato e matching con il portal
- [ ] DB SaaS `organizations` table ha `external_id` che corrisponde al
      portal `customer_id`
- [ ] Email credenziali arrivata a admin AcmeCorp con link login SaaS
- [ ] Login SaaS funziona con quelle credenziali
- [ ] Primo login forza cambio password

### F.1.2 Admin-created customer (manual)
- [ ] Portal admin → `/admin/customers/new`
- [ ] Compila: company, admin email, plan=`business`, seats=50
      (il Pro plan ha max_users=5 / max_agents=25, quindi per "seats=50"
      il plan corretto e' `business` che ha max_agents=50, max_users=10)
- [ ] Submit → portal crea org sul SaaS via API `/api/provision`
- [ ] **Verifica portal**: customer status=`active`
- [ ] **Verifica SaaS**: org appare con plan=`business`, seat_limit=50
- [ ] Logs SaaS mostrano `POST /api/provision` con 200 OK
- [ ] Logs portal mostrano risposta OK dal SaaS
- [ ] Email inviata a customer admin
- [ ] Nessun errore in entrambi i log

### F.1.3 Signup failures (rollback)
- [ ] Portal admin prova a creare customer con email già usata
      → errore chiaro, nessuna org creata sul SaaS
- [ ] Simula SaaS down (`docker stop saas-web`) → portal signup fallisce
      con messaggio "provisioning failed, retry later"
- [ ] Portal customer resta in status `pending_provision`
- [ ] Restart SaaS → portal ha job di retry che completa
- [ ] Dopo retry, status=`active` su entrambi

---

## F.2 Plan Change (Portal → SaaS sync)

### F.2.1 Upgrade plan
- [ ] Scegli customer "AcmeCorp" (subscription_status=`trial`, plan=`free`)
- [ ] Portal `/admin/customers/acmecorp/edit` → cambia plan da
      `free` a `pro`, seats da 1 a 5 (limite Pro)
- [ ] Salva → portal chiama SaaS `PATCH /api/license/<license_key>`
- [ ] **Verifica SaaS**: `/super-admin/organizations/acmecorp`
      mostra plan=`pro`, max_users=5, max_agents=25, expires_at rinnovato
- [ ] Login come user AcmeCorp sul SaaS → Subscription page mostra
      "Professional — Active"
- [ ] Feature limits aggiornate: puoi aggiungere più asset (fino al nuovo
      limite), vedi feature prima gated
- [ ] Audit log sul SaaS ha entry `plan_changed`
- [ ] Audit log sul portal ha entry `plan_updated`
- [ ] Timestamps corrispondono (±1 sec)

### F.2.2 Downgrade plan
- [ ] Customer "AcmeCorp" ora su plan=`business` con 45/50 asset usati
- [ ] Portal: downgrade a plan=`starter` (limite 10 agents, NOT 20)
- [ ] **Verifica comportamento**: che succede ai 45 asset esistenti?
      - opzione A: grace period 30gg, readonly sopra 20
      - opzione B: blocco immediato nuove creazioni, lettura ok
      - opzione C: errore "cannot downgrade, disable assets first"
- [ ] Verifica che la policy definita sia effettivamente implementata
      (non solo documentata)
- [ ] User AcmeCorp vede notifica nel SaaS sul downgrade
- [ ] Email notifica inviata all'admin

### F.2.3 Feature flag sync
- [ ] Portal admin abilita feature `SIEM_EXPORT` per AcmeCorp
- [ ] Verifica sul SaaS: menu SIEM appare per user AcmeCorp
- [ ] Disabilita → menu sparisce
- [ ] Cambio è immediato (refresh, no logout)
- [ ] Altri customer non sono toccati

---

## F.3 License key & validation loop

### F.3.1 Heartbeat / license refresh
- [ ] SaaS fa heartbeat al portal ogni N minuti (verifica `LICENSE_CHECK_INTERVAL`)
- [ ] `tail -f` logs: vedi richieste `GET /api/license/<key>/status`
- [ ] Portal risponde con plan, expires_at, feature_flags, seat_limit
- [ ] SaaS cache aggiorna senza downtime
- [ ] Se portal risponde `revoked` → SaaS blocca login non-admin
      dopo max grace (es. 1h)
- [ ] Super-admin SaaS può sempre entrare (fallback locale)

### F.3.2 License revocation (emergency stop)
- [ ] Portal admin → customer → "Suspend" → status=`suspended`
- [ ] Entro 1h il SaaS recepisce e mette org in readonly
- [ ] Tutti gli utenti di quell'org al login vedono banner
      "Account suspended, contact support"
- [ ] Agents dell'org smettono di inviare dati (ricevono 403 dal API)
- [ ] Altri org NON sono toccati (isolamento confermato)
- [ ] Portal "Unsuspend" → entro 1h SaaS torna attivo
- [ ] Nessuna perdita di dati durante la sospensione

### F.3.3 License key rotation
- [ ] Portal admin → customer → "Rotate license key"
- [ ] Nuova chiave generata, vecchia marcata `rotating` per grace 24h
- [ ] SaaS riceve nuova chiave via webhook
- [ ] Config SaaS aggiornata automaticamente (no manual restart)
- [ ] Agents continuano a funzionare (loro usano token separato)
- [ ] Dopo grace 24h, vecchia chiave non più valida

---

## F.4 Usage Metering (SaaS → Portal reporting)

### F.4.1 Daily usage push
- [ ] SaaS raccoglie metrics (asset count, scan count, user count, storage GB)
- [ ] Cron SaaS invia al portal `POST /api/usage/<customer_id>` a mezzanotte
- [ ] **Verifica portal** `/admin/customers/acmecorp/usage` mostra metrics
- [ ] Grafico ultimi 30gg valorizzato
- [ ] Billing calcola correttamente (seats × price + overage)
- [ ] Idempotenza: re-inviare stesso payload non duplica
- [ ] Se portal down, SaaS bufferizza e retry

### F.4.2 Overage handling
- [ ] Customer su plan=`starter` (max_agents=10) supera a 12 asset
- [ ] Portal riceve usage e calcola overage = 2 × overage_price
- [ ] Portal mostra warning "overage" nel dashboard customer
- [ ] Email al customer admin avvisa dell'overage
- [ ] SaaS mostra anche warning inline (header banner)
- [ ] Policy definita: soft warn vs hard block (verifica matches docs)

### F.4.3 Real-time events
- [ ] User SaaS fa login → evento `user_login` push al portal
- [ ] Portal aggrega MAU (Monthly Active Users)
- [ ] Nuovo user invitato → evento `user_created`
- [ ] Asset aggiunto → evento `asset_created` (se on piano metered)

---

## F.5 Billing & Subscription lifecycle

### F.5.1 First invoice (trial → paid)
- [ ] Customer in trial clicca "Upgrade" dentro il SaaS
- [ ] Redirect a portal billing page
- [ ] Inserisce carta (Stripe test card `4242 4242 4242 4242`)
- [ ] Subscription attivata sul portal
- [ ] Webhook Stripe → portal → SaaS: plan updated
- [ ] **Verifica SaaS**: Subscription page mostra "Professional — Active"
- [ ] Invoice #1 generata sul portal, PDF scaricabile
- [ ] Invoice email inviata

### F.5.2 Renewal
- [ ] Simula tempo +30gg (o cambia data test clock Stripe)
- [ ] Stripe tenta renewal → success
- [ ] Portal aggiorna `paid_through = +30gg`
- [ ] SaaS heartbeat riceve nuovo expires_at
- [ ] Nessuna interruzione servizio

### F.5.3 Failed payment
- [ ] Usa Stripe test card `4000 0000 0000 0341` (fails on renewal)
- [ ] Portal riceve `invoice.payment_failed`
- [ ] Customer entra in `past_due` state
- [ ] Email dunning inviata (giorno 1, 3, 7)
- [ ] Dopo grace 7gg senza pagamento → SaaS limita funzionalità
      (es. readonly, no new scans)
- [ ] Pagamento ritardato → tutto torna normale

### F.5.4 Cancellation
- [ ] Customer su portal clicca "Cancel subscription"
- [ ] Mostra data fine periodo corrente, opzione "cancel immediately"
- [ ] Schedule cancel at period end
- [ ] Alla fine del periodo: portal notifica SaaS
- [ ] SaaS mette org in `cancelled`, export dati abilitato per 30gg
- [ ] Dopo 30gg: dati cancellati, org soft-deleted
- [ ] GDPR: customer può richiedere export tutti i dati

---

## F.6 Authentication & SSO across portal/SaaS

### F.6.1 Portal admin login
- [ ] Portal admin NON è lo stesso di SaaS user (repo separati,
      permessi diversi)
- [ ] Portal admin login fallisce se usato con SaaS credentials
- [ ] SaaS user login fallisce con portal credentials
- [ ] Isolamento confermato

### F.6.2 SSO Impersonation (Sprint 6 contract)

**Flusso**: portal admin clicca "Impersonate" su un customer → il portal
minta un JWT HS256 con `aud="saas"`, TTL 60s, claims `{sub:"sentrikat-admin",
tenant_id:<email>, nonce:<uuid>, exp}` → redirect del browser a
`https://app.sentrikat.com/admin/sso?token=<jwt>`.

**Verifica backend** (log SaaS):
- [ ] Portal admin clicca impersonate su `alice@example.com`
- [ ] `docker compose logs sentrikat 2>&1 | grep "SSO impersonation"` mostra
      `SSO impersonation successful user=alice@example.com org=<id> tenant=alice@example.com nonce=<uuid>`
- [ ] Audit log scritto (se `AuditLog` model presente) con
      `reason=sso_from_license_server`, altrimenti log INFO fallback

**Verifica GUI impersonation banner** (Sprint 6 UI):
- [ ] Dopo il redirect, la landing page è il dashboard SaaS (`/`, non `/dashboard`)
- [ ] **In cima a ogni pagina** appare banner **giallo sticky** con testo
      `⚠️ Impersonation active — You are viewing as alice@example.com via SSO
      from the admin portal (by sentrikat-admin)`
- [ ] Il banner ha un bottone `Exit impersonation`
- [ ] Z-index del banner è 10000 (sopra qualunque altro banner)
- [ ] La navigazione normale (dashboard, vulns, reports) funziona
- [ ] Su ogni pagina l'header mostra ancora il banner (è nel base template)

**Verifica Exit impersonation**:
- [ ] Click su `Exit impersonation` → redirect a `/admin/sso/exit`
- [ ] Il session cookie viene clearato (`session.clear()`)
- [ ] Browser landing: pagina di login
- [ ] `docker compose logs sentrikat 2>&1 | grep "impersonation exited"` mostra
      `SSO impersonation exited by=sentrikat-admin`
- [ ] Ritorno al portal admin dalla tab già aperta funziona senza re-auth

### F.6.3 Token abuse
- [ ] Token impersonation scaduto (exp nel passato) → 401 (log: `SSO token expired`)
- [ ] Token riusato con lo stesso nonce → 401 (log: `SSO token replay detected`)
- [ ] Token firmato con secret sbagliato → 401 (log: `SSO token invalid (Signature verification failed)`)
- [ ] Token con `aud` diverso da `"saas"` → 401 (log: `SSO token has wrong audience`)
- [ ] Token con `sub` diverso da `"sentrikat-admin"` → 401 (log: `SSO token missing required claims`)
- [ ] Token per tenant inesistente → 401 (log: `SSO: no admin user resolvable for tenant=...`)

---

## F.7 Webhook reliability (Sprint 6 contract)

### F.7.1 Portal → SaaS webhooks — Sprint 6 event types

Il portal deve inviare **esclusivamente** questi 5 event types con
prefisso `license.*`:

- [ ] `license.plan_changed` — payload `{license_id, license_key, from_edition, from_status, to_edition, to_status, max_agents, subscription_years, reason}`
- [ ] `license.revoked` — payload `{license_id, license_key, edition, reason}`
- [ ] `license.limits_updated` — payload `{license_id, license_key, limits:{max_users, max_products, max_agents, max_organizations, max_storage_gb?, features?}, changed:{...}, reason}` (limits **nested** sotto la key `limits`, non flat)
- [ ] `license.suspended` — payload `{license_id, license_key, stripe_subscription_id, reason}`
- [ ] `license.unsuspended` — payload `{license_id, license_key, reason}`

**Headers richiesti** (tutti e 3 obbligatori):
- [ ] `X-SentriKat-Signature: <hex>` (HMAC-SHA256 del body raw, key=`SENTRIKAT_WEBHOOK_SECRET`)
- [ ] `X-SentriKat-Timestamp: <unix_seconds>` (±300s dal now del SaaS)
- [ ] `X-Idempotency-Key: <uuid>` (dedup per 24h)

**Body contract**:
- [ ] `tenant_id` è **email string**, non integer (es. `"alice@example.com"`)
- [ ] `timestamp` field nel body è ISO-8601 string (informativo, non usato per verifica)

**Verifica comportamento receiver**:
- [ ] Ogni webhook firmato correttamente → 200 con `{received, event_type, tenant_id, idempotency_key, result}`
- [ ] Signature invalida → 401 `{"error":"invalid signature"}`
- [ ] Timestamp skew > 300s → 400 `{"error":"timestamp skew too large"}`
- [ ] Idempotency key mancante → 400
- [ ] Event type con nome vecchio (`plan_updated`, `license_revoked` senza dot) → 400 (legacy names rifiutati, clean break)
- [ ] Portal retry policy: exponential backoff, max 5 tentativi
- [ ] Dopo 5 fail → alert al portal admin + DLQ lato portal

### F.7.2 Webhook GUI visibility — Super-admin page

**Nuova pagina Sprint 6** per ispezionare gli eventi ricevuti senza
entrare nel container:

- [ ] Login come `super_admin@sentrikat.com` (SaaS super-admin)
- [ ] Naviga a `https://app.sentrikat.com/super-admin/webhook-events`
- [ ] Pagina carica con titolo "License Webhook Events Received"
- [ ] Se il portal ha già inviato eventi di test, vedi una tabella con:
  - Colonna "Received" con timestamp UTC
  - Colonna "Event Type" con `license.plan_changed`, `license.revoked`, ecc.
  - Colonna "Tenant" con l'email string
  - Colonna "Idempotency Key" troncata agli 8 caratteri
  - Colonna "Result" con badge `ok` verde + sub-action (`plan_changed`, `limits_updated`)
  - Bottone "Details" per expand → mostra payload JSON completo
- [ ] Click "Details" su una riga → expand con JSON formattato
- [ ] Se nessun evento ricevuto → message "No webhook events received yet"
- [ ] User non super-admin prova ad accedere → **403**
- [ ] Utente anonimo → **403**

### F.7.3 SaaS → Portal usage metering webhook (H7)

**Invio orario automatico** al minuto :05, job registrato come
`usage_metering_upload` sotto scheduler leader lock.

- [ ] Il portal ha endpoint `POST /api/v1/metrics/usage` che ritorna 202 Accepted
- [ ] **URL chiamata dal SaaS**: `{SENTRIKAT_LICENSE_SERVER}/v1/metrics/usage`
      dove `SENTRIKAT_LICENSE_SERVER` è tipicamente `https://license.sentrikat.com/api`
      → URL risultante `https://license.sentrikat.com/api/v1/metrics/usage`
      (⚠️ **NON** `/api/api/v1/metrics/usage` — la base già include `/api`)
- [ ] `Authorization: Bearer <SENTRIKAT_METRICS_KEY>`
- [ ] Body: `{tenant_id, ts, agents_active, products_total, users_active, api_calls_1h, scan_count_1h, storage_bytes}`
  - [ ] `tenant_id` è email string (lookup da `Organization.billing_email` o admin user)
  - [ ] `ts` è ISO-8601 UTC floored all'ora (es. `"2026-04-14T16:00:00Z"`)
- [ ] Trigger manuale del job (senza aspettare :05):
  ```bash
  docker compose exec sentrikat python -c "
  from app import create_app
  from app.scheduler import usage_metering_upload_job
  usage_metering_upload_job(create_app())
  "
  ```
- [ ] Log mostrano `Usage upload OK for tenant <email>: N agents, M products, ts=...` per ogni tenant
- [ ] Log finale: `Usage metering upload complete: N ok, 0 failed (of N tenants)`
- [ ] **Lato portal**: la tabella `usage_metrics` ha righe fresche con `ts=2026-04-14T16:00:00Z`
- [ ] Idempotenza: trigger 2 volte nello stesso minuto → il portal dedupa su `(tenant_id, ts_hour)`

### F.7.4 Usage uploads GUI visibility — Super-admin page

**Nuova pagina Sprint 6** per ispezionare gli upload inviati:

- [ ] Naviga a `https://app.sentrikat.com/super-admin/usage-uploads`
- [ ] Titolo "Usage Metering Uploads"
- [ ] Card "Last Run" con:
  - Timestamp dell'ultimo run
  - N tenant totali / OK / Failed
  - Endpoint URL (deve finire con `/v1/metrics/usage`)
- [ ] Tabella per-tenant con:
  - Tenant ID (email)
  - Last Upload timestamp
  - Status badge (`ok` verde / `failed` rosso)
  - HTTP status code
  - Error message se fail
- [ ] Se nessun upload eseguito → message con istruzioni trigger manuale
- [ ] User non super-admin → **403**
- [ ] Utente anonimo → **403**

### F.7.5 Webhook replay test
- [ ] Cattura payload webhook reale (es. da log portal)
- [ ] Re-inviare stesso `X-Idempotency-Key` → 200 ma con response body cached (il receiver ritorna la stessa result della prima volta, no side effects)
- [ ] Modifica timestamp > 5 min → 400 `{"error":"timestamp skew too large"}`
- [ ] Il replay deve apparire nella pagina `/super-admin/webhook-events` come
      una sola riga (non due) — l'idempotency key è univoca

### F.7.6 License revocation GUI banner (Sprint 6)

**Flusso**: portal invia `license.revoked` → SaaS scrive flag in SystemSettings
→ UI mostra banner rosso sticky all'utente finale.

- [ ] Portal admin revoca la license di `AcmeCorp` → invia webhook `license.revoked`
- [ ] Log SaaS: `license.revoked tenant=... license_id=... reason=...`
- [ ] Log SaaS: `SystemSettings[license_revoked] = true`
- [ ] **Utente di AcmeCorp già loggato** ricarica la dashboard
- [ ] Appare **banner rosso sticky top** con testo
      `❌ Revoked — Your license has been revoked. Contact support.`
- [ ] Il banner è presente su ogni pagina (è nel base template)
- [ ] Z-index 9998 (sotto l'eventuale banner impersonation)
- [ ] Portal invia `license.suspended` (invece di `revoked`)
- [ ] Banner cambia a: `❌ Suspended — Your subscription is suspended due to a
      payment issue. Contact support to restore access.`
- [ ] Portal invia `license.unsuspended` → flag clearato → banner sparisce al refresh

---

## F.8 Multi-tenancy end-to-end

### F.8.1 Isolation between customers
- [ ] Crea 2 customer: AcmeCorp e BetaInc
- [ ] Login come AcmeCorp admin, aggiungi asset "server-acme-1"
- [ ] Login come BetaInc admin, aggiungi asset "server-beta-1"
- [ ] AcmeCorp non vede "server-beta-1" (né in UI né in API)
- [ ] BetaInc non vede "server-acme-1"
- [ ] Prova API diretta: `GET /api/assets/<beta_asset_id>` come Acme
      → 404 (non 403, per non leakare esistenza)
- [ ] Portal admin vede entrambi

### F.8.2 Portal admin scoping
- [ ] Portal ha ruoli: `superadmin`, `support`, `sales`, `readonly`
- [ ] `support` può impersonare ma non cambiare plan
- [ ] `sales` può creare customer ma non vedere dati interni
- [ ] `readonly` solo visualizza
- [ ] Verifica RBAC per ogni ruolo con test manuale

---

## F.9 Data export & GDPR

- [ ] Customer richiede export GDPR dal SaaS
- [ ] SaaS genera ZIP con dati org, salva su S3 temporaneo
- [ ] Link firmato (TTL 24h) inviato via email
- [ ] Portal admin vede la richiesta nel log
- [ ] Customer richiede cancellazione totale
- [ ] Portal admin deve approvare manualmente (evita cancellazioni accidentali)
- [ ] Dopo approvazione, cascade delete su SaaS + portal
- [ ] Audit log entry preservata (solo metadata, non dati)
- [ ] Conferma email inviata

---

## F.10 Disaster recovery cross-repo

### F.10.1 Portal down
- [ ] `docker stop portal-web`
- [ ] SaaS continua a funzionare (licenza cached)
- [ ] Login SaaS funziona (uses cached license)
- [ ] Dopo grace `LICENSE_CHECK_GRACE=24h` → SaaS warn banner
- [ ] Nessuna perdita dati
- [ ] Portal torna online → heartbeat riprende, cache refresh

### F.10.2 SaaS down
- [ ] `docker stop saas-web`
- [ ] Portal admin continua a funzionare
- [ ] Signup nuovi customer: portal bufferizza provisioning, retry al restart
- [ ] Customer vede status page "SaaS degraded"

### F.10.3 Network partition
- [ ] Blocca connettività portal ↔ SaaS con iptables
- [ ] Entrambi continuano a funzionare in standalone
- [ ] Webhook retry queue si riempie su entrambi
- [ ] Sblocca → drain delle code entro 10 min
- [ ] Nessun dato duplicato (idempotency keys funzionano)

---

## F.11 Checklist rapida cross-repo Sprint 6 (sanity E2E)

**10 minuti, go/no-go finale per il contract Sprint 6:**

### Webhook receiver (B3)
- [ ] Portal triggera `license.plan_changed` → appare in `/super-admin/webhook-events` con badge `ok` verde
- [ ] Portal triggera `license.revoked` → banner rosso "Revoked" appare all'utente del tenant
- [ ] Portal triggera `license.suspended` → banner rosso "Suspended"
- [ ] Portal triggera `license.unsuspended` → banner sparisce al refresh
- [ ] Portal triggera `license.limits_updated` → `sub.plan` limits aggiornati nel SaaS DB
- [ ] Replay dello stesso `X-Idempotency-Key` → stessa risposta cached, una sola riga in `/super-admin/webhook-events`

### SSO Impersonation (contract C)
- [ ] Portal admin clicca "Impersonate" → landa su dashboard SaaS (`/`, non `/dashboard`)
- [ ] Banner giallo sticky "Impersonation active — You are viewing as ... (by sentrikat-admin)" visibile
- [ ] Click "Exit impersonation" → session clear + redirect login
- [ ] Token expired (TTL 60s) → 401
- [ ] Token replay (stesso nonce due volte) → seconda volta 401

### Usage metering (H7)
- [ ] Trigger manuale del job → log `Usage upload OK for tenant <email>: N agents, M products, ts=2026-04-14T16:00:00Z`
- [ ] `/super-admin/usage-uploads` mostra "Last Run" con N ok / 0 failed
- [ ] Endpoint mostrato in pagina finisce con `/v1/metrics/usage` (NON `/api/v1/metrics/usage`)
- [ ] Portal vede le righe in `usage_metrics` con stesso `ts` floored all'ora

### Heartbeat (H9)
- [ ] Portal aggiorna `updated_limits` nella response heartbeat → SaaS persiste entro max 12h
- [ ] `max_storage_gb=null` accettato senza errore
- [ ] `features` list applicato a `SubscriptionPlan.features`

### Sanity logs
- [ ] `docker compose logs sentrikat 2>&1 | grep -iE "error|traceback|exception"` → nessun hit non atteso
- [ ] Nessun `invalid signature` nei log (significherebbe secret mismatch)
- [ ] Nessun `status=404` nei log metering (significherebbe URL path sbagliato)
- [ ] Nessun `SSO token invalid` su token legittimi del portal

**Se tutti i check F.11 passano → Sprint 6 chiuso 13/13 e cross-repo integration OK per go-live.**

### Shortcut diagnostici se qualcosa fallisce

| Sintomo | Probabile causa | Fix |
|---|---|---|
| Webhook 401 `invalid signature` | `SENTRIKAT_WEBHOOK_SECRET` diverso ai due lati | Rigenera e sincronizza il secret |
| SSO 401 `wrong audience` | Portal firma con `aud` ≠ `"saas"` | Portal deve usare `aud="saas"` |
| SSO 401 `Signature verification failed` | `SENTRIKAT_SSO_SECRET` diverso | Sincronizza |
| SSO 401 `Not enough segments` | Token troncato nell'URL (padding `=` mangiato) | Portal deve URL-encodare il token |
| SSO 401 `Token is missing the "nonce" claim` | Portal non mette `nonce` nelle claims | Aggiungi claim |
| SSO 302 ma poi 404 | Redirect a `/dashboard` invece di `/` | **Già fixato in Sprint 6** — se succede, pull main |
| Usage upload 404 `{"detail":"Not Found"}` | Path con doppio `/api` o senza `/v1` | Verifica `SENTRIKAT_LICENSE_SERVER` env var |
| Usage upload 401 | `SENTRIKAT_METRICS_KEY` diverso | Sincronizza |
| Event type 400 `unknown event_type` | Portal usa nome vecchio (`plan_updated` senza prefisso `license.`) | Portal deve usare `license.*` names |
| Webhook `tenant_id must be an email string or null` | Portal manda int | Cambia a email string |

---

## Note per il bug tracker

Per ogni fallimento, aprire issue nel repo appropriato:
- Bug nel **flusso di provisioning** → issue in `sbr0nch/SentriKat`
  con label `cross-repo`
- Bug nel **portal UI** o **billing** → issue in `sbr0nch/SentriKat-web`
- Bug nel **contract API** (schema webhook, payload) → issue in
  **entrambi** i repo, linkati tra loro
- Includere sempre:
  - Timestamp
  - Customer ID / License key (anonimizzata)
  - Payload webhook (se applicabile)
  - Log snippet da entrambi i lati
  - Expected vs actual
