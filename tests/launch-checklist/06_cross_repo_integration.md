# 06 — Cross-Repo Integration: SaaS ↔ Admin Portal / License Server (Part F)

> **Durata:** 2-3h. **Priorità:** 🔴 Obbligatoria prima del go-live.
>
> Questa parte testa i flussi end-to-end tra **SentriKat SaaS**
> (questo repo) e **SentriKat-web** (repo `sbr0nch/SentriKat-web` —
> admin portal + license server + billing/marketing site).
>
> **Prereq**: entrambi gli ambienti devono essere deployati e collegati
> (stessa `LICENSE_SERVER_URL`, stesso `LICENSE_SERVER_API_KEY`,
> webhook secret condiviso).
>
> **Convenzione:** ogni test descrive
> 1. **Azione** (dove la fai)
> 2. **Verifica lato portal** (SentriKat-web admin)
> 3. **Verifica lato SaaS** (questo repo)
> 4. **Verifica DB / logs** (sanity check)

---

## F.0 Setup iniziale (una volta sola)

- [ ] Portal admin raggiungibile: `https://admin.sentrikat.com` (o URL di staging)
- [ ] SaaS raggiungibile: `https://app.sentrikat.com`
- [ ] DNS risolve entrambi
- [ ] TLS valido su entrambi (no cert warnings)
- [ ] Portal `.env` ha `SAAS_CALLBACK_URL` puntato al SaaS
- [ ] SaaS `.env` ha `LICENSE_SERVER_URL` puntato al portal
- [ ] `LICENSE_SERVER_API_KEY` identico su entrambi i lati
- [ ] Webhook shared secret identico (per firma HMAC)
- [ ] Portal ha superadmin account creato (`portal_admin@sentrikat.com`)
- [ ] SaaS ha super-admin locale (`saas_admin@sentrikat.com`) — solo fallback
- [ ] Stripe / billing provider in **test mode** per questa sessione
- [ ] Logs in real-time: `tail -f` su `portal.log` e `saas.log` in due terminali

---

## F.1 Customer Signup (Portal → SaaS provisioning)

**Flusso**: un potenziale cliente si registra sul portale, il portale
crea l'organizzazione sul SaaS, invia credenziali email.

### F.1.1 Self-service signup
- [ ] Apri `https://sentrikat.com/signup` (marketing site) in incognito
- [ ] Compila form: company name, email admin, password, plan=**Free Trial**
- [ ] Check email verification: arriva email con link
- [ ] Click verify → redirect a portal customer dashboard
- [ ] **Portal admin panel** (`/admin/customers`): nuova row "AcmeCorp"
      status=`active`, plan=`trial`, trial_ends_at = +14 giorni
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
- [ ] Compila: company, admin email, plan=**Professional**, seats=50
- [ ] Submit → portal crea org sul SaaS via API `/api/provision`
- [ ] **Verifica portal**: customer status=`active`
- [ ] **Verifica SaaS**: org appare con plan=professional, seat_limit=50
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
- [ ] Scegli customer "AcmeCorp" (trial)
- [ ] Portal `/admin/customers/acmecorp/edit` → cambia plan da
      `trial` a `professional`, seats da 5 a 50
- [ ] Salva → portal chiama SaaS `PATCH /api/license/<license_key>`
- [ ] **Verifica SaaS**: `/super-admin/organizations/acmecorp`
      mostra plan=professional, seat_limit=50, expires_at rinnovato
- [ ] Login come user AcmeCorp sul SaaS → banner "You are on Professional"
- [ ] Feature limits aggiornate: puoi aggiungere più asset (fino al nuovo
      limite), vedi feature prima gated
- [ ] Audit log sul SaaS ha entry `plan_changed`
- [ ] Audit log sul portal ha entry `plan_updated`
- [ ] Timestamps corrispondono (±1 sec)

### F.2.2 Downgrade plan
- [ ] Customer "AcmeCorp" ora su Professional con 45/50 asset usati
- [ ] Portal: downgrade a `Starter` (limite 20 asset)
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
- [ ] Customer su Starter (20 asset) supera a 22 asset
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
- [ ] **Verifica SaaS**: user vede "You are on Professional"
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

### F.6.2 Impersonation (support flow)
- [ ] Portal admin su customer detail → "Login as customer admin"
- [ ] Genera one-time token firmato, redirect al SaaS con token
- [ ] SaaS valida token (firma HMAC + TTL 60s)
- [ ] Session creata con user customer, marcata `impersonated_by=portal_admin_id`
- [ ] Banner giallo sticky: "You are impersonating Acme Admin. [Exit]"
- [ ] Tutte le azioni loggate con `actor=portal_admin, on_behalf_of=customer_admin`
- [ ] Exit impersonation → torna al portal admin
- [ ] Audit log su entrambi i lati

### F.6.3 Token abuse
- [ ] Token impersonation scaduto → rifiutato
- [ ] Token riusato (replay) → rifiutato (one-time nonce)
- [ ] Token firmato con chiave sbagliata → rifiutato
- [ ] Log security alert su tentativi falliti

---

## F.7 Webhook reliability

### F.7.1 Portal → SaaS webhooks
- [ ] Lista webhook: `plan_changed`, `license_revoked`, `customer_updated`,
      `feature_flag_changed`, `billing_status_changed`
- [ ] Ogni webhook firmato HMAC-SHA256 con shared secret
- [ ] SaaS valida firma, rifiuta payload non firmati (401)
- [ ] SaaS risponde 200 in < 5s
- [ ] Portal retry policy: exponential backoff, max 5 tentativi
- [ ] Dopo 5 fail → alert al portal admin + DLQ (dead letter queue)
- [ ] DLQ manualmente reprocessabile dal portal admin

### F.7.2 SaaS → Portal webhooks
- [ ] `usage_reported`, `trial_expired`, `threshold_reached`, `critical_vuln_detected`
- [ ] Stesso schema firma/retry
- [ ] Portal valida
- [ ] Idempotency key (UUID) previene duplicati

### F.7.3 Webhook replay test
- [ ] Cattura payload webhook reale
- [ ] Re-inviare stesso payload → rifiutato per idempotency
- [ ] Modifica timestamp > 5 min → rifiutato per replay protection

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

## F.11 Checklist rapida cross-repo (sanity E2E)

**5 minuti, go/no-go finale:**

- [ ] Signup nuovo customer dal portale → login SaaS funziona
- [ ] Plan change sul portale → SaaS recepisce entro 5 min
- [ ] Suspend customer → SaaS blocca accesso entro grace
- [ ] Unsuspend → SaaS riabilita
- [ ] Impersonate da portal → funziona con banner
- [ ] Usage metrics visibili sul portale
- [ ] Invoice generata dopo upgrade
- [ ] Webhook delivery log pulito (no 500, no retry pending)
- [ ] Nessun errore nei log di entrambi i servizi

**Se tutti i check F.11 passano → cross-repo integration OK per go-live.**

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
