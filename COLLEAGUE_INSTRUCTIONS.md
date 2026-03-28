# Istruzioni per il Collega — SentriKat-Web

> Copia-incolla queste istruzioni al collega che lavora su sentrikat-web.
> Aggiornato: 28 Marzo 2026

---

## SITUAZIONE

Il SaaS di SentriKat e' LIVE su `app.sentrikat.com`. Il provisioning automatico
funziona (testato). Ora serve collegare il sito web (sentrikat-web) al SaaS.

Il branch con tutto il codice SaaS e': `claude/create-saas-dual-mode-6pjRo`

## COSA DEVE FARE (in ordine di priorita')

### PRIORITA' 1 — Merge del branch SaaS su main

Il branch `claude/create-saas-dual-mode-6pjRo` contiene gia':
- `license-server/app/api/provision.py` — bridge verso SaaS
- `license-server/app/api/payments.py` — webhook aggiornato con provisioning
- `license-server/app/core/email.py` — template email SaaS welcome
- `nginx/sites/app.conf` — reverse proxy per app.sentrikat.com
- `docker-compose.yml` — env vars per provisioning bridge
- `.env.example` — documentazione variabili

**Azione**: Fare PR del branch su main, review, merge.

### PRIORITA' 2 — Configurare le variabili di ambiente

Sul server VPS #1 (dove gira sentrikat-web), aggiungere al `.env`:

```bash
# SaaS Provisioning Bridge
SAAS_PROVISION_URL=https://app.sentrikat.com/api/provision
SENTRIKAT_PROVISION_KEY=fca98d4f0f29fa732e21e67d102f5b81a76952f04d854d32c1a21712bc75b549
SAAS_BASE_URL=https://app.sentrikat.com
```

**IMPORTANTE**: La `SENTRIKAT_PROVISION_KEY` deve essere IDENTICA a quella
configurata sul server SaaS (VPS #2). Se la cambi su uno, cambiala su entrambi.

### PRIORITA' 3 — Aggiornare i Prezzi nella Landing Page

I prezzi SaaS aggiornati sono:

| Piano | Prezzo Mensile | Prezzo Annuale | Agents |
|-------|---------------|----------------|--------|
| Free | €0 | €0 | 3 |
| Starter | €39/mo | €390/anno | 25 |
| Professional | €99/mo | €990/anno | 100 |
| Business | €249/mo | €2,490/anno | 500 |
| Enterprise | €499/mo | €4,990/anno | Illimitati |

**File da modificare**: `landing/src/pages/pricing.astro` (o equivalente)

Per ora il pricing SaaS puo' mostrare "Coming Soon" o "Contact Us".
La pagina on-premise resta come e' (Demo gratis + Pro €2,499/anno).

### PRIORITA' 4 — Aggiornare il Portal Admin

Il portale admin (`portal/`) deve mostrare:

1. **Lista tenant SaaS** — chiamare `GET /api/provision/status?email=...`
   oppure creare un endpoint admin che lista tutti i tenant
2. **Stato subscription** — piano attivo, data scadenza, usage
3. **Azioni rapide** — upgrade/downgrade manuale, suspend/reattiva

Per ora basta una sezione "SaaS Tenants" nel pannello admin che mostra
i dati dalla tabella `subscriptions` del database SaaS.

### PRIORITA' 5 — Security Fix (fare comunque)

1. `landing/` — `npm audit fix` per aggiornare dipendenze vulnerabili
2. `portal/` — `npm audit fix` per aggiornare dipendenze vulnerabili
3. `license-server/` — aggiungere rate limiting su `/api/activate` e `/api/verify`
   (usare `slowapi`, gia' in requirements.txt)
4. `docker-compose.yml` — rimuovere porte esposte dei servizi interni
   (solo nginx 80/443 deve essere pubblico)

### PRIORITA' 6 — Testare il Flusso End-to-End

**Test con Stripe Test Mode:**

1. Assicurarsi che `STRIPE_SECRET_KEY=sk_test_...` sia configurato
2. Creare un checkout session di test
3. Completare il pagamento con carta di test `4242 4242 4242 4242`
4. Verificare che:
   - Il webhook riceva `checkout.session.completed`
   - `provision_saas_tenant()` venga chiamato
   - Il tenant venga creato su `app.sentrikat.com`
   - L'email welcome venga inviata

**Stripe CLI per test locale:**
```bash
stripe listen --forward-to localhost:8000/api/v1/payments/webhook
stripe trigger checkout.session.completed
```

### PRIORITA' 7 — Switch Stripe a Live (quando Denis da' OK)

1. Sostituire `STRIPE_SECRET_KEY` da `sk_test_` a `sk_live_`
2. Sostituire `STRIPE_WEBHOOK_SECRET` da `whsec_test_` a `whsec_live_`
3. Creare il webhook endpoint live su Stripe Dashboard:
   `https://api.sentrikat.com/api/v1/payments/webhook`
4. Testare con un pagamento reale di piccolo importo
5. Verificare che il provisioning funzioni anche con Stripe live

---

## ARCHITETTURA DI RIFERIMENTO

```
Flusso Pagamento → Provisioning:

Browser                  VPS #1                        VPS #2
(Cliente)                (sentrikat-web)               (SaaS app)
                                                       app.sentrikat.com
    │                         │                              │
    │  1. Click "Buy"         │                              │
    ├────────────────────────>│                              │
    │                         │                              │
    │  2. Stripe Checkout     │                              │
    │<────────────────────────│                              │
    │                         │                              │
    │  3. Pagamento           │                              │
    ├───> Stripe ────────────>│  4. Webhook received         │
    │                         │                              │
    │                         │  5. POST /api/provision      │
    │                         ├─────────────────────────────>│
    │                         │                              │  6. Crea org+user
    │                         │  7. Response {credentials}   │
    │                         │<─────────────────────────────│
    │                         │                              │
    │  8. Email welcome       │                              │
    │<────────────────────────│                              │
    │                         │                              │
    │  9. Login               │                              │
    ├────────────────────────────────────────────────────────>│
    │                         │                              │
```

## NOTE

- Il branch SaaS su sentrikat-web (`claude/create-saas-dual-mode-6pjRo`) e'
  gia' pronto e testato a livello di codice
- Il provisioning bridge e' un "fire and forget" sicuro: se fallisce,
  la licenza on-premise viene comunque creata (fallback)
- NON attivare Stripe live senza conferma di Denis
- Tutte le comunicazioni tra VPS #1 e VPS #2 passano via HTTPS
