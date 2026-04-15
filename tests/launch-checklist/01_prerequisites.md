# 01 — Prerequisites (Part A)

> **Durata:** 10 min. **Priorita':** 🔴 Obbligatoria. Senza questi
> prerequisiti non puoi nemmeno iniziare a testare.

---

## A.1 Istanza di test accessibile

- [ ] L'istanza SentriKat e' raggiungibile su HTTPS, es.
      `https://app.sentrikat.com` o `https://staging.sentrikat.com`
- [ ] `curl -sk $BASE/api/health` ritorna `{"status":"healthy",...}` con HTTP 200
- [ ] La dashboard apre nel browser senza errori nella console JavaScript.
      💡 In modalita' SaaS (org_admin non super_admin) il box "Last Sync" non
      viene renderizzato: il codice gia' salta la chiamata se l'elemento non
      esiste, quindi la console deve essere pulita. Un errore
      `loadLastSync ... innerHTML null` indica una regressione — fixala.
- [ ] Il container `sentrikat` e' in stato `healthy`:
      ```bash
      docker compose ps sentrikat
      ```

## A.2 Due utenti di test (per il cross-tenant della Part G)

- [ ] **User A** (Org A): email `testA@example.com`, password nota,
      organization "Org A" con almeno 10 prodotti + 3 vulnerabilita' KEV
- [ ] **User B** (Org B): email `testB@example.com`, password nota,
      organization "Org B" con almeno 5 prodotti + 1 vulnerabilita' KEV
- [ ] User A e User B **non condividono** product, asset, match —
      cross-tenant pulito
- [ ] Almeno un terzo utente (User C, Free tier) per testare i license gate

## A.3 Strumenti locali sulla tua macchina

- [ ] `curl` installato
- [ ] `python3` con `json.tool` (pretty print)
- [ ] Un secondo browser (Chrome + Firefox, oppure Firefox + Safari)
- [ ] Un terminale SSH aperto sulla VM (per `docker compose logs`)
- [ ] Accesso al pannello Stripe test mode (per la Part F — cross-repo)
- [ ] Accesso al license server admin panel
      (`https://api.sentrikat.com/admin` o equivalente)

## A.4 Backup completo del DB di produzione (non negoziabile)

- [ ] Backup eseguito e salvato off-box:
      ```bash
      docker compose exec -T db pg_dump -U sentrikat sentrikat \
          > ~/sentrikat-backup-$(date +%Y%m%d-%H%M).sql
      ```
- [ ] Dimensione verificata `ls -lh ~/sentrikat-backup-*.sql` > 1 MB,
      non 0 bytes
- [ ] Procedura di restore testata su staging almeno una volta:
      ```bash
      docker compose exec -T db psql -U sentrikat -d sentrikat < backup.sql
      ```
- [ ] Backup del license-server DB eseguito (pgdump separato per il
      DB di sentrikat-web)

## A.5 Variabili shell per i test curl

```bash
# Incollale nel tuo terminale prima di fare gli smoke test
export BASE="https://app.sentrikat.com"              # dominio SaaS
export LICENSE_BASE="https://api.sentrikat.com"      # license server
export PORTAL_BASE="https://portal.sentrikat.com"    # customer portal
export LANDING_BASE="https://sentrikat.com"          # landing marketing

# Dopo aver fatto login in browser come User A:
# DevTools > Application > Cookies > copia il valore di 'session'
export COOKIE_A="session=IL_COOKIE_DI_USER_A"
export COOKIE_B="session=IL_COOKIE_DI_USER_B"
export COOKIE_FREE="session=IL_COOKIE_DI_USER_C_FREE"

# Admin API key del license server (dal .env del sentrikat-web)
export LICENSE_ADMIN_KEY="la_admin_api_key_del_license_server"
```

- [ ] Tutte le variabili sopra esportate nel tuo terminale corrente
- [ ] `echo $BASE` e `echo $COOKIE_A` ritornano valori non vuoti

## A.6 Rollback plan pronto

- [ ] Hai salvato il SHA dell'ultimo commit "buono" prima del lancio:
      `git log --oneline -1`
- [ ] Sai come tornare al commit precedente + applicare
      `migrations/sprint4_sprint5/rollback.sql` se serve
- [ ] Hai il numero di telefono di chi ti puo' aiutare (amico tecnico,
      partner, anche solo per non essere solo durante il disastro)

---

## ✅ Gate A

Tutti i check sopra sono verdi? Se si' → vai a
[`02_smoke_test_critical_path.md`](02_smoke_test_critical_path.md).

Se NO → fermati, sistema, poi torna qui.
