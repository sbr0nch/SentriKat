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

## A.2 Utenti di test — copertura ruoli e piani

SentriKat ha **4 ruoli** (`super_admin`, `org_admin`, `manager`, `user`)
e **5 piani SaaS** (`free`, `starter`, `pro`, `business`, `enterprise`).
Per testare davvero ci serve una matrice di account.

### Ruoli per la Part G (cross-tenant)

- [ ] **User A** (Org A, role `org_admin`): email `testA@example.com`,
      organization "Org A" con almeno 10 prodotti + 3 vulnerabilita' KEV
- [ ] **User B** (Org B, role `org_admin`): email `testB@example.com`,
      organization "Org B" con almeno 5 prodotti + 1 vulnerabilita' KEV
- [ ] User A e User B **non condividono** product, asset, match —
      cross-tenant pulito

### Ruoli intra-org (per la Part E / smoke RBAC)

- [ ] **manager@orgA.test** — role `manager` dentro Org A.
      Deve poter creare/modificare prodotti + gestire Integrations
      (Agent Keys, Scheduled Reports, Issue Trackers). **NON** deve
      vedere Users & Access ne' Settings.
- [ ] **viewer@orgA.test** — role `user` dentro Org A. Solo letture:
      Dashboard + tab Inventory in sola visualizzazione. **NON** deve
      vedere bottoni "Add Product", "Approve/Reject" nell'Import Queue,
      "Add Exclusion", "Delete endpoint", ne' Settings / Integrations.

> ⚠️ **Nota importante**: il ruolo `viewer` come label UI **non esiste**
> — nel codice e' semplicemente `role='user'`. Assicurati che l'account
> di test per il viewer abbia davvero `role='user'` nel DB e non
> `role='manager'`, altrimenti vedrai il warning "manager e viewer
> vedono le stesse cose" (e' una misconfigurazione dell'account, non
> un bug).

### Piani (per i gate di plan_features)

- [ ] **free@test** — plan `free`. Per testare i license gate (niente
      email_alerts, webhooks, api_access, compliance).
- [ ] **starter@test** — plan `starter`. Sidebar ridotta: NO Compliance,
      NO SIEM/Syslog, NO Issue Trackers, NO Scheduled Reports.
- [ ] **pro@test** — plan `pro` / Professional. Sidebar "standard" come
      `cliente1@test.com`.
- [ ] **business@test** — plan `business`. Deve vedere IN PIU' rispetto
      a Pro: LDAP/SSO sotto Settings → Authentication, Multi-Tenant
      (assegnazione prodotti cross-org tra le proprie org),
      White-Label (Settings → Appearance), Backup/Restore.
- [ ] **enterprise@test** — plan `enterprise`. Superset di Business con
      limits unlimited. Di solito skip: testato come "tutto come
      Business ma senza limiti".

### Mappa piano → feature (canonica, da `models.py:3718-3837`)

| Feature | Free | Starter | Pro | Business | Enterprise |
|---|:-:|:-:|:-:|:-:|:-:|
| email_alerts | ✗ | ✓ | ✓ | ✓ | ✓ |
| webhooks | ✗ | ✓ | ✓ | ✓ | ✓ |
| api_access | ✗ | ✓ | ✓ | ✓ | ✓ |
| push_agents | ✓ | ✓ | ✓ | ✓ | ✓ |
| compliance_reports (CISA BOD + NIS2) | ✗ | ✗ | ✓ | ✓ | ✓ |
| jira_integration (Issue Trackers) | ✗ | ✗ | ✓ | ✓ | ✓ |
| siem_integration (Syslog/CEF) | ✗ | ✗ | ✓ | ✓ | ✓ |
| audit_export | ✗ | ✗ | ✓ | ✓ | ✓ |
| ldap | ✗ | ✗ | ✗ | ✓ | ✓ |
| sso (SAML) | ✗ | ✗ | ✗ | ✓ | ✓ |
| white_label | ✗ | ✗ | ✗ | ✓ | ✓ |
| backup_restore | ✗ | ✗ | ✗ | ✓ | ✓ |
| multi_org | ✗ | ✗ | ✗ | ✓ | ✓ |

### Limits per piano

| Plan | Agents | Users | Products | API Keys | Storage | Orgs | Price/mo |
|---|---:|---:|---:|---:|---:|---:|---:|
| Free | 3 | 1 | 25 | 1 | 100 MB | 1 | €0 |
| Starter | 10 | 3 | ∞ | 2 | 500 MB | 1 | €59 |
| Pro | 25 | 5 | ∞ | 5 | 2 GB | 1 | €199 |
| Business | 50 | 10 | ∞ | 25 | 10 GB | 10 | €499 |
| Enterprise | ∞ | ∞ | ∞ | ∞ | ∞ | ∞ | €999 |

> 💡 **"Exclusive PDF Reports"** nel marketing = `compliance_reports`
> feature flag nel codice (CISA BOD 22-01 + NIS2). Non e' un flag
> separato.
>
> ⚠️ **Compliance Pack** (€199/mo add-on) e' venduto separatamente
> come paid add-on *oltre* il piano base — vedi
> `models.py::Subscription.addons`. Non incluso in nessun piano di
> default.

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
