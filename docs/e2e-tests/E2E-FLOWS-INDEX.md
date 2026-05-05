# E2E Flow Test Index — SentriKat

> Successore funzionale di `00-INDEX.md` per la fase **E2E flow validation**.
>
> `00-INDEX.md` traccia bug discovery (functional component testing). Questo
> file traccia se i flussi end-to-end del prodotto **funzionano davvero da
> capo a coda con dati realistici**.
>
> Pre-requisito di esecuzione: aver lanciato `scripts/seed_e2e_dev.py` per
> popolare DB on-prem con 5 asset + 10 product + 30 vuln + matches.
>
> **Naming convention**: `{AREA}-{N}` dove AREA ∈ {AG, VM, RB, PA, PC, SY, IN, AD}.
> AG=Agent · VM=Vulnerability Mgmt · RB=RBAC · PA=Portal Admin · PC=Portal Customer
> SY=Sync · IN=Integrations · AD=Admin ops

---

## Stato globale

| Area | Flussi totali | ✅ Done | 🔧 Partial | ❌ Not started | ⏸️ Blocked |
|---|---|---|---|---|---|
| AG (Agent) | 7 | 0 | 1 | 6 | 0 |
| VM (Vulnerability Mgmt) | 6 | 0 | 1 | 5 | 0 |
| RB (RBAC) | 5 | 0 | 2 | 3 | 0 |
| PA (Portal Admin web) | 5 | 0 | 1 | 4 | 0 |
| PC (Portal Customer web) | 6 | 0 | 2 | 4 | 0 |
| SY (Sync/Schedule) | 6 | 0 | 1 | 5 | 0 |
| IN (Integrations) | 5 | 0 | 0 | 5 | 0 |
| AD (Admin ops) | 6 | 0 | 0 | 6 | 0 |
| **Totale** | **46** | **0** | **8** | **38** | **0** |

Coverage E2E flow attuale: **0%** done + **17%** partial. **83% mai testato**.

---

## 🤖 AG — Agent flows

### `AG-1` Download agent script (Windows/Linux/macOS) dalla UI
- **Pre**: login admin → Integrations → Agent Keys → "Create API Key"
- **Steps**:
  1. Click su icona download Windows → atteso: `.ps1` file scaricato con API key e SENTRIKAT_URL injected
  2. Click Linux → `.sh` con stessi parametri
  3. Click macOS → `.sh` per macOS
- **Verify**: ognuno script contiene `Bearer ${API_KEY}` e URL corretto, niente placeholder
- **Stato**: 🔧 partial (UI testata in `[06.10.x]`, download funzionale, **install reale mai eseguito**)
- **Bloccante post-status**: serve macchina Windows/Linux/macOS reale per AG-2

### `AG-2` Install agent → first heartbeat
- **Pre**: AG-1 done + macchina target raggiungibile
- **Steps**:
  1. Eseguire script su target machine (con privilegi admin)
  2. Lo script installa SentriKat-Agent come servizio (Windows) / systemd unit (Linux) / launchd (macOS)
  3. Primo POST a `/api/agent/heartbeat` parte automaticamente
- **Verify**:
  - In SentriKat UI → Inventory → Endpoints: nuovo asset visibile con hostname target
  - `last_checkin` aggiornato negli ultimi 60s
  - Agent log su target macchina: `Connected to {SENTRIKAT_URL}, agent_id=xxx`
- **Stato**: ❌ not started
- **Bloccante**: Pro license per Push Agents (`[03.13.2]`)
- **Workaround dev**: chiamare l'endpoint heartbeat manualmente via curl con API key + dati fake

### `AG-3` Inventory scan → POST `/api/agent/inventory`
- **Pre**: AG-2 done
- **Steps**:
  1. Su target machine: `sudo systemctl restart sentrikat-agent` (forza scan)
  2. Agent esegue inventory locale (apt list / dnf list / dpkg / wmic) e fa POST con payload JSON
- **Verify**:
  - Worker pool processa il job (logs `application.log`: "Processing inventory for asset_id=N")
  - `product_installations` table popolata con i prodotti scoperti
- **Stato**: ❌ not started
- **Bloccante**: AG-2

### `AG-4` Worker pool process inventory → DB write
- **Pre**: AG-3 in flight
- **Verify**:
  - InventoryJob row con status=processing → completed
  - `Asset.last_inventory_at` aggiornato
  - `ProductInstallation.last_seen_at` per ogni prodotto trovato
- **Stato**: ❌ not started

### `AG-5` CVE matching → vulnerability rows created
- **Pre**: AG-4 done + vulnerability data presenti (CISA sync già done)
- **Verify**:
  - VulnerabilityMatch table cresce per ogni Product matched
  - `is_vulnerable=True` su ProductInstallation se almeno 1 match
  - Dashboard counter "Active vulnerabilities" cresce
- **Stato**: ❌ not started

### `AG-6` Agent offline detection (>15 min no heartbeat)
- **Pre**: AG-2 done
- **Steps**:
  1. Stoppare il servizio agent su target
  2. Aspettare > 15 min (o cambiare `AGENT_OFFLINE_THRESHOLD_MIN`)
- **Verify**:
  - Scheduler job "Agent Offline Detection" tick → flag asset.active=False o similar
  - Dashboard Inventory mostra badge "OFFLINE" o "STALE"
- **Stato**: ❌ not started

### `AG-7` Agent reinstall + key rotation
- **Pre**: AG-2 done
- **Steps**:
  1. Admin → Agent Keys → "Rotate" su key esistente
  2. Re-install agent su target con nuova key
- **Verify**:
  - Vecchia key usage_count smette di crescere
  - Nuova key usage_count cresce dal momento della reinstall
  - Asset rimane lo stesso (basato su agent_id, non key)
- **Stato**: ❌ not started

---

## 🔍 VM — Vulnerability Management flows

### `VM-1` CVE list pagination + filter
- **Pre**: seed_e2e_dev.py done (30 vuln in DB)
- **Steps**:
  1. Login admin → Vulnerabilities (sidebar)
  2. Lista 30 CVE-2099-* visibili
  3. Filter by severity: select "CRITICAL" → solo i CRITICAL mostrati
  4. Filter by date_added range
  5. Pagination: 25/page, click pagina 2
- **Verify**: counter totale, filter chip visibili, pagination funzionante
- **Stato**: 🔧 partial (testato con 0 data, mai con data)

### `VM-2` CVE detail view → affected endpoints
- **Pre**: seed done, VM-1 ok
- **Steps**:
  1. Click su CVE-2099-10000 → modal/page detail
  2. Sezione "Affected products" → 1+ prodotti listati
  3. Sezione "Affected endpoints" → asset linkati via product_installation
- **Verify**: counter affected_endpoints, link cliccabili, navigazione bidirezionale (asset → CVE)
- **Stato**: ❌ not started

### `VM-3` Mark CVE as resolved/false-positive/accepted
- **Pre**: seed done
- **Steps**:
  1. Vulnerabilities list → click su un row → action "Acknowledge"
  2. Action "Mark resolved" + commento
  3. Action "False positive" + reason
- **Verify**:
  - DB: `VulnerabilityMatch.acknowledged=True`, `resolution_status='resolved'`, ecc.
  - Audit log riga creata
  - Dashboard counter aggiornato
- **Stato**: ❌ not started

### `VM-4` Bulk operations (assign, prioritize, archive)
- **Pre**: seed done
- **Steps**:
  1. Vulnerabilities list → checkbox 5+ row
  2. Bulk toolbar appare → "Assign to user" / "Set priority" / "Archive"
- **Verify**: 5 record updated atomically, audit log con singolo bulk event
- **Stato**: ❌ not started

### `VM-5` Compliance report PDF/JSON/CSV con dati reali
- **Pre**: seed done
- **Steps**:
  1. Settings → Compliance → "Generate report" preset (NIST, SOC2, ecc.)
  2. Export JSON → file scaricato
  3. Export PDF → file scaricato
  4. Export CSV → file scaricato
- **Verify**:
  - File contiene 30 vuln + 5 asset + statistiche
  - Niente vuoto sui template
  - Schema JSON valido (parsabile via `jq`)
- **Stato**: ❌ not started

### `VM-6` Email digest CVE alert
- **Pre**: seed done + SMTP configurato (Mailpit) + alert recipients
- **Steps**:
  1. Settings → Alerts → "Send Email Alerts Now" (manual trigger)
  2. Aspettare delivery
- **Verify**: email arriva su Mailpit con subject `[ALERT] N new vulnerabilities`, lista CVE leggibile
- **Stato**: ❌ not started

---

## 👥 RB — RBAC flows

### `RB-1` Super_admin → multi-tenant view
- **Pre**: 2+ org + dati per org (seed può creare 2nd org se esteso)
- **Steps**:
  1. Login super_admin
  2. Org switcher dropdown → vedi tutte le org
  3. Switch tra org → dashboard mostra dati org corrente
- **Stato**: 🔧 partial (1 org testata)

### `RB-2` Org_admin → vede solo sua org
- **Pre**: 2 org, 1 user con role=org_admin in org1
- **Steps**:
  1. Login org_admin
  2. Org switcher → solo org1 visibile
  3. URL hack `/admin?org_id=2` → 403
- **Stato**: 🔧 partial (Community 1-user blocca creazione 2nd user)
- **Workaround**: temporanea Pro license + manual user creation

### `RB-3` User → vede solo i suoi assignments
- **Pre**: assignment data + user normale loggato
- **Stato**: ❌ not started

### `RB-4` Cross-org isolation (security)
- **Pre**: 2 org con dati diversi
- **Steps**:
  1. Login user di org1
  2. Tentare GET `/api/products/{id_di_prodotto_org2}` → 403/404
  3. Stesso per asset, vuln, assignment, user
- **Stato**: ❌ not started

### `RB-5` Role downgrade after revoke
- **Pre**: user con role=org_admin
- **Steps**:
  1. Super_admin revoca ruolo → user diventa "user"
  2. User refresh pagina admin-only → 403 + redirect home
- **Stato**: ❌ not started

---

## 🏛 PA — Portal Admin (web) flows

> Accesso `https://portal.sentrikat.com/admin` con bearer `ADMIN_API_KEY`.
> Cross-repo: gira su `sentrikat-web` deployment.

### `PA-1` Login admin portal con OTP
- **Stato**: 🔧 partial (OTP arriva via fix `[04.1.3]`, dashboard mai vista con dati reali)

### `PA-2` Dashboard tenants list con dati
- **Pre**: tenant in license-server DB (seed-side?)
- **Stato**: ❌ not started

### `PA-3` Drill into singolo tenant view
- **Stato**: ❌ not started

### `PA-4` Push KB update / CVE feed sync
- **Stato**: ❌ not started — cross-repo flow

### `PA-5` Release publish + auto-sync to on-prem
- **Stato**: ❌ not started — cross-repo flow

---

## 🛒 PC — Portal Customer (web) flows

> `https://portal.sentrikat.com` consumer-facing.
> Cross-repo: gira su `sentrikat-web` deployment.

### `PC-1` Signup → email verify → trial start
- **Stato**: ✅ verified (`[02.x]` cluster) — può servire come baseline

### `PC-2` Login portal customer → dashboard
- **Stato**: 🔧 partial (OTP fix verified, dashboard con dati mai vista)

### `PC-3` License page → activate/upgrade flow
- **Stato**: ❌ not started — serve test purchase flow

### `PC-4` Download installer agent dalla portal
- **Stato**: ❌ not started

### `PC-5` Support ticket form
- **Stato**: ❌ not started

### `PC-6` Account billing / invoice
- **Stato**: ❌ not started

---

## 🔄 SY — Sync/Schedule flows

### `SY-1` CISA daily sync trigger → vuln updates
- **Stato**: 🔧 partial (trigger funziona, downstream verifica con data mai fatta)

### `SY-2` NVD enrichment (CVSS update)
- **Pre**: NVD API key
- **Stato**: ❌ not started

### `SY-3` EPSS score refresh
- **Stato**: ❌ not started

### `SY-4` KB sync (CPE mapping) from license-server
- **Stato**: ❌ not started — cross-repo flow

### `SY-5` License heartbeat to license-server
- **Stato**: ❌ not started — cross-repo flow

### `SY-6` Usage metering upload
- **Stato**: ❌ not started — cross-repo flow

---

## 🔌 IN — Integration flows

### `IN-1` Jira create issue from CVE
- **Pre**: Jira testlab MockServer + integration configurato
- **Stato**: ❌ not started (config testato in `[03.11.4]`, end-to-end create mai fatto)

### `IN-2` Webhook outgoing on alert
- **Pre**: webhook-tester testlab + integration on
- **Stato**: ❌ not started

### `IN-3` LDAP user auto-provision on login
- **Pre**: testlab Keycloak/OpenLDAP
- **Stato**: ❌ not started

### `IN-4` SAML SSO login → user creation
- **Pre**: SAML config + Keycloak realm
- **Stato**: 🔧 partial (license-block path verified `[03.14.21]`, success path mai testato)

### `IN-5` Syslog forwarding alert events
- **Pre**: syslog testlab
- **Stato**: ❌ not started

---

## 🛠 AD — Admin ops flows

### `AD-1` Backup creation + restore
- **Stato**: ❌ not started

### `AD-2` Audit log search + filter + export
- **Pre**: audit log popolato (events da seed o real activity)
- **Stato**: ❌ not started

### `AD-3` Agent key rotate + revoke
- **Stato**: ❌ not started

### `AD-4` Service catalog import (CSV/JSON)
- **Stato**: ❌ not started

### `AD-5` Health check manual run + remediation
- **Stato**: 🔧 partial (manual run testato, remediation mai)

### `AD-6` Settings export/import (preset migration)
- **Stato**: ❌ not started

---

## Esecuzione roadmap

### Sessione 1 (post seed) — **2-3h**
Sblocca tutti i flussi VM-x:
- VM-1, VM-2, VM-3, VM-4
- AD-2 (audit log dovrebbe popolare)

### Sessione 2 — **2h**
Health + report:
- VM-5 (compliance report con seed data)
- VM-6 (email digest, serve SMTP)
- AD-5 remediation

### Sessione 3 — Pro license + Agent — **3-4h**
- AG-1 (verify download), AG-2 (install reale o curl mock), AG-3, AG-4, AG-5
- AG-6 (offline detection) e AG-7 (rotate)

### Sessione 4 — Cross-repo — **2-3h** (richiede sentrikat-web running)
- PA-1, PA-2, PA-3
- PC-2, PC-3 (dipende da test purchase)
- SY-4, SY-5, SY-6

### Sessione 5 — Integrations + RBAC — **2-3h**
- IN-1, IN-2, IN-3, IN-4, IN-5
- RB-3, RB-4, RB-5

### Sessione 6 — Admin ops finali — **1-2h**
- AD-1 backup/restore
- AD-3 key rotate
- AD-4 catalog import
- AD-6 settings export

**Totale**: 12-17h spalmate in 6 sessioni di test.

---

## Convenzione di tracking

Quando esegui un flusso:
1. Cambia stato qui da ❌ a 🔧 (in progress) o ✅ (passed) o 🔴 (bug found)
2. Se 🔴, crea bug `[NN.X.Y]` in `00-INDEX.md` referenziando il flow ID (es. `Discovered during VM-3`)
3. Aggiorna counter top
4. Commit con messaggio `docs(e2e-flow): {ID} {esito} {dettaglio}`
