# Fase 06 — App SaaS core auth / RBAC / user management (`app.sentrikat.com`)

> Test del prodotto SaaS core (Flask app in repo `sbr0nch/SentriKat` con `SENTRIKAT_MODE=saas`). Auth con password locale + force change al primo login (non OTP come portal). Include user management (All Users), RBAC matrix (super_admin/org_admin/manager/user).
>
> **Account disponibili su questo tenant Starter EA** (quota 3/3 users dopo oggi):
> - `muscleaddiction49@gmail.com` — super_admin, password `TestPass123!` (creata in fase 02)
> - `sentrikat@gmail.com` — role `manager` (creato oggi ma **email invite non arrivata** → non loggabile)
> - Third user creato con role `user` (email invite non arrivata, stesso pattern)

## Aree coperte

| Area | Descrizione |
|---|---|
| 06.1 | Login happy path + session persistence |
| 06.2 | Sidebar mapping super_admin Starter EA |
| 06.3 | Users & Access — CRUD users |
| 06.4 | User invite email delivery (NEW bug dedicated) |
| 06.5 | Limit enforcement quota 3/3 users |
| 06.6 | RBAC matrix dim 4 (role → sidebar + permissions) — ⏸️ BLOCKED da 06.4 |
| 06.7 | State transitions user (disable/block/delete) — dim 5 |
| 06.8 | Dashboard SaaS Starter dettaglio |
| 06.9 | Assignments page |
| 06.10 | Products sub-pages (List, Endpoints, Containers, Dependencies, Import Queue, SBOM Export, Exclusions) |
| 06.11 | Settings → Alert Management |
| 06.12 | Settings → Email & Notifications |
| 06.13 | Settings → Subscription (già in 02.7.12, riprendere con 7-dim) |
| 06.14 | Negative/edge: email malformate, role invalidi, XSS/SQL injection nei form |

---

## 06.1 — Login happy path ✅

### [06.1.1] Login super_admin SaaS Starter ✅

- **Fase**: 06 · **Area**: Login
- **Deployment scope**: ☁️ SaaS
- **Tipo**: 🟢 OK (dim 1 Happy)
- **Actual**:
  - Login `app.sentrikat.com/login` con `muscleaddiction49@gmail.com` + `TestPass123!` → dashboard
  - Dashboard empty data (no CVE, no product — ambiente fresco Starter EA)
  - Top-right: email + badge confermati
- **Persistence (dim 2)**: session cookie persiste dal login di fase 02 — da verificare separatamente con logout+login
- **Discovered**: 2026-04-25

---

## 06.2 — Sidebar super_admin SaaS Starter (baseline)

### [06.2.1] Mappa sidebar SaaS Starter vs on-prem DEMO/Community ✅

- **Fase**: 06 · **Area**: Sidebar mapping
- **Deployment scope**: ☁️ SaaS
- **Tipo**: 🟢 OK + 🔵 Info (mappatura comparativa)
- **Mappa osservata (super_admin SaaS Starter EA)**:

```
Overview
  - Dashboard
  - Assignments

Inventory
  - Products ▼
    - Products List
    - Endpoints
    - Containers
    - Dependencies
    - Import Queue
    - SBOM Export
    - Exclusions

Management
  - Users & Access ▼
    - All Users
    (NO "Organizations")

Integrations
  - Integrations ▼
    - Agent Keys
    - Agent Activity
    (NO Scheduled Reports, NO Issue Trackers)

System
  - Settings ▼
    - Alert Management
    - Email & Notifications
    - Subscription
    (NO Authentication/LDAP/SAML, NO SIEM/Syslog, NO System, NO Compliance, NO Appearance, NO License, NO Health Checks, NO System Logs, NO Admin Guide)
```

- **Confronto con on-prem super_admin Community** [03.7.1]:

| Voce | On-prem Community | SaaS Starter EA |
|---|---|---|
| Overview (Dashboard, Assignments) | ✅ | ✅ |
| Products (7 sub) | ✅ | ✅ (identici) |
| Organizations | ✅ | ❌ (single-tenant forced in SaaS Starter) |
| All Users | ✅ | ✅ |
| Agent Keys | ✅ | ✅ |
| Agent Activity | ✅ | ✅ |
| Scheduled Reports | ✅ | ❌ (Pro+ only atteso) |
| Issue Trackers | ✅ | ❌ (Pro+) |
| Authentication (LDAP/SAML) | ✅ | ❌ (LDAP Pro, SAML Business) |
| SIEM / Syslog | ✅ | ❌ (Pro+) |
| System (sub-tabs General/Security/Data Retention) | ✅ | ❌ |
| Compliance Reports | ✅ | ❌ (NIS2/BOD Pro+) |
| Appearance | ✅ | ❌ (white-label Business+) |
| License | ✅ | ❌ (managed by billing on SaaS) |
| Health Checks | ✅ | ❌ |
| System Logs | ✅ | ❌ |
| Admin Guide | ✅ | ❌ |
| **Platform Operations** | ⚠️ visibile (bug [03.6.6]) | ✅ **non visibile** (correct!) |
| Alert Management | ❌ (sotto altra voce in on-prem) | ✅ |
| Email & Notifications | ❌ (sotto "Email (SMTP)" on-prem) | ✅ |
| Subscription | ❌ (on-prem usa License) | ✅ |

- **Osservazioni chiave**:
  - ✅ **Platform Operations non è visible** su SaaS → conferma che [03.6.6] è bug **on-prem only** (su SaaS la logica gating funziona nella direzione giusta)
  - ⚠️ **Su SaaS Starter il super_admin non può configurare niente di significativo**: no auth, no appearance, no health, no logs, no compliance. È un admin depotenziato rispetto a on-prem super_admin. Design decision o bug?
  - Se `org_admin` (role più basso) su SaaS ha la **stessa** sidebar ridotta → `super_admin` e `org_admin` sono confusi in SaaS Starter (cross-ref [03.11.3.12] che diceva `manager == org_admin` su on-prem)
- **Discovered**: 2026-04-25

---

## 06.3 — Users & Access CRUD

### [06.3.1] Create user happy path ✅ (con caveat 06.4)

- **Fase**: 06 · **Area**: Users & Access / dim 3 CRUD Create
- **Deployment scope**: ☁️ SaaS
- **Tipo**: 🟢 OK (create lato UI/DB) + ⏸️ BLOCKED (post-create email)
- **Actual**:
  - Bottone "Create User" visible nella pagina All Users
  - Creazione user #2: email `sentrikat@gmail.com`, role `manager` → accettato, aggiunto alla lista con status (Pending/Invited atteso)
  - Creazione user #3: simile, role `user` → accettato
- **Cross-ref**: bug [06.4.1] per la mancata consegna email invite
- **Dim 3 CRUD partial**: Create ✅, Read ✅, Update ⬜ (da testare edit form), Delete ⬜
- **Discovered**: 2026-04-25

### [06.3.2] 🟡 Alias email `+qualcosa` bloccati anche su admin invite

- **Fase**: 06 · **Area**: Users & Access / admin invite validation
- **Deployment scope**: ☁️ SaaS (e 🏢 on-prem presumibile, stessa validation)
- **Tipo**: 🟡 Warning (UX di test + stretto)
- **Severity**: Medium (limita testing + può bloccare admin enterprise che usano alias)
- **Actual**: utente ha tentato `muscleaddiction49+manager@gmail.com` → **rifiutato**, costretto a usare email completamente separata (`sentrikat@gmail.com`)
- **Cross-ref**: [02.3.2] alias bloccati su signup trial — stesso pattern esteso anche qui
- **Issue**:
  - Admin enterprise può legittimamente usare alias `+` (Microsoft 365 supporta, Gmail supporta, Outlook supporta) per categorizzare utenti (`accounting+cto@company.com`, `dev+john@company.com`)
  - Bloccando gli alias SentriKat forza a usare email distinte — scomodo per team strutturati
- **Razionale forse voluto**: prevenzione di "1 customer → N account gratis bypass" sul signup. Ma su **admin invite** (dove il quota limit è già enforced lato piano) questo razionale NON si applica
- **Fix candidato (per fase fix)**: separare la validation. Alias block solo sul signup pubblico (`/api/v1/provision/trial`), ma NON sul flow admin invite (`/api/users`, che è già gated dal piano)
- **Discovered**: 2026-04-25

### [06.3.3] 🟢 Limit enforcement: 4° user rifiutato ✅

- **Fase**: 06 · **Area**: Users & Access / dim 6 negative (limit)
- **Deployment scope**: ☁️ SaaS
- **Tipo**: 🟢 OK (dim 6)
- **Actual**: con 3/3 users già creati, tentativo creare 4° → **bloccato** (utente conferma "anche il terzo funziona, e non posso crearne 4")
- **Note**: messaggio d'errore esatto non catturato, da riprendere in un secondo passaggio
- **Follow-up TODO 06.3.3a**: catturare messaggio esatto + verificare se è simile a "Demo version limit" di on-prem [03.14.20] o usa terminology SaaS-specific
- **Discovered**: 2026-04-25

### [06.3.4] ⬜ dim 3 Update / Delete user + dim 5 State transitions — da fare

- **Status**: pending
- **Test da eseguire** (stessa sessione, subito dopo):
  - Edit user role (manager → user, user → manager)
  - Delete user (conferma popup come [03.11.3.15]?)
  - Disable/Block user (toggle?)
  - Force password change sull'user
- **Note**: i 2 users creati sono ancora "orfani" (no email invite ricevuta, non loggabili). Ma possiamo comunque testare le operazioni admin SU quegli utenti

### [06.3.5] 🔴 HIGH — Azione "Force setup 2FA" → redirect a `/profile?setup_2fa=required` produce 404, auto-recupero al refresh

- **Fase**: 06 · **Area**: Admin user actions / Setup 2FA redirect
- **Deployment scope**: ☁️ SaaS
- **Tipo**: 🔴 Bug
- **Severity**: **High** (UX broken, potenziale data loss se il refresh non riparte, ma soprattutto admin confidence in 2FA flow compromessa — 2FA è security-critical)
- **Steps to reproduce**:
  1. Users & Access → All Users → edit user orfano
  2. Azione "Force setup 2FA" (o equivalente toggle "Require 2FA")
  3. Save / Confirm
- **Expected**: redirect a `/profile` (o `/settings/security`) con banner "User X must setup 2FA at next login"
- **Actual**:
  - URL: `https://app.sentrikat.com/profile?setup_2fa=required` → **404 Not Found**
  - **Auto-recupero**: dopo refresh della pagina (F5), l'app entra correttamente
- **Interpretazione**:
  - Possibile: il path `/profile` esiste ma non gestisce il query param `?setup_2fa=required`, che trigger un 404 nel router
  - Oppure: redirect segue un path SPA client-side routing che non è registrato, refresh forza server-side render che invece funziona
  - Oppure: flaky routing dovuto a async state hydration
- **Impatto**:
  - Admin fa azione critica (Force 2FA) → vede 404 → pensa che l'azione sia fallita → riesegue o richiede support
  - Potenziale action non persisita (se il 404 abortisce il submit server-side)
  - **MA** dato che refresh auto-risolve, probabilmente l'azione è andata a buon fine lato server, è solo la UX del redirect post-action rotta
- **Fix candidato**: verificare il router client-side per handling del query param; alternativamente redirect pulito a `/profile` (senza query) dopo l'azione
- **Follow-up TODO 06.3.5a**: verificare con DevTools Network se il server-side request ha ritornato 200/302 ma il client-side ha fatto render 404, oppure server ha ritornato 404 davvero
- **Discovered**: 2026-04-25
- **🔧 Root cause + Fix 2026-05-01** (commit pending): non c'è nessun client-side render strano — il path `/profile` **non esiste come route Flask**. Il 2FA setup vive in un Bootstrap modal in `base.html` apribile via dropdown user → "Security Settings" → `openSecuritySettings()`. Il login redirect (`login.html:468,530`) mandava su `/profile?setup_2fa=required` senza nessun handler. Refresh "auto-recuperava" perché la dashboard caricava normalmente nascondendo l'errore. Fix: redirect cambiato a `/?setup_2fa=required` (root, route esiste) + `DOMContentLoaded` listener in `base.html` che, se trova `setup_2fa=required`, apre `openSecuritySettings()` automaticamente e ripulisce la query string via `history.replaceState`. Verifica pending: admin force 2FA su user → user logga → atterra su dashboard con modal Security già aperto + URL pulito.

### [06.3.6] Dim 3 Update role user ✅

- **Fase**: 06 · **Area**: Users / CRUD Update
- **Deployment scope**: ☁️ SaaS · **Tipo**: 🟢 OK · **Dim**: 3 CRUD
- **Actual**: edit user `sentrikat@gmail.com` role da `manager` → `user` → save → role aggiornato correttamente
- **Discovered**: 2026-04-25

### [06.3.7] Dim 5 State transitions Disable/Re-enable user ✅

- **Fase**: 06 · **Area**: Users / state transitions
- **Deployment scope**: ☁️ SaaS · **Tipo**: 🟢 OK · **Dim**: 5
- **Actual**: toggle disable → user status cambiato; re-enable → ripristino OK
- **Follow-up TODO 06.3.7a**: verificare comportamento end-to-end dopo unblock email: user disabled tenta login → rejected con messaggio chiaro?
- **Discovered**: 2026-04-25

### [06.3.8] Dim 5 Force Password Change admin action ✅ (funziona, con caveat 06.3.5 per 2FA)

- **Fase**: 06 · **Area**: Users / admin force password change
- **Deployment scope**: ☁️ SaaS · **Tipo**: 🟢 OK · **Dim**: 5
- **Actual**: azione "Force password change" funziona, nessun redirect 404 (diverso dal Setup 2FA di 06.3.5)
- **End-to-end verify**: impossibile ora — user orfano non può loggare per vedere se al login riceve request di password change. Rinviato dopo fix email cluster
- **Discovered**: 2026-04-25

### [06.3.9] Dim 6 Security — SQL/XSS injection protection user create form ✅

- **Fase**: 06 · **Area**: Users create / input sanitization
- **Deployment scope**: ☁️ SaaS · **Tipo**: 🟢 OK (positive security) · **Dim**: 6 negative
- **Actual**:
  - Name = `<script>alert('XSS')</script>` → **rifiutato** con messaggio "invalid"
  - Email = `test'; DROP TABLE users;--@evil.com` → **rifiutato** con messaggio "invalid"
- **Valutazione**: sanitization attiva, nessun input eseguito come HTML o SQL. **Good security posture** su form critico admin
- **Follow-up TODO 06.3.9a** (non-urgent): test anche caratteri Unicode unusuali (zero-width joiner, right-to-left override), path traversal in full_name (`../../../etc/passwd`), LDAP injection syntax se formato email LDAP-like (`*)(|(uid=*)`). Più esotici, bassa priorità
- **Discovered**: 2026-04-25

### [06.3.10] Dim 6 Email validation robust (4 casi negativi) ✅

- **Fase**: 06 · **Area**: Users create / email format validation
- **Deployment scope**: ☁️ SaaS · **Tipo**: 🟢 OK · **Dim**: 6 negative
- **Casi testati (tutti rifiutati con messaggi corretti)**:
  - `notanemail` (senza @) → rifiutato
  - `a@b` (dominio senza TLD) → rifiutato
  - email vuota → rifiutato
  - `muscleaddiction49@gmail.com` (duplicate) → rifiutato con messaggio appropriato
- **Valutazione**: email validation solida (RFC 5321/5322 respect + duplicate check)
- **Discovered**: 2026-04-25

### [06.3.11] Delete user (dim 3) ✅ implicito

- **Fase**: 06 · **Area**: Users / CRUD Delete
- **Deployment scope**: ☁️ SaaS · **Tipo**: 🟢 OK · **Dim**: 3
- **Actual**: delete di un user orfano (presumibile dai successivi test che hanno ri-creato un 4° slot libero)
- **Follow-up TODO 06.3.11a**: catturare esplicitamente style del popup di conferma delete (modal branded vs `window.confirm` grezzo — vedi [03.11.3.15])
- **Discovered**: 2026-04-25

---

## 06.4 — 🔴 HIGH — User invite email NON arriva (secondo flow email rotto, pattern `04.1.3`)

### [06.4.1] 🔴 HIGH — Admin invite email non arriva

- **Fase**: 06 · **Area**: User invite / email delivery
- **Deployment scope**: ☁️ SaaS (core Flask app + SMTP prod upstream)
- **Tipo**: 🔴 Bug
- **Severity**: **High** (admin non può onboardare nuovi user → team adoption bloccato)
- **Environment**: prod `app.sentrikat.com`
- **Steps to reproduce**:
  1. Login come super_admin (`muscleaddiction49@gmail.com`)
  2. Users & Access → All Users → Create User
  3. Compila: email `sentrikat@gmail.com`, role `manager`, submit
  4. UI conferma "User created, invitation email sent" (o simile)
  5. Click "Resend invite" → UI dice "spedita"
- **Expected**: `sentrikat@gmail.com` riceve email con:
  - Link di attivazione OR
  - Credenziali temporanee (come fase 02.4.1) OR
  - Link magic per set password iniziale
- **Actual**: email **NON arriva** in nessun folder (inbox / spam / promotions — user conferma "non la vedo sull inbox in nessun luogo")
- **Response server**: 200 OK, UI dice "sent" → **silent-fail pattern identico a [04.1.3]**
- **Regressione pattern SMTP systemico — cluster di bug correlati**:

| Bug | Flow | Scope | Status |
|---|---|---|---|
| [02.4.1] | Welcome email SaaS signup | 🔐 license-server | 🟢 funziona (ieri) |
| [04.1.3] | Portal OTP login | 🔐 license-server | 🔴 CRITICAL non arriva (oggi) |
| [06.4.1] | Admin invite SaaS user | ☁️ SaaS core app | 🔴 HIGH non arriva (oggi) |

- **Analisi**: 2 flow email rotti + 1 funzionante. I 2 rotti hanno path diversi (license-server per portal, Flask core per invite). Suggerisce:
  - Causa comune: SMTP **upstream** del tenant SaaS (Amazon SES quota esaurita, SendGrid API key scaduta, dominio blacklisted, bounce list contaminata)
  - Oppure: regressione in un **modulo email comune** importato da entrambi i servizi
  - Oppure: **configurazione SMTP prod** ruotata/dimenticata dopo un deploy
- **Azione da suggerire all'utente**: controllare dashboard SES/SendGrid/MailerSend/Postmark (chiunque sia il provider) per:
  - Bounce rate / complaint rate / suppression list → `sentrikat@gmail.com` potrebbe essere su suppression dopo bounces precedenti
  - Send quota / rate limit
  - API key validity
- **Altra verifica**: `muscleaddiction49@gmail.com` (original signup) riceveva email in fase 02. Ora? Se adesso NON riceve più nemmeno `muscleaddiction49@gmail.com` → il problema è SMTP generale. Se riceve ancora → il problema è specifico `sentrikat@gmail.com` (suppression list) o flow-specific
- **Impact on other scope**:
  - Portal OTP bloccato (04.1.3)
  - SaaS invite bloccato (06.4.1)
  - Team expansion bloccata in SaaS
  - **NON impatta** welcome email signup (02.4.1) che arrivava ieri — diverso trigger
- **Status test**: **⏸️ BLOCKED** — dim 4 role-based matrix completa bloccata (non possiamo loggare come manager/user senza invite email)
- **Discovered**: 2026-04-25

---

## 06.6 — RBAC matrix dim 4 ⏸️ BLOCKED

### [06.6.1] ⏸️ BLOCKED — RBAC matrix completo rinviato

- **Fase**: 06 · **Area**: RBAC dim 4
- **Tipo**: ⏸️ Test bloccato
- **Bloccato da**: [06.4.1] (invite email non arriva) → impossibile loggare come manager/user per vedere il loro punto di vista della sidebar + permissions
- **Workaround**:
  - A — (solo se tiene accesso DB prod): UPDATE diretto della password hash dei 2 user orfani per bypassare attivazione email
  - B — aspettare fix di 06.4.1 / 04.1.3 (stessa regressione presumibile)
  - C — testare `dim 4 partial` solo sul super_admin (già fatto implicitamente in 06.2.1 — sidebar super_admin conosciuta)
- **Discovered**: 2026-04-25

---

## 06.8 — Dashboard SaaS Starter (batch 1)

### [06.8.1] Dashboard empty state completo, tutti i widget coerenti ✅

- **Deployment scope**: ☁️ SaaS
- **Tipo**: 🟢 OK · **Dim**: 1 happy
- **Widget mappati** (tutti empty come atteso):
  - 4 cards CVE severity: `0-DAY (— matches)`, `CRITICAL (0)`, `HIGH (0)`, `MEDIUM (0)`
  - Source filter: `All / Servers / Clients / Containers / Dependencies` → tab click aggiorna stat panel sotto
  - Stats panel: Unique CVEs, Total Findings, Critical CVEs, Container Images, High CVEs, Medium+Low — tutti 0
  - Priority Breakdown donut: "No data yet"
  - Remediation Progress line chart: tooltip "Apr 24 — Acknowledged: 0 / Unacknowledged: 0"
  - Remediation Actions: "No pending remediation actions"
  - SLA Compliance: "No SLA policies configured" + `+ Set up SLA`
  - Remediation Overview: "No data"
  - Assignments: "No assignments yet. Use the [+] button in Remediation Actions to assign work"
  - Vulnerability Trends: chart empty with `Last 30 days` + `By Severity` dropdown
- **Console**: zero errori (utente conferma)
- **Network**: tutti 200
- **Discovered**: 2026-04-25

### [06.8.2] 🔵 "Set up SLA" click → messaggio verde ma count resta 0 (UX ambiguity)

- **Deployment scope**: ☁️ SaaS · **Tipo**: 🔵 Info · **Dim**: 3 CRUD
- **Actual**: utente ha cliccato `+ Set up SLA` → UI mostra messaggio verde di successo, ma indicator dice ancora "0 SLA policies saved"
- **Ipotesi**:
  - Click con form vuoto → creata SLA "empty" che non conta
  - Oppure messaggio verde è "form acknowledged" ma non save effettivo
  - Oppure race condition: conteggio non refresh dopo save
- **Follow-up TODO 06.8.2a**: ricliccare Set up SLA con almeno 1 campo popolato (es. name), verificare counter
- **Discovered**: 2026-04-25

## 06.9 — Assignments page ✅

### [06.9.1] Assignments page struttura completa, empty state ✅

- **Deployment scope**: ☁️ SaaS · **Tipo**: 🟢 OK · **Dim**: 1 happy
- **Actual**:
  - Header: "Remediation Assignments" + badges `Total 0` · `Overdue 0` · refresh icon
  - Filtri: Search, Status (All), Priority (All), Assigned to, Sort (Due date), filter button
  - Tabella: CVE · PRODUCT · ASSIGNEE · PRIORITY · STATUS · DUE DATE · TRACKER · ACTIONS
  - Empty: "No assignments match the current filters"
- **Dim 3 CRUD Create**: bottone "Create" non esplorato (con dati vuoti poco testabile — richiederebbe prima un CVE match reale)
- **Follow-up TODO 06.9.1a**: aprire modal Create Assignment (anche senza dati) per screenshot form + fields validation
- **Discovered**: 2026-04-25

## 06.10 — Products sub-pages (batch 1 parziale — Products List + Endpoints)

### [06.10.1] Products List empty state ✅

- **Deployment scope**: ☁️ SaaS · **Tipo**: 🟢 OK · **Dim**: 1 happy
- **Actual**: bottone `+ Add Product` visible, Columns dropdown, Search + 4 filtri (Statuses, CPE, Sources, Types). Empty: "No products added yet. Click Add Product to start tracking vulnerabilities"
- **Discovered**: 2026-04-25

### [06.10.2] 🔴 HIGH — Endpoints page: "Latest: linux: v1.0.0, macos: v1.0.0, windows: v1.0.0" HARDCODED

- **Deployment scope**: ☁️ SaaS (+ 🏢 on-prem probabile, da verificare)
- **Tipo**: 🔴 Bug
- **Severity**: **High** (customer non scopre mai se c'è una nuova agent version disponibile)
- **Actual** (dalla pagina Endpoints):
  - Sezione `Agent Versions`: `0 CURRENT / 0 OUTDATED / 0 UNMANAGED`
  - **Label "Latest: linux: v1.0.0, macos: v1.0.0, windows: v1.0.0"** — utente osserva che "spero non sia fisso deve in qualche modo nel saas seguire i release"
- **Issue**: la versione `v1.0.0` sembra essere **hardcoded** nel frontend (o nel backend) invece di essere derivata dinamicamente dalle release GitHub (`v1.0.0-beta.6` è la release più recente con cui stiamo lavorando)
- **Pattern correlato**: stesso root cause di [03.5.3] (`VERSION` file inchiodato a beta.2) e [03.14.9] (License page dice "Up to date beta.2"). **Terzo hardcode di versione** scoperto
- **Impatto**:
  - Customer installa agent `v1.0.0-beta.6` (magari) ma la pagina dice "Latest: v1.0.0" → agent appare come "CURRENT" (falso: è beta.6, latest è...?)
  - Security patch release non promossa ai customer
  - Contraddittorio con mappa architetturale che promette scheduled update + heartbeat check
- **Fix candidato (per fase fix)**: la label "Latest" deve essere fetchata da un endpoint `/api/releases/latest` che query GitHub Releases API (o un cache interno aggiornato via `license_heartbeat` job ogni 12h)
- **Follow-up TODO 06.10.2a**: verificare se la stessa label compare anche in on-prem → se sì aggiornare scope a `🏢☁️ both`
- **Discovered**: 2026-04-25
- **🔧 Root cause + Fix 2026-05-01** (commit pending): la versione **non era hardcoded a `1.0.0`**. `_get_latest_agent_versions()` in `app/agent_api.py:4393` fa `APP_VERSION.split('-')[0]` per stripppare il pre-release (es. `1.0.0-beta.6` → `1.0.0`). Era un workaround perché `_version_compare` faceva `int(x)` su ogni dotted part e crashava sul `0-beta`. Stripping rendeva la comparison numerica funzionante ma mostrava label errata. **Doppio fix**: (1) restituire `APP_VERSION` intero senza strip (`1.0.0-beta.6`); (2) `_version_compare` ora semver-aware (https://semver.org/#spec-item-11): pre-release ranks lower del release release puro, identifiers numerici < alphanumerici, dot-by-dot compare. Test cases inclusi nel commit (9 casi: equal, beta vs release, beta vs beta, rc vs beta, alpha < alpha.1, ecc.) — tutti pass. Verifica pending: Endpoints page mostra `Latest: linux: v1.0.0-beta.6, ...` corretto + agent installati appaiono `current` solo se versione esattamente uguale.

### [06.10.3] 🔵 NVD online/offline indicator fluttua dinamicamente

- **Deployment scope**: ☁️ SaaS · **Tipo**: 🔵 Info (cross-ref [03.13.1])
- **Actual**: durante la sessione il footer ha mostrato alternatamente `NVD offline` e `NVD Online`. Utente ha esplicitamente confermato: "ps ora nel footer nvd è di nuovo online"
- **Valutazione**: conferma fault-tolerance del multi-source fallback funzionante anche su SaaS. Stesso pattern di on-prem
- **Discovered**: 2026-04-25

## 06.10 (continua) — Products sub-pages batch 2 (Containers, Dependencies, Import Queue, SBOM Export, Exclusions)

### [06.10.4] Containers empty state ✅

- **Deployment scope**: ☁️ SaaS · **Tipo**: 🟢 OK
- **Actual**: header "Container Security — Container image vulnerabilities from Trivy scans". 5 stat cards (Images 0, Critical 0, High 0, Total Vulns 0, Fixable 0). Search + All severities + All fix status filters. Empty: "No container images found. Container scans from push agents will appear here."
- **Nota feature gating**: "**push agents**" è Pro+ (vedi [03.13.2]), quindi Starter Community può vedere la pagina ma non popolarla
- **Discovered**: 2026-04-25

### [06.10.5] Dependencies empty state ✅

- **Deployment scope**: ☁️ SaaS · **Tipo**: 🟢 OK
- **Actual**: header "Code libraries, extensions, and their vulnerability status". 4 stat cards (Dependencies 0, Extensions 0, Ecosystems 0, With Vulnerabilities 0). Search + All types + All ecosystems + All statuses. Empty: "No dependencies found. Enable extension or dependency scanning on your agent API keys to see data here."
- **Link a [03.12.1]**: la pagina rimanda esplicitamente all'Agent Keys "Scan Capabilities" (OS / Extensions / Code Dependencies toggles)
- **Discovered**: 2026-04-25

### [06.10.6] Import Queue empty state ✅

- **Deployment scope**: ☁️ SaaS · **Tipo**: 🟢 OK
- **Actual**:
  - Info banner blue: "Software discovered from agents and integrations appears here for review before being added to your product inventory."
  - Bulk actions: `Approve Selected`, `Reject Selected`, `Approve All`, `Reject All`
  - Filter: All Categories / All Vendors / 25 per page / Pending
  - Table: SOFTWARE · VERSION · ORGANIZATION · CATEGORY · CRITICALITY · SOURCE · REPORTED BY · ACTIONS
  - Empty: "No items in queue"
- **Valutazione**: governance pattern correct (review before import, bulk actions)
- **Discovered**: 2026-04-25

### [06.10.7] SBOM Export page ricca ✅ + follow-up feature gating da verificare

- **Deployment scope**: ☁️ SaaS · **Tipo**: 🟢 OK (rendering) + 🔵 Info (gating da confermare)
- **Actual**:
  - Header "Software Bill of Materials" con banner educational: "Each format serves a different ecosystem: CycloneDX (OWASP/AppSec), SPDX (Linux Foundation/ISO 5962), STIX 2.1 (OASIS for threat-intel sharing)"
  - **3 format cards** con descrizione tecnica + bottone `Download JSON`:
    - CycloneDX 1.5 — `components[]` + `vulnerabilities[]` CVSS. Compatible Dependency-Track, Sonatype, GitHub Dependabot, Snyk
    - SPDX 2.3 — `packages[]`, preferred for license compliance (ISO/IEC 5962)
    - STIX 2.1 — `vulnerability` SDOs + `software` SCOs + `relationship` SROs. ISACs, MISP, CISA AIS
  - Endpoint paths esposti: `/api/sbom/export/cyclonedx`, `/api/sbom/export/spdx`, `/api/sbom/export/stix21`
  - **CLI / CI pipeline usage** section con 2 esempi curl:
    ```
    curl -sk -H "Cookie: session=$SESSION" https://app.sentrikat.com/api/sbom/export/cyclonedx -o sbom-cdx.json
    curl -sk -H "X-API-Key: $SENTRIKAT_API_KEY" https://app.sentrikat.com/api/sbom/export/spdx -o sbom-spdx.json
    ```
  - **Rate limit banner** giallo: "10 exports per hour per user. Exports larger than the per-bundle cap return HTTP 413 — filter with `?product_ids=1,2,3` or contact support for streaming exports."
- **Follow-up TODO 06.10.7a — URGENTE verifica gating**: cliccare `Download JSON` per uno dei 3 formati anche con inventory vuoto. Atteso:
  - Se 200 OK + JSON valido → SBOM è feature universale (Starter included) → conferma commit `e769ce9 fix(plans): declare sbom_export in seeded plans so /api/sbom/* isn't 403`
  - Se 403 "upgrade required" → gating invertito, bug: la pagina è visible ma la funzione bloccata
- **Valutazione UX**: **pagina eccellente** — 3 formati + endpoint espliciti + CLI examples production-ready + rate limit info. Best practice documentation
- **Discovered**: 2026-04-25

### [06.10.8] Exclusions empty state ✅

- **Deployment scope**: ☁️ SaaS · **Tipo**: 🟢 OK
- **Actual**: banner info "Excluded products are blocked from being imported by agents. When you delete a product with 'Exclude from future scans', it appears here. You can also manually add exclusions." Bottone `+ Add Exclusion`. Table: VENDOR · PRODUCT · VERSION · ORGANIZATION · EXCLUDED BY · REASON · DATE · ACTIONS. Empty: "No exclusions configured"
- **Discovered**: 2026-04-25

---

## 06.11 — Settings → Alert Management (batch 3)

### [06.11.1] Alert Management rendering + features ✅

- **Deployment scope**: ☁️ SaaS · **Tipo**: 🟢 OK
- **Content mappato**:
  - **Webhooks section**: badge `Inactive` top-right, copy "No webhooks configured" + link "Configure Webhooks" (rimanda a Email & Notifications → Slack/Teams)
  - **Alert Rules for TAKIRTNES** section:
    - Banner: "Your plan includes one organization. Configure the alert rules that apply to it. 0-Day and active-exploitation alerts (CISA KEV / EUVD) are always enabled and cannot be turned off."
    - Riga singola organization: CRITICAL ✅ · HIGH ☐ · NEW CVE ✅ · RANSOMWARE ✅ · ALERT MODE dropdown "New Only" · DELIVERY badges `NO EMAILS` + `NO SMTP` (giallo) · edit icon in Actions
  - **Alert Delivery History**:
    - Filtri: All Types · All Statuses · date from `mm/dd/yyyy` · date to `mm/dd/yyyy` · clear X
    - Table: DATE/TIME · ORGANIZATION · TYPE · STATUS · MATCHES · RECIPIENTS · ERROR
    - Empty: "No alert history found" + "No records"
    - Auto-refresh: 60s
- **Feature positive**:
  - ✅ `0-Day + active-exploitation always-on` — smart security default (non disabilitabile = critico sempre notificato)
  - ✅ Per-org alert rules (coerente anche con 1 org sul plan)
  - ✅ Delivery badge immediato (`NO EMAILS`, `NO SMTP`) → admin vede subito stato canale
  - ✅ Alert history 60s refresh con error visibility
- **Discovered**: 2026-04-25

### [06.11.2] 🔴 HIGH — Alert Management manca dalla tab bar Settings (sidebar 3 voci, tab 2 voci)

- **Fase**: 06 · **Area**: Settings navigation / UI consistency
- **Deployment scope**: ☁️ SaaS
- **Tipo**: 🔴 Bug
- **Severity**: **High** (navigation broken, UX disorientante)
- **Actual**:
  - Sidebar → System → Settings espande 3 voci: `Alert Management`, `Email & Notifications`, `Subscription`
  - Dentro la pagina **Alert Management**: NO tab bar in cima (pagina standalone)
  - Dentro la pagina **Email & Notifications**: tab bar in cima con 2 tabs → `Email & Notifications` (selected) + `Subscription`
  - Dentro la pagina **Subscription**: tab bar con 2 tabs → `Email & Notifications` + `Subscription` (selected)
- **Issue**: **Alert Management non è raggiungibile da tab bar**. L'admin che è su Email & Notifications o Subscription non vede alcun tab `Alert Management` → l'unico modo per tornarci è via sidebar → "sembra che sia una pagina di un'altra sezione"
- **User osservazione esplicita**: `"come vedi alert management non fa appartire le tab, e dalle altre due sezioni nelle tab in alto non c'è alert management. però nel menu sidebar sono tutte e 3 insieme"`
- **Fix candidato**: aggiungere `Alert Management` come terza tab nella tab bar di Settings (attualmente solo 2). Così le 3 voci sidebar e le 3 tab combaciano
- **Cross-ref [02.7.8]**: breadcrumb "Home / Administration" inconsistente su SaaS, stessa area navigation rotta
- **Discovered**: 2026-04-25
- **🔧 Fix 2026-05-01** (commit pending): non era spostabile dentro `admin_panel.html` (`alerts_settings.html` è una pagina standalone con widget complessi specifici delivery channels), quindi cross-link bidirectional. (1) `alerts_settings.html`: aggiunto `nav-tabs` header in cima con 3 tab — Alert Management active, Email & Notifications + Subscription come link a `/admin-panel#settings:email` / `#settings:subscription`. (2) `admin_panel.html` settings tab bar: aggiunto `<a>` link-style pill "Alert Management" prima del tab Email che linka a `/alerts/settings`. Risultato: da qualunque delle 3 pagine, le altre 2 sono visibili e raggiungibili nella tab bar. Sidebar grouping invariata. Verifica pending: navigare via tab bar tra le 3 pagine senza dover ripiegare sulla sidebar.

### [06.11.3] 🔵 Info — Delivery badges `NO EMAILS` / `NO SMTP` visibili per quick diagnosis

- **Deployment scope**: ☁️ SaaS · **Tipo**: 🔵 Info
- **Actual**: le righe alert rules mostrano badge stato canale (`NO EMAILS` = nessun destinatario configurato; `NO SMTP` = no SMTP configured)
- **Valutazione**: UX eccellente per diagnosi rapida — l'admin vede subito se i canali di delivery sono OK
- **Discovered**: 2026-04-25

### [06.11.4] 🔵 i18n — Alert Delivery History usa `mm/dd/yyyy` (US) mentre altri form usano `tt.mm.jjjj` (DE)

- **Deployment scope**: ☁️ SaaS · **Tipo**: 🔵 Info (cluster i18n)
- **Actual**: filtri date range della Alert Delivery History mostrano placeholder `mm/dd/yyyy` (US style)
- **Cluster i18n browser-native update**:
  - [02.2.1] tooltip validation DE
  - [03.12.3] date picker agent key DE (`tt.mm.jjjj`)
  - [03.14.4] audit logs date DE
  - [03.14.17] file picker logo DE (`Datei auswählen`)
  - [06.11.4] alert delivery date **US** (`mm/dd/yyyy`) ← **diverso locale!**
- **Nota**: qui il form mostra US format invece che DE → suggerisce che il placeholder è **esplicitamente settato dal frontend** (non lasciato al browser native), ma con locale US. Mentre gli altri date input sono browser-native. **Incoerenza interna al prodotto**: dove lo imposta manualmente usa US, dove lo lascia al browser risolve a DE (browser locale user)
- **Fix candidato**: standardizzare su **ISO 8601** (`YYYY-MM-DD`) come già fa [03.14.13] General settings "Date Format: 2024-01-15 14:30 (ISO)"
- **Discovered**: 2026-04-25

---

## 06.12 — Settings → Email & Notifications

### [06.12.1] 🔴 CRITICAL (cross-ref) — "Managed Email Delivery: no SMTP config needed" MA i flow email sono rotti ([04.1.3] + [06.4.1])

- **Fase**: 06 · **Area**: Email infrastructure / cross-ref
- **Deployment scope**: ☁️ SaaS (managed infrastructure upstream)
- **Tipo**: 🔴 Bug (cross-ref)
- **Severity**: **CRITICAL** (già marcato in 04.1.3)
- **Actual** (pagina Email & Notifications):
  - Banner verde tranquillizzante: `"Managed Email Delivery — Email alerts, reports, and notifications are sent automatically by the SentriKat platform. No SMTP configuration needed."`
  - **Sender**: `From: SentriKat Alerts <noreply@alerts.sentrikat.com>`
  - **Monthly Email Quota**: `0 / 200 emails used this month (starter plan)` → nessuna email spedita questo mese! Il quota count conferma che **zero emails sono partite**
- **Implicazione chiave**: il quota 0/200 conferma che il problema [04.1.3] + [06.4.1] è **realmente una silent-fail server-side** — se le email fossero partite ma rimbalzate, il counter sarebbe ≥ 1. Invece è 0. Significa che il send **non è nemmeno tentato** o fallisce prima del count
- **Sender discovery**: `noreply@alerts.sentrikat.com` (subdomain `alerts.`) differente da:
  - Fase 02 welcome: `noreply@sentrikat.com` (no subdomain)
  - Probabile ipotesi: `alerts.sentrikat.com` è il subdomain per alert/invite/OTP (nuovo setup SMTP?), mentre `sentrikat.com` serviva welcome/provisioning. **Se le credenziali DNS/SPF/DKIM del subdomain `alerts.` non sono setup correttamente o sono state modificate recentemente** → silent fail consistente solo su quei flow
- **Cross-check azione suggerita**: lookup DNS/SPF/DKIM/DMARC del subdomain `alerts.sentrikat.com`:
  ```
  dig TXT alerts.sentrikat.com | grep -E "spf|dkim"
  nslookup -type=TXT _dmarc.alerts.sentrikat.com
  ```
  Se SPF/DKIM mancanti o broken sul subdomain → email bloccate upstream
- **Impact on other scope**: conferma che il cluster email (portal OTP + invite + alerts) è **CENTRALIZZATO** sulla managed infrastructure `alerts.sentrikat.com`. Il fix in questo subdomain risolve tutto il cluster
- **Discovered**: 2026-04-25 (diagnosi breakthrough)

### [06.12.2] Email & Notifications features ✅

- **Deployment scope**: ☁️ SaaS · **Tipo**: 🟢 OK (features mapped)
- **Content**:
  - **Email Delivery** section (già coperto in 06.12.1)
  - **Reply-To** input: default placeholder `support@yourcompany.com` (vedi [06.12.3])
  - **Monthly Email Quota**: `0 / 200 emails` (Starter plan quota)
  - **Notification Integrations**:
    - **Slack Integration**: toggle `Enable Slack Notifications` + `Slack Webhook URL` input + `Test` button — info: "Create an incoming webhook in your Slack workspace settings"
    - **Microsoft Teams Integration**: toggle `Enable Teams Notifications` (scrolled, presumibile stessa struttura Slack)
- **Valutazione**: Slack + Teams integrations disponibili **out-of-the-box** su Starter (non gated Pro+ come Issue Trackers). Good UX
- **Discovered**: 2026-04-25

### [06.12.3] 🟡 Reply-To default placeholder `support@yourcompany.com` può essere lasciato fittizio

- **Fase**: 06 · **Area**: Email reply-to config
- **Deployment scope**: ☁️ SaaS
- **Tipo**: 🟡 Warning
- **Severity**: Medium (if customer hits reply → email sent to nonexistent address)
- **Actual**: il campo Reply-To ha placeholder `support@yourcompany.com` ma se l'admin non compila rimane placeholder → nessun "Reply-To" effettivo
- **Issue**:
  - Se customer riceve alert email e hit `Reply` → arriva a `noreply@alerts.sentrikat.com` (il From) → nero, nessuno legge
  - Se placeholder venisse salvato letteralmente → email a dominio `yourcompany.com` (dominio non esistente → bounce)
- **Fix candidato**:
  - Validazione: impedire save con valore vuoto
  - Oppure: default intelligente a email admin dell'org (es. `sotadenis94@gmail.com`) invece di placeholder
  - Oppure: warning banner se Reply-To non configurato e alert rules attive
- **Cross-ref [02.4.6] follow-up** TODO welcome email reply-to: stesso tema
- **Discovered**: 2026-04-25

---

## 06.13 — Settings → Subscription (cross-ref [02.7.6] — [02.7.12])

### [06.13.1] Subscription page contenuto già mappato in [02.7.6] — [02.7.12]

- **Deployment scope**: ☁️ SaaS · **Tipo**: 🟢 OK (cross-ref) + 🔵 Info
- **Re-check rapido oggi**:
  - Current Plan: Starter · ACTIVE · Monthly · Renews 23 May 2026 (stessa data di [02.7.6] → 30 gg dal signup iniziale)
  - Plan Limits: 10 agents / 3 users / Unlimited products / 2 API keys / 500 MB storage (coerente)
  - Features Included matrix: Email Alerts ✅, Webhooks ✅, NIS2/DORA+BOD ❌, Push Agents ✅, Multi-Tenant ❌, LDAP/AD ❌, White-Labeling ❌, Issue Trackers ❌, Backup&Restore ❌, SAML SSO ❌, API Access ✅, SIEM Integration ❌, Audit Log Export ❌
  - Paid Add-on: Compliance Pack (PCI-DSS + ISO 27001 + SOC 2) — NOT PURCHASED + banner "Upgrade to Pro/Business/Enterprise first to unlock add-on eligibility"
  - Need more capacity? — `View Plans` CTA footer
- **Osservazione — discrepanza con fase 02.7.12**: oggi Features Included dice **Push Agents ✅** su Starter, mentre l'agent era bloccato con messaggio `"Push Agents require a Professional license"` ([03.13.2] on-prem Community). Quindi:
  - **SaaS Starter**: Push Agents INCLUSO (dice ✅)
  - **On-prem Community**: Push Agents ESCLUSO (errore runtime)
  - Questa è **asimmetria intenzionale** (SaaS paga un canone, on-prem Community è free-with-limit) oppure **nuovo bug** di inconsistenza tier-mapping
- **Follow-up TODO 06.13.1a**: sul SaaS Starter, dopo fix del cluster email, creare un agent key + deploy + vedere se su **SaaS** l'agent riesce a pushare (mentre on-prem Community NO). Se funziona → conferma asimmetria intenzionale, se fallisce con stesso messaggio → bug gating SaaS
- **Discovered (re-check)**: 2026-04-25

---

## 06.14 — Follow-up TODO sweep — 2026-04-30

> Re-test orchestrato dei TODO segnati durante le sessioni precedenti, ora che Phase 04 è sbloccata e i fix recenti (524208b, 23ce9da, backfill round-2) sono in prod.

### [06.3.4] ✅ Update / Delete user — re-tested (org admin scope)

- **User loggato**: `cliente1@test.com` (org admin di Acme Italia SRL).
- **Edit user**: tentato cambio username/email → error "**Only super admins can change usernames**" → vedi `[06.3.12]` sotto per design issue.
- **Delete user**: action presente.
- **Severity**: 🟢 funzionalità presente, cluster permission model `[06.3.12]` aperto.

### [06.3.7a] ✅ Disabled user login → reject confermato

- Disable user → tentativo login da incognito con quelle credenziali → reject con messaggio chiaro (utente conferma OK).
- **Severity**: 🟢 OK chiude `[06.3.7a]`.

### [06.3.12] 🟡 **WARN** — Permission model org admin: review necessaria

- **Tipo**: 🟡 design issue, non bug isolato
- **Sintomo**: org admin (`cliente1@test.com`) tenta di modificare username/email di un user nella **propria org** → bloccato con "Only super admins can change usernames".
- **Domanda valida sollevata dall'utente**: in un SaaS multi-tenant, "super admin" = noi sviluppatori, non il customer. L'org admin del customer dovrebbe avere pieno controllo della SUA org. Ma sicurezza: cambiare email senza notifica = attack vector.
- **Pattern industria SaaS**:
  - **Display name (`full_name`)** → org admin CAN edit. Cosmetico.
  - **Username** → **immutabile dopo creazione** (GitHub/Slack/Notion/Atlassian/M365). Rompe SSO/audit/joins. Comportamento attuale SentriKat è in linea con la prassi MA messaggio UX sbagliato — customer non sa chi è super admin (siamo noi). **Fix UX**: "Username is permanent and cannot be changed".
  - **Email** → 🥇 pattern Stripe/AWS/Google: solo l'utente STESSO può cambiare la SUA email + conferma link sulla nuova address. Org admin non può.
  - **Password** → org admin **NON** setta password. Può solo trigger **Reset Password** (email magic link). Pattern universale.
- **Fix prescriptivo**:
  1. Cambiare error message su username change → "Username is permanent and cannot be changed."
  2. Aggiungere bottone "Reset Password" visibile a org admin per ogni user della sua org.
  3. Implementare email change flow: user-self only, con confirmation link.
  4. "Edit Display Name" abilitato per org admin.
  5. Documentare in Admin Guide il modello org-admin vs super-admin.
- **Severity = 🟡 WARN**: codice attuale è ragionevole ma UX/coverage incompleto.
- **Discovered**: 2026-04-30
- **🔧 Fix parziale 2026-04-30** (commit pending): punto 1 del fix prescriptivo applicato. `app/routes.py:6977` error string da "Only super admins can change usernames" → "Username is permanent and cannot be changed.". Punti 2-5 (reset password button, email change flow user-self, display name edit, admin guide doc) restano aperti come follow-up feature work.

### [06.8.2] ✅ SLA setup già configurato (cross-ref `[06.8.2a]`)

- SLA Compliance widget popolato:
  - CRITICAL within 1d → 0% (0 OK / **1 overdue** / 1 total) — overdue = Adobe Acrobat
  - HIGH within 30d → 100% (249 OK / 0 / 249)
  - MEDIUM within 90d → 100% (145 OK / 0 / 145)
  - LOW within 180d → 100% (17 OK / 0 / 17)
- **Remediation Overview**: 14 products, 412 total open CVEs, 1 critical, 0 actively exploited. Highest impact: Adobe Acrobat Reader DC MUI (349 CVEs).
- **Severity**: 🟢 OK chiude `[06.8.2a]`.

### [06.9.2] 🔴 **HIGH** — Assignment state transitions tutti ritornano 400

- **Tab**: Assignments → click row → modal "Assignment detail #1"
- **Steps**: click `In progress` o `Resolved` o `Accepted risk` o `Delete`
- **Actual**: tutti e 4 i bottoni → **HTTP 400**
- **Expected**: state transition Open → In Progress (etc.) con persistenza + audit log entry
- **Impatto**: feature core "remediation workflow" morta. Customer può solo READ assignments, non aggiornare. Senza state transitions:
  - SLA tracking bugiardo (assignment overdue ma irrisolvibile)
  - Workflow ticketing inutile
  - Audit log non popolato
- **Severity = 🔴 HIGH**
- **Possibile root cause**: API endpoint `/api/v1/assignments/<id>/transition` richiede payload o query param mancante. DevTools Network → catturare body 400 → quasi sicuramente dice quale field manca.
- **Test follow-up post-fix**: verificare audit log entry per ogni transizione (cluster `[05.5.1]`).
- **Discovered**: 2026-04-30
- **🔧 Root cause reale + Fix 2026-04-30** (commit pending): non era payload mancante. Endpoint reale è `PUT /api/remediation/assignments/<id>` (commento intenzionale in `app/remediation_api.py:28-30` esplicita "CSRF is NOT exempted blueprint-wide... web pages include the CSRF token via flask-wtf"). Tutti gli **altri** blueprint API (`integrations_api`, `settings_api`, `reports_api`, `ldap_api`, `agent_api`, `routes`, ecc.) hanno `csrf.exempt(bp)` — `remediation_api` è l'eccezione. Frontend in `assignments.html` (4 button: in_progress / resolved / accepted_risk / delete) e in `dashboard.html` (4 fetch: quickStatusChange PUT, saveAssignmentDetail PUT, deleteAssignment DELETE, submitAssignment POST) non passavano `X-CSRFToken` → Flask-WTF rifiutava con 400 "CSRF token missing." Fix: aggiunto `'X-CSRFToken': getCSRFToken()` ai 6 fetch state-changing. Helper `getCSRFToken()` già definito globalmente in `base.html:3998`. Verifica pending: aprire assignment → click `In progress` → status update OK + audit log entry.

### [06.9.3] 🟡 **WARN** — Assignments table CVE column mostra HTML markup raw `<span class="text-muted">—</span>`

- **Sintomo**: colonna CVE row Adobe mostra letteralmente la stringa **`<span class="text-muted">—</span>`** invece di renderizzare "—" muted. Il modal detail invece mostra "—" correttamente.
- **Root cause**: backend memorizza/restituisce CVE-vuoto come HTML markup invece di null/em-dash. Renderer table escapa l'HTML (XSS protection → mostra come testo). Renderer modal applica innerHTML correttamente.
- **Anti-pattern security**: mescolare HTML nel data layer. Se renderer table cambia in futuro (innerHTML), exploit XSS possibile.
- **Fix prescriptivo**:
  1. Backend: store/return null o "—" pulito. Niente HTML nel data layer.
  2. Frontend: applicare classe `text-muted` nel template, non nel dato.
- **Severity = 🟡 WARN** anti-pattern + cosmetico immediato. Cluster con `[05.14.1]` (badge-green leak) + `[05.21.2]` (-1 leak) → pattern "data presentation mixing".
- **Discovered**: 2026-04-30
- **🔧 Fix 2026-04-30** (commit pending): in `app/templates/assignments.html` `renderRow()` separato `cveId` (puro dato) da `cveCell` (HTML placeholder se mancante). Cella renderizzata senza `esc()` come già fatto per `productLabel` e `trackerCell`. Il dato CVE reale viene comunque escapato via `esc(cveId)`. Verifica pending: row Adobe → "—" muted renderizzato correttamente, no più stringa raw `<span...>`.

### [06.10.7a] ✅ SBOM Export download funzionante in Starter

- L'utente conferma SBOM Export (JSON/CycloneDX/SPDX) **funziona** in Starter SaaS.
- **Cluster `[02.7.11]`**: la mismatch è solo nel display "Features Included" matrix (Starter dice SBOM ❌ ma in pratica ✅). Display bug, non gating.
- **Severity**: 🟢 OK funzionale. `[02.7.11]` resta aperto (display fix).
