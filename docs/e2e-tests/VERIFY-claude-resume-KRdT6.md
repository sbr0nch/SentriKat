# Verification checklist — branch `claude/resume-sentrikat-KRdT6`

**Per**: utente in testlab al PC casa, dopo merge della PR su `main`.
**Ambiente**: docker rebuild fresh con beta.6 + 7 commit di sopra.
**Obiettivo**: verificare i 7 fix applicati 2026-05-01, marcare ✅ VERIFIED in `00-INDEX.md` quelli che passano, riaprire 🔴 quelli che falliscono.

> ⚠️ Tutti i fix sono `🔧 unverified`. Nessuno è ✅. Ogni esito qui sostituisce lo stato in `00-INDEX.md` § "batch fix `claude/resume-sentrikat-KRdT6`".

## Pre-flight (1 min)

```powershell
cd C:\SentriKat\v1.0.0-beta.6
git fetch origin ; git switch main ; git pull origin main
docker compose -f docker-compose.yml -f testlab\docker-compose.testlab.yml up -d --build
docker compose ps   # tutti up: sentrikat, sentrikat-db, mailpit, webhook-tester, ...
```

Login `cliente1@test.com` / password — sessione Acme Italia SRL (org admin).

---

## ✅ [03.16.1] 🔴 SSL Verify default ON + confirm guard — `8818d9d`

**Cosa testare**:
1. Fresh DB → System Settings → System tab → General → Network & Proxy. Toggle "Verify SSL Certificates" deve essere **ON**.
2. Click sul toggle per disattivare → deve apparire `confirm()` browser-native con testo "Disable SSL certificate verification? ... Only disable in trusted corporate networks ... Never on the public internet."
3. Click **Cancel** → toggle rimane ON.
4. Click sul toggle di nuovo + click **OK** → toggle passa OFF.
5. Click sul toggle per riattivare → nessun confirm (solo OFF→ON richiede conferma).

**Pass** se: 1 ON + 2 confirm visibile + 3 cancel ripristina + 4 OK consente + 5 ON senza dialog.
**Fail** se: confirm non appare → `console.log` per errore JS, sospetta che `static/js/admin_panel.js` non sia ricaricato (hard reload Ctrl+Shift+R).

---

## ✅ [03.18.4] 🔵 polling 503 cleanup — `708a093`

**Cosa testare**:
1. Click `Sync` button (qualunque sync veloce — CISA KEV).
2. Aspettare che progress banner sparisca (sync completata).
3. F12 → Network → filtra `progress`. Refresh pagina → continua a vedere richieste a `/api/progress/<jobId>`?
4. Aspettare 30s. Se sì → ✅ pulizia post-completion funziona; se no → comunque ✅.
5. Vero test: simulare stale jobId — apri DevTools → `sessionStorage.setItem('activeJobId','cpe_backfill_99999')` → reload pagina.
6. Console DevTools: deve mostrare 1 (massimo 2) request a `/api/progress/cpe_backfill_99999` → 503 → poi STOP. Niente loop infinito.
7. `sessionStorage.getItem('activeJobId')` dopo lo stop → deve essere `null`.

**Pass** se: stop dopo 1-2 request + sessionStorage svuotato.
**Fail** se: continua a pollare → controllare che `hideProgressBanner()` venga chiamato (breakpoint in `app/templates/base.html` `pollProgress`).

---

## ✅ [06.9.3] 🟡 Assignments table CVE cell — `89436ef`

**Cosa testare**:
1. Dashboard → Open assignments table.
2. Cercare row con `a.cve_id` mancante / null (es. assignment Adobe Acrobat).
3. Cella CVE deve mostrare **"—"** in grigio muted, **NON** la stringa `<span class="text-muted">—</span>`.
4. Cella CVE row con CVE valida (es. CVE-2024-1234) → mostra l'ID linkato/grassetto, no markup raw.

**Pass** se: row vuota mostra em-dash muted, row valida mostra CVE id.
**Fail** se: ancora HTML escapato → controllare hard reload (cache `assignments.html`).

---

## ✅ [06.3.12] 🟡 username error UX — `c3b773f`

**Cosa testare**:
1. User Management → click utente esistente (non sé stessi) → Edit.
2. Cambia il campo `username` → Save.
3. Toast/error message: deve dire **"Username is permanent and cannot be changed."**, NON "Only super admins can change usernames".

**Pass** se: stringa esatta nuova.
**Fail** se: ancora vecchia stringa → controllare deploy backend (`docker compose restart sentrikat`).

---

## ✅ [06.9.2] 🔴 Assignment state transitions (CSRF) — `2a44f4b`

**Test core del round, il più importante**.

1. Dashboard → click assignment row con status `Open` → modal "Assignment detail".
2. Click button **In progress** → confirm → Save.
3. **Expected**: toast "Status updated", modal chiude, table reload, status row diventa "In progress".
4. **Expected** F12 Network: `PUT /api/remediation/assignments/<id>` → **200 OK** (non più 400).
5. Ripeti per **Resolved** e **Accepted risk** (su altre assignment perché terminal).
6. Click **Delete** su un'altra assignment → confirm → assignment sparisce.
7. Dashboard panel "Assignments summary" → click Quick Status Change → stessa cosa.
8. Crea nuova assignment via "Assign Remediation" modal → POST `/api/remediation/assignments` → 201 Created.
9. **Audit log check**: System Settings → Audit Log → filtrare per `assignment` → deve esserci 1 entry per ogni transizione (cluster `[05.5.1]`).

**Pass** se: 4 button funzionano + audit log popolato.
**Fail** se: 400 ancora → F12 Network response body. Se dice "CSRF token missing" → hard reload, controllare che `getCSRFToken()` esista in console (`getCSRFToken()` deve ritornare stringa). Se dice altro → nuovo bug, `[06.9.2.x]`.

---

## ✅ [03.18.1] 🔴 Health check notify (DB-resilient + transitions) — `5ca72d0`

**Test più articolato. ~10 min**. Pre-requisito: Mailpit + webhook-tester running.

### Setup

1. System Settings → Notifications → Health Checks tab.
2. **Notification Email**: `admin@sentrikat-test.local`.
3. **Webhook**: toggle ON (Generic Webhook configurato in altra tab a `http://host.docker.internal:8800/test-uuid` con format generic).
4. Save.

### Smoke test (transition OK→FAIL→OK)

5. Tutti i check verdi → click `Run All Now` → mailpit/webhook-tester: 0 messaggi (corretto: tutto OK, niente da notificare).
6. `docker stop sentrikat-db` → attendi 30s.
7. UI: 503 toast (atteso, app non risponde senza DB). MA scheduler dovrebbe comunque tentare: aspetta 1-2 min (interval scheduler).
8. `docker start sentrikat-db` → attendi 30s.
9. **Mailpit `http://localhost:8025`**: deve esserci 1 email "SentriKat Health Alert: 1 critical" con body "CRITICAL: Database Connectivity - ...".
10. **Webhook-tester `http://localhost:8800`**: deve esserci 1 POST con same content.
11. Aspetta next scheduler cycle (~1-2 min) dopo recovery → mailpit deve avere 2a email "SentriKat Health Alert: 1 recovered" con body "RECOVERED: Database Connectivity (critical -> ok)".

### Edge — env fallback (DB irraggiungibile + nessun setting DB)

12. (Optional, se hai 5 min) `docker compose down`. Aggiungi a `docker-compose.yml` env:
    ```yaml
    environment:
      - HEALTH_CHECK_NOTIFY_EMAIL=fallback@sentrikat-test.local
      - HEALTH_CHECK_NOTIFY_WEBHOOK_URL=http://host.docker.internal:8800/fallback-uuid
    ```
13. `docker compose up -d`. Wipe DB volume (test fresh): `docker volume rm v100betarc6_db_data` → re-up.
14. Repeat smoke test step 6-10. Anche senza row `health_check_notify_email` nel DB, mailpit deve ricevere il messaggio sull'indirizzo `fallback@`.

**Pass** se: step 9 ✅ + step 10 ✅ + step 11 ✅ recovery alert. Step 12-14 = bonus.
**Fail mode tipici**:
- Niente email su step 9 → check `docker logs sentrikat | grep health` per vedere se `_send_health_notifications` viene chiamato.
- Email su 9 ma niente su 11 (recovery) → `_LAST_STATUS_CACHE` non popolata: bug nel module-level state.
- 2+ email su 9 entro 1 min → rate-limit non rispettato, transition detection rotta (deve essere 1 sola al primo failure).

---

## ✅ [03.16.2] 🟡 Compliance preset dropdown — `1fc1dff`

**Cosa testare**:
1. System Settings → System tab → Security sub-tab.
2. In cima al form deve esserci sezione "Compliance Preset" con dropdown.
3. Default selezionato: **NIST SP 800-63B**.
4. Cambia a **PCI-DSS v4.0** → osserva i campi:
   - `passwordMinLength` → 12
   - `passwordRequireSpecial` → checked
   - `passwordExpiryDays` → 90
   - `require2FA` → checked
5. Apri General sub-tab (mantieni Security aperto in altro tab) → `verifySSL` deve essere ON.
6. Torna su Security → Save Security Settings.
7. Reload pagina (F5) → riapri Security → dropdown ricorda **PCI-DSS v4.0**.
8. Cambia a **Custom** → nessun campo si modifica (no-op).
9. Cambia a **NIST** → 2FA on, special char OFF (NIST-specific!), min length 8.

**Pass** se: 8/9 step OK.
**Fail** se: dropdown non appare → cache, hard reload. Se valori non si applicano → check console per errore JS in `applyCompliancePreset()`.

---

## Post-verify — update counter

Per ogni fix verificato, in `docs/e2e-tests/00-INDEX.md` cambiare `🔧` → `✅ VERIFIED 2026-05-01` nella sezione "batch fix `claude/resume-sentrikat-KRdT6`". Se 7/7 OK:

```
✅✅ Fix VERIFIED: 20 su 27   (era 13 su 20)
```

Per ogni fail, aprire nuovo bug ID `[FF.S.B.x]` con sintomo + step ripro + commit di provenienza + raccomandazione (rollback `git revert <commit>` o nuovo fix).

## Cosa NON serve testare in questa pass

- Bug Phase 05 SentriKat-web: scope di altra sessione (`claude/fix-sentrikat-web-handoff-*`).
- Phase 03.14 cluster CPE backfill: già ✅ VERIFIED 2026-04-30.
- LDAP/SAML/SSRF integrations: già ✅ VERIFIED 2026-04-30.

---

# Round 3 — branch `claude/fix-round3-core-316ec1` (PR #?)

> Aggiunto 2026-05-01. 4 fix HIGH + 1 audit + 1 rebranding cluster + 1 callout UX. Pre-requisito: stessa procedura pre-flight della sezione Round 1+2 sopra (pull + rebuild fresh).

## ✅ [06.3.5] 🔴 Force setup 2FA → 404 redirect — `9cfc00a`

1. `cliente1@test.com` (org admin) → Users & Access → click su un user qualunque → Edit → "Force setup 2FA" / equivalent toggle "Require 2FA at next login" → Save.
2. Logout. Login come quel user (in incognito).
3. **Expected**: dopo password OK, atterri su **dashboard `/`** (non più `/profile?...`), modal Security Settings **già aperto** sulla card "Two-Factor Authentication".
4. **Expected** URL bar: `https://app.sentrikat.com/` (no più `?setup_2fa=required`, ripulito via `history.replaceState`).
5. F5 sulla pagina → modal NON si riapre (query è stata rimossa).

**Pass** se: 3 ✅ + 4 ✅ + 5 ✅.
**Fail** se: ancora 404 → controllare hard reload (cache `login.html`); se modal non apre → console `getElementById('securitySettingsModal')` per esistenza.

## ✅ [06.10.2] 🔴 Latest agent version label — `8b513b7`

1. `/admin#endpoints` o equivalent endpoints page con sezione `Agent Versions`.
2. Label deve mostrare **"Latest: linux: v1.0.0-beta.6, macos: v1.0.0-beta.6, windows: v1.0.0-beta.6"** (full semver, **NON** `v1.0.0`).
3. Se installi un agent con versione esattamente `1.0.0-beta.6` → conta in `CURRENT`.
4. Se installi/simuli un agent con versione `1.0.0-beta.5` → conta in `OUTDATED`.
5. Se installi/simuli un agent con versione `1.0.0-rc.1` o `1.0.0` → conta `UP_TO_DATE` (rc.1/release > beta.6).

**Pass** se: 2 ✅ semver completo. 3-5 sono test ottimali (richiedono manipolare DB Asset table o multipli agent install).
**Fail mode**: ancora `v1.0.0` puro → docker compose restart sentrikat per ricaricare agent_api.py.

## ✅ [06.11.2] 🟡 Tab nav siblings (Alert Management / Email / Subscription) — `ad28576`

1. `/alerts/settings` → in cima alla pagina, sotto il titolo "Alert Management", deve esserci una **nav-tabs** strip con 3 tab:
   - "Alert Management" (active, current page)
   - "Email & Notifications" (link a `/admin-panel#settings:email`)
   - "Subscription" (link a `/admin-panel#settings:subscription`) — **solo SaaS**
2. Click "Email & Notifications" → atterri su admin-panel con il tab Email aperto.
3. Sulla settings tab bar di admin-panel, click pill "Alert Management" (icon bell) → atterri su `/alerts/settings`.

**Pass** se: 1 ✅ tab visibili + 2 ✅ navigazione + 3 ✅ ritorno.
**Fail mode**: se in admin-panel non vedi "Alert Management" pill → la tua org/role potrebbe non avere `email_alerts` feature. Verifica con super_admin login.

## ✅ [03.11.5.3] 🔴 Test Connection error mapping — `8882644`

1. Settings → Authentication / Integrations → Issue Tracker tab.
2. Configura tipo "Jira", URL = `http://host.docker.internal:8080` (privato → triggera SSRF).
3. Click "Test Connection".
4. **Expected** F12 Network: `POST /api/integrations/issue-tracker/test` → **400 Bad Request** (non più 500).
5. **Expected** body: `{"success": false, "error": "Invalid Jira URL: URL must not target..."}` o simile.
6. Toast UI: messaggio chiaro, no più "internal server error".
7. (Bonus) Configura tipo Jira con URL pubblico irraggiungibile (es. `https://example-fake-jira-12345.com`) → `502 Bad Gateway` con `error: "Connection to tracker failed: ConnectionError"`.
8. (Bonus) Configura tipo "webhook" con URL privato → resta `200 OK` con `success: false` (era già strutturato, niente regressione).

**Pass** se: 4 ✅ codice 400 + 5 ✅ body strutturato + 6 ✅ toast leggibile.
**Fail mode**: ancora 500 → check server logs `docker logs sentrikat | grep -i "test_issue_tracker"`.

## ✅ Rebranding `[03.14.10.expand]` + `[03.14.20]` — Demo→Community — `<commit>`

1. Login come admin senza license PRO (Community).
2. Banner top page: deve mostrare **"COMMUNITY EDITION"** (non più "DEMO VERSION").
3. License page: già mostrava "COMMUNITY EDITION" (no regressione).
4. Health Check page: già diceva "COMMUNITY" (no regressione).
5. Tentativo invite user oltre limit (1 user max in Community): error message **"Community Edition limit: 1 users. Upgrade to Professional for unlimited."** (non più "Demo version limit").
6. Tentativo create org oltre limit: stesso pattern "Community Edition limit: ...".
7. Settings → System → admin_panel feature comparison table: header colonna sinistra **"Community"** (non "Demo").
8. License page → "Remove License" button → message "License removed. Reverted to Community Edition." (non "Demo version").
9. Setup wizard welcome card "Multi-Tenancy" → ora ha badge **"PRO"** accanto al titolo (cluster `[03.6.2]`).

**Pass** se: 5/9 OK. È rename + UX consistency, regressioni improbabili.
**Fail mode**: stringhe stale in cache browser → hard reload. Se Python still mostra "Demo" → probabilmente importi cached, restart container.

## ⚠️ `[03.11.2.2]` LDAP Group Mapping — partial fix UX callout — `<commit>`

> NON fix completo del bug. Era un'**inconsistenza di percezione**: la feature Group Mapping esiste già come pagina dedicata `/admin-panel#ldapGroups` (con discovery, role mapping matrix, sync dashboard, auto-provision toggle). Il bug originario era che dalla LDAP **config form** non c'era nessun puntatore a quella pagina, quindi sembrava feature mancante.

1. Settings → Authentication → LDAP / Active Directory Configuration form.
2. **Expected**: sotto l'alert info standard di setup, deve esserci un **alert giallo** con: "Group & role mappings: assign LDAP/AD groups to SentriKat roles and organizations on the dedicated LDAP Groups page (auto-provision, default role, sync dashboard)" + bottone "Open LDAP Groups →".
3. Click bottone → atterri su `/admin-panel#ldapGroups` con la pagina Group Mappings + Sync Dashboard tab.
4. Bug originale chiuso parzialmente: fields espliciti "Group Search Base" / "Group Filter" / "Member Attribute" non sono inline nel config form (by design — sono nella discovery panel della pagina dedicata). Decisione architetturale, non fix.

**Pass** se: 2 ✅ callout visibile + 3 ✅ navigation funziona.
**Note**: il bug doc resta open con etichetta "discoverability fix only". Per richiedere fields inline nel config form, riaprire `[03.11.2.2.b]`.

## 🔍 `[06.4.1]` Admin invite email — audit only

> NON fixato. Audit ha rivelato che **NON è un bug di delivery email** (come ipotizzato cluster con `[04.1.3]`). È **feature mancante**:
>
> - `POST /api/users` (`app/routes.py:6832 create_user`) richiede `password` obbligatoria → admin DEVE settare la password e comunicarla out-of-band al user. **Nessun path invite email** per local users esiste.
> - `send_user_invite_email()` esiste in `app/email_alerts.py:989` ma è chiamata SOLO da `ldap_manager.py` (LDAP discover flow). Local user create non la chiama mai.
> - Il fix lato `sentrikat-web` `524208b` (BackgroundTasks SMTP) non si applica: era per OTP customer SaaS, path completamente diverso.
>
> **Conclusione audit**: il bug è in realtà *"feature da costruire"*, non *"feature rotta da fixare"*. Implementarlo richiede:
> 1. Schema change User: aggiungere `invite_token` + `invite_expires_at` colonne (oppure riusare token JWT firmato).
> 2. Endpoint `POST /api/users` accetta `send_invite=true` opzionale → genera token, salva user con password=null + `must_set_password=true`, chiama `send_user_invite_email`.
> 3. Endpoint pubblico `GET /accept-invite?token=...` → form set password, attiva user.
> 4. Email template invite.
>
> Stima: 200-400 righe + UI + test. Out of scope di sessione autonomous. Va aperto come **`[06.4.1.feature]` BUILD** in roadmap separata. Marcato 🔍 **AUDITED** finché non viene pianificato.

