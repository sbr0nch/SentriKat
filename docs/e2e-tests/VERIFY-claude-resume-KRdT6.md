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
