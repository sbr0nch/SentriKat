# 07 — Cross-Tenant Isolation (Part G)

> **Durata:** 30-45 min. **Priorità:** 🔴 Obbligatoria prima del go-live.
>
> Questa parte verifica che **due organizzazioni diverse sul SaaS non
> possano mai vedersi dati reciproci**, in nessuna condizione. È il
> test più importante per un multi-tenant SaaS: un fallimento qui è un
> incident di sicurezza grave con potenziale leak GDPR.
>
> **Regola d'oro**: ogni query al DB deve avere `WHERE organization_id = ?`
> enforced a livello applicativo. Questa checklist lo verifica da
> utente finale + da chiamata API diretta.

---

## G.0 Setup

- [ ] Crea (o riusa) 2 org di test: `AcmeCorp` e `BetaInc`
- [ ] Ogni org ha:
  - 1 admin user (`admin@acme.test` / `admin@beta.test`)
  - 1 normal user (`user@acme.test` / `user@beta.test`)
  - Almeno 3 asset ciascuna, nominati in modo riconoscibile
    (es. `acme-web-01`, `beta-db-02`)
  - Almeno 1 scan completato ciascuna
  - Almeno 1 CVE detected ciascuna
  - Almeno 1 assignment ciascuna
- [ ] 2 browser diversi (o 1 normale + 1 incognito) per sessioni parallele
- [ ] `curl` pronto per test API diretti

---

## G.1 UI isolation (visual check)

### G.1.1 Dashboard
- [ ] Login come `admin@acme.test` → dashboard mostra solo asset Acme
- [ ] Contatori (asset count, vuln count, scan count) riflettono solo Acme
- [ ] Login parallelo come `admin@beta.test` → vede solo Beta
- [ ] Nessun asset Beta visibile in dashboard Acme e viceversa

### G.1.2 Asset list
- [ ] Acme `/assets` → tabella mostra solo `acme-*`
- [ ] Beta `/assets` → tabella mostra solo `beta-*`
- [ ] Filter/search per nome "beta" in Acme → 0 risultati
- [ ] Filter/search per nome "acme" in Beta → 0 risultati
- [ ] Paginazione non leaka conteggi totali cross-tenant

### G.1.3 Vulnerabilities / CVE list
- [ ] Acme vede solo CVE detected sui propri asset
- [ ] Beta vede solo CVE detected sui propri asset
- [ ] Stessa CVE-ID su entrambi → vista separata, con detection context distinti

### G.1.4 Reports
- [ ] Acme genera report compliance → contiene solo asset/vuln Acme
- [ ] Beta genera report compliance → contiene solo asset/vuln Beta
- [ ] PDF scaricato da Acme non ha riferimenti a Beta (grep sul PDF content)

### G.1.5 Assignments
- [ ] Acme vede solo i propri assignments
- [ ] Lista assignee dropdown mostra solo user Acme (non user Beta)

### G.1.6 Settings
- [ ] Org settings (name, logo, retention, SIEM config) separate
- [ ] Acme cambia logo → Beta continua a vedere il proprio
- [ ] Email templates per org non leakano

---

## G.2 Direct API isolation (security test)

**Setup**: ottieni 2 API token, uno per Acme e uno per Beta.
Prendi nota di un resource ID esistente per ciascuno (es.
`acme_asset_id=123`, `beta_asset_id=456`).

### G.2.1 Direct object reference (IDOR)
- [ ] Con token **Acme**, fai `GET /api/assets/<beta_asset_id>`
  → atteso **404** (non 403, per non confermare l'esistenza)
- [ ] Con token Acme, `GET /api/scans/<beta_scan_id>` → 404
- [ ] Con token Acme, `GET /api/vulnerabilities/<beta_vuln_id>` → 404
- [ ] Con token Acme, `GET /api/assignments/<beta_assignment_id>` → 404
- [ ] Con token Acme, `GET /api/users/<beta_user_id>` → 404
- [ ] Con token Acme, `GET /api/reports/<beta_report_id>` → 404

### G.2.2 Write attempts
- [ ] Con token Acme, `PATCH /api/assets/<beta_asset_id>` body arbitrario
  → 404 (NO modifica)
- [ ] Con token Acme, `DELETE /api/assets/<beta_asset_id>` → 404
- [ ] Con token Acme, `POST /api/scans` con `asset_id=<beta_asset_id>`
  → 400/404 (NO scan creato)
- [ ] Verifica su DB: nessun record modificato

### G.2.3 Bulk endpoints
- [ ] `GET /api/assets?limit=1000` con token Acme → solo asset Acme
- [ ] `GET /api/vulnerabilities?severity=critical` con token Acme → solo Acme
- [ ] `GET /api/export/assets` con token Acme → ZIP contiene solo Acme

### G.2.4 Query param injection
- [ ] `GET /api/assets?organization_id=<beta_org_id>` con token Acme
  → ignorato, ritorna solo Acme (il filtro org è server-side, non param)
- [ ] `GET /api/assets?org=beta` con token Acme → stesso comportamento
- [ ] Header `X-Organization-Id: <beta>` con token Acme → ignorato

### G.2.5 Filter / search injection
- [ ] Prova SQLi nel search: `' OR 1=1--` → nessun leak
- [ ] Prova `acme' UNION SELECT name FROM assets WHERE organization_id != ?`
  → nessun leak (query parametrizzata)

---

## G.3 Agent isolation

**Setup**: 1 agent Acme installato + 1 agent Beta installato con token diversi.

- [ ] Agent Acme invia dati → appaiono solo in org Acme
- [ ] Agent Beta invia dati → appaiono solo in org Beta
- [ ] Con token agent Acme, prova a inviare hostname con prefisso "beta-"
  → asset creato in Acme (il token decide l'org, non il payload)
- [ ] Con token agent Beta, prova `POST /api/agent/report` con
  `organization_id=<acme>` nel body → ignorato, finisce in Beta
- [ ] Token agent Acme revocato → agent non può più inviare (401)
- [ ] Agent Beta non è impattato dalla revoca

---

## G.4 Background jobs / scheduler isolation

- [ ] Scheduler Acme (es. daily scan) non triggera scan su asset Beta
- [ ] Email alerts Acme inviate solo al contatto Acme
- [ ] Email templates org-specific (logo, nome) rispettati
- [ ] Retention cleanup: cancellazione dati vecchi Acme non tocca Beta
  (verifica record count Beta prima/dopo cron cleanup)

---

## G.5 Webhook & integrations isolation

- [ ] Acme configura webhook verso `https://acme-siem.com/events`
- [ ] Beta configura webhook verso `https://beta-siem.com/events`
- [ ] Evento su Acme → chiamata SOLO all'URL Acme (check target logs)
- [ ] Evento su Beta → chiamata SOLO all'URL Beta
- [ ] Acme può vedere solo i propri webhook config (non quello di Beta)
- [ ] Stesso test per Jira/Slack/SIEM integrations

---

## G.6 Search & aggregation isolation

- [ ] Global search bar in Acme → cerca solo in Acme
- [ ] Search digita `beta` in Acme → 0 risultati
- [ ] Aggregation endpoint (count by severity, top CVE) → calcolato solo su Acme
- [ ] Super-admin dashboard mostra aggregate cross-org (questo è OK per super-admin)
- [ ] Normale admin Acme NON ha accesso al super-admin dashboard

---

## G.7 File storage isolation

- [ ] Acme carica logo custom → salvato in path `/uploads/<acme_org_id>/...`
- [ ] Beta carica logo → salvato in path `/uploads/<beta_org_id>/...`
- [ ] Prova accesso diretto al file Beta da sessione Acme → 403/404
- [ ] URL firmati per download export hanno TTL breve + scoping all'org
- [ ] URL Acme (rubato da logs) usato da Beta → rifiutato (firma + org check)

---

## G.8 Session & cookie isolation

- [ ] Login Acme in tab 1, login Beta in tab 2 (stesso browser, cookie
  session diverse via subdomain? o via org_id in session)
- [ ] Verifica che le 2 tab non si "contaminino" a vicenda
  (es. refresh tab 1 non mostra dati di tab 2)
- [ ] Logout Acme in tab 1 → tab 2 Beta resta loggata
- [ ] Cookie session NON contiene org_id plaintext manipolabile
- [ ] Cambiare `organization_id` nel JWT payload (se usato) → firma
  invalida, rifiutato

---

## G.9 Logs & error messages

- [ ] Error message "Asset not found" identico tra "asset inesistente"
  e "asset di altra org" (no info leak)
- [ ] Log applicativo include `organization_id` in ogni riga (per audit)
- [ ] User Acme non può leggere log di Beta (nessuna endpoint espone log cross-org)
- [ ] Sentry / error tracking non mostra dati di org diverse mescolati

---

## G.10 Super-admin "God mode" (intended exceptions)

Queste sono le **uniche** eccezioni legittime dove un utente vede
dati cross-org: il super-admin del SaaS (non il portal admin, quello
è Part F).

- [ ] Super-admin SaaS (`/super-admin`) vede lista tutte le org
- [ ] Può vedere dashboard aggregate cross-org
- [ ] Ogni accesso super-admin a dati di un'org è **loggato con reason**
  (audit log immutabile)
- [ ] Super-admin NON ha credenziali Acme/Beta — usa SSO separato
- [ ] Super-admin account è 2FA obbligatorio
- [ ] Rimozione super-admin rights è effettiva immediatamente

---

## G.11 Stress test isolation

- [ ] 10 sessioni parallele Acme + 10 Beta → nessun cross-contamination
  (script con `curl` in parallel)
- [ ] Load test con `ab`/`wrk` → response time non dipende da volume
  dell'altra org (no shared lock che serializza cross-org)
- [ ] Query plan EXPLAIN su `assets` usa index su `organization_id`

---

## G.12 Checklist rapida (go/no-go)

**5 minuti:**

- [ ] Creare 2 org, aggiungere 1 asset ciascuno con nome unico
- [ ] Login Acme → vedi solo il tuo asset
- [ ] Login Beta → vedi solo il tuo asset
- [ ] Con token API Acme, GET asset di Beta → 404
- [ ] DB query check: `SELECT count(*) FROM assets GROUP BY organization_id`
  → conteggi corretti separati

**Se tutti e 5 passano → isolation OK per go-live.**

**Se UNO fallisce → 🔴 STOP, è un incident di sicurezza. Fix immediato.**

---

## Note per il bug tracker

Un fallimento cross-tenant va aperto con severity **CRITICAL** e con
label `security-incident`. Blocca il go-live anche se è l'unico bug
trovato. Post-mortem obbligatorio dopo il fix con root cause, impact
analysis (quali dati hanno potuto leakare), e regression test
automatico.
