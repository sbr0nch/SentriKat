# 03 — Core Features (Part C)

> **Durata:** 2-3h. **Priorita':** 🟠 Alta (skippabile se hai fretta, le
> feature sono stabili da mesi, test di regressione se vuoi).

Test delle feature "non nuove" — le cose che esistevano gia' prima di
Sprint 4+5. Ogni sottosezione e' indipendente: saltane quelle che non
usi (es. salta LDAP se non vendi a clienti enterprise nei primi mesi).

---

## C.1 Settings > System sub-tabs

- [ ] Click Settings > System → pill nav mostra: Sync & Updates,
      General, Security, Data Retention
- [ ] Ogni sub-tab apre una card diversa
- [ ] Switch a un'altra main tab (Email, Compliance) → tutte le sub-pane
      di System si nascondono
- [ ] Torna su System → si ricorda l'ultima sub-tab attiva
- [ ] User non-admin: General e Security NON appaiono
- [ ] Salva un setting in ogni sub-tab → persiste dopo reload

## C.2 LDAP Authentication (skip se non usi LDAP)

Config (Settings > Authentication > LDAP):

| Field | Value (test env) |
|---|---|
| Server | `ldap://localhost` |
| Port | `389` |
| Base DN | `dc=sentrikat,dc=test` |
| Bind DN | `cn=readonly,dc=sentrikat,dc=test` |
| Bind Password | `readonly` |
| Search Filter | `(uid={username})` |
| Username Attr | `uid` |
| Email Attr | `mail` |

- [ ] Enable LDAP, save config
- [ ] Test Connection → succeeds
- [ ] Search LDAP users → trova john.doe, jane.admin, marco.rossi
- [ ] Invita `john.doe` a un org
- [ ] Logout, login come `john.doe / password123` → success
- [ ] User mostra `auth_type: ldap` in admin panel
- [ ] Wrong password → error chiaro
- [ ] User inesistente → error chiaro
- [ ] Disable LDAP → bottone login sparisce

## C.3 SAML SSO (skip se non usi SAML)

Config (Settings > Authentication > SAML):
- IdP Metadata URL: `http://localhost:8080/realms/sentrikat/protocol/saml/descriptor`
- SP Entity ID: `sentrikat-saml`
- SP ACS URL: `http://localhost:5000/saml/acs`
- Auto-provision: Enabled

- [ ] Enable SAML, paste metadata URL, save
- [ ] Test SAML Config → validates successfully
- [ ] Visita `/api/saml/metadata` → XML valido
- [ ] Click "Login with SSO" → redirect a Keycloak
- [ ] Login come `testuser / password123`
- [ ] Redirect back a SentriKat, logged in
- [ ] User auto-provisioned (Settings > Users)
- [ ] Test LDAP user via SAML (`john.doe` attraverso Keycloak)
- [ ] SAML attributes mapped: email, nome
- [ ] Logout → session cleared

## C.4 Audit Logs

- [ ] Fai azioni: crea user, salva settings, esegui sync
- [ ] Settings > Compliance > Audit Logs → entries visibili
      (timestamp, user, action, resource, details)
- [ ] Filter by action → si aggiorna
- [ ] Filter by user → si aggiorna
- [ ] Export CSV → file scaricato
- [ ] File rotation: `ls -la /var/log/sentrikat/audit.log*` (max 20MB,
      50 backups)

## C.5 Data Retention

- [ ] Settings > System > Data Retention
- [ ] Set audit log retention = 365 giorni
- [ ] Set sync history = 90 giorni
- [ ] Set session log = 30 giorni
- [ ] Save → success toast
- [ ] Persiste dopo reload
- [ ] Scheduler logs mostrano `cleanup_old_data` alle 3:00 AM
- [ ] Auto-acknowledge: enable + "Run Auto-Acknowledge Now"
- [ ] Verifica match acknowledged (se ci sono dati rilevanti)

## C.6 Compliance Reports pre-Sprint5 (CISA + NIS2 + Executive)

### CISA BOD 22-01
- [ ] Settings > Compliance > Reports → click BOD 22-01 JSON → download
- [ ] CSV → download
- [ ] PDF → download
- [ ] Dati reali (CVE IDs, date, count) — non placeholder

### NIS2 Directive
- [ ] NIS2 JSON → download con Article 21 mapping
- [ ] NIS2 CSV → download
- [ ] NIS2 PDF → download
- [ ] Sezioni: supply_chain, vulnerability_handling, cyber_hygiene
- [ ] compliance_status calcolato (COMPLIANT / PARTIALLY / NON-COMPLIANT)
- [ ] MTTR calcolato se ci sono match acknowledged

### Executive Summary
- [ ] Dashboard > Export > Executive Summary PDF → one-pager
- [ ] Settings > Compliance > Executive Summary JSON → download
- [ ] Risk score (0-100) calcolato
- [ ] Top 5 urgent vulnerabilities listed
- [ ] KPIs: total matches, critical, overdue, remediation rate

## C.7 CSV Export

- [ ] Dashboard > Export > Export CSV (Excel) → download
- [ ] Apre in Excel senza problemi di encoding (UTF-8 BOM)
- [ ] 18 colonne presenti: CVE ID, severity, product, vendor, ecc.
- [ ] Applica filter `priority=critical` → re-export → CSV solo critical
- [ ] Filter acknowledged passa correttamente nel export

## C.8 Scheduled Reports

> 💡 Accesso: sidebar → **Integrations → Scheduled Reports**
> (`/reports/scheduled`). *Non* e' sotto Settings/Compliance.
>
> I `report_type` attualmente validi lato backend sono esclusivamente
> `summary`, `full`, `critical_only` (vedi
> `app/models.py::ScheduledReport.REPORT_TYPE_CHOICES`). Se la UI
> mostra opzioni tipo "Compliance (CISA BOD 22-01)" o "NIS2" e le
> sottomette letteralmente, la chiamata fallisce con
> `Invalid report_type`.

- [ ] Integrations → Scheduled Reports → "New Report"
- [ ] Crea: name="Daily Summary", frequency=daily, time=09:00,
      report_type=**Summary**, recipient=`you@example.com`
- [ ] Save → appare in lista con `enabled: true`, `last_sent: null`
- [ ] Click "Send Now" → si apre **modal di conferma stilizzato
      Bootstrap** (non browser confirm nativo), dopo conferma appare
      toast "Generating report…" poi success/fail
- [ ] Verifica email ricevuta (o `docker compose logs sentrikat | grep scheduled_report`)
- [ ] `last_sent` aggiornato nella lista dopo reload
- [ ] Crea un secondo report weekly con `report_type=critical_only`
- [ ] Toggle pause → `enabled: false`, il record rimane in lista
- [ ] Delete → modal di conferma `btn-danger`, dopo conferma record
      rimosso **hard delete** (non soft-delete)
- [ ] Scheduler logs: `process_scheduled_reports` registrato ogni 10 min

## C.9 Notifications

> 💡 **Alert Management** e' una pagina a se' (`/alerts/settings`),
> raggiungibile dalla sidebar **Settings → Alert Management**. NON e'
> una tab del pannello `/admin-panel#settings` — non cercarla li' se
> non la trovi. In SaaS mode la configurazione SMTP e' disabilitata (le
> email passano dal provider gestito Resend su `noreply@alerts.sentrikat.com`).

### Email Alerts
- [ ] Sidebar → Settings → Alert Management (`/alerts/settings`)
- [ ] Configura alert mode per l'org (critical_only / high_and_above / all)
- [ ] Configura email recipients per l'org
- [ ] In SaaS mode: Settings → Email & Notifications mostra quota
      residua (es. `0 / 500 emails used this month`). Il counter e'
      reale — viene popolato da `EmailMonthlyUsage` ogni invio
      (vedi `app/settings_api.py::get_email_quota`).
- [ ] On-premise: configura SMTP (Settings → Email & Notifications)
      e verifica test email
- [ ] Trigger sync → se nuovi CVE critici, alert spedito
- [ ] AlertLog table contiene record sent

### Slack / Teams / Webhook
- [ ] Alert Management → Delivery Channels → Webhooks → add Slack
      webhook URL, test → delivered
- [ ] Aggiungi Teams webhook URL, test → delivered
- [ ] Generic Webhook: URL + format + test → delivered

### Issue Trackers
- [ ] Sidebar → Integrations → Issue Trackers
      (`/admin-panel#integrations:jiraIntegration`)
- [ ] Configura Jira/GitHub/GitLab/YouTrack, test connection
- [ ] Crea issue da vulnerability → verifica nel tracker esterno

## C.10 License Activation

### Online
- [ ] Settings > License
- [ ] Note Installation ID
- [ ] Inserisci activation code, click Activate Online
- [ ] Server raggiungibile → license activates, features unlock
- [ ] Server non raggiungibile → fallback offline con messaggio chiaro

### Installation ID stability
- [ ] Restart SentriKat → ID stesso
- [ ] Docker: imposta `SENTRIKAT_INSTALLATION_ID` in .env → rebuild → stesso
- [ ] Docker senza env var → rebuild → NUOVO ID = license invalida

### License Heartbeat
- [ ] Logs: `license_heartbeat` ogni 12h
- [ ] Telemetry: agent count, product count, org count spediti
- [ ] Offline: nessun errore se portale irraggiungibile

## C.11 EPSS Scoring

- [ ] Run CISA KEV sync (per avere vulnerabilita')
- [ ] Vulnerability detail → EPSS score mostrato
- [ ] No score → trigger EPSS sync manualmente
- [ ] DB: `epss_score`, `epss_percentile`, `epss_fetched_at` popolati
- [ ] Dopo server rebuild → scores persistono (sono in PostgreSQL)
- [ ] Color coding: Critical 95%+, High 85%+, Medium 70%+, Low <70%

## C.12 CPE Dictionary

- [ ] Settings > System > Sync → stats CPE dictionary
- [ ] Entries > 0 (dovrebbero essere migliaia)
- [ ] Last sync timestamps (bulk download + incremental)
- [ ] Aggiungi "Apache HTTP Server" → CPE auto-mapped
- [ ] Lookup strategies: exact (0.92), product-only (0.88), alias (0.60-0.85)
- [ ] KB sync status se abilitato

## C.13 2FA / TOTP

### Setup utente
- [ ] Login come user → profile
- [ ] Enable 2FA → QR code
- [ ] Scan con Google Authenticator / Authy
- [ ] Codice 6 cifre per verificare → 2FA enabled
- [ ] Logout, login → chiede 2FA code
- [ ] Codice giusto → access
- [ ] Codice sbagliato → denied

### Force per org
- [ ] Admin imposta `totp_required: true` su un user
- [ ] User forzato a setup TOTP al prossimo login
- [ ] Non puo' bypassare

### Disable
- [ ] User disabilita 2FA dal profile
- [ ] Next login → no prompt

## C.14 SIEM / Syslog forwarding

Test setup:
```bash
# Listener UDP (terminale dedicato)
nc -u -l -p 5514

# Oppure TCP
nc -l -p 5514
```

- [ ] Settings > SIEM / Syslog: host=localhost, port=5514, UDP, CEF, On
- [ ] Save → success toast
- [ ] Click "Test Connection"
- [ ] CEF: listener riceve `CEF:0|SentriKat|VulnerabilityManagement|1.0|test|...`
- [ ] Switch to JSON → structure JSON nel listener
- [ ] Switch to RFC5424 → structure RFC
- [ ] Switch UDP → TCP → funziona over TCP
- [ ] Disable → no piu' eventi forward
- [ ] Reload page → settings persisted

## C.15 Exclusions (inventory noise reduction)

> ⚠️ **Limite noto**: il form "Add Exclusion" (Inventory → Exclusions)
> e' puramente testuale — vendor + product_name + reason, **zero
> validazione** lato UI/backend. Non controlla che il prodotto esista
> nel tuo inventario, non lookup su CPE dictionary, non suggerisce
> vendor noti. Un refactor e' tracciato come follow-up (vedi TODO).
> Per ora testa solo il "happy path".

- [ ] Sidebar → Inventory → Exclusions → "Add Exclusion"
- [ ] Compila vendor (es. "Microsoft") + product_name (es. "Edge") +
      reason
- [ ] Save → l'entry compare nella tabella
- [ ] Trigger un sync / match refresh → i match per
      Microsoft/Edge non compaiono piu' nei risultati
- [ ] Delete esclusione → i match tornano visibili al sync successivo
- [ ] Prova a creare un'esclusione con vendor vuoto → errore 400
      `vendor and product_name required`
- [ ] Edge case: vendor con case diverso ("microsoft" vs "Microsoft")
      → documenta il comportamento reale (case-sensitive? trim?)

---

## ✅ Gate C

- [ ] Tutto quello che ti serve per il lancio e' green (skippa il resto)
- [ ] Nota a lato le feature che hai deciso di NON promuovere al lancio
      commerciale (es. "LDAP/SAML: disponibili ma non testate, offerte
      on-request")

Prossima: [`04_sprint4_5_features.md`](04_sprint4_5_features.md)
