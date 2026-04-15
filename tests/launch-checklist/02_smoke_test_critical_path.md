# 02 — Smoke Test Critical Path (Part B)

> **Durata:** 30 min. **Priorita':** 🔴 Obbligatoria.
> **Se qualcosa qui fallisce → STOP, c'e' un blocker di produzione.**

Questa e' la "golden path" del prodotto: il percorso che un customer
reale fara' nei primi 30 minuti. Se non funziona, niente lancio.

> 💡 **Dove vivono davvero le feature** (mappa sidebar reale):
> - **Dashboard** (`/`) — Priority Matrix, match list, vulnerability
>   trends, detail CVE, Acknowledge, Create Assignment. Non c'e' una
>   voce "Vulnerabilities" separata: tutto e' in dashboard.
> - **Inventory → Products List / Endpoints / Containers /
>   Dependencies / Import Queue / Exclusions** — gestione asset.
>   I prodotti si gestiscono **solo via modal** (no pagina dettaglio).
> - **Integrations → Agent Keys / Agent Activity / Scheduled Reports /
>   Issue Trackers** — agent lifecycle + report periodici +
>   Jira/GitHub/GitLab/YouTrack. "Scheduled Reports" e "Agent Activity"
>   sono **pagine separate**, non tab del pannello Integrations.
> - **Settings → Alert Management / Email & Notifications / SIEM /
>   Compliance / Subscription** — "Alert Management" e' una **pagina
>   separata** (`/alerts/settings`), le altre voci sono tab del
>   pannello `/admin-panel`.
> - **SBOM export** — solo API (`/api/sbom/export/{cyclonedx,spdx,stix}`),
>   nessun bottone in UI.
> - **Assignments** — gestiti dentro il dettaglio del match sulla
>   dashboard, niente lista standalone.

---

## B.1 Login + dashboard (5 min)

- [ ] Apri `$BASE` nel browser → atterri sulla pagina di login
- [ ] Login come User A (email + password) → reindirizzato alla dashboard
- [ ] La dashboard carica entro 3 secondi
- [ ] Console JS del browser senza errori rossi (warning OK)
- [ ] Vedi: priority matrix (cards critical/high/medium/low), widget
      "Vulnerability Trends" (Chart.js), lista top vulnerabilita'
- [ ] Widget trends mostra un grafico o lo stato vuoto "No trend data yet"
- [ ] Il menu header mostra il nome dell'org corrente

## B.2 Inventory e agent (5 min)

- [ ] Sidebar → Inventory → Products List → vedi i prodotti di Org A
- [ ] Click sulla riga di un prodotto apre la **modal di edit** (non esiste
      una pagina dettaglio dedicata: i prodotti si gestiscono solo tramite
      modal inline con Edit, Assign Organizations e Delete). Verifica che
      la modal si apra e mostri versione, CPE, vendor, organizzazioni
      assegnate.
- [ ] Sidebar → Inventory → Endpoints → vedi la lista asset
- [ ] Ogni asset ha: hostname, OS, last_seen, stato (online/offline/stale)
- [ ] Filtri per stato e per OS funzionano
- [ ] **Cross-tenant guard — Assign Organizations**: nella modal "Assign
      Organizations" di un prodotto, prova a forzare via DevTools/curl un
      `organization_ids: [<id_di_un_org_a_cui_non_appartieni>]` sul
      POST `/api/products/<id>/organizations`. Atteso: **HTTP 403**
      "You can only assign products to organizations you belong to".
      Se ottieni `200 OK` → **STOP**: c'e' un leak cross-tenant.

## B.3 Vulnerabilita' e matching (5 min)

> 💡 La "pagina Vulnerabilities" **non esiste come voce di sidebar**. I
> match sono visualizzati direttamente sulla **Dashboard** (sezioni
> Priority Matrix + tabella dei match). L'interazione avviene li'.

- [ ] Dashboard → sezione match / priority matrix → vedi l'elenco dei match
- [ ] Filtro `severity=critical` (toggle o query string `?severity=critical`)
      → lista si aggiorna
- [ ] Click su un match → dettaglio CVE con:
      - CVE ID
      - CVSS score + fonte (NVD / CVE.org / EUVD)
      - EPSS percentile (se disponibile)
      - Prodotto + versione
      - Badge KEV se in CISA KEV
      - Badge "Ransomware" se nel feed ransomware
- [ ] Azione "Acknowledge" → status del match cambia

## B.4 Assignment + email notification (5 min)

> 💡 "Assignments" non ha una voce di sidebar dedicata: gli assignment
> di remediation vivono nel dettaglio del match/CVE sulla Dashboard. Per
> verificare la persistenza si usa la stessa UI o l'API
> `/api/remediation/assignments`.

- [ ] Da un match → click "Create Assignment" nel dettaglio
- [ ] Compila: assignee=user@example.com, priority=high,
      due_date=2 settimane
- [ ] Salva → l'assignment appare nella lista remediation del match
- [ ] Lo status e' "open" di default
- [ ] La notifica email e' stata inviata (check inbox OR check log:
      `docker compose logs sentrikat | grep "assignment.*created"`).
      💡 In SaaS mode le email passano dal provider gestito (Resend) e
      consumano la quota mensile visibile in Settings → Email &
      Notifications.
- [ ] Modifica l'assignment: cambia status a "in_progress" → persiste
      dopo reload

## B.5 Issue tracker integration (5 min, se Jira/GitHub configurato)

- [ ] Hai un integration attivo (Jira, GitHub Issues, GitLab, YouTrack
      o Webhook). Se no, SKIP questa sezione con nota.
- [ ] Da un match → click "Create Ticket" (o "Create Jira")
- [ ] Il ticket e' creato sul tracker esterno (vai a verificare nel
      tracker stesso — non fidarti solo del response)
- [ ] L'assignment ha `tracker_issue_key` + `tracker_issue_url`
      popolati
- [ ] Click sul link → apre il ticket nel tracker

## B.6 SBOM export — 3 formati (3 min)

> 💡 L'export SBOM e' esposto **solo via API** (non c'e' un bottone
> "Export" in dashboard). Testa direttamente con curl — questo e' anche
> piu' rappresentativo dei clienti che lo consumano da pipeline CI.

- [ ] `curl -sk -H "Cookie: $COOKIE_A" "$BASE/api/sbom/export/cyclonedx"` →
      JSON con `bomFormat: "CycloneDX"`, `specVersion: "1.5"`,
      `components` non vuoto
- [ ] `curl -sk -H "Cookie: $COOKIE_A" "$BASE/api/sbom/export/spdx"` →
      JSON con `spdxVersion: "SPDX-2.3"`, `packages` non vuoto
- [ ] `curl -sk -H "Cookie: $COOKIE_A" "$BASE/api/sbom/export/stix"` →
      JSON con `type: "bundle"`, `objects` non vuoto

Sanity check rapido:
```bash
curl -sk -H "Cookie: $COOKIE_A" "$BASE/api/sbom/export/cyclonedx" \
  | python3 -c "import sys, json; d=json.load(sys.stdin); print('bomFormat:', d.get('bomFormat'), '/ specVersion:', d.get('specVersion'), '/ components:', len(d.get('components',[])))"
```
**Atteso:** `bomFormat: CycloneDX / specVersion: 1.5 / components: >0`

## B.7 Compliance reports (5 min)

> 💡 I report di compliance sono accessibili da **Settings → Compliance**
> (nella sidebar, sezione "System"). I framework supportati dalla
> pipeline di generazione sono: **CISA BOD 22-01**, **NIS2 Directive**,
> **PCI-DSS v4.0**, **ISO/IEC 27001:2022**, **SOC 2** (i tre ultimi
> sono gated dal Compliance Pack add-on — vedi `compliance_reports.py`
> e `reports_api.py::_add_report_integrity`).
>
> ℹ️ **Integrità**: i report generati includono un blocco
> `document_integrity` con `algorithm: "SHA-256"`, `content_hash` e
> `hmac_sha256` calcolato sulla rappresentazione canonica del JSON
> (escluso il blocco `document_integrity` stesso). L'HMAC usa il
> `SECRET_KEY` dell'istanza, quindi prova che il report **non è stato
> manomesso dopo la generazione**, ma può essere verificato solo
> dall'istanza che l'ha prodotto — **non è una firma digitale PKI**
> e non sostituisce una firma di un compliance officer per
> submission regolatorie. Va presentata come "tamper-evident audit
> trail", non come "certificato ufficiale".

- [ ] Settings → Compliance → "CISA BOD 22-01" → download JSON:
      - Campo `report_type: "CISA BOD 22-01 Compliance"`
      - Sezione KEV con elenco dei match KEV dell'organizzazione
      - Blocco `document_integrity` con `algorithm`, `content_hash`,
        `hmac_sha256`, `verification_note`
- [ ] Settings → Compliance → "NIS2 Directive" → download JSON:
      - Campo `report_type: "NIS2 Directive - Vulnerability Management Compliance"`
      - Sezioni per i controlli di vulnerability management
      - Blocco `document_integrity` presente
- [ ] PCI-DSS / ISO 27001 / SOC 2 (se Compliance Pack abilitato):
      - `GET /api/reports/compliance/pci-dss?format=json` → 200
      - `GET /api/reports/compliance/iso-27001?format=json` → 200
      - `GET /api/reports/compliance/soc2?format=json` → 200
      - Ognuno con `document_integrity.hmac_sha256` non vuoto
- [ ] Ripeti il download in formato PDF:
      - Prima pagina: nome org, data, framework
      - Una sezione per ogni controllo
      - Footer con hash SHA-256 visibile
- [ ] Verifica che i bottoni "Download JSON" / "Download PDF" funzionino
      senza errore e che la risposta arrivi entro 10s per un org di
      dimensioni realistiche
- [ ] **Tamper test**: scarica il JSON, modifica un campo a caso,
      ricalcola SHA-256 sul canonicale → deve differire dal
      `content_hash` nel blocco originale → prova che l'integrità
      rileva la manomissione

## B.8 Vulnerability trending dashboard (2 min)

- [ ] Dashboard → widget "Vulnerability Trends"
- [ ] Toggle view: Total → By severity → Open vs resolved
- [ ] Ogni toggle ridisegna il grafico senza page reload
- [ ] Se vuoto, forza uno snapshot (admin):
      ```bash
      curl -sk -X POST -H "Cookie: $COOKIE_A" "$BASE/api/vulnerabilities/trends/snapshot"
      ```
      poi reload dashboard → vedi un punto dati

## B.9 Patch Tuesday trigger (dry-run) (2 min)

- [ ] Via curl (admin only, dry-run NON manda email reali):
      ```bash
      curl -sk -X POST -H "Cookie: $COOKIE_A" \
        "$BASE/api/reports/patch-tuesday/trigger?dry_run=true" \
        | python3 -m json.tool
      ```
- [ ] Response JSON mostra `dry_run: true`, `organization`, `digest` con
      contatori CVE

## B.10 RBAC smoke — 4 ruoli, 3 account (5 min)

> 💡 Gli account di test devono avere `role` esattamente come di seguito
> — verifica nel DB prima di partire, altrimenti il comportamento e'
> falsato (es. un "viewer" con `role='manager'` vede i bottoni di
> scrittura, non e' un bug).

### B.10.a Viewer (`role='user'`) — lettura pura

Login come `viewer@orgA.test`, poi:

- [ ] Sidebar: **solo** Dashboard + Inventory (Products List, Endpoints,
      Containers, Dependencies, Import Queue, Exclusions). Niente
      Management, niente Integrations, niente Settings.
- [ ] Products List carica senza errori console. **Atteso**: zero
      crash `updateBulkToolbar null`. Se lo vedi, e' una regressione
      del fix in `admin.html::updateBulkToolbar` (deve essere un
      no-op quando `#bulkActionsToolbar` non esiste).
- [ ] Products List: **nessun** bottone "Add Product", "Edit", "Delete"
      accanto alle righe (il flag `userPermissions.canManageProducts`
      deve essere `false`)
- [ ] Endpoints: **nessun** bottone "Delete endpoint" nelle azioni
      asset
- [ ] Import Queue: **nessun** bottone "Approve Selected / Reject
      Selected / Approve All / Reject All"
- [ ] Exclusions: **nessun** bottone "Add Exclusion"
- [ ] Dashboard: puo' comunque vedere match, CVE detail, priority
      matrix (lettura ok)
- [ ] Top-right profile badge: mostra "User"

### B.10.b Manager (`role='manager'`) — gestione prodotti

Login come `manager@orgA.test`, poi:

- [ ] Sidebar: vede tutto quello che vede il viewer PIU' la sezione
      **Integrations** (Agent Keys, Agent Activity, Scheduled Reports
      se compliance_reports nel piano, Issue Trackers se
      jira_integration nel piano)
- [ ] Sidebar: **NON** deve vedere Users & Access ne' Settings
- [ ] Products List: vede bottoni Add / Edit / Delete / Bulk actions
- [ ] Endpoints: vede "Delete endpoint"
- [ ] Import Queue: vede Approve/Reject
- [ ] Exclusions: vede "Add Exclusion"
- [ ] Top-right profile badge: mostra "Manager"
- [ ] **NON** puo' aprire `/admin-panel#settings:*` (403 o redirect)

### B.10.c Org admin (`role='org_admin'`) — sidebar completa per il piano

Login come `testA@example.com`, poi:

- [ ] Sidebar completa: Dashboard + Inventory + Management + Integrations
      + Settings. Tutte le voci gated dal piano (vedi A.2 plan table).
- [ ] Top-right profile badge: mostra "Org Admin"
- [ ] `/api/remediation/assignments?per_page=100` → HTTP 200, NON 500.
      💡 Se ottieni 500, guarda i log: il fix in `remediation_api.py`
      logga ogni riga che fallisce la serializzazione con
      `assignment id=..., org=...` e il resto della lista continua
      comunque. Segnala i row id incriminati.

## B.11 Cross-tenant regression (3 min)

> ⚠️ Dopo il leak critico fixato nel PR "cross-tenant + RBAC" (commit
> di riferimento nel changelog), questo test deve **sempre** passare.

Prepara due cookie: `COOKIE_A` (org_admin di Org A) e `COOKIE_B`
(org_admin di Org B). Prendi l'`id` di un prodotto di Org A
(`PROD_A`) e l'`id` dell'organizzazione di Org B (`ORG_B`).

- [ ] **Assign cross-tenant forzato** — deve essere **bloccato con 403**:
      ```bash
      curl -sk -X POST -H "Cookie: $COOKIE_A" \
        -H "Content-Type: application/json" \
        -d "{\"organization_ids\": [$ORG_B]}" \
        "$BASE/api/products/$PROD_A/organizations"
      ```
      **Atteso**: `{"error": "You can only assign products to organizations you belong to"}`
      con HTTP **403**. Se ottieni 200, STOP: leak cross-tenant
      rientrato.

- [ ] **GET org list filtrata** — non deve leakkare org altrui:
      Prendi un `PROD_AB` assegnato a entrambe Org A e Org B (solo
      possibile se super_admin l'ha fatto, o per test fixture). Fai:
      ```bash
      curl -sk -H "Cookie: $COOKIE_A" \
        "$BASE/api/products/$PROD_AB/organizations" | python3 -m json.tool
      ```
      **Atteso**: `organizations` contiene **solo Org A**, non Org B.
      Se vedi Org B, il leak metadata su `get_product_organizations`
      e' rientrato.

- [ ] **User edit cross-tenant** — deve essere bloccato con 403:
      ```bash
      curl -sk -X POST -H "Cookie: $COOKIE_A" \
        -H "Content-Type: application/json" \
        -d "{\"organization_id\": $ORG_B, \"role\": \"org_admin\"}" \
        "$BASE/api/users/<user_id_in_Org_B>/organizations"
      ```
      **Atteso**: 403.

- [ ] **Integration PATCH cross-tenant** — deve essere bloccato con
      404 o 403:
      ```bash
      curl -sk -X PUT -H "Cookie: $COOKIE_A" \
        -H "Content-Type: application/json" \
        -d "{\"organization_id\": $ORG_B}" \
        "$BASE/api/integrations/<id_of_integration_in_Org_B>"
      ```

---

## ✅ Gate B — Verdict

- [ ] 🟢 TUTTI i check sopra sono verdi → puoi procedere con le Part C-I
- [ ] 🔴 ANCHE UNO e' rosso → **STOP**. C'e' un blocker. Non lanciare.
      Sistema e rifai il Gate B da capo.

Prossima parte: [`03_core_features.md`](03_core_features.md) o, se hai
fretta, salta direttamente a [`05_security_hardening.md`](05_security_hardening.md).
