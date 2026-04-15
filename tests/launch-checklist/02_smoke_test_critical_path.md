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
> pipeline di generazione sono **CISA BOD 22-01** e **NIS2 Directive**
> (niente PCI-DSS / ISO 27001 / SOC 2 — se li vedi e' una regressione).
>
> ⚠️ **Disclaimer legale**: questi sono *assessment report interni*,
> **non certificati ufficiali firmati**. Non c'e' firma digitale ne'
> HMAC di integrita'. Non sono utilizzabili direttamente come submission
> regolatoria: un compliance officer deve rivederli e firmarli a parte.

- [ ] Settings → Compliance → "CISA BOD 22-01" → download JSON:
      - Campo `report_type: "CISA BOD 22-01 Compliance"`
      - Sezione KEV con elenco dei match KEV dell'organizzazione
      - Campo `scope_note` che chiarisce che SentriKat non fa
        external network-perimeter scan
- [ ] Settings → Compliance → "NIS2 Directive" → download JSON:
      - Campo `report_type: "NIS2 Directive - Vulnerability Management Compliance"`
      - Sezioni per i controlli di vulnerability management
- [ ] Ripeti il download in formato PDF:
      - Prima pagina: nome org, data, framework
      - Una sezione per ogni controllo
- [ ] Verifica che i bottoni "Download JSON" / "Download PDF" funzionino
      senza errore e che la risposta arrivi entro 10s per un org di
      dimensioni realistiche

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

---

## ✅ Gate B — Verdict

- [ ] 🟢 TUTTI i check sopra sono verdi → puoi procedere con le Part C-I
- [ ] 🔴 ANCHE UNO e' rosso → **STOP**. C'e' un blocker. Non lanciare.
      Sistema e rifai il Gate B da capo.

Prossima parte: [`03_core_features.md`](03_core_features.md) o, se hai
fretta, salta direttamente a [`05_security_hardening.md`](05_security_hardening.md).
