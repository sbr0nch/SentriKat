# 02 — Smoke Test Critical Path (Part B)

> **Durata:** 30 min. **Priorita':** 🔴 Obbligatoria.
> **Se qualcosa qui fallisce → STOP, c'e' un blocker di produzione.**

Questa e' la "golden path" del prodotto: il percorso che un customer
reale fara' nei primi 30 minuti. Se non funziona, niente lancio.

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

- [ ] Menu → Inventory (o Products) → vedi i prodotti di Org A
- [ ] Click su un prodotto → pagina dettaglio si apre correttamente
- [ ] Menu → Agents (o Endpoints) → vedi la lista asset
- [ ] Ogni asset ha: hostname, OS, last_seen, stato (online/offline/stale)
- [ ] Filtri per stato e per OS funzionano

## B.3 Vulnerabilita' e matching (5 min)

- [ ] Menu → Vulnerabilities → lista dei match caricata
- [ ] Filtro `severity=critical` → lista si aggiorna
- [ ] Click su un match → dettaglio CVE con:
      - CVE ID
      - CVSS score + fonte (NVD / CVE.org / EUVD)
      - EPSS percentile (se disponibile)
      - Prodotto + versione
      - Badge KEV se in CISA KEV
      - Badge "Ransomware" se nel feed ransomware
- [ ] Azione "Acknowledge" → status del match cambia

## B.4 Assignment + email notification (5 min)

- [ ] Da un match → click "Create Assignment"
- [ ] Compila: assignee=user@example.com, priority=high,
      due_date=2 settimane
- [ ] Salva → l'assignment appare nella pagina Assignments
- [ ] Lo status e' "open" di default
- [ ] La notifica email e' stata inviata (check inbox OR check log:
      `docker compose logs sentrikat | grep "assignment.*created"`)
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

- [ ] Dashboard → Export → "SBOM CycloneDX 1.5" → download
      - File JSON
      - `bomFormat: "CycloneDX"`, `specVersion: "1.5"`
      - `components` array non vuoto
- [ ] Dashboard → Export → "SBOM SPDX 2.3" → download
      - `spdxVersion: "SPDX-2.3"`, `packages` array non vuoto
- [ ] Dashboard → Export → "SBOM STIX 2.1" → download
      - `type: "bundle"`, `objects` array non vuoto

Via curl, sanity check rapido:
```bash
curl -sk -H "Cookie: $COOKIE_A" "$BASE/api/sbom/export/cyclonedx" \
  | python3 -c "import sys, json; d=json.load(sys.stdin); print('bomFormat:', d.get('bomFormat'), '/ specVersion:', d.get('specVersion'), '/ components:', len(d.get('components',[])))"
```
**Atteso:** `bomFormat: CycloneDX / specVersion: 1.5 / components: >0`

## B.7 Compliance reports (5 min)

- [ ] Dashboard → Reports → Compliance → "PCI-DSS v4.0" → JSON
      - Blocco `integrity` presente con `algorithm: "HMAC-SHA256"` e `hash`
      - `requirements` array con almeno 2 entry (6.3, 11.3)
      - Ogni requirement ha `status` (PASS/PARTIAL/FAIL/NOT_APPLICABLE)
- [ ] Click "PDF" → download, apri:
      - Prima pagina: nome org, data, framework
      - Una sezione per ogni requirement
      - Footer con integrity hash visibile
- [ ] Ripeti per ISO 27001 (Annex A.8.8, A.8.16, A.5.24)
- [ ] Ripeti per SOC 2 (CC7.1, CC7.2, CC7.4, CC6.6)

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
