# 04 — Sprint 4 + 5 New Features (Part D)

> **Durata:** 1-2h. **Priorita':** 🔴 Obbligatoria — sono le feature nuove
> di cui non hai storia pregressa, devono passare tutte prima del lancio.

---

## D.1 Assignments Management page (Sprint 4 #29)

**Setup**: avere almeno 1 prodotto con vulnerabilita'. Login come `org_admin`.

- [ ] Naviga a **Assignments** (menu) → pagina con tabella
- [ ] Click "+ Create Assignment" → modal si apre
- [ ] Compila: assignee, CVE, priority, due_date, notes
- [ ] Salva → appare in lista
- [ ] Filter per status (open / in_progress / resolved / accepted_risk)
      → lista si aggiorna
- [ ] Filter per assignee → si aggiorna
- [ ] Filter per overdue=true → mostra solo scaduti
- [ ] Paginazione funziona (se hai ≥ 50 assignments)
- [ ] Inline status change (dropdown nella row) → persiste
- [ ] Click su una row → modal dettaglio / edit
- [ ] Modifica notes, resolution_notes → salva → persiste
- [ ] Delete assignment → rimossa dalla lista
- [ ] **Non-admin**: user normale non vede il bottone Create
      (o vede solo le assignments a lui)

## D.2 Issue Tracker Integration (Sprint 4 #30)

Setup: avere almeno un tracker configurato (Jira / GitHub / GitLab /
YouTrack / Webhook).

- [ ] Create Assignment → checkbox "Create Jira/tracker ticket"
- [ ] Salva → ticket creato nel tracker esterno
- [ ] `tracker_issue_key` popolato sull'assignment (es. "SEC-1234")
- [ ] `tracker_issue_url` popolato e apre il ticket nel tracker
- [ ] `tracker_type` popolato (jira / github / gitlab / youtrack / webhook)
- [ ] Backward compat: `jira_issue_key` (field vecchio) = `tracker_issue_key`
- [ ] **Strict tracker test**: invalida le credentials Jira, crea
      assignment con `?strict_tracker=true`:
      ```bash
      curl -sk -X POST -H "Cookie: $COOKIE_A" \
        -H "Content-Type: application/json" \
        -d '{"assigned_to":"test@example.com","match_id":1,"create_jira_ticket":true,"strict_tracker":true}' \
        "$BASE/api/remediation/assignments?strict_tracker=true"
      ```
      Atteso: HTTP 502, assignment NON creata nel DB (rollback).
- [ ] Senza `strict_tracker` (default legacy): assignment creata con
      warning, tracker_issue_key=NULL.

## D.3 Email Notifications per Assignments (Sprint 4 #31)

- [ ] Crea assignment → email spedita al **solo assignee** (non admin)
- [ ] Check logs: `docker compose logs sentrikat | grep -i "assignment.*email"`
- [ ] Cambia status a `resolved` → seconda email spedita
- [ ] Cambia status a `in_progress` → **nessuna email** (solo created/resolved)
- [ ] Crea 5 assignment nello stesso minuto per lo stesso assignee
      → max 1 email/ora (throttling applicato — controlla timestamps
      nelle email ricevute)
- [ ] Invalid email address (`user@localhost`) → log warning "Skipping
      invalid email address", no email

## D.4 SBOM Export — CycloneDX / SPDX / STIX 2.1 (Sprint 4 #32 + Sprint 5)

- [ ] Dashboard → Export → "SBOM" section visibile
- [ ] **CycloneDX 1.5 JSON** → download
      - `bomFormat: "CycloneDX"`, `specVersion: "1.5"`
      - `components` array: ogni component ha `type`, `name`, `version`,
        `purl` (es. `pkg:apt/openssl/openssl@1.1.1k`), `supplier` (vendor)
      - `vulnerabilities` array: ogni vuln ha `id`, `source`, `ratings`,
        `affects` refs
- [ ] **Validazione online**: upload su
      https://cyclonedx.github.io/cyclonedx.org/tool-center/ → no errors
- [ ] **SPDX 2.3 JSON** → download
      - `spdxVersion: "SPDX-2.3"`
      - `packages` array con SPDXID, name, versionInfo, externalRefs
        (cpe23Type se disponibile)
- [ ] **STIX 2.1 JSON** → download
      - `type: "bundle"`, `id` starts with `bundle--`
      - `objects` array:
        - Almeno 1 `vulnerability` SDO (external_references[0].source_name = "cve")
        - `software` SCO per ogni prodotto affetto
        - `relationship` SRO con `relationship_type: "affects"`
- [ ] **Validazione online**: upload su
      https://oasis-open.github.io/cti-stix-validator/ → no errors
- [ ] **Cross-tenant**: user di Org A → SBOM contiene SOLO dati Org A
- [ ] **License gate**: user Free → HTTP 403 con messaggio upgrade
- [ ] **Rate limit**: 11+ requests in 1 ora → HTTP 429 dopo il 10°
- [ ] **Size cap**: se l'org ha > 5000 prodotti → HTTP 413 con messaggio
      "too large"

## D.5 Risk Exception Management (Sprint 4 #33)

- [ ] Click shield icon → pannello Risk Exceptions
- [ ] Via API: `POST /api/risk-exceptions` con body:
      ```json
      {
        "justification": "WAF mitigation in place, patch Q3",
        "expires_at": "2026-12-31",
        "cve_id": "CVE-2024-1234",
        "product_id": 1
      }
      ```
      → HTTP 201
- [ ] Exception appare con status "Active"
- [ ] Justification truncated a 60 chars in tabella, full in tooltip
- [ ] Filter by status: Active / Revoked / Expired
- [ ] Click X (revoke) → conferma → status = "Revoked"
- [ ] Crea senza `expires_at` → "Expires" column mostra "Permanent"
- [ ] Crea con past `expires_at` → `is_expired: true` → icona warning
- [ ] Campo obbligatorio: POST senza `justification` → HTTP 400
- [ ] Length cap: POST con `justification` di 6000+ chars → HTTP 400
      "justification too long"
- [ ] Cross-tenant: try to revoke Org B's exception as Org A → HTTP 404
- [ ] Non-admin: regular user POST → HTTP 403
- [ ] Rate limit: 30+ POSTs/min → HTTP 429
- [ ] **Pagination**: `GET /api/risk-exceptions?page=1&per_page=10`
      ritorna `{risk_exceptions:[...], page:1, per_page:10, total:N, pages:N}`

## D.6 Agent Delta Scan + Gzip (Sprint 4 #34)

Setup: installa agent Linux/macOS/Windows su macchina di test.

### Linux / macOS agent
- [ ] **Primo run**: agent invia FULL inventory. Server log:
      `docker compose logs sentrikat | grep delta`
      → vedi `delta=full`
- [ ] **Secondo run (no changes)**: vedi `delta=unchanged`, lightweight heartbeat
- [ ] `last_hash.txt` esiste:
      - Linux: `/var/lib/sentrikat/last_hash.txt`
      - macOS: `/usr/local/var/sentrikat/last_hash.txt`
- [ ] Installa un pacchetto nuovo (es. `apt install jq`) → next run
      sends FULL di nuovo
- [ ] **24h forced full**: `sudo date -s "+25 hours"` → next run FULL
      anche se hash unchanged (poi resetta la data!)
- [ ] **Compression**: `tcpdump -A -i any port 443 | grep Content-Encoding`
      → `Content-Encoding: gzip` nel POST
- [ ] Server log payload size < 2KB compressed (era 100-500KB)

### Windows agent
- [ ] Stessi check. Hash file: `$env:ProgramData\SentriKat\last_hash.txt`
- [ ] PowerShell GZip in network capture (Fiddler o Wireshark)

### Server-side zip bomb protection
- [ ] Send 1KB compressed → 100MB decompressed (payload malevolo)
      → HTTP 413 "Decompressed payload too large"
- [ ] Send 5MB compressed (sopra il cap 2MB) → HTTP 413
      "Compressed payload too large"
- [ ] Normal 10KB compressed → 100KB decompressed → HTTP 200

## D.7 Agent Store-and-Forward (Sprint 4 #35)

- [ ] Stop il server SentriKat (o blocca hostname in /etc/hosts agent)
- [ ] Run agent 5 volte → 5 file in spool:
      - Linux: `/var/lib/sentrikat/spool/`
      - macOS: `/usr/local/var/sentrikat/spool/`
      - Windows: `$env:ProgramData\SentriKat\spool\`
- [ ] Restart server / unblock connectivity
- [ ] Run agent → spool files sent in chronological order **prima** del
      nuovo heartbeat
- [ ] Spool directory vuota dopo replay
- [ ] Spool limit: blocca server, 60+ heartbeats → spool contiene max
      50 file (oldest deleted)
- [ ] Replay stops on failure: blocca server mid-replay → no further
      replay attempts fino al prossimo heartbeat success
- [ ] Server logs: ogni spooled payload ricevuto e processato in ordine

## D.8 Product Alias (Sprint 4 #36)

- [ ] `POST /api/product-aliases` con `{product_id:1, alias_vendor:"OpenSSL", alias_product:"openssl-libs"}`
      → HTTP 201
- [ ] `GET /api/product-aliases?page=1&per_page=10` → alias listed con
      embedded product info, paginazione presente
- [ ] **Duplicate check**: POST same alias → HTTP 409 conflict
- [ ] **Cross-tenant**: `product_id` di Org B come Org A → HTTP 403
- [ ] **Delete**: `DELETE /api/product-aliases/<id>` → HTTP 200 → lista vuota
- [ ] **Non-admin**: regular user POST → HTTP 403
- [ ] **Rate limit**: 30+ POST/min → HTTP 429
- [ ] DB: unique constraint su `(organization_id, alias_vendor, alias_product)`

## D.9 Telemetry / Prometheus Metrics (Sprint 4)

```bash
curl -sk $BASE/metrics | grep sentrikat_
```

- [ ] Contiene `sentrikat_assignments{status="open|in_progress|resolved"}`
- [ ] Contiene `sentrikat_assignments_overdue`
- [ ] Contiene `sentrikat_assignments_with_tracker_ticket`
- [ ] Contiene `sentrikat_risk_exceptions{status="active|revoked|expired"}`
- [ ] Contiene `sentrikat_product_aliases_total`
- [ ] Valori riflettono lo stato reale del DB

## D.10 Vulnerability Trending Dashboard (Sprint 5)

- [ ] Dashboard → widget "Vulnerability Trends" (Chart.js)
- [ ] 3 view: **Total** / **By severity** / **Open vs resolved**
- [ ] Switch view → chart re-render senza page reload
- [ ] Empty state: fresh org, zero snapshots → messaggio "No trend data yet"
- [ ] `GET /api/vulnerabilities/trends?days=30` → array `trends` con
      `{date, total, critical, high, medium, low, open, resolved}`
- [ ] `?days=7` → solo ultimi 7 giorni
- [ ] **Force snapshot**: `POST /api/vulnerabilities/trends/snapshot`
      (admin only) → HTTP 200, nuova riga in `vulnerability_snapshots`
- [ ] Cross-tenant: Org A user → solo Org A snapshots
- [ ] Non-admin: force snapshot → HTTP 403
- [ ] Scheduler job `Daily Vulnerability Snapshot` alle 02:00 UTC
      (vedi `docker compose logs sentrikat | grep snapshot`)
- [ ] Con ≥ 2 snapshots, chart mostra linea continua

## D.11 STIX 2.1 Export (Sprint 5)

Gia' coperto in D.4 sopra. Verifica addizionale:

- [ ] Ogni STIX object ha un `id` valido che inizia con
      `vulnerability--`, `software--`, `relationship--`
- [ ] Ogni `vulnerability` SDO ha `created`, `modified`, `name`
- [ ] Ogni `software` SCO ha `name` e `version`
- [ ] Ogni `relationship` SRO ha `source_ref` e `target_ref` validi

## D.12 Patch Tuesday Digest (Sprint 5)

- [ ] Scheduler registra job `patch_tuesday_digest` con cron
      `day=8-14, dow=wed, hour=9, minute=0`:
      ```bash
      docker compose logs sentrikat | grep "Patch Tuesday"
      ```
- [ ] `app.scheduler.get_jobs()` contiene `patch_tuesday_digest`
- [ ] **Dry run**: `POST /api/reports/patch-tuesday/trigger?dry_run=true`
      → HTTP 200, response JSON con `dry_run: true`, `organization`,
      `digest` containing cve_count, NO email actually sent
- [ ] **Live trigger** (admin): `POST .../trigger` (no dry_run)
      → email delivered to org admin, subject contains the month
      (es. "SentriKat Patch Tuesday Digest — April 2026")
- [ ] **Rate limit**: 6 calls in 1 ora → 6° call → HTTP 429
- [ ] **Non-admin**: regular user POST → HTTP 403
- [ ] Job idempotency: `get_setting('patch_tuesday_marker_YYYY-MM')` =
      'true' dopo il primo run; manual trigger della stessa org lo
      skippa con log "already_sent" (noto: questo sara' migliorato in
      Sprint 6, vedi 99_TODO sezione 0.4)
- [ ] Uses `Vulnerability.date_added` (NON `published_date`)

## D.13 Compliance Gap Analysis Reports (Sprint 5 — PCI / ISO / SOC 2)

### PCI-DSS v4.0
- [ ] `GET /api/reports/compliance/pci-dss` → HTTP 200, JSON
- [ ] Top-level keys: `framework`, `version`, `generated_at`,
      `organization`, `requirements`, `integrity`
- [ ] `requirements` contiene entries per Req 6.3 e Req 11.3
- [ ] Ogni requirement ha `id`, `title`, `status`
      (`PASS|PARTIAL|FAIL|NOT_APPLICABLE`), `evidence`, `gaps`, `recommendations`
- [ ] `integrity.algorithm = "HMAC-SHA256"`, `hash`, `signed_at`
- [ ] `?format=pdf` → download PDF, cover page con nome org + data
- [ ] **License gate**: Free user → HTTP 403
- [ ] Cross-tenant: Org A user → only Org A data
- [ ] Verifica integrity: ricalcola HMAC-SHA256 sul JSON canonicale
      con `SECRET_KEY` → deve matchare `integrity.hash`

### ISO/IEC 27001:2022
- [ ] `GET /api/reports/compliance/iso-27001` → 200
- [ ] Requirements: A.8.8, A.8.16, A.5.24
- [ ] PDF variant funziona
- [ ] Integrity verifies

### SOC 2
- [ ] `GET /api/reports/compliance/soc2` → 200
- [ ] Requirements: CC7.1, CC7.2, CC7.4, CC6.6
- [ ] PDF variant funziona
- [ ] Integrity verifies

### Cross-cutting
- [ ] Rate limit: 11+ req in 1h → 429
- [ ] Content-Type: JSON = `application/json`, PDF = `application/pdf`
      + `Content-Disposition: attachment`
- [ ] `?format=xml` → HTTP 400 "Invalid format"
- [ ] Status mapping deterministico: stessa posture → stesso status
- [ ] Generation time per org con ~500 prodotti < 5 secondi
- [ ] **Size cap**: org con 100k+ requirements → truncated al 200°,
      nota `truncation_note` nel response

---

## ✅ Gate D

- [ ] Tutte le feature Sprint 4+5 verdi
- [ ] Eventuali `F` (fail) documentati e triaggiati in
      `docs/business/99_TODO_BEFORE_LAUNCH.md`

Prossima: [`05_security_hardening.md`](05_security_hardening.md)
