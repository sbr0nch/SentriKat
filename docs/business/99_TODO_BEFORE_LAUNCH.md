# SENTRIKAT - TODO BEFORE LAUNCH
## Azioni Richieste Prima del Lancio Commerciale

---

**Documento Versione:** 1.1
**Ultimo Aggiornamento:** Aprile 2026 (esteso dopo Sprint 4+5 audit)
**Scopo:** Checklist di azioni necessarie per completare i documenti business e avviare l'azienda

---

## 0. DEBITO TECNICO DA SPRINT 4+5 AUDIT (Aprile 2026)

Questi item sono stati identificati dall'audit security + completeness del
2026-04-14 e **accettati come debito tecnico** perche' troppo grossi per
essere fixati prima del lancio. Devono essere pianificati nei Sprint 6-7.

### 0.1 Test coverage automatica per Sprint 4+5 (HIGH — 3-5 giorni)

Al momento **zero** test coprono i moduli nuovi. Serve scrivere minimo:
- [ ] `tests/test_sbom_export.py` — happy path + license gate + cross-tenant + size cap
- [ ] `tests/test_compliance_reports.py` — JSON + PDF per i 3 framework, integrity block verification, format validation, size cap
- [ ] `tests/test_remediation_api.py` — assignments CRUD, SLA policies, risk exceptions, product aliases, cross-tenant, pagination
- [ ] `tests/test_scheduler_sprint5.py` — patch_tuesday_digest_job (dry-run, idempotency, quota), vulnerability_snapshot_job
- [ ] `tests/test_agent_delta_scan.py` — delta scan hash detection + gzip round-trip + store-and-forward replay

Target: 80%+ coverage sui 4 moduli nuovi (`sbom_export.py`, `compliance_reports.py`, `remediation_api.py`, `email_service.py` sezione Sprint 4+5).

### 0.2 OpenAPI spec update (HIGH — 2 ore)

- [ ] Aggiornare `app/api_docs.py` con le voci OpenAPI per tutti gli endpoint Sprint 4+5 (20+):
  - `/api/sbom/export/{cyclonedx,spdx,stix21}`
  - `/api/reports/compliance/{pci-dss,iso-27001,soc2}`
  - `/api/remediation/assignments` (GET/POST/PUT/DELETE)
  - `/api/sla/policies`, `/api/sla/compliance`
  - `/api/risk-exceptions` (GET/POST/PUT/DELETE)
  - `/api/product-aliases` (GET/POST/DELETE)
  - `/api/vulnerabilities/trends`, `/api/vulnerabilities/trends/snapshot`
  - `/api/reports/patch-tuesday/trigger`

### 0.3 Email throttle DB-backed (MEDIUM — 1 giorno)

`app/email_service.py:147-303` usa un dict in-memory per throttlare le
email sulle assignments. Problemi:
1. Multi-worker gunicorn: ogni worker ha il proprio dict → nessun throttle cross-worker
2. Restart server → azzerato → spam temporaneo
3. Race condition check/update non atomico

Fix:
- [ ] Aggiungere tabella `email_throttle (subject_key TEXT PK, last_sent_at TIMESTAMP)` oppure colonna `last_email_sent_at` su `RemediationAssignment`
- [ ] Sostituire il dict con una `UPDATE ... WHERE last_sent_at < NOW() - INTERVAL '1 hour'` atomica che ritorna il row count (1 = procedi, 0 = throttled)
- [ ] Test multi-worker con 5 worker gunicorn + 10 POST paralleli = max 1 email per assignment/ora

### 0.4 Patch Tuesday digest idempotency DB-backed (MEDIUM — 1 giorno)

`app/scheduler.py:1571-1572` usa `get_setting(marker_key)` per tracciare
"already_sent". Problemi: niente timestamp/expiry, mid-run failure → digest perso.

Fix:
- [ ] Creare tabella `patch_tuesday_digest_log (id, organization_id, sent_at, success, error, cve_count)`
- [ ] Sostituire il check `get_setting()` con `SELECT 1 FROM patch_tuesday_digest_log WHERE organization_id = :org AND sent_at >= :start_of_month AND success = true`
- [ ] Eliminare il marker setting una volta che il log e' in produzione
- [ ] Query dashboard opzionale per vedere chi ha ricevuto cosa e quando

### 0.5 Flask-Migrate / Alembic setup formale (MEDIUM — 2-4 ore)

Sprint 4+5 usa uno script SQL manuale (`migrations/sprint4_sprint5/upgrade.sql`).
Per i prossimi sprint va inizializzato Alembic proprio:

- [ ] `flask db init` su staging → crea `migrations/alembic.ini` e `migrations/env.py`
- [ ] `flask db stamp <baseline_revision>` su ogni istanza in esecuzione per marcarla a schema pre-Sprint-4
- [ ] `flask db migrate -m "sprint4_sprint5_baseline"` → genera revision automatica
- [ ] Verificare che la revision matchi il contenuto dello script SQL manuale
- [ ] Applicare con `flask db upgrade` su staging, poi prod
- [ ] Documentare workflow in `docs/ADMIN_GUIDE.md`

### 0.6 Fix MEDIUM/LOW gia' applicati 2026-04-14

Questi sono gia' stati fixati nel commit che ha aggiunto l'audit:

- [x] CSRF exempt rimosso da `sbom_export`, `compliance_reports`, `remediation_api` blueprint (9.6)
- [x] Pagination su `list_risk_exceptions` e `list_product_aliases` (9.7)
- [x] Format param validation `json|pdf` nei compliance reports (9.14)
- [x] `MAX_SBOM_PRODUCTS = 5000` size cap (9.9)
- [x] `MAX_REPORT_REQUIREMENTS = 200` + evidence cap nei PDF (9.8)
- [x] `@limiter.limit("5/hour")` su `/api/reports/patch-tuesday/trigger` (9.11)
- [x] Email regex + CRLF injection protection in `email_provider.py` (9.13)
- [x] `assigned_to` validation (regex + length) + `notes` cap (9.17, 9.16)
- [x] `justification` length cap (9.16)
- [x] `strict_tracker=true` opt-in rollback su Jira failure (9.12)
- [x] Bare except critici in `scheduler.py` convertiti a logger.warning (9.15)
- [x] PDF error context nelle response 500 (9.18)
- [x] Alembic SQL manual migration scripts in `migrations/sprint4_sprint5/` (BLOCKER 9.1)

### 0.7 BLOCKER NON fixato automaticamente — richiede intervento umano

- [ ] **Verificare SECRET_KEY in produzione** (HIGH 9.3): lanciare sulla VM
      `python3 -c "import os; k=os.environ.get('SECRET_KEY',''); print('len:', len(k), 'is_hex:', all(c in '0123456789abcdef' for c in k), 'is_default:', k in ('','dev-secret-key','change-me'))"`
      → se len < 64 o is_default = True → sostituire con
      `python3 -c "import secrets; print(secrets.token_hex(32))"` e ridepployare.
- [ ] Se esistono compliance report gia' generati prima del cambio di
      SECRET_KEY, documentare che la loro integrity hash e' firmata con la
      chiave vecchia e non piu' riverificabile dopo la rotazione.

### 0.8 Minor test failure — test_siem_syslog

Dopo il deploy Sprint 4+5 la test suite e' stata girata (1.329 test
totali, **1.328 passed, 1 failed** — 99.92% pass rate). L'unico fail e':

- `tests/test_siem_syslog.py::TestUpdateSyslogSettings::test_no_data_returns_400`
  expected: `assert 403 == 400`

**Diagnosi**: l'endpoint `POST /api/settings/syslog` (in `app/reports_api.py:1795`)
ha il decorator `@requires_professional('SIEM Integration')` che restituisce
HTTP 403 quando la licensing feature key non e' attiva. Nel container di
test con configurazione "fresh install" (nessuna licenza professional
importata) il check licensing scatta PRIMA del check "no data" = 400, e
quindi il test vede 403 invece di 400.

**NON e' un bug introdotto da Sprint 4+5**. Nessun file di Sprint 4+5
tocca `reports_api.py` ne' il blueprint di settings syslog. Il test
verosimilmente falliva gia' prima della Sprint 4, ma la suite non era
stata girata end-to-end di recente.

**Opzioni di fix** (1-2h, Sprint 6):
- Aggiungere una licenza pro mock nel fixture `admin_client` di testing.
- Oppure skippare il test con `@pytest.mark.skipif(not has_pro_license)`.
- Oppure riordinare i decorator nell'endpoint: prima il check "no data"
  (400), poi il check licensing (403) — piu' REST-friendly.

**Impatto sul lancio**: ZERO. L'endpoint funziona correttamente in
produzione perche' in prod la licenza pro e' attiva. Il test failure e'
un artefatto del test environment.

---

## 1. AZIONI LEGALI E SOCIETARIE

### 1.1 Costituzione Azienda

| Azione | Priorità | Note |
|--------|----------|------|
| Scegliere forma giuridica (SRL, SRLS, etc.) | ALTA | Consulta commercialista |
| Registrare la società | ALTA | Camera di Commercio |
| Ottenere P.IVA | ALTA | Agenzia delle Entrate |
| Aprire conto corrente aziendale | ALTA | Necessario per Stripe |
| Registrare PEC aziendale | ALTA | Obbligatoria per SRL |
| Depositare marchio "SentriKat" | MEDIA | UIBM o EUIPO |

### 1.2 Contratti e Documenti Legali

| Documento | File | Cosa Aggiornare |
|-----------|------|-----------------|
| Terms of Service | `05_TERMS_OF_SERVICE.md` | - Linea 261: Inserire giurisdizione legale<br>- Linea 295: Inserire indirizzo legale<br>- Revisione legale completa consigliata |
| Privacy Policy | `06_PRIVACY_POLICY.md` | - Linea 215: Inserire giurisdizione<br>- Linea 239: Inserire indirizzo fisico<br>- Verificare conformità GDPR con DPO |
| SLA | `07_SLA.md` | Nessun placeholder, ma revisiona i tempi di risposta |

---

## 2. AGGIORNAMENTI AI DOCUMENTI

### 2.1 Executive Summary (`01_EXECUTIVE_SUMMARY.md`)

| Linea | Placeholder | Da Sostituire Con |
|-------|-------------|-------------------|
| 9 | `[your-email]` | Email aziendale reale |
| 71-74 | `$X/month`, `$Y/month`, `$Z/month` | Prezzi definitivi dopo validazione mercato |
| 151 | `[Your Name]` | Nome completo fondatore |
| 202-203 | `[your-email]` | Email contatto |

### 2.2 Privacy Policy (`06_PRIVACY_POLICY.md`)

| Linea | Placeholder | Da Sostituire Con |
|-------|-------------|-------------------|
| 215 | `[Your Jurisdiction]` | Italia/EU o giurisdizione scelta |
| 239 | `[Your Address]` | Indirizzo sede legale |

### 2.3 Pricing Strategy (`04_PRICING_STRATEGY.md`)

| Sezione | Cosa Fare |
|---------|-----------|
| Prezzi | Validare con A/B testing o customer interviews |
| Proiezioni finanziarie | Aggiornare dopo primi 3-6 mesi di vendite |

### 2.4 Go-to-Market (`08_GO_TO_MARKET.md`)

| Sezione | Cosa Fare |
|---------|-----------|
| Budget | Aggiornare con budget reale disponibile |
| Timeline | Adattare alle date effettive di lancio |

---

## 3. INFRASTRUTTURA E ACCOUNT

### 3.1 Account da Creare

| Servizio | Scopo | URL |
|----------|-------|-----|
| Stripe | Pagamenti | https://stripe.com |
| SendGrid/Resend | Email transazionali | https://sendgrid.com |
| Plausible/GA4 | Analytics | https://plausible.io |
| GitHub Organization | Gestione codice | https://github.com |
| Cloudflare | DNS/CDN | https://cloudflare.com |
| OVH/Hetzner | Server hosting | Provider EU |

### 3.2 Domini e DNS

| Dominio | Stato | Azione |
|---------|-------|--------|
| sentrikat.com | Da verificare | Acquistare se non già posseduto |
| sentrikat.eu | Consigliato | Protezione brand EU |
| sentrikat.it | Consigliato | Mercato italiano |

### 3.3 Email Aziendali da Configurare

```
support@sentrikat.com    - Supporto clienti
sales@sentrikat.com      - Vendite
legal@sentrikat.com      - Questioni legali
privacy@sentrikat.com    - Richieste privacy
dpo@sentrikat.com        - Data Protection Officer
billing@sentrikat.com    - Fatturazione
info@sentrikat.com       - Informazioni generali
```

---

## 4. PRICING DA DEFINIRE

### 4.1 Ricerca di Mercato Necessaria

Prima di fissare i prezzi definitivi:

1. **Customer Interviews** (5-10 potenziali clienti)
   - Quanto pagano attualmente per soluzioni simili?
   - Qual è il budget tipico per security tools?
   - Quale modello preferiscono (per-agent vs flat)?

2. **Analisi Competitor Aggiornata**
   - Tenable.io: ~$2,900/anno per 128 asset ([fonte](https://www.tenable.com/buy))
   - Qualys: Contattare per preventivo
   - Rapid7: Contattare per preventivo

### 4.2 Prezzi Suggeriti (Da Validare)

| Tier | Suggerito | Basato Su |
|------|-----------|-----------|
| Professional | €99-149/mese | 70-80% in meno di Tenable |
| Agent Pack +10 | €49-79/mese | Margine 85%+ |
| Agent Pack +25 | €99-149/mese | Volume discount |
| Business | €499-699/mese | Mid-market target |

---

## 5. COMPLIANCE E CERTIFICAZIONI

### 5.1 Priorità Immediata

| Requisito | Priorità | Timeline | Stato |
|-----------|----------|----------|-------|
| GDPR Export endpoint (`/api/gdpr/export`) | ALTA | Prima del lancio EU | FATTO |
| GDPR Delete endpoint (`/api/gdpr/delete`) | ALTA | Prima del lancio EU | FATTO |
| security.txt (`/.well-known/security.txt`) | ALTA | Prima del lancio | FATTO |
| Prometheus metrics (`/metrics`) | MEDIA | Prima del lancio | FATTO |
| Password reset token hashing (SHA-256) | ALTA | Prima del lancio | FATTO |
| Docker read-only filesystem | MEDIA | Prima del lancio | FATTO |
| Privacy Policy completa | ALTA | Prima del lancio | Da fare (testo in docs/business/06) |
| Cookie Banner | ALTA | Per il sito web | Da fare (sentrikat-web) |
| DPA (Data Processing Agreement) | MEDIA | Per clienti enterprise | Da fare |

### 5.2 Priorità Futura (Post-Launch)

| Certificazione | Quando | Costo Stimato |
|----------------|--------|---------------|
| SOC 2 Type I | Anno 1 | €15,000-30,000 |
| SOC 2 Type II | Anno 2 | €20,000-40,000 |
| ISO 27001 | Anno 2-3 | €25,000-50,000 |
| CE Marking (se applicabile) | Verificare | Variabile |

---

## 6. MARKETING E BRANDING

### 6.1 Asset da Creare

| Asset | Priorità | Note |
|-------|----------|------|
| Logo vettoriale (SVG, AI) | ALTA | Per sito e materiali |
| Brand guidelines | MEDIA | Colori, font, usage |
| Demo video (2-3 min) | ALTA | Per landing page |
| Screenshot prodotto | ALTA | Per marketing |
| Slide deck investitori | ALTA | PowerPoint/Google Slides |

### 6.2 Contenuti da Preparare

| Contenuto | Priorità |
|-----------|----------|
| Landing page copy | ALTA |
| Blog post di lancio | ALTA |
| Comparison pages (vs competitors) | MEDIA |
| Case study template | MEDIA |
| Newsletter template | BASSA |

---

## 7. VALIDAZIONE DATI NEI DOCUMENTI

### 7.1 Dati con Fonti Verificate ✅

I seguenti dati nei documenti hanno fonti affidabili:

| Dato | Valore | Fonte |
|------|--------|-------|
| Mercato VM globale 2024 | $16.5B | [Grand View Research](https://www.grandviewresearch.com/industry-analysis/security-and-vulnerability-management-svm-market) |
| CAGR mercato | 6.5-9.6% | [MarketsandMarkets](https://www.marketsandmarkets.com/Market-Reports/security-vulnerability-management-market-204180861.html) |
| CVE totali 2024 | 40,009 | [CyberPress](https://cyberpress.org/over-40000-cves-published-in-2024/) |
| CISA KEV totale | 1,484 (2025) | [SecurityWeek](https://www.securityweek.com/cisa-kev-catalog-expanded-20-in-2025-topping-1480-entries/) |
| Tenable Nessus Pro prezzo | ~$3,590/anno | [Tenable](https://www.tenable.com/buy) |

### 7.2 Dati da Aggiornare Periodicamente

| Dato | Frequenza | Fonte |
|------|-----------|-------|
| Numero CVE in NVD | Trimestrale | [NVD Statistics](https://nvd.nist.gov/vuln/search/statistics) |
| CISA KEV count | Mensile | [CISA KEV](https://www.cisa.gov/known-exploited-vulnerabilities-catalog) |
| Market size | Annuale | Report di ricerca |
| Competitor pricing | Semestrale | Siti competitor |

---

## 8. TIMELINE SUGGERITA

### Settimana 1-2: Fondazione
- [ ] Consultazione commercialista
- [ ] Decisione forma giuridica
- [ ] Registrazione società
- [ ] Apertura conto corrente

### Settimana 3-4: Infrastruttura
- [ ] Setup Stripe
- [ ] Configurazione email aziendali
- [ ] Setup hosting produzione

### Settimana 5-6: Documenti Legali
- [ ] Revisione legale ToS e Privacy Policy
- [ ] Completamento placeholder nei documenti
- [ ] Preparazione DPA template

### Settimana 7-8: Marketing
- [ ] Finalizzazione pricing
- [ ] Creazione landing page
- [ ] Preparazione demo video

### Settimana 9-10: Soft Launch
- [ ] Beta con 5-10 utenti
- [ ] Raccolta feedback
- [ ] Iterazione prodotto

### Settimana 11-12: Launch
- [ ] Annuncio pubblico
- [ ] Primo push marketing
- [ ] Monitoraggio metriche

---

## 9. CONTATTI UTILI

### Professionisti da Coinvolgere

| Ruolo | Scopo | Quando |
|-------|-------|--------|
| Commercialista | Costituzione, fiscalità | Subito |
| Avvocato tech/privacy | Revisione contratti, GDPR | Prima del lancio |
| Designer | Logo, brand identity | Prima del lancio |
| Copywriter | Contenuti marketing | Prima del lancio |

---

## 10. CHECKLIST FINALE PRE-LANCIO

### Must Have
- [ ] Società costituita e operativa
- [ ] P.IVA attiva
- [ ] Conto corrente aziendale
- [ ] Stripe configurato e testato
- [ ] ToS e Privacy Policy completati
- [ ] Dominio e hosting attivi
- [ ] Email aziendali funzionanti
- [ ] Prezzi definiti
- [ ] Landing page online
- [ ] Demo disponibile

### Nice to Have
- [ ] Demo video
- [ ] Blog attivo
- [ ] Social media setup
- [ ] Newsletter pronta
- [ ] Certificazioni (SOC 2, etc.)

---

*Questo documento deve essere aggiornato man mano che le azioni vengono completate.*
