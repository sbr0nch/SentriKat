# SENTRIKAT - TODO BEFORE LAUNCH
## Azioni Richieste Prima del Lancio Commerciale

---

**Documento Versione:** 1.0
**Ultimo Aggiornamento:** Febbraio 2026
**Scopo:** Checklist di azioni necessarie per completare i documenti business e avviare l'azienda

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

| Requisito | Priorità | Timeline |
|-----------|----------|----------|
| GDPR Compliance | ALTA | Prima del lancio EU |
| Privacy Policy completa | ALTA | Prima del lancio |
| Cookie Banner | ALTA | Per il sito web |
| DPA (Data Processing Agreement) | MEDIA | Per clienti enterprise |

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

### Must Have - Business
- [ ] Società costituita e operativa
- [ ] P.IVA attiva
- [ ] Conto corrente aziendale
- [x] Stripe configurato e testato
- [ ] ToS e Privacy Policy completati
- [ ] Dominio e hosting attivi
- [ ] Email aziendali funzionanti
- [x] Prezzi definiti (PRO €999/anno + agent packs)
- [ ] Landing page online
- [x] Demo disponibile

### Must Have - Licensing System
- [x] License server (RSA-4096 signing, FastAPI)
- [x] Portal license management (bind, rebind, download, copy)
- [x] Stripe payment integration on portal
- [x] SentriKat license validation (signature verification, hardware lock)
- [x] Input cleaning (prefix stripping, JSON extraction, BOM removal)
- [x] Edition mapping (pro→professional, demo→community)
- [x] Limit mapping (null→unlimited)
- [x] ENV→DB license sync
- [x] Embedded production RSA-4096 public key
- [x] GUI activation (Admin > License)
- [x] Installation ID generation and persistence
- [x] Docker-safe installation ID (SENTRIKAT_INSTALLATION_ID env var)
- [x] Feature gating (@requires_professional decorator)
- [x] License lifecycle (activation, expiration, migration/rebind)

### Must Have - Update & Deployment
- [x] CI/CD pipeline (GitHub Actions: test → build → push → release)
- [x] Docker image on GHCR (ghcr.io/sbr0nch/sentrikat)
- [x] Release packages (sentrikat-<version>.tar.gz)
- [x] Update scripts (update.sh for Linux, update.ps1 for Windows)
- [x] Centralized VERSION file
- [x] Version display in footer and license page
- [ ] In-app update notification (check for new versions in admin panel)

### Nice to Have
- [ ] Demo video
- [ ] Blog attivo
- [ ] Social media setup
- [ ] Newsletter pronta
- [ ] Certificazioni (SOC 2, etc.)
- [ ] In-app "Check for Updates" button

---

*Questo documento deve essere aggiornato man mano che le azioni vengono completate.*
