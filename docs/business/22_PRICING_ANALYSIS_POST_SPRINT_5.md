# SENTRIKAT — PRICING ANALYSIS POST SPRINT 4 + 5

**Data:** Aprile 2026
**Autore:** Analisi tecnica dopo completamento Sprint 4 + Sprint 5
**Scopo:** Decidere se mantenere o alzare i prezzi SaaS dopo l'aggiunta di 15+ feature nuove

---

## 1. STATO ATTUALE

### Prezzi SaaS attualmente hardcoded in `app/models.py:3718-3822`

| Tier | Prezzo mensile | Prezzo annuale | Agents | Users | Orgs | Note |
|---|---|---|---|---|---|---|
| **Free** | €0 | €0 | 3 | 1 | 1 | 25 prodotti, 100MB, 1 API key |
| **Starter** | €59 | €590 (-17%) | 10 | 3 | 1 | Prodotti illimitati, 500MB |
| **Pro** | €199 | €1.990 (-17%) | 25 | 5 | 3 | 2GB, 5 API keys |
| **Business** | €499 | €4.990 (-17%) | 50 | 10 | 10 | 10GB, 25 API keys |
| **Enterprise** | €999 | €9.990 (-17%) | ∞ | ∞ | ∞ | Tutto illimitato |

### Prezzo on-premise (docs/business/04_PRICING_STRATEGY.md)

- **Demo:** gratis, 5 agent, 1 utente
- **Professional:** €4.999/anno, 10 agent (espandibile via pack)

---

## 2. COSA È CAMBIATO CON SPRINT 4 + SPRINT 5

Aggiunte **15 feature nuove** di cui 7 competitive-parity verso Tenable/Qualys/Wiz:

### Sprint 4 (ship)
- ✅ **SBOM Export CycloneDX 1.5 + SPDX 2.3** (must-have per CRA EU + EO 14028 USA)
- ✅ **STIX 2.1 Export** (must-have per threat intel sharing, MISP/ISAC)
- ✅ **Remediation Assignments + SLA Policies** (ticketing interno con due dates)
- ✅ **Issue tracker integration** (Jira, YouTrack, GitHub, GitLab, Webhook)
- ✅ **Risk Exception Management** (accetta rischio con justification + expiry, ISO/SOC2 evidence)
- ✅ **Email notifications** per assignments con throttling per Resend free tier
- ✅ **Agent delta scan + gzip** (-90% banda)
- ✅ **Agent offline store-and-forward** (zero perdita dati su connessioni intermittenti)
- ✅ **Product alias/disambiguation**

### Sprint 5 (ship)
- ✅ **Vulnerability trending dashboard** (grafico temporale Chart.js)
- ✅ **Patch Tuesday automation** (digest email 2° mercoledì del mese)
- ✅ **PCI-DSS v4.0 gap analysis report** (Req 6.3, 11.3)
- ✅ **ISO/IEC 27001:2022 gap analysis report** (Annex A.8.8, A.8.16, A.5.24)
- ✅ **SOC 2 gap analysis report** (CC7.1, CC7.2, CC7.4, CC6.6)

### Già presenti (Sprint 1-3)
- ✅ Container scanning + lockfile dependency scanning
- ✅ CISA BOD 22-01 + EU NIS2 compliance reports
- ✅ Multi-tenant SaaS con isolamento
- ✅ LDAP, SAML SSO, SMTP, Webhook

**Totale feature aggiunte dal momento in cui i prezzi attuali sono stati fissati:** ~18

---

## 3. CONFRONTO VS COMPETITOR (mid-market EU, 50 asset)

| Prodotto | Prezzo annuale ~50 asset | Incluso |
|---|---|---|
| **Tenable.io** | €24.000 - €36.000 | VM scanning, no SBOM, no remediation workflows |
| **Qualys VMDR** | €18.000 - €30.000 | VM + cloud, niente SBOM export standard |
| **Rapid7 InsightVM** | €15.000 - €25.000 | VM + remediation tracking |
| **Wiz** | €50.000+ | Solo cloud, no on-prem |
| **CrowdStrike Spotlight** | €20.000+ | EDR-bundled, no SBOM |
| **Greenbone / OpenVAS** | €5.000 - €10.000 | Network scanning, tech debt |
| **Defender for Cloud (Microsoft)** | €15.000+ | Solo Azure ecosystem |
| **SentriKat Business (ATTUALE)** | **€4.990** | Tutto quello che hanno loro + SBOM + compliance + EU hosting |

### Verdetto onesto sul prezzo attuale

**Business €499/mese è 4-6x più economico di Tenable** a parità di capability (ora), e siamo l'unico che offre:
- SBOM export CycloneDX + SPDX + STIX out-of-the-box
- Compliance gap analysis reports (CISA, NIS2, PCI-DSS, ISO 27001, SOC 2) out-of-the-box
- Hosting EU GDPR-native
- On-premise + SaaS (dual deployment)
- Open API

**Il prezzo attuale è sottoprezzato per il valore consegnato.**

---

## 4. RACCOMANDAZIONE PREZZI

### Principio guida

**Non sotto-prezzare mai più del 40% sotto i competitor diretti.** Se sei 70% meno caro, il cliente enterprise pensa "qualcosa non va, questo non può funzionare davvero". Il prezzo è un segnale di qualità.

Ma **mantieni il vantaggio sotto Tenable** per vincere sul mid-market che non si può permettere Tenable.

### Proposta nuova pricing (da applicare prima del lancio commerciale)

| Tier | ATTUALE | **NUOVO** | Δ | Ragionamento |
|---|---|---|---|---|
| **Free** | €0 | **€0** | = | Acquisition funnel. Non toccare. |
| **Starter** | €59 | **€59** | = | Prezzo d'ingresso per PMI. Non toccare. |
| **Pro** | €199 | **€249** | +25% | Giustificato da SBOM + assignments + trending + issue tracker + risk exceptions |
| **Business** | €499 | **€649** | +30% | Giustificato da compliance reports PCI/ISO/SOC2 (questo solo vale €200/mese) |
| **Enterprise** | €999 | **€1.499** | +50% | Unlimited + SLA garantito + priority support. Ancora 10x sotto Tenable |
| **NEW: Compliance Pack** | — | **+€199/mese** | — | Add-on opzionale su qualsiasi tier per sbloccare PCI-DSS/ISO 27001/SOC 2 reports |

### Grandfathering

**Regola fondamentale:** chi ha già un abbonamento attivo resta sul prezzo vecchio **per sempre** (o minimo 24 mesi). Questo è etico, riduce churn, e crea advocacy.

Nel codice: aggiungi campo `SubscriptionPlan.legacy_price` e logica in `licensing.py` per preservare il prezzo di iscrizione iniziale.

### Cosa succede al ricavo atteso

Con 100 clienti distribuiti realisticamente:
- 40 Free (€0) → €0
- 30 Starter (€59) → €1.770/mese
- 20 Pro (€249) → €4.980/mese (prima €3.980, **+€1.000**)
- 8 Business (€649) → €5.192/mese (prima €3.992, **+€1.200**)
- 2 Enterprise (€1.499) → €2.998/mese (prima €1.998, **+€1.000**)
- **Totale MRR:** €14.940/mese (prima €11.740, **+€3.200/mese = +27%**)
- **Totale ARR:** €179.280/anno (prima €140.880, **+€38.400/anno**)

**+27% di MRR senza aggiungere un singolo cliente**, solo riconoscendo il valore delle feature nuove.

### Perché funziona

1. **Lo sconto annuale resta a -17%** → incentivo forte a pagare annuale = meglio cashflow
2. **Free e Starter invariati** → zero friction sull'acquisizione
3. **Pro aumenta di soli €50/mese** → pochi churn su cliente attivo
4. **Business +€150/mese** giustificato da compliance reports (singolo report PCI-DSS costerebbe €2.000+ con consulente)
5. **Enterprise +€500/mese** → chi compra Enterprise non guarda la differenza
6. **Compliance Pack** come add-on = revenue stream aggiuntivo su tier bassi

---

## 5. POSSIAMO PERMETTERCELO? (COSTI)

### Costi variabili per cliente attivo (stima)

| Voce | Costo/mese per cliente attivo |
|---|---|
| Hosting VPS shared (DigitalOcean/Hetzner, condiviso fra molti org) | €0,50 - €2 |
| DB PostgreSQL (stesso) | €0,30 - €1 |
| CDN + static assets | €0,05 |
| Resend email (100 free, poi Pro €20 per 50k) | €0,02 - €0,40 |
| NVD/CISA sync (gratis) | €0 |
| Support tempo umano (stima 15 min/mese su Starter, 30 su Pro, 1h su Business) | €5 - €30 |
| **TOTALE COGS stimato** | **€6 - €35/mese per cliente** |

### Margini lordi

| Tier | Prezzo nuovo | COGS stimato | Margine lordo | % margine |
|---|---|---|---|---|
| Starter | €59 | €8 | €51 | 86% |
| Pro | €249 | €18 | €231 | 93% |
| Business | €649 | €40 | €609 | 94% |
| Enterprise | €1.499 | €80 | €1.419 | 95% |

**Margini software-tipici (85-95%)**. Scalabile. Sì, puoi permetterti questi prezzi.

### Investimento necessario per sostenere il lancio

| Voce | One-time | Mensile |
|---|---|---|
| Infrastruttura EU (Hetzner, 2 server prod + 1 staging) | €0 | €150 |
| Stripe setup + fees (~3% sulle transazioni) | €0 | ~3% MRR |
| Dominio + email (Fastmail/Google Workspace) | €50 | €12 |
| Legal review TOS/Privacy | €800 - €2.000 | €0 |
| Marchio EUIPO | €850 (1 classe) | €0 |
| P.IVA + commercialista | €400 | €120 |
| Sito marketing (Framer/Webflow template + customization) | €0 - €500 | €25 |
| **TOTALE** | **~€2.500** | **~€450 + fees** |

### Break-even

Con i prezzi nuovi, bastano **1 Business + 2 Pro** per coprire tutti i costi fissi mensili (€649 + €498 = €1.147 vs €450). **Break-even a 3 clienti paganti.** Molto raggiungibile.

---

## 6. QUANDO APPLICARE L'AUMENTO

**Timing consigliato:**

1. **Settimana 1-2:** Chiudi bugfixing + full test (vedi `PRE_LAUNCH_BUGFIX_AND_TEST_PLAN.md`)
2. **Settimana 3:** Deploy production + dominio + Stripe in live mode
3. **Settimana 4:** Aggiorna il sito con i nuovi prezzi + pubblica feature page Sprint 4+5 + blog post
4. **Settimana 5:** Primi invii cold (vedi `21_SALES_CAMPAIGN_STARTER_PACK.md`)
5. **Settimana 6+:** Iterazioni sulla base del feedback

**NON cambiare i prezzi dopo aver già venduto a clienti al prezzo vecchio**, a meno di grandfathering rigoroso.

---

## 7. AZIONI CONCRETE DA FARE NEL CODICE

Prima di cambiare i prezzi in produzione:

1. `app/models.py:3718-3822` — aggiornare `DEFAULT_PLANS`:
   ```python
   # Pro: 19900 → 24900 (€199 → €249)
   # Business: 49900 → 64900 (€499 → €649)
   # Enterprise: 99900 → 149900 (€999 → €1499)
   ```
2. Aggiungere campo `legacy_price_monthly_cents` per grandfathering
3. `app/licensing.py` — aggiungere `compliance_pack` add-on feature key
4. Creare endpoint `POST /api/billing/upgrade-to-compliance-pack`
5. Stripe: creare Price ID per ogni nuovo prezzo + un Price ID per Compliance Pack (€199/mese)
6. Sito: aggiornare pagina pricing (vedi `20_SPRINT_4_5_WEB_BRIEF.md`)
7. Email ai clienti esistenti: "Stiamo aggiornando i prezzi, tu resti sul vecchio per sempre"

---

## 8. RISCHI DELL'AUMENTO

| Rischio | Mitigazione |
|---|---|
| Churn su clienti esistenti | Grandfathering rigoroso, comunicazione chiara |
| Prospect si spaventa del prezzo più alto | Enfatizza il confronto con Tenable (siamo ancora 5x più economici) |
| Competitor ci accusa di averci aumentato | Risposta: "Abbiamo aggiunto 15 feature, il prezzo riflette il valore nuovo" |
| Resend quota esaurita se Business fa troppe email | Già risolto con throttling Sprint 4 (max 1 email per assignment/ora) |

---

## 9. DECISIONE FINALE

**Raccomandazione:** ALZARE i prezzi come da proposta sopra, con grandfathering rigoroso per clienti esistenti. Lanciare con i prezzi nuovi sul sito dal giorno 1 del lancio commerciale.

**Expected outcome:**
- MRR +27% a parità di clienti
- ARR +€38k/anno
- Margini lordi al 90%+
- Break-even a 3 clienti paganti
- Ancora 4-8x più economici di Tenable/Qualys/Rapid7

**Se il rialzo non ti convince → tieni Starter e Pro invariati, alza solo Business → €599 e Enterprise → €1.299.** Sarebbe un aumento minimo che comunque copre il valore di PCI-DSS/ISO/SOC 2 reports.
