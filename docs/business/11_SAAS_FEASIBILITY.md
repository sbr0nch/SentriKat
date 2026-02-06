# SENTRIKAT - SAAS FEASIBILITY ANALYSIS
## Analisi di Fattibilità per Offerta Cloud/SaaS

---

**Versione:** 1.0
**Ultimo Aggiornamento:** Febbraio 2026
**Autore:** SentriKat Development Team

---

## 1. EXECUTIVE SUMMARY

### 1.1 Obiettivo del Documento

Questo documento analizza la fattibilità di trasformare SentriKat da prodotto **self-hosted** a un'offerta **SaaS (Software as a Service)** cloud-hosted, valutando:
- Opportunità di mercato
- Requisiti tecnici
- Costi operativi
- ROI atteso
- Rischi e mitigazioni

### 1.2 Raccomandazione

| Scenario | Raccomandazione | Motivazione |
|----------|-----------------|-------------|
| Anno 1 (2026) | **Self-hosted only** | Focus su PMV, bassa complessità |
| Anno 2 (2027) | **Hybrid (self-hosted + SaaS)** | Expand market, incrementa ARR |
| Anno 3+ (2028) | **SaaS-first** | Scalabilità, ricavi ricorrenti |

**Verdetto: SaaS è FATTIBILE ma richiede investimento iniziale significativo (~€50-100k) e 6-12 mesi di sviluppo.**

---

## 2. ANALISI DI MERCATO

### 2.1 Trend del Mercato SaaS

| Metrica | Valore | Fonte |
|---------|--------|-------|
| Mercato SaaS globale 2024 | $197B | [Statista](https://www.statista.com/statistics/505243/worldwide-software-as-a-service-revenue/) |
| CAGR previsto 2024-2030 | 13.7% | [Grand View Research](https://www.grandviewresearch.com/industry-analysis/saas-market-report) |
| % aziende che usano SaaS | 80%+ | [Gartner](https://www.gartner.com/en/newsroom/press-releases/2022-04-19-gartner-forecasts-worldwide-public-cloud-end-user-spending-to-reach-nearly-500-billion-in-2022) |

### 2.2 Preferenze Clienti nel Security Market

```
┌─────────────────────────────────────────────────────────────────────┐
│           PREFERENZE DEPLOYMENT (Security Software)                  │
├─────────────────────────────────────────────────────────────────────┤
│                                                                      │
│   Enterprise (>5000 emp)     │████████████████░░░░│ 80% Self-hosted │
│                              │                    │ 20% SaaS        │
│                                                                      │
│   Mid-Market (500-5000)      │████████████░░░░░░░░│ 60% Self-hosted │
│                              │                    │ 40% SaaS        │
│                                                                      │
│   SMB (<500 emp)             │████░░░░░░░░░░░░░░░░│ 20% Self-hosted │
│                              │                    │ 80% SaaS        │
│                                                                      │
│   Fonte: Forrester 2024 Security Survey                             │
└─────────────────────────────────────────────────────────────────────┘
```

### 2.3 Competitor Analysis (Self-hosted vs SaaS)

| Competitor | Self-Hosted | SaaS | Entrambi |
|------------|-------------|------|----------|
| Tenable | Nessus Pro | Tenable.io | ✓ |
| Qualys | - | VMDR | Solo SaaS |
| Rapid7 | InsightVM | InsightVM Cloud | ✓ |
| OpenVAS/Greenbone | ✓ | - | Solo self-hosted |
| **SentriKat (oggi)** | **✓** | **-** | **Solo self-hosted** |

**Opportunità:** SentriKat può differenziarsi offrendo entrambe le opzioni, cosa che pochi competitor mid-market fanno.

---

## 3. ARCHITETTURA SAAS PROPOSTA

### 3.1 Multi-Tenant Architecture

```
┌─────────────────────────────────────────────────────────────────────┐
│                    SENTRIKAT SAAS ARCHITECTURE                       │
├─────────────────────────────────────────────────────────────────────┤
│                                                                      │
│                         ┌─────────────────┐                         │
│                         │   CLOUDFLARE    │                         │
│                         │   CDN / WAF     │                         │
│                         └────────┬────────┘                         │
│                                  │                                   │
│                         ┌────────▼────────┐                         │
│                         │  LOAD BALANCER  │                         │
│                         │   (AWS ALB)     │                         │
│                         └────────┬────────┘                         │
│                                  │                                   │
│          ┌───────────────────────┼───────────────────────┐          │
│          │                       │                       │          │
│   ┌──────▼──────┐        ┌──────▼──────┐        ┌──────▼──────┐    │
│   │  APP POD 1  │        │  APP POD 2  │        │  APP POD N  │    │
│   │  (K8s)      │        │  (K8s)      │        │  (K8s)      │    │
│   └──────┬──────┘        └──────┬──────┘        └──────┬──────┘    │
│          │                       │                       │          │
│          └───────────────────────┼───────────────────────┘          │
│                                  │                                   │
│          ┌───────────────────────┼───────────────────────┐          │
│          │                       │                       │          │
│   ┌──────▼──────┐        ┌──────▼──────┐        ┌──────▼──────┐    │
│   │  DATABASE   │        │   REDIS     │        │   STORAGE   │    │
│   │  (RDS PG)   │        │  (Elastica) │        │   (S3)      │    │
│   └─────────────┘        └─────────────┘        └─────────────┘    │
│                                                                      │
│   ISOLAMENTO DATI: Schema-per-tenant o Row-Level Security           │
│                                                                      │
└─────────────────────────────────────────────────────────────────────┘
```

### 3.2 Opzioni di Multi-Tenancy

| Modello | Pro | Contro | Costo | Raccomandato |
|---------|-----|--------|-------|--------------|
| **Shared DB, Row-Level Security** | Basso costo, semplice | Rischio isolamento | € | ✓ Per start |
| **Schema-per-Tenant** | Buon isolamento, backup facili | Più complesso | €€ | ✓ Mid-term |
| **DB-per-Tenant** | Isolamento totale | Costoso, ops complesse | €€€ | Enterprise only |
| **Instance-per-Tenant** | Isolamento massimo | Molto costoso | €€€€ | Non raccomandato |

**Raccomandazione:** Iniziare con **Row-Level Security** in PostgreSQL, migrare a **Schema-per-Tenant** per clienti enterprise.

### 3.3 Modifiche Codice Necessarie

```python
# MODIFICHE RICHIESTE PER MULTI-TENANT

# 1. Tenant Context Middleware
class TenantMiddleware:
    def __init__(self, app):
        self.app = app

    def __call__(self, environ, start_response):
        # Estrai tenant da subdomain o header
        host = environ.get('HTTP_HOST', '')
        tenant = host.split('.')[0] if '.' in host else 'default'
        environ['TENANT_ID'] = tenant
        return self.app(environ, start_response)

# 2. Row-Level Security in PostgreSQL
"""
-- Abilita RLS su ogni tabella
ALTER TABLE product ENABLE ROW LEVEL SECURITY;

-- Policy per tenant
CREATE POLICY tenant_isolation ON product
    USING (tenant_id = current_setting('app.current_tenant')::uuid);

-- Set tenant context
SET app.current_tenant = 'tenant-uuid-here';
"""

# 3. Modifica modelli SQLAlchemy
class Product(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    tenant_id = db.Column(db.UUID, nullable=False, index=True)  # NUOVO
    # ... existing fields

# 4. Query con tenant filter automatico
class TenantQuery(BaseQuery):
    def filter_by_tenant(self):
        tenant_id = g.get('tenant_id')
        return self.filter_by(tenant_id=tenant_id)

# 5. Stima effort: 80-120 ore di sviluppo
```

---

## 4. ANALISI COSTI

### 4.1 Costi Infrastruttura Cloud (AWS)

#### Scenario: 100 Clienti SaaS

| Servizio | Configurazione | Costo/mese |
|----------|----------------|------------|
| EKS Cluster | 3 nodes t3.medium | €150 |
| RDS PostgreSQL | db.t3.medium, Multi-AZ | €200 |
| ElastiCache Redis | cache.t3.micro | €30 |
| S3 Storage | 100GB | €5 |
| CloudFront CDN | 100GB transfer | €15 |
| ALB | Load Balancer | €25 |
| Route 53 | DNS | €5 |
| CloudWatch | Monitoring | €20 |
| **Infrastruttura Totale** | | **~€450/mese** |

#### Scenario: 500 Clienti SaaS

| Servizio | Configurazione | Costo/mese |
|----------|----------------|------------|
| EKS Cluster | 5 nodes t3.large | €400 |
| RDS PostgreSQL | db.r5.large, Multi-AZ | €500 |
| ElastiCache Redis | cache.r5.large | €150 |
| S3 Storage | 500GB | €15 |
| CloudFront CDN | 500GB transfer | €60 |
| ALB | Load Balancer | €25 |
| Route 53 | DNS | €5 |
| CloudWatch | Monitoring + Logs | €100 |
| WAF | Web Application Firewall | €50 |
| **Infrastruttura Totale** | | **~€1,300/mese** |

### 4.2 Costi Operativi

| Voce | Costo/mese | Note |
|------|------------|------|
| Support (se esterno) | €500-2000 | Dipende da volume |
| DevOps/SRE (0.5 FTE) | €2,500 | Gestione infra |
| Security tools | €100-500 | Snyk, etc. |
| Compliance (ammortizzato) | €500 | SOC 2, etc. |
| **Operativi Totale** | **~€3,500-5,500/mese** |

### 4.3 Costi di Sviluppo (Una Tantum)

| Attività | Ore | Costo (€50/h) |
|----------|-----|---------------|
| Multi-tenant architecture | 80 | €4,000 |
| User/tenant management | 40 | €2,000 |
| Billing integration (Stripe) | 30 | €1,500 |
| Usage metering | 20 | €1,000 |
| Admin dashboard | 40 | €2,000 |
| Migration tools | 20 | €1,000 |
| Testing & QA | 60 | €3,000 |
| Documentation | 20 | €1,000 |
| Security hardening | 40 | €2,000 |
| **Sviluppo Totale** | **350 ore** | **€17,500** |

### 4.4 Costi Totali Anno 1 SaaS

| Categoria | Costo |
|-----------|-------|
| Sviluppo iniziale | €17,500 |
| Infrastruttura (12 mesi × €450) | €5,400 |
| Operativi (12 mesi × €3,500) | €42,000 |
| Compliance (SOC 2 Type I) | €15,000 |
| Marketing SaaS | €10,000 |
| Contingenza (15%) | €13,500 |
| **TOTALE ANNO 1** | **~€103,000** |

---

## 5. PROIEZIONI FINANZIARIE

### 5.1 Pricing SaaS Proposto

| Tier | Agenti | Prezzo/mese | Prezzo/anno |
|------|--------|-------------|-------------|
| **Starter** | 10 | €49 | €490 |
| **Team** | 50 | €149 | €1,490 |
| **Business** | 200 | €399 | €3,990 |
| **Enterprise** | 500+ | Custom | Custom |

### 5.2 Proiezioni Revenue (Scenario Conservativo)

| Metrica | Anno 1 | Anno 2 | Anno 3 |
|---------|--------|--------|--------|
| **Clienti SaaS** | 50 | 200 | 500 |
| **Mix Tier** | 60% Starter, 30% Team, 10% Business | 50/30/20 | 40/35/25 |
| **ARPU** | €75/mese | €95/mese | €120/mese |
| **MRR (fine anno)** | €3,750 | €19,000 | €60,000 |
| **ARR (fine anno)** | €45,000 | €228,000 | €720,000 |

### 5.3 Unit Economics SaaS

| Metrica | Valore Target | Note |
|---------|---------------|------|
| CAC (Customer Acquisition Cost) | €300-500 | Inbound marketing focus |
| LTV (Lifetime Value) | €2,500+ | 24+ mesi retention |
| LTV:CAC Ratio | 5:1+ | Salutare per SaaS |
| Gross Margin | 70-80% | Dopo costi infra |
| Churn Rate | <5% mensile | Target |
| Payback Period | <6 mesi | Tempo per recuperare CAC |

### 5.4 Break-Even Analysis

```
BREAK-EVEN SAAS

Costi fissi mensili:
- Infrastruttura: €450
- Operativi: €3,500
- Total: €3,950/mese

Margine lordo per cliente (avg): €75 × 75% = €56

Break-even clienti: €3,950 / €56 = ~71 clienti

Con 100 clienti:
- Revenue: €7,500/mese
- Costi: €3,950/mese
- Profit: €3,550/mese (47% margin)

Con 500 clienti:
- Revenue: €60,000/mese
- Costi: €6,800/mese (scalato)
- Profit: €53,200/mese (89% margin)
```

---

## 6. ANALISI RISCHI

### 6.1 Matrice dei Rischi

| Rischio | Probabilità | Impatto | Mitigazione |
|---------|-------------|---------|-------------|
| **Data breach** | Media | Critico | SOC 2, encryption, audit |
| **Downtime prolungato** | Bassa | Alto | Multi-AZ, DR plan |
| **Churn alto** | Media | Alto | Onboarding, support |
| **Competizione pricing** | Alta | Medio | Differenziazione valore |
| **Compliance failure** | Bassa | Critico | Consulenza legale |
| **Scalability issues** | Media | Alto | Load testing, architecutre review |

### 6.2 Rischi Specifici SaaS vs Self-Hosted

| Aspetto | Self-Hosted | SaaS | Rischio |
|---------|-------------|------|---------|
| Sicurezza dati | Cliente responsabile | Noi responsabili | ALTO |
| Uptime | Cliente gestisce | SLA richiesto | MEDIO |
| Compliance | Più semplice | Più complesso | ALTO |
| Support | Limitato | 24/7 atteso | MEDIO |
| Costi | Predittibili | Variabili | MEDIO |

### 6.3 Compliance Requirements SaaS

| Requisito | Necessario | Costo | Timeline |
|-----------|------------|-------|----------|
| SOC 2 Type I | Sì (enterprise) | €15-25k | 3-6 mesi |
| SOC 2 Type II | Raccomandato | €20-40k | 12 mesi |
| GDPR Compliance | Sì (EU customers) | €5-10k | 1-2 mesi |
| ISO 27001 | Nice-to-have | €25-50k | 6-12 mesi |
| HIPAA | Solo healthcare | €30-50k | 6-12 mesi |
| DPA Templates | Sì | €2-5k | 1 mese |

---

## 7. ROADMAP IMPLEMENTAZIONE

### 7.1 Fase 1: Preparazione (Q3 2026)

| Settimana | Attività |
|-----------|----------|
| 1-2 | Architettura multi-tenant design |
| 3-4 | Setup infrastruttura cloud (staging) |
| 5-6 | Implementazione Row-Level Security |
| 7-8 | Tenant management system |

**Deliverable:** Ambiente staging multi-tenant funzionante

### 7.2 Fase 2: Core Development (Q4 2026)

| Settimana | Attività |
|-----------|----------|
| 1-2 | Billing integration (Stripe) |
| 3-4 | Usage metering & limits |
| 5-6 | Admin dashboard |
| 7-8 | Self-service signup flow |
| 9-10 | Testing & security audit |

**Deliverable:** SaaS beta ready

### 7.3 Fase 3: Beta Launch (Q1 2027)

| Settimana | Attività |
|-----------|----------|
| 1-2 | Beta launch (10-20 clienti) |
| 3-6 | Feedback & iteration |
| 7-8 | SOC 2 Type I audit start |
| 9-12 | Public launch prep |

**Deliverable:** SaaS in produzione

### 7.4 Fase 4: GA Launch (Q2 2027)

| Attività | Timeline |
|----------|----------|
| General Availability | Q2 2027 |
| Marketing campaign | Ongoing |
| Partner program | Q3 2027 |
| Enterprise tier | Q4 2027 |

---

## 8. GO/NO-GO DECISION FRAMEWORK

### 8.1 Criteri GO

| Criterio | Threshold | Importanza |
|----------|-----------|------------|
| Self-hosted ARR | >€100k | Alta |
| Customer demand documented | >10 richieste | Alta |
| Funding available | >€50k | Alta |
| Technical capacity | 1+ FTE | Media |
| Competitor SaaS success | Verificato | Media |

### 8.2 Criteri NO-GO

| Criterio | Descrizione |
|----------|-------------|
| No funding | <€30k disponibili |
| No demand | <5 richieste clienti |
| Team troppo piccolo | <0.5 FTE dedicabili |
| Technical debt alto | Codebase non pronto |
| Compliance impossibile | Settore troppo regolato |

### 8.3 Decisione Suggerita

```
┌─────────────────────────────────────────────────────────────────────┐
│                    DECISION MATRIX                                   │
├─────────────────────────────────────────────────────────────────────┤
│                                                                      │
│   SE self-hosted ARR > €100k                                        │
│   E richieste SaaS > 10                                             │
│   E funding > €50k                                                  │
│   ──────────────────                                                │
│   ALLORA: GO per SaaS development (Q3 2026)                         │
│                                                                      │
│   SE self-hosted ARR < €50k                                         │
│   O richieste SaaS < 5                                              │
│   O funding < €30k                                                  │
│   ──────────────────                                                │
│   ALLORA: WAIT - Focus su self-hosted growth                        │
│                                                                      │
│   SE conditions intermedie                                          │
│   ──────────────────                                                │
│   ALLORA: PILOT con 5-10 clienti beta (low investment)              │
│                                                                      │
└─────────────────────────────────────────────────────────────────────┘
```

---

## 9. ALTERNATIVE AL SAAS COMPLETO

### 9.1 Opzione "Managed Hosting"

Invece di SaaS completo, offrire **hosting gestito** dell'istanza self-hosted del cliente.

| Pro | Contro |
|-----|--------|
| Meno sviluppo necessario | Meno scalabile |
| Isolamento completo dati | Ops più complesse |
| Pricing più alto | Margini inferiori |
| Nessun multi-tenant code | Meno standardizzato |

**Costo implementazione:** ~€5-10k
**Timeline:** 1-2 mesi

### 9.2 Opzione "Hybrid Cloud"

Offrire **agent cloud** che comunica con istanza self-hosted del cliente.

```
┌─────────────────┐        ┌─────────────────┐
│  CLOUD AGENT    │◄──────►│  CUSTOMER       │
│  (SentriKat)    │        │  SELF-HOSTED    │
│                 │        │                 │
│ • KEV sync      │        │ • Data storage  │
│ • NVD queries   │        │ • Dashboard     │
│ • Notifications │        │ • Reporting     │
└─────────────────┘        └─────────────────┘

Vantaggi:
- Dati rimangono on-premise (compliance)
- Noi gestiamo sync e notifiche
- Pricing ibrido possibile
```

**Costo implementazione:** ~€10-15k
**Timeline:** 2-3 mesi

### 9.3 Confronto Opzioni

| Opzione | Costo Dev | Revenue Potential | Complessità | Timeline |
|---------|-----------|-------------------|-------------|----------|
| Full SaaS | €17k | €€€€ | Alta | 6-12 mesi |
| Managed Hosting | €5k | €€ | Media | 1-2 mesi |
| Hybrid Cloud | €10k | €€€ | Media | 2-3 mesi |
| Solo Self-Hosted | €0 | € | Bassa | Già pronto |

---

## 10. CONCLUSIONI E RACCOMANDAZIONI

### 10.1 Sintesi

| Aspetto | Valutazione |
|---------|-------------|
| Fattibilità tecnica | ✅ Fattibile |
| Fattibilità economica | ✅ Con funding |
| Market fit | ✅ Forte domanda SMB |
| Competitive advantage | ⚠️ Medio (hybrid è plus) |
| Rischi | ⚠️ Gestibili |
| ROI potenziale | ✅ Positivo dopo 18 mesi |

### 10.2 Raccomandazione Finale

**2026 (Anno 1):**
- Focus su self-hosted, build ARR to €100k+
- Raccogliere richieste SaaS dai clienti
- Preparare architettura (multi-tenant ready code)

**2027 (Anno 2):**
- Se criteri GO soddisfatti: sviluppo SaaS
- Beta Q1, GA Q2
- Target: 100 clienti SaaS fine anno

**2028+ (Anno 3):**
- SaaS-first go-to-market
- Self-hosted come opzione enterprise
- Target: €500k+ ARR SaaS

### 10.3 Next Steps Immediati

1. [ ] Tracciare richieste SaaS dai clienti potenziali
2. [ ] Stimare funding disponibile per SaaS
3. [ ] Refactoring graduale codice per multi-tenant readiness
4. [ ] Valutare partner tecnici per infrastruttura cloud
5. [ ] Consulenza legale per compliance SaaS (GDPR, DPA)

---

## APPENDICE: RISORSE

### Cloud Provider Comparison

| Provider | Pro | Contro | Costo stimato |
|----------|-----|--------|---------------|
| AWS | Completo, standard | Complesso, costoso | €€€ |
| Google Cloud | ML/AI tools | Meno diffuso | €€ |
| Azure | Enterprise integration | Meno startup-friendly | €€€ |
| Hetzner Cloud | Economico, EU | Meno servizi managed | € |
| OVH | EU, GDPR-friendly | Meno features | € |

**Raccomandazione:** Hetzner/OVH per start, migrazione a AWS/GCP per scale.

### Riferimenti

- [SaaS Metrics 2.0](https://www.forentrepreneurs.com/saas-metrics-2/) - David Skok
- [The SaaS CFO](https://www.thesaascfo.com/) - Metriche e benchmark
- [OpenSaaS](https://opensaas.sh/) - Template SaaS open source
- [Multi-tenant SaaS Architecture](https://docs.aws.amazon.com/whitepapers/latest/saas-tenant-isolation-strategies/saas-tenant-isolation-strategies.html) - AWS Whitepaper

---

*Documento da rivedere trimestralmente o al raggiungimento di milestone significative.*
