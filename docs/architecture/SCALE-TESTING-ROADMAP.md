# SentriKat — Scale Testing Roadmap

> Strategia per portare SentriKat dal current state ("easy mode" pre-launch)
> a "enterprise production-ready" attraverso 5 livelli progressivi di
> scale testing.
>
> Documento di riferimento per pianificazione post-launch. **Non** richiede
> azione immediata: il bug fixing functional in corso è il prerequisito
> per arrivare al Livello 1.

---

## Stato attuale (2026-05-04)

### Cosa abbiamo testato finora — "Easy Mode"

| Dimensione | Coverage |
|---|---|
| Functional bug discovery (1-admin, 0-agent) | ✅ ~78% (vedi `docs/e2e-tests/00-INDEX.md` counter) |
| Auth flow E2E (SAML, LDAP, OTP, 2FA, session) | ✅ done (Round 1-6) |
| RBAC matrix base (super_admin, org_admin, user) | ✅ partial (cluster `[06.6.x]`) |
| Setup wizard happy path | ✅ done (`[03.6.3]` verified) |
| Sync CISA/EPSS/CPE/NVD trigger | ✅ done (Round 4 cluster) |
| Integration connectors (Jira/Webhook/GitLab/YouTrack) | ✅ done (testlab MockServer) |
| Settings tabs sub-section | ✅ done (Round 5) |
| Logging + observability resilience | ✅ done (`[03.20.1]` cascade fix) |
| Health checks + notifications | ✅ done (`[03.18.1]` resilience) |
| Cross-repo sync (sentrikat-web admin portal) | ✅ in progress (web team) |

### Cosa NON abbiamo testato — "Easy Mode" gaps

| Dimensione | Status | Why deferred |
|---|---|---|
| Multi-user concurrent (50+ admin) | ❌ | Non rilevante a stage "primi customer pilot" |
| Multi-tenant SaaS scale (100+ org) | ❌ | Idem |
| Agent fleet > 10 endpoint | ❌ | Community license cap impedisce test interno |
| DB dataset > 100K record | ❌ | Tutti i seed test usano DB pulito |
| Long-running sessions (24h+) | ❌ | Memory leak detection richiede setup dedicato |
| Network failure injection | ❌ | Chaos testing è Livello 4 |

**Verdict**: easy mode è solido per **vendita primi 5-20 customer Community/Starter** (fino a ~100 endpoint per cliente). Per customer enterprise (1000+ endpoint) servono Livelli 1-3 prima di firmare contratto.

---

## Roadmap 5 livelli — quando attivare ogni livello

### Trigger by customer profile

| Customer profile | Livelli richiesti prima del go-live |
|---|---|
| Community / Starter (≤ 50 endpoint) | Easy mode ✅ (current) |
| Professional (50-500 endpoint) | + Livello 1 (load test base) |
| Enterprise (500-5000 endpoint) | + Livello 2-3 (DB dataset + fleet sim) |
| Strategic (5000-10000+ endpoint) | + Livello 4 (chaos engineering) |
| Mission-critical / SLA hard | + Livello 5 (pilot) |

### Livello 1 — Synthetic load testing (basic)

**Quando**: prima del primo customer Professional > 50 endpoint.
**Effort**: 1 dev × 3 giorni = 1 settimana cal.
**Repo separato**: `sbr0nch/sentrikat-loadtest` (da creare).

**Tooling**: [k6](https://k6.io/) (Go-based, scripts JavaScript) o [Locust](https://locust.io/) (Python).

**Scenari**:

```js
// k6 example — agent inventory burst
import http from 'k6/http';
import { check, sleep } from 'k6';

export const options = {
  vus: 1000,           // 1000 virtual users
  duration: '5m',
  thresholds: {
    http_req_duration: ['p(95)<500'],  // P95 < 500ms
    http_req_failed: ['rate<0.01'],     // < 1% errors
  },
};

export default function() {
  const payload = JSON.stringify({
    inventory: [/* 50 fake products per submit */]
  });
  const res = http.post('https://app.sentrikat.com/api/agent/inventory',
                        payload,
                        { headers: { Authorization: `Bearer ${__ENV.API_KEY}` }});
  check(res, { 'status 200': (r) => r.status === 200 });
  sleep(60); // realistic 1-min sync interval per agent
}
```

**Misuro**:
- P50/P95/P99 response time per endpoint
- Error rate sotto load
- DB connections used (`SHOW pg_stat_activity`)
- Memory crescita worker gunicorn
- CPU saturation

**Pass criteria**:
- 1000 agent inventory submit/min senza degradation
- Admin dashboard P95 < 1s con 50 admin concurrent
- Zero 5xx errori sotto load nominale
- Memory steady-state (no leak)

**Output deliverable**:
- `sentrikat-loadtest/` repo con scripts riusabili
- Dashboard Grafana con baseline metrics
- Doc "Performance baseline beta.6 release"

---

### Livello 2 — Database scale dataset

**Quando**: prima del primo customer Enterprise > 500 endpoint.
**Effort**: 1 dev × 2 giorni = 1 settimana cal.

**Tooling**: Python script bulk insert + faker + numpy.

**Dataset target**:

| Tabella | Record count target | Justification |
|---|---|---|
| `users` | 5.000 | 100 org × 50 user avg |
| `organizations` | 500 | Mid-market SaaS |
| `endpoints` (tutti tenant) | 50.000 | 100 endpoint avg × 500 org |
| `products` | 200.000 | OS+app inventory realistico |
| `vulnerabilities` (CVE) | 250.000 | Full NVD + CISA + EPSS |
| `affected_endpoint` (join) | 1.000.000 | Dense vuln matching |
| `audit_log` | 5.000.000 | 1 anno operations |
| `inventory_jobs` | 100.000 | Storia agent submission |

**Script structure**:

```python
# scripts/seed_scale_db.py
import os
from faker import Faker
from sqlalchemy import create_engine
from app import db
# ... bulk insert con executemany() o COPY FROM

def seed_organizations(n=500): ...
def seed_users(n=5000): ...
def seed_endpoints(n=50000): ...
def seed_cves(n=250000):
    """Pull real CVE data from local NVD mirror, randomize affected_endpoint"""
    ...
def seed_audit_log(n=5000000):
    """Use INSERT ... SELECT generate_series for speed"""
    ...
```

**Test functional a quella scala**:
- Dashboard load time
- Compliance report generation (timeout?)
- Vulnerability list pagination > 10K row
- Search performance (full-text con GIN index)
- Bulk operations (delete 1000 user, archive 10K vuln)

**Pass criteria**:
- Dashboard P95 < 2s con DB scale
- Compliance report PDF/JSON < 30s per tenant medio
- Search all-vulnerabilities P95 < 1s
- Pagination scroll smooth fino a 100K row

**Output deliverable**:
- `scripts/seed_scale_db.py` parametrico
- Slow query report (`pg_stat_statements`)
- Index recommendations
- Doc "Database scale baseline"

---

### Livello 3 — Fleet simulator (custom tool)

**Quando**: prima del go-live customer 1000+ endpoint.
**Effort**: 1 dev × 5 giorni = 2 settimane cal.

**Tool**: `sentrikat-fleet-sim` — CLI Python che simula N agent reali.

```bash
# Esempio invocazione
sentrikat-fleet-sim \
  --agents 5000 \
  --duration 24h \
  --target https://app.sentrikat.com \
  --api-key-file /etc/sentrikat/keys.txt \
  --inventory-rate "10/agent/h" \
  --jitter 30s \
  --os-distribution "linux:40,windows:35,macos:20,container:5" \
  --failure-rate 0.05 \
  --metrics-port 9090
```

**Comportamento per agent simulato**:
- Inventory submit periodicamente con varianza realistica (Poisson distribution)
- Occasional failure (5% timeout, 1% malformed payload, 0.5% auth error)
- Varied OS distribution con CVE matching realistico
- 1% degli agent va offline per 1-24h (realistic outage)
- Inventory size cresce nel tempo (1 prodotto installato/settimana)

**Esposto su `:9090/metrics`** (Prometheus format):
- `fleet_sim_agents_active` gauge
- `fleet_sim_inventory_submits_total` counter
- `fleet_sim_errors_total` counter per error type
- `fleet_sim_response_time_seconds` histogram

**Lasciato girare 24-72h trova**:
- Memory leak in worker pool
- Scheduler degradation oltre 10K job in queue
- Connection pool exhaustion timing
- DB lock contention durante sync notturno
- Audit log bloat / partition needs

**Pass criteria**:
- 5000 agent simulati per 72h con 0 SLA breach
- Memory steady (RSS crescita < 5%/giorno)
- DB query plan stabile (no degradation)
- Audit log non blocca insert oltre N record

**Output deliverable**:
- `sentrikat-fleet-sim` CLI installabile via pip/docker
- Test runbook 72h
- Doc "Fleet scale validation methodology"

---

### Livello 4 — Chaos engineering

**Quando**: prima del primo customer mission-critical / SLA hard.
**Effort**: 1 dev × 5 giorni + 2 giorni runbook = 2 settimane cal.

**Tooling**: [Chaos Mesh](https://chaos-mesh.org/) (Kubernetes) o `pumba` (Docker) o custom scripts.

**Failure scenarios da testare durante carico Livello 1+3**:

| Failure injection | Atteso behavior | SLA target |
|---|---|---|
| DB primary failover (RDS Multi-AZ) | < 90s recovery, no data loss | < 2 min |
| Network partition app↔license-server | License heartbeat retry, fallback to cached | 0 customer impact |
| Container OOM-killed + auto-restart | New container picks up state, queues drain | < 30s |
| NVD API down per 6h | Sync job queue, retry with backoff | No 5xx exposure |
| CISA feed corrupted (malformed JSON) | Sync rejects + alert, no DB pollution | Manual intervention |
| Disk full /var/log | App continues, log rotation kicks in | < 5min recovery |
| Postgres slow query > 30s | Statement timeout, request 503, no cascade | App stays up |
| Redis (rate limit storage) down | Fallback to in-memory limiter, warn | 0 functional impact |
| 100x normal traffic burst (DDoS-like) | Rate limit kicks in, app stays responsive | < 1% legit user 5xx |

**Output deliverable**:
- `docs/operations/chaos-runbook.md` con ogni scenario step-by-step
- Auto-test in CI (subset di chaos scenarios eseguiti settimanalmente)
- Doc "Resilience SLA evidence"

---

### Livello 5 — Real customer pilot

**Quando**: dopo Livelli 1-4 ✅ + customer design partner trovato.
**Effort**: infra + 1 dev × 4 settimane = 2 mesi cal.

**Setup pilot**:
- Customer con fleet realistico 3000-5000 endpoint
- Production deploy con observability massima:
  - Prometheus + Grafana dashboard
  - PostgreSQL slow query log + EXPLAIN ANALYZE
  - Distributed tracing (OpenTelemetry → Jaeger)
  - Sentry per error reporting
  - Daily/weekly SLA report
- Daily standup con customer ops team
- Bug rate / error rate / SLA tracked

**Outcome target**:
- 30 giorni 99.9% uptime
- Zero data loss events
- Bug discovery rate decrescente (Round 1 trova X, Round 4 trova X/10)
- Customer NPS > 8

**Output deliverable**:
- Case study pubblico (con permesso customer)
- Doc "Production readiness checklist" finalizzata
- GA announcement con baseline performance numbers

---

## Tooling stack consolidato

| Layer | Tool | Purpose |
|---|---|---|
| Load generation | k6 | HTTP load test, multi-VU |
| Fleet simulation | Custom Python | Realistic agent behavior |
| DB seeding | Python + Faker + bulk SQL | Dataset realistico |
| Chaos injection | Chaos Mesh / pumba / custom | Failure scenarios |
| Observability | Prometheus + Grafana + Sentry + OpenTelemetry | Metrics + tracing + errors |
| Slow query analysis | pg_stat_statements + pgBadger | DB profiling |
| Synthetic monitoring | Pingdom / Uptime-Kuma | External SLA proof |
| Penetration testing | OWASP ZAP / Burp Suite | Security audit |

---

## Costo stimato totale (per arrivare a "production-ready enterprise")

| Livello | Effort dev | Calendar | Costo dev (assumendo 80€/h × 7h) |
|---|---|---|---|
| 1 | 3 gg | 1 settimana | ~1.700€ |
| 2 | 2 gg | 1 settimana | ~1.100€ |
| 3 | 5 gg | 2 settimane | ~2.800€ |
| 4 | 7 gg | 2 settimane | ~3.900€ |
| 5 | 4 settimane (28 gg) | 2 mesi | ~15.700€ |
| **Totale** | **~9 settimane dev** | **3-4 mesi cal** | **~25.000€** |

**Più**:
- Infra costs (cloud, monitoring, observability stack): ~500€/mese
- Customer pilot incentive (sconto + supporto dedicato): variabile
- Possibile audit security esterno (penetration test): 5-10K€

**Totale onesto per "GA enterprise certified"**: **35-45K€** + 3-4 mesi.

---

## Quick wins immediati (post-launch easy mode)

Prima del primo customer Professional, low-effort prep:

1. **Setup `sentrikat-loadtest` repo** con skeleton k6/Locust (anche solo 1 scenario base)
2. **Doc "Performance & Scale" su docs.sentrikat.com** Operations section (descrive cosa testiamo a quale tier)
3. **Script `seed_scale_db.py`** parametrico (anche solo 10K endpoint per ora — espandibile)
4. **GitHub Actions workflow** "smoke-load-test" su main: 60s di carico base, blocca PR se P95 > 500ms

Tutti questi 4 = ~2 giorni di lavoro mio in autonomia. Output: hai già la base dell'infrastruttura testing pronta a scalare quando arriva il primo customer enterprise.

---

## Domande aperte (per planning team)

1. **Customer profile target** primi 6-12 mesi: Community/Starter (≤50 endpoint) prevalente o anche Pro/Enterprise?
2. **Budget testing infrastructure** disponibile?
3. **Customer design partner** — c'è qualcuno disposto a fare pilot?
4. **GA target date** — definita?
5. **Penetration testing esterno** — preventivato?

Aggiornare questo doc quando le risposte arrivano. Le risposte cambiano la priorità dei livelli.
