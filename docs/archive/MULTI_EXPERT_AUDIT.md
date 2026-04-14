# MEGA-AUDIT SENTRIKAT — 8 Esperti, 1 Report
**Data: 2026-03-28**

---

## 1. PENETRATION TESTER — Audit Sicurezza

**Voto Complessivo: B+ (Buono)**

### CRITICAL (2)

| # | Problema | File | Rischio |
|---|----------|------|---------|
| 1 | SQL Injection in migrations — f-string in `text(f"PRAGMA table_info({table_name})")` | `app/__init__.py:144-156` | Basso oggi (valori hardcoded), alto se refactorato |
| 2 | SQL Injection in info_schema — interpolazione diretta in query PostgreSQL | `app/__init__.py:148-150` | Stessa valutazione |

**Fix:** Usare query parametrizzate:
```python
conn.execute(text("SELECT column_name FROM information_schema.columns WHERE table_name = :t"), {"t": table_name})
```

### HIGH (3)

| # | Problema | File |
|---|----------|------|
| 1 | Password reset token in plaintext nel DB | `models.py:1136-1162` |
| 2 | Encryption key fallback da SECRET_KEY | `encryption.py:41-50` |
| 3 | Nessun meccanismo di key rotation | `encryption.py` |

### MEDIUM (5)

| # | Problema |
|---|----------|
| 1 | Default SECRET_KEY in dev bypassabile |
| 2 | Docker filesystem read-write (manca `read_only: true`) |
| 3 | TLS version non enforced in nginx |
| 4 | RBAC misto legacy (`is_admin`) + nuovo (roles) |
| 5 | Proxy config non validata contro SSRF |

### Cosa Funziona Bene
- Password hashing (Werkzeug + salt)
- Session fixation protection
- TOTP 2FA
- Rate limiting (Flask-Limiter + nginx)
- CSRF protection (Flask-WTF)
- SSRF protection (blocco IP privati e cloud metadata)
- SVG XSS validation
- LDAP injection prevention
- Zero `eval()`, `exec()`, `os.system()`
- Agent API key hashate SHA256
- Non-root Docker user
- Security headers completi
- Audit logging (7 file con rotation)

---

## 2. ESPERTO UX/UI — Audit Design

### Punti di Forza
- Design system coerente (Bootstrap 5.3.2 + CSS variables + dark mode 100+ selectors)
- Color palette severity-coded professionale
- Typography Inter con gerarchia chiara
- Responsive a 4 breakpoint
- Loading states (skeleton, spinner, overlay)
- Empty states ben progettati

### Miglioramenti per Vendibilità

| Priorità | Problema | Soluzione |
|-----------|----------|-----------|
| ALTA | No onboarding post-setup | Tour guidato interattivo, empty state con Quick Start |
| ALTA | No wow factor al primo accesso | Schermata benvenuto con metriche e getting-started checklist |
| ALTA | Chart.js senza dark mode | Colori Chart.js dinamici da CSS variables |
| MEDIA | No keyboard shortcut | `/` per search, `Ctrl+K` command palette, `G+D` dashboard |
| MEDIA | No tooltip su termini tecnici | `data-bs-tooltip` su CPE, EPSS, KEV |
| MEDIA | ARIA incompleto su componenti custom | Aggiungere aria-controls, aria-selected, role="tabpanel" |
| BASSA | No animazioni transizione pagine | Fade-in CSS su page load |
| BASSA | Logo invert(1) in dark mode | Variante logo dedicata per dark mode |

### Mancanze vs Competitor (Tenable, Qualys, Rapid7)
- Manca executive dashboard con grafici impattanti
- Manca risk score unico visibile ("Security Score: 72/100")
- Manca export PDF con branding professionale

---

## 3. ESPERTO MARKETING — Audit Go-to-Market

### Differenziatori Commerciali
- Dual-mode SaaS + On-Premise (raro nel mercato)
- Compliance NIS2 nativa (forte per EU/PA)
- Pricing chiaro con Free tier
- Agent leggeri (shell script)
- Multi-fonte (CISA KEV + NVD + EPSS + OSV)

### Azioni per Go-to-Market

| Area | Azione |
|------|--------|
| Positioning | "L'unico VMS dual-mode europeo con compliance NIS2 nativa" |
| Trust signals | Percorso SOC2 Type II + badge in landing |
| Social proof | 3-5 early adopter testimonial |
| Content | Blog su NIS2, CISA KEV, vulnerability management |
| Free tier | "Start Free — No Credit Card" prominente |
| Demo | Ambiente demo con dati pre-caricati |
| API docs | Pubblicare su docs.sentrikat.com |
| SEO | Pagine "vs Tenable", "vs Qualys" |
| Pricing | Pagina pricing trasparente pubblica |

### Segmenti Target
1. PMI europee sotto NIS2
2. PA italiana (requisiti on-premise, AGID)
3. MSP/MSSP (multi-tenancy nativa)
4. DevSecOps (container + dependency scanning)

---

## 4. ARCHITETTO SOFTWARE — Audit Architettura

**Voto: A- (Ottimo)**

### Punti di Forza
- Monolite modulare ben strutturato (62 file Python, blueprint separati)
- Dual-mode elegante (saas.py senza duplicazione)
- Database migration automatica all'avvio
- Background workers (APScheduler)
- Connection pooling configurato
- Agent API con chunking e filtering a 3 fasi
- Storage abstraction (local + S3)

### Miglioramenti

| Priorità | Problema | Soluzione |
|-----------|----------|-----------|
| ALTA | `routes.py` = 7277 righe | Spezzare in products_api, vulnerabilities_api, charts_api |
| ALTA | `models.py` = 3682 righe | Package `models/` con file per dominio |
| ALTA | `base.html` = 5609 righe | Componenti Jinja2 separati |
| MEDIA | No message queue | Redis + Celery per job pesanti |
| MEDIA | No caching | Redis per dashboard stats, CVE counts |
| MEDIA | No API versioning | `/v1/` prima di avere clienti API esterni |
| BASSA | Health check basic | Readiness vs liveness probe per k8s |

---

## 5. PRODUCT MANAGER ON-PREMISE

### Funzionalità Mancanti

| Priorità | Feature | Motivo |
|-----------|---------|--------|
| CRITICA | Offline mode (air-gapped) | Difesa, governo: import manuale CVE |
| ALTA | Backup/Restore da UI | Oggi solo script bash |
| ALTA | Update checker | Notifica nuove versioni |
| ALTA | RBAC granulare custom | Solo 4 ruoli fissi |
| MEDIA | Multi-site aggregation | Un'istanza per sito |
| MEDIA | Asset discovery attivo (nmap) | Oggi solo push agent |
| MEDIA | Remediation workflow interno | Jira presente, manca workflow interno |

---

## 6. PRODUCT MANAGER SAAS

### Funzionalità Mancanti

| Priorità | Feature | Motivo |
|-----------|---------|--------|
| CRITICA | Self-service portal | Cliente deve contattare support per upgrade |
| CRITICA | Trial automatico 14 giorni | Conversione utenti |
| ALTA | Usage dashboard | Il cliente non vede il consumo |
| ALTA | Onboarding email sequence | 5 email: welcome → setup → scan → report → upgrade |
| ALTA | In-app notifications | Solo email oggi |
| MEDIA | Rate limiting per piano | Free: 100/h, Pro: 1000/h, Enterprise: unlimited |
| MEDIA | Data retention policy | Free: 30gg, Pro: 1 anno, Enterprise: illimitato |
| BASSA | White-label per MSP | Custom domain, logo, colori |

---

## 7. QA ENGINEER

### Gap nel Testing

| Priorità | Gap |
|-----------|-----|
| ALTA | No E2E test (Selenium/Playwright) |
| ALTA | No test coverage enforcement in CI |
| MEDIA | No performance test (benchmark 100/1000/10000 agent) |
| MEDIA | No chaos testing |
| MEDIA | No cross-browser test |
| BASSA | No contract test (sentrikat-web ↔ sentrikat) |

---

## 8. DEVOPS/SRE

### Gap Operativi

| Priorità | Gap | Soluzione |
|-----------|-----|-----------|
| ALTA | No monitoring | Prometheus + Grafana + `/metrics` endpoint |
| ALTA | No CI/CD | GitHub Actions: test → build → push → deploy |
| MEDIA | No container registry | GHCR o DockerHub |
| MEDIA | No secrets management | Docker secrets o Vault |
| MEDIA | No auto-scaling | Kubernetes HPA |
| BASSA | No distributed tracing | OpenTelemetry |

---

## 9. LEGAL/COMPLIANCE

| Area | Stato | Azione |
|------|-------|--------|
| GDPR | Parziale | API "Right to be Forgotten", privacy policy |
| NIS2 | Report presente | Documentare conformità propria come vendor |
| Cookie consent | Assente | Cookie banner |
| Terms of Service | Assenti | Creare ToS per SaaS |
| DPA | Assente | Data Processing Agreement per EU |
| Vulnerability disclosure | Assente | security.txt + responsible disclosure |

---

## Top 10 Priorità Assolute

| # | Cosa | Chi | Effort |
|---|------|-----|--------|
| 1 | Fix SQL injection in migrations | Dev | 1h |
| 2 | Hash password reset tokens | Dev | 2h |
| 3 | Spezzare routes.py (7277 righe) | Architect | 1 giorno |
| 4 | Self-service portal SaaS | Product | 1 settimana |
| 5 | Trial automatico 14 giorni | Product | 2 giorni |
| 6 | Monitoring Prometheus/Grafana | DevOps | 2 giorni |
| 7 | CI/CD pipeline | DevOps | 1 giorno |
| 8 | Onboarding guidato post-setup | UX | 3 giorni |
| 9 | Executive dashboard con risk score | UX/Product | 3 giorni |
| 10 | GDPR compliance | Legal | 1 settimana |
