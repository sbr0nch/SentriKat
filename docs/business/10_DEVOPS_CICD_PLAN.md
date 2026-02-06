# SENTRIKAT - DEVOPS & CI/CD PLAN
## Stato Attuale e Roadmap delle Automazioni

---

**Versione:** 1.0
**Ultimo Aggiornamento:** Febbraio 2026
**Autore:** SentriKat Development Team

---

## 1. STATO ATTUALE (AS-IS)

### 1.1 Infrastruttura CI/CD Esistente

```
┌─────────────────────────────────────────────────────────────────────┐
│                    CURRENT CI/CD PIPELINE                            │
├─────────────────────────────────────────────────────────────────────┤
│                                                                      │
│   ┌──────────┐    ┌──────────┐    ┌──────────┐    ┌──────────┐     │
│   │  PUSH    │───>│   CI     │───>│  BUILD   │───>│  GHCR    │     │
│   │  (git)   │    │ (tests)  │    │ (docker) │    │ (publish)│     │
│   └──────────┘    └──────────┘    └──────────┘    └──────────┘     │
│        │               │               │               │            │
│        │               │               │               │            │
│   [Developer]     [GitHub]        [GitHub]        [GitHub]         │
│                   Actions         Actions         Actions          │
│                                                                      │
│   ✅ Attivo       ✅ Attivo       ✅ Attivo       ✅ Attivo         │
│                                                                      │
└─────────────────────────────────────────────────────────────────────┘
```

### 1.2 Workflow Esistenti

#### `.github/workflows/ci.yml` - Continuous Integration

```yaml
# Stato: ✅ ATTIVO
name: CI

on:
  push:
    branches: [main]
  pull_request:
    branches: [main]

jobs:
  lint:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-python@v5
        with:
          python-version: '3.11'
      - run: pip install flake8
      - run: flake8 app/ --count --select=E9,F63,F7,F82 --show-source

  test:
    runs-on: ubuntu-latest
    needs: lint
    services:
      postgres:
        image: postgres:16
        env:
          POSTGRES_PASSWORD: test
        ports:
          - 5432:5432
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-python@v5
      - run: pip install -r requirements.txt
      - run: pytest tests/ -v
```

**Metriche attuali:**
- Tempo medio build: ~3-5 minuti
- Success rate: ~95%
- Coverage: Non ancora configurato

#### `.github/workflows/release.yml` - Release Automation

```yaml
# Stato: ✅ ATTIVO
name: Release

on:
  push:
    tags: ['v*.*.*']

jobs:
  build-and-push:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: docker/login-action@v3
        with:
          registry: ghcr.io
          username: ${{ github.actor }}
          password: ${{ secrets.GITHUB_TOKEN }}
      - uses: docker/build-push-action@v5
        with:
          push: true
          tags: |
            ghcr.io/sbr0nch/sentrikat:${{ github.ref_name }}
            ghcr.io/sbr0nch/sentrikat:latest
```

**Output attuali:**
- Docker image su GHCR
- GitHub Release con asset zip
- docker-compose.yml incluso nel release

### 1.3 Cosa Manca (Gaps)

| Area | Stato Attuale | Gap |
|------|---------------|-----|
| Test Coverage | Non tracciato | Nessun report coverage |
| Security Scanning | Non attivo | Nessun SAST/DAST |
| Dependency Updates | Manuale | Nessun Dependabot |
| Staging Deploy | Manuale | Nessun auto-deploy |
| Production Deploy | Manuale | Nessun auto-deploy |
| Monitoring | Non attivo | Nessun alerting |
| Documentation | Manuale | Nessuna doc generation |

---

## 2. ROADMAP DEVOPS

### 2.1 Timeline Overview

```
         Q1 2026          Q2 2026          Q3 2026          Q4 2026
            │                │                │                │
            ▼                ▼                ▼                ▼
    ┌───────────────┐ ┌───────────────┐ ┌───────────────┐ ┌───────────────┐
    │  FOUNDATION   │ │   QUALITY     │ │   SECURITY    │ │   SCALE       │
    │               │ │               │ │               │ │               │
    │ • Basic CI/CD │ │ • Coverage    │ │ • SAST/DAST   │ │ • K8s ready   │
    │ • Lint/Test   │ │ • Staging CD  │ │ • Compliance  │ │ • Multi-region│
    │ • Docker      │ │ • Dependabot  │ │ • Pen testing │ │ • DR tested   │
    │               │ │               │ │               │ │               │
    │ ✅ COMPLETATO │ │ 🔄 IN CORSO   │ │ ⏳ PIANIFICATO│ │ ⏳ PIANIFICATO│
    └───────────────┘ └───────────────┘ └───────────────┘ └───────────────┘
```

---

## 3. FASE 2: QUALITY (Q2 2026)

### 3.1 Test Coverage Reporting

```yaml
# .github/workflows/ci.yml - AGGIORNAMENTO
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-python@v5
        with:
          python-version: '3.11'

      - name: Install dependencies
        run: |
          pip install -r requirements.txt
          pip install pytest-cov

      - name: Run tests with coverage
        run: |
          pytest tests/ -v \
            --cov=app \
            --cov-report=xml \
            --cov-report=html \
            --cov-fail-under=70

      - name: Upload coverage to Codecov
        uses: codecov/codecov-action@v4
        with:
          files: ./coverage.xml
          fail_ci_if_error: true

      - name: Upload coverage report
        uses: actions/upload-artifact@v4
        with:
          name: coverage-report
          path: htmlcov/
```

**Target Coverage:**
- Q2 2026: 70%
- Q3 2026: 80%
- Q4 2026: 85%

### 3.2 Continuous Deployment to Staging

```yaml
# .github/workflows/deploy-staging.yml - NUOVO
name: Deploy to Staging

on:
  push:
    branches: [main]
  workflow_dispatch:

jobs:
  deploy:
    runs-on: ubuntu-latest
    environment: staging

    steps:
      - uses: actions/checkout@v4

      - name: Build and push image
        uses: docker/build-push-action@v5
        with:
          push: true
          tags: ghcr.io/sbr0nch/sentrikat:staging

      - name: Deploy to staging server
        uses: appleboy/ssh-action@v1.0.3
        with:
          host: ${{ secrets.STAGING_HOST }}
          username: ${{ secrets.STAGING_USER }}
          key: ${{ secrets.STAGING_SSH_KEY }}
          script: |
            cd /opt/sentrikat
            docker-compose pull
            docker-compose up -d --force-recreate
            docker system prune -f

      - name: Health check
        run: |
          sleep 30
          curl -f https://staging.sentrikat.com/health || exit 1

      - name: Notify Slack
        uses: slackapi/slack-github-action@v1.25.0
        with:
          payload: |
            {
              "text": "✅ Deployed to staging: ${{ github.sha }}"
            }
        env:
          SLACK_WEBHOOK_URL: ${{ secrets.SLACK_WEBHOOK }}
```

### 3.3 Dependabot Configuration

```yaml
# .github/dependabot.yml - NUOVO
version: 2
updates:
  - package-ecosystem: "pip"
    directory: "/"
    schedule:
      interval: "weekly"
      day: "monday"
    open-pull-requests-limit: 5
    groups:
      security:
        applies-to: security-updates
      minor-and-patch:
        applies-to: version-updates
        update-types:
          - "minor"
          - "patch"
    reviewers:
      - "sbr0nch"
    labels:
      - "dependencies"
      - "automated"

  - package-ecosystem: "docker"
    directory: "/"
    schedule:
      interval: "weekly"
    labels:
      - "docker"
      - "automated"

  - package-ecosystem: "github-actions"
    directory: "/"
    schedule:
      interval: "monthly"
    labels:
      - "ci"
      - "automated"
```

### 3.4 Pre-commit Hooks

```yaml
# .pre-commit-config.yaml - NUOVO
repos:
  - repo: https://github.com/pre-commit/pre-commit-hooks
    rev: v4.5.0
    hooks:
      - id: trailing-whitespace
      - id: end-of-file-fixer
      - id: check-yaml
      - id: check-added-large-files
        args: ['--maxkb=500']
      - id: check-merge-conflict
      - id: detect-private-key

  - repo: https://github.com/psf/black
    rev: 24.1.0
    hooks:
      - id: black
        args: ['--line-length=120']

  - repo: https://github.com/PyCQA/flake8
    rev: 7.0.0
    hooks:
      - id: flake8
        args: ['--max-line-length=120']

  - repo: https://github.com/PyCQA/isort
    rev: 5.13.2
    hooks:
      - id: isort

  - repo: https://github.com/PyCQA/bandit
    rev: 1.7.7
    hooks:
      - id: bandit
        args: ['-r', 'app/', '-ll']
```

---

## 4. FASE 3: SECURITY (Q3 2026)

### 4.1 SAST (Static Application Security Testing)

```yaml
# .github/workflows/security.yml - NUOVO
name: Security Scan

on:
  push:
    branches: [main]
  pull_request:
    branches: [main]
  schedule:
    - cron: '0 0 * * 0'  # Weekly on Sunday

jobs:
  sast:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Run Bandit (Python SAST)
        run: |
          pip install bandit
          bandit -r app/ -f json -o bandit-report.json || true

      - name: Upload Bandit report
        uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: bandit-report.json

  dependency-scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Run Safety (dependency vulnerabilities)
        run: |
          pip install safety
          safety check -r requirements.txt --json > safety-report.json || true

      - name: Run pip-audit
        run: |
          pip install pip-audit
          pip-audit -r requirements.txt --format json > pip-audit-report.json || true

  container-scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Build image
        run: docker build -t sentrikat:scan .

      - name: Run Trivy vulnerability scanner
        uses: aquasecurity/trivy-action@master
        with:
          image-ref: 'sentrikat:scan'
          format: 'sarif'
          output: 'trivy-results.sarif'
          severity: 'CRITICAL,HIGH'

      - name: Upload Trivy scan results
        uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: 'trivy-results.sarif'

  secret-scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          fetch-depth: 0

      - name: TruffleHog OSS
        uses: trufflesecurity/trufflehog@main
        with:
          path: ./
          base: ${{ github.event.repository.default_branch }}
          head: HEAD
```

### 4.2 DAST (Dynamic Application Security Testing)

```yaml
# .github/workflows/dast.yml - NUOVO (per staging)
name: DAST Scan

on:
  workflow_dispatch:
  schedule:
    - cron: '0 3 * * 1'  # Weekly Monday 3 AM

jobs:
  zap-scan:
    runs-on: ubuntu-latest
    steps:
      - name: OWASP ZAP Baseline Scan
        uses: zaproxy/action-baseline@v0.11.0
        with:
          target: 'https://staging.sentrikat.com'
          rules_file_name: '.zap/rules.tsv'

      - name: Upload ZAP report
        uses: actions/upload-artifact@v4
        with:
          name: zap-report
          path: report_html.html
```

### 4.3 Software Bill of Materials (SBOM)

```yaml
# Aggiunta a release.yml
- name: Generate SBOM
  uses: anchore/sbom-action@v0
  with:
    image: ghcr.io/sbr0nch/sentrikat:${{ github.ref_name }}
    format: spdx-json
    output-file: sbom.spdx.json

- name: Upload SBOM to release
  uses: softprops/action-gh-release@v1
  with:
    files: sbom.spdx.json
```

---

## 5. FASE 4: SCALE (Q4 2026)

### 5.1 Production Deployment con Approval

```yaml
# .github/workflows/deploy-production.yml - NUOVO
name: Deploy to Production

on:
  release:
    types: [published]
  workflow_dispatch:
    inputs:
      version:
        description: 'Version to deploy'
        required: true

jobs:
  deploy-production:
    runs-on: ubuntu-latest
    environment: production  # Richiede approval

    steps:
      - uses: actions/checkout@v4

      - name: Verify staging deployment
        run: |
          # Controlla che questa versione sia stata testata in staging
          STAGING_VERSION=$(curl -s https://staging.sentrikat.com/api/version | jq -r '.version')
          if [ "$STAGING_VERSION" != "${{ github.event.release.tag_name }}" ]; then
            echo "Version mismatch: staging=$STAGING_VERSION, releasing=${{ github.event.release.tag_name }}"
            exit 1
          fi

      - name: Create deployment record
        run: |
          echo "Deploying ${{ github.event.release.tag_name }} to production"
          echo "Deployed by: ${{ github.actor }}"
          echo "Time: $(date -u)"

      - name: Deploy to production
        uses: appleboy/ssh-action@v1.0.3
        with:
          host: ${{ secrets.PROD_HOST }}
          username: ${{ secrets.PROD_USER }}
          key: ${{ secrets.PROD_SSH_KEY }}
          script: |
            cd /opt/sentrikat

            # Backup current state
            docker-compose exec -T db pg_dump -U postgres sentrikat > backup_$(date +%Y%m%d_%H%M%S).sql

            # Pull new version
            export VERSION=${{ github.event.release.tag_name }}
            docker-compose pull

            # Blue-green deployment
            docker-compose up -d --no-deps --scale sentrikat=2 sentrikat
            sleep 30
            docker-compose up -d --no-deps --scale sentrikat=1 sentrikat

            # Cleanup
            docker system prune -f

      - name: Health check
        run: |
          for i in {1..10}; do
            if curl -f https://sentrikat.com/health; then
              echo "Health check passed"
              exit 0
            fi
            sleep 10
          done
          echo "Health check failed"
          exit 1

      - name: Notify success
        if: success()
        uses: slackapi/slack-github-action@v1.25.0
        with:
          payload: |
            {
              "text": "🚀 Production deployed: ${{ github.event.release.tag_name }}"
            }
        env:
          SLACK_WEBHOOK_URL: ${{ secrets.SLACK_WEBHOOK }}

      - name: Notify failure
        if: failure()
        uses: slackapi/slack-github-action@v1.25.0
        with:
          payload: |
            {
              "text": "❌ Production deployment FAILED: ${{ github.event.release.tag_name }}"
            }
        env:
          SLACK_WEBHOOK_URL: ${{ secrets.SLACK_WEBHOOK }}
```

### 5.2 Kubernetes Helm Chart (Futuro)

```yaml
# helm/sentrikat/values.yaml - FUTURO
replicaCount: 3

image:
  repository: ghcr.io/sbr0nch/sentrikat
  tag: "1.0.0"
  pullPolicy: IfNotPresent

service:
  type: ClusterIP
  port: 5000

ingress:
  enabled: true
  className: "nginx"
  annotations:
    cert-manager.io/cluster-issuer: "letsencrypt-prod"
  hosts:
    - host: sentrikat.com
      paths:
        - path: /
          pathType: Prefix
  tls:
    - secretName: sentrikat-tls
      hosts:
        - sentrikat.com

resources:
  limits:
    cpu: 2000m
    memory: 4Gi
  requests:
    cpu: 500m
    memory: 1Gi

autoscaling:
  enabled: true
  minReplicas: 2
  maxReplicas: 10
  targetCPUUtilizationPercentage: 70

postgresql:
  enabled: true
  auth:
    database: sentrikat
  primary:
    persistence:
      size: 100Gi
```

---

## 6. PIPELINE COMPLETA (TARGET)

### 6.1 Visione Completa

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                        COMPLETE CI/CD PIPELINE (TARGET)                      │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                              │
│  ┌─────────┐  ┌─────────┐  ┌─────────┐  ┌─────────┐  ┌─────────┐           │
│  │ COMMIT  │─>│  LINT   │─>│  TEST   │─>│  SAST   │─>│  BUILD  │           │
│  │         │  │ flake8  │  │ pytest  │  │ bandit  │  │ docker  │           │
│  │         │  │ black   │  │ coverage│  │ trivy   │  │         │           │
│  └─────────┘  └─────────┘  └─────────┘  └─────────┘  └─────────┘           │
│       │            │            │            │            │                  │
│       │            │            │            │            │                  │
│       ▼            ▼            ▼            ▼            ▼                  │
│  [Feature]    [Quality]    [Quality]    [Security]   [Artifact]             │
│   Branch       Gate         Gate         Gate         Ready                 │
│                                                                              │
│                              │                                               │
│                              │ PR Merge to main                              │
│                              ▼                                               │
│  ┌─────────────────────────────────────────────────────────────────────┐    │
│  │                          STAGING                                     │    │
│  │  Auto-deploy → Smoke tests → DAST scan → Integration tests          │    │
│  └─────────────────────────────────────────────────────────────────────┘    │
│                              │                                               │
│                              │ Manual approval + Tag                         │
│                              ▼                                               │
│  ┌─────────────────────────────────────────────────────────────────────┐    │
│  │                         PRODUCTION                                   │    │
│  │  Blue-green → Health check → Smoke tests → Monitor → Rollback ready │    │
│  └─────────────────────────────────────────────────────────────────────┘    │
│                                                                              │
└─────────────────────────────────────────────────────────────────────────────┘
```

### 6.2 Gate Summary

| Gate | Strumenti | Threshold | Bloccante |
|------|-----------|-----------|-----------|
| Lint | flake8, black, isort | No errors | Sì |
| Unit Tests | pytest | 100% pass | Sì |
| Coverage | pytest-cov | ≥70% | Sì |
| SAST | Bandit, Safety | No HIGH | Sì |
| Container Scan | Trivy | No CRITICAL | Sì |
| Secret Scan | TruffleHog | No secrets | Sì |
| Staging Smoke | curl, pytest | All pass | Sì |
| DAST | OWASP ZAP | No HIGH | Warning |

---

## 7. MONITORING & OBSERVABILITY

### 7.1 Application Metrics (Prometheus)

```python
# app/metrics.py - NUOVO
from prometheus_client import Counter, Histogram, Gauge, generate_latest
from functools import wraps
import time

# Metriche
REQUEST_COUNT = Counter(
    'sentrikat_requests_total',
    'Total HTTP requests',
    ['method', 'endpoint', 'status']
)

REQUEST_LATENCY = Histogram(
    'sentrikat_request_duration_seconds',
    'Request latency',
    ['method', 'endpoint'],
    buckets=[.005, .01, .025, .05, .075, .1, .25, .5, .75, 1.0, 2.5, 5.0, 7.5, 10.0]
)

ACTIVE_AGENTS = Gauge(
    'sentrikat_active_agents',
    'Number of active agents',
    ['organization']
)

VULNERABILITY_COUNT = Gauge(
    'sentrikat_vulnerabilities_total',
    'Total vulnerabilities tracked',
    ['severity']
)

DB_CONNECTIONS = Gauge(
    'sentrikat_db_connections',
    'Database connection pool usage'
)

def track_request(f):
    @wraps(f)
    def wrapper(*args, **kwargs):
        start = time.time()
        try:
            response = f(*args, **kwargs)
            status = response.status_code
        except Exception as e:
            status = 500
            raise
        finally:
            REQUEST_COUNT.labels(
                method=request.method,
                endpoint=request.endpoint,
                status=status
            ).inc()
            REQUEST_LATENCY.labels(
                method=request.method,
                endpoint=request.endpoint
            ).observe(time.time() - start)
        return response
    return wrapper

# Endpoint per Prometheus
@app.route('/metrics')
def metrics():
    return generate_latest()
```

### 7.2 Logging Strutturato

```python
# app/logging_config.py - NUOVO
import logging
import json
from datetime import datetime

class JSONFormatter(logging.Formatter):
    def format(self, record):
        log_record = {
            'timestamp': datetime.utcnow().isoformat(),
            'level': record.levelname,
            'logger': record.name,
            'message': record.getMessage(),
            'module': record.module,
            'function': record.funcName,
            'line': record.lineno
        }

        if hasattr(record, 'user_id'):
            log_record['user_id'] = record.user_id
        if hasattr(record, 'organization_id'):
            log_record['organization_id'] = record.organization_id
        if hasattr(record, 'request_id'):
            log_record['request_id'] = record.request_id
        if record.exc_info:
            log_record['exception'] = self.formatException(record.exc_info)

        return json.dumps(log_record)

# Configurazione
logging.config.dictConfig({
    'version': 1,
    'formatters': {
        'json': {
            '()': JSONFormatter
        }
    },
    'handlers': {
        'console': {
            'class': 'logging.StreamHandler',
            'formatter': 'json',
            'stream': 'ext://sys.stdout'
        },
        'file': {
            'class': 'logging.handlers.RotatingFileHandler',
            'formatter': 'json',
            'filename': '/var/log/sentrikat/app.log',
            'maxBytes': 10485760,  # 10MB
            'backupCount': 5
        }
    },
    'root': {
        'level': 'INFO',
        'handlers': ['console', 'file']
    }
})
```

### 7.3 Grafana Dashboards

```json
// grafana/dashboards/sentrikat-overview.json - NUOVO
{
  "title": "SentriKat Overview",
  "panels": [
    {
      "title": "Request Rate",
      "type": "graph",
      "targets": [
        {
          "expr": "rate(sentrikat_requests_total[5m])",
          "legendFormat": "{{method}} {{endpoint}}"
        }
      ]
    },
    {
      "title": "Response Time (p99)",
      "type": "gauge",
      "targets": [
        {
          "expr": "histogram_quantile(0.99, rate(sentrikat_request_duration_seconds_bucket[5m]))"
        }
      ]
    },
    {
      "title": "Error Rate",
      "type": "stat",
      "targets": [
        {
          "expr": "rate(sentrikat_requests_total{status=~\"5..\"}[5m]) / rate(sentrikat_requests_total[5m]) * 100"
        }
      ]
    },
    {
      "title": "Active Agents",
      "type": "stat",
      "targets": [
        {
          "expr": "sum(sentrikat_active_agents)"
        }
      ]
    },
    {
      "title": "Vulnerabilities by Severity",
      "type": "piechart",
      "targets": [
        {
          "expr": "sentrikat_vulnerabilities_total",
          "legendFormat": "{{severity}}"
        }
      ]
    }
  ]
}
```

---

## 8. COSTI E RISORSE

### 8.1 Costi GitHub Actions

| Piano | Minuti inclusi | Costo extra | Stima mensile |
|-------|----------------|-------------|---------------|
| Free | 2,000 min/mese | $0.008/min | €0 (se < 2000) |
| Team | 3,000 min/mese | $0.008/min | ~€4/user/mese |
| Enterprise | 50,000 min/mese | $0.008/min | Custom |

**Stima utilizzo SentriKat:**
- CI per PR: ~5 min × 20 PR/mese = 100 min
- Staging deploy: ~3 min × 20/mese = 60 min
- Security scans: ~10 min × 4/mese = 40 min
- Release: ~5 min × 4/mese = 20 min
- **Totale: ~220 min/mese** (ben dentro il free tier)

### 8.2 Strumenti Aggiuntivi

| Strumento | Costo | Note |
|-----------|-------|------|
| Codecov | Free (open source) | Coverage reporting |
| Snyk | Free (100 tests/mese) | Dependency scanning |
| Grafana Cloud | Free (10k metrics) | Monitoring |
| Slack | Free tier | Notifications |

---

## 9. CHECKLIST IMPLEMENTAZIONE

### Fase 2 (Q2 2026)
- [ ] Configurare pytest-cov
- [ ] Integrare Codecov
- [ ] Creare deploy-staging.yml
- [ ] Configurare Dependabot
- [ ] Implementare pre-commit hooks
- [ ] Setup Slack notifications

### Fase 3 (Q3 2026)
- [ ] Aggiungere Bandit alla CI
- [ ] Configurare Trivy container scan
- [ ] Implementare TruffleHog
- [ ] Setup OWASP ZAP per staging
- [ ] Generare SBOM nelle release

### Fase 4 (Q4 2026)
- [ ] Creare deploy-production.yml con approval
- [ ] Implementare blue-green deployment
- [ ] Setup Prometheus metrics
- [ ] Configurare Grafana dashboards
- [ ] Preparare Helm chart (se K8s)

---

## 10. RISORSE E RIFERIMENTI

- [GitHub Actions Documentation](https://docs.github.com/en/actions)
- [Docker Build Best Practices](https://docs.docker.com/develop/develop-images/dockerfile_best-practices/)
- [OWASP DevSecOps Guidelines](https://owasp.org/www-project-devsecops-guideline/)
- [12 Factor App](https://12factor.net/)
- [Prometheus Best Practices](https://prometheus.io/docs/practices/)
- [Grafana Dashboards](https://grafana.com/grafana/dashboards/)

---

*Questo documento viene aggiornato ad ogni milestone DevOps completata.*
