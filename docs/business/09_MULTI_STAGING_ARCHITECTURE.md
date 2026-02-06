# SENTRIKAT - MULTI-STAGING ARCHITECTURE
## Piano Architetturale per Ambienti Development, Staging e Production

---

**Versione:** 1.0
**Ultimo Aggiornamento:** Febbraio 2026
**Autore:** SentriKat Development Team

---

## 1. PANORAMICA

### 1.1 Obiettivi del Multi-Staging

| Obiettivo | Descrizione |
|-----------|-------------|
| **Isolamento** | Separazione completa tra ambienti per evitare impatti su produzione |
| **Qualità** | Test approfonditi prima del rilascio |
| **Velocità** | Deploy frequenti con rischio controllato |
| **Compliance** | Audit trail e controllo cambiamenti |
| **Disaster Recovery** | Ambiente di fallback in caso di problemi |

### 1.2 Ambienti Proposti

```
┌─────────────────────────────────────────────────────────────────────┐
│                     SENTRIKAT ENVIRONMENT PIPELINE                   │
├─────────────────────────────────────────────────────────────────────┤
│                                                                      │
│   ┌──────────┐    ┌──────────┐    ┌──────────┐    ┌──────────┐     │
│   │   DEV    │───>│  TEST    │───>│ STAGING  │───>│   PROD   │     │
│   │          │    │          │    │          │    │          │     │
│   │ Feature  │    │ QA/Auto  │    │ Pre-Prod │    │  Live    │     │
│   │ Branch   │    │ Testing  │    │ Validation│   │ Customers│     │
│   └──────────┘    └──────────┘    └──────────┘    └──────────┘     │
│        │               │               │               │            │
│        ▼               ▼               ▼               ▼            │
│   [Developers]   [CI/CD Auto]   [QA Team +     [Monitoring +       │
│                                  Stakeholders]  On-Call]            │
│                                                                      │
└─────────────────────────────────────────────────────────────────────┘
```

---

## 2. ARCHITETTURA PER AMBIENTE

### 2.1 Development (DEV)

**Scopo:** Sviluppo locale e feature branch testing

```yaml
# docker-compose.dev.yml
version: '3.8'

services:
  sentrikat:
    build:
      context: .
      dockerfile: Dockerfile.dev
    ports:
      - "5000:5000"
    environment:
      - FLASK_ENV=development
      - FLASK_DEBUG=1
      - DATABASE_URL=postgresql://dev:dev@db:5432/sentrikat_dev
      - SECRET_KEY=dev-secret-key-not-for-prod
      - SENTRIKAT_LICENSE=  # Demo mode
    volumes:
      - ./app:/app/app:ro  # Hot reload
      - ./tests:/app/tests:ro
    depends_on:
      - db
      - mailhog

  db:
    image: postgres:16-alpine
    environment:
      - POSTGRES_USER=dev
      - POSTGRES_PASSWORD=dev
      - POSTGRES_DB=sentrikat_dev
    ports:
      - "5432:5432"  # Accessible for debugging
    volumes:
      - dev-postgres:/var/lib/postgresql/data

  mailhog:
    image: mailhog/mailhog
    ports:
      - "1025:1025"  # SMTP
      - "8025:8025"  # Web UI

  adminer:
    image: adminer
    ports:
      - "8080:8080"  # Database admin UI

volumes:
  dev-postgres:
```

**Caratteristiche DEV:**
- Hot reload del codice
- Debug mode attivo
- Database locale con dati di test
- MailHog per cattura email
- Adminer per gestione DB
- Nessuna licenza richiesta (Demo mode)

---

### 2.2 Test (TEST/CI)

**Scopo:** Test automatizzati in CI/CD

```yaml
# docker-compose.test.yml
version: '3.8'

services:
  sentrikat-test:
    build:
      context: .
      dockerfile: Dockerfile
    environment:
      - FLASK_ENV=testing
      - DATABASE_URL=postgresql://test:test@db-test:5432/sentrikat_test
      - SECRET_KEY=test-secret-key
      - TESTING=true
    depends_on:
      - db-test

  db-test:
    image: postgres:16-alpine
    environment:
      - POSTGRES_USER=test
      - POSTGRES_PASSWORD=test
      - POSTGRES_DB=sentrikat_test
    tmpfs:
      - /var/lib/postgresql/data  # RAM disk for speed

  test-runner:
    build:
      context: .
      dockerfile: Dockerfile.test
    command: pytest -v --cov=app --cov-report=xml
    environment:
      - DATABASE_URL=postgresql://test:test@db-test:5432/sentrikat_test
    depends_on:
      - db-test
    volumes:
      - ./test-results:/app/test-results
```

**Caratteristiche TEST:**
- Database in RAM per velocità
- Coverage report generato
- Nessuna persistenza dati
- Esecuzione isolata per ogni build
- Timeout aggressivi

---

### 2.3 Staging (STAGING)

**Scopo:** Validazione pre-produzione con dati realistici

```yaml
# docker-compose.staging.yml
version: '3.8'

services:
  nginx:
    image: nginx:alpine
    ports:
      - "443:443"
    volumes:
      - ./nginx/staging.conf:/etc/nginx/nginx.conf:ro
      - ./ssl/staging:/etc/nginx/ssl:ro
    depends_on:
      - sentrikat

  sentrikat:
    image: ghcr.io/sbr0nch/sentrikat:${VERSION:-latest}
    environment:
      - FLASK_ENV=staging
      - DATABASE_URL=postgresql://${DB_USER}:${DB_PASS}@db:5432/sentrikat_staging
      - SECRET_KEY=${SECRET_KEY}
      - ENCRYPTION_KEY=${ENCRYPTION_KEY}
      - SENTRIKAT_INSTALLATION_ID=${STAGING_INSTALLATION_ID}
      - SENTRIKAT_LICENSE=${STAGING_LICENSE}
      - VERIFY_SSL=true
    depends_on:
      - db
    deploy:
      resources:
        limits:
          memory: 2G
          cpus: '2'

  db:
    image: postgres:16-alpine
    environment:
      - POSTGRES_USER=${DB_USER}
      - POSTGRES_PASSWORD=${DB_PASS}
      - POSTGRES_DB=sentrikat_staging
    volumes:
      - staging-postgres:/var/lib/postgresql/data
    deploy:
      resources:
        limits:
          memory: 1G

  # Backup automatico giornaliero
  backup:
    image: prodrigestivill/postgres-backup-local
    environment:
      - POSTGRES_HOST=db
      - POSTGRES_DB=sentrikat_staging
      - POSTGRES_USER=${DB_USER}
      - POSTGRES_PASSWORD=${DB_PASS}
      - BACKUP_KEEP_DAYS=7
      - SCHEDULE=@daily
    volumes:
      - ./backups/staging:/backups

volumes:
  staging-postgres:
```

**Caratteristiche STAGING:**
- Immagine Docker identica a produzione
- Dati anonimi/sanitizzati da produzione
- SSL/TLS attivo
- Backup automatici
- Resource limits simili a produzione
- Licenza staging dedicata
- Accessibile a QA e stakeholders

**URL Staging:** `https://staging.sentrikat.com` (interno)

---

### 2.4 Production (PROD)

**Scopo:** Ambiente live per i clienti

```yaml
# docker-compose.prod.yml
version: '3.8'

services:
  nginx:
    image: nginx:alpine
    ports:
      - "443:443"
      - "80:80"  # Redirect to HTTPS
    volumes:
      - ./nginx/prod.conf:/etc/nginx/nginx.conf:ro
      - ./ssl/prod:/etc/nginx/ssl:ro
      - ./nginx/logs:/var/log/nginx
    depends_on:
      - sentrikat
    restart: always
    deploy:
      resources:
        limits:
          memory: 256M

  sentrikat:
    image: ghcr.io/sbr0nch/sentrikat:${VERSION}
    environment:
      - FLASK_ENV=production
      - DATABASE_URL=postgresql://${DB_USER}:${DB_PASS}@db:5432/sentrikat_prod
      - SECRET_KEY=${SECRET_KEY}
      - ENCRYPTION_KEY=${ENCRYPTION_KEY}
      - SENTRIKAT_INSTALLATION_ID=${PROD_INSTALLATION_ID}
      - SENTRIKAT_LICENSE=${PROD_LICENSE}
      - NVD_API_KEY=${NVD_API_KEY}
      - VERIFY_SSL=true
      - GUNICORN_WORKERS=4
      - GUNICORN_TIMEOUT=120
    depends_on:
      - db
    restart: always
    deploy:
      resources:
        limits:
          memory: 4G
          cpus: '4'
    healthcheck:
      test: ["CMD", "curl", "-f", "http://localhost:5000/health"]
      interval: 30s
      timeout: 10s
      retries: 3
      start_period: 40s

  db:
    image: postgres:16-alpine
    environment:
      - POSTGRES_USER=${DB_USER}
      - POSTGRES_PASSWORD=${DB_PASS}
      - POSTGRES_DB=sentrikat_prod
    volumes:
      - prod-postgres:/var/lib/postgresql/data
      - ./postgres/conf:/etc/postgresql/conf.d:ro
    restart: always
    deploy:
      resources:
        limits:
          memory: 4G
    command: >
      postgres
        -c shared_buffers=1GB
        -c effective_cache_size=3GB
        -c maintenance_work_mem=256MB
        -c checkpoint_completion_target=0.9
        -c wal_buffers=16MB
        -c max_connections=200

  # Backup automatico
  backup:
    image: prodrigestivill/postgres-backup-local
    environment:
      - POSTGRES_HOST=db
      - POSTGRES_DB=sentrikat_prod
      - POSTGRES_USER=${DB_USER}
      - POSTGRES_PASSWORD=${DB_PASS}
      - BACKUP_KEEP_DAYS=30
      - BACKUP_KEEP_WEEKS=8
      - BACKUP_KEEP_MONTHS=6
      - SCHEDULE=0 2 * * *  # 2 AM daily
    volumes:
      - ./backups/prod:/backups
    restart: always

  # Monitoring
  prometheus:
    image: prom/prometheus:latest
    volumes:
      - ./monitoring/prometheus.yml:/etc/prometheus/prometheus.yml
      - prometheus-data:/prometheus
    restart: always

  grafana:
    image: grafana/grafana:latest
    ports:
      - "3000:3000"
    volumes:
      - grafana-data:/var/lib/grafana
    restart: always

volumes:
  prod-postgres:
  prometheus-data:
  grafana-data:
```

**Caratteristiche PROD:**
- High availability ready
- Backup multi-livello (daily/weekly/monthly)
- Monitoring con Prometheus/Grafana
- Health checks
- Auto-restart on failure
- Tuned PostgreSQL
- SSL/TLS con certificati validi
- Rate limiting attivo

---

## 3. NETWORK ARCHITECTURE

### 3.1 Separazione Network

```
┌─────────────────────────────────────────────────────────────────────┐
│                        NETWORK TOPOLOGY                              │
├─────────────────────────────────────────────────────────────────────┤
│                                                                      │
│  ┌─────────────────────────────────────────────────────────────┐    │
│  │                    INTERNET / CLIENTS                         │    │
│  └─────────────────────────────┬───────────────────────────────┘    │
│                                │                                     │
│                    ┌───────────▼───────────┐                        │
│                    │      CLOUDFLARE       │                        │
│                    │      (CDN/WAF)        │                        │
│                    └───────────┬───────────┘                        │
│                                │                                     │
│  ┌─────────────────────────────┼─────────────────────────────────┐  │
│  │                     DMZ NETWORK                                │  │
│  │         ┌───────────────────▼───────────────────┐             │  │
│  │         │           NGINX PROXY                  │             │  │
│  │         │         (SSL Termination)              │             │  │
│  │         └───────────────────┬───────────────────┘             │  │
│  └─────────────────────────────┼─────────────────────────────────┘  │
│                                │                                     │
│  ┌─────────────────────────────┼─────────────────────────────────┐  │
│  │                  APPLICATION NETWORK                           │  │
│  │         ┌───────────────────▼───────────────────┐             │  │
│  │         │        SENTRIKAT APP                   │             │  │
│  │         │       (Flask/Gunicorn)                 │             │  │
│  │         └───────────────────┬───────────────────┘             │  │
│  └─────────────────────────────┼─────────────────────────────────┘  │
│                                │                                     │
│  ┌─────────────────────────────┼─────────────────────────────────┐  │
│  │                   DATABASE NETWORK                             │  │
│  │         ┌───────────────────▼───────────────────┐             │  │
│  │         │          POSTGRESQL                    │             │  │
│  │         │         (No external)                  │             │  │
│  │         └───────────────────────────────────────┘             │  │
│  └───────────────────────────────────────────────────────────────┘  │
│                                                                      │
└─────────────────────────────────────────────────────────────────────┘
```

### 3.2 Firewall Rules

```bash
# Production firewall rules (UFW example)

# Default policies
ufw default deny incoming
ufw default allow outgoing

# Allow SSH (with IP restriction)
ufw allow from 10.0.0.0/8 to any port 22

# Allow HTTPS
ufw allow 443/tcp

# Allow HTTP (redirect to HTTPS)
ufw allow 80/tcp

# Internal network for services
ufw allow from 172.18.0.0/16 to any

# Block direct database access
ufw deny 5432

# Enable
ufw enable
```

---

## 4. DATA FLOW E PROMOZIONE

### 4.1 Flusso di Promozione Codice

```
┌──────────┐    ┌──────────┐    ┌──────────┐    ┌──────────┐
│ Feature  │───>│  Test    │───>│ Staging  │───>│   Main   │
│ Branch   │    │  Pass    │    │  Approve │    │  Release │
└──────────┘    └──────────┘    └──────────┘    └──────────┘
     │               │               │               │
     │               │               │               │
     ▼               ▼               ▼               ▼
┌──────────┐    ┌──────────┐    ┌──────────┐    ┌──────────┐
│   DEV    │    │   TEST   │    │ STAGING  │    │   PROD   │
│  (auto)  │    │  (auto)  │    │ (manual) │    │ (manual) │
└──────────┘    └──────────┘    └──────────┘    └──────────┘
```

### 4.2 Promozione Dati (Reverse)

```
PROD ──sanitize──> STAGING ──subset──> DEV

⚠️ MAI copiare dati da DEV/STAGING a PROD
```

**Script di sanitizzazione:**

```bash
#!/bin/bash
# sanitize-prod-to-staging.sh

# Dump produzione
pg_dump -h prod-db -U admin sentrikat_prod > /tmp/prod_dump.sql

# Sanitize sensitive data
sed -i 's/password_hash.*$/password_hash = "$2b$12$sanitized"/g' /tmp/prod_dump.sql
sed -i 's/smtp_password.*$/smtp_password = "REDACTED"/g' /tmp/prod_dump.sql
sed -i 's/webhook_url.*$/webhook_url = "https://staging-webhook.example.com"/g' /tmp/prod_dump.sql

# Remove PII
psql -f /tmp/prod_dump.sql sentrikat_staging
psql sentrikat_staging << EOF
  UPDATE "user" SET email = 'user_' || id || '@example.com';
  UPDATE "user" SET username = 'user_' || id;
  DELETE FROM alert_log;
  DELETE FROM sync_log WHERE created_at < NOW() - INTERVAL '7 days';
EOF

echo "Staging database sanitized from production"
```

---

## 5. DEPLOYMENT STRATEGY

### 5.1 Blue-Green Deployment (Production)

```
┌─────────────────────────────────────────────────────────────────────┐
│                    BLUE-GREEN DEPLOYMENT                             │
├─────────────────────────────────────────────────────────────────────┤
│                                                                      │
│                    ┌──────────────────┐                             │
│                    │   LOAD BALANCER  │                             │
│                    │    (nginx)       │                             │
│                    └────────┬─────────┘                             │
│                             │                                        │
│              ┌──────────────┴──────────────┐                        │
│              │ (switch traffic)            │                        │
│              ▼                             ▼                        │
│   ┌──────────────────┐         ┌──────────────────┐                │
│   │   BLUE (v1.0.0)  │         │  GREEN (v1.0.1)  │                │
│   │   ✓ ACTIVE       │         │   ○ STANDBY      │                │
│   │                  │         │   (new version)  │                │
│   └──────────────────┘         └──────────────────┘                │
│                                                                      │
│   ROLLBACK: Switch traffic back to BLUE                            │
│                                                                      │
└─────────────────────────────────────────────────────────────────────┘
```

**nginx config per blue-green:**

```nginx
# /etc/nginx/conf.d/sentrikat.conf

upstream sentrikat_blue {
    server sentrikat-blue:5000;
}

upstream sentrikat_green {
    server sentrikat-green:5000;
}

# Active backend (change this for deployment)
map $request_uri $backend {
    default sentrikat_blue;  # Change to sentrikat_green for deploy
}

server {
    listen 443 ssl http2;
    server_name sentrikat.com;

    location / {
        proxy_pass http://$backend;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
    }
}
```

### 5.2 Rolling Deployment (Kubernetes - Futuro)

```yaml
# k8s/deployment.yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: sentrikat
spec:
  replicas: 3
  strategy:
    type: RollingUpdate
    rollingUpdate:
      maxSurge: 1
      maxUnavailable: 0
  selector:
    matchLabels:
      app: sentrikat
  template:
    metadata:
      labels:
        app: sentrikat
    spec:
      containers:
      - name: sentrikat
        image: ghcr.io/sbr0nch/sentrikat:1.0.1
        ports:
        - containerPort: 5000
        readinessProbe:
          httpGet:
            path: /health
            port: 5000
          initialDelaySeconds: 10
          periodSeconds: 5
        livenessProbe:
          httpGet:
            path: /health
            port: 5000
          initialDelaySeconds: 30
          periodSeconds: 10
```

---

## 6. CONFIGURATION MANAGEMENT

### 6.1 Environment Variables per Ambiente

```bash
# .env.dev
FLASK_ENV=development
DATABASE_URL=postgresql://dev:dev@localhost:5432/sentrikat_dev
SECRET_KEY=dev-not-secure
DEBUG=true

# .env.staging
FLASK_ENV=staging
DATABASE_URL=postgresql://staging_user:${DB_PASS}@db:5432/sentrikat_staging
SECRET_KEY=${SECRET_KEY}
DEBUG=false
SENTRIKAT_LICENSE=${STAGING_LICENSE}

# .env.prod
FLASK_ENV=production
DATABASE_URL=postgresql://prod_user:${DB_PASS}@db:5432/sentrikat_prod
SECRET_KEY=${SECRET_KEY}
DEBUG=false
SENTRIKAT_LICENSE=${PROD_LICENSE}
NVD_API_KEY=${NVD_API_KEY}
```

### 6.2 Secrets Management

**Opzione 1: Docker Secrets (Docker Swarm)**
```yaml
secrets:
  db_password:
    external: true
  secret_key:
    external: true

services:
  sentrikat:
    secrets:
      - db_password
      - secret_key
```

**Opzione 2: HashiCorp Vault (Enterprise)**
```bash
# Lettura secrets da Vault
export DATABASE_URL=$(vault kv get -field=url secret/sentrikat/prod/database)
export SECRET_KEY=$(vault kv get -field=key secret/sentrikat/prod/app)
```

**Opzione 3: Cloud Provider Secrets**
- AWS Secrets Manager
- Azure Key Vault
- Google Secret Manager

---

## 7. MONITORING E ALERTING

### 7.1 Stack di Monitoring

```
┌─────────────────────────────────────────────────────────────────────┐
│                     MONITORING STACK                                 │
├─────────────────────────────────────────────────────────────────────┤
│                                                                      │
│   ┌─────────────┐    ┌─────────────┐    ┌─────────────┐            │
│   │ SENTRIKAT   │───>│ PROMETHEUS  │───>│  GRAFANA    │            │
│   │  /metrics   │    │  (scrape)   │    │ (visualize) │            │
│   └─────────────┘    └─────────────┘    └─────────────┘            │
│          │                  │                   │                    │
│          │                  ▼                   │                    │
│          │           ┌─────────────┐            │                    │
│          │           │ALERTMANAGER │────────────┤                    │
│          │           └─────────────┘            │                    │
│          │                  │                   │                    │
│          ▼                  ▼                   ▼                    │
│   ┌─────────────┐    ┌─────────────┐    ┌─────────────┐            │
│   │    LOKI     │    │   SLACK     │    │  PAGERDUTY  │            │
│   │   (logs)    │    │  (alerts)   │    │ (on-call)   │            │
│   └─────────────┘    └─────────────┘    └─────────────┘            │
│                                                                      │
└─────────────────────────────────────────────────────────────────────┘
```

### 7.2 Metriche Chiave

| Metrica | Warning | Critical | Azione |
|---------|---------|----------|--------|
| CPU Usage | >70% | >90% | Scale up |
| Memory Usage | >75% | >90% | Scale up / investigate |
| Disk Usage | >70% | >85% | Cleanup / expand |
| Response Time (p99) | >2s | >5s | Investigate / scale |
| Error Rate | >1% | >5% | Investigate |
| DB Connections | >80% pool | >95% pool | Increase pool |
| Agent Checkin Failures | >5% | >20% | Alert + investigate |

### 7.3 Alert Rules (Prometheus)

```yaml
# alerting_rules.yml
groups:
  - name: sentrikat
    rules:
      - alert: HighErrorRate
        expr: rate(http_requests_total{status=~"5.."}[5m]) > 0.05
        for: 5m
        labels:
          severity: critical
        annotations:
          summary: "High error rate detected"

      - alert: SlowResponses
        expr: histogram_quantile(0.99, rate(http_request_duration_seconds_bucket[5m])) > 5
        for: 10m
        labels:
          severity: warning
        annotations:
          summary: "Slow response times"

      - alert: DatabaseConnectionsHigh
        expr: pg_stat_activity_count > 180
        for: 5m
        labels:
          severity: warning
        annotations:
          summary: "Database connections approaching limit"
```

---

## 8. DISASTER RECOVERY

### 8.1 RPO e RTO per Ambiente

| Ambiente | RPO (Data Loss) | RTO (Downtime) |
|----------|-----------------|----------------|
| DEV | N/A | N/A |
| TEST | N/A | N/A |
| STAGING | 24 hours | 4 hours |
| PROD | 1 hour | 30 minutes |

### 8.2 Backup Strategy

```bash
#!/bin/bash
# backup-strategy.sh

# Continuous WAL archiving (Point-in-Time Recovery)
# postgresql.conf:
# archive_mode = on
# archive_command = 'aws s3 cp %p s3://sentrikat-backups/wal/%f'

# Daily full backup
pg_dump -Fc sentrikat_prod | aws s3 cp - s3://sentrikat-backups/daily/$(date +%Y%m%d).dump

# Weekly full backup (kept for 3 months)
if [ $(date +%u) -eq 7 ]; then
    pg_dump -Fc sentrikat_prod | aws s3 cp - s3://sentrikat-backups/weekly/$(date +%Y%m%d).dump
fi

# Monthly backup (kept for 1 year)
if [ $(date +%d) -eq 1 ]; then
    pg_dump -Fc sentrikat_prod | aws s3 cp - s3://sentrikat-backups/monthly/$(date +%Y%m).dump
fi
```

### 8.3 Recovery Procedures

```bash
#!/bin/bash
# restore-from-backup.sh

# 1. Stop application
docker-compose -f docker-compose.prod.yml stop sentrikat

# 2. Restore database
BACKUP_FILE=$1
aws s3 cp s3://sentrikat-backups/daily/${BACKUP_FILE} /tmp/restore.dump
pg_restore -c -d sentrikat_prod /tmp/restore.dump

# 3. Verify data integrity
psql sentrikat_prod -c "SELECT COUNT(*) FROM vulnerability;"
psql sentrikat_prod -c "SELECT COUNT(*) FROM product;"

# 4. Start application
docker-compose -f docker-compose.prod.yml up -d sentrikat

# 5. Verify health
curl -f http://localhost:5000/health
```

---

## 9. COSTI STIMATI

### 9.1 Costi Infrastruttura Mensili

| Ambiente | Server | Database | Storage | Totale/mese |
|----------|--------|----------|---------|-------------|
| DEV | Locale | Locale | Locale | €0 |
| TEST | CI/CD minutes | N/A | N/A | ~€20 (GitHub) |
| STAGING | VPS 2CPU/4GB | Incluso | 50GB | ~€25 |
| PROD (small) | VPS 4CPU/8GB | Managed | 100GB | ~€80 |
| PROD (medium) | VPS 8CPU/16GB | Managed | 250GB | ~€200 |

**Provider consigliati (EU-based):**
- Hetzner Cloud: https://www.hetzner.com/cloud
- OVH: https://www.ovhcloud.com
- Scaleway: https://www.scaleway.com

### 9.2 Costi Aggiuntivi

| Servizio | Costo | Note |
|----------|-------|------|
| Cloudflare | Free tier | CDN, DDoS, basic WAF |
| SSL Certificate | Free (Let's Encrypt) | Auto-renewal |
| Monitoring (Grafana Cloud) | Free tier | 10k metrics |
| Backup Storage (S3) | ~€5/mese | Per 100GB |
| Domain | ~€15/anno | .com |

---

## 10. PIANO DI IMPLEMENTAZIONE

### 10.1 Fase 1: Fondazione (Settimana 1-2)

- [ ] Setup VPS per staging
- [ ] Configurare docker-compose.staging.yml
- [ ] Implementare CI/CD per staging auto-deploy
- [ ] Configurare backup automatici

### 10.2 Fase 2: Produzione (Settimana 3-4)

- [ ] Setup VPS produzione
- [ ] Configurare SSL/TLS
- [ ] Implementare monitoring base
- [ ] Test disaster recovery

### 10.3 Fase 3: Ottimizzazione (Settimana 5-8)

- [ ] Fine-tuning PostgreSQL
- [ ] Implementare blue-green deployment
- [ ] Setup alerting completo
- [ ] Documentazione runbook

---

## RISORSE E RIFERIMENTI

- [12 Factor App](https://12factor.net/) - Best practices per app cloud-native
- [Docker Compose Production](https://docs.docker.com/compose/production/)
- [PostgreSQL Tuning](https://pgtune.leopard.in.ua/) - Calcolo parametri ottimali
- [Prometheus Best Practices](https://prometheus.io/docs/practices/)

---

*Documento da aggiornare con le specifiche dell'infrastruttura scelta.*
