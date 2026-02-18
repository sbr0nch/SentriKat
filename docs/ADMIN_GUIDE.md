# SentriKat Administration Guide

Operations reference for managing a SentriKat vulnerability management platform.

---

## 1. Quick Reference

### Default Credentials

| Item | Default | Notes |
|------|---------|-------|
| Admin login | `admin` / `admin` | Created during setup wizard; change immediately |
| PostgreSQL user | `sentrikat` | Password set via `DB_PASSWORD` in `.env` |
| Application port | `5000` (internal) | Not exposed externally; nginx proxies to it |

### Default URLs and Ports

| Endpoint | URL | Purpose |
|----------|-----|---------|
| Web UI | `http://localhost` (port 80) | Main interface |
| HTTPS | `https://localhost` (port 443) | When SSL is enabled |
| Health check | `GET /api/health` | Load balancer / uptime monitoring (no auth) |
| Sync status | `GET /api/sync/status` | CISA KEV / NVD sync status (auth required) |
| System health | `GET /api/system/health` | Detailed system health (auth required) |
| Health checks | `GET /api/admin/health-checks` | Background health check results (admin) |
| Setup wizard | `/setup` | First-run configuration (disabled after setup) |

### Key Configuration Files

| File | Purpose |
|------|---------|
| `.env` | All environment variables (copy from `.env.example`) |
| `docker-compose.yml` | Container orchestration (PostgreSQL, app, nginx) |
| `docker-compose.storage.yml` | Optional: bind-mount override for custom storage paths |
| `config.py` | Application configuration (reads from environment) |
| `gunicorn.conf.py` | Web server tuning (workers, threads, timeouts) |
| `nginx/nginx.conf.template` | HTTP reverse proxy config |
| `nginx/nginx-ssl.conf.template` | HTTPS reverse proxy config |
| `certs/` | Directory for custom CA certificates (corporate PKI) |

---

## 2. Day-to-Day Operations

### Monitoring Health

**Quick health check** (no authentication required):
```bash
curl -s http://localhost/api/health | python3 -m json.tool
```
Returns `200` if healthy, `503` if database is unreachable.

**Background health checks** run every 30 minutes covering: database, disk space, worker pool, stuck jobs, CVE sync freshness, agent health, CPE coverage, license, SMTP, import queue, and API source status. View at **Settings > Health Checks**.

**Docker container health:**
```bash
docker compose ps                       # Container status
docker compose logs --tail=50 sentrikat # Application logs
docker compose logs --tail=50 db        # Database logs
docker compose logs --tail=50 nginx     # Nginx logs
```

### Checking Sync Status

SentriKat syncs vulnerability data from multiple sources on automatic schedules:

| Source | Schedule | Description |
|--------|----------|-------------|
| CISA KEV | Daily at `SYNC_HOUR:SYNC_MINUTE` (default 02:00 UTC) | Known exploited vulnerabilities |
| EPSS scores | After each CISA KEV sync | Exploit prediction scores |
| ENISA EUVD | Every 6 hours | European exploited CVE feed |
| NVD recent CVEs | Every 2 hours | HIGH/CRITICAL CVEs from NVD |
| Vendor advisories | 1 hour after CISA sync | OSV, Red Hat, MSRC, Debian |
| NVD CPE dictionary | Weekly (Sundays 04:00 UTC) | Product-to-CPE mapping data |
| CVSS re-enrichment | Every 4 hours | Upgrades fallback CVSS to NVD |
| KB sync | Every 12 hours | SentriKat knowledge base CPE mappings |

If the CISA KEV sync fails, automatic retries use exponential backoff: 15 min, 30 min, 1 hour, 2 hours (max 4 retries).

**Check sync status:** Settings > Sync Settings, or the Sync History page. Trigger manual sync from the UI or `POST /api/sync/trigger`.

### Managing Users and Organizations

- **Users:** Settings > User Management. Roles: `super_admin`, `org_admin`, `manager`, `user`.
- **Organizations:** Settings > Organizations. Each org has its own products, agents, alerts, and SMTP.
- Users can belong to multiple organizations with different roles per org.

### Reviewing Agent Status

View at **Agents > Agent Status**. Transitions: **online** -> **offline** (15 min no heartbeat) -> **stale** (14 days). Detection runs every 5 minutes.

---

## 3. Configuration

### Environment Variables (.env)

```bash
cp .env.example .env
python3 -c "import secrets; print(secrets.token_hex(32))"    # Generate SECRET_KEY
python3 -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"  # Generate ENCRYPTION_KEY
```

**Required:** `SECRET_KEY`, `ENCRYPTION_KEY` (auto-generated if unset), `DB_PASSWORD` (must match `DATABASE_URL`).

**Production:** `SERVER_NAME`, `SENTRIKAT_URL`, `SENTRIKAT_ENV=production`, `SESSION_COOKIE_SECURE=true`.

### Proxy Configuration

Set in `.env` for corporate networks:
```ini
HTTP_PROXY=http://proxy.corp.com:3128
HTTPS_PROXY=http://proxy.corp.com:3128
NO_PROXY=localhost,127.0.0.1,db,.yourcompany.com
```

For SSL-inspecting proxies, set `VERIFY_SSL=false` or add your corporate CA to `certs/`:
```bash
cp your-corporate-ca.crt certs/
docker compose restart sentrikat
```
The entrypoint script installs all `.crt` and `.pem` files from `certs/` into the system trust store.

### SSL/TLS Setup

1. Place certificate files in a directory (e.g., `/etc/ssl/sentrikat/`).
2. Update `.env`:
```ini
NGINX_TEMPLATE=nginx-ssl.conf.template
SSL_CERT_PATH=/etc/ssl/sentrikat
SSL_CERT_FILE=fullchain.pem
SSL_KEY_FILE=privkey.pem
SESSION_COOKIE_SECURE=true
FORCE_HTTPS=true
SENTRIKAT_URL=https://sentrikat.yourcompany.com
```
3. Restart: `docker compose up -d`

The SSL template enforces TLS 1.2+, modern cipher suites, HSTS, OCSP stapling, and security headers.

### LDAP/SAML SSO Configuration

**LDAP** is configured via the web UI at **Settings > LDAP / Active Directory**. Key settings:
- LDAP server, port, Base DN, Bind DN, Bind password
- Search filter (default: `(sAMAccountName={username})`)
- Username/email attribute mappings
- TLS toggle

Scheduled LDAP sync can be enabled with env vars:
```ini
LDAP_SYNC_ENABLED=true
LDAP_SYNC_INTERVAL_HOURS=24
```

**SAML 2.0 SSO** is configured at **Settings > SAML SSO**. SentriKat acts as the Service Provider (SP). Supply your IdP metadata (XML or URL) from Okta, Azure AD, ADFS, etc. Configure:
- SP entity ID, ACS URL, SLS URL
- Default organization for new SAML users
- Attribute-to-user-field mappings

### Email/SMTP Setup

Configure at **Settings > Email & Alerts** (global) or per-organization. Env var fallbacks: `SMTP_HOST`, `SMTP_PORT` (587), `SMTP_USERNAME`, `SMTP_PASSWORD`, `SMTP_USE_TLS` (true), `SMTP_FROM_EMAIL`, `SMTP_FROM_NAME`. Web UI settings take precedence.

### Timezone and Sync Schedule

Sync times use UTC. Set `SYNC_HOUR` and `SYNC_MINUTE` in `.env` (default: 02:00). Critical CVE reminder time is set in the web UI.

---

## 4. Agent Management

### Agent Deployment

Generate an API key at **Agents > API Keys**. Agent scripts are in the `agents/` directory.

**Linux:**
```bash
# Install as systemd service (runs every 4 hours, heartbeat every 5 minutes)
sudo ./sentrikat-agent-linux.sh --install \
  --server-url "https://sentrikat.yourcompany.com" \
  --api-key "sk_agent_xxxxxxxxxxxx"
```
Config: `/etc/sentrikat/agent.conf` | Log: `/var/log/sentrikat-agent.log`

**Windows (PowerShell 5.1+):**
```powershell
# Install as scheduled task
.\sentrikat-agent-windows.ps1 -Install `
  -ServerUrl "https://sentrikat.yourcompany.com" `
  -ApiKey "sk_agent_xxxxxxxxxxxx"

# Or install as Windows Service
.\sentrikat-agent-windows.ps1 -InstallService `
  -ServerUrl "https://sentrikat.yourcompany.com" `
  -ApiKey "sk_agent_xxxxxxxxxxxx"
```
Config: `%ProgramData%\SentriKat\config.json`

**macOS:**
```bash
sudo ./sentrikat-agent-macos.sh --install \
  --server-url "https://sentrikat.yourcompany.com" \
  --api-key "sk_agent_xxxxxxxxxxxx"
```

**Agent authentication:** Uses `X-Agent-Key` header. Rate limits: 60 inventory reports/min, 120 heartbeats/min per API key.

### Agent Updates (Push Updates)

SentriKat supports push-updating agents remotely. Mark assets for update in the web UI or via API; the agent picks up the pending update on its next heartbeat and self-updates.

### Agent Troubleshooting

- **Not reporting:** Verify server URL and API key. Check `/var/log/sentrikat-agent.log` (Linux) or Event Viewer (Windows).
- **Showing offline:** Check firewall rules for HTTPS. Heartbeat interval is 5 min; offline after 15 min.
- **Inventory backlog:** Check worker pool at Settings > Health Checks. Increase `WORKER_POOL_SIZE`.
- **Uninstall:** Linux: `--uninstall` flag. Windows: `-Uninstall` parameter.

### API Key Management

Create at **Agents > API Keys** (scoped per org). Keys support auto-approve for agent-discovered products. Rotate by creating a new key, deploying to agents, then revoking the old one.

---

## 5. Backup & Restore

### Database Backup

**Using the included script:**
```bash
./scripts/backup_database.sh                     # Default: ./backups/
./scripts/backup_database.sh /mnt/backups        # Custom location
```
The script auto-compresses with gzip and cleans up backups older than 7 days.

**Manual Docker backup:**
```bash
docker compose exec -T db pg_dump -U sentrikat sentrikat > sentrikat_backup_$(date +%Y%m%d).sql
gzip sentrikat_backup_*.sql
```

### Volume Backup

```bash
# Application data volume (encryption keys, uploads, branding)
docker run --rm -v sentrikat_sentrikat_data:/data -v $(pwd):/backup \
  alpine tar czf /backup/sentrikat_data_$(date +%Y%m%d).tar.gz -C /data .
```

If using `STORAGE_ROOT`, back up that directory instead: `tar czf sentrikat_storage.tar.gz -C /data/sentrikat .`

### Restore Procedures

**Database restore:**
```bash
# Stop the application first to prevent writes
docker compose stop sentrikat
# Restore
gunzip < sentrikat_backup_20260101.sql.gz | \
  docker compose exec -T db psql -U sentrikat sentrikat
# Restart
docker compose start sentrikat
```

**Critical:** The `ENCRYPTION_KEY` must match the key used when the backup was created. If lost, encrypted settings (SMTP passwords, LDAP bind passwords) must be re-entered. The key is persisted at `${DATA_DIR}/.encryption_key`.

### Scheduled Backup Recommendations

Add to crontab on the Docker host:
```cron
# Daily database backup at 4 AM
0 4 * * * cd /opt/sentrikat && ./scripts/backup_database.sh /mnt/backups/sentrikat
```

---

## 6. Maintenance

### Log Management

**Log files** (default directory: `/var/log/sentrikat`, configurable via `LOG_DIR`):

| File | Content | Rotation |
|------|---------|----------|
| `application.log` | General application logs (INFO+) | 10 MB x 10 |
| `error.log` | Errors and critical issues | 10 MB x 10 |
| `access.log` | HTTP request logs | 20 MB x 10 |
| `security.log` | Auth and permission events | 10 MB x 20 |
| `audit.log` | Data modification audit trail (JSON) | 20 MB x 50 |
| `ldap.log` | LDAP operations | 10 MB x 10 |
| `performance.log` | Slow query/endpoint profiling (JSON) | 20 MB x 10 |

All logs use `RotatingFileHandler` with automatic rotation. Console output goes to Docker logs (`docker compose logs`).

**View logs in Docker:**
```bash
docker compose logs -f sentrikat          # Follow app logs
docker compose exec sentrikat tail -100 /var/log/sentrikat/error.log
docker compose exec sentrikat tail -100 /var/log/sentrikat/security.log
```

### Database Maintenance

PostgreSQL auto-vacuums by default. For large installations:
```bash
# Full vacuum (reclaims disk, requires exclusive lock -- schedule during downtime)
docker compose exec db vacuumdb -U sentrikat -d sentrikat --full --analyze

# Regular vacuum + analyze (online, no lock)
docker compose exec db vacuumdb -U sentrikat -d sentrikat --analyze
```

### Data Retention and Cleanup

Automated data retention runs daily at 03:00 UTC. Configure in **Settings > Administration**:
- `sync_history_retention_days` (default: 90)
- `audit_log_retention_days` (default: 365)

Maintenance tasks (run via Settings > Maintenance or the scheduler):
- Remove stale product installations (not reported for 30+ days)
- Mark assets stale after 14 days, remove after 90 days
- Clean orphaned agent-created products
- Auto-disable products not reported for 90+ days
- Auto-acknowledge CVEs for uninstalled or upgraded software
- Clean processed import queue items after 30 days

### Updating SentriKat

**Using the update script (recommended):**
```bash
./scripts/update.sh              # Update to latest version
./scripts/update.sh 1.0.3        # Update to specific version
./scripts/update.sh --check      # Check for updates only
```

The script auto-detects deployment type (Docker image, Docker build, or standalone), creates a pre-update backup, and handles the upgrade.

**Manual Docker update (build from source):**
```bash
git pull origin main
docker compose build
docker compose up -d
```

**Post-update:** Clear browser cache with Ctrl+Shift+R. Verify at Settings > License (shows version).

---

## 7. Performance Tuning

### Gunicorn Worker Configuration

Set in `.env`. Defaults auto-detect CPU count.

```ini
GUNICORN_WORKERS=8       # Default: min(CPU*2+1, 16)
GUNICORN_THREADS=4       # Threads per worker (default: 4)
GUNICORN_TIMEOUT=120     # Request timeout seconds
```

Workers auto-recycle after 2000 requests (with jitter) to prevent memory leaks.

### Database Connection Pooling

```ini
DB_POOL_SIZE=10          # Base connections per worker (default: 10)
DB_POOL_MAX_OVERFLOW=20  # Burst connections per worker (default: 20)
DB_POOL_TIMEOUT=30       # Seconds to wait for connection (default: 30)
DB_POOL_RECYCLE=1800     # Recycle connections every 30 min (default: 1800)
DB_STATEMENT_TIMEOUT=60000  # Max query time in ms (default: 60000)
```

**PostgreSQL tuning** (set in `.env`, applied to the `db` container):
```ini
PG_MAX_CONNECTIONS=300   # Must be >= WORKERS * (POOL_SIZE + MAX_OVERFLOW) + 10
PG_SHARED_BUFFERS=256MB  # 25% of total RAM, max 8 GB
PG_EFFECTIVE_CACHE=768MB # 75% of total RAM
PG_WORK_MEM=4MB          # Per sort/hash operation
```

### Background Worker Pool

Controls concurrent inventory job processing:
```ini
WORKER_POOL_SIZE=4       # Parallel job threads (default: 4)
```

### Recommended Hardware

| Deployment | Agents | CPU | RAM | Disk | Workers | Pool Size |
|------------|--------|-----|-----|------|---------|-----------|
| Small | < 100 | 2 cores | 4 GB | 20 GB | 4 | 2 |
| Medium | 100-1K | 4 cores | 8 GB | 50 GB | 8 | 4 |
| Large | 1K-5K | 8 cores | 16 GB | 100 GB | 12 | 8 |
| Enterprise | 5K-10K+ | 16 cores | 32 GB | 200 GB | 16 | 16 |

Rule of thumb: 1 CPU core per 2 Gunicorn workers, 256 MB RAM per worker.

---

## 8. Troubleshooting

### Common Issues

**Application won't start:**
- Check `SECRET_KEY` is set in `.env` (production mode requires it).
- Check `DB_PASSWORD` matches the password in `DATABASE_URL`.
- Run `docker compose logs sentrikat` for error details.

**"Setup wizard" keeps appearing:**
- At least one organization and one user must exist. The setup endpoint is at `/setup`.

**502 Bad Gateway from nginx:**
- The `sentrikat` container is still starting (allow 60s) or has crashed.
- Check: `docker compose ps` and `docker compose logs sentrikat`.

**Sync failures (CISA/NVD):**
- Check internet connectivity from the container: `docker compose exec sentrikat curl -I https://www.cisa.gov`
- If behind a proxy, verify `HTTP_PROXY`/`HTTPS_PROXY` in `.env`.
- For SSL inspection proxies, add your CA cert to `certs/` and restart.
- NVD API key recommended for 10x higher rate limit. Set at Settings > Sync Settings or `NVD_API_KEY` in `.env`.

**Slow performance / inventory backlog:**
- Check worker pool status at Settings > Health Checks.
- Increase `WORKER_POOL_SIZE` (default: 4) for more concurrent processing.
- Increase `GUNICORN_WORKERS` if the web UI feels slow.
- Check `performance.log` for slow endpoints.

### Checking Logs

```bash
docker compose exec sentrikat tail -50 /var/log/sentrikat/error.log      # Errors
docker compose exec sentrikat tail -50 /var/log/sentrikat/security.log   # Auth events
docker compose exec sentrikat tail -20 /var/log/sentrikat/audit.log      # Audit trail (JSON)
docker compose logs db --tail=50                                          # Database issues
```

### Agent Connectivity Issues

1. Verify agent can reach the server: `curl -k https://sentrikat.yourcompany.com/api/health`
2. Verify API key is valid and not revoked.
3. Check agent log: `/var/log/sentrikat-agent.log` (Linux), Event Viewer (Windows).
4. Check nginx access log: `docker compose logs nginx | grep agent`
5. If behind a proxy, ensure agents can reach the SentriKat URL directly or through the proxy.

### Database Issues

**Connection pool exhaustion** ("QueuePool limit" errors): increase `DB_POOL_SIZE`, `DB_POOL_MAX_OVERFLOW`, and `PG_MAX_CONNECTIONS`. Check active connections:
```bash
docker compose exec db psql -U sentrikat -c "SELECT count(*) FROM pg_stat_activity;"
```

**Stuck jobs:** Auto-recovered every 10 minutes (up to 5 retries). Check at Settings > Health Checks.

**Database size:** `docker compose exec db psql -U sentrikat -c "SELECT pg_size_pretty(pg_database_size('sentrikat'));"`
Run maintenance cleanup (Settings > Maintenance) to remove stale data.

---

## 9. Security Hardening

### SSL Configuration

Use `nginx-ssl.conf.template` in production. The template enforces:
- TLS 1.2 and 1.3 only
- Modern ECDHE cipher suites
- HSTS with `max-age=31536000` and `includeSubDomains`
- OCSP stapling
- Security headers: `X-Frame-Options`, `X-Content-Type-Options`, `X-XSS-Protection`, `Referrer-Policy`

### Session Security

Set `SESSION_COOKIE_SECURE=true` and `FORCE_HTTPS=true` in `.env` for production. Hardcoded defaults: `HTTPONLY=True`, `SAMESITE=Lax`, session lifetime 4 hours.

### Rate Limiting

**Application level** (Flask-Limiter): 1000 requests/day, 200 requests/hour per IP (default).

**Nginx level**: API endpoints limited to 10 requests/second per IP with burst of 20. Connection limit: 50 concurrent per IP.

**Agent API**: 60 inventory reports/minute, 120 heartbeats/minute per API key.

### Network Isolation

In Docker, only the `nginx` container exposes ports externally. The `sentrikat` app and `db` containers communicate over the internal Docker network. PostgreSQL is never exposed to the host.

For additional isolation, place SentriKat on a management VLAN and restrict agent traffic to HTTPS (port 443) only.

### API Key Rotation

1. Create a new agent API key in the web UI.
2. Deploy the new key to agents (update config files or push via management tools).
3. Verify agents are reporting with the new key (check agent status).
4. Revoke the old key.

Sensitive settings (LDAP bind password, SMTP password, webhook tokens) are encrypted at rest using the `ENCRYPTION_KEY`. If you rotate the encryption key, re-enter all encrypted settings.
