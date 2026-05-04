# Bozze documentazione per `docs.sentrikat.com`

> Da consegnare al team SentriKat-web. Cablare in `mkdocs.yml` (o equivalent) → nuova sezione **Operations**.
>
> Branch suggerito: `claude/docs-operations-section`.

---

## File 1 — `docs/docs/operations/logging-and-observability.md`

```markdown
# Logging & Observability

SentriKat writes structured logs to `/var/log/sentrikat/` inside the
container. Logs are split per concern so SOC2/SIEM consumers can ingest
the security and audit streams independently from application noise.

## Log files

| File | Level | Content | Retention |
|---|---|---|---|
| `application.log` | INFO+ | App boot, scheduler ticks, Flask request handlers info/warning | 10 MB × 10 backups (~100 MB) |
| `error.log` | ERROR | Uncaught exceptions, sanitized 500 errors, stack traces | 10 MB × 10 backups |
| `access.log` | INFO | HTTP request access (method, path, status, IP, UA) | 20 MB × 10 backups |
| `security.log` | WARNING+ | Auth events, license rejections, permission denials, lockouts | 10 MB × 20 backups (~200 MB) |
| `audit.log` | INFO (JSON) | Privileged CRUD on user/role/setting/integration | 20 MB × 50 backups (~1 GB) |
| `ldap.log` | INFO | LDAP operations (bind, search, sync, auto-provision) | 10 MB × 10 backups |
| `performance.log` | INFO (JSON) | Slow queries (>200ms), slow endpoints | 20 MB × 10 backups |

Rotation is automatic (Python `logging.handlers.RotatingFileHandler`).
Retention can be tuned by editing `app/logging_config.py:setup_logging`.

## Ownership and permissions

All log files are owned by the `sentrikat` user (UID 999) inside the
container. The entrypoint `docker-entrypoint.sh` drops privileges from
root to `sentrikat` via `gosu` *before* starting `gunicorn`, so the
master and all workers create files with the correct ownership and can
write to them.

This is critical: a previous deployment bug ([03.20.1]) left the master
running as root, which created log files mode `0644 root:root`. The
forked workers then dropped to `sentrikat` and silently failed every
write because they had no permission. If you ever see logs only
populated with the boot lines (~6 entries in `application.log`,
everything else 0 bytes), check ownership first:

```bash
docker exec sentrikat ls -la /var/log/sentrikat/
# Expected: every file 'sentrikat sentrikat'
# Wrong:    'root root' → privilege drop didn't happen
```

## Mounting logs to host

By default `/var/log/sentrikat/` is a `tmpfs` (in-memory) under the
read-only rootfs. Logs are lost on container restart. To persist:

### Option A — `STORAGE_ROOT` env var

```yaml
# docker-compose.yml
services:
  sentrikat:
    environment:
      STORAGE_ROOT: /data/sentrikat
    volumes:
      - /host/path/sentrikat-data:/data/sentrikat
```

The entrypoint derives `LOG_DIR=$STORAGE_ROOT/logs`,
`DATA_DIR=$STORAGE_ROOT/data`, `BACKUP_DIR=$STORAGE_ROOT/backups`
automatically. Make sure the host path is owned by UID 999:

```bash
sudo chown -R 999:999 /host/path/sentrikat-data
```

### Option B — explicit `LOG_DIR`

```yaml
environment:
  LOG_DIR: /var/log/sentrikat
volumes:
  - /host/path/sentrikat-logs:/var/log/sentrikat
```

If the host path can't be chowned (NFS readonly, etc.), the entrypoint
falls back to `/app/logs` inside the container — but that defeats the
purpose of mounting. Configure ownership upfront.

## Shipping logs externally

Two patterns supported.

### Syslog forwarding (UDP/TCP)

```yaml
environment:
  RSYSLOG_REMOTE: "syslog.example.com:514"
  RSYSLOG_PROTOCOL: udp  # or tcp
```

A sidecar `syslog-forwarder` reads `/var/log/sentrikat/*.log` and
forwards to the remote endpoint. (Currently a separate container —
documented in `deploy-on-prem.md`.)

### Elasticsearch / Kibana

```yaml
environment:
  ELASTIC_HOST: https://es.example.com:9200
  ELASTIC_INDEX_PREFIX: sentrikat-
```

Filebeat sidecar tails the log files and ships to ES with the configured
index pattern.

## Diagnostics — logs not populating

```bash
# Check ownership
docker exec sentrikat ls -la /var/log/sentrikat/
#   Expected: sentrikat:sentrikat for every file

# Check line counts
docker exec sentrikat sh -c "wc -l /var/log/sentrikat/*.log"
#   Expected after first hour of traffic: access.log >> 100,
#   application.log >> 50, others vary by activity.

# Confirm gunicorn workers are running and re-initialized post_fork
docker logs sentrikat 2>&1 | grep "re-initialized DB pool + logging"
#   Expected: one line per worker (typically 4-16 lines)

# If access.log is 0 but the app responds: workers might still be
# logging only to stderr. Verify alembic logging didn't disable
# our loggers (regression of [03.20.1]):
docker logs sentrikat 2>&1 | grep -i "alembic.runtime.migration" | tail -5
docker exec sentrikat sh -c "tail -5 /var/log/sentrikat/application.log"
```

## See also

- [03.20.1] root cause analysis: `docs/e2e-tests/03-signup-onprem.md` § 03.20
- `gunicorn.conf.py` `post_fork` hook reasoning
- `app/logging_config.py:setup_logging` source
```

---

## File 2 — `docs/docs/operations/container-permissions.md`

```markdown
# Container User & Privilege Model

SentriKat's container intentionally runs the long-lived `gunicorn`
process as a non-root user (`sentrikat`, UID 999). This document
explains why, and what operators need to know when bind-mounting
volumes or troubleshooting permission issues.

## Lifecycle

1. **Container starts as `root`**. Required so the entrypoint can
   `update-ca-certificates` (custom CA installation needs root) and
   `chown` runtime directories.
2. **Entrypoint runs custom-CA install** and validates secrets
   (`SECRET_KEY`, `DB_PASSWORD` in production mode).
3. **Privilege drop via `gosu sentrikat`**: the entrypoint exec's
   `gunicorn` as the `sentrikat` user. From this point on, master
   *and* all workers run as UID 999.
4. **Gunicorn workers fork** from the master. They inherit the
   `sentrikat` UID via fork.

This model prevents two classes of bugs:

- A compromised gunicorn worker has no root privileges to escalate to.
- The "master is root, workers are sentrikat" mismatch (silently
  breaking log file writes — bug [03.20.1]) cannot occur.

## Bind-mount permissions

Any host path mounted into the container must be writable by UID 999
unless the container only needs to read it. Common cases:

| Mount target | Purpose | Required ownership |
|---|---|---|
| `/var/log/sentrikat` | Log files | `999:999`, mode `755` |
| `/app/data` | Uploads, encryption key, backups | `999:999`, mode `755` |
| `/data/...` (when using `STORAGE_ROOT`) | All persistent data | `999:999`, mode `755` |
| `/app/custom-certs` | Custom CA certificates | `0:0` read-only OK (root reads it during entrypoint) |

Set ownership before starting the container:

```bash
sudo mkdir -p /opt/sentrikat/{logs,data,backups}
sudo chown -R 999:999 /opt/sentrikat
sudo chmod -R 755 /opt/sentrikat
```

If the filesystem doesn't allow `chown` (NFS readonly, some bind mounts
on Windows hosts), the entrypoint defensively retries the `chown` on
`$LOG_DIR`. If that also fails the application logs to `/app/logs`
(tmpfs inside container, lost on restart) — log a warning but keep
serving requests.

## Troubleshooting

### Symptom: `Permission denied` writing logs

```bash
docker exec sentrikat ls -la /var/log/sentrikat/
# If files show `root:root`, the gosu privilege drop did not happen.
# Likely cause: a downstream image overrode the entrypoint.
```

Recovery: `chown` in a shell, then restart the container.

### Symptom: container starts but exits immediately

Check entrypoint output:

```bash
docker logs sentrikat
# Look for "FATAL: SECRET_KEY must be set" or similar.
# Production mode requires SECRET_KEY and DB_PASSWORD changed from
# their default values.
```

### Symptom: `gosu: command not found`

Indicates a base image without `gosu`. Should not happen with the
official image (`gosu` is installed in the apt step). Rebuild from a
clean clone of the SentriKat repo.

## See also

- `Dockerfile` (look for `RUN apt-get install ... gosu`).
- `docker-entrypoint.sh` (look for `exec gosu sentrikat "$@"`).
- [Logging & Observability](./logging-and-observability.md) for log
  ownership specifically.
```

---

## File 3 — `docs/docs/operations/external-postgres.md`

```markdown
# Deploying with an External Postgres

SentriKat's docker-compose ships with a colocated `postgres:15-alpine`
container for quick start. Production deployments typically point the
application at a managed Postgres (AWS RDS, Cloud SQL, Azure Database)
or a dedicated VM. This page covers the supported topologies and the
configuration surface.

## Supported topologies

| Topology | DATABASE_URL example |
|---|---|
| Same-host (default) | `postgresql://sentrikat:pwd@db:5432/sentrikat` |
| Same-VPC VM | `postgresql://user:pwd@10.0.1.5:5432/sentrikat` |
| AWS RDS | `postgresql://user:pwd@xx.rds.amazonaws.com:5432/sentrikat?sslmode=require` |
| GCP Cloud SQL (TCP) | `postgresql://user:pwd@1.2.3.4:5432/sentrikat?sslmode=require` |
| GCP Cloud SQL (Unix socket via auth proxy) | `postgresql://user:pwd@/sentrikat?host=/cloudsql/PROJECT:REGION:INSTANCE` |
| Azure Database | `postgresql://user:pwd@xx.postgres.database.azure.com:5432/sentrikat?sslmode=require` |
| PgBouncer in front | Same URL pattern, point at PgBouncer endpoint |

To switch to an external DB, drop the `db` service from your
`docker-compose.yml` and set:

```yaml
environment:
  DATABASE_URL: postgresql://user:pwd@xx.rds.amazonaws.com:5432/sentrikat?sslmode=require
```

## TLS / SSL setup

`sslmode=require` is the minimum for managed clouds. For mutual TLS or
custom CA verification:

```
DATABASE_URL=postgresql://user:pwd@host:5432/db?sslmode=verify-full&sslrootcert=/app/data/ca.pem
```

Mount the CA bundle as a read-only file:

```yaml
volumes:
  - ./certs/rds-ca.pem:/app/data/ca.pem:ro
```

`sslmode` levels:

| Mode | Verifies CA? | Verifies hostname? | Use when |
|---|---|---|---|
| `disable` | no | no | local dev only |
| `require` | no | no | basic encryption |
| `verify-ca` | yes | no | trusted private CA |
| `verify-full` | yes | yes | **production with managed cloud** |

## Connection pool tuning

Default settings in `config.py`:

```python
DB_POOL_SIZE         = 10        # base connections per worker
DB_POOL_MAX_OVERFLOW = 20        # extra above pool_size on burst
DB_POOL_TIMEOUT      = 30        # seconds to wait for free conn
DB_POOL_RECYCLE      = 1800      # seconds before recycling
                                 # (max_conn_age on managed DB)
```

Sizing guidance:

| Fleet size | Workers × Threads | Recommended `DB_POOL_SIZE` | `DB_POOL_MAX_OVERFLOW` |
|---|---|---|---|
| Up to 100 agents | 4 × 4 (16 conc) | 5 | 10 |
| 100-1000 agents | 8 × 4 (32 conc) | 10 (default) | 20 (default) |
| 1000-5000 agents | 12 × 8 (96 conc) | 20 | 30 |
| 5000-10000 agents | 16 × 8 (128 conc) | 30 | 50 |

Total connections to the DB ≈ `(pool_size + max_overflow) × workers`.
Make sure your Postgres `max_connections` is high enough, or place
PgBouncer in transaction-pooling mode in front to multiplex.

## Failover behavior

`pool_pre_ping=True` is enabled, so SQLAlchemy verifies each connection
before checkout. After a managed-DB failover (RDS Multi-AZ takes
30-60 seconds, Cloud SQL HA similar):

1. Connections in use at the moment of failover raise an error to the
   request handler — users see HTTP 503 (or 500 if uncaught).
2. New requests `pre_ping`, find the connection dead, transparently
   reconnect to the new primary.
3. End-to-end recovery typically within 60-90 seconds of failover
   start.

To mask the brief outage from end-users, place PgBouncer in front (it
buffers reconnects and retries). For aggressive resilience, also set
short `pool_recycle` (e.g., 300 seconds) so stale connections are
replaced more frequently.

## Required Postgres version & extensions

- Postgres **13 or newer** (tested on 15-alpine).
- Extensions: none required at runtime. Schema migrations create
  indexes only.
- User: needs `CREATE TABLE` on the target database. Migrations run
  automatically on container start (`flask db upgrade head`).

## Network requirements

- Egress from SentriKat container to DB host on port 5432 (or your
  custom port).
- VPC peering / security group rules / firewall rules as appropriate.
- DNS resolution from inside the container — verify with
  `docker exec sentrikat getent hosts $DB_HOST`.

## Connection resilience for transient errors

What SentriKat handles automatically:

- **Stale connection (idle timeout, killed by DB)**: pre_ping detects,
  reconnects.
- **Master failover (managed cloud HA)**: pre_ping detects, reconnects.
  In-flight requests fail.
- **Brief network blip < 1 sec**: pre_ping retries.

What requires operator intervention:

- **Sustained DB outage > 5 minutes**: SentriKat returns 503 errors.
  The "Background Health Checks" job (configurable interval) detects
  the FAIL state and emits an alert via SMTP/webhook (see [03.18.1]).
  Recovery is automatic when the DB returns.
- **Schema migration mid-failover**: do not deploy a new SentriKat
  release during an active DB failover; let the DB stabilize first.

## Diagnostics

```bash
# Confirm DB connectivity from inside the container
docker exec sentrikat python3 -c "from app import db, create_app; app=create_app(); ctx=app.app_context(); ctx.push(); print(db.engine.execute('SELECT version()').scalar())"

# Check active pool size
docker exec sentrikat python3 -c "from app import db, create_app; app=create_app(); ctx=app.app_context(); ctx.push(); print('size=', db.engine.pool.size(), 'checked_out=', db.engine.pool.checkedout())"
```

## See also

- [03.18.1] Health check notification: how DB-down is surfaced.
- Backup & restore: `./backups.md` (separate page).
- Multi-tenant isolation in SaaS mode: `../saas-guides/multi-tenancy.md`.
```

---

## Da fare (web team)

1. Creare la sezione `docs/docs/operations/` nel repo `sentrikat-web`.
2. Salvare i 3 file MDX/MD sopra (rinominando `.md` → `.mdx` se serve, e adattando il front-matter come da convenzioni di SentriKat-web).
3. Aggiornare `mkdocs.yml` (o `astro.config` se è Starlight) per esporre la nuova sezione "Operations" con 3 voci nel nav: "Logging & Observability", "Container Permissions", "External Postgres".
4. Cross-link dalla pagina Troubleshooting esistente.
5. Effort totale stimato: 1-2h (formattazione + nav + cross-link, contenuto è già stato scritto qui).
