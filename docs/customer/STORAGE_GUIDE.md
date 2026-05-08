# Storage Configuration Guide

SentriKat stores several types of persistent data. By default everything lives
inside Docker named volumes, which is fine for small deployments. For production
servers — especially those with a dedicated data drive — you can redirect all
heavy data to a custom location with a single environment variable.

---

## What data does SentriKat store?

| Data type | Default location | Size profile |
|---|---|---|
| **PostgreSQL database** | Docker volume `postgres_data` | Grows with inventory & vulnerabilities |
| **Application logs** (7 rotating files) | `/var/log/sentrikat` inside container | 10–20 MB each, auto-rotated |
| **Uploads** (logos, branding) | `/app/data/uploads` inside container | Small (< 10 MB) |
| **Encryption key** | `/app/data/.encryption_key` | 1 file |
| **Database backups** | `./backups` on host | Grows with database size |

---

## Quick setup — one variable

If your server has a second disk mounted at `/data`:

```bash
# .env
STORAGE_ROOT=/data/sentrikat
```

Create the directory tree and start with the storage override:

```bash
sudo mkdir -p /data/sentrikat/{postgres,data,logs,backups}
sudo chown -R 999:999 /data/sentrikat/postgres   # PostgreSQL UID
sudo chown -R $(id -u):$(id -g) /data/sentrikat/{data,logs,backups}

docker compose -f docker-compose.yml -f docker-compose.storage.yml up -d
```

This gives you:

```
/data/sentrikat/
├── postgres/    ← PostgreSQL database files
├── data/        ← uploads, encryption key
├── logs/        ← application.log, error.log, audit.log, ...
└── backups/     ← database backup .sql.gz files
```

The backup script also picks up `STORAGE_ROOT` automatically:

```bash
./scripts/backup_database.sh          # writes to /data/sentrikat/backups/
```

---

## Fine-grained overrides

Individual path variables take precedence over `STORAGE_ROOT`. For example, to
put only the database on a fast SSD and everything else on a large spinning disk:

```bash
# .env
STORAGE_ROOT=/mnt/hdd/sentrikat       # logs, uploads, backups → HDD
LOG_DIR=/mnt/hdd/sentrikat/logs       # (derived from STORAGE_ROOT anyway)
```

Then in `docker-compose.storage.yml`, override just the Postgres volume to
point at the SSD:

```yaml
services:
  db:
    volumes:
      - /mnt/ssd/sentrikat/postgres:/var/lib/postgresql/data
```

### All available variables

| Variable | Derived from STORAGE_ROOT as | Default (no STORAGE_ROOT) |
|---|---|---|
| `LOG_DIR` | `${STORAGE_ROOT}/logs` | `/var/log/sentrikat` |
| `DATA_DIR` | `${STORAGE_ROOT}/data` | `/app/data` |
| `BACKUP_DIR` | `${STORAGE_ROOT}/backups` | `./backups` |
| PostgreSQL | `${STORAGE_ROOT}/postgres` (via override file) | Docker named volume |

Setting any individual variable explicitly overrides the `STORAGE_ROOT` derivation.

---

## Without STORAGE_ROOT (default)

If you don't set `STORAGE_ROOT`, everything stays as before:

- PostgreSQL → `postgres_data` Docker named volume
- App data → `sentrikat_data` Docker named volume (mounted at `/app/data`)
- Logs → `/var/log/sentrikat` inside the container
- Backups → `./backups` relative to docker-compose directory

No changes are needed if you're happy with Docker named volumes.

---

## Migrating existing data to a new location

If you already have data in Docker named volumes and want to move to a bind mount:

```bash
# 1. Stop SentriKat
docker compose down

# 2. Find where Docker stores the named volume
docker volume inspect sentrikat_postgres_data | grep Mountpoint

# 3. Copy data to new location
sudo cp -a /var/lib/docker/volumes/sentrikat_postgres_data/_data/* /data/sentrikat/postgres/
sudo cp -a /var/lib/docker/volumes/sentrikat_sentrikat_data/_data/* /data/sentrikat/data/

# 4. Set STORAGE_ROOT in .env
echo 'STORAGE_ROOT=/data/sentrikat' >> .env

# 5. Start with storage override
docker compose -f docker-compose.yml -f docker-compose.storage.yml up -d

# 6. Verify everything works, then optionally remove old volumes
docker volume rm sentrikat_postgres_data sentrikat_sentrikat_data
```

---

## Permissions

- **PostgreSQL** runs as UID 999 inside the container. The `postgres/` directory
  must be owned by `999:999`.
- **SentriKat app** runs as a non-root user. The `data/` and `logs/` directories
  should be writable by the container user (or world-writable `chmod 777` for
  simplicity in trusted environments).
