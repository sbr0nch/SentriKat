# SentriKat Disaster Recovery Runbook

## Recovery Targets

| Metric | Target | Notes |
|--------|--------|-------|
| **RTO** (Recovery Time Objective) | 1 hour | Time to restore service |
| **RPO** (Recovery Point Objective) | 24 hours | Maximum data loss (last backup) |
| **MTTR** (Mean Time to Repair) | 30 minutes | Average recovery time |

## Backup Strategy

### Automated Backups
```bash
# Install daily automated backups (host crontab)
crontab -e
0 1 * * * cd /opt/sentrikat && ./scripts/backup_cron.sh >> /var/log/sentrikat/backup.log 2>&1
```

### Backup Configuration
| Setting | Default | Recommended |
|---------|---------|-------------|
| `BACKUP_DIR` | `./backups` | `/mnt/backup/sentrikat` (separate volume) |
| `BACKUP_RETENTION` | 30 days | 90 days for compliance |
| `BACKUP_ENCRYPT` | false | true (production) |
| `BACKUP_REMOTE` | none | `s3://your-bucket/sentrikat-backups` |

### Manual Backup
```bash
# Docker deployment
docker compose exec -T db pg_dump -U sentrikat --format=custom --compress=6 sentrikat > backup.dump

# Verify backup integrity
pg_restore --list backup.dump > /dev/null && echo "Backup valid"
```

## Recovery Procedures

### Scenario 1: Application Container Failure

**Symptoms:** 503 errors, health check failures, container restart loops.

**Steps:**
```bash
# 1. Check container status
docker compose ps
docker compose logs --tail=100 sentrikat

# 2. Restart the application
docker compose restart sentrikat

# 3. If restart fails, rebuild
docker compose up -d --build sentrikat

# 4. Verify recovery
curl -f http://localhost/api/health
```

**Estimated recovery:** 2-5 minutes.

### Scenario 2: Database Corruption / Data Loss

**Symptoms:** 500 errors, database connection failures, missing data.

**Steps:**
```bash
# 1. Stop the application
docker compose stop sentrikat

# 2. Find the most recent backup
ls -lt /path/to/backups/sentrikat_backup_*.dump | head -5

# 3. Drop and recreate the database
docker compose exec db psql -U sentrikat -c "DROP DATABASE IF EXISTS sentrikat;"
docker compose exec db psql -U sentrikat -c "CREATE DATABASE sentrikat;"

# 4. Restore from backup
cat backup.dump | docker compose exec -T db pg_restore -U sentrikat -d sentrikat --no-owner --clean

# 5. Restart the application
docker compose up -d sentrikat

# 6. Verify
curl -f http://localhost/api/health
```

**Estimated recovery:** 10-30 minutes (depends on database size).

### Scenario 3: Full Server Loss

**Prerequisites:** Backups stored off-site (S3, GCS, or remote NAS).

**Steps:**
```bash
# 1. Provision new server (same OS, Docker installed)

# 2. Clone the repository
git clone https://github.com/sbr0nch/SentriKat.git /opt/sentrikat
cd /opt/sentrikat

# 3. Restore .env configuration
# Copy .env from secure storage or recreate from .env.example
cp /secure/backup/.env .env

# 4. Start database only
docker compose up -d db
sleep 10  # Wait for PostgreSQL to initialize

# 5. Download and restore backup
aws s3 cp s3://your-bucket/sentrikat-backups/latest.dump ./backup.dump
cat backup.dump | docker compose exec -T db pg_restore -U sentrikat -d sentrikat --no-owner

# 6. Start all services
docker compose up -d

# 7. Verify
curl -f http://localhost/api/health

# 8. Update DNS if server IP changed
```

**Estimated recovery:** 30-60 minutes.

### Scenario 4: Database Migration Failure

**Symptoms:** Application won't start after upgrade, migration errors in logs.

**Steps:**
```bash
# 1. Check the logs for specific error
docker compose logs --tail=50 sentrikat | grep -i "migration\|error\|column"

# 2. If a column already exists error: safe to ignore, restart
docker compose restart sentrikat

# 3. If data corruption: restore from pre-upgrade backup
docker compose stop sentrikat
# Follow Scenario 2 restore steps

# 4. If schema mismatch: connect directly and fix
docker compose exec db psql -U sentrikat -d sentrikat
# Run manual ALTER TABLE commands as needed
```

### Scenario 5: SSL/TLS Certificate Expiry

**Symptoms:** Browser certificate warnings, HTTPS connection failures.

**Steps:**
```bash
# 1. Check certificate expiry
openssl s_client -connect your-domain:443 2>/dev/null | openssl x509 -noout -dates

# 2. Renew certificate (Let's Encrypt)
certbot renew

# 3. Copy new certificates
cp /etc/letsencrypt/live/your-domain/fullchain.pem ./nginx/ssl/
cp /etc/letsencrypt/live/your-domain/privkey.pem ./nginx/ssl/

# 4. Restart nginx
docker compose restart nginx
```

## Verification Checklist

After any recovery, verify:

- [ ] `curl -f http://localhost/api/health` returns 200
- [ ] Login works (admin/your-password)
- [ ] Dashboard shows correct vulnerability counts
- [ ] Agent check-ins are being received
- [ ] Scheduled jobs are running (`docker compose logs sentrikat | grep "scheduler"`)
- [ ] Email alerts are working (Settings > Test Email)
- [ ] Webhook notifications are working (Settings > Test Webhook)

## Contacts

| Role | Contact | Escalation |
|------|---------|------------|
| Primary on-call | (configure) | 15 minutes |
| Secondary | (configure) | 30 minutes |
| Database admin | (configure) | 1 hour |

## Recovery Testing

Test recovery procedures quarterly:

1. **Backup restore test:** Restore latest backup to a staging environment
2. **Failover test:** Simulate container failure, verify auto-restart
3. **Full DR test:** Provision new server, restore from off-site backup
4. **Document results:** Record recovery time and any issues found
