#!/bin/bash
# =============================================================================
# SentriKat Automated Backup with Cron
# =============================================================================
#
# Install automated daily backups:
#   crontab -e
#   # Daily at 1:00 AM, keep 30 days, log output
#   0 1 * * * /path/to/SentriKat/scripts/backup_cron.sh >> /var/log/sentrikat/backup.log 2>&1
#
# For Docker deployments, add to host crontab:
#   0 1 * * * cd /path/to/SentriKat && docker compose exec -T sentrikat /app/scripts/backup_cron.sh
#
# Environment variables:
#   BACKUP_DIR          - Backup directory (default: $STORAGE_ROOT/backups or ./backups)
#   BACKUP_RETENTION    - Days to keep backups (default: 30)
#   BACKUP_ENCRYPT      - Encrypt backups with GPG (default: false)
#   BACKUP_GPG_KEY      - GPG key ID for encryption
#   BACKUP_REMOTE       - Upload to S3/GCS (s3://bucket/path or gs://bucket/path)
#   BACKUP_NOTIFY_URL   - Webhook URL for backup status notifications
# =============================================================================

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
TIMESTAMP=$(date +%Y%m%d_%H%M%S)

# Configuration
BACKUP_DIR="${BACKUP_DIR:-${STORAGE_ROOT:-./backups}/backups}"
BACKUP_RETENTION="${BACKUP_RETENTION:-30}"
BACKUP_ENCRYPT="${BACKUP_ENCRYPT:-false}"
BACKUP_GPG_KEY="${BACKUP_GPG_KEY:-}"
BACKUP_REMOTE="${BACKUP_REMOTE:-}"
BACKUP_NOTIFY_URL="${BACKUP_NOTIFY_URL:-}"

DB_HOST="${DB_HOST:-db}"
DB_PORT="${DB_PORT:-5432}"
DB_NAME="${DB_NAME:-sentrikat}"
DB_USER="${DB_USER:-sentrikat}"

BACKUP_FILE="${BACKUP_DIR}/sentrikat_backup_${TIMESTAMP}.sql"
STATUS="success"
ERROR_MSG=""

log() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] $1"
}

notify() {
    local status="$1"
    local message="$2"
    if [ -n "$BACKUP_NOTIFY_URL" ]; then
        curl -s -X POST "$BACKUP_NOTIFY_URL" \
            -H "Content-Type: application/json" \
            -d "{\"text\":\"SentriKat Backup: ${status} - ${message}\"}" \
            --max-time 10 2>/dev/null || true
    fi
}

cleanup() {
    if [ "$STATUS" != "success" ]; then
        notify "FAILED" "$ERROR_MSG"
        log "ERROR: Backup failed - $ERROR_MSG"
        exit 1
    fi
}
trap cleanup EXIT

log "Starting automated backup..."

# Create backup directory
mkdir -p "$BACKUP_DIR"

# Perform database dump
log "Dumping database..."
if [ -f /.dockerenv ] || [ -n "${DOCKER_CONTAINER:-}" ]; then
    PGPASSWORD="${DB_PASSWORD:-sentrikat}" pg_dump \
        -h "$DB_HOST" \
        -p "$DB_PORT" \
        -U "$DB_USER" \
        --format=custom \
        --compress=6 \
        "$DB_NAME" > "${BACKUP_FILE}.dump" 2>/dev/null
    BACKUP_FILE="${BACKUP_FILE}.dump"
else
    if command -v docker compose &> /dev/null; then
        docker compose exec -T db pg_dump -U "$DB_USER" --format=custom --compress=6 "$DB_NAME" > "${BACKUP_FILE}.dump"
        BACKUP_FILE="${BACKUP_FILE}.dump"
    elif command -v docker-compose &> /dev/null; then
        docker-compose exec -T db pg_dump -U "$DB_USER" --format=custom --compress=6 "$DB_NAME" > "${BACKUP_FILE}.dump"
        BACKUP_FILE="${BACKUP_FILE}.dump"
    else
        STATUS="failed"
        ERROR_MSG="Docker not found"
        exit 1
    fi
fi

# Verify backup
if [ ! -f "$BACKUP_FILE" ] || [ ! -s "$BACKUP_FILE" ]; then
    STATUS="failed"
    ERROR_MSG="Backup file is empty or missing"
    exit 1
fi

BACKUP_SIZE=$(du -h "$BACKUP_FILE" | cut -f1)
log "Backup created: $BACKUP_FILE ($BACKUP_SIZE)"

# Optional: Encrypt backup
if [ "$BACKUP_ENCRYPT" = "true" ] && [ -n "$BACKUP_GPG_KEY" ]; then
    log "Encrypting backup..."
    gpg --batch --yes --recipient "$BACKUP_GPG_KEY" --encrypt "$BACKUP_FILE"
    rm -f "$BACKUP_FILE"
    BACKUP_FILE="${BACKUP_FILE}.gpg"
    log "Encrypted: $BACKUP_FILE"
fi

# Optional: Upload to remote storage
if [ -n "$BACKUP_REMOTE" ]; then
    log "Uploading to $BACKUP_REMOTE..."
    if echo "$BACKUP_REMOTE" | grep -q "^s3://"; then
        aws s3 cp "$BACKUP_FILE" "${BACKUP_REMOTE}/$(basename "$BACKUP_FILE")" --quiet
    elif echo "$BACKUP_REMOTE" | grep -q "^gs://"; then
        gsutil cp "$BACKUP_FILE" "${BACKUP_REMOTE}/$(basename "$BACKUP_FILE")"
    fi
    log "Upload complete"
fi

# Cleanup old backups
log "Cleaning up backups older than ${BACKUP_RETENTION} days..."
DELETED=$(find "$BACKUP_DIR" -name "sentrikat_backup_*" -mtime +${BACKUP_RETENTION} -delete -print 2>/dev/null | wc -l)
log "Deleted $DELETED old backup(s)"

# Count remaining backups
REMAINING=$(find "$BACKUP_DIR" -name "sentrikat_backup_*" 2>/dev/null | wc -l)

log "Backup complete. File: $(basename "$BACKUP_FILE"), Size: $BACKUP_SIZE, Retention: ${BACKUP_RETENTION}d, Total backups: $REMAINING"
notify "SUCCESS" "$(basename "$BACKUP_FILE") ($BACKUP_SIZE), $REMAINING total backups"
