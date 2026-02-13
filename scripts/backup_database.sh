#!/bin/bash
# =============================================================================
# SentriKat Database Backup Script
# =============================================================================
#
# Usage:
#   ./scripts/backup_database.sh                    # Backup to default location
#   ./scripts/backup_database.sh /path/to/backup    # Backup to custom location
#
# For Docker deployments:
#   docker-compose exec db pg_dump -U sentrikat sentrikat > backup.sql
#
# Restore:
#   cat backup.sql | docker-compose exec -T db psql -U sentrikat sentrikat
# =============================================================================

set -e

# Configuration
# Priority: CLI argument > BACKUP_DIR env var > STORAGE_ROOT/backups > ./backups
if [ -n "$1" ]; then
    BACKUP_DIR="$1"
elif [ -n "$BACKUP_DIR" ]; then
    BACKUP_DIR="$BACKUP_DIR"
elif [ -n "$STORAGE_ROOT" ]; then
    BACKUP_DIR="${STORAGE_ROOT}/backups"
else
    BACKUP_DIR="./backups"
fi
TIMESTAMP=$(date +%Y%m%d_%H%M%S)
BACKUP_FILE="${BACKUP_DIR}/sentrikat_backup_${TIMESTAMP}.sql"

# Database settings (from environment or defaults)
DB_HOST="${DB_HOST:-db}"
DB_PORT="${DB_PORT:-5432}"
DB_NAME="${DB_NAME:-sentrikat}"
DB_USER="${DB_USER:-sentrikat}"

# Colors for output
GREEN='\033[0;32m'
RED='\033[0;31m'
NC='\033[0m' # No Color

echo "=============================================="
echo "SentriKat Database Backup"
echo "=============================================="

# Create backup directory if it doesn't exist
mkdir -p "$BACKUP_DIR"

# Check if running in Docker
if [ -f /.dockerenv ] || [ -n "$DOCKER_CONTAINER" ]; then
    echo "Running inside Docker container..."
    PGPASSWORD="${DB_PASSWORD:-sentrikat}" pg_dump \
        -h "$DB_HOST" \
        -p "$DB_PORT" \
        -U "$DB_USER" \
        "$DB_NAME" > "$BACKUP_FILE"
else
    # Running on host - use docker-compose
    if command -v docker-compose &> /dev/null; then
        echo "Using docker-compose to backup..."
        docker-compose exec -T db pg_dump -U "$DB_USER" "$DB_NAME" > "$BACKUP_FILE"
    elif command -v docker &> /dev/null; then
        echo "Using docker to backup..."
        docker exec sentrikat-db-1 pg_dump -U "$DB_USER" "$DB_NAME" > "$BACKUP_FILE"
    else
        echo -e "${RED}Error: Docker not found. Cannot backup.${NC}"
        exit 1
    fi
fi

# Check if backup was successful
if [ -f "$BACKUP_FILE" ] && [ -s "$BACKUP_FILE" ]; then
    BACKUP_SIZE=$(du -h "$BACKUP_FILE" | cut -f1)
    echo -e "${GREEN}Backup successful!${NC}"
    echo "  File: $BACKUP_FILE"
    echo "  Size: $BACKUP_SIZE"

    # Compress the backup
    if command -v gzip &> /dev/null; then
        gzip "$BACKUP_FILE"
        echo "  Compressed: ${BACKUP_FILE}.gz"
    fi
else
    echo -e "${RED}Backup failed or empty!${NC}"
    exit 1
fi

# Cleanup old backups (keep last 7 days)
echo ""
echo "Cleaning up old backups (keeping last 7 days)..."
find "$BACKUP_DIR" -name "sentrikat_backup_*.sql*" -mtime +7 -delete 2>/dev/null || true

echo ""
echo "=============================================="
echo "Backup complete!"
echo "=============================================="
