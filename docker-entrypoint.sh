#!/bin/bash
set -e

# ── STORAGE_ROOT: derive LOG_DIR, DATA_DIR, BACKUP_DIR if not set ──
# Allows operators to point all heavy data at a single mount (e.g. /data)
if [ -n "$STORAGE_ROOT" ]; then
    export LOG_DIR="${LOG_DIR:-${STORAGE_ROOT}/logs}"
    export DATA_DIR="${DATA_DIR:-${STORAGE_ROOT}/data}"
    export BACKUP_DIR="${BACKUP_DIR:-${STORAGE_ROOT}/backups}"
    # Ensure directories exist
    mkdir -p "$LOG_DIR" "$DATA_DIR" "$BACKUP_DIR" 2>/dev/null || true
    echo "STORAGE_ROOT=${STORAGE_ROOT} — derived paths:"
    echo "  LOG_DIR=${LOG_DIR}  DATA_DIR=${DATA_DIR}  BACKUP_DIR=${BACKUP_DIR}"
fi

# Install custom CA certificates if present
CUSTOM_CERTS_DIR="/app/custom-certs"

if [ -d "$CUSTOM_CERTS_DIR" ] && [ "$(ls -A $CUSTOM_CERTS_DIR/*.crt 2>/dev/null)" ] || [ "$(ls -A $CUSTOM_CERTS_DIR/*.pem 2>/dev/null)" ]; then
    echo "Installing custom CA certificates..."

    # Copy all .crt and .pem files to the system CA store
    for cert in "$CUSTOM_CERTS_DIR"/*.crt "$CUSTOM_CERTS_DIR"/*.pem; do
        if [ -f "$cert" ]; then
            filename=$(basename "$cert")
            # Ensure .crt extension for update-ca-certificates
            if [[ "$filename" == *.pem ]]; then
                cp "$cert" "/usr/local/share/ca-certificates/${filename%.pem}.crt"
            else
                cp "$cert" "/usr/local/share/ca-certificates/$filename"
            fi
            echo "  Added: $filename"
        fi
    done

    # Update the system CA certificate store
    update-ca-certificates

    # Also update the Python certifi bundle for requests library
    # This ensures Python's requests library trusts the custom CAs
    CERTIFI_BUNDLE=$(python -c "import certifi; print(certifi.where())" 2>/dev/null || echo "")
    if [ -n "$CERTIFI_BUNDLE" ] && [ -f "$CERTIFI_BUNDLE" ]; then
        echo "Updating Python certifi bundle..."
        for cert in "$CUSTOM_CERTS_DIR"/*.crt "$CUSTOM_CERTS_DIR"/*.pem; do
            if [ -f "$cert" ]; then
                cat "$cert" >> "$CERTIFI_BUNDLE"
            fi
        done
    fi

    # Set REQUESTS_CA_BUNDLE to use system CA store
    # This is critical for requests library when proxies are explicitly passed
    export REQUESTS_CA_BUNDLE=/etc/ssl/certs/ca-certificates.crt
    export SSL_CERT_FILE=/etc/ssl/certs/ca-certificates.crt
    echo "Custom CA certificates installed successfully."
    echo "REQUESTS_CA_BUNDLE set to: $REQUESTS_CA_BUNDLE"
else
    echo "No custom CA certificates found in $CUSTOM_CERTS_DIR"
fi

# ── Validate required secrets in production ──
if [ "${FLASK_ENV:-}" = "production" ]; then
    _default_secret="change-this-secret-key-in-production"
    if [ -z "$SECRET_KEY" ] || [ "$SECRET_KEY" = "$_default_secret" ]; then
        echo "FATAL: SECRET_KEY must be set to a unique value in production."
        echo "Generate one with: python -c \"import secrets; print(secrets.token_hex(32))\""
        exit 1
    fi
    # Check DB_PASSWORD: try env var first, then extract from DATABASE_URL
    _db_pass="${DB_PASSWORD:-}"
    if [ -z "$_db_pass" ] && [ -n "$DATABASE_URL" ]; then
        # Extract password from postgresql://user:password@host:port/db
        _db_pass=$(echo "$DATABASE_URL" | sed -n 's|.*://[^:]*:\([^@]*\)@.*|\1|p')
    fi
    if [ -z "$_db_pass" ] || [ "$_db_pass" = "sentrikat" ]; then
        echo "FATAL: DB_PASSWORD must be changed from the default in production."
        echo "Set DB_PASSWORD in your .env file."
        exit 1
    fi
fi

# Auto-generate ENCRYPTION_KEY if not set
# Persists to DATA_DIR/.encryption_key so it survives container rebuilds
ENCRYPTION_KEY_FILE="${DATA_DIR:-/app/data}/.encryption_key"

if [ -z "$ENCRYPTION_KEY" ]; then
    if [ -f "$ENCRYPTION_KEY_FILE" ]; then
        export ENCRYPTION_KEY=$(cat "$ENCRYPTION_KEY_FILE")
        echo "Loaded ENCRYPTION_KEY from $ENCRYPTION_KEY_FILE"
    else
        export ENCRYPTION_KEY=$(python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())")
        echo "$ENCRYPTION_KEY" > "$ENCRYPTION_KEY_FILE"
        chmod 600 "$ENCRYPTION_KEY_FILE"
        echo "Generated new ENCRYPTION_KEY and saved to $ENCRYPTION_KEY_FILE"
        echo "IMPORTANT: Back up this key! Without it, encrypted data (LDAP/SMTP passwords) cannot be recovered."
    fi
fi

# Execute the main command (gunicorn)
exec "$@"
