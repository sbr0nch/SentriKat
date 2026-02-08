#!/bin/bash
set -e

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

# Auto-generate ENCRYPTION_KEY if not set
# Persists to /app/data/.encryption_key so it survives container rebuilds
ENCRYPTION_KEY_FILE="/app/data/.encryption_key"

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
