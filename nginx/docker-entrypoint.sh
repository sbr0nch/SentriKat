#!/bin/sh
set -e

# Prepare SSL certificates
mkdir -p /etc/nginx/ssl

# If chain file is provided, concatenate cert + chain into fullchain
if [ -n "$SSL_CHAIN_FILE" ] && [ -f "/ssl-certs/$SSL_CERT_FILE" ] && [ -f "/ssl-certs/$SSL_CHAIN_FILE" ]; then
    echo "Creating fullchain from $SSL_CERT_FILE + $SSL_CHAIN_FILE"
    cat "/ssl-certs/$SSL_CERT_FILE" "/ssl-certs/$SSL_CHAIN_FILE" > /etc/nginx/ssl/fullchain.pem
    export SSL_CERT_FILE="fullchain.pem"
else
    # No chain file, just copy the cert
    if [ -f "/ssl-certs/$SSL_CERT_FILE" ]; then
        cp "/ssl-certs/$SSL_CERT_FILE" /etc/nginx/ssl/
    fi
fi

# Copy the key file
if [ -f "/ssl-certs/$SSL_KEY_FILE" ]; then
    cp "/ssl-certs/$SSL_KEY_FILE" /etc/nginx/ssl/
fi

# Run envsubst on the template and start nginx
# This replaces the default nginx docker-entrypoint behavior for templates
envsubst '${SERVER_NAME} ${SSL_CERT_FILE} ${SSL_KEY_FILE}' < /etc/nginx/templates/default.conf.template > /etc/nginx/nginx.conf

exec nginx -g 'daemon off;'
