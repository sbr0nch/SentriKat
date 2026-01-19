# Nginx Reverse Proxy Configuration

This directory contains nginx configuration templates for the SentriKat reverse proxy.

## Templates

- `nginx.conf.template` - HTTP-only configuration (default)
- `nginx-ssl.conf.template` - HTTPS configuration with SSL/TLS

## Configuration

Set these environment variables in your `.env` file:

```bash
# Your server's hostname
SERVER_NAME=sentrikat.yourcompany.com

# Which template to use
NGINX_TEMPLATE=nginx.conf.template  # or nginx-ssl.conf.template

# Custom ports (optional, defaults to 80/443)
HTTP_PORT=80
HTTPS_PORT=443
```

## Enabling HTTPS

1. Obtain SSL certificates (e.g., from Let's Encrypt)

2. Update your `.env` file:
   ```bash
   NGINX_TEMPLATE=nginx-ssl.conf.template
   SSL_CERT_PATH=/etc/letsencrypt/live/yourdomain.com
   SESSION_COOKIE_SECURE=true
   FORCE_HTTPS=true
   SENTRIKAT_URL=https://yourdomain.com
   ```

3. Restart the containers:
   ```bash
   docker-compose down
   docker-compose up -d
   ```

## SSL Directory

The `ssl/` directory is a placeholder for local SSL certificates. You can either:

- Mount external certificates via `SSL_CERT_PATH` environment variable
- Place `fullchain.pem` and `privkey.pem` directly in the `ssl/` directory

## Let's Encrypt Example

```bash
# Install certbot
apt install certbot

# Get certificate (stop nginx first)
docker-compose down
certbot certonly --standalone -d yourdomain.com

# Update .env
SSL_CERT_PATH=/etc/letsencrypt/live/yourdomain.com
NGINX_TEMPLATE=nginx-ssl.conf.template

# Start with HTTPS
docker-compose up -d
```
