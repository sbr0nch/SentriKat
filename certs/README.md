# Custom CA Certificates

Place your company's root and intermediate CA certificates in this directory.

## Supported formats
- `.crt` or `.pem` files (PEM format, Base64 encoded)
- Each certificate should be a separate file

## Example
```
certs/
  company-root-ca.crt
  company-intermediate-ca.crt
```

## How it works
When the SentriKat container starts, any `.crt` or `.pem` files in this directory
will be automatically added to the system's trusted CA certificate store.

This allows SentriKat to trust:
- Webhook endpoints using certificates signed by your company CA
- Internal APIs with self-signed or company-signed certificates
- Any other HTTPS endpoints that use your company's PKI

## After adding certificates
Restart the SentriKat container:
```bash
docker compose restart sentrikat
```
