<p align="center">
  <img src="docs/images/logo.png" alt="SentriKat Logo" width="200"/>
</p>

<h1 align="center">SentriKat</h1>

<p align="center">
  <strong>Enterprise Vulnerability Management Platform</strong>
</p>

<p align="center">
  <a href="#features">Features</a> •
  <a href="#quick-start">Quick Start</a> •
  <a href="#documentation">Documentation</a> •
  <a href="#support">Support</a>
</p>

<p align="center">
  <img src="https://img.shields.io/badge/version-1.0.0-blue.svg" alt="Version"/>
  <img src="https://img.shields.io/badge/python-3.11+-green.svg" alt="Python"/>
  <img src="https://img.shields.io/badge/license-Commercial-red.svg" alt="License"/>
</p>

---

## Overview

**SentriKat** is an enterprise-grade vulnerability management platform that automatically tracks and filters the CISA Known Exploited Vulnerabilities (KEV) catalog against your organization's software inventory. It provides real-time alerting, multi-tenant support, and comprehensive reporting capabilities.

### Why SentriKat?

- **Automated Threat Intelligence**: Automatically syncs with CISA KEV feed daily
- **Smart Matching**: Intelligent CVE-to-product matching with custom keywords
- **Multi-Tenant**: Separate organizations with their own products, users, and settings
- **Enterprise Authentication**: LDAP/Active Directory integration
- **Secure by Design**: Encrypted credentials, rate limiting, CSRF protection
- **Actionable Alerts**: Email notifications for critical vulnerabilities

---

## Features

### Core Functionality
- **CISA KEV Integration** - Automatic daily sync of Known Exploited Vulnerabilities
- **Product Inventory** - Manage software/service inventory per organization
- **Intelligent Matching** - CVE matching by vendor, product, version, and keywords
- **Dashboard** - Interactive vulnerability overview with statistics
- **Acknowledgement Workflow** - Track reviewed vulnerabilities

### Enterprise Features
- **Multi-Tenancy** - Multiple organizations with isolated data
- **Role-Based Access Control** - Super Admin, Org Admin, Manager, User roles
- **LDAP/AD Authentication** - Integrate with corporate directories
- **Email Alerts** - Configurable notifications for new vulnerabilities
- **PDF Reports** - Generate vulnerability reports
- **Audit Logging** - Track all user actions

### Security
- **Encrypted Credentials** - LDAP and SMTP passwords encrypted at rest
- **Rate Limiting** - Protection against brute force attacks
- **CSRF Protection** - Cross-site request forgery prevention
- **Secure Sessions** - HttpOnly, SameSite cookies
- **Security Headers** - HSTS, CSP in production

---

## Quick Start

### Docker Deployment (Recommended)

```bash
# Clone repository
git clone https://github.com/your-org/SentriKat.git
cd SentriKat

# Create environment file
cp .env.example .env

# Generate required security keys
python3 -c "import secrets; print(f'SECRET_KEY={secrets.token_hex(32)}')" >> .env
python3 -c "from cryptography.fernet import Fernet; print(f'ENCRYPTION_KEY={Fernet.generate_key().decode()}')" >> .env

# Start SentriKat with PostgreSQL
docker-compose up -d

# Access at http://localhost:5000
```

This starts:
- **PostgreSQL 15** database container
- **SentriKat** application container

**First-time Setup**: Visit http://localhost:5000 and complete the setup wizard.

---

## Documentation

| Document | Description |
|----------|-------------|
| [Installation Guide](docs/INSTALLATION.md) | Complete installation instructions (Linux, Docker, Windows) |
| [Configuration Guide](docs/CONFIGURATION.md) | Environment variables, GUI settings, encryption keys |
| [User Guide](docs/USER_GUIDE.md) | End-user documentation for daily operations |
| [Admin Guide](docs/ADMIN_GUIDE.md) | Technical administration and troubleshooting |

---

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                        SentriKat                            │
├─────────────────────────────────────────────────────────────┤
│  Frontend: Bootstrap 5 + JavaScript                         │
├─────────────────────────────────────────────────────────────┤
│  Backend: Python 3.11 + Flask                               │
│  ├── Authentication (Local + LDAP)                          │
│  ├── REST API                                               │
│  ├── Background Scheduler (APScheduler)                     │
│  └── Email Service                                          │
├─────────────────────────────────────────────────────────────┤
│  Database: PostgreSQL 15                                    │
├─────────────────────────────────────────────────────────────┤
│  External: CISA KEV Feed, LDAP Server, SMTP Server          │
└─────────────────────────────────────────────────────────────┘
```

---

## Requirements

- **Docker**: 20.10+ with Docker Compose (recommended)
- **Python**: 3.11 or higher (for manual installation)
- **Database**: PostgreSQL 15+
- **Memory**: 1GB minimum, 2GB recommended
- **Disk**: 500MB for application + database growth

### Optional
- LDAP/Active Directory server for enterprise authentication
- SMTP server for email notifications
- Reverse proxy (Nginx/Apache) for production

---

## Environment Variables

| Variable | Required | Description |
|----------|----------|-------------|
| `SECRET_KEY` | Yes (production) | Flask session signing key |
| `ENCRYPTION_KEY` | Yes (production) | Fernet key for credential encryption |
| `DATABASE_URL` | No | Database connection string |
| `FLASK_ENV` | No | `production` or `development` |

See [Configuration Guide](docs/CONFIGURATION.md) for complete reference.

---

## Troubleshooting

### Docker Build Fails with Connection Timeout

**Symptom**: `Unable to connect to deb.debian.org` during `docker-compose build`

**Cause**: Corporate firewall blocks direct internet access

**Solution**: Add proxy settings to `.env`:
```bash
HTTP_PROXY=http://your-proxy:3128
HTTPS_PROXY=http://your-proxy:3128
NO_PROXY=localhost,127.0.0.1,db
```

### SSL Certificate Verification Failed

**Symptom**: `SSL: CERTIFICATE_VERIFY_FAILED` during pip install in Docker build

**Cause**: Corporate proxy performs SSL inspection (MITM)

**Solution**: This is handled automatically in the Dockerfile. If issues persist, ensure your proxy settings are in `.env`.

### Cannot Connect to Database

**Symptom**: Application cannot reach PostgreSQL container

**Cause**: Proxy trying to route internal Docker traffic externally

**Solution**: Add `db` to `NO_PROXY` in `.env`:
```bash
NO_PROXY=localhost,127.0.0.1,db
```

### CISA KEV Sync Fails

**Symptom**: Sync fails with connection errors

**Cause**: Cannot reach external CISA website

**Solution**:
1. Configure proxy in Admin Panel > System Settings > Proxy
2. Or set in `.env`: `HTTP_PROXY` and `HTTPS_PROXY`
3. If behind SSL inspection proxy, enable "Skip SSL Verification" in proxy settings

### Fresh Deployment Steps

For a completely fresh deployment:
```bash
# Stop and remove existing containers and volumes
docker-compose down -v

# Remove cached images (optional)
docker system prune -f

# Rebuild and start
docker-compose up -d --build

# Check logs
docker-compose logs -f
```

---

## Support

### Bug Reports & Feature Requests

- **Website**: *Coming Soon*
- **GitHub Issues**: Report bugs and request features

### Commercial Support

For enterprise support, custom development, or licensing inquiries:

- **Website**: *Coming Soon*
- **Email**: *Contact for details*

---

## License

SentriKat is a **commercial product**. See [LICENSE.md](LICENSE.md) for terms.

**Special License**: Free for use by Zertificon Solutions GmbH.

---

## Credits

- **Vulnerability Data**: [CISA Known Exploited Vulnerabilities Catalog](https://www.cisa.gov/known-exploited-vulnerabilities-catalog)
- **Framework**: Flask, SQLAlchemy, Bootstrap
- **Icons**: Bootstrap Icons

---

<p align="center">
  <sub>Built with security in mind</sub>
</p>
