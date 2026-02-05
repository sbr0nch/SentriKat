<h1 align="center">
  <br>
  SentriKat
  <br>
</h1>

<h4 align="center">Enterprise Vulnerability Management for CISA Known Exploited Vulnerabilities</h4>

<p align="center">
  <img src="https://img.shields.io/badge/version-1.0.0-blue.svg" alt="Version"/>
  <img src="https://img.shields.io/badge/python-3.11+-green.svg" alt="Python"/>
  <img src="https://img.shields.io/badge/docker-ready-blue.svg" alt="Docker"/>
  <img src="https://img.shields.io/badge/license-Commercial-red.svg" alt="License"/>
</p>

<p align="center">
  <a href="#key-features">Features</a> •
  <a href="#quick-start">Quick Start</a> •
  <a href="#configuration">Configuration</a> •
  <a href="#agents">Agents</a> •
  <a href="#api">API</a> •
  <a href="#editions">Editions</a>
</p>

---

## Overview

**SentriKat** is an enterprise-grade vulnerability management platform that automatically tracks the [CISA Known Exploited Vulnerabilities (KEV)](https://www.cisa.gov/known-exploited-vulnerabilities-catalog) catalog against your organization's software inventory.

Unlike traditional vulnerability scanners that overwhelm you with thousands of CVEs, SentriKat focuses on **what matters most**: vulnerabilities that are actively being exploited in the wild and require immediate attention.

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                              SentriKat                                       │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                              │
│   CISA KEV Feed ──────┐                                                      │
│                       │     ┌──────────────┐     ┌──────────────────────┐   │
│   NVD Database ───────┼────►│  Matching    │────►│  Priority Dashboard  │   │
│                       │     │  Engine      │     │  & Alerts            │   │
│   Your Inventory ─────┘     └──────────────┘     └──────────────────────┘   │
│        │                                                                     │
│        ├── Push Agents (Windows/Linux)                                       │
│        ├── Integrations (PDQ, SCCM, Intune, Lansweeper)                      │
│        └── Manual Entry / CSV Import                                         │
│                                                                              │
└─────────────────────────────────────────────────────────────────────────────┘
```

---

## Key Features

### Core Vulnerability Management

| Feature | Description |
|---------|-------------|
| **CISA KEV Sync** | Automatic daily sync of Known Exploited Vulnerabilities catalog |
| **NVD Integration** | Real-time search of 800,000+ products with CVSS enrichment |
| **Smart Matching** | Multi-method CVE matching (CPE, vendor+product, keywords) |
| **Priority Matrix** | Intelligent prioritization based on severity, criticality, age, and ransomware risk |
| **Remediation Tracking** | Due date tracking with acknowledgment workflow |

### Inventory Collection

| Method | Description |
|--------|-------------|
| **Push Agents** | Native Windows (PowerShell) and Linux (Bash) agents |
| **Integrations** | PDQ Deploy, SCCM, Microsoft Intune, Lansweeper |
| **REST API** | Generic API for custom integrations |
| **CSV Import** | Bulk import with review queue |

### Enterprise Features (Professional)

| Feature | Description |
|---------|-------------|
| **Multi-Tenant** | Isolated organizations with separate settings |
| **LDAP/AD** | Active Directory integration with group mapping |
| **Email Alerts** | Configurable notifications with time windows |
| **Webhooks** | Slack, Teams, Discord, custom webhooks |
| **Backup/Restore** | Full database backup and restoration |
| **White Label** | Custom branding, remove "Powered by" footer |

---

## Quick Start

### Prerequisites

- **Docker** 20.10+ with Docker Compose
- **Memory**: 1GB minimum, 2GB recommended
- **Disk**: 500MB for application

### Installation

```bash
# 1. Clone the repository
git clone https://github.com/sbr0nch/SentriKat.git
cd SentriKat

# 2. Create environment file
cp .env.example .env

# 3. Generate security keys (REQUIRED)
# Generate SECRET_KEY:
python3 -c "import secrets; print(secrets.token_hex(32))"

# Generate ENCRYPTION_KEY:
python3 -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"

# Generate INSTALLATION_ID (for licensing - keep this forever!):
python3 -c "import uuid; print(f'SK-INST-{uuid.uuid4().hex[:32].upper()}')"

# 4. Edit .env and set:
#    - SECRET_KEY (from step 3)
#    - ENCRYPTION_KEY (from step 3)
#    - SENTRIKAT_INSTALLATION_ID (from step 3 - keep forever!)
#    - DB_PASSWORD (choose a strong password)
#    - DATABASE_URL (update password to match DB_PASSWORD)
#    - SERVER_NAME (your domain)
#    - SENTRIKAT_URL (full URL with https://)

# 5. Start services
docker-compose up -d

# 6. Access the application
# HTTP:  http://localhost
# HTTPS: https://localhost (if SSL configured)
```

### First-Time Setup

1. Navigate to your SentriKat URL
2. Complete the setup wizard:
   - Create admin account
   - Set organization name
   - Configure email settings (optional)
3. Add your first products manually or deploy agents

---

## Configuration

### Environment Variables

| Variable | Required | Description |
|----------|----------|-------------|
| `SECRET_KEY` | **Yes** | Flask session signing key |
| `ENCRYPTION_KEY` | **Yes** | Fernet key for sensitive data encryption |
| `DATABASE_URL` | **Yes** | PostgreSQL connection URL |
| `DB_PASSWORD` | **Yes** | PostgreSQL password |
| `SENTRIKAT_URL` | **Yes** | Public URL (for email links) |
| `SERVER_NAME` | **Yes** | Hostname for nginx |
| `FLASK_ENV` | No | Set to `production` for production mode |
| `SESSION_COOKIE_SECURE` | No | Set to `true` when using HTTPS |
| `FORCE_HTTPS` | No | Set to `true` to force HTTPS redirects |

### SSL/TLS Configuration

```bash
# 1. Place certificates in nginx/ssl/
#    - fullchain.pem (certificate + chain)
#    - privkey.pem (private key)

# 2. Update .env
NGINX_TEMPLATE=nginx-ssl.conf.template
ENABLE_SSL=true
SSL_CERT_FILE=fullchain.pem
SSL_KEY_FILE=privkey.pem
SESSION_COOKIE_SECURE=true
FORCE_HTTPS=true

# 3. Restart nginx
docker-compose restart nginx
```

### Optional Configuration

```bash
# NVD API Key (10x faster product search)
# Get free key: https://nvd.nist.gov/developers/request-an-api-key
NVD_API_KEY=your-api-key

# Sync schedule (default: 2:00 AM UTC)
SYNC_HOUR=2
SYNC_MINUTE=0

# Proxy settings (if behind corporate proxy)
HTTP_PROXY=http://proxy.example.com:8080
HTTPS_PROXY=http://proxy.example.com:8080
```

---

## Agents

SentriKat provides lightweight push agents for automatic software inventory collection.

### Windows Agent

```powershell
# Download and install
Invoke-WebRequest -Uri "https://your-sentrikat/api/agent/download/windows" -OutFile agent.ps1

# Configure
$env:SENTRIKAT_URL = "https://your-sentrikat"
$env:SENTRIKAT_API_KEY = "your-api-key"

# Run (installs as scheduled task)
.\agent.ps1 -Install
```

**Collected Data:**
- Installed programs (32-bit and 64-bit)
- Windows Features and Roles
- Version information

### Linux Agent

```bash
# Download and install
curl -o sentrikat-agent.sh https://your-sentrikat/api/agent/download/linux
chmod +x sentrikat-agent.sh

# Configure and install as systemd service
sudo ./sentrikat-agent.sh --install \
  --url "https://your-sentrikat" \
  --key "your-api-key"
```

**Supported Package Managers:**
- dpkg (Debian/Ubuntu)
- rpm (RHEL/CentOS/Fedora)
- apk (Alpine)
- pacman (Arch)
- snap
- flatpak

### Agent API Keys

Generate agent API keys in the Admin panel:

1. Go to **Administration > Agent API Keys**
2. Click **Create API Key**
3. Set organization scope and permissions
4. Copy the generated key (shown only once)

---

## API

SentriKat provides a comprehensive REST API with 80+ endpoints.

### Authentication

```bash
# Session-based (for web applications)
POST /api/auth/login
Content-Type: application/json
{"username": "admin", "password": "secret"}

# API Key (for agents/integrations)
X-Agent-Key: your-api-key
```

### Key Endpoints

```bash
# Vulnerabilities
GET  /api/vulnerabilities              # List vulnerabilities
GET  /api/vulnerabilities/stats        # Statistics
POST /api/matches/{id}/acknowledge     # Acknowledge CVE

# Products
GET  /api/products                     # List products
POST /api/products                     # Create product
PUT  /api/products/{id}                # Update product

# Agent Inventory
POST /api/agent/inventory              # Report inventory
POST /api/agent/heartbeat              # Agent keepalive

# Sync
POST /api/sync                         # Trigger CISA sync
GET  /api/sync/status                  # Sync status

# Health
GET  /api/health                       # Health check
```

### Example: Report Inventory

```bash
curl -X POST https://your-sentrikat/api/agent/inventory \
  -H "X-Agent-Key: your-api-key" \
  -H "Content-Type: application/json" \
  -d '{
    "hostname": "workstation-001",
    "os": "Windows 10 Enterprise",
    "products": [
      {"vendor": "Microsoft", "product": "Office", "version": "16.0.14326"},
      {"vendor": "Adobe", "product": "Acrobat Reader", "version": "2023.003"}
    ]
  }'
```

---

## Editions

### Demo Edition (Free)

| Limit | Value |
|-------|-------|
| Users | 1 |
| Organizations | 1 |
| Products | 50 |
| Push Agents | 5 |

**Included Features:**
- CISA KEV sync
- NVD product search
- Vulnerability matching
- Basic dashboard
- CSV import
- Push agents (limited)

### Professional Edition

| Limit | Value |
|-------|-------|
| Users | Unlimited |
| Organizations | Unlimited |
| Products | Unlimited |
| Push Agents | Unlimited |

**Additional Features:**
- LDAP/Active Directory integration
- Email alerts with scheduling
- Slack/Teams/Discord webhooks
- Push agents (Windows/Linux)
- Multi-organization support
- Backup and restore
- API access
- White-label branding
- Audit log export
- Priority support

### License Activation

```bash
# Via environment variable
SENTRIKAT_LICENSE=your-license-key

# Or via Admin UI
Administration > License > Activate License
```

Licenses are hardware-locked to your installation ID. Contact sales for licensing.

---

## Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                         Docker Compose                           │
├─────────────────────────────────────────────────────────────────┤
│                                                                  │
│  ┌──────────┐    ┌─────────────────┐    ┌──────────────────┐   │
│  │  nginx   │───►│    SentriKat    │───►│   PostgreSQL     │   │
│  │  :80/443 │    │    (Flask)      │    │   (Database)     │   │
│  └──────────┘    │    :5000        │    │   :5432          │   │
│       │          └─────────────────┘    └──────────────────┘   │
│       │                   │                                      │
│       │                   ├── Sync Worker (CISA KEV)            │
│       │                   ├── Alert Worker (Email/Webhooks)      │
│       │                   └── Maintenance Worker (Cleanup)       │
│       │                                                          │
│       ▼                                                          │
│   Users/Agents                                                   │
│                                                                  │
└─────────────────────────────────────────────────────────────────┘
```

### Technology Stack

| Component | Technology |
|-----------|------------|
| Backend | Python 3.11, Flask 3.x |
| Database | PostgreSQL 15 |
| Web Server | nginx (reverse proxy) |
| Task Queue | APScheduler |
| Frontend | Jinja2, Bootstrap 5 |
| Containerization | Docker, Docker Compose |

---

## Security

### Built-in Security Features

- CSRF protection on all forms
- Session security (Secure, HttpOnly, SameSite cookies)
- Password hashing with bcrypt
- Fernet encryption for sensitive data
- Rate limiting (1000/day, 200/hour default)
- SQL injection prevention (SQLAlchemy ORM)
- XSS protection via Content Security Policy
- HTTPS/TLS enforcement
- Security headers (HSTS, X-Frame-Options, etc.)

### Production Checklist

- [ ] Set strong `SECRET_KEY` and `ENCRYPTION_KEY`
- [ ] Use unique `DB_PASSWORD`
- [ ] Enable HTTPS with valid certificates
- [ ] Set `FLASK_ENV=production`
- [ ] Set `SESSION_COOKIE_SECURE=true`
- [ ] Configure firewall (only expose 80/443)
- [ ] Set up log rotation
- [ ] Configure backup schedule

---

## Troubleshooting

### Common Issues

**Container won't start**
```bash
# Check logs
docker-compose logs sentrikat

# Verify environment
docker-compose config
```

**Database connection failed**
```bash
# Check database container
docker-compose logs db

# Verify DATABASE_URL matches DB_PASSWORD
```

**SSL certificate errors**
```bash
# Verify certificate files exist
ls -la nginx/ssl/

# Check nginx logs
docker-compose logs nginx
```

### Health Check

```bash
curl -k https://localhost/api/health
# Expected: {"status": "healthy", "checks": {"database": "ok"}}
```

---

## Support

- **Documentation**: [docs.sentrikat.com](https://docs.sentrikat.com) *(Coming Soon)*
- **Issues**: GitHub Issues
- **Email**: support@sentrikat.com

---

## License

SentriKat is **commercial software**.

- **Demo Edition**: Free for evaluation and small deployments
- **Professional Edition**: Commercial license required for enterprise features

Purchase licenses at [sentrikat.com/pricing](https://sentrikat.com/pricing)

See [LICENSE.md](LICENSE.md) for full terms.

---

<p align="center">
  <sub>Built with care for security teams everywhere.</sub>
  <br>
  <sub>© 2025-2026 Denis Sota. All Rights Reserved.</sub>
</p>
