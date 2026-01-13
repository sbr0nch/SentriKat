<h1 align="center">SentriKat</h1>

<p align="center">
  <strong>Enterprise Vulnerability Management Platform</strong>
</p>

<p align="center">
  <img src="https://img.shields.io/badge/version-1.0.0-blue.svg" alt="Version"/>
  <img src="https://img.shields.io/badge/python-3.11+-green.svg" alt="Python"/>
  <img src="https://img.shields.io/badge/license-Commercial-red.svg" alt="License"/>
</p>

---

## Overview

**SentriKat** is an enterprise-grade vulnerability management platform that automatically tracks and filters the CISA Known Exploited Vulnerabilities (KEV) catalog against your organization's software inventory.

### Key Features

- **CISA KEV Integration** - Automatic daily sync of Known Exploited Vulnerabilities
- **NVD CPE Search** - Real-time search of 800,000+ products from NIST NVD
- **Smart Matching** - CVE matching via CPE identifiers and keywords
- **Multi-Tenant** - Separate organizations with isolated data
- **LDAP/AD Integration** - Enterprise authentication support
- **Email Alerts** - Configurable notifications for critical vulnerabilities

---

## Quick Start

```bash
# Clone repository
git clone https://github.com/sbr0nch/SentriKat.git
cd SentriKat

# Create environment file
cp .env.example .env

# Generate security keys
python3 -c "import secrets; print(f'SECRET_KEY={secrets.token_hex(32)}')" >> .env
python3 -c "from cryptography.fernet import Fernet; print(f'ENCRYPTION_KEY={Fernet.generate_key().decode()}')" >> .env

# Start with Docker
docker-compose up -d

# Access at http://localhost:5000
```

---

## Requirements

- **Docker** 20.10+ with Docker Compose
- **Memory**: 1GB minimum, 2GB recommended
- **Disk**: 500MB for application

---

## Documentation

Full documentation available at: **[docs.sentrikat.com](https://docs.sentrikat.com)** *(Coming Soon)*

---

## License

SentriKat is **commercial software**. See [LICENSE.md](LICENSE.md) for terms.

For licensing inquiries: **[sentrikat.com](https://sentrikat.com)** *(Coming Soon)*

---

<p align="center">
  <sub>© 2024-2026 Denis Sota. All Rights Reserved.</sub>
</p>
