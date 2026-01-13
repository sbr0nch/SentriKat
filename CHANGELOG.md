# Changelog

All notable changes to SentriKat will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [1.0.0-alpha.1] - 2026-01-13

### Added
- CISA KEV (Known Exploited Vulnerabilities) automatic daily sync
- NVD CPE API integration for real-time product search (800,000+ products)
- Multi-tenant organization support with isolated data
- LDAP/Active Directory authentication integration
- Email alerts for critical vulnerabilities
- PDF report generation
- Health check and version API endpoints
- Database backup script
- Enterprise configuration pattern (Database > Environment > Default)

### Security
- Encrypted storage for sensitive credentials (LDAP passwords, API keys)
- Session management with secure cookie handling
- CSRF protection via Flask-Talisman

---

## Version Naming

| Stage | Example | Description |
|-------|---------|-------------|
| Alpha | 1.0.0-alpha.1 | Early testing, may have bugs |
| Beta | 1.0.0-beta.1 | Feature complete, testing phase |
| RC | 1.0.0-rc.1 | Release candidate, final testing |
| Release | 1.0.0 | Stable production release |

---

[Unreleased]: https://github.com/sbr0nch/SentriKat/compare/v1.0.0-alpha.1...HEAD
[1.0.0-alpha.1]: https://github.com/sbr0nch/SentriKat/releases/tag/v1.0.0-alpha.1
