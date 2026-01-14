# Changelog

All notable changes to SentriKat will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- **Discovery Agents** - Lightweight daemon agents for Windows/Linux endpoints
  - Runs as background service (systemd on Linux, NSSM on Windows)
  - Automatic software inventory sync every 6 hours (configurable)
  - Heartbeat every 5 minutes for online status tracking
  - Smart package filtering (only reports important software, skips libraries)
  - One-shot mode available (`--once` / `-RunOnce`)
- **Integration System** - External software inventory integrations
  - Support for PDQ, SCCM, Intune, Lansweeper, CSV, REST API, and Agent types
  - Push and Pull sync models
  - Import queue with approval workflow
  - CPE auto-matching for vulnerability correlation
- **Agent Sync Status Tracking**
  - Last sync status (success/partial/failed) with error details
  - Count of new items queued vs duplicates skipped
  - Displayed in Discovery Agents table
- **Admin Panel Sidebar Navigation** - Reorganized admin panel with sidebar menu
  - Grouped sections: Identity, Organization, Data Sources, System
  - URL hash persistence (tabs survive page refresh)
- **Product Source Tracking** - Track where products came from
  - Sources: Manual, Catalog, Agent, Import
  - Filterable column in products table
- **Software Audit** - Version drift detection across endpoints

### Changed
- Default logo changed from favicon to logo-512.png (higher quality)
- Login page now uses actual logo instead of Bootstrap icon
- Agent scripts converted from one-shot to daemon mode

### Fixed
- Linux agent dpkg parsing bug (was capturing status fields instead of package names)
- Agent report timeout on large inventories (optimized batch processing)
- Organization deletion JSON parsing error
- Admin panel tabs not persisting on refresh
- Agent disappearing when paused (now shows disabled agents)

### Security
- Timing-safe API key comparison using `secrets.compare_digest()`
- Input sanitization for agent-reported data
- Audit logging for integration CRUD operations

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
