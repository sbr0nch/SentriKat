# Fase 10 — Compliance Reports & SBOM

> Report di compliance verso 6 framework + SBOM (Software Bill of Materials) export/import. Surface principale: `/reports`, `app/compliance_reports.py`, `app/reports_api.py`.

## Aree coperte

| Area | Surface | Description | Env |
|---|---|---|---|
| 10.1 | CISA BOD 22-01 report | Federal civilian KEV remediation requirements report | 🏢☁️ both |
| 10.2 | NIS2 report | EU NIS2 Directive compliance per categoria entità | 🏢☁️ both |
| 10.3 | PCI-DSS v4.0 report | Cardholder data environment scoping + 30-day patch SLA | 🏢☁️ both |
| 10.4 | ISO 27001:2022 report | A.5 + A.8 controls mapping | 🏢☁️ both |
| 10.5 | SOC 2 Type II report | CC7.1 vulnerability management evidence | 🏢☁️ both |
| 10.6 | Executive Summary | High-level dashboard PDF export | 🏢☁️ both |
| 10.7 | SBOM export CycloneDX | `/api/sbom/export?format=cyclonedx-1.4` | 🏢☁️ both |
| 10.8 | SBOM export SPDX | SPDX 2.3 format | 🏢☁️ both |
| 10.9 | SBOM export STIX | STIX 2.1 (cyber threat intel format) | 🏢☁️ both |
| 10.10 | SBOM import | Upload customer's SBOM to populate products | 🏢☁️ both |
| 10.11 | Scheduled reports | Weekly/monthly auto-generated, email delivery | 🏢☁️ both |
| 10.12 | Patch Tuesday digest | Microsoft second-Tuesday CVE roundup email | 🏢☁️ both |
| 10.13 | Report PDF rendering | wkhtmltopdf / weasyprint pipeline | 🏢☁️ both |
| 10.14 | Report data accuracy | Match counts coerenti tra dashboard, /reports, e PDF | 🏢☁️ both |

## 7-dim standard

---

_Sezioni 10.1-10.14 da popolare durante walkthrough live. Status iniziale: ⬜ da iniziare._

## Bug summary

| Bug ID | Severity | Env | Title |
|---|---|---|---|
| _(none yet)_ | | | |

## Cross-ref

- `app/compliance_reports.py` — engine
- `app/reports_api.py` — REST endpoints
- `app/email_service.py:327` — `send_patch_tuesday_digest`
- `scheduler.py` job `patch_tuesday_digest` (second Tuesday auto-trigger)
