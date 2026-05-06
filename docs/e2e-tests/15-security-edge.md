# Fase 15 — Security & Edge Cases

> Test end-to-end di security hardening + edge cases. Surface: tutta l'app, target categorie OWASP A01-A10 + edge cases (DB down, disk full, NVD timeout, Akamai 403, ecc.). **Importante**: questa fase NON sostituisce un pentest professionale (~5-10k€ raccomandato pre-customer-enterprise).

## Aree coperte — OWASP Top 10

### A01 Broken Access Control

| Area | Surface | Description |
|---|---|---|
| 15.1 | RBAC bypass attempts | Manager prova endpoint admin-only → 403 |
| 15.2 | IDOR via URL ID enumeration | User A modifica product di User B con ID guess → 403 / 404 |
| 15.3 | Cross-tenant data leak | Org A super-admin vs Org B (SaaS) — verify isolamento |
| 15.4 | API key scope confusion | Agent API key non può accedere admin endpoints |

### A02 Cryptographic Failures

| Area | Surface | Description |
|---|---|---|
| 15.5 | Fernet encryption at rest | SMTP password, API keys, integration tokens cifrati |
| 15.6 | TLS-only enforcement | HTTP → HTTPS redirect, HSTS header, no mixed content |
| 15.7 | Cookie flags | `Secure`, `HttpOnly`, `SameSite=Lax` su session cookies |
| 15.8 | Password storage | bcrypt with cost ≥ 12 |

### A03 Injection

| Area | Surface | Description |
|---|---|---|
| 15.9 | SQL injection | OWASP smoke test ✅ done (`docs/audits/owasp-sample-audit-2026-05-06.md`) — extend to all routes |
| 15.10 | Command injection | subprocess / os.system audit — 0 occorrenze nei file critici |
| 15.11 | LDAP injection | `(uid=*)*)((|userPassword=*)` payload nei form auth |
| 15.12 | XSS via stored content | Product name `<script>alert(1)</script>` — Jinja2 auto-escape verify |
| 15.13 | SSRF | Webhook URL `http://169.254.169.254/...` (cloud metadata), `http://localhost:5000/admin/...` |
| 15.14 | XXE (XML External Entity) | SAML metadata XML upload con `<!ENTITY ...>` payload |

### A05 Security Misconfiguration

| Area | Surface | Description |
|---|---|---|
| 15.15 | CSP headers | `Content-Security-Policy` enforce, no inline scripts post `[05.9.1]` fix |
| 15.16 | DEBUG mode in prod | `FLASK_ENV=production` enforce, no DEBUG=True |
| 15.17 | Default credentials | First-run wizard force admin password change |

### A07 Auth Failures

| Area | Surface | Description |
|---|---|---|
| 15.18 | User enumeration prevention | Login error generico ("Invalid username or password") |
| 15.19 | Lockout after N attempts | Configurable threshold |
| 15.20 | Password reset token security | Single-use, expires, sufficient entropy |

### A10 SSRF

| Area | Surface | Description |
|---|---|---|
| 15.21 | Webhook outbound URL validation | Block private IP ranges + cloud metadata |
| 15.22 | LDAP server URL allowlist | LDAP test connection senza proxy |
| 15.23 | NVD/CISA URL hardcoded | Verified post B.1 fix — Config.NVD_*_API_URL |

## Aree coperte — Edge cases

| Area | Surface | Description |
|---|---|---|
| 15.30 | DB connection lost during sync | `cisa_sync_job` si recupera, retry exponential backoff |
| 15.31 | NVD API timeout | `nvd_api.py` retry, fallback to MITRE 5.x |
| 15.32 | Akamai 403 on CISA KEV | Nuovo: scoperto 2026-05-06 da Hetzner Nuremberg. sentrikat-web PR #267 mitigato via GitHub mirror |
| 15.33 | Disk full | Container handles graceful + alert |
| 15.34 | Concurrent agent push burst | 100 agent push simultanei — DB pool, scheduler queue |
| 15.35 | Worker crash mid-job | `stuck_job_recovery` scheduler — pickup interrotti |
| 15.36 | Encryption key rotation | Re-encrypt all sensitive fields with new ENCRYPTION_KEY |
| 15.37 | Backup restore con DB schema migration in mezzo | Restore da backup di versione 1.0.0-beta.5 → corrente |
| 15.38 | Race condition: 2 admin modificano stesso product simultaneamente | optimistic lock o last-write-wins documented |
| 15.39 | Long-running sync interrotto da OOM | progress save + resume |
| 15.40 | Agent inviarsi inventory di 10000 prodotti in un payload | rate-limit, batch-split, max payload size |

## 7-dim standard

---

_Sezioni 15.1-15.40 da popolare durante walkthrough. Anti-pattern: smoke test rapido + dynamic analysis + pentest professionale post-launch. Vedi `docs/audits/owasp-sample-audit-2026-05-06.md` per OWASP smoke test già completato (0 reali findings sui file core)._

## Bug summary

| Bug ID | Severity | Env | Title |
|---|---|---|---|
| _(none yet)_ | | | |

## Cross-ref

- `docs/audits/owasp-sample-audit-2026-05-06.md` — OWASP A01-A07 statico (3 file)
- `docs/audits/anti-pattern-audit-2026-05-06.md` + `..-extension..` — silent except + suppression layer
- `docs/OWASP-ASVS.md` — ASVS coverage doc (esistente)
- `bandit-report.json` — Bandit static analysis (CI integrated, non gating)
- `pip-audit` — known-CVE dependency check (CI integrated)
- **PENTEST PROFESSIONALE raccomandato** prima del primo customer enterprise (~5-10k€ scope ridotto: auth + multi-tenant isolation + agent ingestion)
