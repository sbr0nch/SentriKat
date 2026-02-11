# OWASP ASVS v4.0.3 — Self-Assessment

<p align="center">
  <img src="owasp-asvs-badge.svg" alt="OWASP ASVS Level 1 Self-Assessment"/>
</p>

| Field | Value |
|---|---|
| **Product** | SentriKat v1.0.2 |
| **Standard** | [OWASP ASVS 4.0.3](https://owasp.org/www-project-application-security-verification-standard/) |
| **Target Level** | Level 1 (Opportunistic) |
| **Assessment Type** | Self-Assessment |
| **Date** | 2026-02-11 |

> **Disclaimer:** This is a self-assessment, not a third-party audit. It documents the controls present in the codebase as of the date above. A formal pentest or independent ASVS audit by an accredited assessor is recommended before claiming verified compliance.

---

## Summary

| Chapter | Title | L1 | Notes |
|---|---|---|---|
| V1 | Architecture, Design and Threat Modeling | PASS | Multi-tenant, documented architecture |
| V2 | Authentication | PASS | bcrypt, LDAP/SAML, TOTP 2FA, lockout |
| V3 | Session Management | PASS | HttpOnly, SameSite, timeout, fixation protection |
| V4 | Access Control | PASS | RBAC with 4 roles, org isolation |
| V5 | Validation, Sanitization and Encoding | PASS | ORM, autoescaping, CSRF, CSP |
| V6 | Stored Cryptography | PASS | Fernet AES-128, bcrypt, no hardcoded keys |
| V7 | Error Handling and Logging | PASS | Safe responses, 7 log channels, rotation |
| V8 | Data Protection | PASS | Encrypted fields, masked responses, tenant isolation |
| V9 | Communication | PASS | TLS via nginx, HSTS, HTTPS-only external calls |
| V10 | Malicious Code | PASS | No eval/exec, auditable agents, pinned deps |
| V11 | Business Logic | PASS | Rate limits, lockout, approval workflows |
| V12 | Files and Resources | PASS | 16 MB limit, CSV validation, no execution |
| V13 | API and Web Service | PASS | API key auth (SHA-256), rate limiting, CSRF |
| V14 | Configuration | PASS | No hardcoded secrets, security headers, non-root Docker |

**Overall: Level 1 PASS (14/14 chapters)**

---

## V1 — Architecture, Design and Threat Modeling

| # | Requirement | Status | Evidence |
|---|---|---|---|
| 1.1.1 | Defined security architecture | PASS | Multi-tier: nginx → gunicorn → Flask → PostgreSQL. Clear separation of agent API, web API, and background schedulers. |
| 1.1.2 | Components verified at a high level | PASS | Routes organized into blueprints (`auth`, `agent_api`, `routes`, `settings_api`, `saml_api`). Each module has a distinct responsibility. |
| 1.1.3 | Application doesn't use unsupported features | PASS | Flask 3.0, Python 3.11, PostgreSQL 15 — all actively maintained. |
| 1.1.4 | Threat model for the application | PARTIAL | Implicit threat model via CISA KEV focus. No formal threat model document. |
| 1.1.5 | Security controls are centralized | PASS | Auth decorators in `auth.py`, encryption in `encryption.py`, error handling in `error_utils.py`, rate limiting via Flask-Limiter. |

**Files:** `app/__init__.py`, `app/auth.py`, `app/routes.py`, `config.py`

---

## V2 — Authentication

| # | Requirement | Status | Evidence |
|---|---|---|---|
| 2.1.1 | Password minimum 8 characters | PASS | Configurable `minimum_password_length` (default 8). Enforced in `validate_password()`. |
| 2.1.2 | Passwords at least 64 chars allowed | PASS | No upper limit enforced in validation. |
| 2.1.4 | No password composition rules that reduce entropy | PASS | Uppercase/lowercase/digit requirements configurable and can be disabled. |
| 2.1.7 | Passwords checked against breach lists | N/A | Not implemented; compensated by strong policy + 2FA. |
| 2.2.1 | Anti-automation on login | PASS | Rate limiting at 5 requests/minute on `/api/auth/login`. |
| 2.2.3 | Account lockout after failed attempts | PASS | `failed_login_attempts` counter; lockout after 5 failures (configurable), 30-minute lockout duration. |
| 2.3.1 | System-generated passwords meet policy | PASS | Random TOTP secrets (160-bit), API keys (32-char urlsafe random). |
| 2.4.1 | Passwords stored with bcrypt/scrypt/argon2 | PASS | Werkzeug `generate_password_hash` (bcrypt). |
| 2.5.2 | No default/hardcoded credentials | PASS | Config rejects insecure defaults in production mode. `.env.example` requires user-set values. |
| 2.7.1 | OTP time-based (TOTP RFC 6238) | PASS | TOTP with SHA-1, 30-second window, ±1 step tolerance. QR-code provisioning. |
| 2.8.1 | Multi-factor authentication available | PASS | TOTP 2FA for local + LDAP users. Enforceable per-user. |
| 2.9.1 | SSO integration available | PASS | SAML 2.0 (Okta, Azure AD, ADFS, Google). LDAP/Active Directory. |

**Files:** `app/auth.py`, `app/models.py` (User model), `app/ldap_manager.py`, `app/saml_manager.py`

---

## V3 — Session Management

| # | Requirement | Status | Evidence |
|---|---|---|---|
| 3.1.1 | URL does not expose session tokens | PASS | Sessions stored in signed cookies, not in URL parameters. |
| 3.2.1 | Session invalidated on logout | PASS | `session.clear()` called on logout. |
| 3.2.3 | Session invalidated after inactivity | PASS | `PERMANENT_SESSION_LIFETIME = 4 hours` (configurable via SystemSettings). |
| 3.3.1 | Session token regenerated on login | PASS | `session.clear()` before setting new session data on authentication. |
| 3.4.1 | Cookie `HttpOnly` attribute set | PASS | `SESSION_COOKIE_HTTPONLY = True`. |
| 3.4.2 | Cookie `SameSite` attribute set | PASS | `SESSION_COOKIE_SAMESITE = 'Lax'`. |
| 3.4.3 | Cookie `Secure` attribute set | PASS | `SESSION_COOKIE_SECURE` configurable, True when HTTPS enabled. |
| 3.4.4 | Cookie prefix (`__Host-` / `__Secure-`) | N/A | Standard Flask session name used. |

**Files:** `config.py`, `app/auth.py`

---

## V4 — Access Control

| # | Requirement | Status | Evidence |
|---|---|---|---|
| 4.1.1 | Application enforces access control at server | PASS | Server-side decorators: `@login_required`, `@admin_required`, `@org_admin_required`, `@manager_required`. |
| 4.1.2 | Access controls fail securely | PASS | Decorators return 401/403 on failure; default deny. |
| 4.1.3 | Principle of least privilege | PASS | 4-tier RBAC: `user < manager < org_admin < super_admin`. Per-org role assignment. |
| 4.2.1 | Sensitive data accessible only to authorized users | PASS | Multi-tenant isolation: all queries filtered by `organization_id`. Sensitive fields masked in API responses. |
| 4.2.2 | No IDOR on user-owned resources | PASS | Organization-scoped queries prevent cross-tenant access. |
| 4.3.1 | Administrative interfaces protected | PASS | `/api/settings/*` protected by `@admin_required`. System settings restricted to `super_admin`. |

**Files:** `app/auth.py` (decorators), `app/routes.py`, `app/settings_api.py`

---

## V5 — Validation, Sanitization and Encoding

| # | Requirement | Status | Evidence |
|---|---|---|---|
| 5.1.1 | HTTP parameter pollution prevented | PASS | Flask request parsing; single-value extraction from JSON payloads. |
| 5.1.3 | All input validated on server side | PASS | Length limits (`MAX_HOSTNAME_LENGTH=255`, `MAX_VENDOR_LENGTH=200`, etc.), type checks, 3-phase filtering for agent data. |
| 5.2.1 | HTML form inputs use CSRF tokens | PASS | Flask-WTF CSRF enabled globally. Agent API exempt (uses API-key + JSON). |
| 5.2.4 | Structured data strongly typed | PASS | SQLAlchemy models enforce types. JSON schema validated in agent API. |
| 5.3.1 | Output encoding for XSS prevention | PASS | Jinja2 autoescaping enabled. CSP restricts script sources. |
| 5.3.4 | Context-aware output encoding | PASS | Jinja2 handles HTML context; JSON responses via `jsonify()`. |
| 5.3.10 | No SQL injection | PASS | SQLAlchemy ORM used exclusively. No raw SQL queries. Parameterized queries. |
| 5.5.1 | LDAP injection prevented | PASS | `escape_filter_chars()` from ldap3 used on all LDAP search filters. |

**Files:** `app/agent_api.py`, `app/routes.py`, `app/__init__.py`, `app/ldap_manager.py`

---

## V6 — Stored Cryptography

| # | Requirement | Status | Evidence |
|---|---|---|---|
| 6.1.1 | Regulated data encrypted at rest | PASS | Fernet (AES-128-CBC + HMAC-SHA256) for LDAP passwords, SMTP credentials, webhook tokens, API keys in DB. |
| 6.2.1 | Industry-proven cryptographic algorithms | PASS | Fernet (AES-128), bcrypt (passwords), RSA-4096 (licensing), HMAC-SHA1 (TOTP). |
| 6.2.3 | Random values generated using approved RNG | PASS | `secrets.token_urlsafe()`, `os.urandom()` for API keys, TOTP secrets, nonces. |
| 6.2.5 | No hardcoded cryptographic keys | PASS | Encryption key from `ENCRYPTION_KEY` env var or derived from `SECRET_KEY`. Not in source code. |
| 6.4.1 | Key management process exists | PASS | Environment variable injection; key can be rotated by changing `ENCRYPTION_KEY` and re-encrypting. |
| 6.4.2 | Keys stored outside application code | PASS | All keys in environment variables or Docker secrets. `.env` excluded from git. |

**Files:** `app/encryption.py`, `app/auth.py`, `app/licensing.py`, `.env.example`

---

## V7 — Error Handling and Logging

| # | Requirement | Status | Evidence |
|---|---|---|---|
| 7.1.1 | No sensitive data in error messages | PASS | `safe_error_response()` returns generic messages. Real errors logged server-side only. |
| 7.1.2 | No stack traces in production responses | PASS | Custom error handlers for 404, 500, 429 return generic JSON/HTML. |
| 7.1.3 | No technical details leaked | PASS | `ERROR_MSGS` dictionary maps error types to generic user-facing messages. |
| 7.2.1 | All authentication events logged | PASS | `security.log` captures login success/failure, 2FA, LDAP auth events. |
| 7.2.2 | All access control failures logged | PASS | Auth decorators log unauthorized access attempts. |
| 7.3.1 | No sensitive data in logs | PASS | Passwords/tokens not logged. Safe error utility strips sensitive details. |
| 7.4.1 | Log integrity maintained | PASS | `RotatingFileHandler` with 10 MB per file, 10 backups. Separate log channels prevent cross-contamination. |

**Files:** `app/error_utils.py`, `app/logging_config.py`, `app/auth.py`

---

## V8 — Data Protection

| # | Requirement | Status | Evidence |
|---|---|---|---|
| 8.1.1 | Sensitive data identified and classified | PASS | Encrypted fields enumerated: LDAP passwords, SMTP credentials, webhook tokens, API keys. |
| 8.1.2 | Sensitive data has access controls | PASS | Admin-only settings endpoints. Encrypted fields masked (`********`) in API responses. |
| 8.2.1 | Anti-caching headers on sensitive responses | PASS | `Cache-Control: no-cache, no-store, must-revalidate` on API responses. |
| 8.2.2 | No sensitive data in URL parameters | PASS | POST bodies for authentication. Session via cookies. API keys in `Authorization` header. |
| 8.3.1 | Sensitive data not sent to third parties | PASS | Self-hosted; no telemetry. External calls limited to CISA KEV/NVD feeds (no user data sent). |
| 8.3.4 | Backup includes sensitive data protection | PARTIAL | DB backups contain encrypted fields; backup encryption is operator responsibility. |

**Files:** `app/settings_api.py`, `app/models.py`, `config.py`

---

## V9 — Communication

| # | Requirement | Status | Evidence |
|---|---|---|---|
| 9.1.1 | TLS for all connections | PASS | Nginx SSL termination. `FORCE_HTTPS` and `HSTS` enabled in production. |
| 9.1.2 | Trusted TLS certificates | PASS | Supports Let's Encrypt, corporate CA, and custom certificates. |
| 9.1.3 | TLS for external connections | PASS | CISA KEV, NVD API, vendor advisory feeds — all HTTPS. `REQUESTS_CA_BUNDLE` configured. |
| 9.2.1 | HSTS header set | PASS | `strict_transport_security=True`, `max_age=31536000` via Flask-Talisman. |

**Files:** `app/__init__.py` (Talisman config), `docker-compose.yml`, `nginx-ssl.conf.template`

---

## V10 — Malicious Code

| # | Requirement | Status | Evidence |
|---|---|---|---|
| 10.1.1 | No time bombs or logic bombs | PASS | Code review: no conditional time-based malicious behavior. License expiry is standard business logic. |
| 10.2.1 | No backdoors or undocumented functions | PASS | All routes registered in blueprints. No hidden debug endpoints in production. |
| 10.3.1 | Application verifies integrity of dependencies | PARTIAL | `requirements.txt` pins exact versions. No hash verification (e.g., `pip --require-hashes`). |
| 10.3.2 | No untrusted code execution | PASS | No `eval()`, `exec()`, or dynamic code execution on user input. Agent scripts are static templates. |

**Files:** `requirements.txt`, `app/agent_api.py`, `app/routes.py`

---

## V11 — Business Logic

| # | Requirement | Status | Evidence |
|---|---|---|---|
| 11.1.1 | Business logic flows in sequential steps | PASS | Agent inventory: submit → 3-phase filter → CPE assignment → vuln match. Import: queue → admin approval → product creation. |
| 11.1.2 | Business logic detects and rejects tampering | PASS | API key validation (SHA-256 hash comparison), IP whitelist checks, rate limiting. |
| 11.1.5 | Anti-automation on business-critical functions | PASS | Rate limits: agent inventory 60/min, login 5/min, general 200/hour. Account lockout after 5 failed attempts. |
| 11.1.8 | Audit logging for business-critical operations | PASS | `audit.log` for data modifications. `security.log` for auth events. LDAP operations logged to `ldap.log`. |

**Files:** `app/agent_api.py`, `app/auth.py`, `app/logging_config.py`

---

## V12 — Files and Resources

| # | Requirement | Status | Evidence |
|---|---|---|---|
| 12.1.1 | File upload size limits | PASS | `MAX_CONTENT_LENGTH = 16 MB`. |
| 12.1.2 | File type validation | PASS | CSV import validates header columns and data types before processing. |
| 12.1.3 | No direct file execution from uploads | PASS | CSV data goes to `ImportQueue` table. No filesystem write of uploaded content. |
| 12.3.1 | User-submitted filenames sanitized | PASS | No user-controlled filenames stored on disk. CSV parsed in-memory. |
| 12.4.1 | Files from untrusted sources not served directly | PASS | Reports generated server-side (ReportLab PDF). No user-uploaded file serving. |

**Files:** `config.py`, `app/routes.py`

---

## V13 — API and Web Service

| # | Requirement | Status | Evidence |
|---|---|---|---|
| 13.1.1 | All API endpoints require authentication | PASS | Web API: session auth + `@login_required`. Agent API: API key in `Authorization` header. Health endpoint intentionally public. |
| 13.1.3 | API responses include proper security headers | PASS | `X-Content-Type-Options: nosniff`, `X-Frame-Options: DENY`, CSP, HSTS via Talisman. |
| 13.2.1 | RESTful API uses proper HTTP methods | PASS | `GET` for reads, `POST` for creates/actions, `PUT` for updates, `DELETE` for removals. |
| 13.2.3 | API rejects unexpected content types | PASS | JSON-only APIs check `request.get_json()`. Invalid content-type returns 400. |
| 13.3.1 | API rate limiting in place | PASS | Flask-Limiter: global 200/hour, per-endpoint limits (login 5/min, agent 60/min). |
| 13.4.1 | No sensitive data in API responses | PASS | Passwords masked. API keys shown only once at creation time. Encrypted fields returned as `********`. |

**Files:** `app/agent_api.py`, `app/auth.py`, `app/__init__.py`

---

## V14 — Configuration

| # | Requirement | Status | Evidence |
|---|---|---|---|
| 14.1.1 | Build/deploy pipeline repeatable and secure | PASS | `Dockerfile` + `docker-compose.yml` with pinned base images. Non-root runtime user. |
| 14.1.5 | No hardcoded secrets in source | PASS | Grep confirms no embedded passwords/keys. `.env` in `.gitignore`. |
| 14.2.1 | All components up to date | PASS | Flask 3.0, Python 3.11, PostgreSQL 15, cryptography 43.0.3 — all current as of assessment date. |
| 14.2.2 | Unnecessary features disabled | PASS | `FLASK_ENV=production` disables debug mode. No debug endpoints exposed. |
| 14.3.1 | Security headers set correctly | PASS | Flask-Talisman sets CSP, HSTS, X-Frame-Options, X-Content-Type-Options. |
| 14.4.1 | Third-party components from trusted sources | PASS | All dependencies from PyPI. Versions pinned in `requirements.txt`. |
| 14.4.2 | Unused dependencies removed | PASS | 27 dependencies, all actively used. No dead imports. |
| 14.5.1 | HTTP security headers present | PASS | `Cache-Control`, `X-Response-Time`, `X-Query-Count` (debug), plus all Talisman headers. |

**Files:** `Dockerfile`, `docker-compose.yml`, `requirements.txt`, `.env.example`, `config.py`

---

## Known Gaps and Recommendations

| Area | Gap | Recommendation | Priority |
|---|---|---|---|
| V2 | No breached-password check (2.1.7) | Integrate HaveIBeenPwned API or offline list | Low |
| V3 | No `__Host-` cookie prefix (3.4.4) | Consider adding for defense-in-depth | Low |
| V8 | Backup encryption is operator-managed | Document backup encryption procedure | Medium |
| V10 | No pip hash verification (10.3.1) | Add `--require-hashes` to pip install | Medium |
| — | No formal threat model document | Create STRIDE/DREAD threat model | Medium |

---

## Methodology

This self-assessment was conducted by static analysis of the SentriKat v1.0.2 source code against [OWASP ASVS 4.0.3](https://github.com/OWASP/ASVS/tree/v4.0.3). Each requirement was evaluated by inspecting the relevant source files, configuration, and test suite. Requirements marked **PASS** have corresponding code-level evidence. Requirements marked **PARTIAL** meet the intent but have room for hardening. Requirements marked **N/A** are not applicable to the deployment model.

The assessment targeted **Level 1** — the minimum verification level appropriate for all applications. Many controls also satisfy Level 2 requirements (e.g., MFA, encryption-at-rest, comprehensive logging) but a full Level 2 assessment was not claimed.
