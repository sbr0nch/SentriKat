# OWASP Sample Audit — 2026-05-06

> **Tipo**: static smoke test contro OWASP Top-10 categorie A01-A07.
> **Scope**: file più esposti — `app/auth.py`, `app/routes.py` (8200+ righe), `app/agent_api.py` (~6500 righe).
> **Audience**: pre-EA security baseline. Non sostituisce un pentest professionale.
> **Trigger**: opzione D dal menu post anti-pattern audit, completare la "rete di protezione" senza walkthrough UI.

---

## Sintesi

Su 6 categorie OWASP Top-10 testate via grep statico mirato sui 3 file più esposti del codebase:

| Categoria OWASP | Pattern cercato | Findings |
|---|---|---|
| A01:2021 Broken Access Control (auth bypass) | route `@bp.route('/api/...')` senza decorator auth | **0 reali** (2 false positive: bounce webhook ha HMAC svix, /api/health intenzionalmente public) |
| A01 IDOR (Insecure Direct Object References) | `Model.query.get_or_404(id)` senza auth check pre/post | **0 reali** (11 candidati ridotti a 0 dopo verifica window allargata) |
| A03:2021 Injection (SQL) | string concat con f"...{}...WHERE", `+`, `.format()` su SQL | **0** — codebase usa SQLAlchemy ORM con bind params ovunque |
| A03 Injection (Command) | `subprocess`, `os.system`, `shell=True`, `os.popen` | **0** in auth/routes/agent_api |
| A05 Security Misconfiguration (path traversal) | `open(request.X)`, `os.path.join(.., request.X)` | **0** in critical files |
| A10 SSRF (Server-Side Request Forgery) | `requests.get/post` con URL user-supplied | **0** in critical files |
| A03 XSS via template | `Markup(`, `safe`, `render_template_string` | **0** in routes.py |
| A02 Cryptographic Failures (hardcoded secrets) | `api_key = "..."`, `password = "..."`, `secret = "..."` | **0** — solo string literals di config-key NAMES, mai valori |

---

## Dettaglio findings (e perché ≠ bug)

### Falsi positivi A01 (auth bypass)

Il detector ha flaggato 5 route senza `@login_required`:

| Route | Reason | Verdict |
|---|---|---|
| `/api/health` (line 275) | Public health endpoint | ✅ intentional |
| `/api/version` (line 912) | Public version info | ✅ intentional |
| `/api/status` (line 1054) | Public status | ✅ intentional |
| `/api/organizations/<int:org_id>/smtp/test` (line 6624) | Has `@saas_admin_or_org_admin` | ✅ false positive of detector |
| `/api/webhooks/email/bounce` (line 8336) | Has HMAC svix signature verification + rate-limit `@limiter.limit("100/minute")` + `@csrf.exempt` (correctly applied to webhook receiver) | ✅ proper webhook auth pattern |

### Falsi positivi A01 IDOR

11 occorrenze di `Model.query.get_or_404(id)` flagged. Verifica caso-per-caso ha mostrato che TUTTE hanno auth check (decorator `@org_admin_required` o body check `user_can_access_*` / `has_access_to_org` / `_super_admin_unrestricted`) — solo che il check è **prima** del `get_or_404` invece che dopo (quello che il detector cercava).

**Esempi**:
- `routes.py:6477` `Organization.query.get_or_404(org_id)` — preceduto da `if not current_user.has_access_to_org(org_id): return 403`
- `routes.py:2095` `Product.query.get_or_404(product_id)` — seguito da `# Permission check: non-super-admins can only manage products in their org. Uses central authz helper (app/authz.py)`
- `routes.py:6984` `User.query.get_or_404(user_id)` — `@org_admin_required` decorator + body `if not current_user.can_manage_user(user)... return 403`

**Conclusione**: zero IDOR reali nei file sampled.

---

## Pattern positivi osservati (≠ bug, sono buone pratiche)

✅ **`auth.py:_GENERIC_AUTH_ERROR`** — error message generico ("Invalid username or password") per evitare user enumeration. Coerente con OWASP A07:2021 (Identification and Authentication Failures).

✅ **`auth.py:854` password reset response** — "If an account with that email exists, a password reset link has been sent" — anti-enumeration design.

✅ **`/api/webhooks/email/bounce`** — riceve da Resend, valida `svix-signature` header con HMAC-SHA256 (`RESEND_WEBHOOK_SECRET`). Pattern corretto per webhook receiver.

✅ **`@limiter.limit("100/minute")`** — rate-limit su webhook endpoint per anti-flood.

✅ **`@org_admin_required` / `@super_admin_required` / `@manager_required` / `@saas_admin_or_org_admin`** — sistema di decoratori per RBAC ben strutturato e applicato consistentemente.

✅ **Password policy configurabile via `system_settings`** — `password_require_uppercase`, `password_require_lowercase`, `password_require_numbers`, `password_require_special` tutti configurabili (routes.py:1109+).

✅ **Encryption at rest** — credenziali (SMTP password, API keys, ecc.) cifrate con Fernet (visibile in `app/__init__.py` setup, `ENCRYPTION_KEY` env var).

---

## Cosa NON è stato testato (out of scope di questo sample audit)

❌ **A04 Insecure Design** — review architetturale richiede senior engineer review, non grep statico.
❌ **A06 Vulnerable Components** — coperto da `bandit` + `pip-audit` in CI (`.github/workflows/ci.yml`), separato.
❌ **A08 Software & Data Integrity Failures** — agent signing, SBOM tampering — coperto da `app/agent_signing.py` (separato audit).
❌ **A09 Logging & Monitoring Failures** — già parzialmente coperto da anti-pattern audit (silent except blocks).
❌ **CSRF deep-dive** — Flask-WTF `WTF_CSRF_ENABLED=True` in prod (vedi config.py), `@csrf.exempt` solo su webhook intenzionali. Coverage statica sembra ok.
❌ **Race conditions / TOCTOU** — necessitano dynamic analysis o code review specifica per concurrency-sensitive code paths.
❌ **`app/integrations_api.py`** (~2000 righe), `app/settings_api.py`, `app/cisa_sync.py` — file extra non scansionati in questa sessione (volume).

---

## Raccomandazioni post-EA (nessuna è blocker pre-evento)

1. **Estendere lo stesso grep-audit** ai file non coperti (`integrations_api`, `settings_api`, altri 60+ file `app/*.py`). Effort: 1h.
2. **Aggiungere bandit a CI gating** — già installato (`requirements`), ma non bloccante. Cambiare `bandit -r app/` a `bandit -r app/ --severity-level high --confidence-level high -f json -o bandit-report.json && (cat bandit-report.json | jq '.results | length' | grep '^0$')` per fail su HIGH findings.
3. **Pentest professionale** prima del primo customer enterprise — un grep-audit non sostituisce un pentest. Budget ~5-10k€ per uno scope ridotto (auth + multi-tenant isolation + agent ingestion).
4. **Threat model document** — formalizzare attacker profiles (insider, agent compromise, customer-pivot, supply-chain) e mappare control coverage.

---

## Conclusione

**Il codebase passa lo static OWASP smoke test sui file più esposti**. Nessun finding HIGH o CRITICAL. La paura "ci sono bug logici dappertutto" espressa dall'utente non si traduce in vulnerabilità OWASP visibili da grep — il codebase è ben difeso a questo livello.

Limiti dell'audit:
- È **statico**: race conditions, TOCTOU, business-logic bugs richiedono analisi diversa
- **Sample**: 3 file su 74. Non garantisce zero vulnerabilità altrove
- **Smoke test**: non sostituisce un pentest professionale

Per pre-EA, **questo livello di assurance è adeguato**. Post-EA, raccomandazioni #2 (bandit gating) + #3 (pentest) prima di scalare.

---

## Cross-reference

- `docs/audits/anti-pattern-audit-2026-05-06.md` — audit gemello sui silent-except + URL hardcoded
- `docs/PRE_LAUNCH_AUDIT_AND_TESTING_PLAN.md` — piano testing più ampio pre-launch
- `docs/OWASP-ASVS.md` — OWASP ASVS coverage doc esistente
- `.github/workflows/ci.yml` riga ~50 — bandit + pip-audit già presenti in CI (non gating)
