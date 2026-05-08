# Cross-Repo Contracts — SentriKat ↔ sentrikat-web/license-server

> **Single source of truth** for the API surface between `sbr0nch/sentrikat` (SaaS app + on-prem core) and `sbr0nch/sentrikat-web` (marketing site + license-server + portal admin). When either side modifies one of these endpoints, **the contract here must be updated AND the other team notified**.
>
> Last updated: 2026-05-08
> Auth model: HMAC via `X-Provision-Key` header (32-64 char shared secret in env `SENTRIKAT_PROVISION_KEY`). Same for all 3 contracts below unless noted.

## Table of contents

1. [Tenant Provisioning Spec](#1-tenant-provisioning-spec) — original `SAAS_INTEGRATION_SPEC` content
2. [Hard-Delete Contract](#2-hard-delete-contract) — `POST /api/provision/hard-delete`
3. [Activation Token Contract](#3-activation-token-contract) — welcome-email mono-CTA flow

---

## 1. Tenant Provisioning Spec

> Imported from the legacy `docs/SAAS_INTEGRATION_SPEC.md`. Defines `POST /api/provision`, `/api/provision/upgrade`, `/api/provision/cancel`, `/api/provision/status`, `/api/provision/reset-password`, `/api/provision/tenants`, `/api/provision/plans`.

See [SAAS_INTEGRATION_SPEC.md](./SAAS_INTEGRATION_SPEC.md) for the full original spec (kept verbatim to preserve git history).

**Key points** (as of 2026-05-08):

- `POST /api/provision` creates a tenant in one shot: Organization + admin User + Subscription. Idempotent on `idempotency_key`.
- `POST /api/provision/cancel` flips subscription status (Stripe webhook bookkeeping). It does **NOT** remove the tenant rows — that's the job of `/hard-delete` (contract 2 below).
- `POST /api/provision/reset-password` resets a tenant user's password from license-server side (admin-driven, not user-driven recovery).

---

## 2. Hard-Delete Contract

> **Driver**: 2026-05-07 cross-team session — orphan-zombie users blocking re-signup with `409 email conflict`. License-server `delete_customer` path was calling only `/cancel` which left rows in DB. Hard-delete fills the gap as a **GDPR-style cascade delete**.

### Endpoint

```
POST /api/provision/hard-delete
Auth: X-Provision-Key: <secret>
Content-Type: application/json
```

### Request body

```json
{
  "email": "user@example.com",          // optional — at least one of email/org_id required
  "organization_id": 42,                // optional
  "reason": "gdpr_erasure"              // optional, free-text, max 200 chars; common values:
                                         //   gdpr_erasure | admin_test_reset | abuse | unspecified
}
```

### Response 200

```json
{
  "success": true,
  "deleted": {
    "users": 3,
    "organizations": 1,
    "subscriptions": 1,
    "assets": 12,
    "vulnerability_matches": 287,
    "agent_api_keys": 2
  },
  "reason": "gdpr_erasure"
}
```

### Properties

- **Idempotent** — 200 with all-zero counts when target doesn't exist (NOT 404). License-server can safely retry.
- **Atomic** — single transaction; on any failure, full rollback + 500 + no partial state.
- **Cascade-aware** — explicit pre-delete on 7 FK tables that lack `ondelete='CASCADE'` (`integrations`, `import_queue`, `agent_registrations`, `ldap_*`, `shared_views`) + `user_organizations` (m2m). Then `db.session.delete(org)` cascades the rest.
- **Email-only path** — catches orphan User rows whose primary org has been deleted in a prior call.
- **Auth required** — `X-Provision-Key` header. Rate-limited 10/minute.

### Error responses

| HTTP | Body shape | Meaning |
|---|---|---|
| 400 | `{ "error": "Either email or organization_id is required" }` | Body validation |
| 401 | `{ "error": "Invalid provision key" }` | Auth |
| 500 | `{ "error": "Hard delete failed (atomic rollback)", "detail": "...", "reason": "..." }` | DB/transaction error — full rollback already done |

### License-server integration flow

```
1. Customer clicks "Delete Account" in admin portal (sentrikat-web)
2. license-server.delete_customer():
     a. POST /api/provision/cancel  → subscription status canceled
     b. Stripe API → cancel subscription / refund
     c. POST /api/provision/hard-delete → SaaS cascade delete
3. License-server marks customer record as DELETED in its own DB
```

Behind feature flag `SAAS_HARD_DELETE_ENABLED` (license-server side, PR #279) for staged rollout.

### Verified (smoke test 2026-05-07)

```bash
curl -X POST https://app.sentrikat.com/api/provision/hard-delete \
  -H "X-Provision-Key: $KEY" \
  -d '{"email":"never-existed@test.com","reason":"smoke"}'
# → HTTP 200, counts=0, idempotent OK
```

---

## 3. Activation Token Contract

> **Driver**: 2026-05-07 — new customer onboarding UX. The original "welcome email → Sign In → Forgot Password → email" path was 3 round-trips and had "first action is forgot password" which is terrible first impression. Industry pattern (Linear/Vercel/Notion/Slack): single mono-CTA "Set your password" landing on a token-gated set-password page.

### Endpoint A — extended `/api/provision`

When license-server creates a new tenant, it can request the activation URL be returned in the same response.

```
POST /api/provision
Auth: X-Provision-Key
Content-Type: application/json
```

#### Request body (relevant fields)

```json
{
  "email": "newcust@example.com",
  "company_name": "ACME Inc",
  "plan_name": "professional",
  // ... other existing fields ...

  "include_activation_url": true,             // NEW — opt-in flag
  "activation_expiry_hours": 48               // NEW — optional, default 48, max 168 (7 days)
}
```

#### Response 201 — relevant new fields

```json
{
  "success": true,
  "tenant": {
    // ... existing fields ...
    "activation_url": "https://app.sentrikat.com/reset-password?token=<plaintext-token>",
    "activation_expires_at": "2026-05-09T14:00:00.000000Z",

    // When include_activation_url=true, these become:
    "temporary_password": null,
    "must_change_password": false
  }
}
```

License-server embeds `activation_url` as the `<a href>` of a single mono-CTA button **"Set your password"** in the welcome email.

### Endpoint B — `/api/provision/regenerate-activation-token`

For when the original 48h token expired and the customer asks for a new link.

```
POST /api/provision/regenerate-activation-token
Auth: X-Provision-Key
Content-Type: application/json
```

#### Request body

```json
{
  "email": "newcust@example.com",         // OR organization_id OR user_id
  "expiry_hours": 48                       // optional, default 48, capped at 168
}
```

#### Response 200

```json
{
  "success": true,
  "activation_url": "https://app.sentrikat.com/reset-password?token=...",
  "expires_at": "2026-05-09T14:00:00.000000Z",
  "user_id": 11,
  "email": "newcust@example.com"
}
```

#### Errors

- 400 — `auth_type != 'local'` (LDAP/SAML users have their own auth, no password to set)
- 404 — no matching user/org found

### Why this design

- **No new SaaS-side page**: the existing `/reset-password?token=...` page already handles the token-gated set-password form. Activation reuses it.
- **Token semantics**: same DB column (`users.password_reset_token`), but with longer expiry (48h activation vs 30min recovery). The two flows are functionally identical (one-time token to set password without knowing current).
- **Forgot-password recovery flow remains unchanged** — activation is for onboarding, recovery is for "I forgot my password 6 months later". Both flows are needed; activation does **not** replace recovery.

### License-server welcome email integration

```html
<!-- pseudocode -->
<a href="{tenant.activation_url}" class="cta">
  Set your password
</a>
<p style="font-size:12px;color:#888">
  This link expires in 48 hours.
  If it expired, click "Forgot Password" on the login page to request a new one.
</p>
```

Status (2026-05-07): SaaS endpoint live; sentrikat-web welcome-email branch in progress, ETA shared via team chat.

---

## Adjacent contracts (informational)

These are not on `/api/provision/*` but exist between the two repos:

- **Webhook**: `POST <license-server>/v1/webhook/saas` — heartbeat + usage metrics. See `app/license_webhook.py`.
- **License activation**: `POST <license-server>/v1/license/activate` — on-prem customer pastes activation code, SaaS-on-prem boundary fetches signed license. See `app/licensing.py:activate_license_online`.
- **CISA KEV monitoring** (sentrikat-web side, PR #273): the public mirror at `raw.githubusercontent.com/cisagov/kev-data` is health-monitored from the sentrikat-web side. SaaS depends on this mirror as Akamai bypass for CISA KEV ingestion. If GitHub renames the path or schema drift is detected, sentrikat-web alerts before customers notice.

---

## Changelog of this document

- **2026-05-08**: file created. Sections 2 + 3 written from scratch (fresh contracts from session); section 1 references the pre-existing `SAAS_INTEGRATION_SPEC.md`.
