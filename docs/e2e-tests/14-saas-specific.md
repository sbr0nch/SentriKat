# Fase 14 — SaaS-Specific Features

> Test end-to-end delle feature SaaS-only (multi-tenant, billing, quota): `app.sentrikat.com` (core) + `portal.sentrikat.com` (license-server). Mode `SENTRIKAT_MODE=saas`.

## Aree coperte

### Multi-tenancy isolation

| Area | Surface | Description |
|---|---|---|
| 14.1 | Tenant create via license-server | `POST /api/v1/provision/trial` from sentrikat-web → bridge call to app.sentrikat.com |
| 14.2 | Tenant data isolation | Org A user cannot see Org B products / matches / settings (RBAC + DB filters) |
| 14.3 | Tenant suspension | Admin suspends a tenant → users locked out, data preserved |
| 14.4 | Tenant deletion (hard-delete) | `[01.18.3]` cascade audit_archive + orphan cleanup (Bundle 1+2 sentrikat-web) |
| 14.5 | Cross-tenant admin operations | Super-admin SaaS sees ALL orgs; org_admin sees only own |

### Subscription plans + quota

| Area | Surface | Description |
|---|---|---|
| 14.6 | Plan limits enforcement (`[01.18.5]`) | max_users, max_agents, max_products per piano. UI error 403 quando si supera |
| 14.7 | Plan upgrade flow | Customer richiede upgrade via portal → admin approva → caps aggiornati live |
| 14.8 | Plan downgrade flow | Conferma `over_limit` warning, sospende prodotti in eccesso |
| 14.9 | Trial expiry | 14 giorni default, email reminder T-3, T-1, T-0 |
| 14.10 | License webhook | Stripe → license-server webhook → tenant.is_active toggle |
| 14.11 | Feature gating per tier | `push_agents` (pro+), `multi_org` (business+), `white_label` (business+), `sso` (business+) |
| 14.12 | Plan-specific feature display | UI nasconde / disabilita feature fuori del piano |

### Metering + billing

| Area | Surface | Description |
|---|---|---|
| 14.13 | Usage metering | `metering.py` → endpoint count, agent count, scan count per tenant per giorno |
| 14.14 | Usage upload to license-server | Scheduler `usage_metering_upload`, daily roll-up |
| 14.15 | Stripe Subscription integration | Plan changes via Stripe → webhook → tenant_subscriptions table |
| 14.16 | Invoicing | Customer vede invoice tramite portal `/billing` (sentrikat-web) |
| 14.17 | Add-ons | Agent packs (+25/+50/+100/Unlimited) — `/api/settings/subscription/addons` |

### Provisioning + lifecycle

| Area | Surface | Description |
|---|---|---|
| 14.18 | Tenant create rebuild | Re-provision idempotente se webhook duplicato |
| 14.19 | Tenant capacity check | `/trial/capacity` ACTIVE-only count (`[01.18.3]` Bundle 1) |
| 14.20 | Welcome email | Post-signup, 1 user / 1 org / 100 products limits coerenti con landing pricing |
| 14.21 | Tenant export (GDPR) | Customer richiede export → ZIP con products + matches + settings |
| 14.22 | Tenant import | Restore da export — è separato dal core backup/restore |

## 7-dim standard

---

_Sezioni 14.1-14.22 da popolare durante walkthrough. Richiede SaaS access (Massimiliano operatore PC casa). Cross-repo: ognuna delle aree tocca sia `app.sentrikat.com` (core) sia `portal.sentrikat.com` (sentrikat-web)._

## Bug summary

| Bug ID | Severity | Env | Title |
|---|---|---|---|
| _(none yet)_ | | | |

## Cross-ref

- `app/saas_*.py` — SaaS-specific code path
- `app/metering.py` — usage tracking
- `app/agent_api.py` — `[01.18.5]` cap enforcement
- `app/api_v1.py` — license-server bridge endpoints
- `docs/SAAS_INTEGRATION_SPEC.md` — contract con sentrikat-web
- `sentrikat-web/license-server/` — counterpart server-side
- `docs/architecture/VULN-FEED-BROKER-DESIGN.md` — quando broker live, nuove aree da aggiungere qui
