# SentriKat — SaaS User Guide

> **Audience:** customer organisation admins and users on the managed
> SentriKat SaaS platform (`https://app.sentrikat.com`). If you are
> running SentriKat on your own infrastructure, see
> [`ADMIN_GUIDE.md`](ADMIN_GUIDE.md) instead.

This guide covers the **feature-level** usage of SentriKat for SaaS
customers — how to onboard your team, manage your inventory, tune
alerts, and consume reports. Infrastructure concerns (Docker,
PostgreSQL, SSL certificates, SMTP, license files) are handled by the
SentriKat platform team and are not relevant to SaaS customers.

---

## 1. Getting started

### 1.1 Your first login

1. Open the signup email from `noreply@alerts.sentrikat.com`.
2. Click the activation link — you will land on `https://app.sentrikat.com/login`.
3. Enter your email and the initial password from the email.
4. You will be asked to **renew your password** on first login. This
   is also the flow used if your password later expires or an
   administrator asks you to reset it.
5. Set up 2FA (Profile menu → Security Settings → Enable 2FA). We
   recommend enabling it for every human account, especially for
   `org_admin` and above.

### 1.2 Understanding your role

SentriKat has four roles. The badge in the top-right header always
shows your current role.

| Role | What it can do | Where it can go |
|------|----------------|-----------------|
| **Super Admin** | Platform-level. Only SentriKat staff have this. | Everywhere including platform operations. |
| **Org Admin** | Full control of your organisation — users, billing, integrations, alerts, settings. | All sidebar sections. |
| **Manager** | Manage products, endpoints, integrations, scheduled reports, issue trackers. Cannot invite users or change billing. | Overview, Inventory, Integrations. |
| **User** | Read-only by default — see dashboard, products, assignments. Sensitive assignment notes are redacted. | Overview, Inventory (read-only). |

> ℹ️ There is no separate "viewer" role — `user` **is** the read-only
> role. An org admin can grant a specific user write access to
> products by toggling the `can_manage_products` flag in Users &
> Access without promoting them to Manager.

### 1.3 Plans and feature gates

Your current plan is visible at **Settings → Subscription**. Features
are gated by plan:

| Feature | Free | Starter | Pro | Business | Enterprise |
|---------|:----:|:-------:|:---:|:--------:|:----------:|
| Email alerts | ✗ | ✓ | ✓ | ✓ | ✓ |
| Webhooks | ✗ | ✓ | ✓ | ✓ | ✓ |
| Push agents | ✓ | ✓ | ✓ | ✓ | ✓ |
| API access | ✗ | ✓ | ✓ | ✓ | ✓ |
| Compliance reports (NIS2, CISA BOD 22-01) | ✗ | ✗ | ✓ | ✓ | ✓ |
| Issue trackers (Jira / GitHub / GitLab / YouTrack) | ✗ | ✗ | ✓ | ✓ | ✓ |
| SIEM / syslog forwarding | ✗ | ✗ | ✓ | ✓ | ✓ |
| Audit log export | ✗ | ✗ | ✓ | ✓ | ✓ |
| LDAP / Active Directory | ✗ | ✗ | ✗ | ✓ | ✓ |
| SAML SSO | ✗ | ✗ | ✗ | ✓ | ✓ |
| White-labelling | ✗ | ✗ | ✗ | ✓ | ✓ |
| Backup & restore | ✗ | ✗ | ✗ | ✓ | ✓ |
| Multi-Tenant (multi-org) | ✗ | ✗ | ✗ | ✓ | ✓ |
| Compliance Pack add-on (PCI-DSS, ISO 27001, SOC 2) | — | — | add-on | add-on | add-on |

Agent / user / storage limits are on the Subscription page. Upgrading
is a self-service action; downgrading requires manual action and may
require reducing your inventory first.

---

## 2. Invite your team

**Settings → Users & Access → All Users → + Invite User**.

- Email: the invitee receives an activation link at this address.
- Role: pick one of `user`, `manager`, `org_admin`.
- Organization: only relevant if you have multiple orgs (Business+).

Org Admins can delete users, reset passwords, and lock accounts from
the same page. User activity is visible in **Settings → Audit Log**
on plans with audit export.

---

## 3. Build your inventory

### 3.1 Push agents

1. **Sidebar → Integrations → Agent Keys** → click **+ New Agent Key**.
2. Copy the generated key (it is shown **once**).
3. Download the installer for your OS:
   - Linux: `curl -sSL $BASE/static/agents/sentrikat-agent-linux.sh | bash -s -- --install --server-url $BASE --api-key <KEY>`
   - macOS: `chmod +x sentrikat-agent-macos.sh && sudo ./sentrikat-agent-macos.sh --install --server-url $BASE --api-key <KEY>`
   - Windows: run the signed `.ps1` installer with elevated privileges
4. The agent will register within ~60 seconds. You will see the new
   asset at **Inventory → Endpoints**.

**Mass-removal protection (QA round 3):** if an agent ever reports a
drop of more than 50 % of its installed software in a single check-in
(and it had 5+ products to start with), SentriKat refuses the
removals, logs an `anomaly_rejected` event in Agent Activity, and
surfaces a warning in the response. New / updated products in the
same report are still accepted. This stops a compromised or malicious
agent from wiping its own vulnerability record. The threshold is
tunable via the `AGENT_MAX_REMOVAL_PCT` environment variable on the
platform side — talk to us if you have a legitimate reason (mass
provisioning, image rebase) that requires a temporary relaxation.

### 3.2 Manual product entry

**Inventory → Products List → + Add Product**. The modal searches the
NVD CPE dictionary as you type — pick a canonical entry so
vulnerability matching works correctly. Custom vendors / products
without a CPE are supported but will not auto-match NVD CVEs.

> ℹ️ **Tenant isolation:** two different customers can independently
> own the same (vendor, name, version) triple. You will only ever see
> duplicate-detection errors for products that already exist inside
> **your** organisation(s).

### 3.3 Import queue

When an agent discovers software that isn't in the CPE dictionary or
whose vendor mapping is ambiguous, it lands in **Inventory → Import
Queue**. Managers and admins can approve, reject, or bulk-process
items from there.

### 3.4 Exclusions

**Inventory → Exclusions → + Add Exclusion** opens a modal with a
dual-source search box: start typing and you will see matches from
**your current inventory** and from the **NVD CPE dictionary**
side-by-side. Picking either auto-fills vendor + product_name with
canonical values. An exclusion blocks future agent scans from
re-importing the excluded software.

---

## 4. Act on vulnerabilities

### 4.1 Dashboard

`/` (Dashboard) is the main workspace. Top-of-page alert cards show
zero-day, critical, high, and medium counts — click any of them to
filter the vulnerability list below. Filters, sort, pagination, CVE /
vendor / product search, and unacknowledged toggle all work together.

### 4.2 Remediation assignments

Click any match to open its detail, then **+ Create Assignment** to
assign it to a user, set a priority, due date, and optional notes.
The full list of your assignments lives at **Assignments** in the
sidebar (direct URL: `/assignments`).

- Notes are **redacted** for non-admin roles (`user`, `manager`) —
  only admins can read assignment rationale.
- Status transitions enforce a state machine: terminal states
  (`resolved`, `accepted_risk`) cannot be re-opened. Create a new
  assignment instead.
- Integrations with Jira, GitHub, GitLab, YouTrack or generic webhook
  create an external ticket and store the link on the assignment.

### 4.3 Risk exceptions

Click **Accept Risk** on a match detail to record a compensating
control / justification / optional expiry date. Active exceptions
hide the match from the critical list until they expire.

---

## 5. Alerts, reports and integrations

### 5.1 Email delivery

All emails (alerts, reports, notifications) are sent by the SentriKat
platform from `noreply@alerts.sentrikat.com`. **You do not configure
SMTP in SaaS mode** — it's managed delivery via Resend.

Your monthly quota is visible at **Settings → Email & Notifications**.
Free: 50 / Starter: 500 / Pro: 500 / Business: 2000 / Enterprise: 10000
emails per month. Exceeding the quota does not block the app — alerts
queue silently until the next month.

### 5.2 Alert Management

**Settings → Alert Management** is a dedicated page (not a tab). It
lets you:

- Set an alert mode per org: `critical_only`, `high_and_above`, `all`
- Configure email recipients per org
- Add webhook delivery channels (Slack, Teams, generic)
- Toggle individual alert triggers (daily digest, patch Tuesday,
  overdue remediations, new KEV entries, …)

### 5.3 Scheduled reports

**Integrations → Scheduled Reports** (yes, under Integrations — not
under Settings / Compliance). Create a recurring vulnerability report
that gets emailed to a list of recipients. Valid report types:

- `summary` — monthly high-level overview (PDF)
- `full` — 30-day detailed report (PDF)
- `critical_only` — only CRITICAL severity matches

Click **Send Now** on any report for an immediate one-off send —
useful for validating delivery before the first scheduled run.

### 5.4 Issue trackers

**Integrations → Issue Trackers** (Pro+). Configure credentials for
Jira, GitHub Issues, GitLab Issues, YouTrack, or a generic webhook.
Once configured, the **Create Assignment** modal gets an extra
"Create tracker ticket" checkbox.

### 5.5 SIEM / Syslog forwarding

**Settings → SIEM / Syslog** (Pro+). Send every vulnerability match
and remediation event as a syslog message (UDP / TCP, CEF or RFC 5424
JSON) to your SIEM. Typical use-cases: Splunk, ELK, Wazuh,
QRadar, Sentinel.

### 5.6 Compliance reports

**Settings → Compliance** (Pro+). Generate point-in-time reports for
CISA BOD 22-01 and the EU NIS2 Directive. PCI-DSS, ISO 27001 and
SOC 2 are gated behind the **Compliance Pack** add-on.

All compliance reports include a `document_integrity` block with a
SHA-256 content hash and an HMAC-SHA256 signature using the
platform's secret key. This is a **tamper-evident** audit trail —
proof that the report has not been modified after generation — but
it is **not a legal digital signature**. Present it to auditors as
supporting evidence; a compliance officer still needs to review and
sign the official submission.

### 5.7 SBOM export

**Inventory → SBOM Export** is a dedicated page with three buttons
(CycloneDX 1.5 / SPDX 2.3 / STIX 2.1) plus copy-paste `curl` snippets
for CI pipelines. All three formats also live under the Dashboard's
**Export** dropdown for quick access.

CLI example:

```bash
curl -sk -H "X-API-Key: $SENTRIKAT_API_KEY" \
  https://app.sentrikat.com/api/sbom/export/cyclonedx -o sbom.json
```

Rate-limited to 10 exports / hour / user. Exports larger than the
bundle cap return HTTP 413 — use `?product_ids=1,2,3` to split.

---

## 6. Billing and subscription

**Settings → Subscription** shows your current plan, billing cycle,
next renewal date, feature matrix, and usage vs. limits (agents,
users, products, API keys, storage). Upgrading is self-service; plan
change takes effect at the next billing cycle unless you choose
"immediate" at checkout.

Invoices arrive by email and are also available from the Subscription
page.

---

## 7. Troubleshooting

### 7.1 "Password has expired" at login

That is the renew-password flow. You will be asked for your current
password and a new one. The new password must satisfy the platform
policy (min 12 chars, mixed case, digit, special char by default).

### 7.2 Agent install on macOS fails with "existing agent detected"

Fixed in QA round 3 — the install script now correctly distinguishes
a clean machine from one with a partial / aborted prior install. If
you see this error on a deployed platform older than the fix, either
run `sudo ./sentrikat-agent-macos.sh --uninstall` first, or manually
remove `/Library/Application Support/SentriKat/agent.conf` and rerun
the installer.

### 7.3 CVE I acknowledged keeps reappearing

Acknowledge is per-match. If the underlying vulnerability record is
re-imported from NVD with a newer `last_modified` timestamp, the
match is re-created and the acknowledge is cleared — this is correct
behaviour, because something material changed about the CVE. Use a
**Risk Exception** instead of Acknowledge for permanent
suppressions.

### 7.4 Dashboard is slow

For organisations with more than ~5000 matches, use the filter and
pagination controls instead of "All" page size. The backend is
indexed for the common filter combinations but rendering a 10k-row
table in the browser is slow regardless of backend speed.

### 7.5 Email quota exceeded

Alerts are silently dropped until the next month. Contact support if
this is a recurring issue — you probably need a plan upgrade or a
tuned alert policy (e.g. `critical_only` instead of `all`).

---

## 8. Security notes

- **Tenant isolation** is enforced at the query level. An org admin
  can only see and modify data in organisations they belong to —
  even the product duplicate check is scoped to your organisation
  boundary (so other customers' inventories never leak).
- **Agent trust boundary**: agents can report any software for the
  asset they are bound to, and can create new assets within the org
  their API key belongs to. They **cannot** write to other
  organisations or inflate platform-wide metering (which is
  server-side counted). The mass-removal anomaly threshold prevents
  a compromised agent from wiping its own vulnerability history.
- **CSRF** is enforced on every state-changing endpoint — including
  the first-login password renewal form.
- **2FA (TOTP)** is available to every user and can be enforced per
  organisation via Settings → Users & Access → Security.
- **Audit log export** (Pro+) captures every create / update / delete
  on your organisation's data with actor, timestamp, and diff.

---

## 9. Getting help

- **In-app**: help icons (?) next to every feature link to the
  corresponding section of this guide.
- **Email**: `support@sentrikat.com`
- **Status page**: `https://status.sentrikat.com`
- **GitHub issues** (public): `https://github.com/sbr0nch/SentriKat/issues`
