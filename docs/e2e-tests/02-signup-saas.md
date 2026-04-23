# Fase 02 — Signup SaaS (Early Access trial)

> Test end-to-end del flow di provisioning SaaS: form `TrialSignup` sulla landing → `POST /api/v1/provision/trial` (license-server FastAPI) → bridge provisioning a `app.sentrikat.com` → welcome email → login → prima esperienza nel prodotto.
>
> **Vincolo environment**: solo **prod** (`sentrikat.com`), nessuno staging disponibile.
> **Vincolo pagamento**: Early Access = €0, Stripe checkout **non previsto** in questo flow (verificare che la UI non proponga pagamento).
> **Email test**: utente usa alias Gmail `+testN` per generare email univoche; una email già usata serve per testare il caso duplicato (409).

## Aree coperte

| Area | Descrizione |
|---|---|
| 02.1 | Form `TrialSignup` rendering + ancoraggio `#trial` su home e pricing |
| 02.2 | Validazione lato client (required fields, email format, terms checkbox, deployment type switcher) |
| 02.3 | Submit happy path SaaS → `POST /api/v1/provision/trial` |
| 02.4 | Welcome email (subject, sender, contenuto, link di attivazione, spam folder) |
| 02.5 | Redirect post-success (`app.sentrikat.com/login` per SaaS, `portal.sentrikat.com` per on-prem) |
| 02.6 | Login in `app.sentrikat.com` (OTP? password temp? SSO?) |
| 02.7 | Onboarding / first-time experience (setup wizard, empty dashboard, tour, agent deploy CTA) |
| 02.8 | Edge 409 — account già esistente |
| 02.9 | Edge 503 — `EA_CAPACITY_FULL` (forzabile solo da admin con capacity abbassata) |
| 02.10 | Edge 422 — validation errors (email malformed, terms non checked, campi mancanti) |
| 02.11 | Provisioning bridge license-server → SentriKat SaaS (`SAAS_PROVISION_URL`, `SENTRIKAT_PROVISION_KEY`, webhook outbox) — verificabile da admin portal `/admin/webhook-outbox`, `/admin/saas-tenants` |
| 02.12 | Stripe checkout NON proposto in Early Access (check che non ci siano CTA pagamento) |
| 02.13 | Terms tracking (`terms_accepted_at`, `terms_version: "2026-02-09"`) |
| 02.14 | Pricing page `#pricing` — bottoni Early Access SaaS (starter/pro/business/enterprise) + waitlist quando capacity full |
| 02.15 | Deployment type switcher (SaaS vs On-prem) — nasconde/mostra plan picker |

---

## Setup test account

- **Email base**: alias Gmail dell'utente con suffissi `+trialN@gmail.com` dove `N` incrementa per ogni test
- **Email già registrata** (per 409): l'email usata da un trial passato (utente la conosce)
- **Terms version attesa** (visto in TrialSignup.astro): `2026-02-09`
- **Capacity prod attuale**: `2/30 open` (visto in 01.18.1)

---

*(bug/osservazioni da popolare durante la sessione)*
