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

---

## 02.1 — Form TrialSignup rendering

### [02.1.1] Required fields correttamente marcati ✅

- **Tipo**: 🟢 OK
- **Actual**: utente conferma "tutto a posto", i required hanno marker visibile o comportamento nativo `required`
- **Discovered**: 2026-04-23

---

## 02.2 — Validazione lato client

### [02.2.1] Messaggio di validazione del checkbox Terms mostrato in TEDESCO

- **Fase**: 02 — Signup SaaS
- **Area**: Client validation
- **URL**: `https://sentrikat.com/#trial`
- **Tipo**: 🔴 Bug
- **Severity**: Medium (UX, non funzionale — validazione funziona ma in lingua sbagliata)
- **Environment**: prod
- **Steps to reproduce**:
  1. Apri `https://sentrikat.com/#trial`
  2. Compila il form senza flaggare il checkbox "I agree to the Early Access Terms..."
  3. Clicca "Join Early Access"
- **Expected**: messaggio di errore in inglese (il sito è EN-only, vedi 01.9.1), es. "Please check this box to continue"
- **Actual**: messaggio di errore in **tedesco**: `"Klicke dieses Kästchen an, wenn du fortfahren möchtest."`
- **Root cause**: il checkbox usa l'attributo HTML nativo `required`, che produce un tooltip di validazione **nella lingua del browser** (UA locale), non nella lingua del sito. Se l'utente ha Chrome in DE (come mostrato in screenshot "DevTools is now available in German"), vede il messaggio in DE — anche se il sito è EN.
- **Impatto**: visitatori EN su Chrome DE (comune in Svizzera/Germania/Austria) vedono messaggio inaspettato. Mix di lingue dà impressione di sito poco curato.
- **Fix candidato**:
  - Opzione A (minima): sostituire `required` HTML con validation JS + messaggio custom in inglese `input.setCustomValidity("Please accept the Terms to continue")` oppure pattern `<div role="alert">`
  - Opzione B (i18n completa): se si introduce i18n (vedi 01.9.1), localizzare anche i messaggi di validazione secondo la lingua dichiarata della pagina
- **File sospetto**: `SentriKat-web/landing/src/components/TrialSignup.astro` (checkbox `accepted_terms`)
- **Discovered**: 2026-04-23

### [02.2.2] Submit bloccato se terms non checked ✅

- **Tipo**: 🟢 OK
- **Actual**: il form non submitta se `accepted_terms` non è flaggato (browser-native HTML5 validation fa il suo lavoro)
- **Discovered**: 2026-04-23

### [02.2.3] Nessun CAPTCHA Turnstile sul form TrialSignup ✅ (by design)

- **Tipo**: 🟢 OK (behavior coerente col repo) / 🔵 Info
- **Actual**: form Trial NON ha Turnstile (contrariamente a Contact e Demo). Utente conferma assenza.
- **Consistency check**: coerente con `TrialSignup.astro` nel repo (Turnstile è usato solo in `Contact.astro` e `DemoRequest.astro`).
- **Security note**: l'assenza di Turnstile sul form che CREA ACCOUNT (= consuma slot da 30 di capacity) è un potenziale rischio spam/DoS. Mitigato dal fatto che email alias comuni sono bloccati server-side (vedi 02.3.2) e da capacity cap EA. Da considerare l'aggiunta di Turnstile anche qui se il programma Early Access esce da "beta fidata" — va documentato come decisione esplicita.
- **Discovered**: 2026-04-23

---

## 02.3 — Submit happy path SaaS

### [02.3.1] Happy path SaaS → `201 Created` ✅

- **Fase**: 02
- **Area**: Submit happy path
- **URL**: `POST https://sentrikat.com/api/v1/provision/trial`
- **Tipo**: 🟢 OK
- **Environment**: prod
- **Actual**:
  - Network: `POST /api/v1/provision/trial` → **201 Created**, 1.2 kB response, 329 ms
  - UI: messaggio di conferma inline "Welcome to Early Access! Check your email for your credentials. You'll log in at app.sentrikat.com."
  - Email ricevuta pochi secondi dopo (vedi 02.4)
- **Discovered**: 2026-04-23

### [02.3.2] Email con alias Gmail `+tag` bloccate → `409 Conflict` ✅ (funzione di sicurezza)

- **Fase**: 02
- **Area**: Submit happy path / Edge duplicate
- **Tipo**: 🟢 OK + 🔵 Info (behavior voluto)
- **Actual**:
  - Due tentativi `POST /api/v1/provision/trial` con alias Gmail (pattern `user+tag@gmail.com`) → entrambi **409 Conflict**, ~400 ms e ~267 ms
  - Terzo tentativo con email pulita → **201 Created** (happy path)
- **Behavior**: il backend bloccando gli alias `+tag` previene abuse (1 utente che crea N trial bypassando email univoca). Coerente con best practice.
- **Follow-up TODO — verificare**:
  - Il 409 su alias Gmail: la response body dice esplicitamente "alias blocked" / "email plus-sign not allowed" / o generico "account already exists"? Dal punto di vista UX il messaggio dovrebbe essere chiaro (non generico), altrimenti un utente che ha davvero un alias legittimo si confonde.
  - Il **vero** caso duplicato (stessa email EXACT match, senza alias) produce anche 409? Da testare in 02.8 con email già registrata.
  - Altri provider con alias (Outlook `.` e `+`, ProtonMail `+`, ecc.) sono bloccati? In alternativa viene normalizzato solo Gmail?
- **Discovered**: 2026-04-23

---

## 02.4 — Welcome email

### [02.4.1] 🔴 Temporary password inviata IN CHIARO via email

- **Fase**: 02
- **Area**: Welcome email / Security
- **Tipo**: 🔴 Bug
- **Severity**: **Medium-High** (security — password in plaintext su canale non crittografato end-to-end)
- **Environment**: prod
- **Steps to reproduce**:
  1. Completa signup trial
  2. Controlla inbox della email di signup
  3. Apri la email "Welcome to SentriKat Early Access — Your Account is Ready!"
- **Expected**: nessuna password in chiaro nell'email. Best practice possibili:
  - Magic link one-time (token JWT) per primo login → utente fa subito reset password
  - Oppure: email dice solo "Go to `app.sentrikat.com/login`, use your email, we'll send a 6-digit code" (stile OTP come già fa il portal)
  - Oppure: password temp consegnata tramite secondo canale (SMS, pagina post-signup visibile solo una volta)
- **Actual**: email contiene la **temporary password in chiaro** (es. `922DaVMks3giMNhI`) visibile come testo selezionabile nel corpo dell'email, accanto all'URL di login e alla email dell'utente. Screenshot:
  ```
  Login URL:          https://app.sentrikat.com/login
  Email:              musicaaddiction49@gmail.com
  TEMPORARY PASSWORD  922DaVMks3giMNhI
  You will be asked to change this password on first login.
  ```
- **Attack model**:
  - Se un attaccante compromette l'email provider della vittima (phishing, password reuse, breach DB provider, SIM swap → reset email) ha accesso immediato al prodotto prima che la vittima si accorga
  - Email gateway/SMTP intermediari possono loggare il body in chiaro (rischio insider/SIEM leak)
  - Email NON cifrata end-to-end: chiunque sniffi il traffico SMTP pre-TLS o acceda al mailbox legge la password
  - Account takeover: attaccante logga, cambia password, manda reset email, blocca vittima
- **Mitigazione attuale**: `"You will be asked to change this password on first login"` → la temp password ha vita breve. Ma **se l'attaccante logga prima della vittima, diventa lui a fare il forced change** e l'account è perso.
- **Fix candidato**:
  - Magic link one-time che scade in 15 min, no password nel body
  - Dopo click, pagina che richiede set password + opzionalmente 2FA immediato
  - In alternativa: OTP via email a ogni login (modello passwordless), senza temporary password
- **File sospetto**:
  - Backend SentriKat core: template email welcome trial (probabilmente in `app/email_alerts.py` o `app/provision_api.py`)
  - Template HTML: cercare stringa "Temporary Password" in `app/templates/` o `app/email_templates/`
- **Discovered**: 2026-04-23

### [02.4.2] 🟡 Valuta email in dollari ($) mentre il sito usa euro (€)

- **Fase**: 02
- **Area**: Welcome email / i18n / pricing
- **Tipo**: 🟡 Warning
- **Severity**: Medium (coerenza brand, fiducia cliente — lo customer si chiede "quanto pagherò? dollari o euro?")
- **Actual**: email mostra "`Starter (Early Access — $0)`" con simbolo dollaro. Il resto del sito (`/pricing`, Stripe checkout, Contact Sales agent packs) usa **€ EUR**.
- **Consistency check vs mappa repo**:
  - Landing pricing: €
  - Stripe agent upgrade: €999/yr Priority, €199/mo Compliance
  - Portal admin pricing config: atteso €
  - Email template: $ ← incoerente
- **Impatto**:
  - Confusione utente al prossimo upgrade paid (si aspetta USD, vede EUR)
  - Argomento particolarmente sensibile per CH/EU customers (SentriKat è Swiss-focused)
- **Fix candidato**:
  - Template email: sostituire `$` con `€` per plan price display, O usare un formato locale-aware
  - Idealmente: leggere la valuta dal Plan.currency nel DB invece di hardcodarla
- **File sospetto**: template welcome email (core backend `app/` + stringa "Early Access — $0")
- **Discovered**: 2026-04-23

### [02.4.3] ~~Layout email con spazio nero a sinistra~~ — FALSO POSITIVO ❌

- **Tipo**: ❌ Non-bug (rettificato)
- **Actual**: utente conferma che lo spazio nero era solo il crop dello screenshot iniziale; aprendo la mail a larghezza piena il layout è correttamente centrato e simmetrico (vedi secondo screenshot email).
- **Azione**: voce annullata, non va in bug count.
- **Discovered / resolved**: 2026-04-23

### [02.4.4] Welcome email contenuto — rimanenti aspetti ✅ (con follow-up)

- **Fase**: 02
- **Area**: Welcome email
- **Tipo**: 🟢 OK + 🔵 Info
- **Attributi verificati**:
  - Subject: `"Welcome to SentriKat Early Access — Your Account is Ready!"` ✅
  - Sender: `SentriKat <noreply@sentrikat.com>` ✅
  - Contenuto: plan, email, login URL, temp password, getting started (4 step), managing licenses section con rimando a `portal.sentrikat.com` ✅
  - Menzione del doppio sistema auth: `app.sentrikat.com` (password) vs `portal.sentrikat.com` (OTP 6-digit) ✅ — coerente con architettura mappata
- **Follow-up TODO**:
  - 02.4.5 SPF/DKIM/DMARC: verificare da Gmail "Show original" che l'email passi SPF=pass, DKIM=pass, DMARC=pass
  - 02.4.6 Reply-to: verificare che un reply arrivi a `support@` o `hello@` e non a `noreply@` (black hole)
  - 02.4.7 Link tracking: ci sono redirect tracking sui link (tipo `click.sentrikat.com/r/...`)? Se sì, sono sicuri/consistenti?
  - 02.4.8 Unsubscribe: c'è link List-Unsubscribe header (obbligatorio per Gmail/Yahoo 2024+)?
- **Discovered**: 2026-04-23

---

## 02.15 — Deployment type switcher

### [02.15.1] Plan picker nascosto quando deployment=on-prem ✅

- **Tipo**: 🟢 OK
- **Actual**: utente conferma "sparisce" il plan picker (Starter/Pro/Business/Enterprise) quando si passa da SaaS a On-prem — behavior corretto (piani SaaS non applicabili on-prem, i piani on-prem passano da contact-sales / licensing dedicato).
- **Discovered**: 2026-04-23

---

## 02.5 — Redirect post-success

### [02.5.1] Nessun auto-redirect post-submit — utente usa il link dalla email (by design) ✅

- **Tipo**: 🟢 OK
- **Actual**: dopo `201 Created` l'UI rimane sulla landing con il messaggio di conferma; l'utente prosegue cliccando "Log In Now" dalla welcome email (link validi, tutti funzionanti)
- **Decisione di design coerente**: evita confusione se l'utente ha chiuso l'email; il flow resta: submit → email → click in email → login. È un modello accettato.
- **Discovered**: 2026-04-23

---

## 02.6 — Login `app.sentrikat.com` + force password change

### [02.6.1] Login con temp password funziona + forced change al primo login ✅

- **Fase**: 02
- **Area**: Login app.sentrikat.com
- **URL**: `https://app.sentrikat.com/login`
- **Tipo**: 🟢 OK
- **Actual**: email + temp password (dall'email welcome) → login OK → pagina `Password Update Required` appare subito (come promesso nell'email).
- **Evidence**: screenshot `Password Update Required` con logo mascot stile mongoose, campi "Current Password / New Password / Confirm New Password" e bottone "Change Password"
- **Discovered**: 2026-04-23

### [02.6.2] Policy password: min 8 char enforced, mismatch rilevato ✅

- **Tipo**: 🟢 OK (policy enforcement visibile)
- **Actual**:
  - Password `test123` (6 char) → errore chiaro: `"Password must be at least 8 characters"`
  - Password `TestPass123!` (12 char, mix) → accettata
  - Confirm password diversa da new password → errore chiaro "password non uguali"
- **Discovered**: 2026-04-23

### [02.6.3] 🔵 Password policy: da verificare complessità oltre il min-length

- **Fase**: 02
- **Area**: Login / password policy
- **Tipo**: 🔵 Info (follow-up)
- **Severity**: Low-Medium (security posture)
- **Actual**: l'unico messaggio visto è "at least 8 characters". Non è chiaro se il server enforce anche: maiuscole, minuscole, numeri, simboli, no-common-passwords list (NIST SP 800-63B raccomanda di confrontare con lista breached password come Have-I-Been-Pwned invece di regole di complessità).
- **Follow-up TODO 02.6.3a**: testare con password:
  - `password` (8 lowercase, dizionario comune) → dovrebbe essere rifiutata se c'è breached-list check
  - `12345678` (8 digit) → dovrebbe essere rifiutata
  - `aaaaaaaa` (8 ripetute)
  - Registrare quali passano e quali no → mappare la policy effettiva
- **Discovered**: 2026-04-23

### [02.6.4] 🔵 Copy "an administrator asked you to renew it" visibile anche su SaaS first-login

- **Fase**: 02
- **Area**: Login / copywriting
- **Tipo**: 🔵 Info (minor UX)
- **Severity**: Low
- **Actual**: la pagina `Password Update Required` mostra il messaggio:
  > "Please choose a new password to continue. This is required either because your password has expired, it's your first login, or an administrator asked you to renew it."
- **Issue**: su **SaaS self-signup** non esiste un "administrator" che ha chiesto il renew — l'utente ha appena creato da sé l'account. Il copy è un "union message" pensato per on-prem (dove super_admin può forzare renew) ma riusato anche su SaaS.
- **Fix candidato**: render condizionale del copy in base al context:
  - `first_login=True` → "Welcome! Please choose a new password to replace the temporary one we emailed you."
  - `expired=True` → "Your password has expired. Please choose a new one."
  - `forced_by_admin=True` → "An administrator asked you to renew your password."
- **Discovered**: 2026-04-23

---

## 02.7 — Onboarding / first-time UX

### [02.7.1] Dashboard empty state coerente e ben strutturata ✅

- **Fase**: 02
- **Area**: First-time UX
- **URL**: `https://app.sentrikat.com/` (dopo login + password change)
- **Tipo**: 🟢 OK
- **Actual**: **Vulnerability Dashboard** con:
  - 4 cards counter: `0-DAY (0)`, `CRITICAL CVES (0)`, `HIGH CVES (0)`, `MEDIUM CVES (0)` — coerente per un account appena creato senza agent
  - Widget **KEV Catalog: 13,978** (conteggio totale CISA KEV, popolato dal sync) + `Affecting Products: 0`, `Needs Review: 0`, `Products Tracked: 0`, `High EPSS Risk: 0`, `Low Priority: 0`
  - Priority Breakdown (donut chart, empty "No data yet")
  - Remediation Progress (line chart, empty "No data yet" + CTA `Take Snapshot`)
  - Remediation Actions list ("No pending remediation actions")
  - SLA Compliance ("No SLA policies configured" + CTA `Set up SLA`)
  - Remediation Overview, Assignments (empty)
  - Source filter: `All | Servers | Clients | Containers | Dependencies` — filtering per tipologia asset
  - Top bar: breadcrumb `Home / Dashboard`, badge `TAKIRTNES` (company), dark mode toggle, user email dropdown
- **Console**: zero errori
- **Network**: tutte 200
- **Discovered**: 2026-04-23

### [02.7.2] 🔵 Badge company name in uppercase (text-transform CSS)

- **Fase**: 02
- **Area**: First-time UX / branding
- **Tipo**: 🔵 Info
- **Actual**: l'utente ha dichiarato company name `Takirtnes` (mixed case) nel form Trial; l'email welcome mostra coerentemente `Takirtnes`. Nel dashboard top-right il badge mostra `TAKIRTNES` (uppercase).
- **Ipotesi**: CSS `text-transform: uppercase` sul badge (styling intenzionale). Se fosse DB normalization sarebbe un bug di consistency.
- **Follow-up TODO 02.7.2a**: inspect element sul badge per confermare CSS vs valore salvato. Se c'è un editor company name (Settings → profile) verificare che il valore in DB sia preservato nella sua casing.
- **Discovered**: 2026-04-23

### [02.7.3] 🔵 Feature gating mappa da validare su piano Starter

- **Fase**: 02
- **Area**: First-time UX / subscription / feature gating
- **Tipo**: 🔵 Info (da validare in fase 14 SaaS-specific)
- **Sidebar menu visto (piano Starter)**:
  - **OVERVIEW**: Dashboard, Assignments
  - **INVENTORY → Products**: Products List, Endpoints, Containers, Dependencies, Import Queue, **SBOM Export**, Exclusions
  - **MANAGEMENT → Users & Access**: All Users
  - **INTEGRATIONS**: Agent Keys, Agent Activity
  - **SYSTEM → Settings**: Alert Management, Email & Notifications, Subscription
- **Osservazioni da confermare (dalla mappa architetturale originale)**:
  - ❓ **SBOM Export** visibile su Starter: dalla mappatura `SBOM export` era previsto `Pro+ only`. Da verificare cliccandolo: si apre o dà 403 "upgrade required"? Se si apre, la mappa di gating è sbagliata o Starter include SBOM da recente change (cfr. commit `e769ce9 fix(plans): declare sbom_export in seeded plans so /api/sbom/* isn't 403` — probabilmente SBOM ora è incluso in tutti i plan)
  - ❓ **LDAP settings**, **SAML settings**: NON visibili nel menu → feature gated correttamente (Pro+/Business+). Tuttavia bisogna verificare che sulla pagina `/settings` o `/subscription` l'utente veda un teaser "Upgrade to unlock LDAP/SAML" per informare dell'opzione
  - ❓ **Jira/GitHub/GitLab/YouTrack integrations**: "Integrations" in sidebar mostra solo Agent Keys + Agent Activity → probabilmente gating Pro+. Verificare se esiste una pagina Integrations con teaser
  - ❓ **Compliance reports** (BOD, NIS2, PCI, ISO, SOC2) non appaiono in menu: gated Pro+
- **Follow-up TODO 02.7.3a**: in fase 14 SaaS-specific fare il test completo di feature gating (cliccare ogni voce gated e registrare il messaggio ricevuto). In fase 13 admin cross-ref con `/admin/plans` e `/admin/licenses` per vedere cosa il tenant ha effettivamente abilitato
- **Discovered**: 2026-04-23

### [02.7.4] 🔵 No welcome modal / tour / onboarding wizard

- **Fase**: 02
- **Area**: First-time UX
- **Tipo**: 🔵 Info (UX)
- **Severity**: Low
- **Actual**: subito dopo il cambio password l'utente atterra nella dashboard empty senza:
  - welcome modal di benvenuto
  - checklist "Complete your setup" (deploy agent, invite team, configure alerts, set up SLA)
  - tour guidato (es. driver.js / intro.js)
  - CTA dominante per "primo step" (Deploy your first agent)
- **Impatto**: utente tecnico power va bene; early access signup è una popolazione che conosce il prodotto. Ma per conversione trial → paid un onboarding guidato aumenta attivazione. Nel repo `setup.html` esiste ma forse è solo per on-prem first-run.
- **Nota**: il widget "KEV Catalog 13,978" senza contesto può confondere chi non conosce CISA KEV — sarebbe utile un tooltip "? what's this?"
- **Follow-up TODO 02.7.4a**: verificare se esiste una pagina `/getting-started` o `/welcome` non linkata dal sidebar; controllare `app/templates/setup.html` se viene mostrato anche su SaaS first-login
- **Discovered**: 2026-04-23

### [02.7.5] Menu navigabile, niente errori console, tutti 200 su network ✅

- **Tipo**: 🟢 OK (sanity check)
- **Actual**: utente conferma "console nessun errore, ho tutti 200 su network"
- **Discovered**: 2026-04-23

---

## 02.12 — Stripe NOT proposed in Early Access

### [02.12.1] Nessun CTA Stripe/checkout durante signup EA ✅

- **Tipo**: 🟢 OK
- **Actual**: dall'intero flow (form Trial → submit → email welcome → login → dashboard) NESSUN punto propone pagamento / Stripe checkout. L'email dichiara esplicitamente `Starter (Early Access — $0)` e "features are free during Early Access".
- **Follow-up TODO 02.12.2**: verificare cosa succede al termine dell'Early Access (trial expire): l'utente vede paywall? email reminder? downgrade automatico a Free?
- **Discovered**: 2026-04-23

---

## 02.8 — Edge 409 duplicate (parziale)

### [02.8.1] 409 su email non accettate ✅

- **Tipo**: 🟢 OK (parziale, vedi follow-up in 02.3.2)
- **Actual**: 2 tentativi con alias Gmail → 409 entrambi
- **Discovered**: 2026-04-23
- **Follow-up TODO 02.8.2**: vero duplicate (stessa email già registrata in precedenza, senza alias) — testare con l'email del trial passato per confermare 409 + messaggio UI chiaro.

### [02.8.2] 409 su true duplicate (stessa email già registrata) + UI chiara ✅

- **Fase**: 02
- **Area**: Edge 409 duplicate
- **URL**: `POST /api/v1/provision/trial` con email già usata nel trial appena completato
- **Tipo**: 🟢 OK
- **Actual**: submit con stessa email appena registrata → UI mostra `"Account already exist"`, messaggio chiaro. Funzione di dedup operativa.
- **Discovered**: 2026-04-23

---

## 02.14 — Pricing page CTAs

### [02.14.1] `/pricing` rendering + CTAs coerenti ✅

- **Fase**: 02
- **Area**: Pricing page
- **URL**: `https://sentrikat.com/pricing`
- **Tipo**: 🟢 OK
- **Actual**: utente conferma "si va tutto bene" (pagina carica, card visibili, CTAs puntano agli endpoint attesi: `#trial` per EA, `mailto:sales@sentrikat.com` per Enterprise, `#demo` per On-prem, capacity endpoint popolato)
- **Follow-up TODO 02.14.2**: in un prossimo passaggio verificare dettagli quantitativi (sconti multi-anno 10%/15%, listino agent packs +25/+50/+100/Unlimited, add-on Compliance Pack €199/mo e Priority Support €999/yr) e testare il toggle "annual vs monthly" se esiste
- **Discovered**: 2026-04-23

---

## 02.7 (continua) — Subscription detail in `app.sentrikat.com`

### [02.7.6] 🟡 Contraddizione Early Access vs Billing "Monthly / Renews 23 May 2026"

- **Fase**: 02
- **Area**: First-time UX / Subscription
- **URL**: `https://app.sentrikat.com/` → Settings → Subscription
- **Tipo**: 🟡 Warning
- **Severity**: Medium (causa ansia al cliente: "mi addebiteranno qualcosa il 23 maggio?" — rischio churn)
- **Environment**: prod
- **Actual** (dallo screenshot):
  - Plan: `Starter`
  - Status: `ACTIVE`
  - **Billing: `Monthly`**
  - **Renews: `23 May 2026`** (1 mese dopo il signup di oggi 2026-04-23)
  - Nessuna label esplicita "Early Access" visibile sulla card Current Plan
  - Email welcome diceva `"Starter (Early Access — $0)"` e `"all features are free during Early Access"`
- **Issue**: il customer vede un billing mensile con data di rinnovo concreta ma non c'è indicazione che sia gratuito. Un cliente EA si chiede: "devo cancellare per non essere addebitato?"
- **Expected**:
  - Opzione A: `Billing: Early Access (Free)` + `Renews: —` (o EA end date chiaramente etichettata)
  - Opzione B: riga aggiuntiva `Early Access: Active (Free until 2026-XX-YY)`
  - Opzione C: badge grande "EARLY ACCESS — FREE" accanto al plan name
- **File sospetto**: template/component della pagina Subscription nel frontend SaaS prodotto, + logica Plan/Subscription backend dove non discrimina tra EA trial e paid subscription
- **Discovered**: 2026-04-23

### [02.7.7] 🔵 Subtitle "LDAP configuration, SMTP settings..." su Starter dove LDAP è gated

- **Fase**: 02
- **Area**: Copywriting / feature gating consistency
- **Tipo**: 🔵 Info
- **Severity**: Low
- **Actual**: la pagina Subscription ha header `"System Settings"` con subtitle `"LDAP configuration, SMTP settings, and system options"`. Ma nella stessa pagina `LDAP / Active Directory` è listato come ❌ (non incluso su Starter).
- **Issue**: copy hardcoded che menziona feature non disponibili → confonde l'utente.
- **Fix candidato**: subtitle dinamico che elenchi solo le feature disponibili nel plan attuale, oppure più generico `"Manage your subscription, notifications, and system options"`
- **Discovered**: 2026-04-23

### [02.7.8] 🔵 Breadcrumb "Home / Administration" non coerente col menu

- **Fase**: 02
- **Area**: Navigation / breadcrumbs
- **Tipo**: 🔵 Info
- **Severity**: Low
- **Actual**: l'utente ha cliccato `Settings → Subscription` in sidebar ma la breadcrumb mostra `Home / Administration` (non `Home / Settings / Subscription` come ci si aspetterebbe)
- **Issue**: il path percorso non è rappresentato; se l'utente clicca "Administration" nella breadcrumb, dove finisce?
- **Fix candidato**: breadcrumb basata sulla navigazione reale della sidebar
- **Discovered**: 2026-04-23

### [02.7.9] 🔵 Manca label esplicita "Early Access" sulla Current Plan card

- **Fase**: 02
- **Area**: Subscription / UX
- **Tipo**: 🔵 Info
- **Severity**: Low (strettamente collegato a 02.7.6)
- **Actual**: la card Current Plan mostra `Starter / ACTIVE / Monthly / 23 May 2026` senza dire che il cliente è in Early Access (€0). Unica indicazione "Early Access" era nell'email welcome.
- **Fix candidato**: quando `plan.is_early_access == True` → badge verde "EARLY ACCESS" + testo "Free during Early Access program"
- **Discovered**: 2026-04-23

### [02.7.10] 🔵 Manca usage / quota attuale (agenti used, users used, storage used)

- **Fase**: 02
- **Area**: Subscription / quota visibility
- **Tipo**: 🔵 Info
- **Severity**: Low-Medium
- **Actual**: `Plan Limits` mostra i massimi (Agents: 10, Users: 3, Products: Unlimited, API Keys: 2, Storage: 500 MB) ma NON mostra il consumo attuale (es. `2 / 10 agents used`, `1 / 3 users`, `48 MB / 500 MB used`)
- **Issue**: utente non sa quando sta per saturare; cliente a livelli critici non ha early warning
- **Fix candidato**:
  - Aggiungere barre di progresso `<n> / <max> (<%>)` per ogni limit
  - Alert email al 80%/95% del limite
- **Discovered**: 2026-04-23

### [02.7.11] 🔵 SBOM Export visibile in sidebar ma NON nella lista "Features Included"

- **Fase**: 02
- **Area**: Feature gating / consistency
- **Tipo**: 🔵 Info
- **Severity**: Low (da chiarire: feature universale o bug di visibilità?)
- **Actual**:
  - Sidebar su Starter mostra voce `Inventory → Products → SBOM Export` (visibile e presumibilmente cliccabile)
  - Pagina Subscription → `Features Included` NON elenca SBOM tra le feature attive (né come ❌)
  - Nel repo il commit recente `e769ce9 fix(plans): declare sbom_export in seeded plans so /api/sbom/* isn't 403` suggerisce che SBOM è stato reso feature universale
- **Chiarimenti da ottenere**:
  - SBOM Export è incluso in tutti i piani (anche Starter/Early Access)?
  - Se sì: la feature list della Subscription page va aggiornata per elencarlo come ✅
  - Se no: la voce in sidebar va nascosta o deve mostrare teaser "Pro+ only"
- **Follow-up TODO 02.7.11a**: cliccare SBOM Export in sidebar → si apre la pagina? restituisce 403? scarica un JSON?
- **Discovered**: 2026-04-23

### [02.7.12] Subscription page rendering + feature matrix visibile ✅

- **Fase**: 02
- **Area**: Subscription / UX
- **Tipo**: 🟢 OK (contenuto presente e ben organizzato)
- **Actual**: pagina bene strutturata con:
  - Current Plan card (Starter / ACTIVE / Monthly / 23 May 2026)
  - Plan Limits card (10 agents, 3 users, Unlimited products, 2 API keys, 500 MB storage)
  - Features Included grid (13 feature, ✅/❌ per piano Starter)
  - Paid Add-on section (Compliance Pack — NOT PURCHASED, con teaser "Upgrade your plan to Pro, Business, or Enterprise first to unlock add-on eligibility")
  - Footer CTA "Need more capacity? → View Plans"
- **Feature matrix Starter documentata** (da 13 voci):
  - ✅ Email Alerts
  - ✅ Webhooks
  - ✅ Push Agents
  - ✅ API Access
  - ❌ NIS2/DORA + BOD 22-01 Reports
  - ❌ Multi-Tenant
  - ❌ LDAP / Active Directory
  - ❌ White-Labeling
  - ❌ Issue Trackers
  - ❌ Backup & Restore
  - ❌ SAML SSO
  - ❌ SIEM Integration
  - ❌ Audit Log Export
- **Nota su compliance**: NIS2/DORA+BOD gated; Compliance Pack (PCI-DSS/ISO 27001/SOC 2) come paid add-on separato su Pro/Business/Enterprise → due layer di compliance gating
- **Discovered**: 2026-04-23

---

## Stato fase

**✅ FASE 02 COMPLETATA (al 90%)** — happy path e primo onboarding coperti.

**Sotto-aree chiuse**: 02.1 · 02.2 · 02.3 · 02.4 · 02.5 · 02.6 · 02.7 · 02.8 · 02.12 · 02.14 · 02.15

**Sotto-aree rimanenti (cross-fase, da riprendere dopo admin portal)**:
- 02.9 — 503 `EA_CAPACITY_FULL`: non forzabile su prod (capacity 2/30 open). Da testare in fase 05 abbassando `capacity` da `/admin/settings` o `/admin/plans` a 2, riprovare signup → attesa 503.
- 02.10 — 422 validation server-side: HTML5 blocca la maggior parte a client-side (email format, required). Test con payload malformato via fetch/curl rinviato (opzionale).
- 02.11 — Provisioning bridge license-server → SentriKat SaaS: verificare in fase 05 `/admin/saas-tenants` che il tenant creato oggi appaia nell'elenco e che `/admin/webhook-outbox` mostri la delivery webhook come SUCCESS.
- 02.13 — Terms tracking (`terms_accepted_at`, `terms_version: "2026-02-09"`): verificare in fase 05 nella detail page del tenant/customer in `/admin/customers/<id>`.

## Riepilogo bug fase 02

| ID | Severity | Titolo |
|---|---|---|
| 🔴 02.2.1 | Medium | Validation in tedesco (Chrome DE) su sito EN-only |
| 🔴 02.4.1 | Medium-High | Temp password inviata in plaintext via email |
| 🟡 02.4.2 | Medium | Prezzo email in USD `$` mentre il sito usa EUR `€` |
| 🟡 02.7.6 | Medium | Billing "Monthly / Renews 23 May" su Early Access gratuito |
| 🔵 02.2.3 | — | Niente Turnstile su TrialSignup (by design, ma ← spam surface su free account) |
| 🔵 02.3.2 | — | Alias Gmail bloccati (feature, ma UX del messaggio 409 da rivedere) |
| 🔵 02.4.5–4.8 | — | Email: SPF/DKIM/DMARC, reply-to, tracking, List-Unsubscribe |
| 🔵 02.6.3 | — | Complessità password oltre min-length da verificare |
| 🔵 02.6.4 | — | Copy "admin asked you to renew" su SaaS self-signup |
| 🔵 02.7.2 | — | Company name uppercase in badge (CSS?) |
| 🔵 02.7.3 | — | Feature gating Starter sidebar vs Features Included |
| 🔵 02.7.4 | — | No onboarding wizard / welcome modal |
| 🔵 02.7.7 | — | Subtitle hardcoded "LDAP configuration" su Starter senza LDAP |
| 🔵 02.7.8 | — | Breadcrumb "Home / Administration" inconsistente |
| 🔵 02.7.9 | — | Manca label "Early Access" su Current Plan card |
| 🔵 02.7.10 | — | Manca usage/quota attuale (x/max con %) |
| 🔵 02.7.11 | — | SBOM Export visibile in sidebar ma non in Features Included |

**Totale fase 02: 2 bug (1 Med-High + 1 Med) + 2 warning Medium + 13 info, 11 OK** — rilevanti 🟡 02.7.6 (EA billing confusion) e 🔴 02.4.1 (plaintext password email).

---

## Follow-up cross-fase

### [01.1.2] 🔵 DOMContentLoaded 4.99s + Finish 4.1 min — possibile revisione "velocissimo" (01.1.1)

- **Fase**: 01 → cross-ref
- **Area**: Performance
- **Tipo**: 🔵 Info (da rivalidare)
- **Actual**: dagli screenshot di DevTools in fase 02 risulta `DOMContentLoaded: 4.99s` e `Finish: 4.1 min` sulla pagina `/#trial` con 37 requests / 6.8 kB transferred / 1.2 MB resources
- **Note**:
  - `Finish: 4.1 min` è probabilmente dovuto a "Preserve log" attivato durante l'intera sessione (somma di tutto il tempo con tab aperta), non un tempo di caricamento reale
  - `DOMContentLoaded: 4.99s` è più interessante: per una pagina Astro static dovrebbe essere sub-secondo. Possibili cause: hydration React islands pesanti, CSP block del font che causa layout shift/timeout, risorse bloccanti
- **Follow-up**: ricaricare `/` in tab fresco senza Preserve log e misurare `DOMContentLoaded`. Se davvero è >3s su prod → bug performance (riclassificare 01.1.1 da 🟢 a 🟡)
- **Discovered**: 2026-04-23
