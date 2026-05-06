# Fase 04 — Portal Customer (`portal.sentrikat.com`)

> Test end-to-end del portal clienti ospitato in `SentriKat-web/portal/` (Astro + React islands). Accesso customer per gestire licenze, downloads, support, checkout, upgrade. Auth **passwordless OTP** (6-digit code email) ≠ dall'app SaaS `app.sentrikat.com` (password-based).
>
> **Backend**: API `license-server` FastAPI su `SentriKat-web/license-server/`, esposto via `api.sentrikat.com` (o proxy nginx su `portal.sentrikat.com/api`).
>
> **Deployment scope per questa fase**: 🏛 portal (Astro) + 🔐 license-server (FastAPI). Dato che è in prod `sentrikat.com` deploy, ogni bug riscontrato qui **impatta direttamente i customer reali**.

## Aree coperte

| Area | Descrizione |
|---|---|
| 04.1 | Login OTP: email → request-otp → verify-otp → cookie `sk_portal_session` |
| 04.2 | Dashboard post-login: overview account, licenze attive |
| 04.3 | Account page: update name/company, delete account (typed "DELETE") |
| 04.4 | Licenses page: lista, activation code, download JSON, bind/rebind installation |
| 04.5 | Downloads: release list, CVE badges, LTS/LATEST/DEPRECATED |
| 04.6 | Support: bug report, feature request, license upgrade request, canned responses admin |
| 04.7 | Checkout: pricing preview, Stripe create session, success polling |
| 04.8 | Upgrade flow agent pack: lookup email, preview, checkout |
| 04.9 | Logout: POST logout, cookie cleared, redirect login |
| 04.10 | 401 handling: session scaduta → redirect login automatico |
| 04.11 | Cross-domain cookie security (`portal.sentrikat.com` ↔ `api.sentrikat.com`) |
| 04.12 | Feedback submission |
| 04.13 | Error pages (404, 500) sul portal |

---

## 04.1 — Login OTP

### [04.1.1] Pagina login form rendering ✅

- **Fase**: 04
- **Area**: Login OTP
- **Deployment scope**: 🏛 portal
- **URL**: `https://portal.sentrikat.com` (o `/login`)
- **Tipo**: 🟢 OK
- **Actual**: al primo accesso appare form login con **solo campo email**. Design passwordless coerente con mappa architetturale
- **Discovered**: 2026-04-24

### [04.1.2] Email non esistente → messaggio di errore chiaro ✅

- **Fase**: 04
- **Area**: Login OTP / validation
- **Deployment scope**: 🏛 portal + 🔐 license-server
- **Tipo**: 🟢 OK (comportamento corretto)
- **Actual**: inserendo una email non registrata, il portal mostra un messaggio di errore chiaro (testo esatto da catturare in un retest)
- **Note sicurezza**: in molte app passwordless il messaggio è volutamente **vago** ("If your email is registered, we'll send you a code") per evitare **user enumeration**. Se SentriKat dice apertamente "email not found" → potenziale vulnerabilità minore (enumerazione account). Da verificare esattezza testo + valutare se cambiare
- **Follow-up TODO 04.1.2a**: copiare il testo esatto del messaggio di errore e valutare contro best practice NIST / OWASP A07 Identification and Authentication Failures
- **Discovered**: 2026-04-24

### [04.1.3] ✅ **VERIFIED 2026-04-30** — OTP email arriva regolarmente dopo deploy SentriKat-web `524208b` (era 🔴 CRITICAL, root cause `BackgroundTasks.send_email` silent swallow)

- **Fase**: 04
- **Area**: Login OTP / email delivery
- **Deployment scope**: 🔐 license-server (flow OTP backend) + possibile SMTP config upstream prod
- **Tipo**: 🔴 Bug
- **Severity**: **HIGH** (customer completamente bloccato dall'accedere al portal — non può gestire licenze, supporto, checkout, upgrade. Impatto business diretto)
- **Environment**: prod `portal.sentrikat.com`
- **Steps to reproduce**:
  1. Apri `https://portal.sentrikat.com`
  2. Inserisci email valida registrata (`muscleaddiction49@gmail.com`, già usata nel signup SaaS di fase 02)
  3. Click Send OTP / Request Code
  4. Il portal procede allo step successivo chiedendo il codice OTP a 6 cifre
- **Expected**: email contenente codice OTP 6-digit arriva in inbox Gmail entro pochi secondi
- **Actual**: **NESSUNA email arriva** nell'inbox (verificato da utente). Flow bloccato alla pagina di input OTP
- **Evidence regressione**: utente esplicito `"cavolo ieri avevamo risolto sta roba in un altra sessione....."` → il bug **è stato già risolto in passato** e ora è **tornato** = regressione su un fix precedente
- **Impatto business**:
  - Customer reali che cercano di loggarsi al portal → falliscono silently
  - Impossibile gestire licenze esistenti, renewal, upgrade, support tickets
  - Support team riceve escalation "il portale non mi manda il codice"
  - Fiducia nel brand degradata (già loggati in past, ora non funziona più)
- **Differenza con SMTP funzionante fase 02**:
  - [02.4.1] welcome email SaaS signup dal `noreply@sentrikat.com` → **È arrivata** in fase 02
  - Conclusione: il sistema SMTP **in generale** funziona (almeno per transazionali legate a provisioning SaaS)
  - Ma il flow OTP login portal **non arriva** → bug specifico di quel flow, non infrastruttura email
- **Ipotesi root cause**:
  1. **Template OTP email rotto** nel license-server (FastAPI `app/` in SentriKat-web/license-server) — invio fallisce silent, o il template genera un body vuoto che viene filtrato come spam
  2. **Rate limiting aggressivo lato prod** (lo stesso utente ha richiesto OTP molte volte in passato?)
  3. **SMTP config del license-server usa credential diverse** da quella del flow provisioning (es. provisioning usa Amazon SES, OTP usa SendGrid con API key scaduta)
  4. **Email finisce in spam** Gmail → verificare spam folder prima di concludere
  5. **Regressione codice**: un commit recente ha toccato il flow `request-otp` e l'ha rotto
- **Diagnostica richiesta (user action)**:
  1. ✅ Controllare **spam folder** Gmail per `muscleaddiction49@gmail.com`
  2. ✅ Provare con **altra email** (es. alias +test o altra casella) per escludere blocco spam Gmail specifico
  3. ✅ Osservare **Network tab DevTools** al click `Send OTP`: URL chiamato (`POST /api/v1/portal/auth/request-otp`), status code, response body
  4. ✅ Se abbiamo accesso al license-server prod: controllare log applicativi per vedere se l'invio è stato tentato e se ha fallito (error code SMTP, connection refused, auth rejected, ecc.)
- **Impact on other scope**: nessun impatto direct su SaaS app (ha auth diversa: password + force change), nessun impatto su on-prem (auth locale). Isolato al portal customer
- **Discovered**: 2026-04-24
- **Nota storica**: bug risolto in sessione precedente ma riapparso → implica che il fix non è stato durevole (rollback? deploy ha sovrascritto? regression test mancante su questo flow?)

### [04.1.3 — confirmed 2026-04-25] ⚠️ Conferma + bisection del periodo di regressione

- **Actions di diagnosi 2026-04-25** (session resumed):
  1. ✅ Fresh incognito browser → `https://portal.sentrikat.com`
  2. ✅ Inserita email `muscleaddiction49@gmail.com`
  3. ✅ Click "Send OTP" — Network: `POST /api/v1/portal/auth/request-otp` → **200 OK**
  4. ✅ Controllo Gmail: **Inbox**, **Spam/Junk**, **Promotions/Updates** → nessuna email da `noreply@sentrikat.com` con OTP
  5. ✅ Click "Resend code" sul form OTP → stesso risultato, 200 OK ma no email
- **Utente conferma**: *"non arriva, sì 200 [...] in passato c'erano tipo 7 giorni fa"* → regressione **confermata** con finestra bisection:
  - ✅ Funzionava: ≤ 2026-04-18 (7 giorni fa)
  - ❌ Non funziona: ≥ 2026-04-24 (ieri)
  - Periodo sospetto: **2026-04-18 → 2026-04-24** (6 giorni)
- **Commit sospetti in quella finestra** (da `SentriKat-web` GitHub, già raccolti in handoff):
  - **2026-04-22** PR #231 `fix(license-server): wrap all enqueue_webhook_event call-sites in try/except` — il license-server è lo stesso processo che manda le email OTP. Il wrapping try/except può aver **nascosto** un'eccezione reale di email delivery, trasformando un 500 → 200 silent fail
- **Hypothesis aggiornata**: PR #231 è il **prime suspect**. Il fix era sull'outbox webhook, ma probabilmente ha avvolto anche il send-email path. Se la funzione di send-email solleva un'eccezione (credenziali SMTP scadute, quota SES, rate limit SendGrid, bounce list), il try/except **swallow silently** e l'endpoint risponde 200 anche quando l'email non è partita
- **Silent-fail pattern** è anti-pattern: meglio 500 + log error + response `{"error":"email_service_unavailable"}` che 200 OK bugiardo
- **Severity escalated**: `High` → **CRITICAL** (un customer non può mai loggare nel portale in prod, in qualunque browser, qualunque email. Azienda bloccata sul flow customer principale)
- **Status test**: **⏸️ BLOCKED** — fase 04 intera rinviata a post-fix
- **Impact on other scope**:
  - 🏛 portal customer → completely non-funzionale
  - 🔐 license-server → silent-fail pattern da investigare ovunque ci siano try/except recenti
  - ☁️ SaaS welcome email arrivava in fase 02.4 → quel flow è separato, non impattato
  - 🏢 on-prem → non impattato (auth locale, no OTP)

### [04.1.4] Step UI post-request-otp visibile ✅

- **Fase**: 04
- **Area**: Login OTP / UX flow
- **Deployment scope**: 🏛 portal
- **Tipo**: 🟢 OK (flow UI procede anche se email non arriva)
- **Actual**: dopo il click su "Send OTP" con email valida, il portal mostra il form di inserimento codice 6-digit, come atteso dal design passwordless
- **Note**: il fatto che la UI procede anche se l'email non arriva è UX **accettabile** (best practice dice "fingere successo anche per email non esistenti" per evitare enumeration). Ma combinato con [04.1.3] che blocca la consegna, il customer è incastrato su una pagina senza feedback
- **Discovered**: 2026-04-24

---

## Re-test 7-dim sistematico — 2026-05-06

> Sessione walkthrough 7-dim su tutte le aree post sentrikat-web PR #252-#263 (stable platform, hard-delete + email deliverability + branding + pricing fix mergeati).

### 04.1 Login OTP — re-verify 2026-05-06

| Dim | Stato | Note |
|---|---|---|
| 1 Happy path | ✅ | Pagina login `portal.sentrikat.com/login` clean, "Sign in to your account / Enter your email to get started", placeholder `you@company.com`, link "New customer? View pricing" + "Trouble signing in? Contact support" + "← Back to SentriKat" |
| 2 Persistence | ⏸️ | Cookie `sk_portal_session` da verificare (F12 → Application) |
| 3 CRUD | n/a | |
| 4 RBAC | ⏸️ | Solo customer, no role variants (verifico in 04.3 admin-vs-customer) |
| 5 State transitions | ✅ | Email **utente esistente attivo** → OTP arriva (verificato `noreply@sentrikat.com`, subject "Your SentriKat verification code", code `041395`, expire 10 min, branding meerkat ✅ post PR #256) |
| 5 (b) | ✅ | Email **utente cancellato** → flow procede al form OTP ma email non arriva (security correct: no user-enumeration leak) |
| 6 Negative input | ⏸️ | Email malformata, OTP errato, OTP scaduto — da testare separatamente |
| 7 Audit / integration | ⏸️ | Verificare audit_events `portal.otp.requested` lato license-server |

#### [04.1.5] 🟢 OK — Email OTP branding + deliverability post PR #256+#257

- Mittente: `SentriKat <noreply@sentrikat.com>` ✅
- Subject: `Your SentriKat verification code` ✅
- Logo SentriKat meerkat ✅ (PR #256 confirmed)
- Body: "Your Verification Code · Enter this code to sign in to your SentriKat account · 041395 · This code expires in 10 minutes · If you didn't request this code, you can safely ignore this email."
- Footer: links a `sentrikat.com | Documentation | Support`, claim "SentriKat - Enterprise Vulnerability Management · Focus on what matters: actively exploited vulnerabilities."
- Inbox primaria Gmail (non spam) ✅

### 04.2 Dashboard post-login — re-verify 2026-05-06

| Dim | Stato | Note |
|---|---|---|
| 1 Happy path | ✅ | Card SAAS "Your Cloud Subscription" Plan ENTERPRISE active · Limits: 10 agents · 3 users · Provisioned 16/04/2026 · CTA "Open SentriKat Cloud →" |
| 1 (b) | ✅ | Quick Links: Download Center, Support & Tickets, Documentation |
| 1 (c) | ✅ | "Need Help?" Getting Started Guide |
| 1 (d) | ✅ | Footer data sources: CISA KEV \| NVD \| CVE.org \| ENISA EUVD \| EPSS \| OSV (6+ sources) |
| 2 Persistence | ⏸️ | Refresh + logout-login da testare |
| 5 State transitions | ✅ | Pagina sidebar attiva mostra "Dashboard" highlighted; navigation funziona |
| 7 Audit | ⏸️ | login event lato license-server |

#### [04.2.1] 🔵 INFO — Limits ENTERPRISE: "10 agents · 3 users"

- **Severity**: 🔵 INFO (da verificare se è cap reale dell'Enterprise plan o solo seed test data)
- **Note**: Enterprise di solito è "unlimited" in catena pricing. 3 user limit per Enterprise è strano. **Verificare canonical `plans_config` lato license-server**.
- **Cross-link**: cluster con `[01.18.4]` welcome email limits / landing pricing inconsistency già in backlog sentrikat-web.

### 04.3 Licenses page — re-verify 2026-05-06

| Dim | Stato |
|---|---|
| 1 Happy path | ✅ Card "SentriKat Cloud subscription active" + Plan ENTERPRISE · Status active |
| 1 (b) | ✅ Empty state "No on-premises licenses · You're on SentriKat Cloud — the subscription is managed at app.sentrikat.com, no license file required." |
| 1 (c) | ✅ 2 CTA: "Open SentriKat Cloud" (primary) + "Need on-prem? Contact Sales" (secondary) |
| 7 Integration | ✅ Coerente con architettura SaaS: customer Cloud non riceve `.license` file |

🟢 **OK overall** — pagina ha gli stati giusti per customer SaaS-only.

### 04.5 Downloads page — re-verify 2026-05-06

| Dim | Stato | Note |
|---|---|---|
| 1 Happy path | 🟡 con bug | Banner "You're on SentriKat Cloud · Downloads below are only relevant if you also run SentriKat on-premises" ✅ corretto disclaimer |
| 1 (b) | ✅ | "Getting Started - 3 Simple Steps" guida: Download & Install / Get Installation ID / Activate License |
| 1 (c) | 🔴 bug | Lista versioni: v1.0.0, v1.0.0-beta.6 **LATEST**, SentriKat v1.0.0 — vedi [04.5.1] |
| 1 (d) | 🟡 | "What's New — Agent v1.2.0" Container Image Scanning via Trivy (Docker + Podman, Linux + Windows endpoints, scans pip/npm/Maven/Go/Rust deps) |

#### [04.5.1] 🔴 HIGH — `v1.0.0-beta.6` marcato LATEST mentre `v1.0.0` (release stable) esiste sopra

- **Fase**: 04 / Downloads
- **Deployment scope**: 🏛 portal (release list source) + possibile 🔐 license-server (releases endpoint)
- **Severity**: 🔴 HIGH — customer on-prem che vuole installare l'ultima versione clicca beta invece di stable. Confusione + potenziale install di build pre-release in produzione.
- **Repro**: `https://portal.sentrikat.com/downloads`
- **Symptom**:
  - Versione `v1.0.0` (Apr 2, 2026) — listata, **nessun badge LATEST**
  - Versione `v1.0.0-beta.6` (Apr 23, 2026) — badge **LATEST** 🟢
  - Sotto: "SentriKat v1.0.0 · Released 02/04/2026 · Unknown" con bottoni Download + View Changelog + badge "Secure — No known vulnerabilities"
- **Expected**: badge LATEST sulla versione **stable più recente** (v1.0.0), non sulla pre-release. Per semver, `v1.0.0` > `v1.0.0-beta.6` (pre-release < release).
- **Hypothesis**: l'ordinamento per "data release" sta sovrascrivendo la logica semver. v1.0.0-beta.6 è uscita 23/04 mentre v1.0.0 stable è uscita 02/04 — quindi temporalmente la beta è più recente, ma è una pre-release. La regola corretta è: latest = max(stable releases) OR mark stable+beta separately con badge diversi (es. "LATEST STABLE" vs "LATEST BETA").
- **Cross-repo**: il fix vive in **sentrikat-web** (portal Astro releases page o license-server `/api/v1/releases`).
- **Discovered**: 2026-05-06

#### [04.5.2] 🟡 MEDIUM — "Unknown" CVE count su tutte le release listate

- **Severity**: 🟡 MEDIUM (UX confusing, ma non blocca download)
- **Symptom**: ogni release mostra "Unknown" come ultima colonna (probabilmente CVE count). Solo "SentriKat v1.0.0" ha badge "Secure — No known vulnerabilities" che è la versione corretta del messaggio.
- **Expected**: `0 CVEs` o `Secure` o numero esplicito; mai "Unknown" che fa pensare "non sappiamo se è sicura".
- **Hypothesis**: il scan CVE per release non è ancora wired up al portal — il chore daily security scan (`d935a1b` di stamattina) probabilmente popola solo le release di SentriKat-web non quelle del core SentriKat.
- **Cross-repo**: fix lato sentrikat-web (releases endpoint).
- **Discovered**: 2026-05-06

#### [04.5.3] 🔵 INFO — "What's New — Agent v1.2.0" Container Image Scanning via Trivy

- **Tipo**: 🔵 INFO (feature highlight UI corretto)
- **Note**: feature description chiara: "automatically detect Docker and Podman on endpoints and scan all local container images for vulnerabilities using Trivy"; lista 4 punti (auto-detect, scans deps, reports HIGH+CRITICAL, included in Pro). Ottimo highlight per upsell community → pro.

### 04.6 Support / 04.7 Account — già coperti in sessioni precedenti

L'utente conferma 04.6 (Support tickets, feedback, canned responses) e 04.7 (Account update name/company, delete account typed "DELETE") già screenshottate e funzionali. Vedi sessioni precedenti per evidence.

---

## Riassunto bug nuovi 2026-05-06 (Phase 04)

| Bug ID | Severity | Env | Title |
|---|---|---|---|
| [04.5.1] | 🔴 HIGH | 🏛 portal (cross-repo sentrikat-web) | `v1.0.0-beta.6` marcato LATEST invece di `v1.0.0` stable |
| [04.5.2] | 🟡 MEDIUM | 🏛 portal (cross-repo sentrikat-web) | "Unknown" CVE count su release list |
| [04.5.3] | 🔵 INFO | 🏛 portal | What's New highlight Trivy ok |
| [04.2.1] | 🔵 INFO | 🔐 license-server | Enterprise plan limits 10 agents/3 users — verifica plans_config canonical |
| [04.1.5] | 🟢 OK | 🏛 + 🔐 | OTP email branding + deliverability post PR #256+#257 confermato live |


---

## Status fase

**🔧 → ✅ FASE 04 SBLOCCATA 2026-04-30** — bug `[04.1.3]` ✅ VERIFIED dopo deploy SentriKat-web `524208b` (root cause: `BackgroundTasks.send_email` swallow silent, NON era PR #231 sospettata).

**Evidenza verify** (2026-04-30):
- Login OTP testato in incognito su `https://portal.sentrikat.com` con `muscleaddiction49@gmail.com`.
- Email arrivata da `noreply@sentrikat.com` con subject "Your Verification Code", body branded SentriKat (logo viola), 6-digit code (esempio: `834487`), expire `10 minutes`, footer con link `sentrikat.com / Documentation / Support`.
- Login completato → flow customer accessibile.

**Aree 04.2–04.13 — happy path testato dall'utente in sessioni precedenti** (Dashboard, Account, Licenses, Downloads, Support, Checkout, Upgrade, Logout, 401 handling, cookie security, Feedback, Error pages). L'utente ha confermato funzionamento end-to-end customer-side, non documentato 7-dim qui per evitare duplicazione con Phase 02 (dove gli stessi flow post-login sono documentati per il SaaS analogo `[02.6]`/`[02.7]`/`[02.8]`).

**Re-test 7-dim deferred** al secondo giro post-fix-cycle, quando si rifaranno tutte le fasi con framework completo. In quel momento serviranno screenshot puntuali per ogni page.

---

## Cross-ref

- [04.1.3] è presumibilmente lo stesso cluster di bug SMTP-flow-specific di:
  - [02.4.1] (temp password plaintext welcome SaaS) — welcome email funzionava
  - [03.11.1.2] (SMTP → Mailpit testlab locale) — funzionante localmente
  - Questa è **prod license-server specifically**, con flow OTP email — diverso da welcome

- La ricorrenza "risolto in passato, ora torna" suggerisce **mancanza di regression test** automatico sulla email OTP delivery. Follow-up: aggiungere test E2E playwright su "send OTP → email received via mock SMTP" nella CI pipeline `SentriKat-web/.github/workflows/ci.yml`

---

## Re-test addendum 2026-05-06: 04.6 Support + 04.7 Account

### 04.6 Support — re-verify 2026-05-06

| Dim | Stato | Note |
|---|---|---|
| 1 Happy path | ✅ | Pagina `/support` divisa in: My Submissions list (filter All Types + All Statuses, empty state "No submissions yet") + Report a Bug form + Request a Feature form + Manage Your Cloud Subscription callout + Need More Help (Email Support) |
| 1 (b) Report a Bug | ✅ | Campi: Bug Title, Severity dropdown ("Medium - Feature not working correctly" default), Description, Steps to Reproduce con placeholder utile, Tags optional comma-separated, Submit Bug Report |
| 1 (c) Request a Feature | ✅ | Campi: Feature Title, Category dropdown ("Vulnerability Management" default), Description, Tags optional, Submit Feature Request |
| 1 (d) Cloud subscription | ✅ | Banner "Manage Your Cloud Subscription · plan changes (upgrade tier, change billing cycle, view invoices) are managed inside the app" + CTA "Open SentriKat Cloud →" |
| 1 (e) Need More Help | ✅ | Email Support CTA per casi urgenti |
| 2-7 | ⏸️ | Rinviato a sessione bug-test mirata (submit, persistenza, XSS, audit) |

🟢 **OK overall** — form completo, separazione bug/feature, callout subscription corretta.

### 04.7 Account Settings — re-verify 2026-05-06

| Dim | Stato | Note |
|---|---|---|
| 1 Happy path | ✅ | Pagina `/account` con due card: Profile Information (Full Name "Denis Sota" editable, Email `contact.sotadenis@gmail.com` non-editable con label "Email cannot be changed", Company empty, Save Changes button) + Danger Zone "Delete My Account" |
| 1 (b) | ✅ | Footer data sources coerente |
| 3 CRUD | 🟢 partial | Update profile via Save Changes; Delete via Danger Zone (typed "DELETE" modal — verificato post PR #258→#263 hard-delete cascade) |
| 5 State transitions | ✅ | Email immutable: vincolo coerente con architettura passwordless OTP |
| 2/4/6/7 | ⏸️ | Rinviato |

🟢 **OK overall** — semantica giusta + hard-delete funzionante post PR #258-263.

---

## Status finale 2026-05-06

✅ **Phase 04 Portal Customer — re-test completato**.

**Bug attivi sentrikat-web**:

| Bug ID | Severity | Stato post nota utente |
|---|---|---|
| [04.5.1] beta.6 LATEST badge | 🟡 MEDIUM (era 🔴 HIGH) | **Mitigato manualmente**: utente gestisce releases via git tags + cancella i vecchi prima di rolloutare. Sort semver portal Astro resta nice-to-have post-EA |
| [04.5.2] "Unknown" CVE count | 🟡 MEDIUM | post-EA |
| [04.2.1] Enterprise 10/3 cap | 🔵 INFO | verificare plans_config canonical |
| [04.7.1] Company vuoto | 🔵 INFO | verificare signup→profile flow |

Nessun blocker pre-EA. Flusso customer end-to-end funziona: login OTP → dashboard → license → download → support → account → logout (logout testato a vista in sidebar).
