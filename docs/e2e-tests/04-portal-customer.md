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

### [04.1.3] 🔴 HIGH — OTP email NON arriva dopo request-otp (regressione ricorrente)

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

### [04.1.4] Step UI post-request-otp visibile ✅

- **Fase**: 04
- **Area**: Login OTP / UX flow
- **Deployment scope**: 🏛 portal
- **Tipo**: 🟢 OK (flow UI procede anche se email non arriva)
- **Actual**: dopo il click su "Send OTP" con email valida, il portal mostra il form di inserimento codice 6-digit, come atteso dal design passwordless
- **Note**: il fatto che la UI procede anche se l'email non arriva è UX **accettabile** (best practice dice "fingere successo anche per email non esistenti" per evitare enumeration). Ma combinato con [04.1.3] che blocca la consegna, il customer è incastrato su una pagina senza feedback
- **Discovered**: 2026-04-24

---

## Status fase

**⏸️ FASE 04 BLOCCATA** dal bug [04.1.3]: senza OTP l'intero portal post-login (Dashboard, Account, Licenses, Downloads, Support, Checkout, Upgrade) è **non testabile dal customer reale**.

### Workaround possibili per sbloccare testing

| Opzione | Descrizione | Feasibility |
|---|---|---|
| A — Admin bypass DB | Insert sessione fake direttamente nel DB del license-server | richiede accesso prod DB |
| B — Request OTP via API diretta + log scraping | `curl` a `/api/v1/portal/auth/request-otp` + vedere se OTP finisce nei log | richiede accesso prod logs |
| C — Admin fallback login | Esiste un login admin portal (`ADMIN_API_KEY` bearer) che bypassa OTP customer | ✅ **viable** — da verificare se è il nostro case |
| D — Wait for fix | Aspettare che il team fixi e ritenti | lungo, blocca ogni progresso fase 04 |
| E — Test su altro ambiente | staging / local build SentriKat-web license-server + portal | servirebbe clone e run del repo SentriKat-web locale |

Raccomandazione: Opzione **C (admin portal bypass)** se possibile, perché permette di testare **almeno il lato admin** del portal (fase 05) senza dipendere dal fix OTP. Il lato customer resta bloccato.

---

## Cross-ref

- [04.1.3] è presumibilmente lo stesso cluster di bug SMTP-flow-specific di:
  - [02.4.1] (temp password plaintext welcome SaaS) — welcome email funzionava
  - [03.11.1.2] (SMTP → Mailpit testlab locale) — funzionante localmente
  - Questa è **prod license-server specifically**, con flow OTP email — diverso da welcome

- La ricorrenza "risolto in passato, ora torna" suggerisce **mancanza di regression test** automatico sulla email OTP delivery. Follow-up: aggiungere test E2E playwright su "send OTP → email received via mock SMTP" nella CI pipeline `SentriKat-web/.github/workflows/ci.yml`
