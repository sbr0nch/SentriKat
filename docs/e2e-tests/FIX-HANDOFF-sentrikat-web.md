# FIX HANDOFF — sbr0nch/SentriKat-web

> **Per chi è questo file**: qualunque sessione Claude **scoped a `sbr0nch/SentriKat-web`**. L'utente aprirà una sessione dedicata quando torna al laptop principale (o quando vuole). Questa pagina è self-contained: NON servono altri input dall'utente, tutto il contesto è qui.
>
> **Contesto globale**: stiamo in fase di bug-fixing iterativo del progetto SentriKat. Una sessione parallela sta fixando i bug del repo core `sbr0nch/SentriKat` su branch `claude/resume-e2e-testing-Ro2aJ`. Tu (futura sessione) fixi quelli di `SentriKat-web`. Poi l'utente, su laptop principale con Docker, ritesta tutto e scopre la prossima ondata di bug.
>
> **Scope**: questo handoff elenca **solo** i bug con deployment scope `🌐 landing`, `🏛 portal`, `🔐 license-server`, `📚 docs`, o combinati che toccano SentriKat-web. I bug core (`🏢 on-prem`, `☁️ SaaS`, `🏢☁️ both`, `🚀 release`, `📦 agent`) NON sono qui.

---

## Prerequisiti per la sessione fix

1. **Verifica scope MCP**: le tue istruzioni di sessione devono autorizzare `sbr0nch/SentriKat-web`. Se diversamente, **fermati e avvisa l'utente**.
2. **Branch**: crea branch `claude/fix-sentrikat-web-handoff-<random>` da `main` del repo SentriKat-web.
3. **Lettura preliminare** (via MCP `mcp__github__get_file_contents`):
   - `README.md` del repo per layout generale
   - `landing/package.json` e `landing/astro.config.mjs` (Astro stack)
   - `portal/package.json` (Astro + OTP flow)
   - `license-server/pyproject.toml` o `requirements.txt` (FastAPI)
   - `nginx/` directory structure
   - `docs/` (MkDocs)
4. Leggi questo file dall'alto verso il basso, in **ordine di priorità** (CRITICAL → High → Medium).
5. **Reference**: i file di test originali sono su `main` del repo `sbr0nch/SentriKat`:
   - `docs/e2e-tests/00-INDEX.md` (scope map retroactive, cerca 🌐/🏛/🔐/📚)
   - `docs/e2e-tests/01-landing-site.md`
   - `docs/e2e-tests/02-signup-saas.md`
   - `docs/e2e-tests/04-portal-customer.md`
   
   Leggili via `mcp__github__get_file_contents` con `owner=sbr0nch`, `repo=sentrikat` per il contesto completo di ogni bug.

---

## Ordine di fix consigliato

1. **CRITICAL**: `[04.1.3]` OTP regression (customer bloccato in prod)
2. **High security**: `[02.4.1]` temp password plaintext, `[01.2.1]` CSP fonts, `[01.8.1]` cookie banner, `[01.17.1]` 404 redirect
3. **High UX / i18n**: `[02.2.1]` DE validation, `[02.4.2]` USD→EUR, `[01.16.4]` security.txt langs
4. **Medium/Low**: gli altri info/UX

Dopo ogni fix:
- Commit con ID nel messaggio (es. `fix(license-server): wrap OTP send with explicit error handling [04.1.3]`)
- Pusha sul branch di fix
- Aggiungi una riga nel progress log di questo file (in fondo) con il SHA del commit
- NON creare PR prima che l'utente lo chieda

---

## Bug list per fase

### 🔴 CRITICAL

---

#### `[04.1.3]` OTP email non arriva (regressione post-2026-04-22)

- **Scope**: 🔐 license-server
- **Severity**: CRITICAL (customer non può mai loggare in portal prod)
- **Path sospetto**: `license-server/app/` — cercare il route `POST /api/v1/portal/auth/request-otp` e la funzione che manda l'email OTP
- **Prime suspect**: PR #231 (2026-04-22) `fix(license-server): wrap all enqueue_webhook_event call-sites in try/except`
  - Quel patch ha wrappato anche il send-email path? Se sì, un'eccezione reale (credenziali SMTP, quota SES, rate limit) viene **swallow silently** → endpoint risponde 200 OK ma email non parte
- **Repro**: `POST /api/v1/portal/auth/request-otp` con email valida registrata → risposta 200 OK ma nessuna email arriva (verificato in prod 2026-04-25)
- **Fix direzione**:
  1. Aprire diff di PR #231 — identificare i try/except aggiunti
  2. Controllare se coprono il path `send_otp_email()` (o equivalente)
  3. **Non rimuovere il try/except** (il motivo originale era proteggere un flow webhook), ma:
     - Log `logger.error(...)` con l'eccezione dentro l'except
     - Se l'email fallisce, response deve essere `500 {"error":"email_service_unavailable"}` (NOT silent 200)
     - **Alternativa migliore**: separare try/except del webhook outbox dal send-email path — il send-email non dovrebbe mai essere wrappato
  4. Testare manualmente con SMTP mock locale che l'errore viene propagato
- **Acceptance**:
  - Request OTP con email valida + SMTP funzionante → email arriva + 200
  - Request OTP con SMTP intenzionalmente rotto → 500 con error specifico + log server con stacktrace
- **Ref**: `docs/e2e-tests/04-portal-customer.md` linee 52-114 su `sbr0nch/sentrikat` main

---

### 🔴 High

---

#### `[02.4.1]` Temp password in chiaro nel welcome email SaaS signup

- **Scope**: ☁️ SaaS + 🔐 license-server (template email)
- **Severity**: Medium-High (security)
- **Path sospetto**: `license-server/app/` — grep `"Temporary Password"` o `"TEMPORARY PASSWORD"` (stringa letterale) + `"922DaVMks3giMNhI"` no, cercare template engine usato (probabile Jinja2)
- **Altre location da controllare**: se il template è nel core Flask `SentriKat/app/templates/` o `app/email_alerts.py`, allora **è fuori scope** di questa sessione. In tal caso: documenta nel fix che hai verificato e cross-reference.
- **Attack model**: password in plaintext su SMTP = compromessa se attaccante ha accesso all'inbox. Best practice moderne: magic link o OTP a ogni login.
- **Fix direzione (preferred)**:
  1. Sostituire "temp password" con **magic link** one-time (token firmato, scade 15 min) che porta a pagina `/first-login` dove user imposta password
  2. Oppure (soluzione minima): rimuovere la password dal body e aggiungere "Use 'Forgot password?' on the login page to receive a reset link"
- **Fix minimo accettabile**: rimuovere la linea `TEMPORARY PASSWORD: xxx` dal body e sostituire con flow "reset password via forgot-password"
- **Acceptance**: email welcome non contiene password in chiaro. Documentare il nuovo flow primo-login.
- **Ref**: `docs/e2e-tests/02-signup-saas.md` linee 128-163

---

#### `[01.17.1]` 404 redireziona alla home invece di servire 404.html

- **Scope**: 🌐 landing + nginx
- **Severity**: High (SEO + UX)
- **Path sospetto**: `nginx/sites/sentrikat.com.conf` (o `nginx/conf.d/*.conf`), verificare regola `try_files` / `error_page`
- **Repro**: apri `https://sentrikat.com/pagina-che-non-esiste-12345` → viene rediretto a `/` con status 200 invece di servire `/404.html` con status 404
- **Fix direzione**:
  1. Verificare che la build Astro produca `landing/dist/404.html` (il source `landing/src/pages/404.astro` esiste)
  2. In nginx config:
     ```nginx
     error_page 404 /404.html;
     location = /404.html { internal; }
     # rimuovere eventuale try_files fallback a /index.html per path non-asset
     ```
  3. Verificare Cloudflare page rules — se c'è wildcard redirect a `/`, rimuoverlo
- **Acceptance**: `curl -I https://sentrikat.com/xxx-nonexistent` → `HTTP/1.1 404 Not Found` + body di `404.html`
- **Ref**: `docs/e2e-tests/01-landing-site.md` linee 246-278

---

#### `[01.2.1]` CSP blocca Google Fonts stylesheet

- **Scope**: 🌐 landing (potenzialmente nginx se CSP è header-based)
- **Severity**: Medium (fallback font usato, ma FOUT visibile + brand typography non applicata)
- **Path sospetto**: cercare definizione CSP in **due posti**:
  1. `nginx/` — `add_header Content-Security-Policy "..."`
  2. `landing/src/layouts/Layout.astro` — meta tag `<meta http-equiv="Content-Security-Policy" ...>`
- **Fix direzione**:
  - Preferito: **self-host dei font** (GDPR-friendly, niente dipendenza esterna, niente CSP issues). Scaricare Inter + JetBrains Mono, servire da `landing/public/fonts/`, usare `@font-face`
  - Fallback (minimo): aggiungere a CSP:
    - `style-src 'self' 'unsafe-inline' https://fonts.googleapis.com`
    - `font-src 'self' https://fonts.gstatic.com data:`
- **Acceptance**: nessun errore CSP in console browser visitando `https://sentrikat.com`; font Inter renderizzato correttamente
- **Ref**: `docs/e2e-tests/01-landing-site.md` linee 47-76

---

#### `[01.8.1]` Cookie banner non visibile al primo load

- **Scope**: 🌐 landing
- **Severity**: High (compliance GDPR / ePrivacy)
- **Path sospetto**: `landing/src/components/CookieBanner.astro` (componente esiste) + `landing/src/layouts/Layout.astro` (verificare import)
- **Diagnosi preliminare (via code reading)**:
  1. Controllare se `<CookieBanner />` è importato/usato in `Layout.astro`
  2. Se sì, verificare condizione di rendering (es. potrebbe essere dietro a `{client:load}` o a una env var)
  3. Verificare CSS: `z-index`, `display`, visibility, viewport (potrebbe essere off-screen)
  4. Controllare localStorage key check: se il componente controlla `sentrikat_cookie_consent` e lo trova già settato per visite pregresse, non si mostra → comportamento corretto solo se utente ha dismesso. Incognito dovrebbe resettare
- **Fix direzione**: dipende dalla causa. Se import mancante → aggiungere in Layout. Se CSS → correggere. Se build non include componente → Astro config.
- **Acceptance**: fresh incognito `https://sentrikat.com` → banner appare in basso con CTA dismiss
- **Ref**: `docs/e2e-tests/01-landing-site.md` linee 295-319

---

#### `[02.2.1]` Validazione checkbox terms in TEDESCO

- **Scope**: 🌐 landing
- **Severity**: Medium (UX — messaggio in lingua sbagliata)
- **Path sospetto**: `landing/src/components/TrialSignup.astro` (checkbox `accepted_terms`)
- **Root cause**: HTML attributo nativo `required` usa la lingua del browser per tooltip (se Chrome DE → messaggio DE). Sito è EN-only.
- **Fix direzione**:
  ```astro
  <script>
    const cb = document.querySelector('input[name="accepted_terms"]');
    cb.addEventListener('invalid', (e) => {
      e.target.setCustomValidity('Please accept the Terms to continue');
    });
    cb.addEventListener('input', (e) => e.target.setCustomValidity(''));
  </script>
  ```
- **Acceptance**: utente su Chrome DE/FR/IT — submit senza checkbox checked → messaggio custom in EN
- **Ref**: `docs/e2e-tests/02-signup-saas.md` linee 56-76

---

### 🟡 Warning / Medium

---

#### `[02.4.2]` Welcome email usa `$` USD invece di `€` EUR

- **Scope**: ☁️ SaaS + 🔐 license-server (template email)
- **Severity**: Medium (coerenza brand)
- **Path sospetto**: stesso template di `[02.4.1]` — cercare `"$0"` o `"Starter (Early Access"` nel template
- **Fix direzione**: sostituire `$` con `€` nella display price del plan. Preferibilmente leggere `Plan.currency` dinamicamente invece di hardcodare.
- **Acceptance**: welcome email mostra `Starter (Early Access — €0)` non `$0`
- **Ref**: `docs/e2e-tests/02-signup-saas.md` linee 165-184

---

#### `[01.9.1]` Post blog IT su sito EN-only senza language switcher

- **Scope**: 🌐 landing + 📚 docs
- **Severity**: Medium (UX / i18n gap)
- **Fix direzione** — tre opzioni:
  - A: rimuovere i post IT dal blog pubblico (se non strategici)
  - B: aggiungere un badge visivo `[IT]` accanto al titolo nel blog index + intro text "This post is in Italian"
  - C: introdurre i18n completa con language switcher (overkill per ora)
- **Path**: `landing/src/pages/blog/` + `landing/src/content/blog/` (schema Astro)
- **Acceptance**: discusso con utente quale opzione. Default: **opzione B** (meno invasiva, segnala chiaramente)
- **Cross-ref**: `[01.12.3]` stesso problema sul blog index
- **Ref**: `docs/e2e-tests/01-landing-site.md` linee 324 (01.9.1) + 375 (01.12.3)

---

### 🔵 Info / UX (low priority, batch dopo high)

---

#### `[01.12.3]` Blog index manca badge lingua su post IT

- **Scope**: 🌐 landing
- **Fix**: insieme a `[01.9.1]` — stesso fix

#### `[01.16.1]` `sitemap-index.xml` contenuto da verificare

- **Scope**: 🌐 landing
- **Severity**: Info (probabile OK, da validare)
- **Fix**: verificare che `sitemap-0.xml` contenga tutti gli URL pubblici (home, pricing, blog, vs/, terms, ecc.) e NON contenga `/impressum` (se escluso dalla sitemap intenzionalmente)

#### `[01.16.4]` `security.txt` dichiara IT+DE su sito EN-only

- **Scope**: 🌐 landing
- **Severity**: Info
- **Fix**: rimuovere `Preferred-Languages: it, de, en` → `Preferred-Languages: en` (coerente con sito EN). Path: `landing/public/.well-known/security.txt`

#### `[02.3.2]` Alias Gmail `+tag` bloccati con 409 (UX review)

- **Scope**: 🔐 license-server
- **Severity**: Info (feature è voluta per prevenire abuse capacity 30-account cap, ma UX potrebbe essere migliorata)
- **Fix proposta (minima)**: se `+tag` detection scatta, response 409 con messaggio esplicito: `"Email aliases (e.g., you+tag@gmail.com) are not accepted. Please use your main email address."` invece di "Email already registered"
- **Path sospetto**: route `/api/v1/provision/trial` + funzione validazione email

#### `[02.4.5–4.8]` Email deliverability hardening (SPF/DKIM/DMARC, reply-to, List-Unsubscribe)

- **Scope**: 🔐 license-server + DNS config (ops)
- **Severity**: Info (follow-up da testare, non bug confermati)
- **Fix**: validare configurazione DNS SPF/DKIM/DMARC per dominio `sentrikat.com`. Aggiungere header `Reply-To: support@sentrikat.com` e `List-Unsubscribe: <mailto:unsubscribe@...>` al template email template.
- **Tool**: https://www.mail-tester.com/ con l'email di welcome per score

---

## Cross-repo concerns

Alcuni bug potrebbero avere il fix **sia** in SentriKat-web **sia** in SentriKat core (es. template email). Regole:

- Se grep nel repo SentriKat-web NON trova la stringa/route → il bug è in SentriKat core → **documentalo qui come "confirmed not in SentriKat-web, needs fix in sentrikat core"** e passa al prossimo.
- Se trovi la stringa/route in entrambi i repo → fix nel repo dove è chiamata in runtime (probabilmente solo uno).

---

## Dopo aver finito i fix

1. **Non mergiare la PR** — lascia che l'utente la riveda sul laptop principale con Docker per riprodurre la repro
2. Lista tutti i commit nel progress log qui sotto
3. Nel PR body, elenca i bug ID fixati in ordine di severity
4. Chiedi all'utente di verificare i fix uno per uno con i test e2e originali (puntando alle linee dei file `docs/e2e-tests/*.md` sul repo core)

---

## Progress log (da aggiornare mano a mano dalla sessione SentriKat-web)

Sessione SentriKat-web aperta **2026-04-26** su branch `claude/fix-sentrikat-e2e-handoff-gsI9M` (poi PR aperta dall'utente). **12/12 bug del handoff fixati**, 9 commit atomici, HEAD `b766153`.

| Data | Bug ID | Commit SHA | Note |
|---|---|---|---|
| 2026-04-26 | 04.1.3 | `524208b` | OTP CRITICAL: `logger.exception` in `send_email` + `await` sincrono in `/portal/auth/request-otp`, restituisce 500 on fail invece di 200 bugiardo. **Root cause reale**: `send_email` + `BackgroundTasks` catturavano ogni eccezione con `print(...)` → response sempre 200 anche su fallimento SMTP. **PR #231 NON era la causa** (nonostante sospetto nell'handoff) |
| 2026-04-26 | 02.4.1 | `0f93867` | SaaS welcome email: rimossa temp password plaintext, redirect a flow forgot-password (OTP). File: `license-server/app/{core/email,api/trial,api/payments}.py` |
| 2026-04-26 | 02.4.2 | `0f93867` | Welcome email: `$0` → `€0` (co-fix con 02.4.1) |
| 2026-04-26 | 01.17.1 | `06f157d` | `landing/nginx.conf`: `try_files … =404` + `error_page /404.html` invece di fallback a `/` |
| 2026-04-26 | 01.2.1 | `dec104a` | `nginx/sites/landing.conf` CSP: aggiunti `fonts.googleapis.com` in `style-src` + `fonts.gstatic.com` in `font-src`. Self-hosting fonts resta follow-up |
| 2026-04-26 | 01.8.1 | `e339bdd` | `CookieBanner.astro`: rewrite difensivo — inline `style.display` + `localStorage` try/catch + `DOMContentLoaded` listener. Copre le 3 cause plausibili senza poter riprodurre |
| 2026-04-26 | 02.2.1 | `004d25c` | `TrialSignup.astro`: `setCustomValidity("Please accept…")` EN sul terms checkbox invalid, bypassa il tooltip native browser locale-based |
| 2026-04-26 | 01.16.4 | `bd7bf25` | `security.txt` (entrambe le copie): `Preferred-Languages: en` (era `en, it, de` su sito EN-only) |
| 2026-04-26 | 01.9.1 | `beb7d27` | Blog i18n minimale (Option B): schema `lang`, frontmatter `lang: it` sul post IT, badge amber in index + layout |
| 2026-04-26 | 01.12.3 | `beb7d27` | co-fix con 01.9.1 |
| 2026-04-26 | 01.16.1 | — | Verified only: `astro.config.mjs` filtra `/impressum` correttamente, no fix needed |
| 2026-04-26 | 02.3.2 | `b766153` | `trial.py` helper `_dup_signup_detail` → messaggio specifico `EMAIL_ALIAS_NOT_ACCEPTED` sul 409 con `+tag`; frontend specializza UI message. Interpretazione "specialize" scelta rispetto a "block upfront" (meno invasiva, mantiene dedup canonico) |
| 2026-04-26 | **04.2.1** | `42d7ea0` | **NUOVO BUG scoperto durante verify round 1**: portal stuck su "Verifying authentication..." per CSP che bloccava inline scripts da Astro/Vite. Root cause: M-7 nonce-CSP (commit `93b9c42` 16-apr) richiede `__CSP_NONCE__` placeholder che `sub_filter` nginx sostituisce, ma Vite inlinea script `<4KB` automaticamente senza placeholder. Fix 1-line: `assetsInlineLimit: 0` in `portal/astro.config.mjs` → tutti script emessi come `/_astro/*.js` esterni autorizzati da `script-src 'self'`. Sicurezza M-7 invariata. ✅ VERIFIED post-rebuild |
| 2026-04-26 | **04.2.2** | — | **NUOVO BUG OPEN — non fixato**: Chart.js usa `new Function()` per animazioni → bloccato da `script-src` senza `'unsafe-eval'`. Impact: solo pagine portal `/admin/*` (Chart.js non caricato in dashboard cliente). Da fixare separatamente: bundling locale di Chart.js con tree-shake animazioni, oppure aggiungere `unsafe-eval` (security degrade). Sessione dedicata necessaria |

### ⚠️ Non fixati — da discutere architetturalmente

**[02.4.5–4.8] Email deliverability hardening** (SPF/DKIM/DMARC/Reply-To/List-Unsubscribe):
- Classificati come `Info` nel handoff perché richiedono:
  - Modifiche DNS (ops, non code) per SPF/DKIM/DMARC — fuori scope code-fix
  - Test reali con `mail-tester.com`
  - Decisione architetturale su Reply-To mailbox e endpoint `List-Unsubscribe` one-click RFC 8058
- **Raccomandazione altra sessione**: trattarli in una sessione/issue dedicata, non nel batch fix
- **TODO mio**: quando torni al laptop principale decidere se aprire issue separata o rimandare al testing round 2

### Scelte di design che hanno richiesto giudizio (documentate dall'altra sessione)

1. **[04.1.3]**: fix con propagazione sincrona (converti `request_otp` a `async def`, drop `BackgroundTasks`) per soddisfare criterio "500 con error specifico". Refactor contenuto a una route
2. **[01.2.1]**: fallback allow-list CSP invece di self-hosting — consistente con disclosure già presente in `/privacy` verso Google Fonts. Self-hosting resta follow-up
3. **[01.8.1]**: non riproducibile nel browser, rewrite difensivo che copre tutte e 3 le cause plausibili
4. **[01.9.1]**: Option B (default del handoff) — badge IT + nota italic "This post is in Italian", senza i18n completo
5. **[02.3.2]**: interpretazione "specialize message" invece di "block upfront"

---

## Riferimenti veloci

- Master index test: https://github.com/sbr0nch/SentriKat/blob/main/docs/e2e-tests/00-INDEX.md
- Scope map retroactive (cerca label 🌐/🏛/🔐/📚): sezione "Scope map — retroactive" del master
- Fase 01: https://github.com/sbr0nch/SentriKat/blob/main/docs/e2e-tests/01-landing-site.md
- Fase 02: https://github.com/sbr0nch/SentriKat/blob/main/docs/e2e-tests/02-signup-saas.md
- Fase 04: https://github.com/sbr0nch/SentriKat/blob/main/docs/e2e-tests/04-portal-customer.md
