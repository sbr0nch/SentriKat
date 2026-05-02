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
- **Fase 05 (NEW)**: https://github.com/sbr0nch/SentriKat/blob/main/docs/e2e-tests/05-admin-portal.md

---

## 🆕 Batch 2 — Fase 05 Portal Admin (`portal.sentrikat.com/admin/*`) — 2026-04-29

Sessione di apertura Fase 05 sul branch `claude/add-e2e-test-docs-UVya5` ha mappato 8 pagine admin del portal con 8 bug aperti + 4 info. **Tutti i fix sono nel repo `sentrikat-web`**: il portal admin è generato dallo stesso codebase del portal customer (Astro), gira sulla VM Hetzner SaaS, non in locale.

### 🔴🔴 CRITICAL — agire per primo

**`[05.9.1]` — Intera UI admin morta ai click (CSP `script-src-attr` blocca onclick inline)**
- Tutti i bottoni del portal admin sono incliccabili: Sign Out, Export CSV/JSON, campanellina notifiche, "+ New User", "+ New Incident", Probe, Sync from GitHub, Sync NVD, Sync Now, Probe All, Filter, Edit/Disable/Delete, Run Cleanup Now, Refresh, "+ Manual Release", Schedule Maintenance.
- Errore console (4+ warning identici con hash diversi): `Content-Security-Policy: ... script-src 'self' 'nonce-xxx'` blocca inline event handlers in `admin:702:7`.
- Diagnosi: il template HTML usa `onclick=""` inline ma CSP non ha `'unsafe-inline'` né `'unsafe-hashes'` con i hash necessari. Pattern identico a [04.2.1] portal customer (già fixato in `42d7ea0` → `assetsInlineLimit: 0`), qui il regression è sull'admin layout.
- Fix proposto: sostituire `onclick=""` con `data-action="..."` + un singolo `<script nonce="{{ csp_nonce }}">` esterno che fa `addEventListener` sui bottoni. Pattern unobtrusive JS standard.
- File coinvolto: `admin:702:7` → uno dei layout/partial admin (probabilmente sidebar o header condiviso).
- Impatto: il portal admin è in pratica read-only forzato (per bug). L'unico modo di amministrare è API diretta o accesso DB.

### 🔴 HIGH — dopo il CRITICAL

| Bug | Dettaglio | Diagnosi probabile |
|---|---|---|
| `[05.5.1]` | Centralized Logs vuoto (`/admin/logs` Total/Audit/Activation/SaaS = 0) anche durante sessione admin attiva e dopo logout/OTP login fresh | Audit logger non scrive su DB letto dalla pagina, o middleware audit non agganciato alle route admin/auth |
| `[05.6.1]` | `Last Login: -` per super-admin appena loggato via OTP fresh | Auth flow non scrive `last_login_at` (correlato a [05.5.1] — root cause condivisa) |
| `[05.1.1]` | `/admin/releases` mostra 0 releases mentre `/api/health` core dice `1.0.0-beta.6` | Sync GitHub mai eseguito, oppure pipeline release non popola endpoint admin |
| `[05.3.1]` | Data source "Unknown" Critical/Down senza identificativo, no probe history | Seed/migration ha inserito riga senza `name`/`url`, oppure config loader fallisce silenzioso |
| `[05.4.1]` | Status page pubblica dichiara "All systems operational" mentre `[05.3.1]` mostra source DOWN | Status page manuale, non legge probe automatico delle data sources → integrare auto-incident |
| `[05.8.1]` | `RSA_PRIVATE_KEY = NOT SET` in env config admin | UI legge solo env, ma probabile che la chiave sia in vault/DB. UI deve riflettere "configured via vault" |

### 🟡 WARN

- `[05.2.1]` Filter "Community" default su `/admin/kb` mostra "No mappings found" mentre KPI sopra dice 64.697 → cambiare default filter a "All".
- `[05.5.2]` Retention policy: `/admin/logs` dice "365 days" mentre `/admin/settings` dice "730 DAYS" → 1 delle 2 UI è obsoleta, riconciliare.
- `[05.8.2]` `NVD_API_KEY = NOT SET` → NVD sync funziona ma rate-limited. Da configurare prima di scalare.

### 🔵 INFO/UX

- `[05.1.2]` "CVE Findings: 0" su `/admin/releases` → aggiungere tooltip su cosa significa.
- `[05.6.2]` Super-admin di prod usa email gmail personale (`sotadenis94@gmail.com`) → governance smell, creare email custodial aziendale.
- `[05.7.1]` `/admin/runbook` manca "Last updated" timestamp + link al commit GitHub che lo ha modificato.
- `[05.9.2]` Due pagine "audit log" simili: `/admin/logs` (Centralized Logs) e `/admin/audit` (Audit Log dedicated) → unificare o chiarire diff con tooltip.

### Cluster bug correlati (root cause condivisa)

- **Audit logging rotto**: `[05.5.1]` + `[05.6.1]` → middleware audit non agganciato alle route admin/auth. Fixare il middleware (probabilmente nel file `app/auth.py` o middleware FastAPI) risolve entrambi.
- **Status page disonesta**: `[05.4.1]` + `[05.3.1]` → integrare data source health nel status page con auto-incident creation quando una source è Down per >N min.

### Test bloccati da `[05.9.1]` (riprendere DOPO il fix CRITICAL)

9 test follow-up Fase 05 sono bloccati finché la UI non risponde ai click. Vedi sezione "Test follow-up" dentro `05-admin-portal.md` per ogni pagina (Sync from GitHub, Probe, Test Connection, "+ New User", export CSV/JSON, ecc.).

### Riferimento dettagliato

- **Tutti i 23 finding con repro step e fix proposto**: `docs/e2e-tests/05-admin-portal.md` (file completo).
- **Sessione apertura**: branch `claude/add-e2e-test-docs-UVya5`, commit `e99d6cb` → `c8ce89e` su `sbr0nch/SentriKat`.
- **Verify post-fix**: appena `[05.9.1]` è live su `portal.sentrikat.com`, l'utente riaprirà `05-admin-portal.md` e procederà coi test follow-up bloccati (cluster sblocco automatico).

---

## 🛑 UPDATE 2026-04-29 — fix `[05.9.1]` PARZIALE — serve fix one-shot globale

**Verificato live su `portal.sentrikat.com/admin/*`**: il deploy ha fixato SOLO il bottone **Sign Out**. Tutti gli altri `onclick` inline sono ancora rotti. Errori console attuali (sample dalla pagina `/admin/users`):

```
CSP blocked event handler: showCreateUser()      hash: VSJ5UkXbRNeSr8hXxq1rzv47uOHY5ZPLEZP7OlwUbO8=
CSP blocked event handler: hideUserModal()       hash: J0B2g3DjNzi6XLap5osB7P3FVGD3ZYpZXS7s6xNo23U=
CSP blocked event handler: saveUser()            hash: OS6F7RAqovpX/0puMxxPq+DYBxFlfKFnpYpGVEAtwxA=
+ 3 altri unnamed handlers nella stessa pagina
```

E presumibilmente decine di altri in `/admin/releases`, `/admin/datasources`, `/admin/logs`, `/admin/audit`, `/admin/customers`, `/admin/licenses`, `/admin/leads`, `/admin/demo-requests`, `/admin/feedback`, `/admin/support-tickets`, `/admin/response-templates`, ecc.

### Richiesta fix one-shot (NON bug-by-bug)

Tre opzioni in ordine di preferenza tecnica:

**A) (preferito) Sostituire TUTTI gli `onclick="..."` inline nei template admin con `data-action="<id>"` + un singolo `<script nonce="{{ csp_nonce }}">` centralizzato che fa `addEventListener` su `data-action`.** Pattern unobtrusive JS, mantiene CSP strict, fix definitivo.

**B) Aggiungere `'unsafe-hashes'` al CSP + uno script di build che genera lo `sha256` di ogni handler e li inietta nella direttiva.** Più fragile (hash da rigenerare ad ogni cambio template), ma fattibile.

**C) Aggiungere `'unsafe-inline'` allo `script-src-attr`.** 2 minuti di lavoro ma **degrada la security posture** (rinuncia a una difesa CSP). Da considerare solo se A/B sono impraticabili in tempi brevi.

### Comando per identificare TUTTI gli onclick da fixare in colpo solo

Da repo root `sentrikat-web`:

```bash
grep -rn 'onclick=' src/ --include="*.astro" --include="*.html" --include="*.jsx" --include="*.tsx" | wc -l
grep -rn 'onclick=' src/ --include="*.astro" --include="*.html" --include="*.jsx" --include="*.tsx" > /tmp/onclick-audit.txt
```

(adatta i path/estensioni al layout reale di Astro). Il numero totale ti dice la dimensione del refactor. Se >100, opzione A diventa onerosa → considera B (con script generatore hash).

### Bug HIGH non-CSP nello stesso cluster (anche questi NON fixati)

- **`[05.5.1]` Centralized Logs vuoto** — `/admin/logs` mostra Total Logs=0 anche dopo login admin attivo. Audit middleware non agganciato alle route admin/auth.
- **`[05.6.1]` `Last Login: -`** — anche dopo OTP login fresh, `users.last_login_at` non viene scritto. Stessa root cause: l'auth flow del portal admin non emette `user.login` audit event né aggiorna `last_login_at`.

**Fix proposto per questo cluster**: aggiungere alle handler delle route admin/auth (suggerimento: middleware FastAPI/Astro server endpoint) un hook che fa:
1. `INSERT INTO audit_log (...)` per `admin.login`, `admin.logout`, `admin.<resource>.read/write`
2. `UPDATE users SET last_login_at = NOW() WHERE id = <admin_id>` al login

Un solo middleware risolve entrambi.

### Cosa NON fare nel prossimo deploy

- ❌ Non spostare i singoli `onclick` uno per uno (è quello che ha fatto il deploy parziale per Sign Out, e ora ci sono ancora 30+ pagine da girare).
- ✅ Applicare A o B come **single PR globale** che fixa l'intero cluster, poi un commit separato per audit middleware.

### Verify post-fix

Quando avete deployato:
1. Apri `https://portal.sentrikat.com/admin/users` con DevTools console aperta.
2. Devi vedere **zero** errori CSP `script-src-attr` su qualsiasi pagina admin (testare tutte le 8 documentate in `05-admin-portal.md`: `/admin/releases`, `/admin/kb`, `/admin/datasources`, `/admin/status`, `/admin/logs`, `/admin/users`, `/admin/runbook`, `/admin/settings`).
3. Click "**+ New User**" → modal apre. Click "**Save**" su un user fittizio → toast verde + l'utente appare nella lista.
4. `/admin/logs` Total Logs > 0 (deve mostrare almeno l'event `admin.login` di te stesso).
5. `/admin/users` colonna Last Login mostra timestamp di te stesso.

Scrivete un Progress log nello stesso file (sezione "🛑 UPDATE 2026-04-29") con commit hash + branch.

---

## ✅ Progress log — 2026-04-29 (sentrikat-web batch 2 — option A delivered)

**Branch**: `claude/fix-admin-csp-critical-QWC8v` (commit `23ce9da` pushed)

### `[05.9.1]` CRITICAL — admin UI dead under strict CSP — ✅ FIXED (one-shot, option A)

- Single delegated dispatcher in `AdminLayout.astro` nonce'd script: parses call expressions via regex (no `eval`/`new Function`, no `'unsafe-eval'` needed), resolves the function name against `window`, invokes with parsed literal args (`'str'`, `"str"`, numbers, `true|false|null|undefined`, `this`, `this.value`, `event`).
- Verbatim recognition for: `event.stopPropagation()`, `event.preventDefault()`, `if(event.target===this)F()` (modal backdrop), `window.location.href='/x'` (row navigation).
- Bulk attribute migration across **22 files** (AdminLayout + 21 pagine): `onclick=` → `data-action=`, `onchange=` → `data-change-action=`, `oninput=` → `data-input-action=`, `onsubmit=` → `data-submit-action=`. Hover-only `onmouseover` → CSS classes (`.hover-bg-indigo`, `.hover-border-gray`).
- Document-level delegation: dynamically-injected rows (`tbody.innerHTML…`) pick up handlers without rebind.
- Pre-existing kebab-case registry in `saas-tenants` preserved (dispatcher silently no-ops on non-call expressions).
- `npx astro build` clean; rendered `dist/admin/*.html` contains **zero** `on*=` attributes.
- **Acceptance**: zero "Refused to execute inline event handler" violations on every `/admin/*` page; create/save/delete actions, table row navigation, modal open/close, incident toggles, status selects, exports — all firing.

### `[05.5.1]` — already FIXED in earlier batch (commit `31805d6`)

- `/admin/auth/login` emits `LOGIN_SUCCESS` / `LOGIN_FAILED` (with `details.reason`: `missing_credentials` / `invalid_credentials` / `account_deactivated`) on every outcome via `log_admin_action`.
- `/admin/users` POST/PATCH/DELETE emit `ADMIN_ACTION` with operator credit + `target_email`.

### `[05.6.1]` — already FIXED in earlier batch (commit `31805d6`)

- `admin.py:171` writes `user.last_login_at = datetime.utcnow()` on every successful `/admin/auth/login`.
- Customer-side OTP flow (`portal.py:373` `verify_otp`) already writes `customer.last_login_at = datetime.utcnow()`. **Note**: if `/admin/customers` continues to show `-` for a customer after a fresh OTP login, the scenario differs from the original repro and needs precise repro steps (which page, which user, which login flow).

### Deploy

`docker compose up -d --build portal` (license-server unchanged in `23ce9da` — audit/login changes shipped in `31805d6`).

### ✅ User verify 2026-04-29 (sul laptop): "sembra tutto ok in console in ogni sezione"

- Sign Out: ✅ funziona
- Console F12 admin pages: zero CSP errors visibili dall'utente.
- `[05.5.1]` `[05.6.1]` da ri-verificare puntualmente lato `portal.sentrikat.com/admin/users` (last_login admin) e `portal.sentrikat.com/admin/logs` (audit entries) — eseguire dopo aver chiuso il sync core in corso.

---

## ✅ Progress log — 2026-05-01 (sentrikat-web Round 1+2)

**Branch**: `claude/fix-sentrikat-web-handoff-I26pC` (5 commit pushati, no PR auto — la apre l'utente).

| Bug | Sev | Commit | Note tecniche |
|---|---|---|---|
| `[05.13.1]` + `[05.22.1]` | 🔴 | `a1e2169` | Cluster auth: rimossi 2 `verify_admin_key` locali in `newsletter.py` e `ea_tenants.py`, ridiretti alla canonica in `admin.py:95` (accetta sia env API key sia JWT user-token). -36 righe nette. |
| `[05.1.1]` | 🔴 | `b5bcce0` | Estratto `_do_sync_github_releases(db)` helper riusabile + `releases_sync_scheduler()` (boot+60s, poi ogni 6h) registrato accanto agli altri 8 schedulers in `lifespan`. |
| `[05.4.1]` | 🔴 | `6fd0041` | `/api/health/services` ora include `_get_data_sources_health()` che legge ultimo probe per ogni `DataSource` enum + folds nel campo `overall`. Banner pubblico onesto: non più "All Operational" mentre NVD/CVE.org sono DOWN. Aggiunto `data_sources[]` nella response per UI iteration future. |
| `[05.3.1]` | 🔴 | `0679375` | Frontend `datasources.astro` trattava la response come array ma è envelope `{sources:{...}, summary:{...}}` → un solo card bogus "Unknown" status undefined contato come Down. Unwrap via `Object.values(data.sources)`. |
| `[05.8.1]` | 🔴 | `0679375` | `get_system_info` leggeva `os.getenv("RSA_PRIVATE_KEY")`, ma il signer carica da `settings.license_private_key_path` (file). Sostituito con check reale del file. |

### Note tecniche da segnalare al verify

1. Il fix `[05.13.1]`/`[05.22.1]` introduce `from app.api.admin import verify_admin_key` in `ea_tenants.py` e `newsletter.py`. Non circolare oggi (`admin.py` importa da `app.api.provision` ma non da newsletter/ea_tenants). Se in futuro viene aggiunto un import da `admin.py` verso uno di questi due, attenzione.
2. Lo scheduler releases logga warning su HTTPException (es. `GITHUB_TOKEN` non valido) ma non blocca. Se il token è rotto, le release restano vuote silenziosamente — solo log warning. Da verificare al primo boot post-deploy.
3. `[05.4.1]` rispetta semantica `DataSourceStatus.UNKNOWN → 'unknown' → NON peggiora overall`. Se il probe non è mai stato scritto (DB nuovo) il banner resta verde. **Comportamento intenzionale** per evitare falsi positivi al primo boot, MA va chiuso da `[05.3.1]` (seed/migration) — fixato nello stesso round, OK.

### `[05.21.1]` — NOT taken in Round 2 (intenzionale)

**Correzione di premessa importante**: la "4ª fonte" landing **NON è cross-repo**. `landing/` è una directory dentro `sentrikat-web` (mono-repo) — vedi `landing/src/pages/`, `landing/src/components/Pricing.astro`. Confermato dal checkout della sessione web.

Implicazioni:
- Niente handoff a un altro repo per la 4ª fonte.
- Il fix resta strutturale: unificare Pydantic model in `license-server` + Pricing Calculator + Reference table + landing `Pricing.astro`.
- **Round 3 dedicato**, non più "out of scope".

### Verify pending (per l'utente al deploy)

- `[05.13.1]` `/admin/newsletter` subscribers list popola (Active=6 atteso).
- `[05.22.1]` `/admin/saas-tenants` stats card mostra numeri reali (EA Capacity 6/30 atteso).
- `[05.1.1]` `/admin/releases` pagina mostra release (>0 dopo primo cycle scheduler, ~60s dopo boot).
- `[05.4.1]` status pubblico riflette stato reale data sources.
- `[05.3.1]` no più card "Unknown" bogus su `/admin/datasources`.
- `[05.8.1]` UI `RSA_PRIVATE_KEY` mostra `configured` se file presente.

### Round 3 candidates (dopo PR merge)

- `[05.21.1]` 🔴 HIGH — pricing 3-source-of-truth (4ª fonte landing inclusa, mono-repo).
- `[04.2.2]` 🟠 OPEN — Chart.js `new Function()` CSP (admin only, `unsafe-eval` o bundle locale).
- 3 WARN + 11 INFO residui.

---

## ✅ Audit `[05.21.1]` 2026-05-01 — Pricing source-of-truth (REPO STATE VERIFIED)

> Audit completato dalla sessione `claude/fix-sentrikat-web-handoff-I26pC` su `sentrikat-web/main`. Sostituisce la mia ipotesi precedente sulle "4 fonti divergenti", che era imprecisa. **Round 3 deve partire da queste premesse**.

### Stato reale — 3 fonti distinte (non 4)

- **`license-server/app/core/plans_config.py`** è già la **canonical SoT** (docstring esplicito "Centralized product configuration — single source of truth"). Espone `get_full_config()` via `GET /api/v1/admin/config/plans` (admin auth).
- **`portal/src/pages/admin/pricing.astro`** (Calculator + Reference table, **stessa pagina**) legge già `/config/plans` → 100% dinamico.
- **`portal/src/pages/admin/plans.astro`** tenta `/api/v1/admin/saas/plans` (PROXY a `${SAAS_PROVISION_URL}/plans`, ovvero **SaaS core esterno** `sbr0nch/sentrikat`) e fa fallback su `/config/plans`. Il drift `€199/mo 25/5` osservato in test viene da quel proxy → DB del repo core, NON da divergenza nel codice sentrikat-web.
- **`landing/src/components/Pricing.astro:14-147`** è hardcoded (TS const arrays: `saasPlans`, `onPremPlans`, `agentPacks`, `compliancePack`).

### Falsi positivi del mio report originale

- I numeri "€4999 vs €249 vs €199" **NON divergono per lo stesso piano**: sono on-prem Pro, SaaS Pro normale, SaaS Pro proxy-stale rispettivamente. Plus l'EA tier (25 agents 5 users) della landing matcha `EA_CONFIG.plans["pro"]` correttamente.
- Calculator + Reference table contati come 2 fonti separate ma sono la stessa pagina.

### Azioni effettive Round 3 (in ordine, ridotte vs proposta originale)

1. **Public pricing endpoint** — `GET /api/v1/pricing/plans` (no auth, cache-friendly, restituisce `get_full_config()` filtrato per campi pubblici, escludendo chiavi sensibili come `early_access.saas_capacity` se vogliamo).
2. **Landing build-time fetch** — frontmatter di `landing/src/components/Pricing.astro` sostituisce le const arrays con `await fetch(${PUBLIC_API_URL}/api/v1/pricing/plans)` in fase di build (Astro SSG: il fetch si risolve a build time, NO client runtime). Mappare `saasPlans` da `cfg.saas_plans`, `onPremPlans` da `cfg.onprem_editions`, `eaAgents/eaUsers` da `cfg.early_access.plans[<key>]` per preservare la semantica EA-tier corrente.
3. **`/admin/plans` SaaS proxy** — decidere: (a) tenere il primary path verso SaaS core e accettare drift cross-repo, (b) rimuoverlo e leggere solo `/config/plans` (cambia semantica: `/admin/plans` mostra canonical config invece dello stato live del SaaS instance). **Decisione architetturale, NON code-fix.**
4. **Test acceptance** (corretto):
   - `pricing-consistency.test.ts`: builda landing e parsa `dist/`, fa fetch `/api/v1/pricing/plans` in CI, verifica per ogni `(plan_key, field)`: `landing[plan_key].futureMonthlyPrice === api.saas_plans[plan_key].monthly_eur`, `landing.eaAgents === api.early_access.plans[plan_key].max_agents`, ecc.
   - **NON** confrontare numeri raw: confrontare `(prodotto, scope EA/non-EA, plan_key)` deve dare identico valore.
5. **Pydantic model (opzionale)** — `plans_config.py` è dict-based. Refactor a `class PricingPlan(BaseModel)` migliora type safety ma è cosmetico, non urgente.

**Effort stimato**: 1 endpoint pubblico + refactor frontmatter landing + test CI. ~150 righe nette. Niente coordinamento landing-as-other-repo (è mono-repo).

### NON-azioni

- Non creare `license-server/app/pricing.py`: usare il file esistente `plans_config.py`.
- Non toccare `pricing.astro` admin (già dinamico).
- Non toccare i numeri in `plans_config.py` come parte del fix (separato per business decision).

### Decisione architetturale richiesta all'utente prima di Round 3

**Scelta su `/admin/plans` proxy** (punto 3 sopra): mantenere o eliminare? Implicazioni:
- **Mantieni proxy `/saas/plans`**: `/admin/plans` resta "fonte vera" per lo stato live SaaS (multi-tenant). Drift è bug di sync, non architetturale. Va fixato sul SaaS core.
- **Rimuovi proxy**: `/admin/plans` diventa specchio di `/config/plans` (canonical). Perde visibilità su stato live SaaS multi-tenant ma elimina cross-repo drift.

L'utente deve scegliere prima che Round 3 inizi.
