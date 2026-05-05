# Fase 01 — Landing Site (`sentrikat.com`)

> Test end-to-end della landing pubblica Astro (`SentriKat-web/landing`). Include: navigazione, rendering, form pubbliche, pagine marketing, blog, compliance, legal, SEO artifacts (sitemap, RSS).

## Aree coperte

| Area | Descrizione | Sotto-test |
|---|---|---|
| 01.1 | Performance | load time, asset weight, cache headers |
| 01.2 | Console / CSP | JS errors, CSP violations, mixed content |
| 01.3 | HTTPS & Security headers | cert, HSTS, X-Frame, CSP policy |
| 01.4 | Navbar | link, CTA, rendering, hover, sticky |
| 01.5 | Hero | titolo, CTA, animazioni |
| 01.6 | Home sections (scroll) | Features, Pricing, FAQ, ComplianceBadges, DeploymentModes, ecc. |
| 01.7 | Footer | link, email, social |
| 01.8 | Cookie banner / privacy | rendering, consent, localStorage |
| 01.9 | i18n / lingua | EN only vs contenuti IT |
| 01.10 | Responsive (mobile/tablet) | hamburger menu, breakpoints |
| 01.11 | Pagine marketing (Features, Pricing, Compare, Trust, NIS2, Integrations, Compliance, SBOM, Roadmap, Changelog, Security, SLA, Status, About, FAQ, Integrations) | rendering + CTA + link interni |
| 01.12 | Blog (`/blog`, `/blog/[slug]`) | 14 post, frontmatter, RSS, sitemap |
| 01.13 | Vs pages (`/vs/tenable`, `/vs/qualys`, `/vs/rapid7`, `/vs/snyk`, `/vs/openvas`, `/vs/dependabot`) | 6 SEO pages |
| 01.14 | Legal / trust (`/terms`, `/privacy`, `/dpa`, `/eula`, `/impressum`, `/subprocessors`, `/disclosure`, `/sla`, `/ea-terms`) | rendering, versioning, link mutuali |
| 01.15 | Form pubbliche (Contact, Demo, Contact-Sales, Feedback) | validazione UI, Turnstile, eventuali edge |
| 01.16 | SEO artifacts | `sitemap-index.xml`, `rss.xml`, `robots.txt`, `security.txt`, Open Graph tags |
| 01.17 | 404 page | rendering, link ritorno |
| 01.18 | Capacity check | `GET /api/v1/provision/trial/capacity` chiamata da Pricing |

---

## 01.1 — Performance

### [01.1.1] Load iniziale "velocissimo" ✅

- **Fase**: 01 — Landing site
- **Area**: Performance
- **URL**: `https://sentrikat.com`
- **Tipo**: 🟢 OK
- **Environment**: prod
- **Expected**: load rapido (Astro static build, no hydration pesante)
- **Actual**: caricamento velocissimo
- **Discovered**: 2026-04-23

---

## 01.2 — Console / CSP

### [01.2.1] CSP blocca il caricamento del Google Font stylesheet

- **Fase**: 01 — Landing site
- **Area**: Console / CSP
- **URL**: `https://sentrikat.com` (home)
- **Tipo**: 🔴 Bug
- **Severity**: Medium (fallback font usato, ma FOUT visibile e brand typography non applicata — Inter/JetBrains Mono sono la font family del brand)
- **Environment**: prod
- **Steps to reproduce**:
  1. Apri `https://sentrikat.com`
  2. Apri DevTools → Console
  3. Osserva il primo errore al load
- **Expected**: font Inter e JetBrains Mono caricati da `fonts.googleapis.com`
- **Actual**: console error:
  ```
  Loading the stylesheet 'https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700;800&family=JetBrains+Mono:wght@400;500;600&display=swap'
  violates the following Content Security Policy directive: "style-src 'self' 'unsafe-inline'".
  Note that 'style-src-elem' was not explicitly set, so 'style-src' is used as a fallback.
  The action has been blocked.
  ```
- **Root cause ipotesi**: il CSP header impostato da nginx (o meta tag) manca di `https://fonts.googleapis.com` in `style-src` (o `style-src-elem`) e manca `https://fonts.gstatic.com` in `font-src`.
- **Fix candidato**: aggiornare policy CSP in `SentriKat-web/nginx/nginx.conf` o dove è definita:
  ```
  style-src 'self' 'unsafe-inline' https://fonts.googleapis.com;
  font-src 'self' https://fonts.gstatic.com data:;
  ```
  In alternativa: self-host dei font per eliminare la dipendenza esterna (privacy GDPR-friendly, niente CSP issues, niente hit su Google).
- **File sospetto**: `SentriKat-web/nginx/*.conf` oppure `landing/src/layouts/Layout.astro` (se CSP è via meta)
- **Discovered**: 2026-04-23

---

## 01.3 — HTTPS & Security headers

### [01.3.1] Certificato TLS valido ✅

- **Tipo**: 🟢 OK
- **Actual**: certificato valido, nessun warning
- **Discovered**: 2026-04-23
- **Follow-up (da testare in 01.3.2)**: verificare con `curl -I https://sentrikat.com` che ci siano header HSTS, X-Frame-Options, X-Content-Type-Options, Referrer-Policy, Permissions-Policy — **TODO**.

---

## 01.4 — Navbar

### [01.4.1] Navbar links presenti ✅

- **Fase**: 01
- **Area**: Navbar
- **Tipo**: 🟢 OK
- **Actual**: link visibili in ordine:
  `[Logo + wordmark SentriKat]` (anchor unico verso `/`) · `Features` · `Pricing` · `Compare` · `Trust` · `Blog` · `Docs` (external → `docs.sentrikat.com`) · `Community` (external → `community.sentrikat.com`) · `Sign In` (→ `portal.sentrikat.com`) · `Join Early Access` (→ `/#trial`)
- **Note**: confermato — il "doppio SentriKat" era solo artefatto del copia/incolla (logo SVG + testo wordmark nello stesso `<a>`).
- **Follow-up TODO**: in 01.10/responsive confermare che hover style e sticky on scroll funzionino; verifica esplicita che gli `href` corrispondano ai domini sopra (test 01.4.2).
- **Discovered**: 2026-04-23

---

## 01.5 — Hero

### [01.5.1] Hero rendering corretto ✅

- **Tipo**: 🟢 OK
- **Actual**: hero section rendering corretto, tutto a posto
- **Follow-up TODO**: in 01.6 verificare animazioni Framer Motion, CTA hover, scroll indicator.
- **Discovered**: 2026-04-23

---

## 01.6 — Home sections (scroll)

### [01.6.1] Tutte le sezioni della home presenti e correttamente renderizzate ✅

- **Fase**: 01
- **Area**: Home sections (scroll)
- **URL**: `https://sentrikat.com`
- **Tipo**: 🟢 OK
- **Environment**: prod
- **Sezioni verificate (ordine atteso da repo)**:
  Hero · WhyDifferent · Features · HowItWorks · MultiSourceIntel · DeploymentModes · ContainerScanning · AgentDeploy · SecurityScore · ComplianceBadges · SwissFocus · TrustedBy · Pricing (embed `#pricing`) · FAQ · TrialSignup form (`#trial`) · BetaBanner/EarlyAccessBanner
- **Actual**: utente conferma "tutto ok qui" per il giro completo dall'alto al basso
- **Note**: nessuna sezione mancante segnalata, nessun layout/animazione rotta, ordine sezioni corretto. Form Trial visibile (test funzionale del submit rinviato a 01.15 + fase 02).
- **Discovered**: 2026-04-23

---

## 01.11 — Pagine marketing

### [01.11.1] Tutte le pagine marketing raggiungibili via footer ✅

- **Fase**: 01
- **Area**: Pagine marketing
- **Tipo**: 🟢 OK
- **Environment**: prod
- **Pagine verificate** (aperte via link footer in 01.7.1):
  `/features` · `/pricing` · `/compare` · `/integrations` · `/nis2` · `/compliance` · `/sbom` · `/trust` · `/security` · `/sla` · `/status` · `/roadmap` · `/changelog` · `/about` · `/faq` · `/contact`
- **Actual**: tutte raggiungibili, tutte rendering OK (200, nessun 404)
- **Note**: test rendering profondo (CTA, Turnstile, layout interno) rinviato a 01.15 per le pagine con form; per le altre basta il pass di footer.
- **Discovered**: 2026-04-23

---

## 01.14 — Legal / trust

### [01.14.1] Tutte le pagine legali raggiungibili via footer ✅

- **Fase**: 01
- **Area**: Legal
- **Tipo**: 🟢 OK
- **Environment**: prod
- **Pagine verificate** (tutte nel footer, testate in 01.7.1):
  `/terms` · `/privacy` · `/dpa` · `/eula` · `/impressum` · `/subprocessors` · `/disclosure` · `/sla` · `/ea-terms` · `/feedback`
- **Actual**: tutte 200 OK, rendering corretto
- **Follow-up TODO**: verificare in un secondo passaggio che
  - `terms_version` (visto in TrialSignup = `2026-02-09`) sia coerente tra `/terms` e `/ea-terms`
  - link mutuali tra documenti non siano rotti (es. `/dpa` che linka `/subprocessors`)
  - versione datata visibile in ogni pagina (`Last updated: ...`)
  - `/impressum` sia escluso dal sitemap (come da config `astro.config.mjs`)
- **Discovered**: 2026-04-23

---

## 01.13 — Vs pages (comparative SEO)

### [01.13.1] Tutte le 6 pagine comparative raggiungibili ✅

- **Fase**: 01
- **Area**: Vs pages
- **Tipo**: 🟢 OK
- **Environment**: prod
- **Pagine verificate**: `/vs/tenable` · `/vs/qualys` · `/vs/rapid7` · `/vs/snyk` · `/vs/openvas` · `/vs/dependabot`
- **Actual**: tutte 200 OK, tutte rendering OK
- **Follow-up TODO**: verificare che ogni pagina abbia contenuto unico (feature comparison table), non siano template clonati con stesso testo — rilevante per SEO (Google penalizza duplicate content).
- **Discovered**: 2026-04-23

---

## 01.16 — SEO artifacts

### [01.16.1] `sitemap-index.xml` presente, formato corretto 🔵

- **Fase**: 01
- **Area**: SEO artifacts
- **URL**: `https://sentrikat.com/sitemap-index.xml`
- **Tipo**: 🔵 Info (OK ma con follow-up)
- **Environment**: prod
- **Actual**: XML valido, contiene riferimento a `https://sentrikat.com/sitemap-0.xml`:
  ```xml
  <sitemapindex xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">
    <sitemap>
      <loc>https://sentrikat.com/sitemap-0.xml</loc>
    </sitemap>
  </sitemapindex>
  ```
- **Follow-up TODO (01.16.1a)**: aprire `https://sentrikat.com/sitemap-0.xml` e verificare:
  1. Contiene TUTTE le pagine pubbliche (home, features, pricing, compare, trust, nis2, compliance, sbom, integrations, security, sla, status, roadmap, changelog, about, faq, contact, contact-sales, ea-terms, terms, privacy, dpa, eula, subprocessors, disclosure, feedback + 6 vs/* + 14 blog post)
  2. `/impressum` è **escluso** (come da `astro.config.mjs` → `exclude: ['/impressum']`)
  3. Ogni URL ha `<lastmod>` popolato
- **Discovered**: 2026-04-23

### [01.16.2] `robots.txt` corretto ✅

- **Tipo**: 🟢 OK
- **Actual**: utente conferma formato corretto (User-agent + Sitemap reference)
- **Discovered**: 2026-04-23

### [01.16.3] `rss.xml` feed blog OK ✅

- **Tipo**: 🟢 OK
- **URL**: `https://sentrikat.com/blog/rss.xml`
- **Actual**: feed XML valido, conforme
- **Follow-up TODO**: verificare che tutti i 14 post siano presenti nel feed e che abbiano `pubDate`, `description`, `category`
- **Discovered**: 2026-04-23

### [01.16.4] `security.txt` RFC 9116 compliant ✅ + nota i18n

- **Fase**: 01
- **Area**: SEO artifacts / Security disclosure
- **URL**: `https://sentrikat.com/.well-known/security.txt`
- **Tipo**: 🟢 OK / 🔵 Info follow-up
- **Actual**:
  ```
  Contact: mailto:security@sentrikat.com
  Expires: 2027-03-28T00:00:00.000Z
  Encryption: mailto:security@sentrikat.com
  Preferred-Languages: en, it, de
  Canonical: https://sentrikat.com/.well-known/security.txt
  Policy: https://sentrikat.com/disclosure
  ```
- **Osservazione**: dichiara `Preferred-Languages: en, it, de` ma il sito è attualmente EN-only (vedi 01.9.1). Incoerenza minore: se il security team davvero risponde in IT e DE è OK; se è un default del template va corretto.
- **Anomalia minore**: campo `Encryption:` punta a una `mailto:` invece di una chiave PGP o URL di una chiave (formato inusuale ma tollerato dalla RFC 9116 se l'intenzione è dire "contattaci per ottenere la chiave"). Convenzione più comune è `Encryption: https://example.com/pgp-key.txt` o OpenPGP fingerprint.
- **Rafforza**: bug [01.9.1] i18n — se dichiariamo `Preferred-Languages: en, it, de`, i contenuti pubblici dovrebbero esserlo (o quantomeno la disclosure policy deve essere tradotta).
- **Follow-up TODO**: aprire `https://sentrikat.com/disclosure` e controllare che la pagina di policy esista e sia coerente (linkata da `Policy:`).
- **Discovered**: 2026-04-23

---

## 01.17 — 404 page

### [01.17.1] 404 redireziona alla home invece di mostrare pagina 404 custom

- **Fase**: 01
- **Area**: 404 page
- **URL**: `https://sentrikat.com/sicuramente-non-esiste-questa-pagina-12345` (o qualsiasi path inesistente)
- **Tipo**: 🔴 Bug
- **Severity**: High (SEO + UX + potenziale spam risk)
- **Environment**: prod
- **Steps to reproduce**:
  1. Apri `https://sentrikat.com/path-che-non-esiste`
  2. Osserva la barra URL e il contenuto
- **Expected**: pagina 404 custom con status HTTP 404, branding coerente, CTA "Torna alla home" (il repo contiene `landing/src/pages/404.astro`)
- **Actual**: il browser viene **rediretto alla home** (presumibilmente 301/302 → 200 su `/`)
- **Impatto**:
  - **SEO critico**: Google Search Console riceve 200 su URL fantasma → indicizzazione duplicata di contenuto home su infiniti path → risk penalty "soft 404" o duplicate content
  - **UX**: utente che sbaglia URL (typo, link rotto esterno, share obsoleto) non capisce dove è finito
  - **Attack surface**: qualunque URL trashy viene loggato come 200 nelle analytics, polluting metriche; path enumeration attacker non riceve segnale "not found"
  - **Link rot recovery**: un redirect SEO-safe per URL rinominati è accettabile, ma un catch-all 200 wildcard è sbagliato
- **Root cause ipotesi**:
  - Regola nginx con `try_files ... /index.html;` che fallback a home invece che al file `404.html` generato da Astro
  - Oppure regola Cloudflare / redirect rule configurata come wildcard
  - Oppure configurazione Astro `output: 'static'` senza abbinare il 404 al path richiesto
- **Fix candidato**:
  - In `SentriKat-web/nginx/sites/sentrikat.com.conf` (o equivalente): assicurarsi che nginx serva `404.html` con status 404 per path sconosciuti
    ```nginx
    error_page 404 /404.html;
    location = /404.html { internal; }
    ```
  - Verificare che la build Astro produca `dist/404.html` (sì, 404.astro esiste nel repo)
  - Rimuovere eventuali catch-all redirect a `/` su Cloudflare
- **File sospetto**: `SentriKat-web/nginx/*.conf` (config reverse proxy) o page rules Cloudflare esterne al repo
- **Verifica aggiuntiva (da chiedere utente next)**: aprire DevTools → Network → visitare URL inesistente → guardare lo status code della prima richiesta. Se è 301/302 è un redirect lato server; se è 200 è un rewrite/fallback a index.
- **Discovered**: 2026-04-23

---

## 01.7 — Footer

### [01.7.1] Tutti i link footer risolvono correttamente ✅

- **Tipo**: 🟢 OK
- **Actual**: tutti i link del footer sono validi (200 OK, nessun 404)
- **Discovered**: 2026-04-23
- **Follow-up TODO (01.7.2)**: inventariare i link per sezione (Product / Resources / Company / Legal / Social) per riferimento futuro; verificare che i `mailto:` (hello@, sales@, support@sentrikat.com) siano reachable e che eventuali social abbiano `rel="noopener"`.

---

## 01.8 — Cookie banner / privacy

### [01.8.1] Cookie banner NON visibile al primo load

- **Fase**: 01
- **Area**: Cookie banner
- **URL**: `https://sentrikat.com`
- **Tipo**: 🔴 Bug
- **Severity**: High (compliance GDPR / EU Cookie Law — se ci sono cookie non strettamente necessari DEVE esserci consent; se solo essenziali comunque best practice avere una notice)
- **Environment**: prod
- **Steps to reproduce**:
  1. Apri browser in modalità incognito (no `cookie_banner_dismissed` in localStorage)
  2. Vai su `https://sentrikat.com`
- **Expected**: il componente `CookieBanner.astro` visto nel repo (`SentriKat-web/landing/src/components/CookieBanner.astro`) dovrebbe apparire in basso con la dichiarazione "cookie essenziali only" e un bottone di dismissal
- **Actual**: nessun banner visibile
- **Root cause ipotesi**:
  - Il componente non è incluso nel layout (`Layout.astro`) oppure è condizionato su path/env
  - Oppure è nascosto da CSS (z-index, display:none su mobile dev)
  - Oppure la build non include il componente (import mancante)
  - Oppure il localStorage key è già settato da una visita precedente (sbloccabile: `localStorage.clear()` + reload)
- **Da verificare**:
  1. `localStorage.getItem('sentrikat_cookie_consent')` (o chiave simile) — se esiste, banner è stato chiuso
  2. `document.querySelector('[data-cookie-banner]')` in console — se restituisce `null` il componente non è in DOM, se restituisce elemento ma invisibile è problema CSS
  3. Controllare `SentriKat-web/landing/src/layouts/Layout.astro` se importa `<CookieBanner />`
- **Impatto compliance**: se il sito setta cookie analytics/tracking (Google Analytics, Plausible, ecc.) senza consent esplicito = violazione GDPR Art. 7 + ePrivacy
- **Discovered**: 2026-04-23

---

## 01.9 — i18n / lingua

### [01.9.1] Post blog in italiano in sito EN-only senza switcher

- **Fase**: 01
- **Area**: i18n / lingua
- **URL**: `https://sentrikat.com/blog/gestione-vulnerabilita-pmi` (da verificare esistenza)
- **Tipo**: 🟡 Warning / UX inconsistency
- **Severity**: Low-Medium (UX + SEO: Google potrebbe penalizzare mixed language senza `hreflang`)
- **Environment**: prod
- **Steps to reproduce**:
  1. Sito principale `sentrikat.com` tutto in EN
  2. Navbar, footer, nessuno switcher lingua visibile
  3. Nel blog esiste post `gestione-vulnerabilita-pmi` in italiano
- **Expected**: o sito multi-lingua con switcher EN/IT, oppure tutti i contenuti in una lingua unica
- **Actual**: contenuto misto senza language picker né `<link rel="alternate" hreflang="it">`
- **Decisione da prendere (parlarne)**:
  - Opzione A: tradurre il post IT in EN (o rimuoverlo)
  - Opzione B: introdurre i18n Astro (`astro-i18n` o nativo) con prefisso `/it/` per pagine IT + switcher in navbar
  - Opzione C: lasciare come "article in original language" con nota editoriale (peggiore per SEO ma più veloce)
- **Discovered**: 2026-04-23

---

## 01.10 — Responsive

### [01.10.1] Mobile rendering OK ✅

- **Tipo**: 🟢 OK
- **Actual**: su dispositivo mobile tutto a posto
- **Follow-up TODO**: test esplicito in DevTools mobile view (iPhone SE, Pixel 5, iPad) per verificare hamburger menu funzionante, nessun overflow orizzontale, bottoni tappable (≥ 44×44pt).
- **Discovered**: 2026-04-23

---

## 01.12 — Blog

### [01.12.1] Index blog mostra tutti i 14 post ✅

- **Fase**: 01
- **Area**: Blog
- **URL**: `https://sentrikat.com/blog`
- **Tipo**: 🟢 OK
- **Actual**: lista di 14 post visibile, conteggio coerente con i 14 markdown in `SentriKat-web/landing/src/content/blog/`
- **Discovered**: 2026-04-23

### [01.12.2] Post blog apertura e rendering OK ✅

- **Tipo**: 🟢 OK
- **Actual**: post cliccato si apre correttamente con titolo/body/formattazione
- **Follow-up TODO**: verificare che ogni post abbia: author, pubDate (ISO), tag/category, reading time, OG image per share, `<link rel="canonical">`; verificare che il layout `BlogPost.astro` renderizzi correttamente un post con code blocks, tabelle, immagini
- **Discovered**: 2026-04-23

### [01.12.3] Post IT mischiato con EN senza badge/flag lingua 🔵 (rafforza 01.9.1)

- **Fase**: 01
- **Area**: Blog / i18n
- **URL**: `https://sentrikat.com/blog/gestione-vulnerabilita-pmi/`
- **Tipo**: 🔵 Info (legato a bug 01.9.1)
- **Severity**: Low-Medium
- **Actual**: il post in italiano appare nella stessa lista dei post EN senza alcun indicatore visivo (flag 🇮🇹, badge `IT`, label "Italiano", ecc.). Il post si apre correttamente ma un utente EN riceve contenuto non comprensibile senza preavviso.
- **Consistency check**: `security.txt` dichiara `Preferred-Languages: en, it, de` → SentriKat supporta ufficialmente IT come lingua. Questo rafforza l'argomento per introdurre i18n completo (vedi 01.9.1).
- **Fix candidato minimale** (se non si vuole fare i18n pieno):
  - Aggiungere `lang: "it"` nel frontmatter del markdown
  - Nel componente card blog mostrare badge lingua quando `lang !== "en"`
  - Aggiungere `<html lang="it">` al layout post IT per SEO + screen reader
- **Discovered**: 2026-04-23

---

## 01.15 — Form pubbliche (rendering)

### [01.15.1] `/contact` — due form (Demo + Contact) con Turnstile ✅

- **Fase**: 01
- **Area**: Form pubbliche
- **URL**: `https://sentrikat.com/contact`
- **Tipo**: 🟢 OK (rendering)
- **Actual**: entrambi i form visibili:
  - **Demo Request**: name, email, company, company_size, message, accepted_terms + widget Turnstile
  - **Contact (generic)**: name, email, subject (General/Sales/Support/Partnership/Other), message, accepted_terms + widget Turnstile
- **Note**: test funzionale del submit (success, Turnstile failure, campi invalidi, 422) rinviato a 01.15 submit phase oppure fase 02 (se il flow è legato al signup).
- **Discovered**: 2026-04-23

### [01.15.2] `/contact-sales` — form lead rendering OK ✅

- **Tipo**: 🟢 OK (rendering)
- **URL**: `https://sentrikat.com/contact-sales`
- **Actual**: form visibile con tutti i campi (first_name, last_name, email, company, job_title, company_size, country, interest dropdown, agent_count, message, accepted_terms)
- **Follow-up TODO**: test validazione `agent_count` range 0-10000, test dropdown `interest` con default `onprem_pro`, test submit vero con tracking lead in admin portal
- **Discovered**: 2026-04-23

### [01.15.3] `/feedback` rendering OK ✅

- **Tipo**: 🟢 OK (rendering)
- **URL**: `https://sentrikat.com/feedback`
- **Actual**: pagina si apre correttamente (conferma utente: "feedback bene")
- **Follow-up TODO**: chiarire se è un form pubblico anonimo o richiede login; verificare dove finisce il feedback inviato (admin panel `/admin/feedback` nel portal — visto in mapping — oppure email, o entrambi); verificare endpoint `POST /api/v1/portal/feedback` o equivalente
- **Discovered**: 2026-04-23

---

## 01.18 — Capacity check (Early Access)

### [01.18.1] Endpoint capacity risponde con JSON corretto ✅

- **Fase**: 01
- **Area**: Capacity check
- **URL**: `https://sentrikat.com/api/v1/provision/trial/capacity`
- **Tipo**: 🟢 OK + 🔵 Info (stato business)
- **Environment**: prod
- **Actual response**:
  ```json
  {"active":2,"capacity":30,"status":"open"}
  ```
- **Interpretazione**:
  - `active: 2` — 2 trial attivi al momento
  - `capacity: 30` — limite totale Early Access programma
  - `status: "open"` — ancora disponibile (utenti attivi 2/30 = 6.7%)
- **Copertura test**:
  - ✅ Happy path `status: "open"` verificato
  - ⬜ Edge `status: "full"` + `EA_CAPACITY_FULL` (quando `active >= capacity`) non verificato — bisogna o aumentare gli active (impossibile da prod) o abbassare `capacity` da admin portal oppure testare in staging/local dev
  - ⬜ Verificare che `capacity` sia configurabile da admin portal (`/admin/settings` o `/admin/plans`)
  - ⬜ Verificare che quando `status: "full"` il pricing page nasconda i bottoni Early Access e mostri solo waitlist `mailto:`
- **Consistency check**: nota che il server espone questo endpoint su `sentrikat.com/api/v1/...` (non `api.sentrikat.com/...`) → significa che nginx proxy la richiesta al license-server FastAPI interno. Il repo `SentriKat-web` ha questa config in `/landing/astro.config.mjs` + `/nginx/*.conf`.
- **Discovered**: 2026-04-23

---

## Note di sessione

- **2026-04-23**: Primo giro home landing. Coperti i punti 01.1, 01.2, 01.3 (parziale), 01.4, 01.5, 01.7, 01.8, 01.9, 01.10.
- **2026-04-23 (batch 2)**: 01.6 scroll home OK · 01.11 marketing via footer OK · 01.14 legal via footer OK · 01.13 vs/* OK · 01.16 SEO artifacts OK (con follow-up sitemap-0) · 🔴 01.17 bug 404→home · 01.12 blog OK (rafforzo 01.9.1 con post IT) · 01.15 form rendering OK (Demo, Contact, Contact-sales, Feedback) · 01.18 capacity endpoint OK (2/30 open).
- **Follow-up ancora aperti (non bloccanti per passaggio fase 02)**:
  - 01.3.2 security headers (HSTS, X-Frame, Referrer-Policy) via DevTools Network
  - 01.16.1a contenuto `sitemap-0.xml` (esclusione `/impressum`, presenza di tutti gli URL)
  - 01.15 submit reale form Contact/Demo/Contact-Sales/Feedback (legato a fase 02/11 admin portal)
  - 01.13 contenuto unico vs duplicate su pagine `/vs/*`
  - 01.4.2 verifica `href` esatti link navbar (Docs, Community, Sign In, Join Early Access)

## Stato fase

**✅ FASE 01 COMPLETATA** (happy path + navigation). Follow-up elencati sopra da riprendere quando servono per test incrociati (es. `/admin/leads` in fase 05 per verificare lead submit, capacity admin config in fase 05).

## Riepilogo bug fase 01

| ID | Severity | Titolo |
|---|---|---|
| 🔴 01.2.1 | Medium | CSP blocca Google Fonts |
| 🔴 01.8.1 | High | Cookie banner non visibile (compliance GDPR) |
| 🔴 01.17.1 | High | 404 redireziona a home invece di mostrare pagina 404 |
| 🟡 01.9.1 | Low-Med | Post IT in sito EN-only senza switcher/hreflang |
| 🔵 01.16.1 | — | Follow-up contenuto `sitemap-0.xml` |
| 🔵 01.16.4 | — | `security.txt` dichiara IT+DE ma sito è EN-only |
| 🔵 01.12.3 | Low-Med | Post IT senza badge lingua nella lista blog |

**Totale: 3 bug (2 High + 1 Med), 1 warning, 3 info, 18 OK**

---

## 01.18 — Phase 2 walkthrough discoveries — 2026-05-05

### [01.18.1] 🔴 **HIGH** — On-prem pricing card mostra limiti diversi da quelli enforced dall'app

**Discovery context**: sessione W1 walkthrough customer SaaS, 2026-05-05.

Customer apre `https://sentrikat.com` → toggle "On-Premises" → vede card "Evaluation" Free con:
- 10 Agents (Windows, Linux, macOS)
- 3 Users
- 1 Organization
- 100 Products

Customer scarica e installa on-prem → l'app banner mostra "COMMUNITY EDITION - Limited to 1 user, 50 products" → tenta di creare 3° user → bloccato a 1 → reclama / refund / social complaint.

**Mismatch confermato a codice**:

| Campo | Landing (`sentrikat.com/pricing`) | Core (`app/licensing.py:LICENSE_TIERS`) |
|---|---|---|
| Max Agents | 10 | 5 |
| Max Users | 3 | 1 |
| Max Products | 100 | 50 |
| Max Orgs | 1 | 1 ✅ |

**Fix applicato lato core (commit `4ea5606` — branch `claude/round7-walkthrough-bugs`)**: aggiornato `LICENSE_TIERS['community']` con i numeri della landing (10/3/100/1). Decisione product: allineare core a landing (più generoso, meno churn) invece del contrario.

**Severity**: 🔴 HIGH — false advertising risk + early-customer churn / brand damage.
**Deployment scope**: 🏢 on-prem (esclusivo — il SaaS ha tier diversi).
**Status**: ✅ FIXED core side (`4ea5606`); landing side OK (numeri già corretti). Solo verify post-merge.

### [01.18.2] 🔴 **HIGH** — Terminology cluster on-prem free tier: 4 nomi diversi

**Discovery context**: stesso walkthrough W1.

Sulla stessa landing pagina e nell'app ci sono **4 nomi diversi** per il tier 0 on-prem:

| Posizione | Nome usato |
|---|---|
| Landing card title | **"Evaluation"** |
| Landing card price label | **"Free"** + **"Early Access — Free"** |
| App banner top page | **"COMMUNITY EDITION"** |
| App health check License Status badge | **"COMMUNITY"** |
| App License page header | **"Free"** |
| App error messages | **"Community Edition limit"** |
| Handbook + docs | **"Community"** |

7 punti UI, 4 nomi distinti. Customer pensa: 'Evaluation' = trial 30gg, 'Community' = FOSS forever, 'Free' = generic. Sono 3 prodotti diversi nella sua testa.

**Fix proposto**: uniformare ovunque a **"Community Edition"** (industry standard: GitLab CE, MongoDB Community, MySQL Community). "Evaluation" è confondente perché implica scadenza temporale.

**Severity**: 🔴 HIGH — brand consistency + customer confusion + perceived support quality.
**Deployment scope**: 🌐 landing + 🏢 on-prem app (cluster).
**Status**: 🔧 partial — core già corretto a "Community Edition" (ref `[03.14.10.expand]`). Landing card title ancora "Evaluation" — handoff cross-repo a sentrikat-web team.

### [01.18.3] 🔴 **HIGH** — No hard-delete account signup record + EA counter sync

**Discovery context**: walkthrough W2 signup, 2026-05-05. Tester ha già usato tutti i suoi alias email per signup precedenti → bloccato a continuare. Admin console ha solo "deactivate", non "delete".

**Issues separati**:

1. **GDPR compliance gap** — Art. 17 right to erasure: customer chiede cancellazione totale del proprio account → oggi non possiamo soddisfarla. Solo deactivate (logico delete con soft flag), non hard delete.

2. **EA counter staleness** — `sentrikat.com` homepage mostra "15 On-Prem spots available" (Early Access counter). Quando un customer firma, il counter dovrebbe scendere a 14. Quando viene cancellato (oggi non possibile), dovrebbe risalire a 15. Senza hard delete, il counter cresce monotonicamente verso 0 includendo dummy/test signup.

3. **Testing blocker** — durante development testing non possiamo riusare email (già consumed), siamo costretti a inventare alias indefinitamente.

**Architettura fix proposta** (cross-repo):

- `sentrikat-web` admin portal: nuova action "Hard Delete Account" sui customer record. Prompt confirmation 2-step (digita "DELETE accountID" per confermare).
- `sentrikat-web` license-server: endpoint `DELETE /api/v1/admin/customers/{id}` che cancella user + license + tenant record + email suppression list entry.
- `sentrikat-web` license-server: trigger automatico su delete → `update_ea_counter()` decrement.
- `sentrikat-web` landing: Pricing.astro fetch counter live (o build-time refresh ogni N min) — al momento sembra hardcoded "15".
- `sentrikat` core: niente da fare lato core — il customer signup record vive nel license-server, non nel SentriKat app.

**Severity**: 🔴 HIGH — GDPR compliance hard requirement + counter accuracy + dev-test workflow.
**Deployment scope**: 🌐 landing + 🏛 portal admin + 🔐 license-server (NO core).
**Status**: ❌ open — handoff cross-repo a sentrikat-web team.
