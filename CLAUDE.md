# CLAUDE.md — Istruzioni perenni per Claude Code in questo repo

> Caricato automaticamente all'inizio di ogni sessione Claude Code in `/home/user/SentriKat`. Aggiornare quando cambiano regole operative o lo stato del lavoro E2E.

---

## 🛑 REGOLA #1 — Anti-timeout (PRIORITÀ MASSIMA)

L'utente ha avuto sessioni rotte ripetutamente da `Stream idle timeout - partial response received` su Opus 4.7 (1M context). **Ogni Claude in questo repo deve seguire queste regole prima di qualsiasi tool call**, senza eccezioni:

1. **Mai un `Write`/`Edit` > 250 righe in un colpo solo.** Se serve più, spezza in `Edit` successivi e committa in mezzo.
2. **Mai una `Read` senza `limit`/`offset` su file > 200 righe.** Solo le sezioni che servono. Ammessi file piccoli per intero.
3. **Mai una `Bash` con output potenzialmente enorme** (`grep -r` senza filtri, `find /`, `cat` su file lunghi, `git log` senza limite). Sempre `head`, `--max-count`, `-n`, ecc.
4. **Niente `Agent` (subagent) per task incrementali.** La risposta del subagent è grossa e mangia il context principale. Usa subagent solo per ricerche su molti file dove non sai dove guardare.
5. **Commit + push ogni 1–2 step utili.** Se la sessione muore, il lavoro è già salvato sul remote. Branch di lavoro: vedi sezione qui sotto.
6. **Niente esplorazione speculativa.** Ogni tool call deve produrre un risultato che entra nel commit corrente. No "leggo per capire", solo "leggo perché mi serve QUESTO".

**Pre-flight check**: prima di un tool call grosso, stima output. Se rischia di superare 15 KB → spezzalo. Se non sai → spezzalo lo stesso.

**Se l'utente segnala un timeout**: NON ricominciare da zero — chiedi a che punto eravamo (`git log -5`, `git status`), riparti dal commit successivo. Mai rifare lavoro già committato.

---

## 📚 Stato lavoro E2E (aggiornare quando cambia)

### ⚠️ Repo split — leggere PRIMA di proporre fix

I bug E2E sono divisi in **due repository** distinti. Il tuo working dir potrebbe essere uno dei due — controlla con `pwd` + `cat README.md`:

| Repo | Path tipico | Dominio prod | Cosa contiene | Container docker locali |
|---|---|---|---|---|
| **`sbr0nch/SentriKat`** (on-prem core) | `/home/user/SentriKat` o `C:\SentriKat` | `app.sentrikat.com` | Vulnerability management Flask app, license-server, agent API, KB sync | `sentrikat`, `sentrikat-db`, `sentrikat-nginx`, `testlab-*` |
| **`sbr0nch/SentriKat-web`** (Astro frontend + admin portal) | `/home/user/SentriKat-web` o equivalente | `sentrikat.com`, `portal.sentrikat.com` (customer + **admin**) | Landing site, portal customer, **portal admin**, blog, docs, status page | NESSUNO in locale — gira su VM Hetzner SaaS in prod |

**Regole derivate**:
- Bug `[01.*]` `[02.*]` `[04.*]` `[05.*]` (admin portal) → fix in `SentriKat-web`. **NON cercare il codice in questo repo**.
- Bug `[03.*]` `[06.*]` `[07.*]`+ → fix in `SentriKat` core (questo repo se siamo qui).
- I doc E2E (`docs/e2e-tests/*.md`) vivono SOLO in questo repo `SentriKat`. L'altro repo riceve handoff via `FIX-HANDOFF-sentrikat-web.md`.
- Mai eseguire `grep onclick` in questo repo per debuggare bug del portal admin — il template colpevole NON è qui.
- `portal.sentrikat.com` non è raggiungibile in locale (no docker container) → tutti i test sono via browser su prod URL.

- **Repo principale (questo)**: `sbr0nch/SentriKat` core. Master file E2E: `docs/e2e-tests/00-INDEX.md`.
- **Master file**: `docs/e2e-tests/00-INDEX.md` — leggere sempre la sezione HANDOFF in cima prima di iniziare.
- **Branch correntemente in lavoro**: `claude/add-e2e-test-docs-UVya5` (push qui).
- **Phase status**: vedi tabella in `00-INDEX.md`. Fase 05 (Portal Admin) in apertura — screenshot di 8 pagine acquisiti il 2026-04-28, doc da scrivere in `docs/e2e-tests/05-admin-portal.md`.

### Ambiente test disponibile

- **PC casa**: docker on-prem + testlab → tutti i test sbloccabili (LDAP/SAML reali, Jira/Webhook con `FLASK_ENV=development`, agent install, scan, compliance reports).
- **Laptop remoto**: solo browser-only su superfici prod (`sentrikat.com`, `portal.sentrikat.com`, `app.sentrikat.com`, `docs`, `community`). NON fare i test che richiedono docker.

### Testlab — URL e credenziali (perenni, non chiedere all'utente)

Working dir testlab: `C:\SentriKat\testlab\docker-compose.testlab.yml`. Container `testlab-*` running su PC casa.

| Servizio | URL host (browser) | URL da DENTRO container `sentrikat` | Auth |
|---|---|---|---|
| **Mailpit** (SMTP+inbox) | `http://localhost:8025` (UI), `localhost:1025` (SMTP) | `mailpit:1025` o `host.docker.internal:1025` | nessuna |
| **Keycloak** (SAML/OIDC IdP) | `http://localhost:8180` | `host.docker.internal:8180` | admin: `admin` / `admin123` |
| **OpenLDAP** | `ldap://localhost:389` | `host.docker.internal:389` | bind DN: `cn=admin,dc=sentrikat-test,dc=local` / `admin123` |
| **phpLDAPadmin** | `https://localhost:6443` | n/a | stesso bind DN OpenLDAP |
| **Webhook-tester** | `http://localhost:8800` | `host.docker.internal:8800` | nessuna |
| **Jira mock** (MockServer) | `http://localhost:8080` (host) → container `:1080` | `http://host.docker.internal:8080` o `http://testlab-jira-mock:1080` | nessuna; mock accetta qualsiasi credential |
| **Dozzle** (log viewer) | `http://localhost:9999` | n/a | nessuna |
| **Uptime-Kuma** | `http://localhost:3001` | n/a | setup iniziale alla prima visita |
| **Kibana** | `http://localhost:5601` | n/a | — |
| **Elasticsearch** | n/a esposto | `testlab-elasticsearch:9200` | — |
| **Squid proxy** | `localhost:3128` (HTTP proxy) | `host.docker.internal:3128` | — |
| **Syslog** | `localhost:514` (UDP) | `testlab-syslog:514` | — |

#### Jira mock — endpoints pre-configurati (`jira-expectations.json`, vedi [03.11.4.2])

Project key preconfigurato: **`VULN`**. Endpoint mockati:

| Method | Path | Scopo |
|---|---|---|
| GET | `/rest/api/2/serverInfo` | Server version info (Test Connection ping) |
| GET | `/rest/api/2/myself` | Auth check |
| GET | `/rest/api/2/project/VULN` | Project detail (project key=VULN preconfigurato) |
| GET | `/rest/api/2/project` | List projects |
| POST | `/rest/api/2/issue` | Create issue (core integration endpoint) |
| GET | `/rest/api/2/search` | JQL search |
| GET | `/rest/api/2/issuetype` | Issue types list (dropdown UI) |

**Test Connection Jira tipo**: URL `http://host.docker.internal:8080`, email arbitraria (`test@sentrikat.local`), API token arbitrario (`mock-token-123`), project key `VULN`. Il mock non valida credenziali.

**Per altri integration mock similari**: webhook-tester (`http://host.docker.internal:8800`), GitLab on-prem mock (vedi se esiste), GitHub (no URL custom — passa SSRF), YouTrack (uguale a Jira pattern atteso).

### Workflow PowerShell utente (Windows)

- `&&` NON funziona in PowerShell. Usare `;` per concatenare, oppure eseguire comandi separati.
- Per pull aggiornato dopo merge su main: `git fetch origin ; git switch main` (la prima volta serve `git switch -c main origin/main` perché il repo locale è in detached HEAD su tag `v1.0.0-beta.6`).
- Path repo locale: `C:\SentriKat\v1.0.0-beta.6\` (sottocartella, NON `C:\SentriKat\`).

---

## 🤝 Stile collaborazione (preferenze utente)

- **Italiano**, tono diretto, niente fronzoli.
- **Una pagina alla volta**: utente esegue nel browser → riporta screenshot/output → Claude annota nel file della fase. Non saltare avanti.
- **7-dim per ogni pagina**: dim 1 happy path, dim 2 persistence, dim 3 CRUD, dim 4 RBAC, dim 5 state transitions, dim 6 negative input, dim 7 integration/audit. Vedi `00-INDEX.md` per dettaglio.
- **Bug ID**: formato `[FF.S.B]` o `[FF.S.B.N]` (Fase.Sezione.Bug.SubBug). Mai rinumerare retroattivamente.
- **Severity icon**: 🔴 HIGH/CRITICAL · 🟡 MEDIUM/WARN · 🔵 INFO · 🟢 OK · ⏸️ BLOCKED · 🔧 fix applicato unverified · ✅ verified.
- **No PR auto**: non creare PR se non richiesto esplicitamente. Push sì, PR no.
- **Workflow git utente**: l'utente apre PR `claude/*` → review → merge su `main` → poi pulla da `main` sui suoi laptop. NON proporre `git pull origin claude/<branch>` se non strettamente necessario; è meglio aspettare che il commit arrivi su `main` via PR. Se il fix urge (es. serve per testare nel container locale), avvisare l'utente che è una scorciatoia temporanea.

---

## 🚫 Cose da NON fare

- Non leggere `00-INDEX.md` per intero (è enorme). Usa `grep -n` + `Read` con `offset`/`limit` mirato.
- Non rifare verify di fix già marcati ✅ in `00-INDEX.md` — sono stati confermati dall'utente.
- Non toccare `main` direttamente. Tutto su branch `claude/*`.
- Non eseguire comandi distruttivi (reset --hard, push --force, branch -D) senza chiedere.
