# 09 — Go-Live & Post-Launch (Part I)

> **Durata:** 30-45 min il giorno del lancio + monitoring continuo
> per 48h. **Priorità:** 🔴 Obbligatoria.
>
> Questa è l'ultima checklist: da eseguire il giorno del go-live, con
> ordine preciso. Include il rollback plan in caso di problemi.

---

## I.0 Pre-launch final sanity (T-24h)

Il giorno PRIMA del lancio pubblico. Non saltare nessun punto.

- [ ] Tutti i test delle parti A-H sono passati (o hanno un waiver documentato)
- [ ] Nessun issue con label `blocker` aperto in GitHub
- [ ] Nessun security finding HIGH o CRITICAL non fixato
- [ ] Ultimo commit su `main` ha CI verde
- [ ] Release tag pronto (es. `v1.0.0`)
- [ ] Changelog scritto e pubblicato
- [ ] Status page online (`status.sentrikat.com`)
- [ ] Incident response runbook stampato / accessibile
- [ ] Team su Slack/whatever, reachable nelle 48h successive

---

## I.1 DNS & domains

- [ ] `sentrikat.com` → marketing site
- [ ] `www.sentrikat.com` → redirect a apex
- [ ] `app.sentrikat.com` → SaaS web app
- [ ] `admin.sentrikat.com` → portal admin
- [ ] `api.sentrikat.com` → API endpoint (se separato)
- [ ] `status.sentrikat.com` → status page
- [ ] Tutti i record A/AAAA/CNAME verificati (`dig`, `nslookup`)
- [ ] TTL ragionevole (300-3600s, basso per emergency rollback)
- [ ] DNSSEC abilitato (opzionale ma raccomandato)

---

## I.2 TLS / SSL

- [ ] Certificato valido su tutti i domini
- [ ] Scadenza ≥ 60 giorni (se < 30, rinnova subito)
- [ ] Chain completo (no intermediate missing)
- [ ] SSL Labs test (`https://www.ssllabs.com/ssltest/`) → grade A o A+
- [ ] HSTS header presente con `max-age=31536000; includeSubDomains`
- [ ] HSTS preload submitted (se HSTS è stable ≥ 6 mesi)
- [ ] TLS 1.2+ only (no TLS 1.0/1.1, no SSL 3.0)
- [ ] Cipher suites modern (no RC4, no 3DES)
- [ ] Auto-renewal configurato (Let's Encrypt / ACME)
- [ ] Alert se renewal fail (monitoring)

---

## I.3 Security headers

Test con `curl -I https://app.sentrikat.com` o `securityheaders.com`:

- [ ] `Strict-Transport-Security` ✅
- [ ] `Content-Security-Policy` configurato e testato (niente `unsafe-inline`
      dove evitabile)
- [ ] `X-Frame-Options: DENY` o equivalente via CSP `frame-ancestors`
- [ ] `X-Content-Type-Options: nosniff`
- [ ] `Referrer-Policy: strict-origin-when-cross-origin` (o più restrittivo)
- [ ] `Permissions-Policy` per feature non usate (camera, mic, geo)
- [ ] `Cross-Origin-Opener-Policy: same-origin`
- [ ] securityheaders.com grade ≥ A
- [ ] `Server` header non leaka versione esatta

---

## I.4 Backup & recovery

- [ ] Backup DB configurato e **testato con restore reale**
- [ ] Frequenza: almeno daily, meglio hourly per DB transazionale
- [ ] Retention: ≥ 30 giorni
- [ ] Backup cifrati at-rest (AES-256)
- [ ] Backup su storage diverso (off-site, cross-region, S3 + Glacier)
- [ ] **Restore drill**: in staging, restore dell'ultimo backup e verifica
      che il SaaS parte correttamente
- [ ] RTO (Recovery Time Objective) documentato e realistico
- [ ] RPO (Recovery Point Objective) documentato
- [ ] Backup file storage (/uploads) anch'essi inclusi
- [ ] Backup delle config e secrets (in vault separato)

---

## I.5 Monitoring & alerting

### I.5.1 Uptime
- [ ] Uptime monitor esterno (UptimeRobot / Pingdom / Better Uptime)
- [ ] Check ogni 60s su: marketing, app, admin, api
- [ ] Alert via email + SMS + push su down > 2 min
- [ ] Alert scalano a più persone se non acked in 10 min

### I.5.2 Application metrics
- [ ] Prometheus/Grafana o equivalente attivo
- [ ] Metriche: request rate, error rate, latency p50/p95/p99
- [ ] Alert su error rate > 1% sustained 5 min
- [ ] Alert su p95 latency > 2s sustained 5 min
- [ ] Dashboard operativa con KPI visibili

### I.5.3 Errors
- [ ] Sentry (o simile) connesso all'app
- [ ] Source maps uploaded (frontend)
- [ ] Alert su nuovo error type
- [ ] Alert su error rate spike

### I.5.4 Logs
- [ ] Centralized logging (ELK, Loki, CloudWatch)
- [ ] Retention ≥ 90 giorni
- [ ] Audit log separato con retention ≥ 1 anno (compliance)
- [ ] Log NON contengono PII/password/token

### I.5.5 Database
- [ ] Slow query log attivo
- [ ] Alert su query > 5s
- [ ] Connection pool monitoring
- [ ] Disk space monitoring → alert a 80% full

### I.5.6 Resource
- [ ] CPU, RAM, disk usage su tutti i host
- [ ] Alert su CPU > 80% sustained 10 min
- [ ] Alert su RAM > 90%
- [ ] Alert su disk > 80%

---

## I.6 Rate limiting & abuse

- [ ] Rate limit su login endpoint (max 5 tentativi / 15 min / IP)
- [ ] Rate limit su signup (prevent bot flood)
- [ ] Rate limit su API generico (es. 100 req/min/token)
- [ ] WAF/CDN (Cloudflare / AWS WAF) attivo con regole base
- [ ] DDoS mitigation testata o almeno configurata
- [ ] IP blocklist configurabile per emergency

---

## I.7 Launch window (T-0)

**Ora del lancio. Segui l'ordine.**

### I.7.1 Final checks (T-30 min)
- [ ] Team in call / war room
- [ ] Rollback plan aperto e letto ancora una volta
- [ ] Status page "operational"
- [ ] DNS TTL basso (300s) per rollback rapido
- [ ] Monitoring dashboard aperto su schermo grande
- [ ] DB backup fresco (last 10 min)

### I.7.2 Deploy (T-0)
- [ ] Feature flag `PUBLIC_LAUNCH=true` (se applicabile)
- [ ] Rimozione "invite only" / waitlist
- [ ] Marketing site va live (se era in stealth)
- [ ] Announcement su social (schedulato o manuale)
- [ ] Email al newsletter

### I.7.3 Post-deploy smoke (T+15 min)
- [ ] Da browser pulito: signup nuovo account funziona
- [ ] Login funziona
- [ ] Primo scan funziona
- [ ] Email di conferma arriva
- [ ] Pagamento test (se trial → paid disponibile)
- [ ] Nessun spike di errori in Sentry
- [ ] Nessun alert uptime triggered

---

## I.8 First 60 minutes

- [ ] Monitora error rate: deve restare < 1%
- [ ] Monitora latency: p95 deve restare sotto target
- [ ] Monitora signup rate: verifica che il funnel funzioni
- [ ] Check Sentry ogni 5 min per nuovi error type
- [ ] Check status page aggiornamenti
- [ ] Check Twitter / social per segnalazioni utente
- [ ] Check support inbox per ticket
- [ ] Check mailing provider per bounce/spam flag (email deliverability)

**Trigger rollback se:**
- [ ] Error rate > 5% per 5 min
- [ ] Login flow broken (utenti non riescono a entrare)
- [ ] Data loss o corruption detected
- [ ] Security incident attivo
- [ ] Critical payment flow broken

---

## I.9 Rollback plan

**Pre-condizioni per un rollback clean:**
- [ ] Backup DB < 1h fa disponibile
- [ ] Release precedente taggata e deployabile
- [ ] DNS TTL basso (max 5 min)

### I.9.1 Rollback application
1. [ ] Status page: "investigating" / "degraded"
2. [ ] Comunicazione interna: "rolling back"
3. [ ] `docker-compose down && docker-compose up -d` con image precedente
      (o k8s `kubectl rollout undo`)
4. [ ] Verifica health endpoint
5. [ ] Smoke test base (login, dashboard)
6. [ ] Status page: "operational" se OK

### I.9.2 Rollback con data migration
Se il deploy includeva una migration SQL:
1. [ ] STOP: valuta se migration è reversibile
2. [ ] Se sì: `rollback.sql` pronto → eseguilo
3. [ ] Se no: restore DB da backup (accetta data loss del periodo intercorso)
4. [ ] Comunicazione agli utenti sul data loss (se rilevante)
5. [ ] Post-mortem obbligatorio

### I.9.3 Rollback DNS (last resort)
- [ ] Cambia DNS apex verso pagina "maintenance"
- [ ] Espone un contact email per support urgente
- [ ] Comunicazione pubblica (blog, social, email)

---

## I.10 First 24 hours

- [ ] Ogni 30 min: check metriche principali
- [ ] Ogni 1h: check support inbox
- [ ] Ogni 2h: check business metrics (signup rate, conversion)
- [ ] Log strange behaviors in un doc condiviso (bug tracker)
- [ ] Triage ticket support con priorità alta per bug critici
- [ ] NON deployare fix non-critical in queste 24h (aspetta il freeze)

---

## I.11 First 48 hours

- [ ] Review degli errori accumulati in Sentry
- [ ] Review dei ticket support
- [ ] Identifica top 3 issue segnalati dagli utenti
- [ ] Patch release (hotfix) se necessario
- [ ] Blog post "launch successful, what we learned"
- [ ] Thank you email agli early adopters

---

## I.12 First week (post-launch)

- [ ] Metriche aggregate: uptime %, avg response time, error rate
- [ ] Retention D1, D7 dei primi utenti
- [ ] Conversion rate trial → paid
- [ ] Churn rate (se applicabile)
- [ ] Cost review (infra, provider esterni)
- [ ] Backup restore drill reale (secondo test in ambiente isolato)
- [ ] Security audit logs review
- [ ] Feedback form mandato agli utenti attivi

---

## I.13 Compliance & legal

- [ ] Privacy policy pubblicata e linkata in footer
- [ ] Terms of Service pubblicati
- [ ] Cookie banner + consent management (se EU users)
- [ ] DPA template pronto per customer enterprise
- [ ] GDPR data request procedure documentata
- [ ] Data processing agreement con sub-processors firmato
- [ ] Incident notification plan (72h GDPR rule) documentato

---

## I.14 Communication plan

- [ ] Status page è pubblica e linkata da footer
- [ ] Support email monitored: `support@sentrikat.com`
- [ ] Response SLA definito (es. entro 24h)
- [ ] Escalation path per bug critici
- [ ] Social media template per incidents
- [ ] Blog pronto per post-mortem pubblico (se serve)

---

## I.15 Final go/no-go

**Prima di annunciare pubblicamente, verifica con un check mentale:**

- [ ] Avrei il coraggio di far testare il servizio a mia mamma? (UX)
- [ ] Se riceviamo 1000 signup in 1 ora, regge? (scale)
- [ ] Se domani un cliente enterprise chiede il DPA, ce l'ho? (sales)
- [ ] Se qualcuno trova un bug di sicurezza grave, come lo gestisco? (security)
- [ ] Se il DB si corrompe stanotte, come lo restore? (disaster)
- [ ] Dormirò tranquillo stanotte dopo il lancio? (peace of mind)

**Se a tutte e 6 è "sì", lancia.**

**Se anche solo una è "no" → posticipa di 24h e sistema quel punto.**

---

## I.16 Post-launch retrospective (T+7 giorni)

Da fare in team, 1h max:

- [ ] Cosa è andato bene?
- [ ] Cosa è andato male?
- [ ] Quali bug è emerso che non avevamo previsto?
- [ ] Le stime erano realistiche?
- [ ] La checklist è stata utile? Come migliorarla?
- [ ] Quali metriche monitorare in modo ongoing?
- [ ] Priorità per Sprint 6+

**Aggiorna questo documento con i learning per il prossimo major release.**

---

## Appendice: contatti emergency

_Compila prima del lancio:_

- On-call primary: ___________
- On-call backup: ___________
- Provider hosting (support): ___________
- Provider DNS (support): ___________
- Legal/privacy officer: ___________
- Stripe/billing provider: ___________
- Status page admin: ___________

**Buon lancio. Respira. Tutto andrà bene.**
