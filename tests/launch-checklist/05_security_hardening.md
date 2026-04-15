# 05 — Security Hardening Verification (Part E)

> **Durata:** 1h. **Priorita':** 🔴 Obbligatoria — verifica che i fix
> dell'audit Sprint 4+5 siano effettivamente attivi in produzione.

Ogni test qui corrisponde a una voce dell'audit report
(`docs/PRE_LAUNCH_AUDIT_AND_TESTING_PLAN.md` PARTE 9). Se qualcosa
fallisce, significa che il fix non e' attivo e devi rollbackare / rifare.

---

## E.1 Migrations applicate (BLOCKER 9.1)

```bash
docker compose exec db psql -U sentrikat -d sentrikat -c \
  "SELECT tablename FROM pg_tables WHERE tablename IN \
  ('vulnerability_snapshots','sla_policies','remediation_assignments','risk_exceptions','product_aliases') \
  ORDER BY tablename;"
```

- [ ] Risultato: 5 righe, una per tabella

```bash
docker compose exec db psql -U sentrikat -d sentrikat -c \
  "SELECT indexname FROM pg_indexes WHERE indexname IN \
  ('idx_assign_org_status','idx_assign_org_assignee','idx_assign_org_due',\
   'idx_riskexc_org_status','idx_riskexc_org_expiry','uq_product_alias') \
  ORDER BY indexname;"
```

- [ ] Risultato: 6 righe, una per indice

```bash
docker compose exec db psql -U sentrikat -d sentrikat -c \
  "SELECT column_name FROM information_schema.columns \
  WHERE table_name='remediation_assignments' \
  AND column_name IN ('tracker_issue_key','tracker_issue_url','tracker_type') \
  ORDER BY column_name;"
```

- [ ] Risultato: 3 righe (rinomina `jira_issue_key` → `tracker_issue_key`
      andata a buon fine)

## E.2 SECRET_KEY robusto (HIGH 9.3)

```bash
docker compose exec sentrikat python3 -c "
import os
sk = os.environ.get('SECRET_KEY', '')
print('SECRET_KEY length:', len(sk))
print('SECRET_KEY is hex:', all(c in '0123456789abcdef' for c in sk) if sk else False)
print('SECRET_KEY is default:', sk in ('', 'dev-secret-key', 'change-me', 'changeme'))
"
```

- [ ] `length: 64` (32 byte esadecimali)
- [ ] `is_hex: True`
- [ ] `is_default: False`

**⚠️ Se uno di questi e' FAIL → STOP lancio.** Rigenera:
```bash
python3 -c "import secrets; print(secrets.token_hex(32))"
```
e aggiorna il `.env` prima di continuare.

## E.3 CSRF exempt rimosso dai 3 blueprint (MEDIUM 9.6)

```bash
docker compose exec sentrikat grep -cH "csrf.exempt" \
  app/sbom_export.py app/compliance_reports.py app/remediation_api.py
```

- [ ] Ogni file mostra `0` (zero match)

**Test funzionale** (deve fallire con 400/403 senza CSRF token):
```bash
# Questo deve fallire con 400 CSRF
curl -sk -X POST -H "Cookie: $COOKIE_A" -H "Content-Type: application/json" \
  -d '{"justification":"test","cve_id":"CVE-2024-1234"}' \
  "$BASE/api/risk-exceptions" -w "\nHTTP %{http_code}\n"
```

- [ ] HTTP 400 "CSRF token missing" (o 403)
- [ ] **Nota:** dal browser con CSRF token auto-iniettato da Jinja2,
      l'endpoint deve continuare a funzionare. Verifica andando sulla
      pagina Risk Exceptions e creando una exception via UI → deve
      riuscire.

## E.4 Pagination su list endpoints (MEDIUM 9.7)

```bash
curl -sk -H "Cookie: $COOKIE_A" \
  "$BASE/api/risk-exceptions?page=1&per_page=10" | python3 -m json.tool
```

- [ ] Response contiene `page`, `per_page`, `pages`, `total`
- [ ] `per_page` capped a max 100 anche se si passa `per_page=99999`

```bash
curl -sk -H "Cookie: $COOKIE_A" \
  "$BASE/api/product-aliases?page=1&per_page=10" | python3 -m json.tool
```

- [ ] Stesso formato response

## E.5 SBOM size limit (MEDIUM 9.9)

Se hai un org di test con > 5000 prodotti:
```bash
curl -sk -H "Cookie: $COOKIE_A" \
  "$BASE/api/sbom/export/cyclonedx" -w "\nHTTP %{http_code}\n"
```

- [ ] Org grande → HTTP 413 "SBOM export too large" con `max_products: 5000`
- [ ] Org normale (< 5000 prodotti) → HTTP 200 con bundle

## E.6 PDF compliance report size cap (MEDIUM 9.8)

- [ ] Org con molti prodotti → PDF generato < 200 requirements inclusi
- [ ] `report.truncated = true` se truncato
- [ ] Worker NON va in OOM: `docker stats sentrikat` durante la generazione

## E.7 Patch Tuesday rate limit (MEDIUM 9.11)

```bash
for i in 1 2 3 4 5 6 7; do
  curl -sk -X POST -H "Cookie: $COOKIE_A" \
    "$BASE/api/reports/patch-tuesday/trigger?dry_run=true" \
    -o /dev/null -w "Req $i: HTTP %{http_code}\n"
done
```

- [ ] Richieste 1-5 → HTTP 200
- [ ] Richieste 6-7 → HTTP 429 "Too many requests"

## E.8 Assignment + Jira strict rollback (MEDIUM 9.12)

Setup: configure un Jira integration con credenziali **INVALIDE**.

```bash
curl -sk -X POST -H "Cookie: $COOKIE_A" -H "Content-Type: application/json" \
  -d '{"assigned_to":"test@example.com","match_id":1,"create_jira_ticket":true}' \
  "$BASE/api/remediation/assignments?strict_tracker=true" \
  -w "\nHTTP %{http_code}\n"
```

- [ ] Con `?strict_tracker=true` → HTTP 502, assignment NON creata nel DB
- [ ] Senza strict_tracker (default legacy) → HTTP 201 con warning,
      assignment creata (tracker_issue_key=NULL)

## E.9 Email validation con regex (MEDIUM 9.13)

```bash
docker compose exec sentrikat grep -n "_EMAIL_REGEX" app/email_provider.py
```

- [ ] Regex presente alla riga 25 circa
- [ ] Regex usata nella funzione `send_email` (riga 348 circa)

Test funzionale: crea assignment con email malformata:
```bash
curl -sk -X POST -H "Cookie: $COOKIE_A" -H "Content-Type: application/json" \
  -d '{"assigned_to":"invalid@localhost","match_id":1}' \
  "$BASE/api/remediation/assignments" -w "\nHTTP %{http_code}\n"
```

- [ ] HTTP 400 "assigned_to contains invalid characters" (ora la
      validazione lato API scatta prima che arrivi al sender)

Test di iniezione CRLF nel `_obfuscate_email`:
- [ ] Manuale: configura un user con email contenente `\n` →
      send email → log mostra "Skipping email with CR/LF"

## E.10 Format parameter validation (MEDIUM 9.14)

```bash
curl -sk -H "Cookie: $COOKIE_A" \
  "$BASE/api/reports/compliance/pci-dss?format=xml" -w "\nHTTP %{http_code}\n"
```

- [ ] HTTP 400 "Invalid format", response JSON con `message: "format must be one of ['json', 'pdf']"`

```bash
curl -sk -H "Cookie: $COOKIE_A" \
  "$BASE/api/reports/compliance/pci-dss?format=pdf" -w "\nHTTP %{http_code}\n"
```

- [ ] HTTP 200 + PDF binary

## E.11 Rate limit patch-tuesday decorator presente (MEDIUM 9.11)

```bash
docker compose exec sentrikat grep -B4 -A1 "def trigger_patch_tuesday_digest" app/routes.py
```

- [ ] Vedi `@limiter.limit("5/hour")` tra i decorator

## E.12 Length validations (LOW 9.16 + 9.17)

- [ ] POST risk-exception con `justification` di 6000 chars → HTTP 400
      "justification too long"
- [ ] POST assignment con `assigned_to = "../../etc/passwd"` → HTTP 400
      "invalid characters"
- [ ] POST assignment con `notes` di 15000 chars → HTTP 400 "notes too long"

## E.13 Bare except in scheduler cleaned up (LOW 9.15)

```bash
docker compose exec sentrikat grep -cn "except: pass\|except Exception: pass" app/scheduler.py
```

- [ ] Conteggio sceso (i bare critici delle righe 1644 e 1650 sono stati
      rimpiazzati con `logger.warning(..., exc_info=True)`)

## E.14 Licensing gate su SBOM e Compliance

```bash
# Login come user sul plan `free` (niente SBOM / API / compliance)
curl -sk -H "Cookie: $COOKIE_FREE" \
  "$BASE/api/sbom/export/cyclonedx" -w "\nHTTP %{http_code}\n"
```
- [ ] HTTP 403 con messaggio upgrade

```bash
curl -sk -H "Cookie: $COOKIE_FREE" \
  "$BASE/api/reports/compliance/pci-dss" -w "\nHTTP %{http_code}\n"
```
- [ ] HTTP 403 con messaggio upgrade

## E.15 HMAC integrity dei compliance report

```bash
# Genera un report JSON, estrai hash, ricalcola
REPORT=$(curl -sk -H "Cookie: $COOKIE_A" "$BASE/api/reports/compliance/pci-dss")
echo "$REPORT" | python3 -c "
import sys, json, hmac, hashlib, os
data = json.load(sys.stdin)
integrity = data.pop('integrity', {})
print('Claimed hash:', integrity.get('hash'))
# Ricalcola
canonical = json.dumps(data, sort_keys=True, separators=(',', ':')).encode()
# Serve la stessa SECRET_KEY del server. Per test: run this inside the container.
"
```

- [ ] Eseguibile dal container: ricalcolo hash matcha `integrity.hash`
- [ ] Modifica 1 byte nel JSON → ricalcolo NON matcha piu'

---

## ✅ Gate E

- [ ] Tutti i check Sprint 4+5 security verdi
- [ ] SECRET_KEY validato (il piu' critico)
- [ ] Rate limits funzionanti
- [ ] License gate attivo

Prossima: [`06_cross_repo_integration.md`](06_cross_repo_integration.md)
