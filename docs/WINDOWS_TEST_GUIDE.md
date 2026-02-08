# SentriKat - Complete Windows Test Guide

**For:** Investor demo / Full feature test
**Environment:** Windows 11 + Docker Desktop
**Time needed:** ~45 minutes

---

## PHASE 0: Prerequisites

```powershell
# Verify Docker Desktop is running
docker --version
docker compose version

# Verify testlab is running
docker compose -f C:\SentriKat\testlab\docker-compose.testlab.yml ps
```

All 8 testlab services should be "Up". If not:
```powershell
docker compose -f C:\SentriKat\testlab\docker-compose.testlab.yml up -d
```

---

## PHASE 1: Download Package from Portal

1. Go to **sentrikat.com** -> request demo or purchase
2. You'll receive an activation code (format: `SK-XXXX-XXXX-XXXX-XXXX`)
3. Download the release package `sentrikat-X.X.X.tar.gz`
4. Extract to `C:\SentriKat`

You should have:
```
C:\SentriKat\
  docker-compose.yml
  .env.example
  nginx\
  scripts\
  certs\
```

---

## PHASE 2: Configure Environment

```powershell
cd C:\SentriKat
copy .env.example .env
```

Edit `.env` with Notepad or VS Code - set these values:

```env
# Generate these (run in PowerShell):
# python -c "import secrets; print(secrets.token_hex(32))"
SECRET_KEY=<paste generated key>

# python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"
ENCRYPTION_KEY=<paste generated key>

# Generate once, keep forever:
# python -c "import uuid; print(f'SK-INST-{uuid.uuid4().hex[:32].upper()}')"
SENTRIKAT_INSTALLATION_ID=<paste generated ID>

# Database
DB_PASSWORD=MySecurePassword123!
DATABASE_URL=postgresql://sentrikat:MySecurePassword123!@db:5432/sentrikat

# Network
SERVER_NAME=localhost
SENTRIKAT_URL=http://localhost
HTTP_PORT=80

# For local testing (no HTTPS)
FORCE_HTTPS=false
SESSION_COOKIE_SECURE=false
FLASK_ENV=production
SENTRIKAT_ENV=production
NGINX_TEMPLATE=nginx.conf.template
```

**IMPORTANT:** Write down the `SENTRIKAT_INSTALLATION_ID` - you'll need it for license activation.

---

## PHASE 3: Start SentriKat

```powershell
cd C:\SentriKat
docker compose up -d
```

Wait for all 3 containers to be healthy:
```powershell
docker compose ps
```

Expected output:
```
NAME              STATUS          PORTS
sentrikat-db      Up (healthy)
sentrikat         Up (healthy)
sentrikat-nginx   Up (healthy)    0.0.0.0:80->80/tcp
```

If `sentrikat` shows "starting", wait 30-60 seconds for the database to initialize.

Open browser: **http://localhost**

---

## PHASE 4: Setup Wizard

The setup wizard appears on first launch. Follow these steps:

### Step 1: Welcome
- Click **"Get Started"**

### Step 2: Organization
- **Name:** `Acme Corp` (or your company name)
- **Description:** `Security operations`
- **Alert Emails:** `admin@test.local`
- Click **"Create"**

### Step 3: Admin Account
- **Username:** `admin`
- **Password:** `Admin123!secure` (min 8 chars)
- **Email:** `admin@test.local`
- **Full Name:** `System Administrator`
- Click **"Create"**

### Step 4: Service Catalog
- Click **"Seed Catalog"**
- Wait for confirmation (~47 services loaded)

### Step 5: CISA KEV Sync
- Click **"Start Sync"**
- Wait 30-60 seconds for ~1200+ CVEs to download
- If it fails (proxy/firewall), click **"Skip"** - you can sync later from Admin panel

### Step 6: Complete
- Click **"Continue"**
- You'll be redirected to the login page

---

## PHASE 5: Login & Activate License

### Login
- Username: `admin`
- Password: `Admin123!secure`

### Activate License
1. Go to **Administration > License** (sidebar menu)
2. You'll see "Demo Version" with limits
3. Note the **Installation ID** displayed (should match your `.env`)
4. Click **"Online Activation"** (or "Activate License")
5. Paste your activation code: `SK-XXXX-XXXX-XXXX-XXXX`
6. Click **"Activate"**
7. Should show: **"Professional"** with 10 agents

If online activation fails (firewall), use manual activation:
1. Copy the Installation ID
2. Go to portal.sentrikat.com, log in
3. Bind the license to your Installation ID
4. Download the license key
5. Paste in SentriKat > Administration > License > "Activate License"

---

## PHASE 6: Configure Integrations (Using Testlab)

### 6A. Email (MailHog)

1. Go to **Administration > Settings** (or Organization settings)
2. Find Email/SMTP section
3. Configure:

| Field | Value |
|-------|-------|
| SMTP Host | `host.docker.internal` |
| SMTP Port | `1025` |
| Use TLS | No |
| Username | *(empty)* |
| Password | *(empty)* |
| From Email | `sentrikat@test.local` |
| From Name | `SentriKat Alerts` |

4. Click **"Send Test Email"**
5. Open **http://localhost:8025** (MailHog) - verify email arrived

### 6B. LDAP (OpenLDAP)

1. Go to **Administration > LDAP/AD**
2. Configure:

| Field | Value |
|-------|-------|
| Enabled | Yes |
| Host | `host.docker.internal` |
| Port | `389` |
| Use SSL | No |
| Bind DN | `cn=admin,dc=sentrikat-test,dc=local` |
| Bind Password | `admin123` |
| User Search Base | `ou=users,dc=sentrikat-test,dc=local` |
| User Filter | `(uid={username})` |
| Username Attribute | `uid` |
| Email Attribute | `mail` |
| Display Name Attribute | `displayName` |
| Group Search Base | `ou=groups,dc=sentrikat-test,dc=local` |
| Group Filter | `(member={userDN})` |
| Group Name Attribute | `cn` |
| Admin Group | `sentrikat-admins` |

3. Click **"Test Connection"** - should show success
4. Click **"Save"**

### 6C. Webhooks

1. Open **http://localhost:8800** (Webhook Tester)
2. Copy the webhook URL
3. Replace `localhost` with `host.docker.internal` in the URL
4. Go to **Administration > Webhooks**
5. Add Custom Webhook with the modified URL
6. Click **"Test"** - verify payload appears in Webhook Tester

### 6D. Jira Integration

1. Go to **Administration > Issue Trackers**
2. Enable Jira:

| Field | Value |
|-------|-------|
| URL | `http://host.docker.internal:8080` |
| Username | `admin` |
| API Token | `mock-token-12345` |
| Project Key | `VULN` |
| Issue Type | `Vulnerability` |

3. Click **"Test Connection"** - should return Jira v9.12.0
4. Click **"Save"**

---

## PHASE 7: Test Core Features

### 7A. Add Products Manually

1. Go to **Inventory > Products**
2. Click **"Add Product"**
3. Search NVD for: `Firefox`
4. Select `Mozilla Firefox` from results
5. Set version: `115.0`
6. Click **"Save"**
7. Repeat for:
   - `Apache HTTP Server` version `2.4.57`
   - `OpenSSL` version `3.0.2`
   - `Microsoft Exchange Server` version `2019`

### 7B. Check Vulnerability Matches

1. Go to **Dashboard**
2. You should see matched CVEs for the products you added
3. Click a CVE to see full details
4. Try **Acknowledge** on a CVE
5. Try **Unacknowledge**
6. Try **Snooze** (7 days)
7. Filter by **Critical** / **High** severity

### 7C. Deploy an Agent

1. Go to **Administration > Agent Keys**
2. Click **"Create API Key"**
3. **Copy the key** (shown only once!)
4. Open PowerShell and run:

```powershell
# Test agent registration + inventory
$headers = @{
    "X-Agent-Key" = "YOUR_KEY_HERE"
    "Content-Type" = "application/json"
}

$body = @{
    hostname = "WIN-SERVER-01"
    os = "Windows Server 2022"
    ip = "192.168.1.100"
    products = @(
        @{vendor="Mozilla"; product="Firefox"; version="115.0"},
        @{vendor="Apache"; product="HTTP Server"; version="2.4.57"},
        @{vendor="OpenSSL"; product="OpenSSL"; version="3.0.2"},
        @{vendor="Microsoft"; product="Exchange Server"; version="2019"},
        @{vendor="Microsoft"; product="Windows Server"; version="2022"}
    )
} | ConvertTo-Json -Depth 3

Invoke-RestMethod -Uri "http://localhost/api/agent/inventory" -Method POST -Headers $headers -Body $body
```

5. Check **Inventory > Connected Endpoints** - "WIN-SERVER-01" should appear
6. Check that new products from agent show up

### 7D. Deploy Linux Agent (if available)

```powershell
# Simulate a Linux server
$body2 = @{
    hostname = "LINUX-WEB-01"
    os = "Ubuntu 22.04 LTS"
    ip = "192.168.1.101"
    products = @(
        @{vendor="Nginx"; product="Nginx"; version="1.24.0"},
        @{vendor="PostgreSQL"; product="PostgreSQL"; version="15.4"},
        @{vendor="Python"; product="Python"; version="3.11.5"},
        @{vendor="Docker"; product="Docker Engine"; version="24.0.7"}
    )
} | ConvertTo-Json -Depth 3

Invoke-RestMethod -Uri "http://localhost/api/agent/inventory" -Method POST -Headers $headers -Body $body2
```

---

## PHASE 8: Test LDAP Login

1. **Log out** from admin account
2. Login with LDAP user:
   - Username: `sec.analyst`
   - Password: `password123`
3. Should see dashboard with limited permissions (analyst role)
4. Log out, try: `it.manager` / `password123` (admin role)
5. Try: `disabled.user` / `password123` - should **FAIL** (no group)

---

## PHASE 9: Test Email Alerts

1. Login as admin
2. Go to **Administration > Settings > Email**
3. Ensure SMTP is configured (from Phase 6A)
4. Go to **Administration > Settings > Alerts**
5. Enable alerts for Critical CVEs
6. Trigger a manual sync (Admin > Sync > Sync Now)
7. Check **http://localhost:8025** (MailHog) for alert emails

---

## PHASE 10: Test Reports & Backup (Professional)

### Reports
1. Go to **Reports**
2. Generate **Vulnerability Report** -> PDF downloaded
3. Generate **Compliance Report** -> PDF with CISA BOD 22-01 status

### Backup
1. Go to **Administration > Backup**
2. Click **"Create Backup"** -> JSON file downloaded
3. Open the file - verify it contains products, vulnerabilities, settings

---

## PHASE 11: Test API Documentation

1. Go to **http://localhost/api/docs**
2. Browse the interactive API documentation
3. Try executing `GET /api/health` from the docs UI
4. Try `GET /api/version`

---

## PHASE 12: Test Security

### Account Lockout
```powershell
# Try 5 wrong passwords
1..5 | ForEach-Object {
    try {
        $loginBody = @{username="admin"; password="wrongpassword$_"} | ConvertTo-Json
        Invoke-RestMethod -Uri "http://localhost/api/auth/login" -Method POST -Body $loginBody -ContentType "application/json"
    } catch { Write-Host "Attempt $_ : $($_.Exception.Response.StatusCode)" }
}
# 6th attempt should show "Account locked"
```

### Security Headers
```powershell
$response = Invoke-WebRequest -Uri "http://localhost" -UseBasicParsing
$response.Headers | Format-Table Key, Value
# Should see: X-Content-Type-Options, X-Frame-Options, Content-Security-Policy
```

### XSS Test
1. Add a product with name: `<script>alert('xss')</script>`
2. Verify the script tag is displayed as text, NOT executed

---

## PHASE 13: Dark Mode

1. Toggle dark mode (theme switch in top bar)
2. Navigate through: Dashboard, Inventory, Admin, Reports
3. Verify all elements are readable and properly styled
4. Toggle back to light mode

---

## PHASE 14: Create Jira Issue from CVE

1. Go to Dashboard, find a Critical CVE
2. Click **"Create Jira Issue"** (or similar button)
3. Check **http://localhost:8080/mockserver/dashboard** for the captured request
4. Verify issue creation payload is correct

---

## Quick Reference Commands

```powershell
# Check SentriKat status
docker compose -f C:\SentriKat\docker-compose.yml ps

# View SentriKat logs
docker logs sentrikat --tail 50

# Restart SentriKat
docker compose -f C:\SentriKat\docker-compose.yml restart

# Full reset (destroy all data)
docker compose -f C:\SentriKat\docker-compose.yml down -v
docker compose -f C:\SentriKat\docker-compose.yml up -d

# Check testlab
docker compose -f C:\SentriKat\testlab\docker-compose.testlab.yml ps

# Check all emails received
Start-Process "http://localhost:8025"

# Check webhook payloads
Start-Process "http://localhost:8800"

# Check Jira mock
Start-Process "http://localhost:8080/mockserver/dashboard"
```

---

## Troubleshooting

### "Connection refused" on port 80
```powershell
# Check if nginx is running
docker logs sentrikat-nginx --tail 20
# Check if something else uses port 80
Get-NetTCPConnection -LocalPort 80 -ErrorAction SilentlyContinue
```

### CISA Sync fails
- Check internet connectivity from container:
  ```powershell
  docker exec sentrikat curl -s https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json | Select-Object -First 100
  ```
- If behind corporate proxy, set `HTTP_PROXY`/`HTTPS_PROXY` in `.env`

### Agent inventory returns 401
- Verify the API key is correct (check for trailing spaces)
- Verify the key is active in Admin > Agent Keys

### License activation fails
- Check Installation ID matches: Admin > License vs `.env`
- Check internet connectivity to portal.sentrikat.com
- Try manual activation via portal

### LDAP login fails
- Test connection first from Admin > LDAP
- Verify testlab LDAP container is running: `docker logs testlab-ldap --tail 20`
- Check with phpLDAPadmin: https://localhost:6443

---

*Guide version 1.0 - February 2026*
