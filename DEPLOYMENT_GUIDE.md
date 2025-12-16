# SentriKat Deployment Guide

This guide will walk you through deploying the latest SentriKat features to your live server.

## Prerequisites

- Python 3.8 or higher
- PostgreSQL or SQLite database
- Git installed on your server
- SMTP server credentials (for email alerts)

## Step 1: Pull the Latest Changes

```bash
cd /path/to/SentriKat
git checkout claude/retry-task-0164dJBaeL4rFJmP5RBkbodX
git pull origin claude/retry-task-0164dJBaeL4rFJmP5RBkbodX
```

## Step 2: Install Dependencies

If you added any new dependencies (like ldap3 for LDAP authentication):

```bash
# Activate your virtual environment first
source venv/bin/activate  # On Linux/Mac
# or
venv\Scripts\activate  # On Windows

# Install/update dependencies
pip install -r requirements.txt

# Optional: For LDAP authentication support
pip install ldap3
```

## Step 3: Configure Environment Variables

Edit your `.env` file or set environment variables:

```bash
# Database Configuration
DATABASE_URL=postgresql://user:password@localhost/sentrikat

# SMTP Configuration (Required for email alerts)
SMTP_SERVER=smtp.gmail.com
SMTP_PORT=587
SMTP_USERNAME=your-email@gmail.com
SMTP_PASSWORD=your-app-password
SMTP_FROM_EMAIL=noreply@yourcompany.com
SMTP_FROM_NAME=SentriKat Security Alerts
SMTP_USE_TLS=true

# NVD API Configuration
NVD_API_KEY=your-nvd-api-key-here

# Authentication (Optional - defaults to false)
ENABLE_AUTH=true  # Set to 'true' to enable authentication, 'false' to disable

# LDAP Configuration (Optional - only if using LDAP auth)
LDAP_SERVER=ldap.yourcompany.com
LDAP_PORT=389
LDAP_USE_SSL=false

# Proxy Configuration (Optional)
# HTTP_PROXY=http://proxy.company.com:8080
# HTTPS_PROXY=http://proxy.company.com:8080
```

### Important Notes:

- **SMTP Configuration**: Required for email alerts to work. Use your email provider's SMTP settings.
- **ENABLE_AUTH**: Set to `true` if you want to require login, `false` for open access (default).
- **NVD_API_KEY**: Get a free API key from https://nvd.nist.gov/developers/request-an-api-key

## Step 4: Run Database Migrations

Apply the latest database schema changes:

```bash
# Initialize migrations if this is a fresh install
flask db init

# Create migration for the changes
flask db migrate -m "Add authentication and multi-tenancy features"

# Apply the migration
flask db upgrade
```

**Note**: If you already have an existing database with the previous migrations, you only need `flask db upgrade`.

## Step 5: Seed Service Catalog

The application includes 80+ common enterprise services. To populate them:

```bash
python seed_services.py
```

This will create services like:
- Microsoft Windows Server, Exchange, SQL Server
- VMware ESXi, vCenter, NSX
- Cisco IOS, ASA, ISE
- Apache, Nginx, Tomcat
- And many more...

**Check the output**: The script will show how many services were created or already exist.

## Step 6: Create Default Organization

If this is a fresh installation, create a default organization:

```bash
flask shell
```

Then in the Flask shell:

```python
from app import db
from app.models import Organization

# Create default organization
org = Organization(
    name='default',
    display_name='Default Organization',
    description='Default organization for uncategorized products',
    active=True
)
db.session.add(org)
db.session.commit()
print(f"Created organization: {org.display_name} (ID: {org.id})")
exit()
```

## Step 7: Create Admin User (If Authentication is Enabled)

If you set `ENABLE_AUTH=true`, you need to create an admin user:

```bash
flask shell
```

Then in the Flask shell:

```python
from app import db
from app.models import User, Organization

# Get default organization
org = Organization.query.filter_by(name='default').first()

# Create admin user
admin = User(
    username='admin',
    email='admin@yourcompany.com',
    full_name='System Administrator',
    is_admin=True,
    is_active=True,
    auth_type='local',
    organization_id=org.id if org else None
)

# Set password
admin.set_password('ChangeMe123!')  # CHANGE THIS PASSWORD!

db.session.add(admin)
db.session.commit()
print(f"Created admin user: {admin.username}")
print("IMPORTANT: Change the default password after first login!")
exit()
```

**CRITICAL**: Change the default password immediately after first login!

## Step 8: Test CISA KEV Sync

Run a manual sync to test everything is working:

```bash
flask shell
```

Then in the Flask shell:

```python
from app.cisa_sync import sync_cisa_kev

# Run sync with CVSS enrichment
result = sync_cisa_kev(enrich_cvss=True, cvss_limit=50)

print(f"Status: {result['status']}")
print(f"New vulnerabilities: {result.get('stored', 0)}")
print(f"Updated vulnerabilities: {result.get('updated', 0)}")
print(f"Matches found: {result.get('matches', 0)}")
print(f"Duration: {result.get('duration', 0):.2f} seconds")

if result.get('alerts_sent'):
    print(f"Email alerts sent: {len(result['alerts_sent'])}")
    for alert in result['alerts_sent']:
        print(f"  - {alert['organization']}: {alert['result']}")

exit()
```

**Expected Output**:
- Should download CISA KEV catalog (~1000+ vulnerabilities)
- Should match vulnerabilities to your products
- Should enrich first 50 CVEs with CVSS scores from NVD
- Should send email alerts if configured

## Step 9: Set Up Automated Sync (Optional but Recommended)

### Option A: Cron Job (Linux)

```bash
crontab -e
```

Add this line to sync every 6 hours:

```cron
0 */6 * * * cd /path/to/SentriKat && /path/to/venv/bin/python -c "from app.cisa_sync import sync_cisa_kev; sync_cisa_kev(enrich_cvss=True, cvss_limit=100)"
```

### Option B: Systemd Timer (Linux)

Create `/etc/systemd/system/sentrikat-sync.service`:

```ini
[Unit]
Description=SentriKat CISA KEV Sync
After=network.target

[Service]
Type=oneshot
User=your-user
WorkingDirectory=/path/to/SentriKat
Environment="PATH=/path/to/venv/bin"
ExecStart=/path/to/venv/bin/python -c "from app.cisa_sync import sync_cisa_kev; sync_cisa_kev(enrich_cvss=True, cvss_limit=100)"
```

Create `/etc/systemd/system/sentrikat-sync.timer`:

```ini
[Unit]
Description=Run SentriKat sync every 6 hours

[Timer]
OnBootSec=15min
OnUnitActiveSec=6h

[Install]
WantedBy=timers.target
```

Enable and start:

```bash
sudo systemctl daemon-reload
sudo systemctl enable sentrikat-sync.timer
sudo systemctl start sentrikat-sync.timer
```

## Step 10: Start the Application

### Development Mode (for testing):

```bash
flask run --host=0.0.0.0 --port=5000
```

### Production Mode (recommended):

Using Gunicorn:

```bash
gunicorn -w 4 -b 0.0.0.0:5000 run:app
```

Using systemd service:

Create `/etc/systemd/system/sentrikat.service`:

```ini
[Unit]
Description=SentriKat Vulnerability Management
After=network.target

[Service]
Type=notify
User=your-user
WorkingDirectory=/path/to/SentriKat
Environment="PATH=/path/to/venv/bin"
ExecStart=/path/to/venv/bin/gunicorn -w 4 -b 127.0.0.1:5000 run:app
Restart=always

[Install]
WantedBy=multi-user.target
```

Then:

```bash
sudo systemctl daemon-reload
sudo systemctl enable sentrikat
sudo systemctl start sentrikat
sudo systemctl status sentrikat
```

### Nginx Reverse Proxy (recommended for production):

Create `/etc/nginx/sites-available/sentrikat`:

```nginx
server {
    listen 80;
    server_name sentrikat.yourcompany.com;

    location / {
        proxy_pass http://127.0.0.1:5000;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }
}
```

Enable and restart:

```bash
sudo ln -s /etc/nginx/sites-available/sentrikat /etc/nginx/sites-enabled/
sudo nginx -t
sudo systemctl restart nginx
```

## Step 11: Access and Test the Application

1. **Open your browser** and navigate to:
   - Development: `http://your-server:5000`
   - Production: `http://sentrikat.yourcompany.com`

2. **If authentication is enabled** (`ENABLE_AUTH=true`):
   - You should see the login page
   - Login with: username=`admin`, password=`ChangeMe123!`
   - **IMMEDIATELY** change your password!

3. **Test the features**:

### Test Organization Management

1. Navigate to **Organizations** page
2. Create a new organization:
   - Name: `engineering`
   - Display Name: `Engineering Team`
   - Description: `Engineering department products`
3. Create another organization:
   - Name: `operations`
   - Display Name: `Operations Team`

### Test Product Management

1. Navigate to **Products** page
2. Add a product:
   - Vendor: `Microsoft`
   - Product Name: `Windows Server`
   - Version: `2019`
   - Keywords: `windows, server, microsoft`
   - Select your organization
3. The product should be added and visible only to the selected organization

### Test Organization Switcher

1. Look at the top navigation bar
2. You should see a dropdown with your current organization
3. Click the dropdown and select a different organization
4. The page should reload and show products/vulnerabilities for that organization only

### Test Vulnerability Matching

1. After adding products, run a sync (or wait for the next scheduled sync)
2. Navigate to **Vulnerabilities** page
3. You should see vulnerabilities matched to your products
4. Filter by:
   - Product (dropdown)
   - CVE ID (search)
   - Ransomware only (checkbox)
   - Acknowledged status (dropdown)

### Test Priority System

1. Vulnerabilities should show priority badges:
   - **CRITICAL** (red) - CVSS 9.0-10.0
   - **HIGH** (orange) - CVSS 7.0-8.9
   - **MEDIUM** (yellow) - CVSS 4.0-6.9
   - **LOW** (blue) - CVSS 0.1-3.9
   - **N/A** (gray) - No CVSS score

2. Check the statistics dashboard for priority breakdown

### Test Email Alerts

1. Add a test product that matches a recent CISA KEV entry
2. Run a manual sync
3. Check your email for alert notifications
4. The email should include:
   - Organization name
   - List of new critical CVEs
   - Product matches
   - Links to acknowledge vulnerabilities

### Test Acknowledgment Workflow

1. Click on a vulnerability match
2. Click the "Acknowledge" button
3. The vulnerability should be marked as acknowledged
4. It should no longer appear in email alerts

## Step 12: Change Admin Password (IMPORTANT!)

If authentication is enabled:

1. Login as admin
2. Navigate to your user profile (if profile page exists) or use Flask shell:

```bash
flask shell
```

```python
from app import db
from app.models import User

admin = User.query.filter_by(username='admin').first()
admin.set_password('YourSecurePasswordHere!')
db.session.commit()
print("Password changed successfully!")
exit()
```

## Troubleshooting

### Issue: No vulnerabilities showing

**Solution**:
- Check if CISA sync completed successfully
- Check if products are added and match vulnerability keywords
- Run manual sync and check for errors

### Issue: Email alerts not working

**Solution**:
- Verify SMTP settings in `.env`
- Test SMTP connection:

```python
flask shell
from app.email_alerts import EmailAlertManager
EmailAlertManager.test_smtp_connection()
```

- Check spam folder
- Verify organization has email set up

### Issue: Organization switcher not showing

**Solution**:
- Check browser console for JavaScript errors
- Verify `/api/organizations` endpoint returns data
- Clear browser cache

### Issue: Authentication not working

**Solution**:
- Verify `ENABLE_AUTH=true` in environment
- Check if admin user exists: `flask shell` → `User.query.all()`
- Check session configuration in `config.py`

### Issue: CVSS scores not showing

**Solution**:
- Verify NVD_API_KEY is set
- Run enrichment manually: `sync_cisa_kev(enrich_cvss=True, cvss_limit=100)`
- Check NVD API rate limits (50 requests per 30 seconds with API key)

### Issue: Products not filtering by organization

**Solution**:
- Check if session has organization_id set
- Verify organization exists in database
- Check browser cookies are enabled

## Security Best Practices

1. **Change default passwords** immediately
2. **Enable HTTPS** in production (use Let's Encrypt)
3. **Set strong SECRET_KEY** in config.py
4. **Use environment variables** for sensitive data (never commit .env)
5. **Enable authentication** in production (`ENABLE_AUTH=true`)
6. **Regularly update** dependencies
7. **Monitor logs** for suspicious activity
8. **Backup database** regularly
9. **Use firewall** to restrict access to server
10. **Implement rate limiting** for API endpoints

## Monitoring

### Check Sync Logs

```bash
flask shell
```

```python
from app.models import SyncLog

# Get recent syncs
recent_syncs = SyncLog.query.order_by(SyncLog.timestamp.desc()).limit(10).all()

for sync in recent_syncs:
    print(f"{sync.timestamp} - {sync.status}")
    if sync.status == 'success':
        print(f"  Vulnerabilities: {sync.vulnerabilities_count}")
        print(f"  Matches: {sync.matches_found}")
        print(f"  Duration: {sync.duration_seconds}s")
    else:
        print(f"  Error: {sync.error_message}")

exit()
```

### Monitor Application Logs

```bash
# If using systemd
sudo journalctl -u sentrikat -f

# If using log file
tail -f /var/log/sentrikat/app.log
```

## Maintenance

### Regular Updates

```bash
cd /path/to/SentriKat
git pull origin claude/retry-task-0164dJBaeL4rFJmP5RBkbodX
pip install -r requirements.txt
flask db upgrade
sudo systemctl restart sentrikat
```

### Database Backup

```bash
# PostgreSQL
pg_dump sentrikat > backup_$(date +%Y%m%d).sql

# SQLite
cp instance/sentrikat.db backup_$(date +%Y%m%d).db
```

### Clean Old Data (Optional)

```bash
flask shell
```

```python
from app import db
from app.models import VulnerabilityMatch, SyncLog
from datetime import datetime, timedelta

# Delete acknowledged matches older than 90 days
cutoff = datetime.utcnow() - timedelta(days=90)
old_matches = VulnerabilityMatch.query.filter(
    VulnerabilityMatch.acknowledged == True,
    VulnerabilityMatch.acknowledged_at < cutoff
).delete()

# Delete sync logs older than 30 days
cutoff = datetime.utcnow() - timedelta(days=30)
old_logs = SyncLog.query.filter(SyncLog.timestamp < cutoff).delete()

db.session.commit()
print(f"Deleted {old_matches} old matches and {old_logs} old sync logs")
exit()
```

## Support

For issues or questions:
1. Check this deployment guide
2. Review application logs
3. Check GitHub issues
4. Contact your system administrator

## Feature Summary

### ✅ Authentication System
- Optional login/logout (toggle with ENABLE_AUTH)
- Local and LDAP authentication support
- Admin and regular user roles
- Session-based authentication

### ✅ Email Alerts
- Automated alerts after each sync
- Per-organization alert filtering
- Configurable SMTP settings
- Professional HTML email templates

### ✅ Multi-Tenancy
- Organization-based data isolation
- Organization switcher in UI
- Separate product catalogs per organization
- Filtered vulnerability views

### ✅ Priority System
- CVSS-based priority classification
- Color-coded severity badges
- Priority statistics dashboard
- CISA urgency consideration

### ✅ Service Catalog
- 80+ pre-configured enterprise services
- Easy product assignment
- Vendor and product matching
- Keyword-based filtering

### ✅ Vulnerability Management
- Automatic CISA KEV sync
- NVD CVSS enrichment
- Product matching engine
- Acknowledgment workflow
- Ransomware tracking

---

**Congratulations!** Your SentriKat deployment is now complete and ready for production use.
