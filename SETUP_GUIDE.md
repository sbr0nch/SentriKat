# SentriKat Setup Guide

This guide will walk you through setting up SentriKat for your organization.

## Table of Contents

1. [Understanding SECRET_KEY](#understanding-secret_key)
2. [Proxy Configuration](#proxy-configuration)
3. [Installation Methods](#installation-methods)
4. [First Time Setup](#first-time-setup)
5. [Adding Your Products](#adding-your-products)

## Understanding SECRET_KEY

### What is SECRET_KEY?

The `SECRET_KEY` is a cryptographically secure random string that Flask uses for security purposes:

- **Session Security**: Signs session cookies to prevent users from tampering with session data
- **Data Encryption**: Encrypts sensitive data stored in cookies
- **CSRF Protection**: Provides protection against Cross-Site Request Forgery attacks

### Why is it important?

Without a strong SECRET_KEY, attackers could:
- Forge session cookies and impersonate other users
- Tamper with application data
- Bypass security controls

### How to generate a SECRET_KEY?

We provide a helper script:

```bash
python generate_secret_key.py
```

This will output two options:

```
Generated SECRET_KEYs (choose one):

Option 1 - Hexadecimal (recommended):
SECRET_KEY=a1b2c3d4e5f6...

Option 2 - Alphanumeric:
SECRET_KEY=AbCdEfGh123...
```

**Copy one of these lines and paste it into your `.env` file.**

### Security Best Practices

- ✅ Generate a unique SECRET_KEY for each environment (dev, staging, production)
- ✅ Keep SECRET_KEY private and secure
- ✅ Never commit SECRET_KEY to version control
- ✅ Use at least 64 characters
- ✅ If compromised, generate a new key immediately (this will invalidate all sessions)
- ❌ Never share your SECRET_KEY
- ❌ Never use the default key in production

## Proxy Configuration

### Do I need proxy configuration?

You need proxy configuration if:

- Your company requires a proxy to access external websites
- You get connection errors when trying to sync CISA KEV data
- Your network administrator told you to use a proxy

### How to configure proxy?

1. Ask your IT department for proxy details:
   - Proxy hostname/IP
   - Proxy port
   - Authentication requirements (if any)

2. Add to your `.env` file:

```bash
# Basic proxy (no authentication)
HTTP_PROXY=http://proxy.company.com:8080
HTTPS_PROXY=http://proxy.company.com:8080

# Proxy with authentication
HTTP_PROXY=http://username:password@proxy.company.com:8080
HTTPS_PROXY=http://username:password@proxy.company.com:8080

# Exclude internal domains
NO_PROXY=localhost,127.0.0.1,.company.internal
```

3. Restart SentriKat:

```bash
# Docker
docker-compose restart

# Manual
# Stop the app (Ctrl+C) and run again
python run.py
```

### Testing proxy configuration

After configuration, click "Sync Now" in the dashboard. If successful, the proxy is working correctly.

If you still get errors:
- Verify proxy details with IT
- Check if proxy requires authentication
- Ensure firewall allows outbound HTTPS (port 443)
- Try accessing https://www.cisa.gov in a browser from the same server

## Installation Methods

### Option 1: Docker (Recommended)

**Pros**: Easy, consistent, isolated
**Requirements**: Docker and docker-compose installed

```bash
# 1. Clone repository
git clone <repository-url>
cd SentriKat

# 2. Generate SECRET_KEY
python generate_secret_key.py

# 3. Configure environment
cp .env.example .env
nano .env  # Edit and add your SECRET_KEY and proxy settings

# 4. Start application
docker-compose up -d

# 5. Access application
# Open http://localhost:5000 in your browser
```

### Option 2: Manual Installation

**Pros**: More control, easier debugging
**Requirements**: Python 3.11+

```bash
# 1. Clone repository
git clone <repository-url>
cd SentriKat

# 2. Create virtual environment
python3 -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

# 3. Install dependencies
pip install -r requirements.txt

# 4. Generate SECRET_KEY
python generate_secret_key.py

# 5. Configure environment
cp .env.example .env
nano .env  # Edit and add your SECRET_KEY and proxy settings

# 6. Run application
python run.py

# 7. Access application
# Open http://localhost:5000 in your browser
```

### Option 3: Production Deployment with Nginx

For production deployment behind Nginx reverse proxy:

1. Follow Option 1 or 2 above
2. Configure Nginx:

```nginx
server {
    listen 80;
    server_name vulnerabilities.company.internal;

    location / {
        proxy_pass http://localhost:5000;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }
}
```

3. Enable site and restart Nginx:

```bash
sudo ln -s /etc/nginx/sites-available/sentrikat /etc/nginx/sites-enabled/
sudo nginx -t
sudo systemctl restart nginx
```

## First Time Setup

### 1. Access the application

Open your browser and go to:
- Local: http://localhost:5000
- Network: http://your-server-ip:5000
- Domain: http://vulnerabilities.company.internal

### 2. Perform initial sync

1. Click **"Sync Now"** button in the top navigation
2. Wait for the sync to complete (may take 30-60 seconds)
3. You should see: "✓ Sync completed! X vulnerabilities updated, 0 matches found"

**Note**: 0 matches is normal on first sync because you haven't added any products yet.

### 3. Verify sync success

- Check Dashboard shows statistics
- "Total Vulnerabilities" should show a number (typically 1000+)
- "Last Synchronization" at the bottom should show recent date/time

## Adding Your Products

### Understanding Product Matching

SentriKat matches vulnerabilities to your products by:

1. **Vendor Name**: CVE vendor contains your product's vendor
2. **Product Name**: CVE product contains your product name
3. **Keywords**: Additional terms that might appear in CVEs

### Product Addition Workflow

1. **Go to Products page**
   - Click "Products" in top navigation

2. **Click "Add Product"**
   - Fill in the form

3. **Fill in details**:

   **Example 1 - Microsoft Windows Server**
   ```
   Vendor: Microsoft
   Product Name: Windows Server
   Version: 2022 (optional)
   Keywords: Windows, Server (optional but recommended)
   Description: Production web servers (optional)
   Active: ✓ (checked)
   ```

   **Example 2 - Cisco IOS**
   ```
   Vendor: Cisco
   Product Name: IOS
   Version: 15.2 (optional)
   Keywords: Catalyst, Switch, Router
   Description: Network infrastructure switches
   Active: ✓ (checked)
   ```

   **Example 3 - Apache Tomcat**
   ```
   Vendor: Apache
   Product Name: Tomcat
   Version: 9.0 (optional)
   Keywords: Java, Application Server
   Description: Java application servers
   Active: ✓ (checked)
   ```

4. **Click "Save Product"**

5. **Repeat for all your products**

### Tips for Better Matching

1. **Be specific with vendor names**
   - ✅ "Microsoft" instead of "MS"
   - ✅ "Cisco Systems" or just "Cisco"
   - ✅ "Apache Software Foundation" or just "Apache"

2. **Use common product names**
   - Check CISA KEV catalog for naming conventions
   - Use both full and short names as keywords

3. **Add relevant keywords**
   - Product variations (e.g., "Exchange" for "Exchange Server")
   - Related components (e.g., "IIS" for Windows Server)
   - Acronyms and abbreviations

4. **Examples from real CVEs**:

   | Your Product | CVE Lists As | Use These Values |
   |--------------|--------------|------------------|
   | Windows 11   | Microsoft Windows | Vendor: Microsoft, Product: Windows, Keywords: Windows 11 |
   | iPhone | Apple iPhone | Vendor: Apple, Product: iPhone, Keywords: iOS |
   | Chrome Browser | Google Chrome | Vendor: Google, Product: Chrome, Keywords: Browser, Chromium |

### After Adding Products

1. **Trigger a new sync**
   - Go to Dashboard
   - Click "Sync Now"

2. **Check for matches**
   - "Affecting Your Products" card should now show matches
   - Scroll down to see matched vulnerabilities

3. **Review and acknowledge**
   - Click on each vulnerability to review
   - Click "Acknowledge" after reviewing
   - Use "Bulk Acknowledge" for multiple items

## Ongoing Maintenance

### Daily Operations

- SentriKat automatically syncs daily at 2:00 AM (configurable)
- Check dashboard regularly for new vulnerabilities
- Acknowledge reviewed items
- Update product versions when you upgrade

### Monthly Tasks

- Review inactive/decommissioned products
- Update product list as infrastructure changes
- Check sync history for any failures
- Export reports if needed

### Best Practices

- Document why you acknowledged each vulnerability
- Keep product inventory up to date
- Set up notifications (future feature)
- Export monthly reports for compliance

## Troubleshooting

### Sync Fails

**Error**: "Failed to download CISA KEV"

**Solutions**:
1. Check internet connectivity
2. Verify proxy configuration if behind proxy
3. Check firewall allows HTTPS to cisa.gov
4. View sync history for detailed error messages

### No Matches Found

**Possible causes**:
1. Products not marked as "Active"
2. Vendor/product names don't match CVE format
3. Need better keywords

**Solutions**:
1. Check product is Active in Products page
2. Review product names against CISA KEV catalog
3. Add more keywords
4. Manually trigger sync after changes

### Application Won't Start

**Docker**:
```bash
# Check logs
docker-compose logs -f sentrikat

# Restart
docker-compose restart

# Rebuild
docker-compose down
docker-compose up -d --build
```

**Manual**:
```bash
# Check for errors
python run.py

# Common issues:
# - Missing dependencies: pip install -r requirements.txt
# - Port in use: Change port in run.py or docker-compose.yml
# - Database locked: Stop other instances
```

## Getting Help

### Before asking for help

1. Check logs for error messages
2. Verify configuration in `.env`
3. Test connectivity to cisa.gov
4. Review this guide again

### Information to provide

When seeking help, include:
- Error messages from logs
- Your configuration (remove SECRET_KEY!)
- Steps to reproduce the issue
- Browser console errors (F12 developer tools)

## Next Steps

Once setup is complete:

1. ✅ Generate SECRET_KEY
2. ✅ Configure proxy (if needed)
3. ✅ Install and start application
4. ✅ Perform initial sync
5. ✅ Add all your products
6. ✅ Review matched vulnerabilities
7. ✅ Set up regular monitoring workflow
8. 📧 Consider email notifications (future feature)
9. 📊 Export regular reports for management
10. 🔒 Set up authentication (if needed)

---

**Questions?** Contact your internal security team or create an issue in the repository.
