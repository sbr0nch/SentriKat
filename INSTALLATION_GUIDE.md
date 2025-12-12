# SentriKat Production Installation Guide
## Linux Server with Apache - Step by Step

This guide will walk you through installing SentriKat on a fresh Linux server with Apache already installed.

## Table of Contents
1. [Prerequisites Check](#prerequisites-check)
2. [Clean Up Old Services](#clean-up-old-services)
3. [Install Required Software](#install-required-software)
4. [Clone and Setup SentriKat](#clone-and-setup-sentrikat)
5. [Configure SentriKat](#configure-sentrikat)
6. [Setup Systemd Service](#setup-systemd-service)
7. [Configure Apache Reverse Proxy](#configure-apache-reverse-proxy)
8. [Start and Test](#start-and-test)
9. [Maintenance and Troubleshooting](#maintenance-and-troubleshooting)

---

## Prerequisites Check

First, check your system details:

```bash
# Check OS version
cat /etc/os-release

# Check if Apache is running
sudo systemctl status apache2  # Debian/Ubuntu
# OR
sudo systemctl status httpd    # RHEL/CentOS

# Check Apache version
apache2 -v  # Debian/Ubuntu
# OR
httpd -v    # RHEL/CentOS

# Check current user
whoami

# Check available disk space
df -h
```

**Minimum Requirements:**
- Ubuntu 20.04+ / RHEL 8+ / CentOS 8+
- 2GB RAM minimum (4GB recommended)
- 10GB free disk space
- Apache 2.4+
- Root or sudo access

---

## Clean Up Old Services

### Step 1: Check what's currently running

```bash
# List all active services
sudo systemctl list-units --type=service --state=running

# Check what's listening on ports
sudo netstat -tlnp
# OR
sudo ss -tlnp

# Check Apache virtual hosts
apache2ctl -S  # Debian/Ubuntu
# OR
httpd -S       # RHEL/CentOS
```

### Step 2: Identify services to remove

Look for old vulnerability management tools or services you no longer need:

```bash
# Example: Check if old services exist
systemctl status old-vuln-scanner.service
systemctl status legacy-monitor.service
```

### Step 3: Stop and disable old services

```bash
# Stop the service
sudo systemctl stop old-service-name

# Disable from auto-start
sudo systemctl disable old-service-name

# Remove service file (optional)
sudo rm /etc/systemd/system/old-service-name.service

# Reload systemd
sudo systemctl daemon-reload
```

### Step 4: Clean up old files

```bash
# Remove old application directories (CAREFUL!)
# First, backup if needed:
sudo tar -czf /backup/old-app-backup.tar.gz /opt/old-app/

# Then remove:
sudo rm -rf /opt/old-app/
sudo rm -rf /var/www/old-app/

# Remove old Apache configs
sudo rm /etc/apache2/sites-available/old-app.conf
sudo rm /etc/apache2/sites-enabled/old-app.conf

# Remove old log files (optional)
sudo rm -rf /var/log/old-app/
```

---

## Install Required Software

### Step 1: Update system packages

```bash
# Ubuntu/Debian
sudo apt update
sudo apt upgrade -y

# RHEL/CentOS
sudo yum update -y
# OR
sudo dnf update -y
```

### Step 2: Install Python 3.11+

**Ubuntu/Debian:**
```bash
# Install Python 3.11
sudo apt install -y software-properties-common
sudo add-apt-repository ppa:deadsnakes/ppa -y
sudo apt update
sudo apt install -y python3.11 python3.11-venv python3.11-dev

# Install pip
sudo apt install -y python3-pip

# Verify installation
python3.11 --version
```

**RHEL/CentOS:**
```bash
# Install Python 3.11
sudo dnf install -y python3.11 python3.11-devel python3.11-pip

# Verify installation
python3.11 --version
```

### Step 3: Install additional tools

```bash
# Ubuntu/Debian
sudo apt install -y git curl wget build-essential libssl-dev

# RHEL/CentOS
sudo dnf install -y git curl wget gcc openssl-devel
```

### Step 4: Enable required Apache modules

```bash
# Ubuntu/Debian
sudo a2enmod proxy
sudo a2enmod proxy_http
sudo a2enmod headers
sudo a2enmod rewrite
sudo systemctl restart apache2

# RHEL/CentOS
# Modules are usually enabled by default, verify in:
sudo vi /etc/httpd/conf.modules.d/00-proxy.conf
# Ensure these lines are uncommented:
# LoadModule proxy_module modules/mod_proxy.so
# LoadModule proxy_http_module modules/mod_proxy_http.so

sudo systemctl restart httpd
```

---

## Clone and Setup SentriKat

### Step 1: Create application directory

```bash
# Create directory for the application
sudo mkdir -p /opt/sentrikat
sudo chown $USER:$USER /opt/sentrikat
cd /opt/sentrikat
```

### Step 2: Clone the repository

```bash
# Clone your public GitHub repository
git clone https://github.com/sbr0nch/SentriKat.git .

# Verify files were cloned
ls -la
```

### Step 3: Create Python virtual environment

```bash
# Create virtual environment
python3.11 -m venv venv

# Activate virtual environment
source venv/bin/activate

# Verify activation (should show venv path)
which python
```

### Step 4: Install Python dependencies

```bash
# Upgrade pip
pip install --upgrade pip

# Install all requirements
pip install -r requirements.txt

# Verify installation
pip list
```

---

## Configure SentriKat

### Step 1: Generate SECRET_KEY

```bash
# Run the generator
python generate_secret_key.py

# You'll see output like:
# SECRET_KEY=a1b2c3d4e5f6...

# COPY this entire line for the next step
```

### Step 2: Create environment configuration

```bash
# Copy example to actual .env file
cp .env.example .env

# Edit the .env file
nano .env
```

**Paste your SECRET_KEY and configure:**

```bash
# SECRET_KEY - REQUIRED
# Paste the line you copied from generate_secret_key.py
SECRET_KEY=PASTE_YOUR_GENERATED_KEY_HERE

# Database (using SQLite for simplicity)
DATABASE_URL=sqlite:////opt/sentrikat/data/sentrikat.db

# Proxy (if your server needs proxy to reach internet)
# Ask your IT department if unsure
# HTTP_PROXY=http://proxy.company.com:8080
# HTTPS_PROXY=http://proxy.company.com:8080

# Sync schedule (2 AM local time)
SYNC_HOUR=2
SYNC_MINUTE=0

# Flask environment
FLASK_ENV=production
```

**Save and exit:** Press `Ctrl+X`, then `Y`, then `Enter`

### Step 3: Create data directory

```bash
# Create directory for SQLite database
mkdir -p /opt/sentrikat/data

# Set permissions
chmod 755 /opt/sentrikat/data
```

### Step 4: Initialize the database

```bash
# Make sure virtual environment is activated
source /opt/sentrikat/venv/bin/activate

# Test run to initialize database
cd /opt/sentrikat
python run.py &

# Let it run for 5 seconds
sleep 5

# Kill the test run
pkill -f "python run.py"

# Verify database was created
ls -lh /opt/sentrikat/data/
```

---

## Setup Systemd Service

### Step 1: Create service file

```bash
sudo nano /etc/systemd/system/sentrikat.service
```

**Paste this content:**

```ini
[Unit]
Description=SentriKat Vulnerability Management System
After=network.target

[Service]
Type=simple
User=www-data
Group=www-data
WorkingDirectory=/opt/sentrikat
Environment="PATH=/opt/sentrikat/venv/bin"
ExecStart=/opt/sentrikat/venv/bin/gunicorn --bind 127.0.0.1:5000 --workers 2 --timeout 120 run:app
Restart=always
RestartSec=10

# Security settings
NoNewPrivileges=true
PrivateTmp=true

[Install]
WantedBy=multi-user.target
```

**Save and exit:** Press `Ctrl+X`, then `Y`, then `Enter`

### Step 2: Set proper permissions

```bash
# Change ownership to www-data
sudo chown -R www-data:www-data /opt/sentrikat

# Ensure executable permissions
sudo chmod +x /opt/sentrikat/run.py
```

### Step 3: Enable and start the service

```bash
# Reload systemd to recognize new service
sudo systemctl daemon-reload

# Enable service to start on boot
sudo systemctl enable sentrikat

# Start the service
sudo systemctl start sentrikat

# Check status
sudo systemctl status sentrikat

# You should see: "Active: active (running)"
```

### Step 4: Verify service is running

```bash
# Check if it's listening on port 5000
sudo netstat -tlnp | grep 5000
# OR
sudo ss -tlnp | grep 5000

# Test local access
curl http://127.0.0.1:5000

# You should see HTML output
```

---

## Configure Apache Reverse Proxy

### Step 1: Create Apache virtual host configuration

**Ubuntu/Debian:**
```bash
sudo nano /etc/apache2/sites-available/sentrikat.conf
```

**RHEL/CentOS:**
```bash
sudo nano /etc/httpd/conf.d/sentrikat.conf
```

**Paste this configuration:**

```apache
<VirtualHost *:80>
    ServerName vulnerabilities.yourdomain.com
    ServerAlias vuln.yourdomain.com

    # Logging
    ErrorLog ${APACHE_LOG_DIR}/sentrikat-error.log
    CustomLog ${APACHE_LOG_DIR}/sentrikat-access.log combined

    # Proxy settings
    ProxyPreserveHost On
    ProxyPass / http://127.0.0.1:5000/
    ProxyPassReverse / http://127.0.0.1:5000/

    # Security headers
    Header always set X-Frame-Options "SAMEORIGIN"
    Header always set X-Content-Type-Options "nosniff"
    Header always set X-XSS-Protection "1; mode=block"

    # Optional: Restrict access to internal network only
    # <Location />
    #     Require ip 10.0.0.0/8 192.168.0.0/16
    # </Location>
</VirtualHost>
```

**Important:** Replace `vulnerabilities.yourdomain.com` with your actual domain or server IP.

**Save and exit:** Press `Ctrl+X`, then `Y`, then `Enter`

### Step 2: Enable the site and restart Apache

**Ubuntu/Debian:**
```bash
# Disable default site (optional)
sudo a2dissite 000-default.conf

# Enable SentriKat site
sudo a2ensite sentrikat.conf

# Test Apache configuration
sudo apache2ctl configtest

# Should say: "Syntax OK"

# Restart Apache
sudo systemctl restart apache2

# Check status
sudo systemctl status apache2
```

**RHEL/CentOS:**
```bash
# Test Apache configuration
sudo httpd -t

# Should say: "Syntax OK"

# Restart Apache
sudo systemctl restart httpd

# Check status
sudo systemctl status httpd
```

### Step 3: Configure firewall (if enabled)

```bash
# Ubuntu/Debian (ufw)
sudo ufw status
sudo ufw allow 'Apache Full'
sudo ufw allow 22/tcp  # Ensure SSH stays open
sudo ufw enable

# RHEL/CentOS (firewalld)
sudo firewall-cmd --state
sudo firewall-cmd --permanent --add-service=http
sudo firewall-cmd --permanent --add-service=https
sudo firewall-cmd --reload
```

---

## Start and Test

### Step 1: Verify all services are running

```bash
# Check SentriKat service
sudo systemctl status sentrikat

# Check Apache
sudo systemctl status apache2  # or httpd

# Both should show "active (running)"
```

### Step 2: Test local access

```bash
# Test direct access to Flask app
curl http://127.0.0.1:5000

# Test through Apache proxy
curl http://localhost

# Both should return HTML
```

### Step 3: Access from browser

**Option 1: Using server IP**
```
http://YOUR_SERVER_IP
```

**Option 2: Using domain name**
```
http://vulnerabilities.yourdomain.com
```

You should see the SentriKat dashboard!

### Step 4: Perform initial setup in browser

1. **Access the dashboard** - You should see the interface
2. **Click "Sync Now"** - This downloads CISA KEV data
3. **Wait for sync** - Takes 30-60 seconds first time
4. **Go to Products** - Add your software inventory
5. **Click "Sync Now"** again - To match your products

---

## Post-Installation Configuration

### Step 1: Add your first product

1. Go to **Products** page
2. Click **Add Product**
3. Fill in:
   - Vendor: Microsoft
   - Product Name: Windows Server
   - Version: 2022
   - Keywords: Windows, Server
   - Active: ✓

4. Click **Save Product**

### Step 2: Sync and verify matches

1. Click **Sync Now** in navigation
2. Wait for completion
3. Check **Dashboard** - you should see matches now
4. Review vulnerabilities and acknowledge them

### Step 3: Setup log rotation

```bash
sudo nano /etc/logrotate.d/sentrikat
```

**Paste:**
```
/var/log/apache2/sentrikat-*.log {
    daily
    missingok
    rotate 14
    compress
    delaycompress
    notifempty
    create 0640 www-data adm
    sharedscripts
    postrotate
        systemctl reload apache2 > /dev/null 2>&1 || true
    endscript
}
```

---

## Maintenance and Troubleshooting

### View Logs

```bash
# SentriKat application logs
sudo journalctl -u sentrikat -f

# Apache access logs
sudo tail -f /var/log/apache2/sentrikat-access.log

# Apache error logs
sudo tail -f /var/log/apache2/sentrikat-error.log
```

### Restart Services

```bash
# Restart SentriKat
sudo systemctl restart sentrikat

# Restart Apache
sudo systemctl restart apache2  # or httpd

# Restart both
sudo systemctl restart sentrikat apache2
```

### Update SentriKat

```bash
# Stop service
sudo systemctl stop sentrikat

# Navigate to directory
cd /opt/sentrikat

# Pull latest changes
sudo -u www-data git pull origin main

# Activate virtual environment
source venv/bin/activate

# Update dependencies (if needed)
pip install -r requirements.txt

# Restart service
sudo systemctl start sentrikat

# Check status
sudo systemctl status sentrikat
```

### Common Issues

**Issue: "Connection refused" when accessing from browser**
```bash
# Check if SentriKat is running
sudo systemctl status sentrikat

# Check if Apache is running
sudo systemctl status apache2

# Check firewall
sudo ufw status  # Ubuntu
sudo firewall-cmd --list-all  # RHEL/CentOS

# Check if port 5000 is listening
sudo ss -tlnp | grep 5000
```

**Issue: "Sync failed" when clicking Sync Now**
```bash
# Check logs for errors
sudo journalctl -u sentrikat -n 50

# Test internet connectivity
curl https://www.cisa.gov

# If behind proxy, verify .env has correct proxy settings
cat /opt/sentrikat/.env | grep PROXY
```

**Issue: "Permission denied" errors**
```bash
# Fix ownership
sudo chown -R www-data:www-data /opt/sentrikat

# Fix permissions
sudo chmod -R 755 /opt/sentrikat
sudo chmod 644 /opt/sentrikat/.env
```

### Backup and Restore

**Backup:**
```bash
# Backup database and config
sudo tar -czf /backup/sentrikat-$(date +%Y%m%d).tar.gz \
    /opt/sentrikat/data/ \
    /opt/sentrikat/.env

# Copy to safe location
sudo cp /backup/sentrikat-*.tar.gz /mnt/backup/
```

**Restore:**
```bash
# Stop service
sudo systemctl stop sentrikat

# Extract backup
sudo tar -xzf /backup/sentrikat-20241212.tar.gz -C /

# Fix permissions
sudo chown -R www-data:www-data /opt/sentrikat

# Start service
sudo systemctl start sentrikat
```

---

## Security Hardening (Optional)

### Enable HTTPS with Let's Encrypt

```bash
# Ubuntu/Debian
sudo apt install certbot python3-certbot-apache -y

# RHEL/CentOS
sudo dnf install certbot python3-certbot-apache -y

# Obtain certificate
sudo certbot --apache -d vulnerabilities.yourdomain.com

# Follow prompts, choose to redirect HTTP to HTTPS
```

### Restrict access to internal network only

Edit Apache config:
```bash
sudo nano /etc/apache2/sites-available/sentrikat.conf
```

Add inside `<VirtualHost>`:
```apache
<Location />
    # Allow only from internal networks
    Require ip 10.0.0.0/8 192.168.0.0/16 172.16.0.0/12

    # Or allow specific IPs
    # Require ip 192.168.1.100 192.168.1.101
</Location>
```

Restart Apache:
```bash
sudo systemctl restart apache2
```

---

## Quick Command Reference

| Task | Command |
|------|---------|
| Start SentriKat | `sudo systemctl start sentrikat` |
| Stop SentriKat | `sudo systemctl stop sentrikat` |
| Restart SentriKat | `sudo systemctl restart sentrikat` |
| Check status | `sudo systemctl status sentrikat` |
| View logs | `sudo journalctl -u sentrikat -f` |
| Restart Apache | `sudo systemctl restart apache2` |
| Test Apache config | `sudo apache2ctl configtest` |
| Update app | `cd /opt/sentrikat && sudo -u www-data git pull` |

---

## Success Checklist

- [ ] Old services removed
- [ ] Python 3.11+ installed
- [ ] SentriKat cloned from GitHub
- [ ] SECRET_KEY generated and configured
- [ ] Virtual environment created
- [ ] Dependencies installed
- [ ] Database initialized
- [ ] Systemd service created and running
- [ ] Apache reverse proxy configured
- [ ] Firewall rules configured
- [ ] Application accessible from browser
- [ ] Initial sync completed successfully
- [ ] At least one product added
- [ ] Vulnerabilities showing on dashboard
- [ ] Logs are being written correctly

---

## Getting Help

If you encounter issues:

1. **Check logs first:**
   ```bash
   sudo journalctl -u sentrikat -n 100
   ```

2. **Verify configuration:**
   ```bash
   cat /opt/sentrikat/.env
   sudo apache2ctl -S
   ```

3. **Test connectivity:**
   ```bash
   curl http://127.0.0.1:5000
   curl http://localhost
   ```

4. **Check permissions:**
   ```bash
   ls -la /opt/sentrikat/
   ```

**Your installation is complete! 🎉**

Access your SentriKat dashboard and start managing vulnerabilities!
