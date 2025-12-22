# SentriKat Installation Guide

This guide covers installing SentriKat on various platforms including Linux, Docker, and Windows.

---

## Table of Contents

- [Prerequisites](#prerequisites)
- [Docker Installation (Recommended)](#docker-installation-recommended)
- [Linux Installation](#linux-installation)
- [Windows Installation](#windows-installation)
- [Production Deployment](#production-deployment)
- [Upgrading](#upgrading)
- [Uninstallation](#uninstallation)

---

## Prerequisites

### Minimum Requirements

| Component | Requirement |
|-----------|-------------|
| CPU | 1 core |
| Memory | 512 MB RAM |
| Disk | 100 MB + database storage |
| Network | Outbound HTTPS (port 443) for CISA KEV sync |

### Software Requirements

- **Python 3.11+** (for manual installation)
- **Docker & Docker Compose** (for containerized deployment)
- **Git** (to clone repository)

---

## Docker Installation (Recommended)

Docker is the recommended installation method for production environments.

### Step 1: Install Docker

**Ubuntu/Debian:**
```bash
# Update packages
sudo apt update

# Install Docker
sudo apt install -y docker.io docker-compose

# Start and enable Docker
sudo systemctl start docker
sudo systemctl enable docker

# Add current user to docker group (logout required)
sudo usermod -aG docker $USER
```

**CentOS/RHEL:**
```bash
# Install Docker
sudo yum install -y docker docker-compose

# Start and enable Docker
sudo systemctl start docker
sudo systemctl enable docker
```

**Windows/macOS:**
- Download and install [Docker Desktop](https://www.docker.com/products/docker-desktop/)

### Step 2: Clone Repository

```bash
git clone https://github.com/your-org/SentriKat.git
cd SentriKat
```

### Step 3: Configure Environment

```bash
# Copy example environment file
cp .env.example .env

# Generate SECRET_KEY
python3 -c "import secrets; print(f'SECRET_KEY={secrets.token_hex(32)}')" >> .env

# Generate ENCRYPTION_KEY (requires cryptography package)
pip3 install cryptography
python3 -c "from cryptography.fernet import Fernet; print(f'ENCRYPTION_KEY={Fernet.generate_key().decode()}')" >> .env
```

Or manually edit `.env`:
```bash
# Required for production
SECRET_KEY=your-64-character-hex-string
ENCRYPTION_KEY=your-fernet-key

# Optional
DATABASE_URL=sqlite:////app/data/sentrikat.db
FLASK_ENV=production
```

### Step 4: Start Application

```bash
# Build and start containers
docker-compose up -d

# View logs
docker-compose logs -f

# Check status
docker-compose ps
```

### Step 5: Access Application

1. Open browser: `http://localhost:5000`
2. Complete the setup wizard
3. Create your first organization and admin user

### Docker Compose Configuration

Default `docker-compose.yml`:
```yaml
version: '3.8'

services:
  sentrikat:
    build: .
    ports:
      - "5000:5000"
    volumes:
      - ./data:/app/data
    environment:
      - SECRET_KEY=${SECRET_KEY}
      - ENCRYPTION_KEY=${ENCRYPTION_KEY}
      - DATABASE_URL=sqlite:////app/data/sentrikat.db
      - FLASK_ENV=production
    restart: unless-stopped
```

**Custom port:**
```yaml
ports:
  - "8080:5000"  # Access on port 8080
```

**Persistent data location:**
```yaml
volumes:
  - /var/lib/sentrikat:/app/data
```

---

## Linux Installation

Manual installation on Linux without Docker.

### Step 1: Install System Dependencies

**Ubuntu/Debian:**
```bash
sudo apt update
sudo apt install -y python3.11 python3.11-venv python3-pip git
```

**CentOS/RHEL:**
```bash
sudo yum install -y python3.11 python3-pip git
```

**Fedora:**
```bash
sudo dnf install -y python3.11 python3-pip git
```

### Step 2: Create Application Directory

```bash
# Create directory
sudo mkdir -p /opt/sentrikat
sudo chown $USER:$USER /opt/sentrikat

# Clone repository
cd /opt/sentrikat
git clone https://github.com/your-org/SentriKat.git .
```

### Step 3: Create Virtual Environment

```bash
# Create virtual environment
python3.11 -m venv venv

# Activate virtual environment
source venv/bin/activate

# Upgrade pip
pip install --upgrade pip
```

### Step 4: Install Dependencies

```bash
pip install -r requirements.txt
```

### Step 5: Configure Environment

```bash
# Copy example configuration
cp .env.example .env

# Generate keys
echo "SECRET_KEY=$(python -c 'import secrets; print(secrets.token_hex(32))')" >> .env
echo "ENCRYPTION_KEY=$(python -c 'from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())')" >> .env

# Set database location
echo "DATABASE_URL=sqlite:////opt/sentrikat/data/sentrikat.db" >> .env

# Create data directory
mkdir -p /opt/sentrikat/data
```

### Step 6: Run Application

**Development mode:**
```bash
source venv/bin/activate
python run.py
```

**Production mode with Gunicorn:**
```bash
source venv/bin/activate
gunicorn -w 4 -b 0.0.0.0:5000 "app:create_app()"
```

### Step 7: Create Systemd Service (Optional)

Create `/etc/systemd/system/sentrikat.service`:
```ini
[Unit]
Description=SentriKat Vulnerability Management
After=network.target

[Service]
Type=simple
User=sentrikat
Group=sentrikat
WorkingDirectory=/opt/sentrikat
Environment="PATH=/opt/sentrikat/venv/bin"
EnvironmentFile=/opt/sentrikat/.env
ExecStart=/opt/sentrikat/venv/bin/gunicorn -w 4 -b 0.0.0.0:5000 "app:create_app()"
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target
```

Enable and start:
```bash
sudo systemctl daemon-reload
sudo systemctl enable sentrikat
sudo systemctl start sentrikat
sudo systemctl status sentrikat
```

---

## Windows Installation

### Step 1: Install Python

1. Download Python 3.11+ from [python.org](https://www.python.org/downloads/)
2. Run installer with "Add Python to PATH" checked
3. Verify installation:
```powershell
python --version
```

### Step 2: Clone Repository

```powershell
git clone https://github.com/your-org/SentriKat.git
cd SentriKat
```

### Step 3: Create Virtual Environment

```powershell
python -m venv venv
.\venv\Scripts\activate
pip install --upgrade pip
```

### Step 4: Install Dependencies

```powershell
pip install -r requirements.txt
```

### Step 5: Configure Environment

```powershell
# Copy example configuration
copy .env.example .env

# Generate keys (run in Python)
python -c "import secrets; print(f'SECRET_KEY={secrets.token_hex(32)}')"
python -c "from cryptography.fernet import Fernet; print(f'ENCRYPTION_KEY={Fernet.generate_key().decode()}')"

# Edit .env file with generated keys
notepad .env
```

### Step 6: Run Application

```powershell
.\venv\Scripts\activate
python run.py
```

### Windows Service (Optional)

Use [NSSM](https://nssm.cc/) to run as Windows service:
```powershell
nssm install SentriKat "C:\SentriKat\venv\Scripts\python.exe" "C:\SentriKat\run.py"
nssm start SentriKat
```

---

## Production Deployment

### Reverse Proxy with Nginx

Install Nginx:
```bash
sudo apt install -y nginx
```

Create `/etc/nginx/sites-available/sentrikat`:
```nginx
server {
    listen 80;
    server_name sentrikat.yourdomain.com;

    # Redirect HTTP to HTTPS
    return 301 https://$server_name$request_uri;
}

server {
    listen 443 ssl http2;
    server_name sentrikat.yourdomain.com;

    # SSL certificates
    ssl_certificate /etc/letsencrypt/live/sentrikat.yourdomain.com/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/sentrikat.yourdomain.com/privkey.pem;

    # SSL settings
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_ciphers ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256;
    ssl_prefer_server_ciphers off;

    # Security headers
    add_header X-Frame-Options "SAMEORIGIN" always;
    add_header X-Content-Type-Options "nosniff" always;
    add_header X-XSS-Protection "1; mode=block" always;

    location / {
        proxy_pass http://127.0.0.1:5000;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;

        # WebSocket support (if needed)
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "upgrade";
    }

    # Static files (optional optimization)
    location /static {
        alias /opt/sentrikat/static;
        expires 30d;
        add_header Cache-Control "public, immutable";
    }
}
```

Enable site:
```bash
sudo ln -s /etc/nginx/sites-available/sentrikat /etc/nginx/sites-enabled/
sudo nginx -t
sudo systemctl reload nginx
```

### SSL with Let's Encrypt

```bash
sudo apt install -y certbot python3-certbot-nginx
sudo certbot --nginx -d sentrikat.yourdomain.com
```

### PostgreSQL Database (Recommended for Production)

Install PostgreSQL:
```bash
sudo apt install -y postgresql postgresql-contrib
```

Create database:
```bash
sudo -u postgres psql
CREATE USER sentrikat WITH PASSWORD 'secure_password';
CREATE DATABASE sentrikat OWNER sentrikat;
\q
```

Update `.env`:
```bash
DATABASE_URL=postgresql://sentrikat:secure_password@localhost/sentrikat
```

Install PostgreSQL driver:
```bash
pip install psycopg2-binary
```

---

## Upgrading

### Docker Upgrade

```bash
cd /path/to/SentriKat

# Pull latest changes
git pull origin main

# Rebuild and restart
docker-compose down
docker-compose build --no-cache
docker-compose up -d
```

### Manual Upgrade

```bash
cd /opt/sentrikat

# Activate virtual environment
source venv/bin/activate

# Pull latest changes
git pull origin main

# Update dependencies
pip install -r requirements.txt --upgrade

# Restart service
sudo systemctl restart sentrikat
```

### Database Migrations

If there are database schema changes:
```bash
source venv/bin/activate
flask db upgrade
```

---

## Uninstallation

### Docker

```bash
cd /path/to/SentriKat
docker-compose down -v  # -v removes volumes
rm -rf /path/to/SentriKat
```

### Linux Manual

```bash
# Stop service
sudo systemctl stop sentrikat
sudo systemctl disable sentrikat

# Remove service file
sudo rm /etc/systemd/system/sentrikat.service
sudo systemctl daemon-reload

# Remove application
sudo rm -rf /opt/sentrikat
```

---

## Troubleshooting

### Application Won't Start

1. Check logs:
   ```bash
   # Docker
   docker-compose logs -f

   # Systemd
   sudo journalctl -u sentrikat -f
   ```

2. Verify environment variables are set
3. Check database file permissions
4. Ensure port 5000 is not in use

### Database Errors

1. Check `DATABASE_URL` is correct
2. Verify database file/server is accessible
3. Check disk space

### LDAP Connection Issues

1. Verify LDAP server is reachable
2. Check bind credentials
3. Test with `ldapsearch` command

### Permission Denied

```bash
# Fix ownership
sudo chown -R sentrikat:sentrikat /opt/sentrikat

# Fix permissions
chmod 750 /opt/sentrikat/data
chmod 640 /opt/sentrikat/.env
```

---

## Next Steps

After installation:

1. Complete the [Setup Wizard](#) in the web interface
2. Configure [LDAP Authentication](CONFIGURATION.md#ldap-configuration)
3. Set up [Email Alerts](CONFIGURATION.md#smtp-configuration)
4. Add your [Products](USER_GUIDE.md#managing-products)
5. Run initial [CISA KEV Sync](USER_GUIDE.md#syncing-vulnerabilities)

See [Configuration Guide](CONFIGURATION.md) for detailed settings.
