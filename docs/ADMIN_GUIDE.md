# SentriKat Administration Guide

This guide covers administration tasks for SentriKat, including user management, organization configuration, system maintenance, and troubleshooting.

---

## Table of Contents

- [Administration Overview](#administration-overview)
- [User Management](#user-management)
- [Organization Management](#organization-management)
- [LDAP Administration](#ldap-administration)
- [Email & Alerts](#email--alerts)
- [System Maintenance](#system-maintenance)
- [Database Administration](#database-administration)
- [Security Administration](#security-administration)
- [Monitoring & Logging](#monitoring--logging)
- [Troubleshooting](#troubleshooting)
- [API Reference](#api-reference)

---

## Administration Overview

### Admin Roles

| Role | Scope | Capabilities |
|------|-------|--------------|
| **Super Admin** | Global | All settings, all organizations, LDAP, global SMTP |
| **Org Admin** | Organization | Users, products, org settings within their org |

### Accessing Administration

1. Log in with admin credentials
2. Click **Administration** in navigation bar
3. Access admin panels:
   - **Users** - User management
   - **Organizations** - Organization management
   - **LDAP Users** - LDAP user discovery
   - **Settings** - System configuration (Super Admin only)

---

## User Management

### Creating Users

**Local User:**
1. Go to **Administration > Users**
2. Click **Add User**
3. Fill in required fields:
   - Username (unique)
   - Email
   - Full Name
   - Password (or generate)
   - Role
   - Organization
4. Click **Create**

**LDAP User:**
1. Go to **Administration > LDAP Users**
2. Search for user in directory
3. Click **Import** next to user
4. Assign role and organization
5. User can now login with LDAP credentials

### User Fields

| Field | Required | Description |
|-------|----------|-------------|
| **Username** | Yes | Unique login identifier |
| **Email** | Yes | Email for notifications |
| **Full Name** | Yes | Display name |
| **Password** | Yes* | Required for local users |
| **Role** | Yes | Permission level |
| **Organization** | Yes | Primary organization |
| **Active** | Yes | Account status |
| **Auth Source** | Auto | `local` or `ldap` |

### Editing Users

1. Click **Edit** on user row
2. Modify fields as needed
3. Click **Save**

**Note:** Cannot change username after creation.

### Password Management

**Reset Password (Local Users):**
1. Edit user
2. Click **Reset Password**
3. Enter new password or generate
4. User receives email notification (if configured)

**LDAP Users:**
- Password managed in Active Directory/LDAP
- Cannot reset password in SentriKat

### Blocking/Unblocking Users

1. Edit user
2. Toggle **Active** status
3. Save changes

Blocked users:
- Cannot login
- Sessions are invalidated
- Receive notification email (if configured)

### Deleting Users

1. Click **Delete** on user row
2. Confirm deletion
3. User data is permanently removed

**Warning:** Deletion is permanent. Consider blocking instead.

### Multi-Organization Assignment

Users can belong to multiple organizations:
1. Edit user
2. Go to **Organizations** tab
3. Add/remove organization memberships
4. Set role per organization
5. Save changes

---

## Organization Management

### Creating Organizations

1. Go to **Administration > Organizations**
2. Click **Add Organization**
3. Fill in fields:
   - Name (unique identifier)
   - Display Name
   - Description
4. Click **Create**

### Organization Settings

| Setting | Description |
|---------|-------------|
| **Name** | Unique URL-safe identifier |
| **Display Name** | Friendly name shown in UI |
| **Description** | Optional notes |
| **Active** | Enable/disable organization |
| **SMTP Settings** | Per-org email configuration |
| **Alert Settings** | Notification preferences |

### SMTP Configuration (Per-Org)

Each organization can have its own SMTP:
1. Edit organization
2. Configure SMTP section:
   - Host, Port
   - Username, Password
   - From Address
   - TLS/SSL settings
3. Test connection
4. Save

**Priority:** Organization SMTP > Global SMTP

### Alert Configuration

Configure when to send email alerts:

| Setting | Description |
|---------|-------------|
| **Critical Alerts** | New critical severity CVEs |
| **High Alerts** | New high severity CVEs |
| **New CVE Alerts** | Any new matching CVEs |
| **Ransomware Alerts** | Ransomware-flagged CVEs |
| **Alert Window** | Time window for alerts (e.g., 08:00-18:00) |
| **Alert Days** | Days to send alerts (Mon-Fri) |
| **Recipients** | Email addresses for alerts |

### Deleting Organizations

1. Click **Delete** on organization
2. Confirm deletion

**Warning:** Deletes all associated:
- Products
- User memberships
- Alert configurations

---

## LDAP Administration

### LDAP Configuration

Navigate to **Administration > Settings > LDAP**

### Required Settings

| Setting | Example |
|---------|---------|
| Server | `ldap://dc01.company.com` |
| Port | `389` |
| Base DN | `DC=company,DC=com` |
| Bind DN | `CN=svc_sentrikat,OU=Service,DC=company,DC=com` |
| Bind Password | (encrypted) |

### Search Configuration

| Setting | Example | Description |
|---------|---------|-------------|
| Search Filter | `(sAMAccountName={username})` | User search query |
| Username Attr | `sAMAccountName` | Login attribute |
| Email Attr | `mail` | Email attribute |
| Full Name Attr | `displayName` | Display name attribute |

### Testing LDAP

1. Configure all settings
2. Click **Test Connection**
3. Verify successful bind
4. Test user search

### LDAP User Discovery

1. Go to **Administration > LDAP Users**
2. Enter search term (username, name, email)
3. Click **Search**
4. View matching LDAP users
5. Click **Import** to create SentriKat user

### LDAP Group Sync

Sync users from LDAP groups:
1. Go to **LDAP Groups**
2. Search for group
3. View group members
4. Import selected users

### Troubleshooting LDAP

**Connection Failed:**
- Verify server hostname/IP
- Check port (389 for LDAP, 636 for LDAPS)
- Test network connectivity
- Verify TLS certificate (if LDAPS)

**Bind Failed:**
- Verify bind DN format
- Check bind password
- Ensure service account has read access

**User Not Found:**
- Check search filter syntax
- Verify base DN is correct
- Ensure user exists in directory

---

## Email & Alerts

### Global SMTP Configuration

Navigate to **Administration > Settings > SMTP**

1. Configure SMTP server settings
2. Set from address and name
3. Test connection
4. Save settings

### Alert Types

| Alert | Trigger | Default |
|-------|---------|---------|
| **Critical CVE** | New critical severity match | Enabled |
| **High CVE** | New high severity match | Disabled |
| **New CVE** | Any new matching CVE | Enabled |
| **Ransomware** | Ransomware-flagged CVE | Enabled |
| **User Welcome** | New user created | Enabled |
| **Account Status** | User blocked/unblocked | Enabled |

### Testing Alerts

1. Configure SMTP
2. Click **Send Test Email**
3. Check inbox for test message
4. Verify formatting and delivery

### Alert Troubleshooting

**Emails Not Sending:**
1. Check SMTP configuration
2. Verify credentials
3. Test connection
4. Check spam/junk folder
5. Review application logs

**Delayed Emails:**
- Check SMTP server queue
- Verify network connectivity
- Check rate limits

---

## System Maintenance

### Backup

**Database Backup (SQLite):**
```bash
# Stop application (optional but recommended)
docker-compose stop

# Copy database file
cp /path/to/data/sentrikat.db /backup/sentrikat_$(date +%Y%m%d).db

# Restart application
docker-compose start
```

**Database Backup (PostgreSQL):**
```bash
pg_dump -h localhost -U sentrikat sentrikat > /backup/sentrikat_$(date +%Y%m%d).sql
```

**Full Backup:**
```bash
# Backup data directory
tar -czvf sentrikat_backup_$(date +%Y%m%d).tar.gz /opt/sentrikat/data

# Backup configuration
cp /opt/sentrikat/.env /backup/.env_$(date +%Y%m%d)
```

### Restore

**SQLite Restore:**
```bash
# Stop application
docker-compose stop

# Restore database
cp /backup/sentrikat_20240101.db /path/to/data/sentrikat.db

# Start application
docker-compose start
```

**PostgreSQL Restore:**
```bash
psql -h localhost -U sentrikat sentrikat < /backup/sentrikat_20240101.sql
```

### Updates

**Docker Update:**
```bash
cd /path/to/SentriKat
git pull origin main
docker-compose down
docker-compose build --no-cache
docker-compose up -d
```

**Manual Update:**
```bash
cd /opt/sentrikat
source venv/bin/activate
git pull origin main
pip install -r requirements.txt --upgrade
sudo systemctl restart sentrikat
```

### Log Rotation

Logs are automatically rotated:
- Location: `logs/sentrikat.log`
- Rotation: Daily
- Retention: 30 days

Manual log cleanup:
```bash
find /opt/sentrikat/logs -name "*.log" -mtime +30 -delete
```

---

## Database Administration

### Database Location

| Type | Default Location |
|------|------------------|
| SQLite | `/opt/sentrikat/data/sentrikat.db` |
| PostgreSQL | Configured via `DATABASE_URL` |

### Database Schema

Key tables:

| Table | Description |
|-------|-------------|
| `users` | User accounts |
| `organizations` | Organizations |
| `products` | Tracked products |
| `vulnerabilities` | CISA KEV data |
| `matches` | Product-vulnerability matches |
| `system_settings` | Configuration settings |
| `sync_logs` | Sync history |
| `audit_logs` | User action logs |

### Database Queries

**View user count:**
```sql
SELECT COUNT(*) FROM users WHERE is_active = 1;
```

**View vulnerability count:**
```sql
SELECT COUNT(*) FROM vulnerabilities;
```

**View unacknowledged matches:**
```sql
SELECT COUNT(*) FROM matches WHERE acknowledged = 0;
```

### Encryption Migration

Encrypt existing plaintext passwords:
```bash
cd /opt/sentrikat
source venv/bin/activate
python encrypt_sensitive_data.py
```

### Database Optimization

**SQLite Vacuum:**
```bash
sqlite3 /opt/sentrikat/data/sentrikat.db "VACUUM;"
```

**PostgreSQL Vacuum:**
```sql
VACUUM ANALYZE;
```

---

## Security Administration

### Access Control

**Password Policy:**
- Minimum 8 characters
- Must contain uppercase, lowercase, number
- No common passwords

**Session Security:**
- 4-hour session timeout
- HttpOnly cookies
- SameSite=Strict
- Secure cookies (HTTPS only)

### Rate Limiting

Default limits:
- Login: 5 attempts per minute
- API: 200 requests per day, 50 per hour

### Encryption

Sensitive data encryption:
- LDAP bind password
- SMTP password
- API keys

All encrypted with Fernet (AES-128-CBC).

### Audit Logging

All actions are logged:
- User logins/logouts
- Product changes
- User management
- Configuration changes

View audit logs:
1. Go to **Administration**
2. Click **Audit Logs**
3. Filter by user, action, date

### Security Checklist

- [ ] Strong `SECRET_KEY` set
- [ ] `ENCRYPTION_KEY` set and migration run
- [ ] HTTPS enabled
- [ ] LDAP over TLS
- [ ] Regular backups
- [ ] Log monitoring
- [ ] Update schedule in place

---

## Monitoring & Logging

### Application Logs

**Location:** `logs/sentrikat.log`

**Log Levels:**
- `ERROR` - Application errors
- `WARNING` - Potential issues
- `INFO` - Normal operations
- `DEBUG` - Detailed debugging (development)

**View Logs:**
```bash
# Docker
docker-compose logs -f

# Systemd
sudo journalctl -u sentrikat -f

# Direct file
tail -f /opt/sentrikat/logs/sentrikat.log
```

### Sync Monitoring

Check sync status:
1. View dashboard "Last Sync" timestamp
2. Go to **Administration > Sync History**
3. Check for errors in logs

### Health Check

**Application Health:**
```bash
curl http://localhost:5000/api/health
```

**Database Health:**
```bash
curl http://localhost:5000/api/status
```

### Performance Monitoring

Monitor via logs:
- Request timing
- Database query performance
- Memory usage

---

## Troubleshooting

### Common Issues

**Application Won't Start**

1. Check logs: `docker-compose logs -f`
2. Verify environment variables
3. Check database connectivity
4. Verify port availability

**Login Issues**

1. Verify user is active
2. Check LDAP configuration (if LDAP user)
3. Reset password (local users)
4. Check rate limiting

**Sync Failures**

1. Check network connectivity
2. Verify CISA URL is accessible
3. Check proxy settings
4. Review sync logs

**Email Not Sending**

1. Verify SMTP configuration
2. Test SMTP connection
3. Check credentials
4. Review email logs

**Performance Issues**

1. Check database size
2. Run database vacuum
3. Increase server resources
4. Consider PostgreSQL migration

### Log Analysis

**Find errors:**
```bash
grep -i error /opt/sentrikat/logs/sentrikat.log
```

**Find login failures:**
```bash
grep -i "login failed" /opt/sentrikat/logs/sentrikat.log
```

**Find sync issues:**
```bash
grep -i "sync" /opt/sentrikat/logs/sentrikat.log
```

### Support Information

When requesting support, provide:
1. Application version
2. Error messages
3. Relevant log excerpts
4. Steps to reproduce
5. Environment details

---

## API Reference

### Authentication

API uses session authentication. Login via web interface or:
```bash
curl -X POST http://localhost:5000/api/auth/login \
  -H "Content-Type: application/json" \
  -d '{"username": "admin", "password": "password"}'
```

### Endpoints

**Products:**
- `GET /api/products` - List products
- `POST /api/products` - Create product
- `PUT /api/products/{id}` - Update product
- `DELETE /api/products/{id}` - Delete product

**Vulnerabilities:**
- `GET /api/vulnerabilities` - List vulnerabilities
- `GET /api/vulnerabilities/{cve_id}` - Get details
- `GET /api/vulnerabilities/stats` - Get statistics

**Matches:**
- `POST /api/matches/{id}/acknowledge` - Acknowledge
- `POST /api/matches/{id}/unacknowledge` - Unacknowledge

**Sync:**
- `POST /api/sync` - Trigger sync
- `GET /api/sync/status` - Get status
- `GET /api/sync/history` - Get history

**Users (Admin):**
- `GET /api/users` - List users
- `POST /api/users` - Create user
- `PUT /api/users/{id}` - Update user
- `DELETE /api/users/{id}` - Delete user

**Organizations (Admin):**
- `GET /api/organizations` - List organizations
- `POST /api/organizations` - Create organization
- `PUT /api/organizations/{id}` - Update organization
- `DELETE /api/organizations/{id}` - Delete organization

### Response Format

```json
{
  "success": true,
  "data": { ... },
  "message": "Operation completed"
}
```

Error response:
```json
{
  "success": false,
  "error": "Error message"
}
```

---

## Quick Reference

### Important Paths

| Path | Description |
|------|-------------|
| `/opt/sentrikat` | Application directory |
| `/opt/sentrikat/data` | Database and data files |
| `/opt/sentrikat/logs` | Application logs |
| `/opt/sentrikat/.env` | Environment configuration |

### Important Commands

```bash
# Start application
docker-compose up -d

# Stop application
docker-compose down

# View logs
docker-compose logs -f

# Restart application
docker-compose restart

# Run sync manually
curl -X POST http://localhost:5000/api/sync

# Database backup
sqlite3 data/sentrikat.db ".backup 'backup.db'"
```

### Default Ports

| Service | Port |
|---------|------|
| Web Application | 5000 |
| LDAP | 389/636 |
| SMTP | 25/465/587 |
| PostgreSQL | 5432 |
