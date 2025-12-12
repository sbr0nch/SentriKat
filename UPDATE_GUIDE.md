# SentriKat Update Guide

## How to Pull Latest Changes

### Quick Update (Recommended)

```bash
# Navigate to your SentriKat directory
cd /opt/sentrikat

# Pull the latest changes from your branch
sudo -u www-data git pull origin claude/retry-task-0164dJBaeL4rFJmP5RBkbodX

# Restart the application
sudo systemctl restart sentrikat

# Check status
sudo systemctl status sentrikat
```

### Update from Main Branch (Future)

When changes are merged to main:

```bash
cd /opt/sentrikat

# Switch to main branch
sudo -u www-data git checkout main

# Pull latest changes
sudo -u www-data git pull origin main

# Restart the application
sudo systemctl restart sentrikat
```

### Force Pull (if conflicts occur)

If you have local changes that conflict:

```bash
cd /opt/sentrikat

# Stash local changes
sudo -u www-data git stash

# Pull latest changes
sudo -u www-data git pull origin claude/retry-task-0164dJBaeL4rFJmP5RBkbodX

# Apply your local changes back (if needed)
sudo -u www-data git stash pop

# Restart
sudo systemctl restart sentrikat
```

### View Change Log

```bash
# See what changed in the last 5 commits
git log --oneline -5

# See detailed changes
git log -5 --stat
```

### Troubleshooting

**Issue: Permission denied**
```bash
# Fix permissions
sudo chown -R www-data:www-data /opt/sentrikat
```

**Issue: Database errors after update**
```bash
# Run any pending migrations
cd /opt/sentrikat
sudo -u www-data python3 migrate_add_criticality.py
sudo -u www-data python3 migrate_add_cvss.py
```

**Issue: Application not restarting**
```bash
# Check logs
sudo journalctl -u sentrikat -n 50

# Force restart
sudo systemctl stop sentrikat
sudo pkill -9 gunicorn
sudo systemctl start sentrikat
```

## After Major Updates

1. **Check for new migrations**: Look for `migrate_*.py` files
2. **Run migrations**: Execute any new migration scripts
3. **Clear browser cache**: Ctrl+F5 to reload CSS/JS
4. **Check logs**: `sudo journalctl -u sentrikat -f`

## Automatic Updates (Optional)

Create a cron job to pull updates daily:

```bash
# Edit crontab for www-data user
sudo crontab -u www-data -e

# Add this line to pull updates at 3 AM daily
0 3 * * * cd /opt/sentrikat && git pull origin claude/retry-task-0164dJBaeL4rFJmP5RBkbodX && systemctl restart sentrikat
```

⚠️ **Warning**: Only enable automatic updates if you trust the source!
