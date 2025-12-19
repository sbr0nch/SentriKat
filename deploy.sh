#!/bin/bash
# SentriKat Production Deployment Script
# Use this to deploy code updates to production with Gunicorn

echo "🚀 SentriKat Deployment"
echo "======================"
echo ""

# Check if running from correct directory
if [ ! -f "run.py" ]; then
    echo "❌ Error: Please run this script from the SentriKat root directory"
    exit 1
fi

# Pull latest code
echo "📥 Pulling latest code from git..."
git fetch origin
git pull origin $(git branch --show-current)

if [ $? -ne 0 ]; then
    echo "❌ Git pull failed"
    exit 1
fi

echo "✓ Code updated"
echo ""

# Check if running with systemctl
if systemctl is-active --quiet sentrikat 2>/dev/null; then
    echo "🔄 Restarting systemctl service..."
    sudo systemctl restart sentrikat

    if [ $? -eq 0 ]; then
        echo "✓ Service restarted successfully"
        sudo systemctl status sentrikat --no-pager -l
    else
        echo "❌ Failed to restart service"
        exit 1
    fi
else
    echo "ℹ️  systemctl service not running"
    echo ""
    echo "If you're using ./start_fresh.sh, stop it (Ctrl+C) and restart it"
    echo "If you want to use systemctl instead:"
    echo "  sudo systemctl start sentrikat"
fi

echo ""
echo "✅ Deployment complete!"
echo ""
echo "⚠️  Don't forget to hard refresh your browser: Ctrl+Shift+R"
