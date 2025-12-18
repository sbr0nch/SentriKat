#!/bin/bash
# Complete fix script to ensure latest GUI is loaded

echo "=========================================="
echo "SentriKat Complete Fix & Restart"
echo "=========================================="
echo ""

# Step 1: Kill all Flask processes
echo "[1/7] Stopping Flask server..."
pkill -f "flask run" 2>/dev/null || true
pkill -f "python.*run.py" 2>/dev/null || true
sleep 2
echo "✓ Server stopped"
echo ""

# Step 2: Clear Python cache
echo "[2/7] Clearing Python cache..."
find . -name "*.pyc" -delete 2>/dev/null
find . -type d -name "__pycache__" -exec rm -rf {} + 2>/dev/null || true
echo "✓ Python cache cleared"
echo ""

# Step 3: Verify we're on correct branch
echo "[3/7] Verifying git branch..."
CURRENT_BRANCH=$(git branch --show-current)
if [ "$CURRENT_BRANCH" != "claude/continue-previous-tasks-nm378" ]; then
    echo "⚠️  WARNING: You're on branch '$CURRENT_BRANCH'"
    echo "   Switching to claude/continue-previous-tasks-nm378..."
    git checkout claude/continue-previous-tasks-nm378
else
    echo "✓ On correct branch: $CURRENT_BRANCH"
fi
echo ""

# Step 4: Pull latest changes
echo "[4/7] Pulling latest changes..."
git pull origin claude/continue-previous-tasks-nm378
echo "✓ Code updated"
echo ""

# Step 5: Check file sizes to verify we have new code
echo "[5/7] Verifying files..."
JS_LINES=$(wc -l < static/js/admin_panel.js)
if [ "$JS_LINES" -gt 2000 ]; then
    echo "✓ admin_panel.js: $JS_LINES lines (correct)"
else
    echo "✗ admin_panel.js: $JS_LINES lines (should be ~2061)"
    echo "   Pulling again..."
    git fetch --all
    git reset --hard origin/claude/continue-previous-tasks-nm378
fi

# Check for LDAP files
if [ -f "app/ldap_api.py" ]; then
    echo "✓ LDAP files present"
else
    echo "✗ LDAP files missing - reinstalling..."
    git fetch --all
    git reset --hard origin/claude/continue-previous-tasks-nm378
fi
echo ""

# Step 6: Fix ENABLE_AUTH default in app/__init__.py
echo "[6/7] Fixing ENABLE_AUTH default..."
if grep -q "ENABLE_AUTH', 'false'" app/__init__.py; then
    echo "   Updating app/__init__.py..."
    sed -i "s/ENABLE_AUTH', 'false'/ENABLE_AUTH', 'true'/g" app/__init__.py
    echo "✓ Fixed ENABLE_AUTH default to 'true'"
else
    echo "✓ ENABLE_AUTH already correct"
fi
echo ""

# Step 7: Display next steps
echo "[7/7] Setup complete!"
echo ""
echo "=========================================="
echo "✓ ALL FIXES APPLIED"
echo "=========================================="
echo ""
echo "Next steps:"
echo "  1. Activate venv: source venv/bin/activate"
echo "  2. Start server: ./start_fresh.sh"
echo "  3. Clear browser cache:"
echo "     - Chrome/Edge: Ctrl+Shift+Delete → Clear cached images/files"
echo "     - Firefox: Ctrl+Shift+Delete → Cached Web Content"
echo "     - Or just hard reload: Ctrl+F5"
echo "  4. Login at: http://cve.cti.bonelabs.com:5001/login"
echo ""
echo "=========================================="
echo ""
