#!/bin/bash
# SentriKat Diagnostic Script
# Run this to check if everything is in the right place

echo "=========================="
echo "SentriKat Diagnostic Check"
echo "=========================="
echo ""

# Get the directory where this script is located
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
echo "✓ Running from: $SCRIPT_DIR"
echo ""

# Check critical files
echo "Checking critical files..."
echo ""

FILES=(
    "static/js/admin_panel.js"
    "app/templates/admin_panel.html"
    "app/routes.py"
    "app/auth.py"
    "run.py"
    "config.py"
)

ALL_GOOD=true

for file in "${FILES[@]}"; do
    FILEPATH="$SCRIPT_DIR/$file"
    if [ -f "$FILEPATH" ]; then
        SIZE=$(ls -lh "$FILEPATH" | awk '{print $5}')
        PERMS=$(ls -l "$FILEPATH" | awk '{print $1}')
        echo "✓ $file ($SIZE) - $PERMS"
    else
        echo "✗ MISSING: $file"
        ALL_GOOD=false
    fi
done

echo ""
echo "Checking directories..."
if [ -d "$SCRIPT_DIR/static/js" ]; then
    echo "✓ static/js directory exists"
    ls -lh "$SCRIPT_DIR/static/js/" | tail -n +2
else
    echo "✗ static/js directory MISSING!"
    ALL_GOOD=false
fi

echo ""
echo "Checking git status..."
cd "$SCRIPT_DIR"
BRANCH=$(git branch --show-current 2>/dev/null || echo "Not a git repo")
echo "  Branch: $BRANCH"

BEHIND=$(git rev-list HEAD..origin/$BRANCH --count 2>/dev/null || echo "Unknown")
if [ "$BEHIND" != "Unknown" ] && [ "$BEHIND" -gt 0 ]; then
    echo "  ⚠ WARNING: You are $BEHIND commits behind origin!"
    echo "  Run: git pull origin $BRANCH"
fi

echo ""
if [ "$ALL_GOOD" = true ]; then
    echo "✓ All checks passed!"
    echo ""
    echo "Next steps:"
    echo "  1. Make sure you pulled latest code: git pull"
    echo "  2. Fix permissions: ./fix_permissions.sh"
    echo "  3. Restart server: ./start_fresh.sh"
else
    echo "✗ Some checks failed!"
    echo ""
    echo "Fix by running:"
    echo "  git pull origin claude/retry-task-0164dJBaeL4rFJmP5RBkbodX"
fi
