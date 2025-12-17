#!/bin/bash
# Fix file permissions for SentriKat
# This ensures the web server can read static files and templates

echo "SentriKat Permission Fix"
echo "========================"
echo ""

# Get the directory where this script is located
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

echo "✓ Setting permissions for static files..."
chmod -R 755 static/
chmod 644 static/**/*

echo "✓ Setting permissions for app folder..."
chmod -R 755 app/
find app/ -type f -name "*.py" -exec chmod 644 {} \;
find app/ -type f -name "*.html" -exec chmod 644 {} \;

echo "✓ Setting permissions for templates..."
chmod 755 app/templates/
chmod 644 app/templates/*.html

echo "✓ Setting correct permissions for Python files..."
chmod 644 *.py
chmod 755 run.py
chmod 755 *.sh

echo ""
echo "✓ All permissions fixed!"
echo ""
echo "Now restart your Flask server:"
echo "  pkill -f 'flask run'"
echo "  ./start_fresh.sh"
echo ""
