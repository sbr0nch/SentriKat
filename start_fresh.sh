#!/bin/bash
# SentriKat Fresh Start Script
# This script helps you start fresh with a clean database

echo "SentriKat Fresh Start"
echo "===================="
echo ""

# Check if running from correct directory
if [ ! -f "run.py" ]; then
    echo "❌ Error: Please run this script from the SentriKat root directory"
    exit 1
fi

# Activate virtual environment
if [ -d "venv" ]; then
    echo "✓ Activating virtual environment..."
    source venv/bin/activate
else
    echo "❌ Error: Virtual environment not found. Please create it first:"
    echo "   python3 -m venv venv"
    echo "   source venv/bin/activate"
    echo "   pip install -r requirements.txt"
    exit 1
fi

# Kill any running Flask processes
echo "✓ Killing any running Flask processes..."
pkill -f "flask run" 2>/dev/null || true
pkill -f "python.*run.py" 2>/dev/null || true
sleep 2

# Prompt for database reset
echo ""
read -p "Delete existing database and start fresh? (y/N): " response
if [[ "$response" =~ ^[Yy]$ ]]; then
    echo "✓ Removing old database..."
    rm -rf instance/sentrikat.db
    echo "✓ Database removed"
else
    echo "✓ Keeping existing database"
fi

echo ""
echo "✓ Starting Flask on port 5001..."
echo ""
echo "========================================"
echo "  Access SentriKat at:"
echo "  http://localhost:5001"
echo "  http://$(hostname -I | awk '{print $1}'):5001"
echo "========================================"
echo ""
echo "Press Ctrl+C to stop the server"
echo ""

# Start Flask
flask run --host=0.0.0.0 --port=5001
