#!/usr/bin/env python3
"""
SentriKat Vulnerability Verification Report (Simple)
=====================================================
Quick report generation. For full tooling use security_report.py instead.

Usage:
  docker compose exec sentrikat python report.py
  docker compose exec sentrikat python security_report.py fix-all  (recommended)
"""
import sys
import os
sys.path.insert(0, os.path.dirname(__file__))

from security_report import generate_report, app

if __name__ == '__main__':
    with app.app_context():
        generate_report()
