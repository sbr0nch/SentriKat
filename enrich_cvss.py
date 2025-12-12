#!/usr/bin/env python3
"""
Standalone script to enrich existing vulnerabilities with CVSS scores from NVD API
"""
import sys
from app import create_app
from app.cisa_sync import enrich_with_cvss_data

def main():
    app = create_app()
    with app.app_context():
        print("=" * 60)
        print("SentriKat - CVSS Data Enrichment Tool")
        print("=" * 60)
        print()
        print("This script fetches CVSS scores and severity ratings from")
        print("the National Vulnerability Database (NVD) for all CVEs")
        print("in your database.")
        print()
        print("Note: NVD API has rate limits (5 requests per 30 seconds)")
        print("This script processes 50 CVEs at a time to respect limits.")
        print()

        # Check how many CVEs need enrichment
        from app.models import Vulnerability
        total_vulns = Vulnerability.query.count()
        missing_cvss = Vulnerability.query.filter(Vulnerability.cvss_score == None).count()

        print(f"Total vulnerabilities: {total_vulns}")
        print(f"Missing CVSS data: {missing_cvss}")
        print()

        if missing_cvss == 0:
            print("✓ All vulnerabilities already have CVSS data!")
            return

        response = input(f"Fetch CVSS data for {min(50, missing_cvss)} CVEs? (y/n): ")
        if response.lower() != 'y':
            print("Cancelled.")
            return

        print()
        print("Fetching CVSS data from NVD API...")
        print("-" * 60)

        enriched = enrich_with_cvss_data(limit=50)

        print("-" * 60)
        print()
        print(f"✓ Enriched {enriched} vulnerabilities with CVSS data")
        print()

        remaining = Vulnerability.query.filter(Vulnerability.cvss_score == None).count()
        if remaining > 0:
            print(f"ℹ  {remaining} CVEs still need CVSS data")
            print(f"   Run this script again to process more")
            print()
            print(f"   Or run: python3 enrich_cvss.py")
        else:
            print("✓ All CVEs now have CVSS data!")

if __name__ == '__main__':
    try:
        main()
    except KeyboardInterrupt:
        print("\n\nInterrupted by user")
        sys.exit(1)
    except Exception as e:
        print(f"\n✗ Error: {str(e)}")
        sys.exit(1)
