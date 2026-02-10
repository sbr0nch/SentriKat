#!/usr/bin/env python3
"""
SentriKat Vulnerability Verification Report
============================================
Generates a report of all active products, their CPE identifiers,
matched CVEs, and severity breakdown - for external verification.

Usage:
  docker compose exec sentrikat python report.py
"""
import sys
import os
sys.path.insert(0, os.path.dirname(__file__))

from run import app
from app import db
from app.models import Product, Vulnerability, VulnerabilityMatch, Organization, product_organizations
from sqlalchemy import func, select
from datetime import datetime

def generate_report():
    with app.app_context():
        # Header
        print("=" * 80)
        print("  SENTRIKAT VULNERABILITY VERIFICATION REPORT")
        print(f"  Generated: {datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S')} UTC")
        print("=" * 80)
        print()

        # Overall stats
        total_products = Product.query.filter_by(active=True).count()
        total_vulns = Vulnerability.query.count()
        total_matches = VulnerabilityMatch.query.count()
        unacked = VulnerabilityMatch.query.filter_by(acknowledged=False).count()

        print(f"SUMMARY")
        print(f"  Active Products:        {total_products}")
        print(f"  Total CVEs in DB:       {total_vulns}")
        print(f"  Total Matches:          {total_matches}")
        print(f"  Unacknowledged Matches: {unacked}")
        print()

        # Severity breakdown of all matched CVEs
        severity_counts = db.session.query(
            Vulnerability.severity,
            func.count(func.distinct(VulnerabilityMatch.vulnerability_id))
        ).join(
            VulnerabilityMatch, VulnerabilityMatch.vulnerability_id == Vulnerability.id
        ).filter(
            VulnerabilityMatch.acknowledged == False
        ).group_by(Vulnerability.severity).all()

        severity_map = {}
        for sev, cnt in severity_counts:
            severity_map[sev or 'UNKNOWN'] = cnt

        print(f"SEVERITY BREAKDOWN (unacknowledged matches)")
        for level in ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'UNKNOWN']:
            count = severity_map.get(level, 0)
            if count > 0:
                print(f"  {level:<12} {count}")
        if not severity_map:
            print("  (no unacknowledged matches)")
        print()

        # Per-product detail
        products = Product.query.filter_by(active=True).order_by(
            Product.vendor, Product.product_name
        ).all()

        if not products:
            print("NO ACTIVE PRODUCTS FOUND")
            print("=" * 80)
            return

        # Batch-query all matches with vulnerability data
        product_ids = [p.id for p in products]
        matches = db.session.query(
            VulnerabilityMatch.product_id,
            Vulnerability.cve_id,
            Vulnerability.severity,
            Vulnerability.cvss_score,
            VulnerabilityMatch.acknowledged,
            VulnerabilityMatch.match_method,
            VulnerabilityMatch.match_confidence
        ).join(
            Vulnerability, VulnerabilityMatch.vulnerability_id == Vulnerability.id
        ).filter(
            VulnerabilityMatch.product_id.in_(product_ids)
        ).order_by(
            VulnerabilityMatch.product_id,
            Vulnerability.cvss_score.desc().nullslast()
        ).all()

        # Group matches by product_id
        product_matches = {}
        for pid, cve_id, severity, cvss, acked, method, confidence in matches:
            product_matches.setdefault(pid, []).append({
                'cve_id': cve_id,
                'severity': severity or 'UNKNOWN',
                'cvss': cvss,
                'acknowledged': acked,
                'method': method,
                'confidence': confidence
            })

        # Batch-query org names
        org_rows = db.session.query(
            product_organizations.c.product_id,
            Organization.display_name
        ).join(
            Organization, product_organizations.c.organization_id == Organization.id
        ).filter(
            product_organizations.c.product_id.in_(product_ids)
        ).all()
        product_orgs = {}
        for pid, name in org_rows:
            product_orgs.setdefault(pid, []).append(name)

        print("-" * 80)
        print("PRODUCT DETAILS")
        print("-" * 80)
        print()

        products_with_cves = 0
        products_without_cpe = 0

        for p in products:
            cpe_str = f"cpe:2.3:a:{p.cpe_vendor}:{p.cpe_product}" if p.cpe_vendor and p.cpe_product else "NO CPE"
            if not (p.cpe_vendor and p.cpe_product):
                products_without_cpe += 1

            orgs = product_orgs.get(p.id, [])
            org_str = ", ".join(orgs) if orgs else "(none)"

            pmatches = product_matches.get(p.id, [])
            unacked_matches = [m for m in pmatches if not m['acknowledged']]
            acked_matches = [m for m in pmatches if m['acknowledged']]

            if unacked_matches:
                products_with_cves += 1

            # Product header
            print(f"PRODUCT: {p.vendor} / {p.product_name}")
            print(f"  Version:      {p.version or '(any)'}")
            print(f"  CPE:          {cpe_str}")
            print(f"  Organization: {org_str}")
            print(f"  Source:       {p.source or 'manual'}")
            print(f"  CVEs:         {len(unacked_matches)} active, {len(acked_matches)} acknowledged")

            if unacked_matches:
                # Per-severity count for this product
                prod_sev = {}
                for m in unacked_matches:
                    prod_sev[m['severity']] = prod_sev.get(m['severity'], 0) + 1

                sev_parts = []
                for level in ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'UNKNOWN']:
                    if level in prod_sev:
                        sev_parts.append(f"{prod_sev[level]} {level}")
                print(f"  Breakdown:    {', '.join(sev_parts)}")

                # List CVEs (max 20 per product for readability)
                print(f"  CVE List:")
                for i, m in enumerate(unacked_matches[:20]):
                    cvss_str = f"CVSS {m['cvss']:.1f}" if m['cvss'] else "no score"
                    print(f"    - {m['cve_id']} ({m['severity']}, {cvss_str}) [{m['method']}/{m['confidence']}]")
                if len(unacked_matches) > 20:
                    print(f"    ... and {len(unacked_matches) - 20} more")

            print()

        # Footer summary
        print("-" * 80)
        print("VERIFICATION SUMMARY")
        print("-" * 80)
        print(f"  Products with active CVEs:   {products_with_cves} / {total_products}")
        print(f"  Products without CPE:        {products_without_cpe} (cannot detect CVEs)")
        print(f"  Total unacknowledged CVEs:   {unacked}")
        print()
        print("HOW TO VERIFY:")
        print("  For each product with a CPE, search NVD:")
        print("  https://nvd.nist.gov/vuln/search/results?cpe_version=cpe:2.3:a:VENDOR:PRODUCT")
        print("  Compare the CVE IDs listed above against NVD results.")
        print("  Note: SentriKat only tracks CISA KEV catalog CVEs, not ALL NVD CVEs.")
        print("=" * 80)

if __name__ == '__main__':
    generate_report()
