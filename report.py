#!/usr/bin/env python3
"""
SentriKat Vulnerability Verification Report
============================================
Generates a report of all active products with CVEs, their CPE identifiers,
matched CVEs, and severity breakdown - for external verification.

Skips products with 0 active and 0 acknowledged CVEs.
Saves to /tmp/sentrikat-report.txt for easy download.

Usage:
  docker compose exec sentrikat python report.py
  Then download: docker compose cp sentrikat:/tmp/sentrikat-report.txt ./
"""
import sys
import os
sys.path.insert(0, os.path.dirname(__file__))

from run import app
from app import db
from app.models import Product, Vulnerability, VulnerabilityMatch, Organization, product_organizations
from sqlalchemy import func, select
from datetime import datetime

OUTPUT_PATH = '/tmp/sentrikat-report.txt'

def generate_report():
    lines = []

    def out(text=''):
        lines.append(text)

    with app.app_context():
        # Header
        out("=" * 80)
        out("  SENTRIKAT VULNERABILITY VERIFICATION REPORT")
        out(f"  Generated: {datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S')} UTC")
        out("=" * 80)
        out()

        # Overall stats
        total_products = Product.query.filter_by(active=True).count()
        total_vulns = Vulnerability.query.count()
        total_matches = VulnerabilityMatch.query.count()
        unacked = VulnerabilityMatch.query.filter_by(acknowledged=False).count()

        out("SUMMARY")
        out(f"  Active Products:        {total_products}")
        out(f"  Total CVEs in DB:       {total_vulns}")
        out(f"  Total Matches:          {total_matches}")
        out(f"  Unacknowledged Matches: {unacked}")
        out()

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

        out("SEVERITY BREAKDOWN (unacknowledged matches)")
        for level in ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'UNKNOWN']:
            count = severity_map.get(level, 0)
            if count > 0:
                out(f"  {level:<12} {count}")
        if not severity_map:
            out("  (no unacknowledged matches)")
        out()

        # Per-product detail
        products = Product.query.filter_by(active=True).order_by(
            Product.vendor, Product.product_name
        ).all()

        if not products:
            out("NO ACTIVE PRODUCTS FOUND")
            out("=" * 80)
            report_text = '\n'.join(lines)
            with open(OUTPUT_PATH, 'w') as f:
                f.write(report_text)
            print(report_text)
            print(f"\nReport saved to: {OUTPUT_PATH}")
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

        out("-" * 80)
        out("PRODUCTS WITH CVEs (skipping 0-match products)")
        out("-" * 80)
        out()

        products_with_cves = 0
        products_without_cpe = 0
        products_clean = 0

        for p in products:
            cpe_str = f"cpe:2.3:a:{p.cpe_vendor}:{p.cpe_product}" if p.cpe_vendor and p.cpe_product else "NO CPE"
            if not (p.cpe_vendor and p.cpe_product):
                products_without_cpe += 1

            orgs = product_orgs.get(p.id, [])
            org_str = ", ".join(orgs) if orgs else "(none)"

            pmatches = product_matches.get(p.id, [])
            unacked_matches = [m for m in pmatches if not m['acknowledged']]
            acked_matches = [m for m in pmatches if m['acknowledged']]

            # Skip products with no CVEs at all
            if len(unacked_matches) == 0 and len(acked_matches) == 0:
                products_clean += 1
                continue

            if unacked_matches:
                products_with_cves += 1

            # Product header
            out(f"PRODUCT: {p.vendor} / {p.product_name}")
            out(f"  Version:      {p.version or '(any)'}")
            out(f"  CPE:          {cpe_str}")
            out(f"  Organization: {org_str}")
            out(f"  Source:       {p.source or 'manual'}")
            out(f"  CVEs:         {len(unacked_matches)} active, {len(acked_matches)} acknowledged")

            if unacked_matches:
                # Per-severity count for this product
                prod_sev = {}
                for m in unacked_matches:
                    prod_sev[m['severity']] = prod_sev.get(m['severity'], 0) + 1

                sev_parts = []
                for level in ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'UNKNOWN']:
                    if level in prod_sev:
                        sev_parts.append(f"{prod_sev[level]} {level}")
                out(f"  Breakdown:    {', '.join(sev_parts)}")

                # List all CVEs
                out(f"  CVE List:")
                for m in unacked_matches:
                    cvss_str = f"CVSS {m['cvss']:.1f}" if m['cvss'] else "no score"
                    out(f"    - {m['cve_id']} ({m['severity']}, {cvss_str}) [{m['method']}/{m['confidence']}]")

            if acked_matches:
                out(f"  Acknowledged ({len(acked_matches)}):")
                for m in acked_matches[:10]:
                    cvss_str = f"CVSS {m['cvss']:.1f}" if m['cvss'] else "no score"
                    out(f"    ~ {m['cve_id']} ({m['severity']}, {cvss_str})")
                if len(acked_matches) > 10:
                    out(f"    ... and {len(acked_matches) - 10} more acknowledged")

            out()

        # Footer summary
        out("-" * 80)
        out("VERIFICATION SUMMARY")
        out("-" * 80)
        out(f"  Products with active CVEs:   {products_with_cves} / {total_products}")
        out(f"  Products clean (0 CVEs):     {products_clean}")
        out(f"  Products without CPE:        {products_without_cpe} (cannot detect CVEs)")
        out(f"  Total unacknowledged CVEs:   {unacked}")
        out()
        out("HOW TO VERIFY:")
        out("  For each product with a CPE, search NVD:")
        out("  https://nvd.nist.gov/vuln/search/results?cpe_version=cpe:2.3:a:VENDOR:PRODUCT")
        out("  Compare the CVE IDs listed above against NVD results.")
        out("  Note: SentriKat only tracks CISA KEV catalog CVEs, not ALL NVD CVEs.")
        out("=" * 80)

    # Write to file and print
    report_text = '\n'.join(lines)
    with open(OUTPUT_PATH, 'w') as f:
        f.write(report_text)
    print(report_text)
    print(f"\n>>> Report saved to: {OUTPUT_PATH}")
    print(f">>> Download with: docker compose cp sentrikat:{OUTPUT_PATH} ./sentrikat-report.txt")

if __name__ == '__main__':
    generate_report()
