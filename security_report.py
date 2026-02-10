#!/usr/bin/env python3
"""
SentriKat Security Report & Data Integrity Tool
=================================================
Comprehensive CLI tool that:
1. Audits and fixes CPE mappings (detects wrong assignments)
2. Bulk-enriches ALL CVEs with CVSS scores from NVD
3. Bulk-fetches CPE version range data for accurate version matching
4. Runs a full rematch with corrected logic
5. Generates a verification report

Usage:
  docker compose exec sentrikat python security_report.py [command]

Commands:
  report     - Generate verification report (default)
  fix-all    - Run all fixes then generate report
  fix-cvss   - Bulk-enrich all CVEs with CVSS scores
  fix-cpe    - Bulk-fetch CPE version data for all CVEs
  fix-match  - Clean up stale matches and rematch
  audit-cpe  - Audit CPE mappings for suspicious assignments
"""
import sys
import os
import time
sys.path.insert(0, os.path.dirname(__file__))

from run import app
from app import db
from app.models import Product, Vulnerability, VulnerabilityMatch, Organization, product_organizations
from sqlalchemy import func
from datetime import datetime

OUTPUT_PATH = '/tmp/sentrikat-report.txt'


def bulk_enrich_cvss(batch_size=50):
    """Enrich ALL CVEs without CVSS scores. Processes in batches to respect NVD rate limits."""
    from app.cisa_sync import enrich_with_cvss_data

    total_without = Vulnerability.query.filter(Vulnerability.cvss_score == None).count()
    if total_without == 0:
        print(f"  All CVEs already have CVSS data.")
        return 0

    print(f"  {total_without} CVEs need CVSS scores. Processing in batches of {batch_size}...")
    total_enriched = 0
    batch_num = 0

    while True:
        remaining = Vulnerability.query.filter(Vulnerability.cvss_score == None).count()
        if remaining == 0:
            break

        batch_num += 1
        print(f"  Batch {batch_num}: {remaining} remaining...")
        enriched = enrich_with_cvss_data(limit=batch_size)
        total_enriched += enriched

        if enriched == 0:
            break  # No more to process

        # Brief pause between batches for NVD rate limits
        if remaining > batch_size:
            time.sleep(2)

    print(f"  Enriched {total_enriched} CVEs with CVSS scores.")
    return total_enriched


def bulk_fetch_cpe_data(batch_size=30):
    """Fetch CPE version range data for ALL CVEs. Processes in batches."""
    from app.cisa_sync import fetch_cpe_version_data

    total_without = Vulnerability.query.filter(Vulnerability.cpe_data == None).count()
    if total_without == 0:
        print(f"  All CVEs already have CPE version data.")
        return 0

    print(f"  {total_without} CVEs need CPE version data. Processing in batches of {batch_size}...")
    total_enriched = 0
    batch_num = 0

    while True:
        remaining = Vulnerability.query.filter(Vulnerability.cpe_data == None).count()
        if remaining == 0:
            break

        batch_num += 1
        print(f"  Batch {batch_num}: {remaining} remaining...")
        enriched = fetch_cpe_version_data(limit=batch_size)
        total_enriched += enriched

        if enriched == 0:
            break

        if remaining > batch_size:
            time.sleep(2)

    print(f"  Fetched CPE data for {total_enriched} CVEs.")
    return total_enriched


def fix_rematch():
    """Run full rematch: clean up stale matches and create new ones."""
    from app.filters import rematch_all_products
    print("  Running full rematch...")
    removed, added = rematch_all_products()
    print(f"  Removed {removed} stale matches, added {added} new matches.")
    return removed, added


def audit_cpe_mappings():
    """Audit CPE mappings for suspicious assignments."""
    print("\n" + "=" * 70)
    print("CPE AUDIT REPORT")
    print("=" * 70)

    products = Product.query.filter_by(active=True).all()

    issues = []

    for p in products:
        cpe_v, cpe_p, _ = p.get_effective_cpe()
        if not cpe_v or not cpe_p:
            continue

        # Check 1: _skip products that somehow still have matches
        if cpe_v == '_skip':
            match_count = VulnerabilityMatch.query.filter_by(
                product_id=p.id, acknowledged=False
            ).count()
            if match_count > 0:
                issues.append({
                    'type': 'SKIP_WITH_MATCHES',
                    'product': f"{p.vendor} / {p.product_name}",
                    'cpe': f"{cpe_v}:{cpe_p}",
                    'detail': f"{match_count} active matches (should be 0)"
                })
            continue

        # Check 2: CPE vendor doesn't match product vendor (possible wrong mapping)
        vendor_lower = p.vendor.lower().replace(' ', '').replace('-', '').replace('_', '')
        cpe_vendor_lower = cpe_v.lower().replace(' ', '').replace('-', '').replace('_', '')

        # Allow common vendor name variations
        vendor_aliases = {
            'microsoft': ['microsoft'],
            'google': ['google'],
            'mozilla': ['mozilla'],
            'oracle': ['oracle', 'java', 'openjdk', 'mysql', 'virtualbox'],
            'adobe': ['adobe'],
            'apache': ['apache'],
            'git': ['git'],
            'nodejs': ['nodejs', 'node'],
            'python': ['python'],
            'videolan': ['videolan', 'vlc'],
            'logitech': ['logitech'],
            '7zip': ['7zip', '7-zip'],
        }

        # Check if CPE vendor is plausibly related to product vendor
        is_plausible = False
        if vendor_lower in cpe_vendor_lower or cpe_vendor_lower in vendor_lower:
            is_plausible = True
        else:
            # Check known aliases
            for alias_group in vendor_aliases.values():
                if any(a in vendor_lower for a in alias_group) and any(a in cpe_vendor_lower for a in alias_group):
                    is_plausible = True
                    break

        if not is_plausible:
            issues.append({
                'type': 'VENDOR_MISMATCH',
                'product': f"{p.vendor} / {p.product_name}",
                'cpe': f"{cpe_v}:{cpe_p}",
                'detail': f"Product vendor '{p.vendor}' doesn't match CPE vendor '{cpe_v}'"
            })

        # Check 3: Product with excessive matches (possible too-broad CPE)
        match_count = VulnerabilityMatch.query.filter_by(
            product_id=p.id, acknowledged=False
        ).count()
        if match_count > 50:
            issues.append({
                'type': 'EXCESSIVE_MATCHES',
                'product': f"{p.vendor} / {p.product_name} (v{p.version or 'any'})",
                'cpe': f"{cpe_v}:{cpe_p}",
                'detail': f"{match_count} active matches (suspiciously high)"
            })

    if issues:
        for issue in sorted(issues, key=lambda x: x['type']):
            print(f"\n  [{issue['type']}]")
            print(f"    Product: {issue['product']}")
            print(f"    CPE:     {issue['cpe']}")
            print(f"    Issue:   {issue['detail']}")
        print(f"\n  Total issues found: {len(issues)}")
    else:
        print("\n  No CPE mapping issues detected.")

    return issues


def generate_report():
    """Generate comprehensive verification report."""
    lines = []

    def out(text=''):
        lines.append(text)

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

    # Data quality stats
    cvss_populated = Vulnerability.query.filter(
        Vulnerability.cvss_score != None,
        Vulnerability.cvss_score > 0
    ).count()
    cvss_missing = Vulnerability.query.filter(Vulnerability.cvss_score == None).count()
    cpe_data_populated = Vulnerability.query.filter(
        Vulnerability.cpe_data != None,
        Vulnerability.cpe_data != '[]'
    ).count()
    cpe_data_missing = Vulnerability.query.filter(Vulnerability.cpe_data == None).count()

    # Products with _skip CPE
    skip_products = Product.query.filter(
        Product.cpe_vendor == '_skip',
        Product.active == True
    ).count()

    # Products with real CPE
    real_cpe_products = Product.query.filter(
        Product.cpe_vendor != None,
        Product.cpe_vendor != '',
        Product.cpe_vendor != '_skip',
        Product.cpe_product != None,
        Product.cpe_product != '',
        Product.active == True
    ).count()

    # Products without CPE
    no_cpe_products = Product.query.filter(
        db.or_(
            Product.cpe_vendor == None,
            Product.cpe_vendor == ''
        ),
        Product.active == True
    ).count()

    out("SUMMARY")
    out(f"  Active Products:        {total_products}")
    out(f"    With real CPE:        {real_cpe_products}")
    out(f"    Skipped (noise):      {skip_products}")
    out(f"    Without CPE:          {no_cpe_products}")
    out(f"  Total CVEs in DB:       {total_vulns}")
    out(f"  Total Matches:          {total_matches}")
    out(f"  Unacknowledged Matches: {unacked}")
    out()

    out("DATA QUALITY")
    out(f"  CVEs with CVSS scores:  {cvss_populated} / {total_vulns} ({cvss_populated*100//max(total_vulns,1)}%)")
    out(f"  CVEs missing CVSS:      {cvss_missing}")
    out(f"  CVEs with CPE data:     {cpe_data_populated} / {total_vulns} ({cpe_data_populated*100//max(total_vulns,1)}%)")
    out(f"  CVEs missing CPE data:  {cpe_data_missing}")
    out()

    # Match method breakdown
    method_counts = db.session.query(
        VulnerabilityMatch.match_method,
        VulnerabilityMatch.match_confidence,
        func.count(VulnerabilityMatch.id)
    ).filter(
        VulnerabilityMatch.acknowledged == False
    ).group_by(
        VulnerabilityMatch.match_method,
        VulnerabilityMatch.match_confidence
    ).all()

    out("MATCH METHOD BREAKDOWN (unacknowledged)")
    for method, confidence, cnt in sorted(method_counts, key=lambda x: -x[2]):
        out(f"  {method or 'unknown'}/{confidence or 'unknown'}: {cnt}")
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
    out("PRODUCTS WITH CVEs (skipping 0-match and noise products)")
    out("-" * 80)
    out()

    products_with_cves = 0
    products_without_cpe = 0
    products_clean = 0
    products_skipped = 0

    for p in products:
        # Skip noise products
        if p.cpe_vendor == '_skip':
            products_skipped += 1
            continue

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
        out(f"  Match Type:   {p.match_type or 'auto'}")
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
    out(f"  Products skipped (noise):    {products_skipped}")
    out(f"  Products without CPE:        {products_without_cpe} (keyword-only matching)")
    out(f"  Total unacknowledged CVEs:   {unacked}")
    out()
    out("DATA QUALITY SCORES")
    cvss_pct = cvss_populated * 100 // max(total_vulns, 1)
    cpe_pct = cpe_data_populated * 100 // max(total_vulns, 1)
    out(f"  CVSS Coverage:  {cvss_pct}% ({cvss_populated}/{total_vulns})")
    out(f"  CPE Coverage:   {cpe_pct}% ({cpe_data_populated}/{total_vulns})")

    if cvss_missing > 0 or cpe_data_missing > 0:
        out()
        out("RECOMMENDATIONS")
        if cvss_missing > 0:
            out(f"  - Run 'python security_report.py fix-cvss' to fetch {cvss_missing} missing CVSS scores")
        if cpe_data_missing > 0:
            out(f"  - Run 'python security_report.py fix-cpe' to fetch {cpe_data_missing} missing CPE version ranges")
        if cvss_missing > 0 or cpe_data_missing > 0:
            out(f"  - Run 'python security_report.py fix-all' to fix everything in one go")

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


def fix_all():
    """Run all fixes in the correct order, then generate report."""
    print("=" * 70)
    print("SENTRIKAT SECURITY DATA FIX - FULL PIPELINE")
    print("=" * 70)

    print("\nStep 1/4: Fetching CVSS scores for all CVEs...")
    bulk_enrich_cvss(batch_size=50)

    print("\nStep 2/4: Fetching CPE version range data for all CVEs...")
    bulk_fetch_cpe_data(batch_size=30)

    print("\nStep 3/4: Running full rematch with corrected logic...")
    fix_rematch()

    print("\nStep 4/4: Generating verification report...")
    generate_report()

    print("\n" + "=" * 70)
    print("ALL FIXES COMPLETE")
    print("=" * 70)


def main():
    command = sys.argv[1] if len(sys.argv) > 1 else 'report'

    with app.app_context():
        if command == 'report':
            generate_report()
        elif command == 'fix-all':
            fix_all()
        elif command == 'fix-cvss':
            print("Bulk-enriching CVSS scores...")
            bulk_enrich_cvss(batch_size=50)
            print("Done. Run 'python security_report.py report' to see results.")
        elif command == 'fix-cpe':
            print("Bulk-fetching CPE version data...")
            bulk_fetch_cpe_data(batch_size=30)
            print("Done. Run 'python security_report.py fix-match' to rematch with new data.")
        elif command == 'fix-match':
            fix_rematch()
            print("Done. Run 'python security_report.py report' to see results.")
        elif command == 'audit-cpe':
            audit_cpe_mappings()
        else:
            print(__doc__)
            sys.exit(1)


if __name__ == '__main__':
    main()
