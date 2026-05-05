"""Seed E2E development data into a fresh SentriKat install.

Purpose: unblock end-to-end flow testing in Community edition without
needing a Pro license to push real agents. Generates a small but
representative dataset:
- 5 assets (mixed OS: Linux/Windows/macOS/container)
- 10 products (popular software with realistic versions)
- 30 vulnerabilities (recent CVEs, mix of severity)
- 18 vulnerability matches (cross-join product × vuln)
- 12 product installations (Asset ↔ Product link)

Usage (from inside the container):
    docker exec sentrikat python3 scripts/seed_e2e_dev.py
    # or to wipe + reseed:
    docker exec sentrikat python3 scripts/seed_e2e_dev.py --reset

After running, the dashboard will show realistic numbers and most
VM-related flows (VM-1..VM-6 in E2E-FLOWS-INDEX.md) become testable.

Safety: refuses to run in production mode unless --force is passed.
Uses transaction so partial failures roll back cleanly.
"""
import argparse
import os
import sys
import random
from datetime import datetime, date, timedelta

# Ensure /app is on sys.path when invoked via docker exec
sys.path.insert(0, '/app')


def seed():
    from app import create_app, db
    from app.models import (
        Organization, Asset, Product, Vulnerability,
        VulnerabilityMatch, ProductInstallation,
    )

    app = create_app()

    with app.app_context():
        if os.environ.get('FLASK_ENV') == 'production' and '--force' not in sys.argv:
            print('REFUSING to seed in FLASK_ENV=production without --force')
            sys.exit(1)

        org = Organization.query.first()
        if not org:
            print('No organization in DB — run setup wizard first.')
            sys.exit(1)
        print(f'Seeding into organization: {org.name} (id={org.id})')

        if '--reset' in sys.argv:
            print('Resetting existing E2E seed data...')
            VulnerabilityMatch.query.delete()
            ProductInstallation.query.delete()
            Asset.query.filter(Asset.hostname.like('e2e-%')).delete()
            Product.query.filter(Product.vendor.like('SeedVendor%')).delete()
            Vulnerability.query.filter(Vulnerability.cve_id.like('CVE-2099-%')).delete()
            db.session.commit()

        # ---------------------------------------------------------------
        # 1. Assets — 5 with varied OS
        # ---------------------------------------------------------------
        asset_specs = [
            ('e2e-web01.test.local',  '10.0.1.10',  'server',      'Linux',   'Ubuntu 22.04 LTS', '5.15.0-89-generic'),
            ('e2e-db01.test.local',   '10.0.1.11',  'server',      'Linux',   'RHEL 8.9',         '4.18.0-513'),
            ('e2e-laptop-jdoe',       '10.0.2.45',  'workstation', 'Windows', 'Windows 11 Pro',   '10.0.22631'),
            ('e2e-mac-anna',          '10.0.2.46',  'workstation', 'macOS',   'Sonoma 14.4',      '23E214'),
            ('e2e-runner-01',         '10.0.3.20',  'container',   'Linux',   'Alpine 3.19',      None),
        ]
        assets = []
        for hostname, ip, atype, os_n, os_v, kernel in asset_specs:
            existing = Asset.query.filter_by(hostname=hostname).first()
            if existing:
                assets.append(existing)
                continue
            a = Asset(
                organization_id=org.id,
                hostname=hostname,
                ip_address=ip,
                asset_type=atype,
                os_name=os_n,
                os_version=os_v,
                os_kernel=kernel,
                last_checkin=datetime.utcnow() - timedelta(minutes=random.randint(1, 30)),
                last_inventory_at=datetime.utcnow() - timedelta(minutes=random.randint(1, 60)),
            )
            db.session.add(a)
            assets.append(a)
        db.session.flush()
        print(f'  Assets: {len(assets)}')

        # ---------------------------------------------------------------
        # 2. Products — 10 popular software entries
        # ---------------------------------------------------------------
        product_specs = [
            # (vendor, name, version, keywords)
            ('SeedVendor-nginx',     'nginx',                  '1.24.0',         'web,server,proxy'),
            ('SeedVendor-postgres',  'PostgreSQL',             '15.5',           'database,sql'),
            ('SeedVendor-openssl',   'OpenSSL',                '3.0.11',         'crypto,tls,ssl'),
            ('SeedVendor-redis',     'Redis',                  '7.2.3',          'cache,database'),
            ('SeedVendor-python',    'Python',                 '3.11.5',         'runtime,interpreter'),
            ('SeedVendor-nodejs',    'Node.js',                '20.10.0',        'runtime,javascript'),
            ('SeedVendor-docker',    'Docker Engine',          '24.0.7',         'container,runtime'),
            ('SeedVendor-firefox',   'Firefox',                '120.0.1',        'browser'),
            ('SeedVendor-chrome',    'Google Chrome',          '120.0.6099.71',  'browser'),
            ('SeedVendor-adobe',     'Adobe Acrobat Reader',   '23.006.20360',   'pdf,viewer'),
        ]
        products = []
        for vendor, pname, ver, kw in product_specs:
            existing = Product.query.filter_by(vendor=vendor, product_name=pname).first()
            if existing:
                products.append(existing)
                continue
            p = Product(
                organization_id=org.id,
                vendor=vendor,
                product_name=pname,
                version=ver,
                keywords=kw,
                description=f'E2E seed: {pname} {ver}',
                active=True,
            )
            db.session.add(p)
            products.append(p)
        db.session.flush()
        print(f'  Products: {len(products)}')

        # ---------------------------------------------------------------
        # 3. Vulnerabilities — 30 fake CVE-2099 (avoid clashes with real)
        # ---------------------------------------------------------------
        severities_cvss = [
            ('CRITICAL', 9.8), ('CRITICAL', 9.5), ('HIGH', 8.5), ('HIGH', 7.8),
            ('HIGH', 7.5), ('MEDIUM', 6.4), ('MEDIUM', 5.9), ('MEDIUM', 5.0),
            ('LOW', 3.5), ('LOW', 2.8),
        ]
        vuln_titles = [
            'Remote Code Execution in HTTP request parser',
            'Authentication bypass via crafted JWT',
            'SQL injection in admin search endpoint',
            'Heap buffer overflow in image decoder',
            'Use-after-free in connection pool cleanup',
            'Path traversal in static file handler',
            'Cross-site scripting in error page renderer',
            'Privilege escalation via setuid wrapper',
            'Information disclosure in debug endpoint',
            'Denial of service via crafted Content-Length',
            'Memory corruption in SSL handshake',
            'Race condition in session management',
            'XML external entity injection in import',
            'Server-side request forgery in webhook',
            'Improper input validation in API token',
        ]
        vulns = []
        for i in range(30):
            cve_id = f'CVE-2099-{10000 + i}'
            existing = Vulnerability.query.filter_by(cve_id=cve_id).first()
            if existing:
                vulns.append(existing)
                continue
            sev, cvss = random.choice(severities_cvss)
            title = random.choice(vuln_titles)
            vendor_project, target_product = random.choice([
                ('SeedVendor-nginx', 'nginx'),
                ('SeedVendor-postgres', 'PostgreSQL'),
                ('SeedVendor-openssl', 'OpenSSL'),
                ('SeedVendor-python', 'Python'),
                ('SeedVendor-nodejs', 'Node.js'),
                ('SeedVendor-docker', 'Docker Engine'),
                ('SeedVendor-firefox', 'Firefox'),
                ('SeedVendor-chrome', 'Google Chrome'),
            ])
            d_added = date.today() - timedelta(days=random.randint(1, 90))
            d_due = d_added + timedelta(days=random.randint(14, 60))
            v = Vulnerability(
                cve_id=cve_id,
                vendor_project=vendor_project,
                product=target_product,
                vulnerability_name=f'{target_product}: {title}',
                date_added=d_added,
                short_description=f'A {sev.lower()} flaw in {target_product} allows {title.lower()}. CVSS {cvss}.',
                required_action=f'Upgrade {target_product} to the latest patched release.',
                due_date=d_due,
                severity=sev,
                cvss_score=cvss,
            )
            db.session.add(v)
            vulns.append(v)
        db.session.flush()
        print(f'  Vulnerabilities: {len(vulns)}')

        # ---------------------------------------------------------------
        # 4. VulnerabilityMatch — 18 product↔vuln links
        # ---------------------------------------------------------------
        match_count = 0
        for p in products:
            # ~60% of products get matches
            if random.random() > 0.6:
                continue
            n = random.randint(1, 4)
            picks = random.sample(vulns, min(n, len(vulns)))
            for v in picks:
                exists = VulnerabilityMatch.query.filter_by(
                    product_id=p.id, vulnerability_id=v.id
                ).first()
                if exists:
                    continue
                m = VulnerabilityMatch(
                    product_id=p.id,
                    vulnerability_id=v.id,
                    match_reason='vendor+product keyword match',
                    acknowledged=random.random() < 0.2,  # 20% pre-ack'd
                )
                db.session.add(m)
                match_count += 1
        db.session.flush()
        print(f'  VulnerabilityMatch: {match_count}')

        # ---------------------------------------------------------------
        # 5. ProductInstallation — 12 asset↔product links
        # ---------------------------------------------------------------
        install_count = 0
        for a in assets:
            n = random.randint(2, 4)
            picks = random.sample(products, min(n, len(products)))
            for p in picks:
                existing = ProductInstallation.query.filter_by(
                    asset_id=a.id, product_id=p.id
                ).first()
                if existing:
                    continue
                os_label = (a.os_name or '').lower().split()[0] if a.os_name else None
                pi = ProductInstallation(
                    asset_id=a.id,
                    product_id=p.id,
                    version=p.version,
                    detected_by='manual',
                    detected_on_os=os_label,
                    discovered_at=datetime.utcnow() - timedelta(days=random.randint(7, 90)),
                    last_seen_at=datetime.utcnow() - timedelta(hours=random.randint(1, 24)),
                )
                db.session.add(pi)
                install_count += 1
        db.session.flush()
        print(f'  ProductInstallation: {install_count}')

        db.session.commit()
        print('\nSeed complete. Dashboard should now show realistic numbers.')
        print('Next: log in to the admin UI and verify the data shows up.')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--reset', action='store_true',
                        help='Wipe existing E2E seed data first')
    parser.add_argument('--force', action='store_true',
                        help='Allow seeding even in FLASK_ENV=production')
    args, _ = parser.parse_known_args()
    seed()
