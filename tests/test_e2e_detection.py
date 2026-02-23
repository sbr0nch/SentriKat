"""
End-to-end detection integration tests.

These tests verify the COMPLETE detection pipeline: product ingestion → vulnerability
sync → match creation → priority calculation → alert readiness.

Unlike unit tests that use mocks, these tests use real database records and exercise
the actual matching logic to prove SentriKat's core value proposition works.
"""
import pytest
from datetime import date, datetime, timedelta
from unittest.mock import patch


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_product(db_session, test_org, vendor, product_name, version,
                  cpe_vendor=None, cpe_product=None, ecosystem=None):
    """Create a Product with CPE configuration."""
    from app.models import Product

    product = Product(
        vendor=vendor,
        product_name=product_name,
        version=version,
        cpe_vendor=cpe_vendor or vendor.lower(),
        cpe_product=cpe_product or product_name.lower().replace(' ', '_'),
        match_type='auto',
        active=True,
        criticality='high',
        organization_id=test_org.id,
        ecosystem=ecosystem,
    )
    db_session.add(product)
    db_session.flush()
    return product


def _make_vulnerability(db_session, cve_id, vendor, product, severity='HIGH',
                        cvss_score=8.5, cpe_entries=None,
                        is_actively_exploited=False, known_ransomware=False,
                        due_date=None, epss_score=None, source='cisa_kev'):
    """Create a Vulnerability with optional CPE data."""
    from app.models import Vulnerability

    vuln = Vulnerability(
        cve_id=cve_id,
        vendor_project=vendor,
        product=product,
        vulnerability_name=f'Test vulnerability {cve_id}',
        date_added=date.today(),
        short_description=f'Test CVE {cve_id}',
        required_action='Update to latest version',
        cvss_score=cvss_score,
        severity=severity,
        is_actively_exploited=is_actively_exploited,
        known_ransomware=known_ransomware,
        due_date=due_date,
        epss_score=epss_score,
        source=source,
    )
    db_session.add(vuln)
    db_session.flush()

    if cpe_entries:
        vuln.set_cpe_entries(cpe_entries)
        vuln.cpe_fetched_at = datetime.utcnow()
        db_session.flush()

    return vuln


# ===========================================================================
# PART 1 — Full pipeline tests (Product → CVE → Match → Alert readiness)
# ===========================================================================

class TestEndToEndDetectionPipeline:
    """Verify the full detection chain: product + vuln → match → priority."""

    def test_product_matched_against_cve_with_version_range(
        self, app, db_session, test_org
    ):
        """Apache Tomcat 10.1.18 in range [10.0.0, 10.1.25) → MATCH."""
        from app.filters import match_vulnerabilities_to_products
        from app.models import VulnerabilityMatch

        product = _make_product(db_session, test_org,
                                'Apache', 'Tomcat', '10.1.18',
                                cpe_vendor='apache', cpe_product='tomcat')

        vuln = _make_vulnerability(db_session, 'CVE-2024-50379', 'Apache', 'Tomcat',
                                   severity='HIGH', cvss_score=8.1,
                                   cpe_entries=[{
                                       'vendor': 'apache', 'product': 'tomcat',
                                       'version_start': '10.0.0', 'version_end': '10.1.25',
                                       'version_start_type': 'including',
                                       'version_end_type': 'excluding',
                                   }])
        db_session.commit()

        count = match_vulnerabilities_to_products()
        assert count >= 1

        match = VulnerabilityMatch.query.filter_by(
            product_id=product.id, vulnerability_id=vuln.id
        ).first()
        assert match is not None, "Match should exist"
        assert match.match_method == 'cpe'
        assert match.match_confidence == 'high'

    def test_patched_version_not_matched(self, app, db_session, test_org):
        """Apache Tomcat 10.1.25 (patched) is OUTSIDE [10.0.0, 10.1.25) → NO MATCH."""
        from app.filters import match_vulnerabilities_to_products
        from app.models import VulnerabilityMatch

        product = _make_product(db_session, test_org,
                                'Apache', 'Tomcat', '10.1.25',
                                cpe_vendor='apache', cpe_product='tomcat')

        _make_vulnerability(db_session, 'CVE-2024-50379', 'Apache', 'Tomcat',
                            cpe_entries=[{
                                'vendor': 'apache', 'product': 'tomcat',
                                'version_start': '10.0.0', 'version_end': '10.1.25',
                                'version_start_type': 'including',
                                'version_end_type': 'excluding',
                            }])
        db_session.commit()

        count = match_vulnerabilities_to_products()
        assert count == 0, "Patched version should NOT produce a match"

        match = VulnerabilityMatch.query.filter_by(product_id=product.id).first()
        assert match is None

    def test_match_creates_correct_priority(self, app, db_session, test_org):
        """HIGH severity + actively exploited → CRITICAL priority."""
        from app.filters import match_vulnerabilities_to_products
        from app.models import VulnerabilityMatch

        product = _make_product(db_session, test_org,
                                'Apache', 'Log4j', '2.14.1',
                                cpe_vendor='apache', cpe_product='log4j')

        vuln = _make_vulnerability(
            db_session, 'CVE-2021-44228', 'Apache', 'Log4j',
            severity='CRITICAL', cvss_score=10.0,
            is_actively_exploited=True,
            cpe_entries=[{
                'vendor': 'apache', 'product': 'log4j',
                'version_start': '2.0.0', 'version_end': '2.15.0',
                'version_start_type': 'including',
                'version_end_type': 'excluding',
            }],
        )
        db_session.commit()

        match_vulnerabilities_to_products()

        match = VulnerabilityMatch.query.filter_by(
            product_id=product.id, vulnerability_id=vuln.id
        ).first()
        assert match is not None
        priority = match.calculate_effective_priority()
        assert priority == 'critical'

    def test_multiple_products_against_same_cve(self, app, db_session, test_org):
        """Two affected products → two separate matches for the same CVE."""
        from app.filters import match_vulnerabilities_to_products
        from app.models import VulnerabilityMatch

        prod1 = _make_product(db_session, test_org,
                              'Apache', 'Tomcat', '10.1.18',
                              cpe_vendor='apache', cpe_product='tomcat')
        prod2 = _make_product(db_session, test_org,
                              'Apache', 'Tomcat', '9.0.80',
                              cpe_vendor='apache', cpe_product='tomcat')

        _make_vulnerability(db_session, 'CVE-2024-99999', 'Apache', 'Tomcat',
                            cpe_entries=[{
                                'vendor': 'apache', 'product': 'tomcat',
                                'version_start': '9.0.0', 'version_end': '11.0.0',
                                'version_start_type': 'including',
                                'version_end_type': 'excluding',
                            }])
        db_session.commit()

        count = match_vulnerabilities_to_products()
        assert count == 2

        m1 = VulnerabilityMatch.query.filter_by(product_id=prod1.id).first()
        m2 = VulnerabilityMatch.query.filter_by(product_id=prod2.id).first()
        assert m1 is not None
        assert m2 is not None


# ===========================================================================
# PART 2 — Ransomware & Actively Exploited alert escalation
# ===========================================================================

class TestRansomwareAndExploitedAlerts:
    """Verify ransomware + actively exploited flags drive priority correctly."""

    def test_ransomware_always_critical(self, app, db_session, test_org):
        """known_ransomware=True → priority always 'critical', regardless of CVSS."""
        product = _make_product(db_session, test_org,
                                'Accellion', 'FTA', '9.12.370',
                                cpe_vendor='accellion', cpe_product='fta')

        vuln = _make_vulnerability(
            db_session, 'CVE-2021-27101', 'Accellion', 'FTA',
            severity='LOW', cvss_score=3.5,
            known_ransomware=True,
            cpe_entries=[{
                'vendor': 'accellion', 'product': 'fta',
                'version_start': None, 'version_end': None,
            }],
        )
        db_session.commit()

        assert vuln.calculate_priority() == 'critical', \
            "Ransomware CVE must always be CRITICAL regardless of CVSS severity"

    def test_actively_exploited_elevates_by_one(self, app, db_session, test_org):
        """is_actively_exploited=True elevates MEDIUM→HIGH."""
        vuln = _make_vulnerability(
            db_session, 'CVE-2024-11111', 'Vendor', 'Product',
            severity='MEDIUM', cvss_score=5.5,
            is_actively_exploited=True,
        )
        db_session.commit()

        assert vuln.calculate_priority() == 'high', \
            "Actively exploited MEDIUM should be elevated to HIGH"

    def test_actively_exploited_high_becomes_critical(self, app, db_session, test_org):
        """is_actively_exploited=True elevates HIGH→CRITICAL."""
        vuln = _make_vulnerability(
            db_session, 'CVE-2024-22222', 'Vendor', 'Product',
            severity='HIGH', cvss_score=7.5,
            is_actively_exploited=True,
        )
        db_session.commit()

        assert vuln.calculate_priority() == 'critical'

    def test_epss_high_elevates_priority(self, app, db_session, test_org):
        """EPSS >= 0.5 elevates MEDIUM→HIGH."""
        vuln = _make_vulnerability(
            db_session, 'CVE-2024-33333', 'Vendor', 'Product',
            severity='MEDIUM', cvss_score=6.0,
            epss_score=0.85,
        )
        db_session.commit()

        assert vuln.calculate_priority() == 'high', \
            "High EPSS (0.85) should elevate MEDIUM to HIGH"

    def test_epss_below_threshold_no_elevation(self, app, db_session, test_org):
        """EPSS < 0.5 does NOT elevate."""
        vuln = _make_vulnerability(
            db_session, 'CVE-2024-44444', 'Vendor', 'Product',
            severity='MEDIUM', cvss_score=6.0,
            epss_score=0.3,
        )
        db_session.commit()

        assert vuln.calculate_priority() == 'medium', \
            "Low EPSS (0.3) should NOT elevate priority"

    def test_epss_plus_exploited_double_elevation(self, app, db_session, test_org):
        """EPSS >= 0.5 AND actively exploited → LOW can reach HIGH (two elevations)."""
        vuln = _make_vulnerability(
            db_session, 'CVE-2024-55555', 'Vendor', 'Product',
            severity='LOW', cvss_score=3.0,
            epss_score=0.7,
            is_actively_exploited=True,
        )
        db_session.commit()

        # LOW (1) + EPSS elevation (+1) + exploited elevation (+1) = HIGH (3)
        assert vuln.calculate_priority() == 'high', \
            "LOW + high EPSS + actively exploited should reach HIGH"

    def test_due_date_urgency_escalation(self, app, db_session, test_org):
        """Due date within 7 days → CRITICAL regardless of base severity."""
        vuln = _make_vulnerability(
            db_session, 'CVE-2024-66666', 'Vendor', 'Product',
            severity='MEDIUM', cvss_score=5.0,
            due_date=date.today() + timedelta(days=3),
        )
        db_session.commit()

        assert vuln.calculate_priority() == 'critical', \
            "Due in 3 days should escalate to CRITICAL"


# ===========================================================================
# PART 3 — Version range boundary tests with real-ish NVD data
# ===========================================================================

class TestVersionRangeBoundaries:
    """Test CPE version range matching at boundary conditions."""

    def _match(self, db_session, test_org, version, cpe_entries):
        """Helper: create product + vuln and check if they match."""
        from app.filters import check_cpe_match

        product = _make_product(db_session, test_org,
                                'TestVendor', 'TestProduct', version,
                                cpe_vendor='testvendor', cpe_product='testproduct')

        vuln = _make_vulnerability(db_session, f'CVE-2024-{abs(hash(version)) % 99999:05d}',
                                   'TestVendor', 'TestProduct',
                                   cpe_entries=cpe_entries)
        db_session.commit()

        match_reasons, method, confidence = check_cpe_match(vuln, product)
        return len(match_reasons) > 0

    def test_inclusive_start_boundary(self, app, db_session, test_org):
        """Version == start (including) → MATCH."""
        cpe = [{'vendor': 'testvendor', 'product': 'testproduct',
                'version_start': '2.0.0', 'version_end': '3.0.0',
                'version_start_type': 'including', 'version_end_type': 'excluding'}]
        assert self._match(db_session, test_org, '2.0.0', cpe) is True

    def test_exclusive_end_boundary(self, app, db_session, test_org):
        """Version == end (excluding) → NO MATCH."""
        cpe = [{'vendor': 'testvendor', 'product': 'testproduct',
                'version_start': '2.0.0', 'version_end': '3.0.0',
                'version_start_type': 'including', 'version_end_type': 'excluding'}]
        assert self._match(db_session, test_org, '3.0.0', cpe) is False

    def test_just_below_end(self, app, db_session, test_org):
        """Version just below end → MATCH."""
        cpe = [{'vendor': 'testvendor', 'product': 'testproduct',
                'version_start': '2.0.0', 'version_end': '3.0.0',
                'version_start_type': 'including', 'version_end_type': 'excluding'}]
        assert self._match(db_session, test_org, '2.99.99', cpe) is True

    def test_just_above_start_excluding(self, app, db_session, test_org):
        """Version just above start (excluding) → MATCH."""
        cpe = [{'vendor': 'testvendor', 'product': 'testproduct',
                'version_start': '2.0.0', 'version_end': '3.0.0',
                'version_start_type': 'excluding', 'version_end_type': 'excluding'}]
        assert self._match(db_session, test_org, '2.0.1', cpe) is True

    def test_at_start_excluding(self, app, db_session, test_org):
        """Version == start (excluding) → NO MATCH."""
        cpe = [{'vendor': 'testvendor', 'product': 'testproduct',
                'version_start': '2.0.0', 'version_end': '3.0.0',
                'version_start_type': 'excluding', 'version_end_type': 'excluding'}]
        assert self._match(db_session, test_org, '2.0.0', cpe) is False

    def test_well_below_range(self, app, db_session, test_org):
        """Version well below range → NO MATCH."""
        cpe = [{'vendor': 'testvendor', 'product': 'testproduct',
                'version_start': '10.0.0', 'version_end': '11.0.0',
                'version_start_type': 'including', 'version_end_type': 'excluding'}]
        assert self._match(db_session, test_org, '9.0.0', cpe) is False

    def test_well_above_range(self, app, db_session, test_org):
        """Version well above range → NO MATCH."""
        cpe = [{'vendor': 'testvendor', 'product': 'testproduct',
                'version_start': '10.0.0', 'version_end': '11.0.0',
                'version_start_type': 'including', 'version_end_type': 'excluding'}]
        assert self._match(db_session, test_org, '12.0.0', cpe) is False

    def test_open_ended_range_start_only(self, app, db_session, test_org):
        """Only start bound, no end → all versions >= start match."""
        cpe = [{'vendor': 'testvendor', 'product': 'testproduct',
                'version_start': '5.0.0', 'version_end': None,
                'version_start_type': 'including', 'version_end_type': None}]
        assert self._match(db_session, test_org, '999.0.0', cpe) is True
        assert self._match(db_session, test_org, '4.9.9', cpe) is False

    def test_open_ended_range_end_only(self, app, db_session, test_org):
        """Only end bound, no start → all versions < end match."""
        cpe = [{'vendor': 'testvendor', 'product': 'testproduct',
                'version_start': None, 'version_end': '5.0.0',
                'version_start_type': None, 'version_end_type': 'excluding'}]
        assert self._match(db_session, test_org, '4.9.9', cpe) is True
        assert self._match(db_session, test_org, '5.0.0', cpe) is False


# ===========================================================================
# PART 4 — Distro-native version comparison in CPE matching
# ===========================================================================

class TestDistroNativeVersionMatching:
    """Verify that dpkg/rpm/apk versions are compared correctly in CPE matching."""

    def test_debian_version_in_range(self, app, db_session, test_org):
        """Debian version 2.4.52-1ubuntu4.3 in dpkg range → MATCH."""
        from app.filters import check_cpe_match

        product = _make_product(db_session, test_org,
                                'Apache', 'HTTP Server', '2.4.52-1ubuntu4.3',
                                cpe_vendor='apache', cpe_product='http_server',
                                ecosystem='ubuntu')

        vuln = _make_vulnerability(
            db_session, 'CVE-2024-DEB01', 'Apache', 'HTTP Server',
            cpe_entries=[{
                'vendor': 'apache', 'product': 'http_server',
                'version_start': '2.4.0', 'version_end': '2.4.52-1ubuntu4.6',
                'version_start_type': 'including', 'version_end_type': 'excluding',
            }],
        )
        db_session.commit()

        match_reasons, method, confidence = check_cpe_match(vuln, product)
        assert len(match_reasons) > 0, \
            "Debian version 2.4.52-1ubuntu4.3 should be in range for dpkg comparison"

    def test_debian_version_patched_out_of_range(self, app, db_session, test_org):
        """Debian version 2.4.52-1ubuntu4.6 at end (excluding) → NO MATCH."""
        from app.filters import check_cpe_match

        product = _make_product(db_session, test_org,
                                'Apache', 'HTTP Server', '2.4.52-1ubuntu4.6',
                                cpe_vendor='apache', cpe_product='http_server',
                                ecosystem='ubuntu')

        vuln = _make_vulnerability(
            db_session, 'CVE-2024-DEB02', 'Apache', 'HTTP Server',
            cpe_entries=[{
                'vendor': 'apache', 'product': 'http_server',
                'version_start': '2.4.0', 'version_end': '2.4.52-1ubuntu4.6',
                'version_start_type': 'including', 'version_end_type': 'excluding',
            }],
        )
        db_session.commit()

        match_reasons, _, _ = check_cpe_match(vuln, product)
        assert len(match_reasons) == 0, \
            "Patched Debian version at range boundary should NOT match"

    def test_rpm_version_comparison(self, app, db_session, test_org):
        """RPM version 2.4.37-47.el8 in range → MATCH."""
        from app.filters import check_cpe_match

        product = _make_product(db_session, test_org,
                                'Apache', 'HTTP Server', '2.4.37-47.el8',
                                cpe_vendor='apache', cpe_product='http_server',
                                ecosystem='rhel')

        vuln = _make_vulnerability(
            db_session, 'CVE-2024-RPM01', 'Apache', 'HTTP Server',
            cpe_entries=[{
                'vendor': 'apache', 'product': 'http_server',
                'version_start': '2.4.0', 'version_end': '2.4.37-50.el8',
                'version_start_type': 'including', 'version_end_type': 'excluding',
            }],
        )
        db_session.commit()

        match_reasons, method, confidence = check_cpe_match(vuln, product)
        assert len(match_reasons) > 0, \
            "RPM version 2.4.37-47.el8 should match in rpm range"


# ===========================================================================
# PART 5 — Confidence decay (cleanup updates confidence)
# ===========================================================================

class TestConfidenceDecay:
    """Verify that cleanup_invalid_matches() upgrades match confidence."""

    def test_confidence_upgraded_on_recheck(self, app, db_session, test_org):
        """A medium-confidence match should upgrade to high when CPE data arrives."""
        from app.filters import cleanup_invalid_matches
        from app.models import VulnerabilityMatch

        product = _make_product(db_session, test_org,
                                'Apache', 'Tomcat', '10.1.18',
                                cpe_vendor='apache', cpe_product='tomcat')

        vuln = _make_vulnerability(db_session, 'CVE-2024-CONF1', 'Apache', 'Tomcat',
                                   cpe_entries=[{
                                       'vendor': 'apache', 'product': 'tomcat',
                                       'version_start': '10.0.0', 'version_end': '10.1.25',
                                       'version_start_type': 'including',
                                       'version_end_type': 'excluding',
                                   }])

        # Manually create a match with medium confidence (as if NVD was pending earlier)
        match = VulnerabilityMatch(
            product_id=product.id,
            vulnerability_id=vuln.id,
            match_method='cpe',
            match_confidence='medium',
            match_reason='CPE inference: apache:tomcat (NVD analysis pending)',
        )
        db_session.add(match)
        db_session.commit()

        # Now cleanup should re-evaluate and upgrade confidence to high
        cleanup_invalid_matches()

        match = VulnerabilityMatch.query.filter_by(
            product_id=product.id, vulnerability_id=vuln.id
        ).first()
        assert match is not None, "Match should still exist"
        assert match.match_confidence == 'high', \
            "Match confidence should be upgraded from medium to high"


# ===========================================================================
# PART 6 — UNIQUE constraint enforcement
# ===========================================================================

class TestUniqueConstraint:
    """Verify that duplicate matches are prevented at the DB level."""

    def test_duplicate_match_prevented(self, app, db_session, test_org):
        """Inserting a duplicate (product_id, vulnerability_id) raises IntegrityError."""
        from app.models import VulnerabilityMatch
        from sqlalchemy.exc import IntegrityError

        product = _make_product(db_session, test_org,
                                'Apache', 'Tomcat', '10.1.18',
                                cpe_vendor='apache', cpe_product='tomcat')
        vuln = _make_vulnerability(db_session, 'CVE-2024-UNIQ1', 'Apache', 'Tomcat')

        m1 = VulnerabilityMatch(
            product_id=product.id, vulnerability_id=vuln.id,
            match_method='cpe', match_confidence='high',
            match_reason='First match',
        )
        db_session.add(m1)
        db_session.commit()

        m2 = VulnerabilityMatch(
            product_id=product.id, vulnerability_id=vuln.id,
            match_method='keyword', match_confidence='low',
            match_reason='Duplicate match',
        )
        db_session.add(m2)

        with pytest.raises(IntegrityError):
            db_session.commit()
        db_session.rollback()
