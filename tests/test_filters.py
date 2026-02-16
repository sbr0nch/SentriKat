"""
Tests for the vulnerability matching filters module.
"""
import pytest
from unittest.mock import MagicMock, patch


class TestNormalizeString:
    """Tests for string normalization."""

    def test_normalize_basic(self):
        from app.filters import normalize_string
        assert normalize_string('Apache') == 'apache'
        assert normalize_string('  Apache  ') == 'apache'
        assert normalize_string('APACHE TOMCAT') == 'apache tomcat'

    def test_normalize_empty(self):
        from app.filters import normalize_string
        assert normalize_string('') == ''
        assert normalize_string(None) == ''


class TestKeywordMatch:
    """Tests for keyword matching logic."""

    def setup_method(self):
        """Set up mock product and vulnerability."""
        self.product = MagicMock()
        self.product.vendor = 'Apache'
        self.product.product_name = 'Tomcat'
        self.product.keywords = ''
        self.product.match_type = 'keyword'

        self.vulnerability = MagicMock()
        self.vulnerability.vendor_project = 'Apache'
        self.vulnerability.product = 'Tomcat'

    def test_vendor_product_match(self):
        """Test matching when both vendor and product match."""
        from app.filters import check_keyword_match

        match_reasons, method, confidence = check_keyword_match(self.vulnerability, self.product)
        assert len(match_reasons) > 0
        assert 'Vendor+Product match' in match_reasons[0]
        assert method == 'vendor_product'
        assert confidence == 'medium'

    def test_partial_product_match(self):
        """Test matching with partial product names."""
        from app.filters import check_keyword_match

        self.vulnerability.product = 'Apache Tomcat Server'
        match_reasons, _, _ = check_keyword_match(self.vulnerability, self.product)
        assert len(match_reasons) > 0

    def test_no_match(self):
        """Test when there's no match."""
        from app.filters import check_keyword_match

        self.vulnerability.vendor_project = 'Microsoft'
        self.vulnerability.product = 'Windows'
        match_reasons, method, confidence = check_keyword_match(self.vulnerability, self.product)
        assert len(match_reasons) == 0
        assert method is None

    def test_keyword_match(self):
        """Test keyword-based matching."""
        from app.filters import check_keyword_match

        self.product.keywords = 'servlet, jakarta'
        self.vulnerability.product = 'Apache Tomcat servlet container'

        match_reasons, method, confidence = check_keyword_match(self.vulnerability, self.product)
        # Should match on vendor+product and keyword
        assert any('servlet' in r.lower() for r in match_reasons)

    def test_keyword_word_boundary(self):
        """Test that keywords match whole words only."""
        from app.filters import check_keyword_match

        self.product.vendor = ''
        self.product.product_name = ''
        self.product.keywords = 'http'
        self.vulnerability.vendor_project = ''
        self.vulnerability.product = 'nhttpd'  # Should NOT match 'http'

        match_reasons, _, _ = check_keyword_match(self.vulnerability, self.product)
        # 'http' should not match 'nhttpd' due to word boundary
        keyword_matches = [r for r in match_reasons if 'Keyword' in r]
        assert len(keyword_matches) == 0

    def test_vendor_product_no_false_positive_long_name(self):
        """Test that generic product names don't false-match longer product names.

        'Microsoft Windows Desktop Targeting Pack' is NOT 'Microsoft Windows'.
        The word 'Windows' in a much longer product name should not match the
        vulnerability product 'Windows'.
        """
        from app.filters import check_keyword_match

        self.product.vendor = 'Microsoft'
        self.product.product_name = 'Microsoft Windows Desktop Targeting Pack - 9.0.13 (x64)'
        self.product.keywords = ''
        self.vulnerability.vendor_project = 'Microsoft'
        self.vulnerability.product = 'Windows'

        match_reasons, _, _ = check_keyword_match(self.vulnerability, self.product)
        assert len(match_reasons) == 0, (
            "Windows Desktop Targeting Pack should NOT match Windows OS CVEs"
        )

    def test_vendor_product_matches_with_vendor_prefix(self):
        """Test that vendor prefix in product name doesn't prevent matching.

        'Mozilla Firefox' should still match vulnerability product 'Firefox'.
        """
        from app.filters import check_keyword_match

        self.product.vendor = 'Mozilla'
        self.product.product_name = 'Mozilla Firefox'
        self.product.keywords = ''
        self.vulnerability.vendor_project = 'Mozilla'
        self.vulnerability.product = 'Firefox'

        match_reasons, method, _ = check_keyword_match(self.vulnerability, self.product)
        assert len(match_reasons) > 0, "Mozilla Firefox should match Firefox CVEs"
        assert method == 'vendor_product'


class TestCPEMatch:
    """Tests for CPE-based matching."""

    def setup_method(self):
        """Set up mock product and vulnerability."""
        self.product = MagicMock()
        self.product.vendor = 'Apache'
        self.product.product_name = 'Tomcat'
        self.product.version = '10.1.18'
        self.product.cpe_vendor = 'apache'
        self.product.cpe_product = 'tomcat'
        self.product.cpe_uri = None
        self.product.match_type = 'cpe'
        self.product.get_effective_cpe = MagicMock(return_value=('apache', 'tomcat', None))

        self.vulnerability = MagicMock()
        self.vulnerability.vendor_project = 'Apache'
        self.vulnerability.product = 'Tomcat'
        self.vulnerability.get_cpe_entries = MagicMock(return_value=[])

    def test_cpe_inference_match(self):
        """Test CPE matching via inference for versionless products (no cached CPE data)."""
        from app.filters import check_cpe_match

        # Inference only works for versionless products (versioned products
        # require NVD CPE data for safe matching — prevents false positives)
        self.product.version = None
        self.vulnerability.cpe_fetched_at = None

        match_reasons, method, confidence = check_cpe_match(self.vulnerability, self.product)
        assert len(match_reasons) > 0
        assert method == 'cpe'
        assert 'CPE inference' in match_reasons[0]

    def test_cpe_inference_skips_versioned_product(self):
        """Test that versioned products do NOT match via inference (prevents false positives)."""
        from app.filters import check_cpe_match

        # Product has version 10.1.18 but vulnerability has no CPE data
        # from NVD — we can't verify the version is actually affected, so skip.
        self.vulnerability.cpe_fetched_at = None

        match_reasons, method, confidence = check_cpe_match(self.vulnerability, self.product)
        assert len(match_reasons) == 0, "Versioned product should not match via inference"

    def test_cpe_cached_match(self):
        """Test CPE matching with cached CPE data."""
        from app.filters import check_cpe_match

        self.vulnerability.get_cpe_entries = MagicMock(return_value=[
            {
                'vendor': 'apache',
                'product': 'tomcat',
                'version_start': None,
                'version_end': None
            }
        ])

        match_reasons, method, confidence = check_cpe_match(self.vulnerability, self.product)
        assert len(match_reasons) > 0
        assert method == 'cpe'
        assert confidence == 'high'
        assert 'CPE match' in match_reasons[0]

    def test_cpe_version_range_match(self):
        """Test CPE matching with version range."""
        from app.filters import check_cpe_match

        self.vulnerability.get_cpe_entries = MagicMock(return_value=[
            {
                'vendor': 'apache',
                'product': 'tomcat',
                'version_start': '10.0.0',
                'version_end': '11.0.0',
                'version_start_type': 'including',
                'version_end_type': 'excluding'
            }
        ])

        match_reasons, method, confidence = check_cpe_match(self.vulnerability, self.product)
        assert len(match_reasons) > 0
        assert 'in range' in match_reasons[0]

    def test_cpe_no_match_wrong_vendor(self):
        """Test CPE not matching with wrong vendor."""
        from app.filters import check_cpe_match

        self.vulnerability.vendor_project = 'Microsoft'
        self.vulnerability.product = 'IIS'
        self.vulnerability.get_cpe_entries = MagicMock(return_value=[
            {'vendor': 'microsoft', 'product': 'iis'}
        ])

        match_reasons, _, _ = check_cpe_match(self.vulnerability, self.product)
        assert len(match_reasons) == 0

    def test_cpe_no_cpe_configured(self):
        """Test when product has no CPE configured."""
        from app.filters import check_cpe_match

        self.product.get_effective_cpe = MagicMock(return_value=(None, None, None))

        match_reasons, _, _ = check_cpe_match(self.vulnerability, self.product)
        assert len(match_reasons) == 0


class TestCheckMatch:
    """Tests for the main check_match function."""

    def setup_method(self):
        """Set up mock product and vulnerability."""
        self.product = MagicMock()
        self.product.vendor = 'Apache'
        self.product.product_name = 'Tomcat'
        self.product.version = '10.1.18'
        self.product.keywords = ''
        self.product.cpe_vendor = 'apache'
        self.product.cpe_product = 'tomcat'
        self.product.match_type = 'auto'
        self.product.get_effective_cpe = MagicMock(return_value=('apache', 'tomcat', None))

        self.vulnerability = MagicMock()
        self.vulnerability.vendor_project = 'Apache'
        self.vulnerability.product = 'Tomcat'
        self.vulnerability.get_cpe_entries = MagicMock(return_value=[])

    def test_auto_mode_prefers_cpe(self):
        """Test auto mode prefers CPE when available."""
        from app.filters import check_match

        # Provide CPE data so the proper CPE path is used
        self.vulnerability.get_cpe_entries = MagicMock(return_value=[
            {'vendor': 'apache', 'product': 'tomcat',
             'version_start': '10.0.0', 'version_end': '11.0.0',
             'version_start_type': 'including', 'version_end_type': 'excluding'}
        ])

        match_reasons, method, confidence = check_match(self.vulnerability, self.product)
        assert method == 'cpe'

    def test_auto_mode_fallback_to_keyword(self):
        """Test auto mode falls back to keyword when CPE not available."""
        from app.filters import check_match

        self.product.get_effective_cpe = MagicMock(return_value=(None, None, None))
        self.vulnerability.vendor_project = 'Microsoft'
        self.vulnerability.product = 'Windows'

        # No CPE and no keyword match
        match_reasons, method, confidence = check_match(self.vulnerability, self.product)
        assert len(match_reasons) == 0

    def test_cpe_only_mode(self):
        """Test CPE-only mode ignores keyword matches."""
        from app.filters import check_match

        self.product.match_type = 'cpe'
        self.product.get_effective_cpe = MagicMock(return_value=(None, None, None))

        match_reasons, _, _ = check_match(self.vulnerability, self.product)
        # Should be empty since no CPE
        assert len(match_reasons) == 0

    def test_keyword_only_mode(self):
        """Test keyword-only mode ignores CPE."""
        from app.filters import check_match

        self.product.match_type = 'keyword'

        match_reasons, method, _ = check_match(self.vulnerability, self.product)
        # Should match via keyword (vendor+product)
        assert len(match_reasons) > 0
        assert method == 'vendor_product'

    def test_both_mode(self):
        """Test both mode uses CPE if available."""
        from app.filters import check_match

        self.product.match_type = 'both'
        # Provide CPE data so the proper CPE path is used
        self.vulnerability.get_cpe_entries = MagicMock(return_value=[
            {'vendor': 'apache', 'product': 'tomcat',
             'version_start': '10.0.0', 'version_end': '11.0.0',
             'version_start_type': 'including', 'version_end_type': 'excluding'}
        ])

        match_reasons, method, _ = check_match(self.vulnerability, self.product)
        # Should prefer CPE
        assert method == 'cpe'


class TestVersionRange:
    """Tests for version range checking."""

    def test_version_in_range_including_both(self):
        from app.filters import _version_in_range

        # Version 1.5.0 should be in [1.0.0, 2.0.0]
        assert _version_in_range('1.5.0', '1.0.0', '2.0.0', 'including', 'including')
        # Boundaries included
        assert _version_in_range('1.0.0', '1.0.0', '2.0.0', 'including', 'including')
        assert _version_in_range('2.0.0', '1.0.0', '2.0.0', 'including', 'including')

    def test_version_in_range_excluding_both(self):
        from app.filters import _version_in_range

        # Boundaries excluded
        assert not _version_in_range('1.0.0', '1.0.0', '2.0.0', 'excluding', 'excluding')
        assert not _version_in_range('2.0.0', '1.0.0', '2.0.0', 'excluding', 'excluding')
        # Middle still works
        assert _version_in_range('1.5.0', '1.0.0', '2.0.0', 'excluding', 'excluding')

    def test_version_out_of_range(self):
        from app.filters import _version_in_range

        assert not _version_in_range('0.5.0', '1.0.0', '2.0.0', 'including', 'including')
        assert not _version_in_range('2.5.0', '1.0.0', '2.0.0', 'including', 'including')

    def test_version_with_no_bounds(self):
        from app.filters import _version_in_range

        # No bounds means any version matches
        assert _version_in_range('999.0.0', None, None, None, None)


class TestVersionSortKey:
    """Tests for the _version_sort_key function in app.version_utils."""

    def test_simple_semver(self):
        """Test simple semver string produces correct numeric tuples."""
        from app.version_utils import _version_sort_key

        result = _version_sort_key('1.2.3')
        assert result == ((0, 1), (0, 2), (0, 3))

    def test_complex_version(self):
        """Test complex version string with multi-digit components."""
        from app.version_utils import _version_sort_key

        result = _version_sort_key('10.1.18')
        assert result == ((0, 10), (0, 1), (0, 18))

    def test_mixed_alphanumeric(self):
        """Test mixed alphanumeric parts like '18ubuntu1' are split correctly."""
        from app.version_utils import _version_sort_key

        result = _version_sort_key('18ubuntu1')
        # '18ubuntu1' has no delimiters, so regex splits into numeric prefix 18
        # and alpha remainder 'ubuntu1'
        assert result[0] == (0, 18)
        assert result[1] == (1, 'ubuntu1')
        assert len(result) == 2

    def test_empty_version(self):
        """Test empty or None version returns empty tuple."""
        from app.version_utils import _version_sort_key

        assert _version_sort_key('') == tuple()
        assert _version_sort_key(None) == tuple()

    def test_version_with_plus(self):
        """Test version with + delimiter (e.g., build metadata)."""
        from app.version_utils import _version_sort_key

        result = _version_sort_key('1.0.0+build123')
        # + is a delimiter, so splits into '1', '0', '0', 'build123'
        assert result[0] == (0, 1)
        assert result[1] == (0, 0)
        assert result[2] == (0, 0)
        # 'build123' is mixed alphanumeric — should not crash
        assert len(result) >= 4

    def test_version_comparison_ordering(self):
        """Verify that version sort keys produce correct ordering."""
        from app.version_utils import _version_sort_key

        key_10 = _version_sort_key('10.1.0')
        key_9 = _version_sort_key('9.9.9')
        key_1 = _version_sort_key('1.0.0')

        assert key_10 > key_9
        assert key_9 > key_1
        assert key_10 > key_1


class TestVendorFixOverride:
    """Tests for vendor fix override matching logic."""

    def test_no_override_returns_match(self, app, db_session, test_org,
                                       sample_product, sample_vulnerability):
        """Without a VendorFixOverride, a CVE match should work normally."""
        from app.filters import check_match

        # Ensure the product and vulnerability match via CPE inference
        match_reasons, method, confidence = check_match(
            sample_vulnerability, sample_product
        )
        assert len(match_reasons) > 0, "Expected a match without override"

    def test_approved_override_suppresses_match(self, app, db_session, test_org,
                                                 sample_product, sample_vulnerability):
        """An approved VendorFixOverride for the CVE+product+version should suppress the match."""
        from app.models import VendorFixOverride
        from app.filters import check_match

        override = VendorFixOverride(
            cve_id='CVE-2024-1234',
            vendor='apache',
            product='tomcat',
            fixed_version='10.1.18',
            fix_type='backport_patch',
            status='approved',
            organization_id=test_org.id
        )
        db_session.add(override)
        db_session.commit()

        match_reasons, method, confidence = check_match(
            sample_vulnerability, sample_product
        )
        assert len(match_reasons) == 0, "Expected match to be suppressed by approved override"

    def test_pending_override_does_not_suppress(self, app, db_session, test_org,
                                                 sample_product, sample_vulnerability):
        """A pending VendorFixOverride should NOT suppress the match."""
        from app.models import VendorFixOverride
        from app.filters import check_match

        override = VendorFixOverride(
            cve_id='CVE-2024-1234',
            vendor='apache',
            product='tomcat',
            fixed_version='10.1.18',
            fix_type='backport_patch',
            status='pending',
            organization_id=test_org.id
        )
        db_session.add(override)
        db_session.commit()

        match_reasons, method, confidence = check_match(
            sample_vulnerability, sample_product
        )
        assert len(match_reasons) > 0, "Pending override should not suppress the match"

    def test_override_with_cpe_names(self, app, db_session, test_org,
                                      sample_product, sample_vulnerability):
        """Override using CPE vendor/product names also works."""
        from app.models import VendorFixOverride
        from app.filters import has_vendor_fix_override

        # Use CPE-style names (cpe_vendor/cpe_product) instead of display names
        override = VendorFixOverride(
            cve_id='CVE-2024-1234',
            vendor='apache',
            product='tomcat',
            fixed_version='10.1.18',
            fix_type='backport_patch',
            status='approved',
            organization_id=test_org.id
        )
        db_session.add(override)
        db_session.commit()

        result = has_vendor_fix_override(sample_vulnerability, sample_product)
        assert result is not None, "Override with CPE names should be found"


class TestExtractCoreProductName:
    """Tests for the extract_core_product_name function."""

    def test_with_architecture(self):
        """Test removal of architecture/language parenthetical suffix."""
        from app.filters import extract_core_product_name

        result = extract_core_product_name('Mozilla Firefox (x64 en-US)')
        assert result == 'mozilla firefox'

    def test_with_version(self):
        """Test removal of version number and architecture."""
        from app.filters import extract_core_product_name

        result = extract_core_product_name('7-Zip 25.01 (x64)')
        assert result == '7-zip'

    def test_simple(self):
        """Test simple product name is lowered."""
        from app.filters import extract_core_product_name

        result = extract_core_product_name('Git')
        assert result == 'git'

    def test_empty(self):
        """Test empty string returns empty string."""
        from app.filters import extract_core_product_name

        result = extract_core_product_name('')
        assert result == ''


class TestMatchVulnerabilitiesToProducts:
    """Integration tests for match_vulnerabilities_to_products (requires DB)."""

    def test_creates_new_matches(self, app, db_session, test_org,
                                  sample_product, sample_vulnerability):
        """Creating a product+vulnerability pair should produce a match."""
        from app.filters import match_vulnerabilities_to_products
        from app.models import VulnerabilityMatch

        count = match_vulnerabilities_to_products()
        assert count >= 1, "Expected at least one new match to be created"

        match = VulnerabilityMatch.query.filter_by(
            product_id=sample_product.id,
            vulnerability_id=sample_vulnerability.id
        ).first()
        assert match is not None, "Match record should exist in the database"

    def test_does_not_duplicate_matches(self, app, db_session, test_org,
                                         sample_product, sample_vulnerability):
        """Running match_vulnerabilities_to_products twice should not create duplicates."""
        from app.filters import match_vulnerabilities_to_products
        from app.models import VulnerabilityMatch

        first_count = match_vulnerabilities_to_products()
        second_count = match_vulnerabilities_to_products()
        assert second_count == 0, "Second run should not create new matches"

        total = VulnerabilityMatch.query.filter_by(
            product_id=sample_product.id,
            vulnerability_id=sample_vulnerability.id
        ).count()
        assert total == 1, "Should have exactly one match, not duplicates"

    def test_cleanup_invalid_matches(self, app, db_session, test_org,
                                      sample_product, sample_vulnerability):
        """cleanup_invalid_matches should remove matches that no longer pass."""
        from app.filters import match_vulnerabilities_to_products, cleanup_invalid_matches
        from app.models import VulnerabilityMatch

        # First create a match
        match_vulnerabilities_to_products()

        match = VulnerabilityMatch.query.filter_by(
            product_id=sample_product.id,
            vulnerability_id=sample_vulnerability.id
        ).first()
        assert match is not None, "Match should exist before cleanup"

        # Now change the vulnerability so it no longer matches this product
        sample_vulnerability.vendor_project = 'Microsoft'
        sample_vulnerability.product = 'Windows'
        sample_vulnerability.set_cpe_entries([{
            'vendor': 'microsoft', 'product': 'windows',
            'version_start': '10.0.0', 'version_end': '10.0.99',
            'version_start_type': 'including', 'version_end_type': 'excluding',
        }])
        db_session.commit()

        removed = cleanup_invalid_matches()
        assert removed >= 1, "Should have removed at least one invalid match"

        match = VulnerabilityMatch.query.filter_by(
            product_id=sample_product.id,
            vulnerability_id=sample_vulnerability.id
        ).first()
        assert match is None, "Invalid match should have been removed"


class TestGetFilteredVulnerabilitiesDualPath:
    """
    Regression tests for get_filtered_vulnerabilities() ensuring it handles
    both legacy organization_id FK and many-to-many product_organizations.
    """

    def _create_orgs_and_products(self, db_session):
        """Helper: create two orgs, products via legacy FK and m2m, plus vuln matches."""
        from app.models import (
            Organization, Product, Vulnerability, VulnerabilityMatch,
            product_organizations
        )
        from datetime import date

        org1 = Organization(name='org_legacy', display_name='Legacy Org', active=True)
        org2 = Organization(name='org_m2m', display_name='M2M Org', active=True)
        db_session.add_all([org1, org2])
        db_session.flush()

        # Product assigned ONLY via legacy FK (no m2m entry)
        legacy_product = Product(
            vendor='Apache', product_name='Tomcat', version='9.0.1',
            criticality='high', active=True, organization_id=org1.id,
            cpe_vendor='apache', cpe_product='tomcat', match_type='auto'
        )
        # Product assigned ONLY via m2m (no legacy FK)
        m2m_product = Product(
            vendor='Microsoft', product_name='Edge', version='120',
            criticality='medium', active=True, organization_id=None,
            cpe_vendor='microsoft', cpe_product='edge', match_type='auto'
        )
        # Product assigned via BOTH paths
        both_product = Product(
            vendor='Mozilla', product_name='Firefox', version='121',
            criticality='medium', active=True, organization_id=org1.id,
            cpe_vendor='mozilla', cpe_product='firefox', match_type='auto'
        )
        db_session.add_all([legacy_product, m2m_product, both_product])
        db_session.flush()

        # Add m2m assignments
        db_session.execute(product_organizations.insert().values(
            product_id=m2m_product.id, organization_id=org2.id
        ))
        db_session.execute(product_organizations.insert().values(
            product_id=both_product.id, organization_id=org1.id
        ))

        # Create vulnerabilities + matches for each product
        vuln = Vulnerability(
            cve_id='CVE-2024-9999', vendor_project='Apache', product='Tomcat',
            vulnerability_name='Test Vuln', date_added=date.today(),
            short_description='Test', required_action='Update', cvss_score=9.0,
            severity='CRITICAL'
        )
        db_session.add(vuln)
        db_session.flush()

        for prod in [legacy_product, m2m_product, both_product]:
            db_session.add(VulnerabilityMatch(
                product_id=prod.id, vulnerability_id=vuln.id,
                match_method='cpe', match_confidence='high',
                match_reason='Test match'
            ))
        db_session.commit()

        return {
            'org1': org1, 'org2': org2,
            'legacy_product': legacy_product,
            'm2m_product': m2m_product,
            'both_product': both_product,
            'vuln': vuln
        }

    def test_legacy_only_product_appears_in_org_filter(self, app, db_session):
        """Products assigned ONLY via legacy FK must appear when filtering by org."""
        from app.filters import get_filtered_vulnerabilities

        data = self._create_orgs_and_products(db_session)
        results = get_filtered_vulnerabilities({'organization_id': data['org1'].id})

        product_ids = [r.product_id for r in results]
        assert data['legacy_product'].id in product_ids, \
            "Legacy-only product should appear in vulnerability results"

    def test_m2m_only_product_appears_in_org_filter(self, app, db_session):
        """Products assigned ONLY via m2m must appear when filtering by org."""
        from app.filters import get_filtered_vulnerabilities

        data = self._create_orgs_and_products(db_session)
        results = get_filtered_vulnerabilities({'organization_id': data['org2'].id})

        product_ids = [r.product_id for r in results]
        assert data['m2m_product'].id in product_ids, \
            "M2M-only product should appear in vulnerability results"

    def test_both_path_product_appears_in_org_filter(self, app, db_session):
        """Products assigned via BOTH paths must appear (no duplicates)."""
        from app.filters import get_filtered_vulnerabilities

        data = self._create_orgs_and_products(db_session)
        results = get_filtered_vulnerabilities({'organization_id': data['org1'].id})

        product_ids = [r.product_id for r in results]
        assert data['both_product'].id in product_ids, \
            "Dual-path product should appear in vulnerability results"

    def test_other_org_products_excluded(self, app, db_session):
        """Products NOT in the filtered org must NOT appear."""
        from app.filters import get_filtered_vulnerabilities

        data = self._create_orgs_and_products(db_session)
        # Filter for org2 — should NOT see legacy_product (org1 only) or both_product (org1)
        results = get_filtered_vulnerabilities({'organization_id': data['org2'].id})

        product_ids = [r.product_id for r in results]
        assert data['legacy_product'].id not in product_ids, \
            "Other org's legacy product should NOT appear"

    def test_empty_org_returns_empty(self, app, db_session):
        """An org with no products should return empty results."""
        from app.models import Organization
        from app.filters import get_filtered_vulnerabilities

        self._create_orgs_and_products(db_session)
        empty_org = Organization(name='empty_org', display_name='Empty', active=True)
        db_session.add(empty_org)
        db_session.commit()

        results = get_filtered_vulnerabilities({'organization_id': empty_org.id})
        assert results == [], "Empty org should return no vulnerability results"
