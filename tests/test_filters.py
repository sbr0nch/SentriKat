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
        """Test CPE matching via inference (no cached CPE data)."""
        from app.filters import check_cpe_match

        match_reasons, method, confidence = check_cpe_match(self.vulnerability, self.product)
        assert len(match_reasons) > 0
        assert method == 'cpe'
        assert 'CPE inference' in match_reasons[0]

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
