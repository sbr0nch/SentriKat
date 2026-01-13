"""
Tests for the NVD CPE API module.
"""
import pytest
from unittest.mock import patch, MagicMock
from app.nvd_cpe_api import (
    parse_cpe_uri,
    build_cpe_uri,
    search_cpe,
    search_cpe_grouped,
    get_cpe_versions,
    _version_sort_key,
    _version_in_range,
    clear_cache,
    get_cache_stats
)


class TestCPEUriParsing:
    """Tests for CPE URI parsing."""

    def test_parse_cpe23_full(self):
        """Test parsing a full CPE 2.3 URI."""
        uri = "cpe:2.3:a:apache:tomcat:10.1.18:*:*:*:*:*:*:*"
        result = parse_cpe_uri(uri)

        assert result['part'] == 'a'
        assert result['vendor'] == 'apache'
        assert result['product'] == 'tomcat'
        assert result['version'] == '10.1.18'
        assert result['raw_uri'] == uri

    def test_parse_cpe23_with_wildcards(self):
        """Test parsing CPE 2.3 URI with wildcards."""
        uri = "cpe:2.3:a:microsoft:windows_server:*:*:*:*:*:*:*:*"
        result = parse_cpe_uri(uri)

        assert result['vendor'] == 'microsoft'
        assert result['product'] == 'windows_server'
        assert result['version'] is None  # * should be None

    def test_parse_cpe22_format(self):
        """Test parsing CPE 2.2 format URI."""
        uri = "cpe:/a:apache:http_server:2.4.51"
        result = parse_cpe_uri(uri)

        assert result['part'] == 'a'
        assert result['vendor'] == 'apache'
        assert result['product'] == 'http_server'
        assert result['version'] == '2.4.51'

    def test_parse_empty_uri(self):
        """Test parsing empty or invalid URI."""
        result = parse_cpe_uri('')
        assert result['vendor'] is None

        result = parse_cpe_uri('invalid')
        assert result['vendor'] is None

    def test_parse_operating_system(self):
        """Test parsing OS CPE."""
        uri = "cpe:2.3:o:linux:linux_kernel:5.10:*:*:*:*:*:*:*"
        result = parse_cpe_uri(uri)

        assert result['part'] == 'o'
        assert result['vendor'] == 'linux'
        assert result['product'] == 'linux_kernel'


class TestCPEUriBuild:
    """Tests for CPE URI building."""

    def test_build_basic_cpe(self):
        """Test building a basic CPE URI."""
        uri = build_cpe_uri('apache', 'tomcat')
        assert uri == 'cpe:2.3:a:apache:tomcat:*:*:*:*:*:*:*:*'

    def test_build_cpe_with_version(self):
        """Test building CPE URI with version."""
        uri = build_cpe_uri('apache', 'tomcat', '10.1.18')
        assert uri == 'cpe:2.3:a:apache:tomcat:10.1.18:*:*:*:*:*:*:*'

    def test_build_cpe_normalizes_names(self):
        """Test that build normalizes vendor/product names."""
        uri = build_cpe_uri('Apache Software Foundation', 'Apache Tomcat')
        assert uri == 'cpe:2.3:a:apache_software_foundation:apache_tomcat:*:*:*:*:*:*:*:*'


class TestVersionComparison:
    """Tests for version comparison utilities."""

    def test_version_sort_key_semver(self):
        """Test version sort key with semver versions."""
        versions = ['1.0.0', '2.0.0', '1.10.0', '1.2.0']
        sorted_versions = sorted(versions, key=_version_sort_key)
        assert sorted_versions == ['1.0.0', '1.2.0', '1.10.0', '2.0.0']

    def test_version_sort_key_mixed(self):
        """Test version sort key with mixed versions."""
        versions = ['10.1.18', '9.0.85', '10.0.27']
        sorted_versions = sorted(versions, key=_version_sort_key, reverse=True)
        assert sorted_versions[0] == '10.1.18'

    def test_version_in_range_including(self):
        """Test version range with including bounds."""
        assert _version_in_range('1.5.0', '1.0.0', '2.0.0', 'including', 'including')
        assert _version_in_range('1.0.0', '1.0.0', '2.0.0', 'including', 'including')
        assert _version_in_range('2.0.0', '1.0.0', '2.0.0', 'including', 'including')
        assert not _version_in_range('0.9.0', '1.0.0', '2.0.0', 'including', 'including')
        assert not _version_in_range('2.1.0', '1.0.0', '2.0.0', 'including', 'including')

    def test_version_in_range_excluding(self):
        """Test version range with excluding bounds."""
        assert _version_in_range('1.5.0', '1.0.0', '2.0.0', 'excluding', 'excluding')
        assert not _version_in_range('1.0.0', '1.0.0', '2.0.0', 'excluding', 'excluding')
        assert not _version_in_range('2.0.0', '1.0.0', '2.0.0', 'excluding', 'excluding')

    def test_version_in_range_no_bounds(self):
        """Test version range with no bounds."""
        assert _version_in_range('1.5.0', None, None, None, None)


class TestCacheOperations:
    """Tests for cache operations."""

    def test_clear_cache(self):
        """Test clearing the cache."""
        clear_cache()
        stats = get_cache_stats()
        assert stats['total_entries'] == 0

    def test_cache_stats(self):
        """Test getting cache statistics."""
        clear_cache()
        stats = get_cache_stats()
        assert 'total_entries' in stats
        assert 'valid_entries' in stats
        assert 'cache_ttl_minutes' in stats


class TestCPESearch:
    """Tests for CPE search functionality (with mocking)."""

    @patch('app.nvd_cpe_api.requests.get')
    def test_search_cpe_success(self, mock_get):
        """Test successful CPE search."""
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            'products': [
                {
                    'cpe': {
                        'cpeName': 'cpe:2.3:a:apache:tomcat:10.1.18:*:*:*:*:*:*:*',
                        'cpeNameId': 'test-id',
                        'deprecated': False,
                        'titles': [{'title': 'Apache Tomcat 10.1.18'}]
                    }
                }
            ]
        }
        mock_get.return_value = mock_response

        # Clear cache first
        clear_cache()

        results = search_cpe('apache tomcat')
        assert len(results) == 1
        assert results[0]['vendor'] == 'apache'
        assert results[0]['product'] == 'tomcat'

    @patch('app.nvd_cpe_api.requests.get')
    def test_search_cpe_empty_result(self, mock_get):
        """Test CPE search with no results."""
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {'products': []}
        mock_get.return_value = mock_response

        clear_cache()
        results = search_cpe('nonexistent_product_xyz')
        assert len(results) == 0

    def test_search_cpe_short_query(self):
        """Test CPE search with too short query."""
        results = search_cpe('a')
        assert len(results) == 0

    @patch('app.nvd_cpe_api.requests.get')
    def test_search_cpe_grouped(self, mock_get):
        """Test grouped CPE search."""
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            'products': [
                {
                    'cpe': {
                        'cpeName': 'cpe:2.3:a:apache:tomcat:10.1.18:*:*:*:*:*:*:*',
                        'cpeNameId': 'id1',
                        'deprecated': False,
                        'titles': [{'title': 'Apache Tomcat 10.1.18'}]
                    }
                },
                {
                    'cpe': {
                        'cpeName': 'cpe:2.3:a:apache:tomcat:9.0.85:*:*:*:*:*:*:*',
                        'cpeNameId': 'id2',
                        'deprecated': False,
                        'titles': [{'title': 'Apache Tomcat 9.0.85'}]
                    }
                }
            ]
        }
        mock_get.return_value = mock_response

        clear_cache()
        results = search_cpe_grouped('apache tomcat')

        assert 'apache' in results
        assert 'tomcat' in results['apache']['products']
        assert len(results['apache']['products']['tomcat']['versions']) == 2


class TestCPEVersionFetch:
    """Tests for CPE version fetching."""

    @patch('app.nvd_cpe_api.requests.get')
    def test_get_cpe_versions(self, mock_get):
        """Test fetching versions for a product."""
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            'products': [
                {
                    'cpe': {
                        'cpeName': 'cpe:2.3:a:apache:tomcat:10.1.18:*:*:*:*:*:*:*',
                        'deprecated': False
                    }
                },
                {
                    'cpe': {
                        'cpeName': 'cpe:2.3:a:apache:tomcat:9.0.85:*:*:*:*:*:*:*',
                        'deprecated': False
                    }
                }
            ]
        }
        mock_get.return_value = mock_response

        clear_cache()
        versions = get_cpe_versions('apache', 'tomcat')

        assert '10.1.18' in versions
        assert '9.0.85' in versions
