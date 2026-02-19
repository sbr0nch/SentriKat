"""
Tests for the network security module (SSRF protection).
"""
import pytest
import socket
from unittest.mock import patch, MagicMock


class TestIsSSRFSafeURL:
    """Tests for is_ssrf_safe_url() function."""

    # ------------------------------------------------------------------ #
    #  Valid public URLs - should be allowed
    # ------------------------------------------------------------------ #

    @patch('app.network_security.socket.getaddrinfo')
    def test_public_http_url_is_safe(self, mock_dns):
        """Test that a standard public HTTP URL is allowed."""
        from app.network_security import is_ssrf_safe_url

        mock_dns.return_value = [(socket.AF_INET, socket.SOCK_STREAM, 0, '', ('93.184.216.34', 0))]
        assert is_ssrf_safe_url('http://example.com/path') is True

    @patch('app.network_security.socket.getaddrinfo')
    def test_public_https_url_is_safe(self, mock_dns):
        """Test that a standard public HTTPS URL is allowed."""
        from app.network_security import is_ssrf_safe_url

        mock_dns.return_value = [(socket.AF_INET, socket.SOCK_STREAM, 0, '', ('93.184.216.34', 0))]
        assert is_ssrf_safe_url('https://example.com/webhook') is True

    @patch('app.network_security.socket.getaddrinfo')
    def test_public_url_with_port_is_safe(self, mock_dns):
        """Test that a public URL with an explicit port is allowed."""
        from app.network_security import is_ssrf_safe_url

        mock_dns.return_value = [(socket.AF_INET, socket.SOCK_STREAM, 0, '', ('93.184.216.34', 0))]
        assert is_ssrf_safe_url('https://example.com:8443/api/v1') is True

    def test_public_ip_url_is_safe(self):
        """Test that a URL with a public IP address is allowed."""
        from app.network_security import is_ssrf_safe_url

        assert is_ssrf_safe_url('https://8.8.8.8/dns-query') is True

    # ------------------------------------------------------------------ #
    #  Private IP ranges - 10.x.x.x - should be blocked
    # ------------------------------------------------------------------ #

    def test_blocks_10_dot_private_range(self):
        """Test that 10.x.x.x private range is blocked."""
        from app.network_security import is_ssrf_safe_url

        assert is_ssrf_safe_url('http://10.0.0.1/admin') is False

    def test_blocks_10_dot_arbitrary_address(self):
        """Test that arbitrary addresses in the 10.x range are blocked."""
        from app.network_security import is_ssrf_safe_url

        assert is_ssrf_safe_url('https://10.255.255.255/api') is False

    # ------------------------------------------------------------------ #
    #  Private IP ranges - 172.16-31.x.x - should be blocked
    # ------------------------------------------------------------------ #

    def test_blocks_172_16_private_range(self):
        """Test that 172.16.x.x private range is blocked."""
        from app.network_security import is_ssrf_safe_url

        assert is_ssrf_safe_url('http://172.16.0.1/internal') is False

    def test_blocks_172_31_private_range(self):
        """Test that 172.31.x.x (upper end of 172 private range) is blocked."""
        from app.network_security import is_ssrf_safe_url

        assert is_ssrf_safe_url('http://172.31.255.255/internal') is False

    # ------------------------------------------------------------------ #
    #  Private IP ranges - 192.168.x.x - should be blocked
    # ------------------------------------------------------------------ #

    def test_blocks_192_168_private_range(self):
        """Test that 192.168.x.x private range is blocked."""
        from app.network_security import is_ssrf_safe_url

        assert is_ssrf_safe_url('http://192.168.1.1/router') is False

    def test_blocks_192_168_zero_subnet(self):
        """Test that 192.168.0.x is blocked."""
        from app.network_security import is_ssrf_safe_url

        assert is_ssrf_safe_url('https://192.168.0.100:8080/api') is False

    # ------------------------------------------------------------------ #
    #  Loopback addresses - should be blocked
    # ------------------------------------------------------------------ #

    def test_blocks_loopback_127_0_0_1(self):
        """Test that 127.0.0.1 loopback is blocked."""
        from app.network_security import is_ssrf_safe_url

        assert is_ssrf_safe_url('http://127.0.0.1/secret') is False

    @patch('app.network_security.socket.getaddrinfo')
    def test_blocks_localhost_hostname(self, mock_dns):
        """Test that 'localhost' hostname is blocked after DNS resolution."""
        from app.network_security import is_ssrf_safe_url

        mock_dns.return_value = [(socket.AF_INET, socket.SOCK_STREAM, 0, '', ('127.0.0.1', 0))]
        assert is_ssrf_safe_url('http://localhost/admin') is False

    @patch('app.network_security.socket.getaddrinfo')
    def test_blocks_localhost_with_port(self, mock_dns):
        """Test that localhost with a port is blocked."""
        from app.network_security import is_ssrf_safe_url

        mock_dns.return_value = [(socket.AF_INET, socket.SOCK_STREAM, 0, '', ('127.0.0.1', 0))]
        assert is_ssrf_safe_url('http://localhost:8080/api') is False

    def test_blocks_127_x_loopback_variants(self):
        """Test that the entire 127.x.x.x loopback range is blocked."""
        from app.network_security import is_ssrf_safe_url

        assert is_ssrf_safe_url('http://127.0.0.2/path') is False
        assert is_ssrf_safe_url('http://127.255.255.255/path') is False

    # ------------------------------------------------------------------ #
    #  Link-local addresses - should be blocked
    # ------------------------------------------------------------------ #

    def test_blocks_link_local_169_254(self):
        """Test that link-local 169.254.x.x addresses are blocked."""
        from app.network_security import is_ssrf_safe_url

        assert is_ssrf_safe_url('http://169.254.1.1/path') is False

    # ------------------------------------------------------------------ #
    #  Cloud metadata endpoints - should be blocked
    # ------------------------------------------------------------------ #

    def test_blocks_aws_metadata_endpoint(self):
        """Test that the AWS metadata endpoint (169.254.169.254) is blocked."""
        from app.network_security import is_ssrf_safe_url

        assert is_ssrf_safe_url('http://169.254.169.254/latest/meta-data/') is False

    def test_blocks_ecs_metadata_endpoint(self):
        """Test that the ECS metadata endpoint (169.254.170.2) is blocked."""
        from app.network_security import is_ssrf_safe_url

        assert is_ssrf_safe_url('http://169.254.170.2/v2/credentials') is False

    @patch('app.network_security.socket.getaddrinfo')
    def test_blocks_dns_resolving_to_metadata_ip(self, mock_dns):
        """Test that a hostname resolving to a metadata IP is blocked."""
        from app.network_security import is_ssrf_safe_url

        mock_dns.return_value = [(socket.AF_INET, socket.SOCK_STREAM, 0, '', ('169.254.169.254', 0))]
        assert is_ssrf_safe_url('http://evil.attacker.com/steal-creds') is False

    # ------------------------------------------------------------------ #
    #  Invalid URL schemes - should be blocked
    # ------------------------------------------------------------------ #

    def test_blocks_ftp_scheme(self):
        """Test that ftp:// scheme is rejected."""
        from app.network_security import is_ssrf_safe_url

        assert is_ssrf_safe_url('ftp://example.com/file.txt') is False

    def test_blocks_file_scheme(self):
        """Test that file:// scheme is rejected."""
        from app.network_security import is_ssrf_safe_url

        assert is_ssrf_safe_url('file:///etc/passwd') is False

    def test_blocks_gopher_scheme(self):
        """Test that gopher:// scheme is rejected."""
        from app.network_security import is_ssrf_safe_url

        assert is_ssrf_safe_url('gopher://evil.com/_GET') is False

    def test_blocks_javascript_scheme(self):
        """Test that javascript: scheme is rejected."""
        from app.network_security import is_ssrf_safe_url

        assert is_ssrf_safe_url('javascript:alert(1)') is False

    # ------------------------------------------------------------------ #
    #  Missing scheme - should be blocked
    # ------------------------------------------------------------------ #

    def test_blocks_url_without_scheme(self):
        """Test that a URL with no scheme is rejected."""
        from app.network_security import is_ssrf_safe_url

        assert is_ssrf_safe_url('example.com/path') is False

    def test_blocks_scheme_relative_url(self):
        """Test that a scheme-relative URL (//host/path) is rejected."""
        from app.network_security import is_ssrf_safe_url

        assert is_ssrf_safe_url('//example.com/path') is False

    # ------------------------------------------------------------------ #
    #  Empty / None URLs - should be blocked
    # ------------------------------------------------------------------ #

    def test_blocks_empty_string(self):
        """Test that an empty string is rejected."""
        from app.network_security import is_ssrf_safe_url

        assert is_ssrf_safe_url('') is False

    def test_blocks_none_url(self):
        """Test that None is rejected."""
        from app.network_security import is_ssrf_safe_url

        assert is_ssrf_safe_url(None) is False

    def test_blocks_whitespace_only(self):
        """Test that whitespace-only input is rejected."""
        from app.network_security import is_ssrf_safe_url

        assert is_ssrf_safe_url('   ') is False

    # ------------------------------------------------------------------ #
    #  DNS rebinding protection
    # ------------------------------------------------------------------ #

    @patch('app.network_security.socket.getaddrinfo')
    def test_blocks_dns_rebinding_to_private_ip(self, mock_dns):
        """Test that a hostname resolving to a private IP is blocked (DNS rebinding)."""
        from app.network_security import is_ssrf_safe_url

        mock_dns.return_value = [(socket.AF_INET, socket.SOCK_STREAM, 0, '', ('10.0.0.1', 0))]
        assert is_ssrf_safe_url('http://evil.attacker.com/webhook') is False

    @patch('app.network_security.socket.getaddrinfo')
    def test_blocks_dns_rebinding_to_loopback(self, mock_dns):
        """Test that a hostname resolving to 127.0.0.1 is blocked."""
        from app.network_security import is_ssrf_safe_url

        mock_dns.return_value = [(socket.AF_INET, socket.SOCK_STREAM, 0, '', ('127.0.0.1', 0))]
        assert is_ssrf_safe_url('http://attacker-controlled.com/exfil') is False

    @patch('app.network_security.socket.getaddrinfo')
    def test_blocks_dns_rebinding_to_192_168(self, mock_dns):
        """Test that a hostname resolving to 192.168.x.x is blocked."""
        from app.network_security import is_ssrf_safe_url

        mock_dns.return_value = [(socket.AF_INET, socket.SOCK_STREAM, 0, '', ('192.168.1.100', 0))]
        assert is_ssrf_safe_url('http://malicious-redirect.com/api') is False

    @patch('app.network_security.socket.getaddrinfo')
    def test_unresolvable_hostname_allowed(self, mock_dns):
        """Test that an unresolvable hostname is allowed (let the request fail naturally)."""
        from app.network_security import is_ssrf_safe_url

        mock_dns.side_effect = socket.gaierror('Name or service not known')
        assert is_ssrf_safe_url('http://does-not-exist.invalid/path') is True

    @patch('app.network_security.socket.getaddrinfo')
    def test_dns_oserror_allowed(self, mock_dns):
        """Test that a DNS OSError is treated as allowed (fail-open for DNS)."""
        from app.network_security import is_ssrf_safe_url

        mock_dns.side_effect = OSError('Network is unreachable')
        assert is_ssrf_safe_url('http://some-hostname.com/path') is True


class TestValidateURLForRequest:
    """Tests for validate_url_for_request() wrapper function."""

    def test_returns_error_for_empty_url(self):
        """Test that an empty URL returns an error tuple."""
        from app.network_security import validate_url_for_request

        is_safe, error = validate_url_for_request('')
        assert is_safe is False
        assert error == "URL is required"

    def test_returns_error_for_none_url(self):
        """Test that None URL returns an error tuple."""
        from app.network_security import validate_url_for_request

        is_safe, error = validate_url_for_request(None)
        assert is_safe is False
        assert error == "URL is required"

    def test_returns_error_for_missing_scheme(self):
        """Test that a URL without http/https scheme is rejected."""
        from app.network_security import validate_url_for_request

        is_safe, error = validate_url_for_request('example.com/path')
        assert is_safe is False
        assert error == "URL must start with http:// or https://"

    def test_returns_error_for_ftp_scheme(self):
        """Test that ftp:// is rejected at the scheme check."""
        from app.network_security import validate_url_for_request

        is_safe, error = validate_url_for_request('ftp://example.com/file')
        assert is_safe is False
        assert error == "URL must start with http:// or https://"

    def test_returns_error_for_internal_url(self):
        """Test that an internal/private URL is rejected with SSRF message."""
        from app.network_security import validate_url_for_request

        is_safe, error = validate_url_for_request('http://192.168.1.1/admin', context='webhook')
        assert is_safe is False
        assert error == "URL must not target internal or private network addresses"

    @patch('app.network_security.socket.getaddrinfo')
    def test_returns_safe_for_valid_public_url(self, mock_dns):
        """Test that a valid public URL returns (True, None)."""
        from app.network_security import validate_url_for_request

        mock_dns.return_value = [(socket.AF_INET, socket.SOCK_STREAM, 0, '', ('93.184.216.34', 0))]
        is_safe, error = validate_url_for_request('https://example.com/webhook', context='integration')
        assert is_safe is True
        assert error is None

    @patch('app.network_security.logger')
    def test_logs_warning_for_blocked_url(self, mock_logger):
        """Test that a blocked SSRF attempt is logged with a warning."""
        from app.network_security import validate_url_for_request

        validate_url_for_request('http://10.0.0.1/internal', context='webhook test')
        mock_logger.warning.assert_called_once()
        log_message = mock_logger.warning.call_args[0][0]
        assert 'SSRF blocked' in log_message
        assert 'webhook test' in log_message
        assert '10.0.0.1' in log_message

    @patch('app.network_security.socket.getaddrinfo')
    def test_context_parameter_is_optional(self, mock_dns):
        """Test that calling validate_url_for_request without context works."""
        from app.network_security import validate_url_for_request

        mock_dns.return_value = [(socket.AF_INET, socket.SOCK_STREAM, 0, '', ('93.184.216.34', 0))]
        is_safe, error = validate_url_for_request('https://example.com/api')
        assert is_safe is True
        assert error is None


class TestEdgeCases:
    """Edge case and boundary condition tests."""

    def test_blocks_zero_address(self):
        """Test that 0.0.0.0 is blocked."""
        from app.network_security import is_ssrf_safe_url

        assert is_ssrf_safe_url('http://0.0.0.0/path') is False

    @patch('app.network_security.socket.getaddrinfo')
    def test_url_with_username_and_password(self, mock_dns):
        """Test that URL with embedded credentials pointing to public IP is safe."""
        from app.network_security import is_ssrf_safe_url

        mock_dns.return_value = [(socket.AF_INET, socket.SOCK_STREAM, 0, '', ('93.184.216.34', 0))]
        assert is_ssrf_safe_url('http://user:pass@example.com/path') is True

    @patch('app.network_security.socket.getaddrinfo')
    def test_url_with_query_params_is_safe(self, mock_dns):
        """Test that a public URL with query parameters is allowed."""
        from app.network_security import is_ssrf_safe_url

        mock_dns.return_value = [(socket.AF_INET, socket.SOCK_STREAM, 0, '', ('93.184.216.34', 0))]
        assert is_ssrf_safe_url('https://example.com/api?key=value&other=123') is True

    def test_blocks_ipv6_loopback(self):
        """Test that IPv6 loopback (::1) is blocked when used as literal."""
        from app.network_security import is_ssrf_safe_url

        assert is_ssrf_safe_url('http://[::1]/admin') is False

    @patch('app.network_security.socket.getaddrinfo')
    def test_blocks_hostname_resolving_to_ipv6_loopback(self, mock_dns):
        """Test that a hostname resolving to IPv6 ::1 is blocked."""
        from app.network_security import is_ssrf_safe_url

        mock_dns.return_value = [(socket.AF_INET6, socket.SOCK_STREAM, 0, '', ('::1', 0, 0, 0))]
        assert is_ssrf_safe_url('http://ipv6-loopback.attacker.com/exfil') is False
