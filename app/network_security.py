"""
Network security utilities for SentriKat.

Provides SSRF (Server-Side Request Forgery) protection for all outbound
HTTP requests to user-supplied URLs, including webhooks, issue trackers,
and integration connectors.
"""

import ipaddress
import logging
import os
import socket
from urllib.parse import urlparse

logger = logging.getLogger(__name__)


def _allow_private_urls():
    """Check if private/internal URLs are allowed (for dev/test environments)."""
    return os.environ.get('ALLOW_PRIVATE_URLS', '').lower() == 'true'


def is_ssrf_safe_url(url):
    """
    Validate that a URL does not target internal/private network addresses.

    Blocks requests to:
    - Private IP ranges (10.x, 172.16-31.x, 192.168.x)
    - Loopback addresses (127.x, ::1)
    - Link-local addresses (169.254.x)
    - Reserved addresses
    - Cloud metadata endpoints (169.254.169.254, 169.254.170.2)

    When the ALLOW_PRIVATE_URLS environment variable is set to 'true',
    all private/internal network checks are bypassed. This is intended
    for dev/test environments where services run on internal networks
    (e.g. Docker containers using host.docker.internal). The variable
    should never be set in production.

    Args:
        url: The URL to validate.

    Returns:
        True if the URL is safe to request, False if it targets internal networks.
    """
    try:
        parsed = urlparse(url)
        hostname = parsed.hostname
        if not hostname or parsed.scheme not in ('http', 'https'):
            return False

        # If private URLs are explicitly allowed (dev/test), skip network checks
        if _allow_private_urls():
            return True

        # Resolve hostname to IP and check against private ranges
        try:
            ip = ipaddress.ip_address(hostname)
        except ValueError:
            # It's a hostname, resolve it
            try:
                resolved = socket.getaddrinfo(hostname, None, socket.AF_UNSPEC, socket.SOCK_STREAM)
                ip = ipaddress.ip_address(resolved[0][4][0])
            except (socket.gaierror, IndexError, OSError):
                return True  # Can't resolve - let the request fail naturally

        # Block private, loopback, link-local, and metadata addresses
        if ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_reserved:
            return False
        # Block AWS/GCP/Azure metadata endpoints
        if str(ip) in ('169.254.169.254', '169.254.170.2'):
            return False

        return True
    except Exception:
        return False


def validate_url_for_request(url, context=""):
    """
    Validate a URL before making an outbound request.

    Args:
        url: The URL to validate.
        context: Description of the request context (for logging).

    Returns:
        Tuple of (is_safe, error_message). error_message is None if safe.
    """
    if not url:
        return False, "URL is required"

    if not url.startswith(('http://', 'https://')):
        return False, "URL must start with http:// or https://"

    if not is_ssrf_safe_url(url):
        logger.warning(f"SSRF blocked: {context} attempted request to internal URL: {url}")
        return False, "URL must not target internal or private network addresses"

    return True, None
