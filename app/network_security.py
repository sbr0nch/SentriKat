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

# Cache the "private URLs ignored in production" warning so we log it once
# at the first call instead of once per outbound URL validation. Without
# this, admins saw a flood of CRITICAL lines in production any time the
# misconfiguration was present (see bug [03.11.4.5]).
_PROD_IGNORE_WARNING_EMITTED = False


def _allow_private_urls():
    """Check if private/internal URLs are allowed.

    Behavior depends on deployment mode (see bug [03.11.4.5] revisited):

    - **On-prem** (``saas_mode=False``): the flag is honored even in
      production, because reaching internal network resources (Jira,
      GitLab, webhooks, syslog, AD) is the primary use case for an
      on-prem vulnerability management deployment.
    - **SaaS** (``saas_mode=True``): the flag is ignored in production
      to harden against an admin accidentally enabling SSRF bypass on
      a multi-tenant cloud box (where private IPs would target other
      tenants or cloud-provider metadata endpoints).

    In ``FLASK_ENV=development`` the flag is honored regardless of mode.
    """
    global _PROD_IGNORE_WARNING_EMITTED
    allowed = (os.environ.get('ALLOW_PRIVATE_URLS', '').lower() == 'true' or
               os.environ.get('ALLOW_PRIVATE_JIRA_URL', '').lower() == 'true')
    if not allowed:
        return False
    if os.environ.get('FLASK_ENV') != 'production':
        return True
    # Production: only honor the flag if this is an on-prem deployment.
    try:
        from app.saas import is_saas_mode
        if not is_saas_mode():
            return True
    except Exception:
        # If saas detection fails, fall through to the conservative path.
        pass
    if not _PROD_IGNORE_WARNING_EMITTED:
        logger.warning(
            "ALLOW_PRIVATE_URLS is set in a SaaS production deployment — "
            "the flag is ignored as SSRF hardening. If this is an on-prem "
            "install, ensure SAAS_MODE is unset/false."
        )
        _PROD_IGNORE_WARNING_EMITTED = True
    return False


def private_urls_ignored_in_production():
    """Return True when the admin set ALLOW_PRIVATE_URLS but we're in a
    SaaS production deployment that ignores it.

    Call-sites that reject a URL for targeting a private network can use
    this to enrich their error message (see bug [03.11.4.5]). On-prem
    deployments now honor the flag in production, so this returns False
    for them.
    """
    if os.environ.get('FLASK_ENV') != 'production':
        return False
    flag_set = (os.environ.get('ALLOW_PRIVATE_URLS', '').lower() == 'true' or
                os.environ.get('ALLOW_PRIVATE_JIRA_URL', '').lower() == 'true')
    if not flag_set:
        return False
    try:
        from app.saas import is_saas_mode
        return is_saas_mode()
    except Exception:
        return True


def is_ssrf_safe_url(url):
    """
    Validate that a URL does not target internal/private network addresses.

    Blocks requests to:
    - Private IP ranges (10.x, 172.16-31.x, 192.168.x)
    - Loopback addresses (127.x, ::1)
    - Link-local addresses (169.254.x)
    - Reserved addresses
    - Cloud metadata endpoints (169.254.169.254, 169.254.170.2)

    When ``ALLOW_PRIVATE_URLS=true`` the private/internal network
    checks are bypassed if EITHER ``FLASK_ENV=development`` OR the
    deployment is on-prem (``saas_mode=False``). On-prem must reach
    internal services (Jira, GitLab, webhooks, syslog) — that is the
    point of an on-prem install. In a SaaS production deployment the
    flag is ignored as SSRF hardening against accidental misconfig
    that could target other tenants or cloud-provider metadata.

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
        msg = "URL must not target internal or private network addresses"
        if private_urls_ignored_in_production():
            msg += " (ALLOW_PRIVATE_URLS is set but only applies when FLASK_ENV=development)"
        return False, msg

    return True, None
