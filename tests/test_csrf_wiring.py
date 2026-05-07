"""Regression tests for CSRF token wiring on protected admin endpoints.

Ensures every fetch() call to an endpoint decorated with
``@csrf_protect_session`` (auth.py) sends an X-CSRFToken header.
Catches regressions like the 2FA setup bug discovered 2026-05-07
(months-old latent bug: file existed since 2026-04-29 with
incorrect fetch).
"""

import re
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parent.parent
BASE_HTML = REPO_ROOT / 'app' / 'templates' / 'base.html'
LOGIN_HTML = REPO_ROOT / 'app' / 'templates' / 'login.html'

# Endpoints decorated with @csrf_protect_session in app/auth.py.
# When adding a new one, add it here AND wire X-CSRFToken in the JS caller.
CSRF_REQUIRED_ENDPOINTS = [
    '/api/auth/change-password',
    '/api/auth/2fa/setup',
    '/api/auth/2fa/verify',
    '/api/auth/2fa/disable',
]


def _fetch_blocks_for_url(html_text: str, url: str):
    """Return list of fetch(...) call snippets that target the given url."""
    # Match fetch( ... { ... method: 'POST' ... } ) with the url anywhere inside.
    blocks = []
    pattern = re.compile(
        r"fetch\([^)]*?" + re.escape(url) + r"[^)]*?\)?\s*,?\s*\{(?P<body>[^}]*?method\s*:\s*['\"](POST|PUT|PATCH|DELETE)['\"][^}]*?)\}",
        re.DOTALL,
    )
    for m in pattern.finditer(html_text):
        blocks.append(m.group('body'))
    # Also try the simpler form: fetch(url, { method: 'POST' })
    simple_pattern = re.compile(
        r"fetch\([^,]*" + re.escape(url) + r"[^,]*,\s*\{(?P<body>[^}]*?method\s*:\s*['\"](POST|PUT|PATCH|DELETE)['\"][^}]*?)\}",
        re.DOTALL,
    )
    for m in simple_pattern.finditer(html_text):
        body = m.group('body')
        if body not in blocks:
            blocks.append(body)
    return blocks


def _get_csrf_token_helper_present(html_text: str) -> bool:
    """The helper getCSRFToken() must exist in base.html so callers can use it."""
    return 'function getCSRFToken' in html_text or 'getCSRFToken =' in html_text


def test_csrf_helper_exists_in_base():
    text = BASE_HTML.read_text()
    assert _get_csrf_token_helper_present(text), (
        "base.html must define a getCSRFToken() helper for fetch callers"
    )


def test_meta_csrf_token_tag_in_base():
    text = BASE_HTML.read_text()
    assert '<meta name="csrf-token"' in text, (
        "base.html must expose csrf_token() via <meta name='csrf-token'> for JS"
    )


def test_change_password_fetch_in_base_sends_csrf():
    text = BASE_HTML.read_text()
    blocks = _fetch_blocks_for_url(text, '/api/auth/change-password')
    assert blocks, "change-password fetch not found in base.html"
    for block in blocks:
        assert 'X-CSRFToken' in block or 'X-CSRF-Token' in block, (
            f"change-password fetch in base.html missing X-CSRFToken header.\n"
            f"Block: {block[:300]}"
        )


def test_change_password_fetch_in_login_sends_csrf():
    text = LOGIN_HTML.read_text()
    blocks = _fetch_blocks_for_url(text, '/api/auth/change-password')
    assert blocks, "change-password fetch not found in login.html"
    for block in blocks:
        assert 'X-CSRFToken' in block or 'X-CSRF-Token' in block, (
            f"change-password fetch in login.html missing X-CSRFToken header.\n"
            f"Block: {block[:300]}"
        )


def test_2fa_setup_fetch_sends_csrf():
    text = BASE_HTML.read_text()
    blocks = _fetch_blocks_for_url(text, '/api/auth/2fa/setup')
    assert blocks, "2fa/setup fetch not found in base.html"
    for block in blocks:
        assert 'X-CSRFToken' in block or 'X-CSRF-Token' in block, (
            f"2fa/setup fetch missing X-CSRFToken header.\n"
            f"Block: {block[:300]}"
        )


def test_2fa_verify_fetch_sends_csrf():
    text = BASE_HTML.read_text()
    blocks = _fetch_blocks_for_url(text, '/api/auth/2fa/verify')
    assert blocks, "2fa/verify fetch not found in base.html"
    for block in blocks:
        assert 'X-CSRFToken' in block or 'X-CSRF-Token' in block, (
            f"2fa/verify fetch missing X-CSRFToken header.\n"
            f"Block: {block[:300]}"
        )


def test_2fa_disable_fetch_sends_csrf():
    text = BASE_HTML.read_text()
    blocks = _fetch_blocks_for_url(text, '/api/auth/2fa/disable')
    assert blocks, "2fa/disable fetch not found in base.html"
    for block in blocks:
        assert 'X-CSRFToken' in block or 'X-CSRF-Token' in block, (
            f"2fa/disable fetch missing X-CSRFToken header.\n"
            f"Block: {block[:300]}"
        )


def test_csrf_protect_session_decorators_match_known_set():
    """Snapshot test: if a new @csrf_protect_session decorator is added in
    auth.py without updating CSRF_REQUIRED_ENDPOINTS in this test, fail
    so the developer is forced to wire the matching frontend fetch."""
    auth_py = (REPO_ROOT / 'app' / 'auth.py').read_text()
    # Find each @csrf_protect_session occurrence and the route URL above it
    decorator = '@csrf_protect_session'
    found_endpoints = []
    lines = auth_py.split('\n')
    for i, line in enumerate(lines):
        if decorator in line and not line.strip().startswith('#'):
            # Walk backwards to find @auth_bp.route(...)
            for j in range(i - 1, max(0, i - 5), -1):
                m = re.search(r"route\(\s*['\"]([^'\"]+)['\"]", lines[j])
                if m:
                    found_endpoints.append(m.group(1))
                    break
    found_set = set(found_endpoints)
    expected_set = set(CSRF_REQUIRED_ENDPOINTS)
    new_endpoints = found_set - expected_set
    removed_endpoints = expected_set - found_set
    assert not new_endpoints, (
        f"New @csrf_protect_session endpoint(s) detected in auth.py: {new_endpoints}. "
        f"Add them to CSRF_REQUIRED_ENDPOINTS in this test AND wire X-CSRFToken "
        f"in their frontend fetch caller."
    )
    assert not removed_endpoints, (
        f"Expected @csrf_protect_session endpoint(s) gone from auth.py: {removed_endpoints}. "
        f"Update CSRF_REQUIRED_ENDPOINTS if intentional."
    )


def test_close_security_settings_guards_against_null_element():
    """Regression: bootstrap modal hide() throws TypeError when _element is null
    (after a 400 response triggers showAlert). closeSecuritySettings must
    check _element exists before calling hide()."""
    text = BASE_HTML.read_text()
    # Locate function body
    m = re.search(r'function closeSecuritySettings\(\)\s*\{([^}]+(?:\{[^}]*\}[^}]*)*)\}', text)
    assert m, "closeSecuritySettings function not found in base.html"
    body = m.group(1)
    assert 'securityModal._element' in body or '._element' in body, (
        "closeSecuritySettings must guard against null Bootstrap modal _element. "
        "See 2026-05-07 bug: TypeError 'this._element is null' in modal.js:244"
    )
