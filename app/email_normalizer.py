"""
Email normalization for duplicate detection.

Mirrors the ruleset from the license-server (app/core/email_normalizer.py)
so both sides agree on what counts as "same user".

Rules:
  1. Lowercase the entire address.
  2. For @gmail.com and @googlemail.com ONLY:
     a. Strip +tag from local part  (user+promo → user)
     b. Strip dots from local part  (u.s.e.r → user)
     c. Canonicalize @googlemail.com → @gmail.com
  3. For all other domains:
     a. Strip +tag from local part (most MTAs ignore it)
     b. Do NOT strip dots (dots are significant on non-Gmail domains)

Usage:
    from app.email_normalizer import normalize_email_for_dedup

    canonical = normalize_email_for_dedup("U.ser+tag@Gmail.com")
    # → "user@gmail.com"
"""

import re

_GMAIL_DOMAINS = frozenset({'gmail.com', 'googlemail.com'})


def normalize_email_for_dedup(email: str) -> str:
    """Return a canonical form of *email* for duplicate detection.

    The original address is preserved in the User record for delivery;
    this function is used only for uniqueness checks.
    """
    if not email or '@' not in email:
        return (email or '').strip().lower()

    email = email.strip().lower()
    local, domain = email.rsplit('@', 1)

    # Strip +tag (subaddressing) — works for Gmail, Outlook, Fastmail, etc.
    if '+' in local:
        local = local[:local.index('+')]

    # Gmail-specific: strip dots and canonicalize domain
    if domain in _GMAIL_DOMAINS:
        local = local.replace('.', '')
        domain = 'gmail.com'

    return f'{local}@{domain}'
