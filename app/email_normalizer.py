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


def find_and_merge_duplicate_emails(dry_run: bool = True) -> dict:
    """Scan all users, group by canonical email, and merge duplicates.

    For each group with more than one user:
      - Keep the "primary" (most recently active, most agents linked,
        or holds an admin role).
      - Deactivate the others (``is_active=False``, append ``[MERGED]``
        to their username).

    Parameters
    ----------
    dry_run : bool
        When *True* (default) no database writes are made — the function
        only reports what *would* happen.  Set to *False* to apply changes.

    Returns
    -------
    dict
        ``{'duplicates_found': int, 'users_deactivated': int, 'groups': [...]}``
        Each entry in *groups* describes one canonical email and the actions
        taken (or planned).

    Can be called from ``flask shell`` or a maintenance endpoint::

        from app.email_normalizer import find_and_merge_duplicate_emails
        result = find_and_merge_duplicate_emails(dry_run=True)
    """
    import logging
    from collections import defaultdict

    from app import db
    from app.models import User

    logger = logging.getLogger(__name__)

    canonical_map: dict[str, list] = defaultdict(list)

    for user in User.query.all():
        canonical = normalize_email_for_dedup(user.email)
        canonical_map[canonical].append(user)

    duplicates_found = 0
    users_deactivated = 0
    groups = []

    for canonical, users in canonical_map.items():
        if len(users) < 2:
            continue

        duplicates_found += 1

        def _score(u):
            """Higher score = more reason to keep this account."""
            from datetime import datetime as _dt

            role_weight = {
                'super_admin': 40,
                'org_admin': 30,
                'manager': 20,
                'user': 10,
            }
            score = role_weight.get(getattr(u, 'role', 'user'), 0)

            # Prefer active accounts
            if getattr(u, 'is_active', False):
                score += 100

            # Prefer most recent login
            last_login = getattr(u, 'last_login', None)
            if last_login:
                score += 50

            # Prefer accounts with more agents
            try:
                agent_count = len(getattr(u, 'agents', []))
                score += agent_count * 5
            except Exception:
                pass

            return score

        # Sort: highest score first; ties broken by most recent id (newest)
        users_sorted = sorted(users, key=lambda u: (_score(u), u.id), reverse=True)
        primary = users_sorted[0]
        duplicates = users_sorted[1:]

        group_info = {
            'canonical_email': canonical,
            'primary_user': {
                'id': primary.id,
                'username': primary.username,
                'email': primary.email,
                'role': getattr(primary, 'role', None),
                'is_active': primary.is_active,
            },
            'merged': [],
        }

        for dup in duplicates:
            entry = {
                'id': dup.id,
                'username': dup.username,
                'email': dup.email,
                'role': getattr(dup, 'role', None),
                'is_active': dup.is_active,
            }

            if not dry_run:
                dup.is_active = False
                if not dup.username.endswith('[MERGED]'):
                    dup.username = f"{dup.username}[MERGED]"
                entry['action'] = 'deactivated'
                logger.info(
                    "Merged duplicate user id=%s (%s) -> primary id=%s (%s) "
                    "[canonical=%s]",
                    dup.id, dup.email, primary.id, primary.email, canonical,
                )
            else:
                entry['action'] = 'would_deactivate'

            group_info['merged'].append(entry)
            users_deactivated += 1

        groups.append(group_info)

    if not dry_run:
        db.session.commit()
        logger.info(
            "Duplicate email merge complete: %d groups, %d users deactivated",
            duplicates_found, users_deactivated,
        )
    else:
        logger.info(
            "Duplicate email merge DRY RUN: %d groups, %d users would be deactivated",
            duplicates_found, users_deactivated,
        )

    return {
        'dry_run': dry_run,
        'duplicates_found': duplicates_found,
        'users_deactivated': users_deactivated,
        'groups': groups,
    }
