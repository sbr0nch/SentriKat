"""Centralized authorization helpers.

Single source of truth for multi-tenant access checks. Use these helpers in
every resource-scoped endpoint instead of reimplementing the org-membership
logic inline. Prevents GET/PUT asymmetry bugs (audit finding H-1).

MSSP multi-org users CAN access any org they're a member of (via
``User.get_all_organizations``). On-prem ``super_admin`` users bypass all
checks; in SaaS mode ``super_admin`` is scoped to their own tenant.
"""
from __future__ import annotations

from typing import Iterable, Optional

from flask import session

from app.saas import is_saas_mode


def _super_admin_unrestricted(user) -> bool:
    """Return True when the user is an unrestricted on-prem super admin."""
    if not user:
        return False
    try:
        return user.is_super_admin() and not is_saas_mode()
    except AttributeError:
        return False


def _user_org_ids(user) -> set:
    """Collect every organization id the user can act on."""
    if not user:
        return set()
    ids = set()
    try:
        for org in user.get_all_organizations():
            if isinstance(org, dict):
                oid = org.get('id')
            else:
                oid = getattr(org, 'id', None)
            if oid is not None:
                ids.add(oid)
    except Exception:
        pass
    if getattr(user, 'organization_id', None):
        ids.add(user.organization_id)
    return ids


def _product_org_ids(product) -> set:
    """Collect every organization id a product belongs to."""
    if product is None:
        return set()
    ids = set()
    try:
        for org in product.organizations.all():
            if getattr(org, 'id', None) is not None:
                ids.add(org.id)
    except Exception:
        pass
    if getattr(product, 'organization_id', None):
        ids.add(product.organization_id)
    return ids


def current_user():
    """Return the currently authenticated ``User`` or ``None``.

    Imported lazily to avoid circular imports with ``app.models``.
    """
    user_id = session.get('user_id')
    if not user_id:
        return None
    from app.models import User
    return User.query.get(user_id)


def user_can_access_product(user, product, *, write: bool = False) -> bool:
    """Single source of truth for product-level authorization.

    Both read and write use the same org-membership rule. Multi-org MSSP
    analysts can write to any org they belong to — fixes the H-1 asymmetry
    where PUT only allowed the user's primary organization.
    """
    if not user or product is None:
        return False
    if _super_admin_unrestricted(user):
        return True
    user_ids = _user_org_ids(user)
    if not user_ids:
        return False
    return bool(user_ids & _product_org_ids(product))


def user_can_access_org(user, organization_id: Optional[int], *, write: bool = False) -> bool:
    """Check if a user can access a specific organization scope."""
    if not user or organization_id is None:
        return False
    if _super_admin_unrestricted(user):
        return True
    return organization_id in _user_org_ids(user)


def user_can_access_asset(user, asset, *, write: bool = False) -> bool:
    """Check asset-level authorization by organization id."""
    if not user or asset is None:
        return False
    if _super_admin_unrestricted(user):
        return True
    return user_can_access_org(user, getattr(asset, 'organization_id', None), write=write)


def user_can_access_vuln_match(user, match, *, write: bool = False) -> bool:
    """Check VulnerabilityMatch authorization via its product."""
    if not user or match is None:
        return False
    if _super_admin_unrestricted(user):
        return True
    product = getattr(match, 'product', None)
    if product is not None:
        return user_can_access_product(user, product, write=write)
    return user_can_access_org(user, getattr(match, 'organization_id', None), write=write)


def user_can_access_container(user, container, *, write: bool = False) -> bool:
    """Check container/image authorization by organization id."""
    if not user or container is None:
        return False
    if _super_admin_unrestricted(user):
        return True
    return user_can_access_org(user, getattr(container, 'organization_id', None), write=write)


def accessible_org_ids(user) -> Iterable[int]:
    """Return the set of org ids the caller can access.

    Returns an empty set for unauthenticated users and an all-inclusive
    sentinel (``None``) for unrestricted super admins so callers can skip
    filtering.
    """
    if not user:
        return set()
    if _super_admin_unrestricted(user):
        return None
    return _user_org_ids(user)


__all__ = [
    'user_can_access_product',
    'user_can_access_org',
    'user_can_access_asset',
    'user_can_access_vuln_match',
    'user_can_access_container',
    'accessible_org_ids',
    'current_user',
]
