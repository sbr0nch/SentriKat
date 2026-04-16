"""Regression test: enforce that resource endpoints use the central authz helper.

If a new endpoint touching ``<int:product_id>`` is added without calling one of
the ``app.authz`` helpers (or one of the known pre-existing inline guards),
this test fails. Prevents IDOR regressions of the H-1 class where isolation
checks were reimplemented per-endpoint and drifted (GET vs PUT).
"""
from __future__ import annotations

import inspect

import pytest


# Endpoints intentionally excluded from the authz-helper requirement.
# They either do not need per-resource isolation (write-then-fetch by id on
# just-created rows), or they enforce the check via a different documented
# mechanism. Keep this list as small as possible.
_AUTHZ_EXCLUDED_ENDPOINTS: set[str] = set()


def _view_source(app, endpoint: str) -> str:
    view = app.view_functions.get(endpoint)
    if view is None:
        return ''
    try:
        return inspect.getsource(view)
    except (OSError, TypeError):
        return ''


def test_product_id_endpoints_enforce_authz(app):
    """Every ``<int:product_id>`` view must reference the central helper."""
    offenders: list[str] = []
    for rule in app.url_map.iter_rules():
        if '<int:product_id>' not in str(rule.rule):
            continue
        endpoint = rule.endpoint
        if endpoint in _AUTHZ_EXCLUDED_ENDPOINTS:
            continue
        source = _view_source(app, endpoint)
        if not source:
            continue
        # Accept either the new helper, a module-level wrapper calling it, or
        # the existing super_admin bypass paired with explicit org filtering.
        markers = (
            'user_can_access_product',
            'accessible_org_ids',
            'user_can_access_vuln_match',
            'user_can_access_asset',
            'user_can_access_container',
            # Legacy but still safe inline checks — these iterate
            # get_all_organizations() AND compare against product_org_ids.
            'get_all_organizations',
            '_authorize_container_vuln',
        )
        if not any(m in source for m in markers):
            offenders.append(f"{endpoint} @ {rule.rule}")

    assert not offenders, (
        "Endpoints touching <int:product_id> without using the authz helper "
        "(this is how H-1 happened — GET/PUT drifted):\n  - "
        + '\n  - '.join(offenders)
    )


def test_authz_helper_resolves_multi_org_user():
    """Sanity check: user_can_access_product uses all orgs, not just primary."""
    from app.authz import user_can_access_product

    class FakeOrg:
        def __init__(self, oid):
            self.id = oid

    class FakeProduct:
        def __init__(self, org_ids, primary=None):
            self._orgs = [FakeOrg(o) for o in org_ids]
            self.organization_id = primary

        @property
        def organizations(self):
            class _Q:
                def __init__(self, orgs):
                    self._orgs = orgs

                def all(self):
                    return self._orgs

            return _Q(self._orgs)

    class FakeUser:
        def __init__(self, primary_org, extra_orgs=()):
            self.organization_id = primary_org
            self._extra = list(extra_orgs)

        def is_super_admin(self):
            return False

        def get_all_organizations(self):
            return [{'id': self.organization_id}] + [
                {'id': o} for o in self._extra
            ]

    user = FakeUser(primary_org=1, extra_orgs=[2, 3])
    product_in_secondary = FakeProduct(org_ids=[2])

    # Historic bug: PUT used only primary org — secondary-org access denied.
    assert user_can_access_product(user, product_in_secondary, write=True)
    assert user_can_access_product(user, product_in_secondary, write=False)

    product_elsewhere = FakeProduct(org_ids=[99])
    assert not user_can_access_product(user, product_elsewhere, write=True)
    assert not user_can_access_product(user, product_elsewhere, write=False)


def test_authz_helper_handles_none_inputs():
    from app.authz import (
        user_can_access_product,
        user_can_access_asset,
        user_can_access_org,
    )

    assert user_can_access_product(None, None) is False
    assert user_can_access_asset(None, None) is False
    assert user_can_access_org(None, None) is False
