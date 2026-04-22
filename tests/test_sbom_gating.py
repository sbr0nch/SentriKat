"""
Regression tests for SBOM export licensing/plan gating.

Locks in the public pricing matrix (landing/src/components/Pricing.astro):

    Free     — no SBOM
    Starter  — no SBOM
    Pro      — ✅ SBOM (CycloneDX / SPDX / STIX)
    Business — ✅ SBOM
    Enterprise — ✅ SBOM

Origin of the bug this file pins: the ``@requires_professional('SBOM Export')``
decorator in ``app/sbom_export.py`` mapped to the feature key ``sbom_export``
in ``app/licensing.py``, but the key was missing from every plan's features
JSON in ``DEFAULT_PLANS``. Every non-super-admin user therefore hit HTTP 403
on all three SBOM endpoints, regardless of plan.
"""

from unittest.mock import patch

import pytest


SBOM_ENDPOINTS = (
    '/api/sbom/export/cyclonedx',
    '/api/sbom/export/spdx',
    '/api/sbom/export/stix21',
)


def _setup_tenant_on_plan(app, client, plan_name):
    """Create an org + user + active subscription on ``plan_name`` and
    return a test client whose session is already logged in.
    """
    from app import db
    from app.models import (
        SubscriptionPlan, Subscription, Organization, User,
    )
    from werkzeug.security import generate_password_hash

    with app.app_context():
        if SubscriptionPlan.query.count() == 0:
            SubscriptionPlan.seed_default_plans()
        plan = SubscriptionPlan.query.filter_by(name=plan_name).first()
        assert plan is not None, f"Plan {plan_name!r} missing from seeds"

        org = Organization(
            name=f'sbom-{plan_name}-org',
            display_name=f'SBOM {plan_name} Org',
            active=True,
        )
        db.session.add(org)
        db.session.flush()

        user = User(
            username=f'sbom-{plan_name}',
            email=f'sbom-{plan_name}@test.local',
            password_hash=generate_password_hash('pw'),
            role='org_admin',
            organization_id=org.id,
            is_active=True,
            auth_type='local',
        )
        db.session.add(user)
        db.session.flush()

        sub = Subscription(
            organization_id=org.id,
            plan_id=plan.id,
            status='active',
        )
        db.session.add(sub)
        db.session.commit()
        org_id = org.id
        user_id = user.id

    with client.session_transaction() as sess:
        sess['user_id'] = user_id
        sess['organization_id'] = org_id
        sess['_fresh'] = True
    return client


class TestSbomGatingPerPlan:
    """One test per (plan, endpoint) pair so failures name the exact combo."""

    @pytest.mark.parametrize('endpoint', SBOM_ENDPOINTS)
    @pytest.mark.parametrize('plan_name', ['free', 'starter'])
    def test_sbom_gated_off_on_free_and_starter(
        self, client, app, plan_name, endpoint,
    ):
        with patch('app.saas.is_saas_mode', return_value=True):
            _setup_tenant_on_plan(app, client, plan_name)

            resp = client.get(endpoint)
            assert resp.status_code == 403, (
                f"{plan_name} should not have SBOM export "
                f"(status={resp.status_code}, body={resp.get_data(as_text=True)[:200]})"
            )
            body = resp.get_json() or {}
            assert body.get('feature_required') == 'sbom_export'
            assert body.get('upgrade_required') is True

    @pytest.mark.parametrize('endpoint', SBOM_ENDPOINTS)
    @pytest.mark.parametrize('plan_name', ['pro', 'business', 'enterprise'])
    def test_sbom_allowed_on_pro_and_above(
        self, client, app, plan_name, endpoint,
    ):
        with patch('app.saas.is_saas_mode', return_value=True):
            _setup_tenant_on_plan(app, client, plan_name)

            resp = client.get(endpoint)
            # A 403 with upgrade_required=True is the exact regression we
            # are pinning. Any other outcome (200 on an empty-product org,
            # or even a 500 from downstream rendering) is outside the scope
            # of plan gating — but "your plan does not include this" must
            # not happen on Pro or above.
            if resp.status_code == 403:
                body = resp.get_json() or {}
                assert body.get('upgrade_required') is not True, (
                    f"{plan_name} wrongly denied SBOM export: {body}"
                )
            else:
                assert resp.status_code != 403


class TestSbomPlanSeedContract:
    """Directly assert the shape of ``DEFAULT_PLANS`` so a future refactor
    of the seed list can't silently drop ``sbom_export`` again without
    tripping a test."""

    def test_default_plans_declare_sbom_export_explicitly(self, app):
        import json
        from app.models import SubscriptionPlan

        expected = {
            'free': False,
            'starter': False,
            'pro': True,
            'business': True,
            'enterprise': True,
        }
        seen = {}
        for p in SubscriptionPlan.DEFAULT_PLANS:
            features = json.loads(p['features'])
            assert 'sbom_export' in features, (
                f"Plan {p['name']!r} missing sbom_export flag in seeds"
            )
            seen[p['name']] = features['sbom_export']
        assert seen == expected, (
            f"sbom_export flag mismatch against pricing matrix: {seen}"
        )

    def test_seeded_plans_match_default_plans(self, app):
        """After ``seed_default_plans()`` the DB rows must reflect the
        DEFAULT_PLANS dict — this catches a class of bugs where a feature
        was added to the list but the seeder silently ignored it on
        re-boot of an already-populated DB."""
        from app.models import SubscriptionPlan

        with app.app_context():
            SubscriptionPlan.seed_default_plans()

            for plan in SubscriptionPlan.query.all():
                features = plan.get_features()
                expected = {
                    'free': False, 'starter': False,
                    'pro': True, 'business': True, 'enterprise': True,
                }.get(plan.name)
                if expected is None:
                    continue  # custom plan, not in the matrix
                assert features.get('sbom_export') is expected, (
                    f"DB plan {plan.name!r} has sbom_export={features.get('sbom_export')!r}, "
                    f"expected {expected!r}"
                )
