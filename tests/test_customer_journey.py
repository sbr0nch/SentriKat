"""
End-to-end customer journey tests.

These tests walk through the same sequence the SentriKat-web license-server
drives on behalf of a real user, so that any break between the website
signup form and the admin-portal add-on toggles is caught by CI instead of
surfacing as an HTTP 500 in the admin UI.

The chain being verified:

    portal.sentrikat.com (Astro admin page)
            │
            ▼  POST /api/v1/admin/saas/tenants/{org_id}/addon
    license-server (SentriKat-web repo, FastAPI)
            │
            ▼  POST /api/provision/addon  (shared X-Provision-Key)
    app.sentrikat.com (this repo, Flask)

The license-server is a thin forwarder — all of the business logic that can
return 5xx lives in this repo's ``/api/provision/*`` endpoints, which is
what these tests exercise directly.
"""

from unittest.mock import patch


def _enable_provision_mode():
    """Patch to enable SaaS-mode provisioning with a known test key."""
    return (
        patch('app.provision_api._PROVISION_KEY', 'test-key'),
        patch('app.provision_api.is_saas_mode', return_value=True),
    )


def _seed_plans(app):
    with app.app_context():
        from app.models import SubscriptionPlan
        if SubscriptionPlan.query.count() == 0:
            SubscriptionPlan.seed_default_plans()


class TestFullEarlyAccessJourney:
    """Verify the full EA signup → admin-toggle path for a realistic tenant.

    The shape of the request bodies mirrors the license-server bridge
    (SentriKat-web ``license-server/app/api/admin.py::toggle_saas_tenant_addon``)
    which forwards ``organization_id`` as a **string** path segment and
    sends ``addon`` (not ``addon_name``) with ``action`` derived from the
    portal's ``enabled`` boolean. Both spellings MUST be accepted so the
    two services can be deployed independently.
    """

    HEADERS = {'X-Provision-Key': 'test-key'}

    def test_ea_signup_then_enable_and_disable_compliance_pack(self, client, app):
        """Full happy path — the exact sequence the UI triggers."""
        key_patch, mode_patch = _enable_provision_mode()
        with key_patch, mode_patch:
            _seed_plans(app)

            # 1. Website signup — license-server forwards this to /api/provision
            #    with NO Stripe IDs (EA path).
            resp = client.post('/api/provision', json={
                'email': 'contact.sotadenis@gmail.com',
                'full_name': 'Denis Sota',
                'company_name': 'Sberlerch SPA',
                'plan_name': 'enterprise',
                'trial_days': 14,
            }, headers=self.HEADERS)
            assert resp.status_code == 201, resp.get_data(as_text=True)[:300]
            tenant = resp.get_json()['tenant']
            org_id = tenant['organization_id']
            assert tenant['billing_mode'] == 'ea'  # EA path: no Stripe IDs

            # 2. Admin clicks "Enable Compliance Pack" — license-server
            #    forwards with `addon` spelling + `action: "enable"` and
            #    ``organization_id`` as a STRING (FastAPI path param).
            resp = client.post('/api/provision/addon', json={
                'organization_id': str(org_id),
                'addon': 'compliance_pack',
                'action': 'enable',
            }, headers=self.HEADERS)
            assert resp.status_code == 200, resp.get_data(as_text=True)[:300]
            body = resp.get_json()
            assert body['success'] is True
            assert body['addon_name'] == 'compliance_pack'
            assert body['action'] == 'enable'
            assert body['subscription']['addons']['compliance_pack'] is True

            # 3. Admin disables it again.
            resp = client.post('/api/provision/addon', json={
                'organization_id': str(org_id),
                'addon': 'compliance_pack',
                'action': 'disable',
            }, headers=self.HEADERS)
            assert resp.status_code == 200
            assert resp.get_json()['subscription']['addons']['compliance_pack'] is False

    def test_addon_endpoint_accepts_int_org_id(self, client, app):
        """The license-server sends ``organization_id`` as a string; the
        older direct-callers (and our own backfill scripts) send an int.
        Both must work so we don't break either side during a rolling
        deploy."""
        key_patch, mode_patch = _enable_provision_mode()
        with key_patch, mode_patch:
            _seed_plans(app)

            resp = client.post('/api/provision', json={
                'email': 'int-id@test.local',
                'full_name': 'Int User',
                'company_name': 'Int Corp',
                'plan_name': 'pro',
            }, headers=self.HEADERS)
            org_id = resp.get_json()['tenant']['organization_id']

            resp = client.post('/api/provision/addon', json={
                'organization_id': org_id,  # int, not string
                'addon_name': 'compliance_pack',
                'action': 'enable',
            }, headers=self.HEADERS)
            assert resp.status_code == 200

    def test_addon_endpoint_accepts_addons_plural_alias(self, client, app):
        """Route accepts both ``/addon`` and ``/addons`` — the portal uses
        the singular, some internal tools the plural. A regression here
        would break the portal silently."""
        key_patch, mode_patch = _enable_provision_mode()
        with key_patch, mode_patch:
            _seed_plans(app)

            resp = client.post('/api/provision', json={
                'email': 'plural@test.local',
                'full_name': 'Plural User',
                'company_name': 'Plural Corp',
                'plan_name': 'starter',
            }, headers=self.HEADERS)
            org_id = resp.get_json()['tenant']['organization_id']

            resp = client.post('/api/provision/addons', json={
                'organization_id': str(org_id),
                'addon': 'compliance_pack',
                'action': 'enable',
            }, headers=self.HEADERS)
            assert resp.status_code == 200


class TestAddonEndpointRobustness:
    """Regression tests for the 500 we saw on production tenant id=5.

    The original endpoint committed the add-on change and THEN serialised
    ``subscription.to_dict()`` inside the same try/except. A serialisation
    failure therefore:

    1. Left the add-on flag set on disk (commit already succeeded).
    2. Called ``db.session.rollback()`` on an already-committed session,
       which is a no-op but is confusingly logged.
    3. Returned 500 to the caller.

    Retrying gave the same 500 forever (serialisation deterministic), and
    the admin had no way to tell whether the flag was actually applied.
    These tests pin the fixed behaviour: commit is authoritative, response
    rendering cannot poison it.
    """

    HEADERS = {'X-Provision-Key': 'test-key'}

    def test_addon_toggle_survives_corrupted_addons_json(self, client, app):
        """Pre-existing invalid JSON in Subscription.addons must not 500."""
        key_patch, mode_patch = _enable_provision_mode()
        with key_patch, mode_patch:
            _seed_plans(app)

            resp = client.post('/api/provision', json={
                'email': 'corrupt@test.local',
                'full_name': 'Corrupt User',
                'company_name': 'Corrupt Corp',
                'plan_name': 'enterprise',
            }, headers=self.HEADERS)
            org_id = resp.get_json()['tenant']['organization_id']

            with app.app_context():
                from app import db
                from app.models import Subscription
                sub = Subscription.query.filter_by(organization_id=org_id).first()
                sub.addons = 'not-valid-json{{{'
                db.session.commit()

            resp = client.post('/api/provision/addon', json={
                'organization_id': str(org_id),
                'addon': 'compliance_pack',
                'action': 'enable',
            }, headers=self.HEADERS)
            assert resp.status_code == 200
            # Subsequent read should show a clean parsed dict with the flag set.
            assert resp.get_json()['subscription']['addons'] == {'compliance_pack': True}

    def test_addon_toggle_survives_orphan_plan_id(self, client, app):
        """If ``subscriptions.plan_id`` points to a row that no longer
        exists (e.g. a plan was renamed and the old id was removed),
        ``self.plan`` is None and to_dict() must not blow up."""
        key_patch, mode_patch = _enable_provision_mode()
        with key_patch, mode_patch:
            _seed_plans(app)

            resp = client.post('/api/provision', json={
                'email': 'orphan@test.local',
                'full_name': 'Orphan User',
                'company_name': 'Orphan Corp',
                'plan_name': 'pro',
            }, headers=self.HEADERS)
            org_id = resp.get_json()['tenant']['organization_id']

            with app.app_context():
                from app import db
                from sqlalchemy import text
                # Point the subscription at a plan id that does not exist.
                # SQLite does not enforce FKs by default, which matches
                # a production scenario where plans were reseeded with
                # different ids after a manual intervention.
                db.session.execute(
                    text('UPDATE subscriptions SET plan_id = 9999 '
                         'WHERE organization_id = :oid'),
                    {'oid': org_id},
                )
                db.session.commit()

            resp = client.post('/api/provision/addon', json={
                'organization_id': str(org_id),
                'addon': 'compliance_pack',
                'action': 'enable',
            }, headers=self.HEADERS)
            assert resp.status_code == 200
            body = resp.get_json()
            assert body['subscription']['addons']['compliance_pack'] is True
            # plan is explicitly None rather than raising.
            assert body['subscription']['plan'] is None

    def test_addon_flag_persists_even_if_response_serialisation_fails(
        self, client, app,
    ):
        """Belt-and-braces: if ``Subscription.to_dict()`` raises AFTER the
        commit, the add-on flag must still be set on disk and the endpoint
        must still answer 200. The admin UI can then re-read state on its
        next poll; silently losing the write would be much worse.
        """
        key_patch, mode_patch = _enable_provision_mode()
        with key_patch, mode_patch:
            _seed_plans(app)

            resp = client.post('/api/provision', json={
                'email': 'serialize@test.local',
                'full_name': 'Serialize User',
                'company_name': 'Serialize Corp',
                'plan_name': 'business',
            }, headers=self.HEADERS)
            org_id = resp.get_json()['tenant']['organization_id']

            # Force to_dict() to blow up for this one request.
            from app.models import Subscription

            def _boom(self):  # pragma: no cover - stand-in for a real bug
                raise RuntimeError('simulated serialisation failure')

            with patch.object(Subscription, 'to_dict', _boom):
                resp = client.post('/api/provision/addon', json={
                    'organization_id': str(org_id),
                    'addon': 'compliance_pack',
                    'action': 'enable',
                }, headers=self.HEADERS)

            # The add-on change IS authoritative even though rendering failed.
            assert resp.status_code == 200
            body = resp.get_json()
            assert body['success'] is True
            assert body['addon_name'] == 'compliance_pack'
            assert body['action'] == 'enable'
            # When rendering fails we report the committed state without the
            # full serialised subscription — the client can re-fetch.
            assert body.get('subscription') in (None, {}) or \
                body.get('subscription_serialization_error') is not None

            # And the flag is really on disk.
            with app.app_context():
                sub = Subscription.query.filter_by(organization_id=org_id).first()
                assert sub.get_addons().get('compliance_pack') is True
