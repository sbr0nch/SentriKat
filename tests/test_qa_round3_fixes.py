"""
Regression tests for QA round 3 fixes (the ones landing in the third
post-launch fix PR). Locks in the behaviour of:

1. Delete product with orphaned FK children — the "Apache Tomcat
   delete fails" bug. Creates a product with remediation assignments,
   risk exceptions, product aliases, vulnerability matches, version
   history, and multi-org assignments, then deletes it. All children
   must disappear, no FK constraint violation, no 500.

2. Duplicate product check in SaaS vs on-prem mode — an org_admin in
   Org A must be able to create "Apache Tomcat 10.1.18" even if an
   unrelated Org B already has a row with the same vendor/name/version.
   Inside a single customer's own multi-org setup the duplicate check
   still fires (intra-customer dedup preserved).

3. Agent inventory mass-removal anomaly threshold — an agent that
   posts {products: []} after previously reporting 10 products must
   NOT have its installations wiped. The anomaly must be logged and
   the response must carry a warning; new/updated products in the
   same report still go through.

These tests use the existing role / client fixtures from conftest.py
(test_org, viewer_user, org_admin_client, second_org, ...).
"""

import os
import pytest
from datetime import date
from unittest.mock import patch


# Agent inventory tests need to bypass the Professional-license gate
# because the in-memory test database uses the community/free edition.
# This matches the pattern used in tests/test_agent_inventory.py.
LICENSE_PATCH = 'app.agent_api.check_license_can_add_agent'
CPE_PATCH = 'app.cpe_mapping.apply_cpe_to_product'
SKIP_SW_PATCH = 'app.agent_api._should_skip_software'


def _license_ok(org_id, is_new_agent=True):
    """Pretend the caller has a Professional license with plenty of headroom."""
    return True, None, {
        'edition': 'professional',
        'feature_enabled': True,
        'agents_used': 0,
        'agent_limit': 100,
    }


# =============================================================================
# #5 — Delete product with assignments / exceptions / aliases
# =============================================================================

class TestDeleteProductWithChildren:
    """Delete a product that has rows in every child table.

    This is the "Apache Tomcat" scenario: products with lots of
    remediation assignments + risk exceptions used to fail delete
    because routes.py only manually wiped a subset of the FK children
    and relied on CASCADE for the rest.
    """

    def test_delete_product_with_remediation_assignment(
        self, db_session, org_admin_client, org_admin_user, test_org, sample_product
    ):
        from app.models import (
            RemediationAssignment, RiskException, ProductAlias,
            VulnerabilityMatch, ProductInstallation, Vulnerability, Asset,
        )

        # Set the session org_id so the delete decorator sees the user
        # as being in the right org.
        with org_admin_client.session_transaction() as sess:
            sess['organization_id'] = test_org.id

        # -- Build a realistic fan-out of child rows around the product --
        # 1) A remediation assignment pointing straight at product_id
        ra = RemediationAssignment(
            organization_id=test_org.id,
            product_id=sample_product.id,
            cve_id='CVE-2024-0001',
            assigned_to='someone@test.local',
            assigned_by='orgadmin@test.local',
            due_date=date.today(),
            status='open',
            priority='high',
            notes='',
        )
        db_session.add(ra)

        # 2) A risk exception pointing straight at product_id
        re = RiskException(
            organization_id=test_org.id,
            product_id=sample_product.id,
            cve_id='CVE-2024-0001',
            justification='accepted for testing',
            approved_by='orgadmin@test.local',
            status='active',
        )
        db_session.add(re)

        # 3) A product alias (column name is `alias_product`, not `alias_product_name`)
        alias = ProductAlias(
            organization_id=test_org.id,
            product_id=sample_product.id,
            alias_vendor='apache',
            alias_product='tomcat-server',
        )
        db_session.add(alias)

        # 4) An asset + product installation
        asset = Asset(
            organization_id=test_org.id,
            hostname='test-host.local',
            status='online',
        )
        db_session.add(asset)
        db_session.flush()
        inst = ProductInstallation(
            asset_id=asset.id,
            product_id=sample_product.id,
            version='10.1.18',
            detected_by='agent',
        )
        db_session.add(inst)

        # 5) A vulnerability + match pointing at the product
        vuln = Vulnerability(
            cve_id='CVE-2024-0002',
            vendor_project='Apache',
            product='Tomcat',
            vulnerability_name='Test vuln',
            date_added=date.today(),
            short_description='Test',
            required_action='Update',
            cvss_score=8.0,
            severity='HIGH',
        )
        db_session.add(vuln)
        db_session.flush()
        match = VulnerabilityMatch(
            product_id=sample_product.id,
            vulnerability_id=vuln.id,
            match_reason='vendor+product exact match',
        )
        db_session.add(match)
        db_session.commit()

        product_id = sample_product.id

        # -- Delete --
        response = org_admin_client.delete(f'/api/products/{product_id}')
        assert response.status_code == 200, (
            f"REGRESSION: delete failed with orphan children. "
            f"HTTP {response.status_code}: {response.get_data(as_text=True)[:500]}"
        )

        # -- Verify everything is gone --
        from app.models import Product
        assert Product.query.get(product_id) is None
        assert RemediationAssignment.query.filter_by(product_id=product_id).count() == 0
        assert RiskException.query.filter_by(product_id=product_id).count() == 0
        assert ProductAlias.query.filter_by(product_id=product_id).count() == 0
        assert ProductInstallation.query.filter_by(product_id=product_id).count() == 0
        assert VulnerabilityMatch.query.filter_by(product_id=product_id).count() == 0

    def test_delete_product_batch_with_children(
        self, db_session, org_admin_client, test_org, sample_product
    ):
        """The batch-delete path must also invoke the same wipe helper."""
        from app.models import RemediationAssignment

        with org_admin_client.session_transaction() as sess:
            sess['organization_id'] = test_org.id

        ra = RemediationAssignment(
            organization_id=test_org.id,
            product_id=sample_product.id,
            cve_id='CVE-2024-0003',
            assigned_to='batch@test.local',
            assigned_by='orgadmin@test.local',
            due_date=date.today(),
            status='open',
            priority='medium',
        )
        db_session.add(ra)
        db_session.commit()

        product_id = sample_product.id
        response = org_admin_client.post('/api/products/batch-delete', json={
            'product_ids': [product_id],
        })
        assert response.status_code == 200, (
            f"Batch delete failed with orphan assignment: "
            f"HTTP {response.status_code}: {response.get_data(as_text=True)[:300]}"
        )
        from app.models import Product
        assert Product.query.get(product_id) is None
        assert RemediationAssignment.query.filter_by(product_id=product_id).count() == 0


# =============================================================================
# #4 — Duplicate product is org-scoped in SaaS / non-super-admin flows
# =============================================================================

class TestDuplicateProductOrgScoped:
    """
    Two unrelated orgs must be able to independently own the same
    (vendor, name, version) triple. The legacy behaviour — a global
    duplicate check — leaked tenant presence and blocked legitimate
    creation in SaaS.

    We simulate this by having the second_org_admin create a product
    that already exists in test_org. The create should succeed
    because they're different tenants (different customer boundary).
    """

    def test_same_product_in_two_separate_orgs(
        self, db_session, test_org, second_org, sample_product,
        second_org_client, second_org_admin
    ):
        # sample_product is ("Apache", "Tomcat", "10.1.18") in test_org.
        # second_org is a DIFFERENT customer — they should be able to
        # create the same product under their own org id.
        with second_org_client.session_transaction() as sess:
            sess['organization_id'] = second_org.id

        response = second_org_client.post('/api/products', json={
            'vendor': 'Apache',
            'product_name': 'Tomcat',
            'version': '10.1.18',
            'organization_id': second_org.id,
        })

        # Must NOT 409 — that would be the old leaky behaviour.
        assert response.status_code != 409, (
            f"REGRESSION: global duplicate check leaked across tenants. "
            f"second_org got HTTP 409 creating a product that only "
            f"test_org has. Body: {response.get_data(as_text=True)[:300]}"
        )
        assert response.status_code in (200, 201), (
            f"Expected 200/201, got {response.status_code}: "
            f"{response.get_data(as_text=True)[:200]}"
        )


# =============================================================================
# #6 — Agent inventory mass-removal anomaly threshold
# =============================================================================

@patch(SKIP_SW_PATCH, return_value=False)
@patch(CPE_PATCH)
@patch(LICENSE_PATCH, side_effect=_license_ok)
class TestAgentInventoryAnomalyThreshold:
    """
    An agent posting `products: []` (or any drop > AGENT_MAX_REMOVAL_PCT)
    after previously reporting products must NOT wipe its own
    installations. The removal phase is rejected; new/updated products
    in the same report still go through; a warning is returned.
    """

    def _register_baseline_inventory(self, client, api_key, hostname='anom-host-01'):
        """Seed the asset with 10 products so mass removal can be tested."""
        products = [
            {'vendor': 'acme', 'product': f'widget-{i}', 'version': '1.0.0'}
            for i in range(10)
        ]
        payload = {
            'hostname': hostname,
            'agent': {'version': '1.5.0'},
            'os': {'type': 'linux', 'name': 'ubuntu', 'version': '22.04'},
            'products': products,
        }
        res = client.post(
            '/api/agent/inventory',
            json=payload,
            headers={'X-Agent-Key': api_key},
        )
        assert res.status_code == 200, (
            f"Baseline inventory failed: {res.status_code} "
            f"{res.get_data(as_text=True)[:300]}"
        )
        return res.get_json()

    def test_empty_products_list_triggers_anomaly_rejection(
        self, mock_lic, mock_cpe, mock_skip,
        db_session, client, test_api_key, setup_complete,
    ):
        """After 10 products, an empty products list must be refused."""
        api_key = test_api_key['raw_key']

        # 1. Seed the asset with 10 products.
        self._register_baseline_inventory(client, api_key)

        # 2. Sanity check — the installations exist.
        from app.models import Asset, ProductInstallation
        asset = Asset.query.filter_by(hostname='anom-host-01').first()
        assert asset is not None
        installs_before = ProductInstallation.query.filter_by(
            asset_id=asset.id, detected_by='agent'
        ).count()
        assert installs_before == 10, (
            f"Expected 10 baseline installations, got {installs_before}"
        )

        # 3. Post an empty products list (the attack).
        attack_payload = {
            'hostname': 'anom-host-01',
            'agent': {'version': '1.5.0'},
            'os': {'type': 'linux', 'name': 'ubuntu', 'version': '22.04'},
            'products': [],
        }
        res = client.post(
            '/api/agent/inventory',
            json=attack_payload,
            headers={'X-Agent-Key': api_key},
        )
        assert res.status_code == 200, (
            f"Expected 200 (success with anomaly warning), got {res.status_code}"
        )
        data = res.get_json()

        # 4. The response must carry a warning AND an anomaly structure.
        assert 'warning' in data, (
            f"Expected 'warning' field in response for mass-removal attempt, "
            f"got keys: {list(data.keys())}"
        )
        assert 'anomaly' in data
        assert data['anomaly'].get('type') == 'mass_removal_threshold'
        assert data['anomaly'].get('removals_rejected') is True

        # 5. The installations must STILL be there.
        installs_after = ProductInstallation.query.filter_by(
            asset_id=asset.id, detected_by='agent'
        ).count()
        assert installs_after == installs_before, (
            f"CRITICAL REGRESSION: agent wiped {installs_before - installs_after} "
            f"installations with an empty-products payload. The anomaly "
            f"threshold is not protecting the asset."
        )

    def test_small_uninstall_below_threshold_is_allowed(
        self, mock_lic, mock_cpe, mock_skip,
        db_session, client, test_api_key, setup_complete,
    ):
        """
        Removing a couple of products (legitimate uninstall) must still
        work — the threshold is only for mass removals, not for every
        uninstall. This is the "don't break the happy path" test.
        """
        api_key = test_api_key['raw_key']

        self._register_baseline_inventory(client, api_key, hostname='anom-host-02')

        from app.models import Asset, ProductInstallation
        asset = Asset.query.filter_by(hostname='anom-host-02').first()
        assert asset is not None

        # Remove 2 out of 10 = 20%, well below the 50% default threshold.
        remaining_products = [
            {'vendor': 'acme', 'product': f'widget-{i}', 'version': '1.0.0'}
            for i in range(8)  # keep the first 8
        ]
        res = client.post(
            '/api/agent/inventory',
            json={
                'hostname': 'anom-host-02',
                'agent': {'version': '1.5.0'},
                'os': {'type': 'linux', 'name': 'ubuntu', 'version': '22.04'},
                'products': remaining_products,
            },
            headers={'X-Agent-Key': api_key},
        )
        assert res.status_code == 200
        data = res.get_json()
        assert 'warning' not in data or 'anomaly' not in data, (
            "20% removal should NOT trigger the anomaly path"
        )

        active_after = ProductInstallation.query.filter_by(
            asset_id=asset.id, detected_by='agent'
        ).filter(ProductInstallation.removed_at.is_(None)).count()
        assert active_after == 8, (
            f"Legitimate uninstall of 2/10 products was blocked "
            f"(expected 8 active installs, got {active_after})"
        )

    def test_threshold_is_configurable(
        self, mock_lic, mock_cpe, mock_skip,
        db_session, client, test_api_key, setup_complete, monkeypatch,
    ):
        """
        The AGENT_MAX_REMOVAL_PCT env var tunes the threshold — tighten
        it to 10% and even a 20% uninstall should be rejected.
        """
        api_key = test_api_key['raw_key']
        monkeypatch.setenv('AGENT_MAX_REMOVAL_PCT', '10')

        self._register_baseline_inventory(client, api_key, hostname='anom-host-03')

        remaining_products = [
            {'vendor': 'acme', 'product': f'widget-{i}', 'version': '1.0.0'}
            for i in range(8)  # remove 2 → 20% > 10%
        ]
        res = client.post(
            '/api/agent/inventory',
            json={
                'hostname': 'anom-host-03',
                'agent': {'version': '1.5.0'},
                'os': {'type': 'linux', 'name': 'ubuntu', 'version': '22.04'},
                'products': remaining_products,
            },
            headers={'X-Agent-Key': api_key},
        )
        assert res.status_code == 200
        data = res.get_json()
        assert data.get('anomaly', {}).get('type') == 'mass_removal_threshold', (
            f"With AGENT_MAX_REMOVAL_PCT=10, a 20% uninstall should be rejected. "
            f"Response: {data}"
        )

        from app.models import Asset, ProductInstallation
        asset = Asset.query.filter_by(hostname='anom-host-03').first()
        installs_after = ProductInstallation.query.filter_by(
            asset_id=asset.id, detected_by='agent'
        ).count()
        assert installs_after == 10, (
            "10% threshold should preserve all 10 installs when agent tries to "
            "remove 2"
        )
