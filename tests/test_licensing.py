"""
Tests for the licensing system.
"""
import pytest
from unittest.mock import patch, MagicMock
from datetime import datetime, timedelta


class TestLicenseValidation:
    """Tests for license validation."""

    def test_community_license_limits(self, app):
        """Test demo license has correct limits."""
        from app.licensing import get_license

        with app.app_context():
            # Get license info (demo when no license installed)
            license_info = get_license()
            limits = license_info.get_effective_limits()

            # Demo edition includes 5 agents
            assert limits['max_agents'] == 5
            assert limits['max_organizations'] == 1
            assert license_info.edition == 'community'

    def test_license_info_structure(self, app):
        """Test license info has correct structure."""
        from app.licensing import get_license

        with app.app_context():
            license_info = get_license()

            # Check that license info has expected attributes
            assert hasattr(license_info, 'edition')
            assert hasattr(license_info, 'is_valid')
            assert hasattr(license_info, 'get_effective_limits')
            assert hasattr(license_info, 'is_professional')

    def test_license_limits_structure(self, app):
        """Test license limits have correct structure."""
        from app.licensing import get_license

        with app.app_context():
            license_info = get_license()
            limits = license_info.get_effective_limits()

            # Check that limits have expected keys
            assert 'max_agents' in limits
            assert 'max_organizations' in limits
            assert 'max_agent_api_keys' in limits


class TestAgentUsageTracking:
    """Tests for agent usage tracking."""

    def test_agent_count_tracking(self, app, db_session):
        """Test that agent counts are tracked correctly."""
        from app.models import Asset, Organization
        from app.licensing import get_agent_usage

        org = Organization(name='test', display_name='Test', active=True)
        db_session.add(org)
        db_session.flush()

        # Add some assets (using correct field names)
        for i in range(5):
            asset = Asset(
                hostname=f'server{i}.test.local',
                ip_address=f'10.0.0.{i}',
                asset_type='server',
                organization_id=org.id,
                active=True
            )
            db_session.add(asset)

        db_session.commit()

        with app.app_context():
            usage = get_agent_usage()

            assert usage['agents']['current'] == 5

    def test_server_client_breakdown(self, app, db_session):
        """Test server vs client breakdown in usage."""
        from app.models import Asset, Organization
        from app.licensing import get_agent_usage

        org = Organization(name='test', display_name='Test', active=True)
        db_session.add(org)
        db_session.flush()

        # Add servers
        for i in range(3):
            asset = Asset(
                hostname=f'server{i}.test.local',
                ip_address=f'10.0.0.{i}',
                asset_type='server',
                organization_id=org.id,
                active=True
            )
            db_session.add(asset)

        # Add workstations
        for i in range(5):
            asset = Asset(
                hostname=f'desktop{i}.test.local',
                ip_address=f'10.0.1.{i}',
                asset_type='workstation',
                organization_id=org.id,
                active=True
            )
            db_session.add(asset)

        db_session.commit()

        with app.app_context():
            usage = get_agent_usage()

            assert usage['agents']['current'] == 8

            # Check breakdown if available
            if 'breakdown' in usage:
                assert usage['breakdown']['servers'] == 3
                assert usage['breakdown']['clients'] == 5

    def test_weighted_units_calculation(self, app, db_session):
        """Test weighted unit calculation (servers=1.0, clients=0.5)."""
        from app.models import Asset, Organization
        from app.licensing import get_agent_usage

        org = Organization(name='test', display_name='Test', active=True)
        db_session.add(org)
        db_session.flush()

        # Add 2 servers (2 * 1.0 = 2.0 units)
        for i in range(2):
            asset = Asset(
                hostname=f'server{i}.test.local',
                ip_address=f'10.0.0.{i}',
                asset_type='server',
                organization_id=org.id,
                active=True
            )
            db_session.add(asset)

        # Add 4 workstations (4 * 0.5 = 2.0 units)
        for i in range(4):
            asset = Asset(
                hostname=f'desktop{i}.test.local',
                ip_address=f'10.0.1.{i}',
                asset_type='workstation',
                organization_id=org.id,
                active=True
            )
            db_session.add(asset)

        db_session.commit()

        with app.app_context():
            usage = get_agent_usage()

            if 'breakdown' in usage:
                # 2 servers * 1.0 + 4 clients * 0.5 = 4.0 weighted units
                expected_weighted = 2 * 1.0 + 4 * 0.5
                assert usage['breakdown']['weighted_units'] == expected_weighted


class TestFeatureGating:
    """Tests for professional feature gating."""

    def test_ldap_settings_requires_login(self, app, client, db_session):
        """Test LDAP settings endpoint requires authentication."""
        # Try to access LDAP settings without login
        response = client.get('/api/settings/ldap')

        # Should redirect to login or return 401
        assert response.status_code in [302, 401, 403]

    def test_admin_can_get_ldap_settings(self, app, client, db_session):
        """Test admin can access LDAP settings endpoint."""
        from app.models import User, Organization

        org = Organization(name='test', display_name='Test', active=True)
        db_session.add(org)
        db_session.flush()

        admin = User(
            username='admin',
            email='admin@test.com',
            role='super_admin',
            is_admin=True,
            is_active=True,
            auth_type='local',
            organization_id=org.id
        )
        admin.set_password('adminpass')
        db_session.add(admin)
        db_session.commit()

        # Login
        client.post('/api/auth/login', json={
            'username': 'admin',
            'password': 'adminpass'
        })

        # Get LDAP settings - may be restricted by license (Professional feature)
        response = client.get('/api/settings/ldap')

        # Should succeed or return 403 (license restriction)
        assert response.status_code in [200, 403]


class TestAgentLicenseModel:
    """Tests for the AgentLicense model."""

    def test_server_client_classification(self, app, db_session):
        """Test asset type classification."""
        from app.models import AgentLicense

        # Test server types
        assert 'server' in AgentLicense.SERVER_TYPES
        assert 'container' in AgentLicense.SERVER_TYPES

        # Test client types
        assert 'workstation' in AgentLicense.CLIENT_TYPES
        assert 'desktop' in AgentLicense.CLIENT_TYPES
        assert 'laptop' in AgentLicense.CLIENT_TYPES

    def test_weighted_units_method(self, app, db_session):
        """Test the get_weighted_units method."""
        from app.models import AgentLicense, Organization
        from datetime import date

        org = Organization(name='test', display_name='Test', active=True)
        db_session.add(org)
        db_session.flush()

        license_record = AgentLicense(
            organization_id=org.id,
            server_count=10,
            client_count=20
        )
        db_session.add(license_record)
        db_session.commit()

        # Default weights: servers=1.0, clients=0.5
        weighted = license_record.get_weighted_units()
        expected = 10 * 1.0 + 20 * 0.5  # 10 + 10 = 20
        assert weighted == expected

        # Custom weights
        weighted_custom = license_record.get_weighted_units(server_weight=2.0, client_weight=0.25)
        expected_custom = 10 * 2.0 + 20 * 0.25  # 20 + 5 = 25
        assert weighted_custom == expected_custom


class TestAgentLimit:
    """Tests for agent limit enforcement."""

    def test_check_agent_limit_function(self, app, db_session):
        """Test the check_agent_limit function."""
        from app.licensing import check_agent_limit

        with app.app_context():
            # Check agent limit
            allowed, limit, message = check_agent_limit()

            # Should return a tuple with allowed status, limit, and message
            assert isinstance(allowed, bool)
            assert isinstance(limit, int)
            assert message is None or isinstance(message, str)

    def test_get_agent_usage_structure(self, app, db_session):
        """Test get_agent_usage returns correct structure."""
        from app.licensing import get_agent_usage

        with app.app_context():
            usage = get_agent_usage()

            # Check structure
            assert 'agents' in usage
            assert 'current' in usage['agents']
            assert 'limit' in usage['agents']
            assert 'api_keys' in usage


class TestGlobalAgentLimitEnforcement:
    """Tests that agent limits are enforced globally across all organizations."""

    def test_limit_blocks_when_exceeded(self, app, db_session):
        """Create enough assets to hit the limit, then verify check_agent_limit returns (False, limit, message)."""
        from app.models import Asset, Organization
        from app.licensing import check_agent_limit

        org = Organization(name='limitorg', display_name='Limit Org', active=True)
        db_session.add(org)
        db_session.flush()

        # Community edition allows 5 agents - create exactly 5 to hit the limit
        for i in range(5):
            asset = Asset(
                hostname=f'agent{i}.limit.local',
                ip_address=f'10.1.0.{i}',
                asset_type='server',
                organization_id=org.id,
                active=True
            )
            db_session.add(asset)
        db_session.commit()

        with app.app_context():
            allowed, limit, message = check_agent_limit()
            assert allowed is False
            assert limit == 5
            assert message is not None
            assert isinstance(message, str)

    def test_limit_allows_within_bounds(self, app, db_session):
        """Fewer assets than limit returns (True, limit, None)."""
        from app.models import Asset, Organization
        from app.licensing import check_agent_limit

        org = Organization(name='boundsorg', display_name='Bounds Org', active=True)
        db_session.add(org)
        db_session.flush()

        # Create only 3 assets - well under the community limit of 5
        for i in range(3):
            asset = Asset(
                hostname=f'bounded{i}.test.local',
                ip_address=f'10.2.0.{i}',
                asset_type='server',
                organization_id=org.id,
                active=True
            )
            db_session.add(asset)
        db_session.commit()

        with app.app_context():
            allowed, limit, message = check_agent_limit()
            assert allowed is True
            assert limit == 5
            assert message is None

    def test_inactive_agents_not_counted(self, app, db_session):
        """Inactive assets (active=False) should NOT count toward the agent limit."""
        from app.models import Asset, Organization
        from app.licensing import check_agent_limit

        org = Organization(name='inactiveorg', display_name='Inactive Org', active=True)
        db_session.add(org)
        db_session.flush()

        # Create 3 active assets
        for i in range(3):
            asset = Asset(
                hostname=f'active{i}.test.local',
                ip_address=f'10.3.0.{i}',
                asset_type='server',
                organization_id=org.id,
                active=True
            )
            db_session.add(asset)

        # Create 5 INACTIVE assets - these should not count
        for i in range(5):
            asset = Asset(
                hostname=f'inactive{i}.test.local',
                ip_address=f'10.3.1.{i}',
                asset_type='server',
                organization_id=org.id,
                active=False
            )
            db_session.add(asset)
        db_session.commit()

        with app.app_context():
            allowed, limit, message = check_agent_limit()
            # Only 3 active assets, so should be allowed
            assert allowed is True
            assert limit == 5
            assert message is None


class TestGlobalApiKeyLimitEnforcement:
    """Tests for API key limits enforced globally."""

    def test_api_key_limit_blocks_when_exceeded(self, app, db_session):
        """Create active API keys up to the limit and verify blocking."""
        import hashlib
        from app.models import AgentApiKey, Organization
        from app.licensing import check_agent_api_key_limit

        org = Organization(name='apikeyorg', display_name='ApiKey Org', active=True)
        db_session.add(org)
        db_session.flush()

        # Community edition allows 5 API keys - create exactly 5 to hit the limit
        for i in range(5):
            raw_key = f'sk_test_apikey_{i}_abcdef1234567890'
            key_hash = hashlib.sha256(raw_key.encode()).hexdigest()
            api_key = AgentApiKey(
                organization_id=org.id,
                name=f'Test Key {i}',
                key_hash=key_hash,
                key_prefix=raw_key[:8],
                active=True
            )
            db_session.add(api_key)
        db_session.commit()

        with app.app_context():
            allowed, limit, message = check_agent_api_key_limit()
            assert allowed is False
            assert limit == 5
            assert message is not None
            assert isinstance(message, str)

    def test_api_key_limit_allows_within_bounds(self, app, db_session):
        """Fewer API keys than limit returns (True, limit, None)."""
        import hashlib
        from app.models import AgentApiKey, Organization
        from app.licensing import check_agent_api_key_limit

        org = Organization(name='apiboundsorg', display_name='ApiBounds Org', active=True)
        db_session.add(org)
        db_session.flush()

        # Create only 2 API keys - under the community limit of 5
        for i in range(2):
            raw_key = f'sk_test_bounds_{i}_abcdef1234567890'
            key_hash = hashlib.sha256(raw_key.encode()).hexdigest()
            api_key = AgentApiKey(
                organization_id=org.id,
                name=f'Bounds Key {i}',
                key_hash=key_hash,
                key_prefix=raw_key[:8],
                active=True
            )
            db_session.add(api_key)
        db_session.commit()

        with app.app_context():
            allowed, limit, message = check_agent_api_key_limit()
            assert allowed is True
            assert limit == 5
            assert message is None

    def test_inactive_keys_not_counted(self, app, db_session):
        """Keys with active=False should not count toward the limit."""
        import hashlib
        from app.models import AgentApiKey, Organization
        from app.licensing import check_agent_api_key_limit

        org = Organization(name='inactivekeysorg', display_name='InactiveKeys Org', active=True)
        db_session.add(org)
        db_session.flush()

        # Create 2 active keys
        for i in range(2):
            raw_key = f'sk_test_activekey_{i}_abcdef1234567890'
            key_hash = hashlib.sha256(raw_key.encode()).hexdigest()
            api_key = AgentApiKey(
                organization_id=org.id,
                name=f'Active Key {i}',
                key_hash=key_hash,
                key_prefix=raw_key[:8],
                active=True
            )
            db_session.add(api_key)

        # Create 10 INACTIVE keys - these should not count
        for i in range(10):
            raw_key = f'sk_test_inactivekey_{i}_abcdef1234567890'
            key_hash = hashlib.sha256(raw_key.encode()).hexdigest()
            api_key = AgentApiKey(
                organization_id=org.id,
                name=f'Inactive Key {i}',
                key_hash=key_hash,
                key_prefix=raw_key[:8],
                active=False
            )
            db_session.add(api_key)
        db_session.commit()

        with app.app_context():
            allowed, limit, message = check_agent_api_key_limit()
            # Only 2 active keys, so should be allowed
            assert allowed is True
            assert limit == 5
            assert message is None


class TestProductLimitEnforcement:
    """Test product limit checking."""

    def test_product_limit_community(self, app, db_session):
        """Community edition has max 50 products."""
        from app.models import Product, Organization
        from app.licensing import check_product_limit

        org = Organization(name='prodorg', display_name='Prod Org', active=True)
        db_session.add(org)
        db_session.flush()

        # Create exactly 50 products to hit the community limit
        for i in range(50):
            product = Product(
                vendor=f'Vendor{i}',
                product_name=f'Product{i}',
                version='1.0',
                criticality='medium',
                active=True,
                cpe_vendor=f'vendor{i}',
                cpe_product=f'product{i}',
                match_type='auto',
                organization_id=org.id
            )
            db_session.add(product)
        db_session.commit()

        with app.app_context():
            allowed, limit, message = check_product_limit()
            assert allowed is False
            assert limit == 50
            assert message is not None

    def test_product_limit_within_bounds(self, app, db_session):
        """Fewer products than the limit should be allowed."""
        from app.models import Product, Organization
        from app.licensing import check_product_limit

        org = Organization(name='prodboundsorg', display_name='ProdBounds Org', active=True)
        db_session.add(org)
        db_session.flush()

        # Create only 10 products - well under the 50 limit
        for i in range(10):
            product = Product(
                vendor=f'BoundsVendor{i}',
                product_name=f'BoundsProduct{i}',
                version='1.0',
                criticality='low',
                active=True,
                cpe_vendor=f'boundsvendor{i}',
                cpe_product=f'boundsproduct{i}',
                match_type='auto',
                organization_id=org.id
            )
            db_session.add(product)
        db_session.commit()

        with app.app_context():
            allowed, limit, message = check_product_limit()
            assert allowed is True
            assert limit == 50
            assert message is None


class TestLicenseEditions:
    """Test edition detection."""

    def test_community_edition_detected(self, app):
        """With no license key, edition should be 'community'."""
        from app.licensing import get_license

        with app.app_context():
            license_info = get_license()
            assert license_info.edition == 'community'

    def test_community_is_not_professional(self, app):
        """Community license.is_professional() returns False."""
        from app.licensing import get_license

        with app.app_context():
            license_info = get_license()
            assert license_info.is_professional() is False

    def test_community_features(self, app):
        """Community features don't include professional-only features."""
        from app.licensing import get_license

        with app.app_context():
            license_info = get_license()
            # Community edition has an empty features list
            assert 'push_agents' not in license_info.features
            assert 'ldap' not in license_info.features
            assert 'email_alerts' not in license_info.features
            assert 'white_label' not in license_info.features
            assert 'api_access' not in license_info.features
            assert 'multi_org' not in license_info.features
            assert 'jira_integration' not in license_info.features
