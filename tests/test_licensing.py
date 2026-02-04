"""
Tests for the licensing system.
"""
import pytest
from unittest.mock import patch, MagicMock
from datetime import datetime, timedelta


class TestLicenseValidation:
    """Tests for license validation."""

    def test_community_license_limits(self, app):
        """Test community license has correct limits."""
        from app.licensing import get_license

        with app.app_context():
            # Get license info (community when no license installed)
            license_info = get_license()
            limits = license_info.get_effective_limits()

            # Community edition has no agents (push agents require Professional)
            assert limits['max_agents'] == 0
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

        # Get LDAP settings
        response = client.get('/api/settings/ldap')

        # Should succeed (may return upgrade message for community)
        assert response.status_code == 200


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
