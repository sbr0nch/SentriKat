"""
Tests for API endpoints.
"""
import pytest
from unittest.mock import patch, MagicMock
from datetime import datetime, date


class TestHealthEndpoints:
    """Tests for health check endpoints."""

    def test_health_endpoint(self, client):
        """Test basic health check endpoint."""
        response = client.get('/api/health')

        assert response.status_code == 200
        data = response.get_json()
        assert data['status'] == 'healthy'

    def test_version_endpoint(self, client):
        """Test version endpoint."""
        response = client.get('/api/version')

        assert response.status_code == 200
        data = response.get_json()
        assert 'version' in data


class TestProductEndpoints:
    """Tests for product CRUD endpoints."""

    def setup_auth(self, client, db_session):
        """Set up authenticated session."""
        from app.models import User, Organization

        org = Organization(name='test', display_name='Test', active=True)
        db_session.add(org)
        db_session.flush()

        user = User(
            username='manager',
            email='manager@test.com',
            role='manager',
            is_active=True,
            auth_type='local',
            organization_id=org.id,
            can_manage_products=True
        )
        user.set_password('password')
        db_session.add(user)
        db_session.commit()

        client.post('/api/auth/login', json={
            'username': 'manager',
            'password': 'password'
        })

        return org

    def test_list_products(self, app, client, db_session):
        """Test listing products."""
        org = self.setup_auth(client, db_session)

        from app.models import Product
        product = Product(
            vendor='Apache',
            product_name='Tomcat',
            version='10.1.18',
            criticality='high',
            active=True,
            organization_id=org.id
        )
        db_session.add(product)
        db_session.commit()

        response = client.get('/api/products')

        assert response.status_code == 200
        products = response.get_json()
        assert len(products) >= 1
        assert any(p['product_name'] == 'Tomcat' for p in products)

    def test_create_product(self, app, client, db_session):
        """Test creating a product."""
        self.setup_auth(client, db_session)

        response = client.post('/api/products', json={
            'vendor': 'Microsoft',
            'product_name': 'Exchange',
            'version': '2019',
            'criticality': 'critical'
        })

        assert response.status_code == 201
        data = response.get_json()
        assert data['product_name'] == 'Exchange'
        assert 'id' in data

    def test_get_product(self, app, client, db_session):
        """Test getting a single product."""
        org = self.setup_auth(client, db_session)

        from app.models import Product
        product = Product(
            vendor='Apache',
            product_name='HTTP Server',
            version='2.4.51',
            criticality='medium',
            active=True,
            organization_id=org.id
        )
        db_session.add(product)
        db_session.commit()

        response = client.get(f'/api/products/{product.id}')

        assert response.status_code == 200
        data = response.get_json()
        assert data['product_name'] == 'HTTP Server'

    def test_update_product(self, app, client, db_session):
        """Test updating a product."""
        org = self.setup_auth(client, db_session)

        from app.models import Product
        product = Product(
            vendor='Apache',
            product_name='Tomcat',
            version='10.0.0',
            criticality='high',
            active=True,
            organization_id=org.id
        )
        db_session.add(product)
        db_session.commit()

        response = client.put(f'/api/products/{product.id}', json={
            'version': '10.1.18',
            'criticality': 'critical'
        })

        assert response.status_code == 200
        data = response.get_json()
        assert data['version'] == '10.1.18'
        assert data['criticality'] == 'critical'

    def test_delete_product(self, app, client, db_session):
        """Test deleting a product."""
        org = self.setup_auth(client, db_session)

        from app.models import Product
        product = Product(
            vendor='Test',
            product_name='DeleteMe',
            version='1.0',
            criticality='low',
            active=True,
            organization_id=org.id
        )
        db_session.add(product)
        db_session.commit()

        product_id = product.id
        response = client.delete(f'/api/products/{product_id}')

        assert response.status_code in [200, 204]

        # Verify product is deleted
        from app.models import Product as P
        with app.app_context():
            deleted = P.query.get(product_id)
            assert deleted is None or deleted.active is False

    def test_create_product_validation(self, app, client, db_session):
        """Test product creation validation."""
        self.setup_auth(client, db_session)

        # Missing required fields
        response = client.post('/api/products', json={
            'vendor': 'Test'
            # Missing product_name
        })

        assert response.status_code == 400


class TestVulnerabilityEndpoints:
    """Tests for vulnerability endpoints."""

    def setup_auth(self, client, db_session):
        """Set up authenticated session."""
        from app.models import User, Organization

        org = Organization(name='test', display_name='Test', active=True)
        db_session.add(org)
        db_session.flush()

        user = User(
            username='user',
            email='user@test.com',
            role='user',
            is_active=True,
            auth_type='local',
            organization_id=org.id
        )
        user.set_password('password')
        db_session.add(user)
        db_session.commit()

        client.post('/api/auth/login', json={
            'username': 'user',
            'password': 'password'
        })

        return org

    def test_list_vulnerabilities(self, app, client, db_session):
        """Test listing vulnerabilities."""
        org = self.setup_auth(client, db_session)

        from app.models import Vulnerability
        vuln = Vulnerability(
            cve_id='CVE-2024-1234',
            vendor_project='Apache',
            product='Tomcat',
            vulnerability_name='Test Vuln',
            date_added=date.today(),
            short_description='A test vulnerability',
            required_action='Update software'
        )
        db_session.add(vuln)
        db_session.commit()

        response = client.get('/api/vulnerabilities')

        assert response.status_code == 200

    def test_get_vulnerability_details(self, app, client, db_session):
        """Test getting vulnerability details."""
        org = self.setup_auth(client, db_session)

        from app.models import Vulnerability
        vuln = Vulnerability(
            cve_id='CVE-2024-5678',
            vendor_project='Microsoft',
            product='Exchange',
            vulnerability_name='Exchange RCE',
            date_added=date.today(),
            short_description='Remote code execution',
            required_action='Apply patch',
            cvss_score=9.8,
            severity='CRITICAL'
        )
        db_session.add(vuln)
        db_session.commit()

        response = client.get(f'/api/vulnerabilities/{vuln.cve_id}')

        if response.status_code == 200:
            data = response.get_json()
            assert data['cve_id'] == 'CVE-2024-5678'


class TestMatchEndpoints:
    """Tests for vulnerability match endpoints."""

    def setup_data(self, client, db_session):
        """Set up test data with products, vulns, and matches."""
        from app.models import User, Organization, Product, Vulnerability, VulnerabilityMatch

        org = Organization(name='test', display_name='Test', active=True)
        db_session.add(org)
        db_session.flush()

        user = User(
            username='manager',
            email='manager@test.com',
            role='manager',
            is_active=True,
            auth_type='local',
            organization_id=org.id,
            can_manage_products=True
        )
        user.set_password('password')
        db_session.add(user)

        product = Product(
            vendor='Apache',
            product_name='Tomcat',
            version='10.1.18',
            criticality='high',
            active=True,
            organization_id=org.id
        )
        db_session.add(product)
        db_session.flush()

        vuln = Vulnerability(
            cve_id='CVE-2024-9999',
            vendor_project='Apache',
            product='Tomcat',
            vulnerability_name='Tomcat Vuln',
            date_added=date.today(),
            short_description='Test',
            required_action='Update'
        )
        db_session.add(vuln)
        db_session.flush()

        match = VulnerabilityMatch(
            product_id=product.id,
            vulnerability_id=vuln.id,
            match_method='cpe',
            match_confidence='high',
            acknowledged=False
        )
        db_session.add(match)
        db_session.commit()

        client.post('/api/auth/login', json={
            'username': 'manager',
            'password': 'password'
        })

        return {'org': org, 'product': product, 'vuln': vuln, 'match': match}

    def test_acknowledge_match(self, app, client, db_session):
        """Test acknowledging a vulnerability match."""
        data = self.setup_data(client, db_session)

        response = client.post(f'/api/matches/{data["match"].id}/acknowledge', json={
            'notes': 'Acknowledged for testing'
        })

        assert response.status_code == 200
        result = response.get_json()
        assert result.get('success') is True or result.get('is_acknowledged') is True

    def test_snooze_match(self, app, client, db_session):
        """Test snoozing a vulnerability match."""
        data = self.setup_data(client, db_session)

        response = client.post(f'/api/matches/{data["match"].id}/snooze', json={
            'days': 7,
            'reason': 'Patch scheduled for next week'
        })

        assert response.status_code == 200


class TestAgentEndpoints:
    """Tests for agent/asset endpoints."""

    def setup_api_key(self, db_session):
        """Set up an API key for agent registration."""
        from app.models import Organization, AgentApiKey
        import hashlib

        org = Organization(name='test', display_name='Test', is_active=True)
        db_session.add(org)
        db_session.flush()

        raw_key = 'test-agent-api-key-1234567890'
        key_hash = hashlib.sha256(raw_key.encode()).hexdigest()

        api_key = AgentApiKey(
            name='Test Agent Key',
            organization_id=org.id,
            key_hash=key_hash,
            key_prefix=raw_key[:8],
            active=True
        )
        db_session.add(api_key)
        db_session.commit()

        return {'org': org, 'api_key': api_key, 'raw_key': raw_key}

    def test_agent_register(self, app, client, db_session):
        """Test agent registration."""
        data = self.setup_api_key(db_session)

        response = client.post('/api/agent/register',
            json={
                'hostname': 'newserver.test.local',
                'ip_address': '192.168.1.100',
                'os_type': 'Linux',
                'os_version': 'Ubuntu 22.04'
            },
            headers={'X-Agent-Key': 'test-agent-api-key-1234567890'}
        )

        assert response.status_code in [200, 201]

    def test_agent_register_invalid_key(self, app, client, db_session):
        """Test agent registration with invalid API key."""
        response = client.post('/api/agent/register',
            json={
                'hostname': 'server.test.local',
                'ip_address': '192.168.1.101',
                'os_type': 'Linux'
            },
            headers={'X-Agent-Key': 'invalid-key'}
        )

        assert response.status_code in [401, 403]

    def test_agent_inventory_submit(self, app, client, db_session):
        """Test agent inventory submission."""
        data = self.setup_api_key(db_session)

        # Register agent first
        client.post('/api/agent/register',
            json={
                'hostname': 'server.test.local',
                'ip_address': '192.168.1.100',
                'os_type': 'Linux'
            },
            headers={'X-Agent-Key': 'test-agent-api-key-1234567890'}
        )

        # Submit inventory
        response = client.post('/api/agent/inventory',
            json={
                'hostname': 'server.test.local',
                'inventory': [
                    {
                        'name': 'Apache Tomcat',
                        'vendor': 'Apache',
                        'version': '10.1.18'
                    },
                    {
                        'name': 'nginx',
                        'vendor': 'nginx',
                        'version': '1.24.0'
                    }
                ]
            },
            headers={'X-Agent-Key': 'test-agent-api-key-1234567890'}
        )

        assert response.status_code in [200, 202]


class TestSettingsEndpoints:
    """Tests for settings endpoints."""

    def setup_admin(self, client, db_session):
        """Set up admin user."""
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

        client.post('/api/auth/login', json={
            'username': 'admin',
            'password': 'adminpass'
        })

        return org

    def test_get_general_settings(self, app, client, db_session):
        """Test getting general settings."""
        self.setup_admin(client, db_session)

        response = client.get('/api/settings/general')

        assert response.status_code == 200
        data = response.get_json()
        # Should include proxy settings and timezone
        assert isinstance(data, dict)

    def test_get_branding_settings(self, app, client, db_session):
        """Test getting branding settings."""
        self.setup_admin(client, db_session)

        response = client.get('/api/settings/branding')

        assert response.status_code == 200

    def test_get_security_settings(self, app, client, db_session):
        """Test getting security settings."""
        self.setup_admin(client, db_session)

        response = client.get('/api/settings/security')

        assert response.status_code == 200


class TestCPEEndpoints:
    """Tests for CPE-related endpoints."""

    def setup_auth(self, client, db_session):
        """Set up authenticated session."""
        from app.models import User, Organization

        org = Organization(name='test', display_name='Test', active=True)
        db_session.add(org)
        db_session.flush()

        user = User(
            username='manager',
            email='manager@test.com',
            role='manager',
            is_active=True,
            auth_type='local',
            organization_id=org.id,
            can_manage_products=True
        )
        user.set_password('password')
        db_session.add(user)
        db_session.commit()

        client.post('/api/auth/login', json={
            'username': 'manager',
            'password': 'password'
        })

        return org

    @patch('app.nvd_cpe_api.requests.get')
    def test_cpe_search(self, mock_get, app, client, db_session):
        """Test CPE search endpoint."""
        self.setup_auth(client, db_session)

        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            'products': [
                {
                    'cpe': {
                        'cpeName': 'cpe:2.3:a:apache:tomcat:10.1.18:*:*:*:*:*:*:*',
                        'cpeNameId': 'test-id',
                        'deprecated': False,
                        'titles': [{'title': 'Apache Tomcat 10.1.18'}]
                    }
                }
            ]
        }
        mock_get.return_value = mock_response

        response = client.get('/api/cpe/search?query=apache tomcat')

        assert response.status_code == 200
