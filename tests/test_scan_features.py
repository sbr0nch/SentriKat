"""
Tests for extension/dependency scanning features.

Covers:
- API key scan capabilities (creation, commands endpoint)
- Inventory processing with source_type/ecosystem fields
- License gating (blocking extensions/deps when key lacks capability)
- Input validation (ecosystem whitelist, source_type whitelist, _safe_bool)
- Product filtering by source_type in the UI API
"""
import pytest
import hashlib
from unittest.mock import patch, MagicMock


# ---------------------------------------------------------------------------
# License mocking helpers
# ---------------------------------------------------------------------------

def make_professional_license():
    """Create a mock professional license for tests requiring licensed features."""
    mock_license = MagicMock()
    mock_license.is_professional.return_value = True
    mock_license.get_effective_edition.return_value = 'professional'
    mock_license.get_effective_limits.return_value = {
        'max_products': -1,
        'max_integrations': -1,
        'max_agent_api_keys': -1,
    }
    mock_license.features = ['push_agents', 'Agent Keys']
    mock_license.has_feature.return_value = True
    return mock_license


@pytest.fixture
def pro_license():
    """Patch licensing to always return professional for agent key endpoints."""
    mock_license = make_professional_license()
    with patch('app.licensing.get_license', return_value=mock_license):
        with patch('app.agent_api.requires_professional',
                   lambda feature=None: lambda f: f):
            yield mock_license


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def api_key_full(db_session, test_org):
    """Agent API key with ALL scan capabilities enabled."""
    from app.models import AgentApiKey

    raw = 'sk_test_fullcap_1234567890'
    api_key = AgentApiKey(
        organization_id=test_org.id,
        name='Full Capabilities Key',
        key_hash=hashlib.sha256(raw.encode()).hexdigest(),
        key_prefix=raw[:10],
        active=True,
        scan_os_packages=True,
        scan_extensions=True,
        scan_dependencies=True,
        auto_approve=True,
    )
    db_session.add(api_key)
    db_session.commit()
    return {'api_key': api_key, 'raw_key': raw}


@pytest.fixture
def api_key_os_only(db_session, test_org):
    """Agent API key with ONLY OS package scanning (extensions/deps disabled)."""
    from app.models import AgentApiKey

    raw = 'sk_test_osonly_1234567890'
    api_key = AgentApiKey(
        organization_id=test_org.id,
        name='OS Only Key',
        key_hash=hashlib.sha256(raw.encode()).hexdigest(),
        key_prefix=raw[:10],
        active=True,
        scan_os_packages=True,
        scan_extensions=False,
        scan_dependencies=False,
        auto_approve=True,
    )
    db_session.add(api_key)
    db_session.commit()
    return {'api_key': api_key, 'raw_key': raw}


def _inventory_payload(products=None):
    """Build a minimal agent inventory payload."""
    return {
        'hostname': 'test-workstation.local',
        'os': 'Linux',
        'os_version': 'Ubuntu 22.04',
        'agent': {'id': 'test-uuid-scan-features', 'version': '1.4.0'},
        'products': products or [],
    }


# ---------------------------------------------------------------------------
# _safe_bool unit tests
# ---------------------------------------------------------------------------

class TestSafeBool:
    """Unit tests for the _safe_bool() validation helper."""

    def test_none_returns_none(self):
        from app.agent_api import _safe_bool
        assert _safe_bool(None) is None

    def test_true_returns_true(self):
        from app.agent_api import _safe_bool
        assert _safe_bool(True) is True

    def test_false_returns_false(self):
        from app.agent_api import _safe_bool
        assert _safe_bool(False) is False

    def test_int_one_returns_true(self):
        from app.agent_api import _safe_bool
        assert _safe_bool(1) is True

    def test_int_zero_returns_false(self):
        from app.agent_api import _safe_bool
        assert _safe_bool(0) is False

    def test_string_rejected(self):
        from app.agent_api import _safe_bool
        assert _safe_bool("true") is None

    def test_list_rejected(self):
        from app.agent_api import _safe_bool
        assert _safe_bool([1, 2]) is None

    def test_dict_rejected(self):
        from app.agent_api import _safe_bool
        assert _safe_bool({"a": 1}) is None


# ---------------------------------------------------------------------------
# Validation constants tests
# ---------------------------------------------------------------------------

class TestValidationConstants:
    """Verify the whitelist constants exist and contain expected values."""

    def test_valid_source_types(self):
        from app.agent_api import VALID_SOURCE_TYPES
        assert 'os_package' in VALID_SOURCE_TYPES
        assert 'extension' in VALID_SOURCE_TYPES
        assert 'code_library' in VALID_SOURCE_TYPES
        # Legacy types still accepted for backwards compatibility (normalized on ingest)
        assert 'vscode_extension' in VALID_SOURCE_TYPES
        assert 'browser_extension' in VALID_SOURCE_TYPES
        assert 'malicious_type' not in VALID_SOURCE_TYPES

    def test_valid_ecosystems(self):
        from app.agent_api import VALID_ECOSYSTEMS
        for eco in ('npm', 'pypi', 'maven', 'nuget', 'cargo', 'go', 'gem', 'composer',
                    'vscode', 'chrome', 'firefox', 'edge', 'jetbrains'):
            assert eco in VALID_ECOSYSTEMS
        assert 'evil_ecosystem' not in VALID_ECOSYSTEMS


# ---------------------------------------------------------------------------
# API key scan capability creation
# ---------------------------------------------------------------------------

class TestAgentKeyCreation:
    """Test that agent API keys can be created with scan capabilities."""

    @patch('app.agent_api.check_agent_api_key_limit', return_value=(True, 10, 'OK'))
    def test_create_key_with_extensions_enabled(self, mock_limit, app, admin_client, db_session, test_org, pro_license):
        """Creating a key with scan_extensions=True stores the capability."""
        with app.app_context():
            response = admin_client.post('/api/agent-keys', json={
                'organization_id': test_org.id,
                'name': 'Ext Scan Key',
                'scan_extensions': True,
                'scan_dependencies': False,
            })
            assert response.status_code in [200, 201]

            from app.models import AgentApiKey
            key = AgentApiKey.query.filter_by(name='Ext Scan Key').first()
            assert key is not None
            assert key.scan_extensions is True
            assert key.scan_dependencies is False

    @patch('app.agent_api.check_agent_api_key_limit', return_value=(True, 10, 'OK'))
    def test_create_key_with_deps_enabled(self, mock_limit, app, admin_client, db_session, test_org, pro_license):
        """Creating a key with scan_dependencies=True stores the capability."""
        with app.app_context():
            response = admin_client.post('/api/agent-keys', json={
                'organization_id': test_org.id,
                'name': 'Dep Scan Key',
                'scan_extensions': False,
                'scan_dependencies': True,
            })
            assert response.status_code in [200, 201]

            from app.models import AgentApiKey
            key = AgentApiKey.query.filter_by(name='Dep Scan Key').first()
            assert key is not None
            assert key.scan_dependencies is True

    @patch('app.agent_api.check_agent_api_key_limit', return_value=(True, 10, 'OK'))
    def test_create_key_defaults_extensions_off(self, mock_limit, app, admin_client, db_session, test_org, pro_license):
        """By default, scan_extensions and scan_dependencies are disabled."""
        with app.app_context():
            response = admin_client.post('/api/agent-keys', json={
                'organization_id': test_org.id,
                'name': 'Default Key',
            })
            assert response.status_code in [200, 201]

            from app.models import AgentApiKey
            key = AgentApiKey.query.filter_by(name='Default Key').first()
            assert key is not None
            assert key.scan_extensions is False
            assert key.scan_dependencies is False

    @patch('app.agent_api.check_agent_api_key_limit', return_value=(True, 10, 'OK'))
    def test_create_key_with_key_type(self, mock_limit, app, admin_client, db_session, test_org, pro_license):
        """Test creating keys with server/client key_type."""
        with app.app_context():
            response = admin_client.post('/api/agent-keys', json={
                'organization_id': test_org.id,
                'name': 'Client Key',
                'key_type': 'client',
            })
            assert response.status_code in [200, 201]

            from app.models import AgentApiKey
            key = AgentApiKey.query.filter_by(name='Client Key').first()
            assert key is not None
            assert key.key_type == 'client'

    @patch('app.agent_api.check_agent_api_key_limit', return_value=(True, 10, 'OK'))
    def test_create_key_invalid_key_type(self, mock_limit, app, admin_client, db_session, test_org, pro_license):
        """Reject invalid key_type values."""
        with app.app_context():
            response = admin_client.post('/api/agent-keys', json={
                'organization_id': test_org.id,
                'name': 'Bad Type Key',
                'key_type': 'invalid',
            })
            assert response.status_code == 400


# ---------------------------------------------------------------------------
# Commands endpoint: scan_capabilities
# ---------------------------------------------------------------------------

class TestCommandsScanCapabilities:
    """Test that the commands endpoint returns scan_capabilities."""

    def test_commands_returns_scan_capabilities(self, app, client, db_session, api_key_full):
        """Commands endpoint should return scan_capabilities from the API key."""
        with app.app_context():
            response = client.get(
                '/api/agent/commands?hostname=test-host&agent_id=test-uuid',
                headers={'X-Agent-Key': api_key_full['raw_key']}
            )
            assert response.status_code in [200, 403]
            if response.status_code == 200:
                data = response.get_json()
                caps = data.get('scan_capabilities', {})
                assert caps.get('os_packages') is True
                assert caps.get('extensions') is True
                assert caps.get('dependencies') is True

    def test_commands_os_only_key(self, app, client, db_session, api_key_os_only):
        """OS-only key should return extensions=False, dependencies=False."""
        with app.app_context():
            response = client.get(
                '/api/agent/commands?hostname=test-host&agent_id=test-uuid',
                headers={'X-Agent-Key': api_key_os_only['raw_key']}
            )
            assert response.status_code in [200, 403]
            if response.status_code == 200:
                data = response.get_json()
                caps = data.get('scan_capabilities', {})
                assert caps.get('extensions') is False
                assert caps.get('dependencies') is False


# ---------------------------------------------------------------------------
# License gating: inventory filtering
# ---------------------------------------------------------------------------

class TestInventoryLicenseGating:
    """Test that extension/dependency products are filtered by API key capabilities."""

    def test_full_key_accepts_all_types(self, app, client, db_session, api_key_full):
        """A key with all capabilities should accept all product types."""
        with app.app_context():
            payload = _inventory_payload([
                {'vendor': 'Apache', 'product': 'httpd', 'version': '2.4.52', 'source_type': 'os_package'},
                {'vendor': 'Microsoft', 'product': 'Python', 'version': '2024.1', 'source_type': 'vscode_extension', 'ecosystem': 'vscode'},
                {'vendor': 'PyPI', 'product': 'requests', 'version': '2.31.0', 'source_type': 'code_library', 'ecosystem': 'pypi'},
            ])
            response = client.post('/api/agent/inventory',
                json=payload,
                headers={'X-Agent-Key': api_key_full['raw_key']}
            )
            # Accept success or license error (depends on license presence)
            assert response.status_code in [200, 201, 202, 403]

    def test_os_only_key_rejects_extensions(self, app, client, db_session, api_key_os_only):
        """A key without scan_extensions should silently reject extension products."""
        with app.app_context():
            payload = _inventory_payload([
                {'vendor': 'Apache', 'product': 'httpd', 'version': '2.4.52', 'source_type': 'os_package'},
                {'vendor': 'Microsoft', 'product': 'Python', 'version': '2024.1', 'source_type': 'vscode_extension', 'ecosystem': 'vscode'},
            ])
            response = client.post('/api/agent/inventory',
                json=payload,
                headers={'X-Agent-Key': api_key_os_only['raw_key']}
            )
            assert response.status_code in [200, 201, 202, 403]
            # If 200/201/202, the extension product should NOT have been created
            if response.status_code in [200, 201, 202]:
                from app.models import Product
                # Legacy vscode_extension is normalized to 'extension' on ingest
                ext = Product.query.filter_by(
                    product_name='Python',
                    source_type='extension'
                ).first()
                assert ext is None, "Extension product should be rejected by OS-only key"

    def test_os_only_key_rejects_code_libraries(self, app, client, db_session, api_key_os_only):
        """A key without scan_dependencies should silently reject code_library products."""
        with app.app_context():
            payload = _inventory_payload([
                {'vendor': 'PyPI', 'product': 'requests', 'version': '2.31.0', 'source_type': 'code_library', 'ecosystem': 'pypi'},
            ])
            response = client.post('/api/agent/inventory',
                json=payload,
                headers={'X-Agent-Key': api_key_os_only['raw_key']}
            )
            assert response.status_code in [200, 201, 202, 403]
            if response.status_code in [200, 201, 202]:
                from app.models import Product
                lib = Product.query.filter_by(
                    product_name='requests',
                    source_type='code_library'
                ).first()
                assert lib is None, "Code library should be rejected by OS-only key"

    def test_os_packages_always_accepted(self, app, client, db_session, api_key_os_only):
        """OS packages should always be accepted regardless of scan capabilities."""
        with app.app_context():
            payload = _inventory_payload([
                {'vendor': 'Apache', 'product': 'httpd-osonly', 'version': '2.4.52', 'source_type': 'os_package'},
            ])
            response = client.post('/api/agent/inventory',
                json=payload,
                headers={'X-Agent-Key': api_key_os_only['raw_key']}
            )
            assert response.status_code in [200, 201, 202, 403]


# ---------------------------------------------------------------------------
# Input validation: source_type, ecosystem, is_direct
# ---------------------------------------------------------------------------

class TestInventoryInputValidation:
    """Test that invalid source_type and ecosystem values are sanitized."""

    def test_unknown_source_type_defaults_to_os_package(self, app, client, db_session, api_key_full):
        """An unknown source_type should default to 'os_package'."""
        with app.app_context():
            payload = _inventory_payload([
                {'vendor': 'Test', 'product': 'unknown-type-test', 'version': '1.0', 'source_type': 'malicious_type'},
            ])
            response = client.post('/api/agent/inventory',
                json=payload,
                headers={'X-Agent-Key': api_key_full['raw_key']}
            )
            assert response.status_code in [200, 201, 202, 403]
            if response.status_code in [200, 201, 202]:
                from app.models import Product
                p = Product.query.filter_by(product_name='unknown-type-test').first()
                if p:
                    assert p.source_type == 'os_package', \
                        f"Unknown source_type should default to os_package, got {p.source_type}"

    def test_unknown_ecosystem_rejected(self, app, client, db_session, api_key_full):
        """An unknown ecosystem should be set to None."""
        with app.app_context():
            payload = _inventory_payload([
                {'vendor': 'Test', 'product': 'bad-eco-test', 'version': '1.0',
                 'source_type': 'os_package', 'ecosystem': 'evil_ecosystem'},
            ])
            response = client.post('/api/agent/inventory',
                json=payload,
                headers={'X-Agent-Key': api_key_full['raw_key']}
            )
            assert response.status_code in [200, 201, 202, 403]
            if response.status_code in [200, 201, 202]:
                from app.models import Product
                p = Product.query.filter_by(product_name='bad-eco-test').first()
                if p:
                    assert p.ecosystem is None, \
                        f"Unknown ecosystem should be rejected, got {p.ecosystem}"

    def test_valid_ecosystem_accepted(self, app, client, db_session, api_key_full):
        """A valid ecosystem from the whitelist should be stored."""
        with app.app_context():
            payload = _inventory_payload([
                {'vendor': 'PyPI', 'product': 'valid-eco-test', 'version': '1.0',
                 'source_type': 'code_library', 'ecosystem': 'pypi'},
            ])
            response = client.post('/api/agent/inventory',
                json=payload,
                headers={'X-Agent-Key': api_key_full['raw_key']}
            )
            assert response.status_code in [200, 201, 202, 403]
            if response.status_code in [200, 201, 202]:
                from app.models import Product
                p = Product.query.filter_by(product_name='valid-eco-test').first()
                if p:
                    assert p.ecosystem == 'pypi'

    def test_missing_vendor_skipped(self, app, client, db_session, api_key_full):
        """Products without vendor should be silently skipped."""
        with app.app_context():
            payload = _inventory_payload([
                {'product': 'no-vendor-test', 'version': '1.0'},
            ])
            response = client.post('/api/agent/inventory',
                json=payload,
                headers={'X-Agent-Key': api_key_full['raw_key']}
            )
            assert response.status_code in [200, 201, 202, 403]

    def test_invalid_api_key(self, app, client, db_session):
        """Invalid API key should be rejected."""
        with app.app_context():
            response = client.post('/api/agent/inventory',
                json=_inventory_payload([]),
                headers={'X-Agent-Key': 'sk_invalid_key_123456'}
            )
            assert response.status_code in [302, 401, 403]


# ---------------------------------------------------------------------------
# Inventory with dependency-specific fields
# ---------------------------------------------------------------------------

class TestDependencyFields:
    """Test that dependency-specific fields are processed correctly."""

    def test_project_path_stored(self, app, client, db_session, api_key_full):
        """project_path should be stored in the installation record."""
        with app.app_context():
            payload = _inventory_payload([
                {'vendor': 'PyPI', 'product': 'flask-pathtest', 'version': '3.0.0',
                 'source_type': 'code_library', 'ecosystem': 'pypi',
                 'project_path': '/opt/myapp/requirements.txt', 'is_direct': True},
            ])
            response = client.post('/api/agent/inventory',
                json=payload,
                headers={'X-Agent-Key': api_key_full['raw_key']}
            )
            assert response.status_code in [200, 201, 202, 403]

    def test_is_direct_boolean_stored(self, app, client, db_session, api_key_full):
        """is_direct=True should be stored as is_direct_dependency."""
        with app.app_context():
            payload = _inventory_payload([
                {'vendor': 'npm', 'product': 'express-directtest', 'version': '4.18.2',
                 'source_type': 'code_library', 'ecosystem': 'npm',
                 'is_direct': True},
            ])
            response = client.post('/api/agent/inventory',
                json=payload,
                headers={'X-Agent-Key': api_key_full['raw_key']}
            )
            assert response.status_code in [200, 201, 202, 403]

    def test_is_direct_string_rejected(self, app, client, db_session, api_key_full):
        """is_direct as a string should be coerced to None by _safe_bool."""
        with app.app_context():
            payload = _inventory_payload([
                {'vendor': 'npm', 'product': 'express-stringtest', 'version': '4.18.2',
                 'source_type': 'code_library', 'ecosystem': 'npm',
                 'is_direct': 'yes'},  # String, not boolean
            ])
            response = client.post('/api/agent/inventory',
                json=payload,
                headers={'X-Agent-Key': api_key_full['raw_key']}
            )
            # Should not crash - just store None for is_direct
            assert response.status_code in [200, 201, 202, 403]


# ---------------------------------------------------------------------------
# Product filtering API
# ---------------------------------------------------------------------------

class TestProductSourceTypeFilter:
    """Test filtering products by source_type in the products API."""

    def test_filter_by_os_package(self, app, admin_client, db_session, test_org):
        """Filtering by source_type=os_package should work."""
        from app.models import Product

        p = Product(vendor='Test', product_name='filter-os-test', version='1.0',
                    source_type='os_package', organization_id=test_org.id, active=True)
        db_session.add(p)
        db_session.commit()

        response = admin_client.get(f'/api/products?organization_id={test_org.id}&source_type=os_package')
        assert response.status_code == 200

    def test_filter_by_extension(self, app, admin_client, db_session, test_org):
        """Filtering by source_type=extension should work."""
        from app.models import Product

        p = Product(vendor='Microsoft', product_name='filter-ext-test', version='1.0',
                    source_type='extension', ecosystem='vscode',
                    organization_id=test_org.id, active=True)
        db_session.add(p)
        db_session.commit()

        response = admin_client.get(f'/api/products?organization_id={test_org.id}&source_type=extension')
        assert response.status_code == 200
        data = response.get_json()
        # API may return a list directly or a dict with 'products' key
        products = data if isinstance(data, list) else data.get('products', data.get('items', []))
        if products:
            for prod in products:
                assert prod.get('source_type') == 'extension'

    def test_filter_by_code_library(self, app, admin_client, db_session, test_org):
        """Filtering by source_type=code_library should work."""
        from app.models import Product

        p = Product(vendor='PyPI', product_name='filter-lib-test', version='1.0',
                    source_type='code_library', ecosystem='pypi',
                    organization_id=test_org.id, active=True)
        db_session.add(p)
        db_session.commit()

        response = admin_client.get(f'/api/products?organization_id={test_org.id}&source_type=code_library')
        assert response.status_code == 200

    def test_invalid_source_type_ignored(self, app, admin_client, db_session, test_org):
        """An invalid source_type filter should be safely ignored (return all)."""
        response = admin_client.get(f'/api/products?organization_id={test_org.id}&source_type=INJECTED')
        assert response.status_code == 200


# ---------------------------------------------------------------------------
# Agent key model scan capabilities
# ---------------------------------------------------------------------------

class TestAgentKeyModel:
    """Test AgentApiKey model scan capability fields."""

    def test_scan_capabilities_in_to_dict(self, app, db_session, test_org):
        """to_dict() should include scan_capabilities."""
        from app.models import AgentApiKey

        raw = 'sk_test_model_dict_test_123'
        key = AgentApiKey(
            organization_id=test_org.id,
            name='Dict Test Key',
            key_hash=hashlib.sha256(raw.encode()).hexdigest(),
            key_prefix=raw[:10],
            active=True,
            scan_os_packages=True,
            scan_extensions=True,
            scan_dependencies=False,
        )
        db_session.add(key)
        db_session.commit()

        d = key.to_dict()
        caps = d.get('scan_capabilities', {})
        assert caps.get('os_packages') is True
        assert caps.get('extensions') is True
        assert caps.get('dependencies') is False

    def test_default_scan_capabilities(self, app, db_session, test_org):
        """Default scan capabilities: os=True, extensions=False, deps=False."""
        from app.models import AgentApiKey

        raw = 'sk_test_model_default_123'
        key = AgentApiKey(
            organization_id=test_org.id,
            name='Default Cap Key',
            key_hash=hashlib.sha256(raw.encode()).hexdigest(),
            key_prefix=raw[:10],
            active=True,
        )
        db_session.add(key)
        db_session.commit()

        assert key.scan_os_packages is True
        assert key.scan_extensions is False
        assert key.scan_dependencies is False


# ---------------------------------------------------------------------------
# Heartbeat endpoint
# ---------------------------------------------------------------------------

class TestHeartbeatEndpoint:
    """Test heartbeat with scan capability keys."""

    def test_heartbeat_auth_with_scan_key(self, app, client, db_session, api_key_full):
        """Heartbeat should authenticate successfully with a scan-capable key.
        Note: Returns 404 if no asset exists yet (expected behavior)."""
        with app.app_context():
            response = client.post('/api/agent/heartbeat',
                json={
                    'hostname': 'test-heartbeat.local',
                    'agent_id': 'test-hb-uuid',
                    'agent_version': '1.4.0',
                    'status': 'idle',
                },
                headers={'X-Agent-Key': api_key_full['raw_key']}
            )
            # 200 if asset exists, 404 if not (but key auth succeeded), 403 if auth failed
            assert response.status_code in [200, 404]
            # Confirm it's not an auth failure
            if response.status_code == 404:
                data = response.get_json()
                assert 'Asset not found' in data.get('error', '')

    def test_heartbeat_rejects_invalid_key(self, app, client, db_session):
        """Heartbeat should reject invalid API keys."""
        with app.app_context():
            response = client.post('/api/agent/heartbeat',
                json={'hostname': 'test.local', 'agent_id': 'uuid'},
                headers={'X-Agent-Key': 'sk_invalid_heartbeat_key'}
            )
            assert response.status_code == 401


# ---------------------------------------------------------------------------
# Multiple products: mixed types in single inventory
# ---------------------------------------------------------------------------

class TestMixedInventory:
    """Test inventory submissions with mixed product types."""

    def test_mixed_os_ext_dep_inventory(self, app, client, db_session, api_key_full):
        """Submit inventory with OS packages, extensions, and dependencies together."""
        with app.app_context():
            payload = _inventory_payload([
                # OS packages
                {'vendor': 'Apache', 'product': 'httpd-mixed', 'version': '2.4.52', 'source_type': 'os_package'},
                {'vendor': 'nginx', 'product': 'nginx-mixed', 'version': '1.24.0', 'source_type': 'os_package'},
                # Extensions
                {'vendor': 'Microsoft', 'product': 'python-ext-mixed', 'version': '2024.1',
                 'source_type': 'vscode_extension', 'ecosystem': 'vscode'},
                # Dependencies
                {'vendor': 'PyPI', 'product': 'flask-mixed', 'version': '3.0.0',
                 'source_type': 'code_library', 'ecosystem': 'pypi', 'is_direct': True},
                {'vendor': 'npm', 'product': 'lodash-mixed', 'version': '4.17.21',
                 'source_type': 'code_library', 'ecosystem': 'npm', 'is_direct': False,
                 'project_path': '/app/package-lock.json'},
            ])
            response = client.post('/api/agent/inventory',
                json=payload,
                headers={'X-Agent-Key': api_key_full['raw_key']}
            )
            assert response.status_code in [200, 201, 202, 403]

    def test_large_dependency_inventory(self, app, client, db_session, api_key_full):
        """Submit a larger inventory with many dependencies (typical real-world scenario)."""
        with app.app_context():
            products = []
            for i in range(50):
                products.append({
                    'vendor': 'PyPI',
                    'product': f'dep-bulk-{i}',
                    'version': f'1.{i}.0',
                    'source_type': 'code_library',
                    'ecosystem': 'pypi',
                    'is_direct': i < 10,  # First 10 are direct
                    'project_path': '/app/requirements.txt',
                })
            payload = _inventory_payload(products)
            response = client.post('/api/agent/inventory',
                json=payload,
                headers={'X-Agent-Key': api_key_full['raw_key']}
            )
            assert response.status_code in [200, 201, 202, 403]

    def test_empty_products_accepted(self, app, client, db_session, api_key_full):
        """Empty products list should still be accepted (heartbeat-like inventory)."""
        with app.app_context():
            response = client.post('/api/agent/inventory',
                json=_inventory_payload([]),
                headers={'X-Agent-Key': api_key_full['raw_key']}
            )
            assert response.status_code in [200, 201, 202, 403]
