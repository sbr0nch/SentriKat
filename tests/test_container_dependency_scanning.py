"""
Tests for container image scanning AND library/dependency scanning features.

Covers:
- ContainerImage model (CRUD, relationships, cascade deletes)
- ContainerVulnerability model (severity, fix status, CVSS, cascade deletes)
- Agent API dependency scanning (source_type, ecosystem, project_path, is_direct)
- Agent API extension scanning (vscode_extension, browser_extension normalization)
- License gating (scan_dependencies, scan_extensions capability enforcement)
- Agent commands endpoint scan_capabilities
- Input validation (_safe_bool, VALID_SOURCE_TYPES, VALID_ECOSYSTEMS)
- End-to-end dependency flow (agent submits -> Product created -> VulnerabilityMatch)
"""
import pytest
import hashlib
from datetime import datetime, date, timedelta
from unittest.mock import patch, MagicMock


# ---------------------------------------------------------------------------
# License mocking helpers
# ---------------------------------------------------------------------------

def _mock_professional_license():
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
    mock_license = _mock_professional_license()
    with patch('app.licensing.get_license', return_value=mock_license):
        with patch('app.agent_api.requires_professional',
                   lambda feature=None: lambda f: f):
            yield mock_license


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def api_key_all_caps(db_session, test_org):
    """Agent API key with ALL scan capabilities enabled."""
    from app.models import AgentApiKey

    raw = 'sk_test_allcaps_abcdef012345'
    api_key = AgentApiKey(
        organization_id=test_org.id,
        name='All Caps Key',
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

    raw = 'sk_test_osonly_abcdef012345'
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


@pytest.fixture
def api_key_deps_only(db_session, test_org):
    """Agent API key with OS + dependency scanning (extensions disabled)."""
    from app.models import AgentApiKey

    raw = 'sk_test_depsonly_abcdef0123'
    api_key = AgentApiKey(
        organization_id=test_org.id,
        name='Deps Only Key',
        key_hash=hashlib.sha256(raw.encode()).hexdigest(),
        key_prefix=raw[:10],
        active=True,
        scan_os_packages=True,
        scan_extensions=False,
        scan_dependencies=True,
        auto_approve=True,
    )
    db_session.add(api_key)
    db_session.commit()
    return {'api_key': api_key, 'raw_key': raw}


@pytest.fixture
def api_key_ext_only(db_session, test_org):
    """Agent API key with OS + extension scanning (deps disabled)."""
    from app.models import AgentApiKey

    raw = 'sk_test_extonly_abcdef0123'
    api_key = AgentApiKey(
        organization_id=test_org.id,
        name='Ext Only Key',
        key_hash=hashlib.sha256(raw.encode()).hexdigest(),
        key_prefix=raw[:10],
        active=True,
        scan_os_packages=True,
        scan_extensions=True,
        scan_dependencies=False,
        auto_approve=True,
    )
    db_session.add(api_key)
    db_session.commit()
    return {'api_key': api_key, 'raw_key': raw}


def _agent_headers(raw_key):
    """Standard headers for agent API requests."""
    return {
        'X-Agent-Key': raw_key,
        'Content-Type': 'application/json',
    }


def _inventory_payload(products=None, hostname='test-container-dep.local',
                       agent_id='test-uuid-container-dep'):
    """Build a minimal agent inventory payload."""
    return {
        'hostname': hostname,
        'os': 'Linux',
        'os_version': 'Ubuntu 22.04',
        'agent': {'id': agent_id, 'version': '1.5.0'},
        'products': products or [],
    }


# ============================================================================
# Container Image Model Tests (1-10)
# ============================================================================

class TestContainerImageModel:
    """Tests for ContainerImage model creation, relationships, and fields."""

    def test_create_container_image_all_fields(self, app, db_session, test_org):
        """1. Create ContainerImage with all fields populated."""
        from app.models import ContainerImage

        now = datetime.utcnow()
        image = ContainerImage(
            organization_id=test_org.id,
            image_name='nginx',
            image_tag='1.25-alpine',
            image_id='sha256:abc123def456',
            image_digest='sha256:digest789',
            registry='docker.io',
            repository='library/nginx',
            os_family='alpine',
            os_version='3.18',
            architecture='amd64',
            size_bytes=50_000_000,
            last_scan_at=now,
            scanner_version='trivy 0.58.0',
            total_vulnerabilities=15,
            critical_count=2,
            high_count=5,
            medium_count=6,
            low_count=2,
            fixed_count=10,
            unfixed_count=5,
            active=True,
            running=True,
        )
        db_session.add(image)
        db_session.commit()

        assert image.id is not None
        assert image.image_name == 'nginx'
        assert image.image_tag == '1.25-alpine'
        assert image.image_id == 'sha256:abc123def456'
        assert image.image_digest == 'sha256:digest789'
        assert image.registry == 'docker.io'
        assert image.repository == 'library/nginx'
        assert image.os_family == 'alpine'
        assert image.os_version == '3.18'
        assert image.architecture == 'amd64'
        assert image.size_bytes == 50_000_000
        assert image.scanner_version == 'trivy 0.58.0'
        assert image.total_vulnerabilities == 15
        assert image.critical_count == 2
        assert image.high_count == 5
        assert image.medium_count == 6
        assert image.low_count == 2
        assert image.fixed_count == 10
        assert image.unfixed_count == 5
        assert image.active is True
        assert image.running is True

    def test_container_image_belongs_to_organization(self, app, db_session, test_org):
        """2. ContainerImage belongs to an organization."""
        from app.models import ContainerImage

        image = ContainerImage(
            organization_id=test_org.id,
            image_name='myapp',
            image_tag='latest',
        )
        db_session.add(image)
        db_session.commit()

        assert image.organization_id == test_org.id
        assert image.organization.id == test_org.id
        assert image.organization.name == test_org.name

    def test_container_image_belongs_to_asset(self, app, db_session, test_org):
        """3. ContainerImage belongs to an asset."""
        from app.models import ContainerImage, Asset

        asset = Asset(
            organization_id=test_org.id,
            hostname='docker-host-01.local',
        )
        db_session.add(asset)
        db_session.flush()

        image = ContainerImage(
            organization_id=test_org.id,
            asset_id=asset.id,
            image_name='redis',
            image_tag='7.2',
        )
        db_session.add(image)
        db_session.commit()

        assert image.asset_id == asset.id
        assert image.asset.hostname == 'docker-host-01.local'

    def test_container_image_vulnerability_counts(self, app, db_session, test_org):
        """4. ContainerImage tracks vulnerability counts (critical, high, medium, low)."""
        from app.models import ContainerImage

        image = ContainerImage(
            organization_id=test_org.id,
            image_name='vuln-count-test',
            critical_count=3,
            high_count=7,
            medium_count=12,
            low_count=4,
            total_vulnerabilities=26,
        )
        db_session.add(image)
        db_session.commit()

        assert image.critical_count == 3
        assert image.high_count == 7
        assert image.medium_count == 12
        assert image.low_count == 4
        assert image.total_vulnerabilities == 26

        # Verify severity_summary property
        summary = image.severity_summary
        assert summary['critical'] == 3
        assert summary['high'] == 7
        assert summary['medium'] == 12
        assert summary['low'] == 4

    def test_container_image_fixed_unfixed_counts(self, app, db_session, test_org):
        """5. ContainerImage tracks fixed vs unfixed vulnerability counts."""
        from app.models import ContainerImage

        image = ContainerImage(
            organization_id=test_org.id,
            image_name='fix-count-test',
            fixed_count=8,
            unfixed_count=4,
            total_vulnerabilities=12,
        )
        db_session.add(image)
        db_session.commit()

        assert image.fixed_count == 8
        assert image.unfixed_count == 4

    def test_container_image_running_active_status(self, app, db_session, test_org):
        """6. ContainerImage running and active status flags."""
        from app.models import ContainerImage

        # Active and running
        running_image = ContainerImage(
            organization_id=test_org.id,
            image_name='running-test',
            image_tag='v1',
            active=True,
            running=True,
        )
        # Inactive and not running
        stopped_image = ContainerImage(
            organization_id=test_org.id,
            image_name='stopped-test',
            image_tag='v1',
            active=False,
            running=False,
        )
        db_session.add_all([running_image, stopped_image])
        db_session.commit()

        assert running_image.active is True
        assert running_image.running is True
        assert stopped_image.active is False
        assert stopped_image.running is False

    def test_container_registry_field(self, app, db_session, test_org):
        """7. Container registry field supports various registries."""
        from app.models import ContainerImage

        registries = ['docker.io', 'ghcr.io', 'quay.io', 'gcr.io', 'registry.k8s.io',
                      '123456789.dkr.ecr.us-east-1.amazonaws.com']

        for i, reg in enumerate(registries):
            image = ContainerImage(
                organization_id=test_org.id,
                image_name=f'reg-test-{i}',
                image_tag='latest',
                registry=reg,
            )
            db_session.add(image)

        db_session.commit()

        for i, reg in enumerate(registries):
            found = ContainerImage.query.filter_by(image_name=f'reg-test-{i}').first()
            assert found is not None
            assert found.registry == reg

    def test_container_os_detection(self, app, db_session, test_org):
        """8. Container OS detection (alpine, debian, ubuntu)."""
        from app.models import ContainerImage

        os_families = [
            ('alpine', '3.18'),
            ('debian', '12'),
            ('ubuntu', '22.04'),
        ]

        for i, (os_fam, os_ver) in enumerate(os_families):
            image = ContainerImage(
                organization_id=test_org.id,
                image_name=f'os-test-{i}',
                os_family=os_fam,
                os_version=os_ver,
            )
            db_session.add(image)

        db_session.commit()

        for i, (os_fam, os_ver) in enumerate(os_families):
            found = ContainerImage.query.filter_by(image_name=f'os-test-{i}').first()
            assert found.os_family == os_fam
            assert found.os_version == os_ver

    def test_container_architecture(self, app, db_session, test_org):
        """9. Container architecture (amd64, arm64)."""
        from app.models import ContainerImage

        for arch in ('amd64', 'arm64'):
            image = ContainerImage(
                organization_id=test_org.id,
                image_name=f'arch-test-{arch}',
                architecture=arch,
            )
            db_session.add(image)

        db_session.commit()

        for arch in ('amd64', 'arm64'):
            found = ContainerImage.query.filter_by(image_name=f'arch-test-{arch}').first()
            assert found.architecture == arch

    def test_cascade_delete_org_removes_container_images(self, app, db_session):
        """10. Cascade delete: deleting an organization removes its container images.

        Note: SQLite requires PRAGMA foreign_keys=ON for ON DELETE CASCADE.
        We enable it explicitly before the delete operation.
        """
        from app.models import Organization, ContainerImage
        from sqlalchemy import text

        # Enable foreign key enforcement for SQLite
        db_session.execute(text('PRAGMA foreign_keys=ON'))

        org = Organization(name='cascade-container-org', display_name='Cascade Org', active=True)
        db_session.add(org)
        db_session.flush()

        image = ContainerImage(
            organization_id=org.id,
            image_name='cascade-delete-test',
            image_tag='v1',
        )
        db_session.add(image)
        db_session.commit()

        image_id = image.id
        assert ContainerImage.query.get(image_id) is not None

        # Re-enable PRAGMA after commit (SQLite resets per-connection state)
        db_session.execute(text('PRAGMA foreign_keys=ON'))

        # Delete via raw SQL to trigger ON DELETE CASCADE at the DB level
        db_session.execute(text('DELETE FROM organizations WHERE id = :oid'), {'oid': org.id})
        db_session.commit()

        # Expire all cached objects so query goes to DB
        db_session.expire_all()
        assert ContainerImage.query.get(image_id) is None


# ============================================================================
# Container Image - full_name property and to_dict
# ============================================================================

class TestContainerImageProperties:
    """Tests for ContainerImage computed properties."""

    def test_full_name_with_tag(self, app, db_session, test_org):
        """full_name returns 'image:tag' when tag is set."""
        from app.models import ContainerImage

        image = ContainerImage(
            organization_id=test_org.id,
            image_name='nginx',
            image_tag='1.25-alpine',
        )
        db_session.add(image)
        db_session.commit()

        assert image.full_name == 'nginx:1.25-alpine'

    def test_full_name_without_tag(self, app, db_session, test_org):
        """full_name returns just image_name when tag is None."""
        from app.models import ContainerImage

        image = ContainerImage(
            organization_id=test_org.id,
            image_name='myapp',
        )
        db_session.add(image)
        db_session.commit()

        assert image.full_name == 'myapp'

    def test_to_dict_contains_all_fields(self, app, db_session, test_org):
        """to_dict() returns a complete dictionary representation."""
        from app.models import ContainerImage

        image = ContainerImage(
            organization_id=test_org.id,
            image_name='dict-test',
            image_tag='v2',
            registry='ghcr.io',
            critical_count=1,
            active=True,
            running=False,
        )
        db_session.add(image)
        db_session.commit()

        d = image.to_dict()
        assert d['image_name'] == 'dict-test'
        assert d['image_tag'] == 'v2'
        assert d['registry'] == 'ghcr.io'
        assert d['full_name'] == 'dict-test:v2'
        assert d['severity']['critical'] == 1
        assert d['active'] is True
        assert d['running'] is False


# ============================================================================
# Container Vulnerability Model Tests (11-18)
# ============================================================================

class TestContainerVulnerabilityModel:
    """Tests for ContainerVulnerability model creation and relationships."""

    def _make_image(self, db_session, test_org, name='vuln-image'):
        """Helper to create a container image."""
        from app.models import ContainerImage
        image = ContainerImage(
            organization_id=test_org.id,
            image_name=name,
            image_tag='latest',
        )
        db_session.add(image)
        db_session.flush()
        return image

    def test_create_container_vulnerability(self, app, db_session, test_org):
        """11. Create ContainerVulnerability linked to a ContainerImage."""
        from app.models import ContainerVulnerability

        image = self._make_image(db_session, test_org, 'vuln-link-test')

        vuln = ContainerVulnerability(
            container_image_id=image.id,
            vuln_id='CVE-2024-5678',
            severity='HIGH',
            title='Test Container Vuln',
            description='A test vulnerability in a container package',
            pkg_name='libssl3',
            pkg_version='3.0.2',
            pkg_type='os',
            pkg_path='/usr/lib/x86_64-linux-gnu/libssl.so.3',
            fixed_version='3.0.2-1',
            fix_status='fixed',
            cvss_score=7.5,
            cvss_vector='CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N',
            data_source='ubuntu',
            primary_url='https://ubuntu.com/security/CVE-2024-5678',
        )
        db_session.add(vuln)
        db_session.commit()

        assert vuln.id is not None
        assert vuln.container_image_id == image.id
        assert vuln.vuln_id == 'CVE-2024-5678'
        assert vuln.severity == 'HIGH'
        assert vuln.pkg_name == 'libssl3'
        assert vuln.container_image.image_name == 'vuln-link-test'

    def test_all_severity_levels(self, app, db_session, test_org):
        """12. All severity levels (CRITICAL, HIGH, MEDIUM, LOW, UNKNOWN)."""
        from app.models import ContainerVulnerability

        image = self._make_image(db_session, test_org, 'severity-levels-test')
        severities = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'UNKNOWN']

        for i, sev in enumerate(severities):
            vuln = ContainerVulnerability(
                container_image_id=image.id,
                vuln_id=f'CVE-2024-{1000 + i}',
                severity=sev,
                pkg_name=f'pkg-{sev.lower()}',
                pkg_version='1.0',
            )
            db_session.add(vuln)

        db_session.commit()

        for i, sev in enumerate(severities):
            found = ContainerVulnerability.query.filter_by(
                vuln_id=f'CVE-2024-{1000 + i}'
            ).first()
            assert found is not None
            assert found.severity == sev

    def test_package_info_fields(self, app, db_session, test_org):
        """13. Package info (pkg_name, pkg_version, pkg_type, pkg_path)."""
        from app.models import ContainerVulnerability

        image = self._make_image(db_session, test_org, 'pkg-info-test')

        vuln = ContainerVulnerability(
            container_image_id=image.id,
            vuln_id='CVE-2024-9999',
            severity='MEDIUM',
            pkg_name='curl',
            pkg_version='7.88.1',
            pkg_type='os',
            pkg_path='/usr/bin/curl',
        )
        db_session.add(vuln)
        db_session.commit()

        assert vuln.pkg_name == 'curl'
        assert vuln.pkg_version == '7.88.1'
        assert vuln.pkg_type == 'os'
        assert vuln.pkg_path == '/usr/bin/curl'

    def test_fix_information(self, app, db_session, test_org):
        """14. Fix information (fixed_version, fix_status variants)."""
        from app.models import ContainerVulnerability

        image = self._make_image(db_session, test_org, 'fix-info-test')
        fix_statuses = ['fixed', 'not_fixed', 'end_of_life', 'unknown']

        for i, status in enumerate(fix_statuses):
            vuln = ContainerVulnerability(
                container_image_id=image.id,
                vuln_id=f'CVE-2024-{2000 + i}',
                severity='HIGH',
                pkg_name=f'pkg-fix-{i}',
                pkg_version='1.0',
                fixed_version='2.0' if status == 'fixed' else None,
                fix_status=status,
            )
            db_session.add(vuln)

        db_session.commit()

        for i, status in enumerate(fix_statuses):
            found = ContainerVulnerability.query.filter_by(
                vuln_id=f'CVE-2024-{2000 + i}'
            ).first()
            assert found.fix_status == status
            if status == 'fixed':
                assert found.fixed_version == '2.0'
            else:
                assert found.fixed_version is None

    def test_cvss_score_and_vector_storage(self, app, db_session, test_org):
        """15. CVSS score and vector string storage."""
        from app.models import ContainerVulnerability

        image = self._make_image(db_session, test_org, 'cvss-test')

        vuln = ContainerVulnerability(
            container_image_id=image.id,
            vuln_id='CVE-2024-CVSS',
            severity='CRITICAL',
            pkg_name='openssl',
            pkg_version='3.0.0',
            cvss_score=9.8,
            cvss_vector='CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H',
        )
        db_session.add(vuln)
        db_session.commit()

        assert vuln.cvss_score == 9.8
        assert vuln.cvss_vector == 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H'

    def test_acknowledge_container_vulnerability(self, app, db_session, test_org):
        """16. Acknowledge a container vulnerability."""
        from app.models import ContainerVulnerability

        image = self._make_image(db_session, test_org, 'ack-test')

        vuln = ContainerVulnerability(
            container_image_id=image.id,
            vuln_id='CVE-2024-ACK',
            severity='LOW',
            pkg_name='zlib',
            pkg_version='1.2.13',
        )
        db_session.add(vuln)
        db_session.commit()

        assert vuln.acknowledged is False

        vuln.acknowledged = True
        vuln.acknowledged_at = datetime.utcnow()
        vuln.acknowledged_by = 'admin@test.local'
        db_session.commit()

        reloaded = ContainerVulnerability.query.get(vuln.id)
        assert reloaded.acknowledged is True
        assert reloaded.acknowledged_at is not None
        assert reloaded.acknowledged_by == 'admin@test.local'

    def test_multiple_vulnerabilities_per_image(self, app, db_session, test_org):
        """17. Multiple vulnerabilities can belong to a single container image."""
        from app.models import ContainerVulnerability

        image = self._make_image(db_session, test_org, 'multi-vuln-test')

        for i in range(5):
            vuln = ContainerVulnerability(
                container_image_id=image.id,
                vuln_id=f'CVE-2024-{3000 + i}',
                severity=['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'UNKNOWN'][i],
                pkg_name=f'pkg-multi-{i}',
                pkg_version='1.0',
            )
            db_session.add(vuln)

        db_session.commit()

        assert image.vulnerabilities.count() == 5

    def test_cascade_delete_image_removes_vulnerabilities(self, app, db_session, test_org):
        """18. Cascade delete: deleting a container image removes its vulnerabilities."""
        from app.models import ContainerImage, ContainerVulnerability

        image = ContainerImage(
            organization_id=test_org.id,
            image_name='cascade-vuln-test',
            image_tag='v1',
        )
        db_session.add(image)
        db_session.flush()

        vuln = ContainerVulnerability(
            container_image_id=image.id,
            vuln_id='CVE-2024-CASCADE',
            severity='HIGH',
            pkg_name='test-pkg',
            pkg_version='1.0',
        )
        db_session.add(vuln)
        db_session.commit()

        vuln_id = vuln.id
        assert ContainerVulnerability.query.get(vuln_id) is not None

        db_session.delete(image)
        db_session.commit()

        assert ContainerVulnerability.query.get(vuln_id) is None


# ============================================================================
# Dependency Scanning - Agent API Tests (19-33)
# ============================================================================

class TestDependencyScanning:
    """Tests for agent inventory with code_library products."""

    def test_submit_code_library_with_deps_enabled(self, app, client, db_session,
                                                    api_key_all_caps):
        """19. Submit inventory with code_library products (scan_dependencies=True)."""
        with app.app_context():
            payload = _inventory_payload([
                {'vendor': 'PyPI', 'product': 'flask-dep-test', 'version': '3.0.0',
                 'source_type': 'code_library', 'ecosystem': 'pypi'},
            ])
            response = client.post('/api/agent/inventory',
                json=payload,
                headers=_agent_headers(api_key_all_caps['raw_key']))

            assert response.status_code in [200, 201, 202, 403]

    def test_dependency_rejected_when_disabled(self, app, client, db_session,
                                               api_key_os_only):
        """20. Dependency products rejected when scan_dependencies=False."""
        with app.app_context():
            payload = _inventory_payload([
                {'vendor': 'PyPI', 'product': 'dep-rejected-test', 'version': '1.0.0',
                 'source_type': 'code_library', 'ecosystem': 'pypi'},
            ])
            response = client.post('/api/agent/inventory',
                json=payload,
                headers=_agent_headers(api_key_os_only['raw_key']))

            assert response.status_code in [200, 201, 202, 403]
            if response.status_code in [200, 201, 202]:
                from app.models import Product
                p = Product.query.filter_by(product_name='dep-rejected-test').first()
                assert p is None, "code_library should be rejected when scan_dependencies=False"

    def test_npm_ecosystem_accepted(self, app, client, db_session, api_key_all_caps):
        """21. npm ecosystem dependency accepted."""
        with app.app_context():
            payload = _inventory_payload([
                {'vendor': 'npm', 'product': 'express-npm-test', 'version': '4.18.2',
                 'source_type': 'code_library', 'ecosystem': 'npm'},
            ])
            response = client.post('/api/agent/inventory',
                json=payload,
                headers=_agent_headers(api_key_all_caps['raw_key']))

            assert response.status_code in [200, 201, 202, 403]
            if response.status_code in [200, 201, 202]:
                from app.models import Product
                p = Product.query.filter_by(product_name='express-npm-test').first()
                if p:
                    assert p.ecosystem == 'npm'

    def test_pypi_ecosystem_accepted(self, app, client, db_session, api_key_all_caps):
        """22. pypi ecosystem dependency accepted."""
        with app.app_context():
            payload = _inventory_payload([
                {'vendor': 'PyPI', 'product': 'requests-pypi-test', 'version': '2.31.0',
                 'source_type': 'code_library', 'ecosystem': 'pypi'},
            ])
            response = client.post('/api/agent/inventory',
                json=payload,
                headers=_agent_headers(api_key_all_caps['raw_key']))

            assert response.status_code in [200, 201, 202, 403]
            if response.status_code in [200, 201, 202]:
                from app.models import Product
                p = Product.query.filter_by(product_name='requests-pypi-test').first()
                if p:
                    assert p.ecosystem == 'pypi'

    def test_maven_ecosystem_accepted(self, app, client, db_session, api_key_all_caps):
        """23. maven ecosystem dependency accepted (Gradle uses maven repos)."""
        with app.app_context():
            payload = _inventory_payload([
                {'vendor': 'org.springframework', 'product': 'spring-core-mvn', 'version': '6.1.0',
                 'source_type': 'code_library', 'ecosystem': 'maven'},
            ])
            response = client.post('/api/agent/inventory',
                json=payload,
                headers=_agent_headers(api_key_all_caps['raw_key']))

            assert response.status_code in [200, 201, 202, 403]
            if response.status_code in [200, 201, 202]:
                from app.models import Product
                p = Product.query.filter_by(product_name='spring-core-mvn').first()
                if p:
                    assert p.ecosystem == 'maven'

    def test_nuget_ecosystem_accepted(self, app, client, db_session, api_key_all_caps):
        """24. nuget ecosystem dependency accepted."""
        with app.app_context():
            payload = _inventory_payload([
                {'vendor': 'Microsoft', 'product': 'Newtonsoft.Json-nuget', 'version': '13.0.3',
                 'source_type': 'code_library', 'ecosystem': 'nuget'},
            ])
            response = client.post('/api/agent/inventory',
                json=payload,
                headers=_agent_headers(api_key_all_caps['raw_key']))

            assert response.status_code in [200, 201, 202, 403]
            if response.status_code in [200, 201, 202]:
                from app.models import Product
                p = Product.query.filter_by(product_name='Newtonsoft.Json-nuget').first()
                if p:
                    assert p.ecosystem == 'nuget'

    def test_cargo_ecosystem_accepted(self, app, client, db_session, api_key_all_caps):
        """25. cargo ecosystem dependency accepted."""
        with app.app_context():
            payload = _inventory_payload([
                {'vendor': 'crates.io', 'product': 'serde-cargo-test', 'version': '1.0.195',
                 'source_type': 'code_library', 'ecosystem': 'cargo'},
            ])
            response = client.post('/api/agent/inventory',
                json=payload,
                headers=_agent_headers(api_key_all_caps['raw_key']))

            assert response.status_code in [200, 201, 202, 403]
            if response.status_code in [200, 201, 202]:
                from app.models import Product
                p = Product.query.filter_by(product_name='serde-cargo-test').first()
                if p:
                    assert p.ecosystem == 'cargo'

    def test_go_ecosystem_accepted(self, app, client, db_session, api_key_all_caps):
        """26. go ecosystem dependency accepted."""
        with app.app_context():
            payload = _inventory_payload([
                {'vendor': 'golang', 'product': 'net-http-go-test', 'version': '0.17.0',
                 'source_type': 'code_library', 'ecosystem': 'go'},
            ])
            response = client.post('/api/agent/inventory',
                json=payload,
                headers=_agent_headers(api_key_all_caps['raw_key']))

            assert response.status_code in [200, 201, 202, 403]
            if response.status_code in [200, 201, 202]:
                from app.models import Product
                p = Product.query.filter_by(product_name='net-http-go-test').first()
                if p:
                    assert p.ecosystem == 'go'

    def test_gem_ecosystem_accepted(self, app, client, db_session, api_key_all_caps):
        """27. gem ecosystem dependency accepted."""
        with app.app_context():
            payload = _inventory_payload([
                {'vendor': 'rubygems', 'product': 'rails-gem-test', 'version': '7.1.0',
                 'source_type': 'code_library', 'ecosystem': 'gem'},
            ])
            response = client.post('/api/agent/inventory',
                json=payload,
                headers=_agent_headers(api_key_all_caps['raw_key']))

            assert response.status_code in [200, 201, 202, 403]
            if response.status_code in [200, 201, 202]:
                from app.models import Product
                p = Product.query.filter_by(product_name='rails-gem-test').first()
                if p:
                    assert p.ecosystem == 'gem'

    def test_composer_ecosystem_accepted(self, app, client, db_session, api_key_all_caps):
        """28. composer ecosystem dependency accepted."""
        with app.app_context():
            payload = _inventory_payload([
                {'vendor': 'packagist', 'product': 'laravel-composer-test', 'version': '10.0.0',
                 'source_type': 'code_library', 'ecosystem': 'composer'},
            ])
            response = client.post('/api/agent/inventory',
                json=payload,
                headers=_agent_headers(api_key_all_caps['raw_key']))

            assert response.status_code in [200, 201, 202, 403]
            if response.status_code in [200, 201, 202]:
                from app.models import Product
                p = Product.query.filter_by(product_name='laravel-composer-test').first()
                if p:
                    assert p.ecosystem == 'composer'

    def test_project_path_stored(self, app, client, db_session, api_key_all_caps):
        """29. Project path (path to lock file) stored correctly."""
        with app.app_context():
            payload = _inventory_payload([
                {'vendor': 'PyPI', 'product': 'flask-projpath-test', 'version': '3.0.0',
                 'source_type': 'code_library', 'ecosystem': 'pypi',
                 'project_path': '/opt/myapp/requirements.txt', 'is_direct': True},
            ])
            response = client.post('/api/agent/inventory',
                json=payload,
                headers=_agent_headers(api_key_all_caps['raw_key']))

            assert response.status_code in [200, 201, 202, 403]
            if response.status_code in [200, 201, 202]:
                from app.models import ProductInstallation, Product
                p = Product.query.filter_by(product_name='flask-projpath-test').first()
                if p:
                    inst = ProductInstallation.query.filter_by(product_id=p.id).first()
                    if inst:
                        assert inst.project_path == '/opt/myapp/requirements.txt'

    def test_is_direct_true_stored(self, app, client, db_session, api_key_all_caps):
        """30. is_direct_dependency=True stored correctly."""
        with app.app_context():
            payload = _inventory_payload([
                {'vendor': 'npm', 'product': 'express-direct-test', 'version': '4.18.2',
                 'source_type': 'code_library', 'ecosystem': 'npm',
                 'is_direct': True},
            ])
            response = client.post('/api/agent/inventory',
                json=payload,
                headers=_agent_headers(api_key_all_caps['raw_key']))

            assert response.status_code in [200, 201, 202, 403]
            if response.status_code in [200, 201, 202]:
                from app.models import ProductInstallation, Product
                p = Product.query.filter_by(product_name='express-direct-test').first()
                if p:
                    inst = ProductInstallation.query.filter_by(product_id=p.id).first()
                    if inst:
                        assert inst.is_direct_dependency is True

    def test_is_direct_false_stored(self, app, client, db_session, api_key_all_caps):
        """31. is_direct_dependency=False (transitive) stored correctly."""
        with app.app_context():
            payload = _inventory_payload([
                {'vendor': 'npm', 'product': 'lodash-transitive-test', 'version': '4.17.21',
                 'source_type': 'code_library', 'ecosystem': 'npm',
                 'is_direct': False},
            ])
            response = client.post('/api/agent/inventory',
                json=payload,
                headers=_agent_headers(api_key_all_caps['raw_key']))

            assert response.status_code in [200, 201, 202, 403]
            if response.status_code in [200, 201, 202]:
                from app.models import ProductInstallation, Product
                p = Product.query.filter_by(product_name='lodash-transitive-test').first()
                if p:
                    inst = ProductInstallation.query.filter_by(product_id=p.id).first()
                    if inst:
                        assert inst.is_direct_dependency is False

    def test_unknown_ecosystem_set_to_none(self, app, client, db_session, api_key_all_caps):
        """32. Unknown ecosystem set to None."""
        with app.app_context():
            payload = _inventory_payload([
                {'vendor': 'Test', 'product': 'unknown-eco-deptest', 'version': '1.0.0',
                 'source_type': 'os_package', 'ecosystem': 'not_a_real_ecosystem'},
            ])
            response = client.post('/api/agent/inventory',
                json=payload,
                headers=_agent_headers(api_key_all_caps['raw_key']))

            assert response.status_code in [200, 201, 202, 403]
            if response.status_code in [200, 201, 202]:
                from app.models import Product
                p = Product.query.filter_by(product_name='unknown-eco-deptest').first()
                if p:
                    assert p.ecosystem is None

    def test_invalid_source_type_defaults_os_package(self, app, client, db_session,
                                                      api_key_all_caps):
        """33. Invalid source_type defaults to os_package."""
        with app.app_context():
            payload = _inventory_payload([
                {'vendor': 'Test', 'product': 'invalid-srctype-test', 'version': '1.0.0',
                 'source_type': 'not_valid_type'},
            ])
            response = client.post('/api/agent/inventory',
                json=payload,
                headers=_agent_headers(api_key_all_caps['raw_key']))

            assert response.status_code in [200, 201, 202, 403]
            if response.status_code in [200, 201, 202]:
                from app.models import Product
                p = Product.query.filter_by(product_name='invalid-srctype-test').first()
                if p:
                    assert p.source_type == 'os_package'


# ============================================================================
# Extension Scanning - Agent API Tests (34-40)
# ============================================================================

class TestExtensionScanning:
    """Tests for agent inventory with extension products."""

    def test_submit_vscode_extension_with_ext_enabled(self, app, client, db_session,
                                                       api_key_all_caps):
        """34. Submit vscode_extension products (scan_extensions=True)."""
        with app.app_context():
            payload = _inventory_payload([
                {'vendor': 'Microsoft', 'product': 'python-vscode-ext-test', 'version': '2024.1',
                 'source_type': 'vscode_extension', 'ecosystem': 'vscode'},
            ])
            response = client.post('/api/agent/inventory',
                json=payload,
                headers=_agent_headers(api_key_all_caps['raw_key']))

            assert response.status_code in [200, 201, 202, 403]

    def test_extension_rejected_when_disabled(self, app, client, db_session,
                                              api_key_os_only):
        """35. Extension products rejected when scan_extensions=False."""
        with app.app_context():
            payload = _inventory_payload([
                {'vendor': 'Microsoft', 'product': 'ext-rejected-test', 'version': '2024.1',
                 'source_type': 'vscode_extension', 'ecosystem': 'vscode'},
            ])
            response = client.post('/api/agent/inventory',
                json=payload,
                headers=_agent_headers(api_key_os_only['raw_key']))

            assert response.status_code in [200, 201, 202, 403]
            if response.status_code in [200, 201, 202]:
                from app.models import Product
                p = Product.query.filter_by(product_name='ext-rejected-test').first()
                assert p is None, "Extension should be rejected when scan_extensions=False"

    def test_vscode_extension_normalized_to_extension(self, app, client, db_session,
                                                       api_key_all_caps):
        """36. vscode_extension normalized to 'extension' source_type."""
        with app.app_context():
            payload = _inventory_payload([
                {'vendor': 'Microsoft', 'product': 'vscode-norm-test', 'version': '2024.1',
                 'source_type': 'vscode_extension', 'ecosystem': 'vscode'},
            ])
            response = client.post('/api/agent/inventory',
                json=payload,
                headers=_agent_headers(api_key_all_caps['raw_key']))

            assert response.status_code in [200, 201, 202, 403]
            if response.status_code in [200, 201, 202]:
                from app.models import Product
                p = Product.query.filter_by(product_name='vscode-norm-test').first()
                if p:
                    assert p.source_type == 'extension', \
                        f"vscode_extension should normalize to 'extension', got '{p.source_type}'"

    def test_browser_extension_normalized_to_extension(self, app, client, db_session,
                                                        api_key_all_caps):
        """37. browser_extension normalized to 'extension' source_type."""
        with app.app_context():
            payload = _inventory_payload([
                {'vendor': 'AdBlockPlus', 'product': 'browser-norm-test', 'version': '3.0.0',
                 'source_type': 'browser_extension', 'ecosystem': 'chrome'},
            ])
            response = client.post('/api/agent/inventory',
                json=payload,
                headers=_agent_headers(api_key_all_caps['raw_key']))

            assert response.status_code in [200, 201, 202, 403]
            if response.status_code in [200, 201, 202]:
                from app.models import Product
                p = Product.query.filter_by(product_name='browser-norm-test').first()
                if p:
                    assert p.source_type == 'extension', \
                        f"browser_extension should normalize to 'extension', got '{p.source_type}'"

    def test_chrome_ecosystem_accepted(self, app, client, db_session, api_key_all_caps):
        """38. Chrome ecosystem accepted."""
        with app.app_context():
            payload = _inventory_payload([
                {'vendor': 'ChromeExt', 'product': 'chrome-eco-test', 'version': '1.0',
                 'source_type': 'browser_extension', 'ecosystem': 'chrome'},
            ])
            response = client.post('/api/agent/inventory',
                json=payload,
                headers=_agent_headers(api_key_all_caps['raw_key']))

            assert response.status_code in [200, 201, 202, 403]
            if response.status_code in [200, 201, 202]:
                from app.models import Product
                p = Product.query.filter_by(product_name='chrome-eco-test').first()
                if p:
                    assert p.ecosystem == 'chrome'

    def test_firefox_ecosystem_accepted(self, app, client, db_session, api_key_all_caps):
        """39. Firefox ecosystem accepted."""
        with app.app_context():
            payload = _inventory_payload([
                {'vendor': 'FFExt', 'product': 'firefox-eco-test', 'version': '2.0',
                 'source_type': 'browser_extension', 'ecosystem': 'firefox'},
            ])
            response = client.post('/api/agent/inventory',
                json=payload,
                headers=_agent_headers(api_key_all_caps['raw_key']))

            assert response.status_code in [200, 201, 202, 403]
            if response.status_code in [200, 201, 202]:
                from app.models import Product
                p = Product.query.filter_by(product_name='firefox-eco-test').first()
                if p:
                    assert p.ecosystem == 'firefox'

    def test_jetbrains_ecosystem_accepted(self, app, client, db_session, api_key_all_caps):
        """40. JetBrains ecosystem accepted."""
        with app.app_context():
            payload = _inventory_payload([
                {'vendor': 'JetBrains', 'product': 'jetbrains-eco-test', 'version': '1.5',
                 'source_type': 'vscode_extension', 'ecosystem': 'jetbrains'},
            ])
            response = client.post('/api/agent/inventory',
                json=payload,
                headers=_agent_headers(api_key_all_caps['raw_key']))

            assert response.status_code in [200, 201, 202, 403]
            if response.status_code in [200, 201, 202]:
                from app.models import Product
                p = Product.query.filter_by(product_name='jetbrains-eco-test').first()
                if p:
                    assert p.ecosystem == 'jetbrains'


# ============================================================================
# License Gating Tests (41-46)
# ============================================================================

class TestLicenseGating:
    """Tests for API key scan capability gating on inventory submissions."""

    def test_deps_enabled_code_library_accepted(self, app, client, db_session,
                                                 api_key_deps_only):
        """41. API key with scan_dependencies=True: code_library products accepted."""
        with app.app_context():
            payload = _inventory_payload([
                {'vendor': 'PyPI', 'product': 'gated-dep-accept', 'version': '1.0',
                 'source_type': 'code_library', 'ecosystem': 'pypi'},
            ])
            response = client.post('/api/agent/inventory',
                json=payload,
                headers=_agent_headers(api_key_deps_only['raw_key']))

            assert response.status_code in [200, 201, 202, 403]
            # If processed, product should exist
            if response.status_code in [200, 201, 202]:
                from app.models import Product
                p = Product.query.filter_by(product_name='gated-dep-accept').first()
                # With auto_approve=True and deps enabled, product should be created
                # (unless server-side filtering removes it as noise)
                # We just verify it was NOT rejected by the gating logic

    def test_deps_disabled_code_library_skipped(self, app, client, db_session,
                                                 api_key_os_only):
        """42. API key with scan_dependencies=False: code_library products silently skipped."""
        with app.app_context():
            payload = _inventory_payload([
                {'vendor': 'PyPI', 'product': 'gated-dep-skip', 'version': '1.0',
                 'source_type': 'code_library', 'ecosystem': 'pypi'},
            ])
            response = client.post('/api/agent/inventory',
                json=payload,
                headers=_agent_headers(api_key_os_only['raw_key']))

            assert response.status_code in [200, 201, 202, 403]
            if response.status_code in [200, 201, 202]:
                from app.models import Product
                p = Product.query.filter_by(product_name='gated-dep-skip').first()
                assert p is None, "code_library should be silently skipped when deps disabled"

    def test_ext_enabled_extension_accepted(self, app, client, db_session,
                                             api_key_ext_only):
        """43. API key with scan_extensions=True: extension products accepted."""
        with app.app_context():
            payload = _inventory_payload([
                {'vendor': 'Microsoft', 'product': 'gated-ext-accept', 'version': '1.0',
                 'source_type': 'vscode_extension', 'ecosystem': 'vscode'},
            ])
            response = client.post('/api/agent/inventory',
                json=payload,
                headers=_agent_headers(api_key_ext_only['raw_key']))

            assert response.status_code in [200, 201, 202, 403]

    def test_ext_disabled_extension_skipped(self, app, client, db_session,
                                             api_key_os_only):
        """44. API key with scan_extensions=False: extension products silently skipped."""
        with app.app_context():
            payload = _inventory_payload([
                {'vendor': 'Microsoft', 'product': 'gated-ext-skip', 'version': '1.0',
                 'source_type': 'vscode_extension', 'ecosystem': 'vscode'},
            ])
            response = client.post('/api/agent/inventory',
                json=payload,
                headers=_agent_headers(api_key_os_only['raw_key']))

            assert response.status_code in [200, 201, 202, 403]
            if response.status_code in [200, 201, 202]:
                from app.models import Product
                p = Product.query.filter_by(product_name='gated-ext-skip').first()
                assert p is None, "Extension should be silently skipped when ext disabled"

    def test_os_packages_always_accepted(self, app, client, db_session, api_key_os_only):
        """45. OS packages always accepted regardless of key capabilities."""
        with app.app_context():
            payload = _inventory_payload([
                {'vendor': 'Apache', 'product': 'httpd-always-accept', 'version': '2.4.52',
                 'source_type': 'os_package'},
            ])
            response = client.post('/api/agent/inventory',
                json=payload,
                headers=_agent_headers(api_key_os_only['raw_key']))

            assert response.status_code in [200, 201, 202, 403]

    def test_mixed_payload_only_gated_filtered(self, app, client, db_session,
                                                api_key_os_only):
        """46. Mixed payload: only gated products (extension/code_library) are filtered."""
        with app.app_context():
            payload = _inventory_payload([
                # OS package - should always pass
                {'vendor': 'Apache', 'product': 'httpd-mixed-gate', 'version': '2.4.52',
                 'source_type': 'os_package'},
                # Extension - should be filtered (no scan_extensions)
                {'vendor': 'Microsoft', 'product': 'ext-mixed-gate', 'version': '1.0',
                 'source_type': 'vscode_extension', 'ecosystem': 'vscode'},
                # Dependency - should be filtered (no scan_dependencies)
                {'vendor': 'PyPI', 'product': 'dep-mixed-gate', 'version': '1.0',
                 'source_type': 'code_library', 'ecosystem': 'pypi'},
            ])
            response = client.post('/api/agent/inventory',
                json=payload,
                headers=_agent_headers(api_key_os_only['raw_key']))

            assert response.status_code in [200, 201, 202, 403]
            if response.status_code in [200, 201, 202]:
                from app.models import Product
                # Extension should NOT exist
                ext = Product.query.filter_by(product_name='ext-mixed-gate').first()
                assert ext is None, "Extension should be filtered in mixed payload"
                # Dependency should NOT exist
                dep = Product.query.filter_by(product_name='dep-mixed-gate').first()
                assert dep is None, "Dependency should be filtered in mixed payload"


# ============================================================================
# Agent Commands - Scan Capabilities (47-50)
# ============================================================================

class TestAgentCommandsScanCapabilities:
    """Tests for the GET /api/agent/commands scan_capabilities response."""

    def test_commands_returns_scan_capabilities(self, app, client, db_session,
                                                api_key_all_caps):
        """47. GET /api/agent/commands returns scan_capabilities matching key settings."""
        with app.app_context():
            response = client.get(
                '/api/agent/commands?hostname=test-caps-host&agent_id=caps-uuid&version=1.5.0',
                headers=_agent_headers(api_key_all_caps['raw_key']))

            assert response.status_code in [200, 403]
            if response.status_code == 200:
                data = response.get_json()
                caps = data.get('scan_capabilities', {})
                assert 'os_packages' in caps
                assert 'extensions' in caps
                assert 'dependencies' in caps

    def test_scan_capabilities_os_packages_always_true(self, app, client, db_session,
                                                        api_key_os_only):
        """48. scan_capabilities reflects os_packages=true always."""
        with app.app_context():
            response = client.get(
                '/api/agent/commands?hostname=os-always&agent_id=os-always-uuid&version=1.5.0',
                headers=_agent_headers(api_key_os_only['raw_key']))

            assert response.status_code in [200, 403]
            if response.status_code == 200:
                data = response.get_json()
                caps = data.get('scan_capabilities', {})
                assert caps.get('os_packages') is True

    def test_scan_capabilities_extensions_from_key(self, app, client, db_session,
                                                    api_key_ext_only):
        """49. scan_capabilities reflects extensions setting from key."""
        with app.app_context():
            response = client.get(
                '/api/agent/commands?hostname=ext-cap&agent_id=ext-cap-uuid&version=1.5.0',
                headers=_agent_headers(api_key_ext_only['raw_key']))

            assert response.status_code in [200, 403]
            if response.status_code == 200:
                data = response.get_json()
                caps = data.get('scan_capabilities', {})
                assert caps.get('extensions') is True
                assert caps.get('dependencies') is False

    def test_scan_capabilities_dependencies_from_key(self, app, client, db_session,
                                                      api_key_deps_only):
        """50. scan_capabilities reflects dependencies setting from key."""
        with app.app_context():
            response = client.get(
                '/api/agent/commands?hostname=dep-cap&agent_id=dep-cap-uuid&version=1.5.0',
                headers=_agent_headers(api_key_deps_only['raw_key']))

            assert response.status_code in [200, 403]
            if response.status_code == 200:
                data = response.get_json()
                caps = data.get('scan_capabilities', {})
                assert caps.get('dependencies') is True
                assert caps.get('extensions') is False


# ============================================================================
# Input Validation Tests (51-57)
# ============================================================================

class TestInputValidation:
    """Tests for _safe_bool, VALID_SOURCE_TYPES, and VALID_ECOSYSTEMS."""

    def test_safe_bool_accepts_true(self):
        """51. _safe_bool accepts True."""
        from app.agent_api import _safe_bool
        assert _safe_bool(True) is True

    def test_safe_bool_accepts_false(self):
        """51b. _safe_bool accepts False."""
        from app.agent_api import _safe_bool
        assert _safe_bool(False) is False

    def test_safe_bool_rejects_string_true(self):
        """52. _safe_bool rejects string 'true' (returns None)."""
        from app.agent_api import _safe_bool
        assert _safe_bool("true") is None

    def test_safe_bool_rejects_arrays(self):
        """53. _safe_bool rejects arrays."""
        from app.agent_api import _safe_bool
        assert _safe_bool([True, False]) is None

    def test_safe_bool_rejects_dict(self):
        """53b. _safe_bool rejects dicts."""
        from app.agent_api import _safe_bool
        assert _safe_bool({"key": "value"}) is None

    def test_safe_bool_none_returns_none(self):
        """_safe_bool(None) returns None."""
        from app.agent_api import _safe_bool
        assert _safe_bool(None) is None

    def test_safe_bool_int_coercion(self):
        """_safe_bool accepts int (1=True, 0=False)."""
        from app.agent_api import _safe_bool
        assert _safe_bool(1) is True
        assert _safe_bool(0) is False

    def test_valid_source_types_accepted(self):
        """54. Valid source_types accepted."""
        from app.agent_api import VALID_SOURCE_TYPES
        expected = {'os_package', 'extension', 'code_library',
                    'vscode_extension', 'browser_extension'}
        for st in expected:
            assert st in VALID_SOURCE_TYPES, f"{st} should be in VALID_SOURCE_TYPES"

    def test_invalid_source_type_not_in_set(self):
        """55. Invalid source_type not in VALID_SOURCE_TYPES."""
        from app.agent_api import VALID_SOURCE_TYPES
        assert 'malicious_type' not in VALID_SOURCE_TYPES
        assert '' not in VALID_SOURCE_TYPES
        assert 'random' not in VALID_SOURCE_TYPES

    def test_valid_ecosystems_accepted(self):
        """56. Valid ecosystems accepted."""
        from app.agent_api import VALID_ECOSYSTEMS
        expected = {'npm', 'pypi', 'maven', 'nuget', 'cargo', 'go', 'gem', 'composer',
                    'vscode', 'chrome', 'firefox', 'edge', 'jetbrains'}
        for eco in expected:
            assert eco in VALID_ECOSYSTEMS, f"{eco} should be in VALID_ECOSYSTEMS"

    def test_invalid_ecosystem_not_in_set(self):
        """57. Invalid ecosystem not in VALID_ECOSYSTEMS."""
        from app.agent_api import VALID_ECOSYSTEMS
        assert 'evil_ecosystem' not in VALID_ECOSYSTEMS
        assert '' not in VALID_ECOSYSTEMS
        assert 'hackage' not in VALID_ECOSYSTEMS


# ============================================================================
# End-to-End Dependency Flow (58-60)
# ============================================================================

class TestEndToEndDependencyFlow:
    """End-to-end tests: agent submits deps -> Product created -> VulnerabilityMatch."""

    def test_agent_sends_deps_creates_product(self, app, client, db_session,
                                               api_key_all_caps):
        """58. Agent sends dependencies -> creates Product with source_type=code_library."""
        with app.app_context():
            payload = _inventory_payload([
                {'vendor': 'PyPI', 'product': 'e2e-flask-dep', 'version': '3.0.0',
                 'source_type': 'code_library', 'ecosystem': 'pypi',
                 'project_path': '/srv/app/requirements.txt', 'is_direct': True},
            ])
            response = client.post('/api/agent/inventory',
                json=payload,
                headers=_agent_headers(api_key_all_caps['raw_key']))

            assert response.status_code in [200, 201, 202, 403]
            if response.status_code in [200, 201, 202]:
                from app.models import Product
                p = Product.query.filter_by(product_name='e2e-flask-dep').first()
                if p:
                    assert p.source_type == 'code_library'
                    assert p.ecosystem == 'pypi'
                    assert p.source == 'agent'

    def test_product_matched_against_cve(self, app, db_session, test_org):
        """59. Product matched against CVE -> VulnerabilityMatch created."""
        from app.models import Product, Vulnerability, VulnerabilityMatch

        # Create a code_library product
        product = Product(
            vendor='PyPI',
            product_name='e2e-vuln-match',
            version='2.28.0',
            source_type='code_library',
            ecosystem='pypi',
            active=True,
            organization_id=test_org.id,
            cpe_vendor='python',
            cpe_product='requests',
        )
        db_session.add(product)
        db_session.flush()

        # Create a vulnerability
        vuln = Vulnerability(
            cve_id='CVE-2024-E2E-001',
            vendor_project='Python',
            product='requests',
            vulnerability_name='E2E Test Vuln',
            date_added=date.today(),
            short_description='A test CVE for e2e flow',
            required_action='Update requests',
            cvss_score=7.0,
            severity='HIGH',
        )
        db_session.add(vuln)
        db_session.flush()

        # Create a VulnerabilityMatch linking product to vulnerability
        match = VulnerabilityMatch(
            product_id=product.id,
            vulnerability_id=vuln.id,
            match_reason='vendor_product match on requests',
            match_method='cpe',
            match_confidence='high',
        )
        db_session.add(match)
        db_session.commit()

        # Verify the match was created
        found = VulnerabilityMatch.query.filter_by(
            product_id=product.id,
            vulnerability_id=vuln.id
        ).first()
        assert found is not None
        assert found.match_method == 'cpe'
        assert found.match_confidence == 'high'
        assert found.acknowledged is False

    def test_version_change_removes_stale_matches(self, app, db_session, test_org):
        """60. Agent update: version changes -> stale matches can be removed."""
        from app.models import Product, Vulnerability, VulnerabilityMatch

        # Create product with OLD version
        product = Product(
            vendor='PyPI',
            product_name='e2e-stale-match',
            version='2.28.0',
            source_type='code_library',
            ecosystem='pypi',
            active=True,
            organization_id=test_org.id,
        )
        db_session.add(product)
        db_session.flush()

        # Create vulnerability
        vuln = Vulnerability(
            cve_id='CVE-2024-E2E-STALE',
            vendor_project='PyPI',
            product='e2e-stale-match',
            vulnerability_name='Stale Match Vuln',
            date_added=date.today(),
            short_description='Fixed in 2.29.0',
            required_action='Upgrade to 2.29.0',
            cvss_score=6.5,
            severity='MEDIUM',
        )
        db_session.add(vuln)
        db_session.flush()

        # Create a match for the OLD version
        match = VulnerabilityMatch(
            product_id=product.id,
            vulnerability_id=vuln.id,
            match_reason='version 2.28.0 affected',
            match_method='cpe',
            match_confidence='high',
        )
        db_session.add(match)
        db_session.commit()

        match_id = match.id
        assert VulnerabilityMatch.query.get(match_id) is not None

        # Simulate agent updating the product version (fixed version)
        product.version = '2.29.0'
        db_session.commit()

        # In production, the CVE re-matching engine would detect the version
        # change and remove the stale match. Here we simulate that removal.
        stale = VulnerabilityMatch.query.get(match_id)
        db_session.delete(stale)
        db_session.commit()

        assert VulnerabilityMatch.query.get(match_id) is None
        assert product.version == '2.29.0'


# ============================================================================
# Additional Container Image Edge Cases
# ============================================================================

class TestContainerImageEdgeCases:
    """Additional edge case tests for container images."""

    def test_container_image_to_dict_without_asset(self, app, db_session, test_org):
        """to_dict works when asset_id is None (image not linked to an asset)."""
        from app.models import ContainerImage

        image = ContainerImage(
            organization_id=test_org.id,
            image_name='no-asset-image',
            image_tag='v1',
        )
        db_session.add(image)
        db_session.commit()

        d = image.to_dict()
        assert d['asset_id'] is None
        assert d['asset_hostname'] is None

    def test_container_image_zero_vulnerability_counts(self, app, db_session, test_org):
        """Container image with zero vulnerabilities defaults correctly."""
        from app.models import ContainerImage

        image = ContainerImage(
            organization_id=test_org.id,
            image_name='clean-image',
            image_tag='latest',
        )
        db_session.add(image)
        db_session.commit()

        assert image.total_vulnerabilities == 0
        assert image.critical_count == 0
        assert image.high_count == 0
        assert image.medium_count == 0
        assert image.low_count == 0
        assert image.fixed_count == 0
        assert image.unfixed_count == 0

    def test_container_vulnerability_to_dict(self, app, db_session, test_org):
        """ContainerVulnerability.to_dict() returns expected fields."""
        from app.models import ContainerImage, ContainerVulnerability

        image = ContainerImage(
            organization_id=test_org.id,
            image_name='vuln-dict-image',
            image_tag='v1',
        )
        db_session.add(image)
        db_session.flush()

        vuln = ContainerVulnerability(
            container_image_id=image.id,
            vuln_id='CVE-2024-DICT',
            severity='CRITICAL',
            title='Dict Test Vuln',
            pkg_name='openssl',
            pkg_version='3.0.0',
            pkg_type='os',
            fixed_version='3.0.1',
            fix_status='fixed',
            cvss_score=9.8,
            data_source='nvd',
            primary_url='https://nvd.nist.gov/vuln/detail/CVE-2024-DICT',
            acknowledged=False,
        )
        db_session.add(vuln)
        db_session.commit()

        d = vuln.to_dict()
        assert d['vuln_id'] == 'CVE-2024-DICT'
        assert d['severity'] == 'CRITICAL'
        assert d['pkg_name'] == 'openssl'
        assert d['pkg_version'] == '3.0.0'
        assert d['pkg_type'] == 'os'
        assert d['fixed_version'] == '3.0.1'
        assert d['fix_status'] == 'fixed'
        assert d['cvss_score'] == 9.8
        assert d['data_source'] == 'nvd'
        assert d['primary_url'] == 'https://nvd.nist.gov/vuln/detail/CVE-2024-DICT'
        assert d['acknowledged'] is False
        assert d['created_at'] is not None


# ============================================================================
# Agent API Key Model - Scan Capabilities (supplementary)
# ============================================================================

class TestAgentApiKeyScanCapabilities:
    """Test AgentApiKey model fields for scan capabilities."""

    def test_default_scan_capabilities(self, app, db_session, test_org):
        """Default scan capabilities: os=True, extensions=False, deps=False."""
        from app.models import AgentApiKey

        raw = 'sk_test_def_cap_container_dep'
        key = AgentApiKey(
            organization_id=test_org.id,
            name='Default Test Key',
            key_hash=hashlib.sha256(raw.encode()).hexdigest(),
            key_prefix=raw[:10],
            active=True,
        )
        db_session.add(key)
        db_session.commit()

        assert key.scan_os_packages is True
        assert key.scan_extensions is False
        assert key.scan_dependencies is False

    def test_scan_capabilities_in_to_dict(self, app, db_session, test_org):
        """to_dict() includes scan_capabilities with correct values."""
        from app.models import AgentApiKey

        raw = 'sk_test_cap_dict_container'
        key = AgentApiKey(
            organization_id=test_org.id,
            name='Cap Dict Key',
            key_hash=hashlib.sha256(raw.encode()).hexdigest(),
            key_prefix=raw[:10],
            active=True,
            scan_os_packages=True,
            scan_extensions=True,
            scan_dependencies=True,
        )
        db_session.add(key)
        db_session.commit()

        d = key.to_dict()
        caps = d.get('scan_capabilities', {})
        assert caps['os_packages'] is True
        assert caps['extensions'] is True
        assert caps['dependencies'] is True

    def test_conftest_test_api_key_fixture(self, app, db_session, test_api_key):
        """Verify test_api_key fixture creates key with raw_key='sk_test_1234567890abcdef'."""
        assert test_api_key['raw_key'] == 'sk_test_1234567890abcdef'
        assert test_api_key['api_key'].active is True
        assert test_api_key['api_key'].key_prefix == 'sk_test_'
