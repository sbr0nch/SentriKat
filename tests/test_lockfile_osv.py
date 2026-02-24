"""
Tests for lock file parsing and OSV.dev dependency scanning.

Covers:
- Lock file parser: package-lock.json, yarn.lock, pnpm-lock.yaml, Pipfile.lock,
  poetry.lock, Cargo.lock, go.sum, go.mod, Gemfile.lock, composer.lock,
  packages.lock.json
- OSV client: batch query construction, response parsing, vulnerability mapping
- DependencyScan / DependencyScanResult models
- Agent API dependency-scan endpoint (auth, parsing, result storage)
- Lock file type detection
"""

import pytest
import json
import hashlib
from unittest.mock import patch, MagicMock
from datetime import datetime


# ---------------------------------------------------------------------------
# Lock File Parser Tests
# ---------------------------------------------------------------------------

class TestLockfileDetection:
    """Test lock file type detection from filenames."""

    def test_detect_package_lock_json(self):
        from app.lockfile_parser import detect_lockfile_type
        assert detect_lockfile_type('package-lock.json') == 'npm'

    def test_detect_yarn_lock(self):
        from app.lockfile_parser import detect_lockfile_type
        assert detect_lockfile_type('yarn.lock') == 'yarn'

    def test_detect_pnpm_lock(self):
        from app.lockfile_parser import detect_lockfile_type
        assert detect_lockfile_type('pnpm-lock.yaml') == 'pnpm'

    def test_detect_pipfile_lock(self):
        from app.lockfile_parser import detect_lockfile_type
        assert detect_lockfile_type('Pipfile.lock') == 'pipfile'

    def test_detect_poetry_lock(self):
        from app.lockfile_parser import detect_lockfile_type
        assert detect_lockfile_type('poetry.lock') == 'poetry'

    def test_detect_cargo_lock(self):
        from app.lockfile_parser import detect_lockfile_type
        assert detect_lockfile_type('Cargo.lock') == 'cargo'

    def test_detect_go_sum(self):
        from app.lockfile_parser import detect_lockfile_type
        assert detect_lockfile_type('go.sum') == 'gosum'

    def test_detect_go_mod(self):
        from app.lockfile_parser import detect_lockfile_type
        assert detect_lockfile_type('go.mod') == 'gomod'

    def test_detect_gemfile_lock(self):
        from app.lockfile_parser import detect_lockfile_type
        assert detect_lockfile_type('Gemfile.lock') == 'gem'

    def test_detect_composer_lock(self):
        from app.lockfile_parser import detect_lockfile_type
        assert detect_lockfile_type('composer.lock') == 'composer'

    def test_detect_nuget_packages_lock(self):
        from app.lockfile_parser import detect_lockfile_type
        assert detect_lockfile_type('packages.lock.json') == 'nuget'

    def test_detect_unknown(self):
        from app.lockfile_parser import detect_lockfile_type
        assert detect_lockfile_type('random.txt') is None

    def test_detect_with_path(self):
        from app.lockfile_parser import detect_lockfile_type
        assert detect_lockfile_type('/home/user/project/package-lock.json') == 'npm'


class TestPackageLockJsonParser:
    """Test npm package-lock.json parsing."""

    def test_parse_v3_format(self):
        from app.lockfile_parser import parse_lockfile
        content = json.dumps({
            "lockfileVersion": 3,
            "packages": {
                "": {
                    "dependencies": {"express": "^4.18.0"},
                    "devDependencies": {"jest": "^29.0.0"}
                },
                "node_modules/express": {"version": "4.18.2"},
                "node_modules/body-parser": {"version": "1.20.2"},
                "node_modules/jest": {"version": "29.7.0"},
            }
        })
        deps = parse_lockfile('package-lock.json', content)
        assert deps is not None
        assert len(deps) == 3

        names = {d.name: d for d in deps}
        assert 'express' in names
        assert names['express'].version == '4.18.2'
        assert names['express'].ecosystem == 'npm'
        assert names['express'].is_direct is True
        assert names['body-parser'].is_direct is False
        assert names['jest'].is_direct is True

    def test_parse_v1_format(self):
        from app.lockfile_parser import parse_lockfile
        content = json.dumps({
            "lockfileVersion": 1,
            "dependencies": {
                "lodash": {"version": "4.17.21"},
                "chalk": {
                    "version": "5.3.0",
                    "dependencies": {
                        "ansi-styles": {"version": "6.2.1"}
                    }
                }
            }
        })
        deps = parse_lockfile('package-lock.json', content)
        assert deps is not None
        assert len(deps) == 3

    def test_parse_scoped_packages(self):
        from app.lockfile_parser import parse_lockfile
        content = json.dumps({
            "lockfileVersion": 3,
            "packages": {
                "": {"dependencies": {"@angular/core": "^17.0.0"}},
                "node_modules/@angular/core": {"version": "17.0.8"},
                "node_modules/@types/node": {"version": "20.10.0"},
            }
        })
        deps = parse_lockfile('package-lock.json', content)
        assert deps is not None
        names = {d.name for d in deps}
        assert '@angular/core' in names
        assert '@types/node' in names

    def test_purl_generation_scoped(self):
        from app.lockfile_parser import LockfileDependency
        dep = LockfileDependency('@angular/core', '17.0.8', 'npm')
        assert dep.purl == 'pkg:npm/angular/core@17.0.8'


class TestYarnLockParser:
    """Test yarn.lock parsing."""

    def test_parse_yarn_v1(self):
        from app.lockfile_parser import parse_lockfile
        content = '''\
# THIS IS AN AUTOGENERATED FILE. DO NOT EDIT THIS FILE DIRECTLY.

express@^4.18.0:
  version "4.18.2"
  resolved "https://registry.yarnpkg.com/express/-/express-4.18.2.tgz"

lodash@^4.17.21:
  version "4.17.21"
  resolved "https://registry.yarnpkg.com/lodash/-/lodash-4.17.21.tgz"

"@types/node@^20.0.0":
  version "20.10.0"
  resolved "https://registry.yarnpkg.com/@types/node/-/node-20.10.0.tgz"
'''
        deps = parse_lockfile('yarn.lock', content)
        assert deps is not None
        assert len(deps) == 3
        names = {d.name for d in deps}
        assert 'express' in names
        assert 'lodash' in names
        assert '@types/node' in names


class TestPipfileLockParser:
    """Test Pipfile.lock parsing."""

    def test_parse_pipfile_lock(self):
        from app.lockfile_parser import parse_lockfile
        content = json.dumps({
            "_meta": {"hash": {"sha256": "abc"}},
            "default": {
                "requests": {"version": "==2.31.0"},
                "flask": {"version": "==3.0.0"},
            },
            "develop": {
                "pytest": {"version": "==7.4.3"},
            }
        })
        deps = parse_lockfile('Pipfile.lock', content)
        assert deps is not None
        assert len(deps) == 3

        names = {d.name: d for d in deps}
        assert names['requests'].version == '2.31.0'
        assert names['requests'].ecosystem == 'PyPI'
        assert names['requests'].is_direct is True
        assert names['pytest'].is_direct is False


class TestPoetryLockParser:
    """Test poetry.lock parsing."""

    def test_parse_poetry_lock(self):
        from app.lockfile_parser import parse_lockfile
        content = '''\
[[package]]
name = "requests"
version = "2.31.0"
description = "Python HTTP for Humans."

[[package]]
name = "flask"
version = "3.0.0"
description = "A simple framework for building complex web applications."

[metadata]
lock-version = "2.0"
'''
        deps = parse_lockfile('poetry.lock', content)
        assert deps is not None
        assert len(deps) == 2

        names = {d.name: d for d in deps}
        assert 'requests' in names
        assert names['flask'].version == '3.0.0'
        assert names['flask'].ecosystem == 'PyPI'


class TestCargoLockParser:
    """Test Cargo.lock parsing."""

    def test_parse_cargo_lock(self):
        from app.lockfile_parser import parse_lockfile
        content = '''\
[[package]]
name = "serde"
version = "1.0.193"
source = "registry+https://github.com/rust-lang/crates.io-index"

[[package]]
name = "tokio"
version = "1.35.1"
source = "registry+https://github.com/rust-lang/crates.io-index"

[[package]]
name = "my-local-crate"
version = "0.1.0"
'''
        deps = parse_lockfile('Cargo.lock', content)
        assert deps is not None
        assert len(deps) == 3
        names = {d.name for d in deps}
        assert 'serde' in names
        assert 'tokio' in names
        assert 'my-local-crate' in names  # No source = local, still included


class TestGoSumParser:
    """Test go.sum parsing."""

    def test_parse_go_sum(self):
        from app.lockfile_parser import parse_lockfile
        content = '''\
github.com/gin-gonic/gin v1.9.1 h1:4idEAncQnU5cB7BeOkPtxjfCSye0AAm1R0RVIqFPSHw=
github.com/gin-gonic/gin v1.9.1/go.mod h1:hPrL/0KcuCAs=
golang.org/x/crypto v0.17.0 h1:r8bRNjWMQoez8ZSjnhjG5hOC0/n7B=
golang.org/x/crypto v0.17.0/go.mod h1:gCAAfMLgwOJRpTjQ2zCCt2OcSfYMTeZV=
'''
        deps = parse_lockfile('go.sum', content)
        assert deps is not None
        assert len(deps) == 2  # Deduped: each module appears once

        names = {d.name: d for d in deps}
        assert 'github.com/gin-gonic/gin' in names
        assert names['github.com/gin-gonic/gin'].version == '1.9.1'
        assert names['github.com/gin-gonic/gin'].ecosystem == 'Go'
        assert 'golang.org/x/crypto' in names
        assert names['golang.org/x/crypto'].version == '0.17.0'


class TestGoModParser:
    """Test go.mod parsing."""

    def test_parse_go_mod(self):
        from app.lockfile_parser import parse_lockfile
        content = '''\
module github.com/myorg/myapp

go 1.21

require (
\tgithub.com/gin-gonic/gin v1.9.1
\tgolang.org/x/crypto v0.17.0 // indirect
)

require github.com/stretchr/testify v1.8.4
'''
        deps = parse_lockfile('go.mod', content)
        assert deps is not None
        assert len(deps) == 3

        names = {d.name: d for d in deps}
        assert names['github.com/gin-gonic/gin'].is_direct is True
        assert names['golang.org/x/crypto'].is_direct is False
        assert names['github.com/stretchr/testify'].is_direct is True


class TestGemfileLockParser:
    """Test Gemfile.lock parsing."""

    def test_parse_gemfile_lock(self):
        from app.lockfile_parser import parse_lockfile
        content = '''\
GEM
  remote: https://rubygems.org/
  specs:
    rails (7.1.2)
      actioncable (= 7.1.2)
    actioncable (7.1.2)
    puma (6.4.2)

PLATFORMS
  ruby

DEPENDENCIES
  rails
  puma
'''
        deps = parse_lockfile('Gemfile.lock', content)
        assert deps is not None
        # Should find top-level gems
        names = {d.name for d in deps}
        assert 'rails' in names
        assert 'puma' in names


class TestComposerLockParser:
    """Test composer.lock parsing."""

    def test_parse_composer_lock(self):
        from app.lockfile_parser import parse_lockfile
        content = json.dumps({
            "packages": [
                {"name": "laravel/framework", "version": "v10.38.0"},
                {"name": "guzzlehttp/guzzle", "version": "v7.8.1"},
            ],
            "packages-dev": [
                {"name": "phpunit/phpunit", "version": "v10.5.2"},
            ]
        })
        deps = parse_lockfile('composer.lock', content)
        assert deps is not None
        assert len(deps) == 3

        names = {d.name: d for d in deps}
        assert 'laravel/framework' in names
        assert names['laravel/framework'].version == '10.38.0'
        assert names['laravel/framework'].ecosystem == 'Packagist'
        assert names['phpunit/phpunit'].is_direct is False


class TestNugetPackagesLockParser:
    """Test NuGet packages.lock.json parsing."""

    def test_parse_nuget_lock(self):
        from app.lockfile_parser import parse_lockfile
        content = json.dumps({
            "version": 1,
            "dependencies": {
                "net8.0": {
                    "Newtonsoft.Json": {
                        "type": "Direct",
                        "resolved": "13.0.3"
                    },
                    "System.Text.Json": {
                        "type": "Transitive",
                        "resolved": "8.0.0"
                    }
                }
            }
        })
        deps = parse_lockfile('packages.lock.json', content)
        assert deps is not None
        assert len(deps) == 2

        names = {d.name: d for d in deps}
        assert names['Newtonsoft.Json'].is_direct is True
        assert names['System.Text.Json'].is_direct is False
        assert names['Newtonsoft.Json'].ecosystem == 'NuGet'


class TestBatchParsing:
    """Test batch lock file parsing."""

    def test_parse_multiple_lockfiles(self):
        from app.lockfile_parser import parse_lockfiles_batch

        lockfiles = [
            {
                'filename': 'package-lock.json',
                'content': json.dumps({
                    "lockfileVersion": 3,
                    "packages": {
                        "": {"dependencies": {"express": "^4.18.0"}},
                        "node_modules/express": {"version": "4.18.2"},
                    }
                }),
            },
            {
                'filename': 'Pipfile.lock',
                'content': json.dumps({
                    "default": {"requests": {"version": "==2.31.0"}},
                    "develop": {}
                }),
            },
        ]

        result = parse_lockfiles_batch(lockfiles)
        assert result['stats']['files_parsed'] == 2
        assert result['stats']['total_dependencies'] == 2
        assert len(result['errors']) == 0

    def test_handles_parse_errors_gracefully(self):
        from app.lockfile_parser import parse_lockfiles_batch

        lockfiles = [
            {'filename': 'package-lock.json', 'content': 'NOT JSON AT ALL'},
            {'filename': 'Pipfile.lock', 'content': json.dumps({
                "default": {"flask": {"version": "==3.0.0"}},
                "develop": {}
            })},
        ]

        result = parse_lockfiles_batch(lockfiles)
        assert result['stats']['files_parsed'] == 1
        assert result['stats']['files_failed'] == 1
        assert len(result['errors']) == 1


class TestPURLGeneration:
    """Test Package URL generation."""

    def test_npm_purl(self):
        from app.lockfile_parser import LockfileDependency
        dep = LockfileDependency('express', '4.18.2', 'npm')
        assert dep.purl == 'pkg:npm/express@4.18.2'

    def test_pypi_purl(self):
        from app.lockfile_parser import LockfileDependency
        dep = LockfileDependency('requests', '2.31.0', 'PyPI')
        assert dep.purl == 'pkg:pypi/requests@2.31.0'

    def test_cargo_purl(self):
        from app.lockfile_parser import LockfileDependency
        dep = LockfileDependency('serde', '1.0.193', 'crates.io')
        assert dep.purl == 'pkg:cargo/serde@1.0.193'

    def test_go_purl(self):
        from app.lockfile_parser import LockfileDependency
        dep = LockfileDependency('github.com/gin-gonic/gin', '1.9.1', 'Go')
        assert dep.purl == 'pkg:golang/github.com/gin-gonic/gin@1.9.1'

    def test_gem_purl(self):
        from app.lockfile_parser import LockfileDependency
        dep = LockfileDependency('rails', '7.1.2', 'RubyGems')
        assert dep.purl == 'pkg:gem/rails@7.1.2'

    def test_composer_purl(self):
        from app.lockfile_parser import LockfileDependency
        dep = LockfileDependency('laravel/framework', '10.38.0', 'Packagist')
        assert dep.purl == 'pkg:composer/laravel/framework@10.38.0'

    def test_nuget_purl(self):
        from app.lockfile_parser import LockfileDependency
        dep = LockfileDependency('Newtonsoft.Json', '13.0.3', 'NuGet')
        assert dep.purl == 'pkg:nuget/Newtonsoft.Json@13.0.3'


# ---------------------------------------------------------------------------
# OSV Client Tests
# ---------------------------------------------------------------------------

class TestOSVClient:
    """Test OSV.dev API client (mocked)."""

    def test_query_batch_constructs_correct_payload(self):
        """Verify batch query builds correct request format."""
        from app.osv_client import query_osv_batch

        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            'results': [
                {'vulns': [{'id': 'GHSA-abc-123', 'aliases': ['CVE-2024-1234'], 'summary': 'Test vuln'}]},
                {'vulns': []},
            ]
        }

        with patch('app.osv_client.requests.post', return_value=mock_response) as mock_post:
            results = query_osv_batch([
                {'name': 'express', 'version': '4.17.1', 'ecosystem': 'npm'},
                {'name': 'requests', 'version': '2.31.0', 'ecosystem': 'PyPI'},
            ])

            # Verify POST was called with correct payload
            call_args = mock_post.call_args
            payload = call_args[1]['json']
            assert len(payload['queries']) == 2
            assert payload['queries'][0]['package']['name'] == 'express'
            assert payload['queries'][0]['package']['ecosystem'] == 'npm'
            assert payload['queries'][0]['version'] == '4.17.1'

            # Verify results mapped correctly
            assert ('npm', 'express', '4.17.1') in results
            assert len(results[('npm', 'express', '4.17.1')]) == 1
            assert ('PyPI', 'requests', '2.31.0') not in results  # No vulns

    def test_scan_dependencies_osv_returns_vulnerable_and_clean(self):
        """Test the main scan entry point with mocked OSV responses."""
        from app.osv_client import scan_dependencies_osv, OSVVulnerability

        mock_vuln = MagicMock(spec=OSVVulnerability)
        mock_vuln.to_dict.return_value = {
            'id': 'GHSA-test-1234',
            'cve_id': 'CVE-2024-9999',
            'aliases': ['CVE-2024-9999'],
            'summary': 'Test vulnerability',
            'severity': 'HIGH',
            'cvss_score': 7.5,
            'fixed_versions': ['4.18.0'],
            'primary_url': 'https://osv.dev/vulnerability/GHSA-test-1234',
        }

        with patch('app.osv_client.query_osv_batch') as mock_batch:
            mock_batch.return_value = {
                ('npm', 'express', '4.17.1'): [mock_vuln],
            }

            deps = [
                {'name': 'express', 'version': '4.17.1', 'ecosystem': 'npm', 'is_direct': True, 'purl': 'pkg:npm/express@4.17.1'},
                {'name': 'lodash', 'version': '4.17.21', 'ecosystem': 'npm', 'is_direct': False, 'purl': 'pkg:npm/lodash@4.17.21'},
            ]

            result = scan_dependencies_osv(deps)
            assert result['stats']['vulnerable_packages'] == 1
            assert result['stats']['clean_packages'] == 1
            assert len(result['vulnerable']) == 1
            assert result['vulnerable'][0]['name'] == 'express'
            assert result['vulnerable'][0]['is_direct'] is True

    def test_handles_empty_dependencies(self):
        from app.osv_client import scan_dependencies_osv
        result = scan_dependencies_osv([])
        assert result['stats']['total_scanned'] == 0


class TestOSVVulnerabilityParsing:
    """Test OSV vulnerability response parsing."""

    def test_parse_vulnerability_with_cve(self):
        from app.osv_client import OSVVulnerability
        vuln = OSVVulnerability({
            'id': 'GHSA-xxxx-yyyy',
            'aliases': ['CVE-2024-1234'],
            'summary': 'A test vulnerability',
            'severity': [{'type': 'CVSS_V3', 'score': 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H'}],
            'affected': [{
                'package': {'name': 'express', 'ecosystem': 'npm'},
                'ranges': [{'type': 'ECOSYSTEM', 'events': [{'introduced': '0'}, {'fixed': '4.18.0'}]}],
            }],
            'references': [{'type': 'ADVISORY', 'url': 'https://github.com/advisories/GHSA-xxxx-yyyy'}],
        })
        assert vuln.cve_id == 'CVE-2024-1234'
        assert vuln.id == 'GHSA-xxxx-yyyy'
        assert '4.18.0' in vuln.fixed_versions
        assert vuln.primary_url == 'https://github.com/advisories/GHSA-xxxx-yyyy'

    def test_parse_vulnerability_without_cve(self):
        from app.osv_client import OSVVulnerability
        vuln = OSVVulnerability({
            'id': 'PYSEC-2024-1',
            'aliases': [],
            'summary': 'Python specific vuln',
        })
        assert vuln.cve_id is None
        assert vuln.primary_url == 'https://osv.dev/vulnerability/PYSEC-2024-1'


# ---------------------------------------------------------------------------
# Database Model Tests
# ---------------------------------------------------------------------------

class TestDependencyScanModels:
    """Test DependencyScan and DependencyScanResult models."""

    def test_create_dependency_scan(self, db_session, test_org):
        from app.models import DependencyScan, Asset

        asset = Asset(
            hostname='test-server',
            organization_id=test_org.id,
            agent_id='test-agent-123',
        )
        db_session.add(asset)
        db_session.flush()

        scan = DependencyScan(
            organization_id=test_org.id,
            asset_id=asset.id,
            scan_status='completed',
            lockfiles_submitted=2,
            lockfiles_parsed=2,
            total_dependencies=50,
            direct_dependencies=10,
            transitive_dependencies=40,
            vulnerable_count=3,
            total_vulnerabilities=5,
            critical_count=1,
            high_count=2,
            medium_count=1,
            low_count=1,
        )
        db_session.add(scan)
        db_session.commit()

        assert scan.id is not None
        d = scan.to_dict()
        assert d['scan_status'] == 'completed'
        assert d['total_dependencies'] == 50
        assert d['severity']['critical'] == 1

    def test_create_scan_result(self, db_session, test_org):
        from app.models import DependencyScan, DependencyScanResult, Asset

        asset = Asset(
            hostname='test-server-2',
            organization_id=test_org.id,
            agent_id='test-agent-456',
        )
        db_session.add(asset)
        db_session.flush()

        scan = DependencyScan(
            organization_id=test_org.id,
            asset_id=asset.id,
            scan_status='completed',
        )
        db_session.add(scan)
        db_session.flush()

        result = DependencyScanResult(
            scan_id=scan.id,
            pkg_name='express',
            pkg_version='4.17.1',
            pkg_ecosystem='npm',
            purl='pkg:npm/express@4.17.1',
            is_direct=True,
            vuln_id='GHSA-test-1234',
            cve_id='CVE-2024-9999',
            severity='HIGH',
            cvss_score=7.5,
            summary='Test vulnerability in express',
            fixed_versions=json.dumps(['4.18.0', '4.17.2']),
            aliases=json.dumps(['CVE-2024-9999', 'GHSA-test-1234']),
        )
        db_session.add(result)
        db_session.commit()

        assert result.id is not None
        d = result.to_dict()
        assert d['pkg_name'] == 'express'
        assert d['cve_id'] == 'CVE-2024-9999'
        assert d['fixed_versions'] == ['4.18.0', '4.17.2']
        assert d['aliases'] == ['CVE-2024-9999', 'GHSA-test-1234']

    def test_cascade_delete(self, db_session, test_org):
        """Deleting a scan should cascade-delete its results."""
        from app.models import DependencyScan, DependencyScanResult, Asset

        asset = Asset(
            hostname='test-server-3',
            organization_id=test_org.id,
            agent_id='test-agent-789',
        )
        db_session.add(asset)
        db_session.flush()

        scan = DependencyScan(
            organization_id=test_org.id,
            asset_id=asset.id,
            scan_status='completed',
        )
        db_session.add(scan)
        db_session.flush()
        scan_id = scan.id

        result = DependencyScanResult(
            scan_id=scan.id,
            pkg_name='lodash',
            pkg_version='4.17.20',
            pkg_ecosystem='npm',
            vuln_id='GHSA-cascade-test',
            severity='MEDIUM',
        )
        db_session.add(result)
        db_session.commit()

        # Delete the scan
        db_session.delete(scan)
        db_session.commit()

        # Result should be gone too
        remaining = DependencyScanResult.query.filter_by(scan_id=scan_id).count()
        assert remaining == 0


# ---------------------------------------------------------------------------
# Agent API Endpoint Tests (Dependency Scan)
# ---------------------------------------------------------------------------

RAW_KEY = 'sk_test_depscn_abcdef012345'
DEPSCAN_URL = '/api/agent/dependency-scan'


def _auth_headers():
    return {'X-Agent-Key': RAW_KEY}


def _license_ok(org_id, is_new_agent=True):
    return True, None, {'edition': 'professional', 'current_agents': 1, 'max_agents': 100}


@pytest.fixture
def dep_api_key(db_session, test_org):
    """Agent API key for dependency scan tests."""
    from app.models import AgentApiKey
    api_key = AgentApiKey(
        organization_id=test_org.id,
        name='Dep Scan Key',
        key_hash=hashlib.sha256(RAW_KEY.encode()).hexdigest(),
        key_prefix=RAW_KEY[:10],
        active=True,
        scan_os_packages=True,
        scan_dependencies=True,
        auto_approve=True,
    )
    db_session.add(api_key)
    db_session.commit()
    return api_key


@pytest.fixture
def dep_asset(db_session, test_org):
    """Test asset for dependency scan."""
    from app.models import Asset
    asset = Asset(
        hostname='dep-test-host',
        organization_id=test_org.id,
        agent_id='dep-agent-001',
    )
    db_session.add(asset)
    db_session.commit()
    return asset


class TestDependencyScanEndpoint:
    """Test the /api/agent/dependency-scan endpoint."""

    @patch('app.agent_api.check_agent_limit', side_effect=_license_ok)
    def test_scan_requires_auth(self, mock_license, client, setup_complete):
        response = client.post(DEPSCAN_URL, json={})
        assert response.status_code == 401

    @patch('app.agent_api.check_agent_limit', side_effect=_license_ok)
    def test_scan_requires_hostname(self, mock_license, client, dep_api_key, setup_complete):
        response = client.post(DEPSCAN_URL,
            headers=_auth_headers(),
            json={'lockfiles': [{'filename': 'test', 'content': '{}'}]})
        assert response.status_code == 400

    @patch('app.agent_api.check_agent_limit', side_effect=_license_ok)
    def test_scan_auto_creates_asset_for_unknown_host(self, mock_license, client, dep_api_key, setup_complete):
        """Unknown hostname should auto-create a repository asset (CI/CD support).
        The request still fails because 'test' is not a valid lockfile name."""
        response = client.post(DEPSCAN_URL,
            headers=_auth_headers(),
            json={'hostname': 'unknown-host', 'lockfiles': [{'filename': 'test', 'content': '{}'}]})
        assert response.status_code == 200
        data = response.get_json()
        # The lockfile name 'test' is rejected by the whitelist, so 0 parsed
        assert data['status'] == 'success'
        assert data['summary']['lockfiles_parsed'] == 0

    @patch('app.osv_client.requests.post')
    @patch('app.agent_api.check_agent_limit', side_effect=_license_ok)
    def test_scan_success_with_lockfiles(self, mock_license, mock_osv_post, client,
                                          dep_api_key, dep_asset, setup_complete, db_session):
        # Mock OSV response: express 4.17.1 is vulnerable
        mock_osv_response = MagicMock()
        mock_osv_response.status_code = 200
        mock_osv_response.content = b'{"results":[{"vulns":[]}]}'  # small, passes size check
        mock_osv_response.json.return_value = {
            'results': [{
                'vulns': [{
                    'id': 'GHSA-test-scan',
                    'aliases': ['CVE-2024-5555'],
                    'summary': 'Test vuln in express',
                    'affected': [{
                        'package': {'name': 'express', 'ecosystem': 'npm'},
                        'ranges': [{'type': 'ECOSYSTEM', 'events': [
                            {'introduced': '0'}, {'fixed': '4.18.0'}
                        ]}],
                    }],
                }]
            }]
        }
        mock_osv_post.return_value = mock_osv_response

        lockfile_content = json.dumps({
            "lockfileVersion": 3,
            "packages": {
                "": {"dependencies": {"express": "^4.17.0"}},
                "node_modules/express": {"version": "4.17.1"},
            }
        })

        response = client.post(DEPSCAN_URL,
            headers=_auth_headers(),
            json={
                'hostname': 'dep-test-host',
                'agent_id': 'dep-agent-001',
                'lockfiles': [{
                    'filename': 'package-lock.json',
                    'content': lockfile_content,
                }]
            })

        assert response.status_code == 200
        data = response.get_json()
        assert data['status'] == 'success'
        assert data['scan_id'] is not None
        assert data['summary']['total_dependencies'] == 1
        assert data['summary']['total_vulnerabilities'] >= 1

    @patch('app.agent_api.check_agent_limit', side_effect=_license_ok)
    def test_scan_empty_lockfiles(self, mock_license, client, dep_api_key, dep_asset, setup_complete):
        response = client.post(DEPSCAN_URL,
            headers=_auth_headers(),
            json={
                'hostname': 'dep-test-host',
                'lockfiles': []
            })
        assert response.status_code == 200
        data = response.get_json()
        assert data['status'] == 'ok'

    @patch('app.osv_client.requests.post')
    @patch('app.agent_api.check_agent_limit', side_effect=_license_ok)
    def test_scan_no_vulns_found(self, mock_license, mock_osv_post, client,
                                   dep_api_key, dep_asset, setup_complete):
        # Mock OSV response: no vulnerabilities
        mock_osv_response = MagicMock()
        mock_osv_response.status_code = 200
        mock_osv_response.content = b'{"results":[{"vulns":[]}]}'
        mock_osv_response.json.return_value = {'results': [{'vulns': []}]}
        mock_osv_post.return_value = mock_osv_response

        lockfile_content = json.dumps({
            "lockfileVersion": 3,
            "packages": {
                "": {"dependencies": {"express": "^4.18.0"}},
                "node_modules/express": {"version": "4.18.2"},
            }
        })

        response = client.post(DEPSCAN_URL,
            headers=_auth_headers(),
            json={
                'hostname': 'dep-test-host',
                'lockfiles': [{
                    'filename': 'package-lock.json',
                    'content': lockfile_content,
                }]
            })

        assert response.status_code == 200
        data = response.get_json()
        assert data['summary']['total_vulnerabilities'] == 0
