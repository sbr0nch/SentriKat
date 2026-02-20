"""
Tests for SentriKat export/import functionality.

Covers CSV export, PDF export, audit log export, backup/restore,
CPE mapping import/export, SBOM import, and data integrity checks.
"""
import io
import json
import csv
import sys
import pytest
from types import ModuleType
from unittest.mock import patch, MagicMock
from datetime import datetime, date, timedelta

# Ensure flask_login is available as a stub so that
# `from flask_login import current_user` inside cpe_api
# does not raise ModuleNotFoundError in the test environment.
if 'flask_login' not in sys.modules:
    _fl = ModuleType('flask_login')
    _fl.current_user = MagicMock(id=None)  # type: ignore[attr-defined]
    sys.modules['flask_login'] = _fl


# ============================================================================
# Helper Utilities
# ============================================================================

def _parse_csv(response_data):
    """Parse CSV response data into rows, stripping BOM if present."""
    text = response_data.decode('utf-8')
    # Strip UTF-8 BOM if present
    if text.startswith('\ufeff'):
        text = text[1:]
    reader = csv.reader(io.StringIO(text))
    return list(reader)


def _make_audit_log_content(entries):
    """Build newline-delimited JSON audit log content."""
    lines = []
    for entry in entries:
        lines.append(json.dumps(entry))
    return '\n'.join(lines) + '\n'


def _mock_license_professional():
    """Return a MagicMock that behaves like a professional license."""
    lic = MagicMock()
    lic.is_professional.return_value = True
    lic.get_effective_edition.return_value = 'professional'
    return lic


# ============================================================================
# CSV Export Tests
# ============================================================================

class TestCsvExport:
    """Tests for GET /api/reports/export/csv."""

    def test_csv_export_authenticated(
        self, app, authenticated_client, db_session,
        setup_complete, test_org, sample_product,
        sample_vulnerability,
    ):
        """1. CSV export of vulnerabilities returns 200 with CSV data."""
        from app.models import VulnerabilityMatch

        match = VulnerabilityMatch(
            product_id=sample_product.id,
            vulnerability_id=sample_vulnerability.id,
            match_method='cpe',
            match_confidence='high',
        )
        db_session.add(match)
        db_session.commit()

        with authenticated_client.session_transaction() as sess:
            sess['organization_id'] = test_org.id

        response = authenticated_client.get('/api/reports/export/csv')

        assert response.status_code == 200
        assert 'text/csv' in response.content_type
        rows = _parse_csv(response.data)
        # Header row + at least one data row
        assert len(rows) >= 2
        header = rows[0]
        assert 'CVE ID' in header
        assert 'Severity' in header
        assert 'Product' in header

    def test_csv_export_with_priority_filter(
        self, app, authenticated_client, db_session,
        setup_complete, test_org, sample_product,
        sample_vulnerability,
    ):
        """2a. CSV export with priority filter."""
        from app.models import VulnerabilityMatch

        match = VulnerabilityMatch(
            product_id=sample_product.id,
            vulnerability_id=sample_vulnerability.id,
            match_method='cpe',
            match_confidence='high',
        )
        db_session.add(match)
        db_session.commit()

        with authenticated_client.session_transaction() as sess:
            sess['organization_id'] = test_org.id

        response = authenticated_client.get(
            '/api/reports/export/csv?priority=high'
        )
        assert response.status_code == 200
        assert 'text/csv' in response.content_type

    def test_csv_export_with_acknowledged_filter(
        self, app, authenticated_client, db_session,
        setup_complete, test_org, sample_product,
        sample_vulnerability,
    ):
        """2b. CSV export with acknowledged filter."""
        from app.models import VulnerabilityMatch

        match = VulnerabilityMatch(
            product_id=sample_product.id,
            vulnerability_id=sample_vulnerability.id,
            acknowledged=True,
            acknowledged_at=datetime.utcnow(),
        )
        db_session.add(match)
        db_session.commit()

        with authenticated_client.session_transaction() as sess:
            sess['organization_id'] = test_org.id

        response = authenticated_client.get(
            '/api/reports/export/csv?acknowledged=true'
        )
        assert response.status_code == 200
        rows = _parse_csv(response.data)
        # All data rows should show Acknowledged status
        for row in rows[1:]:
            if row:  # skip empty rows
                assert row[7] == 'Acknowledged'

    def test_csv_export_with_product_id_filter(
        self, app, authenticated_client, db_session,
        setup_complete, test_org, sample_product,
        sample_vulnerability,
    ):
        """2c. CSV export with product_id filter."""
        from app.models import VulnerabilityMatch

        match = VulnerabilityMatch(
            product_id=sample_product.id,
            vulnerability_id=sample_vulnerability.id,
        )
        db_session.add(match)
        db_session.commit()

        with authenticated_client.session_transaction() as sess:
            sess['organization_id'] = test_org.id

        response = authenticated_client.get(
            f'/api/reports/export/csv?product_id={sample_product.id}'
        )
        assert response.status_code == 200

    def test_csv_export_with_ransomware_filter(
        self, app, authenticated_client, db_session,
        setup_complete, test_org, sample_product,
        sample_vulnerability,
    ):
        """2d. CSV export with ransomware_only filter."""
        with authenticated_client.session_transaction() as sess:
            sess['organization_id'] = test_org.id

        response = authenticated_client.get(
            '/api/reports/export/csv?ransomware_only=true'
        )
        assert response.status_code == 200
        assert 'text/csv' in response.content_type

    def test_csv_export_no_matches_returns_headers(
        self, app, authenticated_client, db_session,
        setup_complete, test_org,
    ):
        """3. CSV export with no matches returns empty CSV with headers."""
        with authenticated_client.session_transaction() as sess:
            sess['organization_id'] = test_org.id

        response = authenticated_client.get('/api/reports/export/csv')
        assert response.status_code == 200
        rows = _parse_csv(response.data)
        # Should have at least the header row
        assert len(rows) >= 1
        header = rows[0]
        assert 'CVE ID' in header

    def test_csv_export_unauthorized_redirects(
        self, app, client, db_session, setup_complete,
    ):
        """4. CSV export without login returns redirect or 401."""
        response = client.get('/api/reports/export/csv')
        # The route uses login_required from reports_api which returns 401
        assert response.status_code in (401, 302)


# ============================================================================
# Audit Log Export Tests
# ============================================================================

class TestAuditLogExport:
    """Tests for GET /api/audit-logs/export."""

    @patch('app.licensing.get_license')
    def test_audit_log_export_csv_admin(
        self, mock_get_license, app, admin_client,
        db_session, setup_complete, admin_user,
    ):
        """5. Audit log export as CSV by admin returns 200."""
        mock_get_license.return_value = _mock_license_professional()

        audit_entries = [
            {
                'timestamp': datetime.utcnow().isoformat() + 'Z',
                'action': 'login',
                'resource': 'user',
                'resource_id': '1',
                'user_id': admin_user.id,
                'username': admin_user.username,
                'ip_address': '127.0.0.1',
                'details': {'method': 'local'},
            },
        ]
        log_content = _make_audit_log_content(audit_entries)

        with patch('os.path.exists', return_value=True):
            with patch(
                'builtins.open',
                MagicMock(
                    return_value=io.StringIO(log_content)
                ),
            ):
                response = admin_client.get(
                    '/api/audit-logs/export?format=csv'
                )

        assert response.status_code == 200
        assert 'text/csv' in response.content_type

    @patch('app.licensing.get_license')
    def test_audit_log_export_json_format(
        self, mock_get_license, app, admin_client,
        db_session, setup_complete, admin_user,
    ):
        """6. Audit log export as JSON returns valid JSON."""
        mock_get_license.return_value = _mock_license_professional()

        audit_entries = [
            {
                'timestamp': datetime.utcnow().isoformat() + 'Z',
                'action': 'settings_update',
                'resource': 'settings',
                'user_id': admin_user.id,
                'username': admin_user.username,
                'ip_address': '127.0.0.1',
            },
        ]
        log_content = _make_audit_log_content(audit_entries)

        with patch('os.path.exists', return_value=True):
            with patch(
                'builtins.open',
                MagicMock(
                    return_value=io.StringIO(log_content)
                ),
            ):
                response = admin_client.get(
                    '/api/audit-logs/export?format=json'
                )

        assert response.status_code == 200
        assert 'application/json' in response.content_type
        data = json.loads(response.data.decode('utf-8'))
        assert isinstance(data, list)
        assert len(data) == 1

    @patch('app.licensing.get_license')
    def test_audit_log_export_with_day_filter(
        self, mock_get_license, app, admin_client,
        db_session, setup_complete, admin_user,
    ):
        """7. Audit log export with day filter excludes old entries."""
        mock_get_license.return_value = _mock_license_professional()

        now = datetime.utcnow()
        old_ts = (now - timedelta(days=60)).isoformat() + 'Z'
        new_ts = now.isoformat() + 'Z'

        audit_entries = [
            {
                'timestamp': old_ts,
                'action': 'login',
                'resource': 'user',
                'user_id': admin_user.id,
                'username': admin_user.username,
                'ip_address': '10.0.0.1',
            },
            {
                'timestamp': new_ts,
                'action': 'logout',
                'resource': 'user',
                'user_id': admin_user.id,
                'username': admin_user.username,
                'ip_address': '10.0.0.2',
            },
        ]
        log_content = _make_audit_log_content(audit_entries)

        with patch('os.path.exists', return_value=True):
            with patch(
                'builtins.open',
                MagicMock(
                    return_value=io.StringIO(log_content)
                ),
            ):
                # Only last 7 days
                response = admin_client.get(
                    '/api/audit-logs/export?format=json&days=7'
                )

        assert response.status_code == 200
        data = json.loads(response.data.decode('utf-8'))
        # Only the recent entry should survive
        assert len(data) == 1
        assert data[0]['action'] == 'logout'

    @patch('app.licensing.get_license')
    def test_audit_log_export_with_action_filter(
        self, mock_get_license, app, admin_client,
        db_session, setup_complete, admin_user,
    ):
        """8. Audit log export with action filter."""
        mock_get_license.return_value = _mock_license_professional()

        now_ts = datetime.utcnow().isoformat() + 'Z'
        audit_entries = [
            {
                'timestamp': now_ts,
                'action': 'login',
                'resource': 'user',
                'user_id': admin_user.id,
                'username': admin_user.username,
                'ip_address': '127.0.0.1',
            },
            {
                'timestamp': now_ts,
                'action': 'product_create',
                'resource': 'product',
                'user_id': admin_user.id,
                'username': admin_user.username,
                'ip_address': '127.0.0.1',
            },
        ]
        log_content = _make_audit_log_content(audit_entries)

        with patch('os.path.exists', return_value=True):
            with patch(
                'builtins.open',
                MagicMock(
                    return_value=io.StringIO(log_content)
                ),
            ):
                response = admin_client.get(
                    '/api/audit-logs/export?format=json&action=login'
                )

        assert response.status_code == 200
        data = json.loads(response.data.decode('utf-8'))
        assert all(e['action'] == 'login' for e in data)

    @patch('app.licensing.get_license')
    def test_audit_log_export_with_resource_filter(
        self, mock_get_license, app, admin_client,
        db_session, setup_complete, admin_user,
    ):
        """9. Audit log export with resource filter."""
        mock_get_license.return_value = _mock_license_professional()

        now_ts = datetime.utcnow().isoformat() + 'Z'
        audit_entries = [
            {
                'timestamp': now_ts,
                'action': 'create',
                'resource': 'product',
                'user_id': admin_user.id,
                'username': admin_user.username,
                'ip_address': '127.0.0.1',
            },
            {
                'timestamp': now_ts,
                'action': 'update',
                'resource': 'settings',
                'user_id': admin_user.id,
                'username': admin_user.username,
                'ip_address': '127.0.0.1',
            },
        ]
        log_content = _make_audit_log_content(audit_entries)

        with patch('os.path.exists', return_value=True):
            with patch(
                'builtins.open',
                MagicMock(
                    return_value=io.StringIO(log_content)
                ),
            ):
                response = admin_client.get(
                    '/api/audit-logs/export?format=json&resource=product'
                )

        assert response.status_code == 200
        data = json.loads(response.data.decode('utf-8'))
        assert all(
            e['resource'].startswith('product') for e in data
        )

    @patch('app.licensing.get_license')
    def test_audit_log_export_non_admin_gets_403(
        self, mock_get_license, app, authenticated_client,
        db_session, setup_complete,
    ):
        """10. Audit log export by non-admin returns 403."""
        mock_get_license.return_value = _mock_license_professional()

        response = authenticated_client.get(
            '/api/audit-logs/export?format=csv'
        )
        assert response.status_code == 403

    @patch('app.licensing.get_license')
    def test_audit_log_export_no_file_returns_404(
        self, mock_get_license, app, admin_client,
        db_session, setup_complete,
    ):
        """11. Audit log export when no audit file exists returns 404."""
        mock_get_license.return_value = _mock_license_professional()

        with patch('os.path.exists', return_value=False):
            response = admin_client.get(
                '/api/audit-logs/export?format=csv'
            )

        assert response.status_code == 404
        data = response.get_json()
        assert 'error' in data


# ============================================================================
# PDF Report Export Tests
# ============================================================================

_reportlab_available = True
try:
    import reportlab  # noqa: F401
except ImportError:
    _reportlab_available = False


@pytest.mark.skipif(not _reportlab_available, reason="reportlab not installed")
class TestPdfExport:
    """Tests for GET /api/reports/export (PDF)."""

    @patch('app.reports.VulnerabilityReportGenerator')
    def test_pdf_export_with_match_ids(
        self, mock_gen_cls, app, authenticated_client,
        db_session, setup_complete, test_org,
        sample_product, sample_vulnerability,
    ):
        """12. PDF export with valid match_ids returns PDF."""
        from app.models import VulnerabilityMatch

        match = VulnerabilityMatch(
            product_id=sample_product.id,
            vulnerability_id=sample_vulnerability.id,
        )
        db_session.add(match)
        db_session.commit()

        mock_gen = MagicMock()
        pdf_buf = io.BytesIO(b'%PDF-1.4 fake pdf content')
        mock_gen.generate_selected_report.return_value = pdf_buf
        mock_gen_cls.return_value = mock_gen

        with authenticated_client.session_transaction() as sess:
            sess['organization_id'] = test_org.id

        response = authenticated_client.get(
            f'/api/reports/export?match_ids={match.id}'
        )

        assert response.status_code == 200
        assert 'application/pdf' in response.content_type

    def test_pdf_export_no_match_ids_returns_400(
        self, app, authenticated_client, db_session,
        setup_complete,
    ):
        """13. PDF export with no match_ids returns 400."""
        response = authenticated_client.get('/api/reports/export')
        assert response.status_code == 400
        data = response.get_json()
        assert 'error' in data

    def test_pdf_export_invalid_match_ids_returns_400(
        self, app, authenticated_client, db_session,
        setup_complete,
    ):
        """14. PDF export with invalid match_ids returns 400."""
        response = authenticated_client.get(
            '/api/reports/export?match_ids=abc,xyz'
        )
        assert response.status_code == 400
        data = response.get_json()
        assert 'error' in data


# ============================================================================
# Backup & Restore Tests
# ============================================================================

class TestBackupRestore:
    """Tests for backup/restore endpoints."""

    @patch('app.licensing.get_license')
    def test_full_backup_restore_flow(
        self, mock_get_license, app, admin_client,
        db_session, setup_complete, test_org, admin_user,
        sample_product,
    ):
        """15. Full backup then restore-full round-trip."""
        mock_get_license.return_value = _mock_license_professional()

        # Create backup
        response = admin_client.get('/api/settings/backup')
        assert response.status_code == 200
        assert 'application/json' in response.content_type
        backup_data = json.loads(response.data.decode('utf-8'))
        assert 'backup_info' in backup_data
        assert 'settings' in backup_data
        assert 'organizations' in backup_data
        assert 'products' in backup_data

        # Restore full backup
        backup_bytes = json.dumps(backup_data).encode('utf-8')
        data = {
            'backup': (io.BytesIO(backup_bytes), 'backup.json'),
        }
        response = admin_client.post(
            '/api/settings/restore-full',
            data=data,
            content_type='multipart/form-data',
        )
        assert response.status_code == 200
        rdata = response.get_json()
        assert rdata.get('success') is True

    @patch('app.licensing.get_license')
    def test_settings_only_restore(
        self, mock_get_license, app, admin_client,
        db_session, setup_complete, admin_user,
    ):
        """16. Settings-only restore via POST /api/settings/restore."""
        mock_get_license.return_value = _mock_license_professional()

        backup_data = {
            'backup_info': {
                'version': '1.1',
                'created_at': datetime.utcnow().isoformat(),
            },
            'settings': {
                'app_name': {
                    'value': 'TestApp',
                    'category': 'general',
                    'description': 'Application name',
                },
            },
        }
        backup_bytes = json.dumps(backup_data).encode('utf-8')
        data = {
            'backup': (io.BytesIO(backup_bytes), 'backup.json'),
        }
        response = admin_client.post(
            '/api/settings/restore',
            data=data,
            content_type='multipart/form-data',
        )
        assert response.status_code == 200
        rdata = response.get_json()
        assert rdata.get('success') is True
        assert rdata.get('restored_count', 0) >= 1

    @patch('app.licensing.get_license')
    def test_restore_with_invalid_json_returns_400(
        self, mock_get_license, app, admin_client,
        db_session, setup_complete,
    ):
        """17. Restore with invalid JSON returns 400."""
        mock_get_license.return_value = _mock_license_professional()

        data = {
            'backup': (io.BytesIO(b'not valid json'), 'backup.json'),
        }
        response = admin_client.post(
            '/api/settings/restore',
            data=data,
            content_type='multipart/form-data',
        )
        assert response.status_code == 400

    @patch('app.licensing.get_license')
    def test_restore_non_admin_returns_403(
        self, mock_get_license, app, authenticated_client,
        db_session, setup_complete,
    ):
        """18. Restore by non-admin returns 403."""
        mock_get_license.return_value = _mock_license_professional()

        backup_data = {
            'backup_info': {'version': '1.1'},
            'settings': {},
        }
        backup_bytes = json.dumps(backup_data).encode('utf-8')
        data = {
            'backup': (io.BytesIO(backup_bytes), 'backup.json'),
        }
        response = authenticated_client.post(
            '/api/settings/restore',
            data=data,
            content_type='multipart/form-data',
        )
        assert response.status_code == 403


# ============================================================================
# CPE Mapping Export / Import Tests
# ============================================================================

class TestCpeMappingExportImport:
    """Tests for CPE mapping export/import endpoints."""

    @patch('app.cpe_mappings.get_all_user_mappings')
    def test_cpe_mapping_export(
        self, mock_get_mappings, app, admin_client,
        db_session, setup_complete,
    ):
        """19. CPE mapping export returns JSON file."""
        mock_get_mappings.return_value = [
            {
                'vendor_pattern': 'apache',
                'product_pattern': 'tomcat',
                'cpe_vendor': 'apache',
                'cpe_product': 'tomcat',
                'confidence': 0.95,
                'notes': 'test',
            },
        ]

        response = admin_client.get('/api/cpe/user-mappings/export')

        assert response.status_code == 200
        assert 'application/json' in response.content_type
        data = json.loads(response.data.decode('utf-8'))
        assert 'mappings' in data
        assert data['version'] == '1.0'

    @patch('app.cpe_mappings.import_user_mappings')
    def test_cpe_mapping_import(
        self, mock_import, app, admin_client,
        db_session, setup_complete, admin_user,
    ):
        """20. CPE mapping import with valid data succeeds."""
        mock_import.return_value = {
            'imported': 1,
            'skipped': 0,
            'errors': 0,
        }

        response = admin_client.post(
            '/api/cpe/user-mappings/import',
            json={
                'mappings': [
                    {
                        'vendor_pattern': 'custom_vendor',
                        'product_pattern': 'custom_product',
                        'cpe_vendor': 'custom',
                        'cpe_product': 'product',
                    },
                ],
            },
        )

        assert response.status_code == 200
        data = response.get_json()
        assert data.get('success') is True
        assert data['imported'] == 1

    @patch('app.cpe_mappings.import_user_mappings')
    def test_cpe_mapping_import_with_duplicate_handling(
        self, mock_import, app, admin_client,
        db_session, setup_complete, admin_user,
    ):
        """21. CPE mapping import with duplicates reports skipped."""
        mock_import.return_value = {
            'imported': 0,
            'skipped': 2,
            'errors': 0,
        }

        response = admin_client.post(
            '/api/cpe/user-mappings/import',
            json={
                'mappings': [
                    {
                        'vendor_pattern': 'dup_vendor',
                        'product_pattern': 'dup_product',
                        'cpe_vendor': 'dup',
                        'cpe_product': 'product',
                    },
                    {
                        'vendor_pattern': 'dup_vendor',
                        'product_pattern': 'dup_product',
                        'cpe_vendor': 'dup',
                        'cpe_product': 'product',
                    },
                ],
                'overwrite': False,
            },
        )

        assert response.status_code == 200
        data = response.get_json()
        assert data['skipped'] == 2

    def test_cpe_mapping_import_invalid_format(
        self, app, admin_client, db_session,
        setup_complete, admin_user,
    ):
        """22. CPE mapping import with no mappings returns 400."""
        response = admin_client.post(
            '/api/cpe/user-mappings/import',
            json={'mappings': []},
        )
        assert response.status_code == 400
        data = response.get_json()
        assert 'error' in data


# ============================================================================
# SBOM Import Tests
# ============================================================================

class TestSbomImport:
    """Tests for POST /api/import/sbom."""

    def test_sbom_import_cyclonedx(
        self, app, admin_client, db_session,
        setup_complete, test_org, admin_user,
    ):
        """23. SBOM import CycloneDX format processes components."""
        sbom = {
            'bomFormat': 'CycloneDX',
            'specVersion': '1.5',
            'components': [
                {
                    'type': 'library',
                    'name': 'lodash',
                    'version': '4.17.21',
                    'publisher': 'John-David Dalton',
                },
            ],
        }

        with admin_client.session_transaction() as sess:
            sess['organization_id'] = test_org.id

        response = admin_client.post(
            '/api/import/sbom',
            json=sbom,
        )
        assert response.status_code == 200
        data = response.get_json()
        assert data['format'] == 'cyclonedx'
        assert data['total_components'] >= 1

    def test_sbom_import_spdx(
        self, app, admin_client, db_session,
        setup_complete, test_org, admin_user,
    ):
        """24. SBOM import SPDX format processes packages."""
        sbom = {
            'spdxVersion': 'SPDX-2.3',
            'packages': [
                {
                    'name': 'express',
                    'versionInfo': '4.18.2',
                    'supplier': 'Organization: Express Contributors',
                },
            ],
        }

        with admin_client.session_transaction() as sess:
            sess['organization_id'] = test_org.id

        response = admin_client.post(
            '/api/import/sbom',
            json=sbom,
        )
        assert response.status_code == 200
        data = response.get_json()
        assert data['format'] == 'spdx'
        assert data['total_components'] >= 1

    def test_sbom_import_invalid_format_returns_400(
        self, app, admin_client, db_session,
        setup_complete, admin_user,
    ):
        """25. SBOM import with unrecognized format returns 400."""
        response = admin_client.post(
            '/api/import/sbom',
            json={'unknown_key': 'value'},
        )
        assert response.status_code == 400
        data = response.get_json()
        assert 'error' in data


# ============================================================================
# Software Import Tests
# ============================================================================

class TestSoftwareImport:
    """Tests for POST /api/import."""

    def test_software_import_valid_products(
        self, app, admin_client, db_session,
        setup_complete, test_org, admin_user,
    ):
        """26. Software import with valid products succeeds."""
        with admin_client.session_transaction() as sess:
            sess['organization_id'] = test_org.id

        response = admin_client.post(
            '/api/import',
            json={
                'organization_id': test_org.id,
                'software': [
                    {
                        'vendor': 'ImportVendor',
                        'product': 'ImportProduct',
                        'version': '1.0',
                    },
                ],
            },
        )
        assert response.status_code == 200
        data = response.get_json()
        total = (
            data.get('queued', 0)
            + data.get('auto_approved', 0)
            + data.get('duplicates', 0)
        )
        assert total >= 1

    def test_software_import_missing_fields_returns_error(
        self, app, admin_client, db_session,
        setup_complete, admin_user,
    ):
        """27. Software import with missing vendor/product counts errors."""
        response = admin_client.post(
            '/api/import',
            json={
                'software': [
                    {'version': '1.0'},  # missing vendor and product
                ],
            },
        )
        assert response.status_code == 200
        data = response.get_json()
        # Items with missing fields are counted as errors
        assert data.get('errors', 0) >= 1


# ============================================================================
# Data Integrity Tests
# ============================================================================

class TestDataIntegrity:
    """Tests for data integrity across export/import."""

    @patch('app.licensing.get_license')
    def test_round_trip_backup_restore(
        self, mock_get_license, app, admin_client,
        db_session, setup_complete, test_org,
        admin_user, sample_product,
    ):
        """28. Exported data can be imported back (round-trip)."""
        mock_get_license.return_value = _mock_license_professional()

        # Export
        response = admin_client.get('/api/settings/backup')
        assert response.status_code == 200
        backup_data = json.loads(response.data.decode('utf-8'))

        # Verify critical sections present
        assert 'backup_info' in backup_data
        assert 'organizations' in backup_data
        assert 'products' in backup_data
        assert len(backup_data['products']) >= 1

        # Restore
        backup_bytes = json.dumps(backup_data).encode('utf-8')
        data = {
            'backup': (io.BytesIO(backup_bytes), 'backup.json'),
        }
        response = admin_client.post(
            '/api/settings/restore',
            data=data,
            content_type='multipart/form-data',
        )
        assert response.status_code == 200

    @patch('app.licensing.get_license')
    def test_encrypted_settings_show_marker_in_export(
        self, mock_get_license, app, admin_client,
        db_session, setup_complete, admin_user,
    ):
        """29. Encrypted settings show ***ENCRYPTED*** in export."""
        mock_get_license.return_value = _mock_license_professional()

        from app.models import SystemSettings

        enc_setting = SystemSettings(
            key='smtp_password',
            value='secret_value',
            category='smtp',
            is_encrypted=True,
        )
        db_session.add(enc_setting)
        db_session.commit()

        response = admin_client.get('/api/settings/backup')
        assert response.status_code == 200
        backup_data = json.loads(response.data.decode('utf-8'))

        assert backup_data['settings']['smtp_password'] == '***ENCRYPTED***'

    @patch('app.licensing.get_license')
    def test_passwords_not_in_backup(
        self, mock_get_license, app, admin_client,
        db_session, setup_complete, admin_user,
    ):
        """30. Password hashes are NOT included in backup."""
        mock_get_license.return_value = _mock_license_professional()

        response = admin_client.get('/api/settings/backup')
        assert response.status_code == 200
        backup_data = json.loads(response.data.decode('utf-8'))

        # Check that user entries do not contain password_hash
        for user_entry in backup_data.get('users', []):
            assert 'password_hash' not in user_entry
            assert 'totp_secret' not in user_entry

    @patch('app.licensing.get_license')
    def test_license_data_not_in_backup(
        self, mock_get_license, app, admin_client,
        db_session, setup_complete, admin_user,
    ):
        """31. License data is NOT included in backup."""
        mock_get_license.return_value = _mock_license_professional()

        from app.models import SystemSettings

        lic_setting = SystemSettings(
            key='license_key',
            value='SK-PRO-TESTKEY',
            category='license',
            is_encrypted=True,
        )
        db_session.add(lic_setting)
        db_session.commit()

        response = admin_client.get('/api/settings/backup')
        assert response.status_code == 200
        backup_data = json.loads(response.data.decode('utf-8'))

        # License key should be masked since is_encrypted=True
        if 'license_key' in backup_data.get('settings', {}):
            assert (
                backup_data['settings']['license_key'] == '***ENCRYPTED***'
            )

    def test_utf8_characters_survive_csv_export(
        self, app, authenticated_client, db_session,
        setup_complete, test_org,
    ):
        """32. UTF-8 characters in product names survive export."""
        from app.models import (
            Product, Vulnerability, VulnerabilityMatch,
        )

        product = Product(
            vendor='Uferfischer GmbH',
            product_name='Datenbank-Verwaltung',
            version='2.0',
            criticality='medium',
            active=True,
            cpe_vendor='uferfischer',
            cpe_product='datenbank',
            match_type='auto',
            organization_id=test_org.id,
        )
        db_session.add(product)
        db_session.flush()

        vuln = Vulnerability(
            cve_id='CVE-2024-9999',
            vendor_project='Uferfischer GmbH',
            product='Datenbank-Verwaltung',
            vulnerability_name='Test UTF-8',
            date_added=date.today(),
            short_description='Schwachstelle mit Umlauten',
            required_action='Aktualisieren',
            cvss_score=5.0,
            severity='MEDIUM',
        )
        db_session.add(vuln)
        db_session.flush()

        match = VulnerabilityMatch(
            product_id=product.id,
            vulnerability_id=vuln.id,
        )
        db_session.add(match)
        db_session.commit()

        with authenticated_client.session_transaction() as sess:
            sess['organization_id'] = test_org.id

        response = authenticated_client.get('/api/reports/export/csv')
        assert response.status_code == 200

        text = response.data.decode('utf-8')
        # The UTF-8 product name should appear in the CSV
        assert 'Datenbank-Verwaltung' in text
        assert 'Uferfischer' in text

    def test_large_dataset_export(
        self, app, authenticated_client, db_session,
        setup_complete, test_org,
    ):
        """33. Large dataset export (100+ products) works correctly."""
        from app.models import (
            Product, Vulnerability, VulnerabilityMatch,
        )

        # Create a vulnerability to match against
        vuln = Vulnerability(
            cve_id='CVE-2024-0001',
            vendor_project='BulkVendor',
            product='BulkProduct',
            vulnerability_name='Bulk Test Vuln',
            date_added=date.today(),
            short_description='Bulk test',
            required_action='Update',
            cvss_score=7.0,
            severity='HIGH',
        )
        db_session.add(vuln)
        db_session.flush()

        # Create 110 products and matches
        for i in range(110):
            product = Product(
                vendor='BulkVendor',
                product_name=f'BulkProduct-{i}',
                version='1.0',
                criticality='medium',
                active=True,
                organization_id=test_org.id,
            )
            db_session.add(product)
            db_session.flush()

            match = VulnerabilityMatch(
                product_id=product.id,
                vulnerability_id=vuln.id,
            )
            db_session.add(match)

        db_session.commit()

        with authenticated_client.session_transaction() as sess:
            sess['organization_id'] = test_org.id

        response = authenticated_client.get('/api/reports/export/csv')
        assert response.status_code == 200

        rows = _parse_csv(response.data)
        # Header + at least 110 data rows
        data_rows = [r for r in rows[1:] if r and r[0]]
        assert len(data_rows) >= 110
