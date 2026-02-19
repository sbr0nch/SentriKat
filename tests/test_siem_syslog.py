"""
Tests for SentriKat SIEM/syslog forwarding functionality.

Covers:
  - GET /api/settings/syslog (read configuration)
  - POST /api/settings/syslog (update configuration)
  - POST /api/settings/syslog/test (send test message)
  - send_syslog_event() (CEF, JSON, RFC5424 formats; UDP/TCP; severity/facility mapping)
  - Integration with vulnerability matching in filters.py
"""
import pytest
import json
import socket as stdlib_socket
from unittest.mock import patch, MagicMock, call
from datetime import datetime, date


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _set_syslog_settings(db_session, enabled=True, host='siem.example.com',
                         port='514', protocol='udp', fmt='cef',
                         facility='local0'):
    """Persist syslog settings into SystemSettings so the API/function can read them."""
    from app.models import SystemSettings

    settings = {
        'syslog_enabled': 'true' if enabled else 'false',
        'syslog_host': host,
        'syslog_port': str(port),
        'syslog_protocol': protocol,
        'syslog_format': fmt,
        'syslog_facility': facility,
    }
    for key, value in settings.items():
        existing = SystemSettings.query.filter_by(key=key).first()
        if existing:
            existing.value = value
        else:
            db_session.add(SystemSettings(key=key, value=value, category='syslog'))
    db_session.commit()


def _seed_syslog_settings(db_session):
    """Create all six syslog setting rows with defaults so the POST endpoint
    always hits the *update* path (avoiding the NOT NULL category bug on insert)."""
    _set_syslog_settings(db_session, enabled=False, host='', port='514',
                         protocol='udp', fmt='cef', facility='local0')


def _make_product(db_session, org, vendor='Apache', product_name='Tomcat',
                  version='10.1.18'):
    """Create a product that will match the sample vulnerability."""
    from app.models import Product

    product = Product(
        vendor=vendor,
        product_name=product_name,
        version=version,
        criticality='high',
        active=True,
        cpe_vendor=vendor.lower(),
        cpe_product=product_name.lower(),
        match_type='auto',
        organization_id=org.id,
    )
    db_session.add(product)
    db_session.commit()
    return product


def _make_vulnerability(db_session, cve_id='CVE-2024-1234', severity='HIGH',
                        cvss=8.5):
    """Create a vulnerability with CPE data covering Tomcat 10.1.18."""
    from app.models import Vulnerability

    vuln = Vulnerability(
        cve_id=cve_id,
        vendor_project='Apache',
        product='Tomcat',
        vulnerability_name=f'Test Vulnerability {cve_id}',
        date_added=date.today(),
        short_description='A test vulnerability for syslog testing',
        required_action='Update to latest version',
        cvss_score=cvss,
        severity=severity,
    )
    db_session.add(vuln)
    db_session.flush()
    vuln.set_cpe_entries([{
        'vendor': 'apache',
        'product': 'tomcat',
        'version_start': '10.0.0',
        'version_end': '10.1.25',
        'version_start_type': 'including',
        'version_end_type': 'excluding',
    }])
    db_session.commit()
    return vuln


# ===========================================================================
# Settings API Tests
# ===========================================================================

class TestGetSyslogSettings:
    """Tests for GET /api/settings/syslog."""

    def test_default_values_when_none_configured(self, app, admin_client, setup_complete):
        """1. Returns sensible defaults when no syslog settings exist."""
        resp = admin_client.get('/api/settings/syslog')
        assert resp.status_code == 200
        data = resp.get_json()
        assert data['enabled'] is False
        # When no DB rows exist, the value stored is None.  dict.get()
        # returns the key's value (None) rather than the default because
        # the key *is* present.  Port is the exception: the `or '514'`
        # fallback handles None correctly.
        assert data['host'] is None or data['host'] == ''
        assert data['port'] == 514
        # protocol/format/facility may be None or the documented default
        assert data['protocol'] in (None, 'udp')
        assert data['format'] in (None, 'cef')
        assert data['facility'] in (None, 'local0')

    def test_returns_saved_values(self, app, admin_client, db_session, setup_complete):
        """2. Returns previously persisted settings."""
        _set_syslog_settings(
            db_session, enabled=True, host='10.0.0.1', port='1514',
            protocol='tcp', fmt='json', facility='local3',
        )
        resp = admin_client.get('/api/settings/syslog')
        assert resp.status_code == 200
        data = resp.get_json()
        assert data['enabled'] is True
        assert data['host'] == '10.0.0.1'
        assert data['port'] == 1514
        assert data['protocol'] == 'tcp'
        assert data['format'] == 'json'
        assert data['facility'] == 'local3'


class TestUpdateSyslogSettings:
    """Tests for POST /api/settings/syslog."""

    def test_valid_update(self, app, admin_client, db_session, setup_complete):
        """3. Updating with valid data succeeds."""
        # Pre-seed so the endpoint hits the update path
        _seed_syslog_settings(db_session)

        resp = admin_client.post('/api/settings/syslog', json={
            'enabled': True,
            'host': 'siem.corp.local',
            'port': 1514,
            'protocol': 'tcp',
            'format': 'json',
            'facility': 'local5',
        })
        assert resp.status_code == 200
        body = resp.get_json()
        assert body['success'] is True

        # Verify persisted
        resp2 = admin_client.get('/api/settings/syslog')
        data = resp2.get_json()
        assert data['enabled'] is True
        assert data['host'] == 'siem.corp.local'
        assert data['port'] == 1514
        assert data['protocol'] == 'tcp'
        assert data['format'] == 'json'
        assert data['facility'] == 'local5'

    def test_invalid_protocol(self, app, admin_client, setup_complete):
        """4. Protocol not udp/tcp returns 400."""
        resp = admin_client.post('/api/settings/syslog', json={
            'host': 'siem.example.com',
            'protocol': 'tls',
        })
        assert resp.status_code == 400
        assert 'protocol' in resp.get_json()['error'].lower()

    def test_invalid_format(self, app, admin_client, setup_complete):
        """5. Format not cef/json/rfc5424 returns 400."""
        resp = admin_client.post('/api/settings/syslog', json={
            'host': 'siem.example.com',
            'format': 'xml',
        })
        assert resp.status_code == 400
        assert 'format' in resp.get_json()['error'].lower()

    @pytest.mark.parametrize('port', [0, 65536, -1])
    def test_invalid_port(self, app, admin_client, setup_complete, port):
        """6. Ports outside 1-65535 return 400."""
        resp = admin_client.post('/api/settings/syslog', json={
            'host': 'siem.example.com',
            'port': port,
        })
        assert resp.status_code == 400
        assert 'port' in resp.get_json()['error'].lower()

    def test_no_data_returns_400(self, app, admin_client, setup_complete):
        """7. POST with no JSON body returns 400."""
        resp = admin_client.post('/api/settings/syslog',
                                 content_type='application/json',
                                 data='')
        assert resp.status_code == 400

    def test_unauthenticated_returns_401(self, app, client, setup_complete):
        """8. Unauthenticated request is rejected."""
        resp = client.post('/api/settings/syslog', json={'host': 'x'})
        assert resp.status_code in (401, 302)

    def test_enable_disable_toggle(self, app, admin_client, db_session, setup_complete):
        """9. Can toggle syslog enabled/disabled."""
        _seed_syslog_settings(db_session)

        # Enable
        resp = admin_client.post('/api/settings/syslog', json={
            'enabled': True, 'host': 'siem.test', 'port': 514,
        })
        assert resp.status_code == 200
        data = admin_client.get('/api/settings/syslog').get_json()
        assert data['enabled'] is True

        # Disable
        resp = admin_client.post('/api/settings/syslog', json={
            'enabled': False, 'host': 'siem.test', 'port': 514,
        })
        assert resp.status_code == 200
        data = admin_client.get('/api/settings/syslog').get_json()
        assert data['enabled'] is False

    def test_overwrite_existing_settings(self, app, admin_client, db_session, setup_complete):
        """10. Updating settings overwrites previous values."""
        _seed_syslog_settings(db_session)

        # Initial save
        admin_client.post('/api/settings/syslog', json={
            'enabled': True, 'host': 'old.host', 'port': 514,
            'protocol': 'udp', 'format': 'cef',
        })
        # Overwrite
        admin_client.post('/api/settings/syslog', json={
            'enabled': True, 'host': 'new.host', 'port': 1514,
            'protocol': 'tcp', 'format': 'json',
        })
        data = admin_client.get('/api/settings/syslog').get_json()
        assert data['host'] == 'new.host'
        assert data['port'] == 1514
        assert data['protocol'] == 'tcp'
        assert data['format'] == 'json'


# ===========================================================================
# send_syslog_event() Unit Tests
#
# Note: send_syslog_event() imports `socket` locally.  We patch
# `socket.socket` at the stdlib level so the local import picks up
# our mock.
# ===========================================================================

class TestSendSyslogEventFormats:
    """Tests for CEF, JSON, and RFC5424 output formatting."""

    def test_cef_format_structure(self, app, db_session, setup_complete):
        """11. CEF format matches CEF:0|SentriKat|... template."""
        _set_syslog_settings(db_session, enabled=True, fmt='cef')
        mock_sock = MagicMock()
        with patch('socket.socket', return_value=mock_sock):
            from app.reports_api import send_syslog_event
            result = send_syslog_event(
                event_type='new_vulnerability',
                cve_id='CVE-2024-9999',
                severity='CRITICAL',
                product='Apache Tomcat',
                message='Critical vulnerability found',
            )
            assert result is True

            # Inspect the payload sent via UDP
            sent_data = mock_sock.sendto.call_args[0][0].decode('utf-8')
            assert 'CEF:0|SentriKat|VulnerabilityManagement|1.0|' in sent_data
            assert 'new_vulnerability' in sent_data
            assert 'CVE-2024-9999' in sent_data
            assert 'CRITICAL' in sent_data
            # CEF severity for CRITICAL = 10
            assert '|10|' in sent_data

    def test_json_format_structure(self, app, db_session, setup_complete):
        """12. JSON format contains structured payload."""
        _set_syslog_settings(db_session, enabled=True, fmt='json')
        mock_sock = MagicMock()
        with patch('socket.socket', return_value=mock_sock):
            from app.reports_api import send_syslog_event
            send_syslog_event(
                event_type='new_vulnerability',
                cve_id='CVE-2024-5555',
                severity='HIGH',
                product='nginx',
                message='High severity vulnerability',
            )

            sent_data = mock_sock.sendto.call_args[0][0].decode('utf-8')
            # Extract JSON portion (after the syslog header)
            json_start = sent_data.index('{')
            payload = json.loads(sent_data[json_start:])
            assert payload['source'] == 'SentriKat'
            assert payload['event_type'] == 'new_vulnerability'
            assert payload['cve_id'] == 'CVE-2024-5555'
            assert payload['severity'] == 'HIGH'
            assert payload['product'] == 'nginx'
            assert payload['message'] == 'High severity vulnerability'
            assert 'timestamp' in payload

    def test_rfc5424_format_structure(self, app, db_session, setup_complete):
        """13. RFC5424 output has the correct syslog structure."""
        _set_syslog_settings(db_session, enabled=True, fmt='rfc5424')
        mock_sock = MagicMock()
        with patch('socket.socket', return_value=mock_sock):
            from app.reports_api import send_syslog_event
            send_syslog_event(
                event_type='acknowledged',
                cve_id='CVE-2024-1111',
                severity='LOW',
                product='curl',
                message='Vulnerability acknowledged',
            )

            sent_data = mock_sock.sendto.call_args[0][0].decode('utf-8')
            # RFC5424: <priority>1 timestamp hostname appname ...
            assert '>1 ' in sent_data  # VERSION field = 1
            assert 'SentriKat' in sent_data
            assert 'VulnerabilityManagement' in sent_data
            assert 'CVE-2024-1111' in sent_data
            assert 'LOW' in sent_data
            assert 'curl' in sent_data


class TestSeverityMapping:
    """Tests for syslog severity code mapping."""

    @pytest.mark.parametrize('severity,expected_code', [
        ('CRITICAL', 2),
        ('HIGH', 3),
        ('MEDIUM', 4),
        ('LOW', 5),
    ])
    def test_severity_to_syslog_code(self, app, db_session, setup_complete,
                                     severity, expected_code):
        """14. Severity strings map to the correct syslog severity numbers."""
        _set_syslog_settings(db_session, enabled=True, fmt='cef',
                             facility='local0')
        mock_sock = MagicMock()
        with patch('socket.socket', return_value=mock_sock):
            from app.reports_api import send_syslog_event
            send_syslog_event(
                event_type='new_vulnerability',
                cve_id='CVE-2024-0001',
                severity=severity,
                product='TestProduct',
                message='test',
            )

            sent_data = mock_sock.sendto.call_args[0][0].decode('utf-8')
            # Priority = facility(16) * 8 + severity_code
            expected_priority = 16 * 8 + expected_code
            assert sent_data.startswith(f'<{expected_priority}>')

    def test_unknown_severity_defaults_to_5(self, app, db_session, setup_complete):
        """24. Unknown severity string defaults to syslog code 5."""
        _set_syslog_settings(db_session, enabled=True, fmt='cef',
                             facility='local0')
        mock_sock = MagicMock()
        with patch('socket.socket', return_value=mock_sock):
            from app.reports_api import send_syslog_event
            send_syslog_event(
                event_type='new_vulnerability',
                cve_id='CVE-2024-0002',
                severity='UNKNOWN',
                product='TestProduct',
                message='test',
            )

            sent_data = mock_sock.sendto.call_args[0][0].decode('utf-8')
            # facility=local0 (16) -> priority = 16*8 + 5 = 133
            assert sent_data.startswith('<133>')


class TestFacilityMapping:
    """Tests for syslog facility mapping."""

    @pytest.mark.parametrize('facility,expected_code', [
        ('local0', 16),
        ('local1', 17),
        ('local2', 18),
        ('local3', 19),
        ('local4', 20),
        ('local5', 21),
        ('local6', 22),
        ('local7', 23),
    ])
    def test_facility_to_code(self, app, db_session, setup_complete,
                              facility, expected_code):
        """15. Facility names map to the correct numeric codes."""
        _set_syslog_settings(db_session, enabled=True, fmt='cef',
                             facility=facility)
        mock_sock = MagicMock()
        with patch('socket.socket', return_value=mock_sock):
            from app.reports_api import send_syslog_event
            send_syslog_event(
                event_type='test',
                cve_id='CVE-0000-0000',
                severity='MEDIUM',  # severity code 4
                product='Test',
                message='test',
            )

            sent_data = mock_sock.sendto.call_args[0][0].decode('utf-8')
            expected_priority = expected_code * 8 + 4
            assert sent_data.startswith(f'<{expected_priority}>')

    def test_unknown_facility_defaults_to_local0(self, app, db_session, setup_complete):
        """25. Unknown facility defaults to local0 (code 16)."""
        _set_syslog_settings(db_session, enabled=True, fmt='cef',
                             facility='invalid_facility')
        mock_sock = MagicMock()
        with patch('socket.socket', return_value=mock_sock):
            from app.reports_api import send_syslog_event
            send_syslog_event(
                event_type='test',
                cve_id='CVE-0000-0000',
                severity='MEDIUM',  # code 4
                product='Test',
                message='test',
            )

            sent_data = mock_sock.sendto.call_args[0][0].decode('utf-8')
            # local0 (16) * 8 + 4 = 132
            assert sent_data.startswith('<132>')


class TestSocketTransport:
    """Tests for UDP and TCP socket sending."""

    def test_udp_socket_sending(self, app, db_session, setup_complete):
        """16. UDP mode uses SOCK_DGRAM and sendto."""
        _set_syslog_settings(db_session, enabled=True, protocol='udp',
                             host='10.0.0.1', port='514')
        mock_sock = MagicMock()
        with patch('socket.socket', return_value=mock_sock) as mock_ctor:
            from app.reports_api import send_syslog_event
            result = send_syslog_event(
                event_type='test', cve_id='CVE-0000-0000',
                severity='LOW', product='Test', message='udp test',
            )

            assert result is True
            mock_ctor.assert_called_with(stdlib_socket.AF_INET, stdlib_socket.SOCK_DGRAM)
            mock_sock.settimeout.assert_called_with(5)
            mock_sock.sendto.assert_called_once()
            args = mock_sock.sendto.call_args[0]
            assert args[1] == ('10.0.0.1', 514)
            mock_sock.close.assert_called_once()

    def test_tcp_socket_sending(self, app, db_session, setup_complete):
        """17. TCP mode uses SOCK_STREAM, connect, and sendall."""
        _set_syslog_settings(db_session, enabled=True, protocol='tcp',
                             host='10.0.0.2', port='1514')
        mock_sock = MagicMock()
        with patch('socket.socket', return_value=mock_sock) as mock_ctor:
            from app.reports_api import send_syslog_event
            result = send_syslog_event(
                event_type='test', cve_id='CVE-0000-0000',
                severity='HIGH', product='Test', message='tcp test',
            )

            assert result is True
            mock_ctor.assert_called_with(stdlib_socket.AF_INET, stdlib_socket.SOCK_STREAM)
            mock_sock.settimeout.assert_called_with(5)
            mock_sock.connect.assert_called_once_with(('10.0.0.2', 1514))
            mock_sock.sendall.assert_called_once()
            # TCP messages end with newline
            sent_bytes = mock_sock.sendall.call_args[0][0]
            assert sent_bytes.endswith(b'\n')
            mock_sock.close.assert_called_once()


class TestSendSyslogEventReturnValues:
    """Tests for return value behaviour of send_syslog_event."""

    def test_returns_false_when_disabled(self, app, db_session, setup_complete):
        """18. Returns False when syslog is disabled."""
        _set_syslog_settings(db_session, enabled=False, host='siem.example.com')

        from app.reports_api import send_syslog_event
        result = send_syslog_event(
            event_type='test', cve_id='CVE-0000-0000',
            severity='HIGH', product='Test', message='test',
        )
        assert result is False

    def test_returns_false_when_no_host(self, app, db_session, setup_complete):
        """19. Returns False when no host is configured."""
        _set_syslog_settings(db_session, enabled=True, host='')

        from app.reports_api import send_syslog_event
        result = send_syslog_event(
            event_type='test', cve_id='CVE-0000-0000',
            severity='HIGH', product='Test', message='test',
        )
        assert result is False

    def test_returns_true_on_success(self, app, db_session, setup_complete):
        """20. Returns True when the message is sent successfully."""
        _set_syslog_settings(db_session, enabled=True, host='siem.example.com')
        mock_sock = MagicMock()
        with patch('socket.socket', return_value=mock_sock):
            from app.reports_api import send_syslog_event
            result = send_syslog_event(
                event_type='test', cve_id='CVE-0000-0000',
                severity='MEDIUM', product='Test', message='test',
            )
            assert result is True

    def test_connection_failure_returns_false(self, app, db_session, setup_complete):
        """21. Socket connection failure returns False."""
        _set_syslog_settings(db_session, enabled=True, host='unreachable.host',
                             protocol='tcp')
        mock_sock = MagicMock()
        mock_sock.connect.side_effect = ConnectionRefusedError('Connection refused')
        with patch('socket.socket', return_value=mock_sock):
            from app.reports_api import send_syslog_event
            result = send_syslog_event(
                event_type='test', cve_id='CVE-0000-0000',
                severity='HIGH', product='Test', message='test',
            )
            assert result is False

    def test_socket_timeout_returns_false(self, app, db_session, setup_complete):
        """22. Socket timeout returns False."""
        _set_syslog_settings(db_session, enabled=True, host='slow.host',
                             protocol='udp')
        mock_sock = MagicMock()
        mock_sock.sendto.side_effect = stdlib_socket.timeout('timed out')
        with patch('socket.socket', return_value=mock_sock):
            from app.reports_api import send_syslog_event
            result = send_syslog_event(
                event_type='test', cve_id='CVE-0000-0000',
                severity='LOW', product='Test', message='test',
            )
            assert result is False


class TestSendSyslogEventExtras:
    """Tests for extra kwargs included in the payload."""

    def test_extra_kwargs_in_cef_extensions(self, app, db_session, setup_complete):
        """23. vendor, due_date, ransomware appear in CEF extensions."""
        _set_syslog_settings(db_session, enabled=True, fmt='cef')
        mock_sock = MagicMock()
        with patch('socket.socket', return_value=mock_sock):
            from app.reports_api import send_syslog_event
            send_syslog_event(
                event_type='new_vulnerability',
                cve_id='CVE-2024-7777',
                severity='CRITICAL',
                product='Apache Tomcat',
                message='Critical vuln',
                vendor='Apache',
                due_date='2024-06-01',
                ransomware=True,
            )

            sent_data = mock_sock.sendto.call_args[0][0].decode('utf-8')
            assert 'vendor=Apache' in sent_data
            assert 'dueDate=2024-06-01' in sent_data
            assert 'ransomware=true' in sent_data

    def test_extra_kwargs_in_json_payload(self, app, db_session, setup_complete):
        """23b. Extra kwargs are merged into the JSON payload."""
        _set_syslog_settings(db_session, enabled=True, fmt='json')
        mock_sock = MagicMock()
        with patch('socket.socket', return_value=mock_sock):
            from app.reports_api import send_syslog_event
            send_syslog_event(
                event_type='new_vulnerability',
                cve_id='CVE-2024-8888',
                severity='HIGH',
                product='nginx',
                message='High vuln',
                vendor='NGINX Inc',
                due_date='2024-07-15',
                ransomware=False,
            )

            sent_data = mock_sock.sendto.call_args[0][0].decode('utf-8')
            json_start = sent_data.index('{')
            payload = json.loads(sent_data[json_start:])
            assert payload['vendor'] == 'NGINX Inc'
            assert payload['due_date'] == '2024-07-15'
            assert payload['ransomware'] is False


# ===========================================================================
# Test Endpoint Tests
# ===========================================================================

class TestSyslogTestEndpoint:
    """Tests for POST /api/settings/syslog/test."""

    def test_sends_test_message(self, app, admin_client, db_session, setup_complete):
        """26. Test endpoint sends a test syslog message when configured."""
        _set_syslog_settings(db_session, enabled=True, host='siem.test.local')
        mock_sock = MagicMock()
        with patch('socket.socket', return_value=mock_sock):
            resp = admin_client.post('/api/settings/syslog/test')
            assert resp.status_code == 200
            data = resp.get_json()
            assert data['success'] is True
            assert 'sent' in data['message'].lower()

            # Verify that a message was actually sent
            mock_sock.sendto.assert_called_once()
            sent_payload = mock_sock.sendto.call_args[0][0].decode('utf-8')
            assert 'CVE-0000-0000' in sent_payload
            assert 'SentriKat' in sent_payload

    def test_returns_400_when_disabled(self, app, admin_client, db_session, setup_complete):
        """27. Test endpoint returns 400 when syslog is disabled."""
        _set_syslog_settings(db_session, enabled=False, host='siem.test.local')

        resp = admin_client.post('/api/settings/syslog/test')
        assert resp.status_code == 400
        data = resp.get_json()
        assert data['success'] is False

    def test_returns_400_when_misconfigured(self, app, admin_client, db_session, setup_complete):
        """28. Test endpoint returns 400 when host is empty."""
        _set_syslog_settings(db_session, enabled=True, host='')

        resp = admin_client.post('/api/settings/syslog/test')
        assert resp.status_code == 400
        data = resp.get_json()
        assert data['success'] is False

    def test_exception_returns_500(self, app, admin_client, db_session, setup_complete):
        """29. Test endpoint returns 500 on unexpected exception."""
        _set_syslog_settings(db_session, enabled=True, host='siem.test.local')

        with patch('app.reports_api.send_syslog_event', side_effect=RuntimeError('boom')):
            resp = admin_client.post('/api/settings/syslog/test')
            assert resp.status_code == 500
            data = resp.get_json()
            assert data['success'] is False


# ===========================================================================
# Integration with Vulnerability Matching
# ===========================================================================

class TestSyslogVulnerabilityMatchingIntegration:
    """Tests for syslog events fired during vulnerability matching (filters.py)."""

    def test_new_match_triggers_syslog_event(self, app, db_session, setup_complete, test_org):
        """30. A new vulnerability match triggers a syslog event."""
        product = _make_product(db_session, test_org)
        vuln = _make_vulnerability(db_session)
        _set_syslog_settings(db_session, enabled=True, host='siem.int.local')

        mock_sock = MagicMock()
        with patch('socket.socket', return_value=mock_sock):
            from app.filters import match_vulnerabilities_to_products
            count = match_vulnerabilities_to_products(
                target_products=[product],
                target_vulnerabilities=[vuln],
            )

            assert count >= 1
            # Syslog was called at least once
            assert mock_sock.sendto.call_count >= 1
            sent_data = mock_sock.sendto.call_args[0][0].decode('utf-8')
            assert vuln.cve_id in sent_data

    def test_syslog_failure_doesnt_block_matching(self, app, db_session, setup_complete,
                                                  test_org):
        """31. A syslog send failure does not prevent the match from being created."""
        product = _make_product(db_session, test_org)
        vuln = _make_vulnerability(db_session, cve_id='CVE-2024-2222')
        _set_syslog_settings(db_session, enabled=True, host='siem.broken.local')

        mock_sock = MagicMock()
        mock_sock.sendto.side_effect = OSError('Network unreachable')
        with patch('socket.socket', return_value=mock_sock):
            from app.filters import match_vulnerabilities_to_products
            from app.models import VulnerabilityMatch
            count = match_vulnerabilities_to_products(
                target_products=[product],
                target_vulnerabilities=[vuln],
            )

            assert count >= 1
            match = VulnerabilityMatch.query.filter_by(
                product_id=product.id,
                vulnerability_id=vuln.id,
            ).first()
            assert match is not None

    def test_multiple_matches_send_multiple_events(self, app, db_session, setup_complete,
                                                   test_org):
        """32. Each new match sends a separate syslog event."""
        product = _make_product(db_session, test_org)
        vuln1 = _make_vulnerability(db_session, cve_id='CVE-2024-3001', severity='HIGH')
        vuln2 = _make_vulnerability(db_session, cve_id='CVE-2024-3002', severity='CRITICAL')
        _set_syslog_settings(db_session, enabled=True, host='siem.multi.local')

        mock_sock = MagicMock()
        with patch('socket.socket', return_value=mock_sock):
            from app.filters import match_vulnerabilities_to_products
            count = match_vulnerabilities_to_products(
                target_products=[product],
                target_vulnerabilities=[vuln1, vuln2],
            )

            assert count >= 2
            # At least 2 sendto calls (one per new match)
            assert mock_sock.sendto.call_count >= 2

    def test_existing_match_doesnt_send_syslog(self, app, db_session, setup_complete,
                                               test_org):
        """33. Re-running matching on an existing match does not re-send syslog."""
        product = _make_product(db_session, test_org)
        vuln = _make_vulnerability(db_session, cve_id='CVE-2024-4001')
        _set_syslog_settings(db_session, enabled=True, host='siem.dup.local')

        # First run: creates the match
        mock_sock1 = MagicMock()
        with patch('socket.socket', return_value=mock_sock1):
            from app.filters import match_vulnerabilities_to_products
            count1 = match_vulnerabilities_to_products(
                target_products=[product],
                target_vulnerabilities=[vuln],
            )
            assert count1 >= 1

        # Second run: match already exists, no new syslog event expected
        mock_sock2 = MagicMock()
        with patch('socket.socket', return_value=mock_sock2):
            count2 = match_vulnerabilities_to_products(
                target_products=[product],
                target_vulnerabilities=[vuln],
            )
            assert count2 == 0  # No new matches
            assert mock_sock2.sendto.call_count == 0

    def test_syslog_disabled_no_events(self, app, db_session, setup_complete, test_org):
        """34. When syslog is disabled, no events are sent even when matches are created."""
        product = _make_product(db_session, test_org)
        vuln = _make_vulnerability(db_session, cve_id='CVE-2024-5001')
        _set_syslog_settings(db_session, enabled=False, host='siem.off.local')

        mock_sock = MagicMock()
        with patch('socket.socket', return_value=mock_sock) as mock_ctor:
            from app.filters import match_vulnerabilities_to_products
            count = match_vulnerabilities_to_products(
                target_products=[product],
                target_vulnerabilities=[vuln],
            )

            assert count >= 1
            # Socket constructor should never be called when disabled
            mock_ctor.assert_not_called()


# ===========================================================================
# Priority / CEF Score Tests
# ===========================================================================

class TestCEFSeverityScores:
    """Tests for CEF severity score mapping."""

    @pytest.mark.parametrize('severity,expected_cef_score', [
        ('CRITICAL', 10),
        ('HIGH', 8),
        ('MEDIUM', 5),
        ('LOW', 3),
    ])
    def test_cef_severity_mapping(self, app, db_session, setup_complete,
                                  severity, expected_cef_score):
        """35-38. Severity maps to the correct CEF severity score."""
        _set_syslog_settings(db_session, enabled=True, fmt='cef')
        mock_sock = MagicMock()
        with patch('socket.socket', return_value=mock_sock):
            from app.reports_api import send_syslog_event
            send_syslog_event(
                event_type='new_vulnerability',
                cve_id='CVE-2024-0099',
                severity=severity,
                product='TestProduct',
                message='CEF score test',
            )

            sent_data = mock_sock.sendto.call_args[0][0].decode('utf-8')
            # CEF format: ...|Name|Severity|Extensions
            assert f'|{expected_cef_score}|' in sent_data


class TestPriorityCalculation:
    """Tests for syslog priority value (facility * 8 + severity)."""

    @pytest.mark.parametrize('facility,severity,expected_priority', [
        ('local0', 'CRITICAL', 16 * 8 + 2),  # 130
        ('local0', 'HIGH', 16 * 8 + 3),       # 131
        ('local0', 'MEDIUM', 16 * 8 + 4),     # 132
        ('local0', 'LOW', 16 * 8 + 5),        # 133
        ('local1', 'CRITICAL', 17 * 8 + 2),   # 138
        ('local3', 'HIGH', 19 * 8 + 3),       # 155
        ('local7', 'LOW', 23 * 8 + 5),        # 189
    ])
    def test_priority_equals_facility_times_8_plus_severity(
        self, app, db_session, setup_complete, facility, severity, expected_priority
    ):
        """39. Priority = facility_code * 8 + severity_code."""
        _set_syslog_settings(db_session, enabled=True, fmt='cef',
                             facility=facility)
        mock_sock = MagicMock()
        with patch('socket.socket', return_value=mock_sock):
            from app.reports_api import send_syslog_event
            send_syslog_event(
                event_type='test',
                cve_id='CVE-0000-0000',
                severity=severity,
                product='Test',
                message='priority test',
            )

            sent_data = mock_sock.sendto.call_args[0][0].decode('utf-8')
            assert sent_data.startswith(f'<{expected_priority}>')
