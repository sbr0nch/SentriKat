"""
Tests for the license heartbeat retry/backoff logic (H5).
"""

from unittest.mock import patch, MagicMock

import pytest
import requests


@pytest.fixture
def _dev_license(monkeypatch, app):
    """Install the in-repo development license key so license_heartbeat()
    will actually reach the HTTP branch instead of short-circuiting."""
    monkeypatch.setenv('SENTRIKAT_LICENSE', 'SENTRIKAT-DEV-PROFESSIONAL')
    monkeypatch.delenv('FLASK_ENV', raising=False)
    monkeypatch.delenv('SENTRIKAT_ENV', raising=False)
    from app.licensing import reload_license
    with app.app_context():
        reload_license()
    yield
    with app.app_context():
        reload_license()


@pytest.fixture(autouse=True)
def _no_sleep(monkeypatch):
    """Skip the real sleeps between retries so tests stay fast."""
    monkeypatch.setattr('app.licensing.time.sleep', lambda *_a, **_k: None)
    yield


class TestHeartbeatRetry:
    def test_retries_then_succeeds(self, app, _dev_license, setup_complete):
        """Mock that fails twice then returns 200 — heartbeat must succeed
        and the failure counter must NOT be bumped."""
        from app import licensing

        ok_response = MagicMock()
        ok_response.status_code = 200
        ok_response.json.return_value = {'status': 'active', 'message': 'ok'}

        call_count = {'n': 0}

        def _post(*args, **kwargs):
            call_count['n'] += 1
            if call_count['n'] <= 2:
                raise requests.ConnectionError('simulated network blip')
            return ok_response

        with app.app_context(), \
                patch('requests.post', side_effect=_post):
            result = licensing.license_heartbeat()

        assert result['success'] is True, result
        assert call_count['n'] == 3  # two failures + one success

        # Failure counter should be 0 (reset on success).
        with app.app_context():
            from app.models import SystemSettings
            row = SystemSettings.query.filter_by(
                key='license_heartbeat_failures'
            ).first()
            assert row is None or row.value == '0'

    def test_exhausts_retries_and_records_failure(
        self, app, _dev_license, setup_complete
    ):
        """Mock that fails on every attempt — we expect a terminal failure,
        the failure counter to advance, and after 3 failures the
        ``license_heartbeat_alert`` flag to be set."""
        from app import licensing

        with app.app_context(), \
                patch(
                    'requests.post',
                    side_effect=requests.ConnectionError('totally down'),
                ):
            result1 = licensing.license_heartbeat()
            assert result1['success'] is False
            assert 'Heartbeat failed' in (result1.get('message') or '')

            result2 = licensing.license_heartbeat()
            assert result2['success'] is False

            result3 = licensing.license_heartbeat()
            assert result3['success'] is False

        with app.app_context():
            from app.models import SystemSettings
            counter = SystemSettings.query.filter_by(
                key='license_heartbeat_failures'
            ).first()
            assert counter is not None
            assert int(counter.value) >= 3

            alert = SystemSettings.query.filter_by(
                key='license_heartbeat_alert'
            ).first()
            assert alert is not None
            assert alert.value == 'true'

    def test_success_resets_alert(self, app, _dev_license, setup_complete):
        """After a success, the alert flag must be cleared."""
        from app import licensing
        from app.models import SystemSettings
        from app import db

        with app.app_context():
            db.session.add(SystemSettings(
                key='license_heartbeat_failures', value='5',
                category='licensing',
            ))
            db.session.add(SystemSettings(
                key='license_heartbeat_alert', value='true',
                category='licensing',
            ))
            db.session.commit()

        ok = MagicMock()
        ok.status_code = 200
        ok.json.return_value = {'status': 'active'}

        with app.app_context(), patch('requests.post', return_value=ok):
            result = licensing.license_heartbeat()

        assert result['success'] is True
        with app.app_context():
            counter = SystemSettings.query.filter_by(
                key='license_heartbeat_failures'
            ).first()
            assert counter.value == '0'
            alert = SystemSettings.query.filter_by(
                key='license_heartbeat_alert'
            ).first()
            assert alert.value == 'false'
