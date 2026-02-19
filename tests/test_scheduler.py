"""
Tests for app/scheduler.py - Background job scheduler.

Covers: _run_with_lock, start_scheduler, cisa_sync_job, retry logic,
reschedule_critical_email, individual job handlers, and error handling.
"""
import pytest
import threading
from unittest.mock import patch, MagicMock, PropertyMock, call
from datetime import datetime, timedelta


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _reset_scheduler_globals():
    """Reset module-level globals between tests to avoid cross-contamination."""
    import app.scheduler as sched_mod
    sched_mod._scheduler = None
    sched_mod._app = None
    sched_mod._sync_retry_count = 0
    with sched_mod._job_locks_lock:
        sched_mod._job_locks.clear()


@pytest.fixture(autouse=True)
def _clean_scheduler_state():
    """Ensure scheduler globals are reset before and after every test."""
    _reset_scheduler_globals()
    yield
    _reset_scheduler_globals()


# ===================================================================
# _run_with_lock
# ===================================================================

class TestRunWithLock:
    """Tests for the _run_with_lock concurrency guard."""

    def test_run_with_lock_executes_function(self):
        """_run_with_lock should call the wrapped function and return its result."""
        from app.scheduler import _run_with_lock

        result = _run_with_lock('test_job', lambda: 42)
        assert result == 42

    def test_run_with_lock_prevents_concurrent_execution(self):
        """If a job is already running, a second invocation should be skipped."""
        import app.scheduler as sched_mod
        from app.scheduler import _run_with_lock

        barrier = threading.Barrier(2, timeout=5)
        call_count = 0

        def slow_job():
            nonlocal call_count
            call_count += 1
            barrier.wait()  # hold the lock until the other thread tries

        t1 = threading.Thread(target=_run_with_lock, args=('dup', slow_job))
        t1.start()

        # Give t1 time to acquire the lock
        import time
        time.sleep(0.05)

        # This should be skipped because t1 still holds the lock
        _run_with_lock('dup', slow_job)

        # Release barrier so t1 can finish
        try:
            barrier.wait(timeout=0.1)
        except threading.BrokenBarrierError:
            pass
        t1.join(timeout=3)

        assert call_count == 1, "Second invocation should have been skipped"

    def test_run_with_lock_releases_after_exception(self):
        """Lock must be released even when the wrapped function raises."""
        import app.scheduler as sched_mod
        from app.scheduler import _run_with_lock

        def failing_job():
            raise RuntimeError("boom")

        # First call raises
        with pytest.raises(RuntimeError):
            _run_with_lock('err_job', failing_job)

        # Lock should now be False so a subsequent call should execute
        result = _run_with_lock('err_job', lambda: 'recovered')
        assert result == 'recovered'

    def test_run_with_lock_passes_args_and_kwargs(self):
        """Arguments and keyword arguments should be forwarded."""
        from app.scheduler import _run_with_lock

        def add(a, b, extra=0):
            return a + b + extra

        assert _run_with_lock('math', add, 2, 3, extra=10) == 15


# ===================================================================
# start_scheduler
# ===================================================================

class TestStartScheduler:
    """Tests for start_scheduler initialization."""

    @patch('app.scheduler.BackgroundScheduler')
    @patch('app.scheduler.get_critical_email_settings', return_value=(True, 9, 0))
    @patch('app.scheduler.refresh_known_cve_products', create=True)
    def test_start_scheduler_returns_scheduler_and_starts_it(
        self, mock_refresh, mock_email_settings, MockScheduler, app
    ):
        """start_scheduler should create, configure, and start a BackgroundScheduler."""
        from app.scheduler import start_scheduler
        import app.scheduler as sched_mod

        mock_sched_instance = MagicMock()
        MockScheduler.return_value = mock_sched_instance

        with patch('app.scheduler.refresh_known_cve_products', return_value=0):
            result = start_scheduler(app)

        assert result is mock_sched_instance
        mock_sched_instance.start.assert_called_once()
        assert sched_mod._scheduler is mock_sched_instance
        assert sched_mod._app is app

    @patch('app.scheduler.BackgroundScheduler')
    @patch('app.scheduler.get_critical_email_settings', return_value=(True, 9, 0))
    def test_start_scheduler_registers_daily_cisa_sync(
        self, mock_email_settings, MockScheduler, app
    ):
        """The daily CISA KEV sync job must always be registered."""
        from app.scheduler import start_scheduler

        mock_sched = MagicMock()
        MockScheduler.return_value = mock_sched

        with patch('app.scheduler.refresh_known_cve_products', return_value=0):
            start_scheduler(app)

        job_ids = [c.kwargs.get('id') for c in mock_sched.add_job.call_args_list]
        assert 'daily_cisa_sync' in job_ids

    @patch('app.scheduler.BackgroundScheduler')
    @patch('app.scheduler.get_critical_email_settings', return_value=(False, 9, 0))
    def test_start_scheduler_skips_critical_email_when_disabled(
        self, mock_email_settings, MockScheduler, app
    ):
        """If critical email is disabled, its job should NOT be registered."""
        from app.scheduler import start_scheduler

        mock_sched = MagicMock()
        MockScheduler.return_value = mock_sched

        with patch('app.scheduler.refresh_known_cve_products', return_value=0):
            start_scheduler(app)

        job_ids = [c.kwargs.get('id') for c in mock_sched.add_job.call_args_list]
        assert 'daily_critical_cve_reminder' not in job_ids

    @patch.dict('os.environ', {'LDAP_SYNC_ENABLED': 'true', 'LDAP_SYNC_INTERVAL_HOURS': '12'})
    @patch('app.scheduler.BackgroundScheduler')
    @patch('app.scheduler.get_critical_email_settings', return_value=(True, 9, 0))
    def test_start_scheduler_registers_ldap_sync_when_enabled(
        self, mock_email_settings, MockScheduler, app
    ):
        """LDAP sync job should be registered when LDAP_SYNC_ENABLED=true."""
        from app.scheduler import start_scheduler

        mock_sched = MagicMock()
        MockScheduler.return_value = mock_sched

        with patch('app.scheduler.refresh_known_cve_products', return_value=0):
            start_scheduler(app)

        job_ids = [c.kwargs.get('id') for c in mock_sched.add_job.call_args_list]
        assert 'scheduled_ldap_sync' in job_ids

    @patch('app.scheduler.BackgroundScheduler')
    @patch('app.scheduler.get_critical_email_settings', return_value=(True, 9, 0))
    def test_start_scheduler_registers_all_core_jobs(
        self, mock_email_settings, MockScheduler, app
    ):
        """Verify the core set of always-registered jobs exists."""
        from app.scheduler import start_scheduler

        mock_sched = MagicMock()
        MockScheduler.return_value = mock_sched

        with patch('app.scheduler.refresh_known_cve_products', return_value=0):
            start_scheduler(app)

        job_ids = set(c.kwargs.get('id') for c in mock_sched.add_job.call_args_list)
        expected_core_jobs = {
            'daily_cisa_sync',
            'daily_critical_cve_reminder',
            'data_retention_cleanup',
            'daily_vulnerability_snapshot',
            'process_scheduled_reports',
            'vendor_advisory_sync',
            'license_heartbeat',
            'kb_sync',
            'nvd_cpe_dict_sync',
            'cve_known_products_refresh',
            'stuck_job_recovery',
            'auto_detect_asset_type',
            'agent_offline_detection',
            'unmapped_cpe_retry',
            'background_health_checks',
            'euvd_exploited_sync',
            'cvss_reenrich',
            'nvd_cve_sync',
        }
        for jid in expected_core_jobs:
            assert jid in job_ids, f"Expected job '{jid}' not registered"


# ===================================================================
# cisa_sync_job
# ===================================================================

class TestCisaSyncJob:
    """Tests for the cisa_sync_job wrapper."""

    @patch('app.scheduler._cancel_pending_sync_retries')
    @patch('app.scheduler._record_sync_retry_status')
    @patch('app.scheduler.sync_cisa_kev', return_value={'added': 5})
    def test_cisa_sync_job_success(self, mock_sync, mock_record, mock_cancel, app):
        """On success, sync_cisa_kev is called and retry state is cleared."""
        from app.scheduler import cisa_sync_job
        import app.scheduler as sched_mod

        sched_mod._sync_retry_count = 2  # pretend we had retries

        with app.app_context():
            # Need to mock the sub-steps that import app modules
            with patch('app.scheduler.sync_epss_scores', create=True, return_value=(0, 0, 'ok')), \
                 patch('app.scheduler.build_cpe_dictionary', create=True, return_value={}), \
                 patch('app.scheduler.batch_apply_cpe_mappings', create=True, return_value=(0, 0)), \
                 patch('app.scheduler.cleanup_bad_auto_mappings', create=True, return_value=0):
                cisa_sync_job(app)

        mock_sync.assert_called_once()
        mock_cancel.assert_called_once()
        mock_record.assert_called_with('idle')
        assert sched_mod._sync_retry_count == 0

    @patch('app.scheduler._schedule_sync_retry')
    @patch('app.scheduler.sync_cisa_kev', side_effect=Exception("Network error"))
    def test_cisa_sync_job_failure_triggers_retry(self, mock_sync, mock_retry, app):
        """On failure, _schedule_sync_retry should be called."""
        from app.scheduler import cisa_sync_job

        with app.app_context():
            cisa_sync_job(app)

        mock_retry.assert_called_once_with(app)


# ===================================================================
# Retry logic
# ===================================================================

class TestSyncRetryLogic:
    """Tests for _schedule_sync_retry and _cancel_pending_sync_retries."""

    @patch('app.scheduler._record_sync_retry_status')
    def test_schedule_sync_retry_increments_count(self, mock_record, app):
        """Each retry call should increment _sync_retry_count."""
        import app.scheduler as sched_mod
        from app.scheduler import _schedule_sync_retry

        mock_scheduler = MagicMock()
        sched_mod._scheduler = mock_scheduler
        sched_mod._sync_retry_count = 0

        _schedule_sync_retry(app)

        assert sched_mod._sync_retry_count == 1
        mock_scheduler.add_job.assert_called_once()
        # Verify the job id contains the retry number
        call_kwargs = mock_scheduler.add_job.call_args
        assert call_kwargs.kwargs['id'] == 'cisa_sync_retry_1'

    @patch('app.scheduler._record_sync_retry_status')
    def test_schedule_sync_retry_uses_exponential_delays(self, mock_record, app):
        """Retry delays should follow the exponential backoff schedule."""
        import app.scheduler as sched_mod
        from app.scheduler import _schedule_sync_retry, _SYNC_RETRY_DELAYS

        mock_scheduler = MagicMock()
        sched_mod._scheduler = mock_scheduler

        for i in range(4):
            sched_mod._sync_retry_count = i
            _schedule_sync_retry(app)
            # Verify recorded delay matches schedule
            mock_record.assert_called_with(
                'retry_scheduled', i + 1, _SYNC_RETRY_DELAYS[i]
            )
            mock_record.reset_mock()
            mock_scheduler.reset_mock()

    @patch('app.scheduler._record_sync_retry_status')
    def test_schedule_sync_retry_stops_after_max_retries(self, mock_record, app):
        """After _MAX_SYNC_RETRIES the retry count resets and no job is added."""
        import app.scheduler as sched_mod
        from app.scheduler import _schedule_sync_retry, _MAX_SYNC_RETRIES

        mock_scheduler = MagicMock()
        sched_mod._scheduler = mock_scheduler
        sched_mod._sync_retry_count = _MAX_SYNC_RETRIES

        _schedule_sync_retry(app)

        mock_scheduler.add_job.assert_not_called()
        mock_record.assert_called_with('exhausted')
        assert sched_mod._sync_retry_count == 0

    def test_cancel_pending_sync_retries_removes_jobs(self):
        """_cancel_pending_sync_retries should try to remove all retry job IDs."""
        import app.scheduler as sched_mod
        from app.scheduler import _cancel_pending_sync_retries, _MAX_SYNC_RETRIES

        mock_scheduler = MagicMock()
        sched_mod._scheduler = mock_scheduler

        _cancel_pending_sync_retries()

        assert mock_scheduler.remove_job.call_count == _MAX_SYNC_RETRIES
        for i in range(1, _MAX_SYNC_RETRIES + 1):
            mock_scheduler.remove_job.assert_any_call(f'cisa_sync_retry_{i}')

    def test_cancel_pending_sync_retries_tolerates_missing_jobs(self):
        """Removing non-existent jobs should not raise."""
        import app.scheduler as sched_mod
        from app.scheduler import _cancel_pending_sync_retries

        mock_scheduler = MagicMock()
        mock_scheduler.remove_job.side_effect = Exception("No such job")
        sched_mod._scheduler = mock_scheduler

        # Should not raise
        _cancel_pending_sync_retries()

    def test_cancel_pending_sync_retries_noop_without_scheduler(self):
        """When _scheduler is None, cancelling should be a silent no-op."""
        import app.scheduler as sched_mod
        from app.scheduler import _cancel_pending_sync_retries

        sched_mod._scheduler = None
        _cancel_pending_sync_retries()  # should not raise


# ===================================================================
# reschedule_critical_email
# ===================================================================

class TestRescheduleCriticalEmail:
    """Tests for reschedule_critical_email."""

    def test_reschedule_noop_without_scheduler(self):
        """If _scheduler or _app is None, reschedule should do nothing."""
        import app.scheduler as sched_mod
        from app.scheduler import reschedule_critical_email

        sched_mod._scheduler = None
        sched_mod._app = None
        reschedule_critical_email()  # should not raise

    @patch('app.scheduler.get_critical_email_settings', return_value=(True, 14, 30))
    def test_reschedule_adds_job_when_enabled(self, mock_settings, app):
        """When enabled, the existing job is removed and a new one added."""
        import app.scheduler as sched_mod
        from app.scheduler import reschedule_critical_email

        mock_scheduler = MagicMock()
        sched_mod._scheduler = mock_scheduler
        sched_mod._app = app

        reschedule_critical_email()

        mock_scheduler.remove_job.assert_called_once_with('daily_critical_cve_reminder')
        mock_scheduler.add_job.assert_called_once()
        add_kwargs = mock_scheduler.add_job.call_args.kwargs
        assert add_kwargs['id'] == 'daily_critical_cve_reminder'

    @patch('app.scheduler.get_critical_email_settings', return_value=(False, 9, 0))
    def test_reschedule_only_removes_when_disabled(self, mock_settings, app):
        """When disabled, the job is removed but NOT re-added."""
        import app.scheduler as sched_mod
        from app.scheduler import reschedule_critical_email

        mock_scheduler = MagicMock()
        sched_mod._scheduler = mock_scheduler
        sched_mod._app = app

        reschedule_critical_email()

        mock_scheduler.remove_job.assert_called_once_with('daily_critical_cve_reminder')
        mock_scheduler.add_job.assert_not_called()


# ===================================================================
# get_critical_email_settings
# ===================================================================

class TestGetCriticalEmailSettings:
    """Tests for get_critical_email_settings reading from the database."""

    def test_defaults_when_no_settings_exist(self, app, db_session):
        """With no SystemSettings rows, should return (True, 9, 0)."""
        from app.scheduler import get_critical_email_settings

        enabled, hour, minute = get_critical_email_settings(app)
        assert enabled is True
        assert hour == 9
        assert minute == 0

    def test_reads_enabled_and_time_from_db(self, app, db_session):
        """Should parse settings stored in SystemSettings."""
        from app.models import SystemSettings
        from app.scheduler import get_critical_email_settings

        db_session.add(SystemSettings(key='critical_email_enabled', value='false', category='email'))
        db_session.add(SystemSettings(key='critical_email_time', value='15:45', category='email'))
        db_session.commit()

        enabled, hour, minute = get_critical_email_settings(app)
        assert enabled is False
        assert hour == 15
        assert minute == 45

    def test_handles_malformed_time(self, app, db_session):
        """Malformed time values should fallback to 09:00."""
        from app.models import SystemSettings
        from app.scheduler import get_critical_email_settings

        db_session.add(SystemSettings(key='critical_email_time', value='not-a-time', category='email'))
        db_session.commit()

        enabled, hour, minute = get_critical_email_settings(app)
        assert hour == 9
        assert minute == 0


# ===================================================================
# Individual job handlers
# ===================================================================

class TestIndividualJobHandlers:
    """Tests for individual job wrappers (ldap, critical cve, data retention, etc.)."""

    @patch('app.scheduler.LDAPSyncEngine', create=True)
    def test_ldap_sync_job_calls_sync_all(self, MockEngine, app):
        """ldap_sync_job should invoke LDAPSyncEngine.sync_all_ldap_users."""
        from app.scheduler import ldap_sync_job

        MockEngine.sync_all_ldap_users = MagicMock(return_value={
            'success': True, 'sync_id': 1, 'stats': {}, 'duration': 0.5
        })

        with app.app_context():
            with patch('app.scheduler.LDAPSyncEngine', MockEngine):
                ldap_sync_job(app)

        MockEngine.sync_all_ldap_users.assert_called_once_with(
            organization_id=None, initiated_by=None
        )

    def test_ldap_sync_job_handles_exception(self, app):
        """ldap_sync_job should log and not raise on errors."""
        from app.scheduler import ldap_sync_job

        with app.app_context():
            with patch('app.scheduler.LDAPSyncEngine', create=True,
                       side_effect=ImportError("no ldap module")):
                # Should not raise
                ldap_sync_job(app)

    @patch('app.scheduler.VulnerabilitySnapshot', create=True)
    def test_vulnerability_snapshot_job(self, MockSnapshot, app, db_session):
        """vulnerability_snapshot_job should take snapshots for each org + global."""
        from app.scheduler import vulnerability_snapshot_job
        from app.models import Organization

        org = Organization(name='snap_org', display_name='Snap Org', active=True)
        db_session.add(org)
        db_session.commit()

        mock_take = MagicMock()
        with patch('app.scheduler.VulnerabilitySnapshot') as MS:
            MS.take_snapshot = mock_take
            vulnerability_snapshot_job(app)

        # Once for the org, once for global (org_id=None)
        assert mock_take.call_count >= 2

    def test_vendor_advisory_sync_job_calls_sync(self, app):
        """vendor_advisory_sync_job should call sync_vendor_advisories."""
        from app.scheduler import vendor_advisory_sync_job

        with app.app_context():
            with patch('app.scheduler.sync_vendor_advisories', create=True,
                       return_value={'overrides_created': 0, 'matches_resolved': 0, 'feeds_checked': 3}) as mock_sync:
                vendor_advisory_sync_job(app)
                mock_sync.assert_called_once()

    def test_license_heartbeat_job_calls_heartbeat(self, app):
        """license_heartbeat_job should call license_heartbeat."""
        from app.scheduler import license_heartbeat_job

        with app.app_context():
            with patch('app.scheduler.license_heartbeat', create=True,
                       return_value={'success': True, 'message': 'ok'}) as mock_hb:
                license_heartbeat_job(app)
                mock_hb.assert_called_once()

    def test_health_check_job_runs_checks(self, app):
        """health_check_job should call run_all_health_checks."""
        from app.scheduler import health_check_job

        with app.app_context():
            with patch('app.scheduler.run_all_health_checks', create=True,
                       return_value={'db': 'ok', 'disk': 'ok'}) as mock_hc:
                health_check_job(app)
                mock_hc.assert_called_once()


# ===================================================================
# Error handling in jobs
# ===================================================================

class TestJobErrorHandling:
    """Verify that all job wrappers catch exceptions gracefully."""

    def test_data_retention_cleanup_handles_exception(self, app):
        """data_retention_cleanup_job should not raise on internal errors."""
        from app.scheduler import data_retention_cleanup_job

        with app.app_context():
            with patch('app.scheduler.SystemSettings', create=True,
                       side_effect=Exception("DB gone")):
                # Should not raise
                data_retention_cleanup_job(app)

    def test_euvd_sync_job_handles_exception(self, app):
        """euvd_sync_job should catch and log errors."""
        from app.scheduler import euvd_sync_job

        with app.app_context():
            with patch('app.scheduler.enrich_with_euvd_exploited', create=True,
                       side_effect=RuntimeError("EUVD unreachable")):
                euvd_sync_job(app)  # should not raise

    def test_nvd_cve_sync_job_handles_exception(self, app):
        """nvd_cve_sync_job should catch and log errors."""
        from app.scheduler import nvd_cve_sync_job

        with app.app_context():
            with patch('app.scheduler.sync_nvd_recent_cves', create=True,
                       side_effect=RuntimeError("NVD down")):
                nvd_cve_sync_job(app)  # should not raise

    def test_cvss_reenrich_job_handles_exception(self, app):
        """cvss_reenrich_job should catch and log errors."""
        from app.scheduler import cvss_reenrich_job

        with app.app_context():
            with patch('app.scheduler.reenrich_fallback_cvss', create=True,
                       side_effect=RuntimeError("NVD rate limited")):
                cvss_reenrich_job(app)  # should not raise

    def test_kb_sync_job_handles_exception(self, app):
        """kb_sync_job should catch and log errors."""
        from app.scheduler import kb_sync_job

        with app.app_context():
            with patch('app.scheduler.kb_sync', create=True,
                       side_effect=RuntimeError("KB server unreachable")):
                kb_sync_job(app)  # should not raise

    def test_unmapped_cpe_retry_job_handles_exception(self, app):
        """unmapped_cpe_retry_job should catch and log errors."""
        from app.scheduler import unmapped_cpe_retry_job

        with app.app_context():
            with patch('app.scheduler.batch_apply_cpe_mappings', create=True,
                       side_effect=RuntimeError("mapping error")):
                unmapped_cpe_retry_job(app)  # should not raise


# ===================================================================
# sync_job backward compatibility
# ===================================================================

class TestSyncJobCompat:
    """Test the legacy sync_job function."""

    @patch('app.scheduler.cisa_sync_job')
    def test_sync_job_delegates_to_cisa_sync_job(self, mock_cisa, app):
        """sync_job should simply call cisa_sync_job."""
        from app.scheduler import sync_job

        sync_job(app)
        mock_cisa.assert_called_once_with(app)
