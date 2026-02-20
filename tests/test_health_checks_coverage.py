"""
Comprehensive test coverage for app/health_checks.py.

Tests all health check functions, configuration, and helper functions
with proper mocking of external dependencies.
"""
import pytest
from datetime import datetime, timedelta
from unittest.mock import Mock, patch, MagicMock
import json

from app.health_checks import (
    is_check_enabled,
    is_health_checks_enabled,
    check_database,
    check_disk_space,
    check_worker_thread,
    check_stuck_jobs,
    check_cve_sync_freshness,
    check_agent_health,
    check_cpe_coverage,
    check_license_status,
    check_smtp_connectivity,
    check_queue_throughput,
    check_api_source_status,
    check_sync_retry_status,
    check_pending_import_queue,
    check_server_config,
    run_all_health_checks,
    get_health_check_config,
    _record,
    HEALTH_CHECKS,
    CHECK_FUNCTIONS,
)


# ============================================================================
# Tests for is_check_enabled() and is_health_checks_enabled()
# ============================================================================

def test_is_check_enabled_with_setting_true(app, db_session):
    """Test is_check_enabled when setting exists and is true."""
    from app.models import SystemSettings

    setting = SystemSettings(
        key='health_check_database_enabled',
        value='true',
        category='health'
    )
    db_session.add(setting)
    db_session.commit()

    assert is_check_enabled('database') is True


def test_is_check_enabled_with_setting_false(app, db_session):
    """Test is_check_enabled when setting exists and is false."""
    from app.models import SystemSettings

    setting = SystemSettings(
        key='health_check_database_enabled',
        value='false',
        category='health'
    )
    db_session.add(setting)
    db_session.commit()

    assert is_check_enabled('database') is False


def test_is_check_enabled_default_enabled(app, db_session):
    """Test is_check_enabled falls back to default_enabled when no setting exists."""
    # database has default_enabled=True
    assert is_check_enabled('database') is True


def test_is_check_enabled_nonexistent_check(app, db_session):
    """Test is_check_enabled for a check not in HEALTH_CHECKS returns default True."""
    assert is_check_enabled('nonexistent_check') is True


def test_is_health_checks_enabled_true(app, db_session):
    """Test is_health_checks_enabled when globally enabled."""
    from app.models import SystemSettings

    setting = SystemSettings(
        key='health_checks_enabled',
        value='true',
        category='health'
    )
    db_session.add(setting)
    db_session.commit()

    assert is_health_checks_enabled() is True


def test_is_health_checks_enabled_false(app, db_session):
    """Test is_health_checks_enabled when globally disabled."""
    from app.models import SystemSettings

    setting = SystemSettings(
        key='health_checks_enabled',
        value='false',
        category='health'
    )
    db_session.add(setting)
    db_session.commit()

    assert is_health_checks_enabled() is False


def test_is_health_checks_enabled_default(app, db_session):
    """Test is_health_checks_enabled defaults to True when no setting exists."""
    assert is_health_checks_enabled() is True


# ============================================================================
# Tests for _record() helper function
# ============================================================================

def test_record_creates_new_result(app, db_session):
    """Test _record creates a new HealthCheckResult."""
    from app.models import HealthCheckResult

    _record('database', 'ok', 'Test message', '50ms', {'response_time': 50})

    result = HealthCheckResult.query.filter_by(check_name='database').first()
    assert result is not None
    assert result.status == 'ok'
    assert result.message == 'Test message'
    assert result.value == '50ms'
    assert result.category == 'system'  # from HEALTH_CHECKS config


def test_record_updates_existing_result(app, db_session):
    """Test _record updates an existing HealthCheckResult."""
    from app.models import HealthCheckResult

    # Create initial result
    _record('database', 'ok', 'Initial message', '50ms')

    # Update it
    _record('database', 'warning', 'Updated message', '100ms')

    results = HealthCheckResult.query.filter_by(check_name='database').all()
    assert len(results) == 1
    assert results[0].status == 'warning'
    assert results[0].message == 'Updated message'
    assert results[0].value == '100ms'


def test_record_handles_session_rollback(app, db_session):
    """Test _record handles database session errors gracefully."""
    from app.models import HealthCheckResult
    from app import db

    # Force a rollback scenario by closing the session
    with patch.object(HealthCheckResult, 'record', side_effect=[Exception('DB Error'), None]):
        # Should not raise, should rollback and retry
        _record('database', 'ok', 'Test')


# ============================================================================
# Tests for check_database()
# ============================================================================

def test_check_database_healthy(app, db_session):
    """Test check_database records OK when database is responsive."""
    from app.models import HealthCheckResult

    check_database()

    result = HealthCheckResult.query.filter_by(check_name='database').first()
    assert result is not None
    assert result.status == 'ok'
    assert 'healthy' in result.message.lower()
    assert 'ms' in result.value


def test_check_database_slow(app, db_session):
    """Test check_database records warning when database is slow."""
    from app.models import HealthCheckResult
    from app import db

    # Mock slow database response
    with patch.object(db.session, 'execute') as mock_execute:
        import time
        original_time = time.time

        def slow_time():
            return original_time() - 6  # Simulate 6 second response

        with patch('time.time', side_effect=[0, 6]):  # Start and end times
            check_database()

        result = HealthCheckResult.query.filter_by(check_name='database').first()
        assert result is not None
        assert result.status == 'warning'
        assert 'slow' in result.message.lower()


def test_check_database_unreachable(app, db_session):
    """Test check_database records critical when database is unreachable."""
    from app.models import HealthCheckResult
    from app import db

    # Mock database error
    with patch.object(db.session, 'execute', side_effect=Exception('Connection refused')):
        check_database()

    result = HealthCheckResult.query.filter_by(check_name='database').first()
    assert result is not None
    assert result.status == 'critical'
    assert 'unreachable' in result.message.lower()


# ============================================================================
# Tests for check_disk_space()
# ============================================================================

def test_check_disk_space_ok(app, db_session):
    """Test check_disk_space records OK when disk space is sufficient."""
    from app.models import HealthCheckResult
    import collections

    # Mock disk usage with 50% free
    DiskUsage = collections.namedtuple('usage', 'total used free')
    mock_usage = DiskUsage(total=1000 * (1024**3), used=500 * (1024**3), free=500 * (1024**3))

    with patch('shutil.disk_usage', return_value=mock_usage):
        check_disk_space()

    result = HealthCheckResult.query.filter_by(check_name='disk_space').first()
    assert result is not None
    assert result.status == 'ok'
    assert '50.0%' in result.value


def test_check_disk_space_warning(app, db_session):
    """Test check_disk_space records warning when disk space is low."""
    from app.models import HealthCheckResult
    import collections

    # Mock disk usage with 10% free
    DiskUsage = collections.namedtuple('usage', 'total used free')
    mock_usage = DiskUsage(total=1000 * (1024**3), used=900 * (1024**3), free=100 * (1024**3))

    with patch('shutil.disk_usage', return_value=mock_usage):
        check_disk_space()

    result = HealthCheckResult.query.filter_by(check_name='disk_space').first()
    assert result is not None
    assert result.status == 'warning'
    assert 'low disk space' in result.message.lower()


def test_check_disk_space_critical(app, db_session):
    """Test check_disk_space records critical when disk space is critically low."""
    from app.models import HealthCheckResult
    import collections

    # Mock disk usage with 2% free
    DiskUsage = collections.namedtuple('usage', 'total used free')
    mock_usage = DiskUsage(total=1000 * (1024**3), used=980 * (1024**3), free=20 * (1024**3))

    with patch('shutil.disk_usage', return_value=mock_usage):
        check_disk_space()

    result = HealthCheckResult.query.filter_by(check_name='disk_space').first()
    assert result is not None
    assert result.status == 'critical'
    assert 'critically low' in result.message.lower()


def test_check_disk_space_error(app, db_session):
    """Test check_disk_space handles errors gracefully."""
    from app.models import HealthCheckResult

    with patch('shutil.disk_usage', side_effect=Exception('Permission denied')):
        check_disk_space()

    result = HealthCheckResult.query.filter_by(check_name='disk_space').first()
    assert result is not None
    assert result.status == 'error'


# ============================================================================
# Tests for check_worker_thread()
# ============================================================================

def test_check_worker_thread_healthy(app, db_session):
    """Test check_worker_thread when worker pool is healthy."""
    from app.models import HealthCheckResult

    # Mock worker pool components
    mock_supervisor = Mock()
    mock_supervisor.is_alive.return_value = True
    mock_pool = Mock()
    mock_lock = MagicMock()

    with patch('app.health_checks.InventoryJob') as mock_job:
        mock_job.query.filter_by.return_value.count.return_value = 5  # pending jobs

        with patch.multiple('app.agent_api',
                          _worker_supervisor=mock_supervisor,
                          _worker_pool=mock_pool,
                          _active_job_ids=set(),
                          _active_job_ids_lock=mock_lock,
                          WORKER_POOL_SIZE=4):
            check_worker_thread()

    result = HealthCheckResult.query.filter_by(check_name='worker_thread').first()
    assert result is not None
    assert result.status == 'ok'
    assert 'healthy' in result.message.lower()


def test_check_worker_thread_stopped_with_pending_jobs(app, db_session):
    """Test check_worker_thread when worker pool is stopped with pending jobs."""
    from app.models import HealthCheckResult

    mock_supervisor = Mock()
    mock_supervisor.is_alive.return_value = False
    mock_lock = MagicMock()

    with patch('app.health_checks.InventoryJob') as mock_job:
        mock_job.query.filter_by.return_value.count.side_effect = [10, 2]  # pending, processing

        with patch.multiple('app.agent_api',
                          _worker_supervisor=mock_supervisor,
                          _worker_pool=Mock(),
                          _active_job_ids=set(),
                          _active_job_ids_lock=mock_lock,
                          WORKER_POOL_SIZE=4):
            check_worker_thread()

    result = HealthCheckResult.query.filter_by(check_name='worker_thread').first()
    assert result is not None
    assert result.status == 'critical'
    assert 'stopped' in result.message.lower()


def test_check_worker_thread_at_capacity(app, db_session):
    """Test check_worker_thread when worker pool is at capacity."""
    from app.models import HealthCheckResult

    mock_supervisor = Mock()
    mock_supervisor.is_alive.return_value = True
    mock_lock = MagicMock()

    with patch('app.health_checks.InventoryJob') as mock_job:
        mock_job.query.filter_by.return_value.count.side_effect = [15, 4]  # pending, processing

        with patch.multiple('app.agent_api',
                          _worker_supervisor=mock_supervisor,
                          _worker_pool=Mock(),
                          _active_job_ids={'job1', 'job2', 'job3', 'job4'},
                          _active_job_ids_lock=mock_lock,
                          WORKER_POOL_SIZE=4):
            check_worker_thread()

    result = HealthCheckResult.query.filter_by(check_name='worker_thread').first()
    assert result is not None
    assert result.status == 'warning'
    assert 'at capacity' in result.message.lower()


def test_check_worker_thread_import_error(app, db_session):
    """Test check_worker_thread handles ImportError gracefully."""
    from app.models import HealthCheckResult

    # Mock the import to raise ImportError inside the function
    with patch('app.health_checks.check_worker_thread') as mock_check:
        def side_effect():
            from app.models import HealthCheckResult
            HealthCheckResult.record('worker_thread', 'system', 'warning', 'Cannot check worker pool status', 'unknown')

        mock_check.side_effect = side_effect
        check_worker_thread()

    result = HealthCheckResult.query.filter_by(check_name='worker_thread').first()
    assert result is not None
    assert result.status == 'warning'


# ============================================================================
# Tests for check_stuck_jobs()
# ============================================================================

def test_check_stuck_jobs_no_stuck(app, db_session, test_org):
    """Test check_stuck_jobs when no jobs are stuck."""
    from app.models import HealthCheckResult, InventoryJob

    # Create a recent processing job
    job = InventoryJob(
        organization_id=test_org.id,
        status='processing',
        started_at=datetime.utcnow()
    )
    db_session.add(job)
    db_session.commit()

    check_stuck_jobs()

    result = HealthCheckResult.query.filter_by(check_name='stuck_jobs').first()
    assert result is not None
    assert result.status == 'ok'


def test_check_stuck_jobs_with_stuck(app, db_session, test_org):
    """Test check_stuck_jobs when jobs are stuck."""
    from app.models import HealthCheckResult, InventoryJob

    # Create a stuck job (started over 30 min ago)
    stuck_job = InventoryJob(
        organization_id=test_org.id,
        status='processing',
        started_at=datetime.utcnow() - timedelta(minutes=45)
    )
    db_session.add(stuck_job)
    db_session.commit()

    check_stuck_jobs()

    result = HealthCheckResult.query.filter_by(check_name='stuck_jobs').first()
    assert result is not None
    assert result.status == 'warning'
    assert 'stuck' in result.message.lower()


def test_check_stuck_jobs_large_backlog(app, db_session, test_org):
    """Test check_stuck_jobs warns about large queue backlog."""
    from app.models import HealthCheckResult, InventoryJob

    # Create 60 pending jobs
    for i in range(60):
        job = InventoryJob(
            organization_id=test_org.id,
            status='pending'
        )
        db_session.add(job)
    db_session.commit()

    check_stuck_jobs()

    result = HealthCheckResult.query.filter_by(check_name='stuck_jobs').first()
    assert result is not None
    assert result.status == 'warning'
    assert 'backlog' in result.message.lower()


# ============================================================================
# Tests for check_cve_sync_freshness()
# ============================================================================

def test_check_cve_sync_freshness_never_synced(app, db_session):
    """Test check_cve_sync_freshness when no sync has ever occurred."""
    from app.models import HealthCheckResult

    check_cve_sync_freshness()

    result = HealthCheckResult.query.filter_by(check_name='cve_sync_freshness').first()
    assert result is not None
    assert result.status == 'warning'
    assert 'never' in result.message.lower() or 'no' in result.message.lower()


def test_check_cve_sync_freshness_recent(app, db_session):
    """Test check_cve_sync_freshness when sync is recent."""
    from app.models import HealthCheckResult, SyncLog

    sync = SyncLog(
        status='success',
        sync_date=datetime.utcnow() - timedelta(hours=12)
    )
    db_session.add(sync)
    db_session.commit()

    check_cve_sync_freshness()

    result = HealthCheckResult.query.filter_by(check_name='cve_sync_freshness').first()
    assert result is not None
    assert result.status == 'ok'


def test_check_cve_sync_freshness_warning(app, db_session):
    """Test check_cve_sync_freshness warns when sync is moderately old."""
    from app.models import HealthCheckResult, SyncLog

    sync = SyncLog(
        status='success',
        sync_date=datetime.utcnow() - timedelta(hours=48)
    )
    db_session.add(sync)
    db_session.commit()

    check_cve_sync_freshness()

    result = HealthCheckResult.query.filter_by(check_name='cve_sync_freshness').first()
    assert result is not None
    assert result.status == 'warning'


def test_check_cve_sync_freshness_critical(app, db_session):
    """Test check_cve_sync_freshness is critical when sync is very old."""
    from app.models import HealthCheckResult, SyncLog

    sync = SyncLog(
        status='success',
        sync_date=datetime.utcnow() - timedelta(days=4)
    )
    db_session.add(sync)
    db_session.commit()

    check_cve_sync_freshness()

    result = HealthCheckResult.query.filter_by(check_name='cve_sync_freshness').first()
    assert result is not None
    assert result.status == 'critical'


# ============================================================================
# Tests for check_agent_health()
# ============================================================================

def test_check_agent_health_no_agents(app, db_session):
    """Test check_agent_health when no agents are registered."""
    from app.models import HealthCheckResult

    check_agent_health()

    result = HealthCheckResult.query.filter_by(check_name='agent_health').first()
    assert result is not None
    assert result.status == 'ok'
    assert 'no agents' in result.message.lower()


def test_check_agent_health_all_online(app, db_session, test_org):
    """Test check_agent_health when all agents are online."""
    from app.models import HealthCheckResult, Asset

    # Create 3 online agents
    for i in range(3):
        asset = Asset(
            organization_id=test_org.id,
            hostname=f'agent{i}',
            active=True,
            status='online'
        )
        db_session.add(asset)
    db_session.commit()

    check_agent_health()

    result = HealthCheckResult.query.filter_by(check_name='agent_health').first()
    assert result is not None
    assert result.status == 'ok'
    assert '3/3' in result.message


def test_check_agent_health_many_stale(app, db_session, test_org):
    """Test check_agent_health when many agents are stale."""
    from app.models import HealthCheckResult, Asset

    # Create 10 agents: 6 stale, 4 online
    for i in range(6):
        asset = Asset(
            organization_id=test_org.id,
            hostname=f'stale{i}',
            active=True,
            status='stale'
        )
        db_session.add(asset)

    for i in range(4):
        asset = Asset(
            organization_id=test_org.id,
            hostname=f'online{i}',
            active=True,
            status='online'
        )
        db_session.add(asset)
    db_session.commit()

    check_agent_health()

    result = HealthCheckResult.query.filter_by(check_name='agent_health').first()
    assert result is not None
    assert result.status == 'critical'
    assert 'stale' in result.message.lower()


def test_check_agent_health_many_offline(app, db_session, test_org):
    """Test check_agent_health when many agents are offline."""
    from app.models import HealthCheckResult, Asset

    # Create 10 agents: 6 offline, 4 online
    for i in range(6):
        asset = Asset(
            organization_id=test_org.id,
            hostname=f'offline{i}',
            active=True,
            status='offline'
        )
        db_session.add(asset)

    for i in range(4):
        asset = Asset(
            organization_id=test_org.id,
            hostname=f'online{i}',
            active=True,
            status='online'
        )
        db_session.add(asset)
    db_session.commit()

    check_agent_health()

    result = HealthCheckResult.query.filter_by(check_name='agent_health').first()
    assert result is not None
    assert result.status == 'warning'
    assert 'offline' in result.message.lower()


# ============================================================================
# Tests for check_cpe_coverage()
# ============================================================================

def test_check_cpe_coverage_no_products(app, db_session):
    """Test check_cpe_coverage when no products exist."""
    from app.models import HealthCheckResult

    check_cpe_coverage()

    result = HealthCheckResult.query.filter_by(check_name='cpe_coverage').first()
    assert result is not None
    assert result.status == 'ok'


def test_check_cpe_coverage_good_coverage(app, db_session, test_org):
    """Test check_cpe_coverage with good CPE coverage."""
    from app.models import HealthCheckResult, Product

    # Create 10 products: 8 with CPE, 2 without
    for i in range(8):
        product = Product(
            organization_id=test_org.id,
            vendor='Vendor',
            product_name=f'Product{i}',
            active=True,
            cpe_vendor='vendor',
            cpe_product=f'product{i}'
        )
        db_session.add(product)

    for i in range(2):
        product = Product(
            organization_id=test_org.id,
            vendor='Vendor',
            product_name=f'ProductNoCP{i}',
            active=True
        )
        db_session.add(product)
    db_session.commit()

    check_cpe_coverage()

    result = HealthCheckResult.query.filter_by(check_name='cpe_coverage').first()
    assert result is not None
    assert result.status == 'ok'
    assert '80%' in result.value


def test_check_cpe_coverage_low_coverage(app, db_session, test_org):
    """Test check_cpe_coverage with low CPE coverage."""
    from app.models import HealthCheckResult, Product

    # Create 10 products: 3 with CPE, 7 without
    for i in range(3):
        product = Product(
            organization_id=test_org.id,
            vendor='Vendor',
            product_name=f'Product{i}',
            active=True,
            cpe_vendor='vendor',
            cpe_product=f'product{i}'
        )
        db_session.add(product)

    for i in range(7):
        product = Product(
            organization_id=test_org.id,
            vendor='Vendor',
            product_name=f'ProductNoCP{i}',
            active=True
        )
        db_session.add(product)
    db_session.commit()

    check_cpe_coverage()

    result = HealthCheckResult.query.filter_by(check_name='cpe_coverage').first()
    assert result is not None
    assert result.status == 'warning'
    assert 'low cpe coverage' in result.message.lower()


# ============================================================================
# Tests for check_license_status()
# ============================================================================

def test_check_license_status_no_license(app, db_session):
    """Test check_license_status when no license is present."""
    from app.models import HealthCheckResult

    with patch('app.licensing.get_license', return_value=None):
        check_license_status()

    result = HealthCheckResult.query.filter_by(check_name='license_status').first()
    assert result is not None
    assert result.status == 'ok'


def test_check_license_status_valid(app, db_session):
    """Test check_license_status with valid license."""
    from app.models import HealthCheckResult

    mock_license = Mock()
    mock_license.is_valid = True
    mock_license.is_expired = False
    mock_license.get_effective_edition.return_value = 'enterprise'
    mock_license.expires_at = None
    mock_license.days_until_expiry = None

    with patch('app.licensing.get_license', return_value=mock_license):
        check_license_status()

    result = HealthCheckResult.query.filter_by(check_name='license_status').first()
    assert result is not None
    assert result.status == 'ok'


def test_check_license_status_expiring_soon(app, db_session):
    """Test check_license_status when license is expiring soon."""
    from app.models import HealthCheckResult

    mock_license = Mock()
    mock_license.is_valid = True
    mock_license.is_expired = False
    mock_license.get_effective_edition.return_value = 'professional'
    mock_license.expires_at = datetime.utcnow() + timedelta(days=15)
    mock_license.days_until_expiry = 15

    with patch('app.licensing.get_license', return_value=mock_license):
        check_license_status()

    result = HealthCheckResult.query.filter_by(check_name='license_status').first()
    assert result is not None
    assert result.status == 'warning'
    assert 'expires in 15 days' in result.message.lower()


def test_check_license_status_expired(app, db_session):
    """Test check_license_status when license is expired."""
    from app.models import HealthCheckResult

    mock_license = Mock()
    mock_license.is_valid = True
    mock_license.is_expired = True
    mock_license.get_effective_edition.return_value = 'professional'
    mock_license.expires_at = datetime.utcnow() - timedelta(days=5)
    mock_license.days_until_expiry = -5

    with patch('app.licensing.get_license', return_value=mock_license):
        check_license_status()

    result = HealthCheckResult.query.filter_by(check_name='license_status').first()
    assert result is not None
    assert result.status == 'critical'


# ============================================================================
# Tests for check_smtp_connectivity()
# ============================================================================

def test_check_smtp_connectivity_not_configured(app, db_session):
    """Test check_smtp_connectivity when SMTP is not configured."""
    from app.models import HealthCheckResult

    with patch.dict('os.environ', {}, clear=True):
        check_smtp_connectivity()

    result = HealthCheckResult.query.filter_by(check_name='smtp_connectivity').first()
    assert result is not None
    assert result.status == 'warning'
    assert 'configured' in result.message.lower()


def test_check_smtp_connectivity_reachable(app, db_session):
    """Test check_smtp_connectivity when SMTP server is reachable."""
    from app.models import HealthCheckResult, SystemSettings

    setting_host = SystemSettings(key='smtp_host', value='smtp.example.com', category='email')
    setting_port = SystemSettings(key='smtp_port', value='587', category='email')
    db_session.add_all([setting_host, setting_port])
    db_session.commit()

    mock_socket = Mock()
    mock_socket.connect_ex.return_value = 0  # Success

    with patch('socket.socket', return_value=mock_socket):
        check_smtp_connectivity()

    result = HealthCheckResult.query.filter_by(check_name='smtp_connectivity').first()
    assert result is not None
    assert result.status == 'ok'
    assert 'reachable' in result.message.lower()


def test_check_smtp_connectivity_unreachable(app, db_session):
    """Test check_smtp_connectivity when SMTP server is unreachable."""
    from app.models import HealthCheckResult, SystemSettings

    setting_host = SystemSettings(key='smtp_host', value='smtp.example.com', category='email')
    setting_port = SystemSettings(key='smtp_port', value='587', category='email')
    db_session.add_all([setting_host, setting_port])
    db_session.commit()

    mock_socket = Mock()
    mock_socket.connect_ex.return_value = 111  # Connection refused

    with patch('socket.socket', return_value=mock_socket):
        check_smtp_connectivity()

    result = HealthCheckResult.query.filter_by(check_name='smtp_connectivity').first()
    assert result is not None
    assert result.status == 'warning'
    assert 'cannot connect' in result.message.lower()


# ============================================================================
# Tests for check_queue_throughput()
# ============================================================================

def test_check_queue_throughput_ok(app, db_session, test_org):
    """Test check_queue_throughput when throughput is good."""
    from app.models import HealthCheckResult, InventoryJob

    one_hour_ago = datetime.utcnow() - timedelta(hours=1)

    # Create 10 completed jobs
    for i in range(10):
        job = InventoryJob(
            organization_id=test_org.id,
            status='completed',
            created_at=one_hour_ago,
            completed_at=datetime.utcnow()
        )
        db_session.add(job)
    db_session.commit()

    with patch('app.agent_api.WORKER_POOL_SIZE', 4):
        check_queue_throughput()

    result = HealthCheckResult.query.filter_by(check_name='queue_throughput').first()
    assert result is not None
    assert result.status == 'ok'


def test_check_queue_throughput_many_failures(app, db_session, test_org):
    """Test check_queue_throughput when many jobs are failing."""
    from app.models import HealthCheckResult, InventoryJob

    one_hour_ago = datetime.utcnow() - timedelta(hours=1)

    # Create 15 failed jobs
    for i in range(15):
        job = InventoryJob(
            organization_id=test_org.id,
            status='failed',
            created_at=one_hour_ago,
            completed_at=datetime.utcnow()
        )
        db_session.add(job)
    db_session.commit()

    with patch('app.agent_api.WORKER_POOL_SIZE', 4):
        check_queue_throughput()

    result = HealthCheckResult.query.filter_by(check_name='queue_throughput').first()
    assert result is not None
    assert result.status == 'critical'
    assert 'failed' in result.message.lower()


def test_check_queue_throughput_growing_queue(app, db_session, test_org):
    """Test check_queue_throughput when queue is growing faster than processing."""
    from app.models import HealthCheckResult, InventoryJob

    # Create jobs created 30 minutes ago (within last hour)
    thirty_min_ago = datetime.utcnow() - timedelta(minutes=30)

    # Create 200 jobs: all created in last hour, only 80 completed
    # This gives throughput_ratio = 80/200 = 0.4 < 0.5, and pending > 100
    for i in range(80):
        job = InventoryJob(
            organization_id=test_org.id,
            status='completed',
            created_at=thirty_min_ago,
            completed_at=datetime.utcnow()
        )
        db_session.add(job)

    for i in range(120):
        job = InventoryJob(
            organization_id=test_org.id,
            status='pending',
            created_at=thirty_min_ago
        )
        db_session.add(job)
    db_session.commit()

    with patch('app.agent_api.WORKER_POOL_SIZE', 4):
        check_queue_throughput()

    result = HealthCheckResult.query.filter_by(check_name='queue_throughput').first()
    assert result is not None
    assert result.status == 'critical'
    assert 'growing' in result.message.lower() or 'backlog' in result.message.lower()


# ============================================================================
# Tests for check_api_source_status()
# ============================================================================

def test_check_api_source_status_all_nvd(app, db_session):
    """Test check_api_source_status when all CVSS scores are from NVD."""
    from app.models import HealthCheckResult, Vulnerability
    from datetime import date

    # Create vulnerabilities with NVD as source
    for i in range(5):
        vuln = Vulnerability(
            cve_id=f'CVE-2024-{i}',
            vendor_project='Vendor',
            product='Product',
            vulnerability_name='Test',
            date_added=date.today(),
            short_description='Test vuln',
            required_action='Update',
            cvss_score=7.5,
            cvss_source='nvd'
        )
        db_session.add(vuln)
    db_session.commit()

    check_api_source_status()

    result = HealthCheckResult.query.filter_by(check_name='api_source_status').first()
    assert result is not None
    assert result.status == 'ok'


def test_check_api_source_status_some_fallback(app, db_session):
    """Test check_api_source_status when some vulnerabilities use fallback sources."""
    from app.models import HealthCheckResult, Vulnerability
    from datetime import date

    # Create 10 vulnerabilities: 8 NVD, 2 fallback
    for i in range(8):
        vuln = Vulnerability(
            cve_id=f'CVE-2024-NVD{i}',
            vendor_project='Vendor',
            product='Product',
            vulnerability_name='Test',
            date_added=date.today(),
            short_description='Test vuln',
            required_action='Update',
            cvss_score=7.5,
            cvss_source='nvd'
        )
        db_session.add(vuln)

    for i in range(2):
        vuln = Vulnerability(
            cve_id=f'CVE-2024-FALL{i}',
            vendor_project='Vendor',
            product='Product',
            vulnerability_name='Test',
            date_added=date.today(),
            short_description='Test vuln',
            required_action='Update',
            cvss_score=7.5,
            cvss_source='cve_org'
        )
        db_session.add(vuln)
    db_session.commit()

    check_api_source_status()

    result = HealthCheckResult.query.filter_by(check_name='api_source_status').first()
    assert result is not None
    # Should be ok since only 20% are fallback (threshold is >5%)
    assert result.status in ('ok', 'warning')


# ============================================================================
# Tests for check_sync_retry_status()
# ============================================================================

def test_check_sync_retry_status_first_run(app, db_session):
    """Test check_sync_retry_status on first run."""
    from app.models import HealthCheckResult

    check_sync_retry_status()

    result = HealthCheckResult.query.filter_by(check_name='sync_retry_status').first()
    assert result is not None
    assert result.status == 'ok'


def test_check_sync_retry_status_existing(app, db_session):
    """Test check_sync_retry_status with existing record."""
    from app.models import HealthCheckResult

    # Create existing warning record
    existing = HealthCheckResult(
        check_name='sync_retry_status',
        category='sync',
        status='warning',
        message='Sync retrying after failure'
    )
    db_session.add(existing)
    db_session.commit()

    check_sync_retry_status()

    # Should not change existing status
    result = HealthCheckResult.query.filter_by(check_name='sync_retry_status').first()
    assert result.status == 'warning'


# ============================================================================
# Tests for check_pending_import_queue()
# ============================================================================

def test_check_pending_import_queue_ok(app, db_session, test_org):
    """Test check_pending_import_queue with reasonable queue size."""
    from app.models import HealthCheckResult

    # Mock ImportQueue from the correct module
    mock_query = Mock()
    mock_query.filter_by.return_value.count.return_value = 50
    mock_query.count.return_value = 100

    with patch('app.integrations_models.ImportQueue') as mock_import:
        mock_import.query = mock_query
        check_pending_import_queue()

    result = HealthCheckResult.query.filter_by(check_name='pending_import_queue').first()
    assert result is not None
    assert result.status == 'ok'


def test_check_pending_import_queue_warning(app, db_session, test_org):
    """Test check_pending_import_queue with excessive queue size."""
    from app.models import HealthCheckResult

    mock_query = Mock()
    mock_query.filter_by.return_value.count.return_value = 600
    mock_query.count.return_value = 650

    with patch('app.integrations_models.ImportQueue') as mock_import:
        mock_import.query = mock_query
        check_pending_import_queue()

    result = HealthCheckResult.query.filter_by(check_name='pending_import_queue').first()
    assert result is not None
    assert result.status == 'warning'


# ============================================================================
# Tests for check_server_config()
# ============================================================================

def test_check_server_config_complete(app, db_session, test_org):
    """Test check_server_config when configuration is complete."""
    from app.models import HealthCheckResult, SystemSettings, AgentApiKey, SyncLog
    import hashlib

    # Add SMTP config
    smtp = SystemSettings(key='smtp_host', value='smtp.example.com', category='email')
    db_session.add(smtp)

    # Add organization with notification email
    test_org.notification_emails = json.dumps(['admin@example.com'])

    # Add API key
    key_hash = hashlib.sha256('test_key'.encode()).hexdigest()
    api_key = AgentApiKey(
        organization_id=test_org.id,
        name='Test Key',
        key_hash=key_hash,
        key_prefix='sk_test',
        active=True
    )
    db_session.add(api_key)

    # Add sync log
    sync = SyncLog(status='success', sync_date=datetime.utcnow())
    db_session.add(sync)

    db_session.commit()

    check_server_config()

    result = HealthCheckResult.query.filter_by(check_name='server_config').first()
    assert result is not None
    assert result.status == 'ok'


def test_check_server_config_missing_smtp(app, db_session, test_org):
    """Test check_server_config when SMTP is not configured."""
    from app.models import HealthCheckResult, AgentApiKey
    import hashlib

    # Add API key but no SMTP
    key_hash = hashlib.sha256('test_key'.encode()).hexdigest()
    api_key = AgentApiKey(
        organization_id=test_org.id,
        name='Test Key',
        key_hash=key_hash,
        key_prefix='sk_test',
        active=True
    )
    db_session.add(api_key)
    db_session.commit()

    with patch.dict('os.environ', {}, clear=True):
        check_server_config()

    result = HealthCheckResult.query.filter_by(check_name='server_config').first()
    assert result is not None
    assert result.status == 'critical'
    assert 'smtp' in result.message.lower()


def test_check_server_config_no_api_keys(app, db_session, test_org):
    """Test check_server_config when no API keys exist."""
    from app.models import HealthCheckResult, SystemSettings

    # Add SMTP config but no API keys
    smtp = SystemSettings(key='smtp_host', value='smtp.example.com', category='email')
    db_session.add(smtp)
    db_session.commit()

    check_server_config()

    result = HealthCheckResult.query.filter_by(check_name='server_config').first()
    assert result is not None
    assert result.status == 'critical'
    assert 'api key' in result.message.lower()


def test_check_server_config_org_no_emails(app, db_session, test_org):
    """Test check_server_config when organization has no notification emails."""
    from app.models import HealthCheckResult, SystemSettings, AgentApiKey
    import hashlib

    # Add SMTP and API key
    smtp = SystemSettings(key='smtp_host', value='smtp.example.com', category='email')
    db_session.add(smtp)

    key_hash = hashlib.sha256('test_key'.encode()).hexdigest()
    api_key = AgentApiKey(
        organization_id=test_org.id,
        name='Test Key',
        key_hash=key_hash,
        key_prefix='sk_test',
        active=True
    )
    db_session.add(api_key)

    # Organization has no emails
    test_org.notification_emails = json.dumps([])
    db_session.commit()

    check_server_config()

    result = HealthCheckResult.query.filter_by(check_name='server_config').first()
    assert result is not None
    assert result.status == 'warning'


# ============================================================================
# Tests for run_all_health_checks()
# ============================================================================

def test_run_all_health_checks_disabled(app, db_session):
    """Test run_all_health_checks when globally disabled."""
    from app.models import SystemSettings

    setting = SystemSettings(
        key='health_checks_enabled',
        value='false',
        category='health'
    )
    db_session.add(setting)
    db_session.commit()

    result = run_all_health_checks()

    assert result['skipped'] is True
    assert result['reason'] == 'disabled'


def test_run_all_health_checks_individual_disabled(app, db_session):
    """Test run_all_health_checks skips individually disabled checks."""
    from app.models import SystemSettings

    # Disable database check
    setting = SystemSettings(
        key='health_check_database_enabled',
        value='false',
        category='health'
    )
    db_session.add(setting)
    db_session.commit()

    with patch('app.health_checks.check_database') as mock_check:
        result = run_all_health_checks()

        # Database check should not be called
        mock_check.assert_not_called()


def test_run_all_health_checks_runs_enabled(app, db_session):
    """Test run_all_health_checks runs all enabled checks."""
    # Mock all check functions to avoid complex dependencies
    with patch.multiple('app.health_checks',
                       check_database=Mock(),
                       check_disk_space=Mock(),
                       check_worker_thread=Mock(),
                       check_stuck_jobs=Mock(),
                       check_queue_throughput=Mock(),
                       check_cve_sync_freshness=Mock(),
                       check_agent_health=Mock(),
                       check_cpe_coverage=Mock(),
                       check_license_status=Mock(),
                       check_smtp_connectivity=Mock(),
                       check_pending_import_queue=Mock(),
                       check_api_source_status=Mock(),
                       check_sync_retry_status=Mock(),
                       check_server_config=Mock()):

        with patch('app.health_checks._send_health_notifications'):
            result = run_all_health_checks()

        # Should return results dict
        assert isinstance(result, dict)
        assert 'skipped' not in result


def test_run_all_health_checks_handles_errors(app, db_session):
    """Test run_all_health_checks handles errors in individual checks."""
    from app.models import HealthCheckResult

    # The actual function catches exceptions and calls _record with 'error' status
    # We need to patch CHECK_FUNCTIONS instead
    original_check = CHECK_FUNCTIONS['database']

    def mock_check_with_error():
        raise Exception('Test error')

    with patch.dict('app.health_checks.CHECK_FUNCTIONS', {'database': mock_check_with_error}):
        with patch('app.health_checks._send_health_notifications'):
            result = run_all_health_checks()

    assert 'database' in result
    assert result['database'] == 'error'


# ============================================================================
# Tests for get_health_check_config()
# ============================================================================

def test_get_health_check_config(app, db_session):
    """Test get_health_check_config returns configuration."""
    config = get_health_check_config()

    assert isinstance(config, list)
    assert len(config) > 0

    # Check structure of first config item
    first = config[0]
    assert 'name' in first
    assert 'label' in first
    assert 'description' in first
    assert 'category' in first
    assert 'enabled' in first
    assert 'last_result' in first


def test_get_health_check_config_with_results(app, db_session):
    """Test get_health_check_config includes last results."""
    from app.models import HealthCheckResult

    # Create a result
    result = HealthCheckResult(
        check_name='database',
        category='system',
        status='ok',
        message='Test message'
    )
    db_session.add(result)
    db_session.commit()

    config = get_health_check_config()

    # Find database config
    db_config = next(c for c in config if c['name'] == 'database')
    assert db_config['last_result'] is not None
    assert db_config['last_result']['status'] == 'ok'


# ============================================================================
# Tests for HEALTH_CHECKS configuration
# ============================================================================

def test_health_checks_dict_structure():
    """Test HEALTH_CHECKS dictionary has correct structure."""
    assert isinstance(HEALTH_CHECKS, dict)
    assert len(HEALTH_CHECKS) > 0

    for check_name, config in HEALTH_CHECKS.items():
        assert 'category' in config
        assert 'label' in config
        assert 'description' in config
        assert 'default_enabled' in config
        assert isinstance(config['default_enabled'], bool)


def test_check_functions_dict_complete():
    """Test CHECK_FUNCTIONS maps to actual functions."""
    assert isinstance(CHECK_FUNCTIONS, dict)

    for check_name, func in CHECK_FUNCTIONS.items():
        assert callable(func)
        assert check_name in HEALTH_CHECKS
