"""Stress tests for app.nvd_rate_limiter — [08.17.1] audit follow-up.

Validates the sliding-window limiter under:
- Burst load beyond the effective limit (no API key path)
- Concurrent thread contention (no slot leak above limit)
- API key invalidation mid-window
- Window expiry frees slots correctly

These tests do NOT sleep for 30s — they manipulate `_request_times`
directly to fast-forward window boundaries. Production behavior is
preserved; tests just avoid wall-clock waits.
"""

import threading
import time

import pytest

from app.nvd_rate_limiter import (
    NVDRateLimiter,
    NVDRateLimitError,
    _reset_limiter,
    get_rate_limiter,
    rate_limited,
)


@pytest.fixture(autouse=True)
def reset_limiter_singleton():
    """Each test gets a fresh limiter instance (singleton would otherwise carry state)."""
    _reset_limiter()
    yield
    _reset_limiter()


@pytest.fixture
def no_api_key_limiter(monkeypatch):
    """Force the limiter to behave as if no API key is configured (5/30s)."""
    monkeypatch.setattr(NVDRateLimiter, '_get_api_key', lambda self: None)
    return get_rate_limiter()


@pytest.fixture
def api_key_limiter(monkeypatch):
    """Force the limiter to behave as if an API key is configured (50/30s)."""
    monkeypatch.setattr(NVDRateLimiter, '_get_api_key', lambda self: 'fake-key')
    return get_rate_limiter()


class TestEffectiveLimit:
    def test_no_key_uses_safety_factor(self, no_api_key_limiter):
        # 5 * 0.9 = 4.5 → int → 4
        assert no_api_key_limiter._get_effective_limit() == 4

    def test_with_key_uses_safety_factor(self, api_key_limiter):
        # 50 * 0.9 = 45
        assert api_key_limiter._get_effective_limit() == 45


class TestBurstBehavior:
    def test_burst_within_limit_all_succeed(self, no_api_key_limiter):
        # 4 acquisitions back-to-back should all return True without blocking
        for _ in range(4):
            assert no_api_key_limiter.acquire(timeout=0.1, block=True) is True

    def test_burst_at_limit_non_blocking_returns_false(self, no_api_key_limiter):
        # Fill the window
        for _ in range(4):
            no_api_key_limiter.acquire(timeout=0.1, block=True)
        # 5th non-blocking call must fail fast
        start = time.time()
        result = no_api_key_limiter.acquire(timeout=0.1, block=False)
        elapsed = time.time() - start
        assert result is False
        assert elapsed < 0.05  # didn't actually wait

    def test_burst_at_limit_blocking_bails_when_wait_exceeds_timeout(self, no_api_key_limiter):
        for _ in range(4):
            no_api_key_limiter.acquire(timeout=0.1, block=True)
        # Blocking call with short timeout — limiter is smart enough to
        # bail immediately when the required wait_needed (~30s) exceeds
        # the requested timeout. This is the desired behavior: don't
        # waste the caller's budget on a futile sleep.
        start = time.time()
        result = no_api_key_limiter.acquire(timeout=0.5, block=True)
        elapsed = time.time() - start
        assert result is False
        assert elapsed < 0.05  # bailed fast, did NOT sleep the full 0.5s

    def test_blocked_count_increments(self, no_api_key_limiter):
        for _ in range(4):
            no_api_key_limiter.acquire(timeout=0.1, block=True)
        no_api_key_limiter.acquire(timeout=0.05, block=False)
        no_api_key_limiter.acquire(timeout=0.05, block=False)
        stats = no_api_key_limiter.get_stats()
        assert stats['blocked_requests'] == 2


class TestWindowExpiry:
    def test_aged_requests_freed_on_clean(self, no_api_key_limiter):
        # Manually inject expired entries
        old_ts = time.time() - (NVDRateLimiter.WINDOW_SECONDS + 1)
        for _ in range(4):
            no_api_key_limiter._request_times.append(old_ts)
        # acquire should clean and proceed without waiting
        start = time.time()
        result = no_api_key_limiter.acquire(timeout=0.1, block=True)
        elapsed = time.time() - start
        assert result is True
        assert elapsed < 0.05

    def test_partial_aged_requests(self, no_api_key_limiter):
        # 2 aged + 2 fresh — only 2 effective slots used
        old_ts = time.time() - (NVDRateLimiter.WINDOW_SECONDS + 1)
        no_api_key_limiter._request_times.append(old_ts)
        no_api_key_limiter._request_times.append(old_ts)
        no_api_key_limiter._request_times.append(time.time())
        no_api_key_limiter._request_times.append(time.time())
        # 2 fresh slots remain
        assert no_api_key_limiter.get_available_slots() == 2

    def test_get_wait_time_zero_when_slots_free(self, no_api_key_limiter):
        assert no_api_key_limiter.get_wait_time() == 0.0


class TestConcurrentAccess:
    def test_concurrent_threads_do_not_exceed_limit(self, no_api_key_limiter):
        """20 threads racing for 4 slots — exactly 4 succeed, 16 block out."""
        successes = []
        failures = []
        lock = threading.Lock()

        def worker():
            ok = no_api_key_limiter.acquire(timeout=0.05, block=False)
            with lock:
                if ok:
                    successes.append(1)
                else:
                    failures.append(1)

        threads = [threading.Thread(target=worker) for _ in range(20)]
        for t in threads:
            t.start()
        for t in threads:
            t.join(timeout=2.0)

        assert len(successes) == 4
        assert len(failures) == 16

    def test_high_capacity_concurrent_with_api_key(self, api_key_limiter):
        """100 threads racing for 45 slots."""
        results = []
        lock = threading.Lock()

        def worker():
            ok = api_key_limiter.acquire(timeout=0.05, block=False)
            with lock:
                results.append(ok)

        threads = [threading.Thread(target=worker) for _ in range(100)]
        for t in threads:
            t.start()
        for t in threads:
            t.join(timeout=2.0)

        assert sum(results) == 45
        assert sum(1 for r in results if not r) == 55


class TestApiKeyInvalidation:
    def test_invalidate_clears_cache_state(self):
        # Use a real (non-monkey-patched) limiter to test the actual cache
        from datetime import datetime
        limiter = get_rate_limiter()
        # Manually populate cache to simulate a prior fetch
        limiter._api_key_cached = 'previous-key'
        limiter._api_key_check_time = datetime.now()
        limiter.invalidate_api_key_cache()
        assert limiter._api_key_check_time is None
        assert limiter._api_key_cached is None

    def test_existing_window_records_kept_after_invalidation(self, no_api_key_limiter):
        # Critical for stability under key rotation: existing in-window
        # records must NOT be wiped, otherwise we could double-spend the
        # 30s budget by adding another N requests immediately.
        for _ in range(4):
            no_api_key_limiter.acquire(timeout=0.1, block=True)
        no_api_key_limiter.invalidate_api_key_cache()
        # Should still report 0 free slots — history preserved
        assert no_api_key_limiter.get_available_slots() == 0


class TestRateLimitedDecorator:
    def test_decorator_lets_call_through_when_slot_free(self, api_key_limiter):
        @rate_limited(timeout=0.5)
        def call():
            return 'ok'

        assert call() == 'ok'

    def test_decorator_raises_when_exhausted(self, no_api_key_limiter):
        @rate_limited(timeout=0.05)
        def call():
            return 'ok'

        # Burn the budget directly
        for _ in range(4):
            no_api_key_limiter.acquire(timeout=0.1, block=True)

        with pytest.raises(NVDRateLimitError):
            call()


class TestStatsTelemetry:
    def test_stats_after_mixed_load(self, api_key_limiter):
        for _ in range(10):
            api_key_limiter.acquire(timeout=0.1, block=True)
        stats = api_key_limiter.get_stats()
        assert stats['has_api_key'] is True
        assert stats['effective_limit'] == 45
        assert stats['base_limit'] == 50
        assert stats['requests_in_window'] == 10
        assert stats['available_slots'] == 35
        assert stats['total_requests'] == 10
        assert stats['blocked_requests'] == 0

    def test_reset_stats(self, api_key_limiter):
        for _ in range(3):
            api_key_limiter.acquire(timeout=0.1, block=True)
        api_key_limiter.reset_stats()
        stats = api_key_limiter.get_stats()
        assert stats['total_requests'] == 0
        assert stats['blocked_requests'] == 0
        # request_times not cleared by reset_stats — only counters reset
        assert stats['requests_in_window'] == 3
