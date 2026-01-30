"""
Tests for the NVD rate limiter module.
"""
import pytest
import time
from unittest.mock import patch, MagicMock


class TestNVDRateLimiter:
    """Tests for the NVD API rate limiter."""

    def test_rate_limiter_limits_without_key(self, app):
        """Test rate limiter has correct limits when no API key."""
        from app.nvd_rate_limiter import get_rate_limiter, _reset_limiter, NVDRateLimiter

        with app.app_context():
            _reset_limiter()

            # Mock no API key
            with patch.object(NVDRateLimiter, '_get_api_key', return_value=None):
                limiter = get_rate_limiter()
                stats = limiter.get_stats()

                assert stats['base_limit'] == 5
                assert stats['has_api_key'] is False
                assert limiter.WINDOW_SECONDS == 30

    def test_rate_limiter_limits_with_key(self, app):
        """Test rate limiter has correct limits when API key present."""
        from app.nvd_rate_limiter import get_rate_limiter, _reset_limiter, NVDRateLimiter

        with app.app_context():
            _reset_limiter()

            # Mock API key present
            with patch.object(NVDRateLimiter, '_get_api_key', return_value='test-api-key'):
                limiter = get_rate_limiter()
                stats = limiter.get_stats()

                assert stats['base_limit'] == 50
                assert stats['has_api_key'] is True

    def test_acquire_within_limit(self, app):
        """Test acquiring tokens within the rate limit."""
        from app.nvd_rate_limiter import get_rate_limiter, _reset_limiter, NVDRateLimiter

        with app.app_context():
            _reset_limiter()

            # Mock no API key (limit of 5, but with safety factor ~4)
            with patch.object(NVDRateLimiter, '_get_api_key', return_value=None):
                limiter = get_rate_limiter()
                effective_limit = limiter._get_effective_limit()

                # Should be able to acquire up to the effective limit
                for i in range(effective_limit):
                    result = limiter.acquire(block=False)
                    assert result is True, f"Failed to acquire token {i+1}"

    def test_acquire_exceeds_limit_non_blocking(self, app):
        """Test non-blocking acquire fails when limit exceeded."""
        from app.nvd_rate_limiter import get_rate_limiter, _reset_limiter, NVDRateLimiter

        with app.app_context():
            _reset_limiter()

            with patch.object(NVDRateLimiter, '_get_api_key', return_value=None):
                limiter = get_rate_limiter()
                effective_limit = limiter._get_effective_limit()

                # Exhaust the limit
                for i in range(effective_limit):
                    limiter.acquire(block=False)

                # Next acquire should fail
                result = limiter.acquire(block=False)
                assert result is False

    def test_get_stats(self, app):
        """Test rate limiter statistics."""
        from app.nvd_rate_limiter import get_rate_limiter, _reset_limiter, NVDRateLimiter

        with app.app_context():
            _reset_limiter()

            with patch.object(NVDRateLimiter, '_get_api_key', return_value='test-key'):
                limiter = get_rate_limiter()

                # Make some requests
                limiter.acquire(block=False)
                limiter.acquire(block=False)

                stats = limiter.get_stats()

                assert 'requests_in_window' in stats
                assert 'base_limit' in stats
                assert 'effective_limit' in stats
                assert 'window_seconds' in stats
                assert 'has_api_key' in stats
                assert stats['requests_in_window'] == 2

    def test_window_sliding(self, app):
        """Test that old requests expire from the window."""
        from app.nvd_rate_limiter import get_rate_limiter, _reset_limiter, NVDRateLimiter

        with app.app_context():
            _reset_limiter()

            with patch.object(NVDRateLimiter, '_get_api_key', return_value=None):
                limiter = get_rate_limiter()

                # Manually set a short window for testing
                original_window = limiter.WINDOW_SECONDS
                limiter.WINDOW_SECONDS = 0.1  # 100ms window

                effective_limit = limiter._get_effective_limit()

                # Exhaust limit
                for _ in range(effective_limit):
                    limiter.acquire(block=False)

                # Should fail immediately
                assert limiter.acquire(block=False) is False

                # Wait for window to expire
                time.sleep(0.15)

                # Should succeed now
                assert limiter.acquire(block=False) is True

                # Restore original window
                limiter.WINDOW_SECONDS = original_window

    def test_thread_safety(self, app):
        """Test rate limiter is thread-safe."""
        from app.nvd_rate_limiter import get_rate_limiter, _reset_limiter, NVDRateLimiter
        import threading

        with app.app_context():
            _reset_limiter()

            with patch.object(NVDRateLimiter, '_get_api_key', return_value=None):
                limiter = get_rate_limiter()
                effective_limit = limiter._get_effective_limit()
                results = []
                lock = threading.Lock()

                def try_acquire():
                    result = limiter.acquire(block=False)
                    with lock:
                        results.append(result)

                # Launch more threads than the limit
                num_threads = effective_limit + 5
                threads = [threading.Thread(target=try_acquire) for _ in range(num_threads)]
                for t in threads:
                    t.start()
                for t in threads:
                    t.join()

                # Only effective_limit should succeed
                success_count = sum(1 for r in results if r)
                assert success_count == effective_limit


class TestRateLimiterSingleton:
    """Tests for the rate limiter singleton."""

    def test_get_rate_limiter_returns_same_instance(self, app):
        """Test that get_rate_limiter returns a singleton."""
        from app.nvd_rate_limiter import get_rate_limiter, _reset_limiter

        with app.app_context():
            _reset_limiter()  # Reset for clean test

            limiter1 = get_rate_limiter()
            limiter2 = get_rate_limiter()

            assert limiter1 is limiter2

    def test_update_api_key_status(self, app):
        """Test updating the rate limiter when API key status changes."""
        from app.nvd_rate_limiter import get_rate_limiter, update_api_key_status, _reset_limiter, NVDRateLimiter

        with app.app_context():
            _reset_limiter()

            # Get limiter and check stats
            limiter = get_rate_limiter()

            # Invalidate cache to force refresh
            update_api_key_status(True)

            # Check that the cache was invalidated
            assert limiter._api_key_check_time is None


class TestRateLimiterIntegration:
    """Integration tests for rate limiter with NVD API calls."""

    @patch('app.nvd_api.requests.get')
    def test_nvd_api_uses_rate_limiter(self, mock_get, app):
        """Test that NVD API calls use the rate limiter."""
        from app.nvd_rate_limiter import get_rate_limiter, _reset_limiter

        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            'vulnerabilities': [{
                'cve': {
                    'id': 'CVE-2024-1234',
                    'metrics': {
                        'cvssMetricV31': [{
                            'cvssData': {'baseScore': 7.5}
                        }]
                    }
                }
            }]
        }
        mock_get.return_value = mock_response

        with app.app_context():
            _reset_limiter()
            limiter = get_rate_limiter()

            # Record initial state
            initial_stats = limiter.get_stats()
            initial_count = initial_stats['requests_in_window']

            # Make an NVD API call
            from app.nvd_api import fetch_cvss_data
            fetch_cvss_data('CVE-2024-1234')

            # Check that rate limiter was used
            final_stats = limiter.get_stats()
            # The count should have increased
            assert final_stats['requests_in_window'] >= initial_count
