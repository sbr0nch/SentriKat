"""
NVD API Rate Limiter - Intelligent request management to respect NVD ToS.

NVD Rate Limits:
- Without API key: 5 requests per 30 seconds
- With API key: 50 requests per 30 seconds

This module provides a centralized, thread-safe rate limiter that:
1. Uses sliding window algorithm for accurate rate tracking
2. Maintains a safety buffer to prevent accidental limit breaches
3. Provides request queuing with backpressure
4. Logs rate limit status for monitoring
5. Handles API key changes dynamically
"""
import time
import logging
from threading import Lock, RLock
from typing import Optional, Dict, Any, Callable
from datetime import datetime, timedelta
from collections import deque
from functools import wraps

logger = logging.getLogger(__name__)


class NVDRateLimiter:
    """
    Thread-safe sliding window rate limiter for NVD API requests.

    Uses a token bucket-like approach with sliding window for accurate
    rate limiting that respects NVD's 30-second rolling window.
    """

    # Rate limits per 30-second window
    LIMIT_WITHOUT_KEY = 5
    LIMIT_WITH_KEY = 50
    WINDOW_SECONDS = 30

    # Safety buffer - use 90% of actual limit to prevent edge cases
    SAFETY_FACTOR = 0.9

    # Singleton instance
    _instance = None
    _instance_lock = Lock()

    def __new__(cls):
        """Singleton pattern to ensure one rate limiter across all modules."""
        with cls._instance_lock:
            if cls._instance is None:
                cls._instance = super().__new__(cls)
                cls._instance._initialized = False
            return cls._instance

    def __init__(self):
        """Initialize the rate limiter (only once due to singleton)."""
        if self._initialized:
            return

        self._lock = RLock()
        self._request_times: deque = deque()
        self._api_key_cached: Optional[str] = None
        self._api_key_check_time: Optional[datetime] = None
        self._total_requests = 0
        self._blocked_requests = 0
        self._last_limit_warning: Optional[datetime] = None
        self._initialized = True

        logger.info("NVD Rate Limiter initialized")

    def _get_api_key(self) -> Optional[str]:
        """
        Get NVD API key with caching (check every 60 seconds).
        This avoids database hits on every request.
        """
        now = datetime.now()

        # Cache API key check for 60 seconds
        if (self._api_key_check_time is None or
            now - self._api_key_check_time > timedelta(seconds=60)):

            try:
                import os
                from app.models import SystemSettings
                from app.encryption import decrypt_value

                setting = SystemSettings.query.filter_by(key='nvd_api_key').first()
                if setting and setting.value:
                    if setting.is_encrypted:
                        try:
                            self._api_key_cached = decrypt_value(setting.value)
                        except Exception:
                            self._api_key_cached = setting.value
                    else:
                        self._api_key_cached = setting.value
                else:
                    self._api_key_cached = os.environ.get('NVD_API_KEY')
            except Exception as e:
                logger.debug(f"Could not check API key from DB: {e}")
                import os
                self._api_key_cached = os.environ.get('NVD_API_KEY')

            self._api_key_check_time = now

        return self._api_key_cached

    def _get_effective_limit(self) -> int:
        """Get the effective rate limit based on API key availability."""
        api_key = self._get_api_key()
        base_limit = self.LIMIT_WITH_KEY if api_key else self.LIMIT_WITHOUT_KEY
        return int(base_limit * self.SAFETY_FACTOR)

    def _clean_old_requests(self):
        """Remove requests older than the window from the tracking deque."""
        cutoff = time.time() - self.WINDOW_SECONDS
        while self._request_times and self._request_times[0] < cutoff:
            self._request_times.popleft()

    def get_available_slots(self) -> int:
        """Get number of requests that can be made immediately."""
        with self._lock:
            self._clean_old_requests()
            limit = self._get_effective_limit()
            return max(0, limit - len(self._request_times))

    def get_wait_time(self) -> float:
        """
        Get time to wait before next request can be made.
        Returns 0 if a request can be made immediately.
        """
        with self._lock:
            self._clean_old_requests()
            limit = self._get_effective_limit()

            if len(self._request_times) < limit:
                return 0.0

            # Need to wait for oldest request to expire
            oldest = self._request_times[0]
            wait_time = (oldest + self.WINDOW_SECONDS) - time.time()
            return max(0.0, wait_time)

    def acquire(self, timeout: float = 60.0, block: bool = True) -> bool:
        """
        Acquire permission to make an NVD API request.

        Args:
            timeout: Maximum time to wait for a slot (seconds)
            block: If False, return immediately if no slot available

        Returns:
            True if request can proceed, False if timed out or non-blocking fail
        """
        start_time = time.time()

        while True:
            with self._lock:
                self._clean_old_requests()
                limit = self._get_effective_limit()

                if len(self._request_times) < limit:
                    # Slot available - record request and allow
                    self._request_times.append(time.time())
                    self._total_requests += 1
                    return True

                if not block:
                    self._blocked_requests += 1
                    return False

                # Calculate wait time
                oldest = self._request_times[0]
                wait_needed = (oldest + self.WINDOW_SECONDS) - time.time()

                # Check timeout
                elapsed = time.time() - start_time
                if elapsed + wait_needed > timeout:
                    self._blocked_requests += 1
                    self._log_limit_warning()
                    return False

            # Wait outside the lock
            sleep_time = min(wait_needed + 0.1, timeout - elapsed)
            if sleep_time > 0:
                time.sleep(sleep_time)

    def _log_limit_warning(self):
        """Log rate limit warning (max once per minute)."""
        now = datetime.now()
        if (self._last_limit_warning is None or
            now - self._last_limit_warning > timedelta(minutes=1)):
            api_key = self._get_api_key()
            limit_type = "with API key" if api_key else "without API key"
            logger.warning(
                f"NVD API rate limit reached ({limit_type}). "
                f"Total: {self._total_requests}, Blocked: {self._blocked_requests}"
            )
            self._last_limit_warning = now

    def get_stats(self) -> Dict[str, Any]:
        """Get rate limiter statistics."""
        with self._lock:
            self._clean_old_requests()
            api_key = self._get_api_key()
            limit = self._get_effective_limit()

            return {
                'has_api_key': bool(api_key),
                'effective_limit': limit,
                'base_limit': self.LIMIT_WITH_KEY if api_key else self.LIMIT_WITHOUT_KEY,
                'window_seconds': self.WINDOW_SECONDS,
                'requests_in_window': len(self._request_times),
                'available_slots': max(0, limit - len(self._request_times)),
                'total_requests': self._total_requests,
                'blocked_requests': self._blocked_requests,
                'wait_time': self.get_wait_time()
            }

    def reset_stats(self):
        """Reset statistics counters."""
        with self._lock:
            self._total_requests = 0
            self._blocked_requests = 0

    def invalidate_api_key_cache(self):
        """Force re-check of API key on next request."""
        with self._lock:
            self._api_key_check_time = None
            self._api_key_cached = None


# Global singleton instance
_rate_limiter = None


def get_rate_limiter() -> NVDRateLimiter:
    """Get the global NVD rate limiter instance."""
    global _rate_limiter
    if _rate_limiter is None:
        _rate_limiter = NVDRateLimiter()
    return _rate_limiter


def _reset_limiter():
    """Reset rate limiter for testing. Not for production use."""
    global _rate_limiter
    NVDRateLimiter._instance = None
    _rate_limiter = None


def update_api_key_status(has_key: bool):
    """Force update of API key status. Used when key is added/removed."""
    limiter = get_rate_limiter()
    limiter.invalidate_api_key_cache()


def rate_limited(timeout: float = 60.0):
    """
    Decorator to apply NVD rate limiting to a function.

    Usage:
        @rate_limited(timeout=30.0)
        def fetch_from_nvd(cve_id):
            ...
    """
    def decorator(func: Callable) -> Callable:
        @wraps(func)
        def wrapper(*args, **kwargs):
            limiter = get_rate_limiter()
            if not limiter.acquire(timeout=timeout, block=True):
                raise NVDRateLimitError(
                    f"NVD API rate limit exceeded. "
                    f"Stats: {limiter.get_stats()}"
                )
            return func(*args, **kwargs)
        return wrapper
    return decorator


def wait_for_slot(timeout: float = 60.0) -> bool:
    """
    Wait for an available NVD API request slot.

    Args:
        timeout: Maximum time to wait

    Returns:
        True if slot acquired, False if timed out
    """
    return get_rate_limiter().acquire(timeout=timeout, block=True)


def can_make_request() -> bool:
    """Check if an NVD API request can be made immediately."""
    return get_rate_limiter().get_available_slots() > 0


def get_nvd_stats() -> Dict[str, Any]:
    """Get NVD rate limiter statistics."""
    return get_rate_limiter().get_stats()


class NVDRateLimitError(Exception):
    """Raised when NVD API rate limit is exceeded."""
    pass
