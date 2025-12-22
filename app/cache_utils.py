"""
Simple In-Memory Cache with TTL
Provides basic caching for frequently accessed data to reduce database queries

Note: This is an in-memory cache. For production with multiple workers,
consider using Redis instead.
"""

import time
from functools import wraps
from threading import Lock

class SimpleCache:
    """
    Thread-safe in-memory cache with TTL (Time To Live)
    """
    def __init__(self):
        self._cache = {}
        self._lock = Lock()

    def get(self, key):
        """
        Get value from cache

        Returns:
            Value if exists and not expired, None otherwise
        """
        with self._lock:
            if key not in self._cache:
                return None

            value, expiry = self._cache[key]

            # Check if expired
            if expiry and time.time() > expiry:
                del self._cache[key]
                return None

            return value

    def set(self, key, value, ttl=300):
        """
        Set value in cache with TTL

        Args:
            key: Cache key
            value: Value to cache
            ttl: Time to live in seconds (default: 5 minutes)
        """
        with self._lock:
            expiry = time.time() + ttl if ttl else None
            self._cache[key] = (value, expiry)

    def delete(self, key):
        """Delete key from cache"""
        with self._lock:
            if key in self._cache:
                del self._cache[key]

    def clear(self):
        """Clear all cache"""
        with self._lock:
            self._cache.clear()

    def get_stats(self):
        """Get cache statistics"""
        with self._lock:
            active_keys = 0
            expired_keys = 0
            now = time.time()

            for key, (value, expiry) in self._cache.items():
                if expiry and now > expiry:
                    expired_keys += 1
                else:
                    active_keys += 1

            return {
                'total_keys': len(self._cache),
                'active_keys': active_keys,
                'expired_keys': expired_keys
            }


# Global cache instance
_cache = SimpleCache()


def get_cache():
    """Get global cache instance"""
    return _cache


def cached(ttl=300, key_prefix=''):
    """
    Decorator to cache function results

    Args:
        ttl: Time to live in seconds (default: 5 minutes)
        key_prefix: Prefix for cache key

    Usage:
        @cached(ttl=600, key_prefix='stats')
        def get_stats():
            return expensive_operation()
    """
    def decorator(func):
        @wraps(func)
        def wrapper(*args, **kwargs):
            # Build cache key
            key_parts = [key_prefix or func.__name__]

            # Add args to key
            if args:
                key_parts.extend(str(arg) for arg in args)

            # Add kwargs to key (sorted for consistency)
            if kwargs:
                key_parts.extend(f"{k}={v}" for k, v in sorted(kwargs.items()))

            cache_key = ':'.join(key_parts)

            # Try to get from cache
            cached_value = _cache.get(cache_key)
            if cached_value is not None:
                return cached_value

            # Execute function
            result = func(*args, **kwargs)

            # Store in cache
            _cache.set(cache_key, result, ttl)

            return result

        # Add cache management methods to function
        wrapper.clear_cache = lambda: _cache.delete(key_prefix or func.__name__)
        wrapper.cache_key = key_prefix or func.__name__

        return wrapper
    return decorator


def cached_query(ttl=300):
    """
    Decorator specifically for SQLAlchemy query results

    Usage:
        @cached_query(ttl=600)
        def get_active_products(org_id):
            return Product.query.filter_by(
                organization_id=org_id,
                active=True
            ).all()
    """
    return cached(ttl=ttl, key_prefix='query')


def invalidate_cache_pattern(pattern):
    """
    Invalidate all cache keys matching pattern

    Args:
        pattern: String pattern to match (simple contains check)
    """
    cache = get_cache()
    with cache._lock:
        keys_to_delete = [k for k in cache._cache.keys() if pattern in k]
        for key in keys_to_delete:
            del cache._cache[key]


# Example usage functions
def cache_organizations(org_id=None):
    """Cache key for organization data"""
    return f"org:{org_id}" if org_id else "org:all"


def cache_products(org_id=None):
    """Cache key for product data"""
    return f"products:{org_id}" if org_id else "products:all"


def cache_vulnerability_stats():
    """Cache key for vulnerability statistics"""
    return "vuln_stats"
