"""
Performance Profiling Middleware for Flask
Automatically tracks and logs slow API endpoints and database queries
"""

import time
from flask import request, g
from functools import wraps
from app.logging_config import log_performance, log_request


def setup_performance_middleware(app):
    """
    Setup performance monitoring middleware for Flask app

    Tracks:
    - Request duration
    - Slow endpoints (> 1 second)
    - Database query count (if SQLAlchemy is used)
    - All HTTP requests to access.log
    """

    @app.before_request
    def before_request():
        """Start request timer"""
        g.start_time = time.time()
        g.query_count = 0  # Will be incremented by SQLAlchemy events

    @app.after_request
    def after_request(response):
        """
        Log request and check for slow endpoints
        """
        if not hasattr(g, 'start_time'):
            return response

        # Calculate duration
        duration_ms = (time.time() - g.start_time) * 1000

        # Log all requests to access.log
        try:
            log_request(request, response, duration_ms)
        except Exception:
            pass  # Don't fail request if logging fails

        # Log slow requests to performance.log
        if duration_ms > 1000:  # Log requests slower than 1 second
            query_count = getattr(g, 'query_count', None)
            log_performance(
                endpoint=f"{request.method} {request.path}",
                duration_ms=duration_ms,
                query_count=query_count
            )

        # Add performance header for debugging (only in debug mode)
        if app.debug:
            response.headers['X-Response-Time'] = f"{duration_ms:.2f}ms"
            if hasattr(g, 'query_count'):
                response.headers['X-Query-Count'] = str(g.query_count)

        return response

    # Setup SQLAlchemy query counting if available
    try:
        from app import db
        from sqlalchemy import event
        from sqlalchemy.engine import Engine

        @event.listens_for(Engine, "before_cursor_execute")
        def before_cursor_execute(conn, cursor, statement, parameters, context, executemany):
            """Count database queries"""
            if hasattr(g, 'query_count'):
                g.query_count += 1

    except (ImportError, AttributeError):
        # SQLAlchemy not available or not configured
        pass

    app.logger.info("Performance middleware enabled")


def profile_function(threshold_ms=1000):
    """
    Decorator to profile individual functions
    Logs to performance.log if execution exceeds threshold

    Usage:
        @profile_function(threshold_ms=500)
        def slow_operation():
            ...
    """
    def decorator(func):
        @wraps(func)
        def wrapper(*args, **kwargs):
            start_time = time.time()
            result = func(*args, **kwargs)
            duration_ms = (time.time() - start_time) * 1000

            if duration_ms > threshold_ms:
                log_performance(
                    endpoint=f"{func.__module__}.{func.__name__}",
                    duration_ms=duration_ms
                )

            return result
        return wrapper
    return decorator


class PerformanceMonitor:
    """
    Context manager for monitoring code blocks

    Usage:
        with PerformanceMonitor('expensive_operation'):
            # code to monitor
            ...
    """
    def __init__(self, operation_name, threshold_ms=1000):
        self.operation_name = operation_name
        self.threshold_ms = threshold_ms
        self.start_time = None

    def __enter__(self):
        self.start_time = time.time()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        duration_ms = (time.time() - self.start_time) * 1000

        if duration_ms > self.threshold_ms:
            log_performance(
                endpoint=self.operation_name,
                duration_ms=duration_ms
            )


# Utility functions for identifying slow queries

def log_slow_query(query_description, duration_ms, result_count=None):
    """
    Log a slow database query

    Args:
        query_description: Description of the query
        duration_ms: Query execution time in milliseconds
        result_count: Number of results returned (optional)
    """
    if duration_ms > 500:  # Log queries slower than 500ms
        details = f"{query_description}"
        if result_count is not None:
            details += f" (returned {result_count} rows)"

        log_performance(
            endpoint=f"DB Query: {details}",
            duration_ms=duration_ms,
            query_count=1
        )


def track_endpoint_stats():
    """
    Track detailed endpoint statistics
    Call this in your route handlers for detailed tracking

    Usage:
        @app.route('/api/data')
        def get_data():
            stats = track_endpoint_stats()
            # ... your code ...
            stats.record_query_count(5)
            return jsonify(data)
    """
    class EndpointStats:
        def __init__(self):
            self.start_time = time.time()
            self.query_count = 0
            self.cache_hit = False

        def record_query_count(self, count):
            self.query_count = count

        def mark_cache_hit(self):
            self.cache_hit = True

        def finish(self, endpoint_name=None):
            duration_ms = (time.time() - self.start_time) * 1000
            if duration_ms > 1000:
                log_performance(
                    endpoint=endpoint_name or request.endpoint,
                    duration_ms=duration_ms,
                    query_count=self.query_count if self.query_count > 0 else None,
                    cache_hit=self.cache_hit
                )

    return EndpointStats()
