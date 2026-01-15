"""
Logging Configuration with Rotation
Provides comprehensive logging for SentriKat with automatic file rotation

Log Types:
- application.log: General application logs (INFO+)
- error.log: Error and critical logs (ERROR+)
- access.log: HTTP request logs
- ldap.log: LDAP operation logs
- security.log: Authentication and authorization events
- audit.log: Data modification audit trail (NEW)
- performance.log: Slow query and endpoint profiling (NEW)
"""

import logging
import logging.handlers
import os
import json
from datetime import datetime
from functools import wraps
import time

def setup_logging(app):
    """
    Configure comprehensive logging with rotation

    Creates logs in /var/log/sentrikat/ with automatic rotation
    """
    # Create log directory if it doesn't exist
    log_dir = os.environ.get('LOG_DIR', '/var/log/sentrikat')
    if not os.path.exists(log_dir):
        try:
            os.makedirs(log_dir, exist_ok=True)
        except PermissionError:
            # Fall back to local logs directory if can't write to /var/log
            log_dir = os.path.join(os.path.dirname(os.path.dirname(__file__)), 'logs')
            os.makedirs(log_dir, exist_ok=True)

    # Configure root logger
    root_logger = logging.getLogger()
    root_logger.setLevel(logging.INFO)

    # Clear any existing handlers
    root_logger.handlers = []

    # Create formatters
    detailed_formatter = logging.Formatter(
        '[%(asctime)s] %(levelname)s in %(module)s (%(funcName)s:%(lineno)d): %(message)s',
        datefmt='%Y-%m-%d %H:%M:%S'
    )

    simple_formatter = logging.Formatter(
        '[%(asctime)s] %(levelname)s: %(message)s',
        datefmt='%Y-%m-%d %H:%M:%S'
    )

    # ========================================
    # Application Log (INFO and above)
    # ========================================
    app_log_file = os.path.join(log_dir, 'application.log')
    app_handler = logging.handlers.RotatingFileHandler(
        app_log_file,
        maxBytes=10 * 1024 * 1024,  # 10MB
        backupCount=10,
        encoding='utf-8'
    )
    app_handler.setLevel(logging.INFO)
    app_handler.setFormatter(detailed_formatter)
    root_logger.addHandler(app_handler)

    # ========================================
    # Error Log (ERROR and above only)
    # ========================================
    error_log_file = os.path.join(log_dir, 'error.log')
    error_handler = logging.handlers.RotatingFileHandler(
        error_log_file,
        maxBytes=10 * 1024 * 1024,  # 10MB
        backupCount=10,
        encoding='utf-8'
    )
    error_handler.setLevel(logging.ERROR)
    error_handler.setFormatter(detailed_formatter)
    root_logger.addHandler(error_handler)

    # ========================================
    # Access Log (HTTP requests)
    # ========================================
    access_log_file = os.path.join(log_dir, 'access.log')
    access_handler = logging.handlers.RotatingFileHandler(
        access_log_file,
        maxBytes=20 * 1024 * 1024,  # 20MB
        backupCount=10,
        encoding='utf-8'
    )
    access_handler.setLevel(logging.INFO)
    access_handler.setFormatter(simple_formatter)

    # Create separate logger for access logs
    access_logger = logging.getLogger('access')
    access_logger.addHandler(access_handler)
    access_logger.propagate = False

    # ========================================
    # LDAP Operations Log
    # ========================================
    ldap_log_file = os.path.join(log_dir, 'ldap.log')
    ldap_handler = logging.handlers.RotatingFileHandler(
        ldap_log_file,
        maxBytes=10 * 1024 * 1024,  # 10MB
        backupCount=10,
        encoding='utf-8'
    )
    ldap_handler.setLevel(logging.INFO)
    ldap_handler.setFormatter(detailed_formatter)

    # Create separate logger for LDAP
    ldap_logger = logging.getLogger('ldap')
    ldap_logger.addHandler(ldap_handler)
    ldap_logger.propagate = False

    # ========================================
    # Security Log (auth, permission errors)
    # ========================================
    security_log_file = os.path.join(log_dir, 'security.log')
    security_handler = logging.handlers.RotatingFileHandler(
        security_log_file,
        maxBytes=10 * 1024 * 1024,  # 10MB
        backupCount=20,  # Keep more security logs
        encoding='utf-8'
    )
    security_handler.setLevel(logging.WARNING)
    security_handler.setFormatter(detailed_formatter)

    # Create separate logger for security
    security_logger = logging.getLogger('security')
    security_logger.addHandler(security_handler)
    security_logger.propagate = False

    # ========================================
    # Audit Log (data modifications)
    # ========================================
    audit_log_file = os.path.join(log_dir, 'audit.log')
    audit_handler = logging.handlers.RotatingFileHandler(
        audit_log_file,
        maxBytes=20 * 1024 * 1024,  # 20MB
        backupCount=50,  # Keep extensive audit history
        encoding='utf-8'
    )
    audit_handler.setLevel(logging.INFO)

    # Use JSON formatter for audit logs (easier to parse)
    audit_formatter = JsonFormatter()
    audit_handler.setFormatter(audit_formatter)

    # Create separate logger for audit
    audit_logger = logging.getLogger('audit')
    audit_logger.addHandler(audit_handler)
    audit_logger.propagate = False

    # ========================================
    # Performance Log (slow queries/endpoints)
    # ========================================
    perf_log_file = os.path.join(log_dir, 'performance.log')
    perf_handler = logging.handlers.RotatingFileHandler(
        perf_log_file,
        maxBytes=20 * 1024 * 1024,  # 20MB
        backupCount=10,
        encoding='utf-8'
    )
    perf_handler.setLevel(logging.INFO)
    perf_handler.setFormatter(JsonFormatter())

    # Create separate logger for performance
    perf_logger = logging.getLogger('performance')
    perf_logger.addHandler(perf_handler)
    perf_logger.propagate = False

    # ========================================
    # Console Handler (for Docker logging)
    # ========================================
    # Always output to stdout/stderr so docker-compose logs can capture
    import sys
    console_handler = logging.StreamHandler(sys.stdout)
    console_handler.setLevel(logging.DEBUG if app.debug else logging.INFO)
    console_handler.setFormatter(detailed_formatter)
    root_logger.addHandler(console_handler)

    # Log startup
    app.logger.info(f"Logging configured. Log directory: {log_dir}")
    app.logger.info(f"Log files: application.log, error.log, access.log, ldap.log, security.log, audit.log, performance.log")

    return log_dir


class JsonFormatter(logging.Formatter):
    """
    JSON formatter for structured logging
    Makes logs easy to parse and analyze
    """
    def format(self, record):
        log_data = {
            'timestamp': datetime.utcnow().isoformat() + 'Z',
            'level': record.levelname,
            'logger': record.name,
            'message': record.getMessage(),
        }

        # Add exception info if present
        if record.exc_info:
            log_data['exception'] = self.formatException(record.exc_info)

        # Add custom fields from record
        if hasattr(record, 'user_id'):
            log_data['user_id'] = record.user_id
        if hasattr(record, 'ip_address'):
            log_data['ip_address'] = record.ip_address
        if hasattr(record, 'action'):
            log_data['action'] = record.action
        if hasattr(record, 'resource'):
            log_data['resource'] = record.resource
        if hasattr(record, 'duration_ms'):
            log_data['duration_ms'] = record.duration_ms
        if hasattr(record, 'endpoint'):
            log_data['endpoint'] = record.endpoint
        if hasattr(record, 'old_value'):
            log_data['old_value'] = record.old_value
        if hasattr(record, 'new_value'):
            log_data['new_value'] = record.new_value

        return json.dumps(log_data, default=str)


def log_audit_event(action, resource, resource_id=None, old_value=None, new_value=None, details=None):
    """
    Log audit trail for data modifications

    Args:
        action: CREATE, UPDATE, DELETE, INVITE, SYNC, etc.
        resource: users, products, organizations, ldap_groups, etc.
        resource_id: ID of the affected resource
        old_value: Previous value (for updates)
        new_value: New value (for creates/updates)
        details: Additional context

    Example:
        log_audit_event('UPDATE', 'users', 123,
                       old_value={'role': 'user'},
                       new_value={'role': 'admin'})
    """
    from flask import request, session, has_request_context

    audit_logger = logging.getLogger('audit')

    # Create log record with custom attributes
    extra = {
        'action': action,
        'resource': resource,
    }

    if has_request_context():
        extra['user_id'] = session.get('user_id', 'system')
        extra['ip_address'] = request.remote_addr
    else:
        extra['user_id'] = 'system'
        extra['ip_address'] = 'localhost'

    if resource_id is not None:
        extra['resource'] = f"{resource}:{resource_id}"

    if old_value is not None:
        extra['old_value'] = old_value

    if new_value is not None:
        extra['new_value'] = new_value

    message = f"{action} {resource}"
    if resource_id:
        message += f":{resource_id}"
    if details:
        message += f" - {details}"

    audit_logger.info(message, extra=extra)


def log_request(request, response, duration_ms):
    """Log HTTP request with details"""
    access_logger = logging.getLogger('access')

    # Get user info if available
    from flask import session
    user_id = session.get('user_id', 'anonymous')

    # Log format: [timestamp] method path status duration user_id ip
    access_logger.info(
        f"{request.method} {request.path} {response.status_code} "
        f"{duration_ms:.2f}ms user:{user_id} ip:{request.remote_addr}"
    )


def log_security_event(event_type, details, level='WARNING'):
    """Log security-related events"""
    security_logger = logging.getLogger('security')

    from flask import request, session
    user_id = session.get('user_id', 'anonymous')
    ip = request.remote_addr if request else 'unknown'

    message = f"[{event_type}] user:{user_id} ip:{ip} - {details}"

    if level == 'ERROR':
        security_logger.error(message)
    elif level == 'CRITICAL':
        security_logger.critical(message)
    else:
        security_logger.warning(message)


def log_ldap_operation(operation, details, success=True):
    """Log LDAP operations"""
    ldap_logger = logging.getLogger('ldap')

    from flask import session, has_request_context
    user_id = session.get('user_id', 'system') if has_request_context() else 'system'

    status = 'SUCCESS' if success else 'FAILED'
    message = f"[{operation}] {status} user:{user_id} - {details}"

    if success:
        ldap_logger.info(message)
    else:
        ldap_logger.error(message)


def log_performance(endpoint, duration_ms, query_count=None, cache_hit=False):
    """
    Log performance metrics for endpoints and queries

    Args:
        endpoint: API endpoint or function name
        duration_ms: Execution time in milliseconds
        query_count: Number of database queries executed
        cache_hit: Whether result was from cache
    """
    from flask import request, has_request_context

    perf_logger = logging.getLogger('performance')

    extra = {
        'endpoint': endpoint,
        'duration_ms': round(duration_ms, 2),
    }

    if has_request_context():
        extra['method'] = request.method
        extra['ip_address'] = request.remote_addr

    if query_count is not None:
        extra['query_count'] = query_count

    if cache_hit:
        extra['cache_hit'] = True

    # Only log if slow (> 1 second) or warn if very slow (> 5 seconds)
    if duration_ms > 5000:
        perf_logger.warning(f"VERY SLOW: {endpoint} took {duration_ms:.2f}ms", extra=extra)
    elif duration_ms > 1000:
        perf_logger.info(f"SLOW: {endpoint} took {duration_ms:.2f}ms", extra=extra)


def track_performance(threshold_ms=1000):
    """
    Decorator to track function performance
    Logs to performance.log if execution exceeds threshold

    Usage:
        @track_performance(threshold_ms=500)
        def slow_function():
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
