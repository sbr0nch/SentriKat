"""
Logging Configuration with Rotation
Provides comprehensive logging for SentriKat with automatic file rotation
"""

import logging
import logging.handlers
import os
from datetime import datetime

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
    # Console Handler (for development)
    # ========================================
    if app.debug:
        console_handler = logging.StreamHandler()
        console_handler.setLevel(logging.DEBUG)
        console_handler.setFormatter(detailed_formatter)
        root_logger.addHandler(console_handler)

    # Log startup
    app.logger.info(f"Logging configured. Log directory: {log_dir}")
    app.logger.info(f"Log files: application.log, error.log, access.log, ldap.log, security.log")

    return log_dir


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

    from flask import session
    user_id = session.get('user_id', 'system')

    status = 'SUCCESS' if success else 'FAILED'
    message = f"[{operation}] {status} user:{user_id} - {details}"

    if success:
        ldap_logger.info(message)
    else:
        ldap_logger.error(message)
