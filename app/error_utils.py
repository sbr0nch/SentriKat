"""
Utility functions for secure error handling.
Prevents information disclosure by not exposing internal error details to users.
"""
import logging
from flask import jsonify, current_app

logger = logging.getLogger(__name__)


def safe_error_response(e, generic_msg="An error occurred", status_code=500, log_level='error'):
    """
    Create a safe error response that logs the real error but returns a generic message.

    Args:
        e: The exception object
        generic_msg: The message to show to users (no internal details)
        status_code: HTTP status code to return
        log_level: Logging level ('error', 'warning', 'info')

    Returns:
        Flask response tuple (jsonify response, status_code)
    """
    # Log the actual error for debugging (server-side only)
    if log_level == 'error':
        logger.exception(f"Internal error: {generic_msg}")
    elif log_level == 'warning':
        logger.warning(f"{generic_msg}: {str(e)}")
    else:
        logger.info(f"{generic_msg}: {str(e)}")

    # Return generic message to user
    return jsonify({'error': generic_msg}), status_code


def safe_json_error(generic_msg="An error occurred"):
    """
    Create a simple error dict for internal use (not API responses).
    Still generic to avoid information disclosure if serialized.
    """
    return {'error': generic_msg}


# Common generic error messages
ERROR_MSGS = {
    'database': 'A database error occurred',
    'validation': 'Invalid input provided',
    'auth': 'Authentication failed',
    'permission': 'Permission denied',
    'not_found': 'Resource not found',
    'config': 'Configuration error',
    'external': 'External service error',
    'upload': 'Upload failed',
    'backup': 'Backup operation failed',
    'restore': 'Restore operation failed',
    'ldap': 'LDAP operation failed',
    'smtp': 'Email operation failed',
    'sync': 'Synchronization failed',
    'network': 'Network error occurred',
    'timeout': 'Operation timed out',
    'internal': 'An internal error occurred',
}
