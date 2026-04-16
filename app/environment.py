"""Canonical runtime environment helpers (M-5).

SentriKat historically read environment from ``FLASK_ENV``, ``ENV`` and
``SENTRIKAT_ENV`` in different call sites — a misconfigured deployment
could therefore be treated as ``production`` by some components and
``development`` by others. These helpers give the whole codebase a single
source of truth.

Precedence (first wins): ``SENTRIKAT_ENV`` > ``FLASK_ENV`` > ``ENV``.
Default: ``production`` (fail-safe; debug features opt-in only).
"""
from __future__ import annotations

import os

_PROD_VALUES = {'production', 'prod', 'live'}
_DEV_VALUES = {'development', 'dev', 'local'}
_TEST_VALUES = {'testing', 'test', 'ci'}


def _raw_env() -> str:
    for var in ('SENTRIKAT_ENV', 'FLASK_ENV', 'ENV'):
        val = os.environ.get(var, '').strip().lower()
        if val:
            return val
    return 'production'


def current_env() -> str:
    """Return the normalized environment name."""
    val = _raw_env()
    if val in _PROD_VALUES:
        return 'production'
    if val in _DEV_VALUES:
        return 'development'
    if val in _TEST_VALUES:
        return 'testing'
    return val


def is_production() -> bool:
    return current_env() == 'production'


def is_development() -> bool:
    return current_env() == 'development'


def is_testing() -> bool:
    return current_env() == 'testing'


def is_debug() -> bool:
    """True when the process should expose debugging info (stack traces etc.).

    Separate from :func:`is_development` because a production deployment
    might set ``FLASK_DEBUG=1`` during incident response without flipping
    the environment name.
    """
    if os.environ.get('FLASK_DEBUG', '').strip().lower() in ('1', 'true', 'yes'):
        return True
    return is_development()


__all__ = [
    'current_env',
    'is_production',
    'is_development',
    'is_testing',
    'is_debug',
]
