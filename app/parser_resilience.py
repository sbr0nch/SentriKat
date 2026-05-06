"""Defensive upstream-parser primitives — R-PARSER-RESILIENCE.

Implements the requirement defined in
``docs/architecture/VULN-FEED-BROKER-DESIGN.md`` (section
"R-PARSER-RESILIENCE — Non-functional requirement"):

- Required vs optional field declaration
- Field-alias lookup chain (renamed/re-nested upstream keys still resolve)
- Type coercion at parse boundary (str/int/float for severity & score)
- Schema-drift telemetry (non-blocking shape-hash diffing)
- ``SchemaIncompatibleError`` for unrecoverable required-field loss

Used by ``cisa_sync.parse_and_store_vulnerabilities`` and
``nvd_api._fetch_cvss_from_nvd``. Pattern is also expected to be ported
into the future ``vuln_feed_broker`` server-side enrichment layer.
"""

from __future__ import annotations

import hashlib
import json
import logging
from typing import Any, Iterable, Mapping, Optional, Sequence

logger = logging.getLogger(__name__)


class SchemaIncompatibleError(Exception):
    """Raised when a REQUIRED field cannot be resolved by any alias.

    Distinguishes "upstream broke our contract" from generic transient
    failures. Callers should treat it as fatal for the current record
    (skip, alert ops) but NOT abort the rest of the batch.
    """


def get_aliased(
    payload: Mapping[str, Any],
    aliases: Sequence[str],
    default: Any = None,
) -> Any:
    """Look up the first alias that resolves to a non-None value.

    Aliases support dotted paths for nested dicts (``a.b.c``) and integer
    indices for arrays (``a.0.b``). First hit wins. Returns ``default``
    if none of the aliases resolve.

    Example:
        >>> get_aliased({'cve': {'id': 'CVE-2024-1'}}, ['cveId', 'cve.id'])
        'CVE-2024-1'
    """
    for path in aliases:
        value = _resolve_path(payload, path)
        if value is not None:
            return value
    return default


def _resolve_path(payload: Any, path: str) -> Any:
    cur: Any = payload
    for part in path.split('.'):
        if cur is None:
            return None
        if isinstance(cur, Mapping):
            cur = cur.get(part)
        elif isinstance(cur, list):
            try:
                cur = cur[int(part)]
            except (ValueError, IndexError):
                return None
        else:
            return None
    return cur


def require_aliased(
    payload: Mapping[str, Any],
    aliases: Sequence[str],
    field_name: str,
    record_id: Optional[str] = None,
) -> Any:
    """Like ``get_aliased`` but raises ``SchemaIncompatibleError`` if missing."""
    value = get_aliased(payload, aliases)
    if value is None or value == '':
        ctx = f" (record={record_id})" if record_id else ''
        raise SchemaIncompatibleError(
            f"Required field {field_name!r} not found via aliases "
            f"{list(aliases)!r}{ctx}"
        )
    return value


# ---------------------------------------------------------------------------
# Type coercion at parse boundary
# ---------------------------------------------------------------------------

_SEVERITY_NUMERIC_BANDS = (
    (9.0, 'CRITICAL'),
    (7.0, 'HIGH'),
    (4.0, 'MEDIUM'),
    (0.0, 'LOW'),
)

_SEVERITY_ALIAS = {
    'critical': 'CRITICAL',
    'high': 'HIGH',
    'med': 'MEDIUM',
    'medium': 'MEDIUM',
    'moderate': 'MEDIUM',
    'low': 'LOW',
    'none': 'NONE',
    'informational': 'NONE',
    'info': 'NONE',
}


def coerce_severity(value: Any) -> Optional[str]:
    """Normalise a severity to one of CRITICAL/HIGH/MEDIUM/LOW/NONE.

    Accepts upstream variants:
    - String: 'high', 'High', 'HIGH', 'medium', 'moderate', etc.
    - Number (int/float): mapped via CVSS bands (9+ → CRITICAL, 7+ → HIGH, ...)
    - None or empty → None

    Returns None when input is unrecognised (caller logs and continues).
    """
    if value is None or value == '':
        return None
    if isinstance(value, (int, float)) and not isinstance(value, bool):
        score = float(value)
        for threshold, label in _SEVERITY_NUMERIC_BANDS:
            if score >= threshold:
                return label
        return 'NONE'
    if isinstance(value, str):
        s = value.strip().lower()
        if s in _SEVERITY_ALIAS:
            return _SEVERITY_ALIAS[s]
        # Try parsing as number (e.g. '7.5' delivered as string)
        try:
            return coerce_severity(float(s))
        except ValueError:
            return None
    return None


def coerce_float(value: Any) -> Optional[float]:
    """Best-effort float coercion. Returns None on failure."""
    if value is None or value == '':
        return None
    if isinstance(value, bool):
        return None
    if isinstance(value, (int, float)):
        return float(value)
    if isinstance(value, str):
        try:
            return float(value.strip())
        except ValueError:
            return None
    return None


def coerce_bool(value: Any, *, truthy: Iterable[str] = ('true', '1', 'yes', 'known')) -> bool:
    """Best-effort bool coercion. CISA KEV uses 'Known' for ransomware."""
    if isinstance(value, bool):
        return value
    if isinstance(value, (int, float)):
        return bool(value)
    if isinstance(value, str):
        return value.strip().lower() in truthy
    return False


# ---------------------------------------------------------------------------
# Schema-drift telemetry
# ---------------------------------------------------------------------------

def _key_shape(obj: Any, depth: int = 0, max_depth: int = 4) -> Any:
    """Recursively extract the *key shape* of a JSON-like object.

    Strips values, keeps key names + nesting structure. Used to detect
    upstream renaming/restructuring without firing on every payload.
    """
    if depth >= max_depth:
        return type(obj).__name__
    if isinstance(obj, Mapping):
        return {k: _key_shape(v, depth + 1, max_depth) for k, v in sorted(obj.items())}
    if isinstance(obj, list):
        if not obj:
            return []
        # Sample first element only — assume list elements share shape
        return [_key_shape(obj[0], depth + 1, max_depth)]
    return type(obj).__name__


def shape_hash(payload: Any) -> str:
    """Stable hash of the *structure* of a payload (not its values).

    Two payloads with identical key-tree produce identical hashes; an
    upstream that adds, removes, or renames a key changes the hash.
    """
    shape = _key_shape(payload)
    return hashlib.sha256(
        json.dumps(shape, sort_keys=True, default=str).encode('utf-8')
    ).hexdigest()[:16]


# In-process cache: feed_name → last-seen shape hash. Module-level so it
# survives across calls but resets on process restart (acceptable: drift
# alerts on restart are harmless and re-emitted soon enough).
_LAST_KNOWN_SHAPE: dict[str, str] = {}


def detect_schema_drift(feed_name: str, payload: Any) -> bool:
    """Compute shape hash, compare to last-known, log + cache on change.

    Returns True if the shape changed (caller may emit a metric/event).
    Non-blocking: parsing continues regardless.
    """
    new_hash = shape_hash(payload)
    old_hash = _LAST_KNOWN_SHAPE.get(feed_name)
    if old_hash != new_hash:
        if old_hash is not None:
            logger.warning(
                "feed.schema_drift feed=%s old=%s new=%s — verify alias coverage",
                feed_name, old_hash, new_hash,
            )
        _LAST_KNOWN_SHAPE[feed_name] = new_hash
        return old_hash is not None
    return False
