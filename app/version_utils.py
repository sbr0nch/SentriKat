"""
Consolidated version comparison utilities.

Provides version string parsing and range-checking functions used by
both filters.py (vulnerability matching) and nvd_cpe_api.py (CPE lookups).
"""
import re


def _version_sort_key(version):
    """
    Generate a sortable key for version strings.
    Handles semver-like versions properly: 1.2.3, 10.1.18, etc.

    Key format: tuple of (type, value) pairs where:
    - type 0 = numeric (for proper numeric comparison)
    - type 1 = string (for alphabetic comparison)

    Examples:
    - "10.1.18" -> ((0,10), (0,1), (0,18))
    - "1.0.0-alpha" -> ((0,1), (0,0), (0,0), (1,'alpha'))
    """
    if not version:
        return tuple()

    parts = []
    # Split on common version delimiters
    for part in re.split(r'[.\-_+]', str(version)):
        if not part:
            continue
        # Try to convert to int for numeric comparison
        try:
            parts.append((0, int(part)))
        except ValueError:
            # Handle mixed alphanumeric like "18ubuntu1"
            # Split into numeric prefix and alpha suffix
            match = re.match(r'^(\d+)(.*)$', part)
            if match:
                parts.append((0, int(match.group(1))))
                if match.group(2):
                    parts.append((1, match.group(2).lower()))
            else:
                parts.append((1, part.lower()))
    return tuple(parts)


def _version_in_range(version, start, end, start_type, end_type):
    """
    Check if a version falls within a specified range.

    ENTERPRISE LOGIC:
    - If no version range specified (no start AND no end): Returns True (all versions affected)
    - If version range exists but product has no version: Returns False (can't verify, be conservative)
    - Otherwise: Check if version is within the specified range

    This prevents false positives by requiring version verification when CPE data has ranges.
    """
    # If no version range specified at all, all versions are affected
    if not start and not end:
        return True

    # If version range exists but product has no version, we can't verify - be conservative
    if not version:
        return False  # Changed from True - don't assume match without version proof

    version_key = _version_sort_key(version)

    if start:
        start_key = _version_sort_key(start)
        if start_type == 'including':
            if version_key < start_key:
                return False
        else:  # excluding
            if version_key <= start_key:
                return False

    if end:
        end_key = _version_sort_key(end)
        if end_type == 'including':
            if version_key > end_key:
                return False
        else:  # excluding
            if version_key >= end_key:
                return False

    return True
