"""
Consolidated version comparison utilities.

Provides version string parsing and range-checking functions used by
both filters.py (vulnerability matching) and nvd_cpe_api.py (CPE lookups).

Includes distro-native version comparison:
- dpkg EVR: Ubuntu, Debian (epoch:upstream_version-debian_revision)
- RPM EVR: RHEL, CentOS, Fedora, SUSE (epoch:version-release)
- APK: Alpine Linux
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

    # Pre-release labels that should sort BEFORE the release version.
    # In semver, 1.0.0-alpha < 1.0.0-beta < 1.0.0-rc < 1.0.0
    _PRE_RELEASE_ORDER = {
        'dev': -5, 'alpha': -4, 'a': -4,
        'beta': -3, 'b': -3,
        'rc': -2, 'cr': -2,
        'pre': -1, 'preview': -1,
    }

    parts = []
    # Split on common version delimiters (includes ':' to handle epoch prefixes
    # like "2:1.0.3" — the epoch becomes a leading numeric segment, ensuring
    # 2:1.0 sorts higher than 1:2.0 in the generic comparator)
    for part in re.split(r'[.\-_+:]', str(version)):
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
                    label = match.group(2).lower()
                    pre_order = _PRE_RELEASE_ORDER.get(label)
                    if pre_order is not None:
                        parts.append((-1, pre_order))
                    else:
                        parts.append((1, label))
            else:
                label = part.lower()
                pre_order = _PRE_RELEASE_ORDER.get(label)
                if pre_order is not None:
                    # Pre-release: sort before the release (type -1 < type 0 < type 1)
                    parts.append((-1, pre_order))
                else:
                    parts.append((1, label))
    return tuple(parts)


def _version_in_range(version, start, end, start_type, end_type, version_format='generic'):
    """
    Check if a version falls within a specified range.

    ENTERPRISE LOGIC:
    - If no version range specified (no start AND no end): Returns True (all versions affected)
    - If version range exists but product has no version: Returns False (can't verify, be conservative)
    - Otherwise: Check if version is within the specified range

    When version_format is 'dpkg', 'rpm', or 'apk', uses the distro-native
    comparator instead of the generic _version_sort_key().  This correctly
    handles Debian epochs/tildes, RPM release strings, and Alpine revisions.

    This prevents false positives by requiring version verification when CPE data has ranges.
    """
    # If no version range specified at all, all versions are affected
    if not start and not end:
        return True

    # If version range exists but product has no version, we can't verify - be conservative
    if not version:
        return False  # Changed from True - don't assume match without version proof

    # Use distro-native comparison when format is known, generic otherwise
    def _cmp(a, b):
        return distro_version_compare(a, b, version_format)

    if start:
        cmp_result = _cmp(version, start)
        if start_type == 'including':
            if cmp_result < 0:
                return False
        else:  # excluding
            if cmp_result <= 0:
                return False

    if end:
        cmp_result = _cmp(version, end)
        if end_type == 'including':
            if cmp_result > 0:
                return False
        else:  # excluding
            if cmp_result >= 0:
                return False

    return True


# =============================================================================
# Distro-native version comparison (dpkg EVR, RPM EVR, APK)
# =============================================================================

def _parse_evr(version_string):
    """
    Parse an epoch:version-release string into (epoch, version, release).
    Works for both dpkg and RPM version formats.

    Examples:
        "2:1.0-3"      -> (2, "1.0", "3")
        "1.0-3ubuntu1" -> (0, "1.0", "3ubuntu1")
        "1.0"          -> (0, "1.0", "")
        "0:2.4.52-1ubuntu4.6" -> (0, "2.4.52", "1ubuntu4.6")
    """
    s = str(version_string).strip()
    if not s:
        return (0, "", "")

    # Extract epoch (everything before first ':')
    epoch = 0
    if ':' in s:
        epoch_str, s = s.split(':', 1)
        try:
            epoch = int(epoch_str)
        except ValueError:
            epoch = 0

    # Split version and release on last '-'
    if '-' in s:
        idx = s.rfind('-')
        version = s[:idx]
        release = s[idx + 1:]
    else:
        version = s
        release = ""

    return (epoch, version, release)


# --- dpkg version comparison (Debian/Ubuntu) ---

def _dpkg_char_order(c):
    """
    Character ordering for dpkg version comparison.
    From dpkg source (lib/dpkg/version.c):
    - '~' sorts before everything (even empty)
    - Empty/end-of-string sorts next
    - Letters sort before non-letters
    - Everything else sorts by ASCII value
    """
    if c == '~':
        return -1
    if c == '':
        return 0
    if c.isalpha():
        return ord(c)
    # Non-alpha chars sort after letters (letters are 65-122)
    return ord(c) + 256


def _dpkg_compare_part(a, b):
    """
    Compare two version parts (upstream or revision) using dpkg algorithm.

    From dpkg source: the string is consumed left-to-right by first
    comparing non-digit characters (using _dpkg_char_order), then
    comparing digit groups as integers.
    """
    ia = 0
    ib = 0

    while ia < len(a) or ib < len(b):
        # Compare non-digit characters
        while (ia < len(a) and not a[ia].isdigit()) or \
              (ib < len(b) and not b[ib].isdigit()):
            ac = a[ia] if ia < len(a) and not a[ia].isdigit() else ''
            bc = b[ib] if ib < len(b) and not b[ib].isdigit() else ''
            ao = _dpkg_char_order(ac)
            bo = _dpkg_char_order(bc)
            if ao != bo:
                return -1 if ao < bo else 1
            if ia < len(a) and not a[ia].isdigit():
                ia += 1
            if ib < len(b) and not b[ib].isdigit():
                ib += 1
            # Break if both have reached digits or end
            if (ia >= len(a) or a[ia].isdigit()) and \
               (ib >= len(b) or b[ib].isdigit()):
                break

        # Compare digit groups as integers
        da = ""
        while ia < len(a) and a[ia].isdigit():
            da += a[ia]
            ia += 1
        db = ""
        while ib < len(b) and b[ib].isdigit():
            db += b[ib]
            ib += 1

        na = int(da) if da else 0
        nb = int(db) if db else 0
        if na != nb:
            return -1 if na < nb else 1

    return 0


def dpkg_version_compare(ver_a, ver_b):
    """
    Compare two Debian/Ubuntu version strings using the dpkg algorithm.

    Returns: -1 if a < b, 0 if a == b, 1 if a > b

    Algorithm (from Debian Policy Manual §5.6.12):
    1. Compare epochs numerically
    2. Compare upstream versions using dpkg part comparison
    3. Compare debian revisions using dpkg part comparison

    Examples:
        dpkg_version_compare("2.4.52-1ubuntu4.6", "2.4.52-1ubuntu4.3") -> 1
        dpkg_version_compare("1.0~beta1", "1.0") -> -1  (tilde < release)
        dpkg_version_compare("2:1.0", "1:2.0") -> 1  (higher epoch wins)
    """
    e_a, v_a, r_a = _parse_evr(ver_a)
    e_b, v_b, r_b = _parse_evr(ver_b)

    # Compare epochs
    if e_a != e_b:
        return -1 if e_a < e_b else 1

    # Compare upstream versions
    result = _dpkg_compare_part(v_a, v_b)
    if result != 0:
        return result

    # Compare debian revisions
    return _dpkg_compare_part(r_a, r_b)


# --- RPM version comparison (RHEL/CentOS/Fedora/SUSE) ---

def _rpmvercmp(a, b):
    """
    Compare two version strings using the RPM algorithm (rpmvercmp).

    From RPM source (lib/rpmvercmp.c):
    1. Strip leading non-alphanumeric characters
    2. Extract segments of contiguous digits or contiguous letters
    3. If both digits: compare as integers
    4. If both letters: compare lexically
    5. Digit segment always beats alpha segment
    6. More remaining segments wins
    """
    if a == b:
        return 0
    if not a:
        return -1
    if not b:
        return 1

    # Tokenize into segments of digits or letters
    def tokenize(s):
        tokens = []
        i = 0
        while i < len(s):
            # Skip non-alphanumeric separators
            while i < len(s) and not s[i].isalnum():
                i += 1
            if i >= len(s):
                break
            j = i
            if s[i].isdigit():
                while j < len(s) and s[j].isdigit():
                    j += 1
                tokens.append(('d', s[i:j]))
            else:
                while j < len(s) and s[j].isalpha():
                    j += 1
                tokens.append(('a', s[i:j]))
            i = j
        return tokens

    a_tokens = tokenize(a)
    b_tokens = tokenize(b)

    for i in range(min(len(a_tokens), len(b_tokens))):
        a_type, a_val = a_tokens[i]
        b_type, b_val = b_tokens[i]

        # Digit segments always beat alpha segments
        if a_type != b_type:
            return 1 if a_type == 'd' else -1

        if a_type == 'd':
            # Numeric comparison
            a_num = int(a_val)
            b_num = int(b_val)
            if a_num != b_num:
                return -1 if a_num < b_num else 1
        else:
            # Lexicographic comparison
            if a_val != b_val:
                return -1 if a_val < b_val else 1

    # All compared segments equal; longer one wins
    if len(a_tokens) != len(b_tokens):
        return -1 if len(a_tokens) < len(b_tokens) else 1

    return 0


def rpm_version_compare(ver_a, ver_b):
    """
    Compare two RPM version strings using the RPM EVR algorithm.

    Returns: -1 if a < b, 0 if a == b, 1 if a > b

    Examples:
        rpm_version_compare("2.4.37-47.el8", "2.4.37-43.el8") -> 1
        rpm_version_compare("1:1.0-1.el8", "2.0-1.el8") -> 1  (epoch wins)
        rpm_version_compare("8.0.1763-19.el8_6.4", "8.0.1763-19.el8_6.2") -> 1
    """
    e_a, v_a, r_a = _parse_evr(ver_a)
    e_b, v_b, r_b = _parse_evr(ver_b)

    # Compare epochs
    if e_a != e_b:
        return -1 if e_a < e_b else 1

    # Compare versions
    result = _rpmvercmp(v_a, v_b)
    if result != 0:
        return result

    # Compare releases (only if both have releases)
    if r_a or r_b:
        return _rpmvercmp(r_a, r_b)

    return 0


# --- APK version comparison (Alpine) ---

def apk_version_compare(ver_a, ver_b):
    """
    Compare two Alpine APK version strings.
    Format: digit.digit.digit-rN where -rN is the Alpine package revision.

    Returns: -1 if a < b, 0 if a == b, 1 if a > b
    """
    def split_apk(v):
        s = str(v).strip()
        match = re.match(r'^(.+)-r(\d+)$', s)
        if match:
            return match.group(1), int(match.group(2))
        return s, 0

    base_a, rev_a = split_apk(ver_a)
    base_b, rev_b = split_apk(ver_b)

    # Compare base versions using sort key (APK is close to semver)
    key_a = _version_sort_key(base_a)
    key_b = _version_sort_key(base_b)

    if key_a != key_b:
        return -1 if key_a < key_b else 1

    # Compare revisions
    if rev_a != rev_b:
        return -1 if rev_a < rev_b else 1

    return 0


# --- Unified comparison interface ---

def detect_version_format(ecosystem, os_info=None):
    """
    Detect the version comparison format based on ecosystem or OS info.

    Returns: "dpkg", "rpm", "apk", or "generic"
    """
    eco = (ecosystem or '').lower()
    os_str = (os_info or '').lower()

    # Debian-family (dpkg)
    if any(d in eco for d in ['debian', 'ubuntu', 'mint', 'kali']):
        return 'dpkg'
    if any(d in os_str for d in ['debian', 'ubuntu', 'mint', 'kali']):
        return 'dpkg'

    # RPM-family
    if any(d in eco for d in ['rhel', 'redhat', 'centos', 'fedora', 'suse',
                               'opensuse', 'rocky', 'alma', 'oracle', 'amazon']):
        return 'rpm'
    if any(d in os_str for d in ['rhel', 'red hat', 'centos', 'fedora', 'suse',
                                  'rocky', 'alma', 'oracle linux', 'amazon']):
        return 'rpm'

    # Alpine (APK)
    if 'alpine' in eco or 'alpine' in os_str:
        return 'apk'

    return 'generic'


def distro_version_compare(ver_a, ver_b, version_format='generic'):
    """
    Compare two version strings using the appropriate distro algorithm.

    Returns: -1 if a < b, 0 if a == b, 1 if a > b
    """
    if not ver_a and not ver_b:
        return 0
    if not ver_a:
        return -1
    if not ver_b:
        return 1

    ver_a = str(ver_a).strip()
    ver_b = str(ver_b).strip()

    if version_format == 'dpkg':
        return dpkg_version_compare(ver_a, ver_b)
    elif version_format == 'rpm':
        return rpm_version_compare(ver_a, ver_b)
    elif version_format == 'apk':
        return apk_version_compare(ver_a, ver_b)
    else:
        key_a = _version_sort_key(ver_a)
        key_b = _version_sort_key(ver_b)
        if key_a == key_b:
            return 0
        return -1 if key_a < key_b else 1


def is_version_patched(installed_version, fixed_version, version_format='generic'):
    """
    Check if an installed version is >= the fixed version (i.e., patched).

    This is the main entry point used by vendor_advisories.py to decide
    whether a package has the fix applied.

    Returns: True if installed_version >= fixed_version
    """
    if not installed_version or not fixed_version:
        return False
    return distro_version_compare(installed_version, fixed_version, version_format) >= 0
