"""
Tests for distro-native version comparison algorithms.

Covers dpkg EVR (Debian/Ubuntu), RPM EVR (RHEL/CentOS), APK (Alpine),
format detection, and the unified is_version_patched interface.
"""
import pytest
from app.version_utils import (
    _parse_evr,
    dpkg_version_compare,
    rpm_version_compare,
    apk_version_compare,
    detect_version_format,
    distro_version_compare,
    is_version_patched,
    _version_sort_key,
    _version_in_range,
)


# =============================================================================
# EVR Parsing
# =============================================================================

class TestParseEVR:
    def test_full_evr(self):
        assert _parse_evr("2:1.0-3") == (2, "1.0", "3")

    def test_no_epoch(self):
        assert _parse_evr("1.0-3ubuntu1") == (0, "1.0", "3ubuntu1")

    def test_no_release(self):
        assert _parse_evr("1.0") == (0, "1.0", "")

    def test_epoch_zero(self):
        assert _parse_evr("0:2.4.52-1ubuntu4.6") == (0, "2.4.52", "1ubuntu4.6")

    def test_empty(self):
        assert _parse_evr("") == (0, "", "")

    def test_multiple_dashes(self):
        # Last dash separates version from release
        assert _parse_evr("1.0-beta1-2") == (0, "1.0-beta1", "2")

    def test_invalid_epoch(self):
        assert _parse_evr("abc:1.0-1") == (0, "1.0", "1")


# =============================================================================
# dpkg Version Comparison (Debian/Ubuntu)
# =============================================================================

class TestDpkgVersionCompare:
    """Test cases from the Debian Policy Manual §5.6.12 and real-world packages."""

    def test_simple_newer(self):
        assert dpkg_version_compare("1.1", "1.0") == 1

    def test_simple_older(self):
        assert dpkg_version_compare("1.0", "1.1") == -1

    def test_equal(self):
        assert dpkg_version_compare("1.0-1", "1.0-1") == 0

    # --- Tilde handling (critical for backports) ---

    def test_tilde_before_release(self):
        """1.0~beta sorts BEFORE 1.0 (tilde = pre-release)"""
        assert dpkg_version_compare("1.0~beta1", "1.0") == -1

    def test_tilde_before_anything(self):
        """Tilde sorts before even the empty string"""
        assert dpkg_version_compare("1.0~", "1.0") == -1

    def test_tilde_rc_vs_beta(self):
        """~rc sorts after ~beta (r > b)"""
        assert dpkg_version_compare("1.0~rc1", "1.0~beta2") == 1

    def test_tilde_ordering(self):
        """~alpha < ~beta < ~rc < release"""
        assert dpkg_version_compare("1.0~alpha", "1.0~beta") == -1
        assert dpkg_version_compare("1.0~beta", "1.0~rc1") == -1
        assert dpkg_version_compare("1.0~rc1", "1.0") == -1

    # --- Epoch handling ---

    def test_epoch_wins(self):
        assert dpkg_version_compare("2:1.0", "1:2.0") == 1

    def test_no_epoch_vs_epoch(self):
        """No epoch = epoch 0"""
        assert dpkg_version_compare("1.0-1", "2:0.1-1") == -1

    def test_same_epoch(self):
        assert dpkg_version_compare("1:1.0-1", "1:1.0-2") == -1

    # --- Real Ubuntu Apache backport ---

    def test_ubuntu_apache_patched(self):
        """Ubuntu Apache: 4.6 revision is newer than 4.3 fix"""
        assert dpkg_version_compare("2.4.52-1ubuntu4.6", "2.4.52-1ubuntu4.3") == 1

    def test_ubuntu_apache_not_patched(self):
        """Ubuntu Apache: 4.1 revision is older than 4.3 fix"""
        assert dpkg_version_compare("2.4.52-1ubuntu4.1", "2.4.52-1ubuntu4.3") == -1

    def test_ubuntu_apache_exact_match(self):
        """Exact match = patched"""
        assert dpkg_version_compare("2.4.52-1ubuntu4.3", "2.4.52-1ubuntu4.3") == 0

    # --- Real Debian OpenSSL backport ---

    def test_debian_openssl(self):
        assert dpkg_version_compare("1.1.1n-0+deb11u5", "1.1.1n-0+deb11u3") == 1

    def test_debian_openssl_not_patched(self):
        assert dpkg_version_compare("1.1.1n-0+deb11u1", "1.1.1n-0+deb11u3") == -1

    # --- Revision comparison ---

    def test_higher_revision(self):
        assert dpkg_version_compare("1.0-2", "1.0-1") == 1

    def test_point_revision(self):
        assert dpkg_version_compare("1.0-1.1", "1.0-1") == 1

    # --- Letter vs digit ordering ---

    def test_letters_before_non_letters(self):
        """In dpkg, letters sort before non-letter chars (except ~)"""
        assert dpkg_version_compare("1.0a", "1.0.") == -1


# =============================================================================
# RPM Version Comparison (RHEL/CentOS/Fedora)
# =============================================================================

class TestRpmVersionCompare:
    """Test cases from RPM rpmvercmp behavior."""

    def test_simple_newer(self):
        assert rpm_version_compare("2.0", "1.0") == 1

    def test_simple_older(self):
        assert rpm_version_compare("1.0", "2.0") == -1

    def test_equal(self):
        assert rpm_version_compare("1.0-1.el8", "1.0-1.el8") == 0

    # --- Release comparison ---

    def test_newer_release(self):
        assert rpm_version_compare("2.4.37-47.el8", "2.4.37-43.el8") == 1

    def test_older_release(self):
        assert rpm_version_compare("2.4.37-43.el8", "2.4.37-47.el8") == -1

    # --- Epoch handling ---

    def test_epoch_wins(self):
        assert rpm_version_compare("1:1.0-1.el8", "2.0-1.el8") == 1

    def test_no_epoch_vs_epoch(self):
        assert rpm_version_compare("2.0-1.el8", "1:1.0-1.el8") == -1

    # --- Real RHEL vim backport ---

    def test_rhel_vim_patched(self):
        assert rpm_version_compare("8.0.1763-19.el8_6.4", "8.0.1763-19.el8_6.2") == 1

    def test_rhel_vim_not_patched(self):
        assert rpm_version_compare("8.0.1763-19.el8_6.1", "8.0.1763-19.el8_6.4") == -1

    # --- Digit beats alpha in RPM ---

    def test_digit_beats_alpha(self):
        """In RPM, digit segments always sort higher than alpha segments"""
        assert rpm_version_compare("1.0.1", "1.0.a") == 1

    # --- Module stream suffixes ---

    def test_module_suffix(self):
        assert rpm_version_compare(
            "2.4.37-47.module+el8.6.0+15654+1",
            "2.4.37-43.module+el8.5.0+13806+b"
        ) == 1

    # --- Leading zeros ---

    def test_leading_zeros(self):
        """Leading zeros stripped in numeric comparison"""
        assert rpm_version_compare("1.01", "1.1") == 0

    # --- Different segment counts ---

    def test_more_segments_wins(self):
        assert rpm_version_compare("1.0.0.1", "1.0.0") == 1

    def test_fewer_segments_loses(self):
        assert rpm_version_compare("1.0", "1.0.1") == -1


# =============================================================================
# APK Version Comparison (Alpine)
# =============================================================================

class TestApkVersionCompare:
    def test_newer_version(self):
        assert apk_version_compare("2.4.58-r0", "2.4.57-r3") == 1

    def test_older_revision(self):
        assert apk_version_compare("2.4.57-r1", "2.4.57-r3") == -1

    def test_equal(self):
        assert apk_version_compare("2.4.57-r3", "2.4.57-r3") == 0

    def test_no_revision(self):
        assert apk_version_compare("1.0", "1.0-r1") == -1

    def test_newer_revision(self):
        assert apk_version_compare("2.4.57-r5", "2.4.57-r3") == 1


# =============================================================================
# Format Detection
# =============================================================================

class TestDetectVersionFormat:
    def test_debian_ecosystem(self):
        assert detect_version_format("Debian:11") == "dpkg"

    def test_ubuntu_ecosystem(self):
        assert detect_version_format("Ubuntu:22.04") == "dpkg"

    def test_rhel_from_os(self):
        assert detect_version_format("", "Red Hat Enterprise Linux 8") == "rpm"

    def test_centos_from_os(self):
        assert detect_version_format("", "CentOS Linux 7") == "rpm"

    def test_alpine_ecosystem(self):
        assert detect_version_format("Alpine:v3.18") == "apk"

    def test_pypi_generic(self):
        assert detect_version_format("PyPI") == "generic"

    def test_none_input(self):
        assert detect_version_format(None, None) == "generic"

    def test_rocky_from_os(self):
        assert detect_version_format("", "Rocky Linux 9") == "rpm"

    def test_alma_from_os(self):
        assert detect_version_format("", "AlmaLinux 9") == "rpm"


# =============================================================================
# Unified Interface
# =============================================================================

class TestDistroVersionCompare:
    def test_dpkg_dispatch(self):
        assert distro_version_compare("1.0~beta", "1.0", "dpkg") == -1

    def test_rpm_dispatch(self):
        assert distro_version_compare("1.0-2.el8", "1.0-1.el8", "rpm") == 1

    def test_apk_dispatch(self):
        assert distro_version_compare("1.0-r2", "1.0-r1", "apk") == 1

    def test_generic_dispatch(self):
        assert distro_version_compare("1.2", "1.1", "generic") == 1

    def test_empty_strings(self):
        assert distro_version_compare("", "", "dpkg") == 0

    def test_none_a(self):
        assert distro_version_compare(None, "1.0", "dpkg") == -1

    def test_none_b(self):
        assert distro_version_compare("1.0", None, "dpkg") == 1


class TestIsVersionPatched:
    """Test the main entry point used by vendor_advisories.py."""

    def test_ubuntu_patched(self):
        assert is_version_patched("2.4.52-1ubuntu4.6", "2.4.52-1ubuntu4.3", "dpkg") is True

    def test_ubuntu_not_patched(self):
        assert is_version_patched("2.4.52-1ubuntu4.1", "2.4.52-1ubuntu4.3", "dpkg") is False

    def test_ubuntu_exact_match(self):
        assert is_version_patched("2.4.52-1ubuntu4.3", "2.4.52-1ubuntu4.3", "dpkg") is True

    def test_rhel_patched(self):
        assert is_version_patched("2.4.37-47.el8", "2.4.37-43.el8", "rpm") is True

    def test_rhel_not_patched(self):
        assert is_version_patched("2.4.37-40.el8", "2.4.37-43.el8", "rpm") is False

    def test_alpine_patched(self):
        assert is_version_patched("2.4.58-r0", "2.4.57-r3", "apk") is True

    def test_alpine_not_patched(self):
        assert is_version_patched("2.4.56-r2", "2.4.57-r3", "apk") is False

    def test_empty_installed(self):
        assert is_version_patched("", "1.0", "dpkg") is False

    def test_empty_fixed(self):
        assert is_version_patched("1.0", "", "rpm") is False

    def test_generic_fallback(self):
        assert is_version_patched("10.1.18", "10.1.15", "generic") is True
        assert is_version_patched("10.1.10", "10.1.15", "generic") is False


# =============================================================================
# Existing sort key and range functions (regression tests)
# =============================================================================

class TestVersionSortKey:
    def test_semver(self):
        key = _version_sort_key("10.1.18")
        assert key == ((0, 10), (0, 1), (0, 18))

    def test_mixed_alphanumeric(self):
        key = _version_sort_key("18ubuntu1")
        assert key == ((0, 18), (1, 'ubuntu1'))

    def test_empty(self):
        assert _version_sort_key("") == tuple()
        assert _version_sort_key(None) == tuple()


class TestVersionInRange:
    def test_no_range(self):
        """No range = all versions affected"""
        assert _version_in_range("1.0", None, None, None, None) is True

    def test_no_version_with_range(self):
        """Version range exists but no product version"""
        assert _version_in_range(None, "1.0", "2.0", "including", "excluding") is False

    def test_in_range_including(self):
        assert _version_in_range("1.5", "1.0", "2.0", "including", "excluding") is True

    def test_at_start_including(self):
        assert _version_in_range("1.0", "1.0", "2.0", "including", "excluding") is True

    def test_at_start_excluding(self):
        assert _version_in_range("1.0", "1.0", "2.0", "excluding", "excluding") is False

    def test_at_end_excluding(self):
        assert _version_in_range("2.0", "1.0", "2.0", "including", "excluding") is False

    def test_at_end_including(self):
        assert _version_in_range("2.0", "1.0", "2.0", "including", "including") is True
