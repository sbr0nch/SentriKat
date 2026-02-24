#!/usr/bin/env python3
"""
sentrikat-scan — Lightweight dependency vulnerability scanner for SentriKat.

Scans lockfiles in the current project and reports vulnerabilities to your
SentriKat server via the dependency-scan API. Designed for:

  - CI/CD pipelines (GitHub Actions, GitLab CI, Jenkins, etc.)
  - Developer workstations (manual or pre-commit hook)
  - Any environment where code lives but no SentriKat agent is installed

Setup:
    # Option 1: pip install (when published)
    pip install sentrikat-scan

    # Option 2: Download and run directly (zero dependencies, Python 3.7+)
    curl -O https://your-sentrikat-server/downloads/sentrikat-scan.py
    chmod +x sentrikat-scan.py

    # Option 3: Copy into your project and commit it
    cp sentrikat-scan.py /path/to/your/project/

Quick start:
    # Initialize config (creates .sentrikat-scan.conf in project root)
    sentrikat-scan --init

    # Test connectivity to SentriKat server
    sentrikat-scan --test

    # Run a scan
    sentrikat-scan

    # CI/CD mode (non-zero exit on critical/high vulns)
    sentrikat-scan --fail-on high

    # Use environment variables instead of config file (for CI secrets)
    export SENTRIKAT_SERVER=https://sentrikat.example.com
    export SENTRIKAT_API_KEY=sk_...
    sentrikat-scan

Supported lockfiles:
    package-lock.json, yarn.lock, pnpm-lock.yaml, Pipfile.lock, poetry.lock,
    Cargo.lock, go.sum, go.mod, Gemfile.lock, composer.lock, packages.lock.json

No dependencies required — uses only Python stdlib (3.7+).
"""

import argparse
import json
import os
import platform
import re
import ssl
import sys
import time
import uuid
from configparser import ConfigParser
from pathlib import Path
from urllib.request import Request, urlopen
from urllib.error import HTTPError, URLError

VERSION = "1.0.0"

LOCKFILE_NAMES = [
    "package-lock.json", "yarn.lock", "pnpm-lock.yaml",
    "Pipfile.lock", "poetry.lock", "Cargo.lock",
    "go.sum", "go.mod", "Gemfile.lock",
    "composer.lock", "packages.lock.json",
]

MAX_FILE_SIZE = 5 * 1024 * 1024  # 5 MB per lockfile
MAX_DEPTH = 5
CONFIG_FILENAME = ".sentrikat-scan.conf"

SKIP_DIRS = [
    "node_modules", ".git", "__pycache__", ".tox",
    "venv", ".venv", "env", ".env", "vendor",
    ".mypy_cache", ".pytest_cache", "dist", "build",
]

# ANSI color codes for terminal output
class Color:
    RED = "\033[91m"
    GREEN = "\033[92m"
    YELLOW = "\033[93m"
    BLUE = "\033[94m"
    CYAN = "\033[96m"
    BOLD = "\033[1m"
    DIM = "\033[2m"
    RESET = "\033[0m"

    @classmethod
    def disable(cls):
        cls.RED = cls.GREEN = cls.YELLOW = cls.BLUE = ""
        cls.CYAN = cls.BOLD = cls.DIM = cls.RESET = ""


def _no_color():
    """Check if color output should be disabled."""
    return (
        os.environ.get("NO_COLOR") is not None
        or os.environ.get("TERM") == "dumb"
        or not sys.stderr.isatty()
    )


def debug(msg, verbose=False):
    if verbose:
        print(f"{Color.DIM}  [debug] {msg}{Color.RESET}", file=sys.stderr)


def info(msg):
    print(f"  {msg}", file=sys.stderr)


def warn(msg):
    print(f"{Color.YELLOW}  [warn] {msg}{Color.RESET}", file=sys.stderr)


def error(msg):
    print(f"{Color.RED}  [error] {msg}{Color.RESET}", file=sys.stderr)


def success(msg):
    print(f"{Color.GREEN}  {msg}{Color.RESET}", file=sys.stderr)


# ────────────────────────────────────────────────────────────────────────────
# Config file management
# ────────────────────────────────────────────────────────────────────────────

def find_config_file(start_path):
    """Walk up from start_path looking for .sentrikat-scan.conf."""
    path = Path(start_path).resolve()
    for _ in range(20):  # Limit depth to avoid infinite traversal
        config_path = path / CONFIG_FILENAME
        if config_path.is_file():
            return config_path
        parent = path.parent
        if parent == path:
            break
        path = parent
    return None


def load_config(scan_path):
    """Load settings from config file, if found. Returns dict."""
    config_path = find_config_file(scan_path)
    if not config_path:
        return {}

    cfg = ConfigParser()
    try:
        cfg.read(str(config_path), encoding="utf-8")
    except Exception:
        return {}

    result = {}
    if cfg.has_section("sentrikat"):
        for key in ["server", "key", "project_name", "fail_on", "depth"]:
            val = cfg.get("sentrikat", key, fallback=None)
            if val:
                result[key] = val
    return result


def init_config(scan_path):
    """Interactive config file creation."""
    config_path = Path(scan_path).resolve() / CONFIG_FILENAME

    print(f"\n{Color.BOLD}SentriKat Scan — Configuration Setup{Color.RESET}")
    print(f"{'─' * 45}")

    if config_path.exists():
        print(f"\n  Config file already exists: {config_path}")
        resp = input("  Overwrite? [y/N]: ").strip().lower()
        if resp != "y":
            print("  Aborted.")
            return

    print()
    server = input("  SentriKat server URL (e.g. https://sentrikat.example.com): ").strip()
    if not server:
        error("Server URL is required.")
        sys.exit(1)

    api_key = input("  API key (starts with sk_): ").strip()
    if not api_key:
        error("API key is required.")
        sys.exit(1)

    project_name = input(f"  Project name [{Path(scan_path).resolve().name}]: ").strip()
    if not project_name:
        project_name = Path(scan_path).resolve().name

    fail_on = input("  Fail CI on severity [none/critical/high/medium/low] (default: none): ").strip().lower()
    if fail_on not in ("critical", "high", "medium", "low"):
        fail_on = ""

    # Write config
    lines = [
        f"# SentriKat Scan configuration",
        f"# Created: {time.strftime('%Y-%m-%d %H:%M:%S')}",
        f"# Docs: sentrikat-scan --help",
        f"",
        f"[sentrikat]",
        f"server = {server}",
        f"key = {api_key}",
        f"project_name = {project_name}",
    ]
    if fail_on:
        lines.append(f"fail_on = {fail_on}")

    try:
        config_path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    except OSError as e:
        error(f"Cannot write config: {e}")
        sys.exit(1)

    print(f"\n{Color.GREEN}  Config saved to: {config_path}{Color.RESET}")
    print()

    # Remind to add to .gitignore
    gitignore = Path(scan_path).resolve() / ".gitignore"
    if gitignore.exists():
        try:
            content = gitignore.read_text(encoding="utf-8", errors="replace")
        except OSError:
            content = ""
        if CONFIG_FILENAME not in content:
            print(f"{Color.YELLOW}  IMPORTANT: Add '{CONFIG_FILENAME}' to your .gitignore!{Color.RESET}")
            print(f"  The config file contains your API key and should NOT be committed.")
            resp = input(f"  Add it to .gitignore now? [Y/n]: ").strip().lower()
            if resp != "n":
                try:
                    with open(str(gitignore), "a", encoding="utf-8") as f:
                        f.write(f"\n# SentriKat scan config (contains API key)\n{CONFIG_FILENAME}\n")
                    success(f"Added '{CONFIG_FILENAME}' to .gitignore")
                except OSError as e:
                    warn(f"Could not update .gitignore: {e}")
    else:
        print(f"{Color.YELLOW}  IMPORTANT: If using git, add '{CONFIG_FILENAME}' to .gitignore!{Color.RESET}")
        print(f"  The config file contains your API key and should NOT be committed.")

    # Test connection
    print(f"\n  Testing connection to {server}...")
    _test_connection(server, api_key, verbose=True)


# ────────────────────────────────────────────────────────────────────────────
# Connection testing
# ────────────────────────────────────────────────────────────────────────────

def _test_connection(server_url, api_key, verbose=False):
    """Test connectivity to SentriKat server. Returns True on success."""
    url = f"{server_url.rstrip('/')}/api/agent/heartbeat"

    debug(f"Testing connection to {url}", verbose)
    debug(f"API key: {api_key[:8]}...{api_key[-4:]}" if len(api_key) > 12 else "API key: (short)", verbose)

    # Validate URL format
    if not re.match(r'^https?://', server_url):
        error("Server URL must start with http:// or https://")
        error(f"  Got: {server_url}")
        return False

    payload = json.dumps({
        "hostname": platform.node() or "scan-test",
        "agent_id": f"scan-test-{uuid.uuid4().hex[:8]}",
        "agent_version": f"sentrikat-scan/{VERSION}",
    }).encode("utf-8")

    req = Request(url, data=payload, method="POST")
    req.add_header("Content-Type", "application/json")
    req.add_header("X-Agent-Key", api_key)
    req.add_header("User-Agent", f"SentriKat-Scan/{VERSION} (Python {platform.python_version()})")

    try:
        debug("Sending heartbeat request...", verbose)
        with urlopen(req, timeout=15) as resp:
            status = resp.status
            body = resp.read().decode("utf-8", errors="replace")
            debug(f"Response: HTTP {status}", verbose)
            debug(f"Body: {body[:200]}", verbose)

            if status == 200:
                success("Connection successful!")
                info(f"Server: {server_url}")
                info(f"API key: valid")
                return True
            else:
                warn(f"Unexpected response (HTTP {status})")
                return False

    except HTTPError as e:
        status = e.code
        body = e.read().decode("utf-8", errors="replace")[:500]
        debug(f"HTTP error body: {body}", verbose)

        if status == 401:
            error("Authentication failed — invalid API key")
            error(f"  Server: {server_url}")
            error(f"  Key: {api_key[:8]}..." if len(api_key) > 8 else f"  Key: {api_key}")
            info("")
            info("Check that:")
            info("  1. The API key is correct (starts with sk_)")
            info("  2. The key has not been revoked in SentriKat settings")
            info("  3. The key is an agent-type key (not user/integration)")
        elif status == 403:
            error("Access forbidden — the API key may not have scan permissions")
            error(f"  Server: {server_url}")
        elif status == 404:
            error("Endpoint not found — is this a SentriKat server?")
            error(f"  URL: {url}")
            info("")
            info("Check that:")
            info("  1. The server URL is correct")
            info("  2. The server is running SentriKat (not another application)")
            info("  3. The server version supports dependency scanning")
        elif status >= 500:
            error(f"Server error (HTTP {status})")
            error(f"  Server: {server_url}")
            info("  The SentriKat server may be experiencing issues. Try again later.")
        else:
            error(f"Unexpected HTTP {status} from server")
            if body:
                debug(f"Response: {body}", verbose)
        return False

    except URLError as e:
        reason = str(e.reason)
        debug(f"URLError reason: {reason}", verbose)

        if "SSL" in reason or "CERTIFICATE" in reason.upper():
            error("SSL/TLS error — cannot verify server certificate")
            error(f"  Server: {server_url}")
            info("")
            info("Check that:")
            info("  1. The server URL uses the correct protocol (https:// vs http://)")
            info("  2. The server has a valid SSL certificate")
            info("  3. Your system clock is correct")
            if "self-signed" in reason.lower() or "CERTIFICATE_VERIFY_FAILED" in reason:
                info("  4. If using a self-signed cert, set PYTHONHTTPSVERIFY=0 (not recommended)")
        elif "refused" in reason.lower():
            error("Connection refused — server is not accepting connections")
            error(f"  Server: {server_url}")
            info("")
            info("Check that:")
            info("  1. The server URL and port are correct")
            info("  2. The SentriKat server is running")
            info("  3. Firewall rules allow outbound connections to the server")
        elif "timed out" in reason.lower() or "timeout" in reason.lower():
            error("Connection timed out — server did not respond within 15 seconds")
            error(f"  Server: {server_url}")
            info("")
            info("Check that:")
            info("  1. The server URL is correct")
            info("  2. Network connectivity exists (try: curl {server_url})")
            info("  3. DNS resolves correctly")
            info("  4. No proxy is required (set HTTP_PROXY/HTTPS_PROXY if needed)")
        elif "name or service not known" in reason.lower() or "nodename" in reason.lower():
            error("DNS resolution failed — cannot resolve server hostname")
            error(f"  Server: {server_url}")
            info("")
            info("Check that:")
            info("  1. The server URL hostname is spelled correctly")
            info("  2. DNS is working (try: nslookup <hostname>)")
        else:
            error(f"Connection error: {reason}")
            error(f"  Server: {server_url}")
        return False

    except Exception as e:
        error(f"Unexpected error: {e}")
        debug(f"Exception type: {type(e).__name__}", verbose)
        return False


# ────────────────────────────────────────────────────────────────────────────
# Lockfile discovery and reading
# ────────────────────────────────────────────────────────────────────────────

def find_lockfiles(root_path, max_depth=MAX_DEPTH, verbose=False):
    """Find lockfiles recursively up to max_depth."""
    found = []
    root = Path(root_path).resolve()

    debug(f"Searching for lockfiles in {root} (max depth: {max_depth})", verbose)

    for lockfile_name in LOCKFILE_NAMES:
        for path in root.rglob(lockfile_name):
            # Respect max depth
            try:
                rel = path.relative_to(root)
                if len(rel.parts) - 1 > max_depth:
                    debug(f"Skipping {rel} (exceeds max depth {max_depth})", verbose)
                    continue
            except ValueError:
                continue

            # Skip symlinks (prevent exfiltration of files outside project)
            if path.is_symlink():
                debug(f"Skipping {rel} (symlink)", verbose)
                continue

            # Skip known non-project directories
            parts_str = str(rel)
            skip = False
            for skip_dir in SKIP_DIRS:
                if skip_dir in parts_str:
                    debug(f"Skipping {rel} (in {skip_dir}/ directory)", verbose)
                    skip = True
                    break
            if skip:
                continue

            # Check file size
            try:
                size = path.stat().st_size
                if size > MAX_FILE_SIZE:
                    warn(f"Skipping {rel} (>{MAX_FILE_SIZE // 1024 // 1024}MB)")
                    continue
                if size == 0:
                    debug(f"Skipping {rel} (empty file)", verbose)
                    continue
            except OSError:
                continue

            found.append(path)

    debug(f"Found {len(found)} lockfile(s)", verbose)
    return found


def read_lockfile(path, root, verbose=False):
    """Read a lockfile and return its metadata."""
    rel = path.relative_to(root)
    project_path = str(rel.parent) if str(rel.parent) != "." else ""

    try:
        content = path.read_text(encoding="utf-8", errors="replace")
        debug(f"Read {rel}: {len(content)} bytes", verbose)
    except (OSError, PermissionError) as e:
        error(f"Cannot read {rel}: {e}")
        return None

    return {
        "filename": path.name,
        "project_path": project_path,
        "content": content,
    }


# ────────────────────────────────────────────────────────────────────────────
# API communication
# ────────────────────────────────────────────────────────────────────────────

def send_scan(server_url, api_key, lockfiles, project_name, hostname, verbose=False):
    """Send lockfiles to the SentriKat server for scanning."""
    url = f"{server_url.rstrip('/')}/api/agent/dependency-scan"

    # Warn if sending lockfile data over unencrypted HTTP
    if server_url.startswith("http://") and not server_url.startswith("http://localhost") and not server_url.startswith("http://127."):
        warn("Sending data over unencrypted HTTP! Use https:// for production.")
        warn("Lockfile contents may contain sensitive dependency information.")

    payload = {
        "hostname": hostname,
        "agent_id": f"scan-{uuid.uuid4().hex[:12]}",
        "project_name": project_name,
        "lockfiles": lockfiles,
    }

    body = json.dumps(payload).encode("utf-8")

    debug(f"POST {url}", verbose)
    debug(f"Payload size: {len(body)} bytes", verbose)
    debug(f"Lockfiles: {len(lockfiles)}", verbose)
    debug(f"Project: {project_name}, Hostname: {hostname}", verbose)

    req = Request(url, data=body, method="POST")
    req.add_header("Content-Type", "application/json")
    req.add_header("X-Agent-Key", api_key)
    req.add_header("User-Agent", f"SentriKat-Scan/{VERSION} (Python {platform.python_version()})")

    try:
        debug("Sending request (timeout: 300s)...", verbose)
        start_time = time.time()
        with urlopen(req, timeout=300) as resp:
            elapsed = time.time() - start_time
            response_body = resp.read().decode("utf-8")
            debug(f"Response: HTTP {resp.status} ({elapsed:.1f}s)", verbose)
            debug(f"Response size: {len(response_body)} bytes", verbose)
            result = json.loads(response_body)
            debug(f"Scan ID: {result.get('scan_id', 'N/A')}", verbose)
            return result

    except HTTPError as e:
        error_body = e.read().decode("utf-8", errors="replace")
        debug(f"HTTP {e.code} response: {error_body[:500]}", verbose)

        try:
            error_data = json.loads(error_body)
            msg = error_data.get("error", error_body[:200])
        except json.JSONDecodeError:
            msg = error_body[:200]

        if e.code == 401:
            error(f"Authentication failed (HTTP 401)")
            error(f"  The API key is invalid or revoked.")
            info(f"  Run: sentrikat-scan --test  (to diagnose)")
        elif e.code == 413:
            error(f"Request too large (HTTP 413)")
            error(f"  Payload: {len(body) / 1024 / 1024:.1f} MB")
            info(f"  Try scanning a smaller project or fewer lockfiles.")
        elif e.code == 400:
            error(f"Bad request (HTTP 400): {msg}")
        elif e.code >= 500:
            error(f"Server error (HTTP {e.code}): {msg}")
            info(f"  The SentriKat server may be experiencing issues.")
        else:
            error(f"Server error (HTTP {e.code}): {msg}")
        sys.exit(1)

    except URLError as e:
        error(f"Connection error: {e.reason}")
        error(f"  Server: {server_url}")
        info(f"  Run: sentrikat-scan --test  (to diagnose connection issues)")
        sys.exit(1)

    except json.JSONDecodeError as e:
        error(f"Invalid JSON in server response: {e}")
        debug(f"Raw response: {response_body[:500]}", verbose)
        sys.exit(1)


# ────────────────────────────────────────────────────────────────────────────
# Results display
# ────────────────────────────────────────────────────────────────────────────

def print_results(result, fail_on=None, verbose=False):
    """Print scan results and return exit code."""
    summary = result.get("summary", {})
    vulnerable = result.get("vulnerable", [])

    total_deps = summary.get("total_dependencies", 0)
    vuln_pkgs = summary.get("vulnerable_packages", 0)
    total_vulns = summary.get("total_vulnerabilities", 0)
    severity = summary.get("severity", {})
    lockfiles = summary.get("lockfiles_parsed", 0)

    crit = severity.get("critical", 0)
    high = severity.get("high", 0)
    med = severity.get("medium", 0)
    low = severity.get("low", 0)

    print(f"\n{'=' * 60}")
    print(f"  {Color.BOLD}SentriKat Dependency Scan Results{Color.RESET}")
    print(f"{'=' * 60}")
    print(f"  Lockfiles scanned:    {lockfiles}")
    print(f"  Dependencies found:   {total_deps}")
    print(f"  Vulnerable packages:  {vuln_pkgs}")
    print(f"  Total vulnerabilities:{total_vulns}")
    print()

    # Colorized severity counts
    crit_str = f"{Color.RED}{crit}{Color.RESET}" if crit > 0 else str(crit)
    high_str = f"{Color.RED}{high}{Color.RESET}" if high > 0 else str(high)
    med_str = f"{Color.YELLOW}{med}{Color.RESET}" if med > 0 else str(med)
    low_str = str(low)

    print(f"  Critical: {crit_str}")
    print(f"  High:     {high_str}")
    print(f"  Medium:   {med_str}")
    print(f"  Low:      {low_str}")
    print(f"{'=' * 60}")

    if vulnerable:
        print(f"\n  {Color.BOLD}Vulnerable Packages:{Color.RESET}")
        print(f"  {'-' * 56}")
        for pkg in vulnerable:
            direct = f" {Color.CYAN}[direct]{Color.RESET}" if pkg.get("is_direct") else ""
            vuln_count = len(pkg.get("vulnerabilities", []))
            print(f"  {pkg['ecosystem']}/{pkg['name']}@{pkg['version']}{direct} — {vuln_count} vuln(s)")
            for v in pkg.get("vulnerabilities", [])[:5]:
                sev = v.get("severity", "?").upper()
                vid = v.get("id", "?")
                fix = v.get("fixed_versions", [])
                fix_str = f" {Color.GREEN}(fix: {', '.join(fix[:2])}){Color.RESET}" if fix else ""

                if sev in ("CRITICAL", "HIGH"):
                    sev_colored = f"{Color.RED}{sev:8s}{Color.RESET}"
                elif sev == "MEDIUM":
                    sev_colored = f"{Color.YELLOW}{sev:8s}{Color.RESET}"
                else:
                    sev_colored = f"{sev:8s}"

                print(f"    [{sev_colored}] {vid}{fix_str}")
            remaining = len(pkg.get("vulnerabilities", [])) - 5
            if remaining > 0:
                print(f"    ... and {remaining} more")
        print()

    if total_vulns == 0:
        success("No vulnerabilities found!")

    # Determine exit code based on --fail-on
    if fail_on and total_vulns > 0:
        fail_levels = {
            "critical": ["critical"],
            "high": ["critical", "high"],
            "medium": ["critical", "high", "medium"],
            "low": ["critical", "high", "medium", "low"],
        }
        check_levels = fail_levels.get(fail_on, [])
        for level in check_levels:
            if severity.get(level, 0) > 0:
                print(f"  {Color.RED}FAILED: Found {severity[level]} {level} vulnerabilities (--fail-on {fail_on}){Color.RESET}")
                return 1

    return 0


# ────────────────────────────────────────────────────────────────────────────
# Main entry point
# ────────────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        prog="sentrikat-scan",
        description="Scan project dependencies for vulnerabilities via SentriKat",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # First time setup (creates .sentrikat-scan.conf)
  sentrikat-scan --init

  # Test connection to SentriKat server
  sentrikat-scan --test

  # Scan current directory
  sentrikat-scan

  # Scan with explicit server/key
  sentrikat-scan --server https://sentrikat.example.com --key sk_...

  # CI/CD mode (exit non-zero on high/critical vulns)
  sentrikat-scan --fail-on high

  # Environment variables (for CI/CD secrets)
  export SENTRIKAT_SERVER=https://sentrikat.example.com
  export SENTRIKAT_API_KEY=sk_...
  sentrikat-scan

  # Verbose output for debugging
  sentrikat-scan --verbose
""",
    )
    parser.add_argument(
        "--server", "-s",
        default="",
        help="SentriKat server URL (or env: SENTRIKAT_SERVER, or config file)",
    )
    parser.add_argument(
        "--key", "-k",
        default="",
        help="API key (or env: SENTRIKAT_API_KEY, or config file)",
    )
    parser.add_argument(
        "--path", "-p",
        default=".",
        help="Project path to scan (default: current directory)",
    )
    parser.add_argument(
        "--project-name",
        default="",
        help="Project name for identification (default: directory name)",
    )
    parser.add_argument(
        "--fail-on",
        choices=["critical", "high", "medium", "low"],
        default=None,
        help="Exit non-zero if vulnerabilities at this severity or above are found",
    )
    parser.add_argument(
        "--json", "-j",
        action="store_true",
        help="Output raw JSON response",
    )
    parser.add_argument(
        "--depth",
        type=int,
        default=None,
        help=f"Max directory depth to search (default: {MAX_DEPTH})",
    )
    parser.add_argument(
        "--verbose", "--debug",
        action="store_true",
        help="Enable verbose/debug output",
    )
    parser.add_argument(
        "--test",
        action="store_true",
        help="Test connectivity to SentriKat server and exit",
    )
    parser.add_argument(
        "--init",
        action="store_true",
        help="Create config file (.sentrikat-scan.conf) interactively",
    )
    parser.add_argument(
        "--show-config",
        action="store_true",
        help="Show resolved configuration and exit",
    )
    parser.add_argument(
        "--no-color",
        action="store_true",
        help="Disable colored output",
    )
    parser.add_argument(
        "--version", "-v",
        action="version",
        version=f"sentrikat-scan {VERSION}",
    )

    args = parser.parse_args()

    # Disable color if requested or not a terminal
    if args.no_color or _no_color():
        Color.disable()

    # Handle --init early
    if args.init:
        init_config(args.path)
        sys.exit(0)

    # ── Resolve configuration (priority: CLI args > env vars > config file) ──

    scan_path = Path(args.path).resolve()
    if not scan_path.is_dir():
        error(f"{scan_path} is not a directory")
        sys.exit(1)

    # Load config file
    file_config = load_config(scan_path)
    config_source = find_config_file(scan_path)

    if args.verbose and config_source:
        debug(f"Config file: {config_source}", True)
        debug(f"Config values: {list(file_config.keys())}", True)

    # Merge: CLI > env > config file
    server = (
        args.server
        or os.environ.get("SENTRIKAT_SERVER", "")
        or file_config.get("server", "")
    ).strip()

    api_key = (
        args.key
        or os.environ.get("SENTRIKAT_API_KEY", "")
        or file_config.get("key", "")
    ).strip()

    project_name = (
        args.project_name
        or os.environ.get("SENTRIKAT_PROJECT", "")
        or file_config.get("project_name", "")
        or scan_path.name
    ).strip()

    fail_on = args.fail_on or file_config.get("fail_on")
    if fail_on and fail_on not in ("critical", "high", "medium", "low"):
        fail_on = None

    depth = args.depth
    if depth is None:
        depth_str = file_config.get("depth", "")
        if depth_str.isdigit():
            depth = int(depth_str)
        else:
            depth = MAX_DEPTH

    hostname = platform.node() or project_name

    # ── Handle --show-config ──

    if args.show_config:
        print(f"\n{Color.BOLD}SentriKat Scan — Resolved Configuration{Color.RESET}")
        print(f"{'─' * 45}")
        if config_source:
            print(f"  Config file:  {config_source}")
        else:
            print(f"  Config file:  (none found)")
        print(f"  Server:       {server or '(not set)'}")
        print(f"  API key:      {api_key[:8]}...{api_key[-4:]}" if len(api_key) > 12 else f"  API key:      {api_key or '(not set)'}")
        print(f"  Project:      {project_name}")
        print(f"  Hostname:     {hostname}")
        print(f"  Scan path:    {scan_path}")
        print(f"  Max depth:    {depth}")
        print(f"  Fail on:      {fail_on or '(disabled)'}")
        print()

        # Show source for each value
        print(f"  {Color.DIM}Sources:{Color.RESET}")
        for name, val, cli, env_key, cfg_key in [
            ("server", server, args.server, "SENTRIKAT_SERVER", "server"),
            ("key", api_key, args.key, "SENTRIKAT_API_KEY", "key"),
            ("project", project_name, args.project_name, "SENTRIKAT_PROJECT", "project_name"),
        ]:
            if cli:
                src = "command line"
            elif os.environ.get(env_key):
                src = f"env ${env_key}"
            elif file_config.get(cfg_key):
                src = "config file"
            else:
                src = "default"
            print(f"    {name}: {src}")
        print()
        sys.exit(0)

    # ── Validate required settings ──

    if not server:
        error("SentriKat server URL is required")
        info("")
        info("Set it via one of:")
        info("  1. sentrikat-scan --init             (create config file)")
        info("  2. sentrikat-scan --server URL        (command line)")
        info("  3. export SENTRIKAT_SERVER=URL        (environment variable)")
        sys.exit(1)

    if not api_key:
        error("API key is required")
        info("")
        info("Set it via one of:")
        info("  1. sentrikat-scan --init             (create config file)")
        info("  2. sentrikat-scan --key KEY           (command line)")
        info("  3. export SENTRIKAT_API_KEY=KEY       (environment variable)")
        sys.exit(1)

    # ── Handle --test ──

    if args.test:
        print(f"\n{Color.BOLD}SentriKat Scan — Connection Test{Color.RESET}")
        print(f"{'─' * 45}")
        info(f"Server:   {server}")
        info(f"API key:  {api_key[:8]}...{api_key[-4:]}" if len(api_key) > 12 else f"API key:  {api_key}")
        info(f"Project:  {project_name}")
        info(f"Hostname: {hostname}")
        print()

        ok = _test_connection(server, api_key, verbose=args.verbose)
        sys.exit(0 if ok else 1)

    # ── Run scan ──

    if args.verbose:
        debug(f"sentrikat-scan v{VERSION}", True)
        debug(f"Python {platform.python_version()} on {platform.system()} {platform.machine()}", True)
        debug(f"Server: {server}", True)
        debug(f"Project: {project_name}", True)
        debug(f"Scan path: {scan_path}", True)

    # Find lockfiles
    print(f"Scanning {scan_path} for lockfiles...")
    lockfile_paths = find_lockfiles(scan_path, max_depth=depth, verbose=args.verbose)

    if not lockfile_paths:
        warn("No lockfiles found.")
        info("")
        info("Supported lockfiles:")
        for name in LOCKFILE_NAMES:
            info(f"  - {name}")
        info("")
        info("Make sure you're scanning a project directory that contains")
        info("dependency lockfiles. Run from your project root, or use --path.")
        sys.exit(0)

    print(f"Found {len(lockfile_paths)} lockfile(s):")
    lockfiles = []
    for lf_path in lockfile_paths:
        rel = lf_path.relative_to(scan_path)
        size_kb = lf_path.stat().st_size / 1024
        print(f"  {rel} ({size_kb:.0f} KB)")
        entry = read_lockfile(lf_path, scan_path, verbose=args.verbose)
        if entry:
            lockfiles.append(entry)

    if not lockfiles:
        error("No readable lockfiles found.")
        sys.exit(1)

    # Send to server
    total_size = sum(len(lf["content"]) for lf in lockfiles)
    print(f"\nSending {len(lockfiles)} lockfile(s) to {server} ({total_size / 1024:.0f} KB)...")

    result = send_scan(server, api_key, lockfiles, project_name, hostname, verbose=args.verbose)

    if args.json:
        print(json.dumps(result, indent=2))
        sys.exit(0)

    # Print results
    exit_code = print_results(result, fail_on=fail_on, verbose=args.verbose)
    sys.exit(exit_code)


if __name__ == "__main__":
    main()
