#!/usr/bin/env python3
"""
sentrikat-scan — Lightweight dependency vulnerability scanner for SentriKat.

Scans lockfiles in the current project and reports vulnerabilities to your
SentriKat server via the dependency-scan API. Designed for:

  - CI/CD pipelines (GitHub Actions, GitLab CI, Jenkins, etc.)
  - Developer workstations (manual or pre-commit hook)
  - Any environment where code lives but no SentriKat agent is installed

Usage:
    # Scan current directory
    sentrikat-scan --server https://sentrikat.example.com --key YOUR_API_KEY

    # Scan specific path
    sentrikat-scan --server https://... --key ... --path /path/to/project

    # CI/CD mode (non-zero exit on critical/high vulns)
    sentrikat-scan --server https://... --key ... --fail-on high

    # Environment variables (for CI secrets)
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
import sys
import uuid
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


def find_lockfiles(root_path, max_depth=MAX_DEPTH):
    """Find lockfiles recursively up to max_depth."""
    found = []
    root = Path(root_path).resolve()

    for lockfile_name in LOCKFILE_NAMES:
        for path in root.rglob(lockfile_name):
            # Respect max depth
            try:
                rel = path.relative_to(root)
                if len(rel.parts) - 1 > max_depth:
                    continue
            except ValueError:
                continue

            # Skip node_modules, .git, vendor directories
            parts_str = str(rel)
            if any(skip in parts_str for skip in [
                "node_modules", ".git", "__pycache__", ".tox",
                "venv", ".venv", "env", ".env",
            ]):
                continue

            # Check file size
            try:
                if path.stat().st_size > MAX_FILE_SIZE:
                    print(f"  [skip] {rel} (>{MAX_FILE_SIZE // 1024 // 1024}MB)", file=sys.stderr)
                    continue
                if path.stat().st_size == 0:
                    continue
            except OSError:
                continue

            found.append(path)

    return found


def read_lockfile(path, root):
    """Read a lockfile and return its metadata."""
    rel = path.relative_to(root)
    project_path = str(rel.parent) if str(rel.parent) != "." else ""

    try:
        content = path.read_text(encoding="utf-8", errors="replace")
    except (OSError, PermissionError) as e:
        print(f"  [error] Cannot read {rel}: {e}", file=sys.stderr)
        return None

    return {
        "filename": path.name,
        "project_path": project_path,
        "content": content,
    }


def send_scan(server_url, api_key, lockfiles, project_name, hostname):
    """Send lockfiles to the SentriKat server for scanning."""
    url = f"{server_url.rstrip('/')}/api/agent/dependency-scan"

    payload = {
        "hostname": hostname,
        "agent_id": f"scan-{uuid.uuid4().hex[:12]}",
        "project_name": project_name,
        "lockfiles": lockfiles,
    }

    body = json.dumps(payload).encode("utf-8")

    req = Request(url, data=body, method="POST")
    req.add_header("Content-Type", "application/json")
    req.add_header("X-Agent-Key", api_key)
    req.add_header("User-Agent", f"SentriKat-Scan/{VERSION} (Python {platform.python_version()})")

    try:
        with urlopen(req, timeout=300) as resp:
            return json.loads(resp.read().decode("utf-8"))
    except HTTPError as e:
        error_body = e.read().decode("utf-8", errors="replace")
        try:
            error_data = json.loads(error_body)
            msg = error_data.get("error", error_body[:200])
        except json.JSONDecodeError:
            msg = error_body[:200]
        print(f"\n  Server error (HTTP {e.code}): {msg}", file=sys.stderr)
        sys.exit(1)
    except URLError as e:
        print(f"\n  Connection error: {e.reason}", file=sys.stderr)
        print(f"  Server: {server_url}", file=sys.stderr)
        sys.exit(1)


def print_results(result, fail_on=None):
    """Print scan results and return exit code."""
    summary = result.get("summary", {})
    vulnerable = result.get("vulnerable", [])

    total_deps = summary.get("total_dependencies", 0)
    vuln_pkgs = summary.get("vulnerable_packages", 0)
    total_vulns = summary.get("total_vulnerabilities", 0)
    severity = summary.get("severity", {})
    lockfiles = summary.get("lockfiles_parsed", 0)

    print(f"\n{'=' * 60}")
    print(f"  SentriKat Dependency Scan Results")
    print(f"{'=' * 60}")
    print(f"  Lockfiles scanned:    {lockfiles}")
    print(f"  Dependencies found:   {total_deps}")
    print(f"  Vulnerable packages:  {vuln_pkgs}")
    print(f"  Total vulnerabilities:{total_vulns}")
    print(f"")
    print(f"  Critical: {severity.get('critical', 0)}")
    print(f"  High:     {severity.get('high', 0)}")
    print(f"  Medium:   {severity.get('medium', 0)}")
    print(f"  Low:      {severity.get('low', 0)}")
    print(f"{'=' * 60}")

    if vulnerable:
        print(f"\n  Vulnerable Packages:")
        print(f"  {'-' * 56}")
        for pkg in vulnerable:
            direct = " [direct]" if pkg.get("is_direct") else ""
            vuln_count = len(pkg.get("vulnerabilities", []))
            print(f"  {pkg['ecosystem']}/{pkg['name']}@{pkg['version']}{direct} — {vuln_count} vuln(s)")
            for v in pkg.get("vulnerabilities", [])[:5]:
                sev = v.get("severity", "?")
                vid = v.get("id", "?")
                fix = v.get("fixed_versions", [])
                fix_str = f" (fix: {', '.join(fix[:2])})" if fix else ""
                print(f"    [{sev:8s}] {vid}{fix_str}")
            if len(pkg.get("vulnerabilities", [])) > 5:
                print(f"    ... and {len(pkg['vulnerabilities']) - 5} more")
        print()

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
                print(f"  FAILED: Found {severity[level]} {level} vulnerabilities (--fail-on {fail_on})")
                return 1
    return 0


def main():
    parser = argparse.ArgumentParser(
        prog="sentrikat-scan",
        description="Scan project dependencies for vulnerabilities via SentriKat",
    )
    parser.add_argument(
        "--server", "-s",
        default=os.environ.get("SENTRIKAT_SERVER", ""),
        help="SentriKat server URL (or set SENTRIKAT_SERVER env var)",
    )
    parser.add_argument(
        "--key", "-k",
        default=os.environ.get("SENTRIKAT_API_KEY", ""),
        help="API key (or set SENTRIKAT_API_KEY env var)",
    )
    parser.add_argument(
        "--path", "-p",
        default=".",
        help="Project path to scan (default: current directory)",
    )
    parser.add_argument(
        "--project-name",
        default=os.environ.get("SENTRIKAT_PROJECT", ""),
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
        default=MAX_DEPTH,
        help=f"Max directory depth to search (default: {MAX_DEPTH})",
    )
    parser.add_argument(
        "--version", "-v",
        action="version",
        version=f"sentrikat-scan {VERSION}",
    )

    args = parser.parse_args()

    if not args.server:
        print("Error: --server or SENTRIKAT_SERVER environment variable required", file=sys.stderr)
        sys.exit(1)
    if not args.key:
        print("Error: --key or SENTRIKAT_API_KEY environment variable required", file=sys.stderr)
        sys.exit(1)

    scan_path = Path(args.path).resolve()
    if not scan_path.is_dir():
        print(f"Error: {scan_path} is not a directory", file=sys.stderr)
        sys.exit(1)

    project_name = args.project_name or scan_path.name
    hostname = platform.node() or project_name

    # Find lockfiles
    print(f"Scanning {scan_path} for lockfiles...")
    lockfile_paths = find_lockfiles(scan_path, max_depth=args.depth)

    if not lockfile_paths:
        print("No lockfiles found. Supported:", file=sys.stderr)
        for name in LOCKFILE_NAMES:
            print(f"  - {name}", file=sys.stderr)
        sys.exit(0)

    print(f"Found {len(lockfile_paths)} lockfile(s):")
    lockfiles = []
    for lf_path in lockfile_paths:
        rel = lf_path.relative_to(scan_path)
        print(f"  {rel}")
        entry = read_lockfile(lf_path, scan_path)
        if entry:
            lockfiles.append(entry)

    if not lockfiles:
        print("No readable lockfiles found.", file=sys.stderr)
        sys.exit(0)

    # Send to server
    print(f"\nSending {len(lockfiles)} lockfile(s) to {args.server}...")
    result = send_scan(args.server, args.key, lockfiles, project_name, hostname)

    if args.json:
        print(json.dumps(result, indent=2))
        sys.exit(0)

    # Print results
    exit_code = print_results(result, fail_on=args.fail_on)
    sys.exit(exit_code)


if __name__ == "__main__":
    main()
