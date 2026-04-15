#!/usr/bin/env bash
#
# Build the sentrikat-scan PyPI distribution.
#
# The source of truth for the scanner is scripts/sentrikat-scan.py in the
# main SentriKat repo. That file is also served by the Flask app via the
# /downloads/sentrikat-scan.py endpoint for curl-install, so we do not
# move it. Instead this script copies it into the packaging dir as
# sentrikat_scan.py (Python module names can't contain dashes), runs
# `python -m build`, and drops the .whl + .tar.gz into dist/.
#
# The copied sentrikat_scan.py and the dist/ + build/ artifacts are
# gitignored — the repo never holds two divergent copies of the code.
#
# Usage:
#   packaging/sentrikat-scan/build.sh          # build with current pyproject version
#   packaging/sentrikat-scan/build.sh --test   # build + install into a venv + smoke test
#
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$HERE/../.." && pwd)"
SCRIPT_SRC="$REPO_ROOT/scripts/sentrikat-scan.py"

if [[ ! -f "$SCRIPT_SRC" ]]; then
    echo "ERROR: source script not found at $SCRIPT_SRC" >&2
    exit 1
fi

echo "==> Copying $SCRIPT_SRC → $HERE/sentrikat_scan.py"
cp "$SCRIPT_SRC" "$HERE/sentrikat_scan.py"

echo "==> Cleaning previous build artifacts"
rm -rf "$HERE/dist" "$HERE/build" "$HERE"/*.egg-info

echo "==> Building sdist + wheel"
cd "$HERE"
python -m build

echo ""
echo "==> Build complete. Artifacts:"
ls -la "$HERE/dist/"

if [[ "${1:-}" == "--test" ]]; then
    echo ""
    echo "==> Smoke test: install wheel into a fresh venv and run --help"
    TMPVENV="$(mktemp -d)/venv"
    python -m venv "$TMPVENV"
    "$TMPVENV/bin/pip" install --quiet "$HERE"/dist/*.whl
    "$TMPVENV/bin/sentrikat-scan" --help | head -20
    echo ""
    echo "==> Smoke test OK: the 'sentrikat-scan' entry point runs."
    rm -rf "$(dirname "$TMPVENV")"
fi

echo ""
echo "==> Done. To publish manually (not recommended — use the GitHub Actions"
echo "    release workflow instead):"
echo "      python -m twine upload $HERE/dist/*"
