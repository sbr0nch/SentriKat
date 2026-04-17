#!/usr/bin/env python3
"""Audit inline <script>/<style> blocks missing the CSP nonce (M-7).

Run from the repo root:

    python scripts/audit_inline_scripts.py

Reports every inline ``<script>`` or ``<style>`` block in
``app/templates/`` that does NOT carry ``nonce="{{ csp_nonce }}"``.
Exits with status 1 if any are found, so it can be wired into CI to
prevent regressions during the M-7 migration.

Once every inline block carries a nonce, the audit comes back clean and
``'unsafe-inline'`` can be removed from the CSP in ``app/__init__.py``.
"""
from __future__ import annotations

import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
TEMPLATES = ROOT / 'app' / 'templates'

# Match opening <script> or <style> tags, but not <script src=...> (external).
INLINE_TAG = re.compile(
    r'<(script|style)\b(?P<attrs>[^>]*)>',
    re.IGNORECASE,
)
HAS_SRC = re.compile(r'\bsrc\s*=', re.IGNORECASE)
HAS_NONCE = re.compile(r'\bnonce\s*=', re.IGNORECASE)


EVENT_HANDLER = re.compile(
    r'\bon(?:click|submit|change|load|input|keyup|keydown|keypress|mouseover|mouseout|focus|blur|error|toggle)\s*=',
    re.IGNORECASE,
)


def audit() -> int:
    inline_offenders: list[tuple[Path, int, str]] = []
    handler_count = 0
    handler_files: dict[Path, int] = {}

    for template in sorted(TEMPLATES.rglob('*.html')):
        text = template.read_text(encoding='utf-8', errors='replace')
        for line_no, line in enumerate(text.splitlines(), start=1):
            for match in INLINE_TAG.finditer(line):
                tag = match.group(1).lower()
                attrs = match.group('attrs')
                if tag == 'script' and HAS_SRC.search(attrs):
                    continue
                if HAS_NONCE.search(attrs):
                    continue
                inline_offenders.append((template.relative_to(ROOT), line_no, line.strip()))

            for _ in EVENT_HANDLER.finditer(line):
                handler_count += 1
                handler_files[template.relative_to(ROOT)] = (
                    handler_files.get(template.relative_to(ROOT), 0) + 1
                )

    rc = 0

    if inline_offenders:
        print(f"FAIL: {len(inline_offenders)} inline <script>/<style> block(s) missing nonce:")
        for path, line_no, snippet in inline_offenders:
            print(f"  {path}:{line_no}: {snippet[:120]}")
        print()
        print("Add nonce=\"{{ csp_nonce }}\" to each, then re-run.")
        rc = 1
    else:
        print(f"OK: every inline <script>/<style> in {TEMPLATES} carries a nonce.")

    if handler_count:
        print()
        print(
            f"WARN: {handler_count} inline event handlers (onclick=, onsubmit=, ...) "
            "found across {} files.".format(len(handler_files))
        )
        for path, count in sorted(handler_files.items(), key=lambda x: -x[1]):
            print(f"  {count:>4}  {path}")
        print()
        print(
            "Inline event handlers block CSP from removing 'unsafe-inline'. "
            "Convert each to addEventListener inside a <script nonce> block "
            "before tightening the CSP in app/__init__.py."
        )
        # Don't fail CI on these yet — too many to fix at once. Just track.
    else:
        print()
        print("OK: no inline event handlers — 'unsafe-inline' can be removed from CSP.")

    return rc


if __name__ == '__main__':
    sys.exit(audit())
