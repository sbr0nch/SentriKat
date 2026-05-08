# Contributing to SentriKat

Thanks for your interest. This file is the entry point for external contributors and internal devs joining the project.

## Project structure

- **Code**: `app/` (Flask backend), `agents/` (Win/Linux/macOS agents), `tests/`, `migrations/` (alembic).
- **Documentation**: see [`docs/README.md`](./docs/README.md) for the audience-based index.
- **Cross-repo**: see [`docs/contracts/CROSS-REPO-CONTRACTS.md`](./docs/contracts/CROSS-REPO-CONTRACTS.md) for the API surface between this repo and `sentrikat-web/license-server`.

## Branch policy

- `main` — protected; merges via PR only.
- `claude/*` — Claude session branches; review + merge via PR by maintainers.
- Other feature branches — open a PR against `main`.

## Commit message convention

Format follows the imperative mood:

```
<type>(<scope>): <subject>

<body — what + why, not how>

<footer with cross-refs, claude session URL, etc.>
```

Types: `feat`, `fix`, `docs`, `test`, `refactor`, `chore`, `feat+docs`, `fix+test`. Scope is module-level (`auth`, `provision`, `cisa-sync`, etc.).

Example:

```
fix(provision): /hard-delete NotNullViolation — no_autoflush + explicit DELETE on non-cascade tables

Cross-team bug found by sentrikat-web during admin portal hard-delete journey...
```

## Testing

```bash
pip install -r requirements.txt
python -m pytest tests/ -v
```

Tests are organized by topic (`tests/test_csrf_wiring.py`, `tests/test_parser_resilience.py`, etc.). When fixing a bug, **add a regression test** even if just a snapshot/source-inspection style — the bug must not silently come back.

## Documentation

- Customer-facing docs (`docs/customer/`) are public-readable and should stay polished.
- Internal docs (`docs/business/`, audits, handoffs) are confidential.
- Architecture / contracts / operations docs are technical reference — keep them current.

When making non-trivial changes:

1. Update the relevant doc.
2. If you add/change a cross-repo API, update `docs/contracts/CROSS-REPO-CONTRACTS.md` AND notify the sentrikat-web team.
3. Bump `CHANGELOG.md` `[Unreleased]` section.

## Issue reports

- Security issues: see [`SECURITY.md`](./SECURITY.md). Do **not** open public issues for security findings.
- Bug reports: GitHub Issues with reproduction steps, environment (on-prem/SaaS), version, log excerpt.
- Feature requests: GitHub Issues with use-case explanation.

## Code style

- Python: PEP 8, max line length 100. `black .` is the canonical formatter (not yet enforced in CI but applied to new code).
- HTML/JS templates: 4-space indent, semicolons in JS.
- SQL: lowercase keywords in raw queries (we use SQLAlchemy ORM mostly).
- Comments: explain **why** non-obvious, not **what**. Don't write planning/decision documents in comments.

## License

See [`LICENSE.md`](./LICENSE.md). Contributions are accepted under the project's existing license.

## Questions

- Internal: Slack `#sentrikat-dev` (or whatever the team channel is).
- External: open a GitHub Discussion or Issue.
