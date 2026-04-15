# sentrikat-scan

**Dependency lockfile scanner and CI/CD connector for the SentriKat vulnerability management platform.**

`sentrikat-scan` is a single-file Python CLI (Python 3.7+, zero runtime dependencies) that walks a project tree, finds every dependency lockfile it recognises, and ships the contents to your SentriKat server for vulnerability matching against CISA KEV, NVD, OSV, vendor advisories and EPSS. It is designed to slot into CI/CD pipelines, pre-commit hooks, and developer workstations — anywhere source code lives but no full SentriKat agent is installed.

> **This is a connector, not a standalone scanner.** It requires a SentriKat server (self-hosted or [SentriKat Cloud](https://sentrikat.com)) and a valid agent API key. The scanner uploads lockfile contents; the server does the vulnerability matching and persists results in your tenant dashboard, SBOM exports, compliance reports, and email/webhook alerts.

## Install

```bash
pip install sentrikat-scan
```

Or, if you prefer zero install (copy the single file into your repo):

```bash
curl -O https://app.sentrikat.com/downloads/sentrikat-scan.py
chmod +x sentrikat-scan.py
```

Both entry points run the same code.

## Configure

Either drop a `.sentrikat-scan.conf` next to your project root:

```ini
[sentrikat]
server = https://app.sentrikat.com
api_key = sk_agent_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx
```

…or pass it via environment variables (recommended for CI secrets):

```bash
export SENTRIKAT_SERVER=https://app.sentrikat.com
export SENTRIKAT_API_KEY=sk_agent_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx
```

Generate a bootstrap config file with:

```bash
sentrikat-scan --init
```

## Usage

```bash
# Scan the current directory and print a summary
sentrikat-scan

# Scan a specific path
sentrikat-scan /path/to/project

# Fail the CI build if any CRITICAL or HIGH CVE is found
sentrikat-scan --fail-on high

# Emit JSON (machine-readable) instead of human output
sentrikat-scan --json

# Test connectivity / API key validity
sentrikat-scan --test

# Install a git pre-commit hook that scans before every commit
sentrikat-scan --install-hook pre-commit
```

## Supported lockfile formats

| Ecosystem | Files |
|-----------|-------|
| JavaScript / TypeScript | `package-lock.json`, `yarn.lock`, `pnpm-lock.yaml` |
| Python | `Pipfile.lock`, `poetry.lock`, `requirements.txt`, `pyproject.toml`, `uv.lock` |
| Rust | `Cargo.lock` |
| Go | `go.sum`, `go.mod` |
| Ruby | `Gemfile.lock` |
| PHP | `composer.lock` |
| .NET | `packages.lock.json` |

The scanner recursively walks the project (up to 5 levels deep) and skips the usual suspects (`node_modules`, `.git`, `venv`, `vendor`, `dist`, `build`, `.tox`, `.mypy_cache`, etc.). Each lockfile is capped at 5 MB.

## CI/CD integration

### GitHub Actions

```yaml
- name: SentriKat dependency scan
  env:
    SENTRIKAT_SERVER: ${{ secrets.SENTRIKAT_SERVER }}
    SENTRIKAT_API_KEY: ${{ secrets.SENTRIKAT_API_KEY }}
  run: |
    pip install sentrikat-scan
    sentrikat-scan --fail-on high
```

### GitLab CI

```yaml
sentrikat:
  image: python:3.11-slim
  variables:
    SENTRIKAT_SERVER: https://app.sentrikat.com
  script:
    - pip install sentrikat-scan
    - sentrikat-scan --fail-on critical
```

### Pre-commit hook

```bash
sentrikat-scan --install-hook pre-commit
```

This drops a `pre-commit` hook under `.git/hooks/` that runs the scanner before every commit and blocks it if critical or high CVEs are detected.

## Exit codes

| Code | Meaning |
|------|---------|
| `0`  | Scan completed. No vulnerabilities, or none at or above `--fail-on` severity. |
| `1`  | Scan completed. Vulnerabilities found at or above `--fail-on` severity. |
| `2`  | Usage error (bad flags, missing config, etc.). |
| `3`  | Network / server error (server unreachable, 5xx, timeout). |
| `4`  | Authentication error (invalid API key, 401). |

## Privacy & data

`sentrikat-scan` uploads **lockfile contents** (package names + versions + sometimes integrity hashes) to your SentriKat server. It does **not** upload source code, environment variables, git history, secrets, or any file outside the recognised lockfile set. If you send data over unencrypted HTTP, the scanner warns before transmitting.

## License

This client CLI is released under the **MIT license**. See [LICENSE](./LICENSE) for the full text. Note that the SentriKat server itself is commercially licensed — this package is an open-source client to a commercial backend, like `stripe-cli`, `datadog-ci`, or `sentry-cli`.

## Links

- [SentriKat homepage](https://sentrikat.com)
- [Connector docs](https://sentrikat.com/docs/connectors/sentrikat-scan)
- [Issue tracker](https://github.com/sbr0nch/SentriKat/issues)
