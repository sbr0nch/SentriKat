# sentrikat-scan

Lightweight dependency vulnerability scanner for [SentriKat](https://github.com/sbr0nch/SentriKat).

Scans your project's lockfiles and reports vulnerabilities via your SentriKat server. Zero dependencies — uses only Python standard library (3.7+).

## Install

```bash
# Option 1: pip install (recommended)
pip install sentrikat-scan

# Option 2: Download the script directly
curl -O https://your-sentrikat-server/downloads/sentrikat-scan.py
chmod +x sentrikat-scan.py

# Option 3: Copy into your project
cp sentrikat-scan.py /path/to/your/project/
```

## Quick Start

```bash
# 1. Create config file (interactive — saves server URL and API key)
sentrikat-scan --init

# 2. Test connection
sentrikat-scan --test

# 3. Scan!
sentrikat-scan
```

## Usage

```bash
# Scan current directory
sentrikat-scan

# Scan specific path
sentrikat-scan --path /path/to/project

# CI/CD mode — exit non-zero on critical/high vulnerabilities
sentrikat-scan --fail-on high

# Use environment variables (for CI secrets)
export SENTRIKAT_SERVER=https://sentrikat.example.com
export SENTRIKAT_API_KEY=sk_...
sentrikat-scan

# Verbose output for debugging
sentrikat-scan --verbose

# Show resolved config (helpful for troubleshooting)
sentrikat-scan --show-config

# JSON output
sentrikat-scan --json
```

## Configuration

Settings are resolved in this order (first wins):

1. Command-line arguments (`--server`, `--key`)
2. Environment variables (`SENTRIKAT_SERVER`, `SENTRIKAT_API_KEY`)
3. Config file (`.sentrikat-scan.conf`)

### Config File

Run `sentrikat-scan --init` to create a `.sentrikat-scan.conf` in your project root:

```ini
[sentrikat]
server = https://sentrikat.example.com
key = sk_your_api_key_here
project_name = my-project
fail_on = high
```

The config file contains your API key — add it to `.gitignore`!

## CI/CD Integration

### GitHub Actions

```yaml
- name: Scan dependencies
  env:
    SENTRIKAT_SERVER: ${{ secrets.SENTRIKAT_SERVER }}
    SENTRIKAT_API_KEY: ${{ secrets.SENTRIKAT_API_KEY }}
  run: |
    pip install sentrikat-scan
    sentrikat-scan --fail-on high
```

### GitLab CI

```yaml
dependency-scan:
  script:
    - pip install sentrikat-scan
    - sentrikat-scan --fail-on high
  variables:
    SENTRIKAT_SERVER: $SENTRIKAT_SERVER
    SENTRIKAT_API_KEY: $SENTRIKAT_API_KEY
```

### Jenkins

```groovy
stage('Dependency Scan') {
    sh '''
        pip install sentrikat-scan
        sentrikat-scan --fail-on high
    '''
}
```

## Supported Lockfiles

| Ecosystem | Lockfile |
|-----------|----------|
| Node.js | `package-lock.json`, `yarn.lock`, `pnpm-lock.yaml` |
| Python | `Pipfile.lock`, `poetry.lock` |
| Rust | `Cargo.lock` |
| Go | `go.sum`, `go.mod` |
| Ruby | `Gemfile.lock` |
| PHP | `composer.lock` |
| .NET | `packages.lock.json` |

## How It Works

1. Finds lockfiles in your project directory
2. Sends them to your SentriKat server
3. Server parses dependencies and queries [OSV.dev](https://osv.dev) for known vulnerabilities
4. Results are displayed in your terminal and stored in SentriKat's dashboard

The scanner uses ecosystem-native vulnerability matching (not CPE guessing), so results are precise and trustworthy.
