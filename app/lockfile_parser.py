"""
Lock file parser for extracting exact dependency trees.

Parses lock files from various package managers to extract precise
package name + version pairs. Lock files provide the ACTUAL installed
versions (not ranges from manifests), including transitive dependencies.

Supported formats:
- npm: package-lock.json, yarn.lock, pnpm-lock.yaml
- Python: Pipfile.lock, poetry.lock, requirements.txt (pinned)
- Rust: Cargo.lock
- Go: go.sum, go.mod
- Ruby: Gemfile.lock
- PHP: composer.lock
- Java/Kotlin: (via SBOM — lock files are Gradle/Maven specific)
- .NET: packages.lock.json
"""

import json
import re
import logging

logger = logging.getLogger(__name__)

# OSV ecosystem names (must match https://osv.dev/docs/#section/Ecosystem)
ECOSYSTEM_NPM = 'npm'
ECOSYSTEM_PYPI = 'PyPI'
ECOSYSTEM_CARGO = 'crates.io'
ECOSYSTEM_GO = 'Go'
ECOSYSTEM_RUBYGEMS = 'RubyGems'
ECOSYSTEM_PACKAGIST = 'Packagist'
ECOSYSTEM_MAVEN = 'Maven'
ECOSYSTEM_NUGET = 'NuGet'

# Maximum lock file size we'll parse (10 MB)
MAX_LOCKFILE_SIZE = 10 * 1024 * 1024

# Maximum dependencies per lock file (prevent memory exhaustion)
MAX_DEPS_PER_LOCKFILE = 10000


class LockfileDependency:
    """A single dependency extracted from a lock file."""

    __slots__ = ('name', 'version', 'ecosystem', 'is_direct', 'purl')

    def __init__(self, name, version, ecosystem, is_direct=False):
        self.name = name
        self.version = version
        self.ecosystem = ecosystem
        self.is_direct = is_direct
        self.purl = self._build_purl()

    def _build_purl(self):
        """Build Package URL (PURL) for this dependency."""
        purl_type_map = {
            ECOSYSTEM_NPM: 'npm',
            ECOSYSTEM_PYPI: 'pypi',
            ECOSYSTEM_CARGO: 'cargo',
            ECOSYSTEM_GO: 'golang',
            ECOSYSTEM_RUBYGEMS: 'gem',
            ECOSYSTEM_PACKAGIST: 'composer',
            ECOSYSTEM_MAVEN: 'maven',
            ECOSYSTEM_NUGET: 'nuget',
        }
        purl_type = purl_type_map.get(self.ecosystem)
        if not purl_type:
            return None

        # Handle scoped npm packages (@scope/name)
        if purl_type == 'npm' and '/' in self.name:
            scope, pkg = self.name.split('/', 1)
            scope = scope.lstrip('@')
            return f"pkg:{purl_type}/{scope}/{pkg}@{self.version}"

        # Handle Go modules (contain /)
        if purl_type == 'golang' and '/' in self.name:
            return f"pkg:{purl_type}/{self.name}@{self.version}"

        # Handle Packagist (vendor/package)
        if purl_type == 'composer' and '/' in self.name:
            return f"pkg:{purl_type}/{self.name}@{self.version}"

        # Handle Maven (group:artifact)
        if purl_type == 'maven' and ':' in self.name:
            group, artifact = self.name.split(':', 1)
            return f"pkg:{purl_type}/{group}/{artifact}@{self.version}"

        return f"pkg:{purl_type}/{self.name}@{self.version}"

    def to_dict(self):
        return {
            'name': self.name,
            'version': self.version,
            'ecosystem': self.ecosystem,
            'is_direct': self.is_direct,
            'purl': self.purl,
        }


def detect_lockfile_type(filename):
    """Detect lock file type from filename."""
    name = filename.rsplit('/', 1)[-1] if '/' in filename else filename
    name_lower = name.lower()

    mapping = {
        'package-lock.json': 'npm',
        'yarn.lock': 'yarn',
        'pnpm-lock.yaml': 'pnpm',
        'pipfile.lock': 'pipfile',
        'poetry.lock': 'poetry',
        'cargo.lock': 'cargo',
        'go.sum': 'gosum',
        'go.mod': 'gomod',
        'gemfile.lock': 'gem',
        'composer.lock': 'composer',
        'packages.lock.json': 'nuget',
    }

    return mapping.get(name_lower)


def parse_lockfile(filename, content):
    """
    Parse a lock file and return a list of LockfileDependency objects.

    Args:
        filename: The lock file name (used to detect type)
        content: The raw file content as a string

    Returns:
        list[LockfileDependency] or None if parsing fails
    """
    if not content or len(content) > MAX_LOCKFILE_SIZE:
        logger.warning(f"Lock file too large or empty: {filename} ({len(content) if content else 0} bytes)")
        return None

    lockfile_type = detect_lockfile_type(filename)
    if not lockfile_type:
        logger.warning(f"Unknown lock file type: {filename}")
        return None

    parser_map = {
        'npm': _parse_package_lock_json,
        'yarn': _parse_yarn_lock,
        'pnpm': _parse_pnpm_lock,
        'pipfile': _parse_pipfile_lock,
        'poetry': _parse_poetry_lock,
        'cargo': _parse_cargo_lock,
        'gosum': _parse_go_sum,
        'gomod': _parse_go_mod,
        'gem': _parse_gemfile_lock,
        'composer': _parse_composer_lock,
        'nuget': _parse_nuget_packages_lock,
    }

    parser = parser_map.get(lockfile_type)
    if not parser:
        return None

    try:
        deps = parser(content)
        if deps and len(deps) > MAX_DEPS_PER_LOCKFILE:
            logger.warning(f"Truncating {filename}: {len(deps)} deps exceeds limit of {MAX_DEPS_PER_LOCKFILE}")
            deps = deps[:MAX_DEPS_PER_LOCKFILE]
        return deps
    except Exception as e:
        logger.error(f"Failed to parse {filename}: {e}")
        return None


# =============================================================================
# npm: package-lock.json (v2/v3 format)
# =============================================================================

def _parse_package_lock_json(content):
    """
    Parse npm package-lock.json (lockfileVersion 2 or 3).

    v2/v3 use the 'packages' key with a flat map of node_modules paths.
    v1 uses the 'dependencies' key with nested structure.
    """
    try:
        data = json.loads(content)
    except json.JSONDecodeError as e:
        logger.error(f"Invalid JSON in package-lock.json: {e}")
        return None

    deps = []

    # v2/v3 format: packages key (preferred)
    packages = data.get('packages', {})
    if packages:
        # Read root package.json deps to mark direct dependencies
        root_pkg = packages.get('', {})
        direct_names = set()
        for dep_key in ('dependencies', 'devDependencies', 'optionalDependencies'):
            direct_names.update((root_pkg.get(dep_key) or {}).keys())

        for path, pkg_info in packages.items():
            if not path:  # Skip root entry
                continue
            version = pkg_info.get('version', '')
            if not version:
                continue

            # Extract package name from path: node_modules/@scope/name -> @scope/name
            name = path.split('node_modules/')[-1] if 'node_modules/' in path else path
            if not name:
                continue

            is_direct = name in direct_names
            deps.append(LockfileDependency(name, version, ECOSYSTEM_NPM, is_direct))
        return deps

    # v1 fallback: dependencies key (nested)
    dependencies = data.get('dependencies', {})
    if dependencies:
        _parse_npm_v1_deps(dependencies, deps, is_direct=True)
        return deps

    return deps


def _parse_npm_v1_deps(deps_dict, result, is_direct=False, _depth=0):
    """Recursively parse npm v1 lock file dependencies."""
    if _depth > 50:  # Prevent stack overflow from crafted lockfiles
        return
    for name, info in deps_dict.items():
        version = info.get('version', '')
        if version:
            result.append(LockfileDependency(name, version, ECOSYSTEM_NPM, is_direct))
        # Recurse into sub-dependencies
        sub_deps = info.get('dependencies', {})
        if sub_deps:
            _parse_npm_v1_deps(sub_deps, result, is_direct=False, _depth=_depth + 1)


# =============================================================================
# Yarn: yarn.lock (v1 classic format)
# =============================================================================

def _parse_yarn_lock(content):
    """
    Parse yarn.lock v1 (classic) format.

    Format:
        package-name@^1.0.0:
          version "1.2.3"
          resolved "https://..."
          ...
    """
    deps = []
    seen = set()  # Deduplicate (same package can appear with multiple version ranges)

    current_name = None
    for line in content.split('\n'):
        stripped = line.strip()

        # Skip comments and empty lines
        if not stripped or stripped.startswith('#'):
            current_name = None
            continue

        # Package header line: "name@version-range, name@other-range:"
        if not line.startswith(' ') and not line.startswith('\t') and stripped.endswith(':'):
            # Extract package name from first specifier
            spec = stripped.rstrip(':').split(',')[0].strip().strip('"')
            # Handle scoped packages: @scope/name@version
            if spec.startswith('@'):
                at_idx = spec.index('@', 1)
                current_name = spec[:at_idx]
            else:
                at_idx = spec.index('@') if '@' in spec else -1
                current_name = spec[:at_idx] if at_idx > 0 else spec
            continue

        # Version line inside a package block
        if current_name and stripped.startswith('version '):
            version = stripped.split('"')[1] if '"' in stripped else stripped.split()[-1]
            key = (current_name, version)
            if key not in seen:
                seen.add(key)
                deps.append(LockfileDependency(current_name, version, ECOSYSTEM_NPM))
            current_name = None

    return deps


# =============================================================================
# pnpm: pnpm-lock.yaml
# =============================================================================

def _parse_pnpm_lock(content):
    """
    Parse pnpm-lock.yaml.

    Uses simple line parsing instead of full YAML to avoid PyYAML dependency
    issues with large files. pnpm-lock v6+ uses the 'packages' key with
    entries like:
        /@scope/name@version:
        /name@version:
    """
    deps = []
    seen = set()
    in_packages = False

    for line in content.split('\n'):
        stripped = line.strip()

        if stripped == 'packages:':
            in_packages = True
            continue

        if in_packages:
            # New top-level key means we left the packages section
            if not line.startswith(' ') and not line.startswith('\t') and stripped and not stripped.startswith('#'):
                if not stripped.startswith('/') and not stripped.startswith("'"):
                    in_packages = False
                    continue

            # Package entry: /name@version: or /@scope/name@version:
            # Also handles quoted format: '/@scope/name@version':
            match = re.match(r"^\s+['\"]?/?(@?[^@'\"]+)@([^:'\"(]+)", stripped)
            if match:
                name = match.group(1).rstrip('/')
                version = match.group(2).strip()
                if name and version and (name, version) not in seen:
                    seen.add((name, version))
                    deps.append(LockfileDependency(name, version, ECOSYSTEM_NPM))

    return deps


# =============================================================================
# Python: Pipfile.lock
# =============================================================================

def _parse_pipfile_lock(content):
    """
    Parse Pipfile.lock (JSON format).

    Structure:
    {
        "default": {
            "package-name": { "version": "==1.2.3", ... },
            ...
        },
        "develop": { ... }
    }
    """
    try:
        data = json.loads(content)
    except json.JSONDecodeError as e:
        logger.error(f"Invalid JSON in Pipfile.lock: {e}")
        return None

    deps = []

    for section in ('default', 'develop'):
        packages = data.get(section, {})
        for name, info in packages.items():
            version = info.get('version', '')
            # Strip version specifier prefix (==, >=, etc.)
            version = re.sub(r'^[=<>!~]+', '', version)
            if not version:
                continue
            is_direct = section == 'default'
            deps.append(LockfileDependency(name, version, ECOSYSTEM_PYPI, is_direct))

    return deps


# =============================================================================
# Python: poetry.lock (TOML-like format)
# =============================================================================

def _parse_poetry_lock(content):
    """
    Parse poetry.lock (TOML format).

    We use simple line parsing to avoid requiring a TOML library.
    Structure:
        [[package]]
        name = "package-name"
        version = "1.2.3"
        ...
    """
    deps = []
    current_name = None
    current_version = None

    for line in content.split('\n'):
        stripped = line.strip()

        if stripped == '[[package]]':
            # Save previous package
            if current_name and current_version:
                deps.append(LockfileDependency(current_name, current_version, ECOSYSTEM_PYPI))
            current_name = None
            current_version = None
            continue

        if stripped.startswith('name = '):
            current_name = stripped.split('=', 1)[1].strip().strip('"').strip("'")
        elif stripped.startswith('version = '):
            current_version = stripped.split('=', 1)[1].strip().strip('"').strip("'")

    # Don't forget the last package
    if current_name and current_version:
        deps.append(LockfileDependency(current_name, current_version, ECOSYSTEM_PYPI))

    return deps


# =============================================================================
# Rust: Cargo.lock (TOML-like format)
# =============================================================================

def _parse_cargo_lock(content):
    """
    Parse Cargo.lock.

    Structure:
        [[package]]
        name = "package-name"
        version = "1.2.3"
        source = "registry+https://github.com/rust-lang/crates.io-index"
        ...
    """
    deps = []
    current_name = None
    current_version = None
    current_source = None

    for line in content.split('\n'):
        stripped = line.strip()

        if stripped == '[[package]]':
            if current_name and current_version:
                # Only include crates.io packages (not path/git deps)
                if not current_source or 'crates.io' in (current_source or ''):
                    deps.append(LockfileDependency(current_name, current_version, ECOSYSTEM_CARGO))
            current_name = None
            current_version = None
            current_source = None
            continue

        if stripped.startswith('name = '):
            current_name = stripped.split('=', 1)[1].strip().strip('"')
        elif stripped.startswith('version = '):
            current_version = stripped.split('=', 1)[1].strip().strip('"')
        elif stripped.startswith('source = '):
            current_source = stripped.split('=', 1)[1].strip().strip('"')

    # Last package
    if current_name and current_version:
        if not current_source or 'crates.io' in (current_source or ''):
            deps.append(LockfileDependency(current_name, current_version, ECOSYSTEM_CARGO))

    return deps


# =============================================================================
# Go: go.sum
# =============================================================================

def _parse_go_sum(content):
    """
    Parse go.sum file.

    Format: module version hash
    Each module may have two lines (one for go.mod, one for the zip).
    We deduplicate by (module, version).
    """
    deps = []
    seen = set()

    for line in content.split('\n'):
        line = line.strip()
        if not line:
            continue

        parts = line.split()
        if len(parts) < 3:
            continue

        module = parts[0]
        version_raw = parts[1]

        # Skip /go.mod hash entries (duplicates of the module entry)
        if version_raw.endswith('/go.mod'):
            continue

        # Strip 'v' prefix
        version = version_raw.lstrip('v')
        # Strip +incompatible suffix
        version = version.split('+')[0]

        key = (module, version)
        if key not in seen:
            seen.add(key)
            deps.append(LockfileDependency(module, version, ECOSYSTEM_GO))

    return deps


# =============================================================================
# Go: go.mod (for direct dependencies only)
# =============================================================================

def _parse_go_mod(content):
    """
    Parse go.mod for require directives (direct dependencies).

    Format:
        require (
            module v1.2.3
            module v1.2.3 // indirect
        )
        require module v1.2.3
    """
    deps = []
    in_require = False

    for line in content.split('\n'):
        stripped = line.strip()

        if stripped.startswith('require ('):
            in_require = True
            continue

        if in_require and stripped == ')':
            in_require = False
            continue

        # Single-line require
        if stripped.startswith('require ') and '(' not in stripped:
            parts = stripped.split()
            if len(parts) >= 3:
                module = parts[1]
                version = parts[2].lstrip('v').split('+')[0]
                is_direct = '// indirect' not in stripped
                deps.append(LockfileDependency(module, version, ECOSYSTEM_GO, is_direct))
            continue

        # Inside require block
        if in_require and stripped:
            parts = stripped.split()
            if len(parts) >= 2:
                module = parts[0]
                version = parts[1].lstrip('v').split('+')[0]
                is_direct = '// indirect' not in stripped
                deps.append(LockfileDependency(module, version, ECOSYSTEM_GO, is_direct))

    return deps


# =============================================================================
# Ruby: Gemfile.lock
# =============================================================================

def _parse_gemfile_lock(content):
    """
    Parse Gemfile.lock.

    Structure:
        GEM
          remote: https://rubygems.org/
          specs:
            package-name (1.2.3)
              dep1 (~> 1.0)
            another-package (4.5.6)
        ...
        DEPENDENCIES
          package-name
          another-package
    """
    deps = []
    in_gem_specs = False
    direct_names = set()
    in_dependencies = False

    # First pass: collect direct dependency names
    for line in content.split('\n'):
        stripped = line.strip()
        if stripped == 'DEPENDENCIES':
            in_dependencies = True
            continue
        if in_dependencies:
            if not stripped or (not line.startswith(' ') and not line.startswith('\t')):
                in_dependencies = False
                continue
            # "package-name" or "package-name (~> 1.0)"
            dep_name = stripped.split('(')[0].strip().split('!')[0].strip()
            if dep_name:
                direct_names.add(dep_name)

    # Second pass: extract packages with versions from GEM specs
    for line in content.split('\n'):
        stripped = line.strip()

        if stripped == 'specs:':
            in_gem_specs = True
            continue

        if in_gem_specs:
            # End of specs section
            if not stripped or (not line.startswith(' ') and not line.startswith('\t') and stripped not in ('', )):
                if stripped and not stripped.startswith(' '):
                    in_gem_specs = False
                    continue

            # Package with version: "    name (1.2.3)" (4 spaces indent = top-level gem)
            # Sub-dependency: "      dep (~> 1.0)" (6+ spaces = transitive, skip)
            indent = len(line) - len(line.lstrip())
            match = re.match(r'^(\S[\w.\-]+)\s+\(([^)]+)\)', stripped)
            if match and indent <= 6:
                name = match.group(1)
                version = match.group(2)
                is_direct = name in direct_names
                deps.append(LockfileDependency(name, version, ECOSYSTEM_RUBYGEMS, is_direct))

    return deps


# =============================================================================
# PHP: composer.lock
# =============================================================================

def _parse_composer_lock(content):
    """
    Parse composer.lock (JSON format).

    Structure:
    {
        "packages": [
            { "name": "vendor/package", "version": "v1.2.3", ... },
            ...
        ],
        "packages-dev": [ ... ]
    }
    """
    try:
        data = json.loads(content)
    except json.JSONDecodeError as e:
        logger.error(f"Invalid JSON in composer.lock: {e}")
        return None

    deps = []

    for section, is_direct in [('packages', True), ('packages-dev', False)]:
        packages = data.get(section, [])
        for pkg in packages:
            name = pkg.get('name', '')
            version = pkg.get('version', '')
            if not name or not version:
                continue
            # Strip 'v' prefix from version
            version = version.lstrip('v')
            deps.append(LockfileDependency(name, version, ECOSYSTEM_PACKAGIST, is_direct))

    return deps


# =============================================================================
# .NET: packages.lock.json
# =============================================================================

def _parse_nuget_packages_lock(content):
    """
    Parse NuGet packages.lock.json.

    Structure:
    {
        "version": 1,
        "dependencies": {
            "net8.0": {
                "PackageName": {
                    "type": "Direct" | "Transitive",
                    "resolved": "1.2.3",
                    ...
                }
            }
        }
    }
    """
    try:
        data = json.loads(content)
    except json.JSONDecodeError as e:
        logger.error(f"Invalid JSON in packages.lock.json: {e}")
        return None

    deps = []
    seen = set()

    frameworks = data.get('dependencies', {})
    for framework, packages in frameworks.items():
        for name, info in packages.items():
            version = info.get('resolved', '')
            if not version:
                continue
            dep_type = info.get('type', 'Transitive')
            is_direct = dep_type == 'Direct'

            key = (name, version)
            if key not in seen:
                seen.add(key)
                deps.append(LockfileDependency(name, version, ECOSYSTEM_NUGET, is_direct))

    return deps


# =============================================================================
# Batch parsing for agent submissions
# =============================================================================

def parse_lockfiles_batch(lockfiles):
    """
    Parse multiple lock files and return all dependencies.

    Args:
        lockfiles: list of dicts with 'filename' and 'content' keys

    Returns:
        dict with:
            'dependencies': list of dep dicts grouped by project
            'errors': list of files that failed to parse
            'stats': parsing statistics
    """
    all_deps = []
    errors = []
    total_direct = 0
    total_transitive = 0

    for lf in lockfiles:
        filename = lf.get('filename', '')
        content = lf.get('content', '')

        if not filename or not content:
            errors.append({'filename': filename, 'error': 'Missing filename or content'})
            continue

        deps = parse_lockfile(filename, content)
        if deps is None:
            errors.append({'filename': filename, 'error': 'Parse failed'})
            continue

        for dep in deps:
            if dep.is_direct:
                total_direct += 1
            else:
                total_transitive += 1
            all_deps.append({
                'name': dep.name,
                'version': dep.version,
                'ecosystem': dep.ecosystem,
                'is_direct': dep.is_direct,
                'purl': dep.purl,
                'source_file': filename,
            })

    return {
        'dependencies': all_deps,
        'errors': errors,
        'stats': {
            'files_parsed': len(lockfiles) - len(errors),
            'files_failed': len(errors),
            'total_dependencies': len(all_deps),
            'direct_dependencies': total_direct,
            'transitive_dependencies': total_transitive,
        }
    }
