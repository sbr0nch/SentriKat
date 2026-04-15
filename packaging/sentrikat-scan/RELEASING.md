# Releasing `sentrikat-scan` to PyPI

This package is published to [PyPI](https://pypi.org/project/sentrikat-scan/) via the `.github/workflows/publish-sentrikat-scan.yml` GitHub Actions workflow, using **PEP 740 Trusted Publishing** (OIDC) — no long-lived API token is stored as a GitHub secret.

## One-time setup (do this once per environment)

You have to do this exactly once for PyPI and exactly once for TestPyPI. It takes ~5 minutes per environment.

### 1. Create the PyPI accounts

- Register an account on <https://pypi.org/account/register/>.
- Register a **separate** account on <https://test.pypi.org/account/register/> (TestPyPI is a standalone staging mirror, not the same account database).
- Enable 2FA on both. PyPI requires it for any maintainer of a package.

### 2. Register the Trusted Publisher on PyPI (production)

1. Log in to <https://pypi.org/>.
2. Go to your account menu → **Publishing**. You should land on <https://pypi.org/manage/account/publishing/>.
3. Scroll down to **Add a new pending publisher**.
4. Fill the form exactly like this:
   - **PyPI project name**: `sentrikat-scan`
   - **Owner**: `sbr0nch`
   - **Repository name**: `SentriKat`
   - **Workflow name**: `publish-sentrikat-scan.yml`
   - **Environment name**: `pypi`
5. Click **Add**.

PyPI now knows that any GitHub Actions run from `sbr0nch/SentriKat` using the workflow file `publish-sentrikat-scan.yml` running in the environment named `pypi` is allowed to publish to the `sentrikat-scan` project. No other workflow can.

### 3. Register the Trusted Publisher on TestPyPI (staging)

Repeat the same procedure on <https://test.pypi.org/manage/account/publishing/> but this time with:

- **Environment name**: `testpypi` (note the lowercase)

Everything else identical.

### 4. Create the GitHub environments

In the SentriKat repo on GitHub:

1. Settings → **Environments** → **New environment**.
2. Create one named `pypi`. No secrets, no branch protection needed — Trusted Publishing handles auth.
3. Create another named `testpypi`, same deal.

You can optionally add a **required reviewer** on the `pypi` environment so the real publish step pauses for manual approval, which is a nice seatbelt against accidental tag pushes.

## Cutting a release

Once the one-time setup is done, releasing is two commands:

```bash
# Bump the version in packaging/sentrikat-scan/pyproject.toml, commit, merge to main.
# Then from main:
git tag sentrikat-scan-v1.0.0
git push origin sentrikat-scan-v1.0.0
```

That pushes the tag to GitHub. The workflow triggers on `sentrikat-scan-v*` tags. It will:

1. Build the wheel + sdist from `scripts/sentrikat-scan.py` (via `build.sh`).
2. Upload them to **TestPyPI** first (always, as a smoke test).
3. If TestPyPI succeeds, upload them to real **PyPI**.
4. The new version appears on <https://pypi.org/project/sentrikat-scan/> within a minute or two.

The tag namespace `sentrikat-scan-v*` is intentionally separate from the main product release tags (`v*`) handled by `.github/workflows/release.yml`, so the scanner can be released on its own cadence without forcing a full product bump.

## Testing without a real release

Use the **manual dispatch** trigger on the Actions UI:

1. GitHub → Actions → **Publish sentrikat-scan to PyPI**.
2. **Run workflow** → `target: testpypi`.
3. The run builds and uploads to TestPyPI only, skipping the real PyPI step (guarded by `github.event_name == 'push'`).

You can then install from TestPyPI and smoke-test:

```bash
pip install --index-url https://test.pypi.org/simple/ \
            --extra-index-url https://pypi.org/simple/ \
            sentrikat-scan
sentrikat-scan --help
sentrikat-scan --version
```

(The `--extra-index-url` fallback to real PyPI is needed because TestPyPI mirrors only a subset of dependencies — for our package it doesn't matter since we have zero runtime deps, but it's good hygiene.)

## Version bump checklist

Before pushing a release tag:

- [ ] Bump `version` in `packaging/sentrikat-scan/pyproject.toml`.
- [ ] Update `VERSION = "..."` constant in `scripts/sentrikat-scan.py` to match.
- [ ] Run `./packaging/sentrikat-scan/build.sh --test` locally — must pass.
- [ ] Update `CHANGELOG` entry (if you keep one).
- [ ] Commit, open PR, merge to `main`.
- [ ] Pull `main`, create and push the `sentrikat-scan-v<new-version>` tag.
- [ ] Watch the Actions run complete.
- [ ] Verify `pip install sentrikat-scan==<new-version>` works on a clean machine.

## Rollback / yank

PyPI does not allow re-uploading the same version. If a release is broken:

1. Log in to <https://pypi.org/project/sentrikat-scan/>.
2. Click **Manage releases**, pick the broken version, click **Yank**.
3. Bump the version (e.g. `1.0.0` → `1.0.1`) and re-release via the tag flow.

Yanked versions remain installable only by exact pin — `pip install sentrikat-scan` (without a version) will skip them.
