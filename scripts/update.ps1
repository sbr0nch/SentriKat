# ============================================================
# SentriKat Update Script (Windows)
# ============================================================
# Updates a SentriKat installation to the latest (or specified) version.
#
# Usage:
#   .\scripts\update.ps1                    # Update to latest version
#   .\scripts\update.ps1 -Version 1.0.3     # Update to specific version
#   .\scripts\update.ps1 -CheckOnly         # Check for updates only
#
# Supports three deployment types (auto-detected):
#   1. Docker image (customer package with ghcr.io pre-built image)
#   2. Docker build (developer/self-hosted, builds from source)
#   3. Standalone (no Docker, source-based)
# ============================================================

param(
    [string]$Version = "",
    [switch]$CheckOnly,
    [switch]$Help
)

$ErrorActionPreference = "Stop"
$Repo = "sbr0nch/SentriKat"
$GithubApi = "https://api.github.com/repos/$Repo"
$PortalApi = if ($env:SENTRIKAT_LICENSE_SERVER) { $env:SENTRIKAT_LICENSE_SERVER } else { "https://license.sentrikat.com/api" }

function Write-Info  { param($Msg) Write-Host "[INFO] $Msg" -ForegroundColor Cyan }
function Write-OK    { param($Msg) Write-Host "[OK] $Msg" -ForegroundColor Green }
function Write-Warn  { param($Msg) Write-Host "[WARN] $Msg" -ForegroundColor Yellow }
function Write-Err   { param($Msg) Write-Host "[ERROR] $Msg" -ForegroundColor Red }

if ($Help) {
    Write-Host ""
    Write-Host "SentriKat Update Tool (Windows)"
    Write-Host "================================"
    Write-Host ""
    Write-Host "Usage:"
    Write-Host "  .\update.ps1                         Update to latest stable version"
    Write-Host "  .\update.ps1 -Version 1.0.3          Update to specific version"
    Write-Host "  .\update.ps1 -Version 1.0.0-beta.1   Update to pre-release"
    Write-Host "  .\update.ps1 -CheckOnly              Check for updates only"
    Write-Host ""
    Write-Host "Environment:"
    Write-Host "  GITHUB_TOKEN          Auth token for private repos"
    Write-Host "  SENTRIKAT_DIR         Override install directory detection"
    Write-Host ""
    exit 0
}

Write-Host ""
Write-Host "=========================================="
Write-Host "  SentriKat Update Tool (Windows)"
Write-Host "=========================================="
Write-Host ""

# Strip leading 'v' from version if present
if ($Version -and $Version.StartsWith("v")) {
    $Version = $Version.Substring(1)
}

# ============================================================
# Installation Detection
# ============================================================

function Test-SentriKatDir {
    param([string]$Dir)

    # 1. Full source install: VERSION + app/licensing.py
    if ((Test-Path "$Dir\VERSION") -and (Test-Path "$Dir\app\licensing.py")) {
        return $true
    }

    # 2. Customer Docker: docker-compose.yml with GHCR image
    if ((Test-Path "$Dir\docker-compose.yml") -and
        (Select-String -Path "$Dir\docker-compose.yml" -Pattern "ghcr.io/sbr0nch/sentrikat" -Quiet)) {
        return $true
    }

    # 3. Developer Docker: Dockerfile + docker-compose.yml + app/
    if ((Test-Path "$Dir\docker-compose.yml") -and (Test-Path "$Dir\Dockerfile") -and
        (Test-Path "$Dir\app\licensing.py")) {
        return $true
    }

    # 4. Source checkout without VERSION: run.py + app/licensing.py
    if ((Test-Path "$Dir\run.py") -and (Test-Path "$Dir\app\licensing.py")) {
        return $true
    }

    return $false
}

# Check a directory and its app/ subdirectory for a SentriKat installation
function Find-SentriKatIn {
    param([string]$Dir)
    if (-not $Dir -or -not (Test-Path $Dir -PathType Container)) { return $null }
    if (Test-SentriKatDir $Dir) { return $Dir }
    $appSub = Join-Path $Dir "app"
    if ((Test-Path $appSub -PathType Container) -and (Test-SentriKatDir $appSub)) { return $appSub }
    return $null
}

$InstallDir = $null

# 1. Explicit override
if ($env:SENTRIKAT_DIR) {
    $resolved = try { (Resolve-Path $env:SENTRIKAT_DIR -ErrorAction Stop).Path } catch { $env:SENTRIKAT_DIR }
    $InstallDir = Find-SentriKatIn $resolved
}

# 2. Walk up from current directory and script directory
if (-not $InstallDir) {
    $SearchPaths = @((Get-Location).Path, $PSScriptRoot)
    foreach ($startPath in $SearchPaths) {
        $dir = $startPath
        while ($dir -and $dir.Length -gt 3) {
            $found = Find-SentriKatIn $dir
            if ($found) {
                $InstallDir = $found
                break
            }
            $dir = Split-Path $dir -Parent
        }
        if ($InstallDir) { break }
    }
}

# 3. Well-known paths
if (-not $InstallDir) {
    foreach ($candidate in @("C:\SentriKat", "C:\Program Files\SentriKat", "$env:ProgramData\SentriKat")) {
        if ($candidate) {
            $found = Find-SentriKatIn $candidate
            if ($found) {
                $InstallDir = $found
                break
            }
        }
    }
}

if (-not $InstallDir) {
    Write-Err "Could not find SentriKat installation."
    Write-Err "Looked for SentriKat files (VERSION, app\licensing.py, docker-compose.yml, run.py)"
    Write-Err "in these locations (and their app\ subdirectories):"
    if ($env:SENTRIKAT_DIR) { Write-Err "  SENTRIKAT_DIR: $($env:SENTRIKAT_DIR)" }
    Write-Err "  Script location: $PSScriptRoot"
    Write-Err "  Working directory: $((Get-Location).Path) (walked up to root)"
    Write-Err "  Well-known paths: C:\SentriKat, C:\Program Files\SentriKat"
    Write-Err ""
    Write-Err "Set SENTRIKAT_DIR=C:\path\to\sentrikat to override."
    exit 1
}

$InstallDir = (Resolve-Path $InstallDir).Path
Write-Info "Installation directory: $InstallDir"

# Detect deployment type
$DeployType = "standalone"
if (Get-Command docker -ErrorAction SilentlyContinue) {
    $DockerCompose = Join-Path $InstallDir "docker-compose.yml"
    if (Test-Path $DockerCompose) {
        if (Select-String -Path $DockerCompose -Pattern "ghcr.io/sbr0nch/sentrikat" -Quiet) {
            $DeployType = "docker_image"
        } elseif (Select-String -Path $DockerCompose -Pattern '^\s+build:' -Quiet) {
            $DeployType = "docker_build"
        }
    }
}
Write-Info "Deployment type: $DeployType"

# Load proxy settings from .env
$EnvFile = Join-Path $InstallDir ".env"
if (Test-Path $EnvFile) {
    $envContent = Get-Content $EnvFile
    foreach ($line in $envContent) {
        if ($line -match '^(HTTP_PROXY|HTTPS_PROXY|NO_PROXY)=(.+)$') {
            $varName = $Matches[1]
            $varValue = $Matches[2]
            if (-not [Environment]::GetEnvironmentVariable($varName)) {
                [Environment]::SetEnvironmentVariable($varName, $varValue, "Process")
            }
        }
    }
}
$proxy = [Environment]::GetEnvironmentVariable("HTTPS_PROXY")
if (-not $proxy) { $proxy = [Environment]::GetEnvironmentVariable("HTTP_PROXY") }
if ($proxy) {
    Write-Info "Proxy: $proxy"
    [System.Net.WebRequest]::DefaultWebProxy = New-Object System.Net.WebProxy($proxy)
    [System.Net.WebRequest]::DefaultWebProxy.BypassProxyOnLocal = $true
}

# Get current version
$CurrentVersion = "unknown"
$VersionFile = Join-Path $InstallDir "VERSION"
if (Test-Path $VersionFile) {
    $CurrentVersion = (Get-Content $VersionFile -Raw).Trim()
} elseif ($DeployType -eq "docker_image") {
    $tag = Select-String -Path (Join-Path $InstallDir "docker-compose.yml") -Pattern 'ghcr\.io/sbr0nch/sentrikat:([^\s"]+)' |
        ForEach-Object { $_.Matches[0].Groups[1].Value } | Select-Object -First 1
    if ($tag) { $CurrentVersion = $tag }
}
Write-Info "Current version: $CurrentVersion"

# Get latest version (portal then GitHub)
$TargetVersion = $Version
if (-not $TargetVersion) {
    Write-Info "Checking for latest release..."

    # Try portal first
    try {
        $portalResponse = Invoke-RestMethod -Uri "$PortalApi/v1/releases/latest" -UseBasicParsing -ErrorAction Stop
        if ($portalResponse.version) {
            $TargetVersion = $portalResponse.version -replace '^v', ''
        }
    } catch {
        # Portal unavailable, try GitHub
    }

    if (-not $TargetVersion) {
        Write-Info "Portal unavailable, checking GitHub..."
        try {
            $headers = @{}
            if ($env:GITHUB_TOKEN) { $headers["Authorization"] = "token $($env:GITHUB_TOKEN)" }
            $release = Invoke-RestMethod -Uri "$GithubApi/releases/latest" -Headers $headers -UseBasicParsing
            $TargetVersion = $release.tag_name -replace '^v', ''
        } catch {
            Write-Err "Could not determine latest version from portal or GitHub."
            exit 1
        }
    }
}
Write-Info "Target version:  $TargetVersion"

# Compare
if ($CurrentVersion -eq $TargetVersion) {
    Write-OK "Already up to date (v$CurrentVersion)."
    exit 0
}

if ($CheckOnly) {
    Write-Host ""
    Write-OK "Update available: v$CurrentVersion -> v$TargetVersion"
    Write-Host ""
    Write-Host "  Run '.\update.ps1' to update, or '.\update.ps1 -Version $TargetVersion' for this version."
    Write-Host ""
    exit 0
}

Write-Host ""
Write-Info "Updating: v$CurrentVersion -> v$TargetVersion"
Write-Host ""

# ============================================================
# Download Helper
# ============================================================

function Download-Release {
    param([string]$Ver, [string]$Output)

    $headers = @{}
    if ($env:GITHUB_TOKEN) { $headers["Authorization"] = "token $($env:GITHUB_TOKEN)" }

    # 1. GitHub source archive
    Write-Info "Downloading from GitHub..."
    try {
        Invoke-WebRequest -Uri "https://github.com/$Repo/archive/refs/tags/v$Ver.tar.gz" `
            -OutFile $Output -UseBasicParsing -Headers $headers -ErrorAction Stop
        Write-OK "Downloaded source archive from GitHub"
        return $true
    } catch {}

    # 2. GitHub release asset
    try {
        Invoke-WebRequest -Uri "https://github.com/$Repo/releases/download/v$Ver/sentrikat-$Ver.tar.gz" `
            -OutFile $Output -UseBasicParsing -Headers $headers -ErrorAction Stop
        Write-OK "Downloaded release package from GitHub"
        return $true
    } catch {}

    # 3. Portal
    Write-Info "Trying portal download..."
    try {
        Invoke-WebRequest -Uri "$PortalApi/v1/releases/$Ver/download" `
            -OutFile $Output -UseBasicParsing -ErrorAction Stop
        Write-OK "Downloaded from portal"
        return $true
    } catch {}

    Write-Err "Failed to download v$Ver from any source."
    if (-not $env:GITHUB_TOKEN) { Write-Warn "If the repo is private, set GITHUB_TOKEN=<your-token>" }
    return $false
}

# ============================================================
# Update Functions
# ============================================================

function Update-SourceFiles {
    param([string]$InstDir, [string]$Ver)

    $TempDir = Join-Path $env:TEMP "sentrikat-update-$(Get-Date -Format 'yyyyMMddHHmmss')"
    New-Item -ItemType Directory -Path $TempDir -Force | Out-Null
    $archivePath = Join-Path $TempDir "sentrikat-$Ver.tar.gz"

    try {
        Write-Info "Downloading SentriKat v$Ver..."
        if (-not (Download-Release -Ver $Ver -Output $archivePath)) {
            exit 1
        }

        # Extract
        Write-Info "Extracting..."
        tar xzf $archivePath -C $TempDir

        # Find extracted directory
        $ExtractDir = Get-ChildItem $TempDir -Directory | Select-Object -First 1
        if (-not $ExtractDir) {
            Write-Err "Could not find extracted directory"
            exit 1
        }
        Write-Info "Extracted: $($ExtractDir.Name)"

        # Backup
        $BackupDir = Join-Path $InstDir "backups\pre-update-$(Get-Date -Format 'yyyyMMddHHmmss')"
        New-Item -ItemType Directory -Path $BackupDir -Force | Out-Null
        Write-Info "Creating backup in $BackupDir..."

        foreach ($item in @("app", "static", "templates", "VERSION", ".env", "docker-compose.yml", "Dockerfile")) {
            $source = Join-Path $InstDir $item
            if (Test-Path $source) {
                Copy-Item $source (Join-Path $BackupDir $item) -Recurse -Force
            }
        }
        Write-OK "Backup created"

        # Replace source files (NEVER touch .env, docker-compose.yml, or data/)
        Write-Info "Updating application files..."
        $updateItems = @("app", "static", "templates", "scripts", "tools", "agents", "docs", "nginx",
                         "Dockerfile", "docker-entrypoint.sh", "gunicorn.conf.py",
                         "requirements.txt", "VERSION", "README.md", "run.py")

        foreach ($item in $updateItems) {
            $source = Join-Path $ExtractDir.FullName $item
            $dest = Join-Path $InstDir $item
            if (Test-Path $source) {
                if (Test-Path $dest) { Remove-Item $dest -Recurse -Force }
                Copy-Item $source $dest -Recurse -Force
            }
        }

        Set-Content -Path (Join-Path $InstDir "VERSION") -Value $Ver -NoNewline
        Write-OK "Application files updated"

    } finally {
        Remove-Item $TempDir -Recurse -Force -ErrorAction SilentlyContinue
    }
}

# --- Docker image update ---
if ($DeployType -eq "docker_image") {
    $DockerCompose = Join-Path $InstallDir "docker-compose.yml"

    Write-Info "Updating Docker image to v$TargetVersion..."

    (Get-Content $DockerCompose) -replace 'ghcr.io/sbr0nch/sentrikat:[^\s"]+', "ghcr.io/sbr0nch/sentrikat:$TargetVersion" |
        Set-Content $DockerCompose
    Write-Info "Updated image tag to $TargetVersion"

    Push-Location $InstallDir
    try {
        Write-Info "Pulling new Docker image..."
        docker compose pull 2>&1
        if ($LASTEXITCODE -ne 0) {
            Write-Err "Failed to pull Docker image ghcr.io/sbr0nch/sentrikat:$TargetVersion"
            Write-Err "Check: https://github.com/$Repo/pkgs/container/sentrikat"
            if ($CurrentVersion -ne "unknown") {
                (Get-Content $DockerCompose) -replace 'ghcr.io/sbr0nch/sentrikat:[^\s"]+', "ghcr.io/sbr0nch/sentrikat:$CurrentVersion" |
                    Set-Content $DockerCompose
                Write-Warn "Reverted docker-compose.yml to v$CurrentVersion"
            }
            exit 1
        }
        Write-OK "Docker image pulled"

        Write-Info "Restarting SentriKat..."
        docker compose up -d
        if ($LASTEXITCODE -ne 0) {
            Write-Err "Failed to restart containers. Check: docker compose logs"
            exit 1
        }
        Write-OK "SentriKat restarted"
    } finally {
        Pop-Location
    }

    Set-Content -Path $VersionFile -Value $TargetVersion -NoNewline

# --- Docker build update ---
} elseif ($DeployType -eq "docker_build") {
    Write-Info "Updating Docker (build from source) to v$TargetVersion..."

    Update-SourceFiles -InstDir $InstallDir -Ver $TargetVersion

    Push-Location $InstallDir
    try {
        Write-Info "Rebuilding Docker image (this may take a few minutes)..."
        docker compose build 2>&1
        if ($LASTEXITCODE -ne 0) {
            Write-Err "Docker build failed. Check the output above."
            Write-Warn "Source files were updated. Retry: docker compose build && docker compose up -d"
            exit 1
        }
        Write-OK "Docker image rebuilt"

        Write-Info "Restarting SentriKat..."
        docker compose up -d
        if ($LASTEXITCODE -ne 0) {
            Write-Err "Failed to restart containers."
            exit 1
        }
        Write-OK "SentriKat restarted"
    } finally {
        Pop-Location
    }

# --- Standalone update ---
} else {
    Update-SourceFiles -InstDir $InstallDir -Ver $TargetVersion

    Write-Warn "Restart SentriKat for changes to take effect."
    Write-Warn "  Docker: docker compose up -d"
    Write-Warn "  Service: Restart-Service SentriKat"
}

Write-Host ""
Write-Host "=========================================="
Write-OK "SentriKat updated to v$TargetVersion!"
Write-Host "=========================================="
Write-Host ""
Write-Host "  Next steps:"
Write-Host "  1. Verify the application is running correctly"
Write-Host "  2. Check Administration > License for version info"
Write-Host "  3. Clear your browser cache (Ctrl+Shift+R)"
Write-Host ""
