# ============================================================
# SentriKat Update Script (Windows)
# ============================================================
# Updates a SentriKat installation to the latest (or specified) version.
#
# Usage:
#   .\scripts\update.ps1              # Update to latest version
#   .\scripts\update.ps1 -Version 1.0.3  # Update to specific version
#   .\scripts\update.ps1 -CheckOnly      # Check for updates only
# ============================================================

param(
    [string]$Version = "",
    [switch]$CheckOnly,
    [switch]$Help
)

$ErrorActionPreference = "Stop"
$Repo = "sbr0nch/SentriKat"
$GithubApi = "https://api.github.com/repos/$Repo"

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
    Write-Host "  .\update.ps1                    Update to latest version"
    Write-Host "  .\update.ps1 -Version 1.0.3     Update to specific version"
    Write-Host "  .\update.ps1 -CheckOnly         Check for updates only"
    Write-Host ""
    exit 0
}

Write-Host ""
Write-Host "=========================================="
Write-Host "  SentriKat Update Tool (Windows)"
Write-Host "=========================================="
Write-Host ""

# Find installation directory
$InstallDir = $null
$SearchPaths = @(".", "..", $PSScriptRoot, (Split-Path $PSScriptRoot))

foreach ($path in $SearchPaths) {
    $resolved = Resolve-Path $path -ErrorAction SilentlyContinue
    if ($resolved -and (Test-Path "$resolved\app\licensing.py")) {
        $InstallDir = $resolved.Path
        break
    }
}

if (-not $InstallDir) {
    Write-Err "Could not find SentriKat installation."
    Write-Err "Run this script from the SentriKat directory."
    exit 1
}

Write-Info "Installation directory: $InstallDir"

# Get current version
$CurrentVersion = "unknown"
$VersionFile = Join-Path $InstallDir "VERSION"
if (Test-Path $VersionFile) {
    $CurrentVersion = (Get-Content $VersionFile -Raw).Trim()
}
Write-Info "Current version: $CurrentVersion"

# Get latest version from GitHub
Write-Info "Checking for latest release..."
try {
    $release = Invoke-RestMethod -Uri "$GithubApi/releases/latest" -UseBasicParsing
    $LatestVersion = $release.tag_name -replace '^v', ''
} catch {
    Write-Err "Could not reach GitHub API. Check your internet connection."
    exit 1
}

# Determine target version
$TargetVersion = if ($Version) { $Version } else { $LatestVersion }
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
    Write-Host "  Run '.\update.ps1' to update."
    Write-Host ""
    exit 0
}

Write-Host ""
Write-Info "Updating: v$CurrentVersion -> v$TargetVersion"
Write-Host ""

# Check if Docker installation
$DockerCompose = Join-Path $InstallDir "docker-compose.yml"
$IsDocker = (Test-Path $DockerCompose) -and (Get-Command docker -ErrorAction SilentlyContinue)

if ($IsDocker -and (Select-String -Path $DockerCompose -Pattern "ghcr.io/sbr0nch/sentrikat" -Quiet)) {
    # Docker update
    Write-Info "Updating Docker installation..."

    # Backup docker-compose.yml
    $backupName = "docker-compose.yml.bak.$(Get-Date -Format 'yyyyMMddHHmmss')"
    Copy-Item $DockerCompose (Join-Path $InstallDir $backupName)
    Write-Info "Backed up docker-compose.yml"

    # Update image tag
    (Get-Content $DockerCompose) -replace 'ghcr.io/sbr0nch/sentrikat:[^\s"]+', "ghcr.io/sbr0nch/sentrikat:$TargetVersion" |
        Set-Content $DockerCompose
    Write-Info "Updated image tag"

    # Pull and restart
    Push-Location $InstallDir
    try {
        Write-Info "Pulling new Docker image..."
        docker compose pull
        Write-Info "Restarting SentriKat..."
        docker compose up -d
    } finally {
        Pop-Location
    }

    # Update VERSION file
    Set-Content -Path $VersionFile -Value $TargetVersion
    Write-OK "Docker update complete"

} else {
    # File-based update
    $DownloadUrl = "https://github.com/$Repo/releases/download/v$TargetVersion/sentrikat-$TargetVersion.tar.gz"
    $TempDir = Join-Path $env:TEMP "sentrikat-update-$(Get-Date -Format 'yyyyMMddHHmmss')"
    New-Item -ItemType Directory -Path $TempDir -Force | Out-Null

    try {
        # Download
        Write-Info "Downloading SentriKat v$TargetVersion..."
        $archivePath = Join-Path $TempDir "sentrikat-$TargetVersion.tar.gz"
        Invoke-WebRequest -Uri $DownloadUrl -OutFile $archivePath -UseBasicParsing
        Write-OK "Downloaded release package"

        # Extract (requires tar, available on Windows 10+)
        Write-Info "Extracting..."
        tar xzf $archivePath -C $TempDir

        # Find extracted directory
        $ExtractDir = Get-ChildItem $TempDir -Directory -Filter "sentrikat-*" | Select-Object -First 1
        if (-not $ExtractDir) {
            Write-Err "Could not find extracted directory"
            exit 1
        }

        # Backup
        $BackupDir = Join-Path $InstallDir "backups\pre-update-$(Get-Date -Format 'yyyyMMddHHmmss')"
        New-Item -ItemType Directory -Path $BackupDir -Force | Out-Null
        Write-Info "Creating backup in $BackupDir..."

        foreach ($item in @("app", "static", "templates", "VERSION", ".env", "docker-compose.yml")) {
            $source = Join-Path $InstallDir $item
            if (Test-Path $source) {
                Copy-Item $source (Join-Path $BackupDir $item) -Recurse -Force
            }
        }
        Write-OK "Backup created"

        # Update files (preserve .env and data)
        Write-Info "Updating application files..."
        $updateItems = @("app", "static", "templates", "scripts", "tools", "agents", "docs",
                         "Dockerfile", "docker-compose.yml", "docker-entrypoint.sh",
                         "requirements.txt", "VERSION", "README.md")

        foreach ($item in $updateItems) {
            $source = Join-Path $ExtractDir.FullName $item
            $dest = Join-Path $InstallDir $item
            if (Test-Path $source) {
                if (Test-Path $dest) { Remove-Item $dest -Recurse -Force }
                Copy-Item $source $dest -Recurse -Force
            }
        }

        # Ensure VERSION is updated
        Set-Content -Path $VersionFile -Value $TargetVersion
        Write-OK "Application files updated"

    } finally {
        # Clean up temp
        Remove-Item $TempDir -Recurse -Force -ErrorAction SilentlyContinue
    }

    Write-Warn "Restart SentriKat for changes to take effect."
    Write-Warn "  Docker: docker compose up -d"
    Write-Warn "  Manual: Restart your Python/Flask process"
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
