<#
.SYNOPSIS
    SentriKat Windows Agent - Software Inventory Collector

.DESCRIPTION
    Silent daemon agent that collects software inventory from Windows endpoints
    and reports to a SentriKat server. Designed to run as a Windows Service
    or Scheduled Task.

.NOTES
    Version: 1.0.0
    Author: SentriKat
    Requires: PowerShell 5.1+, Windows 10/Server 2016+

.EXAMPLE
    # Run once (for testing)
    .\sentrikat-agent-windows.ps1 -ServerUrl "https://sentrikat.example.com" -ApiKey "sk_agent_xxx"

    # Install as scheduled task (runs every 4 hours)
    .\sentrikat-agent-windows.ps1 -Install -ServerUrl "https://sentrikat.example.com" -ApiKey "sk_agent_xxx"

    # Install as Windows Service
    .\sentrikat-agent-windows.ps1 -InstallService -ServerUrl "https://sentrikat.example.com" -ApiKey "sk_agent_xxx"
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory=$false)]
    [string]$ServerUrl,

    [Parameter(Mandatory=$false)]
    [string]$ApiKey,

    [Parameter(Mandatory=$false)]
    [string]$ConfigFile = "$env:ProgramData\SentriKat\config.json",

    [Parameter(Mandatory=$false)]
    [switch]$Install,

    [Parameter(Mandatory=$false)]
    [switch]$InstallService,

    [Parameter(Mandatory=$false)]
    [switch]$Uninstall,

    [Parameter(Mandatory=$false)]
    [switch]$RunOnce,

    [Parameter(Mandatory=$false)]
    [int]$IntervalMinutes = 240,  # 4 hours default

    [Parameter(Mandatory=$false)]
    [switch]$Verbose
)

$ErrorActionPreference = "SilentlyContinue"
$AgentVersion = "1.0.0"
$LogFile = "$env:ProgramData\SentriKat\agent.log"

# ============================================================================
# Logging Functions
# ============================================================================

function Write-Log {
    param([string]$Message, [string]$Level = "INFO")

    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $logEntry = "[$timestamp] [$Level] $Message"

    # Ensure log directory exists
    $logDir = Split-Path $LogFile -Parent
    if (!(Test-Path $logDir)) {
        New-Item -ItemType Directory -Path $logDir -Force | Out-Null
    }

    # Write to log file (rotate if > 10MB)
    if ((Test-Path $LogFile) -and ((Get-Item $LogFile).Length -gt 10MB)) {
        Move-Item $LogFile "$LogFile.old" -Force
    }

    Add-Content -Path $LogFile -Value $logEntry

    if ($Verbose) {
        switch ($Level) {
            "ERROR" { Write-Host $logEntry -ForegroundColor Red }
            "WARN"  { Write-Host $logEntry -ForegroundColor Yellow }
            default { Write-Host $logEntry }
        }
    }
}

# ============================================================================
# Configuration Management
# ============================================================================

function Get-AgentConfig {
    $config = @{
        ServerUrl = $ServerUrl
        ApiKey = $ApiKey
        IntervalMinutes = $IntervalMinutes
        AgentId = $null
    }

    # Load from config file if exists
    if (Test-Path $ConfigFile) {
        try {
            $savedConfig = Get-Content $ConfigFile | ConvertFrom-Json
            if ($savedConfig.ServerUrl -and !$ServerUrl) { $config.ServerUrl = $savedConfig.ServerUrl }
            if ($savedConfig.ApiKey -and !$ApiKey) { $config.ApiKey = $savedConfig.ApiKey }
            if ($savedConfig.IntervalMinutes) { $config.IntervalMinutes = $savedConfig.IntervalMinutes }
            if ($savedConfig.AgentId) { $config.AgentId = $savedConfig.AgentId }
        } catch {
            Write-Log "Failed to load config file: $_" -Level "WARN"
        }
    }

    # Generate AgentId if not set
    if (!$config.AgentId) {
        $config.AgentId = (Get-WmiObject -Class Win32_ComputerSystemProduct).UUID
        if (!$config.AgentId) {
            $config.AgentId = [System.Guid]::NewGuid().ToString()
        }
        Save-AgentConfig $config
    }

    return $config
}

function Save-AgentConfig {
    param($Config)

    $configDir = Split-Path $ConfigFile -Parent
    if (!(Test-Path $configDir)) {
        New-Item -ItemType Directory -Path $configDir -Force | Out-Null
    }

    $Config | ConvertTo-Json | Set-Content $ConfigFile -Force
}

# ============================================================================
# System Information Collection
# ============================================================================

function Get-SystemInfo {
    $computerInfo = Get-WmiObject -Class Win32_ComputerSystem
    $osInfo = Get-WmiObject -Class Win32_OperatingSystem
    $networkAdapter = Get-WmiObject -Class Win32_NetworkAdapterConfiguration |
                      Where-Object { $_.IPEnabled -eq $true } |
                      Select-Object -First 1

    return @{
        hostname = $env:COMPUTERNAME
        fqdn = [System.Net.Dns]::GetHostEntry($env:COMPUTERNAME).HostName
        ip_address = $networkAdapter.IPAddress | Where-Object { $_ -match '^\d+\.\d+\.\d+\.\d+$' } | Select-Object -First 1
        os = @{
            name = "Windows"
            version = "$($osInfo.Caption) $($osInfo.Version)"
            kernel = $osInfo.BuildNumber
        }
        agent = @{
            id = $config.AgentId
            version = $AgentVersion
        }
    }
}

# ============================================================================
# Software Inventory Collection
# ============================================================================

function Get-InstalledSoftware {
    Write-Log "Collecting software inventory..."

    $software = @()

    # Registry paths for installed software
    $registryPaths = @(
        "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*",
        "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*",
        "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*"
    )

    foreach ($path in $registryPaths) {
        try {
            $items = Get-ItemProperty $path -ErrorAction SilentlyContinue |
                     Where-Object { $_.DisplayName -and $_.DisplayName.Trim() -ne "" }

            foreach ($item in $items) {
                $vendor = $item.Publisher
                $name = $item.DisplayName
                $version = $item.DisplayVersion

                # Skip if no vendor - try to extract from name
                if (!$vendor) {
                    $vendor = "Unknown"
                }

                # Clean up vendor name
                $vendor = $vendor -replace ',.*$', '' -replace '\s+Inc\.?$', '' -replace '\s+LLC\.?$', '' -replace '\s+Ltd\.?$', ''

                $software += @{
                    vendor = $vendor.Trim()
                    product = $name.Trim()
                    version = if ($version) { $version.Trim() } else { $null }
                    path = $item.InstallLocation
                }
            }
        } catch {
            Write-Log "Error reading registry path $path : $_" -Level "WARN"
        }
    }

    # Also get Windows Features/Roles (Server)
    try {
        $features = Get-WindowsOptionalFeature -Online | Where-Object { $_.State -eq "Enabled" }
        foreach ($feature in $features) {
            $software += @{
                vendor = "Microsoft"
                product = "Windows Feature: $($feature.FeatureName)"
                version = $null
                path = $null
            }
        }
    } catch {
        # Not available on all systems
    }

    # Deduplicate by vendor+product (keep highest version)
    $uniqueSoftware = @{}
    foreach ($sw in $software) {
        $key = "$($sw.vendor)|$($sw.product)".ToLower()
        if (!$uniqueSoftware.ContainsKey($key)) {
            $uniqueSoftware[$key] = $sw
        }
    }

    $result = $uniqueSoftware.Values | Sort-Object { $_.vendor }, { $_.product }
    Write-Log "Found $($result.Count) unique software packages"

    return $result
}

# ============================================================================
# API Communication
# ============================================================================

function Send-Inventory {
    param($Config, $SystemInfo, $Products)

    $endpoint = "$($Config.ServerUrl)/api/agent/inventory"

    $payload = @{
        hostname = $SystemInfo.hostname
        fqdn = $SystemInfo.fqdn
        ip_address = $SystemInfo.ip_address
        os = $SystemInfo.os
        agent = $SystemInfo.agent
        products = @($Products)
    }

    $jsonPayload = $payload | ConvertTo-Json -Depth 10 -Compress

    Write-Log "Sending inventory to $endpoint ($($Products.Count) products)..."

    $headers = @{
        "X-Agent-Key" = $Config.ApiKey
        "Content-Type" = "application/json"
        "User-Agent" = "SentriKat-Agent/$AgentVersion (Windows)"
    }

    $maxRetries = 3
    $retryDelay = 5

    for ($i = 1; $i -le $maxRetries; $i++) {
        try {
            # Use TLS 1.2
            [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

            $response = Invoke-RestMethod -Uri $endpoint -Method Post -Headers $headers -Body $jsonPayload -TimeoutSec 120

            Write-Log "Inventory sent successfully: $($response.status)"

            if ($response.job_id) {
                Write-Log "Async job queued: $($response.job_id)"
            } elseif ($response.summary) {
                Write-Log "Summary: Created=$($response.summary.products_created), Updated=$($response.summary.products_updated)"
            }

            return $true
        }
        catch {
            $errorMsg = $_.Exception.Message
            if ($_.Exception.Response) {
                try {
                    $reader = New-Object System.IO.StreamReader($_.Exception.Response.GetResponseStream())
                    $errorBody = $reader.ReadToEnd()
                    $errorMsg = "$errorMsg - $errorBody"
                } catch {}
            }

            Write-Log "Attempt $i failed: $errorMsg" -Level "WARN"

            if ($i -lt $maxRetries) {
                Write-Log "Retrying in $retryDelay seconds..."
                Start-Sleep -Seconds $retryDelay
                $retryDelay *= 2
            }
        }
    }

    Write-Log "Failed to send inventory after $maxRetries attempts" -Level "ERROR"
    return $false
}

function Send-Heartbeat {
    param($Config, $SystemInfo)

    $endpoint = "$($Config.ServerUrl)/api/agent/heartbeat"

    $payload = @{
        hostname = $SystemInfo.hostname
        agent_id = $SystemInfo.agent.id
    }

    $headers = @{
        "X-Agent-Key" = $Config.ApiKey
        "Content-Type" = "application/json"
        "User-Agent" = "SentriKat-Agent/$AgentVersion (Windows)"
    }

    try {
        [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
        $response = Invoke-RestMethod -Uri $endpoint -Method Post -Headers $headers -Body ($payload | ConvertTo-Json) -TimeoutSec 30
        return $true
    }
    catch {
        Write-Log "Heartbeat failed: $_" -Level "WARN"
        return $false
    }
}

# ============================================================================
# Installation Functions
# ============================================================================

function Install-ScheduledTask {
    param($Config)

    Write-Log "Installing scheduled task..."

    # Save config
    Save-AgentConfig $Config

    $scriptPath = $MyInvocation.PSCommandPath
    if (!$scriptPath) {
        $scriptPath = "$env:ProgramData\SentriKat\sentrikat-agent.ps1"
        Copy-Item $PSCommandPath $scriptPath -Force
    }

    $action = New-ScheduledTaskAction -Execute "powershell.exe" -Argument "-NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -File `"$scriptPath`" -RunOnce"
    $trigger = New-ScheduledTaskTrigger -Once -At (Get-Date) -RepetitionInterval (New-TimeSpan -Minutes $Config.IntervalMinutes)
    $principal = New-ScheduledTaskPrincipal -UserId "SYSTEM" -LogonType ServiceAccount -RunLevel Highest
    $settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -StartWhenAvailable -RunOnlyIfNetworkAvailable

    Unregister-ScheduledTask -TaskName "SentriKat Agent" -Confirm:$false -ErrorAction SilentlyContinue
    Register-ScheduledTask -TaskName "SentriKat Agent" -Action $action -Trigger $trigger -Principal $principal -Settings $settings -Description "SentriKat Software Inventory Agent"

    Write-Log "Scheduled task installed successfully"
    Write-Host "SentriKat Agent installed as scheduled task (runs every $($Config.IntervalMinutes) minutes)"
}

function Uninstall-Agent {
    Write-Log "Uninstalling agent..."

    # Remove scheduled task
    Unregister-ScheduledTask -TaskName "SentriKat Agent" -Confirm:$false -ErrorAction SilentlyContinue

    # Remove config and logs (optional)
    # Remove-Item "$env:ProgramData\SentriKat" -Recurse -Force -ErrorAction SilentlyContinue

    Write-Log "Agent uninstalled"
    Write-Host "SentriKat Agent uninstalled"
}

# ============================================================================
# Main Execution
# ============================================================================

function Main {
    Write-Log "SentriKat Agent v$AgentVersion starting..."

    # Load configuration
    $config = Get-AgentConfig

    # Validate configuration
    if (!$config.ServerUrl -or !$config.ApiKey) {
        Write-Log "ERROR: ServerUrl and ApiKey are required" -Level "ERROR"
        Write-Host "ERROR: ServerUrl and ApiKey are required. Use -ServerUrl and -ApiKey parameters or create config file at $ConfigFile"
        exit 1
    }

    # Handle installation
    if ($Install) {
        Install-ScheduledTask $config
        return
    }

    if ($Uninstall) {
        Uninstall-Agent
        return
    }

    # Collect and send inventory
    try {
        $systemInfo = Get-SystemInfo
        Write-Log "System: $($systemInfo.hostname) ($($systemInfo.os.version))"

        $products = Get-InstalledSoftware

        if ($products.Count -eq 0) {
            Write-Log "No software found to report" -Level "WARN"
            return
        }

        $success = Send-Inventory $config $systemInfo $products

        if ($success) {
            Write-Log "Inventory report completed successfully"
        } else {
            Write-Log "Inventory report failed" -Level "ERROR"
            exit 1
        }
    }
    catch {
        Write-Log "Fatal error: $_" -Level "ERROR"
        exit 1
    }
}

# Run
Main
