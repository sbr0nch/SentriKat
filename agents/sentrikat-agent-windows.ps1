<#
.SYNOPSIS
    SentriKat Windows Agent - Software Inventory Collector

.DESCRIPTION
    Silent daemon agent that collects software inventory from Windows endpoints
    and reports to a SentriKat server. Designed to run as a Windows Service
    or Scheduled Task.

.NOTES
    Version: 1.4.0
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
    [switch]$Heartbeat,

    [Parameter(Mandatory=$false)]
    [int]$IntervalMinutes = 240,  # 4 hours default

    [Parameter(Mandatory=$false)]
    [switch]$VerboseOutput
)

# Use Stop so unexpected errors are visible; individual cmdlets use -ErrorAction SilentlyContinue where intended
$ErrorActionPreference = "Stop"
$AgentVersion = "1.4.0"
$LogFile = "$env:ProgramData\SentriKat\agent.log"
$HeartbeatIntervalMinutes = 5

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

    if ($VerboseOutput) {
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
        ScanExtensions = $false
        ScanDependencies = $false
    }

    # Load from config file if exists
    if (Test-Path $ConfigFile) {
        try {
            $savedConfig = Get-Content $ConfigFile | ConvertFrom-Json
            if ($savedConfig.ServerUrl -and !$ServerUrl) { $config.ServerUrl = $savedConfig.ServerUrl }
            if ($savedConfig.ApiKey -and !$ApiKey) { $config.ApiKey = $savedConfig.ApiKey }
            if ($savedConfig.IntervalMinutes) { $config.IntervalMinutes = $savedConfig.IntervalMinutes }
            if ($savedConfig.AgentId) { $config.AgentId = $savedConfig.AgentId }
            if ($null -ne $savedConfig.ScanExtensions) { $config.ScanExtensions = [bool]$savedConfig.ScanExtensions }
            if ($null -ne $savedConfig.ScanDependencies) { $config.ScanDependencies = [bool]$savedConfig.ScanDependencies }
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

    # Restrict file ACL to SYSTEM and Administrators only (config contains API key)
    # Use well-known SIDs instead of localized names for non-English Windows
    try {
        $acl = Get-Acl $ConfigFile
        $acl.SetAccessRuleProtection($true, $false)
        $adminSid = New-Object System.Security.Principal.SecurityIdentifier("S-1-5-32-544")  # BUILTIN\Administrators
        $systemSid = New-Object System.Security.Principal.SecurityIdentifier("S-1-5-18")     # NT AUTHORITY\SYSTEM
        $adminRule = New-Object System.Security.AccessControl.FileSystemAccessRule($adminSid,"FullControl","Allow")
        $systemRule = New-Object System.Security.AccessControl.FileSystemAccessRule($systemSid,"FullControl","Allow")
        $acl.AddAccessRule($adminRule)
        $acl.AddAccessRule($systemRule)
        Set-Acl $ConfigFile $acl
    } catch {
        Write-Log "Warning: Could not restrict config file permissions: $_" -Level "WARN"
    }
}

# ============================================================================
# System Information Collection
# ============================================================================

function Get-SystemInfo {
    $computerInfo = Get-WmiObject -Class Win32_ComputerSystem
    $osInfo = Get-WmiObject -Class Win32_OperatingSystem

    # Get the best IP address - prefer physical adapters with default gateway
    $ipAddress = $null

    # Get adapters with name info
    $adaptersWithNames = Get-WmiObject -Class Win32_NetworkAdapter | Where-Object { $_.NetEnabled -eq $true }
    $virtualAdapterPatterns = @('Virtual', 'VMware', 'VirtualBox', 'Hyper-V', 'vEthernet', 'Docker', 'WSL')

    # Try to find a physical adapter with a default gateway first
    $allAdapters = Get-WmiObject -Class Win32_NetworkAdapterConfiguration | Where-Object { $_.IPEnabled -eq $true }

    foreach ($adapter in $allAdapters) {
        # Skip adapters without IP addresses
        $adapterIp = $adapter.IPAddress | Where-Object { $_ -match '^\d+\.\d+\.\d+\.\d+$' } | Select-Object -First 1
        if (-not $adapterIp) { continue }

        # Skip Docker/WSL/VM network ranges (172.16-31.x.x, 192.168.x.x often used by VMs)
        if ($adapterIp -match '^172\.(1[6-9]|2[0-9]|3[0-1])\.') { continue }
        if ($adapterIp -match '^169\.254\.') { continue }  # Link-local

        # Check if this is a virtual adapter by description
        $adapterInfo = $adaptersWithNames | Where-Object { $_.Index -eq $adapter.Index }
        $isVirtual = $false
        if ($adapterInfo) {
            foreach ($pattern in $virtualAdapterPatterns) {
                if ($adapterInfo.Name -like "*$pattern*" -or $adapterInfo.Description -like "*$pattern*") {
                    $isVirtual = $true
                    break
                }
            }
        }

        # Prefer adapters with default gateway (means it's likely the main network)
        if ($adapter.DefaultIPGateway -and -not $isVirtual) {
            $ipAddress = $adapterIp
            break
        }

        # Fall back to first non-virtual adapter
        if (-not $ipAddress -and -not $isVirtual) {
            $ipAddress = $adapterIp
        }
    }

    # Ultimate fallback: just use first IP
    if (-not $ipAddress) {
        $firstAdapter = $allAdapters | Select-Object -First 1
        $ipAddress = $firstAdapter.IPAddress | Where-Object { $_ -match '^\d+\.\d+\.\d+\.\d+$' } | Select-Object -First 1
    }

    return @{
        hostname = $env:COMPUTERNAME
        fqdn = [System.Net.Dns]::GetHostEntry($env:COMPUTERNAME).HostName
        ip_address = $ipAddress
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

    # Also get Windows Features/Roles (Server) - only security-relevant ones
    try {
        $securityFeaturePatterns = @('IIS-*', 'TelnetClient', 'TelnetServer', 'SMB1Protocol*', 'TFTP', 'Microsoft-Hyper-V*', 'Containers*', 'Microsoft-Windows-Subsystem-Linux')
        $features = Get-WindowsOptionalFeature -Online -ErrorAction SilentlyContinue | Where-Object {
            $feat = $_
            $feat.State -eq "Enabled" -and ($securityFeaturePatterns | Where-Object { $feat.FeatureName -like $_ })
        }
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
    Write-Log "Collected $($result.Count) installed packages (server-side filtering)"

    return $result
}

# ============================================================================
# Extension Scanning (VS Code, Browsers, JetBrains IDEs)
# ============================================================================

function Get-Extensions {
    Write-Log "Scanning extensions (VS Code, browsers, IDEs)..."

    $extensions = @()

    # --- VS Code extensions ---
    $extensionDirs = @()
    $usersDir = "C:\Users"
    if (Test-Path $usersDir) {
        $userProfiles = Get-ChildItem -Path $usersDir -Directory -ErrorAction SilentlyContinue |
            Where-Object { $_.Name -notin @('Public', 'Default', 'Default User', 'All Users') }
        foreach ($profile in $userProfiles) {
            @(".vscode\extensions", ".vscode-insiders\extensions") | ForEach-Object {
                $p = Join-Path $profile.FullName $_
                if ((Test-Path $p) -and ($p -notin $extensionDirs)) { $extensionDirs += $p }
            }
        }
    }
    if ($env:USERPROFILE) {
        @(".vscode\extensions", ".vscode-insiders\extensions") | ForEach-Object {
            $p = Join-Path $env:USERPROFILE $_
            if ((Test-Path $p) -and ($p -notin $extensionDirs)) { $extensionDirs += $p }
        }
    }
    foreach ($extDir in $extensionDirs) {
        $extFolders = Get-ChildItem -Path $extDir -Directory -ErrorAction SilentlyContinue
        foreach ($folder in $extFolders) {
            $packageJsonPath = Join-Path $folder.FullName "package.json"
            if (!(Test-Path $packageJsonPath)) { continue }
            try {
                $packageJson = Get-Content $packageJsonPath -Raw -ErrorAction SilentlyContinue | ConvertFrom-Json
                $extensions += @{
                    vendor = if ($packageJson.publisher) { $packageJson.publisher } else { "Unknown" }
                    product = if ($packageJson.displayName) { $packageJson.displayName } elseif ($packageJson.name) { $packageJson.name } else { $folder.Name }
                    version = if ($packageJson.version) { $packageJson.version } else { $null }
                    path = $folder.FullName
                    source_type = "extension"
                    ecosystem = "vscode"
                }
            } catch {
                Write-Log "Failed to parse VS Code extension in $($folder.FullName): $_" -Level "WARN"
            }
        }
    }

    # --- Chrome extensions ---
    if (Test-Path $usersDir) {
        foreach ($profile in (Get-ChildItem -Path $usersDir -Directory -ErrorAction SilentlyContinue | Where-Object { $_.Name -notin @('Public', 'Default', 'Default User', 'All Users') })) {
            $chromeExtDir = Join-Path $profile.FullName "AppData\Local\Google\Chrome\User Data\Default\Extensions"
            if (!(Test-Path $chromeExtDir)) { continue }
            Get-ChildItem -Path $chromeExtDir -Directory -ErrorAction SilentlyContinue | ForEach-Object {
                $verDirs = Get-ChildItem -Path $_.FullName -Directory -ErrorAction SilentlyContinue | Select-Object -First 1
                if ($verDirs) {
                    $manifest = Join-Path $verDirs.FullName "manifest.json"
                    if (Test-Path $manifest) {
                        try {
                            $m = Get-Content $manifest -Raw -ErrorAction SilentlyContinue | ConvertFrom-Json
                            $eName = if ($m.name -and $m.name -notlike "__MSG_*") { $m.name } else { $null }
                            if ($eName) {
                                $extensions += @{
                                    vendor = "Chrome Web Store"
                                    product = $eName
                                    version = if ($m.version) { $m.version } else { $null }
                                    source_type = "extension"
                                    ecosystem = "chrome"
                                }
                            }
                        } catch {}
                    }
                }
            }
        }
    }

    # --- Edge extensions ---
    if (Test-Path $usersDir) {
        foreach ($profile in (Get-ChildItem -Path $usersDir -Directory -ErrorAction SilentlyContinue | Where-Object { $_.Name -notin @('Public', 'Default', 'Default User', 'All Users') })) {
            $edgeExtDir = Join-Path $profile.FullName "AppData\Local\Microsoft\Edge\User Data\Default\Extensions"
            if (!(Test-Path $edgeExtDir)) { continue }
            Get-ChildItem -Path $edgeExtDir -Directory -ErrorAction SilentlyContinue | ForEach-Object {
                $verDirs = Get-ChildItem -Path $_.FullName -Directory -ErrorAction SilentlyContinue | Select-Object -First 1
                if ($verDirs) {
                    $manifest = Join-Path $verDirs.FullName "manifest.json"
                    if (Test-Path $manifest) {
                        try {
                            $m = Get-Content $manifest -Raw -ErrorAction SilentlyContinue | ConvertFrom-Json
                            $eName = if ($m.name -and $m.name -notlike "__MSG_*") { $m.name } else { $null }
                            if ($eName) {
                                $extensions += @{
                                    vendor = "Edge Add-ons"
                                    product = $eName
                                    version = if ($m.version) { $m.version } else { $null }
                                    source_type = "extension"
                                    ecosystem = "edge"
                                }
                            }
                        } catch {}
                    }
                }
            }
        }
    }

    # --- Firefox extensions ---
    if (Test-Path $usersDir) {
        foreach ($profile in (Get-ChildItem -Path $usersDir -Directory -ErrorAction SilentlyContinue | Where-Object { $_.Name -notin @('Public', 'Default', 'Default User', 'All Users') })) {
            $ffDir = Join-Path $profile.FullName "AppData\Roaming\Mozilla\Firefox\Profiles"
            if (!(Test-Path $ffDir)) { continue }
            Get-ChildItem -Path $ffDir -Directory -Filter "*.default*" -ErrorAction SilentlyContinue | ForEach-Object {
                $extJson = Join-Path $_.FullName "extensions.json"
                if (Test-Path $extJson) {
                    try {
                        $data = Get-Content $extJson -Raw -ErrorAction SilentlyContinue | ConvertFrom-Json
                        foreach ($addon in $data.addons) {
                            if ($addon.type -ne 'extension') { continue }
                            $ffName = if ($addon.defaultLocale.name) { $addon.defaultLocale.name } else { $addon.id }
                            if ($ffName -and !$ffName.StartsWith('@')) {
                                $extensions += @{
                                    vendor = if ($addon.defaultLocale.creator) { $addon.defaultLocale.creator } else { "Mozilla Add-ons" }
                                    product = $ffName
                                    version = if ($addon.version) { $addon.version } else { $null }
                                    source_type = "extension"
                                    ecosystem = "firefox"
                                }
                            }
                        }
                    } catch {}
                }
            }
        }
    }

    # --- JetBrains IDE plugins ---
    if (Test-Path $usersDir) {
        foreach ($profile in (Get-ChildItem -Path $usersDir -Directory -ErrorAction SilentlyContinue | Where-Object { $_.Name -notin @('Public', 'Default', 'Default User', 'All Users') })) {
            $jbBase = Join-Path $profile.FullName "AppData\Roaming\JetBrains"
            if (!(Test-Path $jbBase)) { continue }
            Get-ChildItem -Path $jbBase -Directory -ErrorAction SilentlyContinue | ForEach-Object {
                $pluginsDir = Join-Path $_.FullName "plugins"
                if (!(Test-Path $pluginsDir)) { return }
                Get-ChildItem -Path $pluginsDir -Directory -ErrorAction SilentlyContinue | ForEach-Object {
                    $pluginXml = Join-Path $_.FullName "META-INF\plugin.xml"
                    if ((Test-Path $pluginXml) -and -not (Get-Item $pluginXml -ErrorAction SilentlyContinue).Attributes.HasFlag([IO.FileAttributes]::ReparsePoint)) {
                        try {
                            $xmlSettings = New-Object System.Xml.XmlReaderSettings
                            $xmlSettings.DtdProcessing = [System.Xml.DtdProcessing]::Prohibit
                            $xmlSettings.XmlResolver = $null
                            $xmlContent = Get-Content $pluginXml -Raw -ErrorAction SilentlyContinue
                            $xmlReader = [System.Xml.XmlReader]::Create((New-Object System.IO.StringReader($xmlContent)), $xmlSettings)
                            $xml = New-Object System.Xml.XmlDocument
                            $xml.Load($xmlReader)
                            $pName = if ($xml.'idea-plugin'.name) { $xml.'idea-plugin'.name } else { $_.Name }
                            $pVer = $xml.'idea-plugin'.version
                            $extensions += @{
                                vendor = "JetBrains Marketplace"
                                product = $pName
                                version = if ($pVer) { $pVer } else { $null }
                                source_type = "extension"
                                ecosystem = "jetbrains"
                            }
                        } catch {}
                    }
                }
            }
        }
    }

    # Deduplicate by vendor+name+version (keep first occurrence)
    $uniqueExtensions = @{}
    foreach ($ext in $extensions) {
        $key = "$($ext.vendor)|$($ext.product)|$($ext.version)".ToLower()
        if (!$uniqueExtensions.ContainsKey($key)) {
            $uniqueExtensions[$key] = $ext
        }
    }

    $result = @($uniqueExtensions.Values)
    Write-Log "Found $($result.Count) extensions (VS Code, browsers, IDEs)"
    return $result
}

# ============================================================================
# Code Dependency Scanning
# ============================================================================

function Get-CodeDependencies {
    Write-Log "Scanning code dependencies..."

    $dependencies = @()

    # --- Python: pip freeze ---
    foreach ($pipCmd in @("pip3", "pip")) {
        try {
            $pipExe = Get-Command $pipCmd -ErrorAction SilentlyContinue
            if (!$pipExe) { continue }

            Write-Log "Running $pipCmd freeze for global Python packages..."
            $pipOutput = & $pipCmd freeze 2>&1
            if ($LASTEXITCODE -eq 0 -and $pipOutput) {
                foreach ($line in $pipOutput) {
                    if ($line -match '^([^=]+)==(.+)$') {
                        $dependencies += @{
                            vendor = "PyPI"
                            product = $Matches[1].Trim()
                            version = $Matches[2].Trim()
                            path = $null
                            source_type = "code_library"
                            ecosystem = "python"
                        }
                    }
                }
            }
            # Only run the first pip variant that succeeds
            break
        }
        catch {
            Write-Log "Failed to run $pipCmd freeze: $_" -Level "WARN"
        }
    }

    # --- Node.js: npm ls -g ---
    try {
        $npmExe = Get-Command npm -ErrorAction SilentlyContinue
        if ($npmExe) {
            Write-Log "Running npm ls -g for global Node.js packages..."
            $npmOutput = & npm ls -g --depth=0 --json 2>&1
            if ($LASTEXITCODE -eq 0 -and $npmOutput) {
                try {
                    $npmJson = $npmOutput | Out-String | ConvertFrom-Json
                    if ($npmJson.dependencies) {
                        $npmJson.dependencies.PSObject.Properties | ForEach-Object {
                            $dependencies += @{
                                vendor = "npm"
                                product = $_.Name
                                version = if ($_.Value.version) { $_.Value.version } else { $null }
                                path = $null
                                source_type = "code_library"
                                ecosystem = "nodejs"
                            }
                        }
                    }
                }
                catch {
                    Write-Log "Failed to parse npm ls output: $_" -Level "WARN"
                }
            }
        }
    }
    catch {
        Write-Log "Failed to run npm ls: $_" -Level "WARN"
    }

    # --- .NET/NuGet: scan user NuGet cache and *.csproj files ---
    try {
        # Check user-level NuGet package cache
        $nugetCachePath = Join-Path $env:USERPROFILE ".nuget\packages"
        if (Test-Path $nugetCachePath) {
            Write-Log "Scanning NuGet package cache..."
            $nugetPackages = Get-ChildItem -Path $nugetCachePath -Directory -ErrorAction SilentlyContinue
            foreach ($pkg in $nugetPackages) {
                $versions = Get-ChildItem -Path $pkg.FullName -Directory -ErrorAction SilentlyContinue |
                    Sort-Object Name -Descending | Select-Object -First 1
                if ($versions) {
                    $dependencies += @{
                        vendor = "NuGet"
                        product = $pkg.Name
                        version = $versions.Name
                        path = $pkg.FullName
                        source_type = "code_library"
                        ecosystem = "nuget"
                    }
                }
            }
        }

        # Scan common project directories for .csproj files with PackageReference
        $projectScanPaths = @()
        if ($env:USERPROFILE) {
            $devPaths = @("source", "repos", "projects", "dev", "src", "Documents\source", "Documents\repos", "Documents\projects")
            foreach ($devPath in $devPaths) {
                $fullPath = Join-Path $env:USERPROFILE $devPath
                if (Test-Path $fullPath) { $projectScanPaths += $fullPath }
            }
        }

        foreach ($scanPath in $projectScanPaths) {
            $csprojFiles = Get-ChildItem -Path $scanPath -Filter "*.csproj" -Recurse -Depth 4 -ErrorAction SilentlyContinue | Select-Object -First 100
            foreach ($csproj in $csprojFiles) {
                try {
                    if ($csproj.Attributes.HasFlag([IO.FileAttributes]::ReparsePoint)) { continue }
                    $xmlSettings = New-Object System.Xml.XmlReaderSettings
                    $xmlSettings.DtdProcessing = [System.Xml.DtdProcessing]::Prohibit
                    $xmlSettings.XmlResolver = $null
                    $csprojContent = Get-Content $csproj.FullName -Raw -ErrorAction SilentlyContinue
                    $csprojReader = [System.Xml.XmlReader]::Create((New-Object System.IO.StringReader($csprojContent)), $xmlSettings)
                    $csprojXml = New-Object System.Xml.XmlDocument
                    $csprojXml.Load($csprojReader)
                    $packageRefs = $csprojXml.SelectNodes("//PackageReference")
                    foreach ($ref in $packageRefs) {
                        $pkgName = $ref.GetAttribute("Include")
                        $pkgVersion = $ref.GetAttribute("Version")
                        if ($pkgName) {
                            $dependencies += @{
                                vendor = "NuGet"
                                product = $pkgName
                                version = if ($pkgVersion) { $pkgVersion } else { $null }
                                path = $csproj.FullName
                                source_type = "code_library"
                                ecosystem = "nuget"
                            }
                        }
                    }
                }
                catch {
                    # Silently skip malformed csproj files
                }
            }
        }
    }
    catch {
        Write-Log "Failed to scan NuGet dependencies: $_" -Level "WARN"
    }

    # --- Rust: cargo install --list ---
    try {
        $cargoExe = Get-Command cargo -ErrorAction SilentlyContinue
        if ($cargoExe) {
            Write-Log "Running cargo install --list for Rust packages..."
            $cargoOutput = & cargo install --list 2>&1
            if ($LASTEXITCODE -eq 0 -and $cargoOutput) {
                foreach ($line in $cargoOutput) {
                    # Lines like: "ripgrep v14.1.0:"
                    if ($line -match '^(\S+)\s+v([\d.]+)') {
                        $dependencies += @{
                            vendor = "crates.io"
                            product = $Matches[1]
                            version = $Matches[2]
                            path = $null
                            source_type = "code_library"
                            ecosystem = "rust"
                        }
                    }
                }
            }
        }
    }
    catch {
        Write-Log "Failed to run cargo install --list: $_" -Level "WARN"
    }

    # --- Composer: composer global show ---
    try {
        $composerExe = Get-Command composer -ErrorAction SilentlyContinue
        if ($composerExe) {
            Write-Log "Running composer global show for PHP packages..."
            $composerOutput = & composer global show --format=json 2>&1
            if ($LASTEXITCODE -eq 0 -and $composerOutput) {
                try {
                    $composerJson = $composerOutput | Out-String | ConvertFrom-Json
                    if ($composerJson.installed) {
                        foreach ($pkg in $composerJson.installed) {
                            $dependencies += @{
                                vendor = "Packagist"
                                product = $pkg.name
                                version = if ($pkg.version) { ($pkg.version -replace '^v', '') } else { $null }
                                path = $null
                                source_type = "code_library"
                                ecosystem = "composer"
                            }
                        }
                    }
                }
                catch {
                    Write-Log "Failed to parse composer output: $_" -Level "WARN"
                }
            }
        }
    }
    catch {
        Write-Log "Failed to run composer global show: $_" -Level "WARN"
    }

    # --- Scan common project directories for lock files / manifests ---
    try {
        $projectScanPaths = @()
        if ($env:USERPROFILE) {
            $devPaths = @("source", "repos", "projects", "dev", "src", "Documents\source", "Documents\repos", "Documents\projects")
            foreach ($devPath in $devPaths) {
                $fullPath = Join-Path $env:USERPROFILE $devPath
                if (Test-Path $fullPath) { $projectScanPaths += $fullPath }
            }
        }

        foreach ($scanPath in $projectScanPaths) {
            # Node.js: package-lock.json
            $lockFiles = Get-ChildItem -Path $scanPath -Filter "package-lock.json" -Recurse -Depth 3 -ErrorAction SilentlyContinue | Select-Object -First 50
            foreach ($lockFile in $lockFiles) {
                try {
                    $lockJson = Get-Content $lockFile.FullName -Raw -ErrorAction SilentlyContinue | ConvertFrom-Json
                    if ($lockJson.dependencies) {
                        $lockJson.dependencies.PSObject.Properties | ForEach-Object {
                            # Skip deeply nested deps, only top-level
                            $dependencies += @{
                                vendor = "npm"
                                product = $_.Name
                                version = if ($_.Value.version) { $_.Value.version } else { $null }
                                path = $lockFile.DirectoryName
                                source_type = "code_library"
                                ecosystem = "nodejs"
                            }
                        }
                    }
                }
                catch {
                    Write-Log "Failed to parse $($lockFile.FullName): $_" -Level "WARN"
                }
            }

            # Python: requirements.txt
            $reqFiles = Get-ChildItem -Path $scanPath -Filter "requirements.txt" -Recurse -Depth 3 -ErrorAction SilentlyContinue | Select-Object -First 50
            foreach ($reqFile in $reqFiles) {
                try {
                    $lines = Get-Content $reqFile.FullName -ErrorAction SilentlyContinue
                    foreach ($line in $lines) {
                        $line = $line.Trim()
                        # Skip comments and empty lines
                        if (!$line -or $line.StartsWith("#") -or $line.StartsWith("-")) { continue }
                        if ($line -match '^([A-Za-z0-9_.-]+)\s*==\s*(.+)$') {
                            $dependencies += @{
                                vendor = "PyPI"
                                product = $Matches[1]
                                version = $Matches[2].Trim()
                                path = $reqFile.DirectoryName
                                source_type = "code_library"
                                ecosystem = "python"
                            }
                        }
                        elseif ($line -match '^([A-Za-z0-9_.-]+)\s*[><=!~]') {
                            $pkgName = $Matches[1]
                            $dependencies += @{
                                vendor = "PyPI"
                                product = $pkgName
                                version = $null
                                path = $reqFile.DirectoryName
                                source_type = "code_library"
                                ecosystem = "python"
                            }
                        }
                        elseif ($line -match '^([A-Za-z0-9_.-]+)\s*$') {
                            $dependencies += @{
                                vendor = "PyPI"
                                product = $Matches[1]
                                version = $null
                                path = $reqFile.DirectoryName
                                source_type = "code_library"
                                ecosystem = "python"
                            }
                        }
                    }
                }
                catch {
                    Write-Log "Failed to parse $($reqFile.FullName): $_" -Level "WARN"
                }
            }
        }
    }
    catch {
        Write-Log "Failed to scan project dependency files: $_" -Level "WARN"
    }

    # Deduplicate by ecosystem+product+version (keep first occurrence)
    $uniqueDeps = @{}
    foreach ($dep in $dependencies) {
        $key = "$($dep.ecosystem)|$($dep.product)|$($dep.version)".ToLower()
        if (!$uniqueDeps.ContainsKey($key)) {
            $uniqueDeps[$key] = $dep
        }
    }

    $result = @($uniqueDeps.Values)
    Write-Log "Found $($result.Count) code dependencies"
    return $result
}

# ============================================================================
# API Communication
# ============================================================================

function Send-Inventory {
    param($Config, $SystemInfo, $Products)

    $endpoint = "$($Config.ServerUrl)/api/agent/inventory"

    # Collect installed Windows KBs for vulnerability confidence scoring
    $installedKBs = @()
    try {
        $hotfixes = Get-HotFix -ErrorAction SilentlyContinue | Select-Object -ExpandProperty HotFixID
        $installedKBs = @($hotfixes | Where-Object { $_ -match '^KB\d+' })
        Write-Log "Collected $($installedKBs.Count) installed KBs"
    } catch {
        Write-Log "Failed to collect installed KBs: $_" -Level "WARN"
    }

    $payload = @{
        hostname = $SystemInfo.hostname
        fqdn = $SystemInfo.fqdn
        ip_address = $SystemInfo.ip_address
        os = $SystemInfo.os
        agent = $SystemInfo.agent
        products = @($Products)
        installed_kbs = $installedKBs
    }

    $jsonPayload = $payload | ConvertTo-Json -Depth 10 -Compress

    Write-Log "Sending inventory to $endpoint ($($Products.Count) products, payload: $([math]::Round($jsonPayload.Length / 1024))KB)..."

    $headers = @{
        "X-Agent-Key" = $Config.ApiKey
        "User-Agent" = "SentriKat-Agent/$AgentVersion (Windows)"
    }

    # Write payload to temp file for large inventories (avoids memory issues)
    $tmpFile = $null
    $useFile = $jsonPayload.Length -gt 100000  # > 100KB use file
    if ($useFile) {
        $tmpFile = [System.IO.Path]::GetTempFileName()
        [System.IO.File]::WriteAllText($tmpFile, $jsonPayload, [System.Text.Encoding]::UTF8)
        Write-Log "Large payload written to temp file"
    }

    $maxRetries = 3
    $retryDelay = 5

    for ($i = 1; $i -le $maxRetries; $i++) {
        try {
            # Use TLS 1.2
            [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

            $bodyContent = if ($useFile) { Get-Content $tmpFile -Raw } else { $jsonPayload }
            # Encode body as UTF-8 bytes explicitly to avoid system default encoding
            # (e.g. Windows-1252 on German Windows) corrupting non-ASCII characters
            $bodyBytes = [System.Text.Encoding]::UTF8.GetBytes($bodyContent)
            $response = Invoke-RestMethod -Uri $endpoint -Method Post -Headers $headers -Body $bodyBytes -ContentType "application/json; charset=utf-8" -TimeoutSec 120

            Write-Log "Inventory sent successfully: $($response.status)"

            if ($response.job_id) {
                Write-Log "Async job queued: $($response.job_id)"
            } elseif ($response.summary) {
                Write-Log "Summary: Created=$($response.summary.products_created), Updated=$($response.summary.products_updated)"
            }

            if ($tmpFile -and (Test-Path $tmpFile)) { Remove-Item $tmpFile -Force -ErrorAction SilentlyContinue }
            return $true
        }
        catch {
            $errorMsg = $_.Exception.Message
            if ($_.Exception.Response) {
                try {
                    $stream = $_.Exception.Response.GetResponseStream()
                    $stream.Position = 0
                    $reader = New-Object System.IO.StreamReader($stream, [System.Text.Encoding]::UTF8)
                    $errorBody = $reader.ReadToEnd()
                    $reader.Close()
                    if ($errorBody) { $errorMsg = "$errorMsg - $errorBody" }
                } catch {
                    # Stream may already be disposed on some PS versions
                }
            }

            Write-Log "Attempt $i failed: $errorMsg" -Level "WARN"

            if ($i -lt $maxRetries) {
                Write-Log "Retrying in $retryDelay seconds..."
                Start-Sleep -Seconds $retryDelay
                $retryDelay *= 2
            }
        }
    }

    if ($tmpFile -and (Test-Path $tmpFile)) { Remove-Item $tmpFile -Force -ErrorAction SilentlyContinue }
    Write-Log "Failed to send inventory after $maxRetries attempts" -Level "ERROR"
    return $false
}

function Send-Heartbeat {
    param($Config, $SystemInfo)

    $endpoint = "$($Config.ServerUrl)/api/agent/heartbeat"

    $payload = @{
        hostname = $SystemInfo.hostname
        agent_id = $SystemInfo.agent.id
        agent_version = $AgentVersion
    }

    $headers = @{
        "X-Agent-Key" = $Config.ApiKey
        "User-Agent" = "SentriKat-Agent/$AgentVersion (Windows)"
    }

    try {
        [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
        $bodyBytes = [System.Text.Encoding]::UTF8.GetBytes(($payload | ConvertTo-Json))
        $response = Invoke-RestMethod -Uri $endpoint -Method Post -Headers $headers -Body $bodyBytes -ContentType "application/json; charset=utf-8" -TimeoutSec 30
        return $true
    }
    catch {
        # Extract error body from response for better diagnostics
        $errorDetail = $_.Exception.Message
        if ($_.Exception.Response) {
            try {
                $stream = $_.Exception.Response.GetResponseStream()
                $stream.Position = 0
                $reader = New-Object System.IO.StreamReader($stream, [System.Text.Encoding]::UTF8)
                $errorBody = $reader.ReadToEnd()
                $reader.Close()
                if ($errorBody) { $errorDetail = "$errorDetail - $errorBody" }
            } catch {}
        }
        Write-Log "Heartbeat failed: $errorDetail" -Level "WARN"
        return $false
    }
}

function Update-Agent {
    param($Config, [string]$TargetVersion)

    # Auto-update the agent script from the server
    # Flow: download -> verify -> backup -> replace -> log
    $downloadUrl = "$($Config.ServerUrl)/api/agent/download/windows"
    $scriptPath = "$env:ProgramData\SentriKat\sentrikat-agent.ps1"
    $backupPath = "$env:ProgramData\SentriKat\sentrikat-agent.backup.$AgentVersion.ps1"

    Write-Log "Auto-updating agent: $AgentVersion -> $TargetVersion"

    try {
        $headers = @{
            "X-Agent-Key" = $Config.ApiKey
            "User-Agent" = "SentriKat-Agent/$AgentVersion (Windows)"
        }

        # Download new script to temp file
        $tmpFile = [System.IO.Path]::GetTempFileName() + ".ps1"
        [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
        Invoke-WebRequest -Uri $downloadUrl -Headers $headers -OutFile $tmpFile -TimeoutSec 60

        # Verify downloaded script is valid PowerShell (contains expected marker)
        $content = Get-Content $tmpFile -Raw
        if ($content -notmatch 'AgentVersion') {
            Write-Log "Downloaded file missing AgentVersion marker - aborting update" -Level "ERROR"
            Remove-Item $tmpFile -Force -ErrorAction SilentlyContinue
            return
        }

        # Backup current script
        if (Test-Path $scriptPath) {
            Copy-Item $scriptPath $backupPath -Force
            Write-Log "Backed up current agent to $backupPath"
        }

        # Replace the script
        Move-Item $tmpFile $scriptPath -Force
        Write-Log "Agent updated successfully to $TargetVersion"
    }
    catch {
        Write-Log "Agent update failed: $_" -Level "ERROR"
        Remove-Item $tmpFile -Force -ErrorAction SilentlyContinue
        # Restore backup if available
        if (Test-Path $backupPath) {
            Copy-Item $backupPath $scriptPath -Force
            Write-Log "Restored backup agent"
        }
    }
}

function Check-Commands {
    param($Config, $SystemInfo)

    # Poll the server for pending commands
    $endpoint = "$($Config.ServerUrl)/api/agent/commands?agent_id=$($SystemInfo.agent.id)&hostname=$($SystemInfo.hostname)&version=$AgentVersion&platform=windows"

    Write-Log "Checking for commands from server..."

    $headers = @{
        "X-Agent-Key" = $Config.ApiKey
        "User-Agent" = "SentriKat-Agent/$AgentVersion (Windows)"
    }

    try {
        [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
        $response = Invoke-RestMethod -Uri $endpoint -Method Get -Headers $headers -TimeoutSec 30

        $scanRequested = $false

        foreach ($cmd in $response.commands) {
            switch ($cmd.command) {
                "scan_now" {
                    Write-Log "Received scan_now command - triggering immediate inventory scan"
                    $scanRequested = $true
                }
                "update_config" {
                    Write-Log "Received config update command"
                    if ($cmd.config.scan_interval_minutes) {
                        $newInterval = $cmd.config.scan_interval_minutes
                        if ($newInterval -ge 15 -and $newInterval -ne $Config.IntervalMinutes) {
                            Write-Log "Updating scan interval from $($Config.IntervalMinutes) to $newInterval minutes"
                            $Config.IntervalMinutes = $newInterval
                            Save-AgentConfig $Config
                            # Note: Would need to reinstall scheduled task to apply new interval
                        }
                    }
                    # Handle scan_capabilities from config update
                    if ($cmd.config.scan_capabilities) {
                        $caps = $cmd.config.scan_capabilities
                        $configChanged = $false
                        if ($null -ne $caps.scan_extensions) {
                            $newVal = [bool]$caps.scan_extensions
                            if ($newVal -ne $Config.ScanExtensions) {
                                Write-Log "Updating ScanExtensions: $($Config.ScanExtensions) -> $newVal"
                                $Config.ScanExtensions = $newVal
                                $configChanged = $true
                            }
                        }
                        if ($null -ne $caps.scan_dependencies) {
                            $newVal = [bool]$caps.scan_dependencies
                            if ($newVal -ne $Config.ScanDependencies) {
                                Write-Log "Updating ScanDependencies: $($Config.ScanDependencies) -> $newVal"
                                $Config.ScanDependencies = $newVal
                                $configChanged = $true
                            }
                        }
                        if ($configChanged) {
                            Save-AgentConfig $Config
                        }
                    }
                }
                "scan_capabilities" {
                    Write-Log "Received scan_capabilities command"
                    $configChanged = $false
                    if ($null -ne $cmd.scan_extensions) {
                        $newVal = [bool]$cmd.scan_extensions
                        if ($newVal -ne $Config.ScanExtensions) {
                            Write-Log "Updating ScanExtensions: $($Config.ScanExtensions) -> $newVal"
                            $Config.ScanExtensions = $newVal
                            $configChanged = $true
                        }
                    }
                    if ($null -ne $cmd.scan_dependencies) {
                        $newVal = [bool]$cmd.scan_dependencies
                        if ($newVal -ne $Config.ScanDependencies) {
                            Write-Log "Updating ScanDependencies: $($Config.ScanDependencies) -> $newVal"
                            $Config.ScanDependencies = $newVal
                            $configChanged = $true
                        }
                    }
                    if ($configChanged) {
                        Save-AgentConfig $Config
                        $scanRequested = $true
                    }
                }
                "update_available" {
                    Write-Log "Agent update available: $($cmd.current_version) -> $($cmd.latest_version)" -Level "WARN"
                    Update-Agent -Config $Config -TargetVersion $cmd.latest_version
                }
            }
        }

        return $scanRequested
    }
    catch {
        Write-Log "Failed to check commands: $_" -Level "WARN"
        return $false
    }
}

# ============================================================================
# Container Image Scanning (Trivy Integration)
# ============================================================================

$TrivyBin = "$env:ProgramData\SentriKat\trivy.exe"
$TrivyCacheDir = "$env:ProgramData\SentriKat\trivy-cache"
# Offline mode: set $env:TRIVY_OFFLINE = "true" to skip download attempts.
# Pre-deploy trivy.exe to $env:ProgramData\SentriKat\trivy.exe and optionally
# pre-download DB with: trivy.exe image --download-db-only --cache-dir <cache-dir>
$TrivyOffline = $env:TRIVY_OFFLINE -eq "true"

function Test-DockerAvailable {
    try {
        $null = Get-Command docker -ErrorAction Stop
        $info = docker info 2>&1
        return $LASTEXITCODE -eq 0
    } catch {
        return $false
    }
}

function Install-Trivy {
    if (Test-Path $TrivyBin) {
        Write-Log "Trivy found at $TrivyBin"
        return $true
    }

    # Check if trivy is already in PATH (e.g. installed via scoop/chocolatey)
    $existingTrivy = Get-Command trivy -ErrorAction SilentlyContinue
    if ($existingTrivy) {
        $script:TrivyBin = $existingTrivy.Source
        Write-Log "Trivy found in PATH at $script:TrivyBin"
        return $true
    }

    # Offline mode: don't attempt download
    if ($TrivyOffline) {
        Write-Log "Trivy not found and TRIVY_OFFLINE=true. Pre-deploy trivy.exe to $TrivyBin" -Level "WARN"
        Write-Log "Download from: https://github.com/aquasecurity/trivy/releases" -Level "WARN"
        return $false
    }

    Write-Log "Installing Trivy for container image scanning..."

    # Create cache directory
    New-Item -ItemType Directory -Path $TrivyCacheDir -Force -ErrorAction SilentlyContinue | Out-Null

    try {
        # Detect architecture
        $arch = if ([Environment]::Is64BitOperatingSystem) { "64bit" } else { "32bit" }

        # Download pinned Trivy version (not "latest" to avoid surprises)
        $trivyVersion = "0.58.2"
        $downloadUrl = "https://github.com/aquasecurity/trivy/releases/download/v$trivyVersion/trivy_${trivyVersion}_Windows-$arch.zip"

        $tmpDir = Join-Path $env:TEMP "trivy-install-$(Get-Random)"
        New-Item -ItemType Directory -Path $tmpDir -Force | Out-Null

        Write-Log "Downloading Trivy v$trivyVersion..."
        [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
        $zipPath = Join-Path $tmpDir "trivy.zip"
        Invoke-WebRequest -Uri $downloadUrl -OutFile $zipPath -TimeoutSec 120

        Expand-Archive -Path $zipPath -DestinationPath $tmpDir -Force

        $trivyExe = Get-ChildItem -Path $tmpDir -Filter "trivy.exe" -Recurse | Select-Object -First 1
        if ($trivyExe) {
            Copy-Item $trivyExe.FullName $TrivyBin -Force
            Write-Log "Trivy v$trivyVersion installed successfully"
            Remove-Item $tmpDir -Recurse -Force -ErrorAction SilentlyContinue
            return $true
        }

        Write-Log "Failed to install Trivy" -Level "WARN"
        Remove-Item $tmpDir -Recurse -Force -ErrorAction SilentlyContinue
        return $false
    }
    catch {
        Write-Log "Failed to install Trivy: $_" -Level "WARN"
        Write-Log "For offline deployment, pre-install trivy.exe to $TrivyBin" -Level "WARN"
        return $false
    }
}

function Get-ContainerImages {
    $images = @()

    if (Test-DockerAvailable) {
        $dockerImages = docker images --format "{{.Repository}}:{{.Tag}}|{{.ID}}|{{.Size}}" 2>&1
        foreach ($line in $dockerImages) {
            if ($line -and $line -notmatch '<none>' -and $line -match '\|') {
                $images += $line
            }
        }
    }

    return $images
}

function Invoke-ContainerScan {
    param($Config, $SystemInfo)

    # Check if Docker is available
    if (-not (Test-DockerAvailable)) {
        Write-Log "No container runtime detected, skipping container scan"
        return
    }

    Write-Log "Starting container image scan..."

    # Install Trivy if needed
    if (-not (Install-Trivy)) {
        Write-Log "Trivy not available, skipping container scan" -Level "WARN"
        return
    }

    # Get list of images
    $imageList = Get-ContainerImages
    if ($imageList.Count -eq 0) {
        Write-Log "No container images found"
        return
    }

    $scanResults = @()
    $imageCount = 0

    foreach ($imageLine in $imageList) {
        $parts = $imageLine -split '\|'
        $imageRef = $parts[0]
        $imageId = if ($parts.Count -gt 1) { $parts[1].Substring(0, [Math]::Min(12, $parts[1].Length)) } else { "" }

        Write-Log "Scanning container image: $imageRef"

        try {
            # Run Trivy scan
            $trivyOutput = & $TrivyBin image --format json --severity HIGH,CRITICAL --cache-dir $TrivyCacheDir --quiet --timeout 5m $imageRef 2>&1

            if ($LASTEXITCODE -ne 0) {
                Write-Log "Trivy scan failed for $imageRef" -Level "WARN"
                continue
            }

            $imageName = ($imageRef -split ':')[0]
            $imageTag = if ($imageRef -match ':(.+)$') { $Matches[1] } else { "latest" }

            # Parse Trivy JSON output
            $trivyJson = $trivyOutput | ConvertFrom-Json

            $scanResults += @{
                image_name = $imageName
                image_tag = $imageTag
                image_id = $imageId
                trivy_output = $trivyJson
            }

            $imageCount++

            # Limit to 50 images
            if ($imageCount -ge 50) {
                Write-Log "Reached 50 image limit, skipping remaining" -Level "WARN"
                break
            }
        }
        catch {
            Write-Log "Error scanning $imageRef : $_" -Level "WARN"
        }
    }

    if ($imageCount -eq 0) {
        Write-Log "No images scanned successfully"
        return
    }

    Write-Log "Scanned $imageCount container images"

    # Get Trivy version
    $trivyVersion = "unknown"
    try {
        $versionOutput = & $TrivyBin --version 2>&1
        if ($versionOutput -match '(\d+\.\d+\.\d+)') {
            $trivyVersion = $Matches[1]
        }
    } catch {}

    # Send results to server
    $payload = @{
        agent_id = $SystemInfo.agent.id
        hostname = $SystemInfo.hostname
        scanner = "trivy"
        scanner_version = $trivyVersion
        images = $scanResults
    }

    $jsonPayload = $payload | ConvertTo-Json -Depth 20 -Compress
    $endpoint = "$($Config.ServerUrl)/api/agent/container-scan"

    $headers = @{
        "X-Agent-Key" = $Config.ApiKey
        "User-Agent" = "SentriKat-Agent/$AgentVersion (Windows)"
    }

    try {
        [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
        $bodyBytes = [System.Text.Encoding]::UTF8.GetBytes($jsonPayload)
        $response = Invoke-RestMethod -Uri $endpoint -Method Post -Headers $headers -Body $bodyBytes -ContentType "application/json; charset=utf-8" -TimeoutSec 120
        Write-Log "Container scan results sent successfully"
    }
    catch {
        Write-Log "Failed to send container scan results: $_" -Level "WARN"
    }
}

# ============================================================================
# Installation Functions
# ============================================================================

function Install-ScheduledTask {
    param($Config)

    Write-Log "Installing scheduled tasks..."

    # Save config
    Save-AgentConfig $Config

    $scriptPath = $MyInvocation.PSCommandPath
    if (!$scriptPath) {
        $scriptPath = "$env:ProgramData\SentriKat\sentrikat-agent.ps1"
        Copy-Item $PSCommandPath $scriptPath -Force
    }

    # Main inventory scan task
    $action = New-ScheduledTaskAction -Execute "powershell.exe" -Argument "-NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -File `"$scriptPath`" -RunOnce"
    $trigger = New-ScheduledTaskTrigger -Once -At (Get-Date) -RepetitionInterval (New-TimeSpan -Minutes $Config.IntervalMinutes)
    $principal = New-ScheduledTaskPrincipal -UserId "SYSTEM" -LogonType ServiceAccount -RunLevel Highest
    $settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -StartWhenAvailable -RunOnlyIfNetworkAvailable

    Unregister-ScheduledTask -TaskName "SentriKat Agent" -Confirm:$false -ErrorAction SilentlyContinue
    Register-ScheduledTask -TaskName "SentriKat Agent" -Action $action -Trigger $trigger -Principal $principal -Settings $settings -Description "SentriKat Software Inventory Agent"

    # Heartbeat task (every 5 minutes)
    $heartbeatAction = New-ScheduledTaskAction -Execute "powershell.exe" -Argument "-NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -File `"$scriptPath`" -Heartbeat"
    $heartbeatTrigger = New-ScheduledTaskTrigger -Once -At (Get-Date).AddMinutes(2) -RepetitionInterval (New-TimeSpan -Minutes $HeartbeatIntervalMinutes)

    Unregister-ScheduledTask -TaskName "SentriKat Agent Heartbeat" -Confirm:$false -ErrorAction SilentlyContinue
    Register-ScheduledTask -TaskName "SentriKat Agent Heartbeat" -Action $heartbeatAction -Trigger $heartbeatTrigger -Principal $principal -Settings $settings -Description "SentriKat Agent Heartbeat - Checks for commands"

    Write-Log "Scheduled tasks installed successfully"
    Write-Host "SentriKat Agent installed:"
    Write-Host "  - Full scan: every $($Config.IntervalMinutes) minutes"
    Write-Host "  - Heartbeat: every $HeartbeatIntervalMinutes minutes (checks for commands)"
}

function Install-WindowsService {
    param($Config)

    Write-Log "Installing SentriKat as a Windows service..."

    # Save config
    Save-AgentConfig $Config

    $scriptPath = $MyInvocation.PSCommandPath
    if (!$scriptPath) {
        $scriptPath = "$env:ProgramData\SentriKat\sentrikat-agent.ps1"
        Copy-Item $PSCommandPath $scriptPath -Force
    }

    $serviceName = "SentriKatAgent"
    $serviceDisplayName = "SentriKat Agent"
    $serviceDescription = "SentriKat Software Inventory Agent - Collects and reports installed software inventory and checks for commands."

    # Remove existing service if present
    $existing = Get-Service -Name $serviceName -ErrorAction SilentlyContinue
    if ($existing) {
        Write-Log "Removing existing SentriKat service..."
        Stop-Service -Name $serviceName -Force -ErrorAction SilentlyContinue
        & sc.exe delete $serviceName | Out-Null
        Start-Sleep -Seconds 2
    }

    # Also remove scheduled tasks if they exist (switching from task to service mode)
    Unregister-ScheduledTask -TaskName "SentriKat Agent" -Confirm:$false -ErrorAction SilentlyContinue
    Unregister-ScheduledTask -TaskName "SentriKat Agent Heartbeat" -Confirm:$false -ErrorAction SilentlyContinue

    # Create a service wrapper script that runs the agent in a loop
    $wrapperPath = "$env:ProgramData\SentriKat\sentrikat-service.ps1"
    $wrapperContent = @"
# SentriKat Agent Service Wrapper
# This script runs as a Windows service via sc.exe
# It manages both inventory scans and heartbeat polling

`$ErrorActionPreference = "Continue"
`$AgentScript = "$scriptPath"
`$HeartbeatInterval = $HeartbeatIntervalMinutes
`$ScanInterval = $($Config.IntervalMinutes)
`$LogFile = "$env:ProgramData\SentriKat\service.log"

function Write-ServiceLog(`$msg) {
    `$ts = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    Add-Content -Path `$LogFile -Value "[`$ts] `$msg" -ErrorAction SilentlyContinue
}

Write-ServiceLog "SentriKat service wrapper started"

`$lastScan = [DateTime]::MinValue
`$lastHeartbeat = [DateTime]::MinValue

while (`$true) {
    try {
        `$now = Get-Date

        # Run heartbeat every `$HeartbeatInterval minutes
        if ((`$now - `$lastHeartbeat).TotalMinutes -ge `$HeartbeatInterval) {
            Write-ServiceLog "Running heartbeat..."
            & powershell.exe -NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -File `$AgentScript -Heartbeat 2>&1 | Out-Null
            `$lastHeartbeat = `$now
        }

        # Run full scan every `$ScanInterval minutes
        if ((`$now - `$lastScan).TotalMinutes -ge `$ScanInterval) {
            Write-ServiceLog "Running full inventory scan..."
            & powershell.exe -NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -File `$AgentScript -RunOnce 2>&1 | Out-Null
            `$lastScan = `$now
        }

        Start-Sleep -Seconds 60
    } catch {
        Write-ServiceLog "Error: `$_"
        Start-Sleep -Seconds 30
    }
}
"@
    Set-Content -Path $wrapperPath -Value $wrapperContent -Force

    # Create the service using sc.exe with powershell.exe as the binary
    $binPath = "powershell.exe -NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -File `"$wrapperPath`""

    & sc.exe create $serviceName binPath= $binPath start= auto DisplayName= $serviceDisplayName
    & sc.exe description $serviceName $serviceDescription
    & sc.exe failure $serviceName reset= 86400 actions= restart/60000/restart/120000/restart/300000

    # Start the service
    Start-Service -Name $serviceName -ErrorAction SilentlyContinue

    $svc = Get-Service -Name $serviceName -ErrorAction SilentlyContinue
    if ($svc -and $svc.Status -eq 'Running') {
        Write-Log "Windows service '$serviceDisplayName' installed and running"
        Write-Host "SentriKat Agent installed as Windows service:"
        Write-Host "  - Service name: $serviceName"
        Write-Host "  - Full scan: every $($Config.IntervalMinutes) minutes"
        Write-Host "  - Heartbeat: every $HeartbeatIntervalMinutes minutes"
        Write-Host "  - View in services.msc or: Get-Service $serviceName"
    } else {
        Write-Log "Windows service created but may need manual start" -Level "WARN"
        Write-Host "SentriKat Agent service created. Start manually:"
        Write-Host "  Start-Service $serviceName"
    }
}

function Uninstall-Agent {
    Write-Log "Uninstalling agent..."

    # Remove Windows service if exists
    $serviceName = "SentriKatAgent"
    $existing = Get-Service -Name $serviceName -ErrorAction SilentlyContinue
    if ($existing) {
        Stop-Service -Name $serviceName -Force -ErrorAction SilentlyContinue
        & sc.exe delete $serviceName | Out-Null
        Write-Log "Windows service removed"
    }

    # Remove scheduled tasks
    Unregister-ScheduledTask -TaskName "SentriKat Agent" -Confirm:$false -ErrorAction SilentlyContinue
    Unregister-ScheduledTask -TaskName "SentriKat Agent Heartbeat" -Confirm:$false -ErrorAction SilentlyContinue

    # Remove service wrapper script
    Remove-Item "$env:ProgramData\SentriKat\sentrikat-service.ps1" -Force -ErrorAction SilentlyContinue

    # Remove config and logs (optional)
    # Remove-Item "$env:ProgramData\SentriKat" -Recurse -Force -ErrorAction SilentlyContinue

    Write-Log "Agent uninstalled"
    Write-Host "SentriKat Agent uninstalled (service and scheduled tasks removed)"
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
    if ($InstallService) {
        Install-WindowsService $config
        return
    }

    if ($Install) {
        Install-ScheduledTask $config

        # Run first inventory immediately so the asset appears in the dashboard
        Write-Host "Running initial inventory scan..."
        Write-Log "Running initial inventory scan after install..."
        try {
            $systemInfo = Get-SystemInfo
            $products = Get-InstalledSoftware

            # Include extensions and dependencies in initial scan if enabled
            if ($config.ScanExtensions) {
                try {
                    $extensions = Get-Extensions
                    if ($extensions.Count -gt 0) { $products = @($products) + @($extensions) }
                } catch {
                    Write-Log "Extension scanning failed during initial scan: $_" -Level "WARN"
                }
            }
            if ($config.ScanDependencies) {
                try {
                    $deps = Get-CodeDependencies
                    if ($deps.Count -gt 0) { $products = @($products) + @($deps) }
                } catch {
                    Write-Log "Dependency scanning failed during initial scan: $_" -Level "WARN"
                }
            }

            if ($products.Count -gt 0) {
                $success = Send-Inventory $config $systemInfo $products
                if ($success) {
                    Write-Host "Initial scan complete - agent is now visible in SentriKat dashboard"
                    Write-Log "Initial inventory sent successfully"
                } else {
                    Write-Host "Initial scan failed - agent will retry on next scheduled scan"
                    Write-Log "Initial inventory failed, will retry on next scheduled run" -Level "WARN"
                }
            }
        } catch {
            Write-Log "Initial inventory scan failed: $_" -Level "WARN"
            Write-Host "Initial scan failed - agent will retry on next scheduled scan"
        }
        return
    }

    if ($Uninstall) {
        Uninstall-Agent
        return
    }

    # Handle heartbeat mode
    if ($Heartbeat) {
        Write-Log "Running heartbeat check..."
        $systemInfo = Get-SystemInfo

        # Send heartbeat to keep agent online in dashboard
        Send-Heartbeat $config $systemInfo

        # Check for pending commands (scan_now, update, etc.)
        $scanRequested = Check-Commands $config $systemInfo

        if ($scanRequested) {
            Write-Log "Executing requested scan..."
            # Continue to run full inventory below
        } else {
            Write-Log "Heartbeat complete - no scan requested"
            return
        }
    }

    # Collect and send inventory
    try {
        $systemInfo = Get-SystemInfo
        Write-Log "System: $($systemInfo.hostname) ($($systemInfo.os.version))"

        $products = Get-InstalledSoftware

        # VSCode extension scanning (conditional)
        if ($config.ScanExtensions) {
            try {
                $extensions = Get-Extensions
                if ($extensions.Count -gt 0) {
                    $products = @($products) + @($extensions)
                    Write-Log "Added $($extensions.Count) extensions to inventory"
                }
            }
            catch {
                Write-Log "Extension scanning failed (non-fatal): $_" -Level "WARN"
            }
        }

        # Code dependency scanning (conditional)
        if ($config.ScanDependencies) {
            try {
                $deps = Get-CodeDependencies
                if ($deps.Count -gt 0) {
                    $products = @($products) + @($deps)
                    Write-Log "Added $($deps.Count) code dependencies to inventory"
                }
            }
            catch {
                Write-Log "Code dependency scanning failed (non-fatal): $_" -Level "WARN"
            }
        }

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

        # Run container image scan (if Docker available)
        try {
            Invoke-ContainerScan $config $systemInfo
        } catch {
            Write-Log "Container scanning encountered issues (non-fatal): $_" -Level "WARN"
        }
    }
    catch {
        Write-Log "Fatal error: $_" -Level "ERROR"
        exit 1
    }
}

# Run
Main
