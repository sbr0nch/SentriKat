# SentriKat Push Agents

Lightweight agents that collect software inventory from endpoints and report to a SentriKat server.

## Overview

Push agents run on your endpoints (servers, workstations) and periodically scan for installed software. They send this inventory to your SentriKat server where it's matched against known vulnerabilities (CISA KEV).

## Requirements

### Windows Agent
- Windows 10/11 or Windows Server 2016+
- PowerShell 5.1 or higher
- Network access to SentriKat server

### Linux Agent
- Linux with bash 4.0+
- `curl` for API communication
- Package manager (dpkg, rpm, apk, or pacman)
- systemd (for service installation)
- Network access to SentriKat server

## Quick Start

### 1. Create an Agent API Key

In SentriKat web interface:
1. Go to **Integrations** > **Push Agents**
2. Click **Create API Key**
3. Select your organization
4. Name the key (e.g., "Production Servers")
5. Save the generated key (it won't be shown again!)

### 2. Deploy the Agent

All agents support multiple modes:
- **One-shot mode** (default): Run once, collect and send inventory, then exit. No installation needed.
- **Service mode** (`--install`): Set up as a persistent background service with recurring scans and heartbeats.
- **Windows Service mode** (`-InstallService`, Windows only): Register as a Windows service visible in `services.msc` with auto-restart on failure.

#### Windows (PowerShell)

```powershell
# One-shot run (no installation required, run as Administrator)
powershell -ExecutionPolicy Bypass -File .\sentrikat-agent-windows.ps1

# Test run with verbose output
.\sentrikat-agent-windows.ps1 -ServerUrl "https://sentrikat.example.com" -ApiKey "sk_agent_xxx" -Verbose

# Install as scheduled task (runs every 4 hours + heartbeat every 5 min)
.\sentrikat-agent-windows.ps1 -Install -ServerUrl "https://sentrikat.example.com" -ApiKey "sk_agent_xxx"

# Install as Windows service (visible in services.msc, auto-restart on failure)
.\sentrikat-agent-windows.ps1 -InstallService -ServerUrl "https://sentrikat.example.com" -ApiKey "sk_agent_xxx"

# Check service status
Get-Service SentriKatAgent

# Uninstall (removes both service and scheduled tasks)
.\sentrikat-agent-windows.ps1 -Uninstall
```

#### Linux (Bash)

```bash
# Make executable
chmod +x sentrikat-agent-linux.sh

# One-shot run (no installation required)
sudo ./sentrikat-agent-linux.sh

# Test run with verbose output
./sentrikat-agent-linux.sh --server-url "https://sentrikat.example.com" --api-key "sk_agent_xxx" --verbose

# Install as systemd service (runs every 4 hours + heartbeat every 5 min)
sudo ./sentrikat-agent-linux.sh --install --server-url "https://sentrikat.example.com" --api-key "sk_agent_xxx"

# Check status
systemctl status sentrikat-agent.timer

# Uninstall
sudo ./sentrikat-agent-linux.sh --uninstall
```

#### macOS (Bash)

```bash
# Make executable
chmod +x sentrikat-agent-macos.sh

# One-shot run (no installation required)
sudo ./sentrikat-agent-macos.sh

# Test run with verbose output
./sentrikat-agent-macos.sh --server-url "https://sentrikat.example.com" --api-key "sk_agent_xxx" --verbose

# Install as LaunchDaemon (runs every 4 hours + heartbeat every 5 min)
sudo ./sentrikat-agent-macos.sh --install --server-url "https://sentrikat.example.com" --api-key "sk_agent_xxx"

# Check status
sudo launchctl list | grep sentrikat

# Uninstall
sudo ./sentrikat-agent-macos.sh --uninstall
```

### Multi-Organization Deployment

When creating an API key, you can optionally select **additional organizations**. Software reported by agents using that key will appear in all selected organizations independently (without mixing data between them). This is useful when:

- A single infrastructure serves multiple departments or clients
- You want the same inventory visible to different teams
- A managed service provider deploys agents for multiple customers

## Configuration

### Windows
Configuration is stored at: `C:\ProgramData\SentriKat\config.json`

### Linux
Configuration is stored at: `/etc/sentrikat/agent.conf`

### macOS
Configuration is stored at: `/Library/Application Support/SentriKat/agent.conf`

### Config Options

| Option | Description | Default |
|--------|-------------|---------|
| `ServerUrl` | SentriKat server URL | (required) |
| `ApiKey` | Agent API key | (required) |
| `IntervalHours` | Hours between scans | 4 |
| `AgentId` | Unique agent identifier | Auto-generated |

## What Gets Collected

### Windows
- Installed programs from Windows Registry (Add/Remove Programs)
- 32-bit and 64-bit applications
- Windows Features and Roles (on Server editions)
- **Installed KBs/Hotfixes** (for automatic vendor patch detection)

### Linux
- Packages from system package manager:
  - Debian/Ubuntu: dpkg
  - RHEL/CentOS/Fedora: rpm
  - Alpine: apk
  - Arch: pacman
- **Full distro package versions** (e.g., `2.4.52-1ubuntu4.6` for backport detection)
- Snap packages
- Flatpak packages

### Vendor Backport Detection

SentriKat agents collect distro-specific package version strings and installed patches to enable **automatic false-positive detection**. When a vendor backports a security fix into an existing version (e.g., Ubuntu patches Apache 2.4.52 in-place), SentriKat automatically:

1. Detects the full distro package version from the agent
2. Cross-references vendor advisory feeds (OSV.dev, Red Hat, MSRC, Debian)
3. Removes the false-positive CVE match from the dashboard, emails, and webhooks

The agent inventory payload now supports these optional fields:

```json
{
  "products": [
    {
      "vendor": "Apache",
      "product": "HTTP Server",
      "version": "2.4.52",
      "path": "/usr/sbin/apache2",
      "distro_package_version": "2.4.52-1ubuntu4.6"
    }
  ],
  "installed_kbs": ["KB5040442", "KB5034763"]
}
```

- `distro_package_version`: Full distro-specific version string (Linux agents)
- `installed_kbs`: List of installed KB article IDs (Windows agents)

## API Endpoints

The agent communicates with the following SentriKat API endpoints:

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/api/agent/inventory` | POST | Submit software inventory |
| `/api/agent/heartbeat` | POST | Send keepalive signal |
| `/api/agent/commands` | GET | Poll for pending commands (scan, update) |
| `/api/agent/download/{platform}` | GET | Download latest agent script for auto-update |
| `/api/agent/jobs/{id}` | GET | Check async job status |

## Security

- API keys are stored securely with restricted file permissions
- All communication uses HTTPS (TLS 1.2+)
- Agents run with minimal privileges where possible
- No sensitive data is collected (only software names/versions)

## Troubleshooting

### Check Logs

**Windows:**
```powershell
Get-Content C:\ProgramData\SentriKat\agent.log -Tail 50
```

**Linux:**
```bash
tail -50 /var/log/sentrikat-agent.log
# or
journalctl -u sentrikat-agent
```

### Common Issues

1. **Connection refused**: Check firewall rules and ensure SentriKat server is accessible
2. **401 Unauthorized**: Verify API key is correct and active
3. **No products found**: Ensure agent has permission to query package managers

### Manual Test

Run with verbose output to diagnose issues:

**Windows:**
```powershell
.\sentrikat-agent-windows.ps1 -ServerUrl "..." -ApiKey "..." -Verbose -RunOnce
```

**Linux:**
```bash
./sentrikat-agent-linux.sh --server-url "..." --api-key "..." --verbose --run-once
```

## Large Deployments

For deployments with >100 software packages per endpoint:
- Inventory is queued for background processing
- Agent receives job ID for status tracking
- Background worker processes batches to avoid timeouts

## License

Part of SentriKat - see main LICENSE file.
