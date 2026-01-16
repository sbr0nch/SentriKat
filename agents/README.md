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

#### Windows (PowerShell)

```powershell
# Test run (verbose)
.\sentrikat-agent-windows.ps1 -ServerUrl "https://sentrikat.example.com" -ApiKey "sk_agent_xxx" -Verbose

# Install as scheduled task (runs every 4 hours)
.\sentrikat-agent-windows.ps1 -Install -ServerUrl "https://sentrikat.example.com" -ApiKey "sk_agent_xxx"

# Uninstall
.\sentrikat-agent-windows.ps1 -Uninstall
```

#### Linux (Bash)

```bash
# Make executable
chmod +x sentrikat-agent-linux.sh

# Test run (verbose)
./sentrikat-agent-linux.sh --server-url "https://sentrikat.example.com" --api-key "sk_agent_xxx" --verbose

# Install as systemd service (runs every 4 hours)
sudo ./sentrikat-agent-linux.sh --install --server-url "https://sentrikat.example.com" --api-key "sk_agent_xxx"

# Check status
systemctl status sentrikat-agent.timer

# Uninstall
sudo ./sentrikat-agent-linux.sh --uninstall
```

## Configuration

### Windows
Configuration is stored at: `C:\ProgramData\SentriKat\config.json`

### Linux
Configuration is stored at: `/etc/sentrikat/agent.conf`

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

### Linux
- Packages from system package manager:
  - Debian/Ubuntu: dpkg
  - RHEL/CentOS/Fedora: rpm
  - Alpine: apk
  - Arch: pacman
- Snap packages
- Flatpak packages

## API Endpoints

The agent communicates with the following SentriKat API endpoints:

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/api/agent/inventory` | POST | Submit software inventory |
| `/api/agent/heartbeat` | POST | Send keepalive signal |
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
