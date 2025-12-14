# Installation Guide

## Requirements

- Python 3.10 or higher
- pip (Python package manager)
- Git (for cloning the repository)

## Command Names

After installation, the following commands will be available (all are identical):

- `dnsscience-globalconnect` - Primary command name
- `globalconnect` - Short alias
- `dnsscience-globaldetect` - Legacy name
- `globaldetect` - Legacy short alias

## Quick Install

```bash
# Clone the repository
git clone https://github.com/dnsscience/globaldetect.git
cd globaldetect

# Run the installer
./install.sh
```

## Installation Methods

### Method 1: Virtual Environment (Development)

Install to a local virtual environment in the current directory:

```bash
# Using the installer
./install.sh --venv

# Or manually
python3 -m venv venv
source venv/bin/activate
pip install -e .
```

After installation, activate the environment:
```bash
source venv/bin/activate
globalconnect --help
```

### Method 2: System-Wide Installation

Install to `/usr/local/globaldetect` with symlinks in `/usr/local/bin`:

```bash
# Requires sudo
./install.sh --system

# With all optional extras
./install.sh --system --extras all
```

This creates:
- `/usr/local/globaldetect/` - Installation directory with venv
- `/usr/local/bin/dnsscience-globalconnect` - Primary command (symlink)
- `/usr/local/bin/globalconnect` - Alias (symlink)
- `/usr/local/bin/dnsscience-globaldetect` - Legacy alias (symlink)
- `/usr/local/bin/globaldetect` - Legacy alias (symlink)

### Method 3: User Installation

Install to `~/.local/globaldetect` without requiring sudo:

```bash
./install.sh --user

# With extras
./install.sh --user --extras enterprise,backup
```

Add `~/.local/bin` to your PATH if not already present:
```bash
echo 'export PATH="$HOME/.local/bin:$PATH"' >> ~/.bashrc
source ~/.bashrc
```

### Method 4: Using pip (When Published)

```bash
pip install dnsscience-globalconnect
```

## Optional Extras

Install additional features using `--extras`:

| Extra | Description |
|-------|-------------|
| `dev` | Development tools (pytest, black, ruff, mypy) |
| `enterprise` | Enterprise features (encryption, PostgreSQL) |
| `server` | REST API server mode (Flask) |
| `backup` | Device backup features (SSH, NETCONF, REST) |
| `all` | All optional extras |

Examples:
```bash
./install.sh --system --extras enterprise,backup
./install.sh --venv --extras dev
./install.sh --user --extras all
```

## Configuration

### Environment Variables

Create a `.env` file or export environment variables:

```bash
# IPInfo.io - IP geolocation and ASN data
IPINFO_TOKEN=your_ipinfo_token

# AbuseIPDB - IP reputation data
ABUSEIPDB_API_KEY=your_abuseipdb_key

# Cloudflare - DNS and Radar API access
CLOUDFLARE_API_TOKEN=your_cloudflare_token

# DNS Science.io - Threat intelligence
DNSSCIENCE_API_KEY=your_dnsscience_key

# Have I Been Pwned (optional)
HIBP_API_KEY=your_hibp_key

# Database (optional, defaults to SQLite)
GLOBALDETECT_DB=postgresql://user:pass@localhost/inventory
```

### Getting API Keys

1. **IPInfo.io**: Sign up at https://ipinfo.io/signup
2. **AbuseIPDB**: Register at https://www.abuseipdb.com/register
3. **Cloudflare**: Create an API token at https://dash.cloudflare.com/profile/api-tokens
4. **DNS Science.io**: Contact support@dnsscience.io
5. **HIBP**: Get API key at https://haveibeenpwned.com/API/Key

## Platform-Specific Notes

### macOS

```bash
# If you have Homebrew Python
/usr/local/bin/python3 -m venv venv

# Or use the installer which auto-detects
./install.sh
```

### Linux (Ubuntu/Debian)

```bash
# Install Python 3.10+ if needed
sudo apt update
sudo apt install python3.10 python3.10-venv python3-pip

# Run installer
./install.sh --system
```

### Linux (CentOS/RHEL)

```bash
# Install Python 3.10+ if needed
sudo dnf install python3.10

# Run installer
./install.sh --system
```

### Windows

Windows is supported with PowerShell:

```powershell
# Create virtual environment
python -m venv venv

# Activate
.\venv\Scripts\Activate

# Install
pip install -e .
```

## Verifying Installation

```bash
# Check version
globalconnect --version

# Test IP tools
globalconnect ip info 8.8.8.8

# Test DNS tools
globalconnect dns query google.com

# Test BGP tools
globalconnect bgp asinfo 15169

# List all commands
globalconnect --help
```

## Uninstalling

### Virtual Environment
```bash
rm -rf venv
```

### System Installation
```bash
./install.sh --uninstall --system
```

### User Installation
```bash
./install.sh --uninstall --user
```

## Updating

```bash
cd globaldetect
git pull

# For venv install
source venv/bin/activate
pip install -e . --upgrade

# For system install
./install.sh --system

# For user install
./install.sh --user
```

## Troubleshooting

### "Command not found" Error

For venv installations, ensure it's activated:
```bash
source venv/bin/activate
```

For user installations, ensure `~/.local/bin` is in PATH:
```bash
export PATH="$HOME/.local/bin:$PATH"
```

### Import Errors

Reinstall dependencies:
```bash
pip install -e . --force-reinstall
```

### Permission Errors

Some commands require root/sudo:
```bash
# Neighbor discovery
sudo globalconnect neighbors discover

# DHCP client
sudo globalconnect dhcp obtain -i eth0

# Packet crafting (SYN/ARP scans)
sudo globalconnect packet syn-scan target.com 22,80,443
```

### API Key Errors

Verify environment variables:
```bash
echo $IPINFO_TOKEN
cat .env
```
