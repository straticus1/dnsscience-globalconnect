# Installation Guide

## Requirements

- Python 3.10 or higher
- pip (Python package manager)
- Git (for cloning the repository)

## Installation Methods

### Method 1: From Source (Recommended for Development)

```bash
# Clone the repository
git clone https://github.com/dnsscience/globaldetect.git
cd globaldetect

# Create a virtual environment
python3 -m venv venv

# Activate the virtual environment
# On macOS/Linux:
source venv/bin/activate
# On Windows:
# venv\Scripts\activate

# Install in development mode
pip install -e .

# Verify installation
globaldetect --version
```

### Method 2: Using pip (When Published)

```bash
pip install globaldetect
```

### Method 3: Using the Wrapper Script

For development, you can use the included wrapper script that automatically loads environment variables:

```bash
# Make the wrapper executable
chmod +x globaldetect

# Run directly
./globaldetect --help
```

## Configuration

### Environment Variables

GlobalDetect uses environment variables for API credentials. You can set them in your shell or create a `.env` file in the project root.

#### Required for Full Functionality:

```bash
# IPInfo.io - IP geolocation and ASN data
IPINFO_TOKEN=your_ipinfo_token

# AbuseIPDB - IP reputation data
ABUSEIPDB_API_KEY=your_abuseipdb_key

# Cloudflare - DNS and Radar API access
CLOUDFLARE_API_TOKEN=your_cloudflare_token

# DNS Science.io - Threat intelligence
DNSSCIENCE_API_KEY=your_dnsscience_key
```

#### Example .env file:

```bash
# GlobalDetect Configuration
IPINFO_TOKEN=abc123
ABUSEIPDB_API_KEY=def456
CLOUDFLARE_API_TOKEN=ghi789
DNSSCIENCE_API_KEY=jkl012
```

### Getting API Keys

1. **IPInfo.io**: Sign up at https://ipinfo.io/signup
2. **AbuseIPDB**: Register at https://www.abuseipdb.com/register
3. **Cloudflare**: Create an API token at https://dash.cloudflare.com/profile/api-tokens
4. **DNS Science.io**: Contact support@dnsscience.io

## Platform-Specific Notes

### macOS

If you have multiple Python versions installed:

```bash
# Use specific Python version
/usr/local/bin/python3.12 -m venv venv
source venv/bin/activate
pip install -e .
```

### Linux

Install Python 3.10+ if not available:

```bash
# Ubuntu/Debian
sudo apt update
sudo apt install python3.10 python3.10-venv python3-pip

# CentOS/RHEL
sudo dnf install python3.10
```

### Windows

```powershell
# Create virtual environment
python -m venv venv

# Activate
venv\Scripts\activate

# Install
pip install -e .
```

## Verifying Installation

After installation, test the core functionality:

```bash
# Check version
globaldetect --version

# Test IP tools
globaldetect ip info 8.8.8.8

# Test DNS tools
globaldetect dns query google.com

# Test BGP tools
globaldetect bgp asinfo 15169
```

## Troubleshooting

### "Command not found" Error

Ensure the virtual environment is activated:
```bash
source venv/bin/activate
```

Or use the full path:
```bash
./venv/bin/globaldetect --help
```

### Import Errors

Reinstall dependencies:
```bash
pip install -e . --force-reinstall
```

### Permission Errors (Diagnostics)

Some diagnostic commands require elevated privileges:
```bash
# For ping/traceroute on some systems
sudo globaldetect diag ping 8.8.8.8
```

### API Key Errors

Verify your environment variables are set:
```bash
echo $IPINFO_TOKEN
echo $ABUSEIPDB_API_KEY
```

## Updating

To update to the latest version:

```bash
cd globaldetect
git pull
pip install -e . --upgrade
```

## Uninstalling

```bash
pip uninstall globaldetect
rm -rf /path/to/globaldetect  # Remove source directory
```
