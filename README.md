# GlobalDetect

ISP Network Engineering Utilities - A comprehensive CLI toolkit for network engineers providing tools for IP/CIDR management, BGP analysis, DNS utilities, diagnostics, and security intelligence.

## Features

### IP/CIDR Tools (`globaldetect ip`)
- **info** - Get detailed information about an IP address (supports `--geoip` for full geolocation)
- **calc** - Subnet calculator with network/broadcast/usable range
- **split** - Split CIDR blocks into smaller subnets
- **merge** - Merge adjacent CIDR blocks
- **bogon** - Check if an IP is a bogon (reserved/private)
- **contains** - Check if an IP is within a CIDR range

### BGP/Routing (`globaldetect bgp`)
- **asinfo** - Get AS information (name, country, prefixes)
- **prefixes** - List prefixes announced by an AS
- **peers** - Get peering information from PeeringDB
- **whois** - BGP WHOIS lookup

### DNS Utilities (`globaldetect dns`)
- **query** - DNS lookups with any record type
- **propagation** - Check DNS propagation across global resolvers
- **trace** - Trace DNS delegation chain
- **mx** - Mail server lookup with priority
- **reverse** - Reverse DNS (PTR) lookup

### Diagnostics (`globaldetect diag`)
- **ping** - ICMP ping with statistics
- **traceroute** - Network path tracing (supports `--geoip` for geolocation of each hop)
- **mtu** - MTU path discovery
- **port** - TCP port connectivity check

### Reconnaissance (`globaldetect recon`)
- **scan** - Port scanning with service detection
- **ssl** - SSL/TLS certificate analysis and grading
- **profile** - Comprehensive target profiling

### RBL/Blacklist (`globaldetect rbl`)
- **check** - Check IP against 50+ RBL providers
- **batch** - Batch check multiple IPs
- **list** - List all supported RBL providers

Supported providers include: Spamhaus, Barracuda, SpamCop, SORBS, UCEProtect, Proofpoint, SenderBase (Cisco/IronPort), and many more.

### Dark Web Intelligence (`globaldetect darkweb`)
- **tor** - Check if IP is a Tor exit node
- **check** - Comprehensive dark web association check
- **batch** - Batch Tor exit check

### External Services (`globaldetect services`)
- **ipinfo** - IPInfo.io lookup
- **abuse** - AbuseIPDB reputation check
- **cloudflare** - Cloudflare DNS and Radar API
- **dnsscience** - DNS Science.io threat intelligence

## Installation

See [INSTALL.md](INSTALL.md) for detailed installation instructions.

### Quick Start

```bash
# Clone the repository
git clone https://github.com/dnsscience/globaldetect.git
cd globaldetect

# Create virtual environment (requires Python 3.10+)
python3 -m venv venv
source venv/bin/activate

# Install in development mode
pip install -e .

# Run
globaldetect --help
```

## Configuration

GlobalDetect uses environment variables for API keys. Create a `.env` file or export them:

```bash
export IPINFO_TOKEN="your_token"
export ABUSEIPDB_API_KEY="your_key"
export CLOUDFLARE_API_TOKEN="your_token"
export DNSSCIENCE_API_KEY="your_key"
```

## Usage Examples

```bash
# IP Information
globaldetect ip info 8.8.8.8
globaldetect ip info 8.8.8.8 --geoip      # Include full GeoIP data
globaldetect ip calc 10.0.0.0/24
globaldetect ip bogon 192.168.1.1

# BGP Analysis
globaldetect bgp asinfo 15169
globaldetect bgp prefixes 15169
globaldetect bgp peers 15169

# DNS Utilities
globaldetect dns query google.com
globaldetect dns propagation example.com --type A
globaldetect dns trace example.com

# Diagnostics
globaldetect diag ping 8.8.8.8
globaldetect diag trace google.com
globaldetect diag trace 1.1.1.1 --geoip   # Traceroute with GeoIP for each hop
globaldetect diag port 8.8.8.8 443

# Reconnaissance
globaldetect recon scan 192.168.1.1 --ports 22,80,443
globaldetect recon ssl google.com
globaldetect recon profile example.com

# RBL/Blacklist
globaldetect rbl check 1.2.3.4
globaldetect rbl batch 1.2.3.4 5.6.7.8

# Dark Web Intelligence
globaldetect darkweb tor 185.220.101.1
globaldetect darkweb check suspicious-domain.com
```

## Requirements

- Python 3.10+
- Dependencies: click, netaddr, dnspython, rich, httpx, python-dotenv

## License

MIT License - Copyright (c) 2025 DNS Science.io, an After Dark Systems, LLC company.

See [LICENSE](LICENSE) for details.

## Contributing

Contributions are welcome! Please read our contributing guidelines and submit pull requests.

## Support

- GitHub Issues: https://github.com/dnsscience/globaldetect/issues
- Documentation: https://dnsscience.io/docs/globaldetect
