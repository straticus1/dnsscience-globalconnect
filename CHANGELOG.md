# Changelog

All notable changes to GlobalDetect will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.0] - 2025-12-14

### Added

#### Core Features
- Initial release of GlobalDetect CLI toolkit
- Modular architecture with library + CLI structure
- Full IPv4 and IPv6 support across all modules

#### IP/CIDR Tools (`globaldetect ip`)
- IP information lookup with geolocation and ASN data
- Subnet calculator with network details
- CIDR splitting and merging utilities
- Bogon detection (RFC 1918, RFC 5737, documentation, etc.)
- IP containment checking

#### BGP/Routing (`globaldetect bgp`)
- AS information lookup via BGPView API
- Prefix listing for autonomous systems
- PeeringDB integration for peering data
- BGP WHOIS functionality

#### DNS Utilities (`globaldetect dns`)
- DNS query tool supporting all record types
- DNS propagation checking across 15+ global resolvers
- DNS delegation trace
- MX record lookup with priority sorting
- Reverse DNS (PTR) lookups

#### Diagnostics (`globaldetect diag`)
- ICMP ping with statistics
- Traceroute with AS path resolution
- MTU path discovery
- TCP port connectivity testing

#### Reconnaissance (`globaldetect recon`)
- Async port scanner with configurable concurrency
- Service detection via banner grabbing
- SSL/TLS certificate analysis with security grading
- Comprehensive target profiling

#### RBL/Blacklist (`globaldetect rbl`)
- Support for 50+ RBL providers
- Major providers: Spamhaus, Barracuda, SpamCop, SORBS, UCEProtect
- Proofpoint and SenderBase (Cisco/IronPort) support
- Batch checking for multiple IPs
- Detailed listing status and categories

#### Dark Web Intelligence (`globaldetect darkweb`)
- Tor exit node detection via multiple sources
- DNSBL-based Tor checking
- Tor Project API integration (OnionOO)
- Comprehensive dark web association analysis
- Proxy and anonymizer detection
- Risk scoring system

#### External Service Integrations
- IPInfo.io client for IP geolocation
- AbuseIPDB client for IP reputation
- Cloudflare DNS and Radar API client
- DNS Science.io threat intelligence client

#### Infrastructure
- Connection pooling for HTTP clients
- Async/await patterns throughout
- Structured logging support
- Environment-based configuration
- Rich terminal output formatting

### Technical Details
- Python 3.10+ required
- Key dependencies: click, netaddr, dnspython, rich, httpx, python-dotenv
- MIT License

## [Unreleased]

### Added

#### Facilities / Data Center Management (`globaldetect facility`)
- PeeringDB API integration for global data center information
- 5,800+ facilities with carrier and network presence data
- Tier classification (1-4) based on network presence count
- Region filtering (NA, SA, EU, APAC, MEA)
- Search by CLLI code, site code, owner, country, state
- SQLite caching with incremental sync
- Automated sync via cron (every 6 hours)

#### DHCP Client (`globaldetect dhcp`)
- Full DHCP DORA process (Discover-Offer-Request-Ack)
- DHCP lease obtain, release, and renew operations
- Option 82 (Relay Agent Information) parsing for debugging
- PXE boot option support and display
- Verbose debugging mode for troubleshooting
- DHCP server discovery on network

#### Netcat with Encryption (`globaldetect nc`)
- Full netcat functionality with TLS/SSL support
- Encryption modes: yes (force TLS), no (plaintext), auto (try TLS, fallback)
- Client connect mode with send/receive
- Server listen mode for incoming connections
- Port scanning capability
- UDP support

#### Packet Crafting & Protocol Testing (`globaldetect packet`)
- User-friendly packet crafting with pre-built templates
- Protocol listing with requirements and parameters
- NTP server testing (works without scapy)
- Ping with ICMP and TCP fallback
- TCP connection testing with banner grab
- SYN scan (half-open scan, requires scapy + root)
- ARP scan for local network discovery (requires scapy + root)
- Support for ICMP, TCP, UDP, ARP, DNS protocol templates

#### Routing Protocol Support (`globaldetect routing`)
- BGP session management and monitoring
- OSPF neighbor discovery and LSA parsing
- IS-IS adjacency monitoring
- Route table analysis

#### Firewall Rule Parsing (`globaldetect firewall`)
- Multi-vendor firewall rule parsing
- Support for Cisco ASA, Palo Alto, Juniper SRX, FortiGate
- Rule analysis and conflict detection
- ACL to object-group conversion

#### Device Config Backup Collectors
- A10 load balancer backup collector
- F5 BIG-IP backup collector
- Extended backup framework support

#### Have I Been Pwned Integration (`globaldetect hibp`)
- Email breach checking (requires API key)
- Password checking with k-anonymity (no API key needed)
- Batch email/password checking
- Breach database queries
- Paste appearance checking

#### Secrets Management (`globaldetect secrets`)
- Multi-backend secrets storage (SQLite, PostgreSQL, Aurora, RDS)
- Lyft Confidant integration with fallback support
- MFA support (TOTP, S/KEY, RADIUS, RSA SecurID, Azure MFA)
- SSH key generation and management
- Unix password file generation

### Changed
- CDP (Cisco Discovery Protocol) v2 neighbor discovery
- LLDP (Link Layer Discovery Protocol) neighbor discovery
- Combined listener for simultaneous CDP/LLDP capture
- Network interface enumeration

### Planned
- Additional threat intelligence integrations
- WHOIS lookup functionality
- Network topology mapping
- Configuration file support
- Output format options (JSON, CSV)
