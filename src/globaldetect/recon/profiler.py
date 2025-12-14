"""
Comprehensive Target Profiling.

Combines multiple reconnaissance techniques to build a complete
target profile.

Copyright (c) 2025 DNS Science.io, an After Dark Systems, LLC company.
All rights reserved.
"""

import asyncio
from dataclasses import dataclass, field
from typing import Any

from globaldetect.recon.scanner import (
    HostDiscovery,
    PortScanner,
    ServiceDetector,
    HostInfo,
    PortInfo,
    ServiceInfo,
)
from globaldetect.recon.ssl_analyzer import SSLAnalyzer, CertificateInfo
from globaldetect.dns import lookup_all, reverse_lookup
from globaldetect.ip import get_ip_info, is_bogon
from globaldetect.services.dnsscience import DNSScienceClient
from globaldetect.services.ipinfo import IPInfoClient
from globaldetect.config import get_config


@dataclass
class TargetProfile:
    """Comprehensive target profile."""
    target: str
    target_type: str = "unknown"  # ip, hostname, domain, network
    is_alive: bool = False

    # Network info
    ip_addresses: list[str] = field(default_factory=list)
    hostnames: list[str] = field(default_factory=list)
    reverse_dns: str | None = None

    # IP intelligence
    asn: int | None = None
    as_name: str | None = None
    country: str | None = None
    is_bogon: bool = False
    is_private: bool = False

    # DNS records
    dns_records: dict[str, list[str]] = field(default_factory=dict)
    nameservers: list[str] = field(default_factory=list)
    mx_records: list[str] = field(default_factory=list)

    # Open ports and services
    open_ports: list[PortInfo] = field(default_factory=list)
    services: list[ServiceInfo] = field(default_factory=list)

    # SSL/TLS
    ssl_info: CertificateInfo | None = None
    ssl_grade: str | None = None

    # Web technologies (if HTTP detected)
    web_server: str | None = None
    web_technologies: list[str] = field(default_factory=list)

    # Security observations
    security_issues: list[str] = field(default_factory=list)
    recommendations: list[str] = field(default_factory=list)

    # Threat intelligence (from DNS Science)
    threat_intel: dict[str, Any] = field(default_factory=dict)
    risk_score: int = 0
    is_malicious: bool = False
    blacklists: list[str] = field(default_factory=list)

    # Email security (from DNS Science)
    spf_record: str | None = None
    dmarc_record: str | None = None
    dkim_valid: bool = False
    email_security_score: str | None = None

    # Subdomains (from DNS Science)
    subdomains: list[str] = field(default_factory=list)

    # WHOIS info (from DNS Science)
    registrar: str | None = None
    creation_date: str | None = None
    expiration_date: str | None = None

    # Timing
    scan_duration_seconds: float = 0.0


class TargetProfiler:
    """Build comprehensive target profiles."""

    def __init__(
        self,
        port_scan: bool = True,
        service_detect: bool = True,
        ssl_analyze: bool = True,
        dns_lookup: bool = True,
        use_dnsscience: bool = True,
        use_ipinfo: bool = True,
        timeout: float = 10.0,
        concurrency: int = 50,
    ):
        self.port_scan = port_scan
        self.service_detect = service_detect
        self.ssl_analyze = ssl_analyze
        self.dns_lookup = dns_lookup
        self.use_dnsscience = use_dnsscience
        self.use_ipinfo = use_ipinfo
        self.timeout = timeout
        self.concurrency = concurrency

        self.host_discovery = HostDiscovery(timeout=timeout)
        self.port_scanner = PortScanner(timeout=timeout, concurrency=concurrency)
        self.service_detector = ServiceDetector(timeout=timeout)
        self.ssl_analyzer = SSLAnalyzer(timeout=timeout)

        # Initialize API clients if keys are available
        config = get_config()
        self.dnsscience_client = DNSScienceClient() if config.dnsscience_api_key else None
        self.ipinfo_client = IPInfoClient() if config.ipinfo_token else None

    def _detect_target_type(self, target: str) -> str:
        """Detect what type of target was provided."""
        import re
        from netaddr import IPAddress, IPNetwork

        # Check if it's a CIDR network
        if "/" in target:
            try:
                IPNetwork(target)
                return "network"
            except:
                pass

        # Check if it's an IP address
        try:
            IPAddress(target)
            return "ip"
        except:
            pass

        # Check if it's a hostname/domain
        if re.match(r"^[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z]{2,})+$", target):
            # Check if it has subdomain
            parts = target.split(".")
            if len(parts) > 2 and parts[0] not in ["www", "mail", "ftp"]:
                return "hostname"
            return "domain"

        return "unknown"

    async def profile_async(self, target: str) -> TargetProfile:
        """Build a comprehensive target profile."""
        import time
        import socket

        start_time = time.monotonic()

        profile = TargetProfile(target=target)
        profile.target_type = self._detect_target_type(target)

        # Resolve target to IP(s)
        if profile.target_type in ("hostname", "domain"):
            try:
                # DNS resolution
                results = socket.getaddrinfo(target, None, socket.AF_UNSPEC, socket.SOCK_STREAM)
                profile.ip_addresses = list(set(r[4][0] for r in results))
                profile.hostnames.append(target)

                # Get DNS records
                if self.dns_lookup:
                    dns_records = lookup_all(target)
                    for rtype, records in dns_records.items():
                        profile.dns_records[rtype] = [r.value for r in records]

                    if "NS" in profile.dns_records:
                        profile.nameservers = profile.dns_records["NS"]
                    if "MX" in profile.dns_records:
                        profile.mx_records = profile.dns_records["MX"]

            except Exception:
                pass

        elif profile.target_type == "ip":
            profile.ip_addresses = [target]

            # Reverse DNS
            try:
                rdns = reverse_lookup(target)
                if rdns:
                    profile.reverse_dns = rdns[0]
                    profile.hostnames.append(rdns[0])
            except:
                pass

        # Get IP intelligence for first IP
        if profile.ip_addresses:
            ip = profile.ip_addresses[0]
            try:
                ip_info = get_ip_info(ip)
                profile.is_bogon = ip_info.is_bogon
                profile.is_private = ip_info.is_private
                profile.country = None  # Would come from IPInfo service
            except:
                pass

        # Host discovery
        if profile.ip_addresses:
            ip = profile.ip_addresses[0]
            host_info = await self.host_discovery.ping_host_async(ip)
            profile.is_alive = host_info.is_alive

        # Port scanning
        if profile.is_alive and self.port_scan and profile.ip_addresses:
            ip = profile.ip_addresses[0]
            profile.open_ports = await self.port_scanner.scan_host_async(ip)

            # Security observations
            open_port_nums = [p.port for p in profile.open_ports if p.state == "open"]

            if 23 in open_port_nums:
                profile.security_issues.append("Telnet (port 23) is open - unencrypted protocol")
                profile.recommendations.append("Disable Telnet and use SSH instead")

            if 21 in open_port_nums:
                profile.security_issues.append("FTP (port 21) is open - consider SFTP")

            if 3389 in open_port_nums:
                profile.security_issues.append("RDP (port 3389) exposed to internet")
                profile.recommendations.append("Use VPN or restrict RDP access")

        # Service detection
        if self.service_detect and profile.open_ports:
            ip = profile.ip_addresses[0]
            open_port_nums = [p.port for p in profile.open_ports if p.state == "open"]
            profile.services = await self.service_detector.detect_services_async(
                ip, open_port_nums[:20]  # Limit to first 20
            )

            # Extract web server
            for svc in profile.services:
                if svc.port in [80, 443, 8080, 8443] and svc.product:
                    profile.web_server = f"{svc.product} {svc.version or ''}"
                    break

        # SSL analysis
        if self.ssl_analyze and profile.ip_addresses:
            # Check if HTTPS is open
            has_https = any(p.port == 443 and p.state == "open" for p in profile.open_ports)
            if has_https:
                target_host = profile.hostnames[0] if profile.hostnames else profile.ip_addresses[0]
                profile.ssl_info = await self.ssl_analyzer.analyze_async(target_host, 443)
                profile.ssl_grade = self.ssl_analyzer.grade_certificate(profile.ssl_info)

                if profile.ssl_info:
                    if profile.ssl_info.is_expired:
                        profile.security_issues.append("SSL certificate is expired")
                        profile.recommendations.append("Renew SSL certificate immediately")
                    elif profile.ssl_info.days_remaining and profile.ssl_info.days_remaining < 30:
                        profile.security_issues.append(
                            f"SSL certificate expires in {profile.ssl_info.days_remaining} days"
                        )
                        profile.recommendations.append("Plan SSL certificate renewal")

                    if profile.ssl_info.is_self_signed:
                        profile.security_issues.append("SSL certificate is self-signed")

        # DNS Science API integration - enrich with threat intel and email security
        if self.use_dnsscience and self.dnsscience_client and profile.target_type in ("hostname", "domain"):
            try:
                # Get threat intelligence
                threat_result = await self.dnsscience_client.get_threat_intel_async(target)
                if not threat_result.error:
                    profile.is_malicious = threat_result.is_malicious
                    profile.risk_score = threat_result.risk_score
                    profile.blacklists = threat_result.blacklists
                    profile.threat_intel = {
                        "threat_types": threat_result.threat_types,
                        "sources": threat_result.sources,
                        "first_seen": threat_result.first_seen,
                        "last_seen": threat_result.last_seen,
                    }

                    if threat_result.is_malicious:
                        profile.security_issues.append(f"MALICIOUS: Domain flagged as malicious (score: {threat_result.risk_score})")
                    elif threat_result.risk_score > 50:
                        profile.security_issues.append(f"SUSPICIOUS: Elevated risk score ({threat_result.risk_score})")

                # Get email security info
                email_security = await self.dnsscience_client.check_email_security_async(target)
                if email_security:
                    profile.spf_record = email_security.get("spf")
                    profile.dmarc_record = email_security.get("dmarc")
                    profile.dkim_valid = email_security.get("dkim_valid", False)
                    profile.email_security_score = email_security.get("score")

                    if not profile.spf_record:
                        profile.security_issues.append("Missing SPF record - email spoofing risk")
                        profile.recommendations.append("Configure SPF record for email authentication")
                    if not profile.dmarc_record:
                        profile.security_issues.append("Missing DMARC record - email spoofing risk")
                        profile.recommendations.append("Configure DMARC policy for email protection")

                # Get subdomain enumeration (limited)
                subdomain_result = await self.dnsscience_client.enumerate_subdomains_async(target)
                if not subdomain_result.error:
                    profile.subdomains = subdomain_result.subdomains[:50]  # Limit to 50

                # Get WHOIS info
                whois_data = await self.dnsscience_client.get_whois_async(target)
                if whois_data:
                    profile.registrar = whois_data.get("registrar")
                    profile.creation_date = whois_data.get("creation_date")
                    profile.expiration_date = whois_data.get("expiration_date")

            except Exception:
                pass  # DNS Science API not available or error

        # IPInfo enrichment
        if self.use_ipinfo and self.ipinfo_client and profile.ip_addresses:
            try:
                ip = profile.ip_addresses[0]
                ipinfo_result = await self.ipinfo_client.lookup_async(ip)
                if not ipinfo_result.error:
                    profile.country = ipinfo_result.country
                    profile.asn = ipinfo_result.asn
                    profile.as_name = ipinfo_result.as_name

                    # Check privacy flags
                    if ipinfo_result.is_vpn:
                        profile.security_issues.append("IP is associated with VPN service")
                    if ipinfo_result.is_tor:
                        profile.security_issues.append("IP is a Tor exit node")
                    if ipinfo_result.is_proxy:
                        profile.security_issues.append("IP is associated with proxy service")

            except Exception:
                pass  # IPInfo API not available

        profile.scan_duration_seconds = time.monotonic() - start_time
        return profile

    def profile(self, target: str) -> TargetProfile:
        """Synchronous target profiling."""
        return asyncio.run(self.profile_async(target))

    async def profile_batch_async(self, targets: list[str]) -> list[TargetProfile]:
        """Profile multiple targets concurrently."""
        tasks = [self.profile_async(target) for target in targets]
        return await asyncio.gather(*tasks)

    def profile_batch(self, targets: list[str]) -> list[TargetProfile]:
        """Synchronous batch profiling."""
        return asyncio.run(self.profile_batch_async(targets))

    def generate_report(self, profile: TargetProfile) -> str:
        """Generate a text report from a profile."""
        lines = []
        lines.append(f"=" * 60)
        lines.append(f"TARGET PROFILE: {profile.target}")
        lines.append(f"=" * 60)
        lines.append("")

        lines.append(f"Type: {profile.target_type}")
        lines.append(f"Status: {'ALIVE' if profile.is_alive else 'DOWN'}")
        lines.append(f"Scan Duration: {profile.scan_duration_seconds:.2f}s")
        lines.append("")

        if profile.ip_addresses:
            lines.append("IP ADDRESSES:")
            for ip in profile.ip_addresses:
                lines.append(f"  - {ip}")
            lines.append("")

        if profile.hostnames:
            lines.append("HOSTNAMES:")
            for host in profile.hostnames:
                lines.append(f"  - {host}")
            lines.append("")

        if profile.dns_records:
            lines.append("DNS RECORDS:")
            for rtype, values in profile.dns_records.items():
                lines.append(f"  {rtype}:")
                for val in values[:5]:
                    lines.append(f"    - {val}")
            lines.append("")

        if profile.open_ports:
            lines.append("OPEN PORTS:")
            for port in profile.open_ports:
                if port.state == "open":
                    svc = port.service or "unknown"
                    lines.append(f"  - {port.port}/{port.protocol} ({svc})")
            lines.append("")

        if profile.services:
            lines.append("DETECTED SERVICES:")
            for svc in profile.services:
                if svc.product:
                    ver = svc.version or ""
                    lines.append(f"  - Port {svc.port}: {svc.product} {ver}")
            lines.append("")

        if profile.ssl_info and profile.ssl_info.is_valid:
            lines.append("SSL/TLS CERTIFICATE:")
            lines.append(f"  Grade: {profile.ssl_grade}")
            lines.append(f"  Subject: {profile.ssl_info.subject.get('commonName', 'N/A')}")
            lines.append(f"  Issuer: {profile.ssl_info.issuer.get('organizationName', 'N/A')}")
            if profile.ssl_info.days_remaining:
                lines.append(f"  Expires: {profile.ssl_info.days_remaining} days")
            lines.append("")

        if profile.security_issues:
            lines.append("SECURITY ISSUES:")
            for issue in profile.security_issues:
                lines.append(f"  [!] {issue}")
            lines.append("")

        if profile.recommendations:
            lines.append("RECOMMENDATIONS:")
            for rec in profile.recommendations:
                lines.append(f"  - {rec}")
            lines.append("")

        return "\n".join(lines)
