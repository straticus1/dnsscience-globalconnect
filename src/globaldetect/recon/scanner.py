"""
Network scanning functionality.

Implements host discovery, port scanning, and service detection
using pure Python (no nmap dependency).
"""

import asyncio
import socket
import struct
import time
from dataclasses import dataclass, field
from typing import AsyncIterator

from netaddr import IPNetwork, IPAddress


# Well-known service ports for identification
SERVICE_PORTS = {
    21: ("ftp", "File Transfer Protocol"),
    22: ("ssh", "Secure Shell"),
    23: ("telnet", "Telnet"),
    25: ("smtp", "Simple Mail Transfer"),
    53: ("dns", "Domain Name System"),
    80: ("http", "HTTP"),
    110: ("pop3", "Post Office Protocol v3"),
    119: ("nntp", "Network News Transfer"),
    123: ("ntp", "Network Time Protocol"),
    143: ("imap", "Internet Message Access"),
    161: ("snmp", "Simple Network Management"),
    194: ("irc", "Internet Relay Chat"),
    389: ("ldap", "Lightweight Directory Access"),
    443: ("https", "HTTPS"),
    445: ("smb", "Server Message Block"),
    465: ("smtps", "SMTP over SSL"),
    514: ("syslog", "Syslog"),
    587: ("submission", "Email Submission"),
    636: ("ldaps", "LDAP over SSL"),
    993: ("imaps", "IMAP over SSL"),
    995: ("pop3s", "POP3 over SSL"),
    1433: ("mssql", "Microsoft SQL Server"),
    1521: ("oracle", "Oracle Database"),
    2049: ("nfs", "Network File System"),
    3306: ("mysql", "MySQL Database"),
    3389: ("rdp", "Remote Desktop"),
    5432: ("postgresql", "PostgreSQL Database"),
    5900: ("vnc", "Virtual Network Computing"),
    6379: ("redis", "Redis"),
    8080: ("http-proxy", "HTTP Proxy"),
    8443: ("https-alt", "HTTPS Alternate"),
    9200: ("elasticsearch", "Elasticsearch"),
    27017: ("mongodb", "MongoDB"),
}

# Common ports to scan (top 100)
TOP_PORTS = [
    21, 22, 23, 25, 53, 80, 110, 111, 135, 139,
    143, 443, 445, 993, 995, 1433, 1521, 1723, 3306, 3389,
    5432, 5900, 5985, 6379, 8080, 8443, 9200, 27017,
    20, 69, 79, 88, 113, 119, 137, 138, 161, 177,
    179, 199, 389, 427, 465, 500, 514, 515, 548, 554,
    587, 631, 636, 646, 873, 902, 990, 1080, 1099, 1194,
    1352, 1434, 1701, 1883, 2049, 2121, 2181, 2375, 2376, 2483,
    3128, 3268, 3269, 3690, 4333, 4443, 4848, 5000, 5001, 5222,
    5269, 5357, 5601, 5672, 5901, 5984, 6000, 6443, 7001, 7002,
    8000, 8008, 8081, 8088, 8888, 9000, 9090, 9100, 9999, 10000,
]


@dataclass
class HostInfo:
    """Information about a discovered host."""
    ip: str
    is_alive: bool = False
    hostname: str | None = None
    response_time_ms: float = 0.0
    discovery_method: str | None = None


@dataclass
class PortInfo:
    """Information about a scanned port."""
    port: int
    state: str = "unknown"  # open, closed, filtered
    protocol: str = "tcp"
    service: str | None = None
    service_desc: str | None = None
    banner: str | None = None
    response_time_ms: float = 0.0


@dataclass
class ServiceInfo:
    """Detailed service information from banner grabbing."""
    port: int
    protocol: str = "tcp"
    service: str | None = None
    version: str | None = None
    product: str | None = None
    extra_info: str | None = None
    banner: str | None = None
    fingerprint: str | None = None


class HostDiscovery:
    """Host discovery using various probing methods."""

    def __init__(self, timeout: float = 2.0, concurrency: int = 100):
        self.timeout = timeout
        self.concurrency = concurrency

    async def ping_host_async(self, ip: str) -> HostInfo:
        """Check if host is alive using ICMP-like TCP probe."""
        result = HostInfo(ip=ip)
        start = time.monotonic()

        # Try common ports that are usually responsive
        probe_ports = [80, 443, 22, 445, 3389]

        for port in probe_ports:
            try:
                _, writer = await asyncio.wait_for(
                    asyncio.open_connection(ip, port),
                    timeout=self.timeout,
                )
                writer.close()
                await writer.wait_closed()

                result.is_alive = True
                result.response_time_ms = (time.monotonic() - start) * 1000
                result.discovery_method = f"tcp:{port}"
                break
            except (asyncio.TimeoutError, ConnectionRefusedError):
                # Connection refused means host is up but port closed
                result.is_alive = True
                result.response_time_ms = (time.monotonic() - start) * 1000
                result.discovery_method = f"tcp:{port}:refused"
                break
            except Exception:
                continue

        # Try reverse DNS
        if result.is_alive:
            try:
                hostname, _, _ = await asyncio.get_event_loop().run_in_executor(
                    None, socket.gethostbyaddr, ip
                )
                result.hostname = hostname
            except Exception:
                pass

        return result

    async def discover_network_async(self, network: str) -> AsyncIterator[HostInfo]:
        """Discover live hosts in a network (CIDR)."""
        net = IPNetwork(network)

        # Limit scan size
        if net.size > 65536:
            raise ValueError("Network too large. Maximum /16 supported.")

        semaphore = asyncio.Semaphore(self.concurrency)

        async def probe_with_limit(ip: str) -> HostInfo:
            async with semaphore:
                return await self.ping_host_async(ip)

        # Create tasks for all IPs
        tasks = []
        for ip in net:
            # Skip network and broadcast addresses
            if ip == net.network or ip == net.broadcast:
                continue
            tasks.append(probe_with_limit(str(ip)))

        # Process as they complete
        for coro in asyncio.as_completed(tasks):
            result = await coro
            if result.is_alive:
                yield result

    def discover_network(self, network: str) -> list[HostInfo]:
        """Synchronous wrapper for network discovery."""
        async def gather_all():
            results = []
            async for host in self.discover_network_async(network):
                results.append(host)
            return results
        return asyncio.run(gather_all())


class PortScanner:
    """TCP/UDP port scanner."""

    def __init__(
        self,
        timeout: float = 2.0,
        concurrency: int = 100,
        grab_banner: bool = True,
    ):
        self.timeout = timeout
        self.concurrency = concurrency
        self.grab_banner = grab_banner

    async def scan_port_async(self, host: str, port: int, protocol: str = "tcp") -> PortInfo:
        """Scan a single port."""
        result = PortInfo(port=port, protocol=protocol)
        start = time.monotonic()

        if protocol == "tcp":
            try:
                reader, writer = await asyncio.wait_for(
                    asyncio.open_connection(host, port),
                    timeout=self.timeout,
                )

                result.state = "open"
                result.response_time_ms = (time.monotonic() - start) * 1000

                # Get service name
                if port in SERVICE_PORTS:
                    result.service, result.service_desc = SERVICE_PORTS[port]

                # Try banner grabbing
                if self.grab_banner:
                    try:
                        # Send probe for some protocols
                        if port in [21, 22, 25, 110, 143]:
                            # These send banners on connect
                            banner = await asyncio.wait_for(
                                reader.read(1024),
                                timeout=2.0,
                            )
                            result.banner = banner.decode("utf-8", errors="ignore").strip()
                        elif port in [80, 8080]:
                            writer.write(b"HEAD / HTTP/1.0\r\n\r\n")
                            await writer.drain()
                            banner = await asyncio.wait_for(
                                reader.read(1024),
                                timeout=2.0,
                            )
                            result.banner = banner.decode("utf-8", errors="ignore").strip()
                    except Exception:
                        pass

                writer.close()
                await writer.wait_closed()

            except asyncio.TimeoutError:
                result.state = "filtered"
            except ConnectionRefusedError:
                result.state = "closed"
            except Exception:
                result.state = "filtered"

        return result

    async def scan_host_async(
        self,
        host: str,
        ports: list[int] | None = None,
        protocol: str = "tcp",
    ) -> list[PortInfo]:
        """Scan multiple ports on a host."""
        if ports is None:
            ports = TOP_PORTS

        semaphore = asyncio.Semaphore(self.concurrency)

        async def scan_with_limit(port: int) -> PortInfo:
            async with semaphore:
                return await self.scan_port_async(host, port, protocol)

        tasks = [scan_with_limit(port) for port in ports]
        results = await asyncio.gather(*tasks)

        # Return only open/filtered ports by default
        return [r for r in results if r.state in ("open", "filtered")]

    def scan_host(
        self,
        host: str,
        ports: list[int] | None = None,
        protocol: str = "tcp",
    ) -> list[PortInfo]:
        """Synchronous host scan."""
        return asyncio.run(self.scan_host_async(host, ports, protocol))

    async def scan_range_async(
        self,
        host: str,
        start_port: int = 1,
        end_port: int = 1024,
    ) -> list[PortInfo]:
        """Scan a port range."""
        ports = list(range(start_port, end_port + 1))
        return await self.scan_host_async(host, ports)

    def scan_range(
        self,
        host: str,
        start_port: int = 1,
        end_port: int = 1024,
    ) -> list[PortInfo]:
        """Synchronous range scan."""
        return asyncio.run(self.scan_range_async(host, start_port, end_port))


class ServiceDetector:
    """Service version detection through banner analysis."""

    # Common service banners and patterns
    FINGERPRINTS = {
        "ssh": [
            (r"SSH-2\.0-OpenSSH_(\S+)", "OpenSSH"),
            (r"SSH-2\.0-dropbear_(\S+)", "Dropbear"),
            (r"SSH-1\.\d+-(.+)", "SSH v1"),
        ],
        "http": [
            (r"Server: Apache/(\S+)", "Apache"),
            (r"Server: nginx/(\S+)", "nginx"),
            (r"Server: Microsoft-IIS/(\S+)", "IIS"),
            (r"Server: cloudflare", "Cloudflare"),
            (r"Server: AmazonS3", "Amazon S3"),
        ],
        "ftp": [
            (r"220.*vsftpd (\S+)", "vsftpd"),
            (r"220.*ProFTPD (\S+)", "ProFTPD"),
            (r"220.*Pure-FTPd", "Pure-FTPd"),
            (r"220.*FileZilla Server", "FileZilla Server"),
        ],
        "smtp": [
            (r"220.*Postfix", "Postfix"),
            (r"220.*Exim (\S+)", "Exim"),
            (r"220.*Microsoft ESMTP", "Microsoft Exchange"),
            (r"220.*Sendmail", "Sendmail"),
        ],
        "mysql": [
            (r"(\d+\.\d+\.\d+)-MariaDB", "MariaDB"),
            (r"(\d+\.\d+\.\d+).*MySQL", "MySQL"),
        ],
    }

    def __init__(self, timeout: float = 5.0):
        self.timeout = timeout

    async def detect_service_async(self, host: str, port: int) -> ServiceInfo:
        """Detect service version on a port."""
        import re

        result = ServiceInfo(port=port)

        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(host, port),
                timeout=self.timeout,
            )

            # Determine protocol and send appropriate probe
            if port in [21, 22, 25, 110, 143, 3306]:
                # Services that send banner on connect
                banner = await asyncio.wait_for(
                    reader.read(1024),
                    timeout=3.0,
                )
            elif port in [80, 443, 8080, 8443]:
                # HTTP services
                writer.write(b"HEAD / HTTP/1.1\r\nHost: " + host.encode() + b"\r\nConnection: close\r\n\r\n")
                await writer.drain()
                banner = await asyncio.wait_for(
                    reader.read(2048),
                    timeout=3.0,
                )
            else:
                # Generic probe
                banner = await asyncio.wait_for(
                    reader.read(1024),
                    timeout=2.0,
                )

            writer.close()
            await writer.wait_closed()

            if banner:
                result.banner = banner.decode("utf-8", errors="ignore").strip()

                # Try to identify service
                if port in SERVICE_PORTS:
                    result.service = SERVICE_PORTS[port][0]

                # Match against fingerprints
                for service_type, patterns in self.FINGERPRINTS.items():
                    for pattern, product in patterns:
                        match = re.search(pattern, result.banner, re.IGNORECASE)
                        if match:
                            result.product = product
                            if match.groups():
                                result.version = match.group(1)
                            break

        except Exception:
            pass

        return result

    def detect_service(self, host: str, port: int) -> ServiceInfo:
        """Synchronous service detection."""
        return asyncio.run(self.detect_service_async(host, port))

    async def detect_services_async(
        self,
        host: str,
        ports: list[int],
    ) -> list[ServiceInfo]:
        """Detect services on multiple ports."""
        tasks = [self.detect_service_async(host, port) for port in ports]
        return await asyncio.gather(*tasks)

    def detect_services(self, host: str, ports: list[int]) -> list[ServiceInfo]:
        """Synchronous multi-port service detection."""
        return asyncio.run(self.detect_services_async(host, ports))
