"""
Core diagnostics functionality.
"""

import asyncio
import platform
import re
import socket
import struct
import subprocess
import time
from dataclasses import dataclass, field


@dataclass
class PingResult:
    """Result of a ping operation."""
    host: str
    ip: str | None = None
    packets_sent: int = 0
    packets_received: int = 0
    packet_loss: float = 0.0
    min_ms: float = 0.0
    avg_ms: float = 0.0
    max_ms: float = 0.0
    stddev_ms: float = 0.0
    error: str | None = None


@dataclass
class TracerouteHop:
    """A single hop in a traceroute."""
    hop_number: int
    ip: str | None = None
    hostname: str | None = None
    rtt_ms: list[float] = field(default_factory=list)
    is_timeout: bool = False
    asn: int | None = None
    as_name: str | None = None
    # GeoIP fields
    city: str | None = None
    region: str | None = None
    country: str | None = None
    org: str | None = None
    loc: str | None = None  # "lat,lon"


@dataclass
class MTUResult:
    """Result of MTU path discovery."""
    host: str
    mtu: int
    error: str | None = None


def ping(host: str, count: int = 4, timeout: float = 5.0) -> PingResult:
    """Ping a host and return statistics."""
    result = PingResult(host=host, packets_sent=count)

    system = platform.system().lower()

    if system == "darwin" or system == "linux":
        cmd = ["ping", "-c", str(count), "-W", str(int(timeout)), host]
    elif system == "windows":
        cmd = ["ping", "-n", str(count), "-w", str(int(timeout * 1000)), host]
    else:
        result.error = f"Unsupported platform: {system}"
        return result

    try:
        output = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout * count + 5,
        )

        stdout = output.stdout

        # Try to extract IP address
        ip_match = re.search(r'\((\d+\.\d+\.\d+\.\d+)\)', stdout)
        if ip_match:
            result.ip = ip_match.group(1)

        # Extract packet stats
        if system == "windows":
            loss_match = re.search(r'(\d+)% loss', stdout)
            stats_match = re.search(r'Minimum = (\d+)ms, Maximum = (\d+)ms, Average = (\d+)ms', stdout)
        else:
            loss_match = re.search(r'(\d+(?:\.\d+)?)% packet loss', stdout)
            stats_match = re.search(r'(\d+(?:\.\d+)?)/(\d+(?:\.\d+)?)/(\d+(?:\.\d+)?)/(\d+(?:\.\d+)?)', stdout)

        if loss_match:
            result.packet_loss = float(loss_match.group(1))
            result.packets_received = int(count * (100 - result.packet_loss) / 100)

        if stats_match:
            if system == "windows":
                result.min_ms = float(stats_match.group(1))
                result.max_ms = float(stats_match.group(2))
                result.avg_ms = float(stats_match.group(3))
            else:
                result.min_ms = float(stats_match.group(1))
                result.avg_ms = float(stats_match.group(2))
                result.max_ms = float(stats_match.group(3))
                result.stddev_ms = float(stats_match.group(4))

    except subprocess.TimeoutExpired:
        result.error = "Ping timed out"
    except FileNotFoundError:
        result.error = "ping command not found"
    except Exception as e:
        result.error = str(e)

    return result


def traceroute(
    host: str,
    max_hops: int = 30,
    timeout: float = 3.0,
    resolve_as: bool = True,
    resolve_geoip: bool = False,
) -> list[TracerouteHop]:
    """Perform a traceroute to a host."""
    hops = []
    system = platform.system().lower()

    if system == "darwin":
        cmd = ["traceroute", "-m", str(max_hops), "-w", str(int(timeout)), host]
    elif system == "linux":
        cmd = ["traceroute", "-m", str(max_hops), "-w", str(timeout), host]
    elif system == "windows":
        cmd = ["tracert", "-h", str(max_hops), "-w", str(int(timeout * 1000)), host]
    else:
        return hops

    try:
        output = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=max_hops * timeout + 10,
        )

        lines = output.stdout.strip().split("\n")

        for line in lines[1:]:  # Skip header
            line = line.strip()
            if not line:
                continue

            hop = _parse_traceroute_line(line, system)
            if hop:
                hops.append(hop)

    except subprocess.TimeoutExpired:
        pass
    except Exception:
        pass

    # Optionally resolve AS info
    if resolve_as:
        _add_as_info(hops)

    # Optionally resolve GeoIP info
    if resolve_geoip:
        _add_geoip_info(hops)

    return hops


def _parse_traceroute_line(line: str, system: str) -> TracerouteHop | None:
    """Parse a single traceroute line."""
    # Try to match hop number
    hop_match = re.match(r'\s*(\d+)\s+', line)
    if not hop_match:
        return None

    hop_num = int(hop_match.group(1))
    rest = line[hop_match.end():]

    hop = TracerouteHop(hop_number=hop_num)

    # Check for timeout/asterisks
    if rest.strip() == "* * *" or "Request timed out" in rest:
        hop.is_timeout = True
        return hop

    # Extract IP and hostname
    # Pattern: hostname (IP) or just IP
    ip_match = re.search(r'\((\d+\.\d+\.\d+\.\d+)\)', rest)
    if ip_match:
        hop.ip = ip_match.group(1)
        # Hostname is before the IP
        hostname_part = rest[:ip_match.start()].strip()
        if hostname_part and not hostname_part.startswith("*"):
            hop.hostname = hostname_part.split()[0]
    else:
        # Try bare IP
        bare_ip = re.search(r'(\d+\.\d+\.\d+\.\d+)', rest)
        if bare_ip:
            hop.ip = bare_ip.group(1)

    # Extract RTT values
    rtt_matches = re.findall(r'(\d+(?:\.\d+)?)\s*ms', rest)
    hop.rtt_ms = [float(rtt) for rtt in rtt_matches]

    return hop


def _add_as_info(hops: list[TracerouteHop]) -> None:
    """Add AS information to traceroute hops."""
    # This would normally query Team Cymru or similar
    # For now, we'll leave AS info empty to avoid external dependencies
    pass


def _add_geoip_info(hops: list[TracerouteHop]) -> None:
    """Add GeoIP information to traceroute hops using IPInfo.io."""
    try:
        from globaldetect.services.ipinfo import IPInfoClient

        # Collect IPs that need lookup
        ips_to_lookup = [hop.ip for hop in hops if hop.ip and not hop.is_timeout]
        if not ips_to_lookup:
            return

        client = IPInfoClient()
        results = client.lookup_batch(ips_to_lookup)

        # Create a map of IP -> result
        result_map = {r.ip: r for r in results}

        # Apply to hops
        for hop in hops:
            if hop.ip and hop.ip in result_map:
                info = result_map[hop.ip]
                hop.city = info.city
                hop.region = info.region
                hop.country = info.country
                hop.org = info.org
                hop.loc = info.loc
                if info.asn and not hop.asn:
                    hop.asn = info.asn
                    hop.as_name = info.as_name
    except ImportError:
        pass
    except Exception:
        pass


def mtu_discover(host: str, start_mtu: int = 1500, min_mtu: int = 68) -> MTUResult:
    """Discover the path MTU to a host using binary search."""
    result = MTUResult(host=host, mtu=min_mtu)

    system = platform.system().lower()

    def test_mtu(size: int) -> bool:
        """Test if a specific MTU works."""
        # Account for IP and ICMP headers (28 bytes)
        payload_size = size - 28

        if system == "darwin":
            cmd = ["ping", "-c", "1", "-D", "-s", str(payload_size), "-W", "2", host]
        elif system == "linux":
            cmd = ["ping", "-c", "1", "-M", "do", "-s", str(payload_size), "-W", "2", host]
        elif system == "windows":
            cmd = ["ping", "-n", "1", "-f", "-l", str(payload_size), "-w", "2000", host]
        else:
            return False

        try:
            proc = subprocess.run(cmd, capture_output=True, text=True, timeout=5)
            return proc.returncode == 0
        except Exception:
            return False

    # Binary search for MTU
    low = min_mtu
    high = start_mtu

    while low < high:
        mid = (low + high + 1) // 2
        if test_mtu(mid):
            low = mid
        else:
            high = mid - 1

    result.mtu = low

    return result


async def port_check_async(
    host: str,
    ports: list[int],
    timeout: float = 3.0,
) -> dict[int, bool]:
    """Check if ports are open on a host."""
    results = {}

    async def check_port(port: int) -> tuple[int, bool]:
        try:
            _, writer = await asyncio.wait_for(
                asyncio.open_connection(host, port),
                timeout=timeout,
            )
            writer.close()
            await writer.wait_closed()
            return (port, True)
        except Exception:
            return (port, False)

    tasks = [check_port(port) for port in ports]
    completed = await asyncio.gather(*tasks)

    for port, is_open in completed:
        results[port] = is_open

    return results


def port_check(host: str, ports: list[int], timeout: float = 3.0) -> dict[int, bool]:
    """Synchronous wrapper for port check."""
    return asyncio.run(port_check_async(host, ports, timeout))


# Common port ranges for quick scans
COMMON_PORTS = [
    21,    # FTP
    22,    # SSH
    23,    # Telnet
    25,    # SMTP
    53,    # DNS
    80,    # HTTP
    110,   # POP3
    143,   # IMAP
    443,   # HTTPS
    465,   # SMTPS
    587,   # Submission
    993,   # IMAPS
    995,   # POP3S
    3306,  # MySQL
    3389,  # RDP
    5432,  # PostgreSQL
    6379,  # Redis
    8080,  # HTTP Alt
    8443,  # HTTPS Alt
]
