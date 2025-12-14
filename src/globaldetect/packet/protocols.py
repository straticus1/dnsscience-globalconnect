"""
Protocol templates for packet crafting.

Provides user-friendly interfaces for common protocol testing
using scapy when available, with fallback implementations.

Copyright (c) 2025 DNS Science.io, an After Dark Systems, LLC company.
All rights reserved.
"""

import socket
import struct
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any, Callable

# Try to import scapy
try:
    from scapy.all import (
        IP, TCP, UDP, ICMP, ARP, Ether, DNS, DNSQR, Raw,
        sr1, sr, send, sendp, sniff, conf,
        RandShort
    )
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False


class ProtocolCategory(str, Enum):
    """Protocol categories."""
    NETWORK = "network"
    TRANSPORT = "transport"
    APPLICATION = "application"
    LINK = "link"


@dataclass
class ProtocolTemplate:
    """Template for a network protocol."""
    name: str
    category: ProtocolCategory
    description: str
    default_port: int | None = None
    requires_scapy: bool = False
    requires_root: bool = False
    parameters: dict[str, Any] = field(default_factory=dict)


# Available protocols
PROTOCOLS: dict[str, ProtocolTemplate] = {
    # Network Layer
    "icmp": ProtocolTemplate(
        name="ICMP",
        category=ProtocolCategory.NETWORK,
        description="Internet Control Message Protocol (ping, traceroute)",
        requires_scapy=True,
        requires_root=True,
        parameters={
            "type": "Echo Request (8) or Echo Reply (0)",
            "code": "ICMP code (usually 0)",
            "payload": "Optional data payload",
        }
    ),
    "arp": ProtocolTemplate(
        name="ARP",
        category=ProtocolCategory.LINK,
        description="Address Resolution Protocol",
        requires_scapy=True,
        requires_root=True,
        parameters={
            "op": "1=who-has, 2=is-at",
            "pdst": "Target IP address",
            "hwdst": "Target MAC address",
        }
    ),

    # Transport Layer
    "tcp": ProtocolTemplate(
        name="TCP",
        category=ProtocolCategory.TRANSPORT,
        description="Transmission Control Protocol",
        requires_scapy=True,
        requires_root=True,
        parameters={
            "sport": "Source port",
            "dport": "Destination port",
            "flags": "TCP flags (S=SYN, A=ACK, F=FIN, R=RST, P=PSH)",
            "seq": "Sequence number",
            "ack": "Acknowledgment number",
        }
    ),
    "udp": ProtocolTemplate(
        name="UDP",
        category=ProtocolCategory.TRANSPORT,
        description="User Datagram Protocol",
        requires_scapy=True,
        requires_root=True,
        parameters={
            "sport": "Source port",
            "dport": "Destination port",
            "payload": "Data payload",
        }
    ),

    # Application Layer
    "dns": ProtocolTemplate(
        name="DNS",
        category=ProtocolCategory.APPLICATION,
        description="Domain Name System queries",
        default_port=53,
        requires_scapy=False,
        parameters={
            "qname": "Query name (domain)",
            "qtype": "Query type (A, AAAA, MX, NS, TXT, etc.)",
            "server": "DNS server address",
        }
    ),
    "ntp": ProtocolTemplate(
        name="NTP",
        category=ProtocolCategory.APPLICATION,
        description="Network Time Protocol",
        default_port=123,
        requires_scapy=False,
        parameters={
            "server": "NTP server address",
            "version": "NTP version (3 or 4)",
        }
    ),
    "http": ProtocolTemplate(
        name="HTTP",
        category=ProtocolCategory.APPLICATION,
        description="Hypertext Transfer Protocol",
        default_port=80,
        requires_scapy=False,
        parameters={
            "method": "HTTP method (GET, POST, HEAD, etc.)",
            "path": "Request path",
            "headers": "HTTP headers",
            "body": "Request body",
        }
    ),
    "https": ProtocolTemplate(
        name="HTTPS",
        category=ProtocolCategory.APPLICATION,
        description="HTTP over TLS",
        default_port=443,
        requires_scapy=False,
        parameters={
            "method": "HTTP method",
            "path": "Request path",
            "verify": "Verify TLS certificate",
        }
    ),

    # Scanning/Probing
    "syn": ProtocolTemplate(
        name="TCP SYN",
        category=ProtocolCategory.TRANSPORT,
        description="TCP SYN scan (half-open scan)",
        requires_scapy=True,
        requires_root=True,
        parameters={
            "dport": "Destination port(s)",
            "timeout": "Response timeout",
        }
    ),
    "xmas": ProtocolTemplate(
        name="TCP XMAS",
        category=ProtocolCategory.TRANSPORT,
        description="TCP XMAS scan (FIN+PSH+URG flags)",
        requires_scapy=True,
        requires_root=True,
        parameters={
            "dport": "Destination port(s)",
        }
    ),
    "null": ProtocolTemplate(
        name="TCP NULL",
        category=ProtocolCategory.TRANSPORT,
        description="TCP NULL scan (no flags)",
        requires_scapy=True,
        requires_root=True,
        parameters={
            "dport": "Destination port(s)",
        }
    ),
}


def list_protocols() -> list[dict[str, Any]]:
    """List all available protocols with descriptions."""
    result = []
    for name, proto in PROTOCOLS.items():
        result.append({
            "name": name,
            "display_name": proto.name,
            "category": proto.category.value,
            "description": proto.description,
            "default_port": proto.default_port,
            "requires_scapy": proto.requires_scapy,
            "requires_root": proto.requires_root,
            "parameters": proto.parameters,
            "available": not proto.requires_scapy or SCAPY_AVAILABLE,
        })
    return result


def get_protocol(name: str) -> ProtocolTemplate | None:
    """Get protocol template by name."""
    return PROTOCOLS.get(name.lower())


# Scapy-based packet builders
if SCAPY_AVAILABLE:
    def build_icmp_echo(target: str, payload: bytes = b"", ttl: int = 64) -> Any:
        """Build ICMP echo request packet."""
        return IP(dst=target, ttl=ttl) / ICMP(type=8, code=0) / Raw(load=payload)

    def build_tcp_syn(target: str, port: int, sport: int | None = None) -> Any:
        """Build TCP SYN packet."""
        sport = sport or RandShort()
        return IP(dst=target) / TCP(sport=sport, dport=port, flags="S")

    def build_tcp_packet(
        target: str,
        dport: int,
        sport: int | None = None,
        flags: str = "S",
        seq: int = 0,
        ack: int = 0,
        payload: bytes = b"",
    ) -> Any:
        """Build custom TCP packet."""
        sport = sport or RandShort()
        pkt = IP(dst=target) / TCP(
            sport=sport,
            dport=dport,
            flags=flags,
            seq=seq,
            ack=ack,
        )
        if payload:
            pkt = pkt / Raw(load=payload)
        return pkt

    def build_udp_packet(
        target: str,
        dport: int,
        sport: int | None = None,
        payload: bytes = b"",
    ) -> Any:
        """Build UDP packet."""
        sport = sport or RandShort()
        pkt = IP(dst=target) / UDP(sport=sport, dport=dport)
        if payload:
            pkt = pkt / Raw(load=payload)
        return pkt

    def build_arp_request(target_ip: str, source_ip: str | None = None) -> Any:
        """Build ARP who-has request."""
        return Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=target_ip, psrc=source_ip, op=1)

    def build_dns_query(
        qname: str,
        qtype: str = "A",
        server: str = "8.8.8.8",
    ) -> Any:
        """Build DNS query packet."""
        qtype_map = {"A": 1, "AAAA": 28, "MX": 15, "NS": 2, "TXT": 16, "PTR": 12, "SOA": 6}
        return IP(dst=server) / UDP(sport=RandShort(), dport=53) / DNS(
            rd=1,
            qd=DNSQR(qname=qname, qtype=qtype_map.get(qtype.upper(), 1))
        )

    def send_packet(packet: Any, verbose: bool = False, timeout: float = 2.0) -> Any:
        """Send packet and receive response."""
        conf.verb = 0 if not verbose else 1
        return sr1(packet, timeout=timeout, verbose=verbose)

    def send_packet_no_response(packet: Any, verbose: bool = False) -> None:
        """Send packet without waiting for response."""
        conf.verb = 0 if not verbose else 1
        send(packet, verbose=verbose)

    def send_layer2(packet: Any, verbose: bool = False) -> None:
        """Send layer 2 packet."""
        conf.verb = 0 if not verbose else 1
        sendp(packet, verbose=verbose)


# Non-scapy implementations for basic protocols
def ping(host: str, timeout: float = 2.0, count: int = 1) -> list[dict[str, Any]]:
    """
    Simple ping using ICMP (requires root on most systems).

    Falls back to TCP connect if ICMP fails.
    """
    results = []

    if SCAPY_AVAILABLE:
        try:
            for i in range(count):
                pkt = build_icmp_echo(host, payload=f"ping{i}".encode())
                start = datetime.now()
                reply = send_packet(pkt, timeout=timeout)
                elapsed = (datetime.now() - start).total_seconds() * 1000

                if reply:
                    results.append({
                        "seq": i,
                        "success": True,
                        "rtt_ms": elapsed,
                        "ttl": reply.ttl,
                        "type": "icmp",
                    })
                else:
                    results.append({
                        "seq": i,
                        "success": False,
                        "error": "timeout",
                        "type": "icmp",
                    })
            return results
        except PermissionError:
            pass  # Fall through to TCP

    # Fallback: TCP connect to common port
    for i in range(count):
        for port in [80, 443, 22]:
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(timeout)
                start = datetime.now()
                result = sock.connect_ex((host, port))
                elapsed = (datetime.now() - start).total_seconds() * 1000
                sock.close()

                if result == 0:
                    results.append({
                        "seq": i,
                        "success": True,
                        "rtt_ms": elapsed,
                        "port": port,
                        "type": "tcp",
                    })
                    break
            except Exception:
                continue
        else:
            results.append({
                "seq": i,
                "success": False,
                "error": "all ports failed",
                "type": "tcp",
            })

    return results


def tcp_connect(host: str, port: int, timeout: float = 5.0) -> dict[str, Any]:
    """
    Test TCP connection to host:port.
    """
    result = {
        "host": host,
        "port": port,
        "success": False,
    }

    try:
        start = datetime.now()
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        error = sock.connect_ex((host, port))
        elapsed = (datetime.now() - start).total_seconds() * 1000

        if error == 0:
            result["success"] = True
            result["connect_time_ms"] = elapsed

            # Try to get banner
            try:
                sock.settimeout(0.5)
                banner = sock.recv(1024)
                if banner:
                    result["banner"] = banner.decode("utf-8", errors="ignore").strip()
            except Exception:
                pass

        else:
            result["error"] = f"Connection failed (error {error})"

        sock.close()

    except socket.timeout:
        result["error"] = "Connection timed out"
    except socket.gaierror as e:
        result["error"] = f"DNS resolution failed: {e}"
    except Exception as e:
        result["error"] = str(e)

    return result


def syn_scan(host: str, ports: list[int], timeout: float = 2.0) -> dict[int, str]:
    """
    TCP SYN scan (half-open scan).

    Requires scapy and root privileges.

    Returns:
        Dict mapping port to state (open, closed, filtered)
    """
    if not SCAPY_AVAILABLE:
        raise RuntimeError("SYN scan requires scapy")

    results = {}

    for port in ports:
        pkt = build_tcp_syn(host, port)
        reply = send_packet(pkt, timeout=timeout)

        if reply is None:
            results[port] = "filtered"
        elif reply.haslayer(TCP):
            tcp_flags = reply.getlayer(TCP).flags
            if tcp_flags & 0x12:  # SYN+ACK
                results[port] = "open"
                # Send RST to close connection
                rst = IP(dst=host) / TCP(sport=pkt.sport, dport=port, flags="R")
                send_packet_no_response(rst)
            elif tcp_flags & 0x14:  # RST+ACK
                results[port] = "closed"
        elif reply.haslayer(ICMP):
            results[port] = "filtered"

    return results


def arp_scan(network: str, timeout: float = 2.0) -> list[dict[str, str]]:
    """
    ARP scan to discover hosts on local network.

    Requires scapy and root privileges.

    Args:
        network: Network in CIDR notation (e.g., "192.168.1.0/24")

    Returns:
        List of dicts with 'ip' and 'mac' keys
    """
    if not SCAPY_AVAILABLE:
        raise RuntimeError("ARP scan requires scapy")

    from scapy.all import Ether, ARP, srp

    conf.verb = 0
    ans, _ = srp(
        Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=network),
        timeout=timeout,
        verbose=False
    )

    results = []
    for sent, received in ans:
        results.append({
            "ip": received.psrc,
            "mac": received.hwsrc,
        })

    return sorted(results, key=lambda x: socket.inet_aton(x["ip"]))
