"""
Packet capture functionality.

Captures network traffic using tcpdump/libpcap and saves to pcap files.

Copyright (c) 2025 DNS Science.io, an After Dark Systems, LLC company.
All rights reserved.
"""

import os
import subprocess
import signal
import time
import tempfile
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any


# Protocol capture filters
CAPTURE_FILTERS = {
    # DNS - port 53 UDP and TCP
    "dns": "port 53",

    # Email/SMTP - ports 25, 465, 587
    "email": "port 25 or port 465 or port 587",
    "smtp": "port 25",
    "submission": "port 587 or port 465",

    # SSL/TLS - common HTTPS and secure ports
    "ssl": "port 443 or port 8443 or port 465 or port 993 or port 995 or port 636",
    "ssl-standard": "port 443",
    "https": "port 443 or port 8443",

    # Other common protocols
    "http": "port 80 or port 8080",
    "ssh": "port 22",
    "ftp": "port 20 or port 21",
    "telnet": "port 23",
    "ntp": "port 123",
    "snmp": "port 161 or port 162",
    "syslog": "port 514",
    "ldap": "port 389 or port 636",
    "radius": "port 1812 or port 1813",
    "bgp": "port 179",
    "dhcp": "port 67 or port 68",

    # Broadcast/multicast for L2 issues
    "broadcast": "broadcast or multicast",
    "arp": "arp",
    "icmp": "icmp or icmp6",
    "stp": "ether proto 0x0027 or ether dst 01:80:c2:00:00:00",

    # CDP/LLDP for neighbor discovery
    "cdp": "ether dst 01:00:0c:cc:cc:cc",
    "lldp": "ether proto 0x88cc",

    # All traffic (use with caution)
    "all": "",
}


@dataclass
class CaptureConfig:
    """Configuration for packet capture."""
    protocol: str = "all"
    interface: str | None = None
    duration: int = 300  # 5 minutes default
    max_packets: int | None = None
    snaplen: int = 65535  # Full packet capture
    output_file: str | None = None
    custom_filter: str | None = None
    promiscuous: bool = True
    buffer_size: int = 2  # MB


@dataclass
class CaptureStats:
    """Statistics from a capture session."""
    packets_captured: int = 0
    packets_dropped: int = 0
    packets_filtered: int = 0
    bytes_captured: int = 0
    duration_seconds: float = 0.0
    start_time: datetime | None = None
    end_time: datetime | None = None


@dataclass
class CaptureResult:
    """Result of a packet capture session."""
    success: bool = False
    output_file: str | None = None
    stats: CaptureStats = field(default_factory=CaptureStats)
    filter_used: str = ""
    interface: str = ""
    error: str | None = None
    warnings: list[str] = field(default_factory=list)


def get_capture_filter(protocol: str, custom_filter: str | None = None) -> str:
    """Get the BPF filter for a protocol."""
    if custom_filter:
        return custom_filter

    protocol = protocol.lower()
    if protocol in CAPTURE_FILTERS:
        return CAPTURE_FILTERS[protocol]

    # Try to parse as port number
    if protocol.isdigit():
        return f"port {protocol}"

    # Try to parse as port range (e.g., "80-443")
    if "-" in protocol and all(p.isdigit() for p in protocol.split("-")):
        start, end = protocol.split("-")
        return f"portrange {start}-{end}"

    # Assume it's a custom BPF filter
    return protocol


def find_tcpdump() -> str | None:
    """Find tcpdump binary."""
    paths = [
        "/usr/sbin/tcpdump",
        "/usr/bin/tcpdump",
        "/sbin/tcpdump",
        "/bin/tcpdump",
        "/usr/local/bin/tcpdump",
        "/opt/homebrew/bin/tcpdump",
    ]
    for path in paths:
        if os.path.exists(path) and os.access(path, os.X_OK):
            return path

    # Try PATH
    try:
        result = subprocess.run(["which", "tcpdump"], capture_output=True, text=True)
        if result.returncode == 0:
            return result.stdout.strip()
    except Exception:
        pass

    return None


def find_tshark() -> str | None:
    """Find tshark (Wireshark CLI) binary."""
    paths = [
        "/usr/bin/tshark",
        "/usr/local/bin/tshark",
        "/opt/homebrew/bin/tshark",
        "/Applications/Wireshark.app/Contents/MacOS/tshark",
    ]
    for path in paths:
        if os.path.exists(path) and os.access(path, os.X_OK):
            return path

    try:
        result = subprocess.run(["which", "tshark"], capture_output=True, text=True)
        if result.returncode == 0:
            return result.stdout.strip()
    except Exception:
        pass

    return None


class PacketCapture:
    """Captures network packets using tcpdump."""

    def __init__(self, config: CaptureConfig | None = None):
        self.config = config or CaptureConfig()
        self._process: subprocess.Popen | None = None
        self._tcpdump = find_tcpdump()
        self._tshark = find_tshark()

    def _get_interface(self) -> str:
        """Get interface to capture on."""
        if self.config.interface:
            return self.config.interface

        # Auto-detect first physical interface
        from globaldetect.neighbors.core import get_physical_interfaces, get_interfaces

        physical = get_physical_interfaces()
        if physical:
            return physical[0]

        interfaces = get_interfaces()
        if interfaces:
            return interfaces[0]

        return "any"  # Linux supports 'any' for all interfaces

    def _build_command(self, output_file: str) -> list[str]:
        """Build tcpdump command."""
        if not self._tcpdump:
            raise RuntimeError("tcpdump not found. Please install tcpdump.")

        interface = self._get_interface()
        bpf_filter = get_capture_filter(self.config.protocol, self.config.custom_filter)

        cmd = [
            self._tcpdump,
            "-i", interface,
            "-w", output_file,
            "-s", str(self.config.snaplen),
            "-B", str(self.config.buffer_size * 1024),  # Buffer in KB
        ]

        if not self.config.promiscuous:
            cmd.append("-p")

        if self.config.max_packets:
            cmd.extend(["-c", str(self.config.max_packets)])

        # Add filter if specified
        if bpf_filter:
            cmd.append(bpf_filter)

        return cmd

    def start(self, output_file: str | None = None) -> str:
        """Start packet capture in background."""
        if self._process is not None:
            raise RuntimeError("Capture already running")

        # Determine output file
        if output_file:
            self.config.output_file = output_file
        elif not self.config.output_file:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            protocol = self.config.protocol.replace("-", "_")
            self.config.output_file = f"capture_{protocol}_{timestamp}.pcap"

        cmd = self._build_command(self.config.output_file)

        try:
            self._process = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            )
            return self.config.output_file
        except PermissionError:
            raise RuntimeError("Permission denied. Run with sudo/root privileges.")
        except Exception as e:
            raise RuntimeError(f"Failed to start capture: {e}")

    def stop(self) -> CaptureStats:
        """Stop packet capture and return stats."""
        stats = CaptureStats()

        if self._process is None:
            return stats

        # Send SIGINT for graceful shutdown (tcpdump prints stats)
        self._process.send_signal(signal.SIGINT)

        try:
            stdout, stderr = self._process.communicate(timeout=5)

            # Parse tcpdump stats from stderr
            stderr_text = stderr.decode("utf-8", errors="replace")
            stats = self._parse_tcpdump_stats(stderr_text)

        except subprocess.TimeoutExpired:
            self._process.kill()
            self._process.communicate()
        finally:
            self._process = None

        return stats

    def _parse_tcpdump_stats(self, stderr: str) -> CaptureStats:
        """Parse tcpdump statistics from stderr."""
        import re
        stats = CaptureStats()

        # tcpdump output format:
        # X packets captured
        # Y packets received by filter
        # Z packets dropped by kernel

        captured = re.search(r'(\d+) packets? captured', stderr)
        if captured:
            stats.packets_captured = int(captured.group(1))

        received = re.search(r'(\d+) packets? received by filter', stderr)
        if received:
            stats.packets_filtered = int(received.group(1))

        dropped = re.search(r'(\d+) packets? dropped', stderr)
        if dropped:
            stats.packets_dropped = int(dropped.group(1))

        return stats

    def capture(self, duration: int | None = None) -> CaptureResult:
        """Run capture for specified duration."""
        result = CaptureResult()
        duration = duration or self.config.duration

        try:
            output_file = self.start()
            result.output_file = output_file
            result.interface = self._get_interface()
            result.filter_used = get_capture_filter(
                self.config.protocol, self.config.custom_filter
            )

            result.stats.start_time = datetime.now()

            # Wait for duration
            time.sleep(duration)

            result.stats.end_time = datetime.now()
            result.stats.duration_seconds = duration

            # Stop and get stats
            stats = self.stop()
            result.stats.packets_captured = stats.packets_captured
            result.stats.packets_dropped = stats.packets_dropped
            result.stats.packets_filtered = stats.packets_filtered

            # Check file was created
            if os.path.exists(output_file):
                result.stats.bytes_captured = os.path.getsize(output_file)
                result.success = True
            else:
                result.error = "Capture file not created"

        except Exception as e:
            result.error = str(e)
            self.stop()

        return result

    def capture_live(
        self,
        callback,
        duration: int | None = None,
    ) -> CaptureResult:
        """Capture and analyze packets in real-time."""
        result = CaptureResult()
        duration = duration or self.config.duration

        if not self._tcpdump:
            result.error = "tcpdump not found"
            return result

        interface = self._get_interface()
        bpf_filter = get_capture_filter(self.config.protocol, self.config.custom_filter)

        # Use tcpdump with immediate output
        cmd = [
            self._tcpdump,
            "-i", interface,
            "-l",  # Line buffered
            "-n",  # No DNS resolution
            "-v",  # Verbose
            "-s", str(self.config.snaplen),
        ]

        if not self.config.promiscuous:
            cmd.append("-p")

        if bpf_filter:
            cmd.append(bpf_filter)

        result.interface = interface
        result.filter_used = bpf_filter
        result.stats.start_time = datetime.now()

        try:
            process = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
            )

            start_time = time.time()
            packet_count = 0

            while True:
                if duration and (time.time() - start_time) >= duration:
                    break

                line = process.stdout.readline()
                if not line:
                    break

                packet_count += 1
                callback(line.strip(), packet_count)

            process.send_signal(signal.SIGINT)
            process.wait(timeout=2)

            result.stats.packets_captured = packet_count
            result.stats.end_time = datetime.now()
            result.stats.duration_seconds = time.time() - start_time
            result.success = True

        except Exception as e:
            result.error = str(e)

        return result


def parse_duration(duration_str: str) -> int:
    """Parse duration string like '5m', '1h', '30s' to seconds."""
    import re

    duration_str = duration_str.strip().lower()

    # Already a number
    if duration_str.isdigit():
        return int(duration_str)

    match = re.match(r'^(\d+)\s*(s|sec|m|min|h|hr|hour)?$', duration_str)
    if not match:
        raise ValueError(f"Invalid duration format: {duration_str}")

    value = int(match.group(1))
    unit = match.group(2) or 's'

    if unit in ('s', 'sec'):
        return value
    elif unit in ('m', 'min'):
        return value * 60
    elif unit in ('h', 'hr', 'hour'):
        return value * 3600
    else:
        return value
