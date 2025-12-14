"""
NTP client for testing NTP servers.

Provides NTP query functionality without requiring scapy.

Copyright (c) 2025 DNS Science.io, an After Dark Systems, LLC company.
All rights reserved.
"""

import socket
import struct
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from enum import IntEnum
from typing import Any


# NTP timestamp epoch (Jan 1, 1900)
NTP_EPOCH = 2208988800


class NTPMode(IntEnum):
    """NTP mode field values."""
    RESERVED = 0
    SYMMETRIC_ACTIVE = 1
    SYMMETRIC_PASSIVE = 2
    CLIENT = 3
    SERVER = 4
    BROADCAST = 5
    CONTROL = 6
    PRIVATE = 7


class NTPLeapIndicator(IntEnum):
    """NTP Leap Indicator values."""
    NO_WARNING = 0
    LAST_MINUTE_61 = 1
    LAST_MINUTE_59 = 2
    ALARM = 3  # Clock not synchronized


@dataclass
class NTPResponse:
    """NTP server response."""
    # Server info
    server: str
    port: int = 123

    # Status
    success: bool = False
    error: str | None = None

    # NTP fields
    leap_indicator: int | None = None
    version: int | None = None
    mode: int | None = None
    stratum: int | None = None
    poll: int | None = None
    precision: int | None = None

    # Reference
    reference_id: str | None = None
    reference_timestamp: datetime | None = None

    # Timestamps
    originate_timestamp: datetime | None = None
    receive_timestamp: datetime | None = None
    transmit_timestamp: datetime | None = None

    # Calculated values
    offset: float | None = None  # Clock offset in seconds
    delay: float | None = None   # Round-trip delay in seconds
    server_time: datetime | None = None

    # Response time
    response_time_ms: float | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "server": self.server,
            "port": self.port,
            "success": self.success,
            "error": self.error,
            "leap_indicator": self.leap_indicator,
            "version": self.version,
            "mode": self.mode,
            "stratum": self.stratum,
            "poll": self.poll,
            "precision": self.precision,
            "reference_id": self.reference_id,
            "reference_timestamp": self.reference_timestamp.isoformat() if self.reference_timestamp else None,
            "originate_timestamp": self.originate_timestamp.isoformat() if self.originate_timestamp else None,
            "receive_timestamp": self.receive_timestamp.isoformat() if self.receive_timestamp else None,
            "transmit_timestamp": self.transmit_timestamp.isoformat() if self.transmit_timestamp else None,
            "offset": self.offset,
            "delay": self.delay,
            "server_time": self.server_time.isoformat() if self.server_time else None,
            "response_time_ms": self.response_time_ms,
        }


class NTPClient:
    """
    NTP client for querying time servers.

    Usage:
        client = NTPClient()
        response = client.query("pool.ntp.org")
        print(f"Server time: {response.server_time}")
        print(f"Offset: {response.offset:.6f}s")
    """

    def __init__(self, timeout: float = 5.0, version: int = 4):
        """
        Initialize NTP client.

        Args:
            timeout: Query timeout in seconds
            version: NTP version (3 or 4)
        """
        self.timeout = timeout
        self.version = version

    def _ntp_to_datetime(self, ntp_time: float) -> datetime:
        """Convert NTP timestamp to datetime."""
        unix_time = ntp_time - NTP_EPOCH
        return datetime.fromtimestamp(unix_time, tz=timezone.utc)

    def _datetime_to_ntp(self, dt: datetime) -> float:
        """Convert datetime to NTP timestamp."""
        return dt.timestamp() + NTP_EPOCH

    def _current_ntp_time(self) -> float:
        """Get current time as NTP timestamp."""
        return time.time() + NTP_EPOCH

    def _parse_reference_id(self, ref_id: bytes, stratum: int) -> str:
        """Parse reference ID based on stratum."""
        if stratum == 0 or stratum == 1:
            # Stratum 0/1: ASCII string (4 chars)
            return ref_id.decode("ascii", errors="ignore").rstrip("\x00")
        else:
            # Stratum 2+: IPv4 address
            return ".".join(str(b) for b in ref_id)

    def query(self, server: str, port: int = 123) -> NTPResponse:
        """
        Query an NTP server.

        Args:
            server: NTP server hostname or IP
            port: NTP port (default 123)

        Returns:
            NTPResponse with server time and statistics
        """
        response = NTPResponse(server=server, port=port)

        try:
            # Build NTP request packet
            # LI (2 bits) | VN (3 bits) | Mode (3 bits)
            li_vn_mode = (0 << 6) | (self.version << 3) | NTPMode.CLIENT

            # 48-byte NTP packet
            packet = bytearray(48)
            packet[0] = li_vn_mode

            # Record transmit time
            t1 = self._current_ntp_time()
            t1_int = int(t1)
            t1_frac = int((t1 - t1_int) * (2**32))

            # Set transmit timestamp (bytes 40-47)
            struct.pack_into(">II", packet, 40, t1_int, t1_frac)

            # Send request
            start_time = time.time()

            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.settimeout(self.timeout)

            try:
                sock.sendto(bytes(packet), (server, port))
                data, addr = sock.recvfrom(48)
            finally:
                sock.close()

            # Record receive time
            t4 = self._current_ntp_time()
            response.response_time_ms = (time.time() - start_time) * 1000

            if len(data) < 48:
                response.error = f"Invalid response size: {len(data)} bytes"
                return response

            # Parse response
            # Byte 0: LI (2) | VN (3) | Mode (3)
            byte0 = data[0]
            response.leap_indicator = (byte0 >> 6) & 0x03
            response.version = (byte0 >> 3) & 0x07
            response.mode = byte0 & 0x07

            # Bytes 1-3
            response.stratum = data[1]
            response.poll = data[2]
            response.precision = struct.unpack("b", bytes([data[3]]))[0]

            # Bytes 12-15: Reference ID
            ref_id = data[12:16]
            response.reference_id = self._parse_reference_id(ref_id, response.stratum)

            # Timestamps (64-bit: 32-bit seconds + 32-bit fraction)
            def unpack_timestamp(offset: int) -> float:
                seconds, fraction = struct.unpack(">II", data[offset:offset + 8])
                return seconds + fraction / (2**32)

            # Reference timestamp (16-23)
            ref_ts = unpack_timestamp(16)
            if ref_ts > 0:
                response.reference_timestamp = self._ntp_to_datetime(ref_ts)

            # Originate timestamp (24-31) - our transmit time echoed back
            orig_ts = unpack_timestamp(24)
            if orig_ts > 0:
                response.originate_timestamp = self._ntp_to_datetime(orig_ts)

            # Receive timestamp (32-39) - when server received our request
            t2 = unpack_timestamp(32)
            if t2 > 0:
                response.receive_timestamp = self._ntp_to_datetime(t2)

            # Transmit timestamp (40-47) - when server sent response
            t3 = unpack_timestamp(40)
            if t3 > 0:
                response.transmit_timestamp = self._ntp_to_datetime(t3)
                response.server_time = self._ntp_to_datetime(t3)

            # Calculate offset and delay
            # offset = ((t2 - t1) + (t3 - t4)) / 2
            # delay = (t4 - t1) - (t3 - t2)
            if t2 > 0 and t3 > 0:
                response.offset = ((t2 - t1) + (t3 - t4)) / 2
                response.delay = (t4 - t1) - (t3 - t2)

            response.success = True

        except socket.timeout:
            response.error = "Request timed out"
        except socket.gaierror as e:
            response.error = f"DNS resolution failed: {e}"
        except Exception as e:
            response.error = str(e)

        return response

    def query_multiple(self, servers: list[str], port: int = 123) -> list[NTPResponse]:
        """
        Query multiple NTP servers.

        Args:
            servers: List of NTP server hostnames or IPs
            port: NTP port

        Returns:
            List of NTPResponse objects
        """
        return [self.query(server, port) for server in servers]


# Well-known NTP servers
KNOWN_NTP_SERVERS = {
    "pool": [
        "pool.ntp.org",
        "0.pool.ntp.org",
        "1.pool.ntp.org",
        "2.pool.ntp.org",
        "3.pool.ntp.org",
    ],
    "google": [
        "time.google.com",
        "time1.google.com",
        "time2.google.com",
        "time3.google.com",
        "time4.google.com",
    ],
    "cloudflare": [
        "time.cloudflare.com",
    ],
    "apple": [
        "time.apple.com",
        "time1.apple.com",
        "time2.apple.com",
    ],
    "microsoft": [
        "time.windows.com",
    ],
    "nist": [
        "time.nist.gov",
        "time-a-g.nist.gov",
        "time-b-g.nist.gov",
        "time-c-g.nist.gov",
        "time-d-g.nist.gov",
    ],
}


def get_stratum_description(stratum: int) -> str:
    """Get human-readable stratum description."""
    if stratum == 0:
        return "Kiss-o'-Death"
    elif stratum == 1:
        return "Primary (GPS, atomic clock)"
    elif stratum <= 15:
        return f"Secondary (Stratum {stratum})"
    else:
        return "Unsynchronized"


def get_leap_description(leap: int) -> str:
    """Get human-readable leap indicator description."""
    descriptions = {
        0: "No warning",
        1: "Last minute has 61 seconds",
        2: "Last minute has 59 seconds",
        3: "Clock not synchronized",
    }
    return descriptions.get(leap, "Unknown")
