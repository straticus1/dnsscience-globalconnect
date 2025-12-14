"""
Packet crafting module using scapy.

Provides user-friendly packet crafting with pre-built protocol templates
for testing and network troubleshooting.

Copyright (c) 2025 DNS Science.io, an After Dark Systems, LLC company.
All rights reserved.
"""

from globaldetect.packet.protocols import (
    PROTOCOLS,
    get_protocol,
    list_protocols,
)
from globaldetect.packet.ntp import NTPClient, NTPMode

__all__ = [
    "PROTOCOLS",
    "get_protocol",
    "list_protocols",
    "NTPClient",
    "NTPMode",
]
