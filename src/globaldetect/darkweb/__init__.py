"""
Dark Web Intelligence Module

Provides utilities for checking if IPs or domains have dark web associations:
- Tor exit node detection
- Known .onion association lookup
- Dark web threat intelligence feeds
- Proxy/VPN detection

Copyright (c) 2025 DNS Science.io, an After Dark Systems, LLC company.
All rights reserved.
"""

from globaldetect.darkweb.core import (
    DarkWebChecker,
    TorExitChecker,
    DarkWebResult,
    TorExitResult,
    check_tor_exit,
    check_darkweb_intel,
)

__all__ = [
    "DarkWebChecker",
    "TorExitChecker",
    "DarkWebResult",
    "TorExitResult",
    "check_tor_exit",
    "check_darkweb_intel",
]
