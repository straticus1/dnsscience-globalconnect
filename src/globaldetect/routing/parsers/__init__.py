"""
Output parsers for different device vendors.

Provides regex-based and template-based parsers for converting
device command output into structured data.

Copyright (c) 2025 DNS Science.io, an After Dark Systems, LLC company.
All rights reserved.
"""

from globaldetect.routing.parsers.base import OutputParser
from globaldetect.routing.parsers.cisco_ios import CiscoIOSParser
from globaldetect.routing.parsers.juniper import JuniperJunOSParser
from globaldetect.routing.parsers.arista import AristaEOSParser

__all__ = [
    "OutputParser",
    "CiscoIOSParser",
    "JuniperJunOSParser",
    "AristaEOSParser",
]
