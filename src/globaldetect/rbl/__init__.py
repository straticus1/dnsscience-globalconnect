"""
RBL/Blacklist Lookup Module

Provides utilities for checking IP addresses and domains against
Real-time Blackhole Lists (RBLs), DNSBLs, and reputation services.

Supports all major providers including:
- Spamhaus (ZEN, SBL, XBL, PBL, DBL)
- Barracuda
- SpamCop
- SORBS
- UCEProtect
- Proofpoint/Cloudmark
- Cisco/IronPort (SenderBase)
- And 50+ other RBL providers

Full IPv4 and IPv6 support.

Copyright (c) 2025 DNS Science.io, an After Dark Systems, LLC company.
All rights reserved.
"""

from globaldetect.rbl.core import (
    RBLChecker,
    RBLResult,
    DomainBlacklistChecker,
    check_ip,
    check_ip_all,
    check_domain,
    get_rbl_list,
    RBL_PROVIDERS,
    DNSBL_PROVIDERS,
)

__all__ = [
    "RBLChecker",
    "RBLResult",
    "DomainBlacklistChecker",
    "check_ip",
    "check_ip_all",
    "check_domain",
    "get_rbl_list",
    "RBL_PROVIDERS",
    "DNSBL_PROVIDERS",
]
