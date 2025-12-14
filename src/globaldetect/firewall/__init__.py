"""
Firewall rule parsing and analysis.

Provides parsers for various firewall rule export formats
including iptables-save, ipfilter, and Checkpoint.

Copyright (c) 2025 DNS Science.io, an After Dark Systems, LLC company.
All rights reserved.
"""

from globaldetect.firewall.models import (
    FirewallRule,
    FirewallChain,
    FirewallTable,
    FirewallPolicy,
    RuleAction,
    Protocol,
)
from globaldetect.firewall.parsers.iptables import IptablesParser
from globaldetect.firewall.parsers.ipfilter import IpfilterParser
from globaldetect.firewall.parsers.checkpoint import CheckpointParser

__all__ = [
    "FirewallRule",
    "FirewallChain",
    "FirewallTable",
    "FirewallPolicy",
    "RuleAction",
    "Protocol",
    "IptablesParser",
    "IpfilterParser",
    "CheckpointParser",
]
