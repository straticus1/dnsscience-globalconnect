"""
BGP/Routing Tools Module

Provides utilities for BGP analysis, AS lookups, route analysis,
and PeeringDB integration.
"""

from globaldetect.bgp.core import (
    ASInfo,
    PrefixInfo,
    PeeringDBClient,
    get_as_info,
    get_prefix_info,
    get_whois_info,
)

__all__ = [
    "ASInfo",
    "PrefixInfo",
    "PeeringDBClient",
    "get_as_info",
    "get_prefix_info",
    "get_whois_info",
]
