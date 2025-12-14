"""
Routing protocol implementations.

Provides protocol-specific logic for BGP, OSPF, IS-IS, RIP, and EIGRP.

Copyright (c) 2025 DNS Science.io, an After Dark Systems, LLC company.
All rights reserved.
"""

from globaldetect.routing.protocols.base import RoutingProtocolHandler

__all__ = [
    "RoutingProtocolHandler",
]
