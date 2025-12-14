"""
Routing protocol support for GlobalDetect.

Provides multi-vendor routing protocol analysis, route table queries,
neighbor state tracking, and troubleshooting capabilities.

Supported protocols:
- BGP (iBGP, eBGP, route-reflectors, confederations)
- OSPF (areas, LSA types, neighbor states)
- IS-IS (levels, LSP database, adjacencies)
- RIP (v1/v2)
- EIGRP (feasible successors, DUAL, topology table)

Supported vendors:
- Cisco (IOS, IOS-XE, NX-OS)
- Juniper (JunOS)
- Arista (EOS)
- Nokia (SR OS)

Copyright (c) 2025 DNS Science.io, an After Dark Systems, LLC company.
All rights reserved.
"""

from globaldetect.routing.models import (
    RoutingProtocol,
    RouteType,
    BGPState,
    BGPOrigin,
    BGPSessionType,
    OSPFState,
    OSPFAreaType,
    OSPFRouteType,
    ISISLevel,
    ISISState,
    EIGRPState,
    Route,
    BGPRoute,
    OSPFRoute,
    ISISRoute,
    RIPRoute,
    EIGRPRoute,
    ProtocolNeighbor,
    BGPNeighbor,
    OSPFNeighbor,
    ISISAdjacency,
    RIPNeighbor,
    EIGRPNeighbor,
    RedistributionPoint,
    RoutingSnapshot,
    RouteChange,
    VRF,
)

__all__ = [
    # Enums
    "RoutingProtocol",
    "RouteType",
    "BGPState",
    "BGPOrigin",
    "BGPSessionType",
    "OSPFState",
    "OSPFAreaType",
    "OSPFRouteType",
    "ISISLevel",
    "ISISState",
    "EIGRPState",
    # Route models
    "Route",
    "BGPRoute",
    "OSPFRoute",
    "ISISRoute",
    "RIPRoute",
    "EIGRPRoute",
    # Neighbor models
    "ProtocolNeighbor",
    "BGPNeighbor",
    "OSPFNeighbor",
    "ISISAdjacency",
    "RIPNeighbor",
    "EIGRPNeighbor",
    # Other models
    "RedistributionPoint",
    "RoutingSnapshot",
    "RouteChange",
    "VRF",
]
