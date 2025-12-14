"""
Data models for routing protocol support.

Provides dataclass-based models for routes, neighbors, and protocol-specific
attributes across BGP, OSPF, IS-IS, RIP, and EIGRP.

Copyright (c) 2025 DNS Science.io, an After Dark Systems, LLC company.
All rights reserved.
"""

from dataclasses import dataclass, field
from datetime import datetime, timedelta
from enum import Enum
from typing import Any


# =============================================================================
# Enumerations
# =============================================================================

class RoutingProtocol(str, Enum):
    """Routing protocol types."""
    CONNECTED = "connected"
    DIRECT = "direct"  # JunOS term for connected
    STATIC = "static"
    LOCAL = "local"
    BGP = "bgp"
    OSPF = "ospf"
    ISIS = "is-is"
    RIP = "rip"
    EIGRP = "eigrp"
    ODR = "odr"  # On-Demand Routing
    MOBILE = "mobile"
    LISP = "lisp"
    NHRP = "nhrp"
    AGGREGATE = "aggregate"  # JunOS aggregate routes
    ACCESS = "access"  # Access-internal routes
    ACCESS_INTERNAL = "access-internal"
    UNKNOWN = "unknown"


class RouteType(str, Enum):
    """General route classification."""
    BEST = "best"
    BACKUP = "backup"
    ECMP = "ecmp"  # Equal-cost multi-path
    INACTIVE = "inactive"
    HIDDEN = "hidden"
    REJECTED = "rejected"


class BGPState(str, Enum):
    """BGP session states (RFC 4271)."""
    IDLE = "idle"
    CONNECT = "connect"
    ACTIVE = "active"
    OPENSENT = "opensent"
    OPENCONFIRM = "openconfirm"
    ESTABLISHED = "established"


class BGPOrigin(str, Enum):
    """BGP origin attribute."""
    IGP = "igp"
    EGP = "egp"
    INCOMPLETE = "incomplete"


class BGPSessionType(str, Enum):
    """BGP session type."""
    IBGP = "ibgp"
    EBGP = "ebgp"
    CONFEDERATION = "confederation"


class OSPFState(str, Enum):
    """OSPF neighbor states (RFC 2328)."""
    DOWN = "down"
    ATTEMPT = "attempt"
    INIT = "init"
    TWO_WAY = "2-way"
    EXSTART = "exstart"
    EXCHANGE = "exchange"
    LOADING = "loading"
    FULL = "full"


class OSPFAreaType(str, Enum):
    """OSPF area types."""
    NORMAL = "normal"
    STUB = "stub"
    TOTALLY_STUB = "totally-stub"
    NSSA = "nssa"
    TOTALLY_NSSA = "totally-nssa"
    BACKBONE = "backbone"


class OSPFRouteType(str, Enum):
    """OSPF route types."""
    INTRA_AREA = "O"  # Intra-area
    INTER_AREA = "O IA"  # Inter-area
    EXTERNAL_1 = "O E1"  # External type 1
    EXTERNAL_2 = "O E2"  # External type 2
    NSSA_1 = "O N1"  # NSSA type 1
    NSSA_2 = "O N2"  # NSSA type 2


class ISISLevel(str, Enum):
    """IS-IS levels."""
    L1 = "L1"
    L2 = "L2"
    L1L2 = "L1L2"


class ISISState(str, Enum):
    """IS-IS adjacency states."""
    DOWN = "down"
    INITIALIZING = "initializing"
    UP = "up"


class EIGRPState(str, Enum):
    """EIGRP peer states."""
    PENDING = "pending"
    ACTIVE = "active"


class DeviceVendor(str, Enum):
    """Supported device vendors."""
    CISCO_IOS = "cisco_ios"
    CISCO_IOS_XE = "cisco_ios_xe"
    CISCO_NXOS = "cisco_nxos"
    JUNIPER = "juniper"
    ARISTA = "arista"
    NOKIA = "nokia"
    HUAWEI = "huawei"
    UNKNOWN = "unknown"


# =============================================================================
# Administrative Distances (Cisco defaults)
# =============================================================================

DEFAULT_ADMIN_DISTANCES = {
    RoutingProtocol.CONNECTED: 0,
    RoutingProtocol.STATIC: 1,
    RoutingProtocol.EIGRP: 90,  # Internal EIGRP
    RoutingProtocol.OSPF: 110,
    RoutingProtocol.ISIS: 115,
    RoutingProtocol.RIP: 120,
    RoutingProtocol.BGP: 20,  # eBGP (iBGP is 200)
}


# =============================================================================
# VRF Model
# =============================================================================

@dataclass
class VRF:
    """VRF/routing-instance information."""
    name: str
    rd: str | None = None  # Route distinguisher
    rt_import: list[str] = field(default_factory=list)  # Import route targets
    rt_export: list[str] = field(default_factory=list)  # Export route targets
    description: str | None = None
    interfaces: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "rd": self.rd,
            "rt_import": self.rt_import,
            "rt_export": self.rt_export,
            "description": self.description,
            "interfaces": self.interfaces,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "VRF":
        return cls(
            name=data["name"],
            rd=data.get("rd"),
            rt_import=data.get("rt_import", []),
            rt_export=data.get("rt_export", []),
            description=data.get("description"),
            interfaces=data.get("interfaces", []),
        )


# =============================================================================
# Base Route Model
# =============================================================================

@dataclass
class Route:
    """Base route entry with common attributes."""
    prefix: str  # Network/prefix (e.g., "10.0.0.0/8")
    prefix_length: int  # Prefix length (e.g., 8)
    protocol: RoutingProtocol  # Source protocol
    next_hop: str | None = None  # Primary next-hop
    next_hops: list[str] = field(default_factory=list)  # All next-hops (ECMP)
    interface: str | None = None  # Outgoing interface
    metric: int = 0  # Protocol metric
    admin_distance: int = 0  # Administrative distance
    age: timedelta | None = None  # Route age
    age_seconds: int | None = None  # Route age in seconds
    tag: int | None = None  # Route tag
    vrf: str = "default"  # VRF name
    route_type: RouteType = RouteType.BEST
    active: bool = True  # Is route active in RIB
    fib_installed: bool = True  # Is route in FIB
    attributes: dict[str, Any] = field(default_factory=dict)  # Protocol-specific

    def __post_init__(self):
        # Extract prefix_length from prefix if not set
        if "/" in self.prefix and self.prefix_length == 0:
            parts = self.prefix.split("/")
            self.prefix = parts[0]
            self.prefix_length = int(parts[1])
        # Ensure next_hops includes next_hop
        if self.next_hop and self.next_hop not in self.next_hops:
            self.next_hops = [self.next_hop] + self.next_hops

    @property
    def network(self) -> str:
        """Return prefix in CIDR notation."""
        return f"{self.prefix}/{self.prefix_length}"

    def to_dict(self) -> dict[str, Any]:
        return {
            "prefix": self.prefix,
            "prefix_length": self.prefix_length,
            "protocol": self.protocol.value,
            "next_hop": self.next_hop,
            "next_hops": self.next_hops,
            "interface": self.interface,
            "metric": self.metric,
            "admin_distance": self.admin_distance,
            "age_seconds": self.age_seconds,
            "tag": self.tag,
            "vrf": self.vrf,
            "route_type": self.route_type.value,
            "active": self.active,
            "fib_installed": self.fib_installed,
            "attributes": self.attributes,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "Route":
        return cls(
            prefix=data["prefix"],
            prefix_length=data.get("prefix_length", 0),
            protocol=RoutingProtocol(data.get("protocol", "unknown")),
            next_hop=data.get("next_hop"),
            next_hops=data.get("next_hops", []),
            interface=data.get("interface"),
            metric=data.get("metric", 0),
            admin_distance=data.get("admin_distance", 0),
            age_seconds=data.get("age_seconds"),
            tag=data.get("tag"),
            vrf=data.get("vrf", "default"),
            route_type=RouteType(data.get("route_type", "best")),
            active=data.get("active", True),
            fib_installed=data.get("fib_installed", True),
            attributes=data.get("attributes", {}),
        )


# =============================================================================
# Protocol-Specific Route Models
# =============================================================================

@dataclass
class BGPRoute(Route):
    """BGP route with full path attributes."""
    # BGP path attributes
    as_path: list[int] = field(default_factory=list)
    as_path_str: str | None = None  # Human-readable AS path
    origin: BGPOrigin = BGPOrigin.INCOMPLETE
    local_pref: int = 100  # Local preference (default 100)
    med: int = 0  # Multi-Exit Discriminator
    weight: int = 0  # Cisco weight (local)

    # Communities
    communities: list[str] = field(default_factory=list)
    large_communities: list[str] = field(default_factory=list)
    ext_communities: list[str] = field(default_factory=list)

    # Route reflector attributes
    cluster_list: list[str] = field(default_factory=list)
    originator_id: str | None = None

    # Path info
    neighbor: str | None = None  # BGP neighbor that advertised this
    neighbor_asn: int | None = None
    session_type: BGPSessionType | None = None

    # Path selection
    best: bool = False
    valid: bool = True
    multipath: bool = False

    # Additional attributes
    atomic_aggregate: bool = False
    aggregator_as: int | None = None
    aggregator_id: str | None = None

    def __post_init__(self):
        super().__post_init__()
        self.protocol = RoutingProtocol.BGP
        if self.as_path and not self.as_path_str:
            self.as_path_str = " ".join(str(asn) for asn in self.as_path)

    @property
    def as_path_length(self) -> int:
        """Return AS path length."""
        return len(self.as_path)

    def to_dict(self) -> dict[str, Any]:
        base = super().to_dict()
        base.update({
            "as_path": self.as_path,
            "as_path_str": self.as_path_str,
            "origin": self.origin.value,
            "local_pref": self.local_pref,
            "med": self.med,
            "weight": self.weight,
            "communities": self.communities,
            "large_communities": self.large_communities,
            "ext_communities": self.ext_communities,
            "cluster_list": self.cluster_list,
            "originator_id": self.originator_id,
            "neighbor": self.neighbor,
            "neighbor_asn": self.neighbor_asn,
            "session_type": self.session_type.value if self.session_type else None,
            "best": self.best,
            "valid": self.valid,
            "multipath": self.multipath,
            "atomic_aggregate": self.atomic_aggregate,
            "aggregator_as": self.aggregator_as,
            "aggregator_id": self.aggregator_id,
        })
        return base


@dataclass
class OSPFRoute(Route):
    """OSPF route with LSA and area information."""
    area: str | None = None  # Area ID
    area_type: OSPFAreaType = OSPFAreaType.NORMAL
    ospf_route_type: OSPFRouteType = OSPFRouteType.INTRA_AREA
    cost: int = 0  # OSPF cost/metric

    # External route attributes
    forwarding_address: str | None = None
    external_tag: int | None = None

    # LSA info
    lsa_type: int | None = None
    advertising_router: str | None = None
    lsa_age: int | None = None
    lsa_sequence: str | None = None

    def __post_init__(self):
        super().__post_init__()
        self.protocol = RoutingProtocol.OSPF
        if self.cost > 0:
            self.metric = self.cost

    def to_dict(self) -> dict[str, Any]:
        base = super().to_dict()
        base.update({
            "area": self.area,
            "area_type": self.area_type.value,
            "ospf_route_type": self.ospf_route_type.value,
            "cost": self.cost,
            "forwarding_address": self.forwarding_address,
            "external_tag": self.external_tag,
            "lsa_type": self.lsa_type,
            "advertising_router": self.advertising_router,
            "lsa_age": self.lsa_age,
            "lsa_sequence": self.lsa_sequence,
        })
        return base


@dataclass
class ISISRoute(Route):
    """IS-IS route with level and metric information."""
    level: ISISLevel = ISISLevel.L2
    metric: int = 10
    metric_type: str = "internal"  # internal or external

    # LSP info
    system_id: str | None = None
    lsp_id: str | None = None

    def __post_init__(self):
        super().__post_init__()
        self.protocol = RoutingProtocol.ISIS

    def to_dict(self) -> dict[str, Any]:
        base = super().to_dict()
        base.update({
            "level": self.level.value,
            "metric_type": self.metric_type,
            "system_id": self.system_id,
            "lsp_id": self.lsp_id,
        })
        return base


@dataclass
class RIPRoute(Route):
    """RIP route with hop count and timers."""
    hop_count: int = 0
    timeout: int | None = None  # Seconds until route expires
    garbage_collect: int | None = None  # Seconds in garbage collection

    def __post_init__(self):
        super().__post_init__()
        self.protocol = RoutingProtocol.RIP
        self.metric = self.hop_count

    def to_dict(self) -> dict[str, Any]:
        base = super().to_dict()
        base.update({
            "hop_count": self.hop_count,
            "timeout": self.timeout,
            "garbage_collect": self.garbage_collect,
        })
        return base


@dataclass
class EIGRPRoute(Route):
    """EIGRP route with composite metric and DUAL state."""
    # Composite metric components
    bandwidth: int = 0  # Minimum bandwidth (Kbps)
    delay: int = 0  # Cumulative delay (microseconds)
    reliability: int = 255  # 0-255
    load: int = 1  # 0-255
    mtu: int = 1500

    # DUAL
    feasible_distance: int = 0
    reported_distance: int = 0
    successor: str | None = None  # Successor next-hop
    feasible_successors: list[str] = field(default_factory=list)

    # Process info
    as_number: int | None = None  # EIGRP AS number

    # State
    is_successor: bool = True
    is_feasible_successor: bool = False
    query_origin: str | None = None

    def __post_init__(self):
        super().__post_init__()
        self.protocol = RoutingProtocol.EIGRP

    def to_dict(self) -> dict[str, Any]:
        base = super().to_dict()
        base.update({
            "bandwidth": self.bandwidth,
            "delay": self.delay,
            "reliability": self.reliability,
            "load": self.load,
            "mtu": self.mtu,
            "feasible_distance": self.feasible_distance,
            "reported_distance": self.reported_distance,
            "successor": self.successor,
            "feasible_successors": self.feasible_successors,
            "as_number": self.as_number,
            "is_successor": self.is_successor,
            "is_feasible_successor": self.is_feasible_successor,
            "query_origin": self.query_origin,
        })
        return base


# =============================================================================
# Protocol Neighbor Models
# =============================================================================

@dataclass
class ProtocolNeighbor:
    """Base protocol neighbor/adjacency."""
    protocol: RoutingProtocol
    neighbor_id: str  # Router ID or identifier
    neighbor_address: str  # IP address
    interface: str | None = None
    state: str = "unknown"
    uptime: timedelta | None = None
    uptime_seconds: int | None = None
    last_change: datetime | None = None
    vrf: str = "default"

    def to_dict(self) -> dict[str, Any]:
        return {
            "protocol": self.protocol.value,
            "neighbor_id": self.neighbor_id,
            "neighbor_address": self.neighbor_address,
            "interface": self.interface,
            "state": self.state,
            "uptime_seconds": self.uptime_seconds,
            "last_change": self.last_change.isoformat() if self.last_change else None,
            "vrf": self.vrf,
        }


@dataclass
class BGPNeighbor(ProtocolNeighbor):
    """BGP neighbor with session details."""
    remote_asn: int = 0
    local_asn: int = 0
    session_type: BGPSessionType = BGPSessionType.EBGP
    bgp_state: BGPState = BGPState.IDLE

    # Prefix counts
    prefixes_received: int = 0
    prefixes_sent: int = 0
    prefixes_accepted: int = 0
    prefixes_rejected: int = 0

    # Timers
    hold_time: int = 180
    keepalive: int = 60
    connect_retry: int = 30

    # Capabilities
    capabilities: list[str] = field(default_factory=list)
    address_families: list[str] = field(default_factory=list)

    # Router IDs
    local_router_id: str | None = None
    remote_router_id: str | None = None

    # Route reflector
    route_reflector_client: bool = False
    cluster_id: str | None = None

    # Counters
    messages_received: int = 0
    messages_sent: int = 0
    updates_received: int = 0
    updates_sent: int = 0
    notifications_received: int = 0
    notifications_sent: int = 0

    # Last error
    last_error: str | None = None
    last_error_time: datetime | None = None

    def __post_init__(self):
        self.protocol = RoutingProtocol.BGP
        self.state = self.bgp_state.value

    def to_dict(self) -> dict[str, Any]:
        base = super().to_dict()
        base.update({
            "remote_asn": self.remote_asn,
            "local_asn": self.local_asn,
            "session_type": self.session_type.value,
            "bgp_state": self.bgp_state.value,
            "prefixes_received": self.prefixes_received,
            "prefixes_sent": self.prefixes_sent,
            "prefixes_accepted": self.prefixes_accepted,
            "prefixes_rejected": self.prefixes_rejected,
            "hold_time": self.hold_time,
            "keepalive": self.keepalive,
            "capabilities": self.capabilities,
            "address_families": self.address_families,
            "local_router_id": self.local_router_id,
            "remote_router_id": self.remote_router_id,
            "route_reflector_client": self.route_reflector_client,
            "cluster_id": self.cluster_id,
            "messages_received": self.messages_received,
            "messages_sent": self.messages_sent,
            "updates_received": self.updates_received,
            "updates_sent": self.updates_sent,
            "last_error": self.last_error,
            "last_error_time": self.last_error_time.isoformat() if self.last_error_time else None,
        })
        return base


@dataclass
class OSPFNeighbor(ProtocolNeighbor):
    """OSPF neighbor with DR/BDR information."""
    ospf_state: OSPFState = OSPFState.DOWN
    area: str = "0.0.0.0"
    priority: int = 1

    # DR/BDR
    dr: str | None = None  # Designated Router
    bdr: str | None = None  # Backup Designated Router
    is_dr: bool = False
    is_bdr: bool = False

    # Timers
    dead_timer: int = 40
    hello_timer: int = 10
    retransmit_interval: int = 5

    # Database sync
    dbd_sequence: int = 0
    lsa_retransmit_count: int = 0

    # Options
    options: list[str] = field(default_factory=list)

    def __post_init__(self):
        self.protocol = RoutingProtocol.OSPF
        self.state = self.ospf_state.value

    def to_dict(self) -> dict[str, Any]:
        base = super().to_dict()
        base.update({
            "ospf_state": self.ospf_state.value,
            "area": self.area,
            "priority": self.priority,
            "dr": self.dr,
            "bdr": self.bdr,
            "is_dr": self.is_dr,
            "is_bdr": self.is_bdr,
            "dead_timer": self.dead_timer,
            "hello_timer": self.hello_timer,
            "options": self.options,
        })
        return base


@dataclass
class ISISAdjacency(ProtocolNeighbor):
    """IS-IS adjacency information."""
    isis_state: ISISState = ISISState.DOWN
    level: ISISLevel = ISISLevel.L2
    system_id: str | None = None

    # Circuit info
    circuit_type: str | None = None
    circuit_id: int | None = None

    # Metrics
    metric: int = 10

    # Timers
    hold_time: int = 30

    # SNPA (Subnetwork Point of Attachment) - usually MAC address
    snpa: str | None = None

    def __post_init__(self):
        self.protocol = RoutingProtocol.ISIS
        self.state = self.isis_state.value

    def to_dict(self) -> dict[str, Any]:
        base = super().to_dict()
        base.update({
            "isis_state": self.isis_state.value,
            "level": self.level.value,
            "system_id": self.system_id,
            "circuit_type": self.circuit_type,
            "circuit_id": self.circuit_id,
            "metric": self.metric,
            "hold_time": self.hold_time,
            "snpa": self.snpa,
        })
        return base


@dataclass
class RIPNeighbor(ProtocolNeighbor):
    """RIP neighbor information."""
    version: int = 2  # RIP version
    bad_packets: int = 0
    bad_routes: int = 0
    last_update: datetime | None = None

    def __post_init__(self):
        self.protocol = RoutingProtocol.RIP

    def to_dict(self) -> dict[str, Any]:
        base = super().to_dict()
        base.update({
            "version": self.version,
            "bad_packets": self.bad_packets,
            "bad_routes": self.bad_routes,
            "last_update": self.last_update.isoformat() if self.last_update else None,
        })
        return base


@dataclass
class EIGRPNeighbor(ProtocolNeighbor):
    """EIGRP neighbor with DUAL state."""
    eigrp_state: EIGRPState = EIGRPState.ACTIVE
    as_number: int = 0

    # Queue counts
    q_count: int = 0  # Packets in queue

    # Timers
    hold_time: int = 15
    uptime_str: str | None = None  # Human readable uptime

    # Retransmit
    srtt: int = 0  # Smooth Round Trip Time (ms)
    rto: int = 0  # Retransmission Timeout (ms)

    # Sequence numbers
    sequence_number: int = 0

    # K-values (metric weights)
    k_values: list[int] = field(default_factory=lambda: [1, 0, 1, 0, 0])

    def __post_init__(self):
        self.protocol = RoutingProtocol.EIGRP
        self.state = self.eigrp_state.value

    def to_dict(self) -> dict[str, Any]:
        base = super().to_dict()
        base.update({
            "eigrp_state": self.eigrp_state.value,
            "as_number": self.as_number,
            "q_count": self.q_count,
            "hold_time": self.hold_time,
            "srtt": self.srtt,
            "rto": self.rto,
            "sequence_number": self.sequence_number,
            "k_values": self.k_values,
        })
        return base


# =============================================================================
# Redistribution Model
# =============================================================================

@dataclass
class RedistributionPoint:
    """Route redistribution configuration."""
    source_protocol: RoutingProtocol
    target_protocol: RoutingProtocol
    route_map: str | None = None
    prefix_list: str | None = None
    metric: int | None = None
    metric_type: str | None = None  # For OSPF: E1, E2
    tag: int | None = None

    # Match criteria
    match_criteria: dict[str, Any] = field(default_factory=dict)
    # Set actions
    set_actions: dict[str, Any] = field(default_factory=dict)

    # Status
    enabled: bool = True

    def to_dict(self) -> dict[str, Any]:
        return {
            "source_protocol": self.source_protocol.value,
            "target_protocol": self.target_protocol.value,
            "route_map": self.route_map,
            "prefix_list": self.prefix_list,
            "metric": self.metric,
            "metric_type": self.metric_type,
            "tag": self.tag,
            "match_criteria": self.match_criteria,
            "set_actions": self.set_actions,
            "enabled": self.enabled,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "RedistributionPoint":
        return cls(
            source_protocol=RoutingProtocol(data["source_protocol"]),
            target_protocol=RoutingProtocol(data["target_protocol"]),
            route_map=data.get("route_map"),
            prefix_list=data.get("prefix_list"),
            metric=data.get("metric"),
            metric_type=data.get("metric_type"),
            tag=data.get("tag"),
            match_criteria=data.get("match_criteria", {}),
            set_actions=data.get("set_actions", {}),
            enabled=data.get("enabled", True),
        )


# =============================================================================
# Snapshot and Change Tracking Models
# =============================================================================

@dataclass
class RoutingSnapshot:
    """Point-in-time snapshot of routing state."""
    id: int | None = None
    device_id: str | None = None
    device_hostname: str | None = None
    timestamp: datetime | None = None
    snapshot_type: str = "manual"  # manual, scheduled, event

    # Counts
    route_count: int = 0
    neighbor_count: int = 0

    # Routes and neighbors (populated when loaded)
    routes: list[Route] = field(default_factory=list)
    neighbors: list[ProtocolNeighbor] = field(default_factory=list)
    redistributions: list[RedistributionPoint] = field(default_factory=list)
    vrfs: list[VRF] = field(default_factory=list)

    # Metadata
    notes: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "device_id": self.device_id,
            "device_hostname": self.device_hostname,
            "timestamp": self.timestamp.isoformat() if self.timestamp else None,
            "snapshot_type": self.snapshot_type,
            "route_count": self.route_count,
            "neighbor_count": self.neighbor_count,
            "notes": self.notes,
        }


@dataclass
class RouteChange:
    """Track route changes for flap detection."""
    id: int | None = None
    device_id: str | None = None
    prefix: str | None = None
    prefix_length: int = 0
    change_type: str = "update"  # add, withdraw, update
    timestamp: datetime | None = None

    # Old and new state
    old_next_hop: str | None = None
    new_next_hop: str | None = None
    old_metric: int | None = None
    new_metric: int | None = None
    old_attributes: dict[str, Any] = field(default_factory=dict)
    new_attributes: dict[str, Any] = field(default_factory=dict)

    # Protocol
    protocol: RoutingProtocol = RoutingProtocol.UNKNOWN

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "device_id": self.device_id,
            "prefix": self.prefix,
            "prefix_length": self.prefix_length,
            "change_type": self.change_type,
            "timestamp": self.timestamp.isoformat() if self.timestamp else None,
            "old_next_hop": self.old_next_hop,
            "new_next_hop": self.new_next_hop,
            "old_metric": self.old_metric,
            "new_metric": self.new_metric,
            "protocol": self.protocol.value,
        }


# =============================================================================
# Protocol Summary Models
# =============================================================================

@dataclass
class BGPSummary:
    """BGP protocol summary."""
    router_id: str | None = None
    local_asn: int = 0
    total_neighbors: int = 0
    established_neighbors: int = 0
    total_prefixes: int = 0
    total_paths: int = 0

    # Memory
    memory_used: int = 0  # bytes

    # Per address-family stats
    ipv4_unicast_prefixes: int = 0
    ipv6_unicast_prefixes: int = 0
    vpnv4_prefixes: int = 0

    def to_dict(self) -> dict[str, Any]:
        return {
            "router_id": self.router_id,
            "local_asn": self.local_asn,
            "total_neighbors": self.total_neighbors,
            "established_neighbors": self.established_neighbors,
            "total_prefixes": self.total_prefixes,
            "total_paths": self.total_paths,
            "memory_used": self.memory_used,
            "ipv4_unicast_prefixes": self.ipv4_unicast_prefixes,
            "ipv6_unicast_prefixes": self.ipv6_unicast_prefixes,
            "vpnv4_prefixes": self.vpnv4_prefixes,
        }


@dataclass
class OSPFSummary:
    """OSPF protocol summary."""
    router_id: str | None = None
    process_id: int = 0
    reference_bandwidth: int = 100  # Mbps
    spf_delay: int = 5000  # ms
    spf_hold: int = 10000  # ms

    # Area counts
    total_areas: int = 0
    normal_areas: int = 0
    stub_areas: int = 0
    nssa_areas: int = 0

    # LSA counts
    total_lsas: int = 0
    router_lsas: int = 0
    network_lsas: int = 0
    summary_lsas: int = 0
    external_lsas: int = 0

    # Neighbor counts
    total_neighbors: int = 0
    full_neighbors: int = 0

    def to_dict(self) -> dict[str, Any]:
        return {
            "router_id": self.router_id,
            "process_id": self.process_id,
            "reference_bandwidth": self.reference_bandwidth,
            "total_areas": self.total_areas,
            "total_lsas": self.total_lsas,
            "total_neighbors": self.total_neighbors,
            "full_neighbors": self.full_neighbors,
        }


@dataclass
class ISISSummary:
    """IS-IS protocol summary."""
    system_id: str | None = None
    net: str | None = None  # Network Entity Title
    is_type: ISISLevel = ISISLevel.L1L2

    # Area info
    area_addresses: list[str] = field(default_factory=list)

    # Interface counts
    l1_interfaces: int = 0
    l2_interfaces: int = 0

    # Adjacency counts
    l1_adjacencies: int = 0
    l2_adjacencies: int = 0

    # LSP counts
    l1_lsps: int = 0
    l2_lsps: int = 0

    def to_dict(self) -> dict[str, Any]:
        return {
            "system_id": self.system_id,
            "net": self.net,
            "is_type": self.is_type.value,
            "area_addresses": self.area_addresses,
            "l1_adjacencies": self.l1_adjacencies,
            "l2_adjacencies": self.l2_adjacencies,
            "l1_lsps": self.l1_lsps,
            "l2_lsps": self.l2_lsps,
        }


@dataclass
class EIGRPSummary:
    """EIGRP protocol summary."""
    router_id: str | None = None
    as_number: int = 0

    # K-values
    k1: int = 1
    k2: int = 0
    k3: int = 1
    k4: int = 0
    k5: int = 0

    # Counts
    neighbor_count: int = 0
    route_count: int = 0

    # Active queries
    active_queries: int = 0
    stuck_in_active: int = 0

    def to_dict(self) -> dict[str, Any]:
        return {
            "router_id": self.router_id,
            "as_number": self.as_number,
            "k_values": [self.k1, self.k2, self.k3, self.k4, self.k5],
            "neighbor_count": self.neighbor_count,
            "route_count": self.route_count,
            "active_queries": self.active_queries,
            "stuck_in_active": self.stuck_in_active,
        }
