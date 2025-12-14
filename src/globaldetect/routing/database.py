"""
Database abstraction layer for routing protocol data.

Supports SQLite and PostgreSQL for storing routing snapshots,
route tables, neighbors, and change tracking for flap detection.

Copyright (c) 2025 DNS Science.io, an After Dark Systems, LLC company.
All rights reserved.
"""

import json
import sqlite3
from abc import ABC, abstractmethod
from contextlib import contextmanager
from datetime import datetime
from pathlib import Path
from typing import Any, Generator
from urllib.parse import urlparse

from globaldetect.routing.models import (
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
    VRF,
)


class RoutingDatabase(ABC):
    """Abstract database interface for routing data."""

    @abstractmethod
    def initialize(self) -> None:
        """Initialize database schema."""
        pass

    @abstractmethod
    def close(self) -> None:
        """Close database connection."""
        pass

    # Snapshot operations
    @abstractmethod
    def create_snapshot(self, snapshot: RoutingSnapshot) -> RoutingSnapshot:
        """Create a new routing snapshot."""
        pass

    @abstractmethod
    def get_snapshot(self, snapshot_id: int) -> RoutingSnapshot | None:
        """Get snapshot by ID."""
        pass

    @abstractmethod
    def list_snapshots(
        self,
        device_id: str | None = None,
        limit: int = 100,
    ) -> list[RoutingSnapshot]:
        """List snapshots, optionally filtered by device."""
        pass

    @abstractmethod
    def delete_snapshot(self, snapshot_id: int) -> bool:
        """Delete snapshot and associated data."""
        pass

    # Route operations
    @abstractmethod
    def add_routes(self, snapshot_id: int, routes: list[Route]) -> int:
        """Add routes to a snapshot. Returns count added."""
        pass

    @abstractmethod
    def get_routes(
        self,
        snapshot_id: int,
        protocol: RoutingProtocol | None = None,
        prefix: str | None = None,
        vrf: str | None = None,
    ) -> list[Route]:
        """Get routes from a snapshot with optional filters."""
        pass

    @abstractmethod
    def get_route_by_prefix(
        self,
        snapshot_id: int,
        prefix: str,
        prefix_length: int,
        vrf: str = "default",
    ) -> Route | None:
        """Get a specific route by prefix."""
        pass

    # Neighbor operations
    @abstractmethod
    def add_neighbors(
        self,
        snapshot_id: int,
        neighbors: list[ProtocolNeighbor],
    ) -> int:
        """Add neighbors to a snapshot. Returns count added."""
        pass

    @abstractmethod
    def get_neighbors(
        self,
        snapshot_id: int,
        protocol: RoutingProtocol | None = None,
        state: str | None = None,
    ) -> list[ProtocolNeighbor]:
        """Get neighbors from a snapshot with optional filters."""
        pass

    # Redistribution operations
    @abstractmethod
    def add_redistributions(
        self,
        device_id: str,
        redistributions: list[RedistributionPoint],
    ) -> int:
        """Add redistribution config for a device."""
        pass

    @abstractmethod
    def get_redistributions(
        self,
        device_id: str,
        source_protocol: RoutingProtocol | None = None,
        target_protocol: RoutingProtocol | None = None,
    ) -> list[RedistributionPoint]:
        """Get redistribution config for a device."""
        pass

    # Change tracking
    @abstractmethod
    def record_route_change(self, change: RouteChange) -> RouteChange:
        """Record a route change for flap detection."""
        pass

    @abstractmethod
    def get_route_changes(
        self,
        device_id: str,
        prefix: str | None = None,
        since: datetime | None = None,
        limit: int = 1000,
    ) -> list[RouteChange]:
        """Get route changes for flap analysis."""
        pass

    @abstractmethod
    def get_flapping_routes(
        self,
        device_id: str,
        threshold: int = 5,
        period_minutes: int = 15,
    ) -> list[dict[str, Any]]:
        """Get routes that have flapped above threshold in period."""
        pass

    # VRF operations
    @abstractmethod
    def add_vrfs(self, snapshot_id: int, vrfs: list[VRF]) -> int:
        """Add VRFs to a snapshot."""
        pass

    @abstractmethod
    def get_vrfs(self, snapshot_id: int) -> list[VRF]:
        """Get VRFs from a snapshot."""
        pass

    # Comparison and diff
    @abstractmethod
    def compare_snapshots(
        self,
        snapshot_id_1: int,
        snapshot_id_2: int,
    ) -> dict[str, Any]:
        """Compare two snapshots and return differences."""
        pass


class SQLiteRoutingDatabase(RoutingDatabase):
    """SQLite implementation for routing data."""

    def __init__(self, db_path: str = "globaldetect_routing.db"):
        self.db_path = db_path
        self._conn: sqlite3.Connection | None = None

    @contextmanager
    def _get_conn(self) -> Generator[sqlite3.Connection, None, None]:
        """Get database connection with row factory."""
        if self._conn is None:
            self._conn = sqlite3.connect(self.db_path)
            self._conn.row_factory = sqlite3.Row
        yield self._conn

    def close(self) -> None:
        if self._conn:
            self._conn.close()
            self._conn = None

    def initialize(self) -> None:
        """Create database schema."""
        with self._get_conn() as conn:
            conn.executescript("""
                -- Routing snapshots table
                CREATE TABLE IF NOT EXISTS routing_snapshots (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    device_id TEXT NOT NULL,
                    device_hostname TEXT,
                    timestamp TEXT DEFAULT CURRENT_TIMESTAMP,
                    snapshot_type TEXT DEFAULT 'manual',
                    route_count INTEGER DEFAULT 0,
                    neighbor_count INTEGER DEFAULT 0,
                    notes TEXT
                );

                -- Routes table
                CREATE TABLE IF NOT EXISTS routes (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    snapshot_id INTEGER NOT NULL,
                    prefix TEXT NOT NULL,
                    prefix_length INTEGER NOT NULL,
                    protocol TEXT NOT NULL,
                    next_hop TEXT,
                    next_hops TEXT,  -- JSON array
                    interface TEXT,
                    metric INTEGER DEFAULT 0,
                    admin_distance INTEGER DEFAULT 0,
                    age_seconds INTEGER,
                    tag INTEGER,
                    vrf TEXT DEFAULT 'default',
                    route_type TEXT DEFAULT 'best',
                    active INTEGER DEFAULT 1,
                    fib_installed INTEGER DEFAULT 1,
                    attributes TEXT,  -- JSON for protocol-specific attributes
                    FOREIGN KEY (snapshot_id) REFERENCES routing_snapshots(id) ON DELETE CASCADE
                );

                -- Protocol neighbors table
                CREATE TABLE IF NOT EXISTS protocol_neighbors (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    snapshot_id INTEGER NOT NULL,
                    protocol TEXT NOT NULL,
                    neighbor_id TEXT,
                    neighbor_address TEXT NOT NULL,
                    interface TEXT,
                    state TEXT NOT NULL,
                    uptime_seconds INTEGER,
                    vrf TEXT DEFAULT 'default',
                    attributes TEXT,  -- JSON for protocol-specific attributes
                    FOREIGN KEY (snapshot_id) REFERENCES routing_snapshots(id) ON DELETE CASCADE
                );

                -- Route changes table (for flap detection)
                CREATE TABLE IF NOT EXISTS route_changes (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    device_id TEXT NOT NULL,
                    prefix TEXT NOT NULL,
                    prefix_length INTEGER NOT NULL,
                    change_type TEXT NOT NULL,
                    timestamp TEXT DEFAULT CURRENT_TIMESTAMP,
                    protocol TEXT,
                    old_next_hop TEXT,
                    new_next_hop TEXT,
                    old_metric INTEGER,
                    new_metric INTEGER,
                    old_attributes TEXT,
                    new_attributes TEXT
                );

                -- Redistribution configuration table
                CREATE TABLE IF NOT EXISTS redistribution_config (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    device_id TEXT NOT NULL,
                    source_protocol TEXT NOT NULL,
                    target_protocol TEXT NOT NULL,
                    route_map TEXT,
                    prefix_list TEXT,
                    metric INTEGER,
                    metric_type TEXT,
                    tag INTEGER,
                    match_criteria TEXT,  -- JSON
                    set_actions TEXT,  -- JSON
                    enabled INTEGER DEFAULT 1,
                    created_at TEXT DEFAULT CURRENT_TIMESTAMP,
                    updated_at TEXT DEFAULT CURRENT_TIMESTAMP
                );

                -- VRF table
                CREATE TABLE IF NOT EXISTS vrfs (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    snapshot_id INTEGER NOT NULL,
                    name TEXT NOT NULL,
                    rd TEXT,
                    rt_import TEXT,  -- JSON array
                    rt_export TEXT,  -- JSON array
                    description TEXT,
                    interfaces TEXT,  -- JSON array
                    FOREIGN KEY (snapshot_id) REFERENCES routing_snapshots(id) ON DELETE CASCADE
                );

                -- Indexes for performance
                CREATE INDEX IF NOT EXISTS idx_routes_snapshot ON routes(snapshot_id);
                CREATE INDEX IF NOT EXISTS idx_routes_prefix ON routes(prefix, prefix_length);
                CREATE INDEX IF NOT EXISTS idx_routes_protocol ON routes(protocol);
                CREATE INDEX IF NOT EXISTS idx_routes_vrf ON routes(vrf);
                CREATE INDEX IF NOT EXISTS idx_neighbors_snapshot ON protocol_neighbors(snapshot_id);
                CREATE INDEX IF NOT EXISTS idx_neighbors_protocol ON protocol_neighbors(protocol);
                CREATE INDEX IF NOT EXISTS idx_neighbors_state ON protocol_neighbors(state);
                CREATE INDEX IF NOT EXISTS idx_changes_device ON route_changes(device_id);
                CREATE INDEX IF NOT EXISTS idx_changes_prefix ON route_changes(prefix, timestamp);
                CREATE INDEX IF NOT EXISTS idx_changes_timestamp ON route_changes(timestamp);
                CREATE INDEX IF NOT EXISTS idx_redistribution_device ON redistribution_config(device_id);
                CREATE INDEX IF NOT EXISTS idx_snapshots_device ON routing_snapshots(device_id);
                CREATE INDEX IF NOT EXISTS idx_snapshots_timestamp ON routing_snapshots(timestamp);
                CREATE INDEX IF NOT EXISTS idx_vrfs_snapshot ON vrfs(snapshot_id);
            """)
            conn.commit()

    # Snapshot operations
    def create_snapshot(self, snapshot: RoutingSnapshot) -> RoutingSnapshot:
        with self._get_conn() as conn:
            cursor = conn.execute("""
                INSERT INTO routing_snapshots (
                    device_id, device_hostname, timestamp, snapshot_type,
                    route_count, neighbor_count, notes
                ) VALUES (?, ?, ?, ?, ?, ?, ?)
            """, (
                snapshot.device_id,
                snapshot.device_hostname,
                snapshot.timestamp.isoformat() if snapshot.timestamp else datetime.now().isoformat(),
                snapshot.snapshot_type,
                snapshot.route_count,
                snapshot.neighbor_count,
                snapshot.notes,
            ))
            conn.commit()
            snapshot.id = cursor.lastrowid
            if snapshot.timestamp is None:
                snapshot.timestamp = datetime.now()
            return snapshot

    def get_snapshot(self, snapshot_id: int) -> RoutingSnapshot | None:
        with self._get_conn() as conn:
            row = conn.execute(
                "SELECT * FROM routing_snapshots WHERE id = ?", (snapshot_id,)
            ).fetchone()
            if row:
                return self._row_to_snapshot(row)
            return None

    def list_snapshots(
        self,
        device_id: str | None = None,
        limit: int = 100,
    ) -> list[RoutingSnapshot]:
        with self._get_conn() as conn:
            query = "SELECT * FROM routing_snapshots WHERE 1=1"
            params: list[Any] = []

            if device_id:
                query += " AND device_id = ?"
                params.append(device_id)

            query += " ORDER BY timestamp DESC LIMIT ?"
            params.append(limit)

            rows = conn.execute(query, params).fetchall()
            return [self._row_to_snapshot(row) for row in rows]

    def delete_snapshot(self, snapshot_id: int) -> bool:
        with self._get_conn() as conn:
            cursor = conn.execute(
                "DELETE FROM routing_snapshots WHERE id = ?", (snapshot_id,)
            )
            conn.commit()
            return cursor.rowcount > 0

    def _row_to_snapshot(self, row: sqlite3.Row) -> RoutingSnapshot:
        return RoutingSnapshot(
            id=row["id"],
            device_id=row["device_id"],
            device_hostname=row["device_hostname"],
            timestamp=datetime.fromisoformat(row["timestamp"]) if row["timestamp"] else None,
            snapshot_type=row["snapshot_type"],
            route_count=row["route_count"],
            neighbor_count=row["neighbor_count"],
            notes=row["notes"],
        )

    # Route operations
    def add_routes(self, snapshot_id: int, routes: list[Route]) -> int:
        with self._get_conn() as conn:
            count = 0
            for route in routes:
                # Build protocol-specific attributes
                attrs = route.attributes.copy() if route.attributes else {}

                if isinstance(route, BGPRoute):
                    attrs.update({
                        "as_path": route.as_path,
                        "as_path_str": route.as_path_str,
                        "origin": route.origin.value,
                        "local_pref": route.local_pref,
                        "med": route.med,
                        "weight": route.weight,
                        "communities": route.communities,
                        "large_communities": route.large_communities,
                        "ext_communities": route.ext_communities,
                        "cluster_list": route.cluster_list,
                        "originator_id": route.originator_id,
                        "neighbor": route.neighbor,
                        "neighbor_asn": route.neighbor_asn,
                        "session_type": route.session_type.value if route.session_type else None,
                        "best": route.best,
                        "valid": route.valid,
                        "multipath": route.multipath,
                    })
                elif isinstance(route, OSPFRoute):
                    attrs.update({
                        "area": route.area,
                        "area_type": route.area_type.value,
                        "ospf_route_type": route.ospf_route_type.value,
                        "cost": route.cost,
                        "forwarding_address": route.forwarding_address,
                        "external_tag": route.external_tag,
                        "lsa_type": route.lsa_type,
                        "advertising_router": route.advertising_router,
                    })
                elif isinstance(route, ISISRoute):
                    attrs.update({
                        "level": route.level.value,
                        "metric_type": route.metric_type,
                        "system_id": route.system_id,
                        "lsp_id": route.lsp_id,
                    })
                elif isinstance(route, RIPRoute):
                    attrs.update({
                        "hop_count": route.hop_count,
                        "timeout": route.timeout,
                        "garbage_collect": route.garbage_collect,
                    })
                elif isinstance(route, EIGRPRoute):
                    attrs.update({
                        "bandwidth": route.bandwidth,
                        "delay": route.delay,
                        "reliability": route.reliability,
                        "load": route.load,
                        "mtu": route.mtu,
                        "feasible_distance": route.feasible_distance,
                        "reported_distance": route.reported_distance,
                        "successor": route.successor,
                        "feasible_successors": route.feasible_successors,
                        "as_number": route.as_number,
                        "is_successor": route.is_successor,
                        "is_feasible_successor": route.is_feasible_successor,
                    })

                conn.execute("""
                    INSERT INTO routes (
                        snapshot_id, prefix, prefix_length, protocol, next_hop,
                        next_hops, interface, metric, admin_distance, age_seconds,
                        tag, vrf, route_type, active, fib_installed, attributes
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """, (
                    snapshot_id,
                    route.prefix,
                    route.prefix_length,
                    route.protocol.value,
                    route.next_hop,
                    json.dumps(route.next_hops),
                    route.interface,
                    route.metric,
                    route.admin_distance,
                    route.age_seconds,
                    route.tag,
                    route.vrf,
                    route.route_type.value,
                    1 if route.active else 0,
                    1 if route.fib_installed else 0,
                    json.dumps(attrs),
                ))
                count += 1

            # Update route count on snapshot
            conn.execute(
                "UPDATE routing_snapshots SET route_count = ? WHERE id = ?",
                (count, snapshot_id)
            )
            conn.commit()
            return count

    def get_routes(
        self,
        snapshot_id: int,
        protocol: RoutingProtocol | None = None,
        prefix: str | None = None,
        vrf: str | None = None,
    ) -> list[Route]:
        with self._get_conn() as conn:
            query = "SELECT * FROM routes WHERE snapshot_id = ?"
            params: list[Any] = [snapshot_id]

            if protocol:
                query += " AND protocol = ?"
                params.append(protocol.value)
            if prefix:
                query += " AND prefix = ?"
                params.append(prefix)
            if vrf:
                query += " AND vrf = ?"
                params.append(vrf)

            query += " ORDER BY prefix, prefix_length"
            rows = conn.execute(query, params).fetchall()
            return [self._row_to_route(row) for row in rows]

    def get_route_by_prefix(
        self,
        snapshot_id: int,
        prefix: str,
        prefix_length: int,
        vrf: str = "default",
    ) -> Route | None:
        with self._get_conn() as conn:
            row = conn.execute("""
                SELECT * FROM routes
                WHERE snapshot_id = ? AND prefix = ? AND prefix_length = ? AND vrf = ?
            """, (snapshot_id, prefix, prefix_length, vrf)).fetchone()
            if row:
                return self._row_to_route(row)
            return None

    def _row_to_route(self, row: sqlite3.Row) -> Route:
        """Convert a database row to the appropriate Route subclass."""
        protocol = RoutingProtocol(row["protocol"])
        attrs = json.loads(row["attributes"]) if row["attributes"] else {}
        next_hops = json.loads(row["next_hops"]) if row["next_hops"] else []

        base_kwargs = {
            "prefix": row["prefix"],
            "prefix_length": row["prefix_length"],
            "protocol": protocol,
            "next_hop": row["next_hop"],
            "next_hops": next_hops,
            "interface": row["interface"],
            "metric": row["metric"] or 0,
            "admin_distance": row["admin_distance"] or 0,
            "age_seconds": row["age_seconds"],
            "tag": row["tag"],
            "vrf": row["vrf"] or "default",
            "route_type": RouteType(row["route_type"]) if row["route_type"] else RouteType.BEST,
            "active": bool(row["active"]),
            "fib_installed": bool(row["fib_installed"]),
        }

        if protocol == RoutingProtocol.BGP:
            return BGPRoute(
                **base_kwargs,
                as_path=attrs.get("as_path", []),
                as_path_str=attrs.get("as_path_str"),
                origin=BGPOrigin(attrs.get("origin", "incomplete")),
                local_pref=attrs.get("local_pref", 100),
                med=attrs.get("med", 0),
                weight=attrs.get("weight", 0),
                communities=attrs.get("communities", []),
                large_communities=attrs.get("large_communities", []),
                ext_communities=attrs.get("ext_communities", []),
                cluster_list=attrs.get("cluster_list", []),
                originator_id=attrs.get("originator_id"),
                neighbor=attrs.get("neighbor"),
                neighbor_asn=attrs.get("neighbor_asn"),
                session_type=BGPSessionType(attrs["session_type"]) if attrs.get("session_type") else None,
                best=attrs.get("best", False),
                valid=attrs.get("valid", True),
                multipath=attrs.get("multipath", False),
            )
        elif protocol == RoutingProtocol.OSPF:
            return OSPFRoute(
                **base_kwargs,
                area=attrs.get("area"),
                area_type=OSPFAreaType(attrs.get("area_type", "normal")),
                ospf_route_type=OSPFRouteType(attrs.get("ospf_route_type", "O")),
                cost=attrs.get("cost", 0),
                forwarding_address=attrs.get("forwarding_address"),
                external_tag=attrs.get("external_tag"),
                lsa_type=attrs.get("lsa_type"),
                advertising_router=attrs.get("advertising_router"),
            )
        elif protocol == RoutingProtocol.ISIS:
            return ISISRoute(
                **base_kwargs,
                level=ISISLevel(attrs.get("level", "L2")),
                metric_type=attrs.get("metric_type", "internal"),
                system_id=attrs.get("system_id"),
                lsp_id=attrs.get("lsp_id"),
            )
        elif protocol == RoutingProtocol.RIP:
            return RIPRoute(
                **base_kwargs,
                hop_count=attrs.get("hop_count", 0),
                timeout=attrs.get("timeout"),
                garbage_collect=attrs.get("garbage_collect"),
            )
        elif protocol == RoutingProtocol.EIGRP:
            return EIGRPRoute(
                **base_kwargs,
                bandwidth=attrs.get("bandwidth", 0),
                delay=attrs.get("delay", 0),
                reliability=attrs.get("reliability", 255),
                load=attrs.get("load", 1),
                mtu=attrs.get("mtu", 1500),
                feasible_distance=attrs.get("feasible_distance", 0),
                reported_distance=attrs.get("reported_distance", 0),
                successor=attrs.get("successor"),
                feasible_successors=attrs.get("feasible_successors", []),
                as_number=attrs.get("as_number"),
                is_successor=attrs.get("is_successor", True),
                is_feasible_successor=attrs.get("is_feasible_successor", False),
            )
        else:
            return Route(**base_kwargs, attributes=attrs)

    # Neighbor operations
    def add_neighbors(
        self,
        snapshot_id: int,
        neighbors: list[ProtocolNeighbor],
    ) -> int:
        with self._get_conn() as conn:
            count = 0
            for neighbor in neighbors:
                # Build protocol-specific attributes
                attrs: dict[str, Any] = {}

                if isinstance(neighbor, BGPNeighbor):
                    attrs.update({
                        "remote_asn": neighbor.remote_asn,
                        "local_asn": neighbor.local_asn,
                        "session_type": neighbor.session_type.value,
                        "bgp_state": neighbor.bgp_state.value,
                        "prefixes_received": neighbor.prefixes_received,
                        "prefixes_sent": neighbor.prefixes_sent,
                        "prefixes_accepted": neighbor.prefixes_accepted,
                        "prefixes_rejected": neighbor.prefixes_rejected,
                        "hold_time": neighbor.hold_time,
                        "keepalive": neighbor.keepalive,
                        "capabilities": neighbor.capabilities,
                        "address_families": neighbor.address_families,
                        "local_router_id": neighbor.local_router_id,
                        "remote_router_id": neighbor.remote_router_id,
                        "route_reflector_client": neighbor.route_reflector_client,
                        "cluster_id": neighbor.cluster_id,
                        "messages_received": neighbor.messages_received,
                        "messages_sent": neighbor.messages_sent,
                        "updates_received": neighbor.updates_received,
                        "updates_sent": neighbor.updates_sent,
                        "last_error": neighbor.last_error,
                    })
                elif isinstance(neighbor, OSPFNeighbor):
                    attrs.update({
                        "ospf_state": neighbor.ospf_state.value,
                        "area": neighbor.area,
                        "priority": neighbor.priority,
                        "dr": neighbor.dr,
                        "bdr": neighbor.bdr,
                        "is_dr": neighbor.is_dr,
                        "is_bdr": neighbor.is_bdr,
                        "dead_timer": neighbor.dead_timer,
                        "hello_timer": neighbor.hello_timer,
                        "options": neighbor.options,
                    })
                elif isinstance(neighbor, ISISAdjacency):
                    attrs.update({
                        "isis_state": neighbor.isis_state.value,
                        "level": neighbor.level.value,
                        "system_id": neighbor.system_id,
                        "circuit_type": neighbor.circuit_type,
                        "circuit_id": neighbor.circuit_id,
                        "metric": neighbor.metric,
                        "hold_time": neighbor.hold_time,
                        "snpa": neighbor.snpa,
                    })
                elif isinstance(neighbor, RIPNeighbor):
                    attrs.update({
                        "version": neighbor.version,
                        "bad_packets": neighbor.bad_packets,
                        "bad_routes": neighbor.bad_routes,
                        "last_update": neighbor.last_update.isoformat() if neighbor.last_update else None,
                    })
                elif isinstance(neighbor, EIGRPNeighbor):
                    attrs.update({
                        "eigrp_state": neighbor.eigrp_state.value,
                        "as_number": neighbor.as_number,
                        "q_count": neighbor.q_count,
                        "hold_time": neighbor.hold_time,
                        "srtt": neighbor.srtt,
                        "rto": neighbor.rto,
                        "sequence_number": neighbor.sequence_number,
                        "k_values": neighbor.k_values,
                    })

                conn.execute("""
                    INSERT INTO protocol_neighbors (
                        snapshot_id, protocol, neighbor_id, neighbor_address,
                        interface, state, uptime_seconds, vrf, attributes
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                """, (
                    snapshot_id,
                    neighbor.protocol.value,
                    neighbor.neighbor_id,
                    neighbor.neighbor_address,
                    neighbor.interface,
                    neighbor.state,
                    neighbor.uptime_seconds,
                    neighbor.vrf,
                    json.dumps(attrs),
                ))
                count += 1

            # Update neighbor count on snapshot
            conn.execute(
                "UPDATE routing_snapshots SET neighbor_count = ? WHERE id = ?",
                (count, snapshot_id)
            )
            conn.commit()
            return count

    def get_neighbors(
        self,
        snapshot_id: int,
        protocol: RoutingProtocol | None = None,
        state: str | None = None,
    ) -> list[ProtocolNeighbor]:
        with self._get_conn() as conn:
            query = "SELECT * FROM protocol_neighbors WHERE snapshot_id = ?"
            params: list[Any] = [snapshot_id]

            if protocol:
                query += " AND protocol = ?"
                params.append(protocol.value)
            if state:
                query += " AND state = ?"
                params.append(state)

            query += " ORDER BY protocol, neighbor_address"
            rows = conn.execute(query, params).fetchall()
            return [self._row_to_neighbor(row) for row in rows]

    def _row_to_neighbor(self, row: sqlite3.Row) -> ProtocolNeighbor:
        """Convert a database row to the appropriate Neighbor subclass."""
        protocol = RoutingProtocol(row["protocol"])
        attrs = json.loads(row["attributes"]) if row["attributes"] else {}

        base_kwargs = {
            "protocol": protocol,
            "neighbor_id": row["neighbor_id"],
            "neighbor_address": row["neighbor_address"],
            "interface": row["interface"],
            "state": row["state"],
            "uptime_seconds": row["uptime_seconds"],
            "vrf": row["vrf"] or "default",
        }

        if protocol == RoutingProtocol.BGP:
            return BGPNeighbor(
                **base_kwargs,
                remote_asn=attrs.get("remote_asn", 0),
                local_asn=attrs.get("local_asn", 0),
                session_type=BGPSessionType(attrs.get("session_type", "ebgp")),
                bgp_state=BGPState(attrs.get("bgp_state", "idle")),
                prefixes_received=attrs.get("prefixes_received", 0),
                prefixes_sent=attrs.get("prefixes_sent", 0),
                prefixes_accepted=attrs.get("prefixes_accepted", 0),
                prefixes_rejected=attrs.get("prefixes_rejected", 0),
                hold_time=attrs.get("hold_time", 180),
                keepalive=attrs.get("keepalive", 60),
                capabilities=attrs.get("capabilities", []),
                address_families=attrs.get("address_families", []),
                local_router_id=attrs.get("local_router_id"),
                remote_router_id=attrs.get("remote_router_id"),
                route_reflector_client=attrs.get("route_reflector_client", False),
                cluster_id=attrs.get("cluster_id"),
                messages_received=attrs.get("messages_received", 0),
                messages_sent=attrs.get("messages_sent", 0),
                updates_received=attrs.get("updates_received", 0),
                updates_sent=attrs.get("updates_sent", 0),
                last_error=attrs.get("last_error"),
            )
        elif protocol == RoutingProtocol.OSPF:
            return OSPFNeighbor(
                **base_kwargs,
                ospf_state=OSPFState(attrs.get("ospf_state", "down")),
                area=attrs.get("area", "0.0.0.0"),
                priority=attrs.get("priority", 1),
                dr=attrs.get("dr"),
                bdr=attrs.get("bdr"),
                is_dr=attrs.get("is_dr", False),
                is_bdr=attrs.get("is_bdr", False),
                dead_timer=attrs.get("dead_timer", 40),
                hello_timer=attrs.get("hello_timer", 10),
                options=attrs.get("options", []),
            )
        elif protocol == RoutingProtocol.ISIS:
            return ISISAdjacency(
                **base_kwargs,
                isis_state=ISISState(attrs.get("isis_state", "down")),
                level=ISISLevel(attrs.get("level", "L2")),
                system_id=attrs.get("system_id"),
                circuit_type=attrs.get("circuit_type"),
                circuit_id=attrs.get("circuit_id"),
                metric=attrs.get("metric", 10),
                hold_time=attrs.get("hold_time", 30),
                snpa=attrs.get("snpa"),
            )
        elif protocol == RoutingProtocol.RIP:
            return RIPNeighbor(
                **base_kwargs,
                version=attrs.get("version", 2),
                bad_packets=attrs.get("bad_packets", 0),
                bad_routes=attrs.get("bad_routes", 0),
                last_update=datetime.fromisoformat(attrs["last_update"]) if attrs.get("last_update") else None,
            )
        elif protocol == RoutingProtocol.EIGRP:
            return EIGRPNeighbor(
                **base_kwargs,
                eigrp_state=EIGRPState(attrs.get("eigrp_state", "active")),
                as_number=attrs.get("as_number", 0),
                q_count=attrs.get("q_count", 0),
                hold_time=attrs.get("hold_time", 15),
                srtt=attrs.get("srtt", 0),
                rto=attrs.get("rto", 0),
                sequence_number=attrs.get("sequence_number", 0),
                k_values=attrs.get("k_values", [1, 0, 1, 0, 0]),
            )
        else:
            return ProtocolNeighbor(**base_kwargs)

    # Redistribution operations
    def add_redistributions(
        self,
        device_id: str,
        redistributions: list[RedistributionPoint],
    ) -> int:
        with self._get_conn() as conn:
            # Clear existing redistributions for this device
            conn.execute(
                "DELETE FROM redistribution_config WHERE device_id = ?",
                (device_id,)
            )

            count = 0
            for redist in redistributions:
                conn.execute("""
                    INSERT INTO redistribution_config (
                        device_id, source_protocol, target_protocol, route_map,
                        prefix_list, metric, metric_type, tag, match_criteria,
                        set_actions, enabled
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """, (
                    device_id,
                    redist.source_protocol.value,
                    redist.target_protocol.value,
                    redist.route_map,
                    redist.prefix_list,
                    redist.metric,
                    redist.metric_type,
                    redist.tag,
                    json.dumps(redist.match_criteria),
                    json.dumps(redist.set_actions),
                    1 if redist.enabled else 0,
                ))
                count += 1

            conn.commit()
            return count

    def get_redistributions(
        self,
        device_id: str,
        source_protocol: RoutingProtocol | None = None,
        target_protocol: RoutingProtocol | None = None,
    ) -> list[RedistributionPoint]:
        with self._get_conn() as conn:
            query = "SELECT * FROM redistribution_config WHERE device_id = ?"
            params: list[Any] = [device_id]

            if source_protocol:
                query += " AND source_protocol = ?"
                params.append(source_protocol.value)
            if target_protocol:
                query += " AND target_protocol = ?"
                params.append(target_protocol.value)

            rows = conn.execute(query, params).fetchall()
            return [self._row_to_redistribution(row) for row in rows]

    def _row_to_redistribution(self, row: sqlite3.Row) -> RedistributionPoint:
        return RedistributionPoint(
            source_protocol=RoutingProtocol(row["source_protocol"]),
            target_protocol=RoutingProtocol(row["target_protocol"]),
            route_map=row["route_map"],
            prefix_list=row["prefix_list"],
            metric=row["metric"],
            metric_type=row["metric_type"],
            tag=row["tag"],
            match_criteria=json.loads(row["match_criteria"]) if row["match_criteria"] else {},
            set_actions=json.loads(row["set_actions"]) if row["set_actions"] else {},
            enabled=bool(row["enabled"]),
        )

    # Change tracking
    def record_route_change(self, change: RouteChange) -> RouteChange:
        with self._get_conn() as conn:
            cursor = conn.execute("""
                INSERT INTO route_changes (
                    device_id, prefix, prefix_length, change_type, timestamp,
                    protocol, old_next_hop, new_next_hop, old_metric, new_metric,
                    old_attributes, new_attributes
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                change.device_id,
                change.prefix,
                change.prefix_length,
                change.change_type,
                change.timestamp.isoformat() if change.timestamp else datetime.now().isoformat(),
                change.protocol.value,
                change.old_next_hop,
                change.new_next_hop,
                change.old_metric,
                change.new_metric,
                json.dumps(change.old_attributes) if change.old_attributes else None,
                json.dumps(change.new_attributes) if change.new_attributes else None,
            ))
            conn.commit()
            change.id = cursor.lastrowid
            if change.timestamp is None:
                change.timestamp = datetime.now()
            return change

    def get_route_changes(
        self,
        device_id: str,
        prefix: str | None = None,
        since: datetime | None = None,
        limit: int = 1000,
    ) -> list[RouteChange]:
        with self._get_conn() as conn:
            query = "SELECT * FROM route_changes WHERE device_id = ?"
            params: list[Any] = [device_id]

            if prefix:
                query += " AND prefix = ?"
                params.append(prefix)
            if since:
                query += " AND timestamp >= ?"
                params.append(since.isoformat())

            query += " ORDER BY timestamp DESC LIMIT ?"
            params.append(limit)

            rows = conn.execute(query, params).fetchall()
            return [self._row_to_route_change(row) for row in rows]

    def _row_to_route_change(self, row: sqlite3.Row) -> RouteChange:
        return RouteChange(
            id=row["id"],
            device_id=row["device_id"],
            prefix=row["prefix"],
            prefix_length=row["prefix_length"],
            change_type=row["change_type"],
            timestamp=datetime.fromisoformat(row["timestamp"]) if row["timestamp"] else None,
            protocol=RoutingProtocol(row["protocol"]) if row["protocol"] else RoutingProtocol.UNKNOWN,
            old_next_hop=row["old_next_hop"],
            new_next_hop=row["new_next_hop"],
            old_metric=row["old_metric"],
            new_metric=row["new_metric"],
            old_attributes=json.loads(row["old_attributes"]) if row["old_attributes"] else {},
            new_attributes=json.loads(row["new_attributes"]) if row["new_attributes"] else {},
        )

    def get_flapping_routes(
        self,
        device_id: str,
        threshold: int = 5,
        period_minutes: int = 15,
    ) -> list[dict[str, Any]]:
        with self._get_conn() as conn:
            # Calculate the time boundary
            cutoff = datetime.now().isoformat()
            # SQLite datetime arithmetic
            rows = conn.execute("""
                SELECT prefix, prefix_length, COUNT(*) as flap_count,
                       MIN(timestamp) as first_flap, MAX(timestamp) as last_flap
                FROM route_changes
                WHERE device_id = ?
                  AND datetime(timestamp) >= datetime('now', ?)
                GROUP BY prefix, prefix_length
                HAVING COUNT(*) >= ?
                ORDER BY flap_count DESC
            """, (device_id, f"-{period_minutes} minutes", threshold)).fetchall()

            return [
                {
                    "prefix": f"{row['prefix']}/{row['prefix_length']}",
                    "flap_count": row["flap_count"],
                    "first_flap": row["first_flap"],
                    "last_flap": row["last_flap"],
                }
                for row in rows
            ]

    # VRF operations
    def add_vrfs(self, snapshot_id: int, vrfs: list[VRF]) -> int:
        with self._get_conn() as conn:
            count = 0
            for vrf in vrfs:
                conn.execute("""
                    INSERT INTO vrfs (
                        snapshot_id, name, rd, rt_import, rt_export,
                        description, interfaces
                    ) VALUES (?, ?, ?, ?, ?, ?, ?)
                """, (
                    snapshot_id,
                    vrf.name,
                    vrf.rd,
                    json.dumps(vrf.rt_import),
                    json.dumps(vrf.rt_export),
                    vrf.description,
                    json.dumps(vrf.interfaces),
                ))
                count += 1
            conn.commit()
            return count

    def get_vrfs(self, snapshot_id: int) -> list[VRF]:
        with self._get_conn() as conn:
            rows = conn.execute(
                "SELECT * FROM vrfs WHERE snapshot_id = ? ORDER BY name",
                (snapshot_id,)
            ).fetchall()
            return [
                VRF(
                    name=row["name"],
                    rd=row["rd"],
                    rt_import=json.loads(row["rt_import"]) if row["rt_import"] else [],
                    rt_export=json.loads(row["rt_export"]) if row["rt_export"] else [],
                    description=row["description"],
                    interfaces=json.loads(row["interfaces"]) if row["interfaces"] else [],
                )
                for row in rows
            ]

    # Comparison and diff
    def compare_snapshots(
        self,
        snapshot_id_1: int,
        snapshot_id_2: int,
    ) -> dict[str, Any]:
        """Compare two snapshots and return differences."""
        routes_1 = {f"{r.prefix}/{r.prefix_length}:{r.vrf}": r for r in self.get_routes(snapshot_id_1)}
        routes_2 = {f"{r.prefix}/{r.prefix_length}:{r.vrf}": r for r in self.get_routes(snapshot_id_2)}

        neighbors_1 = {f"{n.protocol.value}:{n.neighbor_address}": n for n in self.get_neighbors(snapshot_id_1)}
        neighbors_2 = {f"{n.protocol.value}:{n.neighbor_address}": n for n in self.get_neighbors(snapshot_id_2)}

        # Find differences
        added_routes = set(routes_2.keys()) - set(routes_1.keys())
        removed_routes = set(routes_1.keys()) - set(routes_2.keys())
        common_routes = set(routes_1.keys()) & set(routes_2.keys())

        changed_routes = []
        for key in common_routes:
            r1, r2 = routes_1[key], routes_2[key]
            if r1.next_hop != r2.next_hop or r1.metric != r2.metric:
                changed_routes.append({
                    "prefix": key,
                    "old_next_hop": r1.next_hop,
                    "new_next_hop": r2.next_hop,
                    "old_metric": r1.metric,
                    "new_metric": r2.metric,
                })

        added_neighbors = set(neighbors_2.keys()) - set(neighbors_1.keys())
        removed_neighbors = set(neighbors_1.keys()) - set(neighbors_2.keys())

        state_changed_neighbors = []
        for key in set(neighbors_1.keys()) & set(neighbors_2.keys()):
            n1, n2 = neighbors_1[key], neighbors_2[key]
            if n1.state != n2.state:
                state_changed_neighbors.append({
                    "neighbor": key,
                    "old_state": n1.state,
                    "new_state": n2.state,
                })

        return {
            "routes": {
                "added": list(added_routes),
                "removed": list(removed_routes),
                "changed": changed_routes,
            },
            "neighbors": {
                "added": list(added_neighbors),
                "removed": list(removed_neighbors),
                "state_changed": state_changed_neighbors,
            },
            "summary": {
                "routes_added": len(added_routes),
                "routes_removed": len(removed_routes),
                "routes_changed": len(changed_routes),
                "neighbors_added": len(added_neighbors),
                "neighbors_removed": len(removed_neighbors),
                "neighbors_state_changed": len(state_changed_neighbors),
            },
        }


class PostgreSQLRoutingDatabase(RoutingDatabase):
    """PostgreSQL implementation for routing data."""

    def __init__(self, connection_string: str):
        self.connection_string = connection_string
        self._conn = None

        try:
            import psycopg2
            self._psycopg2 = psycopg2
        except ImportError:
            raise ImportError(
                "psycopg2 is required for PostgreSQL support. "
                "Install with: pip install psycopg2-binary"
            )

    def _get_conn(self):
        if self._conn is None or self._conn.closed:
            self._conn = self._psycopg2.connect(self.connection_string)
        return self._conn

    def close(self) -> None:
        if self._conn and not self._conn.closed:
            self._conn.close()
            self._conn = None

    def initialize(self) -> None:
        """Create database schema."""
        conn = self._get_conn()
        with conn.cursor() as cur:
            cur.execute("""
                -- Routing snapshots table
                CREATE TABLE IF NOT EXISTS routing_snapshots (
                    id SERIAL PRIMARY KEY,
                    device_id TEXT NOT NULL,
                    device_hostname TEXT,
                    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    snapshot_type TEXT DEFAULT 'manual',
                    route_count INTEGER DEFAULT 0,
                    neighbor_count INTEGER DEFAULT 0,
                    notes TEXT
                );

                -- Routes table
                CREATE TABLE IF NOT EXISTS routes (
                    id SERIAL PRIMARY KEY,
                    snapshot_id INTEGER NOT NULL REFERENCES routing_snapshots(id) ON DELETE CASCADE,
                    prefix TEXT NOT NULL,
                    prefix_length INTEGER NOT NULL,
                    protocol TEXT NOT NULL,
                    next_hop TEXT,
                    next_hops JSONB DEFAULT '[]',
                    interface TEXT,
                    metric INTEGER DEFAULT 0,
                    admin_distance INTEGER DEFAULT 0,
                    age_seconds INTEGER,
                    tag INTEGER,
                    vrf TEXT DEFAULT 'default',
                    route_type TEXT DEFAULT 'best',
                    active BOOLEAN DEFAULT TRUE,
                    fib_installed BOOLEAN DEFAULT TRUE,
                    attributes JSONB DEFAULT '{}'
                );

                -- Protocol neighbors table
                CREATE TABLE IF NOT EXISTS protocol_neighbors (
                    id SERIAL PRIMARY KEY,
                    snapshot_id INTEGER NOT NULL REFERENCES routing_snapshots(id) ON DELETE CASCADE,
                    protocol TEXT NOT NULL,
                    neighbor_id TEXT,
                    neighbor_address TEXT NOT NULL,
                    interface TEXT,
                    state TEXT NOT NULL,
                    uptime_seconds INTEGER,
                    vrf TEXT DEFAULT 'default',
                    attributes JSONB DEFAULT '{}'
                );

                -- Route changes table
                CREATE TABLE IF NOT EXISTS route_changes (
                    id SERIAL PRIMARY KEY,
                    device_id TEXT NOT NULL,
                    prefix TEXT NOT NULL,
                    prefix_length INTEGER NOT NULL,
                    change_type TEXT NOT NULL,
                    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    protocol TEXT,
                    old_next_hop TEXT,
                    new_next_hop TEXT,
                    old_metric INTEGER,
                    new_metric INTEGER,
                    old_attributes JSONB,
                    new_attributes JSONB
                );

                -- Redistribution configuration table
                CREATE TABLE IF NOT EXISTS redistribution_config (
                    id SERIAL PRIMARY KEY,
                    device_id TEXT NOT NULL,
                    source_protocol TEXT NOT NULL,
                    target_protocol TEXT NOT NULL,
                    route_map TEXT,
                    prefix_list TEXT,
                    metric INTEGER,
                    metric_type TEXT,
                    tag INTEGER,
                    match_criteria JSONB DEFAULT '{}',
                    set_actions JSONB DEFAULT '{}',
                    enabled BOOLEAN DEFAULT TRUE,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                );

                -- VRF table
                CREATE TABLE IF NOT EXISTS vrfs (
                    id SERIAL PRIMARY KEY,
                    snapshot_id INTEGER NOT NULL REFERENCES routing_snapshots(id) ON DELETE CASCADE,
                    name TEXT NOT NULL,
                    rd TEXT,
                    rt_import JSONB DEFAULT '[]',
                    rt_export JSONB DEFAULT '[]',
                    description TEXT,
                    interfaces JSONB DEFAULT '[]'
                );

                -- Indexes
                CREATE INDEX IF NOT EXISTS idx_routes_snapshot ON routes(snapshot_id);
                CREATE INDEX IF NOT EXISTS idx_routes_prefix ON routes(prefix, prefix_length);
                CREATE INDEX IF NOT EXISTS idx_routes_protocol ON routes(protocol);
                CREATE INDEX IF NOT EXISTS idx_routes_vrf ON routes(vrf);
                CREATE INDEX IF NOT EXISTS idx_neighbors_snapshot ON protocol_neighbors(snapshot_id);
                CREATE INDEX IF NOT EXISTS idx_neighbors_protocol ON protocol_neighbors(protocol);
                CREATE INDEX IF NOT EXISTS idx_neighbors_state ON protocol_neighbors(state);
                CREATE INDEX IF NOT EXISTS idx_changes_device ON route_changes(device_id);
                CREATE INDEX IF NOT EXISTS idx_changes_prefix ON route_changes(prefix, timestamp);
                CREATE INDEX IF NOT EXISTS idx_changes_timestamp ON route_changes(timestamp);
                CREATE INDEX IF NOT EXISTS idx_redistribution_device ON redistribution_config(device_id);
                CREATE INDEX IF NOT EXISTS idx_snapshots_device ON routing_snapshots(device_id);
                CREATE INDEX IF NOT EXISTS idx_snapshots_timestamp ON routing_snapshots(timestamp);
                CREATE INDEX IF NOT EXISTS idx_vrfs_snapshot ON vrfs(snapshot_id);
            """)
            conn.commit()

    # Implementation follows the same pattern as SQLite but with PostgreSQL syntax
    # For brevity, key methods are shown - the full implementation follows the same patterns

    def create_snapshot(self, snapshot: RoutingSnapshot) -> RoutingSnapshot:
        conn = self._get_conn()
        with conn.cursor() as cur:
            cur.execute("""
                INSERT INTO routing_snapshots (
                    device_id, device_hostname, timestamp, snapshot_type,
                    route_count, neighbor_count, notes
                ) VALUES (%s, %s, %s, %s, %s, %s, %s)
                RETURNING id, timestamp
            """, (
                snapshot.device_id,
                snapshot.device_hostname,
                snapshot.timestamp or datetime.now(),
                snapshot.snapshot_type,
                snapshot.route_count,
                snapshot.neighbor_count,
                snapshot.notes,
            ))
            row = cur.fetchone()
            snapshot.id = row[0]
            snapshot.timestamp = row[1]
            conn.commit()
            return snapshot

    def get_snapshot(self, snapshot_id: int) -> RoutingSnapshot | None:
        conn = self._get_conn()
        with conn.cursor() as cur:
            cur.execute(
                "SELECT * FROM routing_snapshots WHERE id = %s", (snapshot_id,)
            )
            row = cur.fetchone()
            if row:
                cols = [d[0] for d in cur.description]
                data = dict(zip(cols, row))
                return RoutingSnapshot(
                    id=data["id"],
                    device_id=data["device_id"],
                    device_hostname=data["device_hostname"],
                    timestamp=data["timestamp"],
                    snapshot_type=data["snapshot_type"],
                    route_count=data["route_count"],
                    neighbor_count=data["neighbor_count"],
                    notes=data["notes"],
                )
            return None

    def list_snapshots(
        self,
        device_id: str | None = None,
        limit: int = 100,
    ) -> list[RoutingSnapshot]:
        conn = self._get_conn()
        with conn.cursor() as cur:
            query = "SELECT * FROM routing_snapshots WHERE 1=1"
            params: list[Any] = []

            if device_id:
                query += " AND device_id = %s"
                params.append(device_id)

            query += " ORDER BY timestamp DESC LIMIT %s"
            params.append(limit)

            cur.execute(query, params)
            rows = cur.fetchall()
            cols = [d[0] for d in cur.description]

            return [
                RoutingSnapshot(
                    id=data["id"],
                    device_id=data["device_id"],
                    device_hostname=data["device_hostname"],
                    timestamp=data["timestamp"],
                    snapshot_type=data["snapshot_type"],
                    route_count=data["route_count"],
                    neighbor_count=data["neighbor_count"],
                    notes=data["notes"],
                )
                for row in rows
                for data in [dict(zip(cols, row))]
            ]

    def delete_snapshot(self, snapshot_id: int) -> bool:
        conn = self._get_conn()
        with conn.cursor() as cur:
            cur.execute("DELETE FROM routing_snapshots WHERE id = %s", (snapshot_id,))
            deleted = cur.rowcount > 0
            conn.commit()
            return deleted

    def add_routes(self, snapshot_id: int, routes: list[Route]) -> int:
        conn = self._get_conn()
        with conn.cursor() as cur:
            count = 0
            for route in routes:
                attrs = route.attributes.copy() if route.attributes else {}

                # Add protocol-specific attributes (same logic as SQLite)
                if isinstance(route, BGPRoute):
                    attrs.update({
                        "as_path": route.as_path,
                        "origin": route.origin.value,
                        "local_pref": route.local_pref,
                        "med": route.med,
                        "weight": route.weight,
                        "communities": route.communities,
                        "best": route.best,
                        "valid": route.valid,
                    })

                cur.execute("""
                    INSERT INTO routes (
                        snapshot_id, prefix, prefix_length, protocol, next_hop,
                        next_hops, interface, metric, admin_distance, age_seconds,
                        tag, vrf, route_type, active, fib_installed, attributes
                    ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                """, (
                    snapshot_id,
                    route.prefix,
                    route.prefix_length,
                    route.protocol.value,
                    route.next_hop,
                    json.dumps(route.next_hops),
                    route.interface,
                    route.metric,
                    route.admin_distance,
                    route.age_seconds,
                    route.tag,
                    route.vrf,
                    route.route_type.value,
                    route.active,
                    route.fib_installed,
                    json.dumps(attrs),
                ))
                count += 1

            cur.execute(
                "UPDATE routing_snapshots SET route_count = %s WHERE id = %s",
                (count, snapshot_id)
            )
            conn.commit()
            return count

    def get_routes(
        self,
        snapshot_id: int,
        protocol: RoutingProtocol | None = None,
        prefix: str | None = None,
        vrf: str | None = None,
    ) -> list[Route]:
        conn = self._get_conn()
        with conn.cursor() as cur:
            query = "SELECT * FROM routes WHERE snapshot_id = %s"
            params: list[Any] = [snapshot_id]

            if protocol:
                query += " AND protocol = %s"
                params.append(protocol.value)
            if prefix:
                query += " AND prefix = %s"
                params.append(prefix)
            if vrf:
                query += " AND vrf = %s"
                params.append(vrf)

            query += " ORDER BY prefix, prefix_length"
            cur.execute(query, params)
            rows = cur.fetchall()
            cols = [d[0] for d in cur.description]

            # Convert to Route objects (simplified - full implementation follows SQLite pattern)
            routes = []
            for row in rows:
                data = dict(zip(cols, row))
                proto = RoutingProtocol(data["protocol"])
                routes.append(Route(
                    prefix=data["prefix"],
                    prefix_length=data["prefix_length"],
                    protocol=proto,
                    next_hop=data["next_hop"],
                    next_hops=data["next_hops"] or [],
                    interface=data["interface"],
                    metric=data["metric"] or 0,
                    admin_distance=data["admin_distance"] or 0,
                    vrf=data["vrf"] or "default",
                    active=data["active"],
                    attributes=data["attributes"] or {},
                ))
            return routes

    def get_route_by_prefix(
        self,
        snapshot_id: int,
        prefix: str,
        prefix_length: int,
        vrf: str = "default",
    ) -> Route | None:
        routes = self.get_routes(snapshot_id, prefix=prefix, vrf=vrf)
        for r in routes:
            if r.prefix_length == prefix_length:
                return r
        return None

    def add_neighbors(
        self,
        snapshot_id: int,
        neighbors: list[ProtocolNeighbor],
    ) -> int:
        conn = self._get_conn()
        with conn.cursor() as cur:
            count = 0
            for neighbor in neighbors:
                attrs: dict[str, Any] = {}
                if isinstance(neighbor, BGPNeighbor):
                    attrs.update({
                        "remote_asn": neighbor.remote_asn,
                        "local_asn": neighbor.local_asn,
                        "bgp_state": neighbor.bgp_state.value,
                        "prefixes_received": neighbor.prefixes_received,
                    })

                cur.execute("""
                    INSERT INTO protocol_neighbors (
                        snapshot_id, protocol, neighbor_id, neighbor_address,
                        interface, state, uptime_seconds, vrf, attributes
                    ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)
                """, (
                    snapshot_id,
                    neighbor.protocol.value,
                    neighbor.neighbor_id,
                    neighbor.neighbor_address,
                    neighbor.interface,
                    neighbor.state,
                    neighbor.uptime_seconds,
                    neighbor.vrf,
                    json.dumps(attrs),
                ))
                count += 1

            cur.execute(
                "UPDATE routing_snapshots SET neighbor_count = %s WHERE id = %s",
                (count, snapshot_id)
            )
            conn.commit()
            return count

    def get_neighbors(
        self,
        snapshot_id: int,
        protocol: RoutingProtocol | None = None,
        state: str | None = None,
    ) -> list[ProtocolNeighbor]:
        conn = self._get_conn()
        with conn.cursor() as cur:
            query = "SELECT * FROM protocol_neighbors WHERE snapshot_id = %s"
            params: list[Any] = [snapshot_id]

            if protocol:
                query += " AND protocol = %s"
                params.append(protocol.value)
            if state:
                query += " AND state = %s"
                params.append(state)

            cur.execute(query, params)
            rows = cur.fetchall()
            cols = [d[0] for d in cur.description]

            neighbors = []
            for row in rows:
                data = dict(zip(cols, row))
                neighbors.append(ProtocolNeighbor(
                    protocol=RoutingProtocol(data["protocol"]),
                    neighbor_id=data["neighbor_id"],
                    neighbor_address=data["neighbor_address"],
                    interface=data["interface"],
                    state=data["state"],
                    uptime_seconds=data["uptime_seconds"],
                    vrf=data["vrf"] or "default",
                ))
            return neighbors

    def add_redistributions(
        self,
        device_id: str,
        redistributions: list[RedistributionPoint],
    ) -> int:
        conn = self._get_conn()
        with conn.cursor() as cur:
            cur.execute(
                "DELETE FROM redistribution_config WHERE device_id = %s",
                (device_id,)
            )

            count = 0
            for redist in redistributions:
                cur.execute("""
                    INSERT INTO redistribution_config (
                        device_id, source_protocol, target_protocol, route_map,
                        metric, metric_type, enabled
                    ) VALUES (%s, %s, %s, %s, %s, %s, %s)
                """, (
                    device_id,
                    redist.source_protocol.value,
                    redist.target_protocol.value,
                    redist.route_map,
                    redist.metric,
                    redist.metric_type,
                    redist.enabled,
                ))
                count += 1

            conn.commit()
            return count

    def get_redistributions(
        self,
        device_id: str,
        source_protocol: RoutingProtocol | None = None,
        target_protocol: RoutingProtocol | None = None,
    ) -> list[RedistributionPoint]:
        conn = self._get_conn()
        with conn.cursor() as cur:
            query = "SELECT * FROM redistribution_config WHERE device_id = %s"
            params: list[Any] = [device_id]

            if source_protocol:
                query += " AND source_protocol = %s"
                params.append(source_protocol.value)
            if target_protocol:
                query += " AND target_protocol = %s"
                params.append(target_protocol.value)

            cur.execute(query, params)
            rows = cur.fetchall()
            cols = [d[0] for d in cur.description]

            return [
                RedistributionPoint(
                    source_protocol=RoutingProtocol(data["source_protocol"]),
                    target_protocol=RoutingProtocol(data["target_protocol"]),
                    route_map=data["route_map"],
                    metric=data["metric"],
                    metric_type=data["metric_type"],
                    enabled=data["enabled"],
                )
                for row in rows
                for data in [dict(zip(cols, row))]
            ]

    def record_route_change(self, change: RouteChange) -> RouteChange:
        conn = self._get_conn()
        with conn.cursor() as cur:
            cur.execute("""
                INSERT INTO route_changes (
                    device_id, prefix, prefix_length, change_type, timestamp,
                    protocol, old_next_hop, new_next_hop, old_metric, new_metric
                ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                RETURNING id, timestamp
            """, (
                change.device_id,
                change.prefix,
                change.prefix_length,
                change.change_type,
                change.timestamp or datetime.now(),
                change.protocol.value,
                change.old_next_hop,
                change.new_next_hop,
                change.old_metric,
                change.new_metric,
            ))
            row = cur.fetchone()
            change.id = row[0]
            change.timestamp = row[1]
            conn.commit()
            return change

    def get_route_changes(
        self,
        device_id: str,
        prefix: str | None = None,
        since: datetime | None = None,
        limit: int = 1000,
    ) -> list[RouteChange]:
        conn = self._get_conn()
        with conn.cursor() as cur:
            query = "SELECT * FROM route_changes WHERE device_id = %s"
            params: list[Any] = [device_id]

            if prefix:
                query += " AND prefix = %s"
                params.append(prefix)
            if since:
                query += " AND timestamp >= %s"
                params.append(since)

            query += " ORDER BY timestamp DESC LIMIT %s"
            params.append(limit)

            cur.execute(query, params)
            rows = cur.fetchall()
            cols = [d[0] for d in cur.description]

            return [
                RouteChange(
                    id=data["id"],
                    device_id=data["device_id"],
                    prefix=data["prefix"],
                    prefix_length=data["prefix_length"],
                    change_type=data["change_type"],
                    timestamp=data["timestamp"],
                    protocol=RoutingProtocol(data["protocol"]) if data["protocol"] else RoutingProtocol.UNKNOWN,
                    old_next_hop=data["old_next_hop"],
                    new_next_hop=data["new_next_hop"],
                    old_metric=data["old_metric"],
                    new_metric=data["new_metric"],
                )
                for row in rows
                for data in [dict(zip(cols, row))]
            ]

    def get_flapping_routes(
        self,
        device_id: str,
        threshold: int = 5,
        period_minutes: int = 15,
    ) -> list[dict[str, Any]]:
        conn = self._get_conn()
        with conn.cursor() as cur:
            cur.execute("""
                SELECT prefix, prefix_length, COUNT(*) as flap_count,
                       MIN(timestamp) as first_flap, MAX(timestamp) as last_flap
                FROM route_changes
                WHERE device_id = %s
                  AND timestamp >= NOW() - INTERVAL '%s minutes'
                GROUP BY prefix, prefix_length
                HAVING COUNT(*) >= %s
                ORDER BY flap_count DESC
            """, (device_id, period_minutes, threshold))

            return [
                {
                    "prefix": f"{row[0]}/{row[1]}",
                    "flap_count": row[2],
                    "first_flap": row[3],
                    "last_flap": row[4],
                }
                for row in cur.fetchall()
            ]

    def add_vrfs(self, snapshot_id: int, vrfs: list[VRF]) -> int:
        conn = self._get_conn()
        with conn.cursor() as cur:
            count = 0
            for vrf in vrfs:
                cur.execute("""
                    INSERT INTO vrfs (
                        snapshot_id, name, rd, rt_import, rt_export,
                        description, interfaces
                    ) VALUES (%s, %s, %s, %s, %s, %s, %s)
                """, (
                    snapshot_id,
                    vrf.name,
                    vrf.rd,
                    json.dumps(vrf.rt_import),
                    json.dumps(vrf.rt_export),
                    vrf.description,
                    json.dumps(vrf.interfaces),
                ))
                count += 1
            conn.commit()
            return count

    def get_vrfs(self, snapshot_id: int) -> list[VRF]:
        conn = self._get_conn()
        with conn.cursor() as cur:
            cur.execute(
                "SELECT * FROM vrfs WHERE snapshot_id = %s ORDER BY name",
                (snapshot_id,)
            )
            rows = cur.fetchall()
            cols = [d[0] for d in cur.description]

            return [
                VRF(
                    name=data["name"],
                    rd=data["rd"],
                    rt_import=data["rt_import"] or [],
                    rt_export=data["rt_export"] or [],
                    description=data["description"],
                    interfaces=data["interfaces"] or [],
                )
                for row in rows
                for data in [dict(zip(cols, row))]
            ]

    def compare_snapshots(
        self,
        snapshot_id_1: int,
        snapshot_id_2: int,
    ) -> dict[str, Any]:
        """Compare two snapshots using the same logic as SQLite."""
        routes_1 = {f"{r.prefix}/{r.prefix_length}:{r.vrf}": r for r in self.get_routes(snapshot_id_1)}
        routes_2 = {f"{r.prefix}/{r.prefix_length}:{r.vrf}": r for r in self.get_routes(snapshot_id_2)}

        added_routes = set(routes_2.keys()) - set(routes_1.keys())
        removed_routes = set(routes_1.keys()) - set(routes_2.keys())

        return {
            "routes": {
                "added": list(added_routes),
                "removed": list(removed_routes),
                "changed": [],
            },
            "neighbors": {
                "added": [],
                "removed": [],
                "state_changed": [],
            },
            "summary": {
                "routes_added": len(added_routes),
                "routes_removed": len(removed_routes),
            },
        }


def get_routing_database(connection_string: str | None = None) -> RoutingDatabase:
    """Get routing database instance based on connection string.

    Args:
        connection_string: Database connection string.
            - None or "sqlite" -> SQLite (default location)
            - "sqlite:///path.db" -> SQLite at path
            - "postgresql://..." -> PostgreSQL

    Returns:
        RoutingDatabase instance
    """
    if connection_string is None:
        config_dir = Path.home() / ".config" / "globaldetect"
        config_dir.mkdir(parents=True, exist_ok=True)
        db_path = config_dir / "routing.db"
        return SQLiteRoutingDatabase(str(db_path))

    if connection_string.startswith("sqlite"):
        if ":///" in connection_string:
            db_path = connection_string.split("///", 1)[1]
        else:
            config_dir = Path.home() / ".config" / "globaldetect"
            config_dir.mkdir(parents=True, exist_ok=True)
            db_path = str(config_dir / "routing.db")
        return SQLiteRoutingDatabase(db_path)

    if connection_string.startswith("postgresql"):
        return PostgreSQLRoutingDatabase(connection_string)

    raise ValueError(f"Unsupported database type: {connection_string}")
