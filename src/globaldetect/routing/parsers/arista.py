"""
Arista EOS output parser.

Parses routing protocol output from Arista EOS devices.

Copyright (c) 2025 DNS Science.io, an After Dark Systems, LLC company.
All rights reserved.
"""

import re
import logging
from datetime import timedelta
from typing import Any

from globaldetect.routing.parsers.base import OutputParser
from globaldetect.routing.models import (
    Route,
    BGPRoute,
    OSPFRoute,
    ISISRoute,
    RoutingProtocol,
    RouteType,
    BGPOrigin,
    OSPFRouteType,
    ISISLevel,
    ProtocolNeighbor,
    BGPNeighbor,
    OSPFNeighbor,
    ISISAdjacency,
    BGPState,
    BGPSessionType,
    OSPFState,
    ISISState,
    RedistributionPoint,
    VRF,
    BGPSummary,
    OSPFSummary,
    ISISSummary,
)

logger = logging.getLogger(__name__)


class AristaEOSParser(OutputParser):
    """Parser for Arista EOS CLI output.

    Arista EOS output is very similar to Cisco IOS, with minor differences.
    """

    # Protocol code mappings (same as Cisco)
    PROTOCOL_MAP = {
        "C": RoutingProtocol.CONNECTED,
        "S": RoutingProtocol.STATIC,
        "B": RoutingProtocol.BGP,
        "O": RoutingProtocol.OSPF,
        "i": RoutingProtocol.ISIS,
        "D": RoutingProtocol.EIGRP,
        "R": RoutingProtocol.RIP,
        "L": RoutingProtocol.LOCAL,
        "A": RoutingProtocol.AGGREGATE,
    }

    # BGP state mappings
    BGP_STATE_MAP = {
        "Established": BGPState.ESTABLISHED,
        "Active": BGPState.ACTIVE,
        "Connect": BGPState.CONNECT,
        "Idle": BGPState.IDLE,
        "OpenSent": BGPState.OPENSENT,
        "OpenConfirm": BGPState.OPENCONFIRM,
    }

    # OSPF state mappings
    OSPF_STATE_MAP = {
        "FULL": OSPFState.FULL,
        "2WAY": OSPFState.TWO_WAY,
        "EXSTART": OSPFState.EXSTART,
        "EXCHANGE": OSPFState.EXCHANGE,
        "LOADING": OSPFState.LOADING,
        "INIT": OSPFState.INIT,
        "DOWN": OSPFState.DOWN,
    }

    def parse_route_table(self, output: str, vrf: str = "default") -> list[Route]:
        """Parse Arista EOS route table output.

        Args:
            output: Output from 'show ip route' command
            vrf: VRF name

        Returns:
            List of Route objects
        """
        routes = []

        # Pattern for route entries
        # B E      10.0.0.0/24 [200/0] via 10.0.0.2, Ethernet1
        route_pattern = re.compile(
            r"^([CSBOIDRLA])\s+([EIN12\s]*)\s*"
            r"(\d+\.\d+\.\d+\.\d+/\d+)\s+"
            r"\[(\d+)/(\d+)\]\s+"
            r"via\s+(\S+)(?:,\s+(\S+))?",
            re.MULTILINE
        )

        for match in route_pattern.finditer(output):
            proto_code = match.group(1)
            subtype = match.group(2).strip() if match.group(2) else ""
            network = match.group(3)
            ad = int(match.group(4))
            metric = int(match.group(5))
            next_hop = match.group(6)
            interface = match.group(7) if match.group(7) else ""

            protocol = self.PROTOCOL_MAP.get(proto_code, RoutingProtocol.UNKNOWN)

            route = Route(
                network=network,
                protocol=protocol,
                next_hop=next_hop,
                interface=interface,
                admin_distance=ad,
                metric=metric,
                vrf=vrf,
                active=True,
            )
            routes.append(route)

        return routes

    def parse_bgp_summary(self, output: str) -> BGPSummary | None:
        """Parse Arista EOS BGP summary output.

        Args:
            output: Output from 'show ip bgp summary' command

        Returns:
            BGPSummary object
        """
        summary = BGPSummary(
            router_id="",
            local_asn=0,
            total_neighbors=0,
            established_neighbors=0,
            total_prefixes=0,
        )

        # Parse router ID and local AS
        router_pattern = re.compile(
            r"BGP router identifier\s+(\S+),\s+local AS number\s+(\d+)"
        )
        match = router_pattern.search(output)
        if match:
            summary.router_id = match.group(1)
            summary.local_asn = int(match.group(2))

        # Parse neighbor summary lines
        # Neighbor         V  AS           MsgRcvd   MsgSent  InQ OutQ  Up/Down State   PfxRcd PfxAcc
        neighbor_pattern = re.compile(
            r"^(\d+\.\d+\.\d+\.\d+)\s+\d+\s+(\d+)\s+\d+\s+\d+\s+\d+\s+\d+\s+(\S+)\s+(\S+)",
            re.MULTILINE
        )

        for match in neighbor_pattern.finditer(output):
            summary.total_neighbors += 1
            state = match.group(4)

            # Check if established (shows prefix count)
            if state.isdigit():
                summary.established_neighbors += 1
                summary.total_prefixes += int(state)
            elif state == "Estab":
                summary.established_neighbors += 1

        return summary

    def parse_bgp_neighbors(self, output: str) -> list[BGPNeighbor]:
        """Parse Arista EOS BGP neighbor detail output.

        Args:
            output: Output from 'show ip bgp neighbors' command

        Returns:
            List of BGPNeighbor objects
        """
        neighbors = []

        # Split by neighbor sections
        sections = re.split(r"BGP neighbor is\s+", output)

        for section in sections[1:]:
            lines = section.split("\n")
            if not lines:
                continue

            # First line: 10.0.0.2, remote AS 65001, internal link
            first_line = lines[0]
            peer_match = re.match(r"(\S+),\s+remote AS\s+(\d+)", first_line)
            if not peer_match:
                continue

            neighbor = BGPNeighbor(
                protocol=RoutingProtocol.BGP,
                neighbor_id="",
                neighbor_address=peer_match.group(1),
                interface="",
                state="",
                remote_asn=int(peer_match.group(2)),
                local_asn=0,
                session_type=BGPSessionType.EBGP,
                prefixes_received=0,
                prefixes_sent=0,
            )

            section_text = "\n".join(lines)

            # Internal vs external
            if "internal link" in section_text:
                neighbor.session_type = BGPSessionType.IBGP
            else:
                neighbor.session_type = BGPSessionType.EBGP

            # Parse BGP state
            state_match = re.search(r"BGP state is\s+(\w+)", section_text)
            if state_match:
                state_str = state_match.group(1)
                neighbor.state = state_str
                neighbor.bgp_state = self.BGP_STATE_MAP.get(
                    state_str, BGPState.IDLE
                )

            # Parse local AS
            local_as_match = re.search(r"Local AS is\s+(\d+)", section_text)
            if local_as_match:
                neighbor.local_asn = int(local_as_match.group(1))

            # Parse prefixes
            prefixes_match = re.search(
                r"Prefixes Total:\s+(\d+)\s+(\d+)",
                section_text
            )
            if prefixes_match:
                neighbor.prefixes_received = int(prefixes_match.group(1))
                neighbor.prefixes_sent = int(prefixes_match.group(2))

            # Parse uptime
            uptime_match = re.search(r"Up for\s+(\S+)", section_text)
            if uptime_match:
                neighbor.uptime_seconds = self._parse_uptime(uptime_match.group(1))

            neighbors.append(neighbor)

        return neighbors

    def parse_bgp_routes(self, output: str) -> list[BGPRoute]:
        """Parse Arista EOS BGP route output.

        Args:
            output: Output from 'show ip bgp' command

        Returns:
            List of BGPRoute objects
        """
        routes = []

        # Pattern for BGP routes
        # *> 10.0.0.0/24        10.0.0.2                 0 65001 65002 i
        route_pattern = re.compile(
            r"^([*>sirhSdx\s]{3})\s*"
            r"(\d+\.\d+\.\d+\.\d+/\d+)\s+"
            r"(\d+\.\d+\.\d+\.\d+)?\s*"
            r"(\d+)?\s+"
            r"(\d+)?\s+"
            r"([\d\s]+)?\s*([ie?])?",
            re.MULTILINE
        )

        for match in route_pattern.finditer(output):
            status = match.group(1)
            network = match.group(2)
            next_hop = match.group(3) or ""
            med = int(match.group(4)) if match.group(4) else 0
            local_pref = int(match.group(5)) if match.group(5) else 100
            as_path_str = match.group(6) or ""
            origin_code = match.group(7) or "?"

            # Parse AS path
            as_path = []
            if as_path_str.strip():
                as_path = [int(asn) for asn in as_path_str.split() if asn.isdigit()]

            # Parse origin
            origin = {
                "i": BGPOrigin.IGP,
                "e": BGPOrigin.EGP,
                "?": BGPOrigin.INCOMPLETE,
            }.get(origin_code, BGPOrigin.INCOMPLETE)

            route = BGPRoute(
                network=network,
                protocol=RoutingProtocol.BGP,
                next_hop=next_hop,
                admin_distance=200,
                metric=med,
                as_path=as_path,
                origin=origin,
                local_pref=local_pref,
                med=med,
                communities=[],
                best=">" in status,
                valid="*" in status,
            )
            routes.append(route)

        return routes

    def parse_ospf_summary(self, output: str) -> OSPFSummary | None:
        """Parse Arista EOS OSPF summary output.

        Args:
            output: Output from 'show ip ospf' command

        Returns:
            OSPFSummary object
        """
        summary = OSPFSummary(
            router_id="",
            process_id=0,
            reference_bandwidth=100,
            total_areas=0,
            total_lsas=0,
            total_neighbors=0,
            full_neighbors=0,
        )

        # Parse router ID
        router_match = re.search(r"Router ID\s+(\S+)", output)
        if router_match:
            summary.router_id = router_match.group(1)

        # Parse process ID
        process_match = re.search(r"OSPF process\s+(\d+)", output)
        if process_match:
            summary.process_id = int(process_match.group(1))

        # Count areas
        area_matches = re.findall(r"Area\s+(\S+)", output)
        summary.total_areas = len(set(area_matches))

        return summary

    def parse_ospf_neighbors(self, output: str) -> list[OSPFNeighbor]:
        """Parse Arista EOS OSPF neighbor output.

        Args:
            output: Output from 'show ip ospf neighbor' command

        Returns:
            List of OSPFNeighbor objects
        """
        neighbors = []

        # Pattern for neighbor entries
        # Neighbor ID     Pri State           Dead Time   Address         Interface
        # 10.0.0.2          1 FULL/DR         00:00:35    10.0.0.2        Ethernet1
        neighbor_pattern = re.compile(
            r"^(\d+\.\d+\.\d+\.\d+)\s+(\d+)\s+(\w+)(?:/(\w+))?\s+"
            r"(\S+)\s+(\d+\.\d+\.\d+\.\d+)\s+(\S+)",
            re.MULTILINE
        )

        for match in neighbor_pattern.finditer(output):
            state_str = match.group(3).upper()
            role = match.group(4) or ""

            neighbor = OSPFNeighbor(
                protocol=RoutingProtocol.OSPF,
                neighbor_id=match.group(1),
                neighbor_address=match.group(6),
                interface=match.group(7),
                state=f"{state_str}/{role}" if role else state_str,
                ospf_state=self.OSPF_STATE_MAP.get(state_str, OSPFState.DOWN),
                area="0",
                priority=int(match.group(2)),
            )

            # Parse DR/BDR role
            if role == "DR":
                neighbor.dr = match.group(6)
            elif role == "BDR":
                neighbor.bdr = match.group(6)

            neighbors.append(neighbor)

        return neighbors

    def parse_ospf_routes(self, output: str) -> list[OSPFRoute]:
        """Parse Arista EOS OSPF route output.

        Args:
            output: Output from 'show ip route ospf' command

        Returns:
            List of OSPFRoute objects
        """
        routes = []

        # Pattern for OSPF routes
        route_pattern = re.compile(
            r"^O\s+([EIN12\s]*)\s*"
            r"(\d+\.\d+\.\d+\.\d+/\d+)\s+"
            r"\[(\d+)/(\d+)\]",
            re.MULTILINE
        )

        for match in route_pattern.finditer(output):
            subtype = match.group(1).strip()
            network = match.group(2)
            ad = int(match.group(3))
            metric = int(match.group(4))

            # Determine route type
            route_type = OSPFRouteType.INTRA_AREA
            if "E1" in subtype:
                route_type = OSPFRouteType.EXTERNAL_TYPE1
            elif "E2" in subtype:
                route_type = OSPFRouteType.EXTERNAL_TYPE2
            elif "IA" in subtype:
                route_type = OSPFRouteType.INTER_AREA
            elif "N1" in subtype:
                route_type = OSPFRouteType.NSSA_TYPE1
            elif "N2" in subtype:
                route_type = OSPFRouteType.NSSA_TYPE2

            route = OSPFRoute(
                network=network,
                protocol=RoutingProtocol.OSPF,
                next_hop="",
                admin_distance=ad,
                metric=metric,
                area="0",
                ospf_route_type=route_type,
                cost=metric,
            )
            routes.append(route)

        return routes

    def parse_isis_summary(self, output: str) -> ISISSummary | None:
        """Parse Arista EOS IS-IS summary output.

        Args:
            output: Output from 'show isis summary' command

        Returns:
            ISISSummary object
        """
        summary = ISISSummary(
            system_id="",
            level=ISISLevel.L1_L2,
            total_adjacencies=0,
            up_adjacencies=0,
            l1_lsps=0,
            l2_lsps=0,
        )

        # Parse system ID
        sysid_match = re.search(r"System ID:\s+(\S+)", output)
        if sysid_match:
            summary.system_id = sysid_match.group(1)

        return summary

    def parse_isis_adjacencies(self, output: str) -> list[ISISAdjacency]:
        """Parse Arista EOS IS-IS adjacency output.

        Args:
            output: Output from 'show isis neighbors' command

        Returns:
            List of ISISAdjacency objects
        """
        adjacencies = []

        # Pattern for adjacency entries
        adj_pattern = re.compile(
            r"^(\S+)\s+(\S+)\s+([12])\s+(\w+)\s+(\d+)",
            re.MULTILINE
        )

        for match in adj_pattern.finditer(output):
            level_num = match.group(3)
            state_str = match.group(4)

            adj = ISISAdjacency(
                protocol=RoutingProtocol.ISIS,
                neighbor_id="",
                neighbor_address="",
                interface=match.group(2),
                state=state_str,
                system_id=match.group(1),
                level=ISISLevel.L1 if level_num == "1" else ISISLevel.L2,
                isis_state=ISISState.UP if state_str.lower() == "up" else ISISState.DOWN,
                hold_time=int(match.group(5)),
            )
            adjacencies.append(adj)

        return adjacencies

    def parse_isis_routes(self, output: str) -> list[ISISRoute]:
        """Parse Arista EOS IS-IS route output.

        Args:
            output: Output from 'show ip route isis' command

        Returns:
            List of ISISRoute objects
        """
        routes = []

        route_pattern = re.compile(
            r"^i\s+([L12\s]*)\s*"
            r"(\d+\.\d+\.\d+\.\d+/\d+)\s+"
            r"\[(\d+)/(\d+)\]",
            re.MULTILINE
        )

        for match in route_pattern.finditer(output):
            level_str = match.group(1).strip()
            network = match.group(2)
            ad = int(match.group(3))
            metric = int(match.group(4))

            level = ISISLevel.L1_L2
            if "L1" in level_str and "L2" not in level_str:
                level = ISISLevel.L1
            elif "L2" in level_str and "L1" not in level_str:
                level = ISISLevel.L2

            route = ISISRoute(
                network=network,
                protocol=RoutingProtocol.ISIS,
                next_hop="",
                admin_distance=ad,
                metric=metric,
                level=level,
            )
            routes.append(route)

        return routes

    def parse_vrfs(self, output: str) -> list[VRF]:
        """Parse Arista EOS VRF output.

        Args:
            output: Output from 'show vrf' command

        Returns:
            List of VRF objects
        """
        vrfs = []

        # Pattern for VRF entries
        vrf_pattern = re.compile(
            r"^(\S+)\s+(\S+)\s+(\S+)",
            re.MULTILINE
        )

        for match in vrf_pattern.finditer(output):
            name = match.group(1)
            if name == "VRF" or name == "---":  # Skip headers
                continue

            vrf = VRF(
                name=name,
                rd=match.group(2) if match.group(2) != "-" else "",
                import_rt=[],
                export_rt=[],
            )
            vrfs.append(vrf)

        return vrfs

    def parse_redistribution(self, output: str) -> list[RedistributionPoint]:
        """Parse Arista EOS redistribution configuration.

        Args:
            output: Output from 'show running-config | section router'

        Returns:
            List of RedistributionPoint objects
        """
        redistributions = []

        # Pattern for redistribution commands
        redist_pattern = re.compile(
            r"redistribute\s+(\w+)(?:\s+route-map\s+(\S+))?(?:\s+metric\s+(\d+))?"
        )

        current_protocol = None
        for line in output.split("\n"):
            # Detect protocol section
            if line.strip().startswith("router "):
                parts = line.strip().split()
                if len(parts) >= 2:
                    current_protocol = parts[1].lower()

            # Look for redistribute commands
            match = redist_pattern.search(line)
            if match and current_protocol:
                source = match.group(1).lower()
                route_map = match.group(2)
                metric = int(match.group(3)) if match.group(3) else None

                target_proto = {
                    "bgp": RoutingProtocol.BGP,
                    "ospf": RoutingProtocol.OSPF,
                    "isis": RoutingProtocol.ISIS,
                    "eigrp": RoutingProtocol.EIGRP,
                }.get(current_protocol, RoutingProtocol.UNKNOWN)

                source_proto = {
                    "connected": RoutingProtocol.CONNECTED,
                    "static": RoutingProtocol.STATIC,
                    "bgp": RoutingProtocol.BGP,
                    "ospf": RoutingProtocol.OSPF,
                    "isis": RoutingProtocol.ISIS,
                }.get(source, RoutingProtocol.UNKNOWN)

                redist = RedistributionPoint(
                    source_protocol=source_proto,
                    target_protocol=target_proto,
                    route_map=route_map,
                    metric=metric,
                )
                redistributions.append(redist)

        return redistributions

    def _parse_uptime(self, uptime_str: str) -> int:
        """Parse uptime string to seconds.

        Args:
            uptime_str: Uptime string like "1d2h", "3:45:00"

        Returns:
            Uptime in seconds
        """
        total_seconds = 0

        # Handle format like "1d2h3m"
        day_match = re.search(r"(\d+)d", uptime_str)
        if day_match:
            total_seconds += int(day_match.group(1)) * 86400

        hour_match = re.search(r"(\d+)h", uptime_str)
        if hour_match:
            total_seconds += int(hour_match.group(1)) * 3600

        min_match = re.search(r"(\d+)m", uptime_str)
        if min_match:
            total_seconds += int(min_match.group(1)) * 60

        # Handle format like "00:45:00"
        time_match = re.match(r"(\d+):(\d+):(\d+)", uptime_str)
        if time_match:
            total_seconds = (
                int(time_match.group(1)) * 3600 +
                int(time_match.group(2)) * 60 +
                int(time_match.group(3))
            )

        return total_seconds
