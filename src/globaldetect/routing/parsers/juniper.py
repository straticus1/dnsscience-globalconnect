"""
Juniper JunOS output parser.

Parses routing protocol output from Juniper JunOS devices.

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


class JuniperJunOSParser(OutputParser):
    """Parser for Juniper JunOS CLI output.

    Handles output from commands like:
    - show route
    - show bgp summary
    - show bgp neighbor
    - show ospf neighbor
    - show isis adjacency
    """

    # Protocol code mappings for JunOS route table
    PROTOCOL_MAP = {
        "B": RoutingProtocol.BGP,
        "O": RoutingProtocol.OSPF,
        "I": RoutingProtocol.ISIS,
        "D": RoutingProtocol.STATIC,  # Direct
        "S": RoutingProtocol.STATIC,
        "L": RoutingProtocol.LOCAL,
        "C": RoutingProtocol.CONNECTED,
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
        "Full": OSPFState.FULL,
        "2Way": OSPFState.TWO_WAY,
        "ExStart": OSPFState.EXSTART,
        "Exchange": OSPFState.EXCHANGE,
        "Loading": OSPFState.LOADING,
        "Init": OSPFState.INIT,
        "Down": OSPFState.DOWN,
    }

    def parse_route_table(self, output: str, vrf: str = "default") -> list[Route]:
        """Parse JunOS route table output.

        Args:
            output: Output from 'show route' command
            vrf: VRF/routing-instance name

        Returns:
            List of Route objects
        """
        routes = []

        # Pattern for route entries in JunOS
        # Example: 10.0.0.0/24        *[BGP/170] 1d 02:30:15, localpref 100
        route_pattern = re.compile(
            r"^(\d+\.\d+\.\d+\.\d+/\d+|\S+/\d+)\s+"
            r"\*?\[(\w+)/(\d+)\]\s+"
            r"(?:(\d+[dwh]?\s*[\d:]+)(?:,\s*)?)?",
            re.MULTILINE
        )

        # Pattern for next-hop lines
        nexthop_pattern = re.compile(
            r">\s+(?:to\s+)?(\d+\.\d+\.\d+\.\d+)\s+via\s+(\S+)"
        )

        current_prefix = None
        current_protocol = None
        current_ad = None
        current_age = None

        for line in output.split("\n"):
            line = line.rstrip()

            # Check for route header
            route_match = route_pattern.match(line)
            if route_match:
                current_prefix = route_match.group(1)
                proto_code = route_match.group(2)
                current_ad = int(route_match.group(3))
                age_str = route_match.group(4)

                current_protocol = self.PROTOCOL_MAP.get(
                    proto_code[0], RoutingProtocol.UNKNOWN
                )

                # Parse age
                current_age = self._parse_junos_age(age_str) if age_str else None

            # Check for next-hop
            nexthop_match = nexthop_pattern.search(line)
            if nexthop_match and current_prefix:
                next_hop = nexthop_match.group(1)
                interface = nexthop_match.group(2)

                route = Route(
                    network=current_prefix,
                    protocol=current_protocol or RoutingProtocol.UNKNOWN,
                    next_hop=next_hop,
                    interface=interface,
                    admin_distance=current_ad or 0,
                    metric=0,
                    age=current_age,
                    vrf=vrf,
                    active=line.strip().startswith(">"),
                )
                routes.append(route)

        return routes

    def parse_bgp_summary(self, output: str) -> BGPSummary | None:
        """Parse JunOS BGP summary output.

        Args:
            output: Output from 'show bgp summary' command

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
        # Groups: 1
        # Router ID: 10.0.0.1  Local AS: 65000
        router_pattern = re.compile(
            r"Router ID:\s+(\S+)\s+Local AS:\s+(\d+)"
        )
        match = router_pattern.search(output)
        if match:
            summary.router_id = match.group(1)
            summary.local_asn = int(match.group(2))

        # Count neighbors and established sessions
        # Peer                     AS      InPkt     OutPkt    OutQ   Flaps Last Up/Dwn State|#Active/Received/Accepted/Damped...
        neighbor_pattern = re.compile(
            r"^(\d+\.\d+\.\d+\.\d+)\s+(\d+)\s+\d+\s+\d+\s+\d+\s+\d+\s+\S+\s+(\S+)",
            re.MULTILINE
        )

        for match in neighbor_pattern.finditer(output):
            summary.total_neighbors += 1
            state = match.group(3)
            if state == "Establ" or "/" in state:  # Active/Received/Accepted format
                summary.established_neighbors += 1
                # Parse prefix count from state like "10/15/15/0"
                if "/" in state:
                    parts = state.split("/")
                    try:
                        summary.total_prefixes += int(parts[1])
                    except (ValueError, IndexError):
                        pass

        return summary

    def parse_bgp_neighbors(self, output: str) -> list[BGPNeighbor]:
        """Parse JunOS BGP neighbor detail output.

        Args:
            output: Output from 'show bgp neighbor' command

        Returns:
            List of BGPNeighbor objects
        """
        neighbors = []

        # Split by peer sections
        peer_sections = re.split(r"^Peer:\s+", output, flags=re.MULTILINE)

        for section in peer_sections[1:]:  # Skip first empty section
            lines = section.split("\n")
            if not lines:
                continue

            # First line contains peer address and AS
            # 10.0.0.2+179 AS 65001 Local AS 65000
            first_line = lines[0]
            peer_match = re.match(r"(\S+?)(?:\+\d+)?\s+AS\s+(\d+)", first_line)
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

            # Parse local AS
            local_as_match = re.search(r"Local AS\s+(\d+)", section_text)
            if local_as_match:
                neighbor.local_asn = int(local_as_match.group(1))
                if neighbor.local_asn == neighbor.remote_asn:
                    neighbor.session_type = BGPSessionType.IBGP

            # Parse state
            state_match = re.search(r"State:\s+(\w+)", section_text)
            if state_match:
                state_str = state_match.group(1)
                neighbor.state = state_str
                neighbor.bgp_state = self.BGP_STATE_MAP.get(
                    state_str, BGPState.IDLE
                )

            # Parse prefixes received
            prefixes_match = re.search(
                r"Active prefixes:\s+(\d+)\s+Received prefixes:\s+(\d+)",
                section_text
            )
            if prefixes_match:
                neighbor.prefixes_received = int(prefixes_match.group(2))

            # Parse uptime
            uptime_match = re.search(r"Last State Change:\s+(\S+)", section_text)
            if uptime_match:
                neighbor.uptime_seconds = self._parse_junos_uptime(
                    uptime_match.group(1)
                )

            neighbors.append(neighbor)

        return neighbors

    def parse_bgp_routes(self, output: str) -> list[BGPRoute]:
        """Parse JunOS BGP route output.

        Args:
            output: Output from 'show route protocol bgp' command

        Returns:
            List of BGPRoute objects
        """
        routes = []

        # Pattern for BGP routes with attributes
        # 10.0.0.0/24        *[BGP/170] 1d 02:30:15, localpref 100, from 10.0.0.2
        #                       AS path: 65001 65002 I, validation-state: unverified
        route_pattern = re.compile(
            r"^(\d+\.\d+\.\d+\.\d+/\d+)\s+\*?\[BGP/(\d+)\].*?"
            r"(?:localpref\s+(\d+))?.*?(?:from\s+(\S+))?",
            re.MULTILINE
        )

        as_path_pattern = re.compile(r"AS path:\s+([\d\s]+)\s*([IEi?])?")

        current_route = None

        for line in output.split("\n"):
            route_match = route_pattern.match(line)
            if route_match:
                if current_route:
                    routes.append(current_route)

                current_route = BGPRoute(
                    network=route_match.group(1),
                    protocol=RoutingProtocol.BGP,
                    next_hop="",
                    admin_distance=int(route_match.group(2)),
                    metric=0,
                    as_path=[],
                    origin=BGPOrigin.INCOMPLETE,
                    local_pref=int(route_match.group(3)) if route_match.group(3) else 100,
                    med=0,
                    communities=[],
                    best=line.strip().startswith("*") or "> " in line,
                    valid=True,
                )

                if route_match.group(4):
                    current_route.from_peer = route_match.group(4)

            elif current_route:
                # Check for AS path
                as_match = as_path_pattern.search(line)
                if as_match:
                    as_path_str = as_match.group(1).strip()
                    if as_path_str:
                        current_route.as_path = [
                            int(asn) for asn in as_path_str.split()
                            if asn.isdigit()
                        ]
                    origin_code = as_match.group(2) or "?"
                    current_route.origin = {
                        "I": BGPOrigin.IGP,
                        "E": BGPOrigin.EGP,
                        "i": BGPOrigin.IGP,
                        "?": BGPOrigin.INCOMPLETE,
                    }.get(origin_code, BGPOrigin.INCOMPLETE)

                # Check for next-hop
                nexthop_match = re.search(r">\s+to\s+(\S+)", line)
                if nexthop_match:
                    current_route.next_hop = nexthop_match.group(1)

        if current_route:
            routes.append(current_route)

        return routes

    def parse_ospf_summary(self, output: str) -> OSPFSummary | None:
        """Parse JunOS OSPF overview output.

        Args:
            output: Output from 'show ospf overview' command

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
        router_match = re.search(r"Router ID:\s+(\S+)", output)
        if router_match:
            summary.router_id = router_match.group(1)

        # Parse reference bandwidth
        ref_bw_match = re.search(r"Reference bandwidth:\s+(\d+)", output)
        if ref_bw_match:
            summary.reference_bandwidth = int(ref_bw_match.group(1))

        # Count areas
        area_matches = re.findall(r"Area:\s+(\S+)", output)
        summary.total_areas = len(set(area_matches))

        return summary

    def parse_ospf_neighbors(self, output: str) -> list[OSPFNeighbor]:
        """Parse JunOS OSPF neighbor output.

        Args:
            output: Output from 'show ospf neighbor detail' command

        Returns:
            List of OSPFNeighbor objects
        """
        neighbors = []

        # Pattern for neighbor entries
        # Address          Interface              State     ID               Pri  Dead
        # 10.0.0.2         ge-0/0/0.0             Full      10.0.0.2         128    35
        neighbor_pattern = re.compile(
            r"^(\d+\.\d+\.\d+\.\d+)\s+(\S+)\s+(\w+)\s+(\d+\.\d+\.\d+\.\d+)\s+(\d+)\s+(\d+)",
            re.MULTILINE
        )

        for match in neighbor_pattern.finditer(output):
            state_str = match.group(3)
            neighbor = OSPFNeighbor(
                protocol=RoutingProtocol.OSPF,
                neighbor_id=match.group(4),
                neighbor_address=match.group(1),
                interface=match.group(2),
                state=state_str,
                ospf_state=self.OSPF_STATE_MAP.get(state_str, OSPFState.DOWN),
                area="0",  # Need to parse from context
                priority=int(match.group(5)),
                dead_timer=int(match.group(6)),
            )
            neighbors.append(neighbor)

        return neighbors

    def parse_ospf_routes(self, output: str) -> list[OSPFRoute]:
        """Parse JunOS OSPF route output.

        Args:
            output: Output from 'show route protocol ospf' command

        Returns:
            List of OSPFRoute objects
        """
        routes = []

        # Pattern for OSPF routes
        route_pattern = re.compile(
            r"^(\d+\.\d+\.\d+\.\d+/\d+)\s+\*?\[OSPF/(\d+)\]",
            re.MULTILINE
        )

        for match in route_pattern.finditer(output):
            route = OSPFRoute(
                network=match.group(1),
                protocol=RoutingProtocol.OSPF,
                next_hop="",
                admin_distance=int(match.group(2)),
                metric=0,
                area="0",
                ospf_route_type=OSPFRouteType.INTRA_AREA,
                cost=0,
            )
            routes.append(route)

        return routes

    def parse_isis_summary(self, output: str) -> ISISSummary | None:
        """Parse JunOS IS-IS overview output.

        Args:
            output: Output from 'show isis overview' command

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

        # Parse level
        if "level 1 only" in output.lower():
            summary.level = ISISLevel.L1
        elif "level 2 only" in output.lower():
            summary.level = ISISLevel.L2

        return summary

    def parse_isis_adjacencies(self, output: str) -> list[ISISAdjacency]:
        """Parse JunOS IS-IS adjacency output.

        Args:
            output: Output from 'show isis adjacency detail' command

        Returns:
            List of ISISAdjacency objects
        """
        adjacencies = []

        # Pattern for adjacency entries
        # Interface             System         L State        Hold (secs) SNPA
        # ge-0/0/0.0            0000.0000.0002 2  Up                    23
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
                interface=match.group(1),
                state=state_str,
                system_id=match.group(2),
                level=ISISLevel.L1 if level_num == "1" else ISISLevel.L2,
                isis_state=ISISState.UP if state_str.lower() == "up" else ISISState.DOWN,
                hold_time=int(match.group(5)),
            )
            adjacencies.append(adj)

        return adjacencies

    def parse_isis_routes(self, output: str) -> list[ISISRoute]:
        """Parse JunOS IS-IS route output.

        Args:
            output: Output from 'show route protocol isis' command

        Returns:
            List of ISISRoute objects
        """
        routes = []

        route_pattern = re.compile(
            r"^(\d+\.\d+\.\d+\.\d+/\d+)\s+\*?\[IS-IS/(\d+)\]",
            re.MULTILINE
        )

        for match in route_pattern.finditer(output):
            route = ISISRoute(
                network=match.group(1),
                protocol=RoutingProtocol.ISIS,
                next_hop="",
                admin_distance=int(match.group(2)),
                metric=0,
                level=ISISLevel.L1_L2,
            )
            routes.append(route)

        return routes

    def parse_vrfs(self, output: str) -> list[VRF]:
        """Parse JunOS routing instances.

        Args:
            output: Output from 'show route instance' command

        Returns:
            List of VRF objects
        """
        vrfs = []

        # Pattern for routing instances
        instance_pattern = re.compile(
            r"^(\S+):\s+Type:\s+(\S+)",
            re.MULTILINE
        )

        for match in instance_pattern.finditer(output):
            name = match.group(1)
            inst_type = match.group(2)

            vrf = VRF(
                name=name,
                rd="",
                import_rt=[],
                export_rt=[],
            )
            vrfs.append(vrf)

        return vrfs

    def parse_redistribution(self, output: str) -> list[RedistributionPoint]:
        """Parse JunOS policy configuration for redistribution.

        Args:
            output: Output from 'show configuration policy-options'

        Returns:
            List of RedistributionPoint objects
        """
        redistributions = []
        # JunOS uses policy-options for redistribution
        # This would require more complex parsing of policy chains
        return redistributions

    def _parse_junos_age(self, age_str: str) -> timedelta | None:
        """Parse JunOS age string to timedelta.

        Args:
            age_str: Age string like "1d 02:30:15" or "02:30:15"

        Returns:
            timedelta object
        """
        if not age_str:
            return None

        total_seconds = 0

        # Handle days
        day_match = re.search(r"(\d+)d", age_str)
        if day_match:
            total_seconds += int(day_match.group(1)) * 86400

        # Handle hours
        hour_match = re.search(r"(\d+)h", age_str)
        if hour_match:
            total_seconds += int(hour_match.group(1)) * 3600

        # Handle HH:MM:SS format
        time_match = re.search(r"(\d+):(\d+):(\d+)", age_str)
        if time_match:
            total_seconds += int(time_match.group(1)) * 3600
            total_seconds += int(time_match.group(2)) * 60
            total_seconds += int(time_match.group(3))

        return timedelta(seconds=total_seconds) if total_seconds > 0 else None

    def _parse_junos_uptime(self, uptime_str: str) -> int:
        """Parse JunOS uptime string to seconds.

        Args:
            uptime_str: Uptime string

        Returns:
            Uptime in seconds
        """
        td = self._parse_junos_age(uptime_str)
        return int(td.total_seconds()) if td else 0
