"""
Cisco IOS/IOS-XE output parser.

Parses command output from Cisco IOS and IOS-XE devices into
structured routing data models.

Copyright (c) 2025 DNS Science.io, an After Dark Systems, LLC company.
All rights reserved.
"""

import re
from typing import Any

from globaldetect.routing.parsers.base import OutputParser
from globaldetect.routing.models import (
    Route,
    BGPRoute,
    OSPFRoute,
    ISISRoute,
    RIPRoute,
    EIGRPRoute,
    BGPNeighbor,
    OSPFNeighbor,
    ISISAdjacency,
    RIPNeighbor,
    EIGRPNeighbor,
    RedistributionPoint,
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
    BGPSummary,
    OSPFSummary,
    ISISSummary,
    EIGRPSummary,
)


class CiscoIOSParser(OutputParser):
    """Parser for Cisco IOS/IOS-XE command output."""

    @property
    def vendor(self) -> str:
        return "cisco_ios"

    # Protocol codes used in route table
    PROTOCOL_CODES = {
        "C": RoutingProtocol.CONNECTED,
        "S": RoutingProtocol.STATIC,
        "L": RoutingProtocol.LOCAL,
        "R": RoutingProtocol.RIP,
        "B": RoutingProtocol.BGP,
        "D": RoutingProtocol.EIGRP,
        "EX": RoutingProtocol.EIGRP,  # EIGRP external
        "O": RoutingProtocol.OSPF,
        "IA": RoutingProtocol.OSPF,   # OSPF inter-area
        "N1": RoutingProtocol.OSPF,   # OSPF NSSA type 1
        "N2": RoutingProtocol.OSPF,   # OSPF NSSA type 2
        "E1": RoutingProtocol.OSPF,   # OSPF external type 1
        "E2": RoutingProtocol.OSPF,   # OSPF external type 2
        "i": RoutingProtocol.ISIS,
        "is": RoutingProtocol.ISIS,   # IS-IS summary
        "ia": RoutingProtocol.ISIS,   # IS-IS inter-area
        "su": RoutingProtocol.STATIC, # Static (user-configured)
        "U": RoutingProtocol.STATIC,  # Per-user static route
        "M": RoutingProtocol.MOBILE,
        "o": RoutingProtocol.ODR,
    }

    # ==========================================================================
    # Route Table Parsing
    # ==========================================================================

    def parse_route_table(self, output: str, vrf: str = "default") -> list[Route]:
        """Parse 'show ip route' output."""
        output = self.clean_output(output)
        routes: list[Route] = []

        # Pattern for route entries
        # Examples:
        # B        10.0.0.0/8 [20/0] via 192.168.1.1, 00:05:30
        # O        172.16.0.0/16 [110/20] via 10.1.1.1, 00:10:00, GigabitEthernet0/0
        # C        192.168.1.0/24 is directly connected, GigabitEthernet0/1
        # S*       0.0.0.0/0 [1/0] via 192.168.1.1

        route_pattern = re.compile(
            r"^([A-Za-z\*\+]+)\s+"  # Protocol code(s)
            r"(\d+\.\d+\.\d+\.\d+/\d+)\s+"  # Network/prefix
            r"(?:\[(\d+)/(\d+)\]\s+)?"  # [AD/metric]
            r"(?:via\s+(\d+\.\d+\.\d+\.\d+))?"  # Next hop
            r"(?:,\s*(\S+))?"  # Age
            r"(?:,\s*(\S+))?"  # Interface
            r"|"
            r"^([A-Za-z\*\+]+)\s+"  # Protocol code
            r"(\d+\.\d+\.\d+\.\d+/\d+)\s+"  # Network
            r"is directly connected,\s*(\S+)",  # Directly connected
            re.MULTILINE
        )

        # Simpler pattern for directly connected
        connected_pattern = re.compile(
            r"^([CL])\s+(\d+\.\d+\.\d+\.\d+/\d+)\s+is directly connected,\s*(\S+)",
            re.MULTILINE
        )

        # Pattern for routes with next-hop
        nexthop_pattern = re.compile(
            r"^([A-Za-z\*\+\s]+?)\s+"  # Protocol codes
            r"(\d+\.\d+\.\d+\.\d+/\d+)\s+"  # Network
            r"\[(\d+)/(\d+)\]\s+"  # [AD/metric]
            r"via\s+(\d+\.\d+\.\d+\.\d+)"  # Next hop
            r"(?:,\s*([^,\n]+))?"  # Uptime
            r"(?:,\s*(\S+))?",  # Interface
            re.MULTILINE
        )

        # Parse directly connected routes
        for match in connected_pattern.finditer(output):
            code, prefix, interface = match.groups()
            network, prefix_len = self.parse_prefix(prefix)
            protocol = RoutingProtocol.LOCAL if code == "L" else RoutingProtocol.CONNECTED

            routes.append(Route(
                prefix=network,
                prefix_length=prefix_len,
                protocol=protocol,
                interface=interface,
                admin_distance=0,
                metric=0,
                vrf=vrf,
                active=True,
            ))

        # Parse routes with next-hop
        for match in nexthop_pattern.finditer(output):
            codes, prefix, ad, metric, next_hop, uptime, interface = match.groups()
            codes = codes.strip()
            network, prefix_len = self.parse_prefix(prefix)

            # Determine protocol from codes
            protocol = self._parse_protocol_code(codes)

            # Parse uptime
            age_seconds = self.parse_uptime(uptime) if uptime else None

            route = Route(
                prefix=network,
                prefix_length=prefix_len,
                protocol=protocol,
                next_hop=next_hop,
                interface=interface,
                admin_distance=int(ad) if ad else 0,
                metric=int(metric) if metric else 0,
                age_seconds=age_seconds,
                vrf=vrf,
                active=True,
            )

            # Check for best route indicator
            if "*" in codes:
                route.route_type = RouteType.BEST

            routes.append(route)

        return routes

    def _parse_protocol_code(self, codes: str) -> RoutingProtocol:
        """Parse protocol from route code."""
        codes = codes.strip()

        # Check multi-character codes first
        for code in ["EX", "IA", "N1", "N2", "E1", "E2", "is", "ia", "su"]:
            if code in codes:
                return self.PROTOCOL_CODES.get(code, RoutingProtocol.UNKNOWN)

        # Check single-character codes
        for char in codes:
            if char in self.PROTOCOL_CODES:
                return self.PROTOCOL_CODES[char]

        return RoutingProtocol.UNKNOWN

    # ==========================================================================
    # BGP Parsing
    # ==========================================================================

    def parse_bgp_summary(self, output: str) -> BGPSummary:
        """Parse 'show ip bgp summary' output."""
        output = self.clean_output(output)
        summary = BGPSummary()

        # Router ID and local AS
        router_id_match = re.search(
            r"BGP router identifier\s+(\d+\.\d+\.\d+\.\d+),\s+local AS number\s+(\d+)",
            output
        )
        if router_id_match:
            summary.router_id = router_id_match.group(1)
            summary.local_asn = int(router_id_match.group(2))

        # Count neighbors and established sessions
        # Neighbor header line followed by data
        neighbor_pattern = re.compile(
            r"^(\d+\.\d+\.\d+\.\d+)\s+\d+\s+(\d+)\s+\d+\s+\d+\s+\d+\s+\d+\s+\d+\s+(\S+)\s+(\d+)",
            re.MULTILINE
        )

        total = 0
        established = 0
        total_prefixes = 0

        for match in neighbor_pattern.finditer(output):
            total += 1
            state_or_prefixes = match.group(3)

            # If it's a number, session is established with that many prefixes
            if state_or_prefixes.isdigit():
                established += 1
                total_prefixes += int(state_or_prefixes)

        summary.total_neighbors = total
        summary.established_neighbors = established
        summary.total_prefixes = total_prefixes

        return summary

    def parse_bgp_neighbors(self, output: str) -> list[BGPNeighbor]:
        """Parse 'show ip bgp neighbors' detailed output."""
        output = self.clean_output(output)
        neighbors: list[BGPNeighbor] = []

        # Split by neighbor sections
        neighbor_sections = re.split(
            r"BGP neighbor is (\d+\.\d+\.\d+\.\d+)",
            output
        )

        # Process pairs (ip, section_content)
        for i in range(1, len(neighbor_sections), 2):
            neighbor_ip = neighbor_sections[i]
            section = neighbor_sections[i + 1] if i + 1 < len(neighbor_sections) else ""

            neighbor = BGPNeighbor(
                protocol=RoutingProtocol.BGP,
                neighbor_id=neighbor_ip,
                neighbor_address=neighbor_ip,
                state="unknown",
            )

            # Remote AS
            as_match = re.search(r"remote AS\s+(\d+)", section)
            if as_match:
                neighbor.remote_asn = int(as_match.group(1))

            # Local AS
            local_as_match = re.search(r"local AS\s+(\d+)", section)
            if local_as_match:
                neighbor.local_asn = int(local_as_match.group(1))

            # Determine iBGP/eBGP
            if neighbor.remote_asn == neighbor.local_asn:
                neighbor.session_type = BGPSessionType.IBGP
            else:
                neighbor.session_type = BGPSessionType.EBGP

            # BGP state
            state_match = re.search(r"BGP state\s*=\s*(\w+)", section)
            if state_match:
                state_str = state_match.group(1).lower()
                neighbor.state = state_str
                try:
                    neighbor.bgp_state = BGPState(state_str)
                except ValueError:
                    neighbor.bgp_state = BGPState.IDLE

            # Router IDs
            remote_id_match = re.search(
                r"Remote router ID\s+(\d+\.\d+\.\d+\.\d+)",
                section
            )
            if remote_id_match:
                neighbor.remote_router_id = remote_id_match.group(1)

            # Uptime
            uptime_match = re.search(r"uptime:\s+(\S+)", section, re.IGNORECASE)
            if uptime_match:
                neighbor.uptime_seconds = self.parse_uptime(uptime_match.group(1))

            # Prefix counts
            prefixes_match = re.search(
                r"Prefixes Current:\s+(\d+)\s+(\d+)",
                section
            )
            if prefixes_match:
                neighbor.prefixes_received = int(prefixes_match.group(1))
                neighbor.prefixes_sent = int(prefixes_match.group(2))

            # Hold time and keepalive
            timers_match = re.search(
                r"Hold time is\s+(\d+),\s+keepalive interval is\s+(\d+)",
                section
            )
            if timers_match:
                neighbor.hold_time = int(timers_match.group(1))
                neighbor.keepalive = int(timers_match.group(2))

            # Message counts
            msg_match = re.search(
                r"Message statistics.*?Opens:\s+(\d+)\s+(\d+)",
                section,
                re.DOTALL
            )
            if msg_match:
                neighbor.messages_sent = int(msg_match.group(1))
                neighbor.messages_received = int(msg_match.group(2))

            # Address families
            afi_matches = re.findall(
                r"For address family:\s+(\S+\s*\S*)",
                section
            )
            neighbor.address_families = [afi.strip() for afi in afi_matches]

            # Route reflector client
            if "Route-Reflector Client" in section:
                neighbor.route_reflector_client = True

            # Last error
            error_match = re.search(
                r"Last reset\s+.*?,\s+due to\s+(.+?)(?:\n|$)",
                section
            )
            if error_match:
                neighbor.last_error = error_match.group(1).strip()

            neighbors.append(neighbor)

        return neighbors

    def parse_bgp_routes(self, output: str) -> list[BGPRoute]:
        """Parse 'show ip bgp' route table output."""
        output = self.clean_output(output)
        routes: list[BGPRoute] = []

        # BGP table entry pattern
        # *>  10.0.0.0/8       192.168.1.1              0    100      0 65001 65002 i
        # *>i 172.16.0.0/16    10.1.1.1                 0    100      0 i
        route_pattern = re.compile(
            r"^([*>sibhdSrRfxace ]{0,3})\s*"  # Status codes
            r"(\d+\.\d+\.\d+\.\d+(?:/\d+)?)\s+"  # Network
            r"(\d+\.\d+\.\d+\.\d+|0\.0\.0\.0)?\s*"  # Next hop
            r"(\d+)?\s*"  # MED
            r"(\d+)?\s*"  # Local pref
            r"(\d+)?\s*"  # Weight
            r"([\d\s{}]+)?\s*"  # AS path
            r"([ie?])?\s*$",  # Origin
            re.MULTILINE
        )

        current_network = None

        for match in route_pattern.finditer(output):
            status, network, next_hop, med, local_pref, weight, as_path, origin = match.groups()

            # Handle continuation lines (no network specified)
            if network:
                current_network = network
            else:
                network = current_network

            if not network:
                continue

            # Parse network
            if "/" in network:
                prefix, prefix_len = network.split("/")
            else:
                prefix = network
                prefix_len = 32 if "." in network else 24

            # Parse AS path
            as_path_list = []
            if as_path:
                # Remove AS set braces and split
                as_path_clean = re.sub(r"[{}]", " ", as_path)
                as_path_list = [int(asn) for asn in as_path_clean.split() if asn.isdigit()]

            # Parse origin
            origin_map = {"i": BGPOrigin.IGP, "e": BGPOrigin.EGP, "?": BGPOrigin.INCOMPLETE}
            bgp_origin = origin_map.get(origin, BGPOrigin.INCOMPLETE) if origin else BGPOrigin.INCOMPLETE

            # Determine if best route
            is_best = ">" in status
            is_valid = "*" in status
            is_internal = "i" in status

            route = BGPRoute(
                prefix=prefix,
                prefix_length=int(prefix_len),
                protocol=RoutingProtocol.BGP,
                next_hop=next_hop if next_hop and next_hop != "0.0.0.0" else None,
                as_path=as_path_list,
                origin=bgp_origin,
                med=int(med) if med else 0,
                local_pref=int(local_pref) if local_pref else 100,
                weight=int(weight) if weight else 0,
                best=is_best,
                valid=is_valid,
                session_type=BGPSessionType.IBGP if is_internal else BGPSessionType.EBGP,
                active=is_best,
            )

            routes.append(route)

        return routes

    # ==========================================================================
    # OSPF Parsing
    # ==========================================================================

    def parse_ospf_summary(self, output: str) -> OSPFSummary:
        """Parse 'show ip ospf' output."""
        output = self.clean_output(output)
        summary = OSPFSummary()

        # Router ID
        router_id_match = re.search(
            r"Router ID\s+(\d+\.\d+\.\d+\.\d+)",
            output
        )
        if router_id_match:
            summary.router_id = router_id_match.group(1)

        # Process ID
        process_match = re.search(
            r"Routing Process \"ospf\s+(\d+)\"",
            output
        )
        if process_match:
            summary.process_id = int(process_match.group(1))

        # Reference bandwidth
        ref_bw_match = re.search(
            r"Reference bandwidth unit is\s+(\d+)",
            output
        )
        if ref_bw_match:
            summary.reference_bandwidth = int(ref_bw_match.group(1))

        # Count areas
        area_matches = re.findall(
            r"Area\s+(BACKBONE\(\d+\)|\d+\.\d+\.\d+\.\d+|\d+)",
            output
        )
        summary.total_areas = len(set(area_matches))

        # Count LSAs from database summary if present
        lsa_match = re.search(
            r"Number of LSA\s+(\d+)",
            output
        )
        if lsa_match:
            summary.total_lsas = int(lsa_match.group(1))

        return summary

    def parse_ospf_neighbors(self, output: str) -> list[OSPFNeighbor]:
        """Parse 'show ip ospf neighbor' output."""
        output = self.clean_output(output)
        neighbors: list[OSPFNeighbor] = []

        # Pattern for neighbor entries
        # Neighbor ID     Pri   State           Dead Time   Address         Interface
        # 10.1.1.1        1     FULL/DR         00:00:39    192.168.1.1     GigabitEthernet0/0
        neighbor_pattern = re.compile(
            r"^(\d+\.\d+\.\d+\.\d+)\s+"  # Neighbor ID
            r"(\d+)\s+"  # Priority
            r"(\w+)/(\w+)\s+"  # State/Role (FULL/DR)
            r"(\S+)\s+"  # Dead time
            r"(\d+\.\d+\.\d+\.\d+)\s+"  # Address
            r"(\S+)",  # Interface
            re.MULTILINE
        )

        for match in neighbor_pattern.finditer(output):
            neighbor_id, priority, state, role, dead_time, address, interface = match.groups()

            # Map state string to enum
            state_map = {
                "DOWN": OSPFState.DOWN,
                "ATTEMPT": OSPFState.ATTEMPT,
                "INIT": OSPFState.INIT,
                "2WAY": OSPFState.TWO_WAY,
                "EXSTART": OSPFState.EXSTART,
                "EXCHANGE": OSPFState.EXCHANGE,
                "LOADING": OSPFState.LOADING,
                "FULL": OSPFState.FULL,
            }
            ospf_state = state_map.get(state.upper(), OSPFState.DOWN)

            # Parse dead time to seconds
            dead_seconds = self.parse_uptime(dead_time)

            neighbor = OSPFNeighbor(
                protocol=RoutingProtocol.OSPF,
                neighbor_id=neighbor_id,
                neighbor_address=address,
                interface=interface,
                state=state,
                ospf_state=ospf_state,
                priority=int(priority),
                dead_timer=dead_seconds or 40,
                is_dr=role == "DR",
                is_bdr=role == "BDR",
            )

            neighbors.append(neighbor)

        return neighbors

    def parse_ospf_routes(self, output: str) -> list[OSPFRoute]:
        """Parse OSPF routes from 'show ip route ospf' output."""
        output = self.clean_output(output)
        routes: list[OSPFRoute] = []

        # OSPF route pattern
        # O        10.0.0.0/8 [110/20] via 192.168.1.1, 00:05:30, Gi0/0
        # O IA     172.16.0.0/16 [110/30] via 10.1.1.1, 00:10:00, Gi0/1
        # O E2     0.0.0.0/0 [110/1] via 192.168.1.1, 00:15:00, Gi0/0
        route_pattern = re.compile(
            r"^O\s*(IA|E1|E2|N1|N2)?\s+"  # OSPF type
            r"(\d+\.\d+\.\d+\.\d+/\d+)\s+"  # Network
            r"\[(\d+)/(\d+)\]\s+"  # [AD/metric]
            r"via\s+(\d+\.\d+\.\d+\.\d+)"  # Next hop
            r"(?:,\s*(\S+))?"  # Age
            r"(?:,\s*(\S+))?",  # Interface
            re.MULTILINE
        )

        route_type_map = {
            None: OSPFRouteType.INTRA_AREA,
            "": OSPFRouteType.INTRA_AREA,
            "IA": OSPFRouteType.INTER_AREA,
            "E1": OSPFRouteType.EXTERNAL_1,
            "E2": OSPFRouteType.EXTERNAL_2,
            "N1": OSPFRouteType.NSSA_1,
            "N2": OSPFRouteType.NSSA_2,
        }

        for match in route_pattern.finditer(output):
            route_type, network, ad, metric, next_hop, age, interface = match.groups()

            prefix, prefix_len = self.parse_prefix(network)
            ospf_type = route_type_map.get(route_type, OSPFRouteType.INTRA_AREA)

            route = OSPFRoute(
                prefix=prefix,
                prefix_length=prefix_len,
                protocol=RoutingProtocol.OSPF,
                next_hop=next_hop,
                interface=interface,
                admin_distance=int(ad),
                metric=int(metric),
                cost=int(metric),
                ospf_route_type=ospf_type,
                age_seconds=self.parse_uptime(age) if age else None,
                active=True,
            )

            routes.append(route)

        return routes

    # ==========================================================================
    # IS-IS Parsing
    # ==========================================================================

    def parse_isis_summary(self, output: str) -> ISISSummary:
        """Parse 'show isis' or 'show clns' output."""
        output = self.clean_output(output)
        summary = ISISSummary()

        # System ID
        system_id_match = re.search(
            r"System ID:\s+(\S+)",
            output
        )
        if system_id_match:
            summary.system_id = system_id_match.group(1)

        # NET
        net_match = re.search(
            r"NET:\s+(\S+)",
            output
        )
        if net_match:
            summary.net = net_match.group(1)

        # IS-Type
        is_type_match = re.search(
            r"IS-Type:\s+(level-1-2|level-1|level-2)",
            output,
            re.IGNORECASE
        )
        if is_type_match:
            type_str = is_type_match.group(1).lower()
            if "1-2" in type_str:
                summary.is_type = ISISLevel.L1L2
            elif "level-1" in type_str:
                summary.is_type = ISISLevel.L1
            else:
                summary.is_type = ISISLevel.L2

        # Area addresses
        area_matches = re.findall(
            r"Area Address\s*:\s*(\S+)",
            output
        )
        summary.area_addresses = area_matches

        return summary

    def parse_isis_adjacencies(self, output: str) -> list[ISISAdjacency]:
        """Parse 'show isis neighbors' output."""
        output = self.clean_output(output)
        adjacencies: list[ISISAdjacency] = []

        # Pattern for IS-IS neighbor entries
        # System Id      Interface   State    Type Priority  Circuit Id
        # R1             Gi0/0       Up       L2   64        R2.01
        adj_pattern = re.compile(
            r"^(\S+)\s+"  # System ID
            r"(\S+)\s+"   # Interface
            r"(\w+)\s+"   # State
            r"(L1|L2|L1L2)\s+"  # Level
            r"(\d+)\s+"   # Priority
            r"(\S+)",     # Circuit ID
            re.MULTILINE
        )

        state_map = {
            "UP": ISISState.UP,
            "INIT": ISISState.INITIALIZING,
            "DOWN": ISISState.DOWN,
        }

        level_map = {
            "L1": ISISLevel.L1,
            "L2": ISISLevel.L2,
            "L1L2": ISISLevel.L1L2,
        }

        for match in adj_pattern.finditer(output):
            system_id, interface, state, level, priority, circuit_id = match.groups()

            adj = ISISAdjacency(
                protocol=RoutingProtocol.ISIS,
                neighbor_id=system_id,
                neighbor_address=system_id,  # IS-IS uses system ID
                interface=interface,
                state=state,
                isis_state=state_map.get(state.upper(), ISISState.DOWN),
                level=level_map.get(level, ISISLevel.L2),
                system_id=system_id,
                circuit_id=int(circuit_id.split(".")[-1]) if "." in circuit_id else None,
            )

            adjacencies.append(adj)

        return adjacencies

    def parse_isis_routes(self, output: str) -> list[ISISRoute]:
        """Parse IS-IS routes from 'show ip route isis' output."""
        output = self.clean_output(output)
        routes: list[ISISRoute] = []

        # IS-IS route pattern
        # i L1     10.0.0.0/8 [115/20] via 192.168.1.1, Gi0/0
        # i L2     172.16.0.0/16 [115/30] via 10.1.1.1, Gi0/1
        route_pattern = re.compile(
            r"^i\s+(L1|L2|ia|su)?\s*"  # IS-IS type
            r"(\d+\.\d+\.\d+\.\d+/\d+)\s+"  # Network
            r"\[(\d+)/(\d+)\]\s+"  # [AD/metric]
            r"via\s+(\d+\.\d+\.\d+\.\d+)"  # Next hop
            r"(?:,\s*(\S+))?",  # Interface
            re.MULTILINE
        )

        for match in route_pattern.finditer(output):
            level_str, network, ad, metric, next_hop, interface = match.groups()

            prefix, prefix_len = self.parse_prefix(network)

            # Determine level
            level = ISISLevel.L2  # Default
            if level_str:
                if level_str == "L1":
                    level = ISISLevel.L1
                elif level_str == "L2":
                    level = ISISLevel.L2

            route = ISISRoute(
                prefix=prefix,
                prefix_length=prefix_len,
                protocol=RoutingProtocol.ISIS,
                next_hop=next_hop,
                interface=interface,
                admin_distance=int(ad),
                metric=int(metric),
                level=level,
                active=True,
            )

            routes.append(route)

        return routes

    # ==========================================================================
    # EIGRP Parsing
    # ==========================================================================

    def parse_eigrp_summary(self, output: str) -> EIGRPSummary:
        """Parse 'show ip eigrp' or 'show ip protocols' for EIGRP output."""
        output = self.clean_output(output)
        summary = EIGRPSummary()

        # AS number
        as_match = re.search(
            r"EIGRP.*?AS\s*\((\d+)\)",
            output
        )
        if as_match:
            summary.as_number = int(as_match.group(1))

        # Router ID
        router_id_match = re.search(
            r"Router-ID:\s+(\d+\.\d+\.\d+\.\d+)",
            output
        )
        if router_id_match:
            summary.router_id = router_id_match.group(1)

        # K-values
        k_match = re.search(
            r"K1=(\d+),\s*K2=(\d+),\s*K3=(\d+),\s*K4=(\d+),\s*K5=(\d+)",
            output
        )
        if k_match:
            summary.k1, summary.k2, summary.k3, summary.k4, summary.k5 = map(int, k_match.groups())

        return summary

    def parse_eigrp_neighbors(self, output: str) -> list[EIGRPNeighbor]:
        """Parse 'show ip eigrp neighbors' output."""
        output = self.clean_output(output)
        neighbors: list[EIGRPNeighbor] = []

        # Pattern for EIGRP neighbor entries
        # H   Address         Interface       Hold   Uptime   SRTT   RTO   Q   Seq
        # 0   192.168.1.1     Gi0/0           12     00:05:30 1      50    0   15
        neighbor_pattern = re.compile(
            r"^\d+\s+"  # H (handle)
            r"(\d+\.\d+\.\d+\.\d+)\s+"  # Address
            r"(\S+)\s+"  # Interface
            r"(\d+)\s+"  # Hold time
            r"(\S+)\s+"  # Uptime
            r"(\d+)\s+"  # SRTT
            r"(\d+)\s+"  # RTO
            r"(\d+)\s+"  # Q count
            r"(\d+)",    # Sequence number
            re.MULTILINE
        )

        for match in neighbor_pattern.finditer(output):
            address, interface, hold, uptime, srtt, rto, q_count, seq = match.groups()

            neighbor = EIGRPNeighbor(
                protocol=RoutingProtocol.EIGRP,
                neighbor_id=address,
                neighbor_address=address,
                interface=interface,
                state="active",
                eigrp_state=EIGRPState.ACTIVE,
                hold_time=int(hold),
                uptime_seconds=self.parse_uptime(uptime),
                uptime_str=uptime,
                srtt=int(srtt),
                rto=int(rto),
                q_count=int(q_count),
                sequence_number=int(seq),
            )

            neighbors.append(neighbor)

        return neighbors

    def parse_eigrp_topology(self, output: str) -> list[EIGRPRoute]:
        """Parse 'show ip eigrp topology' output."""
        output = self.clean_output(output)
        routes: list[EIGRPRoute] = []

        # Pattern for EIGRP topology entries
        # P 10.0.0.0/8, 1 successors, FD is 2816
        #         via 192.168.1.1 (2816/2560), GigabitEthernet0/0
        prefix_pattern = re.compile(
            r"^([PA])\s+(\d+\.\d+\.\d+\.\d+/\d+),\s+"  # State and Network
            r"(\d+)\s+successors,\s+"  # Successors count
            r"FD is\s+(\d+)",  # Feasible distance
            re.MULTILINE
        )

        via_pattern = re.compile(
            r"via\s+(\d+\.\d+\.\d+\.\d+|Connected)\s+"  # Next hop
            r"\((\d+)/(\d+)\)"  # (FD/RD)
            r"(?:,\s*(\S+))?",  # Interface
            re.MULTILINE
        )

        current_route = None

        for line in output.split("\n"):
            # Check for prefix line
            prefix_match = prefix_pattern.match(line)
            if prefix_match:
                state, network, successors, fd = prefix_match.groups()

                prefix, prefix_len = self.parse_prefix(network)

                current_route = EIGRPRoute(
                    prefix=prefix,
                    prefix_length=prefix_len,
                    protocol=RoutingProtocol.EIGRP,
                    feasible_distance=int(fd),
                    active=state == "P",  # P=Passive (stable), A=Active (querying)
                )
                routes.append(current_route)
                continue

            # Check for via line
            via_match = via_pattern.search(line)
            if via_match and current_route:
                next_hop, via_fd, rd, interface = via_match.groups()

                if next_hop == "Connected":
                    current_route.next_hop = None
                    current_route.interface = interface
                else:
                    if not current_route.next_hop:
                        current_route.next_hop = next_hop
                        current_route.successor = next_hop
                    else:
                        current_route.feasible_successors.append(next_hop)

                    current_route.reported_distance = int(rd)
                    current_route.interface = interface

        return routes

    # ==========================================================================
    # VRF Parsing
    # ==========================================================================

    def parse_vrfs(self, output: str) -> list[VRF]:
        """Parse 'show vrf' or 'show ip vrf' output."""
        output = self.clean_output(output)
        vrfs: list[VRF] = []

        # Pattern for VRF entries
        # Name                             Default RD          Protocols   Interfaces
        # VRF1                             1:1                 ipv4        Gi0/1
        vrf_pattern = re.compile(
            r"^(\S+)\s+"  # Name
            r"(<not set>|\d+:\d+)\s+"  # RD
            r"(\S+)\s+"  # Protocols
            r"(.+)?$",   # Interfaces
            re.MULTILINE
        )

        for match in vrf_pattern.finditer(output):
            name, rd, protocols, interfaces = match.groups()

            if name in ["Name", "---"]:
                continue

            interface_list = []
            if interfaces:
                interface_list = [i.strip() for i in interfaces.split(",") if i.strip()]

            vrf = VRF(
                name=name,
                rd=rd if rd != "<not set>" else None,
                interfaces=interface_list,
            )

            vrfs.append(vrf)

        return vrfs

    # ==========================================================================
    # Redistribution Parsing
    # ==========================================================================

    def parse_redistribution(self, output: str) -> list[RedistributionPoint]:
        """Parse redistribution from running config."""
        output = self.clean_output(output)
        redistributions: list[RedistributionPoint] = []

        # Find router sections
        router_sections = re.findall(
            r"router\s+(ospf|bgp|eigrp|rip|isis)\s*(\d+)?\s*\n((?:.*?\n)*?)(?=router\s|\Z)",
            output,
            re.IGNORECASE
        )

        protocol_map = {
            "ospf": RoutingProtocol.OSPF,
            "bgp": RoutingProtocol.BGP,
            "eigrp": RoutingProtocol.EIGRP,
            "rip": RoutingProtocol.RIP,
            "isis": RoutingProtocol.ISIS,
        }

        for protocol, process_id, section in router_sections:
            target_protocol = protocol_map.get(protocol.lower(), RoutingProtocol.UNKNOWN)

            # Find redistribute commands
            redist_pattern = re.compile(
                r"redistribute\s+(\w+)\s*(\d+)?"  # Protocol and optional process
                r"(?:\s+metric\s+(\d+))?"  # Metric
                r"(?:\s+metric-type\s+(\d+))?"  # Metric type
                r"(?:\s+route-map\s+(\S+))?"  # Route map
                r"(?:\s+subnets)?",  # Subnets flag
                re.IGNORECASE
            )

            for redist_match in redist_pattern.finditer(section):
                source, src_process, metric, metric_type, route_map = redist_match.groups()

                source_protocol = protocol_map.get(source.lower(), RoutingProtocol.UNKNOWN)

                if source.lower() == "connected":
                    source_protocol = RoutingProtocol.CONNECTED
                elif source.lower() == "static":
                    source_protocol = RoutingProtocol.STATIC

                redist = RedistributionPoint(
                    source_protocol=source_protocol,
                    target_protocol=target_protocol,
                    metric=int(metric) if metric else None,
                    metric_type=f"E{metric_type}" if metric_type else None,
                    route_map=route_map,
                )

                redistributions.append(redist)

        return redistributions
