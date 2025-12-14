"""
Base class for device output parsers.

Provides common functionality for parsing device command output
into structured data models.

Copyright (c) 2025 DNS Science.io, an After Dark Systems, LLC company.
All rights reserved.
"""

import re
from abc import ABC, abstractmethod
from typing import Any

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
    RoutingProtocol,
    VRF,
    BGPSummary,
    OSPFSummary,
    ISISSummary,
    EIGRPSummary,
)


class OutputParser(ABC):
    """Abstract base class for device output parsers.

    Each vendor-specific parser must implement methods to parse
    command output into model objects.
    """

    @property
    @abstractmethod
    def vendor(self) -> str:
        """Return the vendor name this parser supports."""
        pass

    # ==========================================================================
    # Route Table Parsing
    # ==========================================================================

    @abstractmethod
    def parse_route_table(self, output: str, vrf: str = "default") -> list[Route]:
        """Parse 'show ip route' output.

        Args:
            output: Raw command output
            vrf: VRF name (default for global table)

        Returns:
            List of Route objects
        """
        pass

    # ==========================================================================
    # BGP Parsing
    # ==========================================================================

    @abstractmethod
    def parse_bgp_summary(self, output: str) -> BGPSummary:
        """Parse 'show ip bgp summary' output.

        Args:
            output: Raw command output

        Returns:
            BGPSummary object
        """
        pass

    @abstractmethod
    def parse_bgp_neighbors(self, output: str) -> list[BGPNeighbor]:
        """Parse 'show ip bgp neighbors' output.

        Args:
            output: Raw command output

        Returns:
            List of BGPNeighbor objects
        """
        pass

    @abstractmethod
    def parse_bgp_routes(self, output: str) -> list[BGPRoute]:
        """Parse 'show ip bgp' route table output.

        Args:
            output: Raw command output

        Returns:
            List of BGPRoute objects
        """
        pass

    def parse_bgp_neighbor_routes(
        self,
        output: str,
        route_type: str = "received"
    ) -> list[BGPRoute]:
        """Parse BGP neighbor advertised/received routes.

        Args:
            output: Raw command output
            route_type: 'received' or 'advertised'

        Returns:
            List of BGPRoute objects
        """
        # Default implementation uses parse_bgp_routes
        return self.parse_bgp_routes(output)

    # ==========================================================================
    # OSPF Parsing
    # ==========================================================================

    @abstractmethod
    def parse_ospf_summary(self, output: str) -> OSPFSummary:
        """Parse 'show ip ospf' output.

        Args:
            output: Raw command output

        Returns:
            OSPFSummary object
        """
        pass

    @abstractmethod
    def parse_ospf_neighbors(self, output: str) -> list[OSPFNeighbor]:
        """Parse 'show ip ospf neighbor' output.

        Args:
            output: Raw command output

        Returns:
            List of OSPFNeighbor objects
        """
        pass

    @abstractmethod
    def parse_ospf_routes(self, output: str) -> list[OSPFRoute]:
        """Parse OSPF routes from route table.

        Args:
            output: Raw command output

        Returns:
            List of OSPFRoute objects
        """
        pass

    def parse_ospf_database(self, output: str) -> dict[str, Any]:
        """Parse 'show ip ospf database' output.

        Args:
            output: Raw command output

        Returns:
            Dictionary with LSDB information
        """
        return {"raw": output}

    def parse_ospf_interfaces(self, output: str) -> list[dict[str, Any]]:
        """Parse 'show ip ospf interface' output.

        Args:
            output: Raw command output

        Returns:
            List of interface information dictionaries
        """
        return []

    # ==========================================================================
    # IS-IS Parsing
    # ==========================================================================

    @abstractmethod
    def parse_isis_summary(self, output: str) -> ISISSummary:
        """Parse IS-IS summary output.

        Args:
            output: Raw command output

        Returns:
            ISISSummary object
        """
        pass

    @abstractmethod
    def parse_isis_adjacencies(self, output: str) -> list[ISISAdjacency]:
        """Parse IS-IS adjacencies output.

        Args:
            output: Raw command output

        Returns:
            List of ISISAdjacency objects
        """
        pass

    @abstractmethod
    def parse_isis_routes(self, output: str) -> list[ISISRoute]:
        """Parse IS-IS routes.

        Args:
            output: Raw command output

        Returns:
            List of ISISRoute objects
        """
        pass

    # ==========================================================================
    # RIP Parsing
    # ==========================================================================

    def parse_rip_summary(self, output: str) -> dict[str, Any]:
        """Parse RIP summary output.

        Args:
            output: Raw command output

        Returns:
            Dictionary with RIP information
        """
        return {"raw": output}

    def parse_rip_neighbors(self, output: str) -> list[RIPNeighbor]:
        """Parse RIP neighbors.

        Args:
            output: Raw command output

        Returns:
            List of RIPNeighbor objects
        """
        return []

    def parse_rip_routes(self, output: str) -> list[RIPRoute]:
        """Parse RIP routes.

        Args:
            output: Raw command output

        Returns:
            List of RIPRoute objects
        """
        return []

    # ==========================================================================
    # EIGRP Parsing
    # ==========================================================================

    @abstractmethod
    def parse_eigrp_summary(self, output: str) -> EIGRPSummary:
        """Parse EIGRP summary output.

        Args:
            output: Raw command output

        Returns:
            EIGRPSummary object
        """
        pass

    @abstractmethod
    def parse_eigrp_neighbors(self, output: str) -> list[EIGRPNeighbor]:
        """Parse EIGRP neighbors output.

        Args:
            output: Raw command output

        Returns:
            List of EIGRPNeighbor objects
        """
        pass

    @abstractmethod
    def parse_eigrp_topology(self, output: str) -> list[EIGRPRoute]:
        """Parse EIGRP topology table.

        Args:
            output: Raw command output

        Returns:
            List of EIGRPRoute objects
        """
        pass

    # ==========================================================================
    # VRF Parsing
    # ==========================================================================

    def parse_vrfs(self, output: str) -> list[VRF]:
        """Parse VRF information.

        Args:
            output: Raw command output

        Returns:
            List of VRF objects
        """
        return []

    # ==========================================================================
    # Redistribution Parsing
    # ==========================================================================

    def parse_redistribution(self, output: str) -> list[RedistributionPoint]:
        """Parse redistribution configuration from running config.

        Args:
            output: Raw running config section

        Returns:
            List of RedistributionPoint objects
        """
        return []

    # ==========================================================================
    # Utility Methods
    # ==========================================================================

    @staticmethod
    def parse_uptime(uptime_str: str) -> int | None:
        """Parse uptime string to seconds.

        Args:
            uptime_str: Uptime string (e.g., "1d2h", "00:05:30", "2w3d")

        Returns:
            Uptime in seconds, or None if unable to parse
        """
        if not uptime_str:
            return None

        total_seconds = 0

        # Pattern: weeks (w), days (d), hours (h), minutes (m), seconds (s)
        patterns = [
            (r"(\d+)w", 7 * 24 * 3600),  # weeks
            (r"(\d+)d", 24 * 3600),       # days
            (r"(\d+)h", 3600),            # hours
            (r"(\d+)m", 60),              # minutes
            (r"(\d+)s", 1),               # seconds
        ]

        for pattern, multiplier in patterns:
            match = re.search(pattern, uptime_str)
            if match:
                total_seconds += int(match.group(1)) * multiplier

        # Try HH:MM:SS format
        hms_match = re.match(r"(\d+):(\d+):(\d+)", uptime_str)
        if hms_match:
            hours, minutes, seconds = map(int, hms_match.groups())
            total_seconds = hours * 3600 + minutes * 60 + seconds

        return total_seconds if total_seconds > 0 else None

    @staticmethod
    def parse_prefix(prefix_str: str) -> tuple[str, int]:
        """Parse prefix string into network and length.

        Args:
            prefix_str: Prefix string (e.g., "10.0.0.0/8" or "10.0.0.0 255.0.0.0")

        Returns:
            Tuple of (network, prefix_length)
        """
        if "/" in prefix_str:
            parts = prefix_str.split("/")
            return parts[0], int(parts[1])

        # Handle mask format
        if " " in prefix_str:
            parts = prefix_str.split()
            network = parts[0]
            mask = parts[1]
            prefix_length = OutputParser._mask_to_prefix_length(mask)
            return network, prefix_length

        # Assume /32 for single IP
        return prefix_str, 32

    @staticmethod
    def _mask_to_prefix_length(mask: str) -> int:
        """Convert subnet mask to prefix length.

        Args:
            mask: Subnet mask (e.g., "255.255.255.0")

        Returns:
            Prefix length (e.g., 24)
        """
        octets = mask.split(".")
        binary = "".join(format(int(octet), "08b") for octet in octets)
        return binary.count("1")

    @staticmethod
    def clean_output(output: str) -> str:
        """Clean command output by removing ANSI codes and extra whitespace.

        Args:
            output: Raw command output

        Returns:
            Cleaned output
        """
        # Remove ANSI escape codes
        ansi_escape = re.compile(r"\x1B(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])")
        output = ansi_escape.sub("", output)

        # Remove carriage returns
        output = output.replace("\r", "")

        return output
