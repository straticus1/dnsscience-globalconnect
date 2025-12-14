"""
Base class for routing protocol handlers.

Provides the interface that all protocol-specific handlers must implement.

Copyright (c) 2025 DNS Science.io, an After Dark Systems, LLC company.
All rights reserved.
"""

from abc import ABC, abstractmethod
from typing import Any

from globaldetect.routing.models import (
    Route,
    ProtocolNeighbor,
    RoutingProtocol,
    RedistributionPoint,
)


class RoutingProtocolHandler(ABC):
    """Abstract base class for routing protocol handlers.

    Each protocol handler is responsible for:
    - Defining commands to query the protocol
    - Parsing output into model objects
    - Protocol-specific analysis and troubleshooting
    """

    # Protocol this handler supports
    protocol: RoutingProtocol

    @property
    @abstractmethod
    def name(self) -> str:
        """Human-readable name for the protocol."""
        pass

    @abstractmethod
    def get_summary_commands(self) -> list[str]:
        """Return commands to get protocol summary/status.

        Returns:
            List of device commands to execute
        """
        pass

    @abstractmethod
    def get_neighbor_commands(self) -> list[str]:
        """Return commands to get neighbor/adjacency information.

        Returns:
            List of device commands to execute
        """
        pass

    @abstractmethod
    def get_route_commands(self, prefix: str | None = None) -> list[str]:
        """Return commands to get routes for this protocol.

        Args:
            prefix: Optional prefix to filter routes

        Returns:
            List of device commands to execute
        """
        pass

    @abstractmethod
    def get_database_commands(self) -> list[str]:
        """Return commands to get protocol database (LSA, LSP, etc).

        Returns:
            List of device commands to execute
        """
        pass

    @abstractmethod
    def parse_summary(self, output: str) -> dict[str, Any]:
        """Parse protocol summary output.

        Args:
            output: Raw command output

        Returns:
            Dictionary with protocol summary information
        """
        pass

    @abstractmethod
    def parse_neighbors(self, output: str) -> list[ProtocolNeighbor]:
        """Parse neighbor/adjacency output.

        Args:
            output: Raw command output

        Returns:
            List of protocol neighbors
        """
        pass

    @abstractmethod
    def parse_routes(self, output: str) -> list[Route]:
        """Parse route table output.

        Args:
            output: Raw command output

        Returns:
            List of routes
        """
        pass

    def parse_database(self, output: str) -> dict[str, Any]:
        """Parse protocol database output.

        Args:
            output: Raw command output

        Returns:
            Dictionary with database information
        """
        # Default implementation - subclasses can override
        return {"raw": output}

    def analyze_neighbors(self, neighbors: list[ProtocolNeighbor]) -> dict[str, Any]:
        """Analyze neighbor state and return insights.

        Args:
            neighbors: List of protocol neighbors

        Returns:
            Analysis results including:
            - Total neighbors
            - Neighbors by state
            - Problem neighbors
            - Recommendations
        """
        states: dict[str, int] = {}
        problems: list[dict[str, Any]] = []

        for neighbor in neighbors:
            state = neighbor.state.lower()
            states[state] = states.get(state, 0) + 1

            # Check for problematic states
            if self._is_problem_state(state):
                problems.append({
                    "neighbor": neighbor.neighbor_address,
                    "state": state,
                    "interface": neighbor.interface,
                })

        return {
            "total": len(neighbors),
            "by_state": states,
            "problems": problems,
            "healthy": len(problems) == 0,
        }

    def _is_problem_state(self, state: str) -> bool:
        """Check if a neighbor state indicates a problem.

        Args:
            state: Neighbor state string

        Returns:
            True if state indicates a problem
        """
        # Protocol-specific implementations should override
        problem_states = {"down", "idle", "init", "active", "connect"}
        return state.lower() in problem_states

    def analyze_routes(self, routes: list[Route]) -> dict[str, Any]:
        """Analyze routes and return insights.

        Args:
            routes: List of routes

        Returns:
            Analysis results including:
            - Total routes
            - Routes by type
            - Inactive routes
            - Recommendations
        """
        by_type: dict[str, int] = {}
        inactive: list[Route] = []

        for route in routes:
            route_type = route.route_type.value
            by_type[route_type] = by_type.get(route_type, 0) + 1

            if not route.active:
                inactive.append(route)

        return {
            "total": len(routes),
            "by_type": by_type,
            "inactive_count": len(inactive),
            "inactive_routes": [r.network for r in inactive[:10]],  # First 10
        }

    def get_redistribution_into_commands(self) -> list[str]:
        """Return commands to check what routes are redistributed INTO this protocol.

        Returns:
            List of device commands to execute
        """
        return []

    def parse_redistribution(self, output: str) -> list[RedistributionPoint]:
        """Parse redistribution configuration.

        Args:
            output: Raw command output

        Returns:
            List of redistribution points
        """
        return []
