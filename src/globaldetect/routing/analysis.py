"""
Routing analysis and troubleshooting tools.

Provides algorithms for analyzing routing tables, detecting issues,
and troubleshooting common routing problems.

Copyright (c) 2025 DNS Science.io, an After Dark Systems, LLC company.
All rights reserved.
"""

import logging
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Any
from collections import defaultdict

from globaldetect.routing.models import (
    Route,
    BGPRoute,
    OSPFRoute,
    EIGRPRoute,
    ProtocolNeighbor,
    BGPNeighbor,
    OSPFNeighbor,
    ISISAdjacency,
    EIGRPNeighbor,
    RedistributionPoint,
    RoutingProtocol,
    BGPState,
    OSPFState,
    ISISState,
    RouteChange,
)

logger = logging.getLogger(__name__)


# =============================================================================
# Analysis Results
# =============================================================================

@dataclass
class RoutingHealthReport:
    """Overall routing health assessment."""
    device_id: str
    timestamp: datetime = field(default_factory=datetime.now)
    overall_health: str = "unknown"  # healthy, degraded, critical
    score: int = 100  # 0-100

    # Issues found
    issues: list[dict[str, Any]] = field(default_factory=list)
    warnings: list[dict[str, Any]] = field(default_factory=list)

    # Protocol health
    bgp_health: str = "unknown"
    ospf_health: str = "unknown"
    isis_health: str = "unknown"
    eigrp_health: str = "unknown"

    # Statistics
    total_routes: int = 0
    total_neighbors: int = 0
    established_neighbors: int = 0
    problem_neighbors: int = 0

    # Recommendations
    recommendations: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "device_id": self.device_id,
            "timestamp": self.timestamp.isoformat(),
            "overall_health": self.overall_health,
            "score": self.score,
            "issues": self.issues,
            "warnings": self.warnings,
            "bgp_health": self.bgp_health,
            "ospf_health": self.ospf_health,
            "isis_health": self.isis_health,
            "eigrp_health": self.eigrp_health,
            "total_routes": self.total_routes,
            "total_neighbors": self.total_neighbors,
            "established_neighbors": self.established_neighbors,
            "problem_neighbors": self.problem_neighbors,
            "recommendations": self.recommendations,
        }


@dataclass
class RouteAnalysis:
    """Analysis of a specific route or prefix."""
    prefix: str
    protocol: RoutingProtocol
    available_paths: int = 0
    best_path: Route | None = None
    backup_paths: list[Route] = field(default_factory=list)

    # BGP-specific
    as_path_diversity: int = 0  # Number of unique AS paths
    origin_asns: list[int] = field(default_factory=list)

    # Issues
    issues: list[str] = field(default_factory=list)
    is_blackholed: bool = False
    is_suboptimal: bool = False


@dataclass
class ConvergenceAnalysis:
    """Analysis of routing convergence."""
    start_time: datetime | None = None
    end_time: datetime | None = None
    convergence_time_seconds: float = 0.0

    # Route changes during convergence
    routes_added: int = 0
    routes_withdrawn: int = 0
    routes_updated: int = 0

    # Protocols involved
    protocols_affected: list[RoutingProtocol] = field(default_factory=list)

    # Issue detection
    slow_convergence: bool = False
    micro_loops_detected: bool = False


# =============================================================================
# Analysis Functions
# =============================================================================

class RoutingAnalyzer:
    """Routing analysis and troubleshooting engine."""

    # Thresholds for health assessment
    BGP_ESTABLISHED_THRESHOLD = 0.8  # 80% of neighbors should be established
    OSPF_FULL_THRESHOLD = 0.9  # 90% of neighbors should be FULL
    FLAP_THRESHOLD = 5  # Routes flapping more than this are problematic
    ECMP_MAX_PATHS = 16  # Maximum reasonable ECMP paths

    def __init__(self):
        pass

    def analyze_health(
        self,
        routes: list[Route],
        neighbors: list[ProtocolNeighbor],
        redistributions: list[RedistributionPoint] | None = None,
        device_id: str = "unknown",
    ) -> RoutingHealthReport:
        """Perform comprehensive health analysis.

        Args:
            routes: List of routes
            neighbors: List of protocol neighbors
            redistributions: Optional redistribution config
            device_id: Device identifier

        Returns:
            RoutingHealthReport with findings
        """
        report = RoutingHealthReport(device_id=device_id)
        report.total_routes = len(routes)
        report.total_neighbors = len(neighbors)

        # Analyze each protocol
        bgp_neighbors = [n for n in neighbors if isinstance(n, BGPNeighbor)]
        ospf_neighbors = [n for n in neighbors if isinstance(n, OSPFNeighbor)]
        isis_neighbors = [n for n in neighbors if isinstance(n, ISISAdjacency)]
        eigrp_neighbors = [n for n in neighbors if isinstance(n, EIGRPNeighbor)]

        # BGP analysis
        if bgp_neighbors:
            bgp_result = self._analyze_bgp_health(bgp_neighbors)
            report.bgp_health = bgp_result["health"]
            report.issues.extend(bgp_result["issues"])
            report.warnings.extend(bgp_result["warnings"])
            report.established_neighbors += bgp_result["established"]
            report.problem_neighbors += bgp_result["problem_count"]

        # OSPF analysis
        if ospf_neighbors:
            ospf_result = self._analyze_ospf_health(ospf_neighbors)
            report.ospf_health = ospf_result["health"]
            report.issues.extend(ospf_result["issues"])
            report.warnings.extend(ospf_result["warnings"])
            report.established_neighbors += ospf_result["full"]
            report.problem_neighbors += ospf_result["problem_count"]

        # IS-IS analysis
        if isis_neighbors:
            isis_result = self._analyze_isis_health(isis_neighbors)
            report.isis_health = isis_result["health"]
            report.issues.extend(isis_result["issues"])
            report.warnings.extend(isis_result["warnings"])
            report.established_neighbors += isis_result["up"]
            report.problem_neighbors += isis_result["problem_count"]

        # EIGRP analysis
        if eigrp_neighbors:
            eigrp_result = self._analyze_eigrp_health(eigrp_neighbors)
            report.eigrp_health = eigrp_result["health"]
            report.issues.extend(eigrp_result["issues"])
            report.warnings.extend(eigrp_result["warnings"])
            report.established_neighbors += eigrp_result["active"]
            report.problem_neighbors += eigrp_result["problem_count"]

        # Route analysis
        route_result = self._analyze_routes(routes)
        report.issues.extend(route_result["issues"])
        report.warnings.extend(route_result["warnings"])

        # Redistribution analysis
        if redistributions:
            redist_result = self._analyze_redistribution(redistributions, routes)
            report.warnings.extend(redist_result["warnings"])

        # Calculate overall health score
        report.score = self._calculate_health_score(report)

        if report.score >= 90:
            report.overall_health = "healthy"
        elif report.score >= 70:
            report.overall_health = "degraded"
        else:
            report.overall_health = "critical"

        # Generate recommendations
        report.recommendations = self._generate_recommendations(report)

        return report

    def _analyze_bgp_health(self, neighbors: list[BGPNeighbor]) -> dict[str, Any]:
        """Analyze BGP neighbor health."""
        result = {
            "health": "healthy",
            "issues": [],
            "warnings": [],
            "established": 0,
            "problem_count": 0,
        }

        if not neighbors:
            return result

        for neighbor in neighbors:
            if neighbor.bgp_state == BGPState.ESTABLISHED:
                result["established"] += 1
            else:
                result["problem_count"] += 1
                result["issues"].append({
                    "type": "bgp_neighbor_down",
                    "severity": "critical",
                    "neighbor": neighbor.neighbor_address,
                    "state": neighbor.bgp_state.value,
                    "remote_asn": neighbor.remote_asn,
                    "message": f"BGP neighbor {neighbor.neighbor_address} (AS{neighbor.remote_asn}) is {neighbor.bgp_state.value}",
                })

            # Check for stale sessions (no prefixes received)
            if neighbor.bgp_state == BGPState.ESTABLISHED and neighbor.prefixes_received == 0:
                result["warnings"].append({
                    "type": "bgp_no_prefixes",
                    "severity": "warning",
                    "neighbor": neighbor.neighbor_address,
                    "message": f"BGP neighbor {neighbor.neighbor_address} established but no prefixes received",
                })

            # Check for errors
            if neighbor.last_error:
                result["warnings"].append({
                    "type": "bgp_last_error",
                    "severity": "warning",
                    "neighbor": neighbor.neighbor_address,
                    "error": neighbor.last_error,
                    "message": f"BGP neighbor {neighbor.neighbor_address} last error: {neighbor.last_error}",
                })

        # Determine overall BGP health
        established_ratio = result["established"] / len(neighbors) if neighbors else 0
        if established_ratio >= self.BGP_ESTABLISHED_THRESHOLD:
            result["health"] = "healthy"
        elif established_ratio >= 0.5:
            result["health"] = "degraded"
        else:
            result["health"] = "critical"

        return result

    def _analyze_ospf_health(self, neighbors: list[OSPFNeighbor]) -> dict[str, Any]:
        """Analyze OSPF neighbor health."""
        result = {
            "health": "healthy",
            "issues": [],
            "warnings": [],
            "full": 0,
            "problem_count": 0,
        }

        if not neighbors:
            return result

        for neighbor in neighbors:
            if neighbor.ospf_state == OSPFState.FULL:
                result["full"] += 1
            elif neighbor.ospf_state == OSPFState.TWO_WAY:
                # 2-WAY is expected on broadcast networks for non-DR/BDR
                if not neighbor.is_dr and not neighbor.is_bdr:
                    result["full"] += 1  # This is normal
                else:
                    result["warnings"].append({
                        "type": "ospf_not_full",
                        "severity": "warning",
                        "neighbor": neighbor.neighbor_id,
                        "state": neighbor.ospf_state.value,
                        "message": f"OSPF neighbor {neighbor.neighbor_id} stuck in {neighbor.ospf_state.value}",
                    })
            else:
                result["problem_count"] += 1
                result["issues"].append({
                    "type": "ospf_neighbor_down",
                    "severity": "critical",
                    "neighbor": neighbor.neighbor_id,
                    "state": neighbor.ospf_state.value,
                    "interface": neighbor.interface,
                    "message": f"OSPF neighbor {neighbor.neighbor_id} is {neighbor.ospf_state.value}",
                })

        # Determine overall OSPF health
        full_ratio = result["full"] / len(neighbors) if neighbors else 0
        if full_ratio >= self.OSPF_FULL_THRESHOLD:
            result["health"] = "healthy"
        elif full_ratio >= 0.5:
            result["health"] = "degraded"
        else:
            result["health"] = "critical"

        return result

    def _analyze_isis_health(self, neighbors: list[ISISAdjacency]) -> dict[str, Any]:
        """Analyze IS-IS adjacency health."""
        result = {
            "health": "healthy",
            "issues": [],
            "warnings": [],
            "up": 0,
            "problem_count": 0,
        }

        if not neighbors:
            return result

        for neighbor in neighbors:
            if neighbor.isis_state == ISISState.UP:
                result["up"] += 1
            else:
                result["problem_count"] += 1
                result["issues"].append({
                    "type": "isis_adjacency_down",
                    "severity": "critical",
                    "neighbor": neighbor.system_id or neighbor.neighbor_id,
                    "state": neighbor.isis_state.value,
                    "level": neighbor.level.value,
                    "message": f"IS-IS adjacency to {neighbor.system_id} is {neighbor.isis_state.value}",
                })

        # Determine health
        up_ratio = result["up"] / len(neighbors) if neighbors else 0
        if up_ratio >= 0.9:
            result["health"] = "healthy"
        elif up_ratio >= 0.5:
            result["health"] = "degraded"
        else:
            result["health"] = "critical"

        return result

    def _analyze_eigrp_health(self, neighbors: list[EIGRPNeighbor]) -> dict[str, Any]:
        """Analyze EIGRP neighbor health."""
        result = {
            "health": "healthy",
            "issues": [],
            "warnings": [],
            "active": 0,
            "problem_count": 0,
        }

        if not neighbors:
            return result

        for neighbor in neighbors:
            result["active"] += 1  # EIGRP neighbors in list are typically active

            # Check for high queue counts (stuck in active)
            if neighbor.q_count > 0:
                result["warnings"].append({
                    "type": "eigrp_queue",
                    "severity": "warning",
                    "neighbor": neighbor.neighbor_address,
                    "q_count": neighbor.q_count,
                    "message": f"EIGRP neighbor {neighbor.neighbor_address} has {neighbor.q_count} packets queued",
                })

            # Check for high SRTT (slow neighbor)
            if neighbor.srtt > 1000:  # > 1 second
                result["warnings"].append({
                    "type": "eigrp_slow_neighbor",
                    "severity": "warning",
                    "neighbor": neighbor.neighbor_address,
                    "srtt": neighbor.srtt,
                    "message": f"EIGRP neighbor {neighbor.neighbor_address} has high SRTT ({neighbor.srtt}ms)",
                })

        result["health"] = "healthy" if result["problem_count"] == 0 else "degraded"
        return result

    def _analyze_routes(self, routes: list[Route]) -> dict[str, Any]:
        """Analyze route table for issues."""
        result = {
            "issues": [],
            "warnings": [],
        }

        # Group routes by prefix
        by_prefix: dict[str, list[Route]] = defaultdict(list)
        for route in routes:
            by_prefix[route.network].append(route)

        # Check for issues
        for prefix, route_list in by_prefix.items():
            # Check for excessive ECMP
            active_routes = [r for r in route_list if r.active]
            if len(active_routes) > self.ECMP_MAX_PATHS:
                result["warnings"].append({
                    "type": "excessive_ecmp",
                    "severity": "warning",
                    "prefix": prefix,
                    "path_count": len(active_routes),
                    "message": f"Prefix {prefix} has {len(active_routes)} ECMP paths (threshold: {self.ECMP_MAX_PATHS})",
                })

            # Check for null routes (potential blackholes)
            for route in route_list:
                if route.next_hop is None and route.interface and "Null" in route.interface:
                    result["warnings"].append({
                        "type": "null_route",
                        "severity": "info",
                        "prefix": prefix,
                        "message": f"Null route detected for {prefix}",
                    })

        # Check for default route
        has_default = any(r.prefix == "0.0.0.0" and r.prefix_length == 0 for r in routes)
        if not has_default:
            result["warnings"].append({
                "type": "no_default_route",
                "severity": "info",
                "message": "No default route (0.0.0.0/0) present",
            })

        return result

    def _analyze_redistribution(
        self,
        redistributions: list[RedistributionPoint],
        routes: list[Route],
    ) -> dict[str, Any]:
        """Analyze redistribution configuration."""
        result = {
            "warnings": [],
        }

        # Check for mutual redistribution (potential loops)
        redist_pairs = set()
        for redist in redistributions:
            pair = (redist.source_protocol, redist.target_protocol)
            reverse_pair = (redist.target_protocol, redist.source_protocol)

            if reverse_pair in redist_pairs:
                result["warnings"].append({
                    "type": "mutual_redistribution",
                    "severity": "warning",
                    "protocols": [pair[0].value, pair[1].value],
                    "message": f"Mutual redistribution detected between {pair[0].value} and {pair[1].value}. "
                              "Ensure route filtering is in place to prevent routing loops.",
                })

            redist_pairs.add(pair)

        # Check for redistribution without route-map
        for redist in redistributions:
            if not redist.route_map and not redist.prefix_list:
                result["warnings"].append({
                    "type": "unfiltered_redistribution",
                    "severity": "warning",
                    "source": redist.source_protocol.value,
                    "target": redist.target_protocol.value,
                    "message": f"Redistribution from {redist.source_protocol.value} into "
                              f"{redist.target_protocol.value} has no route-map or prefix-list",
                })

        return result

    def _calculate_health_score(self, report: RoutingHealthReport) -> int:
        """Calculate overall health score (0-100)."""
        score = 100

        # Deduct for critical issues
        score -= len([i for i in report.issues if i.get("severity") == "critical"]) * 15

        # Deduct for warnings
        score -= len(report.warnings) * 3

        # Factor in neighbor health
        if report.total_neighbors > 0:
            neighbor_health = report.established_neighbors / report.total_neighbors
            if neighbor_health < 0.5:
                score -= 30
            elif neighbor_health < 0.8:
                score -= 15

        # Ensure score stays in range
        return max(0, min(100, score))

    def _generate_recommendations(self, report: RoutingHealthReport) -> list[str]:
        """Generate recommendations based on findings."""
        recommendations = []

        # BGP recommendations
        if report.bgp_health == "critical":
            recommendations.append(
                "Critical: Multiple BGP sessions are down. Investigate BGP peering issues - "
                "check interface status, BGP configuration, and connectivity to peers."
            )
        elif report.bgp_health == "degraded":
            recommendations.append(
                "Warning: Some BGP sessions are not established. Review BGP neighbor status "
                "and check for configuration mismatches or network issues."
            )

        # OSPF recommendations
        if report.ospf_health == "critical":
            recommendations.append(
                "Critical: OSPF adjacencies are failing. Check interface MTU settings, "
                "area configuration, authentication, and network connectivity."
            )

        # Check for no default route
        for warning in report.warnings:
            if warning.get("type") == "no_default_route":
                recommendations.append(
                    "Note: No default route present. Verify this is expected behavior "
                    "or configure a default route for internet connectivity."
                )

        # Check for unfiltered redistribution
        for warning in report.warnings:
            if warning.get("type") == "unfiltered_redistribution":
                recommendations.append(
                    f"Recommendation: Add route filtering (route-map) to redistribution "
                    f"from {warning['source']} into {warning['target']} to prevent "
                    "unintended route advertisement."
                )

        # Mutual redistribution
        for warning in report.warnings:
            if warning.get("type") == "mutual_redistribution":
                recommendations.append(
                    f"Warning: Mutual redistribution detected between {warning['protocols']}. "
                    "Implement route tagging and filtering to prevent routing loops."
                )

        return recommendations

    def analyze_bgp_path(
        self,
        routes: list[BGPRoute],
        prefix: str,
    ) -> RouteAnalysis:
        """Analyze BGP path selection for a prefix.

        Args:
            routes: List of BGP routes
            prefix: Prefix to analyze

        Returns:
            RouteAnalysis with path information
        """
        analysis = RouteAnalysis(prefix=prefix, protocol=RoutingProtocol.BGP)

        # Filter routes for this prefix
        prefix_routes = [r for r in routes if r.network == prefix]
        analysis.available_paths = len(prefix_routes)

        if not prefix_routes:
            analysis.issues.append(f"No BGP routes found for {prefix}")
            return analysis

        # Find best path
        best = next((r for r in prefix_routes if r.best), None)
        analysis.best_path = best
        analysis.backup_paths = [r for r in prefix_routes if not r.best]

        # Analyze AS path diversity
        unique_as_paths = set()
        origin_asns = set()
        for route in prefix_routes:
            if route.as_path:
                unique_as_paths.add(tuple(route.as_path))
                origin_asns.add(route.as_path[-1])

        analysis.as_path_diversity = len(unique_as_paths)
        analysis.origin_asns = list(origin_asns)

        # Check for issues
        if len(origin_asns) > 1:
            analysis.issues.append(
                f"Multiple origin ASNs detected: {origin_asns}. "
                "This could indicate a prefix hijack or misconfiguration."
            )

        if best and best.as_path_length > 10:
            analysis.issues.append(
                f"Long AS path ({best.as_path_length} hops) may indicate suboptimal routing."
            )

        return analysis

    def detect_routing_loops(
        self,
        routes: list[Route],
        neighbors: list[ProtocolNeighbor],
    ) -> list[dict[str, Any]]:
        """Detect potential routing loops.

        Args:
            routes: List of routes
            neighbors: List of neighbors

        Returns:
            List of detected loop conditions
        """
        loops = []

        # Build next-hop to neighbor mapping
        neighbor_ips = {n.neighbor_address for n in neighbors}

        # Check for routes pointing to ourselves
        for route in routes:
            if route.next_hop and route.next_hop in neighbor_ips:
                # Check if there's a return route
                for other_route in routes:
                    if (other_route.prefix in route.next_hop and
                        other_route.next_hop and
                        route.prefix in other_route.next_hop):
                        loops.append({
                            "type": "potential_loop",
                            "route1": route.network,
                            "route2": other_route.network,
                            "next_hop1": route.next_hop,
                            "next_hop2": other_route.next_hop,
                        })

        return loops

    def analyze_convergence(
        self,
        changes: list[RouteChange],
        window_minutes: int = 5,
    ) -> ConvergenceAnalysis:
        """Analyze routing convergence from route changes.

        Args:
            changes: List of route changes
            window_minutes: Analysis window

        Returns:
            ConvergenceAnalysis results
        """
        analysis = ConvergenceAnalysis()

        if not changes:
            return analysis

        # Sort by timestamp
        sorted_changes = sorted(changes, key=lambda c: c.timestamp or datetime.min)

        analysis.start_time = sorted_changes[0].timestamp
        analysis.end_time = sorted_changes[-1].timestamp

        if analysis.start_time and analysis.end_time:
            analysis.convergence_time_seconds = (
                analysis.end_time - analysis.start_time
            ).total_seconds()

        # Count change types
        for change in changes:
            if change.change_type == "add":
                analysis.routes_added += 1
            elif change.change_type == "withdraw":
                analysis.routes_withdrawn += 1
            else:
                analysis.routes_updated += 1

            if change.protocol not in analysis.protocols_affected:
                analysis.protocols_affected.append(change.protocol)

        # Check for slow convergence (more than 30 seconds)
        if analysis.convergence_time_seconds > 30:
            analysis.slow_convergence = True

        return analysis
