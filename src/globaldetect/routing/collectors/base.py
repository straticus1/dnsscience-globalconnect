"""
Base collector class for routing protocol information.

Provides the interface for connecting to devices and retrieving
routing protocol state.

Copyright (c) 2025 DNS Science.io, an After Dark Systems, LLC company.
All rights reserved.
"""

import asyncio
import logging
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any

from globaldetect.routing.models import (
    Route,
    RoutingProtocol,
    ProtocolNeighbor,
    RedistributionPoint,
    RoutingSnapshot,
    VRF,
    BGPSummary,
    OSPFSummary,
    ISISSummary,
    EIGRPSummary,
)
from globaldetect.routing.parsers.base import OutputParser

logger = logging.getLogger(__name__)


@dataclass
class ProxyConfig:
    """Proxy configuration for device connections."""
    proxy_type: str = "none"  # none, http, socks4, socks5
    proxy_host: str | None = None
    proxy_port: int | None = None
    proxy_username: str | None = None
    proxy_password: str | None = None

    @property
    def is_enabled(self) -> bool:
        """Check if proxy is configured."""
        return self.proxy_type != "none" and self.proxy_host is not None

    def get_asyncssh_tunnel(self) -> tuple[str, int] | None:
        """Get tunnel config for asyncssh."""
        if not self.is_enabled:
            return None
        return (self.proxy_host, self.proxy_port or 1080)

    def get_socks_url(self) -> str | None:
        """Get SOCKS proxy URL."""
        if not self.is_enabled or self.proxy_type not in ("socks4", "socks5"):
            return None
        auth = ""
        if self.proxy_username:
            auth = f"{self.proxy_username}"
            if self.proxy_password:
                auth += f":{self.proxy_password}"
            auth += "@"
        return f"{self.proxy_type}://{auth}{self.proxy_host}:{self.proxy_port or 1080}"

    def get_http_proxy_url(self) -> str | None:
        """Get HTTP proxy URL."""
        if not self.is_enabled or self.proxy_type != "http":
            return None
        auth = ""
        if self.proxy_username:
            auth = f"{self.proxy_username}"
            if self.proxy_password:
                auth += f":{self.proxy_password}"
            auth += "@"
        return f"http://{auth}{self.proxy_host}:{self.proxy_port or 8080}"


@dataclass
class DeviceCredentials:
    """Credentials for device access."""
    hostname: str
    ip_address: str | None = None
    username: str | None = None
    password: str | None = None
    ssh_key: str | None = None
    ssh_key_passphrase: str | None = None
    enable_password: str | None = None
    port: int = 22
    timeout: int = 30
    device_type: str = "cisco_ios"

    # Proxy configuration
    proxy: ProxyConfig | None = None

    @property
    def device_id(self) -> str:
        """Return unique device identifier."""
        return self.ip_address or self.hostname

    @classmethod
    def with_proxy(
        cls,
        hostname: str,
        proxy_type: str = "socks5",
        proxy_host: str | None = None,
        proxy_port: int | None = None,
        proxy_username: str | None = None,
        proxy_password: str | None = None,
        **kwargs,
    ) -> "DeviceCredentials":
        """Create credentials with proxy configuration.

        Args:
            hostname: Device hostname
            proxy_type: Proxy type (http, socks4, socks5)
            proxy_host: Proxy server hostname/IP
            proxy_port: Proxy server port
            proxy_username: Proxy authentication username
            proxy_password: Proxy authentication password
            **kwargs: Additional DeviceCredentials fields

        Returns:
            DeviceCredentials with proxy configured
        """
        proxy = ProxyConfig(
            proxy_type=proxy_type,
            proxy_host=proxy_host,
            proxy_port=proxy_port,
            proxy_username=proxy_username,
            proxy_password=proxy_password,
        )
        return cls(hostname=hostname, proxy=proxy, **kwargs)


@dataclass
class CollectorResult:
    """Result from a routing collector operation."""
    success: bool = False
    device_id: str | None = None
    device_hostname: str | None = None
    timestamp: datetime | None = None
    duration_seconds: float = 0.0

    # Data collected
    routes: list[Route] = field(default_factory=list)
    neighbors: list[ProtocolNeighbor] = field(default_factory=list)
    redistributions: list[RedistributionPoint] = field(default_factory=list)
    vrfs: list[VRF] = field(default_factory=list)

    # Summaries
    bgp_summary: BGPSummary | None = None
    ospf_summary: OSPFSummary | None = None
    isis_summary: ISISSummary | None = None
    eigrp_summary: EIGRPSummary | None = None

    # Raw outputs (for debugging)
    raw_outputs: dict[str, str] = field(default_factory=dict)

    # Errors
    error_message: str | None = None

    def to_snapshot(self) -> RoutingSnapshot:
        """Convert result to a RoutingSnapshot for database storage."""
        return RoutingSnapshot(
            device_id=self.device_id,
            device_hostname=self.device_hostname,
            timestamp=self.timestamp or datetime.now(),
            snapshot_type="collector",
            route_count=len(self.routes),
            neighbor_count=len(self.neighbors),
            routes=self.routes,
            neighbors=self.neighbors,
            redistributions=self.redistributions,
            vrfs=self.vrfs,
        )


class RoutingCollector(ABC):
    """Abstract base class for routing protocol collectors.

    Handles device connectivity and routing data retrieval.
    """

    # Parser class for this collector
    PARSER_CLASS: type[OutputParser] | None = None

    def __init__(self, credentials: DeviceCredentials):
        """Initialize the collector.

        Args:
            credentials: Device credentials
        """
        self.credentials = credentials
        self._connection: Any = None
        self._parser: OutputParser | None = None

        if self.PARSER_CLASS:
            self._parser = self.PARSER_CLASS()

    @property
    def hostname(self) -> str:
        """Get device hostname."""
        return self.credentials.hostname

    @property
    def device_id(self) -> str:
        """Get device identifier."""
        return self.credentials.device_id

    @abstractmethod
    async def connect(self) -> bool:
        """Establish connection to the device.

        Returns:
            True if connection successful
        """
        pass

    @abstractmethod
    async def disconnect(self) -> None:
        """Close connection to the device."""
        pass

    @abstractmethod
    async def run_command(self, command: str) -> str:
        """Execute a command on the device.

        Args:
            command: Command to execute

        Returns:
            Command output
        """
        pass

    async def run_commands(self, commands: list[str]) -> dict[str, str]:
        """Execute multiple commands and return outputs.

        Args:
            commands: List of commands to execute

        Returns:
            Dictionary mapping commands to outputs
        """
        results = {}
        for command in commands:
            try:
                output = await self.run_command(command)
                results[command] = output
            except Exception as e:
                logger.error(f"Command failed: {command}: {e}")
                results[command] = f"ERROR: {e}"
        return results

    # ==========================================================================
    # Route Table Collection
    # ==========================================================================

    async def get_route_table(self, vrf: str = "default") -> list[Route]:
        """Get the full route table.

        Args:
            vrf: VRF name (default for global table)

        Returns:
            List of routes
        """
        command = self._get_route_table_command(vrf)
        output = await self.run_command(command)

        if self._parser:
            return self._parser.parse_route_table(output, vrf)
        return []

    def _get_route_table_command(self, vrf: str = "default") -> str:
        """Get the command for route table. Override in subclass."""
        if vrf == "default":
            return "show ip route"
        return f"show ip route vrf {vrf}"

    # ==========================================================================
    # BGP Collection
    # ==========================================================================

    async def get_bgp_summary(self) -> BGPSummary | None:
        """Get BGP summary information."""
        command = self._get_bgp_summary_command()
        output = await self.run_command(command)

        if self._parser:
            return self._parser.parse_bgp_summary(output)
        return None

    async def get_bgp_neighbors(self, detailed: bool = True) -> list[ProtocolNeighbor]:
        """Get BGP neighbors.

        Args:
            detailed: If True, get detailed neighbor info

        Returns:
            List of BGP neighbors
        """
        command = self._get_bgp_neighbors_command(detailed)
        output = await self.run_command(command)

        if self._parser:
            return self._parser.parse_bgp_neighbors(output)
        return []

    async def get_bgp_routes(
        self,
        prefix: str | None = None,
        neighbor: str | None = None,
        advertised: bool = False,
        received: bool = False,
    ) -> list[Route]:
        """Get BGP routes.

        Args:
            prefix: Filter by prefix
            neighbor: Filter by neighbor
            advertised: Get routes advertised to neighbor
            received: Get routes received from neighbor

        Returns:
            List of BGP routes
        """
        command = self._get_bgp_routes_command(prefix, neighbor, advertised, received)
        output = await self.run_command(command)

        if self._parser:
            return self._parser.parse_bgp_routes(output)
        return []

    def _get_bgp_summary_command(self) -> str:
        """Get BGP summary command. Override in subclass."""
        return "show ip bgp summary"

    def _get_bgp_neighbors_command(self, detailed: bool = True) -> str:
        """Get BGP neighbors command. Override in subclass."""
        if detailed:
            return "show ip bgp neighbors"
        return "show ip bgp summary"

    def _get_bgp_routes_command(
        self,
        prefix: str | None,
        neighbor: str | None,
        advertised: bool,
        received: bool,
    ) -> str:
        """Get BGP routes command. Override in subclass."""
        if neighbor and advertised:
            return f"show ip bgp neighbors {neighbor} advertised-routes"
        if neighbor and received:
            return f"show ip bgp neighbors {neighbor} received-routes"
        if prefix:
            return f"show ip bgp {prefix}"
        return "show ip bgp"

    # ==========================================================================
    # OSPF Collection
    # ==========================================================================

    async def get_ospf_summary(self) -> OSPFSummary | None:
        """Get OSPF summary information."""
        command = self._get_ospf_summary_command()
        output = await self.run_command(command)

        if self._parser:
            return self._parser.parse_ospf_summary(output)
        return None

    async def get_ospf_neighbors(self, detailed: bool = True) -> list[ProtocolNeighbor]:
        """Get OSPF neighbors."""
        command = self._get_ospf_neighbors_command(detailed)
        output = await self.run_command(command)

        if self._parser:
            return self._parser.parse_ospf_neighbors(output)
        return []

    async def get_ospf_routes(self) -> list[Route]:
        """Get OSPF routes."""
        command = self._get_ospf_routes_command()
        output = await self.run_command(command)

        if self._parser:
            return self._parser.parse_ospf_routes(output)
        return []

    async def get_ospf_database(self, area: str | None = None) -> dict[str, Any]:
        """Get OSPF LSDB summary."""
        command = self._get_ospf_database_command(area)
        output = await self.run_command(command)

        if self._parser:
            return self._parser.parse_ospf_database(output)
        return {"raw": output}

    def _get_ospf_summary_command(self) -> str:
        return "show ip ospf"

    def _get_ospf_neighbors_command(self, detailed: bool = True) -> str:
        if detailed:
            return "show ip ospf neighbor detail"
        return "show ip ospf neighbor"

    def _get_ospf_routes_command(self) -> str:
        return "show ip route ospf"

    def _get_ospf_database_command(self, area: str | None = None) -> str:
        if area:
            return f"show ip ospf database | include Area {area}"
        return "show ip ospf database"

    # ==========================================================================
    # IS-IS Collection
    # ==========================================================================

    async def get_isis_summary(self) -> ISISSummary | None:
        """Get IS-IS summary information."""
        command = self._get_isis_summary_command()
        output = await self.run_command(command)

        if self._parser:
            return self._parser.parse_isis_summary(output)
        return None

    async def get_isis_adjacencies(self) -> list[ProtocolNeighbor]:
        """Get IS-IS adjacencies."""
        command = self._get_isis_adjacencies_command()
        output = await self.run_command(command)

        if self._parser:
            return self._parser.parse_isis_adjacencies(output)
        return []

    async def get_isis_routes(self) -> list[Route]:
        """Get IS-IS routes."""
        command = self._get_isis_routes_command()
        output = await self.run_command(command)

        if self._parser:
            return self._parser.parse_isis_routes(output)
        return []

    def _get_isis_summary_command(self) -> str:
        return "show isis"

    def _get_isis_adjacencies_command(self) -> str:
        return "show isis neighbors detail"

    def _get_isis_routes_command(self) -> str:
        return "show ip route isis"

    # ==========================================================================
    # EIGRP Collection
    # ==========================================================================

    async def get_eigrp_summary(self) -> EIGRPSummary | None:
        """Get EIGRP summary information."""
        command = self._get_eigrp_summary_command()
        output = await self.run_command(command)

        if self._parser:
            return self._parser.parse_eigrp_summary(output)
        return None

    async def get_eigrp_neighbors(self) -> list[ProtocolNeighbor]:
        """Get EIGRP neighbors."""
        command = self._get_eigrp_neighbors_command()
        output = await self.run_command(command)

        if self._parser:
            return self._parser.parse_eigrp_neighbors(output)
        return []

    async def get_eigrp_topology(self) -> list[Route]:
        """Get EIGRP topology table."""
        command = self._get_eigrp_topology_command()
        output = await self.run_command(command)

        if self._parser:
            return self._parser.parse_eigrp_topology(output)
        return []

    def _get_eigrp_summary_command(self) -> str:
        return "show ip eigrp"

    def _get_eigrp_neighbors_command(self) -> str:
        return "show ip eigrp neighbors"

    def _get_eigrp_topology_command(self) -> str:
        return "show ip eigrp topology"

    # ==========================================================================
    # RIP Collection
    # ==========================================================================

    async def get_rip_routes(self) -> list[Route]:
        """Get RIP routes."""
        command = self._get_rip_routes_command()
        output = await self.run_command(command)

        if self._parser:
            return self._parser.parse_rip_routes(output)
        return []

    def _get_rip_routes_command(self) -> str:
        return "show ip rip database"

    # ==========================================================================
    # VRF Collection
    # ==========================================================================

    async def get_vrfs(self) -> list[VRF]:
        """Get VRF information."""
        command = self._get_vrfs_command()
        output = await self.run_command(command)

        if self._parser:
            return self._parser.parse_vrfs(output)
        return []

    def _get_vrfs_command(self) -> str:
        return "show vrf"

    # ==========================================================================
    # Redistribution Collection
    # ==========================================================================

    async def get_redistribution(self) -> list[RedistributionPoint]:
        """Get redistribution configuration."""
        command = self._get_redistribution_command()
        output = await self.run_command(command)

        if self._parser:
            return self._parser.parse_redistribution(output)
        return []

    def _get_redistribution_command(self) -> str:
        return "show running-config | section router"

    # ==========================================================================
    # Full Collection
    # ==========================================================================

    async def collect_all(
        self,
        protocols: list[RoutingProtocol] | None = None,
        include_routes: bool = True,
        include_neighbors: bool = True,
        include_redistribution: bool = True,
    ) -> CollectorResult:
        """Collect all routing information from the device.

        Args:
            protocols: Protocols to collect (None = all detected)
            include_routes: Include route tables
            include_neighbors: Include neighbor information
            include_redistribution: Include redistribution config

        Returns:
            CollectorResult with all collected data
        """
        result = CollectorResult(
            device_id=self.device_id,
            device_hostname=self.hostname,
            timestamp=datetime.now(),
        )

        start_time = datetime.now()

        try:
            # Connect
            if not await self.connect():
                result.error_message = "Failed to connect to device"
                return result

            # Get VRFs first
            result.vrfs = await self.get_vrfs()

            # Get route table
            if include_routes:
                result.routes = await self.get_route_table()

            # Detect and collect protocols
            detected_protocols = protocols or self._detect_protocols(result.routes)

            for protocol in detected_protocols:
                try:
                    if protocol == RoutingProtocol.BGP:
                        result.bgp_summary = await self.get_bgp_summary()
                        if include_neighbors:
                            result.neighbors.extend(await self.get_bgp_neighbors())
                        if include_routes:
                            bgp_routes = await self.get_bgp_routes()
                            result.routes.extend(bgp_routes)

                    elif protocol == RoutingProtocol.OSPF:
                        result.ospf_summary = await self.get_ospf_summary()
                        if include_neighbors:
                            result.neighbors.extend(await self.get_ospf_neighbors())

                    elif protocol == RoutingProtocol.ISIS:
                        result.isis_summary = await self.get_isis_summary()
                        if include_neighbors:
                            result.neighbors.extend(await self.get_isis_adjacencies())

                    elif protocol == RoutingProtocol.EIGRP:
                        result.eigrp_summary = await self.get_eigrp_summary()
                        if include_neighbors:
                            result.neighbors.extend(await self.get_eigrp_neighbors())

                except Exception as e:
                    logger.error(f"Failed to collect {protocol.value}: {e}")

            # Get redistribution
            if include_redistribution:
                result.redistributions = await self.get_redistribution()

            result.success = True

        except Exception as e:
            result.error_message = str(e)
            logger.exception(f"Collection failed for {self.hostname}")

        finally:
            await self.disconnect()
            result.duration_seconds = (datetime.now() - start_time).total_seconds()

        return result

    def _detect_protocols(self, routes: list[Route]) -> list[RoutingProtocol]:
        """Detect active protocols from route table.

        Args:
            routes: List of routes

        Returns:
            List of detected protocols
        """
        protocols = set()
        for route in routes:
            if route.protocol in (
                RoutingProtocol.BGP,
                RoutingProtocol.OSPF,
                RoutingProtocol.ISIS,
                RoutingProtocol.EIGRP,
                RoutingProtocol.RIP,
            ):
                protocols.add(route.protocol)
        return list(protocols)
