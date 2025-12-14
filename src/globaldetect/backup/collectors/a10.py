"""
A10 Thunder ADC configuration collector.

Provides backup, restore, and DNS/GSLB troubleshooting for A10 Thunder devices
using the aXAPI REST API.

Copyright (c) 2025 DNS Science.io, an After Dark Systems, LLC company.
All rights reserved.
"""

import asyncio
import base64
import json
import logging
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any

from globaldetect.backup.base import APICollector
from globaldetect.backup.models import (
    DeviceVendor,
    BackupType,
)

logger = logging.getLogger(__name__)


@dataclass
class A10GSLBSite:
    """A10 GSLB site information."""
    name: str
    ip_address: str = ""
    enabled: bool = True
    weight: int = 1
    status: str = "unknown"


@dataclass
class A10GSLBZone:
    """A10 GSLB zone information."""
    name: str
    policy: str = ""
    enabled: bool = True
    services: list[dict] = field(default_factory=list)
    dns_records: list[dict] = field(default_factory=list)


@dataclass
class A10GSLBService:
    """A10 GSLB service (similar to F5 Wide IP)."""
    name: str
    zone: str = ""
    service_port: int = 0
    policy: str = ""
    enabled: bool = True
    service_groups: list[str] = field(default_factory=list)
    status: str = "unknown"


@dataclass
class A10VirtualServer:
    """A10 Virtual Server (SLB VIP)."""
    name: str
    ip_address: str = ""
    port: int = 0
    protocol: str = "tcp"
    service_group: str | None = None
    enabled: bool = True
    status: str = "unknown"
    current_connections: int = 0


@dataclass
class A10BGPNeighbor:
    """BGP neighbor information from A10."""
    neighbor_address: str
    remote_as: int
    local_as: int
    state: str = "unknown"
    uptime: str = ""
    routes_received: int = 0
    routes_advertised: int = 0


@dataclass
class A10DNSQueryResult:
    """DNS query result from GSLB."""
    query_name: str
    query_type: str
    response_code: str
    answers: list[dict] = field(default_factory=list)
    response_time_ms: float = 0.0


class A10ThunderCollector(APICollector):
    """Collector for A10 Thunder devices using aXAPI REST API.

    Supports:
    - Full system backup/restore
    - GSLB/DNS configuration and troubleshooting
    - SLB virtual server configuration
    - BGP routing status
    - SSL certificate management
    """

    VENDOR = DeviceVendor.A10_THUNDER
    SUPPORTED_BACKUP_TYPES = [
        BackupType.FULL,     # Full system backup
        BackupType.DNS,      # GSLB configuration
        BackupType.SSL,      # Certificates
        BackupType.NETWORK,  # Routing/BGP
    ]
    DEFAULT_PORT = 443

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._auth_token: str | None = None
        self._base_url: str = ""
        self._api_version: str = "v3"

    async def connect(self) -> bool:
        """Connect to A10 Thunder aXAPI."""
        try:
            import aiohttp

            host = self.credential.device_ip or self.credential.device_hostname
            self._base_url = f"https://{host}/axapi/{self._api_version}"

            connector = aiohttp.TCPConnector(ssl=False)  # Allow self-signed certs
            self._session = aiohttp.ClientSession(connector=connector)

            # Authenticate and get token
            return await self._authenticate()

        except ImportError:
            logger.error("aiohttp not installed. Run: pip install aiohttp")
            return False
        except Exception as e:
            logger.error(f"A10 API connection failed: {e}")
            return False

    async def _authenticate(self) -> bool:
        """Authenticate to A10 aXAPI and get session token.

        Returns:
            True if authentication successful
        """
        try:
            auth_data = {
                "credentials": {
                    "username": self.credential.username,
                    "password": self.credential.password,
                }
            }

            async with self._session.post(
                f"{self._base_url}/auth",
                json=auth_data,
                ssl=False,
            ) as resp:
                if resp.status == 200:
                    data = await resp.json()
                    self._auth_token = data.get("authresponse", {}).get("signature")
                    if self._auth_token:
                        logger.info("A10 Thunder authentication successful")
                        return True

            logger.error("A10 authentication failed")
            return False

        except Exception as e:
            logger.error(f"A10 authentication error: {e}")
            return False

    async def disconnect(self) -> None:
        """Close A10 API session and logout."""
        if self._session and self._auth_token:
            try:
                async with self._session.post(
                    f"{self._base_url}/logoff",
                    headers=self._get_auth_headers(),
                    ssl=False,
                ) as resp:
                    pass
            except Exception:
                pass

        if self._session:
            await self._session.close()
            self._session = None

        self._auth_token = None

    def _get_auth_headers(self) -> dict:
        """Get authentication headers for API calls."""
        headers = {"Content-Type": "application/json"}
        if self._auth_token:
            headers["Authorization"] = f"A10 {self._auth_token}"
        return headers

    async def _api_get(self, endpoint: str, params: dict | None = None) -> dict:
        """Make authenticated GET request.

        Args:
            endpoint: API endpoint
            params: Query parameters

        Returns:
            JSON response
        """
        if not self._session:
            raise RuntimeError("Not connected")

        url = f"{self._base_url}/{endpoint}"

        async with self._session.get(
            url,
            params=params,
            headers=self._get_auth_headers(),
            ssl=False,
        ) as resp:
            if resp.status == 200:
                return await resp.json()
            else:
                logger.warning(f"API GET {endpoint} returned {resp.status}")
                return {}

    async def _api_post(self, endpoint: str, data: dict | None = None) -> dict:
        """Make authenticated POST request.

        Args:
            endpoint: API endpoint
            data: POST data

        Returns:
            JSON response
        """
        if not self._session:
            raise RuntimeError("Not connected")

        url = f"{self._base_url}/{endpoint}"

        async with self._session.post(
            url,
            json=data,
            headers=self._get_auth_headers(),
            ssl=False,
        ) as resp:
            if resp.status in (200, 201):
                return await resp.json()
            else:
                logger.warning(f"API POST {endpoint} returned {resp.status}")
                return {}

    async def get_config(self, backup_type: BackupType) -> str | None:
        """Retrieve configuration from A10 Thunder.

        Args:
            backup_type: Type of configuration to retrieve

        Returns:
            Configuration content
        """
        if backup_type == BackupType.FULL:
            return await self._get_full_backup()
        elif backup_type == BackupType.DNS:
            return await self._get_gslb_config()
        elif backup_type == BackupType.SSL:
            return await self._get_ssl_config()
        elif backup_type == BackupType.NETWORK:
            return await self._get_network_config()
        else:
            logger.warning(f"Unsupported backup type: {backup_type}")
            return None

    async def _get_full_backup(self) -> str | None:
        """Create and retrieve full system backup.

        Returns:
            Base64-encoded backup content
        """
        try:
            backup_name = f"backup_{datetime.now().strftime('%Y%m%d_%H%M%S')}"

            # Create backup
            backup_data = {
                "backup": {
                    "name": backup_name,
                    "use-mgmt-port": 1,
                }
            }

            result = await self._api_post("backup/system", backup_data)
            if not result:
                logger.error("Failed to create backup")
                return None

            # Wait for backup creation
            await asyncio.sleep(5)

            # Download backup
            async with self._session.get(
                f"{self._base_url}/file/backup/{backup_name}",
                headers=self._get_auth_headers(),
                ssl=False,
            ) as resp:
                if resp.status == 200:
                    content = await resp.read()
                    return base64.b64encode(content).decode("utf-8")

            logger.error("Failed to download backup")
            return None

        except Exception as e:
            logger.error(f"Full backup failed: {e}")
            return None

    async def _get_gslb_config(self) -> str | None:
        """Get GSLB configuration.

        Returns:
            JSON string of GSLB configuration
        """
        try:
            config = {
                "zones": [],
                "sites": [],
                "services": [],
                "policies": [],
                "dns_servers": [],
            }

            # Get GSLB zones
            data = await self._api_get("gslb/zone")
            config["zones"] = data.get("zone-list", [])

            # Get GSLB sites
            data = await self._api_get("gslb/site")
            config["sites"] = data.get("site-list", [])

            # Get GSLB services
            data = await self._api_get("gslb/service-ip")
            config["services"] = data.get("service-ip-list", [])

            # Get GSLB policies
            data = await self._api_get("gslb/policy")
            config["policies"] = data.get("policy-list", [])

            return json.dumps(config, indent=2)

        except Exception as e:
            logger.error(f"GSLB config retrieval failed: {e}")
            return None

    async def _get_ssl_config(self) -> str | None:
        """Get SSL/TLS certificate configuration.

        Returns:
            JSON string of SSL configuration
        """
        try:
            config = {
                "certificates": [],
                "keys": [],
                "templates": [],
            }

            # Get SSL certificates
            data = await self._api_get("file/ssl-cert")
            config["certificates"] = data.get("ssl-cert-list", [])

            # Get SSL templates
            data = await self._api_get("slb/template/client-ssl")
            config["templates"] = data.get("client-ssl-list", [])

            return json.dumps(config, indent=2)

        except Exception as e:
            logger.error(f"SSL config retrieval failed: {e}")
            return None

    async def _get_network_config(self) -> str | None:
        """Get network/routing configuration.

        Returns:
            JSON string of network configuration
        """
        try:
            config = {
                "interfaces": [],
                "vlans": [],
                "routes": [],
                "bgp": None,
            }

            # Get interfaces
            data = await self._api_get("interface/ethernet")
            config["interfaces"] = data.get("ethernet-list", [])

            # Get VLANs
            data = await self._api_get("network/vlan")
            config["vlans"] = data.get("vlan-list", [])

            # Get static routes
            data = await self._api_get("ip/route/rib")
            config["routes"] = data.get("rib-list", [])

            # Get BGP config
            config["bgp"] = await self._get_bgp_config()

            return json.dumps(config, indent=2)

        except Exception as e:
            logger.error(f"Network config retrieval failed: {e}")
            return None

    # =========================================================================
    # GSLB/DNS Troubleshooting Methods
    # =========================================================================

    async def get_gslb_zones(self) -> list[A10GSLBZone]:
        """Get all GSLB zones.

        Returns:
            List of GSLB zone objects
        """
        zones = []

        try:
            data = await self._api_get("gslb/zone")
            for item in data.get("zone-list", []):
                zone = A10GSLBZone(
                    name=item.get("name", ""),
                    policy=item.get("policy", ""),
                    enabled=item.get("disable") != 1,
                    services=item.get("service-list", []),
                    dns_records=item.get("dns-soa-record", {}),
                )
                zones.append(zone)

        except Exception as e:
            logger.error(f"Failed to get GSLB zones: {e}")

        return zones

    async def get_gslb_sites(self) -> list[A10GSLBSite]:
        """Get all GSLB sites.

        Returns:
            List of GSLB site objects
        """
        sites = []

        try:
            data = await self._api_get("gslb/site")
            for item in data.get("site-list", []):
                site = A10GSLBSite(
                    name=item.get("site-name", ""),
                    ip_address=item.get("ip-addr", ""),
                    enabled=item.get("disable") != 1,
                    weight=item.get("weight", 1),
                )
                sites.append(site)

        except Exception as e:
            logger.error(f"Failed to get GSLB sites: {e}")

        return sites

    async def get_gslb_service_status(self, zone_name: str, service_name: str) -> dict:
        """Get status of a GSLB service.

        Args:
            zone_name: Name of the zone
            service_name: Name of the service

        Returns:
            Service status dictionary
        """
        try:
            data = await self._api_get(f"gslb/zone/{zone_name}/service/{service_name}/stats")
            return data
        except Exception as e:
            logger.error(f"Failed to get GSLB service status: {e}")
        return {}

    async def get_gslb_statistics(self) -> dict:
        """Get GSLB statistics.

        Returns:
            Dictionary of GSLB statistics
        """
        stats = {
            "total_queries": 0,
            "total_responses": 0,
            "cache_hits": 0,
            "cache_misses": 0,
        }

        try:
            data = await self._api_get("gslb/stats")
            gslb_stats = data.get("gslb", {}).get("stats", {})
            stats["total_queries"] = gslb_stats.get("total-queries", 0)
            stats["total_responses"] = gslb_stats.get("total-responses", 0)
            stats["cache_hits"] = gslb_stats.get("cache-hits", 0)
            stats["cache_misses"] = gslb_stats.get("cache-misses", 0)

        except Exception as e:
            logger.error(f"Failed to get GSLB stats: {e}")

        return stats

    async def test_gslb_resolution(self, hostname: str) -> A10DNSQueryResult:
        """Test GSLB DNS resolution for a hostname.

        Args:
            hostname: Hostname to resolve

        Returns:
            DNS query result
        """
        result = A10DNSQueryResult(
            query_name=hostname,
            query_type="A",
            response_code="UNKNOWN",
        )

        try:
            # Use CLI command via API
            data = await self._api_post(
                "clideploy",
                {"cli-command-list": [{"command": f"show gslb zone {hostname}"}]}
            )
            output = data.get("response", {}).get("cli-command-list", [{}])[0].get("output", "")

            if "not found" in output.lower():
                result.response_code = "NXDOMAIN"
            else:
                result.response_code = "NOERROR"
                # Parse output for answers (format varies)

        except Exception as e:
            logger.error(f"GSLB resolution test failed: {e}")
            result.response_code = "ERROR"

        return result

    # =========================================================================
    # BGP Methods
    # =========================================================================

    async def _get_bgp_config(self) -> dict | None:
        """Get BGP configuration.

        Returns:
            BGP configuration dictionary
        """
        try:
            data = await self._api_get("router/bgp")
            return data.get("bgp", {})
        except Exception as e:
            logger.debug(f"BGP config not available: {e}")
        return None

    async def get_bgp_neighbors(self) -> list[A10BGPNeighbor]:
        """Get BGP neighbor status.

        Returns:
            List of BGP neighbor objects
        """
        neighbors = []

        try:
            data = await self._api_get("router/bgp/neighbor")
            for item in data.get("neighbor-list", []):
                neighbor = A10BGPNeighbor(
                    neighbor_address=item.get("peer-address", ""),
                    remote_as=item.get("remote-as", 0),
                    local_as=item.get("local-as", 0),
                    state=item.get("state", "unknown"),
                )
                neighbors.append(neighbor)

        except Exception as e:
            logger.debug(f"BGP neighbors not available: {e}")

        return neighbors

    async def get_bgp_routes(self) -> list[dict]:
        """Get BGP routes.

        Returns:
            List of BGP route dictionaries
        """
        routes = []

        try:
            data = await self._api_get("router/bgp/network/ip-cidr")
            routes = data.get("ip-cidr-list", [])
        except Exception as e:
            logger.debug(f"BGP routes not available: {e}")

        return routes

    # =========================================================================
    # SLB Methods
    # =========================================================================

    async def get_virtual_servers(self) -> list[A10VirtualServer]:
        """Get all SLB virtual servers.

        Returns:
            List of virtual server objects
        """
        virtual_servers = []

        try:
            data = await self._api_get("slb/virtual-server")
            for item in data.get("virtual-server-list", []):
                vs = A10VirtualServer(
                    name=item.get("name", ""),
                    ip_address=item.get("ip-address", ""),
                    enabled=item.get("enable-disable-action", "enable") == "enable",
                )

                # Get port info from port list
                for port in item.get("port-list", []):
                    vs.port = port.get("port-number", 0)
                    vs.protocol = port.get("protocol", "tcp")
                    vs.service_group = port.get("service-group")
                    break  # Just get first port for now

                virtual_servers.append(vs)

        except Exception as e:
            logger.error(f"Failed to get virtual servers: {e}")

        return virtual_servers

    async def get_service_group_status(self, group_name: str) -> dict:
        """Get SLB service group status.

        Args:
            group_name: Name of the service group

        Returns:
            Service group status dictionary
        """
        try:
            data = await self._api_get(f"slb/service-group/{group_name}/stats")
            return data
        except Exception as e:
            logger.error(f"Failed to get service group status: {e}")
        return {}

    async def get_server_status(self, server_name: str) -> dict:
        """Get SLB server status.

        Args:
            server_name: Name of the server

        Returns:
            Server status dictionary
        """
        try:
            data = await self._api_get(f"slb/server/{server_name}/stats")
            return data
        except Exception as e:
            logger.error(f"Failed to get server status: {e}")
        return {}

    # =========================================================================
    # Restore Methods
    # =========================================================================

    async def restore_backup(self, backup_content: str, backup_name: str | None = None) -> bool:
        """Restore system backup to A10 device.

        Args:
            backup_content: Base64-encoded backup content
            backup_name: Name for the backup file

        Returns:
            True if restore successful
        """
        try:
            if not backup_name:
                backup_name = f"restore_{datetime.now().strftime('%Y%m%d_%H%M%S')}"

            # Decode the content
            backup_bytes = base64.b64decode(backup_content)

            # Upload backup file
            async with self._session.post(
                f"{self._base_url}/file/backup/{backup_name}",
                data=backup_bytes,
                headers={
                    **self._get_auth_headers(),
                    "Content-Type": "application/octet-stream",
                },
                ssl=False,
            ) as resp:
                if resp.status not in (200, 201):
                    logger.error(f"Failed to upload backup: {resp.status}")
                    return False

            # Restore backup
            restore_data = {
                "restore": {
                    "name": backup_name,
                }
            }

            result = await self._api_post("backup/restore", restore_data)
            if result:
                logger.info(f"Backup restore initiated: {backup_name}")
                return True

            logger.error("Failed to initiate backup restore")
            return False

        except Exception as e:
            logger.error(f"Backup restore failed: {e}")
            return False

    async def restore_gslb_config(self, config_json: str) -> bool:
        """Restore GSLB configuration from JSON.

        Args:
            config_json: JSON string of GSLB configuration

        Returns:
            True if restore successful
        """
        try:
            config = json.loads(config_json)

            # Restore sites first
            for site in config.get("sites", []):
                await self._api_post("gslb/site", {"site": site})

            # Restore policies
            for policy in config.get("policies", []):
                await self._api_post("gslb/policy", {"policy": policy})

            # Restore zones
            for zone in config.get("zones", []):
                await self._api_post("gslb/zone", {"zone": zone})

            logger.info("GSLB configuration restored")
            return True

        except Exception as e:
            logger.error(f"GSLB restore failed: {e}")
            return False

    # =========================================================================
    # Health Check Methods
    # =========================================================================

    async def get_system_info(self) -> dict:
        """Get A10 system information.

        Returns:
            System information dictionary
        """
        try:
            data = await self._api_get("version/oper")
            return data.get("version", {}).get("oper", {})
        except Exception as e:
            logger.error(f"Failed to get system info: {e}")
        return {}

    async def get_system_health(self) -> dict:
        """Get system health status.

        Returns:
            Health status dictionary
        """
        health = {
            "cpu_usage": 0,
            "memory_usage": 0,
            "disk_usage": 0,
            "temperature": 0,
        }

        try:
            # Get CPU stats
            data = await self._api_get("system/cpu/stats")
            cpu_stats = data.get("cpu", {}).get("stats", {})
            health["cpu_usage"] = cpu_stats.get("cpu-usage", 0)

            # Get memory stats
            data = await self._api_get("system/memory/oper")
            mem_oper = data.get("memory", {}).get("oper", {})
            health["memory_usage"] = mem_oper.get("memory-usage", 0)

        except Exception as e:
            logger.error(f"Failed to get system health: {e}")

        return health
