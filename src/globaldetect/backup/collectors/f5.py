"""
F5 BIG-IP configuration collector.

Provides backup, restore, and DNS/GTM troubleshooting for F5 BIG-IP devices
using the iControl REST API.

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
class F5GTMPool:
    """GTM/DNS pool information."""
    name: str
    partition: str = "Common"
    pool_type: str = "A"  # A, AAAA, CNAME, MX, etc.
    load_balancing_mode: str = "round-robin"
    enabled: bool = True
    members: list[dict] = field(default_factory=list)
    monitors: list[str] = field(default_factory=list)
    fallback_ip: str | None = None
    status: str = "unknown"
    availability: str = "unknown"


@dataclass
class F5GTMWideIP:
    """GTM/DNS Wide IP information."""
    name: str
    partition: str = "Common"
    pool_lb_mode: str = "round-robin"
    enabled: bool = True
    pools: list[str] = field(default_factory=list)
    aliases: list[str] = field(default_factory=list)
    status: str = "unknown"
    availability: str = "unknown"


@dataclass
class F5VirtualServer:
    """LTM Virtual Server information."""
    name: str
    partition: str = "Common"
    destination: str = ""
    port: int = 0
    pool: str | None = None
    profiles: list[str] = field(default_factory=list)
    rules: list[str] = field(default_factory=list)
    enabled: bool = True
    status: str = "unknown"


@dataclass
class F5BGPNeighbor:
    """BGP neighbor information from F5."""
    neighbor_address: str
    remote_as: int
    local_as: int
    state: str = "unknown"
    uptime: str = ""
    prefixes_received: int = 0
    prefixes_advertised: int = 0


@dataclass
class F5DNSQueryResult:
    """DNS query result from GTM."""
    query_name: str
    query_type: str
    response_code: str
    answers: list[dict] = field(default_factory=list)
    response_time_ms: float = 0.0
    server_used: str = ""


class F5BigIPCollector(APICollector):
    """Collector for F5 BIG-IP devices using iControl REST API.

    Supports:
    - Full UCS backup/restore
    - GTM/DNS configuration and troubleshooting
    - LTM virtual server configuration
    - BGP routing status
    - SSL certificate management
    """

    VENDOR = DeviceVendor.F5_BIGIP
    SUPPORTED_BACKUP_TYPES = [
        BackupType.FULL,  # UCS archive
        BackupType.DNS,   # GTM configuration
        BackupType.SSL,   # Certificates
        BackupType.NETWORK,  # Routing/BGP
    ]
    DEFAULT_PORT = 443

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._auth_token: str | None = None
        self._base_url: str = ""

    async def connect(self) -> bool:
        """Connect to F5 BIG-IP iControl REST API."""
        try:
            import aiohttp

            host = self.credential.device_ip or self.credential.device_hostname
            self._base_url = f"https://{host}:{self.port}/mgmt"

            # Create session with basic auth
            auth = aiohttp.BasicAuth(
                self.credential.username,
                self.credential.password,
            )

            connector = aiohttp.TCPConnector(ssl=False)  # Allow self-signed certs
            self._session = aiohttp.ClientSession(
                auth=auth,
                connector=connector,
            )

            # Verify connectivity
            return await self._verify_api()

        except ImportError:
            logger.error("aiohttp not installed. Run: pip install aiohttp")
            return False
        except Exception as e:
            logger.error(f"F5 API connection failed: {e}")
            return False

    async def _verify_api(self) -> bool:
        """Verify API connectivity by checking system info."""
        try:
            async with self._session.get(
                f"{self._base_url}/tm/sys/version",
                ssl=False,
            ) as resp:
                if resp.status == 200:
                    data = await resp.json()
                    entries = data.get("entries", {})
                    for key, value in entries.items():
                        if "nestedStats" in value:
                            stats = value["nestedStats"]["entries"]
                            version = stats.get("Version", {}).get("description", "unknown")
                            product = stats.get("Product", {}).get("description", "unknown")
                            logger.info(f"Connected to F5 {product} version {version}")
                            return True
                return False
        except Exception as e:
            logger.error(f"F5 API verification failed: {e}")
            return False

    async def get_config(self, backup_type: BackupType) -> str | None:
        """Retrieve configuration from F5 BIG-IP.

        Args:
            backup_type: Type of configuration to retrieve

        Returns:
            Configuration content
        """
        if backup_type == BackupType.FULL:
            return await self._get_ucs_backup()
        elif backup_type == BackupType.DNS:
            return await self._get_gtm_config()
        elif backup_type == BackupType.SSL:
            return await self._get_ssl_config()
        elif backup_type == BackupType.NETWORK:
            return await self._get_network_config()
        else:
            logger.warning(f"Unsupported backup type: {backup_type}")
            return None

    async def _get_ucs_backup(self) -> str | None:
        """Create and retrieve UCS backup archive.

        Returns:
            Base64-encoded UCS archive content
        """
        try:
            # Create UCS archive
            ucs_name = f"backup_{datetime.now().strftime('%Y%m%d_%H%M%S')}.ucs"

            # Trigger UCS creation
            async with self._session.post(
                f"{self._base_url}/tm/sys/ucs",
                json={"command": "save", "name": ucs_name},
                ssl=False,
            ) as resp:
                if resp.status not in (200, 202):
                    logger.error(f"Failed to create UCS: {resp.status}")
                    return None

            # Wait for UCS creation
            await asyncio.sleep(5)

            # Download UCS file
            async with self._session.get(
                f"{self._base_url}/shared/file-transfer/ucs-downloads/{ucs_name}",
                ssl=False,
            ) as resp:
                if resp.status == 200:
                    content = await resp.read()
                    # Return base64 encoded for text storage
                    return base64.b64encode(content).decode("utf-8")

            logger.error("Failed to download UCS archive")
            return None

        except Exception as e:
            logger.error(f"UCS backup failed: {e}")
            return None

    async def _get_gtm_config(self) -> str | None:
        """Get GTM/DNS configuration.

        Returns:
            JSON string of GTM configuration
        """
        try:
            config = {
                "wide_ips": [],
                "pools": [],
                "datacenters": [],
                "servers": [],
                "listeners": [],
            }

            # Get Wide IPs
            async with self._session.get(
                f"{self._base_url}/tm/gtm/wideip/a",
                ssl=False,
            ) as resp:
                if resp.status == 200:
                    data = await resp.json()
                    config["wide_ips"].extend(data.get("items", []))

            # Get GTM Pools
            async with self._session.get(
                f"{self._base_url}/tm/gtm/pool/a",
                ssl=False,
            ) as resp:
                if resp.status == 200:
                    data = await resp.json()
                    config["pools"].extend(data.get("items", []))

            # Get Datacenters
            async with self._session.get(
                f"{self._base_url}/tm/gtm/datacenter",
                ssl=False,
            ) as resp:
                if resp.status == 200:
                    data = await resp.json()
                    config["datacenters"] = data.get("items", [])

            # Get GTM Servers
            async with self._session.get(
                f"{self._base_url}/tm/gtm/server",
                ssl=False,
            ) as resp:
                if resp.status == 200:
                    data = await resp.json()
                    config["servers"] = data.get("items", [])

            # Get Listeners
            async with self._session.get(
                f"{self._base_url}/tm/gtm/listener",
                ssl=False,
            ) as resp:
                if resp.status == 200:
                    data = await resp.json()
                    config["listeners"] = data.get("items", [])

            return json.dumps(config, indent=2)

        except Exception as e:
            logger.error(f"GTM config retrieval failed: {e}")
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
                "profiles": [],
            }

            # Get certificates
            async with self._session.get(
                f"{self._base_url}/tm/sys/file/ssl-cert",
                ssl=False,
            ) as resp:
                if resp.status == 200:
                    data = await resp.json()
                    config["certificates"] = data.get("items", [])

            # Get SSL profiles
            async with self._session.get(
                f"{self._base_url}/tm/ltm/profile/client-ssl",
                ssl=False,
            ) as resp:
                if resp.status == 200:
                    data = await resp.json()
                    config["profiles"] = data.get("items", [])

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
                "self_ips": [],
                "vlans": [],
                "routes": [],
                "route_domains": [],
                "bgp": None,
            }

            # Get Self IPs
            async with self._session.get(
                f"{self._base_url}/tm/net/self",
                ssl=False,
            ) as resp:
                if resp.status == 200:
                    data = await resp.json()
                    config["self_ips"] = data.get("items", [])

            # Get VLANs
            async with self._session.get(
                f"{self._base_url}/tm/net/vlan",
                ssl=False,
            ) as resp:
                if resp.status == 200:
                    data = await resp.json()
                    config["vlans"] = data.get("items", [])

            # Get Routes
            async with self._session.get(
                f"{self._base_url}/tm/net/route",
                ssl=False,
            ) as resp:
                if resp.status == 200:
                    data = await resp.json()
                    config["routes"] = data.get("items", [])

            # Get BGP config
            config["bgp"] = await self._get_bgp_config()

            return json.dumps(config, indent=2)

        except Exception as e:
            logger.error(f"Network config retrieval failed: {e}")
            return None

    # =========================================================================
    # GTM/DNS Troubleshooting Methods
    # =========================================================================

    async def get_gtm_wide_ips(self) -> list[F5GTMWideIP]:
        """Get all GTM Wide IPs with status.

        Returns:
            List of Wide IP objects
        """
        wide_ips = []

        try:
            # Get A record Wide IPs
            for record_type in ["a", "aaaa", "cname", "mx"]:
                async with self._session.get(
                    f"{self._base_url}/tm/gtm/wideip/{record_type}",
                    params={"expandSubcollections": "true"},
                    ssl=False,
                ) as resp:
                    if resp.status == 200:
                        data = await resp.json()
                        for item in data.get("items", []):
                            wide_ip = F5GTMWideIP(
                                name=item.get("name", ""),
                                partition=item.get("partition", "Common"),
                                pool_lb_mode=item.get("poolLbMode", "round-robin"),
                                enabled=item.get("enabled", True),
                                pools=[p.get("name") for p in item.get("pools", [])],
                                status=item.get("status", {}).get("availabilityState", "unknown"),
                            )
                            wide_ips.append(wide_ip)

        except Exception as e:
            logger.error(f"Failed to get Wide IPs: {e}")

        return wide_ips

    async def get_gtm_pools(self) -> list[F5GTMPool]:
        """Get all GTM pools with status.

        Returns:
            List of GTM pool objects
        """
        pools = []

        try:
            for record_type in ["a", "aaaa", "cname", "mx"]:
                async with self._session.get(
                    f"{self._base_url}/tm/gtm/pool/{record_type}",
                    params={"expandSubcollections": "true"},
                    ssl=False,
                ) as resp:
                    if resp.status == 200:
                        data = await resp.json()
                        for item in data.get("items", []):
                            pool = F5GTMPool(
                                name=item.get("name", ""),
                                partition=item.get("partition", "Common"),
                                pool_type=record_type.upper(),
                                load_balancing_mode=item.get("loadBalancingMode", "round-robin"),
                                enabled=item.get("enabled", True),
                                members=item.get("membersReference", {}).get("items", []),
                                fallback_ip=item.get("fallbackIp"),
                                status=item.get("status", {}).get("availabilityState", "unknown"),
                            )
                            pools.append(pool)

        except Exception as e:
            logger.error(f"Failed to get GTM pools: {e}")

        return pools

    async def get_gtm_pool_members_status(self, pool_name: str, pool_type: str = "a") -> list[dict]:
        """Get status of all members in a GTM pool.

        Args:
            pool_name: Name of the pool
            pool_type: Pool type (a, aaaa, cname, mx)

        Returns:
            List of member status dictionaries
        """
        try:
            async with self._session.get(
                f"{self._base_url}/tm/gtm/pool/{pool_type}/{pool_name}/members",
                ssl=False,
            ) as resp:
                if resp.status == 200:
                    data = await resp.json()
                    return data.get("items", [])
        except Exception as e:
            logger.error(f"Failed to get pool members: {e}")

        return []

    async def get_gtm_statistics(self) -> dict:
        """Get GTM statistics.

        Returns:
            Dictionary of GTM statistics
        """
        stats = {
            "wide_ip_requests": 0,
            "pool_selections": 0,
            "dns_queries": 0,
            "dns_responses": 0,
        }

        try:
            async with self._session.get(
                f"{self._base_url}/tm/gtm/global-settings/general/stats",
                ssl=False,
            ) as resp:
                if resp.status == 200:
                    data = await resp.json()
                    entries = data.get("entries", {})
                    for key, value in entries.items():
                        if "nestedStats" in value:
                            nested = value["nestedStats"]["entries"]
                            stats["dns_queries"] = nested.get("requestsTotal", {}).get("value", 0)
                            stats["dns_responses"] = nested.get("responsesTotal", {}).get("value", 0)

        except Exception as e:
            logger.error(f"Failed to get GTM stats: {e}")

        return stats

    async def test_gtm_resolution(self, hostname: str) -> F5DNSQueryResult:
        """Test GTM DNS resolution for a hostname.

        Args:
            hostname: Hostname to resolve

        Returns:
            DNS query result
        """
        result = F5DNSQueryResult(
            query_name=hostname,
            query_type="A",
            response_code="UNKNOWN",
        )

        try:
            # Use dig command via iControl REST
            async with self._session.post(
                f"{self._base_url}/tm/util/bash",
                json={"command": "run", "utilCmdArgs": f"-c 'dig @localhost {hostname} +short'"},
                ssl=False,
            ) as resp:
                if resp.status == 200:
                    data = await resp.json()
                    output = data.get("commandResult", "")
                    if output:
                        result.response_code = "NOERROR"
                        result.answers = [{"address": ip.strip()} for ip in output.strip().split("\n") if ip.strip()]
                    else:
                        result.response_code = "NXDOMAIN"

        except Exception as e:
            logger.error(f"GTM resolution test failed: {e}")
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
            async with self._session.get(
                f"{self._base_url}/tm/net/routing/bgp",
                ssl=False,
            ) as resp:
                if resp.status == 200:
                    data = await resp.json()
                    return data.get("items", [{}])[0] if data.get("items") else None
        except Exception as e:
            logger.debug(f"BGP config not available: {e}")
        return None

    async def get_bgp_neighbors(self) -> list[F5BGPNeighbor]:
        """Get BGP neighbor status.

        Returns:
            List of BGP neighbor objects
        """
        neighbors = []

        try:
            async with self._session.get(
                f"{self._base_url}/tm/net/routing/bgp/neighbor",
                ssl=False,
            ) as resp:
                if resp.status == 200:
                    data = await resp.json()
                    for item in data.get("items", []):
                        neighbor = F5BGPNeighbor(
                            neighbor_address=item.get("name", ""),
                            remote_as=item.get("remoteAs", 0),
                            local_as=item.get("localAs", 0),
                            state=item.get("state", "unknown"),
                        )
                        neighbors.append(neighbor)

        except Exception as e:
            logger.debug(f"BGP neighbors not available: {e}")

        return neighbors

    async def get_bgp_routes(self) -> list[dict]:
        """Get BGP routes from F5.

        Returns:
            List of BGP route dictionaries
        """
        routes = []

        try:
            # Use tmsh command via REST
            async with self._session.post(
                f"{self._base_url}/tm/util/bash",
                json={"command": "run", "utilCmdArgs": "-c 'tmsh show net routing bgp routes'"},
                ssl=False,
            ) as resp:
                if resp.status == 200:
                    data = await resp.json()
                    output = data.get("commandResult", "")
                    # Parse the output (format varies)
                    for line in output.split("\n"):
                        if "/" in line:  # Likely a route entry
                            routes.append({"raw": line.strip()})

        except Exception as e:
            logger.debug(f"BGP routes not available: {e}")

        return routes

    # =========================================================================
    # LTM Methods
    # =========================================================================

    async def get_virtual_servers(self) -> list[F5VirtualServer]:
        """Get all LTM virtual servers.

        Returns:
            List of virtual server objects
        """
        virtual_servers = []

        try:
            async with self._session.get(
                f"{self._base_url}/tm/ltm/virtual",
                ssl=False,
            ) as resp:
                if resp.status == 200:
                    data = await resp.json()
                    for item in data.get("items", []):
                        dest = item.get("destination", "")
                        # Parse destination (format: /partition/address:port)
                        addr_port = dest.split("/")[-1] if "/" in dest else dest
                        address = addr_port.rsplit(":", 1)[0] if ":" in addr_port else addr_port
                        port = int(addr_port.rsplit(":", 1)[1]) if ":" in addr_port else 0

                        vs = F5VirtualServer(
                            name=item.get("name", ""),
                            partition=item.get("partition", "Common"),
                            destination=address,
                            port=port,
                            pool=item.get("pool"),
                            enabled=item.get("enabled", True),
                            status=item.get("status", {}).get("availabilityState", "unknown"),
                        )
                        virtual_servers.append(vs)

        except Exception as e:
            logger.error(f"Failed to get virtual servers: {e}")

        return virtual_servers

    async def get_pool_status(self, pool_name: str) -> dict:
        """Get LTM pool status.

        Args:
            pool_name: Name of the pool

        Returns:
            Pool status dictionary
        """
        try:
            async with self._session.get(
                f"{self._base_url}/tm/ltm/pool/{pool_name}",
                params={"expandSubcollections": "true"},
                ssl=False,
            ) as resp:
                if resp.status == 200:
                    return await resp.json()
        except Exception as e:
            logger.error(f"Failed to get pool status: {e}")

        return {}

    # =========================================================================
    # Restore Methods
    # =========================================================================

    async def restore_ucs(self, ucs_content: str, ucs_name: str | None = None) -> bool:
        """Restore UCS backup to F5 device.

        Args:
            ucs_content: Base64-encoded UCS archive content
            ucs_name: Name for the UCS file

        Returns:
            True if restore successful
        """
        try:
            if not ucs_name:
                ucs_name = f"restore_{datetime.now().strftime('%Y%m%d_%H%M%S')}.ucs"

            # Decode the content
            ucs_bytes = base64.b64decode(ucs_content)

            # Upload UCS file
            async with self._session.post(
                f"{self._base_url}/shared/file-transfer/uploads/{ucs_name}",
                data=ucs_bytes,
                headers={"Content-Type": "application/octet-stream"},
                ssl=False,
            ) as resp:
                if resp.status not in (200, 201):
                    logger.error(f"Failed to upload UCS: {resp.status}")
                    return False

            # Load UCS
            async with self._session.post(
                f"{self._base_url}/tm/sys/ucs",
                json={"command": "load", "name": f"/var/local/ucs/{ucs_name}"},
                ssl=False,
            ) as resp:
                if resp.status in (200, 202):
                    logger.info(f"UCS restore initiated: {ucs_name}")
                    return True

            logger.error("Failed to initiate UCS restore")
            return False

        except Exception as e:
            logger.error(f"UCS restore failed: {e}")
            return False

    async def restore_gtm_config(self, config_json: str) -> bool:
        """Restore GTM configuration from JSON.

        Args:
            config_json: JSON string of GTM configuration

        Returns:
            True if restore successful
        """
        try:
            config = json.loads(config_json)

            # Restore datacenters first
            for dc in config.get("datacenters", []):
                await self._create_or_update_resource("tm/gtm/datacenter", dc)

            # Restore servers
            for server in config.get("servers", []):
                await self._create_or_update_resource("tm/gtm/server", server)

            # Restore pools
            for pool in config.get("pools", []):
                pool_type = pool.get("type", "a").lower()
                await self._create_or_update_resource(f"tm/gtm/pool/{pool_type}", pool)

            # Restore wide IPs
            for wip in config.get("wide_ips", []):
                wip_type = wip.get("type", "a").lower()
                await self._create_or_update_resource(f"tm/gtm/wideip/{wip_type}", wip)

            logger.info("GTM configuration restored")
            return True

        except Exception as e:
            logger.error(f"GTM restore failed: {e}")
            return False

    async def _create_or_update_resource(self, endpoint: str, data: dict) -> bool:
        """Create or update an API resource.

        Args:
            endpoint: API endpoint
            data: Resource data

        Returns:
            True if successful
        """
        try:
            name = data.get("name", "")
            partition = data.get("partition", "Common")

            # Try to get existing resource
            async with self._session.get(
                f"{self._base_url}/{endpoint}/~{partition}~{name}",
                ssl=False,
            ) as resp:
                if resp.status == 200:
                    # Update existing
                    async with self._session.patch(
                        f"{self._base_url}/{endpoint}/~{partition}~{name}",
                        json=data,
                        ssl=False,
                    ) as update_resp:
                        return update_resp.status in (200, 201)
                else:
                    # Create new
                    async with self._session.post(
                        f"{self._base_url}/{endpoint}",
                        json=data,
                        ssl=False,
                    ) as create_resp:
                        return create_resp.status in (200, 201)

        except Exception as e:
            logger.error(f"Resource create/update failed: {e}")
            return False
