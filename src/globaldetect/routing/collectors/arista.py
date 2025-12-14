"""
Arista EOS routing collector.

Provides connectivity to Arista EOS devices for
routing protocol information collection.

Copyright (c) 2025 DNS Science.io, an After Dark Systems, LLC company.
All rights reserved.
"""

import asyncio
import logging
import re
from typing import Any

from globaldetect.routing.collectors.base import RoutingCollector, DeviceCredentials
from globaldetect.routing.parsers.arista import AristaEOSParser

logger = logging.getLogger(__name__)


class AristaEOSCollector(RoutingCollector):
    """Collector for Arista EOS devices.

    Uses SSH or eAPI (REST) for device interaction.
    Arista EOS commands are very similar to Cisco IOS.
    """

    PARSER_CLASS = AristaEOSParser

    # Prompt patterns for Arista EOS
    PROMPT_PATTERNS = [
        r"[\w\-\.]+[>#]\s*$",  # hostname> or hostname#
        r"[\w\-\.]+\(config[^\)]*\)#\s*$",  # Config mode
    ]

    # More prompt pattern
    MORE_PATTERN = r"--More--|lines \d+-\d+"

    def __init__(self, credentials: DeviceCredentials):
        super().__init__(credentials)
        self._shell: Any = None
        self._in_enable_mode = False
        self._proxy_tunnel: Any = None

    async def connect(self) -> bool:
        """Connect to Arista device via SSH."""
        try:
            import asyncssh

            connect_kwargs = {
                "host": self.credentials.ip_address or self.credentials.hostname,
                "port": self.credentials.port,
                "username": self.credentials.username,
                "known_hosts": None,
            }

            if self.credentials.password:
                connect_kwargs["password"] = self.credentials.password

            if self.credentials.ssh_key:
                connect_kwargs["client_keys"] = [self.credentials.ssh_key]
                if self.credentials.ssh_key_passphrase:
                    connect_kwargs["passphrase"] = self.credentials.ssh_key_passphrase

            # Configure proxy if enabled
            if self.credentials.proxy and self.credentials.proxy.is_enabled:
                tunnel = await self._create_proxy_tunnel()
                if tunnel:
                    connect_kwargs["tunnel"] = tunnel

            self._connection = await asyncssh.connect(**connect_kwargs)

            # Open interactive shell
            self._shell = await self._connection.create_process(
                term_type="vt100",
                term_size=(200, 50),
            )

            # Wait for initial prompt
            await self._wait_for_prompt()

            # Disable paging
            await self._disable_paging()

            # Enter enable mode if needed
            await self._enter_enable_mode()

            return True

        except ImportError:
            logger.error("asyncssh not installed. Run: pip install asyncssh")
            return False
        except Exception as e:
            logger.error(f"Connection to {self.hostname} failed: {e}")
            return False

    async def _create_proxy_tunnel(self) -> Any:
        """Create proxy tunnel for SSH connection."""
        if not self.credentials.proxy or not self.credentials.proxy.is_enabled:
            return None

        proxy = self.credentials.proxy

        try:
            if proxy.proxy_type in ("socks4", "socks5"):
                try:
                    import python_socks
                    from python_socks.async_.asyncio.v2 import Proxy

                    proxy_type = (
                        python_socks.ProxyType.SOCKS5
                        if proxy.proxy_type == "socks5"
                        else python_socks.ProxyType.SOCKS4
                    )

                    socks_proxy = Proxy(
                        proxy_type=proxy_type,
                        host=proxy.proxy_host,
                        port=proxy.proxy_port or 1080,
                        username=proxy.proxy_username,
                        password=proxy.proxy_password,
                    )

                    target_host = self.credentials.ip_address or self.credentials.hostname
                    target_port = self.credentials.port

                    sock = await socks_proxy.connect(
                        dest_host=target_host,
                        dest_port=target_port,
                    )
                    self._proxy_tunnel = sock
                    return sock

                except ImportError:
                    logger.warning(
                        "python-socks not installed. Run: pip install python-socks[asyncio]"
                    )

            elif proxy.proxy_type == "http":
                try:
                    from python_socks.async_.asyncio.v2 import Proxy
                    import python_socks

                    http_proxy = Proxy(
                        proxy_type=python_socks.ProxyType.HTTP,
                        host=proxy.proxy_host,
                        port=proxy.proxy_port or 8080,
                        username=proxy.proxy_username,
                        password=proxy.proxy_password,
                    )

                    target_host = self.credentials.ip_address or self.credentials.hostname
                    target_port = self.credentials.port

                    sock = await http_proxy.connect(
                        dest_host=target_host,
                        dest_port=target_port,
                    )
                    self._proxy_tunnel = sock
                    return sock

                except ImportError:
                    logger.error(
                        "python-socks not installed for HTTP proxy. "
                        "Run: pip install python-socks[asyncio]"
                    )

        except Exception as e:
            logger.error(f"Failed to create proxy tunnel: {e}")

        return None

    async def disconnect(self) -> None:
        """Close SSH connection."""
        if self._shell:
            try:
                self._shell.stdin.write("exit\n")
                self._shell.close()
            except Exception:
                pass
            self._shell = None

        if self._connection:
            try:
                self._connection.close()
                await self._connection.wait_closed()
            except Exception:
                pass
            self._connection = None

        if self._proxy_tunnel:
            try:
                if hasattr(self._proxy_tunnel, "close"):
                    self._proxy_tunnel.close()
            except Exception:
                pass
            self._proxy_tunnel = None

    async def run_command(self, command: str, timeout: int = 60) -> str:
        """Execute command on device.

        Args:
            command: Command to execute
            timeout: Command timeout in seconds

        Returns:
            Command output
        """
        if not self._shell:
            raise RuntimeError("Not connected")

        # Send command
        self._shell.stdin.write(f"{command}\n")

        # Collect output
        output = await self._read_until_prompt(timeout)

        # Clean output
        output = self._clean_output(output, command)

        return output

    async def _wait_for_prompt(self, timeout: int = 30) -> str:
        """Wait for device prompt."""
        output = ""
        try:
            async with asyncio.timeout(timeout):
                while True:
                    chunk = await self._shell.stdout.read(4096)
                    if not chunk:
                        break
                    output += chunk

                    for pattern in self.PROMPT_PATTERNS:
                        if re.search(pattern, output):
                            return output

                    if re.search(self.MORE_PATTERN, output):
                        self._shell.stdin.write(" ")

        except asyncio.TimeoutError:
            logger.warning(f"Timeout waiting for prompt from {self.hostname}")

        return output

    async def _read_until_prompt(self, timeout: int = 60) -> str:
        """Read output until prompt appears."""
        output = ""
        try:
            async with asyncio.timeout(timeout):
                while True:
                    chunk = await self._shell.stdout.read(4096)
                    if not chunk:
                        break
                    output += chunk

                    if re.search(self.MORE_PATTERN, output):
                        self._shell.stdin.write(" ")
                        continue

                    for pattern in self.PROMPT_PATTERNS:
                        if re.search(pattern, output):
                            return output

        except asyncio.TimeoutError:
            logger.warning(f"Timeout reading output from {self.hostname}")

        return output

    async def _disable_paging(self) -> None:
        """Disable terminal paging."""
        try:
            await self.run_command("terminal length 0", timeout=10)
            await self.run_command("terminal width 200", timeout=10)
        except Exception as e:
            logger.debug(f"Could not disable paging: {e}")

    async def _enter_enable_mode(self) -> None:
        """Enter enable mode if not already."""
        if self._in_enable_mode:
            return

        self._shell.stdin.write("\n")
        output = await self._wait_for_prompt(5)

        if ">" in output and "#" not in output:
            self._shell.stdin.write("enable\n")
            output = await self._wait_for_prompt(5)

            if "Password:" in output or "password:" in output:
                enable_pass = self.credentials.enable_password or self.credentials.password
                if enable_pass:
                    self._shell.stdin.write(f"{enable_pass}\n")
                    await self._wait_for_prompt(5)

            self._in_enable_mode = True

    def _clean_output(self, output: str, command: str) -> str:
        """Clean command output."""
        ansi_escape = re.compile(r"\x1B(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])")
        output = ansi_escape.sub("", output)

        lines = output.split("\n")
        clean_lines = []
        skip_first = True

        for line in lines:
            if skip_first and command in line:
                skip_first = False
                continue

            is_prompt = False
            for pattern in self.PROMPT_PATTERNS:
                if re.search(pattern, line):
                    is_prompt = True
                    break

            if not is_prompt:
                clean_lines.append(line)

        return "\n".join(clean_lines).strip()

    # ==========================================================================
    # Command Overrides for Arista EOS
    # ==========================================================================

    def _get_route_table_command(self, vrf: str = "default") -> str:
        if vrf == "default":
            return "show ip route"
        return f"show ip route vrf {vrf}"

    def _get_bgp_summary_command(self) -> str:
        return "show ip bgp summary"

    def _get_bgp_neighbors_command(self, detailed: bool = True) -> str:
        return "show ip bgp neighbors"

    def _get_bgp_routes_command(
        self,
        prefix: str | None,
        neighbor: str | None,
        advertised: bool,
        received: bool,
    ) -> str:
        if neighbor and advertised:
            return f"show ip bgp neighbors {neighbor} advertised-routes"
        if neighbor and received:
            return f"show ip bgp neighbors {neighbor} received-routes"
        if prefix:
            return f"show ip bgp {prefix}"
        return "show ip bgp"

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

    def _get_ospf_interfaces_command(self) -> str:
        return "show ip ospf interface"

    def _get_isis_summary_command(self) -> str:
        return "show isis summary"

    def _get_isis_adjacencies_command(self) -> str:
        return "show isis neighbors detail"

    def _get_isis_routes_command(self) -> str:
        return "show ip route isis"

    def _get_isis_database_command(self) -> str:
        return "show isis database detail"

    def _get_vrfs_command(self) -> str:
        return "show vrf"

    def _get_redistribution_command(self) -> str:
        return "show running-config | section router"

    # ==========================================================================
    # Additional Arista-specific methods
    # ==========================================================================

    async def get_interfaces(self) -> str:
        """Get interface status."""
        return await self.run_command("show ip interface brief")

    async def get_mac_address_table(self) -> str:
        """Get MAC address table."""
        return await self.run_command("show mac address-table")

    async def get_lldp_neighbors(self) -> str:
        """Get LLDP neighbors."""
        return await self.run_command("show lldp neighbors detail")

    async def get_mlag_status(self) -> str:
        """Get MLAG status."""
        return await self.run_command("show mlag")

    async def get_running_config_section(self, section: str) -> str:
        """Get a section of running config.

        Args:
            section: Config section (e.g., "router bgp")

        Returns:
            Config section output
        """
        return await self.run_command(f"show running-config | section {section}")

    async def get_bgp_evpn_summary(self) -> str:
        """Get BGP EVPN summary for VXLAN deployments."""
        return await self.run_command("show bgp evpn summary")

    async def get_vxlan_vtep(self) -> str:
        """Get VXLAN VTEP information."""
        return await self.run_command("show vxlan vtep")

    async def get_route_for_prefix(self, prefix: str) -> str:
        """Get route information for specific prefix.

        Args:
            prefix: IP prefix or address

        Returns:
            Route information
        """
        return await self.run_command(f"show ip route {prefix}")
