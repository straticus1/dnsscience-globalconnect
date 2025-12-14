"""
Juniper JunOS routing collector.

Provides connectivity to Juniper JunOS devices for
routing protocol information collection.

Copyright (c) 2025 DNS Science.io, an After Dark Systems, LLC company.
All rights reserved.
"""

import asyncio
import logging
import re
from typing import Any

from globaldetect.routing.collectors.base import RoutingCollector, DeviceCredentials
from globaldetect.routing.parsers.juniper import JuniperJunOSParser

logger = logging.getLogger(__name__)


class JuniperJunOSCollector(RoutingCollector):
    """Collector for Juniper JunOS devices.

    Uses SSH with NETCONF-style or CLI interaction.
    """

    PARSER_CLASS = JuniperJunOSParser

    # Prompt patterns for JunOS
    PROMPT_PATTERNS = [
        r"[\w\-\.]+[@>]\s*$",  # user@router> or router>
        r"[\w\-\.]+#\s*$",     # root@router#
    ]

    def __init__(self, credentials: DeviceCredentials):
        super().__init__(credentials)
        self._shell: Any = None
        self._proxy_tunnel: Any = None

    async def connect(self) -> bool:
        """Connect to Juniper device via SSH."""
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

            # Enter CLI mode if in shell
            await self._enter_cli_mode()

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

                    # Handle --More-- prompts
                    if "---More---" in output or "---(more" in output.lower():
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
            await self.run_command("set cli screen-length 0", timeout=10)
            await self.run_command("set cli screen-width 200", timeout=10)
        except Exception as e:
            logger.debug(f"Could not disable paging: {e}")

    async def _enter_cli_mode(self) -> None:
        """Enter CLI mode if in shell."""
        try:
            # Check if we're in operational mode
            self._shell.stdin.write("\n")
            output = await self._wait_for_prompt(5)

            # If we see a shell prompt, enter CLI
            if "%" in output or "$" in output:
                await self.run_command("cli", timeout=10)
        except Exception as e:
            logger.debug(f"CLI mode check: {e}")

    def _clean_output(self, output: str, command: str) -> str:
        """Clean command output."""
        # Remove ANSI escape codes
        ansi_escape = re.compile(r"\x1B(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])")
        output = ansi_escape.sub("", output)

        # Remove the command echo and prompts
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
    # Command Overrides for JunOS
    # ==========================================================================

    def _get_route_table_command(self, vrf: str = "default") -> str:
        if vrf == "default":
            return "show route"
        return f"show route instance {vrf}"

    def _get_bgp_summary_command(self) -> str:
        return "show bgp summary"

    def _get_bgp_neighbors_command(self, detailed: bool = True) -> str:
        return "show bgp neighbor"

    def _get_bgp_routes_command(
        self,
        prefix: str | None,
        neighbor: str | None,
        advertised: bool,
        received: bool,
    ) -> str:
        if neighbor and advertised:
            return f"show route advertising-protocol bgp {neighbor}"
        if neighbor and received:
            return f"show route receive-protocol bgp {neighbor}"
        if prefix:
            return f"show route protocol bgp {prefix}"
        return "show route protocol bgp"

    def _get_ospf_summary_command(self) -> str:
        return "show ospf overview"

    def _get_ospf_neighbors_command(self, detailed: bool = True) -> str:
        if detailed:
            return "show ospf neighbor detail"
        return "show ospf neighbor"

    def _get_ospf_routes_command(self) -> str:
        return "show route protocol ospf"

    def _get_ospf_database_command(self, area: str | None = None) -> str:
        if area:
            return f"show ospf database area {area}"
        return "show ospf database"

    def _get_ospf_interfaces_command(self) -> str:
        return "show ospf interface"

    def _get_isis_summary_command(self) -> str:
        return "show isis overview"

    def _get_isis_adjacencies_command(self) -> str:
        return "show isis adjacency detail"

    def _get_isis_routes_command(self) -> str:
        return "show route protocol isis"

    def _get_isis_database_command(self) -> str:
        return "show isis database detail"

    def _get_vrfs_command(self) -> str:
        return "show route instance"

    def _get_redistribution_command(self) -> str:
        return "show configuration policy-options"

    # ==========================================================================
    # Additional JunOS-specific methods
    # ==========================================================================

    async def get_interfaces(self) -> str:
        """Get interface status."""
        return await self.run_command("show interfaces terse")

    async def get_arp_table(self) -> str:
        """Get ARP table."""
        return await self.run_command("show arp no-resolve")

    async def get_lldp_neighbors(self) -> str:
        """Get LLDP neighbors."""
        return await self.run_command("show lldp neighbors")

    async def get_configuration_section(self, section: str) -> str:
        """Get a section of configuration.

        Args:
            section: Config section (e.g., "protocols bgp")

        Returns:
            Config section output
        """
        return await self.run_command(f"show configuration {section}")

    async def get_bgp_group(self, group_name: str) -> str:
        """Get BGP group configuration.

        Args:
            group_name: BGP group name

        Returns:
            Group configuration
        """
        return await self.run_command(f"show configuration protocols bgp group {group_name}")

    async def get_route_for_prefix(self, prefix: str) -> str:
        """Get route information for specific prefix.

        Args:
            prefix: IP prefix or address

        Returns:
            Route information
        """
        return await self.run_command(f"show route {prefix} detail")
