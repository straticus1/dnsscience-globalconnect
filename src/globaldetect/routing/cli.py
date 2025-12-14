"""
CLI commands for routing protocol support.

Provides commands for querying route tables, protocol neighbors,
and troubleshooting routing issues.

Copyright (c) 2025 DNS Science.io, an After Dark Systems, LLC company.
All rights reserved.
"""

import asyncio
import json
from datetime import datetime

import click
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.tree import Tree

from globaldetect.routing.models import (
    RoutingProtocol,
    BGPState,
    OSPFState,
)
from globaldetect.routing.database import get_routing_database
from globaldetect.routing.collectors.base import DeviceCredentials, ProxyConfig
from globaldetect.routing.collectors.cisco import CiscoIOSCollector

console = Console()


def get_collector(
    device: str,
    username: str,
    password: str,
    enable: str | None = None,
    proxy_type: str | None = None,
    proxy_host: str | None = None,
    proxy_port: int | None = None,
    proxy_user: str | None = None,
    proxy_pass: str | None = None,
):
    """Create a collector for the specified device.

    Args:
        device: Device hostname or IP (optionally with :port)
        username: SSH username
        password: SSH password
        enable: Enable password
        proxy_type: Proxy type (http, socks4, socks5)
        proxy_host: Proxy server hostname/IP
        proxy_port: Proxy server port
        proxy_user: Proxy username
        proxy_pass: Proxy password

    Returns:
        CiscoIOSCollector configured with credentials
    """
    # Parse device string (hostname or hostname:port)
    parts = device.split(":")
    hostname = parts[0]
    port = int(parts[1]) if len(parts) > 1 else 22

    # Determine if it's an IP or hostname
    ip_address = None
    if hostname.replace(".", "").isdigit():
        ip_address = hostname

    # Configure proxy if specified
    proxy = None
    if proxy_type and proxy_host:
        proxy = ProxyConfig(
            proxy_type=proxy_type,
            proxy_host=proxy_host,
            proxy_port=proxy_port,
            proxy_username=proxy_user,
            proxy_password=proxy_pass,
        )

    credentials = DeviceCredentials(
        hostname=hostname,
        ip_address=ip_address,
        username=username,
        password=password,
        enable_password=enable,
        port=port,
        proxy=proxy,
    )

    return CiscoIOSCollector(credentials)


# Common Click decorators for proxy options
def proxy_options(func):
    """Add proxy options to a Click command."""
    func = click.option(
        "--proxy-type",
        type=click.Choice(["http", "socks4", "socks5"]),
        help="Proxy type for SSH connection",
    )(func)
    func = click.option(
        "--proxy-host",
        help="Proxy server hostname or IP",
    )(func)
    func = click.option(
        "--proxy-port",
        type=int,
        help="Proxy server port (default: 8080 for HTTP, 1080 for SOCKS)",
    )(func)
    func = click.option(
        "--proxy-user",
        help="Proxy authentication username",
    )(func)
    func = click.option(
        "--proxy-pass",
        help="Proxy authentication password",
    )(func)
    return func


# =============================================================================
# Main routing command group
# =============================================================================

@click.group()
def routing():
    """Routing protocol analysis and troubleshooting.

    Query route tables, protocol neighbors, and diagnose routing issues
    across BGP, OSPF, IS-IS, RIP, and EIGRP.
    """
    pass


# =============================================================================
# Route table commands
# =============================================================================

@routing.command("table")
@click.argument("device")
@click.option("-u", "--username", required=True, help="SSH username")
@click.option("-p", "--password", prompt=True, hide_input=True, help="SSH password")
@click.option("--enable", help="Enable password")
@click.option("--protocol", type=click.Choice(["bgp", "ospf", "isis", "eigrp", "rip", "static", "connected"]),
              help="Filter by protocol")
@click.option("--prefix", help="Filter by prefix")
@click.option("--vrf", default="default", help="VRF name")
@click.option("--best-only", is_flag=True, help="Show only best routes")
@click.option("--json", "as_json", is_flag=True, help="Output as JSON")
@proxy_options
def show_route_table(device, username, password, enable, protocol, prefix, vrf, best_only, as_json,
                     proxy_type, proxy_host, proxy_port, proxy_user, proxy_pass):
    """Show route table from a device.

    DEVICE: Device hostname or IP address (optionally with :port)

    Examples:

        globaldetect routing table router1.example.com -u admin -p

        globaldetect routing table 192.168.1.1 -u admin -p --protocol bgp

        globaldetect routing table 10.0.0.1 -u admin -p --proxy-type socks5 --proxy-host jump.example.com
    """
    collector = get_collector(
        device, username, password, enable,
        proxy_type, proxy_host, proxy_port, proxy_user, proxy_pass
    )

    async def fetch():
        with console.status(f"[cyan]Connecting to {device}...[/cyan]"):
            if not await collector.connect():
                console.print(f"[red]Failed to connect to {device}[/red]")
                return None
        try:
            with console.status(f"[cyan]Fetching route table...[/cyan]"):
                return await collector.get_route_table(vrf)
        finally:
            await collector.disconnect()

    routes = asyncio.run(fetch())

    if routes is None:
        return

    # Apply filters
    if protocol:
        proto_enum = RoutingProtocol(protocol.lower())
        routes = [r for r in routes if r.protocol == proto_enum]

    if prefix:
        routes = [r for r in routes if prefix in r.network]

    if best_only:
        routes = [r for r in routes if r.active]

    if as_json:
        console.print(json.dumps([r.to_dict() for r in routes], indent=2))
        return

    # Display table
    table = Table(title=f"Route Table - {device} (VRF: {vrf})")
    table.add_column("Protocol", style="cyan")
    table.add_column("Network", style="green")
    table.add_column("Next Hop")
    table.add_column("AD/Metric", justify="right")
    table.add_column("Interface")
    table.add_column("Age")

    for route in routes:
        # Protocol indicator
        proto_str = route.protocol.value[0].upper()
        if route.protocol == RoutingProtocol.OSPF:
            proto_str = "O"
        elif route.protocol == RoutingProtocol.BGP:
            proto_str = "B"
        elif route.protocol == RoutingProtocol.EIGRP:
            proto_str = "D"

        # Age
        age_str = ""
        if route.age_seconds:
            hours = route.age_seconds // 3600
            minutes = (route.age_seconds % 3600) // 60
            if hours > 24:
                days = hours // 24
                age_str = f"{days}d{hours % 24}h"
            elif hours > 0:
                age_str = f"{hours}h{minutes}m"
            else:
                age_str = f"{minutes}m"

        table.add_row(
            proto_str,
            route.network,
            route.next_hop or "directly connected",
            f"{route.admin_distance}/{route.metric}",
            route.interface or "",
            age_str,
        )

    console.print(table)
    console.print(f"\nTotal routes: {len(routes)}")


# =============================================================================
# BGP commands
# =============================================================================

@routing.group()
def bgp():
    """BGP protocol commands."""
    pass


@bgp.command("summary")
@click.argument("device")
@click.option("-u", "--username", required=True, help="SSH username")
@click.option("-p", "--password", prompt=True, hide_input=True, help="SSH password")
@click.option("--enable", help="Enable password")
@click.option("--json", "as_json", is_flag=True, help="Output as JSON")
@proxy_options
def bgp_summary(device, username, password, enable, as_json,
                proxy_type, proxy_host, proxy_port, proxy_user, proxy_pass):
    """Show BGP summary.

    DEVICE: Device hostname or IP address
    """
    collector = get_collector(
        device, username, password, enable,
        proxy_type, proxy_host, proxy_port, proxy_user, proxy_pass
    )

    async def fetch():
        with console.status(f"[cyan]Connecting to {device}...[/cyan]"):
            if not await collector.connect():
                console.print(f"[red]Failed to connect to {device}[/red]")
                return None, None
        try:
            with console.status("[cyan]Fetching BGP summary...[/cyan]"):
                summary = await collector.get_bgp_summary()
                neighbors = await collector.get_bgp_neighbors()
                return summary, neighbors
        finally:
            await collector.disconnect()

    summary, neighbors = asyncio.run(fetch())

    if summary is None:
        return

    if as_json:
        data = summary.to_dict() if summary else {}
        data["neighbors"] = [n.to_dict() for n in neighbors] if neighbors else []
        console.print(json.dumps(data, indent=2))
        return

    # Display summary panel
    if summary:
        summary_text = f"""Router ID: {summary.router_id or 'N/A'}
Local AS: {summary.local_asn}
Total Neighbors: {summary.total_neighbors}
Established: {summary.established_neighbors}
Total Prefixes: {summary.total_prefixes}"""
        console.print(Panel(summary_text, title=f"BGP Summary - {device}"))

    # Display neighbors table
    if neighbors:
        table = Table(title="BGP Neighbors")
        table.add_column("Neighbor", style="cyan")
        table.add_column("Remote AS", justify="right")
        table.add_column("Type")
        table.add_column("State", style="green")
        table.add_column("Prefixes Rcvd", justify="right")
        table.add_column("Uptime")

        for neighbor in neighbors:
            state_style = "green" if neighbor.bgp_state == BGPState.ESTABLISHED else "red"
            uptime_str = ""
            if neighbor.uptime_seconds:
                hours = neighbor.uptime_seconds // 3600
                if hours > 24:
                    uptime_str = f"{hours // 24}d"
                else:
                    uptime_str = f"{hours}h"

            table.add_row(
                neighbor.neighbor_address,
                str(neighbor.remote_asn),
                neighbor.session_type.value,
                f"[{state_style}]{neighbor.bgp_state.value}[/{state_style}]",
                str(neighbor.prefixes_received),
                uptime_str,
            )

        console.print(table)


@bgp.command("neighbors")
@click.argument("device")
@click.option("-u", "--username", required=True, help="SSH username")
@click.option("-p", "--password", prompt=True, hide_input=True, help="SSH password")
@click.option("--enable", help="Enable password")
@click.option("--neighbor", help="Specific neighbor IP")
@click.option("--json", "as_json", is_flag=True, help="Output as JSON")
@proxy_options
def bgp_neighbors(device, username, password, enable, neighbor, as_json,
                  proxy_type, proxy_host, proxy_port, proxy_user, proxy_pass):
    """Show BGP neighbor details.

    DEVICE: Device hostname or IP address
    """
    collector = get_collector(
        device, username, password, enable,
        proxy_type, proxy_host, proxy_port, proxy_user, proxy_pass
    )

    async def fetch():
        with console.status(f"[cyan]Connecting to {device}...[/cyan]"):
            if not await collector.connect():
                console.print(f"[red]Failed to connect to {device}[/red]")
                return None
        try:
            with console.status("[cyan]Fetching BGP neighbors...[/cyan]"):
                return await collector.get_bgp_neighbors()
        finally:
            await collector.disconnect()

    neighbors = asyncio.run(fetch())

    if neighbors is None:
        return

    # Filter by specific neighbor
    if neighbor:
        neighbors = [n for n in neighbors if n.neighbor_address == neighbor]

    if as_json:
        console.print(json.dumps([n.to_dict() for n in neighbors], indent=2))
        return

    for n in neighbors:
        state_style = "green" if n.bgp_state == BGPState.ESTABLISHED else "red"

        info = f"""Neighbor: {n.neighbor_address}
Remote AS: {n.remote_asn}
Local AS: {n.local_asn}
Session Type: {n.session_type.value}
State: [{state_style}]{n.bgp_state.value}[/{state_style}]
Remote Router ID: {n.remote_router_id or 'N/A'}
Hold Time: {n.hold_time}s
Keepalive: {n.keepalive}s

Prefixes Received: {n.prefixes_received}
Prefixes Sent: {n.prefixes_sent}

Messages Received: {n.messages_received}
Messages Sent: {n.messages_sent}
Updates Received: {n.updates_received}
Updates Sent: {n.updates_sent}

Address Families: {', '.join(n.address_families) or 'N/A'}"""

        if n.route_reflector_client:
            info += "\nRoute Reflector Client: Yes"

        if n.last_error:
            info += f"\n\n[red]Last Error: {n.last_error}[/red]"

        console.print(Panel(info, title=f"BGP Neighbor - {n.neighbor_address}"))


@bgp.command("routes")
@click.argument("device")
@click.option("-u", "--username", required=True, help="SSH username")
@click.option("-p", "--password", prompt=True, hide_input=True, help="SSH password")
@click.option("--enable", help="Enable password")
@click.option("--prefix", help="Filter by prefix")
@click.option("--neighbor", help="Filter by neighbor")
@click.option("--advertised", is_flag=True, help="Show advertised routes")
@click.option("--received", is_flag=True, help="Show received routes")
@click.option("--best-only", is_flag=True, help="Show only best routes")
@click.option("--json", "as_json", is_flag=True, help="Output as JSON")
@proxy_options
def bgp_routes(device, username, password, enable, prefix, neighbor, advertised, received, best_only, as_json,
               proxy_type, proxy_host, proxy_port, proxy_user, proxy_pass):
    """Show BGP routes.

    DEVICE: Device hostname or IP address
    """
    collector = get_collector(
        device, username, password, enable,
        proxy_type, proxy_host, proxy_port, proxy_user, proxy_pass
    )

    async def fetch():
        with console.status(f"[cyan]Connecting to {device}...[/cyan]"):
            if not await collector.connect():
                console.print(f"[red]Failed to connect to {device}[/red]")
                return None
        try:
            with console.status("[cyan]Fetching BGP routes...[/cyan]"):
                return await collector.get_bgp_routes(
                    prefix=prefix,
                    neighbor=neighbor,
                    advertised=advertised,
                    received=received,
                )
        finally:
            await collector.disconnect()

    routes = asyncio.run(fetch())

    if routes is None:
        return

    if best_only:
        routes = [r for r in routes if r.best]

    if as_json:
        console.print(json.dumps([r.to_dict() for r in routes], indent=2))
        return

    # Display routes table
    table = Table(title="BGP Routes")
    table.add_column("Status")
    table.add_column("Network", style="cyan")
    table.add_column("Next Hop")
    table.add_column("MED", justify="right")
    table.add_column("LocPref", justify="right")
    table.add_column("AS Path")
    table.add_column("Origin")

    for route in routes:
        status = ""
        if route.valid:
            status += "*"
        if route.best:
            status += ">"
        if route.session_type and route.session_type.value == "ibgp":
            status += "i"

        table.add_row(
            status,
            route.network,
            route.next_hop or "0.0.0.0",
            str(route.med),
            str(route.local_pref),
            route.as_path_str or "",
            route.origin.value[0],
        )

    console.print(table)
    console.print(f"\nTotal routes: {len(routes)}")


# =============================================================================
# OSPF commands
# =============================================================================

@routing.group()
def ospf():
    """OSPF protocol commands."""
    pass


@ospf.command("summary")
@click.argument("device")
@click.option("-u", "--username", required=True, help="SSH username")
@click.option("-p", "--password", prompt=True, hide_input=True, help="SSH password")
@click.option("--enable", help="Enable password")
@click.option("--json", "as_json", is_flag=True, help="Output as JSON")
@proxy_options
def ospf_summary(device, username, password, enable, as_json,
                 proxy_type, proxy_host, proxy_port, proxy_user, proxy_pass):
    """Show OSPF summary.

    DEVICE: Device hostname or IP address
    """
    collector = get_collector(
        device, username, password, enable,
        proxy_type, proxy_host, proxy_port, proxy_user, proxy_pass
    )

    async def fetch():
        with console.status(f"[cyan]Connecting to {device}...[/cyan]"):
            if not await collector.connect():
                console.print(f"[red]Failed to connect to {device}[/red]")
                return None
        try:
            with console.status("[cyan]Fetching OSPF summary...[/cyan]"):
                return await collector.get_ospf_summary()
        finally:
            await collector.disconnect()

    summary = asyncio.run(fetch())

    if summary is None:
        return

    if as_json:
        console.print(json.dumps(summary.to_dict(), indent=2))
        return

    summary_text = f"""Router ID: {summary.router_id or 'N/A'}
Process ID: {summary.process_id}
Reference Bandwidth: {summary.reference_bandwidth} Mbps
Total Areas: {summary.total_areas}
Total LSAs: {summary.total_lsas}
Total Neighbors: {summary.total_neighbors}
Full Adjacencies: {summary.full_neighbors}"""

    console.print(Panel(summary_text, title=f"OSPF Summary - {device}"))


@ospf.command("neighbors")
@click.argument("device")
@click.option("-u", "--username", required=True, help="SSH username")
@click.option("-p", "--password", prompt=True, hide_input=True, help="SSH password")
@click.option("--enable", help="Enable password")
@click.option("--json", "as_json", is_flag=True, help="Output as JSON")
@proxy_options
def ospf_neighbors(device, username, password, enable, as_json,
                   proxy_type, proxy_host, proxy_port, proxy_user, proxy_pass):
    """Show OSPF neighbors.

    DEVICE: Device hostname or IP address
    """
    collector = get_collector(
        device, username, password, enable,
        proxy_type, proxy_host, proxy_port, proxy_user, proxy_pass
    )

    async def fetch():
        with console.status(f"[cyan]Connecting to {device}...[/cyan]"):
            if not await collector.connect():
                console.print(f"[red]Failed to connect to {device}[/red]")
                return None
        try:
            with console.status("[cyan]Fetching OSPF neighbors...[/cyan]"):
                return await collector.get_ospf_neighbors()
        finally:
            await collector.disconnect()

    neighbors = asyncio.run(fetch())

    if neighbors is None:
        return

    if as_json:
        console.print(json.dumps([n.to_dict() for n in neighbors], indent=2))
        return

    table = Table(title="OSPF Neighbors")
    table.add_column("Neighbor ID", style="cyan")
    table.add_column("Address")
    table.add_column("Interface")
    table.add_column("Area")
    table.add_column("State", style="green")
    table.add_column("Priority", justify="right")
    table.add_column("Role")

    for neighbor in neighbors:
        state_style = "green" if neighbor.ospf_state == OSPFState.FULL else "yellow"
        role = ""
        if neighbor.is_dr:
            role = "DR"
        elif neighbor.is_bdr:
            role = "BDR"
        else:
            role = "DROTHER"

        table.add_row(
            neighbor.neighbor_id,
            neighbor.neighbor_address,
            neighbor.interface or "",
            neighbor.area,
            f"[{state_style}]{neighbor.ospf_state.value}[/{state_style}]",
            str(neighbor.priority),
            role,
        )

    console.print(table)


@ospf.command("routes")
@click.argument("device")
@click.option("-u", "--username", required=True, help="SSH username")
@click.option("-p", "--password", prompt=True, hide_input=True, help="SSH password")
@click.option("--enable", help="Enable password")
@click.option("--json", "as_json", is_flag=True, help="Output as JSON")
@proxy_options
def ospf_routes(device, username, password, enable, as_json,
                proxy_type, proxy_host, proxy_port, proxy_user, proxy_pass):
    """Show OSPF routes.

    DEVICE: Device hostname or IP address
    """
    collector = get_collector(
        device, username, password, enable,
        proxy_type, proxy_host, proxy_port, proxy_user, proxy_pass
    )

    async def fetch():
        with console.status(f"[cyan]Connecting to {device}...[/cyan]"):
            if not await collector.connect():
                console.print(f"[red]Failed to connect to {device}[/red]")
                return None
        try:
            with console.status("[cyan]Fetching OSPF routes...[/cyan]"):
                return await collector.get_ospf_routes()
        finally:
            await collector.disconnect()

    routes = asyncio.run(fetch())

    if routes is None:
        return

    if as_json:
        console.print(json.dumps([r.to_dict() for r in routes], indent=2))
        return

    table = Table(title="OSPF Routes")
    table.add_column("Type", style="cyan")
    table.add_column("Network")
    table.add_column("Next Hop")
    table.add_column("Cost", justify="right")
    table.add_column("Area")
    table.add_column("Interface")

    for route in routes:
        table.add_row(
            route.ospf_route_type.value,
            route.network,
            route.next_hop or "",
            str(route.cost),
            route.area or "",
            route.interface or "",
        )

    console.print(table)
    console.print(f"\nTotal routes: {len(routes)}")


# =============================================================================
# IS-IS commands
# =============================================================================

@routing.group()
def isis():
    """IS-IS protocol commands."""
    pass


@isis.command("summary")
@click.argument("device")
@click.option("-u", "--username", required=True, help="SSH username")
@click.option("-p", "--password", prompt=True, hide_input=True, help="SSH password")
@click.option("--enable", help="Enable password")
@click.option("--json", "as_json", is_flag=True, help="Output as JSON")
@proxy_options
def isis_summary(device, username, password, enable, as_json,
                 proxy_type, proxy_host, proxy_port, proxy_user, proxy_pass):
    """Show IS-IS summary.

    DEVICE: Device hostname or IP address
    """
    collector = get_collector(
        device, username, password, enable,
        proxy_type, proxy_host, proxy_port, proxy_user, proxy_pass
    )

    async def fetch():
        with console.status(f"[cyan]Connecting to {device}...[/cyan]"):
            if not await collector.connect():
                console.print(f"[red]Failed to connect to {device}[/red]")
                return None
        try:
            with console.status("[cyan]Fetching IS-IS summary...[/cyan]"):
                return await collector.get_isis_summary()
        finally:
            await collector.disconnect()

    summary = asyncio.run(fetch())

    if summary is None:
        return

    if as_json:
        console.print(json.dumps(summary.to_dict(), indent=2))
        return

    summary_text = f"""System ID: {summary.system_id or 'N/A'}
NET: {summary.net or 'N/A'}
IS Type: {summary.is_type.value}
L1 Adjacencies: {summary.l1_adjacencies}
L2 Adjacencies: {summary.l2_adjacencies}
L1 LSPs: {summary.l1_lsps}
L2 LSPs: {summary.l2_lsps}"""

    console.print(Panel(summary_text, title=f"IS-IS Summary - {device}"))


@isis.command("adjacencies")
@click.argument("device")
@click.option("-u", "--username", required=True, help="SSH username")
@click.option("-p", "--password", prompt=True, hide_input=True, help="SSH password")
@click.option("--enable", help="Enable password")
@click.option("--json", "as_json", is_flag=True, help="Output as JSON")
@proxy_options
def isis_adjacencies(device, username, password, enable, as_json,
                     proxy_type, proxy_host, proxy_port, proxy_user, proxy_pass):
    """Show IS-IS adjacencies.

    DEVICE: Device hostname or IP address
    """
    collector = get_collector(
        device, username, password, enable,
        proxy_type, proxy_host, proxy_port, proxy_user, proxy_pass
    )

    async def fetch():
        with console.status(f"[cyan]Connecting to {device}...[/cyan]"):
            if not await collector.connect():
                console.print(f"[red]Failed to connect to {device}[/red]")
                return None
        try:
            with console.status("[cyan]Fetching IS-IS adjacencies...[/cyan]"):
                return await collector.get_isis_adjacencies()
        finally:
            await collector.disconnect()

    adjacencies = asyncio.run(fetch())

    if adjacencies is None:
        return

    if as_json:
        console.print(json.dumps([a.to_dict() for a in adjacencies], indent=2))
        return

    table = Table(title="IS-IS Adjacencies")
    table.add_column("System ID", style="cyan")
    table.add_column("Interface")
    table.add_column("Level")
    table.add_column("State", style="green")
    table.add_column("Hold Time", justify="right")

    for adj in adjacencies:
        state_style = "green" if adj.isis_state.value == "up" else "red"

        table.add_row(
            adj.system_id or adj.neighbor_id,
            adj.interface or "",
            adj.level.value,
            f"[{state_style}]{adj.isis_state.value}[/{state_style}]",
            f"{adj.hold_time}s",
        )

    console.print(table)


# =============================================================================
# EIGRP commands
# =============================================================================

@routing.group()
def eigrp():
    """EIGRP protocol commands."""
    pass


@eigrp.command("summary")
@click.argument("device")
@click.option("-u", "--username", required=True, help="SSH username")
@click.option("-p", "--password", prompt=True, hide_input=True, help="SSH password")
@click.option("--enable", help="Enable password")
@click.option("--json", "as_json", is_flag=True, help="Output as JSON")
@proxy_options
def eigrp_summary(device, username, password, enable, as_json,
                  proxy_type, proxy_host, proxy_port, proxy_user, proxy_pass):
    """Show EIGRP summary.

    DEVICE: Device hostname or IP address
    """
    collector = get_collector(
        device, username, password, enable,
        proxy_type, proxy_host, proxy_port, proxy_user, proxy_pass
    )

    async def fetch():
        with console.status(f"[cyan]Connecting to {device}...[/cyan]"):
            if not await collector.connect():
                console.print(f"[red]Failed to connect to {device}[/red]")
                return None
        try:
            with console.status("[cyan]Fetching EIGRP summary...[/cyan]"):
                return await collector.get_eigrp_summary()
        finally:
            await collector.disconnect()

    summary = asyncio.run(fetch())

    if summary is None:
        return

    if as_json:
        console.print(json.dumps(summary.to_dict(), indent=2))
        return

    k_values = f"K1={summary.k1} K2={summary.k2} K3={summary.k3} K4={summary.k4} K5={summary.k5}"

    summary_text = f"""Router ID: {summary.router_id or 'N/A'}
AS Number: {summary.as_number}
K-Values: {k_values}
Neighbor Count: {summary.neighbor_count}
Route Count: {summary.route_count}
Active Queries: {summary.active_queries}
Stuck in Active: {summary.stuck_in_active}"""

    console.print(Panel(summary_text, title=f"EIGRP Summary - {device}"))


@eigrp.command("neighbors")
@click.argument("device")
@click.option("-u", "--username", required=True, help="SSH username")
@click.option("-p", "--password", prompt=True, hide_input=True, help="SSH password")
@click.option("--enable", help="Enable password")
@click.option("--json", "as_json", is_flag=True, help="Output as JSON")
@proxy_options
def eigrp_neighbors(device, username, password, enable, as_json,
                    proxy_type, proxy_host, proxy_port, proxy_user, proxy_pass):
    """Show EIGRP neighbors.

    DEVICE: Device hostname or IP address
    """
    collector = get_collector(
        device, username, password, enable,
        proxy_type, proxy_host, proxy_port, proxy_user, proxy_pass
    )

    async def fetch():
        with console.status(f"[cyan]Connecting to {device}...[/cyan]"):
            if not await collector.connect():
                console.print(f"[red]Failed to connect to {device}[/red]")
                return None
        try:
            with console.status("[cyan]Fetching EIGRP neighbors...[/cyan]"):
                return await collector.get_eigrp_neighbors()
        finally:
            await collector.disconnect()

    neighbors = asyncio.run(fetch())

    if neighbors is None:
        return

    if as_json:
        console.print(json.dumps([n.to_dict() for n in neighbors], indent=2))
        return

    table = Table(title="EIGRP Neighbors")
    table.add_column("Address", style="cyan")
    table.add_column("Interface")
    table.add_column("Hold", justify="right")
    table.add_column("Uptime")
    table.add_column("SRTT", justify="right")
    table.add_column("RTO", justify="right")
    table.add_column("Q", justify="right")
    table.add_column("Seq", justify="right")

    for neighbor in neighbors:
        table.add_row(
            neighbor.neighbor_address,
            neighbor.interface or "",
            f"{neighbor.hold_time}s",
            neighbor.uptime_str or "",
            str(neighbor.srtt),
            str(neighbor.rto),
            str(neighbor.q_count),
            str(neighbor.sequence_number),
        )

    console.print(table)


@eigrp.command("topology")
@click.argument("device")
@click.option("-u", "--username", required=True, help="SSH username")
@click.option("-p", "--password", prompt=True, hide_input=True, help="SSH password")
@click.option("--enable", help="Enable password")
@click.option("--json", "as_json", is_flag=True, help="Output as JSON")
@proxy_options
def eigrp_topology(device, username, password, enable, as_json,
                   proxy_type, proxy_host, proxy_port, proxy_user, proxy_pass):
    """Show EIGRP topology table.

    DEVICE: Device hostname or IP address
    """
    collector = get_collector(
        device, username, password, enable,
        proxy_type, proxy_host, proxy_port, proxy_user, proxy_pass
    )

    async def fetch():
        with console.status(f"[cyan]Connecting to {device}...[/cyan]"):
            if not await collector.connect():
                console.print(f"[red]Failed to connect to {device}[/red]")
                return None
        try:
            with console.status("[cyan]Fetching EIGRP topology...[/cyan]"):
                return await collector.get_eigrp_topology()
        finally:
            await collector.disconnect()

    routes = asyncio.run(fetch())

    if routes is None:
        return

    if as_json:
        console.print(json.dumps([r.to_dict() for r in routes], indent=2))
        return

    table = Table(title="EIGRP Topology")
    table.add_column("State")
    table.add_column("Network", style="cyan")
    table.add_column("Successor")
    table.add_column("FD", justify="right")
    table.add_column("RD", justify="right")
    table.add_column("FS Count", justify="right")

    for route in routes:
        state = "P" if route.active else "A"
        state_style = "green" if route.active else "yellow"

        table.add_row(
            f"[{state_style}]{state}[/{state_style}]",
            route.network,
            route.successor or "Connected",
            str(route.feasible_distance),
            str(route.reported_distance),
            str(len(route.feasible_successors)),
        )

    console.print(table)
    console.print(f"\nTotal entries: {len(routes)}")
    console.print("P = Passive (stable), A = Active (querying)")


# =============================================================================
# Redistribution commands
# =============================================================================

@routing.command("redistribution")
@click.argument("device")
@click.option("-u", "--username", required=True, help="SSH username")
@click.option("-p", "--password", prompt=True, hide_input=True, help="SSH password")
@click.option("--enable", help="Enable password")
@click.option("--source", type=click.Choice(["bgp", "ospf", "isis", "eigrp", "rip", "static", "connected"]),
              help="Filter by source protocol")
@click.option("--target", type=click.Choice(["bgp", "ospf", "isis", "eigrp", "rip"]),
              help="Filter by target protocol")
@click.option("--json", "as_json", is_flag=True, help="Output as JSON")
@proxy_options
def show_redistribution(device, username, password, enable, source, target, as_json,
                        proxy_type, proxy_host, proxy_port, proxy_user, proxy_pass):
    """Show route redistribution configuration.

    DEVICE: Device hostname or IP address
    """
    collector = get_collector(
        device, username, password, enable,
        proxy_type, proxy_host, proxy_port, proxy_user, proxy_pass
    )

    async def fetch():
        with console.status(f"[cyan]Connecting to {device}...[/cyan]"):
            if not await collector.connect():
                console.print(f"[red]Failed to connect to {device}[/red]")
                return None
        try:
            with console.status("[cyan]Fetching redistribution config...[/cyan]"):
                return await collector.get_redistribution()
        finally:
            await collector.disconnect()

    redistributions = asyncio.run(fetch())

    if redistributions is None:
        return

    # Apply filters
    if source:
        source_enum = RoutingProtocol(source.lower())
        redistributions = [r for r in redistributions if r.source_protocol == source_enum]

    if target:
        target_enum = RoutingProtocol(target.lower())
        redistributions = [r for r in redistributions if r.target_protocol == target_enum]

    if as_json:
        console.print(json.dumps([r.to_dict() for r in redistributions], indent=2))
        return

    if not redistributions:
        console.print("[yellow]No redistribution configured[/yellow]")
        return

    # Display as a tree
    tree = Tree(f"[bold]Redistribution Map - {device}[/bold]")

    # Group by target protocol
    by_target: dict[str, list] = {}
    for redist in redistributions:
        target_proto = redist.target_protocol.value
        if target_proto not in by_target:
            by_target[target_proto] = []
        by_target[target_proto].append(redist)

    for target_proto, redists in by_target.items():
        target_branch = tree.add(f"[cyan]Into {target_proto.upper()}[/cyan]")
        for redist in redists:
            source_info = f"[green]{redist.source_protocol.value}[/green]"
            if redist.metric:
                source_info += f" metric={redist.metric}"
            if redist.metric_type:
                source_info += f" type={redist.metric_type}"
            if redist.route_map:
                source_info += f" route-map={redist.route_map}"
            target_branch.add(source_info)

    console.print(tree)


# =============================================================================
# Snapshot commands
# =============================================================================

@routing.group()
def snapshot():
    """Route snapshot management."""
    pass


@snapshot.command("create")
@click.argument("device")
@click.option("-u", "--username", required=True, help="SSH username")
@click.option("-p", "--password", prompt=True, hide_input=True, help="SSH password")
@click.option("--enable", help="Enable password")
@click.option("--notes", help="Notes for this snapshot")
@proxy_options
def snapshot_create(device, username, password, enable, notes,
                    proxy_type, proxy_host, proxy_port, proxy_user, proxy_pass):
    """Create a routing snapshot.

    DEVICE: Device hostname or IP address
    """
    collector = get_collector(
        device, username, password, enable,
        proxy_type, proxy_host, proxy_port, proxy_user, proxy_pass
    )

    async def fetch():
        with console.status(f"[cyan]Collecting routing data from {device}...[/cyan]"):
            return await collector.collect_all()

    result = asyncio.run(fetch())

    if not result.success:
        console.print(f"[red]Collection failed: {result.error_message}[/red]")
        return

    # Save to database
    db = get_routing_database()
    db.initialize()

    snapshot_obj = result.to_snapshot()
    snapshot_obj.notes = notes
    snapshot_obj = db.create_snapshot(snapshot_obj)

    # Save routes and neighbors
    route_count = db.add_routes(snapshot_obj.id, result.routes)
    neighbor_count = db.add_neighbors(snapshot_obj.id, result.neighbors)

    if result.vrfs:
        db.add_vrfs(snapshot_obj.id, result.vrfs)

    if result.redistributions:
        db.add_redistributions(result.device_id, result.redistributions)

    db.close()

    console.print(f"[green]Snapshot created: ID {snapshot_obj.id}[/green]")
    console.print(f"Routes: {route_count}, Neighbors: {neighbor_count}")
    console.print(f"Duration: {result.duration_seconds:.2f}s")


@snapshot.command("list")
@click.option("--device", help="Filter by device")
@click.option("--limit", default=20, help="Number of snapshots to show")
def snapshot_list(device, limit):
    """List routing snapshots."""
    db = get_routing_database()
    db.initialize()

    snapshots = db.list_snapshots(device_id=device, limit=limit)
    db.close()

    if not snapshots:
        console.print("[yellow]No snapshots found[/yellow]")
        return

    table = Table(title="Routing Snapshots")
    table.add_column("ID", justify="right")
    table.add_column("Device", style="cyan")
    table.add_column("Timestamp")
    table.add_column("Type")
    table.add_column("Routes", justify="right")
    table.add_column("Neighbors", justify="right")
    table.add_column("Notes")

    for snap in snapshots:
        timestamp = snap.timestamp.strftime("%Y-%m-%d %H:%M") if snap.timestamp else ""
        table.add_row(
            str(snap.id),
            snap.device_hostname or snap.device_id or "",
            timestamp,
            snap.snapshot_type,
            str(snap.route_count),
            str(snap.neighbor_count),
            (snap.notes or "")[:30],
        )

    console.print(table)


@snapshot.command("diff")
@click.argument("snapshot1", type=int)
@click.argument("snapshot2", type=int)
@click.option("--json", "as_json", is_flag=True, help="Output as JSON")
def snapshot_diff(snapshot1, snapshot2, as_json):
    """Compare two routing snapshots.

    SNAPSHOT1: First snapshot ID
    SNAPSHOT2: Second snapshot ID
    """
    db = get_routing_database()
    db.initialize()

    diff = db.compare_snapshots(snapshot1, snapshot2)
    db.close()

    if as_json:
        console.print(json.dumps(diff, indent=2))
        return

    summary = diff["summary"]

    console.print(Panel(
        f"""Routes Added: {summary.get('routes_added', 0)}
Routes Removed: {summary.get('routes_removed', 0)}
Routes Changed: {summary.get('routes_changed', 0)}
Neighbors Added: {summary.get('neighbors_added', 0)}
Neighbors Removed: {summary.get('neighbors_removed', 0)}
Neighbor State Changes: {summary.get('neighbors_state_changed', 0)}""",
        title=f"Snapshot Diff: {snapshot1} vs {snapshot2}"
    ))

    # Show details
    if diff["routes"]["added"]:
        console.print("\n[green]Added Routes:[/green]")
        for route in diff["routes"]["added"][:10]:
            console.print(f"  + {route}")
        if len(diff["routes"]["added"]) > 10:
            console.print(f"  ... and {len(diff['routes']['added']) - 10} more")

    if diff["routes"]["removed"]:
        console.print("\n[red]Removed Routes:[/red]")
        for route in diff["routes"]["removed"][:10]:
            console.print(f"  - {route}")
        if len(diff["routes"]["removed"]) > 10:
            console.print(f"  ... and {len(diff['routes']['removed']) - 10} more")


# =============================================================================
# Troubleshooting commands
# =============================================================================

@routing.group()
def troubleshoot():
    """Routing troubleshooting tools."""
    pass


@troubleshoot.command("flaps")
@click.argument("device")
@click.option("--threshold", default=5, help="Minimum flaps to report")
@click.option("--period", default=15, help="Analysis period in minutes")
@click.option("--json", "as_json", is_flag=True, help="Output as JSON")
def detect_flaps(device, threshold, period, as_json):
    """Detect route flapping.

    DEVICE: Device ID to analyze
    """
    db = get_routing_database()
    db.initialize()

    flaps = db.get_flapping_routes(
        device_id=device,
        threshold=threshold,
        period_minutes=period,
    )
    db.close()

    if as_json:
        console.print(json.dumps(flaps, indent=2, default=str))
        return

    if not flaps:
        console.print(f"[green]No route flapping detected (threshold: {threshold} in {period} minutes)[/green]")
        return

    console.print(f"[yellow]Route Flapping Detected![/yellow]")

    table = Table(title=f"Flapping Routes (>{threshold} changes in {period} minutes)")
    table.add_column("Prefix", style="cyan")
    table.add_column("Flap Count", justify="right", style="red")
    table.add_column("First Flap")
    table.add_column("Last Flap")

    for flap in flaps:
        table.add_row(
            flap["prefix"],
            str(flap["flap_count"]),
            str(flap["first_flap"]),
            str(flap["last_flap"]),
        )

    console.print(table)
