"""
CLI commands for DHCP operations.

Provides DHCP troubleshooting commands with verbose output
for debugging DHCP, relay agent, and PXE boot issues.

Copyright (c) 2025 DNS Science.io, an After Dark Systems, LLC company.
All rights reserved.
"""

import json
import sys

import click
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from globaldetect.dhcp.client import DHCPClient, DHCPConfig, DHCPLease

console = Console()


@click.group()
def dhcp():
    """DHCP client operations for network troubleshooting.

    Provides tools for testing DHCP servers, debugging relay agent
    issues (Option 82), and troubleshooting PXE boot problems.

    \b
    Examples:
        # Discover available DHCP servers
        globaldetect dhcp discover -v

        # Obtain a lease with full debug output
        globaldetect dhcp obtain -v -i eth0

        # Test PXE boot configuration
        globaldetect dhcp obtain -v --pxe

        # Release a lease
        globaldetect dhcp release --ip 192.168.1.100 --server 192.168.1.1

    Note: Most DHCP operations require root privileges.
    """
    pass


def create_client(
    interface: str | None,
    mac: str | None,
    hostname: str | None,
    verbose: bool,
    pxe: bool,
    pxe_arch: int | None,
) -> DHCPClient:
    """Create DHCP client with configuration."""
    config = DHCPConfig(
        interface=interface,
        mac_address=mac,
        hostname=hostname,
    )

    # PXE configuration
    if pxe:
        config.vendor_class_id = "PXEClient:Arch:00000:UNDI:002001"
        config.pxe_client_arch = pxe_arch if pxe_arch is not None else 0
        config.requested_options.extend([
            66,  # TFTP server name
            67,  # Bootfile name
            93,  # PXE client arch
        ])

    return DHCPClient(config=config, verbose=verbose)


def display_lease(lease: DHCPLease, verbose: bool = False):
    """Display lease information."""
    table = Table(title="DHCP Lease", show_header=False)
    table.add_column("Field", style="cyan")
    table.add_column("Value")

    table.add_row("IP Address", lease.ip_address or "N/A")
    table.add_row("Subnet Mask", lease.subnet_mask or "N/A")
    table.add_row("Gateway", lease.gateway or "N/A")
    table.add_row("DNS Servers", ", ".join(lease.dns_servers) if lease.dns_servers else "N/A")
    table.add_row("Domain", lease.domain_name or "N/A")
    table.add_row("Broadcast", lease.broadcast_address or "N/A")

    if lease.ntp_servers:
        table.add_row("NTP Servers", ", ".join(lease.ntp_servers))

    table.add_row("", "")  # Spacer
    table.add_row("Lease Time", f"{lease.lease_time}s ({lease.lease_time // 3600}h)" if lease.lease_time else "N/A")
    table.add_row("Renewal (T1)", f"{lease.renewal_time}s" if lease.renewal_time else "N/A")
    table.add_row("Rebinding (T2)", f"{lease.rebinding_time}s" if lease.rebinding_time else "N/A")
    table.add_row("Server ID", lease.server_id or "N/A")

    # PXE/Boot info
    if lease.tftp_server or lease.bootfile or lease.next_server:
        table.add_row("", "")  # Spacer
        table.add_row("[bold]PXE Boot Info[/bold]", "")
        table.add_row("Next Server (siaddr)", lease.next_server or "N/A")
        table.add_row("TFTP Server", lease.tftp_server or "N/A")
        table.add_row("Boot File", lease.bootfile or "N/A")

    # Relay agent info
    if lease.relay_agent_circuit_id or lease.relay_agent_remote_id:
        table.add_row("", "")  # Spacer
        table.add_row("[bold]Relay Agent (Opt 82)[/bold]", "")
        if lease.relay_agent_circuit_id:
            # Try ASCII decode
            try:
                circuit_str = lease.relay_agent_circuit_id.decode('ascii')
                if circuit_str.isprintable():
                    table.add_row("Circuit ID", circuit_str)
                else:
                    table.add_row("Circuit ID", lease.relay_agent_circuit_id.hex())
            except:
                table.add_row("Circuit ID", lease.relay_agent_circuit_id.hex())
        if lease.relay_agent_remote_id:
            table.add_row("Remote ID", lease.relay_agent_remote_id.hex())

    console.print(table)


@dhcp.command()
@click.option("--interface", "-i", help="Network interface to use")
@click.option("--mac", "-m", help="Override MAC address (xx:xx:xx:xx:xx:xx)")
@click.option("--hostname", "-h", help="Client hostname to send")
@click.option("--verbose", "-v", is_flag=True, help="Verbose debug output")
@click.option("--pxe", is_flag=True, help="Include PXE client options")
@click.option("--pxe-arch", type=int, help="PXE architecture (0=x86 BIOS, 7=x64 UEFI)")
@click.option("--timeout", "-t", default=5.0, help="Timeout in seconds")
@click.option("--json-output", "json_out", is_flag=True, help="Output as JSON")
def discover(
    interface: str | None,
    mac: str | None,
    hostname: str | None,
    verbose: bool,
    pxe: bool,
    pxe_arch: int | None,
    timeout: float,
    json_out: bool,
):
    """Send DHCPDISCOVER and show DHCPOFFER responses.

    Discovers available DHCP servers without obtaining a lease.
    Useful for verifying DHCP server availability and configuration.

    \b
    Examples:
        # Basic discovery
        globaldetect dhcp discover

        # Verbose output for troubleshooting
        globaldetect dhcp discover -v

        # Discovery on specific interface
        globaldetect dhcp discover -i eth0

        # PXE discovery
        globaldetect dhcp discover -v --pxe
    """
    client = create_client(interface, mac, hostname, verbose, pxe, pxe_arch)
    client.config.discover_timeout = timeout

    if not json_out and not verbose:
        console.print("[dim]Sending DHCPDISCOVER...[/dim]")

    try:
        offer = client.discover(interface)
    except PermissionError:
        console.print("[red]Error: Permission denied. Run as root or with CAP_NET_RAW capability.[/red]")
        sys.exit(1)

    if not offer:
        if json_out:
            click.echo(json.dumps({"success": False, "error": "No DHCPOFFER received"}))
        else:
            console.print("[yellow]No DHCPOFFER received. DHCP server may be unavailable.[/yellow]")
        sys.exit(1)

    if json_out:
        output = {"success": True, "offer": offer.to_dict()}
        click.echo(json.dumps(output, indent=2))
    else:
        console.print()
        display_lease(offer, verbose)


@dhcp.command()
@click.option("--interface", "-i", help="Network interface to use")
@click.option("--mac", "-m", help="Override MAC address (xx:xx:xx:xx:xx:xx)")
@click.option("--hostname", "-h", help="Client hostname to send")
@click.option("--verbose", "-v", is_flag=True, help="Verbose debug output")
@click.option("--pxe", is_flag=True, help="Include PXE client options")
@click.option("--pxe-arch", type=int, help="PXE architecture (0=x86 BIOS, 7=x64 UEFI)")
@click.option("--timeout", "-t", default=5.0, help="Timeout in seconds")
@click.option("--retries", "-r", default=3, help="Number of retries")
@click.option("--json-output", "json_out", is_flag=True, help="Output as JSON")
def obtain(
    interface: str | None,
    mac: str | None,
    hostname: str | None,
    verbose: bool,
    pxe: bool,
    pxe_arch: int | None,
    timeout: float,
    retries: int,
    json_out: bool,
):
    """Obtain a DHCP lease (full DORA process).

    Performs complete DHCP handshake:
    - DHCPDISCOVER (broadcast)
    - DHCPOFFER (from server)
    - DHCPREQUEST (to server)
    - DHCPACK (from server)

    \b
    Examples:
        # Obtain lease with verbose output
        globaldetect dhcp obtain -v

        # Obtain lease on specific interface
        globaldetect dhcp obtain -i eth0 -v

        # Test PXE boot configuration
        globaldetect dhcp obtain -v --pxe --pxe-arch 7
    """
    client = create_client(interface, mac, hostname, verbose, pxe, pxe_arch)
    client.config.discover_timeout = timeout
    client.config.request_timeout = timeout
    client.config.max_retries = retries

    if not json_out and not verbose:
        console.print("[dim]Starting DHCP DORA process...[/dim]")

    try:
        lease = client.discover_and_request(interface)
    except PermissionError:
        console.print("[red]Error: Permission denied. Run as root or with CAP_NET_RAW capability.[/red]")
        sys.exit(1)

    if not lease:
        if json_out:
            click.echo(json.dumps({"success": False, "error": "Failed to obtain lease"}))
        else:
            console.print("[red]Failed to obtain DHCP lease.[/red]")
        sys.exit(1)

    if json_out:
        output = {"success": True, "lease": lease.to_dict()}
        click.echo(json.dumps(output, indent=2))
    else:
        console.print()
        console.print("[green]Lease obtained successfully![/green]")
        console.print()
        display_lease(lease, verbose)


@dhcp.command()
@click.option("--ip", required=True, help="IP address to release")
@click.option("--server", required=True, help="DHCP server IP")
@click.option("--mac", "-m", help="Client MAC address")
@click.option("--interface", "-i", help="Network interface to use")
@click.option("--verbose", "-v", is_flag=True, help="Verbose debug output")
def release(
    ip: str,
    server: str,
    mac: str | None,
    interface: str | None,
    verbose: bool,
):
    """Release a DHCP lease.

    Sends DHCPRELEASE to the server to release an IP address.
    Note: DHCPRELEASE doesn't expect a response from the server.

    \b
    Examples:
        # Release a lease
        globaldetect dhcp release --ip 192.168.1.100 --server 192.168.1.1

        # Release with specific MAC
        globaldetect dhcp release --ip 192.168.1.100 --server 192.168.1.1 -m aa:bb:cc:dd:ee:ff
    """
    config = DHCPConfig(
        interface=interface,
        mac_address=mac,
    )
    client = DHCPClient(config=config, verbose=verbose)

    # Create a minimal lease object for release
    lease = DHCPLease(
        ip_address=ip,
        server_id=server,
        client_mac=mac or "00:00:00:00:00:00",
    )

    try:
        success = client.release(lease, interface)
        if success:
            console.print(f"[green]DHCPRELEASE sent for {ip}[/green]")
        else:
            console.print("[red]Failed to send DHCPRELEASE[/red]")
            sys.exit(1)
    except PermissionError:
        console.print("[red]Error: Permission denied. Run as root or with CAP_NET_RAW capability.[/red]")
        sys.exit(1)


@dhcp.command()
@click.option("--ip", required=True, help="Your current IP address")
@click.option("--interface", "-i", help="Network interface to use")
@click.option("--mac", "-m", help="Override MAC address")
@click.option("--verbose", "-v", is_flag=True, help="Verbose debug output")
@click.option("--pxe", is_flag=True, help="Include PXE client options")
@click.option("--json-output", "json_out", is_flag=True, help="Output as JSON")
def inform(
    ip: str,
    interface: str | None,
    mac: str | None,
    verbose: bool,
    pxe: bool,
    json_out: bool,
):
    """Send DHCPINFORM to get configuration options.

    Requests DHCP options without requesting an IP address.
    Useful when you have a static IP but want DHCP-provided
    configuration like DNS servers, NTP, or PXE boot info.

    \b
    Examples:
        # Get config options for existing IP
        globaldetect dhcp inform --ip 192.168.1.100 -v

        # Get PXE boot configuration
        globaldetect dhcp inform --ip 192.168.1.100 --pxe -v
    """
    client = create_client(interface, mac, None, verbose, pxe, None)

    if not json_out and not verbose:
        console.print(f"[dim]Sending DHCPINFORM for {ip}...[/dim]")

    try:
        lease = client.inform(ip, interface)
    except PermissionError:
        console.print("[red]Error: Permission denied. Run as root or with CAP_NET_RAW capability.[/red]")
        sys.exit(1)

    if not lease:
        if json_out:
            click.echo(json.dumps({"success": False, "error": "No response received"}))
        else:
            console.print("[yellow]No DHCPACK received.[/yellow]")
        sys.exit(1)

    if json_out:
        output = {"success": True, "config": lease.to_dict()}
        click.echo(json.dumps(output, indent=2))
    else:
        console.print()
        display_lease(lease, verbose)


@dhcp.command()
@click.option("--interface", "-i", help="Network interface to use")
@click.option("--verbose", "-v", is_flag=True, help="Verbose debug output")
@click.option("--timeout", "-t", default=10.0, help="Timeout in seconds")
@click.option("--json-output", "json_out", is_flag=True, help="Output as JSON")
def servers(
    interface: str | None,
    verbose: bool,
    timeout: float,
    json_out: bool,
):
    """Discover all DHCP servers on the network.

    Sends DHCPDISCOVER and collects all DHCPOFFER responses.
    Useful for detecting rogue DHCP servers.

    \b
    Examples:
        # Find all DHCP servers
        globaldetect dhcp servers -v

        # Extended timeout for slow networks
        globaldetect dhcp servers -t 15
    """
    import socket
    import random
    import struct

    from globaldetect.dhcp.client import (
        DHCPMessageType, DHCP_SERVER_PORT, DHCP_CLIENT_PORT,
        DHCP_MAGIC_COOKIE, BOOTREQUEST, HTYPE_ETHERNET, BOOTREPLY
    )

    config = DHCPConfig(interface=interface)
    client = DHCPClient(config=config, verbose=verbose)

    mac = client._get_mac_address(interface)
    xid = random.randint(0, 0xFFFFFFFF)

    if verbose:
        console.print(f"[dim]Discovering DHCP servers (timeout: {timeout}s)...[/dim]")

    packet = client._build_dhcp_packet(DHCPMessageType.DISCOVER, mac, xid)

    servers_found = []

    try:
        sock = client._create_socket(interface)
        sock.settimeout(1.0)  # Short timeout for polling

        sock.sendto(packet, ('255.255.255.255', DHCP_SERVER_PORT))

        import time
        start_time = time.time()

        while time.time() - start_time < timeout:
            try:
                data, addr = sock.recvfrom(4096)
                lease = client._parse_dhcp_packet(data, mac, xid)

                if lease:
                    msg_type = lease.all_options.get(53)  # MESSAGE_TYPE
                    if msg_type and msg_type[0] == DHCPMessageType.OFFER:
                        server_info = {
                            "server_ip": addr[0],
                            "server_id": lease.server_id,
                            "offered_ip": lease.ip_address,
                            "subnet_mask": lease.subnet_mask,
                            "gateway": lease.gateway,
                            "dns_servers": lease.dns_servers,
                            "lease_time": lease.lease_time,
                        }

                        # Check for duplicates
                        if not any(s["server_ip"] == addr[0] for s in servers_found):
                            servers_found.append(server_info)
                            if verbose:
                                console.print(f"[green]Found server: {addr[0]} (offers {lease.ip_address})[/green]")

            except socket.timeout:
                continue

    except PermissionError:
        console.print("[red]Error: Permission denied. Run as root or with CAP_NET_RAW capability.[/red]")
        sys.exit(1)
    finally:
        if 'sock' in locals():
            sock.close()

    if json_out:
        click.echo(json.dumps({"servers": servers_found}, indent=2))
        return

    if not servers_found:
        console.print("[yellow]No DHCP servers found.[/yellow]")
        return

    table = Table(title=f"DHCP Servers Found ({len(servers_found)})")
    table.add_column("Server IP", style="cyan")
    table.add_column("Server ID")
    table.add_column("Offered IP")
    table.add_column("Subnet")
    table.add_column("Gateway")
    table.add_column("Lease Time")

    for server in servers_found:
        table.add_row(
            server["server_ip"],
            server["server_id"] or "N/A",
            server["offered_ip"] or "N/A",
            server["subnet_mask"] or "N/A",
            server["gateway"] or "N/A",
            f"{server['lease_time']}s" if server.get("lease_time") else "N/A",
        )

    console.print(table)

    if len(servers_found) > 1:
        console.print()
        console.print("[yellow]Warning: Multiple DHCP servers detected. Check for rogue servers.[/yellow]")


if __name__ == "__main__":
    dhcp()
