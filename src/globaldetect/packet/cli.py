"""
CLI for packet crafting and protocol testing.

Copyright (c) 2025 DNS Science.io, an After Dark Systems, LLC company.
All rights reserved.
"""

import json
import sys
from datetime import datetime

import click
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from globaldetect.packet.protocols import (
    PROTOCOLS,
    SCAPY_AVAILABLE,
    list_protocols,
    get_protocol,
    ping,
    tcp_connect,
)
from globaldetect.packet.ntp import (
    NTPClient,
    NTPResponse,
    KNOWN_NTP_SERVERS,
    get_stratum_description,
    get_leap_description,
)

console = Console()


@click.group()
def packet():
    """Packet crafting and protocol testing.

    User-friendly interface for network protocol testing with
    pre-built templates. Uses scapy when available for advanced
    packet crafting.

    \b
    Examples:
        # List available protocols
        globaldetect packet protocols

        # Test NTP server
        globaldetect packet ntp pool.ntp.org

        # Ping with custom options
        globaldetect packet ping example.com -c 5

        # TCP connect test
        globaldetect packet tcp example.com 443
    """
    pass


@packet.command("protocols")
@click.option("--json-output", "json_out", is_flag=True, help="Output as JSON")
def list_protos(json_out: bool):
    """List available protocol templates.

    Shows all supported protocols with their parameters and requirements.
    """
    protocols = list_protocols()

    if json_out:
        click.echo(json.dumps(protocols, indent=2))
        return

    console.print(Panel(
        f"[bold]Scapy Available:[/bold] {'Yes' if SCAPY_AVAILABLE else 'No (some features disabled)'}",
        title="Protocol Templates"
    ))

    # Group by category
    categories = {}
    for proto in protocols:
        cat = proto["category"]
        if cat not in categories:
            categories[cat] = []
        categories[cat].append(proto)

    for category, protos in sorted(categories.items()):
        table = Table(title=f"{category.title()} Layer")
        table.add_column("Protocol", style="cyan")
        table.add_column("Description")
        table.add_column("Port", justify="right")
        table.add_column("Root", justify="center")
        table.add_column("Status")

        for proto in protos:
            status = "[green]Available[/green]" if proto["available"] else "[red]Unavailable[/red]"
            root = "[yellow]Yes[/yellow]" if proto["requires_root"] else "No"
            port = str(proto["default_port"]) if proto["default_port"] else "-"

            table.add_row(
                proto["name"],
                proto["description"][:40],
                port,
                root,
                status
            )

        console.print(table)
        console.print()


# ================================================================
# NTP Testing
# ================================================================

@packet.command()
@click.argument("server", required=False)
@click.option("--pool", "-p", type=click.Choice(["pool", "google", "cloudflare", "apple", "microsoft", "nist"]),
              help="Use well-known server pool")
@click.option("--timeout", "-t", type=float, default=5.0, help="Query timeout")
@click.option("--count", "-c", type=int, default=1, help="Number of queries")
@click.option("--all-pools", "-a", is_flag=True, help="Query all known NTP pools")
@click.option("--verbose", "-v", is_flag=True, help="Verbose output")
@click.option("--json-output", "json_out", is_flag=True, help="Output as JSON")
def ntp(
    server: str | None,
    pool: str | None,
    timeout: float,
    count: int,
    all_pools: bool,
    verbose: bool,
    json_out: bool,
):
    """Test NTP server(s).

    Query NTP servers to verify time synchronization, check
    server stratum, and measure clock offset.

    \b
    Examples:
        # Query specific server
        globaldetect packet ntp time.google.com

        # Query pool.ntp.org
        globaldetect packet ntp --pool pool

        # Query all known NTP pools
        globaldetect packet ntp --all-pools

        # Multiple queries for statistics
        globaldetect packet ntp pool.ntp.org -c 5
    """
    servers = []

    if all_pools:
        for pool_servers in KNOWN_NTP_SERVERS.values():
            servers.extend(pool_servers)
    elif pool:
        servers = KNOWN_NTP_SERVERS.get(pool, [])
    elif server:
        servers = [server]
    else:
        servers = ["pool.ntp.org"]

    client = NTPClient(timeout=timeout)
    results = []

    if not json_out:
        console.print(f"[dim]Querying {len(servers)} NTP server(s)...[/dim]")

    for srv in servers:
        for i in range(count):
            response = client.query(srv)
            results.append(response)

            if verbose and not json_out:
                display_ntp_response(response, verbose=True)

    if json_out:
        click.echo(json.dumps([r.to_dict() for r in results], indent=2))
        return

    # Summary table
    if len(results) > 1 or not verbose:
        table = Table(title="NTP Server Results")
        table.add_column("Server", style="cyan")
        table.add_column("Status")
        table.add_column("Stratum", justify="center")
        table.add_column("Offset (ms)", justify="right")
        table.add_column("Delay (ms)", justify="right")
        table.add_column("Response (ms)", justify="right")

        for resp in results:
            if resp.success:
                status = "[green]OK[/green]"
                offset = f"{resp.offset * 1000:.3f}" if resp.offset else "-"
                delay = f"{resp.delay * 1000:.3f}" if resp.delay else "-"
                rtt = f"{resp.response_time_ms:.1f}" if resp.response_time_ms else "-"
                stratum = str(resp.stratum) if resp.stratum is not None else "-"
            else:
                status = f"[red]{resp.error or 'Failed'}[/red]"
                offset = delay = rtt = stratum = "-"

            table.add_row(
                resp.server,
                status,
                stratum,
                offset,
                delay,
                rtt
            )

        console.print(table)

        # Statistics
        successful = [r for r in results if r.success]
        if successful:
            offsets = [r.offset for r in successful if r.offset is not None]
            if offsets:
                avg_offset = sum(offsets) / len(offsets) * 1000
                max_offset = max(abs(o) for o in offsets) * 1000
                console.print(f"\n[dim]Average offset: {avg_offset:.3f} ms, Max: {max_offset:.3f} ms[/dim]")


def display_ntp_response(resp: NTPResponse, verbose: bool = False):
    """Display a single NTP response."""
    if not resp.success:
        console.print(f"[red]{resp.server}: {resp.error}[/red]")
        return

    info = f"""[bold]{resp.server}[/bold]

[cyan]Server Time:[/cyan] {resp.server_time.strftime('%Y-%m-%d %H:%M:%S.%f UTC') if resp.server_time else 'N/A'}
[cyan]Stratum:[/cyan] {resp.stratum} ({get_stratum_description(resp.stratum)})
[cyan]Reference:[/cyan] {resp.reference_id}
[cyan]Leap:[/cyan] {get_leap_description(resp.leap_indicator)}

[cyan]Clock Offset:[/cyan] {resp.offset * 1000:.6f} ms
[cyan]Round Trip:[/cyan] {resp.delay * 1000:.3f} ms
[cyan]Response Time:[/cyan] {resp.response_time_ms:.1f} ms
"""

    if verbose:
        info += f"""
[dim]NTP Version: {resp.version}
Poll Interval: {resp.poll}
Precision: {resp.precision}
Reference Timestamp: {resp.reference_timestamp}
Originate Timestamp: {resp.originate_timestamp}
Receive Timestamp: {resp.receive_timestamp}
Transmit Timestamp: {resp.transmit_timestamp}[/dim]
"""

    console.print(Panel(info, title=f"NTP Response: {resp.server}"))


# ================================================================
# Ping / ICMP
# ================================================================

@packet.command("ping")
@click.argument("host")
@click.option("--count", "-c", type=int, default=4, help="Number of pings")
@click.option("--timeout", "-t", type=float, default=2.0, help="Timeout per ping")
@click.option("--json-output", "json_out", is_flag=True, help="Output as JSON")
def do_ping(host: str, count: int, timeout: float, json_out: bool):
    """Ping a host using ICMP or TCP fallback.

    Uses ICMP echo requests when available (requires root).
    Falls back to TCP connect probes if ICMP fails.

    \b
    Examples:
        # Basic ping
        globaldetect packet ping example.com

        # 10 pings with 1s timeout
        globaldetect packet ping example.com -c 10 -t 1
    """
    if not json_out:
        console.print(f"[dim]Pinging {host}...[/dim]")

    results = ping(host, timeout=timeout, count=count)

    if json_out:
        click.echo(json.dumps({"host": host, "results": results}, indent=2))
        return

    successful = [r for r in results if r["success"]]
    failed = len(results) - len(successful)

    for r in results:
        if r["success"]:
            rtt = r.get("rtt_ms", 0)
            method = r.get("type", "unknown")
            extra = f"port={r['port']}" if "port" in r else f"ttl={r.get('ttl', '-')}"
            console.print(f"  [green]Reply[/green] seq={r['seq']} time={rtt:.1f}ms ({method}) {extra}")
        else:
            console.print(f"  [red]Timeout[/red] seq={r['seq']}")

    # Statistics
    console.print()
    if successful:
        rtts = [r["rtt_ms"] for r in successful]
        console.print(f"[dim]--- {host} ping statistics ---[/dim]")
        console.print(f"{count} packets transmitted, {len(successful)} received, {failed * 100 // count}% packet loss")
        console.print(f"rtt min/avg/max = {min(rtts):.1f}/{sum(rtts)/len(rtts):.1f}/{max(rtts):.1f} ms")
    else:
        console.print(f"[red]All {count} pings failed[/red]")


# ================================================================
# TCP Testing
# ================================================================

@packet.command("tcp")
@click.argument("host")
@click.argument("port", type=int)
@click.option("--timeout", "-t", type=float, default=5.0, help="Connection timeout")
@click.option("--verbose", "-v", is_flag=True, help="Verbose output")
@click.option("--json-output", "json_out", is_flag=True, help="Output as JSON")
def do_tcp(host: str, port: int, timeout: float, verbose: bool, json_out: bool):
    """Test TCP connection to host:port.

    Attempts to establish TCP connection and optionally
    receive service banner.

    \b
    Examples:
        # Test SSH
        globaldetect packet tcp example.com 22

        # Test HTTPS with verbose
        globaldetect packet tcp example.com 443 -v
    """
    result = tcp_connect(host, port, timeout)

    if json_out:
        click.echo(json.dumps(result, indent=2))
        return

    if result["success"]:
        console.print(f"[green]Connected to {host}:{port}[/green]")
        console.print(f"  Connect time: {result.get('connect_time_ms', 0):.1f} ms")
        if "banner" in result:
            console.print(f"  Banner: {result['banner'][:100]}")
    else:
        console.print(f"[red]Connection failed: {result.get('error', 'Unknown error')}[/red]")


# ================================================================
# Advanced (Scapy-based)
# ================================================================

@packet.command("syn-scan")
@click.argument("host")
@click.argument("ports")
@click.option("--timeout", "-t", type=float, default=2.0, help="Timeout per port")
@click.option("--json-output", "json_out", is_flag=True, help="Output as JSON")
def syn_scan_cmd(host: str, ports: str, timeout: float, json_out: bool):
    """TCP SYN scan (half-open scan).

    Requires scapy and root privileges. More stealthy than
    full connect scan as it doesn't complete the handshake.

    PORTS can be: single (80), range (1-1000), or list (22,80,443)

    \b
    Examples:
        # Scan common ports
        globaldetect packet syn-scan example.com 22,80,443

        # Scan range
        globaldetect packet syn-scan example.com 1-100
    """
    if not SCAPY_AVAILABLE:
        console.print("[red]Error: SYN scan requires scapy. Install with: pip install scapy[/red]")
        sys.exit(1)

    from globaldetect.packet.protocols import syn_scan

    # Parse ports
    port_list = parse_ports(ports)

    if not json_out:
        console.print(f"[dim]SYN scanning {host} ({len(port_list)} ports)...[/dim]")

    try:
        results = syn_scan(host, port_list, timeout)
    except PermissionError:
        console.print("[red]Error: SYN scan requires root privileges[/red]")
        sys.exit(1)

    if json_out:
        click.echo(json.dumps({"host": host, "ports": results}, indent=2))
        return

    table = Table(title=f"SYN Scan Results: {host}")
    table.add_column("Port", style="cyan", justify="right")
    table.add_column("State")

    for port in sorted(port_list):
        state = results.get(port, "unknown")
        style = {"open": "green", "closed": "dim", "filtered": "yellow"}.get(state, "")
        table.add_row(str(port), f"[{style}]{state}[/{style}]")

    console.print(table)

    open_ports = [p for p, s in results.items() if s == "open"]
    console.print(f"\n[dim]{len(open_ports)} open port(s) found[/dim]")


@packet.command("arp-scan")
@click.argument("network")
@click.option("--timeout", "-t", type=float, default=2.0, help="Scan timeout")
@click.option("--json-output", "json_out", is_flag=True, help="Output as JSON")
def arp_scan_cmd(network: str, timeout: float, json_out: bool):
    """ARP scan to discover hosts on local network.

    Requires scapy and root privileges.

    \b
    Examples:
        # Scan local subnet
        globaldetect packet arp-scan 192.168.1.0/24

        # Scan smaller range
        globaldetect packet arp-scan 10.0.0.1-10
    """
    if not SCAPY_AVAILABLE:
        console.print("[red]Error: ARP scan requires scapy. Install with: pip install scapy[/red]")
        sys.exit(1)

    from globaldetect.packet.protocols import arp_scan

    if not json_out:
        console.print(f"[dim]ARP scanning {network}...[/dim]")

    try:
        results = arp_scan(network, timeout)
    except PermissionError:
        console.print("[red]Error: ARP scan requires root privileges[/red]")
        sys.exit(1)

    if json_out:
        click.echo(json.dumps({"network": network, "hosts": results}, indent=2))
        return

    if not results:
        console.print("[yellow]No hosts found[/yellow]")
        return

    table = Table(title=f"ARP Scan Results: {network}")
    table.add_column("IP Address", style="cyan")
    table.add_column("MAC Address")

    for host in results:
        table.add_row(host["ip"], host["mac"])

    console.print(table)
    console.print(f"\n[dim]{len(results)} host(s) discovered[/dim]")


def parse_ports(ports_str: str) -> list[int]:
    """Parse port specification string."""
    ports = []

    for part in ports_str.split(","):
        part = part.strip()
        if "-" in part:
            start, end = part.split("-")
            ports.extend(range(int(start), int(end) + 1))
        else:
            ports.append(int(part))

    return sorted(set(ports))


if __name__ == "__main__":
    packet()
