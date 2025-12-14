"""
Diagnostics CLI commands.
"""

import click
from rich.console import Console
from rich.table import Table
from rich.live import Live

from globaldetect.diag.core import (
    ping,
    traceroute,
    mtu_discover,
    port_check,
    COMMON_PORTS,
)


@click.group()
def diag():
    """Network diagnostics utilities."""
    pass


@diag.command()
@click.argument("host")
@click.option("-c", "--count", default=4, help="Number of pings to send")
@click.option("-t", "--timeout", default=5.0, help="Timeout per ping in seconds")
def ping_cmd(host: str, count: int, timeout: float):
    """Ping a host and show statistics.

    Examples:
        globaldetect diag ping 8.8.8.8
        globaldetect diag ping google.com -c 10
    """
    console = Console()

    with console.status(f"[cyan]Pinging {host}...[/cyan]"):
        result = ping(host, count, timeout)

    if result.error:
        console.print(f"[red]Error:[/red] {result.error}")
        raise SystemExit(1)

    table = Table(title=f"Ping: {host}", show_header=False, box=None)
    table.add_column("Property", style="cyan")
    table.add_column("Value", style="white")

    table.add_row("Host", host)
    if result.ip:
        table.add_row("IP", result.ip)
    table.add_row("Packets Sent", str(result.packets_sent))
    table.add_row("Packets Received", str(result.packets_received))

    loss_color = "green" if result.packet_loss == 0 else "yellow" if result.packet_loss < 50 else "red"
    table.add_row("Packet Loss", f"[{loss_color}]{result.packet_loss:.1f}%[/{loss_color}]")

    table.add_row("", "")
    table.add_row("Min RTT", f"{result.min_ms:.2f} ms")
    table.add_row("Avg RTT", f"{result.avg_ms:.2f} ms")
    table.add_row("Max RTT", f"{result.max_ms:.2f} ms")
    if result.stddev_ms:
        table.add_row("Std Dev", f"{result.stddev_ms:.2f} ms")

    console.print(table)


# Alias for ping
ping_cmd.name = "ping"


@diag.command()
@click.argument("host")
@click.option("-m", "--max-hops", default=30, help="Maximum number of hops")
@click.option("-t", "--timeout", default=3.0, help="Timeout per hop in seconds")
@click.option("--no-as", is_flag=True, help="Don't resolve AS information")
@click.option("--geoip", is_flag=True, help="Include GeoIP information for each hop")
def trace(host: str, max_hops: int, timeout: float, no_as: bool, geoip: bool):
    """Perform a traceroute to a host.

    Examples:
        globaldetect diag trace 8.8.8.8
        globaldetect diag trace google.com -m 20
        globaldetect diag trace 1.1.1.1 --geoip
    """
    console = Console()

    status_msg = f"[cyan]Tracing route to {host}..."
    if geoip:
        status_msg += " (with GeoIP lookup)"
    status_msg += "[/cyan]"

    with console.status(status_msg):
        hops = traceroute(host, max_hops, timeout, resolve_as=not no_as, resolve_geoip=geoip)

    if not hops:
        console.print(f"[yellow]No route found to {host}[/yellow]")
        return

    table = Table(title=f"Traceroute: {host}", box=None)
    table.add_column("Hop", style="cyan", width=4)
    table.add_column("IP", style="white", width=16)
    table.add_column("Hostname", style="dim", width=30)
    table.add_column("RTT", style="white", width=24)

    if geoip:
        table.add_column("Location", style="yellow", width=25)
        table.add_column("Org/ASN", style="dim", width=25)

    for hop in hops:
        if hop.is_timeout:
            row = [
                str(hop.hop_number),
                "*",
                "[dim]Request timed out[/dim]",
                "* * *",
            ]
            if geoip:
                row.extend(["-", "-"])
            table.add_row(*row)
        else:
            rtt_str = "  ".join([f"{rtt:.1f}ms" for rtt in hop.rtt_ms])
            row = [
                str(hop.hop_number),
                hop.ip or "-",
                hop.hostname or "-",
                rtt_str or "-",
            ]
            if geoip:
                # Build location string
                loc_parts = []
                if hop.city:
                    loc_parts.append(hop.city)
                if hop.region:
                    loc_parts.append(hop.region)
                if hop.country:
                    loc_parts.append(hop.country)
                location = ", ".join(loc_parts) if loc_parts else "-"

                # Build org/ASN string
                org_str = hop.org or "-"
                row.extend([location, org_str])

            table.add_row(*row)

    console.print(table)


@diag.command()
@click.argument("host")
@click.option("--start", default=1500, help="Starting MTU to test")
@click.option("--min", "min_mtu", default=68, help="Minimum MTU to consider")
def mtu(host: str, start: int, min_mtu: int):
    """Discover path MTU to a host.

    Examples:
        globaldetect diag mtu 8.8.8.8
        globaldetect diag mtu google.com --start 9000
    """
    console = Console()

    with console.status(f"[cyan]Discovering MTU to {host}...[/cyan]"):
        result = mtu_discover(host, start, min_mtu)

    if result.error:
        console.print(f"[red]Error:[/red] {result.error}")
        raise SystemExit(1)

    console.print(f"[cyan]Path MTU to {host}:[/cyan] [green]{result.mtu}[/green] bytes")

    # Provide context
    if result.mtu >= 1500:
        console.print("[dim]Standard Ethernet MTU or larger[/dim]")
    elif result.mtu >= 1492:
        console.print("[dim]PPPoE typical MTU[/dim]")
    elif result.mtu >= 1400:
        console.print("[dim]VPN/tunnel overhead likely[/dim]")
    else:
        console.print("[yellow]Unusually low MTU - potential issues[/yellow]")


@diag.command()
@click.argument("host")
@click.option("-p", "--ports", help="Comma-separated list of ports to check")
@click.option("--common", is_flag=True, help="Check common ports")
@click.option("-t", "--timeout", default=3.0, help="Timeout per port in seconds")
def ports(host: str, ports: str | None, common: bool, timeout: float):
    """Check if ports are open on a host.

    Examples:
        globaldetect diag ports 192.168.1.1 -p 22,80,443
        globaldetect diag ports example.com --common
    """
    console = Console()

    # Determine ports to scan
    if ports:
        port_list = [int(p.strip()) for p in ports.split(",")]
    elif common:
        port_list = COMMON_PORTS
    else:
        console.print("[yellow]Please specify ports with -p or use --common[/yellow]")
        raise SystemExit(1)

    with console.status(f"[cyan]Checking {len(port_list)} ports on {host}...[/cyan]"):
        results = port_check(host, port_list, timeout)

    # Sort by port number
    sorted_ports = sorted(results.items())

    # Count open/closed
    open_count = sum(1 for _, is_open in sorted_ports if is_open)
    closed_count = len(sorted_ports) - open_count

    console.print(f"\n[cyan]Port Scan Results for {host}[/cyan]")
    console.print(f"[green]Open:[/green] {open_count}  [red]Closed:[/red] {closed_count}\n")

    table = Table(box=None)
    table.add_column("Port", style="cyan", width=8)
    table.add_column("Status", style="white", width=10)
    table.add_column("Service", style="dim", width=20)

    # Common port to service mapping
    port_services = {
        21: "FTP",
        22: "SSH",
        23: "Telnet",
        25: "SMTP",
        53: "DNS",
        80: "HTTP",
        110: "POP3",
        143: "IMAP",
        443: "HTTPS",
        465: "SMTPS",
        587: "Submission",
        993: "IMAPS",
        995: "POP3S",
        3306: "MySQL",
        3389: "RDP",
        5432: "PostgreSQL",
        6379: "Redis",
        8080: "HTTP-Alt",
        8443: "HTTPS-Alt",
    }

    for port, is_open in sorted_ports:
        status = "[green]OPEN[/green]" if is_open else "[red]CLOSED[/red]"
        service = port_services.get(port, "-")
        table.add_row(str(port), status, service)

    console.print(table)


@diag.command()
@click.argument("host")
def lookup(host: str):
    """Resolve a hostname to IP addresses.

    Examples:
        globaldetect diag lookup google.com
        globaldetect diag lookup github.com
    """
    console = Console()
    import socket

    try:
        # Get all addresses
        results = socket.getaddrinfo(host, None, socket.AF_UNSPEC, socket.SOCK_STREAM)

        # Deduplicate
        ipv4 = set()
        ipv6 = set()

        for family, _, _, _, sockaddr in results:
            if family == socket.AF_INET:
                ipv4.add(sockaddr[0])
            elif family == socket.AF_INET6:
                ipv6.add(sockaddr[0])

        console.print(f"[cyan]DNS Resolution for {host}:[/cyan]\n")

        if ipv4:
            console.print("[cyan]IPv4:[/cyan]")
            for ip in sorted(ipv4):
                console.print(f"  {ip}")

        if ipv6:
            console.print("\n[cyan]IPv6:[/cyan]")
            for ip in sorted(ipv6):
                console.print(f"  {ip}")

        if not ipv4 and not ipv6:
            console.print("[yellow]No addresses found[/yellow]")

    except socket.gaierror as e:
        console.print(f"[red]Error:[/red] {e}")
        raise SystemExit(1)
