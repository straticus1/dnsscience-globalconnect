"""
IP/CIDR CLI commands.
"""

import click
from rich.console import Console
from rich.table import Table
from rich.panel import Panel

from globaldetect.ip.core import (
    get_ip_info,
    calculate_subnet,
    summarize_cidrs,
    split_cidr,
    is_bogon,
    is_private,
    CIDROperations,
    SubnetCalculator,
)


@click.group()
def ip():
    """IP address and CIDR utilities."""
    pass


@ip.command()
@click.argument("address")
@click.option("--geoip", is_flag=True, help="Fetch extended GeoIP data from IPInfo.io")
def info(address: str, geoip: bool):
    """Get detailed information about an IP address or CIDR.

    Examples:
        globaldetect ip info 8.8.8.8
        globaldetect ip info 192.168.1.0/24
        globaldetect ip info 2001:4860:4860::8888
        globaldetect ip info 8.8.8.8 --geoip
    """
    console = Console()

    try:
        ip_info = get_ip_info(address)
    except Exception as e:
        console.print(f"[red]Error:[/red] {e}")
        raise SystemExit(1)

    table = Table(title=f"IP Information: {address}", show_header=False, box=None)
    table.add_column("Property", style="cyan")
    table.add_column("Value", style="white")

    table.add_row("Address", ip_info.address)
    table.add_row("Version", f"IPv{ip_info.version}")
    table.add_row("Reverse DNS", ip_info.reverse_dns)

    # Flags
    flags = []
    if ip_info.is_private:
        flags.append("[yellow]Private[/yellow]")
    if ip_info.is_loopback:
        flags.append("[blue]Loopback[/blue]")
    if ip_info.is_multicast:
        flags.append("[magenta]Multicast[/magenta]")
    if ip_info.is_link_local:
        flags.append("[cyan]Link-Local[/cyan]")
    if ip_info.is_reserved:
        flags.append("[red]Reserved[/red]")
    if ip_info.is_bogon:
        flags.append("[red]Bogon[/red]")

    if flags:
        table.add_row("Flags", " ".join(flags))
    else:
        table.add_row("Flags", "[green]Globally Routable[/green]")

    # Network info if CIDR
    if ip_info.network:
        table.add_row("", "")
        table.add_row("Network", ip_info.network)
        table.add_row("Broadcast", ip_info.broadcast)
        table.add_row("Netmask", ip_info.netmask)
        table.add_row("Hostmask", ip_info.hostmask)
        table.add_row("Prefix Length", f"/{ip_info.prefix_length}")
        table.add_row("Total Addresses", f"{ip_info.num_addresses:,}")
        if ip_info.first_host:
            table.add_row("First Host", ip_info.first_host)
            table.add_row("Last Host", ip_info.last_host)

    # Extended GeoIP lookup
    if geoip and not ip_info.is_private and not ip_info.is_bogon:
        table.add_row("", "")
        table.add_row("[cyan bold]GeoIP Data[/cyan bold]", "")

        with console.status("[cyan]Fetching GeoIP data...[/cyan]"):
            try:
                from globaldetect.services.ipinfo import IPInfoClient
                client = IPInfoClient()
                # Extract just the IP (not CIDR) for lookup
                lookup_ip = address.split("/")[0]
                geo_result = client.lookup(lookup_ip)

                if geo_result.error:
                    table.add_row("Error", f"[red]{geo_result.error}[/red]")
                else:
                    if geo_result.hostname:
                        table.add_row("Hostname", geo_result.hostname)
                    if geo_result.city:
                        table.add_row("City", geo_result.city)
                    if geo_result.region:
                        table.add_row("Region", geo_result.region)
                    if geo_result.country:
                        table.add_row("Country", geo_result.country)
                    if geo_result.loc:
                        table.add_row("Coordinates", geo_result.loc)
                    if geo_result.postal:
                        table.add_row("Postal", geo_result.postal)
                    if geo_result.timezone:
                        table.add_row("Timezone", geo_result.timezone)
                    if geo_result.org:
                        table.add_row("Organization", geo_result.org)
                    if geo_result.asn:
                        table.add_row("ASN", f"AS{geo_result.asn}")
                    if geo_result.as_name:
                        table.add_row("AS Name", geo_result.as_name)

                    # Privacy indicators
                    privacy_flags = []
                    if geo_result.is_vpn:
                        privacy_flags.append("[yellow]VPN[/yellow]")
                    if geo_result.is_proxy:
                        privacy_flags.append("[yellow]Proxy[/yellow]")
                    if geo_result.is_tor:
                        privacy_flags.append("[red]Tor[/red]")
                    if geo_result.is_hosting:
                        privacy_flags.append("[blue]Hosting[/blue]")
                    if privacy_flags:
                        table.add_row("Privacy", " ".join(privacy_flags))
            except ImportError:
                table.add_row("Error", "[red]IPInfo client not available[/red]")
            except Exception as e:
                table.add_row("Error", f"[red]{e}[/red]")
    elif geoip and (ip_info.is_private or ip_info.is_bogon):
        table.add_row("", "")
        table.add_row("[dim]GeoIP[/dim]", "[dim]Not available for private/bogon addresses[/dim]")

    console.print(table)


@ip.command()
@click.argument("cidr")
def calc(cidr: str):
    """Calculate subnet information from CIDR notation.

    Examples:
        globaldetect ip calc 10.0.0.0/8
        globaldetect ip calc 172.16.0.0/12
        globaldetect ip calc 2001:db8::/32
    """
    console = Console()

    try:
        subnet = calculate_subnet(cidr)
    except Exception as e:
        console.print(f"[red]Error:[/red] {e}")
        raise SystemExit(1)

    table = Table(title=f"Subnet Calculator: {cidr}", show_header=False, box=None)
    table.add_column("Property", style="cyan")
    table.add_column("Value", style="white")

    table.add_row("Network", subnet.network)
    table.add_row("Broadcast", subnet.broadcast)
    table.add_row("Netmask", subnet.netmask)
    table.add_row("Hostmask", subnet.hostmask)
    table.add_row("Prefix Length", f"/{subnet.prefix_length}")
    table.add_row("Total Addresses", f"{subnet.num_addresses:,}")
    table.add_row("Usable Hosts", f"{subnet.num_hosts:,}")

    if subnet.first_host:
        table.add_row("First Host", subnet.first_host)
        table.add_row("Last Host", subnet.last_host)

    console.print(table)


@ip.command()
@click.argument("cidr")
@click.argument("new_prefix", type=int)
def split(cidr: str, new_prefix: int):
    """Split a CIDR into smaller subnets.

    Examples:
        globaldetect ip split 10.0.0.0/8 /16
        globaldetect ip split 192.168.0.0/24 28
    """
    console = Console()

    try:
        subnets = split_cidr(cidr, new_prefix)
    except Exception as e:
        console.print(f"[red]Error:[/red] {e}")
        raise SystemExit(1)

    console.print(f"[cyan]Splitting {cidr} into /{new_prefix} subnets:[/cyan]")
    console.print(f"[dim]Total subnets: {len(subnets):,}[/dim]\n")

    # Limit output for very large splits
    if len(subnets) > 256:
        console.print("[yellow]Showing first 256 subnets...[/yellow]\n")
        for subnet in subnets[:256]:
            console.print(subnet)
        console.print(f"\n[dim]... and {len(subnets) - 256:,} more[/dim]")
    else:
        for subnet in subnets:
            console.print(subnet)


@ip.command()
@click.argument("cidrs", nargs=-1, required=True)
def summarize(cidrs: tuple[str, ...]):
    """Summarize/aggregate multiple CIDRs into minimum set.

    Examples:
        globaldetect ip summarize 192.168.0.0/24 192.168.1.0/24
        globaldetect ip summarize 10.0.0.0/24 10.0.1.0/24 10.0.2.0/24 10.0.3.0/24
    """
    console = Console()

    try:
        result = summarize_cidrs(list(cidrs))
    except Exception as e:
        console.print(f"[red]Error:[/red] {e}")
        raise SystemExit(1)

    console.print(f"[cyan]Input CIDRs:[/cyan] {len(cidrs)}")
    console.print(f"[cyan]Summarized:[/cyan] {len(result)}\n")

    for cidr in result:
        console.print(cidr)


@ip.command()
@click.argument("cidr")
@click.argument("address")
def contains(cidr: str, address: str):
    """Check if a CIDR contains an IP address or subnet.

    Examples:
        globaldetect ip contains 10.0.0.0/8 10.1.2.3
        globaldetect ip contains 192.168.0.0/16 192.168.1.0/24
    """
    console = Console()

    try:
        result = CIDROperations.contains(cidr, address)
    except Exception as e:
        console.print(f"[red]Error:[/red] {e}")
        raise SystemExit(1)

    if result:
        console.print(f"[green]Yes[/green] - {address} is within {cidr}")
    else:
        console.print(f"[red]No[/red] - {address} is not within {cidr}")


@ip.command()
@click.argument("cidr1")
@click.argument("cidr2")
def overlap(cidr1: str, cidr2: str):
    """Check if two CIDRs overlap.

    Examples:
        globaldetect ip overlap 10.0.0.0/8 10.1.0.0/16
        globaldetect ip overlap 192.168.0.0/24 192.168.1.0/24
    """
    console = Console()

    try:
        result = CIDROperations.overlap(cidr1, cidr2)
    except Exception as e:
        console.print(f"[red]Error:[/red] {e}")
        raise SystemExit(1)

    if result:
        console.print(f"[yellow]Yes[/yellow] - {cidr1} and {cidr2} overlap")
    else:
        console.print(f"[green]No[/green] - {cidr1} and {cidr2} do not overlap")


@ip.command()
@click.argument("cidr1")
@click.argument("cidr2")
def diff(cidr1: str, cidr2: str):
    """Subtract one CIDR from another (cidr1 - cidr2).

    Examples:
        globaldetect ip diff 10.0.0.0/8 10.1.0.0/16
    """
    console = Console()

    try:
        result = CIDROperations.difference(cidr1, cidr2)
    except Exception as e:
        console.print(f"[red]Error:[/red] {e}")
        raise SystemExit(1)

    console.print(f"[cyan]{cidr1} - {cidr2} =[/cyan]\n")

    if not result:
        console.print("[dim]Empty set (cidr2 completely contains cidr1)[/dim]")
    else:
        for cidr in result:
            console.print(cidr)


@ip.command()
@click.argument("addresses", nargs=-1, required=True)
def check(addresses: tuple[str, ...]):
    """Check if IP addresses are bogons or private.

    Examples:
        globaldetect ip check 8.8.8.8 192.168.1.1 10.0.0.1
    """
    console = Console()

    table = Table(title="IP Address Check", box=None)
    table.add_column("Address", style="white")
    table.add_column("Bogon", style="white")
    table.add_column("Private", style="white")
    table.add_column("Status", style="white")

    for addr in addresses:
        try:
            bogon = is_bogon(addr)
            private = is_private(addr)

            bogon_str = "[red]Yes[/red]" if bogon else "[green]No[/green]"
            private_str = "[yellow]Yes[/yellow]" if private else "[green]No[/green]"

            if bogon:
                status = "[red]Should not appear on public internet[/red]"
            elif private:
                status = "[yellow]RFC1918 private space[/yellow]"
            else:
                status = "[green]Globally routable[/green]"

            table.add_row(addr, bogon_str, private_str, status)
        except Exception as e:
            table.add_row(addr, "[red]Error[/red]", "[red]Error[/red]", f"[red]{e}[/red]")

    console.print(table)
