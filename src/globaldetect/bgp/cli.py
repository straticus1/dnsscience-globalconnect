"""
BGP/Routing CLI commands.
"""

import asyncio

import click
from rich.console import Console
from rich.table import Table
from rich.panel import Panel

from globaldetect.bgp.core import (
    get_as_info,
    get_prefix_info,
    get_whois_info,
    PeeringDBClient,
    get_as_info_async,
)


@click.group()
def bgp():
    """BGP and routing utilities."""
    pass


@bgp.command()
@click.argument("asn")
def asinfo(asn: str):
    """Get information about an Autonomous System.

    Examples:
        globaldetect bgp asinfo 15169
        globaldetect bgp asinfo AS13335
    """
    console = Console()

    # Parse ASN
    try:
        asn_int = int(asn.upper().replace("AS", ""))
    except ValueError:
        console.print(f"[red]Error:[/red] Invalid ASN: {asn}")
        raise SystemExit(1)

    with console.status(f"[cyan]Fetching AS{asn_int} information...[/cyan]"):
        try:
            info = get_as_info(asn_int)
        except Exception as e:
            console.print(f"[red]Error:[/red] {e}")
            raise SystemExit(1)

    # Main info panel
    table = Table(title=f"AS{info.asn} - {info.name or 'Unknown'}", show_header=False, box=None)
    table.add_column("Property", style="cyan")
    table.add_column("Value", style="white")

    table.add_row("ASN", f"AS{info.asn}")
    if info.name:
        table.add_row("Name", info.name)
    if info.description:
        table.add_row("Description", info.description)
    if info.country:
        table.add_row("Country", info.country)
    if info.rir:
        table.add_row("RIR", info.rir)
    if info.network_type:
        table.add_row("Network Type", info.network_type)
    if info.traffic_levels:
        table.add_row("Traffic Level", info.traffic_levels)
    if info.traffic_ratios:
        table.add_row("Traffic Ratio", info.traffic_ratios)
    if info.website:
        table.add_row("Website", info.website)
    if info.abuse_contact:
        table.add_row("Abuse Contact", info.abuse_contact)
    if info.looking_glass:
        table.add_row("Looking Glass", info.looking_glass)

    table.add_row("", "")
    table.add_row("IPv4 Prefixes", str(info.prefixes_v4))
    table.add_row("IPv6 Prefixes", str(info.prefixes_v6))
    table.add_row("IX Presence", str(info.ix_count))

    console.print(table)

    # Show IXs if present
    if info.ixs:
        console.print("\n[cyan]Internet Exchange Points:[/cyan]")
        ix_table = Table(box=None)
        ix_table.add_column("IX Name", style="white")
        ix_table.add_column("IPv4", style="dim")
        ix_table.add_column("IPv6", style="dim")
        ix_table.add_column("Speed", style="dim")

        for ix in info.ixs[:20]:  # Limit display
            speed = f"{ix.get('speed', 0) // 1000}G" if ix.get('speed') else "-"
            ix_table.add_row(
                ix.get("name", "-"),
                ix.get("ipv4") or "-",
                ix.get("ipv6") or "-",
                speed,
            )

        console.print(ix_table)

        if len(info.ixs) > 20:
            console.print(f"[dim]... and {len(info.ixs) - 20} more IXs[/dim]")


@bgp.command()
@click.argument("asn")
def prefixes(asn: str):
    """List prefixes announced by an AS.

    Examples:
        globaldetect bgp prefixes 15169
        globaldetect bgp prefixes AS13335
    """
    console = Console()

    try:
        asn_int = int(asn.upper().replace("AS", ""))
    except ValueError:
        console.print(f"[red]Error:[/red] Invalid ASN: {asn}")
        raise SystemExit(1)

    with console.status(f"[cyan]Fetching prefixes for AS{asn_int}...[/cyan]"):
        try:
            info = get_as_info(asn_int)
        except Exception as e:
            console.print(f"[red]Error:[/red] {e}")
            raise SystemExit(1)

    console.print(f"[cyan]AS{asn_int}[/cyan] announces [green]{info.prefixes_v4}[/green] IPv4 and [blue]{info.prefixes_v6}[/blue] IPv6 prefixes\n")

    if info.prefixes:
        for prefix in info.prefixes:
            console.print(prefix)

        if info.prefixes_v4 + info.prefixes_v6 > 50:
            console.print(f"\n[dim]Showing first 50 of {info.prefixes_v4 + info.prefixes_v6} prefixes[/dim]")
    else:
        console.print("[dim]No prefixes found[/dim]")


@bgp.command()
@click.argument("prefix")
def prefix(prefix: str):
    """Get information about an IP prefix.

    Examples:
        globaldetect bgp prefix 8.8.8.0/24
        globaldetect bgp prefix 2001:4860::/32
    """
    console = Console()

    with console.status(f"[cyan]Fetching prefix information...[/cyan]"):
        try:
            info = get_prefix_info(prefix)
        except Exception as e:
            console.print(f"[red]Error:[/red] {e}")
            raise SystemExit(1)

    table = Table(title=f"Prefix: {info.prefix}", show_header=False, box=None)
    table.add_column("Property", style="cyan")
    table.add_column("Value", style="white")

    table.add_row("Prefix", info.prefix)
    if info.asn:
        table.add_row("Origin AS", f"AS{info.asn}")
    if info.as_name:
        table.add_row("AS Name", info.as_name)
    if info.description:
        table.add_row("Description", info.description)
    if info.country:
        table.add_row("Country", info.country)
    if info.rir:
        table.add_row("RIR", info.rir)
    if info.parent_prefix:
        table.add_row("Parent Prefix", info.parent_prefix)

    console.print(table)

    if info.related_prefixes:
        console.print("\n[cyan]Related Prefixes:[/cyan]")
        for p in info.related_prefixes[:10]:
            console.print(f"  {p}")
        if len(info.related_prefixes) > 10:
            console.print(f"[dim]  ... and {len(info.related_prefixes) - 10} more[/dim]")


@bgp.command()
@click.argument("query")
def whois(query: str):
    """Perform a WHOIS lookup.

    Examples:
        globaldetect bgp whois AS15169
        globaldetect bgp whois 8.8.8.8
    """
    console = Console()

    with console.status(f"[cyan]Querying WHOIS...[/cyan]"):
        result = get_whois_info(query)

    console.print(Panel(result, title=f"WHOIS: {query}", border_style="dim"))


@bgp.command()
@click.argument("query")
def ixsearch(query: str):
    """Search for Internet Exchanges.

    Examples:
        globaldetect bgp ixsearch "DE-CIX"
        globaldetect bgp ixsearch "Los Angeles"
    """
    console = Console()

    async def search():
        pdb = PeeringDBClient()
        return await pdb.search_ix(query)

    with console.status(f"[cyan]Searching for IXs...[/cyan]"):
        results = asyncio.run(search())

    if not results:
        console.print(f"[yellow]No IXs found matching '{query}'[/yellow]")
        return

    table = Table(title=f"IX Search: {query}", box=None)
    table.add_column("Name", style="white")
    table.add_column("City", style="dim")
    table.add_column("Country", style="dim")
    table.add_column("Participants", style="cyan")

    for ix in results[:25]:
        table.add_row(
            ix.get("name", "-"),
            ix.get("city", "-"),
            ix.get("country", "-"),
            str(ix.get("net_count", 0)),
        )

    console.print(table)

    if len(results) > 25:
        console.print(f"\n[dim]Showing 25 of {len(results)} results[/dim]")


@bgp.command()
@click.argument("asns", nargs=-1, required=True)
def compare(asns: tuple[str, ...]):
    """Compare multiple ASNs side by side.

    Examples:
        globaldetect bgp compare AS15169 AS13335 AS32934
    """
    console = Console()

    if len(asns) < 2:
        console.print("[red]Error:[/red] Please provide at least 2 ASNs to compare")
        raise SystemExit(1)

    # Parse ASNs
    asn_list = []
    for asn in asns:
        try:
            asn_list.append(int(asn.upper().replace("AS", "")))
        except ValueError:
            console.print(f"[red]Error:[/red] Invalid ASN: {asn}")
            raise SystemExit(1)

    async def fetch_all():
        return await asyncio.gather(*[get_as_info_async(asn) for asn in asn_list])

    with console.status("[cyan]Fetching AS information...[/cyan]"):
        results = asyncio.run(fetch_all())

    table = Table(title="AS Comparison", box=None)
    table.add_column("Property", style="cyan")
    for info in results:
        table.add_column(f"AS{info.asn}", style="white")

    table.add_row("Name", *[info.name or "-" for info in results])
    table.add_row("Country", *[info.country or "-" for info in results])
    table.add_row("Network Type", *[info.network_type or "-" for info in results])
    table.add_row("Traffic Level", *[info.traffic_levels or "-" for info in results])
    table.add_row("IPv4 Prefixes", *[str(info.prefixes_v4) for info in results])
    table.add_row("IPv6 Prefixes", *[str(info.prefixes_v6) for info in results])
    table.add_row("IX Presence", *[str(info.ix_count) for info in results])

    console.print(table)
