"""
RBL/Blacklist CLI commands.

Copyright (c) 2025 DNS Science.io, an After Dark Systems, LLC company.
All rights reserved.
"""

import click
from rich.console import Console
from rich.table import Table
from rich.progress import Progress, SpinnerColumn, TextColumn

from globaldetect.rbl.core import (
    RBLChecker,
    DomainBlacklistChecker,
    RBL_PROVIDERS,
    DNSBL_PROVIDERS,
)


@click.group()
def rbl():
    """RBL/Blacklist lookup utilities."""
    pass


@rbl.command()
@click.argument("ip")
@click.option("--quick", is_flag=True, help="Check only major RBLs (faster)")
@click.option("--timeout", default=3.0, help="Timeout per lookup in seconds")
def check(ip: str, quick: bool, timeout: float):
    """Check an IP address against RBL providers.

    Supports both IPv4 and IPv6 addresses.

    Examples:
        globaldetect rbl check 8.8.8.8
        globaldetect rbl check 2001:4860:4860::8888
        globaldetect rbl check 192.168.1.1 --quick
    """
    console = Console()
    checker = RBLChecker(timeout=timeout)

    # Quick mode uses only major RBLs
    if quick:
        providers = [
            "zen.spamhaus.org",
            "b.barracudacentral.org",
            "bl.spamcop.net",
            "dnsbl.sorbs.net",
            "cbl.abuseat.org",
            "dnsbl.dronebl.org",
            "psbl.surriel.com",
            "dnsbl-1.uceprotect.net",
        ]
    else:
        providers = None

    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        console=console,
    ) as progress:
        num_rbls = len(providers) if providers else len(RBL_PROVIDERS)
        progress.add_task(f"Checking {ip} against {num_rbls} RBLs...", total=None)
        result = checker.check_all(ip, providers)

    # Display results
    if result.is_ipv6:
        console.print(f"\n[cyan]IPv6 RBL Check: {ip}[/cyan]")
        console.print("[dim]Note: Many RBLs do not support IPv6[/dim]\n")
    else:
        console.print(f"\n[cyan]RBL Check: {ip}[/cyan]\n")

    # Summary
    if result.total_listed == 0:
        console.print(f"[green]CLEAN[/green] - Not listed on any of {result.total_checked} RBLs checked\n")
    else:
        console.print(f"[red]LISTED[/red] on {result.total_listed} of {result.total_checked} RBLs\n")

        # Show listings
        table = Table(title="Blacklist Listings", box=None)
        table.add_column("RBL", style="red", width=30)
        table.add_column("Type", style="dim", width=12)
        table.add_column("Code", style="dim", width=15)
        table.add_column("Details", style="white", width=50, overflow="ellipsis")

        for listing in result.listings:
            details = listing.txt_record or "-"
            table.add_row(
                listing.rbl_name,
                listing.rbl_type or "-",
                listing.return_code or "-",
                details[:50],
            )

        console.print(table)

    # Show errors if any
    if result.errors:
        console.print(f"\n[yellow]Errors ({len(result.errors)}):[/yellow]")
        for err in result.errors[:5]:
            console.print(f"  {err.rbl}: {err.error}")
        if len(result.errors) > 5:
            console.print(f"  ... and {len(result.errors) - 5} more errors")


@rbl.command()
@click.argument("domain")
@click.option("--timeout", default=3.0, help="Timeout per lookup in seconds")
def domain(domain: str, timeout: float):
    """Check a domain against domain blacklists (DBL).

    Examples:
        globaldetect rbl domain example.com
        globaldetect rbl domain suspicious-site.xyz
    """
    console = Console()
    checker = DomainBlacklistChecker(timeout=timeout)

    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        console=console,
    ) as progress:
        progress.add_task(f"Checking {domain} against {len(DNSBL_PROVIDERS)} DNSBLs...", total=None)
        result = checker.check_all(domain)

    console.print(f"\n[cyan]Domain Blacklist Check: {domain}[/cyan]\n")

    if result.total_listed == 0:
        console.print(f"[green]CLEAN[/green] - Not listed on any of {result.total_checked} DNSBLs\n")
    else:
        console.print(f"[red]LISTED[/red] on {result.total_listed} of {result.total_checked} DNSBLs\n")

        table = Table(title="Blacklist Listings", box=None)
        table.add_column("DNSBL", style="red", width=30)
        table.add_column("Type", style="dim", width=12)
        table.add_column("Code", style="dim", width=15)
        table.add_column("Details", style="white", width=50)

        for listing in result.listings:
            table.add_row(
                listing.rbl_name,
                listing.rbl_type or "-",
                listing.return_code or "-",
                listing.txt_record or "-",
            )

        console.print(table)


@rbl.command(name="list")
@click.option("--ipv6", is_flag=True, help="Show only IPv6-capable RBLs")
@click.option("--type", "rbl_type", help="Filter by type (spam, exploit, policy, proxy)")
def list_rbls(ipv6: bool, rbl_type: str | None):
    """List available RBL providers.

    Examples:
        globaldetect rbl list
        globaldetect rbl list --ipv6
        globaldetect rbl list --type spam
    """
    console = Console()

    table = Table(title="Available RBL Providers", box=None)
    table.add_column("RBL", style="cyan", width=35)
    table.add_column("Name", style="white", width=25)
    table.add_column("Type", style="dim", width=12)
    table.add_column("IPv6", style="dim", width=6)
    table.add_column("Description", style="dim", width=40, overflow="ellipsis")

    for rbl, info in sorted(RBL_PROVIDERS.items()):
        if ipv6 and not info.get("ipv6", False):
            continue
        if rbl_type and info.get("type") != rbl_type:
            continue

        ipv6_str = "[green]Yes[/green]" if info.get("ipv6") else "[dim]No[/dim]"
        table.add_row(
            rbl,
            info.get("name", "-"),
            info.get("type", "-"),
            ipv6_str,
            info.get("description", "-"),
        )

    console.print(table)
    console.print(f"\nTotal: {len(RBL_PROVIDERS)} IP RBLs, {len(DNSBL_PROVIDERS)} Domain DNSBLs")


@rbl.command()
@click.argument("ip")
@click.argument("rbl")
def single(ip: str, rbl: str):
    """Check an IP against a specific RBL.

    Examples:
        globaldetect rbl single 8.8.8.8 zen.spamhaus.org
        globaldetect rbl single 192.168.1.1 b.barracudacentral.org
    """
    console = Console()
    checker = RBLChecker()

    with console.status(f"[cyan]Checking {ip} on {rbl}...[/cyan]"):
        result = checker.check_single(ip, rbl)

    if result.error:
        console.print(f"[yellow]Error:[/yellow] {result.error}")
        return

    if result.listed:
        console.print(f"[red]LISTED[/red] on {result.rbl_name}")
        if result.return_code:
            console.print(f"  Return code: {result.return_code}")
        if result.txt_record:
            console.print(f"  Details: {result.txt_record}")
    else:
        console.print(f"[green]NOT LISTED[/green] on {result.rbl_name}")

    console.print(f"  Response time: {result.response_time_ms:.1f}ms")


@rbl.command()
@click.argument("ips", nargs=-1, required=True)
@click.option("--quick", is_flag=True, help="Check only major RBLs")
def batch(ips: tuple[str, ...], quick: bool):
    """Check multiple IPs against RBLs.

    Examples:
        globaldetect rbl batch 8.8.8.8 1.1.1.1 9.9.9.9
        globaldetect rbl batch 192.168.1.1 10.0.0.1 --quick
    """
    console = Console()
    checker = RBLChecker()

    if quick:
        providers = [
            "zen.spamhaus.org",
            "b.barracudacentral.org",
            "bl.spamcop.net",
            "cbl.abuseat.org",
        ]
    else:
        providers = list(RBL_PROVIDERS.keys())[:20]  # Limit for batch

    console.print(f"\n[cyan]Batch RBL Check ({len(ips)} IPs, {len(providers)} RBLs each)[/cyan]\n")

    table = Table(box=None)
    table.add_column("IP", style="white", width=20)
    table.add_column("Status", width=15)
    table.add_column("Listed On", style="dim", width=50)

    import asyncio

    async def check_all_ips():
        tasks = [checker.check_all_async(ip, providers) for ip in ips]
        return await asyncio.gather(*tasks)

    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        console=console,
    ) as progress:
        progress.add_task("Checking IPs...", total=None)
        results = asyncio.run(check_all_ips())

    for result in results:
        if result.total_listed == 0:
            status = "[green]CLEAN[/green]"
            listed_on = "-"
        else:
            status = f"[red]LISTED ({result.total_listed})[/red]"
            listed_on = ", ".join([l.rbl_name for l in result.listings[:3]])
            if result.total_listed > 3:
                listed_on += f" +{result.total_listed - 3} more"

        table.add_row(result.target, status, listed_on)

    console.print(table)
