"""
Dark Web Intelligence CLI commands.

Copyright (c) 2025 DNS Science.io, an After Dark Systems, LLC company.
All rights reserved.
"""

import click
from rich.console import Console
from rich.table import Table
from rich.panel import Panel

from globaldetect.darkweb.core import (
    TorExitChecker,
    DarkWebChecker,
)


@click.group()
def darkweb():
    """Dark web intelligence utilities."""
    pass


@darkweb.command()
@click.argument("ip")
def tor(ip: str):
    """Check if an IP is a Tor exit node.

    Checks against multiple sources including:
    - Tor Project official exit list
    - OnionOO API
    - Tor exit DNSBLs

    Examples:
        globaldetect darkweb tor 185.220.101.1
        globaldetect darkweb tor 8.8.8.8
    """
    console = Console()
    checker = TorExitChecker()

    with console.status(f"[cyan]Checking if {ip} is a Tor exit node...[/cyan]"):
        result = checker.check(ip)

    if result.error:
        console.print(f"[red]Error:[/red] {result.error}")
        raise SystemExit(1)

    if result.is_tor_exit:
        console.print(f"\n[red]TOR EXIT NODE[/red]: {ip}\n")

        table = Table(show_header=False, box=None)
        table.add_column("Property", style="cyan")
        table.add_column("Value", style="white")

        table.add_row("IP Address", result.ip)
        table.add_row("Status", "[red]Tor Exit Node[/red]")

        if result.nickname:
            table.add_row("Nickname", result.nickname)
        if result.fingerprint:
            table.add_row("Fingerprint", result.fingerprint[:20] + "...")
        if result.bandwidth:
            table.add_row("Bandwidth", f"{result.bandwidth / 1024 / 1024:.1f} MB/s")
        if result.first_seen:
            table.add_row("First Seen", result.first_seen)
        if result.last_seen:
            table.add_row("Last Seen", result.last_seen)

        table.add_row("Sources", ", ".join(result.sources))

        console.print(table)
    else:
        console.print(f"\n[green]NOT A TOR EXIT[/green]: {ip}")
        console.print("[dim]IP was not found in any Tor exit node lists[/dim]")


@darkweb.command()
@click.argument("target")
def check(target: str):
    """Check IP or domain for dark web associations.

    Performs comprehensive dark web intelligence lookup:
    - Tor exit node detection
    - Proxy/anonymizer detection
    - Dark web threat intelligence
    - .onion association lookup

    Examples:
        globaldetect darkweb check 185.220.101.1
        globaldetect darkweb check suspicious-domain.com
        globaldetect darkweb check example.onion
    """
    console = Console()
    checker = DarkWebChecker()

    with console.status(f"[cyan]Checking {target} for dark web associations...[/cyan]"):
        result = checker.check(target)

    if result.error:
        console.print(f"[red]Error:[/red] {result.error}")
        raise SystemExit(1)

    # Determine overall status
    if result.risk_score >= 70:
        status_color = "red"
        status_text = "HIGH RISK"
    elif result.risk_score >= 40:
        status_color = "yellow"
        status_text = "MEDIUM RISK"
    elif result.risk_score > 0:
        status_color = "orange1"
        status_text = "LOW RISK"
    else:
        status_color = "green"
        status_text = "CLEAN"

    console.print(f"\n[cyan]Dark Web Intelligence: {target}[/cyan]\n")

    table = Table(show_header=False, box=None)
    table.add_column("Property", style="cyan")
    table.add_column("Value", style="white")

    table.add_row("Target", result.target)
    table.add_row("Type", result.target_type)
    table.add_row("Risk Score", f"[{status_color}]{result.risk_score}/100 ({status_text})[/{status_color}]")

    table.add_row("", "")

    # Flags
    tor_exit = "[red]Yes[/red]" if result.is_tor_exit else "[green]No[/green]"
    tor_relay = "[yellow]Yes[/yellow]" if result.is_tor_relay else "[green]No[/green]"
    proxy = "[yellow]Yes[/yellow]" if result.is_proxy else "[green]No[/green]"
    vpn = "[yellow]Yes[/yellow]" if result.is_vpn else "[green]No[/green]"
    onion = "[red]Yes[/red]" if result.has_onion_association else "[green]No[/green]"

    table.add_row("Tor Exit Node", tor_exit)
    table.add_row("Tor Relay", tor_relay)
    table.add_row("Proxy/Anonymizer", proxy)
    table.add_row("VPN", vpn)
    table.add_row(".onion Association", onion)

    if result.sources:
        table.add_row("", "")
        table.add_row("Sources", ", ".join(set(result.sources)))

    console.print(table)

    # Threat indicators
    if result.threat_indicators:
        console.print("\n[red]Threat Indicators:[/red]")
        for indicator in result.threat_indicators:
            console.print(f"  [!] {indicator}")

    # Onion addresses
    if result.onion_addresses:
        console.print("\n[cyan]Associated .onion addresses:[/cyan]")
        for onion in result.onion_addresses[:10]:
            console.print(f"  {onion}")


@darkweb.command()
@click.argument("ips", nargs=-1, required=True)
def batch(ips: tuple[str, ...]):
    """Check multiple IPs for Tor exit status.

    Examples:
        globaldetect darkweb batch 185.220.101.1 185.220.101.2 185.220.101.3
    """
    console = Console()
    checker = TorExitChecker()

    console.print(f"\n[cyan]Batch Tor Exit Check ({len(ips)} IPs)[/cyan]\n")

    table = Table(box=None)
    table.add_column("IP", style="white", width=20)
    table.add_column("Status", width=20)
    table.add_column("Nickname", style="dim", width=20)
    table.add_column("Sources", style="dim", width=30)

    import asyncio

    async def check_all():
        tasks = [checker.check_async(ip) for ip in ips]
        return await asyncio.gather(*tasks)

    with console.status("[cyan]Checking IPs...[/cyan]"):
        results = asyncio.run(check_all())

    tor_count = 0
    for result in results:
        if result.is_tor_exit:
            tor_count += 1
            status = "[red]TOR EXIT[/red]"
        else:
            status = "[green]Clean[/green]"

        table.add_row(
            result.ip,
            status,
            result.nickname or "-",
            ", ".join(result.sources) if result.sources else "-",
        )

    console.print(table)
    console.print(f"\n[cyan]Summary:[/cyan] {tor_count} of {len(ips)} IPs are Tor exit nodes")
