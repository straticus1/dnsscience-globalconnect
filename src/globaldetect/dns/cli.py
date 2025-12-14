"""
DNS CLI commands.
"""

import click
from rich.console import Console
from rich.table import Table
from rich.panel import Panel

from globaldetect.dns.core import (
    lookup,
    lookup_all,
    reverse_lookup,
    check_propagation,
    get_nameservers,
    get_mx_records,
    trace_delegation,
)


@click.group()
def dns():
    """DNS utilities."""
    pass


@dns.command()
@click.argument("name")
@click.option("-t", "--type", "record_type", default="A", help="Record type (A, AAAA, MX, NS, TXT, etc.)")
@click.option("-s", "--server", help="DNS server to query")
def query(name: str, record_type: str, server: str | None):
    """Perform a DNS lookup.

    Examples:
        globaldetect dns query google.com
        globaldetect dns query google.com -t MX
        globaldetect dns query google.com -t NS -s 8.8.8.8
    """
    console = Console()

    records = lookup(name, record_type.upper(), server)

    if not records:
        console.print(f"[yellow]No {record_type} records found for {name}[/yellow]")
        return

    table = Table(title=f"DNS Lookup: {name}", box=None)
    table.add_column("Type", style="cyan")
    table.add_column("TTL", style="dim")
    table.add_column("Value", style="white")
    if record_type.upper() == "MX":
        table.add_column("Priority", style="dim")

    for record in records:
        if record_type.upper() == "MX":
            table.add_row(record.record_type, str(record.ttl), record.value, str(record.priority))
        else:
            table.add_row(record.record_type, str(record.ttl), record.value)

    console.print(table)


@dns.command()
@click.argument("name")
@click.option("-s", "--server", help="DNS server to query")
def all(name: str, server: str | None):
    """Lookup all common record types for a domain.

    Examples:
        globaldetect dns all google.com
        globaldetect dns all example.org -s 1.1.1.1
    """
    console = Console()

    with console.status(f"[cyan]Looking up all records for {name}...[/cyan]"):
        results = lookup_all(name, server)

    if not results:
        console.print(f"[yellow]No records found for {name}[/yellow]")
        return

    for record_type, records in results.items():
        console.print(f"\n[cyan]{record_type} Records:[/cyan]")

        for record in records:
            if record_type == "MX":
                console.print(f"  [{record.priority}] {record.value} (TTL: {record.ttl})")
            else:
                console.print(f"  {record.value} (TTL: {record.ttl})")


@dns.command()
@click.argument("ip")
@click.option("-s", "--server", help="DNS server to query")
def reverse(ip: str, server: str | None):
    """Perform a reverse DNS lookup.

    Examples:
        globaldetect dns reverse 8.8.8.8
        globaldetect dns reverse 2001:4860:4860::8888
    """
    console = Console()

    results = reverse_lookup(ip, server)

    if not results:
        console.print(f"[yellow]No PTR records found for {ip}[/yellow]")
        return

    console.print(f"[cyan]Reverse DNS for {ip}:[/cyan]")
    for ptr in results:
        console.print(f"  {ptr}")


@dns.command()
@click.argument("name")
@click.option("-t", "--type", "record_type", default="A", help="Record type to check")
def propagation(name: str, record_type: str):
    """Check DNS propagation across public resolvers.

    Examples:
        globaldetect dns propagation example.com
        globaldetect dns propagation example.com -t MX
    """
    console = Console()

    with console.status(f"[cyan]Checking propagation for {name}...[/cyan]"):
        results = check_propagation(name, record_type.upper())

    # Group by success/failure
    successful = [r for r in results if r.success]
    failed = [r for r in results if not r.success]

    # Calculate consistency
    all_records = [tuple(sorted(r.records)) for r in successful]
    unique_answers = set(all_records)

    if len(unique_answers) <= 1:
        status = "[green]Consistent[/green]"
    else:
        status = "[yellow]Inconsistent[/yellow]"

    console.print(f"\n[cyan]Propagation Status:[/cyan] {status}")
    console.print(f"[cyan]Servers Checked:[/cyan] {len(results)}")
    console.print(f"[cyan]Responding:[/cyan] {len(successful)}")
    console.print(f"[cyan]Failed:[/cyan] {len(failed)}\n")

    # Show results table
    table = Table(title=f"{record_type} Propagation: {name}", box=None)
    table.add_column("Provider", style="cyan")
    table.add_column("Server", style="dim")
    table.add_column("Status", style="white")
    table.add_column("Response", style="white")
    table.add_column("Time", style="dim")

    for result in results:
        if result.success:
            status_str = "[green]OK[/green]"
            response = ", ".join(result.records[:3])
            if len(result.records) > 3:
                response += f" (+{len(result.records) - 3} more)"
        else:
            status_str = "[red]FAIL[/red]"
            response = result.error or "Unknown error"

        time_str = f"{result.response_time_ms:.0f}ms" if result.response_time_ms else "-"

        table.add_row(
            result.server_name,
            result.server,
            status_str,
            response,
            time_str,
        )

    console.print(table)

    # Show unique answers if inconsistent
    if len(unique_answers) > 1:
        console.print("\n[yellow]Warning: Different answers detected:[/yellow]")
        for i, answer in enumerate(unique_answers, 1):
            console.print(f"  Answer {i}: {', '.join(answer) if answer else '(empty)'}")


@dns.command()
@click.argument("domain")
def ns(domain: str):
    """Get nameservers for a domain.

    Examples:
        globaldetect dns ns google.com
        globaldetect dns ns cloudflare.com
    """
    console = Console()

    nameservers = get_nameservers(domain)

    if not nameservers:
        console.print(f"[yellow]No nameservers found for {domain}[/yellow]")
        return

    console.print(f"[cyan]Nameservers for {domain}:[/cyan]")
    for ns in sorted(nameservers):
        console.print(f"  {ns}")


@dns.command()
@click.argument("domain")
def mx(domain: str):
    """Get MX records for a domain.

    Examples:
        globaldetect dns mx google.com
        globaldetect dns mx microsoft.com
    """
    console = Console()

    mx_records = get_mx_records(domain)

    if not mx_records:
        console.print(f"[yellow]No MX records found for {domain}[/yellow]")
        return

    console.print(f"[cyan]MX Records for {domain}:[/cyan]")
    table = Table(box=None)
    table.add_column("Priority", style="cyan")
    table.add_column("Mail Server", style="white")

    for priority, server in mx_records:
        table.add_row(str(priority), server)

    console.print(table)


@dns.command()
@click.argument("domain")
def trace(domain: str):
    """Trace DNS delegation from root servers.

    Examples:
        globaldetect dns trace example.com
        globaldetect dns trace www.google.com
    """
    console = Console()

    with console.status(f"[cyan]Tracing delegation for {domain}...[/cyan]"):
        trace_results = trace_delegation(domain)

    console.print(f"\n[cyan]DNS Delegation Trace: {domain}[/cyan]\n")

    for i, step in enumerate(trace_results):
        zone = step["zone"]
        console.print(f"[cyan]{i + 1}. Zone: {zone}[/cyan]")

        if step.get("error"):
            console.print(f"   [red]Error: {step['error']}[/red]")
        else:
            if step["ns_records"]:
                console.print(f"   NS Records:")
                for ns in step["ns_records"][:5]:
                    console.print(f"     {ns}")

            if step["glue_records"]:
                console.print(f"   Glue Records:")
                for glue in step["glue_records"][:5]:
                    console.print(f"     {glue['ns']} -> {glue['ip']}")

        console.print()
