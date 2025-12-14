"""
Firewall CLI commands.

Copyright (c) 2025 DNS Science.io, an After Dark Systems, LLC company.
All rights reserved.
"""

import json
import sys
from pathlib import Path

import click
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.syntax import Syntax
from rich.tree import Tree

from globaldetect.firewall.models import (
    FirewallPolicy,
    FirewallVendor,
    RuleAction,
    Protocol,
)
from globaldetect.firewall.parsers.base import FirewallParser
from globaldetect.firewall.parsers.iptables import IptablesParser, Ip6tablesParser
from globaldetect.firewall.parsers.ipfilter import IpfilterParser, OpenBSDPfParser
from globaldetect.firewall.parsers.checkpoint import CheckpointParser

console = Console()


@click.group()
def firewall():
    """Firewall rule parsing and analysis.

    Parse and analyze firewall rules from various formats including
    iptables-save, ipfilter, and Checkpoint exports.
    """
    pass


@firewall.command("parse")
@click.argument("file", type=click.Path(exists=True))
@click.option(
    "--format", "-f",
    type=click.Choice(["auto", "iptables", "ip6tables", "ipfilter", "pf", "checkpoint"]),
    default="auto",
    help="Input format (auto-detect by default)"
)
@click.option("--json", "-j", "output_json", is_flag=True, help="Output as JSON")
@click.option("--summary", "-s", is_flag=True, help="Show summary only")
def parse_file(file: str, format: str, output_json: bool, summary: bool):
    """Parse firewall rules from a file.

    FILE is the path to the firewall export file.
    """
    path = Path(file)
    content = path.read_text()

    # Select parser
    if format == "auto":
        vendor = FirewallParser.detect_format(content)
        if not vendor:
            console.print("[red]Could not auto-detect firewall format[/red]")
            sys.exit(1)
    else:
        format_map = {
            "iptables": FirewallVendor.IPTABLES,
            "ip6tables": FirewallVendor.IPTABLES,
            "ipfilter": FirewallVendor.IPFILTER,
            "pf": FirewallVendor.PF,
            "checkpoint": FirewallVendor.CHECKPOINT,
        }
        vendor = format_map[format]

    # Get parser
    parser_map = {
        FirewallVendor.IPTABLES: IptablesParser() if format != "ip6tables" else Ip6tablesParser(),
        FirewallVendor.IPFILTER: IpfilterParser(),
        FirewallVendor.PF: OpenBSDPfParser(),
        FirewallVendor.CHECKPOINT: CheckpointParser(),
    }

    parser = parser_map.get(vendor)
    if not parser:
        console.print(f"[red]No parser available for {vendor}[/red]")
        sys.exit(1)

    # Parse
    policy = parser.parse(content)
    policy.name = path.name

    if output_json:
        _output_policy_json(policy)
    elif summary:
        _output_policy_summary(policy)
    else:
        _output_policy_detail(policy)


@firewall.command("analyze")
@click.argument("file", type=click.Path(exists=True))
@click.option(
    "--format", "-f",
    type=click.Choice(["auto", "iptables", "ip6tables", "ipfilter", "pf", "checkpoint"]),
    default="auto",
    help="Input format"
)
@click.option("--check-permissive", is_flag=True, help="Find overly permissive rules")
@click.option("--check-port", type=int, help="Find rules matching specific port")
@click.option("--check-address", type=str, help="Find rules matching specific address")
@click.option("--check-shadows", is_flag=True, help="Find potentially shadowed rules")
def analyze_rules(
    file: str,
    format: str,
    check_permissive: bool,
    check_port: int | None,
    check_address: str | None,
    check_shadows: bool
):
    """Analyze firewall rules for issues.

    Performs various security and configuration checks on firewall rules.
    """
    path = Path(file)
    content = path.read_text()

    # Parse
    if format == "auto":
        policy = FirewallParser.auto_parse(content)
    else:
        vendor_map = {
            "iptables": FirewallVendor.IPTABLES,
            "ip6tables": FirewallVendor.IPTABLES,
            "ipfilter": FirewallVendor.IPFILTER,
            "pf": FirewallVendor.PF,
            "checkpoint": FirewallVendor.CHECKPOINT,
        }
        parser = FirewallParser.get_parser(vendor_map[format])
        policy = parser.parse(content)

    console.print(Panel(f"[bold]Firewall Analysis: {path.name}[/bold]"))
    console.print()

    issues_found = False

    # Check for permissive rules
    if check_permissive or not any([check_port, check_address, check_shadows]):
        permissive = policy.find_permissive_rules()
        if permissive:
            issues_found = True
            console.print("[yellow]Overly Permissive Rules Found:[/yellow]")
            table = Table()
            table.add_column("Rule #", style="cyan")
            table.add_column("Action", style="green")
            table.add_column("Source")
            table.add_column("Destination")
            table.add_column("Comment")

            for rule in permissive:
                table.add_row(
                    str(rule.rule_number or "-"),
                    rule.action.value,
                    str(rule.source) if rule.source else "any",
                    str(rule.destination) if rule.destination else "any",
                    rule.comment or "-"
                )

            console.print(table)
            console.print()
        else:
            console.print("[green]No overly permissive rules found[/green]")
            console.print()

    # Check for rules matching specific port
    if check_port:
        port_rules = policy.find_rules_by_port(check_port)
        if port_rules:
            issues_found = True
            console.print(f"[cyan]Rules matching port {check_port}:[/cyan]")
            table = Table()
            table.add_column("Rule #", style="cyan")
            table.add_column("Action", style="green")
            table.add_column("Protocol")
            table.add_column("Source")
            table.add_column("Destination")
            table.add_column("Port")

            for rule in port_rules:
                port_str = ""
                if rule.destination_port:
                    port_str = str(rule.destination_port)

                table.add_row(
                    str(rule.rule_number or "-"),
                    rule.action.value,
                    rule.protocol.value,
                    str(rule.source) if rule.source else "any",
                    str(rule.destination) if rule.destination else "any",
                    port_str
                )

            console.print(table)
            console.print()
        else:
            console.print(f"[dim]No rules found matching port {check_port}[/dim]")
            console.print()

    # Check for rules matching specific address
    if check_address:
        addr_rules = policy.find_rules_by_address(check_address)
        if addr_rules:
            console.print(f"[cyan]Rules matching address {check_address}:[/cyan]")
            table = Table()
            table.add_column("Rule #", style="cyan")
            table.add_column("Action", style="green")
            table.add_column("Source")
            table.add_column("Destination")
            table.add_column("Protocol")

            for rule in addr_rules:
                table.add_row(
                    str(rule.rule_number or "-"),
                    rule.action.value,
                    str(rule.source) if rule.source else "any",
                    str(rule.destination) if rule.destination else "any",
                    rule.protocol.value
                )

            console.print(table)
            console.print()
        else:
            console.print(f"[dim]No rules found matching address {check_address}[/dim]")
            console.print()

    # Check for shadowed rules
    if check_shadows:
        shadows = _find_shadowed_rules(policy)
        if shadows:
            issues_found = True
            console.print("[yellow]Potentially Shadowed Rules:[/yellow]")
            for shadow_info in shadows:
                console.print(
                    f"  Rule #{shadow_info['rule'].rule_number} may be shadowed by "
                    f"rule #{shadow_info['shadowed_by'].rule_number}"
                )
            console.print()
        else:
            console.print("[green]No shadowed rules detected[/green]")
            console.print()

    if not issues_found:
        console.print("[green]No issues found in firewall rules[/green]")


@firewall.command("compare")
@click.argument("file1", type=click.Path(exists=True))
@click.argument("file2", type=click.Path(exists=True))
@click.option(
    "--format", "-f",
    type=click.Choice(["auto", "iptables", "ipfilter", "checkpoint"]),
    default="auto",
    help="Input format"
)
def compare_rules(file1: str, file2: str, format: str):
    """Compare two firewall rule sets.

    Shows differences between two firewall configurations.
    """
    path1 = Path(file1)
    path2 = Path(file2)

    # Parse both files
    if format == "auto":
        policy1 = FirewallParser.auto_parse(path1.read_text())
        policy2 = FirewallParser.auto_parse(path2.read_text())
    else:
        vendor_map = {
            "iptables": FirewallVendor.IPTABLES,
            "ipfilter": FirewallVendor.IPFILTER,
            "checkpoint": FirewallVendor.CHECKPOINT,
        }
        parser = FirewallParser.get_parser(vendor_map[format])
        policy1 = parser.parse(path1.read_text())
        policy2 = parser.parse(path2.read_text())

    console.print(Panel(f"[bold]Comparing: {path1.name} vs {path2.name}[/bold]"))
    console.print()

    # Compare basic stats
    table = Table(title="Summary Comparison")
    table.add_column("Metric")
    table.add_column(path1.name, style="cyan")
    table.add_column(path2.name, style="green")

    table.add_row(
        "Total Rules",
        str(policy1.rule_count()),
        str(policy2.rule_count())
    )
    table.add_row(
        "Tables",
        str(len(policy1.tables)),
        str(len(policy2.tables))
    )
    table.add_row(
        "Chains",
        str(len(policy1.all_chains())),
        str(len(policy2.all_chains()))
    )
    table.add_row(
        "Permissive Rules",
        str(len(policy1.find_permissive_rules())),
        str(len(policy2.find_permissive_rules()))
    )

    console.print(table)
    console.print()

    # Compare chains
    chains1 = {c.name for c in policy1.all_chains()}
    chains2 = {c.name for c in policy2.all_chains()}

    only_in_1 = chains1 - chains2
    only_in_2 = chains2 - chains1

    if only_in_1:
        console.print(f"[yellow]Chains only in {path1.name}:[/yellow] {', '.join(only_in_1)}")
    if only_in_2:
        console.print(f"[yellow]Chains only in {path2.name}:[/yellow] {', '.join(only_in_2)}")

    if not only_in_1 and not only_in_2:
        console.print("[green]Both files have the same chains[/green]")


@firewall.command("export")
@click.argument("file", type=click.Path(exists=True))
@click.option(
    "--format", "-f",
    type=click.Choice(["auto", "iptables", "ipfilter", "checkpoint"]),
    default="auto",
    help="Input format"
)
@click.option(
    "--output-format", "-o",
    type=click.Choice(["json", "csv", "markdown"]),
    default="json",
    help="Output format"
)
@click.option("--output", type=click.Path(), help="Output file path")
def export_rules(file: str, format: str, output_format: str, output: str | None):
    """Export firewall rules to different formats.

    Convert parsed firewall rules to JSON, CSV, or Markdown.
    """
    path = Path(file)

    # Parse
    if format == "auto":
        policy = FirewallParser.auto_parse(path.read_text())
    else:
        vendor_map = {
            "iptables": FirewallVendor.IPTABLES,
            "ipfilter": FirewallVendor.IPFILTER,
            "checkpoint": FirewallVendor.CHECKPOINT,
        }
        parser = FirewallParser.get_parser(vendor_map[format])
        policy = parser.parse(path.read_text())

    if output_format == "json":
        result = _export_json(policy)
    elif output_format == "csv":
        result = _export_csv(policy)
    elif output_format == "markdown":
        result = _export_markdown(policy)
    else:
        result = ""

    if output:
        Path(output).write_text(result)
        console.print(f"[green]Exported to {output}[/green]")
    else:
        console.print(result)


@firewall.command("show")
@click.argument("file", type=click.Path(exists=True))
@click.option(
    "--format", "-f",
    type=click.Choice(["auto", "iptables", "ipfilter", "checkpoint"]),
    default="auto",
    help="Input format"
)
@click.option("--table", "-t", "table_name", help="Show specific table")
@click.option("--chain", "-c", "chain_name", help="Show specific chain")
@click.option("--rule", "-r", "rule_number", type=int, help="Show specific rule")
def show_rules(
    file: str,
    format: str,
    table_name: str | None,
    chain_name: str | None,
    rule_number: int | None
):
    """Show firewall rules in detail.

    Display parsed firewall rules with filtering options.
    """
    path = Path(file)

    # Parse
    if format == "auto":
        policy = FirewallParser.auto_parse(path.read_text())
    else:
        vendor_map = {
            "iptables": FirewallVendor.IPTABLES,
            "ipfilter": FirewallVendor.IPFILTER,
            "checkpoint": FirewallVendor.CHECKPOINT,
        }
        parser = FirewallParser.get_parser(vendor_map[format])
        policy = parser.parse(path.read_text())

    # Filter tables
    tables_to_show = policy.tables
    if table_name:
        if table_name in policy.tables:
            tables_to_show = {table_name: policy.tables[table_name]}
        else:
            console.print(f"[red]Table '{table_name}' not found[/red]")
            return

    for tbl_name, table in tables_to_show.items():
        console.print(Panel(f"[bold]Table: {tbl_name}[/bold]"))

        # Filter chains
        chains_to_show = table.chains
        if chain_name:
            if chain_name in table.chains:
                chains_to_show = {chain_name: table.chains[chain_name]}
            else:
                continue

        for chn_name, chain in chains_to_show.items():
            policy_str = f" (policy: {chain.policy.value})" if chain.policy else ""
            console.print(f"\n[cyan]Chain: {chn_name}[/cyan]{policy_str}")

            if not chain.rules:
                console.print("  [dim]No rules[/dim]")
                continue

            rules_table = Table(show_header=True)
            rules_table.add_column("#", style="dim")
            rules_table.add_column("Action", style="green")
            rules_table.add_column("Proto")
            rules_table.add_column("Source")
            rules_table.add_column("Dest")
            rules_table.add_column("Ports")
            rules_table.add_column("Options")

            for rule in chain.rules:
                if rule_number and rule.rule_number != rule_number:
                    continue

                # Build options string
                options = []
                if rule.state:
                    options.append(f"state:{','.join(rule.state)}")
                if rule.in_interface:
                    options.append(f"in:{rule.in_interface}")
                if rule.out_interface:
                    options.append(f"out:{rule.out_interface}")
                if rule.comment:
                    options.append(f'"{rule.comment}"')

                # Build ports string
                ports = []
                if rule.source_port:
                    ports.append(f"sport:{rule.source_port}")
                if rule.destination_port:
                    ports.append(f"dport:{rule.destination_port}")

                rules_table.add_row(
                    str(rule.rule_number or "-"),
                    rule.action.value,
                    rule.protocol.value,
                    str(rule.source) if rule.source else "any",
                    str(rule.destination) if rule.destination else "any",
                    " ".join(ports) if ports else "-",
                    " ".join(options) if options else "-"
                )

            console.print(rules_table)


# ==========================================================================
# Helper functions
# ==========================================================================

def _output_policy_json(policy: FirewallPolicy) -> None:
    """Output policy as JSON."""
    data = {
        "vendor": policy.vendor.value,
        "name": policy.name,
        "generated_at": policy.generated_at,
        "version": policy.version,
        "rule_count": policy.rule_count(),
        "tables": {}
    }

    for table_name, table in policy.tables.items():
        data["tables"][table_name] = {
            "chains": {}
        }
        for chain_name, chain in table.chains.items():
            data["tables"][table_name]["chains"][chain_name] = {
                "policy": chain.policy.value if chain.policy else None,
                "rules": [
                    {
                        "number": r.rule_number,
                        "action": r.action.value,
                        "protocol": r.protocol.value,
                        "source": str(r.source) if r.source else None,
                        "destination": str(r.destination) if r.destination else None,
                        "source_port": str(r.source_port) if r.source_port else None,
                        "destination_port": str(r.destination_port) if r.destination_port else None,
                        "comment": r.comment,
                    }
                    for r in chain.rules
                ]
            }

    console.print(json.dumps(data, indent=2))


def _output_policy_summary(policy: FirewallPolicy) -> None:
    """Output policy summary."""
    console.print(Panel(f"[bold]Firewall Policy Summary[/bold]"))
    console.print()

    table = Table(show_header=False)
    table.add_column("Property", style="cyan")
    table.add_column("Value")

    table.add_row("Vendor", policy.vendor.value)
    table.add_row("Name", policy.name or "-")
    table.add_row("Generated", policy.generated_at or "-")
    table.add_row("Version", policy.version or "-")
    table.add_row("Total Rules", str(policy.rule_count()))
    table.add_row("Tables", str(len(policy.tables)))
    table.add_row("Chains", str(len(policy.all_chains())))

    console.print(table)
    console.print()

    # Per-table summary
    for table_name, tbl in policy.tables.items():
        console.print(f"[cyan]Table: {table_name}[/cyan]")
        for chain_name, chain in tbl.chains.items():
            policy_str = f" ({chain.policy.value})" if chain.policy else ""
            console.print(f"  {chain_name}: {len(chain.rules)} rules{policy_str}")
        console.print()


def _output_policy_detail(policy: FirewallPolicy) -> None:
    """Output detailed policy view."""
    _output_policy_summary(policy)

    # Show rules
    for table_name, table in policy.tables.items():
        for chain_name, chain in table.chains.items():
            if not chain.rules:
                continue

            console.print(f"[bold cyan]{table_name} / {chain_name}[/bold cyan]")

            rules_table = Table()
            rules_table.add_column("#", style="dim")
            rules_table.add_column("Action", style="green")
            rules_table.add_column("Protocol")
            rules_table.add_column("Source")
            rules_table.add_column("Destination")
            rules_table.add_column("Ports")

            for rule in chain.rules[:20]:  # Limit display
                ports = []
                if rule.destination_port:
                    ports.append(str(rule.destination_port))

                rules_table.add_row(
                    str(rule.rule_number or "-"),
                    rule.action.value,
                    rule.protocol.value,
                    str(rule.source) if rule.source else "any",
                    str(rule.destination) if rule.destination else "any",
                    ",".join(ports) if ports else "-"
                )

            console.print(rules_table)

            if len(chain.rules) > 20:
                console.print(f"  [dim]... and {len(chain.rules) - 20} more rules[/dim]")

            console.print()


def _find_shadowed_rules(policy: FirewallPolicy) -> list[dict]:
    """Find potentially shadowed rules.

    A rule is shadowed if a more general rule appears before it.
    """
    shadows = []

    for chain in policy.all_chains():
        for i, rule in enumerate(chain.rules):
            # Check if any previous rule shadows this one
            for j in range(i):
                prev_rule = chain.rules[j]

                # Basic shadow detection:
                # If prev rule is more general and has same action, this rule may be shadowed
                if prev_rule.action == rule.action:
                    if prev_rule.matches_any_source() and not rule.matches_any_source():
                        shadows.append({
                            "rule": rule,
                            "shadowed_by": prev_rule,
                            "reason": "Previous rule matches any source"
                        })
                    elif prev_rule.matches_any_destination() and not rule.matches_any_destination():
                        shadows.append({
                            "rule": rule,
                            "shadowed_by": prev_rule,
                            "reason": "Previous rule matches any destination"
                        })

    return shadows


def _export_json(policy: FirewallPolicy) -> str:
    """Export policy to JSON."""
    data = {
        "vendor": policy.vendor.value,
        "name": policy.name,
        "rules": []
    }

    for rule in policy.all_rules():
        data["rules"].append({
            "number": rule.rule_number,
            "action": rule.action.value,
            "protocol": rule.protocol.value,
            "source": str(rule.source) if rule.source else None,
            "destination": str(rule.destination) if rule.destination else None,
            "source_port": str(rule.source_port) if rule.source_port else None,
            "destination_port": str(rule.destination_port) if rule.destination_port else None,
            "in_interface": rule.in_interface,
            "out_interface": rule.out_interface,
            "comment": rule.comment,
        })

    return json.dumps(data, indent=2)


def _export_csv(policy: FirewallPolicy) -> str:
    """Export policy to CSV."""
    lines = ["number,action,protocol,source,destination,src_port,dst_port,in_if,out_if,comment"]

    for rule in policy.all_rules():
        line = ",".join([
            str(rule.rule_number or ""),
            rule.action.value,
            rule.protocol.value,
            str(rule.source) if rule.source else "",
            str(rule.destination) if rule.destination else "",
            str(rule.source_port) if rule.source_port else "",
            str(rule.destination_port) if rule.destination_port else "",
            rule.in_interface or "",
            rule.out_interface or "",
            f'"{rule.comment}"' if rule.comment else "",
        ])
        lines.append(line)

    return "\n".join(lines)


def _export_markdown(policy: FirewallPolicy) -> str:
    """Export policy to Markdown."""
    lines = [
        f"# Firewall Policy: {policy.name or 'Unknown'}",
        "",
        f"**Vendor:** {policy.vendor.value}",
        f"**Total Rules:** {policy.rule_count()}",
        "",
    ]

    for table_name, table in policy.tables.items():
        lines.append(f"## Table: {table_name}")
        lines.append("")

        for chain_name, chain in table.chains.items():
            policy_str = f" (policy: {chain.policy.value})" if chain.policy else ""
            lines.append(f"### Chain: {chain_name}{policy_str}")
            lines.append("")

            if chain.rules:
                lines.append("| # | Action | Protocol | Source | Destination | Ports |")
                lines.append("|---|--------|----------|--------|-------------|-------|")

                for rule in chain.rules:
                    ports = str(rule.destination_port) if rule.destination_port else "-"
                    lines.append(
                        f"| {rule.rule_number or '-'} "
                        f"| {rule.action.value} "
                        f"| {rule.protocol.value} "
                        f"| {rule.source or 'any'} "
                        f"| {rule.destination or 'any'} "
                        f"| {ports} |"
                    )

                lines.append("")

    return "\n".join(lines)
