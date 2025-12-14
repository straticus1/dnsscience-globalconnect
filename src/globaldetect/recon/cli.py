"""
Reconnaissance CLI commands.

Copyright (c) 2025 DNS Science.io, an After Dark Systems, LLC company.
All rights reserved.
"""

import click
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, TextColumn

from globaldetect.recon.scanner import (
    HostDiscovery,
    PortScanner,
    ServiceDetector,
    TOP_PORTS,
)
from globaldetect.recon.ssl_analyzer import SSLAnalyzer
from globaldetect.recon.profiler import TargetProfiler


@click.group()
def recon():
    """Network reconnaissance utilities."""
    pass


@recon.command()
@click.argument("target")
@click.option("--quick", is_flag=True, help="Quick scan (fewer ports)")
@click.option("--full", is_flag=True, help="Full port scan (1-65535)")
@click.option("--top", default=100, help="Scan top N ports")
def scan(target: str, quick: bool, full: bool, top: int):
    """Scan ports on a target host.

    Examples:
        globaldetect recon scan 192.168.1.1
        globaldetect recon scan example.com --quick
        globaldetect recon scan 10.0.0.1 --full
    """
    console = Console()
    scanner = PortScanner()

    if full:
        ports = list(range(1, 65536))
        console.print("[yellow]Full port scan (1-65535) - this may take a while...[/yellow]\n")
    elif quick:
        ports = TOP_PORTS[:20]
    else:
        ports = TOP_PORTS[:top]

    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        console=console,
    ) as progress:
        progress.add_task(f"Scanning {len(ports)} ports on {target}...", total=None)
        results = scanner.scan_host(target, ports)

    open_ports = [p for p in results if p.state == "open"]
    filtered_ports = [p for p in results if p.state == "filtered"]

    console.print(f"\n[cyan]Scan Results for {target}[/cyan]")
    console.print(f"Open: [green]{len(open_ports)}[/green]  Filtered: [yellow]{len(filtered_ports)}[/yellow]\n")

    if open_ports:
        table = Table(title="Open Ports", box=None)
        table.add_column("Port", style="cyan", width=8)
        table.add_column("Service", style="white", width=15)
        table.add_column("Description", style="dim", width=30)
        table.add_column("Banner", style="dim", width=40, overflow="ellipsis")

        for port in sorted(open_ports, key=lambda p: p.port):
            banner = port.banner[:40] if port.banner else "-"
            table.add_row(
                str(port.port),
                port.service or "-",
                port.service_desc or "-",
                banner,
            )

        console.print(table)
    else:
        console.print("[yellow]No open ports found[/yellow]")


@recon.command()
@click.argument("network")
@click.option("--timeout", default=2.0, help="Timeout per host in seconds")
def discover(network: str, timeout: float):
    """Discover live hosts in a network.

    Examples:
        globaldetect recon discover 192.168.1.0/24
        globaldetect recon discover 10.0.0.0/24 --timeout 1
    """
    console = Console()
    discovery = HostDiscovery(timeout=timeout)

    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        console=console,
    ) as progress:
        progress.add_task(f"Discovering hosts in {network}...", total=None)
        hosts = discovery.discover_network(network)

    console.print(f"\n[cyan]Live Hosts in {network}[/cyan]")
    console.print(f"Found: [green]{len(hosts)}[/green] hosts\n")

    if hosts:
        table = Table(box=None)
        table.add_column("IP Address", style="white", width=18)
        table.add_column("Hostname", style="dim", width=40)
        table.add_column("Response", style="cyan", width=12)
        table.add_column("Method", style="dim", width=15)

        for host in sorted(hosts, key=lambda h: h.ip):
            table.add_row(
                host.ip,
                host.hostname or "-",
                f"{host.response_time_ms:.1f}ms",
                host.discovery_method or "-",
            )

        console.print(table)


@recon.command()
@click.argument("host")
@click.argument("port", type=int)
def service(host: str, port: int):
    """Detect service version on a specific port.

    Examples:
        globaldetect recon service 192.168.1.1 22
        globaldetect recon service example.com 443
    """
    console = Console()
    detector = ServiceDetector()

    with console.status(f"[cyan]Detecting service on {host}:{port}...[/cyan]"):
        result = detector.detect_service(host, port)

    table = Table(title=f"Service: {host}:{port}", show_header=False, box=None)
    table.add_column("Property", style="cyan")
    table.add_column("Value", style="white")

    table.add_row("Host", host)
    table.add_row("Port", str(port))

    if result.service:
        table.add_row("Service", result.service)
    if result.product:
        table.add_row("Product", result.product)
    if result.version:
        table.add_row("Version", result.version)
    if result.banner:
        banner_lines = result.banner.split("\n")[:5]
        table.add_row("Banner", banner_lines[0])
        for line in banner_lines[1:]:
            table.add_row("", line[:60])

    console.print(table)


@recon.command()
@click.argument("host")
@click.option("-p", "--port", default=443, help="Port number")
def ssl(host: str, port: int):
    """Analyze SSL/TLS certificate and configuration.

    Examples:
        globaldetect recon ssl google.com
        globaldetect recon ssl example.com -p 8443
    """
    console = Console()
    analyzer = SSLAnalyzer()

    with console.status(f"[cyan]Analyzing SSL/TLS on {host}:{port}...[/cyan]"):
        result = analyzer.analyze(host, port)
        grade = analyzer.grade_certificate(result)

    if result.error:
        console.print(f"[red]Error:[/red] {result.error}")
        raise SystemExit(1)

    # Grade color
    grade_colors = {"A": "green", "B": "cyan", "C": "yellow", "D": "orange1", "F": "red"}
    grade_color = grade_colors.get(grade, "white")

    table = Table(title=f"SSL/TLS Analysis: {host}:{port}", show_header=False, box=None)
    table.add_column("Property", style="cyan")
    table.add_column("Value", style="white")

    table.add_row("Grade", f"[{grade_color}]{grade}[/{grade_color}]")
    table.add_row("Protocol", result.protocol_version or "-")
    table.add_row("Cipher", result.cipher_name or "-")

    table.add_row("", "")
    table.add_row("Subject", result.subject.get("commonName", "-"))
    table.add_row("Issuer", result.issuer.get("organizationName", "-"))

    if result.san:
        table.add_row("SANs", ", ".join(result.san[:5]))
        if len(result.san) > 5:
            table.add_row("", f"... and {len(result.san) - 5} more")

    table.add_row("", "")
    if result.not_before:
        table.add_row("Not Before", result.not_before.strftime("%Y-%m-%d"))
    if result.not_after:
        table.add_row("Not After", result.not_after.strftime("%Y-%m-%d"))
        days_color = "green" if result.days_remaining > 30 else "yellow" if result.days_remaining > 0 else "red"
        table.add_row("Days Remaining", f"[{days_color}]{result.days_remaining}[/{days_color}]")

    table.add_row("", "")
    table.add_row("Self-Signed", "[red]Yes[/red]" if result.is_self_signed else "[green]No[/green]")
    table.add_row("Wildcard", "[cyan]Yes[/cyan]" if result.is_wildcard else "No")

    console.print(table)


@recon.command()
@click.argument("target")
@click.option("--no-ports", is_flag=True, help="Skip port scanning")
@click.option("--no-ssl", is_flag=True, help="Skip SSL analysis")
@click.option("--no-dns", is_flag=True, help="Skip DNS lookups")
def profile(target: str, no_ports: bool, no_ssl: bool, no_dns: bool):
    """Generate comprehensive target profile.

    Combines host discovery, port scanning, service detection,
    SSL analysis, and DNS lookups into a single report.

    Examples:
        globaldetect recon profile example.com
        globaldetect recon profile 192.168.1.1 --no-ssl
    """
    console = Console()

    profiler = TargetProfiler(
        port_scan=not no_ports,
        ssl_analyze=not no_ssl,
        dns_lookup=not no_dns,
    )

    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        console=console,
    ) as progress:
        progress.add_task(f"Profiling {target}...", total=None)
        result = profiler.profile(target)

    # Display profile
    status_color = "green" if result.is_alive else "red"
    console.print(f"\n[cyan]Target Profile: {target}[/cyan]")
    console.print(f"Status: [{status_color}]{'ALIVE' if result.is_alive else 'DOWN'}[/{status_color}]")
    console.print(f"Type: {result.target_type}")
    console.print(f"Scan Duration: {result.scan_duration_seconds:.2f}s\n")

    # Network info
    if result.ip_addresses:
        console.print("[cyan]Network:[/cyan]")
        for ip in result.ip_addresses:
            console.print(f"  IP: {ip}")
        if result.reverse_dns:
            console.print(f"  Reverse DNS: {result.reverse_dns}")
        console.print()

    # DNS
    if result.nameservers:
        console.print("[cyan]Nameservers:[/cyan]")
        for ns in result.nameservers[:5]:
            console.print(f"  {ns}")
        console.print()

    # Open ports
    if result.open_ports:
        open_ports = [p for p in result.open_ports if p.state == "open"]
        if open_ports:
            console.print("[cyan]Open Ports:[/cyan]")
            table = Table(box=None)
            table.add_column("Port", width=8)
            table.add_column("Service", width=15)

            for port in sorted(open_ports, key=lambda p: p.port)[:15]:
                table.add_row(str(port.port), port.service or "-")

            console.print(table)
            if len(open_ports) > 15:
                console.print(f"  ... and {len(open_ports) - 15} more")
            console.print()

    # Services
    if result.services:
        detected = [s for s in result.services if s.product]
        if detected:
            console.print("[cyan]Detected Services:[/cyan]")
            for svc in detected[:10]:
                ver = svc.version or ""
                console.print(f"  Port {svc.port}: {svc.product} {ver}")
            console.print()

    # SSL
    if result.ssl_info and result.ssl_info.is_valid:
        grade_colors = {"A": "green", "B": "cyan", "C": "yellow", "D": "orange1", "F": "red"}
        grade_color = grade_colors.get(result.ssl_grade, "white")

        console.print("[cyan]SSL/TLS:[/cyan]")
        console.print(f"  Grade: [{grade_color}]{result.ssl_grade}[/{grade_color}]")
        console.print(f"  Subject: {result.ssl_info.subject.get('commonName', '-')}")
        if result.ssl_info.days_remaining:
            console.print(f"  Expires: {result.ssl_info.days_remaining} days")
        console.print()

    # Security issues
    if result.security_issues:
        console.print("[red]Security Issues:[/red]")
        for issue in result.security_issues:
            console.print(f"  [!] {issue}")
        console.print()

    if result.recommendations:
        console.print("[yellow]Recommendations:[/yellow]")
        for rec in result.recommendations:
            console.print(f"  - {rec}")


@recon.command()
@click.argument("host")
def protocols(host: str):
    """Check which TLS/SSL protocols are supported.

    Examples:
        globaldetect recon protocols example.com
    """
    console = Console()
    analyzer = SSLAnalyzer()

    with console.status(f"[cyan]Checking TLS/SSL protocols on {host}...[/cyan]"):
        results = analyzer.check_protocols(host)

    console.print(f"\n[cyan]Protocol Support: {host}[/cyan]\n")

    table = Table(box=None)
    table.add_column("Protocol", width=12)
    table.add_column("Supported", width=12)
    table.add_column("Status", width=20)

    for proto, supported in sorted(results.items()):
        if supported:
            support_str = "[green]Yes[/green]"
            if proto in ["SSLv3", "TLSv1.0", "TLSv1.1"]:
                status = "[yellow]Deprecated[/yellow]"
            elif proto == "TLSv1.3":
                status = "[green]Recommended[/green]"
            else:
                status = "[green]OK[/green]"
        else:
            support_str = "[dim]No[/dim]"
            status = "-"

        table.add_row(proto, support_str, status)

    console.print(table)
