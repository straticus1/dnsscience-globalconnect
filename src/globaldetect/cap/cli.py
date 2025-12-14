"""
Packet Capture and Analysis CLI commands.

Copyright (c) 2025 DNS Science.io, an After Dark Systems, LLC company.
All rights reserved.
"""

import os
import click
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, TextColumn
from datetime import datetime

from globaldetect.cap.capture import (
    PacketCapture,
    CaptureConfig,
    CAPTURE_FILTERS,
    parse_duration,
)
from globaldetect.cap.analyzer import (
    PacketAnalyzer,
    IssueSeverity,
)
from globaldetect.cap.protocols import (
    DNSAnalyzer,
    SMTPAnalyzer,
    SSLAnalyzer,
)


@click.group()
def cap():
    """Packet capture and analysis for network troubleshooting."""
    pass


@cap.command("capture")
@click.argument("protocol", type=click.Choice(list(CAPTURE_FILTERS.keys()) + ["custom"]))
@click.option("-i", "--interface", help="Network interface to capture on")
@click.option("-t", "--timelimit", default="5m", help="Capture duration (e.g., 30s, 5m, 1h)")
@click.option("-o", "--output", help="Output pcap file path")
@click.option("-c", "--count", type=int, help="Stop after N packets")
@click.option("-f", "--filter", "custom_filter", help="Custom BPF filter (for 'custom' protocol)")
@click.option("--no-promisc", is_flag=True, help="Disable promiscuous mode")
def capture_cmd(protocol: str, interface: str | None, timelimit: str, output: str | None,
                count: int | None, custom_filter: str | None, no_promisc: bool):
    """Capture network traffic for analysis.

    PROTOCOL can be: dns, email, smtp, submission, ssl, ssl-standard, https,
    http, bgp, dhcp, icmp, arp, broadcast, cdp, lldp, or 'custom' with -f filter.

    Examples:
        sudo globaldetect cap capture dns -t 5m
        sudo globaldetect cap capture email -t 10m -o email_capture.pcap
        sudo globaldetect cap capture ssl-standard -i en0 -t 1h
        sudo globaldetect cap capture custom -f "host 10.0.0.1" -t 30s
    """
    console = Console()

    if protocol == "custom" and not custom_filter:
        console.print("[red]Error:[/red] Custom protocol requires -f/--filter option")
        raise SystemExit(1)

    try:
        duration = parse_duration(timelimit)
    except ValueError as e:
        console.print(f"[red]Error:[/red] {e}")
        raise SystemExit(1)

    config = CaptureConfig(
        protocol=protocol,
        interface=interface,
        duration=duration,
        max_packets=count,
        custom_filter=custom_filter,
        promiscuous=not no_promisc,
    )

    if output:
        config.output_file = output

    capture = PacketCapture(config)

    # Get actual interface and filter for display
    try:
        actual_interface = capture._get_interface()
    except Exception:
        actual_interface = interface or "auto"

    filter_str = CAPTURE_FILTERS.get(protocol, custom_filter or "")

    console.print(f"\n[cyan]Starting packet capture[/cyan]")
    console.print(f"  Protocol: [white]{protocol}[/white]")
    console.print(f"  Interface: [white]{actual_interface}[/white]")
    console.print(f"  Filter: [white]{filter_str or '(all traffic)'}[/white]")
    console.print(f"  Duration: [white]{timelimit}[/white]")
    console.print(f"\n[dim]Press Ctrl+C to stop early[/dim]\n")

    try:
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            console=console,
        ) as progress:
            task = progress.add_task(f"Capturing {protocol} traffic...", total=None)
            result = capture.capture(duration)

        if result.success:
            console.print(f"\n[green]Capture complete![/green]")
            console.print(f"  Output: [white]{result.output_file}[/white]")
            console.print(f"  Packets: [white]{result.stats.packets_captured:,}[/white]")
            console.print(f"  Bytes: [white]{result.stats.bytes_captured:,}[/white]")

            if result.stats.packets_dropped > 0:
                console.print(f"  [yellow]Dropped: {result.stats.packets_dropped:,}[/yellow]")

            console.print(f"\n[dim]Analyze with: globaldetect cap analyze --file {result.output_file}[/dim]")
        else:
            console.print(f"[red]Capture failed:[/red] {result.error}")
            raise SystemExit(1)

    except KeyboardInterrupt:
        console.print("\n[yellow]Capture stopped by user[/yellow]")
        capture.stop()
    except PermissionError:
        console.print("[red]Error:[/red] Permission denied. Run with sudo/root privileges.")
        raise SystemExit(1)
    except Exception as e:
        console.print(f"[red]Error:[/red] {e}")
        raise SystemExit(1)


@cap.command("analyze")
@click.option("-f", "--file", "pcap_file", required=True, help="PCAP file to analyze")
@click.option("--protocol", type=click.Choice(["auto", "dns", "smtp", "ssl"]), default="auto",
              help="Focus analysis on specific protocol")
@click.option("--verbose", "-v", is_flag=True, help="Show detailed output")
def analyze_cmd(pcap_file: str, protocol: str, verbose: bool):
    """Analyze captured packets for network issues.

    Detects L2/L3 issues, protocol errors, and security problems:
    - Broadcast storms, ARP anomalies, STP issues
    - ICMP unreachable, TTL exceeded, fragmentation
    - TCP retransmissions, RST floods, zero window
    - DNS errors, slow responses, NXDOMAIN
    - SSL/TLS handshake failures, weak ciphers
    - SMTP errors, authentication issues

    Examples:
        globaldetect cap analyze --file capture.pcap
        globaldetect cap analyze -f dns_capture.pcap --protocol dns -v
    """
    console = Console()

    if not os.path.exists(pcap_file):
        console.print(f"[red]Error:[/red] File not found: {pcap_file}")
        raise SystemExit(1)

    console.print(f"\n[cyan]Analyzing {pcap_file}...[/cyan]\n")

    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        console=console,
    ) as progress:
        task = progress.add_task("Running packet analysis...", total=None)

        analyzer = PacketAnalyzer()
        result = analyzer.analyze(pcap_file)

    if not result.success:
        console.print(f"[red]Analysis failed:[/red] {result.error}")
        raise SystemExit(1)

    # Display stats
    stats = result.stats
    console.print(Panel(
        f"[cyan]Packets:[/cyan] {stats.total_packets:,}  "
        f"[cyan]Bytes:[/cyan] {stats.total_bytes:,}  "
        f"[cyan]Duration:[/cyan] {stats.duration_seconds:.1f}s\n"
        f"[cyan]TCP:[/cyan] {stats.tcp_packets:,}  "
        f"[cyan]UDP:[/cyan] {stats.udp_packets:,}  "
        f"[cyan]ICMP:[/cyan] {stats.icmp_packets:,}  "
        f"[cyan]ARP:[/cyan] {stats.arp_packets:,}\n"
        f"[cyan]Unique IPs:[/cyan] {stats.unique_src_ips + stats.unique_dst_ips}  "
        f"[cyan]Conversations:[/cyan] {stats.unique_conversations}",
        title="Capture Statistics",
    ))

    # Protocol-specific analysis
    if protocol in ("auto", "dns"):
        dns_analyzer = DNSAnalyzer()
        dns_result = dns_analyzer.analyze(pcap_file)
        if dns_result["stats"]["total_queries"] > 0:
            console.print(Panel(
                f"[cyan]Queries:[/cyan] {dns_result['stats']['total_queries']:,}  "
                f"[cyan]Responses:[/cyan] {dns_result['stats']['total_responses']:,}  "
                f"[cyan]Unique Domains:[/cyan] {dns_result['stats']['unique_domains']}\n"
                f"[cyan]Avg Response Time:[/cyan] {dns_result['stats']['avg_response_time_ms']:.1f}ms  "
                f"[cyan]Slow (>500ms):[/cyan] {dns_result['stats']['slow_queries']}",
                title="DNS Analysis",
            ))
            result.issues.extend(dns_result["issues"])

    if protocol in ("auto", "smtp"):
        smtp_analyzer = SMTPAnalyzer()
        smtp_result = smtp_analyzer.analyze(pcap_file)
        if smtp_result["stats"]["total_connections"] > 0:
            console.print(Panel(
                f"[cyan]Connections:[/cyan] {smtp_result['stats']['total_connections']}  "
                f"[cyan]TLS:[/cyan] {smtp_result['stats']['tls_connections']}  "
                f"[cyan]Auth:[/cyan] {smtp_result['stats']['auth_attempts']}\n"
                f"[cyan]Senders:[/cyan] {smtp_result['stats']['unique_senders']}  "
                f"[cyan]Recipients:[/cyan] {smtp_result['stats']['unique_recipients']}  "
                f"[cyan]Failed:[/cyan] {smtp_result['stats']['failed_deliveries']}",
                title="SMTP Analysis",
            ))
            result.issues.extend(smtp_result["issues"])

    if protocol in ("auto", "ssl"):
        ssl_analyzer = SSLAnalyzer()
        ssl_result = ssl_analyzer.analyze(pcap_file)
        if ssl_result["stats"]["total_connections"] > 0:
            versions = ", ".join(f"{k}: {v}" for k, v in ssl_result["stats"]["tls_versions"].items())
            console.print(Panel(
                f"[cyan]Connections:[/cyan] {ssl_result['stats']['total_connections']}  "
                f"[cyan]Deprecated:[/cyan] {ssl_result['stats']['deprecated_protocols']}\n"
                f"[cyan]TLS Versions:[/cyan] {versions}",
                title="SSL/TLS Analysis",
            ))
            result.issues.extend(ssl_result["issues"])

    # Display issues
    if result.issues:
        console.print(f"\n[cyan bold]Issues Detected ({len(result.issues)}):[/cyan bold]\n")

        # Sort by severity
        severity_order = {
            IssueSeverity.CRITICAL: 0,
            IssueSeverity.ERROR: 1,
            IssueSeverity.WARNING: 2,
            IssueSeverity.INFO: 3,
        }
        sorted_issues = sorted(result.issues, key=lambda x: severity_order.get(x.severity, 99))

        for issue in sorted_issues:
            if issue.severity == IssueSeverity.CRITICAL:
                color = "red bold"
                icon = "[!]"
            elif issue.severity == IssueSeverity.ERROR:
                color = "red"
                icon = "[E]"
            elif issue.severity == IssueSeverity.WARNING:
                color = "yellow"
                icon = "[W]"
            else:
                color = "dim"
                icon = "[i]"

            console.print(f"[{color}]{icon} {issue.title}[/{color}]")
            console.print(f"    {issue.description}")
            if verbose and issue.recommendation:
                console.print(f"    [dim]Recommendation: {issue.recommendation}[/dim]")
            console.print()

        # Summary
        console.print(Panel(
            f"[red]Critical:[/red] {len(result.critical_issues)}  "
            f"[red]Errors:[/red] {len(result.error_issues)}  "
            f"[yellow]Warnings:[/yellow] {len(result.warning_issues)}",
            title="Issue Summary",
        ))
    else:
        console.print("[green]No significant issues detected.[/green]")


@cap.command("live")
@click.argument("protocol", type=click.Choice(list(CAPTURE_FILTERS.keys())))
@click.option("-i", "--interface", help="Network interface")
@click.option("-t", "--timelimit", default="1m", help="Duration (e.g., 30s, 1m)")
@click.option("--analyze/--no-analyze", default=True, help="Analyze packets in real-time")
def live_cmd(protocol: str, interface: str | None, timelimit: str, analyze: bool):
    """Capture and analyze traffic in real-time.

    Shows packets as they're captured with optional real-time analysis.

    Examples:
        sudo globaldetect cap live dns -t 30s
        sudo globaldetect cap live icmp -i en0 --no-analyze
    """
    console = Console()

    try:
        duration = parse_duration(timelimit)
    except ValueError as e:
        console.print(f"[red]Error:[/red] {e}")
        raise SystemExit(1)

    config = CaptureConfig(
        protocol=protocol,
        interface=interface,
        duration=duration,
    )

    capture = PacketCapture(config)

    console.print(f"\n[cyan]Live capture: {protocol}[/cyan]")
    console.print(f"[dim]Duration: {timelimit}, Press Ctrl+C to stop[/dim]\n")

    packet_count = [0]  # Use list for closure

    def packet_callback(line: str, num: int):
        packet_count[0] = num
        # Color-code by protocol indicators
        if "DNS" in line or "domain" in line:
            console.print(f"[cyan]{num:5d}[/cyan] {line[:120]}")
        elif "ICMP" in line or "icmp" in line:
            console.print(f"[yellow]{num:5d}[/yellow] {line[:120]}")
        elif "TCP" in line or "Flags" in line:
            if "RST" in line or "FIN" in line:
                console.print(f"[red]{num:5d}[/red] {line[:120]}")
            else:
                console.print(f"[green]{num:5d}[/green] {line[:120]}")
        elif "ARP" in line or "arp" in line:
            console.print(f"[magenta]{num:5d}[/magenta] {line[:120]}")
        else:
            console.print(f"[white]{num:5d}[/white] {line[:120]}")

    try:
        result = capture.capture_live(packet_callback, duration)
        console.print(f"\n[cyan]Captured {packet_count[0]} packets in {result.stats.duration_seconds:.1f}s[/cyan]")
    except KeyboardInterrupt:
        console.print(f"\n[yellow]Stopped. Captured {packet_count[0]} packets[/yellow]")
    except PermissionError:
        console.print("[red]Error:[/red] Permission denied. Run with sudo/root privileges.")
        raise SystemExit(1)
    except Exception as e:
        console.print(f"[red]Error:[/red] {e}")
        raise SystemExit(1)


@cap.command("protocols")
def protocols_cmd():
    """List available capture protocols and their filters.

    Examples:
        globaldetect cap protocols
    """
    console = Console()

    table = Table(title="Available Capture Protocols", box=None)
    table.add_column("Protocol", style="cyan")
    table.add_column("BPF Filter", style="white")
    table.add_column("Description", style="dim")

    descriptions = {
        "dns": "DNS queries and responses (port 53)",
        "email": "All email traffic (ports 25, 465, 587)",
        "smtp": "SMTP relay (port 25)",
        "submission": "Email submission (ports 587, 465)",
        "ssl": "All SSL/TLS traffic (443, 8443, 465, 993, 995, 636)",
        "ssl-standard": "HTTPS only (port 443)",
        "https": "HTTPS traffic (ports 443, 8443)",
        "http": "HTTP traffic (ports 80, 8080)",
        "ssh": "SSH traffic (port 22)",
        "ftp": "FTP traffic (ports 20, 21)",
        "telnet": "Telnet traffic (port 23)",
        "ntp": "NTP time sync (port 123)",
        "snmp": "SNMP monitoring (ports 161, 162)",
        "syslog": "Syslog messages (port 514)",
        "ldap": "LDAP/LDAPS (ports 389, 636)",
        "radius": "RADIUS auth (ports 1812, 1813)",
        "bgp": "BGP routing (port 179)",
        "dhcp": "DHCP (ports 67, 68)",
        "broadcast": "Broadcast and multicast traffic",
        "arp": "ARP traffic",
        "icmp": "ICMP/ICMPv6 traffic",
        "stp": "Spanning Tree Protocol",
        "cdp": "Cisco Discovery Protocol",
        "lldp": "Link Layer Discovery Protocol",
        "all": "All traffic (no filter)",
    }

    for protocol, bpf_filter in sorted(CAPTURE_FILTERS.items()):
        desc = descriptions.get(protocol, "")
        table.add_row(protocol, bpf_filter or "(none)", desc)

    console.print(table)
    console.print("\n[dim]Use 'custom' protocol with -f to specify your own BPF filter[/dim]")
