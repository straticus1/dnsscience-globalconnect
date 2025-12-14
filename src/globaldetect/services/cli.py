"""
Services CLI commands for external API integrations.
"""

import click
from rich.console import Console
from rich.table import Table
from rich.panel import Panel

from globaldetect.services.ipinfo import IPInfoClient
from globaldetect.services.cloudflare import CloudflareClient
from globaldetect.services.dnsscience import DNSScienceClient
from globaldetect.services.abuseipdb import AbuseIPDBClient


@click.group()
def services():
    """External API service commands."""
    pass


# IPInfo commands
@services.command()
@click.argument("ip")
def ipinfo(ip: str):
    """Get detailed IP information from IPInfo.io.

    Examples:
        globaldetect services ipinfo 8.8.8.8
        globaldetect services ipinfo 2607:f8b0:4004:800::200e
    """
    console = Console()
    client = IPInfoClient()

    with console.status(f"[cyan]Looking up {ip}...[/cyan]"):
        result = client.lookup(ip)

    if result.error:
        console.print(f"[red]Error:[/red] {result.error}")
        raise SystemExit(1)

    table = Table(title=f"IPInfo: {ip}", show_header=False, box=None)
    table.add_column("Property", style="cyan")
    table.add_column("Value", style="white")

    table.add_row("IP", result.ip)
    if result.hostname:
        table.add_row("Hostname", result.hostname)
    if result.city:
        table.add_row("City", result.city)
    if result.region:
        table.add_row("Region", result.region)
    if result.country:
        table.add_row("Country", result.country)
    if result.loc:
        table.add_row("Location", result.loc)
    if result.postal:
        table.add_row("Postal", result.postal)
    if result.timezone:
        table.add_row("Timezone", result.timezone)

    if result.asn:
        table.add_row("", "")
        table.add_row("ASN", f"AS{result.asn}")
    if result.as_name:
        table.add_row("AS Name", result.as_name)
    if result.org:
        table.add_row("Organization", result.org)

    if result.company_name:
        table.add_row("", "")
        table.add_row("Company", result.company_name)
        if result.company_type:
            table.add_row("Company Type", result.company_type)

    # Privacy/security flags
    flags = []
    if result.is_vpn:
        flags.append("[yellow]VPN[/yellow]")
    if result.is_proxy:
        flags.append("[yellow]Proxy[/yellow]")
    if result.is_tor:
        flags.append("[red]Tor[/red]")
    if result.is_hosting:
        flags.append("[blue]Hosting[/blue]")

    if flags:
        table.add_row("", "")
        table.add_row("Flags", " ".join(flags))

    console.print(table)


@services.command()
def myip():
    """Get information about your public IP.

    Examples:
        globaldetect services myip
    """
    console = Console()
    client = IPInfoClient()

    with console.status("[cyan]Getting your public IP...[/cyan]"):
        result = client.get_my_ip()

    if result.error:
        console.print(f"[red]Error:[/red] {result.error}")
        raise SystemExit(1)

    console.print(f"[cyan]Your IP:[/cyan] {result.ip}")
    if result.city and result.country:
        console.print(f"[cyan]Location:[/cyan] {result.city}, {result.region}, {result.country}")
    if result.org:
        console.print(f"[cyan]ISP:[/cyan] {result.org}")


# Cloudflare commands
@services.command()
def cftrace():
    """Get Cloudflare edge trace information.

    Shows your connection to Cloudflare's network.

    Examples:
        globaldetect services cftrace
    """
    console = Console()
    client = CloudflareClient()

    with console.status("[cyan]Tracing connection to Cloudflare...[/cyan]"):
        result = client.trace()

    table = Table(title="Cloudflare Trace", show_header=False, box=None)
    table.add_column("Property", style="cyan")
    table.add_column("Value", style="white")

    table.add_row("Your IP", result.ip)
    if result.colo:
        table.add_row("Datacenter", result.colo)
    if result.location:
        table.add_row("Location", result.location)
    if result.http_version:
        table.add_row("HTTP Version", result.http_version)
    if result.tls_version:
        table.add_row("TLS Version", result.tls_version)
    if result.warp:
        table.add_row("WARP", result.warp)

    console.print(table)


@services.command()
def speedtest():
    """Run a basic speed test via Cloudflare.

    Examples:
        globaldetect services speedtest
    """
    console = Console()
    client = CloudflareClient()

    with console.status("[cyan]Running speed test...[/cyan]"):
        result = client.speed_test()

    console.print(f"[cyan]Datacenter:[/cyan] {result.get('colo', 'Unknown')}")
    console.print(f"[cyan]Latency:[/cyan] {result.get('latency_ms', 'N/A')} ms")
    console.print(f"[cyan]Download:[/cyan] {result.get('download_mbps', 'N/A')} Mbps")


# AbuseIPDB commands
@services.command()
@click.argument("ip")
@click.option("--days", default=90, help="Maximum age of reports in days")
def abuse(ip: str, days: int):
    """Check IP reputation on AbuseIPDB.

    Examples:
        globaldetect services abuse 185.220.101.1
        globaldetect services abuse 8.8.8.8 --days 30
    """
    console = Console()
    client = AbuseIPDBClient()

    with console.status(f"[cyan]Checking {ip} reputation...[/cyan]"):
        result = client.check_ip(ip, days)

    if result.error:
        console.print(f"[red]Error:[/red] {result.error}")
        raise SystemExit(1)

    # Determine risk level
    score = result.abuse_confidence_score
    if score == 0:
        risk_color = "green"
        risk_label = "Clean"
    elif score < 25:
        risk_color = "yellow"
        risk_label = "Low Risk"
    elif score < 75:
        risk_color = "orange1"
        risk_label = "Medium Risk"
    else:
        risk_color = "red"
        risk_label = "High Risk"

    table = Table(title=f"AbuseIPDB: {ip}", show_header=False, box=None)
    table.add_column("Property", style="cyan")
    table.add_column("Value", style="white")

    table.add_row("IP", result.ip)
    table.add_row("Abuse Score", f"[{risk_color}]{score}% ({risk_label})[/{risk_color}]")
    table.add_row("Total Reports", str(result.total_reports))
    table.add_row("Distinct Reporters", str(result.num_distinct_users))

    if result.country_code:
        table.add_row("Country", result.country_code)
    if result.isp:
        table.add_row("ISP", result.isp)
    if result.usage_type:
        table.add_row("Usage Type", result.usage_type)
    if result.domain:
        table.add_row("Domain", result.domain)
    if result.last_reported_at:
        table.add_row("Last Reported", result.last_reported_at)

    if result.is_whitelisted:
        table.add_row("Whitelisted", "[green]Yes[/green]")
    if result.is_tor:
        table.add_row("Tor Exit", "[red]Yes[/red]")

    if result.category_names:
        table.add_row("", "")
        table.add_row("Abuse Categories", ", ".join(result.category_names[:5]))
        if len(result.category_names) > 5:
            table.add_row("", f"... and {len(result.category_names) - 5} more")

    console.print(table)


# DNS Science commands
@services.command()
@click.argument("domain")
@click.option("--full", is_flag=True, help="Perform full scan (slower)")
def scan(domain: str, full: bool):
    """Scan a domain using DNS Science API.

    Examples:
        globaldetect services scan google.com
        globaldetect services scan example.com --full
    """
    console = Console()
    client = DNSScienceClient()

    scan_type = "full" if full else "quick"
    with console.status(f"[cyan]Running {scan_type} scan on {domain}...[/cyan]"):
        result = client.scan_domain(domain, full)

    if result.error:
        console.print(f"[red]Error:[/red] {result.error}")
        raise SystemExit(1)

    table = Table(title=f"Domain Scan: {domain}", show_header=False, box=None)
    table.add_column("Property", style="cyan")
    table.add_column("Value", style="white")

    table.add_row("Domain", result.domain)

    if result.registrar:
        table.add_row("Registrar", result.registrar)
    if result.creation_date:
        table.add_row("Created", result.creation_date)
    if result.expiration_date:
        table.add_row("Expires", result.expiration_date)

    if result.nameservers:
        table.add_row("Nameservers", ", ".join(result.nameservers[:3]))

    if result.ip_addresses:
        table.add_row("IP Addresses", ", ".join(result.ip_addresses[:3]))

    if result.hosting_provider:
        table.add_row("Hosting", result.hosting_provider)

    # Email security
    table.add_row("", "")
    table.add_row("DNSSEC", "[green]Yes[/green]" if result.dnssec_enabled else "[yellow]No[/yellow]")

    if result.spf_record:
        table.add_row("SPF", "[green]Present[/green]")
    else:
        table.add_row("SPF", "[yellow]Missing[/yellow]")

    if result.dmarc_record:
        table.add_row("DMARC", "[green]Present[/green]")
    else:
        table.add_row("DMARC", "[yellow]Missing[/yellow]")

    if result.mx_records:
        table.add_row("MX Records", str(len(result.mx_records)))

    console.print(table)


@services.command()
@click.argument("domain")
def subdomains(domain: str):
    """Enumerate subdomains for a domain.

    Examples:
        globaldetect services subdomains example.com
    """
    console = Console()
    client = DNSScienceClient()

    with console.status(f"[cyan]Enumerating subdomains for {domain}...[/cyan]"):
        result = client.enumerate_subdomains(domain)

    if result.error:
        console.print(f"[red]Error:[/red] {result.error}")
        raise SystemExit(1)

    console.print(f"[cyan]Found {result.total_found} subdomains for {domain}:[/cyan]\n")

    for subdomain in result.subdomains[:50]:
        console.print(f"  {subdomain}")

    if result.total_found > 50:
        console.print(f"\n[dim]... and {result.total_found - 50} more[/dim]")

    if result.sources:
        console.print(f"\n[dim]Sources: {', '.join(result.sources)}[/dim]")


@services.command()
@click.argument("target")
def threat(target: str):
    """Check threat intelligence for a domain or IP.

    Examples:
        globaldetect services threat malware-domain.com
        globaldetect services threat 185.220.101.1
    """
    console = Console()
    client = DNSScienceClient()

    with console.status(f"[cyan]Checking threat intel for {target}...[/cyan]"):
        result = client.get_threat_intel(target)

    if result.error:
        console.print(f"[red]Error:[/red] {result.error}")
        raise SystemExit(1)

    # Determine risk display
    if result.is_malicious:
        status = "[red]MALICIOUS[/red]"
    elif result.risk_score > 50:
        status = "[yellow]SUSPICIOUS[/yellow]"
    else:
        status = "[green]CLEAN[/green]"

    table = Table(title=f"Threat Intel: {target}", show_header=False, box=None)
    table.add_column("Property", style="cyan")
    table.add_column("Value", style="white")

    table.add_row("Target", result.target)
    table.add_row("Status", status)
    table.add_row("Risk Score", f"{result.risk_score}/100")

    if result.threat_types:
        table.add_row("Threat Types", ", ".join(result.threat_types))

    if result.blacklists:
        table.add_row("Blacklists", ", ".join(result.blacklists[:5]))

    if result.first_seen:
        table.add_row("First Seen", result.first_seen)
    if result.last_seen:
        table.add_row("Last Seen", result.last_seen)

    if result.sources:
        table.add_row("Sources", ", ".join(result.sources))

    console.print(table)
