"""
CLI commands for facilities management.

Copyright (c) 2025 DNS Science.io, an After Dark Systems, LLC company.
All rights reserved.
"""

import asyncio
import json

import click
from rich.console import Console
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TaskProgressColumn
from rich.table import Table

from globaldetect.facilities.database import FacilitiesDatabase
from globaldetect.facilities.peeringdb import PeeringDBClient
from globaldetect.facilities.sync import FacilitiesSync, SyncOptions

console = Console()


def get_db() -> FacilitiesDatabase:
    """Get and initialize database."""
    db = FacilitiesDatabase()
    db.initialize()
    return db


@click.group()
def facility():
    """Data center and colocation facility management.

    Syncs and queries global data center information from PeeringDB,
    including facilities, networks, carriers, and Internet Exchanges.

    \b
    Examples:
        # Sync all data from PeeringDB
        globaldetect facility sync

        # Search facilities
        globaldetect facility search --city Ashburn
        globaldetect facility search --country US --owner Equinix

        # View facility details
        globaldetect facility info 1234

        # Show statistics
        globaldetect facility stats
    """
    pass


# ================================================================
# Sync commands
# ================================================================

@facility.command()
@click.option("--full", is_flag=True, help="Full sync (ignore last sync time)")
@click.option("--quiet", "-q", is_flag=True, help="Quiet output")
@click.option("--facilities-only", is_flag=True, help="Only sync facilities")
@click.option("--json-output", "json_out", is_flag=True, help="Output as JSON")
def sync(full: bool, quiet: bool, facilities_only: bool, json_out: bool):
    """Sync data from PeeringDB.

    By default, performs incremental sync (only records changed since
    last sync). Use --full for a complete refresh.

    \b
    Examples:
        # Incremental sync (hourly cron)
        globaldetect facility sync --quiet

        # Full sync
        globaldetect facility sync --full

        # Quick facilities-only sync
        globaldetect facility sync --facilities-only
    """
    db = get_db()
    sync_manager = FacilitiesSync(db)

    options = SyncOptions(
        full_sync=full,
        sync_facilities=True,
        sync_networks=not facilities_only,
        sync_network_facilities=not facilities_only,
        sync_carriers=not facilities_only,
        sync_carrier_facilities=not facilities_only,
        sync_exchanges=not facilities_only,
        sync_ix_facilities=not facilities_only,
    )

    if not quiet and not json_out:
        console.print(Panel(
            "[bold]PeeringDB Sync[/bold]\n"
            f"Mode: {'Full' if full else 'Incremental'}\n"
            f"Scope: {'Facilities only' if facilities_only else 'All entities'}",
            title="Facilities Sync",
        ))

    async def run_sync():
        results = await sync_manager.sync_all(options)
        return results

    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        BarColumn(),
        TaskProgressColumn(),
        console=console,
        disable=quiet or json_out,
    ) as progress:
        task = progress.add_task("Syncing...", total=None)
        results = asyncio.run(run_sync())
        progress.update(task, completed=True)

    if json_out:
        output = {
            "success": all(r.success for r in results),
            "results": [
                {
                    "entity_type": r.entity_type,
                    "success": r.success,
                    "fetched": r.fetched,
                    "created": r.created,
                    "updated": r.updated,
                    "error": r.error,
                    "duration_seconds": r.duration_seconds,
                }
                for r in results
            ],
        }
        click.echo(json.dumps(output, indent=2))
        return

    if quiet:
        # Just exit with appropriate code
        if all(r.success for r in results):
            return
        else:
            raise SystemExit(1)

    # Display results
    table = Table(title="Sync Results")
    table.add_column("Entity", style="cyan")
    table.add_column("Status", style="green")
    table.add_column("Fetched", justify="right")
    table.add_column("Created", justify="right")
    table.add_column("Updated", justify="right")
    table.add_column("Duration", justify="right")

    total_fetched = 0
    total_created = 0
    total_updated = 0
    total_duration = 0.0

    for result in results:
        status = "[green]OK[/green]" if result.success else f"[red]FAIL: {result.error}[/red]"
        table.add_row(
            result.entity_type,
            status,
            str(result.fetched),
            str(result.created),
            str(result.updated),
            f"{result.duration_seconds:.1f}s",
        )
        total_fetched += result.fetched
        total_created += result.created
        total_updated += result.updated
        total_duration += result.duration_seconds

    table.add_row(
        "[bold]Total[/bold]",
        "",
        f"[bold]{total_fetched}[/bold]",
        f"[bold]{total_created}[/bold]",
        f"[bold]{total_updated}[/bold]",
        f"[bold]{total_duration:.1f}s[/bold]",
    )

    console.print(table)


@facility.command()
@click.option("--json-output", "json_out", is_flag=True, help="Output as JSON")
def sync_history(json_out: bool):
    """Show sync history."""
    db = get_db()
    history = db.get_sync_history(limit=20)

    if json_out:
        click.echo(json.dumps([s.to_dict() for s in history], indent=2))
        return

    table = Table(title="Sync History")
    table.add_column("Started", style="cyan")
    table.add_column("Entity", style="blue")
    table.add_column("Status")
    table.add_column("Fetched", justify="right")
    table.add_column("Created", justify="right")
    table.add_column("Updated", justify="right")

    for sync in history:
        started = sync.started_at.strftime("%Y-%m-%d %H:%M") if sync.started_at else "?"
        status_style = "green" if sync.status == "completed" else "red" if sync.status == "failed" else "yellow"
        table.add_row(
            started,
            sync.entity_type or "?",
            f"[{status_style}]{sync.status}[/{status_style}]",
            str(sync.records_fetched),
            str(sync.records_created),
            str(sync.records_updated),
        )

    console.print(table)


# ================================================================
# Search commands
# ================================================================

def get_facility_tier(net_count: int | None) -> tuple[int, str]:
    """
    Classify facility tier based on network count.

    Tier classification:
    - Tier 1: 100+ networks (major global hubs)
    - Tier 2: 30-99 networks (significant regional)
    - Tier 3: 10-29 networks (smaller regional)
    - Tier 4: <10 networks (local/edge)
    """
    count = net_count or 0
    if count >= 100:
        return 1, "Tier 1"
    elif count >= 30:
        return 2, "Tier 2"
    elif count >= 10:
        return 3, "Tier 3"
    else:
        return 4, "Tier 4"


# Region mapping for continents
REGION_COUNTRIES = {
    "NA": ["US", "CA", "MX"],  # North America
    "SA": ["BR", "AR", "CL", "CO", "PE", "VE", "EC", "UY", "PY", "BO"],  # South America
    "EU": ["DE", "GB", "FR", "NL", "ES", "IT", "SE", "CH", "AT", "BE", "PL", "CZ", "DK", "NO", "FI", "IE", "PT", "RO", "HU", "UA", "GR", "SK", "BG", "RS", "HR", "LT", "LV", "EE", "SI", "LU"],  # Europe
    "APAC": ["JP", "AU", "SG", "HK", "KR", "IN", "CN", "TW", "NZ", "MY", "TH", "ID", "PH", "VN", "BD", "PK"],  # Asia Pacific
    "MEA": ["AE", "ZA", "IL", "SA", "EG", "NG", "KE", "MA", "TN", "QA", "KW", "BH", "OM", "JO", "LB"],  # Middle East & Africa
}


@facility.command()
@click.option("--name", "-n", help="Search by facility name")
@click.option("--city", "-c", help="Filter by city")
@click.option("--state", "-s", help="Filter by state/region")
@click.option("--country", help="Filter by country code (e.g., US, DE)")
@click.option("--region", "-r", type=click.Choice(["NA", "SA", "EU", "APAC", "MEA"]), help="Filter by region")
@click.option("--owner", "-o", help="Filter by owner/operator name")
@click.option("--clli", help="Search by CLLI code")
@click.option("--site-code", help="Search by site code")
@click.option("--tier", "-t", type=click.Choice(["1", "2", "3", "4"]), help="Filter by tier (1=major hub, 4=edge)")
@click.option("--min-networks", type=int, help="Minimum network count")
@click.option("--limit", "-l", default=50, help="Maximum results")
@click.option("--sort", type=click.Choice(["name", "networks", "country"]), default="networks", help="Sort by field")
@click.option("--json-output", "json_out", is_flag=True, help="Output as JSON")
def search(
    name: str | None,
    city: str | None,
    state: str | None,
    country: str | None,
    region: str | None,
    owner: str | None,
    clli: str | None,
    site_code: str | None,
    tier: str | None,
    min_networks: int | None,
    limit: int,
    sort: str,
    json_out: bool,
):
    """Search facilities with tier classification.

    Tiers are based on network presence:
    - Tier 1: 100+ networks (major global hubs like Equinix Ashburn)
    - Tier 2: 30-99 networks (significant regional facilities)
    - Tier 3: 10-29 networks (smaller regional/metro)
    - Tier 4: <10 networks (local/edge facilities)

    Regions: NA (North America), SA (South America), EU (Europe),
    APAC (Asia Pacific), MEA (Middle East & Africa)

    \b
    Examples:
        # Search Tier 1 facilities in US
        globaldetect facility search --country US --tier 1

        # Search by region
        globaldetect facility search --region EU --tier 1

        # Search by city and owner
        globaldetect facility search --city Ashburn --owner Equinix

        # Search by CLLI code
        globaldetect facility search --clli DLLSTX

        # Search with minimum network count
        globaldetect facility search --country US --min-networks 50
    """
    db = get_db()

    # Handle region filter - expand to country list
    if region:
        region_countries = REGION_COUNTRIES.get(region, [])
        if country:
            # If both region and country specified, intersect
            if country.upper() not in region_countries:
                console.print(f"[yellow]{country} is not in region {region}[/yellow]")
                return
        # We'll filter by region after the query

    # Get more results initially if we need to filter
    query_limit = limit * 3 if (tier or min_networks or region) else limit

    facilities = db.search_facilities(
        name=name,
        city=city,
        state=state,
        country=country if not region else None,  # Don't filter by country if region specified
        owner=owner,
        clli_code=clli,
        site_code=site_code,
        limit=query_limit,
    )

    # Apply tier filter
    if tier:
        tier_num = int(tier)
        facilities = [f for f in facilities if get_facility_tier(f.net_count)[0] == tier_num]

    # Apply min_networks filter
    if min_networks:
        facilities = [f for f in facilities if (f.net_count or 0) >= min_networks]

    # Apply region filter
    if region:
        region_countries = REGION_COUNTRIES.get(region, [])
        facilities = [f for f in facilities if f.country and f.country.upper() in region_countries]

    # Sort
    if sort == "networks":
        facilities.sort(key=lambda f: f.net_count or 0, reverse=True)
    elif sort == "name":
        facilities.sort(key=lambda f: f.name or "")
    elif sort == "country":
        facilities.sort(key=lambda f: (f.country or "", f.name or ""))

    # Apply final limit
    facilities = facilities[:limit]

    if json_out:
        output = []
        for f in facilities:
            data = f.to_dict()
            tier_num, tier_label = get_facility_tier(f.net_count)
            data["tier"] = tier_num
            data["tier_label"] = tier_label
            output.append(data)
        click.echo(json.dumps(output, indent=2))
        return

    if not facilities:
        console.print("[yellow]No facilities found matching criteria[/yellow]")
        return

    title = f"Facilities ({len(facilities)} results)"
    if tier:
        title += f" - Tier {tier}"
    if region:
        title += f" - {region}"

    table = Table(title=title)
    table.add_column("ID", style="dim")
    table.add_column("Tier", justify="center")
    table.add_column("Name", style="cyan")
    table.add_column("City")
    table.add_column("Country")
    table.add_column("Owner", style="blue")
    table.add_column("Networks", justify="right")

    for fac in facilities:
        tier_num, tier_label = get_facility_tier(fac.net_count)
        tier_style = {1: "green bold", 2: "green", 3: "yellow", 4: "dim"}.get(tier_num, "")
        table.add_row(
            str(fac.peeringdb_id or fac.id),
            f"[{tier_style}]{tier_num}[/{tier_style}]",
            (fac.name or "?")[:40],
            fac.city or "?",
            fac.country or "?",
            (fac.owner or "?")[:25],
            str(fac.net_count or 0),
        )

    console.print(table)

    # Show tier legend
    console.print()
    console.print("[dim]Tier Legend: 1=Major Hub (100+ nets), 2=Regional (30-99), 3=Metro (10-29), 4=Edge (<10)[/dim]")


@facility.command()
@click.argument("facility_id", type=int)
@click.option("--json-output", "json_out", is_flag=True, help="Output as JSON")
def info(facility_id: int, json_out: bool):
    """Show detailed facility information.

    FACILITY_ID is the PeeringDB facility ID.

    \b
    Example:
        globaldetect facility info 1234
    """
    db = get_db()

    fac = db.get_facility(peeringdb_id=facility_id)
    if not fac:
        console.print(f"[red]Facility {facility_id} not found[/red]")
        raise SystemExit(1)

    # Get related data
    networks = db.get_networks_at_facility(facility_id)
    carriers = db.get_carriers_at_facility(facility_id)
    ixs = db.get_ixs_at_facility(facility_id)

    if json_out:
        output = fac.to_dict()
        output["networks_present"] = networks
        output["carriers_present"] = carriers
        output["exchanges_present"] = ixs
        click.echo(json.dumps(output, indent=2))
        return

    # Basic info panel
    info_text = f"""[bold]{fac.name}[/bold]
{fac.aka or ''}

[cyan]Location:[/cyan]
  {fac.address1 or ''}
  {fac.address2 or ''}
  {fac.city or ''}, {fac.state or ''} {fac.zipcode or ''}
  {fac.country or ''}
  Coords: {fac.latitude}, {fac.longitude}

[cyan]Owner/Operator:[/cyan]
  Owner: {fac.owner or 'Unknown'}
  Operator: {fac.operator or fac.owner or 'Unknown'}

[cyan]Contact:[/cyan]
  Sales: {fac.sales_email or 'N/A'} / {fac.sales_phone or 'N/A'}
  Tech: {fac.tech_email or 'N/A'} / {fac.tech_phone or 'N/A'}
  Website: {fac.website or 'N/A'}

[cyan]Codes:[/cyan]
  PeeringDB ID: {fac.peeringdb_id}
  CLLI: {fac.clli_code or 'N/A'}
  Site Code: {fac.site_code or 'N/A'}

[cyan]Presence:[/cyan]
  Networks: {len(networks)}
  Carriers: {len(carriers)}
  Exchanges: {len(ixs)}
"""

    console.print(Panel(info_text, title=f"Facility: {fac.name}"))

    # Networks table
    if networks:
        net_table = Table(title=f"Networks at {fac.name} ({len(networks)} total)")
        net_table.add_column("ASN", justify="right")
        net_table.add_column("Name")
        net_table.add_column("Type")
        net_table.add_column("Policy")

        for net in networks[:20]:  # Show first 20
            net_table.add_row(
                str(net.get("asn", "?")),
                (net.get("name") or "?")[:40],
                net.get("type") or "?",
                net.get("policy") or "?",
            )

        if len(networks) > 20:
            net_table.add_row("...", f"[dim]and {len(networks) - 20} more[/dim]", "", "")

        console.print(net_table)

    # Carriers table
    if carriers:
        carrier_table = Table(title=f"Carriers at {fac.name} ({len(carriers)} total)")
        carrier_table.add_column("Name")
        carrier_table.add_column("Organization")
        carrier_table.add_column("Website")

        for carrier in carriers[:20]:
            carrier_table.add_row(
                (carrier.get("name") or "?")[:30],
                (carrier.get("org") or "?")[:30],
                carrier.get("website") or "N/A",
            )

        if len(carriers) > 20:
            carrier_table.add_row("...", f"[dim]and {len(carriers) - 20} more[/dim]", "")

        console.print(carrier_table)

    # IXs table
    if ixs:
        ix_table = Table(title=f"Internet Exchanges at {fac.name} ({len(ixs)} total)")
        ix_table.add_column("Name")
        ix_table.add_column("City")
        ix_table.add_column("Country")
        ix_table.add_column("Networks", justify="right")

        for ix in ixs:
            ix_table.add_row(
                (ix.get("name") or "?")[:40],
                ix.get("city") or "?",
                ix.get("country") or "?",
                str(ix.get("net_count") or 0),
            )

        console.print(ix_table)


@facility.command()
@click.option("--name", "-n", help="Search by network name")
@click.option("--asn", "-a", type=int, help="Search by ASN")
@click.option("--type", "net_type", help="Filter by network type (NSP, ISP, Content, etc.)")
@click.option("--limit", "-l", default=50, help="Maximum results")
@click.option("--json-output", "json_out", is_flag=True, help="Output as JSON")
def networks(
    name: str | None,
    asn: int | None,
    net_type: str | None,
    limit: int,
    json_out: bool,
):
    """Search networks.

    \b
    Examples:
        # Search by name
        globaldetect facility networks --name Cloudflare

        # Search by ASN
        globaldetect facility networks --asn 13335

        # Filter by type
        globaldetect facility networks --type Content
    """
    db = get_db()

    results = db.search_networks(name=name, asn=asn, info_type=net_type, limit=limit)

    if json_out:
        click.echo(json.dumps([n.to_dict() for n in results], indent=2))
        return

    if not results:
        console.print("[yellow]No networks found matching criteria[/yellow]")
        return

    table = Table(title=f"Networks ({len(results)} results)")
    table.add_column("ASN", style="cyan", justify="right")
    table.add_column("Name")
    table.add_column("Type")
    table.add_column("Policy")
    table.add_column("Facilities", justify="right")

    for net in results:
        table.add_row(
            str(net.asn or "?"),
            (net.name or "?")[:40],
            net.info_type or "?",
            net.policy_general or "?",
            str(net.fac_count or 0),
        )

    console.print(table)


@facility.command()
@click.option("--name", "-n", help="Search by carrier name")
@click.option("--limit", "-l", default=50, help="Maximum results")
@click.option("--json-output", "json_out", is_flag=True, help="Output as JSON")
def carriers(name: str | None, limit: int, json_out: bool):
    """Search carriers (L1/L2 service providers).

    \b
    Examples:
        # List all carriers
        globaldetect facility carriers

        # Search by name
        globaldetect facility carriers --name Zayo
    """
    db = get_db()

    results = db.search_carriers(name=name, limit=limit)

    if json_out:
        click.echo(json.dumps([c.to_dict() for c in results], indent=2))
        return

    if not results:
        console.print("[yellow]No carriers found matching criteria[/yellow]")
        return

    table = Table(title=f"Carriers ({len(results)} results)")
    table.add_column("ID", style="dim")
    table.add_column("Name", style="cyan")
    table.add_column("Organization")
    table.add_column("Website")

    for carrier in results:
        table.add_row(
            str(carrier.peeringdb_id or carrier.id),
            carrier.name or "?",
            (carrier.org_name or "?")[:30],
            carrier.website or "N/A",
        )

    console.print(table)


@facility.command()
@click.option("--name", "-n", help="Search by IX name")
@click.option("--country", "-c", help="Filter by country code")
@click.option("--limit", "-l", default=50, help="Maximum results")
@click.option("--json-output", "json_out", is_flag=True, help="Output as JSON")
def exchanges(name: str | None, country: str | None, limit: int, json_out: bool):
    """Search Internet Exchanges.

    \b
    Examples:
        # List all exchanges
        globaldetect facility exchanges

        # Search by country
        globaldetect facility exchanges --country US

        # Search by name
        globaldetect facility exchanges --name DE-CIX
    """
    db = get_db()

    results = db.search_exchanges(name=name, country=country, limit=limit)

    if json_out:
        click.echo(json.dumps([ix.to_dict() for ix in results], indent=2))
        return

    if not results:
        console.print("[yellow]No exchanges found matching criteria[/yellow]")
        return

    table = Table(title=f"Internet Exchanges ({len(results)} results)")
    table.add_column("ID", style="dim")
    table.add_column("Name", style="cyan")
    table.add_column("City")
    table.add_column("Country")
    table.add_column("Networks", justify="right")

    for ix in results:
        table.add_row(
            str(ix.peeringdb_id or ix.id),
            ix.name or "?",
            ix.city or "?",
            ix.country or "?",
            str(ix.net_count or 0),
        )

    console.print(table)


# ================================================================
# Statistics
# ================================================================

@facility.command()
@click.option("--json-output", "json_out", is_flag=True, help="Output as JSON")
def stats(json_out: bool):
    """Show database statistics.

    \b
    Example:
        globaldetect facility stats
    """
    db = get_db()
    statistics = db.get_stats()

    if json_out:
        click.echo(json.dumps(statistics, indent=2))
        return

    console.print(Panel(
        f"""[bold]Database Statistics[/bold]

[cyan]Entities:[/cyan]
  Facilities:           {statistics['facilities']:,}
  Networks:             {statistics['networks']:,}
  Carriers:             {statistics['carriers']:,}
  Internet Exchanges:   {statistics['exchanges']:,}

[cyan]Relationships:[/cyan]
  Network-Facility:     {statistics['network_facilities']:,}
  Carrier-Facility:     {statistics['carrier_facilities']:,}
  IX-Facility:          {statistics['ix_facilities']:,}

[cyan]Database:[/cyan]
  Path: {statistics['database_path']}
""",
        title="Facilities Statistics",
    ))

    # Top countries
    if statistics.get("top_countries"):
        table = Table(title="Top Countries by Facility Count")
        table.add_column("Country", style="cyan")
        table.add_column("Facilities", justify="right")

        for country in statistics["top_countries"]:
            table.add_row(country["country"], str(country["count"]))

        console.print(table)

    # Last sync
    if statistics.get("last_sync"):
        sync_info = statistics["last_sync"]
        console.print(f"\n[dim]Last sync: {sync_info.get('completed_at', 'Never')}[/dim]")


# ================================================================
# Live query (direct API)
# ================================================================

@facility.command()
@click.argument("facility_id", type=int)
@click.option("--json-output", "json_out", is_flag=True, help="Output as JSON")
def live(facility_id: int, json_out: bool):
    """Fetch live facility data from PeeringDB API.

    Bypasses local database and queries PeeringDB directly.

    \b
    Example:
        globaldetect facility live 1234
    """
    async def fetch():
        async with PeeringDBClient() as client:
            return await client.get_facility_details(facility_id)

    if not json_out:
        console.print(f"[dim]Fetching facility {facility_id} from PeeringDB...[/dim]")

    try:
        details = asyncio.run(fetch())
    except Exception as e:
        console.print(f"[red]Error: {e}[/red]")
        raise SystemExit(1)

    if json_out:
        click.echo(json.dumps(details, indent=2))
        return

    if not details.get("facility"):
        console.print(f"[red]Facility {facility_id} not found[/red]")
        raise SystemExit(1)

    fac = details["facility"]
    console.print(Panel(
        f"""[bold]{fac.get('name')}[/bold]

Location: {fac.get('city')}, {fac.get('state')} {fac.get('country')}
Owner: {fac.get('owner')}
Website: {fac.get('website')}

Networks: {details.get('network_count', 0)}
Carriers: {details.get('carrier_count', 0)}
Exchanges: {details.get('exchange_count', 0)}
""",
        title="Live Facility Data",
    ))


if __name__ == "__main__":
    facility()
