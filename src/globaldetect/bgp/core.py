"""
Core BGP/Routing functionality.
"""

import asyncio
import socket
from dataclasses import dataclass, field
from typing import Any

import httpx


PEERINGDB_API = "https://www.peeringdb.com/api"
BGPVIEW_API = "https://api.bgpview.io"
RIPESTAT_API = "https://stat.ripe.net/data"


@dataclass
class ASInfo:
    """Information about an Autonomous System."""
    asn: int
    name: str | None = None
    description: str | None = None
    country: str | None = None
    rir: str | None = None
    looking_glass: str | None = None
    traffic_levels: str | None = None
    traffic_ratios: str | None = None
    network_type: str | None = None
    prefixes_v4: int = 0
    prefixes_v6: int = 0
    peers: int = 0
    ix_count: int = 0
    facility_count: int = 0
    website: str | None = None
    abuse_contact: str | None = None
    ixs: list[dict] = field(default_factory=list)
    prefixes: list[str] = field(default_factory=list)


@dataclass
class PrefixInfo:
    """Information about an IP prefix."""
    prefix: str
    asn: int | None = None
    as_name: str | None = None
    country: str | None = None
    rir: str | None = None
    description: str | None = None
    parent_prefix: str | None = None
    related_prefixes: list[str] = field(default_factory=list)


class PeeringDBClient:
    """Client for PeeringDB API."""

    def __init__(self):
        self.base_url = PEERINGDB_API

    async def get_network(self, asn: int) -> dict | None:
        """Get network information from PeeringDB."""
        async with httpx.AsyncClient() as client:
            try:
                resp = await client.get(
                    f"{self.base_url}/net",
                    params={"asn": asn},
                    timeout=10.0,
                )
                resp.raise_for_status()
                data = resp.json()
                if data.get("data"):
                    return data["data"][0]
            except Exception:
                pass
        return None

    async def get_ix_list(self, asn: int) -> list[dict]:
        """Get list of IXs where an AS is present."""
        async with httpx.AsyncClient() as client:
            try:
                # First get the network ID
                net_resp = await client.get(
                    f"{self.base_url}/net",
                    params={"asn": asn},
                    timeout=10.0,
                )
                net_resp.raise_for_status()
                net_data = net_resp.json()

                if not net_data.get("data"):
                    return []

                net_id = net_data["data"][0]["id"]

                # Get IX connections
                ix_resp = await client.get(
                    f"{self.base_url}/netixlan",
                    params={"net_id": net_id},
                    timeout=10.0,
                )
                ix_resp.raise_for_status()
                ix_data = ix_resp.json()

                return ix_data.get("data", [])
            except Exception:
                pass
        return []

    async def get_facilities(self, asn: int) -> list[dict]:
        """Get list of facilities where an AS is present."""
        async with httpx.AsyncClient() as client:
            try:
                net_resp = await client.get(
                    f"{self.base_url}/net",
                    params={"asn": asn},
                    timeout=10.0,
                )
                net_resp.raise_for_status()
                net_data = net_resp.json()

                if not net_data.get("data"):
                    return []

                net_id = net_data["data"][0]["id"]

                fac_resp = await client.get(
                    f"{self.base_url}/netfac",
                    params={"net_id": net_id},
                    timeout=10.0,
                )
                fac_resp.raise_for_status()
                fac_data = fac_resp.json()

                return fac_data.get("data", [])
            except Exception:
                pass
        return []

    async def search_ix(self, query: str) -> list[dict]:
        """Search for Internet Exchanges."""
        async with httpx.AsyncClient() as client:
            try:
                resp = await client.get(
                    f"{self.base_url}/ix",
                    params={"name__contains": query},
                    timeout=10.0,
                )
                resp.raise_for_status()
                return resp.json().get("data", [])
            except Exception:
                pass
        return []


async def _get_bgpview_asn(asn: int) -> dict | None:
    """Get AS info from BGPView API."""
    async with httpx.AsyncClient() as client:
        try:
            resp = await client.get(f"{BGPVIEW_API}/asn/{asn}", timeout=10.0)
            resp.raise_for_status()
            data = resp.json()
            if data.get("status") == "ok":
                return data.get("data")
        except Exception:
            pass
    return None


async def _get_bgpview_prefixes(asn: int) -> dict | None:
    """Get prefixes announced by an AS from BGPView."""
    async with httpx.AsyncClient() as client:
        try:
            resp = await client.get(f"{BGPVIEW_API}/asn/{asn}/prefixes", timeout=10.0)
            resp.raise_for_status()
            data = resp.json()
            if data.get("status") == "ok":
                return data.get("data")
        except Exception:
            pass
    return None


async def _get_bgpview_prefix(prefix: str) -> dict | None:
    """Get prefix info from BGPView API."""
    # URL encode the prefix
    encoded = prefix.replace("/", "%2F")
    async with httpx.AsyncClient() as client:
        try:
            resp = await client.get(f"{BGPVIEW_API}/prefix/{encoded}", timeout=10.0)
            resp.raise_for_status()
            data = resp.json()
            if data.get("status") == "ok":
                return data.get("data")
        except Exception:
            pass
    return None


async def _get_ripestat_prefix(prefix: str) -> dict | None:
    """Get prefix info from RIPE Stat API."""
    async with httpx.AsyncClient() as client:
        try:
            resp = await client.get(
                f"{RIPESTAT_API}/prefix-overview/data.json",
                params={"resource": prefix},
                timeout=10.0,
            )
            resp.raise_for_status()
            data = resp.json()
            return data.get("data")
        except Exception:
            pass
    return None


async def get_as_info_async(asn: int) -> ASInfo:
    """Get comprehensive information about an AS."""
    # Normalize ASN input
    if isinstance(asn, str):
        asn = int(asn.upper().replace("AS", ""))

    info = ASInfo(asn=asn)

    # Fetch from multiple sources in parallel
    pdb = PeeringDBClient()
    bgpview_task = _get_bgpview_asn(asn)
    pdb_task = pdb.get_network(asn)
    prefixes_task = _get_bgpview_prefixes(asn)
    ix_task = pdb.get_ix_list(asn)

    bgpview, pdb_data, prefixes_data, ix_data = await asyncio.gather(
        bgpview_task, pdb_task, prefixes_task, ix_task,
        return_exceptions=True
    )

    # Process BGPView data
    if isinstance(bgpview, dict):
        info.name = bgpview.get("name")
        info.description = bgpview.get("description_short")
        info.country = bgpview.get("country_code")
        info.rir = bgpview.get("rir_allocation", {}).get("rir_name") if bgpview.get("rir_allocation") else None
        info.website = bgpview.get("website")
        info.abuse_contact = bgpview.get("abuse_contacts", [None])[0] if bgpview.get("abuse_contacts") else None

    # Process PeeringDB data
    if isinstance(pdb_data, dict):
        info.name = info.name or pdb_data.get("name")
        info.looking_glass = pdb_data.get("looking_glass")
        info.traffic_levels = pdb_data.get("info_traffic")
        info.traffic_ratios = pdb_data.get("info_ratio")
        info.network_type = pdb_data.get("info_type")

    # Process prefixes
    if isinstance(prefixes_data, dict):
        v4 = prefixes_data.get("ipv4_prefixes", [])
        v6 = prefixes_data.get("ipv6_prefixes", [])
        info.prefixes_v4 = len(v4)
        info.prefixes_v6 = len(v6)
        info.prefixes = [p.get("prefix") for p in (v4 + v6)[:50]]  # Limit to first 50

    # Process IX data
    if isinstance(ix_data, list):
        info.ix_count = len(ix_data)
        # Extract unique IX names
        seen_ixs = set()
        for ix in ix_data:
            ix_name = ix.get("name")
            if ix_name and ix_name not in seen_ixs:
                seen_ixs.add(ix_name)
                info.ixs.append({
                    "name": ix_name,
                    "ipv4": ix.get("ipaddr4"),
                    "ipv6": ix.get("ipaddr6"),
                    "speed": ix.get("speed"),
                })

    return info


async def get_prefix_info_async(prefix: str) -> PrefixInfo:
    """Get information about an IP prefix."""
    info = PrefixInfo(prefix=prefix)

    # Fetch from multiple sources
    bgpview_task = _get_bgpview_prefix(prefix)
    ripe_task = _get_ripestat_prefix(prefix)

    bgpview, ripe = await asyncio.gather(
        bgpview_task, ripe_task,
        return_exceptions=True
    )

    # Process BGPView data
    if isinstance(bgpview, dict):
        asns = bgpview.get("asns", [])
        if asns:
            info.asn = asns[0].get("asn")
            info.as_name = asns[0].get("name")
            info.description = asns[0].get("description")
            info.country = asns[0].get("country_code")
        info.rir = bgpview.get("rir_allocation", {}).get("rir_name") if bgpview.get("rir_allocation") else None
        info.parent_prefix = bgpview.get("parent", {}).get("prefix") if bgpview.get("parent") else None

        # Get related prefixes
        related = bgpview.get("related_prefixes", [])
        info.related_prefixes = [r.get("prefix") for r in related[:20]]

    # Process RIPE data
    if isinstance(ripe, dict):
        if not info.asn:
            asns = ripe.get("asns", [])
            if asns:
                info.asn = asns[0].get("asn")
                info.as_name = asns[0].get("holder")

    return info


def get_as_info(asn: int) -> ASInfo:
    """Synchronous wrapper for get_as_info_async."""
    return asyncio.run(get_as_info_async(asn))


def get_prefix_info(prefix: str) -> PrefixInfo:
    """Synchronous wrapper for get_prefix_info_async."""
    return asyncio.run(get_prefix_info_async(prefix))


def get_whois_info(query: str) -> str:
    """Get WHOIS information for an IP or ASN."""
    # Determine appropriate WHOIS server
    whois_servers = {
        "arin": "whois.arin.net",
        "ripe": "whois.ripe.net",
        "apnic": "whois.apnic.net",
        "afrinic": "whois.afrinic.net",
        "lacnic": "whois.lacnic.net",
    }

    # Default to ARIN for now, could add RIR detection
    server = whois_servers["arin"]

    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(10)
        sock.connect((server, 43))
        sock.send(f"{query}\r\n".encode())

        response = b""
        while True:
            data = sock.recv(4096)
            if not data:
                break
            response += data

        sock.close()
        return response.decode("utf-8", errors="ignore")
    except Exception as e:
        return f"Error: {e}"
