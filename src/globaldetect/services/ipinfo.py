"""
IPInfo.io API Client

Provides IP geolocation, ASN information, and metadata lookups.

Copyright (c) 2025 DNS Science.io, an After Dark Systems, LLC company.
All rights reserved.
"""

import asyncio
from dataclasses import dataclass
from typing import Any

import httpx

from globaldetect.config import get_config


IPINFO_API = "https://ipinfo.io"


@dataclass
class IPInfoResult:
    """Result from IPInfo.io lookup."""
    ip: str
    hostname: str | None = None
    city: str | None = None
    region: str | None = None
    country: str | None = None
    loc: str | None = None  # "lat,lon"
    org: str | None = None  # "AS#### Organization Name"
    postal: str | None = None
    timezone: str | None = None
    asn: int | None = None
    as_name: str | None = None
    as_domain: str | None = None
    company_name: str | None = None
    company_domain: str | None = None
    company_type: str | None = None
    carrier_name: str | None = None
    carrier_mcc: str | None = None
    carrier_mnc: str | None = None
    is_vpn: bool = False
    is_proxy: bool = False
    is_tor: bool = False
    is_relay: bool = False
    is_hosting: bool = False
    error: str | None = None


class IPInfoClient:
    """Client for IPInfo.io API with connection pooling."""

    def __init__(self, token: str | None = None):
        self.token = token or get_config().ipinfo_token
        self.base_url = IPINFO_API
        self._client: httpx.AsyncClient | None = None

    async def _get_client(self) -> httpx.AsyncClient:
        """Get or create the HTTP client with connection pooling."""
        if self._client is None or self._client.is_closed:
            self._client = httpx.AsyncClient(
                timeout=httpx.Timeout(10.0, connect=5.0),
                limits=httpx.Limits(max_keepalive_connections=20, max_connections=100),
            )
        return self._client

    async def close(self) -> None:
        """Close the HTTP client and clean up resources."""
        if self._client is not None and not self._client.is_closed:
            await self._client.aclose()

    async def __aenter__(self):
        """Async context manager entry."""
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        """Async context manager exit."""
        await self.close()

    async def lookup_async(self, ip: str) -> IPInfoResult:
        """Look up IP information asynchronously."""
        result = IPInfoResult(ip=ip)

        headers = {}
        if self.token:
            headers["Authorization"] = f"Bearer {self.token}"

        client = await self._get_client()
        try:
            resp = await client.get(
                f"{self.base_url}/{ip}",
                headers=headers,
            )
            resp.raise_for_status()
            data = resp.json()

            result.hostname = data.get("hostname")
            result.city = data.get("city")
            result.region = data.get("region")
            result.country = data.get("country")
            result.loc = data.get("loc")
            result.org = data.get("org")
            result.postal = data.get("postal")
            result.timezone = data.get("timezone")

            # Parse ASN from org field (e.g., "AS15169 Google LLC")
            if result.org and result.org.startswith("AS"):
                parts = result.org.split(" ", 1)
                try:
                    result.asn = int(parts[0][2:])
                    if len(parts) > 1:
                        result.as_name = parts[1]
                except ValueError:
                    pass

            # Extended data (requires paid plans)
            if "asn" in data:
                asn_data = data["asn"]
                result.asn = int(asn_data.get("asn", "0").replace("AS", ""))
                result.as_name = asn_data.get("name")
                result.as_domain = asn_data.get("domain")

            if "company" in data:
                company = data["company"]
                result.company_name = company.get("name")
                result.company_domain = company.get("domain")
                result.company_type = company.get("type")

            if "carrier" in data:
                carrier = data["carrier"]
                result.carrier_name = carrier.get("name")
                result.carrier_mcc = carrier.get("mcc")
                result.carrier_mnc = carrier.get("mnc")

            if "privacy" in data:
                privacy = data["privacy"]
                result.is_vpn = privacy.get("vpn", False)
                result.is_proxy = privacy.get("proxy", False)
                result.is_tor = privacy.get("tor", False)
                result.is_relay = privacy.get("relay", False)
                result.is_hosting = privacy.get("hosting", False)

        except httpx.HTTPStatusError as e:
            result.error = f"HTTP {e.response.status_code}: {e.response.text}"
        except Exception as e:
            result.error = str(e)

        return result

    def lookup(self, ip: str) -> IPInfoResult:
        """Synchronous lookup."""
        return asyncio.run(self.lookup_async(ip))

    async def lookup_batch_async(self, ips: list[str]) -> list[IPInfoResult]:
        """Look up multiple IPs in parallel."""
        tasks = [self.lookup_async(ip) for ip in ips]
        return await asyncio.gather(*tasks)

    def lookup_batch(self, ips: list[str]) -> list[IPInfoResult]:
        """Synchronous batch lookup."""
        return asyncio.run(self.lookup_batch_async(ips))

    async def get_my_ip_async(self) -> IPInfoResult:
        """Get information about the current public IP."""
        headers = {}
        if self.token:
            headers["Authorization"] = f"Bearer {self.token}"

        client = await self._get_client()
        try:
            resp = await client.get(
                f"{self.base_url}/json",
                headers=headers,
            )
            resp.raise_for_status()
            data = resp.json()
            return await self.lookup_async(data["ip"])
        except Exception as e:
            return IPInfoResult(ip="unknown", error=str(e))

    def get_my_ip(self) -> IPInfoResult:
        """Synchronous version of get_my_ip."""
        return asyncio.run(self.get_my_ip_async())
