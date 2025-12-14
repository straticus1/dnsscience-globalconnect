"""
Cloudflare API Client

Provides access to Cloudflare's network services including:
- DNS lookups via 1.1.1.1
- Radar API for network intelligence
- Speed test endpoints
"""

import asyncio
from dataclasses import dataclass, field
from typing import Any

import httpx

from globaldetect.config import get_config


CLOUDFLARE_API = "https://api.cloudflare.com/client/v4"
CLOUDFLARE_RADAR = "https://api.cloudflare.com/client/v4/radar"
CLOUDFLARE_DNS = "https://cloudflare-dns.com/dns-query"


@dataclass
class CloudflareDNSResult:
    """Result from Cloudflare DNS-over-HTTPS lookup."""
    name: str
    record_type: str
    ttl: int
    data: str


@dataclass
class CloudflareASNInfo:
    """ASN information from Cloudflare Radar."""
    asn: int
    name: str | None = None
    country: str | None = None
    domain: str | None = None
    org_type: str | None = None
    ipv4_count: int = 0
    ipv6_count: int = 0


@dataclass
class CloudflareTraceResult:
    """Result from Cloudflare trace endpoint."""
    ip: str
    location: str | None = None
    colo: str | None = None  # Cloudflare datacenter code
    http_version: str | None = None
    tls_version: str | None = None
    sni: str | None = None
    warp: str | None = None
    gateway: str | None = None
    ts: str | None = None


class CloudflareClient:
    """Client for Cloudflare APIs."""

    def __init__(self, api_token: str | None = None, account_id: str | None = None):
        config = get_config()
        self.api_token = api_token or config.cloudflare_api_token
        self.account_id = account_id or config.cloudflare_account_id

    def _get_headers(self) -> dict[str, str]:
        """Get authorization headers."""
        headers = {"Content-Type": "application/json"}
        if self.api_token:
            headers["Authorization"] = f"Bearer {self.api_token}"
        return headers

    async def dns_lookup_async(
        self,
        name: str,
        record_type: str = "A",
    ) -> list[CloudflareDNSResult]:
        """Perform DNS lookup via Cloudflare DNS-over-HTTPS."""
        results = []

        async with httpx.AsyncClient() as client:
            try:
                resp = await client.get(
                    CLOUDFLARE_DNS,
                    headers={"Accept": "application/dns-json"},
                    params={"name": name, "type": record_type},
                    timeout=10.0,
                )
                resp.raise_for_status()
                data = resp.json()

                for answer in data.get("Answer", []):
                    results.append(CloudflareDNSResult(
                        name=answer.get("name", name),
                        record_type=record_type,
                        ttl=answer.get("TTL", 0),
                        data=answer.get("data", ""),
                    ))

            except Exception:
                pass

        return results

    def dns_lookup(self, name: str, record_type: str = "A") -> list[CloudflareDNSResult]:
        """Synchronous DNS lookup."""
        return asyncio.run(self.dns_lookup_async(name, record_type))

    async def trace_async(self) -> CloudflareTraceResult:
        """Get trace information from Cloudflare edge."""
        result = CloudflareTraceResult(ip="unknown")

        async with httpx.AsyncClient() as client:
            try:
                resp = await client.get(
                    "https://1.1.1.1/cdn-cgi/trace",
                    timeout=10.0,
                )
                resp.raise_for_status()

                # Parse key=value format
                data = {}
                for line in resp.text.strip().split("\n"):
                    if "=" in line:
                        key, value = line.split("=", 1)
                        data[key] = value

                result.ip = data.get("ip", "unknown")
                result.location = data.get("loc")
                result.colo = data.get("colo")
                result.http_version = data.get("http")
                result.tls_version = data.get("tls")
                result.sni = data.get("sni")
                result.warp = data.get("warp")
                result.gateway = data.get("gateway")
                result.ts = data.get("ts")

            except Exception:
                pass

        return result

    def trace(self) -> CloudflareTraceResult:
        """Synchronous trace."""
        return asyncio.run(self.trace_async())

    async def get_asn_info_async(self, asn: int) -> CloudflareASNInfo | None:
        """Get ASN information from Cloudflare Radar (requires API token)."""
        if not self.api_token:
            return None

        async with httpx.AsyncClient() as client:
            try:
                resp = await client.get(
                    f"{CLOUDFLARE_RADAR}/entities/asns/{asn}",
                    headers=self._get_headers(),
                    timeout=10.0,
                )
                resp.raise_for_status()
                data = resp.json()

                if data.get("success") and data.get("result"):
                    result_data = data["result"]["asn"]
                    return CloudflareASNInfo(
                        asn=result_data.get("asn", asn),
                        name=result_data.get("name"),
                        country=result_data.get("country"),
                        domain=result_data.get("website"),
                        org_type=result_data.get("orgType"),
                    )

            except Exception:
                pass

        return None

    def get_asn_info(self, asn: int) -> CloudflareASNInfo | None:
        """Synchronous ASN lookup."""
        return asyncio.run(self.get_asn_info_async(asn))

    async def get_ip_asn_async(self, ip: str) -> CloudflareASNInfo | None:
        """Get ASN information for an IP from Cloudflare Radar."""
        if not self.api_token:
            return None

        async with httpx.AsyncClient() as client:
            try:
                resp = await client.get(
                    f"{CLOUDFLARE_RADAR}/entities/ip",
                    headers=self._get_headers(),
                    params={"ip": ip},
                    timeout=10.0,
                )
                resp.raise_for_status()
                data = resp.json()

                if data.get("success") and data.get("result"):
                    result_data = data["result"]
                    asn_data = result_data.get("asn", {})
                    return CloudflareASNInfo(
                        asn=asn_data.get("asn", 0),
                        name=asn_data.get("name"),
                        country=asn_data.get("country"),
                    )

            except Exception:
                pass

        return None

    def get_ip_asn(self, ip: str) -> CloudflareASNInfo | None:
        """Synchronous IP to ASN lookup."""
        return asyncio.run(self.get_ip_asn_async(ip))

    async def speed_test_async(self) -> dict[str, Any]:
        """Perform a basic speed test using Cloudflare's speed test endpoint."""
        results = {
            "download_mbps": None,
            "latency_ms": None,
            "jitter_ms": None,
            "colo": None,
        }

        async with httpx.AsyncClient() as client:
            try:
                import time

                # Get trace info first
                trace = await self.trace_async()
                results["colo"] = trace.colo

                # Measure latency with small request
                start = time.monotonic()
                await client.get("https://speed.cloudflare.com/__down?bytes=0", timeout=10.0)
                results["latency_ms"] = round((time.monotonic() - start) * 1000, 2)

                # Download test (100KB)
                start = time.monotonic()
                resp = await client.get(
                    "https://speed.cloudflare.com/__down?bytes=102400",
                    timeout=30.0,
                )
                elapsed = time.monotonic() - start
                bytes_received = len(resp.content)
                results["download_mbps"] = round((bytes_received * 8) / (elapsed * 1_000_000), 2)

            except Exception:
                pass

        return results

    def speed_test(self) -> dict[str, Any]:
        """Synchronous speed test."""
        return asyncio.run(self.speed_test_async())
