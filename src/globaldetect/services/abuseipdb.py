"""
AbuseIPDB API Client

Provides IP reputation checking and abuse reporting.
"""

import asyncio
from dataclasses import dataclass, field
from typing import Any

import httpx

from globaldetect.config import get_config


ABUSEIPDB_API = "https://api.abuseipdb.com/api/v2"


@dataclass
class IPReputationResult:
    """IP reputation result from AbuseIPDB."""
    ip: str
    is_public: bool = True
    abuse_confidence_score: int = 0  # 0-100
    country_code: str | None = None
    usage_type: str | None = None
    isp: str | None = None
    domain: str | None = None
    total_reports: int = 0
    num_distinct_users: int = 0
    last_reported_at: str | None = None
    is_whitelisted: bool = False
    is_tor: bool = False
    categories: list[int] = field(default_factory=list)
    category_names: list[str] = field(default_factory=list)
    error: str | None = None


# AbuseIPDB category mapping
ABUSE_CATEGORIES = {
    1: "DNS Compromise",
    2: "DNS Poisoning",
    3: "Fraud Orders",
    4: "DDoS Attack",
    5: "FTP Brute-Force",
    6: "Ping of Death",
    7: "Phishing",
    8: "Fraud VoIP",
    9: "Open Proxy",
    10: "Web Spam",
    11: "Email Spam",
    12: "Blog Spam",
    13: "VPN IP",
    14: "Port Scan",
    15: "Hacking",
    16: "SQL Injection",
    17: "Spoofing",
    18: "Brute-Force",
    19: "Bad Web Bot",
    20: "Exploited Host",
    21: "Web App Attack",
    22: "SSH",
    23: "IoT Targeted",
}


class AbuseIPDBClient:
    """Client for AbuseIPDB API."""

    def __init__(self, api_key: str | None = None):
        self.api_key = api_key or get_config().abuseipdb_api_key
        self.base_url = ABUSEIPDB_API
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

    def _get_headers(self) -> dict[str, str]:
        """Get authorization headers."""
        return {
            "Key": self.api_key,
            "Accept": "application/json",
        }

    async def check_ip_async(self, ip: str, max_age_days: int = 90) -> IPReputationResult:
        """Check IP reputation."""
        result = IPReputationResult(ip=ip)

        if not self.api_key:
            result.error = "AbuseIPDB API key not configured"
            return result

        client = await self._get_client()
        try:
            resp = await client.get(
                f"{self.base_url}/check",
                headers=self._get_headers(),
                params={
                    "ipAddress": ip,
                    "maxAgeInDays": max_age_days,
                    "verbose": True,
                },
            )
            resp.raise_for_status()
            data = resp.json()

            if "data" in data:
                ip_data = data["data"]
                result.is_public = ip_data.get("isPublic", True)
                result.abuse_confidence_score = ip_data.get("abuseConfidenceScore", 0)
                result.country_code = ip_data.get("countryCode")
                result.usage_type = ip_data.get("usageType")
                result.isp = ip_data.get("isp")
                result.domain = ip_data.get("domain")
                result.total_reports = ip_data.get("totalReports", 0)
                result.num_distinct_users = ip_data.get("numDistinctUsers", 0)
                result.last_reported_at = ip_data.get("lastReportedAt")
                result.is_whitelisted = ip_data.get("isWhitelisted", False)
                result.is_tor = ip_data.get("isTor", False)

                # Map categories to names
                categories = ip_data.get("reports", [])
                seen_cats = set()
                for report in categories:
                    for cat_id in report.get("categories", []):
                        if cat_id not in seen_cats:
                            seen_cats.add(cat_id)
                            result.categories.append(cat_id)
                            if cat_id in ABUSE_CATEGORIES:
                                result.category_names.append(ABUSE_CATEGORIES[cat_id])

            elif "errors" in data:
                result.error = data["errors"][0].get("detail", "Unknown error")

        except httpx.HTTPStatusError as e:
            result.error = f"HTTP {e.response.status_code}: {e.response.text}"
        except Exception as e:
            result.error = str(e)

        return result

    def check_ip(self, ip: str, max_age_days: int = 90) -> IPReputationResult:
        """Synchronous IP check."""
        return asyncio.run(self.check_ip_async(ip, max_age_days))

    async def check_block_async(self, network: str, max_age_days: int = 30) -> list[IPReputationResult]:
        """Check a CIDR block for reported IPs."""
        results = []

        if not self.api_key:
            return results

        client = await self._get_client()
        try:
            resp = await client.get(
                f"{self.base_url}/check-block",
                headers=self._get_headers(),
                params={
                    "network": network,
                    "maxAgeInDays": max_age_days,
                },
            )
            resp.raise_for_status()
            data = resp.json()

            for ip_data in data.get("data", {}).get("reportedAddress", []):
                result = IPReputationResult(
                    ip=ip_data.get("ipAddress", ""),
                    abuse_confidence_score=ip_data.get("abuseConfidenceScore", 0),
                    country_code=ip_data.get("countryCode"),
                    total_reports=ip_data.get("numReports", 0),
                    last_reported_at=ip_data.get("mostRecentReport"),
                )
                results.append(result)

        except Exception:
            pass

        return results

    def check_block(self, network: str, max_age_days: int = 30) -> list[IPReputationResult]:
        """Synchronous block check."""
        return asyncio.run(self.check_block_async(network, max_age_days))

    async def get_blacklist_async(self, confidence_minimum: int = 90, limit: int = 10000) -> list[str]:
        """Get blacklisted IPs above a confidence threshold."""
        if not self.api_key:
            return []

        client = await self._get_client()
        try:
            resp = await client.get(
                f"{self.base_url}/blacklist",
                headers=self._get_headers(),
                params={
                    "confidenceMinimum": confidence_minimum,
                    "limit": limit,
                },
            )
            resp.raise_for_status()
            data = resp.json()

            return [ip.get("ipAddress") for ip in data.get("data", []) if ip.get("ipAddress")]

        except Exception:
            return []

    def get_blacklist(self, confidence_minimum: int = 90, limit: int = 10000) -> list[str]:
        """Synchronous blacklist retrieval."""
        return asyncio.run(self.get_blacklist_async(confidence_minimum, limit))

    def get_category_name(self, category_id: int) -> str:
        """Get the name for a category ID."""
        return ABUSE_CATEGORIES.get(category_id, f"Unknown ({category_id})")
