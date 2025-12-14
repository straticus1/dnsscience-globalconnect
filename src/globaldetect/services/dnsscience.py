"""
DNS Science API Client

Full integration with dnsscience.io API for comprehensive DNS intelligence.
"""

import asyncio
from dataclasses import dataclass, field
from typing import Any

import httpx

from globaldetect.config import get_config


@dataclass
class DomainScanResult:
    """Comprehensive domain scan result."""
    domain: str
    dns_records: dict[str, list[dict]] = field(default_factory=dict)
    whois: dict[str, Any] = field(default_factory=dict)
    ssl_info: dict[str, Any] = field(default_factory=dict)
    mx_records: list[dict] = field(default_factory=list)
    spf_record: str | None = None
    dmarc_record: str | None = None
    dkim_records: list[dict] = field(default_factory=list)
    dnssec_enabled: bool = False
    nameservers: list[str] = field(default_factory=list)
    registrar: str | None = None
    creation_date: str | None = None
    expiration_date: str | None = None
    hosting_provider: str | None = None
    ip_addresses: list[str] = field(default_factory=list)
    error: str | None = None


@dataclass
class ThreatIntelResult:
    """Threat intelligence result for a domain or IP."""
    target: str
    is_malicious: bool = False
    threat_types: list[str] = field(default_factory=list)
    risk_score: int = 0  # 0-100
    sources: list[str] = field(default_factory=list)
    first_seen: str | None = None
    last_seen: str | None = None
    blacklists: list[str] = field(default_factory=list)
    reputation: str | None = None
    error: str | None = None


@dataclass
class SubdomainResult:
    """Subdomain enumeration result."""
    domain: str
    subdomains: list[str] = field(default_factory=list)
    total_found: int = 0
    sources: list[str] = field(default_factory=list)
    error: str | None = None


@dataclass
class ReverseIPResult:
    """Reverse IP/DNS lookup result."""
    ip: str
    domains: list[str] = field(default_factory=list)
    hostname: str | None = None
    asn: int | None = None
    as_name: str | None = None
    error: str | None = None


class DNSScienceClient:
    """Client for DNS Science API."""

    def __init__(self, api_key: str | None = None, base_url: str | None = None):
        config = get_config()
        self.api_key = api_key or config.dnsscience_api_key
        self.base_url = (base_url or config.dnsscience_api_url).rstrip("/")

    def _get_headers(self) -> dict[str, str]:
        """Get authorization headers."""
        headers = {"Content-Type": "application/json"}
        if self.api_key:
            headers["X-API-Key"] = self.api_key
        return headers

    async def scan_domain_async(self, domain: str, full: bool = False) -> DomainScanResult:
        """Perform comprehensive domain scan."""
        result = DomainScanResult(domain=domain)

        endpoint = "/scan/full" if full else "/scan/quick"

        async with httpx.AsyncClient() as client:
            try:
                resp = await client.post(
                    f"{self.base_url}{endpoint}",
                    headers=self._get_headers(),
                    json={"domain": domain},
                    timeout=60.0,
                )
                resp.raise_for_status()
                data = resp.json()

                if data.get("success"):
                    scan_data = data.get("data", {})
                    result.dns_records = scan_data.get("dns", {})
                    result.whois = scan_data.get("whois", {})
                    result.ssl_info = scan_data.get("ssl", {})
                    result.mx_records = scan_data.get("mx", [])
                    result.spf_record = scan_data.get("spf")
                    result.dmarc_record = scan_data.get("dmarc")
                    result.dkim_records = scan_data.get("dkim", [])
                    result.dnssec_enabled = scan_data.get("dnssec", False)
                    result.nameservers = scan_data.get("nameservers", [])
                    result.registrar = scan_data.get("registrar")
                    result.creation_date = scan_data.get("creation_date")
                    result.expiration_date = scan_data.get("expiration_date")
                    result.hosting_provider = scan_data.get("hosting_provider")
                    result.ip_addresses = scan_data.get("ips", [])
                else:
                    result.error = data.get("error", "Unknown error")

            except httpx.HTTPStatusError as e:
                result.error = f"HTTP {e.response.status_code}: {e.response.text}"
            except Exception as e:
                result.error = str(e)

        return result

    def scan_domain(self, domain: str, full: bool = False) -> DomainScanResult:
        """Synchronous domain scan."""
        return asyncio.run(self.scan_domain_async(domain, full))

    async def get_dns_records_async(self, domain: str, record_types: list[str] | None = None) -> dict[str, list[dict]]:
        """Get DNS records for a domain."""
        if record_types is None:
            record_types = ["A", "AAAA", "MX", "NS", "TXT", "CNAME", "SOA"]

        async with httpx.AsyncClient() as client:
            try:
                resp = await client.get(
                    f"{self.base_url}/dns/{domain}",
                    headers=self._get_headers(),
                    params={"types": ",".join(record_types)},
                    timeout=30.0,
                )
                resp.raise_for_status()
                data = resp.json()
                return data.get("data", {})
            except Exception:
                return {}

    def get_dns_records(self, domain: str, record_types: list[str] | None = None) -> dict[str, list[dict]]:
        """Synchronous DNS records lookup."""
        return asyncio.run(self.get_dns_records_async(domain, record_types))

    async def get_whois_async(self, domain: str) -> dict[str, Any]:
        """Get WHOIS information for a domain."""
        async with httpx.AsyncClient() as client:
            try:
                resp = await client.get(
                    f"{self.base_url}/whois/{domain}",
                    headers=self._get_headers(),
                    timeout=30.0,
                )
                resp.raise_for_status()
                data = resp.json()
                return data.get("data", {})
            except Exception:
                return {}

    def get_whois(self, domain: str) -> dict[str, Any]:
        """Synchronous WHOIS lookup."""
        return asyncio.run(self.get_whois_async(domain))

    async def get_threat_intel_async(self, target: str) -> ThreatIntelResult:
        """Get threat intelligence for a domain or IP."""
        result = ThreatIntelResult(target=target)

        async with httpx.AsyncClient() as client:
            try:
                resp = await client.get(
                    f"{self.base_url}/threat/{target}",
                    headers=self._get_headers(),
                    timeout=30.0,
                )
                resp.raise_for_status()
                data = resp.json()

                if data.get("success"):
                    threat_data = data.get("data", {})
                    result.is_malicious = threat_data.get("malicious", False)
                    result.threat_types = threat_data.get("threat_types", [])
                    result.risk_score = threat_data.get("risk_score", 0)
                    result.sources = threat_data.get("sources", [])
                    result.first_seen = threat_data.get("first_seen")
                    result.last_seen = threat_data.get("last_seen")
                    result.blacklists = threat_data.get("blacklists", [])
                    result.reputation = threat_data.get("reputation")
                else:
                    result.error = data.get("error", "Unknown error")

            except httpx.HTTPStatusError as e:
                result.error = f"HTTP {e.response.status_code}: {e.response.text}"
            except Exception as e:
                result.error = str(e)

        return result

    def get_threat_intel(self, target: str) -> ThreatIntelResult:
        """Synchronous threat intel lookup."""
        return asyncio.run(self.get_threat_intel_async(target))

    async def enumerate_subdomains_async(self, domain: str) -> SubdomainResult:
        """Enumerate subdomains for a domain."""
        result = SubdomainResult(domain=domain)

        async with httpx.AsyncClient() as client:
            try:
                resp = await client.get(
                    f"{self.base_url}/subdomains/{domain}",
                    headers=self._get_headers(),
                    timeout=60.0,
                )
                resp.raise_for_status()
                data = resp.json()

                if data.get("success"):
                    sub_data = data.get("data", {})
                    result.subdomains = sub_data.get("subdomains", [])
                    result.total_found = sub_data.get("total", len(result.subdomains))
                    result.sources = sub_data.get("sources", [])
                else:
                    result.error = data.get("error", "Unknown error")

            except httpx.HTTPStatusError as e:
                result.error = f"HTTP {e.response.status_code}: {e.response.text}"
            except Exception as e:
                result.error = str(e)

        return result

    def enumerate_subdomains(self, domain: str) -> SubdomainResult:
        """Synchronous subdomain enumeration."""
        return asyncio.run(self.enumerate_subdomains_async(domain))

    async def reverse_ip_async(self, ip: str) -> ReverseIPResult:
        """Get reverse IP lookup - domains hosted on an IP."""
        result = ReverseIPResult(ip=ip)

        async with httpx.AsyncClient() as client:
            try:
                resp = await client.get(
                    f"{self.base_url}/reverse-ip/{ip}",
                    headers=self._get_headers(),
                    timeout=30.0,
                )
                resp.raise_for_status()
                data = resp.json()

                if data.get("success"):
                    ip_data = data.get("data", {})
                    result.domains = ip_data.get("domains", [])
                    result.hostname = ip_data.get("hostname")
                    result.asn = ip_data.get("asn")
                    result.as_name = ip_data.get("as_name")
                else:
                    result.error = data.get("error", "Unknown error")

            except httpx.HTTPStatusError as e:
                result.error = f"HTTP {e.response.status_code}: {e.response.text}"
            except Exception as e:
                result.error = str(e)

        return result

    def reverse_ip(self, ip: str) -> ReverseIPResult:
        """Synchronous reverse IP lookup."""
        return asyncio.run(self.reverse_ip_async(ip))

    async def check_email_security_async(self, domain: str) -> dict[str, Any]:
        """Check email security configuration (SPF, DKIM, DMARC)."""
        async with httpx.AsyncClient() as client:
            try:
                resp = await client.get(
                    f"{self.base_url}/email-security/{domain}",
                    headers=self._get_headers(),
                    timeout=30.0,
                )
                resp.raise_for_status()
                data = resp.json()
                return data.get("data", {})
            except Exception:
                return {}

    def check_email_security(self, domain: str) -> dict[str, Any]:
        """Synchronous email security check."""
        return asyncio.run(self.check_email_security_async(domain))

    async def get_certificate_info_async(self, domain: str) -> dict[str, Any]:
        """Get SSL/TLS certificate information."""
        async with httpx.AsyncClient() as client:
            try:
                resp = await client.get(
                    f"{self.base_url}/ssl/{domain}",
                    headers=self._get_headers(),
                    timeout=30.0,
                )
                resp.raise_for_status()
                data = resp.json()
                return data.get("data", {})
            except Exception:
                return {}

    def get_certificate_info(self, domain: str) -> dict[str, Any]:
        """Synchronous certificate info lookup."""
        return asyncio.run(self.get_certificate_info_async(domain))

    async def search_domains_async(
        self,
        query: str,
        filters: dict[str, Any] | None = None,
        limit: int = 100,
    ) -> list[dict]:
        """Search domains in DNS Science database."""
        async with httpx.AsyncClient() as client:
            try:
                params = {"q": query, "limit": limit}
                if filters:
                    params.update(filters)

                resp = await client.get(
                    f"{self.base_url}/search",
                    headers=self._get_headers(),
                    params=params,
                    timeout=30.0,
                )
                resp.raise_for_status()
                data = resp.json()
                return data.get("data", {}).get("results", [])
            except Exception:
                return []

    def search_domains(
        self,
        query: str,
        filters: dict[str, Any] | None = None,
        limit: int = 100,
    ) -> list[dict]:
        """Synchronous domain search."""
        return asyncio.run(self.search_domains_async(query, filters, limit))
