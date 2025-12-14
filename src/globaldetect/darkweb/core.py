"""
Core dark web intelligence functionality.

Provides Tor exit node detection, dark web threat intelligence,
and proxy/anonymizer detection.

Copyright (c) 2025 DNS Science.io, an After Dark Systems, LLC company.
All rights reserved.
"""

import asyncio
from dataclasses import dataclass, field
from typing import Any

import httpx
import dns.resolver
from netaddr import IPAddress


# Tor exit node DNSBL services
TOR_DNSBLS = {
    "exitnodes.tor.dnsbl.sectoor.de": {
        "name": "Sectoor Tor",
        "description": "Tor exit node list",
    },
    "torexit.dan.me.uk": {
        "name": "Dan.me.uk Tor",
        "description": "Tor exit node detection",
    },
}

# Proxy/anonymizer DNSBL services
PROXY_DNSBLS = {
    "dnsbl.tornevall.org": {
        "name": "Tornevall",
        "description": "Proxy and Tor nodes",
    },
    "http.dnsbl.sorbs.net": {
        "name": "SORBS HTTP",
        "description": "Open HTTP proxies",
    },
    "socks.dnsbl.sorbs.net": {
        "name": "SORBS SOCKS",
        "description": "Open SOCKS proxies",
    },
    "misc.dnsbl.sorbs.net": {
        "name": "SORBS Misc",
        "description": "Misc proxy types",
    },
}

# Public APIs for Tor exit node checking
TOR_EXIT_APIS = {
    "dan.me.uk": "https://www.dan.me.uk/torlist/",
    "collector.torproject.org": "https://collector.torproject.org/recent/exit-lists/",
}


@dataclass
class TorExitResult:
    """Result from Tor exit node check."""
    ip: str
    is_tor_exit: bool = False
    exit_policy: str | None = None
    first_seen: str | None = None
    last_seen: str | None = None
    nickname: str | None = None
    fingerprint: str | None = None
    bandwidth: int | None = None
    sources: list[str] = field(default_factory=list)
    error: str | None = None


@dataclass
class DarkWebResult:
    """Result from dark web intelligence check."""
    target: str
    target_type: str = "unknown"  # ip, domain, onion
    is_tor_exit: bool = False
    is_tor_relay: bool = False
    is_proxy: bool = False
    is_vpn: bool = False
    has_onion_association: bool = False
    onion_addresses: list[str] = field(default_factory=list)
    threat_indicators: list[str] = field(default_factory=list)
    risk_score: int = 0  # 0-100
    sources: list[str] = field(default_factory=list)
    raw_data: dict[str, Any] = field(default_factory=dict)
    error: str | None = None


def _reverse_ip(ip: str) -> str:
    """Reverse an IP address for DNSBL lookup."""
    try:
        addr = IPAddress(ip)
        if addr.version == 4:
            return ".".join(reversed(ip.split(".")))
        else:
            expanded = addr.format(dialect=None)
            hex_str = expanded.replace(":", "")
            return ".".join(reversed(hex_str))
    except Exception:
        return ""


class TorExitChecker:
    """Check if an IP is a Tor exit node."""

    def __init__(self, timeout: float = 5.0):
        self.timeout = timeout
        self.resolver = dns.resolver.Resolver()
        self.resolver.timeout = timeout
        self.resolver.lifetime = timeout

    async def check_dnsbl_async(self, ip: str) -> TorExitResult:
        """Check IP against Tor exit DNSBLs."""
        result = TorExitResult(ip=ip)

        reversed_ip = _reverse_ip(ip)
        if not reversed_ip:
            result.error = "Invalid IP address"
            return result

        loop = asyncio.get_event_loop()

        for dnsbl, info in TOR_DNSBLS.items():
            query = f"{reversed_ip}.{dnsbl}"
            try:
                await loop.run_in_executor(
                    None,
                    lambda q=query: self.resolver.resolve(q, "A")
                )
                result.is_tor_exit = True
                result.sources.append(info["name"])
            except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
                pass
            except Exception:
                pass

        return result

    async def check_api_async(self, ip: str) -> TorExitResult:
        """Check IP against Tor Project APIs."""
        result = TorExitResult(ip=ip)

        async with httpx.AsyncClient() as client:
            # Check Tor Project's exit list
            try:
                resp = await client.get(
                    "https://check.torproject.org/torbulkexitlist",
                    timeout=self.timeout,
                )
                if resp.status_code == 200:
                    exit_ips = set(resp.text.strip().split("\n"))
                    if ip in exit_ips:
                        result.is_tor_exit = True
                        result.sources.append("Tor Project")
            except Exception:
                pass

            # Check OnionOO API for relay info
            try:
                resp = await client.get(
                    f"https://onionoo.torproject.org/details?search={ip}",
                    timeout=self.timeout,
                )
                if resp.status_code == 200:
                    data = resp.json()
                    relays = data.get("relays", [])
                    for relay in relays:
                        if ip in relay.get("or_addresses", []) or ip in relay.get("exit_addresses", []):
                            result.is_tor_exit = relay.get("exit_probability", 0) > 0
                            result.nickname = relay.get("nickname")
                            result.fingerprint = relay.get("fingerprint")
                            result.bandwidth = relay.get("bandwidth")
                            result.first_seen = relay.get("first_seen")
                            result.last_seen = relay.get("last_seen")
                            result.sources.append("OnionOO")
                            break
            except Exception:
                pass

        return result

    async def check_async(self, ip: str) -> TorExitResult:
        """Combined Tor exit check using DNSBL and APIs."""
        # Run both checks in parallel
        dnsbl_task = self.check_dnsbl_async(ip)
        api_task = self.check_api_async(ip)

        dnsbl_result, api_result = await asyncio.gather(dnsbl_task, api_task)

        # Merge results
        result = TorExitResult(ip=ip)
        result.is_tor_exit = dnsbl_result.is_tor_exit or api_result.is_tor_exit
        result.sources = list(set(dnsbl_result.sources + api_result.sources))
        result.nickname = api_result.nickname
        result.fingerprint = api_result.fingerprint
        result.bandwidth = api_result.bandwidth
        result.first_seen = api_result.first_seen
        result.last_seen = api_result.last_seen

        return result

    def check(self, ip: str) -> TorExitResult:
        """Synchronous Tor exit check."""
        return asyncio.run(self.check_async(ip))


class DarkWebChecker:
    """Comprehensive dark web intelligence checker."""

    def __init__(self, timeout: float = 10.0):
        self.timeout = timeout
        self.tor_checker = TorExitChecker(timeout=timeout)
        self.resolver = dns.resolver.Resolver()
        self.resolver.timeout = timeout

    async def check_proxy_dnsbl_async(self, ip: str) -> dict[str, bool]:
        """Check IP against proxy DNSBLs."""
        results = {}
        reversed_ip = _reverse_ip(ip)

        if not reversed_ip:
            return results

        loop = asyncio.get_event_loop()

        for dnsbl, info in PROXY_DNSBLS.items():
            query = f"{reversed_ip}.{dnsbl}"
            try:
                await loop.run_in_executor(
                    None,
                    lambda q=query: self.resolver.resolve(q, "A")
                )
                results[info["name"]] = True
            except Exception:
                results[info["name"]] = False

        return results

    async def check_ip_async(self, ip: str) -> DarkWebResult:
        """Check an IP address for dark web associations."""
        result = DarkWebResult(target=ip, target_type="ip")

        try:
            addr = IPAddress(ip)
            if addr.version not in (4, 6):
                result.error = "Invalid IP address"
                return result
        except:
            result.error = "Invalid IP address"
            return result

        # Check Tor exit status
        tor_result = await self.tor_checker.check_async(ip)
        result.is_tor_exit = tor_result.is_tor_exit
        result.sources.extend(tor_result.sources)

        if tor_result.is_tor_exit:
            result.threat_indicators.append("Tor exit node")
            result.risk_score += 30
            result.raw_data["tor"] = {
                "nickname": tor_result.nickname,
                "fingerprint": tor_result.fingerprint,
                "bandwidth": tor_result.bandwidth,
            }

        # Check proxy DNSBLs
        proxy_results = await self.check_proxy_dnsbl_async(ip)
        for source, is_listed in proxy_results.items():
            if is_listed:
                result.is_proxy = True
                result.sources.append(source)
                result.threat_indicators.append(f"Listed on {source}")
                result.risk_score += 15

        # Check against threat intel APIs (if available)
        await self._check_threat_intel_async(ip, result)

        # Cap risk score at 100
        result.risk_score = min(100, result.risk_score)

        return result

    async def check_domain_async(self, domain: str) -> DarkWebResult:
        """Check a domain for dark web associations."""
        result = DarkWebResult(target=domain, target_type="domain")

        # Check if it's an .onion domain
        if domain.endswith(".onion"):
            result.target_type = "onion"
            result.has_onion_association = True
            result.onion_addresses.append(domain)
            result.threat_indicators.append("Tor hidden service (.onion)")
            result.risk_score += 50

        # Resolve domain and check IPs
        try:
            loop = asyncio.get_event_loop()
            answers = await loop.run_in_executor(
                None,
                lambda: self.resolver.resolve(domain, "A")
            )

            for rdata in answers:
                ip = str(rdata)
                ip_result = await self.check_ip_async(ip)
                if ip_result.is_tor_exit:
                    result.is_tor_exit = True
                    result.threat_indicators.append(f"Resolves to Tor exit ({ip})")
                if ip_result.is_proxy:
                    result.is_proxy = True
                result.risk_score = max(result.risk_score, ip_result.risk_score)
                result.sources.extend(ip_result.sources)
        except Exception:
            pass

        # Check for known dark web associations via DNS Science API
        await self._check_domain_intel_async(domain, result)

        result.sources = list(set(result.sources))
        result.risk_score = min(100, result.risk_score)

        return result

    async def _check_threat_intel_async(self, ip: str, result: DarkWebResult) -> None:
        """Check IP against threat intelligence services."""
        # Check AbuseIPDB if available
        try:
            from globaldetect.services.abuseipdb import AbuseIPDBClient
            from globaldetect.config import get_config

            config = get_config()
            if config.abuseipdb_api_key:
                client = AbuseIPDBClient()
                abuse_result = await client.check_ip_async(ip)
                if not abuse_result.error:
                    if abuse_result.is_tor:
                        result.is_tor_exit = True
                        result.sources.append("AbuseIPDB")
                        if "Tor exit node" not in result.threat_indicators:
                            result.threat_indicators.append("Tor exit node (AbuseIPDB)")
                    if abuse_result.abuse_confidence_score > 50:
                        result.threat_indicators.append(
                            f"High abuse score ({abuse_result.abuse_confidence_score}%)"
                        )
                        result.risk_score += abuse_result.abuse_confidence_score // 5
        except ImportError:
            pass
        except Exception:
            pass

    async def _check_domain_intel_async(self, domain: str, result: DarkWebResult) -> None:
        """Check domain against threat intelligence services."""
        # Check DNS Science API if available
        try:
            from globaldetect.services.dnsscience import DNSScienceClient
            from globaldetect.config import get_config

            config = get_config()
            if config.dnsscience_api_key:
                client = DNSScienceClient()
                threat_result = await client.get_threat_intel_async(domain)
                if not threat_result.error:
                    if threat_result.is_malicious:
                        result.threat_indicators.append("Flagged as malicious (DNS Science)")
                        result.risk_score += 40
                    result.sources.append("DNS Science")
        except ImportError:
            pass
        except Exception:
            pass

    async def check_async(self, target: str) -> DarkWebResult:
        """Check any target (IP or domain) for dark web associations."""
        # Determine target type
        try:
            IPAddress(target)
            return await self.check_ip_async(target)
        except:
            return await self.check_domain_async(target)

    def check_ip(self, ip: str) -> DarkWebResult:
        """Synchronous IP check."""
        return asyncio.run(self.check_ip_async(ip))

    def check_domain(self, domain: str) -> DarkWebResult:
        """Synchronous domain check."""
        return asyncio.run(self.check_domain_async(domain))

    def check(self, target: str) -> DarkWebResult:
        """Synchronous check for any target."""
        return asyncio.run(self.check_async(target))


# Convenience functions
def check_tor_exit(ip: str) -> TorExitResult:
    """Check if an IP is a Tor exit node."""
    checker = TorExitChecker()
    return checker.check(ip)


def check_darkweb_intel(target: str) -> DarkWebResult:
    """Check any target for dark web associations."""
    checker = DarkWebChecker()
    return checker.check(target)
