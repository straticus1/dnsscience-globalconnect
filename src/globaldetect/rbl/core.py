"""
Core RBL/Blacklist lookup functionality.

Comprehensive blacklist checking against 50+ RBL providers.
Full IPv4 and IPv6 support.

Copyright (c) 2025 DNS Science.io, an After Dark Systems, LLC company.
All rights reserved.
"""

import asyncio
import socket
from dataclasses import dataclass, field
from typing import Any
from netaddr import IPAddress

import dns.resolver
import dns.reversename


# Comprehensive list of RBL/DNSBL providers for IP addresses
RBL_PROVIDERS = {
    # Spamhaus - Most authoritative
    "zen.spamhaus.org": {
        "name": "Spamhaus ZEN",
        "description": "Combined SBL, XBL, PBL zones",
        "type": "spam",
        "ipv6": False,
    },
    "sbl.spamhaus.org": {
        "name": "Spamhaus SBL",
        "description": "Spamhaus Block List - verified spam sources",
        "type": "spam",
        "ipv6": False,
    },
    "xbl.spamhaus.org": {
        "name": "Spamhaus XBL",
        "description": "Exploits Block List - hijacked PCs",
        "type": "exploit",
        "ipv6": False,
    },
    "pbl.spamhaus.org": {
        "name": "Spamhaus PBL",
        "description": "Policy Block List - dynamic IPs",
        "type": "policy",
        "ipv6": False,
    },
    "sbl-xbl.spamhaus.org": {
        "name": "Spamhaus SBL-XBL",
        "description": "Combined SBL and XBL",
        "type": "spam",
        "ipv6": False,
    },

    # Barracuda
    "b.barracudacentral.org": {
        "name": "Barracuda",
        "description": "Barracuda Reputation Block List",
        "type": "spam",
        "ipv6": False,
    },

    # SpamCop
    "bl.spamcop.net": {
        "name": "SpamCop",
        "description": "SpamCop Blocking List",
        "type": "spam",
        "ipv6": False,
    },

    # SORBS
    "dnsbl.sorbs.net": {
        "name": "SORBS DNSBL",
        "description": "SORBS aggregate zone",
        "type": "spam",
        "ipv6": True,
    },
    "spam.dnsbl.sorbs.net": {
        "name": "SORBS Spam",
        "description": "SORBS spam sources",
        "type": "spam",
        "ipv6": True,
    },
    "recent.spam.dnsbl.sorbs.net": {
        "name": "SORBS Recent Spam",
        "description": "Recent spam (last 48 hours)",
        "type": "spam",
        "ipv6": True,
    },
    "web.dnsbl.sorbs.net": {
        "name": "SORBS Web",
        "description": "Web form spam sources",
        "type": "spam",
        "ipv6": True,
    },
    "dul.dnsbl.sorbs.net": {
        "name": "SORBS DUL",
        "description": "Dynamic User List",
        "type": "policy",
        "ipv6": True,
    },
    "zombie.dnsbl.sorbs.net": {
        "name": "SORBS Zombie",
        "description": "Hijacked networks",
        "type": "exploit",
        "ipv6": True,
    },

    # UCEProtect
    "dnsbl-1.uceprotect.net": {
        "name": "UCEProtect Level 1",
        "description": "Individual spam IPs",
        "type": "spam",
        "ipv6": False,
    },
    "dnsbl-2.uceprotect.net": {
        "name": "UCEProtect Level 2",
        "description": "Networks with spam issues",
        "type": "spam",
        "ipv6": False,
    },
    "dnsbl-3.uceprotect.net": {
        "name": "UCEProtect Level 3",
        "description": "ASNs with spam issues",
        "type": "spam",
        "ipv6": False,
    },

    # SpamRATS
    "dyna.spamrats.com": {
        "name": "SpamRATS Dyna",
        "description": "Dynamic/residential IPs",
        "type": "policy",
        "ipv6": False,
    },
    "noptr.spamrats.com": {
        "name": "SpamRATS NoPTR",
        "description": "IPs without reverse DNS",
        "type": "policy",
        "ipv6": False,
    },
    "spam.spamrats.com": {
        "name": "SpamRATS Spam",
        "description": "Known spam sources",
        "type": "spam",
        "ipv6": False,
    },

    # PSBL
    "psbl.surriel.com": {
        "name": "PSBL",
        "description": "Passive Spam Block List",
        "type": "spam",
        "ipv6": False,
    },

    # Mailspike
    "bl.mailspike.net": {
        "name": "Mailspike BL",
        "description": "Mailspike Blacklist",
        "type": "spam",
        "ipv6": True,
    },
    "z.mailspike.net": {
        "name": "Mailspike Z",
        "description": "Mailspike Zero-hour",
        "type": "spam",
        "ipv6": True,
    },

    # Abuseat / CBL
    "cbl.abuseat.org": {
        "name": "CBL",
        "description": "Composite Blocking List",
        "type": "exploit",
        "ipv6": False,
    },

    # DRONEBL
    "dnsbl.dronebl.org": {
        "name": "DroneBL",
        "description": "Drone/bot infected IPs",
        "type": "exploit",
        "ipv6": True,
    },

    # Invaluement
    "ivmSIP.dnsbl.invaluement.com": {
        "name": "Invaluement SIP",
        "description": "Spam IP addresses",
        "type": "spam",
        "ipv6": False,
    },

    # WPBL
    "db.wpbl.info": {
        "name": "WPBL",
        "description": "Weighted Private Block List",
        "type": "spam",
        "ipv6": False,
    },

    # JustSpam
    "dnsbl.justspam.org": {
        "name": "JustSpam",
        "description": "Spam sources",
        "type": "spam",
        "ipv6": False,
    },

    # Lashback
    "ubl.lashback.com": {
        "name": "Lashback UBL",
        "description": "Unsubscribe violators",
        "type": "spam",
        "ipv6": False,
    },

    # Truncate
    "truncate.gbudb.net": {
        "name": "Truncate",
        "description": "GBUdb Truncate list",
        "type": "spam",
        "ipv6": False,
    },

    # BACKSCATTERER
    "ips.backscatterer.org": {
        "name": "Backscatterer",
        "description": "Backscatter spam sources",
        "type": "spam",
        "ipv6": False,
    },

    # Proofpoint / Cloudmark (via DNS)
    "dnsbl.proofpoint.com": {
        "name": "Proofpoint",
        "description": "Proofpoint dynamic reputation",
        "type": "spam",
        "ipv6": False,
    },

    # SECTOOR
    "exitnodes.tor.dnsbl.sectoor.de": {
        "name": "Sectoor Tor",
        "description": "Tor exit nodes",
        "type": "proxy",
        "ipv6": False,
    },

    # TORNEVALL
    "dnsbl.tornevall.org": {
        "name": "Tornevall",
        "description": "Proxy/TOR list",
        "type": "proxy",
        "ipv6": False,
    },

    # NiX Spam
    "ix.dnsbl.manitu.net": {
        "name": "NiX Spam",
        "description": "German spam list",
        "type": "spam",
        "ipv6": True,
    },

    # Suomispam
    "bl.suomispam.net": {
        "name": "Suomispam",
        "description": "Finnish spam list",
        "type": "spam",
        "ipv6": False,
    },

    # 0spam
    "bl.0spam.org": {
        "name": "0spam",
        "description": "Zero Spam Project",
        "type": "spam",
        "ipv6": False,
    },

    # Access
    "access.redhawk.org": {
        "name": "Access Redhawk",
        "description": "Redhawk access list",
        "type": "spam",
        "ipv6": False,
    },

    # INTERSERVER
    "rbl.interserver.net": {
        "name": "InterServer",
        "description": "InterServer RBL",
        "type": "spam",
        "ipv6": False,
    },

    # Spamhaus DROP
    "drop.spamhaus.org": {
        "name": "Spamhaus DROP",
        "description": "Don't Route Or Peer list",
        "type": "hijacked",
        "ipv6": False,
    },
    "edrop.spamhaus.org": {
        "name": "Spamhaus EDROP",
        "description": "Extended DROP list",
        "type": "hijacked",
        "ipv6": False,
    },

    # Cisco/IronPort SenderBase (via query)
    "rf.senderbase.org": {
        "name": "SenderBase RF",
        "description": "Cisco/IronPort reputation",
        "type": "reputation",
        "ipv6": False,
    },

    # Cymru Bogons
    "bogons.cymru.com": {
        "name": "Cymru Bogons",
        "description": "Team Cymru bogon list",
        "type": "bogon",
        "ipv6": True,
    },

    # SURBL (for IPs in URLs)
    "multi.surbl.org": {
        "name": "SURBL Multi",
        "description": "URI blacklist",
        "type": "uri",
        "ipv6": False,
    },
}

# Domain-based blacklists (DBL)
DNSBL_PROVIDERS = {
    "dbl.spamhaus.org": {
        "name": "Spamhaus DBL",
        "description": "Domain Block List",
        "type": "domain",
    },
    "multi.surbl.org": {
        "name": "SURBL",
        "description": "Spam URI Realtime Blocklist",
        "type": "uri",
    },
    "uribl.spameatingmonkey.net": {
        "name": "SpamEatingMonkey URI",
        "description": "URI blacklist",
        "type": "uri",
    },
    "fresh.spameatingmonkey.net": {
        "name": "SpamEatingMonkey Fresh",
        "description": "Freshly registered domains",
        "type": "fresh",
    },
    "dbl.tiopan.com": {
        "name": "Tiopan DBL",
        "description": "Domain blocklist",
        "type": "domain",
    },
    "dbl.suomispam.net": {
        "name": "Suomispam DBL",
        "description": "Finnish domain list",
        "type": "domain",
    },
    "multi.uribl.com": {
        "name": "URIBL Multi",
        "description": "URI blacklist",
        "type": "uri",
    },
    "black.uribl.com": {
        "name": "URIBL Black",
        "description": "URI blacklist (black zone)",
        "type": "uri",
    },
    "grey.uribl.com": {
        "name": "URIBL Grey",
        "description": "URI blacklist (grey zone)",
        "type": "uri",
    },
    "red.uribl.com": {
        "name": "URIBL Red",
        "description": "URI blacklist (red zone)",
        "type": "uri",
    },
}


@dataclass
class RBLResult:
    """Result from an RBL lookup."""
    target: str
    rbl: str
    rbl_name: str
    listed: bool = False
    return_code: str | None = None
    txt_record: str | None = None
    rbl_type: str | None = None
    response_time_ms: float = 0.0
    error: str | None = None


@dataclass
class RBLSummary:
    """Summary of RBL check results."""
    target: str
    total_checked: int = 0
    total_listed: int = 0
    listings: list[RBLResult] = field(default_factory=list)
    clean: list[str] = field(default_factory=list)
    errors: list[RBLResult] = field(default_factory=list)
    is_ipv6: bool = False


def _reverse_ip(ip: str) -> str:
    """Reverse an IP address for DNSBL lookup."""
    try:
        addr = IPAddress(ip)
        if addr.version == 4:
            # Reverse IPv4: 1.2.3.4 -> 4.3.2.1
            return ".".join(reversed(ip.split(".")))
        else:
            # Reverse IPv6: expand and reverse each nibble
            expanded = addr.format(dialect=None)
            # Remove colons and reverse
            hex_str = expanded.replace(":", "")
            return ".".join(reversed(hex_str))
    except Exception:
        return ""


class RBLChecker:
    """Check IP addresses against RBL providers."""

    def __init__(
        self,
        timeout: float = 3.0,
        providers: dict[str, dict] | None = None,
        include_ipv6_only: bool = False,
    ):
        self.timeout = timeout
        self.providers = providers or RBL_PROVIDERS
        self.include_ipv6_only = include_ipv6_only
        self.resolver = dns.resolver.Resolver()
        self.resolver.timeout = timeout
        self.resolver.lifetime = timeout

    async def check_single_async(self, ip: str, rbl: str) -> RBLResult:
        """Check a single IP against a single RBL."""
        import time

        provider = self.providers.get(rbl, {})
        result = RBLResult(
            target=ip,
            rbl=rbl,
            rbl_name=provider.get("name", rbl),
            rbl_type=provider.get("type"),
        )

        # Check IPv6 support
        try:
            addr = IPAddress(ip)
            is_ipv6 = addr.version == 6
        except:
            result.error = "Invalid IP address"
            return result

        if is_ipv6 and not provider.get("ipv6", False):
            result.error = "RBL does not support IPv6"
            return result

        reversed_ip = _reverse_ip(ip)
        if not reversed_ip:
            result.error = "Failed to reverse IP"
            return result

        query = f"{reversed_ip}.{rbl}"

        start = time.monotonic()
        try:
            loop = asyncio.get_event_loop()
            answers = await loop.run_in_executor(
                None,
                lambda: self.resolver.resolve(query, "A")
            )

            result.response_time_ms = (time.monotonic() - start) * 1000
            result.listed = True

            # Get return code
            for rdata in answers:
                result.return_code = str(rdata)
                break

            # Try to get TXT record for details
            try:
                txt_answers = await loop.run_in_executor(
                    None,
                    lambda: self.resolver.resolve(query, "TXT")
                )
                for rdata in txt_answers:
                    result.txt_record = str(rdata).strip('"')
                    break
            except:
                pass

        except dns.resolver.NXDOMAIN:
            result.response_time_ms = (time.monotonic() - start) * 1000
            result.listed = False
        except dns.resolver.NoAnswer:
            result.response_time_ms = (time.monotonic() - start) * 1000
            result.listed = False
        except dns.resolver.NoNameservers:
            result.error = "No nameservers"
        except dns.exception.Timeout:
            result.error = "Timeout"
        except Exception as e:
            result.error = str(e)

        return result

    async def check_all_async(self, ip: str, providers: list[str] | None = None) -> RBLSummary:
        """Check IP against all (or specified) RBL providers."""
        if providers is None:
            providers = list(self.providers.keys())

        # Filter by IPv6 support if needed
        try:
            addr = IPAddress(ip)
            is_ipv6 = addr.version == 6
        except:
            return RBLSummary(target=ip)

        if is_ipv6:
            providers = [p for p in providers if self.providers.get(p, {}).get("ipv6", False)]

        summary = RBLSummary(target=ip, is_ipv6=is_ipv6)

        tasks = [self.check_single_async(ip, rbl) for rbl in providers]
        results = await asyncio.gather(*tasks)

        for result in results:
            summary.total_checked += 1
            if result.error:
                summary.errors.append(result)
            elif result.listed:
                summary.total_listed += 1
                summary.listings.append(result)
            else:
                summary.clean.append(result.rbl)

        return summary

    def check_single(self, ip: str, rbl: str) -> RBLResult:
        """Synchronous single check."""
        return asyncio.run(self.check_single_async(ip, rbl))

    def check_all(self, ip: str, providers: list[str] | None = None) -> RBLSummary:
        """Synchronous check against all providers."""
        return asyncio.run(self.check_all_async(ip, providers))


class DomainBlacklistChecker:
    """Check domains against domain blacklists."""

    def __init__(self, timeout: float = 3.0, providers: dict[str, dict] | None = None):
        self.timeout = timeout
        self.providers = providers or DNSBL_PROVIDERS
        self.resolver = dns.resolver.Resolver()
        self.resolver.timeout = timeout
        self.resolver.lifetime = timeout

    async def check_single_async(self, domain: str, dnsbl: str) -> RBLResult:
        """Check a domain against a single DNSBL."""
        import time

        provider = self.providers.get(dnsbl, {})
        result = RBLResult(
            target=domain,
            rbl=dnsbl,
            rbl_name=provider.get("name", dnsbl),
            rbl_type=provider.get("type"),
        )

        query = f"{domain}.{dnsbl}"

        start = time.monotonic()
        try:
            loop = asyncio.get_event_loop()
            answers = await loop.run_in_executor(
                None,
                lambda: self.resolver.resolve(query, "A")
            )

            result.response_time_ms = (time.monotonic() - start) * 1000
            result.listed = True

            for rdata in answers:
                result.return_code = str(rdata)
                break

            # Get TXT record
            try:
                txt_answers = await loop.run_in_executor(
                    None,
                    lambda: self.resolver.resolve(query, "TXT")
                )
                for rdata in txt_answers:
                    result.txt_record = str(rdata).strip('"')
                    break
            except:
                pass

        except dns.resolver.NXDOMAIN:
            result.response_time_ms = (time.monotonic() - start) * 1000
            result.listed = False
        except dns.resolver.NoAnswer:
            result.response_time_ms = (time.monotonic() - start) * 1000
            result.listed = False
        except dns.exception.Timeout:
            result.error = "Timeout"
        except Exception as e:
            result.error = str(e)

        return result

    async def check_all_async(self, domain: str) -> RBLSummary:
        """Check domain against all DNSBL providers."""
        summary = RBLSummary(target=domain)

        tasks = [self.check_single_async(domain, dnsbl) for dnsbl in self.providers]
        results = await asyncio.gather(*tasks)

        for result in results:
            summary.total_checked += 1
            if result.error:
                summary.errors.append(result)
            elif result.listed:
                summary.total_listed += 1
                summary.listings.append(result)
            else:
                summary.clean.append(result.rbl)

        return summary

    def check_single(self, domain: str, dnsbl: str) -> RBLResult:
        """Synchronous single check."""
        return asyncio.run(self.check_single_async(domain, dnsbl))

    def check_all(self, domain: str) -> RBLSummary:
        """Synchronous check against all providers."""
        return asyncio.run(self.check_all_async(domain))


# Convenience functions
def check_ip(ip: str, rbl: str) -> RBLResult:
    """Check an IP against a single RBL."""
    checker = RBLChecker()
    return checker.check_single(ip, rbl)


def check_ip_all(ip: str) -> RBLSummary:
    """Check an IP against all RBLs."""
    checker = RBLChecker()
    return checker.check_all(ip)


def check_domain(domain: str) -> RBLSummary:
    """Check a domain against all DNSBLs."""
    checker = DomainBlacklistChecker()
    return checker.check_all(domain)


def get_rbl_list(ipv6_only: bool = False) -> dict[str, dict]:
    """Get list of available RBL providers."""
    if ipv6_only:
        return {k: v for k, v in RBL_PROVIDERS.items() if v.get("ipv6", False)}
    return RBL_PROVIDERS
