"""
Core DNS functionality.
"""

import asyncio
from dataclasses import dataclass, field
from typing import Any

import dns.resolver
import dns.reversename
import dns.rdatatype
import dns.message
import dns.query
import dns.zone


# Well-known public DNS servers for propagation checking
PUBLIC_DNS_SERVERS = {
    "Google": ["8.8.8.8", "8.8.4.4"],
    "Cloudflare": ["1.1.1.1", "1.0.0.1"],
    "OpenDNS": ["208.67.222.222", "208.67.220.220"],
    "Quad9": ["9.9.9.9", "149.112.112.112"],
    "Level3": ["4.2.2.1", "4.2.2.2"],
}

# Flatten for easy iteration
ALL_PUBLIC_DNS = [ip for ips in PUBLIC_DNS_SERVERS.values() for ip in ips]


@dataclass
class DNSRecord:
    """A DNS record."""
    name: str
    record_type: str
    ttl: int
    value: str
    priority: int | None = None  # For MX records


@dataclass
class PropagationResult:
    """Result of a propagation check."""
    server: str
    server_name: str
    success: bool
    records: list[str] = field(default_factory=list)
    error: str | None = None
    response_time_ms: float = 0.0


class DNSResolver:
    """DNS resolver with enhanced functionality."""

    def __init__(self, nameservers: list[str] | None = None, timeout: float = 5.0):
        self.resolver = dns.resolver.Resolver()
        if nameservers:
            self.resolver.nameservers = nameservers
        self.resolver.timeout = timeout
        self.resolver.lifetime = timeout

    def lookup(self, name: str, record_type: str = "A") -> list[DNSRecord]:
        """Perform a DNS lookup."""
        records = []
        try:
            answers = self.resolver.resolve(name, record_type)
            for rdata in answers:
                record = DNSRecord(
                    name=name,
                    record_type=record_type,
                    ttl=answers.ttl,
                    value=str(rdata),
                )
                # Handle MX priority
                if record_type == "MX":
                    record.priority = rdata.preference
                    record.value = str(rdata.exchange)
                records.append(record)
        except dns.resolver.NXDOMAIN:
            pass  # Domain doesn't exist
        except dns.resolver.NoAnswer:
            pass  # No records of this type
        except dns.resolver.NoNameservers:
            pass  # No nameservers available
        except Exception:
            pass
        return records

    def lookup_all(self, name: str) -> dict[str, list[DNSRecord]]:
        """Lookup all common record types for a domain."""
        record_types = ["A", "AAAA", "MX", "NS", "TXT", "CNAME", "SOA", "CAA"]
        results = {}
        for rtype in record_types:
            records = self.lookup(name, rtype)
            if records:
                results[rtype] = records
        return results

    def reverse_lookup(self, ip: str) -> list[str]:
        """Perform a reverse DNS lookup."""
        try:
            rev_name = dns.reversename.from_address(ip)
            answers = self.resolver.resolve(rev_name, "PTR")
            return [str(rdata) for rdata in answers]
        except Exception:
            return []


def lookup(name: str, record_type: str = "A", nameserver: str | None = None) -> list[DNSRecord]:
    """Perform a DNS lookup."""
    resolver = DNSResolver(nameservers=[nameserver] if nameserver else None)
    return resolver.lookup(name, record_type)


def lookup_all(name: str, nameserver: str | None = None) -> dict[str, list[DNSRecord]]:
    """Lookup all common record types."""
    resolver = DNSResolver(nameservers=[nameserver] if nameserver else None)
    return resolver.lookup_all(name)


def reverse_lookup(ip: str, nameserver: str | None = None) -> list[str]:
    """Perform a reverse DNS lookup."""
    resolver = DNSResolver(nameservers=[nameserver] if nameserver else None)
    return resolver.reverse_lookup(ip)


def get_nameservers(domain: str) -> list[str]:
    """Get nameservers for a domain."""
    resolver = DNSResolver()
    records = resolver.lookup(domain, "NS")
    return [r.value for r in records]


def get_mx_records(domain: str) -> list[tuple[int, str]]:
    """Get MX records sorted by priority."""
    resolver = DNSResolver()
    records = resolver.lookup(domain, "MX")
    return sorted([(r.priority or 0, r.value) for r in records])


def get_txt_records(domain: str) -> list[str]:
    """Get TXT records for a domain."""
    resolver = DNSResolver()
    records = resolver.lookup(domain, "TXT")
    return [r.value for r in records]


async def _check_server(
    name: str,
    record_type: str,
    server: str,
    server_name: str,
) -> PropagationResult:
    """Check DNS propagation on a single server."""
    import time

    result = PropagationResult(server=server, server_name=server_name, success=False)

    try:
        resolver = dns.resolver.Resolver()
        resolver.nameservers = [server]
        resolver.timeout = 3.0
        resolver.lifetime = 3.0

        start = time.monotonic()

        # Run in executor since dns.resolver is blocking
        loop = asyncio.get_event_loop()
        answers = await loop.run_in_executor(
            None,
            lambda: resolver.resolve(name, record_type)
        )

        result.response_time_ms = (time.monotonic() - start) * 1000
        result.success = True
        result.records = [str(rdata) for rdata in answers]

    except dns.resolver.NXDOMAIN:
        result.error = "NXDOMAIN"
    except dns.resolver.NoAnswer:
        result.error = "No Answer"
    except dns.resolver.NoNameservers:
        result.error = "No Nameservers"
    except dns.exception.Timeout:
        result.error = "Timeout"
    except Exception as e:
        result.error = str(e)

    return result


async def check_propagation_async(
    name: str,
    record_type: str = "A",
    servers: dict[str, list[str]] | None = None,
) -> list[PropagationResult]:
    """Check DNS propagation across multiple servers."""
    if servers is None:
        servers = PUBLIC_DNS_SERVERS

    tasks = []
    for provider, ips in servers.items():
        for ip in ips:
            tasks.append(_check_server(name, record_type, ip, provider))

    return await asyncio.gather(*tasks)


def check_propagation(
    name: str,
    record_type: str = "A",
    servers: dict[str, list[str]] | None = None,
) -> list[PropagationResult]:
    """Synchronous wrapper for propagation check."""
    return asyncio.run(check_propagation_async(name, record_type, servers))


def trace_delegation(domain: str) -> list[dict]:
    """Trace DNS delegation from root to authoritative servers."""
    trace = []

    # Start with root servers
    root_servers = [
        "198.41.0.4",    # a.root-servers.net
        "199.9.14.201",  # b.root-servers.net
        "192.33.4.12",   # c.root-servers.net
    ]

    parts = domain.rstrip(".").split(".")
    current_servers = root_servers

    # Query each level
    for i in range(len(parts)):
        query_name = ".".join(parts[-(i + 1):]) + "."

        step = {
            "zone": query_name,
            "servers_queried": current_servers[:3],
            "ns_records": [],
            "glue_records": [],
        }

        # Query for NS records
        resolver = dns.resolver.Resolver()
        resolver.nameservers = current_servers[:3]
        resolver.timeout = 5.0

        try:
            answers = resolver.resolve(query_name, "NS")
            ns_records = [str(rdata) for rdata in answers]
            step["ns_records"] = ns_records

            # Try to get glue records
            for ns in ns_records[:3]:
                try:
                    a_records = resolver.resolve(ns, "A")
                    for a in a_records:
                        step["glue_records"].append({
                            "ns": ns,
                            "ip": str(a),
                        })
                except Exception:
                    pass

            # Update servers for next iteration
            if step["glue_records"]:
                current_servers = [g["ip"] for g in step["glue_records"]]

        except Exception as e:
            step["error"] = str(e)

        trace.append(step)

    return trace
