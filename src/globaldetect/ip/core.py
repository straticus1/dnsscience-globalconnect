"""
Core IP/CIDR functionality.
"""

from dataclasses import dataclass
from typing import Iterator
from netaddr import IPNetwork, IPAddress, IPSet, cidr_merge


# RFC 5735 / RFC 6890 - Special-Purpose IP Address Registries
BOGON_RANGES_V4 = [
    "0.0.0.0/8",           # "This" network
    "10.0.0.0/8",          # Private-Use
    "100.64.0.0/10",       # Shared Address Space (CGN)
    "127.0.0.0/8",         # Loopback
    "169.254.0.0/16",      # Link-Local
    "172.16.0.0/12",       # Private-Use
    "192.0.0.0/24",        # IETF Protocol Assignments
    "192.0.2.0/24",        # Documentation (TEST-NET-1)
    "192.168.0.0/16",      # Private-Use
    "198.18.0.0/15",       # Benchmarking
    "198.51.100.0/24",     # Documentation (TEST-NET-2)
    "203.0.113.0/24",      # Documentation (TEST-NET-3)
    "224.0.0.0/4",         # Multicast
    "240.0.0.0/4",         # Reserved for Future Use
    "255.255.255.255/32",  # Limited Broadcast
]

BOGON_RANGES_V6 = [
    "::/128",              # Unspecified
    "::1/128",             # Loopback
    "::ffff:0:0/96",       # IPv4-mapped
    "64:ff9b::/96",        # IPv4/IPv6 Translation
    "100::/64",            # Discard-Only
    "2001::/32",           # TEREDO
    "2001:2::/48",         # Benchmarking
    "2001:db8::/32",       # Documentation
    "2001:10::/28",        # ORCHID
    "2002::/16",           # 6to4
    "fc00::/7",            # Unique-Local
    "fe80::/10",           # Link-Local
    "ff00::/8",            # Multicast
]

PRIVATE_RANGES_V4 = [
    "10.0.0.0/8",
    "172.16.0.0/12",
    "192.168.0.0/16",
]

PRIVATE_RANGES_V6 = [
    "fc00::/7",  # Unique Local Addresses
]


@dataclass
class IPInfo:
    """Information about an IP address or network."""
    address: str
    version: int
    is_private: bool
    is_loopback: bool
    is_multicast: bool
    is_link_local: bool
    is_reserved: bool
    is_bogon: bool
    reverse_dns: str
    network: str | None = None
    broadcast: str | None = None
    netmask: str | None = None
    hostmask: str | None = None
    num_addresses: int | None = None
    first_host: str | None = None
    last_host: str | None = None
    prefix_length: int | None = None


@dataclass
class SubnetInfo:
    """Information about a subnet."""
    network: str
    broadcast: str
    netmask: str
    hostmask: str
    prefix_length: int
    num_addresses: int
    num_hosts: int
    first_host: str | None
    last_host: str | None
    version: int


class SubnetCalculator:
    """Calculator for subnet operations."""

    @staticmethod
    def calculate(cidr: str) -> SubnetInfo:
        """Calculate subnet information from CIDR notation."""
        net = IPNetwork(cidr)

        # For /31 and /32 (v4) or /127 and /128 (v6), there are no "hosts"
        if net.version == 4:
            if net.prefixlen >= 31:
                first_host = None
                last_host = None
                num_hosts = 0 if net.prefixlen == 32 else 2
            else:
                first_host = str(net.network + 1)
                last_host = str(net.broadcast - 1)
                num_hosts = net.size - 2
        else:
            if net.prefixlen >= 127:
                first_host = None
                last_host = None
                num_hosts = 0 if net.prefixlen == 128 else 2
            else:
                first_host = str(net.network + 1)
                last_host = str(net.broadcast - 1)
                num_hosts = net.size - 2

        return SubnetInfo(
            network=str(net.network),
            broadcast=str(net.broadcast),
            netmask=str(net.netmask),
            hostmask=str(net.hostmask),
            prefix_length=net.prefixlen,
            num_addresses=net.size,
            num_hosts=num_hosts,
            first_host=first_host,
            last_host=last_host,
            version=net.version,
        )

    @staticmethod
    def split(cidr: str, new_prefix: int) -> list[str]:
        """Split a CIDR into smaller subnets."""
        net = IPNetwork(cidr)
        if new_prefix <= net.prefixlen:
            raise ValueError(f"New prefix /{new_prefix} must be larger than current /{net.prefixlen}")
        return [str(subnet) for subnet in net.subnet(new_prefix)]

    @staticmethod
    def supernet(cidr: str, new_prefix: int) -> str:
        """Get the supernet for a given CIDR."""
        net = IPNetwork(cidr)
        if new_prefix >= net.prefixlen:
            raise ValueError(f"New prefix /{new_prefix} must be smaller than current /{net.prefixlen}")
        return str(net.supernet(new_prefix)[0])


class CIDROperations:
    """Operations on CIDR blocks."""

    @staticmethod
    def summarize(cidrs: list[str]) -> list[str]:
        """Summarize/aggregate a list of CIDRs into the minimum set."""
        networks = [IPNetwork(cidr) for cidr in cidrs]
        merged = cidr_merge(networks)
        return [str(net) for net in merged]

    @staticmethod
    def contains(cidr: str, address: str) -> bool:
        """Check if a CIDR contains an IP address or subnet."""
        net = IPNetwork(cidr)
        try:
            target = IPNetwork(address)
            return target in net or target.network in net
        except:
            target = IPAddress(address)
            return target in net

    @staticmethod
    def overlap(cidr1: str, cidr2: str) -> bool:
        """Check if two CIDRs overlap."""
        net1 = IPNetwork(cidr1)
        net2 = IPNetwork(cidr2)
        set1 = IPSet([net1])
        set2 = IPSet([net2])
        return bool(set1 & set2)

    @staticmethod
    def difference(cidr1: str, cidr2: str) -> list[str]:
        """Subtract cidr2 from cidr1, returning remaining ranges."""
        set1 = IPSet([IPNetwork(cidr1)])
        set2 = IPSet([IPNetwork(cidr2)])
        result = set1 - set2
        return [str(cidr) for cidr in result.iter_cidrs()]

    @staticmethod
    def intersection(cidrs: list[str]) -> list[str]:
        """Find the intersection of multiple CIDRs."""
        if not cidrs:
            return []
        result = IPSet([IPNetwork(cidrs[0])])
        for cidr in cidrs[1:]:
            result &= IPSet([IPNetwork(cidr)])
        return [str(c) for c in result.iter_cidrs()]


def is_private(address: str) -> bool:
    """Check if an IP address is in private/RFC1918 space."""
    try:
        ip = IPAddress(address)
    except:
        ip = IPNetwork(address).ip

    ranges = PRIVATE_RANGES_V4 if ip.version == 4 else PRIVATE_RANGES_V6
    for r in ranges:
        if ip in IPNetwork(r):
            return True
    return False


def is_bogon(address: str) -> bool:
    """Check if an IP address is a bogon (should not appear on public internet)."""
    try:
        ip = IPAddress(address)
    except:
        ip = IPNetwork(address).ip

    ranges = BOGON_RANGES_V4 if ip.version == 4 else BOGON_RANGES_V6
    for r in ranges:
        if ip in IPNetwork(r):
            return True
    return False


def get_ip_info(address: str) -> IPInfo:
    """Get detailed information about an IP address or CIDR."""
    try:
        # Try as network first
        net = IPNetwork(address)
        ip = net.ip
        is_network = "/" in address
    except:
        ip = IPAddress(address)
        net = None
        is_network = False

    info = IPInfo(
        address=str(ip),
        version=ip.version,
        is_private=is_private(str(ip)),
        is_loopback=ip.is_loopback(),
        is_multicast=ip.is_multicast(),
        is_link_local=ip.is_link_local(),
        is_reserved=ip.is_reserved(),
        is_bogon=is_bogon(str(ip)),
        reverse_dns=ip.reverse_dns,
    )

    if is_network and net:
        info.network = str(net.network)
        info.broadcast = str(net.broadcast)
        info.netmask = str(net.netmask)
        info.hostmask = str(net.hostmask)
        info.num_addresses = net.size
        info.prefix_length = net.prefixlen
        if net.size > 2:
            info.first_host = str(net.network + 1)
            info.last_host = str(net.broadcast - 1)

    return info


def calculate_subnet(cidr: str) -> SubnetInfo:
    """Calculate subnet information from CIDR notation."""
    return SubnetCalculator.calculate(cidr)


def summarize_cidrs(cidrs: list[str]) -> list[str]:
    """Summarize/aggregate a list of CIDRs."""
    return CIDROperations.summarize(cidrs)


def split_cidr(cidr: str, new_prefix: int) -> list[str]:
    """Split a CIDR into smaller subnets."""
    return SubnetCalculator.split(cidr, new_prefix)
