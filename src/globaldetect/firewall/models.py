"""
Firewall data models.

Copyright (c) 2025 DNS Science.io, an After Dark Systems, LLC company.
All rights reserved.
"""

from dataclasses import dataclass, field
from enum import Enum
from typing import Any


class RuleAction(str, Enum):
    """Firewall rule actions."""

    ACCEPT = "accept"
    DROP = "drop"
    REJECT = "reject"
    LOG = "log"
    RETURN = "return"
    JUMP = "jump"
    QUEUE = "queue"
    MASQUERADE = "masquerade"
    SNAT = "snat"
    DNAT = "dnat"
    REDIRECT = "redirect"
    MARK = "mark"
    COUNT = "count"
    SKIP = "skip"
    AUTH = "auth"
    BLOCK = "block"
    PASS = "pass"


class Protocol(str, Enum):
    """Network protocols."""

    ANY = "any"
    TCP = "tcp"
    UDP = "udp"
    ICMP = "icmp"
    ICMPV6 = "icmpv6"
    GRE = "gre"
    ESP = "esp"
    AH = "ah"
    SCTP = "sctp"
    IPIP = "ipip"
    ALL = "all"


class FirewallVendor(str, Enum):
    """Firewall vendor/type."""

    IPTABLES = "iptables"
    NFTABLES = "nftables"
    IPFILTER = "ipfilter"
    PF = "pf"
    CHECKPOINT = "checkpoint"
    PALO_ALTO = "palo_alto"
    FORTINET = "fortinet"
    CISCO_ASA = "cisco_asa"
    JUNIPER_SRX = "juniper_srx"


@dataclass
class PortSpec:
    """Port specification."""

    port: int | None = None
    port_range: tuple[int, int] | None = None
    multiport: list[int] | None = None

    def __str__(self) -> str:
        if self.port is not None:
            return str(self.port)
        if self.port_range:
            return f"{self.port_range[0]}:{self.port_range[1]}"
        if self.multiport:
            return ",".join(str(p) for p in self.multiport)
        return "any"


@dataclass
class AddressSpec:
    """Address specification."""

    address: str | None = None  # Single IP or CIDR
    address_range: tuple[str, str] | None = None
    negated: bool = False

    def __str__(self) -> str:
        prefix = "!" if self.negated else ""
        if self.address:
            return f"{prefix}{self.address}"
        if self.address_range:
            return f"{prefix}{self.address_range[0]}-{self.address_range[1]}"
        return "any"


@dataclass
class FirewallRule:
    """Individual firewall rule."""

    rule_number: int | None = None
    action: RuleAction = RuleAction.ACCEPT
    protocol: Protocol = Protocol.ANY

    # Source specification
    source: AddressSpec | None = None
    source_port: PortSpec | None = None

    # Destination specification
    destination: AddressSpec | None = None
    destination_port: PortSpec | None = None

    # Interface matching
    in_interface: str | None = None
    out_interface: str | None = None

    # State/connection tracking
    state: list[str] | None = None  # NEW, ESTABLISHED, RELATED, etc.
    ctstate: list[str] | None = None

    # Additional matches
    icmp_type: str | None = None
    tcp_flags: dict[str, list[str]] | None = None  # mask -> flags
    mac_source: str | None = None

    # Target options
    target_chain: str | None = None  # For JUMP
    reject_with: str | None = None
    log_prefix: str | None = None
    log_level: str | None = None
    nat_to: str | None = None  # For SNAT/DNAT
    nat_port: int | None = None
    mark_value: int | None = None

    # Counters
    packets: int = 0
    bytes: int = 0

    # Metadata
    comment: str | None = None
    enabled: bool = True
    raw_rule: str | None = None

    # Extended attributes (vendor-specific)
    attributes: dict[str, Any] = field(default_factory=dict)

    def matches_any_source(self) -> bool:
        """Check if rule matches any source."""
        return self.source is None or (
            self.source.address is None and self.source.address_range is None
        )

    def matches_any_destination(self) -> bool:
        """Check if rule matches any destination."""
        return self.destination is None or (
            self.destination.address is None and self.destination.address_range is None
        )

    def is_permissive(self) -> bool:
        """Check if rule is overly permissive (any/any)."""
        return (
            self.action in (RuleAction.ACCEPT, RuleAction.PASS)
            and self.matches_any_source()
            and self.matches_any_destination()
            and self.protocol == Protocol.ANY
        )


@dataclass
class FirewallChain:
    """Firewall chain (iptables) or ruleset."""

    name: str
    policy: RuleAction | None = None
    rules: list[FirewallRule] = field(default_factory=list)
    packets: int = 0
    bytes: int = 0

    # Chain type (for nftables)
    chain_type: str | None = None  # filter, nat, route
    hook: str | None = None  # input, output, forward, prerouting, postrouting
    priority: int | None = None

    def rule_count(self) -> int:
        """Get number of rules in chain."""
        return len(self.rules)

    def enabled_rules(self) -> list[FirewallRule]:
        """Get only enabled rules."""
        return [r for r in self.rules if r.enabled]


@dataclass
class FirewallTable:
    """Firewall table (iptables tables: filter, nat, mangle, raw, security)."""

    name: str
    chains: dict[str, FirewallChain] = field(default_factory=dict)

    def get_chain(self, name: str) -> FirewallChain | None:
        """Get chain by name."""
        return self.chains.get(name)

    def all_rules(self) -> list[FirewallRule]:
        """Get all rules from all chains."""
        rules = []
        for chain in self.chains.values():
            rules.extend(chain.rules)
        return rules


@dataclass
class FirewallPolicy:
    """Complete firewall policy/ruleset."""

    vendor: FirewallVendor
    name: str | None = None
    tables: dict[str, FirewallTable] = field(default_factory=dict)
    generated_at: str | None = None
    hostname: str | None = None
    version: str | None = None

    # Global settings
    default_action: RuleAction | None = None
    ipv6_enabled: bool = False

    # Raw content
    raw_content: str | None = None

    # Metadata
    metadata: dict[str, Any] = field(default_factory=dict)

    def get_table(self, name: str) -> FirewallTable | None:
        """Get table by name."""
        return self.tables.get(name)

    def all_chains(self) -> list[FirewallChain]:
        """Get all chains from all tables."""
        chains = []
        for table in self.tables.values():
            chains.extend(table.chains.values())
        return chains

    def all_rules(self) -> list[FirewallRule]:
        """Get all rules from all tables and chains."""
        rules = []
        for table in self.tables.values():
            rules.extend(table.all_rules())
        return rules

    def rule_count(self) -> int:
        """Get total rule count."""
        return len(self.all_rules())

    def find_permissive_rules(self) -> list[FirewallRule]:
        """Find overly permissive rules."""
        return [r for r in self.all_rules() if r.is_permissive()]

    def find_rules_by_port(self, port: int, protocol: Protocol = Protocol.TCP) -> list[FirewallRule]:
        """Find rules matching a specific port."""
        matching = []
        for rule in self.all_rules():
            if rule.protocol != protocol and rule.protocol != Protocol.ANY:
                continue

            # Check destination port
            if rule.destination_port:
                if rule.destination_port.port == port:
                    matching.append(rule)
                elif rule.destination_port.port_range:
                    low, high = rule.destination_port.port_range
                    if low <= port <= high:
                        matching.append(rule)
                elif rule.destination_port.multiport and port in rule.destination_port.multiport:
                    matching.append(rule)

        return matching

    def find_rules_by_address(self, address: str) -> list[FirewallRule]:
        """Find rules matching a specific address."""
        import ipaddress

        try:
            target = ipaddress.ip_address(address)
        except ValueError:
            try:
                target = ipaddress.ip_network(address, strict=False)
            except ValueError:
                return []

        matching = []
        for rule in self.all_rules():
            # Check source
            if rule.source and rule.source.address:
                try:
                    network = ipaddress.ip_network(rule.source.address, strict=False)
                    if isinstance(target, (ipaddress.IPv4Address, ipaddress.IPv6Address)):
                        if target in network:
                            matching.append(rule)
                    else:
                        if network.overlaps(target):
                            matching.append(rule)
                except ValueError:
                    pass

            # Check destination
            if rule.destination and rule.destination.address:
                try:
                    network = ipaddress.ip_network(rule.destination.address, strict=False)
                    if isinstance(target, (ipaddress.IPv4Address, ipaddress.IPv6Address)):
                        if target in network:
                            matching.append(rule)
                    else:
                        if network.overlaps(target):
                            matching.append(rule)
                except ValueError:
                    pass

        return matching


@dataclass
class CheckpointObject:
    """Checkpoint network object."""

    uid: str
    name: str
    object_type: str  # host, network, group, service, etc.
    ipv4_address: str | None = None
    ipv6_address: str | None = None
    subnet4: str | None = None
    mask_length4: int | None = None
    subnet6: str | None = None
    mask_length6: int | None = None
    port: int | None = None
    protocol: str | None = None
    members: list[str] | None = None  # For groups
    comments: str | None = None
    color: str | None = None
    tags: list[str] | None = None


@dataclass
class CheckpointRule:
    """Checkpoint firewall rule with full object references."""

    uid: str
    rule_number: int
    name: str | None = None
    enabled: bool = True

    # Source/destination as object references
    source: list[str] = field(default_factory=list)  # Object names/UIDs
    source_negate: bool = False
    destination: list[str] = field(default_factory=list)
    destination_negate: bool = False

    # Services
    service: list[str] = field(default_factory=list)
    service_negate: bool = False

    # Action
    action: str = "Drop"
    action_settings: dict[str, Any] = field(default_factory=dict)

    # Track/logging
    track: str | None = None  # None, Log, Alert, etc.

    # Time restrictions
    time: list[str] | None = None

    # Install targets
    install_on: list[str] = field(default_factory=list)

    # VPN
    vpn: str | None = None

    # Comments and metadata
    comments: str | None = None
    custom_fields: dict[str, Any] = field(default_factory=dict)


@dataclass
class CheckpointPolicy:
    """Checkpoint security policy."""

    name: str
    uid: str
    package_name: str | None = None

    # Objects database
    objects: dict[str, CheckpointObject] = field(default_factory=dict)

    # Rulebase
    rules: list[CheckpointRule] = field(default_factory=list)

    # Access layers
    layers: list[str] = field(default_factory=list)

    # Policy metadata
    domain: str | None = None
    last_modified: str | None = None
    last_modifier: str | None = None

    def resolve_object(self, name_or_uid: str) -> CheckpointObject | None:
        """Resolve object by name or UID."""
        # Try UID first
        if name_or_uid in self.objects:
            return self.objects[name_or_uid]

        # Try by name
        for obj in self.objects.values():
            if obj.name == name_or_uid:
                return obj

        return None

    def get_rule_sources(self, rule: CheckpointRule) -> list[CheckpointObject]:
        """Get resolved source objects for a rule."""
        return [self.resolve_object(s) for s in rule.source if self.resolve_object(s)]

    def get_rule_destinations(self, rule: CheckpointRule) -> list[CheckpointObject]:
        """Get resolved destination objects for a rule."""
        return [self.resolve_object(d) for d in rule.destination if self.resolve_object(d)]
