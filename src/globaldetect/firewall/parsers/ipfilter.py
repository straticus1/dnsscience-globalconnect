"""
IPFilter (ipf) output parser.

Parses IPFilter/ipf rules from BSD and Solaris systems
into structured firewall policy objects.

Copyright (c) 2025 DNS Science.io, an After Dark Systems, LLC company.
All rights reserved.
"""

import re
import logging
from typing import Any

from globaldetect.firewall.parsers.base import FirewallParser
from globaldetect.firewall.models import (
    FirewallPolicy,
    FirewallTable,
    FirewallChain,
    FirewallRule,
    FirewallVendor,
    RuleAction,
    Protocol,
    AddressSpec,
    PortSpec,
)

logger = logging.getLogger(__name__)


class IpfilterParser(FirewallParser):
    """Parser for IPFilter (ipf) rules.

    Supports the standard ipfilter syntax used on BSD and Solaris:
    - pass/block actions
    - in/out direction
    - quick keyword
    - interface binding
    - protocol matching
    - source/destination address/port
    - flags and state tracking
    - logging
    """

    VENDOR = FirewallVendor.IPFILTER

    # Action mappings
    ACTION_MAP = {
        "pass": RuleAction.PASS,
        "block": RuleAction.BLOCK,
        "count": RuleAction.COUNT,
        "skip": RuleAction.SKIP,
        "auth": RuleAction.AUTH,
        "log": RuleAction.LOG,
    }

    # Protocol mappings
    PROTOCOL_MAP = {
        "tcp": Protocol.TCP,
        "udp": Protocol.UDP,
        "icmp": Protocol.ICMP,
        "icmpv6": Protocol.ICMPV6,
        "gre": Protocol.GRE,
        "esp": Protocol.ESP,
        "ah": Protocol.AH,
        "sctp": Protocol.SCTP,
    }

    def parse(self, content: str) -> FirewallPolicy:
        """Parse IPFilter rules.

        Args:
            content: IPFilter rules content

        Returns:
            Parsed FirewallPolicy
        """
        policy = FirewallPolicy(
            vendor=FirewallVendor.IPFILTER,
            raw_content=content,
        )

        # IPFilter doesn't have tables like iptables
        # Create a single "filter" table with input/output chains
        filter_table = FirewallTable(name="filter")
        filter_table.chains["input"] = FirewallChain(name="input")
        filter_table.chains["output"] = FirewallChain(name="output")
        filter_table.chains["forward"] = FirewallChain(name="forward")
        policy.tables["filter"] = filter_table

        rule_number = 0

        for line in content.splitlines():
            line = line.strip()

            # Skip empty lines and comments
            if not line or line.startswith("#"):
                continue

            # Parse rule
            rule = self._parse_rule(line)
            if rule:
                rule_number += 1
                rule.rule_number = rule_number

                # Determine chain based on direction
                direction = rule.attributes.get("direction", "in")
                if direction == "in":
                    filter_table.chains["input"].rules.append(rule)
                elif direction == "out":
                    filter_table.chains["output"].rules.append(rule)
                else:
                    filter_table.chains["forward"].rules.append(rule)

        return policy

    def _parse_rule(self, line: str) -> FirewallRule | None:
        """Parse a single IPFilter rule.

        IPFilter rule format:
        action [in|out] [log] [quick] [on interface] [proto protocol]
               [from src [port port]] [to dst [port port]] [flags] [keep state]
        """
        rule = FirewallRule(raw_rule=line)
        rule.attributes = {}

        # Tokenize the line
        tokens = self._tokenize(line)
        if not tokens:
            return None

        pos = 0

        # Parse action (pass, block, count, skip, auth)
        if tokens[pos] in self.ACTION_MAP:
            rule.action = self.ACTION_MAP[tokens[pos]]
            pos += 1
        else:
            return None  # Invalid rule

        # Parse direction (in, out)
        if pos < len(tokens) and tokens[pos] in ("in", "out"):
            rule.attributes["direction"] = tokens[pos]
            pos += 1

        # Parse remaining options
        while pos < len(tokens):
            token = tokens[pos]

            if token == "log":
                rule.attributes["log"] = True
                pos += 1

            elif token == "quick":
                rule.attributes["quick"] = True
                pos += 1

            elif token == "first":
                rule.attributes["first"] = True
                pos += 1

            elif token == "on":
                # Interface specification
                pos += 1
                if pos < len(tokens):
                    interface = tokens[pos]
                    direction = rule.attributes.get("direction", "in")
                    if direction == "in":
                        rule.in_interface = interface
                    else:
                        rule.out_interface = interface
                    pos += 1

            elif token == "proto":
                pos += 1
                if pos < len(tokens):
                    proto = tokens[pos].lower()
                    rule.protocol = self.PROTOCOL_MAP.get(proto, Protocol.ANY)
                    pos += 1

            elif token == "from":
                pos += 1
                pos = self._parse_address_port(tokens, pos, rule, is_source=True)

            elif token == "to":
                pos += 1
                pos = self._parse_address_port(tokens, pos, rule, is_source=False)

            elif token == "flags":
                pos += 1
                if pos < len(tokens):
                    rule.attributes["flags"] = tokens[pos]
                    # Parse TCP flags (e.g., S/SA, S/SAFR)
                    self._parse_tcp_flags(tokens[pos], rule)
                    pos += 1

            elif token == "keep":
                pos += 1
                if pos < len(tokens) and tokens[pos] == "state":
                    rule.state = ["ESTABLISHED", "RELATED"]
                    pos += 1
                if pos < len(tokens) and tokens[pos] == "frags":
                    rule.attributes["keep_frags"] = True
                    pos += 1

            elif token == "icmp-type":
                pos += 1
                if pos < len(tokens):
                    rule.icmp_type = tokens[pos]
                    pos += 1

            elif token == "return-rst":
                rule.action = RuleAction.REJECT
                rule.reject_with = "tcp-reset"
                pos += 1

            elif token == "return-icmp":
                rule.action = RuleAction.REJECT
                pos += 1
                if pos < len(tokens) and tokens[pos].startswith("("):
                    # Parse ICMP type in parentheses
                    rule.reject_with = tokens[pos].strip("()")
                    pos += 1

            elif token == "return-icmp-as-dest":
                rule.action = RuleAction.REJECT
                rule.reject_with = "icmp-as-dest"
                pos += 1

            elif token == "head":
                pos += 1
                if pos < len(tokens):
                    rule.attributes["head"] = tokens[pos]
                    pos += 1

            elif token == "group":
                pos += 1
                if pos < len(tokens):
                    rule.attributes["group"] = tokens[pos]
                    pos += 1

            elif token == "tag":
                pos += 1
                if pos < len(tokens):
                    try:
                        rule.tag = int(tokens[pos])
                    except ValueError:
                        rule.attributes["tag_name"] = tokens[pos]
                    pos += 1

            elif token == "set-tag":
                pos += 1
                if pos < len(tokens) and tokens[pos].startswith("("):
                    rule.attributes["set_tag"] = tokens[pos].strip("()")
                    pos += 1

            else:
                # Unknown token, skip
                pos += 1

        return rule

    def _tokenize(self, line: str) -> list[str]:
        """Tokenize IPFilter rule line.

        Handles quoted strings and parenthetical expressions.
        """
        tokens = []
        current = ""
        in_paren = 0
        in_quote = False

        for char in line:
            if char == '"' and not in_paren:
                in_quote = not in_quote
                current += char
            elif char == "(" and not in_quote:
                in_paren += 1
                current += char
            elif char == ")" and not in_quote:
                in_paren -= 1
                current += char
            elif char.isspace() and not in_quote and in_paren == 0:
                if current:
                    tokens.append(current)
                    current = ""
            else:
                current += char

        if current:
            tokens.append(current)

        return tokens

    def _parse_address_port(
        self,
        tokens: list[str],
        pos: int,
        rule: FirewallRule,
        is_source: bool
    ) -> int:
        """Parse address and optional port specification.

        Returns new position in token list.
        """
        if pos >= len(tokens):
            return pos

        # Parse address
        addr_token = tokens[pos]
        pos += 1

        negated = False
        if addr_token == "!":
            negated = True
            if pos < len(tokens):
                addr_token = tokens[pos]
                pos += 1

        if addr_token == "any":
            address = None
        elif addr_token == "all":
            address = None
        else:
            # Handle address/mask or address mask format
            if "/" in addr_token:
                address = addr_token
            elif pos < len(tokens) and tokens[pos] == "mask":
                pos += 1
                if pos < len(tokens):
                    address = f"{addr_token}/{tokens[pos]}"
                    pos += 1
            else:
                address = addr_token

        if address:
            addr_spec = AddressSpec(address=address, negated=negated)
        else:
            addr_spec = None

        if is_source:
            rule.source = addr_spec
        else:
            rule.destination = addr_spec

        # Check for port specification
        if pos < len(tokens) and tokens[pos] == "port":
            pos += 1
            if pos < len(tokens):
                port_spec = self._parse_port_spec(tokens, pos)
                pos = port_spec[1]

                if is_source:
                    rule.source_port = port_spec[0]
                else:
                    rule.destination_port = port_spec[0]

        return pos

    def _parse_port_spec(self, tokens: list[str], pos: int) -> tuple[PortSpec, int]:
        """Parse port specification.

        Handles:
        - Single port: port = 22
        - Port range: port 1024 >< 65535
        - Comparison: port > 1023, port < 1024
        - Multiple forms: port = 22 or port = 80
        """
        spec = PortSpec()

        if pos >= len(tokens):
            return spec, pos

        # Check for comparison operator
        op = tokens[pos]
        if op in ("=", "!=", "<", ">", "<=", ">=", "><", "<>"):
            pos += 1
            if pos < len(tokens):
                try:
                    port_val = int(tokens[pos])
                    if op == "=" or op == "!=":
                        spec.port = port_val
                    elif op in ("><", "<>"):
                        # Range: port 1024 >< 65535
                        pos += 1
                        if pos < len(tokens):
                            try:
                                port_end = int(tokens[pos])
                                spec.port_range = (port_val, port_end)
                            except ValueError:
                                spec.port = port_val
                    else:
                        # Comparison - store as single port with note
                        spec.port = port_val
                except ValueError:
                    pass
                pos += 1
        else:
            # Direct port number
            try:
                spec.port = int(op)
                pos += 1
            except ValueError:
                pass

        return spec, pos

    def _parse_tcp_flags(self, flags_str: str, rule: FirewallRule) -> None:
        """Parse TCP flags specification.

        Format: flags/mask (e.g., S/SA, S/SAFR)
        """
        if "/" not in flags_str:
            return

        parts = flags_str.split("/")
        if len(parts) == 2:
            flags = list(parts[0])
            mask = list(parts[1])

            # Map single letter flags to full names
            flag_map = {
                "S": "SYN",
                "A": "ACK",
                "F": "FIN",
                "R": "RST",
                "P": "PSH",
                "U": "URG",
            }

            rule.tcp_flags = {
                "mask": [flag_map.get(f, f) for f in mask],
                "flags": [flag_map.get(f, f) for f in flags],
            }


class SolarisIpfilterParser(IpfilterParser):
    """Parser for Solaris-specific IPFilter extensions."""

    def parse(self, content: str) -> FirewallPolicy:
        """Parse Solaris IPFilter rules."""
        policy = super().parse(content)
        policy.metadata["platform"] = "solaris"
        return policy


class OpenBSDPfParser(FirewallParser):
    """Parser for OpenBSD pf.conf format.

    While similar to IPFilter, pf has some differences in syntax.
    """

    VENDOR = FirewallVendor.PF

    def parse(self, content: str) -> FirewallPolicy:
        """Parse OpenBSD pf rules.

        Note: This is a basic implementation. Full pf parsing
        is more complex due to macros, tables, and anchors.
        """
        policy = FirewallPolicy(
            vendor=FirewallVendor.PF,
            raw_content=content,
        )

        # Create filter table
        filter_table = FirewallTable(name="filter")
        filter_table.chains["input"] = FirewallChain(name="input")
        filter_table.chains["output"] = FirewallChain(name="output")
        policy.tables["filter"] = filter_table

        # Parse macros first
        macros: dict[str, str] = {}
        for line in content.splitlines():
            line = line.strip()
            if "=" in line and not line.startswith("#"):
                # Macro definition
                match = re.match(r"(\w+)\s*=\s*(.+)", line)
                if match:
                    macros[match.group(1)] = match.group(2).strip('"')

        # Store macros in policy
        policy.metadata["macros"] = macros

        rule_number = 0

        for line in content.splitlines():
            line = line.strip()

            # Skip empty lines, comments, and non-rule lines
            if not line or line.startswith("#"):
                continue

            # Skip macro definitions and options
            if "=" in line or line.startswith("set "):
                continue

            # Skip table definitions
            if line.startswith("table "):
                continue

            # Skip scrub rules (we could parse these too)
            if line.startswith("scrub "):
                continue

            # Expand macros
            for macro, value in macros.items():
                line = line.replace(f"${macro}", value)
                line = line.replace(f"$({macro})", value)

            # Parse pass/block rules
            if line.startswith("pass ") or line.startswith("block "):
                rule = self._parse_pf_rule(line)
                if rule:
                    rule_number += 1
                    rule.rule_number = rule_number

                    direction = rule.attributes.get("direction", "in")
                    if direction == "in":
                        filter_table.chains["input"].rules.append(rule)
                    else:
                        filter_table.chains["output"].rules.append(rule)

        return policy

    def _parse_pf_rule(self, line: str) -> FirewallRule | None:
        """Parse a single pf rule."""
        rule = FirewallRule(raw_rule=line)
        rule.attributes = {}

        # Basic tokenization
        tokens = line.split()
        if not tokens:
            return None

        pos = 0

        # Action
        if tokens[pos] == "pass":
            rule.action = RuleAction.PASS
            pos += 1
        elif tokens[pos] == "block":
            rule.action = RuleAction.BLOCK
            pos += 1
        else:
            return None

        while pos < len(tokens):
            token = tokens[pos]

            if token in ("in", "out"):
                rule.attributes["direction"] = token
                pos += 1

            elif token == "log":
                rule.attributes["log"] = True
                pos += 1

            elif token == "quick":
                rule.attributes["quick"] = True
                pos += 1

            elif token == "on":
                pos += 1
                if pos < len(tokens):
                    rule.in_interface = tokens[pos]
                    pos += 1

            elif token == "proto":
                pos += 1
                if pos < len(tokens):
                    proto = tokens[pos].lower()
                    proto_map = {
                        "tcp": Protocol.TCP,
                        "udp": Protocol.UDP,
                        "icmp": Protocol.ICMP,
                        "icmp6": Protocol.ICMPV6,
                    }
                    rule.protocol = proto_map.get(proto, Protocol.ANY)
                    pos += 1

            elif token == "from":
                pos += 1
                if pos < len(tokens):
                    if tokens[pos] != "any":
                        rule.source = AddressSpec(address=tokens[pos])
                    pos += 1
                    # Check for port
                    if pos < len(tokens) and tokens[pos] == "port":
                        pos += 1
                        if pos < len(tokens):
                            try:
                                rule.source_port = PortSpec(port=int(tokens[pos]))
                            except ValueError:
                                pass
                            pos += 1

            elif token == "to":
                pos += 1
                if pos < len(tokens):
                    if tokens[pos] != "any":
                        rule.destination = AddressSpec(address=tokens[pos])
                    pos += 1
                    # Check for port
                    if pos < len(tokens) and tokens[pos] == "port":
                        pos += 1
                        if pos < len(tokens):
                            try:
                                rule.destination_port = PortSpec(port=int(tokens[pos]))
                            except ValueError:
                                pass
                            pos += 1

            elif token == "keep":
                pos += 1
                if pos < len(tokens) and tokens[pos] == "state":
                    rule.state = ["ESTABLISHED", "RELATED"]
                    pos += 1

            elif token == "flags":
                pos += 1
                if pos < len(tokens):
                    rule.attributes["flags"] = tokens[pos]
                    pos += 1

            else:
                pos += 1

        return rule
