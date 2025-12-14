"""
Checkpoint firewall export parser.

Parses Checkpoint firewall exports including:
- Management API JSON exports (SmartConsole)
- dbedit text exports
- Policy package exports

Copyright (c) 2025 DNS Science.io, an After Dark Systems, LLC company.
All rights reserved.
"""

import json
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
    CheckpointObject,
    CheckpointRule,
    CheckpointPolicy,
)

logger = logging.getLogger(__name__)


class CheckpointParser(FirewallParser):
    """Parser for Checkpoint firewall exports.

    Supports:
    - Management API JSON format
    - dbedit text export format
    - Basic policy package exports
    """

    VENDOR = FirewallVendor.CHECKPOINT

    # Checkpoint action mappings
    ACTION_MAP = {
        "Accept": RuleAction.ACCEPT,
        "accept": RuleAction.ACCEPT,
        "Drop": RuleAction.DROP,
        "drop": RuleAction.DROP,
        "Reject": RuleAction.REJECT,
        "reject": RuleAction.REJECT,
        "Ask": RuleAction.LOG,
        "Inform": RuleAction.LOG,
        "User Auth": RuleAction.AUTH,
        "Client Auth": RuleAction.AUTH,
    }

    # Checkpoint service to protocol mapping
    SERVICE_PROTOCOL_MAP = {
        "tcp": Protocol.TCP,
        "udp": Protocol.UDP,
        "icmp": Protocol.ICMP,
        "icmp6": Protocol.ICMPV6,
        "gre": Protocol.GRE,
        "esp": Protocol.ESP,
        "ah": Protocol.AH,
    }

    def parse(self, content: str) -> FirewallPolicy:
        """Parse Checkpoint export content.

        Auto-detects format (JSON vs dbedit text) and parses accordingly.

        Args:
            content: Checkpoint export content

        Returns:
            Parsed FirewallPolicy
        """
        content = content.strip()

        # Try JSON format first
        if content.startswith("{") or content.startswith("["):
            try:
                return self._parse_json(content)
            except json.JSONDecodeError:
                pass

        # Try dbedit format
        if "create network" in content.lower() or "addrule" in content.lower():
            return self._parse_dbedit(content)

        # Fallback to generic text parsing
        return self._parse_text(content)

    def _parse_json(self, content: str) -> FirewallPolicy:
        """Parse Checkpoint Management API JSON export.

        This handles exports from:
        - show-access-rulebase
        - show-objects
        - Full policy package exports
        """
        data = json.loads(content)

        policy = FirewallPolicy(
            vendor=FirewallVendor.CHECKPOINT,
            raw_content=content,
        )

        # Create a single filter table for Checkpoint rules
        filter_table = FirewallTable(name="access-policy")
        filter_table.chains["rulebase"] = FirewallChain(name="rulebase")
        policy.tables["access-policy"] = filter_table

        # If this is an array, it might be objects or rules
        if isinstance(data, list):
            for item in data:
                if "type" in item:
                    self._process_json_item(item, policy, filter_table)
        elif isinstance(data, dict):
            # Could be a single response or a wrapped response
            if "objects" in data:
                # Object export
                for obj in data["objects"]:
                    self._parse_json_object(obj, policy)

            if "rulebase" in data:
                # Rulebase export
                rulebase = data["rulebase"]
                if isinstance(rulebase, list):
                    for idx, rule in enumerate(rulebase):
                        parsed = self._parse_json_rule(rule, idx + 1)
                        if parsed:
                            filter_table.chains["rulebase"].rules.append(parsed)

            if "access-rule" in data.get("type", ""):
                # Single rule
                parsed = self._parse_json_rule(data, 1)
                if parsed:
                    filter_table.chains["rulebase"].rules.append(parsed)

            # Handle total and other metadata
            if "total" in data:
                policy.metadata["total_rules"] = data["total"]
            if "name" in data:
                policy.name = data["name"]
            if "uid" in data:
                policy.metadata["uid"] = data["uid"]

        return policy

    def _process_json_item(
        self,
        item: dict,
        policy: FirewallPolicy,
        filter_table: FirewallTable
    ) -> None:
        """Process a single JSON item (could be object or rule)."""
        item_type = item.get("type", "")

        if item_type == "access-rule":
            rule = self._parse_json_rule(
                item,
                len(filter_table.chains["rulebase"].rules) + 1
            )
            if rule:
                filter_table.chains["rulebase"].rules.append(rule)
        elif item_type in ("host", "network", "group", "service-tcp",
                          "service-udp", "service-group", "address-range"):
            self._parse_json_object(item, policy)

    def _parse_json_object(self, obj: dict, policy: FirewallPolicy) -> None:
        """Parse a Checkpoint network object from JSON."""
        uid = obj.get("uid", "")
        name = obj.get("name", "")
        obj_type = obj.get("type", "unknown")

        cp_obj = CheckpointObject(
            uid=uid,
            name=name,
            object_type=obj_type,
            comments=obj.get("comments"),
            color=obj.get("color"),
            tags=obj.get("tags", []),
        )

        # Type-specific parsing
        if obj_type == "host":
            cp_obj.ipv4_address = obj.get("ipv4-address")
            cp_obj.ipv6_address = obj.get("ipv6-address")

        elif obj_type == "network":
            cp_obj.subnet4 = obj.get("subnet4")
            cp_obj.mask_length4 = obj.get("mask-length4")
            cp_obj.subnet6 = obj.get("subnet6")
            cp_obj.mask_length6 = obj.get("mask-length6")

        elif obj_type == "address-range":
            cp_obj.ipv4_address = obj.get("ipv4-address-first")
            # Store range end in subnet4 field
            cp_obj.subnet4 = obj.get("ipv4-address-last")

        elif obj_type in ("service-tcp", "service-udp"):
            cp_obj.port = obj.get("port")
            cp_obj.protocol = obj_type.replace("service-", "")

        elif obj_type == "group" or obj_type == "service-group":
            members = obj.get("members", [])
            cp_obj.members = [
                m.get("name", m.get("uid", "")) if isinstance(m, dict) else m
                for m in members
            ]

        policy.metadata.setdefault("objects", {})[uid] = cp_obj
        policy.metadata.setdefault("objects_by_name", {})[name] = cp_obj

    def _parse_json_rule(self, rule: dict, rule_num: int) -> FirewallRule | None:
        """Parse a single Checkpoint rule from JSON."""
        fw_rule = FirewallRule(
            rule_number=rule_num,
            enabled=rule.get("enabled", True),
            comment=rule.get("comments"),
            raw_rule=json.dumps(rule),
        )

        # Parse action
        action = rule.get("action", {})
        if isinstance(action, dict):
            action_name = action.get("name", "Drop")
        else:
            action_name = str(action)
        fw_rule.action = self.ACTION_MAP.get(action_name, RuleAction.DROP)

        # Parse source
        source = rule.get("source", [])
        if source:
            src_names = self._extract_object_names(source)
            if src_names and src_names != ["Any"]:
                # For now, store first source
                fw_rule.source = AddressSpec(address=src_names[0])
            fw_rule.attributes["source_objects"] = src_names

        # Parse destination
        destination = rule.get("destination", [])
        if destination:
            dst_names = self._extract_object_names(destination)
            if dst_names and dst_names != ["Any"]:
                fw_rule.destination = AddressSpec(address=dst_names[0])
            fw_rule.attributes["destination_objects"] = dst_names

        # Parse service
        service = rule.get("service", [])
        if service:
            svc_names = self._extract_object_names(service)
            fw_rule.attributes["service_objects"] = svc_names

            # Try to extract protocol/port from service name
            for svc in svc_names:
                if svc.lower() != "any":
                    proto, port = self._parse_service_name(svc)
                    if proto:
                        fw_rule.protocol = proto
                    if port:
                        fw_rule.destination_port = PortSpec(port=port)
                    break

        # Parse track (logging)
        track = rule.get("track", {})
        if isinstance(track, dict):
            track_type = track.get("type", {})
            if isinstance(track_type, dict):
                fw_rule.attributes["track"] = track_type.get("name", "None")
            else:
                fw_rule.attributes["track"] = str(track_type)

        # Store UID
        fw_rule.attributes["uid"] = rule.get("uid", "")

        # Rule name
        if rule.get("name"):
            fw_rule.attributes["name"] = rule["name"]

        return fw_rule

    def _extract_object_names(self, objects: list | dict | str) -> list[str]:
        """Extract object names from various formats."""
        if isinstance(objects, str):
            return [objects]
        if isinstance(objects, dict):
            return [objects.get("name", objects.get("uid", ""))]
        if isinstance(objects, list):
            names = []
            for obj in objects:
                if isinstance(obj, dict):
                    names.append(obj.get("name", obj.get("uid", "")))
                else:
                    names.append(str(obj))
            return names
        return []

    def _parse_service_name(self, service: str) -> tuple[Protocol | None, int | None]:
        """Try to parse protocol and port from service name.

        Common patterns:
        - tcp_80, TCP-80, tcp/80
        - http (maps to tcp/80)
        - udp_53, DNS
        """
        service_lower = service.lower()

        # Well-known services
        well_known = {
            "http": (Protocol.TCP, 80),
            "https": (Protocol.TCP, 443),
            "ssh": (Protocol.TCP, 22),
            "telnet": (Protocol.TCP, 23),
            "ftp": (Protocol.TCP, 21),
            "smtp": (Protocol.TCP, 25),
            "dns": (Protocol.UDP, 53),
            "domain": (Protocol.UDP, 53),
            "ntp": (Protocol.UDP, 123),
            "snmp": (Protocol.UDP, 161),
            "ldap": (Protocol.TCP, 389),
            "ldaps": (Protocol.TCP, 636),
        }

        if service_lower in well_known:
            return well_known[service_lower]

        # Pattern matching
        patterns = [
            r"^(tcp|udp)[_\-/](\d+)$",
            r"^(tcp|udp)(\d+)$",
        ]

        for pattern in patterns:
            match = re.match(pattern, service_lower)
            if match:
                proto = self.SERVICE_PROTOCOL_MAP.get(match.group(1))
                try:
                    port = int(match.group(2))
                    return proto, port
                except ValueError:
                    pass

        return None, None

    def _parse_dbedit(self, content: str) -> FirewallPolicy:
        """Parse Checkpoint dbedit text export format.

        dbedit format example:
        create network my_network
        modify network my_network ipaddr 10.0.0.0
        modify network my_network netmask 255.255.255.0

        addrule position top rulebase Standard
        modify position top rulebase Standard -a name "Rule 1"
        modify position top rulebase Standard -a source my_network
        """
        policy = FirewallPolicy(
            vendor=FirewallVendor.CHECKPOINT,
            raw_content=content,
        )

        filter_table = FirewallTable(name="access-policy")
        filter_table.chains["rulebase"] = FirewallChain(name="rulebase")
        policy.tables["access-policy"] = filter_table

        # Track objects and current rule being built
        objects: dict[str, dict[str, Any]] = {}
        current_object: dict[str, Any] | None = None
        current_object_name: str | None = None

        rules: list[dict[str, Any]] = []
        current_rule: dict[str, Any] | None = None

        for line in content.splitlines():
            line = line.strip()

            if not line or line.startswith("#"):
                continue

            # Object creation
            create_match = re.match(
                r"create\s+(\w+)\s+(\S+)",
                line,
                re.IGNORECASE
            )
            if create_match:
                obj_type = create_match.group(1).lower()
                obj_name = create_match.group(2)
                current_object = {"type": obj_type, "name": obj_name}
                current_object_name = obj_name
                objects[obj_name] = current_object
                continue

            # Object modification
            modify_match = re.match(
                r"modify\s+(\w+)\s+(\S+)\s+(\S+)\s+(.+)",
                line,
                re.IGNORECASE
            )
            if modify_match:
                obj_type = modify_match.group(1).lower()
                obj_name = modify_match.group(2)
                attr = modify_match.group(3)
                value = modify_match.group(4).strip('"')

                if obj_name in objects:
                    objects[obj_name][attr] = value
                elif obj_name == "position":
                    # Rule modification
                    if current_rule and attr == "-a":
                        # Parse attribute assignment
                        attr_match = re.match(r"(\w+)\s+(.+)", value)
                        if attr_match:
                            current_rule[attr_match.group(1)] = attr_match.group(2).strip('"')
                continue

            # Rule creation
            if line.lower().startswith("addrule"):
                if current_rule:
                    rules.append(current_rule)
                current_rule = {"action": "Drop", "enabled": True}
                continue

        # Don't forget last rule
        if current_rule:
            rules.append(current_rule)

        # Convert objects to CheckpointObject format
        for name, obj in objects.items():
            cp_obj = CheckpointObject(
                uid=name,
                name=name,
                object_type=obj.get("type", "unknown"),
            )

            if "ipaddr" in obj:
                cp_obj.ipv4_address = obj["ipaddr"]
            if "netmask" in obj:
                # Convert netmask to CIDR if needed
                cp_obj.subnet4 = obj.get("ipaddr")

            policy.metadata.setdefault("objects", {})[name] = cp_obj

        # Convert rules to FirewallRule format
        for idx, rule in enumerate(rules):
            fw_rule = FirewallRule(
                rule_number=idx + 1,
                enabled=rule.get("enabled", True),
                comment=rule.get("comments", rule.get("name")),
            )

            # Action
            action_name = rule.get("action", "Drop")
            fw_rule.action = self.ACTION_MAP.get(action_name, RuleAction.DROP)

            # Source
            if "source" in rule:
                src = rule["source"]
                if src.lower() != "any":
                    fw_rule.source = AddressSpec(address=src)
                fw_rule.attributes["source_objects"] = [src]

            # Destination
            if "destination" in rule or "dst" in rule:
                dst = rule.get("destination", rule.get("dst"))
                if dst.lower() != "any":
                    fw_rule.destination = AddressSpec(address=dst)
                fw_rule.attributes["destination_objects"] = [dst]

            # Service
            if "service" in rule:
                fw_rule.attributes["service_objects"] = [rule["service"]]

            filter_table.chains["rulebase"].rules.append(fw_rule)

        return policy

    def _parse_text(self, content: str) -> FirewallPolicy:
        """Parse generic Checkpoint text export.

        This is a fallback parser for less structured exports.
        """
        policy = FirewallPolicy(
            vendor=FirewallVendor.CHECKPOINT,
            raw_content=content,
        )

        filter_table = FirewallTable(name="access-policy")
        filter_table.chains["rulebase"] = FirewallChain(name="rulebase")
        policy.tables["access-policy"] = filter_table

        # Look for rule-like patterns
        rule_pattern = re.compile(
            r"(?:rule\s*#?\d*|^\d+)\s*[:\-]?\s*"
            r"(?:(?P<action>accept|drop|reject)\s+)?"
            r"(?:from\s+(?P<src>\S+)\s+)?"
            r"(?:to\s+(?P<dst>\S+)\s+)?"
            r"(?:service\s+(?P<svc>\S+))?"
            ,
            re.IGNORECASE | re.MULTILINE
        )

        rule_number = 0
        for match in rule_pattern.finditer(content):
            rule_number += 1

            fw_rule = FirewallRule(rule_number=rule_number)

            action = match.group("action")
            if action:
                fw_rule.action = self.ACTION_MAP.get(
                    action.capitalize(),
                    RuleAction.DROP
                )

            src = match.group("src")
            if src and src.lower() != "any":
                fw_rule.source = AddressSpec(address=src)

            dst = match.group("dst")
            if dst and dst.lower() != "any":
                fw_rule.destination = AddressSpec(address=dst)

            svc = match.group("svc")
            if svc:
                fw_rule.attributes["service_objects"] = [svc]

            filter_table.chains["rulebase"].rules.append(fw_rule)

        return policy

    def parse_checkpoint_api_response(self, data: dict) -> CheckpointPolicy:
        """Parse full Checkpoint Management API response into CheckpointPolicy.

        This provides more detailed object and rule information
        than the generic FirewallPolicy format.

        Args:
            data: Checkpoint API JSON response

        Returns:
            CheckpointPolicy with full object database
        """
        cp_policy = CheckpointPolicy(
            name=data.get("name", "Unknown"),
            uid=data.get("uid", ""),
            package_name=data.get("package", {}).get("name") if isinstance(data.get("package"), dict) else data.get("package"),
        )

        # Parse objects
        if "objects-dictionary" in data:
            for obj in data["objects-dictionary"]:
                cp_obj = self._parse_checkpoint_object(obj)
                cp_policy.objects[cp_obj.uid] = cp_obj

        # Parse rulebase
        if "rulebase" in data:
            for idx, rule in enumerate(data["rulebase"]):
                if rule.get("type") == "access-rule":
                    cp_rule = self._parse_checkpoint_rule(rule, idx + 1)
                    cp_policy.rules.append(cp_rule)
                elif rule.get("type") == "access-section":
                    # Section header - rules inside
                    section_rules = rule.get("rulebase", [])
                    for sub_idx, sub_rule in enumerate(section_rules):
                        cp_rule = self._parse_checkpoint_rule(sub_rule, len(cp_policy.rules) + 1)
                        cp_policy.rules.append(cp_rule)

        # Metadata
        cp_policy.domain = data.get("domain", {}).get("name") if isinstance(data.get("domain"), dict) else None
        cp_policy.last_modified = data.get("meta-info", {}).get("last-modify-time", {}).get("iso-8601")
        cp_policy.last_modifier = data.get("meta-info", {}).get("last-modifier")

        return cp_policy

    def _parse_checkpoint_object(self, obj: dict) -> CheckpointObject:
        """Parse a Checkpoint object from API response."""
        return CheckpointObject(
            uid=obj.get("uid", ""),
            name=obj.get("name", ""),
            object_type=obj.get("type", "unknown"),
            ipv4_address=obj.get("ipv4-address"),
            ipv6_address=obj.get("ipv6-address"),
            subnet4=obj.get("subnet4"),
            mask_length4=obj.get("mask-length4"),
            subnet6=obj.get("subnet6"),
            mask_length6=obj.get("mask-length6"),
            port=obj.get("port"),
            protocol=obj.get("protocol"),
            members=[m.get("name", "") for m in obj.get("members", [])] if isinstance(obj.get("members"), list) else None,
            comments=obj.get("comments"),
            color=obj.get("color"),
            tags=[t.get("name", "") for t in obj.get("tags", [])] if isinstance(obj.get("tags"), list) else None,
        )

    def _parse_checkpoint_rule(self, rule: dict, rule_num: int) -> CheckpointRule:
        """Parse a Checkpoint rule from API response."""
        def extract_names(field: list | dict | str) -> list[str]:
            if isinstance(field, str):
                return [field]
            if isinstance(field, dict):
                return [field.get("name", field.get("uid", ""))]
            if isinstance(field, list):
                return [
                    item.get("name", item.get("uid", "")) if isinstance(item, dict) else str(item)
                    for item in field
                ]
            return []

        action_obj = rule.get("action", {})
        action_name = action_obj.get("name", "Drop") if isinstance(action_obj, dict) else str(action_obj)

        track_obj = rule.get("track", {})
        track_type = track_obj.get("type", {}) if isinstance(track_obj, dict) else {}
        track_name = track_type.get("name") if isinstance(track_type, dict) else None

        return CheckpointRule(
            uid=rule.get("uid", ""),
            rule_number=rule_num,
            name=rule.get("name"),
            enabled=rule.get("enabled", True),
            source=extract_names(rule.get("source", [])),
            source_negate=rule.get("source-negate", False),
            destination=extract_names(rule.get("destination", [])),
            destination_negate=rule.get("destination-negate", False),
            service=extract_names(rule.get("service", [])),
            service_negate=rule.get("service-negate", False),
            action=action_name,
            track=track_name,
            install_on=extract_names(rule.get("install-on", [])),
            vpn=rule.get("vpn", {}).get("name") if isinstance(rule.get("vpn"), dict) else None,
            comments=rule.get("comments"),
        )
