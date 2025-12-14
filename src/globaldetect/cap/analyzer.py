"""
Packet analysis engine for network troubleshooting.

Analyzes captured packets for L2/L3 issues, protocol errors,
and network anomalies.

Copyright (c) 2025 DNS Science.io, an After Dark Systems, LLC company.
All rights reserved.
"""

import os
import re
import subprocess
import struct
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any, Iterator
from collections import defaultdict


class IssueSeverity(Enum):
    """Severity levels for detected issues."""
    INFO = "info"
    WARNING = "warning"
    ERROR = "error"
    CRITICAL = "critical"


class IssueCategory(Enum):
    """Categories of network issues."""
    L2_SWITCHING = "L2/Switching"
    L3_ROUTING = "L3/Routing"
    DNS = "DNS"
    SSL_TLS = "SSL/TLS"
    SMTP = "SMTP/Email"
    TCP = "TCP"
    PERFORMANCE = "Performance"
    SECURITY = "Security"
    CONFIGURATION = "Configuration"


@dataclass
class NetworkIssue:
    """A detected network issue."""
    category: IssueCategory
    severity: IssueSeverity
    title: str
    description: str
    packet_numbers: list[int] = field(default_factory=list)
    source_ip: str | None = None
    dest_ip: str | None = None
    source_mac: str | None = None
    dest_mac: str | None = None
    recommendation: str | None = None
    raw_data: dict[str, Any] = field(default_factory=dict)


@dataclass
class AnalysisStats:
    """Statistics from packet analysis."""
    total_packets: int = 0
    total_bytes: int = 0
    duration_seconds: float = 0.0
    start_time: datetime | None = None
    end_time: datetime | None = None

    # Protocol breakdown
    tcp_packets: int = 0
    udp_packets: int = 0
    icmp_packets: int = 0
    arp_packets: int = 0
    other_packets: int = 0

    # Unique counts
    unique_src_ips: int = 0
    unique_dst_ips: int = 0
    unique_src_macs: int = 0
    unique_dst_macs: int = 0
    unique_conversations: int = 0


@dataclass
class AnalysisResult:
    """Result of packet analysis."""
    success: bool = False
    file_analyzed: str | None = None
    stats: AnalysisStats = field(default_factory=AnalysisStats)
    issues: list[NetworkIssue] = field(default_factory=list)
    summary: dict[str, Any] = field(default_factory=dict)
    error: str | None = None

    @property
    def critical_issues(self) -> list[NetworkIssue]:
        return [i for i in self.issues if i.severity == IssueSeverity.CRITICAL]

    @property
    def error_issues(self) -> list[NetworkIssue]:
        return [i for i in self.issues if i.severity == IssueSeverity.ERROR]

    @property
    def warning_issues(self) -> list[NetworkIssue]:
        return [i for i in self.issues if i.severity == IssueSeverity.WARNING]


class PacketAnalyzer:
    """Analyzes pcap files for network issues."""

    def __init__(self):
        self._tshark = self._find_tshark()
        self._tcpdump = self._find_tcpdump()

    def _find_tshark(self) -> str | None:
        """Find tshark binary."""
        paths = [
            "/usr/bin/tshark",
            "/usr/local/bin/tshark",
            "/opt/homebrew/bin/tshark",
            "/Applications/Wireshark.app/Contents/MacOS/tshark",
        ]
        for path in paths:
            if os.path.exists(path):
                return path
        return None

    def _find_tcpdump(self) -> str | None:
        """Find tcpdump binary."""
        paths = [
            "/usr/sbin/tcpdump",
            "/usr/bin/tcpdump",
            "/sbin/tcpdump",
        ]
        for path in paths:
            if os.path.exists(path):
                return path
        return None

    def analyze(self, pcap_file: str) -> AnalysisResult:
        """Analyze a pcap file for network issues."""
        result = AnalysisResult()
        result.file_analyzed = pcap_file

        if not os.path.exists(pcap_file):
            result.error = f"File not found: {pcap_file}"
            return result

        try:
            # Get basic stats
            result.stats = self._get_stats(pcap_file)

            # Run protocol-specific analyzers
            result.issues.extend(self._analyze_l2_issues(pcap_file))
            result.issues.extend(self._analyze_l3_issues(pcap_file))
            result.issues.extend(self._analyze_tcp_issues(pcap_file))
            result.issues.extend(self._analyze_dns_issues(pcap_file))
            result.issues.extend(self._analyze_ssl_issues(pcap_file))
            result.issues.extend(self._analyze_smtp_issues(pcap_file))

            # Build summary
            result.summary = self._build_summary(result)
            result.success = True

        except Exception as e:
            result.error = str(e)

        return result

    def _get_stats(self, pcap_file: str) -> AnalysisStats:
        """Get basic statistics from pcap file."""
        stats = AnalysisStats()

        if self._tshark:
            # Use tshark for detailed stats
            try:
                # Get packet count and protocols
                cmd = [
                    self._tshark, "-r", pcap_file,
                    "-q", "-z", "io,stat,0"
                ]
                result = subprocess.run(cmd, capture_output=True, text=True, timeout=60)

                # Parse total packets
                for line in result.stdout.split("\n"):
                    if "|" in line and "Frames" not in line:
                        parts = line.split("|")
                        if len(parts) >= 3:
                            try:
                                stats.total_packets = int(parts[1].strip())
                                stats.total_bytes = int(parts[2].strip())
                            except ValueError:
                                pass

                # Get protocol breakdown
                cmd = [
                    self._tshark, "-r", pcap_file,
                    "-q", "-z", "io,phs"
                ]
                result = subprocess.run(cmd, capture_output=True, text=True, timeout=60)

                for line in result.stdout.split("\n"):
                    line_lower = line.lower()
                    if "tcp" in line_lower:
                        match = re.search(r'frames:(\d+)', line)
                        if match:
                            stats.tcp_packets = int(match.group(1))
                    elif "udp" in line_lower:
                        match = re.search(r'frames:(\d+)', line)
                        if match:
                            stats.udp_packets = int(match.group(1))
                    elif "icmp" in line_lower:
                        match = re.search(r'frames:(\d+)', line)
                        if match:
                            stats.icmp_packets = int(match.group(1))
                    elif "arp" in line_lower:
                        match = re.search(r'frames:(\d+)', line)
                        if match:
                            stats.arp_packets = int(match.group(1))

                # Get unique IPs and MACs
                cmd = [
                    self._tshark, "-r", pcap_file,
                    "-T", "fields",
                    "-e", "ip.src", "-e", "ip.dst",
                    "-e", "eth.src", "-e", "eth.dst"
                ]
                result = subprocess.run(cmd, capture_output=True, text=True, timeout=60)

                src_ips = set()
                dst_ips = set()
                src_macs = set()
                dst_macs = set()
                conversations = set()

                for line in result.stdout.strip().split("\n"):
                    parts = line.split("\t")
                    if len(parts) >= 4:
                        if parts[0]:
                            src_ips.add(parts[0])
                        if parts[1]:
                            dst_ips.add(parts[1])
                        if parts[2]:
                            src_macs.add(parts[2])
                        if parts[3]:
                            dst_macs.add(parts[3])
                        if parts[0] and parts[1]:
                            conversations.add(tuple(sorted([parts[0], parts[1]])))

                stats.unique_src_ips = len(src_ips)
                stats.unique_dst_ips = len(dst_ips)
                stats.unique_src_macs = len(src_macs)
                stats.unique_dst_macs = len(dst_macs)
                stats.unique_conversations = len(conversations)

            except Exception:
                pass

        elif self._tcpdump:
            # Fallback to tcpdump
            try:
                cmd = [self._tcpdump, "-r", pcap_file, "-n", "-q"]
                result = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
                stats.total_packets = len(result.stdout.strip().split("\n"))
            except Exception:
                pass

        return stats

    def _analyze_l2_issues(self, pcap_file: str) -> list[NetworkIssue]:
        """Analyze Layer 2 issues."""
        issues = []

        if not self._tshark:
            return issues

        try:
            # Check for duplicate MAC addresses on different IPs (IP conflict indicator)
            cmd = [
                self._tshark, "-r", pcap_file,
                "-T", "fields",
                "-e", "eth.src", "-e", "ip.src",
                "-Y", "ip"
            ]
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=60)

            mac_to_ips = defaultdict(set)
            for line in result.stdout.strip().split("\n"):
                parts = line.split("\t")
                if len(parts) >= 2 and parts[0] and parts[1]:
                    mac_to_ips[parts[0]].add(parts[1])

            for mac, ips in mac_to_ips.items():
                if len(ips) > 1:
                    issues.append(NetworkIssue(
                        category=IssueCategory.L2_SWITCHING,
                        severity=IssueSeverity.WARNING,
                        title="Multiple IPs from single MAC",
                        description=f"MAC {mac} is using multiple IPs: {', '.join(ips)}. "
                                    "This could indicate NAT, IP changes, or a misconfiguration.",
                        source_mac=mac,
                        recommendation="Verify if this is expected (e.g., NAT gateway) or investigate for IP conflicts."
                    ))

            # Check for broadcast storms (high broadcast rate)
            cmd = [
                self._tshark, "-r", pcap_file,
                "-Y", "eth.dst == ff:ff:ff:ff:ff:ff",
                "-T", "fields", "-e", "frame.number"
            ]
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
            broadcast_count = len([l for l in result.stdout.strip().split("\n") if l])

            # Get total packet count for comparison
            cmd = [self._tshark, "-r", pcap_file, "-T", "fields", "-e", "frame.number"]
            total_result = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
            total_count = len([l for l in total_result.stdout.strip().split("\n") if l])

            if total_count > 0:
                broadcast_ratio = broadcast_count / total_count
                if broadcast_ratio > 0.3:  # More than 30% broadcast
                    issues.append(NetworkIssue(
                        category=IssueCategory.L2_SWITCHING,
                        severity=IssueSeverity.ERROR,
                        title="Excessive broadcast traffic",
                        description=f"Broadcast traffic is {broadcast_ratio*100:.1f}% of total packets ({broadcast_count}/{total_count}). "
                                    "This may indicate a broadcast storm or loop.",
                        recommendation="Check for network loops, STP issues, or misconfigured devices."
                    ))
                elif broadcast_ratio > 0.1:  # More than 10%
                    issues.append(NetworkIssue(
                        category=IssueCategory.L2_SWITCHING,
                        severity=IssueSeverity.WARNING,
                        title="High broadcast traffic",
                        description=f"Broadcast traffic is {broadcast_ratio*100:.1f}% of total packets.",
                        recommendation="Monitor for potential broadcast storm development."
                    ))

            # Check for ARP anomalies
            cmd = [
                self._tshark, "-r", pcap_file,
                "-Y", "arp",
                "-T", "fields",
                "-e", "arp.opcode", "-e", "arp.src.hw_mac", "-e", "arp.src.proto_ipv4",
                "-e", "arp.dst.proto_ipv4"
            ]
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=60)

            arp_requests = defaultdict(int)
            arp_replies = defaultdict(list)

            for line in result.stdout.strip().split("\n"):
                parts = line.split("\t")
                if len(parts) >= 4:
                    opcode = parts[0]
                    src_mac = parts[1]
                    src_ip = parts[2]
                    target_ip = parts[3]

                    if opcode == "1":  # ARP request
                        arp_requests[target_ip] += 1
                    elif opcode == "2":  # ARP reply
                        if src_ip and src_mac:
                            arp_replies[src_ip].append(src_mac)

            # Check for gratuitous ARP (potential ARP spoofing)
            for ip, macs in arp_replies.items():
                unique_macs = list(set(macs))
                if len(unique_macs) > 1:
                    issues.append(NetworkIssue(
                        category=IssueCategory.SECURITY,
                        severity=IssueSeverity.CRITICAL,
                        title="Possible ARP spoofing detected",
                        description=f"IP {ip} has ARP replies from multiple MACs: {', '.join(unique_macs)}. "
                                    "This may indicate ARP spoofing or a network configuration issue.",
                        source_ip=ip,
                        recommendation="Investigate for ARP spoofing attack or verify network configuration."
                    ))

            # Check for excessive ARP requests (host scanning or dead hosts)
            for target_ip, count in arp_requests.items():
                if count > 10:
                    issues.append(NetworkIssue(
                        category=IssueCategory.L2_SWITCHING,
                        severity=IssueSeverity.INFO,
                        title="Excessive ARP requests",
                        description=f"IP {target_ip} received {count} ARP requests. "
                                    "Host may be down or unreachable at L2.",
                        dest_ip=target_ip,
                        recommendation="Verify host is online and on correct VLAN."
                    ))

            # Check for STP topology changes
            cmd = [
                self._tshark, "-r", pcap_file,
                "-Y", "stp.type == 0x80",  # TCN BPDU
                "-T", "fields", "-e", "frame.number"
            ]
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
            stp_tcn_count = len([l for l in result.stdout.strip().split("\n") if l])

            if stp_tcn_count > 5:
                issues.append(NetworkIssue(
                    category=IssueCategory.L2_SWITCHING,
                    severity=IssueSeverity.WARNING,
                    title="Frequent STP topology changes",
                    description=f"Detected {stp_tcn_count} STP topology change notifications. "
                                "This may indicate network instability.",
                    recommendation="Check for flapping links, port configuration, or STP priority issues."
                ))

        except Exception as e:
            issues.append(NetworkIssue(
                category=IssueCategory.L2_SWITCHING,
                severity=IssueSeverity.INFO,
                title="L2 analysis incomplete",
                description=f"Could not complete L2 analysis: {e}",
            ))

        return issues

    def _analyze_l3_issues(self, pcap_file: str) -> list[NetworkIssue]:
        """Analyze Layer 3 issues."""
        issues = []

        if not self._tshark:
            return issues

        try:
            # Check for ICMP unreachable messages
            cmd = [
                self._tshark, "-r", pcap_file,
                "-Y", "icmp.type == 3",  # Destination Unreachable
                "-T", "fields",
                "-e", "ip.src", "-e", "icmp.code", "-e", "frame.number"
            ]
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=60)

            icmp_codes = {
                "0": "Network unreachable",
                "1": "Host unreachable",
                "2": "Protocol unreachable",
                "3": "Port unreachable",
                "4": "Fragmentation needed",
                "5": "Source route failed",
                "9": "Network administratively prohibited",
                "10": "Host administratively prohibited",
                "13": "Communication administratively prohibited",
            }

            unreachable_counts = defaultdict(lambda: defaultdict(int))
            for line in result.stdout.strip().split("\n"):
                parts = line.split("\t")
                if len(parts) >= 2 and parts[0] and parts[1]:
                    unreachable_counts[parts[1]][parts[0]] += 1

            for code, sources in unreachable_counts.items():
                code_name = icmp_codes.get(code, f"Code {code}")
                total = sum(sources.values())

                severity = IssueSeverity.WARNING
                if code in ("0", "1"):  # Network/Host unreachable
                    severity = IssueSeverity.ERROR

                issues.append(NetworkIssue(
                    category=IssueCategory.L3_ROUTING,
                    severity=severity,
                    title=f"ICMP {code_name}",
                    description=f"Received {total} ICMP '{code_name}' messages from: {', '.join(sources.keys())}",
                    recommendation="Check routing tables, firewall rules, and destination availability."
                ))

            # Check for TTL exceeded (routing loops or distant hosts)
            cmd = [
                self._tshark, "-r", pcap_file,
                "-Y", "icmp.type == 11",  # Time Exceeded
                "-T", "fields",
                "-e", "ip.src", "-e", "frame.number"
            ]
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=60)

            ttl_exceeded_sources = defaultdict(int)
            for line in result.stdout.strip().split("\n"):
                if line:
                    parts = line.split("\t")
                    if parts[0]:
                        ttl_exceeded_sources[parts[0]] += 1

            if len(ttl_exceeded_sources) > 10:
                issues.append(NetworkIssue(
                    category=IssueCategory.L3_ROUTING,
                    severity=IssueSeverity.ERROR,
                    title="Possible routing loop detected",
                    description=f"Received TTL exceeded from {len(ttl_exceeded_sources)} different sources. "
                                "This may indicate a routing loop.",
                    recommendation="Check routing tables for loops, verify OSPF/BGP configuration."
                ))
            elif ttl_exceeded_sources:
                issues.append(NetworkIssue(
                    category=IssueCategory.L3_ROUTING,
                    severity=IssueSeverity.INFO,
                    title="TTL exceeded messages",
                    description=f"Received TTL exceeded from {len(ttl_exceeded_sources)} sources. "
                                "This is normal for traceroute but may indicate routing issues if unexpected.",
                ))

            # Check for fragmentation issues
            cmd = [
                self._tshark, "-r", pcap_file,
                "-Y", "ip.flags.mf == 1 or ip.frag_offset > 0",
                "-T", "fields", "-e", "frame.number"
            ]
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
            frag_count = len([l for l in result.stdout.strip().split("\n") if l])

            if frag_count > 100:
                issues.append(NetworkIssue(
                    category=IssueCategory.L3_ROUTING,
                    severity=IssueSeverity.WARNING,
                    title="High IP fragmentation",
                    description=f"Detected {frag_count} fragmented packets. "
                                "This may indicate MTU mismatch or path MTU issues.",
                    recommendation="Consider enabling Path MTU Discovery or adjusting MTU settings."
                ))

            # Check for IP options (unusual and potentially problematic)
            cmd = [
                self._tshark, "-r", pcap_file,
                "-Y", "ip.opt.type",
                "-T", "fields", "-e", "ip.src", "-e", "ip.opt.type"
            ]
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=60)

            if result.stdout.strip():
                issues.append(NetworkIssue(
                    category=IssueCategory.L3_ROUTING,
                    severity=IssueSeverity.INFO,
                    title="IP options detected",
                    description="Packets with IP options were detected. These may be dropped by some routers/firewalls.",
                    recommendation="Verify IP options are required and not being filtered."
                ))

        except Exception as e:
            issues.append(NetworkIssue(
                category=IssueCategory.L3_ROUTING,
                severity=IssueSeverity.INFO,
                title="L3 analysis incomplete",
                description=f"Could not complete L3 analysis: {e}",
            ))

        return issues

    def _analyze_tcp_issues(self, pcap_file: str) -> list[NetworkIssue]:
        """Analyze TCP issues."""
        issues = []

        if not self._tshark:
            return issues

        try:
            # Check for TCP retransmissions
            cmd = [
                self._tshark, "-r", pcap_file,
                "-Y", "tcp.analysis.retransmission",
                "-T", "fields", "-e", "frame.number"
            ]
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
            retrans_count = len([l for l in result.stdout.strip().split("\n") if l])

            # Get total TCP packets
            cmd = [
                self._tshark, "-r", pcap_file,
                "-Y", "tcp",
                "-T", "fields", "-e", "frame.number"
            ]
            total_result = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
            total_tcp = len([l for l in total_result.stdout.strip().split("\n") if l])

            if total_tcp > 0:
                retrans_rate = retrans_count / total_tcp
                if retrans_rate > 0.05:  # More than 5%
                    issues.append(NetworkIssue(
                        category=IssueCategory.TCP,
                        severity=IssueSeverity.ERROR,
                        title="High TCP retransmission rate",
                        description=f"TCP retransmission rate is {retrans_rate*100:.2f}% ({retrans_count}/{total_tcp}). "
                                    "This indicates significant packet loss.",
                        recommendation="Check for network congestion, lossy links, or buffer issues."
                    ))
                elif retrans_rate > 0.01:  # More than 1%
                    issues.append(NetworkIssue(
                        category=IssueCategory.TCP,
                        severity=IssueSeverity.WARNING,
                        title="Elevated TCP retransmission rate",
                        description=f"TCP retransmission rate is {retrans_rate*100:.2f}%.",
                        recommendation="Monitor for increasing packet loss."
                    ))

            # Check for RST floods
            cmd = [
                self._tshark, "-r", pcap_file,
                "-Y", "tcp.flags.reset == 1",
                "-T", "fields", "-e", "ip.src", "-e", "ip.dst"
            ]
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
            rst_count = len([l for l in result.stdout.strip().split("\n") if l])

            if rst_count > 100:
                issues.append(NetworkIssue(
                    category=IssueCategory.TCP,
                    severity=IssueSeverity.WARNING,
                    title="High RST count",
                    description=f"Detected {rst_count} TCP RST packets. "
                                "This may indicate connection issues, port scanning, or application problems.",
                    recommendation="Investigate source of RST packets and verify service availability."
                ))

            # Check for zero window (flow control issues)
            cmd = [
                self._tshark, "-r", pcap_file,
                "-Y", "tcp.analysis.zero_window",
                "-T", "fields", "-e", "ip.src", "-e", "frame.number"
            ]
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=60)

            zero_window_sources = defaultdict(int)
            for line in result.stdout.strip().split("\n"):
                if line:
                    parts = line.split("\t")
                    if parts[0]:
                        zero_window_sources[parts[0]] += 1

            if zero_window_sources:
                total_zw = sum(zero_window_sources.values())
                issues.append(NetworkIssue(
                    category=IssueCategory.TCP,
                    severity=IssueSeverity.WARNING,
                    title="TCP zero window detected",
                    description=f"Detected {total_zw} zero window conditions from {len(zero_window_sources)} hosts. "
                                "Receivers cannot keep up with data rate.",
                    recommendation="Check receiver application performance and buffer sizes."
                ))

            # Check for duplicate ACKs (potential packet loss)
            cmd = [
                self._tshark, "-r", pcap_file,
                "-Y", "tcp.analysis.duplicate_ack",
                "-T", "fields", "-e", "frame.number"
            ]
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
            dup_ack_count = len([l for l in result.stdout.strip().split("\n") if l])

            if dup_ack_count > 50:
                issues.append(NetworkIssue(
                    category=IssueCategory.TCP,
                    severity=IssueSeverity.INFO,
                    title="Duplicate ACKs detected",
                    description=f"Detected {dup_ack_count} duplicate ACKs. This indicates packet loss or reordering.",
                    recommendation="May be normal during fast retransmit; investigate if accompanied by other issues."
                ))

            # Check for out-of-order packets
            cmd = [
                self._tshark, "-r", pcap_file,
                "-Y", "tcp.analysis.out_of_order",
                "-T", "fields", "-e", "frame.number"
            ]
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
            ooo_count = len([l for l in result.stdout.strip().split("\n") if l])

            if ooo_count > 50:
                issues.append(NetworkIssue(
                    category=IssueCategory.TCP,
                    severity=IssueSeverity.WARNING,
                    title="Out-of-order packets",
                    description=f"Detected {ooo_count} out-of-order TCP packets. "
                                "This may indicate load balancing issues or path asymmetry.",
                    recommendation="Check for ECMP/load balancing configuration or asymmetric routing."
                ))

        except Exception as e:
            issues.append(NetworkIssue(
                category=IssueCategory.TCP,
                severity=IssueSeverity.INFO,
                title="TCP analysis incomplete",
                description=f"Could not complete TCP analysis: {e}",
            ))

        return issues

    def _analyze_dns_issues(self, pcap_file: str) -> list[NetworkIssue]:
        """Analyze DNS issues."""
        issues = []

        if not self._tshark:
            return issues

        try:
            # Check for DNS errors
            cmd = [
                self._tshark, "-r", pcap_file,
                "-Y", "dns.flags.rcode != 0",
                "-T", "fields",
                "-e", "dns.qry.name", "-e", "dns.flags.rcode", "-e", "ip.src"
            ]
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=60)

            dns_errors = defaultdict(lambda: defaultdict(int))
            rcode_names = {
                "1": "Format Error",
                "2": "Server Failure",
                "3": "NXDOMAIN",
                "4": "Not Implemented",
                "5": "Refused",
            }

            for line in result.stdout.strip().split("\n"):
                parts = line.split("\t")
                if len(parts) >= 3:
                    query_name = parts[0]
                    rcode = parts[1]
                    if rcode and rcode != "0":
                        dns_errors[rcode][query_name] += 1

            for rcode, queries in dns_errors.items():
                rcode_name = rcode_names.get(rcode, f"Code {rcode}")
                total = sum(queries.values())
                top_queries = sorted(queries.items(), key=lambda x: -x[1])[:5]

                severity = IssueSeverity.INFO
                if rcode == "2":  # SERVFAIL
                    severity = IssueSeverity.ERROR
                elif rcode == "5":  # Refused
                    severity = IssueSeverity.WARNING

                issues.append(NetworkIssue(
                    category=IssueCategory.DNS,
                    severity=severity,
                    title=f"DNS {rcode_name} responses",
                    description=f"Received {total} DNS {rcode_name} responses. "
                                f"Top queries: {', '.join(f'{q[0]}({q[1]})' for q in top_queries)}",
                    recommendation="Verify DNS server configuration and query validity."
                ))

            # Check for slow DNS responses
            cmd = [
                self._tshark, "-r", pcap_file,
                "-Y", "dns.response_to",
                "-T", "fields",
                "-e", "dns.time"
            ]
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=60)

            dns_times = []
            for line in result.stdout.strip().split("\n"):
                if line:
                    try:
                        dns_times.append(float(line))
                    except ValueError:
                        pass

            if dns_times:
                avg_time = sum(dns_times) / len(dns_times)
                max_time = max(dns_times)
                slow_count = sum(1 for t in dns_times if t > 0.5)

                if avg_time > 0.5:
                    issues.append(NetworkIssue(
                        category=IssueCategory.DNS,
                        severity=IssueSeverity.WARNING,
                        title="Slow DNS responses",
                        description=f"Average DNS response time is {avg_time*1000:.0f}ms (max: {max_time*1000:.0f}ms). "
                                    f"{slow_count} queries took >500ms.",
                        recommendation="Check DNS server performance, network latency, or consider closer DNS servers."
                    ))

            # Check for DNS truncation (TC flag)
            cmd = [
                self._tshark, "-r", pcap_file,
                "-Y", "dns.flags.truncated == 1",
                "-T", "fields", "-e", "frame.number"
            ]
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
            truncated_count = len([l for l in result.stdout.strip().split("\n") if l])

            if truncated_count > 0:
                issues.append(NetworkIssue(
                    category=IssueCategory.DNS,
                    severity=IssueSeverity.INFO,
                    title="DNS truncation detected",
                    description=f"Detected {truncated_count} truncated DNS responses. "
                                "Clients should retry over TCP.",
                    recommendation="Verify DNS over TCP is working if large responses are expected."
                ))

        except Exception as e:
            issues.append(NetworkIssue(
                category=IssueCategory.DNS,
                severity=IssueSeverity.INFO,
                title="DNS analysis incomplete",
                description=f"Could not complete DNS analysis: {e}",
            ))

        return issues

    def _analyze_ssl_issues(self, pcap_file: str) -> list[NetworkIssue]:
        """Analyze SSL/TLS issues."""
        issues = []

        if not self._tshark:
            return issues

        try:
            # Check for SSL/TLS handshake failures
            cmd = [
                self._tshark, "-r", pcap_file,
                "-Y", "tls.alert_message",
                "-T", "fields",
                "-e", "ip.src", "-e", "ip.dst",
                "-e", "tls.alert_message.level", "-e", "tls.alert_message.desc"
            ]
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=60)

            alert_desc_names = {
                "0": "close_notify",
                "10": "unexpected_message",
                "20": "bad_record_mac",
                "21": "decryption_failed",
                "22": "record_overflow",
                "30": "decompression_failure",
                "40": "handshake_failure",
                "42": "bad_certificate",
                "43": "unsupported_certificate",
                "44": "certificate_revoked",
                "45": "certificate_expired",
                "46": "certificate_unknown",
                "47": "illegal_parameter",
                "48": "unknown_ca",
                "49": "access_denied",
                "50": "decode_error",
                "51": "decrypt_error",
                "70": "protocol_version",
                "71": "insufficient_security",
                "80": "internal_error",
                "86": "inappropriate_fallback",
                "90": "user_canceled",
                "100": "no_renegotiation",
                "110": "unsupported_extension",
                "112": "unrecognized_name",
            }

            alerts = defaultdict(int)
            for line in result.stdout.strip().split("\n"):
                parts = line.split("\t")
                if len(parts) >= 4:
                    level = parts[2]
                    desc = parts[3]
                    alert_name = alert_desc_names.get(desc, f"Unknown({desc})")
                    severity_str = "fatal" if level == "2" else "warning"
                    alerts[f"{alert_name} ({severity_str})"] += 1

            for alert, count in alerts.items():
                severity = IssueSeverity.ERROR if "fatal" in alert else IssueSeverity.WARNING
                issues.append(NetworkIssue(
                    category=IssueCategory.SSL_TLS,
                    severity=severity,
                    title=f"TLS Alert: {alert}",
                    description=f"Detected {count} TLS '{alert}' alerts.",
                    recommendation="Check certificate validity, TLS version compatibility, and cipher suite support."
                ))

            # Check for deprecated TLS versions
            cmd = [
                self._tshark, "-r", pcap_file,
                "-Y", "tls.handshake.type == 1",  # Client Hello
                "-T", "fields",
                "-e", "tls.handshake.version"
            ]
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=60)

            version_names = {
                "0x0300": "SSL 3.0",
                "0x0301": "TLS 1.0",
                "0x0302": "TLS 1.1",
                "0x0303": "TLS 1.2",
                "0x0304": "TLS 1.3",
            }

            deprecated_versions = {"0x0300", "0x0301", "0x0302"}
            version_counts = defaultdict(int)

            for line in result.stdout.strip().split("\n"):
                if line:
                    version_counts[line] += 1

            for version, count in version_counts.items():
                if version in deprecated_versions:
                    version_name = version_names.get(version, version)
                    issues.append(NetworkIssue(
                        category=IssueCategory.SSL_TLS,
                        severity=IssueSeverity.WARNING,
                        title=f"Deprecated TLS version: {version_name}",
                        description=f"Detected {count} connections using deprecated {version_name}.",
                        recommendation="Upgrade to TLS 1.2 or TLS 1.3."
                    ))

            # Check for certificate issues
            cmd = [
                self._tshark, "-r", pcap_file,
                "-Y", "tls.handshake.type == 11",  # Certificate
                "-T", "fields",
                "-e", "x509sat.CountryName",
                "-e", "x509sat.organizationName",
                "-e", "x509ce.dNSName"
            ]
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
            # Just checking if certificates are present

        except Exception as e:
            issues.append(NetworkIssue(
                category=IssueCategory.SSL_TLS,
                severity=IssueSeverity.INFO,
                title="SSL/TLS analysis incomplete",
                description=f"Could not complete SSL/TLS analysis: {e}",
            ))

        return issues

    def _analyze_smtp_issues(self, pcap_file: str) -> list[NetworkIssue]:
        """Analyze SMTP/Email issues."""
        issues = []

        if not self._tshark:
            return issues

        try:
            # Check for SMTP error responses
            cmd = [
                self._tshark, "-r", pcap_file,
                "-Y", "smtp.response.code >= 400",
                "-T", "fields",
                "-e", "smtp.response.code", "-e", "ip.src"
            ]
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=60)

            smtp_errors = defaultdict(int)
            for line in result.stdout.strip().split("\n"):
                parts = line.split("\t")
                if parts and parts[0]:
                    smtp_errors[parts[0]] += 1

            smtp_error_meanings = {
                "421": "Service not available",
                "450": "Mailbox unavailable",
                "451": "Local error in processing",
                "452": "Insufficient storage",
                "500": "Syntax error",
                "501": "Syntax error in parameters",
                "502": "Command not implemented",
                "503": "Bad sequence of commands",
                "504": "Parameter not implemented",
                "550": "Mailbox unavailable/rejected",
                "551": "User not local",
                "552": "Message size exceeded",
                "553": "Mailbox name invalid",
                "554": "Transaction failed",
            }

            for code, count in smtp_errors.items():
                meaning = smtp_error_meanings.get(code, "Unknown error")
                severity = IssueSeverity.ERROR if code.startswith("5") else IssueSeverity.WARNING

                issues.append(NetworkIssue(
                    category=IssueCategory.SMTP,
                    severity=severity,
                    title=f"SMTP {code}: {meaning}",
                    description=f"Received {count} SMTP '{code} {meaning}' responses.",
                    recommendation="Check mail server configuration, authentication, and recipient addresses."
                ))

            # Check for STARTTLS usage
            cmd = [
                self._tshark, "-r", pcap_file,
                "-Y", "smtp.req.command == \"STARTTLS\" or smtp.response.code == 220",
                "-T", "fields", "-e", "frame.number"
            ]
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=60)

            # Check for cleartext auth (AUTH without prior STARTTLS)
            # This is a simplified check
            cmd = [
                self._tshark, "-r", pcap_file,
                "-Y", "smtp.req.command == \"AUTH\"",
                "-T", "fields", "-e", "frame.number", "-e", "tcp.stream"
            ]
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=60)

            if result.stdout.strip():
                auth_count = len([l for l in result.stdout.strip().split("\n") if l])
                issues.append(NetworkIssue(
                    category=IssueCategory.SMTP,
                    severity=IssueSeverity.INFO,
                    title="SMTP AUTH detected",
                    description=f"Detected {auth_count} SMTP authentication attempts. "
                                "Verify STARTTLS is used before authentication.",
                    recommendation="Ensure SMTP connections use STARTTLS before AUTH for security."
                ))

        except Exception as e:
            issues.append(NetworkIssue(
                category=IssueCategory.SMTP,
                severity=IssueSeverity.INFO,
                title="SMTP analysis incomplete",
                description=f"Could not complete SMTP analysis: {e}",
            ))

        return issues

    def _build_summary(self, result: AnalysisResult) -> dict[str, Any]:
        """Build analysis summary."""
        summary = {
            "total_issues": len(result.issues),
            "critical": len(result.critical_issues),
            "errors": len(result.error_issues),
            "warnings": len(result.warning_issues),
            "by_category": defaultdict(int),
            "recommendations": [],
        }

        for issue in result.issues:
            summary["by_category"][issue.category.value] += 1
            if issue.recommendation:
                summary["recommendations"].append(issue.recommendation)

        summary["by_category"] = dict(summary["by_category"])
        summary["recommendations"] = list(set(summary["recommendations"]))[:10]

        return summary
