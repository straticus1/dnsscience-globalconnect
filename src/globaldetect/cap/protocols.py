"""
Protocol-specific analyzers for packet capture.

Copyright (c) 2025 DNS Science.io, an After Dark Systems, LLC company.
All rights reserved.
"""

import os
import subprocess
import re
from dataclasses import dataclass, field
from typing import Any
from collections import defaultdict

from globaldetect.cap.analyzer import (
    NetworkIssue,
    IssueSeverity,
    IssueCategory,
)


def _find_tshark() -> str | None:
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


@dataclass
class DNSQueryInfo:
    """Information about a DNS query."""
    query_name: str
    query_type: str
    response_code: str | None = None
    response_time_ms: float | None = None
    answers: list[str] = field(default_factory=list)
    server_ip: str | None = None
    client_ip: str | None = None


@dataclass
class SMTPTransaction:
    """Information about an SMTP transaction."""
    client_ip: str
    server_ip: str
    ehlo_domain: str | None = None
    mail_from: str | None = None
    rcpt_to: list[str] = field(default_factory=list)
    response_codes: list[str] = field(default_factory=list)
    uses_tls: bool = False
    uses_auth: bool = False


@dataclass
class SSLHandshake:
    """Information about an SSL/TLS handshake."""
    client_ip: str
    server_ip: str
    server_name: str | None = None
    tls_version: str | None = None
    cipher_suite: str | None = None
    certificate_cn: str | None = None
    certificate_issuer: str | None = None
    certificate_valid: bool = True
    handshake_time_ms: float | None = None


class DNSAnalyzer:
    """Detailed DNS traffic analysis."""

    def __init__(self):
        self._tshark = _find_tshark()

    def analyze(self, pcap_file: str) -> dict[str, Any]:
        """Analyze DNS traffic in detail."""
        result = {
            "queries": [],
            "issues": [],
            "stats": {
                "total_queries": 0,
                "total_responses": 0,
                "unique_domains": 0,
                "query_types": {},
                "response_codes": {},
                "avg_response_time_ms": 0,
                "slow_queries": 0,
            }
        }

        if not self._tshark or not os.path.exists(pcap_file):
            return result

        try:
            # Get DNS queries and responses
            cmd = [
                self._tshark, "-r", pcap_file,
                "-Y", "dns",
                "-T", "fields",
                "-e", "frame.number",
                "-e", "ip.src", "-e", "ip.dst",
                "-e", "dns.flags.response",
                "-e", "dns.qry.name", "-e", "dns.qry.type",
                "-e", "dns.flags.rcode",
                "-e", "dns.time",
                "-e", "dns.a", "-e", "dns.aaaa", "-e", "dns.cname", "-e", "dns.mx.mail_exchange"
            ]
            proc = subprocess.run(cmd, capture_output=True, text=True, timeout=120)

            domains = set()
            query_types = defaultdict(int)
            response_codes = defaultdict(int)
            response_times = []

            for line in proc.stdout.strip().split("\n"):
                if not line:
                    continue

                parts = line.split("\t")
                if len(parts) < 8:
                    continue

                is_response = parts[3] == "1"
                query_name = parts[4]
                query_type = parts[5]
                rcode = parts[6]
                dns_time = parts[7]

                if query_name:
                    domains.add(query_name)

                if query_type:
                    type_name = self._query_type_name(query_type)
                    query_types[type_name] += 1

                if is_response:
                    result["stats"]["total_responses"] += 1
                    if rcode:
                        rcode_name = self._rcode_name(rcode)
                        response_codes[rcode_name] += 1

                    if dns_time:
                        try:
                            time_ms = float(dns_time) * 1000
                            response_times.append(time_ms)
                            if time_ms > 500:
                                result["stats"]["slow_queries"] += 1
                        except ValueError:
                            pass
                else:
                    result["stats"]["total_queries"] += 1

            result["stats"]["unique_domains"] = len(domains)
            result["stats"]["query_types"] = dict(query_types)
            result["stats"]["response_codes"] = dict(response_codes)

            if response_times:
                result["stats"]["avg_response_time_ms"] = sum(response_times) / len(response_times)

            # Check with DNS Science.io for threat intel on queried domains
            result["issues"].extend(self._check_dnsscience_threats(list(domains)[:100]))

        except Exception as e:
            result["issues"].append(NetworkIssue(
                category=IssueCategory.DNS,
                severity=IssueSeverity.INFO,
                title="DNS analysis error",
                description=str(e),
            ))

        return result

    def _query_type_name(self, qtype: str) -> str:
        """Convert numeric query type to name."""
        types = {
            "1": "A", "2": "NS", "5": "CNAME", "6": "SOA",
            "12": "PTR", "15": "MX", "16": "TXT", "28": "AAAA",
            "33": "SRV", "35": "NAPTR", "43": "DS", "46": "RRSIG",
            "47": "NSEC", "48": "DNSKEY", "52": "TLSA", "65": "HTTPS",
            "255": "ANY", "256": "URI", "257": "CAA",
        }
        return types.get(qtype, f"TYPE{qtype}")

    def _rcode_name(self, rcode: str) -> str:
        """Convert numeric rcode to name."""
        codes = {
            "0": "NOERROR", "1": "FORMERR", "2": "SERVFAIL",
            "3": "NXDOMAIN", "4": "NOTIMP", "5": "REFUSED",
            "6": "YXDOMAIN", "7": "YXRRSET", "8": "NXRRSET",
            "9": "NOTAUTH", "10": "NOTZONE",
        }
        return codes.get(rcode, f"RCODE{rcode}")

    def _check_dnsscience_threats(self, domains: list[str]) -> list[NetworkIssue]:
        """Check domains against DNS Science.io threat intel."""
        issues = []

        try:
            from globaldetect.services.dnsscience import DNSScienceClient
            from globaldetect.config import get_config

            config = get_config()
            if not config.dnsscience_api_key:
                return issues

            client = DNSScienceClient()

            # Check a sample of domains for threats
            for domain in domains[:20]:  # Limit to avoid rate limits
                try:
                    result = client.get_threat_intel(domain)
                    if result and not result.error:
                        if result.is_malicious:
                            issues.append(NetworkIssue(
                                category=IssueCategory.SECURITY,
                                severity=IssueSeverity.CRITICAL,
                                title=f"Malicious domain detected: {domain}",
                                description=f"DNS Science.io flagged {domain} as malicious. "
                                            f"Categories: {', '.join(result.categories or ['Unknown'])}",
                                recommendation="Block this domain and investigate affected hosts."
                            ))
                        elif result.risk_score and result.risk_score > 50:
                            issues.append(NetworkIssue(
                                category=IssueCategory.SECURITY,
                                severity=IssueSeverity.WARNING,
                                title=f"Suspicious domain: {domain}",
                                description=f"DNS Science.io risk score: {result.risk_score}/100",
                                recommendation="Monitor traffic to this domain."
                            ))
                except Exception:
                    pass

        except ImportError:
            pass
        except Exception:
            pass

        return issues


class SMTPAnalyzer:
    """Detailed SMTP/Email traffic analysis."""

    def __init__(self):
        self._tshark = _find_tshark()

    def analyze(self, pcap_file: str) -> dict[str, Any]:
        """Analyze SMTP traffic in detail."""
        result = {
            "transactions": [],
            "issues": [],
            "stats": {
                "total_connections": 0,
                "successful_deliveries": 0,
                "failed_deliveries": 0,
                "tls_connections": 0,
                "auth_attempts": 0,
                "unique_senders": 0,
                "unique_recipients": 0,
            }
        }

        if not self._tshark or not os.path.exists(pcap_file):
            return result

        try:
            # Get SMTP commands and responses
            cmd = [
                self._tshark, "-r", pcap_file,
                "-Y", "smtp",
                "-T", "fields",
                "-e", "tcp.stream",
                "-e", "ip.src", "-e", "ip.dst",
                "-e", "smtp.req.command",
                "-e", "smtp.req.parameter",
                "-e", "smtp.response.code"
            ]
            proc = subprocess.run(cmd, capture_output=True, text=True, timeout=120)

            streams = defaultdict(lambda: {
                "commands": [], "responses": [], "src": None, "dst": None
            })
            senders = set()
            recipients = set()

            for line in proc.stdout.strip().split("\n"):
                if not line:
                    continue

                parts = line.split("\t")
                if len(parts) < 6:
                    continue

                stream_id = parts[0]
                src_ip = parts[1]
                dst_ip = parts[2]
                command = parts[3]
                parameter = parts[4]
                response_code = parts[5]

                streams[stream_id]["src"] = src_ip
                streams[stream_id]["dst"] = dst_ip

                if command:
                    streams[stream_id]["commands"].append((command, parameter))
                    if command == "MAIL" and parameter:
                        # Extract email from MAIL FROM
                        match = re.search(r'<([^>]+)>', parameter)
                        if match:
                            senders.add(match.group(1))
                    elif command == "RCPT" and parameter:
                        match = re.search(r'<([^>]+)>', parameter)
                        if match:
                            recipients.add(match.group(1))
                    elif command == "STARTTLS":
                        result["stats"]["tls_connections"] += 1
                    elif command == "AUTH":
                        result["stats"]["auth_attempts"] += 1

                if response_code:
                    streams[stream_id]["responses"].append(response_code)
                    if response_code.startswith("2"):
                        if response_code == "250":
                            pass  # Normal OK
                    elif response_code.startswith("5"):
                        result["stats"]["failed_deliveries"] += 1

            result["stats"]["total_connections"] = len(streams)
            result["stats"]["unique_senders"] = len(senders)
            result["stats"]["unique_recipients"] = len(recipients)

            # Check sender reputation via DNS Science.io
            result["issues"].extend(self._check_sender_reputation(list(senders)[:20]))

        except Exception as e:
            result["issues"].append(NetworkIssue(
                category=IssueCategory.SMTP,
                severity=IssueSeverity.INFO,
                title="SMTP analysis error",
                description=str(e),
            ))

        return result

    def _check_sender_reputation(self, senders: list[str]) -> list[NetworkIssue]:
        """Check sender domains via DNS Science.io."""
        issues = []

        try:
            from globaldetect.services.dnsscience import DNSScienceClient
            from globaldetect.config import get_config

            config = get_config()
            if not config.dnsscience_api_key:
                return issues

            client = DNSScienceClient()

            for sender in senders:
                try:
                    # Extract domain from email
                    if "@" in sender:
                        domain = sender.split("@")[1]
                    else:
                        continue

                    result = client.check_email_security(domain)
                    if result and not result.error:
                        problems = []
                        if not result.has_spf:
                            problems.append("No SPF record")
                        if not result.has_dkim:
                            problems.append("No DKIM")
                        if not result.has_dmarc:
                            problems.append("No DMARC")

                        if problems:
                            issues.append(NetworkIssue(
                                category=IssueCategory.SMTP,
                                severity=IssueSeverity.WARNING,
                                title=f"Email security issues: {domain}",
                                description=f"Sender domain {domain} has issues: {', '.join(problems)}",
                                recommendation="Verify sender legitimacy and email security configuration."
                            ))
                except Exception:
                    pass

        except ImportError:
            pass
        except Exception:
            pass

        return issues


class SSLAnalyzer:
    """Detailed SSL/TLS traffic analysis."""

    def __init__(self):
        self._tshark = _find_tshark()

    def analyze(self, pcap_file: str) -> dict[str, Any]:
        """Analyze SSL/TLS traffic in detail."""
        result = {
            "handshakes": [],
            "issues": [],
            "stats": {
                "total_connections": 0,
                "tls_versions": {},
                "cipher_suites": {},
                "certificates_seen": 0,
                "handshake_failures": 0,
                "deprecated_protocols": 0,
            }
        }

        if not self._tshark or not os.path.exists(pcap_file):
            return result

        try:
            # Get TLS handshake info
            cmd = [
                self._tshark, "-r", pcap_file,
                "-Y", "tls.handshake",
                "-T", "fields",
                "-e", "tcp.stream",
                "-e", "ip.src", "-e", "ip.dst",
                "-e", "tls.handshake.type",
                "-e", "tls.handshake.version",
                "-e", "tls.handshake.extensions_server_name",
                "-e", "tls.handshake.ciphersuite"
            ]
            proc = subprocess.run(cmd, capture_output=True, text=True, timeout=120)

            streams = set()
            tls_versions = defaultdict(int)
            cipher_suites = defaultdict(int)
            deprecated = {"0x0300", "0x0301", "0x0302"}  # SSL3, TLS1.0, TLS1.1

            version_names = {
                "0x0300": "SSL 3.0",
                "0x0301": "TLS 1.0",
                "0x0302": "TLS 1.1",
                "0x0303": "TLS 1.2",
                "0x0304": "TLS 1.3",
            }

            for line in proc.stdout.strip().split("\n"):
                if not line:
                    continue

                parts = line.split("\t")
                if len(parts) < 7:
                    continue

                stream_id = parts[0]
                streams.add(stream_id)

                version = parts[4]
                cipher = parts[6]

                if version:
                    version_name = version_names.get(version, version)
                    tls_versions[version_name] += 1
                    if version in deprecated:
                        result["stats"]["deprecated_protocols"] += 1

                if cipher:
                    cipher_suites[cipher] += 1

            result["stats"]["total_connections"] = len(streams)
            result["stats"]["tls_versions"] = dict(tls_versions)
            result["stats"]["cipher_suites"] = dict(list(cipher_suites.items())[:20])

            # Check for weak cipher suites
            weak_ciphers = [
                "RC4", "DES", "3DES", "MD5", "NULL", "EXPORT", "anon"
            ]

            for cipher, count in cipher_suites.items():
                cipher_upper = cipher.upper()
                for weak in weak_ciphers:
                    if weak in cipher_upper:
                        result["issues"].append(NetworkIssue(
                            category=IssueCategory.SSL_TLS,
                            severity=IssueSeverity.ERROR,
                            title=f"Weak cipher suite detected",
                            description=f"Cipher suite {cipher} used {count} times. Contains weak algorithm: {weak}",
                            recommendation="Disable weak cipher suites on servers."
                        ))
                        break

        except Exception as e:
            result["issues"].append(NetworkIssue(
                category=IssueCategory.SSL_TLS,
                severity=IssueSeverity.INFO,
                title="SSL/TLS analysis error",
                description=str(e),
            ))

        return result
