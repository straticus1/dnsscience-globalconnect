"""
SSL/TLS Certificate and Cipher Analysis.

Copyright (c) 2025 DNS Science.io, an After Dark Systems, LLC company.
All rights reserved.
"""

import asyncio
import socket
import ssl
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any


@dataclass
class CipherInfo:
    """Information about a TLS cipher."""
    name: str
    protocol: str
    bits: int
    is_secure: bool = True
    grade: str = "A"  # A, B, C, F


@dataclass
class CertificateInfo:
    """SSL/TLS certificate information."""
    host: str
    port: int = 443
    is_valid: bool = False
    issuer: dict[str, str] = field(default_factory=dict)
    subject: dict[str, str] = field(default_factory=dict)
    san: list[str] = field(default_factory=list)  # Subject Alternative Names
    serial_number: str | None = None
    version: int = 0
    not_before: datetime | None = None
    not_after: datetime | None = None
    days_remaining: int = 0
    signature_algorithm: str | None = None
    public_key_type: str | None = None
    public_key_bits: int = 0
    is_self_signed: bool = False
    is_expired: bool = False
    is_wildcard: bool = False
    chain_length: int = 0
    cipher_name: str | None = None
    protocol_version: str | None = None
    ocsp_uri: str | None = None
    crl_uri: str | None = None
    error: str | None = None


# Weak ciphers that should be flagged
WEAK_CIPHERS = [
    "RC4",
    "DES",
    "3DES",
    "MD5",
    "NULL",
    "EXPORT",
    "anon",
]

# Preferred TLS protocols
PREFERRED_PROTOCOLS = ["TLSv1.3", "TLSv1.2"]
DEPRECATED_PROTOCOLS = ["SSLv2", "SSLv3", "TLSv1.0", "TLSv1.1"]


class SSLAnalyzer:
    """Analyze SSL/TLS configuration of a host."""

    def __init__(self, timeout: float = 10.0):
        self.timeout = timeout

    async def analyze_async(self, host: str, port: int = 443) -> CertificateInfo:
        """Analyze SSL/TLS certificate and configuration."""
        result = CertificateInfo(host=host, port=port)

        try:
            # Create SSL context
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE  # We want to analyze even invalid certs

            # Connect and get certificate
            loop = asyncio.get_event_loop()

            def get_cert_info():
                with socket.create_connection((host, port), timeout=self.timeout) as sock:
                    with context.wrap_socket(sock, server_hostname=host) as ssock:
                        cert = ssock.getpeercert(binary_form=True)
                        cert_dict = ssock.getpeercert()
                        cipher = ssock.cipher()
                        version = ssock.version()
                        return cert, cert_dict, cipher, version

            cert_binary, cert_dict, cipher, version = await loop.run_in_executor(
                None, get_cert_info
            )

            # Parse certificate details
            if cert_dict:
                result.is_valid = True

                # Subject
                for item in cert_dict.get("subject", ()):
                    for key, value in item:
                        result.subject[key] = value

                # Issuer
                for item in cert_dict.get("issuer", ()):
                    for key, value in item:
                        result.issuer[key] = value

                # Check if self-signed
                result.is_self_signed = result.subject == result.issuer

                # Subject Alternative Names
                for san_type, san_value in cert_dict.get("subjectAltName", ()):
                    if san_type == "DNS":
                        result.san.append(san_value)
                        if san_value.startswith("*."):
                            result.is_wildcard = True

                # Dates
                not_before = cert_dict.get("notBefore")
                not_after = cert_dict.get("notAfter")

                if not_before:
                    result.not_before = datetime.strptime(
                        not_before, "%b %d %H:%M:%S %Y %Z"
                    )
                if not_after:
                    result.not_after = datetime.strptime(
                        not_after, "%b %d %H:%M:%S %Y %Z"
                    )
                    result.days_remaining = (result.not_after - datetime.utcnow()).days
                    result.is_expired = result.days_remaining < 0

                # Serial number
                result.serial_number = str(cert_dict.get("serialNumber", ""))

                # Version
                result.version = cert_dict.get("version", 0)

                # OCSP and CRL
                for ext in cert_dict.get("OCSP", ()):
                    result.ocsp_uri = ext

                for ext in cert_dict.get("crlDistributionPoints", ()):
                    result.crl_uri = ext

            # Cipher info
            if cipher:
                result.cipher_name = cipher[0]
                result.protocol_version = version

        except ssl.SSLError as e:
            result.error = f"SSL Error: {e}"
        except socket.timeout:
            result.error = "Connection timeout"
        except socket.gaierror as e:
            result.error = f"DNS resolution failed: {e}"
        except ConnectionRefusedError:
            result.error = "Connection refused"
        except Exception as e:
            result.error = str(e)

        return result

    def analyze(self, host: str, port: int = 443) -> CertificateInfo:
        """Synchronous certificate analysis."""
        return asyncio.run(self.analyze_async(host, port))

    async def check_protocols_async(self, host: str, port: int = 443) -> dict[str, bool]:
        """Check which TLS/SSL protocols are supported."""
        results = {}

        protocols = [
            ("SSLv3", ssl.PROTOCOL_SSLv23),
            ("TLSv1.0", ssl.PROTOCOL_TLSv1 if hasattr(ssl, "PROTOCOL_TLSv1") else None),
            ("TLSv1.1", ssl.PROTOCOL_TLSv1_1 if hasattr(ssl, "PROTOCOL_TLSv1_1") else None),
            ("TLSv1.2", ssl.PROTOCOL_TLSv1_2 if hasattr(ssl, "PROTOCOL_TLSv1_2") else None),
        ]

        for proto_name, proto_const in protocols:
            if proto_const is None:
                results[proto_name] = False
                continue

            try:
                context = ssl.SSLContext(proto_const)
                context.check_hostname = False
                context.verify_mode = ssl.CERT_NONE

                loop = asyncio.get_event_loop()

                def test_protocol():
                    with socket.create_connection((host, port), timeout=5) as sock:
                        with context.wrap_socket(sock, server_hostname=host) as ssock:
                            return True

                results[proto_name] = await loop.run_in_executor(None, test_protocol)
            except Exception:
                results[proto_name] = False

        # Check TLSv1.3 separately (different API)
        try:
            context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            context.minimum_version = ssl.TLSVersion.TLSv1_3
            context.maximum_version = ssl.TLSVersion.TLSv1_3
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE

            loop = asyncio.get_event_loop()

            def test_tls13():
                with socket.create_connection((host, port), timeout=5) as sock:
                    with context.wrap_socket(sock, server_hostname=host) as ssock:
                        return ssock.version() == "TLSv1.3"

            results["TLSv1.3"] = await loop.run_in_executor(None, test_tls13)
        except Exception:
            results["TLSv1.3"] = False

        return results

    def check_protocols(self, host: str, port: int = 443) -> dict[str, bool]:
        """Synchronous protocol check."""
        return asyncio.run(self.check_protocols_async(host, port))

    def grade_certificate(self, cert_info: CertificateInfo) -> str:
        """Grade the certificate configuration (A-F)."""
        if cert_info.error:
            return "F"

        score = 100

        # Deductions
        if cert_info.is_expired:
            score -= 100
        if cert_info.is_self_signed:
            score -= 50
        if cert_info.days_remaining < 30:
            score -= 10
        if cert_info.days_remaining < 7:
            score -= 20

        # Check cipher
        if cert_info.cipher_name:
            for weak in WEAK_CIPHERS:
                if weak in cert_info.cipher_name:
                    score -= 30
                    break

        # Check protocol
        if cert_info.protocol_version in DEPRECATED_PROTOCOLS:
            score -= 20

        # Grade
        if score >= 90:
            return "A"
        elif score >= 80:
            return "B"
        elif score >= 70:
            return "C"
        elif score >= 50:
            return "D"
        else:
            return "F"

    async def analyze_batch_async(
        self,
        hosts: list[tuple[str, int]],
    ) -> list[CertificateInfo]:
        """Analyze multiple hosts concurrently."""
        tasks = [self.analyze_async(host, port) for host, port in hosts]
        return await asyncio.gather(*tasks)

    def analyze_batch(self, hosts: list[tuple[str, int]]) -> list[CertificateInfo]:
        """Synchronous batch analysis."""
        return asyncio.run(self.analyze_batch_async(hosts))
