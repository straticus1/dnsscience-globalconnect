"""
Packet Capture and Analysis module.

Provides capture and analysis of network traffic for troubleshooting:
- DNS traffic analysis
- SMTP/Email traffic analysis
- SSL/TLS handshake analysis
- L2/L3 network issue detection

Copyright (c) 2025 DNS Science.io, an After Dark Systems, LLC company.
All rights reserved.
"""

from globaldetect.cap.capture import (
    PacketCapture,
    CaptureConfig,
    CaptureResult,
)
from globaldetect.cap.analyzer import (
    PacketAnalyzer,
    AnalysisResult,
    NetworkIssue,
)
from globaldetect.cap.protocols import (
    DNSAnalyzer,
    SMTPAnalyzer,
    SSLAnalyzer,
)

__all__ = [
    "PacketCapture",
    "CaptureConfig",
    "CaptureResult",
    "PacketAnalyzer",
    "AnalysisResult",
    "NetworkIssue",
    "DNSAnalyzer",
    "SMTPAnalyzer",
    "SSLAnalyzer",
]
