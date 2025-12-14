"""
Device collectors for routing protocol information.

Provides connectivity to network devices and retrieval of
routing protocol state and configuration.

Copyright (c) 2025 DNS Science.io, an After Dark Systems, LLC company.
All rights reserved.
"""

from globaldetect.routing.collectors.base import (
    RoutingCollector,
    DeviceCredentials,
    ProxyConfig,
    CollectorResult,
)
from globaldetect.routing.collectors.cisco import CiscoIOSCollector, CiscoNXOSCollector
from globaldetect.routing.collectors.juniper import JuniperJunOSCollector
from globaldetect.routing.collectors.arista import AristaEOSCollector

__all__ = [
    "RoutingCollector",
    "DeviceCredentials",
    "ProxyConfig",
    "CollectorResult",
    "CiscoIOSCollector",
    "CiscoNXOSCollector",
    "JuniperJunOSCollector",
    "AristaEOSCollector",
]
