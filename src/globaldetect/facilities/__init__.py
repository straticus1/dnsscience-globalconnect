"""
Facilities module for data center and colocation information.

Provides integration with PeeringDB and other sources to maintain
an up-to-date database of global data center facilities, carriers,
and network presence.

Copyright (c) 2025 DNS Science.io, an After Dark Systems, LLC company.
All rights reserved.
"""

from globaldetect.facilities.models import (
    Facility,
    Carrier,
    CarrierPresence,
    NetworkPresence,
    InternetExchange,
    IXFacility,
    IXLan,
    Network,
    FacilityStatus,
    SyncStatus,
)
from globaldetect.facilities.database import FacilitiesDatabase
from globaldetect.facilities.peeringdb import PeeringDBClient
from globaldetect.facilities.sync import FacilitiesSync, SyncOptions, SyncResult

__all__ = [
    "Facility",
    "Carrier",
    "CarrierPresence",
    "NetworkPresence",
    "InternetExchange",
    "IXFacility",
    "IXLan",
    "Network",
    "FacilityStatus",
    "SyncStatus",
    "FacilitiesDatabase",
    "PeeringDBClient",
    "FacilitiesSync",
    "SyncOptions",
    "SyncResult",
]
