"""
Data models for facilities, carriers, and network presence.

Copyright (c) 2025 DNS Science.io, an After Dark Systems, LLC company.
All rights reserved.
"""

from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any


class FacilityStatus(str, Enum):
    """Operational status of a facility."""
    ACTIVE = "active"
    PLANNED = "planned"
    DEFUNCT = "defunct"
    UNKNOWN = "unknown"


class CarrierType(str, Enum):
    """Type of carrier service."""
    NSP = "nsp"  # Network Service Provider
    ISP = "isp"  # Internet Service Provider
    IXP = "ixp"  # Internet Exchange Point
    CDN = "cdn"  # Content Delivery Network
    ENTERPRISE = "enterprise"
    EDUCATIONAL = "educational"
    GOVERNMENT = "government"
    OTHER = "other"


@dataclass
class Facility:
    """
    A data center or colocation facility.

    Maps to PeeringDB 'fac' object.
    """
    id: int | None = None

    # PeeringDB identifiers
    peeringdb_id: int | None = None

    # Identity
    name: str | None = None
    aka: str | None = None  # Also known as
    name_long: str | None = None
    website: str | None = None

    # Site codes (various naming conventions)
    clli_code: str | None = None  # CLLI code (telco standard)
    site_code: str | None = None  # Custom/internal site code
    npa_nxx: str | None = None  # Area code info

    # Ownership
    owner: str | None = None  # Organization that owns the facility
    owner_id: int | None = None  # PeeringDB org ID
    operator: str | None = None  # Operating company (may differ from owner)

    # Geographic location
    address1: str | None = None
    address2: str | None = None
    city: str | None = None
    state: str | None = None
    zipcode: str | None = None
    country: str | None = None  # ISO 3166-1 alpha-2

    # Coordinates
    latitude: float | None = None
    longitude: float | None = None

    # Facility details
    floor_count: int | None = None
    square_feet: int | None = None
    power_mw: float | None = None  # Total power capacity in MW

    # Contact
    sales_email: str | None = None
    sales_phone: str | None = None
    tech_email: str | None = None
    tech_phone: str | None = None

    # Status
    status: FacilityStatus = FacilityStatus.UNKNOWN

    # Network counts (from PeeringDB)
    net_count: int | None = None  # Number of networks present
    ix_count: int | None = None  # Number of IXPs present

    # Notes
    notes: str | None = None

    # Timestamps
    created_at: datetime | None = None
    updated_at: datetime | None = None
    last_synced: datetime | None = None

    # Source tracking
    source: str | None = None  # peeringdb, manual, etc.
    source_updated: datetime | None = None  # When source data was updated

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "peeringdb_id": self.peeringdb_id,
            "name": self.name,
            "aka": self.aka,
            "name_long": self.name_long,
            "website": self.website,
            "clli_code": self.clli_code,
            "site_code": self.site_code,
            "npa_nxx": self.npa_nxx,
            "owner": self.owner,
            "owner_id": self.owner_id,
            "operator": self.operator,
            "address1": self.address1,
            "address2": self.address2,
            "city": self.city,
            "state": self.state,
            "zipcode": self.zipcode,
            "country": self.country,
            "latitude": self.latitude,
            "longitude": self.longitude,
            "floor_count": self.floor_count,
            "square_feet": self.square_feet,
            "power_mw": self.power_mw,
            "sales_email": self.sales_email,
            "sales_phone": self.sales_phone,
            "tech_email": self.tech_email,
            "tech_phone": self.tech_phone,
            "status": self.status.value,
            "net_count": self.net_count,
            "ix_count": self.ix_count,
            "notes": self.notes,
            "created_at": self.created_at.isoformat() if self.created_at else None,
            "updated_at": self.updated_at.isoformat() if self.updated_at else None,
            "last_synced": self.last_synced.isoformat() if self.last_synced else None,
            "source": self.source,
            "source_updated": self.source_updated.isoformat() if self.source_updated else None,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "Facility":
        return cls(
            id=data.get("id"),
            peeringdb_id=data.get("peeringdb_id"),
            name=data.get("name"),
            aka=data.get("aka"),
            name_long=data.get("name_long"),
            website=data.get("website"),
            clli_code=data.get("clli_code"),
            site_code=data.get("site_code"),
            npa_nxx=data.get("npa_nxx"),
            owner=data.get("owner"),
            owner_id=data.get("owner_id"),
            operator=data.get("operator"),
            address1=data.get("address1"),
            address2=data.get("address2"),
            city=data.get("city"),
            state=data.get("state"),
            zipcode=data.get("zipcode"),
            country=data.get("country"),
            latitude=data.get("latitude"),
            longitude=data.get("longitude"),
            floor_count=data.get("floor_count"),
            square_feet=data.get("square_feet"),
            power_mw=data.get("power_mw"),
            sales_email=data.get("sales_email"),
            sales_phone=data.get("sales_phone"),
            tech_email=data.get("tech_email"),
            tech_phone=data.get("tech_phone"),
            status=FacilityStatus(data.get("status", "unknown")),
            net_count=data.get("net_count"),
            ix_count=data.get("ix_count"),
            notes=data.get("notes"),
            created_at=datetime.fromisoformat(data["created_at"]) if data.get("created_at") else None,
            updated_at=datetime.fromisoformat(data["updated_at"]) if data.get("updated_at") else None,
            last_synced=datetime.fromisoformat(data["last_synced"]) if data.get("last_synced") else None,
            source=data.get("source"),
            source_updated=datetime.fromisoformat(data["source_updated"]) if data.get("source_updated") else None,
        )

    @classmethod
    def from_peeringdb(cls, data: dict[str, Any]) -> "Facility":
        """Create Facility from PeeringDB API response."""
        return cls(
            peeringdb_id=data.get("id"),
            name=data.get("name"),
            aka=data.get("aka"),
            name_long=data.get("name_long"),
            website=data.get("website"),
            clli_code=data.get("clli"),
            npa_nxx=data.get("npanxx"),
            owner=data.get("org_name") or data.get("org", {}).get("name"),
            owner_id=data.get("org_id") or data.get("org", {}).get("id"),
            address1=data.get("address1"),
            address2=data.get("address2"),
            city=data.get("city"),
            state=data.get("state"),
            zipcode=data.get("zipcode"),
            country=data.get("country"),
            latitude=data.get("latitude"),
            longitude=data.get("longitude"),
            sales_email=data.get("sales_email"),
            sales_phone=data.get("sales_phone"),
            tech_email=data.get("tech_email"),
            tech_phone=data.get("tech_phone"),
            status=FacilityStatus.ACTIVE if data.get("status") == "ok" else FacilityStatus.UNKNOWN,
            net_count=data.get("net_count"),
            notes=data.get("notes"),
            source="peeringdb",
            source_updated=datetime.fromisoformat(data["updated"].replace("Z", "+00:00")) if data.get("updated") else None,
        )


@dataclass
class Carrier:
    """
    A network carrier or service provider.

    Maps to PeeringDB 'carrier' object for L1/L2 service providers.
    """
    id: int | None = None

    # PeeringDB identifiers
    peeringdb_id: int | None = None

    # Identity
    name: str | None = None
    aka: str | None = None
    website: str | None = None

    # Organization
    org_name: str | None = None
    org_id: int | None = None

    # Status
    status: str | None = None  # ok, pending, deleted

    # Timestamps
    created_at: datetime | None = None
    updated_at: datetime | None = None
    last_synced: datetime | None = None

    source: str | None = None
    source_updated: datetime | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "peeringdb_id": self.peeringdb_id,
            "name": self.name,
            "aka": self.aka,
            "website": self.website,
            "org_name": self.org_name,
            "org_id": self.org_id,
            "status": self.status,
            "created_at": self.created_at.isoformat() if self.created_at else None,
            "updated_at": self.updated_at.isoformat() if self.updated_at else None,
            "last_synced": self.last_synced.isoformat() if self.last_synced else None,
            "source": self.source,
            "source_updated": self.source_updated.isoformat() if self.source_updated else None,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "Carrier":
        return cls(
            id=data.get("id"),
            peeringdb_id=data.get("peeringdb_id"),
            name=data.get("name"),
            aka=data.get("aka"),
            website=data.get("website"),
            org_name=data.get("org_name"),
            org_id=data.get("org_id"),
            status=data.get("status"),
            created_at=datetime.fromisoformat(data["created_at"]) if data.get("created_at") else None,
            updated_at=datetime.fromisoformat(data["updated_at"]) if data.get("updated_at") else None,
            last_synced=datetime.fromisoformat(data["last_synced"]) if data.get("last_synced") else None,
            source=data.get("source"),
            source_updated=datetime.fromisoformat(data["source_updated"]) if data.get("source_updated") else None,
        )

    @classmethod
    def from_peeringdb(cls, data: dict[str, Any]) -> "Carrier":
        """Create Carrier from PeeringDB API response."""
        return cls(
            peeringdb_id=data.get("id"),
            name=data.get("name"),
            aka=data.get("aka"),
            website=data.get("website"),
            org_name=data.get("org_name") or data.get("org", {}).get("name"),
            org_id=data.get("org_id") or data.get("org", {}).get("id"),
            status=data.get("status"),
            source="peeringdb",
            source_updated=datetime.fromisoformat(data["updated"].replace("Z", "+00:00")) if data.get("updated") else None,
        )


@dataclass
class NetworkPresence:
    """
    A network's presence at a facility.

    Maps to PeeringDB 'netfac' (network-facility) relationship.
    """
    id: int | None = None

    # PeeringDB identifiers
    peeringdb_id: int | None = None

    # Relationships
    facility_id: int | None = None  # Local facility ID
    facility_peeringdb_id: int | None = None
    network_asn: int | None = None  # ASN of the network
    network_name: str | None = None
    network_peeringdb_id: int | None = None

    # Presence details
    local_asn: int | None = None  # May differ from network ASN
    avail_sonet: bool = False
    avail_ethernet: bool = False
    avail_atm: bool = False

    # Status
    status: str | None = None

    # Timestamps
    created_at: datetime | None = None
    updated_at: datetime | None = None
    last_synced: datetime | None = None

    source: str | None = None
    source_updated: datetime | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "peeringdb_id": self.peeringdb_id,
            "facility_id": self.facility_id,
            "facility_peeringdb_id": self.facility_peeringdb_id,
            "network_asn": self.network_asn,
            "network_name": self.network_name,
            "network_peeringdb_id": self.network_peeringdb_id,
            "local_asn": self.local_asn,
            "avail_sonet": self.avail_sonet,
            "avail_ethernet": self.avail_ethernet,
            "avail_atm": self.avail_atm,
            "status": self.status,
            "created_at": self.created_at.isoformat() if self.created_at else None,
            "updated_at": self.updated_at.isoformat() if self.updated_at else None,
            "last_synced": self.last_synced.isoformat() if self.last_synced else None,
            "source": self.source,
            "source_updated": self.source_updated.isoformat() if self.source_updated else None,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "NetworkPresence":
        return cls(
            id=data.get("id"),
            peeringdb_id=data.get("peeringdb_id"),
            facility_id=data.get("facility_id"),
            facility_peeringdb_id=data.get("facility_peeringdb_id"),
            network_asn=data.get("network_asn"),
            network_name=data.get("network_name"),
            network_peeringdb_id=data.get("network_peeringdb_id"),
            local_asn=data.get("local_asn"),
            avail_sonet=data.get("avail_sonet", False),
            avail_ethernet=data.get("avail_ethernet", False),
            avail_atm=data.get("avail_atm", False),
            status=data.get("status"),
            created_at=datetime.fromisoformat(data["created_at"]) if data.get("created_at") else None,
            updated_at=datetime.fromisoformat(data["updated_at"]) if data.get("updated_at") else None,
            last_synced=datetime.fromisoformat(data["last_synced"]) if data.get("last_synced") else None,
            source=data.get("source"),
            source_updated=datetime.fromisoformat(data["source_updated"]) if data.get("source_updated") else None,
        )

    @classmethod
    def from_peeringdb(cls, data: dict[str, Any]) -> "NetworkPresence":
        """Create NetworkPresence from PeeringDB API response."""
        return cls(
            peeringdb_id=data.get("id"),
            facility_peeringdb_id=data.get("fac_id"),
            network_peeringdb_id=data.get("net_id"),
            network_asn=data.get("local_asn"),  # PeeringDB stores ASN here
            network_name=data.get("name"),
            local_asn=data.get("local_asn"),
            avail_sonet=data.get("avail_sonet", False),
            avail_ethernet=data.get("avail_ethernet", False),
            avail_atm=data.get("avail_atm", False),
            status=data.get("status"),
            source="peeringdb",
            source_updated=datetime.fromisoformat(data["updated"].replace("Z", "+00:00")) if data.get("updated") else None,
        )


@dataclass
class CarrierPresence:
    """
    A carrier's presence at a facility.

    Maps to PeeringDB 'carrierfac' (carrier-facility) relationship.
    """
    id: int | None = None

    # PeeringDB identifiers
    peeringdb_id: int | None = None

    # Relationships
    facility_id: int | None = None
    facility_peeringdb_id: int | None = None
    carrier_id: int | None = None
    carrier_peeringdb_id: int | None = None
    carrier_name: str | None = None

    # Status
    status: str | None = None

    # Timestamps
    created_at: datetime | None = None
    updated_at: datetime | None = None
    last_synced: datetime | None = None

    source: str | None = None
    source_updated: datetime | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "peeringdb_id": self.peeringdb_id,
            "facility_id": self.facility_id,
            "facility_peeringdb_id": self.facility_peeringdb_id,
            "carrier_id": self.carrier_id,
            "carrier_peeringdb_id": self.carrier_peeringdb_id,
            "carrier_name": self.carrier_name,
            "status": self.status,
            "created_at": self.created_at.isoformat() if self.created_at else None,
            "updated_at": self.updated_at.isoformat() if self.updated_at else None,
            "last_synced": self.last_synced.isoformat() if self.last_synced else None,
            "source": self.source,
            "source_updated": self.source_updated.isoformat() if self.source_updated else None,
        }

    @classmethod
    def from_peeringdb(cls, data: dict[str, Any]) -> "CarrierPresence":
        """Create CarrierPresence from PeeringDB API response."""
        return cls(
            peeringdb_id=data.get("id"),
            facility_peeringdb_id=data.get("fac_id"),
            carrier_peeringdb_id=data.get("carrier_id"),
            status=data.get("status"),
            source="peeringdb",
            source_updated=datetime.fromisoformat(data["updated"].replace("Z", "+00:00")) if data.get("updated") else None,
        )


@dataclass
class InternetExchange:
    """
    An Internet Exchange Point (IXP).

    Maps to PeeringDB 'ix' object.
    """
    id: int | None = None

    # PeeringDB identifiers
    peeringdb_id: int | None = None

    # Identity
    name: str | None = None
    name_long: str | None = None
    aka: str | None = None
    website: str | None = None
    url_stats: str | None = None

    # Organization
    org_name: str | None = None
    org_id: int | None = None

    # Geographic
    city: str | None = None
    country: str | None = None
    region_continent: str | None = None

    # Media type
    media: str | None = None  # Ethernet, etc.

    # Protocol support
    proto_unicast: bool = True
    proto_multicast: bool = False
    proto_ipv6: bool = True

    # Policy
    policy_email: str | None = None
    policy_phone: str | None = None

    # Status
    status: str | None = None

    # Network counts
    net_count: int | None = None
    fac_count: int | None = None

    # Timestamps
    created_at: datetime | None = None
    updated_at: datetime | None = None
    last_synced: datetime | None = None

    source: str | None = None
    source_updated: datetime | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "peeringdb_id": self.peeringdb_id,
            "name": self.name,
            "name_long": self.name_long,
            "aka": self.aka,
            "website": self.website,
            "url_stats": self.url_stats,
            "org_name": self.org_name,
            "org_id": self.org_id,
            "city": self.city,
            "country": self.country,
            "region_continent": self.region_continent,
            "media": self.media,
            "proto_unicast": self.proto_unicast,
            "proto_multicast": self.proto_multicast,
            "proto_ipv6": self.proto_ipv6,
            "policy_email": self.policy_email,
            "policy_phone": self.policy_phone,
            "status": self.status,
            "net_count": self.net_count,
            "fac_count": self.fac_count,
            "created_at": self.created_at.isoformat() if self.created_at else None,
            "updated_at": self.updated_at.isoformat() if self.updated_at else None,
            "last_synced": self.last_synced.isoformat() if self.last_synced else None,
            "source": self.source,
            "source_updated": self.source_updated.isoformat() if self.source_updated else None,
        }

    @classmethod
    def from_peeringdb(cls, data: dict[str, Any]) -> "InternetExchange":
        """Create InternetExchange from PeeringDB API response."""
        return cls(
            peeringdb_id=data.get("id"),
            name=data.get("name"),
            name_long=data.get("name_long"),
            aka=data.get("aka"),
            website=data.get("website"),
            url_stats=data.get("url_stats"),
            org_name=data.get("org_name") or data.get("org", {}).get("name"),
            org_id=data.get("org_id") or data.get("org", {}).get("id"),
            city=data.get("city"),
            country=data.get("country"),
            region_continent=data.get("region_continent"),
            media=data.get("media"),
            proto_unicast=data.get("proto_unicast", True),
            proto_multicast=data.get("proto_multicast", False),
            proto_ipv6=data.get("proto_ipv6", True),
            policy_email=data.get("policy_email"),
            policy_phone=data.get("policy_phone"),
            status=data.get("status"),
            net_count=data.get("net_count"),
            fac_count=data.get("fac_count"),
            source="peeringdb",
            source_updated=datetime.fromisoformat(data["updated"].replace("Z", "+00:00")) if data.get("updated") else None,
        )


@dataclass
class IXLan:
    """
    An IX LAN (peering LAN at an IX).

    Maps to PeeringDB 'ixlan' object.
    """
    id: int | None = None
    peeringdb_id: int | None = None

    ix_id: int | None = None
    ix_peeringdb_id: int | None = None

    name: str | None = None
    descr: str | None = None

    mtu: int | None = None
    vlan: int | None = None
    dot1q_support: bool = False
    rs_asn: int | None = None  # Route server ASN
    arp_sponge: str | None = None

    status: str | None = None

    created_at: datetime | None = None
    updated_at: datetime | None = None
    last_synced: datetime | None = None

    source: str | None = None
    source_updated: datetime | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "peeringdb_id": self.peeringdb_id,
            "ix_id": self.ix_id,
            "ix_peeringdb_id": self.ix_peeringdb_id,
            "name": self.name,
            "descr": self.descr,
            "mtu": self.mtu,
            "vlan": self.vlan,
            "dot1q_support": self.dot1q_support,
            "rs_asn": self.rs_asn,
            "arp_sponge": self.arp_sponge,
            "status": self.status,
            "created_at": self.created_at.isoformat() if self.created_at else None,
            "updated_at": self.updated_at.isoformat() if self.updated_at else None,
            "last_synced": self.last_synced.isoformat() if self.last_synced else None,
            "source": self.source,
            "source_updated": self.source_updated.isoformat() if self.source_updated else None,
        }

    @classmethod
    def from_peeringdb(cls, data: dict[str, Any]) -> "IXLan":
        """Create IXLan from PeeringDB API response."""
        return cls(
            peeringdb_id=data.get("id"),
            ix_peeringdb_id=data.get("ix_id"),
            name=data.get("name"),
            descr=data.get("descr"),
            mtu=data.get("mtu"),
            vlan=data.get("vlan"),
            dot1q_support=data.get("dot1q_support", False),
            rs_asn=data.get("rs_asn"),
            arp_sponge=data.get("arp_sponge"),
            status=data.get("status"),
            source="peeringdb",
            source_updated=datetime.fromisoformat(data["updated"].replace("Z", "+00:00")) if data.get("updated") else None,
        )


@dataclass
class IXFacility:
    """
    Relationship between an IX and a facility.

    Maps to PeeringDB 'ixfac' object.
    """
    id: int | None = None
    peeringdb_id: int | None = None

    ix_id: int | None = None
    ix_peeringdb_id: int | None = None
    facility_id: int | None = None
    facility_peeringdb_id: int | None = None

    status: str | None = None

    created_at: datetime | None = None
    updated_at: datetime | None = None
    last_synced: datetime | None = None

    source: str | None = None
    source_updated: datetime | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "peeringdb_id": self.peeringdb_id,
            "ix_id": self.ix_id,
            "ix_peeringdb_id": self.ix_peeringdb_id,
            "facility_id": self.facility_id,
            "facility_peeringdb_id": self.facility_peeringdb_id,
            "status": self.status,
            "created_at": self.created_at.isoformat() if self.created_at else None,
            "updated_at": self.updated_at.isoformat() if self.updated_at else None,
            "last_synced": self.last_synced.isoformat() if self.last_synced else None,
            "source": self.source,
            "source_updated": self.source_updated.isoformat() if self.source_updated else None,
        }

    @classmethod
    def from_peeringdb(cls, data: dict[str, Any]) -> "IXFacility":
        """Create IXFacility from PeeringDB API response."""
        return cls(
            peeringdb_id=data.get("id"),
            ix_peeringdb_id=data.get("ix_id"),
            facility_peeringdb_id=data.get("fac_id"),
            status=data.get("status"),
            source="peeringdb",
            source_updated=datetime.fromisoformat(data["updated"].replace("Z", "+00:00")) if data.get("updated") else None,
        )


@dataclass
class Network:
    """
    A network (ASN) from PeeringDB.

    Maps to PeeringDB 'net' object.
    """
    id: int | None = None
    peeringdb_id: int | None = None

    asn: int | None = None
    name: str | None = None
    aka: str | None = None
    website: str | None = None
    looking_glass: str | None = None
    route_server: str | None = None

    # Organization
    org_name: str | None = None
    org_id: int | None = None

    # Network type
    info_type: str | None = None  # NSP, ISP, Content, Enterprise, etc.
    info_prefixes4: int | None = None
    info_prefixes6: int | None = None
    info_traffic: str | None = None
    info_ratio: str | None = None
    info_scope: str | None = None

    # Policy
    policy_general: str | None = None  # Open, Selective, Restrictive
    policy_url: str | None = None
    policy_locations: str | None = None
    policy_ratio: bool = False
    policy_contracts: str | None = None

    # Contact
    irr_as_set: str | None = None

    # Status
    status: str | None = None

    # Counts
    fac_count: int | None = None
    ix_count: int | None = None

    created_at: datetime | None = None
    updated_at: datetime | None = None
    last_synced: datetime | None = None

    source: str | None = None
    source_updated: datetime | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "peeringdb_id": self.peeringdb_id,
            "asn": self.asn,
            "name": self.name,
            "aka": self.aka,
            "website": self.website,
            "looking_glass": self.looking_glass,
            "route_server": self.route_server,
            "org_name": self.org_name,
            "org_id": self.org_id,
            "info_type": self.info_type,
            "info_prefixes4": self.info_prefixes4,
            "info_prefixes6": self.info_prefixes6,
            "info_traffic": self.info_traffic,
            "info_ratio": self.info_ratio,
            "info_scope": self.info_scope,
            "policy_general": self.policy_general,
            "policy_url": self.policy_url,
            "policy_locations": self.policy_locations,
            "policy_ratio": self.policy_ratio,
            "policy_contracts": self.policy_contracts,
            "irr_as_set": self.irr_as_set,
            "status": self.status,
            "fac_count": self.fac_count,
            "ix_count": self.ix_count,
            "created_at": self.created_at.isoformat() if self.created_at else None,
            "updated_at": self.updated_at.isoformat() if self.updated_at else None,
            "last_synced": self.last_synced.isoformat() if self.last_synced else None,
            "source": self.source,
            "source_updated": self.source_updated.isoformat() if self.source_updated else None,
        }

    @classmethod
    def from_peeringdb(cls, data: dict[str, Any]) -> "Network":
        """Create Network from PeeringDB API response."""
        return cls(
            peeringdb_id=data.get("id"),
            asn=data.get("asn"),
            name=data.get("name"),
            aka=data.get("aka"),
            website=data.get("website"),
            looking_glass=data.get("looking_glass"),
            route_server=data.get("route_server"),
            org_name=data.get("org_name") or data.get("org", {}).get("name"),
            org_id=data.get("org_id") or data.get("org", {}).get("id"),
            info_type=data.get("info_type"),
            info_prefixes4=data.get("info_prefixes4"),
            info_prefixes6=data.get("info_prefixes6"),
            info_traffic=data.get("info_traffic"),
            info_ratio=data.get("info_ratio"),
            info_scope=data.get("info_scope"),
            policy_general=data.get("policy_general"),
            policy_url=data.get("policy_url"),
            policy_locations=data.get("policy_locations"),
            policy_ratio=data.get("policy_ratio", False),
            policy_contracts=data.get("policy_contracts"),
            irr_as_set=data.get("irr_as_set"),
            status=data.get("status"),
            fac_count=data.get("fac_count"),
            ix_count=data.get("ix_count"),
            source="peeringdb",
            source_updated=datetime.fromisoformat(data["updated"].replace("Z", "+00:00")) if data.get("updated") else None,
        )


@dataclass
class SyncStatus:
    """Status of a sync operation."""
    id: int | None = None
    source: str | None = None  # peeringdb, pch, etc.
    entity_type: str | None = None  # facility, carrier, network, etc.

    started_at: datetime | None = None
    completed_at: datetime | None = None

    status: str | None = None  # running, completed, failed

    records_fetched: int = 0
    records_created: int = 0
    records_updated: int = 0
    records_deleted: int = 0

    error_message: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "source": self.source,
            "entity_type": self.entity_type,
            "started_at": self.started_at.isoformat() if self.started_at else None,
            "completed_at": self.completed_at.isoformat() if self.completed_at else None,
            "status": self.status,
            "records_fetched": self.records_fetched,
            "records_created": self.records_created,
            "records_updated": self.records_updated,
            "records_deleted": self.records_deleted,
            "error_message": self.error_message,
        }
