"""
Database layer for facilities storage.

Supports SQLite (default) and PostgreSQL for storing facility,
carrier, network, and IX data.

Copyright (c) 2025 DNS Science.io, an After Dark Systems, LLC company.
All rights reserved.
"""

import json
import logging
import os
import sqlite3
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Any, Generator

from globaldetect.facilities.models import (
    Carrier,
    CarrierPresence,
    Facility,
    FacilityStatus,
    InternetExchange,
    IXFacility,
    IXLan,
    Network,
    NetworkPresence,
    SyncStatus,
)

logger = logging.getLogger(__name__)

# Default database location
DEFAULT_DB_PATH = Path.home() / ".config" / "globaldetect" / "facilities.db"


@dataclass
class DatabaseConfig:
    """Database configuration."""
    # SQLite
    sqlite_path: Path | str | None = None

    # PostgreSQL (if configured, takes precedence)
    pg_host: str | None = None
    pg_port: int = 5432
    pg_database: str | None = None
    pg_user: str | None = None
    pg_password: str | None = None

    @classmethod
    def from_env(cls) -> "DatabaseConfig":
        """Create config from environment variables."""
        return cls(
            sqlite_path=os.environ.get("GLOBALDETECT_FACILITIES_DB", str(DEFAULT_DB_PATH)),
            pg_host=os.environ.get("GLOBALDETECT_FACILITIES_PG_HOST"),
            pg_port=int(os.environ.get("GLOBALDETECT_FACILITIES_PG_PORT", "5432")),
            pg_database=os.environ.get("GLOBALDETECT_FACILITIES_PG_DATABASE"),
            pg_user=os.environ.get("GLOBALDETECT_FACILITIES_PG_USER"),
            pg_password=os.environ.get("GLOBALDETECT_FACILITIES_PG_PASSWORD"),
        )

    @property
    def use_postgres(self) -> bool:
        """Check if PostgreSQL should be used."""
        return bool(self.pg_host and self.pg_database)


class FacilitiesDatabase:
    """
    Database interface for facilities data.

    Supports SQLite (default) and PostgreSQL.

    Usage:
        db = FacilitiesDatabase()
        db.initialize()

        # Store facilities
        db.upsert_facility(facility)

        # Query
        facilities = db.search_facilities(city="Ashburn")
    """

    def __init__(self, config: DatabaseConfig | None = None):
        self.config = config or DatabaseConfig.from_env()
        self._connection: sqlite3.Connection | None = None

        # Ensure directory exists for SQLite
        if not self.config.use_postgres:
            db_path = Path(self.config.sqlite_path or DEFAULT_DB_PATH)
            db_path.parent.mkdir(parents=True, exist_ok=True)
            self._db_path = db_path

    @contextmanager
    def _get_connection(self) -> Generator[sqlite3.Connection, None, None]:
        """Get a database connection."""
        if self.config.use_postgres:
            raise NotImplementedError("PostgreSQL support coming soon")

        conn = sqlite3.connect(str(self._db_path))
        conn.row_factory = sqlite3.Row
        try:
            yield conn
        finally:
            conn.close()

    def initialize(self):
        """Initialize the database schema."""
        with self._get_connection() as conn:
            cursor = conn.cursor()

            # Facilities table
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS facilities (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    peeringdb_id INTEGER UNIQUE,
                    name TEXT,
                    aka TEXT,
                    name_long TEXT,
                    website TEXT,
                    clli_code TEXT,
                    site_code TEXT,
                    npa_nxx TEXT,
                    owner TEXT,
                    owner_id INTEGER,
                    operator TEXT,
                    address1 TEXT,
                    address2 TEXT,
                    city TEXT,
                    state TEXT,
                    zipcode TEXT,
                    country TEXT,
                    latitude REAL,
                    longitude REAL,
                    floor_count INTEGER,
                    square_feet INTEGER,
                    power_mw REAL,
                    sales_email TEXT,
                    sales_phone TEXT,
                    tech_email TEXT,
                    tech_phone TEXT,
                    status TEXT DEFAULT 'unknown',
                    net_count INTEGER,
                    ix_count INTEGER,
                    notes TEXT,
                    created_at TEXT,
                    updated_at TEXT,
                    last_synced TEXT,
                    source TEXT,
                    source_updated TEXT
                )
            """)

            # Networks table
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS networks (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    peeringdb_id INTEGER UNIQUE,
                    asn INTEGER UNIQUE,
                    name TEXT,
                    aka TEXT,
                    website TEXT,
                    looking_glass TEXT,
                    route_server TEXT,
                    org_name TEXT,
                    org_id INTEGER,
                    info_type TEXT,
                    info_prefixes4 INTEGER,
                    info_prefixes6 INTEGER,
                    info_traffic TEXT,
                    info_ratio TEXT,
                    info_scope TEXT,
                    policy_general TEXT,
                    policy_url TEXT,
                    policy_locations TEXT,
                    policy_ratio INTEGER,
                    policy_contracts TEXT,
                    irr_as_set TEXT,
                    status TEXT,
                    fac_count INTEGER,
                    ix_count INTEGER,
                    created_at TEXT,
                    updated_at TEXT,
                    last_synced TEXT,
                    source TEXT,
                    source_updated TEXT
                )
            """)

            # Network-Facility relationships
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS network_facilities (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    peeringdb_id INTEGER UNIQUE,
                    facility_id INTEGER,
                    facility_peeringdb_id INTEGER,
                    network_asn INTEGER,
                    network_name TEXT,
                    network_peeringdb_id INTEGER,
                    local_asn INTEGER,
                    avail_sonet INTEGER DEFAULT 0,
                    avail_ethernet INTEGER DEFAULT 0,
                    avail_atm INTEGER DEFAULT 0,
                    status TEXT,
                    created_at TEXT,
                    updated_at TEXT,
                    last_synced TEXT,
                    source TEXT,
                    source_updated TEXT,
                    FOREIGN KEY (facility_id) REFERENCES facilities(id),
                    FOREIGN KEY (network_asn) REFERENCES networks(asn)
                )
            """)

            # Carriers table
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS carriers (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    peeringdb_id INTEGER UNIQUE,
                    name TEXT,
                    aka TEXT,
                    website TEXT,
                    org_name TEXT,
                    org_id INTEGER,
                    status TEXT,
                    created_at TEXT,
                    updated_at TEXT,
                    last_synced TEXT,
                    source TEXT,
                    source_updated TEXT
                )
            """)

            # Carrier-Facility relationships
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS carrier_facilities (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    peeringdb_id INTEGER UNIQUE,
                    facility_id INTEGER,
                    facility_peeringdb_id INTEGER,
                    carrier_id INTEGER,
                    carrier_peeringdb_id INTEGER,
                    carrier_name TEXT,
                    status TEXT,
                    created_at TEXT,
                    updated_at TEXT,
                    last_synced TEXT,
                    source TEXT,
                    source_updated TEXT,
                    FOREIGN KEY (facility_id) REFERENCES facilities(id),
                    FOREIGN KEY (carrier_id) REFERENCES carriers(id)
                )
            """)

            # Internet Exchanges table
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS exchanges (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    peeringdb_id INTEGER UNIQUE,
                    name TEXT,
                    name_long TEXT,
                    aka TEXT,
                    website TEXT,
                    url_stats TEXT,
                    org_name TEXT,
                    org_id INTEGER,
                    city TEXT,
                    country TEXT,
                    region_continent TEXT,
                    media TEXT,
                    proto_unicast INTEGER DEFAULT 1,
                    proto_multicast INTEGER DEFAULT 0,
                    proto_ipv6 INTEGER DEFAULT 1,
                    policy_email TEXT,
                    policy_phone TEXT,
                    status TEXT,
                    net_count INTEGER,
                    fac_count INTEGER,
                    created_at TEXT,
                    updated_at TEXT,
                    last_synced TEXT,
                    source TEXT,
                    source_updated TEXT
                )
            """)

            # IX-Facility relationships
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS ix_facilities (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    peeringdb_id INTEGER UNIQUE,
                    ix_id INTEGER,
                    ix_peeringdb_id INTEGER,
                    facility_id INTEGER,
                    facility_peeringdb_id INTEGER,
                    status TEXT,
                    created_at TEXT,
                    updated_at TEXT,
                    last_synced TEXT,
                    source TEXT,
                    source_updated TEXT,
                    FOREIGN KEY (ix_id) REFERENCES exchanges(id),
                    FOREIGN KEY (facility_id) REFERENCES facilities(id)
                )
            """)

            # IX LANs table
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS ix_lans (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    peeringdb_id INTEGER UNIQUE,
                    ix_id INTEGER,
                    ix_peeringdb_id INTEGER,
                    name TEXT,
                    descr TEXT,
                    mtu INTEGER,
                    vlan INTEGER,
                    dot1q_support INTEGER DEFAULT 0,
                    rs_asn INTEGER,
                    arp_sponge TEXT,
                    status TEXT,
                    created_at TEXT,
                    updated_at TEXT,
                    last_synced TEXT,
                    source TEXT,
                    source_updated TEXT,
                    FOREIGN KEY (ix_id) REFERENCES exchanges(id)
                )
            """)

            # Sync status table
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS sync_status (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    source TEXT,
                    entity_type TEXT,
                    started_at TEXT,
                    completed_at TEXT,
                    status TEXT,
                    records_fetched INTEGER DEFAULT 0,
                    records_created INTEGER DEFAULT 0,
                    records_updated INTEGER DEFAULT 0,
                    records_deleted INTEGER DEFAULT 0,
                    error_message TEXT
                )
            """)

            # Create indexes for common queries
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_facilities_city ON facilities(city)")
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_facilities_country ON facilities(country)")
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_facilities_owner ON facilities(owner)")
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_facilities_clli ON facilities(clli_code)")
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_facilities_site_code ON facilities(site_code)")
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_facilities_peeringdb ON facilities(peeringdb_id)")

            cursor.execute("CREATE INDEX IF NOT EXISTS idx_networks_asn ON networks(asn)")
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_networks_name ON networks(name)")
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_networks_peeringdb ON networks(peeringdb_id)")

            cursor.execute("CREATE INDEX IF NOT EXISTS idx_netfac_facility ON network_facilities(facility_peeringdb_id)")
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_netfac_network ON network_facilities(network_peeringdb_id)")
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_netfac_asn ON network_facilities(network_asn)")

            cursor.execute("CREATE INDEX IF NOT EXISTS idx_carriers_name ON carriers(name)")
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_carriers_peeringdb ON carriers(peeringdb_id)")

            cursor.execute("CREATE INDEX IF NOT EXISTS idx_carrierfac_facility ON carrier_facilities(facility_peeringdb_id)")
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_carrierfac_carrier ON carrier_facilities(carrier_peeringdb_id)")

            cursor.execute("CREATE INDEX IF NOT EXISTS idx_exchanges_name ON exchanges(name)")
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_exchanges_country ON exchanges(country)")
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_exchanges_peeringdb ON exchanges(peeringdb_id)")

            cursor.execute("CREATE INDEX IF NOT EXISTS idx_ixfac_facility ON ix_facilities(facility_peeringdb_id)")
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_ixfac_ix ON ix_facilities(ix_peeringdb_id)")

            conn.commit()
            logger.info(f"Database initialized at {self._db_path}")

    # ================================================================
    # Facilities
    # ================================================================

    def upsert_facility(self, facility: Facility) -> Facility:
        """Insert or update a facility."""
        with self._get_connection() as conn:
            cursor = conn.cursor()
            now = datetime.now().isoformat()

            if facility.peeringdb_id:
                # Check if exists
                cursor.execute(
                    "SELECT id FROM facilities WHERE peeringdb_id = ?",
                    (facility.peeringdb_id,)
                )
                existing = cursor.fetchone()

                if existing:
                    # Update
                    cursor.execute("""
                        UPDATE facilities SET
                            name = ?, aka = ?, name_long = ?, website = ?,
                            clli_code = ?, site_code = ?, npa_nxx = ?,
                            owner = ?, owner_id = ?, operator = ?,
                            address1 = ?, address2 = ?, city = ?, state = ?,
                            zipcode = ?, country = ?, latitude = ?, longitude = ?,
                            floor_count = ?, square_feet = ?, power_mw = ?,
                            sales_email = ?, sales_phone = ?, tech_email = ?, tech_phone = ?,
                            status = ?, net_count = ?, ix_count = ?, notes = ?,
                            updated_at = ?, last_synced = ?, source = ?, source_updated = ?
                        WHERE peeringdb_id = ?
                    """, (
                        facility.name, facility.aka, facility.name_long, facility.website,
                        facility.clli_code, facility.site_code, facility.npa_nxx,
                        facility.owner, facility.owner_id, facility.operator,
                        facility.address1, facility.address2, facility.city, facility.state,
                        facility.zipcode, facility.country, facility.latitude, facility.longitude,
                        facility.floor_count, facility.square_feet, facility.power_mw,
                        facility.sales_email, facility.sales_phone, facility.tech_email, facility.tech_phone,
                        facility.status.value, facility.net_count, facility.ix_count, facility.notes,
                        now, now, facility.source,
                        facility.source_updated.isoformat() if facility.source_updated else None,
                        facility.peeringdb_id,
                    ))
                    facility.id = existing["id"]
                    conn.commit()
                    return facility

            # Insert new
            cursor.execute("""
                INSERT INTO facilities (
                    peeringdb_id, name, aka, name_long, website,
                    clli_code, site_code, npa_nxx,
                    owner, owner_id, operator,
                    address1, address2, city, state, zipcode, country,
                    latitude, longitude, floor_count, square_feet, power_mw,
                    sales_email, sales_phone, tech_email, tech_phone,
                    status, net_count, ix_count, notes,
                    created_at, updated_at, last_synced, source, source_updated
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                facility.peeringdb_id, facility.name, facility.aka, facility.name_long, facility.website,
                facility.clli_code, facility.site_code, facility.npa_nxx,
                facility.owner, facility.owner_id, facility.operator,
                facility.address1, facility.address2, facility.city, facility.state, facility.zipcode, facility.country,
                facility.latitude, facility.longitude, facility.floor_count, facility.square_feet, facility.power_mw,
                facility.sales_email, facility.sales_phone, facility.tech_email, facility.tech_phone,
                facility.status.value, facility.net_count, facility.ix_count, facility.notes,
                now, now, now, facility.source,
                facility.source_updated.isoformat() if facility.source_updated else None,
            ))

            facility.id = cursor.lastrowid
            conn.commit()
            return facility

    def upsert_facilities(self, facilities: list[Facility]) -> tuple[int, int]:
        """Bulk upsert facilities. Returns (created, updated) counts."""
        created = 0
        updated = 0

        with self._get_connection() as conn:
            cursor = conn.cursor()

            for facility in facilities:
                now = datetime.now().isoformat()

                if facility.peeringdb_id:
                    cursor.execute(
                        "SELECT id FROM facilities WHERE peeringdb_id = ?",
                        (facility.peeringdb_id,)
                    )
                    existing = cursor.fetchone()

                    if existing:
                        cursor.execute("""
                            UPDATE facilities SET
                                name = ?, aka = ?, name_long = ?, website = ?,
                                clli_code = ?, site_code = ?, npa_nxx = ?,
                                owner = ?, owner_id = ?, operator = ?,
                                address1 = ?, address2 = ?, city = ?, state = ?,
                                zipcode = ?, country = ?, latitude = ?, longitude = ?,
                                floor_count = ?, square_feet = ?, power_mw = ?,
                                sales_email = ?, sales_phone = ?, tech_email = ?, tech_phone = ?,
                                status = ?, net_count = ?, ix_count = ?, notes = ?,
                                updated_at = ?, last_synced = ?, source = ?, source_updated = ?
                            WHERE peeringdb_id = ?
                        """, (
                            facility.name, facility.aka, facility.name_long, facility.website,
                            facility.clli_code, facility.site_code, facility.npa_nxx,
                            facility.owner, facility.owner_id, facility.operator,
                            facility.address1, facility.address2, facility.city, facility.state,
                            facility.zipcode, facility.country, facility.latitude, facility.longitude,
                            facility.floor_count, facility.square_feet, facility.power_mw,
                            facility.sales_email, facility.sales_phone, facility.tech_email, facility.tech_phone,
                            facility.status.value, facility.net_count, facility.ix_count, facility.notes,
                            now, now, facility.source,
                            facility.source_updated.isoformat() if facility.source_updated else None,
                            facility.peeringdb_id,
                        ))
                        updated += 1
                        continue

                # Insert new
                cursor.execute("""
                    INSERT INTO facilities (
                        peeringdb_id, name, aka, name_long, website,
                        clli_code, site_code, npa_nxx,
                        owner, owner_id, operator,
                        address1, address2, city, state, zipcode, country,
                        latitude, longitude, floor_count, square_feet, power_mw,
                        sales_email, sales_phone, tech_email, tech_phone,
                        status, net_count, ix_count, notes,
                        created_at, updated_at, last_synced, source, source_updated
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """, (
                    facility.peeringdb_id, facility.name, facility.aka, facility.name_long, facility.website,
                    facility.clli_code, facility.site_code, facility.npa_nxx,
                    facility.owner, facility.owner_id, facility.operator,
                    facility.address1, facility.address2, facility.city, facility.state, facility.zipcode, facility.country,
                    facility.latitude, facility.longitude, facility.floor_count, facility.square_feet, facility.power_mw,
                    facility.sales_email, facility.sales_phone, facility.tech_email, facility.tech_phone,
                    facility.status.value, facility.net_count, facility.ix_count, facility.notes,
                    now, now, now, facility.source,
                    facility.source_updated.isoformat() if facility.source_updated else None,
                ))
                created += 1

            conn.commit()

        return created, updated

    def get_facility(
        self,
        id: int | None = None,
        peeringdb_id: int | None = None,
    ) -> Facility | None:
        """Get a single facility by ID."""
        with self._get_connection() as conn:
            cursor = conn.cursor()

            if id:
                cursor.execute("SELECT * FROM facilities WHERE id = ?", (id,))
            elif peeringdb_id:
                cursor.execute("SELECT * FROM facilities WHERE peeringdb_id = ?", (peeringdb_id,))
            else:
                return None

            row = cursor.fetchone()
            return self._row_to_facility(row) if row else None

    def search_facilities(
        self,
        name: str | None = None,
        city: str | None = None,
        state: str | None = None,
        country: str | None = None,
        owner: str | None = None,
        clli_code: str | None = None,
        site_code: str | None = None,
        limit: int = 100,
    ) -> list[Facility]:
        """Search facilities with various criteria."""
        with self._get_connection() as conn:
            cursor = conn.cursor()

            query = "SELECT * FROM facilities WHERE 1=1"
            params = []

            if name:
                query += " AND name LIKE ?"
                params.append(f"%{name}%")
            if city:
                query += " AND city LIKE ?"
                params.append(f"%{city}%")
            if state:
                query += " AND state LIKE ?"
                params.append(f"%{state}%")
            if country:
                query += " AND country = ?"
                params.append(country.upper())
            if owner:
                query += " AND owner LIKE ?"
                params.append(f"%{owner}%")
            if clli_code:
                query += " AND clli_code LIKE ?"
                params.append(f"%{clli_code}%")
            if site_code:
                query += " AND site_code LIKE ?"
                params.append(f"%{site_code}%")

            query += " ORDER BY name LIMIT ?"
            params.append(limit)

            cursor.execute(query, params)
            return [self._row_to_facility(row) for row in cursor.fetchall()]

    def list_facilities(
        self,
        country: str | None = None,
        limit: int = 1000,
        offset: int = 0,
    ) -> list[Facility]:
        """List all facilities with optional country filter."""
        with self._get_connection() as conn:
            cursor = conn.cursor()

            if country:
                cursor.execute(
                    "SELECT * FROM facilities WHERE country = ? ORDER BY name LIMIT ? OFFSET ?",
                    (country.upper(), limit, offset)
                )
            else:
                cursor.execute(
                    "SELECT * FROM facilities ORDER BY name LIMIT ? OFFSET ?",
                    (limit, offset)
                )

            return [self._row_to_facility(row) for row in cursor.fetchall()]

    def count_facilities(self, country: str | None = None) -> int:
        """Count facilities."""
        with self._get_connection() as conn:
            cursor = conn.cursor()

            if country:
                cursor.execute(
                    "SELECT COUNT(*) FROM facilities WHERE country = ?",
                    (country.upper(),)
                )
            else:
                cursor.execute("SELECT COUNT(*) FROM facilities")

            return cursor.fetchone()[0]

    def _row_to_facility(self, row: sqlite3.Row) -> Facility:
        """Convert database row to Facility object."""
        return Facility(
            id=row["id"],
            peeringdb_id=row["peeringdb_id"],
            name=row["name"],
            aka=row["aka"],
            name_long=row["name_long"],
            website=row["website"],
            clli_code=row["clli_code"],
            site_code=row["site_code"],
            npa_nxx=row["npa_nxx"],
            owner=row["owner"],
            owner_id=row["owner_id"],
            operator=row["operator"],
            address1=row["address1"],
            address2=row["address2"],
            city=row["city"],
            state=row["state"],
            zipcode=row["zipcode"],
            country=row["country"],
            latitude=row["latitude"],
            longitude=row["longitude"],
            floor_count=row["floor_count"],
            square_feet=row["square_feet"],
            power_mw=row["power_mw"],
            sales_email=row["sales_email"],
            sales_phone=row["sales_phone"],
            tech_email=row["tech_email"],
            tech_phone=row["tech_phone"],
            status=FacilityStatus(row["status"]) if row["status"] else FacilityStatus.UNKNOWN,
            net_count=row["net_count"],
            ix_count=row["ix_count"],
            notes=row["notes"],
            created_at=datetime.fromisoformat(row["created_at"]) if row["created_at"] else None,
            updated_at=datetime.fromisoformat(row["updated_at"]) if row["updated_at"] else None,
            last_synced=datetime.fromisoformat(row["last_synced"]) if row["last_synced"] else None,
            source=row["source"],
            source_updated=datetime.fromisoformat(row["source_updated"]) if row["source_updated"] else None,
        )

    # ================================================================
    # Networks
    # ================================================================

    def upsert_network(self, network: Network) -> Network:
        """Insert or update a network."""
        with self._get_connection() as conn:
            cursor = conn.cursor()
            now = datetime.now().isoformat()

            if network.peeringdb_id:
                cursor.execute(
                    "SELECT id FROM networks WHERE peeringdb_id = ?",
                    (network.peeringdb_id,)
                )
                existing = cursor.fetchone()

                if existing:
                    cursor.execute("""
                        UPDATE networks SET
                            asn = ?, name = ?, aka = ?, website = ?,
                            looking_glass = ?, route_server = ?,
                            org_name = ?, org_id = ?,
                            info_type = ?, info_prefixes4 = ?, info_prefixes6 = ?,
                            info_traffic = ?, info_ratio = ?, info_scope = ?,
                            policy_general = ?, policy_url = ?, policy_locations = ?,
                            policy_ratio = ?, policy_contracts = ?, irr_as_set = ?,
                            status = ?, fac_count = ?, ix_count = ?,
                            updated_at = ?, last_synced = ?, source = ?, source_updated = ?
                        WHERE peeringdb_id = ?
                    """, (
                        network.asn, network.name, network.aka, network.website,
                        network.looking_glass, network.route_server,
                        network.org_name, network.org_id,
                        network.info_type, network.info_prefixes4, network.info_prefixes6,
                        network.info_traffic, network.info_ratio, network.info_scope,
                        network.policy_general, network.policy_url, network.policy_locations,
                        1 if network.policy_ratio else 0, network.policy_contracts, network.irr_as_set,
                        network.status, network.fac_count, network.ix_count,
                        now, now, network.source,
                        network.source_updated.isoformat() if network.source_updated else None,
                        network.peeringdb_id,
                    ))
                    network.id = existing["id"]
                    conn.commit()
                    return network

            cursor.execute("""
                INSERT INTO networks (
                    peeringdb_id, asn, name, aka, website,
                    looking_glass, route_server,
                    org_name, org_id,
                    info_type, info_prefixes4, info_prefixes6,
                    info_traffic, info_ratio, info_scope,
                    policy_general, policy_url, policy_locations,
                    policy_ratio, policy_contracts, irr_as_set,
                    status, fac_count, ix_count,
                    created_at, updated_at, last_synced, source, source_updated
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                network.peeringdb_id, network.asn, network.name, network.aka, network.website,
                network.looking_glass, network.route_server,
                network.org_name, network.org_id,
                network.info_type, network.info_prefixes4, network.info_prefixes6,
                network.info_traffic, network.info_ratio, network.info_scope,
                network.policy_general, network.policy_url, network.policy_locations,
                1 if network.policy_ratio else 0, network.policy_contracts, network.irr_as_set,
                network.status, network.fac_count, network.ix_count,
                now, now, now, network.source,
                network.source_updated.isoformat() if network.source_updated else None,
            ))

            network.id = cursor.lastrowid
            conn.commit()
            return network

    def upsert_networks(self, networks: list[Network]) -> tuple[int, int]:
        """Bulk upsert networks. Returns (created, updated) counts."""
        created = 0
        updated = 0

        with self._get_connection() as conn:
            cursor = conn.cursor()

            for network in networks:
                now = datetime.now().isoformat()

                if network.peeringdb_id:
                    cursor.execute(
                        "SELECT id FROM networks WHERE peeringdb_id = ?",
                        (network.peeringdb_id,)
                    )
                    existing = cursor.fetchone()

                    if existing:
                        cursor.execute("""
                            UPDATE networks SET
                                asn = ?, name = ?, aka = ?, website = ?,
                                looking_glass = ?, route_server = ?,
                                org_name = ?, org_id = ?,
                                info_type = ?, info_prefixes4 = ?, info_prefixes6 = ?,
                                info_traffic = ?, info_ratio = ?, info_scope = ?,
                                policy_general = ?, policy_url = ?, policy_locations = ?,
                                policy_ratio = ?, policy_contracts = ?, irr_as_set = ?,
                                status = ?, fac_count = ?, ix_count = ?,
                                updated_at = ?, last_synced = ?, source = ?, source_updated = ?
                            WHERE peeringdb_id = ?
                        """, (
                            network.asn, network.name, network.aka, network.website,
                            network.looking_glass, network.route_server,
                            network.org_name, network.org_id,
                            network.info_type, network.info_prefixes4, network.info_prefixes6,
                            network.info_traffic, network.info_ratio, network.info_scope,
                            network.policy_general, network.policy_url, network.policy_locations,
                            1 if network.policy_ratio else 0, network.policy_contracts, network.irr_as_set,
                            network.status, network.fac_count, network.ix_count,
                            now, now, network.source,
                            network.source_updated.isoformat() if network.source_updated else None,
                            network.peeringdb_id,
                        ))
                        updated += 1
                        continue

                cursor.execute("""
                    INSERT INTO networks (
                        peeringdb_id, asn, name, aka, website,
                        looking_glass, route_server,
                        org_name, org_id,
                        info_type, info_prefixes4, info_prefixes6,
                        info_traffic, info_ratio, info_scope,
                        policy_general, policy_url, policy_locations,
                        policy_ratio, policy_contracts, irr_as_set,
                        status, fac_count, ix_count,
                        created_at, updated_at, last_synced, source, source_updated
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """, (
                    network.peeringdb_id, network.asn, network.name, network.aka, network.website,
                    network.looking_glass, network.route_server,
                    network.org_name, network.org_id,
                    network.info_type, network.info_prefixes4, network.info_prefixes6,
                    network.info_traffic, network.info_ratio, network.info_scope,
                    network.policy_general, network.policy_url, network.policy_locations,
                    1 if network.policy_ratio else 0, network.policy_contracts, network.irr_as_set,
                    network.status, network.fac_count, network.ix_count,
                    now, now, now, network.source,
                    network.source_updated.isoformat() if network.source_updated else None,
                ))
                created += 1

            conn.commit()

        return created, updated

    def get_network(
        self,
        id: int | None = None,
        peeringdb_id: int | None = None,
        asn: int | None = None,
    ) -> Network | None:
        """Get a single network by ID or ASN."""
        with self._get_connection() as conn:
            cursor = conn.cursor()

            if id:
                cursor.execute("SELECT * FROM networks WHERE id = ?", (id,))
            elif peeringdb_id:
                cursor.execute("SELECT * FROM networks WHERE peeringdb_id = ?", (peeringdb_id,))
            elif asn:
                cursor.execute("SELECT * FROM networks WHERE asn = ?", (asn,))
            else:
                return None

            row = cursor.fetchone()
            return self._row_to_network(row) if row else None

    def search_networks(
        self,
        name: str | None = None,
        asn: int | None = None,
        info_type: str | None = None,
        limit: int = 100,
    ) -> list[Network]:
        """Search networks."""
        with self._get_connection() as conn:
            cursor = conn.cursor()

            query = "SELECT * FROM networks WHERE 1=1"
            params = []

            if name:
                query += " AND name LIKE ?"
                params.append(f"%{name}%")
            if asn:
                query += " AND asn = ?"
                params.append(asn)
            if info_type:
                query += " AND info_type = ?"
                params.append(info_type)

            query += " ORDER BY name LIMIT ?"
            params.append(limit)

            cursor.execute(query, params)
            return [self._row_to_network(row) for row in cursor.fetchall()]

    def count_networks(self) -> int:
        """Count networks."""
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT COUNT(*) FROM networks")
            return cursor.fetchone()[0]

    def _row_to_network(self, row: sqlite3.Row) -> Network:
        """Convert database row to Network object."""
        return Network(
            id=row["id"],
            peeringdb_id=row["peeringdb_id"],
            asn=row["asn"],
            name=row["name"],
            aka=row["aka"],
            website=row["website"],
            looking_glass=row["looking_glass"],
            route_server=row["route_server"],
            org_name=row["org_name"],
            org_id=row["org_id"],
            info_type=row["info_type"],
            info_prefixes4=row["info_prefixes4"],
            info_prefixes6=row["info_prefixes6"],
            info_traffic=row["info_traffic"],
            info_ratio=row["info_ratio"],
            info_scope=row["info_scope"],
            policy_general=row["policy_general"],
            policy_url=row["policy_url"],
            policy_locations=row["policy_locations"],
            policy_ratio=bool(row["policy_ratio"]),
            policy_contracts=row["policy_contracts"],
            irr_as_set=row["irr_as_set"],
            status=row["status"],
            fac_count=row["fac_count"],
            ix_count=row["ix_count"],
            created_at=datetime.fromisoformat(row["created_at"]) if row["created_at"] else None,
            updated_at=datetime.fromisoformat(row["updated_at"]) if row["updated_at"] else None,
            last_synced=datetime.fromisoformat(row["last_synced"]) if row["last_synced"] else None,
            source=row["source"],
            source_updated=datetime.fromisoformat(row["source_updated"]) if row["source_updated"] else None,
        )

    # ================================================================
    # Network-Facility relationships
    # ================================================================

    def upsert_network_facilities(self, netfacs: list[NetworkPresence]) -> tuple[int, int]:
        """Bulk upsert network-facility relationships."""
        created = 0
        updated = 0

        with self._get_connection() as conn:
            cursor = conn.cursor()

            for nf in netfacs:
                now = datetime.now().isoformat()

                if nf.peeringdb_id:
                    cursor.execute(
                        "SELECT id FROM network_facilities WHERE peeringdb_id = ?",
                        (nf.peeringdb_id,)
                    )
                    existing = cursor.fetchone()

                    if existing:
                        cursor.execute("""
                            UPDATE network_facilities SET
                                facility_peeringdb_id = ?, network_asn = ?,
                                network_name = ?, network_peeringdb_id = ?,
                                local_asn = ?, avail_sonet = ?, avail_ethernet = ?,
                                avail_atm = ?, status = ?,
                                updated_at = ?, last_synced = ?, source = ?, source_updated = ?
                            WHERE peeringdb_id = ?
                        """, (
                            nf.facility_peeringdb_id, nf.network_asn,
                            nf.network_name, nf.network_peeringdb_id,
                            nf.local_asn, 1 if nf.avail_sonet else 0, 1 if nf.avail_ethernet else 0,
                            1 if nf.avail_atm else 0, nf.status,
                            now, now, nf.source,
                            nf.source_updated.isoformat() if nf.source_updated else None,
                            nf.peeringdb_id,
                        ))
                        updated += 1
                        continue

                cursor.execute("""
                    INSERT INTO network_facilities (
                        peeringdb_id, facility_peeringdb_id, network_asn,
                        network_name, network_peeringdb_id,
                        local_asn, avail_sonet, avail_ethernet, avail_atm, status,
                        created_at, updated_at, last_synced, source, source_updated
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """, (
                    nf.peeringdb_id, nf.facility_peeringdb_id, nf.network_asn,
                    nf.network_name, nf.network_peeringdb_id,
                    nf.local_asn, 1 if nf.avail_sonet else 0, 1 if nf.avail_ethernet else 0,
                    1 if nf.avail_atm else 0, nf.status,
                    now, now, now, nf.source,
                    nf.source_updated.isoformat() if nf.source_updated else None,
                ))
                created += 1

            conn.commit()

        return created, updated

    def get_networks_at_facility(self, facility_peeringdb_id: int) -> list[dict[str, Any]]:
        """Get all networks present at a facility with details."""
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                SELECT nf.*, n.name, n.asn, n.info_type, n.policy_general, n.org_name
                FROM network_facilities nf
                LEFT JOIN networks n ON nf.network_peeringdb_id = n.peeringdb_id
                WHERE nf.facility_peeringdb_id = ?
                ORDER BY n.name
            """, (facility_peeringdb_id,))

            results = []
            for row in cursor.fetchall():
                results.append({
                    "asn": row["asn"],
                    "name": row["name"],
                    "type": row["info_type"],
                    "policy": row["policy_general"],
                    "org": row["org_name"],
                    "local_asn": row["local_asn"],
                })
            return results

    def count_network_facilities(self) -> int:
        """Count network-facility relationships."""
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT COUNT(*) FROM network_facilities")
            return cursor.fetchone()[0]

    # ================================================================
    # Carriers
    # ================================================================

    def upsert_carriers(self, carriers: list[Carrier]) -> tuple[int, int]:
        """Bulk upsert carriers."""
        created = 0
        updated = 0

        with self._get_connection() as conn:
            cursor = conn.cursor()

            for carrier in carriers:
                now = datetime.now().isoformat()

                if carrier.peeringdb_id:
                    cursor.execute(
                        "SELECT id FROM carriers WHERE peeringdb_id = ?",
                        (carrier.peeringdb_id,)
                    )
                    existing = cursor.fetchone()

                    if existing:
                        cursor.execute("""
                            UPDATE carriers SET
                                name = ?, aka = ?, website = ?,
                                org_name = ?, org_id = ?, status = ?,
                                updated_at = ?, last_synced = ?, source = ?, source_updated = ?
                            WHERE peeringdb_id = ?
                        """, (
                            carrier.name, carrier.aka, carrier.website,
                            carrier.org_name, carrier.org_id, carrier.status,
                            now, now, carrier.source,
                            carrier.source_updated.isoformat() if carrier.source_updated else None,
                            carrier.peeringdb_id,
                        ))
                        updated += 1
                        continue

                cursor.execute("""
                    INSERT INTO carriers (
                        peeringdb_id, name, aka, website,
                        org_name, org_id, status,
                        created_at, updated_at, last_synced, source, source_updated
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """, (
                    carrier.peeringdb_id, carrier.name, carrier.aka, carrier.website,
                    carrier.org_name, carrier.org_id, carrier.status,
                    now, now, now, carrier.source,
                    carrier.source_updated.isoformat() if carrier.source_updated else None,
                ))
                created += 1

            conn.commit()

        return created, updated

    def search_carriers(self, name: str | None = None, limit: int = 100) -> list[Carrier]:
        """Search carriers by name."""
        with self._get_connection() as conn:
            cursor = conn.cursor()

            if name:
                cursor.execute(
                    "SELECT * FROM carriers WHERE name LIKE ? ORDER BY name LIMIT ?",
                    (f"%{name}%", limit)
                )
            else:
                cursor.execute("SELECT * FROM carriers ORDER BY name LIMIT ?", (limit,))

            return [self._row_to_carrier(row) for row in cursor.fetchall()]

    def count_carriers(self) -> int:
        """Count carriers."""
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT COUNT(*) FROM carriers")
            return cursor.fetchone()[0]

    def _row_to_carrier(self, row: sqlite3.Row) -> Carrier:
        """Convert database row to Carrier object."""
        return Carrier(
            id=row["id"],
            peeringdb_id=row["peeringdb_id"],
            name=row["name"],
            aka=row["aka"],
            website=row["website"],
            org_name=row["org_name"],
            org_id=row["org_id"],
            status=row["status"],
            created_at=datetime.fromisoformat(row["created_at"]) if row["created_at"] else None,
            updated_at=datetime.fromisoformat(row["updated_at"]) if row["updated_at"] else None,
            last_synced=datetime.fromisoformat(row["last_synced"]) if row["last_synced"] else None,
            source=row["source"],
            source_updated=datetime.fromisoformat(row["source_updated"]) if row["source_updated"] else None,
        )

    # ================================================================
    # Carrier-Facility relationships
    # ================================================================

    def upsert_carrier_facilities(self, carrierfacs: list[CarrierPresence]) -> tuple[int, int]:
        """Bulk upsert carrier-facility relationships."""
        created = 0
        updated = 0

        with self._get_connection() as conn:
            cursor = conn.cursor()

            for cf in carrierfacs:
                now = datetime.now().isoformat()

                if cf.peeringdb_id:
                    cursor.execute(
                        "SELECT id FROM carrier_facilities WHERE peeringdb_id = ?",
                        (cf.peeringdb_id,)
                    )
                    existing = cursor.fetchone()

                    if existing:
                        cursor.execute("""
                            UPDATE carrier_facilities SET
                                facility_peeringdb_id = ?, carrier_peeringdb_id = ?,
                                carrier_name = ?, status = ?,
                                updated_at = ?, last_synced = ?, source = ?, source_updated = ?
                            WHERE peeringdb_id = ?
                        """, (
                            cf.facility_peeringdb_id, cf.carrier_peeringdb_id,
                            cf.carrier_name, cf.status,
                            now, now, cf.source,
                            cf.source_updated.isoformat() if cf.source_updated else None,
                            cf.peeringdb_id,
                        ))
                        updated += 1
                        continue

                cursor.execute("""
                    INSERT INTO carrier_facilities (
                        peeringdb_id, facility_peeringdb_id, carrier_peeringdb_id,
                        carrier_name, status,
                        created_at, updated_at, last_synced, source, source_updated
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """, (
                    cf.peeringdb_id, cf.facility_peeringdb_id, cf.carrier_peeringdb_id,
                    cf.carrier_name, cf.status,
                    now, now, now, cf.source,
                    cf.source_updated.isoformat() if cf.source_updated else None,
                ))
                created += 1

            conn.commit()

        return created, updated

    def get_carriers_at_facility(self, facility_peeringdb_id: int) -> list[dict[str, Any]]:
        """Get all carriers present at a facility."""
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                SELECT cf.*, c.name, c.org_name, c.website
                FROM carrier_facilities cf
                LEFT JOIN carriers c ON cf.carrier_peeringdb_id = c.peeringdb_id
                WHERE cf.facility_peeringdb_id = ?
                ORDER BY c.name
            """, (facility_peeringdb_id,))

            results = []
            for row in cursor.fetchall():
                results.append({
                    "name": row["name"],
                    "org": row["org_name"],
                    "website": row["website"],
                    "peeringdb_id": row["carrier_peeringdb_id"],
                })
            return results

    def count_carrier_facilities(self) -> int:
        """Count carrier-facility relationships."""
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT COUNT(*) FROM carrier_facilities")
            return cursor.fetchone()[0]

    # ================================================================
    # Internet Exchanges
    # ================================================================

    def upsert_exchanges(self, exchanges: list[InternetExchange]) -> tuple[int, int]:
        """Bulk upsert Internet Exchanges."""
        created = 0
        updated = 0

        with self._get_connection() as conn:
            cursor = conn.cursor()

            for ix in exchanges:
                now = datetime.now().isoformat()

                if ix.peeringdb_id:
                    cursor.execute(
                        "SELECT id FROM exchanges WHERE peeringdb_id = ?",
                        (ix.peeringdb_id,)
                    )
                    existing = cursor.fetchone()

                    if existing:
                        cursor.execute("""
                            UPDATE exchanges SET
                                name = ?, name_long = ?, aka = ?, website = ?,
                                url_stats = ?, org_name = ?, org_id = ?,
                                city = ?, country = ?, region_continent = ?,
                                media = ?, proto_unicast = ?, proto_multicast = ?, proto_ipv6 = ?,
                                policy_email = ?, policy_phone = ?, status = ?,
                                net_count = ?, fac_count = ?,
                                updated_at = ?, last_synced = ?, source = ?, source_updated = ?
                            WHERE peeringdb_id = ?
                        """, (
                            ix.name, ix.name_long, ix.aka, ix.website,
                            ix.url_stats, ix.org_name, ix.org_id,
                            ix.city, ix.country, ix.region_continent,
                            ix.media, 1 if ix.proto_unicast else 0, 1 if ix.proto_multicast else 0, 1 if ix.proto_ipv6 else 0,
                            ix.policy_email, ix.policy_phone, ix.status,
                            ix.net_count, ix.fac_count,
                            now, now, ix.source,
                            ix.source_updated.isoformat() if ix.source_updated else None,
                            ix.peeringdb_id,
                        ))
                        updated += 1
                        continue

                cursor.execute("""
                    INSERT INTO exchanges (
                        peeringdb_id, name, name_long, aka, website,
                        url_stats, org_name, org_id,
                        city, country, region_continent,
                        media, proto_unicast, proto_multicast, proto_ipv6,
                        policy_email, policy_phone, status,
                        net_count, fac_count,
                        created_at, updated_at, last_synced, source, source_updated
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """, (
                    ix.peeringdb_id, ix.name, ix.name_long, ix.aka, ix.website,
                    ix.url_stats, ix.org_name, ix.org_id,
                    ix.city, ix.country, ix.region_continent,
                    ix.media, 1 if ix.proto_unicast else 0, 1 if ix.proto_multicast else 0, 1 if ix.proto_ipv6 else 0,
                    ix.policy_email, ix.policy_phone, ix.status,
                    ix.net_count, ix.fac_count,
                    now, now, now, ix.source,
                    ix.source_updated.isoformat() if ix.source_updated else None,
                ))
                created += 1

            conn.commit()

        return created, updated

    def search_exchanges(
        self,
        name: str | None = None,
        country: str | None = None,
        limit: int = 100,
    ) -> list[InternetExchange]:
        """Search Internet Exchanges."""
        with self._get_connection() as conn:
            cursor = conn.cursor()

            query = "SELECT * FROM exchanges WHERE 1=1"
            params = []

            if name:
                query += " AND name LIKE ?"
                params.append(f"%{name}%")
            if country:
                query += " AND country = ?"
                params.append(country.upper())

            query += " ORDER BY name LIMIT ?"
            params.append(limit)

            cursor.execute(query, params)
            return [self._row_to_exchange(row) for row in cursor.fetchall()]

    def count_exchanges(self) -> int:
        """Count exchanges."""
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT COUNT(*) FROM exchanges")
            return cursor.fetchone()[0]

    def _row_to_exchange(self, row: sqlite3.Row) -> InternetExchange:
        """Convert database row to InternetExchange object."""
        return InternetExchange(
            id=row["id"],
            peeringdb_id=row["peeringdb_id"],
            name=row["name"],
            name_long=row["name_long"],
            aka=row["aka"],
            website=row["website"],
            url_stats=row["url_stats"],
            org_name=row["org_name"],
            org_id=row["org_id"],
            city=row["city"],
            country=row["country"],
            region_continent=row["region_continent"],
            media=row["media"],
            proto_unicast=bool(row["proto_unicast"]),
            proto_multicast=bool(row["proto_multicast"]),
            proto_ipv6=bool(row["proto_ipv6"]),
            policy_email=row["policy_email"],
            policy_phone=row["policy_phone"],
            status=row["status"],
            net_count=row["net_count"],
            fac_count=row["fac_count"],
            created_at=datetime.fromisoformat(row["created_at"]) if row["created_at"] else None,
            updated_at=datetime.fromisoformat(row["updated_at"]) if row["updated_at"] else None,
            last_synced=datetime.fromisoformat(row["last_synced"]) if row["last_synced"] else None,
            source=row["source"],
            source_updated=datetime.fromisoformat(row["source_updated"]) if row["source_updated"] else None,
        )

    # ================================================================
    # IX-Facility relationships
    # ================================================================

    def upsert_ix_facilities(self, ixfacs: list[IXFacility]) -> tuple[int, int]:
        """Bulk upsert IX-facility relationships."""
        created = 0
        updated = 0

        with self._get_connection() as conn:
            cursor = conn.cursor()

            for ixf in ixfacs:
                now = datetime.now().isoformat()

                if ixf.peeringdb_id:
                    cursor.execute(
                        "SELECT id FROM ix_facilities WHERE peeringdb_id = ?",
                        (ixf.peeringdb_id,)
                    )
                    existing = cursor.fetchone()

                    if existing:
                        cursor.execute("""
                            UPDATE ix_facilities SET
                                ix_peeringdb_id = ?, facility_peeringdb_id = ?, status = ?,
                                updated_at = ?, last_synced = ?, source = ?, source_updated = ?
                            WHERE peeringdb_id = ?
                        """, (
                            ixf.ix_peeringdb_id, ixf.facility_peeringdb_id, ixf.status,
                            now, now, ixf.source,
                            ixf.source_updated.isoformat() if ixf.source_updated else None,
                            ixf.peeringdb_id,
                        ))
                        updated += 1
                        continue

                cursor.execute("""
                    INSERT INTO ix_facilities (
                        peeringdb_id, ix_peeringdb_id, facility_peeringdb_id, status,
                        created_at, updated_at, last_synced, source, source_updated
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                """, (
                    ixf.peeringdb_id, ixf.ix_peeringdb_id, ixf.facility_peeringdb_id, ixf.status,
                    now, now, now, ixf.source,
                    ixf.source_updated.isoformat() if ixf.source_updated else None,
                ))
                created += 1

            conn.commit()

        return created, updated

    def get_ixs_at_facility(self, facility_peeringdb_id: int) -> list[dict[str, Any]]:
        """Get all IXs present at a facility."""
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                SELECT ixf.*, ix.name, ix.city, ix.country, ix.net_count
                FROM ix_facilities ixf
                LEFT JOIN exchanges ix ON ixf.ix_peeringdb_id = ix.peeringdb_id
                WHERE ixf.facility_peeringdb_id = ?
                ORDER BY ix.name
            """, (facility_peeringdb_id,))

            results = []
            for row in cursor.fetchall():
                results.append({
                    "name": row["name"],
                    "city": row["city"],
                    "country": row["country"],
                    "net_count": row["net_count"],
                    "peeringdb_id": row["ix_peeringdb_id"],
                })
            return results

    def count_ix_facilities(self) -> int:
        """Count IX-facility relationships."""
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT COUNT(*) FROM ix_facilities")
            return cursor.fetchone()[0]

    # ================================================================
    # Sync Status
    # ================================================================

    def create_sync_status(self, status: SyncStatus) -> SyncStatus:
        """Create a new sync status record."""
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                INSERT INTO sync_status (
                    source, entity_type, started_at, status
                ) VALUES (?, ?, ?, ?)
            """, (
                status.source, status.entity_type,
                status.started_at.isoformat() if status.started_at else datetime.now().isoformat(),
                status.status or "running",
            ))
            status.id = cursor.lastrowid
            conn.commit()
            return status

    def update_sync_status(self, status: SyncStatus):
        """Update a sync status record."""
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                UPDATE sync_status SET
                    completed_at = ?, status = ?,
                    records_fetched = ?, records_created = ?,
                    records_updated = ?, records_deleted = ?,
                    error_message = ?
                WHERE id = ?
            """, (
                status.completed_at.isoformat() if status.completed_at else None,
                status.status, status.records_fetched, status.records_created,
                status.records_updated, status.records_deleted,
                status.error_message, status.id,
            ))
            conn.commit()

    def get_last_sync(self, source: str, entity_type: str) -> SyncStatus | None:
        """Get the most recent successful sync for an entity type."""
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                SELECT * FROM sync_status
                WHERE source = ? AND entity_type = ? AND status = 'completed'
                ORDER BY completed_at DESC LIMIT 1
            """, (source, entity_type))

            row = cursor.fetchone()
            if not row:
                return None

            return SyncStatus(
                id=row["id"],
                source=row["source"],
                entity_type=row["entity_type"],
                started_at=datetime.fromisoformat(row["started_at"]) if row["started_at"] else None,
                completed_at=datetime.fromisoformat(row["completed_at"]) if row["completed_at"] else None,
                status=row["status"],
                records_fetched=row["records_fetched"],
                records_created=row["records_created"],
                records_updated=row["records_updated"],
                records_deleted=row["records_deleted"],
                error_message=row["error_message"],
            )

    def get_sync_history(self, limit: int = 20) -> list[SyncStatus]:
        """Get recent sync history."""
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                SELECT * FROM sync_status
                ORDER BY started_at DESC LIMIT ?
            """, (limit,))

            results = []
            for row in cursor.fetchall():
                results.append(SyncStatus(
                    id=row["id"],
                    source=row["source"],
                    entity_type=row["entity_type"],
                    started_at=datetime.fromisoformat(row["started_at"]) if row["started_at"] else None,
                    completed_at=datetime.fromisoformat(row["completed_at"]) if row["completed_at"] else None,
                    status=row["status"],
                    records_fetched=row["records_fetched"],
                    records_created=row["records_created"],
                    records_updated=row["records_updated"],
                    records_deleted=row["records_deleted"],
                    error_message=row["error_message"],
                ))
            return results

    # ================================================================
    # Statistics
    # ================================================================

    def get_stats(self) -> dict[str, Any]:
        """Get database statistics."""
        with self._get_connection() as conn:
            cursor = conn.cursor()

            # Get counts
            cursor.execute("SELECT COUNT(*) FROM facilities")
            facility_count = cursor.fetchone()[0]

            cursor.execute("SELECT COUNT(*) FROM networks")
            network_count = cursor.fetchone()[0]

            cursor.execute("SELECT COUNT(*) FROM carriers")
            carrier_count = cursor.fetchone()[0]

            cursor.execute("SELECT COUNT(*) FROM exchanges")
            exchange_count = cursor.fetchone()[0]

            cursor.execute("SELECT COUNT(*) FROM network_facilities")
            netfac_count = cursor.fetchone()[0]

            cursor.execute("SELECT COUNT(*) FROM carrier_facilities")
            carrierfac_count = cursor.fetchone()[0]

            cursor.execute("SELECT COUNT(*) FROM ix_facilities")
            ixfac_count = cursor.fetchone()[0]

            # Get top countries
            cursor.execute("""
                SELECT country, COUNT(*) as count
                FROM facilities
                WHERE country IS NOT NULL
                GROUP BY country
                ORDER BY count DESC
                LIMIT 10
            """)
            top_countries = [{"country": row[0], "count": row[1]} for row in cursor.fetchall()]

            # Get last sync times
            last_sync = self.get_last_sync("peeringdb", "facilities")

            return {
                "facilities": facility_count,
                "networks": network_count,
                "carriers": carrier_count,
                "exchanges": exchange_count,
                "network_facilities": netfac_count,
                "carrier_facilities": carrierfac_count,
                "ix_facilities": ixfac_count,
                "top_countries": top_countries,
                "last_sync": last_sync.to_dict() if last_sync else None,
                "database_path": str(self._db_path),
            }
