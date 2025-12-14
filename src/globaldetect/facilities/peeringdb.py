"""
PeeringDB API client.

Provides access to facility, carrier, network, and IX data from PeeringDB.

API Documentation: https://www.peeringdb.com/apidocs/
API Specs: https://docs.peeringdb.com/api_specs/

Copyright (c) 2025 DNS Science.io, an After Dark Systems, LLC company.
All rights reserved.
"""

import asyncio
import logging
from dataclasses import dataclass
from datetime import datetime
from typing import Any
from urllib.parse import urlencode

import httpx

from globaldetect.facilities.models import (
    Carrier,
    CarrierPresence,
    Facility,
    InternetExchange,
    IXFacility,
    IXLan,
    Network,
    NetworkPresence,
)

logger = logging.getLogger(__name__)

# PeeringDB API base URL
PEERINGDB_API_BASE = "https://www.peeringdb.com/api"


@dataclass
class PeeringDBConfig:
    """Configuration for PeeringDB API client."""
    base_url: str = PEERINGDB_API_BASE
    api_key: str | None = None  # Optional - higher rate limits with key
    username: str | None = None  # Optional - for authenticated requests
    password: str | None = None

    timeout: float = 30.0
    max_retries: int = 3
    retry_delay: float = 1.0

    # Rate limiting
    requests_per_second: float = 2.0  # Be nice to the API


class PeeringDBError(Exception):
    """Base exception for PeeringDB errors."""
    pass


class PeeringDBRateLimitError(PeeringDBError):
    """Rate limit exceeded."""
    pass


class PeeringDBClient:
    """
    Async client for PeeringDB API.

    Usage:
        async with PeeringDBClient() as client:
            facilities = await client.get_facilities(country="US")
    """

    def __init__(self, config: PeeringDBConfig | None = None):
        self.config = config or PeeringDBConfig()
        self._client: httpx.AsyncClient | None = None
        self._last_request: float = 0
        self._lock = asyncio.Lock()

    async def __aenter__(self) -> "PeeringDBClient":
        await self.connect()
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        await self.close()

    async def connect(self):
        """Initialize the HTTP client."""
        headers = {
            "User-Agent": "globaldetect/1.0 (https://github.com/dnsscience/globaldetect)",
            "Accept": "application/json",
        }

        # Add API key if configured
        if self.config.api_key:
            headers["Authorization"] = f"Api-Key {self.config.api_key}"

        # Basic auth if configured
        auth = None
        if self.config.username and self.config.password:
            auth = httpx.BasicAuth(self.config.username, self.config.password)

        self._client = httpx.AsyncClient(
            base_url=self.config.base_url,
            headers=headers,
            auth=auth,
            timeout=self.config.timeout,
            follow_redirects=True,
        )

    async def close(self):
        """Close the HTTP client."""
        if self._client:
            await self._client.aclose()
            self._client = None

    async def _rate_limit(self):
        """Enforce rate limiting."""
        async with self._lock:
            now = asyncio.get_event_loop().time()
            elapsed = now - self._last_request
            min_interval = 1.0 / self.config.requests_per_second

            if elapsed < min_interval:
                await asyncio.sleep(min_interval - elapsed)

            self._last_request = asyncio.get_event_loop().time()

    async def _request(
        self,
        endpoint: str,
        params: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        """Make a request to the PeeringDB API."""
        if not self._client:
            await self.connect()

        await self._rate_limit()

        url = f"/{endpoint}"
        if params:
            # Filter out None values
            params = {k: v for k, v in params.items() if v is not None}

        for attempt in range(self.config.max_retries):
            try:
                response = await self._client.get(url, params=params)

                if response.status_code == 429:
                    retry_after = int(response.headers.get("Retry-After", 60))
                    logger.warning(f"Rate limited, waiting {retry_after}s")
                    await asyncio.sleep(retry_after)
                    continue

                response.raise_for_status()
                return response.json()

            except httpx.HTTPStatusError as e:
                if attempt == self.config.max_retries - 1:
                    raise PeeringDBError(f"HTTP error: {e}") from e
                await asyncio.sleep(self.config.retry_delay * (attempt + 1))

            except httpx.RequestError as e:
                if attempt == self.config.max_retries - 1:
                    raise PeeringDBError(f"Request error: {e}") from e
                await asyncio.sleep(self.config.retry_delay * (attempt + 1))

        raise PeeringDBError("Max retries exceeded")

    # ================================================================
    # Facilities
    # ================================================================

    async def get_facilities(
        self,
        id: int | None = None,
        name: str | None = None,
        city: str | None = None,
        state: str | None = None,
        country: str | None = None,
        org_id: int | None = None,
        since: datetime | None = None,
        limit: int | None = None,
        skip: int | None = None,
    ) -> list[Facility]:
        """
        Get facilities from PeeringDB.

        Args:
            id: Filter by PeeringDB facility ID
            name: Filter by facility name (partial match with __contains)
            city: Filter by city
            state: Filter by state/region
            country: Filter by country (ISO 3166-1 alpha-2)
            org_id: Filter by organization ID
            since: Only return records updated since this time
            limit: Maximum number of results
            skip: Number of results to skip

        Returns:
            List of Facility objects
        """
        params = {
            "id": id,
            "name__contains": name if name else None,
            "city": city,
            "state": state,
            "country": country,
            "org_id": org_id,
            "since": since.timestamp() if since else None,
            "limit": limit,
            "skip": skip,
        }

        data = await self._request("fac", params)
        return [Facility.from_peeringdb(fac) for fac in data.get("data", [])]

    async def get_facility(self, id: int) -> Facility | None:
        """Get a single facility by ID."""
        facilities = await self.get_facilities(id=id)
        return facilities[0] if facilities else None

    async def get_all_facilities(
        self,
        since: datetime | None = None,
        batch_size: int = 500,
    ) -> list[Facility]:
        """
        Get all facilities, paginating as needed.

        Args:
            since: Only return records updated since this time
            batch_size: Number of records per request

        Returns:
            List of all Facility objects
        """
        all_facilities = []
        skip = 0

        while True:
            batch = await self.get_facilities(
                since=since,
                limit=batch_size,
                skip=skip,
            )

            if not batch:
                break

            all_facilities.extend(batch)
            skip += len(batch)

            logger.info(f"Fetched {len(all_facilities)} facilities...")

            if len(batch) < batch_size:
                break

        return all_facilities

    # ================================================================
    # Networks
    # ================================================================

    async def get_networks(
        self,
        id: int | None = None,
        asn: int | None = None,
        name: str | None = None,
        info_type: str | None = None,
        policy_general: str | None = None,
        since: datetime | None = None,
        limit: int | None = None,
        skip: int | None = None,
    ) -> list[Network]:
        """
        Get networks from PeeringDB.

        Args:
            id: Filter by PeeringDB network ID
            asn: Filter by ASN
            name: Filter by network name (partial match)
            info_type: Filter by network type (NSP, ISP, Content, etc.)
            policy_general: Filter by peering policy (Open, Selective, etc.)
            since: Only return records updated since this time
            limit: Maximum number of results
            skip: Number of results to skip

        Returns:
            List of Network objects
        """
        params = {
            "id": id,
            "asn": asn,
            "name__contains": name if name else None,
            "info_type": info_type,
            "policy_general": policy_general,
            "since": since.timestamp() if since else None,
            "limit": limit,
            "skip": skip,
        }

        data = await self._request("net", params)
        return [Network.from_peeringdb(net) for net in data.get("data", [])]

    async def get_network(self, id: int | None = None, asn: int | None = None) -> Network | None:
        """Get a single network by ID or ASN."""
        networks = await self.get_networks(id=id, asn=asn)
        return networks[0] if networks else None

    async def get_all_networks(
        self,
        since: datetime | None = None,
        batch_size: int = 500,
    ) -> list[Network]:
        """Get all networks, paginating as needed."""
        all_networks = []
        skip = 0

        while True:
            batch = await self.get_networks(
                since=since,
                limit=batch_size,
                skip=skip,
            )

            if not batch:
                break

            all_networks.extend(batch)
            skip += len(batch)

            logger.info(f"Fetched {len(all_networks)} networks...")

            if len(batch) < batch_size:
                break

        return all_networks

    # ================================================================
    # Network-Facility relationships (netfac)
    # ================================================================

    async def get_network_facilities(
        self,
        id: int | None = None,
        fac_id: int | None = None,
        net_id: int | None = None,
        since: datetime | None = None,
        limit: int | None = None,
        skip: int | None = None,
    ) -> list[NetworkPresence]:
        """
        Get network-facility relationships.

        This tells you which networks are present at which facilities.

        Args:
            id: Filter by netfac ID
            fac_id: Filter by facility ID
            net_id: Filter by network ID
            since: Only return records updated since this time
            limit: Maximum number of results
            skip: Number of results to skip

        Returns:
            List of NetworkPresence objects
        """
        params = {
            "id": id,
            "fac_id": fac_id,
            "net_id": net_id,
            "since": since.timestamp() if since else None,
            "limit": limit,
            "skip": skip,
        }

        data = await self._request("netfac", params)
        return [NetworkPresence.from_peeringdb(nf) for nf in data.get("data", [])]

    async def get_all_network_facilities(
        self,
        since: datetime | None = None,
        batch_size: int = 1000,
    ) -> list[NetworkPresence]:
        """Get all network-facility relationships."""
        all_netfacs = []
        skip = 0

        while True:
            batch = await self.get_network_facilities(
                since=since,
                limit=batch_size,
                skip=skip,
            )

            if not batch:
                break

            all_netfacs.extend(batch)
            skip += len(batch)

            logger.info(f"Fetched {len(all_netfacs)} network-facility relationships...")

            if len(batch) < batch_size:
                break

        return all_netfacs

    async def get_networks_at_facility(self, facility_id: int) -> list[NetworkPresence]:
        """Get all networks present at a facility."""
        return await self.get_network_facilities(fac_id=facility_id)

    async def get_facility_locations_for_network(self, network_id: int) -> list[NetworkPresence]:
        """Get all facilities where a network is present."""
        return await self.get_network_facilities(net_id=network_id)

    # ================================================================
    # Carriers
    # ================================================================

    async def get_carriers(
        self,
        id: int | None = None,
        name: str | None = None,
        org_id: int | None = None,
        since: datetime | None = None,
        limit: int | None = None,
        skip: int | None = None,
    ) -> list[Carrier]:
        """
        Get carriers (L1/L2 service providers) from PeeringDB.

        Args:
            id: Filter by carrier ID
            name: Filter by carrier name (partial match)
            org_id: Filter by organization ID
            since: Only return records updated since this time
            limit: Maximum number of results
            skip: Number of results to skip

        Returns:
            List of Carrier objects
        """
        params = {
            "id": id,
            "name__contains": name if name else None,
            "org_id": org_id,
            "since": since.timestamp() if since else None,
            "limit": limit,
            "skip": skip,
        }

        data = await self._request("carrier", params)
        return [Carrier.from_peeringdb(c) for c in data.get("data", [])]

    async def get_all_carriers(
        self,
        since: datetime | None = None,
        batch_size: int = 500,
    ) -> list[Carrier]:
        """Get all carriers."""
        all_carriers = []
        skip = 0

        while True:
            batch = await self.get_carriers(
                since=since,
                limit=batch_size,
                skip=skip,
            )

            if not batch:
                break

            all_carriers.extend(batch)
            skip += len(batch)

            logger.info(f"Fetched {len(all_carriers)} carriers...")

            if len(batch) < batch_size:
                break

        return all_carriers

    # ================================================================
    # Carrier-Facility relationships (carrierfac)
    # ================================================================

    async def get_carrier_facilities(
        self,
        id: int | None = None,
        fac_id: int | None = None,
        carrier_id: int | None = None,
        since: datetime | None = None,
        limit: int | None = None,
        skip: int | None = None,
    ) -> list[CarrierPresence]:
        """
        Get carrier-facility relationships.

        This tells you which carriers serve which facilities.

        Args:
            id: Filter by carrierfac ID
            fac_id: Filter by facility ID
            carrier_id: Filter by carrier ID
            since: Only return records updated since this time
            limit: Maximum number of results
            skip: Number of results to skip

        Returns:
            List of CarrierPresence objects
        """
        params = {
            "id": id,
            "fac_id": fac_id,
            "carrier_id": carrier_id,
            "since": since.timestamp() if since else None,
            "limit": limit,
            "skip": skip,
        }

        data = await self._request("carrierfac", params)
        return [CarrierPresence.from_peeringdb(cf) for cf in data.get("data", [])]

    async def get_all_carrier_facilities(
        self,
        since: datetime | None = None,
        batch_size: int = 500,
    ) -> list[CarrierPresence]:
        """Get all carrier-facility relationships."""
        all_carrierfacs = []
        skip = 0

        while True:
            batch = await self.get_carrier_facilities(
                since=since,
                limit=batch_size,
                skip=skip,
            )

            if not batch:
                break

            all_carrierfacs.extend(batch)
            skip += len(batch)

            logger.info(f"Fetched {len(all_carrierfacs)} carrier-facility relationships...")

            if len(batch) < batch_size:
                break

        return all_carrierfacs

    async def get_carriers_at_facility(self, facility_id: int) -> list[CarrierPresence]:
        """Get all carriers present at a facility."""
        return await self.get_carrier_facilities(fac_id=facility_id)

    # ================================================================
    # Internet Exchanges
    # ================================================================

    async def get_exchanges(
        self,
        id: int | None = None,
        name: str | None = None,
        city: str | None = None,
        country: str | None = None,
        org_id: int | None = None,
        since: datetime | None = None,
        limit: int | None = None,
        skip: int | None = None,
    ) -> list[InternetExchange]:
        """
        Get Internet Exchanges from PeeringDB.

        Args:
            id: Filter by IX ID
            name: Filter by IX name (partial match)
            city: Filter by city
            country: Filter by country (ISO 3166-1 alpha-2)
            org_id: Filter by organization ID
            since: Only return records updated since this time
            limit: Maximum number of results
            skip: Number of results to skip

        Returns:
            List of InternetExchange objects
        """
        params = {
            "id": id,
            "name__contains": name if name else None,
            "city": city,
            "country": country,
            "org_id": org_id,
            "since": since.timestamp() if since else None,
            "limit": limit,
            "skip": skip,
        }

        data = await self._request("ix", params)
        return [InternetExchange.from_peeringdb(ix) for ix in data.get("data", [])]

    async def get_all_exchanges(
        self,
        since: datetime | None = None,
        batch_size: int = 500,
    ) -> list[InternetExchange]:
        """Get all Internet Exchanges."""
        all_ixs = []
        skip = 0

        while True:
            batch = await self.get_exchanges(
                since=since,
                limit=batch_size,
                skip=skip,
            )

            if not batch:
                break

            all_ixs.extend(batch)
            skip += len(batch)

            logger.info(f"Fetched {len(all_ixs)} exchanges...")

            if len(batch) < batch_size:
                break

        return all_ixs

    # ================================================================
    # IX-Facility relationships (ixfac)
    # ================================================================

    async def get_ix_facilities(
        self,
        id: int | None = None,
        ix_id: int | None = None,
        fac_id: int | None = None,
        since: datetime | None = None,
        limit: int | None = None,
        skip: int | None = None,
    ) -> list[IXFacility]:
        """
        Get IX-facility relationships.

        This tells you which IXs are present at which facilities.

        Args:
            id: Filter by ixfac ID
            ix_id: Filter by IX ID
            fac_id: Filter by facility ID
            since: Only return records updated since this time
            limit: Maximum number of results
            skip: Number of results to skip

        Returns:
            List of IXFacility objects
        """
        params = {
            "id": id,
            "ix_id": ix_id,
            "fac_id": fac_id,
            "since": since.timestamp() if since else None,
            "limit": limit,
            "skip": skip,
        }

        data = await self._request("ixfac", params)
        return [IXFacility.from_peeringdb(ixf) for ixf in data.get("data", [])]

    async def get_all_ix_facilities(
        self,
        since: datetime | None = None,
        batch_size: int = 500,
    ) -> list[IXFacility]:
        """Get all IX-facility relationships."""
        all_ixfacs = []
        skip = 0

        while True:
            batch = await self.get_ix_facilities(
                since=since,
                limit=batch_size,
                skip=skip,
            )

            if not batch:
                break

            all_ixfacs.extend(batch)
            skip += len(batch)

            logger.info(f"Fetched {len(all_ixfacs)} IX-facility relationships...")

            if len(batch) < batch_size:
                break

        return all_ixfacs

    async def get_ixs_at_facility(self, facility_id: int) -> list[IXFacility]:
        """Get all IXs present at a facility."""
        return await self.get_ix_facilities(fac_id=facility_id)

    # ================================================================
    # IX LANs
    # ================================================================

    async def get_ix_lans(
        self,
        id: int | None = None,
        ix_id: int | None = None,
        since: datetime | None = None,
        limit: int | None = None,
        skip: int | None = None,
    ) -> list[IXLan]:
        """
        Get IX LANs (peering LANs).

        Args:
            id: Filter by ixlan ID
            ix_id: Filter by IX ID
            since: Only return records updated since this time
            limit: Maximum number of results
            skip: Number of results to skip

        Returns:
            List of IXLan objects
        """
        params = {
            "id": id,
            "ix_id": ix_id,
            "since": since.timestamp() if since else None,
            "limit": limit,
            "skip": skip,
        }

        data = await self._request("ixlan", params)
        return [IXLan.from_peeringdb(ixl) for ixl in data.get("data", [])]

    async def get_all_ix_lans(
        self,
        since: datetime | None = None,
        batch_size: int = 500,
    ) -> list[IXLan]:
        """Get all IX LANs."""
        all_ixlans = []
        skip = 0

        while True:
            batch = await self.get_ix_lans(
                since=since,
                limit=batch_size,
                skip=skip,
            )

            if not batch:
                break

            all_ixlans.extend(batch)
            skip += len(batch)

            logger.info(f"Fetched {len(all_ixlans)} IX LANs...")

            if len(batch) < batch_size:
                break

        return all_ixlans

    # ================================================================
    # Convenience methods
    # ================================================================

    async def search_facilities(
        self,
        query: str | None = None,
        city: str | None = None,
        country: str | None = None,
        owner: str | None = None,
        has_carrier: str | None = None,
        has_network_asn: int | None = None,
    ) -> list[Facility]:
        """
        Search facilities with flexible criteria.

        Args:
            query: Search in facility name
            city: Filter by city
            country: Filter by country code
            owner: Filter by owner name
            has_carrier: Filter to facilities with this carrier (name)
            has_network_asn: Filter to facilities with this network (ASN)

        Returns:
            List of matching facilities
        """
        facilities = await self.get_facilities(
            name=query,
            city=city,
            country=country,
        )

        # Post-filter by owner if specified
        if owner:
            owner_lower = owner.lower()
            facilities = [f for f in facilities if f.owner and owner_lower in f.owner.lower()]

        # Filter by carrier presence if specified
        if has_carrier:
            carrier_facilities = set()

            # Get matching carriers
            carriers = await self.get_carriers(name=has_carrier)
            for carrier in carriers:
                if carrier.peeringdb_id:
                    cfacs = await self.get_carrier_facilities(carrier_id=carrier.peeringdb_id)
                    carrier_facilities.update(cf.facility_peeringdb_id for cf in cfacs)

            facilities = [f for f in facilities if f.peeringdb_id in carrier_facilities]

        # Filter by network presence if specified
        if has_network_asn:
            network_facilities = set()

            # Get network
            network = await self.get_network(asn=has_network_asn)
            if network and network.peeringdb_id:
                nfacs = await self.get_network_facilities(net_id=network.peeringdb_id)
                network_facilities.update(nf.facility_peeringdb_id for nf in nfacs)

            facilities = [f for f in facilities if f.peeringdb_id in network_facilities]

        return facilities

    async def get_facility_details(self, facility_id: int) -> dict[str, Any]:
        """
        Get comprehensive details about a facility including:
        - Facility info
        - Networks present
        - Carriers present
        - IXPs present

        Args:
            facility_id: PeeringDB facility ID

        Returns:
            Dictionary with facility details and relationships
        """
        # Fetch all data in parallel
        facility_task = self.get_facility(facility_id)
        networks_task = self.get_networks_at_facility(facility_id)
        carriers_task = self.get_carriers_at_facility(facility_id)
        ixs_task = self.get_ixs_at_facility(facility_id)

        facility, networks, carriers, ixs = await asyncio.gather(
            facility_task, networks_task, carriers_task, ixs_task
        )

        # Get network names
        network_details = []
        for np in networks:
            if np.network_peeringdb_id:
                net = await self.get_network(id=np.network_peeringdb_id)
                if net:
                    network_details.append({
                        "asn": net.asn,
                        "name": net.name,
                        "type": net.info_type,
                        "policy": net.policy_general,
                    })

        # Get carrier names
        carrier_details = []
        for cp in carriers:
            if cp.carrier_peeringdb_id:
                # Would need to fetch carrier by ID
                carrier_details.append({
                    "peeringdb_id": cp.carrier_peeringdb_id,
                    "name": cp.carrier_name,
                })

        # Get IX names
        ix_details = []
        for ixf in ixs:
            if ixf.ix_peeringdb_id:
                ix_list = await self.get_exchanges(id=ixf.ix_peeringdb_id)
                if ix_list:
                    ix = ix_list[0]
                    ix_details.append({
                        "name": ix.name,
                        "city": ix.city,
                        "country": ix.country,
                    })

        return {
            "facility": facility.to_dict() if facility else None,
            "networks": network_details,
            "network_count": len(networks),
            "carriers": carrier_details,
            "carrier_count": len(carriers),
            "exchanges": ix_details,
            "exchange_count": len(ixs),
        }
