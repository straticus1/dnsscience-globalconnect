"""
Sync logic for facilities data.

Handles incremental updates from PeeringDB and other sources,
designed to run as an hourly cron job.

Copyright (c) 2025 DNS Science.io, an After Dark Systems, LLC company.
All rights reserved.
"""

import asyncio
import logging
from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Any, Callable

from globaldetect.facilities.database import FacilitiesDatabase
from globaldetect.facilities.models import SyncStatus
from globaldetect.facilities.peeringdb import PeeringDBClient, PeeringDBConfig

logger = logging.getLogger(__name__)


@dataclass
class SyncResult:
    """Result of a sync operation."""
    entity_type: str
    success: bool
    fetched: int = 0
    created: int = 0
    updated: int = 0
    deleted: int = 0
    error: str | None = None
    duration_seconds: float = 0.0


@dataclass
class SyncOptions:
    """Options for sync operations."""
    # Full sync (ignore last sync time)
    full_sync: bool = False

    # Sync specific entity types only
    sync_facilities: bool = True
    sync_networks: bool = True
    sync_network_facilities: bool = True
    sync_carriers: bool = True
    sync_carrier_facilities: bool = True
    sync_exchanges: bool = True
    sync_ix_facilities: bool = True

    # Progress callback
    progress_callback: Callable[[str, int, int], None] | None = None


class FacilitiesSync:
    """
    Synchronizes facilities data from PeeringDB.

    Supports incremental updates using PeeringDB's `since` parameter
    to only fetch records that changed since the last sync.

    Usage:
        db = FacilitiesDatabase()
        db.initialize()

        sync = FacilitiesSync(db)
        results = await sync.sync_all()

    Cron usage (hourly):
        0 * * * * globaldetect facility sync --quiet
    """

    def __init__(
        self,
        db: FacilitiesDatabase,
        peeringdb_config: PeeringDBConfig | None = None,
    ):
        self.db = db
        self.peeringdb_config = peeringdb_config

    async def sync_all(
        self,
        options: SyncOptions | None = None,
    ) -> list[SyncResult]:
        """
        Sync all data from PeeringDB.

        Args:
            options: Sync options (full sync, which entities, etc.)

        Returns:
            List of SyncResult for each entity type
        """
        options = options or SyncOptions()
        results = []

        async with PeeringDBClient(self.peeringdb_config) as client:
            # Sync in dependency order
            if options.sync_facilities:
                result = await self._sync_facilities(client, options)
                results.append(result)

            if options.sync_networks:
                result = await self._sync_networks(client, options)
                results.append(result)

            if options.sync_network_facilities:
                result = await self._sync_network_facilities(client, options)
                results.append(result)

            if options.sync_carriers:
                result = await self._sync_carriers(client, options)
                results.append(result)

            if options.sync_carrier_facilities:
                result = await self._sync_carrier_facilities(client, options)
                results.append(result)

            if options.sync_exchanges:
                result = await self._sync_exchanges(client, options)
                results.append(result)

            if options.sync_ix_facilities:
                result = await self._sync_ix_facilities(client, options)
                results.append(result)

        return results

    async def sync_facilities_only(
        self,
        full_sync: bool = False,
    ) -> SyncResult:
        """Sync only facilities (quick sync)."""
        options = SyncOptions(
            full_sync=full_sync,
            sync_facilities=True,
            sync_networks=False,
            sync_network_facilities=False,
            sync_carriers=False,
            sync_carrier_facilities=False,
            sync_exchanges=False,
            sync_ix_facilities=False,
        )
        results = await self.sync_all(options)
        return results[0] if results else SyncResult("facilities", False, error="No results")

    def _get_since_time(self, entity_type: str, full_sync: bool) -> datetime | None:
        """Get the 'since' time for incremental sync."""
        if full_sync:
            return None

        last_sync = self.db.get_last_sync("peeringdb", entity_type)
        if last_sync and last_sync.completed_at:
            # Go back a bit to catch any edge cases
            return last_sync.completed_at - timedelta(hours=1)

        return None

    async def _sync_facilities(
        self,
        client: PeeringDBClient,
        options: SyncOptions,
    ) -> SyncResult:
        """Sync facilities from PeeringDB."""
        entity_type = "facilities"
        start_time = datetime.now()

        # Create sync status record
        status = SyncStatus(
            source="peeringdb",
            entity_type=entity_type,
            started_at=start_time,
            status="running",
        )
        status = self.db.create_sync_status(status)

        try:
            since = self._get_since_time(entity_type, options.full_sync)
            logger.info(f"Syncing facilities (since={since})")

            if options.progress_callback:
                options.progress_callback(entity_type, 0, 0)

            facilities = await client.get_all_facilities(since=since)

            if options.progress_callback:
                options.progress_callback(entity_type, len(facilities), len(facilities))

            created, updated = self.db.upsert_facilities(facilities)

            # Update status
            status.completed_at = datetime.now()
            status.status = "completed"
            status.records_fetched = len(facilities)
            status.records_created = created
            status.records_updated = updated
            self.db.update_sync_status(status)

            duration = (datetime.now() - start_time).total_seconds()
            logger.info(
                f"Facilities sync complete: {len(facilities)} fetched, "
                f"{created} created, {updated} updated in {duration:.1f}s"
            )

            return SyncResult(
                entity_type=entity_type,
                success=True,
                fetched=len(facilities),
                created=created,
                updated=updated,
                duration_seconds=duration,
            )

        except Exception as e:
            status.completed_at = datetime.now()
            status.status = "failed"
            status.error_message = str(e)
            self.db.update_sync_status(status)

            logger.error(f"Facilities sync failed: {e}")
            return SyncResult(
                entity_type=entity_type,
                success=False,
                error=str(e),
                duration_seconds=(datetime.now() - start_time).total_seconds(),
            )

    async def _sync_networks(
        self,
        client: PeeringDBClient,
        options: SyncOptions,
    ) -> SyncResult:
        """Sync networks from PeeringDB."""
        entity_type = "networks"
        start_time = datetime.now()

        status = SyncStatus(
            source="peeringdb",
            entity_type=entity_type,
            started_at=start_time,
            status="running",
        )
        status = self.db.create_sync_status(status)

        try:
            since = self._get_since_time(entity_type, options.full_sync)
            logger.info(f"Syncing networks (since={since})")

            if options.progress_callback:
                options.progress_callback(entity_type, 0, 0)

            networks = await client.get_all_networks(since=since)

            if options.progress_callback:
                options.progress_callback(entity_type, len(networks), len(networks))

            created, updated = self.db.upsert_networks(networks)

            status.completed_at = datetime.now()
            status.status = "completed"
            status.records_fetched = len(networks)
            status.records_created = created
            status.records_updated = updated
            self.db.update_sync_status(status)

            duration = (datetime.now() - start_time).total_seconds()
            logger.info(
                f"Networks sync complete: {len(networks)} fetched, "
                f"{created} created, {updated} updated in {duration:.1f}s"
            )

            return SyncResult(
                entity_type=entity_type,
                success=True,
                fetched=len(networks),
                created=created,
                updated=updated,
                duration_seconds=duration,
            )

        except Exception as e:
            status.completed_at = datetime.now()
            status.status = "failed"
            status.error_message = str(e)
            self.db.update_sync_status(status)

            logger.error(f"Networks sync failed: {e}")
            return SyncResult(
                entity_type=entity_type,
                success=False,
                error=str(e),
                duration_seconds=(datetime.now() - start_time).total_seconds(),
            )

    async def _sync_network_facilities(
        self,
        client: PeeringDBClient,
        options: SyncOptions,
    ) -> SyncResult:
        """Sync network-facility relationships from PeeringDB."""
        entity_type = "network_facilities"
        start_time = datetime.now()

        status = SyncStatus(
            source="peeringdb",
            entity_type=entity_type,
            started_at=start_time,
            status="running",
        )
        status = self.db.create_sync_status(status)

        try:
            since = self._get_since_time(entity_type, options.full_sync)
            logger.info(f"Syncing network-facilities (since={since})")

            if options.progress_callback:
                options.progress_callback(entity_type, 0, 0)

            netfacs = await client.get_all_network_facilities(since=since)

            if options.progress_callback:
                options.progress_callback(entity_type, len(netfacs), len(netfacs))

            created, updated = self.db.upsert_network_facilities(netfacs)

            status.completed_at = datetime.now()
            status.status = "completed"
            status.records_fetched = len(netfacs)
            status.records_created = created
            status.records_updated = updated
            self.db.update_sync_status(status)

            duration = (datetime.now() - start_time).total_seconds()
            logger.info(
                f"Network-facilities sync complete: {len(netfacs)} fetched, "
                f"{created} created, {updated} updated in {duration:.1f}s"
            )

            return SyncResult(
                entity_type=entity_type,
                success=True,
                fetched=len(netfacs),
                created=created,
                updated=updated,
                duration_seconds=duration,
            )

        except Exception as e:
            status.completed_at = datetime.now()
            status.status = "failed"
            status.error_message = str(e)
            self.db.update_sync_status(status)

            logger.error(f"Network-facilities sync failed: {e}")
            return SyncResult(
                entity_type=entity_type,
                success=False,
                error=str(e),
                duration_seconds=(datetime.now() - start_time).total_seconds(),
            )

    async def _sync_carriers(
        self,
        client: PeeringDBClient,
        options: SyncOptions,
    ) -> SyncResult:
        """Sync carriers from PeeringDB."""
        entity_type = "carriers"
        start_time = datetime.now()

        status = SyncStatus(
            source="peeringdb",
            entity_type=entity_type,
            started_at=start_time,
            status="running",
        )
        status = self.db.create_sync_status(status)

        try:
            since = self._get_since_time(entity_type, options.full_sync)
            logger.info(f"Syncing carriers (since={since})")

            if options.progress_callback:
                options.progress_callback(entity_type, 0, 0)

            carriers = await client.get_all_carriers(since=since)

            if options.progress_callback:
                options.progress_callback(entity_type, len(carriers), len(carriers))

            created, updated = self.db.upsert_carriers(carriers)

            status.completed_at = datetime.now()
            status.status = "completed"
            status.records_fetched = len(carriers)
            status.records_created = created
            status.records_updated = updated
            self.db.update_sync_status(status)

            duration = (datetime.now() - start_time).total_seconds()
            logger.info(
                f"Carriers sync complete: {len(carriers)} fetched, "
                f"{created} created, {updated} updated in {duration:.1f}s"
            )

            return SyncResult(
                entity_type=entity_type,
                success=True,
                fetched=len(carriers),
                created=created,
                updated=updated,
                duration_seconds=duration,
            )

        except Exception as e:
            status.completed_at = datetime.now()
            status.status = "failed"
            status.error_message = str(e)
            self.db.update_sync_status(status)

            logger.error(f"Carriers sync failed: {e}")
            return SyncResult(
                entity_type=entity_type,
                success=False,
                error=str(e),
                duration_seconds=(datetime.now() - start_time).total_seconds(),
            )

    async def _sync_carrier_facilities(
        self,
        client: PeeringDBClient,
        options: SyncOptions,
    ) -> SyncResult:
        """Sync carrier-facility relationships from PeeringDB."""
        entity_type = "carrier_facilities"
        start_time = datetime.now()

        status = SyncStatus(
            source="peeringdb",
            entity_type=entity_type,
            started_at=start_time,
            status="running",
        )
        status = self.db.create_sync_status(status)

        try:
            since = self._get_since_time(entity_type, options.full_sync)
            logger.info(f"Syncing carrier-facilities (since={since})")

            if options.progress_callback:
                options.progress_callback(entity_type, 0, 0)

            carrierfacs = await client.get_all_carrier_facilities(since=since)

            if options.progress_callback:
                options.progress_callback(entity_type, len(carrierfacs), len(carrierfacs))

            created, updated = self.db.upsert_carrier_facilities(carrierfacs)

            status.completed_at = datetime.now()
            status.status = "completed"
            status.records_fetched = len(carrierfacs)
            status.records_created = created
            status.records_updated = updated
            self.db.update_sync_status(status)

            duration = (datetime.now() - start_time).total_seconds()
            logger.info(
                f"Carrier-facilities sync complete: {len(carrierfacs)} fetched, "
                f"{created} created, {updated} updated in {duration:.1f}s"
            )

            return SyncResult(
                entity_type=entity_type,
                success=True,
                fetched=len(carrierfacs),
                created=created,
                updated=updated,
                duration_seconds=duration,
            )

        except Exception as e:
            status.completed_at = datetime.now()
            status.status = "failed"
            status.error_message = str(e)
            self.db.update_sync_status(status)

            logger.error(f"Carrier-facilities sync failed: {e}")
            return SyncResult(
                entity_type=entity_type,
                success=False,
                error=str(e),
                duration_seconds=(datetime.now() - start_time).total_seconds(),
            )

    async def _sync_exchanges(
        self,
        client: PeeringDBClient,
        options: SyncOptions,
    ) -> SyncResult:
        """Sync Internet Exchanges from PeeringDB."""
        entity_type = "exchanges"
        start_time = datetime.now()

        status = SyncStatus(
            source="peeringdb",
            entity_type=entity_type,
            started_at=start_time,
            status="running",
        )
        status = self.db.create_sync_status(status)

        try:
            since = self._get_since_time(entity_type, options.full_sync)
            logger.info(f"Syncing exchanges (since={since})")

            if options.progress_callback:
                options.progress_callback(entity_type, 0, 0)

            exchanges = await client.get_all_exchanges(since=since)

            if options.progress_callback:
                options.progress_callback(entity_type, len(exchanges), len(exchanges))

            created, updated = self.db.upsert_exchanges(exchanges)

            status.completed_at = datetime.now()
            status.status = "completed"
            status.records_fetched = len(exchanges)
            status.records_created = created
            status.records_updated = updated
            self.db.update_sync_status(status)

            duration = (datetime.now() - start_time).total_seconds()
            logger.info(
                f"Exchanges sync complete: {len(exchanges)} fetched, "
                f"{created} created, {updated} updated in {duration:.1f}s"
            )

            return SyncResult(
                entity_type=entity_type,
                success=True,
                fetched=len(exchanges),
                created=created,
                updated=updated,
                duration_seconds=duration,
            )

        except Exception as e:
            status.completed_at = datetime.now()
            status.status = "failed"
            status.error_message = str(e)
            self.db.update_sync_status(status)

            logger.error(f"Exchanges sync failed: {e}")
            return SyncResult(
                entity_type=entity_type,
                success=False,
                error=str(e),
                duration_seconds=(datetime.now() - start_time).total_seconds(),
            )

    async def _sync_ix_facilities(
        self,
        client: PeeringDBClient,
        options: SyncOptions,
    ) -> SyncResult:
        """Sync IX-facility relationships from PeeringDB."""
        entity_type = "ix_facilities"
        start_time = datetime.now()

        status = SyncStatus(
            source="peeringdb",
            entity_type=entity_type,
            started_at=start_time,
            status="running",
        )
        status = self.db.create_sync_status(status)

        try:
            since = self._get_since_time(entity_type, options.full_sync)
            logger.info(f"Syncing IX-facilities (since={since})")

            if options.progress_callback:
                options.progress_callback(entity_type, 0, 0)

            ixfacs = await client.get_all_ix_facilities(since=since)

            if options.progress_callback:
                options.progress_callback(entity_type, len(ixfacs), len(ixfacs))

            created, updated = self.db.upsert_ix_facilities(ixfacs)

            status.completed_at = datetime.now()
            status.status = "completed"
            status.records_fetched = len(ixfacs)
            status.records_created = created
            status.records_updated = updated
            self.db.update_sync_status(status)

            duration = (datetime.now() - start_time).total_seconds()
            logger.info(
                f"IX-facilities sync complete: {len(ixfacs)} fetched, "
                f"{created} created, {updated} updated in {duration:.1f}s"
            )

            return SyncResult(
                entity_type=entity_type,
                success=True,
                fetched=len(ixfacs),
                created=created,
                updated=updated,
                duration_seconds=duration,
            )

        except Exception as e:
            status.completed_at = datetime.now()
            status.status = "failed"
            status.error_message = str(e)
            self.db.update_sync_status(status)

            logger.error(f"IX-facilities sync failed: {e}")
            return SyncResult(
                entity_type=entity_type,
                success=False,
                error=str(e),
                duration_seconds=(datetime.now() - start_time).total_seconds(),
            )


def run_sync(
    db: FacilitiesDatabase | None = None,
    full_sync: bool = False,
    quiet: bool = False,
) -> list[SyncResult]:
    """
    Convenience function to run sync from CLI or scripts.

    Args:
        db: Database instance (creates new if not provided)
        full_sync: Ignore last sync time and fetch everything
        quiet: Suppress output

    Returns:
        List of SyncResult for each entity type
    """
    if db is None:
        db = FacilitiesDatabase()
        db.initialize()

    sync = FacilitiesSync(db)
    options = SyncOptions(full_sync=full_sync)

    return asyncio.run(sync.sync_all(options))
