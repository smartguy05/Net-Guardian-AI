"""Collector service for managing and running log collectors."""

import asyncio
import hashlib
import time
from datetime import datetime, timezone
from typing import Dict, List, Optional, Tuple
from uuid import UUID, uuid4

import structlog
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.collectors import get_collector
from app.collectors.base import BaseCollector
from app.db.session import AsyncSessionLocal
from app.events.bus import EventBus, get_event_bus
from app.models.device import Device, DeviceStatus
from app.models.log_source import LogSource
from app.models.raw_event import RawEvent
from app.parsers.base import ParseResult

logger = structlog.get_logger()


# Configuration constants
BATCH_SIZE = 100  # Number of events to batch before committing
BATCH_TIMEOUT = 2.0  # Seconds to wait before flushing incomplete batch
MAX_CONCURRENT_BATCHES = 3  # Max concurrent batch processing
DEVICE_CACHE_TTL = 300  # Seconds to cache IP->device mappings
SEMANTIC_QUEUE_SIZE = 10000  # Max queued events for semantic analysis
SEMANTIC_BATCH_SIZE = 50  # Events to process per semantic analysis batch


class DeviceCache:
    """TTL-based cache for IP address to device ID mappings."""

    def __init__(self, ttl: int = DEVICE_CACHE_TTL):
        self._cache: Dict[str, Tuple[Optional[UUID], float]] = {}
        self._ttl = ttl

    def get(self, ip_address: str) -> Tuple[Optional[UUID], bool]:
        """Get device ID for IP. Returns (device_id, cache_hit)."""
        if ip_address in self._cache:
            device_id, timestamp = self._cache[ip_address]
            if time.time() - timestamp < self._ttl:
                return device_id, True
            # Expired
            del self._cache[ip_address]
        return None, False

    def set(self, ip_address: str, device_id: Optional[UUID]) -> None:
        """Cache device ID for IP."""
        self._cache[ip_address] = (device_id, time.time())

    def invalidate(self, ip_address: str) -> None:
        """Remove IP from cache."""
        self._cache.pop(ip_address, None)

    def clear(self) -> None:
        """Clear all cached entries."""
        self._cache.clear()

    def cleanup_expired(self) -> int:
        """Remove expired entries. Returns count removed."""
        now = time.time()
        expired = [k for k, (_, ts) in self._cache.items() if now - ts >= self._ttl]
        for k in expired:
            del self._cache[k]
        return len(expired)


class CollectorService:
    """Service for managing log collectors and processing events.

    Optimizations:
    - Batch inserts: Events are batched and committed together
    - Concurrent processing: Multiple batches processed in parallel
    - Deferred semantic analysis: Queued for background processing
    - Device cache: IP->device mappings cached to reduce DB queries
    """

    def __init__(self):
        self._collectors: Dict[str, BaseCollector] = {}
        self._collector_tasks: Dict[str, asyncio.Task] = {}
        self._running = False
        self._event_bus: Optional[EventBus] = None

        # Batch processing
        self._batch_semaphore = asyncio.Semaphore(MAX_CONCURRENT_BATCHES)

        # Device cache
        self._device_cache = DeviceCache()

        # Deferred semantic analysis
        self._semantic_queue: asyncio.Queue = asyncio.Queue(maxsize=SEMANTIC_QUEUE_SIZE)
        self._semantic_task: Optional[asyncio.Task] = None

    async def start(self) -> None:
        """Start the collector service."""
        if self._running:
            return

        self._running = True
        self._event_bus = await get_event_bus()

        logger.info("collector_service_starting")

        # Start semantic analysis background task
        self._semantic_task = asyncio.create_task(self._semantic_analysis_worker())

        # Load and start all enabled sources
        await self._load_sources()

        logger.info(
            "collector_service_started",
            active_collectors=len(self._collectors),
        )

    async def stop(self) -> None:
        """Stop the collector service."""
        self._running = False

        logger.info("collector_service_stopping")

        # Stop all collectors
        for source_id in list(self._collectors.keys()):
            await self._stop_collector(source_id)

        # Stop semantic analysis worker
        if self._semantic_task:
            self._semantic_task.cancel()
            try:
                await self._semantic_task
            except asyncio.CancelledError:
                pass
            self._semantic_task = None

        # Clear caches
        self._device_cache.clear()

        logger.info("collector_service_stopped")

    async def _load_sources(self) -> None:
        """Load all enabled log sources and start collectors."""
        async with AsyncSessionLocal() as session:
            result = await session.execute(
                select(LogSource).where(LogSource.enabled == True)
            )
            sources = result.scalars().all()

            for source in sources:
                try:
                    await self._start_collector(source)
                except Exception as e:
                    logger.error(
                        "collector_start_failed",
                        source_id=source.id,
                        error=str(e),
                    )

    async def _start_collector(self, source: LogSource) -> None:
        """Start a collector for a log source."""
        if source.id in self._collectors:
            logger.warning(
                "collector_already_running",
                source_id=source.id,
            )
            return

        try:
            # Create collector instance
            collector = get_collector(source)
            self._collectors[source.id] = collector

            # Start the collector
            await collector.start()

            # Start event processing task
            task = asyncio.create_task(
                self._process_events(source.id, collector)
            )
            self._collector_tasks[source.id] = task

            logger.info(
                "collector_started",
                source_id=source.id,
                source_type=source.source_type.value,
            )

        except Exception as e:
            logger.error(
                "collector_start_error",
                source_id=source.id,
                error=str(e),
            )
            # Clean up on failure
            if source.id in self._collectors:
                del self._collectors[source.id]
            raise

    async def _stop_collector(self, source_id: str) -> None:
        """Stop a collector."""
        collector = self._collectors.get(source_id)
        if not collector:
            return

        # Cancel the processing task
        task = self._collector_tasks.get(source_id)
        if task:
            task.cancel()
            try:
                await task
            except asyncio.CancelledError:
                pass
            del self._collector_tasks[source_id]

        # Stop the collector
        await collector.stop()
        del self._collectors[source_id]

        logger.info("collector_stopped", source_id=source_id)

    async def _process_events(
        self,
        source_id: str,
        collector: BaseCollector,
    ) -> None:
        """Process events from a collector with batching."""
        batch: List[ParseResult] = []
        last_flush = time.time()

        async for event in collector.collect():
            if not self._running:
                break

            batch.append(event)

            # Flush batch if full or timeout reached
            should_flush = (
                len(batch) >= BATCH_SIZE or
                (batch and time.time() - last_flush >= BATCH_TIMEOUT)
            )

            if should_flush:
                # Process batch concurrently (limited by semaphore)
                asyncio.create_task(
                    self._process_batch(source_id, batch.copy())
                )
                batch.clear()
                last_flush = time.time()

        # Flush remaining events
        if batch:
            await self._process_batch(source_id, batch)

    async def _process_batch(
        self,
        source_id: str,
        events: List[ParseResult],
    ) -> None:
        """Process a batch of events with a single database transaction."""
        if not events:
            return

        async with self._batch_semaphore:
            try:
                await self._handle_event_batch(source_id, events)
            except Exception as e:
                logger.error(
                    "batch_processing_error",
                    source_id=source_id,
                    batch_size=len(events),
                    error=str(e),
                )

    async def _handle_event_batch(
        self,
        source_id: str,
        events: List[ParseResult],
    ) -> None:
        """Handle a batch of parsed events with optimized DB operations."""
        async with AsyncSessionLocal() as session:
            raw_events: List[RawEvent] = []
            event_data_for_bus: List[dict] = []

            # Collect unique IPs that need device lookup
            ips_to_lookup: Dict[str, Optional[UUID]] = {}
            for event in events:
                if event.client_ip and event.client_ip not in ips_to_lookup:
                    # Check cache first
                    device_id, cache_hit = self._device_cache.get(event.client_ip)
                    if cache_hit:
                        ips_to_lookup[event.client_ip] = device_id
                    else:
                        ips_to_lookup[event.client_ip] = None  # Needs lookup

            # Batch lookup uncached IPs
            uncached_ips = [ip for ip, dev_id in ips_to_lookup.items() if dev_id is None]
            if uncached_ips:
                device_map = await self._batch_get_or_create_devices(session, uncached_ips)
                ips_to_lookup.update(device_map)
                # Update cache
                for ip, device_id in device_map.items():
                    self._device_cache.set(ip, device_id)

            # Create all RawEvent records
            for event in events:
                device_id = ips_to_lookup.get(event.client_ip) if event.client_ip else None

                raw_event = RawEvent(
                    id=uuid4(),
                    timestamp=event.timestamp,
                    source_id=source_id,
                    event_type=event.event_type,
                    severity=event.severity,
                    client_ip=event.client_ip,
                    target_ip=event.target_ip,
                    domain=event.domain,
                    port=event.port,
                    protocol=event.protocol,
                    action=event.action,
                    response_status=event.response_status,
                    raw_message=event.raw_message,
                    parsed_fields=event.parsed_fields,
                    device_id=device_id,
                )
                raw_events.append(raw_event)
                session.add(raw_event)

                # Prepare event bus data
                event_data_for_bus.append({
                    "id": str(raw_event.id),
                    "source_id": source_id,
                    "event_type": event.event_type.value,
                    "severity": event.severity.value,
                    "client_ip": event.client_ip,
                    "domain": event.domain,
                    "action": event.action,
                    "device_id": str(device_id) if device_id else None,
                })

            # Update source metadata (single update for the whole batch)
            source = await session.get(LogSource, source_id)
            if source:
                source.last_event_at = datetime.now(timezone.utc)
                source.event_count += len(events)
                source.last_error = None

            # Single commit for entire batch
            await session.commit()

            logger.debug(
                "batch_committed",
                source_id=source_id,
                event_count=len(events),
            )

            # Queue events for deferred semantic analysis
            for raw_event in raw_events:
                try:
                    self._semantic_queue.put_nowait(raw_event)
                except asyncio.QueueFull:
                    # Queue full, skip semantic analysis for this event
                    logger.warning(
                        "semantic_queue_full",
                        source_id=source_id,
                    )
                    break

            # Publish events to Redis (batch)
            if self._event_bus:
                for event_data in event_data_for_bus:
                    await self._event_bus.publish_raw_event(event_data)

    def _generate_placeholder_mac(self, ip: str) -> str:
        """Generate a deterministic placeholder MAC from IP hash."""
        ip_hash = hashlib.md5(ip.encode()).hexdigest()[:8]
        return f"00:00:{ip_hash[0:2]}:{ip_hash[2:4]}:{ip_hash[4:6]}:{ip_hash[6:8]}"

    async def _batch_get_or_create_devices(
        self,
        session: AsyncSession,
        ip_addresses: List[str],
    ) -> Dict[str, Optional[UUID]]:
        """Batch get or create devices by IP addresses.

        Handles race conditions from concurrent batch processing by:
        1. Looking up by both IP and placeholder MAC
        2. Catching IntegrityError on insert and retrying lookup
        """
        result_map: Dict[str, Optional[UUID]] = {}

        if not ip_addresses:
            return result_map

        from sqlalchemy import or_
        from sqlalchemy.exc import IntegrityError

        # Generate placeholder MACs for lookup
        ip_to_mac = {ip: self._generate_placeholder_mac(ip) for ip in ip_addresses}
        placeholder_macs = list(ip_to_mac.values())

        # Query existing devices by IP OR by placeholder MAC (handles race condition)
        ip_conditions = [Device.ip_addresses.contains([ip]) for ip in ip_addresses]
        mac_condition = Device.mac_address.in_(placeholder_macs)

        result = await session.execute(
            select(Device).where(or_(*ip_conditions, mac_condition))
        )
        existing_devices = result.scalars().all()

        # Map IPs to existing devices
        now = datetime.now(timezone.utc)
        for device in existing_devices:
            for ip in ip_addresses:
                if ip in device.ip_addresses or device.mac_address == ip_to_mac.get(ip):
                    result_map[ip] = device.id
                    # Update last seen
                    device.last_seen = now

        # Create new devices for IPs without matches
        for ip in ip_addresses:
            if ip not in result_map:
                placeholder_mac = ip_to_mac[ip]

                device = Device(
                    id=uuid4(),
                    mac_address=placeholder_mac,
                    ip_addresses=[ip],
                    hostname=None,
                    manufacturer=None,
                    device_type=None,
                    status=DeviceStatus.ACTIVE,
                    first_seen=now,
                    last_seen=now,
                )
                session.add(device)
                result_map[ip] = device.id

                logger.info(
                    "device_auto_created",
                    device_id=str(device.id),
                    ip_address=ip,
                )

        # Flush to detect any constraint violations before returning
        try:
            await session.flush()
        except IntegrityError:
            # Race condition: another batch created this device
            # Rollback the failed inserts and re-query
            await session.rollback()

            # Re-query to get the devices that were created by another batch
            result = await session.execute(
                select(Device).where(or_(*ip_conditions, mac_condition))
            )
            existing_devices = result.scalars().all()

            result_map.clear()
            for device in existing_devices:
                for ip in ip_addresses:
                    if ip in device.ip_addresses or device.mac_address == ip_to_mac.get(ip):
                        result_map[ip] = device.id
                        device.last_seen = now

            logger.debug(
                "device_creation_race_resolved",
                ip_count=len(ip_addresses),
            )

        return result_map

    async def _semantic_analysis_worker(self) -> None:
        """Background worker for deferred semantic analysis."""
        from app.services.semantic_analysis_service import get_semantic_analysis_service

        logger.info("semantic_analysis_worker_started")

        while self._running:
            try:
                # Collect a batch of events
                batch: List[RawEvent] = []

                # Wait for first event (with timeout to check running flag)
                try:
                    event = await asyncio.wait_for(
                        self._semantic_queue.get(),
                        timeout=1.0
                    )
                    batch.append(event)
                except asyncio.TimeoutError:
                    continue

                # Try to get more events without waiting (up to batch size)
                while len(batch) < SEMANTIC_BATCH_SIZE:
                    try:
                        event = self._semantic_queue.get_nowait()
                        batch.append(event)
                    except asyncio.QueueEmpty:
                        break

                # Process the batch
                if batch:
                    async with AsyncSessionLocal() as session:
                        semantic_service = get_semantic_analysis_service(session)

                        for raw_event in batch:
                            try:
                                irregular_log = await semantic_service.process_event(raw_event)
                                if irregular_log:
                                    logger.debug(
                                        "irregular_log_flagged",
                                        event_id=str(raw_event.id),
                                        source_id=raw_event.source_id,
                                        reason=irregular_log.reason,
                                    )
                            except Exception as e:
                                logger.warning(
                                    "semantic_analysis_error",
                                    event_id=str(raw_event.id),
                                    error=str(e),
                                )

                    logger.debug(
                        "semantic_batch_processed",
                        batch_size=len(batch),
                        queue_size=self._semantic_queue.qsize(),
                    )

            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error(
                    "semantic_worker_error",
                    error=str(e),
                )
                await asyncio.sleep(1)

        logger.info("semantic_analysis_worker_stopped")

    async def reload_source(self, source_id: str) -> None:
        """Reload a source configuration."""
        # Stop existing collector if running
        if source_id in self._collectors:
            await self._stop_collector(source_id)

        # Get updated source
        async with AsyncSessionLocal() as session:
            source = await session.get(LogSource, source_id)
            if source and source.enabled:
                await self._start_collector(source)

    async def add_source(self, source_id: str) -> None:
        """Add and start a new source."""
        async with AsyncSessionLocal() as session:
            source = await session.get(LogSource, source_id)
            if source and source.enabled:
                await self._start_collector(source)

    async def remove_source(self, source_id: str) -> None:
        """Remove and stop a source."""
        await self._stop_collector(source_id)

    def get_status(self) -> Dict[str, bool]:
        """Get status of all collectors."""
        return {
            source_id: collector.is_running()
            for source_id, collector in self._collectors.items()
        }

    def get_stats(self) -> Dict[str, any]:
        """Get collector service statistics."""
        return {
            "active_collectors": len(self._collectors),
            "device_cache_size": len(self._device_cache._cache),
            "semantic_queue_size": self._semantic_queue.qsize(),
        }


# Global service instance
_collector_service: Optional[CollectorService] = None


async def get_collector_service() -> CollectorService:
    """Get the global collector service instance."""
    global _collector_service
    if _collector_service is None:
        _collector_service = CollectorService()
    return _collector_service


async def start_collector_service() -> None:
    """Start the global collector service."""
    service = await get_collector_service()
    await service.start()


async def stop_collector_service() -> None:
    """Stop the global collector service."""
    global _collector_service
    if _collector_service is not None:
        await _collector_service.stop()
        _collector_service = None
