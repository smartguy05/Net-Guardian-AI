"""Collector service for managing and running log collectors."""

import asyncio
from datetime import datetime, timezone
from typing import Dict, Optional
from uuid import uuid4

import structlog
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.collectors import get_collector
from app.collectors.base import BaseCollector
from app.db.session import async_session_factory
from app.events.bus import EventBus, get_event_bus
from app.models.device import Device
from app.models.log_source import LogSource
from app.models.raw_event import RawEvent
from app.parsers.base import ParseResult

logger = structlog.get_logger()


class CollectorService:
    """Service for managing log collectors and processing events."""

    def __init__(self):
        self._collectors: Dict[str, BaseCollector] = {}
        self._collector_tasks: Dict[str, asyncio.Task] = {}
        self._running = False
        self._event_bus: Optional[EventBus] = None

    async def start(self) -> None:
        """Start the collector service."""
        if self._running:
            return

        self._running = True
        self._event_bus = await get_event_bus()

        logger.info("collector_service_starting")

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

        logger.info("collector_service_stopped")

    async def _load_sources(self) -> None:
        """Load all enabled log sources and start collectors."""
        async with async_session_factory() as session:
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
        """Process events from a collector."""
        async for event in collector.collect():
            if not self._running:
                break

            try:
                await self._handle_event(source_id, event)
            except Exception as e:
                logger.error(
                    "event_processing_error",
                    source_id=source_id,
                    error=str(e),
                )

    async def _handle_event(
        self,
        source_id: str,
        event: ParseResult,
    ) -> None:
        """Handle a single parsed event."""
        async with async_session_factory() as session:
            # Try to find/create device from client IP
            device_id = None
            if event.client_ip:
                device_id = await self._get_or_create_device(
                    session, event.client_ip
                )

            # Create raw event record
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

            session.add(raw_event)

            # Update source metadata
            source = await session.get(LogSource, source_id)
            if source:
                source.last_event_at = datetime.now(timezone.utc)
                source.event_count += 1
                source.last_error = None

            await session.commit()

            # Publish event to Redis
            if self._event_bus:
                await self._event_bus.publish_raw_event({
                    "id": str(raw_event.id),
                    "source_id": source_id,
                    "event_type": event.event_type.value,
                    "severity": event.severity.value,
                    "client_ip": event.client_ip,
                    "domain": event.domain,
                    "action": event.action,
                    "device_id": str(device_id) if device_id else None,
                })

    async def _get_or_create_device(
        self,
        session: AsyncSession,
        ip_address: str,
    ) -> Optional[uuid4]:
        """Get or create a device by IP address."""
        from app.models.device import Device, DeviceStatus

        # Look for existing device with this IP
        result = await session.execute(
            select(Device).where(Device.ip_addresses.contains([ip_address]))
        )
        device = result.scalar_one_or_none()

        if device:
            # Update last seen
            device.last_seen = datetime.now(timezone.utc)
            return device.id

        # Create new device
        device = Device(
            id=uuid4(),
            mac_address=f"unknown-{ip_address}",  # Placeholder until we get MAC
            ip_addresses=[ip_address],
            hostname=None,
            manufacturer=None,
            device_type=None,
            status=DeviceStatus.ACTIVE,
            first_seen=datetime.now(timezone.utc),
            last_seen=datetime.now(timezone.utc),
        )
        session.add(device)
        await session.flush()

        logger.info(
            "device_auto_created",
            device_id=str(device.id),
            ip_address=ip_address,
        )

        return device.id

    async def reload_source(self, source_id: str) -> None:
        """Reload a source configuration."""
        # Stop existing collector if running
        if source_id in self._collectors:
            await self._stop_collector(source_id)

        # Get updated source
        async with async_session_factory() as session:
            source = await session.get(LogSource, source_id)
            if source and source.enabled:
                await self._start_collector(source)

    async def add_source(self, source_id: str) -> None:
        """Add and start a new source."""
        async with async_session_factory() as session:
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
