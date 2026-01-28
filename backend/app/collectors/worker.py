"""Collector worker that orchestrates all log source collectors."""

import asyncio
import signal
from datetime import UTC, datetime
from uuid import uuid4

import structlog
from sqlalchemy import select, update
from sqlalchemy.ext.asyncio import AsyncSession

from app.collectors.base import BaseCollector
from app.collectors.registry import get_collector
from app.db.session import AsyncSessionLocal, init_db
from app.events.bus import EventBus, get_event_bus
from app.models.device import Device, DeviceStatus, DeviceType
from app.models.log_source import LogSource
from app.models.raw_event import RawEvent
from app.parsers.base import ParseResult

logger = structlog.get_logger()


class CollectorWorker:
    """Worker that manages all log source collectors.

    This worker:
    1. Loads enabled log sources from the database
    2. Creates collectors for each source
    3. Processes events and stores them in the database
    4. Publishes events to the Redis event bus
    5. Auto-discovers devices from event IP addresses
    """

    def __init__(self):
        self._collectors: dict[str, BaseCollector] = {}
        self._tasks: dict[str, asyncio.Task] = {}
        self._running = False
        self._event_bus: EventBus | None = None
        self._shutdown_event = asyncio.Event()

    async def _load_sources(self, session: AsyncSession) -> list[LogSource]:
        """Load all enabled log sources from database."""
        result = await session.execute(
            select(LogSource).where(LogSource.enabled.is_(True))
        )
        return list(result.scalars().all())

    async def _get_or_create_device(
        self,
        session: AsyncSession,
        ip_address: str,
    ) -> Device | None:
        """Get or create a device by IP address.

        This provides basic device auto-discovery from events.
        """
        if not ip_address:
            return None

        # Check if device exists with this IP
        result = await session.execute(
            select(Device).where(Device.ip_addresses.contains([ip_address]))
        )
        device = result.scalar_one_or_none()

        if device:
            # Update last_seen
            device.last_seen = datetime.now(UTC)
            return device

        # Create new device with placeholder MAC
        # In production, you'd want to resolve MAC from ARP or DHCP
        placeholder_mac = f"00:00:00:{ip_address.replace('.', ':')[-8:]}"

        # Ensure unique MAC by appending random suffix if needed
        existing = await session.execute(
            select(Device).where(Device.mac_address == placeholder_mac)
        )
        if existing.scalar_one_or_none():
            placeholder_mac = f"00:00:{uuid4().hex[:2]}:{uuid4().hex[:2]}:{uuid4().hex[:2]}:{uuid4().hex[:2]}"

        now = datetime.now(UTC)
        device = Device(
            mac_address=placeholder_mac,
            ip_addresses=[ip_address],
            device_type=DeviceType.UNKNOWN,
            first_seen=now,
            last_seen=now,
            status=DeviceStatus.ACTIVE,
        )
        session.add(device)

        logger.info(
            "device_auto_discovered",
            ip_address=ip_address,
            mac_address=placeholder_mac,
        )

        return device

    async def _process_event(
        self,
        session: AsyncSession,
        source: LogSource,
        result: ParseResult,
    ) -> None:
        """Process a single parsed event."""
        # Auto-discover device from client IP
        device = None
        if result.client_ip:
            device = await self._get_or_create_device(session, result.client_ip)

        # ParseResult already contains enum types from the parser
        event_type = result.event_type
        severity = result.severity

        # Create RawEvent
        raw_event = RawEvent(
            timestamp=result.timestamp,
            source_id=source.id,
            event_type=event_type,
            severity=severity,
            client_ip=result.client_ip,
            target_ip=result.target_ip,
            domain=result.domain,
            port=result.port,
            protocol=result.protocol,
            action=result.action,
            raw_message=result.raw_message,
            parsed_fields=result.parsed_fields or {},
            device_id=device.id if device else None,
            # DNS-specific fields
            query_type=result.parsed_fields.get("query_type") if result.parsed_fields else None,
            response_status=result.parsed_fields.get("response_status") if result.parsed_fields else None,
            blocked_reason=result.parsed_fields.get("blocked_reason") if result.parsed_fields else None,
            entropy_score=result.parsed_fields.get("entropy_score") if result.parsed_fields else None,
        )
        session.add(raw_event)

        # Update source stats
        await session.execute(
            update(LogSource)
            .where(LogSource.id == source.id)
            .values(
                last_event_at=result.timestamp,
                event_count=LogSource.event_count + 1,
            )
        )

        # Publish to event bus for real-time processing
        if self._event_bus:
            await self._event_bus.publish_raw_event({
                "id": str(raw_event.id),
                "timestamp": result.timestamp.isoformat(),
                "source_id": source.id,
                "event_type": event_type.value,
                "client_ip": result.client_ip,
                "domain": result.domain,
                "action": result.action,
            })

    async def _run_collector(self, source: LogSource) -> None:
        """Run a single collector and process its events."""
        collector = self._collectors.get(source.id)
        if not collector:
            return

        logger.info(
            "collector_task_started",
            source_id=source.id,
            source_type=source.source_type.value,
        )

        try:
            await collector.start()

            async for result in collector.collect():
                if not self._running:
                    break

                try:
                    async with AsyncSessionLocal() as session:
                        await self._process_event(session, source, result)
                        await session.commit()
                except Exception as e:
                    logger.error(
                        "event_processing_error",
                        source_id=source.id,
                        error=str(e),
                    )

        except asyncio.CancelledError:
            logger.info("collector_task_cancelled", source_id=source.id)
        except Exception as e:
            logger.error(
                "collector_task_error",
                source_id=source.id,
                error=str(e),
            )
            # Update source with error
            try:
                async with AsyncSessionLocal() as session:
                    await session.execute(
                        update(LogSource)
                        .where(LogSource.id == source.id)
                        .values(last_error=str(e))
                    )
                    await session.commit()
            except Exception:
                pass
        finally:
            await collector.stop()
            logger.info("collector_task_stopped", source_id=source.id)

    async def _start_collectors(self) -> None:
        """Load sources and start collectors."""
        async with AsyncSessionLocal() as session:
            sources = await self._load_sources(session)

        logger.info("sources_loaded", count=len(sources))

        for source in sources:
            try:
                collector = get_collector(source)
                self._collectors[source.id] = collector

                # Start collector task
                task = asyncio.create_task(self._run_collector(source))
                self._tasks[source.id] = task

                logger.info(
                    "collector_started",
                    source_id=source.id,
                    source_type=source.source_type.value,
                    parser_type=source.parser_type.value,
                )
            except Exception as e:
                logger.error(
                    "collector_start_error",
                    source_id=source.id,
                    error=str(e),
                )

    async def _stop_collectors(self) -> None:
        """Stop all collectors."""
        logger.info("stopping_collectors", count=len(self._collectors))

        # Cancel all tasks
        for source_id, task in self._tasks.items():
            task.cancel()

        # Wait for tasks to complete
        if self._tasks:
            await asyncio.gather(*self._tasks.values(), return_exceptions=True)

        self._tasks.clear()
        self._collectors.clear()

    async def run(self) -> None:
        """Run the collector worker."""
        logger.info("collector_worker_starting")

        # Initialize database
        await init_db()

        # Connect to event bus
        self._event_bus = await get_event_bus()

        self._running = True

        try:
            # Start collectors
            await self._start_collectors()

            # Wait for shutdown signal
            await self._shutdown_event.wait()

        except asyncio.CancelledError:
            logger.info("collector_worker_cancelled")
        finally:
            self._running = False
            await self._stop_collectors()

            if self._event_bus:
                await self._event_bus.disconnect()

            logger.info("collector_worker_stopped")

    def shutdown(self) -> None:
        """Signal the worker to shut down."""
        logger.info("collector_worker_shutdown_requested")
        self._running = False
        self._shutdown_event.set()


async def main() -> None:
    """Main entry point for the collector worker."""
    worker = CollectorWorker()

    # Handle shutdown signals
    loop = asyncio.get_running_loop()

    def signal_handler():
        worker.shutdown()

    for sig in (signal.SIGINT, signal.SIGTERM):
        try:
            loop.add_signal_handler(sig, signal_handler)
        except NotImplementedError:
            # Windows doesn't support add_signal_handler
            pass

    await worker.run()


if __name__ == "__main__":
    asyncio.run(main())
