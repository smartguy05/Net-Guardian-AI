"""Collector worker entry point.

This module runs as a separate process to collect logs from configured sources.
"""

import asyncio
import signal

import structlog

# Import collectors and parsers to register them
from app.collectors import api_pull_collector, file_collector  # noqa: F401
from app.config import settings
from app.core.logging import setup_logging
from app.db.session import close_db, init_db
from app.events.bus import close_event_bus, get_event_bus
from app.parsers import (  # noqa: F401
    adguard_parser,
    custom_parser,
    json_parser,
    nginx_parser,
    syslog_parser,
)
from app.services.collector_service import (
    start_collector_service,
    stop_collector_service,
)

logger = structlog.get_logger()


class CollectorWorker:
    """Main collector worker process."""

    def __init__(self):
        self._shutdown_event: asyncio.Event = asyncio.Event()
        self._loop: asyncio.AbstractEventLoop | None = None

    def _signal_handler(self, sig: signal.Signals) -> None:
        """Handle shutdown signals."""
        logger.info("shutdown_signal_received", signal=sig.name)
        self._shutdown_event.set()

    async def run(self) -> None:
        """Run the collector worker."""
        setup_logging()

        logger.info(
            "collector_worker_starting",
            debug=settings.debug,
        )

        # Set up signal handlers
        self._loop = asyncio.get_running_loop()
        for sig in (signal.SIGTERM, signal.SIGINT):
            try:
                self._loop.add_signal_handler(
                    sig,
                    lambda s=sig: self._signal_handler(s),
                )
            except NotImplementedError:
                # Windows doesn't support add_signal_handler
                signal.signal(sig, lambda s, f, sig=sig: self._signal_handler(sig))

        try:
            # Initialize database connection
            await init_db()
            logger.info("database_connected")

            # Initialize event bus
            await get_event_bus()
            logger.info("event_bus_connected")

            # Start collector service
            await start_collector_service()
            logger.info("collector_service_started")

            # Wait for shutdown signal
            await self._shutdown_event.wait()

        except Exception as e:
            logger.error("collector_worker_error", error=str(e))
            raise
        finally:
            # Shutdown
            logger.info("collector_worker_shutting_down")

            await stop_collector_service()
            await close_event_bus()
            await close_db()

            logger.info("collector_worker_stopped")


def main() -> None:
    """Entry point for the collector worker."""
    worker = CollectorWorker()
    asyncio.run(worker.run())


if __name__ == "__main__":
    main()
