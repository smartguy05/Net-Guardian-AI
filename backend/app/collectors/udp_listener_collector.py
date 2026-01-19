"""UDP listener collector for NetFlow/sFlow data.

Listens on a UDP port for incoming flow data and parses it using
the configured parser (NetFlow or sFlow).
"""

import asyncio
from typing import Any, AsyncGenerator, Dict, Optional

import structlog

from app.collectors.base import BaseCollector
from app.collectors.registry import register_collector
from app.models.log_source import LogSource, SourceType
from app.parsers.base import BaseParser, ParseResult

logger = structlog.get_logger()


class UDPServerProtocol(asyncio.DatagramProtocol):
    """UDP protocol handler for flow data."""

    def __init__(self, queue: asyncio.Queue, parser: BaseParser):
        self.queue = queue
        self.parser = parser
        self.transport: Optional[asyncio.DatagramTransport] = None

    def connection_made(self, transport: asyncio.DatagramTransport) -> None:
        """Called when the socket is ready."""
        self.transport = transport

    def datagram_received(self, data: bytes, addr: tuple[str, int]) -> None:
        """Process received UDP datagram."""
        try:
            # Parse the binary data
            results = self.parser.parse(data)
            for result in results:
                # Add source IP info
                result.parsed_fields["collector_source_ip"] = addr[0]
                result.parsed_fields["collector_source_port"] = addr[1]
                # Put result in queue (non-blocking)
                try:
                    self.queue.put_nowait(result)
                except asyncio.QueueFull:
                    logger.warning("udp_collector_queue_full", source_ip=addr[0])
        except Exception as e:
            logger.warning(
                "udp_datagram_parse_error",
                error=str(e),
                source_ip=addr[0],
                data_length=len(data),
            )

    def error_received(self, exc: Exception) -> None:
        """Handle errors."""
        logger.error("udp_protocol_error", error=str(exc))

    def connection_lost(self, exc: Optional[Exception]) -> None:
        """Called when the connection is lost."""
        if exc:
            logger.warning("udp_connection_lost", error=str(exc))


@register_collector(SourceType.UDP_LISTEN)
class UDPListenerCollector(BaseCollector):
    """Collector that listens for UDP packets (NetFlow/sFlow).

    Config options:
        host: IP address to bind to (default: "0.0.0.0")
        port: UDP port to listen on (required)
        queue_size: Max queued events before dropping (default: 10000)
        allowed_sources: List of allowed source IPs (optional, allows all if not set)
    """

    def __init__(self, source: LogSource, parser: BaseParser):
        """Initialize the UDP listener collector."""
        super().__init__(source, parser)
        self._queue: asyncio.Queue = asyncio.Queue(
            maxsize=self.config.get("queue_size", 10000)
        )
        self._transport: Optional[asyncio.DatagramTransport] = None
        self._protocol: Optional[UDPServerProtocol] = None
        self._host = self.config.get("host", "0.0.0.0")
        self._port = self.config.get("port")
        self._allowed_sources = set(self.config.get("allowed_sources", []))

    async def collect(self) -> AsyncGenerator[ParseResult, None]:
        """Yield parsed events from the UDP queue.

        Yields:
            ParseResult objects from received UDP packets.
        """
        while self._running:
            try:
                # Get from queue with timeout to allow checking _running
                result = await asyncio.wait_for(
                    self._queue.get(),
                    timeout=1.0,
                )
                # Check source filter
                if self._allowed_sources:
                    source_ip = result.parsed_fields.get("collector_source_ip")
                    if source_ip not in self._allowed_sources:
                        continue
                yield result
            except asyncio.TimeoutError:
                continue
            except Exception as e:
                logger.error("udp_collect_error", error=str(e))
                await asyncio.sleep(1.0)

    async def start(self) -> None:
        """Start listening for UDP packets."""
        if not self._port:
            raise ValueError("UDP port not configured for source")

        self._running = True

        # Create UDP endpoint
        loop = asyncio.get_running_loop()

        try:
            self._transport, self._protocol = await loop.create_datagram_endpoint(
                lambda: UDPServerProtocol(self._queue, self.parser),
                local_addr=(self._host, self._port),
            )
            logger.info(
                "udp_listener_started",
                source_id=self.source_id,
                host=self._host,
                port=self._port,
            )
        except OSError as e:
            logger.error(
                "udp_listener_bind_failed",
                source_id=self.source_id,
                host=self._host,
                port=self._port,
                error=str(e),
            )
            self._running = False
            raise

    async def stop(self) -> None:
        """Stop the UDP listener."""
        self._running = False

        if self._transport:
            self._transport.close()
            self._transport = None
            self._protocol = None

        # Clear the queue
        while not self._queue.empty():
            try:
                self._queue.get_nowait()
            except asyncio.QueueEmpty:
                break

        logger.info("udp_listener_stopped", source_id=self.source_id)

    async def test_connection(self) -> tuple[bool, str]:
        """Test that we can bind to the configured port."""
        if not self._port:
            return False, "UDP port not configured"

        try:
            # Try to create a temporary socket
            loop = asyncio.get_running_loop()
            transport, _ = await loop.create_datagram_endpoint(
                asyncio.DatagramProtocol,
                local_addr=(self._host, self._port),
            )
            transport.close()
            return True, f"Successfully bound to {self._host}:{self._port}"
        except OSError as e:
            return False, f"Failed to bind to {self._host}:{self._port}: {e}"
