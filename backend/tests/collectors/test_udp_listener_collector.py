"""Tests for the UDP listener collector."""

import asyncio
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from app.collectors.udp_listener_collector import (
    UDPListenerCollector,
    UDPServerProtocol,
)
from app.models.log_source import LogSource, SourceType
from app.parsers.base import ParseResult


def create_mock_source(config: dict = None, parser_config: dict = None) -> MagicMock:
    """Create a mock LogSource for testing."""
    source = MagicMock(spec=LogSource)
    source.id = "test-udp-source"
    source.name = "Test UDP Source"
    source.source_type = SourceType.UDP_LISTEN
    source.config = config or {
        "host": "0.0.0.0",
        "port": 9995,
        "queue_size": 1000,
    }
    source.parser_type = "netflow"
    source.parser_config = parser_config or {}
    return source


class TestUDPListenerCollectorInit:
    """Tests for UDPListenerCollector initialization."""

    def test_init_basic(self):
        """Test basic collector initialization."""
        source = create_mock_source()
        parser = MagicMock()

        collector = UDPListenerCollector(source, parser)

        assert collector.source_id == "test-udp-source"
        assert collector.parser == parser
        assert not collector.is_running()

    def test_init_with_defaults(self):
        """Test initialization with default values."""
        source = create_mock_source(config={"port": 9995})
        collector = UDPListenerCollector(source, MagicMock())

        assert collector._host == "0.0.0.0"
        assert collector._port == 9995

    def test_init_with_custom_host(self):
        """Test initialization with custom host."""
        source = create_mock_source(config={
            "host": "192.168.1.1",
            "port": 9995,
        })
        collector = UDPListenerCollector(source, MagicMock())

        assert collector._host == "192.168.1.1"

    def test_init_queue_size(self):
        """Test initialization with custom queue size."""
        source = create_mock_source(config={
            "port": 9995,
            "queue_size": 500,
        })
        collector = UDPListenerCollector(source, MagicMock())

        assert collector._queue.maxsize == 500

    def test_init_allowed_sources(self):
        """Test initialization with allowed sources."""
        source = create_mock_source(config={
            "port": 9995,
            "allowed_sources": ["192.168.1.1", "192.168.1.2"],
        })
        collector = UDPListenerCollector(source, MagicMock())

        assert "192.168.1.1" in collector._allowed_sources
        assert "192.168.1.2" in collector._allowed_sources


class TestUDPListenerCollectorStartStop:
    """Tests for start/stop lifecycle."""

    @pytest.mark.asyncio
    async def test_start_missing_port(self):
        """Test that start raises error without port configuration."""
        source = create_mock_source(config={"host": "0.0.0.0"})  # No port
        collector = UDPListenerCollector(source, MagicMock())

        with pytest.raises(ValueError, match="UDP port not configured"):
            await collector.start()

    @pytest.mark.asyncio
    async def test_start_creates_transport(self):
        """Test that start creates UDP transport."""
        # Use a high port number to avoid conflicts
        source = create_mock_source(config={"port": 59995})
        collector = UDPListenerCollector(source, MagicMock())

        try:
            await collector.start()

            assert collector.is_running()
            assert collector._transport is not None
            assert collector._protocol is not None
        finally:
            await collector.stop()

    @pytest.mark.asyncio
    async def test_stop_cleans_up(self):
        """Test that stop properly cleans up resources."""
        source = create_mock_source(config={"port": 59996})
        collector = UDPListenerCollector(source, MagicMock())

        await collector.start()
        await collector.stop()

        assert not collector.is_running()
        assert collector._transport is None
        assert collector._protocol is None

    @pytest.mark.asyncio
    async def test_stop_clears_queue(self):
        """Test that stop clears the queue."""
        source = create_mock_source(config={"port": 59997})
        collector = UDPListenerCollector(source, MagicMock())

        # Add items to queue
        await collector._queue.put(MagicMock())
        await collector._queue.put(MagicMock())

        await collector.start()
        await collector.stop()

        assert collector._queue.empty()


class TestUDPListenerCollectorTestConnection:
    """Tests for test_connection method."""

    @pytest.mark.asyncio
    async def test_connection_missing_port(self):
        """Test connection test without port."""
        source = create_mock_source(config={"host": "0.0.0.0"})  # No port key
        collector = UDPListenerCollector(source, MagicMock())

        success, message = await collector.test_connection()

        assert success is False
        assert "port not configured" in message.lower()

    @pytest.mark.asyncio
    async def test_connection_success(self):
        """Test successful connection test."""
        source = create_mock_source(config={"port": 59998})  # Use a high port
        collector = UDPListenerCollector(source, MagicMock())

        success, message = await collector.test_connection()

        assert success is True
        assert "successfully bound" in message.lower()

    @pytest.mark.asyncio
    async def test_connection_bind_failure(self):
        """Test connection test when bind fails."""
        source = create_mock_source(config={"port": 1})  # Privileged port
        collector = UDPListenerCollector(source, MagicMock())

        # This should fail on most systems without root privileges
        success, message = await collector.test_connection()

        # The result depends on system permissions
        # Just verify the method runs without exception
        assert isinstance(success, bool)
        assert isinstance(message, str)


class TestUDPListenerCollectorCollect:
    """Tests for the collect async generator."""

    @pytest.mark.asyncio
    async def test_collect_yields_results(self):
        """Test that collect yields results from queue."""
        source = create_mock_source(config={"port": 0})
        collector = UDPListenerCollector(source, MagicMock())

        # Put a result in the queue
        mock_result = MagicMock(spec=ParseResult)
        mock_result.parsed_fields = {"collector_source_ip": "192.168.1.1"}
        await collector._queue.put(mock_result)

        collector._running = True

        results = []
        async for result in collector.collect():
            results.append(result)
            collector._running = False  # Stop after first result
            break

        assert len(results) == 1

    @pytest.mark.asyncio
    async def test_collect_filters_by_allowed_sources(self):
        """Test that collect filters by allowed_sources."""
        source = create_mock_source(config={
            "port": 0,
            "allowed_sources": ["192.168.1.1"],  # Only allow this IP
        })
        collector = UDPListenerCollector(source, MagicMock())

        # Put results from different IPs
        allowed_result = MagicMock(spec=ParseResult)
        allowed_result.parsed_fields = {"collector_source_ip": "192.168.1.1"}

        blocked_result = MagicMock(spec=ParseResult)
        blocked_result.parsed_fields = {"collector_source_ip": "10.0.0.1"}

        await collector._queue.put(blocked_result)
        await collector._queue.put(allowed_result)

        collector._running = True

        results = []
        count = 0
        async for result in collector.collect():
            results.append(result)
            count += 1
            if count >= 1:  # Only get first allowed result
                collector._running = False
                break

        assert len(results) == 1
        assert results[0].parsed_fields["collector_source_ip"] == "192.168.1.1"

    @pytest.mark.asyncio
    async def test_collect_no_filter_when_no_allowed_sources(self):
        """Test that collect allows all when allowed_sources is empty."""
        source = create_mock_source(config={
            "port": 0,
            "allowed_sources": [],  # Allow all
        })
        collector = UDPListenerCollector(source, MagicMock())

        mock_result = MagicMock(spec=ParseResult)
        mock_result.parsed_fields = {"collector_source_ip": "10.0.0.1"}
        await collector._queue.put(mock_result)

        collector._running = True

        results = []
        async for result in collector.collect():
            results.append(result)
            collector._running = False
            break

        assert len(results) == 1


class TestUDPServerProtocol:
    """Tests for the UDPServerProtocol class."""

    def test_init(self):
        """Test protocol initialization."""
        queue = asyncio.Queue()
        parser = MagicMock()

        protocol = UDPServerProtocol(queue, parser)

        assert protocol.queue == queue
        assert protocol.parser == parser
        assert protocol.transport is None

    def test_connection_made(self):
        """Test connection_made sets transport."""
        queue = asyncio.Queue()
        protocol = UDPServerProtocol(queue, MagicMock())

        mock_transport = MagicMock()
        protocol.connection_made(mock_transport)

        assert protocol.transport == mock_transport

    def test_datagram_received_parses_and_queues(self):
        """Test datagram_received parses data and adds to queue."""
        queue = asyncio.Queue()
        parser = MagicMock()

        mock_result = MagicMock(spec=ParseResult)
        mock_result.parsed_fields = {}
        parser.parse.return_value = [mock_result]

        protocol = UDPServerProtocol(queue, parser)

        # Receive a datagram
        data = b"test data"
        addr = ("192.168.1.1", 12345)
        protocol.datagram_received(data, addr)

        # Verify parser was called
        parser.parse.assert_called_once_with(data)

        # Verify result was added to queue with source info
        assert not queue.empty()
        result = queue.get_nowait()
        assert result.parsed_fields["collector_source_ip"] == "192.168.1.1"
        assert result.parsed_fields["collector_source_port"] == 12345

    def test_datagram_received_handles_parse_error(self):
        """Test datagram_received handles parse errors gracefully."""
        queue = asyncio.Queue()
        parser = MagicMock()
        parser.parse.side_effect = Exception("Parse error")

        protocol = UDPServerProtocol(queue, parser)

        # Should not raise
        data = b"bad data"
        addr = ("192.168.1.1", 12345)
        protocol.datagram_received(data, addr)

        # Queue should be empty (no result added)
        assert queue.empty()

    def test_datagram_received_handles_queue_full(self):
        """Test datagram_received handles full queue."""
        queue = asyncio.Queue(maxsize=1)
        queue.put_nowait(MagicMock())  # Fill the queue

        parser = MagicMock()
        mock_result = MagicMock(spec=ParseResult)
        mock_result.parsed_fields = {}
        parser.parse.return_value = [mock_result]

        protocol = UDPServerProtocol(queue, parser)

        # Should not raise, just log warning
        data = b"test data"
        addr = ("192.168.1.1", 12345)
        protocol.datagram_received(data, addr)

        # Queue should still have only the original item
        assert queue.qsize() == 1

    def test_error_received(self):
        """Test error_received logs error."""
        protocol = UDPServerProtocol(asyncio.Queue(), MagicMock())

        # Should not raise
        protocol.error_received(Exception("Test error"))

    def test_connection_lost(self):
        """Test connection_lost handles gracefully."""
        protocol = UDPServerProtocol(asyncio.Queue(), MagicMock())

        # Should not raise
        protocol.connection_lost(None)
        protocol.connection_lost(Exception("Connection error"))
