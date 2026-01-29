"""Tests for the file watch collector."""

import asyncio
import os
import tempfile
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from app.collectors.file_collector import FileEventHandler, FileWatchCollector
from app.models.log_source import LogSource, SourceType
from app.parsers.base import ParseResult


def create_mock_source(config: dict = None, parser_config: dict = None) -> MagicMock:
    """Create a mock LogSource for testing."""
    source = MagicMock(spec=LogSource)
    source.id = "test-file-source"
    source.name = "Test File Source"
    source.source_type = SourceType.FILE_WATCH
    source.config = config or {
        "path": "/var/log/test.log",
        "follow": True,
        "encoding": "utf-8",
        "read_from_end": True,
        "batch_size": 100,
    }
    source.parser_type = "syslog"
    source.parser_config = parser_config or {}
    return source


class TestFileWatchCollectorInit:
    """Tests for FileWatchCollector initialization."""

    def test_init_basic(self):
        """Test basic collector initialization."""
        source = create_mock_source()
        parser = MagicMock()

        collector = FileWatchCollector(source, parser)

        assert collector.source_id == "test-file-source"
        assert collector.parser == parser
        assert not collector.is_running()

    def test_file_path_property(self):
        """Test file_path property."""
        source = create_mock_source(config={"path": "/var/log/custom.log"})
        collector = FileWatchCollector(source, MagicMock())

        assert collector.file_path == Path("/var/log/custom.log")

    def test_encoding_property(self):
        """Test encoding property."""
        source = create_mock_source(config={"path": "/test", "encoding": "latin-1"})
        collector = FileWatchCollector(source, MagicMock())

        assert collector.encoding == "latin-1"

    def test_encoding_default(self):
        """Test default encoding is utf-8."""
        source = create_mock_source(config={"path": "/test"})
        collector = FileWatchCollector(source, MagicMock())

        assert collector.encoding == "utf-8"


class TestFileWatchCollectorOpenFile:
    """Tests for file opening logic."""

    def test_open_file_not_found(self):
        """Test that FileNotFoundError is raised for missing files."""
        source = create_mock_source(config={"path": "/nonexistent/path.log"})
        collector = FileWatchCollector(source, MagicMock())

        with pytest.raises(FileNotFoundError, match="Log file not found"):
            collector._open_file()

    def test_open_file_read_from_end(self):
        """Test file opening with read_from_end=True."""
        with tempfile.NamedTemporaryFile(mode="w", delete=False, suffix=".log") as f:
            f.write("line1\nline2\nline3\n")
            temp_path = f.name

        try:
            source = create_mock_source(
                config={
                    "path": temp_path,
                    "read_from_end": True,
                }
            )
            collector = FileWatchCollector(source, MagicMock())

            collector._open_file()

            # Position should be at end of file
            assert collector._file_position > 0
            assert collector._file_handle is not None
        finally:
            if collector._file_handle:
                collector._file_handle.close()
            os.unlink(temp_path)

    def test_open_file_read_from_start(self):
        """Test file opening with read_from_end=False."""
        with tempfile.NamedTemporaryFile(mode="w", delete=False, suffix=".log") as f:
            f.write("line1\nline2\nline3\n")
            temp_path = f.name

        try:
            source = create_mock_source(
                config={
                    "path": temp_path,
                    "read_from_end": False,
                }
            )
            collector = FileWatchCollector(source, MagicMock())

            collector._open_file()

            # Position should be at start of file
            assert collector._file_position == 0
            assert collector._file_handle is not None
        finally:
            if collector._file_handle:
                collector._file_handle.close()
            os.unlink(temp_path)

    def test_open_file_already_open(self):
        """Test that opening an already open file is a no-op."""
        with tempfile.NamedTemporaryFile(mode="w", delete=False, suffix=".log") as f:
            f.write("test\n")
            temp_path = f.name

        try:
            source = create_mock_source(config={"path": temp_path})
            collector = FileWatchCollector(source, MagicMock())

            collector._open_file()
            first_handle = collector._file_handle

            collector._open_file()  # Should not create a new handle
            assert collector._file_handle is first_handle
        finally:
            if collector._file_handle:
                collector._file_handle.close()
            os.unlink(temp_path)


class TestFileWatchCollectorReadLines:
    """Tests for line reading logic."""

    def test_read_new_lines(self):
        """Test reading new lines from file."""
        with tempfile.NamedTemporaryFile(mode="w", delete=False, suffix=".log") as f:
            f.write("line1\nline2\nline3\n")
            temp_path = f.name

        try:
            source = create_mock_source(
                config={
                    "path": temp_path,
                    "read_from_end": False,  # Start from beginning
                }
            )
            collector = FileWatchCollector(source, MagicMock())

            collector._open_file()
            lines = collector._read_new_lines()

            assert len(lines) == 3
            assert lines[0] == "line1"
            assert lines[1] == "line2"
            assert lines[2] == "line3"
        finally:
            if collector._file_handle:
                collector._file_handle.close()
            os.unlink(temp_path)

    def test_read_new_lines_no_handle(self):
        """Test reading without an open file handle returns empty list."""
        source = create_mock_source()
        collector = FileWatchCollector(source, MagicMock())

        lines = collector._read_new_lines()

        assert lines == []

    def test_read_new_lines_batch_limit(self):
        """Test that batch_size limits lines read."""
        with tempfile.NamedTemporaryFile(mode="w", delete=False, suffix=".log") as f:
            for i in range(200):
                f.write(f"line{i}\n")
            temp_path = f.name

        try:
            source = create_mock_source(
                config={
                    "path": temp_path,
                    "read_from_end": False,
                    "batch_size": 50,  # Limit to 50 lines per batch
                }
            )
            collector = FileWatchCollector(source, MagicMock())

            collector._open_file()
            lines = collector._read_new_lines()

            assert len(lines) == 50
        finally:
            if collector._file_handle:
                collector._file_handle.close()
            os.unlink(temp_path)

    def test_read_new_lines_strips_newlines(self):
        """Test that newline characters are stripped."""
        with tempfile.NamedTemporaryFile(mode="w", delete=False, suffix=".log") as f:
            f.write("line1\r\nline2\n")
            temp_path = f.name

        try:
            source = create_mock_source(
                config={
                    "path": temp_path,
                    "read_from_end": False,
                }
            )
            collector = FileWatchCollector(source, MagicMock())

            collector._open_file()
            lines = collector._read_new_lines()

            assert "line1" in lines
            assert "\r" not in lines[0]
            assert "\n" not in lines[0]
        finally:
            if collector._file_handle:
                collector._file_handle.close()
            os.unlink(temp_path)


class TestFileWatchCollectorStartStop:
    """Tests for start/stop lifecycle."""

    @pytest.mark.asyncio
    async def test_start_creates_observer(self):
        """Test that start creates a watchdog observer."""
        with tempfile.NamedTemporaryFile(mode="w", delete=False, suffix=".log") as f:
            f.write("test\n")
            temp_path = f.name

        try:
            source = create_mock_source(
                config={
                    "path": temp_path,
                    "follow": True,
                }
            )
            collector = FileWatchCollector(source, MagicMock())

            await collector.start()

            assert collector.is_running()
            assert collector._observer is not None
            assert collector._read_task is not None

            await collector.stop()
        finally:
            os.unlink(temp_path)

    @pytest.mark.asyncio
    async def test_start_without_follow(self):
        """Test start without file watching (follow=False)."""
        with tempfile.NamedTemporaryFile(mode="w", delete=False, suffix=".log") as f:
            f.write("test\n")
            temp_path = f.name

        try:
            source = create_mock_source(
                config={
                    "path": temp_path,
                    "follow": False,
                }
            )
            collector = FileWatchCollector(source, MagicMock())

            await collector.start()

            assert collector.is_running()
            assert collector._observer is None  # No observer when not following
            assert collector._read_task is not None

            await collector.stop()
        finally:
            os.unlink(temp_path)

    @pytest.mark.asyncio
    async def test_stop_cleans_up(self):
        """Test that stop properly cleans up resources."""
        with tempfile.NamedTemporaryFile(mode="w", delete=False, suffix=".log") as f:
            f.write("test\n")
            temp_path = f.name

        try:
            source = create_mock_source(config={"path": temp_path, "follow": True})
            collector = FileWatchCollector(source, MagicMock())

            await collector.start()
            await collector.stop()

            assert not collector.is_running()
            assert collector._observer is None
            assert collector._read_task is None
            assert collector._file_handle is None
        finally:
            os.unlink(temp_path)

    @pytest.mark.asyncio
    async def test_start_already_running(self):
        """Test that starting an already running collector is a no-op."""
        with tempfile.NamedTemporaryFile(mode="w", delete=False, suffix=".log") as f:
            f.write("test\n")
            temp_path = f.name

        try:
            source = create_mock_source(config={"path": temp_path})
            collector = FileWatchCollector(source, MagicMock())

            await collector.start()
            first_observer = collector._observer

            await collector.start()  # Should be no-op
            assert collector._observer is first_observer

            await collector.stop()
        finally:
            os.unlink(temp_path)


class TestFileWatchCollectorTestConnection:
    """Tests for test_connection method."""

    @pytest.mark.asyncio
    async def test_connection_file_not_found(self):
        """Test connection test with missing file."""
        source = create_mock_source(config={"path": "/nonexistent/file.log"})
        collector = FileWatchCollector(source, MagicMock())

        success, message = await collector.test_connection()

        assert success is False
        assert "not found" in message.lower()

    @pytest.mark.asyncio
    async def test_connection_not_a_file(self):
        """Test connection test with a directory."""
        with tempfile.TemporaryDirectory() as temp_dir:
            source = create_mock_source(config={"path": temp_dir})
            collector = FileWatchCollector(source, MagicMock())

            success, message = await collector.test_connection()

            assert success is False
            assert "not a file" in message.lower()

    @pytest.mark.asyncio
    async def test_connection_success(self):
        """Test successful connection test."""
        with tempfile.NamedTemporaryFile(mode="w", delete=False, suffix=".log") as f:
            f.write("test line\n")
            temp_path = f.name

        try:
            source = create_mock_source(config={"path": temp_path})
            collector = FileWatchCollector(source, MagicMock())

            success, message = await collector.test_connection()

            assert success is True
            assert "readable" in message.lower()
        finally:
            os.unlink(temp_path)


class TestFileWatchCollectorCollect:
    """Tests for the collect async generator."""

    @pytest.mark.asyncio
    async def test_collect_yields_results(self):
        """Test that collect yields parse results from queue."""
        source = create_mock_source()
        collector = FileWatchCollector(source, MagicMock())

        # Manually put results in queue
        collector._running = True
        mock_result = MagicMock(spec=ParseResult)
        await collector._event_queue.put(mock_result)

        results = []
        async for result in collector.collect():
            results.append(result)
            collector._running = False  # Stop after first result
            break

        assert len(results) == 1
        assert results[0] == mock_result


class TestFileEventHandler:
    """Tests for the FileEventHandler class."""

    def test_on_modified_signals_collector(self):
        """Test that on_modified signals the collector."""
        mock_collector = MagicMock()
        mock_collector._loop = asyncio.new_event_loop()
        mock_collector._on_file_modified = AsyncMock()

        handler = FileEventHandler(mock_collector)

        # Create a mock file event
        event = MagicMock()
        event.is_directory = False

        with patch("asyncio.run_coroutine_threadsafe") as mock_run:
            handler.on_modified(event)
            mock_run.assert_called_once()

        mock_collector._loop.close()

    def test_on_modified_ignores_directories(self):
        """Test that on_modified ignores directory events."""
        mock_collector = MagicMock()
        handler = FileEventHandler(mock_collector)

        # Create a directory event
        event = MagicMock()
        event.is_directory = True

        with patch("asyncio.run_coroutine_threadsafe") as mock_run:
            handler.on_modified(event)
            mock_run.assert_not_called()
