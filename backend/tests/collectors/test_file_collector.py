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

        with pytest.raises(FileNotFoundError, match="Path not found"):
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
    async def test_connection_directory_mode(self):
        """Test connection test with a directory (directory mode is now supported)."""
        with tempfile.TemporaryDirectory() as temp_dir:
            # Create a test file in the directory
            (Path(temp_dir) / "test.log").write_text("test\n")

            source = create_mock_source(config={"path": temp_dir, "file_pattern": "*.log"})
            collector = FileWatchCollector(source, MagicMock())

            success, message = await collector.test_connection()

            assert success is True
            assert "directory" in message.lower() or "readable" in message.lower()

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
        with tempfile.NamedTemporaryFile(mode="w", delete=False, suffix=".log") as f:
            f.write("test\n")
            temp_path = f.name

        try:
            # Create a real collector for proper pattern matching
            source = create_mock_source(config={"path": temp_path})
            mock_parser = MagicMock()
            collector = FileWatchCollector(source, mock_parser)
            collector._loop = asyncio.new_event_loop()
            collector._on_file_modified = AsyncMock()

            handler = FileEventHandler(collector)

            # Create a mock file event for the watched file
            event = MagicMock()
            event.is_directory = False
            event.src_path = temp_path

            with patch("asyncio.run_coroutine_threadsafe") as mock_run:
                handler.on_modified(event)
                mock_run.assert_called_once()

            collector._loop.close()
        finally:
            os.unlink(temp_path)

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


class TestFileWatchCollectorDirectoryMode:
    """Tests for directory watching mode."""

    def test_is_directory_mode_with_file(self):
        """Test is_directory_mode returns False for a file path."""
        with tempfile.NamedTemporaryFile(mode="w", delete=False, suffix=".log") as f:
            f.write("test\n")
            temp_path = f.name

        try:
            source = create_mock_source(config={"path": temp_path})
            collector = FileWatchCollector(source, MagicMock())
            assert collector.is_directory_mode is False
        finally:
            os.unlink(temp_path)

    def test_is_directory_mode_with_directory(self):
        """Test is_directory_mode returns True for a directory path."""
        with tempfile.TemporaryDirectory() as temp_dir:
            source = create_mock_source(config={"path": temp_dir})
            collector = FileWatchCollector(source, MagicMock())
            assert collector.is_directory_mode is True

    def test_file_pattern_property_default(self):
        """Test file_pattern defaults to '*'."""
        source = create_mock_source(config={"path": "/test"})
        collector = FileWatchCollector(source, MagicMock())
        assert collector.file_pattern == "*"

    def test_file_pattern_property_custom(self):
        """Test file_pattern with custom pattern."""
        source = create_mock_source(config={"path": "/test", "file_pattern": "*.log"})
        collector = FileWatchCollector(source, MagicMock())
        assert collector.file_pattern == "*.log"

    def test_scan_directory(self):
        """Test scanning directory for matching files."""
        with tempfile.TemporaryDirectory() as temp_dir:
            # Create test files
            (Path(temp_dir) / "app.log").write_text("line1\n")
            (Path(temp_dir) / "app2.log").write_text("line2\n")
            (Path(temp_dir) / "data.txt").write_text("line3\n")

            source = create_mock_source(config={"path": temp_dir, "file_pattern": "*.log"})
            collector = FileWatchCollector(source, MagicMock())

            files = collector._scan_directory()
            assert len(files) == 2
            assert all(f.suffix == ".log" for f in files)

    def test_open_directory(self):
        """Test opening all matching files in a directory."""
        with tempfile.TemporaryDirectory() as temp_dir:
            # Create test files
            (Path(temp_dir) / "app.log").write_text("line1\n")
            (Path(temp_dir) / "app2.log").write_text("line2\n")
            (Path(temp_dir) / "data.txt").write_text("line3\n")

            source = create_mock_source(
                config={"path": temp_dir, "file_pattern": "*.log", "read_from_end": False}
            )
            collector = FileWatchCollector(source, MagicMock())

            collector._open_file()

            assert len(collector._file_handles) == 2
            assert len(collector._file_positions) == 2

            # Clean up
            for handle in collector._file_handles.values():
                handle.close()

    def test_read_lines_from_multiple_files(self):
        """Test reading lines from multiple files in directory mode."""
        with tempfile.TemporaryDirectory() as temp_dir:
            # Create test files
            (Path(temp_dir) / "app1.log").write_text("line1\nline2\n")
            (Path(temp_dir) / "app2.log").write_text("line3\nline4\n")

            source = create_mock_source(
                config={"path": temp_dir, "file_pattern": "*.log", "read_from_end": False}
            )
            collector = FileWatchCollector(source, MagicMock())

            collector._open_file()
            lines = collector._read_new_lines()

            assert len(lines) == 4
            assert "line1" in lines
            assert "line2" in lines
            assert "line3" in lines
            assert "line4" in lines

            # Clean up
            for handle in collector._file_handles.values():
                handle.close()

    def test_position_tracking_per_file(self):
        """Test that positions are tracked independently per file."""
        with tempfile.TemporaryDirectory() as temp_dir:
            file1 = Path(temp_dir) / "app1.log"
            file2 = Path(temp_dir) / "app2.log"
            file1.write_text("line1\n")
            file2.write_text("line2\nline3\n")

            source = create_mock_source(
                config={"path": temp_dir, "file_pattern": "*.log", "read_from_end": False}
            )
            collector = FileWatchCollector(source, MagicMock())

            collector._open_file()
            collector._read_new_lines()

            # Each file should have its own position
            assert len(collector._file_positions) == 2
            assert collector._file_positions[file1] > 0
            assert collector._file_positions[file2] > collector._file_positions[file1]

            # Clean up
            for handle in collector._file_handles.values():
                handle.close()

    @pytest.mark.asyncio
    async def test_start_directory_mode(self):
        """Test starting collector in directory mode."""
        with tempfile.TemporaryDirectory() as temp_dir:
            (Path(temp_dir) / "app.log").write_text("test\n")

            source = create_mock_source(
                config={"path": temp_dir, "file_pattern": "*.log", "follow": True}
            )
            collector = FileWatchCollector(source, MagicMock())

            await collector.start()

            assert collector.is_running()
            assert collector._observer is not None
            assert len(collector._file_handles) == 1

            await collector.stop()

    @pytest.mark.asyncio
    async def test_stop_closes_all_handles(self):
        """Test that stop closes all file handles in directory mode."""
        with tempfile.TemporaryDirectory() as temp_dir:
            (Path(temp_dir) / "app1.log").write_text("test1\n")
            (Path(temp_dir) / "app2.log").write_text("test2\n")

            source = create_mock_source(
                config={"path": temp_dir, "file_pattern": "*.log"}
            )
            collector = FileWatchCollector(source, MagicMock())

            await collector.start()
            assert len(collector._file_handles) == 2

            await collector.stop()
            assert len(collector._file_handles) == 0
            assert len(collector._file_positions) == 0

    @pytest.mark.asyncio
    async def test_connection_directory_success(self):
        """Test connection test for directory mode."""
        with tempfile.TemporaryDirectory() as temp_dir:
            (Path(temp_dir) / "app.log").write_text("test\n")

            source = create_mock_source(
                config={"path": temp_dir, "file_pattern": "*.log"}
            )
            collector = FileWatchCollector(source, MagicMock())

            success, message = await collector.test_connection()

            assert success is True
            assert "readable" in message.lower()
            assert "1 files match" in message

    @pytest.mark.asyncio
    async def test_connection_directory_no_matching_files(self):
        """Test connection test for directory with no matching files."""
        with tempfile.TemporaryDirectory() as temp_dir:
            (Path(temp_dir) / "app.txt").write_text("test\n")  # .txt not .log

            source = create_mock_source(
                config={"path": temp_dir, "file_pattern": "*.log"}
            )
            collector = FileWatchCollector(source, MagicMock())

            success, message = await collector.test_connection()

            assert success is True  # Directory exists
            assert "no files match" in message.lower()

    @pytest.mark.asyncio
    async def test_on_file_created(self):
        """Test handling of new file creation."""
        with tempfile.TemporaryDirectory() as temp_dir:
            # Start with one file
            (Path(temp_dir) / "app1.log").write_text("initial\n")

            source = create_mock_source(
                config={"path": temp_dir, "file_pattern": "*.log"}
            )
            collector = FileWatchCollector(source, MagicMock())

            await collector.start()
            initial_count = len(collector._file_handles)
            assert initial_count == 1

            # Simulate new file creation
            new_file = Path(temp_dir) / "app2.log"
            new_file.write_text("new content\n")
            await collector._on_file_created(new_file)

            # Should have opened the new file
            assert len(collector._file_handles) == 2
            assert new_file in collector._file_handles

            await collector.stop()

    @pytest.mark.asyncio
    async def test_on_file_deleted(self):
        """Test handling of file deletion."""
        with tempfile.TemporaryDirectory() as temp_dir:
            file1 = Path(temp_dir) / "app1.log"
            file2 = Path(temp_dir) / "app2.log"
            file1.write_text("content1\n")
            file2.write_text("content2\n")

            source = create_mock_source(
                config={"path": temp_dir, "file_pattern": "*.log"}
            )
            collector = FileWatchCollector(source, MagicMock())

            await collector.start()
            assert len(collector._file_handles) == 2

            # Simulate file deletion
            await collector._on_file_deleted(file1)

            # Should have removed the file handle
            assert len(collector._file_handles) == 1
            assert file1 not in collector._file_handles
            assert file2 in collector._file_handles

            await collector.stop()


class TestFileEventHandlerPatternMatching:
    """Tests for FileEventHandler pattern matching."""

    def test_matches_pattern_single_file_mode(self):
        """Test pattern matching in single file mode."""
        with tempfile.NamedTemporaryFile(mode="w", delete=False, suffix=".log") as f:
            f.write("test\n")
            temp_path = f.name

        try:
            source = create_mock_source(config={"path": temp_path})
            collector = FileWatchCollector(source, MagicMock())
            handler = FileEventHandler(collector)

            # Should match the exact file
            assert handler._matches_pattern(temp_path) is True
            # Should not match other files
            assert handler._matches_pattern("/other/path.log") is False
        finally:
            os.unlink(temp_path)

    def test_matches_pattern_directory_mode(self):
        """Test pattern matching in directory mode."""
        with tempfile.TemporaryDirectory() as temp_dir:
            source = create_mock_source(
                config={"path": temp_dir, "file_pattern": "*.log"}
            )
            collector = FileWatchCollector(source, MagicMock())
            handler = FileEventHandler(collector)

            # Should match .log files
            assert handler._matches_pattern(f"{temp_dir}/app.log") is True
            assert handler._matches_pattern(f"{temp_dir}/error.log") is True
            # Should not match .txt files
            assert handler._matches_pattern(f"{temp_dir}/data.txt") is False

    def test_matches_pattern_complex_glob(self):
        """Test pattern matching with complex glob patterns."""
        with tempfile.TemporaryDirectory() as temp_dir:
            source = create_mock_source(
                config={"path": temp_dir, "file_pattern": "app-*.log"}
            )
            collector = FileWatchCollector(source, MagicMock())
            handler = FileEventHandler(collector)

            # Should match app-*.log pattern
            assert handler._matches_pattern(f"{temp_dir}/app-2024.log") is True
            assert handler._matches_pattern(f"{temp_dir}/app-error.log") is True
            # Should not match other patterns
            assert handler._matches_pattern(f"{temp_dir}/error.log") is False
            assert handler._matches_pattern(f"{temp_dir}/app.log") is False
