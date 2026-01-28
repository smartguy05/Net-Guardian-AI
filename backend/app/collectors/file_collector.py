"""File collector for watching and tailing log files."""

import asyncio
import os
from collections.abc import AsyncGenerator
from pathlib import Path

import structlog
from watchdog.events import FileModifiedEvent, FileSystemEventHandler
from watchdog.observers import Observer

from app.collectors.base import BaseCollector
from app.collectors.registry import register_collector
from app.models.log_source import LogSource, SourceType
from app.parsers.base import BaseParser, ParseResult

logger = structlog.get_logger()


class FileEventHandler(FileSystemEventHandler):
    """Watchdog event handler for file modifications."""

    def __init__(self, collector: "FileWatchCollector"):
        super().__init__()
        self.collector = collector

    def on_modified(self, event: FileModifiedEvent) -> None:
        """Handle file modification events."""
        if not event.is_directory:
            # Signal that file has new content
            asyncio.run_coroutine_threadsafe(
                self.collector._on_file_modified(),
                self.collector._loop,
            )


@register_collector(SourceType.FILE_WATCH)
class FileWatchCollector(BaseCollector):
    """Collector that watches and tails log files.

    Configuration options:
        path: Path to the log file to watch
        follow: Whether to follow the file (tail -f style)
        encoding: File encoding (default: utf-8)
        read_from_end: Start reading from end of file (default: True)
        batch_size: Number of lines to read at once (default: 100)
    """

    def __init__(self, source: LogSource, parser: BaseParser):
        super().__init__(source, parser)
        self._observer: Observer | None = None
        self._file_handle = None
        self._file_position: int = 0
        self._event_queue: asyncio.Queue = asyncio.Queue()
        self._loop: asyncio.AbstractEventLoop | None = None
        self._read_task: asyncio.Task | None = None
        self._file_modified = asyncio.Event()

    @property
    def file_path(self) -> Path:
        """Get the configured file path."""
        return Path(self.config.get("path", ""))

    @property
    def encoding(self) -> str:
        """Get the file encoding."""
        return self.config.get("encoding", "utf-8")

    async def _on_file_modified(self) -> None:
        """Handle file modification notification."""
        self._file_modified.set()

    def _open_file(self) -> None:
        """Open the log file for reading."""
        if self._file_handle:
            return

        path = self.file_path
        if not path.exists():
            raise FileNotFoundError(f"Log file not found: {path}")

        self._file_handle = open(path, encoding=self.encoding)

        # Position at end if configured
        if self.config.get("read_from_end", True):
            self._file_handle.seek(0, os.SEEK_END)
            self._file_position = self._file_handle.tell()
        else:
            self._file_position = 0

        logger.info(
            "file_opened",
            source_id=self.source_id,
            path=str(path),
            position=self._file_position,
        )

    def _read_new_lines(self) -> list[str]:
        """Read any new lines from the file."""
        if not self._file_handle:
            return []

        lines = []
        batch_size = self.config.get("batch_size", 100)

        try:
            # Seek to last known position
            self._file_handle.seek(self._file_position)

            # Read new lines
            for _ in range(batch_size):
                line = self._file_handle.readline()
                if not line:
                    break
                lines.append(line.rstrip("\n\r"))

            # Update position
            self._file_position = self._file_handle.tell()

        except Exception as e:
            logger.error(
                "file_read_error",
                source_id=self.source_id,
                error=str(e),
            )

        return lines

    async def _read_loop(self) -> None:
        """Main loop for reading file changes."""
        while self._running:
            try:
                # Wait for file modification or timeout
                try:
                    await asyncio.wait_for(
                        self._file_modified.wait(),
                        timeout=1.0,
                    )
                    self._file_modified.clear()
                except TimeoutError:
                    # Check for new content periodically even without event
                    pass

                # Read any new lines
                lines = self._read_new_lines()

                if lines:
                    # Parse the lines
                    results = self.parser.parse(lines)

                    # Queue the results
                    for result in results:
                        await self._event_queue.put(result)

                    logger.debug(
                        "file_lines_read",
                        source_id=self.source_id,
                        lines=len(lines),
                        events=len(results),
                    )

            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error(
                    "file_read_loop_error",
                    source_id=self.source_id,
                    error=str(e),
                )
                await asyncio.sleep(1)

    async def collect(self) -> AsyncGenerator[ParseResult, None]:
        """Collect events from the queue."""
        while self._running or not self._event_queue.empty():
            try:
                result = await asyncio.wait_for(
                    self._event_queue.get(),
                    timeout=1.0,
                )
                yield result
            except TimeoutError:
                continue
            except asyncio.CancelledError:
                break

    async def start(self) -> None:
        """Start watching the file."""
        if self._running:
            return

        self._running = True
        self._loop = asyncio.get_running_loop()

        # Open the file
        self._open_file()

        # Start watchdog observer for file changes
        if self.config.get("follow", True):
            self._observer = Observer()
            handler = FileEventHandler(self)

            # Watch the directory containing the file
            watch_dir = str(self.file_path.parent)
            self._observer.schedule(handler, watch_dir, recursive=False)
            self._observer.start()

        # Start the read loop
        self._read_task = asyncio.create_task(self._read_loop())

        logger.info(
            "file_watch_collector_started",
            source_id=self.source_id,
            path=str(self.file_path),
        )

    async def stop(self) -> None:
        """Stop the collector."""
        self._running = False

        # Stop the read task
        if self._read_task:
            self._read_task.cancel()
            try:
                await self._read_task
            except asyncio.CancelledError:
                pass
            self._read_task = None

        # Stop the observer
        if self._observer:
            self._observer.stop()
            self._observer.join(timeout=5)
            self._observer = None

        # Close the file
        if self._file_handle:
            self._file_handle.close()
            self._file_handle = None

        logger.info("file_watch_collector_stopped", source_id=self.source_id)

    async def test_connection(self) -> tuple[bool, str]:
        """Test that the file exists and is readable."""
        path = self.file_path

        if not path.exists():
            return False, f"File not found: {path}"

        if not path.is_file():
            return False, f"Path is not a file: {path}"

        try:
            with open(path, encoding=self.encoding) as f:
                # Try to read first line
                f.readline()
            return True, f"File is readable: {path}"
        except PermissionError:
            return False, f"Permission denied: {path}"
        except Exception as e:
            return False, f"Cannot read file: {e}"
