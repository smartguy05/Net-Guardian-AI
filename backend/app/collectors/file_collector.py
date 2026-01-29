"""File collector for watching and tailing log files or directories."""

from __future__ import annotations

import asyncio
import fnmatch
import os
from collections.abc import AsyncGenerator
from pathlib import Path
from typing import TYPE_CHECKING, TextIO

import structlog
from watchdog.events import (
    DirModifiedEvent,
    FileCreatedEvent,
    FileDeletedEvent,
    FileModifiedEvent,
    FileSystemEventHandler,
)
from watchdog.observers import Observer

from app.collectors.base import BaseCollector
from app.collectors.registry import register_collector
from app.models.log_source import LogSource, SourceType
from app.parsers.base import BaseParser, ParseResult

if TYPE_CHECKING:
    from watchdog.observers.api import BaseObserver

logger = structlog.get_logger()


class FileEventHandler(FileSystemEventHandler):
    """Watchdog event handler for file modifications.

    Supports both single-file mode and directory mode with glob pattern filtering.
    """

    def __init__(self, collector: FileWatchCollector):
        super().__init__()
        self.collector = collector

    def _matches_pattern(self, path: str) -> bool:
        """Check if file matches the configured pattern (directory mode only)."""
        if not self.collector.is_directory_mode:
            # Single file mode - always match the target file
            return Path(path) == self.collector.file_path
        # Directory mode - apply glob pattern
        return fnmatch.fnmatch(Path(path).name, self.collector.file_pattern)

    def on_modified(self, event: DirModifiedEvent | FileModifiedEvent) -> None:
        """Handle file modification events."""
        if not event.is_directory and self.collector._loop is not None:
            if self._matches_pattern(event.src_path):
                # Signal that file has new content
                asyncio.run_coroutine_threadsafe(
                    self.collector._on_file_modified(Path(event.src_path)),
                    self.collector._loop,
                )

    def on_created(self, event: FileCreatedEvent) -> None:
        """Handle new file creation events (directory mode)."""
        if not event.is_directory and self.collector._loop is not None:
            if self.collector.is_directory_mode and self._matches_pattern(event.src_path):
                # New file created that matches pattern
                asyncio.run_coroutine_threadsafe(
                    self.collector._on_file_created(Path(event.src_path)),
                    self.collector._loop,
                )

    def on_deleted(self, event: FileDeletedEvent) -> None:
        """Handle file deletion events (directory mode)."""
        if not event.is_directory and self.collector._loop is not None:
            if self.collector.is_directory_mode:
                # File deleted - close handle if we have one
                asyncio.run_coroutine_threadsafe(
                    self.collector._on_file_deleted(Path(event.src_path)),
                    self.collector._loop,
                )


@register_collector(SourceType.FILE_WATCH)
class FileWatchCollector(BaseCollector):
    """Collector that watches and tails log files or directories.

    Configuration options:
        path: Path to the log file or directory to watch
        file_pattern: Glob pattern for filtering files when path is a directory (default: "*")
        follow: Whether to follow the file (tail -f style)
        encoding: File encoding (default: utf-8)
        read_from_end: Start reading from end of file (default: True)
        batch_size: Number of lines to read at once (default: 100)

    When path is a directory:
        - Use file_pattern to filter which files to watch (e.g., "*.log", "app-*.log")
        - Track positions for each file individually
        - Monitor for new files matching the pattern

    When path is a file (existing behavior):
        - Ignore file_pattern setting
        - Work exactly as before (backward compatible)
    """

    def __init__(self, source: LogSource, parser: BaseParser):
        super().__init__(source, parser)
        self._observer: BaseObserver | None = None
        # Multi-file state tracking for directory mode
        self._file_handles: dict[Path, TextIO] = {}
        self._file_positions: dict[Path, int] = {}
        self._modified_files: set[Path] = set()
        self._event_queue: asyncio.Queue[ParseResult] = asyncio.Queue()
        self._loop: asyncio.AbstractEventLoop | None = None
        self._read_task: asyncio.Task[None] | None = None
        self._file_modified = asyncio.Event()

    @property
    def file_path(self) -> Path:
        """Get the configured file/directory path."""
        return Path(self.config.get("path", ""))

    @property
    def file_pattern(self) -> str:
        """Get the glob pattern for filtering files (directory mode only)."""
        pattern: str = self.config.get("file_pattern", "*")
        return pattern

    @property
    def is_directory_mode(self) -> bool:
        """Check if watching a directory instead of a single file."""
        return self.file_path.is_dir()

    @property
    def encoding(self) -> str:
        """Get the file encoding."""
        encoding: str = self.config.get("encoding", "utf-8")
        return encoding

    # Backward compatibility properties for single-file mode
    @property
    def _file_handle(self) -> TextIO | None:
        """Get single file handle (backward compat for single-file mode)."""
        if not self.is_directory_mode and self.file_path in self._file_handles:
            return self._file_handles[self.file_path]
        return None

    @property
    def _file_position(self) -> int:
        """Get single file position (backward compat for single-file mode)."""
        if not self.is_directory_mode:
            return self._file_positions.get(self.file_path, 0)
        return 0

    async def _on_file_modified(self, path: Path | None = None) -> None:
        """Handle file modification notification."""
        if path and self.is_directory_mode:
            self._modified_files.add(path)
        elif not self.is_directory_mode:
            self._modified_files.add(self.file_path)
        self._file_modified.set()

    async def _on_file_created(self, path: Path) -> None:
        """Handle new file creation (directory mode)."""
        if self.is_directory_mode and path not in self._file_handles:
            logger.info(
                "new_file_detected",
                source_id=self.source_id,
                path=str(path),
            )
            self._open_single_file(path)
            self._modified_files.add(path)
            self._file_modified.set()

    async def _on_file_deleted(self, path: Path) -> None:
        """Handle file deletion (directory mode)."""
        if path in self._file_handles:
            logger.info(
                "file_deleted",
                source_id=self.source_id,
                path=str(path),
            )
            try:
                self._file_handles[path].close()
            except Exception:
                pass
            del self._file_handles[path]
            self._file_positions.pop(path, None)
            self._modified_files.discard(path)

    def _scan_directory(self) -> list[Path]:
        """Find all files matching pattern in directory."""
        return sorted(self.file_path.glob(self.file_pattern))

    def _open_single_file(self, path: Path) -> None:
        """Open a single file and add to tracking."""
        if path in self._file_handles:
            return

        if not path.exists() or not path.is_file():
            return

        try:
            file_handle: TextIO = open(path, encoding=self.encoding)
            self._file_handles[path] = file_handle

            # Position at end if configured
            if self.config.get("read_from_end", True):
                file_handle.seek(0, os.SEEK_END)
                self._file_positions[path] = file_handle.tell()
            else:
                self._file_positions[path] = 0

            logger.info(
                "file_opened",
                source_id=self.source_id,
                path=str(path),
                position=self._file_positions[path],
            )
        except Exception as e:
            logger.error(
                "file_open_error",
                source_id=self.source_id,
                path=str(path),
                error=str(e),
            )

    def _open_file(self) -> None:
        """Open the log file(s) for reading."""
        path = self.file_path
        if not path.exists():
            raise FileNotFoundError(f"Path not found: {path}")

        if self.is_directory_mode:
            # Directory mode: open all matching files
            matching_files = self._scan_directory()
            if not matching_files:
                logger.warning(
                    "no_matching_files",
                    source_id=self.source_id,
                    path=str(path),
                    pattern=self.file_pattern,
                )
            for file_path in matching_files:
                self._open_single_file(file_path)
            logger.info(
                "directory_watch_started",
                source_id=self.source_id,
                path=str(path),
                pattern=self.file_pattern,
                file_count=len(self._file_handles),
            )
        else:
            # Single file mode (backward compatible)
            if self._file_handles:
                return
            if not path.is_file():
                raise FileNotFoundError(f"Log file not found: {path}")
            self._open_single_file(path)

    def _read_lines_from_file(self, path: Path) -> list[str]:
        """Read new lines from a specific file."""
        if path not in self._file_handles:
            return []

        file_handle = self._file_handles[path]
        lines = []
        batch_size = self.config.get("batch_size", 100)

        try:
            # Seek to last known position
            position = self._file_positions.get(path, 0)
            file_handle.seek(position)

            # Read new lines
            for _ in range(batch_size):
                line = file_handle.readline()
                if not line:
                    break
                lines.append(line.rstrip("\n\r"))

            # Update position
            self._file_positions[path] = file_handle.tell()

        except Exception as e:
            logger.error(
                "file_read_error",
                source_id=self.source_id,
                path=str(path),
                error=str(e),
            )

        return lines

    def _read_new_lines(self) -> list[str]:
        """Read any new lines from all tracked files."""
        if not self._file_handles:
            return []

        all_lines = []

        if self.is_directory_mode:
            # Directory mode: read from modified files
            files_to_read = list(self._modified_files) if self._modified_files else list(self._file_handles.keys())
            self._modified_files.clear()

            for path in files_to_read:
                if path in self._file_handles:
                    lines = self._read_lines_from_file(path)
                    all_lines.extend(lines)
        else:
            # Single file mode
            all_lines = self._read_lines_from_file(self.file_path)

        return all_lines

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
        """Start watching the file(s)."""
        if self._running:
            return

        self._running = True
        self._loop = asyncio.get_running_loop()

        # Open the file(s)
        self._open_file()

        # Start watchdog observer for file changes
        if self.config.get("follow", True):
            self._observer = Observer()
            handler = FileEventHandler(self)

            # Watch the appropriate directory
            if self.is_directory_mode:
                watch_dir = str(self.file_path)
            else:
                watch_dir = str(self.file_path.parent)
            self._observer.schedule(handler, watch_dir, recursive=False)
            self._observer.start()

        # Start the read loop
        self._read_task = asyncio.create_task(self._read_loop())

        if self.is_directory_mode:
            logger.info(
                "file_watch_collector_started",
                source_id=self.source_id,
                path=str(self.file_path),
                pattern=self.file_pattern,
                file_count=len(self._file_handles),
            )
        else:
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

        # Close all file handles
        for path, handle in list(self._file_handles.items()):
            try:
                handle.close()
            except Exception:
                pass
        self._file_handles.clear()
        self._file_positions.clear()
        self._modified_files.clear()

        logger.info("file_watch_collector_stopped", source_id=self.source_id)

    async def test_connection(self) -> tuple[bool, str]:
        """Test that the file/directory exists and is readable."""
        path = self.file_path

        if not path.exists():
            return False, f"Path not found: {path}"

        # Directory mode
        if path.is_dir():
            pattern = self.file_pattern
            matching_files = list(path.glob(pattern))

            if not matching_files:
                return True, f"Directory exists but no files match pattern '{pattern}': {path}"

            # Try to read first matching file
            readable_count = 0
            for file_path in matching_files[:5]:  # Check up to 5 files
                try:
                    with open(file_path, encoding=self.encoding) as f:
                        f.readline()
                    readable_count += 1
                except Exception:
                    pass

            if readable_count > 0:
                return True, f"Directory is readable: {path} ({len(matching_files)} files match '{pattern}')"
            return False, f"Cannot read files in directory: {path}"

        # Single file mode
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
