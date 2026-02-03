"""Systemd journal collector for NetGuardian Agent.

This collector reads logs from the systemd journal and sends them to the
NetGuardian server. Supports filtering by unit, priority, and cursor-based
resumption.
"""

import asyncio
import json
import logging
import os
import subprocess
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, AsyncGenerator, Dict, List, Optional, Set

logger = logging.getLogger("netguardian-agent.journal")

# Optional systemd dependency
try:
    from systemd import journal
    SYSTEMD_AVAILABLE = True
except ImportError:
    SYSTEMD_AVAILABLE = False
    journal = None  # type: ignore


class JournalCollector:
    """Collector for systemd journal logs.

    Features:
    - Read from systemd journal
    - Filter by unit and priority
    - Track cursor for resumption
    - Optional kernel message collection
    - Support for both library and journalctl fallback

    Configuration:
        units: List of systemd units to monitor (default: all)
        priority_min: Minimum priority level (0-7, lower is more severe)
        include_kernel: Include kernel messages (default: False)
        cursor_file: Path to store cursor for resumption
        batch_size: Number of entries to read per batch
    """

    # Priority level names
    PRIORITY_NAMES = {
        0: "emerg",
        1: "alert",
        2: "crit",
        3: "err",
        4: "warning",
        5: "notice",
        6: "info",
        7: "debug",
    }

    def __init__(
        self,
        units: Optional[List[str]] = None,
        priority_min: int = 6,  # info and above
        include_kernel: bool = False,
        cursor_file: Optional[str] = None,
        batch_size: int = 100,
        follow: bool = True,
    ):
        """Initialize the journal collector.

        Args:
            units: List of systemd units to monitor.
            priority_min: Minimum priority (0=emerg, 7=debug).
            include_kernel: Whether to include kernel messages.
            cursor_file: Path to save cursor for resume.
            batch_size: Number of entries per batch.
            follow: Follow journal (tail -f mode).
        """
        self.units = set(units) if units else set()
        self.priority_min = priority_min
        self.include_kernel = include_kernel
        self.cursor_file = cursor_file
        self.batch_size = batch_size
        self.follow = follow

        self._reader: Optional[Any] = None
        self._running = False
        self._last_cursor: Optional[str] = None
        self._use_journalctl = not SYSTEMD_AVAILABLE

    def _load_cursor(self) -> Optional[str]:
        """Load cursor from file if exists."""
        if self.cursor_file and os.path.exists(self.cursor_file):
            try:
                with open(self.cursor_file, "r") as f:
                    return f.read().strip()
            except Exception as e:
                logger.warning(f"Failed to load cursor: {e}")
        return None

    def _save_cursor(self, cursor: str) -> None:
        """Save cursor to file."""
        if self.cursor_file:
            try:
                # Ensure directory exists
                Path(self.cursor_file).parent.mkdir(parents=True, exist_ok=True)
                with open(self.cursor_file, "w") as f:
                    f.write(cursor)
            except Exception as e:
                logger.warning(f"Failed to save cursor: {e}")

    async def connect(self) -> bool:
        """Initialize the journal reader."""
        if self._use_journalctl:
            # Check journalctl is available
            try:
                result = subprocess.run(
                    ["journalctl", "--version"],
                    capture_output=True,
                    text=True,
                    timeout=5,
                )
                if result.returncode != 0:
                    stderr_msg = result.stderr.strip() if result.stderr else "unknown error"
                    logger.error(f"journalctl not available: {stderr_msg}")
                    return False
                version = result.stdout.strip().split("\n")[0] if result.stdout else "unknown"
                logger.info(f"Using journalctl for journal access: {version}")
                return True
            except subprocess.TimeoutExpired:
                logger.error("journalctl check timed out")
                return False
            except FileNotFoundError:
                logger.error("journalctl command not found")
                return False
            except Exception as e:
                logger.error(f"journalctl check failed: {e}")
                return False

        try:
            self._reader = journal.Reader()

            # Apply filters
            if self.units:
                for unit in self.units:
                    self._reader.add_match(_SYSTEMD_UNIT=unit)
                    # Also match user units
                    self._reader.add_match(UNIT=unit)

            # Priority filter
            if self.priority_min < 7:
                for priority in range(self.priority_min + 1):
                    self._reader.add_match(PRIORITY=str(priority))

            # Load cursor for resume
            cursor = self._load_cursor()
            if cursor:
                try:
                    self._reader.seek_cursor(cursor)
                    self._reader.get_next()  # Move past the cursor position
                    logger.info(f"Resumed from cursor: {cursor[:20]}...")
                except Exception as e:
                    logger.warning(f"Failed to seek to cursor: {e}")
                    self._reader.seek_tail()
                    self._reader.get_previous()
            else:
                # Start from end of journal
                self._reader.seek_tail()
                self._reader.get_previous()

            logger.info(
                "Journal reader initialized",
                extra={
                    "units": list(self.units) if self.units else "all",
                    "priority_min": self.PRIORITY_NAMES.get(self.priority_min, str(self.priority_min)),
                },
            )
            return True

        except Exception as e:
            logger.error(f"Failed to initialize journal reader: {e}")
            self._use_journalctl = True
            return await self.connect()  # Fallback to journalctl

    async def disconnect(self) -> None:
        """Close the journal reader."""
        self._running = False

        # Save final cursor
        if self._last_cursor:
            self._save_cursor(self._last_cursor)

        if self._reader:
            try:
                self._reader.close()
            except Exception:
                pass
            self._reader = None

    async def collect(self) -> AsyncGenerator[Dict[str, Any], None]:
        """Collect journal entries.

        Yields:
            Dict with journal entry data.
        """
        if not await self.connect():
            return

        self._running = True

        if self._use_journalctl:
            async for entry in self._collect_journalctl():
                yield entry
        else:
            async for entry in self._collect_native():
                yield entry

    async def _collect_native(self) -> AsyncGenerator[Dict[str, Any], None]:
        """Collect using native systemd library."""
        if not self._reader:
            return

        while self._running:
            entries_read = 0

            for entry in self._reader:
                if not self._running:
                    break

                # Apply additional filters
                if not self._should_include(entry):
                    continue

                parsed = self._parse_entry(entry)
                if parsed:
                    yield parsed
                    entries_read += 1

                    # Update cursor
                    cursor = entry.get("__CURSOR")
                    if cursor:
                        self._last_cursor = cursor
                        if entries_read % 100 == 0:
                            self._save_cursor(cursor)

                if entries_read >= self.batch_size:
                    break

            if self.follow:
                # Wait for new entries
                if entries_read == 0:
                    await asyncio.sleep(1)
                    # Process events (poll for new entries)
                    self._reader.process()
            else:
                # One-shot mode
                break

    async def _collect_journalctl(self) -> AsyncGenerator[Dict[str, Any], None]:
        """Collect using journalctl subprocess."""
        cmd = ["journalctl", "--output=json"]

        # Add unit filters
        for unit in self.units:
            cmd.extend(["-u", unit])

        # Priority filter
        cmd.extend(["-p", str(self.priority_min)])

        # Include kernel if requested
        if self.include_kernel:
            cmd.append("-k")

        # Resume from cursor
        cursor = self._load_cursor()
        if cursor:
            cmd.extend(["--after-cursor", cursor])
        else:
            # Start from recent entries
            cmd.extend(["-n", str(self.batch_size)])

        # Follow mode
        if self.follow:
            cmd.append("-f")

        try:
            process = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )

            if process.stdout:
                while self._running:
                    line = await process.stdout.readline()
                    if not line:
                        break

                    try:
                        entry = json.loads(line.decode("utf-8"))
                        parsed = self._parse_entry(entry)
                        if parsed:
                            yield parsed

                            # Update cursor
                            cursor = entry.get("__CURSOR")
                            if cursor:
                                self._last_cursor = cursor
                    except json.JSONDecodeError:
                        continue

            process.terminate()
            await process.wait()

        except Exception as e:
            logger.error(f"journalctl error: {e}")

    def _should_include(self, entry: Dict[str, Any]) -> bool:
        """Check if entry should be included."""
        # Check kernel messages
        transport = entry.get("_TRANSPORT", "")
        if transport == "kernel" and not self.include_kernel:
            return False

        # Check priority
        try:
            priority = int(entry.get("PRIORITY", 6))
            if priority > self.priority_min:
                return False
        except (ValueError, TypeError):
            pass

        # Check unit filter
        if self.units:
            unit = entry.get("_SYSTEMD_UNIT", entry.get("UNIT", ""))
            if unit and not any(u in unit for u in self.units):
                # Check syslog identifier as fallback
                identifier = entry.get("SYSLOG_IDENTIFIER", "")
                if not any(u in identifier for u in self.units):
                    return False

        return True

    def _parse_entry(self, entry: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """Parse a journal entry to event format."""
        message = entry.get("MESSAGE", "")
        if not message:
            return None

        # Handle binary messages
        if isinstance(message, list):
            try:
                message = bytes(message).decode("utf-8", errors="replace")
            except (TypeError, ValueError):
                message = str(message)

        # Parse timestamp
        timestamp = datetime.now(timezone.utc)
        ts_str = entry.get("__REALTIME_TIMESTAMP")
        if ts_str:
            try:
                ts_us = int(ts_str)
                timestamp = datetime.fromtimestamp(ts_us / 1_000_000, tz=timezone.utc)
            except (ValueError, TypeError, OSError):
                pass

        # Extract fields
        unit = entry.get("_SYSTEMD_UNIT", entry.get("UNIT", ""))
        syslog_identifier = entry.get("SYSLOG_IDENTIFIER", "")
        pid = entry.get("_PID", entry.get("SYSLOG_PID"))
        priority = int(entry.get("PRIORITY", 6))
        hostname = entry.get("_HOSTNAME", "")
        boot_id = entry.get("_BOOT_ID", "")
        cursor = entry.get("__CURSOR", "")

        return {
            "timestamp": timestamp.isoformat(),
            "event_type": "journal",
            "message": message,
            "data": {
                "priority": priority,
                "priority_name": self.PRIORITY_NAMES.get(priority, "unknown"),
                "unit": unit,
                "syslog_identifier": syslog_identifier,
                "pid": int(pid) if pid else None,
                "hostname": hostname,
                "boot_id": boot_id,
                "cursor": cursor,
                "transport": entry.get("_TRANSPORT", ""),
            },
        }

    async def get_service_status(self) -> List[Dict[str, Any]]:
        """Get status of monitored services."""
        if not self.units:
            return []

        statuses = []
        for unit in self.units:
            try:
                result = subprocess.run(
                    ["systemctl", "is-active", unit],
                    capture_output=True,
                    text=True,
                    timeout=5,
                )
                # systemctl is-active returns non-zero for inactive services
                # but that's expected behavior, not an error
                status = result.stdout.strip() or "unknown"

                result = subprocess.run(
                    ["systemctl", "show", unit, "--property=ActiveEnterTimestamp"],
                    capture_output=True,
                    text=True,
                    timeout=5,
                )
                timestamp_line = result.stdout.strip()
                timestamp = timestamp_line.split("=", 1)[-1] if "=" in timestamp_line else None

                statuses.append({
                    "unit": unit,
                    "status": status,
                    "active_since": timestamp if timestamp else None,
                })
            except subprocess.TimeoutExpired:
                logger.debug(f"Timeout getting status for {unit}")
                statuses.append({
                    "unit": unit,
                    "status": "unknown",
                    "error": "timeout",
                })
            except FileNotFoundError:
                logger.debug("systemctl command not found")
                statuses.append({
                    "unit": unit,
                    "status": "unknown",
                    "error": "systemctl not found",
                })
            except Exception as e:
                logger.debug(f"Failed to get status for {unit}: {e}")
                statuses.append({
                    "unit": unit,
                    "status": "unknown",
                    "error": str(e),
                })

        return statuses
