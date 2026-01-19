#!/usr/bin/env python3
"""NetGuardian Endpoint Agent.

A lightweight monitoring agent that collects system activity and sends
it to a NetGuardian server via the API push endpoint.

Features:
- Process monitoring (new processes, suspicious activity)
- Network connection monitoring
- File access monitoring (optional, for sensitive paths)
- Authentication event monitoring
- System event monitoring

Usage:
    python netguardian_agent.py --config agent_config.yaml
    python netguardian_agent.py --server https://netguardian.local:8000 --api-key YOUR_KEY
"""

import argparse
import asyncio
import hashlib
import json
import logging
import os
import platform
import socket
import sys
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Set

# Optional dependencies - graceful degradation
try:
    import psutil
    PSUTIL_AVAILABLE = True
except ImportError:
    PSUTIL_AVAILABLE = False
    print("Warning: psutil not installed. Install with: pip install psutil")

try:
    import httpx
    HTTPX_AVAILABLE = True
except ImportError:
    HTTPX_AVAILABLE = False
    print("Warning: httpx not installed. Install with: pip install httpx")

try:
    import yaml
    YAML_AVAILABLE = True
except ImportError:
    YAML_AVAILABLE = False

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
)
logger = logging.getLogger("netguardian-agent")


class EndpointAgent:
    """NetGuardian endpoint monitoring agent."""

    def __init__(
        self,
        server_url: str,
        api_key: str,
        agent_id: Optional[str] = None,
        hostname: Optional[str] = None,
        poll_interval: int = 30,
        batch_size: int = 50,
        monitor_processes: bool = True,
        monitor_network: bool = True,
        monitor_files: bool = False,
        watched_paths: Optional[List[str]] = None,
        process_whitelist: Optional[List[str]] = None,
        verify_ssl: bool = True,
    ):
        """Initialize the endpoint agent.

        Args:
            server_url: NetGuardian server URL (e.g., https://netguardian.local:8000)
            api_key: API key for push authentication
            agent_id: Unique agent ID (auto-generated if not provided)
            hostname: Override hostname (auto-detected if not provided)
            poll_interval: Seconds between collection cycles
            batch_size: Max events to send per request
            monitor_processes: Enable process monitoring
            monitor_network: Enable network connection monitoring
            monitor_files: Enable file monitoring
            watched_paths: Paths to monitor for file access
            process_whitelist: Processes to ignore
            verify_ssl: Verify SSL certificates
        """
        self.server_url = server_url.rstrip("/")
        self.api_key = api_key
        self.agent_id = agent_id or self._generate_agent_id()
        self.hostname = hostname or socket.gethostname()
        self.poll_interval = poll_interval
        self.batch_size = batch_size
        self.monitor_processes = monitor_processes
        self.monitor_network = monitor_network
        self.monitor_files = monitor_files
        self.watched_paths = watched_paths or []
        self.process_whitelist = set(process_whitelist or [])
        self.verify_ssl = verify_ssl

        self._running = False
        self._event_queue: List[Dict[str, Any]] = []
        self._known_pids: Set[int] = set()
        self._known_connections: Set[str] = set()
        self._client: Optional[httpx.AsyncClient] = None

        # System info
        self._system_info = self._collect_system_info()

    def _generate_agent_id(self) -> str:
        """Generate a unique agent ID based on machine characteristics."""
        machine_id = ""

        # Try to get a stable machine identifier
        if platform.system() == "Linux":
            try:
                with open("/etc/machine-id", "r") as f:
                    machine_id = f.read().strip()
            except Exception:
                pass
        elif platform.system() == "Windows":
            try:
                import subprocess
                result = subprocess.run(
                    ["wmic", "csproduct", "get", "uuid"],
                    capture_output=True,
                    text=True,
                )
                lines = result.stdout.strip().split("\n")
                if len(lines) > 1:
                    machine_id = lines[1].strip()
            except Exception:
                pass
        elif platform.system() == "Darwin":
            try:
                import subprocess
                result = subprocess.run(
                    ["ioreg", "-rd1", "-c", "IOPlatformExpertDevice"],
                    capture_output=True,
                    text=True,
                )
                for line in result.stdout.split("\n"):
                    if "IOPlatformUUID" in line:
                        machine_id = line.split('"')[-2]
                        break
            except Exception:
                pass

        if not machine_id:
            # Fallback to hostname + MAC
            hostname = socket.gethostname()
            if PSUTIL_AVAILABLE:
                try:
                    macs = [
                        nic.address
                        for nics in psutil.net_if_addrs().values()
                        for nic in nics
                        if nic.family == psutil.AF_LINK
                    ]
                    machine_id = f"{hostname}:{':'.join(macs)}"
                except Exception:
                    machine_id = hostname

        # Hash to create consistent ID
        return hashlib.sha256(machine_id.encode()).hexdigest()[:32]

    def _collect_system_info(self) -> Dict[str, Any]:
        """Collect static system information."""
        info = {
            "platform": platform.system(),
            "platform_release": platform.release(),
            "platform_version": platform.version(),
            "architecture": platform.machine(),
            "hostname": self.hostname,
            "processor": platform.processor(),
        }

        if PSUTIL_AVAILABLE:
            info.update({
                "cpu_count": psutil.cpu_count(),
                "memory_total": psutil.virtual_memory().total,
            })

        return info

    async def start(self) -> None:
        """Start the agent."""
        if not PSUTIL_AVAILABLE:
            logger.error("psutil is required. Install with: pip install psutil")
            return

        if not HTTPX_AVAILABLE:
            logger.error("httpx is required. Install with: pip install httpx")
            return

        self._running = True
        self._client = httpx.AsyncClient(
            timeout=30.0,
            verify=self.verify_ssl,
        )

        logger.info(
            "NetGuardian agent starting",
            extra={
                "agent_id": self.agent_id,
                "hostname": self.hostname,
                "server": self.server_url,
            },
        )

        # Initialize known state
        await self._initialize_state()

        # Send startup event
        await self._send_event({
            "event_type": "system",
            "data": {
                "action": "agent_startup",
                "system_info": self._system_info,
            },
        })

        # Main monitoring loop
        try:
            while self._running:
                await self._collection_cycle()
                await asyncio.sleep(self.poll_interval)
        except asyncio.CancelledError:
            pass
        finally:
            await self._shutdown()

    async def stop(self) -> None:
        """Stop the agent."""
        self._running = False

    async def _shutdown(self) -> None:
        """Clean shutdown."""
        # Send shutdown event
        await self._send_event({
            "event_type": "system",
            "data": {"action": "agent_shutdown"},
        })

        # Flush remaining events
        await self._flush_events()

        if self._client:
            await self._client.aclose()

        logger.info("NetGuardian agent stopped")

    async def _initialize_state(self) -> None:
        """Initialize known state (existing processes, connections)."""
        if PSUTIL_AVAILABLE:
            # Record existing processes
            for proc in psutil.process_iter(["pid"]):
                try:
                    self._known_pids.add(proc.info["pid"])
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    pass

            # Record existing connections
            for conn in psutil.net_connections(kind="inet"):
                conn_id = self._connection_id(conn)
                self._known_connections.add(conn_id)

    async def _collection_cycle(self) -> None:
        """Run one collection cycle."""
        try:
            if self.monitor_processes:
                await self._collect_processes()

            if self.monitor_network:
                await self._collect_network()

            # Flush events if we have enough
            if len(self._event_queue) >= self.batch_size:
                await self._flush_events()

        except Exception as e:
            logger.error(f"Collection cycle error: {e}")

    async def _collect_processes(self) -> None:
        """Collect process events."""
        if not PSUTIL_AVAILABLE:
            return

        current_pids = set()

        for proc in psutil.process_iter([
            "pid", "name", "username", "exe", "cmdline", "ppid", "create_time"
        ]):
            try:
                info = proc.info
                pid = info["pid"]
                current_pids.add(pid)

                # New process detected
                if pid not in self._known_pids:
                    name = info.get("name", "unknown")

                    # Skip whitelisted processes
                    if name.lower() in self.process_whitelist:
                        continue

                    # Get parent process info
                    parent_name = "unknown"
                    ppid = info.get("ppid")
                    if ppid:
                        try:
                            parent = psutil.Process(ppid)
                            parent_name = parent.name()
                        except (psutil.NoSuchProcess, psutil.AccessDenied):
                            pass

                    await self._send_event({
                        "event_type": "process",
                        "data": {
                            "pid": pid,
                            "name": name,
                            "path": info.get("exe") or "",
                            "cmdline": " ".join(info.get("cmdline") or []),
                            "user": info.get("username") or "unknown",
                            "parent_pid": ppid,
                            "parent_name": parent_name,
                        },
                    })

            except (psutil.NoSuchProcess, psutil.AccessDenied):
                pass

        # Update known PIDs
        self._known_pids = current_pids

    async def _collect_network(self) -> None:
        """Collect network connection events."""
        if not PSUTIL_AVAILABLE:
            return

        current_connections = set()

        for conn in psutil.net_connections(kind="inet"):
            conn_id = self._connection_id(conn)
            current_connections.add(conn_id)

            # New connection detected
            if conn_id not in self._known_connections:
                # Get process info
                process_name = "unknown"
                process_pid = conn.pid
                if process_pid:
                    try:
                        proc = psutil.Process(process_pid)
                        process_name = proc.name()
                    except (psutil.NoSuchProcess, psutil.AccessDenied):
                        pass

                local_ip = conn.laddr.ip if conn.laddr else ""
                local_port = conn.laddr.port if conn.laddr else 0
                remote_ip = conn.raddr.ip if conn.raddr else ""
                remote_port = conn.raddr.port if conn.raddr else 0

                # Only report established or listening connections
                if conn.status in ("ESTABLISHED", "LISTEN"):
                    await self._send_event({
                        "event_type": "network",
                        "data": {
                            "local_ip": local_ip,
                            "local_port": local_port,
                            "remote_ip": remote_ip,
                            "remote_port": remote_port,
                            "protocol": "tcp" if conn.type == socket.SOCK_STREAM else "udp",
                            "state": conn.status.lower(),
                            "process_name": process_name,
                            "process_pid": process_pid,
                        },
                    })

        # Update known connections
        self._known_connections = current_connections

    def _connection_id(self, conn) -> str:
        """Generate a unique ID for a connection."""
        local = f"{conn.laddr.ip}:{conn.laddr.port}" if conn.laddr else ""
        remote = f"{conn.raddr.ip}:{conn.raddr.port}" if conn.raddr else ""
        return f"{local}-{remote}-{conn.pid}-{conn.status}"

    async def _send_event(self, event: Dict[str, Any]) -> None:
        """Queue an event for sending."""
        event["timestamp"] = datetime.now(timezone.utc).isoformat()
        event["hostname"] = self.hostname
        event["agent_id"] = self.agent_id

        self._event_queue.append(event)

    async def _flush_events(self) -> None:
        """Send queued events to the server."""
        if not self._event_queue or not self._client:
            return

        events = self._event_queue[:self.batch_size]
        self._event_queue = self._event_queue[self.batch_size:]

        try:
            response = await self._client.post(
                f"{self.server_url}/api/v1/logs/ingest",
                json=events,
                headers={
                    "X-API-Key": self.api_key,
                    "Content-Type": "application/json",
                },
            )

            if response.status_code == 200:
                logger.debug(f"Sent {len(events)} events")
            else:
                logger.warning(
                    f"Failed to send events: {response.status_code} {response.text}"
                )
                # Re-queue events on failure
                self._event_queue = events + self._event_queue

        except Exception as e:
            logger.error(f"Error sending events: {e}")
            # Re-queue events on error
            self._event_queue = events + self._event_queue


def load_config(config_path: str) -> Dict[str, Any]:
    """Load configuration from YAML file."""
    if not YAML_AVAILABLE:
        logger.error("PyYAML required for config files. Install with: pip install pyyaml")
        sys.exit(1)

    with open(config_path, "r") as f:
        return yaml.safe_load(f)


def main() -> None:
    """Main entry point."""
    parser = argparse.ArgumentParser(
        description="NetGuardian Endpoint Agent",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )

    parser.add_argument(
        "--config", "-c",
        help="Path to YAML config file",
    )
    parser.add_argument(
        "--server", "-s",
        help="NetGuardian server URL",
    )
    parser.add_argument(
        "--api-key", "-k",
        help="API key for authentication",
    )
    parser.add_argument(
        "--interval", "-i",
        type=int,
        default=30,
        help="Collection interval in seconds (default: 30)",
    )
    parser.add_argument(
        "--no-ssl-verify",
        action="store_true",
        help="Disable SSL certificate verification",
    )
    parser.add_argument(
        "--debug",
        action="store_true",
        help="Enable debug logging",
    )

    args = parser.parse_args()

    if args.debug:
        logging.getLogger().setLevel(logging.DEBUG)

    # Load config
    config = {}
    if args.config:
        config = load_config(args.config)

    # Command line args override config file
    server_url = args.server or config.get("server_url")
    api_key = args.api_key or config.get("api_key")

    if not server_url or not api_key:
        parser.error("Server URL and API key are required")

    # Create and run agent
    agent = EndpointAgent(
        server_url=server_url,
        api_key=api_key,
        agent_id=config.get("agent_id"),
        hostname=config.get("hostname"),
        poll_interval=args.interval or config.get("poll_interval", 30),
        batch_size=config.get("batch_size", 50),
        monitor_processes=config.get("monitor_processes", True),
        monitor_network=config.get("monitor_network", True),
        monitor_files=config.get("monitor_files", False),
        watched_paths=config.get("watched_paths"),
        process_whitelist=config.get("process_whitelist"),
        verify_ssl=not args.no_ssl_verify and config.get("verify_ssl", True),
    )

    try:
        asyncio.run(agent.start())
    except KeyboardInterrupt:
        logger.info("Agent interrupted by user")


if __name__ == "__main__":
    main()
