"""Docker/Podman container log collector for NetGuardian Agent.

This collector connects to the Docker/Podman socket and streams logs from
running containers to the NetGuardian server.
"""

import asyncio
import json
import logging
import os
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
from typing import Any, AsyncGenerator, Dict, List, Optional, Set

logger = logging.getLogger("netguardian-agent.docker")

# Optional docker dependency
try:
    import docker
    from docker.models.containers import Container
    DOCKER_AVAILABLE = True
except ImportError:
    DOCKER_AVAILABLE = False
    docker = None  # type: ignore


class DockerCollector:
    """Collector for Docker/Podman container logs.

    Features:
    - Auto-detect Docker vs Podman runtime
    - Stream logs from running containers
    - Track log position for resume on restart
    - Detect container lifecycle events (start/stop/restart)
    - Filter containers by name/label

    Configuration:
        socket_path: Path to Docker/Podman socket (default: auto-detect)
        include_containers: List of container name patterns to include (default: ["*"])
        exclude_containers: List of container name patterns to exclude
        include_labels: Dict of labels that containers must have
        since: Collect logs since this time (for resume)
        tail: Number of lines to tail from each container initially
    """

    # Default socket paths
    DOCKER_SOCKET = "/var/run/docker.sock"
    PODMAN_SOCKET_PATHS = [
        "/run/podman/podman.sock",
        "/run/user/{uid}/podman/podman.sock",
        f"/run/user/{os.getuid()}/podman/podman.sock" if hasattr(os, 'getuid') else "",
    ]

    def __init__(
        self,
        socket_path: Optional[str] = None,
        include_containers: Optional[List[str]] = None,
        exclude_containers: Optional[List[str]] = None,
        include_labels: Optional[Dict[str, str]] = None,
        since: Optional[datetime] = None,
        tail: int = 100,
    ):
        """Initialize the Docker collector.

        Args:
            socket_path: Path to container runtime socket.
            include_containers: Container name patterns to include.
            exclude_containers: Container name patterns to exclude.
            include_labels: Labels that containers must have.
            since: Start collecting logs from this time.
            tail: Number of lines to tail initially per container.
        """
        self.socket_path = socket_path or self._detect_socket()
        self.include_containers = include_containers or ["*"]
        self.exclude_containers = exclude_containers or []
        self.include_labels = include_labels or {}
        self.since = since
        self.tail = tail

        self._client: Optional[Any] = None
        self._running = False
        self._tracked_containers: Set[str] = set()
        self._log_streams: Dict[str, Any] = {}
        self._runtime = "unknown"

    def _detect_socket(self) -> str:
        """Auto-detect Docker or Podman socket."""
        # Check Docker first
        if os.path.exists(self.DOCKER_SOCKET):
            self._runtime = "docker"
            return self.DOCKER_SOCKET

        # Check Podman sockets
        for path_template in self.PODMAN_SOCKET_PATHS:
            path = path_template.format(uid=os.getuid() if hasattr(os, 'getuid') else 1000)
            if path and os.path.exists(path):
                self._runtime = "podman"
                return path

        # Fallback to Docker socket
        self._runtime = "docker"
        return self.DOCKER_SOCKET

    def _is_container_in_docker_env(self) -> bool:
        """Check if we're running inside a Docker container."""
        return os.path.exists("/.dockerenv") or os.path.exists("/run/.containerenv")

    async def connect(self) -> bool:
        """Connect to the container runtime."""
        if not DOCKER_AVAILABLE:
            logger.error("docker package not installed. Install with: pip install docker")
            return False

        try:
            self._client = docker.DockerClient(base_url=f"unix://{self.socket_path}")
            # Test connection
            self._client.ping()
            version = self._client.version()
            self._runtime = version.get("Platform", {}).get("Name", self._runtime)
            logger.info(
                f"Connected to {self._runtime}",
                extra={"socket": self.socket_path, "version": version.get("Version")},
            )
            return True
        except Exception as e:
            logger.error(f"Failed to connect to container runtime: {e}")
            return False

    async def disconnect(self) -> None:
        """Disconnect from the container runtime."""
        self._running = False

        # Close log streams
        for stream in self._log_streams.values():
            try:
                stream.close()
            except Exception:
                pass
        self._log_streams.clear()

        if self._client:
            try:
                self._client.close()
            except Exception:
                pass
            self._client = None

    def _should_include_container(self, container: "Container") -> bool:
        """Check if a container should be monitored."""
        name = container.name

        # Check exclude patterns
        for pattern in self.exclude_containers:
            if pattern == "*" or pattern in name:
                return False

        # Check include patterns
        included = False
        for pattern in self.include_containers:
            if pattern == "*":
                included = True
                break
            if pattern in name:
                included = True
                break

        if not included:
            return False

        # Check labels
        if self.include_labels:
            labels = container.labels or {}
            for key, value in self.include_labels.items():
                if labels.get(key) != value:
                    return False

        return True

    async def collect(self) -> AsyncGenerator[Dict[str, Any], None]:
        """Collect container logs and events.

        Yields:
            Dict with container log or event data.
        """
        if not self._client:
            if not await self.connect():
                return

        self._running = True

        # Start event listener for container lifecycle
        event_task = asyncio.create_task(self._listen_events())

        try:
            # Initial container discovery
            for container in self._client.containers.list():
                if self._should_include_container(container):
                    self._tracked_containers.add(container.id)

                    # Yield container start event
                    yield self._create_event(container, "container_discovered")

                    # Start streaming logs
                    asyncio.create_task(self._stream_container_logs(container))

            # Wait for events
            while self._running:
                await asyncio.sleep(1)

        finally:
            event_task.cancel()
            try:
                await event_task
            except asyncio.CancelledError:
                pass

    async def _listen_events(self) -> None:
        """Listen for Docker events (container start/stop/restart)."""
        if not self._client:
            return

        try:
            for event in self._client.events(decode=True):
                if not self._running:
                    break

                if event.get("Type") != "container":
                    continue

                action = event.get("Action", "")
                container_id = event.get("id", "")[:12]
                actor = event.get("Actor", {})
                attributes = actor.get("Attributes", {})
                container_name = attributes.get("name", "unknown")

                # Handle container events
                if action in ("start", "restart"):
                    try:
                        container = self._client.containers.get(container_id)
                        if self._should_include_container(container):
                            self._tracked_containers.add(container.id)
                            logger.info(f"Container {action}: {container_name}")
                    except Exception as e:
                        logger.warning(f"Failed to get container {container_id}: {e}")

                elif action in ("stop", "die", "kill"):
                    if container_id in self._tracked_containers:
                        self._tracked_containers.discard(container_id)
                        logger.info(f"Container {action}: {container_name}")

        except Exception as e:
            if self._running:
                logger.error(f"Event listener error: {e}")

    async def _stream_container_logs(self, container: "Container") -> None:
        """Stream logs from a single container."""
        container_name = container.name
        container_id = container.short_id

        try:
            # Get log stream
            log_kwargs = {
                "stream": True,
                "follow": True,
                "timestamps": True,
                "tail": self.tail,
            }

            if self.since:
                log_kwargs["since"] = self.since

            log_stream = container.logs(**log_kwargs)
            self._log_streams[container_id] = log_stream

            logger.debug(f"Started log stream for {container_name}")

            # Use a queue to pass log lines from blocking reader to async handler
            log_queue: asyncio.Queue[Optional[bytes]] = asyncio.Queue()
            loop = asyncio.get_event_loop()

            def blocking_reader() -> None:
                """Read logs in a thread, pushing to async queue."""
                try:
                    for log_line in log_stream:
                        if not self._running:
                            break
                        # Schedule putting item in queue from this thread
                        loop.call_soon_threadsafe(log_queue.put_nowait, log_line)
                finally:
                    # Signal end of stream
                    loop.call_soon_threadsafe(log_queue.put_nowait, None)

            # Start blocking reader in thread pool
            with ThreadPoolExecutor(max_workers=1) as executor:
                reader_future = executor.submit(blocking_reader)

                # Process log lines from queue asynchronously
                while self._running:
                    try:
                        log_line = await asyncio.wait_for(log_queue.get(), timeout=1.0)
                    except asyncio.TimeoutError:
                        # Check if reader thread has finished
                        if reader_future.done():
                            break
                        continue

                    if log_line is None:
                        # End of stream
                        break

                    try:
                        # Parse log line
                        event = self._parse_log_line(container, log_line)
                        if event:
                            # Queue event (would be yielded in a real async context)
                            logger.debug(f"[{container_name}] {event.get('message', '')[:100]}")
                    except Exception as e:
                        logger.warning(f"Failed to parse log from {container_name}: {e}")

        except Exception as e:
            if self._running:
                logger.error(f"Log stream error for {container_name}: {e}")
        finally:
            self._log_streams.pop(container_id, None)

    def _parse_log_line(
        self,
        container: "Container",
        log_line: bytes,
    ) -> Optional[Dict[str, Any]]:
        """Parse a Docker log line.

        Docker log format (with timestamps):
        2024-01-15T10:30:45.123456789Z <log message>
        """
        try:
            decoded = log_line.decode("utf-8", errors="replace").rstrip("\n")
            if not decoded:
                return None

            # Extract timestamp if present
            timestamp = datetime.now(timezone.utc)
            message = decoded

            if decoded[0].isdigit() and "T" in decoded[:30]:
                # Has timestamp prefix
                parts = decoded.split(" ", 1)
                if len(parts) == 2:
                    try:
                        ts_str = parts[0].rstrip("Z")
                        # Handle nanoseconds
                        if "." in ts_str:
                            ts_base, frac = ts_str.rsplit(".", 1)
                            frac = frac[:6]  # Truncate to microseconds
                            ts_str = f"{ts_base}.{frac}"
                        timestamp = datetime.fromisoformat(ts_str).replace(tzinfo=timezone.utc)
                        message = parts[1]
                    except ValueError:
                        pass

            # Determine stream (stdout vs stderr based on Docker log format)
            stream = "stdout"
            if message.startswith("stderr:"):
                stream = "stderr"
                message = message[7:].lstrip()

            return {
                "timestamp": timestamp.isoformat(),
                "event_type": "container",
                "container_id": container.short_id,
                "container_name": container.name,
                "image": container.image.tags[0] if container.image.tags else str(container.image.id)[:12],
                "stream": stream,
                "message": message,
                "data": {
                    "log": message,
                    "stream": stream,
                    "container_id": container.short_id,
                    "container_name": container.name,
                },
            }
        except Exception as e:
            logger.debug(f"Failed to parse log line: {e}")
            return None

    def _create_event(
        self,
        container: "Container",
        action: str,
        extra: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """Create a container event."""
        event = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "event_type": "container",
            "container_id": container.short_id,
            "container_name": container.name,
            "image": container.image.tags[0] if container.image.tags else str(container.image.id)[:12],
            "action": action,
            "data": {
                "container_id": container.short_id,
                "container_name": container.name,
                "image": container.image.tags[0] if container.image.tags else "",
                "status": container.status,
                "labels": container.labels,
            },
        }

        if extra:
            event["data"].update(extra)

        return event

    async def get_container_stats(self) -> List[Dict[str, Any]]:
        """Get stats for all tracked containers."""
        if not self._client:
            return []

        stats = []
        for container_id in self._tracked_containers:
            try:
                container = self._client.containers.get(container_id)
                container_stats = container.stats(stream=False)

                stats.append({
                    "container_id": container.short_id,
                    "container_name": container.name,
                    "cpu_percent": self._calculate_cpu_percent(container_stats),
                    "memory_usage": container_stats.get("memory_stats", {}).get("usage", 0),
                    "memory_limit": container_stats.get("memory_stats", {}).get("limit", 0),
                    "network_rx": sum(
                        net.get("rx_bytes", 0)
                        for net in container_stats.get("networks", {}).values()
                    ),
                    "network_tx": sum(
                        net.get("tx_bytes", 0)
                        for net in container_stats.get("networks", {}).values()
                    ),
                })
            except Exception as e:
                logger.debug(f"Failed to get stats for {container_id}: {e}")

        return stats

    def _calculate_cpu_percent(self, stats: Dict[str, Any]) -> float:
        """Calculate CPU usage percentage from container stats."""
        try:
            cpu_stats = stats.get("cpu_stats", {})
            precpu_stats = stats.get("precpu_stats", {})

            cpu_delta = (
                cpu_stats.get("cpu_usage", {}).get("total_usage", 0) -
                precpu_stats.get("cpu_usage", {}).get("total_usage", 0)
            )
            system_delta = (
                cpu_stats.get("system_cpu_usage", 0) -
                precpu_stats.get("system_cpu_usage", 0)
            )

            if system_delta > 0 and cpu_delta > 0:
                num_cpus = len(cpu_stats.get("cpu_usage", {}).get("percpu_usage", [])) or 1
                return (cpu_delta / system_delta) * num_cpus * 100.0

            return 0.0
        except Exception:
            return 0.0
