"""Container orchestration for honeypots."""

import asyncio
import json
import random
from typing import Any

import structlog

from app.config import settings

logger = structlog.get_logger()


class ContainerOrchestrator:
    """Orchestrator for managing honeypot containers."""

    def __init__(self):
        """Initialize the container orchestrator."""
        self.runtime = settings.honeypot_container_runtime  # docker or podman
        self._used_ports: set[int] = set()

    async def _run_command(self, command: list[str]) -> tuple[int, str, str]:
        """Run a shell command asynchronously.

        Args:
            command: Command and arguments.

        Returns:
            Tuple of (return_code, stdout, stderr).
        """
        try:
            process = await asyncio.create_subprocess_exec(
                *command,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, stderr = await process.communicate()
            return (
                process.returncode or 0,
                stdout.decode("utf-8"),
                stderr.decode("utf-8"),
            )
        except Exception as e:
            logger.error("command_failed", command=command, error=str(e))
            return 1, "", str(e)

    def _get_available_port(self) -> int:
        """Get an available port in the configured range.

        Returns:
            Available port number.
        """
        start = settings.honeypot_port_range_start
        end = settings.honeypot_port_range_end

        for _ in range(100):  # Try 100 times
            port = random.randint(start, end)
            if port not in self._used_ports:
                self._used_ports.add(port)
                return port

        raise RuntimeError("No available ports in configured range")

    def _release_port(self, port: int) -> None:
        """Release a port back to the pool.

        Args:
            port: Port number to release.
        """
        self._used_ports.discard(port)

    async def spawn_container(
        self,
        image: str,
        name: str,
        config: dict[str, Any],
        port_mappings: dict[int, int],
    ) -> tuple[str | None, dict[str, int]]:
        """Create and start a honeypot container.

        Args:
            image: Container image name.
            name: Container name.
            config: Container configuration.
            port_mappings: Container port to host port mappings.

        Returns:
            Tuple of (container_id, actual_port_mappings) or (None, {}) on failure.
        """
        try:
            # Build port mapping arguments
            actual_mappings: dict[str, int] = {}
            port_args: list[str] = []

            for container_port, _ in port_mappings.items():
                host_port = self._get_available_port()
                actual_mappings[str(container_port)] = host_port
                port_args.extend(["-p", f"{settings.honeypot_host_ip}:{host_port}:{container_port}"])

            # Build environment variable arguments
            env_args: list[str] = []
            for key, value in config.get("env", {}).items():
                env_args.extend(["-e", f"{key}={value}"])

            # Build resource limit arguments
            resource_args: list[str] = []
            if "memory_limit" in config:
                resource_args.extend(["--memory", config["memory_limit"]])
            if "cpu_limit" in config:
                resource_args.extend(["--cpus", str(config["cpu_limit"])])

            # Build the command
            command = [
                self.runtime,
                "run",
                "-d",
                "--name",
                name,
                "--network",
                settings.honeypot_network,
            ] + port_args + env_args + resource_args

            # Add custom command if specified
            if "command" in config:
                command.append(image)
                command.extend(config["command"])
            else:
                command.append(image)

            logger.info("spawning_container", name=name, image=image)

            returncode, stdout, stderr = await self._run_command(command)

            if returncode != 0:
                logger.error("container_spawn_failed", name=name, stderr=stderr)
                # Release allocated ports
                for port in actual_mappings.values():
                    self._release_port(port)
                return None, {}

            container_id = stdout.strip()[:12]  # Short container ID
            logger.info("container_spawned", name=name, container_id=container_id)

            return container_id, actual_mappings

        except Exception as e:
            logger.error("container_spawn_error", name=name, error=str(e))
            return None, {}

    async def stop_container(self, container_id: str) -> bool:
        """Stop a running container.

        Args:
            container_id: Container ID.

        Returns:
            True if successful.
        """
        try:
            command = [self.runtime, "stop", container_id]
            returncode, _, stderr = await self._run_command(command)

            if returncode != 0:
                logger.warning("container_stop_failed", container_id=container_id, stderr=stderr)
                return False

            logger.info("container_stopped", container_id=container_id)
            return True

        except Exception as e:
            logger.error("container_stop_error", container_id=container_id, error=str(e))
            return False

    async def remove_container(self, container_id: str, port_mappings: dict[str, int]) -> bool:
        """Remove a container and cleanup resources.

        Args:
            container_id: Container ID.
            port_mappings: Port mappings to release.

        Returns:
            True if successful.
        """
        try:
            # Stop first if running
            await self.stop_container(container_id)

            # Remove container
            command = [self.runtime, "rm", "-f", container_id]
            returncode, _, stderr = await self._run_command(command)

            if returncode != 0:
                logger.warning("container_remove_failed", container_id=container_id, stderr=stderr)
                return False

            # Release ports
            for port in port_mappings.values():
                self._release_port(port)

            logger.info("container_removed", container_id=container_id)
            return True

        except Exception as e:
            logger.error("container_remove_error", container_id=container_id, error=str(e))
            return False

    async def get_container_logs(
        self,
        container_id: str,
        since: str | None = None,
        tail: int | None = 100,
    ) -> str:
        """Get container logs.

        Args:
            container_id: Container ID.
            since: Get logs since this timestamp.
            tail: Number of lines to return.

        Returns:
            Log output.
        """
        try:
            command = [self.runtime, "logs"]

            if since:
                command.extend(["--since", since])
            if tail:
                command.extend(["--tail", str(tail)])

            command.append(container_id)

            returncode, stdout, stderr = await self._run_command(command)

            if returncode != 0:
                logger.warning("container_logs_failed", container_id=container_id, stderr=stderr)
                return ""

            return stdout + stderr  # Some containers log to stderr

        except Exception as e:
            logger.error("container_logs_error", container_id=container_id, error=str(e))
            return ""

    async def get_container_status(self, container_id: str) -> dict[str, Any]:
        """Get container status.

        Args:
            container_id: Container ID.

        Returns:
            Status dict with running, health, etc.
        """
        try:
            command = [
                self.runtime,
                "inspect",
                "--format",
                "{{json .State}}",
                container_id,
            ]

            returncode, stdout, stderr = await self._run_command(command)

            if returncode != 0:
                return {"running": False, "error": stderr}

            state = json.loads(stdout)
            return {
                "running": state.get("Running", False),
                "status": state.get("Status", "unknown"),
                "started_at": state.get("StartedAt"),
                "finished_at": state.get("FinishedAt"),
                "exit_code": state.get("ExitCode", -1),
            }

        except Exception as e:
            logger.error("container_status_error", container_id=container_id, error=str(e))
            return {"running": False, "error": str(e)}

    async def ensure_network(self) -> bool:
        """Ensure the honeypot network exists.

        Returns:
            True if network exists or was created.
        """
        try:
            # Check if network exists
            check_command = [
                self.runtime,
                "network",
                "inspect",
                settings.honeypot_network,
            ]
            returncode, _, _ = await self._run_command(check_command)

            if returncode == 0:
                return True

            # Create network
            create_command = [
                self.runtime,
                "network",
                "create",
                settings.honeypot_network,
            ]
            returncode, _, stderr = await self._run_command(create_command)

            if returncode != 0:
                logger.error("network_create_failed", network=settings.honeypot_network, stderr=stderr)
                return False

            logger.info("network_created", network=settings.honeypot_network)
            return True

        except Exception as e:
            logger.error("network_error", network=settings.honeypot_network, error=str(e))
            return False

    async def pull_image(self, image: str) -> bool:
        """Pull a container image.

        Args:
            image: Image name.

        Returns:
            True if successful.
        """
        try:
            command = [self.runtime, "pull", image]
            returncode, _, stderr = await self._run_command(command)

            if returncode != 0:
                logger.warning("image_pull_failed", image=image, stderr=stderr)
                return False

            logger.info("image_pulled", image=image)
            return True

        except Exception as e:
            logger.error("image_pull_error", image=image, error=str(e))
            return False

    async def list_running_containers(self, name_prefix: str = "honeypot-") -> list[dict[str, Any]]:
        """List running honeypot containers.

        Args:
            name_prefix: Container name prefix to filter.

        Returns:
            List of container info dicts.
        """
        try:
            command = [
                self.runtime,
                "ps",
                "--filter",
                f"name={name_prefix}",
                "--format",
                "{{json .}}",
            ]

            returncode, stdout, _ = await self._run_command(command)

            if returncode != 0:
                return []

            containers = []
            for line in stdout.strip().split("\n"):
                if line:
                    try:
                        containers.append(json.loads(line))
                    except json.JSONDecodeError:
                        pass

            return containers

        except Exception as e:
            logger.error("list_containers_error", error=str(e))
            return []
