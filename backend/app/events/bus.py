"""Redis Streams-based event bus for inter-service communication."""

import asyncio
import json
from collections.abc import Callable
from datetime import UTC, datetime
from typing import Any
from uuid import uuid4

import redis.asyncio as redis
import structlog

from app.config import settings

logger = structlog.get_logger()


class EventBus:
    """Event bus using Redis Streams for reliable message delivery."""

    # Stream names for different event types
    STREAM_RAW_EVENTS = "netguardian:events:raw"
    STREAM_ALERTS = "netguardian:events:alerts"
    STREAM_DEVICE_UPDATES = "netguardian:events:devices"
    STREAM_SYSTEM = "netguardian:events:system"

    def __init__(self, redis_url: str | None = None):
        """Initialize the event bus.

        Args:
            redis_url: Redis connection URL. Defaults to settings.
        """
        self.redis_url = redis_url or settings.redis_url
        self._redis: redis.Redis | None = None
        self._consumer_tasks: list[asyncio.Task[None]] = []
        self._running = False

    async def connect(self) -> None:
        """Connect to Redis."""
        if self._redis is None:
            self._redis = redis.from_url(  # type: ignore[no-untyped-call]
                self.redis_url,
                encoding="utf-8",
                decode_responses=True,
            )
            await self._redis.ping()  # type: ignore[misc]
            logger.info("event_bus_connected", redis_url=self.redis_url)

    async def disconnect(self) -> None:
        """Disconnect from Redis."""
        self._running = False

        # Cancel consumer tasks
        for task in self._consumer_tasks:
            task.cancel()
            try:
                await task
            except asyncio.CancelledError:
                pass

        self._consumer_tasks.clear()

        if self._redis:
            await self._redis.close()
            self._redis = None
            logger.info("event_bus_disconnected")

    async def _ensure_connected(self) -> redis.Redis:
        """Ensure Redis connection is available."""
        if self._redis is None:
            await self.connect()
        return self._redis  # type: ignore

    async def publish(
        self,
        stream: str,
        event_type: str,
        data: dict[str, Any],
        maxlen: int = 10000,
    ) -> str:
        """Publish an event to a stream.

        Args:
            stream: Stream name to publish to.
            event_type: Type of event (e.g., "raw_event", "alert_created").
            data: Event data dictionary.
            maxlen: Maximum stream length (approximate, for memory management).

        Returns:
            The message ID assigned by Redis.
        """
        client = await self._ensure_connected()

        message: dict[
            bytes | bytearray | memoryview[int] | str | int | float,
            bytes | bytearray | memoryview[int] | str | int | float,
        ] = {
            "id": str(uuid4()),
            "type": event_type,
            "timestamp": datetime.now(UTC).isoformat(),
            "data": json.dumps(data),
        }

        message_id: str = await client.xadd(stream, message, maxlen=maxlen)

        logger.debug(
            "event_published",
            stream=stream,
            event_type=event_type,
            message_id=message_id,
        )

        return message_id

    async def publish_raw_event(self, event_data: dict[str, Any]) -> str:
        """Publish a raw event for processing."""
        return await self.publish(
            self.STREAM_RAW_EVENTS,
            "raw_event",
            event_data,
        )

    async def publish_alert(self, alert_data: dict[str, Any]) -> str:
        """Publish an alert event."""
        # Broadcast to WebSocket clients
        try:
            from app.api.v1.websocket import broadcast_alert_created

            await broadcast_alert_created(alert_data)
        except Exception as e:
            logger.warning("websocket_broadcast_failed", error=str(e))

        return await self.publish(
            self.STREAM_ALERTS,
            "alert_created",
            alert_data,
        )

    async def publish_device_update(
        self,
        device_id: str,
        update_type: str,
        data: dict[str, Any],
    ) -> str:
        """Publish a device update event."""
        # Broadcast device status changes to WebSocket clients
        if update_type in ("device_quarantined", "device_released", "device_status_changed"):
            try:
                from app.api.v1.websocket import broadcast_device_status_changed

                await broadcast_device_status_changed(
                    device_id,
                    data.get("status", update_type),
                    data,
                )
            except Exception as e:
                logger.warning("websocket_broadcast_failed", error=str(e))

        return await self.publish(
            self.STREAM_DEVICE_UPDATES,
            update_type,
            {"device_id": device_id, **data},
        )

    async def publish_system_event(
        self,
        event_type: str,
        data: dict[str, Any],
    ) -> str:
        """Publish a system event."""
        return await self.publish(
            self.STREAM_SYSTEM,
            event_type,
            data,
        )

    async def create_consumer_group(
        self,
        stream: str,
        group: str,
        start_id: str = "0",
    ) -> bool:
        """Create a consumer group for a stream.

        Args:
            stream: Stream name.
            group: Consumer group name.
            start_id: Starting message ID ("0" for all, "$" for new only).

        Returns:
            True if created, False if already exists.
        """
        client = await self._ensure_connected()

        try:
            # Create stream if it doesn't exist
            await client.xgroup_create(
                stream,
                group,
                id=start_id,
                mkstream=True,
            )
            logger.info(
                "consumer_group_created",
                stream=stream,
                group=group,
            )
            return True
        except redis.ResponseError as e:
            if "BUSYGROUP" in str(e):
                # Group already exists
                logger.debug(
                    "consumer_group_exists",
                    stream=stream,
                    group=group,
                )
                return False
            raise

    async def consume(
        self,
        stream: str,
        group: str,
        consumer: str,
        handler: Callable[[str, str, dict[str, Any]], Any],
        batch_size: int = 10,
        block_ms: int = 5000,
    ) -> None:
        """Consume messages from a stream using a consumer group.

        Args:
            stream: Stream name to consume from.
            group: Consumer group name.
            consumer: Consumer name (unique within group).
            handler: Async function to handle messages (event_type, message_id, data).
            batch_size: Number of messages to read at once.
            block_ms: How long to block waiting for messages.
        """
        client = await self._ensure_connected()

        # Ensure consumer group exists
        await self.create_consumer_group(stream, group)

        self._running = True
        logger.info(
            "consumer_started",
            stream=stream,
            group=group,
            consumer=consumer,
        )

        while self._running:
            try:
                # Read pending messages first (messages that weren't ACKed)
                pending = await client.xreadgroup(
                    group,
                    consumer,
                    {stream: "0"},
                    count=batch_size,
                )

                # Then read new messages
                if not pending or not pending[0][1]:
                    messages = await client.xreadgroup(
                        group,
                        consumer,
                        {stream: ">"},
                        count=batch_size,
                        block=block_ms,
                    )
                else:
                    messages = pending

                if not messages:
                    continue

                for stream_name, stream_messages in messages:
                    for message_id, message_data in stream_messages:
                        try:
                            event_type = message_data.get("type", "unknown")
                            data = json.loads(message_data.get("data", "{}"))

                            # Call handler
                            if asyncio.iscoroutinefunction(handler):
                                await handler(event_type, message_id, data)
                            else:
                                handler(event_type, message_id, data)

                            # Acknowledge message
                            await client.xack(stream, group, message_id)

                            logger.debug(
                                "message_processed",
                                stream=stream,
                                message_id=message_id,
                                event_type=event_type,
                            )

                        except Exception as e:
                            logger.error(
                                "message_handler_error",
                                stream=stream,
                                message_id=message_id,
                                error=str(e),
                            )
                            # Don't ACK failed messages - they'll be retried

            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error(
                    "consumer_error",
                    stream=stream,
                    group=group,
                    consumer=consumer,
                    error=str(e),
                )
                await asyncio.sleep(1)  # Back off on errors

        logger.info(
            "consumer_stopped",
            stream=stream,
            group=group,
            consumer=consumer,
        )

    def start_consumer(
        self,
        stream: str,
        group: str,
        consumer: str,
        handler: Callable[[str, str, dict[str, Any]], Any],
        batch_size: int = 10,
        block_ms: int = 5000,
    ) -> asyncio.Task[None]:
        """Start a consumer as a background task.

        Args:
            stream: Stream name to consume from.
            group: Consumer group name.
            consumer: Consumer name.
            handler: Message handler function.
            batch_size: Batch size for reading.
            block_ms: Block timeout.

        Returns:
            The asyncio Task running the consumer.
        """
        task = asyncio.create_task(
            self.consume(
                stream,
                group,
                consumer,
                handler,
                batch_size,
                block_ms,
            )
        )
        self._consumer_tasks.append(task)
        return task

    async def get_stream_info(self, stream: str) -> dict[str, Any]:
        """Get information about a stream.

        Args:
            stream: Stream name.

        Returns:
            Stream information dictionary.
        """
        client = await self._ensure_connected()

        try:
            info = await client.xinfo_stream(stream)
            return {
                "length": info.get("length", 0),
                "first_entry": info.get("first-entry"),
                "last_entry": info.get("last-entry"),
                "groups": info.get("groups", 0),
            }
        except redis.ResponseError:
            return {"length": 0, "first_entry": None, "last_entry": None, "groups": 0}

    async def get_consumer_group_info(
        self,
        stream: str,
        group: str,
    ) -> dict[str, Any] | None:
        """Get information about a consumer group.

        Args:
            stream: Stream name.
            group: Group name.

        Returns:
            Group information or None if not found.
        """
        client = await self._ensure_connected()

        try:
            groups = await client.xinfo_groups(stream)
            for g in groups:
                if g.get("name") == group:
                    return {
                        "name": g.get("name"),
                        "consumers": g.get("consumers", 0),
                        "pending": g.get("pending", 0),
                        "last_delivered_id": g.get("last-delivered-id"),
                    }
            return None
        except redis.ResponseError:
            return None

    async def trim_stream(self, stream: str, maxlen: int) -> int:
        """Trim a stream to a maximum length.

        Args:
            stream: Stream name.
            maxlen: Maximum length to keep.

        Returns:
            Number of messages removed.
        """
        client = await self._ensure_connected()
        result: int = await client.xtrim(stream, maxlen=maxlen)
        return result


# Global event bus instance
_event_bus: EventBus | None = None


async def get_event_bus() -> EventBus:
    """Get the global event bus instance."""
    global _event_bus
    if _event_bus is None:
        _event_bus = EventBus()
        await _event_bus.connect()
    return _event_bus


async def close_event_bus() -> None:
    """Close the global event bus instance."""
    global _event_bus
    if _event_bus is not None:
        await _event_bus.disconnect()
        _event_bus = None
