"""WebSocket endpoint for real-time updates."""

import asyncio
from datetime import UTC, datetime
from typing import Any

import structlog
from fastapi import APIRouter, Query, WebSocket, WebSocketDisconnect
from jose import JWTError, jwt

from app.config import settings

logger = structlog.get_logger()

router = APIRouter()


class ConnectionManager:
    """Manages WebSocket connections and broadcasts messages to connected clients."""

    def __init__(self) -> None:
        self.active_connections: dict[str, WebSocket] = {}
        self._lock = asyncio.Lock()

    async def connect(self, websocket: WebSocket, client_id: str) -> None:
        """Accept a WebSocket connection and register it."""
        await websocket.accept()
        async with self._lock:
            self.active_connections[client_id] = websocket
        logger.info(
            "websocket_connected",
            client_id=client_id,
            total_connections=len(self.active_connections),
        )

    async def disconnect(self, client_id: str) -> None:
        """Remove a WebSocket connection."""
        async with self._lock:
            if client_id in self.active_connections:
                del self.active_connections[client_id]
        logger.info(
            "websocket_disconnected",
            client_id=client_id,
            total_connections=len(self.active_connections),
        )

    async def send_personal_message(self, message: dict[str, Any], client_id: str) -> None:
        """Send a message to a specific client."""
        async with self._lock:
            websocket = self.active_connections.get(client_id)
        if websocket:
            try:
                await websocket.send_json(message)
            except Exception as e:
                logger.error(
                    "websocket_send_error",
                    client_id=client_id,
                    error=str(e),
                )
                await self.disconnect(client_id)

    async def broadcast(self, message: dict[str, Any]) -> None:
        """Broadcast a message to all connected clients."""
        async with self._lock:
            connections = list(self.active_connections.items())

        disconnected = []
        for client_id, websocket in connections:
            try:
                await websocket.send_json(message)
            except Exception as e:
                logger.error(
                    "websocket_broadcast_error",
                    client_id=client_id,
                    error=str(e),
                )
                disconnected.append(client_id)

        # Clean up disconnected clients
        for client_id in disconnected:
            await self.disconnect(client_id)

    @property
    def connection_count(self) -> int:
        """Get the number of active connections."""
        return len(self.active_connections)


# Global connection manager instance
manager = ConnectionManager()


def get_connection_manager() -> ConnectionManager:
    """Get the global connection manager instance."""
    return manager


def verify_ws_token(token: str) -> dict[str, Any]:
    """Verify JWT token for WebSocket authentication.

    Args:
        token: JWT token string.

    Returns:
        Decoded token payload if valid.

    Raises:
        ValueError: If token is invalid or expired.
    """
    try:
        payload: dict[str, Any] = jwt.decode(
            token,
            settings.secret_key,
            algorithms=[settings.jwt_algorithm],
        )
        if payload.get("type") != "access":
            raise ValueError("Invalid token type")
        return payload
    except JWTError as e:
        raise ValueError(f"Invalid token: {e}")


@router.websocket("/ws")
async def websocket_endpoint(
    websocket: WebSocket,
    token: str = Query(..., description="JWT access token"),
) -> None:
    """WebSocket endpoint for real-time updates.

    Clients must provide a valid JWT access token as a query parameter.

    Message Types:
    - alert_created: New alert generated
    - alert_updated: Alert status changed
    - device_status_changed: Device status updated (e.g., quarantined)
    - anomaly_detected: New anomaly detected
    - system_notification: System-level notifications
    - connection_info: Connection status information
    """
    # Verify token
    try:
        payload = verify_ws_token(token)
        user_id = payload.get("sub")
        if not user_id:
            await websocket.close(code=4001, reason="Invalid token: missing user ID")
            return
    except ValueError as e:
        await websocket.close(code=4001, reason=str(e))
        return

    # Generate unique client ID
    client_id = f"{user_id}_{id(websocket)}"

    await manager.connect(websocket, client_id)

    # Send connection confirmation
    await manager.send_personal_message(
        {
            "type": "connection_info",
            "data": {
                "status": "connected",
                "client_id": client_id,
                "timestamp": datetime.now(UTC).isoformat(),
            },
        },
        client_id,
    )

    try:
        while True:
            # Wait for messages from client (for ping/pong or future bidirectional communication)
            try:
                data = await asyncio.wait_for(websocket.receive_text(), timeout=30.0)

                # Handle ping/pong for connection keep-alive
                if data == "ping":
                    await manager.send_personal_message(
                        {
                            "type": "pong",
                            "data": {"timestamp": datetime.now(UTC).isoformat()},
                        },
                        client_id,
                    )
            except TimeoutError:
                # Send heartbeat
                await manager.send_personal_message(
                    {
                        "type": "heartbeat",
                        "data": {"timestamp": datetime.now(UTC).isoformat()},
                    },
                    client_id,
                )
    except WebSocketDisconnect:
        await manager.disconnect(client_id)
    except Exception as e:
        logger.error("websocket_error", client_id=client_id, error=str(e))
        await manager.disconnect(client_id)


async def broadcast_alert_created(alert_data: dict[str, Any]) -> None:
    """Broadcast a new alert to all connected clients."""
    await manager.broadcast(
        {
            "type": "alert_created",
            "data": alert_data,
            "timestamp": datetime.now(UTC).isoformat(),
        }
    )


async def broadcast_alert_updated(alert_id: str, update_data: dict[str, Any]) -> None:
    """Broadcast an alert update to all connected clients."""
    await manager.broadcast(
        {
            "type": "alert_updated",
            "data": {"alert_id": alert_id, **update_data},
            "timestamp": datetime.now(UTC).isoformat(),
        }
    )


async def broadcast_device_status_changed(
    device_id: str, new_status: str, details: dict[str, Any] | None = None
) -> None:
    """Broadcast a device status change to all connected clients."""
    await manager.broadcast(
        {
            "type": "device_status_changed",
            "data": {
                "device_id": device_id,
                "new_status": new_status,
                **(details or {}),
            },
            "timestamp": datetime.now(UTC).isoformat(),
        }
    )


async def broadcast_anomaly_detected(anomaly_data: dict[str, Any]) -> None:
    """Broadcast a new anomaly detection to all connected clients."""
    await manager.broadcast(
        {
            "type": "anomaly_detected",
            "data": anomaly_data,
            "timestamp": datetime.now(UTC).isoformat(),
        }
    )


async def broadcast_system_notification(title: str, message: str, severity: str = "info") -> None:
    """Broadcast a system notification to all connected clients."""
    await manager.broadcast(
        {
            "type": "system_notification",
            "data": {
                "title": title,
                "message": message,
                "severity": severity,
            },
            "timestamp": datetime.now(UTC).isoformat(),
        }
    )


# ==================== INVESTIGATION EVENTS ====================


async def broadcast_investigation_started(investigation_data: dict[str, Any]) -> None:
    """Broadcast when a new investigation starts."""
    await manager.broadcast(
        {
            "type": "investigation_started",
            "data": investigation_data,
            "timestamp": datetime.now(UTC).isoformat(),
        }
    )


async def broadcast_investigation_step_completed(
    investigation_id: str, step_data: dict[str, Any]
) -> None:
    """Broadcast when an investigation step completes."""
    await manager.broadcast(
        {
            "type": "investigation_step_completed",
            "data": {"investigation_id": investigation_id, **step_data},
            "timestamp": datetime.now(UTC).isoformat(),
        }
    )


async def broadcast_investigation_completed(investigation_data: dict[str, Any]) -> None:
    """Broadcast when an investigation completes."""
    await manager.broadcast(
        {
            "type": "investigation_completed",
            "data": investigation_data,
            "timestamp": datetime.now(UTC).isoformat(),
        }
    )


async def broadcast_action_pending_approval(action_data: dict[str, Any]) -> None:
    """Broadcast when an investigation action needs approval."""
    await manager.broadcast(
        {
            "type": "action_pending_approval",
            "data": action_data,
            "timestamp": datetime.now(UTC).isoformat(),
        }
    )


# ==================== GAMIFICATION EVENTS ====================


async def broadcast_achievement_unlocked(user_id: str, achievement_data: dict[str, Any]) -> None:
    """Broadcast when a user unlocks an achievement."""
    await manager.broadcast(
        {
            "type": "achievement_unlocked",
            "data": {"user_id": user_id, **achievement_data},
            "timestamp": datetime.now(UTC).isoformat(),
        }
    )


async def broadcast_level_up(user_id: str, level_data: dict[str, Any]) -> None:
    """Broadcast when a user levels up."""
    await manager.broadcast(
        {
            "type": "level_up",
            "data": {"user_id": user_id, **level_data},
            "timestamp": datetime.now(UTC).isoformat(),
        }
    )


async def broadcast_challenge_completed(user_id: str, challenge_data: dict[str, Any]) -> None:
    """Broadcast when a user completes a challenge."""
    await manager.broadcast(
        {
            "type": "challenge_completed",
            "data": {"user_id": user_id, **challenge_data},
            "timestamp": datetime.now(UTC).isoformat(),
        }
    )


async def broadcast_leaderboard_rank_changed(user_id: str, rank_data: dict[str, Any]) -> None:
    """Broadcast when a user's leaderboard rank changes."""
    await manager.broadcast(
        {
            "type": "leaderboard_rank_changed",
            "data": {"user_id": user_id, **rank_data},
            "timestamp": datetime.now(UTC).isoformat(),
        }
    )


# ==================== HONEYPOT EVENTS ====================


async def broadcast_honeypot_spawned(honeypot_data: dict[str, Any]) -> None:
    """Broadcast when a new honeypot is spawned."""
    await manager.broadcast(
        {
            "type": "honeypot_spawned",
            "data": honeypot_data,
            "timestamp": datetime.now(UTC).isoformat(),
        }
    )


async def broadcast_honeypot_interaction(
    honeypot_id: str, interaction_data: dict[str, Any]
) -> None:
    """Broadcast when an attacker interacts with a honeypot."""
    await manager.broadcast(
        {
            "type": "honeypot_interaction",
            "data": {"honeypot_id": honeypot_id, **interaction_data},
            "timestamp": datetime.now(UTC).isoformat(),
        }
    )


async def broadcast_honeypot_expired(honeypot_id: str, summary: dict[str, Any]) -> None:
    """Broadcast when a honeypot expires and is stopped."""
    await manager.broadcast(
        {
            "type": "honeypot_expired",
            "data": {"honeypot_id": honeypot_id, **summary},
            "timestamp": datetime.now(UTC).isoformat(),
        }
    )


async def broadcast_attacker_profile_updated(source_ip: str, profile_data: dict[str, Any]) -> None:
    """Broadcast when an attacker profile is updated with new analysis."""
    await manager.broadcast(
        {
            "type": "attacker_profile_updated",
            "data": {"source_ip": source_ip, **profile_data},
            "timestamp": datetime.now(UTC).isoformat(),
        }
    )
