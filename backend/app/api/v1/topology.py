"""Network topology API endpoints."""

from datetime import UTC, datetime, timedelta
from typing import Any, cast

from fastapi import APIRouter, Depends, Query
from pydantic import BaseModel
from sqlalchemy import and_, func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.v1.auth import get_current_user
from app.db.session import get_async_session
from app.models.device import Device
from app.models.raw_event import RawEvent
from app.models.user import User

router = APIRouter(prefix="/topology", tags=["topology"])


class TopologyNode(BaseModel):
    """A node in the network topology."""

    id: str
    label: str
    type: str  # device, router, internet, unknown
    status: str
    ip_address: str | None = None
    mac_address: str | None = None
    manufacturer: str | None = None
    device_type: str | None = None
    event_count_24h: int = 0
    tags: list[str] = []
    is_quarantined: bool = False


class TopologyLink(BaseModel):
    """A link between nodes in the topology."""

    source: str
    target: str
    traffic_volume: int = 0  # Events in last 24h
    link_type: str = "connection"  # connection, blocked


class TopologyData(BaseModel):
    """Complete network topology data."""

    nodes: list[TopologyNode]
    links: list[TopologyLink]
    stats: dict[str, Any]


@router.get("", response_model=TopologyData)
async def get_network_topology(
    hours: int = Query(24, ge=1, le=168, description="Time window for traffic analysis"),
    include_inactive: bool = Query(False, description="Include inactive devices"),
    session: AsyncSession = Depends(get_async_session),
    current_user: User = Depends(get_current_user),
) -> TopologyData:
    """
    Get network topology data for visualization.

    Returns nodes (devices) and links (connections) based on traffic patterns.
    """
    cutoff_time = datetime.now(UTC) - timedelta(hours=hours)

    # Get all devices
    device_query = select(Device)
    if not include_inactive:
        device_query = device_query.where(Device.status != "inactive")

    result = await session.execute(device_query)
    devices = list(result.scalars().all())

    # Get event counts per device
    event_counts_query = (
        select(RawEvent.device_id, func.count(RawEvent.id).label("count"))
        .where(
            and_(
                RawEvent.timestamp >= cutoff_time,
                RawEvent.device_id.isnot(None),
            )
        )
        .group_by(RawEvent.device_id)
    )
    event_result = await session.execute(event_counts_query)
    event_counts: dict[str, int] = {
        str(row.device_id): cast(int, row.count) for row in event_result
    }

    # Get connection pairs (source IP to destination based on DNS/HTTP events)
    # This identifies which devices communicate with each other or external services
    connection_query = (
        select(
            RawEvent.device_id,
            RawEvent.domain,
            RawEvent.target_ip,
            func.count(RawEvent.id).label("count"),
        )
        .where(
            and_(
                RawEvent.timestamp >= cutoff_time,
                RawEvent.device_id.isnot(None),
            )
        )
        .group_by(RawEvent.device_id, RawEvent.domain, RawEvent.target_ip)
    )
    conn_result = await session.execute(connection_query)
    _connections = list(conn_result)  # TODO: Use for device-to-device links

    # Build nodes
    nodes: list[TopologyNode] = []

    # Add router node (central hub)
    nodes.append(
        TopologyNode(
            id="router",
            label="Router/Gateway",
            type="router",
            status="active",
            ip_address="192.168.1.1",  # Placeholder
        )
    )

    # Add internet node
    nodes.append(
        TopologyNode(
            id="internet",
            label="Internet",
            type="internet",
            status="active",
        )
    )

    # Add device nodes
    device_map = {}
    for device in devices:
        device_id = str(device.id)
        device_map[device_id] = device

        node_type = "device"
        if device.device_type:
            dt_lower = device.device_type.lower()
            if "router" in dt_lower or "gateway" in dt_lower:
                node_type = "router"
            elif "server" in dt_lower:
                node_type = "server"
            elif "phone" in dt_lower or "mobile" in dt_lower:
                node_type = "mobile"
            elif "computer" in dt_lower or "laptop" in dt_lower or "desktop" in dt_lower:
                node_type = "computer"
            elif "iot" in dt_lower or "smart" in dt_lower:
                node_type = "iot"

        nodes.append(
            TopologyNode(
                id=device_id,
                label=device.hostname or device.mac_address,
                type=node_type,
                status=device.status,
                ip_address=device.ip_addresses[0] if device.ip_addresses else None,
                mac_address=device.mac_address,
                manufacturer=device.manufacturer,
                device_type=device.device_type,
                event_count_24h=event_counts.get(device_id, 0),
                tags=device.profile_tags or [],
                is_quarantined=device.status == "quarantined",
            )
        )

    # Build links
    links: list[TopologyLink] = []
    link_set = set()  # Avoid duplicates

    # Every device connects to the router
    for device in devices:
        device_id = str(device.id)
        link_key = f"{device_id}-router"
        if link_key not in link_set:
            link_set.add(link_key)
            links.append(
                TopologyLink(
                    source=device_id,
                    target="router",
                    traffic_volume=event_counts.get(device_id, 0),
                    link_type="blocked" if device.status == "quarantined" else "connection",
                )
            )

    # Router connects to internet
    total_traffic = sum(event_counts.values())
    links.append(
        TopologyLink(
            source="router",
            target="internet",
            traffic_volume=total_traffic,
            link_type="connection",
        )
    )

    # Calculate stats
    active_devices = sum(1 for d in devices if d.status == "active")
    quarantined_devices = sum(1 for d in devices if d.status == "quarantined")

    stats = {
        "total_devices": len(devices),
        "active_devices": active_devices,
        "quarantined_devices": quarantined_devices,
        "total_events": sum(event_counts.values()),
        "time_window_hours": hours,
    }

    return TopologyData(nodes=nodes, links=links, stats=stats)


@router.get("/device/{device_id}/connections")
async def get_device_connections(
    device_id: str,
    hours: int = Query(24, ge=1, le=168),
    limit: int = Query(50, ge=1, le=200),
    session: AsyncSession = Depends(get_async_session),
    current_user: User = Depends(get_current_user),
) -> dict[str, Any]:
    """Get connection details for a specific device."""
    cutoff_time = datetime.now(UTC) - timedelta(hours=hours)

    # Get top domains/IPs this device has connected to
    query = (
        select(
            RawEvent.domain,
            RawEvent.target_ip,
            RawEvent.event_type,
            RawEvent.action,
            func.count(RawEvent.id).label("count"),
            func.max(RawEvent.timestamp).label("last_seen"),
        )
        .where(
            and_(
                RawEvent.device_id == device_id,
                RawEvent.timestamp >= cutoff_time,
            )
        )
        .group_by(RawEvent.domain, RawEvent.target_ip, RawEvent.event_type, RawEvent.action)
        .order_by(func.count(RawEvent.id).desc())
        .limit(limit)
    )

    result = await session.execute(query)
    connections = []

    for row in result:
        connections.append(
            {
                "domain": row.domain,
                "target_ip": row.target_ip,
                "event_type": row.event_type,
                "action": row.action,
                "count": row.count,
                "last_seen": row.last_seen.isoformat() if row.last_seen else None,
            }
        )

    return {"device_id": device_id, "connections": connections, "time_window_hours": hours}
