"""Pytest configuration and shared fixtures."""

import asyncio
from datetime import datetime, timedelta, timezone
from typing import AsyncGenerator, Dict, Generator, Any
from unittest.mock import AsyncMock, MagicMock, patch
from uuid import uuid4

import pytest

from app.core.security import UserRole
from app.models.device import DeviceStatus, DeviceType
from app.models.raw_event import EventSeverity, EventType
from app.models.alert import AlertSeverity, AlertStatus
from app.models.log_source import ParserType, SourceType


@pytest.fixture(scope="session")
def event_loop() -> Generator[asyncio.AbstractEventLoop, None, None]:
    """Create an instance of the default event loop for the test session."""
    loop = asyncio.get_event_loop_policy().new_event_loop()
    yield loop
    loop.close()


# ============================================================================
# Database Fixtures
# ============================================================================


@pytest.fixture
def mock_db_session() -> AsyncMock:
    """Create a reusable async mock database session.

    Provides a pre-configured AsyncMock with common database operation methods.
    """
    session = AsyncMock()

    # Mock common session methods
    session.execute = AsyncMock()
    session.commit = AsyncMock()
    session.rollback = AsyncMock()
    session.refresh = AsyncMock()
    session.close = AsyncMock()
    session.add = MagicMock()
    session.delete = MagicMock()
    session.flush = AsyncMock()

    # Mock scalars pattern commonly used with SQLAlchemy
    mock_scalars = MagicMock()
    mock_scalars.all = MagicMock(return_value=[])
    mock_scalars.first = MagicMock(return_value=None)
    mock_scalars.one = MagicMock()
    mock_scalars.one_or_none = MagicMock(return_value=None)

    mock_result = MagicMock()
    mock_result.scalars = MagicMock(return_value=mock_scalars)
    mock_result.scalar = MagicMock(return_value=None)
    mock_result.scalar_one_or_none = MagicMock(return_value=None)

    session.execute.return_value = mock_result

    return session


@pytest.fixture
def mock_redis() -> AsyncMock:
    """Create a reusable mock Redis client.

    Provides a pre-configured AsyncMock with common Redis operations.
    """
    redis = AsyncMock()

    # String operations
    redis.get = AsyncMock(return_value=None)
    redis.set = AsyncMock(return_value=True)
    redis.setex = AsyncMock(return_value=True)
    redis.delete = AsyncMock(return_value=1)
    redis.exists = AsyncMock(return_value=0)
    redis.incr = AsyncMock(return_value=1)
    redis.expire = AsyncMock(return_value=True)

    # Hash operations
    redis.hget = AsyncMock(return_value=None)
    redis.hset = AsyncMock(return_value=1)
    redis.hgetall = AsyncMock(return_value={})
    redis.hdel = AsyncMock(return_value=1)

    # List operations
    redis.lpush = AsyncMock(return_value=1)
    redis.rpush = AsyncMock(return_value=1)
    redis.lpop = AsyncMock(return_value=None)
    redis.lrange = AsyncMock(return_value=[])

    # Stream operations (for Redis Streams event bus)
    redis.xadd = AsyncMock(return_value=b"1234567890-0")
    redis.xread = AsyncMock(return_value=[])
    redis.xreadgroup = AsyncMock(return_value=[])
    redis.xack = AsyncMock(return_value=1)
    redis.xgroup_create = AsyncMock()

    # Pipeline support
    pipeline = AsyncMock()
    pipeline.execute = AsyncMock(return_value=[])
    redis.pipeline = MagicMock(return_value=pipeline)

    # Connection management
    redis.close = AsyncMock()
    redis.ping = AsyncMock(return_value=True)

    return redis


# ============================================================================
# Time Fixtures
# ============================================================================


@pytest.fixture
def freeze_time():
    """Context manager fixture for freezing time in tests.

    Usage:
        def test_something(freeze_time):
            with freeze_time(datetime(2024, 1, 1, 12, 0, 0, tzinfo=timezone.utc)):
                # Time is now frozen at 2024-01-01 12:00:00 UTC
                ...
    """
    from contextlib import contextmanager

    @contextmanager
    def _freeze_time(frozen_datetime: datetime):
        """Freeze datetime.now() to return a specific time."""
        # Ensure timezone awareness
        if frozen_datetime.tzinfo is None:
            frozen_datetime = frozen_datetime.replace(tzinfo=timezone.utc)

        with patch("datetime.datetime") as mock_datetime:
            mock_datetime.now.return_value = frozen_datetime
            mock_datetime.utcnow.return_value = frozen_datetime.replace(tzinfo=None)
            # Preserve other datetime functionality
            mock_datetime.side_effect = lambda *args, **kwargs: datetime(*args, **kwargs)
            mock_datetime.fromisoformat = datetime.fromisoformat
            mock_datetime.strptime = datetime.strptime
            yield mock_datetime

    return _freeze_time


@pytest.fixture
def fixed_now() -> datetime:
    """Return a fixed datetime for deterministic testing."""
    return datetime(2024, 6, 15, 12, 0, 0, tzinfo=timezone.utc)


# ============================================================================
# Sample Data Fixtures
# ============================================================================


@pytest.fixture
def sample_device_data() -> Dict[str, Any]:
    """Generate sample device test data."""
    device_id = uuid4()
    now = datetime.now(timezone.utc)

    return {
        "id": device_id,
        "mac_address": "AA:BB:CC:DD:EE:FF",
        "ip_addresses": ["192.168.1.100"],
        "hostname": "test-device",
        "manufacturer": "Test Manufacturer",
        "device_type": DeviceType.PC,
        "profile_tags": ["workstation", "windows"],
        "first_seen": now - timedelta(days=30),
        "last_seen": now,
        "status": DeviceStatus.ACTIVE,
        "baseline_ready": True,
    }


@pytest.fixture
def sample_device(sample_device_data) -> MagicMock:
    """Create a mock device object."""
    device = MagicMock()
    for key, value in sample_device_data.items():
        setattr(device, key, value)
    return device


@pytest.fixture
def sample_event_data() -> Dict[str, Any]:
    """Generate sample event test data."""
    event_id = uuid4()
    now = datetime.now(timezone.utc)

    return {
        "id": event_id,
        "timestamp": now,
        "source_id": "test-source",
        "event_type": EventType.DNS,
        "severity": EventSeverity.INFO,
        "client_ip": "192.168.1.100",
        "target_ip": "8.8.8.8",
        "domain": "example.com",
        "port": 53,
        "protocol": "UDP",
        "action": "allow",
        "raw_message": "DNS query for example.com",
        "parsed_fields": {"query_type": "A"},
        "device_id": uuid4(),
    }


@pytest.fixture
def sample_event(sample_event_data) -> MagicMock:
    """Create a mock event object."""
    event = MagicMock()
    for key, value in sample_event_data.items():
        setattr(event, key, value)
    return event


@pytest.fixture
def sample_alert_data() -> Dict[str, Any]:
    """Generate sample alert test data."""
    alert_id = uuid4()
    now = datetime.now(timezone.utc)

    return {
        "id": alert_id,
        "timestamp": now,
        "device_id": uuid4(),
        "rule_id": "suspicious-dns-query",
        "severity": AlertSeverity.MEDIUM,
        "title": "Suspicious DNS Query Detected",
        "description": "Device queried a known malicious domain.",
        "llm_analysis": None,
        "status": AlertStatus.NEW,
        "actions_taken": [],
        "acknowledged_by": None,
        "acknowledged_at": None,
        "resolved_by": None,
        "resolved_at": None,
    }


@pytest.fixture
def sample_alert(sample_alert_data) -> MagicMock:
    """Create a mock alert object."""
    alert = MagicMock()
    for key, value in sample_alert_data.items():
        setattr(alert, key, value)
    return alert


@pytest.fixture
def sample_user_data() -> Dict[str, Any]:
    """Generate sample user test data."""
    user_id = uuid4()
    now = datetime.now(timezone.utc)

    return {
        "id": user_id,
        "username": "testuser",
        "email": "testuser@example.com",
        "password_hash": "$2b$12$test_hash_placeholder",
        "role": UserRole.OPERATOR,
        "is_active": True,
        "must_change_password": False,
        "last_login": now - timedelta(hours=1),
        "created_by": None,
        "totp_enabled": False,
        "totp_secret": None,
        "backup_codes": None,
    }


@pytest.fixture
def sample_user(sample_user_data) -> MagicMock:
    """Create a mock user object."""
    user = MagicMock()
    for key, value in sample_user_data.items():
        setattr(user, key, value)
    return user


@pytest.fixture
def sample_source_data() -> Dict[str, Any]:
    """Generate sample log source test data."""
    now = datetime.now(timezone.utc)

    return {
        "id": "test-adguard",
        "name": "Test AdGuard Home",
        "description": "Test AdGuard Home instance",
        "source_type": SourceType.API_PULL,
        "enabled": True,
        "config": {
            "url": "http://192.168.1.1:3000",
            "username": "admin",
            "password": "password",
        },
        "parser_type": ParserType.ADGUARD,
        "parser_config": {},
        "api_key": None,
        "last_event_at": now - timedelta(minutes=5),
        "last_error": None,
        "event_count": 1000,
    }


@pytest.fixture
def sample_source(sample_source_data) -> MagicMock:
    """Create a mock log source object."""
    source = MagicMock()
    for key, value in sample_source_data.items():
        setattr(source, key, value)
    return source


@pytest.fixture
def sample_rule_data() -> Dict[str, Any]:
    """Generate sample detection rule test data."""
    return {
        "id": "test-rule-001",
        "name": "Test Detection Rule",
        "description": "A test detection rule for unit tests",
        "severity": AlertSeverity.MEDIUM,
        "enabled": True,
        "conditions": {
            "type": "domain_match",
            "pattern": r".*\.malware\.com$",
        },
        "response_actions": [
            {"action": "alert"},
            {"action": "quarantine", "auto": False},
        ],
        "cooldown_minutes": 60,
    }


@pytest.fixture
def sample_rule(sample_rule_data) -> MagicMock:
    """Create a mock detection rule object."""
    rule = MagicMock()
    for key, value in sample_rule_data.items():
        setattr(rule, key, value)
    return rule


# ============================================================================
# Authentication Fixtures
# ============================================================================


@pytest.fixture
def auth_headers_admin() -> Dict[str, str]:
    """Generate mock authentication headers for admin user."""
    return {
        "Authorization": "Bearer mock-admin-jwt-token",
        "Content-Type": "application/json",
    }


@pytest.fixture
def auth_headers_operator() -> Dict[str, str]:
    """Generate mock authentication headers for operator user."""
    return {
        "Authorization": "Bearer mock-operator-jwt-token",
        "Content-Type": "application/json",
    }


@pytest.fixture
def auth_headers_viewer() -> Dict[str, str]:
    """Generate mock authentication headers for viewer user."""
    return {
        "Authorization": "Bearer mock-viewer-jwt-token",
        "Content-Type": "application/json",
    }


@pytest.fixture
def mock_current_user_admin(sample_user_data) -> MagicMock:
    """Create a mock admin user for authentication."""
    user = MagicMock()
    for key, value in sample_user_data.items():
        setattr(user, key, value)
    user.role = UserRole.ADMIN
    user.username = "admin"
    return user


@pytest.fixture
def mock_current_user_operator(sample_user_data) -> MagicMock:
    """Create a mock operator user for authentication."""
    user = MagicMock()
    for key, value in sample_user_data.items():
        setattr(user, key, value)
    user.role = UserRole.OPERATOR
    user.username = "operator"
    return user


@pytest.fixture
def mock_current_user_viewer(sample_user_data) -> MagicMock:
    """Create a mock viewer user for authentication."""
    user = MagicMock()
    for key, value in sample_user_data.items():
        setattr(user, key, value)
    user.role = UserRole.VIEWER
    user.username = "viewer"
    return user


# ============================================================================
# HTTP Client Fixtures
# ============================================================================


@pytest.fixture
def mock_httpx_client() -> AsyncMock:
    """Create a mock httpx async client."""
    client = AsyncMock()

    # Mock response
    mock_response = MagicMock()
    mock_response.status_code = 200
    mock_response.text = ""
    mock_response.json.return_value = {}
    mock_response.raise_for_status = MagicMock()

    client.get = AsyncMock(return_value=mock_response)
    client.post = AsyncMock(return_value=mock_response)
    client.put = AsyncMock(return_value=mock_response)
    client.patch = AsyncMock(return_value=mock_response)
    client.delete = AsyncMock(return_value=mock_response)

    # Context manager support
    client.__aenter__ = AsyncMock(return_value=client)
    client.__aexit__ = AsyncMock(return_value=None)

    return client


# ============================================================================
# Event Generation Helpers
# ============================================================================


@pytest.fixture
def generate_events():
    """Factory fixture for generating multiple test events.

    Usage:
        def test_bulk_processing(generate_events):
            events = generate_events(count=100, event_type=EventType.DNS)
    """
    def _generate_events(
        count: int = 10,
        event_type: EventType = EventType.DNS,
        device_id = None,
        start_time: datetime = None,
    ) -> list:
        if start_time is None:
            start_time = datetime.now(timezone.utc)
        if device_id is None:
            device_id = uuid4()

        events = []
        for i in range(count):
            event = MagicMock()
            event.id = uuid4()
            event.timestamp = start_time - timedelta(minutes=i)
            event.event_type = event_type
            event.device_id = device_id
            event.severity = EventSeverity.INFO
            event.client_ip = f"192.168.1.{100 + (i % 155)}"
            event.domain = f"domain{i}.example.com"
            event.action = "allow" if i % 5 != 0 else "block"
            events.append(event)

        return events

    return _generate_events
