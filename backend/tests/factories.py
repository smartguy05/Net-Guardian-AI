"""Test data factories for generating test objects.

These factories provide convenient methods for creating test data
with sensible defaults while allowing customization of specific fields.
"""

from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional
from uuid import uuid4

from app.core.security import UserRole
from app.models.alert import AlertSeverity, AlertStatus
from app.models.device import DeviceStatus, DeviceType
from app.models.log_source import ParserType, SourceType
from app.models.raw_event import EventSeverity, EventType


class DeviceFactory:
    """Factory for creating test device data."""

    _counter = 0

    @classmethod
    def _next_mac(cls) -> str:
        """Generate a unique MAC address."""
        cls._counter += 1
        return f"AA:BB:CC:DD:{cls._counter // 256:02X}:{cls._counter % 256:02X}"

    @classmethod
    def build(
        cls,
        id: Optional[Any] = None,
        mac_address: Optional[str] = None,
        ip_addresses: Optional[List[str]] = None,
        hostname: Optional[str] = None,
        manufacturer: Optional[str] = None,
        device_type: DeviceType = DeviceType.PC,
        profile_tags: Optional[List[str]] = None,
        first_seen: Optional[datetime] = None,
        last_seen: Optional[datetime] = None,
        status: DeviceStatus = DeviceStatus.ACTIVE,
        baseline_ready: bool = False,
        **kwargs,
    ) -> Dict[str, Any]:
        """Build device data dictionary.

        Args:
            id: Device UUID (auto-generated if not provided).
            mac_address: MAC address (auto-generated if not provided).
            ip_addresses: List of IP addresses.
            hostname: Device hostname.
            manufacturer: Device manufacturer.
            device_type: Type of device.
            profile_tags: Tags for device profiling.
            first_seen: When device was first observed.
            last_seen: When device was last active.
            status: Device operational status.
            baseline_ready: Whether baseline is established.
            **kwargs: Additional fields to include.

        Returns:
            Dictionary with device data.
        """
        now = datetime.now(timezone.utc)
        cls._counter += 1

        data = {
            "id": id or uuid4(),
            "mac_address": mac_address or cls._next_mac(),
            "ip_addresses": ip_addresses or [f"192.168.1.{100 + cls._counter % 155}"],
            "hostname": hostname or f"device-{cls._counter}",
            "manufacturer": manufacturer or "Test Manufacturer",
            "device_type": device_type,
            "profile_tags": profile_tags or [],
            "first_seen": first_seen or now - timedelta(days=30),
            "last_seen": last_seen or now,
            "status": status,
            "baseline_ready": baseline_ready,
        }
        data.update(kwargs)
        return data

    @classmethod
    def build_batch(cls, count: int, **kwargs) -> List[Dict[str, Any]]:
        """Build multiple device data dictionaries.

        Args:
            count: Number of devices to create.
            **kwargs: Common fields for all devices.

        Returns:
            List of device data dictionaries.
        """
        return [cls.build(**kwargs) for _ in range(count)]


class EventFactory:
    """Factory for creating test event data."""

    _counter = 0
    _domains = [
        "google.com", "facebook.com", "twitter.com", "example.com",
        "microsoft.com", "amazon.com", "apple.com", "github.com",
    ]

    @classmethod
    def build(
        cls,
        id: Optional[Any] = None,
        timestamp: Optional[datetime] = None,
        source_id: str = "test-source",
        event_type: EventType = EventType.DNS,
        severity: EventSeverity = EventSeverity.INFO,
        client_ip: Optional[str] = None,
        target_ip: Optional[str] = None,
        domain: Optional[str] = None,
        port: Optional[int] = None,
        protocol: Optional[str] = None,
        action: Optional[str] = None,
        raw_message: Optional[str] = None,
        parsed_fields: Optional[Dict[str, Any]] = None,
        device_id: Optional[Any] = None,
        **kwargs,
    ) -> Dict[str, Any]:
        """Build event data dictionary.

        Args:
            id: Event UUID.
            timestamp: Event timestamp.
            source_id: Source that produced the event.
            event_type: Type of event.
            severity: Event severity level.
            client_ip: Source IP address.
            target_ip: Destination IP address.
            domain: Domain name (for DNS events).
            port: Port number.
            protocol: Protocol (TCP/UDP).
            action: Action taken (allow/block).
            raw_message: Original log message.
            parsed_fields: Additional parsed data.
            device_id: Associated device UUID.
            **kwargs: Additional fields.

        Returns:
            Dictionary with event data.
        """
        cls._counter += 1
        now = datetime.now(timezone.utc)

        data = {
            "id": id or uuid4(),
            "timestamp": timestamp or now,
            "source_id": source_id,
            "event_type": event_type,
            "severity": severity,
            "client_ip": client_ip or f"192.168.1.{100 + cls._counter % 155}",
            "target_ip": target_ip,
            "domain": domain or cls._domains[cls._counter % len(cls._domains)],
            "port": port,
            "protocol": protocol,
            "action": action or "allow",
            "raw_message": raw_message or f"Test event {cls._counter}",
            "parsed_fields": parsed_fields or {},
            "device_id": device_id or uuid4(),
        }
        data.update(kwargs)
        return data

    @classmethod
    def build_dns(cls, **kwargs) -> Dict[str, Any]:
        """Build a DNS event."""
        defaults = {
            "event_type": EventType.DNS,
            "port": 53,
            "protocol": "UDP",
            "parsed_fields": {"query_type": "A"},
        }
        defaults.update(kwargs)
        return cls.build(**defaults)

    @classmethod
    def build_firewall(cls, **kwargs) -> Dict[str, Any]:
        """Build a firewall event."""
        defaults = {
            "event_type": EventType.FIREWALL,
            "port": 443,
            "protocol": "TCP",
            "target_ip": "8.8.8.8",
        }
        defaults.update(kwargs)
        return cls.build(**defaults)

    @classmethod
    def build_auth(cls, success: bool = True, **kwargs) -> Dict[str, Any]:
        """Build an authentication event."""
        defaults = {
            "event_type": EventType.AUTH,
            "action": "success" if success else "failure",
            "parsed_fields": {"auth_type": "ssh", "success": success},
        }
        defaults.update(kwargs)
        return cls.build(**defaults)

    @classmethod
    def build_batch(
        cls,
        count: int,
        time_span_minutes: int = 60,
        **kwargs,
    ) -> List[Dict[str, Any]]:
        """Build multiple event data dictionaries.

        Args:
            count: Number of events to create.
            time_span_minutes: Spread events over this time period.
            **kwargs: Common fields for all events.

        Returns:
            List of event data dictionaries.
        """
        now = datetime.now(timezone.utc)
        events = []
        for i in range(count):
            timestamp = now - timedelta(minutes=i * time_span_minutes / count)
            events.append(cls.build(timestamp=timestamp, **kwargs))
        return events


class AlertFactory:
    """Factory for creating test alert data."""

    _counter = 0
    _titles = [
        "Suspicious DNS Query Detected",
        "Unusual Network Traffic",
        "Failed Authentication Attempt",
        "Port Scan Detected",
        "Data Exfiltration Attempt",
    ]

    @classmethod
    def build(
        cls,
        id: Optional[Any] = None,
        timestamp: Optional[datetime] = None,
        device_id: Optional[Any] = None,
        rule_id: Optional[str] = None,
        severity: AlertSeverity = AlertSeverity.MEDIUM,
        title: Optional[str] = None,
        description: Optional[str] = None,
        llm_analysis: Optional[Dict[str, Any]] = None,
        status: AlertStatus = AlertStatus.NEW,
        actions_taken: Optional[List[Dict[str, Any]]] = None,
        acknowledged_by: Optional[Any] = None,
        acknowledged_at: Optional[datetime] = None,
        resolved_by: Optional[Any] = None,
        resolved_at: Optional[datetime] = None,
        **kwargs,
    ) -> Dict[str, Any]:
        """Build alert data dictionary."""
        cls._counter += 1
        now = datetime.now(timezone.utc)

        data = {
            "id": id or uuid4(),
            "timestamp": timestamp or now,
            "device_id": device_id or uuid4(),
            "rule_id": rule_id or f"rule-{cls._counter:03d}",
            "severity": severity,
            "title": title or cls._titles[cls._counter % len(cls._titles)],
            "description": description or f"Alert description {cls._counter}",
            "llm_analysis": llm_analysis,
            "status": status,
            "actions_taken": actions_taken or [],
            "acknowledged_by": acknowledged_by,
            "acknowledged_at": acknowledged_at,
            "resolved_by": resolved_by,
            "resolved_at": resolved_at,
        }
        data.update(kwargs)
        return data

    @classmethod
    def build_critical(cls, **kwargs) -> Dict[str, Any]:
        """Build a critical severity alert."""
        defaults = {
            "severity": AlertSeverity.CRITICAL,
            "title": "Critical Security Alert",
        }
        defaults.update(kwargs)
        return cls.build(**defaults)

    @classmethod
    def build_acknowledged(cls, user_id: Any = None, **kwargs) -> Dict[str, Any]:
        """Build an acknowledged alert."""
        now = datetime.now(timezone.utc)
        defaults = {
            "status": AlertStatus.ACKNOWLEDGED,
            "acknowledged_by": user_id or uuid4(),
            "acknowledged_at": now,
        }
        defaults.update(kwargs)
        return cls.build(**defaults)

    @classmethod
    def build_resolved(cls, user_id: Any = None, **kwargs) -> Dict[str, Any]:
        """Build a resolved alert."""
        now = datetime.now(timezone.utc)
        defaults = {
            "status": AlertStatus.RESOLVED,
            "resolved_by": user_id or uuid4(),
            "resolved_at": now,
        }
        defaults.update(kwargs)
        return cls.build(**defaults)

    @classmethod
    def build_batch(cls, count: int, **kwargs) -> List[Dict[str, Any]]:
        """Build multiple alert data dictionaries."""
        return [cls.build(**kwargs) for _ in range(count)]


class UserFactory:
    """Factory for creating test user data."""

    _counter = 0

    @classmethod
    def build(
        cls,
        id: Optional[Any] = None,
        username: Optional[str] = None,
        email: Optional[str] = None,
        password_hash: str = "$2b$12$test_hash_placeholder",
        role: UserRole = UserRole.VIEWER,
        is_active: bool = True,
        must_change_password: bool = False,
        last_login: Optional[datetime] = None,
        created_by: Optional[Any] = None,
        totp_enabled: bool = False,
        totp_secret: Optional[str] = None,
        backup_codes: Optional[List[str]] = None,
        **kwargs,
    ) -> Dict[str, Any]:
        """Build user data dictionary."""
        cls._counter += 1
        now = datetime.now(timezone.utc)

        data = {
            "id": id or uuid4(),
            "username": username or f"user{cls._counter}",
            "email": email or f"user{cls._counter}@example.com",
            "password_hash": password_hash,
            "role": role,
            "is_active": is_active,
            "must_change_password": must_change_password,
            "last_login": last_login or now - timedelta(hours=1),
            "created_by": created_by,
            "totp_enabled": totp_enabled,
            "totp_secret": totp_secret,
            "backup_codes": backup_codes,
        }
        data.update(kwargs)
        return data

    @classmethod
    def build_admin(cls, **kwargs) -> Dict[str, Any]:
        """Build an admin user."""
        defaults = {"role": UserRole.ADMIN, "username": f"admin{cls._counter}"}
        defaults.update(kwargs)
        return cls.build(**defaults)

    @classmethod
    def build_operator(cls, **kwargs) -> Dict[str, Any]:
        """Build an operator user."""
        defaults = {"role": UserRole.OPERATOR, "username": f"operator{cls._counter}"}
        defaults.update(kwargs)
        return cls.build(**defaults)

    @classmethod
    def build_viewer(cls, **kwargs) -> Dict[str, Any]:
        """Build a viewer user."""
        defaults = {"role": UserRole.VIEWER, "username": f"viewer{cls._counter}"}
        defaults.update(kwargs)
        return cls.build(**defaults)

    @classmethod
    def build_with_2fa(cls, **kwargs) -> Dict[str, Any]:
        """Build a user with 2FA enabled."""
        defaults = {
            "totp_enabled": True,
            "totp_secret": "JBSWY3DPEHPK3PXP",  # Test secret
            "backup_codes": ["12345678", "23456789", "34567890"],
        }
        defaults.update(kwargs)
        return cls.build(**defaults)


class SourceFactory:
    """Factory for creating test log source data."""

    _counter = 0

    @classmethod
    def build(
        cls,
        id: Optional[str] = None,
        name: Optional[str] = None,
        description: Optional[str] = None,
        source_type: SourceType = SourceType.API_PULL,
        enabled: bool = True,
        config: Optional[Dict[str, Any]] = None,
        parser_type: ParserType = ParserType.ADGUARD,
        parser_config: Optional[Dict[str, Any]] = None,
        api_key: Optional[str] = None,
        last_event_at: Optional[datetime] = None,
        last_error: Optional[str] = None,
        event_count: int = 0,
        **kwargs,
    ) -> Dict[str, Any]:
        """Build log source data dictionary."""
        cls._counter += 1
        now = datetime.now(timezone.utc)

        data = {
            "id": id or f"source-{cls._counter}",
            "name": name or f"Test Source {cls._counter}",
            "description": description or f"Test source description {cls._counter}",
            "source_type": source_type,
            "enabled": enabled,
            "config": config or {},
            "parser_type": parser_type,
            "parser_config": parser_config or {},
            "api_key": api_key,
            "last_event_at": last_event_at or now - timedelta(minutes=5),
            "last_error": last_error,
            "event_count": event_count,
        }
        data.update(kwargs)
        return data

    @classmethod
    def build_adguard(cls, url: str = "http://192.168.1.1:3000", **kwargs) -> Dict[str, Any]:
        """Build an AdGuard Home source."""
        defaults = {
            "source_type": SourceType.API_PULL,
            "parser_type": ParserType.ADGUARD,
            "config": {
                "url": url,
                "username": "admin",
                "password": "password",
                "verify_ssl": False,
            },
        }
        defaults.update(kwargs)
        return cls.build(**defaults)

    @classmethod
    def build_syslog(cls, path: str = "/var/log/syslog", **kwargs) -> Dict[str, Any]:
        """Build a syslog file source."""
        defaults = {
            "source_type": SourceType.FILE_WATCH,
            "parser_type": ParserType.SYSLOG,
            "config": {"path": path},
        }
        defaults.update(kwargs)
        return cls.build(**defaults)

    @classmethod
    def build_netflow(cls, port: int = 2055, **kwargs) -> Dict[str, Any]:
        """Build a NetFlow UDP source."""
        defaults = {
            "source_type": SourceType.UDP_LISTEN,
            "parser_type": ParserType.NETFLOW,
            "config": {"port": port, "bind_address": "0.0.0.0"},
        }
        defaults.update(kwargs)
        return cls.build(**defaults)


class RuleFactory:
    """Factory for creating test detection rule data."""

    _counter = 0

    @classmethod
    def build(
        cls,
        id: Optional[str] = None,
        name: Optional[str] = None,
        description: Optional[str] = None,
        severity: AlertSeverity = AlertSeverity.MEDIUM,
        enabled: bool = True,
        conditions: Optional[Dict[str, Any]] = None,
        response_actions: Optional[List[Dict[str, Any]]] = None,
        cooldown_minutes: int = 60,
        **kwargs,
    ) -> Dict[str, Any]:
        """Build detection rule data dictionary."""
        cls._counter += 1

        data = {
            "id": id or f"rule-{cls._counter:03d}",
            "name": name or f"Test Rule {cls._counter}",
            "description": description or f"Test rule description {cls._counter}",
            "severity": severity,
            "enabled": enabled,
            "conditions": conditions or {
                "type": "field_match",
                "field": "domain",
                "operator": "contains",
                "value": "suspicious",
            },
            "response_actions": response_actions or [{"action": "alert"}],
            "cooldown_minutes": cooldown_minutes,
        }
        data.update(kwargs)
        return data

    @classmethod
    def build_domain_match(cls, pattern: str, **kwargs) -> Dict[str, Any]:
        """Build a domain matching rule."""
        defaults = {
            "name": "Domain Match Rule",
            "conditions": {
                "type": "domain_match",
                "pattern": pattern,
            },
        }
        defaults.update(kwargs)
        return cls.build(**defaults)

    @classmethod
    def build_threshold(cls, field: str, threshold: int, **kwargs) -> Dict[str, Any]:
        """Build a threshold-based rule."""
        defaults = {
            "name": "Threshold Rule",
            "conditions": {
                "type": "threshold",
                "field": field,
                "operator": ">",
                "threshold": threshold,
                "time_window_minutes": 5,
            },
        }
        defaults.update(kwargs)
        return cls.build(**defaults)

    @classmethod
    def build_with_quarantine(cls, auto: bool = False, **kwargs) -> Dict[str, Any]:
        """Build a rule that triggers quarantine."""
        defaults = {
            "severity": AlertSeverity.HIGH,
            "response_actions": [
                {"action": "alert"},
                {"action": "quarantine", "auto": auto},
            ],
        }
        defaults.update(kwargs)
        return cls.build(**defaults)


# Convenience function to reset factory counters (useful between test files)
def reset_factories():
    """Reset all factory counters."""
    DeviceFactory._counter = 0
    EventFactory._counter = 0
    AlertFactory._counter = 0
    UserFactory._counter = 0
    SourceFactory._counter = 0
    RuleFactory._counter = 0
