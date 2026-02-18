"""Log query service for extracting and querying events from user chat messages."""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from typing import Any
from uuid import UUID

import structlog
from anthropic import AsyncAnthropic
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.config import settings
from app.models.raw_event import EventSeverity, EventType, RawEvent

logger = structlog.get_logger()


@dataclass
class LogQueryParameters:
    """Parameters extracted from a user's natural language query."""

    device_name: str | None = None
    device_id: UUID | None = None
    event_types: list[EventType] = field(default_factory=list)
    severity_min: EventSeverity | None = None
    domain_contains: str | None = None
    client_ip: str | None = None
    target_ip: str | None = None
    action: str | None = None
    time_range_hours: int = 24
    keywords: list[str] = field(default_factory=list)
    blocked_only: bool = False


@dataclass
class LogQueryResult:
    """Result of a log query with events and metadata."""

    events: list[dict[str, Any]]
    total_matching: int
    query_params: LogQueryParameters
    query_description: str


# Mapping of natural language terms to EventType values
_EVENT_TYPE_KEYWORDS: dict[str, EventType] = {
    "dns": EventType.DNS,
    "domain": EventType.DNS,
    "query": EventType.DNS,
    "lookup": EventType.DNS,
    "firewall": EventType.FIREWALL,
    "fw": EventType.FIREWALL,
    "block": EventType.FIREWALL,
    "drop": EventType.FIREWALL,
    "auth": EventType.AUTH,
    "authentication": EventType.AUTH,
    "login": EventType.AUTH,
    "logon": EventType.AUTH,
    "password": EventType.AUTH,
    "http": EventType.HTTP,
    "web": EventType.HTTP,
    "system": EventType.SYSTEM,
    "syslog": EventType.SYSTEM,
    "network": EventType.NETWORK,
    "traffic": EventType.NETWORK,
    "connection": EventType.NETWORK,
    "container": EventType.CONTAINER,
    "docker": EventType.CONTAINER,
    "podman": EventType.CONTAINER,
    "journal": EventType.JOURNAL,
    "systemd": EventType.JOURNAL,
    "application": EventType.APPLICATION,
    "app": EventType.APPLICATION,
    "endpoint": EventType.ENDPOINT,
    "process": EventType.ENDPOINT,
    "flow": EventType.FLOW,
    "netflow": EventType.FLOW,
    "sflow": EventType.FLOW,
    "llm": EventType.LLM,
    "ollama": EventType.LLM,
}

_SEVERITY_KEYWORDS: dict[str, EventSeverity] = {
    "critical": EventSeverity.CRITICAL,
    "error": EventSeverity.ERROR,
    "errors": EventSeverity.ERROR,
    "warning": EventSeverity.WARNING,
    "warnings": EventSeverity.WARNING,
    "info": EventSeverity.INFO,
    "debug": EventSeverity.DEBUG,
}

_ACTION_KEYWORDS: set[str] = {"blocked", "denied", "dropped", "allowed", "rejected", "accepted"}

_TIME_EXPRESSIONS: dict[str, int] = {
    "last hour": 1,
    "past hour": 1,
    "last 2 hours": 2,
    "last 4 hours": 4,
    "last 6 hours": 6,
    "last 12 hours": 12,
    "today": 24,
    "last 24 hours": 24,
    "past 24 hours": 24,
    "yesterday": 48,
    "last 2 days": 48,
    "last 3 days": 72,
    "this week": 168,
    "last week": 168,
    "last 7 days": 168,
}

_IP_PATTERN = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
_DOMAIN_PATTERN = re.compile(r"\b[\w-]+\.[\w.-]+\.[a-zA-Z]{2,}\b")

# Severity ordering for >= comparisons
_SEVERITY_ORDER = {
    EventSeverity.DEBUG: 0,
    EventSeverity.INFO: 1,
    EventSeverity.WARNING: 2,
    EventSeverity.ERROR: 3,
    EventSeverity.CRITICAL: 4,
}

_EXTRACTION_PROMPT = """You are a parameter extractor for a network security log query system.

Given a user's natural language question about their network logs, extract structured query parameters.

Available event types: dns, firewall, auth, http, system, network, llm, endpoint, flow, container, journal, application, unknown
Available severities: debug, info, warning, error, critical
Available actions: block, allow, drop, reject, accept

Known devices on the network:
{devices_json}

{conversation_context}

Extract parameters from the user's message and return ONLY a JSON object with these fields (omit fields that don't apply):
{{
  "device_name": "hostname or device description mentioned",
  "event_types": ["list", "of", "event", "types"],
  "severity_min": "minimum severity level",
  "domain_contains": "domain or domain fragment mentioned",
  "client_ip": "source IP if mentioned",
  "target_ip": "destination IP if mentioned",
  "action": "action type if mentioned (block, allow, drop)",
  "time_range_hours": 24,
  "keywords": ["additional", "search", "terms"],
  "blocked_only": false
}}

User message: {message}"""


class LogQueryService:
    """Service for extracting query parameters from chat messages and querying events."""

    def __init__(self) -> None:
        self._client: AsyncAnthropic | None = None

    @property
    def client(self) -> AsyncAnthropic:
        """Get or create the Anthropic client."""
        if self._client is None:
            if not settings.anthropic_api_key:
                raise ValueError("Anthropic API key not configured")
            self._client = AsyncAnthropic(api_key=settings.anthropic_api_key)
        return self._client

    async def extract_query_parameters(
        self,
        message: str,
        devices: list[dict[str, Any]],
        conversation_context: list[dict[str, str]] | None = None,
    ) -> LogQueryParameters:
        """Extract log query parameters from a user's natural language message.

        Uses LLM extraction with heuristic fallback.

        Args:
            message: The user's chat message.
            devices: List of device dicts from network context.
            conversation_context: Previous messages for follow-up context.

        Returns:
            LogQueryParameters extracted from the message.
        """
        if not settings.anthropic_api_key:
            return self._heuristic_extract(message, devices)

        try:
            devices_summary = [
                {
                    "hostname": d.get("hostname"),
                    "device_type": d.get("device_type"),
                    "ip_addresses": d.get("ip_addresses", []),
                    "mac_address": d.get("mac_address"),
                }
                for d in devices[:20]
            ]

            context_text = ""
            if conversation_context:
                recent = conversation_context[-4:]
                context_text = "Recent conversation:\n" + "\n".join(
                    f"- {m['role']}: {m['content'][:200]}" for m in recent
                )

            prompt = _EXTRACTION_PROMPT.format(
                devices_json=json.dumps(devices_summary, indent=2),
                conversation_context=context_text,
                message=message,
            )

            response = await self.client.messages.create(
                model=settings.llm_model_fast,
                max_tokens=300,
                temperature=0.0,
                messages=[{"role": "user", "content": prompt}],
            )

            response_text = response.content[0].text.strip()  # type: ignore[union-attr]

            # Handle markdown code blocks
            if response_text.startswith("```"):
                response_text = response_text.split("```")[1]
                if response_text.startswith("json"):
                    response_text = response_text[4:]
                response_text = response_text.strip()

            result = json.loads(response_text)
            params = LogQueryParameters()

            if result.get("device_name"):
                params.device_name = result["device_name"]
                params.device_id = self._resolve_device(result["device_name"], devices)

            if result.get("event_types"):
                for et in result["event_types"]:
                    try:
                        params.event_types.append(EventType(et))
                    except ValueError:
                        pass

            if result.get("severity_min"):
                try:
                    params.severity_min = EventSeverity(result["severity_min"])
                except ValueError:
                    pass

            params.domain_contains = result.get("domain_contains")
            params.client_ip = result.get("client_ip")
            params.target_ip = result.get("target_ip")
            params.action = result.get("action")
            params.time_range_hours = result.get("time_range_hours", 24)
            params.keywords = result.get("keywords", [])
            params.blocked_only = result.get("blocked_only", False)

            logger.info(
                "log_query_params_extracted",
                method="llm",
                device=params.device_name,
                event_types=[et.value for et in params.event_types],
                time_range=params.time_range_hours,
            )

            return params

        except Exception as e:
            logger.warning("llm_extraction_failed", error=str(e), exc_info=True)
            return self._heuristic_extract(message, devices)

    def _heuristic_extract(
        self,
        message: str,
        devices: list[dict[str, Any]],
    ) -> LogQueryParameters:
        """Regex-based fallback for parameter extraction.

        Args:
            message: The user's chat message.
            devices: List of device dicts from network context.

        Returns:
            LogQueryParameters extracted via heuristics.
        """
        params = LogQueryParameters()
        msg_lower = message.lower()

        # Extract event types
        for keyword, event_type in _EVENT_TYPE_KEYWORDS.items():
            if keyword in msg_lower and event_type not in params.event_types:
                params.event_types.append(event_type)

        # Extract severity
        for keyword, severity in _SEVERITY_KEYWORDS.items():
            if keyword in msg_lower:
                params.severity_min = severity
                break

        # Extract time range
        for expression, hours in _TIME_EXPRESSIONS.items():
            if expression in msg_lower:
                params.time_range_hours = hours
                break

        # Extract IPs
        ips = _IP_PATTERN.findall(message)
        if ips:
            params.client_ip = ips[0]
            if len(ips) > 1:
                params.target_ip = ips[1]

        # Extract domain-like strings
        domains = _DOMAIN_PATTERN.findall(message)
        if domains:
            params.domain_contains = domains[0]

        # Extract action keywords
        for action_kw in _ACTION_KEYWORDS:
            if action_kw in msg_lower:
                # Normalize to base form
                action_map = {
                    "blocked": "block",
                    "denied": "block",
                    "dropped": "drop",
                    "rejected": "block",
                    "allowed": "allow",
                    "accepted": "allow",
                }
                params.action = action_map.get(action_kw, action_kw)
                if action_kw in ("blocked", "denied", "rejected"):
                    params.blocked_only = True
                break

        # Try to match device names
        for device in devices:
            hostname = device.get("hostname", "")
            if hostname and hostname.lower() in msg_lower:
                params.device_name = hostname
                device_id = device.get("id")
                if device_id:
                    params.device_id = UUID(str(device_id)) if not isinstance(device_id, UUID) else device_id
                break
            # Check device type mentions
            device_type = device.get("device_type", "")
            if device_type and device_type != "unknown" and device_type.lower() in msg_lower:
                params.device_name = hostname or device_type
                device_id = device.get("id")
                if device_id:
                    params.device_id = UUID(str(device_id)) if not isinstance(device_id, UUID) else device_id
                break

        logger.info(
            "log_query_params_extracted",
            method="heuristic",
            device=params.device_name,
            event_types=[et.value for et in params.event_types],
            time_range=params.time_range_hours,
        )

        return params

    @staticmethod
    def _resolve_device(
        device_name: str,
        devices: list[dict[str, Any]],
    ) -> UUID | None:
        """Resolve a device name to its UUID via case-insensitive matching.

        Args:
            device_name: Name/description from the user.
            devices: List of device dicts.

        Returns:
            Device UUID if found, None otherwise.
        """
        name_lower = device_name.lower()

        for device in devices:
            # Check hostname
            hostname = device.get("hostname") or ""
            if hostname and name_lower in hostname.lower():
                device_id = device.get("id")
                if device_id:
                    return UUID(str(device_id)) if not isinstance(device_id, UUID) else device_id

            # Check manufacturer
            manufacturer = device.get("manufacturer") or ""
            if manufacturer and name_lower in manufacturer.lower():
                device_id = device.get("id")
                if device_id:
                    return UUID(str(device_id)) if not isinstance(device_id, UUID) else device_id

            # Check device_type
            device_type = device.get("device_type") or ""
            if device_type and name_lower in device_type.lower():
                device_id = device.get("id")
                if device_id:
                    return UUID(str(device_id)) if not isinstance(device_id, UUID) else device_id

            # Check profile tags
            tags = device.get("profile_tags") or []
            for tag in tags:
                if name_lower in tag.lower():
                    device_id = device.get("id")
                    if device_id:
                        return UUID(str(device_id)) if not isinstance(device_id, UUID) else device_id

        return None

    async def query_events(
        self,
        session: AsyncSession,
        params: LogQueryParameters,
        limit: int = 50,
    ) -> LogQueryResult:
        """Query events from the database based on extracted parameters.

        Args:
            session: Async database session.
            params: Query parameters to filter events.
            limit: Maximum number of events to return.

        Returns:
            LogQueryResult with matching events and metadata.
        """
        now = datetime.now(UTC)
        cutoff = now - timedelta(hours=params.time_range_hours)

        # Base query with time range filter
        base_filter = [RawEvent.timestamp >= cutoff]

        if params.device_id:
            base_filter.append(RawEvent.device_id == params.device_id)

        if params.event_types:
            base_filter.append(RawEvent.event_type.in_(params.event_types))

        if params.severity_min:
            min_order = _SEVERITY_ORDER[params.severity_min]
            eligible = [s for s, o in _SEVERITY_ORDER.items() if o >= min_order]
            base_filter.append(RawEvent.severity.in_(eligible))

        if params.domain_contains:
            base_filter.append(RawEvent.domain.ilike(f"%{params.domain_contains}%"))

        if params.client_ip:
            base_filter.append(RawEvent.client_ip == params.client_ip)

        if params.target_ip:
            base_filter.append(RawEvent.target_ip == params.target_ip)

        if params.action:
            base_filter.append(RawEvent.action == params.action)

        if params.blocked_only:
            base_filter.append(RawEvent.response_status == "blocked")

        # Get total count
        count_query = select(func.count()).select_from(RawEvent).where(*base_filter)
        count_result = await session.execute(count_query)
        total_matching = count_result.scalar() or 0

        # Fetch limited results
        events_query = (
            select(RawEvent)
            .where(*base_filter)
            .order_by(RawEvent.timestamp.desc())
            .limit(limit)
        )
        events_result = await session.execute(events_query)
        events = events_result.scalars().all()

        # Convert to compact dicts
        event_dicts = []
        for event in events:
            event_dict: dict[str, Any] = {
                "timestamp": event.timestamp.strftime("%m-%d %H:%M"),
                "type": event.event_type.value if event.event_type else "unknown",
                "severity": event.severity.value if event.severity else "info",
            }

            if event.client_ip:
                event_dict["source_ip"] = event.client_ip
            if event.domain:
                event_dict["domain"] = event.domain
            elif event.target_ip:
                event_dict["destination"] = event.target_ip
            if event.action:
                event_dict["action"] = event.action

            # Type-specific details
            details = self._extract_details(event)
            if details:
                event_dict["details"] = details

            event_dicts.append(event_dict)

        query_description = self._build_query_description(params)

        return LogQueryResult(
            events=event_dicts,
            total_matching=total_matching,
            query_params=params,
            query_description=query_description,
        )

    @staticmethod
    def _extract_details(event: RawEvent) -> str:
        """Extract type-specific details from an event.

        Args:
            event: The raw event to extract details from.

        Returns:
            A compact string of relevant details.
        """
        parts = []

        if event.event_type == EventType.DNS:
            if event.query_type:
                parts.append(event.query_type)
            if event.response_status:
                parts.append(event.response_status)
            if event.blocked_reason:
                parts.append(event.blocked_reason)
        elif event.event_type == EventType.FIREWALL:
            if event.port:
                parts.append(f"port {event.port}")
            if event.protocol:
                parts.append(event.protocol)
        elif event.event_type == EventType.AUTH:
            parsed = event.parsed_fields or {}
            username = parsed.get("username") or parsed.get("user")
            if username:
                parts.append(f"user: {username}")
        elif event.event_type in (EventType.CONTAINER, EventType.APPLICATION):
            parsed = event.parsed_fields or {}
            container = parsed.get("container_name") or parsed.get("service")
            if container:
                parts.append(container)
            error_type = parsed.get("exception_type") or parsed.get("error_type")
            if error_type:
                parts.append(error_type)

        return ", ".join(parts)

    @staticmethod
    def _build_query_description(params: LogQueryParameters) -> str:
        """Build a human-readable description of the query.

        Args:
            params: The query parameters.

        Returns:
            A description like 'DNS events from "ring-doorbell" in the last 24 hours'.
        """
        parts = []

        if params.event_types:
            type_names = [et.value.upper() for et in params.event_types]
            parts.append(", ".join(type_names) + " events")
        else:
            parts.append("All events")

        if params.device_name:
            parts.append(f'from "{params.device_name}"')

        if params.severity_min:
            parts.append(f"with severity >= {params.severity_min.value}")

        if params.domain_contains:
            parts.append(f'matching domain "*{params.domain_contains}*"')

        if params.client_ip:
            parts.append(f"from IP {params.client_ip}")

        if params.target_ip:
            parts.append(f"to IP {params.target_ip}")

        if params.blocked_only:
            parts.append("(blocked only)")
        elif params.action:
            parts.append(f"(action: {params.action})")

        parts.append(f"in the last {params.time_range_hours} hours")

        return " ".join(parts)

    @staticmethod
    def format_events_for_context(result: LogQueryResult) -> str:
        """Format a LogQueryResult as a compact markdown section for LLM context.

        Args:
            result: The query result to format.

        Returns:
            Markdown string suitable for injection into LLM context.
        """
        lines = ["## Log Query Results"]
        lines.append(f"**Query:** {result.query_description}")

        if not result.events:
            lines.append(f"\n**No events found** matching: {result.query_description}")
            lines.append(
                "Consider broadening the search by expanding the time range, "
                "removing filters, or checking if the device name is correct."
            )
            return "\n".join(lines)

        lines.append(
            f"**Results:** Showing {len(result.events)} of "
            f"{result.total_matching:,} matching events"
        )
        lines.append("")

        # Build table
        lines.append("| Time (UTC) | Type | Severity | Source IP | Destination/Domain | Action | Details |")
        lines.append("|---|---|---|---|---|---|---|")

        for event in result.events:
            time = event.get("timestamp", "")
            etype = event.get("type", "")
            severity = event.get("severity", "")
            source_ip = event.get("source_ip", "")
            dest = event.get("domain") or event.get("destination", "")
            action = event.get("action", "")
            details = event.get("details", "")

            lines.append(f"| {time} | {etype} | {severity} | {source_ip} | {dest} | {action} | {details} |")

        return "\n".join(lines)
