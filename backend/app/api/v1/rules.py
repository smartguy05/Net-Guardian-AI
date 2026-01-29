"""Detection rules API endpoints."""

import re
from typing import Annotated, Any

from fastapi import APIRouter, Depends, HTTPException, Query, status
from pydantic import BaseModel, Field, field_validator
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.v1.auth import get_current_user, require_admin
from app.db.session import get_async_session
from app.models.alert import AlertSeverity
from app.models.detection_rule import DetectionRule
from app.models.raw_event import EventType
from app.models.user import User

router = APIRouter()


# --- Pydantic Models ---


class RuleCondition(BaseModel):
    """Single condition within a rule."""

    field: str = Field(
        ..., description="Field to check (e.g., 'event_type', 'severity', 'source_ip')"
    )
    operator: str = Field(
        ..., description="Comparison operator (eq, ne, gt, lt, gte, lte, contains, regex, in)"
    )
    value: Any = Field(..., description="Value to compare against")

    @field_validator("operator")
    @classmethod
    def validate_operator(cls, v: str) -> str:
        valid_ops = {
            "eq",
            "ne",
            "gt",
            "lt",
            "gte",
            "lte",
            "contains",
            "regex",
            "in",
            "not_in",
            "starts_with",
            "ends_with",
        }
        if v not in valid_ops:
            raise ValueError(f"Invalid operator. Must be one of: {', '.join(valid_ops)}")
        return v


class RuleConditionGroup(BaseModel):
    """Group of conditions with logical operator."""

    logic: str = Field("and", description="Logical operator: 'and' or 'or'")
    conditions: list[RuleCondition] = Field(..., description="List of conditions")

    @field_validator("logic")
    @classmethod
    def validate_logic(cls, v: str) -> str:
        if v not in {"and", "or"}:
            raise ValueError("Logic must be 'and' or 'or'")
        return v


class RuleAction(BaseModel):
    """Action to take when rule triggers."""

    type: str = Field(
        ...,
        description="Action type (create_alert, quarantine_device, tag_device, send_notification, execute_webhook)",
    )
    config: dict[str, Any] = Field(
        default_factory=dict, description="Action-specific configuration"
    )

    @field_validator("type")
    @classmethod
    def validate_type(cls, v: str) -> str:
        valid_types = {
            "create_alert",
            "quarantine_device",
            "tag_device",
            "send_notification",
            "execute_webhook",
            "log_event",
        }
        if v not in valid_types:
            raise ValueError(f"Invalid action type. Must be one of: {', '.join(valid_types)}")
        return v


class CreateRuleRequest(BaseModel):
    """Request to create a detection rule."""

    id: str = Field(..., min_length=1, max_length=100, description="Unique rule ID (slug)")
    name: str = Field(..., min_length=1, max_length=255, description="Rule display name")
    description: str | None = Field(None, description="Rule description")
    severity: AlertSeverity = Field(..., description="Alert severity when triggered")
    enabled: bool = Field(True, description="Whether rule is active")
    conditions: RuleConditionGroup = Field(..., description="Rule conditions")
    response_actions: list[RuleAction] = Field(
        default_factory=list, description="Actions when triggered"
    )
    cooldown_minutes: int = Field(
        60, ge=0, le=10080, description="Cooldown between alerts (0-10080 mins)"
    )

    @field_validator("id")
    @classmethod
    def validate_id(cls, v: str) -> str:
        if not re.match(r"^[a-z0-9][a-z0-9_-]*$", v):
            raise ValueError(
                "ID must start with lowercase letter/number and contain only lowercase letters, numbers, underscores, and hyphens"
            )
        return v


class UpdateRuleRequest(BaseModel):
    """Request to update a detection rule."""

    name: str | None = Field(None, min_length=1, max_length=255)
    description: str | None = None
    severity: AlertSeverity | None = None
    enabled: bool | None = None
    conditions: RuleConditionGroup | None = None
    response_actions: list[RuleAction] | None = None
    cooldown_minutes: int | None = Field(None, ge=0, le=10080)


class RuleResponse(BaseModel):
    """Detection rule response."""

    id: str
    name: str
    description: str | None
    severity: AlertSeverity
    enabled: bool
    conditions: dict[str, Any]
    response_actions: list[dict[str, Any]]
    cooldown_minutes: int
    created_at: str
    updated_at: str

    model_config = {"from_attributes": True}


class RuleListResponse(BaseModel):
    """List of detection rules."""

    items: list[RuleResponse]
    total: int


class TestRuleRequest(BaseModel):
    """Request to test a rule against sample event."""

    conditions: RuleConditionGroup
    event: dict[str, Any] = Field(..., description="Sample event data to test against")


class TestRuleResponse(BaseModel):
    """Result of testing a rule."""

    matches: bool
    condition_results: list[dict[str, Any]]


class ConditionFieldInfo(BaseModel):
    """Information about a condition field."""

    name: str
    description: str
    type: str
    example_values: list[str] | None = None


# --- Helper Functions ---


def _normalize_response_actions(actions: list[Any]) -> list[dict[str, Any]]:
    """Normalize response_actions to expected format.

    Handles legacy format (list of strings) and new format (list of dicts).
    """
    normalized = []
    for action in actions:
        if isinstance(action, str):
            # Legacy format: convert string to dict
            normalized.append({"type": action, "config": {}})
        elif isinstance(action, dict):
            # Ensure config key exists
            if "config" not in action:
                action["config"] = {}
            normalized.append(action)
        else:
            # Unknown format, skip
            continue
    return normalized


def _rule_to_response(rule: DetectionRule) -> RuleResponse:
    """Convert DetectionRule to response model."""
    return RuleResponse(
        id=rule.id,
        name=rule.name,
        description=rule.description,
        severity=rule.severity,
        enabled=rule.enabled,
        conditions=rule.conditions,
        response_actions=_normalize_response_actions(rule.response_actions),
        cooldown_minutes=rule.cooldown_minutes,
        created_at=rule.created_at.isoformat(),
        updated_at=rule.updated_at.isoformat(),
    )


def _evaluate_condition(condition: RuleCondition, event: dict[str, Any]) -> dict[str, Any]:
    """Evaluate a single condition against an event."""
    field_value = event.get(condition.field)
    result = False

    try:
        op = condition.operator
        val = condition.value

        if op == "eq":
            result = field_value == val
        elif op == "ne":
            result = field_value != val
        elif op == "gt":
            result = field_value is not None and field_value > val
        elif op == "lt":
            result = field_value is not None and field_value < val
        elif op == "gte":
            result = field_value is not None and field_value >= val
        elif op == "lte":
            result = field_value is not None and field_value <= val
        elif op == "contains":
            result = field_value is not None and str(val) in str(field_value)
        elif op == "regex":
            result = field_value is not None and bool(re.search(str(val), str(field_value)))
        elif op == "in":
            result = field_value in (val if isinstance(val, list) else [val])
        elif op == "not_in":
            result = field_value not in (val if isinstance(val, list) else [val])
        elif op == "starts_with":
            result = field_value is not None and str(field_value).startswith(str(val))
        elif op == "ends_with":
            result = field_value is not None and str(field_value).endswith(str(val))
    except Exception:
        result = False

    return {
        "field": condition.field,
        "operator": condition.operator,
        "expected": condition.value,
        "actual": field_value,
        "result": result,
    }


def _evaluate_conditions(
    group: RuleConditionGroup, event: dict[str, Any]
) -> tuple[bool, list[dict[str, Any]]]:
    """Evaluate a condition group against an event."""
    results = [_evaluate_condition(c, event) for c in group.conditions]

    if group.logic == "and":
        matches = all(r["result"] for r in results)
    else:  # or
        matches = any(r["result"] for r in results)

    return matches, results


# --- API Endpoints ---


@router.get("", response_model=RuleListResponse)
async def list_rules(
    session: Annotated[AsyncSession, Depends(get_async_session)],
    _current_user: Annotated[User, Depends(get_current_user)],
    enabled: bool | None = Query(None, description="Filter by enabled status"),
    severity: AlertSeverity | None = Query(None, description="Filter by severity"),
    search: str | None = Query(None, description="Search in name/description"),
    page: int = Query(1, ge=1),
    page_size: int = Query(50, ge=1, le=100),
) -> RuleListResponse:
    """List all detection rules."""
    query = select(DetectionRule)

    if enabled is not None:
        query = query.where(DetectionRule.enabled == enabled)
    if severity:
        query = query.where(DetectionRule.severity == severity)
    if search:
        search_pattern = f"%{search}%"
        query = query.where(
            (DetectionRule.name.ilike(search_pattern))
            | (DetectionRule.description.ilike(search_pattern))
        )

    # Count total
    count_query = select(func.count()).select_from(query.subquery())
    total_result = await session.execute(count_query)
    total = total_result.scalar() or 0

    # Paginate
    offset = (page - 1) * page_size
    query = query.offset(offset).limit(page_size).order_by(DetectionRule.name)
    result = await session.execute(query)
    rules = result.scalars().all()

    return RuleListResponse(
        items=[_rule_to_response(r) for r in rules],
        total=total,
    )


@router.get("/fields", response_model=list[ConditionFieldInfo])
async def get_condition_fields(
    _current_user: Annotated[User, Depends(get_current_user)],
) -> list[ConditionFieldInfo]:
    """Get available fields for rule conditions."""
    return [
        ConditionFieldInfo(
            name="event_type",
            description="Type of event",
            type="string",
            example_values=[e.value for e in EventType],
        ),
        ConditionFieldInfo(
            name="severity",
            description="Event severity level",
            type="string",
            example_values=["critical", "high", "medium", "low", "info"],
        ),
        ConditionFieldInfo(
            name="source_ip",
            description="Source IP address",
            type="string",
            example_values=["192.168.1.100", "10.0.0.0/8"],
        ),
        ConditionFieldInfo(
            name="dest_ip",
            description="Destination IP address",
            type="string",
            example_values=["8.8.8.8", "1.1.1.1"],
        ),
        ConditionFieldInfo(
            name="domain",
            description="Domain name (for DNS events)",
            type="string",
            example_values=["malware.example.com", "*.suspicious.net"],
        ),
        ConditionFieldInfo(
            name="port",
            description="Port number",
            type="integer",
            example_values=["22", "3389", "4444"],
        ),
        ConditionFieldInfo(
            name="protocol",
            description="Network protocol",
            type="string",
            example_values=["TCP", "UDP", "ICMP"],
        ),
        ConditionFieldInfo(
            name="device_type",
            description="Device type classification",
            type="string",
            example_values=["pc", "mobile", "iot", "server", "network"],
        ),
        ConditionFieldInfo(
            name="bytes_transferred",
            description="Data transfer size in bytes",
            type="integer",
            example_values=["1000000", "10000000"],
        ),
        ConditionFieldInfo(
            name="blocked",
            description="Whether the request was blocked",
            type="boolean",
            example_values=["true", "false"],
        ),
        ConditionFieldInfo(
            name="parser_type",
            description="Log parser that processed the event",
            type="string",
            example_values=["adguard", "syslog", "netflow", "endpoint"],
        ),
        ConditionFieldInfo(
            name="raw_data",
            description="Raw event data (for regex matching)",
            type="string",
        ),
    ]


@router.get("/{rule_id}", response_model=RuleResponse)
async def get_rule(
    rule_id: str,
    session: Annotated[AsyncSession, Depends(get_async_session)],
    _current_user: Annotated[User, Depends(get_current_user)],
) -> RuleResponse:
    """Get a specific detection rule."""
    result = await session.execute(select(DetectionRule).where(DetectionRule.id == rule_id))
    rule = result.scalar_one_or_none()

    if not rule:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Rule '{rule_id}' not found",
        )

    return _rule_to_response(rule)


@router.post("", response_model=RuleResponse, status_code=status.HTTP_201_CREATED)
async def create_rule(
    request: CreateRuleRequest,
    session: Annotated[AsyncSession, Depends(get_async_session)],
    _current_user: Annotated[User, Depends(require_admin)],
) -> RuleResponse:
    """Create a new detection rule (admin only)."""
    # Check for duplicate ID
    existing = await session.execute(select(DetectionRule).where(DetectionRule.id == request.id))
    if existing.scalar_one_or_none():
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=f"Rule with ID '{request.id}' already exists",
        )

    rule = DetectionRule(
        id=request.id,
        name=request.name,
        description=request.description,
        severity=request.severity,
        enabled=request.enabled,
        conditions=request.conditions.model_dump(),
        response_actions=[a.model_dump() for a in request.response_actions],
        cooldown_minutes=request.cooldown_minutes,
    )

    session.add(rule)
    await session.commit()
    await session.refresh(rule)

    return _rule_to_response(rule)


@router.patch("/{rule_id}", response_model=RuleResponse)
async def update_rule(
    rule_id: str,
    request: UpdateRuleRequest,
    session: Annotated[AsyncSession, Depends(get_async_session)],
    _current_user: Annotated[User, Depends(require_admin)],
) -> RuleResponse:
    """Update a detection rule (admin only)."""
    result = await session.execute(select(DetectionRule).where(DetectionRule.id == rule_id))
    rule = result.scalar_one_or_none()

    if not rule:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Rule '{rule_id}' not found",
        )

    if request.name is not None:
        rule.name = request.name
    if request.description is not None:
        rule.description = request.description
    if request.severity is not None:
        rule.severity = request.severity
    if request.enabled is not None:
        rule.enabled = request.enabled
    if request.conditions is not None:
        rule.conditions = request.conditions.model_dump()
    if request.response_actions is not None:
        rule.response_actions = [a.model_dump() for a in request.response_actions]
    if request.cooldown_minutes is not None:
        rule.cooldown_minutes = request.cooldown_minutes

    await session.commit()
    await session.refresh(rule)

    return _rule_to_response(rule)


@router.delete("/{rule_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_rule(
    rule_id: str,
    session: Annotated[AsyncSession, Depends(get_async_session)],
    _current_user: Annotated[User, Depends(require_admin)],
) -> None:
    """Delete a detection rule (admin only)."""
    result = await session.execute(select(DetectionRule).where(DetectionRule.id == rule_id))
    rule = result.scalar_one_or_none()

    if not rule:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Rule '{rule_id}' not found",
        )

    await session.delete(rule)
    await session.commit()


@router.post("/{rule_id}/enable", response_model=RuleResponse)
async def enable_rule(
    rule_id: str,
    session: Annotated[AsyncSession, Depends(get_async_session)],
    _current_user: Annotated[User, Depends(require_admin)],
) -> RuleResponse:
    """Enable a detection rule (admin only)."""
    result = await session.execute(select(DetectionRule).where(DetectionRule.id == rule_id))
    rule = result.scalar_one_or_none()

    if not rule:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Rule '{rule_id}' not found",
        )

    rule.enabled = True
    await session.commit()
    await session.refresh(rule)

    return _rule_to_response(rule)


@router.post("/{rule_id}/disable", response_model=RuleResponse)
async def disable_rule(
    rule_id: str,
    session: Annotated[AsyncSession, Depends(get_async_session)],
    _current_user: Annotated[User, Depends(require_admin)],
) -> RuleResponse:
    """Disable a detection rule (admin only)."""
    result = await session.execute(select(DetectionRule).where(DetectionRule.id == rule_id))
    rule = result.scalar_one_or_none()

    if not rule:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Rule '{rule_id}' not found",
        )

    rule.enabled = False
    await session.commit()
    await session.refresh(rule)

    return _rule_to_response(rule)


@router.post("/test", response_model=TestRuleResponse)
async def test_rule(
    request: TestRuleRequest,
    _current_user: Annotated[User, Depends(get_current_user)],
) -> TestRuleResponse:
    """Test rule conditions against a sample event."""
    matches, results = _evaluate_conditions(request.conditions, request.event)

    return TestRuleResponse(
        matches=matches,
        condition_results=results,
    )
