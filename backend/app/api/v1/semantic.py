"""Semantic analysis API endpoints."""

from datetime import datetime
from typing import Annotated, Any
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query, status
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.v1.auth import get_current_user, require_admin
from app.db.session import get_async_session
from app.models.log_source import LogSource
from app.models.semantic_analysis import (
    LLMProvider,
    SuggestedRuleStatus,
    SuggestedRuleType,
)
from app.models.user import User
from app.services.llm_providers.claude_provider import ClaudeLLMProvider
from app.services.pattern_service import PatternFilters, get_pattern_service
from app.services.rule_suggestion_service import (
    HistoryFilters,
    RuleFilters,
    get_rule_suggestion_service,
)
from app.services.semantic_analysis_service import (
    IrregularLogFilters,
    get_semantic_analysis_service,
)

router = APIRouter()


# --- Pydantic Models ---


class SemanticConfigResponse(BaseModel):
    """Semantic analysis config response."""

    id: str
    source_id: str
    enabled: bool
    llm_provider: str
    ollama_model: str | None
    rarity_threshold: int
    batch_size: int
    batch_interval_minutes: int
    last_run_at: str | None
    created_at: str
    updated_at: str

    model_config = {"from_attributes": True}


class UpdateConfigRequest(BaseModel):
    """Request to update semantic analysis config."""

    enabled: bool | None = None
    llm_provider: str | None = Field(None, description="'claude' or 'ollama'")
    ollama_model: str | None = Field(None, description="Model to use if provider is ollama")
    rarity_threshold: int | None = Field(None, ge=1, le=100)
    batch_size: int | None = Field(None, ge=1, le=500)
    batch_interval_minutes: int | None = Field(None, ge=1, le=1440)


class PatternResponse(BaseModel):
    """Log pattern response."""

    id: str
    source_id: str
    normalized_pattern: str
    pattern_hash: str
    first_seen: str
    last_seen: str
    occurrence_count: int
    is_ignored: bool
    created_at: str
    updated_at: str

    model_config = {"from_attributes": True}


class PatternListResponse(BaseModel):
    """List of patterns."""

    items: list[PatternResponse]
    total: int


class UpdatePatternRequest(BaseModel):
    """Request to update a pattern."""

    is_ignored: bool


class IrregularLogResponse(BaseModel):
    """Irregular log response."""

    id: str
    event_id: str
    event_timestamp: str
    source_id: str
    pattern_id: str | None
    reason: str
    llm_reviewed: bool
    llm_response: str | None
    severity_score: float | None
    reviewed_by_user: bool
    reviewed_at: str | None
    created_at: str

    model_config = {"from_attributes": True}


class IrregularLogListResponse(BaseModel):
    """List of irregular logs."""

    items: list[IrregularLogResponse]
    total: int


class AnalysisRunResponse(BaseModel):
    """Analysis run response."""

    id: str
    source_id: str
    started_at: str
    completed_at: str | None
    status: str
    events_scanned: int
    irregulars_found: int
    llm_provider: str
    llm_response_summary: str | None
    error_message: str | None
    created_at: str

    model_config = {"from_attributes": True}


class AnalysisRunListResponse(BaseModel):
    """List of analysis runs."""

    items: list[AnalysisRunResponse]


class TriggerAnalysisResponse(BaseModel):
    """Response from triggering analysis."""

    run_id: str
    status: str
    message: str


class SemanticStatsResponse(BaseModel):
    """Semantic analysis statistics."""

    total_patterns: int
    total_irregular_logs: int
    pending_review: int
    high_severity_count: int
    last_run_at: str | None
    last_run_status: str | None


class SuggestedRuleResponse(BaseModel):
    """Suggested rule response."""

    id: str
    source_id: str | None
    analysis_run_id: str
    irregular_log_id: str
    name: str
    description: str
    reason: str
    benefit: str
    rule_type: str
    rule_config: dict[str, Any]
    status: str
    enabled: bool
    rule_hash: str
    reviewed_by: str | None
    reviewed_at: str | None
    rejection_reason: str | None
    created_at: str
    updated_at: str

    model_config = {"from_attributes": True}


class SuggestedRuleListResponse(BaseModel):
    """List of suggested rules."""

    items: list[SuggestedRuleResponse]
    total: int


class ApproveRuleRequest(BaseModel):
    """Request to approve a rule."""

    enable: bool = Field(False, description="Whether to enable the rule immediately")
    config_overrides: dict[str, Any] | None = Field(
        None, description="Optional modifications to rule config"
    )


class RejectRuleRequest(BaseModel):
    """Request to reject a rule."""

    reason: str = Field(..., min_length=1, description="Reason for rejection")


class RuleHistoryResponse(BaseModel):
    """Rule history entry response."""

    id: str
    rule_hash: str
    original_rule_id: str
    status: str
    created_at: str

    model_config = {"from_attributes": True}


class RuleHistoryListResponse(BaseModel):
    """List of rule history entries."""

    items: list[RuleHistoryResponse]


class ResearchQueryResponse(BaseModel):
    """Response containing AI-generated research query."""

    query: str
    search_url: str


# --- Helper Functions ---


def _config_to_response(config) -> SemanticConfigResponse:
    """Convert config to response model."""
    return SemanticConfigResponse(
        id=str(config.id),
        source_id=config.source_id,
        enabled=config.enabled,
        llm_provider=config.llm_provider.value,
        ollama_model=config.ollama_model,
        rarity_threshold=config.rarity_threshold,
        batch_size=config.batch_size,
        batch_interval_minutes=config.batch_interval_minutes,
        last_run_at=config.last_run_at.isoformat() if config.last_run_at else None,
        created_at=config.created_at.isoformat(),
        updated_at=config.updated_at.isoformat(),
    )


def _pattern_to_response(pattern) -> PatternResponse:
    """Convert pattern to response model."""
    return PatternResponse(
        id=str(pattern.id),
        source_id=pattern.source_id,
        normalized_pattern=pattern.normalized_pattern,
        pattern_hash=pattern.pattern_hash,
        first_seen=pattern.first_seen.isoformat(),
        last_seen=pattern.last_seen.isoformat(),
        occurrence_count=pattern.occurrence_count,
        is_ignored=pattern.is_ignored,
        created_at=pattern.created_at.isoformat(),
        updated_at=pattern.updated_at.isoformat(),
    )


def _irregular_to_response(irregular) -> IrregularLogResponse:
    """Convert irregular log to response model."""
    return IrregularLogResponse(
        id=str(irregular.id),
        event_id=str(irregular.event_id),
        event_timestamp=irregular.event_timestamp.isoformat(),
        source_id=irregular.source_id,
        pattern_id=str(irregular.pattern_id) if irregular.pattern_id else None,
        reason=irregular.reason,
        llm_reviewed=irregular.llm_reviewed,
        llm_response=irregular.llm_response,
        severity_score=irregular.severity_score,
        reviewed_by_user=irregular.reviewed_by_user,
        reviewed_at=irregular.reviewed_at.isoformat() if irregular.reviewed_at else None,
        created_at=irregular.created_at.isoformat(),
    )


def _run_to_response(run) -> AnalysisRunResponse:
    """Convert analysis run to response model."""
    return AnalysisRunResponse(
        id=str(run.id),
        source_id=run.source_id,
        started_at=run.started_at.isoformat(),
        completed_at=run.completed_at.isoformat() if run.completed_at else None,
        status=run.status.value,
        events_scanned=run.events_scanned,
        irregulars_found=run.irregulars_found,
        llm_provider=run.llm_provider.value,
        llm_response_summary=run.llm_response_summary,
        error_message=run.error_message,
        created_at=run.created_at.isoformat(),
    )


def _suggested_rule_to_response(rule) -> SuggestedRuleResponse:
    """Convert suggested rule to response model."""
    return SuggestedRuleResponse(
        id=str(rule.id),
        source_id=rule.source_id,
        analysis_run_id=str(rule.analysis_run_id),
        irregular_log_id=str(rule.irregular_log_id),
        name=rule.name,
        description=rule.description,
        reason=rule.reason,
        benefit=rule.benefit,
        rule_type=rule.rule_type.value,
        rule_config=rule.rule_config,
        status=rule.status.value,
        enabled=rule.enabled,
        rule_hash=rule.rule_hash,
        reviewed_by=str(rule.reviewed_by) if rule.reviewed_by else None,
        reviewed_at=rule.reviewed_at.isoformat() if rule.reviewed_at else None,
        rejection_reason=rule.rejection_reason,
        created_at=rule.created_at.isoformat(),
        updated_at=rule.updated_at.isoformat(),
    )


def _history_to_response(history) -> RuleHistoryResponse:
    """Convert rule history to response model."""
    return RuleHistoryResponse(
        id=str(history.id),
        rule_hash=history.rule_hash,
        original_rule_id=str(history.original_rule_id),
        status=history.status.value,
        created_at=history.created_at.isoformat(),
    )


# --- Configuration Endpoints ---


@router.get("/config", response_model=list[SemanticConfigResponse])
async def list_configs(
    session: Annotated[AsyncSession, Depends(get_async_session)],
    _current_user: Annotated[User, Depends(get_current_user)],
) -> list[SemanticConfigResponse]:
    """List all semantic analysis configurations."""
    service = get_semantic_analysis_service(session)
    configs = await service.get_all_configs()
    return [_config_to_response(c) for c in configs]


@router.get("/config/{source_id}", response_model=SemanticConfigResponse)
async def get_config(
    source_id: str,
    session: Annotated[AsyncSession, Depends(get_async_session)],
    _current_user: Annotated[User, Depends(get_current_user)],
) -> SemanticConfigResponse:
    """Get semantic analysis config for a source."""
    service = get_semantic_analysis_service(session)
    config = await service.get_config(source_id)

    if not config:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"No config found for source '{source_id}'",
        )

    return _config_to_response(config)


@router.put("/config/{source_id}", response_model=SemanticConfigResponse)
async def update_config(
    source_id: str,
    request: UpdateConfigRequest,
    session: Annotated[AsyncSession, Depends(get_async_session)],
    _current_user: Annotated[User, Depends(require_admin)],
) -> SemanticConfigResponse:
    """Create or update semantic analysis config for a source (admin only)."""
    service = get_semantic_analysis_service(session)

    # Get existing or use defaults
    existing = await service.get_config(source_id)

    llm_provider = LLMProvider.CLAUDE
    if request.llm_provider:
        try:
            llm_provider = LLMProvider(request.llm_provider.lower())
        except ValueError:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Invalid llm_provider. Must be 'claude' or 'ollama'",
            )
    elif existing:
        llm_provider = existing.llm_provider

    config = await service.create_or_update_config(
        source_id=source_id,
        enabled=request.enabled if request.enabled is not None else (existing.enabled if existing else True),
        llm_provider=llm_provider,
        ollama_model=request.ollama_model or (existing.ollama_model if existing else None),
        rarity_threshold=request.rarity_threshold or (existing.rarity_threshold if existing else 3),
        batch_size=request.batch_size or (existing.batch_size if existing else 50),
        batch_interval_minutes=request.batch_interval_minutes or (existing.batch_interval_minutes if existing else 60),
    )

    return _config_to_response(config)


# --- Pattern Endpoints ---


@router.get("/patterns", response_model=PatternListResponse)
async def list_patterns(
    session: Annotated[AsyncSession, Depends(get_async_session)],
    _current_user: Annotated[User, Depends(get_current_user)],
    source_id: str | None = Query(None, description="Filter by source"),
    is_ignored: bool | None = Query(None, description="Filter by ignored status"),
    rare_only: bool = Query(False, description="Only show rare patterns"),
    rarity_threshold: int = Query(3, ge=1, description="Threshold for rarity"),
    search: str | None = Query(None, description="Search in pattern text"),
    page: int = Query(1, ge=1),
    page_size: int = Query(50, ge=1, le=100),
) -> PatternListResponse:
    """List log patterns with filters."""
    service = get_pattern_service(session)

    filters = PatternFilters(
        source_id=source_id,
        is_ignored=is_ignored,
        rare_only=rare_only,
        rarity_threshold=rarity_threshold,
        search=search,
        limit=page_size,
        offset=(page - 1) * page_size,
    )

    patterns = await service.get_patterns_for_source(filters)
    total = await service.get_pattern_count(filters)

    return PatternListResponse(
        items=[_pattern_to_response(p) for p in patterns],
        total=total,
    )


@router.get("/patterns/{source_id}", response_model=PatternListResponse)
async def list_patterns_for_source(
    source_id: str,
    session: Annotated[AsyncSession, Depends(get_async_session)],
    _current_user: Annotated[User, Depends(get_current_user)],
    is_ignored: bool | None = Query(None),
    rare_only: bool = Query(False),
    rarity_threshold: int = Query(3, ge=1),
    page: int = Query(1, ge=1),
    page_size: int = Query(50, ge=1, le=100),
) -> PatternListResponse:
    """List patterns for a specific source."""
    service = get_pattern_service(session)

    filters = PatternFilters(
        source_id=source_id,
        is_ignored=is_ignored,
        rare_only=rare_only,
        rarity_threshold=rarity_threshold,
        limit=page_size,
        offset=(page - 1) * page_size,
    )

    patterns = await service.get_patterns_for_source(filters)
    total = await service.get_pattern_count(filters)

    return PatternListResponse(
        items=[_pattern_to_response(p) for p in patterns],
        total=total,
    )


@router.patch("/patterns/{pattern_id}", response_model=PatternResponse)
async def update_pattern(
    pattern_id: UUID,
    request: UpdatePatternRequest,
    session: Annotated[AsyncSession, Depends(get_async_session)],
    _current_user: Annotated[User, Depends(require_admin)],
) -> PatternResponse:
    """Update a pattern (toggle ignore status, admin only)."""
    service = get_pattern_service(session)
    pattern = await service.mark_pattern_ignored(pattern_id, request.is_ignored)

    if not pattern:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Pattern '{pattern_id}' not found",
        )

    return _pattern_to_response(pattern)


# --- Irregular Log Endpoints ---


@router.get("/irregular", response_model=IrregularLogListResponse)
async def list_irregular_logs(
    session: Annotated[AsyncSession, Depends(get_async_session)],
    _current_user: Annotated[User, Depends(get_current_user)],
    source_id: str | None = Query(None),
    llm_reviewed: bool | None = Query(None),
    reviewed_by_user: bool | None = Query(None),
    min_severity: float | None = Query(None, ge=0, le=1),
    start_date: datetime | None = Query(None),
    end_date: datetime | None = Query(None),
    page: int = Query(1, ge=1),
    page_size: int = Query(50, ge=1, le=100),
) -> IrregularLogListResponse:
    """List irregular logs with filters."""
    service = get_semantic_analysis_service(session)

    filters = IrregularLogFilters(
        source_id=source_id,
        llm_reviewed=llm_reviewed,
        reviewed_by_user=reviewed_by_user,
        min_severity=min_severity,
        start_date=start_date,
        end_date=end_date,
        limit=page_size,
        offset=(page - 1) * page_size,
    )

    logs = await service.get_irregular_logs(filters)
    total = await service.get_irregular_log_count(filters)

    return IrregularLogListResponse(
        items=[_irregular_to_response(log) for log in logs],
        total=total,
    )


@router.get("/irregular/{irregular_id}", response_model=IrregularLogResponse)
async def get_irregular_log(
    irregular_id: UUID,
    session: Annotated[AsyncSession, Depends(get_async_session)],
    _current_user: Annotated[User, Depends(get_current_user)],
) -> IrregularLogResponse:
    """Get a single irregular log."""
    service = get_semantic_analysis_service(session)
    log = await service.get_irregular_log_by_id(irregular_id)

    if not log:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Irregular log '{irregular_id}' not found",
        )

    return _irregular_to_response(log)


@router.patch("/irregular/{irregular_id}/review", response_model=IrregularLogResponse)
async def mark_irregular_reviewed(
    irregular_id: UUID,
    session: Annotated[AsyncSession, Depends(get_async_session)],
    current_user: Annotated[User, Depends(get_current_user)],
) -> IrregularLogResponse:
    """Mark an irregular log as reviewed by user."""
    service = get_semantic_analysis_service(session)
    log = await service.mark_reviewed(irregular_id, current_user.id)

    if not log:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Irregular log '{irregular_id}' not found",
        )

    return _irregular_to_response(log)


@router.get("/irregular/{irregular_id}/research-query", response_model=ResearchQueryResponse)
async def generate_research_query(
    irregular_id: UUID,
    session: Annotated[AsyncSession, Depends(get_async_session)],
    _current_user: Annotated[User, Depends(get_current_user)],
) -> ResearchQueryResponse:
    """Generate an AI-powered Google search query for researching an irregular log issue.

    Uses the Anthropic Claude API to analyze the irregular log and generate
    a high-quality, targeted search query to help investigate the issue.
    """
    import urllib.parse

    service = get_semantic_analysis_service(session)
    log = await service.get_irregular_log_by_id(irregular_id)

    if not log:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Irregular log '{irregular_id}' not found",
        )

    # Fetch the log source to get its name and type
    source_result = await session.execute(
        select(LogSource).where(LogSource.id == log.source_id)
    )
    source = source_result.scalar_one_or_none()

    # Build context for the LLM
    context_parts = []

    # Add source/software information first - this is critical for targeted searches
    if source:
        context_parts.append(f"Software/Source: {source.name}")
        context_parts.append(f"Parser Type: {source.parser_type.value}")
        if source.description:
            context_parts.append(f"Source Description: {source.description}")
    else:
        context_parts.append(f"Source ID: {log.source_id}")

    context_parts.append(f"Detection Reason: {log.reason}")

    if log.llm_response:
        context_parts.append(f"LLM Analysis: {log.llm_response}")

    if log.severity_score is not None:
        severity_label = (
            "Critical" if log.severity_score >= 0.8 else
            "High" if log.severity_score >= 0.6 else
            "Medium" if log.severity_score >= 0.4 else
            "Low"
        )
        context_parts.append(f"Severity: {severity_label} ({log.severity_score:.0%})")

    context = "\n".join(context_parts)

    # Use Claude to generate the search query
    try:
        provider = ClaudeLLMProvider(
            max_tokens=150,
            temperature=0.2,  # Low temperature for precise output
        )

        system_prompt = """You are a cybersecurity research assistant. Your task is to generate the perfect Google search query to help a security analyst research and understand a detected security issue.

Rules:
1. Output ONLY the search query - no explanation, no quotes, no prefixes
2. The query should be 5-10 words, highly targeted and specific
3. ALWAYS include the software/source name (e.g., "AdGuard", "pfSense", "Grafana Loki", "nginx") to find relevant documentation
4. Focus on the technical aspects that would yield useful security documentation, threat intelligence, or remediation guides
5. Include relevant technical terms, protocols, attack names, or CVE patterns if applicable
6. Avoid generic terms like "security issue" or "network problem"
7. Prefer queries that would find: official documentation, security advisories, threat reports, or remediation guides

Example good queries:
- "AdGuard DNS blocking malicious domain detection"
- "pfSense firewall brute force SSH protection"
- "nginx 403 forbidden error troubleshooting"
- "Grafana Loki log anomaly detection alert\""""

        response = await provider.client.messages.create(
            model=provider._model,
            max_tokens=150,
            temperature=0.2,
            system=system_prompt,
            messages=[
                {
                    "role": "user",
                    "content": f"Generate a Google search query for this security issue:\n\n{context}",
                }
            ],
        )

        query = response.content[0].text.strip()
        # Clean up any quotes or extra formatting
        query = query.strip('"\'')

        search_url = f"https://www.google.com/search?q={urllib.parse.quote(query)}"

        return ResearchQueryResponse(
            query=query,
            search_url=search_url,
        )

    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail=f"Failed to generate research query: {str(e)}",
        )


# --- Analysis Run Endpoints ---


@router.get("/runs", response_model=AnalysisRunListResponse)
async def list_runs(
    session: Annotated[AsyncSession, Depends(get_async_session)],
    _current_user: Annotated[User, Depends(get_current_user)],
    source_id: str | None = Query(None),
    limit: int = Query(50, ge=1, le=100),
) -> AnalysisRunListResponse:
    """List analysis runs."""
    service = get_semantic_analysis_service(session)
    runs = await service.get_analysis_runs(source_id, limit)

    return AnalysisRunListResponse(
        items=[_run_to_response(r) for r in runs],
    )


@router.get("/runs/{source_id}", response_model=AnalysisRunListResponse)
async def list_runs_for_source(
    source_id: str,
    session: Annotated[AsyncSession, Depends(get_async_session)],
    _current_user: Annotated[User, Depends(get_current_user)],
    limit: int = Query(50, ge=1, le=100),
) -> AnalysisRunListResponse:
    """List analysis runs for a specific source."""
    service = get_semantic_analysis_service(session)
    runs = await service.get_analysis_runs(source_id, limit)

    return AnalysisRunListResponse(
        items=[_run_to_response(r) for r in runs],
    )


@router.post("/runs/{source_id}/trigger", response_model=TriggerAnalysisResponse)
async def trigger_analysis(
    source_id: str,
    session: Annotated[AsyncSession, Depends(get_async_session)],
    _current_user: Annotated[User, Depends(require_admin)],
    force: bool = Query(False, description="Force run even if interval hasn't passed"),
) -> TriggerAnalysisResponse:
    """Trigger a manual analysis run for a source (admin only)."""
    service = get_semantic_analysis_service(session)

    try:
        run = await service.run_analysis(source_id, force=force)

        return TriggerAnalysisResponse(
            run_id=str(run.id),
            status=run.status.value,
            message=f"Analysis {'completed' if run.status.value == 'completed' else 'started'}: {run.events_scanned} events scanned, {run.irregulars_found} irregulars found",
        )

    except ValueError as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(e),
        )


# --- Statistics Endpoints ---


@router.get("/stats", response_model=SemanticStatsResponse)
async def get_stats(
    session: Annotated[AsyncSession, Depends(get_async_session)],
    _current_user: Annotated[User, Depends(get_current_user)],
) -> SemanticStatsResponse:
    """Get overall semantic analysis statistics."""
    service = get_semantic_analysis_service(session)
    stats = await service.get_stats()

    return SemanticStatsResponse(
        total_patterns=stats.total_patterns,
        total_irregular_logs=stats.total_irregular_logs,
        pending_review=stats.pending_review,
        high_severity_count=stats.high_severity_count,
        last_run_at=stats.last_run_at.isoformat() if stats.last_run_at else None,
        last_run_status=stats.last_run_status,
    )


@router.get("/stats/{source_id}", response_model=SemanticStatsResponse)
async def get_stats_for_source(
    source_id: str,
    session: Annotated[AsyncSession, Depends(get_async_session)],
    _current_user: Annotated[User, Depends(get_current_user)],
) -> SemanticStatsResponse:
    """Get semantic analysis statistics for a specific source."""
    service = get_semantic_analysis_service(session)
    stats = await service.get_stats(source_id)

    return SemanticStatsResponse(
        total_patterns=stats.total_patterns,
        total_irregular_logs=stats.total_irregular_logs,
        pending_review=stats.pending_review,
        high_severity_count=stats.high_severity_count,
        last_run_at=stats.last_run_at.isoformat() if stats.last_run_at else None,
        last_run_status=stats.last_run_status,
    )


# --- Suggested Rules Endpoints ---


@router.get("/rules", response_model=SuggestedRuleListResponse)
async def list_suggested_rules(
    session: Annotated[AsyncSession, Depends(get_async_session)],
    _current_user: Annotated[User, Depends(get_current_user)],
    source_id: str | None = Query(None),
    status_filter: str | None = Query(None, alias="status"),
    rule_type: str | None = Query(None),
    search: str | None = Query(None),
    page: int = Query(1, ge=1),
    page_size: int = Query(50, ge=1, le=100),
) -> SuggestedRuleListResponse:
    """List suggested rules with filters."""
    service = get_rule_suggestion_service(session)

    # Parse status filter
    status_enum = None
    if status_filter:
        try:
            status_enum = SuggestedRuleStatus(status_filter.lower())
        except ValueError:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Invalid status. Must be one of: pending, approved, rejected, implemented",
            )

    # Parse rule type filter
    rule_type_enum = None
    if rule_type:
        try:
            rule_type_enum = SuggestedRuleType(rule_type.lower())
        except ValueError:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Invalid rule_type. Must be one of: pattern_match, threshold, sequence",
            )

    filters = RuleFilters(
        source_id=source_id,
        status=status_enum,
        rule_type=rule_type_enum,
        search=search,
        limit=page_size,
        offset=(page - 1) * page_size,
    )

    rules = await service.get_rules(filters)
    total = await service.get_rule_count(filters)

    return SuggestedRuleListResponse(
        items=[_suggested_rule_to_response(r) for r in rules],
        total=total,
    )


@router.get("/rules/pending", response_model=SuggestedRuleListResponse)
async def list_pending_rules(
    session: Annotated[AsyncSession, Depends(get_async_session)],
    _current_user: Annotated[User, Depends(get_current_user)],
    page: int = Query(1, ge=1),
    page_size: int = Query(50, ge=1, le=100),
) -> SuggestedRuleListResponse:
    """List pending suggested rules."""
    service = get_rule_suggestion_service(session)

    filters = RuleFilters(
        status=SuggestedRuleStatus.PENDING,
        limit=page_size,
        offset=(page - 1) * page_size,
    )

    rules = await service.get_rules(filters)
    total = await service.get_rule_count(filters)

    return SuggestedRuleListResponse(
        items=[_suggested_rule_to_response(r) for r in rules],
        total=total,
    )


@router.get("/rules/history", response_model=RuleHistoryListResponse)
async def get_rule_history(
    session: Annotated[AsyncSession, Depends(get_async_session)],
    _current_user: Annotated[User, Depends(get_current_user)],
    status_filter: str | None = Query(None, alias="status"),
    page: int = Query(1, ge=1),
    page_size: int = Query(50, ge=1, le=100),
) -> RuleHistoryListResponse:
    """Get history of suggested rules."""
    service = get_rule_suggestion_service(session)

    status_enum = None
    if status_filter:
        try:
            status_enum = SuggestedRuleStatus(status_filter.lower())
        except ValueError:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Invalid status filter",
            )

    filters = HistoryFilters(
        status=status_enum,
        limit=page_size,
        offset=(page - 1) * page_size,
    )

    history = await service.get_history(filters)

    return RuleHistoryListResponse(
        items=[_history_to_response(h) for h in history],
    )


@router.get("/rules/{rule_id}", response_model=SuggestedRuleResponse)
async def get_suggested_rule(
    rule_id: UUID,
    session: Annotated[AsyncSession, Depends(get_async_session)],
    _current_user: Annotated[User, Depends(get_current_user)],
) -> SuggestedRuleResponse:
    """Get a specific suggested rule."""
    service = get_rule_suggestion_service(session)
    rule = await service.get_rule_by_id(rule_id)

    if not rule:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Suggested rule '{rule_id}' not found",
        )

    return _suggested_rule_to_response(rule)


@router.post("/rules/{rule_id}/approve", response_model=SuggestedRuleResponse)
async def approve_rule(
    rule_id: UUID,
    request: ApproveRuleRequest,
    session: Annotated[AsyncSession, Depends(get_async_session)],
    current_user: Annotated[User, Depends(require_admin)],
) -> SuggestedRuleResponse:
    """Approve a suggested rule (admin only)."""
    service = get_rule_suggestion_service(session)

    try:
        rule = await service.approve_rule(
            rule_id=rule_id,
            user_id=current_user.id,
            enable=request.enable,
            config_overrides=request.config_overrides,
        )

        if not rule:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"Suggested rule '{rule_id}' not found",
            )

        return _suggested_rule_to_response(rule)

    except ValueError as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(e),
        )


@router.post("/rules/{rule_id}/reject", response_model=SuggestedRuleResponse)
async def reject_rule(
    rule_id: UUID,
    request: RejectRuleRequest,
    session: Annotated[AsyncSession, Depends(get_async_session)],
    current_user: Annotated[User, Depends(require_admin)],
) -> SuggestedRuleResponse:
    """Reject a suggested rule (admin only)."""
    service = get_rule_suggestion_service(session)

    try:
        rule = await service.reject_rule(
            rule_id=rule_id,
            user_id=current_user.id,
            reason=request.reason,
        )

        if not rule:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"Suggested rule '{rule_id}' not found",
            )

        return _suggested_rule_to_response(rule)

    except ValueError as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(e),
        )
