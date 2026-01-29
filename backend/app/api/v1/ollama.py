"""API endpoints for Ollama LLM monitoring."""

from typing import Any

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, Field

from app.api.v1.auth import get_current_user, require_admin
from app.models.user import User
from app.services.ollama_monitoring_service import get_ollama_service

router = APIRouter(prefix="/ollama", tags=["ollama"])


class OllamaStatusResponse(BaseModel):
    """Ollama monitoring status response."""

    enabled: bool
    running: bool
    connected: bool
    connection_message: str
    url: str | None = None
    detection_enabled: bool
    prompt_analysis_enabled: bool
    poll_interval_seconds: int
    recent_threats_count: int
    recent_threats: list[dict[str, Any]] = Field(default_factory=list)


class AnalyzePromptRequest(BaseModel):
    """Request to analyze a prompt for threats."""

    prompt: str = Field(..., description="The prompt to analyze")
    model: str = Field(default="unknown", description="The model name")
    client_ip: str | None = Field(default=None, description="Client IP if known")
    use_llm_analysis: bool = Field(default=True, description="Use Claude for deeper analysis")


class AnalyzePromptResponse(BaseModel):
    """Response from prompt analysis."""

    is_threat: bool
    threat_type: str | None = None
    severity: str | None = None
    risk_score: int = 0
    matched_patterns: list[str] = Field(default_factory=list)
    analysis: dict[str, Any] | None = None
    message: str


class ProcessRequestInput(BaseModel):
    """Input for processing an Ollama request."""

    prompt: str | None = Field(default=None, description="Prompt for /api/generate")
    messages: list[dict[str, str]] | None = Field(
        default=None, description="Messages for /api/chat"
    )
    model: str = Field(default="unknown", description="Model name")
    client_ip: str | None = Field(default=None, description="Client IP")


class ProcessRequestResponse(BaseModel):
    """Response from processing an Ollama request."""

    processed: bool
    threat: dict[str, Any] | None = None
    action: str | None = None


class ThreatListResponse(BaseModel):
    """List of detected threats."""

    threats: list[dict[str, Any]]
    total: int


@router.get("/status", response_model=OllamaStatusResponse)
async def get_ollama_status(
    current_user: User = Depends(get_current_user),
) -> OllamaStatusResponse:
    """Get Ollama monitoring status.

    Returns current status of Ollama monitoring including:
    - Connection status
    - Detection settings
    - Recent threats
    """
    service = get_ollama_service()
    status = await service.get_status()
    return OllamaStatusResponse(**status)


@router.post("/test-connection")
async def test_ollama_connection(
    current_user: User = Depends(require_admin),
) -> dict[str, Any]:
    """Test connection to Ollama instance.

    Admin only. Tests connectivity and returns model information.
    """
    service = get_ollama_service()

    if not service.is_enabled:
        return {
            "success": False,
            "message": "Ollama monitoring is not enabled. Set OLLAMA_ENABLED=true in configuration.",
        }

    success, message = await service.test_connection()
    return {
        "success": success,
        "message": message,
    }


@router.post("/check")
async def check_ollama(
    current_user: User = Depends(get_current_user),
) -> dict[str, Any]:
    """Manually trigger Ollama check.

    Performs an immediate check of Ollama status and returns results.
    """
    service = get_ollama_service()

    if not service.is_enabled:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Ollama monitoring is not enabled",
        )

    result = await service.check_ollama()
    return {
        "success": result.success,
        "message": result.message,
        "threats_detected": result.threats_detected,
        "events_processed": result.events_processed,
        "models_active": result.models_active,
        "details": result.details,
    }


@router.post("/analyze-prompt", response_model=AnalyzePromptResponse)
async def analyze_prompt(
    request: AnalyzePromptRequest,
    current_user: User = Depends(get_current_user),
) -> AnalyzePromptResponse:
    """Analyze a prompt for potential security threats.

    Uses pattern matching and optionally Claude for analysis.
    Useful for testing detection or analyzing suspicious prompts.
    """
    service = get_ollama_service()

    threat = await service.analyze_prompt(
        prompt=request.prompt,
        model=request.model,
        client_ip=request.client_ip,
        use_llm_analysis=request.use_llm_analysis,
    )

    if threat:
        return AnalyzePromptResponse(
            is_threat=True,
            threat_type=threat.threat_type,
            severity=threat.severity,
            risk_score=threat.risk_score,
            matched_patterns=threat.matched_patterns,
            analysis=threat.analysis,
            message=f"Threat detected: {threat.threat_type}",
        )

    return AnalyzePromptResponse(
        is_threat=False,
        risk_score=0,
        matched_patterns=[],
        message="No threats detected",
    )


@router.post("/process-request", response_model=ProcessRequestResponse)
async def process_ollama_request(
    request: ProcessRequestInput,
    current_user: User = Depends(get_current_user),
) -> ProcessRequestResponse:
    """Process an intercepted Ollama request.

    This endpoint can be used by a proxy/webhook to send Ollama
    requests for threat analysis before they reach Ollama.

    Example use case: nginx/caddy proxy intercepts /api/generate
    and sends to this endpoint first for screening.
    """
    service = get_ollama_service()

    result = await service.process_request(
        request_data={
            "prompt": request.prompt,
            "messages": request.messages,
            "model": request.model,
            "client_ip": request.client_ip,
        }
    )

    return ProcessRequestResponse(**result)


@router.get("/threats", response_model=ThreatListResponse)
async def get_recent_threats(
    limit: int = 50,
    current_user: User = Depends(get_current_user),
) -> ThreatListResponse:
    """Get recent detected threats.

    Returns a list of recently detected LLM security threats.
    """
    service = get_ollama_service()
    threats = service.get_recent_threats(limit=limit)

    return ThreatListResponse(
        threats=threats,
        total=len(threats),
    )


@router.post("/start")
async def start_monitoring(
    current_user: User = Depends(require_admin),
) -> dict[str, str]:
    """Start Ollama monitoring.

    Admin only. Starts the background polling loop.
    """
    service = get_ollama_service()

    if not service.is_enabled:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Ollama monitoring is not enabled in configuration",
        )

    if service.is_running:
        return {"message": "Monitoring is already running"}

    await service.start()
    return {"message": "Ollama monitoring started"}


@router.post("/stop")
async def stop_monitoring(
    current_user: User = Depends(require_admin),
) -> dict[str, str]:
    """Stop Ollama monitoring.

    Admin only. Stops the background polling loop.
    """
    service = get_ollama_service()

    if not service.is_running:
        return {"message": "Monitoring is not running"}

    await service.stop()
    return {"message": "Ollama monitoring stopped"}
