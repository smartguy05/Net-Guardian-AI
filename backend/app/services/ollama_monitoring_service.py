"""Ollama monitoring service for detecting LLM-based threats.

This service monitors local Ollama instances to detect:
- Prompt injection attacks
- Jailbreak attempts
- Data exfiltration via LLM
- Unusual usage patterns
"""

import asyncio
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional
from uuid import UUID, uuid4

import httpx
import structlog

from app.config import settings
from app.models.raw_event import EventSeverity, EventType
from app.parsers.ollama_parser import calculate_risk_score

logger = structlog.get_logger()


class OllamaMonitoringResult:
    """Result from Ollama monitoring check."""

    def __init__(
        self,
        success: bool,
        message: str,
        threats_detected: int = 0,
        events_processed: int = 0,
        models_active: int = 0,
        details: Optional[Dict[str, Any]] = None,
    ):
        self.success = success
        self.message = message
        self.threats_detected = threats_detected
        self.events_processed = events_processed
        self.models_active = models_active
        self.details = details or {}


class ThreatDetection:
    """Represents a detected LLM security threat."""

    def __init__(
        self,
        threat_type: str,
        severity: str,
        risk_score: int,
        prompt_snippet: str,
        model: str,
        matched_patterns: List[str],
        timestamp: datetime,
        client_ip: Optional[str] = None,
        analysis: Optional[Dict[str, Any]] = None,
    ):
        self.id = uuid4()
        self.threat_type = threat_type
        self.severity = severity
        self.risk_score = risk_score
        self.prompt_snippet = prompt_snippet[:500]  # Truncate for storage
        self.model = model
        self.matched_patterns = matched_patterns
        self.timestamp = timestamp
        self.client_ip = client_ip
        self.analysis = analysis

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": str(self.id),
            "threat_type": self.threat_type,
            "severity": self.severity,
            "risk_score": self.risk_score,
            "prompt_snippet": self.prompt_snippet,
            "model": self.model,
            "matched_patterns": self.matched_patterns,
            "timestamp": self.timestamp.isoformat(),
            "client_ip": self.client_ip,
            "analysis": self.analysis,
        }


class OllamaMonitoringService:
    """Service for monitoring Ollama LLM instances for security threats.

    Features:
    - Polls Ollama API for active models and requests
    - Detects prompt injection patterns
    - Detects jailbreak attempts
    - Optionally uses Claude for deeper analysis
    - Creates alerts for detected threats
    """

    def __init__(self):
        self._client: Optional[httpx.AsyncClient] = None
        self._running = False
        self._poll_task: Optional[asyncio.Task] = None
        self._recent_threats: List[ThreatDetection] = []
        self._max_threats_cache = 100
        self._llm_service = None

    @property
    def client(self) -> httpx.AsyncClient:
        """Get or create HTTP client."""
        if self._client is None:
            self._client = httpx.AsyncClient(
                base_url=settings.ollama_url,
                timeout=30.0,
                verify=settings.ollama_verify_ssl,
            )
        return self._client

    @property
    def is_enabled(self) -> bool:
        """Check if Ollama monitoring is enabled."""
        return settings.ollama_enabled

    @property
    def is_running(self) -> bool:
        """Check if monitoring is running."""
        return self._running

    async def start(self) -> None:
        """Start the monitoring service."""
        if not self.is_enabled:
            logger.info("ollama_monitoring_disabled")
            return

        if self._running:
            logger.warning("ollama_monitoring_already_running")
            return

        self._running = True
        self._poll_task = asyncio.create_task(self._poll_loop())
        logger.info("ollama_monitoring_started", url=settings.ollama_url)

    async def stop(self) -> None:
        """Stop the monitoring service."""
        self._running = False

        if self._poll_task:
            self._poll_task.cancel()
            try:
                await self._poll_task
            except asyncio.CancelledError:
                pass

        if self._client:
            await self._client.aclose()
            self._client = None

        logger.info("ollama_monitoring_stopped")

    async def _poll_loop(self) -> None:
        """Main polling loop."""
        while self._running:
            try:
                await self.check_ollama()
            except Exception as e:
                logger.error("ollama_poll_error", error=str(e))

            await asyncio.sleep(settings.ollama_poll_interval_seconds)

    async def test_connection(self) -> tuple[bool, str]:
        """Test connection to Ollama API.

        Returns:
            Tuple of (success, message)
        """
        try:
            response = await self.client.get("/api/tags")
            if response.status_code == 200:
                data = response.json()
                model_count = len(data.get("models", []))
                return True, f"Connected to Ollama. {model_count} models available."
            return False, f"Unexpected status: {response.status_code}"
        except httpx.ConnectError:
            return False, f"Cannot connect to Ollama at {settings.ollama_url}"
        except Exception as e:
            return False, f"Connection error: {str(e)}"

    async def check_ollama(self) -> OllamaMonitoringResult:
        """Check Ollama status and detect threats.

        Returns:
            Monitoring result with threat counts and details.
        """
        if not self.is_enabled:
            return OllamaMonitoringResult(
                success=False,
                message="Ollama monitoring is disabled",
            )

        try:
            # Get running models
            models_response = await self.client.get("/api/ps")
            models_data = models_response.json() if models_response.status_code == 200 else {}
            running_models = models_data.get("models", [])

            # Get available models
            tags_response = await self.client.get("/api/tags")
            tags_data = tags_response.json() if tags_response.status_code == 200 else {}
            available_models = tags_data.get("models", [])

            threats_detected = 0
            events_processed = len(running_models)

            # Check each running model for suspicious activity
            for model_info in running_models:
                model_name = model_info.get("name", "unknown")

                # Log model activity
                logger.debug(
                    "ollama_model_active",
                    model=model_name,
                    size=model_info.get("size"),
                    digest=model_info.get("digest"),
                )

            return OllamaMonitoringResult(
                success=True,
                message=f"Ollama check complete. {len(running_models)} running, {len(available_models)} available.",
                threats_detected=threats_detected,
                events_processed=events_processed,
                models_active=len(running_models),
                details={
                    "running_models": [m.get("name") for m in running_models],
                    "available_models": [m.get("name") for m in available_models[:10]],
                },
            )

        except httpx.ConnectError:
            return OllamaMonitoringResult(
                success=False,
                message=f"Cannot connect to Ollama at {settings.ollama_url}",
            )
        except Exception as e:
            logger.error("ollama_check_error", error=str(e))
            return OllamaMonitoringResult(
                success=False,
                message=f"Error checking Ollama: {str(e)}",
            )

    async def analyze_prompt(
        self,
        prompt: str,
        model: str = "unknown",
        client_ip: Optional[str] = None,
        use_llm_analysis: bool = True,
    ) -> ThreatDetection | None:
        """Analyze a prompt for potential threats.

        Args:
            prompt: The prompt to analyze.
            model: The model being used.
            client_ip: Client IP if known.
            use_llm_analysis: Whether to use Claude for deeper analysis.

        Returns:
            ThreatDetection if threat found, None otherwise.
        """
        if not settings.ollama_detection_enabled:
            return None

        # Pattern-based detection
        risk_score, matched_patterns = calculate_risk_score(prompt)

        if risk_score < 30:
            return None  # Below threshold

        # Determine threat type and severity
        threat_type = self._determine_threat_type(matched_patterns)
        severity = self._determine_severity(risk_score)

        # Optional LLM analysis
        analysis = None
        if use_llm_analysis and settings.ollama_prompt_analysis_enabled:
            analysis = await self._llm_analyze_prompt(prompt, matched_patterns)

        threat = ThreatDetection(
            threat_type=threat_type,
            severity=severity,
            risk_score=risk_score,
            prompt_snippet=prompt,
            model=model,
            matched_patterns=matched_patterns,
            timestamp=datetime.now(timezone.utc),
            client_ip=client_ip,
            analysis=analysis,
        )

        # Cache the threat
        self._recent_threats.append(threat)
        if len(self._recent_threats) > self._max_threats_cache:
            self._recent_threats = self._recent_threats[-self._max_threats_cache:]

        logger.warning(
            "llm_threat_detected",
            threat_type=threat_type,
            severity=severity,
            risk_score=risk_score,
            model=model,
            patterns=matched_patterns[:5],
        )

        return threat

    def _determine_threat_type(self, patterns: List[str]) -> str:
        """Determine threat type from matched patterns."""
        for pattern in patterns:
            if pattern.startswith("injection:"):
                return "prompt_injection"
            elif pattern.startswith("jailbreak:"):
                return "jailbreak_attempt"
            elif pattern.startswith("exfiltration:"):
                return "data_exfiltration"

        if "suspicious_length" in patterns:
            return "suspicious_input"
        if "special_chars_abuse" in patterns:
            return "encoding_attack"

        return "unknown_threat"

    def _determine_severity(self, risk_score: int) -> str:
        """Determine severity from risk score."""
        if risk_score >= 70:
            return "critical"
        elif risk_score >= 50:
            return "high"
        elif risk_score >= 30:
            return "medium"
        return "low"

    async def _llm_analyze_prompt(
        self,
        prompt: str,
        matched_patterns: List[str],
    ) -> Optional[Dict[str, Any]]:
        """Use Claude to analyze a potentially malicious prompt.

        Args:
            prompt: The suspicious prompt.
            matched_patterns: Patterns that triggered detection.

        Returns:
            Analysis results or None if LLM unavailable.
        """
        # Lazy import to avoid circular imports
        if self._llm_service is None:
            try:
                from app.services.llm_service import get_llm_service
                self._llm_service = get_llm_service()
            except ImportError:
                return None

        if not self._llm_service.is_enabled:
            return None

        try:
            analysis_prompt = f"""Analyze this potentially malicious LLM prompt for security threats.

## Suspicious Prompt
```
{prompt[:2000]}
```

## Detected Patterns
{', '.join(matched_patterns)}

## Analysis Required
1. Is this a genuine security threat or false positive?
2. What type of attack is being attempted?
3. What is the potential impact?
4. Recommended action (block, alert, allow)?

Respond in JSON:
```json
{{
    "is_threat": true/false,
    "confidence": 0-100,
    "attack_type": "<type>",
    "technique": "<specific technique>",
    "potential_impact": "<what could happen>",
    "recommendation": "block|alert|allow",
    "reasoning": "<why>"
}}
```"""

            response = await self._llm_service.client.messages.create(
                model=settings.llm_model_fast,
                max_tokens=1024,
                temperature=0.1,
                messages=[{"role": "user", "content": analysis_prompt}],
            )

            # Parse response
            response_text = response.content[0].text
            return self._parse_llm_analysis(response_text)

        except Exception as e:
            logger.error("llm_prompt_analysis_error", error=str(e))
            return None

    def _parse_llm_analysis(self, response_text: str) -> Optional[Dict[str, Any]]:
        """Parse LLM analysis response."""
        import json

        try:
            if "```json" in response_text:
                json_start = response_text.find("```json") + 7
                json_end = response_text.find("```", json_start)
                json_str = response_text[json_start:json_end].strip()
                return json.loads(json_str)
            elif "{" in response_text:
                json_start = response_text.find("{")
                json_end = response_text.rfind("}") + 1
                return json.loads(response_text[json_start:json_end])
        except json.JSONDecodeError:
            pass

        return {"raw_analysis": response_text[:500]}

    async def get_status(self) -> Dict[str, Any]:
        """Get current monitoring status.

        Returns:
            Status dictionary with connection info and threat stats.
        """
        connected, message = await self.test_connection()

        return {
            "enabled": self.is_enabled,
            "running": self.is_running,
            "connected": connected,
            "connection_message": message,
            "url": settings.ollama_url if self.is_enabled else None,
            "detection_enabled": settings.ollama_detection_enabled,
            "prompt_analysis_enabled": settings.ollama_prompt_analysis_enabled,
            "poll_interval_seconds": settings.ollama_poll_interval_seconds,
            "recent_threats_count": len(self._recent_threats),
            "recent_threats": [t.to_dict() for t in self._recent_threats[-10:]],
        }

    def get_recent_threats(self, limit: int = 50) -> List[Dict[str, Any]]:
        """Get recent detected threats.

        Args:
            limit: Maximum number of threats to return.

        Returns:
            List of threat dictionaries.
        """
        return [t.to_dict() for t in self._recent_threats[-limit:]]

    async def process_request(
        self,
        request_data: Dict[str, Any],
        source: str = "api",
    ) -> Dict[str, Any]:
        """Process an Ollama request for threat detection.

        This can be called by a webhook/proxy intercepting Ollama requests.

        Args:
            request_data: The request data (prompt, model, etc.)
            source: Source of the request.

        Returns:
            Processing result with threat info if found.
        """
        prompt = request_data.get("prompt", "")
        messages = request_data.get("messages", [])
        model = request_data.get("model", "unknown")
        client_ip = request_data.get("client_ip")

        # Extract content from chat messages
        if messages and not prompt:
            prompt = " ".join(
                m.get("content", "") for m in messages if m.get("role") == "user"
            )

        if not prompt:
            return {"processed": True, "threat": None}

        threat = await self.analyze_prompt(
            prompt=prompt,
            model=model,
            client_ip=client_ip,
        )

        if threat:
            return {
                "processed": True,
                "threat": threat.to_dict(),
                "action": "alert" if settings.ollama_alert_on_injection else "log",
            }

        return {"processed": True, "threat": None}


# Global service instance
_ollama_service: Optional[OllamaMonitoringService] = None


def get_ollama_service() -> OllamaMonitoringService:
    """Get the global Ollama monitoring service instance."""
    global _ollama_service
    if _ollama_service is None:
        _ollama_service = OllamaMonitoringService()
    return _ollama_service
