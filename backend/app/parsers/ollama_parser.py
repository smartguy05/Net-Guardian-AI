"""Ollama LLM server log parser for detecting LLM-based threats."""

import re
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

import structlog

from app.models.raw_event import EventSeverity, EventType
from app.parsers.base import BaseParser, ParseResult
from app.parsers.registry import register_parser

logger = structlog.get_logger()


# Patterns for detecting prompt injection attacks
INJECTION_PATTERNS = [
    # Ignore previous instructions
    r"ignore\s+(all\s+)?(previous|prior|above)\s+(instructions?|prompts?|rules?)",
    r"disregard\s+(all\s+)?(previous|prior|above)\s+(instructions?|prompts?)",
    r"forget\s+(all\s+)?(previous|prior|above|your)\s+(instructions?|prompts?|rules?)",
    # Role manipulation
    r"you\s+are\s+now\s+(DAN|jailbroken|unrestricted|evil)",
    r"pretend\s+(you\s+are|to\s+be)\s+(a|an)\s+(hacker|malicious|evil)",
    r"act\s+as\s+(if|though)\s+you\s+(have\s+no|don't\s+have)\s+(restrictions?|rules?)",
    # System prompt extraction
    r"(reveal|show|tell|output|print)\s+(me\s+)?(your|the)\s+(system\s+)?prompt",
    r"what\s+(is|are)\s+your\s+(system\s+)?instructions?",
    r"(display|output)\s+your\s+(initial|original|system)\s+(prompt|instructions?)",
    # Delimiter injection
    r"```\s*(system|assistant|user)\s*```",
    r"\[SYSTEM\]|\[INST\]|\[/INST\]",
    r"<\|im_start\|>|<\|im_end\|>",
    # Unicode/encoding attacks
    r"\\u[0-9a-fA-F]{4}.*ignore",
    # Command injection attempts
    r"(exec|eval|system|subprocess|os\.)\s*\(",
    r"import\s+(os|subprocess|sys|eval)",
]

# Patterns for detecting jailbreak attempts
JAILBREAK_PATTERNS = [
    r"DAN\s+(mode|prompt|jailbreak)",
    r"developer\s+mode\s+(enabled|activated|on)",
    r"(bypass|circumvent|override)\s+(safety|content|ethical)\s+(filters?|restrictions?)",
    r"hypothetically\s+speaking",
    r"in\s+a\s+fictional\s+(scenario|world|story)",
    r"for\s+(educational|research|academic)\s+purposes?\s+only",
    r"this\s+is\s+just\s+a\s+(test|experiment|game)",
]

# Patterns for sensitive data exfiltration
EXFILTRATION_PATTERNS = [
    r"(password|secret|api[_\s]?key|token|credential)s?\s*(are|is|:)",
    r"(send|transmit|post|upload)\s+(to|this\s+to)\s+(http|https|ftp)",
    r"base64\s+(encode|decode)",
    r"curl\s+.*(-d|--data)",
]


def calculate_risk_score(prompt: str) -> tuple[int, List[str]]:
    """Calculate risk score based on detected patterns.

    Returns:
        Tuple of (risk_score, list of matched patterns)
    """
    matched_patterns = []
    score = 0

    prompt_lower = prompt.lower()

    # Check injection patterns (high risk)
    for pattern in INJECTION_PATTERNS:
        if re.search(pattern, prompt_lower, re.IGNORECASE):
            score += 30
            matched_patterns.append(f"injection:{pattern[:30]}...")

    # Check jailbreak patterns (high risk)
    for pattern in JAILBREAK_PATTERNS:
        if re.search(pattern, prompt_lower, re.IGNORECASE):
            score += 25
            matched_patterns.append(f"jailbreak:{pattern[:30]}...")

    # Check exfiltration patterns (medium risk)
    for pattern in EXFILTRATION_PATTERNS:
        if re.search(pattern, prompt_lower, re.IGNORECASE):
            score += 20
            matched_patterns.append(f"exfiltration:{pattern[:30]}...")

    # Suspicious length (very long prompts)
    if len(prompt) > 10000:
        score += 10
        matched_patterns.append("suspicious_length")

    # Multiple special characters (encoding attacks)
    special_chars = len(re.findall(r'[\\<>\[\]{}|]', prompt))
    if special_chars > 20:
        score += 15
        matched_patterns.append("special_chars_abuse")

    return min(score, 100), matched_patterns


@register_parser("ollama")
class OllamaParser(BaseParser):
    """Parser for Ollama LLM server logs and API responses.

    This parser handles:
    - Model generation requests/responses
    - Chat completion requests
    - Running models list
    - Detects potential prompt injection and jailbreak attempts
    """

    def __init__(self, config: Dict[str, Any] | None = None):
        """Initialize the Ollama parser.

        Config options:
            enable_threat_detection: bool - Enable pattern-based threat detection
            risk_threshold: int - Minimum risk score to flag as threat (default: 30)
        """
        super().__init__(config)
        self.enable_threat_detection = self.config.get("enable_threat_detection", True)
        self.risk_threshold = self.config.get("risk_threshold", 30)

    def parse(self, raw_data: Any) -> List[ParseResult]:
        """Parse Ollama API response data.

        Handles various Ollama API responses:
        - /api/generate responses
        - /api/chat responses
        - /api/ps (running models) responses
        - /api/tags (model list) responses
        """
        if not raw_data:
            return []

        results = []

        # Handle list of events
        if isinstance(raw_data, list):
            for item in raw_data:
                parsed = self._parse_single_event(item)
                if parsed:
                    results.append(parsed)
        else:
            parsed = self._parse_single_event(raw_data)
            if parsed:
                results.append(parsed)

        return results

    def _parse_single_event(self, data: Dict[str, Any]) -> Optional[ParseResult]:
        """Parse a single Ollama event."""
        if not isinstance(data, dict):
            return None

        # Determine event subtype
        event_subtype = data.get("event_type", "unknown")

        if event_subtype == "generate" or "prompt" in data:
            return self._parse_generate_event(data)
        elif event_subtype == "chat" or "messages" in data:
            return self._parse_chat_event(data)
        elif event_subtype == "model_status" or "models" in data:
            return self._parse_model_status(data)
        else:
            return self._parse_generic_event(data)

    def _parse_generate_event(self, data: Dict[str, Any]) -> ParseResult:
        """Parse a generate API event."""
        prompt = data.get("prompt", "")
        model = data.get("model", "unknown")
        response = data.get("response", "")

        # Calculate threat risk
        risk_score, matched_patterns = calculate_risk_score(prompt)
        is_threat = self.enable_threat_detection and risk_score >= self.risk_threshold

        # Determine severity
        if is_threat:
            if risk_score >= 70:
                severity = EventSeverity.CRITICAL
            elif risk_score >= 50:
                severity = EventSeverity.ERROR
            else:
                severity = EventSeverity.WARNING
        else:
            severity = EventSeverity.INFO

        # Build action based on threat detection
        action = "threat_detected" if is_threat else "generate"

        timestamp = data.get("timestamp")
        if timestamp:
            if isinstance(timestamp, str):
                try:
                    timestamp = datetime.fromisoformat(timestamp.replace("Z", "+00:00"))
                except ValueError:
                    timestamp = datetime.now(timezone.utc)
            elif isinstance(timestamp, (int, float)):
                timestamp = datetime.fromtimestamp(timestamp, tz=timezone.utc)
        else:
            timestamp = datetime.now(timezone.utc)

        return ParseResult(
            timestamp=timestamp,
            event_type=EventType.LLM,
            severity=severity,
            raw_message=prompt[:1000] if prompt else str(data)[:1000],
            client_ip=data.get("client_ip"),
            action=action,
            parsed_fields={
                "llm_type": "ollama",
                "model": model,
                "prompt_length": len(prompt),
                "response_length": len(response) if response else 0,
                "risk_score": risk_score,
                "matched_patterns": matched_patterns,
                "is_threat": is_threat,
                "event_subtype": "generate",
                "total_duration": data.get("total_duration"),
                "eval_count": data.get("eval_count"),
            }
        )

    def _parse_chat_event(self, data: Dict[str, Any]) -> ParseResult:
        """Parse a chat API event."""
        messages = data.get("messages", [])
        model = data.get("model", "unknown")

        # Extract user messages for threat detection
        user_content = ""
        for msg in messages:
            if msg.get("role") == "user":
                user_content += msg.get("content", "") + " "

        # Calculate threat risk on combined user input
        risk_score, matched_patterns = calculate_risk_score(user_content)
        is_threat = self.enable_threat_detection and risk_score >= self.risk_threshold

        # Determine severity
        if is_threat:
            if risk_score >= 70:
                severity = EventSeverity.CRITICAL
            elif risk_score >= 50:
                severity = EventSeverity.ERROR
            else:
                severity = EventSeverity.WARNING
        else:
            severity = EventSeverity.INFO

        action = "threat_detected" if is_threat else "chat"

        timestamp = data.get("timestamp")
        if timestamp:
            if isinstance(timestamp, str):
                try:
                    timestamp = datetime.fromisoformat(timestamp.replace("Z", "+00:00"))
                except ValueError:
                    timestamp = datetime.now(timezone.utc)
        else:
            timestamp = datetime.now(timezone.utc)

        return ParseResult(
            timestamp=timestamp,
            event_type=EventType.LLM,
            severity=severity,
            raw_message=user_content[:1000] if user_content else str(data)[:1000],
            client_ip=data.get("client_ip"),
            action=action,
            parsed_fields={
                "llm_type": "ollama",
                "model": model,
                "message_count": len(messages),
                "user_content_length": len(user_content),
                "risk_score": risk_score,
                "matched_patterns": matched_patterns,
                "is_threat": is_threat,
                "event_subtype": "chat",
            }
        )

    def _parse_model_status(self, data: Dict[str, Any]) -> ParseResult:
        """Parse model status event (from /api/ps or /api/tags)."""
        models = data.get("models", [])

        timestamp = datetime.now(timezone.utc)

        return ParseResult(
            timestamp=timestamp,
            event_type=EventType.LLM,
            severity=EventSeverity.INFO,
            raw_message=f"Model status: {len(models)} models",
            action="model_status",
            parsed_fields={
                "llm_type": "ollama",
                "model_count": len(models),
                "models": [m.get("name", "unknown") for m in models[:10]],  # Limit to 10
                "event_subtype": "model_status",
            }
        )

    def _parse_generic_event(self, data: Dict[str, Any]) -> ParseResult:
        """Parse a generic Ollama event."""
        timestamp = data.get("timestamp")
        if timestamp:
            if isinstance(timestamp, str):
                try:
                    timestamp = datetime.fromisoformat(timestamp.replace("Z", "+00:00"))
                except ValueError:
                    timestamp = datetime.now(timezone.utc)
        else:
            timestamp = datetime.now(timezone.utc)

        return ParseResult(
            timestamp=timestamp,
            event_type=EventType.LLM,
            severity=EventSeverity.INFO,
            raw_message=str(data)[:1000],
            client_ip=data.get("client_ip"),
            action=data.get("action", "unknown"),
            parsed_fields={
                "llm_type": "ollama",
                "event_subtype": "generic",
                "raw_keys": list(data.keys())[:20],
            }
        )
