"""Base class for LLM providers used in semantic log analysis."""

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Any, cast


@dataclass
class LogConcern:
    """A security concern identified in a log entry."""

    log_index: int
    severity: float  # 0.0-1.0
    concern: str
    recommendation: str


@dataclass
class BenignExplanation:
    """Explanation for why a log entry is likely benign."""

    log_index: int
    explanation: str


@dataclass
class SuggestedRuleData:
    """A detection rule suggested by the LLM."""

    log_index: int
    name: str
    description: str
    reason: str
    benefit: str
    rule_type: str  # "pattern_match", "threshold", "sequence"
    rule_config: dict[str, Any]


@dataclass
class LLMAnalysisResult:
    """Result of LLM analysis on a batch of logs."""

    summary: str
    concerns: list[LogConcern] = field(default_factory=list)
    benign_explanations: list[BenignExplanation] = field(default_factory=list)
    suggested_rules: list[SuggestedRuleData] = field(default_factory=list)
    raw_response: str | None = None
    error: str | None = None
    tokens_used: int = 0

    @classmethod
    def from_error(cls, error: str) -> "LLMAnalysisResult":
        """Create a result representing an error."""
        return cls(
            summary=f"Analysis failed: {error}",
            error=error,
        )

    @classmethod
    def from_dict(
        cls, data: dict[str, Any], raw_response: str | None = None
    ) -> "LLMAnalysisResult":
        """Create a result from a parsed dictionary."""
        concerns = [
            LogConcern(
                log_index=c.get("log_index", 0),
                severity=c.get("severity", 0.5),
                concern=c.get("concern", ""),
                recommendation=c.get("recommendation", ""),
            )
            for c in data.get("concerns", [])
        ]

        benign = [
            BenignExplanation(
                log_index=b.get("log_index", 0),
                explanation=b.get("explanation", ""),
            )
            for b in data.get("benign_explanations", [])
        ]

        rules = [
            SuggestedRuleData(
                log_index=r.get("log_index", 0),
                name=r.get("name", ""),
                description=r.get("description", ""),
                reason=r.get("reason", ""),
                benefit=r.get("benefit", ""),
                rule_type=r.get("rule_type", "pattern_match"),
                rule_config=r.get("rule_config", {}),
            )
            for r in data.get("suggested_rules", [])
        ]

        return cls(
            summary=data.get("summary", "No summary provided"),
            concerns=concerns,
            benign_explanations=benign,
            suggested_rules=rules,
            raw_response=raw_response,
        )


# System prompt for semantic log analysis
SEMANTIC_ANALYSIS_SYSTEM_PROMPT = """You are a security analyst reviewing system logs that have been flagged as
"irregular" - meaning they differ from normal patterns seen in this environment.

These logs may come from various sources including:
- Servers (Linux, Windows, application servers)
- Network devices (routers, switches, firewalls)
- Containers and orchestration platforms
- Applications and services
- Authentication systems
- DNS servers and proxies

For each batch of logs, analyze them for potential security concerns including:
- Unauthorized access or authentication anomalies
- Privilege escalation attempts
- Suspicious process or service behavior
- Unusual file system operations
- Configuration changes
- Network communication anomalies
- Resource abuse or cryptomining indicators
- Malware indicators or command-and-control patterns
- Data exfiltration attempts
- Lateral movement indicators

Consider the source type when evaluating severity. What's unusual for one
source may be normal for another.

For any concerning findings, suggest detection rules that could catch similar
issues in the future. Rules should be specific enough to be useful but not
so narrow they only match this exact case.

Respond with a JSON structure:
{
  "summary": "Brief overview of findings",
  "concerns": [
    {
      "log_index": 0,
      "severity": 0.8,
      "concern": "Description of concern",
      "recommendation": "Suggested action"
    }
  ],
  "benign_explanations": [
    {
      "log_index": 1,
      "explanation": "Why this is likely benign"
    }
  ],
  "suggested_rules": [
    {
      "log_index": 0,
      "name": "Short descriptive rule name",
      "description": "What this rule detects",
      "reason": "Why this rule was suggested based on the log analysis",
      "benefit": "How this rule improves security posture",
      "rule_type": "pattern_match",
      "rule_config": {
        "pattern": "regex or glob pattern to match",
        "fields": ["field1", "field2"],
        "threshold": null,
        "time_window": null
      }
    }
  ]
}"""


class BaseLLMProvider(ABC):
    """Abstract base class for LLM providers used in semantic analysis."""

    @abstractmethod
    async def analyze_logs(
        self,
        logs: list[dict[str, Any]],
        context: str | None = None,
    ) -> LLMAnalysisResult:
        """Analyze a batch of irregular logs for security concerns.

        Args:
            logs: List of log entries to analyze. Each entry should have:
                - index: Position in the original batch
                - message: The raw log message
                - source: Source name/type
                - timestamp: When the log was generated
                - reason: Why it was flagged as irregular
            context: Optional additional context about the environment.

        Returns:
            LLMAnalysisResult containing concerns, explanations, and suggestions.
        """
        pass

    @abstractmethod
    async def is_available(self) -> bool:
        """Check if the LLM provider is available and configured.

        Returns:
            True if the provider is ready to use.
        """
        pass

    @property
    @abstractmethod
    def provider_name(self) -> str:
        """Get the name of this provider."""
        pass

    def _build_analysis_prompt(
        self,
        logs: list[dict[str, Any]],
        context: str | None = None,
    ) -> str:
        """Build the analysis prompt from logs.

        Args:
            logs: List of log entries.
            context: Optional context.

        Returns:
            Formatted prompt string.
        """
        prompt_parts = ["## Irregular Logs to Analyze\n"]

        for i, log in enumerate(logs):
            prompt_parts.append(f"### Log {i}")
            prompt_parts.append(f"**Source:** {log.get('source', 'Unknown')}")
            prompt_parts.append(f"**Timestamp:** {log.get('timestamp', 'Unknown')}")
            prompt_parts.append(f"**Reason Flagged:** {log.get('reason', 'Unknown')}")
            prompt_parts.append("**Message:**")
            prompt_parts.append("```")
            prompt_parts.append(log.get("message", ""))
            prompt_parts.append("```")
            prompt_parts.append("")

        if context:
            prompt_parts.append("## Additional Context")
            prompt_parts.append(context)
            prompt_parts.append("")

        prompt_parts.append("""## Analysis Instructions

Please analyze these irregular logs and provide:
1. A brief summary of your findings
2. Any security concerns with severity scores (0.0-1.0) and recommendations
3. Explanations for any logs that appear benign despite being flagged
4. Detection rules that could catch similar issues in the future

Respond ONLY with valid JSON matching the specified format.""")

        return "\n".join(prompt_parts)

    def _parse_json_response(self, response_text: str) -> dict[str, Any]:
        """Parse JSON from LLM response text.

        Args:
            response_text: Raw response from LLM.

        Returns:
            Parsed dictionary, or empty dict with error key on failure.
        """
        import json

        try:
            # Try direct JSON parse first
            return cast(dict[str, Any], json.loads(response_text))
        except json.JSONDecodeError:
            pass

        # Try to extract JSON from markdown code block
        try:
            if "```json" in response_text:
                json_start = response_text.find("```json") + 7
                json_end = response_text.find("```", json_start)
                json_str = response_text[json_start:json_end].strip()
                return cast(dict[str, Any], json.loads(json_str))
            elif "```" in response_text:
                json_start = response_text.find("```") + 3
                json_end = response_text.find("```", json_start)
                json_str = response_text[json_start:json_end].strip()
                return cast(dict[str, Any], json.loads(json_str))
        except json.JSONDecodeError:
            pass

        # Try to find JSON object in text
        try:
            if "{" in response_text and "}" in response_text:
                json_start = response_text.find("{")
                json_end = response_text.rfind("}") + 1
                json_str = response_text[json_start:json_end]
                return cast(dict[str, Any], json.loads(json_str))
        except json.JSONDecodeError:
            pass

        # Return error if parsing failed
        return {
            "summary": "Failed to parse LLM response",
            "error": "Invalid JSON in response",
            "raw_response": response_text,
        }
