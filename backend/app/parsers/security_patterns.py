"""Security pattern detection module for parser integration.

This module provides a thin wrapper around SecurityPatternService for use by parsers
to detect security patterns in log content.
"""

from dataclasses import dataclass
from typing import Any
from uuid import UUID

from sqlalchemy.ext.asyncio import AsyncSession

from app.models.alert import AlertSeverity
from app.models.security_pattern import PatternCategory
from app.services.security_pattern_service import PatternMatch, SecurityPatternService


@dataclass
class SecurityPatternDetection:
    """Result of security pattern detection in log content."""

    pattern_id: UUID
    pattern_name: str
    category: str
    severity: str
    matched_text: str
    match_start: int
    match_end: int
    context: dict[str, Any]

    @classmethod
    def from_pattern_match(cls, match: PatternMatch) -> "SecurityPatternDetection":
        """Create from a PatternMatch object."""
        return cls(
            pattern_id=match.pattern_id,
            pattern_name=match.pattern_name,
            category=match.category.value,
            severity=match.severity.value,
            matched_text=match.matched_text,
            match_start=match.match_start,
            match_end=match.match_end,
            context=match.context,
        )


async def detect_security_patterns(
    text: str,
    session: AsyncSession,
    categories: list[PatternCategory] | None = None,
) -> list[SecurityPatternDetection]:
    """Detect security patterns in log content.

    This function is called by parsers to check log messages for attack patterns.

    Args:
        text: The log content to analyze.
        session: Database session for pattern lookup.
        categories: Optional list of categories to check. If None, checks all.

    Returns:
        List of security pattern detections found in the text.

    Example:
        ```python
        async def parse(self, raw_data: Any) -> list[ParseResult]:
            # ... parse log entry ...

            # Check for security patterns
            detections = await detect_security_patterns(
                log_message,
                session,
                categories=[PatternCategory.SQL_INJECTION, PatternCategory.XSS]
            )

            if detections:
                result.parsed_fields["security_patterns"] = [
                    {
                        "pattern": d.pattern_name,
                        "category": d.category,
                        "severity": d.severity,
                        "matched": d.matched_text,
                    }
                    for d in detections
                ]
                # Potentially elevate severity
                if any(d.severity == "critical" for d in detections):
                    result.severity = EventSeverity.CRITICAL
        ```
    """
    service = SecurityPatternService(session)
    matches = await service.match_text(text, categories=categories)
    return [SecurityPatternDetection.from_pattern_match(m) for m in matches]


async def get_highest_severity(
    detections: list[SecurityPatternDetection],
) -> AlertSeverity | None:
    """Get the highest severity from a list of detections.

    Args:
        detections: List of security pattern detections.

    Returns:
        The highest AlertSeverity found, or None if no detections.
    """
    if not detections:
        return None

    severity_order = {
        "info": 0,
        "low": 1,
        "medium": 2,
        "high": 3,
        "critical": 4,
    }

    highest = max(detections, key=lambda d: severity_order.get(d.severity, 0))
    return AlertSeverity(highest.severity)


def detections_to_parsed_fields(
    detections: list[SecurityPatternDetection],
) -> list[dict[str, Any]]:
    """Convert detections to a format suitable for ParseResult.parsed_fields.

    Args:
        detections: List of security pattern detections.

    Returns:
        List of dictionaries with pattern match information.
    """
    return [
        {
            "pattern_id": str(d.pattern_id),
            "pattern_name": d.pattern_name,
            "category": d.category,
            "severity": d.severity,
            "matched_text": d.matched_text[:200],  # Truncate for storage
            "match_position": {"start": d.match_start, "end": d.match_end},
        }
        for d in detections
    ]
