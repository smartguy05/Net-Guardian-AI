"""Security analysis service for detecting attacks in application logs."""

from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Any
from uuid import UUID, uuid4

import structlog
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.db.session import AsyncSessionLocal
from app.models.alert import Alert, AlertSeverity, AlertStatus
from app.models.anomaly import AnomalyDetection, AnomalyStatus, AnomalyType
from app.models.raw_event import EventType, RawEvent
from app.models.security_pattern import PatternCategory, SecurityPattern
from app.services.security_pattern_service import PatternMatch, SecurityPatternService

logger = structlog.get_logger()


@dataclass
class SecurityFinding:
    """A security finding from log analysis."""

    timestamp: datetime
    source_id: str
    event_id: UUID
    pattern_id: UUID
    pattern_name: str
    category: PatternCategory
    severity: AlertSeverity
    matched_text: str
    log_message: str
    context: dict[str, Any]


class SecurityAnalyzer:
    """Analyzes logs for security patterns and creates findings."""

    def __init__(self, session: AsyncSession):
        self._session = session
        self._pattern_service = SecurityPatternService(session)

    async def analyze_recent_events(
        self,
        source_id: str | None = None,
        window_hours: int = 1,
        event_types: list[EventType] | None = None,
        categories: list[PatternCategory] | None = None,
    ) -> list[SecurityFinding]:
        """Analyze recent events for security patterns.

        Args:
            source_id: Optional source to filter.
            window_hours: Hours of events to analyze.
            event_types: Event types to analyze (default: application logs).
            categories: Pattern categories to check (default: all).

        Returns:
            List of SecurityFinding objects.
        """
        cutoff = datetime.now(UTC) - timedelta(hours=window_hours)

        # Build query
        query = select(RawEvent).where(RawEvent.timestamp >= cutoff)

        if source_id:
            query = query.where(RawEvent.source_id == source_id)

        if event_types:
            query = query.where(RawEvent.event_type.in_(event_types))
        else:
            # Default to application log types
            query = query.where(RawEvent.event_type.in_([
                EventType.CONTAINER,
                EventType.JOURNAL,
                EventType.APPLICATION,
                EventType.HTTP,
            ]))

        query = query.order_by(RawEvent.timestamp.desc()).limit(10000)

        result = await self._session.execute(query)
        events = list(result.scalars().all())

        findings: list[SecurityFinding] = []

        for event in events:
            event_findings = await self._analyze_event(event, categories)
            findings.extend(event_findings)

        logger.info(
            "security_analysis_complete",
            events_analyzed=len(events),
            findings_count=len(findings),
            source_id=source_id,
        )

        return findings

    async def _analyze_event(
        self,
        event: RawEvent,
        categories: list[PatternCategory] | None = None,
    ) -> list[SecurityFinding]:
        """Analyze a single event for security patterns."""
        findings: list[SecurityFinding] = []

        # Check raw message
        matches = await self._pattern_service.match_text(
            event.raw_message,
            categories=categories,
        )

        for match in matches:
            findings.append(SecurityFinding(
                timestamp=event.timestamp,
                source_id=event.source_id,
                event_id=event.id,
                pattern_id=match.pattern_id,
                pattern_name=match.pattern_name,
                category=match.category,
                severity=match.severity,
                matched_text=match.matched_text,
                log_message=event.raw_message[:500],
                context={
                    "match_start": match.match_start,
                    "match_end": match.match_end,
                    "event_type": event.event_type.value,
                    "severity": event.severity.value,
                    **match.context,
                },
            ))

        # Also check exception messages if present
        exc_message = event.parsed_fields.get("exception_message", "")
        if exc_message and exc_message != event.raw_message:
            exc_matches = await self._pattern_service.match_text(
                exc_message,
                categories=categories,
            )
            for match in exc_matches:
                findings.append(SecurityFinding(
                    timestamp=event.timestamp,
                    source_id=event.source_id,
                    event_id=event.id,
                    pattern_id=match.pattern_id,
                    pattern_name=match.pattern_name,
                    category=match.category,
                    severity=match.severity,
                    matched_text=match.matched_text,
                    log_message=exc_message[:500],
                    context={
                        "source": "exception_message",
                        "exception_type": event.parsed_fields.get("exception_type"),
                        **match.context,
                    },
                ))

        return findings

    async def correlate_findings(
        self,
        findings: list[SecurityFinding],
        time_window_minutes: int = 5,
        min_occurrences: int = 3,
    ) -> list[dict[str, Any]]:
        """Correlate multiple findings to identify attack patterns.

        Groups findings by pattern and source within a time window to
        identify sustained attack attempts vs one-off matches.

        Args:
            findings: List of security findings.
            time_window_minutes: Window for grouping related findings.
            min_occurrences: Minimum occurrences to be considered an attack.

        Returns:
            List of correlated attack summaries.
        """
        if not findings:
            return []

        # Group findings by pattern and source
        groups: dict[str, list[SecurityFinding]] = {}

        for finding in findings:
            key = f"{finding.pattern_id}:{finding.source_id}"
            if key not in groups:
                groups[key] = []
            groups[key].append(finding)

        attacks: list[dict[str, Any]] = []

        for key, group_findings in groups.items():
            if len(group_findings) < min_occurrences:
                continue

            # Sort by timestamp
            group_findings.sort(key=lambda f: f.timestamp)

            # Check if findings are within time window
            first_ts = group_findings[0].timestamp
            last_ts = group_findings[-1].timestamp
            duration = (last_ts - first_ts).total_seconds() / 60

            # Consider it an attack if multiple findings within window
            if duration <= time_window_minutes or len(group_findings) >= min_occurrences:
                # Find highest severity
                max_severity = max(group_findings, key=lambda f: self._severity_order(f.severity))

                attacks.append({
                    "pattern_id": str(group_findings[0].pattern_id),
                    "pattern_name": group_findings[0].pattern_name,
                    "category": group_findings[0].category.value,
                    "severity": max_severity.severity.value,
                    "source_id": group_findings[0].source_id,
                    "occurrence_count": len(group_findings),
                    "first_seen": first_ts.isoformat(),
                    "last_seen": last_ts.isoformat(),
                    "duration_minutes": duration,
                    "sample_matches": [
                        {
                            "matched_text": f.matched_text[:100],
                            "timestamp": f.timestamp.isoformat(),
                        }
                        for f in group_findings[:5]
                    ],
                })

        # Sort by severity then occurrence count
        attacks.sort(
            key=lambda a: (-self._severity_order(AlertSeverity(a["severity"])), -a["occurrence_count"])
        )

        return attacks

    def _severity_order(self, severity: AlertSeverity) -> int:
        """Get numeric severity order for comparison."""
        order = {
            AlertSeverity.INFO: 0,
            AlertSeverity.LOW: 1,
            AlertSeverity.MEDIUM: 2,
            AlertSeverity.HIGH: 3,
            AlertSeverity.CRITICAL: 4,
        }
        return order.get(severity, 0)

    async def create_anomaly_for_finding(
        self,
        finding: SecurityFinding,
        device_id: UUID | None = None,
    ) -> AnomalyDetection:
        """Create an anomaly detection record for a security finding."""
        anomaly = AnomalyDetection(
            id=uuid4(),
            device_id=device_id or uuid4(),  # Use placeholder if no device
            anomaly_type=AnomalyType.SECURITY_PATTERN,
            severity=finding.severity,
            score=self._severity_order(finding.severity) + 2.0,
            status=AnomalyStatus.ACTIVE,
            description=f"Security pattern detected: {finding.pattern_name}",
            details={
                "pattern_id": str(finding.pattern_id),
                "pattern_name": finding.pattern_name,
                "category": finding.category.value,
                "matched_text": finding.matched_text[:200],
                "source_id": finding.source_id,
                "event_id": str(finding.event_id),
            },
            baseline_comparison={
                "pattern_category": finding.category.value,
                "log_message": finding.log_message[:300],
            },
            detected_at=finding.timestamp,
        )
        self._session.add(anomaly)
        return anomaly

    async def create_alert_for_attack(
        self,
        attack: dict[str, Any],
        device_id: UUID | None = None,
    ) -> Alert:
        """Create an alert for a correlated attack."""
        category = attack["category"].replace("_", " ").title()
        severity = AlertSeverity(attack["severity"])

        alert = Alert(
            id=uuid4(),
            timestamp=datetime.fromisoformat(attack["first_seen"]),
            device_id=device_id,
            rule_id=f"security_pattern_{attack['category']}",
            severity=severity,
            title=f"{category} Attack Detected: {attack['pattern_name']}",
            description=(
                f"Detected {attack['occurrence_count']} occurrences of {attack['pattern_name']} "
                f"over {attack['duration_minutes']:.1f} minutes. "
                f"Source: {attack['source_id']}"
            ),
            status=AlertStatus.NEW,
            actions_taken=[],
        )
        self._session.add(alert)
        return alert


class SecurityAnalysisService:
    """High-level service for security analysis."""

    async def run_analysis(
        self,
        source_id: str | None = None,
        window_hours: int = 1,
        create_alerts: bool = True,
        min_occurrences_for_alert: int = 3,
    ) -> dict[str, Any]:
        """Run security analysis on recent logs.

        Args:
            source_id: Optional source to analyze.
            window_hours: Hours of logs to analyze.
            create_alerts: Whether to create alerts for attacks.
            min_occurrences_for_alert: Minimum occurrences for alert.

        Returns:
            Analysis results summary.
        """
        async with AsyncSessionLocal() as session:
            analyzer = SecurityAnalyzer(session)

            # Analyze recent events
            findings = await analyzer.analyze_recent_events(
                source_id=source_id,
                window_hours=window_hours,
            )

            # Correlate findings
            attacks = await analyzer.correlate_findings(
                findings,
                min_occurrences=min_occurrences_for_alert,
            )

            alerts_created = 0
            if create_alerts:
                for attack in attacks:
                    if attack["occurrence_count"] >= min_occurrences_for_alert:
                        await analyzer.create_alert_for_attack(attack)
                        alerts_created += 1

            await session.commit()

            # Summarize by category
            by_category: dict[str, int] = {}
            for finding in findings:
                cat = finding.category.value
                by_category[cat] = by_category.get(cat, 0) + 1

            return {
                "findings_count": len(findings),
                "findings_by_category": by_category,
                "attacks_detected": len(attacks),
                "alerts_created": alerts_created,
                "attacks": attacks,
            }

    async def check_text(
        self,
        text: str,
        categories: list[PatternCategory] | None = None,
    ) -> list[dict[str, Any]]:
        """Check arbitrary text for security patterns.

        Args:
            text: Text to analyze.
            categories: Optional categories to check.

        Returns:
            List of pattern matches.
        """
        async with AsyncSessionLocal() as session:
            service = SecurityPatternService(session)
            matches = await service.match_text(text, categories)

            return [
                {
                    "pattern_id": str(m.pattern_id),
                    "pattern_name": m.pattern_name,
                    "category": m.category.value,
                    "severity": m.severity.value,
                    "matched_text": m.matched_text,
                    "match_start": m.match_start,
                    "match_end": m.match_end,
                }
                for m in matches
            ]

    async def get_security_stats(
        self,
        window_days: int = 7,
    ) -> dict[str, Any]:
        """Get security analysis statistics.

        Args:
            window_days: Days of history to analyze.

        Returns:
            Statistics summary.
        """
        async with AsyncSessionLocal() as session:
            cutoff = datetime.now(UTC) - timedelta(days=window_days)

            # Get pattern match counts from anomaly detections
            result = await session.execute(
                select(func.count())
                .where(AnomalyDetection.anomaly_type == AnomalyType.SECURITY_PATTERN)
                .where(AnomalyDetection.detected_at >= cutoff)
            )
            security_anomalies = result.scalar() or 0

            # Get security alerts
            result = await session.execute(
                select(func.count())
                .where(Alert.rule_id.like("security_pattern_%"))
                .where(Alert.timestamp >= cutoff)
            )
            security_alerts = result.scalar() or 0

            # Get pattern stats
            pattern_service = SecurityPatternService(session)
            pattern_stats = await pattern_service.get_stats()

            return {
                "window_days": window_days,
                "security_anomalies": security_anomalies,
                "security_alerts": security_alerts,
                "pattern_stats": pattern_stats,
            }


# Global service instance
_security_analysis_service: SecurityAnalysisService | None = None


def get_security_analysis_service() -> SecurityAnalysisService:
    """Get the global security analysis service instance."""
    global _security_analysis_service
    if _security_analysis_service is None:
        _security_analysis_service = SecurityAnalysisService()
    return _security_analysis_service
