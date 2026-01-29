"""Semantic analysis service for intelligent log pattern detection."""

from collections.abc import Sequence
from dataclasses import dataclass
from datetime import datetime, timedelta
from uuid import UUID

import structlog
from sqlalchemy import and_, func, select, true, update
from sqlalchemy.ext.asyncio import AsyncSession

from app.db.session import AsyncSessionLocal
from app.models.raw_event import RawEvent
from app.models.semantic_analysis import (
    AnalysisRunStatus,
    IrregularLog,
    LLMProvider,
    LogPattern,
    SemanticAnalysisConfig,
    SemanticAnalysisRun,
)
from app.services.llm_providers import LLMProviderFactory
from app.services.pattern_service import PatternService

logger = structlog.get_logger()


@dataclass
class IrregularLogFilters:
    """Filters for irregular log queries."""

    source_id: str | None = None
    llm_reviewed: bool | None = None
    reviewed_by_user: bool | None = None
    min_severity: float | None = None
    start_date: datetime | None = None
    end_date: datetime | None = None
    limit: int = 100
    offset: int = 0


@dataclass
class SemanticStats:
    """Statistics for semantic analysis."""

    total_patterns: int
    total_irregular_logs: int
    pending_review: int
    high_severity_count: int  # severity >= 0.7
    last_run_at: datetime | None
    last_run_status: str | None


class SemanticAnalysisService:
    """Service for semantic log analysis."""

    def __init__(self, session: AsyncSession | None = None):
        """Initialize the service.

        Args:
            session: Optional async session.
        """
        self._session = session
        self._pattern_service = PatternService(session)

    async def _get_session(self) -> AsyncSession:
        """Get or create an async session."""
        if self._session:
            return self._session
        return AsyncSessionLocal()

    # --- Configuration Management ---

    async def get_config(self, source_id: str) -> SemanticAnalysisConfig | None:
        """Get semantic analysis config for a source.

        Args:
            source_id: The source ID.

        Returns:
            Config if exists, None otherwise.
        """
        session = await self._get_session()
        should_close = self._session is None

        try:
            stmt = select(SemanticAnalysisConfig).where(
                SemanticAnalysisConfig.source_id == source_id
            )
            result = await session.execute(stmt)
            return result.scalar_one_or_none()

        finally:
            if should_close:
                await session.close()

    async def get_all_configs(self) -> Sequence[SemanticAnalysisConfig]:
        """Get all semantic analysis configs.

        Returns:
            List of all configs.
        """
        session = await self._get_session()
        should_close = self._session is None

        try:
            stmt = select(SemanticAnalysisConfig).order_by(SemanticAnalysisConfig.source_id)
            result = await session.execute(stmt)
            return result.scalars().all()

        finally:
            if should_close:
                await session.close()

    async def create_or_update_config(
        self,
        source_id: str,
        enabled: bool = True,
        llm_provider: LLMProvider = LLMProvider.CLAUDE,
        ollama_model: str | None = None,
        rarity_threshold: int = 3,
        batch_size: int = 50,
        batch_interval_minutes: int = 60,
    ) -> SemanticAnalysisConfig:
        """Create or update a semantic analysis config.

        Args:
            source_id: The source ID.
            enabled: Whether analysis is enabled.
            llm_provider: LLM provider to use.
            ollama_model: Ollama model if using Ollama.
            rarity_threshold: Patterns seen < N times are irregular.
            batch_size: Max logs per LLM batch.
            batch_interval_minutes: How often to run analysis.

        Returns:
            The created or updated config.
        """
        session = await self._get_session()
        should_close = self._session is None

        try:
            existing = await self.get_config(source_id)

            if existing:
                stmt = (
                    update(SemanticAnalysisConfig)
                    .where(SemanticAnalysisConfig.source_id == source_id)
                    .values(
                        enabled=enabled,
                        llm_provider=llm_provider,
                        ollama_model=ollama_model,
                        rarity_threshold=rarity_threshold,
                        batch_size=batch_size,
                        batch_interval_minutes=batch_interval_minutes,
                        updated_at=func.now(),
                    )
                    .returning(SemanticAnalysisConfig)
                )
                result = await session.execute(stmt)
                config = result.scalar_one()
            else:
                config = SemanticAnalysisConfig(
                    source_id=source_id,
                    enabled=enabled,
                    llm_provider=llm_provider,
                    ollama_model=ollama_model,
                    rarity_threshold=rarity_threshold,
                    batch_size=batch_size,
                    batch_interval_minutes=batch_interval_minutes,
                )
                session.add(config)

            await session.commit()
            await session.refresh(config)
            return config

        finally:
            if should_close:
                await session.close()

    # --- Event Processing ---

    async def process_event(self, event: RawEvent) -> IrregularLog | None:
        """Process a single event for pattern learning and irregularity detection.

        This is called for each new event when semantic analysis is enabled.

        Args:
            event: The raw event to process.

        Returns:
            IrregularLog if the event was flagged as irregular, None otherwise.
        """
        session = await self._get_session()
        should_close = self._session is None

        try:
            # Get config for this source
            config = await self.get_config(event.source_id)
            if not config or not config.enabled:
                return None

            # Record the pattern
            pattern = await self._pattern_service.record_pattern(
                source_id=event.source_id,
                message=event.raw_message,
                timestamp=event.timestamp,
            )

            # Check if the pattern is rare (irregular)
            if pattern.is_ignored:
                return None

            is_rare = await self._pattern_service.is_pattern_rare(pattern, config)

            if is_rare and pattern.occurrence_count <= config.rarity_threshold:
                # First time seeing this rare pattern, flag as irregular
                irregular = IrregularLog(
                    event_id=event.id,
                    event_timestamp=event.timestamp,
                    source_id=event.source_id,
                    pattern_id=pattern.id,
                    reason=f"Rare pattern (seen {pattern.occurrence_count} times, threshold: {config.rarity_threshold})",
                    llm_reviewed=False,
                    reviewed_by_user=False,
                )
                session.add(irregular)
                await session.commit()
                await session.refresh(irregular)

                logger.info(
                    "irregular_log_detected",
                    event_id=str(event.id),
                    source_id=event.source_id,
                    pattern_count=pattern.occurrence_count,
                )

                return irregular

            return None

        finally:
            if should_close:
                await session.close()

    # --- Analysis Runs ---

    async def run_analysis(
        self,
        source_id: str,
        force: bool = False,
    ) -> SemanticAnalysisRun:
        """Run batch analysis for a source.

        Args:
            source_id: The source to analyze.
            force: Run even if interval hasn't passed.

        Returns:
            The analysis run record.
        """
        session = await self._get_session()
        should_close = self._session is None

        try:
            config = await self.get_config(source_id)
            if not config:
                raise ValueError(f"No config found for source {source_id}")

            if not config.enabled:
                raise ValueError(f"Semantic analysis disabled for source {source_id}")

            # Check if we should run based on interval
            if not force and config.last_run_at:
                next_run = config.last_run_at + timedelta(minutes=config.batch_interval_minutes)
                if datetime.utcnow() < next_run:
                    raise ValueError(f"Too soon to run analysis, next run at {next_run}")

            # Create run record
            run = SemanticAnalysisRun(
                source_id=source_id,
                started_at=datetime.utcnow(),
                status=AnalysisRunStatus.RUNNING,
                llm_provider=config.llm_provider,
                events_scanned=0,
                irregulars_found=0,
            )
            session.add(run)
            await session.commit()
            await session.refresh(run)

            try:
                # Get unreviewed irregular logs for this source
                stmt = (
                    select(IrregularLog)
                    .where(
                        and_(
                            IrregularLog.source_id == source_id,
                            IrregularLog.llm_reviewed.is_(False),
                        )
                    )
                    .order_by(IrregularLog.created_at.asc())
                    .limit(config.batch_size)
                )
                result = await session.execute(stmt)
                irregular_logs = result.scalars().all()

                if not irregular_logs:
                    # No logs to analyze
                    run.status = AnalysisRunStatus.COMPLETED
                    run.completed_at = datetime.utcnow()
                    run.llm_response_summary = "No unreviewed irregular logs found"
                    await session.commit()
                    return run

                # Get the actual events for these irregular logs
                logs_for_analysis = []
                for i, irregular in enumerate(irregular_logs):
                    # Get the raw event
                    event_stmt = select(RawEvent).where(
                        and_(
                            RawEvent.id == irregular.event_id,
                            RawEvent.timestamp == irregular.event_timestamp,
                        )
                    )
                    event_result = await session.execute(event_stmt)
                    event = event_result.scalar_one_or_none()

                    if event:
                        logs_for_analysis.append(
                            {
                                "index": i,
                                "irregular_id": irregular.id,
                                "message": event.raw_message,
                                "source": source_id,
                                "timestamp": event.timestamp.isoformat(),
                                "reason": irregular.reason,
                            }
                        )

                run.events_scanned = len(logs_for_analysis)

                # Get LLM provider and analyze
                provider = LLMProviderFactory.get_provider(
                    config.llm_provider,
                    ollama_model=config.ollama_model,
                )

                analysis_result = await provider.analyze_logs(logs_for_analysis)

                # Update irregular logs with analysis results
                for concern in analysis_result.concerns:
                    if concern.log_index < len(logs_for_analysis):
                        irregular_id = logs_for_analysis[concern.log_index]["irregular_id"]
                        await session.execute(
                            update(IrregularLog)
                            .where(IrregularLog.id == irregular_id)
                            .values(
                                llm_reviewed=True,
                                llm_response=concern.concern,
                                severity_score=concern.severity,
                                updated_at=func.now(),
                            )
                        )
                        if concern.severity >= 0.7:
                            run.irregulars_found += 1

                # Mark benign logs as reviewed
                for benign in analysis_result.benign_explanations:
                    if benign.log_index < len(logs_for_analysis):
                        irregular_id = logs_for_analysis[benign.log_index]["irregular_id"]
                        await session.execute(
                            update(IrregularLog)
                            .where(IrregularLog.id == irregular_id)
                            .values(
                                llm_reviewed=True,
                                llm_response=benign.explanation,
                                severity_score=0.1,  # Low severity for benign
                                updated_at=func.now(),
                            )
                        )

                # Mark all other logs as reviewed with no concerns
                reviewed_indices = {c.log_index for c in analysis_result.concerns}
                reviewed_indices.update({b.log_index for b in analysis_result.benign_explanations})
                for i, log_data in enumerate(logs_for_analysis):
                    if i not in reviewed_indices:
                        await session.execute(
                            update(IrregularLog)
                            .where(IrregularLog.id == log_data["irregular_id"])
                            .values(
                                llm_reviewed=True,
                                llm_response="No specific concerns identified",
                                severity_score=0.3,  # Medium-low for uncategorized
                                updated_at=func.now(),
                            )
                        )

                # Update run record
                run.status = AnalysisRunStatus.COMPLETED
                run.completed_at = datetime.utcnow()
                run.llm_response_summary = analysis_result.summary

                # Update config last_run_at
                await session.execute(
                    update(SemanticAnalysisConfig)
                    .where(SemanticAnalysisConfig.source_id == source_id)
                    .values(last_run_at=datetime.utcnow())
                )

                await session.commit()

                logger.info(
                    "semantic_analysis_complete",
                    source_id=source_id,
                    run_id=str(run.id),
                    events_scanned=run.events_scanned,
                    irregulars_found=run.irregulars_found,
                )

                # Return analysis result for rule suggestion processing
                run._analysis_result = analysis_result  # type: ignore
                return run

            except Exception as e:
                logger.error(
                    "semantic_analysis_failed",
                    source_id=source_id,
                    run_id=str(run.id),
                    error=str(e),
                )
                run.status = AnalysisRunStatus.FAILED
                run.completed_at = datetime.utcnow()
                run.error_message = str(e)
                await session.commit()
                return run

        finally:
            if should_close:
                await session.close()

    async def get_analysis_runs(
        self,
        source_id: str | None = None,
        limit: int = 50,
    ) -> Sequence[SemanticAnalysisRun]:
        """Get analysis runs.

        Args:
            source_id: Optional filter by source.
            limit: Maximum runs to return.

        Returns:
            List of analysis runs.
        """
        session = await self._get_session()
        should_close = self._session is None

        try:
            conditions = []
            if source_id:
                conditions.append(SemanticAnalysisRun.source_id == source_id)

            stmt = (
                select(SemanticAnalysisRun)
                .where(and_(*conditions) if conditions else true())
                .order_by(SemanticAnalysisRun.started_at.desc())
                .limit(limit)
            )

            result = await session.execute(stmt)
            return result.scalars().all()

        finally:
            if should_close:
                await session.close()

    # --- Irregular Logs ---

    async def get_irregular_logs(
        self,
        filters: IrregularLogFilters,
    ) -> Sequence[IrregularLog]:
        """Get irregular logs with filters.

        Args:
            filters: Filter criteria.

        Returns:
            List of irregular logs.
        """
        session = await self._get_session()
        should_close = self._session is None

        try:
            conditions = []

            if filters.source_id:
                conditions.append(IrregularLog.source_id == filters.source_id)

            if filters.llm_reviewed is not None:
                conditions.append(IrregularLog.llm_reviewed == filters.llm_reviewed)

            if filters.reviewed_by_user is not None:
                conditions.append(IrregularLog.reviewed_by_user == filters.reviewed_by_user)

            if filters.min_severity is not None:
                conditions.append(IrregularLog.severity_score >= filters.min_severity)

            if filters.start_date:
                conditions.append(IrregularLog.created_at >= filters.start_date)

            if filters.end_date:
                conditions.append(IrregularLog.created_at <= filters.end_date)

            stmt = (
                select(IrregularLog)
                .where(and_(*conditions) if conditions else true())
                .order_by(IrregularLog.created_at.desc())
                .limit(filters.limit)
                .offset(filters.offset)
            )

            result = await session.execute(stmt)
            return result.scalars().all()

        finally:
            if should_close:
                await session.close()

    async def get_irregular_log_count(
        self,
        filters: IrregularLogFilters,
    ) -> int:
        """Get count of irregular logs matching filters.

        Args:
            filters: Filter criteria.

        Returns:
            Count of matching logs.
        """
        session = await self._get_session()
        should_close = self._session is None

        try:
            conditions = []

            if filters.source_id:
                conditions.append(IrregularLog.source_id == filters.source_id)

            if filters.llm_reviewed is not None:
                conditions.append(IrregularLog.llm_reviewed == filters.llm_reviewed)

            if filters.reviewed_by_user is not None:
                conditions.append(IrregularLog.reviewed_by_user == filters.reviewed_by_user)

            if filters.min_severity is not None:
                conditions.append(IrregularLog.severity_score >= filters.min_severity)

            stmt = select(func.count(IrregularLog.id)).where(
                and_(*conditions) if conditions else true()
            )

            result = await session.execute(stmt)
            return result.scalar_one()

        finally:
            if should_close:
                await session.close()

    async def get_irregular_log_by_id(
        self,
        irregular_id: UUID,
    ) -> IrregularLog | None:
        """Get an irregular log by ID.

        Args:
            irregular_id: The irregular log ID.

        Returns:
            The irregular log if found.
        """
        session = await self._get_session()
        should_close = self._session is None

        try:
            stmt = select(IrregularLog).where(IrregularLog.id == irregular_id)
            result = await session.execute(stmt)
            return result.scalar_one_or_none()

        finally:
            if should_close:
                await session.close()

    async def mark_reviewed(
        self,
        irregular_id: UUID,
        user_id: UUID | None = None,
    ) -> IrregularLog | None:
        """Mark an irregular log as reviewed by a user.

        Args:
            irregular_id: The irregular log ID.
            user_id: The reviewing user's ID.

        Returns:
            The updated irregular log.
        """
        session = await self._get_session()
        should_close = self._session is None

        try:
            stmt = (
                update(IrregularLog)
                .where(IrregularLog.id == irregular_id)
                .values(
                    reviewed_by_user=True,
                    reviewed_at=datetime.utcnow(),
                    updated_at=func.now(),
                )
                .returning(IrregularLog)
            )
            result = await session.execute(stmt)
            irregular = result.scalar_one_or_none()
            await session.commit()
            return irregular

        finally:
            if should_close:
                await session.close()

    # --- Statistics ---

    async def get_stats(
        self,
        source_id: str | None = None,
    ) -> SemanticStats:
        """Get semantic analysis statistics.

        Args:
            source_id: Optional filter by source.

        Returns:
            Statistics about patterns and irregular logs.
        """
        session = await self._get_session()
        should_close = self._session is None

        try:
            # Get pattern count
            pattern_stmt = select(func.count(LogPattern.id))
            if source_id:
                pattern_stmt = pattern_stmt.where(LogPattern.source_id == source_id)
            pattern_result = await session.execute(pattern_stmt)
            total_patterns = pattern_result.scalar_one()

            # Get irregular log stats
            irregular_base = select(IrregularLog)
            if source_id:
                irregular_base = irregular_base.where(IrregularLog.source_id == source_id)

            total_stmt = select(func.count(IrregularLog.id))
            if source_id:
                total_stmt = total_stmt.where(IrregularLog.source_id == source_id)
            total_result = await session.execute(total_stmt)
            total_irregular = total_result.scalar_one()

            pending_stmt = select(func.count(IrregularLog.id)).where(
                IrregularLog.reviewed_by_user.is_(False)
            )
            if source_id:
                pending_stmt = pending_stmt.where(IrregularLog.source_id == source_id)
            pending_result = await session.execute(pending_stmt)
            pending_review = pending_result.scalar_one()

            high_severity_stmt = select(func.count(IrregularLog.id)).where(
                IrregularLog.severity_score >= 0.7
            )
            if source_id:
                high_severity_stmt = high_severity_stmt.where(IrregularLog.source_id == source_id)
            high_severity_result = await session.execute(high_severity_stmt)
            high_severity_count = high_severity_result.scalar_one()

            # Get last run info
            run_stmt = (
                select(SemanticAnalysisRun).order_by(SemanticAnalysisRun.started_at.desc()).limit(1)
            )
            if source_id:
                run_stmt = run_stmt.where(SemanticAnalysisRun.source_id == source_id)
            run_result = await session.execute(run_stmt)
            last_run = run_result.scalar_one_or_none()

            return SemanticStats(
                total_patterns=total_patterns,
                total_irregular_logs=total_irregular,
                pending_review=pending_review,
                high_severity_count=high_severity_count,
                last_run_at=last_run.started_at if last_run else None,
                last_run_status=last_run.status.value if last_run else None,
            )

        finally:
            if should_close:
                await session.close()


def get_semantic_analysis_service(
    session: AsyncSession | None = None,
) -> SemanticAnalysisService:
    """Factory function to get a SemanticAnalysisService instance.

    Args:
        session: Optional async session.

    Returns:
        SemanticAnalysisService instance.
    """
    return SemanticAnalysisService(session)
