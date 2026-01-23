"""Scheduler for periodic semantic analysis runs."""

import asyncio
from datetime import datetime, timedelta, timezone
from typing import Optional

import structlog
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.config import settings
from app.db.session import AsyncSessionLocal
from app.models.semantic_analysis import SemanticAnalysisConfig
from app.services.semantic_analysis_service import get_semantic_analysis_service

logger = structlog.get_logger(__name__)


class SemanticAnalysisScheduler:
    """Background scheduler for periodic semantic analysis."""

    def __init__(self):
        self._running = False
        self._task: Optional[asyncio.Task] = None
        self._check_interval_seconds = 60  # Check every minute

    async def start(self) -> None:
        """Start the scheduler."""
        if not settings.semantic_analysis_enabled:
            logger.info("Semantic analysis disabled, scheduler not starting")
            return

        if not settings.semantic_scheduler_enabled:
            logger.info("Semantic scheduler disabled in config")
            return

        if self._running:
            logger.warning("Scheduler already running")
            return

        self._running = True
        self._task = asyncio.create_task(self._run_loop())
        logger.info("Semantic analysis scheduler started")

    async def stop(self) -> None:
        """Stop the scheduler."""
        if not self._running:
            return

        self._running = False
        if self._task:
            self._task.cancel()
            try:
                await self._task
            except asyncio.CancelledError:
                pass
            self._task = None
        logger.info("Semantic analysis scheduler stopped")

    async def _run_loop(self) -> None:
        """Main scheduler loop."""
        while self._running:
            try:
                await self._check_and_run_analyses()
            except Exception as e:
                logger.error("Error in scheduler loop", error=str(e))

            await asyncio.sleep(self._check_interval_seconds)

    async def _check_and_run_analyses(self) -> None:
        """Check all source configs and run analyses if due."""
        async with AsyncSessionLocal() as session:
            # Get all enabled configs
            result = await session.execute(
                select(SemanticAnalysisConfig).where(
                    SemanticAnalysisConfig.enabled == True  # noqa: E712
                )
            )
            configs = result.scalars().all()

            for config in configs:
                try:
                    if self._should_run_analysis(config):
                        await self._run_analysis_for_source(session, config)
                except Exception as e:
                    logger.error(
                        "Error running analysis for source",
                        source_id=str(config.source_id),
                        error=str(e),
                    )

    def _should_run_analysis(self, config: SemanticAnalysisConfig) -> bool:
        """Check if analysis should run based on last run time and interval."""
        if not config.last_run_at:
            return True

        now = datetime.now(timezone.utc)
        next_run_time = config.last_run_at + timedelta(
            minutes=config.batch_interval_minutes
        )
        return now >= next_run_time

    async def _run_analysis_for_source(
        self, session: AsyncSession, config: SemanticAnalysisConfig
    ) -> None:
        """Run semantic analysis for a specific source."""
        logger.info(
            "Starting scheduled semantic analysis",
            source_id=str(config.source_id),
        )

        service = get_semantic_analysis_service(session)
        run = await service.run_analysis(config.source_id)

        logger.info(
            "Completed scheduled semantic analysis",
            source_id=str(config.source_id),
            run_id=str(run.id),
            status=run.status,
            irregulars_found=run.irregulars_found,
        )

    async def trigger_source(self, source_id: str) -> None:
        """Manually trigger analysis for a specific source."""
        async with AsyncSessionLocal() as session:
            service = get_semantic_analysis_service(session)
            run = await service.run_analysis(source_id, force=True)
            logger.info(
                "Manual semantic analysis triggered",
                source_id=source_id,
                run_id=str(run.id),
            )


# Global scheduler instance
_scheduler: Optional[SemanticAnalysisScheduler] = None


def get_scheduler() -> SemanticAnalysisScheduler:
    """Get or create the global scheduler instance."""
    global _scheduler
    if _scheduler is None:
        _scheduler = SemanticAnalysisScheduler()
    return _scheduler


async def start_semantic_scheduler() -> None:
    """Start the semantic analysis scheduler."""
    scheduler = get_scheduler()
    await scheduler.start()


async def stop_semantic_scheduler() -> None:
    """Stop the semantic analysis scheduler."""
    if _scheduler:
        await _scheduler.stop()
