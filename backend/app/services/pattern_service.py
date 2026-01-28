"""Pattern service for managing learned log patterns."""

from collections.abc import Sequence
from dataclasses import dataclass
from datetime import datetime
from uuid import UUID

from sqlalchemy import and_, func, select, update
from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.ext.asyncio import AsyncSession

from app.db.session import AsyncSessionLocal
from app.models.semantic_analysis import (
    LogPattern,
    SemanticAnalysisConfig,
)
from app.services.pattern_normalizer import PatternNormalizer


@dataclass
class PatternStats:
    """Statistics about patterns for a source."""

    total_patterns: int
    ignored_patterns: int
    rare_patterns: int  # Below rarity threshold
    total_occurrences: int
    avg_occurrences: float


@dataclass
class PatternFilters:
    """Filters for pattern queries."""

    source_id: str | None = None
    is_ignored: bool | None = None
    rare_only: bool = False
    rarity_threshold: int = 3
    search: str | None = None
    limit: int = 100
    offset: int = 0


class PatternService:
    """Service for managing learned log patterns."""

    def __init__(self, session: AsyncSession | None = None):
        """Initialize the pattern service.

        Args:
            session: Optional async session. If not provided, creates one per operation.
        """
        self._session = session

    async def _get_session(self) -> AsyncSession:
        """Get or create an async session."""
        if self._session:
            return self._session
        return AsyncSessionLocal()

    async def record_pattern(
        self,
        source_id: str,
        message: str,
        timestamp: datetime | None = None,
    ) -> LogPattern:
        """Record a pattern from a log message.

        If the pattern already exists, updates occurrence count and last_seen.
        Otherwise, creates a new pattern.

        Args:
            source_id: The source ID this pattern belongs to.
            message: The raw log message.
            timestamp: Optional timestamp (defaults to now).

        Returns:
            The LogPattern (created or updated).
        """
        normalized, pattern_hash = PatternNormalizer.normalize(message)
        now = timestamp or datetime.utcnow()

        session = await self._get_session()
        should_close = self._session is None

        try:
            # Use upsert (INSERT ON CONFLICT) for efficiency
            stmt = pg_insert(LogPattern).values(
                source_id=source_id,
                normalized_pattern=normalized,
                pattern_hash=pattern_hash,
                first_seen=now,
                last_seen=now,
                occurrence_count=1,
                is_ignored=False,
            ).on_conflict_do_update(
                index_elements=["source_id", "pattern_hash"],
                set_={
                    "last_seen": now,
                    "occurrence_count": LogPattern.occurrence_count + 1,
                    "updated_at": func.now(),
                },
            ).returning(LogPattern)

            result = await session.execute(stmt)
            pattern = result.scalar_one()
            await session.commit()
            return pattern

        finally:
            if should_close:
                await session.close()

    async def get_pattern_by_hash(
        self,
        source_id: str,
        pattern_hash: str,
    ) -> LogPattern | None:
        """Get a pattern by its hash.

        Args:
            source_id: The source ID.
            pattern_hash: The pattern hash.

        Returns:
            The pattern if found, None otherwise.
        """
        session = await self._get_session()
        should_close = self._session is None

        try:
            stmt = select(LogPattern).where(
                and_(
                    LogPattern.source_id == source_id,
                    LogPattern.pattern_hash == pattern_hash,
                )
            )
            result = await session.execute(stmt)
            return result.scalar_one_or_none()

        finally:
            if should_close:
                await session.close()

    async def get_pattern_by_id(self, pattern_id: UUID) -> LogPattern | None:
        """Get a pattern by its ID.

        Args:
            pattern_id: The pattern UUID.

        Returns:
            The pattern if found, None otherwise.
        """
        session = await self._get_session()
        should_close = self._session is None

        try:
            stmt = select(LogPattern).where(LogPattern.id == pattern_id)
            result = await session.execute(stmt)
            return result.scalar_one_or_none()

        finally:
            if should_close:
                await session.close()

    async def get_pattern_stats(
        self,
        source_id: str,
        rarity_threshold: int = 3,
    ) -> PatternStats:
        """Get statistics about patterns for a source.

        Args:
            source_id: The source ID.
            rarity_threshold: Threshold for considering patterns rare.

        Returns:
            PatternStats with various metrics.
        """
        session = await self._get_session()
        should_close = self._session is None

        try:
            # Get all stats in one query
            stmt = select(
                func.count(LogPattern.id).label("total"),
                func.count(LogPattern.id).filter(LogPattern.is_ignored.is_(True)).label("ignored"),
                func.count(LogPattern.id).filter(LogPattern.occurrence_count < rarity_threshold).label("rare"),
                func.coalesce(func.sum(LogPattern.occurrence_count), 0).label("total_occurrences"),
                func.coalesce(func.avg(LogPattern.occurrence_count), 0).label("avg_occurrences"),
            ).where(LogPattern.source_id == source_id)

            result = await session.execute(stmt)
            row = result.one()

            return PatternStats(
                total_patterns=row.total,
                ignored_patterns=row.ignored,
                rare_patterns=row.rare,
                total_occurrences=row.total_occurrences,
                avg_occurrences=float(row.avg_occurrences),
            )

        finally:
            if should_close:
                await session.close()

    async def is_pattern_rare(
        self,
        pattern: LogPattern,
        config: SemanticAnalysisConfig | None = None,
        default_threshold: int = 3,
    ) -> bool:
        """Check if a pattern is considered rare.

        Args:
            pattern: The pattern to check.
            config: Optional config to get threshold from.
            default_threshold: Default threshold if no config.

        Returns:
            True if the pattern is rare (below threshold).
        """
        threshold = config.rarity_threshold if config else default_threshold
        return pattern.occurrence_count < threshold

    async def mark_pattern_ignored(
        self,
        pattern_id: UUID,
        ignored: bool = True,
    ) -> LogPattern | None:
        """Mark a pattern as ignored or not ignored.

        Args:
            pattern_id: The pattern UUID.
            ignored: Whether to ignore (True) or unignore (False).

        Returns:
            The updated pattern, or None if not found.
        """
        session = await self._get_session()
        should_close = self._session is None

        try:
            stmt = (
                update(LogPattern)
                .where(LogPattern.id == pattern_id)
                .values(is_ignored=ignored, updated_at=func.now())
                .returning(LogPattern)
            )
            result = await session.execute(stmt)
            pattern = result.scalar_one_or_none()
            await session.commit()
            return pattern

        finally:
            if should_close:
                await session.close()

    async def get_patterns_for_source(
        self,
        filters: PatternFilters,
    ) -> Sequence[LogPattern]:
        """Get patterns for a source with filters.

        Args:
            filters: Filter criteria.

        Returns:
            List of matching patterns.
        """
        session = await self._get_session()
        should_close = self._session is None

        try:
            conditions = []

            if filters.source_id:
                conditions.append(LogPattern.source_id == filters.source_id)

            if filters.is_ignored is not None:
                conditions.append(LogPattern.is_ignored == filters.is_ignored)

            if filters.rare_only:
                conditions.append(LogPattern.occurrence_count < filters.rarity_threshold)

            if filters.search:
                conditions.append(LogPattern.normalized_pattern.ilike(f"%{filters.search}%"))

            stmt = (
                select(LogPattern)
                .where(and_(*conditions) if conditions else True)
                .order_by(LogPattern.occurrence_count.asc())  # Rarest first
                .limit(filters.limit)
                .offset(filters.offset)
            )

            result = await session.execute(stmt)
            return result.scalars().all()

        finally:
            if should_close:
                await session.close()

    async def get_pattern_count(
        self,
        filters: PatternFilters,
    ) -> int:
        """Get count of patterns matching filters.

        Args:
            filters: Filter criteria.

        Returns:
            Count of matching patterns.
        """
        session = await self._get_session()
        should_close = self._session is None

        try:
            conditions = []

            if filters.source_id:
                conditions.append(LogPattern.source_id == filters.source_id)

            if filters.is_ignored is not None:
                conditions.append(LogPattern.is_ignored == filters.is_ignored)

            if filters.rare_only:
                conditions.append(LogPattern.occurrence_count < filters.rarity_threshold)

            if filters.search:
                conditions.append(LogPattern.normalized_pattern.ilike(f"%{filters.search}%"))

            stmt = select(func.count(LogPattern.id)).where(
                and_(*conditions) if conditions else True
            )

            result = await session.execute(stmt)
            return result.scalar_one()

        finally:
            if should_close:
                await session.close()

    async def delete_pattern(self, pattern_id: UUID) -> bool:
        """Delete a pattern.

        Args:
            pattern_id: The pattern UUID.

        Returns:
            True if deleted, False if not found.
        """
        session = await self._get_session()
        should_close = self._session is None

        try:
            pattern = await self.get_pattern_by_id(pattern_id)
            if not pattern:
                return False

            await session.delete(pattern)
            await session.commit()
            return True

        finally:
            if should_close:
                await session.close()


def get_pattern_service(session: AsyncSession | None = None) -> PatternService:
    """Factory function to get a PatternService instance.

    Args:
        session: Optional async session.

    Returns:
        PatternService instance.
    """
    return PatternService(session)
