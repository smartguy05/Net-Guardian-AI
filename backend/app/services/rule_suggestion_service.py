"""Rule suggestion service for managing LLM-generated detection rules."""

import hashlib
import json
from dataclasses import dataclass
from datetime import datetime
from typing import Any, Dict, List, Optional, Sequence
from uuid import UUID

import structlog
from sqlalchemy import and_, func, select, update
from sqlalchemy.ext.asyncio import AsyncSession

from app.db.session import AsyncSessionLocal
from app.models.semantic_analysis import (
    IrregularLog,
    SemanticAnalysisRun,
    SuggestedRule,
    SuggestedRuleHistory,
    SuggestedRuleStatus,
    SuggestedRuleType,
)
from app.models.detection_rule import DetectionRule
from app.models.alert import AlertSeverity
from app.services.llm_providers.base import SuggestedRuleData

logger = structlog.get_logger()


@dataclass
class RuleFilters:
    """Filters for suggested rule queries."""

    source_id: Optional[str] = None
    status: Optional[SuggestedRuleStatus] = None
    rule_type: Optional[SuggestedRuleType] = None
    search: Optional[str] = None
    limit: int = 100
    offset: int = 0


@dataclass
class HistoryFilters:
    """Filters for rule history queries."""

    status: Optional[SuggestedRuleStatus] = None
    limit: int = 100
    offset: int = 0


class RuleSuggestionService:
    """Service for managing LLM-generated detection rule suggestions."""

    def __init__(self, session: Optional[AsyncSession] = None):
        """Initialize the service.

        Args:
            session: Optional async session.
        """
        self._session = session

    async def _get_session(self) -> AsyncSession:
        """Get or create an async session."""
        if self._session:
            return self._session
        return AsyncSessionLocal()

    def compute_rule_hash(self, rule_config: Dict[str, Any]) -> str:
        """Compute a deterministic hash for deduplication.

        Args:
            rule_config: The rule configuration dict.

        Returns:
            SHA-256 hash of the normalized config.
        """
        # Normalize the config for consistent hashing
        normalized = json.dumps(rule_config, sort_keys=True, separators=(",", ":"))
        return hashlib.sha256(normalized.encode("utf-8")).hexdigest()

    async def is_duplicate(self, rule_hash: str) -> bool:
        """Check if a rule hash already exists in history.

        Args:
            rule_hash: The rule hash to check.

        Returns:
            True if the rule has been previously suggested.
        """
        session = await self._get_session()
        should_close = self._session is None

        try:
            stmt = select(SuggestedRuleHistory).where(
                SuggestedRuleHistory.rule_hash == rule_hash
            )
            result = await session.execute(stmt)
            return result.scalar_one_or_none() is not None

        finally:
            if should_close:
                await session.close()

    async def create_from_llm_response(
        self,
        analysis_run: SemanticAnalysisRun,
        irregular_log: IrregularLog,
        suggested_rule: SuggestedRuleData,
        source_id: Optional[str] = None,
    ) -> Optional[SuggestedRule]:
        """Create a rule suggestion from LLM response.

        Args:
            analysis_run: The analysis run that generated this.
            irregular_log: The irregular log that triggered the suggestion.
            suggested_rule: The rule data from LLM.
            source_id: Optional source to scope the rule.

        Returns:
            The created rule, or None if duplicate.
        """
        session = await self._get_session()
        should_close = self._session is None

        try:
            # Compute hash for deduplication
            rule_hash = self.compute_rule_hash(suggested_rule.rule_config)

            # Check for duplicates
            if await self.is_duplicate(rule_hash):
                logger.debug(
                    "duplicate_rule_suggestion",
                    rule_name=suggested_rule.name,
                    rule_hash=rule_hash,
                )
                return None

            # Map rule type
            rule_type_map = {
                "pattern_match": SuggestedRuleType.PATTERN_MATCH,
                "threshold": SuggestedRuleType.THRESHOLD,
                "sequence": SuggestedRuleType.SEQUENCE,
            }
            rule_type = rule_type_map.get(
                suggested_rule.rule_type.lower(),
                SuggestedRuleType.PATTERN_MATCH,
            )

            rule = SuggestedRule(
                source_id=source_id,
                analysis_run_id=analysis_run.id,
                irregular_log_id=irregular_log.id,
                name=suggested_rule.name[:255],  # Ensure fits in column
                description=suggested_rule.description,
                reason=suggested_rule.reason,
                benefit=suggested_rule.benefit,
                rule_type=rule_type,
                rule_config=suggested_rule.rule_config,
                status=SuggestedRuleStatus.PENDING,
                enabled=False,
                rule_hash=rule_hash,
            )

            session.add(rule)
            await session.commit()
            await session.refresh(rule)

            logger.info(
                "rule_suggestion_created",
                rule_id=str(rule.id),
                rule_name=rule.name,
                source_id=source_id,
            )

            return rule

        finally:
            if should_close:
                await session.close()

    async def create_rules_from_analysis(
        self,
        analysis_run: SemanticAnalysisRun,
        logs_data: List[Dict[str, Any]],
        suggested_rules: List[SuggestedRuleData],
    ) -> List[SuggestedRule]:
        """Create multiple rule suggestions from an analysis run.

        Args:
            analysis_run: The analysis run.
            logs_data: List of log data with irregular_id mappings.
            suggested_rules: List of rule suggestions from LLM.

        Returns:
            List of created rules.
        """
        created_rules = []

        for rule_data in suggested_rules:
            # Get the irregular log this rule was suggested for
            if rule_data.log_index < len(logs_data):
                irregular_id = logs_data[rule_data.log_index].get("irregular_id")
                if irregular_id:
                    irregular_log = await self.get_irregular_log(irregular_id)
                    if irregular_log:
                        rule = await self.create_from_llm_response(
                            analysis_run=analysis_run,
                            irregular_log=irregular_log,
                            suggested_rule=rule_data,
                            source_id=analysis_run.source_id,
                        )
                        if rule:
                            created_rules.append(rule)

        return created_rules

    async def get_irregular_log(self, irregular_id: UUID) -> Optional[IrregularLog]:
        """Get an irregular log by ID (helper method).

        Args:
            irregular_id: The ID.

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

    async def get_pending_rules(
        self,
        filters: Optional[RuleFilters] = None,
    ) -> Sequence[SuggestedRule]:
        """Get pending rule suggestions.

        Args:
            filters: Optional additional filters.

        Returns:
            List of pending rules.
        """
        filters = filters or RuleFilters()
        filters.status = SuggestedRuleStatus.PENDING
        return await self.get_rules(filters)

    async def get_rules(
        self,
        filters: RuleFilters,
    ) -> Sequence[SuggestedRule]:
        """Get suggested rules with filters.

        Args:
            filters: Filter criteria.

        Returns:
            List of matching rules.
        """
        session = await self._get_session()
        should_close = self._session is None

        try:
            conditions = []

            if filters.source_id:
                conditions.append(SuggestedRule.source_id == filters.source_id)

            if filters.status:
                conditions.append(SuggestedRule.status == filters.status)

            if filters.rule_type:
                conditions.append(SuggestedRule.rule_type == filters.rule_type)

            if filters.search:
                search_term = f"%{filters.search}%"
                conditions.append(
                    SuggestedRule.name.ilike(search_term)
                    | SuggestedRule.description.ilike(search_term)
                )

            stmt = (
                select(SuggestedRule)
                .where(and_(*conditions) if conditions else True)
                .order_by(SuggestedRule.created_at.desc())
                .limit(filters.limit)
                .offset(filters.offset)
            )

            result = await session.execute(stmt)
            return result.scalars().all()

        finally:
            if should_close:
                await session.close()

    async def get_rule_by_id(self, rule_id: UUID) -> Optional[SuggestedRule]:
        """Get a suggested rule by ID.

        Args:
            rule_id: The rule ID.

        Returns:
            The rule if found.
        """
        session = await self._get_session()
        should_close = self._session is None

        try:
            stmt = select(SuggestedRule).where(SuggestedRule.id == rule_id)
            result = await session.execute(stmt)
            return result.scalar_one_or_none()

        finally:
            if should_close:
                await session.close()

    async def get_rule_count(self, filters: RuleFilters) -> int:
        """Get count of rules matching filters.

        Args:
            filters: Filter criteria.

        Returns:
            Count of matching rules.
        """
        session = await self._get_session()
        should_close = self._session is None

        try:
            conditions = []

            if filters.source_id:
                conditions.append(SuggestedRule.source_id == filters.source_id)

            if filters.status:
                conditions.append(SuggestedRule.status == filters.status)

            if filters.rule_type:
                conditions.append(SuggestedRule.rule_type == filters.rule_type)

            stmt = select(func.count(SuggestedRule.id)).where(
                and_(*conditions) if conditions else True
            )

            result = await session.execute(stmt)
            return result.scalar_one()

        finally:
            if should_close:
                await session.close()

    async def approve_rule(
        self,
        rule_id: UUID,
        user_id: UUID,
        enable: bool = False,
        config_overrides: Optional[Dict[str, Any]] = None,
    ) -> Optional[SuggestedRule]:
        """Approve a suggested rule.

        Args:
            rule_id: The rule ID.
            user_id: The approving user's ID.
            enable: Whether to enable the rule immediately.
            config_overrides: Optional config modifications.

        Returns:
            The approved rule, or None if not found.
        """
        session = await self._get_session()
        should_close = self._session is None

        try:
            rule = await self.get_rule_by_id(rule_id)
            if not rule:
                return None

            if rule.status != SuggestedRuleStatus.PENDING:
                raise ValueError(f"Rule is not pending (status: {rule.status.value})")

            # Merge config overrides if provided
            final_config = rule.rule_config.copy()
            if config_overrides:
                final_config.update(config_overrides)

            # Update the rule
            new_status = (
                SuggestedRuleStatus.IMPLEMENTED
                if enable
                else SuggestedRuleStatus.APPROVED
            )

            stmt = (
                update(SuggestedRule)
                .where(SuggestedRule.id == rule_id)
                .values(
                    status=new_status,
                    enabled=enable,
                    rule_config=final_config,
                    reviewed_by=user_id,
                    reviewed_at=datetime.utcnow(),
                    updated_at=func.now(),
                )
                .returning(SuggestedRule)
            )
            result = await session.execute(stmt)
            updated_rule = result.scalar_one()

            # Create history entry
            history = SuggestedRuleHistory(
                rule_hash=rule.rule_hash,
                original_rule_id=rule.id,
                status=new_status,
            )
            session.add(history)

            # If enabled, create actual detection rule
            if enable:
                await self._create_detection_rule(session, updated_rule)

            await session.commit()

            logger.info(
                "rule_approved",
                rule_id=str(rule_id),
                user_id=str(user_id),
                enabled=enable,
            )

            return updated_rule

        finally:
            if should_close:
                await session.close()

    async def reject_rule(
        self,
        rule_id: UUID,
        user_id: UUID,
        reason: str,
    ) -> Optional[SuggestedRule]:
        """Reject a suggested rule.

        Args:
            rule_id: The rule ID.
            user_id: The rejecting user's ID.
            reason: Reason for rejection.

        Returns:
            The rejected rule, or None if not found.
        """
        session = await self._get_session()
        should_close = self._session is None

        try:
            rule = await self.get_rule_by_id(rule_id)
            if not rule:
                return None

            if rule.status != SuggestedRuleStatus.PENDING:
                raise ValueError(f"Rule is not pending (status: {rule.status.value})")

            # Update the rule
            stmt = (
                update(SuggestedRule)
                .where(SuggestedRule.id == rule_id)
                .values(
                    status=SuggestedRuleStatus.REJECTED,
                    reviewed_by=user_id,
                    reviewed_at=datetime.utcnow(),
                    rejection_reason=reason,
                    updated_at=func.now(),
                )
                .returning(SuggestedRule)
            )
            result = await session.execute(stmt)
            updated_rule = result.scalar_one()

            # Create history entry
            history = SuggestedRuleHistory(
                rule_hash=rule.rule_hash,
                original_rule_id=rule.id,
                status=SuggestedRuleStatus.REJECTED,
            )
            session.add(history)

            await session.commit()

            logger.info(
                "rule_rejected",
                rule_id=str(rule_id),
                user_id=str(user_id),
                reason=reason,
            )

            return updated_rule

        finally:
            if should_close:
                await session.close()

    async def _create_detection_rule(
        self,
        session: AsyncSession,
        suggested_rule: SuggestedRule,
    ) -> DetectionRule:
        """Create an actual detection rule from a suggested rule.

        Args:
            session: Database session.
            suggested_rule: The approved suggested rule.

        Returns:
            The created detection rule.
        """
        import re

        # Generate a unique ID for the rule
        base_id = re.sub(r"[^a-z0-9-]", "-", suggested_rule.name.lower())
        base_id = re.sub(r"-+", "-", base_id).strip("-")[:80]
        rule_id = f"auto-{base_id}-{str(suggested_rule.id)[:8]}"

        # Map rule config to detection rule conditions
        rule_config = suggested_rule.rule_config
        conditions = self._map_rule_config_to_conditions(
            suggested_rule.rule_type,
            rule_config,
        )

        # Determine severity based on the irregular log's severity
        severity = AlertSeverity.MEDIUM
        if suggested_rule.irregular_log:
            score = suggested_rule.irregular_log.severity_score or 0.5
            if score >= 0.8:
                severity = AlertSeverity.CRITICAL
            elif score >= 0.6:
                severity = AlertSeverity.HIGH
            elif score >= 0.4:
                severity = AlertSeverity.MEDIUM
            else:
                severity = AlertSeverity.LOW

        detection_rule = DetectionRule(
            id=rule_id,
            name=f"[Auto] {suggested_rule.name}",
            description=f"{suggested_rule.description}\n\nReason: {suggested_rule.reason}\nBenefit: {suggested_rule.benefit}",
            severity=severity,
            enabled=True,
            conditions=conditions,
            response_actions=[
                {"type": "create_alert", "params": {}},
            ],
            cooldown_minutes=60,
        )

        session.add(detection_rule)

        logger.info(
            "detection_rule_created_from_suggestion",
            detection_rule_id=rule_id,
            suggested_rule_id=str(suggested_rule.id),
        )

        return detection_rule

    def _map_rule_config_to_conditions(
        self,
        rule_type: SuggestedRuleType,
        config: Dict[str, Any],
    ) -> Dict[str, Any]:
        """Map LLM rule config to detection rule conditions.

        Args:
            rule_type: The type of rule.
            config: The rule configuration from LLM.

        Returns:
            Conditions dict for DetectionRule.
        """
        if rule_type == SuggestedRuleType.PATTERN_MATCH:
            pattern = config.get("pattern", "")
            fields = config.get("fields", ["raw_message"])

            conditions = []
            for field in fields:
                conditions.append({
                    "field": field,
                    "operator": "regex",
                    "value": pattern,
                })

            return {
                "logic": "or" if len(conditions) > 1 else "and",
                "conditions": conditions,
            }

        elif rule_type == SuggestedRuleType.THRESHOLD:
            return {
                "logic": "and",
                "conditions": [
                    {
                        "field": config.get("field", "count"),
                        "operator": "gte",
                        "value": config.get("threshold", 10),
                    },
                ],
                "time_window_minutes": config.get("time_window", 60),
            }

        elif rule_type == SuggestedRuleType.SEQUENCE:
            return {
                "logic": "sequence",
                "conditions": config.get("sequence", []),
                "time_window_minutes": config.get("time_window", 60),
            }

        return {"logic": "and", "conditions": []}

    async def get_history(
        self,
        filters: HistoryFilters,
    ) -> Sequence[SuggestedRuleHistory]:
        """Get rule suggestion history.

        Args:
            filters: Filter criteria.

        Returns:
            List of history entries.
        """
        session = await self._get_session()
        should_close = self._session is None

        try:
            conditions = []

            if filters.status:
                conditions.append(SuggestedRuleHistory.status == filters.status)

            stmt = (
                select(SuggestedRuleHistory)
                .where(and_(*conditions) if conditions else True)
                .order_by(SuggestedRuleHistory.created_at.desc())
                .limit(filters.limit)
                .offset(filters.offset)
            )

            result = await session.execute(stmt)
            return result.scalars().all()

        finally:
            if should_close:
                await session.close()


def get_rule_suggestion_service(
    session: Optional[AsyncSession] = None,
) -> RuleSuggestionService:
    """Factory function to get a RuleSuggestionService instance.

    Args:
        session: Optional async session.

    Returns:
        RuleSuggestionService instance.
    """
    return RuleSuggestionService(session)
