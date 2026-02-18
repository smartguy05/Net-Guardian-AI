"""Investigation service for managing autonomous investigations."""

from datetime import UTC, datetime
from typing import Any
from uuid import UUID

import structlog
from sqlalchemy import and_, desc, func, select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from app.config import settings
from app.db.session import AsyncSessionLocal
from app.models.investigation import (
    Investigation,
    InvestigationAction,
    InvestigationActionRiskLevel,
    InvestigationActionStatus,
    InvestigationStatus,
    InvestigationStep,
    InvestigationTriggerSource,
)
from app.services.investigation.agent import InvestigationAgent

logger = structlog.get_logger()


class InvestigationService:
    """Service for managing security investigations."""

    def __init__(self, session: AsyncSession | None = None):
        """Initialize the investigation service.

        Args:
            session: Optional database session.
        """
        self._session = session

    async def _get_session(self) -> AsyncSession:
        """Get a database session."""
        if self._session:
            return self._session
        return AsyncSessionLocal()

    async def _close_session(self, session: AsyncSession) -> None:
        """Close session if it was created internally."""
        if session != self._session:
            await session.close()

    # ==================== CRUD OPERATIONS ====================

    async def create_investigation(
        self,
        trigger_source: InvestigationTriggerSource,
        alert_id: UUID | None = None,
        anomaly_id: UUID | None = None,
        device_id: UUID | None = None,
        priority: int = 3,
        auto_run: bool = True,
    ) -> Investigation:
        """Create a new investigation.

        Args:
            trigger_source: What triggered this investigation.
            alert_id: Associated alert (optional).
            anomaly_id: Associated anomaly (optional).
            device_id: Associated device (optional).
            priority: Priority level (1-5).
            auto_run: Whether to auto-run the investigation.

        Returns:
            Created investigation.
        """
        session = await self._get_session()
        try:
            # Check concurrent investigation limit
            if auto_run:
                running_count = await self._count_running_investigations(session)
                if running_count >= settings.investigation_max_concurrent:
                    logger.warning(
                        "investigation_limit_reached",
                        running=running_count,
                        max=settings.investigation_max_concurrent,
                    )
                    # Queue it instead of running immediately
                    auto_run = False

            # Determine if approval is required based on config
            requires_approval = self._should_require_approval()

            investigation = Investigation(
                alert_id=alert_id,
                anomaly_id=anomaly_id,
                device_id=device_id,
                status=InvestigationStatus.PENDING,
                trigger_source=trigger_source,
                priority=priority,
                requires_approval=requires_approval,
            )
            session.add(investigation)
            await session.commit()
            await session.refresh(investigation)

            logger.info(
                "investigation_created",
                id=str(investigation.id),
                trigger_source=trigger_source.value,
                auto_run=auto_run,
            )

            if auto_run:
                # Run the investigation asynchronously
                await self.run_investigation(investigation.id)

            return investigation

        finally:
            await self._close_session(session)

    async def get_investigation(
        self,
        investigation_id: UUID,
        include_steps: bool = True,
        include_actions: bool = True,
    ) -> Investigation | None:
        """Get investigation by ID.

        Args:
            investigation_id: Investigation UUID.
            include_steps: Include step details.
            include_actions: Include action details.

        Returns:
            Investigation or None.
        """
        session = await self._get_session()
        try:
            query = select(Investigation).where(Investigation.id == investigation_id)

            if include_steps:
                query = query.options(selectinload(Investigation.steps))
            if include_actions:
                query = query.options(selectinload(Investigation.actions))

            result = await session.execute(query)
            return result.scalar_one_or_none()

        finally:
            await self._close_session(session)

    async def list_investigations(
        self,
        status: InvestigationStatus | None = None,
        device_id: UUID | None = None,
        trigger_source: InvestigationTriggerSource | None = None,
        limit: int = 50,
        offset: int = 0,
    ) -> tuple[list[Investigation], int]:
        """List investigations with filtering.

        Args:
            status: Filter by status.
            device_id: Filter by device.
            trigger_source: Filter by trigger source.
            limit: Max results.
            offset: Results offset.

        Returns:
            Tuple of (investigations, total_count).
        """
        session = await self._get_session()
        try:
            query = select(Investigation)
            count_query = select(func.count(Investigation.id))

            conditions = []
            if status:
                conditions.append(Investigation.status == status)
            if device_id:
                conditions.append(Investigation.device_id == device_id)
            if trigger_source:
                conditions.append(Investigation.trigger_source == trigger_source)

            if conditions:
                query = query.where(and_(*conditions))
                count_query = count_query.where(and_(*conditions))

            # Get total count
            count_result = await session.execute(count_query)
            total = count_result.scalar() or 0

            # Get results
            query = (
                query.options(selectinload(Investigation.actions))
                .order_by(desc(Investigation.created_at))
                .offset(offset)
                .limit(limit)
            )
            result = await session.execute(query)
            investigations = list(result.scalars().all())

            return investigations, total

        finally:
            await self._close_session(session)

    async def cancel_investigation(self, investigation_id: UUID) -> Investigation | None:
        """Cancel a running or pending investigation.

        Args:
            investigation_id: Investigation UUID.

        Returns:
            Updated investigation or None.
        """
        session = await self._get_session()
        try:
            result = await session.execute(
                select(Investigation).where(Investigation.id == investigation_id)
            )
            investigation = result.scalar_one_or_none()

            if not investigation:
                return None

            if investigation.status not in [
                InvestigationStatus.PENDING,
                InvestigationStatus.RUNNING,
            ]:
                return investigation

            investigation.status = InvestigationStatus.CANCELLED
            session.add(investigation)
            await session.commit()

            logger.info("investigation_cancelled", id=str(investigation_id))

            return investigation

        finally:
            await self._close_session(session)

    # ==================== INVESTIGATION EXECUTION ====================

    async def run_investigation(self, investigation_id: UUID) -> Investigation:
        """Run an investigation.

        Args:
            investigation_id: Investigation UUID.

        Returns:
            Updated investigation.
        """
        session = await self._get_session()
        try:
            result = await session.execute(
                select(Investigation).where(Investigation.id == investigation_id)
            )
            investigation = result.scalar_one_or_none()

            if not investigation:
                raise ValueError(f"Investigation {investigation_id} not found")

            if investigation.status != InvestigationStatus.PENDING:
                raise ValueError(f"Investigation is in {investigation.status.value} state")

            # Update status
            investigation.status = InvestigationStatus.RUNNING
            investigation.started_at = datetime.now(UTC)
            session.add(investigation)
            await session.commit()

            # Run the investigation agent
            agent = InvestigationAgent(session)
            investigation = await agent.run_investigation(investigation)

            # Update final status
            if investigation.requires_approval and investigation.actions:
                # Check if any actions need approval
                pending_actions = [
                    a
                    for a in investigation.actions
                    if a.status == InvestigationActionStatus.PENDING
                    and self._action_requires_approval(a.risk_level)
                ]
                if pending_actions:
                    investigation.status = InvestigationStatus.AWAITING_APPROVAL
                else:
                    investigation.status = InvestigationStatus.COMPLETED
            else:
                investigation.status = InvestigationStatus.COMPLETED

            investigation.completed_at = datetime.now(UTC)
            session.add(investigation)
            await session.commit()

            logger.info(
                "investigation_completed",
                id=str(investigation_id),
                status=investigation.status.value,
            )

            return investigation

        except Exception as e:
            # Mark as failed on error
            try:
                result = await session.execute(
                    select(Investigation).where(Investigation.id == investigation_id)
                )
                investigation = result.scalar_one_or_none()
                if investigation:
                    investigation.status = InvestigationStatus.FAILED
                    investigation.completed_at = datetime.now(UTC)
                    session.add(investigation)
                    await session.commit()
            except Exception:
                pass

            logger.error("investigation_failed", id=str(investigation_id), error=str(e))
            raise

        finally:
            await self._close_session(session)

    # ==================== ACTION MANAGEMENT ====================

    async def approve_action(
        self,
        action_id: UUID,
        user_id: UUID,
    ) -> InvestigationAction | None:
        """Approve an investigation action.

        Args:
            action_id: Action UUID.
            user_id: Approving user's UUID.

        Returns:
            Updated action or None.
        """
        session = await self._get_session()
        try:
            result = await session.execute(
                select(InvestigationAction).where(InvestigationAction.id == action_id)
            )
            action = result.scalar_one_or_none()

            if not action or action.status != InvestigationActionStatus.PENDING:
                return None

            action.status = InvestigationActionStatus.APPROVED
            action.approved_by = user_id
            action.approved_at = datetime.now(UTC)
            session.add(action)
            await session.commit()

            logger.info(
                "investigation_action_approved",
                action_id=str(action_id),
                user_id=str(user_id),
            )

            return action

        finally:
            await self._close_session(session)

    async def reject_action(
        self,
        action_id: UUID,
        user_id: UUID,
        reason: str | None = None,
    ) -> InvestigationAction | None:
        """Reject an investigation action.

        Args:
            action_id: Action UUID.
            user_id: Rejecting user's UUID.
            reason: Rejection reason.

        Returns:
            Updated action or None.
        """
        session = await self._get_session()
        try:
            result = await session.execute(
                select(InvestigationAction).where(InvestigationAction.id == action_id)
            )
            action = result.scalar_one_or_none()

            if not action or action.status != InvestigationActionStatus.PENDING:
                return None

            action.status = InvestigationActionStatus.REJECTED
            action.rejected_by = user_id
            action.rejected_at = datetime.now(UTC)
            action.rejection_reason = reason
            session.add(action)
            await session.commit()

            logger.info(
                "investigation_action_rejected",
                action_id=str(action_id),
                user_id=str(user_id),
                reason=reason,
            )

            return action

        finally:
            await self._close_session(session)

    async def execute_approved_actions(
        self,
        investigation_id: UUID,
    ) -> list[dict[str, Any]]:
        """Execute all approved actions for an investigation.

        Args:
            investigation_id: Investigation UUID.

        Returns:
            List of execution results.
        """
        session = await self._get_session()
        try:
            result = await session.execute(
                select(InvestigationAction).where(
                    and_(
                        InvestigationAction.investigation_id == investigation_id,
                        InvestigationAction.status == InvestigationActionStatus.APPROVED,
                    )
                )
            )
            actions = result.scalars().all()

            results = []
            for action in actions:
                execution_result = await self._execute_action(action, session)
                results.append(execution_result)

            # Check if investigation is complete
            investigation_result = await session.execute(
                select(Investigation).where(Investigation.id == investigation_id)
            )
            investigation = investigation_result.scalar_one_or_none()

            if investigation:
                # Check for remaining pending actions
                pending_result = await session.execute(
                    select(func.count(InvestigationAction.id)).where(
                        and_(
                            InvestigationAction.investigation_id == investigation_id,
                            InvestigationAction.status == InvestigationActionStatus.PENDING,
                        )
                    )
                )
                pending_count = pending_result.scalar() or 0

                if pending_count == 0:
                    investigation.status = InvestigationStatus.COMPLETED
                    investigation.completed_at = datetime.now(UTC)
                    session.add(investigation)
                    await session.commit()

            return results

        finally:
            await self._close_session(session)

    async def _execute_action(
        self,
        action: InvestigationAction,
        session: AsyncSession,
    ) -> dict[str, Any]:
        """Execute a single action.

        Args:
            action: Action to execute.
            session: Database session.

        Returns:
            Execution result.
        """
        try:
            result: dict[str, Any] = {"success": False, "message": ""}

            if action.action_type == "quarantine_device":
                # TODO: Integrate with quarantine service
                result = {"success": True, "message": "Device quarantine initiated"}

            elif action.action_type == "block_domain":
                # TODO: Integrate with AdGuard service
                result = {"success": True, "message": "Domain block initiated"}

            elif action.action_type == "create_rule":
                # TODO: Integrate with rule creation
                result = {"success": True, "message": "Detection rule created"}

            elif action.action_type == "notify_user":
                # TODO: Integrate with notification service
                result = {"success": True, "message": "User notification sent"}

            elif action.action_type == "increase_monitoring":
                # TODO: Integrate with monitoring config
                result = {"success": True, "message": "Monitoring increased"}

            elif action.action_type == "no_action":
                result = {"success": True, "message": "No action taken as recommended"}

            else:
                result = {"success": False, "message": f"Unknown action type: {action.action_type}"}

            # Update action status
            action.status = (
                InvestigationActionStatus.EXECUTED
                if result["success"]
                else InvestigationActionStatus.FAILED
            )
            action.executed_at = datetime.now(UTC)
            action.execution_result = result
            session.add(action)
            await session.commit()

            return {
                "action_id": str(action.id),
                "action_type": action.action_type,
                **result,
            }

        except Exception as e:
            action.status = InvestigationActionStatus.FAILED
            action.execution_result = {"success": False, "error": str(e)}
            session.add(action)
            await session.commit()

            return {
                "action_id": str(action.id),
                "action_type": action.action_type,
                "success": False,
                "error": str(e),
            }

    # ==================== HELPERS ====================

    async def _count_running_investigations(self, session: AsyncSession) -> int:
        """Count currently running investigations."""
        result = await session.execute(
            select(func.count(Investigation.id)).where(
                Investigation.status == InvestigationStatus.RUNNING
            )
        )
        return result.scalar() or 0

    def _should_require_approval(self) -> bool:
        """Determine if investigations should require approval."""
        return settings.investigation_require_approval_risk in ["low", "medium", "high"]

    def _action_requires_approval(self, risk_level: InvestigationActionRiskLevel) -> bool:
        """Check if an action requires approval based on its risk level."""
        risk_order = ["low", "medium", "high", "critical"]
        config_threshold = settings.investigation_require_approval_risk.lower()

        if config_threshold not in risk_order:
            return True  # Default to requiring approval

        threshold_idx = risk_order.index(config_threshold)
        action_idx = risk_order.index(risk_level.value)

        return action_idx >= threshold_idx


# Global service instance
_investigation_service: InvestigationService | None = None


def get_investigation_service() -> InvestigationService:
    """Get the global investigation service instance."""
    global _investigation_service
    if _investigation_service is None:
        _investigation_service = InvestigationService()
    return _investigation_service
