"""Audit logging service for tracking administrative actions."""

from datetime import UTC, datetime, timedelta
from typing import Any
from uuid import UUID

import structlog
from sqlalchemy import and_, func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.db.session import AsyncSessionLocal
from app.models.audit_log import AuditAction, AuditLog
from app.models.user import User

logger = structlog.get_logger()


class AuditService:
    """Service for creating and querying audit logs."""

    def __init__(self, session: AsyncSession | None = None):
        """Initialize the audit service.

        Args:
            session: Optional database session. If not provided,
                     a new session will be created for each operation.
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

    async def log(
        self,
        action: AuditAction,
        target_type: str,
        description: str,
        user: User | None = None,
        target_id: str | None = None,
        target_name: str | None = None,
        details: dict[str, Any] | None = None,
        success: bool = True,
        error_message: str | None = None,
        ip_address: str | None = None,
        user_agent: str | None = None,
    ) -> AuditLog:
        """Create an audit log entry.

        Args:
            action: The type of action being logged
            target_type: Type of target (device, user, alert, etc.)
            description: Human-readable description of the action
            user: The user who performed the action (optional)
            target_id: ID of the target (optional)
            target_name: Name of the target (optional)
            details: Additional action details (optional)
            success: Whether the action was successful
            error_message: Error message if action failed
            ip_address: Client IP address
            user_agent: Client user agent string

        Returns:
            The created AuditLog entry
        """
        session = await self._get_session()
        try:
            audit_entry = AuditLog.create(
                action=action,
                target_type=target_type,
                description=description,
                user_id=user.id if user else None,
                username=user.username if user else None,
                target_id=target_id,
                target_name=target_name,
                details=details,
                success=success,
                error_message=error_message,
                ip_address=ip_address,
                user_agent=user_agent,
            )

            session.add(audit_entry)
            await session.commit()
            await session.refresh(audit_entry)

            # Also log to structlog for immediate visibility
            log_method = logger.info if success else logger.warning
            log_method(
                "Audit log created",
                action=action.value,
                target_type=target_type,
                target_id=target_id,
                user=user.username if user else "system",
                success=success,
            )

            return audit_entry

        except Exception as e:
            await session.rollback()
            logger.error("Failed to create audit log", error=str(e))
            raise
        finally:
            await self._close_session(session)

    async def log_device_quarantine(
        self,
        device_id: UUID,
        device_name: str,
        mac_address: str,
        user: User,
        reason: str | None = None,
        integration_results: list[dict[str, Any]] | None = None,
        ip_address: str | None = None,
    ) -> AuditLog:
        """Log a device quarantine action."""
        details = {
            "mac_address": mac_address,
            "reason": reason,
            "integration_results": integration_results or [],
        }

        return await self.log(
            action=AuditAction.DEVICE_QUARANTINE,
            target_type="device",
            description=f"Quarantined device {device_name} ({mac_address})",
            user=user,
            target_id=str(device_id),
            target_name=device_name,
            details=details,
            ip_address=ip_address,
        )

    async def log_device_release(
        self,
        device_id: UUID,
        device_name: str,
        mac_address: str,
        user: User,
        reason: str | None = None,
        integration_results: list[dict[str, Any]] | None = None,
        ip_address: str | None = None,
    ) -> AuditLog:
        """Log a device release action."""
        details = {
            "mac_address": mac_address,
            "reason": reason,
            "integration_results": integration_results or [],
        }

        return await self.log(
            action=AuditAction.DEVICE_RELEASE,
            target_type="device",
            description=f"Released device {device_name} ({mac_address}) from quarantine",
            user=user,
            target_id=str(device_id),
            target_name=device_name,
            details=details,
            ip_address=ip_address,
        )

    async def log_integration_action(
        self,
        action: AuditAction,
        integration_type: str,
        target: str,
        user: User | None = None,
        success: bool = True,
        details: dict[str, Any] | None = None,
        error_message: str | None = None,
    ) -> AuditLog:
        """Log an integration action (block/unblock via external service)."""
        action_desc = "blocked" if action == AuditAction.INTEGRATION_BLOCK else "unblocked"

        # Merge integration_type into details
        merged_details = {"integration_type": integration_type}
        if details:
            merged_details.update(details)

        return await self.log(
            action=action,
            target_type="integration",
            description=f"Device {action_desc} via {integration_type}",
            user=user,
            target_id=target,
            target_name=integration_type,
            details=merged_details,
            success=success,
            error_message=error_message,
        )

    async def log_user_login(
        self,
        user: User | None = None,
        username: str | None = None,
        ip_address: str | None = None,
        user_agent: str | None = None,
        success: bool = True,
        error_message: str | None = None,
    ) -> AuditLog:
        """Log a user login attempt.

        Args:
            user: The user who logged in (if successful)
            username: Username attempted (for failed logins)
            ip_address: Client IP address
            user_agent: Client user agent
            success: Whether the login was successful
            error_message: Error message if login failed
        """
        login_username = user.username if user else username or "unknown"

        return await self.log(
            action=AuditAction.USER_LOGIN,
            target_type="user",
            description=f"User login {'successful' if success else 'failed'}: {login_username}",
            user=user,
            target_id=str(user.id) if user else None,
            target_name=login_username,
            success=success,
            error_message=error_message,
            ip_address=ip_address,
            user_agent=user_agent,
        )

    async def get_logs(
        self,
        action: AuditAction | None = None,
        target_type: str | None = None,
        target_id: str | None = None,
        user_id: UUID | None = None,
        start_time: datetime | None = None,
        end_time: datetime | None = None,
        success_only: bool | None = None,
        limit: int = 100,
        offset: int = 0,
    ) -> list[AuditLog]:
        """Query audit logs with filtering.

        Args:
            action: Filter by action type
            target_type: Filter by target type
            target_id: Filter by target ID
            user_id: Filter by user who performed action
            start_time: Filter by start time
            end_time: Filter by end time
            success_only: Filter by success status
            limit: Maximum number of results
            offset: Number of results to skip

        Returns:
            List of matching audit log entries
        """
        session = await self._get_session()
        try:
            query = select(AuditLog)

            if action:
                query = query.where(AuditLog.action == action)
            if target_type:
                query = query.where(AuditLog.target_type == target_type)
            if target_id:
                query = query.where(AuditLog.target_id == target_id)
            if user_id:
                query = query.where(AuditLog.user_id == user_id)
            if start_time:
                query = query.where(AuditLog.timestamp >= start_time)
            if end_time:
                query = query.where(AuditLog.timestamp <= end_time)
            if success_only is not None:
                query = query.where(AuditLog.success == success_only)

            query = query.order_by(AuditLog.timestamp.desc())
            query = query.offset(offset).limit(limit)

            result = await session.execute(query)
            return list(result.scalars().all())

        finally:
            await self._close_session(session)

    async def get_device_history(
        self,
        device_id: UUID,
        limit: int = 50,
    ) -> list[AuditLog]:
        """Get audit history for a specific device."""
        return await self.get_logs(
            target_type="device",
            target_id=str(device_id),
            limit=limit,
        )

    async def get_quarantine_history(
        self,
        hours: int = 24,
        limit: int = 100,
    ) -> list[AuditLog]:
        """Get recent quarantine actions."""
        start_time = datetime.now(UTC) - timedelta(hours=hours)

        session = await self._get_session()
        try:
            query = (
                select(AuditLog)
                .where(
                    and_(
                        AuditLog.action.in_(
                            [
                                AuditAction.DEVICE_QUARANTINE,
                                AuditAction.DEVICE_RELEASE,
                            ]
                        ),
                        AuditLog.timestamp >= start_time,
                    )
                )
                .order_by(AuditLog.timestamp.desc())
                .limit(limit)
            )

            result = await session.execute(query)
            return list(result.scalars().all())

        finally:
            await self._close_session(session)

    async def count_actions(
        self,
        action: AuditAction,
        hours: int = 24,
    ) -> int:
        """Count actions of a specific type in the given time window."""
        start_time = datetime.now(UTC) - timedelta(hours=hours)

        session = await self._get_session()
        try:
            query = (
                select(func.count())
                .select_from(AuditLog)
                .where(
                    and_(
                        AuditLog.action == action,
                        AuditLog.timestamp >= start_time,
                    )
                )
            )

            result = await session.execute(query)
            return result.scalar() or 0

        finally:
            await self._close_session(session)


# Global service instance
_audit_service: AuditService | None = None


def get_audit_service() -> AuditService:
    """Get the global audit service instance."""
    global _audit_service
    if _audit_service is None:
        _audit_service = AuditService()
    return _audit_service
