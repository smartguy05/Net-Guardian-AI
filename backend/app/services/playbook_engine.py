"""Playbook engine for automated response actions."""

from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional
from uuid import UUID

import structlog
from sqlalchemy import and_, func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.db.session import AsyncSessionLocal
from app.models.device import Device
from app.models.playbook import (
    ExecutionStatus,
    Playbook,
    PlaybookActionType,
    PlaybookExecution,
    PlaybookStatus,
    PlaybookTriggerType,
)
from app.models.user import User
from app.services.audit_service import AuditService, get_audit_service
from app.services.quarantine_service import QuarantineService, get_quarantine_service

logger = structlog.get_logger()


class PlaybookEngine:
    """Engine for executing response playbooks.

    The playbook engine evaluates triggers, executes actions, and tracks
    execution history. It supports both automatic and manual playbook execution.
    """

    def __init__(
        self,
        session: Optional[AsyncSession] = None,
        quarantine_service: Optional[QuarantineService] = None,
        audit_service: Optional[AuditService] = None,
    ):
        """Initialize the playbook engine."""
        self._session = session
        self._quarantine = quarantine_service or get_quarantine_service()
        self._audit = audit_service or get_audit_service()

    async def _get_session(self) -> AsyncSession:
        """Get a database session."""
        if self._session:
            return self._session
        return AsyncSessionLocal()

    async def _close_session(self, session: AsyncSession):
        """Close session if it was created internally."""
        if session != self._session:
            await session.close()

    async def evaluate_triggers(
        self,
        trigger_type: PlaybookTriggerType,
        event_data: Dict[str, Any],
        device_id: Optional[UUID] = None,
    ) -> List[Playbook]:
        """Find playbooks that match the given trigger.

        Args:
            trigger_type: The type of trigger event
            event_data: Data about the triggering event
            device_id: Optional device involved in the event

        Returns:
            List of playbooks that should be executed
        """
        session = await self._get_session()
        try:
            # Get active playbooks with matching trigger type
            result = await session.execute(
                select(Playbook).where(
                    and_(
                        Playbook.status == PlaybookStatus.ACTIVE,
                        Playbook.trigger_type == trigger_type,
                    )
                )
            )
            playbooks = result.scalars().all()

            matching = []
            for playbook in playbooks:
                if await self._check_trigger_conditions(
                    playbook, event_data, device_id
                ):
                    # Check rate limits
                    if await self._check_rate_limits(session, playbook):
                        matching.append(playbook)

            return matching

        finally:
            await self._close_session(session)

    async def _check_trigger_conditions(
        self,
        playbook: Playbook,
        event_data: Dict[str, Any],
        device_id: Optional[UUID],
    ) -> bool:
        """Check if the event matches the playbook's trigger conditions."""
        conditions = playbook.trigger_conditions

        # Check severity threshold
        if "min_severity" in conditions:
            event_severity = event_data.get("severity", "low")
            severity_order = ["low", "medium", "high", "critical"]
            if severity_order.index(event_severity) < severity_order.index(
                conditions["min_severity"]
            ):
                return False

        # Check device type filter
        if "device_types" in conditions and device_id:
            session = await self._get_session()
            try:
                result = await session.execute(
                    select(Device).where(Device.id == device_id)
                )
                device = result.scalar_one_or_none()
                if device and device.device_type.value not in conditions["device_types"]:
                    return False
            finally:
                await self._close_session(session)

        # Check anomaly type filter
        if "anomaly_types" in conditions:
            event_type = event_data.get("anomaly_type")
            if event_type and event_type not in conditions["anomaly_types"]:
                return False

        # Check tag filter
        if "required_tags" in conditions and device_id:
            session = await self._get_session()
            try:
                result = await session.execute(
                    select(Device).where(Device.id == device_id)
                )
                device = result.scalar_one_or_none()
                if device:
                    device_tags = set(device.profile_tags or [])
                    required_tags = set(conditions["required_tags"])
                    if not required_tags.issubset(device_tags):
                        return False
            finally:
                await self._close_session(session)

        # Check excluded tags
        if "excluded_tags" in conditions and device_id:
            session = await self._get_session()
            try:
                result = await session.execute(
                    select(Device).where(Device.id == device_id)
                )
                device = result.scalar_one_or_none()
                if device:
                    device_tags = set(device.profile_tags or [])
                    excluded_tags = set(conditions["excluded_tags"])
                    if device_tags.intersection(excluded_tags):
                        return False
            finally:
                await self._close_session(session)

        return True

    async def _check_rate_limits(
        self, session: AsyncSession, playbook: Playbook
    ) -> bool:
        """Check if the playbook is within rate limits."""
        now = datetime.now(timezone.utc)

        # Check cooldown
        result = await session.execute(
            select(PlaybookExecution)
            .where(
                and_(
                    PlaybookExecution.playbook_id == playbook.id,
                    PlaybookExecution.created_at
                    > now - timedelta(minutes=playbook.cooldown_minutes),
                )
            )
            .order_by(PlaybookExecution.created_at.desc())
            .limit(1)
        )
        recent = result.scalar_one_or_none()
        if recent:
            logger.debug(
                "Playbook in cooldown",
                playbook_id=str(playbook.id),
                last_execution=recent.created_at.isoformat(),
            )
            return False

        # Check max executions per hour
        result = await session.execute(
            select(func.count(PlaybookExecution.id)).where(
                and_(
                    PlaybookExecution.playbook_id == playbook.id,
                    PlaybookExecution.created_at > now - timedelta(hours=1),
                )
            )
        )
        count = result.scalar() or 0
        if count >= playbook.max_executions_per_hour:
            logger.debug(
                "Playbook exceeded hourly limit",
                playbook_id=str(playbook.id),
                executions_this_hour=count,
            )
            return False

        return True

    async def execute_playbook(
        self,
        playbook: Playbook,
        trigger_event: Dict[str, Any],
        device_id: Optional[UUID] = None,
        triggered_by: Optional[User] = None,
    ) -> PlaybookExecution:
        """Execute a playbook.

        Args:
            playbook: The playbook to execute
            trigger_event: Data about the triggering event
            device_id: Optional device involved
            triggered_by: Optional user who triggered (null for automatic)

        Returns:
            The execution record
        """
        session = await self._get_session()
        try:
            # Create execution record
            execution = PlaybookExecution(
                playbook_id=playbook.id,
                status=ExecutionStatus.RUNNING,
                trigger_event=trigger_event,
                trigger_device_id=device_id,
                triggered_by=triggered_by.id if triggered_by else None,
                started_at=datetime.now(timezone.utc),
                action_results=[],
            )
            session.add(execution)
            await session.commit()

            logger.info(
                "Executing playbook",
                playbook_id=str(playbook.id),
                playbook_name=playbook.name,
                execution_id=str(execution.id),
                device_id=str(device_id) if device_id else None,
            )

            # Execute each action
            action_results = []
            for i, action in enumerate(playbook.actions):
                try:
                    result = await self._execute_action(
                        action, trigger_event, device_id, triggered_by
                    )
                    action_results.append({
                        "action_index": i,
                        "action_type": action.get("type"),
                        "success": result.get("success", False),
                        "result": result,
                    })

                    # Stop on failure if configured
                    if not result.get("success", False) and action.get(
                        "stop_on_failure", False
                    ):
                        execution.error_message = f"Action {i} failed: {result.get('error')}"
                        break

                except Exception as e:
                    logger.error(
                        "Action execution failed",
                        playbook_id=str(playbook.id),
                        action_index=i,
                        error=str(e),
                    )
                    action_results.append({
                        "action_index": i,
                        "action_type": action.get("type"),
                        "success": False,
                        "error": str(e),
                    })

                    if action.get("stop_on_failure", False):
                        execution.error_message = f"Action {i} failed: {str(e)}"
                        break

            # Update execution record
            execution.action_results = action_results
            execution.completed_at = datetime.now(timezone.utc)
            execution.status = (
                ExecutionStatus.COMPLETED
                if all(r.get("success", False) for r in action_results)
                else ExecutionStatus.FAILED
            )

            await session.commit()
            await session.refresh(execution)

            logger.info(
                "Playbook execution completed",
                playbook_id=str(playbook.id),
                execution_id=str(execution.id),
                status=execution.status.value,
                actions_executed=len(action_results),
            )

            return execution

        except Exception as e:
            await session.rollback()
            logger.error(
                "Playbook execution failed",
                playbook_id=str(playbook.id),
                error=str(e),
            )
            raise

        finally:
            await self._close_session(session)

    async def _execute_action(
        self,
        action: Dict[str, Any],
        trigger_event: Dict[str, Any],
        device_id: Optional[UUID],
        user: Optional[User],
    ) -> Dict[str, Any]:
        """Execute a single playbook action."""
        action_type = action.get("type")
        params = action.get("params", {})

        if action_type == PlaybookActionType.QUARANTINE_DEVICE.value:
            return await self._action_quarantine_device(
                device_id, params, user, trigger_event
            )

        elif action_type == PlaybookActionType.RELEASE_DEVICE.value:
            return await self._action_release_device(
                device_id, params, user, trigger_event
            )

        elif action_type == PlaybookActionType.CREATE_ALERT.value:
            return await self._action_create_alert(
                device_id, params, trigger_event
            )

        elif action_type == PlaybookActionType.TAG_DEVICE.value:
            return await self._action_tag_device(device_id, params)

        elif action_type == PlaybookActionType.SEND_NOTIFICATION.value:
            return await self._action_send_notification(
                params, trigger_event, device_id
            )

        elif action_type == PlaybookActionType.LOG_EVENT.value:
            return await self._action_log_event(params, trigger_event, device_id)

        elif action_type == PlaybookActionType.EXECUTE_WEBHOOK.value:
            return await self._action_execute_webhook(
                params, trigger_event, device_id
            )

        else:
            return {
                "success": False,
                "error": f"Unknown action type: {action_type}",
            }

    async def _action_quarantine_device(
        self,
        device_id: Optional[UUID],
        params: Dict[str, Any],
        user: Optional[User],
        trigger_event: Dict[str, Any],
    ) -> Dict[str, Any]:
        """Execute quarantine device action."""
        if not device_id:
            return {"success": False, "error": "No device ID provided"}

        # Create a system user for automatic actions if needed
        if not user:
            # Use a placeholder for automatic actions
            class SystemUser:
                id = None
                username = "playbook_engine"

            user = SystemUser()

        reason = params.get(
            "reason", f"Automatic quarantine: {trigger_event.get('description', 'playbook triggered')}"
        )

        result = await self._quarantine.quarantine_device(
            device_id=device_id,
            user=user,
            reason=reason,
        )

        return {
            "success": result.success,
            "message": result.message,
            "device_name": result.device_name,
            "integration_results": result.integration_results,
            "errors": result.errors,
        }

    async def _action_release_device(
        self,
        device_id: Optional[UUID],
        params: Dict[str, Any],
        user: Optional[User],
        trigger_event: Dict[str, Any],
    ) -> Dict[str, Any]:
        """Execute release device action."""
        if not device_id:
            return {"success": False, "error": "No device ID provided"}

        if not user:
            class SystemUser:
                id = None
                username = "playbook_engine"

            user = SystemUser()

        reason = params.get(
            "reason", f"Automatic release: {trigger_event.get('description', 'playbook triggered')}"
        )

        result = await self._quarantine.release_device(
            device_id=device_id,
            user=user,
            reason=reason,
        )

        return {
            "success": result.success,
            "message": result.message,
            "device_name": result.device_name,
        }

    async def _action_create_alert(
        self,
        device_id: Optional[UUID],
        params: Dict[str, Any],
        trigger_event: Dict[str, Any],
    ) -> Dict[str, Any]:
        """Create an alert based on playbook action."""
        from app.models.alert import Alert, AlertSeverity, AlertStatus

        session = await self._get_session()
        try:
            severity = AlertSeverity(params.get("severity", "medium"))
            title = params.get("title", f"Playbook Alert: {trigger_event.get('description', 'Event detected')}")
            description = params.get("description", str(trigger_event))

            alert = Alert(
                device_id=device_id,
                severity=severity,
                title=title,
                description=description,
                status=AlertStatus.OPEN,
            )
            session.add(alert)
            await session.commit()

            return {
                "success": True,
                "alert_id": str(alert.id),
                "severity": severity.value,
            }

        except Exception as e:
            return {"success": False, "error": str(e)}

        finally:
            await self._close_session(session)

    async def _action_tag_device(
        self,
        device_id: Optional[UUID],
        params: Dict[str, Any],
    ) -> Dict[str, Any]:
        """Add or remove tags from a device."""
        if not device_id:
            return {"success": False, "error": "No device ID provided"}

        session = await self._get_session()
        try:
            result = await session.execute(
                select(Device).where(Device.id == device_id)
            )
            device = result.scalar_one_or_none()

            if not device:
                return {"success": False, "error": "Device not found"}

            tags_to_add = params.get("add_tags", [])
            tags_to_remove = params.get("remove_tags", [])

            current_tags = set(device.profile_tags or [])

            for tag in tags_to_add:
                current_tags.add(tag)

            for tag in tags_to_remove:
                current_tags.discard(tag)

            device.profile_tags = list(current_tags)
            await session.commit()

            return {
                "success": True,
                "tags_added": tags_to_add,
                "tags_removed": tags_to_remove,
                "current_tags": list(current_tags),
            }

        except Exception as e:
            return {"success": False, "error": str(e)}

        finally:
            await self._close_session(session)

    async def _action_send_notification(
        self,
        params: Dict[str, Any],
        trigger_event: Dict[str, Any],
        device_id: Optional[UUID],
    ) -> Dict[str, Any]:
        """Send a notification via email and/or ntfy.sh."""
        from app.services.email_service import get_email_service
        from app.services.ntfy_service import get_ntfy_service

        notification_type = params.get("type", "all")  # email, ntfy, all
        message = params.get("message", str(trigger_event.get("description", "")))
        title = params.get("title", trigger_event.get("title", "NetGuardian Notification"))
        severity = params.get("severity", trigger_event.get("severity", "medium"))
        recipients = params.get("recipients", [])  # List of emails
        ntfy_topic = params.get("ntfy_topic")  # Optional topic override

        results = {
            "success": True,
            "notification_type": notification_type,
            "email_sent": False,
            "ntfy_sent": False,
        }

        # Get device name if available
        device_name = None
        if device_id:
            session = await self._get_session()
            try:
                result = await session.execute(
                    select(Device).where(Device.id == device_id)
                )
                device = result.scalar_one_or_none()
                if device:
                    device_name = device.hostname or str(device.mac_address)
            finally:
                await self._close_session(session)

        # Send email notifications
        if notification_type in ("email", "all") and recipients:
            email_service = get_email_service()
            if email_service.is_configured:
                for recipient in recipients:
                    sent = await email_service.send_alert_notification(
                        to_email=recipient,
                        alert_title=title,
                        alert_description=message,
                        severity=severity,
                        device_name=device_name,
                    )
                    if sent:
                        results["email_sent"] = True

        # Send ntfy notification
        if notification_type in ("ntfy", "all"):
            ntfy_service = get_ntfy_service()
            if ntfy_service.is_configured:
                sent = await ntfy_service.send_alert_notification(
                    alert_title=title,
                    alert_description=message,
                    severity=severity,
                    topic=ntfy_topic,
                    device_name=device_name,
                )
                if sent:
                    results["ntfy_sent"] = True

        logger.info(
            "Playbook notification sent",
            notification_type=notification_type,
            email_sent=results["email_sent"],
            ntfy_sent=results["ntfy_sent"],
            device_id=str(device_id) if device_id else None,
        )

        return results

    async def _action_log_event(
        self,
        params: Dict[str, Any],
        trigger_event: Dict[str, Any],
        device_id: Optional[UUID],
    ) -> Dict[str, Any]:
        """Log an event via the audit service."""
        log_level = params.get("level", "info")
        message = params.get("message", str(trigger_event))

        # Use the appropriate log method based on level
        log_data = {
            "message": message,
            "trigger_event": trigger_event,
            "device_id": str(device_id) if device_id else None,
        }

        if log_level == "debug":
            logger.debug("Playbook event log", **log_data)
        elif log_level == "warning":
            logger.warning("Playbook event log", **log_data)
        elif log_level == "error":
            logger.error("Playbook event log", **log_data)
        else:
            logger.info("Playbook event log", **log_data)

        return {"success": True, "level": log_level, "message": message}

    async def _action_execute_webhook(
        self,
        params: Dict[str, Any],
        trigger_event: Dict[str, Any],
        device_id: Optional[UUID],
    ) -> Dict[str, Any]:
        """Execute a webhook (send HTTP request)."""
        import httpx

        url = params.get("url")
        method = params.get("method", "POST").upper()
        headers = params.get("headers", {})
        timeout = params.get("timeout", 30)

        if not url:
            return {"success": False, "error": "No webhook URL provided"}

        # Build payload
        payload = {
            "trigger_event": trigger_event,
            "device_id": str(device_id) if device_id else None,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            **params.get("extra_data", {}),
        }

        try:
            async with httpx.AsyncClient(timeout=timeout) as client:
                if method == "GET":
                    response = await client.get(url, headers=headers, params=payload)
                else:
                    response = await client.request(
                        method, url, headers=headers, json=payload
                    )

                return {
                    "success": response.status_code < 400,
                    "status_code": response.status_code,
                    "response": response.text[:500],  # Limit response size
                }

        except Exception as e:
            return {"success": False, "error": str(e)}

    async def get_playbook(self, playbook_id: UUID) -> Optional[Playbook]:
        """Get a playbook by ID."""
        session = await self._get_session()
        try:
            result = await session.execute(
                select(Playbook).where(Playbook.id == playbook_id)
            )
            return result.scalar_one_or_none()
        finally:
            await self._close_session(session)

    async def list_playbooks(
        self,
        status: Optional[PlaybookStatus] = None,
        trigger_type: Optional[PlaybookTriggerType] = None,
        limit: int = 100,
        offset: int = 0,
    ) -> List[Playbook]:
        """List playbooks with optional filtering."""
        session = await self._get_session()
        try:
            query = select(Playbook)

            if status:
                query = query.where(Playbook.status == status)
            if trigger_type:
                query = query.where(Playbook.trigger_type == trigger_type)

            query = query.offset(offset).limit(limit).order_by(Playbook.name)
            result = await session.execute(query)
            return list(result.scalars().all())

        finally:
            await self._close_session(session)

    async def create_playbook(
        self,
        name: str,
        trigger_type: PlaybookTriggerType,
        actions: List[Dict[str, Any]],
        description: Optional[str] = None,
        trigger_conditions: Optional[Dict[str, Any]] = None,
        created_by: Optional[UUID] = None,
        **kwargs,
    ) -> Playbook:
        """Create a new playbook."""
        session = await self._get_session()
        try:
            playbook = Playbook(
                name=name,
                description=description,
                trigger_type=trigger_type,
                trigger_conditions=trigger_conditions or {},
                actions=actions,
                created_by=created_by,
                status=PlaybookStatus.DRAFT,
                **kwargs,
            )
            session.add(playbook)
            await session.commit()
            await session.refresh(playbook)

            logger.info(
                "Playbook created",
                playbook_id=str(playbook.id),
                name=name,
                trigger_type=trigger_type.value,
            )

            return playbook

        finally:
            await self._close_session(session)

    async def update_playbook(
        self,
        playbook_id: UUID,
        **updates,
    ) -> Optional[Playbook]:
        """Update a playbook."""
        session = await self._get_session()
        try:
            result = await session.execute(
                select(Playbook).where(Playbook.id == playbook_id)
            )
            playbook = result.scalar_one_or_none()

            if not playbook:
                return None

            for key, value in updates.items():
                if hasattr(playbook, key):
                    setattr(playbook, key, value)

            await session.commit()
            await session.refresh(playbook)

            return playbook

        finally:
            await self._close_session(session)

    async def delete_playbook(self, playbook_id: UUID) -> bool:
        """Delete a playbook."""
        session = await self._get_session()
        try:
            result = await session.execute(
                select(Playbook).where(Playbook.id == playbook_id)
            )
            playbook = result.scalar_one_or_none()

            if not playbook:
                return False

            await session.delete(playbook)
            await session.commit()

            logger.info(
                "Playbook deleted",
                playbook_id=str(playbook_id),
            )

            return True

        finally:
            await self._close_session(session)


# Global engine instance
_playbook_engine: Optional[PlaybookEngine] = None


def get_playbook_engine() -> PlaybookEngine:
    """Get the global playbook engine instance."""
    global _playbook_engine
    if _playbook_engine is None:
        _playbook_engine = PlaybookEngine()
    return _playbook_engine
