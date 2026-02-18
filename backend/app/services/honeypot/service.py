"""Honeypot service for managing honeypot instances."""

import json
from datetime import UTC, datetime, timedelta
from typing import Any, cast
from uuid import UUID

import structlog
from sqlalchemy import and_, desc, func, select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from app.config import settings
from app.data.honeypot_templates import DEFAULT_TEMPLATES
from app.db.session import AsyncSessionLocal
from app.models.honeypot import (
    AttackerProfile,
    HoneypotInstance,
    HoneypotInteraction,
    HoneypotStatus,
    HoneypotTemplate,
    HoneypotType,
    SophisticationLevel,
)
from app.parsers.honeypot_parser import HoneypotParser
from app.services.honeypot.orchestrator import ContainerOrchestrator
from app.services.llm_service import get_llm_service

logger = structlog.get_logger()


ATTACKER_ANALYSIS_PROMPT = """Analyze the following honeypot interactions from attacker IP {source_ip} and provide an assessment:

Interactions:
{interactions}

Provide your analysis in JSON format:
{{
    "sophistication_level": "script_kiddie|intermediate|advanced|apt",
    "likely_intent": "reconnaissance|credential_harvesting|malware_deployment|lateral_movement|data_exfiltration|other",
    "analysis": "Detailed analysis of the attacker's behavior, techniques, and likely objectives",
    "iocs": {{
        "domains": ["list of domains"],
        "urls": ["list of URLs"],
        "hashes": ["list of file hashes"],
        "commands": ["notable commands used"]
    }},
    "recommended_actions": [
        {{"action": "action description", "priority": "high|medium|low"}}
    ]
}}
"""


class HoneypotService:
    """Service for managing honeypot instances."""

    def __init__(self, session: AsyncSession | None = None):
        """Initialize the honeypot service.

        Args:
            session: Optional database session.
        """
        self._session = session
        self._orchestrator = ContainerOrchestrator()
        self._llm_service = get_llm_service()
        self._parser = HoneypotParser()

    async def _get_session(self) -> AsyncSession:
        """Get a database session."""
        if self._session:
            return self._session
        return AsyncSessionLocal()

    async def _close_session(self, session: AsyncSession) -> None:
        """Close session if it was created internally."""
        if session != self._session:
            await session.close()

    # ==================== TEMPLATE MANAGEMENT ====================

    async def sync_templates(self) -> int:
        """Sync honeypot templates to database.

        Returns:
            Number of templates synced.
        """
        session = await self._get_session()
        try:
            count = 0
            for template_data in DEFAULT_TEMPLATES:
                result = await session.execute(
                    select(HoneypotTemplate).where(HoneypotTemplate.id == template_data["id"])
                )
                existing = result.scalar_one_or_none()

                if existing:
                    existing.name = cast(str, template_data["name"])
                    existing.honeypot_type = cast(HoneypotType, template_data["honeypot_type"])
                    existing.description = cast(str, template_data.get("description", ""))
                    existing.container_image = cast(str, template_data["container_image"])
                    existing.container_config = cast(dict[str, Any], template_data.get("container_config", {}))
                    existing.exposed_ports = cast(list[int], template_data.get("exposed_ports", []))
                    existing.default_timeout_minutes = cast(int, template_data.get("default_timeout_minutes", 60))
                    existing.enabled = cast(bool, template_data.get("enabled", True))
                else:
                    template = HoneypotTemplate(
                        id=template_data["id"],
                        name=template_data["name"],
                        honeypot_type=template_data["honeypot_type"],
                        description=template_data.get("description", ""),
                        container_image=template_data["container_image"],
                        container_config=template_data.get("container_config", {}),
                        exposed_ports=template_data.get("exposed_ports", []),
                        default_timeout_minutes=template_data.get("default_timeout_minutes", 60),
                        enabled=template_data.get("enabled", True),
                    )
                    session.add(template)

                count += 1

            await session.commit()
            logger.info("honeypot_templates_synced", count=count)
            return count

        finally:
            await self._close_session(session)

    async def get_templates(
        self,
        honeypot_type: HoneypotType | None = None,
        enabled_only: bool = True,
    ) -> list[HoneypotTemplate]:
        """Get available honeypot templates.

        Args:
            honeypot_type: Filter by type.
            enabled_only: Only return enabled templates.

        Returns:
            List of templates.
        """
        session = await self._get_session()
        try:
            query = select(HoneypotTemplate)

            if enabled_only:
                query = query.where(HoneypotTemplate.enabled == True)  # noqa: E712
            if honeypot_type:
                query = query.where(HoneypotTemplate.honeypot_type == honeypot_type)

            result = await session.execute(query)
            return list(result.scalars().all())

        finally:
            await self._close_session(session)

    # ==================== HONEYPOT INSTANCE MANAGEMENT ====================

    async def spawn_honeypot(
        self,
        template_id: str,
        trigger_alert_id: UUID | None = None,
        trigger_device_id: UUID | None = None,
        trigger_reason: str | None = None,
        timeout_minutes: int | None = None,
    ) -> HoneypotInstance | None:
        """Spawn a new honeypot instance.

        Args:
            template_id: Template to use.
            trigger_alert_id: Alert that triggered spawn.
            trigger_device_id: Device that triggered spawn.
            trigger_reason: Why the honeypot was spawned.
            timeout_minutes: Override default timeout.

        Returns:
            Created honeypot instance or None on failure.
        """
        if not settings.honeypot_enabled:
            logger.warning("honeypot_disabled")
            return None

        session = await self._get_session()
        try:
            # Check concurrent limit
            running_count = await self._count_running_honeypots(session)
            if running_count >= settings.honeypot_max_concurrent:
                logger.warning(
                    "honeypot_limit_reached",
                    running=running_count,
                    max=settings.honeypot_max_concurrent,
                )
                return None

            # Get template
            result = await session.execute(
                select(HoneypotTemplate).where(HoneypotTemplate.id == template_id)
            )
            template = result.scalar_one_or_none()

            if not template:
                logger.error("honeypot_template_not_found", template_id=template_id)
                return None

            # Calculate expiration
            timeout = timeout_minutes or template.default_timeout_minutes
            expires_at = datetime.now(UTC) + timedelta(minutes=timeout)

            # Generate container name
            container_name = f"honeypot-{template_id}-{datetime.now(UTC).strftime('%Y%m%d%H%M%S')}"

            # Create instance record
            instance = HoneypotInstance(
                template_id=template_id,
                container_name=container_name,
                status=HoneypotStatus.PENDING,
                trigger_alert_id=trigger_alert_id,
                trigger_device_id=trigger_device_id,
                trigger_reason=trigger_reason,
                expires_at=expires_at,
            )
            session.add(instance)
            await session.commit()
            await session.refresh(instance)

            # Ensure network exists
            await self._orchestrator.ensure_network()

            # Update status to starting
            instance.status = HoneypotStatus.STARTING
            session.add(instance)
            await session.commit()

            # Build port mappings
            port_mappings = {port: 0 for port in template.exposed_ports}

            # Spawn container
            container_id, actual_mappings = await self._orchestrator.spawn_container(
                image=template.container_image,
                name=container_name,
                config=template.container_config,
                port_mappings=port_mappings,
            )

            if not container_id:
                instance.status = HoneypotStatus.FAILED
                instance.error_message = "Failed to spawn container"
                session.add(instance)
                await session.commit()
                return None

            # Update instance with container info
            instance.container_id = container_id
            instance.status = HoneypotStatus.RUNNING
            instance.host_ip = settings.honeypot_host_ip
            instance.port_mappings = actual_mappings
            instance.started_at = datetime.now(UTC)
            session.add(instance)
            await session.commit()

            logger.info(
                "honeypot_spawned",
                id=str(instance.id),
                template=template_id,
                container_id=container_id,
            )

            return instance

        except Exception as e:
            logger.error("honeypot_spawn_error", error=str(e))
            return None

        finally:
            await self._close_session(session)

    async def stop_honeypot(self, honeypot_id: UUID) -> HoneypotInstance | None:
        """Stop and remove a honeypot instance.

        Args:
            honeypot_id: Honeypot instance UUID.

        Returns:
            Updated instance or None.
        """
        session = await self._get_session()
        try:
            result = await session.execute(
                select(HoneypotInstance).where(HoneypotInstance.id == honeypot_id)
            )
            instance = result.scalar_one_or_none()

            if not instance:
                return None

            if instance.status not in [HoneypotStatus.RUNNING, HoneypotStatus.STARTING]:
                return instance

            instance.status = HoneypotStatus.STOPPING
            session.add(instance)
            await session.commit()

            # Stop and remove container
            if instance.container_id:
                await self._orchestrator.remove_container(
                    instance.container_id,
                    instance.port_mappings,
                )

            instance.status = HoneypotStatus.STOPPED
            instance.stopped_at = datetime.now(UTC)
            session.add(instance)
            await session.commit()

            logger.info("honeypot_stopped", id=str(honeypot_id))

            return instance

        finally:
            await self._close_session(session)

    async def get_honeypot(
        self,
        honeypot_id: UUID,
        include_interactions: bool = False,
    ) -> HoneypotInstance | None:
        """Get a honeypot instance.

        Args:
            honeypot_id: Honeypot UUID.
            include_interactions: Include interaction history.

        Returns:
            Honeypot instance or None.
        """
        session = await self._get_session()
        try:
            query = select(HoneypotInstance).where(HoneypotInstance.id == honeypot_id)

            if include_interactions:
                query = query.options(selectinload(HoneypotInstance.interactions))

            result = await session.execute(query)
            return result.scalar_one_or_none()

        finally:
            await self._close_session(session)

    async def list_honeypots(
        self,
        status: HoneypotStatus | None = None,
        template_id: str | None = None,
        limit: int = 50,
        offset: int = 0,
    ) -> tuple[list[HoneypotInstance], int]:
        """List honeypot instances.

        Args:
            status: Filter by status.
            template_id: Filter by template.
            limit: Max results.
            offset: Results offset.

        Returns:
            Tuple of (instances, total_count).
        """
        session = await self._get_session()
        try:
            query = select(HoneypotInstance)
            count_query = select(func.count(HoneypotInstance.id))

            conditions = []
            if status:
                conditions.append(HoneypotInstance.status == status)
            if template_id:
                conditions.append(HoneypotInstance.template_id == template_id)

            if conditions:
                query = query.where(and_(*conditions))
                count_query = count_query.where(and_(*conditions))

            count_result = await session.execute(count_query)
            total = count_result.scalar() or 0

            query = (
                query.order_by(desc(HoneypotInstance.created_at))
                .offset(offset)
                .limit(limit)
            )
            result = await session.execute(query)
            instances = list(result.scalars().all())

            return instances, total

        finally:
            await self._close_session(session)

    async def get_active_honeypots(self) -> list[HoneypotInstance]:
        """Get all active (running) honeypots.

        Returns:
            List of running honeypots.
        """
        instances, _ = await self.list_honeypots(status=HoneypotStatus.RUNNING)
        return instances

    # ==================== INTERACTION MANAGEMENT ====================

    async def record_interaction(
        self,
        honeypot_id: UUID,
        source_ip: str,
        interaction_type: str,
        raw_data: str | None = None,
        parsed_data: dict[str, Any] | None = None,
        source_port: int | None = None,
    ) -> HoneypotInteraction:
        """Record an interaction with a honeypot.

        Args:
            honeypot_id: Honeypot UUID.
            source_ip: Attacker's IP.
            interaction_type: Type of interaction.
            raw_data: Raw interaction data.
            parsed_data: Parsed data.
            source_port: Source port.

        Returns:
            Created interaction.
        """
        session = await self._get_session()
        try:
            # Parse for threat indicators
            threat_indicators = None
            if parsed_data:
                threat_indicators = self._parser.extract_threat_indicators(parsed_data)

            interaction = HoneypotInteraction(
                honeypot_id=honeypot_id,
                timestamp=datetime.now(UTC),
                source_ip=source_ip,
                source_port=source_port,
                interaction_type=interaction_type,
                raw_data=raw_data,
                parsed_data=parsed_data,
                threat_indicators=threat_indicators,
            )
            session.add(interaction)

            # Update honeypot interaction count
            result = await session.execute(
                select(HoneypotInstance).where(HoneypotInstance.id == honeypot_id)
            )
            honeypot = result.scalar_one_or_none()
            if honeypot:
                honeypot.interaction_count += 1
                session.add(honeypot)

            await session.commit()
            await session.refresh(interaction)

            # Update attacker profile
            await self._update_attacker_profile(source_ip, session)

            logger.debug(
                "honeypot_interaction_recorded",
                honeypot_id=str(honeypot_id),
                source_ip=source_ip,
                type=interaction_type,
            )

            return interaction

        finally:
            await self._close_session(session)

    async def get_interactions(
        self,
        honeypot_id: UUID,
        limit: int = 100,
        offset: int = 0,
    ) -> list[HoneypotInteraction]:
        """Get interactions for a honeypot.

        Args:
            honeypot_id: Honeypot UUID.
            limit: Max results.
            offset: Results offset.

        Returns:
            List of interactions.
        """
        session = await self._get_session()
        try:
            result = await session.execute(
                select(HoneypotInteraction)
                .where(HoneypotInteraction.honeypot_id == honeypot_id)
                .order_by(desc(HoneypotInteraction.timestamp))
                .offset(offset)
                .limit(limit)
            )
            return list(result.scalars().all())

        finally:
            await self._close_session(session)

    # ==================== ATTACKER PROFILING ====================

    async def _update_attacker_profile(self, source_ip: str, session: AsyncSession) -> None:
        """Update attacker profile with new interaction.

        Args:
            source_ip: Attacker's IP.
            session: Database session.
        """
        try:
            result = await session.execute(
                select(AttackerProfile).where(AttackerProfile.source_ip == source_ip)
            )
            profile = result.scalar_one_or_none()

            now = datetime.now(UTC)

            if profile:
                profile.last_seen = now
                profile.total_interactions += 1
            else:
                profile = AttackerProfile(
                    source_ip=source_ip,
                    first_seen=now,
                    last_seen=now,
                    total_interactions=1,
                    honeypots_triggered=1,
                )

            session.add(profile)
            # Don't commit here, let caller commit

        except Exception as e:
            logger.warning("attacker_profile_update_error", ip=source_ip, error=str(e))

    async def analyze_attacker(self, source_ip: str) -> AttackerProfile | None:
        """Generate LLM analysis for an attacker.

        Args:
            source_ip: Attacker's IP.

        Returns:
            Updated attacker profile or None.
        """
        if not settings.honeypot_llm_analysis_enabled or not self._llm_service.is_enabled:
            return None

        session = await self._get_session()
        try:
            # Get attacker profile
            result = await session.execute(
                select(AttackerProfile).where(AttackerProfile.source_ip == source_ip)
            )
            profile = result.scalar_one_or_none()

            if not profile:
                return None

            # Get recent interactions
            interaction_result = await session.execute(
                select(HoneypotInteraction)
                .where(HoneypotInteraction.source_ip == source_ip)
                .order_by(desc(HoneypotInteraction.timestamp))
                .limit(50)
            )
            interactions = interaction_result.scalars().all()

            if not interactions:
                return profile

            # Build interaction summary
            interaction_text = "\n".join([
                f"- {i.timestamp.isoformat()}: {i.interaction_type} - {i.raw_data[:200] if i.raw_data else 'No data'}"
                for i in interactions[:20]
            ])

            # Call LLM for analysis
            prompt = ATTACKER_ANALYSIS_PROMPT.format(
                source_ip=source_ip,
                interactions=interaction_text,
            )

            response = await self._llm_service.client.messages.create(
                model=settings.llm_model_default,
                max_tokens=1500,
                messages=[{"role": "user", "content": prompt}],
            )

            response_text = ""
            for block in response.content:
                if hasattr(block, "text"):
                    response_text += block.text

            try:
                analysis = json.loads(response_text)
            except json.JSONDecodeError:
                analysis = {"analysis": response_text}

            # Update profile
            sophistication_map = {
                "script_kiddie": SophisticationLevel.SCRIPT_KIDDIE,
                "intermediate": SophisticationLevel.INTERMEDIATE,
                "advanced": SophisticationLevel.ADVANCED,
                "apt": SophisticationLevel.APT,
            }

            profile.sophistication_level = sophistication_map.get(
                analysis.get("sophistication_level", "").lower(),
                SophisticationLevel.SCRIPT_KIDDIE,
            )
            profile.likely_intent = analysis.get("likely_intent", "unknown")
            profile.llm_analysis = analysis.get("analysis", "")
            profile.iocs = analysis.get("iocs", {})
            profile.recommended_actions = analysis.get("recommended_actions", [])

            session.add(profile)
            await session.commit()

            logger.info("attacker_analyzed", ip=source_ip)

            return profile

        except Exception as e:
            logger.error("attacker_analysis_error", ip=source_ip, error=str(e))
            return None

        finally:
            await self._close_session(session)

    async def get_attacker_profiles(
        self,
        limit: int = 50,
        offset: int = 0,
    ) -> tuple[list[AttackerProfile], int]:
        """Get attacker profiles.

        Args:
            limit: Max results.
            offset: Results offset.

        Returns:
            Tuple of (profiles, total_count).
        """
        session = await self._get_session()
        try:
            count_result = await session.execute(select(func.count(AttackerProfile.id)))
            total = count_result.scalar() or 0

            result = await session.execute(
                select(AttackerProfile)
                .order_by(desc(AttackerProfile.last_seen))
                .offset(offset)
                .limit(limit)
            )
            profiles = list(result.scalars().all())

            return profiles, total

        finally:
            await self._close_session(session)

    async def get_attacker_profile(self, source_ip: str) -> AttackerProfile | None:
        """Get a specific attacker profile.

        Args:
            source_ip: Attacker's IP.

        Returns:
            Attacker profile or None.
        """
        session = await self._get_session()
        try:
            result = await session.execute(
                select(AttackerProfile).where(AttackerProfile.source_ip == source_ip)
            )
            return result.scalar_one_or_none()

        finally:
            await self._close_session(session)

    # ==================== HELPERS ====================

    async def _count_running_honeypots(self, session: AsyncSession) -> int:
        """Count currently running honeypots."""
        result = await session.execute(
            select(func.count(HoneypotInstance.id)).where(
                HoneypotInstance.status == HoneypotStatus.RUNNING
            )
        )
        return result.scalar() or 0

    async def cleanup_expired(self) -> int:
        """Stop expired honeypots.

        Returns:
            Number of honeypots stopped.
        """
        session = await self._get_session()
        try:
            now = datetime.now(UTC)

            result = await session.execute(
                select(HoneypotInstance).where(
                    and_(
                        HoneypotInstance.status == HoneypotStatus.RUNNING,
                        HoneypotInstance.expires_at <= now,
                    )
                )
            )
            expired = result.scalars().all()

            stopped = 0
            for instance in expired:
                await self.stop_honeypot(instance.id)
                stopped += 1

            if stopped:
                logger.info("expired_honeypots_stopped", count=stopped)

            return stopped

        finally:
            await self._close_session(session)

    async def get_stats(self) -> dict[str, Any]:
        """Get honeypot statistics.

        Returns:
            Stats dictionary.
        """
        session = await self._get_session()
        try:
            # Count by status
            status_result = await session.execute(
                select(HoneypotInstance.status, func.count(HoneypotInstance.id))
                .group_by(HoneypotInstance.status)
            )
            status_counts = {row[0].value: row[1] for row in status_result.all()}

            # Total interactions
            interaction_result = await session.execute(
                select(func.sum(HoneypotInstance.interaction_count))
            )
            total_interactions = interaction_result.scalar() or 0

            # Unique attackers
            attacker_result = await session.execute(
                select(func.count(AttackerProfile.id))
            )
            unique_attackers = attacker_result.scalar() or 0

            return {
                "by_status": status_counts,
                "total_interactions": total_interactions,
                "unique_attackers": unique_attackers,
            }

        finally:
            await self._close_session(session)


# Global service instance
_honeypot_service: HoneypotService | None = None


def get_honeypot_service() -> HoneypotService:
    """Get the global honeypot service instance."""
    global _honeypot_service
    if _honeypot_service is None:
        _honeypot_service = HoneypotService()
    return _honeypot_service
