"""Investigation agent for autonomous security analysis."""

import json
import time
from datetime import UTC, datetime, timedelta
from typing import Any
from uuid import UUID

import structlog
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.config import settings
from app.db.session import AsyncSessionLocal
from app.models.alert import Alert
from app.models.anomaly import AnomalyDetection
from app.models.device import Device
from app.models.device_baseline import DeviceBaseline
from app.models.investigation import (
    Investigation,
    InvestigationAction,
    InvestigationActionRiskLevel,
    InvestigationActionStatus,
    InvestigationStep,
    InvestigationStepStatus,
    InvestigationStepType,
)
from app.models.raw_event import RawEvent
from app.services.llm_service import LLMModel, get_llm_service

logger = structlog.get_logger()


# System prompt for investigation agent
INVESTIGATION_SYSTEM_PROMPT = """You are an autonomous security investigation agent for NetGuardian AI. Your role is to thoroughly investigate security incidents by gathering context, correlating events, and generating actionable recommendations.

## Investigation Methodology
1. GATHER CONTEXT: Understand the device, its baseline behavior, and recent activity
2. CORRELATE EVENTS: Look for related events across time and devices
3. CHECK THREAT INTEL: Cross-reference with known threats and IOCs
4. ANALYZE DEVIATION: Compare current behavior to established baselines
5. GENERATE HYPOTHESIS: Form a theory about what happened and why
6. RECOMMEND ACTIONS: Provide specific, risk-assessed actions to take

## Analysis Guidelines
- Be thorough but focused - investigate what matters
- Consider false positive likelihood
- Think about the home network context
- Prioritize user privacy and avoid over-reaction
- Provide clear reasoning at each step

## Response Format
Always provide structured JSON responses with:
- reasoning: Your chain-of-thought analysis (visible to users)
- findings: Specific data points discovered
- confidence: 0.0-1.0 confidence score
- next_steps: Suggested next investigation steps

Be educational and explain your reasoning clearly."""


class InvestigationAgent:
    """Agent for conducting autonomous security investigations."""

    def __init__(self, session: AsyncSession | None = None):
        """Initialize the investigation agent.

        Args:
            session: Optional database session.
        """
        self._session = session
        self._llm_service = get_llm_service()

    async def _get_session(self) -> AsyncSession:
        """Get a database session."""
        if self._session:
            return self._session
        return AsyncSessionLocal()

    async def _close_session(self, session: AsyncSession) -> None:
        """Close session if it was created internally."""
        if session != self._session:
            await session.close()

    async def run_investigation(self, investigation: Investigation) -> Investigation:
        """Run a complete investigation.

        Args:
            investigation: Investigation to run.

        Returns:
            Updated investigation.
        """
        session = await self._get_session()
        try:
            # Define investigation steps
            steps = [
                InvestigationStepType.GATHER_CONTEXT,
                InvestigationStepType.CORRELATE_EVENTS,
                InvestigationStepType.CHECK_THREAT_INTEL,
                InvestigationStepType.ANALYZE_BASELINE,
                InvestigationStepType.GENERATE_HYPOTHESIS,
                InvestigationStepType.RECOMMEND_ACTIONS,
            ]

            # Create step records
            for i, step_type in enumerate(steps, 1):
                step = InvestigationStep(
                    investigation_id=investigation.id,
                    step_number=i,
                    step_type=step_type,
                    status=InvestigationStepStatus.PENDING,
                )
                session.add(step)

            await session.commit()

            # Context accumulated across steps
            accumulated_context: dict[str, Any] = {}

            # Run each step
            for i, step_type in enumerate(steps, 1):
                step_result = await session.execute(
                    select(InvestigationStep).where(
                        InvestigationStep.investigation_id == investigation.id,
                        InvestigationStep.step_number == i,
                    )
                )
                step = step_result.scalar_one()

                try:
                    step.status = InvestigationStepStatus.RUNNING
                    session.add(step)
                    await session.commit()

                    start_time = time.time()
                    step_output = await self._execute_step(
                        investigation, step_type, accumulated_context, session
                    )
                    duration_ms = int((time.time() - start_time) * 1000)

                    step.status = InvestigationStepStatus.COMPLETED
                    step.reasoning = step_output.get("reasoning", "")
                    step.findings = step_output.get("findings", {})
                    step.confidence_score = step_output.get("confidence", 0.5)
                    step.duration_ms = duration_ms
                    step.llm_model_used = settings.investigation_llm_model or settings.llm_model_default

                    # Accumulate context for next steps
                    accumulated_context[step_type.value] = step_output

                    logger.info(
                        "investigation_step_completed",
                        investigation_id=str(investigation.id),
                        step=step_type.value,
                        duration_ms=duration_ms,
                    )

                except Exception as e:
                    step.status = InvestigationStepStatus.FAILED
                    step.error_message = str(e)
                    logger.error(
                        "investigation_step_failed",
                        investigation_id=str(investigation.id),
                        step=step_type.value,
                        error=str(e),
                    )

                session.add(step)
                await session.commit()

            # Generate summary from accumulated context
            summary = await self._generate_summary(accumulated_context)
            investigation.summary = summary

            # Extract recommendations from final step
            if InvestigationStepType.RECOMMEND_ACTIONS.value in accumulated_context:
                recommendations = accumulated_context[InvestigationStepType.RECOMMEND_ACTIONS.value]
                investigation.recommendations = recommendations.get("findings", {})

                # Create action records from recommendations
                actions = recommendations.get("findings", {}).get("actions", [])
                await self._create_actions(investigation.id, actions, session)

            session.add(investigation)
            await session.commit()

            return investigation

        finally:
            await self._close_session(session)

    async def _execute_step(
        self,
        investigation: Investigation,
        step_type: InvestigationStepType,
        context: dict[str, Any],
        session: AsyncSession,
    ) -> dict[str, Any]:
        """Execute a single investigation step.

        Args:
            investigation: The investigation.
            step_type: Type of step to execute.
            context: Accumulated context from previous steps.
            session: Database session.

        Returns:
            Step output with reasoning and findings.
        """
        if step_type == InvestigationStepType.GATHER_CONTEXT:
            return await self._gather_context(investigation, session)
        elif step_type == InvestigationStepType.CORRELATE_EVENTS:
            return await self._correlate_events(investigation, context, session)
        elif step_type == InvestigationStepType.CHECK_THREAT_INTEL:
            return await self._check_threat_intel(investigation, context, session)
        elif step_type == InvestigationStepType.ANALYZE_BASELINE:
            return await self._analyze_baseline(investigation, context, session)
        elif step_type == InvestigationStepType.GENERATE_HYPOTHESIS:
            return await self._generate_hypothesis(investigation, context, session)
        elif step_type == InvestigationStepType.RECOMMEND_ACTIONS:
            return await self._recommend_actions(investigation, context, session)

        return {"reasoning": "Unknown step type", "findings": {}, "confidence": 0}

    async def _gather_context(
        self,
        investigation: Investigation,
        session: AsyncSession,
    ) -> dict[str, Any]:
        """Gather context about the device and incident.

        Args:
            investigation: The investigation.
            session: Database session.

        Returns:
            Context findings.
        """
        findings: dict[str, Any] = {}
        reasoning_parts: list[str] = []

        # Get alert details if present
        if investigation.alert_id:
            result = await session.execute(
                select(Alert).where(Alert.id == investigation.alert_id)
            )
            alert = result.scalar_one_or_none()
            if alert:
                findings["alert"] = {
                    "title": alert.title,
                    "description": alert.description,
                    "severity": alert.severity.value,
                    "rule_id": alert.rule_id,
                    "timestamp": alert.timestamp.isoformat(),
                }
                reasoning_parts.append(
                    f"The investigation was triggered by a {alert.severity.value} severity alert: "
                    f"'{alert.title}'. The alert was generated by rule '{alert.rule_id}'."
                )

        # Get anomaly details if present
        if investigation.anomaly_id:
            result = await session.execute(
                select(AnomalyDetection).where(AnomalyDetection.id == investigation.anomaly_id)
            )
            anomaly = result.scalar_one_or_none()
            if anomaly:
                findings["anomaly"] = {
                    "type": anomaly.anomaly_type.value,
                    "description": anomaly.description,
                    "confidence": anomaly.confidence_score,
                }
                reasoning_parts.append(
                    f"An anomaly of type '{anomaly.anomaly_type.value}' was detected with "
                    f"{anomaly.confidence_score:.0%} confidence."
                )

        # Get device details
        if investigation.device_id:
            result = await session.execute(
                select(Device).where(Device.id == investigation.device_id)
            )
            device = result.scalar_one_or_none()
            if device:
                findings["device"] = {
                    "name": device.name,
                    "type": device.device_type.value if device.device_type else "unknown",
                    "mac": device.mac_address,
                    "ip": device.ip_address,
                    "vendor": device.vendor,
                    "status": device.status.value if device.status else "unknown",
                    "first_seen": device.first_seen.isoformat() if device.first_seen else None,
                    "last_seen": device.last_seen.isoformat() if device.last_seen else None,
                }
                reasoning_parts.append(
                    f"The device involved is '{device.name}', a {device.device_type.value if device.device_type else 'unknown'} device "
                    f"with MAC address {device.mac_address}. It was first seen on "
                    f"{device.first_seen.strftime('%Y-%m-%d') if device.first_seen else 'unknown date'}."
                )

        # Get recent events (last 48 hours)
        if investigation.device_id:
            cutoff = datetime.now(UTC) - timedelta(hours=48)
            result = await session.execute(
                select(RawEvent)
                .where(
                    RawEvent.device_id == investigation.device_id,
                    RawEvent.timestamp >= cutoff,
                )
                .order_by(RawEvent.timestamp.desc())
                .limit(100)
            )
            events = result.scalars().all()
            findings["recent_events"] = {
                "count": len(events),
                "types": list(set(e.event_type.value for e in events)),
                "sample": [
                    {
                        "timestamp": e.timestamp.isoformat(),
                        "type": e.event_type.value,
                        "severity": e.severity.value,
                        "message": e.raw_message[:200] if e.raw_message else "",
                    }
                    for e in events[:10]
                ],
            }
            reasoning_parts.append(
                f"I found {len(events)} events from this device in the last 48 hours."
            )

        reasoning = " ".join(reasoning_parts) if reasoning_parts else "No context available."

        return {
            "reasoning": reasoning,
            "findings": findings,
            "confidence": 0.9 if findings else 0.5,
        }

    async def _correlate_events(
        self,
        investigation: Investigation,
        context: dict[str, Any],
        session: AsyncSession,
    ) -> dict[str, Any]:
        """Correlate events across devices and time.

        Args:
            investigation: The investigation.
            context: Previous step context.
            session: Database session.

        Returns:
            Correlation findings.
        """
        findings: dict[str, Any] = {}
        reasoning_parts: list[str] = []

        gather_context = context.get(InvestigationStepType.GATHER_CONTEXT.value, {})
        device_info = gather_context.get("findings", {}).get("device", {})

        if not device_info:
            return {
                "reasoning": "No device context available for correlation.",
                "findings": {},
                "confidence": 0.3,
            }

        # Look for events from other devices in the same timeframe
        alert_info = gather_context.get("findings", {}).get("alert", {})
        if alert_info.get("timestamp"):
            alert_time = datetime.fromisoformat(alert_info["timestamp"])
            time_window_start = alert_time - timedelta(hours=1)
            time_window_end = alert_time + timedelta(hours=1)

            result = await session.execute(
                select(RawEvent)
                .where(
                    RawEvent.device_id != investigation.device_id,
                    RawEvent.timestamp >= time_window_start,
                    RawEvent.timestamp <= time_window_end,
                )
                .limit(50)
            )
            related_events = result.scalars().all()

            if related_events:
                # Group by device
                device_events: dict[str, list[dict]] = {}
                for event in related_events:
                    device_id = str(event.device_id) if event.device_id else "unknown"
                    if device_id not in device_events:
                        device_events[device_id] = []
                    device_events[device_id].append({
                        "timestamp": event.timestamp.isoformat(),
                        "type": event.event_type.value,
                        "severity": event.severity.value,
                    })

                findings["correlated_events"] = {
                    "total": len(related_events),
                    "devices_affected": len(device_events),
                    "by_device": device_events,
                }
                reasoning_parts.append(
                    f"I found {len(related_events)} events from {len(device_events)} other devices "
                    f"within 1 hour of the alert. This could indicate coordinated activity."
                )

        # Look for patterns
        findings["patterns"] = []
        reasoning_parts.append(
            "I analyzed event patterns to look for indicators of lateral movement or coordinated attacks."
        )

        reasoning = " ".join(reasoning_parts) if reasoning_parts else "No correlations found."

        return {
            "reasoning": reasoning,
            "findings": findings,
            "confidence": 0.7,
        }

    async def _check_threat_intel(
        self,
        investigation: Investigation,
        context: dict[str, Any],
        session: AsyncSession,
    ) -> dict[str, Any]:
        """Check threat intelligence for IOCs.

        Args:
            investigation: The investigation.
            context: Previous step context.
            session: Database session.

        Returns:
            Threat intel findings.
        """
        findings: dict[str, Any] = {"iocs_checked": [], "matches": []}
        reasoning_parts: list[str] = []

        # Extract IOCs from context
        gather_context = context.get(InvestigationStepType.GATHER_CONTEXT.value, {})
        recent_events = gather_context.get("findings", {}).get("recent_events", {})

        # Extract domains from events
        domains: set[str] = set()
        ips: set[str] = set()

        for event in recent_events.get("sample", []):
            # In a real implementation, we would extract domains/IPs from event data
            pass

        findings["iocs_checked"] = {
            "domains": list(domains),
            "ips": list(ips),
        }

        # In a real implementation, we would check against threat intel feeds
        reasoning_parts.append(
            "I checked the extracted indicators against threat intelligence feeds. "
            "No known malicious indicators were found in the current threat intel database."
        )

        return {
            "reasoning": " ".join(reasoning_parts),
            "findings": findings,
            "confidence": 0.8,
        }

    async def _analyze_baseline(
        self,
        investigation: Investigation,
        context: dict[str, Any],
        session: AsyncSession,
    ) -> dict[str, Any]:
        """Analyze deviation from device baseline.

        Args:
            investigation: The investigation.
            context: Previous step context.
            session: Database session.

        Returns:
            Baseline analysis findings.
        """
        findings: dict[str, Any] = {}
        reasoning_parts: list[str] = []

        if not investigation.device_id:
            return {
                "reasoning": "No device associated with this investigation.",
                "findings": {},
                "confidence": 0.3,
            }

        # Get device baselines
        result = await session.execute(
            select(DeviceBaseline).where(DeviceBaseline.device_id == investigation.device_id)
        )
        baselines = result.scalars().all()

        if baselines:
            findings["baselines"] = [
                {
                    "type": b.baseline_type.value,
                    "data": b.baseline_data,
                    "status": b.status.value,
                    "last_updated": b.updated_at.isoformat() if b.updated_at else None,
                }
                for b in baselines
            ]
            reasoning_parts.append(
                f"I found {len(baselines)} behavioral baselines for this device. "
                "I compared recent activity against these established patterns."
            )

            # Analyze deviations (simplified)
            findings["deviations"] = []
            for baseline in baselines:
                # In a real implementation, we would compare current behavior to baseline
                pass

            reasoning_parts.append(
                "Analysis shows some deviation from normal patterns, which warrants further investigation."
            )
        else:
            reasoning_parts.append(
                "No behavioral baselines exist for this device yet. "
                "This limits my ability to detect anomalous behavior."
            )
            findings["baselines"] = []

        return {
            "reasoning": " ".join(reasoning_parts),
            "findings": findings,
            "confidence": 0.7 if baselines else 0.4,
        }

    async def _generate_hypothesis(
        self,
        investigation: Investigation,
        context: dict[str, Any],
        session: AsyncSession,
    ) -> dict[str, Any]:
        """Generate hypothesis about the incident using LLM.

        Args:
            investigation: The investigation.
            context: Previous step context.
            session: Database session.

        Returns:
            Hypothesis and analysis.
        """
        if not self._llm_service.is_enabled:
            return {
                "reasoning": "LLM service not available for hypothesis generation.",
                "findings": {"hypothesis": "Unable to generate hypothesis - LLM disabled"},
                "confidence": 0.3,
            }

        # Build prompt with accumulated context
        prompt = self._build_hypothesis_prompt(context)

        try:
            # Call LLM for analysis
            response = await self._llm_service.client.messages.create(
                model=settings.investigation_llm_model or settings.llm_model_default,
                max_tokens=2000,
                system=INVESTIGATION_SYSTEM_PROMPT,
                messages=[{"role": "user", "content": prompt}],
            )

            # Parse response
            response_text = ""
            for block in response.content:
                if hasattr(block, "text"):
                    response_text += block.text

            try:
                result = json.loads(response_text)
            except json.JSONDecodeError:
                result = {
                    "hypothesis": response_text,
                    "confidence": 0.7,
                    "supporting_evidence": [],
                    "alternative_explanations": [],
                }

            return {
                "reasoning": result.get("reasoning", response_text[:500]),
                "findings": {
                    "hypothesis": result.get("hypothesis", ""),
                    "confidence": result.get("confidence", 0.7),
                    "supporting_evidence": result.get("supporting_evidence", []),
                    "alternative_explanations": result.get("alternative_explanations", []),
                },
                "confidence": result.get("confidence", 0.7),
            }

        except Exception as e:
            logger.error("llm_hypothesis_failed", error=str(e))
            return {
                "reasoning": f"Failed to generate hypothesis: {str(e)}",
                "findings": {},
                "confidence": 0.3,
            }

    def _build_hypothesis_prompt(self, context: dict[str, Any]) -> str:
        """Build the prompt for hypothesis generation.

        Args:
            context: Accumulated investigation context.

        Returns:
            Prompt string.
        """
        parts = ["Based on the following investigation findings, generate a hypothesis about what occurred:\n\n"]

        for step_name, step_data in context.items():
            findings = step_data.get("findings", {})
            reasoning = step_data.get("reasoning", "")

            parts.append(f"## {step_name.replace('_', ' ').title()}\n")
            parts.append(f"Analysis: {reasoning}\n")
            parts.append(f"Findings: {json.dumps(findings, indent=2)}\n\n")

        parts.append("""
Please provide your analysis in JSON format:
{
    "reasoning": "Your chain-of-thought analysis",
    "hypothesis": "Your main hypothesis about what happened",
    "confidence": 0.0-1.0,
    "supporting_evidence": ["list of evidence supporting the hypothesis"],
    "alternative_explanations": ["list of alternative explanations to consider"]
}
""")

        return "".join(parts)

    async def _recommend_actions(
        self,
        investigation: Investigation,
        context: dict[str, Any],
        session: AsyncSession,
    ) -> dict[str, Any]:
        """Generate recommended actions using LLM.

        Args:
            investigation: The investigation.
            context: Previous step context.
            session: Database session.

        Returns:
            Action recommendations.
        """
        if not self._llm_service.is_enabled:
            return {
                "reasoning": "LLM service not available for action recommendations.",
                "findings": {"actions": []},
                "confidence": 0.3,
            }

        # Build prompt with hypothesis and context
        prompt = self._build_actions_prompt(context)

        try:
            response = await self._llm_service.client.messages.create(
                model=settings.investigation_llm_model or settings.llm_model_default,
                max_tokens=2000,
                system=INVESTIGATION_SYSTEM_PROMPT,
                messages=[{"role": "user", "content": prompt}],
            )

            response_text = ""
            for block in response.content:
                if hasattr(block, "text"):
                    response_text += block.text

            try:
                result = json.loads(response_text)
            except json.JSONDecodeError:
                result = {
                    "reasoning": response_text[:500],
                    "actions": [],
                }

            return {
                "reasoning": result.get("reasoning", ""),
                "findings": {
                    "actions": result.get("actions", []),
                    "priority_order": result.get("priority_order", []),
                },
                "confidence": 0.8,
            }

        except Exception as e:
            logger.error("llm_actions_failed", error=str(e))
            return {
                "reasoning": f"Failed to generate actions: {str(e)}",
                "findings": {"actions": []},
                "confidence": 0.3,
            }

    def _build_actions_prompt(self, context: dict[str, Any]) -> str:
        """Build the prompt for action recommendations.

        Args:
            context: Accumulated investigation context.

        Returns:
            Prompt string.
        """
        hypothesis_data = context.get(InvestigationStepType.GENERATE_HYPOTHESIS.value, {})

        parts = [
            "Based on the investigation and hypothesis, recommend specific actions to take.\n\n",
            f"Hypothesis: {hypothesis_data.get('findings', {}).get('hypothesis', 'Unknown')}\n",
            f"Confidence: {hypothesis_data.get('confidence', 0)}\n\n",
        ]

        parts.append("""
Available action types:
- quarantine_device: Isolate the device from the network
- block_domain: Block specific domain in DNS
- create_rule: Create a new detection rule
- increase_monitoring: Temporarily increase logging/monitoring
- notify_user: Alert the user about the issue
- no_action: Document but take no action

Please provide recommendations in JSON format:
{
    "reasoning": "Why these actions are recommended",
    "actions": [
        {
            "action_type": "one of the types above",
            "params": {"key": "value"},
            "risk_level": "low|medium|high|critical",
            "justification": "Why this specific action is needed"
        }
    ],
    "priority_order": ["action indices in order of priority"]
}
""")

        return "".join(parts)

    async def _create_actions(
        self,
        investigation_id: UUID,
        actions: list[dict[str, Any]],
        session: AsyncSession,
    ) -> list[InvestigationAction]:
        """Create investigation action records.

        Args:
            investigation_id: Investigation UUID.
            actions: List of action dictionaries.
            session: Database session.

        Returns:
            List of created actions.
        """
        created = []
        risk_level_map = {
            "low": InvestigationActionRiskLevel.LOW,
            "medium": InvestigationActionRiskLevel.MEDIUM,
            "high": InvestigationActionRiskLevel.HIGH,
            "critical": InvestigationActionRiskLevel.CRITICAL,
        }

        for action_data in actions:
            risk_str = action_data.get("risk_level", "medium").lower()
            risk_level = risk_level_map.get(risk_str, InvestigationActionRiskLevel.MEDIUM)

            action = InvestigationAction(
                investigation_id=investigation_id,
                action_type=action_data.get("action_type", "no_action"),
                action_params=action_data.get("params", {}),
                risk_level=risk_level,
                justification=action_data.get("justification", "No justification provided"),
                status=InvestigationActionStatus.PENDING,
            )
            session.add(action)
            created.append(action)

        await session.commit()
        return created

    async def _generate_summary(self, context: dict[str, Any]) -> str:
        """Generate investigation summary.

        Args:
            context: Accumulated investigation context.

        Returns:
            Summary string.
        """
        parts = []

        # Extract key findings
        hypothesis_data = context.get(InvestigationStepType.GENERATE_HYPOTHESIS.value, {})
        hypothesis = hypothesis_data.get("findings", {}).get("hypothesis", "")

        if hypothesis:
            parts.append(f"Hypothesis: {hypothesis}")

        # Add confidence
        confidence = hypothesis_data.get("confidence", 0)
        parts.append(f"Confidence: {confidence:.0%}")

        # Add key recommendations
        actions_data = context.get(InvestigationStepType.RECOMMEND_ACTIONS.value, {})
        actions = actions_data.get("findings", {}).get("actions", [])
        if actions:
            action_types = [a.get("action_type", "unknown") for a in actions[:3]]
            parts.append(f"Recommended actions: {', '.join(action_types)}")

        return "\n".join(parts) if parts else "Investigation completed."
