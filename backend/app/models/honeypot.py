"""Honeypot models for dynamic honeypot orchestration."""

from __future__ import annotations

import uuid
from datetime import datetime
from enum import Enum
from typing import TYPE_CHECKING, Any

from sqlalchemy import Boolean, DateTime, ForeignKey, Index, Integer, String, Text
from sqlalchemy import Enum as SQLEnum
from sqlalchemy.dialects.postgresql import JSONB, UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.models.base import Base, TimestampMixin

if TYPE_CHECKING:
    from app.models.alert import Alert
    from app.models.device import Device


class HoneypotType(str, Enum):
    """Type of honeypot service."""

    SSH = "ssh"
    HTTP = "http"
    HTTPS = "https"
    SMB = "smb"
    FTP = "ftp"
    TELNET = "telnet"
    MYSQL = "mysql"
    POSTGRESQL = "postgresql"
    REDIS = "redis"
    RDP = "rdp"


class HoneypotStatus(str, Enum):
    """Status of a honeypot instance."""

    PENDING = "pending"
    STARTING = "starting"
    RUNNING = "running"
    STOPPING = "stopping"
    STOPPED = "stopped"
    FAILED = "failed"


class SophisticationLevel(str, Enum):
    """Attacker sophistication level."""

    SCRIPT_KIDDIE = "script_kiddie"
    INTERMEDIATE = "intermediate"
    ADVANCED = "advanced"
    APT = "apt"


class HoneypotTemplate(Base, TimestampMixin):
    """Honeypot template definition.

    Attributes:
        id: Unique identifier (string, e.g., "ssh-cowrie").
        name: Display name of the template.
        honeypot_type: Type of honeypot service.
        description: Detailed description.
        container_image: Docker/Podman image to use.
        container_config: Container configuration (env vars, volumes, etc.).
        exposed_ports: List of ports to expose.
        default_timeout_minutes: Default duration before auto-stop.
        enabled: Whether template is available for use.
    """

    __tablename__ = "honeypot_templates"

    id: Mapped[str] = mapped_column(
        String(50),
        primary_key=True,
    )
    name: Mapped[str] = mapped_column(
        String(100),
        nullable=False,
    )
    honeypot_type: Mapped[HoneypotType] = mapped_column(
        SQLEnum(
            HoneypotType,
            name="honeypottype",
            values_callable=lambda x: [e.value for e in x],
        ),
        nullable=False,
        index=True,
    )
    description: Mapped[str | None] = mapped_column(
        Text,
        nullable=True,
    )
    container_image: Mapped[str] = mapped_column(
        String(255),
        nullable=False,
    )
    container_config: Mapped[dict[str, Any]] = mapped_column(
        JSONB,
        default=dict,
        nullable=False,
    )
    exposed_ports: Mapped[list[int]] = mapped_column(
        JSONB,
        default=list,
        nullable=False,
    )
    default_timeout_minutes: Mapped[int] = mapped_column(
        Integer,
        default=60,
        nullable=False,
    )
    enabled: Mapped[bool] = mapped_column(
        Boolean,
        default=True,
        nullable=False,
    )

    # Relationships
    instances: Mapped[list[HoneypotInstance]] = relationship(
        "HoneypotInstance",
        back_populates="template",
    )

    def __repr__(self) -> str:
        return f"<HoneypotTemplate {self.id}: {self.name}>"


class HoneypotInstance(Base, TimestampMixin):
    """Honeypot instance record.

    Attributes:
        id: Unique identifier (UUID).
        template_id: Template used for this instance.
        container_id: Docker/Podman container ID.
        container_name: Container name for identification.
        status: Current instance status.
        host_ip: IP address the honeypot is listening on.
        port_mappings: Port mappings (host:container).
        trigger_alert_id: Alert that triggered spawn (if any).
        trigger_device_id: Device that triggered spawn (if any).
        trigger_reason: Why the honeypot was spawned.
        started_at: When the container started.
        expires_at: When the honeypot will auto-stop.
        stopped_at: When the container was stopped.
        interaction_count: Number of interactions recorded.
        llm_profile: LLM-generated attacker profile.
    """

    __tablename__ = "honeypot_instances"

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        primary_key=True,
        default=uuid.uuid4,
    )
    template_id: Mapped[str] = mapped_column(
        String(50),
        ForeignKey("honeypot_templates.id", ondelete="SET NULL"),
        nullable=True,
        index=True,
    )
    container_id: Mapped[str | None] = mapped_column(
        String(100),
        nullable=True,
        unique=True,
    )
    container_name: Mapped[str] = mapped_column(
        String(100),
        nullable=False,
    )
    status: Mapped[HoneypotStatus] = mapped_column(
        SQLEnum(
            HoneypotStatus,
            name="honeypotstatus",
            values_callable=lambda x: [e.value for e in x],
        ),
        default=HoneypotStatus.PENDING,
        nullable=False,
        index=True,
    )
    host_ip: Mapped[str | None] = mapped_column(
        String(45),
        nullable=True,
    )
    port_mappings: Mapped[dict[str, int]] = mapped_column(
        JSONB,
        default=dict,
        nullable=False,
    )
    trigger_alert_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("alerts.id", ondelete="SET NULL"),
        nullable=True,
        index=True,
    )
    trigger_device_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("devices.id", ondelete="SET NULL"),
        nullable=True,
        index=True,
    )
    trigger_reason: Mapped[str | None] = mapped_column(
        Text,
        nullable=True,
    )
    started_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
    )
    expires_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
    )
    stopped_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
    )
    interaction_count: Mapped[int] = mapped_column(
        Integer,
        default=0,
        nullable=False,
    )
    llm_profile: Mapped[dict[str, Any] | None] = mapped_column(
        JSONB,
        nullable=True,
    )
    error_message: Mapped[str | None] = mapped_column(
        Text,
        nullable=True,
    )

    # Relationships
    template: Mapped[HoneypotTemplate | None] = relationship(
        "HoneypotTemplate",
        back_populates="instances",
    )
    trigger_alert: Mapped[Alert | None] = relationship(
        "Alert",
        foreign_keys=[trigger_alert_id],
    )
    trigger_device: Mapped[Device | None] = relationship(
        "Device",
        foreign_keys=[trigger_device_id],
    )
    interactions: Mapped[list[HoneypotInteraction]] = relationship(
        "HoneypotInteraction",
        back_populates="honeypot",
        cascade="all, delete-orphan",
        order_by="HoneypotInteraction.timestamp",
    )

    __table_args__ = (
        Index("ix_honeypot_instances_status_expires", "status", "expires_at"),
        Index("ix_honeypot_instances_created_at", "created_at"),
    )

    def __repr__(self) -> str:
        return f"<HoneypotInstance {self.container_name} ({self.status.value})>"


class HoneypotInteraction(Base, TimestampMixin):
    """Honeypot interaction record.

    Attributes:
        id: Unique identifier (UUID).
        honeypot_id: Parent honeypot instance.
        timestamp: When the interaction occurred.
        source_ip: Attacker's IP address.
        source_port: Attacker's source port.
        interaction_type: Type of interaction (login_attempt, command, http_request, etc.).
        raw_data: Raw data from the interaction.
        parsed_data: Parsed/structured interaction data.
        threat_indicators: Extracted IOCs (IPs, domains, hashes, etc.).
    """

    __tablename__ = "honeypot_interactions"

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        primary_key=True,
        default=uuid.uuid4,
    )
    honeypot_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("honeypot_instances.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    timestamp: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        index=True,
    )
    source_ip: Mapped[str] = mapped_column(
        String(45),
        nullable=False,
        index=True,
    )
    source_port: Mapped[int | None] = mapped_column(
        Integer,
        nullable=True,
    )
    interaction_type: Mapped[str] = mapped_column(
        String(50),
        nullable=False,
        index=True,
    )
    raw_data: Mapped[str | None] = mapped_column(
        Text,
        nullable=True,
    )
    parsed_data: Mapped[dict[str, Any] | None] = mapped_column(
        JSONB,
        nullable=True,
    )
    threat_indicators: Mapped[dict[str, Any] | None] = mapped_column(
        JSONB,
        nullable=True,
    )

    # Relationships
    honeypot: Mapped[HoneypotInstance] = relationship(
        "HoneypotInstance",
        back_populates="interactions",
    )

    __table_args__ = (
        Index("ix_honeypot_interactions_honeypot_timestamp", "honeypot_id", "timestamp"),
    )

    def __repr__(self) -> str:
        return f"<HoneypotInteraction {self.source_ip}: {self.interaction_type}>"


class AttackerProfile(Base, TimestampMixin):
    """Attacker profile record.

    Attributes:
        id: Unique identifier (UUID).
        source_ip: Attacker's IP address.
        first_seen: First interaction timestamp.
        last_seen: Most recent interaction timestamp.
        total_interactions: Total number of interactions.
        honeypots_triggered: Number of honeypots interacted with.
        attack_patterns: JSON object with identified patterns.
        sophistication_level: Estimated attacker skill level.
        likely_intent: Assessed attacker intent.
        llm_analysis: LLM-generated analysis.
        recommended_actions: Suggested defensive actions.
        iocs: Extracted indicators of compromise.
    """

    __tablename__ = "attacker_profiles"

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        primary_key=True,
        default=uuid.uuid4,
    )
    source_ip: Mapped[str] = mapped_column(
        String(45),
        nullable=False,
        unique=True,
        index=True,
    )
    first_seen: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
    )
    last_seen: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
    )
    total_interactions: Mapped[int] = mapped_column(
        Integer,
        default=0,
        nullable=False,
    )
    honeypots_triggered: Mapped[int] = mapped_column(
        Integer,
        default=0,
        nullable=False,
    )
    attack_patterns: Mapped[dict[str, Any] | None] = mapped_column(
        JSONB,
        nullable=True,
    )
    sophistication_level: Mapped[SophisticationLevel | None] = mapped_column(
        SQLEnum(
            SophisticationLevel,
            name="sophisticationlevel",
            values_callable=lambda x: [e.value for e in x],
        ),
        nullable=True,
    )
    likely_intent: Mapped[str | None] = mapped_column(
        String(100),
        nullable=True,
    )
    llm_analysis: Mapped[str | None] = mapped_column(
        Text,
        nullable=True,
    )
    recommended_actions: Mapped[dict[str, Any] | None] = mapped_column(
        JSONB,
        nullable=True,
    )
    iocs: Mapped[dict[str, Any] | None] = mapped_column(
        JSONB,
        nullable=True,
    )

    __table_args__ = (
        Index("ix_attacker_profiles_last_seen", "last_seen"),
        Index("ix_attacker_profiles_sophistication", "sophistication_level"),
    )

    def __repr__(self) -> str:
        return f"<AttackerProfile {self.source_ip}>"
