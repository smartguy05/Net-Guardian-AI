"""Add device baselines and anomaly detection tables.

Revision ID: 002
Revises: 001
Create Date: 2026-01-19
"""

from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

# revision identifiers, used by Alembic.
revision: str = "002"
down_revision: Union[str, None] = "001"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # Create enum types for baselines and anomalies
    op.execute("CREATE TYPE baselinetype AS ENUM ('dns', 'traffic', 'connection');")
    op.execute("CREATE TYPE baselinestatus AS ENUM ('learning', 'ready', 'stale');")
    op.execute(
        "CREATE TYPE anomalytype AS ENUM ('new_domain', 'volume_spike', 'time_anomaly', 'new_connection', 'new_port', 'blocked_spike', 'pattern_change');"
    )
    op.execute(
        "CREATE TYPE anomalystatus AS ENUM ('active', 'reviewed', 'false_positive', 'confirmed');"
    )

    # Device Baselines table
    op.create_table(
        "device_baselines",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column(
            "device_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("devices.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column(
            "baseline_type",
            postgresql.ENUM("dns", "traffic", "connection", name="baselinetype", create_type=False),
            nullable=False,
        ),
        sa.Column(
            "status",
            postgresql.ENUM("learning", "ready", "stale", name="baselinestatus", create_type=False),
            nullable=False,
            server_default="learning",
        ),
        sa.Column("metrics", postgresql.JSONB(), nullable=False, server_default="{}"),
        sa.Column("sample_count", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("min_samples", sa.Integer(), nullable=False, server_default="100"),
        sa.Column("baseline_window_days", sa.Integer(), nullable=False, server_default="7"),
        sa.Column("last_calculated", sa.DateTime(timezone=True), nullable=True),
        sa.Column(
            "created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False
        ),
        sa.Column(
            "updated_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False
        ),
    )
    op.create_index("ix_device_baselines_device_id", "device_baselines", ["device_id"])
    op.create_index("ix_device_baselines_baseline_type", "device_baselines", ["baseline_type"])
    op.create_index("ix_device_baselines_status", "device_baselines", ["status"])
    # Unique constraint: one baseline per device per type
    op.create_unique_constraint(
        "uq_device_baselines_device_type", "device_baselines", ["device_id", "baseline_type"]
    )

    # Anomaly Detections table
    op.create_table(
        "anomaly_detections",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column(
            "device_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("devices.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column(
            "anomaly_type",
            postgresql.ENUM(
                "new_domain",
                "volume_spike",
                "time_anomaly",
                "new_connection",
                "new_port",
                "blocked_spike",
                "pattern_change",
                name="anomalytype",
                create_type=False,
            ),
            nullable=False,
        ),
        sa.Column(
            "severity",
            postgresql.ENUM(
                "info", "low", "medium", "high", "critical", name="alertseverity", create_type=False
            ),
            nullable=False,
        ),
        sa.Column("score", sa.Float(), nullable=False),
        sa.Column(
            "status",
            postgresql.ENUM(
                "active",
                "reviewed",
                "false_positive",
                "confirmed",
                name="anomalystatus",
                create_type=False,
            ),
            nullable=False,
            server_default="active",
        ),
        sa.Column("description", sa.Text(), nullable=False),
        sa.Column("details", postgresql.JSONB(), nullable=False, server_default="{}"),
        sa.Column("baseline_comparison", postgresql.JSONB(), nullable=False, server_default="{}"),
        sa.Column("detected_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column(
            "alert_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("alerts.id", ondelete="SET NULL"),
            nullable=True,
        ),
        sa.Column(
            "reviewed_by",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("users.id", ondelete="SET NULL"),
            nullable=True,
        ),
        sa.Column("reviewed_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column(
            "created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False
        ),
        sa.Column(
            "updated_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False
        ),
    )
    op.create_index("ix_anomaly_detections_device_id", "anomaly_detections", ["device_id"])
    op.create_index("ix_anomaly_detections_anomaly_type", "anomaly_detections", ["anomaly_type"])
    op.create_index("ix_anomaly_detections_severity", "anomaly_detections", ["severity"])
    op.create_index("ix_anomaly_detections_status", "anomaly_detections", ["status"])
    op.create_index("ix_anomaly_detections_detected_at", "anomaly_detections", ["detected_at"])
    op.create_index("ix_anomaly_detections_alert_id", "anomaly_detections", ["alert_id"])


def downgrade() -> None:
    # Drop tables
    op.drop_table("anomaly_detections")
    op.drop_table("device_baselines")

    # Drop enum types
    op.execute("DROP TYPE anomalystatus;")
    op.execute("DROP TYPE anomalytype;")
    op.execute("DROP TYPE baselinestatus;")
    op.execute("DROP TYPE baselinetype;")
