"""Add playbooks tables for Phase 4.

Revision ID: 004
Revises: 003
Create Date: 2026-01-19

"""

from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

# revision identifiers, used by Alembic.
revision: str = "004"
down_revision: Union[str, None] = "003"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # Create playbook status enum
    playbookstatus_enum = postgresql.ENUM(
        "active",
        "disabled",
        "draft",
        name="playbookstatus",
        create_type=True,
    )
    playbookstatus_enum.create(op.get_bind(), checkfirst=True)

    # Create playbook trigger type enum
    playbooktriggertype_enum = postgresql.ENUM(
        "anomaly_detected",
        "alert_created",
        "device_new",
        "device_status_change",
        "threshold_exceeded",
        "schedule",
        "manual",
        name="playbooktriggertype",
        create_type=True,
    )
    playbooktriggertype_enum.create(op.get_bind(), checkfirst=True)

    # Create execution status enum
    executionstatus_enum = postgresql.ENUM(
        "pending",
        "running",
        "completed",
        "failed",
        "cancelled",
        name="executionstatus",
        create_type=True,
    )
    executionstatus_enum.create(op.get_bind(), checkfirst=True)

    # Create playbooks table
    op.create_table(
        "playbooks",
        sa.Column("id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("name", sa.String(100), nullable=False),
        sa.Column("description", sa.Text(), nullable=True),
        sa.Column(
            "status",
            sa.Enum(
                "active",
                "disabled",
                "draft",
                name="playbookstatus",
                create_type=False,
            ),
            nullable=False,
            server_default="draft",
        ),
        sa.Column(
            "trigger_type",
            sa.Enum(
                "anomaly_detected",
                "alert_created",
                "device_new",
                "device_status_change",
                "threshold_exceeded",
                "schedule",
                "manual",
                name="playbooktriggertype",
                create_type=False,
            ),
            nullable=False,
        ),
        sa.Column(
            "trigger_conditions",
            postgresql.JSON(),
            nullable=False,
            server_default="{}",
        ),
        sa.Column(
            "actions",
            postgresql.JSON(),
            nullable=False,
            server_default="[]",
        ),
        sa.Column(
            "cooldown_minutes",
            sa.Integer(),
            nullable=False,
            server_default="60",
        ),
        sa.Column(
            "max_executions_per_hour",
            sa.Integer(),
            nullable=False,
            server_default="10",
        ),
        sa.Column(
            "require_approval",
            sa.Boolean(),
            nullable=False,
            server_default="false",
        ),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.text("CURRENT_TIMESTAMP"),
        ),
        sa.Column(
            "updated_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.text("CURRENT_TIMESTAMP"),
        ),
        sa.Column("created_by", postgresql.UUID(as_uuid=True), nullable=True),
        sa.ForeignKeyConstraint(
            ["created_by"],
            ["users.id"],
            ondelete="SET NULL",
        ),
        sa.PrimaryKeyConstraint("id"),
    )

    # Create playbook indexes
    op.create_index(
        "ix_playbooks_status",
        "playbooks",
        ["status"],
    )
    op.create_index(
        "ix_playbooks_trigger_type",
        "playbooks",
        ["trigger_type"],
    )

    # Create playbook_executions table
    op.create_table(
        "playbook_executions",
        sa.Column("id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("playbook_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column(
            "status",
            sa.Enum(
                "pending",
                "running",
                "completed",
                "failed",
                "cancelled",
                name="executionstatus",
                create_type=False,
            ),
            nullable=False,
            server_default="pending",
        ),
        sa.Column(
            "trigger_event",
            postgresql.JSON(),
            nullable=False,
            server_default="{}",
        ),
        sa.Column("trigger_device_id", postgresql.UUID(as_uuid=True), nullable=True),
        sa.Column("started_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("completed_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column(
            "action_results",
            postgresql.JSON(),
            nullable=False,
            server_default="[]",
        ),
        sa.Column("error_message", sa.Text(), nullable=True),
        sa.Column("triggered_by", postgresql.UUID(as_uuid=True), nullable=True),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.text("CURRENT_TIMESTAMP"),
        ),
        sa.ForeignKeyConstraint(
            ["playbook_id"],
            ["playbooks.id"],
            ondelete="CASCADE",
        ),
        sa.ForeignKeyConstraint(
            ["trigger_device_id"],
            ["devices.id"],
            ondelete="SET NULL",
        ),
        sa.ForeignKeyConstraint(
            ["triggered_by"],
            ["users.id"],
            ondelete="SET NULL",
        ),
        sa.PrimaryKeyConstraint("id"),
    )

    # Create playbook_executions indexes
    op.create_index(
        "ix_playbook_executions_playbook_id",
        "playbook_executions",
        ["playbook_id"],
    )
    op.create_index(
        "ix_playbook_executions_status",
        "playbook_executions",
        ["status"],
    )
    op.create_index(
        "ix_playbook_executions_created_at",
        "playbook_executions",
        ["created_at"],
    )


def downgrade() -> None:
    # Drop indexes
    op.drop_index("ix_playbook_executions_created_at", table_name="playbook_executions")
    op.drop_index("ix_playbook_executions_status", table_name="playbook_executions")
    op.drop_index("ix_playbook_executions_playbook_id", table_name="playbook_executions")
    op.drop_index("ix_playbooks_trigger_type", table_name="playbooks")
    op.drop_index("ix_playbooks_status", table_name="playbooks")

    # Drop tables
    op.drop_table("playbook_executions")
    op.drop_table("playbooks")

    # Drop enums
    op.execute("DROP TYPE IF EXISTS executionstatus")
    op.execute("DROP TYPE IF EXISTS playbooktriggertype")
    op.execute("DROP TYPE IF EXISTS playbookstatus")
