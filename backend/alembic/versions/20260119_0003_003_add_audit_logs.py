"""Add audit logs table for Phase 4.

Revision ID: 003
Revises: 002
Create Date: 2026-01-19

"""

from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

# revision identifiers, used by Alembic.
revision: str = "003"
down_revision: Union[str, None] = "002"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # Create audit action enum
    auditaction_enum = postgresql.ENUM(
        "device_quarantine",
        "device_release",
        "device_update",
        "alert_acknowledge",
        "alert_resolve",
        "alert_analyze",
        "anomaly_review",
        "anomaly_confirm",
        "anomaly_false_positive",
        "user_create",
        "user_update",
        "user_deactivate",
        "user_password_reset",
        "user_login",
        "user_logout",
        "source_create",
        "source_update",
        "source_delete",
        "source_enable",
        "source_disable",
        "integration_block",
        "integration_unblock",
        "integration_test",
        "playbook_execute",
        "playbook_create",
        "playbook_update",
        "playbook_delete",
        name="auditaction",
        create_type=True,
    )
    auditaction_enum.create(op.get_bind(), checkfirst=True)

    # Create audit_logs table
    op.create_table(
        "audit_logs",
        sa.Column("id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column(
            "timestamp",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.text("CURRENT_TIMESTAMP"),
        ),
        sa.Column(
            "action",
            sa.Enum(
                "device_quarantine",
                "device_release",
                "device_update",
                "alert_acknowledge",
                "alert_resolve",
                "alert_analyze",
                "anomaly_review",
                "anomaly_confirm",
                "anomaly_false_positive",
                "user_create",
                "user_update",
                "user_deactivate",
                "user_password_reset",
                "user_login",
                "user_logout",
                "source_create",
                "source_update",
                "source_delete",
                "source_enable",
                "source_disable",
                "integration_block",
                "integration_unblock",
                "integration_test",
                "playbook_execute",
                "playbook_create",
                "playbook_update",
                "playbook_delete",
                name="auditaction",
                create_type=False,
            ),
            nullable=False,
        ),
        sa.Column("user_id", postgresql.UUID(as_uuid=True), nullable=True),
        sa.Column("username", sa.String(50), nullable=True),
        sa.Column("target_type", sa.String(50), nullable=False),
        sa.Column("target_id", sa.String(100), nullable=True),
        sa.Column("target_name", sa.String(255), nullable=True),
        sa.Column("description", sa.Text(), nullable=False),
        sa.Column("details", postgresql.JSON(), nullable=False, server_default="{}"),
        sa.Column("success", sa.Boolean(), nullable=False, server_default="true"),
        sa.Column("error_message", sa.Text(), nullable=True),
        sa.Column("ip_address", sa.String(45), nullable=True),
        sa.Column("user_agent", sa.String(500), nullable=True),
        sa.ForeignKeyConstraint(
            ["user_id"],
            ["users.id"],
            ondelete="SET NULL",
        ),
        sa.PrimaryKeyConstraint("id"),
    )

    # Create indexes
    op.create_index(
        "ix_audit_logs_timestamp",
        "audit_logs",
        ["timestamp"],
    )
    op.create_index(
        "ix_audit_logs_action",
        "audit_logs",
        ["action"],
    )
    op.create_index(
        "ix_audit_logs_user_id",
        "audit_logs",
        ["user_id"],
    )
    op.create_index(
        "ix_audit_logs_target_id",
        "audit_logs",
        ["target_id"],
    )


def downgrade() -> None:
    # Drop indexes
    op.drop_index("ix_audit_logs_target_id", table_name="audit_logs")
    op.drop_index("ix_audit_logs_user_id", table_name="audit_logs")
    op.drop_index("ix_audit_logs_action", table_name="audit_logs")
    op.drop_index("ix_audit_logs_timestamp", table_name="audit_logs")

    # Drop table
    op.drop_table("audit_logs")

    # Drop enum
    op.execute("DROP TYPE IF EXISTS auditaction")
