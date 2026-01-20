"""Add notification_preferences table for email and ntfy.sh notifications.

Revision ID: 005
Revises: 004
Create Date: 2026-01-19

"""

from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

# revision identifiers, used by Alembic.
revision: str = "005"
down_revision: Union[str, None] = "004"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # Create notification_preferences table
    op.create_table(
        "notification_preferences",
        sa.Column("id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("user_id", postgresql.UUID(as_uuid=True), nullable=False),
        # Email settings
        sa.Column("email_enabled", sa.Boolean(), nullable=False, server_default="false"),
        sa.Column("email_address", sa.String(255), nullable=True),
        sa.Column("email_on_critical", sa.Boolean(), nullable=False, server_default="true"),
        sa.Column("email_on_high", sa.Boolean(), nullable=False, server_default="true"),
        sa.Column("email_on_medium", sa.Boolean(), nullable=False, server_default="false"),
        sa.Column("email_on_low", sa.Boolean(), nullable=False, server_default="false"),
        sa.Column("email_on_anomaly", sa.Boolean(), nullable=False, server_default="true"),
        sa.Column("email_on_quarantine", sa.Boolean(), nullable=False, server_default="true"),
        # ntfy.sh settings
        sa.Column("ntfy_enabled", sa.Boolean(), nullable=False, server_default="false"),
        sa.Column("ntfy_topic", sa.String(255), nullable=True),
        sa.Column("ntfy_on_critical", sa.Boolean(), nullable=False, server_default="true"),
        sa.Column("ntfy_on_high", sa.Boolean(), nullable=False, server_default="true"),
        sa.Column("ntfy_on_medium", sa.Boolean(), nullable=False, server_default="false"),
        sa.Column("ntfy_on_low", sa.Boolean(), nullable=False, server_default="false"),
        sa.Column("ntfy_on_anomaly", sa.Boolean(), nullable=False, server_default="true"),
        sa.Column("ntfy_on_quarantine", sa.Boolean(), nullable=False, server_default="true"),
        # Timestamps
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
        sa.ForeignKeyConstraint(
            ["user_id"],
            ["users.id"],
            ondelete="CASCADE",
        ),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("user_id", name="uq_notification_preferences_user_id"),
    )

    # Create index on user_id
    op.create_index(
        "ix_notification_preferences_user_id",
        "notification_preferences",
        ["user_id"],
    )


def downgrade() -> None:
    # Drop index
    op.drop_index("ix_notification_preferences_user_id", table_name="notification_preferences")

    # Drop table
    op.drop_table("notification_preferences")
