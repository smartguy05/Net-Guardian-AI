"""Add composite index for app event queries.

Revision ID: 017
Revises: 016
Create Date: 2026-02-02

This migration adds a composite index on (device_id, event_type, timestamp)
to optimize application anomaly detection queries which filter by these columns.
"""

from alembic import op

# revision identifiers, used by Alembic.
revision = "017"
down_revision = "016"
branch_labels = None
depends_on = None


def upgrade() -> None:
    """Add composite index for device app event queries."""
    # This index optimizes queries like:
    # SELECT * FROM raw_events
    # WHERE device_id = X
    #   AND event_type IN ('application', 'container', 'journal')
    #   AND timestamp >= cutoff
    op.create_index(
        "ix_raw_events_device_event_type_timestamp",
        "raw_events",
        ["device_id", "event_type", "timestamp"],
        unique=False,
    )


def downgrade() -> None:
    """Remove composite index."""
    op.drop_index("ix_raw_events_device_event_type_timestamp", table_name="raw_events")
