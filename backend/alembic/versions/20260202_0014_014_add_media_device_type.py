"""Add media device type for TVs, speakers, streaming devices.

Revision ID: 014
Revises: 013
Create Date: 2026-02-02

"""

from alembic import op

# revision identifiers, used by Alembic.
revision = "014"
down_revision = "013"
branch_labels = None
depends_on = None


def upgrade() -> None:
    """Add 'media' value to devicetype enum."""
    op.execute("ALTER TYPE devicetype ADD VALUE IF NOT EXISTS 'media'")


def downgrade() -> None:
    """PostgreSQL doesn't support removing enum values directly."""
    pass
