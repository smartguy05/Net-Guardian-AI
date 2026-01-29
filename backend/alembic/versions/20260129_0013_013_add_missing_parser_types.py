"""Add missing enum values (parser types and event types).

Revision ID: 013
Revises: 012
Create Date: 2026-01-29

"""

from alembic import op

# revision identifiers, used by Alembic.
revision = "013"
down_revision = "012"
branch_labels = None
depends_on = None


def upgrade() -> None:
    """Add missing enum values to parsertype and eventtype enums."""
    # Add missing parser types
    op.execute("ALTER TYPE parsertype ADD VALUE IF NOT EXISTS 'ollama';")
    op.execute("ALTER TYPE parsertype ADD VALUE IF NOT EXISTS 'endpoint';")
    op.execute("ALTER TYPE parsertype ADD VALUE IF NOT EXISTS 'netflow';")
    op.execute("ALTER TYPE parsertype ADD VALUE IF NOT EXISTS 'sflow';")

    # Add missing event types
    op.execute("ALTER TYPE eventtype ADD VALUE IF NOT EXISTS 'llm';")
    op.execute("ALTER TYPE eventtype ADD VALUE IF NOT EXISTS 'endpoint';")
    op.execute("ALTER TYPE eventtype ADD VALUE IF NOT EXISTS 'flow';")


def downgrade() -> None:
    """PostgreSQL doesn't support removing enum values easily.

    To fully downgrade, you would need to:
    1. Create a new enum type without these values
    2. Update all tables using the enum
    3. Drop the old enum
    4. Rename the new enum

    For simplicity, we leave the enum values in place.
    """
    pass
