"""add_loki_parser_type

Revision ID: 4ac0c165a6e9
Revises: 009
Create Date: 2026-01-23 16:54:06.298338+00:00
"""

from typing import Sequence, Union

from alembic import op


# revision identifiers, used by Alembic.
revision: str = "4ac0c165a6e9"
down_revision: Union[str, None] = "009"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # Add 'loki' to the parsertype enum
    op.execute("ALTER TYPE parsertype ADD VALUE IF NOT EXISTS 'loki'")


def downgrade() -> None:
    # Note: PostgreSQL doesn't support removing enum values directly
    # This would require recreating the enum type, which is complex
    # For now, we leave the enum value in place on downgrade
    pass
