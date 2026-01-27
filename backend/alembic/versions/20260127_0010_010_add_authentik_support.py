"""add_authentik_support

Revision ID: 010
Revises: 4ac0c165a6e9
Create Date: 2026-01-27 00:00:00.000000+00:00
"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = '010'
down_revision: Union[str, None] = '4ac0c165a6e9'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # Add external authentication columns to users table
    op.add_column(
        'users',
        sa.Column('external_id', sa.String(255), nullable=True, unique=True)
    )
    op.add_column(
        'users',
        sa.Column('external_provider', sa.String(50), nullable=True)
    )
    op.add_column(
        'users',
        sa.Column('is_external', sa.Boolean(), nullable=False, server_default='false')
    )

    # Create index on external_id for faster lookups
    op.create_index('ix_users_external_id', 'users', ['external_id'], unique=True)

    # Add 'authentik' to the parsertype enum
    op.execute("ALTER TYPE parsertype ADD VALUE IF NOT EXISTS 'authentik'")


def downgrade() -> None:
    # Drop the index
    op.drop_index('ix_users_external_id', table_name='users')

    # Remove the columns
    op.drop_column('users', 'is_external')
    op.drop_column('users', 'external_provider')
    op.drop_column('users', 'external_id')

    # Note: PostgreSQL doesn't support removing enum values directly
    # The 'authentik' enum value will remain in place on downgrade
