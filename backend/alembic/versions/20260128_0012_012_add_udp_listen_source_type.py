"""add_udp_listen_source_type

Revision ID: 012
Revises: 011
Create Date: 2026-01-28 00:00:00.000000+00:00
"""
from typing import Sequence, Union

from alembic import op


# revision identifiers, used by Alembic.
revision: str = '012'
down_revision: Union[str, None] = '011'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # Add udp_listen to the sourcetype enum for receiving syslog/NetFlow/sFlow via UDP
    op.execute("ALTER TYPE sourcetype ADD VALUE IF NOT EXISTS 'udp_listen'")


def downgrade() -> None:
    # PostgreSQL doesn't support removing enum values directly
    # The value will remain but won't be used if code is rolled back
    pass
