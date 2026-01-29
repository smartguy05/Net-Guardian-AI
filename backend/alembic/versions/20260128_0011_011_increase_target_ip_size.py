"""increase_target_ip_size

Revision ID: 011
Revises: 010
Create Date: 2026-01-28 00:00:00.000000+00:00
"""

from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = "011"
down_revision: Union[str, None] = "010"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # Increase target_ip field size to accommodate CNAMEs from DNS responses
    # VARCHAR(45) was only enough for IPv6, but DNS answers can include CNAMEs
    op.alter_column(
        "raw_events",
        "target_ip",
        type_=sa.String(255),
        existing_type=sa.String(45),
        existing_nullable=True,
    )


def downgrade() -> None:
    # Revert to original size (may truncate data)
    op.alter_column(
        "raw_events",
        "target_ip",
        type_=sa.String(45),
        existing_type=sa.String(255),
        existing_nullable=True,
    )
