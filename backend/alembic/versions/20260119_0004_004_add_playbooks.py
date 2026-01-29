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
    # Create enums using raw SQL
    op.execute("""
        DO $$
        BEGIN
            IF NOT EXISTS (SELECT 1 FROM pg_type WHERE typname = 'playbookstatus') THEN
                CREATE TYPE playbookstatus AS ENUM ('active', 'disabled', 'draft');
            END IF;
        END$$
    """)

    op.execute("""
        DO $$
        BEGIN
            IF NOT EXISTS (SELECT 1 FROM pg_type WHERE typname = 'playbooktriggertype') THEN
                CREATE TYPE playbooktriggertype AS ENUM (
                    'anomaly_detected', 'alert_created', 'device_new',
                    'device_status_change', 'threshold_exceeded', 'schedule', 'manual'
                );
            END IF;
        END$$
    """)

    op.execute("""
        DO $$
        BEGIN
            IF NOT EXISTS (SELECT 1 FROM pg_type WHERE typname = 'executionstatus') THEN
                CREATE TYPE executionstatus AS ENUM ('pending', 'running', 'completed', 'failed', 'cancelled');
            END IF;
        END$$
    """)

    # Create playbooks table
    op.execute("""
        CREATE TABLE playbooks (
            id UUID NOT NULL PRIMARY KEY,
            name VARCHAR(100) NOT NULL,
            description TEXT,
            status playbookstatus NOT NULL DEFAULT 'draft',
            trigger_type playbooktriggertype NOT NULL,
            trigger_conditions JSON NOT NULL DEFAULT '{}',
            actions JSON NOT NULL DEFAULT '[]',
            cooldown_minutes INTEGER NOT NULL DEFAULT 60,
            max_executions_per_hour INTEGER NOT NULL DEFAULT 10,
            require_approval BOOLEAN NOT NULL DEFAULT false,
            created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP,
            updated_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP,
            created_by UUID REFERENCES users(id) ON DELETE SET NULL
        )
    """)

    op.execute("CREATE INDEX ix_playbooks_status ON playbooks(status)")
    op.execute("CREATE INDEX ix_playbooks_trigger_type ON playbooks(trigger_type)")

    # Create playbook_executions table
    op.execute("""
        CREATE TABLE playbook_executions (
            id UUID NOT NULL PRIMARY KEY,
            playbook_id UUID NOT NULL REFERENCES playbooks(id) ON DELETE CASCADE,
            status executionstatus NOT NULL DEFAULT 'pending',
            trigger_event JSON NOT NULL DEFAULT '{}',
            trigger_device_id UUID REFERENCES devices(id) ON DELETE SET NULL,
            started_at TIMESTAMP WITH TIME ZONE,
            completed_at TIMESTAMP WITH TIME ZONE,
            action_results JSON NOT NULL DEFAULT '[]',
            error_message TEXT,
            triggered_by UUID REFERENCES users(id) ON DELETE SET NULL,
            created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP
        )
    """)

    op.execute(
        "CREATE INDEX ix_playbook_executions_playbook_id ON playbook_executions(playbook_id)"
    )
    op.execute("CREATE INDEX ix_playbook_executions_status ON playbook_executions(status)")
    op.execute("CREATE INDEX ix_playbook_executions_created_at ON playbook_executions(created_at)")


def downgrade() -> None:
    op.execute("DROP INDEX IF EXISTS ix_playbook_executions_created_at")
    op.execute("DROP INDEX IF EXISTS ix_playbook_executions_status")
    op.execute("DROP INDEX IF EXISTS ix_playbook_executions_playbook_id")
    op.execute("DROP INDEX IF EXISTS ix_playbooks_trigger_type")
    op.execute("DROP INDEX IF EXISTS ix_playbooks_status")
    op.execute("DROP TABLE IF EXISTS playbook_executions")
    op.execute("DROP TABLE IF EXISTS playbooks")
    op.execute("DROP TYPE IF EXISTS executionstatus")
    op.execute("DROP TYPE IF EXISTS playbooktriggertype")
    op.execute("DROP TYPE IF EXISTS playbookstatus")
