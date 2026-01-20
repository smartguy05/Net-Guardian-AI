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
    # Create audit action enum using raw SQL
    op.execute("""
        DO $$
        BEGIN
            IF NOT EXISTS (SELECT 1 FROM pg_type WHERE typname = 'auditaction') THEN
                CREATE TYPE auditaction AS ENUM (
                    'device_quarantine',
                    'device_release',
                    'device_update',
                    'alert_acknowledge',
                    'alert_resolve',
                    'alert_analyze',
                    'anomaly_review',
                    'anomaly_confirm',
                    'anomaly_false_positive',
                    'user_create',
                    'user_update',
                    'user_deactivate',
                    'user_password_reset',
                    'user_login',
                    'user_logout',
                    'source_create',
                    'source_update',
                    'source_delete',
                    'source_enable',
                    'source_disable',
                    'integration_block',
                    'integration_unblock',
                    'integration_test',
                    'playbook_execute',
                    'playbook_create',
                    'playbook_update',
                    'playbook_delete'
                );
            END IF;
        END$$
    """)

    # Create table
    op.execute("""
        CREATE TABLE audit_logs (
            id UUID NOT NULL PRIMARY KEY,
            timestamp TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP,
            action auditaction NOT NULL,
            user_id UUID REFERENCES users(id) ON DELETE SET NULL,
            username VARCHAR(50),
            target_type VARCHAR(50) NOT NULL,
            target_id VARCHAR(100),
            target_name VARCHAR(255),
            description TEXT NOT NULL,
            details JSON NOT NULL DEFAULT '{}',
            success BOOLEAN NOT NULL DEFAULT true,
            error_message TEXT,
            ip_address VARCHAR(45),
            user_agent VARCHAR(500)
        )
    """)

    # Create indexes
    op.execute("CREATE INDEX ix_audit_logs_timestamp ON audit_logs(timestamp)")
    op.execute("CREATE INDEX ix_audit_logs_action ON audit_logs(action)")
    op.execute("CREATE INDEX ix_audit_logs_user_id ON audit_logs(user_id)")
    op.execute("CREATE INDEX ix_audit_logs_target_id ON audit_logs(target_id)")


def downgrade() -> None:
    op.execute("DROP INDEX IF EXISTS ix_audit_logs_target_id")
    op.execute("DROP INDEX IF EXISTS ix_audit_logs_user_id")
    op.execute("DROP INDEX IF EXISTS ix_audit_logs_action")
    op.execute("DROP INDEX IF EXISTS ix_audit_logs_timestamp")
    op.execute("DROP TABLE IF EXISTS audit_logs")
    op.execute("DROP TYPE IF EXISTS auditaction")
