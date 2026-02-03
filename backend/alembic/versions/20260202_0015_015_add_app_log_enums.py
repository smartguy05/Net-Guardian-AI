"""Add application log enum values for container, journal, and application event types.

Adds:
- EventType: container, journal, application
- ParserType: docker, journald, java_stacktrace, python_log
- AnomalyType: error_spike, new_error_pattern, container_restart, security_pattern

Revision ID: 015
Revises: 014
Create Date: 2026-02-02

"""

from alembic import op

# revision identifiers, used by Alembic.
revision = "015"
down_revision = "014"
branch_labels = None
depends_on = None


def upgrade() -> None:
    """Add new enum values for application log analysis."""
    # Add new EventType values
    op.execute("ALTER TYPE eventtype ADD VALUE IF NOT EXISTS 'container'")
    op.execute("ALTER TYPE eventtype ADD VALUE IF NOT EXISTS 'journal'")
    op.execute("ALTER TYPE eventtype ADD VALUE IF NOT EXISTS 'application'")

    # Add new ParserType values
    op.execute("ALTER TYPE parsertype ADD VALUE IF NOT EXISTS 'docker'")
    op.execute("ALTER TYPE parsertype ADD VALUE IF NOT EXISTS 'journald'")
    op.execute("ALTER TYPE parsertype ADD VALUE IF NOT EXISTS 'java_stacktrace'")
    op.execute("ALTER TYPE parsertype ADD VALUE IF NOT EXISTS 'python_log'")

    # Add new AnomalyType values
    op.execute("ALTER TYPE anomalytype ADD VALUE IF NOT EXISTS 'error_spike'")
    op.execute("ALTER TYPE anomalytype ADD VALUE IF NOT EXISTS 'new_error_pattern'")
    op.execute("ALTER TYPE anomalytype ADD VALUE IF NOT EXISTS 'container_restart'")
    op.execute("ALTER TYPE anomalytype ADD VALUE IF NOT EXISTS 'security_pattern'")


def downgrade() -> None:
    """PostgreSQL doesn't support removing enum values directly."""
    pass
