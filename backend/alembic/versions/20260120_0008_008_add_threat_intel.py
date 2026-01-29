"""Add threat_intel_feeds and threat_indicators tables.

Revision ID: 008
Revises: 007
Create Date: 2026-01-20

"""

from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

# revision identifiers, used by Alembic.
revision: str = "008"
down_revision: Union[str, None] = "007"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # Create enums using raw SQL
    op.execute("""
        DO $$
        BEGIN
            IF NOT EXISTS (SELECT 1 FROM pg_type WHERE typname = 'feedtype') THEN
                CREATE TYPE feedtype AS ENUM ('csv', 'json', 'stix', 'url_list', 'ip_list');
            END IF;
        END$$
    """)

    op.execute("""
        DO $$
        BEGIN
            IF NOT EXISTS (SELECT 1 FROM pg_type WHERE typname = 'indicatortype') THEN
                CREATE TYPE indicatortype AS ENUM ('ip', 'domain', 'url', 'hash_md5', 'hash_sha1', 'hash_sha256', 'email', 'cidr');
            END IF;
        END$$
    """)

    # Create threat_intel_feeds table
    op.execute("""
        CREATE TABLE threat_intel_feeds (
            id UUID NOT NULL PRIMARY KEY,
            name VARCHAR(255) NOT NULL,
            description TEXT,
            feed_type feedtype NOT NULL,
            url VARCHAR(2048) NOT NULL,
            enabled BOOLEAN NOT NULL DEFAULT true,
            update_interval_hours INTEGER NOT NULL DEFAULT 24,
            auth_type VARCHAR(32) NOT NULL DEFAULT 'none',
            auth_config JSONB NOT NULL DEFAULT '{}',
            field_mapping JSONB NOT NULL DEFAULT '{}',
            last_fetch_at TIMESTAMP WITH TIME ZONE,
            last_fetch_status VARCHAR(32),
            last_fetch_message TEXT,
            indicator_count INTEGER NOT NULL DEFAULT 0,
            created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT now(),
            updated_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT now()
        )
    """)

    # Create threat_indicators table
    op.execute("""
        CREATE TABLE threat_indicators (
            id UUID NOT NULL PRIMARY KEY,
            feed_id UUID NOT NULL REFERENCES threat_intel_feeds(id) ON DELETE CASCADE,
            indicator_type indicatortype NOT NULL,
            value VARCHAR(2048) NOT NULL,
            confidence INTEGER NOT NULL DEFAULT 50,
            severity VARCHAR(32) NOT NULL DEFAULT 'medium',
            tags JSONB NOT NULL DEFAULT '[]',
            description TEXT,
            source_ref VARCHAR(255),
            first_seen_at TIMESTAMP WITH TIME ZONE,
            last_seen_at TIMESTAMP WITH TIME ZONE,
            expires_at TIMESTAMP WITH TIME ZONE,
            extra_data JSONB NOT NULL DEFAULT '{}',
            hit_count INTEGER NOT NULL DEFAULT 0,
            last_hit_at TIMESTAMP WITH TIME ZONE,
            created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT now(),
            updated_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT now()
        )
    """)

    # Create indexes
    op.execute("CREATE INDEX ix_threat_indicators_value ON threat_indicators(value)")
    op.execute("CREATE INDEX ix_threat_indicators_feed_id ON threat_indicators(feed_id)")
    op.execute(
        "CREATE INDEX ix_threat_indicators_indicator_type ON threat_indicators(indicator_type)"
    )
    op.execute("CREATE INDEX ix_threat_indicators_severity ON threat_indicators(severity)")
    op.execute("CREATE INDEX ix_threat_intel_feeds_enabled ON threat_intel_feeds(enabled)")


def downgrade() -> None:
    op.execute("DROP INDEX IF EXISTS ix_threat_intel_feeds_enabled")
    op.execute("DROP INDEX IF EXISTS ix_threat_indicators_severity")
    op.execute("DROP INDEX IF EXISTS ix_threat_indicators_indicator_type")
    op.execute("DROP INDEX IF EXISTS ix_threat_indicators_feed_id")
    op.execute("DROP INDEX IF EXISTS ix_threat_indicators_value")
    op.execute("DROP TABLE IF EXISTS threat_indicators")
    op.execute("DROP TABLE IF EXISTS threat_intel_feeds")
    op.execute("DROP TYPE IF EXISTS indicatortype")
    op.execute("DROP TYPE IF EXISTS feedtype")
