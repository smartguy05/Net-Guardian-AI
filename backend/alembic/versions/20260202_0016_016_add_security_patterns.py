"""Add security_pattern_feeds and security_patterns tables.

Revision ID: 016
Revises: 015
Create Date: 2026-02-02

"""

from alembic import op

# revision identifiers, used by Alembic.
revision = "016"
down_revision = "015"
branch_labels = None
depends_on = None


def upgrade() -> None:
    """Create security pattern tables and enums."""
    # Create enums
    op.execute("""
        DO $$
        BEGIN
            IF NOT EXISTS (SELECT 1 FROM pg_type WHERE typname = 'patterncategory') THEN
                CREATE TYPE patterncategory AS ENUM (
                    'sql_injection',
                    'command_injection',
                    'path_traversal',
                    'xss',
                    'deserialization',
                    'ssrf',
                    'auth_bypass',
                    'log_injection',
                    'ldap_injection',
                    'xxe',
                    'custom'
                );
            END IF;
        END$$
    """)

    op.execute("""
        DO $$
        BEGIN
            IF NOT EXISTS (SELECT 1 FROM pg_type WHERE typname = 'patterntype') THEN
                CREATE TYPE patterntype AS ENUM ('regex', 'literal', 'keyword');
            END IF;
        END$$
    """)

    op.execute("""
        DO $$
        BEGIN
            IF NOT EXISTS (SELECT 1 FROM pg_type WHERE typname = 'patternsource') THEN
                CREATE TYPE patternsource AS ENUM ('builtin', 'user', 'feed');
            END IF;
        END$$
    """)

    # Create security_pattern_feeds table first (referenced by security_patterns)
    op.execute("""
        CREATE TABLE IF NOT EXISTS security_pattern_feeds (
            id UUID NOT NULL PRIMARY KEY,
            name VARCHAR(255) NOT NULL,
            description TEXT,
            url VARCHAR(2048) NOT NULL,
            enabled BOOLEAN NOT NULL DEFAULT true,
            update_interval_hours INTEGER NOT NULL DEFAULT 24,
            auth_type VARCHAR(32) NOT NULL DEFAULT 'none',
            auth_config JSONB NOT NULL DEFAULT '{}',
            field_mapping JSONB NOT NULL DEFAULT '{}',
            last_fetch_at TIMESTAMP WITH TIME ZONE,
            last_fetch_status VARCHAR(32),
            last_fetch_message TEXT,
            pattern_count INTEGER NOT NULL DEFAULT 0,
            created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT now(),
            updated_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT now()
        )
    """)

    # Create security_patterns table
    op.execute("""
        CREATE TABLE IF NOT EXISTS security_patterns (
            id UUID NOT NULL PRIMARY KEY,
            name VARCHAR(255) NOT NULL,
            description TEXT,
            category patterncategory NOT NULL,
            pattern_type patterntype NOT NULL,
            pattern TEXT NOT NULL,
            severity alertseverity NOT NULL DEFAULT 'medium',
            enabled BOOLEAN NOT NULL DEFAULT true,
            tags JSONB NOT NULL DEFAULT '[]',
            extra_data JSONB NOT NULL DEFAULT '{}',
            source patternsource NOT NULL DEFAULT 'user',
            feed_id UUID REFERENCES security_pattern_feeds(id) ON DELETE CASCADE,
            examples JSONB NOT NULL DEFAULT '[]',
            "references" JSONB NOT NULL DEFAULT '[]',
            hit_count INTEGER NOT NULL DEFAULT 0,
            last_hit_at TIMESTAMP WITH TIME ZONE,
            created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT now(),
            updated_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT now()
        )
    """)

    # Create indexes
    op.execute(
        "CREATE INDEX IF NOT EXISTS ix_security_patterns_category "
        "ON security_patterns(category)"
    )
    op.execute(
        "CREATE INDEX IF NOT EXISTS ix_security_patterns_enabled "
        "ON security_patterns(enabled)"
    )
    op.execute(
        "CREATE INDEX IF NOT EXISTS ix_security_patterns_source "
        "ON security_patterns(source)"
    )
    op.execute(
        "CREATE INDEX IF NOT EXISTS ix_security_patterns_feed_id "
        "ON security_patterns(feed_id)"
    )
    op.execute(
        "CREATE INDEX IF NOT EXISTS ix_security_pattern_feeds_enabled "
        "ON security_pattern_feeds(enabled)"
    )


def downgrade() -> None:
    """Drop security pattern tables and enums."""
    op.execute("DROP INDEX IF EXISTS ix_security_pattern_feeds_enabled")
    op.execute("DROP INDEX IF EXISTS ix_security_patterns_feed_id")
    op.execute("DROP INDEX IF EXISTS ix_security_patterns_source")
    op.execute("DROP INDEX IF EXISTS ix_security_patterns_enabled")
    op.execute("DROP INDEX IF EXISTS ix_security_patterns_category")
    op.execute("DROP TABLE IF EXISTS security_patterns")
    op.execute("DROP TABLE IF EXISTS security_pattern_feeds")
    op.execute("DROP TYPE IF EXISTS patternsource")
    op.execute("DROP TYPE IF EXISTS patterntype")
    op.execute("DROP TYPE IF EXISTS patterncategory")
