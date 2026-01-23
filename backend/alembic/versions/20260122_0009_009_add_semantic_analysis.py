"""Add semantic analysis tables for intelligent log pattern detection.

Revision ID: 009
Revises: 008
Create Date: 2026-01-22

"""

from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

# revision identifiers, used by Alembic.
revision: str = "009"
down_revision: Union[str, None] = "008"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # Create enums using raw SQL
    op.execute("""
        DO $$
        BEGIN
            IF NOT EXISTS (SELECT 1 FROM pg_type WHERE typname = 'llmprovider') THEN
                CREATE TYPE llmprovider AS ENUM ('claude', 'ollama');
            END IF;
        END$$
    """)

    op.execute("""
        DO $$
        BEGIN
            IF NOT EXISTS (SELECT 1 FROM pg_type WHERE typname = 'analysisrunstatus') THEN
                CREATE TYPE analysisrunstatus AS ENUM ('running', 'completed', 'failed');
            END IF;
        END$$
    """)

    op.execute("""
        DO $$
        BEGIN
            IF NOT EXISTS (SELECT 1 FROM pg_type WHERE typname = 'suggestedrulestatus') THEN
                CREATE TYPE suggestedrulestatus AS ENUM ('pending', 'approved', 'rejected', 'implemented');
            END IF;
        END$$
    """)

    op.execute("""
        DO $$
        BEGIN
            IF NOT EXISTS (SELECT 1 FROM pg_type WHERE typname = 'suggestedruletype') THEN
                CREATE TYPE suggestedruletype AS ENUM ('pattern_match', 'threshold', 'sequence');
            END IF;
        END$$
    """)

    # Create log_patterns table
    op.execute("""
        CREATE TABLE log_patterns (
            id UUID NOT NULL PRIMARY KEY,
            source_id VARCHAR(100) NOT NULL REFERENCES log_sources(id) ON DELETE CASCADE,
            normalized_pattern TEXT NOT NULL,
            pattern_hash VARCHAR(64) NOT NULL,
            first_seen TIMESTAMP WITH TIME ZONE NOT NULL,
            last_seen TIMESTAMP WITH TIME ZONE NOT NULL,
            occurrence_count INTEGER NOT NULL DEFAULT 1,
            is_ignored BOOLEAN NOT NULL DEFAULT false,
            created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT now(),
            updated_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT now()
        )
    """)

    # Create semantic_analysis_configs table
    op.execute("""
        CREATE TABLE semantic_analysis_configs (
            id UUID NOT NULL PRIMARY KEY,
            source_id VARCHAR(100) NOT NULL UNIQUE REFERENCES log_sources(id) ON DELETE CASCADE,
            enabled BOOLEAN NOT NULL DEFAULT true,
            llm_provider llmprovider NOT NULL DEFAULT 'claude',
            ollama_model VARCHAR(100),
            rarity_threshold INTEGER NOT NULL DEFAULT 3,
            batch_size INTEGER NOT NULL DEFAULT 50,
            batch_interval_minutes INTEGER NOT NULL DEFAULT 60,
            last_run_at TIMESTAMP WITH TIME ZONE,
            created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT now(),
            updated_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT now()
        )
    """)

    # Create semantic_analysis_runs table
    op.execute("""
        CREATE TABLE semantic_analysis_runs (
            id UUID NOT NULL PRIMARY KEY,
            source_id VARCHAR(100) NOT NULL REFERENCES log_sources(id) ON DELETE CASCADE,
            started_at TIMESTAMP WITH TIME ZONE NOT NULL,
            completed_at TIMESTAMP WITH TIME ZONE,
            status analysisrunstatus NOT NULL DEFAULT 'running',
            events_scanned INTEGER NOT NULL DEFAULT 0,
            irregulars_found INTEGER NOT NULL DEFAULT 0,
            llm_provider llmprovider NOT NULL,
            llm_response_summary TEXT,
            error_message TEXT,
            created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT now(),
            updated_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT now()
        )
    """)

    # Create irregular_logs table
    op.execute("""
        CREATE TABLE irregular_logs (
            id UUID NOT NULL PRIMARY KEY,
            event_id UUID NOT NULL,
            event_timestamp TIMESTAMP WITH TIME ZONE NOT NULL,
            source_id VARCHAR(100) NOT NULL REFERENCES log_sources(id) ON DELETE CASCADE,
            pattern_id UUID REFERENCES log_patterns(id) ON DELETE SET NULL,
            reason TEXT NOT NULL,
            llm_reviewed BOOLEAN NOT NULL DEFAULT false,
            llm_response TEXT,
            severity_score FLOAT,
            reviewed_by_user BOOLEAN NOT NULL DEFAULT false,
            reviewed_at TIMESTAMP WITH TIME ZONE,
            created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT now(),
            updated_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT now()
        )
    """)

    # Create suggested_rules table
    op.execute("""
        CREATE TABLE suggested_rules (
            id UUID NOT NULL PRIMARY KEY,
            source_id VARCHAR(100) REFERENCES log_sources(id) ON DELETE CASCADE,
            analysis_run_id UUID NOT NULL REFERENCES semantic_analysis_runs(id) ON DELETE CASCADE,
            irregular_log_id UUID NOT NULL REFERENCES irregular_logs(id) ON DELETE CASCADE,
            name VARCHAR(255) NOT NULL,
            description TEXT NOT NULL,
            reason TEXT NOT NULL,
            benefit TEXT NOT NULL,
            rule_type suggestedruletype NOT NULL,
            rule_config JSONB NOT NULL,
            status suggestedrulestatus NOT NULL DEFAULT 'pending',
            enabled BOOLEAN NOT NULL DEFAULT false,
            rule_hash VARCHAR(64) NOT NULL,
            reviewed_by UUID REFERENCES users(id) ON DELETE SET NULL,
            reviewed_at TIMESTAMP WITH TIME ZONE,
            rejection_reason TEXT,
            created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT now(),
            updated_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT now()
        )
    """)

    # Create suggested_rule_history table
    op.execute("""
        CREATE TABLE suggested_rule_history (
            id UUID NOT NULL PRIMARY KEY,
            rule_hash VARCHAR(64) NOT NULL UNIQUE,
            original_rule_id UUID NOT NULL REFERENCES suggested_rules(id) ON DELETE CASCADE,
            status suggestedrulestatus NOT NULL,
            created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT now()
        )
    """)

    # Create indexes
    op.execute("CREATE INDEX ix_log_patterns_source_id ON log_patterns(source_id)")
    op.execute("CREATE INDEX ix_log_patterns_pattern_hash ON log_patterns(pattern_hash)")
    op.execute("CREATE UNIQUE INDEX ix_log_patterns_source_hash ON log_patterns(source_id, pattern_hash)")

    op.execute("CREATE INDEX ix_irregular_logs_event_id ON irregular_logs(event_id)")
    op.execute("CREATE INDEX ix_irregular_logs_source_id ON irregular_logs(source_id)")
    op.execute("CREATE INDEX ix_irregular_logs_source_created ON irregular_logs(source_id, created_at)")
    op.execute("CREATE INDEX ix_irregular_logs_severity ON irregular_logs(severity_score)")

    op.execute("CREATE INDEX ix_semantic_analysis_runs_source_id ON semantic_analysis_runs(source_id)")
    op.execute("CREATE INDEX ix_semantic_analysis_runs_source_started ON semantic_analysis_runs(source_id, started_at)")

    op.execute("CREATE INDEX ix_suggested_rules_source_id ON suggested_rules(source_id)")
    op.execute("CREATE INDEX ix_suggested_rules_status ON suggested_rules(status)")
    op.execute("CREATE INDEX ix_suggested_rules_rule_hash ON suggested_rules(rule_hash)")

    op.execute("CREATE INDEX ix_suggested_rule_history_rule_hash ON suggested_rule_history(rule_hash)")


def downgrade() -> None:
    # Drop indexes
    op.execute("DROP INDEX IF EXISTS ix_suggested_rule_history_rule_hash")
    op.execute("DROP INDEX IF EXISTS ix_suggested_rules_rule_hash")
    op.execute("DROP INDEX IF EXISTS ix_suggested_rules_status")
    op.execute("DROP INDEX IF EXISTS ix_suggested_rules_source_id")
    op.execute("DROP INDEX IF EXISTS ix_semantic_analysis_runs_source_started")
    op.execute("DROP INDEX IF EXISTS ix_semantic_analysis_runs_source_id")
    op.execute("DROP INDEX IF EXISTS ix_irregular_logs_severity")
    op.execute("DROP INDEX IF EXISTS ix_irregular_logs_source_created")
    op.execute("DROP INDEX IF EXISTS ix_irregular_logs_source_id")
    op.execute("DROP INDEX IF EXISTS ix_irregular_logs_event_id")
    op.execute("DROP INDEX IF EXISTS ix_log_patterns_source_hash")
    op.execute("DROP INDEX IF EXISTS ix_log_patterns_pattern_hash")
    op.execute("DROP INDEX IF EXISTS ix_log_patterns_source_id")

    # Drop tables in reverse dependency order
    op.execute("DROP TABLE IF EXISTS suggested_rule_history")
    op.execute("DROP TABLE IF EXISTS suggested_rules")
    op.execute("DROP TABLE IF EXISTS irregular_logs")
    op.execute("DROP TABLE IF EXISTS semantic_analysis_runs")
    op.execute("DROP TABLE IF EXISTS semantic_analysis_configs")
    op.execute("DROP TABLE IF EXISTS log_patterns")

    # Drop enums
    op.execute("DROP TYPE IF EXISTS suggestedruletype")
    op.execute("DROP TYPE IF EXISTS suggestedrulestatus")
    op.execute("DROP TYPE IF EXISTS analysisrunstatus")
    op.execute("DROP TYPE IF EXISTS llmprovider")
