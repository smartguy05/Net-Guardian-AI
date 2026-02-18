"""Add investigations, gamification, and honeypot tables.

Revision ID: 018
Revises: 017
Create Date: 2026-02-02

"""

from alembic import op

# revision identifiers, used by Alembic.
revision = "018"
down_revision = "017"
branch_labels = None
depends_on = None


def upgrade() -> None:
    """Create investigation, gamification, and honeypot tables."""
    # ==================== INVESTIGATION ENUMS ====================
    op.execute("""
        DO $$
        BEGIN
            IF NOT EXISTS (SELECT 1 FROM pg_type WHERE typname = 'investigationstatus') THEN
                CREATE TYPE investigationstatus AS ENUM (
                    'pending', 'running', 'awaiting_approval', 'completed', 'failed', 'cancelled'
                );
            END IF;
        END$$
    """)

    op.execute("""
        DO $$
        BEGIN
            IF NOT EXISTS (SELECT 1 FROM pg_type WHERE typname = 'investigationsteptype') THEN
                CREATE TYPE investigationsteptype AS ENUM (
                    'gather_context', 'correlate_events', 'check_threat_intel',
                    'analyze_baseline', 'generate_hypothesis', 'recommend_actions'
                );
            END IF;
        END$$
    """)

    op.execute("""
        DO $$
        BEGIN
            IF NOT EXISTS (SELECT 1 FROM pg_type WHERE typname = 'investigationstepstatus') THEN
                CREATE TYPE investigationstepstatus AS ENUM (
                    'pending', 'running', 'completed', 'failed', 'skipped'
                );
            END IF;
        END$$
    """)

    op.execute("""
        DO $$
        BEGIN
            IF NOT EXISTS (SELECT 1 FROM pg_type WHERE typname = 'investigationactionstatus') THEN
                CREATE TYPE investigationactionstatus AS ENUM (
                    'pending', 'approved', 'rejected', 'executed', 'failed'
                );
            END IF;
        END$$
    """)

    op.execute("""
        DO $$
        BEGIN
            IF NOT EXISTS (SELECT 1 FROM pg_type WHERE typname = 'investigationactionrisklevel') THEN
                CREATE TYPE investigationactionrisklevel AS ENUM (
                    'low', 'medium', 'high', 'critical'
                );
            END IF;
        END$$
    """)

    op.execute("""
        DO $$
        BEGIN
            IF NOT EXISTS (SELECT 1 FROM pg_type WHERE typname = 'investigationtriggersource') THEN
                CREATE TYPE investigationtriggersource AS ENUM (
                    'playbook', 'manual', 'auto'
                );
            END IF;
        END$$
    """)

    # ==================== INVESTIGATION TABLES ====================
    op.execute("""
        CREATE TABLE IF NOT EXISTS investigations (
            id UUID NOT NULL PRIMARY KEY,
            alert_id UUID REFERENCES alerts(id) ON DELETE SET NULL,
            anomaly_id UUID REFERENCES anomaly_detections(id) ON DELETE SET NULL,
            device_id UUID REFERENCES devices(id) ON DELETE SET NULL,
            status investigationstatus NOT NULL DEFAULT 'pending',
            trigger_source investigationtriggersource NOT NULL,
            priority INTEGER NOT NULL DEFAULT 3,
            started_at TIMESTAMP WITH TIME ZONE,
            completed_at TIMESTAMP WITH TIME ZONE,
            summary TEXT,
            recommendations JSONB,
            requires_approval BOOLEAN NOT NULL DEFAULT true,
            approved_by UUID REFERENCES users(id) ON DELETE SET NULL,
            created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT now(),
            updated_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT now()
        )
    """)

    op.execute("""
        CREATE TABLE IF NOT EXISTS investigation_steps (
            id UUID NOT NULL PRIMARY KEY,
            investigation_id UUID NOT NULL REFERENCES investigations(id) ON DELETE CASCADE,
            step_number INTEGER NOT NULL,
            step_type investigationsteptype NOT NULL,
            status investigationstepstatus NOT NULL DEFAULT 'pending',
            reasoning TEXT,
            findings JSONB,
            confidence_score FLOAT,
            duration_ms INTEGER,
            llm_model_used VARCHAR(100),
            error_message TEXT,
            created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT now(),
            updated_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT now()
        )
    """)

    op.execute("""
        CREATE TABLE IF NOT EXISTS investigation_actions (
            id UUID NOT NULL PRIMARY KEY,
            investigation_id UUID NOT NULL REFERENCES investigations(id) ON DELETE CASCADE,
            action_type VARCHAR(50) NOT NULL,
            action_params JSONB NOT NULL DEFAULT '{}',
            risk_level investigationactionrisklevel NOT NULL,
            justification TEXT NOT NULL,
            status investigationactionstatus NOT NULL DEFAULT 'pending',
            approved_by UUID REFERENCES users(id) ON DELETE SET NULL,
            approved_at TIMESTAMP WITH TIME ZONE,
            rejected_by UUID REFERENCES users(id) ON DELETE SET NULL,
            rejected_at TIMESTAMP WITH TIME ZONE,
            rejection_reason TEXT,
            executed_at TIMESTAMP WITH TIME ZONE,
            execution_result JSONB,
            created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT now(),
            updated_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT now()
        )
    """)

    # Investigation indexes
    op.execute("CREATE INDEX IF NOT EXISTS ix_investigations_alert_id ON investigations(alert_id)")
    op.execute("CREATE INDEX IF NOT EXISTS ix_investigations_anomaly_id ON investigations(anomaly_id)")
    op.execute("CREATE INDEX IF NOT EXISTS ix_investigations_device_id ON investigations(device_id)")
    op.execute("CREATE INDEX IF NOT EXISTS ix_investigations_status ON investigations(status)")
    op.execute("CREATE INDEX IF NOT EXISTS ix_investigations_status_priority ON investigations(status, priority)")
    op.execute("CREATE INDEX IF NOT EXISTS ix_investigations_created_at ON investigations(created_at)")
    op.execute("CREATE INDEX IF NOT EXISTS ix_investigation_steps_investigation_id ON investigation_steps(investigation_id)")
    op.execute("CREATE INDEX IF NOT EXISTS ix_investigation_steps_investigation_step ON investigation_steps(investigation_id, step_number)")
    op.execute("CREATE INDEX IF NOT EXISTS ix_investigation_actions_investigation_id ON investigation_actions(investigation_id)")
    op.execute("CREATE INDEX IF NOT EXISTS ix_investigation_actions_status ON investigation_actions(status)")

    # ==================== GAMIFICATION ENUMS ====================
    op.execute("""
        DO $$
        BEGIN
            IF NOT EXISTS (SELECT 1 FROM pg_type WHERE typname = 'achievementrarity') THEN
                CREATE TYPE achievementrarity AS ENUM (
                    'common', 'uncommon', 'rare', 'legendary'
                );
            END IF;
        END$$
    """)

    op.execute("""
        DO $$
        BEGIN
            IF NOT EXISTS (SELECT 1 FROM pg_type WHERE typname = 'achievementcategory') THEN
                CREATE TYPE achievementcategory AS ENUM (
                    'alerts', 'anomalies', 'devices', 'investigations', 'streaks', 'milestones', 'special'
                );
            END IF;
        END$$
    """)

    op.execute("""
        DO $$
        BEGIN
            IF NOT EXISTS (SELECT 1 FROM pg_type WHERE typname = 'challengetype') THEN
                CREATE TYPE challengetype AS ENUM ('daily', 'weekly', 'monthly');
            END IF;
        END$$
    """)

    # ==================== GAMIFICATION TABLES ====================
    op.execute("""
        CREATE TABLE IF NOT EXISTS achievements (
            id VARCHAR(50) NOT NULL PRIMARY KEY,
            name VARCHAR(100) NOT NULL,
            description TEXT NOT NULL,
            category achievementcategory NOT NULL,
            rarity achievementrarity NOT NULL,
            icon VARCHAR(100) NOT NULL DEFAULT 'trophy',
            points INTEGER NOT NULL DEFAULT 10,
            requirements JSONB NOT NULL DEFAULT '{}',
            hidden BOOLEAN NOT NULL DEFAULT false,
            enabled BOOLEAN NOT NULL DEFAULT true,
            created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT now(),
            updated_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT now()
        )
    """)

    op.execute("""
        CREATE TABLE IF NOT EXISTS user_achievements (
            id UUID NOT NULL PRIMARY KEY,
            user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
            achievement_id VARCHAR(50) NOT NULL REFERENCES achievements(id) ON DELETE CASCADE,
            earned_at TIMESTAMP WITH TIME ZONE NOT NULL,
            context JSONB,
            created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT now(),
            updated_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT now(),
            UNIQUE(user_id, achievement_id)
        )
    """)

    op.execute("""
        CREATE TABLE IF NOT EXISTS user_stats (
            user_id UUID NOT NULL PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
            total_points INTEGER NOT NULL DEFAULT 0,
            current_level INTEGER NOT NULL DEFAULT 1,
            current_xp INTEGER NOT NULL DEFAULT 0,
            xp_to_next_level INTEGER NOT NULL DEFAULT 100,
            alerts_resolved INTEGER NOT NULL DEFAULT 0,
            critical_alerts_resolved INTEGER NOT NULL DEFAULT 0,
            anomalies_confirmed INTEGER NOT NULL DEFAULT 0,
            false_positives_marked INTEGER NOT NULL DEFAULT 0,
            devices_quarantined INTEGER NOT NULL DEFAULT 0,
            investigations_completed INTEGER NOT NULL DEFAULT 0,
            current_streak_days INTEGER NOT NULL DEFAULT 0,
            longest_streak_days INTEGER NOT NULL DEFAULT 0,
            last_activity_date DATE,
            last_activity_at TIMESTAMP WITH TIME ZONE,
            leaderboard_opt_in BOOLEAN NOT NULL DEFAULT true,
            created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT now(),
            updated_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT now()
        )
    """)

    op.execute("""
        CREATE TABLE IF NOT EXISTS challenges (
            id UUID NOT NULL PRIMARY KEY,
            name VARCHAR(100) NOT NULL,
            description TEXT NOT NULL,
            challenge_type challengetype NOT NULL,
            start_date DATE NOT NULL,
            end_date DATE NOT NULL,
            requirements JSONB NOT NULL DEFAULT '{}',
            reward_points INTEGER NOT NULL DEFAULT 50,
            reward_achievement_id VARCHAR(50) REFERENCES achievements(id) ON DELETE SET NULL,
            enabled BOOLEAN NOT NULL DEFAULT true,
            created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT now(),
            updated_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT now()
        )
    """)

    op.execute("""
        CREATE TABLE IF NOT EXISTS user_challenges (
            id UUID NOT NULL PRIMARY KEY,
            user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
            challenge_id UUID NOT NULL REFERENCES challenges(id) ON DELETE CASCADE,
            progress JSONB NOT NULL DEFAULT '{}',
            completed BOOLEAN NOT NULL DEFAULT false,
            completed_at TIMESTAMP WITH TIME ZONE,
            created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT now(),
            updated_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT now(),
            UNIQUE(user_id, challenge_id)
        )
    """)

    # Gamification indexes
    op.execute("CREATE INDEX IF NOT EXISTS ix_achievements_category ON achievements(category)")
    op.execute("CREATE INDEX IF NOT EXISTS ix_user_achievements_user_id ON user_achievements(user_id)")
    op.execute("CREATE INDEX IF NOT EXISTS ix_user_achievements_achievement_id ON user_achievements(achievement_id)")
    op.execute("CREATE INDEX IF NOT EXISTS ix_user_stats_total_points ON user_stats(total_points)")
    op.execute("CREATE INDEX IF NOT EXISTS ix_user_stats_current_level ON user_stats(current_level)")
    op.execute("CREATE INDEX IF NOT EXISTS ix_challenges_type ON challenges(challenge_type)")
    op.execute("CREATE INDEX IF NOT EXISTS ix_challenges_active ON challenges(start_date, end_date, enabled)")
    op.execute("CREATE INDEX IF NOT EXISTS ix_user_challenges_user_id ON user_challenges(user_id)")
    op.execute("CREATE INDEX IF NOT EXISTS ix_user_challenges_challenge_id ON user_challenges(challenge_id)")

    # ==================== HONEYPOT ENUMS ====================
    op.execute("""
        DO $$
        BEGIN
            IF NOT EXISTS (SELECT 1 FROM pg_type WHERE typname = 'honeypottype') THEN
                CREATE TYPE honeypottype AS ENUM (
                    'ssh', 'http', 'https', 'smb', 'ftp', 'telnet', 'mysql', 'postgresql', 'redis', 'rdp'
                );
            END IF;
        END$$
    """)

    op.execute("""
        DO $$
        BEGIN
            IF NOT EXISTS (SELECT 1 FROM pg_type WHERE typname = 'honeypotstatus') THEN
                CREATE TYPE honeypotstatus AS ENUM (
                    'pending', 'starting', 'running', 'stopping', 'stopped', 'failed'
                );
            END IF;
        END$$
    """)

    op.execute("""
        DO $$
        BEGIN
            IF NOT EXISTS (SELECT 1 FROM pg_type WHERE typname = 'sophisticationlevel') THEN
                CREATE TYPE sophisticationlevel AS ENUM (
                    'script_kiddie', 'intermediate', 'advanced', 'apt'
                );
            END IF;
        END$$
    """)

    # ==================== HONEYPOT TABLES ====================
    op.execute("""
        CREATE TABLE IF NOT EXISTS honeypot_templates (
            id VARCHAR(50) NOT NULL PRIMARY KEY,
            name VARCHAR(100) NOT NULL,
            honeypot_type honeypottype NOT NULL,
            description TEXT,
            container_image VARCHAR(255) NOT NULL,
            container_config JSONB NOT NULL DEFAULT '{}',
            exposed_ports JSONB NOT NULL DEFAULT '[]',
            default_timeout_minutes INTEGER NOT NULL DEFAULT 60,
            enabled BOOLEAN NOT NULL DEFAULT true,
            created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT now(),
            updated_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT now()
        )
    """)

    op.execute("""
        CREATE TABLE IF NOT EXISTS honeypot_instances (
            id UUID NOT NULL PRIMARY KEY,
            template_id VARCHAR(50) REFERENCES honeypot_templates(id) ON DELETE SET NULL,
            container_id VARCHAR(100) UNIQUE,
            container_name VARCHAR(100) NOT NULL,
            status honeypotstatus NOT NULL DEFAULT 'pending',
            host_ip VARCHAR(45),
            port_mappings JSONB NOT NULL DEFAULT '{}',
            trigger_alert_id UUID REFERENCES alerts(id) ON DELETE SET NULL,
            trigger_device_id UUID REFERENCES devices(id) ON DELETE SET NULL,
            trigger_reason TEXT,
            started_at TIMESTAMP WITH TIME ZONE,
            expires_at TIMESTAMP WITH TIME ZONE NOT NULL,
            stopped_at TIMESTAMP WITH TIME ZONE,
            interaction_count INTEGER NOT NULL DEFAULT 0,
            llm_profile JSONB,
            error_message TEXT,
            created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT now(),
            updated_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT now()
        )
    """)

    op.execute("""
        CREATE TABLE IF NOT EXISTS honeypot_interactions (
            id UUID NOT NULL PRIMARY KEY,
            honeypot_id UUID NOT NULL REFERENCES honeypot_instances(id) ON DELETE CASCADE,
            timestamp TIMESTAMP WITH TIME ZONE NOT NULL,
            source_ip VARCHAR(45) NOT NULL,
            source_port INTEGER,
            interaction_type VARCHAR(50) NOT NULL,
            raw_data TEXT,
            parsed_data JSONB,
            threat_indicators JSONB,
            created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT now(),
            updated_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT now()
        )
    """)

    op.execute("""
        CREATE TABLE IF NOT EXISTS attacker_profiles (
            id UUID NOT NULL PRIMARY KEY,
            source_ip VARCHAR(45) NOT NULL UNIQUE,
            first_seen TIMESTAMP WITH TIME ZONE NOT NULL,
            last_seen TIMESTAMP WITH TIME ZONE NOT NULL,
            total_interactions INTEGER NOT NULL DEFAULT 0,
            honeypots_triggered INTEGER NOT NULL DEFAULT 0,
            attack_patterns JSONB,
            sophistication_level sophisticationlevel,
            likely_intent VARCHAR(100),
            llm_analysis TEXT,
            recommended_actions JSONB,
            iocs JSONB,
            created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT now(),
            updated_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT now()
        )
    """)

    # Honeypot indexes
    op.execute("CREATE INDEX IF NOT EXISTS ix_honeypot_templates_type ON honeypot_templates(honeypot_type)")
    op.execute("CREATE INDEX IF NOT EXISTS ix_honeypot_instances_template_id ON honeypot_instances(template_id)")
    op.execute("CREATE INDEX IF NOT EXISTS ix_honeypot_instances_status ON honeypot_instances(status)")
    op.execute("CREATE INDEX IF NOT EXISTS ix_honeypot_instances_status_expires ON honeypot_instances(status, expires_at)")
    op.execute("CREATE INDEX IF NOT EXISTS ix_honeypot_instances_trigger_alert ON honeypot_instances(trigger_alert_id)")
    op.execute("CREATE INDEX IF NOT EXISTS ix_honeypot_instances_trigger_device ON honeypot_instances(trigger_device_id)")
    op.execute("CREATE INDEX IF NOT EXISTS ix_honeypot_instances_created_at ON honeypot_instances(created_at)")
    op.execute("CREATE INDEX IF NOT EXISTS ix_honeypot_interactions_honeypot_id ON honeypot_interactions(honeypot_id)")
    op.execute("CREATE INDEX IF NOT EXISTS ix_honeypot_interactions_timestamp ON honeypot_interactions(timestamp)")
    op.execute("CREATE INDEX IF NOT EXISTS ix_honeypot_interactions_source_ip ON honeypot_interactions(source_ip)")
    op.execute("CREATE INDEX IF NOT EXISTS ix_honeypot_interactions_type ON honeypot_interactions(interaction_type)")
    op.execute("CREATE INDEX IF NOT EXISTS ix_honeypot_interactions_honeypot_timestamp ON honeypot_interactions(honeypot_id, timestamp)")
    op.execute("CREATE INDEX IF NOT EXISTS ix_attacker_profiles_source_ip ON attacker_profiles(source_ip)")
    op.execute("CREATE INDEX IF NOT EXISTS ix_attacker_profiles_last_seen ON attacker_profiles(last_seen)")
    op.execute("CREATE INDEX IF NOT EXISTS ix_attacker_profiles_sophistication ON attacker_profiles(sophistication_level)")

    # Note: PlaybookActionType is a Python-only enum; the playbook actions column
    # is JSON, so there is no PostgreSQL enum type to alter.


def downgrade() -> None:
    """Drop investigation, gamification, and honeypot tables."""
    # Note: Cannot remove enum values in PostgreSQL, only drop the type

    # Drop honeypot tables and indexes
    op.execute("DROP TABLE IF EXISTS attacker_profiles CASCADE")
    op.execute("DROP TABLE IF EXISTS honeypot_interactions CASCADE")
    op.execute("DROP TABLE IF EXISTS honeypot_instances CASCADE")
    op.execute("DROP TABLE IF EXISTS honeypot_templates CASCADE")
    op.execute("DROP TYPE IF EXISTS sophisticationlevel")
    op.execute("DROP TYPE IF EXISTS honeypotstatus")
    op.execute("DROP TYPE IF EXISTS honeypottype")

    # Drop gamification tables
    op.execute("DROP TABLE IF EXISTS user_challenges CASCADE")
    op.execute("DROP TABLE IF EXISTS challenges CASCADE")
    op.execute("DROP TABLE IF EXISTS user_stats CASCADE")
    op.execute("DROP TABLE IF EXISTS user_achievements CASCADE")
    op.execute("DROP TABLE IF EXISTS achievements CASCADE")
    op.execute("DROP TYPE IF EXISTS challengetype")
    op.execute("DROP TYPE IF EXISTS achievementcategory")
    op.execute("DROP TYPE IF EXISTS achievementrarity")

    # Drop investigation tables
    op.execute("DROP TABLE IF EXISTS investigation_actions CASCADE")
    op.execute("DROP TABLE IF EXISTS investigation_steps CASCADE")
    op.execute("DROP TABLE IF EXISTS investigations CASCADE")
    op.execute("DROP TYPE IF EXISTS investigationtriggersource")
    op.execute("DROP TYPE IF EXISTS investigationactionrisklevel")
    op.execute("DROP TYPE IF EXISTS investigationactionstatus")
    op.execute("DROP TYPE IF EXISTS investigationstepstatus")
    op.execute("DROP TYPE IF EXISTS investigationsteptype")
    op.execute("DROP TYPE IF EXISTS investigationstatus")
