"""Initial schema with TimescaleDB hypertables.

Revision ID: 001
Revises:
Create Date: 2026-01-16
"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

# revision identifiers, used by Alembic.
revision: str = "001"
down_revision: Union[str, None] = None
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # Enable TimescaleDB extension
    op.execute("CREATE EXTENSION IF NOT EXISTS timescaledb CASCADE;")

    # Create enum types
    op.execute("CREATE TYPE userrole AS ENUM ('admin', 'operator', 'viewer');")
    op.execute("CREATE TYPE devicetype AS ENUM ('pc', 'mobile', 'iot', 'server', 'network', 'unknown');")
    op.execute("CREATE TYPE devicestatus AS ENUM ('active', 'inactive', 'quarantined');")
    op.execute("CREATE TYPE sourcetype AS ENUM ('api_pull', 'file_watch', 'api_push');")
    op.execute("CREATE TYPE parsertype AS ENUM ('adguard', 'unifi', 'pfsense', 'json', 'syslog', 'nginx', 'custom');")
    op.execute("CREATE TYPE eventtype AS ENUM ('dns', 'firewall', 'auth', 'http', 'system', 'network', 'unknown');")
    op.execute("CREATE TYPE eventseverity AS ENUM ('debug', 'info', 'warning', 'error', 'critical');")
    op.execute("CREATE TYPE alertseverity AS ENUM ('info', 'low', 'medium', 'high', 'critical');")
    op.execute("CREATE TYPE alertstatus AS ENUM ('new', 'acknowledged', 'resolved', 'false_positive');")

    # Users table
    op.create_table(
        "users",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("username", sa.String(50), unique=True, nullable=False),
        sa.Column("email", sa.String(255), unique=True, nullable=False),
        sa.Column("password_hash", sa.String(255), nullable=False),
        sa.Column("role", postgresql.ENUM("admin", "operator", "viewer", name="userrole", create_type=False), nullable=False, server_default="viewer"),
        sa.Column("is_active", sa.Boolean(), nullable=False, server_default="true"),
        sa.Column("must_change_password", sa.Boolean(), nullable=False, server_default="false"),
        sa.Column("last_login", sa.DateTime(timezone=True), nullable=True),
        sa.Column("created_by", postgresql.UUID(as_uuid=True), sa.ForeignKey("users.id", ondelete="SET NULL"), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
    )
    op.create_index("ix_users_username", "users", ["username"])
    op.create_index("ix_users_email", "users", ["email"])

    # Devices table
    op.create_table(
        "devices",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("mac_address", sa.String(17), unique=True, nullable=False),
        sa.Column("ip_addresses", postgresql.ARRAY(sa.String(45)), nullable=False, server_default="{}"),
        sa.Column("hostname", sa.String(255), nullable=True),
        sa.Column("manufacturer", sa.String(255), nullable=True),
        sa.Column("device_type", postgresql.ENUM("pc", "mobile", "iot", "server", "network", "unknown", name="devicetype", create_type=False), nullable=False, server_default="unknown"),
        sa.Column("profile_tags", postgresql.ARRAY(sa.String(50)), nullable=False, server_default="{}"),
        sa.Column("first_seen", sa.DateTime(timezone=True), nullable=False),
        sa.Column("last_seen", sa.DateTime(timezone=True), nullable=False),
        sa.Column("status", postgresql.ENUM("active", "inactive", "quarantined", name="devicestatus", create_type=False), nullable=False, server_default="active"),
        sa.Column("baseline_ready", sa.Boolean(), nullable=False, server_default="false"),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
    )
    op.create_index("ix_devices_mac_address", "devices", ["mac_address"])
    op.create_index("ix_devices_status", "devices", ["status"])

    # Log Sources table
    op.create_table(
        "log_sources",
        sa.Column("id", sa.String(100), primary_key=True),
        sa.Column("name", sa.String(255), nullable=False),
        sa.Column("description", sa.Text(), nullable=True),
        sa.Column("source_type", postgresql.ENUM("api_pull", "file_watch", "api_push", name="sourcetype", create_type=False), nullable=False),
        sa.Column("enabled", sa.Boolean(), nullable=False, server_default="true"),
        sa.Column("config", postgresql.JSONB(), nullable=False, server_default="{}"),
        sa.Column("parser_type", postgresql.ENUM("adguard", "unifi", "pfsense", "json", "syslog", "nginx", "custom", name="parsertype", create_type=False), nullable=False),
        sa.Column("parser_config", postgresql.JSONB(), nullable=False, server_default="{}"),
        sa.Column("api_key", sa.String(64), unique=True, nullable=True),
        sa.Column("last_event_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("last_error", sa.Text(), nullable=True),
        sa.Column("event_count", sa.BigInteger(), nullable=False, server_default="0"),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
    )
    op.create_index("ix_log_sources_api_key", "log_sources", ["api_key"])

    # Raw Events table (will become TimescaleDB hypertable)
    op.create_table(
        "raw_events",
        sa.Column("id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("timestamp", sa.DateTime(timezone=True), nullable=False),
        sa.Column("source_id", sa.String(100), sa.ForeignKey("log_sources.id", ondelete="CASCADE"), nullable=False),
        sa.Column("event_type", postgresql.ENUM("dns", "firewall", "auth", "http", "system", "network", "unknown", name="eventtype", create_type=False), nullable=False),
        sa.Column("severity", postgresql.ENUM("debug", "info", "warning", "error", "critical", name="eventseverity", create_type=False), nullable=False, server_default="info"),
        sa.Column("client_ip", sa.String(45), nullable=True),
        sa.Column("target_ip", sa.String(45), nullable=True),
        sa.Column("domain", sa.String(255), nullable=True),
        sa.Column("port", sa.Integer(), nullable=True),
        sa.Column("protocol", sa.String(10), nullable=True),
        sa.Column("action", sa.String(50), nullable=True),
        sa.Column("raw_message", sa.Text(), nullable=False),
        sa.Column("parsed_fields", postgresql.JSONB(), nullable=False, server_default="{}"),
        sa.Column("query_type", sa.String(10), nullable=True),
        sa.Column("response_status", sa.String(50), nullable=True),
        sa.Column("blocked_reason", sa.String(255), nullable=True),
        sa.Column("entropy_score", sa.Float(), nullable=True),
        sa.Column("device_id", postgresql.UUID(as_uuid=True), sa.ForeignKey("devices.id", ondelete="SET NULL"), nullable=True),
        sa.PrimaryKeyConstraint("id", "timestamp"),  # Composite PK required for hypertable
    )

    # Convert raw_events to TimescaleDB hypertable (7-day chunks for home use)
    op.execute("""
        SELECT create_hypertable(
            'raw_events',
            'timestamp',
            chunk_time_interval => INTERVAL '7 days',
            if_not_exists => TRUE
        );
    """)

    # Indexes for raw_events
    op.create_index("ix_raw_events_source_id", "raw_events", ["source_id"])
    op.create_index("ix_raw_events_event_type", "raw_events", ["event_type"])
    op.create_index("ix_raw_events_client_ip", "raw_events", ["client_ip"])
    op.create_index("ix_raw_events_domain", "raw_events", ["domain"])
    op.create_index("ix_raw_events_device_id", "raw_events", ["device_id"])
    op.create_index("ix_raw_events_device_timestamp", "raw_events", ["device_id", "timestamp"])
    op.create_index("ix_raw_events_source_timestamp", "raw_events", ["source_id", "timestamp"])

    # Alerts table
    op.create_table(
        "alerts",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("timestamp", sa.DateTime(timezone=True), nullable=False),
        sa.Column("device_id", postgresql.UUID(as_uuid=True), sa.ForeignKey("devices.id", ondelete="SET NULL"), nullable=True),
        sa.Column("rule_id", sa.String(100), nullable=False),
        sa.Column("severity", postgresql.ENUM("info", "low", "medium", "high", "critical", name="alertseverity", create_type=False), nullable=False),
        sa.Column("title", sa.String(255), nullable=False),
        sa.Column("description", sa.Text(), nullable=False),
        sa.Column("llm_analysis", postgresql.JSONB(), nullable=True),
        sa.Column("status", postgresql.ENUM("new", "acknowledged", "resolved", "false_positive", name="alertstatus", create_type=False), nullable=False, server_default="new"),
        sa.Column("actions_taken", postgresql.JSONB(), nullable=False, server_default="[]"),
        sa.Column("acknowledged_by", postgresql.UUID(as_uuid=True), sa.ForeignKey("users.id", ondelete="SET NULL"), nullable=True),
        sa.Column("acknowledged_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("resolved_by", postgresql.UUID(as_uuid=True), sa.ForeignKey("users.id", ondelete="SET NULL"), nullable=True),
        sa.Column("resolved_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
    )
    op.create_index("ix_alerts_device_id", "alerts", ["device_id"])
    op.create_index("ix_alerts_rule_id", "alerts", ["rule_id"])
    op.create_index("ix_alerts_severity", "alerts", ["severity"])
    op.create_index("ix_alerts_status", "alerts", ["status"])
    op.create_index("ix_alerts_timestamp", "alerts", ["timestamp"])

    # Detection Rules table
    op.create_table(
        "detection_rules",
        sa.Column("id", sa.String(100), primary_key=True),
        sa.Column("name", sa.String(255), nullable=False),
        sa.Column("description", sa.Text(), nullable=True),
        sa.Column("severity", postgresql.ENUM("info", "low", "medium", "high", "critical", name="alertseverity", create_type=False), nullable=False),
        sa.Column("enabled", sa.Boolean(), nullable=False, server_default="true"),
        sa.Column("conditions", postgresql.JSONB(), nullable=False),
        sa.Column("response_actions", postgresql.JSONB(), nullable=False, server_default="[]"),
        sa.Column("cooldown_minutes", sa.Integer(), nullable=False, server_default="60"),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
    )


def downgrade() -> None:
    # Drop tables in reverse order
    op.drop_table("detection_rules")
    op.drop_table("alerts")
    op.drop_table("raw_events")
    op.drop_table("log_sources")
    op.drop_table("devices")
    op.drop_table("users")

    # Drop enum types
    op.execute("DROP TYPE IF EXISTS alertstatus;")
    op.execute("DROP TYPE IF EXISTS alertseverity;")
    op.execute("DROP TYPE IF EXISTS eventseverity;")
    op.execute("DROP TYPE IF EXISTS eventtype;")
    op.execute("DROP TYPE IF EXISTS parsertype;")
    op.execute("DROP TYPE IF EXISTS sourcetype;")
    op.execute("DROP TYPE IF EXISTS devicestatus;")
    op.execute("DROP TYPE IF EXISTS devicetype;")
    op.execute("DROP TYPE IF EXISTS userrole;")
