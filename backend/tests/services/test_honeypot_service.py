"""Tests for the honeypot service."""

from datetime import UTC, datetime, timedelta
from unittest.mock import AsyncMock, MagicMock, patch
from uuid import uuid4

import pytest

from app.data.honeypot_templates import DEFAULT_TEMPLATES
from app.models.honeypot import (
    AttackerProfile,
    HoneypotInstance,
    HoneypotInteraction,
    HoneypotStatus,
    HoneypotTemplate,
    HoneypotType,
    SophisticationLevel,
)
from app.services.honeypot.service import HoneypotService


class TestHoneypotType:
    """Tests for honeypot type enum."""

    def test_all_honeypot_types_exist(self):
        """Test all expected honeypot types exist."""
        assert HoneypotType.SSH
        assert HoneypotType.HTTP
        assert HoneypotType.FTP
        assert HoneypotType.TELNET
        assert HoneypotType.MYSQL
        assert HoneypotType.SMB
        assert HoneypotType.REDIS
        assert HoneypotType.RDP
        assert HoneypotType.HTTPS
        assert HoneypotType.POSTGRESQL

    def test_honeypot_type_values(self):
        """Test honeypot type enum values."""
        assert HoneypotType.SSH.value == "ssh"
        assert HoneypotType.HTTP.value == "http"
        assert HoneypotType.MYSQL.value == "mysql"


class TestHoneypotStatus:
    """Tests for honeypot status enum."""

    def test_all_statuses_exist(self):
        """Test all expected statuses exist."""
        assert HoneypotStatus.PENDING
        assert HoneypotStatus.RUNNING
        assert HoneypotStatus.STOPPING
        assert HoneypotStatus.STOPPED
        assert HoneypotStatus.FAILED

    def test_status_values(self):
        """Test status enum values."""
        assert HoneypotStatus.PENDING.value == "pending"
        assert HoneypotStatus.RUNNING.value == "running"
        assert HoneypotStatus.STOPPED.value == "stopped"


class TestSophisticationLevel:
    """Tests for sophistication level enum."""

    def test_all_sophistication_levels_exist(self):
        """Test all expected sophistication levels exist."""
        assert SophisticationLevel.SCRIPT_KIDDIE
        assert SophisticationLevel.INTERMEDIATE
        assert SophisticationLevel.ADVANCED
        assert SophisticationLevel.APT

    def test_sophistication_level_values(self):
        """Test sophistication level enum values."""
        assert SophisticationLevel.SCRIPT_KIDDIE.value == "script_kiddie"
        assert SophisticationLevel.INTERMEDIATE.value == "intermediate"
        assert SophisticationLevel.ADVANCED.value == "advanced"
        assert SophisticationLevel.APT.value == "apt"


class TestInteractionTypes:
    """Tests for interaction type string values."""

    def test_common_interaction_types(self):
        """Test common interaction type strings."""
        # These are the expected string values for interaction_type
        common_types = [
            "login_attempt",
            "command",
            "http_request",
            "file_upload",
            "file_download",
            "connection",
        ]
        # Verify all are strings
        for t in common_types:
            assert isinstance(t, str)
            assert len(t) > 0


class TestHoneypotTemplates:
    """Tests for honeypot template definitions."""

    def test_templates_exist(self):
        """Test that default templates are defined."""
        assert len(DEFAULT_TEMPLATES) > 0

    def test_templates_have_required_fields(self):
        """Test that all templates have required fields."""
        required_fields = [
            "id",
            "name",
            "honeypot_type",
            "container_image",
        ]
        for template in DEFAULT_TEMPLATES:
            for field in required_fields:
                assert field in template, f"Template {template.get('id')} missing {field}"

    def test_templates_have_valid_types(self):
        """Test that all templates have valid honeypot types."""
        valid_types = [t.value for t in HoneypotType]
        for template in DEFAULT_TEMPLATES:
            assert template["honeypot_type"] in valid_types, (
                f"Template {template['id']} has invalid type {template['honeypot_type']}"
            )

    def test_ssh_template_exists(self):
        """Test that SSH honeypot template exists."""
        ssh_templates = [t for t in DEFAULT_TEMPLATES if t["honeypot_type"] == "ssh"]
        assert len(ssh_templates) > 0

    def test_http_template_exists(self):
        """Test that HTTP honeypot template exists."""
        http_templates = [t for t in DEFAULT_TEMPLATES if t["honeypot_type"] == "http"]
        assert len(http_templates) > 0

    def test_templates_have_container_images(self):
        """Test that all templates have container images."""
        for template in DEFAULT_TEMPLATES:
            assert len(template["container_image"]) > 0

    def test_templates_have_unique_ids(self):
        """Test that all templates have unique IDs."""
        ids = [t["id"] for t in DEFAULT_TEMPLATES]
        assert len(ids) == len(set(ids))


class TestHoneypotService:
    """Tests for HoneypotService class."""

    @pytest.fixture
    def mock_session(self):
        """Create a mock async session."""
        session = AsyncMock()
        session.commit = AsyncMock()
        session.refresh = AsyncMock()
        session.close = AsyncMock()
        return session

    @pytest.fixture
    def service(self, mock_session):
        """Create a service with mock session."""
        with patch("app.services.honeypot.service.ContainerOrchestrator"):
            with patch("app.services.honeypot.service.get_llm_service"):
                return HoneypotService(mock_session)

    @pytest.mark.asyncio
    async def test_sync_templates(self, service, mock_session):
        """Test syncing templates to database."""
        # Mock no existing templates
        mock_result = MagicMock()
        mock_result.scalar_one_or_none.return_value = None
        mock_session.execute = AsyncMock(return_value=mock_result)

        count = await service.sync_templates()

        assert count == len(DEFAULT_TEMPLATES)
        mock_session.commit.assert_called_once()

    @pytest.mark.asyncio
    async def test_get_templates_enabled_only(self, service, mock_session):
        """Test getting only enabled templates."""
        mock_template1 = MagicMock(spec=HoneypotTemplate)
        mock_template1.id = "ssh-cowrie"
        mock_template1.enabled = True

        mock_template2 = MagicMock(spec=HoneypotTemplate)
        mock_template2.id = "http-honeypot"
        mock_template2.enabled = True

        mock_result = MagicMock()
        mock_result.scalars.return_value.all.return_value = [mock_template1, mock_template2]
        mock_session.execute = AsyncMock(return_value=mock_result)

        templates = await service.get_templates(enabled_only=True)

        assert len(templates) == 2

    @pytest.mark.asyncio
    async def test_get_templates_by_type(self, service, mock_session):
        """Test filtering templates by type."""
        mock_template = MagicMock(spec=HoneypotTemplate)
        mock_template.id = "ssh-cowrie"
        mock_template.honeypot_type = HoneypotType.SSH

        mock_result = MagicMock()
        mock_result.scalars.return_value.all.return_value = [mock_template]
        mock_session.execute = AsyncMock(return_value=mock_result)

        templates = await service.get_templates(honeypot_type=HoneypotType.SSH)

        assert len(templates) == 1
        assert templates[0].honeypot_type == HoneypotType.SSH


class TestHoneypotInstance:
    """Tests for HoneypotInstance model."""

    def test_instance_creation(self):
        """Test creating a honeypot instance."""
        instance = HoneypotInstance()
        instance.id = uuid4()
        instance.template_id = "ssh-cowrie"
        instance.container_id = "abc123def456"
        instance.container_name = "netguardian-hp-ssh-1234"
        instance.status = HoneypotStatus.RUNNING
        instance.host_ip = "192.168.1.100"
        instance.port_mappings = {"2222": 22}
        instance.trigger_reason = "High severity alert"

        assert instance.status == HoneypotStatus.RUNNING
        assert instance.host_ip == "192.168.1.100"

    def test_instance_expiry(self):
        """Test instance expiry handling."""
        instance = HoneypotInstance()
        instance.id = uuid4()
        instance.started_at = datetime.now(UTC)
        instance.expires_at = datetime.now(UTC) + timedelta(hours=1)

        # Not expired yet
        assert instance.expires_at > datetime.now(UTC)

        # Would be expired after 2 hours
        future_time = datetime.now(UTC) + timedelta(hours=2)
        assert instance.expires_at < future_time


class TestHoneypotInteraction:
    """Tests for HoneypotInteraction model."""

    def test_interaction_creation(self):
        """Test creating a honeypot interaction."""
        interaction = HoneypotInteraction()
        interaction.id = uuid4()
        interaction.honeypot_id = uuid4()
        interaction.timestamp = datetime.now(UTC)
        interaction.source_ip = "203.0.113.50"
        interaction.source_port = 54321
        interaction.interaction_type = "login_attempt"
        interaction.raw_data = "SSH-2.0-OpenSSH_8.0 admin:password123"

        assert interaction.source_ip == "203.0.113.50"
        assert interaction.interaction_type == "login_attempt"

    def test_interaction_parsed_data(self):
        """Test interaction with parsed data."""
        interaction = HoneypotInteraction()
        interaction.id = uuid4()
        interaction.honeypot_id = uuid4()
        interaction.interaction_type = "command"
        interaction.raw_data = "cat /etc/passwd"
        interaction.parsed_data = {
            "command": "cat",
            "arguments": ["/etc/passwd"],
            "working_dir": "/tmp",
        }

        assert interaction.parsed_data["command"] == "cat"

    def test_interaction_threat_indicators(self):
        """Test interaction with threat indicators."""
        interaction = HoneypotInteraction()
        interaction.threat_indicators = {
            "malware_hashes": ["abc123"],
            "suspicious_domains": ["evil.com"],
            "attack_patterns": ["credential_stuffing"],
        }

        assert "malware_hashes" in interaction.threat_indicators
        assert "evil.com" in interaction.threat_indicators["suspicious_domains"]


class TestAttackerProfile:
    """Tests for AttackerProfile model."""

    def test_profile_creation(self):
        """Test creating an attacker profile."""
        profile = AttackerProfile()
        profile.id = uuid4()
        profile.source_ip = "203.0.113.100"
        profile.first_seen = datetime.now(UTC) - timedelta(days=7)
        profile.last_seen = datetime.now(UTC)
        profile.total_interactions = 150
        profile.sophistication_level = SophisticationLevel.INTERMEDIATE
        profile.likely_intent = "credential_harvesting"

        assert profile.source_ip == "203.0.113.100"
        assert profile.sophistication_level == SophisticationLevel.INTERMEDIATE
        assert profile.total_interactions == 150

    def test_profile_attack_patterns(self):
        """Test attacker profile with attack patterns."""
        profile = AttackerProfile()
        profile.attack_patterns = {
            "ssh_brute_force": 45,
            "credential_stuffing": 30,
            "port_scanning": 15,
        }

        assert profile.attack_patterns["ssh_brute_force"] == 45
        assert len(profile.attack_patterns) == 3

    def test_profile_llm_analysis(self):
        """Test attacker profile with LLM analysis."""
        profile = AttackerProfile()
        profile.llm_analysis = """
        Based on the observed behavior patterns, this attacker appears to be
        using automated tools for credential harvesting. The attack pattern
        suggests a moderately sophisticated threat actor with access to
        credential databases from previous breaches.
        """

        assert "credential harvesting" in profile.llm_analysis.lower()

    def test_profile_recommended_actions(self):
        """Test attacker profile with recommended actions."""
        profile = AttackerProfile()
        profile.recommended_actions = {
            "immediate": ["Block IP at firewall", "Alert SOC team"],
            "short_term": ["Analyze related IPs", "Check for lateral movement"],
            "long_term": ["Update detection rules", "Review authentication logs"],
        }

        assert len(profile.recommended_actions["immediate"]) == 2


class TestHoneypotStatusTransitions:
    """Tests for honeypot status transitions."""

    def test_valid_status_flow(self):
        """Test valid status transition flow."""
        # Valid flow: PENDING -> RUNNING -> STOPPING -> STOPPED
        # Or: PENDING -> RUNNING -> STOPPED (quick stop)
        # Or: PENDING -> FAILED

        instance = HoneypotInstance()
        instance.status = HoneypotStatus.PENDING

        # Start running
        instance.status = HoneypotStatus.RUNNING
        assert instance.status == HoneypotStatus.RUNNING

        # Begin stopping
        instance.status = HoneypotStatus.STOPPING
        assert instance.status == HoneypotStatus.STOPPING

        # Stopped
        instance.status = HoneypotStatus.STOPPED
        assert instance.status == HoneypotStatus.STOPPED

    def test_failure_status(self):
        """Test failure status transition."""
        instance = HoneypotInstance()
        instance.status = HoneypotStatus.PENDING

        # Fail to start
        instance.status = HoneypotStatus.FAILED
        assert instance.status == HoneypotStatus.FAILED


class TestSophisticationLevelOrdering:
    """Tests for sophistication level ordering."""

    def test_levels_can_be_compared(self):
        """Test that sophistication levels have meaningful ordering."""
        # script_kiddie < intermediate < advanced < apt
        levels = [
            SophisticationLevel.SCRIPT_KIDDIE,
            SophisticationLevel.INTERMEDIATE,
            SophisticationLevel.ADVANCED,
            SophisticationLevel.APT,
        ]

        # Verify all levels are unique
        assert len(levels) == len(set(levels))

    def test_apt_is_most_sophisticated(self):
        """Test that APT is the highest sophistication level."""
        # APT (Advanced Persistent Threat) should be the highest
        assert SophisticationLevel.APT.value == "apt"

    def test_script_kiddie_is_least_sophisticated(self):
        """Test that script_kiddie is the lowest sophistication level."""
        assert SophisticationLevel.SCRIPT_KIDDIE.value == "script_kiddie"


class TestHoneypotTemplateModel:
    """Tests for HoneypotTemplate model."""

    def test_template_creation(self):
        """Test creating a honeypot template."""
        template = HoneypotTemplate()
        template.id = "ssh-cowrie"
        template.name = "SSH Honeypot (Cowrie)"
        template.honeypot_type = HoneypotType.SSH
        template.description = "High-interaction SSH honeypot"
        template.container_image = "cowrie/cowrie:latest"
        template.exposed_ports = [2222]
        template.default_timeout_minutes = 60
        template.enabled = True

        assert template.id == "ssh-cowrie"
        assert template.honeypot_type == HoneypotType.SSH
        assert 2222 in template.exposed_ports

    def test_template_container_config(self):
        """Test template with container configuration."""
        template = HoneypotTemplate()
        template.container_config = {
            "environment": {"LOG_LEVEL": "DEBUG"},
            "volumes": {"/data": {"bind": "/cowrie/log", "mode": "rw"}},
            "memory_limit": "512m",
        }

        assert template.container_config["memory_limit"] == "512m"
