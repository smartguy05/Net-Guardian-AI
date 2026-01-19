"""Tests for the baseline calculator service."""

import pytest
from datetime import datetime, timedelta, timezone
from unittest.mock import AsyncMock, MagicMock, patch
from uuid import uuid4

from app.models.device_baseline import BaselineStatus, BaselineType, DeviceBaseline
from app.models.raw_event import EventType, RawEvent
from app.services.baseline_service import BaselineCalculator


class TestBaselineCalculator:
    """Tests for the BaselineCalculator class."""

    @pytest.fixture
    def mock_session(self):
        """Create a mock async session."""
        session = AsyncMock()
        return session

    @pytest.fixture
    def calculator(self, mock_session):
        """Create a calculator with mock session."""
        return BaselineCalculator(mock_session)

    @pytest.fixture
    def sample_dns_events(self):
        """Create sample DNS events for testing."""
        device_id = uuid4()
        base_time = datetime.now(timezone.utc)
        events = []

        domains = ["google.com", "facebook.com", "twitter.com", "example.com"]

        for i in range(150):
            events.append(
                MagicMock(
                    id=uuid4(),
                    device_id=device_id,
                    timestamp=base_time - timedelta(hours=i % 24, minutes=i),
                    event_type=EventType.DNS,
                    domain=domains[i % len(domains)],
                    action="allow" if i % 10 != 0 else "block",
                )
            )

        return events, device_id

    def test_calculate_dns_metrics_empty(self, calculator):
        """Test DNS metrics calculation with empty events."""
        metrics = calculator._calculate_dns_metrics([])

        assert metrics["unique_domains"] == []
        assert metrics["domain_frequencies"] == {}
        assert metrics["hourly_distribution"] == [0] * 24
        assert metrics["daily_volumes"] == []
        assert metrics["volume_mean"] == 0.0
        assert metrics["volume_std"] == 0.0
        assert metrics["blocked_ratio"] == 0.0

    def test_calculate_dns_metrics_with_events(self, calculator, sample_dns_events):
        """Test DNS metrics calculation with sample events."""
        events, _ = sample_dns_events
        metrics = calculator._calculate_dns_metrics(events)

        # Check unique domains
        assert len(metrics["unique_domains"]) == 4
        assert "google.com" in metrics["unique_domains"]

        # Check domain frequencies
        assert len(metrics["domain_frequencies"]) <= 100  # Cap at 100

        # Check hourly distribution
        assert len(metrics["hourly_distribution"]) == 24
        assert sum(metrics["hourly_distribution"]) == len(events)

        # Check blocked ratio
        assert metrics["blocked_ratio"] > 0
        assert metrics["blocked_ratio"] < 1

        # Check total queries
        assert metrics["total_queries"] == len(events)

    def test_calculate_traffic_metrics_empty(self, calculator):
        """Test traffic metrics calculation with empty events."""
        metrics = calculator._calculate_traffic_metrics([])

        assert metrics["protocol_distribution"] == {}
        assert metrics["port_distribution"] == {}
        assert metrics["hourly_distribution"] == [0] * 24
        assert metrics["daily_volumes"] == []
        assert metrics["volume_mean"] == 0.0
        assert metrics["volume_std"] == 0.0
        assert metrics["blocked_ratio"] == 0.0

    def test_calculate_traffic_metrics_with_events(self, calculator):
        """Test traffic metrics calculation with sample events."""
        events = []
        base_time = datetime.now(timezone.utc)

        for i in range(100):
            events.append(
                MagicMock(
                    id=uuid4(),
                    timestamp=base_time - timedelta(hours=i % 24, minutes=i),
                    event_type=EventType.FIREWALL,
                    protocol="tcp" if i % 2 == 0 else "udp",
                    port=443 if i % 3 == 0 else 80,
                    action="allow" if i % 5 != 0 else "block",
                )
            )

        metrics = calculator._calculate_traffic_metrics(events)

        assert "tcp" in metrics["protocol_distribution"]
        assert "udp" in metrics["protocol_distribution"]
        assert len(metrics["port_distribution"]) > 0
        assert metrics["total_events"] == 100

    def test_calculate_connection_metrics_empty(self, calculator):
        """Test connection metrics calculation with empty events."""
        metrics = calculator._calculate_connection_metrics([])

        assert metrics["unique_destinations"] == []
        assert metrics["destination_frequencies"] == {}
        assert metrics["internal_external_ratio"] == 0.0
        assert metrics["port_distribution"] == {}
        assert metrics["hourly_distribution"] == [0] * 24

    def test_calculate_connection_metrics_with_events(self, calculator):
        """Test connection metrics calculation with sample events."""
        events = []
        base_time = datetime.now(timezone.utc)

        destinations = [
            "192.168.1.100",  # internal
            "192.168.1.101",  # internal
            "8.8.8.8",  # external
            "1.1.1.1",  # external
        ]

        for i in range(100):
            events.append(
                MagicMock(
                    id=uuid4(),
                    timestamp=base_time - timedelta(hours=i % 24, minutes=i),
                    target_ip=destinations[i % len(destinations)],
                    port=443 if i % 2 == 0 else 80,
                )
            )

        metrics = calculator._calculate_connection_metrics(events)

        assert len(metrics["unique_destinations"]) == 4
        assert metrics["internal_external_ratio"] == 0.5  # Half internal
        assert metrics["total_connections"] == 100

    def test_is_internal_ip(self, calculator):
        """Test internal IP detection."""
        # Internal IPs
        assert calculator._is_internal_ip("192.168.1.1") is True
        assert calculator._is_internal_ip("192.168.0.100") is True
        assert calculator._is_internal_ip("10.0.0.1") is True
        assert calculator._is_internal_ip("10.255.255.255") is True
        assert calculator._is_internal_ip("172.16.0.1") is True
        assert calculator._is_internal_ip("172.31.255.255") is True
        assert calculator._is_internal_ip("127.0.0.1") is True

        # External IPs
        assert calculator._is_internal_ip("8.8.8.8") is False
        assert calculator._is_internal_ip("1.1.1.1") is False
        assert calculator._is_internal_ip("172.15.0.1") is False
        assert calculator._is_internal_ip("172.32.0.1") is False

        # Invalid
        assert calculator._is_internal_ip("invalid") is False
        assert calculator._is_internal_ip("") is False

    def test_determine_status_learning(self, calculator):
        """Test status determination - learning state."""
        baseline = MagicMock()
        baseline.last_calculated = datetime.now(timezone.utc)
        baseline.baseline_window_days = 7

        status = calculator._determine_status(50, 100, baseline)
        assert status == BaselineStatus.LEARNING

    def test_determine_status_ready(self, calculator):
        """Test status determination - ready state."""
        baseline = MagicMock()
        baseline.last_calculated = datetime.now(timezone.utc)
        baseline.baseline_window_days = 7

        status = calculator._determine_status(100, 100, baseline)
        assert status == BaselineStatus.READY

        status = calculator._determine_status(150, 100, baseline)
        assert status == BaselineStatus.READY

    def test_determine_status_stale(self, calculator):
        """Test status determination - stale state."""
        baseline = MagicMock()
        baseline.last_calculated = datetime.now(timezone.utc) - timedelta(days=30)
        baseline.baseline_window_days = 7

        status = calculator._determine_status(100, 100, baseline)
        assert status == BaselineStatus.STALE


class TestDNSMetricsCalculation:
    """Additional tests for DNS metrics edge cases."""

    @pytest.fixture
    def calculator(self):
        session = AsyncMock()
        return BaselineCalculator(session)

    def test_dns_metrics_single_domain(self, calculator):
        """Test with only one domain."""
        events = [
            MagicMock(
                timestamp=datetime.now(timezone.utc),
                domain="example.com",
                action="allow",
            )
            for _ in range(10)
        ]

        metrics = calculator._calculate_dns_metrics(events)
        assert metrics["unique_domains"] == ["example.com"]
        assert metrics["domain_frequencies"]["example.com"] == 10

    def test_dns_metrics_all_blocked(self, calculator):
        """Test when all queries are blocked."""
        events = [
            MagicMock(
                timestamp=datetime.now(timezone.utc),
                domain="malware.com",
                action="block",
            )
            for _ in range(10)
        ]

        metrics = calculator._calculate_dns_metrics(events)
        assert metrics["blocked_ratio"] == 1.0

    def test_dns_metrics_no_blocked(self, calculator):
        """Test when no queries are blocked."""
        events = [
            MagicMock(
                timestamp=datetime.now(timezone.utc),
                domain="safe.com",
                action="allow",
            )
            for _ in range(10)
        ]

        metrics = calculator._calculate_dns_metrics(events)
        assert metrics["blocked_ratio"] == 0.0

    def test_dns_metrics_caps_domains(self, calculator):
        """Test that unique domains are capped at 500."""
        events = [
            MagicMock(
                timestamp=datetime.now(timezone.utc),
                domain=f"domain{i}.com",
                action="allow",
            )
            for i in range(600)
        ]

        metrics = calculator._calculate_dns_metrics(events)
        assert len(metrics["unique_domains"]) <= 500
