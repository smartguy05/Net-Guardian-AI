"""Tests for the baseline calculator service."""

from datetime import UTC, datetime, timedelta
from unittest.mock import AsyncMock, MagicMock
from uuid import uuid4

import pytest

from app.models.device_baseline import BaselineStatus
from app.models.raw_event import EventType
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
        base_time = datetime.now(UTC)
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
        base_time = datetime.now(UTC)

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
        base_time = datetime.now(UTC)

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
        baseline.last_calculated = datetime.now(UTC)
        baseline.baseline_window_days = 7

        status = calculator._determine_status(50, 100, baseline)
        assert status == BaselineStatus.LEARNING

    def test_determine_status_ready(self, calculator):
        """Test status determination - ready state."""
        baseline = MagicMock()
        baseline.last_calculated = datetime.now(UTC)
        baseline.baseline_window_days = 7

        status = calculator._determine_status(100, 100, baseline)
        assert status == BaselineStatus.READY

        status = calculator._determine_status(150, 100, baseline)
        assert status == BaselineStatus.READY

    def test_determine_status_stale(self, calculator):
        """Test status determination - stale state."""
        baseline = MagicMock()
        baseline.last_calculated = datetime.now(UTC) - timedelta(days=30)
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
                timestamp=datetime.now(UTC),
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
                timestamp=datetime.now(UTC),
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
                timestamp=datetime.now(UTC),
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
                timestamp=datetime.now(UTC),
                domain=f"domain{i}.com",
                action="allow",
            )
            for i in range(600)
        ]

        metrics = calculator._calculate_dns_metrics(events)
        assert len(metrics["unique_domains"]) <= 500


class TestBaselineStatusTransitions:
    """Tests for baseline status state transitions."""

    @pytest.fixture
    def calculator(self):
        session = AsyncMock()
        return BaselineCalculator(session)

    def test_status_learning_with_few_events(self, calculator):
        """Test LEARNING status with insufficient events."""
        baseline = MagicMock()
        baseline.last_calculated = datetime.now(UTC)
        baseline.baseline_window_days = 7

        # Few events relative to minimum
        status = calculator._determine_status(30, 100, baseline)
        assert status == BaselineStatus.LEARNING

    def test_status_ready_with_enough_events(self, calculator):
        """Test READY status with sufficient events."""
        baseline = MagicMock()
        baseline.last_calculated = datetime.now(UTC)
        baseline.baseline_window_days = 7

        # Enough events
        status = calculator._determine_status(150, 100, baseline)
        assert status == BaselineStatus.READY

    def test_status_stale_when_old(self, calculator):
        """Test STALE status when baseline is too old."""
        baseline = MagicMock()
        baseline.last_calculated = datetime.now(UTC) - timedelta(days=21)  # 3 weeks old
        baseline.baseline_window_days = 7

        status = calculator._determine_status(200, 100, baseline)
        assert status == BaselineStatus.STALE

    def test_status_boundary_at_minimum(self, calculator):
        """Test status exactly at minimum sample count."""
        baseline = MagicMock()
        baseline.last_calculated = datetime.now(UTC)
        baseline.baseline_window_days = 7

        # Exactly at minimum
        status = calculator._determine_status(100, 100, baseline)
        assert status == BaselineStatus.READY

    def test_status_boundary_just_below_minimum(self, calculator):
        """Test status just below minimum sample count."""
        baseline = MagicMock()
        baseline.last_calculated = datetime.now(UTC)
        baseline.baseline_window_days = 7

        # Just below minimum
        status = calculator._determine_status(99, 100, baseline)
        assert status == BaselineStatus.LEARNING


class TestTrafficMetricsEdgeCases:
    """Additional edge case tests for traffic metrics."""

    @pytest.fixture
    def calculator(self):
        session = AsyncMock()
        return BaselineCalculator(session)

    def test_traffic_metrics_mixed_protocols(self, calculator):
        """Test with multiple protocols."""
        events = []
        base_time = datetime.now(UTC)
        protocols = ["tcp", "udp", "icmp", "other"]

        for i in range(100):
            events.append(
                MagicMock(
                    timestamp=base_time - timedelta(hours=i % 24),
                    protocol=protocols[i % len(protocols)],
                    port=80,
                    action="allow",
                )
            )

        metrics = calculator._calculate_traffic_metrics(events)

        assert len(metrics["protocol_distribution"]) == 4
        assert "tcp" in metrics["protocol_distribution"]
        assert "icmp" in metrics["protocol_distribution"]

    def test_traffic_metrics_many_ports(self, calculator):
        """Test with many different ports."""
        events = [
            MagicMock(
                timestamp=datetime.now(UTC),
                protocol="tcp",
                port=i,
                action="allow",
            )
            for i in range(200)
        ]

        metrics = calculator._calculate_traffic_metrics(events)

        # Port distribution should be capped
        assert len(metrics["port_distribution"]) <= 100

    def test_traffic_metrics_high_blocked_ratio(self, calculator):
        """Test with high blocked ratio."""
        events = [
            MagicMock(
                timestamp=datetime.now(UTC),
                protocol="tcp",
                port=22,
                action="block" if i < 90 else "allow",
            )
            for i in range(100)
        ]

        metrics = calculator._calculate_traffic_metrics(events)

        assert metrics["blocked_ratio"] == 0.9


class TestConnectionMetricsEdgeCases:
    """Additional edge case tests for connection metrics."""

    @pytest.fixture
    def calculator(self):
        session = AsyncMock()
        return BaselineCalculator(session)

    def test_connection_metrics_all_internal(self, calculator):
        """Test with all internal connections."""
        internal_ips = ["192.168.1.100", "10.0.0.1", "172.16.0.1"]
        events = [
            MagicMock(
                timestamp=datetime.now(UTC),
                target_ip=internal_ips[i % len(internal_ips)],
                port=443,
            )
            for i in range(100)
        ]

        metrics = calculator._calculate_connection_metrics(events)

        assert metrics["internal_external_ratio"] == 1.0

    def test_connection_metrics_all_external(self, calculator):
        """Test with all external connections."""
        external_ips = ["8.8.8.8", "1.1.1.1", "208.67.222.222"]
        events = [
            MagicMock(
                timestamp=datetime.now(UTC),
                target_ip=external_ips[i % len(external_ips)],
                port=443,
            )
            for i in range(100)
        ]

        metrics = calculator._calculate_connection_metrics(events)

        assert metrics["internal_external_ratio"] == 0.0

    def test_connection_metrics_missing_target_ip(self, calculator):
        """Test with events missing target_ip."""
        events = [
            MagicMock(
                timestamp=datetime.now(UTC),
                target_ip=None,
                port=443,
            )
            for _ in range(50)
        ]

        metrics = calculator._calculate_connection_metrics(events)

        # Should handle gracefully
        assert metrics["total_connections"] == 50
        assert len(metrics["unique_destinations"]) == 0


class TestIPClassification:
    """Tests for IP address classification edge cases."""

    @pytest.fixture
    def calculator(self):
        session = AsyncMock()
        return BaselineCalculator(session)

    def test_ipv4_class_a_private(self, calculator):
        """Test 10.x.x.x class A private addresses."""
        assert calculator._is_internal_ip("10.0.0.0") is True
        assert calculator._is_internal_ip("10.0.0.1") is True
        assert calculator._is_internal_ip("10.255.255.254") is True
        assert calculator._is_internal_ip("10.255.255.255") is True

    def test_ipv4_class_b_private(self, calculator):
        """Test 172.16-31.x.x class B private addresses."""
        assert calculator._is_internal_ip("172.16.0.0") is True
        assert calculator._is_internal_ip("172.16.0.1") is True
        assert calculator._is_internal_ip("172.31.255.255") is True

        # Boundary - just outside range
        assert calculator._is_internal_ip("172.15.255.255") is False
        assert calculator._is_internal_ip("172.32.0.0") is False

    def test_ipv4_class_c_private(self, calculator):
        """Test 192.168.x.x class C private addresses."""
        assert calculator._is_internal_ip("192.168.0.0") is True
        assert calculator._is_internal_ip("192.168.0.1") is True
        assert calculator._is_internal_ip("192.168.255.255") is True

        # Similar but not private
        assert calculator._is_internal_ip("192.167.1.1") is False
        assert calculator._is_internal_ip("192.169.1.1") is False

    def test_ipv4_loopback(self, calculator):
        """Test loopback addresses."""
        assert calculator._is_internal_ip("127.0.0.1") is True
        assert calculator._is_internal_ip("127.0.0.0") is True
        assert calculator._is_internal_ip("127.255.255.255") is True

    def test_invalid_ip_formats(self, calculator):
        """Test various invalid IP formats."""
        assert calculator._is_internal_ip("") is False
        assert calculator._is_internal_ip("invalid") is False
        assert calculator._is_internal_ip("not-an-ip") is False
        assert calculator._is_internal_ip("256.256.256.256") is False
        # Truncated IP - should return False (invalid format)
        assert calculator._is_internal_ip("192.168.1") is False
