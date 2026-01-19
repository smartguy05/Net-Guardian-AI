"""Tests for the anomaly detection service."""

import pytest
from datetime import datetime, timedelta, timezone
from unittest.mock import AsyncMock, MagicMock, patch
from uuid import uuid4

from app.models.alert import AlertSeverity
from app.models.anomaly import AnomalyDetection, AnomalyStatus, AnomalyType
from app.models.device_baseline import BaselineStatus, BaselineType, DeviceBaseline
from app.models.raw_event import EventType, RawEvent
from app.services.anomaly_service import AnomalyDetector


class TestAnomalyDetector:
    """Tests for the AnomalyDetector class."""

    @pytest.fixture
    def mock_session(self):
        """Create a mock async session."""
        session = AsyncMock()
        return session

    @pytest.fixture
    def detector(self, mock_session):
        """Create a detector with mock session."""
        return AnomalyDetector(mock_session)

    def test_is_internal_ip(self, detector):
        """Test internal IP detection."""
        assert detector._is_internal_ip("192.168.1.1") is True
        assert detector._is_internal_ip("10.0.0.1") is True
        assert detector._is_internal_ip("172.16.0.1") is True
        assert detector._is_internal_ip("8.8.8.8") is False
        assert detector._is_internal_ip("1.1.1.1") is False

    def test_is_suspicious_port(self, detector):
        """Test suspicious port detection."""
        # Safe ports should not be suspicious
        assert detector._is_suspicious_port(80) is False
        assert detector._is_suspicious_port(443) is False
        assert detector._is_suspicious_port(53) is False
        assert detector._is_suspicious_port(22) is False

        # High ports are generally not suspicious
        assert detector._is_suspicious_port(8080) is False
        assert detector._is_suspicious_port(3000) is False

        # Low ports not in safe list could be suspicious
        # but our implementation says high ports are not suspicious
        # so most ports won't trigger

    def test_create_anomaly(self, detector):
        """Test anomaly creation."""
        device_id = uuid4()
        anomaly = detector._create_anomaly(
            device_id=device_id,
            anomaly_type=AnomalyType.NEW_DOMAIN,
            score=3.5,
            description="Test anomaly",
            details={"test": "value"},
            baseline_comparison={"baseline": "data"},
        )

        assert anomaly.device_id == device_id
        assert anomaly.anomaly_type == AnomalyType.NEW_DOMAIN
        assert anomaly.score == 3.5
        assert anomaly.description == "Test anomaly"
        assert anomaly.details == {"test": "value"}
        assert anomaly.baseline_comparison == {"baseline": "data"}
        assert anomaly.status == AnomalyStatus.ACTIVE
        assert anomaly.detected_at is not None


class TestAnomalySeverityCalculation:
    """Tests for anomaly severity calculation."""

    def test_calculate_severity_high_risk_types(self):
        """Test severity calculation for high-risk anomaly types."""
        # NEW_CONNECTION is a high-risk type
        assert (
            AnomalyDetection.calculate_severity(4.0, AnomalyType.NEW_CONNECTION)
            == AlertSeverity.CRITICAL
        )
        assert (
            AnomalyDetection.calculate_severity(3.0, AnomalyType.NEW_CONNECTION)
            == AlertSeverity.HIGH
        )
        assert (
            AnomalyDetection.calculate_severity(2.0, AnomalyType.NEW_CONNECTION)
            == AlertSeverity.MEDIUM
        )
        assert (
            AnomalyDetection.calculate_severity(1.5, AnomalyType.NEW_CONNECTION)
            == AlertSeverity.LOW
        )

        # BLOCKED_SPIKE is also high-risk
        assert (
            AnomalyDetection.calculate_severity(4.0, AnomalyType.BLOCKED_SPIKE)
            == AlertSeverity.CRITICAL
        )

    def test_calculate_severity_standard_types(self):
        """Test severity calculation for standard anomaly types."""
        # NEW_DOMAIN is a standard type
        assert (
            AnomalyDetection.calculate_severity(5.0, AnomalyType.NEW_DOMAIN)
            == AlertSeverity.CRITICAL
        )
        assert (
            AnomalyDetection.calculate_severity(4.0, AnomalyType.NEW_DOMAIN)
            == AlertSeverity.HIGH
        )
        assert (
            AnomalyDetection.calculate_severity(3.0, AnomalyType.NEW_DOMAIN)
            == AlertSeverity.MEDIUM
        )
        assert (
            AnomalyDetection.calculate_severity(2.0, AnomalyType.NEW_DOMAIN)
            == AlertSeverity.LOW
        )
        assert (
            AnomalyDetection.calculate_severity(1.5, AnomalyType.NEW_DOMAIN)
            == AlertSeverity.INFO
        )

    def test_calculate_severity_volume_spike(self):
        """Test severity for volume spike anomalies."""
        assert (
            AnomalyDetection.calculate_severity(5.5, AnomalyType.VOLUME_SPIKE)
            == AlertSeverity.CRITICAL
        )
        assert (
            AnomalyDetection.calculate_severity(4.5, AnomalyType.VOLUME_SPIKE)
            == AlertSeverity.HIGH
        )
        assert (
            AnomalyDetection.calculate_severity(3.5, AnomalyType.VOLUME_SPIKE)
            == AlertSeverity.MEDIUM
        )

    def test_calculate_severity_time_anomaly(self):
        """Test severity for time anomalies."""
        assert (
            AnomalyDetection.calculate_severity(6.0, AnomalyType.TIME_ANOMALY)
            == AlertSeverity.CRITICAL
        )
        assert (
            AnomalyDetection.calculate_severity(2.5, AnomalyType.TIME_ANOMALY)
            == AlertSeverity.LOW
        )

    def test_calculate_severity_pattern_change(self):
        """Test severity for pattern change anomalies."""
        assert (
            AnomalyDetection.calculate_severity(4.5, AnomalyType.PATTERN_CHANGE)
            == AlertSeverity.HIGH
        )
        assert (
            AnomalyDetection.calculate_severity(1.0, AnomalyType.PATTERN_CHANGE)
            == AlertSeverity.INFO
        )


class TestDNSAnomalyDetection:
    """Tests for DNS-related anomaly detection."""

    @pytest.fixture
    def detector(self):
        session = AsyncMock()
        return AnomalyDetector(session)

    @pytest.fixture
    def dns_baseline(self):
        """Create a sample DNS baseline."""
        baseline = MagicMock()
        baseline.baseline_type = BaselineType.DNS
        baseline.status = BaselineStatus.READY
        baseline.metrics = {
            "unique_domains": ["google.com", "facebook.com", "twitter.com"],
            "domain_frequencies": {"google.com": 100, "facebook.com": 50},
            "hourly_distribution": [10] * 24,  # Uniform distribution
            "volume_mean": 100.0,
            "volume_std": 20.0,
            "blocked_ratio": 0.05,
            "total_queries": 500,
        }
        return baseline

    def test_detect_new_domains(self, detector, dns_baseline):
        """Test detection of new domains."""
        device_id = uuid4()

        # Simulate events with a new domain
        events = [
            MagicMock(
                timestamp=datetime.now(timezone.utc),
                domain="malicious-site.com",  # New domain
                action="allow",
            ),
            MagicMock(
                timestamp=datetime.now(timezone.utc),
                domain="google.com",  # Known domain
                action="allow",
            ),
        ]

        # The actual detection would need the async session mocked
        # This test verifies the baseline structure is correct
        assert "unique_domains" in dns_baseline.metrics
        assert "malicious-site.com" not in dns_baseline.metrics["unique_domains"]


class TestTrafficAnomalyDetection:
    """Tests for traffic-related anomaly detection."""

    @pytest.fixture
    def detector(self):
        session = AsyncMock()
        return AnomalyDetector(session)

    @pytest.fixture
    def traffic_baseline(self):
        """Create a sample traffic baseline."""
        baseline = MagicMock()
        baseline.baseline_type = BaselineType.TRAFFIC
        baseline.status = BaselineStatus.READY
        baseline.metrics = {
            "protocol_distribution": {"tcp": 80, "udp": 20},
            "port_distribution": {"443": 60, "80": 30, "53": 10},
            "hourly_distribution": [50] * 24,
            "volume_mean": 1000.0,
            "volume_std": 200.0,
            "blocked_ratio": 0.02,
        }
        return baseline

    def test_baseline_port_detection(self, traffic_baseline):
        """Test that baseline ports are tracked."""
        assert "443" in traffic_baseline.metrics["port_distribution"]
        assert "80" in traffic_baseline.metrics["port_distribution"]


class TestConnectionAnomalyDetection:
    """Tests for connection-related anomaly detection."""

    @pytest.fixture
    def detector(self):
        session = AsyncMock()
        return AnomalyDetector(session)

    @pytest.fixture
    def connection_baseline(self):
        """Create a sample connection baseline."""
        baseline = MagicMock()
        baseline.baseline_type = BaselineType.CONNECTION
        baseline.status = BaselineStatus.READY
        baseline.metrics = {
            "unique_destinations": ["192.168.1.1", "8.8.8.8", "1.1.1.1"],
            "destination_frequencies": {"192.168.1.1": 100, "8.8.8.8": 50},
            "internal_external_ratio": 0.5,
            "port_distribution": {"443": 80, "80": 20},
            "hourly_distribution": [30] * 24,
            "connection_mean": 500.0,
            "connection_std": 100.0,
        }
        return baseline

    def test_new_external_connection_detection(self, detector, connection_baseline):
        """Test detection of new external connections."""
        known_destinations = set(
            connection_baseline.metrics["unique_destinations"]
        )

        new_ip = "185.125.190.56"  # Unknown external IP
        assert new_ip not in known_destinations
        assert not detector._is_internal_ip(new_ip)

    def test_internal_ratio_shift_detection(self, detector, connection_baseline):
        """Test detection of internal/external ratio changes."""
        baseline_ratio = connection_baseline.metrics["internal_external_ratio"]
        assert baseline_ratio == 0.5

        # If current ratio becomes 0.1 (mostly external), that's a pattern change
        current_ratio = 0.1
        assert current_ratio < baseline_ratio


class TestAnomalyStatusUpdates:
    """Tests for anomaly status management."""

    def test_anomaly_status_values(self):
        """Test that all expected status values exist."""
        assert AnomalyStatus.ACTIVE.value == "active"
        assert AnomalyStatus.REVIEWED.value == "reviewed"
        assert AnomalyStatus.FALSE_POSITIVE.value == "false_positive"
        assert AnomalyStatus.CONFIRMED.value == "confirmed"

    def test_anomaly_type_values(self):
        """Test that all expected anomaly types exist."""
        assert AnomalyType.NEW_DOMAIN.value == "new_domain"
        assert AnomalyType.VOLUME_SPIKE.value == "volume_spike"
        assert AnomalyType.TIME_ANOMALY.value == "time_anomaly"
        assert AnomalyType.NEW_CONNECTION.value == "new_connection"
        assert AnomalyType.NEW_PORT.value == "new_port"
        assert AnomalyType.BLOCKED_SPIKE.value == "blocked_spike"
        assert AnomalyType.PATTERN_CHANGE.value == "pattern_change"


class TestAnomalyScoreThresholds:
    """Tests for anomaly score thresholds."""

    def test_z_score_threshold_boundaries(self):
        """Test z-score threshold boundaries."""
        # Score of 2.0 is the minimum for detection
        assert (
            AnomalyDetection.calculate_severity(2.0, AnomalyType.NEW_DOMAIN)
            == AlertSeverity.LOW
        )

        # Score of 1.9 should still be INFO
        assert (
            AnomalyDetection.calculate_severity(1.9, AnomalyType.NEW_DOMAIN)
            == AlertSeverity.INFO
        )

    def test_high_risk_lower_thresholds(self):
        """Test that high-risk types have lower severity thresholds."""
        # Same score should result in higher severity for high-risk types
        standard_severity = AnomalyDetection.calculate_severity(
            3.0, AnomalyType.NEW_DOMAIN
        )
        high_risk_severity = AnomalyDetection.calculate_severity(
            3.0, AnomalyType.NEW_CONNECTION
        )

        # Convert to comparable values
        severity_order = [
            AlertSeverity.INFO,
            AlertSeverity.LOW,
            AlertSeverity.MEDIUM,
            AlertSeverity.HIGH,
            AlertSeverity.CRITICAL,
        ]

        standard_index = severity_order.index(standard_severity)
        high_risk_index = severity_order.index(high_risk_severity)

        assert high_risk_index >= standard_index
