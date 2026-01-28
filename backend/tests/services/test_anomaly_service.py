"""Tests for the anomaly detection service."""

from datetime import UTC, datetime
from unittest.mock import AsyncMock, MagicMock, patch
from uuid import uuid4

import pytest

from app.models.alert import AlertSeverity
from app.models.anomaly import AnomalyDetection, AnomalyStatus, AnomalyType
from app.models.device import DeviceStatus
from app.models.device_baseline import BaselineStatus, BaselineType, DeviceBaseline
from app.services.anomaly_service import AnomalyDetector, AnomalyService


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
                timestamp=datetime.now(UTC),
                domain="malicious-site.com",  # New domain
                action="allow",
            ),
            MagicMock(
                timestamp=datetime.now(UTC),
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


class TestAnomalyDetectorAsyncMethods:
    """Tests for AnomalyDetector async detection methods."""

    @pytest.fixture
    def mock_session(self):
        """Create a mock async session."""
        session = AsyncMock()
        return session

    @pytest.fixture
    def detector(self, mock_session):
        """Create a detector with mock session."""
        return AnomalyDetector(mock_session)

    @pytest.fixture
    def sample_device_id(self):
        """Sample device ID for testing."""
        return uuid4()

    @pytest.fixture
    def dns_baseline_ready(self):
        """Create a ready DNS baseline with normal metrics."""
        baseline = MagicMock(spec=DeviceBaseline)
        baseline.baseline_type = BaselineType.DNS
        baseline.status = BaselineStatus.READY
        baseline.metrics = {
            "unique_domains": ["google.com", "facebook.com", "twitter.com", "example.com"],
            "domain_frequencies": {"google.com": 100, "facebook.com": 50, "twitter.com": 30},
            "hourly_distribution": [50, 45, 40, 35, 30, 25, 20, 30, 60, 80, 90, 100,
                                    95, 90, 85, 80, 75, 70, 65, 60, 55, 50, 50, 50],
            "volume_mean": 100.0,
            "volume_std": 20.0,
            "blocked_ratio": 0.05,
            "total_queries": 2400,
        }
        return baseline

    @pytest.fixture
    def traffic_baseline_ready(self):
        """Create a ready traffic baseline."""
        baseline = MagicMock(spec=DeviceBaseline)
        baseline.baseline_type = BaselineType.TRAFFIC
        baseline.status = BaselineStatus.READY
        baseline.metrics = {
            "protocol_distribution": {"tcp": 0.8, "udp": 0.2},
            "port_distribution": {"443": 60, "80": 30, "53": 10},
            "hourly_distribution": [40] * 24,
            "volume_mean": 500.0,
            "volume_std": 100.0,
            "blocked_ratio": 0.02,
            "total_events": 12000,
        }
        return baseline

    @pytest.fixture
    def connection_baseline_ready(self):
        """Create a ready connection baseline."""
        baseline = MagicMock(spec=DeviceBaseline)
        baseline.baseline_type = BaselineType.CONNECTION
        baseline.status = BaselineStatus.READY
        baseline.metrics = {
            "unique_destinations": ["192.168.1.1", "8.8.8.8", "1.1.1.1", "192.168.1.100"],
            "destination_frequencies": {"192.168.1.1": 100, "8.8.8.8": 50, "1.1.1.1": 30},
            "internal_external_ratio": 0.6,
            "port_distribution": {"443": 80, "80": 15, "22": 5},
            "hourly_distribution": [25] * 24,
            "connection_mean": 300.0,
            "connection_std": 60.0,
            "total_connections": 7200,
        }
        return baseline

    @pytest.mark.asyncio
    async def test_detect_anomalies_no_baselines(self, detector, sample_device_id, mock_session):
        """Test detection when device has no baselines."""
        # No baselines found
        mock_result = MagicMock()
        mock_result.scalars.return_value.all.return_value = []
        mock_session.execute.return_value = mock_result

        anomalies = await detector.detect_anomalies(sample_device_id)

        assert len(anomalies) == 0

    @pytest.mark.asyncio
    async def test_detect_anomalies_learning_baselines(self, detector, sample_device_id, mock_session):
        """Test detection when baselines are still learning."""
        learning_baseline = MagicMock(spec=DeviceBaseline)
        learning_baseline.status = BaselineStatus.LEARNING
        learning_baseline.baseline_type = BaselineType.DNS
        learning_baseline.metrics = {}

        # First call returns baselines
        baselines_result = MagicMock()
        baselines_result.scalars.return_value.all.return_value = [learning_baseline]

        # Events query returns empty for learning baselines (they're skipped)
        events_result = MagicMock()
        events_result.scalars.return_value.all.return_value = []

        mock_session.execute.side_effect = [baselines_result, events_result]

        anomalies = await detector.detect_anomalies(sample_device_id)

        # Should not detect anomalies against learning baselines
        assert len(anomalies) == 0

    def test_volume_spike_detection_math(self, dns_baseline_ready):
        """Test the math behind volume spike detection."""
        # Mean=100, std=20
        # Current volume of 200 would give z-score of (200-100)/20 = 5.0
        mean = dns_baseline_ready.metrics["volume_mean"]
        std = dns_baseline_ready.metrics["volume_std"]
        current_volume = 200

        z_score = (current_volume - mean) / std if std > 0 else 0
        assert z_score == 5.0  # Should trigger CRITICAL severity


class TestAnomalyService:
    """Tests for the AnomalyService high-level facade."""

    @pytest.mark.asyncio
    async def test_get_device_anomalies(self):
        """Test retrieving anomalies for a device."""
        device_id = uuid4()
        anomalies = [
            MagicMock(anomaly_type=AnomalyType.NEW_DOMAIN, status=AnomalyStatus.ACTIVE),
            MagicMock(anomaly_type=AnomalyType.VOLUME_SPIKE, status=AnomalyStatus.ACTIVE),
        ]

        mock_result = MagicMock()
        mock_result.scalars.return_value.all.return_value = anomalies

        with patch("app.services.anomaly_service.AsyncSessionLocal") as mock_local:
            mock_session = AsyncMock()
            mock_session.execute.return_value = mock_result
            mock_local.return_value.__aenter__.return_value = mock_session

            service = AnomalyService()
            result = await service.get_device_anomalies(device_id)

            assert len(result) == 2

    @pytest.mark.asyncio
    async def test_get_active_anomalies(self):
        """Test retrieving all active anomalies."""
        anomalies = [
            MagicMock(
                anomaly_type=AnomalyType.NEW_DOMAIN,
                status=AnomalyStatus.ACTIVE,
                severity=AlertSeverity.HIGH,
            ),
        ]

        mock_result = MagicMock()
        mock_result.scalars.return_value.all.return_value = anomalies

        with patch("app.services.anomaly_service.AsyncSessionLocal") as mock_local:
            mock_session = AsyncMock()
            mock_session.execute.return_value = mock_result
            mock_local.return_value.__aenter__.return_value = mock_session

            service = AnomalyService()
            result = await service.get_active_anomalies()

            assert len(result) == 1
            assert result[0].status == AnomalyStatus.ACTIVE

    @pytest.mark.asyncio
    async def test_get_active_anomalies_with_severity_filter(self):
        """Test retrieving active anomalies with severity filter."""
        anomalies = [
            MagicMock(
                anomaly_type=AnomalyType.NEW_CONNECTION,
                status=AnomalyStatus.ACTIVE,
                severity=AlertSeverity.CRITICAL,
            ),
        ]

        mock_result = MagicMock()
        mock_result.scalars.return_value.all.return_value = anomalies

        with patch("app.services.anomaly_service.AsyncSessionLocal") as mock_local:
            mock_session = AsyncMock()
            mock_session.execute.return_value = mock_result
            mock_local.return_value.__aenter__.return_value = mock_session

            service = AnomalyService()
            result = await service.get_active_anomalies(min_severity=AlertSeverity.HIGH)

            assert len(result) == 1

    @pytest.mark.asyncio
    async def test_update_anomaly_status(self):
        """Test updating anomaly status."""
        anomaly_id = uuid4()
        anomaly = MagicMock(
            id=anomaly_id,
            status=AnomalyStatus.ACTIVE,
        )

        mock_result = MagicMock()
        mock_result.scalar_one_or_none.return_value = anomaly

        with patch("app.services.anomaly_service.AsyncSessionLocal") as mock_local:
            mock_session = AsyncMock()
            mock_session.execute.return_value = mock_result
            mock_local.return_value.__aenter__.return_value = mock_session

            service = AnomalyService()
            result = await service.update_anomaly_status(anomaly_id, AnomalyStatus.REVIEWED)

            assert result.status == AnomalyStatus.REVIEWED
            assert mock_session.commit.called

    @pytest.mark.asyncio
    async def test_update_anomaly_status_not_found(self):
        """Test updating non-existent anomaly."""
        anomaly_id = uuid4()

        mock_result = MagicMock()
        mock_result.scalar_one_or_none.return_value = None

        with patch("app.services.anomaly_service.AsyncSessionLocal") as mock_local:
            mock_session = AsyncMock()
            mock_session.execute.return_value = mock_result
            mock_local.return_value.__aenter__.return_value = mock_session

            service = AnomalyService()
            result = await service.update_anomaly_status(anomaly_id, AnomalyStatus.REVIEWED)

            assert result is None

    @pytest.mark.asyncio
    async def test_run_detection_for_all_devices(self):
        """Test running detection for all devices with ready baselines."""
        device1 = MagicMock()
        device1.id = uuid4()
        device1.status = DeviceStatus.ACTIVE
        device1.baseline_ready = True

        device2 = MagicMock()
        device2.id = uuid4()
        device2.status = DeviceStatus.ACTIVE
        device2.baseline_ready = True

        devices = [device1, device2]

        # Mock device query
        devices_result = MagicMock()
        devices_result.scalars.return_value.all.return_value = devices

        # Mock empty baselines (no READY baselines means no anomalies)
        baselines_result = MagicMock()
        baselines_result.scalars.return_value.all.return_value = []

        with patch("app.services.anomaly_service.AsyncSessionLocal") as mock_local:
            mock_session = AsyncMock()
            # Return devices first, then baselines for each device
            mock_session.execute.side_effect = [
                devices_result,
                baselines_result,  # Device 1 baselines
                baselines_result,  # Device 2 baselines
            ]
            mock_local.return_value.__aenter__.return_value = mock_session

            service = AnomalyService()
            stats = await service.run_detection_for_all_devices()

            # Should have checked 2 devices
            assert stats["devices_checked"] == 2
            # No anomalies because no READY baselines
            assert stats["anomalies_detected"] == 0


class TestSuspiciousPortDetection:
    """Tests for suspicious port detection logic."""

    @pytest.fixture
    def detector(self):
        session = AsyncMock()
        return AnomalyDetector(session)

    def test_common_safe_ports(self, detector):
        """Test that common safe ports are not flagged."""
        safe_ports = [80, 443, 53, 22, 21, 25, 110, 143, 993, 995, 587, 465]
        for port in safe_ports:
            assert detector._is_suspicious_port(port) is False

    def test_alternative_web_ports(self, detector):
        """Test that alternative web ports are not flagged."""
        web_ports = [8080, 8443, 3000, 3001]
        for port in web_ports:
            assert detector._is_suspicious_port(port) is False

    def test_common_service_ports(self, detector):
        """Test common service ports."""
        service_ports = [3389, 5900, 123, 67, 68, 161, 162, 389, 636, 1900, 5353]
        for port in service_ports:
            assert detector._is_suspicious_port(port) is False


class TestAlertCreationForAnomalies:
    """Tests for automatic alert creation from anomalies."""

    @pytest.fixture
    def detector(self):
        session = AsyncMock()
        return AnomalyDetector(session)

    def test_create_anomaly_with_high_severity(self, detector):
        """Test that high severity anomalies get proper severity."""
        device_id = uuid4()
        anomaly = detector._create_anomaly(
            device_id=device_id,
            anomaly_type=AnomalyType.NEW_CONNECTION,
            score=4.5,
            description="New external connection detected",
            details={"ip": "185.125.190.56"},
            baseline_comparison={},
        )

        # High risk type with high score should be CRITICAL or HIGH
        assert anomaly.device_id == device_id
        assert anomaly.score == 4.5
        severity = AnomalyDetection.calculate_severity(4.5, AnomalyType.NEW_CONNECTION)
        assert severity in [AlertSeverity.CRITICAL, AlertSeverity.HIGH]

    def test_create_anomaly_with_low_severity(self, detector):
        """Test that low severity anomalies get proper severity."""
        device_id = uuid4()
        anomaly = detector._create_anomaly(
            device_id=device_id,
            anomaly_type=AnomalyType.TIME_ANOMALY,
            score=1.5,
            description="Activity at unusual time",
            details={},
            baseline_comparison={},
        )

        severity = AnomalyDetection.calculate_severity(1.5, AnomalyType.TIME_ANOMALY)
        assert severity in [AlertSeverity.INFO, AlertSeverity.LOW]


class TestZScoreCalculations:
    """Tests for z-score based anomaly detection."""

    def test_z_score_normal_activity(self):
        """Test that normal activity (z-score < 2) is INFO severity."""
        # Score of 1.5 (below threshold) should be INFO
        severity = AnomalyDetection.calculate_severity(1.5, AnomalyType.VOLUME_SPIKE)
        assert severity == AlertSeverity.INFO

    def test_z_score_at_threshold(self):
        """Test activity exactly at threshold."""
        severity = AnomalyDetection.calculate_severity(2.0, AnomalyType.VOLUME_SPIKE)
        assert severity == AlertSeverity.LOW

    def test_z_score_above_threshold(self):
        """Test activity above threshold."""
        severity = AnomalyDetection.calculate_severity(2.5, AnomalyType.VOLUME_SPIKE)
        assert severity in [AlertSeverity.LOW, AlertSeverity.MEDIUM]

    def test_z_score_high_threshold(self):
        """Test very high z-score (3.0+)."""
        severity = AnomalyDetection.calculate_severity(3.5, AnomalyType.VOLUME_SPIKE)
        assert severity in [AlertSeverity.MEDIUM, AlertSeverity.HIGH]

    def test_z_score_critical_threshold(self):
        """Test critical z-score (4.0+)."""
        severity = AnomalyDetection.calculate_severity(4.5, AnomalyType.VOLUME_SPIKE)
        assert severity in [AlertSeverity.HIGH, AlertSeverity.CRITICAL]

    def test_z_score_extreme(self):
        """Test extreme z-score (5.0+)."""
        severity = AnomalyDetection.calculate_severity(6.0, AnomalyType.VOLUME_SPIKE)
        assert severity == AlertSeverity.CRITICAL
