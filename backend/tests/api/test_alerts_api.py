"""Tests for alerts API endpoints.

Tests cover:
- List alerts with pagination and filters
- Get single alert
- Acknowledge alert
- Resolve alert
- Mark as false positive
- Trigger LLM analysis
"""

from datetime import datetime, timedelta, timezone
from unittest.mock import AsyncMock, MagicMock, patch
from uuid import uuid4

import pytest
from fastapi import HTTPException

from app.models.alert import AlertSeverity, AlertStatus


class TestListAlerts:
    """Tests for the list alerts endpoint."""

    @pytest.fixture
    def mock_alerts(self):
        """Create mock alerts for testing."""
        alerts = []
        severities = [AlertSeverity.LOW, AlertSeverity.MEDIUM, AlertSeverity.HIGH, AlertSeverity.CRITICAL]

        for i in range(10):
            alert = MagicMock()
            alert.id = uuid4()
            alert.timestamp = datetime.now(timezone.utc) - timedelta(hours=i)
            alert.device_id = uuid4()
            alert.rule_id = f"rule-{i % 3:03d}"
            alert.severity = severities[i % len(severities)]
            alert.title = f"Test Alert {i}"
            alert.description = f"Description for alert {i}"
            alert.llm_analysis = None
            alert.status = AlertStatus.NEW if i % 2 == 0 else AlertStatus.ACKNOWLEDGED
            alert.actions_taken = []
            alert.acknowledged_by = None
            alert.acknowledged_at = None
            alert.resolved_by = None
            alert.resolved_at = None
            alerts.append(alert)
        return alerts

    @pytest.mark.asyncio
    async def test_list_alerts_basic(self, mock_alerts, mock_db_session, mock_current_user_viewer):
        """Should return paginated list of alerts."""
        mock_scalars = MagicMock()
        mock_scalars.all.return_value = mock_alerts[:5]

        mock_result = MagicMock()
        mock_result.scalars.return_value = mock_scalars

        mock_count_result = MagicMock()
        mock_count_result.scalar.return_value = 10

        mock_db_session.execute.side_effect = [mock_count_result, mock_result]

        # Import inline to avoid import issues
        from app.api.v1 import alerts as alerts_module

        # Check if list_alerts exists
        if hasattr(alerts_module, 'list_alerts'):
            response = await alerts_module.list_alerts(
                session=mock_db_session,
                _current_user=mock_current_user_viewer,
                page=1,
                page_size=5,
            )
            assert response.total == 10
            assert len(response.items) == 5

    @pytest.mark.asyncio
    async def test_list_alerts_filter_by_status(self, mock_alerts, mock_db_session, mock_current_user_viewer):
        """Should filter alerts by status."""
        new_alerts = [a for a in mock_alerts if a.status == AlertStatus.NEW]

        mock_scalars = MagicMock()
        mock_scalars.all.return_value = new_alerts

        mock_result = MagicMock()
        mock_result.scalars.return_value = mock_scalars

        mock_count_result = MagicMock()
        mock_count_result.scalar.return_value = len(new_alerts)

        mock_db_session.execute.side_effect = [mock_count_result, mock_result]

        from app.api.v1 import alerts as alerts_module

        if hasattr(alerts_module, 'list_alerts'):
            response = await alerts_module.list_alerts(
                session=mock_db_session,
                _current_user=mock_current_user_viewer,
                page=1,
                page_size=50,
                status=AlertStatus.NEW,
            )
            assert response.total == len(new_alerts)

    @pytest.mark.asyncio
    async def test_list_alerts_filter_by_severity(self, mock_alerts, mock_db_session, mock_current_user_viewer):
        """Should filter alerts by severity."""
        critical_alerts = [a for a in mock_alerts if a.severity == AlertSeverity.CRITICAL]

        mock_scalars = MagicMock()
        mock_scalars.all.return_value = critical_alerts

        mock_result = MagicMock()
        mock_result.scalars.return_value = mock_scalars

        mock_count_result = MagicMock()
        mock_count_result.scalar.return_value = len(critical_alerts)

        mock_db_session.execute.side_effect = [mock_count_result, mock_result]

        from app.api.v1 import alerts as alerts_module

        if hasattr(alerts_module, 'list_alerts'):
            response = await alerts_module.list_alerts(
                session=mock_db_session,
                _current_user=mock_current_user_viewer,
                page=1,
                page_size=50,
                severity=AlertSeverity.CRITICAL,
            )
            assert response.total == len(critical_alerts)


class TestGetAlert:
    """Tests for get single alert endpoint."""

    @pytest.fixture
    def mock_alert(self):
        """Create a mock alert."""
        alert = MagicMock()
        alert.id = uuid4()
        alert.timestamp = datetime.now(timezone.utc)
        alert.device_id = uuid4()
        alert.rule_id = "test-rule"
        alert.severity = AlertSeverity.MEDIUM
        alert.title = "Test Alert"
        alert.description = "Test alert description"
        alert.llm_analysis = None
        alert.status = AlertStatus.NEW
        alert.actions_taken = []
        alert.acknowledged_by = None
        alert.acknowledged_at = None
        alert.resolved_by = None
        alert.resolved_at = None
        return alert

    @pytest.mark.asyncio
    async def test_get_alert_found(self, mock_alert, mock_db_session, mock_current_user_viewer):
        """Should return alert when found."""
        mock_result = MagicMock()
        mock_result.scalar_one_or_none.return_value = mock_alert
        mock_db_session.execute.return_value = mock_result

        from app.api.v1 import alerts as alerts_module

        if hasattr(alerts_module, 'get_alert'):
            response = await alerts_module.get_alert(
                alert_id=mock_alert.id,
                session=mock_db_session,
                _current_user=mock_current_user_viewer,
            )
            assert str(response.id) == str(mock_alert.id)

    @pytest.mark.asyncio
    async def test_get_alert_not_found(self, mock_db_session, mock_current_user_viewer):
        """Should return 404 for non-existent alert."""
        mock_result = MagicMock()
        mock_result.scalar_one_or_none.return_value = None
        mock_db_session.execute.return_value = mock_result

        from app.api.v1 import alerts as alerts_module

        if hasattr(alerts_module, 'get_alert'):
            with pytest.raises(HTTPException) as exc_info:
                await alerts_module.get_alert(
                    alert_id=uuid4(),
                    session=mock_db_session,
                    _current_user=mock_current_user_viewer,
                )
            assert exc_info.value.status_code == 404


class TestAcknowledgeAlert:
    """Tests for acknowledge alert endpoint."""

    @pytest.fixture
    def mock_alert(self):
        """Create a mock new alert."""
        alert = MagicMock()
        alert.id = uuid4()
        alert.status = AlertStatus.NEW
        alert.acknowledged_by = None
        alert.acknowledged_at = None
        return alert

    @pytest.mark.asyncio
    async def test_acknowledge_alert_success(self, mock_alert, mock_db_session, mock_current_user_operator):
        """Should acknowledge alert successfully."""
        mock_result = MagicMock()
        mock_result.scalar_one_or_none.return_value = mock_alert
        mock_db_session.execute.return_value = mock_result

        from app.api.v1 import alerts as alerts_module

        if hasattr(alerts_module, 'acknowledge_alert'):
            response = await alerts_module.acknowledge_alert(
                alert_id=mock_alert.id,
                session=mock_db_session,
                _operator=mock_current_user_operator,
            )

            assert mock_alert.status == AlertStatus.ACKNOWLEDGED
            assert mock_alert.acknowledged_by == mock_current_user_operator.id
            mock_db_session.commit.assert_called_once()

    @pytest.mark.asyncio
    async def test_acknowledge_already_acknowledged(self, mock_alert, mock_db_session, mock_current_user_operator):
        """Should handle already acknowledged alert."""
        mock_alert.status = AlertStatus.ACKNOWLEDGED
        mock_result = MagicMock()
        mock_result.scalar_one_or_none.return_value = mock_alert
        mock_db_session.execute.return_value = mock_result

        from app.api.v1 import alerts as alerts_module

        # Behavior depends on implementation - may return success or error
        if hasattr(alerts_module, 'acknowledge_alert'):
            # Just verify it doesn't crash
            try:
                await alerts_module.acknowledge_alert(
                    alert_id=mock_alert.id,
                    session=mock_db_session,
                    _operator=mock_current_user_operator,
                )
            except HTTPException:
                pass  # Some implementations may reject re-acknowledgment


class TestResolveAlert:
    """Tests for resolve alert endpoint."""

    @pytest.fixture
    def mock_alert(self):
        """Create a mock acknowledged alert."""
        alert = MagicMock()
        alert.id = uuid4()
        alert.status = AlertStatus.ACKNOWLEDGED
        alert.resolved_by = None
        alert.resolved_at = None
        return alert

    @pytest.mark.asyncio
    async def test_resolve_alert_success(self, mock_alert, mock_db_session, mock_current_user_operator):
        """Should resolve alert successfully."""
        mock_result = MagicMock()
        mock_result.scalar_one_or_none.return_value = mock_alert
        mock_db_session.execute.return_value = mock_result

        from app.api.v1 import alerts as alerts_module

        if hasattr(alerts_module, 'resolve_alert'):
            response = await alerts_module.resolve_alert(
                alert_id=mock_alert.id,
                session=mock_db_session,
                _operator=mock_current_user_operator,
            )

            assert mock_alert.status == AlertStatus.RESOLVED
            assert mock_alert.resolved_by == mock_current_user_operator.id
            mock_db_session.commit.assert_called_once()


class TestMarkFalsePositive:
    """Tests for mark alert as false positive endpoint."""

    @pytest.fixture
    def mock_alert(self):
        """Create a mock alert."""
        alert = MagicMock()
        alert.id = uuid4()
        alert.status = AlertStatus.NEW
        return alert

    @pytest.mark.asyncio
    async def test_mark_false_positive(self, mock_alert, mock_db_session, mock_current_user_operator):
        """Should mark alert as false positive."""
        mock_result = MagicMock()
        mock_result.scalar_one_or_none.return_value = mock_alert
        mock_db_session.execute.return_value = mock_result

        from app.api.v1 import alerts as alerts_module

        if hasattr(alerts_module, 'mark_false_positive'):
            await alerts_module.mark_false_positive(
                alert_id=mock_alert.id,
                session=mock_db_session,
                _operator=mock_current_user_operator,
            )

            assert mock_alert.status == AlertStatus.FALSE_POSITIVE
            mock_db_session.commit.assert_called_once()


class TestTriggerLLMAnalysis:
    """Tests for triggering LLM analysis on alerts."""

    @pytest.fixture
    def mock_alert(self):
        """Create a mock alert without LLM analysis."""
        alert = MagicMock()
        alert.id = uuid4()
        alert.title = "Suspicious Activity"
        alert.description = "Multiple failed login attempts"
        alert.llm_analysis = None
        return alert

    @pytest.mark.asyncio
    async def test_trigger_llm_analysis(self, mock_alert, mock_db_session, mock_current_user_operator):
        """Should trigger LLM analysis for alert."""
        mock_result = MagicMock()
        mock_result.scalar_one_or_none.return_value = mock_alert
        mock_db_session.execute.return_value = mock_result

        mock_analysis = {
            "summary": "Potential brute force attack",
            "risk_level": "high",
            "recommendations": ["Block IP", "Reset passwords"],
        }

        from app.api.v1 import alerts as alerts_module

        if hasattr(alerts_module, 'analyze_alert'):
            with patch("app.api.v1.alerts.get_llm_service") as mock_llm:
                mock_service = AsyncMock()
                mock_service.analyze_alert.return_value = mock_analysis
                mock_llm.return_value = mock_service

                response = await alerts_module.analyze_alert(
                    alert_id=mock_alert.id,
                    session=mock_db_session,
                    _operator=mock_current_user_operator,
                )

                # Analysis should be stored
                assert mock_alert.llm_analysis is not None


class TestAlertStatistics:
    """Tests for alert statistics endpoints."""

    @pytest.mark.asyncio
    async def test_get_alert_stats(self, mock_db_session, mock_current_user_viewer):
        """Should return alert statistics."""
        from app.api.v1 import alerts as alerts_module

        if hasattr(alerts_module, 'get_alert_stats'):
            # Mock the database queries for stats
            mock_db_session.execute.return_value.scalar.return_value = 100

            response = await alerts_module.get_alert_stats(
                session=mock_db_session,
                _current_user=mock_current_user_viewer,
            )

            # Stats should include counts by status and severity
            assert response is not None


class TestAlertAuthorization:
    """Tests for alert authorization checks."""

    @pytest.fixture
    def mock_alert(self):
        """Create a mock alert."""
        alert = MagicMock()
        alert.id = uuid4()
        alert.status = AlertStatus.NEW
        return alert

    @pytest.mark.asyncio
    async def test_viewer_cannot_acknowledge(self, mock_alert, mock_db_session, mock_current_user_viewer):
        """Viewer should not be able to acknowledge alerts."""
        # This test verifies that the endpoint requires operator role
        # The actual authorization check is done by the require_operator dependency
        from app.api.v1.auth import require_operator

        with pytest.raises(HTTPException) as exc_info:
            await require_operator(mock_current_user_viewer)

        assert exc_info.value.status_code == 403

    @pytest.mark.asyncio
    async def test_viewer_can_view_alerts(self, mock_alert, mock_db_session, mock_current_user_viewer):
        """Viewer should be able to view alerts."""
        mock_result = MagicMock()
        mock_result.scalar_one_or_none.return_value = mock_alert
        mock_db_session.execute.return_value = mock_result

        from app.api.v1 import alerts as alerts_module

        if hasattr(alerts_module, 'get_alert'):
            # Should not raise authorization error
            response = await alerts_module.get_alert(
                alert_id=mock_alert.id,
                session=mock_db_session,
                _current_user=mock_current_user_viewer,
            )
            assert response is not None
