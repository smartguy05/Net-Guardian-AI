"""Tests for detection rules API endpoints.

Tests cover:
- List rules (with filters)
- Get condition fields
- Get rule by ID
- Create rule (admin only)
- Update rule
- Delete rule
- Enable/disable rule
- Test rule against sample event
"""

from datetime import UTC, datetime
from unittest.mock import AsyncMock, MagicMock

import pytest
from fastapi import HTTPException, status

from app.models.alert import AlertSeverity


class TestListRules:
    """Tests for the list rules endpoint."""

    @pytest.mark.asyncio
    async def test_list_rules_returns_all(self, mock_db_session, mock_current_user_operator):
        """Should return all rules with pagination."""
        now = datetime.now(UTC)

        rule1 = MagicMock()
        rule1.id = "rule-001"
        rule1.name = "DNS Alert"
        rule1.description = "Alert on suspicious DNS"
        rule1.severity = AlertSeverity.HIGH
        rule1.enabled = True
        rule1.conditions = {"logic": "and", "conditions": []}
        rule1.response_actions = [{"type": "create_alert", "config": {}}]
        rule1.cooldown_minutes = 60
        rule1.created_at = now
        rule1.updated_at = now

        rule2 = MagicMock()
        rule2.id = "rule-002"
        rule2.name = "Port Scan Alert"
        rule2.description = "Alert on port scanning"
        rule2.severity = AlertSeverity.MEDIUM
        rule2.enabled = False
        rule2.conditions = {"logic": "and", "conditions": []}
        rule2.response_actions = []
        rule2.cooldown_minutes = 30
        rule2.created_at = now
        rule2.updated_at = now

        rules = [rule1, rule2]

        # Mock count query
        count_result = MagicMock()
        count_result.scalar.return_value = 2

        # Mock paginated query
        paginated_result = MagicMock()
        paginated_result.scalars.return_value.all.return_value = rules

        mock_db_session.execute.side_effect = [count_result, paginated_result]

        from app.api.v1.rules import list_rules

        response = await list_rules(
            session=mock_db_session,
            _current_user=mock_current_user_operator,
            page=1,
            page_size=50,
        )

        assert response.total == 2
        assert len(response.items) == 2
        assert response.items[0].id == "rule-001"
        assert response.items[0].enabled is True

    @pytest.mark.asyncio
    async def test_list_rules_filter_by_enabled(self, mock_db_session, mock_current_user_operator):
        """Should filter rules by enabled status."""
        now = datetime.now(UTC)

        enabled_rule = MagicMock()
        enabled_rule.id = "rule-001"
        enabled_rule.name = "Enabled Rule"
        enabled_rule.description = ""
        enabled_rule.severity = AlertSeverity.LOW
        enabled_rule.enabled = True
        enabled_rule.conditions = {}
        enabled_rule.response_actions = []
        enabled_rule.cooldown_minutes = 60
        enabled_rule.created_at = now
        enabled_rule.updated_at = now

        count_result = MagicMock()
        count_result.scalar.return_value = 1

        paginated_result = MagicMock()
        paginated_result.scalars.return_value.all.return_value = [enabled_rule]

        mock_db_session.execute.side_effect = [count_result, paginated_result]

        from app.api.v1.rules import list_rules

        response = await list_rules(
            session=mock_db_session,
            _current_user=mock_current_user_operator,
            enabled=True,
            page=1,
            page_size=50,
        )

        assert response.total == 1
        assert response.items[0].enabled is True

    @pytest.mark.asyncio
    async def test_list_rules_filter_by_severity(self, mock_db_session, mock_current_user_operator):
        """Should filter rules by severity."""
        count_result = MagicMock()
        count_result.scalar.return_value = 0

        paginated_result = MagicMock()
        paginated_result.scalars.return_value.all.return_value = []

        mock_db_session.execute.side_effect = [count_result, paginated_result]

        from app.api.v1.rules import list_rules

        response = await list_rules(
            session=mock_db_session,
            _current_user=mock_current_user_operator,
            severity=AlertSeverity.CRITICAL,
            page=1,
            page_size=50,
        )

        assert response.total == 0


class TestGetConditionFields:
    """Tests for the get condition fields endpoint."""

    @pytest.mark.asyncio
    async def test_get_condition_fields(self, mock_current_user_operator):
        """Should return available condition fields."""
        from app.api.v1.rules import get_condition_fields

        fields = await get_condition_fields(_current_user=mock_current_user_operator)

        assert len(fields) > 0

        # Check some expected fields
        field_names = [f.name for f in fields]
        assert "event_type" in field_names
        assert "severity" in field_names
        assert "source_ip" in field_names
        assert "domain" in field_names
        assert "port" in field_names

    @pytest.mark.asyncio
    async def test_condition_fields_have_descriptions(self, mock_current_user_operator):
        """Should include descriptions for all fields."""
        from app.api.v1.rules import get_condition_fields

        fields = await get_condition_fields(_current_user=mock_current_user_operator)

        for field in fields:
            assert field.name != ""
            assert field.description != ""
            assert field.type != ""


class TestGetRule:
    """Tests for the get rule endpoint."""

    @pytest.mark.asyncio
    async def test_get_rule_success(self, mock_db_session, mock_current_user_operator):
        """Should return rule details."""
        now = datetime.now(UTC)

        mock_rule = MagicMock()
        mock_rule.id = "test-rule"
        mock_rule.name = "Test Rule"
        mock_rule.description = "Test description"
        mock_rule.severity = AlertSeverity.HIGH
        mock_rule.enabled = True
        mock_rule.conditions = {"logic": "and", "conditions": []}
        mock_rule.response_actions = [{"type": "create_alert", "config": {}}]
        mock_rule.cooldown_minutes = 60
        mock_rule.created_at = now
        mock_rule.updated_at = now

        mock_result = MagicMock()
        mock_result.scalar_one_or_none.return_value = mock_rule
        mock_db_session.execute.return_value = mock_result

        from app.api.v1.rules import get_rule

        response = await get_rule(
            rule_id="test-rule",
            session=mock_db_session,
            _current_user=mock_current_user_operator,
        )

        assert response.id == "test-rule"
        assert response.name == "Test Rule"
        assert response.severity == AlertSeverity.HIGH

    @pytest.mark.asyncio
    async def test_get_rule_not_found(self, mock_db_session, mock_current_user_operator):
        """Should return 404 for non-existent rule."""
        mock_result = MagicMock()
        mock_result.scalar_one_or_none.return_value = None
        mock_db_session.execute.return_value = mock_result

        from app.api.v1.rules import get_rule

        with pytest.raises(HTTPException) as exc_info:
            await get_rule(
                rule_id="nonexistent",
                session=mock_db_session,
                _current_user=mock_current_user_operator,
            )

        assert exc_info.value.status_code == status.HTTP_404_NOT_FOUND


class TestCreateRule:
    """Tests for the create rule endpoint."""

    @pytest.mark.asyncio
    async def test_create_rule_success(self, mock_db_session, mock_current_user_admin):
        """Should create a new detection rule."""
        # Mock no existing rule
        mock_result = MagicMock()
        mock_result.scalar_one_or_none.return_value = None
        mock_db_session.execute.return_value = mock_result

        # Make refresh set the expected attributes on the added rule
        now = datetime.now(UTC)

        def refresh_side_effect(rule):
            rule.created_at = now
            rule.updated_at = now

        mock_db_session.refresh = AsyncMock(side_effect=refresh_side_effect)

        from app.api.v1.rules import (
            CreateRuleRequest,
            RuleAction,
            RuleCondition,
            RuleConditionGroup,
            create_rule,
        )

        request = CreateRuleRequest(
            id="new-rule",
            name="New Detection Rule",
            description="Detects suspicious activity",
            severity=AlertSeverity.HIGH,
            enabled=True,
            conditions=RuleConditionGroup(
                logic="and",
                conditions=[
                    RuleCondition(field="event_type", operator="eq", value="dns"),
                    RuleCondition(field="domain", operator="contains", value="malware"),
                ],
            ),
            response_actions=[
                RuleAction(type="create_alert", config={}),
            ],
            cooldown_minutes=30,
        )

        response = await create_rule(
            request=request,
            session=mock_db_session,
            _current_user=mock_current_user_admin,
        )

        assert response.id == "new-rule"
        assert response.name == "New Detection Rule"
        mock_db_session.add.assert_called_once()
        mock_db_session.commit.assert_called_once()

        # Verify the rule object passed to add() has correct values
        added_rule = mock_db_session.add.call_args[0][0]
        assert added_rule.id == "new-rule"
        assert added_rule.name == "New Detection Rule"
        assert added_rule.description == "Detects suspicious activity"
        assert added_rule.severity == AlertSeverity.HIGH
        assert added_rule.enabled is True
        assert added_rule.cooldown_minutes == 30
        assert len(added_rule.response_actions) == 1

    @pytest.mark.asyncio
    async def test_create_rule_duplicate_id(self, mock_db_session, mock_current_user_admin):
        """Should reject duplicate rule ID."""
        existing_rule = MagicMock()
        mock_result = MagicMock()
        mock_result.scalar_one_or_none.return_value = existing_rule
        mock_db_session.execute.return_value = mock_result

        from app.api.v1.rules import (
            CreateRuleRequest,
            RuleCondition,
            RuleConditionGroup,
            create_rule,
        )

        request = CreateRuleRequest(
            id="existing-rule",
            name="Duplicate Rule",
            severity=AlertSeverity.LOW,
            conditions=RuleConditionGroup(
                logic="and",
                conditions=[RuleCondition(field="port", operator="eq", value=22)],
            ),
        )

        with pytest.raises(HTTPException) as exc_info:
            await create_rule(
                request=request,
                session=mock_db_session,
                _current_user=mock_current_user_admin,
            )

        assert exc_info.value.status_code == status.HTTP_409_CONFLICT
        assert "already exists" in exc_info.value.detail


class TestUpdateRule:
    """Tests for the update rule endpoint."""

    @pytest.mark.asyncio
    async def test_update_rule_name(self, mock_db_session, mock_current_user_admin):
        """Should update rule name."""
        mock_rule = MagicMock(
            id="test-rule",
            name="Old Name",
            description="",
            severity=AlertSeverity.LOW,
            enabled=True,
            conditions={},
            response_actions=[],
            cooldown_minutes=60,
            created_at=datetime.now(UTC),
            updated_at=datetime.now(UTC),
        )

        mock_result = MagicMock()
        mock_result.scalar_one_or_none.return_value = mock_rule
        mock_db_session.execute.return_value = mock_result

        from app.api.v1.rules import UpdateRuleRequest, update_rule

        request = UpdateRuleRequest(name="New Name")

        response = await update_rule(
            rule_id="test-rule",
            request=request,
            session=mock_db_session,
            _current_user=mock_current_user_admin,
        )

        assert mock_rule.name == "New Name"
        mock_db_session.commit.assert_called_once()

    @pytest.mark.asyncio
    async def test_update_rule_severity(self, mock_db_session, mock_current_user_admin):
        """Should update rule severity."""
        now = datetime.now(UTC)

        mock_rule = MagicMock()
        mock_rule.id = "test-rule"
        mock_rule.name = "Test"
        mock_rule.description = ""
        mock_rule.severity = AlertSeverity.LOW
        mock_rule.enabled = True
        mock_rule.conditions = {}
        mock_rule.response_actions = []
        mock_rule.cooldown_minutes = 60
        mock_rule.created_at = now
        mock_rule.updated_at = now

        mock_result = MagicMock()
        mock_result.scalar_one_or_none.return_value = mock_rule
        mock_db_session.execute.return_value = mock_result

        from app.api.v1.rules import UpdateRuleRequest, update_rule

        request = UpdateRuleRequest(severity=AlertSeverity.CRITICAL)

        await update_rule(
            rule_id="test-rule",
            request=request,
            session=mock_db_session,
            _current_user=mock_current_user_admin,
        )

        assert mock_rule.severity == AlertSeverity.CRITICAL

    @pytest.mark.asyncio
    async def test_update_rule_not_found(self, mock_db_session, mock_current_user_admin):
        """Should return 404 for non-existent rule."""
        mock_result = MagicMock()
        mock_result.scalar_one_or_none.return_value = None
        mock_db_session.execute.return_value = mock_result

        from app.api.v1.rules import UpdateRuleRequest, update_rule

        with pytest.raises(HTTPException) as exc_info:
            await update_rule(
                rule_id="nonexistent",
                request=UpdateRuleRequest(name="New Name"),
                session=mock_db_session,
                _current_user=mock_current_user_admin,
            )

        assert exc_info.value.status_code == status.HTTP_404_NOT_FOUND


class TestDeleteRule:
    """Tests for the delete rule endpoint."""

    @pytest.mark.asyncio
    async def test_delete_rule_success(self, mock_db_session, mock_current_user_admin):
        """Should delete rule."""
        mock_rule = MagicMock()
        mock_rule.id = "test-rule"

        mock_result = MagicMock()
        mock_result.scalar_one_or_none.return_value = mock_rule
        mock_db_session.execute.return_value = mock_result
        mock_db_session.delete = AsyncMock()

        from app.api.v1.rules import delete_rule

        await delete_rule(
            rule_id="test-rule",
            session=mock_db_session,
            _current_user=mock_current_user_admin,
        )

        mock_db_session.delete.assert_called_once_with(mock_rule)
        mock_db_session.commit.assert_called_once()

    @pytest.mark.asyncio
    async def test_delete_rule_not_found(self, mock_db_session, mock_current_user_admin):
        """Should return 404 for non-existent rule."""
        mock_result = MagicMock()
        mock_result.scalar_one_or_none.return_value = None
        mock_db_session.execute.return_value = mock_result

        from app.api.v1.rules import delete_rule

        with pytest.raises(HTTPException) as exc_info:
            await delete_rule(
                rule_id="nonexistent",
                session=mock_db_session,
                _current_user=mock_current_user_admin,
            )

        assert exc_info.value.status_code == status.HTTP_404_NOT_FOUND


class TestEnableDisableRule:
    """Tests for enable/disable rule endpoints."""

    @pytest.mark.asyncio
    async def test_enable_rule(self, mock_db_session, mock_current_user_admin):
        """Should enable a disabled rule."""
        now = datetime.now(UTC)

        mock_rule = MagicMock()
        mock_rule.id = "test-rule"
        mock_rule.name = "Test"
        mock_rule.description = ""
        mock_rule.severity = AlertSeverity.LOW
        mock_rule.enabled = False
        mock_rule.conditions = {}
        mock_rule.response_actions = []
        mock_rule.cooldown_minutes = 60
        mock_rule.created_at = now
        mock_rule.updated_at = now

        mock_result = MagicMock()
        mock_result.scalar_one_or_none.return_value = mock_rule
        mock_db_session.execute.return_value = mock_result

        from app.api.v1.rules import enable_rule

        response = await enable_rule(
            rule_id="test-rule",
            session=mock_db_session,
            _current_user=mock_current_user_admin,
        )

        assert mock_rule.enabled is True
        assert response.enabled is True

    @pytest.mark.asyncio
    async def test_disable_rule(self, mock_db_session, mock_current_user_admin):
        """Should disable an enabled rule."""
        now = datetime.now(UTC)

        mock_rule = MagicMock()
        mock_rule.id = "test-rule"
        mock_rule.name = "Test"
        mock_rule.description = ""
        mock_rule.severity = AlertSeverity.LOW
        mock_rule.enabled = True
        mock_rule.conditions = {}
        mock_rule.response_actions = []
        mock_rule.cooldown_minutes = 60
        mock_rule.created_at = now
        mock_rule.updated_at = now

        mock_result = MagicMock()
        mock_result.scalar_one_or_none.return_value = mock_rule
        mock_db_session.execute.return_value = mock_result

        from app.api.v1.rules import disable_rule

        response = await disable_rule(
            rule_id="test-rule",
            session=mock_db_session,
            _current_user=mock_current_user_admin,
        )

        assert mock_rule.enabled is False
        assert response.enabled is False

    @pytest.mark.asyncio
    async def test_enable_rule_not_found(self, mock_db_session, mock_current_user_admin):
        """Should return 404 when enabling non-existent rule."""
        mock_result = MagicMock()
        mock_result.scalar_one_or_none.return_value = None
        mock_db_session.execute.return_value = mock_result

        from app.api.v1.rules import enable_rule

        with pytest.raises(HTTPException) as exc_info:
            await enable_rule(
                rule_id="nonexistent",
                session=mock_db_session,
                _current_user=mock_current_user_admin,
            )

        assert exc_info.value.status_code == status.HTTP_404_NOT_FOUND


class TestTestRule:
    """Tests for the test rule endpoint."""

    @pytest.mark.asyncio
    async def test_rule_matches(self, mock_current_user_operator):
        """Should return match when conditions match event."""
        from app.api.v1.rules import RuleCondition, RuleConditionGroup, TestRuleRequest, test_rule

        request = TestRuleRequest(
            conditions=RuleConditionGroup(
                logic="and",
                conditions=[
                    RuleCondition(field="event_type", operator="eq", value="dns"),
                    RuleCondition(field="port", operator="eq", value=53),
                ],
            ),
            event={
                "event_type": "dns",
                "port": 53,
                "domain": "example.com",
            },
        )

        response = await test_rule(
            request=request,
            _current_user=mock_current_user_operator,
        )

        assert response.matches is True
        assert len(response.condition_results) == 2
        assert all(r["result"] for r in response.condition_results)

    @pytest.mark.asyncio
    async def test_rule_no_match(self, mock_current_user_operator):
        """Should return no match when conditions don't match."""
        from app.api.v1.rules import RuleCondition, RuleConditionGroup, TestRuleRequest, test_rule

        request = TestRuleRequest(
            conditions=RuleConditionGroup(
                logic="and",
                conditions=[
                    RuleCondition(field="event_type", operator="eq", value="firewall"),
                ],
            ),
            event={
                "event_type": "dns",
            },
        )

        response = await test_rule(
            request=request,
            _current_user=mock_current_user_operator,
        )

        assert response.matches is False

    @pytest.mark.asyncio
    async def test_rule_or_logic(self, mock_current_user_operator):
        """Should match with OR logic when one condition matches."""
        from app.api.v1.rules import RuleCondition, RuleConditionGroup, TestRuleRequest, test_rule

        request = TestRuleRequest(
            conditions=RuleConditionGroup(
                logic="or",
                conditions=[
                    RuleCondition(field="port", operator="eq", value=22),  # SSH - won't match
                    RuleCondition(field="port", operator="eq", value=443),  # HTTPS - matches
                ],
            ),
            event={
                "port": 443,
            },
        )

        response = await test_rule(
            request=request,
            _current_user=mock_current_user_operator,
        )

        assert response.matches is True

    @pytest.mark.asyncio
    async def test_rule_contains_operator(self, mock_current_user_operator):
        """Should match with contains operator."""
        from app.api.v1.rules import RuleCondition, RuleConditionGroup, TestRuleRequest, test_rule

        request = TestRuleRequest(
            conditions=RuleConditionGroup(
                logic="and",
                conditions=[
                    RuleCondition(field="domain", operator="contains", value="malware"),
                ],
            ),
            event={
                "domain": "download.malware.com",
            },
        )

        response = await test_rule(
            request=request,
            _current_user=mock_current_user_operator,
        )

        assert response.matches is True

    @pytest.mark.asyncio
    async def test_rule_regex_operator(self, mock_current_user_operator):
        """Should match with regex operator."""
        from app.api.v1.rules import RuleCondition, RuleConditionGroup, TestRuleRequest, test_rule

        request = TestRuleRequest(
            conditions=RuleConditionGroup(
                logic="and",
                conditions=[
                    RuleCondition(field="domain", operator="regex", value=r".*\.evil\.net$"),
                ],
            ),
            event={
                "domain": "download.evil.net",
            },
        )

        response = await test_rule(
            request=request,
            _current_user=mock_current_user_operator,
        )

        assert response.matches is True

    @pytest.mark.asyncio
    async def test_rule_comparison_operators(self, mock_current_user_operator):
        """Should handle comparison operators correctly."""
        from app.api.v1.rules import RuleCondition, RuleConditionGroup, TestRuleRequest, test_rule

        # Test greater than
        request = TestRuleRequest(
            conditions=RuleConditionGroup(
                logic="and",
                conditions=[
                    RuleCondition(field="bytes_transferred", operator="gt", value=1000000),
                ],
            ),
            event={
                "bytes_transferred": 5000000,
            },
        )

        response = await test_rule(
            request=request,
            _current_user=mock_current_user_operator,
        )

        assert response.matches is True

    @pytest.mark.asyncio
    async def test_rule_in_operator(self, mock_current_user_operator):
        """Should handle in operator."""
        from app.api.v1.rules import RuleCondition, RuleConditionGroup, TestRuleRequest, test_rule

        request = TestRuleRequest(
            conditions=RuleConditionGroup(
                logic="and",
                conditions=[
                    RuleCondition(field="port", operator="in", value=[22, 23, 3389]),
                ],
            ),
            event={
                "port": 3389,  # RDP port in list
            },
        )

        response = await test_rule(
            request=request,
            _current_user=mock_current_user_operator,
        )

        assert response.matches is True


class TestRuleConditionValidation:
    """Tests for rule condition validation."""

    def test_valid_operators(self):
        """Should accept all valid operators."""
        from app.api.v1.rules import RuleCondition

        valid_ops = [
            "eq",
            "ne",
            "gt",
            "lt",
            "gte",
            "lte",
            "contains",
            "regex",
            "in",
            "not_in",
            "starts_with",
            "ends_with",
        ]

        for op in valid_ops:
            condition = RuleCondition(field="test", operator=op, value="val")
            assert condition.operator == op

    def test_invalid_operator_rejected(self):
        """Should reject invalid operators."""
        from pydantic import ValidationError

        from app.api.v1.rules import RuleCondition

        with pytest.raises(ValidationError):
            RuleCondition(field="test", operator="invalid", value="val")

    def test_valid_logic_operators(self):
        """Should accept valid logic operators."""
        from app.api.v1.rules import RuleCondition, RuleConditionGroup

        for logic in ["and", "or"]:
            group = RuleConditionGroup(
                logic=logic,
                conditions=[RuleCondition(field="test", operator="eq", value="x")],
            )
            assert group.logic == logic

    def test_invalid_logic_rejected(self):
        """Should reject invalid logic operators."""
        from pydantic import ValidationError

        from app.api.v1.rules import RuleCondition, RuleConditionGroup

        with pytest.raises(ValidationError):
            RuleConditionGroup(
                logic="xor",  # Invalid
                conditions=[RuleCondition(field="test", operator="eq", value="x")],
            )


class TestRuleActionValidation:
    """Tests for rule action validation."""

    def test_valid_action_types(self):
        """Should accept all valid action types."""
        from app.api.v1.rules import RuleAction

        valid_types = [
            "create_alert",
            "quarantine_device",
            "tag_device",
            "send_notification",
            "execute_webhook",
            "log_event",
        ]

        for action_type in valid_types:
            action = RuleAction(type=action_type)
            assert action.type == action_type

    def test_invalid_action_type_rejected(self):
        """Should reject invalid action types."""
        from pydantic import ValidationError

        from app.api.v1.rules import RuleAction

        with pytest.raises(ValidationError):
            RuleAction(type="invalid_action")

    def test_action_with_config(self):
        """Should accept action with config."""
        from app.api.v1.rules import RuleAction

        action = RuleAction(
            type="send_notification",
            config={"channel": "slack", "message": "Alert triggered"},
        )

        assert action.type == "send_notification"
        assert action.config["channel"] == "slack"


class TestCreateRuleRequestValidation:
    """Tests for CreateRuleRequest validation."""

    def test_valid_rule_id_format(self):
        """Should accept valid rule ID formats."""
        from app.api.v1.rules import CreateRuleRequest, RuleCondition, RuleConditionGroup

        valid_ids = ["rule-001", "my_rule", "test123", "a", "1abc"]

        for rule_id in valid_ids:
            request = CreateRuleRequest(
                id=rule_id,
                name="Test",
                severity=AlertSeverity.LOW,
                conditions=RuleConditionGroup(
                    logic="and",
                    conditions=[RuleCondition(field="x", operator="eq", value="y")],
                ),
            )
            assert request.id == rule_id

    def test_invalid_rule_id_rejected(self):
        """Should reject invalid rule ID formats."""
        from pydantic import ValidationError

        from app.api.v1.rules import CreateRuleRequest, RuleCondition, RuleConditionGroup

        invalid_ids = ["_rule", "-rule", "Rule", "RULE", "rule space"]

        for rule_id in invalid_ids:
            with pytest.raises(ValidationError):
                CreateRuleRequest(
                    id=rule_id,
                    name="Test",
                    severity=AlertSeverity.LOW,
                    conditions=RuleConditionGroup(
                        logic="and",
                        conditions=[RuleCondition(field="x", operator="eq", value="y")],
                    ),
                )


class TestResponseActionNormalization:
    """Tests for response action normalization."""

    def test_normalize_legacy_string_format(self):
        """Should convert legacy string actions to dict format."""
        from app.api.v1.rules import _normalize_response_actions

        legacy = ["alert", "quarantine"]
        normalized = _normalize_response_actions(legacy)

        assert len(normalized) == 2
        assert normalized[0] == {"type": "alert", "config": {}}
        assert normalized[1] == {"type": "quarantine", "config": {}}

    def test_normalize_dict_format(self):
        """Should preserve dict format."""
        from app.api.v1.rules import _normalize_response_actions

        actions = [{"type": "create_alert", "config": {"level": "high"}}]
        normalized = _normalize_response_actions(actions)

        assert normalized[0]["type"] == "create_alert"
        assert normalized[0]["config"]["level"] == "high"

    def test_normalize_adds_missing_config(self):
        """Should add missing config key."""
        from app.api.v1.rules import _normalize_response_actions

        actions = [{"type": "alert"}]
        normalized = _normalize_response_actions(actions)

        assert "config" in normalized[0]
        assert normalized[0]["config"] == {}
