"""Tests for the collector registry."""

from unittest.mock import MagicMock, patch

import pytest

from app.collectors.base import BaseCollector
from app.collectors.registry import (
    CollectorRegistry,
    get_collector,
    register_collector,
)
from app.models.log_source import LogSource, SourceType


def create_mock_source(source_type: SourceType = SourceType.API_PULL) -> MagicMock:
    """Create a mock LogSource for testing."""
    source = MagicMock(spec=LogSource)
    source.id = "test-source"
    source.name = "Test Source"
    source.source_type = source_type
    source.config = {"url": "http://example.com"}
    source.parser_type = MagicMock()
    source.parser_type.value = "json"
    source.parser_config = {}
    return source


class MockCollector(BaseCollector):
    """Mock collector for testing."""

    async def collect(self):
        yield MagicMock()

    async def start(self):
        pass

    async def stop(self):
        pass


class TestCollectorRegistryRegister:
    """Tests for CollectorRegistry.register method."""

    def test_register_collector(self):
        """Test registering a collector."""
        # Save original state
        original_collectors = CollectorRegistry._collectors.copy()

        try:
            # Create a test source type
            CollectorRegistry.register(SourceType.FILE_WATCH, MockCollector)

            assert SourceType.FILE_WATCH in CollectorRegistry._collectors
            assert CollectorRegistry._collectors[SourceType.FILE_WATCH] == MockCollector
        finally:
            # Restore original state
            CollectorRegistry._collectors = original_collectors

    def test_register_overwrites_existing(self):
        """Test that registering overwrites existing collector."""
        original_collectors = CollectorRegistry._collectors.copy()

        try:
            class FirstCollector(MockCollector):
                pass

            class SecondCollector(MockCollector):
                pass

            CollectorRegistry.register(SourceType.FILE_WATCH, FirstCollector)
            CollectorRegistry.register(SourceType.FILE_WATCH, SecondCollector)

            assert CollectorRegistry._collectors[SourceType.FILE_WATCH] == SecondCollector
        finally:
            CollectorRegistry._collectors = original_collectors


class TestCollectorRegistryGet:
    """Tests for CollectorRegistry.get method."""

    def test_get_collector_success(self):
        """Test getting a registered collector."""
        original_collectors = CollectorRegistry._collectors.copy()

        try:
            CollectorRegistry.register(SourceType.API_PULL, MockCollector)

            source = create_mock_source(SourceType.API_PULL)

            with patch("app.collectors.registry.get_parser") as mock_get_parser:
                mock_parser = MagicMock()
                mock_get_parser.return_value = mock_parser

                collector = CollectorRegistry.get(source)

                assert isinstance(collector, MockCollector)
                mock_get_parser.assert_called_once_with("json", {})
        finally:
            CollectorRegistry._collectors = original_collectors

    def test_get_collector_not_found(self):
        """Test getting unregistered collector raises ValueError."""
        original_collectors = CollectorRegistry._collectors.copy()

        try:
            # Clear registry
            CollectorRegistry._collectors = {}

            source = create_mock_source(SourceType.API_PULL)

            with pytest.raises(ValueError, match="No collector for source type"):
                CollectorRegistry.get(source)
        finally:
            CollectorRegistry._collectors = original_collectors

    def test_get_collector_error_message_includes_available(self):
        """Test error message includes available source types."""
        original_collectors = CollectorRegistry._collectors.copy()

        try:
            CollectorRegistry._collectors = {}
            CollectorRegistry.register(SourceType.FILE_WATCH, MockCollector)
            CollectorRegistry.register(SourceType.UDP_LISTEN, MockCollector)

            source = create_mock_source(SourceType.API_PULL)

            with pytest.raises(ValueError) as exc_info:
                CollectorRegistry.get(source)

            error_msg = str(exc_info.value)
            assert "Available:" in error_msg
        finally:
            CollectorRegistry._collectors = original_collectors


class TestCollectorRegistryListCollectors:
    """Tests for CollectorRegistry.list_collectors method."""

    def test_list_collectors_empty(self):
        """Test listing collectors when registry is empty."""
        original_collectors = CollectorRegistry._collectors.copy()

        try:
            CollectorRegistry._collectors = {}

            collectors = CollectorRegistry.list_collectors()

            assert collectors == []
        finally:
            CollectorRegistry._collectors = original_collectors

    def test_list_collectors_with_entries(self):
        """Test listing collectors with registered entries."""
        original_collectors = CollectorRegistry._collectors.copy()

        try:
            CollectorRegistry._collectors = {}
            CollectorRegistry.register(SourceType.API_PULL, MockCollector)
            CollectorRegistry.register(SourceType.FILE_WATCH, MockCollector)

            collectors = CollectorRegistry.list_collectors()

            assert len(collectors) == 2
            assert SourceType.API_PULL in collectors
            assert SourceType.FILE_WATCH in collectors
        finally:
            CollectorRegistry._collectors = original_collectors


class TestCollectorRegistryIsRegistered:
    """Tests for CollectorRegistry.is_registered method."""

    def test_is_registered_true(self):
        """Test is_registered returns True for registered type."""
        original_collectors = CollectorRegistry._collectors.copy()

        try:
            CollectorRegistry._collectors = {}
            CollectorRegistry.register(SourceType.API_PULL, MockCollector)

            assert CollectorRegistry.is_registered(SourceType.API_PULL) is True
        finally:
            CollectorRegistry._collectors = original_collectors

    def test_is_registered_false(self):
        """Test is_registered returns False for unregistered type."""
        original_collectors = CollectorRegistry._collectors.copy()

        try:
            CollectorRegistry._collectors = {}

            assert CollectorRegistry.is_registered(SourceType.API_PULL) is False
        finally:
            CollectorRegistry._collectors = original_collectors


class TestRegisterCollectorDecorator:
    """Tests for the @register_collector decorator."""

    def test_decorator_registers_class(self):
        """Test that the decorator registers the class."""
        original_collectors = CollectorRegistry._collectors.copy()

        try:
            CollectorRegistry._collectors = {}

            @register_collector(SourceType.FILE_WATCH)
            class DecoratedCollector(MockCollector):
                pass

            assert SourceType.FILE_WATCH in CollectorRegistry._collectors
            assert CollectorRegistry._collectors[SourceType.FILE_WATCH] == DecoratedCollector
        finally:
            CollectorRegistry._collectors = original_collectors

    def test_decorator_returns_class(self):
        """Test that the decorator returns the original class."""
        original_collectors = CollectorRegistry._collectors.copy()

        try:
            CollectorRegistry._collectors = {}

            @register_collector(SourceType.FILE_WATCH)
            class DecoratedCollector(MockCollector):
                pass

            # Should be able to instantiate
            source = MagicMock()
            parser = MagicMock()
            instance = DecoratedCollector(source, parser)

            assert isinstance(instance, DecoratedCollector)
            assert isinstance(instance, BaseCollector)
        finally:
            CollectorRegistry._collectors = original_collectors


class TestGetCollectorFunction:
    """Tests for the get_collector convenience function."""

    def test_get_collector_delegates_to_registry(self):
        """Test that get_collector delegates to CollectorRegistry.get."""
        source = create_mock_source()

        with patch.object(CollectorRegistry, "get") as mock_get:
            mock_collector = MagicMock()
            mock_get.return_value = mock_collector

            result = get_collector(source)

            mock_get.assert_called_once_with(source)
            assert result == mock_collector
