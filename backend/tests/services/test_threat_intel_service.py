"""Tests for the Threat Intelligence Service.

Tests cover:
- Feed management (CRUD operations)
- Feed fetching and parsing
- IP list, URL list, CSV, JSON parsing
- Indicator management
- Indicator lookup and search
- Statistics
"""

from unittest.mock import AsyncMock, MagicMock, patch
from uuid import uuid4

import pytest

from app.models.threat_intel import FeedType, IndicatorType, ThreatIndicator, ThreatIntelFeed
from app.services.threat_intel_service import ThreatIntelService


@pytest.fixture
def mock_session():
    """Create a mock async session."""
    session = AsyncMock()
    session.execute = AsyncMock()
    session.commit = AsyncMock()
    session.refresh = AsyncMock()
    session.add = MagicMock()
    session.delete = AsyncMock()
    return session


@pytest.fixture
def threat_intel_service(mock_session):
    """Create a ThreatIntelService instance with mock session."""
    return ThreatIntelService(mock_session)


@pytest.fixture
def sample_feed():
    """Create a sample threat intel feed."""
    feed = MagicMock(spec=ThreatIntelFeed)
    feed.id = uuid4()
    feed.name = "Test Feed"
    feed.url = "https://example.com/feed.txt"
    feed.feed_type = FeedType.IP_LIST
    feed.description = "Test feed description"
    feed.enabled = True
    feed.update_interval_hours = 24
    feed.auth_type = "none"
    feed.auth_config = {}
    feed.field_mapping = {}
    feed.last_fetch_at = None
    feed.last_fetch_status = None
    feed.last_fetch_message = None
    feed.indicator_count = 0
    return feed


class TestThreatIntelServiceFeedManagement:
    """Tests for feed management operations."""

    @pytest.mark.asyncio
    async def test_get_feeds(self, threat_intel_service, mock_session):
        """Should retrieve feeds with pagination."""
        # Setup mock
        mock_feeds = [MagicMock(spec=ThreatIntelFeed) for _ in range(3)]
        mock_result = MagicMock()
        mock_result.scalars.return_value.all.return_value = mock_feeds

        mock_count_result = MagicMock()
        mock_count_result.scalar.return_value = 3

        mock_session.execute.side_effect = [mock_count_result, mock_result]

        # Execute
        feeds, total = await threat_intel_service.get_feeds()

        # Verify
        assert len(feeds) == 3
        assert total == 3

    @pytest.mark.asyncio
    async def test_get_feeds_filtered_by_enabled(self, threat_intel_service, mock_session):
        """Should filter feeds by enabled status."""
        mock_result = MagicMock()
        mock_result.scalars.return_value.all.return_value = []
        mock_count_result = MagicMock()
        mock_count_result.scalar.return_value = 0
        mock_session.execute.side_effect = [mock_count_result, mock_result]

        await threat_intel_service.get_feeds(enabled=True)

        # Verify execute was called (query built with filter)
        assert mock_session.execute.call_count == 2

    @pytest.mark.asyncio
    async def test_get_feeds_filtered_by_type(self, threat_intel_service, mock_session):
        """Should filter feeds by feed type."""
        mock_result = MagicMock()
        mock_result.scalars.return_value.all.return_value = []
        mock_count_result = MagicMock()
        mock_count_result.scalar.return_value = 0
        mock_session.execute.side_effect = [mock_count_result, mock_result]

        await threat_intel_service.get_feeds(feed_type=FeedType.IP_LIST)

        assert mock_session.execute.call_count == 2

    @pytest.mark.asyncio
    async def test_get_feed(self, threat_intel_service, mock_session, sample_feed):
        """Should retrieve a single feed by ID."""
        mock_result = MagicMock()
        mock_result.scalar_one_or_none.return_value = sample_feed
        mock_session.execute.return_value = mock_result

        feed = await threat_intel_service.get_feed(sample_feed.id)

        assert feed == sample_feed

    @pytest.mark.asyncio
    async def test_get_feed_not_found(self, threat_intel_service, mock_session):
        """Should return None for non-existent feed."""
        mock_result = MagicMock()
        mock_result.scalar_one_or_none.return_value = None
        mock_session.execute.return_value = mock_result

        feed = await threat_intel_service.get_feed(uuid4())

        assert feed is None

    @pytest.mark.asyncio
    async def test_create_feed(self, threat_intel_service, mock_session):
        """Should create a new feed."""
        await threat_intel_service.create_feed(
            name="Test Feed",
            url="https://example.com/feed",
            feed_type=FeedType.IP_LIST,
            description="Test description",
        )

        mock_session.add.assert_called_once()
        mock_session.commit.assert_called_once()
        mock_session.refresh.assert_called_once()

    @pytest.mark.asyncio
    async def test_create_feed_with_auth(self, threat_intel_service, mock_session):
        """Should create a feed with authentication config."""
        await threat_intel_service.create_feed(
            name="Auth Feed",
            url="https://api.example.com/feed",
            feed_type=FeedType.JSON,
            auth_type="bearer",
            auth_config={"token": "secret123"},
        )

        mock_session.add.assert_called_once()
        added_feed = mock_session.add.call_args[0][0]
        assert added_feed.auth_type == "bearer"
        assert added_feed.auth_config == {"token": "secret123"}

    @pytest.mark.asyncio
    async def test_update_feed(self, threat_intel_service, mock_session, sample_feed):
        """Should update feed properties."""
        mock_result = MagicMock()
        mock_result.scalar_one_or_none.return_value = sample_feed
        mock_session.execute.return_value = mock_result

        updated = await threat_intel_service.update_feed(
            sample_feed.id,
            name="Updated Name",
            enabled=False,
        )

        assert updated == sample_feed
        assert sample_feed.name == "Updated Name"
        assert sample_feed.enabled is False
        mock_session.commit.assert_called_once()

    @pytest.mark.asyncio
    async def test_update_feed_not_found(self, threat_intel_service, mock_session):
        """Should return None when updating non-existent feed."""
        mock_result = MagicMock()
        mock_result.scalar_one_or_none.return_value = None
        mock_session.execute.return_value = mock_result

        result = await threat_intel_service.update_feed(uuid4(), name="New Name")

        assert result is None

    @pytest.mark.asyncio
    async def test_delete_feed(self, threat_intel_service, mock_session, sample_feed):
        """Should delete a feed."""
        mock_result = MagicMock()
        mock_result.scalar_one_or_none.return_value = sample_feed
        mock_session.execute.return_value = mock_result

        result = await threat_intel_service.delete_feed(sample_feed.id)

        assert result is True
        mock_session.delete.assert_called_once_with(sample_feed)
        mock_session.commit.assert_called_once()

    @pytest.mark.asyncio
    async def test_delete_feed_not_found(self, threat_intel_service, mock_session):
        """Should return False when deleting non-existent feed."""
        mock_result = MagicMock()
        mock_result.scalar_one_or_none.return_value = None
        mock_session.execute.return_value = mock_result

        result = await threat_intel_service.delete_feed(uuid4())

        assert result is False


class TestThreatIntelServiceIPListParsing:
    """Tests for IP list feed parsing."""

    def test_parse_ip_list_basic(self, threat_intel_service):
        """Should parse basic IP list."""
        content = """192.168.1.1
10.0.0.1
8.8.8.8"""
        field_mapping = {}

        indicators = threat_intel_service._parse_ip_list(content, field_mapping)

        assert len(indicators) == 3
        assert all(ind["indicator_type"] == IndicatorType.IP for ind in indicators)
        assert indicators[0]["value"] == "192.168.1.1"
        assert indicators[1]["value"] == "10.0.0.1"
        assert indicators[2]["value"] == "8.8.8.8"

    def test_parse_ip_list_with_comments(self, threat_intel_service):
        """Should skip comment lines."""
        content = """# This is a comment
192.168.1.1
# Another comment
10.0.0.1"""
        field_mapping = {}

        indicators = threat_intel_service._parse_ip_list(content, field_mapping)

        assert len(indicators) == 2

    def test_parse_ip_list_with_cidr(self, threat_intel_service):
        """Should recognize CIDR notation."""
        content = """192.168.0.0/16
10.0.0.0/8"""
        field_mapping = {}

        indicators = threat_intel_service._parse_ip_list(content, field_mapping)

        assert len(indicators) == 2
        assert all(ind["indicator_type"] == IndicatorType.CIDR for ind in indicators)

    def test_parse_ip_list_with_invalid(self, threat_intel_service):
        """Should skip invalid IP addresses."""
        content = """192.168.1.1
not_an_ip
10.0.0.1
300.300.300.300"""
        field_mapping = {}

        indicators = threat_intel_service._parse_ip_list(content, field_mapping)

        # Only valid IPs should be parsed
        assert len(indicators) == 2

    def test_parse_ip_list_with_defaults(self, threat_intel_service):
        """Should use default severity and confidence."""
        content = "192.168.1.1"
        field_mapping = {"default_severity": "high", "default_confidence": 90}

        indicators = threat_intel_service._parse_ip_list(content, field_mapping)

        assert len(indicators) == 1
        assert indicators[0]["severity"] == "high"
        assert indicators[0]["confidence"] == 90

    def test_parse_ip_list_empty_lines(self, threat_intel_service):
        """Should handle empty lines."""
        content = """192.168.1.1

10.0.0.1

"""
        field_mapping = {}

        indicators = threat_intel_service._parse_ip_list(content, field_mapping)

        assert len(indicators) == 2


class TestThreatIntelServiceURLListParsing:
    """Tests for URL list feed parsing."""

    def test_parse_url_list_domains(self, threat_intel_service):
        """Should parse domain list."""
        content = """malware.example.com
badsite.org
phishing.net"""
        field_mapping = {}

        indicators = threat_intel_service._parse_url_list(content, field_mapping)

        assert len(indicators) == 3
        assert all(ind["indicator_type"] == IndicatorType.DOMAIN for ind in indicators)

    def test_parse_url_list_full_urls(self, threat_intel_service):
        """Should parse full URLs."""
        content = """https://malware.example.com/payload.exe
http://badsite.org/phish"""
        field_mapping = {}

        indicators = threat_intel_service._parse_url_list(content, field_mapping)

        assert len(indicators) == 2
        assert all(ind["indicator_type"] == IndicatorType.URL for ind in indicators)

    def test_parse_url_list_mixed(self, threat_intel_service):
        """Should handle mixed domains and URLs."""
        content = """malware.com
https://malware.com/payload
badsite.org
http://badsite.org/page"""
        field_mapping = {}

        indicators = threat_intel_service._parse_url_list(content, field_mapping)

        assert len(indicators) == 4
        assert indicators[0]["indicator_type"] == IndicatorType.DOMAIN
        assert indicators[1]["indicator_type"] == IndicatorType.URL
        assert indicators[2]["indicator_type"] == IndicatorType.DOMAIN
        assert indicators[3]["indicator_type"] == IndicatorType.URL

    def test_parse_url_list_with_comments(self, threat_intel_service):
        """Should skip comment lines."""
        content = """# Malicious domains
malware.com
# Phishing sites
phishing.net"""
        field_mapping = {}

        indicators = threat_intel_service._parse_url_list(content, field_mapping)

        assert len(indicators) == 2


class TestThreatIntelServiceCSVParsing:
    """Tests for CSV feed parsing."""

    def test_parse_csv_basic(self, threat_intel_service):
        """Should parse basic CSV."""
        content = """value,type,severity
192.168.1.1,ip,high
malware.com,domain,medium"""
        field_mapping = {
            "value_column": 0,
            "type_column": 1,
            "severity_column": 2,
            "skip_header": True,
        }

        indicators = threat_intel_service._parse_csv(content, field_mapping)

        assert len(indicators) == 2
        assert indicators[0]["value"] == "192.168.1.1"
        assert indicators[0]["indicator_type"] == IndicatorType.IP
        assert indicators[0]["severity"] == "high"
        assert indicators[1]["value"] == "malware.com"
        assert indicators[1]["indicator_type"] == IndicatorType.DOMAIN

    def test_parse_csv_without_header(self, threat_intel_service):
        """Should parse CSV without header."""
        content = """192.168.1.1
10.0.0.1"""
        field_mapping = {
            "value_column": 0,
            "skip_header": False,
            "default_type": "ip",
        }

        indicators = threat_intel_service._parse_csv(content, field_mapping)

        assert len(indicators) == 2

    def test_parse_csv_with_description(self, threat_intel_service):
        """Should parse CSV with description column."""
        content = """value,description
malware.com,Known malware domain"""
        field_mapping = {
            "value_column": 0,
            "description_column": 1,
            "skip_header": True,
            "default_type": "domain",
        }

        indicators = threat_intel_service._parse_csv(content, field_mapping)

        assert len(indicators) == 1
        assert indicators[0]["description"] == "Known malware domain"

    def test_parse_csv_with_confidence(self, threat_intel_service):
        """Should parse CSV with confidence column."""
        content = """value,confidence
192.168.1.1,95"""
        field_mapping = {
            "value_column": 0,
            "confidence_column": 1,
            "skip_header": True,
            "default_type": "ip",
        }

        indicators = threat_intel_service._parse_csv(content, field_mapping)

        assert len(indicators) == 1
        assert indicators[0]["confidence"] == 95

    def test_parse_csv_empty_rows(self, threat_intel_service):
        """Should skip empty rows."""
        content = """value
192.168.1.1

10.0.0.1"""
        field_mapping = {"value_column": 0, "skip_header": True, "default_type": "ip"}

        indicators = threat_intel_service._parse_csv(content, field_mapping)

        assert len(indicators) == 2

    def test_parse_csv_invalid_row(self, threat_intel_service):
        """Should handle rows with missing columns gracefully."""
        content = """value,type
192.168.1.1,ip
badrow"""  # Only one column
        field_mapping = {
            "value_column": 0,
            "type_column": 1,
            "skip_header": True,
        }

        # Should not raise, just skip invalid row
        indicators = threat_intel_service._parse_csv(content, field_mapping)

        assert len(indicators) >= 1


class TestThreatIntelServiceJSONParsing:
    """Tests for JSON feed parsing."""

    def test_parse_json_basic(self, threat_intel_service):
        """Should parse basic JSON array."""
        content = """[
            {"value": "192.168.1.1", "type": "ip"},
            {"value": "malware.com", "type": "domain"}
        ]"""
        field_mapping = {
            "value_field": "value",
            "type_field": "type",
        }

        indicators = threat_intel_service._parse_json(content, field_mapping)

        assert len(indicators) == 2
        assert indicators[0]["value"] == "192.168.1.1"
        assert indicators[0]["indicator_type"] == IndicatorType.IP
        assert indicators[1]["value"] == "malware.com"
        assert indicators[1]["indicator_type"] == IndicatorType.DOMAIN

    def test_parse_json_with_array_path(self, threat_intel_service):
        """Should parse JSON with nested array."""
        content = """{
            "data": {
                "indicators": [
                    {"ip": "192.168.1.1"},
                    {"ip": "10.0.0.1"}
                ]
            }
        }"""
        field_mapping = {
            "array_path": "data.indicators",
            "value_field": "ip",
            "default_type": "ip",
        }

        indicators = threat_intel_service._parse_json(content, field_mapping)

        assert len(indicators) == 2

    def test_parse_json_with_all_fields(self, threat_intel_service):
        """Should parse JSON with all indicator fields."""
        content = """[{
            "indicator": "malware.com",
            "ind_type": "domain",
            "sev": "high",
            "conf": 95,
            "desc": "Known malware"
        }]"""
        field_mapping = {
            "value_field": "indicator",
            "type_field": "ind_type",
            "severity_field": "sev",
            "confidence_field": "conf",
            "description_field": "desc",
        }

        indicators = threat_intel_service._parse_json(content, field_mapping)

        assert len(indicators) == 1
        assert indicators[0]["value"] == "malware.com"
        assert indicators[0]["severity"] == "high"
        assert indicators[0]["confidence"] == 95
        assert indicators[0]["description"] == "Known malware"

    def test_parse_json_invalid(self, threat_intel_service):
        """Should handle invalid JSON gracefully."""
        content = "not valid json"
        field_mapping = {}

        indicators = threat_intel_service._parse_json(content, field_mapping)

        assert indicators == []

    def test_parse_json_single_object(self, threat_intel_service):
        """Should handle single object (not array)."""
        content = """{"value": "192.168.1.1", "type": "ip"}"""
        field_mapping = {
            "value_field": "value",
            "type_field": "type",
        }

        indicators = threat_intel_service._parse_json(content, field_mapping)

        assert len(indicators) == 1

    def test_parse_json_type_mapping(self, threat_intel_service):
        """Should map type strings to IndicatorType enum."""
        content = """[
            {"value": "test1", "type": "ip"},
            {"value": "test2", "type": "domain"},
            {"value": "test3", "type": "url"},
            {"value": "test4", "type": "md5"},
            {"value": "test5", "type": "sha1"},
            {"value": "test6", "type": "sha256"},
            {"value": "test7", "type": "email"},
            {"value": "test8", "type": "cidr"}
        ]"""
        field_mapping = {"value_field": "value", "type_field": "type"}

        indicators = threat_intel_service._parse_json(content, field_mapping)

        assert len(indicators) == 8
        assert indicators[0]["indicator_type"] == IndicatorType.IP
        assert indicators[1]["indicator_type"] == IndicatorType.DOMAIN
        assert indicators[2]["indicator_type"] == IndicatorType.URL
        assert indicators[3]["indicator_type"] == IndicatorType.HASH_MD5
        assert indicators[4]["indicator_type"] == IndicatorType.HASH_SHA1
        assert indicators[5]["indicator_type"] == IndicatorType.HASH_SHA256
        assert indicators[6]["indicator_type"] == IndicatorType.EMAIL
        assert indicators[7]["indicator_type"] == IndicatorType.CIDR


class TestThreatIntelServiceFeedFetching:
    """Tests for feed fetching operations."""

    @pytest.mark.asyncio
    async def test_fetch_feed_not_found(self, threat_intel_service, mock_session):
        """Should return error for non-existent feed."""
        mock_result = MagicMock()
        mock_result.scalar_one_or_none.return_value = None
        mock_session.execute.return_value = mock_result

        result = await threat_intel_service.fetch_feed(uuid4())

        assert result["success"] is False
        assert "not found" in result["error"].lower()

    @pytest.mark.asyncio
    async def test_fetch_feed_ip_list(self, threat_intel_service, mock_session, sample_feed):
        """Should fetch and parse IP list feed."""
        sample_feed.feed_type = FeedType.IP_LIST

        mock_result = MagicMock()
        mock_result.scalar_one_or_none.return_value = sample_feed
        mock_result.scalars.return_value.all.return_value = []

        mock_count_result = MagicMock()
        mock_count_result.scalar.return_value = 2

        mock_session.execute.side_effect = [mock_result, mock_result, mock_count_result]

        with patch("httpx.AsyncClient") as mock_client:
            mock_response = AsyncMock()
            mock_response.text = "192.168.1.1\n10.0.0.1"
            mock_response.raise_for_status = MagicMock()

            mock_client_instance = AsyncMock()
            mock_client_instance.get.return_value = mock_response
            mock_client_instance.__aenter__.return_value = mock_client_instance
            mock_client_instance.__aexit__.return_value = AsyncMock()
            mock_client.return_value = mock_client_instance

            result = await threat_intel_service.fetch_feed(sample_feed.id)

        assert result["success"] is True

    @pytest.mark.asyncio
    async def test_fetch_feed_with_bearer_auth(
        self, threat_intel_service, mock_session, sample_feed
    ):
        """Should fetch feed with bearer authentication."""
        sample_feed.auth_type = "bearer"
        sample_feed.auth_config = {"token": "secret_token"}

        mock_result = MagicMock()
        mock_result.scalar_one_or_none.return_value = sample_feed
        mock_result.scalars.return_value.all.return_value = []

        mock_count_result = MagicMock()
        mock_count_result.scalar.return_value = 0

        mock_session.execute.side_effect = [mock_result, mock_result, mock_count_result]

        with patch("httpx.AsyncClient") as mock_client:
            mock_response = AsyncMock()
            mock_response.text = "192.168.1.1"
            mock_response.raise_for_status = MagicMock()

            mock_client_instance = AsyncMock()
            mock_client_instance.get.return_value = mock_response
            mock_client_instance.__aenter__.return_value = mock_client_instance
            mock_client_instance.__aexit__.return_value = AsyncMock()
            mock_client.return_value = mock_client_instance

            await threat_intel_service.fetch_feed(sample_feed.id)

            # Verify Authorization header was set
            call_args = mock_client_instance.get.call_args
            assert "Authorization" in call_args.kwargs.get("headers", {})

    @pytest.mark.asyncio
    async def test_fetch_feed_error_handling(self, threat_intel_service, mock_session, sample_feed):
        """Should handle fetch errors gracefully."""
        mock_result = MagicMock()
        mock_result.scalar_one_or_none.return_value = sample_feed
        mock_session.execute.return_value = mock_result

        with patch("httpx.AsyncClient") as mock_client:
            mock_client_instance = AsyncMock()
            mock_client_instance.get.side_effect = Exception("Connection failed")
            mock_client_instance.__aenter__.return_value = mock_client_instance
            # Return False so exception propagates (truthy value suppresses exceptions)
            mock_client_instance.__aexit__ = AsyncMock(return_value=False)
            mock_client.return_value = mock_client_instance

            result = await threat_intel_service.fetch_feed(sample_feed.id)

        assert result["success"] is False
        assert "Connection failed" in result["error"]


class TestThreatIntelServiceIndicatorLookup:
    """Tests for indicator lookup operations."""

    @pytest.mark.asyncio
    async def test_check_indicator(self, threat_intel_service, mock_session):
        """Should check if indicator exists."""
        mock_indicator = MagicMock(spec=ThreatIndicator)
        mock_indicator.hit_count = 0
        mock_indicator.last_hit_at = None

        mock_result = MagicMock()
        mock_result.scalars.return_value.all.return_value = [mock_indicator]
        mock_session.execute.return_value = mock_result

        indicators = await threat_intel_service.check_indicator("192.168.1.1")

        assert len(indicators) == 1
        assert mock_indicator.hit_count == 1
        mock_session.commit.assert_called_once()

    @pytest.mark.asyncio
    async def test_check_indicator_not_found(self, threat_intel_service, mock_session):
        """Should return empty list when indicator not found."""
        mock_result = MagicMock()
        mock_result.scalars.return_value.all.return_value = []
        mock_session.execute.return_value = mock_result

        indicators = await threat_intel_service.check_indicator("192.168.1.1")

        assert len(indicators) == 0

    @pytest.mark.asyncio
    async def test_check_indicator_with_type(self, threat_intel_service, mock_session):
        """Should filter by indicator type."""
        mock_result = MagicMock()
        mock_result.scalars.return_value.all.return_value = []
        mock_session.execute.return_value = mock_result

        await threat_intel_service.check_indicator("192.168.1.1", IndicatorType.IP)

        # Query should have been built with type filter
        assert mock_session.execute.called

    @pytest.mark.asyncio
    async def test_search_indicators(self, threat_intel_service, mock_session):
        """Should search indicators with filters."""
        mock_indicators = [MagicMock(spec=ThreatIndicator) for _ in range(2)]

        mock_result = MagicMock()
        mock_result.scalars.return_value.all.return_value = mock_indicators

        mock_count_result = MagicMock()
        mock_count_result.scalar.return_value = 2

        mock_session.execute.side_effect = [mock_count_result, mock_result]

        indicators, total = await threat_intel_service.search_indicators(
            value_contains="192.168",
            indicator_type=IndicatorType.IP,
            severity="high",
            limit=10,
        )

        assert len(indicators) == 2
        assert total == 2

    @pytest.mark.asyncio
    async def test_record_hit(self, threat_intel_service, mock_session):
        """Should record hit on indicator."""
        mock_indicator = MagicMock(spec=ThreatIndicator)
        mock_indicator.hit_count = 5
        mock_indicator.last_hit_at = None

        mock_result = MagicMock()
        mock_result.scalar_one_or_none.return_value = mock_indicator
        mock_session.execute.return_value = mock_result

        await threat_intel_service.record_hit(uuid4())

        assert mock_indicator.hit_count == 6
        assert mock_indicator.last_hit_at is not None
        mock_session.commit.assert_called_once()


class TestThreatIntelServiceStatistics:
    """Tests for statistics operations."""

    @pytest.mark.asyncio
    async def test_get_stats(self, threat_intel_service, mock_session):
        """Should return statistics."""
        # Mock all the count queries:
        # 3 (total_feeds, enabled_feeds, total_indicators)
        # + 8 (IndicatorType: IP, DOMAIN, URL, HASH_MD5, HASH_SHA1, HASH_SHA256, EMAIL, CIDR)
        # + 4 (severities: low, medium, high, critical)
        # + 1 (recent_hits)
        # = 16 total
        mock_results = []
        counts = [5, 3, 100, 50, 20, 10, 5, 5, 5, 5, 25, 30, 35, 10, 15, 200]
        for count in counts:
            mock_result = MagicMock()
            mock_result.scalar.return_value = count
            mock_results.append(mock_result)

        mock_session.execute.side_effect = mock_results

        stats = await threat_intel_service.get_stats()

        assert "total_feeds" in stats
        assert "enabled_feeds" in stats
        assert "total_indicators" in stats
        assert "indicators_by_type" in stats
        assert "indicators_by_severity" in stats
        assert "recent_hits" in stats


class TestThreatIntelServiceUpdateIndicators:
    """Tests for indicator update operations."""

    @pytest.mark.asyncio
    async def test_update_indicators_add_new(self, threat_intel_service, mock_session, sample_feed):
        """Should add new indicators."""
        mock_result = MagicMock()
        mock_result.scalars.return_value.all.return_value = []
        mock_session.execute.return_value = mock_result

        indicators = [
            {
                "indicator_type": IndicatorType.IP,
                "value": "192.168.1.1",
                "severity": "high",
                "confidence": 90,
            }
        ]

        added, updated = await threat_intel_service._update_indicators(sample_feed, indicators)

        assert added == 1
        assert updated == 0
        mock_session.add.assert_called_once()

    @pytest.mark.asyncio
    async def test_update_indicators_update_existing(
        self, threat_intel_service, mock_session, sample_feed
    ):
        """Should update existing indicators."""
        existing_indicator = MagicMock(spec=ThreatIndicator)
        existing_indicator.value = "192.168.1.1"

        mock_result = MagicMock()
        mock_result.scalars.return_value.all.return_value = [existing_indicator]
        mock_session.execute.return_value = mock_result

        indicators = [
            {
                "indicator_type": IndicatorType.IP,
                "value": "192.168.1.1",
                "severity": "critical",
                "confidence": 95,
            }
        ]

        added, updated = await threat_intel_service._update_indicators(sample_feed, indicators)

        assert added == 0
        assert updated == 1
        assert existing_indicator.severity == "critical"
        assert existing_indicator.confidence == 95

    @pytest.mark.asyncio
    async def test_update_indicators_remove_old(
        self, threat_intel_service, mock_session, sample_feed
    ):
        """Should remove indicators not in latest feed."""
        old_indicator = MagicMock(spec=ThreatIndicator)
        old_indicator.value = "old_value"

        mock_result = MagicMock()
        mock_result.scalars.return_value.all.return_value = [old_indicator]
        mock_session.execute.return_value = mock_result

        indicators = [
            {
                "indicator_type": IndicatorType.IP,
                "value": "new_value",
                "severity": "high",
                "confidence": 90,
            }
        ]

        await threat_intel_service._update_indicators(sample_feed, indicators)

        mock_session.delete.assert_called_with(old_indicator)


class TestThreatIntelServiceCountIndicators:
    """Tests for indicator counting."""

    @pytest.mark.asyncio
    async def test_count_feed_indicators(self, threat_intel_service, mock_session):
        """Should count indicators for a feed."""
        mock_result = MagicMock()
        mock_result.scalar.return_value = 42
        mock_session.execute.return_value = mock_result

        count = await threat_intel_service._count_feed_indicators(uuid4())

        assert count == 42

    @pytest.mark.asyncio
    async def test_count_feed_indicators_empty(self, threat_intel_service, mock_session):
        """Should return 0 for feed with no indicators."""
        mock_result = MagicMock()
        mock_result.scalar.return_value = None
        mock_session.execute.return_value = mock_result

        count = await threat_intel_service._count_feed_indicators(uuid4())

        assert count == 0
