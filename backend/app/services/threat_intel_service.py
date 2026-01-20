"""Threat intelligence service for managing feeds and indicators."""

import csv
import io
import ipaddress
import re
from datetime import datetime, timedelta, timezone
from typing import Optional, List, Dict, Any
from uuid import UUID

import httpx
import structlog
from sqlalchemy import select, func, delete
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.threat_intel import (
    ThreatIntelFeed,
    ThreatIndicator,
    FeedType,
    IndicatorType,
)

logger = structlog.get_logger()


class ThreatIntelService:
    """Service for managing threat intelligence feeds and indicators."""

    def __init__(self, session: AsyncSession):
        self.session = session

    # --- Feed Management ---

    async def get_feeds(
        self,
        enabled: Optional[bool] = None,
        feed_type: Optional[FeedType] = None,
        limit: int = 50,
        offset: int = 0,
    ) -> tuple[list[ThreatIntelFeed], int]:
        """Get all threat intelligence feeds."""
        query = select(ThreatIntelFeed)

        if enabled is not None:
            query = query.where(ThreatIntelFeed.enabled == enabled)
        if feed_type:
            query = query.where(ThreatIntelFeed.feed_type == feed_type)

        # Count total
        count_query = select(func.count()).select_from(query.subquery())
        total_result = await self.session.execute(count_query)
        total = total_result.scalar() or 0

        # Paginate
        query = query.offset(offset).limit(limit).order_by(ThreatIntelFeed.name)
        result = await self.session.execute(query)
        feeds = list(result.scalars().all())

        return feeds, total

    async def get_feed(self, feed_id: UUID) -> Optional[ThreatIntelFeed]:
        """Get a specific feed by ID."""
        result = await self.session.execute(
            select(ThreatIntelFeed).where(ThreatIntelFeed.id == feed_id)
        )
        return result.scalar_one_or_none()

    async def create_feed(
        self,
        name: str,
        url: str,
        feed_type: FeedType,
        description: Optional[str] = None,
        enabled: bool = True,
        update_interval_hours: int = 24,
        auth_type: str = "none",
        auth_config: Optional[Dict[str, Any]] = None,
        field_mapping: Optional[Dict[str, Any]] = None,
    ) -> ThreatIntelFeed:
        """Create a new threat intelligence feed."""
        feed = ThreatIntelFeed(
            name=name,
            url=url,
            feed_type=feed_type,
            description=description,
            enabled=enabled,
            update_interval_hours=update_interval_hours,
            auth_type=auth_type,
            auth_config=auth_config or {},
            field_mapping=field_mapping or {},
        )
        self.session.add(feed)
        await self.session.commit()
        await self.session.refresh(feed)
        return feed

    async def update_feed(
        self,
        feed_id: UUID,
        **updates: Any,
    ) -> Optional[ThreatIntelFeed]:
        """Update a feed's configuration."""
        feed = await self.get_feed(feed_id)
        if not feed:
            return None

        for key, value in updates.items():
            if hasattr(feed, key) and value is not None:
                setattr(feed, key, value)

        await self.session.commit()
        await self.session.refresh(feed)
        return feed

    async def delete_feed(self, feed_id: UUID) -> bool:
        """Delete a feed and all its indicators."""
        feed = await self.get_feed(feed_id)
        if not feed:
            return False

        await self.session.delete(feed)
        await self.session.commit()
        return True

    # --- Feed Fetching ---

    async def fetch_feed(self, feed_id: UUID) -> Dict[str, Any]:
        """Fetch and parse a threat intelligence feed."""
        feed = await self.get_feed(feed_id)
        if not feed:
            return {"success": False, "error": "Feed not found"}

        try:
            # Build headers for authentication
            headers = {}
            if feed.auth_type == "bearer":
                token = feed.auth_config.get("token", "")
                headers["Authorization"] = f"Bearer {token}"
            elif feed.auth_type == "api_key":
                header_name = feed.auth_config.get("header", "X-API-Key")
                api_key = feed.auth_config.get("key", "")
                headers[header_name] = api_key

            # Fetch the feed
            async with httpx.AsyncClient(timeout=60.0) as client:
                if feed.auth_type == "basic":
                    auth = (
                        feed.auth_config.get("username", ""),
                        feed.auth_config.get("password", ""),
                    )
                    response = await client.get(feed.url, auth=auth, headers=headers)
                else:
                    response = await client.get(feed.url, headers=headers)

                response.raise_for_status()
                content = response.text

            # Parse based on feed type
            indicators = await self._parse_feed_content(feed, content)

            # Update indicators in database
            added, updated = await self._update_indicators(feed, indicators)

            # Update feed status
            feed.last_fetch_at = datetime.now(timezone.utc)
            feed.last_fetch_status = "success"
            feed.last_fetch_message = f"Added {added}, updated {updated} indicators"
            feed.indicator_count = await self._count_feed_indicators(feed.id)
            await self.session.commit()

            logger.info(
                "Feed fetched successfully",
                feed_id=str(feed.id),
                feed_name=feed.name,
                added=added,
                updated=updated,
            )

            return {
                "success": True,
                "added": added,
                "updated": updated,
                "total": feed.indicator_count,
            }

        except Exception as e:
            feed.last_fetch_at = datetime.now(timezone.utc)
            feed.last_fetch_status = "error"
            feed.last_fetch_message = str(e)
            await self.session.commit()

            logger.error(
                "Feed fetch failed",
                feed_id=str(feed.id),
                feed_name=feed.name,
                error=str(e),
            )

            return {"success": False, "error": str(e)}

    async def _parse_feed_content(
        self,
        feed: ThreatIntelFeed,
        content: str,
    ) -> List[Dict[str, Any]]:
        """Parse feed content based on feed type."""
        indicators = []

        if feed.feed_type == FeedType.IP_LIST:
            indicators = self._parse_ip_list(content, feed.field_mapping)
        elif feed.feed_type == FeedType.URL_LIST:
            indicators = self._parse_url_list(content, feed.field_mapping)
        elif feed.feed_type == FeedType.CSV:
            indicators = self._parse_csv(content, feed.field_mapping)
        elif feed.feed_type == FeedType.JSON:
            indicators = self._parse_json(content, feed.field_mapping)
        # STIX parsing would require a dedicated library

        return indicators

    def _parse_ip_list(
        self,
        content: str,
        field_mapping: Dict[str, Any],
    ) -> List[Dict[str, Any]]:
        """Parse a simple IP address list (one per line)."""
        indicators = []
        default_severity = field_mapping.get("default_severity", "medium")
        default_confidence = field_mapping.get("default_confidence", 70)

        for line in content.strip().split("\n"):
            line = line.strip()
            if not line or line.startswith("#"):
                continue

            # Check if it's a CIDR or single IP
            try:
                if "/" in line:
                    ipaddress.ip_network(line, strict=False)
                    ind_type = IndicatorType.CIDR
                else:
                    ipaddress.ip_address(line)
                    ind_type = IndicatorType.IP

                indicators.append({
                    "indicator_type": ind_type,
                    "value": line,
                    "severity": default_severity,
                    "confidence": default_confidence,
                })
            except ValueError:
                continue

        return indicators

    def _parse_url_list(
        self,
        content: str,
        field_mapping: Dict[str, Any],
    ) -> List[Dict[str, Any]]:
        """Parse a URL/domain list (one per line)."""
        indicators = []
        default_severity = field_mapping.get("default_severity", "medium")
        default_confidence = field_mapping.get("default_confidence", 70)

        for line in content.strip().split("\n"):
            line = line.strip()
            if not line or line.startswith("#"):
                continue

            # Determine if it's a full URL or just a domain
            if line.startswith("http://") or line.startswith("https://"):
                ind_type = IndicatorType.URL
            else:
                ind_type = IndicatorType.DOMAIN

            indicators.append({
                "indicator_type": ind_type,
                "value": line,
                "severity": default_severity,
                "confidence": default_confidence,
            })

        return indicators

    def _parse_csv(
        self,
        content: str,
        field_mapping: Dict[str, Any],
    ) -> List[Dict[str, Any]]:
        """Parse CSV format threat intelligence."""
        indicators = []

        # Field mapping tells us which columns map to which indicator fields
        value_col = field_mapping.get("value_column", 0)
        type_col = field_mapping.get("type_column")
        severity_col = field_mapping.get("severity_column")
        confidence_col = field_mapping.get("confidence_column")
        description_col = field_mapping.get("description_column")
        default_type = field_mapping.get("default_type", "domain")
        default_severity = field_mapping.get("default_severity", "medium")
        default_confidence = field_mapping.get("default_confidence", 70)
        skip_header = field_mapping.get("skip_header", True)

        reader = csv.reader(io.StringIO(content))
        for i, row in enumerate(reader):
            if skip_header and i == 0:
                continue
            if not row:
                continue

            try:
                value = row[value_col] if isinstance(value_col, int) else row[int(value_col)]
                value = value.strip()
                if not value:
                    continue

                ind_type = default_type
                if type_col is not None:
                    ind_type = row[int(type_col)].lower().strip()

                # Map type string to enum
                type_mapping = {
                    "ip": IndicatorType.IP,
                    "domain": IndicatorType.DOMAIN,
                    "url": IndicatorType.URL,
                    "md5": IndicatorType.HASH_MD5,
                    "sha1": IndicatorType.HASH_SHA1,
                    "sha256": IndicatorType.HASH_SHA256,
                    "email": IndicatorType.EMAIL,
                    "cidr": IndicatorType.CIDR,
                }
                ind_type_enum = type_mapping.get(ind_type, IndicatorType.DOMAIN)

                severity = default_severity
                if severity_col is not None:
                    severity = row[int(severity_col)].lower().strip() or default_severity

                confidence = default_confidence
                if confidence_col is not None:
                    try:
                        confidence = int(row[int(confidence_col)])
                    except (ValueError, IndexError):
                        pass

                description = None
                if description_col is not None:
                    try:
                        description = row[int(description_col)]
                    except IndexError:
                        pass

                indicators.append({
                    "indicator_type": ind_type_enum,
                    "value": value,
                    "severity": severity,
                    "confidence": confidence,
                    "description": description,
                })

            except (IndexError, ValueError) as e:
                logger.warning(f"Failed to parse CSV row {i}: {e}")
                continue

        return indicators

    def _parse_json(
        self,
        content: str,
        field_mapping: Dict[str, Any],
    ) -> List[Dict[str, Any]]:
        """Parse JSON format threat intelligence."""
        import json

        indicators = []

        try:
            data = json.loads(content)
        except json.JSONDecodeError as e:
            logger.error(f"Failed to parse JSON: {e}")
            return indicators

        # Get the array path (e.g., "data.indicators")
        array_path = field_mapping.get("array_path", "")
        if array_path:
            for key in array_path.split("."):
                if isinstance(data, dict) and key in data:
                    data = data[key]
                else:
                    data = []
                    break

        if not isinstance(data, list):
            data = [data]

        value_field = field_mapping.get("value_field", "value")
        type_field = field_mapping.get("type_field", "type")
        severity_field = field_mapping.get("severity_field", "severity")
        confidence_field = field_mapping.get("confidence_field", "confidence")
        description_field = field_mapping.get("description_field", "description")
        default_type = field_mapping.get("default_type", "domain")
        default_severity = field_mapping.get("default_severity", "medium")
        default_confidence = field_mapping.get("default_confidence", 70)

        type_mapping = {
            "ip": IndicatorType.IP,
            "domain": IndicatorType.DOMAIN,
            "url": IndicatorType.URL,
            "md5": IndicatorType.HASH_MD5,
            "sha1": IndicatorType.HASH_SHA1,
            "sha256": IndicatorType.HASH_SHA256,
            "email": IndicatorType.EMAIL,
            "cidr": IndicatorType.CIDR,
        }

        for item in data:
            if not isinstance(item, dict):
                continue

            value = item.get(value_field, "")
            if not value:
                continue

            ind_type = item.get(type_field, default_type)
            if isinstance(ind_type, str):
                ind_type = type_mapping.get(ind_type.lower(), IndicatorType.DOMAIN)

            indicators.append({
                "indicator_type": ind_type,
                "value": str(value).strip(),
                "severity": item.get(severity_field, default_severity),
                "confidence": item.get(confidence_field, default_confidence),
                "description": item.get(description_field),
            })

        return indicators

    async def _update_indicators(
        self,
        feed: ThreatIntelFeed,
        indicators: List[Dict[str, Any]],
    ) -> tuple[int, int]:
        """Update indicators in the database."""
        added = 0
        updated = 0
        now = datetime.now(timezone.utc)

        # Get existing indicators for this feed
        result = await self.session.execute(
            select(ThreatIndicator).where(ThreatIndicator.feed_id == feed.id)
        )
        existing = {ind.value: ind for ind in result.scalars().all()}

        # Track which values we've seen
        seen_values = set()

        for ind_data in indicators:
            value = ind_data["value"]
            seen_values.add(value)

            if value in existing:
                # Update existing
                indicator = existing[value]
                indicator.indicator_type = ind_data["indicator_type"]
                indicator.severity = ind_data.get("severity", "medium")
                indicator.confidence = ind_data.get("confidence", 70)
                indicator.description = ind_data.get("description")
                indicator.last_seen_at = now
                updated += 1
            else:
                # Create new
                indicator = ThreatIndicator(
                    feed_id=feed.id,
                    indicator_type=ind_data["indicator_type"],
                    value=value,
                    severity=ind_data.get("severity", "medium"),
                    confidence=ind_data.get("confidence", 70),
                    description=ind_data.get("description"),
                    first_seen_at=now,
                    last_seen_at=now,
                )
                self.session.add(indicator)
                added += 1

        # Remove indicators not in the latest feed
        for value, indicator in existing.items():
            if value not in seen_values:
                await self.session.delete(indicator)

        await self.session.commit()
        return added, updated

    async def _count_feed_indicators(self, feed_id: UUID) -> int:
        """Count indicators for a feed."""
        result = await self.session.execute(
            select(func.count()).where(ThreatIndicator.feed_id == feed_id)
        )
        return result.scalar() or 0

    # --- Indicator Lookup ---

    async def check_indicator(
        self,
        value: str,
        indicator_type: Optional[IndicatorType] = None,
    ) -> List[ThreatIndicator]:
        """Check if a value matches any known indicators."""
        from sqlalchemy.orm import selectinload

        query = select(ThreatIndicator).where(ThreatIndicator.value == value)

        if indicator_type:
            query = query.where(ThreatIndicator.indicator_type == indicator_type)

        # Load the feed relationship
        query = query.options(selectinload(ThreatIndicator.feed))

        result = await self.session.execute(query)
        indicators = list(result.scalars().all())

        # Record hits
        now = datetime.now(timezone.utc)
        for indicator in indicators:
            indicator.hit_count += 1
            indicator.last_hit_at = now
        if indicators:
            await self.session.commit()

        return indicators

    async def search_indicators(
        self,
        value_contains: Optional[str] = None,
        indicator_type: Optional[IndicatorType] = None,
        severity: Optional[str] = None,
        feed_id: Optional[UUID] = None,
        limit: int = 50,
        offset: int = 0,
    ) -> tuple[list[ThreatIndicator], int]:
        """Search indicators with filtering."""
        from sqlalchemy.orm import selectinload

        stmt = select(ThreatIndicator)

        if value_contains:
            stmt = stmt.where(ThreatIndicator.value.ilike(f"%{value_contains}%"))
        if indicator_type:
            stmt = stmt.where(ThreatIndicator.indicator_type == indicator_type)
        if severity:
            stmt = stmt.where(ThreatIndicator.severity == severity)
        if feed_id:
            stmt = stmt.where(ThreatIndicator.feed_id == feed_id)

        # Count total
        count_query = select(func.count()).select_from(stmt.subquery())
        total_result = await self.session.execute(count_query)
        total = total_result.scalar() or 0

        # Paginate and load feed relationship
        stmt = stmt.options(selectinload(ThreatIndicator.feed))
        stmt = stmt.offset(offset).limit(limit).order_by(ThreatIndicator.value)
        result = await self.session.execute(stmt)
        indicators = list(result.scalars().all())

        return indicators, total

    async def record_hit(self, indicator_id: UUID) -> None:
        """Record a hit on an indicator."""
        result = await self.session.execute(
            select(ThreatIndicator).where(ThreatIndicator.id == indicator_id)
        )
        indicator = result.scalar_one_or_none()
        if indicator:
            indicator.hit_count += 1
            indicator.last_hit_at = datetime.now(timezone.utc)
            await self.session.commit()

    # --- Statistics ---

    async def get_stats(self) -> Dict[str, Any]:
        """Get threat intelligence statistics."""
        # Feed counts
        feeds_result = await self.session.execute(
            select(func.count()).select_from(ThreatIntelFeed)
        )
        total_feeds = feeds_result.scalar() or 0

        enabled_feeds_result = await self.session.execute(
            select(func.count()).where(ThreatIntelFeed.enabled == True)
        )
        enabled_feeds = enabled_feeds_result.scalar() or 0

        # Indicator counts
        indicators_result = await self.session.execute(
            select(func.count()).select_from(ThreatIndicator)
        )
        total_indicators = indicators_result.scalar() or 0

        # Count by type
        type_counts = {}
        for ind_type in IndicatorType:
            count_result = await self.session.execute(
                select(func.count()).where(ThreatIndicator.indicator_type == ind_type)
            )
            type_counts[ind_type.value] = count_result.scalar() or 0

        # Count by severity
        severity_counts = {}
        for severity in ["low", "medium", "high", "critical"]:
            count_result = await self.session.execute(
                select(func.count()).where(ThreatIndicator.severity == severity)
            )
            severity_counts[severity] = count_result.scalar() or 0

        # Recent hits (total hit count)
        recent_hits_result = await self.session.execute(
            select(func.sum(ThreatIndicator.hit_count))
        )
        recent_hits = recent_hits_result.scalar() or 0

        return {
            "total_feeds": total_feeds,
            "enabled_feeds": enabled_feeds,
            "total_indicators": total_indicators,
            "indicators_by_type": type_counts,
            "indicators_by_severity": severity_counts,
            "recent_hits": recent_hits,
        }
