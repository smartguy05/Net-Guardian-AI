"""Security pattern service for managing patterns and detecting attacks in logs."""

import json
import re
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any
from uuid import UUID

import httpx
import structlog
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from app.models.alert import AlertSeverity
from app.models.security_pattern import (
    PatternCategory,
    PatternSource,
    PatternType,
    SecurityPattern,
    SecurityPatternFeed,
)

logger = structlog.get_logger()


@dataclass
class PatternMatch:
    """Result of a pattern match."""

    pattern_id: UUID
    pattern_name: str
    category: PatternCategory
    severity: AlertSeverity
    matched_text: str
    match_start: int
    match_end: int
    context: dict[str, Any]


class SecurityPatternService:
    """Service for managing security patterns and detecting attacks."""

    def __init__(self, session: AsyncSession):
        self.session = session
        self._compiled_patterns: dict[UUID, re.Pattern[str]] = {}

    # --- Pattern Management ---

    async def get_patterns(
        self,
        enabled: bool | None = None,
        category: PatternCategory | None = None,
        source: PatternSource | None = None,
        feed_id: UUID | None = None,
        tags: list[str] | None = None,
        limit: int = 50,
        offset: int = 0,
    ) -> tuple[list[SecurityPattern], int]:
        """Get security patterns with filtering."""
        query = select(SecurityPattern)

        if enabled is not None:
            query = query.where(SecurityPattern.enabled == enabled)
        if category:
            query = query.where(SecurityPattern.category == category)
        if source:
            query = query.where(SecurityPattern.source == source)
        if feed_id:
            query = query.where(SecurityPattern.feed_id == feed_id)
        if tags:
            # Check if pattern has any of the specified tags
            for tag in tags:
                query = query.where(SecurityPattern.tags.contains([tag]))

        # Count total
        count_query = select(func.count()).select_from(query.subquery())
        total_result = await self.session.execute(count_query)
        total = total_result.scalar() or 0

        # Paginate
        query = query.offset(offset).limit(limit).order_by(SecurityPattern.name)
        result = await self.session.execute(query)
        patterns = list(result.scalars().all())

        return patterns, total

    async def get_pattern(self, pattern_id: UUID) -> SecurityPattern | None:
        """Get a specific pattern by ID."""
        result = await self.session.execute(
            select(SecurityPattern)
            .where(SecurityPattern.id == pattern_id)
            .options(selectinload(SecurityPattern.feed))
        )
        return result.scalar_one_or_none()

    async def create_pattern(
        self,
        name: str,
        category: PatternCategory,
        pattern_type: PatternType,
        pattern: str,
        description: str | None = None,
        severity: AlertSeverity = AlertSeverity.MEDIUM,
        enabled: bool = True,
        tags: list[str] | None = None,
        extra_data: dict[str, Any] | None = None,
        source: PatternSource = PatternSource.USER,
        feed_id: UUID | None = None,
        examples: list[str] | None = None,
        references: list[str] | None = None,
    ) -> SecurityPattern:
        """Create a new security pattern."""
        # Validate regex if pattern_type is regex
        if pattern_type == PatternType.REGEX:
            try:
                re.compile(pattern)
            except re.error as e:
                raise ValueError(f"Invalid regex pattern: {e}") from e

        security_pattern = SecurityPattern(
            name=name,
            description=description,
            category=category,
            pattern_type=pattern_type,
            pattern=pattern,
            severity=severity,
            enabled=enabled,
            tags=tags or [],
            extra_data=extra_data or {},
            source=source,
            feed_id=feed_id,
            examples=examples or [],
            references=references or [],
        )
        self.session.add(security_pattern)
        await self.session.commit()
        await self.session.refresh(security_pattern)
        return security_pattern

    async def update_pattern(
        self,
        pattern_id: UUID,
        **updates: Any,
    ) -> SecurityPattern | None:
        """Update a pattern's configuration."""
        pattern = await self.get_pattern(pattern_id)
        if not pattern:
            return None

        # Don't allow modifying builtin patterns' core fields
        if pattern.source == PatternSource.BUILTIN:
            restricted_fields = {"pattern", "pattern_type", "category", "name"}
            for field in restricted_fields:
                if field in updates:
                    del updates[field]

        # Validate regex if updating pattern with regex type
        if "pattern" in updates and pattern.pattern_type == PatternType.REGEX:
            try:
                re.compile(updates["pattern"])
            except re.error as e:
                raise ValueError(f"Invalid regex pattern: {e}") from e

        for key, value in updates.items():
            if hasattr(pattern, key) and value is not None:
                setattr(pattern, key, value)

        # Clear compiled pattern cache if pattern changed
        if "pattern" in updates and pattern.id in self._compiled_patterns:
            del self._compiled_patterns[pattern.id]

        await self.session.commit()
        await self.session.refresh(pattern)
        return pattern

    async def delete_pattern(self, pattern_id: UUID) -> bool:
        """Delete a pattern (not allowed for builtin patterns)."""
        pattern = await self.get_pattern(pattern_id)
        if not pattern:
            return False

        if pattern.source == PatternSource.BUILTIN:
            raise ValueError("Cannot delete builtin patterns. Disable instead.")

        # Clear from cache
        if pattern.id in self._compiled_patterns:
            del self._compiled_patterns[pattern.id]

        await self.session.delete(pattern)
        await self.session.commit()
        return True

    # --- Feed Management ---

    async def get_feeds(
        self,
        enabled: bool | None = None,
        limit: int = 50,
        offset: int = 0,
    ) -> tuple[list[SecurityPatternFeed], int]:
        """Get all pattern feeds."""
        query = select(SecurityPatternFeed)

        if enabled is not None:
            query = query.where(SecurityPatternFeed.enabled == enabled)

        # Count total
        count_query = select(func.count()).select_from(query.subquery())
        total_result = await self.session.execute(count_query)
        total = total_result.scalar() or 0

        # Paginate
        query = query.offset(offset).limit(limit).order_by(SecurityPatternFeed.name)
        result = await self.session.execute(query)
        feeds = list(result.scalars().all())

        return feeds, total

    async def get_feed(self, feed_id: UUID) -> SecurityPatternFeed | None:
        """Get a specific feed by ID."""
        result = await self.session.execute(
            select(SecurityPatternFeed).where(SecurityPatternFeed.id == feed_id)
        )
        return result.scalar_one_or_none()

    async def create_feed(
        self,
        name: str,
        url: str,
        description: str | None = None,
        enabled: bool = True,
        update_interval_hours: int = 24,
        auth_type: str = "none",
        auth_config: dict[str, Any] | None = None,
        field_mapping: dict[str, Any] | None = None,
    ) -> SecurityPatternFeed:
        """Create a new pattern feed."""
        feed = SecurityPatternFeed(
            name=name,
            url=url,
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
    ) -> SecurityPatternFeed | None:
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
        """Delete a feed and all its patterns."""
        feed = await self.get_feed(feed_id)
        if not feed:
            return False

        await self.session.delete(feed)
        await self.session.commit()
        return True

    # --- Feed Fetching ---

    async def fetch_feed(self, feed_id: UUID) -> dict[str, Any]:
        """Fetch and parse patterns from a feed."""
        feed = await self.get_feed(feed_id)
        if not feed:
            return {"success": False, "error": "Feed not found"}

        try:
            # Build headers for authentication
            headers: dict[str, str] = {}
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

            # Parse the feed content
            patterns = self._parse_feed_content(feed, content)

            # Update patterns in database
            added, updated = await self._update_feed_patterns(feed, patterns)

            # Update feed status
            feed.last_fetch_at = datetime.now(UTC)
            feed.last_fetch_status = "success"
            feed.last_fetch_message = f"Added {added}, updated {updated} patterns"
            feed.pattern_count = await self._count_feed_patterns(feed.id)
            await self.session.commit()

            logger.info(
                "Pattern feed fetched successfully",
                feed_id=str(feed.id),
                feed_name=feed.name,
                added=added,
                updated=updated,
            )

            return {
                "success": True,
                "added": added,
                "updated": updated,
                "total": feed.pattern_count,
            }

        except Exception as e:
            try:
                await self.session.rollback()
                feed.last_fetch_at = datetime.now(UTC)
                feed.last_fetch_status = "error"
                feed.last_fetch_message = str(e)[:500]
                await self.session.commit()
            except Exception:
                pass

            logger.error(
                "Pattern feed fetch failed",
                feed_id=str(feed.id),
                feed_name=feed.name,
                error=str(e),
            )

            return {"success": False, "error": str(e)}

    def _parse_feed_content(
        self,
        feed: SecurityPatternFeed,
        content: str,
    ) -> list[dict[str, Any]]:
        """Parse feed content into pattern dictionaries."""
        patterns: list[dict[str, Any]] = []

        try:
            data = json.loads(content)
        except json.JSONDecodeError as e:
            logger.error(f"Failed to parse feed JSON: {e}")
            return patterns

        # Get field mapping
        mapping = feed.field_mapping
        patterns_path = mapping.get("patterns_path", "patterns")

        # Navigate to patterns array
        if patterns_path:
            for key in patterns_path.split("."):
                if isinstance(data, dict) and key in data:
                    data = data[key]
                else:
                    data = []
                    break

        if not isinstance(data, list):
            data = [data]

        # Map fields
        id_field = mapping.get("id", "id")
        name_field = mapping.get("name", "name")
        description_field = mapping.get("description", "description")
        category_field = mapping.get("category", "category")
        pattern_type_field = mapping.get("pattern_type", "pattern_type")
        pattern_field = mapping.get("pattern", "pattern")
        severity_field = mapping.get("severity", "severity")
        tags_field = mapping.get("tags", "tags")
        examples_field = mapping.get("examples", "examples")
        references_field = mapping.get("references", "references")

        # Category mapping
        category_map = {
            "sql_injection": PatternCategory.SQL_INJECTION,
            "sqli": PatternCategory.SQL_INJECTION,
            "command_injection": PatternCategory.COMMAND_INJECTION,
            "rce": PatternCategory.COMMAND_INJECTION,
            "path_traversal": PatternCategory.PATH_TRAVERSAL,
            "lfi": PatternCategory.PATH_TRAVERSAL,
            "xss": PatternCategory.XSS,
            "deserialization": PatternCategory.DESERIALIZATION,
            "ssrf": PatternCategory.SSRF,
            "auth_bypass": PatternCategory.AUTH_BYPASS,
            "log_injection": PatternCategory.LOG_INJECTION,
            "ldap_injection": PatternCategory.LDAP_INJECTION,
            "xxe": PatternCategory.XXE,
            "custom": PatternCategory.CUSTOM,
        }

        # Severity mapping
        severity_map = {
            "info": AlertSeverity.INFO,
            "low": AlertSeverity.LOW,
            "medium": AlertSeverity.MEDIUM,
            "high": AlertSeverity.HIGH,
            "critical": AlertSeverity.CRITICAL,
        }

        for item in data:
            if not isinstance(item, dict):
                continue

            name = item.get(name_field)
            pattern = item.get(pattern_field)
            if not name or not pattern:
                continue

            # Parse category
            cat_str = item.get(category_field, "custom")
            category = category_map.get(cat_str.lower(), PatternCategory.CUSTOM)

            # Parse severity
            sev_str = item.get(severity_field, "medium")
            severity = severity_map.get(sev_str.lower(), AlertSeverity.MEDIUM)

            # Parse pattern type
            ptype_str = item.get(pattern_type_field, "regex")
            pattern_type = PatternType.REGEX
            if ptype_str.lower() == "literal":
                pattern_type = PatternType.LITERAL
            elif ptype_str.lower() == "keyword":
                pattern_type = PatternType.KEYWORD

            patterns.append(
                {
                    "source_id": item.get(id_field),
                    "name": name,
                    "description": item.get(description_field),
                    "category": category,
                    "pattern_type": pattern_type,
                    "pattern": pattern,
                    "severity": severity,
                    "tags": item.get(tags_field, []),
                    "examples": item.get(examples_field, []),
                    "references": item.get(references_field, []),
                }
            )

        return patterns

    async def _update_feed_patterns(
        self,
        feed: SecurityPatternFeed,
        patterns: list[dict[str, Any]],
    ) -> tuple[int, int]:
        """Update patterns in the database from feed."""
        added = 0
        updated = 0

        # Get existing patterns for this feed
        result = await self.session.execute(
            select(SecurityPattern).where(SecurityPattern.feed_id == feed.id)
        )
        existing = {p.name: p for p in result.scalars().all()}

        seen_names: set[str] = set()

        for pat_data in patterns:
            name = pat_data["name"]
            seen_names.add(name)

            if name in existing:
                # Update existing
                pattern = existing[name]
                pattern.description = pat_data.get("description")
                pattern.category = pat_data["category"]
                pattern.pattern_type = pat_data["pattern_type"]
                pattern.pattern = pat_data["pattern"]
                pattern.severity = pat_data["severity"]
                pattern.tags = pat_data.get("tags", [])
                pattern.examples = pat_data.get("examples", [])
                pattern.references = pat_data.get("references", [])
                updated += 1

                # Clear compiled cache
                if pattern.id in self._compiled_patterns:
                    del self._compiled_patterns[pattern.id]
            else:
                # Create new
                pattern = SecurityPattern(
                    name=name,
                    description=pat_data.get("description"),
                    category=pat_data["category"],
                    pattern_type=pat_data["pattern_type"],
                    pattern=pat_data["pattern"],
                    severity=pat_data["severity"],
                    enabled=True,
                    tags=pat_data.get("tags", []),
                    extra_data={},
                    source=PatternSource.FEED,
                    feed_id=feed.id,
                    examples=pat_data.get("examples", []),
                    references=pat_data.get("references", []),
                )
                self.session.add(pattern)
                added += 1

        # Remove patterns not in the latest feed
        for name, pattern in existing.items():
            if name not in seen_names:
                if pattern.id in self._compiled_patterns:
                    del self._compiled_patterns[pattern.id]
                await self.session.delete(pattern)

        await self.session.commit()
        return added, updated

    async def _count_feed_patterns(self, feed_id: UUID) -> int:
        """Count patterns for a feed."""
        result = await self.session.execute(
            select(func.count()).where(SecurityPattern.feed_id == feed_id)
        )
        return result.scalar() or 0

    # --- Pattern Matching ---

    async def match_text(
        self,
        text: str,
        categories: list[PatternCategory] | None = None,
    ) -> list[PatternMatch]:
        """Check text against all enabled patterns."""
        matches: list[PatternMatch] = []

        # Get enabled patterns
        query = select(SecurityPattern).where(SecurityPattern.enabled.is_(True))
        if categories:
            query = query.where(SecurityPattern.category.in_(categories))

        result = await self.session.execute(query)
        patterns = list(result.scalars().all())

        # Match each pattern
        for pattern in patterns:
            pattern_matches = self._match_pattern(pattern, text)
            matches.extend(pattern_matches)

            # Record hit if matched
            if pattern_matches:
                pattern.hit_count += len(pattern_matches)
                pattern.last_hit_at = datetime.now(UTC)

        if matches:
            await self.session.commit()

        return matches

    def _match_pattern(
        self,
        pattern: SecurityPattern,
        text: str,
    ) -> list[PatternMatch]:
        """Match a single pattern against text."""
        matches: list[PatternMatch] = []

        try:
            if pattern.pattern_type == PatternType.REGEX:
                # Compile and cache regex
                if pattern.id not in self._compiled_patterns:
                    self._compiled_patterns[pattern.id] = re.compile(
                        pattern.pattern, re.IGNORECASE | re.MULTILINE
                    )
                regex = self._compiled_patterns[pattern.id]

                for match in regex.finditer(text):
                    matches.append(
                        PatternMatch(
                            pattern_id=pattern.id,
                            pattern_name=pattern.name,
                            category=pattern.category,
                            severity=pattern.severity,
                            matched_text=match.group(),
                            match_start=match.start(),
                            match_end=match.end(),
                            context={"groups": match.groups()},
                        )
                    )

            elif pattern.pattern_type == PatternType.LITERAL:
                # Exact string match (case-insensitive)
                lower_text = text.lower()
                lower_pattern = pattern.pattern.lower()
                start = 0
                while True:
                    pos = lower_text.find(lower_pattern, start)
                    if pos == -1:
                        break
                    matches.append(
                        PatternMatch(
                            pattern_id=pattern.id,
                            pattern_name=pattern.name,
                            category=pattern.category,
                            severity=pattern.severity,
                            matched_text=text[pos : pos + len(pattern.pattern)],
                            match_start=pos,
                            match_end=pos + len(pattern.pattern),
                            context={},
                        )
                    )
                    start = pos + 1

            elif pattern.pattern_type == PatternType.KEYWORD:
                # Keyword/substring match (case-insensitive)
                keywords = [kw.strip() for kw in pattern.pattern.split(",")]
                lower_text = text.lower()
                for keyword in keywords:
                    lower_kw = keyword.lower()
                    start = 0
                    while True:
                        pos = lower_text.find(lower_kw, start)
                        if pos == -1:
                            break
                        matches.append(
                            PatternMatch(
                                pattern_id=pattern.id,
                                pattern_name=pattern.name,
                                category=pattern.category,
                                severity=pattern.severity,
                                matched_text=text[pos : pos + len(keyword)],
                                match_start=pos,
                                match_end=pos + len(keyword),
                                context={"keyword": keyword},
                            )
                        )
                        start = pos + 1

        except Exception as e:
            logger.warning(
                "Pattern matching failed",
                pattern_id=str(pattern.id),
                pattern_name=pattern.name,
                error=str(e),
            )

        return matches

    async def test_pattern(
        self,
        pattern_type: PatternType,
        pattern: str,
        test_text: str,
    ) -> dict[str, Any]:
        """Test a pattern against sample text without saving."""
        try:
            if pattern_type == PatternType.REGEX:
                try:
                    regex = re.compile(pattern, re.IGNORECASE | re.MULTILINE)
                except re.error as e:
                    return {
                        "success": False,
                        "error": f"Invalid regex: {e}",
                        "matches": [],
                    }

                matches = []
                for match in regex.finditer(test_text):
                    matches.append(
                        {
                            "matched_text": match.group(),
                            "start": match.start(),
                            "end": match.end(),
                            "groups": match.groups(),
                        }
                    )

                return {
                    "success": True,
                    "matches": matches,
                    "match_count": len(matches),
                }

            elif pattern_type == PatternType.LITERAL:
                matches = []
                lower_text = test_text.lower()
                lower_pattern = pattern.lower()
                start = 0
                while True:
                    pos = lower_text.find(lower_pattern, start)
                    if pos == -1:
                        break
                    matches.append(
                        {
                            "matched_text": test_text[pos : pos + len(pattern)],
                            "start": pos,
                            "end": pos + len(pattern),
                        }
                    )
                    start = pos + 1

                return {
                    "success": True,
                    "matches": matches,
                    "match_count": len(matches),
                }

            elif pattern_type == PatternType.KEYWORD:
                matches = []
                keywords = [kw.strip() for kw in pattern.split(",")]
                lower_text = test_text.lower()
                for keyword in keywords:
                    lower_kw = keyword.lower()
                    start = 0
                    while True:
                        pos = lower_text.find(lower_kw, start)
                        if pos == -1:
                            break
                        matches.append(
                            {
                                "matched_text": test_text[pos : pos + len(keyword)],
                                "start": pos,
                                "end": pos + len(keyword),
                                "keyword": keyword,
                            }
                        )
                        start = pos + 1

                return {
                    "success": True,
                    "matches": matches,
                    "match_count": len(matches),
                }

            return {"success": False, "error": "Unknown pattern type", "matches": []}

        except Exception as e:
            return {"success": False, "error": str(e), "matches": []}

    # --- Statistics ---

    async def get_stats(self) -> dict[str, Any]:
        """Get security pattern statistics."""
        # Pattern counts
        patterns_result = await self.session.execute(
            select(func.count()).select_from(SecurityPattern)
        )
        total_patterns = patterns_result.scalar() or 0

        enabled_result = await self.session.execute(
            select(func.count()).where(SecurityPattern.enabled.is_(True))
        )
        enabled_patterns = enabled_result.scalar() or 0

        # Feed counts
        feeds_result = await self.session.execute(
            select(func.count()).select_from(SecurityPatternFeed)
        )
        total_feeds = feeds_result.scalar() or 0

        enabled_feeds_result = await self.session.execute(
            select(func.count()).where(SecurityPatternFeed.enabled.is_(True))
        )
        enabled_feeds = enabled_feeds_result.scalar() or 0

        # Count by category
        category_counts = {}
        for category in PatternCategory:
            count_result = await self.session.execute(
                select(func.count()).where(SecurityPattern.category == category)
            )
            category_counts[category.value] = count_result.scalar() or 0

        # Count by source
        source_counts = {}
        for source in PatternSource:
            count_result = await self.session.execute(
                select(func.count()).where(SecurityPattern.source == source)
            )
            source_counts[source.value] = count_result.scalar() or 0

        # Total hits
        hits_result = await self.session.execute(select(func.sum(SecurityPattern.hit_count)))
        total_hits = hits_result.scalar() or 0

        return {
            "total_patterns": total_patterns,
            "enabled_patterns": enabled_patterns,
            "total_feeds": total_feeds,
            "enabled_feeds": enabled_feeds,
            "patterns_by_category": category_counts,
            "patterns_by_source": source_counts,
            "total_hits": total_hits,
        }

    async def get_patterns_for_category(
        self,
        category: PatternCategory,
    ) -> list[SecurityPattern]:
        """Get all enabled patterns for a specific category."""
        result = await self.session.execute(
            select(SecurityPattern).where(
                SecurityPattern.category == category,
                SecurityPattern.enabled.is_(True),
            )
        )
        return list(result.scalars().all())
