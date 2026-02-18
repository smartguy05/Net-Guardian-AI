# NetGuardian AI - Completed Tasks

Condensed summary of completed implementation work.

---

## AI Chat Log Query Pipeline (February 2026)

**Feature**: When users ask the AI chat questions about network logs (e.g., "What DNS queries did my Ring camera make?"), the system now extracts query parameters from the message, fetches matching events from the database, and injects them into the LLM context so answers are grounded in real data.

**New Files**:
- `backend/app/services/log_query_service.py`: Core service with `LogQueryParameters` and `LogQueryResult` dataclasses, `LogQueryService` class with LLM-based parameter extraction (Haiku), regex heuristic fallback, device resolution, event querying, and compact markdown formatting
- `backend/tests/services/test_log_query_service.py`: 65 tests covering heuristic extraction (23), device resolution (9), event querying (9), formatting (3), details extraction (5), query description (9), LLM extraction (5), dataclasses (2)

**Modified Files**:
- `backend/app/models/chat_intent.py`: Added `log_query_result` field to `ChatContext` dataclass
- `backend/app/services/chat_context_service.py`: Added `log_query_result` parameter to `build_context()`, appends formatted log data to LOG_ANALYSIS context, added "Log Data Instructions" to LOG_ANALYSIS system prompt
- `backend/app/api/v1/chat.py`: Wired `LogQueryService` into both `query_network()` and `chat()` endpoints for LOG_ANALYSIS intent, passes conversation context for follow-up questions

**Key Design Decisions**:
- 50-event limit (~2K-4K tokens) fits within context limits alongside network summary
- Heuristic fallback ensures feature works even if Haiku extraction fails
- Non-fatal errors: log query failures don't break chat, LLM still gets network summary
- Compact markdown table with abbreviated timestamps and type-specific details column
- Conversation context passed for follow-up questions like "were any of those blocked?"

---

## Application Log Analysis (February 2026)

**Implemented application log analysis for Docker containers, systemd services, and application-specific logs (Java/Python) with configurable security pattern detection.**

### Phase 1: Data Model Extensions
- Added `CONTAINER`, `JOURNAL`, `APPLICATION` to `EventType` enum
- Added `DOCKER`, `JOURNALD`, `JAVA_STACKTRACE`, `PYTHON_LOG` to `ParserType` enum
- Added `ERROR_SPIKE`, `NEW_ERROR_PATTERN`, `CONTAINER_RESTART`, `SECURITY_PATTERN` to `AnomalyType` enum
- Migration: `20260202_0015_015_add_app_log_enums.py`

### Phase 2: Security Pattern Management System
**New Files:**
- `backend/app/models/security_pattern.py`: SecurityPattern, SecurityPatternFeed models with PatternCategory, PatternType, PatternSource enums
- `backend/app/api/v1/security_patterns.py`: Full CRUD API for patterns and feeds (list, get, create, update, delete, enable/disable, test, match, fetch)
- `backend/app/services/security_pattern_service.py`: Pattern matching with regex caching, feed fetching with auth support
- `backend/app/parsers/security_patterns.py`: Parser integration wrapper
- `backend/app/data/default_security_patterns.py`: 28+ built-in patterns (SQL injection, command injection, XSS, path traversal, deserialization, SSRF, etc.)
- `docs/security-pattern-feeds.md`: Feed format documentation with field mapping examples
- Migration: `20260202_0016_016_add_security_patterns.py`

### Phase 3: New Parsers
- `backend/app/parsers/docker_parser.py`: Docker JSON log parsing, container events (start/stop/restart/oom_killed), error detection
- `backend/app/parsers/journald_parser.py`: systemd journal JSON parsing, priority mapping, service state detection
- `backend/app/parsers/java_stacktrace_parser.py`: Multi-line stack trace parsing, exception chain extraction, security exception detection
- `backend/app/parsers/python_log_parser.py`: Python logging/traceback parsing, structlog JSON support

### Phase 4: Agent Collectors
- `agent/collectors/docker_collector.py`: Docker/Podman socket connection, container log streaming, lifecycle events
- `agent/collectors/journal_collector.py`: systemd journal reading (library + journalctl fallback), cursor-based resumption

### Phase 5: Analysis Services
- `backend/app/services/app_baseline_service.py`: Application baselines (error rate, container metrics, exception types)
- `backend/app/services/security_analysis_service.py`: Security pattern analysis, finding correlation, attack detection
- Extended `backend/app/services/anomaly_service.py` with `detect_application_anomalies()` method

### Phase 6: Default Rules & Frontend
- `backend/app/data/default_app_rules.py`: 19 pre-built detection rules (SQL injection, command injection, error spikes, container restart loops, OOM errors, Java/Python specific)
- `frontend/src/pages/SecurityPatternsPage.tsx`: Pattern management with filters, pattern testing, text matching
- `frontend/src/types/index.ts`: SecurityPattern, SecurityPatternFeed, PatternMatch types
- `frontend/src/api/hooks.ts`: 15+ hooks for security patterns and feeds CRUD
- Added route in `frontend/src/App.tsx` and navigation in `frontend/src/components/Layout.tsx`

### Documentation Updates
- `README.md`: Updated parser count (11→15), added new parser types to table
- `docs/user-guide.md`: Added CONTAINER/JOURNAL/APPLICATION event types, new anomaly types, Docker/Journald sources, Security Patterns section
- `docs/configuration.md`: Added Docker, Journald, Java Stacktrace, Python Log parser configurations, Security Pattern Detection section
- `docs/deployment-guide.md`: Added Docker, Journald, Java, Python source examples, security pattern feed import instructions
- `frontend/src/content/helpContent.ts`: Added `/dashboard/security-patterns` help content (5 sections)
- `frontend/src/pages/DocsPage.tsx`: Added Security Patterns section with 4 subsections, updated parser list with new parsers

---

## Phase 9: Semantic Log Analysis (January 2026)

**Database**: 6 tables (LogPattern, SemanticAnalysisConfig, IrregularLog, SemanticAnalysisRun, SuggestedRule, SuggestedRuleHistory) with 4 enums - `backend/app/models/semantic_analysis.py`

**Services**:
- `pattern_normalizer.py`: Regex normalization (IPs, timestamps, UUIDs, emails, URLs, paths, hex, numbers)
- `pattern_service.py`: Pattern CRUD, UPSERT, rarity detection
- `semantic_analysis_service.py`: Real-time pattern recording, batch LLM analysis, irregularity detection
- `rule_suggestion_service.py`: Hash-based deduplication, rule approval/rejection tracking

**LLM Providers** (`backend/app/services/llm_providers/`):
- `base.py`: BaseLLMProvider ABC, LLMAnalysisResult dataclass
- `claude_provider.py`: Anthropic API with prompt caching
- `ollama_provider.py`: Local Ollama via httpx
- `factory.py`: Provider instantiation

**API**: `backend/app/api/v1/semantic.py` - Config, patterns, irregular logs, analysis runs, suggested rules endpoints

**Frontend**: SemanticReviewPage, PatternsPage, SuggestedRulesPage with expandable rows, AI research queries

**Scheduler**: `semantic_scheduler.py` for periodic batch analysis, integrated in main.py

---

## Phase 8: Landing Page & Help System

- **LandingPage.tsx**: Hero, 8 feature cards, screenshots gallery, architecture diagram, quick start
- **DocsPage.tsx**: 19 documentation sections with sticky navigation
- **Help System**: Zustand store, HelpButton, HelpPanel with `?` keyboard shortcut, context-sensitive content for 14+ pages
- **Routing**: Dashboard under `/dashboard/*`, public landing at `/`

---

## Phase 7: Technical Debt & Testing

**Prometheus Metrics**: `metrics_service.py` - HTTP counters/histograms, WebSocket gauges, event/alert/anomaly metrics

**Test Coverage**: 488 → 934 tests
- Parser tests: AdGuard, syslog, JSON, custom, NetFlow, sFlow, Loki, Authentik, endpoint
- Collector tests: API pull, file watch, UDP listener, error handler, registry
- Service tests: Baseline, anomaly, pattern, semantic analysis, LLM providers, rule suggestion
- API tests: Auth, devices, alerts, rules, users, semantic, OIDC

---

## Phase 6: Feature Enhancements

| Feature | Key Files |
|---------|-----------|
| Dark Mode | Tailwind config, theme store, all pages |
| WebSockets | JWT auth, connection manager, heartbeat, real-time alerts/devices |
| Email Notifications | SMTP service, HTML templates, notification preferences model |
| ntfy.sh Push | HTTP notifications with priority/emoji |
| 2FA (TOTP) | QR generation, backup codes, login flow |
| Data Retention | Configurable days per type, dry-run cleanup |
| CSV/PDF Export | ReportLab, events/alerts/devices/audit exports |
| Device Tagging | Bulk tagging modal, tag filtering, management endpoints |
| Custom Rules UI | Rule builder, condition groups, action config, testing |
| Mobile Responsive | Touch targets, responsive columns, safe areas |
| Threat Intel Feeds | CSV/JSON/STIX feeds, indicator lookup |
| Ollama Monitoring | Threat patterns, risk scoring, background loop |
| Collector Errors | Error categorization, retry config, circuit breaker |
| Rate Limiting | Token bucket, Redis-based, per-endpoint categories |
| CI/CD | GitHub Actions: lint, test, coverage, Docker, security scan |

---

## Phase 5: Extensions & Performance

- **Endpoint Agent**: Standalone Python agent with process/network monitoring
- **NetFlow/sFlow**: v5/v9 parsing, UDP listener, suspicious flow detection
- **Security**: Rate limiting utilities, input validation, startup checks
- **Performance**: DB pool tuning, shared HTTP client, Redis caching decorators

---

## Authentik Integration (January 2026)

**Backend**:
- Config: `backend/app/config.py` (authentik_* settings)
- User model: external_id, external_provider, is_external fields
- Migration: `20260127_0010_010_add_authentik_support.py`
- OIDC Service: `backend/app/services/oidc_service.py` (PKCE, JWKS, token validation)
- Auth endpoints: GET /oidc/config, GET /oidc/authorize, POST /oidc/callback
- Email-based account linking for pre-created local users

**Frontend**:
- Types/hooks for OIDC operations
- LoginPage SSO button with PKCE flow
- OIDCCallbackPage for callback handling

**Parser**: `backend/app/parsers/authentik_parser.py` - action severity mapping, security event detection

---

## Grafana Loki Parser

- `backend/app/parsers/loki_parser.py`: Query API and push API formats, nanosecond timestamps, severity detection
- Migration for LOKI parser type
- Events page Source column and filtering

---

## Synology NAS Syslog Support (January 2026)

- Added `udp_listen` to frontend SourceType and AddSourceModal
- Parser compatibility: syslog, netflow, sflow with udp_listen
- Migration: `20260128_0012_012_add_udp_listen_source_type.py`
- Documentation: user-guide, deployment-guide, configuration.md

---

## Collector Performance Optimizations (January 2026)

`backend/app/services/collector_service.py`:
- **Batch inserts**: BATCH_SIZE=100, BATCH_TIMEOUT=2.0s, single commit per batch
- **Concurrent processing**: MAX_CONCURRENT_BATCHES=3 via asyncio.Semaphore
- **Deferred semantic analysis**: SEMANTIC_QUEUE_SIZE=10000, background worker
- **Device cache**: DeviceCache class with DEVICE_CACHE_TTL=300s

---

## Codebase Lint Fixes (January 2026)

- Auto-fixed 1783 lint errors with ruff (UP006, UP035, UP045 deprecated typing patterns)
- Fixed 29 remaining errors manually:
  - E712: SQLAlchemy boolean comparisons (`== True` → `.is_(True)`)
  - F821: Forward references in models (added TYPE_CHECKING imports)
  - F841: Unused variables (prefixed with `_`)
  - N806: Constant naming in function (`FIELD_TYPES` → `field_types`)
  - N818: Exception naming (`NetGuardianException` → `NetGuardianError` with alias)
- Models updated: alert.py, anomaly.py, device.py, device_baseline.py, raw_event.py
- Services updated: collector_service.py, anomaly_service.py, pattern_service.py, retention_service.py, semantic_analysis_service.py, threat_intel_service.py
- Parsers updated: custom_parser.py, netflow_parser.py, sflow_parser.py
- Device creation race condition fix: `_batch_get_or_create_devices` handles concurrent batches

---

## Key Bug Fixes

- Route ordering: Static routes before dynamic `/{id}` routes in devices.py
- TestRuleModal/EditRuleModal: Legacy conditions validation and auto-conversion
- Dark theme: Modal contrast issues in AddSourceModal, EditUserModal, AddUserModal
- Test suite: Fixed 33 failing tests (parameter names, mock attributes, async patches)

---

## Documentation Updates

- `CLAUDE.md`: Test counts, LLM providers, database layer, all env variables
- `docs/architecture-guide.md`: Full system overview
- `docs/configuration.md`: 80+ env variables documented
- `docs/user-guide.md`: All features documented
- `docs/deployment-guide.md`: Docker, syslog, Authentik setup
- `README.md`: Phase 9 status, AI features, 19 UI pages, source types table

---

## Mypy Type Error Fixes (January 2026)

Fixed 460 mypy strict type check errors across 50+ files:

**Common fix patterns**:
- Added type parameters: `dict[str, Any]`, `list[str]`, `Queue[ParseResult]`, `Match[str]`
- Added return type annotations: `-> None`, `-> dict[str, str]`, `-> Response`
- Fixed SQLAlchemy queries: `True` → `true()` for `.where()` clauses
- Fixed union-attr errors with null checks and type narrowing
- Used `cast()` for json.loads returns
- Added `# type: ignore[override]` for library class overrides
- Fixed model UUID types: `UUID` → `uuid.UUID`
- Renamed query label `count` to avoid collision with tuple method

**Major files fixed**:
- threat_intel.py (67 errors), email_service.py (24), llm_service.py (23)
- retention_service.py (20), http_client.py (19), quarantine_service.py (16)
- rate_limiter.py (15), semantic.py (14), semantic_analysis.py (12)
- All parsers (syslog, netflow, custom, adguard), collectors, API endpoints

---

## Log Source Edit Feature (January 2026)

**Frontend**:
- `EditSourceModal.tsx`: Full edit modal for log sources with source-type-specific config forms
- `SourcesPage.tsx`: Added Edit button to SourceCard, integrated EditSourceModal
- Supports editing: name, description, and configuration (URL, auth, poll interval, file path, UDP port/host)
- Source type and parser type are displayed read-only (cannot be changed after creation)
- Sensitive fields (password, API key, token) show placeholder - leave empty to keep existing value

**Backend**: Already supported via PUT `/api/v1/sources/{source_id}` endpoint

---

## Demo Data

`backend/scripts/seed_demo_data.py`:
- 3 users (admin/operator/viewer)
- 17 devices with varied types/statuses
- 6 log sources (AdGuard, nginx, syslog-nas, NetFlow, sFlow, Loki)
- 380+ events, 6 detection rules, 13 patterns, 6 irregular logs, 5 suggested rules

---

## AdGuard Device Name Sync (January 2026)

**Feature**: Sync device names from AdGuard Home clients to NetGuardian devices

**Backend**:
- `backend/app/services/integrations/adguard.py`:
  - `get_all_clients()`: Fetches both configured and auto-discovered clients
  - `get_device_name_mapping()`: Returns IP/MAC to name mapping with normalized MACs
- `backend/app/services/device_sync_service.py`:
  - `DeviceSyncService.sync_from_adguard()`: Matches AdGuard clients to devices by IP/MAC
  - Supports `overwrite_existing` flag to optionally replace existing hostnames
  - Returns detailed sync results (total, updated, skipped, match details)
- `backend/app/api/v1/devices.py`:
  - POST `/api/v1/devices/sync` endpoint to trigger sync
  - Requires operator role

**Frontend**:
- `frontend/src/types/index.ts`: DeviceSyncRequest and DeviceSyncResponse types
- `frontend/src/api/hooks.ts`: useSyncDevices mutation hook
- `frontend/src/pages/DevicesPage.tsx`: "Sync Names" button with success/error feedback

**Tests**:
- `tests/services/test_device_sync_service.py`: 6 tests for sync service
- `tests/test_phase4_integrations.py`: 4 tests for new AdGuard methods
- `tests/api/test_devices_api.py`: 4 tests for sync API endpoint

**Documentation**:
- `docs/user-guide.md`: Added "Sync Device Names from AdGuard Home" section
- `frontend/src/content/helpContent.ts`: Added help section for Sync Names feature
- `frontend/src/pages/DocsPage.tsx`: Added "Sync from AdGuard" subsection
- `README.md`: Updated Device Inventory feature description

---

## File Watch Read From End Option (January 2026)

**Feature**: Added "Read from end of file" option for file_watch log sources

**Frontend**:
- `AddSourceModal.tsx`: Added `readFromEnd` state and checkbox for file_watch sources
- `EditSourceModal.tsx`: Added `readFromEnd` state and checkbox, loads from source config

**Behavior**:
- Default: `true` (only collect new log entries written after collector starts)
- When disabled: Reads all existing entries from the beginning of the file
- Useful for importing historical log data (e.g., nginx error logs with existing entries)

---

## File Watch Directory Mode (January 2026)

**Feature**: Added folder/directory watching support to the File Watcher Collector with glob pattern filtering

**Backend** (`backend/app/collectors/file_collector.py`):
- Added `is_directory_mode` property to detect if watching a directory vs single file
- Added `file_pattern` config option for glob filtering (default: "*")
- Multi-file state tracking: `_file_handles`, `_file_positions`, `_modified_files` dicts
- `_scan_directory()`: Finds all files matching the glob pattern
- `_open_single_file()`: Opens individual files with position tracking
- `_read_lines_from_file()`: Reads from specific file by path
- `_on_file_created()`: Handles new file detection in directory mode
- `_on_file_deleted()`: Handles file removal, closes handle gracefully
- `FileEventHandler._matches_pattern()`: Filters events by glob pattern
- Updated `test_connection()` to validate directories and show file count

**Frontend**:
- `AddSourceModal.tsx`: Added "Watch Directory" toggle, file pattern input field
- `EditSourceModal.tsx`: Same directory mode UI, loads `file_pattern` from config

**Config Schema**:
```json
{
  "path": "/var/log/myapp/",
  "file_pattern": "*.log",
  "follow": true,
  "encoding": "utf-8",
  "read_from_end": true
}
```

**Tests** (`backend/tests/collectors/test_file_collector.py`):
- 17 new tests for directory watching mode
- Tests for: directory mode detection, glob pattern matching, multi-file reading, position tracking, file creation/deletion handling, connection testing

---

## Multi-line Log Support (February 2026)

**Feature**: Added multi-line log support to File Watcher Collector for logs with stack traces

**Backend - File Collector** (`backend/app/collectors/file_collector.py`):
- Added `multiline_start_pattern` config option (regex pattern marking start of new log entry)
- Added `_line_buffers: dict[Path, list[str]]` for per-file line buffering
- Added `_multiline_pattern: re.Pattern` compiled regex for efficiency
- Modified `_read_lines_from_file()` to handle buffering:
  - Lines matching start pattern flush the previous buffer and start a new entry
  - Lines not matching are appended to the current buffer as continuation lines
  - Continuation lines are joined with newlines into the final log entry
  - Buffers are preserved between reads for incomplete entries
- Clean up buffers in `_on_file_deleted()` and `stop()`

**Backend - Custom Parser** (`backend/app/parsers/custom_parser.py`):
- Added `multiline_content_field` parser config option
- Modified `parse()` to split multi-line entries into first line + continuation
- Regex matches first line only (since `.*` doesn't cross newlines)
- If `multiline_content_field` is set, continuation lines are appended to that field
- Full entry preserved in `raw_message`

**Frontend**:
- `AddSourceModal.tsx`:
  - Added "Multiline Start Pattern" input field for file_watch sources
  - Added "Multiline Content Field" input field for custom parser config
- `EditSourceModal.tsx`: Same fields, loads from source config

**File Watcher Config Schema**:
```json
{
  "path": "/var/log/myapp/app.log",
  "follow": true,
  "multiline_start_pattern": "^\\d{4}-\\d{2}-\\d{2}"
}
```

**Custom Parser Config Schema**:
```json
{
  "pattern": "(?P<timestamp>...) (?P<level>...) (?P<message>.*)",
  "severity_field": "level",
  "multiline_content_field": "message"
}
```

**Use Case**: Home Assistant logs with stack traces - the timestamp pattern marks where each log entry starts, continuation lines (stack traces) are appended to the `message` field.

---

## Threat Intelligence Feed Documentation (February 2026)

**README.md**:
- Added "Threat Intelligence Feeds" section with comprehensive feed documentation
- Listed 6 free public feeds (Abuse.ch URLhaus, Feodo Tracker, SSL Blacklist, ThreatFox, Spamhaus DROP, CINSscore)
- Listed 2 feeds requiring registration (PhishTank, AlienVault OTX)
- Documented feed types (IP_LIST, URL_LIST, CSV, JSON)
- Added field mapping examples for CSV and JSON feeds
- Listed supported indicator types (IP, CIDR, Domain, URL, Hash, Email)

**docs/user-guide.md**:
- Added comprehensive "Threat Intelligence" section after Ollama Monitoring
- Documented Threat Intel page tabs (Feeds, Indicators, Stats)
- Step-by-step guide for adding feeds with all feed types explained
- Complete field mapping documentation for CSV and JSON feeds
- Authentication options (None, API Key, Bearer, Basic)
- Indicator lookup and automatic matching explanation
- Playbook integration for automated threat response
- Troubleshooting section for common feed issues

**frontend/src/content/helpContent.ts**:
- Enhanced `/dashboard/threat-intel` help panel with 3 new sections:
  - "Free Public Feeds": Lists 6 free feeds with URLs and types
  - "Feed Types": Explains IP List, URL List, CSV, JSON formats
  - "Indicator Types": Documents IP, CIDR, Domain, URL, Hash, Email types

---

## Dark Mode Fix - Device Detail Page (February 2026)

**Issue**: Device detail page and Edit Device modal had poor contrast in dark mode.

**Fixed in `frontend/src/pages/DeviceDetailPage.tsx`**:
- EditDeviceForm modal: Added `dark:bg-zinc-800`, `dark:border-zinc-700`, `dark:text-white` and dark hover states
- Form labels (Hostname, Device Type, Tags): Added `dark:text-gray-300`
- Device info card labels: Added `dark:text-gray-400` to all header labels
- Device info card values: Added `dark:text-white` to all value text
- IP address badges: Added `dark:bg-zinc-700` and `dark:text-gray-200`

---

## Audit Logs Page (February 2026)

**Issue**: "View all audit logs" link on Quarantine page led to blank page - no AuditPage existed.

**Implementation**:
- `frontend/src/pages/AuditPage.tsx`: New page with:
  - Header with title, entry count, export and refresh buttons
  - Filters: Action type dropdown (14 action types), target type dropdown (7 types), success/fail filter
  - Table: Timestamp, Action (badge), User, Target (type + name), Description, Status (success/fail icons)
  - Pagination with page size options
  - Empty state with helpful message
  - CSV/PDF export using existing `exportAuditCSV`/`exportAuditPDF` functions
- `frontend/src/App.tsx`: Added AuditPage import and `/dashboard/audit` route
- `frontend/src/pages/QuarantinePage.tsx`: Fixed link from `/audit` to `/dashboard/audit`

---

## Test Suite Fixes - Comprehensive Coverage Tests (February 2026)

**Issue**: After creating comprehensive tests for low-coverage areas, 23 tests were failing due to API changes and implementation differences.

**Tests Fixed**:

1. **test_quarantine_service.py** (11 IntegrationResult fixes):
   - Imported `ActionType` from integrations base
   - Changed all `action="block"` to `action=ActionType.BLOCK`
   - Changed all `action="unblock"` to `action=ActionType.UNBLOCK`
   - Added required `message` parameter to all `IntegrationResult` instances

2. **test_custom_parser.py** (12 multiline test fixes):
   - Changed multiline tests to pass entries as list items (`parser.parse([entry])`)
   - Parser splits string input on newlines first (line 144), so multiline entries with embedded newlines must be passed as list items where each item is one complete entry
   - Fixed regex pattern in `test_multiline_regex_only_matches_first_line` from `[^\\n]*` to `.*`

3. **test_threat_intel_service.py** (1 stats test fix):
   - Added 16th mock result (was 15) to match the number of queries in `get_stats()`:
     - 3 queries: total_feeds, enabled_feeds, total_indicators
     - 8 queries: one for each IndicatorType
     - 4 queries: one for each severity level
     - 1 query: recent_hits

4. **test_file_collector.py** (3 multiline test fixes):
   - Added trigger entries to flush multiline buffers
   - Multiline buffering keeps last entry in buffer until a new entry arrives (correct streaming behavior)
   - Tests: `test_read_lines_multiline_buffering`, `test_read_lines_multiline_preserves_order`, `test_multiline_directory_mode`

5. **test_threat_intel_service.py** (AsyncMock __aexit__ fix):
   - `AsyncMock()` is truthy, causing exception suppression in async context managers
   - Changed `mock_client_instance.__aexit__.return_value = AsyncMock()` to `mock_client_instance.__aexit__ = AsyncMock(return_value=False)`
   - Python `__aexit__` returning truthy value suppresses the exception

**ThreatIntelService Bug Fix** (`backend/app/services/threat_intel_service.py`):
- Exception handler at line 189 was calling `await self.session.commit()` directly
- If original exception was database-related, session might be in bad state and commit would fail
- Fixed by wrapping status update in try/except with rollback:
  ```python
  except Exception as e:
      try:
          await self.session.rollback()
          feed.last_fetch_at = datetime.now(UTC)
          feed.last_fetch_status = "error"
          feed.last_fetch_message = str(e)[:500]
          await self.session.commit()
      except Exception:
          pass
      logger.error(...)
      return {"success": False, "error": str(e)}
  ```

**Result**: All 1119 tests pass (48 threat intel service tests verified)

---

## Detection Rule Value Combobox (February 2026)

**Feature**: Detection rule value field now shows a dropdown with values from existing event data, while still allowing free text entry.

**Backend** (`backend/app/api/v1/rules.py`):
- Added `FieldValuesResponse` Pydantic model
- Added `_FIELD_COLUMN_MAP` mapping field names to RawEvent columns
- New endpoint `GET /rules/fields/{field_name}/values`:
  - Returns distinct non-null values for the specified field
  - Supports optional `search` query param for prefix filtering
  - Supports `limit` param (default 100, max 500)
  - Maps field names: event_type, severity, source_ip, dest_ip, domain, port, protocol, action, query_type, response_status, blocked_reason, parser_type

**Frontend**:
- `frontend/src/components/ValueCombobox.tsx`: New combobox component
  - Fetches suggestions via `useFieldValues` hook when field is selected
  - Shows loading state while fetching
  - Filters suggestions as user types
  - Allows selecting from dropdown or entering custom text
  - Click-outside closes dropdown and commits value
  - Keyboard navigation (Escape, ArrowDown, Enter)
- `frontend/src/api/hooks.ts`: Added `useFieldValues` hook with 30s cache
- `frontend/src/components/CreateRuleModal.tsx`: Uses ValueCombobox for condition value
- `frontend/src/components/EditRuleModal.tsx`: Uses ValueCombobox for condition value

---

## AI Chat Intent Classification (February 2026)

**Feature**: Intelligent intent detection for AI chat that injects appropriate context based on user intent

**New Files**:
- `backend/app/models/chat_intent.py`: ChatIntent enum (6 types), IntentClassification and ChatContext dataclasses
- `backend/app/services/doc_loader.py`: Singleton service for loading help content and docs with caching
- `backend/app/services/chat_context_service.py`: Intent classification via Haiku + quick heuristics, context building
- `backend/data/help_content.json`: Exported help content from frontend for backend access
- `backend/tests/services/test_chat_context_service.py`: 40 unit tests

**Intent Types**:
| Intent | Example Queries | Context Source |
|--------|-----------------|----------------|
| `app_help` | "How do I quarantine a device?" | helpContent.ts data |
| `setup_config` | "How do I configure Authentik?" | configuration.md |
| `troubleshooting` | "Why isn't my log source working?" | config + diagnostics |
| `log_analysis` | "What is this device doing?" | Network context (devices, alerts, anomalies) |
| `vulnerability_research` | "What is CVE-2024-XXXX?" | Minimal - uses LLM training knowledge |
| `general_chat` | "Hello", "Thanks" | Minimal context |

**Architecture**:
```
User Message → classify_intent() [Haiku] → build_context(intent) → stream_chat_with_context() [Sonnet]
```

**Modified Files**:
- `backend/app/services/llm_service.py`: Added `stream_chat_with_context()` and `query_with_context()` methods
- `backend/app/api/v1/chat.py`: Updated /chat and /query endpoints to use intent classification, added `intent` field to responses

**Key Features**:
- Quick heuristic classification for obvious cases (greetings, CVEs, errors) - no API call needed
- LLM-based classification via Haiku for ambiguous cases
- Intent-specific system prompts for each category
- Conditional network context loading - only fetches database data when needed
- Response includes detected intent for frontend debugging

---

## Application Anomaly Detection in "Run Detection" (February 2026)

**Feature**: Integrated application log anomaly detection (ERROR_SPIKE, NEW_ERROR_PATTERN, CONTAINER_RESTART) into the main "Run Detection" flow on the Anomalies page.

**Background**: Previously, `detect_application_anomalies(source_id)` existed but was not called from `run_detection_for_all_devices()`. Network anomaly detection (DNS, TRAFFIC, CONNECTION) worked per-device, but application anomalies required a source_id.

**Implementation**:

**Backend - App Baseline Service** (`backend/app/services/app_baseline_service.py`):
- Updated `AppBaseline` class to accept optional `device_id` parameter
- Added `calculate_error_rate_baseline_for_device(device_id)` - queries app events by device_id
- Added `calculate_container_baseline_for_device(device_id)` - queries container events by device_id
- Added `calculate_exception_baseline_for_device(device_id)` - queries exception events by device_id

**Backend - Anomaly Service** (`backend/app/services/anomaly_service.py`):
- Added `_detect_application_anomalies_for_device(device_id, time_window_hours)`:
  - Early exit check: Skips expensive baseline calculation if device has no app events in last 7 days
  - Calculates error rate, container, and exception baselines on-demand
  - Returns list of detected anomalies (ERROR_SPIKE, CONTAINER_RESTART, NEW_ERROR_PATTERN)
- Added `_detect_error_spike_for_device()` - z-score based error rate spike detection
- Added `_detect_container_restart_for_device()` - restart count + OOM kill detection
- Added `_detect_new_error_patterns_for_device()` - new exception type detection
- Modified `detect_anomalies()` to call `_detect_application_anomalies_for_device()` after network anomaly detection

**Tests** (`backend/tests/services/test_anomaly_service.py`):
- Added `TestApplicationAnomalyDetectionForDevice` class with 11 new tests:
  - `test_detect_app_anomalies_no_app_events` - early exit when device has no app events
  - `test_detect_error_spike_for_device` - detects high error rates
  - `test_detect_error_spike_for_device_normal` - no anomaly for normal rates
  - `test_detect_container_restart_for_device` - detects excessive restarts
  - `test_detect_container_oom_kill_for_device` - detects OOM kills
  - `test_detect_new_error_patterns_for_device` - detects new exception types
  - `test_detect_new_error_patterns_for_device_no_new` - no anomaly for known types
  - `test_application_anomaly_types_exist` - validates enum values
  - `test_application_anomaly_severity_calculation` - validates severity thresholds
- Updated `test_detect_anomalies_learning_baselines` to account for new app anomaly detection call

**Result**: 45 tests passing in test_anomaly_service.py

**Performance Improvements** (from code review):
1. **Consolidated event fetching**: Single query fetches all app events, then splits for metric calculations
2. **Baseline caching**: 5-minute TTL cache for `DeviceAppBaselines` to avoid redundant calculations
3. **Database index**: Added composite index `ix_raw_events_device_event_type_timestamp` for optimized queries
4. **Debug logging**: Added structured logging for detection start, skip reasons, and anomaly counts

**New files/migrations**:
- `alembic/versions/20260202_0017_017_add_app_event_index.py`: Composite index migration

**User Impact**: When clicking "Run Detection" on the Anomalies page, the system now also checks for:
- Error rate spikes in application/container/journal logs
- Excessive container restarts
- Container OOM kills (always flagged as significant)
- New exception types not seen in the 7-day baseline

---

## CI Fixes & Code Review Improvements (February 2026)

**Lint Fixes** (`app/api/v1/chat.py`, `tests/services/test_chat_context_service.py`):
- Fixed import block sorting (moved `import structlog` to third-party group)
- Removed unused imports (`ChatIntent`, `AsyncMock`, `MagicMock`)

**Type Check Fixes**:
- `app/models/chat_intent.py`: Changed `dict | None` to `dict[str, Any] | None`
- `app/services/integrations/c4000xg.py`:
  - Added explicit type annotations for `response.json()` results
  - Added type annotation for `rules: list[dict[str, Any]] = []`
  - Added 6 `assert self._session_id is not None` before `cookies.set()` calls

**Code Review Improvements** (PR #6):
1. **Fixed typo in `_calculate_exception_metrics`**: `exc_messages` → `exception_messages`
2. **Type consistency**: Changed `known_exception_types` from `set` to `list` for JSON serialization
3. **Documented cache limitation**: Added note that `_device_baseline_cache` is process-local
4. **Removed deprecated source-based methods**: Deleted `detect_application_anomalies()`, `_detect_error_spike()`, `_detect_container_restart_anomaly()`, `_detect_new_error_patterns()` - superseded by device-based methods
5. **Added architecture docs**: New "Application Log Analysis" section in CLAUDE.md

---

## Three Innovative Features (February 2026)

### Feature 1: Autonomous Investigation Agents

**Concept**: LLM-powered agents that automatically investigate high-severity alerts with chain-of-thought reasoning visible to users.

**Backend Files Created**:
- `backend/app/models/investigation.py`: Investigation, InvestigationStep, InvestigationAction models with status/type enums
- `backend/app/services/investigation/__init__.py`: Module exports
- `backend/app/services/investigation/service.py`: InvestigationService with CRUD, approval workflow
- `backend/app/services/investigation/agent.py`: InvestigationAgent with 6 step types (gather_context, correlate_events, check_threat_intel, analyze_baseline, generate_hypothesis, recommend_actions)
- `backend/app/api/v1/investigations.py`: Full API (list, get, create, cancel, approve/reject actions, execute, run)

**Frontend Files Created**:
- `frontend/src/pages/InvestigationsPage.tsx`: List with status filtering, create modal
- `frontend/src/pages/InvestigationDetailPage.tsx`: Timeline view, chain-of-thought display, action approval UI

### Feature 2: Security Gamification System

**Concept**: Achievements, points, levels, streaks, challenges, and leaderboards to make security monitoring engaging.

**Backend Files Created**:
- `backend/app/models/gamification.py`: Achievement, UserAchievement, UserStats, Challenge, UserChallenge models
- `backend/app/data/achievements.py`: 30+ achievement definitions, level progression, point values
- `backend/app/services/gamification_service.py`: Award points, check achievements, leaderboard, challenges
- `backend/app/api/v1/gamification.py`: Stats, achievements, leaderboard, challenges, levels endpoints

**Frontend Files Created**:
- `frontend/src/pages/AchievementsPage.tsx`: User stats, recent achievements, category filtering, achievement grid
- `frontend/src/pages/LeaderboardPage.tsx`: Top 3 podium, full table, rank changes, period filtering

### Feature 3: Dynamic Honeypot Orchestration

**Concept**: Auto-spawn lightweight honeypot containers that record attacker behavior and use LLM to profile attackers.

**Backend Files Created**:
- `backend/app/models/honeypot.py`: HoneypotTemplate, HoneypotInstance, HoneypotInteraction, AttackerProfile models
- `backend/app/data/honeypot_templates.py`: 10 honeypot templates (SSH, HTTP, FTP, Telnet, MySQL, SMB, Redis, RDP)
- `backend/app/services/honeypot/__init__.py`: Module exports
- `backend/app/services/honeypot/orchestrator.py`: ContainerOrchestrator for Docker/Podman management
- `backend/app/services/honeypot/service.py`: HoneypotService (spawn, stop, record interactions, analyze attackers)
- `backend/app/parsers/honeypot_parser.py`: HoneypotParser with Cowrie, HTTP, SQL injection patterns
- `backend/app/api/v1/honeypots.py`: Templates, instances, stats, spawn, stop, interactions, attackers endpoints

**Frontend Files Created**:
- `frontend/src/pages/HoneypotsPage.tsx`: Active honeypots, stats, spawn modal with template selection
- `frontend/src/pages/HoneypotDetailPage.tsx`: Interaction timeline, attacker list, LLM profile display
- `frontend/src/pages/AttackersPage.tsx`: Attacker profiles with sophistication levels, attack patterns, LLM analysis

### Shared Changes

**Database Migration**:
- `backend/alembic/versions/20260202_0017_017_add_investigations_gamification_honeypots.py`: All new enums and tables

**Configuration** (`backend/app/config.py`):
- Investigation settings: enabled, auto_trigger_severity, max_concurrent, require_approval_risk, timeout_minutes
- Gamification settings: enabled, leaderboard_enabled, points_multiplier, streak_reset_hour
- Honeypot settings: enabled, container_runtime, max_concurrent, default_timeout, auto_spawn_on_threat, llm_analysis_enabled, network, host_ip, port_range

**Playbook Integration** (`backend/app/models/playbook.py`, `backend/app/services/playbook_engine.py`):
- Added START_INVESTIGATION and SPAWN_HONEYPOT action types
- Action handlers: _action_start_investigation, _action_spawn_honeypot

**Router Updates** (`backend/app/api/v1/router.py`):
- Registered gamification, investigations, honeypots routers

**WebSocket Events** (`backend/app/api/v1/websocket.py`):
- Investigation events: investigation_started, investigation_step_completed, investigation_completed, action_pending_approval
- Gamification events: achievement_unlocked, level_up, challenge_completed, leaderboard_rank_changed
- Honeypot events: honeypot_spawned, honeypot_interaction, honeypot_expired, attacker_profile_updated

**Frontend Types** (`frontend/src/types/index.ts`):
- Added 20+ new types for all three features

**Frontend Hooks** (`frontend/src/api/hooks.ts`):
- Added 25+ new hooks for gamification, investigations, and honeypots

**Navigation** (`frontend/src/components/Layout.tsx`, `frontend/src/App.tsx`):
- Added navigation items: Investigations, Honeypots, Attackers, Achievements, Leaderboard
- Added 7 new routes

**Test Suite** (98 new tests):
- `tests/services/test_gamification_service.py`: 42 tests for achievements, levels, points, GamificationService
- `tests/services/test_investigation_service.py`: 25 tests for status enums, service CRUD, workflow transitions
- `tests/services/test_honeypot_service.py`: 31 tests for types, templates, service, models, interactions

---

## CenturyLink C4000XG Router Integration (February 2026)

**Feature**: Device blocking via C4000XG modem/router's parental control (Access Scheduler) feature

**Backend**:
- `backend/app/services/integrations/c4000xg.py`:
  - `C4000XGService` class implementing `IntegrationService` interface
  - CGI API authentication with session cookie management (`_login`, `_ensure_session`)
  - GET/POST request helpers for `/cgi/cgi_get` and `/cgi/cgi_set` endpoints
  - `block_device()`: Creates parental control rule with Target=Drop for 24/7 blocking
  - `unblock_device()`: Finds and deletes blocking rule by MAC address
  - `is_device_blocked()`: Queries parental control rules for MAC
  - `get_blocked_devices()`: Lists all devices with Drop rules
  - `get_connected_devices()`: Queries Device.Hosts.Host for device discovery
  - MAC address normalization (handles XX:XX:XX:XX:XX:XX, XX-XX-XX-XX-XX-XX, XXXXXXXXXXXX formats)
- `backend/app/services/integrations/base.py`: Added `IntegrationType.C4000XG`
- `backend/app/services/integrations/__init__.py`: Exported C4000XGService, get_c4000xg_service
- `backend/app/services/quarantine_service.py`: Added C4000XG to router auto-detection
- `backend/app/api/v1/integrations.py`: Added C4000XG test connection and blocked devices endpoints

**Configuration** (backend/.env):
```
ROUTER_INTEGRATION_TYPE=c4000xg
ROUTER_URL=https://192.168.1.1
ROUTER_USERNAME=admin
ROUTER_PASSWORD=<password>
ROUTER_VERIFY_SSL=false
```

**Tests** (`backend/tests/services/test_c4000xg.py`):
- 44 tests covering: configuration, MAC normalization, authentication, test_connection, block_device, unblock_device, is_device_blocked, get_blocked_devices, get_connected_devices, singleton pattern

**Notes**:
- Uses undocumented CGI API - may change with firmware updates
- Parental control rules block by MAC address 24/7
- Session-based auth requires handling session expiry and re-login
- MAC randomization on iOS/Android devices can defeat MAC-based blocking
