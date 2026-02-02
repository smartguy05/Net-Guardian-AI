# NetGuardian AI - Completed Tasks

Condensed summary of completed implementation work.

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
